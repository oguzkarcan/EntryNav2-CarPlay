// Session (control connection) tests.
//
// The iPhone side ("Phone") is implemented here independently from the protocol description:
// a pair-verify client (copied from test_pairing.cpp), control/event keys from direct HKDF of the
// labels (phone read = "Control-Read-Encryption-Key", phone write = "Control-Write-Encryption-Key";
// events phone read = "Events-Write-Encryption-Key", phone write = "Events-Read-Encryption-Key"), and
// RTSP requests built by hand. The controller's LTPK is pre-registered in the pairing store (pair-setup
// itself is covered by test_pairing.cpp; one test also runs a pair-setup M1 through the session).
//
// Fakes record every callback so routing side effects (or their absence) can be asserted.

#include "carplay/airplay_crypto.hpp"
#include "carplay/airplay_hid.hpp"
#include "carplay/airplay_info.hpp"
#include "carplay/airplay_session.hpp"
#include "carplay/bplist_codec.hpp"
#include "carplay/control_cipher.hpp"
#include "carplay/pairing.hpp"
#include "carplay/rtsp_message.hpp"
#include "carplay/tlv8_codec.hpp"
#include "test_support.hpp"

#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

namespace crypto = carplay::crypto;
namespace bplist = carplay::bplist;
namespace rtsp = carplay::rtsp;
namespace hid = carplay::hid;
namespace info = carplay::info;
namespace tlv8 = carplay::tlv8;
namespace pairing = carplay::pairing;
namespace session = carplay::session;
using carplay::ControlCipher;
using test_support::hexToBytes;

typedef std::vector<uint8_t> Bytes;
typedef std::vector<tlv8::Item> Items;
typedef std::vector<std::string> Strings;

namespace {

// ---------------------------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------------------------

Bytes sha(const Bytes& data) {
    Bytes out(64);
    crypto::sha512(data.empty() ? NULL : &data[0], data.size(), &out[0]);
    return out;
}
Bytes strBytes(const std::string& s) { return Bytes(s.begin(), s.end()); }
Bytes shaStr(const std::string& s) { return sha(strBytes(s)); }
Bytes prefix(const Bytes& v, size_t n) { return Bytes(v.begin(), v.begin() + static_cast<long>(n)); }
void cat(Bytes& out, const Bytes& v) { out.insert(out.end(), v.begin(), v.end()); }
Bytes arr(const uint8_t* p, size_t n) { return Bytes(p, p + n); }

Bytes hkdf(const Bytes& ikm, const std::string& salt, const std::string& info_label) {
    Bytes out;
    crypto::hkdfSha512(ikm, salt, info_label, 32, out);
    return out;
}

Bytes nonceFor(const char* label) {
    Bytes n(12, 0);
    memcpy(&n[4], label, 8);
    return n;
}

Bytes seal(const Bytes& key, const char* label, const Bytes& plain) {
    Bytes out;
    const Bytes n = nonceFor(label);
    crypto::chacha20Poly1305Seal(&key[0], &n[0], NULL, 0, plain.empty() ? NULL : &plain[0], plain.size(), out);
    return out;
}

bool open(const Bytes& key, const char* label, const Bytes& sealed, Bytes& plain) {
    const Bytes n = nonceFor(label);
    return crypto::chacha20Poly1305Open(&key[0], &n[0], NULL, 0, sealed.empty() ? NULL : &sealed[0],
                                        sealed.size(), plain);
}

Bytes typesOf(const Items& items) {
    Bytes t;
    for (size_t i = 0; i < items.size(); ++i) t.push_back(items[i].type);
    return t;
}

Bytes valueOf(const Items& items, uint8_t t) {
    const tlv8::Item* it = tlv8::findFirst(items, t);
    return it == NULL ? Bytes() : it->value;
}

bool startsWith(const Bytes& b, const std::string& s) {
    return b.size() >= s.size() && std::string(b.begin(), b.begin() + static_cast<long>(s.size())) == s;
}

Strings keysOf(const bplist::Value& dict) {
    Strings k;
    if (!dict.isDict()) return k;
    for (size_t i = 0; i < dict.asDict().size(); ++i) k.push_back(dict.asDict()[i].first);
    return k;
}

Strings strs(const char* a, const char* b = NULL, const char* c = NULL, const char* d = NULL,
             const char* e = NULL) {
    Strings s;
    const char* all[5] = {a, b, c, d, e};
    for (int i = 0; i < 5; ++i) {
        if (all[i] != NULL) s.push_back(all[i]);
    }
    return s;
}

std::string join(const Strings& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) out += (i ? "," : "") + s[i];
    return out;
}

Bytes encode(const bplist::Value& v) {
    Bytes b;
    bplist::encode(v, b);
    return b;
}

bplist::Value dict() { return bplist::Value::makeDict(); }
bplist::Value str(const std::string& s) { return bplist::Value::makeString(s); }
bplist::Value num(int64_t v) { return bplist::Value::makeInt(v); }

int64_t intAt(const bplist::Value& d, const char* key) {
    int64_t v = -999;
    d.getInt(key, v);
    return v;
}

// Deterministic RandomSource: SHA-512(label | counter_be32) stream (as test_pairing.cpp).
class DetRng : public pairing::RandomSource {
public:
    explicit DetRng(const std::string& label) : label_(label), counter_(0) {}
    virtual bool fill(uint8_t* out, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            if (pool_.empty()) refill();
            out[i] = pool_[0];
            pool_.erase(pool_.begin());
        }
        return true;
    }

private:
    void refill() {
        Bytes in = strBytes(label_);
        in.push_back(static_cast<uint8_t>(counter_ >> 24));
        in.push_back(static_cast<uint8_t>(counter_ >> 16));
        in.push_back(static_cast<uint8_t>(counter_ >> 8));
        in.push_back(static_cast<uint8_t>(counter_));
        ++counter_;
        pool_ = sha(in);
    }
    std::string label_;
    uint32_t counter_;
    Bytes pool_;
};

const char* const kAccessoryId = "a1b2c3d4-0000-4000-8000-0123456789ab";
const char* const kControllerId = "5A2C7E1F-9B3D-4C8A-A6E2-11223344CAFE";

struct Controller {
    std::string id;
    crypto::Ed25519KeyPair keys;
    Controller(const std::string& label, const std::string& pairing_id) : id(pairing_id) {
        const Bytes seed = prefix(shaStr(label), 32);
        crypto::ed25519FromSeed(&seed[0], keys);
    }
    Bytes sign(const Bytes& data) const {
        Bytes sig(64);
        crypto::ed25519Sign(keys.secret_key, &data[0], data.size(), &sig[0]);
        return sig;
    }
};

// Pair-verify controller (test_pairing.cpp VerifyClient).
struct VerifyClient {
    crypto::X25519KeyPair eph;
    Bytes acc_pub;
    Bytes shared;
    Bytes enc_key;

    explicit VerifyClient(const std::string& label) {
        const Bytes s = prefix(shaStr(label), 32);
        crypto::x25519FromSecret(&s[0], eph);
    }
    Bytes pub() const { return arr(eph.public_key, 32); }
    Bytes m1() const {
        Items req;
        req.push_back(tlv8::Item::fromByte(tlv8::kTagState, 1));
        req.push_back(tlv8::Item(tlv8::kTagPublicKey, pub()));
        return tlv8::encode(req);
    }
    bool onM2(const Bytes& resp, const std::string& acc_id, const Bytes& acc_ltpk) {
        Items items;
        if (!tlv8::decode(resp, items)) return false;
        if (typesOf(items) != hexToBytes("060305")) return false;
        acc_pub = valueOf(items, 0x03);
        if (acc_pub.size() != 32) return false;
        shared.assign(32, 0);
        if (!crypto::x25519SharedSecret(eph.secret_key, &acc_pub[0], &shared[0])) return false;
        enc_key = hkdf(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info");
        Bytes plain;
        if (!open(enc_key, "PV-Msg02", valueOf(items, 0x05), plain)) return false;
        Items sub;
        if (!tlv8::decode(plain, sub)) return false;
        if (valueOf(sub, 0x01) != strBytes(acc_id)) return false;
        const Bytes sig = valueOf(sub, 0x0a);
        if (sig.size() != 64) return false;
        Bytes data = acc_pub;
        cat(data, strBytes(acc_id));
        cat(data, pub());
        return crypto::ed25519Verify(&acc_ltpk[0], &data[0], data.size(), &sig[0]);
    }
    Bytes m3(const Controller& signer) const {
        Bytes data = pub();
        cat(data, strBytes(signer.id));
        cat(data, acc_pub);
        Items sub;
        sub.push_back(tlv8::Item(tlv8::kTagIdentifier, strBytes(signer.id)));
        sub.push_back(tlv8::Item(tlv8::kTagSignature, signer.sign(data)));
        Items req;
        req.push_back(tlv8::Item::fromByte(tlv8::kTagState, 3));
        req.push_back(tlv8::Item(tlv8::kTagEncryptedData, seal(enc_key, "PV-Msg03", tlv8::encode(sub))));
        return tlv8::encode(req);
    }
};

// ---------------------------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------------------------

struct FakeListener : public session::SessionListener {
    Strings events;
    int ended;
    session::DeviceInfo device;
    bplist::Value last_params;
    bool close_on_record;
    FakeListener() : ended(0), close_on_record(false) {}

    virtual void onSessionActive(session::Session& s) {
        events.push_back("active");
        if (close_on_record) s.close();
    }
    virtual void onSessionEnded(session::Session&) {
        events.push_back("ended");
        ++ended;
    }
    virtual void onDeviceInfo(session::Session&, const session::DeviceInfo& d) {
        device = d;
        events.push_back("device");
    }
    virtual void onHostUiRequested(session::Session&) { events.push_back("hostui"); }
    virtual void onCommand(session::Session&, const std::string& type, const bplist::Value& params) {
        events.push_back("command:" + type);
        last_params = params;
    }
};

struct FakeMedia : public session::MediaHandler {
    Strings events;
    bool accept_alt_screen;
    bool feedback_body;
    Bytes audio_out_key;  // derived inside onAudio through the session helper
    Bytes screen_key;
    int setup_sent;
    FakeMedia() : accept_alt_screen(false), feedback_body(false), setup_sent(0) {}

    virtual bool onScreen(session::Session& s, int32_t type, const bplist::Value& stream, int32_t& port) {
        events.push_back("screen:" + rtsp::toDecimal(type));
        if (type == info::kStreamTypeAltScreen && !accept_alt_screen) return false;
        screen_key.assign(32, 0);
        if (!s.streamOutputKey(stream, &screen_key[0])) screen_key.clear();
        port = 7100 + (type - 110);
        return true;
    }
    virtual bool onAudio(session::Session& s, int32_t type, const bplist::Value& stream, bplist::Value& r) {
        events.push_back("audio:" + rtsp::toDecimal(type));
        audio_out_key.assign(32, 0);
        if (!s.streamOutputKey(stream, &audio_out_key[0])) audio_out_key.clear();
        r = dict();
        r.set("type", num(type));
        r.set("dataPort", num(7001));
        r.set("controlPort", num(7002));
        const bplist::Value* id = stream.find("streamConnectionID");
        r.set("streamConnectionID", id != NULL ? *id : num(0));
        return true;
    }
    virtual bool onDataStream(session::Session&, const bplist::Value&, bplist::Value& r) {
        events.push_back("data");
        r = dict();
        r.set("type", num(130));
        r.set("streamID", num(1));
        r.set("dataPort", num(7130));
        return true;
    }
    virtual bool onBufferedAudio(session::Session&, const bplist::Value&, bplist::Value& r) {
        events.push_back("buffered");
        r = dict();
        r.set("type", num(103));
        r.set("dataPort", num(7103));
        return true;
    }
    virtual bool onBufferedAudioControl(session::Session&, const std::string& method, const bplist::Value&,
                                        bplist::Value& r) {
        events.push_back("bufctl:" + method);
        if (method != "GETANCHOR") return false;
        r = dict();
        r.set("rtpTime", num(42));
        return true;
    }
    virtual bool onFeedback(session::Session&, bplist::Value& r) {
        events.push_back("feedback");
        if (!feedback_body) return false;
        r = dict();
        r.set("streams", bplist::Value::makeArray());
        return true;
    }
    virtual void onTeardown(session::Session&, int32_t type) { events.push_back("teardown:" + rtsp::toDecimal(type)); }
    virtual void onAudioDuck(session::Session&, bool ducked) { events.push_back(ducked ? "duck" : "unduck"); }
    virtual void onSetupResponseSent(session::Session&) { ++setup_sent; }
    virtual void onSessionClosed(session::Session&) { events.push_back("closed"); }
};

struct FakeTransport : public session::TransportHost {
    Strings events;
    int32_t peer_timing;
    int close_all;
    bool fail_timing;
    FakeTransport() : peer_timing(-1), close_all(0), fail_timing(false) {}
    virtual bool openTiming(int32_t peer, int32_t& port) {
        events.push_back("timing");
        peer_timing = peer;
        if (fail_timing) return false;
        port = 6001;
        return true;
    }
    virtual bool openEvent(int32_t& port) {
        events.push_back("event");
        port = 6002;
        return true;
    }
    virtual bool openKeepAlive(int32_t& port) {
        events.push_back("keepalive");
        port = 6003;
        return true;
    }
    virtual void closeAll() { ++close_all; }
};

struct FakeAuth : public session::AuthProvider {
    int calls;
    FakeAuth() : calls(0) {}
    virtual bool getCertificate(Bytes& out) {
        ++calls;
        out.assign(4, 1);
        return true;
    }
    virtual bool signChallenge(const uint8_t*, size_t, Bytes& sig) {
        ++calls;
        sig.assign(4, 2);
        return true;
    }
};

// ---------------------------------------------------------------------------------------------
// Harness: accessory side (Session + fakes) and the Phone.
// ---------------------------------------------------------------------------------------------

struct Harness {
    info::AirPlayConfig config;
    pairing::Identity identity;
    pairing::InMemoryPairingStore store;
    DetRng rng;
    FakeListener listener;
    FakeMedia media;
    FakeTransport transport;
    Controller ctrl;
    std::unique_ptr<session::Session> s;

    explicit Harness(const session::SessionPolicy& policy = session::SessionPolicy(),
                     session::AuthProvider* auth = NULL, bool buffered = false)
        : config(info::bmwEntryNav2_800x480(true)), rng("session-acc-rng"), ctrl("ctrl-ltsk", kControllerId) {
        config.main_buffered_audio = buffered;
        const Bytes seed = prefix(shaStr("accessory-seed"), 32);
        identity.initFromSeed(&seed[0], kAccessoryId);
        store.save(ctrl.id, ctrl.keys.public_key);
        s.reset(new session::Session(config, identity, store, rng, listener, media, transport, auth, policy));
    }
};

struct Reply {
    int status;
    std::string reason;
    rtsp::Request raw;
};

struct Phone {
    VerifyClient vc;
    std::unique_ptr<ControlCipher> cipher;
    uint32_t cseq;
    Bytes sent;  // every byte handed to the session
    Bytes recv;  // every byte the session produced

    Phone() : vc("phone-eph"), cseq(0) {}

    Bytes build(const std::string& method, const std::string& path, const std::string& ctype, const Bytes& body,
                const rtsp::HeaderList* extra = NULL, const std::string& protocol = "RTSP/1.0") {
        rtsp::HeaderList h;
        if (!ctype.empty()) h.push_back(rtsp::Header("Content-Type", ctype));
        if (extra != NULL) h.insert(h.end(), extra->begin(), extra->end());
        h.push_back(rtsp::Header("CSeq", rtsp::toDecimalUnsigned(++cseq)));
        Bytes out;
        rtsp::buildRequest(method, path, protocol, h, body, out);
        return out;
    }

    /// Encrypts (if keyed) and hands the bytes to the session; returns the session's raw output.
    bool feed(session::Session& s, const Bytes& plain, Bytes& raw_out) {
        Bytes wire;
        if (cipher.get() != NULL) {
            cipher->encrypt(plain, wire);
        } else {
            wire = plain;
        }
        cat(sent, wire);
        raw_out.clear();
        const bool ok = s.onControlBytes(wire.empty() ? NULL : &wire[0], wire.size(), raw_out);
        cat(recv, raw_out);
        return ok;
    }

    bool parseReplies(const Bytes& raw, std::vector<Reply>& replies) {
        Bytes plain;
        if (cipher.get() != NULL) {
            if (!cipher->feed(raw, plain)) return false;
        } else {
            plain = raw;
        }
        rtsp::Parser p;
        std::vector<rtsp::Request> msgs;
        if (!p.feed(plain, msgs) || p.bufferedBytes() != 0) return false;
        replies.clear();
        for (size_t i = 0; i < msgs.size(); ++i) {
            Reply r;
            r.status = atoi(msgs[i].path.c_str());
            r.reason = msgs[i].protocol;
            r.raw = msgs[i];
            replies.push_back(r);
        }
        return true;
    }

    /// One request -> exactly one reply.
    bool call(session::Session& s, const std::string& method, const std::string& path, const std::string& ctype,
              const Bytes& body, Reply& reply, const rtsp::HeaderList* extra = NULL) {
        Bytes raw;
        if (!feed(s, build(method, path, ctype, body, extra), raw)) return false;
        std::vector<Reply> replies;
        if (!parseReplies(raw, replies) || replies.size() != 1U) return false;
        reply = replies[0];
        return reply.raw.header("cseq") == rtsp::toDecimalUnsigned(cseq);
    }

    bool callPlist(session::Session& s, const std::string& method, const std::string& path,
                   const bplist::Value& body, Reply& reply) {
        return call(s, method, path, rtsp::kContentTypeBinaryPlist, encode(body), reply);
    }

    /// Pair-verify M1..M4 in plaintext, then key the phone's control cipher.
    bool pairVerify(Harness& h) {
        Reply r;
        if (!call(*h.s, "POST", "/pair-verify", rtsp::kContentTypePairingTlv8, vc.m1(), r)) return false;
        if (r.status != 200 || r.raw.header("content-type") != rtsp::kContentTypePairingTlv8) return false;
        if (!vc.onM2(r.raw.body, kAccessoryId, arr(h.identity.keys.public_key, 32))) return false;
        if (!call(*h.s, "POST", "/pair-verify", rtsp::kContentTypePairingTlv8, vc.m3(h.ctrl), r)) return false;
        if (r.raw.body != hexToBytes("060104")) return false;
        keyCipher();
        return h.s->encrypted();
    }

    void keyCipher() {
        const Bytes read_key = hkdf(vc.shared, "Control-Salt", "Control-Read-Encryption-Key");
        const Bytes write_key = hkdf(vc.shared, "Control-Salt", "Control-Write-Encryption-Key");
        cipher.reset(new ControlCipher(&read_key[0], &write_key[0]));
    }
};

bool decodeDict(const Reply& r, bplist::Value& v) { return bplist::decode(r.raw.body, v) && v.isDict(); }

bplist::Value sessionSetupBody(bool keep_alive_flag) {
    bplist::Value b = dict();
    b.set("name", str("Test iPhone"));
    b.set("deviceID", str("AA:BB:CC:00:11:22"));
    b.set("macAddress", str("AA:BB:CC:DD:EE:FF"));
    b.set("model", str("iPhone14,2"));
    b.set("timingPort", num(50123));
    if (keep_alive_flag) b.set("keepAliveLowPower", bplist::Value::makeBool(true));
    bplist::Value::Array f;
    f.push_back(str("mainBuffered"));
    f.push_back(num(5));  // non-string ignored
    b.set("features", bplist::Value::makeArray(f));
    return b;
}

bplist::Value streamEntry(int64_t type) {
    bplist::Value e = dict();
    e.set("type", num(type));
    return e;
}

bplist::Value streamsBody(const bplist::Value::Array& entries) {
    bplist::Value b = dict();
    b.set("streams", bplist::Value::makeArray(entries));
    return b;
}

// SETUP of 110, 100 and 130 streams (all accepted by FakeMedia).
bool setupThreeStreams(Harness& h, Phone& p) {
    bplist::Value::Array e;
    bplist::Value screen = streamEntry(110);
    screen.set("streamConnectionID", num(5));
    e.push_back(screen);
    bplist::Value audio = streamEntry(100);
    audio.set("streamConnectionID", num(6));
    e.push_back(audio);
    e.push_back(streamEntry(130));
    Reply r;
    return p.callPlist(*h.s, "SETUP", "rtsp://10.0.0.1/1", streamsBody(e), r) && r.status == 200 &&
           h.s->activeStreams().size() == 3U;
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

TEST_CASE(plaintextInfoBeforePairing) {
    Harness h;
    Phone p;
    Reply r;
    REQUIRE(p.call(*h.s, "GET", "/info", "", Bytes(), r));
    CHECK_EQ(200, r.status);
    CHECK_EQ(std::string("OK"), r.reason);
    CHECK_EQ(std::string(rtsp::kContentTypeBinaryPlist), r.raw.header("content-type"));
    bplist::Value v;
    REQUIRE(decodeDict(r, v));
    CHECK(v == info::buildInfo(h.config));
    CHECK(!h.s->encrypted());
    // HTTP/1.1 is echoed (CarPlayBonjourDualStackTest probes /info over HTTP).
    Bytes raw;
    REQUIRE(p.feed(*h.s, p.build("GET", "/info", "", Bytes(), NULL, "HTTP/1.1"), raw));
    CHECK(startsWith(raw, "HTTP/1.1 200 OK\r\n"));
    CHECK_EQ(2, h.media.setup_sent);
    CHECK(h.listener.events.empty());
}

TEST_CASE(pairVerifyThenEncryptedInfo) {
    Harness h;
    Phone p;
    REQUIRE(p.pairVerify(h));
    CHECK_EQ(std::string(kControllerId), h.s->controllerId());
    Reply r;
    REQUIRE(p.call(*h.s, "GET", "/info", "", Bytes(), r));
    CHECK_EQ(200, r.status);
    bplist::Value v;
    REQUIRE(decodeDict(r, v));
    CHECK(v == info::buildInfo(h.config));
    // The raw output of that call was ciphertext.
    Bytes raw;
    REQUIRE(p.feed(*h.s, p.build("GET_PARAMETER", "*", "", Bytes()), raw));
    CHECK(!startsWith(raw, "RTSP/"));
    std::vector<Reply> replies;
    REQUIRE(p.parseReplies(raw, replies));
    REQUIRE(replies.size() == 1U);
    CHECK_EQ(200, replies[0].status);
    CHECK(replies[0].raw.body.empty());
}

TEST_CASE(m4PlaintextAndNextResponseEncryptedInOneChunk) {
    Harness h;
    Phone p;
    Reply r;
    REQUIRE(p.call(*h.s, "POST", "/pair-verify", rtsp::kContentTypePairingTlv8, p.vc.m1(), r));
    REQUIRE(p.vc.onM2(r.raw.body, kAccessoryId, arr(h.identity.keys.public_key, 32)));
    // M3 (plaintext) immediately followed, in the SAME chunk, by an encrypted /info request.
    Bytes chunk = p.build("POST", "/pair-verify", rtsp::kContentTypePairingTlv8, p.vc.m3(h.ctrl));
    const size_t m3_len = chunk.size();
    p.keyCipher();
    Bytes enc;
    p.cipher->encrypt(p.build("GET", "/info", "", Bytes()), enc);
    cat(chunk, enc);
    Bytes raw;
    REQUIRE(h.s->onControlBytes(&chunk[0], chunk.size(), raw));
    CHECK(m3_len > 0U);
    // First the plaintext M4 ...
    const std::string m4 = "RTSP/1.0 200 OK\r\nContent-Type: application/pairing+tlv8\r\nCSeq: 2\r\n"
                           "Content-Length: 3\r\n\r\n";
    REQUIRE(startsWith(raw, m4));
    REQUIRE(raw.size() > m4.size() + 3U);
    CHECK_BYTES_EQ(hexToBytes("060104"), Bytes(raw.begin() + static_cast<long>(m4.size()),
                                               raw.begin() + static_cast<long>(m4.size() + 3)));
    // ... then the encrypted /info response.
    const Bytes rest(raw.begin() + static_cast<long>(m4.size() + 3), raw.end());
    CHECK(!startsWith(rest, "RTSP/"));
    std::vector<Reply> replies;
    REQUIRE(p.parseReplies(rest, replies));
    REQUIRE(replies.size() == 1U);
    CHECK_EQ(200, replies[0].status);
    CHECK_EQ(std::string("3"), replies[0].raw.header("cseq"));
    bplist::Value v;
    REQUIRE(decodeDict(replies[0], v));
    CHECK(v == info::buildInfo(h.config));
    CHECK_EQ(2, h.media.setup_sent);  // one per onControlBytes call (M1 call + the combined chunk)
}

TEST_CASE(bytewiseAndSingleChunkDeliveryMatchChunked) {
    // Conversation A: one request per call.
    Bytes sent;
    Bytes recv;
    {
        Harness h;
        Phone p;
        REQUIRE(p.pairVerify(h));
        Reply r;
        REQUIRE(p.call(*h.s, "GET", "/info", "", Bytes(), r));
        REQUIRE(p.callPlist(*h.s, "SETUP", "rtsp://10.0.0.1/1", sessionSetupBody(true), r));
        REQUIRE(setupThreeStreams(h, p));
        REQUIRE(p.call(*h.s, "RECORD", "rtsp://10.0.0.1/1", "", Bytes(), r));
        REQUIRE(p.call(*h.s, "POST", "/feedback", "", Bytes(), r));
        sent = p.sent;
        recv = p.recv;
    }
    REQUIRE(!sent.empty());
    // B: the identical byte stream byte by byte.
    {
        Harness h;
        Bytes out;
        for (size_t i = 0; i < sent.size(); ++i) {
            Bytes chunk;
            REQUIRE(h.s->onControlBytes(&sent[i], 1, chunk));
            cat(out, chunk);
        }
        CHECK_BYTES_EQ(recv, out);
        CHECK(h.s->encrypted());
        CHECK_EQ(join(strs("device", "active")), join(h.listener.events));
    }
    // C: everything in ONE chunk (plaintext->encrypted transition inside the chunk).
    {
        Harness h;
        Bytes out;
        REQUIRE(h.s->onControlBytes(&sent[0], sent.size(), out));
        CHECK_BYTES_EQ(recv, out);
        CHECK_EQ(1, h.media.setup_sent);
    }
    // D: odd split sizes.
    {
        Harness h;
        Bytes out;
        size_t i = 0;
        size_t step = 1;
        while (i < sent.size()) {
            const size_t n = std::min(step, sent.size() - i);
            Bytes chunk;
            REQUIRE(h.s->onControlBytes(&sent[i], n, chunk));
            cat(out, chunk);
            i += n;
            step = step * 3 % 97 + 1;
        }
        CHECK_BYTES_EQ(recv, out);
    }
}

TEST_CASE(pipelinedRequests) {
    Harness h;
    Phone p;
    // Plaintext pipelining before pairing.
    Bytes two = p.build("GET", "/info", "", Bytes());
    cat(two, p.build("POST", "/pair-setup", rtsp::kContentTypePairingTlv8, hexToBytes("000100060101")));
    Bytes raw;
    REQUIRE(p.feed(*h.s, two, raw));
    std::vector<Reply> replies;
    REQUIRE(p.parseReplies(raw, replies));
    REQUIRE(replies.size() == 2U);
    CHECK_EQ(std::string("1"), replies[0].raw.header("cseq"));
    CHECK_EQ(std::string("2"), replies[1].raw.header("cseq"));
    CHECK_EQ(std::string(rtsp::kContentTypePairingTlv8), replies[1].raw.header("content-type"));
    Items m2;
    REQUIRE(tlv8::decode(replies[1].raw.body, m2));
    CHECK_BYTES_EQ(Bytes(1, 2), valueOf(m2, tlv8::kTagState));  // pair-setup M2
    CHECK_EQ(384U, valueOf(m2, tlv8::kTagPublicKey).size());

    // Encrypted pipelining: three requests in one encrypted write.
    REQUIRE(p.pairVerify(h));
    Bytes three = p.build("GET_PARAMETER", "*", "", Bytes());
    cat(three, p.build("FLUSH", "rtsp://x/1", "", Bytes()));
    cat(three, p.build("GET", "/info", "", Bytes()));
    REQUIRE(p.feed(*h.s, three, raw));
    REQUIRE(p.parseReplies(raw, replies));
    REQUIRE(replies.size() == 3U);
    for (size_t i = 0; i < 3; ++i) CHECK_EQ(rtsp::toDecimalUnsigned(p.cseq - 2 + i), replies[i].raw.header("cseq"));
    CHECK(replies[0].raw.body.empty());
    CHECK(!replies[2].raw.body.empty());
}

TEST_CASE(sessionSetupResponse) {
    Harness h;
    Phone p;
    REQUIRE(p.pairVerify(h));
    Reply r;
    REQUIRE(p.callPlist(*h.s, "SETUP", "rtsp://10.0.0.1/1", sessionSetupBody(true), r));
    CHECK_EQ(200, r.status);
    CHECK_EQ(std::string(rtsp::kContentTypeBinaryPlist), r.raw.header("content-type"));
    bplist::Value v;
    REQUIRE(decodeDict(r, v));
    CHECK_EQ(join(strs("timingPort", "eventPort", "keepAlivePort", "enabledFeatures")), join(keysOf(v)));
    CHECK_EQ(6001, intAt(v, "timingPort"));
    CHECK_EQ(6002, intAt(v, "eventPort"));
    CHECK_EQ(6003, intAt(v, "keepAlivePort"));
    std::vector<std::string> proposed;
    proposed.push_back("mainBuffered");
    const std::vector<std::string> expect = info::setupEnabledFeatures(h.config, proposed);
    const bplist::Value* ef = v.find("enabledFeatures");
    REQUIRE(ef != NULL && ef->isArray());
    REQUIRE(ef->asArray().size() == expect.size());
    for (size_t i = 0; i < expect.size(); ++i) CHECK_EQ(expect[i], ef->asArray()[i].asString());
    CHECK_EQ(50123, h.transport.peer_timing);
    CHECK_EQ(join(strs("timing", "event", "keepalive")), join(h.transport.events));
    CHECK_EQ(join(strs("device")), join(h.listener.events));
    CHECK_EQ(std::string("Test iPhone"), h.listener.device.name);
    CHECK_EQ(std::string("AA:BB:CC:00:11:22"), h.listener.device.device_id);
    CHECK_EQ(std::string("aa:bb:cc:dd:ee:ff"), h.listener.device.wifi_mac);
    CHECK_EQ(std::string("iPhone14,2"), h.listener.device.model);
    CHECK_EQ(std::string("aa:bb:cc:dd:ee:ff"), h.s->deviceInfo().wifi_mac);

    // Without keepAliveLowPower: no keepAlivePort. Integer 1 enables it, integer 2 does not.
    REQUIRE(p.callPlist(*h.s, "SETUP", "rtsp://10.0.0.1/1", sessionSetupBody(false), r));
    REQUIRE(decodeDict(r, v));
    CHECK_EQ(join(strs("timingPort", "eventPort", "enabledFeatures")), join(keysOf(v)));
    bplist::Value b = sessionSetupBody(false);
    b.set("keepAliveLowPower", num(1));
    REQUIRE(p.callPlist(*h.s, "SETUP", "rtsp://10.0.0.1/1", b, r));
    REQUIRE(decodeDict(r, v));
    CHECK(v.find("keepAlivePort") != NULL);
    b.set("keepAliveLowPower", num(2));
    REQUIRE(p.callPlist(*h.s, "SETUP", "rtsp://10.0.0.1/1", b, r));
    REQUIRE(decodeDict(r, v));
    CHECK(v.find("keepAlivePort") == NULL);

    // Wrong-typed fields are ignored; no identity -> no onDeviceInfo; bad timing port -> 0.
    bplist::Value weird = dict();
    weird.set("name", num(3));
    weird.set("timingPort", str("123"));
    weird.set("features", str("hevc"));
    weird.set("streams", str("not-an-array"));  // not a list: still a session SETUP
    h.listener.events.clear();
    REQUIRE(p.callPlist(*h.s, "SETUP", "rtsp://10.0.0.1/1", weird, r));
    CHECK_EQ(200, r.status);
    CHECK(h.listener.events.empty());
    CHECK_EQ(0, h.transport.peer_timing);
    weird.set("timingPort", num(70000));
    REQUIRE(p.callPlist(*h.s, "SETUP", "rtsp://10.0.0.1/1", weird, r));
    CHECK_EQ(0, h.transport.peer_timing);
}

TEST_CASE(streamsSetup) {
    Harness h;
    Phone p;
    REQUIRE(p.pairVerify(h));
    const uint64_t big_id = 0x8000000000000001ULL;  // >= 2^63
    bplist::Value::Array e;
    bplist::Value screen = streamEntry(110);
    screen.set("streamConnectionID", num(5));
    e.push_back(screen);
    bplist::Value audio = streamEntry(100);
    audio.set("streamConnectionID", bplist::Value::makeUInt(big_id));
    audio.set("audioType", str("media"));
    e.push_back(audio);
    bplist::Value data = streamEntry(130);
    data.set("seed", num(9));
    e.push_back(data);
    e.push_back(streamEntry(999));  // unknown: skipped
    e.push_back(streamEntry(111));  // rejected by the media handler: omitted
    e.push_back(str("not a dict"));
    bplist::Value bad_type = dict();
    bad_type.set("type", str("110"));
    e.push_back(bad_type);
    e.push_back(streamEntry(103));  // buffered audio disabled in config: skipped

    Reply r;
    REQUIRE(p.callPlist(*h.s, "SETUP", "rtsp://10.0.0.1/1", streamsBody(e), r));
    CHECK_EQ(200, r.status);
    bplist::Value v;
    REQUIRE(decodeDict(r, v));
    CHECK_EQ(join(strs("streams")), join(keysOf(v)));
    const bplist::Value* streams = v.find("streams");
    REQUIRE(streams != NULL && streams->isArray());
    REQUIRE(streams->asArray().size() == 3U);
    const bplist::Value& s0 = streams->asArray()[0];
    CHECK_EQ(join(strs("type", "dataPort")), join(keysOf(s0)));
    CHECK_EQ(110, intAt(s0, "type"));
    CHECK_EQ(7100, intAt(s0, "dataPort"));
    const bplist::Value& s1 = streams->asArray()[1];
    CHECK_EQ(join(strs("type", "dataPort", "controlPort", "streamConnectionID")), join(keysOf(s1)));
    uint64_t id = 0;
    CHECK(s1.getUInt("streamConnectionID", id));
    CHECK(id == big_id);
    CHECK(s1.find("streamConnectionID")->type() == bplist::Value::TYPE_UINT64);
    CHECK_EQ(130, intAt(streams->asArray()[2], "type"));
    CHECK_EQ(1, intAt(streams->asArray()[2], "streamID"));

    CHECK_EQ(join(strs("screen:110", "audio:100", "data", "screen:111")), join(h.media.events));
    REQUIRE(h.s->activeStreams().size() == 3U);
    CHECK_EQ(110, h.s->activeStreams()[0]);
    CHECK_EQ(100, h.s->activeStreams()[1]);
    CHECK_EQ(130, h.s->activeStreams()[2]);

    // Unsigned handling end to end: the key the media handler derived uses the unsigned decimal.
    CHECK_BYTES_EQ(hkdf(p.vc.shared, "DataStream-Salt9223372036854775809", "DataStream-Output-Encryption-Key"),
                   h.media.audio_out_key);
    CHECK_BYTES_EQ(hkdf(p.vc.shared, "DataStream-Salt5", "DataStream-Output-Encryption-Key"), h.media.screen_key);

    // Re-SETUP of an active type keeps its position (ordered set).
    bplist::Value::Array again;
    again.push_back(streamEntry(110));
    REQUIRE(p.callPlist(*h.s, "SETUP", "rtsp://10.0.0.1/1", streamsBody(again), r));
    CHECK_EQ(3U, h.s->activeStreams().size());
    CHECK_EQ(110, h.s->activeStreams()[0]);
}

TEST_CASE(streamsSetupCapAndBufferedAudio) {
    session::SessionPolicy policy;
    policy.max_streams_per_setup = 2;
    Harness h(policy, NULL, true);
    Phone p;
    REQUIRE(p.pairVerify(h));
    bplist::Value::Array e;
    e.push_back(streamEntry(103));
    e.push_back(streamEntry(130));
    e.push_back(streamEntry(110));  // beyond the cap
    Reply r;
    REQUIRE(p.callPlist(*h.s, "SETUP", "rtsp://10.0.0.1/1", streamsBody(e), r));
    bplist::Value v;
    REQUIRE(decodeDict(r, v));
    CHECK_EQ(2U, v.find("streams")->asArray().size());
    CHECK_EQ(join(strs("buffered", "data")), join(h.media.events));

    // Buffered-audio control methods are routed only when enabled.
    h.media.events.clear();
    REQUIRE(p.call(*h.s, "GETANCHOR", "rtsp://x/1", "", Bytes(), r));
    REQUIRE(decodeDict(r, v));
    CHECK_EQ(42, intAt(v, "rtpTime"));
    bplist::Value rate = dict();
    rate.set("rate", num(1));
    REQUIRE(p.callPlist(*h.s, "SETRATEANCHORTIME", "rtsp://x/1", rate, r));
    CHECK_EQ(200, r.status);
    CHECK(r.raw.body.empty());
    REQUIRE(p.call(*h.s, "FLUSHBUFFERED", "rtsp://x/1", "", strBytes("junk"), r));
    CHECK_EQ(400, r.status);
    CHECK_EQ(join(strs("bufctl:GETANCHOR", "bufctl:SETRATEANCHORTIME")), join(h.media.events));

    Harness off;
    Phone q;
    REQUIRE(q.pairVerify(off));
    REQUIRE(q.call(*off.s, "GETANCHOR", "rtsp://x/1", "", Bytes(), r));
    CHECK_EQ(200, r.status);
    CHECK(r.raw.body.empty());
    CHECK(off.media.events.empty());
}

TEST_CASE(simpleMethodsAnd500) {
    Harness h;
    Phone p;
    REQUIRE(p.pairVerify(h));
    Reply r;
    REQUIRE(p.call(*h.s, "RECORD", "rtsp://10.0.0.1/1", "", Bytes(), r));
    CHECK_EQ(200, r.status);
    CHECK_EQ(join(strs("active")), join(h.listener.events));
    const char* methods[] = {"SET_PARAMETER", "FLUSH", "GET_PARAMETER", "OPTIONS", "FOO"};
    for (size_t i = 0; i < 5; ++i) {
        REQUIRE(p.call(*h.s, methods[i], "rtsp://10.0.0.1/1", "", strBytes("x"), r));
        CHECK_EQ(200, r.status);
        CHECK(r.raw.body.empty());
        CHECK_EQ(std::string("0"), r.raw.header("content-length"));
    }
    // A failing TransportHost makes SETUP a 500, the session stays up.
    h.transport.fail_timing = true;
    REQUIRE(p.callPlist(*h.s, "SETUP", "rtsp://10.0.0.1/1", sessionSetupBody(false), r));
    CHECK_EQ(500, r.status);
    CHECK_EQ(std::string("Internal Server Error"), r.reason);
    CHECK(!h.s->closed());
    REQUIRE(p.call(*h.s, "GET", "/info", "", Bytes(), r));
    CHECK_EQ(200, r.status);
}

TEST_CASE(feedbackWithAndWithoutBody) {
    Harness h;
    Phone p;
    REQUIRE(p.pairVerify(h));
    Reply r;
    REQUIRE(p.call(*h.s, "POST", "/feedback", "", Bytes(), r));
    CHECK_EQ(200, r.status);
    CHECK(r.raw.body.empty());
    CHECK(!r.raw.hasHeader("content-type"));
    h.media.feedback_body = true;
    REQUIRE(p.call(*h.s, "POST", "/feedback", "", Bytes(), r));
    CHECK_EQ(std::string(rtsp::kContentTypeBinaryPlist), r.raw.header("content-type"));
    bplist::Value v;
    REQUIRE(decodeDict(r, v));
    CHECK(v.find("streams") != NULL && v.find("streams")->isArray());
    // GET /feedback is not the feedback route.
    h.media.events.clear();
    REQUIRE(p.call(*h.s, "GET", "/feedback", "", Bytes(), r));
    CHECK(h.media.events.empty());
}

TEST_CASE(inboundCommands) {
    Harness h;
    Phone p;
    REQUIRE(p.pairVerify(h));
    const char* types[] = {"duckAudio", "modesChanged", "unduckAudio", "requestUI"};
    Reply r;
    for (size_t i = 0; i < 4; ++i) {
        bplist::Value c = dict();
        c.set("type", str(types[i]));
        bplist::Value params = dict();
        params.set("durationMs", num(500));
        c.set("params", params);
        REQUIRE(p.callPlist(*h.s, "POST", "/command", c, r));
        CHECK_EQ(200, r.status);
    }
    CHECK_EQ(join(strs("duck", "unduck")), join(h.media.events));
    CHECK_EQ(join(strs("command:duckAudio", "command:modesChanged", "command:unduckAudio", "hostui",
                       "command:requestUI")),
             join(h.listener.events));
    CHECK_EQ(500, intAt(h.listener.last_params, "durationMs"));

    // Undecodable body -> empty type and params.
    h.listener.events.clear();
    REQUIRE(p.call(*h.s, "POST", "/command", rtsp::kContentTypeBinaryPlist, strBytes("garbage"), r));
    CHECK_EQ(200, r.status);
    CHECK_EQ(join(strs("command:")), join(h.listener.events));
    CHECK(h.listener.last_params.isDict() && h.listener.last_params.asDict().empty());

    // X-Apple-StreamID remote-control message: acknowledged, not dispatched.
    h.listener.events.clear();
    bplist::Value rc = dict();
    bplist::Value rcp = dict();
    rcp.set("data", bplist::Value::makeData(Bytes(3, 7)));
    rc.set("params", rcp);
    rc.set("type", str("duckAudio"));
    rtsp::HeaderList extra;
    extra.push_back(rtsp::Header("X-Apple-StreamID", "3"));
    REQUIRE(p.call(*h.s, "POST", "/command", rtsp::kContentTypeBinaryPlist, encode(rc), r, &extra));
    CHECK_EQ(200, r.status);
    CHECK(h.listener.events.empty());
    CHECK_EQ(2U, h.media.events.size());
    // GET /command is not the command route.
    REQUIRE(p.call(*h.s, "GET", "/command", "", Bytes(), r));
    CHECK(h.listener.events.empty());
}

TEST_CASE(teardownRules) {
    Harness h;
    Phone p;
    REQUIRE(p.pairVerify(h));
    REQUIRE(setupThreeStreams(h, p));
    h.media.events.clear();
    Reply r;
    // Specific type.
    bplist::Value::Array one;
    one.push_back(streamEntry(100));
    REQUIRE(p.callPlist(*h.s, "TEARDOWN", "rtsp://x/1", streamsBody(one), r));
    CHECK_EQ(200, r.status);
    CHECK_EQ(join(strs("teardown:100")), join(h.media.events));
    CHECK_EQ(2U, h.s->activeStreams().size());
    // Type 130 with streamID != 1 is ignored (and the body still names a stream: not whole-session).
    bplist::Value::Array vic;
    bplist::Value d2 = streamEntry(130);
    d2.set("streamID", num(2));
    vic.push_back(d2);
    REQUIRE(p.callPlist(*h.s, "TEARDOWN", "rtsp://x/1", streamsBody(vic), r));
    CHECK_EQ(join(strs("teardown:100")), join(h.media.events));
    CHECK_EQ(2U, h.s->activeStreams().size());
    // A type that is not active: no callback.
    bplist::Value::Array missing;
    missing.push_back(streamEntry(101));
    REQUIRE(p.callPlist(*h.s, "TEARDOWN", "rtsp://x/1", streamsBody(missing), r));
    CHECK_EQ(1U, h.media.events.size());
    // Type 130 with streamID 1 is the iAP tunnel.
    bplist::Value::Array iap;
    bplist::Value d1 = streamEntry(130);
    d1.set("streamID", num(1));
    iap.push_back(d1);
    REQUIRE(p.callPlist(*h.s, "TEARDOWN", "rtsp://x/1", streamsBody(iap), r));
    CHECK_EQ(join(strs("teardown:100", "teardown:130")), join(h.media.events));
    // Whole session: no body.
    REQUIRE(setupThreeStreams(h, p));
    h.media.events.clear();
    REQUIRE(p.call(*h.s, "TEARDOWN", "rtsp://x/1", "", Bytes(), r));
    CHECK_EQ(200, r.status);
    CHECK_EQ(join(strs("teardown:110", "teardown:100", "teardown:130")), join(h.media.events));
    CHECK(h.s->activeStreams().empty());
    // Empty streams list / entries without type also mean the whole session.
    REQUIRE(setupThreeStreams(h, p));
    h.media.events.clear();
    bplist::Value::Array junk;
    junk.push_back(str("x"));
    junk.push_back(dict());
    REQUIRE(p.callPlist(*h.s, "TEARDOWN", "rtsp://x/1", streamsBody(junk), r));
    CHECK_EQ(3U, h.media.events.size());
    CHECK(!h.s->closed());

    // The free function directly.
    bool whole = false;
    std::vector<int32_t> types;
    session::teardownStreamTypes(NULL, whole, types);
    CHECK(whole && types.empty());
    bplist::Value b = streamsBody(vic);
    session::teardownStreamTypes(&b, whole, types);
    CHECK(!whole && types.empty());
}

TEST_CASE(authSetupAlways400) {
    {
        Harness h;
        Phone p;
        Reply r;
        REQUIRE(p.call(*h.s, "POST", "/auth-setup", rtsp::kContentTypeOctetStream, Bytes(33, 1), r));
        CHECK_EQ(400, r.status);
        CHECK_EQ(std::string("Bad Request"), r.reason);
    }
    {
        FakeAuth auth;
        Harness h(session::SessionPolicy(), &auth);
        Phone p;
        Reply r;
        REQUIRE(p.call(*h.s, "POST", "/auth-setup", rtsp::kContentTypeOctetStream, Bytes(33, 1), r));
        CHECK_EQ(400, r.status);
        REQUIRE(p.pairVerify(h));
        REQUIRE(p.call(*h.s, "POST", "/auth-setup", rtsp::kContentTypeOctetStream, Bytes(33, 1), r));
        CHECK_EQ(400, r.status);
        CHECK_EQ(0, auth.calls);
    }
}

TEST_CASE(badSetupPlist400) {
    Harness h;
    Phone p;
    REQUIRE(p.pairVerify(h));
    Reply r;
    REQUIRE(p.call(*h.s, "SETUP", "rtsp://x/1", rtsp::kContentTypeBinaryPlist, strBytes("not a plist"), r));
    CHECK_EQ(400, r.status);
    REQUIRE(p.call(*h.s, "SETUP", "rtsp://x/1", "", Bytes(), r));
    CHECK_EQ(400, r.status);
    REQUIRE(p.callPlist(*h.s, "SETUP", "rtsp://x/1", bplist::Value::makeArray(), r));  // not a dict
    CHECK_EQ(400, r.status);
    CHECK(h.transport.events.empty());
    CHECK(h.media.events.empty());
    CHECK(!h.s->closed());
}

TEST_CASE(requireVerifiedPolicy) {
    Harness h;
    Phone p;
    Reply r;
    struct Req {
        const char* method;
        const char* path;
    };
    const Req refused[] = {{"SETUP", "rtsp://x/1"}, {"RECORD", "rtsp://x/1"}, {"POST", "/command"},
                           {"POST", "/feedback"},  {"TEARDOWN", "rtsp://x/1"}, {"GET_PARAMETER", "*"},
                           {"SET_PARAMETER", "/info"}, {"OPTIONS", "*"}};
    bplist::Value cmd = dict();
    cmd.set("type", str("duckAudio"));
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); ++i) {
        const bool setup = std::string(refused[i].method) == "SETUP";
        REQUIRE(p.call(*h.s, refused[i].method, refused[i].path, rtsp::kContentTypeBinaryPlist,
                       setup ? encode(sessionSetupBody(true)) : encode(cmd), r));
        CHECK_EQ(403, r.status);
        CHECK_EQ(std::string("Forbidden"), r.reason);
        CHECK(r.raw.body.empty());
    }
    CHECK(h.listener.events.empty());
    CHECK(h.media.events.empty());
    CHECK(h.transport.events.empty());
    CHECK(!h.s->closed());
    // Allowed before verification: /info, /pair-setup, /fp-setup.
    REQUIRE(p.call(*h.s, "GET", "/info", "", Bytes(), r));
    CHECK_EQ(200, r.status);
    REQUIRE(p.call(*h.s, "POST", "/fp-setup", "", Bytes(16, 0), r));
    CHECK_EQ(200, r.status);
    // After pair-verify the same SETUP is accepted.
    REQUIRE(p.pairVerify(h));
    REQUIRE(p.callPlist(*h.s, "SETUP", "rtsp://x/1", sessionSetupBody(false), r));
    CHECK_EQ(200, r.status);

    // Flag off: reference behaviour (plaintext SETUP / RECORD / command are served).
    session::SessionPolicy off;
    off.require_verified_for_session_requests = false;
    Harness ref(off);
    Phone q;
    REQUIRE(q.callPlist(*ref.s, "SETUP", "rtsp://x/1", sessionSetupBody(true), r));
    CHECK_EQ(200, r.status);
    bplist::Value v;
    REQUIRE(decodeDict(r, v));
    CHECK_EQ(6002, intAt(v, "eventPort"));
    REQUIRE(q.call(*ref.s, "RECORD", "rtsp://x/1", "", Bytes(), r));
    REQUIRE(q.callPlist(*ref.s, "POST", "/command", cmd, r));
    CHECK_EQ(join(strs("device", "active", "command:duckAudio")), join(ref.listener.events));
    REQUIRE(q.call(*ref.s, "POST", "/x", "", Bytes(756, 0), r));  // ControlReceiveBoundsTest request
    CHECK_EQ(200, r.status);
    CHECK(!ref.s->encrypted());
}

TEST_CASE(tamperedCiphertextClosesOnce) {
    Harness h;
    Phone p;
    REQUIRE(p.pairVerify(h));
    Bytes wire;
    p.cipher->encrypt(p.build("GET", "/info", "", Bytes()), wire);
    wire[wire.size() - 1] ^= 0x01;
    Bytes out;
    CHECK(!h.s->onControlBytes(&wire[0], wire.size(), out));
    CHECK(out.empty());
    CHECK(h.s->closed());
    CHECK_EQ(1, h.listener.ended);
    CHECK_EQ(1, h.transport.close_all);
    CHECK_EQ(join(strs("closed")), join(h.media.events));
    CHECK(!h.s->onControlBytes(&wire[0], wire.size(), out));
    h.s->close();
    CHECK_EQ(1, h.listener.ended);
    CHECK_EQ(1, h.transport.close_all);
    uint8_t s[32];
    CHECK(!h.s->sharedSecret(s));  // key material wiped
    CHECK(!h.s->encrypted());
}

TEST_CASE(oversizedHeaderAndBodyClose) {
    {
        Harness h;
        Bytes req = strBytes("GET /info RTSP/1.0\r\nX: ");
        req.resize(req.size() + 17 * 1024, 'a');
        Bytes out;
        CHECK(!h.s->onControlBytes(&req[0], req.size(), out));
        CHECK(h.s->closed());
        CHECK_EQ(1, h.listener.ended);
    }
    {
        Harness h;
        Phone p;
        REQUIRE(p.pairVerify(h));
        Bytes out;
        CHECK(!p.feed(*h.s, strBytes("POST /x RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 1500000000\r\n\r\n"), out));
        CHECK(h.s->closed());
    }
}

TEST_CASE(closeIdempotentAndReentrant) {
    Harness h;
    Phone p;
    REQUIRE(p.pairVerify(h));
    h.s->close();
    h.s->close();
    CHECK_EQ(1, h.listener.ended);
    CHECK_EQ(1, h.transport.close_all);
    CHECK(h.s->closed());
    Bytes out;
    const uint8_t b = 'G';
    CHECK(!h.s->onControlBytes(&b, 1, out));
    CHECK(!h.s->onEventAccepted(out));
    CHECK(out.empty());

    // A callback that closes the session mid-request: no response, onControlBytes false, ended once.
    Harness h2;
    h2.listener.close_on_record = true;
    Phone q;
    REQUIRE(q.pairVerify(h2));
    CHECK(!q.feed(*h2.s, q.build("RECORD", "rtsp://x/1", "", Bytes()), out));
    CHECK(out.empty());
    CHECK_EQ(1, h2.listener.ended);
    CHECK(h2.s->closed());
}

TEST_CASE(eventChannelThroughSession) {
    {
        Harness h;  // no pair-verify: the event connection is refused and the session closes
        Bytes out;
        CHECK(!h.s->onEventAccepted(out));
        CHECK(out.empty());
        CHECK(h.s->closed());
        CHECK_EQ(1, h.listener.ended);
    }
    Harness h;
    Phone p;
    REQUIRE(p.pairVerify(h));
    Bytes wire;
    CHECK(!h.s->setNightMode(true, wire));  // pending until the event channel is ready
    CHECK(wire.empty());
    CHECK(!h.s->events().ready());
    REQUIRE(h.s->onEventAccepted(wire));
    CHECK(h.s->events().ready());
    CHECK(!h.s->events().hasPendingNightMode());

    std::vector<hid::TouchContact> contacts;
    contacts.push_back(hid::TouchContact(0, true, 10, 20));
    const Bytes touch = hid::touchReport(contacts, 800, 480);
    REQUIRE(h.s->events().sendHidReport(hid::kUidTouchscreen, touch, wire));

    const Bytes ev_read = hkdf(p.vc.shared, "Events-Salt", "Events-Write-Encryption-Key");
    const Bytes ev_write = hkdf(p.vc.shared, "Events-Salt", "Events-Read-Encryption-Key");
    ControlCipher phone_ev(&ev_read[0], &ev_write[0]);
    Bytes plain;
    REQUIRE(phone_ev.feed(wire, plain));
    rtsp::Parser parser;
    std::vector<rtsp::Request> msgs;
    REQUIRE(parser.feed(plain, msgs));
    REQUIRE(msgs.size() == 2U);
    bplist::Value v;
    REQUIRE(bplist::decode(msgs[0].body, v));
    bool night = false;
    CHECK(v.find("params") != NULL && v.find("params")->getBool("nightMode", night) && night);
    REQUIRE(bplist::decode(msgs[1].body, v));
    std::string s;
    CHECK(v.getString("type", s) && s == "hidSendReport");
    CHECK(v.getString("uuid", s) && s == "2a2a2a2a");
    CHECK_BYTES_EQ(touch, v.find("hidReport")->asData());

    // Phone -> accessory request on the event channel: answered with 200.
    Bytes in;
    phone_ev.encrypt(strBytes("POST /command RTSP/1.0\r\nCSeq: 4\r\nContent-Length: 0\r\n\r\n"), in);
    Bytes reply;
    std::vector<rtsp::Request> reqs;
    REQUIRE(h.s->onEventBytes(&in[0], in.size(), reply, &reqs));
    CHECK_EQ(1U, reqs.size());
    plain.clear();
    REQUIRE(phone_ev.feed(reply, plain));
    CHECK_BYTES_EQ(strBytes("RTSP/1.0 200 OK\r\nCSeq: 4\r\nContent-Length: 0\r\n\r\n"), plain);

    // Garbage on the event channel closes the whole session.
    Bytes junk(22, 0x55);  // complete frame (len 4 + 4 + tag 16) that fails authentication
    junk[0] = 0x04;
    junk[1] = 0x00;
    CHECK(!h.s->onEventBytes(&junk[0], junk.size(), reply));
    CHECK(h.s->closed());
    CHECK_EQ(1, h.listener.ended);
}

TEST_CASE(streamKeyHelpers) {
    Harness h;
    uint8_t k[32];
    uint8_t k2[32];
    CHECK(!h.s->deriveScreenStreamKey(5, k));  // before pair-verify
    CHECK(!h.s->deriveAudioStreamKeys(5, k, k2));
    CHECK(h.s->controllerId().empty());
    Phone p;
    REQUIRE(p.pairVerify(h));
    uint8_t shared[32];
    REQUIRE(h.s->sharedSecret(shared));
    CHECK_BYTES_EQ(p.vc.shared, arr(shared, 32));

    REQUIRE(h.s->deriveScreenStreamKey(5, k));
    CHECK_BYTES_EQ(hkdf(p.vc.shared, "DataStream-Salt5", "DataStream-Output-Encryption-Key"), arr(k, 32));
    REQUIRE(h.s->deriveAudioStreamKeys(18446744073709551615ULL, k, k2));
    CHECK_BYTES_EQ(hkdf(p.vc.shared, "DataStream-Salt18446744073709551615", "DataStream-Output-Encryption-Key"),
                   arr(k, 32));
    CHECK_BYTES_EQ(hkdf(p.vc.shared, "DataStream-Salt18446744073709551615", "DataStream-Input-Encryption-Key"),
                   arr(k2, 32));
    REQUIRE(h.s->deriveDataStreamSeedKey(77, k));
    CHECK_BYTES_EQ(hkdf(p.vc.shared, "DataStream-Salt77", "DataStream-Output-Encryption-Key"), arr(k, 32));

    // Plist helpers: negative int64 -> unsigned reinterpretation (Long.toUnsignedString).
    bplist::Value stream = dict();
    stream.set("streamConnectionID", num(-1));
    REQUIRE(h.s->streamInputKey(stream, k));
    CHECK_BYTES_EQ(hkdf(p.vc.shared, "DataStream-Salt18446744073709551615", "DataStream-Input-Encryption-Key"),
                   arr(k, 32));
    stream.set("seed", num(77));
    REQUIRE(h.s->streamOutputKey(stream, k, "seed"));
    CHECK_BYTES_EQ(hkdf(p.vc.shared, "DataStream-Salt77", "DataStream-Output-Encryption-Key"), arr(k, 32));
    stream.set("streamConnectionID", str("5"));
    CHECK(!h.s->streamOutputKey(stream, k));
    CHECK(!h.s->streamOutputKey(dict(), k));

    int64_t l = 0;
    int32_t i = 0;
    CHECK(session::plistNumberToLong(bplist::Value::makeReal(3.9), l) && l == 3);
    CHECK(session::plistNumberToInt(num(0x100000006LL), i) && i == 6);
    CHECK(!session::plistNumberToLong(str("1"), l));
}

TEST_CASE(pairSetupRoutedThroughSession) {
    // pair-setup M1 through the session (the full SRP exchange is covered by test_pairing.cpp).
    Harness h;
    Phone p;
    Items m1;
    m1.push_back(tlv8::Item(tlv8::kTagMethod, Bytes(1, 0)));
    m1.push_back(tlv8::Item::fromByte(tlv8::kTagState, 1));
    Reply r;
    REQUIRE(p.call(*h.s, "POST", "/pair-setup", rtsp::kContentTypePairingTlv8, tlv8::encode(m1), r));
    CHECK_EQ(200, r.status);
    CHECK_EQ(std::string(rtsp::kContentTypePairingTlv8), r.raw.header("content-type"));
    Items items;
    REQUIRE(tlv8::decode(r.raw.body, items));
    CHECK_BYTES_EQ(hexToBytes("060302"), typesOf(items));
    CHECK(!h.s->encrypted());
    // An unregistered controller cannot complete pair-verify; the session stays plaintext.
    Harness h2;
    h2.store.clear();
    Phone q;
    CHECK(!q.pairVerify(h2));
    CHECK(!h2.s->encrypted());
    CHECK(!h2.s->closed());
}

int main() { return test_support::runAll("test_airplay_session"); }
