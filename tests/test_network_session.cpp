// End-to-end real-socket loopback test for Phase 3 F3-P3 (SessionServer + MediaEngine).
//
// Unlike test_e2e_session.cpp (which drives Session through in-memory byte vectors), this test
// runs a real SessionServer + MediaEngine on a single-threaded Reactor with real non-blocking
// loopback TCP and UDP sockets, OsRandomSource, and FilePairingStore on disk.

#include "carplay/airplay_crypto.hpp"
#include "carplay/airplay_hid.hpp"
#include "carplay/airplay_info.hpp"
#include "carplay/airplay_session.hpp"
#include "carplay/audio_rtp.hpp"
#include "carplay/bigint.hpp"
#include "carplay/bplist_codec.hpp"
#include "carplay/control_cipher.hpp"
#include "carplay/mic_uplink.hpp"
#include "carplay/ntp_timing.hpp"
#include "carplay/pairing.hpp"
#include "carplay/platform/file_util.hpp"
#include "carplay/platform/media_engine.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/os_random.hpp"
#include "carplay/platform/pairing_storage.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/session_server.hpp"
#include "carplay/platform/tcp.hpp"
#include "carplay/platform/thread.hpp"
#include "carplay/platform/udp.hpp"
#include "carplay/rtsp_message.hpp"
#include "carplay/screen_stream.hpp"
#include "carplay/srp6a.hpp"
#include "carplay/tlv8_codec.hpp"
#include "test_support.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
namespace audio = carplay::audio;
namespace ntp = carplay::ntp;
namespace stream = carplay::stream;
namespace bi = carplay::bigint;
namespace srp = carplay::srp;
namespace plat = carplay::platform;
using carplay::ControlCipher;

typedef std::vector<uint8_t> Bytes;
typedef std::vector<tlv8::Item> Items;

namespace {

static int g_passed = 0;
static int g_failed = 0;

#define CHECK_TRUE(cond)                                                          \
    do {                                                                          \
        if (!(cond)) {                                                            \
            printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond);            \
            return false;                                                         \
        }                                                                         \
    } while (0)

void cat(Bytes& out, const Bytes& v) {
    for (size_t i = 0; i < v.size(); ++i) {
        out.push_back(v[i]);
    }
}

Bytes sha(const Bytes& data) {
    Bytes out(64);
    crypto::sha512(data.empty() ? NULL : &data[0], data.size(), &out[0]);
    return out;
}

Bytes strBytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

Bytes shaStr(const std::string& s) {
    return sha(strBytes(s));
}

Bytes prefix(const Bytes& v, size_t n) {
    return Bytes(v.begin(), v.begin() + static_cast<ptrdiff_t>(n));
}

Bytes hkdf(const Bytes& ikm, const std::string& salt, const std::string& info_label) {
    Bytes out;
    crypto::hkdfSha512(ikm, salt, info_label, 32, out);
    return out;
}

std::string dec(uint64_t v) {
    if (v == 0) return "0";
    std::string s;
    while (v != 0) {
        s.insert(s.begin(), static_cast<char>('0' + static_cast<int>(v % 10U)));
        v /= 10U;
    }
    return s;
}

void putLe(Bytes& b, size_t off, uint64_t v, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        b[off + i] = static_cast<uint8_t>(v >> (8U * i));
    }
}

void putBe(Bytes& b, size_t off, uint64_t v, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        b[off + i] = static_cast<uint8_t>(v >> (8U * (n - 1U - i)));
    }
}

Bytes labelNonce(const char* label) {
    Bytes n(12, 0);
    memcpy(&n[4], label, 8);
    return n;
}

Bytes sealWith(const Bytes& key, const Bytes& nonce, const Bytes& aad, const Bytes& plain) {
    Bytes out;
    crypto::chacha20Poly1305Seal(&key[0],
                                 &nonce[0],
                                 aad.empty() ? NULL : &aad[0],
                                 aad.size(),
                                 plain.empty() ? NULL : &plain[0],
                                 plain.size(),
                                 out);
    return out;
}

bool openWith(const Bytes& key, const Bytes& nonce, const Bytes& sealed, Bytes& plain) {
    return crypto::chacha20Poly1305Open(&key[0],
                                        &nonce[0],
                                        NULL,
                                        0,
                                        sealed.empty() ? NULL : &sealed[0],
                                        sealed.size(),
                                        plain);
}

Bytes valueOf(const Items& items, uint8_t t) {
    const tlv8::Item* it = tlv8::findFirst(items, t);
    return it == NULL ? Bytes() : it->value;
}

Bytes encodePlist(const bplist::Value& v) {
    Bytes b;
    bplist::encode(v, b);
    return b;
}

int64_t intAt(const bplist::Value& d, const char* key) {
    int64_t v = -1;
    d.getInt(key, v);
    return v;
}

std::string strAt(const bplist::Value& d, const char* key) {
    std::string s;
    d.getString(key, s);
    return s;
}

// ---- SRP-6a client ----

Bytes minimalOf(const Bytes& v) {
    size_t i = 0;
    while (i < v.size() && v[i] == 0) ++i;
    if (i == v.size()) {
        Bytes z;
        z.push_back(0);
        return z;
    }
    return Bytes(v.begin() + static_cast<ptrdiff_t>(i), v.end());
}

Bytes padOf(const Bytes& v) {
    Bytes m = minimalOf(v);
    if (m.size() >= 384U) return m;
    Bytes out(384U - m.size(), 0);
    cat(out, m);
    return out;
}

Bytes numBytes(const bi::Number& n) {
    Bytes out;
    bi::toBytesBE(n, out);
    return out;
}

bi::Number numOf(const Bytes& b) {
    bi::Number n;
    bi::fromBytesBE(b.empty() ? NULL : &b[0], b.size(), n);
    return n;
}

struct SrpClient {
    Bytes a;
    Bytes a_pub;
    Bytes k;
    Bytes m1;
    Bytes m2;

    explicit SrpClient(const std::string& label) : a(prefix(shaStr(label), 32)) {
        bi::Number pub;
        srp::group3072().modExp(bi::fromUint32(5), &a[0], a.size(), pub);
        bi::toBytesBEPadded(pub, 384, a_pub);
    }

    bool compute(const Bytes& b_pub, const Bytes& salt, const std::string& pass) {
        const std::string user = "Pair-Setup";
        const bi::Modulus& m = srp::group3072();
        const Bytes n(srp::rfc5054Prime3072(), srp::rfc5054Prime3072() + 384);
        Bytes g5;
        g5.push_back(5);
        Bytes buf = minimalOf(n);
        cat(buf, padOf(g5));
        const bi::Number kk = numOf(sha(buf));
        buf = salt;
        cat(buf, shaStr(user + ":" + pass));
        const Bytes x = sha(buf);
        buf = a_pub;
        cat(buf, padOf(b_pub));
        const Bytes u = sha(buf);
        bi::Number v, kv, t, ta, tu, tux, s;
        bool ok = m.modExp(bi::fromUint32(5), &x[0], x.size(), v);
        ok = ok && m.mulMod(kk, v, kv);
        ok = ok && m.subMod(numOf(b_pub), kv, t);
        ok = ok && m.modExp(t, &a[0], a.size(), ta);
        ok = ok && m.modExp(t, &u[0], u.size(), tu);
        ok = ok && m.modExp(tu, &x[0], x.size(), tux);
        ok = ok && m.mulMod(ta, tux, s);
        if (!ok) return false;
        k = sha(numBytes(s));
        const Bytes hn = sha(minimalOf(n));
        const Bytes hg = sha(g5);
        buf.clear();
        for (size_t i = 0; i < 64; ++i) {
            buf.push_back(static_cast<uint8_t>(hn[i] ^ hg[i]));
        }
        cat(buf, shaStr(user));
        cat(buf, salt);
        cat(buf, a_pub);
        cat(buf, padOf(b_pub));
        cat(buf, k);
        m1 = sha(buf);
        buf = a_pub;
        cat(buf, m1);
        cat(buf, k);
        m2 = sha(buf);
        return true;
    }
};

struct Controller {
    std::string id;
    crypto::Ed25519KeyPair keys;

    Controller(const std::string& label, const std::string& pairing_id) : id(pairing_id) {
        const Bytes seed = prefix(shaStr(label), 32);
        crypto::ed25519FromSeed(&seed[0], keys);
    }

    Bytes ltpk() const { return Bytes(keys.public_key, keys.public_key + 32); }

    Bytes sign(const Bytes& data) const {
        Bytes sig(64);
        crypto::ed25519Sign(keys.secret_key, &data[0], data.size(), &sig[0]);
        return sig;
    }
};

// ---- TempDir ----

struct TempDir {
    std::string path;
    explicit TempDir(const char* tag) {
        char buf[256];
        snprintf(buf,
                 sizeof(buf),
                 "build/test_net_session_%s_%lld",
                 tag,
                 static_cast<long long>(plat::monotonicNanos()));
        path = buf;
        cleanup();
        plat::ensurePrivateDirectory(path);
    }
    void cleanup() {
        plat::removeFile(plat::joinPath(path, plat::kIdentityFileName));
        plat::removeFile(plat::joinPath(path, plat::kControllersFileName));
        plat::removeDirectory(path);
    }
    ~TempDir() { cleanup(); }
};

// ---- Test Listener & MediaSink ----

struct RecordingListener : public session::SessionListener {
    int active_count;
    int ended_count;
    int host_ui_count;
    session::DeviceInfo device_info;
    std::vector<std::string> commands;

    RecordingListener() : active_count(0), ended_count(0), host_ui_count(0) {}

    virtual void onSessionActive(session::Session&) { active_count += 1; }
    virtual void onSessionEnded(session::Session&) { ended_count += 1; }
    virtual void onDeviceInfo(session::Session&, const session::DeviceInfo& info) {
        device_info = info;
    }
    virtual void onHostUiRequested(session::Session&) { host_ui_count += 1; }
    virtual void onCommand(session::Session&, const std::string& type, const bplist::Value&) {
        commands.push_back(type);
    }
};

struct RecordingSink : public plat::MediaSink {
    struct VideoConfigEvent {
        int32_t type;
        stream::VideoCodecType codec;
        Bytes annexb;
        Bytes raw;
        float width;
        float height;
    };
    struct VideoFrameEvent {
        int32_t type;
        Bytes annexb;
        uint64_t sender_nanos;
    };
    struct AudioPcmEvent {
        plat::AudioStreamId id;
        std::vector<int16_t> samples;
        uint16_t seq;
        uint32_t ts;
    };

    std::vector<std::pair<int32_t, bool> > screen_active;
    std::vector<VideoConfigEvent> video_configs;
    std::vector<VideoFrameEvent> video_frames;
    std::vector<plat::AudioStreamId> audio_started;
    std::vector<plat::AudioStreamId> audio_stopped;
    std::vector<AudioPcmEvent> audio_pcm;
    std::vector<uint16_t> audio_lost;
    std::vector<bool> duck_events;
    std::vector<plat::AudioStreamId> mic_started;
    std::vector<plat::AudioStreamId> mic_stopped;
    audio::MicStreamParams last_mic_params;
    plat::Address last_mic_dest;
    std::vector<Bytes> iap_messages;

    virtual void onScreenStreamActive(int32_t type, bool active) {
        screen_active.push_back(std::make_pair(type, active));
    }

    virtual void onVideoConfig(int32_t type,
                               stream::VideoCodecType codec,
                               const uint8_t* annexb_data,
                               size_t annexb_len,
                               const uint8_t* raw_config,
                               size_t raw_len,
                               float width_px,
                               float height_px) {
        VideoConfigEvent ev;
        ev.type = type;
        ev.codec = codec;
        if (annexb_data != NULL && annexb_len > 0) {
            ev.annexb.assign(annexb_data, annexb_data + annexb_len);
        }
        if (raw_config != NULL && raw_len > 0) {
            ev.raw.assign(raw_config, raw_config + raw_len);
        }
        ev.width = width_px;
        ev.height = height_px;
        video_configs.push_back(ev);
    }

    virtual void onVideoFrame(int32_t type,
                              const uint8_t* annexb_data,
                              size_t len,
                              uint64_t sender_nanos,
                              int64_t /*arrival_mono_nanos*/) {
        VideoFrameEvent ev;
        ev.type = type;
        if (annexb_data != NULL && len > 0) {
            ev.annexb.assign(annexb_data, annexb_data + len);
        }
        ev.sender_nanos = sender_nanos;
        video_frames.push_back(ev);
    }

    virtual void onAudioStarted(const plat::AudioStreamId& id,
                                const audio::AudioFormat& /*format*/,
                                uint32_t /*first_sample*/) {
        audio_started.push_back(id);
    }

    virtual void onAudioPcm(const plat::AudioStreamId& id,
                            const audio::AudioFormat& /*format*/,
                            const int16_t* samples,
                            size_t sample_count,
                            uint16_t sequence,
                            uint32_t rtp_timestamp) {
        AudioPcmEvent ev;
        ev.id = id;
        if (samples != NULL && sample_count > 0) {
            ev.samples.assign(samples, samples + sample_count);
        }
        ev.seq = sequence;
        ev.ts = rtp_timestamp;
        audio_pcm.push_back(ev);
    }

    virtual void onAudioPacketLost(const plat::AudioStreamId& /*id*/,
                                   const audio::AudioFormat& /*format*/,
                                   uint16_t lost_sequence) {
        audio_lost.push_back(lost_sequence);
    }

    virtual void onAudioStopped(const plat::AudioStreamId& id) {
        audio_stopped.push_back(id);
    }

    virtual void onAudioDuck(bool ducked) {
        duck_events.push_back(ducked);
    }

    virtual void onMicrophoneStarted(const plat::AudioStreamId& id,
                                     const audio::MicStreamParams& params,
                                     const plat::Address& peer_dest) {
        mic_started.push_back(id);
        last_mic_params = params;
        last_mic_dest = peer_dest;
    }

    virtual void onMicrophoneStopped(const plat::AudioStreamId& id) {
        mic_stopped.push_back(id);
    }

    virtual void onIapMessage(const uint8_t* data, size_t len) {
        Bytes msg;
        if (data != NULL && len > 0) {
            msg.assign(data, data + len);
        }
        iap_messages.push_back(msg);
    }
};

// ---- Socket client helper driving Reactor in lockstep ----

bool waitUntilConnected(plat::Reactor& reactor, plat::TcpConnection& client) {
    const int64_t deadline = plat::monotonicMillis() + 2000;
    while (client.connecting()) {
        reactor.runOnce(5);
        plat::IoStatus st = client.finishConnect();
        if (st == plat::kIoOk) return true;
        if (st == plat::kIoError) return false;
        if (plat::monotonicMillis() >= deadline) return false;
    }
    reactor.runOnce(5);
    return client.isOpen();
}

struct NetPhoneClient {
    plat::Reactor& reactor;
    Controller ctrl;
    crypto::X25519KeyPair eph;
    std::string acc_id;
    Bytes acc_ltpk;
    Bytes shared;
    std::unique_ptr<ControlCipher> control_cipher;
    std::unique_ptr<ControlCipher> event_cipher;
    rtsp::Parser ctrl_parser;
    rtsp::Parser event_parser;
    uint32_t cseq;
    plat::TcpConnection ctrl_conn;
    plat::TcpConnection event_conn;

    NetPhoneClient(plat::Reactor& r,
                   const std::string& ltsk_label,
                   const std::string& pairing_id,
                   const std::string& eph_label)
        : reactor(r), ctrl(ltsk_label, pairing_id), cseq(0) {
        const Bytes s = prefix(shaStr(eph_label), 32);
        crypto::x25519FromSecret(&s[0], eph);
    }

    ~NetPhoneClient() {
        event_conn.close();
        ctrl_conn.close();
    }

    bool connectControl(const plat::Address& addr) {
        if (!ctrl_conn.connect(addr)) return false;
        if (!waitUntilConnected(reactor, ctrl_conn)) return false;
        // Let the server accept the connection.
        for (int i = 0; i < 4; ++i) reactor.runOnce(5);
        return true;
    }

    bool connectEvent(const plat::Address& addr) {
        if (!event_conn.connect(addr)) return false;
        if (!waitUntilConnected(reactor, event_conn)) return false;
        for (int i = 0; i < 4; ++i) reactor.runOnce(5);
        return true;
    }

    bool sendAll(plat::TcpConnection& conn, const Bytes& wire) {
        size_t off = 0;
        const int64_t deadline = plat::monotonicMillis() + 2000;
        while (off < wire.size()) {
            size_t sent = 0;
            plat::IoStatus st =
                plat::socketSend(conn.handle(), &wire[off], wire.size() - off, sent);
            if (st == plat::kIoOk) {
                off += sent;
                reactor.runOnce(1);
                continue;
            }
            if (st == plat::kIoWouldBlock) {
                reactor.runOnce(5);
                if (plat::monotonicMillis() >= deadline) return false;
                continue;
            }
            return false;
        }
        return true;
    }

    bool call(const std::string& method,
              const std::string& path,
              const std::string& ctype,
              const Bytes& body,
              int& status_out,
              rtsp::Request& raw_out) {
        rtsp::HeaderList h;
        if (!ctype.empty()) {
            h.push_back(rtsp::Header("Content-Type", ctype));
        }
        const uint32_t my_cseq = ++cseq;
        h.push_back(rtsp::Header("CSeq", dec(my_cseq)));
        h.push_back(rtsp::Header("User-Agent", "AirPlay/770.8.1"));
        Bytes plain_req;
        rtsp::buildRequest(method, path, "RTSP/1.0", h, body, plain_req);

        Bytes wire_req;
        const bool encrypted = (control_cipher.get() != NULL);
        if (encrypted) {
            if (!control_cipher->encrypt(plain_req, wire_req)) return false;
        } else {
            wire_req = plain_req;
        }

        if (!sendAll(ctrl_conn, wire_req)) return false;

        std::vector<rtsp::Request> msgs;
        const int64_t deadline = plat::monotonicMillis() + 3000;
        uint8_t buf[16 * 1024];
        while (msgs.empty()) {
            reactor.runOnce(5);
            size_t got = 0;
            plat::IoStatus st = ctrl_conn.read(buf, sizeof(buf), got);
            if (st == plat::kIoOk && got > 0) {
                Bytes raw(buf, buf + got);
                Bytes plain;
                if (encrypted) {
                    if (!control_cipher->feed(raw, plain)) return false;
                } else {
                    plain = raw;
                }
                if (!ctrl_parser.feed(plain, msgs)) return false;
                continue;
            }
            if (st == plat::kIoWouldBlock) {
                if (plat::monotonicMillis() >= deadline) return false;
                continue;
            }
            return false;
        }
        if (msgs.size() != 1U || !msgs[0].isResponse()) return false;
        raw_out = msgs[0];
        status_out = atoi(raw_out.path.c_str());
        return raw_out.header("cseq") == dec(my_cseq);
    }

    bool callPlist(const std::string& method,
                   const std::string& path,
                   const bplist::Value& req_body,
                   int& status_out,
                   bplist::Value& resp_plist_out) {
        rtsp::Request raw;
        if (!call(method, path, rtsp::kContentTypeBinaryPlist, encodePlist(req_body), status_out, raw)) {
            return false;
        }
        if (!raw.body.empty()) {
            return bplist::decode(raw.body, resp_plist_out);
        }
        resp_plist_out = bplist::Value::makeDict();
        return true;
    }

    bool callTlv(const std::string& path, const Items& req_items, Items& resp_items) {
        int status = 0;
        rtsp::Request raw;
        if (!call("POST", path, rtsp::kContentTypePairingTlv8, tlv8::encode(req_items), status, raw)) {
            return false;
        }
        if (status != 200) return false;
        return tlv8::decode(raw.body, resp_items);
    }

    bool pairSetup(const std::string& srp_label) {
        Items m1;
        m1.push_back(tlv8::Item::fromByte(tlv8::kTagMethod, 0));
        m1.push_back(tlv8::Item::fromByte(tlv8::kTagState, 1));
        Items m2;
        if (!callTlv("/pair-setup", m1, m2)) return false;
        const Bytes b_pub = valueOf(m2, tlv8::kTagPublicKey);
        const Bytes salt = valueOf(m2, tlv8::kTagSalt);
        if (b_pub.size() != 384U || salt.size() != 16U) return false;

        SrpClient srp_client(srp_label);
        if (!srp_client.compute(b_pub, salt, "3939")) return false;

        Items m3;
        m3.push_back(tlv8::Item::fromByte(tlv8::kTagState, 3));
        m3.push_back(tlv8::Item(tlv8::kTagPublicKey, srp_client.a_pub));
        m3.push_back(tlv8::Item(tlv8::kTagProof, srp_client.m1));
        Items m4;
        if (!callTlv("/pair-setup", m3, m4)) return false;
        if (valueOf(m4, tlv8::kTagProof) != srp_client.m2) return false;

        const Bytes enc_key = hkdf(srp_client.k, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info");
        Bytes c_data = hkdf(srp_client.k, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info");
        cat(c_data, strBytes(ctrl.id));
        cat(c_data, ctrl.ltpk());
        Items sub5;
        sub5.push_back(tlv8::Item(tlv8::kTagIdentifier, strBytes(ctrl.id)));
        sub5.push_back(tlv8::Item(tlv8::kTagPublicKey, ctrl.ltpk()));
        sub5.push_back(tlv8::Item(tlv8::kTagSignature, ctrl.sign(c_data)));
        Items m5;
        m5.push_back(tlv8::Item::fromByte(tlv8::kTagState, 5));
        m5.push_back(tlv8::Item(tlv8::kTagEncryptedData,
                                sealWith(enc_key, labelNonce("PS-Msg05"), Bytes(), tlv8::encode(sub5))));
        Items m6;
        if (!callTlv("/pair-setup", m5, m6)) return false;
        Bytes m6_plain;
        if (!openWith(enc_key, labelNonce("PS-Msg06"), valueOf(m6, tlv8::kTagEncryptedData), m6_plain)) {
            return false;
        }
        Items acc;
        if (!tlv8::decode(m6_plain, acc)) return false;
        const Bytes id = valueOf(acc, tlv8::kTagIdentifier);
        const Bytes ltpk = valueOf(acc, tlv8::kTagPublicKey);
        const Bytes sig = valueOf(acc, tlv8::kTagSignature);
        if (id.empty() || ltpk.size() != 32U || sig.size() != 64U) return false;
        Bytes a_data = hkdf(srp_client.k, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info");
        cat(a_data, id);
        cat(a_data, ltpk);
        if (!crypto::ed25519Verify(&ltpk[0], &a_data[0], a_data.size(), &sig[0])) return false;
        acc_id.assign(id.begin(), id.end());
        acc_ltpk = ltpk;
        return true;
    }

    bool pairVerify() {
        const Bytes eph_pub(eph.public_key, eph.public_key + 32);
        Items m1;
        m1.push_back(tlv8::Item::fromByte(tlv8::kTagState, 1));
        m1.push_back(tlv8::Item(tlv8::kTagPublicKey, eph_pub));
        Items m2;
        if (!callTlv("/pair-verify", m1, m2)) return false;
        const Bytes acc_eph = valueOf(m2, tlv8::kTagPublicKey);
        if (acc_eph.size() != 32U || acc_ltpk.size() != 32U) return false;
        shared.assign(32, 0);
        if (!crypto::x25519SharedSecret(eph.secret_key, &acc_eph[0], &shared[0])) return false;

        const Bytes pv_key = hkdf(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info");
        Bytes m2_plain;
        if (!openWith(pv_key, labelNonce("PV-Msg02"), valueOf(m2, tlv8::kTagEncryptedData), m2_plain)) {
            return false;
        }
        Items sub2;
        if (!tlv8::decode(m2_plain, sub2)) return false;
        if (valueOf(sub2, tlv8::kTagIdentifier) != strBytes(acc_id)) return false;
        const Bytes sig = valueOf(sub2, tlv8::kTagSignature);
        Bytes signed2 = acc_eph;
        cat(signed2, strBytes(acc_id));
        cat(signed2, eph_pub);
        if (sig.size() != 64U || !crypto::ed25519Verify(&acc_ltpk[0], &signed2[0], signed2.size(), &sig[0])) {
            return false;
        }

        Bytes mine = eph_pub;
        cat(mine, strBytes(ctrl.id));
        cat(mine, acc_eph);
        Items sub3;
        sub3.push_back(tlv8::Item(tlv8::kTagIdentifier, strBytes(ctrl.id)));
        sub3.push_back(tlv8::Item(tlv8::kTagSignature, ctrl.sign(mine)));
        Items m3;
        m3.push_back(tlv8::Item::fromByte(tlv8::kTagState, 3));
        m3.push_back(tlv8::Item(tlv8::kTagEncryptedData,
                                sealWith(pv_key, labelNonce("PV-Msg03"), Bytes(), tlv8::encode(sub3))));
        Items m4;
        if (!callTlv("/pair-verify", m3, m4)) return false;
        const Bytes st4 = valueOf(m4, tlv8::kTagState);
        if (st4.size() != 1U || st4[0] != 4) return false;

        const Bytes c_read = hkdf(shared, "Control-Salt", "Control-Read-Encryption-Key");
        const Bytes c_write = hkdf(shared, "Control-Salt", "Control-Write-Encryption-Key");
        control_cipher.reset(new ControlCipher(&c_read[0], &c_write[0]));

        const Bytes e_read = hkdf(shared, "Events-Salt", "Events-Write-Encryption-Key");
        const Bytes e_write = hkdf(shared, "Events-Salt", "Events-Read-Encryption-Key");
        event_cipher.reset(new ControlCipher(&e_read[0], &e_write[0]));
        return true;
    }

    Bytes streamOutputKey(uint64_t id) const {
        return hkdf(shared, "DataStream-Salt" + dec(id), "DataStream-Output-Encryption-Key");
    }

    Bytes streamInputKey(uint64_t id) const {
        return hkdf(shared, "DataStream-Salt" + dec(id), "DataStream-Input-Encryption-Key");
    }

    bool readEventCommands(size_t expected_count, std::vector<rtsp::Request>& out_reqs) {
        const int64_t deadline = plat::monotonicMillis() + 2000;
        uint8_t buf[8192];
        while (out_reqs.size() < expected_count) {
            reactor.runOnce(5);
            size_t got = 0;
            plat::IoStatus st = event_conn.read(buf, sizeof(buf), got);
            if (st == plat::kIoOk && got > 0) {
                Bytes raw(buf, buf + got);
                Bytes plain;
                if (!event_cipher->feed(raw, plain)) return false;
                if (!event_parser.feed(plain, out_reqs)) return false;
                continue;
            }
            if (st == plat::kIoWouldBlock) {
                if (plat::monotonicMillis() >= deadline) return false;
                continue;
            }
            return false;
        }
        // Acknowledge each received event command with an encrypted 200 OK.
        for (size_t i = 0; i < out_reqs.size(); ++i) {
            const std::string resp =
                "RTSP/1.0 200 OK\r\nCSeq: " + out_reqs[i].header("cseq") + "\r\nContent-Length: 0\r\n\r\n";
            Bytes wire;
            if (!event_cipher->encrypt(strBytes(resp), wire)) return false;
            if (!sendAll(event_conn, wire)) return false;
        }
        for (int i = 0; i < 4; ++i) reactor.runOnce(5);
        return true;
    }
};

Bytes buildScreenHeader(uint16_t opcode, uint32_t body_size, uint64_t ntp_le, float w, float h) {
    Bytes hd(128, 0);
    putLe(hd, 0, body_size, 4);
    putLe(hd, 4, opcode, 2);
    putLe(hd, 8, ntp_le, 8);
    if (opcode == 1) {
        uint32_t wb = 0;
        uint32_t hb = 0;
        memcpy(&wb, &w, 4);
        memcpy(&hb, &h, 4);
        putLe(hd, 16, wb, 4);
        putLe(hd, 20, hb, 4);
    }
    return hd;
}

Bytes buildAvcCRecord(const Bytes& sps, const Bytes& pps) {
    Bytes avcc;
    avcc.push_back(0x01);
    avcc.push_back(sps.size() > 1 ? sps[1] : 0x64);
    avcc.push_back(sps.size() > 2 ? sps[2] : 0x00);
    avcc.push_back(sps.size() > 3 ? sps[3] : 0x1f);
    avcc.push_back(0xff);  // 4-byte NAL lengths
    avcc.push_back(0xe1);  // 1 SPS
    avcc.push_back(static_cast<uint8_t>(sps.size() >> 8));
    avcc.push_back(static_cast<uint8_t>(sps.size()));
    cat(avcc, sps);
    avcc.push_back(0x01);  // 1 PPS
    avcc.push_back(static_cast<uint8_t>(pps.size() >> 8));
    avcc.push_back(static_cast<uint8_t>(pps.size()));
    cat(avcc, pps);
    return avcc;
}

Bytes buildIapSealedCommPackage(const Bytes& seed_key, uint64_t counter, const Bytes& iap_body) {
    const uint32_t pkg_size = static_cast<uint32_t>(32U + iap_body.size());
    Bytes pkg(pkg_size, 0);
    putBe(pkg, 0, pkg_size, 4);
    putBe(pkg, 16, 0x636f6d6dU, 4);  // 'comm'
    for (size_t i = 0; i < iap_body.size(); ++i) {
        pkg[32U + i] = iap_body[i];
    }

    Bytes aad(2, 0);
    putLe(aad, 0, pkg.size(), 2);
    uint8_t nonce[12];
    crypto::makeCounterNonce(counter, nonce);
    Bytes sealed;
    crypto::chacha20Poly1305Seal(&seed_key[0], nonce, &aad[0], 2, &pkg[0], pkg.size(), sealed);
    Bytes frame = aad;
    cat(frame, sealed);
    return frame;
}


// ---- Helpers shared by the edge-case tests ----

void pump(plat::Reactor& reactor, int rounds = 6) {
    for (int i = 0; i < rounds; ++i) reactor.runOnce(5);
}

// Connects, pairs and verifies `phone` on `addr`.
bool pairAndVerify(NetPhoneClient& phone, const plat::Address& addr, const std::string& srp_label) {
    return phone.connectControl(addr) && phone.pairSetup(srp_label) && phone.pairVerify();
}

// Sends one stream SETUP with the given entries and returns the response `streams` array.
bool setupStreams(NetPhoneClient& phone,
                  const std::vector<bplist::Value>& entries,
                  std::vector<bplist::Value>& resp_entries) {
    bplist::Value arr = bplist::Value::makeArray();
    for (size_t i = 0; i < entries.size(); ++i) arr.asArray().push_back(entries[i]);
    bplist::Value req = bplist::Value::makeDict();
    req.set("streams", arr);
    bplist::Value resp;
    int status = 0;
    if (!phone.callPlist("SETUP", "rtsp://127.0.0.1/streams", req, status, resp) || status != 200) {
        return false;
    }
    const bplist::Value* out = resp.find("streams");
    if (out == NULL || !out->isArray()) return false;
    resp_entries = out->asArray();
    return true;
}

bplist::Value screenEntry(int32_t type, int64_t conn_id) {
    bplist::Value e = bplist::Value::makeDict();
    e.set("type", bplist::Value::makeInt(type));
    e.set("streamConnectionID", bplist::Value::makeInt(conn_id));
    return e;
}

bplist::Value audioEntry(int32_t type, const char* audio_type, int64_t format_bits, int64_t conn_id) {
    bplist::Value e = bplist::Value::makeDict();
    e.set("type", bplist::Value::makeInt(type));
    e.set("audioType", bplist::Value::makeString(audio_type));
    e.set("audioFormat", bplist::Value::makeInt(format_bits));
    e.set("streamConnectionID", bplist::Value::makeInt(conn_id));
    return e;
}

bplist::Value iapEntry(int64_t seed) {
    bplist::Value e = bplist::Value::makeDict();
    e.set("type", bplist::Value::makeInt(130));
    e.set("clientTypeUUID", bplist::Value::makeString("e9459fd0-bcad-4c45-820f-1e72447ef2f2"));
    e.set("seed", bplist::Value::makeInt(seed));
    return e;
}

// One sealed screen VideoFrame message: [128-byte header | ciphertext | tag], AAD = header.
Bytes buildSealedScreenFrame(const Bytes& key, uint64_t counter, const Bytes& plain) {
    Bytes hdr = buildScreenHeader(0, static_cast<uint32_t>(plain.size() + 16U), 0, 0.0f, 0.0f);
    uint8_t nonce[12];
    crypto::makeCounterNonce(counter, nonce);
    Bytes sealed;
    crypto::chacha20Poly1305Seal(&key[0],
                                 nonce,
                                 &hdr[0],
                                 hdr.size(),
                                 plain.empty() ? NULL : &plain[0],
                                 plain.size(),
                                 sealed);
    cat(hdr, sealed);
    return hdr;
}

// A length-prefixed access unit of one NAL: [u32 BE len | first_byte | filler...].
Bytes lengthPrefixedNal(size_t nal_len, uint8_t first_byte) {
    Bytes out(4U + nal_len, 0x5a);
    putBe(out, 0, nal_len, 4);
    out[4] = first_byte;
    return out;
}

Bytes buildAudioPacket(const Bytes& key, uint8_t pt, uint16_t seq, uint32_t ts, uint64_t nonce, int16_t first) {
    int16_t samples[4] = {first, static_cast<int16_t>(first + 1), static_cast<int16_t>(first + 2),
                          static_cast<int16_t>(first + 3)};
    Bytes wire_pcm;
    audio::int16ToLpcm(samples, 4, wire_pcm, audio::kBigEndianSamples);
    uint8_t rtp_hdr[12];
    audio::buildRtpHeader(pt, false, seq, ts, 0U, rtp_hdr);
    Bytes pkt;
    audio::sealPacket(&key[0], rtp_hdr, &wire_pcm[0], wire_pcm.size(), nonce, pkt);
    return pkt;
}

bool connectTcp(plat::Reactor& reactor, plat::TcpConnection& conn, uint16_t port) {
    if (!conn.connect(plat::Address::ipv4Loopback(port))) return false;
    if (!waitUntilConnected(reactor, conn)) return false;
    pump(reactor, 4);
    return true;
}

// Storage + reactor every edge-case test needs.
struct Rig {
    TempDir dir;
    plat::OsRandomSource rng;
    pairing::Identity identity;
    plat::FilePairingStore store;
    plat::Reactor reactor;
    RecordingListener listener;
    bool ok;

    explicit Rig(const char* tag) : dir(tag), ok(false) {
        ok = plat::storageUsable(plat::loadOrCreateIdentity(dir.path, rng, identity)) &&
             plat::storageUsable(store.open(dir.path)) && reactor.init();
    }
};

plat::SessionServerConfig quietServerConfig() {
    plat::SessionServerConfig cfg;
    cfg.control_port = 0;
    cfg.ntp_request_interval_ms = 0;
    return cfg;
}

// =============================================================================================
// Test 1: Golden real-socket loopback E2E + Test 2: Persistent reconnect without pair-setup
// =============================================================================================

bool testGoldenRealSocketE2eAndReconnect() {
    TempDir dir("golden");
    plat::OsRandomSource rng;
    pairing::Identity identity;
    CHECK_TRUE(plat::storageUsable(plat::loadOrCreateIdentity(dir.path, rng, identity)));
    plat::FilePairingStore store;
    CHECK_TRUE(plat::storageUsable(store.open(dir.path)));

    const info::AirPlayConfig config = info::bmwEntryNav2_1280x480(true);

    plat::Reactor reactor;
    CHECK_TRUE(reactor.init());

    RecordingListener listener;
    RecordingSink sink;
    plat::MediaEngineConfig me_cfg;
    me_cfg.mic_silent_start_ms = 20;
    plat::MediaEngine media_engine(reactor, sink, me_cfg);

    plat::SessionServerConfig srv_cfg;
    srv_cfg.control_port = 0;
    srv_cfg.ntp_request_interval_ms = 25;
    plat::SessionServer server(
        reactor, config, identity, store, rng, listener, media_engine, NULL, srv_cfg);

    // Pre-configure night mode before any session connects; must flush when event channel opens.
    CHECK_TRUE(!server.setNightMode(true));
    CHECK_TRUE(server.start(plat::Address::ipv4Loopback(0)));
    CHECK_TRUE(server.controlPort() > 0);

    const plat::Address server_ctrl_addr = plat::Address::ipv4Loopback(server.controlPort());
    NetPhoneClient phone(reactor, "net-phone-ltsk", "AA11BB22-CC33-44DD-88EE-FF0011223344", "eph-1");
    CHECK_TRUE(phone.connectControl(server_ctrl_addr));
    CHECK_TRUE(server.hasActiveSession());

    // 1. Plaintext GET /info
    int status = 0;
    rtsp::Request raw_resp;
    CHECK_TRUE(phone.call("GET", "/info", "", Bytes(), status, raw_resp));
    CHECK_TRUE(status == 200);
    bplist::Value info_plist;
    CHECK_TRUE(bplist::decode(raw_resp.body, info_plist));
    CHECK_TRUE(info_plist.isDict());

    // 2. Pair-Setup M1..M6 + Pair-Verify M1..M4 over real TCP socket
    CHECK_TRUE(phone.pairSetup("srp-net-1"));
    CHECK_TRUE(store.size() == 1U);
    CHECK_TRUE(phone.pairVerify());
    CHECK_TRUE(server.activeSession()->encrypted());

    // 3. Encrypted GET /info
    CHECK_TRUE(phone.call("GET", "/info", "", Bytes(), status, raw_resp));
    CHECK_TRUE(status == 200);

    // 4. Open phone-side timing UDP socket and send session SETUP
    plat::UdpSocket phone_timing_udp;
    CHECK_TRUE(phone_timing_udp.open(plat::Address::ipv4Loopback(0)));

    bplist::Value setup_req = bplist::Value::makeDict();
    setup_req.set("timingPort", bplist::Value::makeInt(phone_timing_udp.port()));
    setup_req.set("keepAliveLowPower", bplist::Value::makeBool(true));
    setup_req.set("name", bplist::Value::makeString("Oguz iPhone"));
    setup_req.set("deviceID", bplist::Value::makeString("AA:BB:CC:DD:EE:FF"));
    setup_req.set("macAddress", bplist::Value::makeString("11:22:33:44:55:66"));
    setup_req.set("model", bplist::Value::makeString("iPhone16,2"));

    bplist::Value setup_resp;
    CHECK_TRUE(phone.callPlist("SETUP", "rtsp://127.0.0.1/session", setup_req, status, setup_resp));
    CHECK_TRUE(status == 200);
    const int64_t srv_timing_port = intAt(setup_resp, "timingPort");
    const int64_t srv_event_port = intAt(setup_resp, "eventPort");
    const int64_t srv_keepalive_port = intAt(setup_resp, "keepAlivePort");
    CHECK_TRUE(srv_timing_port > 0 && srv_event_port > 0 && srv_keepalive_port > 0);
    CHECK_TRUE(listener.device_info.name == "Oguz iPhone");
    CHECK_TRUE(listener.device_info.model == "iPhone16,2");

    // 5. NTP timing UDP exchange (answer two PT 210 requests: the initial one from openTiming
    // and the second one from the periodic ntp_request_interval_ms timer so ClockSync steps to synced)
    for (int round = 0; round < 2; ++round) {
        uint8_t ntp_buf[64];
        size_t got = 0;
        plat::Address from;
        const int64_t deadline = plat::monotonicMillis() + 1000;
        while (phone_timing_udp.receiveFrom(ntp_buf, sizeof(ntp_buf), got, from) != plat::kIoOk) {
            reactor.runOnce(5);
            CHECK_TRUE(plat::monotonicMillis() < deadline);
        }
        CHECK_TRUE(got == ntp::kPacketBytes);
        const uint64_t phone_ntp = ntp::ntpFromNanos(reactor.now() + 500000000LL);
        uint8_t reply[ntp::kPacketBytes];
        CHECK_TRUE(ntp::buildResponse(ntp_buf, got, phone_ntp, phone_ntp, reply));
        CHECK_TRUE(phone_timing_udp.sendTo(
                       reply, sizeof(reply), plat::Address::ipv4Loopback(static_cast<uint16_t>(srv_timing_port))) ==
                   plat::kIoOk);
        reactor.runOnce(5);
    }
    CHECK_TRUE(server.clockSync().synced());

    // Also verify phone->server PT 210 request gets a PT 211 response.
    {
        uint8_t req210[ntp::kPacketBytes];
        ntp::buildRequest(0x1122334455667788ULL, req210);
        CHECK_TRUE(phone_timing_udp.sendTo(
                       req210, sizeof(req210), plat::Address::ipv4Loopback(static_cast<uint16_t>(srv_timing_port))) ==
                   plat::kIoOk);
        uint8_t resp211[64];
        size_t got = 0;
        plat::Address from;
        const int64_t deadline = plat::monotonicMillis() + 1000;
        bool got_211 = false;
        while (plat::monotonicMillis() < deadline) {
            reactor.runOnce(5);
            if (phone_timing_udp.receiveFrom(resp211, sizeof(resp211), got, from) == plat::kIoOk) {
                ntp::Packet pkt;
                if (ntp::parsePacket(resp211, got, pkt) &&
                    pkt.payload_type == ntp::kPtResponse &&
                    pkt.originate == 0x1122334455667788ULL) {
                    got_211 = true;
                    break;
                }
            }
        }
        CHECK_TRUE(got_211);
    }

    // 6. Keep-alive UDP packets
    {
        const uint8_t ka_byte = 0x00;
        const plat::Address ka_dest =
            plat::Address::ipv4Loopback(static_cast<uint16_t>(srv_keepalive_port));
        CHECK_TRUE(phone_timing_udp.sendTo(&ka_byte, 1, ka_dest) == plat::kIoOk);
        CHECK_TRUE(phone_timing_udp.sendTo(&ka_byte, 1, ka_dest) == plat::kIoOk);
        for (int i = 0; i < 4; ++i) reactor.runOnce(5);
        CHECK_TRUE(server.keepAlivePacketsReceived() == 2U);
    }

    // 7. Connect Event TCP channel and verify pending nightMode is flushed immediately
    CHECK_TRUE(phone.connectEvent(plat::Address::ipv4Loopback(static_cast<uint16_t>(srv_event_port))));
    CHECK_TRUE(server.hasEventConnection());
    {
        std::vector<rtsp::Request> ev_reqs;
        CHECK_TRUE(phone.readEventCommands(1, ev_reqs));
        bplist::Value cmd;
        CHECK_TRUE(bplist::decode(ev_reqs[0].body, cmd));
        CHECK_TRUE(strAt(cmd, "type") == "setNightMode");
    }

    // 8. Stream SETUP: Screen (110), Main Audio + Mic (100), Alt Audio (101), iAP2 DataStream (130)
    plat::UdpSocket phone_mic_udp;
    CHECK_TRUE(phone_mic_udp.open(plat::Address::ipv4Loopback(0)));

    const uint64_t kScreenConnId = 1001ULL;
    const uint64_t kMainAudioConnId = 0x9000000000001234ULL;
    const uint64_t kAltAudioConnId = 2002ULL;
    const uint64_t kIapSeed = 3003ULL;

    bplist::Value s_screen = bplist::Value::makeDict();
    s_screen.set("type", bplist::Value::makeInt(110));
    s_screen.set("streamConnectionID", bplist::Value::makeInt(static_cast<int64_t>(kScreenConnId)));

    bplist::Value s_main_audio = bplist::Value::makeDict();
    s_main_audio.set("type", bplist::Value::makeInt(100));
    s_main_audio.set("audioType", bplist::Value::makeString("speechrecognition"));
    s_main_audio.set("audioFormat", bplist::Value::makeInt(0x10));  // 16 kHz mono LPCM
    s_main_audio.set("input", bplist::Value::makeBool(true));
    s_main_audio.set("dataPort", bplist::Value::makeInt(phone_mic_udp.port()));
    s_main_audio.set("streamConnectionID", bplist::Value::makeUInt(kMainAudioConnId));

    bplist::Value s_alt_audio = bplist::Value::makeDict();
    s_alt_audio.set("type", bplist::Value::makeInt(101));
    s_alt_audio.set("audioType", bplist::Value::makeString("media"));
    s_alt_audio.set("audioFormat", bplist::Value::makeInt(0x800));  // 44.1 kHz stereo LPCM
    s_alt_audio.set("streamConnectionID", bplist::Value::makeInt(static_cast<int64_t>(kAltAudioConnId)));

    bplist::Value s_iap = bplist::Value::makeDict();
    s_iap.set("type", bplist::Value::makeInt(130));
    s_iap.set("clientTypeUUID", bplist::Value::makeString("E9459FD0-BCAD-4C45-820F-1E72447EF2F2"));
    s_iap.set("seed", bplist::Value::makeInt(static_cast<int64_t>(kIapSeed)));
    s_iap.set("streamConnectionID", bplist::Value::makeInt(4004));

    bplist::Value streams_arr = bplist::Value::makeArray();
    streams_arr.asArray().push_back(s_screen);
    streams_arr.asArray().push_back(s_main_audio);
    streams_arr.asArray().push_back(s_alt_audio);
    streams_arr.asArray().push_back(s_iap);
    bplist::Value streams_req = bplist::Value::makeDict();
    streams_req.set("streams", streams_arr);

    bplist::Value streams_resp;
    CHECK_TRUE(phone.callPlist("SETUP", "rtsp://127.0.0.1/streams", streams_req, status, streams_resp));
    CHECK_TRUE(status == 200);
    const bplist::Value* resp_arr = streams_resp.find("streams");
    CHECK_TRUE(resp_arr != NULL && resp_arr->isArray() && resp_arr->asArray().size() == 4U);

    const int64_t screen_port = intAt(resp_arr->asArray()[0], "dataPort");
    const int64_t main_audio_port = intAt(resp_arr->asArray()[1], "dataPort");
    const int64_t alt_audio_port = intAt(resp_arr->asArray()[2], "dataPort");
    const int64_t iap_port = intAt(resp_arr->asArray()[3], "dataPort");
    CHECK_TRUE(screen_port > 0 && main_audio_port > 0 && alt_audio_port > 0 && iap_port > 0);

    // 9. RECORD
    CHECK_TRUE(phone.call("RECORD", "rtsp://127.0.0.1/session", "", Bytes(), status, raw_resp));
    CHECK_TRUE(status == 200);
    CHECK_TRUE(listener.active_count == 1);

    // 10. Screen TCP stream: send avcC config (inside an ISO box prefix) + 2 sealed H.264 frames
    plat::TcpConnection screen_conn;
    CHECK_TRUE(screen_conn.connect(plat::Address::ipv4Loopback(static_cast<uint16_t>(screen_port))));
    CHECK_TRUE(waitUntilConnected(reactor, screen_conn));
    for (int i = 0; i < 4; ++i) reactor.runOnce(5);

    {
        Bytes sps = test_support::hexToBytes("6764001facd9405005bb0110000003001000000303c0f1831960");
        Bytes pps = test_support::hexToBytes("68eebcb0");
        Bytes avcc = buildAvcCRecord(sps, pps);
        // Wrap avcC in an 8-byte ISO atom header [size BE | 'avcC'] to test box stripping.
        Bytes boxed(8, 0);
        putBe(boxed, 0, 8U + avcc.size(), 4);
        memcpy(&boxed[4], "avcC", 4);
        cat(boxed, avcc);

        Bytes cfg_msg = buildScreenHeader(1, static_cast<uint32_t>(boxed.size()), 0, 1280.0f, 480.0f);
        cat(cfg_msg, boxed);
        CHECK_TRUE(phone.sendAll(screen_conn, cfg_msg));

        const Bytes screen_key = phone.streamOutputKey(kScreenConnId);
        for (uint64_t fc = 0; fc < 2; ++fc) {
            Bytes nal_body = test_support::hexToBytes(fc == 0 ? "65888421a0ff0011" : "419a223344");
            Bytes avcc_frame(4, 0);
            putBe(avcc_frame, 0, nal_body.size(), 4);
            cat(avcc_frame, nal_body);

            const uint64_t ntp_le = (100ULL + fc) << 32;
            Bytes hdr = buildScreenHeader(
                0, static_cast<uint32_t>(avcc_frame.size() + 16U), ntp_le, 0.0f, 0.0f);
            uint8_t nonce[12];
            crypto::makeCounterNonce(fc, nonce);
            Bytes sealed;
            crypto::chacha20Poly1305Seal(&screen_key[0],
                                         nonce,
                                         &hdr[0],
                                         hdr.size(),
                                         &avcc_frame[0],
                                         avcc_frame.size(),
                                         sealed);
            Bytes frame_msg = hdr;
            cat(frame_msg, sealed);
            CHECK_TRUE(phone.sendAll(screen_conn, frame_msg));
        }
        for (int i = 0; i < 6; ++i) reactor.runOnce(5);
        CHECK_TRUE(sink.video_configs.size() == 1U);
        CHECK_TRUE(sink.video_configs[0].codec == stream::CODEC_H264_AVCC);
        CHECK_TRUE(sink.video_configs[0].width == 1280.0f);
        CHECK_TRUE(sink.video_configs[0].height == 480.0f);
        CHECK_TRUE(sink.video_frames.size() == 2U);
        CHECK_TRUE(sink.video_frames[0].annexb ==
                   test_support::hexToBytes("0000000165888421a0ff0011"));
        CHECK_TRUE(sink.video_frames[1].annexb ==
                   test_support::hexToBytes("00000001419a223344"));
    }

    // 11. Audio UDP stream: send reordered + duplicate RTP LPCM packets to main_audio_port
    {
        const Bytes audio_key = phone.streamOutputKey(kMainAudioConnId);
        const int send_order[4] = {0, 2, 1, 2};  // seq 2 arrives before seq 1, plus duplicate seq 2
        for (int idx = 0; idx < 4; ++idx) {
            const int seq_i = send_order[idx];
            int16_t samples[4] = {
                static_cast<int16_t>(100 + seq_i * 10),
                static_cast<int16_t>(101 + seq_i * 10),
                static_cast<int16_t>(102 + seq_i * 10),
                static_cast<int16_t>(103 + seq_i * 10)
            };
            Bytes wire_pcm;
            audio::int16ToLpcm(samples, 4, wire_pcm, audio::kBigEndianSamples);
            uint8_t rtp_hdr[12];
            audio::buildRtpHeader(
                100, seq_i == 0, static_cast<uint16_t>(500 + seq_i), 1000U + seq_i * 4U, 0x12345678U, rtp_hdr);
            Bytes pkt;
            CHECK_TRUE(audio::sealPacket(
                &audio_key[0], rtp_hdr, &wire_pcm[0], wire_pcm.size(), static_cast<uint64_t>(seq_i), pkt));
            CHECK_TRUE(phone_timing_udp.sendTo(
                           &pkt[0],
                           pkt.size(),
                           plat::Address::ipv4Loopback(static_cast<uint16_t>(main_audio_port))) ==
                       plat::kIoOk);
        }
        for (int i = 0; i < 6; ++i) reactor.runOnce(5);
        CHECK_TRUE(sink.audio_started.size() == 1U);
        CHECK_TRUE(sink.audio_pcm.size() == 3U);
        CHECK_TRUE(sink.audio_pcm[0].seq == 500U && sink.audio_pcm[0].samples[0] == 100);
        CHECK_TRUE(sink.audio_pcm[1].seq == 501U && sink.audio_pcm[1].samples[0] == 110);
        CHECK_TRUE(sink.audio_pcm[2].seq == 502U && sink.audio_pcm[2].samples[0] == 120);
    }

    // 12. Microphone RTP uplink: push from reactor thread AND submit from worker thread
    CHECK_TRUE(sink.mic_started.size() == 1U);
    CHECK_TRUE(media_engine.microphoneActive());
    {
        const size_t spf = sink.last_mic_params.samplesPerFrame();
        CHECK_TRUE(spf > 0);
        std::vector<int16_t> frame1(spf);
        std::vector<int16_t> frame2(spf);
        for (size_t i = 0; i < spf; ++i) {
            frame1[i] = static_cast<int16_t>(300 + static_cast<int>(i));
            frame2[i] = static_cast<int16_t>(700 + static_cast<int>(i));
        }
        CHECK_TRUE(media_engine.pushMicrophonePcm(&frame1[0], frame1.size()) == 1U);

        // Submit second frame from a separate worker thread via submitMicrophonePcm.
        struct WorkerCtx {
            plat::MediaEngine* eng;
            const int16_t* data;
            size_t len;
            bool ok;
            static void run(void* p) {
                WorkerCtx* c = static_cast<WorkerCtx*>(p);
                c->ok = c->eng->submitMicrophonePcm(c->data, c->len);
            }
        } wctx = {&media_engine, &frame2[0], frame2.size(), false};
        plat::Thread worker;
        CHECK_TRUE(worker.start(&WorkerCtx::run, &wctx));
        worker.join();
        CHECK_TRUE(wctx.ok);
        for (int i = 0; i < 6; ++i) reactor.runOnce(5);

        const Bytes mic_in_key = phone.streamInputKey(kMainAudioConnId);
        for (int pkt_idx = 0; pkt_idx < 2; ++pkt_idx) {
            uint8_t rx_buf[2048];
            size_t got = 0;
            plat::Address from;
            CHECK_TRUE(phone_mic_udp.receiveFrom(rx_buf, sizeof(rx_buf), got, from) == plat::kIoOk);
            audio::RtpHeader hdr;
            Bytes payload;
            CHECK_TRUE(audio::openPacket(&mic_in_key[0], rx_buf, got, hdr, payload) == audio::kOpenOk);
            CHECK_TRUE(hdr.sequence == static_cast<uint16_t>(pkt_idx));
            std::vector<int16_t> decoded;
            CHECK_TRUE(audio::lpcmToInt16(&payload[0], payload.size(), decoded) == spf);
            CHECK_TRUE(decoded[0] == (pkt_idx == 0 ? 300 : 700));
        }
    }

    // 13. iAP2 DataStream TCP tunnel (type 130)
    plat::TcpConnection iap_conn;
    CHECK_TRUE(iap_conn.connect(plat::Address::ipv4Loopback(static_cast<uint16_t>(iap_port))));
    CHECK_TRUE(waitUntilConnected(reactor, iap_conn));
    for (int i = 0; i < 4; ++i) reactor.runOnce(5);
    {
        const Bytes iap_key = phone.streamOutputKey(kIapSeed);
        const Bytes iap_payload = test_support::hexToBytes("ff5a00104000000100001d0200010008");
        const Bytes sealed_pkg = buildIapSealedCommPackage(iap_key, 0, iap_payload);
        CHECK_TRUE(phone.sendAll(iap_conn, sealed_pkg));
        for (int i = 0; i < 6; ++i) reactor.runOnce(5);
        CHECK_TRUE(sink.iap_messages.size() == 1U);
        CHECK_TRUE(sink.iap_messages[0] == iap_payload);
    }

    // 14. Outbound EventChannel commands (HID report, Siri, iAPSendMessage, forceKeyFrame)
    {
        hid::KnobState ks;
        ks.home = true;
        ks.wheel = 1;
        const Bytes knob_rep = hid::knobReport(ks);
        CHECK_TRUE(server.sendHidReport(hid::kUidKnob, knob_rep));
        CHECK_TRUE(server.requestSiri());
        const Bytes iap_out = test_support::hexToBytes("ff5a000a4000");
        CHECK_TRUE(server.sendIapMessage(iap_out));
        CHECK_TRUE(server.requestKeyFrame(110));

        // 1 hidSendReport + 2 requestSiri (action 2 & 3) + 1 iAPSendMessage + 1 forceKeyFrame = 5
        std::vector<rtsp::Request> ev_reqs;
        CHECK_TRUE(phone.readEventCommands(5, ev_reqs));
        CHECK_TRUE(server.activeSession()->events().responsesReceived() == 6U);
    }

    // 15. POST /feedback
    {
        bplist::Value fb_resp;
        CHECK_TRUE(phone.callPlist(
            "POST", "rtsp://127.0.0.1/feedback", bplist::Value::makeDict(), status, fb_resp));
        CHECK_TRUE(status == 200);
        const bplist::Value* fb_streams = fb_resp.find("streams");
        CHECK_TRUE(fb_streams != NULL && fb_streams->isArray() && fb_streams->asArray().size() == 2U);
        CHECK_TRUE(intAt(fb_streams->asArray()[0], "sampleRate") == 16000);
        uint64_t fb_cid = 0;
        const bplist::Value* cid_v = fb_streams->asArray()[0].find("streamConnectionID");
        CHECK_TRUE(cid_v != NULL && session::Session::plistUnsignedId(*cid_v, fb_cid));
        CHECK_TRUE(fb_cid == kMainAudioConnId);
    }

    // 16. POST /command duckAudio -> unduckAudio -> requestUI
    {
        bplist::Value cmd = bplist::Value::makeDict();
        cmd.set("type", bplist::Value::makeString("duckAudio"));
        bplist::Value cmd_resp;
        CHECK_TRUE(phone.callPlist("POST", "/command", cmd, status, cmd_resp));
        CHECK_TRUE(status == 200 && media_engine.isDucked());

        cmd.set("type", bplist::Value::makeString("unduckAudio"));
        CHECK_TRUE(phone.callPlist("POST", "/command", cmd, status, cmd_resp));
        CHECK_TRUE(status == 200 && !media_engine.isDucked());

        cmd.set("type", bplist::Value::makeString("requestUI"));
        CHECK_TRUE(phone.callPlist("POST", "/command", cmd, status, cmd_resp));
        CHECK_TRUE(status == 200 && listener.host_ui_count == 1);
    }

    // 17. Partial TEARDOWN (101) then whole-session TEARDOWN
    {
        bplist::Value td101_entry = bplist::Value::makeDict();
        td101_entry.set("type", bplist::Value::makeInt(101));
        bplist::Value td101_arr = bplist::Value::makeArray();
        td101_arr.asArray().push_back(td101_entry);
        bplist::Value td101 = bplist::Value::makeDict();
        td101.set("streams", td101_arr);
        bplist::Value td_resp;
        CHECK_TRUE(phone.callPlist("TEARDOWN", "rtsp://127.0.0.1/streams", td101, status, td_resp));
        CHECK_TRUE(status == 200);
        CHECK_TRUE(media_engine.activeAudioCount() == 1U);

        CHECK_TRUE(phone.callPlist(
            "TEARDOWN", "rtsp://127.0.0.1/session", bplist::Value::makeDict(), status, td_resp));
        CHECK_TRUE(status == 200);
        CHECK_TRUE(media_engine.activeAudioCount() == 0U);
        CHECK_TRUE(media_engine.activeScreenCount() == 0U);
        CHECK_TRUE(!media_engine.hasDataStream());
    }

    // 18. Disconnect control socket -> session ends cleanly
    iap_conn.close();
    screen_conn.close();
    phone.event_conn.close();
    phone.ctrl_conn.close();
    for (int i = 0; i < 6; ++i) reactor.runOnce(5);
    CHECK_TRUE(!server.hasActiveSession());
    CHECK_TRUE(listener.ended_count == 1);

    // 19. Reconnect using persisted identity + controller pairing from disk (NO pair-setup!)
    {
        pairing::Identity reloaded_id;
        CHECK_TRUE(plat::storageUsable(plat::loadOrCreateIdentity(dir.path, rng, reloaded_id)));
        CHECK_TRUE(reloaded_id.pairing_id == identity.pairing_id);

        plat::FilePairingStore reloaded_store;
        CHECK_TRUE(plat::storageUsable(reloaded_store.open(dir.path)));
        CHECK_TRUE(reloaded_store.size() == 1U);

        NetPhoneClient phone2(
            reactor, "net-phone-ltsk", "AA11BB22-CC33-44DD-88EE-FF0011223344", "eph-2");
        phone2.acc_id = phone.acc_id;
        phone2.acc_ltpk = phone.acc_ltpk;
        CHECK_TRUE(phone2.connectControl(server_ctrl_addr));
        CHECK_TRUE(phone2.pairVerify());
        CHECK_TRUE(phone2.call("GET", "/info", "", Bytes(), status, raw_resp));
        CHECK_TRUE(status == 200);
    }

    server.stop();
    return true;
}

// =============================================================================================
// Test 2: Peer address filtering & single-session protection
// =============================================================================================

bool testPeerFilteringAndSingleSessionProtection() {
    TempDir dir("peers");
    plat::OsRandomSource rng;
    pairing::Identity identity;
    CHECK_TRUE(plat::storageUsable(plat::loadOrCreateIdentity(dir.path, rng, identity)));
    plat::FilePairingStore store;
    CHECK_TRUE(plat::storageUsable(store.open(dir.path)));

    plat::Reactor reactor;
    CHECK_TRUE(reactor.init());
    RecordingListener listener;
    RecordingSink sink;
    plat::MediaEngine media_engine(reactor, sink);
    plat::SessionServerConfig srv_cfg;
    srv_cfg.control_port = 0;
    srv_cfg.ntp_request_interval_ms = 0;
    plat::SessionServer server(reactor,
                               info::bmwEntryNav2_800x480(false),
                               identity,
                               store,
                               rng,
                               listener,
                               media_engine,
                               NULL,
                               srv_cfg);
    CHECK_TRUE(server.start());  // dual-stack [::]:0 or 0.0.0.0:0

    const plat::Address v4_ctrl = plat::Address::ipv4Loopback(server.controlPort());
    NetPhoneClient phone(reactor, "peer-ltsk", "11112222-3333-4444-8888-99990000AAAA", "peer-eph");
    CHECK_TRUE(phone.connectControl(v4_ctrl));
    CHECK_TRUE(phone.pairSetup("peer-srp"));
    CHECK_TRUE(phone.pairVerify());

    // Open session ports + screen + audio
    bplist::Value setup_req = bplist::Value::makeDict();
    setup_req.set("timingPort", bplist::Value::makeInt(55555));
    bplist::Value setup_resp;
    int status = 0;
    CHECK_TRUE(phone.callPlist("SETUP", "rtsp://127.0.0.1/session", setup_req, status, setup_resp));
    CHECK_TRUE(status == 200);
    const uint16_t ev_port = static_cast<uint16_t>(intAt(setup_resp, "eventPort"));
    const uint16_t tm_port = static_cast<uint16_t>(intAt(setup_resp, "timingPort"));

    bplist::Value s_screen = bplist::Value::makeDict();
    s_screen.set("type", bplist::Value::makeInt(110));
    s_screen.set("streamConnectionID", bplist::Value::makeInt(10));
    bplist::Value s_audio = bplist::Value::makeDict();
    s_audio.set("type", bplist::Value::makeInt(100));
    s_audio.set("audioType", bplist::Value::makeString("media"));
    s_audio.set("audioFormat", bplist::Value::makeInt(0x800));
    s_audio.set("streamConnectionID", bplist::Value::makeInt(20));
    bplist::Value s_arr = bplist::Value::makeArray();
    s_arr.asArray().push_back(s_screen);
    s_arr.asArray().push_back(s_audio);
    bplist::Value s_req = bplist::Value::makeDict();
    s_req.set("streams", s_arr);
    bplist::Value s_resp;
    CHECK_TRUE(phone.callPlist("SETUP", "rtsp://127.0.0.1/streams", s_req, status, s_resp));
    CHECK_TRUE(status == 200);
    const uint16_t scr_port =
        static_cast<uint16_t>(intAt(s_resp.find("streams")->asArray()[0], "dataPort"));
    const uint16_t aud_port =
        static_cast<uint16_t>(intAt(s_resp.find("streams")->asArray()[1], "dataPort"));

    // A second control connection while verified session is active must be rejected.
    {
        plat::TcpConnection intruder;
        if (intruder.connect(v4_ctrl)) {
            for (int i = 0; i < 6; ++i) reactor.runOnce(5);
        }
        CHECK_TRUE(server.busyRejectedAccepts() == 1U);
        CHECK_TRUE(server.hasActiveSession());
    }

    // Legitimate phone connects event channel; a second event connection must be rejected.
    CHECK_TRUE(phone.connectEvent(plat::Address::ipv4Loopback(ev_port)));
    {
        plat::TcpConnection extra_ev;
        if (extra_ev.connect(plat::Address::ipv4Loopback(ev_port))) {
            for (int i = 0; i < 6; ++i) reactor.runOnce(5);
        }
        CHECK_TRUE(server.eventRejectedPeers() >= 1U);
        CHECK_TRUE(server.hasEventConnection());
    }

    // If IPv6 loopback (::1) is available on this host and the listener is dual-stack,
    // verify ::1 is treated as a different host from 127.0.0.1 for screen TCP and timing/audio UDP.
    plat::UdpSocket v6_udp;
    if (v6_udp.open(plat::Address::ipv6Loopback(0))) {
        plat::TcpConnection v6_scr;
        if (v6_scr.connect(plat::Address::ipv6Loopback(scr_port))) {
            for (int i = 0; i < 6; ++i) reactor.runOnce(5);
        }
        CHECK_TRUE(media_engine.screenRejectedPeers() == 1U);

        uint8_t fake_ntp[ntp::kPacketBytes];
        ntp::buildRequest(12345ULL, fake_ntp);
        v6_udp.sendTo(fake_ntp, sizeof(fake_ntp), plat::Address::ipv6Loopback(tm_port));
        v6_udp.sendTo(fake_ntp, sizeof(fake_ntp), plat::Address::ipv6Loopback(aud_port));
        for (int i = 0; i < 6; ++i) reactor.runOnce(5);
        CHECK_TRUE(server.timingStrangerDrops() == 1U);
        CHECK_TRUE(media_engine.audioStrangerDrops() == 1U);
    }

    // Active session must still answer encrypted /info cleanly.
    rtsp::Request raw;
    CHECK_TRUE(phone.call("GET", "/info", "", Bytes(), status, raw));
    CHECK_TRUE(status == 200);
    server.stop();
    return true;
}

// =============================================================================================
// Test 3: Accept rate limiting & unverified handshake timeout
// =============================================================================================

bool testRateLimitingAndUnverifiedTimeout() {
    TempDir dir("ratelimit");
    plat::OsRandomSource rng;
    pairing::Identity identity;
    CHECK_TRUE(plat::storageUsable(plat::loadOrCreateIdentity(dir.path, rng, identity)));
    plat::FilePairingStore store;
    CHECK_TRUE(plat::storageUsable(store.open(dir.path)));

    plat::Reactor reactor;
    CHECK_TRUE(reactor.init());
    RecordingListener listener;
    RecordingSink sink;
    plat::MediaEngine media_engine(reactor, sink);
    plat::SessionServerConfig srv_cfg;
    srv_cfg.control_port = 0;
    srv_cfg.max_accepts_per_window = 3;
    srv_cfg.accept_window_ms = 10000;
    srv_cfg.unverified_timeout_ms = 120;
    plat::SessionServer server(reactor,
                               info::bmwEntryNav2_800x480(false),
                               identity,
                               store,
                               rng,
                               listener,
                               media_engine,
                               NULL,
                               srv_cfg);
    CHECK_TRUE(server.start(plat::Address::ipv4Loopback(0)));
    const plat::Address addr = plat::Address::ipv4Loopback(server.controlPort());

    plat::TcpConnection c[5];
    for (int i = 0; i < 3; ++i) {
        CHECK_TRUE(c[i].connect(addr));
        CHECK_TRUE(waitUntilConnected(reactor, c[i]));
        reactor.runOnce(0);
    }
    for (int i = 3; i < 5; ++i) {
        CHECK_TRUE(c[i].connect(addr));
        const int64_t rl_deadline = plat::monotonicMillis() + 1000;
        while (server.rateLimitedAccepts() < static_cast<size_t>(i - 2) &&
               plat::monotonicMillis() < rl_deadline) {
            reactor.runOnce(0);
        }
    }
    CHECK_TRUE(server.rateLimitedAccepts() == 2U);
    CHECK_TRUE(server.hasActiveSession());

    // Leave the unverified connection idle until unverified_timeout_ms (60 ms) fires.
    const int64_t deadline = plat::monotonicMillis() + 1000;
    while (server.hasActiveSession() && plat::monotonicMillis() < deadline) {
        reactor.runOnce(10);
    }
    CHECK_TRUE(!server.hasActiveSession());
    CHECK_TRUE(server.unverifiedTimeouts() == 1U);
    server.stop();
    return true;
}

// =============================================================================================
// Test 4: Control write-queue overflow protection & screen decrypt failure cleanup
// =============================================================================================

bool testBackpressureOverflowAndScreenErrorCleanup() {
    TempDir dir("overflow");
    plat::OsRandomSource rng;
    pairing::Identity identity;
    CHECK_TRUE(plat::storageUsable(plat::loadOrCreateIdentity(dir.path, rng, identity)));
    plat::FilePairingStore store;
    CHECK_TRUE(plat::storageUsable(store.open(dir.path)));

    plat::Reactor reactor;
    CHECK_TRUE(reactor.init());
    RecordingListener listener;
    RecordingSink sink;
    plat::MediaEngine media_engine(reactor, sink);

    // 4a. With a tiny write-queue limit (32 bytes), a GET /info response (~1.5 KiB) overflows
    // the write queue and closes the session cleanly without tearing framing.
    {
        plat::SessionServerConfig tiny_cfg;
        tiny_cfg.control_port = 0;
        tiny_cfg.control_write_queue_limit = 32;
        plat::SessionServer tiny_srv(reactor,
                                     info::bmwEntryNav2_800x480(false),
                                     identity,
                                     store,
                                     rng,
                                     listener,
                                     media_engine,
                                     NULL,
                                     tiny_cfg);
        CHECK_TRUE(tiny_srv.start(plat::Address::ipv4Loopback(0)));
        NetPhoneClient phone(reactor, "ov-ltsk", "12345678-1234-4321-8888-1234567890AB", "ov-eph");
        CHECK_TRUE(phone.connectControl(plat::Address::ipv4Loopback(tiny_srv.controlPort())));
        const std::string req = "GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        CHECK_TRUE(phone.sendAll(phone.ctrl_conn, strBytes(req)));
        for (int i = 0; i < 6; ++i) reactor.runOnce(5);
        CHECK_TRUE(!tiny_srv.hasActiveSession());
        tiny_srv.stop();
    }

    // 4b. When a session is ducked and the screen stream receives a corrupted (bad tag) frame,
    // the screen stream closes, ducking is automatically restored (onAudioDuck(false)), and
    // the session closes.
    {
        plat::SessionServerConfig srv_cfg;
        srv_cfg.control_port = 0;
        srv_cfg.ntp_request_interval_ms = 0;
        plat::SessionServer server(reactor,
                                   info::bmwEntryNav2_800x480(false),
                                   identity,
                                   store,
                                   rng,
                                   listener,
                                   media_engine,
                                   NULL,
                                   srv_cfg);
        CHECK_TRUE(server.start(plat::Address::ipv4Loopback(0)));
        NetPhoneClient phone(
            reactor, "err-ltsk", "12345678-1234-4321-8888-1234567890AB", "err-eph");
        CHECK_TRUE(phone.connectControl(plat::Address::ipv4Loopback(server.controlPort())));
        CHECK_TRUE(phone.pairSetup("err-srp"));
        CHECK_TRUE(phone.pairVerify());

        int status = 0;
        bplist::Value resp;
        bplist::Value s_screen = bplist::Value::makeDict();
        s_screen.set("type", bplist::Value::makeInt(110));
        s_screen.set("streamConnectionID", bplist::Value::makeInt(99));
        bplist::Value arr = bplist::Value::makeArray();
        arr.asArray().push_back(s_screen);
        bplist::Value req = bplist::Value::makeDict();
        req.set("streams", arr);
        CHECK_TRUE(phone.callPlist("SETUP", "rtsp://127.0.0.1/streams", req, status, resp));
        CHECK_TRUE(status == 200);
        const uint16_t scr_port =
            static_cast<uint16_t>(intAt(resp.find("streams")->asArray()[0], "dataPort"));

        // Duck audio first
        bplist::Value duck_cmd = bplist::Value::makeDict();
        duck_cmd.set("type", bplist::Value::makeString("duckAudio"));
        CHECK_TRUE(phone.callPlist("POST", "/command", duck_cmd, status, resp));
        CHECK_TRUE(media_engine.isDucked());

        // Connect screen TCP and send a frame with a corrupted Poly1305 tag
        plat::TcpConnection scr_conn;
        CHECK_TRUE(scr_conn.connect(plat::Address::ipv4Loopback(scr_port)));
        CHECK_TRUE(waitUntilConnected(reactor, scr_conn));
        Bytes bad_frame = buildScreenHeader(0, 32, 0, 0.0f, 0.0f);
        Bytes garbage(32, 0xaa);
        cat(bad_frame, garbage);
        CHECK_TRUE(phone.sendAll(scr_conn, bad_frame));
        for (int i = 0; i < 8; ++i) reactor.runOnce(5);

        CHECK_TRUE(!server.hasActiveSession());
        CHECK_TRUE(!media_engine.isDucked());
        CHECK_TRUE(!sink.duck_events.empty() && sink.duck_events.back() == false);
        server.stop();
    }

    return true;
}

// =============================================================================================
// Test 5: Screen stream edge cases (ScreenStream.kt / ScreenCodec parity)
// =============================================================================================

bool testScreenStreamEdgeCases() {
    Rig rig("screen_edges");
    CHECK_TRUE(rig.ok);
    RecordingSink sink;
    plat::MediaEngine media_engine(rig.reactor, sink);
    plat::SessionServer server(rig.reactor, info::bmwEntryNav2_800x480(false), rig.identity, rig.store,
                               rig.rng, rig.listener, media_engine, NULL, quietServerConfig());
    CHECK_TRUE(server.start(plat::Address::ipv4Loopback(0)));
    NetPhoneClient phone(rig.reactor, "scr-ltsk", "5C5C5C5C-0000-4000-8000-000000000001", "scr-eph");
    CHECK_TRUE(pairAndVerify(phone, plat::Address::ipv4Loopback(server.controlPort()), "scr-srp"));

    std::vector<bplist::Value> entries;
    entries.push_back(screenEntry(110, 77));
    std::vector<bplist::Value> resp;
    CHECK_TRUE(setupStreams(phone, entries, resp));
    CHECK_TRUE(resp.size() == 1U);
    plat::TcpConnection scr;
    CHECK_TRUE(connectTcp(rig.reactor, scr, static_cast<uint16_t>(intAt(resp[0], "dataPort"))));
    const Bytes key = phone.streamOutputKey(77);

    // (a) A VideoFrame whose body is shorter than the 16-byte tag is ignored (ScreenStream.kt:103):
    //     the stream stays up and the frame counter does not advance.
    Bytes runt = buildScreenHeader(0, 5, 0, 0.0f, 0.0f);
    cat(runt, Bytes(5, 0x11));
    CHECK_TRUE(phone.sendAll(scr, runt));
    // An unknown opcode is skipped as well.
    Bytes unknown_op = buildScreenHeader(7, 3, 0, 0.0f, 0.0f);
    cat(unknown_op, Bytes(3, 0x22));
    CHECK_TRUE(phone.sendAll(scr, unknown_op));
    pump(rig.reactor);
    CHECK_TRUE(server.hasActiveSession());
    CHECK_TRUE(sink.video_frames.empty());

    // (b) First NAL of 300 bytes: its length prefix is 00 00 01 2c, which must NOT be mistaken for a
    //     3-byte Annex-B start code (ScreenCodec only skips payloads starting with 00 00 00 01).
    const Bytes au300 = lengthPrefixedNal(300, 0x41);
    CHECK_TRUE(phone.sendAll(scr, buildSealedScreenFrame(key, 0, au300)));
    // (c) Two NALs in one access unit, the first exactly 256 bytes (00 00 01 00).
    Bytes au2 = lengthPrefixedNal(256, 0x06);
    cat(au2, lengthPrefixedNal(9, 0x41));
    CHECK_TRUE(phone.sendAll(scr, buildSealedScreenFrame(key, 1, au2)));
    // (d) Already Annex-B (00 00 00 01): delivered untouched.
    const Bytes annexb = test_support::hexToBytes("0000000165aabbcc");
    CHECK_TRUE(phone.sendAll(scr, buildSealedScreenFrame(key, 2, annexb)));
    // (e) Malformed lengths: delivered untouched for the decoder's error path.
    const Bytes malformed = test_support::hexToBytes("000000ff6501");
    CHECK_TRUE(phone.sendAll(scr, buildSealedScreenFrame(key, 3, malformed)));
    pump(rig.reactor, 10);

    CHECK_TRUE(sink.video_frames.size() == 4U);
    const Bytes& f0 = sink.video_frames[0].annexb;
    CHECK_TRUE(f0.size() == 304U && f0[0] == 0 && f0[1] == 0 && f0[2] == 0 && f0[3] == 1 && f0[4] == 0x41);
    const Bytes& f1 = sink.video_frames[1].annexb;
    CHECK_TRUE(f1.size() == 273U && f1[2] == 0 && f1[3] == 1 && f1[4] == 0x06);
    CHECK_TRUE(f1[260] == 0 && f1[261] == 0 && f1[262] == 0 && f1[263] == 1 && f1[264] == 0x41);
    CHECK_TRUE(sink.video_frames[2].annexb == annexb);
    CHECK_TRUE(sink.video_frames[3].annexb == malformed);

    // (f) The box fourcc decides the codec (ScreenCodec.detectConfig): an 'hvcC' box is HEVC and the
    //     record after the fourcc is handed over verbatim.
    Bytes hvcc_record(23, 0);
    hvcc_record[0] = 0x01;
    Bytes hvcc_box(8, 0);
    putBe(hvcc_box, 0, 8U + hvcc_record.size(), 4);
    memcpy(&hvcc_box[4], "hvcC", 4);
    cat(hvcc_box, hvcc_record);
    Bytes cfg = buildScreenHeader(1, static_cast<uint32_t>(hvcc_box.size()), 0, 800.0f, 480.0f);
    cat(cfg, hvcc_box);
    CHECK_TRUE(phone.sendAll(scr, cfg));
    // (g) An 'avcC' box stays H.264 even if its bytes also parse as an hvcC record.
    Bytes ambiguous(26, 0);
    ambiguous[0] = 0x01;
    ambiguous[22] = 0x01;  // hvcC numOfArrays = 1, array with zero NAL units
    Bytes avcc_box(8, 0);
    putBe(avcc_box, 0, 8U + ambiguous.size(), 4);
    memcpy(&avcc_box[4], "avcC", 4);
    cat(avcc_box, ambiguous);
    cfg = buildScreenHeader(1, static_cast<uint32_t>(avcc_box.size()), 0, 800.0f, 480.0f);
    cat(cfg, avcc_box);
    CHECK_TRUE(phone.sendAll(scr, cfg));
    pump(rig.reactor, 10);
    CHECK_TRUE(sink.video_configs.size() == 2U);
    CHECK_TRUE(sink.video_configs[0].codec == stream::CODEC_HEVC_HVCC);
    CHECK_TRUE(sink.video_configs[0].raw == hvcc_record);
    CHECK_TRUE(sink.video_configs[1].codec == stream::CODEC_H264_AVCC);
    CHECK_TRUE(sink.video_configs[1].raw == ambiguous);

    // (h) An oversized payload_size ends the stream and with it the session (MAX_BODY, onClosed).
    CHECK_TRUE(phone.sendAll(scr, buildScreenHeader(0, 9U * 1024U * 1024U, 0, 0.0f, 0.0f)));
    pump(rig.reactor, 10);
    CHECK_TRUE(!server.hasActiveSession());
    CHECK_TRUE(media_engine.activeScreenCount() == 0U);
    server.stop();
    return true;
}

// =============================================================================================
// Test 6: A MediaSink callback that closes the session from inside the stream's own dispatch
// =============================================================================================

struct ClosingSink : public RecordingSink {
    plat::SessionServer* server;
    bool close_on_frame;
    bool close_on_config;
    bool close_on_pcm;
    bool close_on_audio_started;
    bool close_on_iap;
    bool close_on_mic_started;

    ClosingSink()
        : server(NULL), close_on_frame(false), close_on_config(false), close_on_pcm(false),
          close_on_audio_started(false), close_on_iap(false), close_on_mic_started(false) {}

    void closeNow() {
        if (server != NULL) server->closeActiveSession();
    }

    virtual void onVideoConfig(int32_t type, stream::VideoCodecType codec, const uint8_t* a, size_t al,
                               const uint8_t* r, size_t rl, float w, float h) {
        RecordingSink::onVideoConfig(type, codec, a, al, r, rl, w, h);
        if (close_on_config) closeNow();
    }
    virtual void onVideoFrame(int32_t type, const uint8_t* d, size_t len, uint64_t sn, int64_t an) {
        RecordingSink::onVideoFrame(type, d, len, sn, an);
        if (close_on_frame) closeNow();
    }
    virtual void onAudioStarted(const plat::AudioStreamId& id, const audio::AudioFormat& f, uint32_t fs) {
        RecordingSink::onAudioStarted(id, f, fs);
        if (close_on_audio_started) closeNow();
    }
    virtual void onAudioPcm(const plat::AudioStreamId& id, const audio::AudioFormat& f, const int16_t* s,
                            size_t n, uint16_t seq, uint32_t ts) {
        RecordingSink::onAudioPcm(id, f, s, n, seq, ts);
        if (close_on_pcm) closeNow();
    }
    virtual void onIapMessage(const uint8_t* data, size_t len) {
        RecordingSink::onIapMessage(data, len);
        if (close_on_iap) closeNow();
    }
    virtual void onMicrophoneStarted(const plat::AudioStreamId& id, const audio::MicStreamParams& p,
                                     const plat::Address& dest) {
        RecordingSink::onMicrophoneStarted(id, p, dest);
        if (close_on_mic_started) closeNow();
    }
};

// mode: 0 = video frame, 1 = video config, 2 = audio PCM, 3 = audio started, 4 = iAP message,
//       5 = microphone started by the silent-start timer.
bool runReentrantCloseScenario(int mode) {
    Rig rig("reentrant");
    CHECK_TRUE(rig.ok);
    ClosingSink sink;
    plat::MediaEngineConfig me_cfg;
    me_cfg.mic_silent_start_ms = (mode == 5) ? 40 : -1;
    plat::MediaEngine media_engine(rig.reactor, sink, me_cfg);
    plat::SessionServer server(rig.reactor, info::bmwEntryNav2_800x480(true), rig.identity, rig.store,
                               rig.rng, rig.listener, media_engine, NULL, quietServerConfig());
    sink.server = &server;
    CHECK_TRUE(server.start(plat::Address::ipv4Loopback(0)));
    NetPhoneClient phone(rig.reactor, "re-ltsk", "5C5C5C5C-0000-4000-8000-000000000002", "re-eph");
    CHECK_TRUE(pairAndVerify(phone, plat::Address::ipv4Loopback(server.controlPort()), "re-srp"));

    plat::UdpSocket phone_udp;
    CHECK_TRUE(phone_udp.open(plat::Address::ipv4Loopback(0)));

    std::vector<bplist::Value> entries;
    entries.push_back(screenEntry(110, 11));
    bplist::Value mic_audio = audioEntry(100, "speechrecognition", 0x10, 22);
    mic_audio.set("dataPort", bplist::Value::makeInt(phone_udp.port()));
    entries.push_back(mic_audio);
    entries.push_back(audioEntry(101, "media", 0x800, 33));
    entries.push_back(iapEntry(44));
    std::vector<bplist::Value> resp;
    // Mode 5: the silent-start timer armed by this SETUP fires in a later reactor round, with no
    // stream socket involved at all.
    sink.close_on_mic_started = (mode == 5);
    CHECK_TRUE(setupStreams(phone, entries, resp));
    CHECK_TRUE(resp.size() == 4U);
    CHECK_TRUE(media_engine.activeScreenCount() == 1U && media_engine.activeAudioCount() == 2U &&
               media_engine.hasDataStream());

    plat::TcpConnection scr;
    plat::TcpConnection iap;
    if (mode != 5) {
        CHECK_TRUE(connectTcp(rig.reactor, scr, static_cast<uint16_t>(intAt(resp[0], "dataPort"))));
        CHECK_TRUE(connectTcp(rig.reactor, iap, static_cast<uint16_t>(intAt(resp[3], "dataPort"))));
    }

    if (mode == 0) {
        sink.close_on_frame = true;
        const Bytes key = phone.streamOutputKey(11);
        // Two frames in one write: the second must never reach the sink after the close.
        Bytes two = buildSealedScreenFrame(key, 0, lengthPrefixedNal(20, 0x65));
        cat(two, buildSealedScreenFrame(key, 1, lengthPrefixedNal(20, 0x41)));
        CHECK_TRUE(phone.sendAll(scr, two));
    } else if (mode == 1) {
        sink.close_on_config = true;
        Bytes cfg = buildScreenHeader(1, 4, 0, 800.0f, 480.0f);
        cat(cfg, Bytes(4, 0x01));
        // Two configs in one write: the second must never reach the sink after the close.
        const Bytes one(cfg);
        cat(cfg, one);
        CHECK_TRUE(phone.sendAll(scr, cfg));
    } else if (mode == 2 || mode == 3) {
        sink.close_on_pcm = (mode == 2);
        sink.close_on_audio_started = (mode == 3);
        const Bytes key = phone.streamOutputKey(33);
        const plat::Address dest =
            plat::Address::ipv4Loopback(static_cast<uint16_t>(intAt(resp[2], "dataPort")));
        for (uint16_t i = 0; i < 3; ++i) {
            const Bytes pkt = buildAudioPacket(key, 101, static_cast<uint16_t>(10 + i), 100U + i * 4U, i,
                                               static_cast<int16_t>(i * 10));
            CHECK_TRUE(phone_udp.sendTo(&pkt[0], pkt.size(), dest) == plat::kIoOk);
        }
    } else if (mode == 4) {
        sink.close_on_iap = true;
        const Bytes key = phone.streamOutputKey(44);
        Bytes two = buildIapSealedCommPackage(key, 0, test_support::hexToBytes("ff5a0001"));
        cat(two, buildIapSealedCommPackage(key, 1, test_support::hexToBytes("ff5a0002")));
        CHECK_TRUE(phone.sendAll(iap, two));
    }

    const int64_t deadline = plat::monotonicMillis() + 2000;
    while (server.hasActiveSession() && plat::monotonicMillis() < deadline) rig.reactor.runOnce(5);
    pump(rig.reactor);

    CHECK_TRUE(!server.hasActiveSession());
    CHECK_TRUE(rig.listener.ended_count == 1);
    CHECK_TRUE(media_engine.activeScreenCount() == 0U);
    CHECK_TRUE(media_engine.activeAudioCount() == 0U);
    CHECK_TRUE(!media_engine.hasDataStream());
    if (mode == 0) CHECK_TRUE(sink.video_frames.size() == 1U);
    if (mode == 1) CHECK_TRUE(sink.video_configs.size() == 1U);
    if (mode == 2) CHECK_TRUE(sink.audio_pcm.size() == 1U);
    if (mode == 3) CHECK_TRUE(sink.audio_started.size() == 1U && sink.audio_pcm.empty());
    if (mode == 4) CHECK_TRUE(sink.iap_messages.size() == 1U);
    if (mode == 5) CHECK_TRUE(sink.mic_started.size() == 1U);
    // Every stream that was announced is also reported gone, exactly once.
    CHECK_TRUE(sink.audio_stopped.size() == 2U);
    CHECK_TRUE(sink.mic_stopped.size() == 1U);
    CHECK_TRUE(sink.screen_active.size() == 2U && sink.screen_active.back().second == false);

    // The server accepts a fresh session afterwards (persisted pairing, no pair-setup).
    NetPhoneClient phone2(rig.reactor, "re-ltsk", "5C5C5C5C-0000-4000-8000-000000000002", "re-eph2");
    phone2.acc_id = phone.acc_id;
    phone2.acc_ltpk = phone.acc_ltpk;
    CHECK_TRUE(phone2.connectControl(plat::Address::ipv4Loopback(server.controlPort())));
    CHECK_TRUE(phone2.pairVerify());
    server.stop();
    return true;
}

bool testSinkClosesSessionFromStreamCallbacks() {
    for (int mode = 0; mode <= 5; ++mode) {
        if (!runReentrantCloseScenario(mode)) {
            printf("  [FAIL] re-entrant close scenario %d\n", mode);
            return false;
        }
    }
    return true;
}

// =============================================================================================
// Test 7: iAP2 DataStream tunnel: peer EOF keeps the listener (IapTunnel.kt accept loop)
// =============================================================================================

bool testIapTunnelReconnectAndErrors() {
    Rig rig("iap_tunnel");
    CHECK_TRUE(rig.ok);
    RecordingSink sink;
    plat::MediaEngine media_engine(rig.reactor, sink);
    plat::SessionServer server(rig.reactor, info::bmwEntryNav2_800x480(false), rig.identity, rig.store,
                               rig.rng, rig.listener, media_engine, NULL, quietServerConfig());
    CHECK_TRUE(server.start(plat::Address::ipv4Loopback(0)));
    NetPhoneClient phone(rig.reactor, "iap-ltsk", "5C5C5C5C-0000-4000-8000-000000000003", "iap-eph");
    CHECK_TRUE(pairAndVerify(phone, plat::Address::ipv4Loopback(server.controlPort()), "iap-srp"));

    std::vector<bplist::Value> entries;
    entries.push_back(iapEntry(555));
    std::vector<bplist::Value> resp;
    CHECK_TRUE(setupStreams(phone, entries, resp));
    CHECK_TRUE(resp.size() == 1U && intAt(resp[0], "streamID") == 1 && intAt(resp[0], "type") == 130);
    CHECK_TRUE(resp[0].find("streamConnectionID") == NULL);  // only echoed when the phone sent one
    const uint16_t port = static_cast<uint16_t>(intAt(resp[0], "dataPort"));
    const Bytes key = phone.streamOutputKey(555);
    const Bytes msg_a = test_support::hexToBytes("ff5a000a40aa");
    const Bytes msg_b = test_support::hexToBytes("ff5a000a40bb");

    {
        plat::TcpConnection iap;
        CHECK_TRUE(connectTcp(rig.reactor, iap, port));
        // A non-'comm' package is skipped; an empty-bodied 'comm' package is delivered empty; the
        // frames may arrive split at any byte.
        Bytes other(32, 0);
        putBe(other, 0, 32, 4);
        putBe(other, 16, 0x70696e67U, 4);  // 'ping'
        Bytes aad(2, 0);
        putLe(aad, 0, other.size(), 2);
        uint8_t nonce[12];
        crypto::makeCounterNonce(0, nonce);
        Bytes sealed;
        crypto::chacha20Poly1305Seal(&key[0], nonce, &aad[0], 2, &other[0], other.size(), sealed);
        Bytes wire = aad;
        cat(wire, sealed);
        cat(wire, buildIapSealedCommPackage(key, 1, msg_a));
        cat(wire, buildIapSealedCommPackage(key, 2, Bytes()));
        for (size_t off = 0; off < wire.size(); off += 7) {
            const size_t n = wire.size() - off < 7 ? wire.size() - off : 7;
            CHECK_TRUE(phone.sendAll(iap, Bytes(wire.begin() + static_cast<ptrdiff_t>(off),
                                                wire.begin() + static_cast<ptrdiff_t>(off + n))));
        }
        pump(rig.reactor);
        CHECK_TRUE(sink.iap_messages.size() == 2U);
        CHECK_TRUE(sink.iap_messages[0] == msg_a && sink.iap_messages[1].empty());
        // Leave half a frame behind and close: the remainder is dropped with the connection.
        const Bytes partial = buildIapSealedCommPackage(key, 3, msg_b);
        CHECK_TRUE(phone.sendAll(iap, Bytes(partial.begin(), partial.begin() + 9)));
        pump(rig.reactor, 3);
        CHECK_TRUE(iap.shutdownWrite());
        pump(rig.reactor);
    }
    // Peer EOF is not an error: the tunnel keeps listening and the session stays up.
    CHECK_TRUE(server.hasActiveSession());
    CHECK_TRUE(media_engine.hasDataStream());

    {
        // The phone reconnects to the same port; the read counter restarts at 0.
        plat::TcpConnection iap;
        CHECK_TRUE(connectTcp(rig.reactor, iap, port));
        CHECK_TRUE(phone.sendAll(iap, buildIapSealedCommPackage(key, 0, msg_b)));
        pump(rig.reactor);
        CHECK_TRUE(sink.iap_messages.size() == 3U && sink.iap_messages[2] == msg_b);

        // A frame sealed with the wrong counter fails authentication: tunnel and session close.
        CHECK_TRUE(phone.sendAll(iap, buildIapSealedCommPackage(key, 9, msg_b)));
        pump(rig.reactor, 10);
        CHECK_TRUE(!server.hasActiveSession());
        CHECK_TRUE(!media_engine.hasDataStream());
        CHECK_TRUE(sink.iap_messages.size() == 3U);
    }
    server.stop();
    return true;
}

// =============================================================================================
// Test 8: Microphone start rules, uplink gating, stream replacement, /feedback wire form
// =============================================================================================

bool testMicrophoneStartAndFeedbackWireForm() {
    Rig rig("mic_rules");
    CHECK_TRUE(rig.ok);
    RecordingSink sink;
    plat::MediaEngineConfig me_cfg;
    me_cfg.mic_silent_start_ms = 30;
    me_cfg.max_audio_streams = 3;
    plat::MediaEngine media_engine(rig.reactor, sink, me_cfg);
    // Start the clock in the wall-clock NTP domain (seconds since 1900, as wallClockNtpOffsetNs
    // gives on the car): such timestamps have the top bit set until 2036.
    plat::SessionServerConfig srv_cfg = quietServerConfig();
    srv_cfg.initial_ntp_offset_ns = 3900000000LL * 1000000000LL;
    plat::SessionServer server(rig.reactor, info::bmwEntryNav2_800x480(true), rig.identity, rig.store,
                               rig.rng, rig.listener, media_engine, NULL, srv_cfg);
    CHECK_TRUE(server.start(plat::Address::ipv4Loopback(0)));
    NetPhoneClient phone(rig.reactor, "mic-ltsk", "5C5C5C5C-0000-4000-8000-000000000004", "mic-eph");
    CHECK_TRUE(pairAndVerify(phone, plat::Address::ipv4Loopback(server.controlPort()), "mic-srp"));

    plat::UdpSocket phone_udp;
    CHECK_TRUE(phone_udp.open(plat::Address::ipv4Loopback(0)));
    const uint64_t kCallId = 0xfedcba9876543210ULL;  // >= 2^63: sent by the phone as a negative int64

    // Telephony waits for its downlink (MicrophoneStart.startsWithoutDownlink == false).
    bplist::Value call = audioEntry(100, "Telephony", 0x10, static_cast<int64_t>(kCallId));
    call.set("dataPort", bplist::Value::makeInt(phone_udp.port()));
    call.set("audioLatencyMs", bplist::Value::makeInt(0));
    std::vector<bplist::Value> entries;
    entries.push_back(call);
    std::vector<bplist::Value> resp;
    CHECK_TRUE(setupStreams(phone, entries, resp));
    CHECK_TRUE(resp.size() == 1U);
    const uint16_t call_port = static_cast<uint16_t>(intAt(resp[0], "dataPort"));
    CHECK_TRUE(intAt(resp[0], "controlPort") > 0 && intAt(resp[0], "controlPort") != call_port);
    // The echoed id keeps the phone's own 8-byte form (unsignedPlistInteger), never 16 bytes.
    const bplist::Value* echoed = resp[0].find("streamConnectionID");
    uint64_t echoed_id = 0;
    CHECK_TRUE(echoed != NULL && echoed->isInt() && session::Session::plistUnsignedId(*echoed, echoed_id));
    CHECK_TRUE(echoed_id == kCallId);

    const int64_t wait_until = plat::monotonicMillis() + 120;
    while (plat::monotonicMillis() < wait_until) rig.reactor.runOnce(5);
    CHECK_TRUE(sink.mic_started.empty());
    CHECK_TRUE(!media_engine.microphoneActive());
    CHECK_TRUE(media_engine.activeMicrophoneParams() != NULL);

    // Captured audio handed over before the microphone started is not transmitted.
    const size_t spf = media_engine.activeMicrophoneParams()->samplesPerFrame();
    CHECK_TRUE(spf > 0);
    std::vector<int16_t> frame(spf, 1234);
    CHECK_TRUE(media_engine.pushMicrophonePcm(&frame[0], frame.size()) == 0U);
    CHECK_TRUE(media_engine.submitMicrophonePcm(&frame[0], frame.size()));
    pump(rig.reactor);
    {
        uint8_t rx[2048];
        size_t got = 0;
        plat::Address from;
        CHECK_TRUE(phone_udp.receiveFrom(rx, sizeof(rx), got, from) == plat::kIoWouldBlock);
    }

    // The first downlink packet starts it.
    const Bytes call_key = phone.streamOutputKey(kCallId);
    const Bytes first = buildAudioPacket(call_key, 100, 7, 4000, 0, 50);
    CHECK_TRUE(phone_udp.sendTo(&first[0], first.size(), plat::Address::ipv4Loopback(call_port)) ==
               plat::kIoOk);
    pump(rig.reactor);
    CHECK_TRUE(sink.mic_started.size() == 1U && sink.mic_started[0].audio_type == "telephony");
    CHECK_TRUE(media_engine.microphoneActive());
    CHECK_TRUE(sink.last_mic_dest.port() == phone_udp.port());
    CHECK_TRUE(media_engine.pushMicrophonePcm(&frame[0], frame.size()) == 1U);
    {
        uint8_t rx[2048];
        size_t got = 0;
        plat::Address from;
        CHECK_TRUE(phone_udp.receiveFrom(rx, sizeof(rx), got, from) == plat::kIoOk);
        const Bytes in_key = phone.streamInputKey(kCallId);
        audio::RtpHeader hdr;
        Bytes payload;
        CHECK_TRUE(audio::openPacket(&in_key[0], rx, got, hdr, payload) == audio::kOpenOk);
        CHECK_TRUE(hdr.sequence == 0U && hdr.payload_type == 100U && payload.size() == spf * 2U);
    }

    // POST /feedback: the NTP timestamp (always >= 2^63 in this NTP era) and the stream id travel as
    // 8-byte integers like the reference's BplistCodec.encodeUnsignedInt, not as 16-byte ones.
    {
        int status = 0;
        rtsp::Request raw;
        CHECK_TRUE(phone.call("POST", "/feedback", "", Bytes(), status, raw));
        CHECK_TRUE(status == 200);
        bplist::Value fb;
        CHECK_TRUE(bplist::decode(raw.body, fb));
        const bplist::Value* streams = fb.find("streams");
        CHECK_TRUE(streams != NULL && streams->isArray() && streams->asArray().size() == 1U);
        const bplist::Value& entry = streams->asArray()[0];
        CHECK_TRUE(intAt(entry, "type") == 100 && intAt(entry, "sampleRate") == 16000);
        const bplist::Value* ts = entry.find("timestamp");
        const bplist::Value* cid = entry.find("streamConnectionID");
        uint64_t ts_u = 0;
        uint64_t cid_u = 0;
        // isInt(): decoded from an 8-byte (0x13) integer. The 16-byte 0x14 form would decode as
        // TYPE_UINT64 instead. Both values are >= 2^63, i.e. negative when read as int64.
        CHECK_TRUE(ts != NULL && ts->isInt() && ts->asInt() < 0);
        CHECK_TRUE(cid != NULL && cid->isInt() && cid->asInt() < 0);
        CHECK_TRUE(session::Session::plistUnsignedId(*ts, ts_u));
        CHECK_TRUE(session::Session::plistUnsignedId(*cid, cid_u));
        CHECK_TRUE(cid_u == kCallId);
        CHECK_TRUE((ts_u >> 32) >= 3900000000ULL);
        CHECK_TRUE(intAt(entry, "timestampRawNs") > 0);
        const int64_t sample_time = intAt(entry, "sampleTime");
        CHECK_TRUE(sample_time >= 4000 && sample_time < 4000 + 16000 * 5);
    }

    // A non-telephony input stream with no downlink starts after mic_silent_start_ms.
    bplist::Value note = audioEntry(100, "default", 0x10, 808);
    note.set("input", bplist::Value::makeBool(true));
    note.set("dataPort", bplist::Value::makeInt(phone_udp.port()));
    entries.clear();
    entries.push_back(note);
    CHECK_TRUE(setupStreams(phone, entries, resp));
    CHECK_TRUE(resp.size() == 1U);
    CHECK_TRUE(sink.mic_started.size() == 1U);
    const int64_t deadline = plat::monotonicMillis() + 1000;
    while (sink.mic_started.size() < 2U && plat::monotonicMillis() < deadline) rig.reactor.runOnce(5);
    CHECK_TRUE(sink.mic_started.size() == 2U && sink.mic_started[1].audio_type == "default");

    // Re-SETUP of the same (type, audioType) replaces the stream: old one reported stopped, new
    // ports, the pending silent start of the old one never fires.
    const int64_t old_port = intAt(resp[0], "dataPort");
    note.set("streamConnectionID", bplist::Value::makeInt(809));
    entries.clear();
    entries.push_back(note);
    const size_t stopped_before = sink.audio_stopped.size();
    const size_t mic_stopped_before = sink.mic_stopped.size();
    CHECK_TRUE(setupStreams(phone, entries, resp));
    CHECK_TRUE(resp.size() == 1U);
    CHECK_TRUE(media_engine.activeAudioCount() == 2U);
    CHECK_TRUE(sink.audio_stopped.size() == stopped_before + 1U);
    CHECK_TRUE(sink.mic_stopped.size() == mic_stopped_before + 1U);
    CHECK_TRUE(intAt(resp[0], "dataPort") > 0);
    (void)old_port;

    // max_audio_streams (3 here) bounds concurrently open streams; replacing still works.
    entries.clear();
    entries.push_back(audioEntry(101, "media", 0x800, 900));
    entries.push_back(audioEntry(102, "alert", 0x800, 901));
    CHECK_TRUE(setupStreams(phone, entries, resp));
    CHECK_TRUE(resp.size() == 1U && intAt(resp[0], "type") == 101);
    CHECK_TRUE(media_engine.activeAudioCount() == 3U);

    // An unsupported downlink format is declined, but (like the reference) the stream it would
    // have replaced is gone.
    entries.clear();
    entries.push_back(audioEntry(101, "media", 0x400000, 902));  // AAC-LC: not offered on the F20 profile
    CHECK_TRUE(setupStreams(phone, entries, resp));
    CHECK_TRUE(resp.empty());
    CHECK_TRUE(media_engine.activeAudioCount() == 2U);

    server.stop();
    return true;
}

// =============================================================================================
// Test 9: Lifetime: engine destroyed with a queued worker post, server destroyed before the
// engine, session closed behind the server's back
// =============================================================================================

bool testLifetimeEdges() {
    Rig rig("lifetime");
    CHECK_TRUE(rig.ok);
    RecordingSink sink;

    // (a) A worker-thread submit leaves a task queued in the reactor; destroying the engine before
    //     the reactor runs it must not leave the task pointing at freed memory.
    {
        plat::MediaEngine short_lived(rig.reactor, sink);
        const int16_t pcm[4] = {1, 2, 3, 4};
        CHECK_TRUE(short_lived.submitMicrophonePcm(pcm, 4));
        CHECK_TRUE(!short_lived.submitMicrophonePcm(NULL, 4));
        CHECK_TRUE(!short_lived.submitMicrophonePcm(pcm, 0));
        // The queue is bounded (~1 s of 48 kHz stereo).
        std::vector<int16_t> big(96000, 0);
        CHECK_TRUE(!short_lived.submitMicrophonePcm(&big[0], big.size()));
    }
    pump(rig.reactor, 3);

    plat::MediaEngine media_engine(rig.reactor, sink);
    // (b) A server that goes away detaches its callbacks from the engine it was wired to.
    {
        plat::SessionServer gone(rig.reactor, info::bmwEntryNav2_800x480(false), rig.identity, rig.store,
                                 rig.rng, rig.listener, media_engine, NULL, quietServerConfig());
        CHECK_TRUE(gone.start(plat::Address::ipv4Loopback(0)));
        CHECK_TRUE(media_engine.hasSessionCallbacks());
    }
    CHECK_TRUE(!media_engine.hasSessionCallbacks());

    plat::SessionServer server(rig.reactor, info::bmwEntryNav2_800x480(false), rig.identity, rig.store,
                               rig.rng, rig.listener, media_engine, NULL, quietServerConfig());
    CHECK_TRUE(server.start(plat::Address::ipv4Loopback(0)));
    const plat::Address addr = plat::Address::ipv4Loopback(server.controlPort());

    // (c) The application closes the Session object directly (not through the server). The next
    //     control connection must get a clean, working session.
    NetPhoneClient phone(rig.reactor, "life-ltsk", "5C5C5C5C-0000-4000-8000-000000000005", "life-eph");
    CHECK_TRUE(pairAndVerify(phone, addr, "life-srp"));
    CHECK_TRUE(server.hasActiveSession());
    server.activeSession()->close();
    CHECK_TRUE(!server.hasActiveSession());
    CHECK_TRUE(rig.listener.ended_count == 1);

    NetPhoneClient phone2(rig.reactor, "life-ltsk", "5C5C5C5C-0000-4000-8000-000000000005", "life-eph2");
    phone2.acc_id = phone.acc_id;
    phone2.acc_ltpk = phone.acc_ltpk;
    CHECK_TRUE(phone2.connectControl(addr));
    CHECK_TRUE(server.hasActiveSession());
    CHECK_TRUE(phone2.pairVerify());
    int status = 0;
    rtsp::Request raw;
    CHECK_TRUE(phone2.call("GET", "/info", "", Bytes(), status, raw));
    CHECK_TRUE(status == 200);
    CHECK_TRUE(rig.listener.ended_count == 1);
    CHECK_TRUE(rig.reactor.socketCount() == 2U);  // control listener + the one live control connection

    server.stop();
    CHECK_TRUE(rig.reactor.socketCount() == 0U);
    CHECK_TRUE(rig.reactor.timerCount() == 0U);
    return true;
}

bool checkSessionQos(bool wifi_qos, int expected_tos) {
    Rig rig(wifi_qos ? "qos_wifi" : "qos_usb");
    CHECK_TRUE(rig.ok);

    RecordingSink sink;
    plat::MediaEngineConfig me_cfg;
    me_cfg.wifi_video_qos = wifi_qos;
    plat::MediaEngine media_engine(rig.reactor, sink, me_cfg);

    plat::SessionServerConfig srv_cfg = quietServerConfig();
    srv_cfg.wifi_video_qos = wifi_qos;
    plat::SessionServer server(
        rig.reactor, info::bmwEntryNav2_800x480(false), rig.identity, rig.store,
        rig.rng, rig.listener, media_engine, NULL, srv_cfg);
    CHECK_TRUE(server.start(plat::Address::ipv4Loopback(0)));
    const plat::Address addr = plat::Address::ipv4Loopback(server.controlPort());

    NetPhoneClient phone(rig.reactor, "qos-ltsk", "6D6D6D6D-0000-4000-8000-000000000006", "qos-eph");
    CHECK_TRUE(pairAndVerify(phone, addr, "qos-srp"));

    int tos = -1;
    CHECK_TRUE(plat::getSocketTrafficClass(server.controlSocketHandle(), tos));
    CHECK_TRUE(tos == expected_tos);

    plat::UdpSocket phone_timing_udp;
    CHECK_TRUE(phone_timing_udp.open(plat::Address::ipv4Loopback(0)));
    bplist::Value setup_req = bplist::Value::makeDict();
    setup_req.set("timingPort", bplist::Value::makeInt(phone_timing_udp.port()));
    setup_req.set("name", bplist::Value::makeString("QoS iPhone"));
    setup_req.set("model", bplist::Value::makeString("iPhone16,2"));
    int status = 0;
    bplist::Value setup_resp;
    CHECK_TRUE(phone.callPlist("SETUP", "rtsp://127.0.0.1/session", setup_req, status, setup_resp));
    CHECK_TRUE(status == 200);
    const int64_t srv_event_port = intAt(setup_resp, "eventPort");
    CHECK_TRUE(phone.connectEvent(plat::Address::ipv4Loopback(static_cast<uint16_t>(srv_event_port))));

    tos = -1;
    CHECK_TRUE(plat::getSocketTrafficClass(server.eventSocketHandle(), tos));
    CHECK_TRUE(tos == expected_tos);

    bplist::Value streams_arr = bplist::Value::makeArray();
    bplist::Value s_screen = bplist::Value::makeDict();
    s_screen.set("type", bplist::Value::makeInt(110));
    s_screen.set("streamConnectionID", bplist::Value::makeInt(5001));
    streams_arr.asArray().push_back(s_screen);
    streams_arr.asArray().push_back(audioEntry(100, "speechrecognition", 0x10, 5002));
    bplist::Value streams_req = bplist::Value::makeDict();
    streams_req.set("streams", streams_arr);
    bplist::Value streams_resp;
    CHECK_TRUE(phone.callPlist("SETUP", "rtsp://127.0.0.1/streams", streams_req, status, streams_resp));
    CHECK_TRUE(status == 200);
    const bplist::Value* resp_arr = streams_resp.find("streams");
    CHECK_TRUE(resp_arr != NULL && resp_arr->isArray() && resp_arr->asArray().size() == 2U);
    const int64_t screen_port = intAt(resp_arr->asArray()[0], "dataPort");

    plat::TcpConnection screen_conn;
    CHECK_TRUE(screen_conn.connect(plat::Address::ipv4Loopback(static_cast<uint16_t>(screen_port))));
    CHECK_TRUE(waitUntilConnected(rig.reactor, screen_conn));
    for (int i = 0; i < 4; ++i) {
        rig.reactor.runOnce(5);
    }

    tos = -1;
    CHECK_TRUE(plat::getSocketTrafficClass(media_engine.firstScreenSocketHandle(), tos));
    CHECK_TRUE(tos == expected_tos);
    tos = -1;
    CHECK_TRUE(plat::getSocketTrafficClass(media_engine.firstAudioDataSocketHandle(), tos));
    CHECK_TRUE(tos == expected_tos);

    server.stop();
    return true;
}

bool testWifiVideoQosSocketOption() {
    // Wired USB path leaves traffic class at 0; wireless CarPlay path marks sockets 0x80.
    return checkSessionQos(false, 0) && checkSessionQos(true, plat::kWifiVideoTos);
}

void runTest(const char* name, bool (*fn)()) {
    if (fn()) {
        printf("  [PASS] %s\n", name);
        g_passed += 1;
    } else {
        printf("  [FAIL] %s\n", name);
        g_failed += 1;
    }
}

}  // namespace

int main() {
    runTest("goldenRealSocketE2eAndReconnect", &testGoldenRealSocketE2eAndReconnect);
    runTest("peerFilteringAndSingleSessionProtection", &testPeerFilteringAndSingleSessionProtection);
    runTest("rateLimitingAndUnverifiedTimeout", &testRateLimitingAndUnverifiedTimeout);
    runTest("backpressureOverflowAndScreenErrorCleanup", &testBackpressureOverflowAndScreenErrorCleanup);
    runTest("screenStreamEdgeCases", &testScreenStreamEdgeCases);
    runTest("sinkClosesSessionFromStreamCallbacks", &testSinkClosesSessionFromStreamCallbacks);
    runTest("iapTunnelReconnectAndErrors", &testIapTunnelReconnectAndErrors);
    runTest("microphoneStartAndFeedbackWireForm", &testMicrophoneStartAndFeedbackWireForm);
    runTest("lifetimeEdges", &testLifetimeEdges);
    runTest("wifiVideoQosSocketOption", &testWifiVideoQosSocketOption);

    printf("test_network_session: %d/%d passed\n", g_passed, g_passed + g_failed);
    return g_failed == 0 ? 0 : 1;
}
