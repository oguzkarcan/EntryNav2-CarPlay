// Unit + socket + end-to-end tests for Phase 3 F3-P6:
//   * vmost_client (wire parsing, Get builder, dlopen error states, VmostApi override)
//   * evo_ccs (E5.01 older CCS + E5.03 CCS35up + CcsProtocol locking & timing)
//   * evo_knob (MFL 15.02 / 15.0C / 20.00 decoders, worker thread with fake VmostApi)
//   * evo_touch_frame & evo_touch (reassembly, TouchTracker state machine, localhost UDP reader)
//   * evo_input_bridge + SessionServer + encrypted EventChannel loopback client E2E

#include "carplay/airplay_crypto.hpp"
#include "carplay/airplay_hid.hpp"
#include "carplay/airplay_info.hpp"
#include "carplay/airplay_session.hpp"
#include "carplay/bplist_codec.hpp"
#include "carplay/control_cipher.hpp"
#include "carplay/pairing.hpp"
#include "carplay/platform/evo_ccs.hpp"
#include "carplay/platform/evo_input_bridge.hpp"
#include "carplay/platform/evo_knob.hpp"
#include "carplay/platform/evo_touch.hpp"
#include "carplay/platform/evo_touch_frame.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/session_server.hpp"
#include "carplay/platform/tcp.hpp"
#include "carplay/platform/thread.hpp"
#include "carplay/platform/udp.hpp"
#include "carplay/platform/vmost_client.hpp"
#include "carplay/rtsp_message.hpp"
#include "carplay/tlv8_codec.hpp"
#include "test_support.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace crypto = carplay::crypto;
namespace bplist = carplay::bplist;
namespace rtsp = carplay::rtsp;
namespace hid = carplay::hid;
namespace info = carplay::info;
namespace tlv8 = carplay::tlv8;
namespace pairing = carplay::pairing;
namespace session = carplay::session;
namespace plat = carplay::platform;
using carplay::ControlCipher;

typedef std::vector<uint8_t> Bytes;
typedef std::vector<tlv8::Item> Items;

namespace {

// ---- Raw vMOST message struct matching parseVmostMsg offsets ----

struct RawVmostMsg {
    uint16_t addr;
    uint8_t fblock;
    uint8_t inst;
    uint16_t fkt;
    uint16_t pad;
    uint32_t op;
    uint16_t len;
    uint16_t pad2;
    const uint8_t* data;
};

plat::VmostMsgView msgView(uint8_t fblock,
                           uint8_t inst,
                           uint16_t fkt,
                           uint32_t op,
                           const uint8_t* data,
                           uint16_t len) {
    plat::VmostMsgView m;
    m.addr = 0x0100U;
    m.fblock = fblock;
    m.inst = inst;
    m.fkt = fkt;
    m.op = op;
    m.len = len;
    m.data = data;
    return m;
}

// Build a synthetic unfragmented IPv4/UDP packet for parseIpv4Udp tests.
Bytes buildIpv4Udp(uint32_t src_ip,
                   uint32_t dst_ip,
                   uint16_t sport,
                   uint16_t dport,
                   const uint8_t* payload,
                   size_t plen,
                   uint16_t frag_field = 0U,
                   uint8_t proto = 17U) {
    const size_t total = 20U + 8U + plen;
    Bytes p(total, 0U);
    p[0] = 0x45U;
    p[2] = static_cast<uint8_t>((total >> 8) & 0xFFU);
    p[3] = static_cast<uint8_t>(total & 0xFFU);
    p[6] = static_cast<uint8_t>((frag_field >> 8) & 0xFFU);
    p[7] = static_cast<uint8_t>(frag_field & 0xFFU);
    p[8] = 64U;
    p[9] = proto;
    p[12] = static_cast<uint8_t>((src_ip >> 24) & 0xFFU);
    p[13] = static_cast<uint8_t>((src_ip >> 16) & 0xFFU);
    p[14] = static_cast<uint8_t>((src_ip >> 8) & 0xFFU);
    p[15] = static_cast<uint8_t>(src_ip & 0xFFU);
    p[16] = static_cast<uint8_t>((dst_ip >> 24) & 0xFFU);
    p[17] = static_cast<uint8_t>((dst_ip >> 16) & 0xFFU);
    p[18] = static_cast<uint8_t>((dst_ip >> 8) & 0xFFU);
    p[19] = static_cast<uint8_t>(dst_ip & 0xFFU);

    const size_t ulen = 8U + plen;
    p[20] = static_cast<uint8_t>((sport >> 8) & 0xFFU);
    p[21] = static_cast<uint8_t>(sport & 0xFFU);
    p[22] = static_cast<uint8_t>((dport >> 8) & 0xFFU);
    p[23] = static_cast<uint8_t>(dport & 0xFFU);
    p[24] = static_cast<uint8_t>((ulen >> 8) & 0xFFU);
    p[25] = static_cast<uint8_t>(ulen & 0xFFU);
    if (plen > 0U && payload != NULL) {
        memcpy(&p[28], payload, plen);
    }
    return p;
}

// ---- Fake in-memory VmostApi server over socketpair (no external .so needed) ----

struct FakeVmostServer {
    struct SentMsg {
        uint16_t addr;
        uint8_t fblock;
        uint8_t inst;
        uint16_t fkt;
        uint32_t op;
        Bytes data;
    };
    struct RegEntry {
        uint8_t fblock;
        uint8_t inst;
    };
    struct WireMsg {
        uint8_t fblock;
        uint8_t inst;
        uint16_t fkt;
        uint32_t op;
        uint16_t len;
        uint8_t data[64];
    };

    plat::Mutex mutex;
    int fds[2];  // fds[0] = client, fds[1] = server inject side
    plat::VmostCallback cb;
    void* user;
    bool connected;
    bool disconnect_called;
    std::vector<RegEntry> registered;
    std::vector<RegEntry> deregistered;
    std::vector<SentMsg> sent_gets;

    FakeVmostServer() : cb(NULL), user(NULL), connected(false), disconnect_called(false) {
        fds[0] = -1;
        fds[1] = -1;
    }

    ~FakeVmostServer() { closeSockets(); }

    bool init() {
        closeSockets();
#ifndef _WIN32
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
            return false;
        }
        return true;
#else
        return false;
#endif
    }

    void closeSockets() {
#ifndef _WIN32
        if (fds[0] >= 0) {
            close(fds[0]);
            fds[0] = -1;
        }
        if (fds[1] >= 0) {
            close(fds[1]);
            fds[1] = -1;
        }
#endif
    }

    bool inject(uint8_t fblock,
                uint8_t inst,
                uint16_t fkt,
                uint32_t op,
                const uint8_t* data,
                uint16_t len) {
#ifndef _WIN32
        if (fds[1] < 0 || len > sizeof(((WireMsg*)0)->data)) {
            return false;
        }
        WireMsg w;
        memset(&w, 0, sizeof(w));
        w.fblock = fblock;
        w.inst = inst;
        w.fkt = fkt;
        w.op = op;
        w.len = len;
        if (len > 0U && data != NULL) {
            memcpy(w.data, data, len);
        }
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&w);
        size_t off = 0U;
        while (off < sizeof(w)) {
            const ssize_t n = write(fds[1], p + off, sizeof(w) - off);
            if (n <= 0) {
                return false;
            }
            off += static_cast<size_t>(n);
        }
        return true;
#else
        (void)fblock;
        (void)inst;
        (void)fkt;
        (void)op;
        (void)data;
        (void)len;
        return false;
#endif
    }
};

static FakeVmostServer* g_fake_vmost = NULL;

int fakeConnect(plat::VmostCallback cb, void* user, int /*flags*/) {
    if (g_fake_vmost == NULL) return -1;
    plat::LockGuard lock(g_fake_vmost->mutex);
    g_fake_vmost->cb = cb;
    g_fake_vmost->user = user;
    g_fake_vmost->connected = true;
    return 0;
}

int fakeShadowRegister(uint8_t fblock, uint8_t inst) {
    if (g_fake_vmost == NULL) return -1;
    plat::LockGuard lock(g_fake_vmost->mutex);
    FakeVmostServer::RegEntry e;
    e.fblock = fblock;
    e.inst = inst;
    g_fake_vmost->registered.push_back(e);
    return 0;
}

int fakeShadowDeregister(uint8_t fblock, uint8_t inst) {
    if (g_fake_vmost == NULL) return -1;
    plat::LockGuard lock(g_fake_vmost->mutex);
    FakeVmostServer::RegEntry e;
    e.fblock = fblock;
    e.inst = inst;
    g_fake_vmost->deregistered.push_back(e);
    return 0;
}

int fakeFdGet(int* fd) {
    if (g_fake_vmost == NULL || fd == NULL) return -1;
    *fd = g_fake_vmost->fds[0];
    return (*fd >= 0) ? 0 : -1;
}

int fakeProcessMessages() {
#ifndef _WIN32
    if (g_fake_vmost == NULL || g_fake_vmost->fds[0] < 0) return -1;
    FakeVmostServer::WireMsg w;
    uint8_t* p = reinterpret_cast<uint8_t*>(&w);
    size_t off = 0U;
    while (off < sizeof(w)) {
        const ssize_t n = read(g_fake_vmost->fds[0], p + off, sizeof(w) - off);
        if (n <= 0) {
            return -1;
        }
        off += static_cast<size_t>(n);
    }
    plat::VmostCallback cb = NULL;
    void* user = NULL;
    {
        plat::LockGuard lock(g_fake_vmost->mutex);
        cb = g_fake_vmost->cb;
        user = g_fake_vmost->user;
    }
    if (cb != NULL) {
        RawVmostMsg raw;
        memset(&raw, 0, sizeof(raw));
        raw.addr = 0x0100U;
        raw.fblock = w.fblock;
        raw.inst = w.inst;
        raw.fkt = w.fkt;
        raw.op = w.op;
        raw.len = w.len;
        raw.data = w.len > 0U ? w.data : NULL;
        cb(&raw, user);
    }
    return 0;
#else
    return -1;
#endif
}

int fakeDisconnect() {
    if (g_fake_vmost == NULL) return -1;
    plat::LockGuard lock(g_fake_vmost->mutex);
    g_fake_vmost->connected = false;
    g_fake_vmost->disconnect_called = true;
    return 0;
}

int fakeSend(void* msg) {
    if (g_fake_vmost == NULL || msg == NULL) return -1;
    const plat::VmostMsgOut* m = static_cast<const plat::VmostMsgOut*>(msg);
    FakeVmostServer::SentMsg s;
    s.addr = m->addr;
    s.fblock = m->fblock;
    s.inst = m->inst;
    s.fkt = m->fkt;
    s.op = m->op;
    if (m->len > 0U && m->data != NULL) {
        s.data.assign(m->data, m->data + m->len);
    }
    plat::LockGuard lock(g_fake_vmost->mutex);
    g_fake_vmost->sent_gets.push_back(s);
    return 0;
}

plat::VmostApi makeFakeVmostApi() {
    plat::VmostApi api;
    api.connect = &fakeConnect;
    api.shadowRegister = &fakeShadowRegister;
    api.shadowDeregister = &fakeShadowDeregister;
    api.fileDescriptorGet = &fakeFdGet;
    api.processMessages = &fakeProcessMessages;
    api.disconnect = &fakeDisconnect;
    api.send = &fakeSend;
    return api;
}

// ---- Loopback CarPlay Phone EventChannel Client ----

Bytes sha512(const Bytes& data) {
    Bytes out(64);
    crypto::sha512(data.empty() ? NULL : &data[0], data.size(), &out[0]);
    return out;
}

Bytes strBytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

Bytes shaStr(const std::string& s) {
    return sha512(strBytes(s));
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

Bytes labelNonce(const char* label) {
    Bytes n(12, 0);
    memcpy(&n[4], label, 8);
    return n;
}

Bytes sealWith(const Bytes& key, const Bytes& nonce, const Bytes& plain) {
    Bytes out;
    crypto::chacha20Poly1305Seal(&key[0], &nonce[0], NULL, 0, plain.empty() ? NULL : &plain[0],
                                 plain.size(), out);
    return out;
}

bool openWith(const Bytes& key, const Bytes& nonce, const Bytes& sealed, Bytes& plain) {
    return crypto::chacha20Poly1305Open(&key[0], &nonce[0], NULL, 0,
                                        sealed.empty() ? NULL : &sealed[0], sealed.size(), plain);
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
        pool_ = sha512(in);
    }

    std::string label_;
    uint32_t counter_;
    Bytes pool_;
};

void sleepMs(int ms) {
#ifndef _WIN32
    usleep(static_cast<useconds_t>(ms) * 1000U);
#else
    (void)ms;
#endif
}

bool waitConnected(plat::Reactor& reactor, plat::TcpConnection& conn) {
    const int64_t deadline = plat::monotonicMillis() + 2000;
    while (conn.connecting()) {
        reactor.runOnce(5);
        const plat::IoStatus st = conn.finishConnect();
        if (st == plat::kIoOk) return true;
        if (st == plat::kIoError || plat::monotonicMillis() >= deadline) return false;
    }
    reactor.runOnce(5);
    return conn.isOpen();
}

struct LoopbackPhone {
    plat::Reactor& reactor;
    crypto::Ed25519KeyPair ltsk;
    std::string id;
    crypto::X25519KeyPair eph;
    std::string acc_id;
    Bytes acc_ltpk;
    ControlCipher* control_cipher;
    ControlCipher* event_cipher;
    rtsp::Parser ctrl_parser;
    rtsp::Parser event_parser;
    uint32_t cseq;
    plat::TcpConnection ctrl_conn;
    plat::TcpConnection event_conn;

    LoopbackPhone(plat::Reactor& r, const std::string& label, const std::string& ctrl_id)
        : reactor(r), id(ctrl_id), control_cipher(NULL), event_cipher(NULL), cseq(0) {
        const Bytes seed = prefix(shaStr(label), 32);
        crypto::ed25519FromSeed(&seed[0], ltsk);
        const Bytes eseed = prefix(shaStr(label + "-eph"), 32);
        crypto::x25519FromSecret(&eseed[0], eph);
    }

    ~LoopbackPhone() {
        event_conn.close();
        ctrl_conn.close();
        delete control_cipher;
        delete event_cipher;
    }

    bool connectControl(const plat::Address& addr) {
        if (!ctrl_conn.connect(addr) || !waitConnected(reactor, ctrl_conn)) return false;
        for (int i = 0; i < 4; ++i) reactor.runOnce(5);
        return true;
    }

    bool connectEvent(const plat::Address& addr) {
        if (!event_conn.connect(addr) || !waitConnected(reactor, event_conn)) return false;
        for (int i = 0; i < 4; ++i) reactor.runOnce(5);
        return true;
    }

    bool sendAll(plat::TcpConnection& conn, const Bytes& wire) {
        size_t off = 0;
        const int64_t deadline = plat::monotonicMillis() + 2000;
        while (off < wire.size()) {
            size_t sent = 0;
            const plat::IoStatus st =
                plat::socketSend(conn.handle(), &wire[off], wire.size() - off, sent);
            if (st == plat::kIoOk) {
                off += sent;
                reactor.runOnce(1);
                continue;
            }
            if (st == plat::kIoWouldBlock && plat::monotonicMillis() < deadline) {
                reactor.runOnce(5);
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
        if (control_cipher != NULL) {
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
            const plat::IoStatus st = ctrl_conn.read(buf, sizeof(buf), got);
            if (st == plat::kIoOk && got > 0) {
                Bytes raw(buf, buf + got);
                Bytes plain;
                if (control_cipher != NULL) {
                    if (!control_cipher->feed(raw, plain)) return false;
                } else {
                    plain = raw;
                }
                if (!ctrl_parser.feed(plain, msgs)) return false;
                continue;
            }
            if (st == plat::kIoWouldBlock && plat::monotonicMillis() < deadline) {
                continue;
            }
            return false;
        }
        if (msgs.size() != 1U || !msgs[0].isResponse()) return false;
        raw_out = msgs[0];
        status_out = atoi(raw_out.path.c_str());
        return raw_out.header("cseq") == dec(my_cseq);
    }

    bool pairVerify() {
        const Bytes eph_pub(eph.public_key, eph.public_key + 32);
        Items m1;
        m1.push_back(tlv8::Item::fromByte(tlv8::kTagState, 1));
        m1.push_back(tlv8::Item(tlv8::kTagPublicKey, eph_pub));
        int status = 0;
        rtsp::Request raw;
        if (!call("POST", "/pair-verify", rtsp::kContentTypePairingTlv8, tlv8::encode(m1), status,
                  raw) ||
            status != 200) {
            return false;
        }
        Items m2;
        if (!tlv8::decode(raw.body, m2)) return false;
        const Bytes acc_eph = valueOf(m2, tlv8::kTagPublicKey);
        if (acc_eph.size() != 32U || acc_ltpk.size() != 32U) return false;
        Bytes shared(32, 0);
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
        signed2.insert(signed2.end(), acc_id.begin(), acc_id.end());
        signed2.insert(signed2.end(), eph_pub.begin(), eph_pub.end());
        if (sig.size() != 64U ||
            !crypto::ed25519Verify(&acc_ltpk[0], &signed2[0], signed2.size(), &sig[0])) {
            return false;
        }

        Bytes mine = eph_pub;
        mine.insert(mine.end(), id.begin(), id.end());
        mine.insert(mine.end(), acc_eph.begin(), acc_eph.end());
        uint8_t my_sig[64];
        crypto::ed25519Sign(ltsk.secret_key, &mine[0], mine.size(), my_sig);

        Items sub3;
        sub3.push_back(tlv8::Item(tlv8::kTagIdentifier, strBytes(id)));
        sub3.push_back(tlv8::Item(tlv8::kTagSignature, Bytes(my_sig, my_sig + 64)));
        Items m3;
        m3.push_back(tlv8::Item::fromByte(tlv8::kTagState, 3));
        m3.push_back(tlv8::Item(tlv8::kTagEncryptedData,
                                sealWith(pv_key, labelNonce("PV-Msg03"), tlv8::encode(sub3))));
        if (!call("POST", "/pair-verify", rtsp::kContentTypePairingTlv8, tlv8::encode(m3), status,
                  raw) ||
            status != 200) {
            return false;
        }
        Items m4;
        if (!tlv8::decode(raw.body, m4)) return false;
        const Bytes st4 = valueOf(m4, tlv8::kTagState);
        if (st4.size() != 1U || st4[0] != 4) return false;

        const Bytes c_read = hkdf(shared, "Control-Salt", "Control-Read-Encryption-Key");
        const Bytes c_write = hkdf(shared, "Control-Salt", "Control-Write-Encryption-Key");
        control_cipher = new ControlCipher(&c_read[0], &c_write[0]);

        const Bytes e_read = hkdf(shared, "Events-Salt", "Events-Write-Encryption-Key");
        const Bytes e_write = hkdf(shared, "Events-Salt", "Events-Read-Encryption-Key");
        event_cipher = new ControlCipher(&e_read[0], &e_write[0]);
        return true;
    }

    bool setupSession(uint16_t timing_port, int64_t& event_port_out) {
        bplist::Value req = bplist::Value::makeDict();
        req.set("timingPort", bplist::Value::makeInt(timing_port));
        req.set("name", bplist::Value::makeString("Test iPhone"));
        req.set("deviceID", bplist::Value::makeString("AA:BB:CC:DD:EE:FF"));
        req.set("model", bplist::Value::makeString("iPhone16,2"));

        int status = 0;
        rtsp::Request raw;
        if (!call("SETUP", "rtsp://127.0.0.1/session", rtsp::kContentTypeBinaryPlist,
                  encodePlist(req), status, raw) ||
            status != 200) {
            return false;
        }
        bplist::Value resp;
        if (!bplist::decode(raw.body, resp)) return false;
        event_port_out = intAt(resp, "eventPort");
        return event_port_out > 0;
    }

    bool readEventCommands(size_t min_count,
                           std::vector<bplist::Value>& cmds_out,
                           int timeout_ms = 2000) {
        const int64_t deadline = plat::monotonicMillis() + timeout_ms;
        uint8_t buf[8192];
        while (cmds_out.size() < min_count) {
            reactor.runOnce(5);
            size_t got = 0;
            const plat::IoStatus st = event_conn.read(buf, sizeof(buf), got);
            if (st == plat::kIoOk && got > 0) {
                Bytes raw(buf, buf + got);
                Bytes plain;
                if (!event_cipher->feed(raw, plain)) return false;
                std::vector<rtsp::Request> reqs;
                if (!event_parser.feed(plain, reqs)) return false;
                for (size_t i = 0; i < reqs.size(); ++i) {
                    bplist::Value cmd;
                    if (!bplist::decode(reqs[i].body, cmd)) return false;
                    cmds_out.push_back(cmd);
                    const std::string resp = "RTSP/1.0 200 OK\r\nCSeq: " +
                                             reqs[i].header("cseq") +
                                             "\r\nContent-Length: 0\r\n\r\n";
                    Bytes wire;
                    if (!event_cipher->encrypt(strBytes(resp), wire)) return false;
                    if (!sendAll(event_conn, wire)) return false;
                }
                continue;
            }
            if (st == plat::kIoWouldBlock && plat::monotonicMillis() < deadline) {
                continue;
            }
            return false;
        }
        return true;
    }
};

// ---- Recording helpers for callbacks ----

struct TouchRecord {
    std::vector<plat::TouchEventOut> events;
    static void cb(const plat::TouchEventOut& ev, void* user) {
        static_cast<TouchRecord*>(user)->events.push_back(ev);
    }
};

struct KnobRecord {
    plat::Mutex mutex;
    std::vector<plat::CcsEvent> ccs;
    std::vector<hid::Zbe3Event> zbe3;
    std::vector<bool> tel;
    std::vector<bool> ptt;
    struct HardKey {
        plat::CcsKey key;
        bool pressed;
        std::string name;
    };
    std::vector<HardKey> hard_keys;
    struct VolStep {
        unsigned steps;
        uint8_t dir;
    };
    std::vector<VolStep> vol_steps;
    std::vector<plat::VolumeLevel> vol_levels;

    static void onCcs(const plat::CcsEvent& ev, void* user) {
        KnobRecord* r = static_cast<KnobRecord*>(user);
        plat::LockGuard lock(r->mutex);
        r->ccs.push_back(ev);
    }
    static void onZbe3(const hid::Zbe3Event& hw, void* user) {
        KnobRecord* r = static_cast<KnobRecord*>(user);
        plat::LockGuard lock(r->mutex);
        r->zbe3.push_back(hw);
    }
    static void onTel(bool pressed, void* user) {
        KnobRecord* r = static_cast<KnobRecord*>(user);
        plat::LockGuard lock(r->mutex);
        r->tel.push_back(pressed);
    }
    static void onPtt(bool pressed, void* user) {
        KnobRecord* r = static_cast<KnobRecord*>(user);
        plat::LockGuard lock(r->mutex);
        r->ptt.push_back(pressed);
    }
    static void onHardKey(plat::CcsKey key, bool pressed, const char* name, void* user) {
        KnobRecord* r = static_cast<KnobRecord*>(user);
        plat::LockGuard lock(r->mutex);
        HardKey hk;
        hk.key = key;
        hk.pressed = pressed;
        hk.name = name != NULL ? name : "";
        r->hard_keys.push_back(hk);
    }
    static void onVolStep(unsigned steps, uint8_t dir, void* user) {
        KnobRecord* r = static_cast<KnobRecord*>(user);
        plat::LockGuard lock(r->mutex);
        VolStep vs;
        vs.steps = steps;
        vs.dir = dir;
        r->vol_steps.push_back(vs);
    }
    static void onVolLevel(const plat::VolumeLevel& level, void* user) {
        KnobRecord* r = static_cast<KnobRecord*>(user);
        plat::LockGuard lock(r->mutex);
        r->vol_levels.push_back(level);
    }
};

struct ListenerRecord : public plat::EvoInputListener {
    std::vector<KnobRecord::HardKey> ui_keys;
    std::vector<KnobRecord::VolStep> vol_steps;
    std::vector<plat::VolumeLevel> vol_levels;

    virtual void onUiKey(plat::CcsKey key, bool pressed, const char* name) {
        KnobRecord::HardKey hk;
        hk.key = key;
        hk.pressed = pressed;
        hk.name = name != NULL ? name : "";
        ui_keys.push_back(hk);
    }
    virtual void onVolumeStep(unsigned steps, uint8_t direction) {
        KnobRecord::VolStep vs;
        vs.steps = steps;
        vs.dir = direction;
        vol_steps.push_back(vs);
    }
    virtual void onVolumeLevel(const plat::VolumeLevel& level) {
        vol_levels.push_back(level);
    }
};

}  // namespace

// =============================================================================================
// 1. Touch packet parsing, reassembly, and TouchTracker state machine
// =============================================================================================

TEST_CASE(testIpv4UdpAndTouchMagic) {
    const uint8_t payload[6] = {0xB0U, 0x04U, 0x80U, 0x02U, 0x11U, 0x22U};
    CHECK(plat::isTouchPdu(payload, sizeof(payload)));
    CHECK(!plat::isTouchPdu(payload, 3U));
    const uint8_t bad[4] = {0xB0U, 0x04U, 0x80U, 0x03U};
    CHECK(!plat::isTouchPdu(bad, sizeof(bad)));

    const Bytes pkt = buildIpv4Udp(0xA030C773U, 0xA030C763U, 30501U, 30567U, payload, sizeof(payload));
    plat::UdpView u;
    CHECK(plat::parseIpv4Udp(&pkt[0], pkt.size(), u));
    CHECK_EQ(0xA030C773U, u.src);
    CHECK_EQ(static_cast<uint16_t>(30501U), u.sport);
    CHECK_EQ(static_cast<uint16_t>(30567U), u.dport);
    CHECK_EQ(sizeof(payload), u.len);
    CHECK(memcmp(u.data, payload, sizeof(payload)) == 0);

    // Fragmented or non-UDP packets must be rejected.
    const Bytes frag = buildIpv4Udp(0x7F000001U, 0x7F000001U, 1U, 30567U, payload, 6U, 0x2000U);
    CHECK(!plat::parseIpv4Udp(&frag[0], frag.size(), u));
    const Bytes tcp = buildIpv4Udp(0x7F000001U, 0x7F000001U, 1U, 30567U, payload, 6U, 0U, 6U);
    CHECK(!plat::parseIpv4Udp(&tcp[0], tcp.size(), u));
}

TEST_CASE(testTouchReassemblerSingleSplitAndDropRecovery) {
    plat::RawTouchContact c[2];
    c[0].id = 0;
    c[0].state = 1;
    c[0].x = 400;
    c[0].y = 240;
    c[0].size = 12;
    c[1].id = 1;
    c[1].state = 2;
    c[1].x = 600;
    c[1].y = 120;
    c[1].size = 8;

    uint8_t frame[plat::touchpdu::kFrameBytes];
    plat::buildTouchFrame(frame, c, 2, 0x11U, 0xFAU);

    // 1. Single 112-byte datagram
    plat::TouchReassembler r;
    plat::TouchMsg msgs[plat::kTouchMaxMsgs];
    CHECK_EQ(1, r.feed(frame, sizeof(frame), msgs, plat::kTouchMaxMsgs));
    CHECK_EQ(static_cast<uint8_t>(0xFAU), msgs[0].seq0);
    CHECK_EQ(static_cast<uint8_t>(0x05U), msgs[0].seq1);

    plat::RawTouchContact parsed[plat::kTouchMaxContacts];
    int declared = 0;
    CHECK_EQ(2, plat::parseTouchStream(msgs[0], parsed, plat::kTouchMaxContacts, &declared));
    CHECK_EQ(2, declared);
    CHECK_EQ(400, parsed[0].x);
    CHECK_EQ(240, parsed[0].y);
    CHECK_EQ(1, parsed[0].state);
    CHECK_EQ(0, parsed[0].id);
    CHECK_EQ(600, parsed[1].x);
    CHECK_EQ(120, parsed[1].y);
    CHECK_EQ(2, parsed[1].state);
    CHECK_EQ(1, parsed[1].id);

    // 2. 3-part split datagram
    const int recs[3] = {4, 4, 4};
    uint8_t dg[plat::touchpdu::kFrameBytes * 3];
    int sizes[3] = {0, 0, 0};
    const int parts = plat::splitTouchFrame(frame, recs, 3, dg, sizes);
    REQUIRE(parts == 3);
    r.reset();
    CHECK_EQ(0, r.feed(dg, static_cast<size_t>(sizes[0]), msgs, plat::kTouchMaxMsgs));
    CHECK_EQ(0, r.feed(dg + plat::touchpdu::kFrameBytes, static_cast<size_t>(sizes[1]), msgs,
                       plat::kTouchMaxMsgs));
    CHECK_EQ(1, r.feed(dg + plat::touchpdu::kFrameBytes * 2, static_cast<size_t>(sizes[2]), msgs,
                       plat::kTouchMaxMsgs));
    CHECK_EQ(0U, r.dropped());

    // 3. Dropped middle part followed by recovery on next 0xC5 start record
    CHECK_EQ(0, r.feed(dg, static_cast<size_t>(sizes[0]), msgs, plat::kTouchMaxMsgs));
    CHECK_EQ(0, r.feed(dg + plat::touchpdu::kFrameBytes * 2, static_cast<size_t>(sizes[2]), msgs,
                       plat::kTouchMaxMsgs));
    CHECK_EQ(1U, r.dropped());
    CHECK_EQ(1, r.feed(frame, sizeof(frame), msgs, plat::kTouchMaxMsgs));
}

TEST_CASE(testTouchTrackerPressMoveReleaseMultitouchAndPictureGate) {
    plat::TouchTracker tr(1.0, 1.0, 0.0, 0.0, 799, 479);
    plat::TouchEventOut ev[8];
    uint8_t frame[plat::touchpdu::kFrameBytes];
    plat::RawTouchContact c[2];

    // Pre-picture touch is blocked until finger lifts.
    tr.setPictureStarted(false);
    c[0].id = 0;
    c[0].state = 1;
    c[0].x = 100;
    c[0].y = 100;
    plat::buildTouchFrame(frame, c, 1, 1U, 0x00U);
    CHECK_EQ(0, tr.feed(frame, sizeof(frame), ev, 8));
    CHECK_EQ(0, tr.activeCount());

    tr.setPictureStarted(true);
    // Same finger moving while still blocked stays blocked until explicit up (state=3).
    c[0].state = 2;
    c[0].x = 120;
    plat::buildTouchFrame(frame, c, 1, 2U, 0x0CU);
    CHECK_EQ(0, tr.feed(frame, sizeof(frame), ev, 8));
    c[0].state = 3;
    plat::buildTouchFrame(frame, c, 1, 3U, 0x18U);
    CHECK_EQ(0, tr.feed(frame, sizeof(frame), ev, 8));

    // Fresh press works now.
    c[0].state = 1;
    c[0].x = 950;  // Clamped to 799
    c[0].y = 200;
    plat::buildTouchFrame(frame, c, 1, 4U, 0x24U);
    CHECK_EQ(1, tr.feed(frame, sizeof(frame), ev, 8));
    CHECK_EQ(static_cast<int>(plat::TouchEventOut::kPress), ev[0].action);
    CHECK_EQ(1, ev[0].n);
    CHECK_EQ(799, ev[0].p[0].x);
    CHECK_EQ(200, ev[0].p[0].y);

    // Duplicate seq0 is suppressed.
    CHECK_EQ(0, tr.feed(frame, sizeof(frame), ev, 8));

    // Repeated state=1 on contiguous seq treated as kMove.
    c[0].x = 400;
    c[0].y = 240;
    plat::buildTouchFrame(frame, c, 1, 5U, 0x30U);
    CHECK_EQ(1, tr.feed(frame, sizeof(frame), ev, 8));
    CHECK_EQ(static_cast<int>(plat::TouchEventOut::kMove), ev[0].action);
    CHECK_EQ(400, ev[0].p[0].x);

    // Second finger joins -> kPointerDown.
    c[0].state = 2;
    c[1].id = 1;
    c[1].state = 1;
    c[1].x = 500;
    c[1].y = 300;
    plat::buildTouchFrame(frame, c, 2, 6U, 0x3CU);
    CHECK_EQ(1, tr.feed(frame, sizeof(frame), ev, 8));
    CHECK_EQ(static_cast<int>(plat::TouchEventOut::kPointerDown), ev[0].action);
    CHECK_EQ(2, ev[0].n);
    CHECK_EQ(1, ev[0].index);

    // Finger 1 lifts -> kPointerUp.
    c[1].state = 3;
    plat::buildTouchFrame(frame, c, 2, 7U, 0x48U);
    CHECK_EQ(1, tr.feed(frame, sizeof(frame), ev, 8));
    CHECK_EQ(static_cast<int>(plat::TouchEventOut::kPointerUp), ev[0].action);
    CHECK_EQ(1, tr.activeCount());

    // Mid-gesture picture loss releases active finger at last position.
    tr.setPictureStarted(false);
    c[0].state = 2;
    c[0].x = 450;
    plat::buildTouchFrame(frame, c, 1, 8U, 0x54U);
    CHECK_EQ(1, tr.feed(frame, sizeof(frame), ev, 8));
    CHECK_EQ(static_cast<int>(plat::TouchEventOut::kRelease), ev[0].action);
    CHECK_EQ(400, ev[0].p[0].x);
    CHECK_EQ(0, tr.activeCount());
}

// =============================================================================================
// 2. vmost_client & CcsProtocol & CcsDecoder & MFL/AudioMaster
// =============================================================================================

TEST_CASE(testVmostClientParsingAndLoadStates) {
    const uint8_t data[4] = {0x11U, 0x22U, 0x33U, 0x44U};
    RawVmostMsg raw;
    memset(&raw, 0, sizeof(raw));
    raw.addr = 0x0210U;
    raw.fblock = 0xE5U;
    raw.inst = 0x01U;
    raw.fkt = 0xC20U;
    raw.op = plat::kMostOpStatus;
    raw.len = 4U;
    raw.data = data;

    plat::VmostMsgView view;
    CHECK(plat::parseVmostMsg(&raw, view));
    CHECK_EQ(static_cast<uint16_t>(0x0210U), view.addr);
    CHECK_EQ(static_cast<uint8_t>(0xE5U), view.fblock);
    CHECK_EQ(static_cast<uint8_t>(0x01U), view.inst);
    CHECK_EQ(static_cast<uint16_t>(0xC20U), view.fkt);
    CHECK_EQ(plat::kMostOpStatus, view.op);
    CHECK_EQ(static_cast<uint16_t>(4U), view.len);

    raw.op = 0x99U;
    CHECK(!plat::parseVmostMsg(&raw, view));
    CHECK(!plat::parseVmostMsg(NULL, view));

    plat::VmostMsgOut out;
    plat::buildVmostGet(out, 0x15U, 0x02U, 0x512U, data, 4U);
    CHECK_EQ(static_cast<uint16_t>(0xFFFFU), out.addr);
    CHECK_EQ(plat::kMostOpGet, out.op);
    CHECK_EQ(static_cast<uint8_t>(0x15U), out.fblock);
    CHECK_EQ(static_cast<uint16_t>(0x512U), out.fkt);

    // kNoDaemon for missing socket path
    plat::setVmostForTest("/tmp/nonexistent_vmost_sock_test_12345", NULL);
    plat::VmostClient client;
    CHECK_EQ(static_cast<int>(plat::VmostClient::kNoDaemon), static_cast<int>(client.load()));
    plat::setVmostForTest(NULL, NULL);

    // kNoSymbols for incomplete VmostApi override; kLoaded for complete override
    plat::VmostApi bad_api;
    client.setApiOverride(&bad_api);
    CHECK_EQ(static_cast<int>(plat::VmostClient::kNoSymbols), static_cast<int>(client.load()));
    const plat::VmostApi good_api = makeFakeVmostApi();
    client.setApiOverride(&good_api);
    CHECK_EQ(static_cast<int>(plat::VmostClient::kLoaded), static_cast<int>(client.load()));

#ifndef _WIN32
    // Bind a real UNIX socket in /tmp to verify kNoLibrary on missing .so
    const std::string sock_path = "/tmp/test_vmost_sock_" + dec(static_cast<uint64_t>(getpid()));
    unlink(sock_path.c_str());
    const int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd >= 0) {
        sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path.c_str());
        if (bind(sfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            plat::VmostClient lib_client;
            plat::setVmostForTest(sock_path.c_str(), "/tmp/nonexistent_vmostclient_lib.so.1");
            CHECK_EQ(static_cast<int>(plat::VmostClient::kNoLibrary),
                     static_cast<int>(lib_client.load()));
            plat::setVmostForTest(NULL, NULL);
        }
        close(sfd);
        unlink(sock_path.c_str());
    }
#endif
}

TEST_CASE(testCcsProtocolArbitrationAndTiming) {
    // Wait-2000ms mode (default)
    plat::CcsProtocol p(false);
    p.ccs35upAsked(0xFFFFFF00U);  // test 32-bit wrap
    CHECK(!p.olderDue(0xFFFFFFFFU));
    CHECK(p.olderDue(0xFFFFFF00U + 2000U));
    CHECK(!p.olderDue(0xFFFFFF00U + 2500U));  // asked once only

    // Immediate E5.01 query mode (for 2017 F20 LCI)
    plat::CcsProtocol imm(true);
    imm.ccs35upAsked(100U);
    CHECK(imm.olderDue(100U));
    CHECK(imm.accept(0x01U, 0xC20U));
    CHECK_EQ(static_cast<int>(plat::CcsProtocol::kOlder), static_cast<int>(imm.kind()));
    CHECK(!imm.accept(0x03U, 0xC46U));  // E5.03 ignored after locking E5.01

    plat::CcsProtocol newer(false);
    CHECK(newer.accept(0x03U, 0xC47U));
    CHECK_EQ(static_cast<int>(plat::CcsProtocol::kCcs35up), static_cast<int>(newer.kind()));
    CHECK(!newer.accept(0x01U, 0xC10U));
}

TEST_CASE(testCcsDecoderE501AndE503) {
    plat::CcsDecoder dec;
    plat::CcsEvent ev[8];

    // 1. E5.01 7-byte BE16 rotary (d[5] == 0x1E)
    const uint8_t r7_base[7] = {0x00U, 0x01U, 0x01U, 0xFFU, 0xFEU, 0x1EU, 0x00U};
    CHECK_EQ(0, dec.feed(0xE5U, 0x01U, 0xC10U, 0xCU, r7_base, 7U, ev, 8));  // baseline
    const uint8_t r7_wrap[7] = {0x00U, 0x01U, 0x02U, 0x00U, 0x02U, 0x1EU, 0x00U};
    CHECK_EQ(1, dec.feed(0xE5U, 0x01U, 0xC10U, 0xCU, r7_wrap, 7U, ev, 8));
    CHECK_EQ(static_cast<int>(plat::CcsEvent::kRotary), ev[0].kind);
    CHECK_EQ(4, ev[0].delta);
    // Overflow d[6] != 0 rebases silently
    const uint8_t r7_ovf[7] = {0x00U, 0x01U, 0x03U, 0x00U, 0x10U, 0x1EU, 0x01U};
    CHECK_EQ(0, dec.feed(0xE5U, 0x01U, 0xC10U, 0xCU, r7_ovf, 7U, ev, 8));

    // 2. E5.01 4-byte compact 8-bit rotary
    const uint8_t r4_base[4] = {0x00U, 0x01U, 0x01U, 0xFEU};
    CHECK_EQ(0, dec.feed(0xE5U, 0x01U, 0xC10U, 0xCU, r4_base, 4U, ev, 8));
    const uint8_t r4_step[4] = {0x00U, 0x01U, 0x02U, 0x02U};
    CHECK_EQ(1, dec.feed(0xE5U, 0x01U, 0xC10U, 0xCU, r4_step, 4U, ev, 8));
    CHECK_EQ(4, ev[0].delta);

    // 3. E5.01 0xC20 center push, 4-way tilt, and all 7 hard keys
    const uint8_t push_dn[7] = {0, 0, 1, 1, 0, 0x1EU, 1};
    CHECK_EQ(1, dec.feed(0xE5U, 0x01U, 0xC20U, 0xCU, push_dn, 7U, ev, 8));
    CHECK_EQ(static_cast<int>(plat::kCcsKeyCenter), static_cast<int>(ev[0].key));
    CHECK(ev[0].down);
    CHECK(dec.centerPressed(true));

    const uint8_t tilt_left[7] = {0, 0, 2, 1, 8, 0x1DU, 0};
    CHECK_EQ(1, dec.feed(0xE5U, 0x01U, 0xC20U, 0xCU, tilt_left, 7U, ev, 8));
    CHECK_EQ(static_cast<int>(plat::kCcsKeyLeft), static_cast<int>(ev[0].key));
    CHECK_EQ(hid::zbe3::kDirLeft, ev[0].dir_mask);
    CHECK(ev[0].down);

    const uint8_t tilt_up[7] = {0, 0, 3, 0, 0, 0x1DU, 0};
    CHECK_EQ(1, dec.feed(0xE5U, 0x01U, 0xC20U, 0xCU, tilt_up, 7U, ev, 8));
    CHECK(!ev[0].down);

    // MENU (0x01) + COM (0x40) + OPTION (0x04)
    const uint8_t hk_dn[7] = {0, 0, 4, 1, 0, 0x00U, 0x45U};
    CHECK_EQ(3, dec.feed(0xE5U, 0x01U, 0xC20U, 0xCU, hk_dn, 7U, ev, 8));
    CHECK_EQ(static_cast<uint8_t>(0x45U), dec.buttonMask(true));
    const uint8_t hk_up[7] = {0, 0, 5, 0, 0, 0x00U, 0x00U};
    CHECK_EQ(3, dec.feed(0xE5U, 0x01U, 0xC20U, 0xCU, hk_up, 7U, ev, 8));
    CHECK_EQ(static_cast<uint8_t>(0x00U), dec.buttonMask(true));

    // 4. E5.03 0xC46 rotary/tilt/push & 0xC47 normalized capacitive buttons
    const uint8_t c46_0[5] = {0, 0x00U, 0x10U, 0x00U, 0x00U};
    CHECK_EQ(0, dec.feed(0xE5U, 0x03U, 0xC46U, 0xCU, c46_0, 5U, ev, 8));
    const uint8_t c46_1[5] = {0, 0x00U, 0x13U, 0x01U, 0x04U};  // +3 steps, push, 4 o'clock -> Right
    CHECK_EQ(3, dec.feed(0xE5U, 0x03U, 0xC46U, 0xCU, c46_1, 5U, ev, 8));
    CHECK_EQ(3, ev[0].delta);
    CHECK_EQ(static_cast<int>(plat::kCcsKeyRight), static_cast<int>(ev[1].key));
    CHECK_EQ(static_cast<int>(plat::kCcsKeyCenter), static_cast<int>(ev[2].key));

    // NormalizePushButtons: 4=finger rest -> 0, 1/2/3 -> 1, 7 -> keep prev
    uint8_t prev[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    const uint8_t raw_btns[7] = {7, 4, 1, 2, 3, 0, 4};  // MENU kept(1), BACK rest(0), OPTION/COM/MEDIA pressed(1)
    uint8_t norm[8];
    memset(norm, 0, sizeof(norm));
    plat::normalizePushButtons(raw_btns, 7U, prev, norm);
    CHECK_EQ(static_cast<uint8_t>(1U), norm[0]);
    CHECK_EQ(static_cast<uint8_t>(0U), norm[1]);
    CHECK_EQ(static_cast<uint8_t>(1U), norm[2]);
    CHECK_EQ(static_cast<uint8_t>(1U), norm[3]);
    CHECK_EQ(static_cast<uint8_t>(1U), norm[4]);
    CHECK_EQ(static_cast<uint8_t>(0U), norm[5]);
}

TEST_CASE(testMflAndAudioMasterDecoders) {
    const uint8_t down[1] = {1U};
    const uint8_t up[1] = {0U};
    const uint8_t noinfo[1] = {7U};
    CHECK_EQ(1, plat::decodeTelephoneButton(msgView(0x15U, 0x02U, 0x400U, 0xCU, down, 1U)));
    CHECK_EQ(0, plat::decodeTelephoneButton(msgView(0x15U, 0x02U, 0x400U, 0xCU, up, 1U)));
    CHECK_EQ(-1, plat::decodeTelephoneButton(msgView(0x15U, 0x02U, 0x400U, 0xCU, noinfo, 1U)));

    CHECK_EQ(1, plat::decodePttButton(msgView(0x15U, 0x02U, 0x512U, 0xCU, down, 1U)));
    CHECK_EQ(0, plat::decodePttButton(msgView(0x15U, 0x02U, 0x512U, 0xCU, up, 1U)));

    const uint8_t vol_cs[2] = {2U, 3U};
    unsigned steps = 0U;
    uint8_t dir = 0U;
    CHECK_EQ(1, plat::decodeVolumeButton(msgView(0x15U, 0x0CU, 0xC01U, 0xCU, vol_cs, 2U),
                                         &steps, &dir));
    CHECK_EQ(3U, steps);
    CHECK_EQ(static_cast<uint8_t>(2U), dir);

    const uint8_t vol_mfl[4] = {0U, 0U, 1U, 2U};
    CHECK_EQ(1, plat::decodeVolumeButton(msgView(0x15U, 0x02U, 0x401U, 0xCU, vol_mfl, 4U),
                                         &steps, &dir));
    CHECK_EQ(2U, steps);
    CHECK_EQ(static_cast<uint8_t>(1U), dir);

    const uint8_t lvl_raw[5] = {0U, 0U, 25U, 0U, 64U};
    plat::VolumeLevel lvl;
    CHECK(plat::decodeVolumeLevel(msgView(0x20U, 0x00U, 0xC08U, 0xCU, lvl_raw, 5U), lvl));
    CHECK_EQ(25U, lvl.value);
    CHECK_EQ(0U, lvl.min);
    CHECK_EQ(64U, lvl.max);
}

// =============================================================================================
// 3. EvoKnob worker thread (fake VmostApi + socketpair) & EvoTouch localhost UDP worker
// =============================================================================================

TEST_CASE(testEvoKnobWorkerThreadWithFakeVmost) {
#ifdef _WIN32
    return;
#endif
    FakeVmostServer fake;
    REQUIRE(fake.init());
    g_fake_vmost = &fake;

    KnobRecord rec;
    plat::EvoKnob knob;
    knob.setOwned(true);
    knob.setZbe3Callback(&KnobRecord::onZbe3, &rec);
    knob.setMflTelephoneCallback(&KnobRecord::onTel, &rec);
    knob.setMflPttCallback(&KnobRecord::onPtt, &rec);
    knob.setHardKeyCallback(&KnobRecord::onHardKey, &rec);
    knob.setVolumeCallback(&KnobRecord::onVolStep, &rec);
    knob.setVolumeLevelCallback(&KnobRecord::onVolLevel, &rec);

    plat::EvoKnobConfig cfg;
    cfg.mode = plat::kInputForward;
    cfg.query_older_immediately = true;
    cfg.use_api_override = true;
    cfg.api_override = makeFakeVmostApi();
    REQUIRE(knob.start(cfg, &KnobRecord::onCcs, &rec));

    // Wait until filter-opening Gets complete (3 CCS35up + 2 E5.01 + 2 vol + 2 MFL + 1 AudioMaster = 10)
    const int64_t deadline = plat::monotonicMillis() + 2000;
    while (plat::monotonicMillis() < deadline) {
        {
            plat::LockGuard lock(fake.mutex);
            if (fake.sent_gets.size() >= 10U) {
                break;
            }
        }
        sleepMs(5);
    }
    {
        plat::LockGuard lock(fake.mutex);
        CHECK_EQ(10U, fake.sent_gets.size());
        CHECK_EQ(6U, fake.registered.size());
        bool saw_ptt_get = false;
        bool saw_e501_rot = false;
        bool saw_e501_btn = false;
        for (size_t i = 0; i < fake.sent_gets.size(); ++i) {
            if (fake.sent_gets[i].fblock == 0x15U && fake.sent_gets[i].inst == 0x02U &&
                fake.sent_gets[i].fkt == 0x512U) {
                saw_ptt_get = true;
            }
            if (fake.sent_gets[i].fblock == 0xE5U && fake.sent_gets[i].inst == 0x01U &&
                fake.sent_gets[i].fkt == 0xC10U) {
                saw_e501_rot = true;
            }
            if (fake.sent_gets[i].fblock == 0xE5U && fake.sent_gets[i].inst == 0x01U &&
                fake.sent_gets[i].fkt == 0xC20U) {
                saw_e501_btn = true;
            }
        }
        CHECK(saw_ptt_get);
        CHECK(saw_e501_rot);
        CHECK(saw_e501_btn);
    }

    // Inject E5.01 push, MFL PTT, Volume, AudioMaster level, then drop ownership while button held.
    const uint8_t menu_dn[7] = {0, 0, 1, 1, 0, 0x00U, 0x01U};
    const uint8_t ptt_dn[1] = {1U};
    const uint8_t ptt_up[1] = {0U};
    const uint8_t vol[2] = {1U, 2U};
    const uint8_t lvl[5] = {0U, 0U, 30U, 0U, 64U};
    REQUIRE(fake.inject(0xE5U, 0x01U, 0xC20U, 0xCU, menu_dn, 7U));
    REQUIRE(fake.inject(0x15U, 0x02U, 0x512U, 0xCU, ptt_dn, 1U));
    REQUIRE(fake.inject(0x15U, 0x02U, 0x512U, 0xCU, ptt_up, 1U));
    REQUIRE(fake.inject(0x15U, 0x0CU, 0xC01U, 0xCU, vol, 2U));
    REQUIRE(fake.inject(0x20U, 0x00U, 0xC08U, 0xCU, lvl, 5U));

    const int64_t wait_dl = plat::monotonicMillis() + 2000;
    while (plat::monotonicMillis() < wait_dl) {
        {
            plat::LockGuard lock(rec.mutex);
            if (!rec.zbe3.empty() && rec.ptt.size() >= 2U && !rec.vol_steps.empty() &&
                !rec.vol_levels.empty()) {
                break;
            }
        }
        sleepMs(5);
    }
    {
        plat::LockGuard lock(rec.mutex);
        REQUIRE(!rec.zbe3.empty());
        CHECK_EQ(hid::zbe3::kBtnMenu, rec.zbe3[0].button_mask);
        REQUIRE(rec.ptt.size() >= 2U);
        CHECK(rec.ptt[0]);
        CHECK(!rec.ptt[1]);
        REQUIRE(!rec.vol_steps.empty());
        CHECK_EQ(2U, rec.vol_steps[0].steps);
        REQUIRE(!rec.vol_levels.empty());
        CHECK_EQ(30U, rec.vol_levels[0].value);
    }

    // Losing ownership releases held MENU key automatically within ~100ms poll cycle.
    knob.setOwned(false);
    const int64_t rel_dl = plat::monotonicMillis() + 2000;
    while (plat::monotonicMillis() < rel_dl) {
        {
            plat::LockGuard lock(rec.mutex);
            if (rec.zbe3.size() >= 2U) {
                break;
            }
        }
        sleepMs(5);
    }
    {
        plat::LockGuard lock(rec.mutex);
        REQUIRE(rec.zbe3.size() >= 2U);
        CHECK_EQ(static_cast<uint8_t>(0U), rec.zbe3[1].button_mask);
    }

    knob.stop();
    CHECK(fake.disconnect_called);
    g_fake_vmost = NULL;
}

TEST_CASE(testEvoTouchUdpWorkerAndTimeout) {
    TouchRecord rec;
    plat::EvoTouch touch;
    touch.setDisplaySize(800, 480);
    touch.setOwned(true);
    REQUIRE(touch.startUdpForTest(0, plat::kInputForward, &TouchRecord::cb, &rec));
    const uint16_t port = touch.boundUdpPort();
    REQUIRE(port > 0U);

    plat::UdpSocket sender;
    REQUIRE(sender.open(plat::Address::ipv4Loopback(0)));

    uint8_t frame[plat::touchpdu::kFrameBytes];
    plat::RawTouchContact c;
    c.id = 0;
    c.state = 1;
    c.x = 250;
    c.y = 180;
    plat::buildTouchFrame(frame, &c, 1, 1U, 0x10U);
    CHECK_EQ(static_cast<int>(plat::kIoOk),
             static_cast<int>(sender.sendTo(frame, sizeof(frame), plat::Address::ipv4Loopback(port))));

    // Wait for kPress via UDP worker
    const int64_t dl1 = plat::monotonicMillis() + 2000;
    while (plat::monotonicMillis() < dl1) {
        if (!rec.events.empty()) break;
        sleepMs(5);
    }
    touch.stop();
    REQUIRE(!rec.events.empty());
    CHECK_EQ(static_cast<int>(plat::TouchEventOut::kPress), rec.events[0].action);
    CHECK_EQ(250, rec.events[0].p[0].x);
    CHECK_EQ(180, rec.events[0].p[0].y);

    // Timeout release check (synchronous test helper)
    TouchRecord rec2;
    plat::EvoTouch t2;
    t2.setDisplaySize(800, 480);
    t2.setOwned(true);
    t2.attachForTest(plat::kInputForward, &TouchRecord::cb, &rec2);
    t2.feedUdpPayload(frame, sizeof(frame), 0x7F000001U, 30501U, 1000U);
    t2.checkTimeoutForTest(1200U);
    CHECK_EQ(1U, rec2.events.size());
    t2.checkTimeoutForTest(1400U);
    REQUIRE(rec2.events.size() == 2U);
    CHECK_EQ(static_cast<int>(plat::TouchEventOut::kRelease), rec2.events[1].action);
}

// =============================================================================================
// 4. End-to-End EvoInputBridge + SessionServer + Encrypted EventChannel Loopback Client
// =============================================================================================

TEST_CASE(testEvoInputBridgeE2eOverEncryptedEventChannel) {
#ifdef _WIN32
    return;
#endif
    FakeVmostServer fake;
    REQUIRE(fake.init());
    g_fake_vmost = &fake;

    plat::Reactor reactor;
    REQUIRE(reactor.init());

    DetRng rng("evo-input-e2e");
    pairing::Identity identity;
    REQUIRE(pairing::generateIdentity(rng, identity));

    pairing::InMemoryPairingStore store;
    LoopbackPhone phone(reactor, "phone-e2e-ltsk", "11223344-5566-4777-8888-99AABBCCDDEE");
    phone.acc_id = identity.pairing_id;
    phone.acc_ltpk.assign(identity.keys.public_key, identity.keys.public_key + 32);
    REQUIRE(store.save(phone.id, phone.ltsk.public_key));

    session::SessionListener sess_listener;
    session::MediaHandler media_handler;
    const info::AirPlayConfig cfg = info::bmwEntryNav2_800x480(true);
    plat::SessionServerConfig srv_cfg;
    srv_cfg.control_port = 0;
    srv_cfg.ntp_request_interval_ms = 0;
    plat::SessionServer server(reactor, cfg, identity, store, rng, sess_listener, media_handler,
                               NULL, srv_cfg);
    REQUIRE(server.start(plat::Address::ipv4Loopback(0)));

    REQUIRE(phone.connectControl(plat::Address::ipv4Loopback(server.controlPort())));
    REQUIRE(phone.pairVerify());

    plat::UdpSocket phone_timing;
    REQUIRE(phone_timing.open(plat::Address::ipv4Loopback(0)));
    int64_t srv_event_port = 0;
    REQUIRE(phone.setupSession(phone_timing.port(), srv_event_port));
    REQUIRE(phone.connectEvent(plat::Address::ipv4Loopback(static_cast<uint16_t>(srv_event_port))));
    REQUIRE(server.hasEventConnection());

    ListenerRecord ui_listener;
    plat::EvoInputBridgeConfig br_cfg;
    br_cfg.display_width = 800;
    br_cfg.display_height = 480;
    br_cfg.menu_to_carplay = true;
    br_cfg.phone_to_idrive = false;
    plat::EvoInputBridge bridge(reactor, server, br_cfg, &ui_listener);

    plat::EvoKnob knob;
    plat::EvoTouch touch;
    bridge.attach(&knob, &touch);
    bridge.setOwned(true);

    plat::EvoKnobConfig kcfg;
    kcfg.mode = plat::kInputForward;
    kcfg.query_older_immediately = true;
    kcfg.use_api_override = true;
    kcfg.api_override = makeFakeVmostApi();
    REQUIRE(knob.start(kcfg, NULL, NULL));
    REQUIRE(touch.startUdpForTest(0, plat::kInputForward, NULL, NULL));

    // Wait for EvoKnob init Gets before injecting messages
    const int64_t knob_dl = plat::monotonicMillis() + 2000;
    while (plat::monotonicMillis() < knob_dl) {
        {
            plat::LockGuard lock(fake.mutex);
            if (fake.sent_gets.size() >= 10U) break;
        }
        sleepMs(5);
    }

    // 1. E5.01 Rotary baseline + +2 detents -> 2 knob reports (+2 then 0)
    const uint8_t r_base[7] = {0, 1, 1, 0x00U, 0x10U, 0x1EU, 0x00U};
    const uint8_t r_plus2[7] = {0, 1, 2, 0x00U, 0x12U, 0x1EU, 0x00U};
    REQUIRE(fake.inject(0xE5U, 0x01U, 0xC10U, 0xCU, r_base, 7U));
    REQUIRE(fake.inject(0xE5U, 0x01U, 0xC10U, 0xCU, r_plus2, 7U));

    // 2. E5.01 COM button press/release -> telephony press (1) + release (0) = 2 reports
    const uint8_t com_dn[7] = {0, 0, 1, 1, 0, 0x00U, 0x40U};
    const uint8_t com_up[7] = {0, 0, 2, 0, 0, 0x00U, 0x00U};
    REQUIRE(fake.inject(0xE5U, 0x01U, 0xC20U, 0xCU, com_dn, 7U));
    REQUIRE(fake.inject(0xE5U, 0x01U, 0xC20U, 0xCU, com_up, 7U));

    // 3. E5.01 MEDIA button press/release -> media press (3) + release (0) = 2 reports
    const uint8_t med_dn[7] = {0, 0, 3, 1, 0, 0x00U, 0x08U};
    const uint8_t med_up[7] = {0, 0, 4, 0, 0, 0x00U, 0x00U};
    REQUIRE(fake.inject(0xE5U, 0x01U, 0xC20U, 0xCU, med_dn, 7U));
    REQUIRE(fake.inject(0xE5U, 0x01U, 0xC20U, 0xCU, med_up, 7U));

    // 4. MFL PTT press -> requestSiri
    const uint8_t ptt_dn[1] = {1U};
    const uint8_t ptt_up[1] = {0U};
    REQUIRE(fake.inject(0x15U, 0x02U, 0x512U, 0xCU, ptt_dn, 1U));
    REQUIRE(fake.inject(0x15U, 0x02U, 0x512U, 0xCU, ptt_up, 1U));

    // 5. Real UDP touch press + release -> 2 touchscreen reports
    plat::UdpSocket touch_sender;
    REQUIRE(touch_sender.open(plat::Address::ipv4Loopback(0)));
    uint8_t tframe[plat::touchpdu::kFrameBytes];
    plat::RawTouchContact tc;
    tc.id = 0;
    tc.state = 1;
    tc.x = 321;
    tc.y = 222;
    plat::buildTouchFrame(tframe, &tc, 1, 1U, 0x00U);
    REQUIRE(touch_sender.sendTo(tframe, sizeof(tframe),
                                plat::Address::ipv4Loopback(touch.boundUdpPort())) == plat::kIoOk);

    tc.state = 3;
    plat::buildTouchFrame(tframe, &tc, 1, 2U, 0x0CU);
    REQUIRE(touch_sender.sendTo(tframe, sizeof(tframe),
                                plat::Address::ipv4Loopback(touch.boundUdpPort())) == plat::kIoOk);

    // Expect 10 commands on encrypted EventChannel:
    //   2 knob (wheel +2, 0), 2 telephony (1, 0), 2 media (3, 0),
    //   2 requestSiri (siriAction 2, 3), 2 touch (down, up)
    std::vector<bplist::Value> cmds;
    REQUIRE(phone.readEventCommands(10U, cmds, 3000));

    int knob_cnt = 0;
    int tel_cnt = 0;
    int media_cnt = 0;
    int touch_cnt = 0;
    int siri_cnt = 0;
    std::vector<int64_t> siri_actions;
    bool saw_wheel_plus2 = false;
    bool saw_touch_down_321_222 = false;
    bool saw_touch_up = false;

    for (size_t i = 0; i < cmds.size(); ++i) {
        const std::string type = strAt(cmds[i], "type");
        if (type == "requestSiri") {
            ++siri_cnt;
            const bplist::Value* p = cmds[i].find("params");
            REQUIRE(p != NULL);
            siri_actions.push_back(intAt(*p, "siriAction"));
        } else if (type == "hidSendReport") {
            const std::string uid = strAt(cmds[i], "uuid");
            const bplist::Value* rep = cmds[i].find("hidReport");
            REQUIRE(rep != NULL && rep->isData());
            const Bytes& b = rep->asData();
            if (uid == "2a2a2a2b") {
                ++knob_cnt;
                REQUIRE(b.size() == 4U);
                if (static_cast<int8_t>(b[3]) == 2) {
                    saw_wheel_plus2 = true;
                }
            } else if (uid == "2a2a2a2d") {
                ++tel_cnt;
                REQUIRE(b.size() == 1U);
            } else if (uid == "2a2a2a2c") {
                ++media_cnt;
                REQUIRE(b.size() == 1U);
            } else if (uid == "2a2a2a2a") {
                ++touch_cnt;
                REQUIRE(b.size() == 12U);
                const uint16_t x = static_cast<uint16_t>(b[2] | (b[3] << 8));
                const uint16_t y = static_cast<uint16_t>(b[4] | (b[5] << 8));
                if (b[1] == 1U && x == 321U && y == 222U) {
                    saw_touch_down_321_222 = true;
                } else if (b[1] == 0U) {
                    saw_touch_up = true;
                }
            }
        }
    }

    CHECK_EQ(2, knob_cnt);
    CHECK(saw_wheel_plus2);
    CHECK_EQ(2, tel_cnt);
    CHECK_EQ(2, media_cnt);
    CHECK_EQ(2, siri_cnt);
    REQUIRE(siri_actions.size() == 2U);
    CHECK_EQ(static_cast<int64_t>(2), siri_actions[0]);
    CHECK_EQ(static_cast<int64_t>(3), siri_actions[1]);
    CHECK_EQ(2, touch_cnt);
    CHECK(saw_touch_down_321_222);
    CHECK(saw_touch_up);

    // 6. Test phone_to_idrive = true suppresses COM & MFL Tel, and setOwned(false) releases held touch & knob
    bridge.setPhoneToIdrive(true);
    hid::Zbe3Event com_ev;
    com_ev.button_mask = hid::zbe3::kBtnCom;
    bridge.handleZbe3(com_ev);
    bridge.handleMflTelephone(true);
    CHECK_EQ(2ULL, bridge.telephonyReportsSent());  // unchanged!

    // Hold MENU and Touch down, then setOwned(false) -> sends zero knob + touch up on wire
    hid::Zbe3Event menu_ev;
    menu_ev.button_mask = hid::zbe3::kBtnMenu;
    bridge.handleZbe3(menu_ev);

    plat::TouchEventOut tdown;
    tdown.action = plat::TouchEventOut::kPress;
    tdown.n = 1;
    tdown.p[0].id = 0;
    tdown.p[0].x = 100;
    tdown.p[0].y = 100;
    bridge.handleTouch(tdown);
    CHECK(bridge.touchDown());

    bridge.setOwned(false);
    CHECK(!bridge.touchDown());
    CHECK(!bridge.lastKnobState().home);

    std::vector<bplist::Value> rel_cmds;
    REQUIRE(phone.readEventCommands(4U, rel_cmds, 2000));
    CHECK_EQ(4U, rel_cmds.size());

    knob.stop();
    touch.stop();
    bridge.detach();
    server.stop();
    g_fake_vmost = NULL;
}

int main() {
    return test_support::runAll("test_evo_input");
}
