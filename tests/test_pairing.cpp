// Pair-Setup / Pair-Verify (accessory side) tests.
//
// The CONTROLLER (iPhone) side is implemented here independently, strictly from the protocol
// description (SRP-6a client adapted from test_srp6a.cpp, M5 builder, M6 checker, pair-verify
// client). Label nonces are built locally (4 zero bytes + 8 ASCII bytes) rather than via
// crypto::makeLabelNonce. All randomness comes from a deterministic SHA-512 based RandomSource.
//
// The pinned M2 vectors at the bottom are REGRESSION vectors produced by this implementation
// (not by an independent tool); they guard against silent wire changes.

#include "carplay/airplay_crypto.hpp"
#include "carplay/bigint.hpp"
#include "carplay/control_cipher.hpp"
#include "carplay/pairing.hpp"
#include "carplay/srp6a.hpp"
#include "carplay/tlv8_codec.hpp"
#include "test_support.hpp"

#include <string.h>

#include <string>
#include <vector>

using carplay::bigint::Modulus;
using carplay::bigint::Number;
using test_support::bytesToHex;
using test_support::hexToBytes;

namespace bi = carplay::bigint;
namespace srp = carplay::srp;
namespace crypto = carplay::crypto;
namespace tlv8 = carplay::tlv8;
namespace pairing = carplay::pairing;

typedef std::vector<uint8_t> Bytes;
typedef std::vector<tlv8::Item> Items;

namespace {

// ---------------------------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------------------------

Bytes sha(const Bytes& data) {
    Bytes out(64);
    crypto::sha512(data.empty() ? NULL : &data[0], data.size(), &out[0]);
    return out;
}

Bytes shaStr(const std::string& s) { return sha(Bytes(s.begin(), s.end())); }

Bytes prefix(const Bytes& v, size_t n) { return Bytes(v.begin(), v.begin() + static_cast<long>(n)); }

void cat(Bytes& out, const Bytes& v) { out.insert(out.end(), v.begin(), v.end()); }

Bytes strBytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

Bytes arr(const uint8_t* p, size_t n) { return Bytes(p, p + n); }

Bytes hkdf(const Bytes& ikm, const std::string& salt, const std::string& info) {
    Bytes out;
    crypto::hkdfSha512(ikm, salt, info, 32, out);
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
    crypto::chacha20Poly1305Seal(&key[0], &n[0], NULL, 0, plain.empty() ? NULL : &plain[0],
                                 plain.size(), out);
    return out;
}

bool open(const Bytes& key, const char* label, const Bytes& sealed, Bytes& plain) {
    const Bytes n = nonceFor(label);
    return crypto::chacha20Poly1305Open(&key[0], &n[0], NULL, 0,
                                        sealed.empty() ? NULL : &sealed[0], sealed.size(), plain);
}

Bytes errorTlv(uint8_t state) {
    Bytes b;
    b.push_back(0x06);
    b.push_back(0x01);
    b.push_back(state);
    b.push_back(0x07);
    b.push_back(0x01);
    b.push_back(0x02);
    return b;
}

tlv8::Item item(uint8_t t, const Bytes& v) { return tlv8::Item(t, v); }
tlv8::Item stateItem(uint8_t s) { return tlv8::Item::fromByte(tlv8::kTagState, s); }

bool decodeItems(const Bytes& b, Items& items) { return tlv8::decode(b, items); }

Bytes typesOf(const Items& items) {
    Bytes t;
    for (size_t i = 0; i < items.size(); ++i) t.push_back(items[i].type);
    return t;
}

Bytes valueOf(const Items& items, uint8_t t) {
    const tlv8::Item* it = tlv8::findFirst(items, t);
    return it == NULL ? Bytes() : it->value;
}

// Deterministic RandomSource: SHA-512(label | counter_be32) stream. Optionally fails after
// `fail_after` successful fill() calls.
class DetRng : public pairing::RandomSource {
public:
    explicit DetRng(const std::string& label, int fail_after = -1)
        : label_(label), counter_(0), calls_(0), fail_after_(fail_after) {}

    virtual bool fill(uint8_t* out, size_t len) {
        if (fail_after_ >= 0 && calls_ >= fail_after_) return false;
        ++calls_;
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
    int calls_;
    int fail_after_;
    Bytes pool_;
};

// ---------------------------------------------------------------------------------------------
// SRP-6a client (adapted from test_srp6a.cpp).
// ---------------------------------------------------------------------------------------------

Bytes minimalOf(const Bytes& v) {
    size_t i = 0;
    while (i < v.size() && v[i] == 0) ++i;
    if (i == v.size()) return Bytes(1, 0);
    return Bytes(v.begin() + static_cast<long>(i), v.end());
}

Bytes padOf(const Bytes& v) {
    Bytes m = minimalOf(v);
    if (m.size() >= 384) return m;
    Bytes out(384 - m.size(), 0);
    cat(out, m);
    return out;
}

Bytes numBytes(const Number& n) {
    Bytes out;
    bi::toBytesBE(n, out);
    return out;
}

Number numOf(const Bytes& b) {
    Number n;
    bi::fromBytesBE(b.empty() ? NULL : &b[0], b.size(), n);
    return n;
}

Bytes primeBytes() { return Bytes(srp::rfc5054Prime3072(), srp::rfc5054Prime3072() + 384); }

struct SrpClient {
    Bytes a;      // private exponent
    Bytes a_pub;  // pad(A)
    Bytes k;      // session key
    Bytes m1;
    Bytes m2;     // expected server proof

    explicit SrpClient(const std::string& label) : a(prefix(shaStr(label), 32)) {
        Number pub;
        srp::group3072().modExp(bi::fromUint32(5), &a[0], a.size(), pub);
        bi::toBytesBEPadded(pub, 384, a_pub);
    }

    bool compute(const Bytes& b_pub, const Bytes& salt, const std::string& pass) {
        const std::string user = "Pair-Setup";
        const Modulus& m = srp::group3072();
        const Bytes n = primeBytes();
        Bytes buf = minimalOf(n);
        cat(buf, padOf(Bytes(1, 5)));
        const Number kk = numOf(sha(buf));
        buf = salt;
        cat(buf, shaStr(user + ":" + pass));
        const Bytes x = sha(buf);
        buf = a_pub;
        cat(buf, padOf(b_pub));
        const Bytes u = sha(buf);

        Number v, kv, t, ta, tu, tux, s;
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
        const Bytes hg = sha(Bytes(1, 5));
        buf.clear();
        for (size_t i = 0; i < 64; ++i) buf.push_back(static_cast<uint8_t>(hn[i] ^ hg[i]));
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

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

const char* const kAccessoryId = "a1b2c3d4-0000-4000-8000-0123456789ab";
const char* const kControllerId = "5A2C7E1F-9B3D-4C8A-A6E2-11223344CAFE";

void makeAccessory(pairing::Identity& id) {
    const Bytes seed = prefix(shaStr("accessory-seed"), 32);
    id.initFromSeed(&seed[0], kAccessoryId);
}

struct Controller {
    std::string id;
    crypto::Ed25519KeyPair keys;

    Controller(const std::string& label, const std::string& pairing_id) : id(pairing_id) {
        const Bytes seed = prefix(shaStr(label), 32);
        crypto::ed25519FromSeed(&seed[0], keys);
    }
    Bytes ltpk() const { return arr(keys.public_key, 32); }
    Bytes sign(const Bytes& data) const {
        Bytes sig(64);
        crypto::ed25519Sign(keys.secret_key, &data[0], data.size(), &sig[0]);
        return sig;
    }
};

Bytes send(pairing::PairSetup& ps, const Items& items) {
    Bytes resp;
    ps.handle(tlv8::encode(items), resp);
    return resp;
}

Bytes send(pairing::PairVerify& pv, const Items& items) {
    Bytes resp;
    pv.handle(tlv8::encode(items), resp);
    return resp;
}

// M1 -> M2. Fills B and salt; returns false if M2 is not well-formed.
bool setupM1(pairing::PairSetup& ps, Bytes& b_pub, Bytes& salt, Bytes* raw = NULL) {
    Items req;
    req.push_back(item(tlv8::kTagMethod, Bytes(1, 0)));
    req.push_back(stateItem(1));
    const Bytes resp = send(ps, req);
    if (raw != NULL) *raw = resp;
    Items items;
    if (!decodeItems(resp, items)) return false;
    if (typesOf(items) != hexToBytes("060302")) return false;
    if (valueOf(items, 0x06) != Bytes(1, 2)) return false;
    b_pub = valueOf(items, 0x03);
    salt = valueOf(items, 0x02);
    return b_pub.size() == 384 && salt.size() == 16;
}

Bytes m3Request(const SrpClient& c) {
    Items req;
    req.push_back(stateItem(3));
    req.push_back(item(tlv8::kTagPublicKey, c.a_pub));
    req.push_back(item(tlv8::kTagProof, c.m1));
    return tlv8::encode(req);
}

// M1..M4 with the correct setup code; K is the client's session key.
bool setupToM4(pairing::PairSetup& ps, Bytes& k) {
    Bytes b_pub, salt;
    if (!setupM1(ps, b_pub, salt)) return false;
    SrpClient c("ctrl-srp-a");
    if (!c.compute(b_pub, salt, "3939")) return false;
    Bytes resp;
    ps.handle(m3Request(c), resp);
    Items items;
    if (!decodeItems(resp, items)) return false;
    if (typesOf(items) != hexToBytes("0604")) return false;
    if (valueOf(items, 0x06) != Bytes(1, 4)) return false;
    if (valueOf(items, 0x04) != c.m2) return false;  // server proof validates on the client
    k = c.k;
    return true;
}

struct M5Opts {
    bool omit_id, omit_pk, omit_sig, bad_sig, tamper;
    bool override_id;
    std::string id;
    size_t pk_len, sig_len;
    M5Opts()
        : omit_id(false), omit_pk(false), omit_sig(false), bad_sig(false), tamper(false),
          override_id(false), pk_len(32), sig_len(64) {}
};

Bytes m5Request(const Bytes& k, const Controller& ctrl, const M5Opts& o = M5Opts()) {
    const Bytes enc_key = hkdf(k, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info");
    const std::string id = o.override_id ? o.id : ctrl.id;
    Bytes data = hkdf(k, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info");
    cat(data, strBytes(id));
    cat(data, ctrl.ltpk());
    Bytes sig = ctrl.sign(data);
    if (o.bad_sig) {
        const Controller other("other-controller-seed", ctrl.id);
        sig = other.sign(data);
    }
    Bytes pk = ctrl.ltpk();
    pk.resize(o.pk_len, 0xaa);
    sig.resize(o.sig_len, 0x55);
    Items sub;
    if (!o.omit_id) sub.push_back(item(tlv8::kTagIdentifier, strBytes(id)));
    if (!o.omit_pk) sub.push_back(item(tlv8::kTagPublicKey, pk));
    if (!o.omit_sig) sub.push_back(item(tlv8::kTagSignature, sig));
    Bytes sealed = seal(enc_key, "PS-Msg05", tlv8::encode(sub));
    if (o.tamper) sealed[3] ^= 0x01;
    Items req;
    req.push_back(stateItem(5));
    req.push_back(item(tlv8::kTagEncryptedData, sealed));
    return tlv8::encode(req);
}

// Checks M6; returns the accessory LTPK it carried.
bool checkM6(const Bytes& resp, const Bytes& k, const pairing::Identity& identity, Bytes& ltpk) {
    Items items;
    if (!decodeItems(resp, items)) return false;
    if (typesOf(items) != hexToBytes("0605")) return false;
    if (valueOf(items, 0x06) != Bytes(1, 6)) return false;
    const Bytes enc_key = hkdf(k, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info");
    Bytes plain;
    if (!open(enc_key, "PS-Msg06", valueOf(items, 0x05), plain)) return false;
    Items sub;
    if (!decodeItems(plain, sub)) return false;
    if (typesOf(sub) != hexToBytes("01030a")) return false;
    const Bytes id = valueOf(sub, 0x01);
    ltpk = valueOf(sub, 0x03);
    const Bytes sig = valueOf(sub, 0x0a);
    if (id != strBytes(identity.pairing_id)) return false;
    if (ltpk != arr(identity.keys.public_key, 32) || sig.size() != 64) return false;
    Bytes data = hkdf(k, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info");
    cat(data, id);
    cat(data, ltpk);
    return crypto::ed25519Verify(&ltpk[0], &data[0], data.size(), &sig[0]);
}

// Pair-verify controller.
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
        req.push_back(stateItem(1));
        req.push_back(item(tlv8::kTagPublicKey, pub()));
        return tlv8::encode(req);
    }

    // Validates M2 against the accessory's LTPK and derives the session secrets.
    bool onM2(const Bytes& resp, const std::string& acc_id, const Bytes& acc_ltpk) {
        Items items;
        if (!decodeItems(resp, items)) return false;
        if (typesOf(items) != hexToBytes("060305")) return false;
        if (valueOf(items, 0x06) != Bytes(1, 2)) return false;
        acc_pub = valueOf(items, 0x03);
        if (acc_pub.size() != 32) return false;
        shared.assign(32, 0);
        if (!crypto::x25519SharedSecret(eph.secret_key, &acc_pub[0], &shared[0])) return false;
        enc_key = hkdf(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info");
        Bytes plain;
        if (!open(enc_key, "PV-Msg02", valueOf(items, 0x05), plain)) return false;
        Items sub;
        if (!decodeItems(plain, sub)) return false;
        if (typesOf(sub) != hexToBytes("010a")) return false;
        if (valueOf(sub, 0x01) != strBytes(acc_id)) return false;
        const Bytes sig = valueOf(sub, 0x0a);
        if (sig.size() != 64) return false;
        Bytes data = acc_pub;
        cat(data, strBytes(acc_id));
        cat(data, pub());
        return crypto::ed25519Verify(&acc_ltpk[0], &data[0], data.size(), &sig[0]);
    }

    Bytes m3(const Controller& signer, const std::string& id, bool tamper = false,
             size_t sig_len = 64, bool omit_id = false) const {
        Bytes data = pub();
        cat(data, strBytes(id));
        cat(data, acc_pub);
        Bytes sig = signer.sign(data);
        sig.resize(sig_len, 0x11);
        Items sub;
        if (!omit_id) sub.push_back(item(tlv8::kTagIdentifier, strBytes(id)));
        sub.push_back(item(tlv8::kTagSignature, sig));
        Bytes sealed = seal(enc_key, "PV-Msg03", tlv8::encode(sub));
        if (tamper) sealed[sealed.size() - 1] ^= 0x80;
        Items req;
        req.push_back(stateItem(3));
        req.push_back(item(tlv8::kTagEncryptedData, sealed));
        return tlv8::encode(req);
    }
};

bool notVerified(const pairing::PairVerify& pv) {
    uint8_t r[32], w[32], s[32];
    return !pv.verified() && !pv.controlKeys(r, w) && !pv.sharedSecret(s) &&
           pv.controllerId().empty();
}

// Runs a successful pair-verify; returns false on any mismatch.
bool verifyOk(pairing::PairVerify& pv, VerifyClient& vc, const Controller& ctrl,
              const pairing::Identity& identity) {
    Bytes resp;
    pv.handle(vc.m1(), resp);
    if (!vc.onM2(resp, identity.pairing_id, arr(identity.keys.public_key, 32))) return false;
    pv.handle(vc.m3(ctrl, ctrl.id), resp);
    return resp == hexToBytes("060104") && pv.verified() && pv.controllerId() == ctrl.id;
}

// Pinned regression vectors (produced by this implementation, see header).
const char* const kPinSetupM2 =
    "06010203ffbe8c42b24236b26da1d9c7cf2941062b95708cb70dd1355081e78b5bec7acfb67fa80f2a0c51cb07b9d22b"
    "72b4e3000a005ff616208f68e967dfa01e25f7a8c22c9f36e1a51c3093e46ec7bd5eda0d6f34c29180f33a20529b83e7"
    "084340164051e14afcc512fdafe32972e27d08fac4be4873d15d9a68975dc6565b603f367b814a1ea6be3e90f0f83c4c"
    "d7b75b7159a201ee23171e3fbcfc3045c2faecae61020118c23becb932645e152d2295d8bdf3404aa87f682516b162ce"
    "32c0b4d695ed770fcf1b31b01fbd9f374580cc67fea3424630f43b39e7a2bc3b1ae88ebc6608bfa4a7330065e1cf02ed"
    "7fccf190890ba8d83943c54f26638977814319af0381d2f09ab48123b90ce999b4d238ce84189e2072937c2eab488b5e"
    "adf71883bf5aba7b69ddc30ea802caff18490b5d3950b920bbc59f2001459cb24d3fc9ff759ac7497963e57a935255d1"
    "94dec0802fd55bb61aad41092d329ab00b214290d3f629028c02adfa11abfc31e9a4661bf4c29fa96f288fa9d6d4f148"
    "6652ca303601250210288751acd15a220fafd7539c0a2d1fb0";
const char* const kPinVerifyM2 =
    "0601020320ce9bc4eebf14d2cfaa71a54bc5dfa5fc4efb8426cc4a43ef0d8d723585f1c7770578504dfaef8f8e9103d8"
    "ca2e9b110b8097f704655bd0bca1d401d3d2526ec079416e28e6f09f0eed2b18c05b284685cb99870ccc5e8de7beced7"
    "eee2f41d380d65a329f43dbcc536bd09351adb601094f5de10333b957cf814c239a81ca7e66533565496c86379390411"
    "43e1adf61a79f2bccc855b46d12888";

}  // namespace

// ---------------------------------------------------------------------------------------------
// Identity / store
// ---------------------------------------------------------------------------------------------

TEST_CASE(identityAndPairingIdFormat) {
    uint8_t ff[16], zz[16];
    memset(ff, 0xff, sizeof(ff));
    memset(zz, 0x00, sizeof(zz));
    CHECK_EQ(std::string("ffffffff-ffff-4fff-bfff-ffffffffffff"), pairing::formatPairingId(ff));
    CHECK_EQ(std::string("00000000-0000-4000-8000-000000000000"), pairing::formatPairingId(zz));

    pairing::Identity id;
    const Bytes seed = prefix(shaStr("accessory-seed"), 32);
    CHECK(!id.initFromSeed(&seed[0], ""));
    CHECK(!id.valid());
    CHECK(!id.initFromSeed(&seed[0], std::string(129, 'x')));
    REQUIRE(id.initFromSeed(&seed[0], kAccessoryId));
    CHECK(id.valid());
    crypto::Ed25519KeyPair ref;
    crypto::ed25519FromSeed(&seed[0], ref);
    CHECK_BYTES_EQ(arr(ref.public_key, 32), arr(id.keys.public_key, 32));

    DetRng rng("identity-rng");
    pairing::Identity gen;
    REQUIRE(pairing::generateIdentity(rng, gen));
    CHECK_EQ(static_cast<size_t>(36), gen.pairing_id.size());
    CHECK_EQ('4', gen.pairing_id[14]);
    DetRng bad("identity-rng", 1);
    pairing::Identity gen2;
    CHECK(!pairing::generateIdentity(bad, gen2));
    CHECK(!gen2.valid());
}

TEST_CASE(inMemoryStore) {
    pairing::InMemoryPairingStore store;
    uint8_t k1[32], out[32];
    memset(k1, 0x42, sizeof(k1));
    CHECK(!store.get("x", out));
    CHECK(store.save("x", k1));
    REQUIRE(store.get("x", out));
    CHECK_BYTES_EQ(arr(k1, 32), arr(out, 32));
    k1[0] = 1;
    CHECK(store.save("x", k1));
    CHECK_EQ(static_cast<size_t>(1), store.size());
    REQUIRE(store.get("x", out));
    CHECK_EQ(1, static_cast<int>(out[0]));
    store.clear();
    CHECK(!store.get("x", out));
}

// ---------------------------------------------------------------------------------------------
// Pair-Setup
// ---------------------------------------------------------------------------------------------

TEST_CASE(fullPairSetup) {
    pairing::Identity identity;
    makeAccessory(identity);
    pairing::InMemoryPairingStore store;
    DetRng rng("ps-rng");
    pairing::PairSetup ps(identity, store, rng);
    const Controller ctrl("controller-seed", kControllerId);

    Bytes k;
    REQUIRE(setupToM4(ps, k));
    CHECK(!ps.complete());
    Bytes resp;
    ps.handle(m5Request(k, ctrl), resp);
    Bytes acc_ltpk;
    CHECK(checkM6(resp, k, identity, acc_ltpk));
    CHECK(ps.complete());
    uint8_t stored[32];
    REQUIRE(store.get(kControllerId, stored));
    CHECK_BYTES_EQ(ctrl.ltpk(), arr(stored, 32));
    CHECK_EQ(static_cast<size_t>(1), store.size());

    // Exchange is finished: a replayed M5 is rejected and clears complete().
    ps.handle(m5Request(k, ctrl), resp);
    CHECK_BYTES_EQ(errorTlv(6), resp);
    CHECK(!ps.complete());
}

TEST_CASE(pairSetupWrongCodeSingleAttempt) {
    pairing::Identity identity;
    makeAccessory(identity);
    pairing::InMemoryPairingStore store;
    DetRng rng("ps-rng");
    pairing::PairSetup ps(identity, store, rng);

    Bytes b_pub, salt;
    REQUIRE(setupM1(ps, b_pub, salt));
    SrpClient wrong("ctrl-srp-a");
    REQUIRE(wrong.compute(b_pub, salt, "0000"));
    Bytes resp;
    ps.handle(m3Request(wrong), resp);
    CHECK_BYTES_EQ(errorTlv(4), resp);

    // Correct proof for the same B/salt, but no new M1: rejected (only one attempt per M1).
    SrpClient right("ctrl-srp-a");
    REQUIRE(right.compute(b_pub, salt, "3939"));
    ps.handle(m3Request(right), resp);
    CHECK_BYTES_EQ(errorTlv(4), resp);
    CHECK(!ps.complete());
}

TEST_CASE(pairSetupOrdering) {
    pairing::Identity identity;
    makeAccessory(identity);
    pairing::InMemoryPairingStore store;
    DetRng rng("ps-rng");
    pairing::PairSetup ps(identity, store, rng);
    const Controller ctrl("controller-seed", kControllerId);

    // M3 before M1.
    SrpClient c("ctrl-srp-a");
    Bytes resp;
    Items req;
    req.push_back(stateItem(3));
    req.push_back(item(tlv8::kTagPublicKey, c.a_pub));
    req.push_back(item(tlv8::kTagProof, Bytes(64, 1)));
    CHECK_BYTES_EQ(errorTlv(4), send(ps, req));

    // M5 before M4 (only M1 done) -> error 6 and the pending M1 is discarded.
    Bytes b_pub, salt;
    REQUIRE(setupM1(ps, b_pub, salt));
    ps.handle(m5Request(Bytes(64, 7), ctrl), resp);
    CHECK_BYTES_EQ(errorTlv(6), resp);
    REQUIRE(c.compute(b_pub, salt, "3939"));
    ps.handle(m3Request(c), resp);
    CHECK_BYTES_EQ(errorTlv(4), resp);

    // M3 missing proof / missing A.
    REQUIRE(setupM1(ps, b_pub, salt));
    Items no_proof;
    no_proof.push_back(stateItem(3));
    no_proof.push_back(item(tlv8::kTagPublicKey, c.a_pub));
    CHECK_BYTES_EQ(errorTlv(4), send(ps, no_proof));
    REQUIRE(setupM1(ps, b_pub, salt));
    Items no_a;
    no_a.push_back(stateItem(3));
    no_a.push_back(item(tlv8::kTagProof, Bytes(64, 1)));
    CHECK_BYTES_EQ(errorTlv(4), send(ps, no_a));
    // M3 with empty A.
    REQUIRE(setupM1(ps, b_pub, salt));
    Items empty_a;
    empty_a.push_back(stateItem(3));
    empty_a.push_back(item(tlv8::kTagPublicKey, Bytes()));
    empty_a.push_back(item(tlv8::kTagProof, Bytes(64, 1)));
    CHECK_BYTES_EQ(errorTlv(4), send(ps, empty_a));
    CHECK_EQ(static_cast<size_t>(0), store.size());
}

TEST_CASE(pairSetupM5Failures) {
    pairing::Identity identity;
    makeAccessory(identity);
    pairing::InMemoryPairingStore store;
    DetRng rng("ps-rng");
    pairing::PairSetup ps(identity, store, rng);
    const Controller ctrl("controller-seed", kControllerId);

    struct Case {
        const char* name;
        M5Opts opts;
        uint8_t state;
    };
    std::vector<Case> cases;
    Case c;
    c.name = "tampered"; c.opts = M5Opts(); c.opts.tamper = true; c.state = 5; cases.push_back(c);
    c.name = "bad_sig"; c.opts = M5Opts(); c.opts.bad_sig = true; c.state = 6; cases.push_back(c);
    c.name = "no_id"; c.opts = M5Opts(); c.opts.omit_id = true; c.state = 6; cases.push_back(c);
    c.name = "no_pk"; c.opts = M5Opts(); c.opts.omit_pk = true; c.state = 6; cases.push_back(c);
    c.name = "no_sig"; c.opts = M5Opts(); c.opts.omit_sig = true; c.state = 6; cases.push_back(c);
    c.name = "pk31"; c.opts = M5Opts(); c.opts.pk_len = 31; c.state = 6; cases.push_back(c);
    c.name = "pk33"; c.opts = M5Opts(); c.opts.pk_len = 33; c.state = 6; cases.push_back(c);
    c.name = "sig63"; c.opts = M5Opts(); c.opts.sig_len = 63; c.state = 6; cases.push_back(c);
    c.name = "sig65"; c.opts = M5Opts(); c.opts.sig_len = 65; c.state = 6; cases.push_back(c);
    c.name = "empty_id"; c.opts = M5Opts(); c.opts.override_id = true; c.opts.id = "";
    c.state = 6; cases.push_back(c);
    c.name = "id129"; c.opts = M5Opts(); c.opts.override_id = true;
    c.opts.id = std::string(129, 'c'); c.state = 6; cases.push_back(c);

    for (size_t i = 0; i < cases.size(); ++i) {
        Bytes k;
        REQUIRE(setupToM4(ps, k));
        Bytes resp;
        ps.handle(m5Request(k, ctrl, cases[i].opts), resp);
        if (resp != errorTlv(cases[i].state)) {
            std::printf("  case %s -> %s\n", cases[i].name, bytesToHex(resp).c_str());
        }
        CHECK_BYTES_EQ(errorTlv(cases[i].state), resp);
        CHECK(!ps.complete());
        // Single attempt: a correct M5 afterwards is rejected (needs a new M1).
        ps.handle(m5Request(k, ctrl), resp);
        CHECK_BYTES_EQ(errorTlv(6), resp);
    }
    CHECK_EQ(static_cast<size_t>(0), store.size());

    // M5 without encrypted data.
    Bytes k;
    REQUIRE(setupToM4(ps, k));
    Items req;
    req.push_back(stateItem(5));
    CHECK_BYTES_EQ(errorTlv(6), send(ps, req));

    // 128-byte controller id is accepted (boundary).
    REQUIRE(setupToM4(ps, k));
    M5Opts o;
    o.override_id = true;
    o.id = std::string(128, 'c');
    Bytes resp;
    ps.handle(m5Request(k, ctrl, o), resp);
    Bytes ltpk;
    CHECK(checkM6(resp, k, identity, ltpk));
    uint8_t stored[32];
    CHECK(store.get(std::string(128, 'c'), stored));
}

TEST_CASE(pairSetupMalformedBodies) {
    pairing::Identity identity;
    makeAccessory(identity);
    pairing::InMemoryPairingStore store;
    DetRng rng("ps-rng");
    pairing::PairSetup ps(identity, store, rng);
    Bytes resp;

    ps.handle(NULL, 0, resp);
    CHECK_BYTES_EQ(errorTlv(0), resp);
    ps.handle(hexToBytes("0605"), resp);  // truncated value
    CHECK_BYTES_EQ(errorTlv(0), resp);
    ps.handle(hexToBytes("06"), resp);  // truncated header
    CHECK_BYTES_EQ(errorTlv(0), resp);
    ps.handle(hexToBytes("ff01000601"), resp);  // bad separator
    CHECK_BYTES_EQ(errorTlv(0), resp);
    ps.handle(hexToBytes("0600"), resp);  // empty state
    CHECK_BYTES_EQ(errorTlv(0), resp);
    ps.handle(hexToBytes("0100"), resp);  // no state
    CHECK_BYTES_EQ(errorTlv(0), resp);
    ps.handle(hexToBytes("060100"), resp);
    CHECK_BYTES_EQ(errorTlv(0), resp);
    ps.handle(hexToBytes("060102"), resp);  // state 2 is a response state
    CHECK_BYTES_EQ(errorTlv(2), resp);
    ps.handle(hexToBytes("060107"), resp);
    CHECK_BYTES_EQ(errorTlv(7), resp);
    ps.handle(hexToBytes("0601ff"), resp);
    CHECK_BYTES_EQ(errorTlv(0xff), resp);
    Bytes garbage;
    for (int i = 0; i < 300; ++i) garbage.push_back(static_cast<uint8_t>(i * 37 + 11));
    ps.handle(garbage, resp);
    CHECK(resp.size() == 6 && resp[0] == 0x06 && resp[3] == 0x07 && resp[5] == 0x02);
    // Multi-byte state: reference takes the first byte.
    ps.handle(hexToBytes("06020199"), resp);
    Items items;
    REQUIRE(decodeItems(resp, items));
    CHECK_BYTES_EQ(hexToBytes("060302"), typesOf(items));
    CHECK(!ps.complete());
}

TEST_CASE(pairSetupRestartAfterFailure) {
    pairing::Identity identity;
    makeAccessory(identity);
    pairing::InMemoryPairingStore store;
    DetRng rng("ps-rng");
    pairing::PairSetup ps(identity, store, rng);
    const Controller ctrl("controller-seed", kControllerId);

    Bytes b_pub, salt;
    REQUIRE(setupM1(ps, b_pub, salt));
    SrpClient wrong("ctrl-srp-a");
    REQUIRE(wrong.compute(b_pub, salt, "0000"));
    Bytes resp;
    ps.handle(m3Request(wrong), resp);
    CHECK_BYTES_EQ(errorTlv(4), resp);

    // Fresh M1 mid-exchange (after a good M4) also restarts: the old K is gone.
    Bytes k_old;
    REQUIRE(setupToM4(ps, k_old));
    Bytes b2, s2;
    REQUIRE(setupM1(ps, b2, s2));
    CHECK(b2 != b_pub);  // new salt / b
    ps.handle(m5Request(k_old, ctrl), resp);
    CHECK_BYTES_EQ(errorTlv(6), resp);

    Bytes k;
    REQUIRE(setupToM4(ps, k));
    ps.handle(m5Request(k, ctrl), resp);
    Bytes ltpk;
    CHECK(checkM6(resp, k, identity, ltpk));
    CHECK(ps.complete());
    ps.reset();
    CHECK(!ps.complete());
}

TEST_CASE(pairSetupRngFailure) {
    pairing::Identity identity;
    makeAccessory(identity);
    pairing::InMemoryPairingStore store;
    DetRng rng("ps-rng", 1);  // salt succeeds, b fails
    pairing::PairSetup ps(identity, store, rng);
    Bytes resp;
    ps.handle(hexToBytes("060101"), resp);
    CHECK_BYTES_EQ(errorTlv(1), resp);

    pairing::Identity invalid;
    DetRng rng2("ps-rng");
    pairing::PairSetup ps2(invalid, store, rng2);
    ps2.handle(hexToBytes("060101"), resp);
    CHECK_BYTES_EQ(errorTlv(1), resp);
}

// ---------------------------------------------------------------------------------------------
// Pair-Verify
// ---------------------------------------------------------------------------------------------

TEST_CASE(fullPairSetupThenPairVerify) {
    pairing::Identity identity;
    makeAccessory(identity);
    pairing::InMemoryPairingStore store;
    DetRng ps_rng("ps-rng");
    DetRng pv_rng("pv-rng");
    pairing::PairSetup ps(identity, store, ps_rng);
    pairing::PairVerify pv(identity, store, pv_rng);
    const Controller ctrl("controller-seed", kControllerId);

    Bytes k;
    REQUIRE(setupToM4(ps, k));
    Bytes resp;
    ps.handle(m5Request(k, ctrl), resp);
    Bytes acc_ltpk;
    REQUIRE(checkM6(resp, k, identity, acc_ltpk));

    VerifyClient vc("ctrl-eph");
    CHECK(notVerified(pv));
    pv.handle(vc.m1(), resp);
    REQUIRE(vc.onM2(resp, identity.pairing_id, acc_ltpk));
    CHECK(notVerified(pv));  // nothing exposed before M4
    pv.handle(vc.m3(ctrl, ctrl.id), resp);
    CHECK_BYTES_EQ(hexToBytes("060104"), resp);  // M4 is exactly {state 4}
    REQUIRE(pv.verified());
    CHECK_EQ(std::string(kControllerId), pv.controllerId());

    uint8_t shared[32], rk[32], wk[32];
    REQUIRE(pv.sharedSecret(shared));
    CHECK_BYTES_EQ(vc.shared, arr(shared, 32));
    REQUIRE(pv.controlKeys(rk, wk));
    const Bytes ctrl_write = hkdf(vc.shared, "Control-Salt", "Control-Write-Encryption-Key");
    const Bytes ctrl_read = hkdf(vc.shared, "Control-Salt", "Control-Read-Encryption-Key");
    CHECK(ctrl_write != ctrl_read);
    CHECK_BYTES_EQ(ctrl_write, arr(rk, 32));  // accessory read == "Control-Write-..."
    CHECK_BYTES_EQ(ctrl_read, arr(wk, 32));   // accessory write == "Control-Read-..."

    uint8_t rk2[32], wk2[32];
    REQUIRE(pairing::deriveControlKeys(shared, rk2, wk2));
    CHECK_BYTES_EQ(arr(rk, 32), arr(rk2, 32));
    CHECK_BYTES_EQ(arr(wk, 32), arr(wk2, 32));

    // End-to-end with ControlCipher: the iPhone uses the opposite keys.
    carplay::ControlCipher accessory(rk, wk);
    carplay::ControlCipher iphone(&ctrl_read[0], &ctrl_write[0]);
    const Bytes req = strBytes("GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n");
    Bytes wire, plain;
    REQUIRE(iphone.encrypt(req, wire));
    REQUIRE(accessory.feed(wire, plain));
    CHECK_BYTES_EQ(req, plain);
    const Bytes rsp = strBytes("RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n");
    wire.clear();
    plain.clear();
    REQUIRE(accessory.encrypt(rsp, wire));
    REQUIRE(iphone.feed(wire, plain));
    CHECK_BYTES_EQ(rsp, plain);

    // A second pair-verify on the same connection works too (fresh M1).
    VerifyClient vc2("ctrl-eph-2");
    CHECK(verifyOk(pv, vc2, ctrl, identity));
    REQUIRE(pv.sharedSecret(shared));
    CHECK_BYTES_EQ(vc2.shared, arr(shared, 32));
}

TEST_CASE(deriveEventKeysMatchesReferenceLabels) {
    const Bytes shared = prefix(shaStr("shared"), 32);
    uint8_t rk[32], wk[32];
    REQUIRE(pairing::deriveEventKeys(&shared[0], rk, wk));
    CHECK_BYTES_EQ(hkdf(shared, "Events-Salt", "Events-Read-Encryption-Key"), arr(rk, 32));
    CHECK_BYTES_EQ(hkdf(shared, "Events-Salt", "Events-Write-Encryption-Key"), arr(wk, 32));
    CHECK(!pairing::deriveEventKeys(NULL, rk, wk));
    CHECK(!pairing::deriveEventKeys(&shared[0], NULL, wk));
    CHECK(!pairing::deriveControlKeys(NULL, rk, wk));
    CHECK(!pairing::deriveControlKeys(&shared[0], rk, NULL));
    uint8_t crk[32], cwk[32];
    REQUIRE(pairing::deriveControlKeys(&shared[0], crk, cwk));
    CHECK(arr(crk, 32) != arr(rk, 32));
}

TEST_CASE(pairVerifyFailures) {
    pairing::Identity identity;
    makeAccessory(identity);
    pairing::InMemoryPairingStore store;
    DetRng rng("pv-rng");
    pairing::PairVerify pv(identity, store, rng);
    const Controller ctrl("controller-seed", kControllerId);
    const Controller impostor("impostor-seed", kControllerId);
    REQUIRE(store.save(ctrl.id, ctrl.keys.public_key));
    const Bytes acc_ltpk = arr(identity.keys.public_key, 32);
    Bytes resp;

    // Unknown controller id.
    {
        VerifyClient vc("e1");
        pv.handle(vc.m1(), resp);
        REQUIRE(vc.onM2(resp, identity.pairing_id, acc_ltpk));
        pv.handle(vc.m3(ctrl, "unknown-controller"), resp);
        CHECK_BYTES_EQ(errorTlv(4), resp);
        CHECK(notVerified(pv));
    }
    // Signature by a different key.
    {
        VerifyClient vc("e2");
        pv.handle(vc.m1(), resp);
        REQUIRE(vc.onM2(resp, identity.pairing_id, acc_ltpk));
        pv.handle(vc.m3(impostor, ctrl.id), resp);
        CHECK_BYTES_EQ(errorTlv(4), resp);
        CHECK(notVerified(pv));
        // Single attempt: a correct M3 now is rejected too.
        pv.handle(vc.m3(ctrl, ctrl.id), resp);
        CHECK_BYTES_EQ(errorTlv(4), resp);
        CHECK(notVerified(pv));
    }
    // Tampered M3 ciphertext (reference: chachaOpen throws -> echoes state 3).
    {
        VerifyClient vc("e3");
        pv.handle(vc.m1(), resp);
        REQUIRE(vc.onM2(resp, identity.pairing_id, acc_ltpk));
        pv.handle(vc.m3(ctrl, ctrl.id, true), resp);
        CHECK_BYTES_EQ(errorTlv(3), resp);
        CHECK(notVerified(pv));
    }
    // Bad signature length / missing identifier / missing encrypted data.
    {
        VerifyClient vc("e4");
        pv.handle(vc.m1(), resp);
        REQUIRE(vc.onM2(resp, identity.pairing_id, acc_ltpk));
        pv.handle(vc.m3(ctrl, ctrl.id, false, 63), resp);
        CHECK_BYTES_EQ(errorTlv(4), resp);
        pv.handle(vc.m1(), resp);
        REQUIRE(vc.onM2(resp, identity.pairing_id, acc_ltpk));
        pv.handle(vc.m3(ctrl, ctrl.id, false, 64, true), resp);
        CHECK_BYTES_EQ(errorTlv(4), resp);
        pv.handle(vc.m1(), resp);
        REQUIRE(vc.onM2(resp, identity.pairing_id, acc_ltpk));
        pv.handle(hexToBytes("060103"), resp);
        CHECK_BYTES_EQ(errorTlv(4), resp);
        CHECK(notVerified(pv));
    }
    // M3 before M1.
    {
        pairing::PairVerify fresh(identity, store, rng);
        VerifyClient vc("e5");
        vc.enc_key = Bytes(32, 9);
        vc.acc_pub = Bytes(32, 9);
        fresh.handle(vc.m3(ctrl, ctrl.id), resp);
        CHECK_BYTES_EQ(errorTlv(4), resp);
        CHECK(notVerified(fresh));
    }
    // Low-order / all-zero client ephemeral keys -> all-zero shared secret rejected.
    {
        const char* low_order[] = {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        };
        for (size_t i = 0; i < sizeof(low_order) / sizeof(low_order[0]); ++i) {
            Items req;
            req.push_back(stateItem(1));
            req.push_back(item(tlv8::kTagPublicKey, hexToBytes(low_order[i])));
            CHECK_BYTES_EQ(errorTlv(1), send(pv, req));
            CHECK(notVerified(pv));
        }
    }
    // Wrong-length / missing public key.
    {
        VerifyClient vc("e6");
        Bytes p31 = vc.pub();
        p31.pop_back();
        Bytes p33 = vc.pub();
        p33.push_back(0);
        Items r31, r33, r_none, r_empty;
        r31.push_back(stateItem(1));
        r31.push_back(item(tlv8::kTagPublicKey, p31));
        r33.push_back(stateItem(1));
        r33.push_back(item(tlv8::kTagPublicKey, p33));
        r_none.push_back(stateItem(1));
        r_empty.push_back(stateItem(1));
        r_empty.push_back(item(tlv8::kTagPublicKey, Bytes()));
        CHECK_BYTES_EQ(errorTlv(1), send(pv, r31));
        CHECK_BYTES_EQ(errorTlv(1), send(pv, r33));
        CHECK_BYTES_EQ(errorTlv(2), send(pv, r_none));
        CHECK_BYTES_EQ(errorTlv(1), send(pv, r_empty));
    }
    // Empty / garbage / unknown-state bodies.
    {
        pv.handle(NULL, 0, resp);
        CHECK_BYTES_EQ(errorTlv(0), resp);
        pv.handle(hexToBytes("0603"), resp);
        CHECK_BYTES_EQ(errorTlv(0), resp);
        pv.handle(hexToBytes("060105"), resp);
        CHECK_BYTES_EQ(errorTlv(5), resp);
        pv.handle(hexToBytes("060102"), resp);
        CHECK_BYTES_EQ(errorTlv(2), resp);
        pv.handle(hexToBytes("060104"), resp);
        CHECK_BYTES_EQ(errorTlv(4), resp);
        CHECK(notVerified(pv));
    }
    // RNG failure on M1.
    {
        DetRng dead("pv-rng", 0);
        pairing::PairVerify pv2(identity, store, dead);
        VerifyClient vc("e7");
        pv2.handle(vc.m1(), resp);
        CHECK_BYTES_EQ(errorTlv(1), resp);
    }
    // A fresh M1 afterwards works.
    VerifyClient vc("e8");
    CHECK(verifyOk(pv, vc, ctrl, identity));
}

TEST_CASE(pairVerifySecretsHiddenUntilM4AndAfterFailure) {
    pairing::Identity identity;
    makeAccessory(identity);
    pairing::InMemoryPairingStore store;
    DetRng rng("pv-rng");
    pairing::PairVerify pv(identity, store, rng);
    const Controller ctrl("controller-seed", kControllerId);
    REQUIRE(store.save(ctrl.id, ctrl.keys.public_key));

    VerifyClient vc("h1");
    Bytes resp;
    pv.handle(vc.m1(), resp);
    REQUIRE(vc.onM2(resp, identity.pairing_id, arr(identity.keys.public_key, 32)));
    CHECK(notVerified(pv));
    pv.handle(vc.m3(ctrl, ctrl.id), resp);
    REQUIRE(pv.verified());

    // A replayed M3 after success fails and drops the verified state.
    pv.handle(vc.m3(ctrl, ctrl.id), resp);
    CHECK_BYTES_EQ(errorTlv(4), resp);
    CHECK(notVerified(pv));

    VerifyClient vc2("h2");
    REQUIRE(verifyOk(pv, vc2, ctrl, identity));
    pv.reset();
    CHECK(notVerified(pv));

    // A fresh M1 after success also clears the previous verification until its M4.
    VerifyClient vc3("h3");
    REQUIRE(verifyOk(pv, vc3, ctrl, identity));
    pv.handle(vc3.m1(), resp);
    CHECK(notVerified(pv));
}

// ---------------------------------------------------------------------------------------------
// Pinned regression vectors
// ---------------------------------------------------------------------------------------------

TEST_CASE(pinnedRegressionVectors) {
    pairing::Identity identity;
    makeAccessory(identity);
    pairing::InMemoryPairingStore store;

    DetRng ps_rng("ps-rng");
    pairing::PairSetup ps(identity, store, ps_rng);
    Bytes setup_m2;
    ps.handle(hexToBytes("000100060101"), setup_m2);
    CHECK_EQ(static_cast<size_t>(3 + 2 + 255 + 2 + 129 + 2 + 16), setup_m2.size());
    CHECK_BYTES_EQ(hexToBytes(kPinSetupM2), setup_m2);

    DetRng pv_rng("pv-rng");
    pairing::PairVerify pv(identity, store, pv_rng);
    VerifyClient vc("pin-eph");
    Bytes verify_m2;
    pv.handle(vc.m1(), verify_m2);
    CHECK_BYTES_EQ(hexToBytes(kPinVerifyM2), verify_m2);
    CHECK(vc.onM2(verify_m2, identity.pairing_id, arr(identity.keys.public_key, 32)));
}

int main() {
    return test_support::runAll("test_pairing");
}
