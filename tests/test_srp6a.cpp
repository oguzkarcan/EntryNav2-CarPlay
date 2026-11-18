// Derived in part from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/airplay/Srp6a.kt: RFC 5054 N_HEX literal & vectors),
// GPL-3.0, Copyright (c) DiPlay contributors.
//
// SRP-6a server (AirPlay pair-setup variant) tests.
//
// A minimal SRP-6a CLIENT is implemented below on top of the bigint module so a full handshake
// can be driven on the host. Fixed inputs: salt = SHA512("srp-salt")[0..16],
// b = SHA512("srp-b")[0..32], a = SHA512("<label>")[0..32], I = "Pair-Setup", P = "3939".
//
// The pinned vectors (kPin*) were produced INDEPENDENTLY of this C++ code by a PowerShell script
// that follows DiPlay Srp6a.kt literally on .NET System.Numerics.BigInteger + SHA512 (and
// additionally checked the server S against the textbook client S = (B - k*g^x)^(a + u*x)).
// Labels "srp-a-330" / "srp-a-634" were found by search so that A resp. S has a leading zero
// byte (minimal encoding 383 bytes), exercising pad() vs toBytes() handling.

#include "carplay/airplay_crypto.hpp"
#include "carplay/bigint.hpp"
#include "carplay/srp6a.hpp"
#include "test_support.hpp"

#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

using carplay::bigint::Modulus;
using carplay::bigint::Number;
using test_support::bytesToHex;
using test_support::hexToBytes;

namespace bi = carplay::bigint;
namespace srp = carplay::srp;
namespace crypto = carplay::crypto;

namespace {

// Pinned vectors from the independent PowerShell/.NET computation (see header comment).
const char* const kPinK =
    "a9c2e2559bf0ebb53f0cbbf62282906bede7f2182f00678211fbd5bde5b285033a4993503b87397f9be5ec02080fedbc"
    "0835587ad039060879b8621e8c3659e0";
const char* const kPinSalt =
    "718665c8ec97a5f63f482dc8e220ecbb";
const char* const kPinB =
    "8d3b4dd2be23f39aae8b1da880bdf6416d22db047bf78c2e7c62db64f8ffdd7b216b2d7c3661b5d85223fd5c86e5782e"
    "f43b02b281491d8ab86f1015ebc320e3f84e22a26fb280b92cf3b5efc0f98dae0061409b79d78ec111ded0bb6309d902"
    "168c6e1d2c93b976ef8738ba4648c34a87ea0783842a62b0e99eaafc1958d5fd6f0a6066280ed86116eded6bacfaa8f6"
    "1ac482d6defffb82c2728448d5e5b05c4a8bc6375556edcf644f42f49f6279713aeca82de62f9ae5bd34c2fea52215d5"
    "e114d79b5e5af4d649bd3847eba3763cb1f0fe2b9434c211795dcbca42c865d323cad37b61e3cb5a51ccc274e14059d7"
    "46f6c90a4431a987fb75bf21276a76e4426fbe319af1366910fc434ec6ef4040e97552a6634083a3d29a095722bee7c4"
    "01f61f97889e7c727dfb5a28e03ff849d571ca4bc8a233217af11a1692939a3c1abff812c382e7bc52691192137c3bc4"
    "be92441f2d1bf02762a33d92aa1d1da114132dc83149722152a845624868f5d16418017746bcecdf4aeab0ce63d9476a";
const char* const kPinA =
    "6056b7186c697ce8e39103bbb04bb6cd7b828f4867d6980ba9e3c267299450a4c74c2227f7c44630b6b444e03b441eeb"
    "4bdf4c538dcfc16f62297951323f2e81e3525789f773af6fb036c6f91f7f6658d2021d207849acd7afafc01ee647f0d8"
    "a9246f91850cf6190ecf486a12506e878e820a9d791c14be7f919280b16afb7376a4edb5685199b5f8e95db879d34440"
    "80e9b84b8a41dadce698e184e66da6d27c594bc5e36caf0c6576cef64a797ce8254cb6cdded5adbf7184138e71ec9207"
    "4ab1e113fc583433b5849ed4d5fe828065d809252f30cb9547c1706be6dfd8d9aa0e34443a6020d93ae95138dd6d0415"
    "d057b64e8921f02f92f839b527575acef9ea65f4fac36ed5b61d5d29aa16668260d1d6b0afad8a15c6dc48e5de1619dd"
    "242db492607a0767d796edb56a9cfb87a66b1f470071d3351ce5f6f912a55ab32f622c09d282afb049cc731814016b0a"
    "495ee53d9682e177380713e34ed214f9101a0fc058b88796df75d3229df980322fef4438028c84455f1ca6e46ac68eb4";
const char* const kPinK_srp_a =
    "fcd34afb50342d285cb23019a5a23c6fb209daa683258dcd8ebbb35b69fcb646f3191ff2c28f2ab6244361ce2f289738"
    "7367a2dcf859f981eafa6e8263fbcf11";
const char* const kPinM1_srp_a =
    "9b6e9f1e9e9e6fa48f38ce4cad908409880dfee539c54c98283f5a1de54af6a2e03f3e6bece9f929a5e5ce541fa8d3f2"
    "eb973a8ac57e4dfc3a23adb203798aa1";
const char* const kPinM2_srp_a =
    "ae837f3087f124133fa65230f95723c885862a2c869a5163e0bd8c76f32b712f3f8f9d814478ebd3813d8a69292e2d74"
    "2f9af88fa995389443af1d467db532e7";
const char* const kPinA_330 =
    "001b2e4b5880258bb20d6f5c2d792fd6d10c47c9c345198ce08b12c02c28cb890f3258c78618f297d766e0b4f2feb18e"
    "2b716acd83dd792b800ae616e2eb60b1f1e9c96ac7cb935e00b3c3481a178cc1bc97a8b3bbd9185d83bea2b20fac9e84"
    "91e9b774a81d73493fb39ab20e0d7a013c20b8ccdd98887787028a52652dc7476b715793d597f9ae31e41d189b567fca"
    "933309e1e5aacac9c4feffce445fb7202658a8677bde4767d8c34a97518ce05f1ea1f0b40794cc58b307c033a7b62b76"
    "acb69d79f11311709cb1abd4f7064e05a9164b10a9ac8748b2c21003daac24ff983a44586fc6c79d11c3b44510e7cacb"
    "e33cff377231aeec2f060abc931a9a4c4623cacdb0ff6c964eaecab55bc2c19239d941d76fe816ed6904554f76387a45"
    "66f5bc6f6279550d56575e41f1a9aa4b1f55fbdda9c05f61c3f2f2bb6dca3c4a88b4665bad57d70d5ecf7d4349547e74"
    "d08fcf244471685d7a478bae24ed7a8e40add28f3f5c8e0eaf78c531e4268c51a8c9e8875bbf54a50c2b0b06bdea96a7";
const char* const kPinK_330 =
    "a322d527c3fc61d6870d7cb33f40b349e170fced0c843ebc59596ea1f1625ccd4230c6a7260b9b0fdfcce1135cc4295d"
    "62f195c0a9d6ed29203bb09b8d526b43";
const char* const kPinM2_330 =
    "1735f1881eba9a86ac4963107ed8eb76f02e3e907903684817e5520e36ac15f7601c120432beaee3405cccaed373154b"
    "9e52f04cbc465deec98e521bd32b1b53";
const char* const kPinK_634 =
    "d9763bd26d620a6951d9b9a4b9226c865205783d21d7a6b7bb0c568fee3662ac90d73b0a84882cd5448826bac3ee0b59"
    "3d2b69189b4bc06d8cd97ca353930c31";
const char* const kPinM2_634 =
    "63235313fd1131dc42e974eb2440af5a97d19ab0e2599e1d4fc1717e36f82b921f64324838a55d103e221757ec26dfe0"
    "ff2c0c55fd063e01770ba0c5cbb9f0d8";

// Srp6a.kt N_HEX literal, copied verbatim (including its uneven line split).
const char* const kKotlinNHex =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183"
    "995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A"
    "85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7AB"
    "F5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D8"
    "7602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208"
    "E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

const char* const kUser = "Pair-Setup";
const char* const kPass = "3939";

std::vector<uint8_t> sha(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out(64);
    crypto::sha512(data.empty() ? NULL : &data[0], data.size(), &out[0]);
    return out;
}

std::vector<uint8_t> shaStr(const std::string& s) {
    return sha(std::vector<uint8_t>(s.begin(), s.end()));
}

std::vector<uint8_t> prefix(const std::vector<uint8_t>& v, size_t n) {
    return std::vector<uint8_t>(v.begin(), v.begin() + static_cast<long>(n));
}

void cat(std::vector<uint8_t>& out, const std::vector<uint8_t>& v) {
    for (size_t i = 0; i < v.size(); ++i) {
        out.push_back(v[i]);
    }
}

// Test-local pad / minimal encodings (Kotlin semantics), deliberately not using srp::encode*.
std::vector<uint8_t> minimalOf(const std::vector<uint8_t>& v) {
    size_t i = 0;
    while (i < v.size() && v[i] == 0) ++i;
    if (i == v.size()) return std::vector<uint8_t>(1, 0);
    return std::vector<uint8_t>(v.begin() + static_cast<long>(i), v.end());
}

std::vector<uint8_t> padOf(const std::vector<uint8_t>& v) {
    std::vector<uint8_t> m = minimalOf(v);
    if (m.size() >= 384) return m;
    std::vector<uint8_t> out(384 - m.size(), 0);
    cat(out, m);
    return out;
}

std::vector<uint8_t> numBytes(const Number& n) {
    std::vector<uint8_t> out;
    bi::toBytesBE(n, out);
    return out;
}

Number numOf(const std::vector<uint8_t>& b) {
    Number n;
    bi::fromBytesBE(b.empty() ? NULL : &b[0], b.size(), n);
    return n;
}

std::vector<uint8_t> primeBytes() {
    return std::vector<uint8_t>(srp::rfc5054Prime3072(), srp::rfc5054Prime3072() + 384);
}

std::vector<uint8_t> addBE(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    const size_t n = (a.size() > b.size() ? a.size() : b.size()) + 1;
    std::vector<uint8_t> out(n, 0);
    unsigned carry = 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned s = carry;
        if (i < a.size()) s += a[a.size() - 1 - i];
        if (i < b.size()) s += b[b.size() - 1 - i];
        out[n - 1 - i] = static_cast<uint8_t>(s);
        carry = s >> 8;
    }
    return out;
}

std::vector<uint8_t> fixedSalt() { return prefix(shaStr("srp-salt"), 16); }
std::vector<uint8_t> fixedB() { return prefix(shaStr("srp-b"), 32); }

// ---------------------------------------------------------------------------------------------
// SRP-6a client (test-only).
// ---------------------------------------------------------------------------------------------
struct Client {
    std::vector<uint8_t> a;        // private exponent (32 bytes)
    std::vector<uint8_t> a_pub;    // pad(A), 384 bytes
    std::vector<uint8_t> s_min;    // minimal S
    std::vector<uint8_t> k;        // session key K
    std::vector<uint8_t> m1;
    std::vector<uint8_t> m2;       // expected server proof
    bool raw_a_hash;               // test knob: hash wire A as-is instead of pad(A) (wrong)

    explicit Client(const std::string& label) : a(prefix(shaStr(label), 32)), raw_a_hash(false) {
        Number pub;
        srp::group3072().modExp(bi::fromUint32(5), &a[0], a.size(), pub);
        bi::toBytesBEPadded(pub, 384, a_pub);
    }

    // `wire_a` is the A byte string the client sends (and therefore hashes via pad()).
    bool compute(const std::vector<uint8_t>& wire_a, const std::vector<uint8_t>& b_pub,
                 const std::vector<uint8_t>& salt, const std::string& user,
                 const std::string& pass) {
        const Modulus& m = srp::group3072();
        const std::vector<uint8_t> n = primeBytes();
        // k = H(N | pad(g))
        std::vector<uint8_t> buf = minimalOf(n);
        cat(buf, padOf(std::vector<uint8_t>(1, 5)));
        const Number kk = numOf(sha(buf));
        // x = H(salt | H(I ":" P))
        buf = salt;
        cat(buf, shaStr(user + ":" + pass));
        const std::vector<uint8_t> x = sha(buf);
        const std::vector<uint8_t> enc_a = raw_a_hash ? wire_a : padOf(wire_a);
        // u = H(pad(A) | pad(B))
        buf = enc_a;
        cat(buf, padOf(b_pub));
        const std::vector<uint8_t> u = sha(buf);

        Number v, kv, t, ta, tu, tux, s;
        bool ok = m.modExp(bi::fromUint32(5), &x[0], x.size(), v);
        ok = ok && m.mulMod(kk, v, kv);
        ok = ok && m.subMod(numOf(b_pub), kv, t);              // B - k*v
        ok = ok && m.modExp(t, &a[0], a.size(), ta);            // t^a
        ok = ok && m.modExp(t, &u[0], u.size(), tu);            // t^u
        ok = ok && m.modExp(tu, &x[0], x.size(), tux);          // t^(u*x)
        ok = ok && m.mulMod(ta, tux, s);                        // t^(a + u*x)
        if (!ok) return false;
        s_min = numBytes(s);
        k = sha(s_min);

        const std::vector<uint8_t> hn = sha(minimalOf(n));
        const std::vector<uint8_t> hg = sha(std::vector<uint8_t>(1, 5));
        buf.clear();
        for (size_t i = 0; i < 64; ++i) buf.push_back(static_cast<uint8_t>(hn[i] ^ hg[i]));
        cat(buf, shaStr(user));
        cat(buf, salt);
        cat(buf, enc_a);
        cat(buf, padOf(b_pub));
        cat(buf, k);
        m1 = sha(buf);

        buf = enc_a;
        cat(buf, m1);
        cat(buf, k);
        m2 = sha(buf);
        return true;
    }
};

bool startServer(srp::Srp6aServer& server, const std::string& pass = kPass) {
    const std::vector<uint8_t> salt = fixedSalt();
    const std::vector<uint8_t> b = fixedB();
    return server.start(kUser, pass, &salt[0], &b[0]);
}

bool serverVerify(const srp::Srp6aServer& server, const std::vector<uint8_t>& a,
                  const std::vector<uint8_t>& m1, std::vector<uint8_t>& k,
                  std::vector<uint8_t>& m2) {
    return server.verify(a.empty() ? NULL : &a[0], a.size(), m1.empty() ? NULL : &m1[0],
                         m1.size(), k, m2);
}

}  // namespace

TEST_CASE(primeMatchesRfc5054AndKotlinLiteral) {
    const std::vector<uint8_t> n = primeBytes();
    CHECK_EQ(static_cast<size_t>(384), n.size());
    const std::string hex = bytesToHex(n);
    CHECK_EQ(static_cast<size_t>(768), hex.size());
    CHECK_EQ(std::string("ffffffffffffffffc90fdaa2"), hex.substr(0, 24));
    CHECK_EQ(std::string("a93ad2caffffffffffffffff"), hex.substr(hex.size() - 24));
    const std::vector<uint8_t> kotlin = hexToBytes(kKotlinNHex);
    CHECK_EQ(static_cast<size_t>(384), kotlin.size());
    CHECK_BYTES_EQ(kotlin, n);
    REQUIRE(srp::group3072().valid());
    CHECK_EQ(static_cast<size_t>(3072), bi::bitLength(srp::group3072().value()));
    CHECK_BYTES_EQ(n, numBytes(srp::group3072().value()));
}

TEST_CASE(multiplierKMatchesPin) {
    CHECK_BYTES_EQ(hexToBytes(kPinK), srp::multiplierK());
}

TEST_CASE(encodingHelpersFollowKotlinSemantics) {
    CHECK_BYTES_EQ(hexToBytes("00"), srp::encodeMinimal(NULL, 0));
    const std::vector<uint8_t> z(5, 0);
    CHECK_BYTES_EQ(hexToBytes("00"), srp::encodeMinimal(&z[0], z.size()));
    CHECK_BYTES_EQ(std::vector<uint8_t>(384, 0), srp::encodePadded(&z[0], z.size()));
    const std::vector<uint8_t> v = hexToBytes("0000ab01");
    CHECK_BYTES_EQ(hexToBytes("ab01"), srp::encodeMinimal(&v[0], v.size()));
    const std::vector<uint8_t> p = srp::encodePadded(&v[0], v.size());
    REQUIRE(p.size() == 384);
    CHECK_EQ(0, static_cast<int>(p[381]));
    CHECK_EQ(0xab, static_cast<int>(p[382]));
    CHECK_EQ(0x01, static_cast<int>(p[383]));
    // >= 384 significant bytes: returned unpadded (minimal).
    std::vector<uint8_t> wide(1, 0);
    cat(wide, std::vector<uint8_t>(400, 0x11));
    CHECK_BYTES_EQ(std::vector<uint8_t>(400, 0x11), srp::encodePadded(&wide[0], wide.size()));
    std::vector<uint8_t> exact(384, 0x22);
    CHECK_BYTES_EQ(exact, srp::encodePadded(&exact[0], exact.size()));
    // 383 significant bytes behind a zero: padded back to 384 with the zero.
    exact[0] = 0;
    CHECK_BYTES_EQ(exact, srp::encodePadded(&exact[0] + 1, 383));
}

TEST_CASE(fullHandshakeMatchesIndependentVector) {
    srp::Srp6aServer server;
    const std::clock_t t0 = std::clock();
    REQUIRE(startServer(server));
    CHECK(server.started());
    CHECK_EQ(static_cast<size_t>(384), server.publicKey().size());
    CHECK_BYTES_EQ(fixedSalt(), server.salt());
    CHECK_BYTES_EQ(hexToBytes(kPinSalt), server.salt());
    CHECK_BYTES_EQ(hexToBytes(kPinB), server.publicKey());

    Client client("srp-a");
    CHECK_BYTES_EQ(hexToBytes(kPinA), client.a_pub);
    REQUIRE(client.compute(client.a_pub, server.publicKey(), server.salt(), kUser, kPass));

    const std::clock_t t1 = std::clock();
    std::vector<uint8_t> k, m2;
    REQUIRE(serverVerify(server, client.a_pub, client.m1, k, m2));
    const std::clock_t t2 = std::clock();

    CHECK_BYTES_EQ(client.k, k);
    CHECK_BYTES_EQ(client.m2, m2);
    CHECK_BYTES_EQ(hexToBytes(kPinK_srp_a), k);
    CHECK_BYTES_EQ(hexToBytes(kPinM1_srp_a), client.m1);
    CHECK_BYTES_EQ(hexToBytes(kPinM2_srp_a), m2);
    CHECK_EQ(static_cast<size_t>(64), k.size());
    CHECK_EQ(static_cast<size_t>(64), m2.size());

    const double start_ms = 1000.0 * static_cast<double>(t1 - t0) / CLOCKS_PER_SEC;
    const double verify_ms = 1000.0 * static_cast<double>(t2 - t1) / CLOCKS_PER_SEC;
    std::printf("  [info] server-side SRP: start (incl. client A/compute) %.1f ms, verify %.1f ms\n",
                start_ms, verify_ms);

    // Pure server-side timing over several iterations (start + verify only).
    const int iters = 5;
    const std::clock_t s0 = std::clock();
    for (int i = 0; i < iters; ++i) {
        srp::Srp6aServer s;
        REQUIRE(startServer(s));
        std::vector<uint8_t> kk, mm;
        REQUIRE(serverVerify(s, client.a_pub, client.m1, kk, mm));
    }
    const std::clock_t s1 = std::clock();
    std::printf("  [info] full server handshake (start + verify), avg of %d: %.1f ms\n", iters,
                1000.0 * static_cast<double>(s1 - s0) / CLOCKS_PER_SEC / iters);
}

TEST_CASE(wrongPasswordRejected) {
    srp::Srp6aServer server;
    REQUIRE(startServer(server));
    Client client("srp-a");
    REQUIRE(client.compute(client.a_pub, server.publicKey(), server.salt(), kUser, "3940"));
    std::vector<uint8_t> k(3, 1), m2(3, 1);
    CHECK(!serverVerify(server, client.a_pub, client.m1, k, m2));
    CHECK(k.empty());
    CHECK(m2.empty());

    // And a server started with the wrong password rejects the right client.
    srp::Srp6aServer other;
    REQUIRE(startServer(other, "0000"));
    Client good("srp-a");
    REQUIRE(good.compute(good.a_pub, other.publicKey(), other.salt(), kUser, kPass));
    CHECK(!serverVerify(other, good.a_pub, good.m1, k, m2));
}

TEST_CASE(tamperedProofAndBadLengthsRejected) {
    srp::Srp6aServer server;
    REQUIRE(startServer(server));
    Client client("srp-a");
    REQUIRE(client.compute(client.a_pub, server.publicKey(), server.salt(), kUser, kPass));
    std::vector<uint8_t> k, m2;
    const size_t positions[] = {0, 31, 63};
    for (size_t i = 0; i < 3; ++i) {
        std::vector<uint8_t> bad = client.m1;
        bad[positions[i]] ^= 0x01;
        CHECK(!serverVerify(server, client.a_pub, bad, k, m2));
    }
    CHECK(!serverVerify(server, client.a_pub, prefix(client.m1, 63), k, m2));
    std::vector<uint8_t> longer = client.m1;
    longer.push_back(0);
    CHECK(!serverVerify(server, client.a_pub, longer, k, m2));
    CHECK(!serverVerify(server, client.a_pub, std::vector<uint8_t>(), k, m2));
    CHECK(!serverVerify(server, std::vector<uint8_t>(), client.m1, k, m2));
    CHECK(!server.verify(NULL, 384, &client.m1[0], 64, k, m2));
    CHECK(!server.verify(&client.a_pub[0], 384, NULL, 64, k, m2));
    // A longer than 512 bytes rejected even if numerically identical (leading zeros).
    std::vector<uint8_t> a513(129, 0);
    cat(a513, client.a_pub);
    CHECK(!serverVerify(server, a513, client.m1, k, m2));
    // Tampered A changes u and S.
    std::vector<uint8_t> bad_a = client.a_pub;
    bad_a[100] ^= 0x80;
    CHECK(!serverVerify(server, bad_a, client.m1, k, m2));
    // The genuine attempt still works afterwards (verify is non-consuming).
    CHECK(serverVerify(server, client.a_pub, client.m1, k, m2));
    CHECK_BYTES_EQ(client.k, k);
}

TEST_CASE(degeneratePublicKeyARejected) {
    srp::Srp6aServer server;
    REQUIRE(startServer(server));
    const std::vector<uint8_t> n = primeBytes();
    const std::vector<uint8_t> n2 = addBE(n, n);
    const std::vector<uint8_t> n3 = addBE(n2, n);
    std::vector<std::vector<uint8_t> > cases;
    cases.push_back(std::vector<uint8_t>(384, 0));
    cases.push_back(std::vector<uint8_t>(1, 0));
    cases.push_back(n);
    cases.push_back(n2);
    cases.push_back(n3);
    for (size_t i = 0; i < cases.size(); ++i) {
        // Even a client "proof" built honestly for this A must be rejected.
        Client c("srp-a");
        REQUIRE(c.compute(cases[i], server.publicKey(), server.salt(), kUser, kPass));
        std::vector<uint8_t> k, m2;
        CHECK(!serverVerify(server, cases[i], c.m1, k, m2));
        CHECK(k.empty());
    }
}

TEST_CASE(lifecycleAndReuse) {
    srp::Srp6aServer server;
    Client client("srp-a");
    std::vector<uint8_t> k, m2;
    CHECK(!server.started());
    CHECK(server.publicKey().empty());
    CHECK(!serverVerify(server, client.a_pub, std::vector<uint8_t>(64, 0), k, m2));

    // All-zero private exponent / null inputs rejected.
    const std::vector<uint8_t> salt = fixedSalt();
    const std::vector<uint8_t> zero_b(32, 0);
    CHECK(!server.start(kUser, kPass, &salt[0], &zero_b[0]));
    CHECK(!server.start(kUser, kPass, NULL, &zero_b[0]));
    CHECK(!server.started());

    REQUIRE(startServer(server));
    REQUIRE(client.compute(client.a_pub, server.publicKey(), server.salt(), kUser, kPass));
    REQUIRE(serverVerify(server, client.a_pub, client.m1, k, m2));
    // Non-consuming: second verify yields identical output.
    std::vector<uint8_t> k2, m22;
    REQUIRE(serverVerify(server, client.a_pub, client.m1, k2, m22));
    CHECK_BYTES_EQ(k, k2);
    CHECK_BYTES_EQ(m2, m22);

    server.reset();
    CHECK(!server.started());
    CHECK(server.publicKey().empty());
    CHECK(server.salt().empty());
    CHECK(!serverVerify(server, client.a_pub, client.m1, k, m2));

    // Restart with a different salt -> different B; old proof no longer valid.
    std::vector<uint8_t> salt2 = salt;
    salt2[0] ^= 0xff;
    const std::vector<uint8_t> b = fixedB();
    REQUIRE(server.start(kUser, kPass, &salt2[0], &b[0]));
    CHECK(server.publicKey() != hexToBytes(kPinB));
    CHECK(!serverVerify(server, client.a_pub, client.m1, k, m2));
}

TEST_CASE(clientALeadingZeroPaddingSemantics) {
    srp::Srp6aServer server;
    REQUIRE(startServer(server));
    Client client("srp-a-330");
    REQUIRE(client.a_pub.size() == 384);
    CHECK_EQ(0, static_cast<int>(client.a_pub[0]));  // minimal encoding is 383 bytes
    CHECK_BYTES_EQ(hexToBytes(kPinA_330), client.a_pub);
    REQUIRE(client.compute(client.a_pub, server.publicKey(), server.salt(), kUser, kPass));
    CHECK_BYTES_EQ(hexToBytes(kPinK_330), client.k);
    CHECK_BYTES_EQ(hexToBytes(kPinM2_330), client.m2);

    // 384-byte padded, 383-byte minimal and 400-byte zero-prefixed forms of A are equivalent.
    const std::vector<uint8_t> minimal(client.a_pub.begin() + 1, client.a_pub.end());
    std::vector<uint8_t> wide(16, 0);
    cat(wide, client.a_pub);
    const std::vector<uint8_t>* forms[] = {&client.a_pub, &minimal, &wide};
    for (size_t i = 0; i < 3; ++i) {
        std::vector<uint8_t> k, m2;
        REQUIRE(serverVerify(server, *forms[i], client.m1, k, m2));
        CHECK_BYTES_EQ(hexToBytes(kPinK_330), k);
        CHECK_BYTES_EQ(hexToBytes(kPinM2_330), m2);
    }

    // A client that (wrongly) hashed the minimal 383-byte A instead of pad(A) everywhere
    // derives a different u/K/M1 and is rejected.
    Client wrong("srp-a-330");
    wrong.raw_a_hash = true;
    REQUIRE(wrong.compute(minimal, server.publicKey(), server.salt(), kUser, kPass));
    CHECK(wrong.k != client.k);
    std::vector<uint8_t> k, m2;
    CHECK(!serverVerify(server, minimal, wrong.m1, k, m2));
}

TEST_CASE(sharedSecretLeadingZeroUsesMinimalEncoding) {
    srp::Srp6aServer server;
    REQUIRE(startServer(server));
    Client client("srp-a-634");
    REQUIRE(client.compute(client.a_pub, server.publicKey(), server.salt(), kUser, kPass));
    CHECK_EQ(static_cast<size_t>(383), client.s_min.size());  // S has a leading zero byte
    std::vector<uint8_t> k, m2;
    REQUIRE(serverVerify(server, client.a_pub, client.m1, k, m2));
    CHECK_BYTES_EQ(client.k, k);
    CHECK_BYTES_EQ(hexToBytes(kPinK_634), k);
    CHECK_BYTES_EQ(hexToBytes(kPinM2_634), m2);
    // K = H(min(S)), not H(pad(S)).
    CHECK(sha(padOf(client.s_min)) != k);
    CHECK_BYTES_EQ(sha(client.s_min), k);
}

TEST_CASE(publicKeyAAboveModulusHashedUnreduced) {
    // Kotlin hashes pad(A) of the raw A (not A mod N): A' = A + N (385 bytes) is accepted when
    // the client hashes the same raw bytes; S (hence K) equals the A case, M1/M2 differ.
    srp::Srp6aServer server;
    REQUIRE(startServer(server));
    Client client("srp-a");
    const std::vector<uint8_t> a_plus_n = addBE(client.a_pub, primeBytes());
    REQUIRE(a_plus_n.size() == 385);
    REQUIRE(client.compute(a_plus_n, server.publicKey(), server.salt(), kUser, kPass));
    std::vector<uint8_t> k, m2;
    // u differs from the plain-A case, so K differs from kPinK_srp_a, but both sides agree.
    REQUIRE(serverVerify(server, a_plus_n, client.m1, k, m2));
    CHECK_BYTES_EQ(client.k, k);
    CHECK_BYTES_EQ(client.m2, m2);
    CHECK(k != hexToBytes(kPinK_srp_a));
    // Hashing the reduced A instead of the raw bytes does not verify.
    Client reduced("srp-a");
    REQUIRE(reduced.compute(reduced.a_pub, server.publicKey(), server.salt(), kUser, kPass));
    CHECK(!serverVerify(server, a_plus_n, reduced.m1, k, m2));
}

int main() {
    return test_support::runAll("test_srp6a");
}
