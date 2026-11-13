#include "carplay/srp6a.hpp"

#include "carplay/airplay_crypto.hpp"

#include <string.h>

namespace carplay {
namespace srp {

namespace {

// RFC 5054 Appendix A / RFC 3526 3072-bit MODP prime.
const uint8_t kPrime3072[kPrimeBytes] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
    0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
    0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
    0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
    0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
    0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31, 0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
    0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x3A, 0xD2, 0xCA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

struct GroupHolder {
    bigint::Modulus modulus;
    GroupHolder() {
        bigint::Number n;
        bigint::fromBytesBE(kPrime3072, kPrimeBytes, n);
        modulus.init(n);
    }
};

void append(std::vector<uint8_t>& out, const uint8_t* data, size_t len) {
    if (len > 0) {
        out.insert(out.end(), data, data + len);
    }
}

void append(std::vector<uint8_t>& out, const std::vector<uint8_t>& data) {
    out.insert(out.end(), data.begin(), data.end());
}

void hash(const std::vector<uint8_t>& data, uint8_t out[kHashBytes]) {
    crypto::sha512(data.empty() ? NULL : &data[0], data.size(), out);
}

void wipeVector(std::vector<uint8_t>& v) {
    if (!v.empty()) {
        crypto::wipe(&v[0], v.size());
    }
    v.clear();
}

std::vector<uint8_t> numberPadded(const bigint::Number& n) {
    std::vector<uint8_t> out;
    if (!bigint::toBytesBEPadded(n, kPrimeBytes, out)) {
        bigint::toBytesBE(n, out);  // >= 384 bytes: unpadded (cannot happen for values < 2^3072)
    }
    return out;
}

}  // namespace

const uint8_t* rfc5054Prime3072() {
    return kPrime3072;
}

const bigint::Modulus& group3072() {
    static const GroupHolder holder;
    return holder.modulus;
}

std::vector<uint8_t> encodeMinimal(const uint8_t* data, size_t len) {
    while (len > 0 && data[0] == 0) {
        ++data;
        --len;
    }
    std::vector<uint8_t> out;
    if (len == 0) {
        out.push_back(0);
    } else {
        out.assign(data, data + len);
    }
    return out;
}

std::vector<uint8_t> encodePadded(const uint8_t* data, size_t len) {
    std::vector<uint8_t> minimal = encodeMinimal(data, len);
    if (minimal.size() >= kPrimeBytes) {
        return minimal;
    }
    std::vector<uint8_t> out(kPrimeBytes - minimal.size(), 0);
    append(out, minimal);
    wipeVector(minimal);
    return out;
}

std::vector<uint8_t> multiplierK() {
    std::vector<uint8_t> buf;
    append(buf, encodeMinimal(kPrime3072, kPrimeBytes));
    const uint8_t g = static_cast<uint8_t>(kGenerator);
    append(buf, encodePadded(&g, 1));
    std::vector<uint8_t> k(kHashBytes);
    hash(buf, &k[0]);
    return k;
}

// ---------------------------------------------------------------------------------------------

Srp6aServer::Srp6aServer() : started_(false) {
    memset(private_b_, 0, sizeof(private_b_));
}

Srp6aServer::~Srp6aServer() {
    reset();
}

void Srp6aServer::reset() {
    started_ = false;
    wipeVector(identifier_);
    wipeVector(salt_);
    wipeVector(public_b_);
    verifier_.clear();
    crypto::wipe(private_b_, sizeof(private_b_));
}

bool Srp6aServer::start(const std::string& username,
                        const std::string& password,
                        const uint8_t salt[kSaltBytes],
                        const uint8_t private_b[kPrivateKeyBytes]) {
    reset();
    if (salt == NULL || private_b == NULL || crypto::isAllZero(private_b, kPrivateKeyBytes)) {
        return false;
    }
    const bigint::Modulus& group = group3072();
    if (!group.valid()) {
        return false;
    }

    // x = H(salt | H(I ":" P))
    std::vector<uint8_t> inner;
    inner.assign(username.begin(), username.end());
    inner.push_back(':');
    inner.insert(inner.end(), password.begin(), password.end());
    uint8_t inner_hash[kHashBytes];
    hash(inner, inner_hash);
    wipeVector(inner);

    std::vector<uint8_t> outer;
    append(outer, salt, kSaltBytes);
    append(outer, inner_hash, kHashBytes);
    uint8_t x[kHashBytes];
    hash(outer, x);
    wipeVector(outer);
    crypto::wipe(inner_hash, sizeof(inner_hash));

    const bigint::Number g = bigint::fromUint32(kGenerator);
    bigint::Number v;
    bigint::Number gb;
    bigint::Number kv;
    bigint::Number b_pub;
    bigint::Number k;
    const std::vector<uint8_t> k_bytes = multiplierK();
    bool ok = group.modExp(g, x, kHashBytes, v);
    crypto::wipe(x, sizeof(x));
    ok = ok && bigint::fromBytesBE(&k_bytes[0], k_bytes.size(), k);
    ok = ok && group.modExp(g, private_b, kPrivateKeyBytes, gb);
    ok = ok && group.mulMod(k, v, kv);
    ok = ok && group.addMod(kv, gb, b_pub);
    ok = ok && !bigint::isZero(b_pub);
    gb.clear();
    kv.clear();
    if (!ok) {
        v.clear();
        return false;
    }

    identifier_.assign(username.begin(), username.end());
    salt_.assign(salt, salt + kSaltBytes);
    public_b_ = numberPadded(b_pub);
    verifier_ = v;
    v.clear();
    memcpy(private_b_, private_b, kPrivateKeyBytes);
    started_ = true;
    return true;
}

bool Srp6aServer::verify(const uint8_t* public_a,
                         size_t a_len,
                         const uint8_t* client_proof,
                         size_t proof_len,
                         std::vector<uint8_t>& session_key_k,
                         std::vector<uint8_t>& server_proof_m2) const {
    session_key_k.clear();
    server_proof_m2.clear();
    if (!started_ || public_a == NULL || client_proof == NULL || a_len == 0 ||
        a_len > kMaxPublicKeyABytes || proof_len != kProofBytes) {
        return false;
    }
    const bigint::Modulus& group = group3072();

    bigint::Number a_mod;
    if (!group.reduce(public_a, a_len, a_mod) || bigint::isZero(a_mod)) {
        return false;
    }
    const std::vector<uint8_t> pad_a = encodePadded(public_a, a_len);

    // u = H(pad(A) | pad(B))
    std::vector<uint8_t> buf;
    append(buf, pad_a);
    append(buf, public_b_);
    uint8_t u[kHashBytes];
    hash(buf, u);

    // S = ((A mod N) * v^u)^b mod N
    bigint::Number vu;
    bigint::Number base;
    bigint::Number s;
    bool ok = group.modExp(verifier_, u, kHashBytes, vu);
    ok = ok && group.mulMod(a_mod, vu, base);
    ok = ok && group.modExp(base, private_b_, kPrivateKeyBytes, s);
    vu.clear();
    base.clear();
    if (!ok) {
        s.clear();
        return false;
    }

    // K = H(min(S))
    std::vector<uint8_t> s_bytes;
    bigint::toBytesBE(s, s_bytes);
    s.clear();
    uint8_t key[kSessionKeyBytes];
    hash(s_bytes, key);
    wipeVector(s_bytes);

    // M1 = H(H(N) xor H(g) | H(I) | salt | pad(A) | pad(B) | K)
    uint8_t hash_n[kHashBytes];
    uint8_t hash_g[kHashBytes];
    uint8_t hash_i[kHashBytes];
    crypto::sha512(kPrime3072, kPrimeBytes, hash_n);
    const uint8_t g = static_cast<uint8_t>(kGenerator);
    crypto::sha512(&g, 1, hash_g);
    hash(identifier_, hash_i);
    buf.clear();
    for (size_t i = 0; i < kHashBytes; ++i) {
        buf.push_back(static_cast<uint8_t>(hash_n[i] ^ hash_g[i]));
    }
    append(buf, hash_i, kHashBytes);
    append(buf, salt_);
    append(buf, pad_a);
    append(buf, public_b_);
    append(buf, key, kSessionKeyBytes);
    uint8_t expected_m1[kProofBytes];
    hash(buf, expected_m1);
    wipeVector(buf);

    if (!crypto::constantTimeEqual(expected_m1, client_proof, kProofBytes)) {
        crypto::wipe(key, sizeof(key));
        crypto::wipe(expected_m1, sizeof(expected_m1));
        return false;
    }

    // M2 = H(pad(A) | M1 | K)
    append(buf, pad_a);
    append(buf, client_proof, kProofBytes);
    append(buf, key, kSessionKeyBytes);
    uint8_t m2[kProofBytes];
    hash(buf, m2);
    wipeVector(buf);

    session_key_k.assign(key, key + kSessionKeyBytes);
    server_proof_m2.assign(m2, m2 + kProofBytes);
    crypto::wipe(key, sizeof(key));
    crypto::wipe(expected_m1, sizeof(expected_m1));
    return true;
}

}  // namespace srp
}  // namespace carplay
