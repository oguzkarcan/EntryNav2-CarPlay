#include "carplay/airplay_crypto.hpp"

#include <cstring>

extern "C" {
#include "monocypher.h"
#include "monocypher-ed25519.h"
}

namespace carplay {
namespace crypto {

X25519KeyPair::X25519KeyPair() {
    std::memset(secret_key, 0, sizeof(secret_key));
    std::memset(public_key, 0, sizeof(public_key));
}

X25519KeyPair::~X25519KeyPair() {
    wipe(secret_key, sizeof(secret_key));
}

Ed25519KeyPair::Ed25519KeyPair() {
    std::memset(secret_key, 0, sizeof(secret_key));
    std::memset(public_key, 0, sizeof(public_key));
}

Ed25519KeyPair::~Ed25519KeyPair() {
    wipe(secret_key, sizeof(secret_key));
}

void wipe(void* data, size_t size) {
    if (data != NULL && size > 0) {
        crypto_wipe(data, size);
    }
}

bool isAllZero(const uint8_t* data, size_t size) {
    uint8_t acc = 0;
    for (size_t i = 0; i < size; ++i) {
        acc |= data[i];
    }
    return acc == 0;
}

bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t size) {
    if (size == 0) {
        return true;
    }
    if (a == NULL || b == NULL) {
        return false;
    }
    if (size == 16) {
        return crypto_verify16(a, b) == 0;
    }
    if (size == 32) {
        return crypto_verify32(a, b) == 0;
    }
    if (size == 64) {
        return crypto_verify64(a, b) == 0;
    }
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < size; ++i) {
        diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    }
    return diff == 0;
}

void x25519FromSecret(const uint8_t secret_key[kKeyBytes], X25519KeyPair& out) {
    std::memcpy(out.secret_key, secret_key, kKeyBytes);
    crypto_x25519_public_key(out.public_key, out.secret_key);
}

bool x25519SharedSecret(const uint8_t our_secret[kKeyBytes],
                        const uint8_t peer_public[kKeyBytes],
                        uint8_t shared_out[kKeyBytes]) {
    crypto_x25519(shared_out, our_secret, peer_public);
    if (isAllZero(shared_out, kKeyBytes)) {
        wipe(shared_out, kKeyBytes);
        return false;
    }
    return true;
}

void ed25519FromSeed(const uint8_t seed[kEd25519SeedBytes], Ed25519KeyPair& out) {
    uint8_t mutable_seed[kEd25519SeedBytes];
    std::memcpy(mutable_seed, seed, kEd25519SeedBytes);
    crypto_ed25519_key_pair(out.secret_key, out.public_key, mutable_seed);
    wipe(mutable_seed, sizeof(mutable_seed));
}

void ed25519Sign(const uint8_t secret_key[kEd25519SecretKeyBytes],
                 const uint8_t* message,
                 size_t message_len,
                 uint8_t signature_out[kEd25519SignatureBytes]) {
    static const uint8_t kEmpty = 0;
    const uint8_t* msg_ptr = (message_len > 0 && message != NULL) ? message : &kEmpty;
    crypto_ed25519_sign(signature_out, secret_key, msg_ptr, message_len);
}

bool ed25519Verify(const uint8_t public_key[kEd25519PublicKeyBytes],
                   const uint8_t* message,
                   size_t message_len,
                   const uint8_t signature[kEd25519SignatureBytes]) {
    static const uint8_t kEmpty = 0;
    const uint8_t* msg_ptr = (message_len > 0 && message != NULL) ? message : &kEmpty;
    return crypto_ed25519_check(signature, public_key, msg_ptr, message_len) == 0;
}

void sha512(const uint8_t* data, size_t len, uint8_t hash_out[kSha512Bytes]) {
    static const uint8_t kEmpty = 0;
    const uint8_t* ptr = (len > 0 && data != NULL) ? data : &kEmpty;
    crypto_sha512(hash_out, ptr, len);
}

bool hkdfSha512(const uint8_t* ikm,
                size_t ikm_len,
                const uint8_t* salt,
                size_t salt_len,
                const uint8_t* info,
                size_t info_len,
                uint8_t* okm_out,
                size_t okm_len) {
    if (okm_out == NULL || okm_len == 0 || okm_len > 255U * kSha512Bytes) {
        return false;
    }
    static const uint8_t kEmpty = 0;
    const uint8_t* ikm_ptr = (ikm_len > 0 && ikm != NULL) ? ikm : &kEmpty;
    const uint8_t* salt_ptr = (salt_len > 0 && salt != NULL) ? salt : &kEmpty;
    const uint8_t* info_ptr = (info_len > 0 && info != NULL) ? info : &kEmpty;
    crypto_sha512_hkdf(okm_out, okm_len, ikm_ptr, ikm_len, salt_ptr, salt_len, info_ptr, info_len);
    return true;
}

bool hkdfSha512(const std::vector<uint8_t>& ikm,
                const std::string& salt,
                const std::string& info,
                size_t okm_len,
                std::vector<uint8_t>& okm_out) {
    if (okm_len == 0 || okm_len > 255U * kSha512Bytes) {
        return false;
    }
    okm_out.assign(okm_len, 0);
    const uint8_t* ikm_ptr = ikm.empty() ? NULL : &ikm[0];
    const uint8_t* salt_ptr = salt.empty() ? NULL : reinterpret_cast<const uint8_t*>(salt.data());
    const uint8_t* info_ptr = info.empty() ? NULL : reinterpret_cast<const uint8_t*>(info.data());
    return hkdfSha512(ikm_ptr, ikm.size(), salt_ptr, salt.size(), info_ptr, info.size(), &okm_out[0], okm_len);
}

void makeCounterNonce(uint64_t counter, uint8_t nonce_out[kNonceBytes]) {
    nonce_out[0] = 0;
    nonce_out[1] = 0;
    nonce_out[2] = 0;
    nonce_out[3] = 0;
    for (size_t i = 0; i < 8; ++i) {
        nonce_out[4 + i] = static_cast<uint8_t>((counter >> (8U * i)) & 0xffU);
    }
}

bool makeLabelNonce(const std::string& label, uint8_t nonce_out[kNonceBytes]) {
    if (label.empty() || label.size() > kNonceBytes) {
        return false;
    }
    std::memset(nonce_out, 0, kNonceBytes);
    const size_t offset = kNonceBytes - label.size();
    std::memcpy(nonce_out + offset, label.data(), label.size());
    return true;
}

bool chacha20Poly1305SealDetached(const uint8_t key[kKeyBytes],
                                  const uint8_t nonce[kNonceBytes],
                                  const uint8_t* aad,
                                  size_t aad_len,
                                  const uint8_t* plaintext,
                                  size_t plaintext_len,
                                  uint8_t* ciphertext_out,
                                  uint8_t tag_out[kTagBytes]) {
    if (key == NULL || nonce == NULL || tag_out == NULL) {
        return false;
    }
    if (plaintext_len > 0 && (plaintext == NULL || ciphertext_out == NULL)) {
        return false;
    }
    static uint8_t dummy = 0;
    const uint8_t* pt_ptr = plaintext_len > 0 ? plaintext : &dummy;
    uint8_t* ct_ptr = plaintext_len > 0 ? ciphertext_out : &dummy;
    const uint8_t* aad_ptr = (aad_len > 0 && aad != NULL) ? aad : &dummy;

    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, nonce);
    crypto_aead_write(&ctx, ct_ptr, tag_out, aad_ptr, aad_len, pt_ptr, plaintext_len);
    wipe(&ctx, sizeof(ctx));
    return true;
}

bool chacha20Poly1305OpenDetached(const uint8_t key[kKeyBytes],
                                  const uint8_t nonce[kNonceBytes],
                                  const uint8_t* aad,
                                  size_t aad_len,
                                  const uint8_t* ciphertext,
                                  size_t ciphertext_len,
                                  const uint8_t tag[kTagBytes],
                                  uint8_t* plaintext_out) {
    if (key == NULL || nonce == NULL || tag == NULL) {
        return false;
    }
    if (ciphertext_len > 0 && (ciphertext == NULL || plaintext_out == NULL)) {
        return false;
    }
    static uint8_t dummy = 0;
    const uint8_t* ct_ptr = ciphertext_len > 0 ? ciphertext : &dummy;
    uint8_t* pt_ptr = ciphertext_len > 0 ? plaintext_out : &dummy;
    const uint8_t* aad_ptr = (aad_len > 0 && aad != NULL) ? aad : &dummy;

    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, nonce);
    const int status = crypto_aead_read(&ctx, pt_ptr, tag, aad_ptr, aad_len, ct_ptr, ciphertext_len);
    wipe(&ctx, sizeof(ctx));
    if (status != 0) {
        if (ciphertext_len > 0 && plaintext_out != NULL) {
            wipe(plaintext_out, ciphertext_len);
        }
        return false;
    }
    return true;
}

bool chacha20Poly1305Seal(const uint8_t key[kKeyBytes],
                          const uint8_t nonce[kNonceBytes],
                          const uint8_t* aad,
                          size_t aad_len,
                          const uint8_t* plaintext,
                          size_t plaintext_len,
                          std::vector<uint8_t>& sealed_out) {
    sealed_out.assign(plaintext_len + kTagBytes, 0);
    uint8_t* ct_ptr = plaintext_len > 0 ? &sealed_out[0] : NULL;
    uint8_t* tag_ptr = &sealed_out[plaintext_len];
    if (!chacha20Poly1305SealDetached(key, nonce, aad, aad_len, plaintext, plaintext_len, ct_ptr, tag_ptr)) {
        sealed_out.clear();
        return false;
    }
    return true;
}

bool chacha20Poly1305Open(const uint8_t key[kKeyBytes],
                          const uint8_t nonce[kNonceBytes],
                          const uint8_t* aad,
                          size_t aad_len,
                          const uint8_t* sealed,
                          size_t sealed_len,
                          std::vector<uint8_t>& plaintext_out) {
    plaintext_out.clear();
    if (sealed == NULL || sealed_len < kTagBytes) {
        return false;
    }
    const size_t ct_len = sealed_len - kTagBytes;
    plaintext_out.assign(ct_len, 0);
    uint8_t* pt_ptr = ct_len > 0 ? &plaintext_out[0] : NULL;
    const uint8_t* ct_ptr = ct_len > 0 ? sealed : NULL;
    const uint8_t* tag_ptr = sealed + ct_len;
    if (!chacha20Poly1305OpenDetached(key, nonce, aad, aad_len, ct_ptr, ct_len, tag_ptr, pt_ptr)) {
        plaintext_out.clear();
        return false;
    }
    return true;
}

namespace {

inline uint32_t rotl32(uint32_t v, unsigned n) {
    return (v << n) | (v >> (32U - n));
}

inline uint32_t rotr32(uint32_t v, unsigned n) {
    return (v >> n) | (v << (32U - n));
}

inline uint32_t loadBe32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

inline void storeBe32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>((v >> 24) & 0xffU);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xffU);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xffU);
    p[3] = static_cast<uint8_t>(v & 0xffU);
}

inline uint8_t aesXtime(uint8_t x) {
    return static_cast<uint8_t>((x << 1) ^ ((x & 0x80U) ? 0x1bU : 0x00U));
}

uint8_t aesGfMul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    for (int i = 0; i < 8; ++i) {
        if ((b & 1U) != 0) r ^= a;
        a = aesXtime(a);
        b >>= 1;
    }
    return r;
}

uint8_t aesSboxByte(uint8_t x) {
    uint8_t inv = 0;
    if (x != 0) {
        uint8_t base = x;
        uint8_t exp = 254U;
        inv = 1;
        while (exp > 0) {
            if ((exp & 1U) != 0) inv = aesGfMul(inv, base);
            base = aesGfMul(base, base);
            exp >>= 1;
        }
    }
    uint8_t s = 0x63U;
    for (unsigned i = 0; i < 5; ++i) {
        s ^= static_cast<uint8_t>((inv << i) | (inv >> (8U - i)));
    }
    return s;
}

void aesKeyExpansion128(const uint8_t key[kAes128KeyBytes], uint8_t round_keys[176]) {
    std::memcpy(round_keys, key, kAes128KeyBytes);
    uint8_t rcon = 0x01U;
    size_t generated = 16;
    while (generated < 176) {
        uint8_t t0 = round_keys[generated - 4];
        uint8_t t1 = round_keys[generated - 3];
        uint8_t t2 = round_keys[generated - 2];
        uint8_t t3 = round_keys[generated - 1];
        if ((generated % 16) == 0) {
            uint8_t tmp = t0;
            t0 = aesSboxByte(t1) ^ rcon;
            t1 = aesSboxByte(t2);
            t2 = aesSboxByte(t3);
            t3 = aesSboxByte(tmp);
            rcon = aesXtime(rcon);
        }
        round_keys[generated + 0] = round_keys[generated - 16] ^ t0;
        round_keys[generated + 1] = round_keys[generated - 15] ^ t1;
        round_keys[generated + 2] = round_keys[generated - 14] ^ t2;
        round_keys[generated + 3] = round_keys[generated - 13] ^ t3;
        generated += 4;
    }
}

void aesAddRoundKey(uint8_t state[16], const uint8_t* rk) {
    for (int i = 0; i < 16; ++i) {
        state[i] ^= rk[i];
    }
}

void aesShiftRows(uint8_t s[16]) {
    uint8_t t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;

    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;

    t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

void aesMixColumns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t* col = s + c * 4;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        uint8_t xor_all = a0 ^ a1 ^ a2 ^ a3;
        col[0] = a0 ^ xor_all ^ aesXtime(a0 ^ a1);
        col[1] = a1 ^ xor_all ^ aesXtime(a1 ^ a2);
        col[2] = a2 ^ xor_all ^ aesXtime(a2 ^ a3);
        col[3] = a3 ^ xor_all ^ aesXtime(a3 ^ a0);
    }
}

void aesEncryptBlock128(const uint8_t round_keys[176], const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    std::memcpy(s, in, 16);
    aesAddRoundKey(s, round_keys);
    for (int round = 1; round <= 10; ++round) {
        for (int i = 0; i < 16; ++i) {
            s[i] = aesSboxByte(s[i]);
        }
        aesShiftRows(s);
        if (round < 10) {
            aesMixColumns(s);
        }
        aesAddRoundKey(s, round_keys + round * 16);
    }
    std::memcpy(out, s, 16);
    wipe(s, sizeof(s));
}

void sha1Transform(uint32_t state[5], const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = loadBe32(block + i * 4);
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1U);
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f = 0;
        uint32_t k = 0;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999U;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1U;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCU;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6U;
        }
        uint32_t temp = rotl32(a, 5U) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30U);
        b = a;
        a = temp;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    wipe(w, sizeof(w));
}

void sha256Transform(uint32_t state[8], const uint8_t block[64]) {
    static const uint32_t kRound[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = loadBe32(block + i * 4);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7U) ^ rotr32(w[i - 15], 18U) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17U) ^ rotr32(w[i - 2], 19U) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e, 6U) ^ rotr32(e, 11U) ^ rotr32(e, 25U);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + kRound[i] + w[i];
        uint32_t S0 = rotr32(a, 2U) ^ rotr32(a, 13U) ^ rotr32(a, 22U);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
    wipe(w, sizeof(w));
}

template <typename TransformFn>
void hashFinalize64(const uint8_t* data,
                    size_t len,
                    uint32_t* state,
                    TransformFn transform_fn) {
    uint8_t block[64];
    size_t offset = 0;
    while (len - offset >= 64U) {
        transform_fn(state, data + offset);
        offset += 64U;
    }
    const size_t rem = len - offset;
    std::memset(block, 0, sizeof(block));
    if (rem > 0 && data != NULL) {
        std::memcpy(block, data + offset, rem);
    }
    block[rem] = 0x80U;
    if (rem >= 56U) {
        transform_fn(state, block);
        std::memset(block, 0, sizeof(block));
    }
    const uint64_t bit_len = static_cast<uint64_t>(len) * 8ULL;
    storeBe32(block + 56, static_cast<uint32_t>((bit_len >> 32) & 0xffffffffULL));
    storeBe32(block + 60, static_cast<uint32_t>(bit_len & 0xffffffffULL));
    transform_fn(state, block);
    wipe(block, sizeof(block));
}

}  // namespace

void sha1(const uint8_t* data, size_t len, uint8_t hash_out[kSha1Bytes]) {
    if (hash_out == NULL) {
        return;
    }
    static const uint8_t dummy = 0;
    const uint8_t* src = (len > 0 && data != NULL) ? data : &dummy;
    uint32_t state[5] = {
        0x67452301U, 0xEFCDAB89U, 0x98BADCFEU, 0x10325476U, 0xC3D2E1F0U
    };
    hashFinalize64(src, len, state, sha1Transform);
    for (int i = 0; i < 5; ++i) {
        storeBe32(hash_out + i * 4, state[i]);
    }
    wipe(state, sizeof(state));
}

void sha256(const uint8_t* data, size_t len, uint8_t hash_out[kSha256Bytes]) {
    if (hash_out == NULL) {
        return;
    }
    static const uint8_t dummy = 0;
    const uint8_t* src = (len > 0 && data != NULL) ? data : &dummy;
    uint32_t state[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    hashFinalize64(src, len, state, sha256Transform);
    for (int i = 0; i < 8; ++i) {
        storeBe32(hash_out + i * 4, state[i]);
    }
    wipe(state, sizeof(state));
}

bool aes128Ctr(const uint8_t key[kAes128KeyBytes],
               const uint8_t iv[kAesBlockBytes],
               const uint8_t* input,
               size_t len,
               uint8_t* output) {
    if (key == NULL || iv == NULL) {
        return false;
    }
    if (len > 0 && (input == NULL || output == NULL)) {
        return false;
    }
    uint8_t round_keys[176];
    aesKeyExpansion128(key, round_keys);
    uint8_t counter[16];
    std::memcpy(counter, iv, 16);
    uint8_t keystream[16];

    size_t offset = 0;
    while (offset < len) {
        aesEncryptBlock128(round_keys, counter, keystream);
        const size_t chunk = (len - offset < 16U) ? (len - offset) : 16U;
        for (size_t i = 0; i < chunk; ++i) {
            output[offset + i] = input[offset + i] ^ keystream[i];
        }
        offset += chunk;
        for (int i = 15; i >= 0; --i) {
            if (++counter[i] != 0U) {
                break;
            }
        }
    }
    wipe(round_keys, sizeof(round_keys));
    wipe(counter, sizeof(counter));
    wipe(keystream, sizeof(keystream));
    return true;
}

}  // namespace crypto
}  // namespace carplay
