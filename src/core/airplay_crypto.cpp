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

}  // namespace crypto
}  // namespace carplay
