#ifndef CARPLAY_AIRPLAY_CRYPTO_HPP
#define CARPLAY_AIRPLAY_CRYPTO_HPP

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace carplay {
namespace crypto {

static const size_t kKeyBytes = 32;
static const size_t kEd25519SeedBytes = 32;
static const size_t kEd25519SecretKeyBytes = 64;
static const size_t kEd25519PublicKeyBytes = 32;
static const size_t kEd25519SignatureBytes = 64;
static const size_t kSha1Bytes = 20;
static const size_t kSha256Bytes = 32;
static const size_t kSha512Bytes = 64;
static const size_t kAes128KeyBytes = 16;
static const size_t kAesBlockBytes = 16;
static const size_t kNonceBytes = 12;
static const size_t kTagBytes = 16;

struct X25519KeyPair {
    uint8_t secret_key[kKeyBytes];
    uint8_t public_key[kKeyBytes];

    X25519KeyPair();
    ~X25519KeyPair();
};

struct Ed25519KeyPair {
    uint8_t secret_key[kEd25519SecretKeyBytes];
    uint8_t public_key[kEd25519PublicKeyBytes];

    Ed25519KeyPair();
    ~Ed25519KeyPair();
};

/// Securely zero a memory region using Monocypher's anti-optimization wipe.
void wipe(void* data, size_t size);

/// Returns true if every byte in [data, data + size) is zero.
bool isAllZero(const uint8_t* data, size_t size);

/// Constant-time comparison helper; returns true iff both buffers are equal.
bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t size);

/// Derives an X25519 key pair from a 32-byte random secret key/seed.
void x25519FromSecret(const uint8_t secret_key[kKeyBytes], X25519KeyPair& out);

/// Computes X25519 Diffie-Hellman shared secret and rejects all-zero low-order outputs.
bool x25519SharedSecret(const uint8_t our_secret[kKeyBytes],
                        const uint8_t peer_public[kKeyBytes],
                        uint8_t shared_out[kKeyBytes]);

/// Derives an Ed25519 key pair from a 32-byte seed without mutating the caller's seed.
void ed25519FromSeed(const uint8_t seed[kEd25519SeedBytes], Ed25519KeyPair& out);

/// Signs a message using a 64-byte Monocypher Ed25519 expanded secret key.
void ed25519Sign(const uint8_t secret_key[kEd25519SecretKeyBytes],
                 const uint8_t* message,
                 size_t message_len,
                 uint8_t signature_out[kEd25519SignatureBytes]);

/// Verifies an Ed25519 signature against a 32-byte public key. Returns true if valid.
bool ed25519Verify(const uint8_t public_key[kEd25519PublicKeyBytes],
                   const uint8_t* message,
                   size_t message_len,
                   const uint8_t signature[kEd25519SignatureBytes]);

/// Computes SHA-1 digest over input bytes.
void sha1(const uint8_t* data, size_t len, uint8_t hash_out[kSha1Bytes]);

/// Computes SHA-256 digest over input bytes.
void sha256(const uint8_t* data, size_t len, uint8_t hash_out[kSha256Bytes]);

/// Encrypts or decrypts `len` bytes using AES-128 in CTR mode (big-endian 128-bit counter).
bool aes128Ctr(const uint8_t key[kAes128KeyBytes],
               const uint8_t iv[kAesBlockBytes],
               const uint8_t* input,
               size_t len,
               uint8_t* output);

/// Computes SHA-512 over input bytes.
void sha512(const uint8_t* data, size_t len, uint8_t hash_out[kSha512Bytes]);

/// Computes HKDF-SHA512 (RFC 5869 extract + expand). Returns false if out_len == 0 or > 255 * 64.
bool hkdfSha512(const uint8_t* ikm,
                size_t ikm_len,
                const uint8_t* salt,
                size_t salt_len,
                const uint8_t* info,
                size_t info_len,
                uint8_t* okm_out,
                size_t okm_len);

/// Convenience HKDF-SHA512 overload returning a byte vector.
bool hkdfSha512(const std::vector<uint8_t>& ikm,
                const std::string& salt,
                const std::string& info,
                size_t okm_len,
                std::vector<uint8_t>& okm_out);

/// Builds a 12-byte HAP/AirPlay counter nonce: 4 zero bytes + 8-byte little-endian counter.
void makeCounterNonce(uint64_t counter, uint8_t nonce_out[kNonceBytes]);

/// Builds a 12-byte HAP/AirPlay label nonce (e.g., "PV-Msg02", "PS-Msg05"), right-aligned with leading zeros.
bool makeLabelNonce(const std::string& label, uint8_t nonce_out[kNonceBytes]);

/// Encrypts plaintext using ChaCha20-Poly1305 (RFC 8439 IETF 96-bit nonce) with detached 16-byte MAC tag.
bool chacha20Poly1305SealDetached(const uint8_t key[kKeyBytes],
                                  const uint8_t nonce[kNonceBytes],
                                  const uint8_t* aad,
                                  size_t aad_len,
                                  const uint8_t* plaintext,
                                  size_t plaintext_len,
                                  uint8_t* ciphertext_out,
                                  uint8_t tag_out[kTagBytes]);

/// Decrypts and verifies ChaCha20-Poly1305 ciphertext with a detached 16-byte MAC tag.
bool chacha20Poly1305OpenDetached(const uint8_t key[kKeyBytes],
                                  const uint8_t nonce[kNonceBytes],
                                  const uint8_t* aad,
                                  size_t aad_len,
                                  const uint8_t* ciphertext,
                                  size_t ciphertext_len,
                                  const uint8_t tag[kTagBytes],
                                  uint8_t* plaintext_out);

/// Encrypts into combined ciphertext || 16-byte tag (used by HAP Pair-Setup / Pair-Verify / HTTP control).
bool chacha20Poly1305Seal(const uint8_t key[kKeyBytes],
                          const uint8_t nonce[kNonceBytes],
                          const uint8_t* aad,
                          size_t aad_len,
                          const uint8_t* plaintext,
                          size_t plaintext_len,
                          std::vector<uint8_t>& sealed_out);

/// Decrypts combined ciphertext || 16-byte tag; returns false and leaves output empty if auth fails.
bool chacha20Poly1305Open(const uint8_t key[kKeyBytes],
                          const uint8_t nonce[kNonceBytes],
                          const uint8_t* aad,
                          size_t aad_len,
                          const uint8_t* sealed,
                          size_t sealed_len,
                          std::vector<uint8_t>& plaintext_out);

}  // namespace crypto
}  // namespace carplay

#endif  // CARPLAY_AIRPLAY_CRYPTO_HPP
