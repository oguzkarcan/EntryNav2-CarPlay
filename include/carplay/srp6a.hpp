#ifndef CARPLAY_SRP6A_HPP
#define CARPLAY_SRP6A_HPP

// SRP-6a SERVER (accessory) side for AirPlay / CarPlay pair-setup.
//
// Byte-exact port of DiPlay `Srp6a.kt` (RFC 5054 3072-bit group, generator 5, SHA-512,
// username "Pair-Setup", password = setup code, e.g. "3939"):
//
//   k  = H(min(N) | pad(g))
//   x  = H(salt | H(I ":" P))
//   v  = g^x mod N
//   B  = (k*v + g^b) mod N                       (published as pad(B), 384 bytes)
//   u  = H(pad(A) | pad(B))
//   S  = ((A mod N) * v^u)^b mod N
//   K  = H(min(S))
//   M1 = H(H(min(N)) xor H(min(g)) | H(I) | salt | pad(A) | pad(B) | K)
//   M2 = H(pad(A) | M1 | K)
//
// min(x) is the minimal big-endian encoding (no leading zero bytes; zero -> single 0x00) and
// pad(x) is min(x) left-padded with zeros to 384 bytes, or min(x) unchanged when it is already
// >= 384 bytes long. A is taken exactly as received (NOT reduced mod N) for pad(A); only the
// S computation uses A mod N. A with A mod N == 0 is rejected.
//
// Randomness is supplied by the caller (salt and the 32-byte private exponent b) so that the
// computation is deterministic and testable.
//
// Not constant-time (see bigint.hpp): acceptable because the password is a public constant.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/bigint.hpp"

namespace carplay {
namespace srp {

static const size_t kSaltBytes = 16;
static const size_t kPrivateKeyBytes = 32;
static const size_t kPrimeBytes = 384;
static const size_t kHashBytes = 64;
static const size_t kProofBytes = 64;
static const size_t kSessionKeyBytes = 64;
/// Longest client public key A accepted by Srp6aServer::verify (raw byte length).
static const size_t kMaxPublicKeyABytes = bigint::kMaxReduceInputBytes;  // 512
static const uint32_t kGenerator = 5;

/// RFC 5054 Appendix A 3072-bit prime N, big-endian, 384 bytes.
const uint8_t* rfc5054Prime3072();
/// Lazily initialised Montgomery context for N (thread-safe function-local static).
const bigint::Modulus& group3072();

/// Kotlin `toBytes(toBigInt(bytes))`: strips leading zero bytes; all-zero/empty -> {0x00}.
std::vector<uint8_t> encodeMinimal(const uint8_t* data, size_t len);
/// Kotlin `pad(toBigInt(bytes))`: minimal encoding left-padded to 384 bytes unless it is
/// already >= 384 bytes long.
std::vector<uint8_t> encodePadded(const uint8_t* data, size_t len);

/// SRP-6a multiplier k = H(min(N) | pad(g)) (64 bytes).
std::vector<uint8_t> multiplierK();

/// SRP-6a server session.
///
/// Lifecycle / reuse semantics:
///  * start() (re)initialises the session; calling it again discards the previous session.
///  * verify() is non-consuming, like the Kotlin reference: it does not modify the session, so
///    it may be called again (e.g. after a failed attempt). Callers that want one-shot
///    semantics (recommended for pair-setup) must call reset() after the first verify().
///  * reset() and the destructor wipe all secrets (b, v, salt, B). The object is non-copyable.
class Srp6aServer {
public:
    Srp6aServer();
    ~Srp6aServer();

    /// Computes v and B. Returns false (session reset) on null pointers, an all-zero private
    /// exponent, or an internal arithmetic failure.
    bool start(const std::string& username,
               const std::string& password,
               const uint8_t salt[kSaltBytes],
               const uint8_t private_b[kPrivateKeyBytes]);

    bool started() const { return started_; }

    /// pad(B): 384 bytes after a successful start(), empty otherwise.
    const std::vector<uint8_t>& publicKey() const { return public_b_; }
    /// The 16-byte salt after a successful start(), empty otherwise.
    const std::vector<uint8_t>& salt() const { return salt_; }

    /// Verifies the client's A and proof M1. On success fills the 64-byte session key K and the
    /// 64-byte server proof M2 and returns true. Returns false (outputs cleared) if not started,
    /// a_len == 0 or > kMaxPublicKeyABytes, proof_len != kProofBytes, A mod N == 0, or the proof
    /// does not match (constant-time comparison).
    bool verify(const uint8_t* public_a,
                size_t a_len,
                const uint8_t* client_proof,
                size_t proof_len,
                std::vector<uint8_t>& session_key_k,
                std::vector<uint8_t>& server_proof_m2) const;

    /// Wipes all session state.
    void reset();

private:
    Srp6aServer(const Srp6aServer&);
    Srp6aServer& operator=(const Srp6aServer&);

    bool started_;
    std::vector<uint8_t> identifier_;
    std::vector<uint8_t> salt_;
    std::vector<uint8_t> public_b_;  // pad(B)
    bigint::Number verifier_;        // v
    uint8_t private_b_[kPrivateKeyBytes];
};

}  // namespace srp
}  // namespace carplay

#endif  // CARPLAY_SRP6A_HPP
