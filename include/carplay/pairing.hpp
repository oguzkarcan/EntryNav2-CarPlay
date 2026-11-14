#ifndef CARPLAY_PAIRING_HPP
#define CARPLAY_PAIRING_HPP

// Accessory-side (receiver) HAP-style Pair-Setup and Pair-Verify state machines used on the
// AirPlay/CarPlay control connection ("application/pairing+tlv8" bodies of POST /pair-setup and
// POST /pair-verify). Byte-exact port of DiPlay PairSetup.kt / PairVerify.kt, plus hardening.
//
// Pure byte-in/byte-out: no sockets, threads, files or OS randomness. Randomness is injected via
// RandomSource; persistence of paired controllers via PairingStore.
//
// ---------------------------------------------------------------------------------------------
// Pair-Setup (SRP-6a, username "Pair-Setup", fixed setup code "3939", see srp6a.hpp)
//   M1 {state 1}                      -> M2 {state 2, public key B (384), salt (16)}
//   M3 {state 3, public key A, proof} -> M4 {state 4, proof M2}
//   M5 {state 5, encrypted data}      -> M6 {state 6, encrypted data}
//   K   = SRP session key (64 bytes)
//   key = HKDF-SHA512(K, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info", 32)
//   M5 nonce "PS-Msg05", M6 nonce "PS-Msg06" (4 zero bytes + 8 ASCII bytes), no AAD.
//   M5 sub-TLV {identifier, public key (controller LTPK), signature} where the signature covers
//     HKDF(K, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info", 32) | id | LTPK.
//     On success the controller LTPK is saved in the PairingStore under its id.
//   M6 sub-TLV {identifier = accessory id, public key = accessory LTPK, signature over
//     HKDF(K, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info", 32) | id | LTPK}.
//
// Pair-Verify (X25519 + Ed25519)
//   M1 {state 1, public key = controller ephemeral} -> M2 {state 2, public key = accessory
//      ephemeral, encrypted data (nonce "PV-Msg02") = sub-TLV {identifier = accessory id,
//      signature over accEph | accId | ctrlEph}}
//   M3 {state 3, encrypted data (nonce "PV-Msg03") = sub-TLV {identifier = controller id,
//      signature over ctrlEph | ctrlId | accEph}}, verified with the STORED controller LTPK
//                                                    -> M4 {state 4}
//   key = HKDF-SHA512(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", 32)
//
// Channel keys (ACCESSORY perspective; "read" decrypts what the iPhone sends):
//   control (PairVerify.kt:96-97, deliberate swap):
//     read  = HKDF(shared, "Control-Salt", "Control-Write-Encryption-Key", 32)
//     write = HKDF(shared, "Control-Salt", "Control-Read-Encryption-Key", 32)
//   events (AirPlaySession.kt acceptEvent():890-902, NO swap):
//     read  = HKDF(shared, "Events-Salt", "Events-Read-Encryption-Key", 32)
//     write = HKDF(shared, "Events-Salt", "Events-Write-Encryption-Key", 32)
//
// Error replies are always TLV {state, error = 2 (authentication)}. The state byte follows the
// reference exactly: "regular" failure paths use the fixed response state (Pair-Setup 4 / 6,
// Pair-Verify 2 / 4), paths that throw in the reference (AEAD open failure, bad X25519 input,
// RNG failure) echo the request state, an unknown state echoes it, a missing state gives 0.
// See pairing.cpp for the full table.
//
// Hardening beyond the reference (legitimate peers see identical bytes):
//   * any failure discards the whole exchange (a new M1 is required), so SRP allows exactly ONE
//     proof attempt per M1, M5 / pair-verify M3 exactly one attempt;
//   * strict message ordering; a fresh M1 always restarts cleanly;
//   * undecodable TLV bodies -> error TLV with state 0;
//   * length checks: X25519 / Ed25519 public keys 32, signatures 64, controller id 1..128 bytes;
//   * all-zero X25519 shared secret rejected (low-order points);
//   * PairVerify exposes sharedSecret()/controlKeys()/controllerId() only after a successful M4.
//
// The SESSION layer must write the M4 response of /pair-verify in PLAINTEXT and only afterwards
// switch the control connection to ControlCipher(read, write) from controlKeys().
//
// Not thread-safe. Classes are non-copyable; secrets are wiped on reset() and destruction.

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <string>
#include <vector>

#include "carplay/airplay_crypto.hpp"
#include "carplay/srp6a.hpp"
#include "carplay/tlv8_codec.hpp"

namespace carplay {
namespace pairing {

static const uint8_t kErrorAuthentication = 2;
static const size_t kMaxControllerIdBytes = 128;
static const size_t kMaxAccessoryIdBytes = 128;
static const size_t kPairingIdRandomBytes = 16;

/// Fixed SRP username / setup code used by CarPlay pair-setup.
extern const char* const kSetupUsername;  // "Pair-Setup"
extern const char* const kSetupCode;      // "3939"

/// Caller-supplied randomness (production: OS CSPRNG, tests: deterministic).
class RandomSource {
public:
    virtual ~RandomSource() {}
    /// Fills out[0..len) with random bytes. Returns false on failure.
    virtual bool fill(uint8_t* out, size_t len) = 0;
};

/// Long-term Ed25519 identity of the accessory (AirPlayIdentity.kt).
struct Identity {
    std::string pairing_id;
    crypto::Ed25519KeyPair keys;  // secret_key = Monocypher 64-byte expanded key (seed | pub)

    Identity() {}

    /// Derives the key pair from a 32-byte seed. Returns false (identity cleared) if `id` is
    /// empty or longer than kMaxAccessoryIdBytes or seed is NULL.
    bool initFromSeed(const uint8_t seed[crypto::kEd25519SeedBytes], const std::string& id);

    bool valid() const { return !pairing_id.empty(); }
    void clear();

private:
    Identity(const Identity&) = delete;
    Identity& operator=(const Identity&) = delete;
};

/// Formats 16 random bytes as a lowercase RFC 4122 version-4 UUID string (the reference uses
/// UUID.randomUUID().toString() as the pairing id). Version/variant bits are forced.
std::string formatPairingId(const uint8_t random16[kPairingIdRandomBytes]);

/// Generates a fresh identity like AirPlayIdentity.generate(): 32-byte seed, then 16 bytes for
/// the UUID pairing id (in that order). Returns false on RNG failure.
bool generateIdentity(RandomSource& rng, Identity& out);

/// Store of paired controllers' long-term Ed25519 public keys (PairingStore.kt).
class PairingStore {
public:
    virtual ~PairingStore() {}
    /// Saves (or replaces) the LTPK for `id`. Returns false if it could not be stored.
    virtual bool save(const std::string& id, const uint8_t ltpk[crypto::kEd25519PublicKeyBytes]) = 0;
    /// Copies the LTPK for `id` into ltpk_out. Returns false if unknown.
    virtual bool get(const std::string& id, uint8_t ltpk_out[crypto::kEd25519PublicKeyBytes]) const = 0;
    /// Removes every pairing.
    virtual void clear() = 0;
};

class InMemoryPairingStore : public PairingStore {
public:
    InMemoryPairingStore() {}
    virtual ~InMemoryPairingStore() {}
    virtual bool save(const std::string& id, const uint8_t ltpk[crypto::kEd25519PublicKeyBytes]);
    virtual bool get(const std::string& id, uint8_t ltpk_out[crypto::kEd25519PublicKeyBytes]) const;
    virtual void clear();
    size_t size() const { return entries_.size(); }

private:
    InMemoryPairingStore(const InMemoryPairingStore&) = delete;
    InMemoryPairingStore& operator=(const InMemoryPairingStore&) = delete;

    std::map<std::string, std::vector<uint8_t> > entries_;
};

/// Pair-Setup responder (PairSetup.kt).
class PairSetup {
public:
    /// All references must outlive this object.
    PairSetup(const Identity& identity, PairingStore& store, RandomSource& rng);
    ~PairSetup();

    /// Handles one request body and always produces a TLV8 reply in response_out (replaced).
    void handle(const uint8_t* body, size_t len, std::vector<uint8_t>& response_out);
    void handle(const std::vector<uint8_t>& body, std::vector<uint8_t>& response_out);

    /// True after M6 was produced for the most recent exchange (cleared by any later message
    /// that starts a new exchange or fails, and by reset()).
    bool complete() const { return complete_; }

    /// Wipes all exchange state.
    void reset();

private:
    PairSetup(const PairSetup&) = delete;
    PairSetup& operator=(const PairSetup&) = delete;

    enum Stage { kIdle = 0, kAwaitM3 = 1, kAwaitM5 = 2 };

    void fail(uint8_t state, std::vector<uint8_t>& response_out);
    void onM1(std::vector<uint8_t>& response_out);
    void onM3(const std::vector<tlv8::Item>& items, std::vector<uint8_t>& response_out);
    void onM5(const std::vector<tlv8::Item>& items, std::vector<uint8_t>& response_out);

    const Identity& identity_;
    PairingStore& store_;
    RandomSource& rng_;
    srp::Srp6aServer srp_;
    uint8_t session_key_[srp::kSessionKeyBytes];
    Stage stage_;
    bool complete_;
};

/// Pair-Verify responder (PairVerify.kt).
class PairVerify {
public:
    /// All references must outlive this object.
    PairVerify(const Identity& identity, PairingStore& store, RandomSource& rng);
    ~PairVerify();

    /// Handles one request body and always produces a TLV8 reply in response_out (replaced).
    void handle(const uint8_t* body, size_t len, std::vector<uint8_t>& response_out);
    void handle(const std::vector<uint8_t>& body, std::vector<uint8_t>& response_out);

    /// True after a successful M3 -> M4.
    bool verified() const { return stage_ == kVerified; }
    /// Verified controller pairing id (empty unless verified()).
    const std::string& controllerId() const { return controller_id_; }
    /// X25519 shared secret; false (out untouched) unless verified().
    bool sharedSecret(uint8_t out[crypto::kKeyBytes]) const;
    /// Accessory-perspective control channel keys (see header comment); false unless verified().
    bool controlKeys(uint8_t read_key[crypto::kKeyBytes], uint8_t write_key[crypto::kKeyBytes]) const;

    /// Wipes all exchange state.
    void reset();

private:
    PairVerify(const PairVerify&) = delete;
    PairVerify& operator=(const PairVerify&) = delete;

    enum Stage { kIdle = 0, kAwaitM3 = 1, kVerified = 2 };

    void fail(uint8_t state, std::vector<uint8_t>& response_out);
    void onM1(const std::vector<tlv8::Item>& items, std::vector<uint8_t>& response_out);
    void onM3(const std::vector<tlv8::Item>& items, std::vector<uint8_t>& response_out);

    const Identity& identity_;
    PairingStore& store_;
    RandomSource& rng_;
    Stage stage_;
    uint8_t own_public_[crypto::kKeyBytes];
    uint8_t peer_public_[crypto::kKeyBytes];
    uint8_t shared_[crypto::kKeyBytes];
    uint8_t encrypt_key_[crypto::kKeyBytes];
    uint8_t read_key_[crypto::kKeyBytes];
    uint8_t write_key_[crypto::kKeyBytes];
    std::string controller_id_;
};

/// Accessory-perspective control keys: read = "Control-Write-Encryption-Key",
/// write = "Control-Read-Encryption-Key" (salt "Control-Salt"). Returns false on NULL args.
bool deriveControlKeys(const uint8_t shared[crypto::kKeyBytes],
                       uint8_t read_key[crypto::kKeyBytes],
                       uint8_t write_key[crypto::kKeyBytes]);

/// Accessory-perspective event-channel keys, exactly as AirPlaySession.acceptEvent():
/// read = "Events-Read-Encryption-Key", write = "Events-Write-Encryption-Key" (salt
/// "Events-Salt"), i.e. NOT swapped like the control channel. Returns false on NULL args.
bool deriveEventKeys(const uint8_t shared[crypto::kKeyBytes],
                     uint8_t read_key[crypto::kKeyBytes],
                     uint8_t write_key[crypto::kKeyBytes]);

}  // namespace pairing
}  // namespace carplay

#endif  // CARPLAY_PAIRING_HPP
