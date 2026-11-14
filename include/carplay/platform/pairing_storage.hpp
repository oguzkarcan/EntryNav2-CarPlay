#ifndef CARPLAY_PLATFORM_PAIRING_STORAGE_HPP
#define CARPLAY_PLATFORM_PAIRING_STORAGE_HPP

// Persistent accessory identity + paired-controller table in a caller-chosen private directory
// (on the car e.g. a sub-directory of the writable, reboot-persistent /var/local/data).
//
// Files (all little-endian, written with writeFileAtomic: temp + fsync + rename, mode 0600, in a
// 0700 directory on POSIX; a leftover "<file>.tmp" from a crash is deleted on load):
//
//   identity.bin   (max 4096 bytes accepted)
//     "CPID" | u16 version = 1 | u16 reserved = 0 | seed[32] | u16 id_len (1..128) |
//     id (printable ASCII 0x21..0x7e) | check[16]
//   controllers.bin  (max 64 KiB accepted)
//     "CPCT" | u16 version = 1 | u16 reserved = 0 | u32 count (<= kMaxStoredControllers) |
//     u64 next_seq | count x { u16 id_len (1..128) | id | ltpk[32] | u64 seq } | check[16]
//   check = first 16 bytes of SHA-512 over every preceding byte. Exact length required; duplicate
//   ids, unknown versions, non-zero reserved fields or trailing bytes are "corrupt".
//
// Corruption policy (StorageOptions, configurable):
//   * identity: default kCorruptRefuse. A silently regenerated identity changes the accessory
//     LTPK, so every iPhone that paired with the car would fail pair-verify with no explanation, and
//     a damaged file may indicate flash trouble or tampering worth surfacing. The daemon gets
//     kStorageCorrupt, the file is left untouched for inspection, and the operator (or a daemon
//     policy that opts into kCorruptReset) decides. With kCorruptReset a fresh identity replaces it
//     (kStorageReset); the caller should then clear() the controller table as well, since every
//     phone has to pair again anyway.
//   * controllers: default kCorruptReset. Losing the table only forces phones to pair again, which
//     the user can do from the phone without help; refusing would disable CarPlay entirely.
//   * read errors (permissions, I/O) are never treated as corruption: kStorageIoError, nothing is
//     overwritten.
//
// Eviction: at most StorageOptions::max_controllers entries (1..kMaxStoredControllers, default
// 16). Saving a NEW id at capacity evicts the entry with the oldest save sequence (the pairing
// performed longest ago; re-pairing an id refreshes it). Pair-verify lookups do not refresh it,
// because get() must stay const and must not write flash on every connection.
//
// Secrets: the seed is wiped (crypto::wipe) from every temporary buffer; nothing here logs key
// material. Controller LTPKs are public keys and are not secret.
//
// Not thread-safe: use from the reactor thread.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/airplay_crypto.hpp"
#include "carplay/pairing.hpp"

namespace carplay {
namespace platform {

static const size_t kMaxStoredControllers = 256;
static const size_t kDefaultMaxControllers = 16;
static const size_t kIdentityFileMaxBytes = 4096;
static const size_t kControllersFileMaxBytes = 64 * 1024;

extern const char* const kIdentityFileName;     // "identity.bin"
extern const char* const kControllersFileName;  // "controllers.bin"

enum CorruptPolicy {
    kCorruptRefuse = 0,  // report kStorageCorrupt, leave the file alone
    kCorruptReset = 1    // replace with a fresh identity / an empty table, report kStorageReset
};

struct StorageOptions {
    size_t max_controllers;
    CorruptPolicy identity_policy;
    CorruptPolicy controllers_policy;

    StorageOptions()
        : max_controllers(kDefaultMaxControllers),
          identity_policy(kCorruptRefuse),
          controllers_policy(kCorruptReset) {}
};

enum StorageStatus {
    kStorageLoaded = 0,       // existing valid file loaded
    kStorageCreated = 1,      // no file existed; a new one was written
    kStorageReset = 2,        // file was corrupt and has been replaced (kCorruptReset)
    kStorageCorrupt = 3,      // file is corrupt and policy is kCorruptRefuse: not usable
    kStorageIoError = 4,      // directory/file could not be created, read or written
    kStorageRngError = 5,     // random source failed while creating an identity
    kStorageBadArgument = 6   // empty directory path or invalid options
};

/// true for kStorageLoaded / kStorageCreated / kStorageReset.
bool storageUsable(StorageStatus status);
const char* storageStatusName(StorageStatus status);

/// Loads <dir>/identity.bin, or creates it (32-byte seed then 16 bytes for the UUID pairing id,
/// like pairing::generateIdentity) if absent. `out` is valid only when storageUsable(result).
StorageStatus loadOrCreateIdentity(const std::string& dir, pairing::RandomSource& rng,
                                   pairing::Identity& out,
                                   const StorageOptions& options = StorageOptions());

/// Serialisation helpers (exposed for tests and tooling).
void encodeIdentityFile(const uint8_t seed[crypto::kEd25519SeedBytes], const std::string& id,
                        std::vector<uint8_t>& out);
bool decodeIdentityFile(const std::vector<uint8_t>& file, uint8_t seed_out[crypto::kEd25519SeedBytes],
                        std::string& id_out);

class FilePairingStore : public pairing::PairingStore {
public:
    explicit FilePairingStore(const StorageOptions& options = StorageOptions());
    virtual ~FilePairingStore();

    /// Loads <dir>/controllers.bin (creating an empty one if absent). On kStorageCorrupt or an
    /// error the store stays closed: get() finds nothing and save() fails.
    StorageStatus open(const std::string& dir);
    bool isOpen() const { return open_; }

    /// Persists before returning true; on a write failure the in-memory table is left unchanged.
    virtual bool save(const std::string& id, const uint8_t ltpk[crypto::kEd25519PublicKeyBytes]);
    virtual bool get(const std::string& id, uint8_t ltpk_out[crypto::kEd25519PublicKeyBytes]) const;
    /// Removes every pairing (persisted; failures are logged, see clearAll()).
    virtual void clear();
    bool clearAll();
    bool remove(const std::string& id);

    size_t size() const { return entries_.size(); }
    size_t capacity() const { return options_.max_controllers; }
    bool contains(const std::string& id) const { return find(id) >= 0; }
    /// Ids ordered from oldest to newest save.
    std::vector<std::string> ids() const;

private:
    FilePairingStore(const FilePairingStore&) = delete;
    FilePairingStore& operator=(const FilePairingStore&) = delete;

    struct Entry {
        std::string id;
        uint8_t ltpk[crypto::kEd25519PublicKeyBytes];
        uint64_t seq;
    };

    int find(const std::string& id) const;
    bool persist(const std::vector<Entry>& entries, uint64_t next_seq) const;
    bool decode(const std::vector<uint8_t>& file, std::vector<Entry>& out, uint64_t& next_seq) const;
    static void evictOldest(std::vector<Entry>& entries, size_t keep);

    StorageOptions options_;
    std::string path_;
    std::vector<Entry> entries_;
    uint64_t next_seq_;
    bool open_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_PAIRING_STORAGE_HPP
