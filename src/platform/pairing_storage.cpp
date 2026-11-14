#include "carplay/platform/pairing_storage.hpp"

#include <string.h>

#include <cstddef>

#include "carplay/platform/file_util.hpp"
#include "carplay/platform/log.hpp"

namespace carplay {
namespace platform {

const char* const kIdentityFileName = "identity.bin";
const char* const kControllersFileName = "controllers.bin";

namespace {

const char kTag[] = "storage";
const uint8_t kIdentityMagic[4] = {'C', 'P', 'I', 'D'};
const uint8_t kControllersMagic[4] = {'C', 'P', 'C', 'T'};
const uint16_t kFormatVersion = 1;
const size_t kCheckBytes = 16;

void putU16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x & 0xff));
    v.push_back(static_cast<uint8_t>(x >> 8));
}

void putU32(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; ++i) {
        v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xff));
    }
}

void putU64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i) {
        v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xff));
    }
}

void appendCheck(std::vector<uint8_t>& v) {
    uint8_t h[crypto::kSha512Bytes];
    crypto::sha512(v.empty() ? NULL : &v[0], v.size(), h);
    v.insert(v.end(), h, h + kCheckBytes);
}

bool checkOk(const std::vector<uint8_t>& v) {
    if (v.size() < kCheckBytes) {
        return false;
    }
    uint8_t h[crypto::kSha512Bytes];
    crypto::sha512(&v[0], v.size() - kCheckBytes, h);
    return memcmp(h, &v[v.size() - kCheckBytes], kCheckBytes) == 0;
}

// Bounds-checked little-endian reader.
class Reader {
public:
    Reader(const std::vector<uint8_t>& v, size_t end) : v_(v), pos_(0), end_(end), ok_(true) {}
    bool ok() const { return ok_; }
    bool atEnd() const { return pos_ == end_; }
    bool bytes(uint8_t* out, size_t n) {
        if (!ok_ || end_ - pos_ < n) {
            ok_ = false;
            return false;
        }
        if (n > 0) {
            memcpy(out, &v_[pos_], n);
        }
        pos_ += n;
        return true;
    }
    uint64_t le(size_t n) {
        uint8_t b[8] = {0};
        if (!bytes(b, n)) {
            return 0;
        }
        uint64_t x = 0;
        for (size_t i = n; i > 0; --i) {
            x = (x << 8) | b[i - 1];
        }
        return x;
    }
    bool string(size_t n, std::string& out) {
        if (!ok_ || end_ - pos_ < n) {
            ok_ = false;
            return false;
        }
        out.assign(reinterpret_cast<const char*>(&v_[pos_]), n);
        pos_ += n;
        return true;
    }

private:
    const std::vector<uint8_t>& v_;
    size_t pos_;
    size_t end_;
    bool ok_;
};

void wipeVector(std::vector<uint8_t>& v) {
    if (!v.empty()) {
        crypto::wipe(&v[0], v.size());
    }
    v.clear();
}

bool validIdentityId(const std::string& id) {
    if (id.empty() || id.size() > pairing::kMaxAccessoryIdBytes) {
        return false;
    }
    for (size_t i = 0; i < id.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(id[i]);
        if (c < 0x21 || c > 0x7e) {
            return false;
        }
    }
    return true;
}

StorageStatus createIdentity(const std::string& path, pairing::RandomSource& rng, pairing::Identity& out) {
    uint8_t seed[crypto::kEd25519SeedBytes];
    uint8_t rand16[pairing::kPairingIdRandomBytes];
    if (!rng.fill(seed, sizeof(seed)) || !rng.fill(rand16, sizeof(rand16))) {
        crypto::wipe(seed, sizeof(seed));
        crypto::wipe(rand16, sizeof(rand16));
        return kStorageRngError;
    }
    const std::string id = pairing::formatPairingId(rand16);
    crypto::wipe(rand16, sizeof(rand16));
    std::vector<uint8_t> file;
    encodeIdentityFile(seed, id, file);
    const bool written = writeFileAtomic(path, &file[0], file.size());
    wipeVector(file);
    if (!written || !out.initFromSeed(seed, id)) {
        crypto::wipe(seed, sizeof(seed));
        out.clear();
        return kStorageIoError;
    }
    crypto::wipe(seed, sizeof(seed));
    return kStorageCreated;
}

}  // namespace

bool storageUsable(StorageStatus s) {
    return s == kStorageLoaded || s == kStorageCreated || s == kStorageReset;
}

const char* storageStatusName(StorageStatus s) {
    switch (s) {
        case kStorageLoaded: return "loaded";
        case kStorageCreated: return "created";
        case kStorageReset: return "reset";
        case kStorageCorrupt: return "corrupt";
        case kStorageIoError: return "io-error";
        case kStorageRngError: return "rng-error";
        case kStorageBadArgument: return "bad-argument";
    }
    return "unknown";
}

void encodeIdentityFile(const uint8_t seed[crypto::kEd25519SeedBytes], const std::string& id,
                        std::vector<uint8_t>& out) {
    out.clear();
    out.reserve(4 + 2 + 2 + crypto::kEd25519SeedBytes + 2 + id.size() + kCheckBytes);
    out.insert(out.end(), kIdentityMagic, kIdentityMagic + 4);
    putU16(out, kFormatVersion);
    putU16(out, 0);
    out.insert(out.end(), seed, seed + crypto::kEd25519SeedBytes);
    putU16(out, static_cast<uint16_t>(id.size()));
    out.insert(out.end(), id.begin(), id.end());
    appendCheck(out);
}

bool decodeIdentityFile(const std::vector<uint8_t>& file, uint8_t seed_out[crypto::kEd25519SeedBytes],
                        std::string& id_out) {
    id_out.clear();
    if (file.size() > kIdentityFileMaxBytes || !checkOk(file)) {
        return false;
    }
    Reader r(file, file.size() - kCheckBytes);
    uint8_t magic[4];
    r.bytes(magic, 4);
    const uint64_t version = r.le(2);
    const uint64_t reserved = r.le(2);
    uint8_t seed[crypto::kEd25519SeedBytes];
    r.bytes(seed, sizeof(seed));
    const uint64_t id_len = r.le(2);
    std::string id;
    if (r.ok() && id_len <= pairing::kMaxAccessoryIdBytes) {
        r.string(static_cast<size_t>(id_len), id);
    }
    const bool ok = r.ok() && r.atEnd() && memcmp(magic, kIdentityMagic, 4) == 0 &&
                    version == kFormatVersion && reserved == 0 && validIdentityId(id);
    if (ok) {
        memcpy(seed_out, seed, sizeof(seed));
        id_out = id;
    }
    crypto::wipe(seed, sizeof(seed));
    return ok;
}

StorageStatus loadOrCreateIdentity(const std::string& dir, pairing::RandomSource& rng,
                                   pairing::Identity& out, const StorageOptions& options) {
    out.clear();
    if (dir.empty()) {
        return kStorageBadArgument;
    }
    if (!ensurePrivateDirectory(dir)) {
        CARPLAY_LOG_ERROR(kTag, "cannot create/secure directory %s", dir.c_str());
        return kStorageIoError;
    }
    const std::string path = joinPath(dir, kIdentityFileName);
    removeFile(path + ".tmp");  // a crash between write and rename leaves only this behind

    std::vector<uint8_t> file;
    const FileReadResult rr = readFileBounded(path, kIdentityFileMaxBytes, file);
    if (rr == kFileMissing) {
        const StorageStatus st = createIdentity(path, rng, out);
        if (st == kStorageCreated) {
            CARPLAY_LOG_INFO(kTag, "created new accessory identity %s", out.pairing_id.c_str());
        } else {
            CARPLAY_LOG_ERROR(kTag, "could not create identity in %s (%s)", dir.c_str(), storageStatusName(st));
        }
        return st;
    }
    if (rr == kFileReadError) {
        CARPLAY_LOG_ERROR(kTag, "cannot read %s", path.c_str());
        return kStorageIoError;
    }
    uint8_t seed[crypto::kEd25519SeedBytes];
    std::string id;
    const bool decoded = rr == kFileReadOk && decodeIdentityFile(file, seed, id);
    wipeVector(file);
    if (decoded) {
        const bool ok = out.initFromSeed(seed, id);
        crypto::wipe(seed, sizeof(seed));
        if (ok) {
            return kStorageLoaded;
        }
    }
    crypto::wipe(seed, sizeof(seed));
    out.clear();
    if (options.identity_policy != kCorruptReset) {
        CARPLAY_LOG_ERROR(kTag, "identity file %s is corrupt; refusing to start (policy: refuse)", path.c_str());
        return kStorageCorrupt;
    }
    CARPLAY_LOG_WARN(kTag, "identity file %s is corrupt; generating a new identity (policy: reset)", path.c_str());
    const StorageStatus st = createIdentity(path, rng, out);
    return st == kStorageCreated ? kStorageReset : st;
}

// ------------------------------------------------------------------------------------------------
// FilePairingStore
// ------------------------------------------------------------------------------------------------

FilePairingStore::FilePairingStore(const StorageOptions& options)
    : options_(options), next_seq_(1), open_(false) {}

FilePairingStore::~FilePairingStore() {}

int FilePairingStore::find(const std::string& id) const {
    for (size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].id == id) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

void FilePairingStore::evictOldest(std::vector<Entry>& entries, size_t keep) {
    while (entries.size() > keep) {
        size_t oldest = 0;
        for (size_t i = 1; i < entries.size(); ++i) {
            if (entries[i].seq < entries[oldest].seq) {
                oldest = i;
            }
        }
        entries.erase(entries.begin() + static_cast<std::ptrdiff_t>(oldest));
    }
}

bool FilePairingStore::persist(const std::vector<Entry>& entries, uint64_t next_seq) const {
    std::vector<uint8_t> file;
    file.insert(file.end(), kControllersMagic, kControllersMagic + 4);
    putU16(file, kFormatVersion);
    putU16(file, 0);
    putU32(file, static_cast<uint32_t>(entries.size()));
    putU64(file, next_seq);
    for (size_t i = 0; i < entries.size(); ++i) {
        putU16(file, static_cast<uint16_t>(entries[i].id.size()));
        file.insert(file.end(), entries[i].id.begin(), entries[i].id.end());
        file.insert(file.end(), entries[i].ltpk, entries[i].ltpk + crypto::kEd25519PublicKeyBytes);
        putU64(file, entries[i].seq);
    }
    appendCheck(file);
    if (file.size() > kControllersFileMaxBytes) {
        return false;
    }
    return writeFileAtomic(path_, &file[0], file.size());
}

bool FilePairingStore::decode(const std::vector<uint8_t>& file, std::vector<Entry>& out,
                              uint64_t& next_seq) const {
    out.clear();
    if (file.size() > kControllersFileMaxBytes || !checkOk(file)) {
        return false;
    }
    Reader r(file, file.size() - kCheckBytes);
    uint8_t magic[4];
    r.bytes(magic, 4);
    const uint64_t version = r.le(2);
    const uint64_t reserved = r.le(2);
    const uint64_t count = r.le(4);
    next_seq = r.le(8);
    if (!r.ok() || memcmp(magic, kControllersMagic, 4) != 0 || version != kFormatVersion || reserved != 0 ||
        count > kMaxStoredControllers) {
        return false;
    }
    uint64_t max_seq = 0;
    for (uint64_t i = 0; i < count; ++i) {
        Entry e;
        const uint64_t id_len = r.le(2);
        if (!r.ok() || id_len == 0 || id_len > pairing::kMaxControllerIdBytes) {
            return false;
        }
        r.string(static_cast<size_t>(id_len), e.id);
        r.bytes(e.ltpk, sizeof(e.ltpk));
        e.seq = r.le(8);
        if (!r.ok()) {
            return false;
        }
        for (size_t k = 0; k < out.size(); ++k) {
            if (out[k].id == e.id) {
                return false;  // duplicate id
            }
        }
        if (e.seq > max_seq) {
            max_seq = e.seq;
        }
        out.push_back(e);
    }
    if (!r.atEnd()) {
        return false;
    }
    if (next_seq <= max_seq) {
        next_seq = max_seq + 1;  // keep ordering monotonic even if the counter was damaged
    }
    return true;
}

StorageStatus FilePairingStore::open(const std::string& dir) {
    open_ = false;
    entries_.clear();
    next_seq_ = 1;
    if (dir.empty() || options_.max_controllers == 0 || options_.max_controllers > kMaxStoredControllers) {
        return kStorageBadArgument;
    }
    if (!ensurePrivateDirectory(dir)) {
        CARPLAY_LOG_ERROR(kTag, "cannot create/secure directory %s", dir.c_str());
        return kStorageIoError;
    }
    path_ = joinPath(dir, kControllersFileName);
    removeFile(path_ + ".tmp");

    std::vector<uint8_t> file;
    const FileReadResult rr = readFileBounded(path_, kControllersFileMaxBytes, file);
    if (rr == kFileReadError) {
        CARPLAY_LOG_ERROR(kTag, "cannot read %s", path_.c_str());
        return kStorageIoError;
    }
    if (rr == kFileMissing) {
        if (!persist(entries_, next_seq_)) {
            return kStorageIoError;
        }
        open_ = true;
        return kStorageCreated;
    }
    std::vector<Entry> loaded;
    uint64_t seq = 1;
    if (rr == kFileReadOk && decode(file, loaded, seq)) {
        if (loaded.size() > options_.max_controllers) {
            evictOldest(loaded, options_.max_controllers);
            if (!persist(loaded, seq)) {
                return kStorageIoError;
            }
        }
        entries_.swap(loaded);
        next_seq_ = seq;
        open_ = true;
        return kStorageLoaded;
    }
    if (options_.controllers_policy != kCorruptReset) {
        CARPLAY_LOG_ERROR(kTag, "controller table %s is corrupt (policy: refuse)", path_.c_str());
        return kStorageCorrupt;
    }
    CARPLAY_LOG_WARN(kTag, "controller table %s is corrupt; starting empty (phones must pair again)",
                     path_.c_str());
    if (!persist(entries_, next_seq_)) {
        return kStorageIoError;
    }
    open_ = true;
    return kStorageReset;
}

bool FilePairingStore::save(const std::string& id, const uint8_t ltpk[crypto::kEd25519PublicKeyBytes]) {
    if (!open_ || ltpk == NULL || id.empty() || id.size() > pairing::kMaxControllerIdBytes) {
        return false;
    }
    std::vector<Entry> next = entries_;
    const int at = find(id);
    Entry* e = NULL;
    if (at >= 0) {
        e = &next[static_cast<size_t>(at)];
    } else {
        evictOldest(next, options_.max_controllers - 1);
        Entry fresh;
        fresh.id = id;
        next.push_back(fresh);
        e = &next.back();
    }
    memcpy(e->ltpk, ltpk, crypto::kEd25519PublicKeyBytes);
    e->seq = next_seq_;
    if (!persist(next, next_seq_ + 1)) {
        CARPLAY_LOG_ERROR(kTag, "could not persist controller table %s", path_.c_str());
        return false;
    }
    entries_.swap(next);
    ++next_seq_;
    return true;
}

bool FilePairingStore::get(const std::string& id, uint8_t ltpk_out[crypto::kEd25519PublicKeyBytes]) const {
    const int at = find(id);
    if (at < 0 || ltpk_out == NULL) {
        return false;
    }
    memcpy(ltpk_out, entries_[static_cast<size_t>(at)].ltpk, crypto::kEd25519PublicKeyBytes);
    return true;
}

bool FilePairingStore::remove(const std::string& id) {
    const int at = find(id);
    if (!open_ || at < 0) {
        return false;
    }
    std::vector<Entry> next = entries_;
    next.erase(next.begin() + at);
    if (!persist(next, next_seq_)) {
        return false;
    }
    entries_.swap(next);
    return true;
}

bool FilePairingStore::clearAll() {
    if (!open_) {
        entries_.clear();
        return false;
    }
    const std::vector<Entry> empty;
    const bool ok = persist(empty, next_seq_);
    entries_.clear();  // forget in memory even if the write failed: unpairing must take effect now
    if (!ok) {
        CARPLAY_LOG_ERROR(kTag, "could not persist cleared controller table %s", path_.c_str());
    }
    return ok;
}

void FilePairingStore::clear() { clearAll(); }

std::vector<std::string> FilePairingStore::ids() const {
    std::vector<Entry> sorted = entries_;
    // Insertion sort by seq (n <= 256).
    for (size_t i = 1; i < sorted.size(); ++i) {
        for (size_t j = i; j > 0 && sorted[j].seq < sorted[j - 1].seq; --j) {
            const Entry tmp = sorted[j];
            sorted[j] = sorted[j - 1];
            sorted[j - 1] = tmp;
        }
    }
    std::vector<std::string> out;
    for (size_t i = 0; i < sorted.size(); ++i) {
        out.push_back(sorted[i].id);
    }
    return out;
}

}  // namespace platform
}  // namespace carplay
