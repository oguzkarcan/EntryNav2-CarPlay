// Persistent identity + controller table: create/reload, persistence across instances, leftover
// temp files, corrupt/truncated/oversized/garbage files under both policies, eviction, clear,
// POSIX permission bits. Temp directories live next to the test binary (under BUILD_DIR).

#include <string.h>

#include <stdio.h>
#include <string>
#include <vector>

#include "carplay/airplay_crypto.hpp"
#include "carplay/pairing.hpp"
#include "carplay/platform/file_util.hpp"
#include "carplay/platform/log.hpp"
#include "carplay/platform/os_random.hpp"
#include "carplay/platform/pairing_storage.hpp"
#include "test_support.hpp"

using namespace carplay;
using namespace carplay::platform;

namespace {

std::string g_base;  // <dir of argv[0]>/tmp_platform_storage
int g_dir_counter = 0;

// Deterministic counter RNG (distinct output per call).
class CounterRng : public pairing::RandomSource {
public:
    CounterRng() : n_(1) {}
    virtual bool fill(uint8_t* out, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            out[i] = static_cast<uint8_t>((n_ * 131U + i * 17U) ^ (n_ >> 3));
            ++n_;
        }
        return true;
    }

private:
    unsigned n_;
};

class FailingRng : public pairing::RandomSource {
public:
    virtual bool fill(uint8_t*, size_t) { return false; }
};

void quietLog(void*, LogLevel, const char*, const char*) {}

const char* const kKnownFiles[] = {"identity.bin", "identity.bin.tmp", "controllers.bin",
                                   "controllers.bin.tmp"};

void cleanDir(const std::string& dir) {
    for (size_t i = 0; i < sizeof(kKnownFiles) / sizeof(kKnownFiles[0]); ++i) {
        removeFile(joinPath(dir, kKnownFiles[i]));
    }
    removeDirectory(dir);
}

// Fresh, empty directory per test case.
class TempDir {
public:
    TempDir() {
        char name[32];
        snprintf(name, sizeof(name), "case%d", ++g_dir_counter);
        path = joinPath(g_base, name);
        cleanDir(path);
    }
    ~TempDir() { cleanDir(path); }
    std::string file(const char* name) const { return joinPath(path, name); }
    std::string path;
};

std::vector<uint8_t> readAll(const std::string& path) {
    std::vector<uint8_t> v;
    readFileBounded(path, 1 << 20, v);
    return v;
}

bool writeRaw(const std::string& path, const std::vector<uint8_t>& data) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (f == NULL) {
        return false;
    }
    const size_t n = data.empty() ? 0 : std::fwrite(&data[0], 1, data.size(), f);
    return std::fclose(f) == 0 && n == data.size();
}

void makeKey(uint8_t seed, uint8_t out[crypto::kEd25519PublicKeyBytes]) {
    for (size_t i = 0; i < crypto::kEd25519PublicKeyBytes; ++i) {
        out[i] = static_cast<uint8_t>(seed + i);
    }
}

}  // namespace

// ------------------------------------------------------------------------------------------------
// Identity
// ------------------------------------------------------------------------------------------------

TEST_CASE(identityCreatedThenReloadedIdentically) {
    TempDir d;
    OsRandomSource rng;
    pairing::Identity a;
    CHECK_EQ(static_cast<int>(kStorageCreated), static_cast<int>(loadOrCreateIdentity(d.path, rng, a)));
    REQUIRE(a.valid());
    CHECK_EQ(36u, static_cast<unsigned>(a.pairing_id.size()));  // UUID text
    pairing::Identity b;
    CHECK_EQ(static_cast<int>(kStorageLoaded), static_cast<int>(loadOrCreateIdentity(d.path, rng, b)));
    REQUIRE(b.valid());
    CHECK_EQ(a.pairing_id, b.pairing_id);
    CHECK(memcmp(a.keys.public_key, b.keys.public_key, sizeof(a.keys.public_key)) == 0);
    CHECK(memcmp(a.keys.secret_key, b.keys.secret_key, sizeof(a.keys.secret_key)) == 0);
    // The reloaded key still signs verifiably.
    uint8_t sig[crypto::kEd25519SignatureBytes];
    const uint8_t msg[3] = {1, 2, 3};
    crypto::ed25519Sign(b.keys.secret_key, msg, sizeof(msg), sig);
    CHECK(crypto::ed25519Verify(a.keys.public_key, msg, sizeof(msg), sig));
}

TEST_CASE(identityFileCodecValidation) {
    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) {
        seed[i] = static_cast<uint8_t>(i * 3);
    }
    std::vector<uint8_t> f;
    encodeIdentityFile(seed, "ABCDEF-0123", f);
    CHECK_EQ(static_cast<size_t>(4 + 2 + 2 + 32 + 2 + 11 + 16), f.size());
    uint8_t out[32];
    std::string id;
    REQUIRE(decodeIdentityFile(f, out, id));
    CHECK(memcmp(out, seed, 32) == 0);
    CHECK_EQ(std::string("ABCDEF-0123"), id);
    // Every single-bit flip is detected.
    for (size_t i = 0; i < f.size(); ++i) {
        std::vector<uint8_t> g = f;
        g[i] ^= 0x01;
        if (decodeIdentityFile(g, out, id)) {
            ::test_support::recordFailure(__FILE__, __LINE__, "bit flip accepted");
            break;
        }
    }
    // Every truncation is rejected.
    for (size_t n = 0; n < f.size(); ++n) {
        std::vector<uint8_t> g(f.begin(), f.begin() + static_cast<std::ptrdiff_t>(n));
        CHECK(!decodeIdentityFile(g, out, id));
    }
    // Ids that are empty / too long / non-printable never encode into a loadable file.
    std::vector<uint8_t> h;
    encodeIdentityFile(seed, "", h);
    CHECK(!decodeIdentityFile(h, out, id));
    encodeIdentityFile(seed, std::string(129, 'a'), h);
    CHECK(!decodeIdentityFile(h, out, id));
    encodeIdentityFile(seed, "has space", h);
    CHECK(!decodeIdentityFile(h, out, id));
    encodeIdentityFile(seed, std::string(128, 'a'), h);
    CHECK(decodeIdentityFile(h, out, id));
}

TEST_CASE(corruptIdentityIsRefusedByDefault) {
    LogSink quiet = &quietLog;
    setLogSink(quiet, NULL);
    TempDir d;
    CounterRng rng;
    pairing::Identity a;
    REQUIRE(loadOrCreateIdentity(d.path, rng, a) == kStorageCreated);
    const std::vector<uint8_t> good = readAll(d.file(kIdentityFileName));
    REQUIRE(!good.empty());

    std::vector<std::vector<uint8_t> > bad;
    std::vector<uint8_t> flipped = good;
    flipped[10] ^= 0x80;
    bad.push_back(flipped);
    bad.push_back(std::vector<uint8_t>(good.begin(), good.begin() + 20));  // truncated
    bad.push_back(std::vector<uint8_t>());                                 // empty
    bad.push_back(std::vector<uint8_t>(5000, 0x41));                       // oversized
    std::vector<uint8_t> garbage(good.size());
    for (size_t i = 0; i < garbage.size(); ++i) {
        garbage[i] = static_cast<uint8_t>(i * 37 + 11);
    }
    bad.push_back(garbage);
    std::vector<uint8_t> trailing = good;
    trailing.push_back(0);
    bad.push_back(trailing);

    for (size_t k = 0; k < bad.size(); ++k) {
        REQUIRE(writeRaw(d.file(kIdentityFileName), bad[k]));
        pairing::Identity b;
        CHECK_EQ(static_cast<int>(kStorageCorrupt), static_cast<int>(loadOrCreateIdentity(d.path, rng, b)));
        CHECK(!b.valid());
        CHECK(readAll(d.file(kIdentityFileName)) == bad[k]);  // left untouched for inspection
    }

    // Opt-in reset policy: a new, different identity replaces the corrupt file.
    StorageOptions reset;
    reset.identity_policy = kCorruptReset;
    pairing::Identity c;
    CHECK_EQ(static_cast<int>(kStorageReset), static_cast<int>(loadOrCreateIdentity(d.path, rng, c, reset)));
    REQUIRE(c.valid());
    CHECK(c.pairing_id != a.pairing_id);
    pairing::Identity e;
    CHECK_EQ(static_cast<int>(kStorageLoaded), static_cast<int>(loadOrCreateIdentity(d.path, rng, e)));
    CHECK_EQ(c.pairing_id, e.pairing_id);
    setLogSink(NULL, NULL);
}

TEST_CASE(identityRngFailureAndBadArguments) {
    setLogSink(&quietLog, NULL);
    TempDir d;
    FailingRng bad;
    pairing::Identity a;
    CHECK_EQ(static_cast<int>(kStorageRngError), static_cast<int>(loadOrCreateIdentity(d.path, bad, a)));
    CHECK(!a.valid());
    CHECK(!pathExists(d.file(kIdentityFileName)));
    CounterRng rng;
    CHECK_EQ(static_cast<int>(kStorageBadArgument), static_cast<int>(loadOrCreateIdentity("", rng, a)));
    // A missing parent directory is an I/O error, never a silent success.
    CHECK_EQ(static_cast<int>(kStorageIoError),
             static_cast<int>(loadOrCreateIdentity(joinPath(d.file("missing-parent"), "x"), rng, a)));
    CHECK(storageUsable(kStorageReset));
    CHECK(!storageUsable(kStorageCorrupt));
    CHECK_EQ(std::string("corrupt"), std::string(storageStatusName(kStorageCorrupt)));
    setLogSink(NULL, NULL);
}

// ------------------------------------------------------------------------------------------------
// Controllers
// ------------------------------------------------------------------------------------------------

TEST_CASE(controllersPersistAcrossInstances) {
    TempDir d;
    uint8_t k1[32];
    uint8_t k2[32];
    uint8_t k3[32];
    makeKey(1, k1);
    makeKey(2, k2);
    makeKey(3, k3);
    {
        FilePairingStore s;
        CHECK_EQ(static_cast<int>(kStorageCreated), static_cast<int>(s.open(d.path)));
        CHECK(pathExists(d.file(kControllersFileName)));
        CHECK(s.save("iphone-A", k1));
        CHECK(s.save("iphone-B", k2));
        CHECK(s.save("iphone-A", k3));  // replace
        CHECK_EQ(2u, static_cast<unsigned>(s.size()));
        CHECK(!s.save("", k1));
        CHECK(!s.save(std::string(129, 'x'), k1));
    }
    FilePairingStore t;
    CHECK_EQ(static_cast<int>(kStorageLoaded), static_cast<int>(t.open(d.path)));
    CHECK_EQ(2u, static_cast<unsigned>(t.size()));
    uint8_t out[32];
    REQUIRE(t.get("iphone-A", out));
    CHECK(memcmp(out, k3, 32) == 0);
    REQUIRE(t.get("iphone-B", out));
    CHECK(memcmp(out, k2, 32) == 0);
    CHECK(!t.get("iphone-C", out));
    const std::vector<std::string> ids = t.ids();
    REQUIRE(ids.size() == 2u);
    CHECK_EQ(std::string("iphone-B"), ids[0]);  // A was re-saved last
    CHECK_EQ(std::string("iphone-A"), ids[1]);
    CHECK(t.remove("iphone-B"));
    CHECK(!t.remove("iphone-B"));

    // Usable through the core interface.
    pairing::PairingStore& iface = t;
    CHECK(iface.get("iphone-A", out));
    FilePairingStore u;
    REQUIRE(u.open(d.path) == kStorageLoaded);
    CHECK_EQ(1u, static_cast<unsigned>(u.size()));
}

TEST_CASE(leftoverTempFilesAreIgnoredAndRemoved) {
    TempDir d;
    uint8_t k[32];
    makeKey(9, k);
    {
        FilePairingStore s;
        REQUIRE(storageUsable(s.open(d.path)));
        REQUIRE(s.save("phone", k));
    }
    CounterRng rng;
    pairing::Identity id;
    REQUIRE(loadOrCreateIdentity(d.path, rng, id) == kStorageCreated);
    // Simulate a crash after writing the temp file but before the rename.
    REQUIRE(writeRaw(d.file("controllers.bin.tmp"), std::vector<uint8_t>(100, 0xee)));
    REQUIRE(writeRaw(d.file("identity.bin.tmp"), std::vector<uint8_t>(10, 0xee)));
    FilePairingStore t;
    CHECK_EQ(static_cast<int>(kStorageLoaded), static_cast<int>(t.open(d.path)));
    CHECK(t.contains("phone"));
    CHECK(!pathExists(d.file("controllers.bin.tmp")));
    pairing::Identity id2;
    CHECK_EQ(static_cast<int>(kStorageLoaded), static_cast<int>(loadOrCreateIdentity(d.path, rng, id2)));
    CHECK_EQ(id.pairing_id, id2.pairing_id);
    CHECK(!pathExists(d.file("identity.bin.tmp")));
}

TEST_CASE(corruptControllerTableResetOrRefused) {
    setLogSink(&quietLog, NULL);
    TempDir d;
    uint8_t k[32];
    makeKey(4, k);
    {
        FilePairingStore s;
        REQUIRE(storageUsable(s.open(d.path)));
        REQUIRE(s.save("a", k));
        REQUIRE(s.save("b", k));
    }
    const std::vector<uint8_t> good = readAll(d.file(kControllersFileName));
    REQUIRE(good.size() > 40u);

    std::vector<std::vector<uint8_t> > bad;
    std::vector<uint8_t> flipped = good;
    flipped[good.size() / 2] ^= 0x04;
    bad.push_back(flipped);
    bad.push_back(std::vector<uint8_t>(good.begin(), good.end() - 1));       // truncated
    bad.push_back(std::vector<uint8_t>(70 * 1024, 0));                        // oversized
    bad.push_back(std::vector<uint8_t>(good.size(), 0x5a));                   // garbage
    bad.push_back(std::vector<uint8_t>(3, 1));                                // tiny

    for (size_t i = 0; i < bad.size(); ++i) {
        StorageOptions refuse;
        refuse.controllers_policy = kCorruptRefuse;
        REQUIRE(writeRaw(d.file(kControllersFileName), bad[i]));
        FilePairingStore r(refuse);
        CHECK_EQ(static_cast<int>(kStorageCorrupt), static_cast<int>(r.open(d.path)));
        CHECK(!r.isOpen());
        CHECK(!r.save("c", k));
        CHECK(readAll(d.file(kControllersFileName)) == bad[i]);

        FilePairingStore s;  // default: reset
        CHECK_EQ(static_cast<int>(kStorageReset), static_cast<int>(s.open(d.path)));
        CHECK(s.isOpen());
        CHECK_EQ(0u, static_cast<unsigned>(s.size()));
        CHECK(s.save("c", k));
        FilePairingStore t;
        CHECK_EQ(static_cast<int>(kStorageLoaded), static_cast<int>(t.open(d.path)));
        CHECK(t.contains("c"));
    }
    setLogSink(NULL, NULL);
}

TEST_CASE(evictionDropsOldestSave) {
    TempDir d;
    StorageOptions o;
    o.max_controllers = 3;
    uint8_t k[32];
    makeKey(7, k);
    {
        FilePairingStore s(o);
        REQUIRE(storageUsable(s.open(d.path)));
        CHECK_EQ(3u, static_cast<unsigned>(s.capacity()));
        REQUIRE(s.save("a", k));
        REQUIRE(s.save("b", k));
        REQUIRE(s.save("c", k));
        REQUIRE(s.save("d", k));  // evicts a
        CHECK(!s.contains("a"));
        REQUIRE(s.save("b", k));  // refresh b: order is now c, d, b
        REQUIRE(s.save("e", k));  // evicts c
        CHECK(!s.contains("c"));
        CHECK(s.contains("d") && s.contains("b") && s.contains("e"));
    }
    {
        FilePairingStore t(o);
        REQUIRE(t.open(d.path) == kStorageLoaded);
        const std::vector<std::string> ids = t.ids();
        REQUIRE(ids.size() == 3u);
        CHECK_EQ(std::string("d"), ids[0]);
        CHECK_EQ(std::string("b"), ids[1]);
        CHECK_EQ(std::string("e"), ids[2]);
    }
    // Reopening with a smaller cap trims the oldest entries on load (and persists that).
    StorageOptions small;
    small.max_controllers = 1;
    {
        FilePairingStore t(small);
        REQUIRE(t.open(d.path) == kStorageLoaded);
        CHECK_EQ(1u, static_cast<unsigned>(t.size()));
        CHECK(t.contains("e"));
    }
    FilePairingStore u(o);
    REQUIRE(u.open(d.path) == kStorageLoaded);
    CHECK_EQ(1u, static_cast<unsigned>(u.size()));
    // Invalid caps are rejected.
    StorageOptions zero;
    zero.max_controllers = 0;
    FilePairingStore z(zero);
    CHECK_EQ(static_cast<int>(kStorageBadArgument), static_cast<int>(z.open(d.path)));
    StorageOptions huge;
    huge.max_controllers = kMaxStoredControllers + 1;
    FilePairingStore h(huge);
    CHECK_EQ(static_cast<int>(kStorageBadArgument), static_cast<int>(h.open(d.path)));
}

TEST_CASE(maximumTableRoundTrips) {
    TempDir d;
    StorageOptions o;
    o.max_controllers = kMaxStoredControllers;
    uint8_t k[32];
    {
        FilePairingStore s(o);
        REQUIRE(storageUsable(s.open(d.path)));
        for (size_t i = 0; i < kMaxStoredControllers + 5; ++i) {
            char id[140];
            snprintf(id, sizeof(id), "%03u-%s", static_cast<unsigned>(i), std::string(120, 'z').c_str());
            makeKey(static_cast<uint8_t>(i), k);
            REQUIRE(s.save(id, k));
        }
        CHECK_EQ(kMaxStoredControllers, s.size());
    }
    FilePairingStore t(o);
    REQUIRE(t.open(d.path) == kStorageLoaded);
    CHECK_EQ(kMaxStoredControllers, t.size());
    char last[140];
    snprintf(last, sizeof(last), "%03u-%s", static_cast<unsigned>(kMaxStoredControllers + 4),
                  std::string(120, 'z').c_str());
    uint8_t out[32];
    REQUIRE(t.get(last, out));
    makeKey(static_cast<uint8_t>(kMaxStoredControllers + 4), k);
    CHECK(memcmp(out, k, 32) == 0);
    CHECK(readAll(d.file(kControllersFileName)).size() <= kControllersFileMaxBytes);
}

TEST_CASE(clearRemovesEveryPairingPersistently) {
    TempDir d;
    uint8_t k[32];
    makeKey(5, k);
    {
        FilePairingStore s;
        REQUIRE(storageUsable(s.open(d.path)));
        REQUIRE(s.save("x", k));
        REQUIRE(s.save("y", k));
        pairing::PairingStore& iface = s;
        iface.clear();
        CHECK_EQ(0u, static_cast<unsigned>(s.size()));
        CHECK(s.save("z", k));
        CHECK(s.clearAll());
    }
    FilePairingStore t;
    REQUIRE(t.open(d.path) == kStorageLoaded);
    CHECK_EQ(0u, static_cast<unsigned>(t.size()));
    FilePairingStore closed;
    CHECK(!closed.clearAll());
    uint8_t out[32];
    CHECK(!closed.get("x", out));
}

TEST_CASE(posixPermissionBits) {
    TempDir d;
    CounterRng rng;
    pairing::Identity id;
    REQUIRE(loadOrCreateIdentity(d.path, rng, id) == kStorageCreated);
    FilePairingStore s;
    REQUIRE(storageUsable(s.open(d.path)));
    unsigned mode = 0;
    if (!posixMode(d.path, mode)) {
        std::printf("  [SKIP] POSIX permission bits not applicable on this OS\n");
        return;
    }
    CHECK_EQ(0700u, mode);
    REQUIRE(posixMode(d.file(kIdentityFileName), mode));
    CHECK_EQ(0600u, mode);
    REQUIRE(posixMode(d.file(kControllersFileName), mode));
    CHECK_EQ(0600u, mode);
}

int main(int argc, char** argv) {
    std::string dir = ".";
    if (argc > 0 && argv[0] != NULL) {
        const std::string self = argv[0];
        const size_t pos = self.find_last_of("/\\");
        if (pos != std::string::npos) {
            dir = self.substr(0, pos);
        }
    }
    g_base = joinPath(dir, "tmp_platform_storage");
    if (!ensurePrivateDirectory(g_base)) {
        std::printf("cannot create %s\n", g_base.c_str());
        return 1;
    }
    setLogSink(&quietLog, NULL);  // keep test output to the PASS/FAIL lines
    const int rc = test_support::runAll("test_platform_storage");
    removeDirectory(g_base);
    return rc;
}
