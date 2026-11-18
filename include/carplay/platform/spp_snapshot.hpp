#ifndef CARPLAY_PLATFORM_SPP_SNAPSHOT_HPP
#define CARPLAY_PLATFORM_SPP_SNAPSHOT_HPP

// Derived from EntryNav2-Android-Auto 0.12.0 platform/evo_spp_snapshot.hpp,
// platform/evo_spp_snapshot.cpp, platform/spp_baseline.hpp, and
// platform/alps_spp_codec.cpp, PolyForm Noncommercial License 1.0.0
//
// Read-only observation of BMW's proprietary ALPS Bluetooth library
// (`libevo_btappl.so`) via its exported `.dynsym` tables (`app`, `spp_info`,
// `spp_connected`), GOT relocation validation, `/proc/<pid>/mem` double-reads,
// and CarPlay SPP slot selection safety policy (slots 0, 1, 5).

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/platform/elf_symbols.hpp"
#include "carplay/sdp_record.hpp"

namespace carplay {
namespace platform {

// Verified ALPS library table sizes and slot indices from
// EntryNav2-Android-Auto-0.12.0/platform/evo_spp_snapshot.cpp & spp_baseline.hpp.
static const char kAlpsLibraryFilename[] = "libevo_btappl.so";
static const unsigned kAlpsMaxInstances = 6U;
static const uint32_t kAlpsAppSymbolSize = 15032U;
static const uint32_t kAlpsSppInfoSymbolSize = 480U;
static const uint32_t kAlpsSppConnectedSymbolSize = 36U;
static const uint32_t kAlpsAppStateOffset = 0x514U;
static const uint32_t kAlpsAppRecordOffset = 0x64cU;
static const uint32_t kAlpsAppRecordStride = 34U;
static const uint32_t kAlpsSppInfoStride = 80U;
static const uint32_t kAlpsSppConnectedStride = 6U;

static const uint8_t kAlpsBmwAppsSlot = 0U;
static const uint8_t kAlpsNativeCarPlaySlot = 1U;
static const uint8_t kAlpsSpareSlot = 5U;

// ------------------------------------------------------------------------------------------------
// UUID Payload Codecs & Known Baselines
// ------------------------------------------------------------------------------------------------

std::string sppPayloadToHex(const std::vector<uint8_t>& bytes);

/// Builds a 34-byte BtApplSppSetUuidReq payload:
///   [0x03][16B initiator UUID][0x03][16B local SDP record UUID]
std::vector<uint8_t> buildSppUuidPayload(const sdp::Uuid128& initiator_uuid,
                                         const sdp::Uuid128& record_uuid);

/// Validates a 2-entry ALPS SPP UUID payload (each entry: [type 1..3][2/4/16 bytes]).
bool validateSppUuidPayload(const std::vector<uint8_t>& payload);

/// Generic 16-bit SPP UUID pair (`01 11 01 01 11 01`) placed by `spp_instance_init`.
const std::vector<uint8_t>& genericSppUuidPair();

/// Verified iAP2/CarPlay UUID pair (`03 ...caff 03 ...cafe`).
/// verified: EntryNav2-Android-Auto-0.12.0/platform/spp_baseline.hpp,
/// tests/fixtures/spp-bmw-uuids.txt, and DiPlay-main/.../CarPlayController.kt:3239.
const std::vector<uint8_t>& carPlayIap2UuidPair();

/// Returns true if `payload` is a known safe baseline pair that may be saved and restored.
bool isSupportedSppBaseline(const std::vector<uint8_t>& payload);

// ------------------------------------------------------------------------------------------------
// ALPS Table Layout & Snapshot Decoding
// ------------------------------------------------------------------------------------------------

struct SppLayout {
    uint32_t app;
    uint32_t info;
    uint32_t connections;
    uint32_t app_got;
    uint32_t info_got;
    uint32_t connections_got;

    SppLayout()
        : app(0), info(0), connections(0),
          app_got(0), info_got(0), connections_got(0) {}
};

struct SppSlotSnapshot {
    uint32_t state;
    uint8_t transport_state;
    bool connected;
    std::vector<uint8_t> uuid_payload;
    std::vector<uint8_t> transport_uuid_payload;

    SppSlotSnapshot() : state(0), transport_state(0), connected(false) {}

    bool isIdle() const { return state == 1U && transport_state == 0U && !connected; }
    bool hasConsistentUuids() const {
        return !uuid_payload.empty() && uuid_payload == transport_uuid_payload;
    }
};

/// Validates exported ALPS symbols (`app`, `spp_info`, `spp_connected`), their
/// exact struct sizes, and non-zero `R_ARM_GLOB_DAT` GOT slots.
bool extractSppLayout(const ElfSymbols& elf, SppLayout& out, std::string* error_out = NULL);
bool extractSppLayoutFromFile(const std::string& path, SppLayout& out, std::string* error_out = NULL);

/// Pure decoder for one SPP instance slot (`0..5`) from raw table slices.
bool decodeSppSlotSnapshot(uint32_t state,
                           const uint8_t record[34],
                           const uint8_t info[80],
                           const uint8_t connected[6],
                           SppSlotSnapshot& out,
                           bool allow_split = false);

/// Parses field 22 (process start time in clock ticks) from a `/proc/<pid>/stat` line.
std::string parseProcStatStartTicks(const std::string& stat_line);

// ------------------------------------------------------------------------------------------------
// Memory Reader Backend & SppSnapshotReader
// ------------------------------------------------------------------------------------------------

struct SppProcessTarget {
    int pid;
    uint32_t base_address;
    SppLayout layout;
    std::string identity;

    SppProcessTarget() : pid(0), base_address(0) {}
};

class SppMemoryBackend {
public:
    virtual ~SppMemoryBackend() {}

    virtual bool openProcess(SppProcessTarget& target_out, std::string* error_out) = 0;
    virtual void closeProcess() = 0;
    virtual bool isOpen() const = 0;
    virtual bool readStartIdentity(int pid, std::string& identity_out) = 0;
    virtual bool readBytes(uint32_t address, void* out, size_t len) = 0;
    virtual void sleepMs(uint32_t ms) = 0;
};

/// Real read-only `/proc/<pid>/{maps,root,stat,mem}` implementation.
class ProcSppMemoryBackend : public SppMemoryBackend {
public:
    explicit ProcSppMemoryBackend(const std::string& proc_root = "/proc");
    virtual ~ProcSppMemoryBackend();

    virtual bool openProcess(SppProcessTarget& target_out, std::string* error_out);
    virtual void closeProcess();
    virtual bool isOpen() const { return mem_fd_ >= 0; }
    virtual bool readStartIdentity(int pid, std::string& identity_out);
    virtual bool readBytes(uint32_t address, void* out, size_t len);
    virtual void sleepMs(uint32_t ms);

private:
    ProcSppMemoryBackend(const ProcSppMemoryBackend&) = delete;
    ProcSppMemoryBackend& operator=(const ProcSppMemoryBackend&) = delete;

    std::string proc_root_;
    int mem_fd_;
};

class SppSnapshotReader {
public:
    /// `backend` is optional; if NULL an internal `ProcSppMemoryBackend` is used.
    explicit SppSnapshotReader(SppMemoryBackend* backend = NULL,
                               uint32_t double_read_delay_ms = 20U);
    ~SppSnapshotReader();

    bool open();
    void close();
    bool isOpen() const { return open_; }

    /// Performs a double-read separated by `double_read_delay_ms` and verifies
    /// process start-ticks identity and state stability.
    bool read(unsigned instance, SppSlotSnapshot& out, bool allow_split = false);

    bool checkProcessIdentity() const;
    int pid() const { return open_ ? target_.pid : 0; }
    const std::string& identity() const { return target_.identity; }
    const SppLayout& layout() const { return target_.layout; }
    const std::string& error() const { return error_; }

private:
    SppSnapshotReader(const SppSnapshotReader&) = delete;
    SppSnapshotReader& operator=(const SppSnapshotReader&) = delete;

    bool readOnce(unsigned instance, SppSlotSnapshot& out, bool allow_split);

    ProcSppMemoryBackend default_backend_;
    SppMemoryBackend* backend_;
    uint32_t double_read_delay_ms_;
    SppProcessTarget target_;
    bool open_;
    std::string error_;
};

// ------------------------------------------------------------------------------------------------
// CarPlay Slot Selection Policy (Slots 1 -> 5 -> Protected 0)
// ------------------------------------------------------------------------------------------------

enum CarPlaySlotDecision {
    kSlotUseNative1 = 0,       // Native CarPlay slot 1 is idle with iAP2 UUID; use directly, never mutate/restore
    kSlotBorrow5 = 1,          // Spare slot 5 is idle with generic UUID; borrow, verify, restore on stop
    kSlotBorrow0 = 2,          // Fallback slot 0 when allow_slot0_fallback == true; borrow, verify, restore on stop
    kSlotRefuseBusy = 3,       // Native slot 1 (carrying iAP2) or slot 5 is busy/connected/already in use
    kSlotRefuseProtected = 4,  // Slot 5 unavailable and slot 0 (My BMW / BMW Apps) fallback refused
    kSlotRefuseError = 5       // Reader invalid/closed or table validation error
};

struct CarPlaySlotPolicy {
    /// MUST stay false by default so BMW Apps / My BMW on slot 0 is never broken.
    bool allow_slot0_fallback;
    std::vector<uint8_t> target_uuid_pair;

    CarPlaySlotPolicy()
        : allow_slot0_fallback(false),
          target_uuid_pair(carPlayIap2UuidPair()) {}
};

struct CarPlaySlotSelection {
    CarPlaySlotDecision decision;
    uint8_t slot;
    bool requires_configure;
    bool requires_restore;
    SppSlotSnapshot snapshot;
    std::string reason;

    CarPlaySlotSelection()
        : decision(kSlotRefuseError),
          slot(0),
          requires_configure(false),
          requires_restore(false) {}

    bool isUsable() const {
        return decision == kSlotUseNative1 ||
               decision == kSlotBorrow5 ||
               decision == kSlotBorrow0;
    }
};

/// Pure slot selection evaluator for pre-decoded snapshots of slots 1, 5, and 0.
CarPlaySlotSelection evaluateCarPlaySppSlot(bool slot1_ok,
                                            const SppSlotSnapshot& slot1,
                                            bool slot5_ok,
                                            const SppSlotSnapshot& slot5,
                                            bool slot0_ok,
                                            const SppSlotSnapshot& slot0,
                                            const CarPlaySlotPolicy& policy = CarPlaySlotPolicy());

/// Evaluates an open `SppSnapshotReader` using strict + split-detection reads
/// across slots 1, 5, and (only if explicitly enabled) 0.
CarPlaySlotSelection selectCarPlaySppSlot(SppSnapshotReader& reader,
                                          const CarPlaySlotPolicy& policy = CarPlaySlotPolicy());

const char* carPlaySlotDecisionName(CarPlaySlotDecision decision);

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_SPP_SNAPSHOT_HPP
