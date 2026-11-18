// Derived from EntryNav2-Android-Auto 0.12.0 platform/evo_spp_snapshot.cpp,
// platform/spp_baseline.hpp, and platform/alps_spp_codec.cpp, PolyForm Noncommercial License 1.0.0

#ifndef _WIN32
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#endif

#include "carplay/platform/spp_snapshot.hpp"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fstream>
#include <sstream>

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

namespace carplay {
namespace platform {

namespace {

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

bool readU32LeBytes(const uint8_t* p, uint32_t& out) {
    out = static_cast<uint32_t>(p[0]) |
          (static_cast<uint32_t>(p[1]) << 8) |
          (static_cast<uint32_t>(p[2]) << 16) |
          (static_cast<uint32_t>(p[3]) << 24);
    return true;
}

bool containsTargetUuid(const SppSlotSnapshot& snap, const std::vector<uint8_t>& target) {
    return !target.empty() &&
           (snap.uuid_payload == target || snap.transport_uuid_payload == target);
}

bool readSlotStrictOrSplit(SppSnapshotReader& reader,
                           unsigned instance,
                           const std::vector<uint8_t>& target_uuid,
                           SppSlotSnapshot& out,
                           bool& ok_out) {
    ok_out = false;
    out = SppSlotSnapshot();
    if (reader.read(instance, out, false)) {
        ok_out = true;
        return true;
    }
    SppSlotSnapshot split;
    if (reader.read(instance, split, true) && containsTargetUuid(split, target_uuid)) {
        out = split;
        ok_out = true;
        return true;
    }
    return false;
}

}  // namespace

// ------------------------------------------------------------------------------------------------
// UUID Payload Codecs & Baselines
// ------------------------------------------------------------------------------------------------

std::string sppPayloadToHex(const std::vector<uint8_t>& bytes) {
    static const char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (size_t i = 0; i < bytes.size(); ++i) {
        out.push_back(kDigits[(bytes[i] >> 4) & 0x0fU]);
        out.push_back(kDigits[bytes[i] & 0x0fU]);
    }
    return out;
}

std::vector<uint8_t> buildSppUuidPayload(const sdp::Uuid128& initiator_uuid,
                                         const sdp::Uuid128& record_uuid) {
    std::vector<uint8_t> out;
    out.reserve(34U);
    out.push_back(0x03U);
    out.insert(out.end(), initiator_uuid.bytes, initiator_uuid.bytes + 16);
    out.push_back(0x03U);
    out.insert(out.end(), record_uuid.bytes, record_uuid.bytes + 16);
    return out;
}

bool validateSppUuidPayload(const std::vector<uint8_t>& payload) {
    static const size_t kTypeLengths[4] = {0U, 2U, 4U, 16U};
    size_t pos = 0U;
    for (int i = 0; i < 2; ++i) {
        if (pos >= payload.size()) {
            return false;
        }
        const uint8_t kind = payload[pos];
        if (kind < 1U || kind > 3U) {
            return false;
        }
        const size_t uuid_len = kTypeLengths[kind];
        if (uuid_len > payload.size() - pos - 1U) {
            return false;
        }
        pos += 1U + uuid_len;
    }
    return pos == payload.size();
}

const std::vector<uint8_t>& genericSppUuidPair() {
    static const uint8_t kRaw[6] = {0x01U, 0x11U, 0x01U, 0x01U, 0x11U, 0x01U};
    static const std::vector<uint8_t> kGeneric(kRaw, kRaw + sizeof(kRaw));
    return kGeneric;
}

const std::vector<uint8_t>& carPlayIap2UuidPair() {
    static const std::vector<uint8_t> kCarPlay = buildSppUuidPayload(
        sdp::defaultAppleIapDeviceUuid128(),
        sdp::defaultIap2AccessoryUuid128());
    return kCarPlay;
}

bool isSupportedSppBaseline(const std::vector<uint8_t>& payload) {
    return payload == genericSppUuidPair() || payload == carPlayIap2UuidPair();
}

// ------------------------------------------------------------------------------------------------
// Layout Extraction & Pure Snapshot Decoder
// ------------------------------------------------------------------------------------------------

bool extractSppLayout(const ElfSymbols& elf, SppLayout& out, std::string* error_out) {
    out = SppLayout();
    if (!elf.isLoaded()) {
        setError(error_out, "ALPS library unreadable or invalid ELF32 ARM image");
        return false;
    }
    ElfSymbolInfo app_sym;
    ElfSymbolInfo info_sym;
    ElfSymbolInfo conn_sym;
    if (!elf.findSymbol("app", app_sym) ||
        !elf.findSymbol("spp_info", info_sym) ||
        !elf.findSymbol("spp_connected", conn_sym) ||
        app_sym.got == 0 || info_sym.got == 0 || conn_sym.got == 0) {
        setError(error_out, "ALPS tables missing from library");
        return false;
    }
    if (app_sym.size != kAlpsAppSymbolSize ||
        info_sym.size != kAlpsSppInfoSymbolSize ||
        conn_sym.size != kAlpsSppConnectedSymbolSize) {
        char detail[128];
        snprintf(detail, sizeof(detail),
                 "unknown ALPS structure (sizes %u/%u/%u)",
                 static_cast<unsigned>(app_sym.size),
                 static_cast<unsigned>(info_sym.size),
                 static_cast<unsigned>(conn_sym.size));
        setError(error_out, detail);
        return false;
    }
    out.app = app_sym.value;
    out.info = info_sym.value;
    out.connections = conn_sym.value;
    out.app_got = app_sym.got;
    out.info_got = info_sym.got;
    out.connections_got = conn_sym.got;
    return true;
}

bool extractSppLayoutFromFile(const std::string& path, SppLayout& out, std::string* error_out) {
    ElfSymbols elf;
    if (!elf.loadFromFile(path)) {
        setError(error_out, "ALPS library unreadable");
        return false;
    }
    return extractSppLayout(elf, out, error_out);
}

bool decodeSppSlotSnapshot(uint32_t state,
                           const uint8_t record[34],
                           const uint8_t info[80],
                           const uint8_t connected[6],
                           SppSlotSnapshot& out,
                           bool allow_split) {
    static const unsigned kLength[4] = {0U, 2U, 4U, 16U};
    static const unsigned kTags[4] = {0U, 1U, 2U, 4U};

    out = SppSlotSnapshot();
    if (record == NULL || info == NULL || connected == NULL) {
        return false;
    }
    if (state > 2U || record[32] < 1U || record[32] > 3U || record[33] < 1U || record[33] > 3U) {
        return false;
    }

    SppSlotSnapshot parsed;
    for (unsigned i = 0; i < 2U; ++i) {
        const unsigned type = record[32U + i];
        const unsigned data_offset = i != 0U ? 56U : 39U;
        const unsigned tag_offset = i != 0U ? 55U : 38U;
        const uint8_t raw_tag = info[tag_offset];
        const unsigned low_type = (raw_tag == 1U) ? 1U : (raw_tag == 2U) ? 2U : (raw_tag == 4U) ? 3U : 0U;
        if (low_type == 0U) {
            return false;
        }
        if (!allow_split &&
            (raw_tag != kTags[type] ||
             memcmp(record + 16U * i, info + data_offset, kLength[type]) != 0)) {
            return false;
        }
        parsed.uuid_payload.push_back(static_cast<uint8_t>(type));
        parsed.uuid_payload.insert(parsed.uuid_payload.end(),
                                   record + 16U * i,
                                   record + 16U * i + kLength[type]);
        parsed.transport_uuid_payload.push_back(static_cast<uint8_t>(low_type));
        parsed.transport_uuid_payload.insert(parsed.transport_uuid_payload.end(),
                                             info + data_offset,
                                             info + data_offset + kLength[low_type]);
    }
    parsed.state = state;
    parsed.transport_state = info[4];
    for (unsigned i = 0; i < 6U; ++i) {
        if (connected[i] != 0U) {
            parsed.connected = true;
            break;
        }
    }
    out = parsed;
    return true;
}

std::string parseProcStatStartTicks(const std::string& stat_line) {
    const size_t rparen = stat_line.rfind(')');
    if (rparen == std::string::npos) {
        return std::string();
    }
    std::istringstream fields(stat_line.substr(rparen + 1U));
    std::string value;
    for (int i = 3; i <= 22; ++i) {
        if (!(fields >> value)) {
            return std::string();
        }
    }
    return value;
}

// ------------------------------------------------------------------------------------------------
// ProcSppMemoryBackend
// ------------------------------------------------------------------------------------------------

ProcSppMemoryBackend::ProcSppMemoryBackend(const std::string& proc_root)
    : proc_root_(proc_root.empty() ? std::string("/proc") : proc_root),
      mem_fd_(-1) {}

ProcSppMemoryBackend::~ProcSppMemoryBackend() {
    closeProcess();
}

void ProcSppMemoryBackend::closeProcess() {
#ifndef _WIN32
    if (mem_fd_ >= 0) {
        ::close(mem_fd_);
        mem_fd_ = -1;
    }
#else
    mem_fd_ = -1;
#endif
}

bool ProcSppMemoryBackend::readStartIdentity(int pid, std::string& identity_out) {
    identity_out.clear();
#ifdef _WIN32
    (void)pid;
    return false;
#else
    if (pid <= 0) {
        return false;
    }
    char path[128];
    snprintf(path, sizeof(path), "%s/%d/stat", proc_root_.c_str(), pid);
    std::ifstream input(path);
    std::string line;
    if (!std::getline(input, line)) {
        return false;
    }
    identity_out = parseProcStatStartTicks(line);
    return !identity_out.empty();
#endif
}

bool ProcSppMemoryBackend::openProcess(SppProcessTarget& target_out, std::string* error_out) {
    closeProcess();
    target_out = SppProcessTarget();
#ifdef _WIN32
    setError(error_out, "/proc memory reader is unsupported on Windows");
    return false;
#else
    DIR* proc = ::opendir(proc_root_.c_str());
    if (proc == NULL) {
        setError(error_out, "cannot open " + proc_root_);
        return false;
    }

    std::string rejected;
    SppProcessTarget selected;
    std::string selected_prefix;
    unsigned matches = 0U;

    struct dirent* item = NULL;
    while ((item = ::readdir(proc)) != NULL) {
        if (item->d_name[0] == '\0') {
            continue;
        }
        char* end = NULL;
        const long pid = strtol(item->d_name, &end, 10);
        if (end == NULL || *end != '\0' || pid <= 0 || pid > INT_MAX) {
            continue;
        }

        const std::string prefix = proc_root_ + "/" + item->d_name;
        std::ifstream maps((prefix + "/maps").c_str());
        std::string line;
        while (std::getline(maps, line)) {
            unsigned long begin = 0;
            unsigned long finish = 0;
            unsigned long offset = 0;
            unsigned long inode = 0;
            unsigned major = 0;
            unsigned minor = 0;
            char perms[8];
            int used = 0;
            if (sscanf(line.c_str(), "%lx-%lx %4s %lx %x:%x %lu %n",
                       &begin, &finish, perms, &offset, &major, &minor, &inode, &used) != 7 ||
                offset != 0 || used <= 0 || static_cast<size_t>(used) >= line.size()) {
                continue;
            }
            const std::string map_path = line.substr(static_cast<size_t>(used));
            const size_t slash = map_path.rfind('/');
            if (slash == std::string::npos ||
                map_path.substr(slash + 1U) != kAlpsLibraryFilename) {
                continue;
            }
            if (begin > 0xffffffffUL) {
                continue;
            }
            SppLayout layout;
            std::string why;
            if (!extractSppLayoutFromFile(prefix + "/root" + map_path, layout, &why)) {
                rejected = why;
                continue;
            }
            ++matches;
            selected.pid = static_cast<int>(pid);
            selected.base_address = static_cast<uint32_t>(begin);
            selected.layout = layout;
            selected_prefix = prefix;
        }
    }
    ::closedir(proc);

    if (matches != 1U) {
        if (matches == 0U && !rejected.empty()) {
            setError(error_out, rejected);
        } else {
            setError(error_out, "ALPS library not found or not unique");
        }
        return false;
    }

    if (!readStartIdentity(selected.pid, selected.identity)) {
        setError(error_out, "cannot read ALPS process start identity");
        return false;
    }

    // Read-only access only: never attach ptrace or modify a BMW process.
    const int fd = ::open((selected_prefix + "/mem").c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        setError(error_out, "reading ALPS in /proc refused: no Bluetooth change allowed");
        return false;
    }

    mem_fd_ = fd;
    target_out = selected;
    return true;
#endif
}

bool ProcSppMemoryBackend::readBytes(uint32_t address, void* out, size_t len) {
#ifdef _WIN32
    (void)address;
    (void)out;
    (void)len;
    return false;
#else
    if (mem_fd_ < 0 || out == NULL) {
        return false;
    }
    if (len == 0U) {
        return true;
    }
    const uint64_t start = static_cast<uint64_t>(address);
    if (start > 0x100000000ULL || static_cast<uint64_t>(len) > 0x100000000ULL - start) {
        return false;
    }
    return ::pread64(mem_fd_, out, len, static_cast<off64_t>(start)) == static_cast<ssize_t>(len);
#endif
}

void ProcSppMemoryBackend::sleepMs(uint32_t ms) {
    if (ms == 0U) {
        return;
    }
#ifdef _WIN32
    ::Sleep(ms);
#else
    ::usleep(static_cast<useconds_t>(ms) * 1000U);
#endif
}

// ------------------------------------------------------------------------------------------------
// SppSnapshotReader
// ------------------------------------------------------------------------------------------------

SppSnapshotReader::SppSnapshotReader(SppMemoryBackend* backend, uint32_t double_read_delay_ms)
    : backend_(backend != NULL ? backend : &default_backend_),
      double_read_delay_ms_(double_read_delay_ms),
      open_(false) {}

SppSnapshotReader::~SppSnapshotReader() {
    close();
}

void SppSnapshotReader::close() {
    if (open_ || backend_->isOpen()) {
        backend_->closeProcess();
    }
    open_ = false;
    target_ = SppProcessTarget();
}

bool SppSnapshotReader::open() {
    if (open_) {
        error_ = "reader already open";
        return false;
    }

    SppProcessTarget tgt;
    std::string err;
    if (!backend_->openProcess(tgt, &err)) {
        error_ = err.empty() ? "cannot open ALPS process" : err;
        return false;
    }

    uint8_t got_a[4];
    uint8_t got_b[4];
    uint8_t got_c[4];
    uint32_t a = 0;
    uint32_t b = 0;
    uint32_t c = 0;
    const uint64_t app_got_addr = static_cast<uint64_t>(tgt.base_address) + tgt.layout.app_got;
    const uint64_t info_got_addr = static_cast<uint64_t>(tgt.base_address) + tgt.layout.info_got;
    const uint64_t conn_got_addr = static_cast<uint64_t>(tgt.base_address) + tgt.layout.connections_got;

    if (app_got_addr > 0xffffffffULL || info_got_addr > 0xffffffffULL || conn_got_addr > 0xffffffffULL ||
        !backend_->readBytes(static_cast<uint32_t>(app_got_addr), got_a, 4U) ||
        !backend_->readBytes(static_cast<uint32_t>(info_got_addr), got_b, 4U) ||
        !backend_->readBytes(static_cast<uint32_t>(conn_got_addr), got_c, 4U)) {
        backend_->closeProcess();
        error_ = "incompatible ALPS layout (relocations unreadable)";
        return false;
    }

    readU32LeBytes(got_a, a);
    readU32LeBytes(got_b, b);
    readU32LeBytes(got_c, c);
    if (a != tgt.base_address + tgt.layout.app ||
        b != tgt.base_address + tgt.layout.info ||
        c != tgt.base_address + tgt.layout.connections) {
        backend_->closeProcess();
        error_ = "incompatible ALPS layout (relocations)";
        return false;
    }

    target_ = tgt;
    open_ = true;
    error_.clear();
    return true;
}

bool SppSnapshotReader::checkProcessIdentity() const {
    if (!open_ || target_.identity.empty() || target_.pid <= 0) {
        return false;
    }
    std::string current_id;
    return backend_->readStartIdentity(target_.pid, current_id) && current_id == target_.identity;
}

bool SppSnapshotReader::readOnce(unsigned instance, SppSlotSnapshot& out, bool allow_split) {
    const uint64_t state_addr = static_cast<uint64_t>(target_.base_address) +
                                target_.layout.app + kAlpsAppStateOffset + instance * 4U;
    const uint64_t record_addr = static_cast<uint64_t>(target_.base_address) +
                                 target_.layout.app + kAlpsAppRecordOffset + instance * kAlpsAppRecordStride;
    const uint64_t info_addr = static_cast<uint64_t>(target_.base_address) +
                               target_.layout.info + instance * kAlpsSppInfoStride;
    const uint64_t conn_addr = static_cast<uint64_t>(target_.base_address) +
                               target_.layout.connections + instance * kAlpsSppConnectedStride;

    uint8_t state_raw[4];
    uint8_t record[34];
    uint8_t info[80];
    uint8_t connected[6];

    if (state_addr > 0xffffffffULL || record_addr > 0xffffffffULL ||
        info_addr > 0xffffffffULL || conn_addr > 0xffffffffULL ||
        !backend_->readBytes(static_cast<uint32_t>(state_addr), state_raw, 4U) ||
        !backend_->readBytes(static_cast<uint32_t>(record_addr), record, 34U) ||
        !backend_->readBytes(static_cast<uint32_t>(info_addr), info, 80U) ||
        !backend_->readBytes(static_cast<uint32_t>(conn_addr), connected, 6U)) {
        error_ = "incomplete read of the ALPS tables";
        return false;
    }

    uint32_t state = 0;
    readU32LeBytes(state_raw, state);
    if (!decodeSppSlotSnapshot(state, record, info, connected, out, allow_split)) {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "SPP state or UUID copies incompatible (state=%u transport=%u types=%u/%u tags=%u/%u)",
                 static_cast<unsigned>(state),
                 static_cast<unsigned>(info[4]),
                 static_cast<unsigned>(record[32]),
                 static_cast<unsigned>(record[33]),
                 static_cast<unsigned>(info[38]),
                 static_cast<unsigned>(info[55]));
        error_ = detail;
        return false;
    }
    return true;
}

bool SppSnapshotReader::read(unsigned instance, SppSlotSnapshot& out, bool allow_split) {
    out = SppSlotSnapshot();
    if (!open_ || instance >= kAlpsMaxInstances || !checkProcessIdentity()) {
        error_ = "invalid instance or ALPS process replaced";
        return false;
    }

    SppSlotSnapshot first;
    SppSlotSnapshot second;
    for (int round = 0; round < 2; ++round) {
        if (!readOnce(instance, round == 0 ? first : second, allow_split)) {
            return false;
        }
        if (round == 0 && double_read_delay_ms_ > 0U) {
            backend_->sleepMs(double_read_delay_ms_);
        }
    }

    if (first.state != second.state ||
        first.transport_state != second.transport_state ||
        first.connected != second.connected ||
        first.uuid_payload != second.uuid_payload ||
        first.transport_uuid_payload != second.transport_uuid_payload) {
        error_ = "SPP state changing";
        return false;
    }

    out = second;
    error_.clear();
    return true;
}

// ------------------------------------------------------------------------------------------------
// CarPlay Slot Selection Policy
// ------------------------------------------------------------------------------------------------

CarPlaySlotSelection evaluateCarPlaySppSlot(bool slot1_ok,
                                            const SppSlotSnapshot& slot1,
                                            bool slot5_ok,
                                            const SppSlotSnapshot& slot5,
                                            bool slot0_ok,
                                            const SppSlotSnapshot& slot0,
                                            const CarPlaySlotPolicy& policy) {
    CarPlaySlotSelection sel;
    const std::vector<uint8_t>& target = policy.target_uuid_pair;
    if (!validateSppUuidPayload(target)) {
        sel.decision = kSlotRefuseError;
        sel.reason = "invalid target UUID payload in CarPlaySlotPolicy";
        return sel;
    }

    // 1. Native BMW CarPlay slot 1: use directly (no reconfig, no restore) when idle and matching iAP2 UUID.
    if (slot1_ok) {
        const bool slot1_has_target = containsTargetUuid(slot1, target);
        if (slot1_has_target) {
            if (slot1.hasConsistentUuids() && slot1.isIdle()) {
                sel.decision = kSlotUseNative1;
                sel.slot = kAlpsNativeCarPlaySlot;
                sel.requires_configure = false;
                sel.requires_restore = false;
                sel.snapshot = slot1;
                sel.reason = "native CarPlay slot 1 already configured with iAP2 UUID";
                return sel;
            }
            sel.decision = kSlotRefuseBusy;
            sel.slot = kAlpsNativeCarPlaySlot;
            sel.snapshot = slot1;
            sel.reason = "native CarPlay slot 1 carries iAP2 UUID but is busy or split; refusing double advertisement";
            return sel;
        }
    }

    // 2. Spare slot 5: borrow only when started (state != 0), idle, consistent, and carrying generic UUID.
    if (slot5_ok && slot5.state != 0U) {
        if (containsTargetUuid(slot5, target) ||
            slot5.connected ||
            slot5.state == 2U ||
            slot5.transport_state != 0U) {
            sel.decision = kSlotRefuseBusy;
            sel.slot = kAlpsSpareSlot;
            sel.snapshot = slot5;
            sel.reason = "spare slot 5 is connected, busy, or already carrying iAP2 UUID";
            return sel;
        }
        if (slot5.isIdle() &&
            slot5.hasConsistentUuids() &&
            slot5.uuid_payload == genericSppUuidPair()) {
            sel.decision = kSlotBorrow5;
            sel.slot = kAlpsSpareSlot;
            sel.requires_configure = true;
            sel.requires_restore = true;
            sel.snapshot = slot5;
            sel.reason = "borrowing spare slot 5 (generic SPP idle); slot 0 (BMW Apps) left untouched";
            return sel;
        }
    }

    // 3. Slot 0 fallback policy: NEVER touch BMW Apps / My BMW slot 0 unless explicitly opted in.
    if (!policy.allow_slot0_fallback) {
        sel.decision = kSlotRefuseProtected;
        sel.slot = kAlpsBmwAppsSlot;
        sel.reason = "slot 1 not native CarPlay and slot 5 unavailable; slot 0 (BMW Apps / My BMW) protected";
        return sel;
    }

    if (!slot0_ok) {
        sel.decision = kSlotRefuseError;
        sel.slot = kAlpsBmwAppsSlot;
        sel.reason = "slot 0 unreadable for explicit fallback";
        return sel;
    }
    if (!slot0.isIdle()) {
        sel.decision = kSlotRefuseBusy;
        sel.slot = kAlpsBmwAppsSlot;
        sel.snapshot = slot0;
        sel.reason = "slot 0 busy or changing";
        return sel;
    }
    if (!slot0.hasConsistentUuids() || !isSupportedSppBaseline(slot0.uuid_payload)) {
        sel.decision = kSlotRefuseProtected;
        sel.slot = kAlpsBmwAppsSlot;
        sel.snapshot = slot0;
        sel.reason = "slot 0 holds unknown UUID pair; refusing explicit fallback";
        return sel;
    }

    sel.decision = kSlotBorrow0;
    sel.slot = kAlpsBmwAppsSlot;
    sel.requires_configure = true;
    sel.requires_restore = true;
    sel.snapshot = slot0;
    sel.reason = "borrowing slot 0 via explicit fallback policy";
    return sel;
}

CarPlaySlotSelection selectCarPlaySppSlot(SppSnapshotReader& reader, const CarPlaySlotPolicy& policy) {
    if (!reader.isOpen()) {
        CarPlaySlotSelection sel;
        sel.decision = kSlotRefuseError;
        sel.reason = reader.error().empty() ? "SppSnapshotReader is not open" : reader.error();
        return sel;
    }

    SppSlotSnapshot slot1;
    bool slot1_ok = false;
    readSlotStrictOrSplit(reader, kAlpsNativeCarPlaySlot, policy.target_uuid_pair, slot1, slot1_ok);

    SppSlotSnapshot slot5;
    bool slot5_ok = false;
    readSlotStrictOrSplit(reader, kAlpsSpareSlot, policy.target_uuid_pair, slot5, slot5_ok);

    SppSlotSnapshot slot0;
    bool slot0_ok = false;
    if (policy.allow_slot0_fallback) {
        slot0_ok = reader.read(kAlpsBmwAppsSlot, slot0, false);
    }

    return evaluateCarPlaySppSlot(slot1_ok, slot1, slot5_ok, slot5, slot0_ok, slot0, policy);
}

const char* carPlaySlotDecisionName(CarPlaySlotDecision decision) {
    switch (decision) {
        case kSlotUseNative1: return "use_native_slot1";
        case kSlotBorrow5: return "borrow_slot5";
        case kSlotBorrow0: return "borrow_slot0";
        case kSlotRefuseBusy: return "refuse_busy";
        case kSlotRefuseProtected: return "refuse_protected";
        case kSlotRefuseError: return "refuse_error";
    }
    return "unknown";
}

}  // namespace platform
}  // namespace carplay
