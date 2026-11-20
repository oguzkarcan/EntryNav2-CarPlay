#include "test_support.hpp"

#include <string.h>

#include <deque>
#include <map>
#include <string>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "carplay/iap2_link.hpp"
#include "carplay/platform/alps_spp.hpp"
#include "carplay/platform/bt_rfcomm.hpp"
#include "carplay/platform/bt_transport.hpp"
#include "carplay/platform/elf_symbols.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/spp_snapshot.hpp"
#include "carplay/platform/thread.hpp"
#include "carplay/platform/wifi_link.hpp"
#include "carplay/sdp_record.hpp"

namespace {

using carplay::platform::AdvertisementSchedule;
using carplay::platform::AlpsBtTransport;
using carplay::platform::AlpsSppLink;
using carplay::platform::AlpsSppLinkListener;
using carplay::platform::AlpsSppManager;
using carplay::platform::AlpsSppManagerConfig;
using carplay::platform::AlpsSppManagerListener;
using carplay::platform::BtAddr;
using carplay::platform::BtBackendKind;
using carplay::platform::BtSocketOps;
using carplay::platform::BtTransport;
using carplay::platform::BtTransportByteSink;
using carplay::platform::BtTransportCapability;
using carplay::platform::BtTransportListener;
using carplay::platform::BtTransportProbePaths;
using carplay::platform::CarPlaySlotDecision;
using carplay::platform::CarPlaySlotPolicy;
using carplay::platform::CarPlaySlotSelection;
using carplay::platform::DbusAlpsSppLink;
using carplay::platform::DbusApi;
using carplay::platform::DbusConnection;
using carplay::platform::DbusErrorRaw;
using carplay::platform::DbusFreeFn;
using carplay::platform::DbusHandleMessageFn;
using carplay::platform::DbusMessage;
using carplay::platform::DbusMessageIterRaw;
using carplay::platform::ElfSymbolInfo;
using carplay::platform::ElfSymbols;
using carplay::platform::IoStatus;
using carplay::platform::LockGuard;
using carplay::platform::Mutex;
using carplay::platform::Reactor;
using carplay::platform::RfcommBtTransport;
using carplay::platform::RfcommBtTransportConfig;
using carplay::platform::SocketHandle;
using carplay::platform::SppLayout;
using carplay::platform::SppMemoryBackend;
using carplay::platform::SppProcessTarget;
using carplay::platform::SppSlotSnapshot;
using carplay::platform::SppSnapshotReader;
using carplay::platform::dbus_bool_raw;
using carplay::platform::kAlpsAppRecordOffset;
using carplay::platform::kAlpsAppRecordStride;
using carplay::platform::kAlpsAppStateOffset;
using carplay::platform::kAlpsAppSymbolSize;
using carplay::platform::kAlpsBmwAppsSlot;
using carplay::platform::kAlpsConfigDataInterface;
using carplay::platform::kAlpsDbusDmInterface;
using carplay::platform::kAlpsDbusPath;
using carplay::platform::kAlpsDbusService;
using carplay::platform::kAlpsDbusSppInterface;
using carplay::platform::kAlpsMaxInstances;
using carplay::platform::kAlpsNativeCarPlaySlot;
using carplay::platform::kAlpsSpareSlot;
using carplay::platform::kAlpsSppConnectedStride;
using carplay::platform::kAlpsSppConnectedSymbolSize;
using carplay::platform::kAlpsSppInfoStride;
using carplay::platform::kAlpsSppInfoSymbolSize;
using carplay::platform::kBtBackendAlpsSpp;
using carplay::platform::kBtBackendNone;
using carplay::platform::kBtBackendRfcomm;
using carplay::platform::kInvalidSocket;
using carplay::platform::kIoClosed;
using carplay::platform::kIoError;
using carplay::platform::kIoOk;
using carplay::platform::kIoWouldBlock;
using carplay::platform::kSlotBorrow0;
using carplay::platform::kSlotBorrow5;
using carplay::platform::kSlotRefuseBusy;
using carplay::platform::kSlotRefuseError;
using carplay::platform::kSlotRefuseProtected;
using carplay::platform::kSlotUseNative1;

// ------------------------------------------------------------------------------------------------
// Synthetic ELF32 ARM LE Builder
// ------------------------------------------------------------------------------------------------

void pushU16Le(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xffU));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xffU));
}

void pushU32Le(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xffU));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xffU));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xffU));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xffU));
}

void writeU32Le(uint8_t* dst, uint32_t v) {
    dst[0] = static_cast<uint8_t>(v & 0xffU);
    dst[1] = static_cast<uint8_t>((v >> 8) & 0xffU);
    dst[2] = static_cast<uint8_t>((v >> 16) & 0xffU);
    dst[3] = static_cast<uint8_t>((v >> 24) & 0xffU);
}

struct SynthSymSpec {
    std::string name;
    uint32_t value;
    uint32_t size;
    uint16_t shndx;
    uint32_t got_offset;
};

std::vector<uint8_t> buildSyntheticArmElf(const std::vector<SynthSymSpec>& syms,
                                          uint16_t machine = 40U) {
    std::vector<uint8_t> dynstr;
    dynstr.push_back('\0');
    std::vector<uint32_t> name_offsets;
    for (size_t i = 0; i < syms.size(); ++i) {
        name_offsets.push_back(static_cast<uint32_t>(dynstr.size()));
        dynstr.insert(dynstr.end(), syms[i].name.begin(), syms[i].name.end());
        dynstr.push_back('\0');
    }

    std::vector<uint8_t> dynsym;
    // Symbol 0: STN_UNDEF
    for (int k = 0; k < 16; ++k) {
        dynsym.push_back(0U);
    }
    std::vector<uint8_t> reldyn;
    for (size_t i = 0; i < syms.size(); ++i) {
        pushU32Le(dynsym, name_offsets[i]);
        pushU32Le(dynsym, syms[i].value);
        pushU32Le(dynsym, syms[i].size);
        dynsym.push_back(0x11U);  // STB_GLOBAL | STT_OBJECT
        dynsym.push_back(0U);
        pushU16Le(dynsym, syms[i].shndx);
        if (syms[i].got_offset != 0U) {
            pushU32Le(reldyn, syms[i].got_offset);
            const uint32_t sym_idx = static_cast<uint32_t>(i + 1U);
            pushU32Le(reldyn, (sym_idx << 8) | 21U);  // R_ARM_GLOB_DAT = 21
        }
    }

    // Layout: [Ehdr (52)] [dynstr] [dynsym] [reldyn] [4 Shdrs (4 * 40 = 160)]
    const uint32_t dynstr_off = 52U;
    const uint32_t dynsym_off = dynstr_off + static_cast<uint32_t>(dynstr.size());
    const uint32_t reldyn_off = dynsym_off + static_cast<uint32_t>(dynsym.size());
    const uint32_t shoff = reldyn_off + static_cast<uint32_t>(reldyn.size());

    std::vector<uint8_t> elf;
    // Elf32_Ehdr
    elf.push_back(0x7fU);
    elf.push_back('E');
    elf.push_back('L');
    elf.push_back('F');
    elf.push_back(1U);  // ELFCLASS32
    elf.push_back(1U);  // ELFDATA2LSB
    elf.push_back(1U);  // EV_CURRENT
    for (int i = 7; i < 16; ++i) {
        elf.push_back(0U);
    }
    pushU16Le(elf, 3U);       // ET_DYN
    pushU16Le(elf, machine);  // EM_ARM = 40
    pushU32Le(elf, 1U);       // e_version
    pushU32Le(elf, 0U);       // e_entry
    pushU32Le(elf, 0U);       // e_phoff
    pushU32Le(elf, shoff);    // e_shoff
    pushU32Le(elf, 0x05000000U);
    pushU16Le(elf, 52U);      // e_ehsize
    pushU16Le(elf, 0U);       // e_phentsize
    pushU16Le(elf, 0U);       // e_phnum
    pushU16Le(elf, 40U);      // e_shentsize
    pushU16Le(elf, 4U);       // e_shnum
    pushU16Le(elf, 0U);       // e_shstrndx

    elf.insert(elf.end(), dynstr.begin(), dynstr.end());
    elf.insert(elf.end(), dynsym.begin(), dynsym.end());
    elf.insert(elf.end(), reldyn.begin(), reldyn.end());

    // Shdr 0: SHT_NULL
    for (int i = 0; i < 40; ++i) {
        elf.push_back(0U);
    }
    // Shdr 1: .dynstr (SHT_STRTAB = 3)
    pushU32Le(elf, 0U);
    pushU32Le(elf, 3U);
    pushU32Le(elf, 2U);
    pushU32Le(elf, dynstr_off);
    pushU32Le(elf, dynstr_off);
    pushU32Le(elf, static_cast<uint32_t>(dynstr.size()));
    pushU32Le(elf, 0U);
    pushU32Le(elf, 0U);
    pushU32Le(elf, 1U);
    pushU32Le(elf, 0U);

    // Shdr 2: .dynsym (SHT_DYNSYM = 11, sh_link = 1)
    pushU32Le(elf, 0U);
    pushU32Le(elf, 11U);
    pushU32Le(elf, 2U);
    pushU32Le(elf, dynsym_off);
    pushU32Le(elf, dynsym_off);
    pushU32Le(elf, static_cast<uint32_t>(dynsym.size()));
    pushU32Le(elf, 1U);
    pushU32Le(elf, 1U);
    pushU32Le(elf, 4U);
    pushU32Le(elf, 16U);

    // Shdr 3: .rel.dyn (SHT_REL = 9, sh_link = 2)
    pushU32Le(elf, 0U);
    pushU32Le(elf, 9U);
    pushU32Le(elf, 2U);
    pushU32Le(elf, reldyn_off);
    pushU32Le(elf, reldyn_off);
    pushU32Le(elf, static_cast<uint32_t>(reldyn.size()));
    pushU32Le(elf, 2U);
    pushU32Le(elf, 0U);
    pushU32Le(elf, 4U);
    pushU32Le(elf, 8U);

    return elf;
}

std::vector<uint8_t> buildValidAlpsElf(uint32_t app_off = 0x20000U,
                                       uint32_t info_off = 0x24000U,
                                       uint32_t conn_off = 0x25000U) {
    std::vector<SynthSymSpec> syms;
    SynthSymSpec a;
    a.name = "app";
    a.value = app_off;
    a.size = kAlpsAppSymbolSize;
    a.shndx = 1U;
    a.got_offset = 0x1000U;
    syms.push_back(a);

    SynthSymSpec i;
    i.name = "spp_info";
    i.value = info_off;
    i.size = kAlpsSppInfoSymbolSize;
    i.shndx = 1U;
    i.got_offset = 0x1004U;
    syms.push_back(i);

    SynthSymSpec c;
    c.name = "spp_connected";
    c.value = conn_off;
    c.size = kAlpsSppConnectedSymbolSize;
    c.shndx = 1U;
    c.got_offset = 0x1008U;
    syms.push_back(c);

    SynthSymSpec imp;
    imp.name = "imported_sym";
    imp.value = 0U;
    imp.size = 4U;
    imp.shndx = 0U;  // SHN_UNDEF
    imp.got_offset = 0U;
    syms.push_back(imp);

    return buildSyntheticArmElf(syms);
}

// ------------------------------------------------------------------------------------------------
// Fake /proc Memory Backend (synthesizes ALPS tables in simulated 32-bit process space)
// ------------------------------------------------------------------------------------------------

class FakeSppMemoryBackend : public SppMemoryBackend {
public:
    FakeSppMemoryBackend()
        : open_succeeds(true),
          is_open_(false),
          pid(4242),
          base_address(0x10000000U),
          identity("123456"),
          fail_next_read_count(0),
          corrupt_on_second_read(false),
          mutate_slot_on_read_n(0),
          mutate_slot_index(0),
          read_calls_(0) {
        layout.app = 0x20000U;
        layout.info = 0x24000U;
        layout.connections = 0x25000U;
        layout.app_got = 0x1000U;
        layout.info_got = 0x1004U;
        layout.connections_got = 0x1008U;
        mem_.assign(0x26000U, 0U);
        writeRelocations(true);
    }

    bool open_succeeds;
    bool is_open_;
    int pid;
    uint32_t base_address;
    SppLayout layout;
    std::string identity;
    int fail_next_read_count;
    bool corrupt_on_second_read;
    int mutate_slot_on_read_n;
    unsigned mutate_slot_index;

    void writeRelocations(bool valid) {
        const uint32_t bias = valid ? base_address : (base_address + 0x100U);
        writeMemU32(layout.app_got, bias + layout.app);
        writeMemU32(layout.info_got, bias + layout.info);
        writeMemU32(layout.connections_got, bias + layout.connections);
    }

    void writeMemU32(uint32_t rel_offset, uint32_t v) {
        writeU32Le(&mem_[rel_offset], v);
    }

    void setSlotUuid(unsigned instance,
                     uint32_t state,
                     uint8_t transport_state,
                     bool connected,
                     const std::vector<uint8_t>& record_pair,
                     const std::vector<uint8_t>& transport_pair) {
        writeMemU32(layout.app + kAlpsAppStateOffset + instance * 4U, state);
        uint8_t* rec = &mem_[layout.app + kAlpsAppRecordOffset + instance * kAlpsAppRecordStride];
        memset(rec, 0, kAlpsAppRecordStride);
        writePairToRecord(record_pair, rec);

        uint8_t* inf = &mem_[layout.info + instance * kAlpsSppInfoStride];
        memset(inf, 0, kAlpsSppInfoStride);
        inf[4] = transport_state;
        writePairToInfo(transport_pair, inf);

        uint8_t* conn = &mem_[layout.connections + instance * kAlpsSppConnectedStride];
        memset(conn, 0, kAlpsSppConnectedStride);
        conn[0] = connected ? 1U : 0U;
    }

    void setSlotUniform(unsigned instance,
                        uint32_t state,
                        uint8_t transport_state,
                        bool connected,
                        const std::vector<uint8_t>& uuid_pair) {
        setSlotUuid(instance, state, transport_state, connected, uuid_pair, uuid_pair);
    }

    void setSlotDisconnectedGeneric(unsigned instance) {
        setSlotUniform(instance, 1U, 0U, false, carplay::platform::genericSppUuidPair());
    }

    virtual bool openProcess(SppProcessTarget& target_out, std::string* error_out) {
        if (!open_succeeds) {
            if (error_out != NULL) {
                *error_out = "fake open failed";
            }
            return false;
        }
        is_open_ = true;
        target_out.pid = pid;
        target_out.base_address = base_address;
        target_out.layout = layout;
        target_out.identity = identity;
        return true;
    }

    virtual void closeProcess() { is_open_ = false; }
    virtual bool isOpen() const { return is_open_; }

    virtual bool readStartIdentity(int req_pid, std::string& identity_out) {
        if (req_pid != pid) {
            return false;
        }
        identity_out = identity;
        return true;
    }

    virtual bool readBytes(uint32_t address, void* out, size_t len) {
        if (!is_open_ || address < base_address) {
            return false;
        }
        if (fail_next_read_count > 0) {
            --fail_next_read_count;
            return false;
        }
        const uint32_t rel = address - base_address;
        if (rel >= mem_.size() || len > mem_.size() - rel) {
            return false;
        }
        ++read_calls_;
        memcpy(out, &mem_[rel], len);
        if (corrupt_on_second_read && rel >= layout.app + kAlpsAppStateOffset && len == 4U) {
            // Mutate between round 0 and round 1 of double-read.
            if (mutate_slot_on_read_n > 0) {
                --mutate_slot_on_read_n;
            } else {
                writeMemU32(layout.app + kAlpsAppStateOffset + mutate_slot_index * 4U, 2U);
                corrupt_on_second_read = false;
            }
        }
        return true;
    }

    virtual void sleepMs(uint32_t /*ms*/) {}

private:
    static void writePairToRecord(const std::vector<uint8_t>& pair, uint8_t rec[34]) {
        static const size_t kLen[4] = {0U, 2U, 4U, 16U};
        size_t pos = 0U;
        for (unsigned i = 0; i < 2U; ++i) {
            if (pos >= pair.size()) {
                return;
            }
            const uint8_t kind = pair[pos++];
            if (kind < 1U || kind > 3U || kLen[kind] > pair.size() - pos) {
                return;
            }
            rec[32U + i] = kind;
            memcpy(rec + 16U * i, &pair[pos], kLen[kind]);
            pos += kLen[kind];
        }
    }

    static void writePairToInfo(const std::vector<uint8_t>& pair, uint8_t inf[80]) {
        static const size_t kLen[4] = {0U, 2U, 4U, 16U};
        static const uint8_t kTag[4] = {0U, 1U, 2U, 4U};
        size_t pos = 0U;
        for (unsigned i = 0; i < 2U; ++i) {
            if (pos >= pair.size()) {
                return;
            }
            const uint8_t kind = pair[pos++];
            if (kind < 1U || kind > 3U || kLen[kind] > pair.size() - pos) {
                return;
            }
            const unsigned tag_off = (i == 0U) ? 38U : 55U;
            const unsigned dat_off = (i == 0U) ? 39U : 56U;
            inf[tag_off] = kTag[kind];
            memcpy(inf + dat_off, &pair[pos], kLen[kind]);
            pos += kLen[kind];
        }
    }

    std::vector<uint8_t> mem_;
    int read_calls_;
};

// ------------------------------------------------------------------------------------------------
// Fake AlpsSppLink (drives AlpsSppManager + AlpsBtTransport cleanly without real D-Bus)
// ------------------------------------------------------------------------------------------------

class FakeAlpsSppLink : public AlpsSppLink {
public:
    explicit FakeAlpsSppLink(FakeSppMemoryBackend* mem = NULL)
        : mem_(mem),
          fail_start(false),
          fail_register_uuid(false),
          fail_set_interface(false),
          fail_disconnect_req(false),
          fail_send_data(false),
          sync_memory_on_register(true),
          sync_memory_on_disconnect(true),
          register_uuid_calls(0),
          set_interface_calls(0),
          read_config_calls(0),
          disconnect_req_calls(0),
          listener_(NULL),
          running_(false),
          link_up_(false),
          instance_(0),
          monitor_only_(false) {
        for (unsigned i = 0; i < kAlpsMaxInstances; ++i) {
            config_0x6203_[i] = (i <= 1U) ? 1U : 0U;
        }
    }

    FakeSppMemoryBackend* mem_;
    bool fail_start;
    bool fail_register_uuid;
    bool fail_set_interface;
    bool fail_disconnect_req;
    bool fail_send_data;
    bool sync_memory_on_register;
    bool sync_memory_on_disconnect;

    int register_uuid_calls;
    int set_interface_calls;
    int read_config_calls;
    int disconnect_req_calls;
    std::vector<std::vector<uint8_t> > registered_payloads;
    std::vector<uint8_t> set_interface_values;
    std::vector<uint8_t> tx_bytes;

    void setSlotConfig0x6203(unsigned slot, uint8_t val) {
        if (slot < kAlpsMaxInstances) {
            config_0x6203_[slot] = val;
        }
    }

    uint8_t slotConfig0x6203(unsigned slot) const {
        return slot < kAlpsMaxInstances ? config_0x6203_[slot] : 0xffU;
    }

    void simulateConnect(const BtAddr& peer) {
        link_up_ = true;
        if (listener_ != NULL) {
            listener_->onAlpsConnected(peer);
        }
    }

    void simulateRx(const uint8_t* data, size_t len) {
        if (listener_ != NULL) {
            listener_->onAlpsData(data, len);
        }
    }

    void simulateRemoteDisconnect(const std::string& reason) {
        link_up_ = false;
        if (mem_ != NULL) {
            // Keep existing UUID pair, mark slot idle.
            std::vector<uint8_t> cur = last_uuid_for_slot(instance_);
            mem_->setSlotUniform(instance_, 1U, 0U, false, cur);
        }
        if (listener_ != NULL) {
            listener_->onAlpsDisconnected(reason);
        }
    }

    virtual bool start(uint8_t instance, bool monitor_only) {
        if (fail_start) {
            last_error_ = "fake link start failed";
            return false;
        }
        instance_ = instance;
        monitor_only_ = monitor_only;
        running_ = true;
        return true;
    }

    virtual void stop() {
        running_ = false;
        link_up_ = false;
    }

    virtual bool isRunning() const { return running_; }
    virtual bool isLinkUp() const { return link_up_; }
    virtual void setListener(AlpsSppLinkListener* listener) { listener_ = listener; }

    virtual int registerUuidPayload(const std::vector<uint8_t>& payload, int /*timeout_ms*/) {
        ++register_uuid_calls;
        registered_payloads.push_back(payload);
        if (fail_register_uuid) {
            return 1;
        }
        if (sync_memory_on_register && mem_ != NULL) {
            mem_->setSlotUniform(instance_, 1U, 0U, false, payload);
        }
        return 0;
    }

    virtual bool readConfiguration(uint8_t instance,
                                   uint16_t id,
                                   std::vector<uint8_t>& out,
                                   int /*timeout_ms*/) {
        ++read_config_calls;
        if (!running_ || id != kAlpsConfigDataInterface || instance >= kAlpsMaxInstances) {
            return false;
        }
        const unsigned eff = (instance <= 1U) ? instance : 0U;
        out.assign(1U, config_0x6203_[eff]);
        return true;
    }

    virtual bool setDataInterface(uint8_t instance, uint8_t value, int /*timeout_ms*/) {
        ++set_interface_calls;
        set_interface_values.push_back(value);
        if (!running_ || fail_set_interface || instance >= kAlpsMaxInstances || value > 1U) {
            return false;
        }
        config_0x6203_[instance] = value;
        return true;
    }

    virtual bool requestSppDisconnect() {
        ++disconnect_req_calls;
        if (!running_ || fail_disconnect_req) {
            return false;
        }
        link_up_ = false;
        if (sync_memory_on_disconnect && mem_ != NULL) {
            std::vector<uint8_t> cur = last_uuid_for_slot(instance_);
            mem_->setSlotUniform(instance_, 1U, 0U, false, cur);
        }
        return true;
    }

    virtual void disconnectLink(const std::string& reason) {
        const bool was_up = link_up_;
        link_up_ = false;
        if (was_up && listener_ != NULL) {
            listener_->onAlpsDisconnected(reason);
        }
    }

    virtual bool sendData(const uint8_t* data, size_t len) {
        if (!running_ || !link_up_ || fail_send_data) {
            return false;
        }
        if (len > 0 && data != NULL) {
            tx_bytes.insert(tx_bytes.end(), data, data + len);
        }
        return true;
    }

    virtual const std::string& lastError() const { return last_error_; }

private:
    std::vector<uint8_t> last_uuid_for_slot(uint8_t /*slot*/) const {
        if (!registered_payloads.empty()) {
            return registered_payloads.back();
        }
        return carplay::platform::carPlayIap2UuidPair();
    }

    AlpsSppLinkListener* listener_;
    bool running_;
    bool link_up_;
    uint8_t instance_;
    bool monitor_only_;
    uint8_t config_0x6203_[kAlpsMaxInstances];
    std::string last_error_;
};

class RecordingTransportListener : public BtTransportListener {
public:
    RecordingTransportListener() : connected_count(0), disconnected_count(0) {}

    int connected_count;
    int disconnected_count;
    BtAddr last_peer;
    std::vector<uint8_t> received;
    std::string last_reason;

    virtual void onBtTransportConnected(const BtAddr& peer) {
        ++connected_count;
        last_peer = peer;
    }

    virtual void onBtTransportData(const uint8_t* data, size_t len) {
        received.insert(received.end(), data, data + len);
    }

    virtual void onBtTransportDisconnected(const std::string& reason) {
        ++disconnected_count;
        last_reason = reason;
    }
};

class RecordingManagerListener : public AlpsSppManagerListener {
public:
    RecordingManagerListener() : connected_count(0), disconnected_count(0) {}

    int connected_count;
    int disconnected_count;
    BtAddr last_peer;
    std::vector<uint8_t> received;
    std::string last_reason;

    virtual void onAlpsManagerConnected(const BtAddr& peer) {
        ++connected_count;
        last_peer = peer;
    }
    virtual void onAlpsManagerData(const uint8_t* data, size_t len) {
        received.insert(received.end(), data, data + len);
    }
    virtual void onAlpsManagerDisconnected(const std::string& reason) {
        ++disconnected_count;
        last_reason = reason;
    }
};

class RecordingLinkListener : public AlpsSppLinkListener {
public:
    RecordingLinkListener() : connected_count(0), disconnected_count(0), fatal_count(0) {}

    int connected_count;
    int disconnected_count;
    int fatal_count;
    BtAddr last_peer;
    std::vector<uint8_t> received;
    std::string last_reason;

    virtual void onAlpsConnected(const BtAddr& peer) {
        ++connected_count;
        last_peer = peer;
    }
    virtual void onAlpsData(const uint8_t* data, size_t len) {
        received.insert(received.end(), data, data + len);
    }
    virtual void onAlpsDisconnected(const std::string& reason) {
        ++disconnected_count;
        last_reason = reason;
    }
    virtual void onAlpsFatalError(const std::string& reason) {
        ++fatal_count;
        last_reason = reason;
    }
};

// ------------------------------------------------------------------------------------------------
// Full In-Process Fake D-Bus C ABI Engine (for testing DbusAlpsSppLink directly)
// ------------------------------------------------------------------------------------------------

struct FakeDbusArg {
    int type;
    uint8_t u8;
    uint16_t u16;
    uint64_t u64;
    std::string str;
    std::vector<uint8_t> bytes;
    FakeDbusArg() : type(0), u8(0), u16(0), u64(0) {}
};

struct FakeDbusMsg {
    int msg_type;  // 1=method_call, 2=method_return, 4=signal
    std::string destination;
    std::string path;
    std::string iface;
    std::string member;
    std::string sender;
    std::string signature;
    bool no_reply;
    std::vector<FakeDbusArg> args;

    FakeDbusMsg() : msg_type(1), no_reply(false) {}
};

struct FakeDbusIterState {
    FakeDbusMsg* msg;
    size_t idx;
    bool is_array_sub;
    const uint8_t* append_ptr_hack;
};

struct FakeDbusWorld {
    Mutex mu;
    DbusHandleMessageFn filter_fn;
    void* filter_user_data;
    bool closed;
    bool fc_paused;
    std::deque<FakeDbusMsg*> incoming_signals;
    std::vector<std::vector<uint8_t> > sent_data_reqs;
    std::vector<std::vector<uint8_t> > sent_uuid_reqs;
    uint8_t stored_cfg[kAlpsMaxInstances];
    int data_req_count;

    FakeDbusWorld()
        : filter_fn(NULL),
          filter_user_data(NULL),
          closed(false),
          fc_paused(false),
          data_req_count(0) {
        for (unsigned i = 0; i < kAlpsMaxInstances; ++i) {
            stored_cfg[i] = (i <= 1U) ? 1U : 0U;
        }
    }

    ~FakeDbusWorld() {
        while (!incoming_signals.empty()) {
            delete incoming_signals.front();
            incoming_signals.pop_front();
        }
    }

    static FakeDbusWorld& instance() {
        static FakeDbusWorld w;
        return w;
    }

    void reset() {
        LockGuard g(mu);
        filter_fn = NULL;
        filter_user_data = NULL;
        closed = false;
        fc_paused = false;
        while (!incoming_signals.empty()) {
            delete incoming_signals.front();
            incoming_signals.pop_front();
        }
        sent_data_reqs.clear();
        sent_uuid_reqs.clear();
        for (unsigned i = 0; i < kAlpsMaxInstances; ++i) {
            stored_cfg[i] = (i <= 1U) ? 1U : 0U;
        }
        data_req_count = 0;
    }

    void pushSignal(FakeDbusMsg* m) {
        LockGuard g(mu);
        incoming_signals.push_back(m);
    }
};

FakeDbusMsg* asMsg(DbusMessage* m) { return reinterpret_cast<FakeDbusMsg*>(m); }
DbusMessage* toDbusMsg(FakeDbusMsg* m) { return reinterpret_cast<DbusMessage*>(m); }

dbus_bool_raw fakeThreadsInit() { return 1U; }
void fakeErrInit(DbusErrorRaw* e) {
    if (e != NULL) {
        memset(e, 0, sizeof(*e));
    }
}
dbus_bool_raw fakeErrIsSet(const DbusErrorRaw* e) {
    return (e != NULL && e->name != NULL) ? 1U : 0U;
}
void fakeErrFree(DbusErrorRaw* e) {
    if (e != NULL) {
        memset(e, 0, sizeof(*e));
    }
}

DbusConnection* fakeBusGetPrivate(int, DbusErrorRaw*) {
    return reinterpret_cast<DbusConnection*>(&FakeDbusWorld::instance());
}
void fakeBusAddMatch(DbusConnection*, const char*, DbusErrorRaw*) {}
void fakeConnExitOnDisc(DbusConnection*, dbus_bool_raw) {}
void fakeConnClose(DbusConnection*) {
    LockGuard g(FakeDbusWorld::instance().mu);
    FakeDbusWorld::instance().closed = true;
}
void fakeConnUnref(DbusConnection*) {}
dbus_bool_raw fakeConnAddFilter(DbusConnection*,
                                 DbusHandleMessageFn fn,
                                 void* user_data,
                                 DbusFreeFn) {
    LockGuard g(FakeDbusWorld::instance().mu);
    FakeDbusWorld::instance().filter_fn = fn;
    FakeDbusWorld::instance().filter_user_data = user_data;
    return 1U;
}
void fakeConnRemoveFilter(DbusConnection*, DbusHandleMessageFn, void*) {
    LockGuard g(FakeDbusWorld::instance().mu);
    FakeDbusWorld::instance().filter_fn = NULL;
    FakeDbusWorld::instance().filter_user_data = NULL;
}

FakeDbusMsg* makeFakeSignal(const char* iface, const char* member, const char* sig) {
    FakeDbusMsg* s = new FakeDbusMsg;
    s->msg_type = 4;
    s->path = kAlpsDbusPath;
    s->sender = ":1.77";
    s->iface = iface;
    s->member = member;
    s->signature = sig;
    return s;
}

dbus_bool_raw fakeConnSend(DbusConnection*, DbusMessage* dm, uint32_t*) {
    FakeDbusMsg* m = asMsg(dm);
    FakeDbusWorld& w = FakeDbusWorld::instance();
    if (m->iface == kAlpsDbusSppInterface && m->member == "BtApplSppSetUuidReq") {
        if (m->args.size() >= 3U) {
            const uint8_t inst = m->args[0].u8;
            {
                LockGuard g(w.mu);
                w.sent_uuid_reqs.push_back(m->args[2].bytes);
            }
            FakeDbusMsg* cfm = makeFakeSignal(kAlpsDbusSppInterface, "BtApplSppSetUuidCfm", "yy");
            FakeDbusArg a0; a0.type = 'y'; a0.u8 = inst;
            FakeDbusArg a1; a1.type = 'y'; a1.u8 = 0U;
            cfm->args.push_back(a0);
            cfm->args.push_back(a1);
            w.pushSignal(cfm);
        }
        return 1U;
    }
    if (m->iface == kAlpsDbusDmInterface && m->member == "BtApplSetConfigurationReq") {
        if (m->args.size() >= 4U) {
            const uint8_t inst = m->args[0].u8;
            const uint16_t id = m->args[1].u16;
            const uint8_t val = m->args[3].bytes.empty() ? 0U : m->args[3].bytes[0];
            {
                LockGuard g(w.mu);
                if (inst < kAlpsMaxInstances && id == kAlpsConfigDataInterface) {
                    w.stored_cfg[inst] = val;
                }
            }
            FakeDbusMsg* cfm = makeFakeSignal(kAlpsDbusDmInterface, "BtApplSetConfigurationCfm", "yyq");
            FakeDbusArg a0; a0.type = 'y'; a0.u8 = 0U;
            FakeDbusArg a1; a1.type = 'y'; a1.u8 = inst;
            FakeDbusArg a2; a2.type = 'q'; a2.u16 = id;
            cfm->args.push_back(a0);
            cfm->args.push_back(a1);
            cfm->args.push_back(a2);
            w.pushSignal(cfm);
        }
        return 1U;
    }
    if (m->iface == kAlpsDbusDmInterface && m->member == "BtApplReadConfigurationReq") {
        if (m->args.size() >= 2U) {
            const uint8_t inst = m->args[0].u8;
            const uint16_t id = m->args[1].u16;
            uint8_t val = 0U;
            {
                LockGuard g(w.mu);
                const unsigned eff = (inst <= 1U) ? inst : 0U;
                val = w.stored_cfg[eff];
            }
            FakeDbusMsg* cfm = makeFakeSignal(kAlpsDbusDmInterface, "BtApplReadConfigurationCfm", "yyqqay");
            FakeDbusArg a0; a0.type = 'y'; a0.u8 = 0U;
            FakeDbusArg a1; a1.type = 'y'; a1.u8 = inst;
            FakeDbusArg a2; a2.type = 'q'; a2.u16 = id;
            FakeDbusArg a3; a3.type = 'q'; a3.u16 = 1U;
            FakeDbusArg a4; a4.type = 'a'; a4.bytes.assign(1U, val);
            cfm->args.push_back(a0);
            cfm->args.push_back(a1);
            cfm->args.push_back(a2);
            cfm->args.push_back(a3);
            cfm->args.push_back(a4);
            w.pushSignal(cfm);
        }
        return 1U;
    }
    if (m->iface == kAlpsDbusSppInterface && m->member == "BtApplSppDataReq") {
        if (m->args.size() >= 3U) {
            const uint8_t inst = m->args[0].u8;
            {
                LockGuard g(w.mu);
                w.sent_data_reqs.push_back(m->args[2].bytes);
                ++w.data_req_count;
            }
            FakeDbusMsg* dcfm = makeFakeSignal(kAlpsDbusSppInterface, "BtApplSppDataCfm", "yy");
            FakeDbusArg c0; c0.type = 'y'; c0.u8 = inst;
            FakeDbusArg c1; c1.type = 'y'; c1.u8 = 0U;
            dcfm->args.push_back(c0);
            dcfm->args.push_back(c1);
            w.pushSignal(dcfm);

            FakeDbusMsg* sind = makeFakeSignal(kAlpsDbusSppInterface, "BtApplSppSendInd", "y");
            FakeDbusArg s0; s0.type = 'y'; s0.u8 = inst;
            sind->args.push_back(s0);
            w.pushSignal(sind);
        }
        return 1U;
    }
    return 1U;
}

DbusMessage* fakeSendWithReply(DbusConnection*, DbusMessage* q, int, DbusErrorRaw*) {
    FakeDbusMsg* req = asMsg(q);
    FakeDbusMsg* rsp = new FakeDbusMsg;
    rsp->msg_type = 2;
    if (req->member == "GetNameOwner") {
        FakeDbusArg a;
        a.type = 's';
        a.str = ":1.77";
        rsp->args.push_back(a);
    }
    return toDbusMsg(rsp);
}

dbus_bool_raw fakeReadWriteDispatch(DbusConnection* conn, int /*timeout_ms*/) {
    FakeDbusWorld& w = FakeDbusWorld::instance();
    FakeDbusMsg* sig = NULL;
    DbusHandleMessageFn fn = NULL;
    void* ud = NULL;
    {
        LockGuard g(w.mu);
        if (w.closed) {
            return 0U;
        }
        if (!w.incoming_signals.empty()) {
            sig = w.incoming_signals.front();
            w.incoming_signals.pop_front();
        }
        fn = w.filter_fn;
        ud = w.filter_user_data;
    }
    if (sig != NULL && fn != NULL) {
        fn(conn, toDbusMsg(sig), ud);
    }
    delete sig;
    return 1U;
}

DbusMessage* fakeNewMethodCall(const char* dest, const char* path, const char* iface, const char* method) {
    FakeDbusMsg* m = new FakeDbusMsg;
    m->msg_type = 1;
    m->destination = dest != NULL ? dest : "";
    m->path = path != NULL ? path : "";
    m->iface = iface != NULL ? iface : "";
    m->member = method != NULL ? method : "";
    return toDbusMsg(m);
}
void fakeMsgUnref(DbusMessage* m) { delete asMsg(m); }
void fakeMsgSetNoReply(DbusMessage* m, dbus_bool_raw nr) { asMsg(m)->no_reply = (nr != 0U); }
int fakeMsgGetType(DbusMessage* m) { return asMsg(m)->msg_type; }
const char* fakeMsgGetMember(DbusMessage* m) { return asMsg(m)->member.c_str(); }
const char* fakeMsgGetInterface(DbusMessage* m) { return asMsg(m)->iface.c_str(); }
const char* fakeMsgGetSignature(DbusMessage* m) { return asMsg(m)->signature.c_str(); }
dbus_bool_raw fakeMsgHasInterface(DbusMessage* m, const char* iface) {
    return (iface != NULL && asMsg(m)->iface == iface) ? 1U : 0U;
}
dbus_bool_raw fakeMsgHasPath(DbusMessage* m, const char* path) {
    return (path != NULL && asMsg(m)->path == path) ? 1U : 0U;
}
dbus_bool_raw fakeMsgHasSender(DbusMessage* m, const char* sender) {
    return (sender != NULL && asMsg(m)->sender == sender) ? 1U : 0U;
}
dbus_bool_raw fakeMsgHasSignature(DbusMessage* m, const char* sig) {
    return (sig != NULL && asMsg(m)->signature == sig) ? 1U : 0U;
}
dbus_bool_raw fakeMsgIsSignal(DbusMessage* m, const char* iface, const char* sig) {
    FakeDbusMsg* fm = asMsg(m);
    return (fm->msg_type == 4 && iface != NULL && sig != NULL &&
            fm->iface == iface && fm->member == sig) ? 1U : 0U;
}

FakeDbusIterState* iterState(DbusMessageIterRaw* it) {
    return reinterpret_cast<FakeDbusIterState*>(it);
}

dbus_bool_raw fakeIterInit(DbusMessage* m, DbusMessageIterRaw* it) {
    FakeDbusIterState* st = iterState(it);
    st->msg = asMsg(m);
    st->idx = 0U;
    st->is_array_sub = false;
    return st->msg->args.empty() ? 0U : 1U;
}
dbus_bool_raw fakeIterNext(DbusMessageIterRaw* it) {
    FakeDbusIterState* st = iterState(it);
    ++st->idx;
    return st->idx < st->msg->args.size() ? 1U : 0U;
}
int fakeIterGetArgType(DbusMessageIterRaw* it) {
    FakeDbusIterState* st = iterState(it);
    if (st->msg == NULL || st->idx >= st->msg->args.size()) {
        return 0;
    }
    return st->msg->args[st->idx].type;
}
int fakeIterGetElemType(DbusMessageIterRaw* it) {
    FakeDbusIterState* st = iterState(it);
    if (st->msg != NULL && st->idx < st->msg->args.size() && st->msg->args[st->idx].type == 'a') {
        return 'y';
    }
    return 0;
}
void fakeIterGetBasic(DbusMessageIterRaw* it, void* out) {
    FakeDbusIterState* st = iterState(it);
    const FakeDbusArg& a = st->msg->args[st->idx];
    if (a.type == 'y') {
        *static_cast<uint8_t*>(out) = a.u8;
    } else if (a.type == 'q') {
        *static_cast<uint16_t*>(out) = a.u16;
    } else if (a.type == 't') {
        *static_cast<uint64_t*>(out) = a.u64;
    } else if (a.type == 's') {
        *static_cast<const char**>(out) = a.str.c_str();
    }
}
void fakeIterRecurse(DbusMessageIterRaw* it, DbusMessageIterRaw* sub) {
    *iterState(sub) = *iterState(it);
    iterState(sub)->is_array_sub = true;
}
void fakeIterGetFixedArray(DbusMessageIterRaw* sub, void* value_ptr, int* n_out) {
    FakeDbusIterState* st = iterState(sub);
    const std::vector<uint8_t>& b = st->msg->args[st->idx].bytes;
    *static_cast<const uint8_t**>(value_ptr) = b.empty() ? NULL : &b[0];
    *n_out = static_cast<int>(b.size());
}

void fakeIterInitAppend(DbusMessage* m, DbusMessageIterRaw* it) {
    FakeDbusIterState* st = iterState(it);
    st->msg = asMsg(m);
    st->idx = 0U;
    st->is_array_sub = false;
}
dbus_bool_raw fakeIterAppendBasic(DbusMessageIterRaw* it, int type, const void* val) {
    FakeDbusIterState* st = iterState(it);
    FakeDbusArg a;
    a.type = type;
    if (type == 'y') {
        a.u8 = *static_cast<const uint8_t*>(val);
    } else if (type == 'q') {
        a.u16 = *static_cast<const uint16_t*>(val);
    } else if (type == 't') {
        a.u64 = *static_cast<const uint64_t*>(val);
    } else if (type == 's') {
        const char* s = *static_cast<const char* const*>(val);
        a.str = s != NULL ? s : "";
    }
    st->msg->args.push_back(a);
    return 1U;
}
dbus_bool_raw fakeIterOpenContainer(DbusMessageIterRaw* it,
                                    int type,
                                    const char*,
                                    DbusMessageIterRaw* sub) {
    FakeDbusIterState* st = iterState(it);
    FakeDbusArg a;
    a.type = type;
    st->msg->args.push_back(a);
    FakeDbusIterState* sst = iterState(sub);
    sst->msg = st->msg;
    sst->idx = st->msg->args.size() - 1U;
    sst->is_array_sub = true;
    return 1U;
}
dbus_bool_raw fakeIterCloseContainer(DbusMessageIterRaw*, DbusMessageIterRaw*) { return 1U; }
void fakeIterAbandonContainer(DbusMessageIterRaw*, DbusMessageIterRaw*) {}
dbus_bool_raw fakeIterAppendFixedArray(DbusMessageIterRaw* sub,
                                       int,
                                       const void* ptr_to_ptr,
                                       int n) {
    FakeDbusIterState* st = iterState(sub);
    const uint8_t* p = *static_cast<const uint8_t* const*>(ptr_to_ptr);
    if (n > 0 && p != NULL) {
        st->msg->args[st->idx].bytes.assign(p, p + n);
    }
    return 1U;
}
dbus_bool_raw fakeValidatePath(const char* p, DbusErrorRaw*) {
    return (p != NULL && p[0] == '/') ? 1U : 0U;
}

DbusApi buildFakeDbusApi() {
    DbusApi api;
    api.threads_init_default = &fakeThreadsInit;
    api.error_init = &fakeErrInit;
    api.error_is_set = &fakeErrIsSet;
    api.error_free = &fakeErrFree;
    api.bus_get_private = &fakeBusGetPrivate;
    api.bus_add_match = &fakeBusAddMatch;
    api.connection_set_exit_on_disconnect = &fakeConnExitOnDisc;
    api.connection_close = &fakeConnClose;
    api.connection_unref = &fakeConnUnref;
    api.connection_add_filter = &fakeConnAddFilter;
    api.connection_remove_filter = &fakeConnRemoveFilter;
    api.connection_send = &fakeConnSend;
    api.connection_send_with_reply_and_block = &fakeSendWithReply;
    api.connection_read_write_dispatch = &fakeReadWriteDispatch;
    api.message_new_method_call = &fakeNewMethodCall;
    api.message_unref = &fakeMsgUnref;
    api.message_set_no_reply = &fakeMsgSetNoReply;
    api.message_get_type = &fakeMsgGetType;
    api.message_get_member = &fakeMsgGetMember;
    api.message_get_interface = &fakeMsgGetInterface;
    api.message_get_signature = &fakeMsgGetSignature;
    api.message_has_interface = &fakeMsgHasInterface;
    api.message_has_path = &fakeMsgHasPath;
    api.message_has_sender = &fakeMsgHasSender;
    api.message_has_signature = &fakeMsgHasSignature;
    api.message_is_signal = &fakeMsgIsSignal;
    api.message_iter_init = &fakeIterInit;
    api.message_iter_next = &fakeIterNext;
    api.message_iter_get_arg_type = &fakeIterGetArgType;
    api.message_iter_get_element_type = &fakeIterGetElemType;
    api.message_iter_get_basic = &fakeIterGetBasic;
    api.message_iter_recurse = &fakeIterRecurse;
    api.message_iter_get_fixed_array = &fakeIterGetFixedArray;
    api.message_iter_init_append = &fakeIterInitAppend;
    api.message_iter_append_basic = &fakeIterAppendBasic;
    api.message_iter_open_container = &fakeIterOpenContainer;
    api.message_iter_close_container = &fakeIterCloseContainer;
    api.message_iter_abandon_container = &fakeIterAbandonContainer;
    api.message_iter_append_fixed_array = &fakeIterAppendFixedArray;
    api.validate_path = &fakeValidatePath;
    return api;
}

class RecordingIap2Listener : public carplay::iap2::LinkListener {
public:
    RecordingIap2Listener() : detected_bytes(0) {}
    int detected_bytes;
    virtual void onLinkError(const std::string&) {}
};

// Fake clock helper for deterministic AdvertisementSchedule timer tests on Reactor.
int64_t g_fake_clock_ns = 1000000000LL;
int64_t fakeClockNs() { return g_fake_clock_ns; }

}  // namespace

// ------------------------------------------------------------------------------------------------
// Test Cases
// ------------------------------------------------------------------------------------------------

TEST_CASE(elfSymbolsAndGotParsing) {
    const std::vector<uint8_t> elf_bytes = buildValidAlpsElf();
    ElfSymbols elf;
    REQUIRE(elf.loadFromBytes(elf_bytes));
    CHECK(elf.isLoaded());

    SppLayout layout;
    std::string err;
    REQUIRE(carplay::platform::extractSppLayout(elf, layout, &err));
    CHECK_EQ(static_cast<uint32_t>(0x20000U), layout.app);
    CHECK_EQ(static_cast<uint32_t>(0x24000U), layout.info);
    CHECK_EQ(static_cast<uint32_t>(0x25000U), layout.connections);
    CHECK_EQ(static_cast<uint32_t>(0x1000U), layout.app_got);
    CHECK_EQ(static_cast<uint32_t>(0x1004U), layout.info_got);
    CHECK_EQ(static_cast<uint32_t>(0x1008U), layout.connections_got);

    // Imported SHN_UNDEF symbols must not resolve as defined.
    ElfSymbolInfo sym;
    CHECK(!elf.findSymbol("imported_sym", sym));
    CHECK(!elf.findSymbol("nonexistent", sym));

    // Wrong machine (x86 = 3 instead of ARM = 40) rejected.
    std::vector<SynthSymSpec> syms;
    SynthSymSpec a;
    a.name = "app";
    a.value = 0x1000U;
    a.size = kAlpsAppSymbolSize;
    a.shndx = 1U;
    a.got_offset = 0x100U;
    syms.push_back(a);
    const std::vector<uint8_t> x86_elf = buildSyntheticArmElf(syms, 3U);
    CHECK(!elf.loadFromBytes(x86_elf));

    // Truncated ELF rejected cleanly.
    std::vector<uint8_t> truncated(elf_bytes.begin(), elf_bytes.begin() + 40);
    CHECK(!elf.loadFromBytes(truncated));

    // Corrupt magic rejected.
    std::vector<uint8_t> bad_magic = elf_bytes;
    bad_magic[0] = 0x00U;
    CHECK(!elf.loadFromBytes(bad_magic));

    // Wrong `app` symbol size rejected by extractSppLayout.
    std::vector<SynthSymSpec> wrong_size_syms;
    SynthSymSpec b = a;
    b.size = kAlpsAppSymbolSize + 4U;
    wrong_size_syms.push_back(b);
    SynthSymSpec c;
    c.name = "spp_info"; c.value = 0x2000U; c.size = kAlpsSppInfoSymbolSize; c.shndx = 1U; c.got_offset = 0x104U;
    wrong_size_syms.push_back(c);
    SynthSymSpec d;
    d.name = "spp_connected"; d.value = 0x3000U; d.size = kAlpsSppConnectedSymbolSize; d.shndx = 1U; d.got_offset = 0x108U;
    wrong_size_syms.push_back(d);
    REQUIRE(elf.loadFromBytes(buildSyntheticArmElf(wrong_size_syms)));
    CHECK(!carplay::platform::extractSppLayout(elf, layout, &err));
    CHECK(err.find("unknown ALPS structure") != std::string::npos);

    // Missing GOT slot rejected.
    wrong_size_syms[0].size = kAlpsAppSymbolSize;
    wrong_size_syms[0].got_offset = 0U;
    REQUIRE(elf.loadFromBytes(buildSyntheticArmElf(wrong_size_syms)));
    CHECK(!carplay::platform::extractSppLayout(elf, layout, &err));
}

TEST_CASE(uuidPayloadsAndProcStatParsing) {
    CHECK_EQ(std::string("011101011101"),
             carplay::platform::sppPayloadToHex(carplay::platform::genericSppUuidPair()));
    CHECK_EQ(std::string("0300000000decafadedecadeafdecacaff0300000000decafadedecadeafdecacafe"),
             carplay::platform::sppPayloadToHex(carplay::platform::carPlayIap2UuidPair()));
    CHECK(carplay::platform::validateSppUuidPayload(carplay::platform::genericSppUuidPair()));
    CHECK(carplay::platform::validateSppUuidPayload(carplay::platform::carPlayIap2UuidPair()));
    CHECK(carplay::platform::isSupportedSppBaseline(carplay::platform::genericSppUuidPair()));
    CHECK(carplay::platform::isSupportedSppBaseline(carplay::platform::carPlayIap2UuidPair()));

    std::vector<uint8_t> bad_payload = carplay::platform::genericSppUuidPair();
    bad_payload.pop_back();
    CHECK(!carplay::platform::validateSppUuidPayload(bad_payload));

    std::vector<uint8_t> third_party(34U, 0x22U);
    third_party[0] = 3U;
    third_party[17] = 3U;
    CHECK(carplay::platform::validateSppUuidPayload(third_party));
    CHECK(!carplay::platform::isSupportedSppBaseline(third_party));

    // Process name containing spaces and parentheses must still extract field 22 (start ticks).
    const std::string stat_line =
        "4242 (bt (media) worker) S 1 4242 4242 0 -1 4194304 10 0 0 0 0 0 0 0 20 0 4 0 987654321 4096 100";
    CHECK_EQ(std::string("987654321"), carplay::platform::parseProcStatStartTicks(stat_line));
    CHECK_EQ(std::string(""), carplay::platform::parseProcStatStartTicks("123 (bad) S 1"));
}

TEST_CASE(snapshotDecodeAndDoubleReadValidation) {
    uint8_t record[34] = {};
    uint8_t info[80] = {};
    uint8_t connected[6] = {};
    record[0] = record[16] = info[39] = info[56] = 0x11U;
    record[1] = record[17] = info[40] = info[57] = 0x01U;
    record[32] = record[33] = info[38] = info[55] = 1U;

    SppSlotSnapshot snap;
    REQUIRE(carplay::platform::decodeSppSlotSnapshot(1U, record, info, connected, snap));
    CHECK(snap.isIdle());
    CHECK(snap.hasConsistentUuids());
    CHECK_BYTES_EQ(carplay::platform::genericSppUuidPair(), snap.uuid_payload);

    // Busy/connected variants are not idle.
    REQUIRE(carplay::platform::decodeSppSlotSnapshot(2U, record, info, connected, snap));
    CHECK(!snap.isIdle());
    connected[2] = 1U;
    REQUIRE(carplay::platform::decodeSppSlotSnapshot(1U, record, info, connected, snap));
    CHECK(!snap.isIdle());
    connected[2] = 0U;
    info[4] = 3U;
    REQUIRE(carplay::platform::decodeSppSlotSnapshot(1U, record, info, connected, snap));
    CHECK(!snap.isIdle());
    info[4] = 0U;

    // Split UUID bytes rejected strictly, accepted only with allow_split=true.
    info[39] = 0x22U;
    CHECK(!carplay::platform::decodeSppSlotSnapshot(1U, record, info, connected, snap, false));
    REQUIRE(carplay::platform::decodeSppSlotSnapshot(1U, record, info, connected, snap, true));
    CHECK(!snap.hasConsistentUuids());

    // Invalid state/type rejected.
    info[39] = 0x11U;
    CHECK(!carplay::platform::decodeSppSlotSnapshot(3U, record, info, connected, snap));
    record[32] = 9U;
    CHECK(!carplay::platform::decodeSppSlotSnapshot(1U, record, info, connected, snap));

    // Reader with FakeSppMemoryBackend: GOT mismatch rejected.
    FakeSppMemoryBackend mem;
    mem.writeRelocations(false);
    SppSnapshotReader bad_got_reader(&mem, 0U);
    CHECK(!bad_got_reader.open());
    CHECK(bad_got_reader.error().find("relocations") != std::string::npos);

    // Valid relocations, double-read changing rejected.
    mem.writeRelocations(true);
    mem.setSlotDisconnectedGeneric(5U);
    SppSnapshotReader reader(&mem, 0U);
    REQUIRE(reader.open());
    CHECK(!reader.open());  // already open
    REQUIRE(reader.read(5U, snap));
    CHECK(snap.isIdle());

    mem.corrupt_on_second_read = true;
    mem.mutate_slot_on_read_n = 0;  // mutate right after round 0 reads state
    mem.mutate_slot_index = 5U;
    CHECK(!reader.read(5U, snap));
    CHECK_EQ(std::string("SPP state changing"), reader.error());

    // Process restart (identity change) rejected.
    mem.identity = "999999";
    CHECK(!reader.read(5U, snap));
    CHECK(reader.error().find("replaced") != std::string::npos);
}

TEST_CASE(carPlaySlotSelectionRules) {
    SppSlotSnapshot s_native_idle;
    s_native_idle.state = 1U;
    s_native_idle.uuid_payload = carplay::platform::carPlayIap2UuidPair();
    s_native_idle.transport_uuid_payload = carplay::platform::carPlayIap2UuidPair();

    SppSlotSnapshot s_generic_idle;
    s_generic_idle.state = 1U;
    s_generic_idle.uuid_payload = carplay::platform::genericSppUuidPair();
    s_generic_idle.transport_uuid_payload = carplay::platform::genericSppUuidPair();

    SppSlotSnapshot s_unstarted;
    s_unstarted.state = 0U;

    SppSlotSnapshot s_busy_iap2 = s_native_idle;
    s_busy_iap2.connected = true;

    SppSlotSnapshot s_other_uuid;
    s_other_uuid.state = 1U;
    s_other_uuid.uuid_payload.assign(6U, 0x01U);
    s_other_uuid.uuid_payload[1] = 0x22U;
    s_other_uuid.transport_uuid_payload = s_other_uuid.uuid_payload;

    // 1. Slot 1 idle with iAP2 UUID -> use native slot 1, no reconfig, no restore.
    CarPlaySlotSelection sel = carplay::platform::evaluateCarPlaySppSlot(
        true, s_native_idle, true, s_generic_idle, true, s_generic_idle);
    CHECK_EQ(kSlotUseNative1, sel.decision);
    CHECK_EQ(kAlpsNativeCarPlaySlot, sel.slot);
    CHECK(!sel.requires_configure);
    CHECK(!sel.requires_restore);

    // 2. Slot 1 carrying iAP2 UUID while busy -> refuse busy (never advertise twice on slot 5!).
    sel = carplay::platform::evaluateCarPlaySppSlot(
        true, s_busy_iap2, true, s_generic_idle, true, s_generic_idle);
    CHECK_EQ(kSlotRefuseBusy, sel.decision);

    // 3. Slot 1 generic (or absent) and slot 5 free generic idle -> borrow slot 5.
    sel = carplay::platform::evaluateCarPlaySppSlot(
        true, s_generic_idle, true, s_generic_idle, true, s_generic_idle);
    CHECK_EQ(kSlotBorrow5, sel.decision);
    CHECK_EQ(kAlpsSpareSlot, sel.slot);
    CHECK(sel.requires_configure);
    CHECK(sel.requires_restore);

    // 4. Slot 5 busy/connected -> refuse busy.
    SppSlotSnapshot s5_busy = s_generic_idle;
    s5_busy.state = 2U;
    sel = carplay::platform::evaluateCarPlaySppSlot(
        true, s_generic_idle, true, s5_busy, true, s_generic_idle);
    CHECK_EQ(kSlotRefuseBusy, sel.decision);

    // 5. Slot 5 already holding iAP2 -> refuse busy.
    sel = carplay::platform::evaluateCarPlaySppSlot(
        true, s_generic_idle, true, s_native_idle, true, s_generic_idle);
    CHECK_EQ(kSlotRefuseBusy, sel.decision);

    // 6. Slot 5 absent (state=0) -> default policy MUST protect slot 0!
    sel = carplay::platform::evaluateCarPlaySppSlot(
        true, s_generic_idle, true, s_unstarted, true, s_generic_idle);
    CHECK_EQ(kSlotRefuseProtected, sel.decision);

    // 7. Slot 5 holding another third-party UUID -> default policy protects slot 0!
    sel = carplay::platform::evaluateCarPlaySppSlot(
        true, s_generic_idle, true, s_other_uuid, true, s_generic_idle);
    CHECK_EQ(kSlotRefuseProtected, sel.decision);

    // 8. Explicit opt-in for slot 0 fallback works only when explicitly enabled & baseline safe.
    CarPlaySlotPolicy opt_in;
    opt_in.allow_slot0_fallback = true;
    sel = carplay::platform::evaluateCarPlaySppSlot(
        true, s_generic_idle, false, SppSlotSnapshot(), true, s_generic_idle, opt_in);
    CHECK_EQ(kSlotBorrow0, sel.decision);
    CHECK_EQ(kAlpsBmwAppsSlot, sel.slot);
    CHECK(sel.requires_configure);
    CHECK(sel.requires_restore);

    // Even with opt-in, unknown UUID on slot 0 is refused.
    sel = carplay::platform::evaluateCarPlaySppSlot(
        true, s_generic_idle, false, SppSlotSnapshot(), true, s_other_uuid, opt_in);
    CHECK_EQ(kSlotRefuseProtected, sel.decision);
}

TEST_CASE(alpsManagerNativeSlot1NoReconfigNoRestore) {
    Reactor reactor;
    REQUIRE(reactor.init());

    FakeSppMemoryBackend mem;
    mem.setSlotUniform(kAlpsNativeCarPlaySlot, 1U, 0U, false, carplay::platform::carPlayIap2UuidPair());
    mem.setSlotDisconnectedGeneric(kAlpsSpareSlot);
    mem.setSlotDisconnectedGeneric(kAlpsBmwAppsSlot);

    FakeAlpsSppLink fake_link(&mem);
    fake_link.setSlotConfig0x6203(kAlpsNativeCarPlaySlot, 1U);

    AlpsSppManagerConfig cfg;
    cfg.double_read_delay_ms = 0U;
    cfg.restore_poll_interval_ms = 0U;

    RecordingManagerListener listener;
    AlpsSppManager mgr(reactor, listener, cfg, &mem, &fake_link);
    std::string err;
    REQUIRE(mgr.start(&err));
    CHECK(mgr.isStarted());
    CHECK_EQ(kSlotUseNative1, mgr.slotDecision());
    CHECK_EQ(kAlpsNativeCarPlaySlot, mgr.activeSlot());
    CHECK(!mgr.borrowedSlot());
    CHECK_EQ(0, fake_link.register_uuid_calls);
    CHECK_EQ(0, fake_link.set_interface_calls);
    CHECK_EQ(1, fake_link.read_config_calls);

    BtAddr peer;
    REQUIRE(BtAddr::parse("11:22:33:44:55:66", peer));
    fake_link.simulateConnect(peer);
    CHECK_EQ(1, listener.connected_count);
    CHECK(mgr.isConnected());

    const uint8_t rx[] = {0xffU, 0x55U, 0x02U};
    fake_link.simulateRx(rx, sizeof(rx));
    CHECK_BYTES_EQ(std::vector<uint8_t>(rx, rx + sizeof(rx)), listener.received);

    const uint8_t tx[] = {0xaaU, 0xbbU};
    CHECK(mgr.sendData(tx, sizeof(tx)));
    CHECK_BYTES_EQ(std::vector<uint8_t>(tx, tx + sizeof(tx)), fake_link.tx_bytes);

    REQUIRE(mgr.stop(&err));
    CHECK(!mgr.isStarted());
    CHECK(!mgr.restoreAttempted());
    CHECK_EQ(0, fake_link.register_uuid_calls);
    CHECK_EQ(0, fake_link.set_interface_calls);
}

TEST_CASE(alpsManagerBorrowSlot5VerifyAndRestore) {
    Reactor reactor(&fakeClockNs);
    REQUIRE(reactor.init());

    FakeSppMemoryBackend mem;
    mem.setSlotDisconnectedGeneric(kAlpsBmwAppsSlot);
    mem.setSlotDisconnectedGeneric(kAlpsNativeCarPlaySlot);
    mem.setSlotDisconnectedGeneric(kAlpsSpareSlot);

    FakeAlpsSppLink fake_link(&mem);
    AlpsSppManagerConfig cfg;
    cfg.double_read_delay_ms = 0U;
    cfg.restore_poll_interval_ms = 0U;

    RecordingManagerListener listener;
    AlpsSppManager mgr(reactor, listener, cfg, &mem, &fake_link);
    std::string err;
    REQUIRE(mgr.start(&err));
    CHECK(mgr.isStarted());
    CHECK_EQ(kSlotBorrow5, mgr.slotDecision());
    CHECK_EQ(kAlpsSpareSlot, mgr.activeSlot());
    CHECK(mgr.borrowedSlot());
    CHECK_EQ(1, fake_link.set_interface_calls);
    CHECK_EQ(static_cast<uint8_t>(1U), fake_link.slotConfig0x6203(kAlpsSpareSlot));
    CHECK_EQ(1, fake_link.register_uuid_calls);
    CHECK_BYTES_EQ(carplay::platform::carPlayIap2UuidPair(), fake_link.registered_payloads[0]);

    // Check advertisement refresh triggers at 15s while idle.
    g_fake_clock_ns += 16000LL * 1000000LL;
    reactor.runOnce(0);
    CHECK_EQ(2, fake_link.register_uuid_calls);

    // Connect on slot 5 and mark memory active to test disconnect + restore on stop().
    BtAddr peer;
    REQUIRE(BtAddr::parse("AA:BB:CC:DD:EE:FF", peer));
    fake_link.simulateConnect(peer);
    mem.setSlotUniform(kAlpsSpareSlot, 2U, 1U, true, carplay::platform::carPlayIap2UuidPair());

    REQUIRE(mgr.stop(&err));
    CHECK(!mgr.isStarted());
    CHECK(mgr.restoreAttempted());
    CHECK(mgr.restoreSucceeded());
    CHECK_EQ(1, fake_link.disconnect_req_calls);
    CHECK_EQ(3, fake_link.register_uuid_calls);
    CHECK_BYTES_EQ(carplay::platform::genericSppUuidPair(), fake_link.registered_payloads[2]);
    CHECK_EQ(2, fake_link.set_interface_calls);
    CHECK_EQ(static_cast<uint8_t>(0U), fake_link.slotConfig0x6203(kAlpsSpareSlot));
}

TEST_CASE(alpsManagerMismatchAndRestoreRefusals) {
    Reactor reactor;
    REQUIRE(reactor.init());

    // Case A: re-read after SetUuid shows memory mismatch -> start fails and immediately restores.
    {
        FakeSppMemoryBackend mem;
        mem.setSlotDisconnectedGeneric(kAlpsBmwAppsSlot);
        mem.setSlotDisconnectedGeneric(kAlpsNativeCarPlaySlot);
        mem.setSlotDisconnectedGeneric(kAlpsSpareSlot);

        FakeAlpsSppLink fake_link(&mem);
        fake_link.sync_memory_on_register = false;  // ALPS memory still holds generic UUID!

        AlpsSppManagerConfig cfg;
        cfg.double_read_delay_ms = 0U;
        cfg.restore_poll_interval_ms = 0U;

        RecordingManagerListener listener;
        AlpsSppManager mgr(reactor, listener, cfg, &mem, &fake_link);
        std::string err;
        CHECK(!mgr.start(&err));
        CHECK(!mgr.isStarted());
        CHECK(mgr.restoreAttempted());
        CHECK(mgr.restoreSucceeded());
        CHECK_EQ(static_cast<uint8_t>(0U), fake_link.slotConfig0x6203(kAlpsSpareSlot));
    }

    // Case B: ALPS process restarted while slot 5 was borrowed -> stop() refuses restore!
    {
        FakeSppMemoryBackend mem;
        mem.setSlotDisconnectedGeneric(kAlpsBmwAppsSlot);
        mem.setSlotDisconnectedGeneric(kAlpsNativeCarPlaySlot);
        mem.setSlotDisconnectedGeneric(kAlpsSpareSlot);

        FakeAlpsSppLink fake_link(&mem);
        AlpsSppManagerConfig cfg;
        cfg.double_read_delay_ms = 0U;
        cfg.restore_poll_interval_ms = 0U;

        RecordingManagerListener listener;
        AlpsSppManager mgr(reactor, listener, cfg, &mem, &fake_link);
        REQUIRE(mgr.start());
        const int reg_before = fake_link.register_uuid_calls;
        const int cfg_before = fake_link.set_interface_calls;

        // Simulate ALPS restart.
        mem.identity = "9999999";
        std::string err;
        CHECK(!mgr.stop(&err));
        CHECK(mgr.restoreAttempted());
        CHECK(!mgr.restoreSucceeded());
        CHECK(err.find("restarted") != std::string::npos);
        CHECK_EQ(reg_before, fake_link.register_uuid_calls);
        CHECK_EQ(cfg_before, fake_link.set_interface_calls);
    }

    // Case C: Third-party UUID appeared on borrowed slot 5 -> stop() refuses restore!
    {
        FakeSppMemoryBackend mem;
        mem.setSlotDisconnectedGeneric(kAlpsBmwAppsSlot);
        mem.setSlotDisconnectedGeneric(kAlpsNativeCarPlaySlot);
        mem.setSlotDisconnectedGeneric(kAlpsSpareSlot);

        FakeAlpsSppLink fake_link(&mem);
        AlpsSppManagerConfig cfg;
        cfg.double_read_delay_ms = 0U;
        cfg.restore_poll_interval_ms = 0U;

        RecordingManagerListener listener;
        AlpsSppManager mgr(reactor, listener, cfg, &mem, &fake_link);
        REQUIRE(mgr.start());
        const int reg_before = fake_link.register_uuid_calls;

        std::vector<uint8_t> other(6U, 0x01U);
        other[1] = 0x33U;
        other[4] = 0x33U;
        mem.setSlotUniform(kAlpsSpareSlot, 1U, 0U, false, other);

        std::string err;
        CHECK(!mgr.stop(&err));
        CHECK(mgr.restoreAttempted());
        CHECK(!mgr.restoreSucceeded());
        CHECK(err.find("third-party") != std::string::npos);
        CHECK_EQ(reg_before, fake_link.register_uuid_calls);
    }
}

TEST_CASE(dbusAlpsSppLinkWithFakeDbusTable) {
#ifdef _WIN32
    std::printf("    [SKIP] DbusAlpsSppLink worker thread test skipped on Windows\n");
#else
    FakeDbusWorld::instance().reset();
    const DbusApi api = buildFakeDbusApi();

    Reactor reactor;
    REQUIRE(reactor.init());
    RecordingLinkListener listener;
    DbusAlpsSppLink link(reactor, &listener, &api);

    REQUIRE(link.start(kAlpsSpareSlot, false));
    CHECK(link.isRunning());

    // Set 0x6203 = 1 and read back (slot 5 write succeeds; slot 0 reads 1).
    CHECK(link.setDataInterface(kAlpsSpareSlot, 1U, 1000));
    std::vector<uint8_t> cfg_out;
    CHECK(link.readConfiguration(0U, kAlpsConfigDataInterface, cfg_out, 1000));
    REQUIRE(cfg_out.size() == 1U);
    CHECK_EQ(static_cast<uint8_t>(1U), cfg_out[0]);

    // Register CarPlay UUID pair via fake D-Bus.
    CHECK_EQ(0, link.registerUuidPayload(carplay::platform::carPlayIap2UuidPair(), 1000));
    {
        LockGuard g(FakeDbusWorld::instance().mu);
        REQUIRE(FakeDbusWorld::instance().sent_uuid_reqs.size() == 1U);
        CHECK_BYTES_EQ(carplay::platform::carPlayIap2UuidPair(),
                       FakeDbusWorld::instance().sent_uuid_reqs[0]);
    }

    // Inject BtApplDeviceConnectInd(status=0, addr=6B, function=1, instance=5)
    FakeDbusMsg* conn_sig = makeFakeSignal(kAlpsDbusDmInterface, "BtApplDeviceConnectInd", "yayty");
    {
        FakeDbusArg a0; a0.type = 'y'; a0.u8 = 0U;
        FakeDbusArg a1; a1.type = 'a';
        const uint8_t bd[6] = {0x06U, 0x05U, 0x04U, 0x03U, 0x02U, 0x01U};
        a1.bytes.assign(bd, bd + 6);
        FakeDbusArg a2; a2.type = 't'; a2.u64 = 1ULL;
        FakeDbusArg a3; a3.type = 'y'; a3.u8 = kAlpsSpareSlot;
        conn_sig->args.push_back(a0);
        conn_sig->args.push_back(a1);
        conn_sig->args.push_back(a2);
        conn_sig->args.push_back(a3);
    }
    FakeDbusWorld::instance().pushSignal(conn_sig);

    for (int i = 0; i < 40 && listener.connected_count < 1; ++i) {
        reactor.runOnce(20);
    }
    REQUIRE(listener.connected_count == 1);
    CHECK(link.isLinkUp());

    // Inject BtApplSppDataInd(instance=5, len=5, "hello")
    FakeDbusMsg* rx_sig = makeFakeSignal(kAlpsDbusSppInterface, "BtApplSppDataInd", "yqay");
    {
        FakeDbusArg a0; a0.type = 'y'; a0.u8 = kAlpsSpareSlot;
        FakeDbusArg a1; a1.type = 'q'; a1.u16 = 5U;
        FakeDbusArg a2; a2.type = 'a';
        const uint8_t msg[5] = {'h', 'e', 'l', 'l', 'o'};
        a2.bytes.assign(msg, msg + 5);
        rx_sig->args.push_back(a0);
        rx_sig->args.push_back(a1);
        rx_sig->args.push_back(a2);
    }
    FakeDbusWorld::instance().pushSignal(rx_sig);

    for (int i = 0; i < 40 && listener.received.size() < 5U; ++i) {
        reactor.runOnce(20);
    }
    CHECK_EQ(std::string("hello"),
             std::string(listener.received.begin(), listener.received.end()));

    // Test flow control pause -> sendData -> resume -> chunked DataReq (> 1024 bytes).
    FakeDbusMsg* fc_pause = makeFakeSignal(kAlpsDbusSppInterface, "BtApplSppDataSendFcInd", "yy");
    {
        FakeDbusArg a0; a0.type = 'y'; a0.u8 = kAlpsSpareSlot;
        FakeDbusArg a1; a1.type = 'y'; a1.u8 = 1U;  // non-zero pauses
        fc_pause->args.push_back(a0);
        fc_pause->args.push_back(a1);
    }
    FakeDbusWorld::instance().pushSignal(fc_pause);
    reactor.runOnce(20);

    std::vector<uint8_t> big_tx(1500U, 0x5aU);
    REQUIRE(link.sendData(&big_tx[0], big_tx.size()));

    FakeDbusMsg* fc_resume = makeFakeSignal(kAlpsDbusSppInterface, "BtApplSppDataSendFcInd", "yy");
    {
        FakeDbusArg a0; a0.type = 'y'; a0.u8 = kAlpsSpareSlot;
        FakeDbusArg a1; a1.type = 'y'; a1.u8 = 0U;  // zero resumes
        fc_resume->args.push_back(a0);
        fc_resume->args.push_back(a1);
    }
    FakeDbusWorld::instance().pushSignal(fc_resume);

    int tx_reqs = 0;
    for (int i = 0; i < 60 && tx_reqs < 2; ++i) {
        {
            LockGuard g(FakeDbusWorld::instance().mu);
            tx_reqs = FakeDbusWorld::instance().data_req_count;
        }
        reactor.runOnce(20);
    }
    {
        LockGuard g(FakeDbusWorld::instance().mu);
        REQUIRE(FakeDbusWorld::instance().sent_data_reqs.size() == 2U);
        CHECK_EQ(static_cast<size_t>(1024U), FakeDbusWorld::instance().sent_data_reqs[0].size());
        CHECK_EQ(static_cast<size_t>(476U), FakeDbusWorld::instance().sent_data_reqs[1].size());
    }

    // Remote disconnect
    FakeDbusMsg* disc_sig = makeFakeSignal(kAlpsDbusDmInterface, "BtApplDeviceDisconnectInd", "yayyty");
    {
        FakeDbusArg a0; a0.type = 'y'; a0.u8 = 0U;
        FakeDbusArg a1; a1.type = 'a'; a1.bytes.assign(6U, 0x11U);
        FakeDbusArg a2; a2.type = 'y'; a2.u8 = 2U;
        FakeDbusArg a3; a3.type = 't'; a3.u64 = 1ULL;
        FakeDbusArg a4; a4.type = 'y'; a4.u8 = kAlpsSpareSlot;
        disc_sig->args.push_back(a0);
        disc_sig->args.push_back(a1);
        disc_sig->args.push_back(a2);
        disc_sig->args.push_back(a3);
        disc_sig->args.push_back(a4);
    }
    FakeDbusWorld::instance().pushSignal(disc_sig);
    for (int i = 0; i < 40 && listener.disconnected_count < 1; ++i) {
        reactor.runOnce(20);
    }
    CHECK_EQ(1, listener.disconnected_count);
    CHECK(!link.isLinkUp());

    link.stop();
    CHECK(!link.isRunning());
#endif
}

TEST_CASE(btTransportSelectionAndByteSink) {
    // 1. Both ALPS and RFCOMM capable -> ALPS preferred!
    BtTransportCapability cap;
    cap.alps_library_present = true;
    cap.alps_dbus_ready = true;
    cap.rfcomm.af_bluetooth_supported = true;
    cap.rfcomm.has_hci_device = true;
    CHECK_EQ(kBtBackendAlpsSpp, carplay::platform::selectBtBackend(cap));

    // 2. ALPS missing (D-Bus or libevo_btappl missing), RFCOMM capable -> RFCOMM fallback.
    cap.alps_dbus_ready = false;
    CHECK_EQ(kBtBackendRfcomm, carplay::platform::selectBtBackend(cap));

    // 3. Neither capable -> kBtBackendNone, createBtTransport returns NULL.
    cap.rfcomm.has_hci_device = false;
    CHECK_EQ(kBtBackendNone, carplay::platform::selectBtBackend(cap));

    Reactor reactor;
    REQUIRE(reactor.init());
    RecordingTransportListener listener;
    CHECK(carplay::platform::createBtTransport(reactor, listener, cap).get() == NULL);

    // 4. AlpsBtTransport + BtTransportByteSink wired to real carplay::iap2::Link.
    FakeSppMemoryBackend mem;
    mem.setSlotDisconnectedGeneric(kAlpsBmwAppsSlot);
    mem.setSlotDisconnectedGeneric(kAlpsNativeCarPlaySlot);
    mem.setSlotDisconnectedGeneric(kAlpsSpareSlot);
    FakeAlpsSppLink fake_link(&mem);

    AlpsSppManagerConfig cfg;
    cfg.double_read_delay_ms = 0U;
    cfg.restore_poll_interval_ms = 0U;

    AlpsBtTransport transport(reactor, listener, cfg, &mem, &fake_link);
    CHECK_EQ(kBtBackendAlpsSpp, transport.backendKind());
    CHECK_EQ(std::string("alps-spp"), std::string(transport.backendName()));
    REQUIRE(transport.start());

    BtTransportByteSink sink(transport);
    RecordingIap2Listener iap2_listener;
    carplay::iap2::Link iap2_link(sink, iap2_listener);

    BtAddr peer;
    REQUIRE(BtAddr::parse("AA:BB:CC:DD:EE:11", peer));
    fake_link.simulateConnect(peer);
    CHECK_EQ(1, listener.connected_count);

    iap2_link.start();
    CHECK_BYTES_EQ(
        std::vector<uint8_t>(carplay::iap2::kDetectSequence,
                             carplay::iap2::kDetectSequence + carplay::iap2::kDetectSequenceBytes),
        fake_link.tx_bytes);

    transport.stop();
    CHECK(transport.manager().restoreSucceeded());

    // 5. AdvertisementSchedule exact milestones (15s, 45s, 90s, then repeat_ms).
    AdvertisementSchedule sched(60000U);
    CHECK(!sched.due(14999U));
    CHECK(sched.due(15000U));
    CHECK(!sched.due(44999U));
    CHECK(sched.due(45000U));
    CHECK(!sched.due(89999U));
    CHECK(sched.due(90000U));
    CHECK(!sched.due(149999U));
    CHECK(sched.due(150000U));
    CHECK(!sched.due(180000U));
    CHECK(sched.due(210000U));
}

TEST_CASE(probeBtTransportCapabilityWithSyntheticProc) {
#ifdef _WIN32
    std::printf("    [SKIP] synthetic /proc probe test skipped on Windows\n");
#else
    char tmp_template[] = "/tmp/carplay_alps_proc_XXXXXX";
    char* tmp_dir = ::mkdtemp(tmp_template);
    REQUIRE(tmp_dir != NULL);

    const std::string proc_dir = std::string(tmp_dir) + "/proc";
    const std::string pid_dir = proc_dir + "/777";
    const std::string root_dir = pid_dir + "/root";
    const std::string lib_dir = root_dir + "/opt";
    REQUIRE(::mkdir(proc_dir.c_str(), 0700) == 0);
    REQUIRE(::mkdir(pid_dir.c_str(), 0700) == 0);
    REQUIRE(::mkdir(root_dir.c_str(), 0700) == 0);
    REQUIRE(::mkdir(lib_dir.c_str(), 0700) == 0);

    const std::string elf_path = lib_dir + "/libevo_btappl.so";
    const std::vector<uint8_t> elf_bytes = buildValidAlpsElf();
    {
        const int fd = ::open(elf_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        REQUIRE(fd >= 0);
        REQUIRE(::write(fd, &elf_bytes[0], elf_bytes.size()) ==
                static_cast<ssize_t>(elf_bytes.size()));
        ::close(fd);
    }

    const std::string maps_path = pid_dir + "/maps";
    {
        const std::string map_line =
            "b6000000-b6040000 r-xp 00000000 b3:02 123 /opt/libevo_btappl.so\n";
        const int fd = ::open(maps_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        REQUIRE(fd >= 0);
        REQUIRE(::write(fd, map_line.data(), map_line.size()) ==
                static_cast<ssize_t>(map_line.size()));
        ::close(fd);
    }

    BtTransportProbePaths paths;
    paths.proc_root = proc_dir;
    paths.probe_alps_dbus = false;
    paths.rfcomm_paths.sys_class_bluetooth = std::string(tmp_dir) + "/missing_sys";
    paths.rfcomm_paths.sdpd_socket = std::string(tmp_dir) + "/missing_sdp";
    paths.rfcomm_paths.bluetoothd_socket = std::string(tmp_dir) + "/missing_btd";
    paths.rfcomm_paths.dbus_socket = std::string(tmp_dir) + "/missing_dbus";
    paths.rfcomm_paths.probe_af_bluetooth = false;

    const BtTransportCapability cap = carplay::platform::probeBtTransportCapability(paths);
    CHECK(cap.alps_library_present);
    CHECK(!cap.alps_dbus_ready);
    CHECK(!cap.alpsCapable());
    CHECK_EQ(kBtBackendNone, carplay::platform::selectBtBackend(cap));
    const std::string formatted = carplay::platform::formatBtTransportCapability(cap);
    CHECK(formatted.find("alps_lib=yes") != std::string::npos);

    ::unlink(maps_path.c_str());
    ::unlink(elf_path.c_str());
    ::rmdir(lib_dir.c_str());
    ::rmdir(root_dir.c_str());
    ::rmdir(pid_dir.c_str());
    ::rmdir(proc_dir.c_str());
    ::rmdir(tmp_dir);
#endif
}

TEST_CASE(alpsCompatProbeAndUnknownVariant15024) {
#ifdef _WIN32
    std::printf("    [SKIP] ALPS compat /proc probe test skipped on Windows\n");
#else
    // 1. Unknown library build (F20 2017 variant 15024/480/36 reported in upstream #106) is
    //    rejected safely before reading memory offsets, and falls back cleanly without blocking
    //    USB mode.
    std::vector<SynthSymSpec> syms15024;
    SynthSymSpec a;
    a.name = "app";
    a.value = 0x20000U;
    a.size = 15024U;
    a.shndx = 1U;
    a.got_offset = 0x1000U;
    syms15024.push_back(a);
    SynthSymSpec i;
    i.name = "spp_info";
    i.value = 0x24000U;
    i.size = kAlpsSppInfoSymbolSize;
    i.shndx = 1U;
    i.got_offset = 0x1004U;
    syms15024.push_back(i);
    SynthSymSpec c;
    c.name = "spp_connected";
    c.value = 0x25000U;
    c.size = kAlpsSppConnectedSymbolSize;
    c.shndx = 1U;
    c.got_offset = 0x1008U;
    syms15024.push_back(c);
    const std::vector<uint8_t> elf_15024 = buildSyntheticArmElf(syms15024);

    char tmp_template[] = "/tmp/carplay_alps_15024_XXXXXX";
    char* tmp_dir = ::mkdtemp(tmp_template);
    REQUIRE(tmp_dir != NULL);
    const std::string proc_dir = std::string(tmp_dir) + "/proc";
    const std::string pid_dir = proc_dir + "/888";
    const std::string root_dir = pid_dir + "/root";
    const std::string lib_dir = root_dir + "/opt";
    REQUIRE(::mkdir(proc_dir.c_str(), 0700) == 0);
    REQUIRE(::mkdir(pid_dir.c_str(), 0700) == 0);
    REQUIRE(::mkdir(root_dir.c_str(), 0700) == 0);
    REQUIRE(::mkdir(lib_dir.c_str(), 0700) == 0);
    const std::string elf_path = lib_dir + "/libevo_btappl.so";
    {
        const int fd = ::open(elf_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        REQUIRE(fd >= 0);
        REQUIRE(::write(fd, &elf_15024[0], elf_15024.size()) ==
                static_cast<ssize_t>(elf_15024.size()));
        ::close(fd);
    }
    const std::string maps_path = pid_dir + "/maps";
    {
        const std::string map_line =
            "b6000000-b6040000 r-xp 00000000 b3:02 123 /opt/libevo_btappl.so\n";
        const int fd = ::open(maps_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        REQUIRE(fd >= 0);
        REQUIRE(::write(fd, map_line.data(), map_line.size()) ==
                static_cast<ssize_t>(map_line.size()));
        ::close(fd);
    }

    BtTransportProbePaths paths;
    paths.proc_root = proc_dir;
    paths.probe_alps_dbus = false;
    paths.rfcomm_paths.sys_class_bluetooth = std::string(tmp_dir) + "/missing_sys";
    paths.rfcomm_paths.sdpd_socket = std::string(tmp_dir) + "/missing_sdp";
    paths.rfcomm_paths.bluetoothd_socket = std::string(tmp_dir) + "/missing_btd";
    paths.rfcomm_paths.dbus_socket = std::string(tmp_dir) + "/missing_dbus";
    paths.rfcomm_paths.probe_af_bluetooth = false;

    const BtTransportCapability cap_unknown =
        carplay::platform::probeBtTransportCapability(paths);
    CHECK(!cap_unknown.alps_library_present);
    CHECK(cap_unknown.alps_detail.find("15024/480/36") != std::string::npos);
    CHECK_EQ(kBtBackendNone, carplay::platform::selectBtBackend(cap_unknown));

    const carplay::platform::AlpsCompatReport rep_wireless =
        carplay::platform::probeAlpsSppCompat(cap_unknown, NULL, false);
    CHECK(!rep_wireless.wireless_ready);
    CHECK_EQ(carplay::platform::kCompatFail, rep_wireless.alps.level);
    CHECK(rep_wireless.alps.detail.find("15024/480/36") != std::string::npos);
    CHECK(rep_wireless.alps.detail.find("wireless only") != std::string::npos);
    CHECK_EQ(carplay::platform::kCompatInfo, rep_wireless.uuid.level);
    CHECK_EQ(carplay::platform::kCompatFail, rep_wireless.spp.level);

    const carplay::platform::AlpsCompatReport rep_usb =
        carplay::platform::probeAlpsSppCompat(cap_unknown, NULL, true);
    CHECK(!rep_usb.wireless_ready);
    CHECK(rep_usb.usb_mode);
    CHECK_EQ(carplay::platform::kCompatInfo, rep_usb.alps.level);
    CHECK_EQ(carplay::platform::kCompatInfo, rep_usb.uuid.level);
    CHECK_EQ(carplay::platform::kCompatInfo, rep_usb.spp.level);
    CHECK(carplay::platform::formatAlpsCompatReport(rep_usb).find("[alps:info ") !=
          std::string::npos);

    ::unlink(maps_path.c_str());
    ::unlink(elf_path.c_str());
    ::rmdir(lib_dir.c_str());
    ::rmdir(root_dir.c_str());
    ::rmdir(pid_dir.c_str());
    ::rmdir(proc_dir.c_str());
    ::rmdir(tmp_dir);
#endif

    // 2. Compatible ALPS library + snapshot + readBmwAppsSlot (slot 0 idle vs connected).
    FakeSppMemoryBackend mem;
    for (unsigned s = 0U; s < kAlpsMaxInstances; ++s) {
        mem.setSlotDisconnectedGeneric(s);
    }
    mem.setSlotUniform(kAlpsNativeCarPlaySlot,
                       1U,
                       0U,
                       false,
                       carplay::platform::carPlayIap2UuidPair());

    BtTransportCapability cap_ok;
    cap_ok.alps_library_present = true;
    cap_ok.alps_dbus_ready = true;
    cap_ok.alps_service_owned = true;
    cap_ok.alps_detail = "found";

    const carplay::platform::AlpsCompatReport rep_ok =
        carplay::platform::probeAlpsSppCompat(cap_ok, &mem, false);
    CHECK(rep_ok.wireless_ready);
    CHECK_EQ(carplay::platform::kCompatPass, rep_ok.alps.level);
    CHECK_EQ(carplay::platform::kCompatPass, rep_ok.uuid.level);
    CHECK_EQ(carplay::platform::kCompatPass, rep_ok.spp.level);

    SppSnapshotReader apps_reader(&mem);
    REQUIRE(apps_reader.open());
    carplay::platform::AppsSlot apps;
    REQUIRE(carplay::platform::readBmwAppsSlot(apps_reader, apps));
    CHECK(apps.read);
    CHECK(!apps.connected);
    CHECK_EQ(1U, apps.state);
    CHECK_EQ(0U, static_cast<unsigned>(apps.transport));

    // When BMW Apps slot 0 is connected and native slot 1 holds generic UUID, slot 5 is borrowed
    // and compat report marks alps with kCompatWarn mentioning slot0_apps=connected.
    mem.setSlotUniform(kAlpsBmwAppsSlot,
                       2U,
                       4U,
                       true,
                       carplay::platform::genericSppUuidPair());
    mem.setSlotDisconnectedGeneric(kAlpsNativeCarPlaySlot);
    REQUIRE(carplay::platform::readBmwAppsSlot(apps_reader, apps));
    CHECK(apps.read);
    CHECK(apps.connected);
    CHECK_EQ(2U, apps.state);
    CHECK_EQ(4U, static_cast<unsigned>(apps.transport));

    const carplay::platform::AlpsCompatReport rep_apps =
        carplay::platform::probeAlpsSppCompat(cap_ok, &mem, false);
    CHECK(rep_apps.wireless_ready);
    CHECK_EQ(carplay::platform::kCompatWarn, rep_apps.alps.level);
    CHECK(rep_apps.alps.detail.find("slot0_apps=connected") != std::string::npos);
}

int main() {
    return test_support::runAll("test_alps_spp");
}
