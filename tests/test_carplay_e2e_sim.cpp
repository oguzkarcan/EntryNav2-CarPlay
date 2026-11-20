// End-to-end host simulation tests for CarPlayDaemon + CarPlayConnectivity:
//   * Wireless: BT connect (real AlpsBtTransport borrowing slot 5) -> iAP2 link SYN/ACK ->
//     identification (wireless profile) -> auth (FakeAuthProvider) -> Wi-Fi AP (car-native +
//     hostapd fallback) -> 0x5702/0x5703 WiFi config -> 0x4300/0x4301 -> mDNS (_airplay._tcp) ->
//     BT handoff disconnect -> TCP connect to SessionServer (pair-verify, /info, SETUP) -> teardown
//   * Wired: USB arrival (coexistence-safe) -> NCM/TAP up -> iAP2 link SYN/ACK -> identification
//     (wired profile) -> auth -> 0xAE03/subscriptions -> 0x4300/0x4301 (TAP IPv6) ->
//     TCP connect to SessionServer -> teardown / unplug
//   * Failure injection: AP fails, auth fails (wireless & wired), phone disappears mid-session,
//     ALPS slot 5 always restored (on stop, failure, and destruction), one active phone at a time.

#include "carplay/airplay_crypto.hpp"
#include "carplay/bplist_codec.hpp"
#include "carplay/control_cipher.hpp"
#include "carplay/dnssd_txt.hpp"
#include "carplay/iap2_link.hpp"
#include "carplay/iap2_session.hpp"
#include "carplay/iap2_wire.hpp"
#include "carplay/platform/alps_spp.hpp"
#include "carplay/platform/bt_transport.hpp"
#include "carplay/platform/carplay_connectivity.hpp"
#include "carplay/platform/carplay_daemon.hpp"
#include "carplay/platform/evo_ap.hpp"
#include "carplay/platform/evo_wlan.hpp"
#include "carplay/platform/hostapd_ctrl.hpp"
#include "carplay/platform/mdns_advertiser.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/spp_snapshot.hpp"
#include "carplay/platform/tap_iface.hpp"
#include "carplay/platform/usb_host.hpp"
#include "carplay/rtsp_message.hpp"
#include "carplay/tlv8_codec.hpp"
#include "test_support.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include <deque>
#include <memory>
#include <string>
#include <vector>

struct carplay_DNSServiceRef_t {
    carplay::platform::SocketHandle read_fd;
    carplay::platform::SocketHandle write_fd;
    carplay::platform::DnsServiceRegisterReplyFn callback;
    void* context;
    std::string name;
    std::string regtype;
    std::string domain;
    uint16_t port_be;
    std::vector<uint8_t> txt;
};

namespace {

namespace crypto = carplay::crypto;
namespace dnssd = carplay::dnssd;
namespace iap2 = carplay::iap2;
namespace ncm = carplay::ncm;
namespace plat = carplay::platform;
namespace rtsp = carplay::rtsp;
namespace tlv8 = carplay::tlv8;
namespace usb = carplay::usb;

typedef std::vector<uint8_t> Bytes;
typedef std::vector<tlv8::Item> Items;

std::string makeTempDir(const char* prefix) {
#ifndef _WIN32
    char tmpl[128];
    snprintf(tmpl, sizeof(tmpl), "/tmp/%s_XXXXXX", prefix ? prefix : "cp_e2e_sim");
    char* d = mkdtemp(tmpl);
    return d ? std::string(d) : std::string("/tmp/cp_e2e_sim_fallback");
#else
    (void)prefix;
    return "build/cp_e2e_sim_tmp";
#endif
}

void removeTempDir(const std::string& dir) {
    if (dir.empty()) {
        return;
    }
#ifndef _WIN32
    std::string cmd = "rm -rf \"" + dir + "\"";
    const int rc = system(cmd.c_str());
    (void)rc;
#endif
}

void pushU16Le(Bytes& v, uint16_t val) {
    v.push_back(static_cast<uint8_t>(val & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 8) & 0xffU));
}

void pushU32Le(Bytes& v, uint32_t val) {
    v.push_back(static_cast<uint8_t>(val & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 8) & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 16) & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 24) & 0xffU));
}

Bytes sha512Bytes(const Bytes& data) {
    Bytes out(64);
    crypto::sha512(data.empty() ? NULL : &data[0], data.size(), &out[0]);
    return out;
}

Bytes strToBytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

Bytes hkdf32(const Bytes& ikm, const std::string& salt, const std::string& info_label) {
    Bytes out;
    crypto::hkdfSha512(ikm, salt, info_label, 32, out);
    return out;
}

Bytes makeLabelNonce12(const char* label) {
    Bytes n(12, 0);
    memcpy(&n[4], label, 8);
    return n;
}

Bytes encodeBplist(const carplay::bplist::Value& v) {
    Bytes b;
    carplay::bplist::encode(v, b);
    return b;
}

// =================================================================================================
// Fake ALPS SPP memory + D-Bus link (exercises real AlpsSppManager slot-5 borrow & restore)
// =================================================================================================

class SimSppMemoryBackend : public plat::SppMemoryBackend {
public:
    SimSppMemoryBackend()
        : is_open_(false), pid_(4242), base_address_(0x10000000U), identity_("123456") {
        layout_.app = 0x20000U;
        layout_.info = 0x24000U;
        layout_.connections = 0x25000U;
        layout_.app_got = 0x1000U;
        layout_.info_got = 0x1004U;
        layout_.connections_got = 0x1008U;
        mem_.assign(0x26000U, 0U);
        writeMemU32(layout_.app_got, base_address_ + layout_.app);
        writeMemU32(layout_.info_got, base_address_ + layout_.info);
        writeMemU32(layout_.connections_got, base_address_ + layout_.connections);

        setSlotDisconnectedGeneric(plat::kAlpsBmwAppsSlot);
        setSlotDisconnectedGeneric(plat::kAlpsNativeCarPlaySlot);
        setSlotDisconnectedGeneric(plat::kAlpsSpareSlot);
    }

    virtual bool openProcess(plat::SppProcessTarget& target_out, std::string* /*error_out*/) {
        is_open_ = true;
        target_out.pid = pid_;
        target_out.base_address = base_address_;
        target_out.layout = layout_;
        target_out.identity = identity_;
        return true;
    }

    virtual void closeProcess() { is_open_ = false; }
    virtual bool isOpen() const { return is_open_; }

    virtual bool readStartIdentity(int req_pid, std::string& identity_out) {
        if (req_pid != pid_) return false;
        identity_out = identity_;
        return true;
    }

    virtual bool readBytes(uint32_t address, void* out, size_t len) {
        if (!is_open_ || address < base_address_) return false;
        const uint32_t rel = address - base_address_;
        if (rel >= mem_.size() || len > mem_.size() - rel) return false;
        memcpy(out, &mem_[rel], len);
        return true;
    }

    virtual void sleepMs(uint32_t /*ms*/) {}

    void writeMemU32(uint32_t rel_offset, uint32_t v) {
        mem_[rel_offset + 0U] = static_cast<uint8_t>(v & 0xffU);
        mem_[rel_offset + 1U] = static_cast<uint8_t>((v >> 8) & 0xffU);
        mem_[rel_offset + 2U] = static_cast<uint8_t>((v >> 16) & 0xffU);
        mem_[rel_offset + 3U] = static_cast<uint8_t>((v >> 24) & 0xffU);
    }

    void setSlotUuid(unsigned slot, const Bytes& uuid_pair, uint32_t app_state, uint32_t conn_flag) {
        if (slot >= plat::kAlpsMaxInstances) return;
        writeMemU32(layout_.app + plat::kAlpsAppStateOffset + slot * 4U, app_state);
        uint8_t* rec = &mem_[layout_.app + plat::kAlpsAppRecordOffset + slot * plat::kAlpsAppRecordStride];
        memset(rec, 0, plat::kAlpsAppRecordStride);
        uint8_t* inf = &mem_[layout_.info + slot * plat::kAlpsSppInfoStride];
        memset(inf, 0, plat::kAlpsSppInfoStride);
        inf[4] = 0U;
        uint8_t* conn = &mem_[layout_.connections + slot * plat::kAlpsSppConnectedStride];
        memset(conn, 0, plat::kAlpsSppConnectedStride);
        conn[0] = conn_flag ? 1U : 0U;

        static const size_t kLen[4] = {0U, 2U, 4U, 16U};
        static const uint8_t kTag[4] = {0U, 1U, 2U, 4U};
        size_t pos = 0U;
        for (unsigned i = 0U; i < 2U && pos < uuid_pair.size(); ++i) {
            const uint8_t kind = uuid_pair[pos++];
            if (kind < 1U || kind > 3U || kLen[kind] > uuid_pair.size() - pos) return;
            rec[32U + i] = kind;
            memcpy(rec + 16U * i, &uuid_pair[pos], kLen[kind]);
            const unsigned tag_off = (i == 0U) ? 38U : 55U;
            const unsigned dat_off = (i == 0U) ? 39U : 56U;
            inf[tag_off] = kTag[kind];
            memcpy(inf + dat_off, &uuid_pair[pos], kLen[kind]);
            pos += kLen[kind];
        }
    }

    void setSlotDisconnectedGeneric(unsigned slot) {
        setSlotUuid(slot, plat::genericSppUuidPair(), 1U, 0U);
    }

    bool slotMatchesGeneric(unsigned slot) const {
        return slotMatchesPair(slot, plat::genericSppUuidPair());
    }

    bool slotMatchesCarPlay(unsigned slot) const {
        return slotMatchesPair(slot, plat::carPlayIap2UuidPair());
    }

    bool slotMatchesPair(unsigned slot, const Bytes& expected) const {
        if (slot >= plat::kAlpsMaxInstances) return false;
        const uint8_t* rec = &mem_[layout_.app + plat::kAlpsAppRecordOffset + slot * plat::kAlpsAppRecordStride];
        Bytes actual;
        for (unsigned i = 0U; i < 2U; ++i) {
            const uint8_t kind = rec[32U + i];
            const size_t len = (kind == 1U) ? 2U : (kind == 2U ? 4U : (kind == 3U ? 16U : 0U));
            if (len == 0U) return false;
            actual.push_back(kind);
            actual.insert(actual.end(), rec + 16U * i, rec + 16U * i + len);
        }
        return actual == expected;
    }

    bool is_open_;
    int pid_;
    uint32_t base_address_;
    plat::SppLayout layout_;
    std::string identity_;
    Bytes mem_;
};

class SimAlpsSppLink : public plat::AlpsSppLink {
public:
    explicit SimAlpsSppLink(SimSppMemoryBackend* mem)
        : mem_(mem),
          listener_(NULL),
          running_(false),
          link_up_(false),
          instance_(0U),
          last_data_interface(0xffU),
          register_calls(0),
          set_iface_calls(0),
          current_uuid_(plat::genericSppUuidPair()) {}

    virtual bool start(uint8_t instance, bool /*monitor_only*/ = false) {
        instance_ = instance;
        running_ = true;
        return true;
    }
    virtual void stop() {
        link_up_ = false;
        running_ = false;
    }
    virtual bool isRunning() const { return running_; }
    virtual bool isLinkUp() const { return link_up_; }
    virtual void setListener(plat::AlpsSppLinkListener* listener) { listener_ = listener; }

    virtual int registerUuidPayload(const Bytes& payload, int /*timeout_ms*/) {
        ++register_calls;
        current_uuid_ = payload;
        if (mem_ != NULL) {
            mem_->setSlotUuid(instance_, current_uuid_, 1U, link_up_ ? 1U : 0U);
        }
        return 0;
    }
    virtual bool readConfiguration(uint8_t /*instance*/, uint16_t /*id*/, Bytes& out, int /*timeout_ms*/) {
        out.assign(1U, last_data_interface);
        return true;
    }
    virtual bool setDataInterface(uint8_t /*instance*/, uint8_t value, int /*timeout_ms*/) {
        ++set_iface_calls;
        last_data_interface = value;
        return true;
    }
    virtual bool requestSppDisconnect() {
        if (mem_ != NULL) {
            mem_->setSlotUuid(instance_, current_uuid_, 1U, 0U);
        }
        return true;
    }
    virtual void disconnectLink(const std::string& reason = "local disconnect") {
        if (mem_ != NULL) {
            mem_->setSlotUuid(instance_, current_uuid_, 1U, 0U);
        }
        if (link_up_) {
            link_up_ = false;
            if (listener_ != NULL) {
                listener_->onAlpsDisconnected(reason);
            }
        }
    }
    virtual bool sendData(const uint8_t* data, size_t len) {
        if (!running_ || !link_up_ || data == NULL || len == 0U) {
            return false;
        }
        tx_to_phone.insert(tx_to_phone.end(), data, data + len);
        return true;
    }
    virtual const std::string& lastError() const { return last_err_; }

    void simulateConnect(const plat::BtAddr& peer) {
        link_up_ = true;
        if (mem_ != NULL) {
            mem_->setSlotUuid(instance_, current_uuid_, 1U, 1U);
        }
        if (listener_ != NULL) {
            listener_->onAlpsConnected(peer);
        }
    }

    void simulateRx(const Bytes& data) {
        if (link_up_ && listener_ != NULL && !data.empty()) {
            listener_->onAlpsData(&data[0], data.size());
        }
    }

    void simulateDisconnect(const std::string& reason) {
        link_up_ = false;
        if (mem_ != NULL) {
            mem_->setSlotUuid(instance_, current_uuid_, 1U, 0U);
        }
        if (listener_ != NULL) {
            listener_->onAlpsDisconnected(reason);
        }
    }

    SimSppMemoryBackend* mem_;
    plat::AlpsSppLinkListener* listener_;
    bool running_;
    bool link_up_;
    uint8_t instance_;
    uint8_t last_data_interface;
    int register_calls;
    int set_iface_calls;
    Bytes current_uuid_;
    Bytes tx_to_phone;
    std::string last_err_;
};

// =================================================================================================
// Fake Wi-Fi AP (Native WLAN + Hostapd fallback) & Fake mDNS
// =================================================================================================

class SimWlanController : public plat::IWlanController {
public:
    SimWlanController()
        : listener_(NULL),
          available_(true),
          fail_begin_enable(false),
          fail_async_enable(false),
          enable_calls(0),
          restore_calls(0) {}

    virtual void setListener(plat::WlanControllerListener* listener) { listener_ = listener; }
    virtual bool isAvailable() const { return available_; }
    virtual bool isBusy() const { return false; }

    virtual bool beginEnable(unsigned /*timeout_ms*/, std::string* error_out = NULL) {
        ++enable_calls;
        if (fail_begin_enable) {
            if (error_out != NULL) {
                *error_out = "injected wlan beginEnable failure";
            }
            return false;
        }
        plat::WlanRequestResult r;
        r.connected = true;
        r.state_before = 0;
        r.sent = true;
        r.state_after = fail_async_enable ? 0 : 1;
        r.switched_on_by_us = !fail_async_enable;
        if (listener_ != NULL) {
            listener_->onWlanEnableResult(!fail_async_enable, r,
                                          fail_async_enable ? "injected vmostd reject" : "");
        }
        return true;
    }

    virtual bool beginDisable(unsigned /*timeout_ms*/, std::string* /*error_out*/ = NULL) {
        return true;
    }
    virtual void cancel() {}
    virtual bool restoreSync(unsigned /*timeout_ms*/, std::string* /*error_out*/ = NULL) {
        ++restore_calls;
        return true;
    }

    plat::WlanControllerListener* listener_;
    bool available_;
    bool fail_begin_enable;
    bool fail_async_enable;
    int enable_calls;
    int restore_calls;
};

class SimAccessPointReader : public plat::IAccessPointReader {
public:
    SimAccessPointReader()
        : raw_cfg("ssid=BMW-CarPlay-Test\nwpa_passphrase=TestPass1234\nbssid=02:aa:bb:cc:dd:99\nchannel=36\n") {}

    virtual bool isNativeEnvironmentPresent(const plat::NativeWlanPaths& /*paths*/) const {
        return true;
    }
    virtual bool readAccessPoint(const plat::NativeWlanPaths& /*paths*/,
                                 plat::EvoApInfo& out,
                                 std::string& source_out,
                                 std::string* error_out = NULL) {
        if (!plat::parseHostapdConfig(raw_cfg, out)) {
            if (error_out) *error_out = "parseHostapdConfig failed";
            return false;
        }
        source_out = "sim-native-ap";
        return true;
    }
    virtual bool readFrequencyMhz(const std::string& /*iface*/, unsigned& mhz_out) {
        mhz_out = 5180U;
        return true;
    }
    virtual bool readConnectedStations(const std::string& /*iface*/,
                                       std::vector<std::string>& macs_out) {
        macs_out = stations;
        return true;
    }

    std::string raw_cfg;
    std::vector<std::string> stations;
};

class SimHostapdCtrl : public plat::IHostapdCtrl {
public:
    SimHostapdCtrl() : listener_(NULL), open_(false) {}

    virtual void setListener(plat::HostapdCtrlListener* listener) { listener_ = listener; }
    virtual bool open(const std::string&, const std::string&, std::string* err) {
        if (err) *err = "ctrl unused in native sim";
        return false;
    }
    virtual void close() { open_ = false; }
    virtual bool isOpen() const { return open_; }
    virtual bool sendPing(int) { return false; }
    virtual bool sendAttach(int) { return false; }
    virtual bool sendDetach(int) { return false; }
    virtual bool sendStatus(int) { return false; }
    virtual bool sendGetConfig(int) { return false; }
    virtual bool sendAllSta(int) { return false; }
    virtual bool sendEnable(int) { return false; }
    virtual bool sendDisable(int) { return false; }
    virtual bool sendCommand(plat::HostapdCommandKind, const std::string&, int) { return false; }

    plat::HostapdCtrlListener* listener_;
    bool open_;
};

struct SimDnsSdState {
    int register_calls;
    int deallocate_calls;
    uint16_t last_port_host;
    std::string last_name;
    std::string last_regtype;
    Bytes last_txt;
    std::vector<carplay_DNSServiceRef_t*> live_refs;

    SimDnsSdState() : register_calls(0), deallocate_calls(0), last_port_host(0U) {}
};

SimDnsSdState* g_sim_dnssd = NULL;

plat::DnsServiceErrorType simDnsRegister(plat::DnsServiceRef* sdRef,
                                         plat::DnsServiceFlags /*flags*/,
                                         uint32_t /*iface*/,
                                         const char* name,
                                         const char* regtype,
                                         const char* domain,
                                         const char* /*host*/,
                                         uint16_t port_be,
                                         uint16_t txtLen,
                                         const void* txtRecord,
                                         plat::DnsServiceRegisterReplyFn callBack,
                                         void* context) {
    ++g_sim_dnssd->register_calls;
    plat::SocketHandle r = plat::kInvalidSocket;
    plat::SocketHandle w = plat::kInvalidSocket;
    if (!plat::wakePairOpen(r, w)) {
        return plat::kDnsServiceErrUnknown;
    }
    carplay_DNSServiceRef_t* ref = new carplay_DNSServiceRef_t();
    ref->read_fd = r;
    ref->write_fd = w;
    ref->callback = callBack;
    ref->context = context;
    ref->name = name ? name : "BMW";
    ref->regtype = regtype ? regtype : "_airplay._tcp";
    ref->domain = domain ? domain : "local.";
    ref->port_be = port_be;
    if (txtLen > 0U && txtRecord != NULL) {
        const uint8_t* p = static_cast<const uint8_t*>(txtRecord);
        ref->txt.assign(p, p + txtLen);
    }

    const uint16_t hi = static_cast<uint16_t>(port_be & 0xffU);
    const uint16_t lo = static_cast<uint16_t>((port_be >> 8) & 0xffU);
    g_sim_dnssd->last_port_host = static_cast<uint16_t>((hi << 8) | lo);
    g_sim_dnssd->last_name = ref->name;
    g_sim_dnssd->last_regtype = ref->regtype;
    g_sim_dnssd->last_txt = ref->txt;
    g_sim_dnssd->live_refs.push_back(ref);

    plat::wakeSignal(w);
    *sdRef = ref;
    return plat::kDnsServiceErrNoError;
}

int simDnsRefSockFd(plat::DnsServiceRef sdRef) {
    return sdRef != NULL ? static_cast<int>(sdRef->read_fd) : -1;
}

plat::DnsServiceErrorType simDnsProcessResult(plat::DnsServiceRef sdRef) {
    if (sdRef == NULL) return plat::kDnsServiceErrUnknown;
    plat::wakeDrain(sdRef->read_fd);
    if (sdRef->callback != NULL) {
        sdRef->callback(sdRef, plat::kDnsServiceFlagsAdd, plat::kDnsServiceErrNoError,
                        sdRef->name.c_str(), sdRef->regtype.c_str(), sdRef->domain.c_str(),
                        sdRef->context);
    }
    return plat::kDnsServiceErrNoError;
}

void simDnsDeallocate(plat::DnsServiceRef sdRef) {
    ++g_sim_dnssd->deallocate_calls;
    if (sdRef == NULL) return;
    plat::wakePairClose(sdRef->read_fd, sdRef->write_fd);
    for (size_t i = 0U; i < g_sim_dnssd->live_refs.size(); ++i) {
        if (g_sim_dnssd->live_refs[i] == sdRef) {
            g_sim_dnssd->live_refs.erase(g_sim_dnssd->live_refs.begin() + static_cast<ptrdiff_t>(i));
            break;
        }
    }
    delete sdRef;
}

plat::DnsSdApi makeSimDnsSdApi() {
    plat::DnsSdApi api;
    api.register_service = &simDnsRegister;
    api.ref_sock_fd = &simDnsRefSockFd;
    api.process_result = &simDnsProcessResult;
    api.ref_deallocate = &simDnsDeallocate;
    return api;
}

// =================================================================================================
// Fake USB Host & TAP Port (tracks claimed/released interfaces and TAP open/close)
// =================================================================================================

Bytes buildCarPlayUsbBlob() {
    Bytes body;
    // Interface 0: Apple iAP2 (0xff/0xf0/0x00), Bulk IN 0x81, Bulk OUT 0x01
    body.push_back(9U); body.push_back(usb::kDescTypeInterface); body.push_back(0U); body.push_back(0U);
    body.push_back(2U); body.push_back(usb::kAppleIap2Class); body.push_back(usb::kAppleIap2SubClass);
    body.push_back(usb::kAppleIap2Protocol); body.push_back(0U);
    body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x81U);
    body.push_back(usb::kEpTypeBulk); pushU16Le(body, 512U); body.push_back(0U);
    body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x01U);
    body.push_back(usb::kEpTypeBulk); pushU16Le(body, 512U); body.push_back(0U);

    // Interface 1: CDC-NCM Control
    body.push_back(9U); body.push_back(usb::kDescTypeInterface); body.push_back(1U); body.push_back(0U);
    body.push_back(1U); body.push_back(usb::kClassCommunications); body.push_back(usb::kSubClassCdcNcm);
    body.push_back(0U); body.push_back(0U);
    body.push_back(5U); body.push_back(usb::kDescTypeCsInterface); body.push_back(usb::kCdcSubtypeHeader);
    pushU16Le(body, 0x0120U);
    body.push_back(5U); body.push_back(usb::kDescTypeCsInterface); body.push_back(usb::kCdcSubtypeUnion);
    body.push_back(1U); body.push_back(2U);
    body.push_back(13U); body.push_back(usb::kDescTypeCsInterface); body.push_back(usb::kCdcSubtypeEthernet);
    body.push_back(4U); pushU32Le(body, 0U); pushU16Le(body, 1514U); pushU16Le(body, 0U); body.push_back(0U);
    body.push_back(6U); body.push_back(usb::kDescTypeCsInterface); body.push_back(usb::kCdcSubtypeNcm);
    pushU16Le(body, 0x0100U); body.push_back(0x0fU);
    body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x82U);
    body.push_back(usb::kEpTypeInterrupt); pushU16Le(body, 16U); body.push_back(9U);

    // Interface 2: CDC-NCM Data alt 0 & alt 1
    body.push_back(9U); body.push_back(usb::kDescTypeInterface); body.push_back(2U); body.push_back(0U);
    body.push_back(0U); body.push_back(usb::kClassCdcData); body.push_back(0U); body.push_back(usb::kProtocolCdcNcmData);
    body.push_back(0U);
    body.push_back(9U); body.push_back(usb::kDescTypeInterface); body.push_back(2U); body.push_back(1U);
    body.push_back(2U); body.push_back(usb::kClassCdcData); body.push_back(0U); body.push_back(usb::kProtocolCdcNcmData);
    body.push_back(0U);
    body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x83U);
    body.push_back(usb::kEpTypeBulk); pushU16Le(body, 512U); body.push_back(0U);
    body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x03U);
    body.push_back(usb::kEpTypeBulk); pushU16Le(body, 512U); body.push_back(0U);

    // Interface 3: Apple Ethernet (0xff/0xfd/0x01)
    body.push_back(9U); body.push_back(usb::kDescTypeInterface); body.push_back(3U); body.push_back(0U);
    body.push_back(0U); body.push_back(usb::kAppleEthernetClass); body.push_back(usb::kAppleEthernetSubClass);
    body.push_back(usb::kAppleEthernetProtocol); body.push_back(0U);

    Bytes blob;
    blob.push_back(18U); blob.push_back(usb::kDescTypeDevice); pushU16Le(blob, 0x0200U);
    blob.push_back(0U); blob.push_back(0U); blob.push_back(0U); blob.push_back(64U);
    pushU16Le(blob, usb::kAppleVendorId); pushU16Le(blob, 0x12a8U); pushU16Le(blob, 0x0100U);
    blob.push_back(1U); blob.push_back(2U); blob.push_back(3U); blob.push_back(1U);

    blob.push_back(9U); blob.push_back(usb::kDescTypeConfiguration);
    pushU16Le(blob, static_cast<uint16_t>(9U + body.size()));
    blob.push_back(4U); blob.push_back(4U); blob.push_back(0U); blob.push_back(0xc0U); blob.push_back(250U);
    blob.insert(blob.end(), body.begin(), body.end());
    return blob;
}

class SimUsbHost : public plat::UsbHostInterface {
public:
    struct PendingUrb {
        uint64_t id;
        uint8_t ep;
        void* ctx;
    };

    SimUsbHost()
        : listener_(NULL),
          started_(false),
          open_(false),
          next_id_(1U),
          saw_detach_usbfs_true(false),
          close_calls(0) {}

    virtual bool start(plat::Reactor& /*reactor*/, plat::UsbHostListener* listener) {
        listener_ = listener;
        started_ = true;
        return true;
    }
    virtual void stop() {
        closeCurrentDevice();
        started_ = false;
        listener_ = NULL;
    }
    virtual bool isDeviceOpen() const { return open_; }
    virtual const plat::UsbDeviceInfo& currentDevice() const { return info_; }
    virtual const usb::DeviceDescriptor& deviceDescriptor() const { return dev_desc_; }
    virtual const std::vector<usb::ConfigurationDescriptor>& configurations() const {
        return configs_;
    }

    virtual bool setConfiguration(uint8_t config_value) {
        info_.configuration_value = config_value;
        return true;
    }
    virtual bool claimInterface(uint8_t iface, bool /*detach*/) {
        claimed_interfaces.push_back(iface);
        return true;
    }
    virtual bool claimInterfaceWithStatus(uint8_t iface,
                                          bool /*detach_kernel*/,
                                          bool detach_usbfs,
                                          plat::UsbClaimStatus& status_out,
                                          std::string& driver_out) {
        if (detach_usbfs) {
            saw_detach_usbfs_true = true;
        }
        status_out = plat::kUsbClaimOk;
        driver_out.clear();
        claimed_interfaces.push_back(iface);
        return true;
    }
    virtual bool releaseInterface(uint8_t iface) {
        for (size_t i = 0U; i < claimed_interfaces.size(); ++i) {
            if (claimed_interfaces[i] == iface) {
                claimed_interfaces.erase(claimed_interfaces.begin() + static_cast<ptrdiff_t>(i));
                break;
            }
        }
        return true;
    }
    virtual bool setInterface(uint8_t /*iface*/, uint8_t /*alt*/) { return true; }
    virtual bool resetDevice() { return true; }

    virtual bool controlTransfer(uint8_t req_type,
                                 uint8_t req,
                                 uint16_t /*val*/,
                                 uint16_t /*idx*/,
                                 Bytes& data_io,
                                 uint32_t /*timeout_ms*/,
                                 int* actual_out = NULL) {
        if (req_type == ncm::kReqTypeClassIn && req == ncm::kReqGetNtbParameters) {
            ncm::NtbParameters p;
            p.formats_supported = 0x0001U;
            p.ntb_in_max_size = 16384U;
            p.ndp_in_divisor = 4U;
            p.ndp_in_alignment = 4U;
            p.ntb_out_max_size = 16384U;
            p.ndp_out_divisor = 4U;
            p.ndp_out_alignment = 4U;
            p.ntb_out_max_datagrams = 16U;
            ncm::encodeNtbParameters(p, data_io);
            if (actual_out) *actual_out = static_cast<int>(data_io.size());
        }
        return true;
    }

    virtual bool readStringDescriptor(uint8_t /*idx*/, std::string& out) {
        out = "021122334455";
        return true;
    }
    virtual bool queryActiveConfiguration(uint8_t& cfg_out) {
        cfg_out = info_.configuration_value;
        return true;
    }
    virtual bool queryAppleUsbMode(Bytes& mode_out) {
        mode_out.clear();
        return true;
    }
    virtual bool requestCarPlayModeSwitch(const plat::AppleCarPlaySwitchRequest&) { return true; }

    virtual uint64_t submitBulkIn(uint8_t ep, size_t /*max_bytes*/, void* ctx) {
        const uint64_t id = next_id_++;
        PendingUrb u;
        u.id = id;
        u.ep = ep;
        u.ctx = ctx;
        pending_in.push_back(u);
        return id;
    }
    virtual uint64_t submitBulkOut(uint8_t ep,
                                   const uint8_t* data,
                                   size_t len,
                                   bool /*zlp*/,
                                   void* ctx) {
        if (!open_) return 0U;
        const uint64_t id = next_id_++;
        if (ep == 0x01U && data != NULL && len > 0U) {
            iap2_out.insert(iap2_out.end(), data, data + len);
        }
        PendingUrb u;
        u.id = id;
        u.ep = ep;
        u.ctx = ctx;
        pending_out.push_back(u);
        return id;
    }
    virtual bool discardUrb(uint64_t) { return true; }
    virtual void ignoreCurrentDevice() {}
    virtual void closeCurrentDevice() {
        if (open_) {
            ++close_calls;
        }
        open_ = false;
        claimed_interfaces.clear();
        pending_in.clear();
        pending_out.clear();
    }

    void flushOut() {
        while (!pending_out.empty()) {
            const PendingUrb u = pending_out.front();
            pending_out.pop_front();
            if (listener_ != NULL) {
                listener_->onUsbUrbComplete(u.id, u.ep, false, 0, NULL, 0U, u.ctx);
            }
        }
    }

    void simulateArrival(const Bytes& blob) {
        REQUIRE(usb::parseUsbfsDescriptors(&blob[0], blob.size(), dev_desc_, configs_));
        info_ = plat::UsbDeviceInfo();
        info_.vendor_id = dev_desc_.id_vendor;
        info_.product_id = dev_desc_.id_product;
        info_.bus_num = 1U;
        info_.dev_num = 3U;
        info_.configuration_value = 0U;
        open_ = true;
        if (listener_ != NULL) {
            listener_->onUsbDeviceArrived(info_, dev_desc_, configs_);
        }
    }

    void deliverIap2In(const Bytes& payload) {
        flushOut();
        for (size_t i = 0U; i < pending_in.size(); ++i) {
            if (pending_in[i].ep == 0x81U) {
                const PendingUrb u = pending_in[i];
                pending_in.erase(pending_in.begin() + static_cast<ptrdiff_t>(i));
                if (listener_ != NULL && !payload.empty()) {
                    listener_->onUsbUrbComplete(u.id, u.ep, true, 0, &payload[0], payload.size(),
                                                u.ctx);
                }
                flushOut();
                return;
            }
        }
        REQUIRE(false);
    }

    void simulateRemoval() {
        closeCurrentDevice();
        if (listener_ != NULL) {
            listener_->onUsbDeviceRemoved();
        }
    }

    plat::UsbHostListener* listener_;
    bool started_;
    bool open_;
    uint64_t next_id_;
    bool saw_detach_usbfs_true;
    int close_calls;
    plat::UsbDeviceInfo info_;
    usb::DeviceDescriptor dev_desc_;
    std::vector<usb::ConfigurationDescriptor> configs_;
    std::vector<uint8_t> claimed_interfaces;
    std::vector<PendingUrb> pending_in;
    std::deque<PendingUrb> pending_out;
    Bytes iap2_out;
};

class SimTapPort : public plat::TapPortInterface {
public:
    SimTapPort() : open_(false), ifname_("carplay0"), ifindex_(7U), open_calls(0), close_calls(0) {
        mac_[0] = 0x02U; mac_[1] = 0xaaU; mac_[2] = 0xbbU;
        mac_[3] = 0xccU; mac_[4] = 0xddU; mac_[5] = 0xeeU;
        REQUIRE(plat::Address::parse("fe80::2aa:bbff:fecc:ddee%7", link_local_));
    }

    virtual bool open(plat::Reactor&, plat::TapListener*) {
        ++open_calls;
        open_ = true;
        return true;
    }
    virtual void close() {
        if (open_) {
            ++close_calls;
        }
        open_ = false;
    }
    virtual bool isOpen() const { return open_; }
    virtual const std::string& interfaceName() const { return ifname_; }
    virtual uint32_t ifIndex() const { return ifindex_; }
    virtual void getMacAddress(uint8_t mac_out[6]) const { memcpy(mac_out, mac_, 6U); }
    virtual plat::TapWriteResult writeFrame(const uint8_t*, size_t) { return plat::kTapWriteSent; }
    virtual bool queryIpv6LinkLocal(plat::Address& out) const {
        if (!open_) return false;
        out = link_local_;
        return true;
    }

    bool open_;
    std::string ifname_;
    uint32_t ifindex_;
    uint8_t mac_[6];
    plat::Address link_local_;
    int open_calls;
    int close_calls;
};

// =================================================================================================
// Fake AuthProvider & Scripted Fake iPhone (iAP2 + AirPlay)
// =================================================================================================

class SimAuthProvider : public iap2::AuthProvider {
public:
    bool fail_cert;
    bool fail_sign;
    Bytes cert;
    uint8_t xor_key;

    SimAuthProvider() : fail_cert(false), fail_sign(false), xor_key(0x5aU) {
        cert.resize(96U);
        for (size_t i = 0U; i < cert.size(); ++i) {
            cert[i] = static_cast<uint8_t>((i * 11U + 5U) & 0xffU);
        }
    }

    virtual bool getCertificate(Bytes& certificate_out) {
        if (fail_cert) {
            return false;
        }
        certificate_out = cert;
        return true;
    }

    virtual bool signChallenge(const uint8_t* challenge, size_t len, Bytes& signature_out) {
        if (fail_sign || challenge == NULL || len == 0U) {
            return false;
        }
        signature_out.resize(len);
        for (size_t i = 0U; i < len; ++i) {
            signature_out[i] = static_cast<uint8_t>(challenge[i] ^ xor_key);
        }
        return true;
    }
};

class ScriptedIap2Phone {
public:
    Bytes tx_to_accessory;
    std::vector<iap2::Frame> rx_frames;
    bool detect_seen;
    bool syn_seen;
    uint8_t dev_seq;
    uint8_t last_acc_seq;
    uint8_t session_id;
    iap2::SynPayload dev_syn;
    iap2::CsmFramer framer;

    ScriptedIap2Phone()
        : detect_seen(false),
          syn_seen(false),
          dev_seq(80U),
          last_acc_seq(0U),
          session_id(10U) {
        dev_syn.version = 1U;
        dev_syn.max_outstanding = 4U;
        dev_syn.max_packet_length = 2048U;
        dev_syn.retransmission_timeout_ms = 4000U;
        dev_syn.cumulative_ack_timeout_ms = 500U;
        dev_syn.max_retransmissions = 4U;
        dev_syn.max_cumulative_acks = 3U;
        dev_syn.sessions.push_back(iap2::SynSession(10U, iap2::kSessionTypeControl, 2U));
    }

    void consumeFromAccessory(Bytes& buf) {
        size_t pos = 0U;
        while (pos < buf.size()) {
            if (pos + iap2::kDetectSequenceBytes <= buf.size() &&
                memcmp(&buf[pos], iap2::kDetectSequence, iap2::kDetectSequenceBytes) == 0) {
                detect_seen = true;
                pos += iap2::kDetectSequenceBytes;
                continue;
            }
            if (pos + iap2::kLinkHeaderBytes <= buf.size() &&
                buf[pos] == 0xffU && buf[pos + 1U] == 0x5aU) {
                const uint16_t len = static_cast<uint16_t>(
                    (static_cast<uint16_t>(buf[pos + 2U]) << 8) | buf[pos + 3U]);
                iap2::LinkPacket pkt;
                REQUIRE(len >= iap2::kLinkHeaderBytes && pos + len <= buf.size());
                REQUIRE(iap2::LinkPacket::decode(&buf[pos], len, pkt));
                pos += len;
                if ((pkt.control & iap2::kCtrlSyn) != 0U) {
                    syn_seen = true;
                    last_acc_seq = pkt.seq;
                    iap2::SynPayload acc_syn;
                    REQUIRE(iap2::SynPayload::decode(pkt.payload, acc_syn));
                    const iap2::SynSession* ctrl =
                        acc_syn.findSessionByType(iap2::kSessionTypeControl);
                    if (ctrl != NULL) {
                        session_id = ctrl->id;
                    }
                } else if (!pkt.payload.empty()) {
                    last_acc_seq = pkt.seq;
                    REQUIRE(framer.push(&pkt.payload[0], pkt.payload.size(), rx_frames));
                    sendAck();
                }
                continue;
            }
            REQUIRE(false);
        }
        buf.clear();
    }

    void sendDetect() {
        tx_to_accessory.insert(tx_to_accessory.end(),
                               iap2::kDetectSequence,
                               iap2::kDetectSequence + iap2::kDetectSequenceBytes);
    }

    void sendSynAck() {
        iap2::LinkPacket pkt;
        pkt.control = static_cast<uint8_t>(iap2::kCtrlSyn | iap2::kCtrlAck);
        pkt.seq = dev_seq;
        pkt.ack = last_acc_seq;
        pkt.session_id = 0U;
        REQUIRE(dev_syn.encode(pkt.payload));
        Bytes raw;
        REQUIRE(pkt.encode(raw));
        tx_to_accessory.insert(tx_to_accessory.end(), raw.begin(), raw.end());
    }

    void sendAck() {
        iap2::LinkPacket pkt;
        pkt.control = iap2::kCtrlAck;
        pkt.seq = dev_seq;
        pkt.ack = last_acc_seq;
        pkt.session_id = 0U;
        Bytes raw;
        REQUIRE(pkt.encode(raw));
        tx_to_accessory.insert(tx_to_accessory.end(), raw.begin(), raw.end());
    }

    void sendControlFrame(uint16_t msg_id,
                          const iap2::ParameterList& params = iap2::ParameterList()) {
        iap2::Frame f;
        REQUIRE(iap2::Frame::build(msg_id, params, f));
        Bytes csm;
        REQUIRE(f.encode(csm));
        dev_seq = static_cast<uint8_t>(dev_seq + 1U);
        iap2::LinkPacket pkt;
        pkt.control = iap2::kCtrlAck;
        pkt.seq = dev_seq;
        pkt.ack = last_acc_seq;
        pkt.session_id = session_id;
        pkt.payload = csm;
        Bytes raw;
        REQUIRE(pkt.encode(raw));
        tx_to_accessory.insert(tx_to_accessory.end(), raw.begin(), raw.end());
    }

    const iap2::Frame* findLastFrame(uint16_t msg_id) const {
        for (size_t i = rx_frames.size(); i > 0U; --i) {
            if (rx_frames[i - 1U].message_id == msg_id) {
                return &rx_frames[i - 1U];
            }
        }
        return NULL;
    }

    size_t countFrames(uint16_t msg_id) const {
        size_t n = 0U;
        for (size_t i = 0U; i < rx_frames.size(); ++i) {
            if (rx_frames[i].message_id == msg_id) {
                ++n;
            }
        }
        return n;
    }
};

struct SimAirPlayPhone {
    plat::Reactor& reactor;
    std::string id;
    crypto::Ed25519KeyPair ltsk;
    plat::TcpConnection control_conn;
    plat::TcpConnection event_conn;
    plat::UdpSocket timing_sock;
    rtsp::Parser control_parser;
    std::unique_ptr<carplay::ControlCipher> control_cipher;
    int cseq;
    Bytes shared_secret;

    SimAirPlayPhone(plat::Reactor& r, const std::string& ctrl_id)
        : reactor(r), id(ctrl_id), cseq(0) {
        const Bytes seed = sha512Bytes(strToBytes("sim-e2e-phone-" + ctrl_id));
        crypto::ed25519FromSeed(&seed[0], ltsk);
    }

    ~SimAirPlayPhone() {
        event_conn.close();
        control_conn.close();
        timing_sock.close();
    }

    bool connectTcp(plat::TcpConnection& conn, const plat::Address& dest) {
        if (!conn.connect(dest)) return false;
        const int64_t dl = plat::monotonicMillis() + 3000;
        while (conn.connecting() && plat::monotonicMillis() < dl) {
            reactor.runOnce(5);
            const plat::IoStatus st = conn.finishConnect();
            if (st == plat::kIoOk) break;
            if (st == plat::kIoError) return false;
        }
        for (int i = 0; i < 4; ++i) {
            reactor.runOnce(5);
        }
        return conn.isOpen();
    }

    bool sendRaw(plat::TcpConnection& conn, const Bytes& data) {
        if (data.empty()) return true;
        if (conn.send(&data[0], data.size()) != plat::TcpConnection::kSendOk) return false;
        const int64_t dl = plat::monotonicMillis() + 3000;
        while (conn.wantsWrite() && plat::monotonicMillis() < dl) {
            reactor.runOnce(5);
            conn.flush();
        }
        for (int i = 0; i < 2; ++i) {
            reactor.runOnce(5);
        }
        return !conn.wantsWrite();
    }

    bool request(const std::string& method,
                 const std::string& path,
                 const std::string& content_type,
                 const Bytes& body,
                 int& status_out,
                 rtsp::Request& resp_out) {
        ++cseq;
        rtsp::HeaderList hdrs;
        if (!content_type.empty()) {
            hdrs.push_back(rtsp::Header("Content-Type", content_type));
        }
        hdrs.push_back(rtsp::Header("CSeq", rtsp::toDecimal(cseq)));
        Bytes wire;
        rtsp::buildRequest(method, path, "RTSP/1.0", hdrs, body, wire);
        Bytes to_send = wire;
        const bool encrypted = (control_cipher.get() != NULL);
        if (encrypted) {
            to_send.clear();
            if (!control_cipher->encrypt(wire, to_send)) return false;
        }
        if (!sendRaw(control_conn, to_send)) return false;

        std::vector<rtsp::Request> msgs;
        uint8_t buf[16384];
        const int64_t dl = plat::monotonicMillis() + 3000;
        while (msgs.empty() && plat::monotonicMillis() < dl) {
            reactor.runOnce(5);
            size_t n = 0;
            const plat::IoStatus st = control_conn.read(buf, sizeof(buf), n);
            if (st == plat::kIoOk && n > 0) {
                Bytes plain;
                if (encrypted) {
                    if (!control_cipher->feed(buf, n, plain)) return false;
                } else {
                    plain.assign(buf, buf + n);
                }
                if (!plain.empty() && !control_parser.feed(plain, msgs)) {
                    return false;
                }
            }
        }
        if (msgs.size() != 1U || !msgs[0].isResponse()) return false;
        resp_out = msgs[0];
        status_out = atoi(resp_out.path.c_str());
        return true;
    }

    bool pairVerify() {
        const Bytes eph_seed = sha512Bytes(strToBytes("sim-e2e-eph-" + id));
        crypto::X25519KeyPair eph;
        crypto::x25519FromSecret(&eph_seed[0], eph);

        Items m1;
        m1.push_back(tlv8::Item::fromByte(tlv8::kTagState, 1));
        m1.push_back(tlv8::Item(tlv8::kTagPublicKey, Bytes(eph.public_key, eph.public_key + 32)));
        int status = 0;
        rtsp::Request m2_resp;
        if (!request("POST", "/pair-verify", rtsp::kContentTypePairingTlv8, tlv8::encode(m1),
                     status, m2_resp) ||
            status != 200) {
            return false;
        }
        Items m2;
        if (!tlv8::decode(m2_resp.body, m2)) return false;
        const tlv8::Item* pk_it = tlv8::findFirst(m2, tlv8::kTagPublicKey);
        if (!pk_it || pk_it->value.size() != 32U) return false;
        const Bytes acc_eph = pk_it->value;

        shared_secret.assign(32, 0);
        if (!crypto::x25519SharedSecret(eph.secret_key, &acc_eph[0], &shared_secret[0])) {
            return false;
        }
        const Bytes session_key =
            hkdf32(shared_secret, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info");

        Bytes info_bytes(eph.public_key, eph.public_key + 32);
        info_bytes.insert(info_bytes.end(), id.begin(), id.end());
        info_bytes.insert(info_bytes.end(), acc_eph.begin(), acc_eph.end());
        uint8_t sig[64];
        crypto::ed25519Sign(ltsk.secret_key, &info_bytes[0], info_bytes.size(), sig);

        Items sub;
        sub.push_back(tlv8::Item(tlv8::kTagIdentifier, strToBytes(id)));
        sub.push_back(tlv8::Item(tlv8::kTagSignature, Bytes(sig, sig + 64)));
        const Bytes sub_plain = tlv8::encode(sub);
        const Bytes nonce3 = makeLabelNonce12("PV-Msg03");
        Bytes sub_ct;
        crypto::chacha20Poly1305Seal(&session_key[0], &nonce3[0], NULL, 0,
                                     &sub_plain[0], sub_plain.size(), sub_ct);

        Items m3;
        m3.push_back(tlv8::Item::fromByte(tlv8::kTagState, 3));
        m3.push_back(tlv8::Item(tlv8::kTagEncryptedData, sub_ct));
        rtsp::Request m4_resp;
        if (!request("POST", "/pair-verify", rtsp::kContentTypePairingTlv8, tlv8::encode(m3),
                     status, m4_resp) ||
            status != 200) {
            return false;
        }

        const Bytes c_read = hkdf32(shared_secret, "Control-Salt", "Control-Read-Encryption-Key");
        const Bytes c_write = hkdf32(shared_secret, "Control-Salt", "Control-Write-Encryption-Key");
        control_cipher.reset(new carplay::ControlCipher(&c_read[0], &c_write[0]));
        return true;
    }
};

template <typename DeliverFn>
void driveIap2SyncAndAuth(ScriptedIap2Phone& phone,
                          Bytes& acc_tx,
                          DeliverFn deliver,
                          const SimAuthProvider& auth,
                          bool expect_wireless) {
    // 1. Detect + SYN/ACK
    phone.consumeFromAccessory(acc_tx);
    REQUIRE(phone.detect_seen);
    if (expect_wireless) {
        // Wireless waits for peer detect before sending SYN.
        phone.sendDetect();
        deliver(phone.tx_to_accessory);
        phone.tx_to_accessory.clear();
        phone.consumeFromAccessory(acc_tx);
        REQUIRE(phone.syn_seen);
    } else {
        // Wired sends SYN immediately with detect.
        REQUIRE(phone.syn_seen);
        phone.sendDetect();
    }
    phone.sendSynAck();
    deliver(phone.tx_to_accessory);
    phone.tx_to_accessory.clear();
    phone.consumeFromAccessory(acc_tx);

    // 2. Identification
    phone.sendControlFrame(iap2::msg::kStartIdentification);
    deliver(phone.tx_to_accessory);
    phone.tx_to_accessory.clear();
    phone.consumeFromAccessory(acc_tx);

    const iap2::Frame* ident = phone.findLastFrame(iap2::msg::kIdentificationInformation);
    REQUIRE(ident != NULL);
    iap2::ParameterList ident_params;
    REQUIRE(iap2::ParameterList::decode(ident->payload, ident_params));
    if (expect_wireless) {
        CHECK(ident_params.findFirst(iap2::param::kIdentBluetoothTransportComponent) != NULL);
        CHECK(ident_params.findFirst(iap2::param::kIdentWirelessCarPlayTransportComponent) != NULL);
        CHECK(ident_params.findFirst(iap2::param::kIdentUsbHostTransportComponent) == NULL);
        CHECK(ident_params.findFirst(iap2::param::kIdentLocationInformationComponent) == NULL);
        CHECK(ident_params.findFirst(iap2::param::kIdentVehicleStatusComponent) == NULL);
    } else {
        CHECK(ident_params.findFirst(iap2::param::kIdentUsbHostTransportComponent) != NULL);
    }

    phone.sendControlFrame(iap2::msg::kIdentificationAccepted);
    deliver(phone.tx_to_accessory);
    phone.tx_to_accessory.clear();
    phone.consumeFromAccessory(acc_tx);

    // 3. Authentication
    phone.sendControlFrame(iap2::msg::kRequestAuthenticationCertificate);
    deliver(phone.tx_to_accessory);
    phone.tx_to_accessory.clear();
    phone.consumeFromAccessory(acc_tx);

    const iap2::Frame* cert_frame = phone.findLastFrame(iap2::msg::kAuthenticationCertificate);
    REQUIRE(cert_frame != NULL);
    iap2::ParameterList cert_params;
    REQUIRE(iap2::ParameterList::decode(cert_frame->payload, cert_params));
    Bytes got_cert;
    REQUIRE(cert_params.readBytes(iap2::param::kAuthCertificateData, got_cert));
    CHECK_BYTES_EQ(auth.cert, got_cert);

    const Bytes challenge(32U, 0x3cU);
    iap2::ParameterList chal_params;
    chal_params.addRaw(iap2::param::kAuthChallengeData, challenge);
    phone.sendControlFrame(iap2::msg::kRequestAuthenticationChallengeResponse, chal_params);
    deliver(phone.tx_to_accessory);
    phone.tx_to_accessory.clear();
    phone.consumeFromAccessory(acc_tx);

    const iap2::Frame* resp_frame = phone.findLastFrame(iap2::msg::kAuthenticationResponse);
    REQUIRE(resp_frame != NULL);
    iap2::ParameterList resp_params;
    REQUIRE(iap2::ParameterList::decode(resp_frame->payload, resp_params));
    Bytes got_sig;
    REQUIRE(resp_params.readBytes(iap2::param::kAuthChallengeResponseData, got_sig));
    REQUIRE(got_sig.size() == challenge.size());
    for (size_t i = 0U; i < challenge.size(); ++i) {
        CHECK_EQ(static_cast<uint8_t>(challenge[i] ^ auth.xor_key), got_sig[i]);
    }

    phone.sendControlFrame(iap2::msg::kAuthenticationSucceeded);
    deliver(phone.tx_to_accessory);
    phone.tx_to_accessory.clear();
    phone.consumeFromAccessory(acc_tx);
}

plat::CarPlayDaemonConfig makeSimDaemonConfig(const std::string& data_dir) {
    plat::CarPlayDaemonConfig cfg;
    cfg.control_port = 0U;
    cfg.bind_loopback_only = true;
    cfg.data_dir = data_dir;
    cfg.enable_video = false;
    cfg.enable_audio = false;
    cfg.enable_input = false;
    cfg.enable_control = false;
    cfg.query_display_from_ilm = false;
    cfg.tick_interval_ms = 20;
    cfg.server_config.ntp_request_interval_ms = 0;
    return cfg;
}

// =================================================================================================
// 1. Golden Wireless E2E Simulation
// =================================================================================================

TEST_CASE(wirelessE2eSimulationAndAlpsRestore) {
#ifdef _WIN32
    return;
#else
    const std::string dir = makeTempDir("cp_sim_wl");
    plat::CarPlayDaemonConfig cfg = makeSimDaemonConfig(dir);
    cfg.enable_wireless = true;
    cfg.connectivity_config.wireless_ips_override.push_back("127.0.0.1");
    cfg.connectivity_config.wifi_ap_config.backend = plat::kWifiApBackendNative;
    cfg.connectivity_config.alps_config.double_read_delay_ms = 0U;
    cfg.connectivity_config.alps_config.restore_poll_interval_ms = 0U;

    plat::CarPlayDaemon daemon(cfg);

    SimSppMemoryBackend spp_mem;
    SimAlpsSppLink alps_link(&spp_mem);
    struct DummyBtListener : public plat::BtTransportListener {
        virtual void onBtTransportConnected(const plat::BtAddr&) {}
        virtual void onBtTransportData(const uint8_t*, size_t) {}
        virtual void onBtTransportDisconnected(const std::string&) {}
    } dummy_bt_listener;
    plat::AlpsBtTransport real_alps_bt(daemon.reactor(),
                                       dummy_bt_listener,
                                       cfg.connectivity_config.alps_config,
                                       &spp_mem,
                                       &alps_link);

    SimWlanController sim_wlan;
    SimAccessPointReader sim_ap_reader;
    SimHostapdCtrl sim_ctrl;
    SimDnsSdState dns_state;
    g_sim_dnssd = &dns_state;
    const plat::DnsSdApi dns_api = makeSimDnsSdApi();
    SimAuthProvider sim_auth;

    daemon.connectivity().setBtTransportForTest(&real_alps_bt);
    daemon.connectivity().setIap2AuthProvider(&sim_auth);
    daemon.connectivity().wifiAp().setWlanControllerForTest(&sim_wlan);
    daemon.connectivity().wifiAp().setAccessPointReaderForTest(&sim_ap_reader);
    daemon.connectivity().wifiAp().setHostapdCtrlForTest(&sim_ctrl);
    daemon.connectivity().wifiAp().setNativeCapabilityForTest(1);
    daemon.connectivity().mdnsAdvertiser().setApiOverride(&dns_api);

    REQUIRE(daemon.start());
    CHECK_EQ(plat::kConnWaiting, daemon.connectivity().state());
    // Verify ALPS slot 5 was borrowed while slot 0 & slot 1 remain generic.
    CHECK(real_alps_bt.manager().borrowedSlot());
    CHECK_EQ(plat::kAlpsSpareSlot, static_cast<unsigned>(real_alps_bt.manager().activeSlot()));
    CHECK(spp_mem.slotMatchesGeneric(plat::kAlpsBmwAppsSlot));
    CHECK(spp_mem.slotMatchesCarPlay(plat::kAlpsSpareSlot));

    // Step 1: Fake iPhone connects over BT SPP.
    plat::BtAddr peer;
    REQUIRE(plat::BtAddr::parse("11:22:33:44:55:66", peer));
    alps_link.simulateConnect(peer);
    CHECK_EQ(plat::kConnWirelessIap2, daemon.connectivity().state());

    // Step 2: Scripted fake iPhone runs iAP2 link SYN/ACK + identification + auth.
    ScriptedIap2Phone iap2_phone;
    auto deliverBt = [&alps_link](const Bytes& b) { alps_link.simulateRx(b); };
    driveIap2SyncAndAuth(iap2_phone, alps_link.tx_to_phone, deliverBt, sim_auth, true);

    // After auth succeeds: Wi-Fi AP started + mDNS registered!
    CHECK_EQ(plat::kConnWirelessWaitingAirPlay, daemon.connectivity().state());
    CHECK_EQ(plat::kWifiApRunning, daemon.connectivity().wifiAp().state());
    CHECK_EQ(1, sim_wlan.enable_calls);
    CHECK_EQ(1, dns_state.register_calls);
    CHECK_EQ(daemon.controlPort(), dns_state.last_port_host);
    CHECK_EQ(std::string("_airplay._tcp"), dns_state.last_regtype);

    // Pump reactor once so mDNS fd callback marks it registered.
    daemon.reactor().runOnce(10);
    CHECK(daemon.connectivity().mdnsAdvertiser().isRegistered());

    // Verify TXT record decodes cleanly and includes pi/pk/features.
    std::vector<dnssd::TxtEntry> txt_entries;
    REQUIRE(dnssd::decodeTxtRecord(dns_state.last_txt, txt_entries));
    CHECK(txt_entries.size() >= 6U);

    // Step 3: iPhone sends 0x4E0D + 0x5702 -> receives 0x5703 Wi-Fi credentials.
    iap2::ParameterList wcp_avail;
    wcp_avail.addU8(0U, 1U);
    iap2_phone.sendControlFrame(iap2::msg::kWirelessCarPlayUpdate, wcp_avail);
    iap2_phone.sendControlFrame(iap2::msg::kRequestAccessoryWiFiConfiguration);
    deliverBt(iap2_phone.tx_to_accessory);
    iap2_phone.tx_to_accessory.clear();
    iap2_phone.consumeFromAccessory(alps_link.tx_to_phone);

    const iap2::Frame* wifi_cfg_frame = iap2_phone.findLastFrame(iap2::msg::kAccessoryWiFiConfiguration);
    REQUIRE(wifi_cfg_frame != NULL);
    iap2::ParameterList wcfg_params;
    REQUIRE(iap2::ParameterList::decode(wifi_cfg_frame->payload, wcfg_params));
    std::string got_ssid, got_pass;
    uint8_t got_sec = 0U, got_ch = 0U;
    REQUIRE(wcfg_params.readString(1U, got_ssid));
    REQUIRE(wcfg_params.readString(2U, got_pass));
    REQUIRE(wcfg_params.readU8(3U, got_sec));
    REQUIRE(wcfg_params.readU8(4U, got_ch));
    CHECK_EQ(std::string("BMW-CarPlay-Test"), got_ssid);
    CHECK_EQ(std::string("TestPass1234"), got_pass);
    CHECK_EQ(static_cast<uint8_t>(iap2::kWirelessSecurityWpaWpa2), got_sec);
    CHECK_EQ(static_cast<uint8_t>(36U), got_ch);

    // Step 4: iPhone sends 0x4300 CarPlayAvailability(wireless=1) -> receives 0x4301 CarPlayStartSession.
    iap2::ParameterList wgrp;
    wgrp.addU8(0U, 1U);
    iap2::ParameterList avail;
    avail.addGroup(1U, wgrp);
    iap2_phone.sendControlFrame(iap2::msg::kCarPlayAvailability, avail);
    deliverBt(iap2_phone.tx_to_accessory);
    iap2_phone.tx_to_accessory.clear();
    iap2_phone.consumeFromAccessory(alps_link.tx_to_phone);

    const iap2::Frame* start_sess = iap2_phone.findLastFrame(iap2::msg::kCarPlayStartSession);
    REQUIRE(start_sess != NULL);
    iap2::ParameterList ss_params;
    REQUIRE(iap2::ParameterList::decode(start_sess->payload, ss_params));
    uint32_t ss_port = 0U;
    REQUIRE(ss_params.readU32(2U, ss_port));
    CHECK_EQ(static_cast<uint32_t>(daemon.controlPort()), ss_port);
    iap2::ParameterList ss_wl;
    REQUIRE(ss_params.readGroup(1U, ss_wl));
    std::string ss_ip;
    REQUIRE(ss_wl.readString(3U, ss_ip));
    CHECK_EQ(std::string("127.0.0.1"), ss_ip);

    // Step 5: iPhone closes BT RFCOMM during handoff -> AP & mDNS must stay UP!
    alps_link.simulateDisconnect("handoff to wifi");
    CHECK_EQ(plat::kConnWirelessWaitingAirPlay, daemon.connectivity().state());
    CHECK_EQ(plat::kWifiApRunning, daemon.connectivity().wifiAp().state());
    CHECK(daemon.connectivity().mdnsAdvertiser().isActive());

    // Step 6: iPhone connects over TCP to SessionServer (:controlPort) and verifies AirPlay session.
    SimAirPlayPhone airplay_phone(daemon.reactor(), "WL-PHONE-001");
    REQUIRE(daemon.pairingStore() != NULL);
    REQUIRE(daemon.pairingStore()->save(airplay_phone.id, airplay_phone.ltsk.public_key));
    REQUIRE(airplay_phone.connectTcp(airplay_phone.control_conn,
                                     plat::Address::ipv4Loopback(static_cast<uint16_t>(ss_port))));
    REQUIRE(airplay_phone.pairVerify());

    int status = 0;
    rtsp::Request info_resp;
    REQUIRE(airplay_phone.request("GET", "/info", "", Bytes(), status, info_resp));
    CHECK_EQ(200, status);

    REQUIRE(airplay_phone.timing_sock.open(plat::Address::ipv4Loopback(0U)));
    carplay::bplist::Value setup_sess = carplay::bplist::Value::makeDict();
    setup_sess.set("deviceID", carplay::bplist::Value::makeString("11:22:33:44:55:66"));
    setup_sess.set("name", carplay::bplist::Value::makeString("Wireless iPhone"));
    setup_sess.set("model", carplay::bplist::Value::makeString("iPhone16,1"));
    setup_sess.set("timingPort", carplay::bplist::Value::makeInt(airplay_phone.timing_sock.port()));
    rtsp::Request setup_resp;
    REQUIRE(airplay_phone.request("SETUP", "rtsp://127.0.0.1/session",
                                  rtsp::kContentTypeBinaryPlist,
                                  encodeBplist(setup_sess), status, setup_resp));
    CHECK_EQ(200, status);
    CHECK(daemon.hasActiveSession());
    CHECK_EQ(plat::kConnActiveSession, daemon.connectivity().state());
    CHECK_EQ(plat::kActiveWireless, daemon.connectivity().activeTransport());

    // Step 7: Phone closes TCP session -> AP restored, mDNS unregistered, state -> kConnWaiting.
    airplay_phone.control_conn.close();
    const int64_t dl = plat::monotonicMillis() + 2000;
    while (plat::monotonicMillis() < dl && daemon.connectivity().state() != plat::kConnWaiting) {
        daemon.reactor().runOnce(10);
    }
    CHECK_EQ(plat::kConnWaiting, daemon.connectivity().state());
    CHECK_EQ(plat::kWifiApStopped, daemon.connectivity().wifiAp().state());
    CHECK_EQ(1, sim_wlan.restore_calls);
    CHECK(!daemon.connectivity().mdnsAdvertiser().isActive());
    CHECK_EQ(1, dns_state.deallocate_calls);

    // Step 8: Daemon stop -> ALPS slot 5 restored back to generic UUID!
    daemon.stop();
    CHECK_EQ(plat::kConnStopped, daemon.connectivity().state());
    CHECK(real_alps_bt.manager().restoreAttempted());
    CHECK(real_alps_bt.manager().restoreSucceeded());
    CHECK(spp_mem.slotMatchesGeneric(plat::kAlpsSpareSlot));

    g_sim_dnssd = NULL;
    removeTempDir(dir);
#endif
}

// =================================================================================================
// 2. Golden Wired USB E2E Simulation
// =================================================================================================

TEST_CASE(wiredE2eSimulationAndTeardown) {
#ifdef _WIN32
    return;
#else
    const std::string dir = makeTempDir("cp_sim_usb");
    plat::CarPlayDaemonConfig cfg = makeSimDaemonConfig(dir);
    cfg.enable_wired = true;
    // Verify coexistence safe default.
    CHECK(!cfg.connectivity_config.usb_host_config.detach_usbfs_driver);
    CHECK(!cfg.connectivity_config.usb_bridge_config.detach_usbfs_driver);

    plat::CarPlayDaemon daemon(cfg);
    SimUsbHost sim_usb;
    SimTapPort sim_tap;
    SimAuthProvider sim_auth;

    daemon.connectivity().setUsbHostForTest(&sim_usb);
    daemon.connectivity().setTapPortForTest(&sim_tap);
    daemon.connectivity().setIap2AuthProvider(&sim_auth);

    REQUIRE(daemon.start());
    CHECK_EQ(plat::kConnWaiting, daemon.connectivity().state());

    // Step 1: USB device arrives -> claims iAP2 + NCM, brings TAP up, enters kConnWiredIap2.
    sim_usb.simulateArrival(buildCarPlayUsbBlob());
    CHECK(!sim_usb.saw_detach_usbfs_true);
    CHECK(sim_tap.isOpen());
    CHECK_EQ(plat::kConnWiredIap2, daemon.connectivity().state());
    CHECK_EQ(3U, sim_usb.claimed_interfaces.size());

    // Step 2: Scripted fake iPhone runs wired iAP2 detect + SYN/ACK + ident + auth.
    ScriptedIap2Phone iap2_phone;
    auto deliverUsb = [&sim_usb](const Bytes& b) { sim_usb.deliverIap2In(b); };
    driveIap2SyncAndAuth(iap2_phone, sim_usb.iap2_out, deliverUsb, sim_auth, false);

    // Expect proactive PowerSourceUpdate (0xAE03) + 5 subscriptions.
    CHECK(iap2_phone.findLastFrame(iap2::msg::kPowerSourceUpdate) != NULL);
    CHECK(iap2_phone.findLastFrame(iap2::msg::kStartNowPlayingUpdates) != NULL);

    // Step 3: iPhone sends 0x4300 CarPlayAvailability(wired=1) -> receives 0x4301 with TAP IPv6.
    iap2::ParameterList wgrp;
    wgrp.addU8(0U, 1U);
    iap2::ParameterList avail;
    avail.addGroup(0U, wgrp);
    iap2_phone.sendControlFrame(iap2::msg::kCarPlayAvailability, avail);
    deliverUsb(iap2_phone.tx_to_accessory);
    iap2_phone.tx_to_accessory.clear();
    iap2_phone.consumeFromAccessory(sim_usb.iap2_out);

    const iap2::Frame* start_sess = iap2_phone.findLastFrame(iap2::msg::kCarPlayStartSession);
    REQUIRE(start_sess != NULL);
    iap2::ParameterList ss_params;
    REQUIRE(iap2::ParameterList::decode(start_sess->payload, ss_params));
    iap2::ParameterList wired_grp;
    REQUIRE(ss_params.readGroup(0U, wired_grp));
    std::string wired_ip;
    REQUIRE(wired_grp.readString(0U, wired_ip));
    CHECK_EQ(std::string("fe80::2aa:bbff:fecc:ddee"), wired_ip);  // %7 scope stripped!
    uint32_t ss_port = 0U;
    REQUIRE(ss_params.readU32(2U, ss_port));
    CHECK_EQ(static_cast<uint32_t>(daemon.controlPort()), ss_port);
    CHECK_EQ(plat::kConnWiredWaitingAirPlay, daemon.connectivity().state());

    // Step 4: iPhone connects over TCP to SessionServer -> active wired session.
    SimAirPlayPhone airplay_phone(daemon.reactor(), "USB-PHONE-001");
    REQUIRE(daemon.pairingStore() != NULL);
    REQUIRE(daemon.pairingStore()->save(airplay_phone.id, airplay_phone.ltsk.public_key));
    REQUIRE(airplay_phone.connectTcp(airplay_phone.control_conn,
                                     plat::Address::ipv4Loopback(static_cast<uint16_t>(ss_port))));
    REQUIRE(airplay_phone.pairVerify());

    int status = 0;
    rtsp::Request info_resp;
    REQUIRE(airplay_phone.request("GET", "/info", "", Bytes(), status, info_resp));
    CHECK_EQ(200, status);

    REQUIRE(airplay_phone.timing_sock.open(plat::Address::ipv4Loopback(0U)));
    carplay::bplist::Value setup_sess = carplay::bplist::Value::makeDict();
    setup_sess.set("deviceID", carplay::bplist::Value::makeString("AA:BB:CC:DD:EE:FF"));
    setup_sess.set("name", carplay::bplist::Value::makeString("Wired iPhone"));
    setup_sess.set("model", carplay::bplist::Value::makeString("iPhone16,2"));
    setup_sess.set("timingPort", carplay::bplist::Value::makeInt(airplay_phone.timing_sock.port()));
    rtsp::Request setup_resp;
    REQUIRE(airplay_phone.request("SETUP", "rtsp://127.0.0.1/session",
                                  rtsp::kContentTypeBinaryPlist,
                                  encodeBplist(setup_sess), status, setup_resp));
    CHECK_EQ(200, status);
    CHECK(daemon.hasActiveSession());
    CHECK_EQ(plat::kConnActiveSession, daemon.connectivity().state());
    CHECK_EQ(plat::kActiveWired, daemon.connectivity().activeTransport());

    // Step 5: USB unplugged mid-session -> AirPlay session closed, TAP closed, USB released!
    sim_usb.simulateRemoval();
    CHECK(!daemon.hasActiveSession());
    CHECK(!sim_tap.isOpen());
    CHECK(sim_usb.claimed_interfaces.empty());
    CHECK_EQ(plat::kConnWaiting, daemon.connectivity().state());
    CHECK_EQ(plat::kActiveNone, daemon.connectivity().activeTransport());

    daemon.stop();
    CHECK_EQ(plat::kConnStopped, daemon.connectivity().state());
    removeTempDir(dir);
#endif
}

// =================================================================================================
// 3. Failure Injection: AP Fails, Auth Fails, Phone Disappears Mid-Session, ALPS Slot Always Restored
// =================================================================================================

TEST_CASE(failureInjectionApFailsAndAlpsRestored) {
#ifdef _WIN32
    return;
#else
    const std::string dir = makeTempDir("cp_sim_apfail");
    plat::CarPlayDaemonConfig cfg = makeSimDaemonConfig(dir);
    cfg.enable_wireless = true;
    cfg.connectivity_config.wifi_ap_config.backend = plat::kWifiApBackendNative;
    cfg.connectivity_config.alps_config.double_read_delay_ms = 0U;
    cfg.connectivity_config.alps_config.restore_poll_interval_ms = 0U;

    plat::CarPlayDaemon daemon(cfg);

    struct NoopBtListener : public plat::BtTransportListener {
        virtual void onBtTransportConnected(const plat::BtAddr&) {}
        virtual void onBtTransportData(const uint8_t*, size_t) {}
        virtual void onBtTransportDisconnected(const std::string&) {}
    } noop_bt;
    SimSppMemoryBackend spp_mem;
    SimAlpsSppLink alps_link(&spp_mem);
    plat::AlpsBtTransport real_alps_bt(daemon.reactor(), noop_bt,
                                       cfg.connectivity_config.alps_config,
                                       &spp_mem, &alps_link);

    SimWlanController sim_wlan;
    sim_wlan.fail_async_enable = true;  // Inject AP failure!
    SimAccessPointReader sim_ap_reader;
    SimHostapdCtrl sim_ctrl;
    SimDnsSdState dns_state;
    g_sim_dnssd = &dns_state;
    const plat::DnsSdApi dns_api = makeSimDnsSdApi();
    SimAuthProvider sim_auth;

    daemon.connectivity().setBtTransportForTest(&real_alps_bt);
    daemon.connectivity().setIap2AuthProvider(&sim_auth);
    daemon.connectivity().wifiAp().setWlanControllerForTest(&sim_wlan);
    daemon.connectivity().wifiAp().setAccessPointReaderForTest(&sim_ap_reader);
    daemon.connectivity().wifiAp().setHostapdCtrlForTest(&sim_ctrl);
    daemon.connectivity().wifiAp().setNativeCapabilityForTest(1);
    daemon.connectivity().mdnsAdvertiser().setApiOverride(&dns_api);

    REQUIRE(daemon.start());
    CHECK(spp_mem.slotMatchesCarPlay(plat::kAlpsSpareSlot));

    plat::BtAddr peer;
    REQUIRE(plat::BtAddr::parse("22:33:44:55:66:77", peer));
    alps_link.simulateConnect(peer);

    ScriptedIap2Phone iap2_phone;
    auto deliverBt = [&alps_link](const Bytes& b) { alps_link.simulateRx(b); };
    driveIap2SyncAndAuth(iap2_phone, alps_link.tx_to_phone, deliverBt, sim_auth, true);

    // AP failed -> must tear down cleanly: mDNS not started, AP stopped, BT disconnected, waiting!
    CHECK_EQ(plat::kConnWaiting, daemon.connectivity().state());
    CHECK_EQ(plat::kActiveNone, daemon.connectivity().activeTransport());
    CHECK(!daemon.connectivity().mdnsAdvertiser().isActive());
    CHECK_EQ(0, dns_state.register_calls);
    CHECK_EQ(plat::kWifiApStopped, daemon.connectivity().wifiAp().state());
    CHECK(!alps_link.isLinkUp());
    CHECK_EQ(1ULL, daemon.connectivity().failureTeardowns());

    // Even after AP failure, daemon.stop() restores borrowed ALPS slot 5!
    daemon.stop();
    CHECK(real_alps_bt.manager().restoreAttempted());
    CHECK(real_alps_bt.manager().restoreSucceeded());
    CHECK(spp_mem.slotMatchesGeneric(plat::kAlpsSpareSlot));

    g_sim_dnssd = NULL;
    removeTempDir(dir);
#endif
}

TEST_CASE(failureInjectionAuthFailsWirelessAndWired) {
#ifdef _WIN32
    return;
#else
    // 1. Wireless auth fails -> AP never started, BT disconnected, ALPS slot 5 restored on stop.
    {
        const std::string dir = makeTempDir("cp_sim_wl_authfail");
        plat::CarPlayDaemonConfig cfg = makeSimDaemonConfig(dir);
        cfg.enable_wireless = true;
        cfg.connectivity_config.wifi_ap_config.backend = plat::kWifiApBackendNative;
        cfg.connectivity_config.alps_config.double_read_delay_ms = 0U;
        cfg.connectivity_config.alps_config.restore_poll_interval_ms = 0U;

        plat::CarPlayDaemon daemon(cfg);
        struct NoopBtListener : public plat::BtTransportListener {
            virtual void onBtTransportConnected(const plat::BtAddr&) {}
            virtual void onBtTransportData(const uint8_t*, size_t) {}
            virtual void onBtTransportDisconnected(const std::string&) {}
        } noop_bt;
        SimSppMemoryBackend spp_mem;
        SimAlpsSppLink alps_link(&spp_mem);
        plat::AlpsBtTransport real_alps_bt(daemon.reactor(), noop_bt,
                                           cfg.connectivity_config.alps_config,
                                           &spp_mem, &alps_link);

        SimWlanController sim_wlan;
        SimAccessPointReader sim_ap_reader;
        SimHostapdCtrl sim_ctrl;
        SimAuthProvider sim_auth;
        sim_auth.fail_sign = true;  // Inject auth failure!

        daemon.connectivity().setBtTransportForTest(&real_alps_bt);
        daemon.connectivity().setIap2AuthProvider(&sim_auth);
        daemon.connectivity().wifiAp().setWlanControllerForTest(&sim_wlan);
        daemon.connectivity().wifiAp().setAccessPointReaderForTest(&sim_ap_reader);
        daemon.connectivity().wifiAp().setHostapdCtrlForTest(&sim_ctrl);
        daemon.connectivity().wifiAp().setNativeCapabilityForTest(1);

        REQUIRE(daemon.start());
        plat::BtAddr peer;
        REQUIRE(plat::BtAddr::parse("33:44:55:66:77:88", peer));
        alps_link.simulateConnect(peer);

        ScriptedIap2Phone phone;
        auto deliverBt = [&alps_link](const Bytes& b) { alps_link.simulateRx(b); };
        phone.consumeFromAccessory(alps_link.tx_to_phone);
        phone.sendDetect();
        deliverBt(phone.tx_to_accessory); phone.tx_to_accessory.clear();
        phone.consumeFromAccessory(alps_link.tx_to_phone);
        phone.sendSynAck();
        deliverBt(phone.tx_to_accessory); phone.tx_to_accessory.clear();
        phone.consumeFromAccessory(alps_link.tx_to_phone);

        phone.sendControlFrame(iap2::msg::kStartIdentification);
        deliverBt(phone.tx_to_accessory); phone.tx_to_accessory.clear();
        phone.consumeFromAccessory(alps_link.tx_to_phone);
        phone.sendControlFrame(iap2::msg::kIdentificationAccepted);
        deliverBt(phone.tx_to_accessory); phone.tx_to_accessory.clear();
        phone.consumeFromAccessory(alps_link.tx_to_phone);

        phone.sendControlFrame(iap2::msg::kRequestAuthenticationCertificate);
        deliverBt(phone.tx_to_accessory); phone.tx_to_accessory.clear();
        phone.consumeFromAccessory(alps_link.tx_to_phone);

        iap2::ParameterList chal;
        chal.addRaw(iap2::param::kAuthChallengeData, Bytes(16U, 0x77U));
        phone.sendControlFrame(iap2::msg::kRequestAuthenticationChallengeResponse, chal);
        deliverBt(phone.tx_to_accessory); phone.tx_to_accessory.clear();

        CHECK_EQ(plat::kConnWaiting, daemon.connectivity().state());
        CHECK_EQ(0, sim_wlan.enable_calls);
        CHECK(!alps_link.isLinkUp());
        CHECK_EQ(1ULL, daemon.connectivity().failureTeardowns());

        // Destroy without explicit stop() -> destructor still restores ALPS slot 5!
        daemon.connectivity().wifiAp().setWlanControllerForTest(NULL);
        daemon.connectivity().wifiAp().setAccessPointReaderForTest(NULL);
        daemon.connectivity().wifiAp().setHostapdCtrlForTest(NULL);
        // Stop daemon (or let dtor run); verify slot 5 restored.
        daemon.stop();
        CHECK(spp_mem.slotMatchesGeneric(plat::kAlpsSpareSlot));
        removeTempDir(dir);
    }

    // 2. Wired auth fails -> TAP closed & USB interfaces released immediately!
    {
        const std::string dir = makeTempDir("cp_sim_usb_authfail");
        plat::CarPlayDaemonConfig cfg = makeSimDaemonConfig(dir);
        cfg.enable_wired = true;
        cfg.connectivity_config.wired_failure_retry_ms = 0;  // keep stopped until test inspects

        plat::CarPlayDaemon daemon(cfg);
        SimUsbHost sim_usb;
        SimTapPort sim_tap;
        SimAuthProvider sim_auth;
        sim_auth.fail_cert = true;  // Inject auth cert failure!

        daemon.connectivity().setUsbHostForTest(&sim_usb);
        daemon.connectivity().setTapPortForTest(&sim_tap);
        daemon.connectivity().setIap2AuthProvider(&sim_auth);

        REQUIRE(daemon.start());
        sim_usb.simulateArrival(buildCarPlayUsbBlob());
        CHECK(sim_tap.isOpen());
        CHECK_EQ(plat::kConnWiredIap2, daemon.connectivity().state());

        ScriptedIap2Phone phone;
        auto deliverUsb = [&sim_usb](const Bytes& b) { sim_usb.deliverIap2In(b); };
        phone.consumeFromAccessory(sim_usb.iap2_out);
        phone.sendDetect();
        phone.sendSynAck();
        deliverUsb(phone.tx_to_accessory); phone.tx_to_accessory.clear();
        phone.consumeFromAccessory(sim_usb.iap2_out);

        phone.sendControlFrame(iap2::msg::kRequestAuthenticationCertificate);
        deliverUsb(phone.tx_to_accessory); phone.tx_to_accessory.clear();

        CHECK_EQ(plat::kConnWaiting, daemon.connectivity().state());
        CHECK(!sim_tap.isOpen());
        CHECK(!sim_usb.isDeviceOpen());
        CHECK(sim_usb.claimed_interfaces.empty());
        CHECK_EQ(1ULL, daemon.connectivity().failureTeardowns());

        daemon.stop();
        removeTempDir(dir);
    }
#endif
}

TEST_CASE(failureInjectionMidSessionDisconnectAndConcurrencyPolicy) {
#ifdef _WIN32
    return;
#else
    const std::string dir = makeTempDir("cp_sim_concurrent");
    plat::CarPlayDaemonConfig cfg = makeSimDaemonConfig(dir);
    cfg.enable_wireless = true;
    cfg.enable_wired = true;
    cfg.connectivity_config.wireless_ips_override.push_back("127.0.0.1");
    cfg.connectivity_config.wifi_ap_config.backend = plat::kWifiApBackendNative;
    cfg.connectivity_config.alps_config.double_read_delay_ms = 0U;
    cfg.connectivity_config.alps_config.restore_poll_interval_ms = 0U;

    plat::CarPlayDaemon daemon(cfg);
    struct NoopBtListener : public plat::BtTransportListener {
        virtual void onBtTransportConnected(const plat::BtAddr&) {}
        virtual void onBtTransportData(const uint8_t*, size_t) {}
        virtual void onBtTransportDisconnected(const std::string&) {}
    } noop_bt;
    SimSppMemoryBackend spp_mem;
    SimAlpsSppLink alps_link(&spp_mem);
    plat::AlpsBtTransport real_alps_bt(daemon.reactor(), noop_bt,
                                       cfg.connectivity_config.alps_config,
                                       &spp_mem, &alps_link);

    SimWlanController sim_wlan;
    SimAccessPointReader sim_ap_reader;
    SimHostapdCtrl sim_ctrl;
    SimDnsSdState dns_state;
    g_sim_dnssd = &dns_state;
    const plat::DnsSdApi dns_api = makeSimDnsSdApi();
    SimUsbHost sim_usb;
    SimTapPort sim_tap;
    SimAuthProvider sim_auth;

    daemon.connectivity().setBtTransportForTest(&real_alps_bt);
    daemon.connectivity().setUsbHostForTest(&sim_usb);
    daemon.connectivity().setTapPortForTest(&sim_tap);
    daemon.connectivity().setIap2AuthProvider(&sim_auth);
    daemon.connectivity().wifiAp().setWlanControllerForTest(&sim_wlan);
    daemon.connectivity().wifiAp().setAccessPointReaderForTest(&sim_ap_reader);
    daemon.connectivity().wifiAp().setHostapdCtrlForTest(&sim_ctrl);
    daemon.connectivity().wifiAp().setNativeCapabilityForTest(1);
    daemon.connectivity().mdnsAdvertiser().setApiOverride(&dns_api);

    REQUIRE(daemon.start());

    // 1. Start a Wired session first.
    sim_usb.simulateArrival(buildCarPlayUsbBlob());
    CHECK_EQ(plat::kConnWiredIap2, daemon.connectivity().state());

    // 2. While Wired is active, an incoming BT connection must be rejected ("one active phone at a time")!
    plat::BtAddr peer;
    REQUIRE(plat::BtAddr::parse("44:55:66:77:88:99", peer));
    alps_link.simulateConnect(peer);
    CHECK_EQ(1ULL, daemon.connectivity().rejectedConcurrentAttempts());
    CHECK_EQ(plat::kConnWiredIap2, daemon.connectivity().state());
    CHECK_EQ(plat::kActiveWired, daemon.connectivity().activeTransport());
    CHECK(!alps_link.isLinkUp());

    // Unplug USB -> returns cleanly to kConnWaiting.
    sim_usb.simulateRemoval();
    CHECK_EQ(plat::kConnWaiting, daemon.connectivity().state());
    CHECK_EQ(plat::kActiveNone, daemon.connectivity().activeTransport());

    // 3. Now start a Wireless session and verify BT mid-iAP2 disappearance cleans up!
    alps_link.simulateConnect(peer);
    CHECK_EQ(plat::kConnWirelessIap2, daemon.connectivity().state());
    // While wireless is active, a USB arrival must be rejected without disrupting wireless!
    sim_usb.simulateArrival(buildCarPlayUsbBlob());
    CHECK_EQ(2ULL, daemon.connectivity().rejectedConcurrentAttempts());
    CHECK_EQ(plat::kConnWirelessIap2, daemon.connectivity().state());
    CHECK_EQ(plat::kActiveWireless, daemon.connectivity().activeTransport());
    CHECK(!sim_tap.isOpen());

    // Phone disappears over BT mid-iAP2 -> cleans up and returns to kConnWaiting, restarting USB bridge!
    alps_link.simulateDisconnect("link lost mid-iap2");
    CHECK_EQ(plat::kConnWaiting, daemon.connectivity().state());
    CHECK_EQ(plat::kActiveNone, daemon.connectivity().activeTransport());
    CHECK_EQ(plat::kBridgeWaiting, daemon.connectivity().usbBridge()->state());

    // 4. Bring Wireless all the way up to active AirPlay session, then call daemon.stop() mid-session!
    alps_link.simulateConnect(peer);
    ScriptedIap2Phone iap2_phone;
    auto deliverBt = [&alps_link](const Bytes& b) { alps_link.simulateRx(b); };
    driveIap2SyncAndAuth(iap2_phone, alps_link.tx_to_phone, deliverBt, sim_auth, true);
    daemon.reactor().runOnce(10);

    SimAirPlayPhone airplay_phone(daemon.reactor(), "WL-MIDSTOP-001");
    REQUIRE(daemon.pairingStore()->save(airplay_phone.id, airplay_phone.ltsk.public_key));
    REQUIRE(airplay_phone.connectTcp(airplay_phone.control_conn,
                                     plat::Address::ipv4Loopback(daemon.controlPort())));
    REQUIRE(airplay_phone.pairVerify());

    int status = 0;
    rtsp::Request info_resp;
    REQUIRE(airplay_phone.request("GET", "/info", "", Bytes(), status, info_resp));
    CHECK_EQ(200, status);

    REQUIRE(airplay_phone.timing_sock.open(plat::Address::ipv4Loopback(0U)));
    carplay::bplist::Value setup_sess = carplay::bplist::Value::makeDict();
    setup_sess.set("deviceID", carplay::bplist::Value::makeString("44:55:66:77:88:99"));
    setup_sess.set("name", carplay::bplist::Value::makeString("Wireless MidStop"));
    setup_sess.set("model", carplay::bplist::Value::makeString("iPhone16,1"));
    setup_sess.set("timingPort", carplay::bplist::Value::makeInt(airplay_phone.timing_sock.port()));
    rtsp::Request setup_resp;
    REQUIRE(airplay_phone.request("SETUP", "rtsp://127.0.0.1/session",
                                  rtsp::kContentTypeBinaryPlist,
                                  encodeBplist(setup_sess), status, setup_resp));
    CHECK_EQ(200, status);
    CHECK_EQ(plat::kConnActiveSession, daemon.connectivity().state());

    // Daemon stop mid-session -> closes AirPlay, restores AP, unregisters mDNS, restores ALPS slot 5!
    daemon.stop();
    CHECK_EQ(plat::kConnStopped, daemon.connectivity().state());
    CHECK(!daemon.hasActiveSession());
    CHECK_EQ(plat::kWifiApStopped, daemon.connectivity().wifiAp().state());
    CHECK(sim_wlan.restore_calls >= 1);
    CHECK(!daemon.connectivity().mdnsAdvertiser().isActive());
    CHECK(dns_state.deallocate_calls >= 1);
    CHECK(spp_mem.slotMatchesGeneric(plat::kAlpsSpareSlot));

    g_sim_dnssd = NULL;
    removeTempDir(dir);
#endif
}

}  // namespace

int main() {
    return test_support::runAll("test_carplay_e2e_sim");
}
