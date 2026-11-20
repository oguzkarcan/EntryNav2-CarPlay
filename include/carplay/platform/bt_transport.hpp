#ifndef CARPLAY_PLATFORM_BT_TRANSPORT_HPP
#define CARPLAY_PLATFORM_BT_TRANSPORT_HPP

// Unified Bluetooth byte-stream transport interface (`BtTransport`) for wireless
// CarPlay iAP2 over either:
//   1. BMW HU_ENTRYNAV2 native ALPS "Evolution" SPP stack (`AlpsBtTransport`,
//      preferred on vehicle), or
//   2. Kernel AF_BLUETOOTH / BTPROTO_RFCOMM + BlueZ sdpd (`RfcommBtTransport`,
//      fallback when ALPS is absent).
//
// ALPS/UUID/SPP compatibility report derived from EntryNav2-Android-Auto 0.13.0-rc.6
// tools/aa_supervisor.cpp, PolyForm Noncommercial License 1.0.0.
//
// `BtTransportByteSink` adapts `BtTransport::sendBytes()` directly to
// `carplay::iap2::ByteSink` (`include/carplay/iap2_link.hpp`).

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>

#include "carplay/iap2_link.hpp"
#include "carplay/platform/alps_spp.hpp"
#include "carplay/platform/bt_rfcomm.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/sdp_record.hpp"

namespace carplay {
namespace platform {

enum BtBackendKind {
    kBtBackendNone = 0,
    kBtBackendAlpsSpp = 1,
    kBtBackendRfcomm = 2
};

const char* btBackendKindName(BtBackendKind kind);

class BtTransportListener {
public:
    virtual ~BtTransportListener() {}
    virtual void onBtTransportConnected(const BtAddr& peer) = 0;
    virtual void onBtTransportData(const uint8_t* data, size_t len) = 0;
    virtual void onBtTransportDisconnected(const std::string& reason) = 0;
};

class BtTransport {
public:
    virtual ~BtTransport() {}

    virtual BtBackendKind backendKind() const = 0;
    virtual const char* backendName() const = 0;

    virtual bool start(std::string* error_out = NULL) = 0;
    virtual void stop() = 0;
    virtual void disconnect(const std::string& reason = "local disconnect") = 0;
    virtual bool sendBytes(const uint8_t* data, size_t len) = 0;

    virtual void setListener(BtTransportListener* listener) = 0;
    virtual bool isStarted() const = 0;
    virtual bool isConnected() const = 0;
    virtual const BtAddr& peerAddress() const = 0;
};

/// Adapts a `BtTransport` instance to `carplay::iap2::ByteSink` for `iap2::Link`.
class BtTransportByteSink : public iap2::ByteSink {
public:
    explicit BtTransportByteSink(BtTransport& transport) : transport_(transport) {}
    virtual bool sendBytes(const uint8_t* data, size_t len) {
        return transport_.sendBytes(data, len);
    }

private:
    BtTransport& transport_;
};

// ------------------------------------------------------------------------------------------------
// ALPS SPP Backend
// ------------------------------------------------------------------------------------------------

class AlpsBtTransport : public BtTransport {
public:
    AlpsBtTransport(Reactor& reactor,
                    BtTransportListener& listener,
                    const AlpsSppManagerConfig& config = AlpsSppManagerConfig(),
                    SppMemoryBackend* mem_backend = NULL,
                    AlpsSppLink* link_override = NULL);
    virtual ~AlpsBtTransport();

    virtual BtBackendKind backendKind() const { return kBtBackendAlpsSpp; }
    virtual const char* backendName() const { return "alps-spp"; }

    virtual bool start(std::string* error_out = NULL);
    virtual void stop();
    virtual void disconnect(const std::string& reason = "local disconnect");
    virtual bool sendBytes(const uint8_t* data, size_t len);

    virtual void setListener(BtTransportListener* listener) { listener_ = listener; }
    virtual bool isStarted() const { return manager_.isStarted(); }
    virtual bool isConnected() const { return manager_.isConnected(); }
    virtual const BtAddr& peerAddress() const { return manager_.peerAddress(); }

    const AlpsSppManager& manager() const { return manager_; }

private:
    AlpsBtTransport(const AlpsBtTransport&) = delete;
    AlpsBtTransport& operator=(const AlpsBtTransport&) = delete;

    class ManagerAdapter : public AlpsSppManagerListener {
    public:
        explicit ManagerAdapter(AlpsBtTransport* owner) : owner_(owner) {}
        virtual void onAlpsManagerConnected(const BtAddr& peer) {
            if (owner_->listener_ != NULL) {
                owner_->listener_->onBtTransportConnected(peer);
            }
        }
        virtual void onAlpsManagerData(const uint8_t* data, size_t len) {
            if (owner_->listener_ != NULL) {
                owner_->listener_->onBtTransportData(data, len);
            }
        }
        virtual void onAlpsManagerDisconnected(const std::string& reason) {
            if (owner_->listener_ != NULL) {
                owner_->listener_->onBtTransportDisconnected(reason);
            }
        }
    private:
        AlpsBtTransport* owner_;
    };

    BtTransportListener* listener_;
    ManagerAdapter adapter_;
    AlpsSppManager manager_;
};

// ------------------------------------------------------------------------------------------------
// Kernel RFCOMM + BlueZ sdpd Fallback Backend
// ------------------------------------------------------------------------------------------------

struct RfcommBtTransportConfig {
    BtRfcommConfig rfcomm;
    sdp::Iap2SdpConfig sdp;
    bool require_sdp_registration;

    RfcommBtTransportConfig() : require_sdp_registration(false) {}
};

class RfcommBtTransport : public BtTransport {
public:
    RfcommBtTransport(Reactor& reactor,
                      BtTransportListener& listener,
                      const RfcommBtTransportConfig& config = RfcommBtTransportConfig(),
                      BtSocketOps* socket_ops = NULL,
                      std::unique_ptr<sdp::SdpRegistrar> sdp_registrar =
                          std::unique_ptr<sdp::SdpRegistrar>());
    virtual ~RfcommBtTransport();

    virtual BtBackendKind backendKind() const { return kBtBackendRfcomm; }
    virtual const char* backendName() const { return "bluez-rfcomm"; }

    virtual bool start(std::string* error_out = NULL);
    virtual void stop();
    virtual void disconnect(const std::string& reason = "local disconnect");
    virtual bool sendBytes(const uint8_t* data, size_t len);

    virtual void setListener(BtTransportListener* listener) { listener_ = listener; }
    virtual bool isStarted() const { return server_.isListening(); }
    virtual bool isConnected() const { return server_.isConnected(); }
    virtual const BtAddr& peerAddress() const { return server_.peerAddress(); }

    uint8_t boundChannel() const { return server_.boundChannel(); }
    bool sdpRegistered() const { return sdp_registered_; }
    uint32_t sdpHandle() const { return sdp_handle_; }

private:
    RfcommBtTransport(const RfcommBtTransport&) = delete;
    RfcommBtTransport& operator=(const RfcommBtTransport&) = delete;

    class ServerAdapter : public BtRfcommListener {
    public:
        explicit ServerAdapter(RfcommBtTransport* owner) : owner_(owner) {}
        virtual void onBtConnected(const BtAddr& peer, uint8_t /*channel*/) {
            if (owner_->listener_ != NULL) {
                owner_->listener_->onBtTransportConnected(peer);
            }
        }
        virtual void onBtData(const uint8_t* data, size_t len) {
            if (owner_->listener_ != NULL) {
                owner_->listener_->onBtTransportData(data, len);
            }
        }
        virtual void onBtDisconnected(const std::string& reason) {
            if (owner_->listener_ != NULL) {
                owner_->listener_->onBtTransportDisconnected(reason);
            }
        }
    private:
        RfcommBtTransport* owner_;
    };

    BtTransportListener* listener_;
    RfcommBtTransportConfig config_;
    ServerAdapter adapter_;
    BtRfcommServer server_;
    std::unique_ptr<sdp::SdpRegistrar> sdp_registrar_;
    bool sdp_registered_;
    uint32_t sdp_handle_;
};

// ------------------------------------------------------------------------------------------------
// Runtime Capability Probe & Backend Selection
// ------------------------------------------------------------------------------------------------

struct BtTransportProbePaths {
    BtProbePaths rfcomm_paths;
    std::string proc_root;
    bool probe_alps_dbus;

    BtTransportProbePaths() : proc_root("/proc"), probe_alps_dbus(true) {}
};

struct BtTransportCapability {
    BtCapability rfcomm;
    bool alps_library_present;
    bool alps_dbus_ready;
    bool alps_service_owned;
    std::string alps_detail;

    BtTransportCapability()
        : alps_library_present(false),
          alps_dbus_ready(false),
          alps_service_owned(false) {}

    bool alpsCapable() const { return alps_library_present && alps_dbus_ready; }
    bool rfcommCapable() const { return rfcomm.rfcommSocketCapable(); }
};

BtTransportCapability probeBtTransportCapability();
BtTransportCapability probeBtTransportCapability(const BtTransportProbePaths& paths);

/// Selects `kBtBackendAlpsSpp` first when ALPS is capable, else `kBtBackendRfcomm`
/// when AF_BLUETOOTH + HCI is capable, else `kBtBackendNone`.
BtBackendKind selectBtBackend(const BtTransportCapability& cap);

std::string formatBtTransportCapability(const BtTransportCapability& cap);
void logBtTransportCapability(const BtTransportCapability& cap);

// ------------------------------------------------------------------------------------------------
// ALPS / UUID / SPP Compatibility Probe (wireless vs USB-only fallback)
// ------------------------------------------------------------------------------------------------

enum CompatStatusLevel {
    kCompatPass = 0,
    kCompatWarn = 1,
    kCompatInfo = 2,
    kCompatFail = 3
};

struct CompatCheckResult {
    std::string name;
    CompatStatusLevel level;
    std::string detail;

    CompatCheckResult() : level(kCompatFail) {}
    CompatCheckResult(const std::string& n, CompatStatusLevel l, const std::string& d)
        : name(n), level(l), detail(d) {}
};

struct AlpsCompatReport {
    bool wireless_ready;
    bool usb_mode;
    CompatCheckResult alps;
    CompatCheckResult uuid;
    CompatCheckResult spp;

    AlpsCompatReport() : wireless_ready(false), usb_mode(false) {}
};

/// Evaluates ALPS library structure, iAP2 SPP baseline/slot policy, and ALPS D-Bus readiness
/// without mutating head-unit state. Unknown ALPS library builds (e.g. F20 2017 15024/480/36)
/// fail cleanly instead of reading wrong memory offsets, and are downgraded to `kCompatInfo`
/// ("wireless only") when `usb_mode` is true so wired USB CarPlay is never blocked.
AlpsCompatReport probeAlpsSppCompat(const BtTransportCapability& cap,
                                    SppMemoryBackend* mem_backend = NULL,
                                    bool usb_mode = false,
                                    const CarPlaySlotPolicy& policy = CarPlaySlotPolicy());
std::string formatAlpsCompatReport(const AlpsCompatReport& report);
const char* compatStatusLevelName(CompatStatusLevel level);

/// Instantiates the selected backend (or returns NULL when `kBtBackendNone`).
std::unique_ptr<BtTransport> createBtTransport(
    Reactor& reactor,
    BtTransportListener& listener,
    const BtTransportCapability& cap,
    const AlpsSppManagerConfig& alps_config = AlpsSppManagerConfig(),
    const RfcommBtTransportConfig& rfcomm_config = RfcommBtTransportConfig(),
    const std::string& sdp_socket_path = "/var/run/sdp");

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_BT_TRANSPORT_HPP
