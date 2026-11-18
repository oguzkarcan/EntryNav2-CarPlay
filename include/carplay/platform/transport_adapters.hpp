#ifndef CARPLAY_PLATFORM_TRANSPORT_ADAPTERS_HPP
#define CARPLAY_PLATFORM_TRANSPORT_ADAPTERS_HPP

// Lightweight cross-package adapters connecting:
//   * B1 carplay::iap2::Session <-> B2 carplay::platform::BtTransport
//   * B1 carplay::iap2::Session <-> B4 carplay::platform::UsbCarPlayBridge
//   * B3 carplay::platform::WifiCredentials / WifiAp <-> B1 iap2::WiFiConfiguration (0x5703)
//
// No internal threads, clocks, or heap ownership of external transports/sessions.
// Callers retain ownership of referenced transports, sessions, and downstream listeners,
// and must ensure those objects outlive these adapters (or detach them via set*(NULL)
// before destruction).

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "carplay/iap2_link.hpp"
#include "carplay/iap2_session.hpp"
#include "carplay/platform/bt_transport.hpp"
#include "carplay/platform/usb_carplay_bridge.hpp"
#include "carplay/platform/wifi_ap.hpp"

namespace carplay {
namespace platform {

/// Bridges a `BtTransport` and an `iap2::Session`:
///   * `iap2::ByteSink::sendBytes()` -> `BtTransport::sendBytes()`
///   * `BtTransportListener::onBtTransportConnected()` -> downstream notify, then `Session::start()`
///   * `BtTransportListener::onBtTransportData()` -> `Session::feed()`, then downstream notify
///   * `BtTransportListener::onBtTransportDisconnected()` -> `Session::reset(false)`, then downstream notify
///
/// Implementing both interfaces lets callers break the construction order cycle between
/// `BtTransport(BtTransportListener&)` and `iap2::Session(iap2::ByteSink&, ...)`.
class BtSessionAdapter : public BtTransportListener, public iap2::ByteSink {
public:
    explicit BtSessionAdapter(BtTransport* transport = NULL,
                              iap2::Session* session = NULL,
                              BtTransportListener* downstream = NULL);

    void setTransport(BtTransport* transport) { transport_ = transport; }
    void setSession(iap2::Session* session) { session_ = session; }
    void setDownstreamListener(BtTransportListener* downstream) { downstream_ = downstream; }

    BtTransport* transport() const { return transport_; }
    iap2::Session* session() const { return session_; }
    BtTransportListener* downstreamListener() const { return downstream_; }

    // iap2::ByteSink
    virtual bool sendBytes(const uint8_t* data, size_t len);

    // BtTransportListener
    virtual void onBtTransportConnected(const BtAddr& peer);
    virtual void onBtTransportData(const uint8_t* data, size_t len);
    virtual void onBtTransportDisconnected(const std::string& reason);

private:
    BtSessionAdapter(const BtSessionAdapter&) = delete;
    BtSessionAdapter& operator=(const BtSessionAdapter&) = delete;

    BtTransport* transport_;
    iap2::Session* session_;
    BtTransportListener* downstream_;
};

/// Adapts `UsbCarPlayBridge::writeIap2()` directly to `carplay::iap2::ByteSink`.
class UsbBridgeIap2ByteSink : public iap2::ByteSink {
public:
    explicit UsbBridgeIap2ByteSink(UsbCarPlayBridge& bridge) : bridge_(bridge) {}

    virtual bool sendBytes(const uint8_t* data, size_t len) {
        return bridge_.writeIap2(data, len);
    }

private:
    UsbCarPlayBridge& bridge_;
};

/// Bridges a `UsbCarPlayBridge` and an `iap2::Session`:
///   * `iap2::ByteSink::sendBytes()` -> `UsbCarPlayBridge::writeIap2()`
///   * `UsbCarPlayBridgeListener::onIap2Ready()` -> downstream notify, then `Session::start()`
///   * `UsbCarPlayBridgeListener::onIap2Data()` -> `Session::feed()`, then downstream notify
///   * `UsbCarPlayBridgeListener::onDeviceRemoved()` -> `Session::reset(false)`, then downstream notify
///   * Other bridge notifications (`onBridgeStateChanged`, `onNcmReady`, `onBridgeError`)
///     pass straight through to `downstream`.
class UsbBridgeSessionAdapter : public UsbCarPlayBridgeListener, public iap2::ByteSink {
public:
    explicit UsbBridgeSessionAdapter(UsbCarPlayBridge* bridge = NULL,
                                     iap2::Session* session = NULL,
                                     UsbCarPlayBridgeListener* downstream = NULL);

    void setBridge(UsbCarPlayBridge* bridge) { bridge_ = bridge; }
    void setSession(iap2::Session* session) { session_ = session; }
    void setDownstreamListener(UsbCarPlayBridgeListener* downstream) { downstream_ = downstream; }

    UsbCarPlayBridge* bridge() const { return bridge_; }
    iap2::Session* session() const { return session_; }
    UsbCarPlayBridgeListener* downstreamListener() const { return downstream_; }

    // iap2::ByteSink
    virtual bool sendBytes(const uint8_t* data, size_t len);

    // UsbCarPlayBridgeListener
    virtual void onBridgeStateChanged(BridgeState state);
    virtual void onIap2Ready(const usb::Iap2InterfaceSelection& iap2);
    virtual void onIap2Data(const uint8_t* data, size_t len);
    virtual void onNcmReady(const std::string& tap_ifname,
                            uint32_t tap_ifindex,
                            const uint8_t tap_mac[6]);
    virtual void onDeviceRemoved();
    virtual void onBridgeError(const std::string& reason);

private:
    UsbBridgeSessionAdapter(const UsbBridgeSessionAdapter&) = delete;
    UsbBridgeSessionAdapter& operator=(const UsbBridgeSessionAdapter&) = delete;

    UsbCarPlayBridge* bridge_;
    iap2::Session* session_;
    UsbCarPlayBridgeListener* downstream_;
};

/// Converts B3 `WifiCredentials` (from `WifiAp` / `EvoApInfo::toWifiCredentials`) into B1
/// `iap2::WiFiConfiguration` for `iap2::SessionConfig::wifi_config` or `0x5703` responses.
bool toIap2WiFiConfiguration(const WifiCredentials& creds,
                             iap2::WiFiConfiguration& out,
                             std::string* error_out = NULL);

/// Converts `ap.credentials()` into `iap2::WiFiConfiguration` when `ap` is `kWifiApRunning`.
bool populateIap2WiFiConfiguration(const WifiAp& ap,
                                   iap2::WiFiConfiguration& out,
                                   std::string* error_out = NULL);

/// Caches live credentials from `WifiApListener::onWifiApStarted()` (clearing them on
/// stop/restart/failure) and formats them as `iap2::WiFiConfiguration` for iAP2 `0x5702`/`0x5703`.
/// Optionally reads directly from `ap` when running, and forwards `WifiApListener` events
/// to `downstream`.
class WifiApCredentialsAdapter : public WifiApListener {
public:
    explicit WifiApCredentialsAdapter(const WifiAp* ap = NULL,
                                      WifiApListener* downstream = NULL);

    void setWifiAp(const WifiAp* ap) { ap_ = ap; }
    void setDownstreamListener(WifiApListener* downstream) { downstream_ = downstream; }
    void clearCredentials();

    bool hasCredentials() const;
    bool provideWiFiConfiguration(iap2::WiFiConfiguration& out,
                                  std::string* error_out = NULL) const;

    // WifiApListener
    virtual void onWifiApStarted(const WifiCredentials& creds);
    virtual void onWifiApStopped();
    virtual void onWifiApRestarting(int attempt, const std::string& reason);
    virtual void onWifiApFailed(const std::string& reason);
    virtual void onStationConnected(const std::string& mac);
    virtual void onStationDisconnected(const std::string& mac);

private:
    WifiApCredentialsAdapter(const WifiApCredentialsAdapter&) = delete;
    WifiApCredentialsAdapter& operator=(const WifiApCredentialsAdapter&) = delete;

    const WifiAp* ap_;
    WifiApListener* downstream_;
    bool has_credentials_;
    WifiCredentials credentials_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_TRANSPORT_ADAPTERS_HPP
