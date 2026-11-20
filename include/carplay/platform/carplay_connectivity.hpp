#ifndef CARPLAY_PLATFORM_CARPLAY_CONNECTIVITY_HPP
#define CARPLAY_PLATFORM_CARPLAY_CONNECTIVITY_HPP

// Transport-to-SessionServer orchestration layer for BMW HU_ENTRYNAV2 CarPlay.
//
// Wires the standalone Phase 4 Wave A/B transport modules into CarPlayDaemon / SessionServer
// on the single-threaded Reactor:
//   * Wireless: BtTransport (ALPS SPP preferred, kernel RFCOMM fallback) -> BtSessionAdapter ->
//     iap2::Session (wirelessBluetooth profile + AuthProvider) -> WifiAp (car-native EVO AP
//     preferred, hostapd fallback) -> toIap2WiFiConfiguration / 0x5703 / 0x4301 ->
//     MdnsAdvertiser (_airplay._tcp) -> SessionServer TCP (:7000).
//   * Wired: UsbHost (coexistence-safe: detach_usbfs_driver = false by default) ->
//     UsbCarPlayBridge (CDC-NCM <-> TapIface) -> UsbBridgeSessionAdapter -> iap2::Session
//     (wiredUsb profile + AuthProvider) -> 0x4301 with TAP IPv6 link-local -> SessionServer.
//
// Enforces:
//   * One active phone at a time across wireless and wired transports.
//   * Explicit state machine with logged transitions.
//   * Clean teardown/restore on every failure path and on stop() (restore borrowed ALPS slot 5,
//     stop/restore Wi-Fi AP, unregister mDNS, close TAP, release USB interfaces).
//   * Purely Reactor-thread execution; all vehicle backends sit behind interfaces for host fakes.

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "carplay/airplay_info.hpp"
#include "carplay/auth_provider.hpp"
#include "carplay/iap2_session.hpp"
#include "carplay/pairing.hpp"
#include "carplay/platform/alps_spp.hpp"
#include "carplay/platform/bt_transport.hpp"
#include "carplay/platform/mdns_advertiser.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/session_server.hpp"
#include "carplay/platform/tap_iface.hpp"
#include "carplay/platform/transport_adapters.hpp"
#include "carplay/platform/usb_carplay_bridge.hpp"
#include "carplay/platform/usb_host.hpp"
#include "carplay/platform/wifi_ap.hpp"

namespace carplay {
namespace platform {

enum ConnectivityState {
    kConnStopped = 0,
    kConnWaiting = 1,
    kConnWirelessIap2 = 2,
    kConnWirelessApStarting = 3,
    kConnWirelessWaitingAirPlay = 4,
    kConnWiredConfiguring = 5,
    kConnWiredIap2 = 6,
    kConnWiredWaitingAirPlay = 7,
    kConnActiveSession = 8
};

enum ActiveTransportMode {
    kActiveNone = 0,
    kActiveWireless = 1,
    kActiveWired = 2
};

const char* connectivityStateName(ConnectivityState state);
const char* activeTransportModeName(ActiveTransportMode mode);

class CarPlayConnectivityListener {
public:
    virtual ~CarPlayConnectivityListener() {}

    virtual void onConnectivityStateChanged(ConnectivityState /*old_state*/,
                                            ConnectivityState /*new_state*/,
                                            ActiveTransportMode /*mode*/) {}
    virtual void onConnectivityError(const std::string& /*reason*/) {}
    virtual void onWirelessCredentialsReady(const WifiCredentials& /*creds*/) {}
};

struct CarPlayConnectivityConfig {
    /// Independent transport enables. Both default to false as safe defaults:
    ///   * enable_wireless=false avoids borrowing ALPS SPP slot 5 or toggling car-native
    ///     Wi-Fi AP (`vmostd`/`wland`) until wireless CarPlay + an AuthProvider are enabled.
    ///   * enable_wired=false avoids touching Apple USB devices alongside BMW MediaPlayer/CARPLAY
    ///     unless explicitly enabled (and even when enabled, detach_usbfs_driver stays false).
    bool enable_wireless;
    bool enable_wired;

    // Accessory identification strings for iAP2 0x1D01.
    std::string accessory_name;
    std::string accessory_model;
    std::string accessory_manufacturer;
    std::string accessory_serial;
    std::string accessory_firmware_version;
    std::string accessory_hardware_version;
    std::string language;
    std::string ea_protocol;

    uint16_t wired_available_current_ma;
    int64_t iap2_tick_interval_ms;
    /// Timeout (ms) while waiting for AP startup or AirPlay TCP connect after 0x4301 (0 = off).
    int64_t handoff_timeout_ms;
    /// Delay (ms) before restarting UsbCarPlayBridge after a wired failure (0 = no auto-restart).
    int64_t wired_failure_retry_ms;
    bool start_mdns_on_wireless;

    /// Optional 6-byte local Bluetooth MAC for iAP2 identification (empty = omit).
    std::vector<uint8_t> bluetooth_mac;
    /// Optional explicit IP addresses advertised in wireless 0x4301 (empty = query AP interface).
    std::vector<std::string> wireless_ips_override;
    /// Optional explicit IPv6 link-local literal for wired 0x4301 (empty = query TAP / EUI-64).
    std::string wired_ipv6_override;

    AlpsSppManagerConfig alps_config;
    RfcommBtTransportConfig rfcomm_config;
    std::string sdp_socket_path;
    WifiApConfig wifi_ap_config;
    UsbHostConfig usb_host_config;
    TapConfig tap_config;
    UsbCarPlayBridgeConfig usb_bridge_config;

    CarPlayConnectivityConfig();
};

class CarPlayConnectivity {
public:
    CarPlayConnectivity(Reactor& reactor, pairing::RandomSource& rng);
    virtual ~CarPlayConnectivity();

    // ---- Pre-start configuration / test injection hooks (must be called while kConnStopped) ----
    void setListener(CarPlayConnectivityListener* listener) { listener_ = listener; }
    void setIap2AuthProvider(iap2::AuthProvider* auth);
    void setBtTransportForTest(BtTransport* transport);
    void setUsbHostForTest(UsbHostInterface* usb);
    void setTapPortForTest(TapPortInterface* tap);

    WifiAp& wifiAp() { return wifi_ap_; }
    const WifiAp& wifiAp() const { return wifi_ap_; }
    MdnsAdvertiser& mdnsAdvertiser() { return mdns_; }
    const MdnsAdvertiser& mdnsAdvertiser() const { return mdns_; }

    // ---- Lifecycle (Reactor thread) ----
    bool start(SessionServer& server,
               const info::AirPlayConfig& airplay_cfg,
               const pairing::Identity& identity,
               const CarPlayConnectivityConfig& config = CarPlayConnectivityConfig());
    void stop();

    // ---- AirPlay SessionServer notifications (Reactor thread) ----
    void onAirPlaySessionStarted();
    void onAirPlaySessionEnded();
    void onAirPlayIapMessage(const uint8_t* data, size_t len);

    // ---- State & Diagnostics ----
    ConnectivityState state() const { return state_; }
    ActiveTransportMode activeTransport() const { return active_mode_; }
    bool isStarted() const { return started_; }
    bool wirelessTransportReady() const { return wireless_transport_ready_; }
    bool wiredTransportReady() const { return wired_transport_ready_; }

    BtBackendKind activeBtBackend() const;
    WifiApBackend activeWifiApBackend() const { return wifi_ap_.activeBackend(); }
    bool hasActiveWifiCredentials() const { return wifi_creds_adapter_.hasCredentials(); }
    const WifiCredentials& activeWifiCredentials() const { return active_wifi_creds_; }

    const iap2::Session* wirelessIap2Session() const { return wireless_iap2_session_; }
    const iap2::Session* wiredIap2Session() const { return wired_iap2_session_; }
    const UsbCarPlayBridge* usbBridge() const { return usb_bridge_; }
    const BtTransport* btTransport() const { return bt_transport_; }

    uint64_t rejectedConcurrentAttempts() const { return rejected_concurrent_attempts_; }
    uint64_t failureTeardowns() const { return failure_teardowns_; }
    const std::string& lastError() const { return last_error_; }

private:
    CarPlayConnectivity(const CarPlayConnectivity&) = delete;
    CarPlayConnectivity& operator=(const CarPlayConnectivity&) = delete;

    class BtDownstream : public BtTransportListener {
    public:
        explicit BtDownstream(CarPlayConnectivity* owner) : owner_(owner) {}
        virtual void onBtTransportConnected(const BtAddr& peer) {
            owner_->handleBtConnected(peer);
        }
        virtual void onBtTransportData(const uint8_t* data, size_t len) {
            (void)data;
            (void)len;
        }
        virtual void onBtTransportDisconnected(const std::string& reason) {
            owner_->handleBtDisconnected(reason);
        }
    private:
        CarPlayConnectivity* owner_;
    };

    class UsbDownstream : public UsbCarPlayBridgeListener {
    public:
        explicit UsbDownstream(CarPlayConnectivity* owner) : owner_(owner) {}
        virtual void onBridgeStateChanged(BridgeState state) {
            owner_->handleUsbBridgeStateChanged(state);
        }
        virtual void onIap2Ready(const usb::Iap2InterfaceSelection& iap2) {
            owner_->handleUsbIap2Ready(iap2);
        }
        virtual void onIap2Data(const uint8_t* data, size_t len) {
            (void)data;
            (void)len;
        }
        virtual void onNcmReady(const std::string& tap_ifname,
                                uint32_t tap_ifindex,
                                const uint8_t tap_mac[6]) {
            owner_->handleUsbNcmReady(tap_ifname, tap_ifindex, tap_mac);
        }
        virtual void onDeviceRemoved() { owner_->handleUsbDeviceRemoved(); }
        virtual void onBridgeError(const std::string& reason) {
            owner_->handleUsbBridgeError(reason);
        }
    private:
        CarPlayConnectivity* owner_;
    };

    class WifiDownstream : public WifiApListener {
    public:
        explicit WifiDownstream(CarPlayConnectivity* owner) : owner_(owner) {}
        virtual void onWifiApStarted(const WifiCredentials& creds) {
            owner_->handleWifiApStarted(creds);
        }
        virtual void onWifiApStopped() { owner_->handleWifiApStopped(); }
        virtual void onWifiApRestarting(int attempt, const std::string& reason) {
            owner_->handleWifiApRestarting(attempt, reason);
        }
        virtual void onWifiApFailed(const std::string& reason) {
            owner_->handleWifiApFailed(reason);
        }
        virtual void onStationConnected(const std::string& mac) {
            owner_->handleWifiStationConnected(mac);
        }
        virtual void onStationDisconnected(const std::string& mac) {
            owner_->handleWifiStationDisconnected(mac);
        }
    private:
        CarPlayConnectivity* owner_;
    };

    class MdnsDownstream : public MdnsAdvertiserListener {
    public:
        explicit MdnsDownstream(CarPlayConnectivity* owner) : owner_(owner) {}
        virtual void onMdnsRegistered(const std::string& assigned_name,
                                      const std::string& regtype,
                                      const std::string& domain) {
            owner_->handleMdnsRegistered(assigned_name, regtype, domain);
        }
        virtual void onMdnsNameConflictRenamed(const std::string& old_name,
                                               const std::string& new_name) {
            owner_->handleMdnsRenamed(old_name, new_name);
        }
        virtual void onMdnsError(DnsServiceErrorType code, const std::string& message) {
            owner_->handleMdnsError(code, message);
        }
        virtual void onMdnsStopped() {}
    private:
        CarPlayConnectivity* owner_;
    };

    class WirelessIap2Listener : public iap2::SessionListener {
    public:
        explicit WirelessIap2Listener(CarPlayConnectivity* owner) : owner_(owner) {}
        virtual void onStateChanged(iap2::SessionState old_state, iap2::SessionState new_state) {
            owner_->handleIap2StateChanged(true, old_state, new_state);
        }
        virtual void onAuthenticationFailed(const std::string& reason) {
            owner_->handleWirelessIap2Failure(reason);
        }
        virtual void onReady() { owner_->handleWirelessIap2Ready(); }
        virtual bool onWiFiCredentialsRequested(iap2::WiFiConfiguration& out) {
            return owner_->handleWirelessWifiRequested(out);
        }
        virtual bool onCarPlayStartSessionRequested(const iap2::CarPlayAvailability& avail,
                                                    iap2::StartSessionConfig& out) {
            return owner_->handleWirelessStartSessionRequested(avail, out);
        }
        virtual void onError(const std::string& message) {
            owner_->handleWirelessIap2Error(message);
        }
    private:
        CarPlayConnectivity* owner_;
    };

    class WiredIap2Listener : public iap2::SessionListener {
    public:
        explicit WiredIap2Listener(CarPlayConnectivity* owner) : owner_(owner) {}
        virtual void onStateChanged(iap2::SessionState old_state, iap2::SessionState new_state) {
            owner_->handleIap2StateChanged(false, old_state, new_state);
        }
        virtual void onAuthenticationFailed(const std::string& reason) {
            owner_->handleWiredIap2Failure(reason);
        }
        virtual void onReady() { owner_->handleWiredIap2Ready(); }
        virtual bool onCarPlayStartSessionRequested(const iap2::CarPlayAvailability& avail,
                                                    iap2::StartSessionConfig& out) {
            return owner_->handleWiredStartSessionRequested(avail, out);
        }
        virtual void onError(const std::string& message) {
            owner_->handleWiredIap2Failure(message);
        }
    private:
        CarPlayConnectivity* owner_;
    };

    class TickTimerHandler : public TimerHandler {
    public:
        explicit TickTimerHandler(CarPlayConnectivity* owner) : owner_(owner) {}
        virtual void onTimer(uint32_t timer_id) { owner_->handleTimer(timer_id); }
    private:
        CarPlayConnectivity* owner_;
    };

    class UnavailableAuthProvider : public iap2::AuthProvider {
    public:
        virtual bool getCertificate(std::vector<uint8_t>& certificate_out);
        virtual bool signChallenge(const uint8_t* challenge,
                                   size_t challenge_len,
                                   std::vector<uint8_t>& signature_out);
    };

    void setState(ConnectivityState next, const char* reason);
    void reportError(const std::string& msg);
    iap2::AuthProvider& effectiveAuthProvider();

    iap2::IdentificationConfig makeWirelessIdent(const std::string& ssid) const;
    iap2::IdentificationConfig makeWiredIdent(uint8_t usb_interface_number) const;
    bool populateWirelessStartSession(iap2::StartSessionConfig& out) const;
    bool populateWiredStartSession(iap2::StartSessionConfig& out) const;

    bool startWirelessSubsystem();
    bool startWiredSubsystem();
    void ensureWiredRestartIfEnabled();

    void handleBtConnected(const BtAddr& peer);
    void handleBtDisconnected(const std::string& reason);
    void handleWirelessIap2Ready();
    void handleWirelessIap2Error(const std::string& reason);
    void handleWirelessIap2Failure(const std::string& reason);
    bool handleWirelessWifiRequested(iap2::WiFiConfiguration& out);
    bool handleWirelessStartSessionRequested(const iap2::CarPlayAvailability& avail,
                                             iap2::StartSessionConfig& out);

    void handleWifiApStarted(const WifiCredentials& creds);
    void handleWifiApStopped();
    void handleWifiApRestarting(int attempt, const std::string& reason);
    void handleWifiApFailed(const std::string& reason);
    void handleWifiStationConnected(const std::string& mac);
    void handleWifiStationDisconnected(const std::string& mac);

    void handleMdnsRegistered(const std::string& assigned_name,
                              const std::string& regtype,
                              const std::string& domain);
    void handleMdnsRenamed(const std::string& old_name, const std::string& new_name);
    void handleMdnsError(DnsServiceErrorType code, const std::string& message);

    void handleUsbBridgeStateChanged(BridgeState state);
    void handleUsbIap2Ready(const usb::Iap2InterfaceSelection& iap2);
    void handleUsbNcmReady(const std::string& tap_ifname,
                           uint32_t tap_ifindex,
                           const uint8_t tap_mac[6]);
    void handleUsbDeviceRemoved();
    void handleUsbBridgeError(const std::string& reason);
    void handleWiredIap2Ready();
    void handleWiredIap2Failure(const std::string& reason);
    bool handleWiredStartSessionRequested(const iap2::CarPlayAvailability& avail,
                                          iap2::StartSessionConfig& out);

    void handleIap2StateChanged(bool wireless,
                                iap2::SessionState old_state,
                                iap2::SessionState new_state);
    void handleTimer(uint32_t timer_id);

    void teardownWirelessSession(const std::string& reason, bool is_failure);
    void teardownWiredSession(const std::string& reason,
                              bool is_failure,
                              bool schedule_restart);
    void startMdnsForWireless(const WifiCredentials& creds);

    Reactor& reactor_;
    pairing::RandomSource& rng_;
    CarPlayConnectivityListener* listener_;
    CarPlayConnectivityConfig config_;

    SessionServer* server_;
    info::AirPlayConfig airplay_cfg_;
    const pairing::Identity* identity_;

    UnavailableAuthProvider default_auth_;
    iap2::AuthProvider* iap2_auth_;

    BtDownstream bt_downstream_;
    UsbDownstream usb_downstream_;
    WifiDownstream wifi_downstream_;
    MdnsDownstream mdns_downstream_;
    WirelessIap2Listener wireless_iap2_listener_;
    WiredIap2Listener wired_iap2_listener_;
    TickTimerHandler timer_handler_;

    BtTransport* bt_transport_override_;
    std::unique_ptr<BtTransport> owned_bt_transport_;
    BtTransport* bt_transport_;
    BtSessionAdapter bt_adapter_;
    iap2::Session* wireless_iap2_session_;

    WifiAp wifi_ap_;
    WifiApCredentialsAdapter wifi_creds_adapter_;
    WifiCredentials active_wifi_creds_;
    MdnsAdvertiser mdns_;

    UsbHostInterface* usb_host_override_;
    TapPortInterface* tap_port_override_;
    UsbHostInterface* owned_usb_host_;
    TapPortInterface* owned_tap_port_;
    UsbHostInterface* usb_host_;
    TapPortInterface* tap_port_;
    UsbCarPlayBridge* usb_bridge_;
    UsbBridgeSessionAdapter usb_adapter_;
    iap2::Session* wired_iap2_session_;

    ConnectivityState state_;
    ActiveTransportMode active_mode_;
    int64_t state_entered_ms_;
    uint32_t iap2_tick_timer_;
    uint32_t wired_retry_timer_;

    bool started_;
    bool stopping_;
    bool in_teardown_;
    bool wireless_transport_ready_;
    bool wired_transport_ready_;
    bool pending_wifi_config_request_;
    bool pending_wireless_start_session_;
    bool wireless_station_seen_;
    std::string last_advertised_wireless_ssid_;

    bool wired_ncm_ready_;
    bool pending_wired_start_session_;
    std::string wired_tap_ifname_;
    uint32_t wired_tap_ifindex_;
    uint8_t wired_tap_mac_[6];

    uint64_t rejected_concurrent_attempts_;
    uint64_t failure_teardowns_;
    std::string last_error_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_CARPLAY_CONNECTIVITY_HPP
