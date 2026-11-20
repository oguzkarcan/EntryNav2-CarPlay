#include "carplay/platform/carplay_connectivity.hpp"

#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "carplay/dnssd_txt.hpp"
#include "carplay/iap2_wire.hpp"
#include "carplay/platform/file_util.hpp"
#include "carplay/platform/hostapd_ctrl.hpp"
#include "carplay/platform/log.hpp"

namespace carplay {
namespace platform {

namespace {

const char* const kTag = "conn";

std::string lowercaseHex(const uint8_t* data, size_t len) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    if (data == NULL || len == 0U) {
        return out;
    }
    out.reserve(len * 2U);
    for (size_t i = 0U; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0x0fU]);
        out.push_back(kHex[data[i] & 0x0fU]);
    }
    return out;
}

std::string stripIpv6Scope(const Address& addr) {
    if (!addr.valid()) {
        return std::string();
    }
    if (addr.family() == Address::kIPv6) {
        return Address::ipv6(addr.bytes(), 0U, 0U).hostString();
    }
    return addr.hostString();
}

void appendUnique(std::vector<std::string>& dst, const std::string& val) {
    if (val.empty()) {
        return;
    }
    for (size_t i = 0U; i < dst.size(); ++i) {
        if (dst[i] == val) {
            return;
        }
    }
    dst.push_back(val);
}

void queryInterfaceIpAddresses(const std::string& ifname, std::vector<std::string>& out) {
#ifdef _WIN32
    (void)ifname;
    (void)out;
#else
    if (ifname.empty() || ifname.size() >= IFNAMSIZ) {
        return;
    }
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        struct ifreq req;
        memset(&req, 0, sizeof(req));
        memcpy(req.ifr_name, ifname.c_str(), ifname.size());
        if (::ioctl(fd, SIOCGIFADDR, &req) == 0) {
            char ip_buf[INET_ADDRSTRLEN];
            const struct sockaddr_in* sin = reinterpret_cast<const struct sockaddr_in*>(&req.ifr_addr);
            if (::inet_ntop(AF_INET, &sin->sin_addr, ip_buf, sizeof(ip_buf)) != NULL) {
                appendUnique(out, std::string(ip_buf));
            }
        }
        ::close(fd);
    }

    std::vector<uint8_t> raw;
    if (readFileBounded("/proc/net/if_inet6", 65536U, raw) == kFileReadOk && !raw.empty()) {
        Address ll;
        const std::string content(raw.begin(), raw.end());
        if (parseProcNetIfInet6(content, ifname, ll)) {
            appendUnique(out, stripIpv6Scope(ll));
        }
    }
#endif
}

const char* iap2SessionStateName(iap2::SessionState s) {
    switch (s) {
        case iap2::kSessionIdle: return "idle";
        case iap2::kSessionDetecting: return "detecting";
        case iap2::kSessionSyncing: return "syncing";
        case iap2::kSessionConnected: return "connected";
        case iap2::kSessionIdentifying: return "identifying";
        case iap2::kSessionIdentified: return "identified";
        case iap2::kSessionAuthenticating: return "authenticating";
        case iap2::kSessionAuthenticated: return "authenticated";
        case iap2::kSessionReady: return "ready";
        case iap2::kSessionFailed: return "failed";
    }
    return "unknown";
}

}  // namespace

const char* connectivityStateName(ConnectivityState state) {
    switch (state) {
        case kConnStopped: return "stopped";
        case kConnWaiting: return "waiting";
        case kConnWirelessIap2: return "wireless_iap2";
        case kConnWirelessApStarting: return "wireless_ap_starting";
        case kConnWirelessWaitingAirPlay: return "wireless_waiting_airplay";
        case kConnWiredConfiguring: return "wired_configuring";
        case kConnWiredIap2: return "wired_iap2";
        case kConnWiredWaitingAirPlay: return "wired_waiting_airplay";
        case kConnActiveSession: return "active_session";
    }
    return "unknown";
}

const char* activeTransportModeName(ActiveTransportMode mode) {
    switch (mode) {
        case kActiveNone: return "none";
        case kActiveWireless: return "wireless";
        case kActiveWired: return "wired";
    }
    return "unknown";
}

CarPlayConnectivityConfig::CarPlayConnectivityConfig()
    : enable_wireless(false),
      enable_wired(false),
      accessory_name("BMW EntryNav2"),
      accessory_model("EntryNav2"),
      accessory_manufacturer("BMW"),
      accessory_serial("00000001"),
      accessory_firmware_version("1.0.0"),
      accessory_hardware_version("HU_ENTRYNAV2"),
      language("en"),
      ea_protocol("com.shilapi.xcertplay"),
      wired_available_current_ma(2400U),
      iap2_tick_interval_ms(50),
      handoff_timeout_ms(30000),
      wired_failure_retry_ms(2000),
      start_mdns_on_wireless(true),
      sdp_socket_path("/var/run/sdp") {}

bool CarPlayConnectivity::UnavailableAuthProvider::getCertificate(
    std::vector<uint8_t>& certificate_out) {
    certificate_out.clear();
    CARPLAY_LOG_ERROR(kTag, "iAP2 auth requested but no AuthProvider is configured (Phase 5)");
    return false;
}

bool CarPlayConnectivity::UnavailableAuthProvider::signChallenge(
    const uint8_t* /*challenge*/,
    size_t /*challenge_len*/,
    std::vector<uint8_t>& signature_out) {
    signature_out.clear();
    CARPLAY_LOG_ERROR(kTag, "iAP2 challenge sign requested but no AuthProvider is configured");
    return false;
}

CarPlayConnectivity::CarPlayConnectivity(Reactor& reactor, pairing::RandomSource& rng)
    : reactor_(reactor),
      rng_(rng),
      listener_(NULL),
      server_(NULL),
      identity_(NULL),
      iap2_auth_(NULL),
      bt_downstream_(this),
      usb_downstream_(this),
      wifi_downstream_(this),
      mdns_downstream_(this),
      wireless_iap2_listener_(this),
      wired_iap2_listener_(this),
      timer_handler_(this),
      bt_transport_override_(NULL),
      bt_cap_override_(),
      has_bt_cap_override_(false),
      spp_mem_override_(NULL),
      alps_link_override_(NULL),
      rfcomm_socket_ops_override_(NULL),
      bt_transport_(NULL),
      bt_adapter_(NULL, NULL, &bt_downstream_),
      wireless_iap2_session_(NULL),
      has_compat_report_(false),
      last_compat_report_(),
      alps_snapshot_safe_(false),
      wifi_link_log_(),
      wifi_ap_(reactor_, rng_),
      wifi_creds_adapter_(&wifi_ap_, &wifi_downstream_),
      mdns_(reactor_),
      usb_host_override_(NULL),
      tap_port_override_(NULL),
      owned_usb_host_(NULL),
      owned_tap_port_(NULL),
      usb_host_(NULL),
      tap_port_(NULL),
      usb_bridge_(NULL),
      usb_adapter_(NULL, NULL, &usb_downstream_),
      wired_iap2_session_(NULL),
      state_(kConnStopped),
      active_mode_(kActiveNone),
      state_entered_ms_(0),
      iap2_tick_timer_(Reactor::kNoTimer),
      wired_retry_timer_(Reactor::kNoTimer),
      started_(false),
      stopping_(false),
      in_teardown_(false),
      wireless_transport_ready_(false),
      wired_transport_ready_(false),
      pending_wifi_config_request_(false),
      pending_wireless_start_session_(false),
      wireless_station_seen_(false),
      wired_ncm_ready_(false),
      pending_wired_start_session_(false),
      wired_tap_ifindex_(0U),
      rejected_concurrent_attempts_(0U),
      failure_teardowns_(0U) {
    memset(wired_tap_mac_, 0, sizeof(wired_tap_mac_));
    wifi_link_log_.setAppsProbe(&CarPlayConnectivity::appsProbeThunk, this);
}

CarPlayConnectivity::~CarPlayConnectivity() {
    stop();
}

void CarPlayConnectivity::setIap2AuthProvider(iap2::AuthProvider* auth) {
    if (!started_) {
        iap2_auth_ = auth;
    }
}

void CarPlayConnectivity::setBtTransportForTest(BtTransport* transport) {
    if (!started_) {
        bt_transport_override_ = transport;
    }
}

void CarPlayConnectivity::setBtCapabilityForTest(const BtTransportCapability& cap) {
    if (!started_) {
        bt_cap_override_ = cap;
        has_bt_cap_override_ = true;
    }
}

void CarPlayConnectivity::clearBtCapabilityForTest() {
    if (!started_) {
        bt_cap_override_ = BtTransportCapability();
        has_bt_cap_override_ = false;
    }
}

void CarPlayConnectivity::setSppMemoryBackendForTest(SppMemoryBackend* mem) {
    if (!started_) {
        spp_mem_override_ = mem;
    }
}

void CarPlayConnectivity::setAlpsLinkForTest(AlpsSppLink* link) {
    if (!started_) {
        alps_link_override_ = link;
    }
}

void CarPlayConnectivity::setRfcommSocketOpsForTest(BtSocketOps* ops) {
    if (!started_) {
        rfcomm_socket_ops_override_ = ops;
    }
}

void CarPlayConnectivity::setUsbHostForTest(UsbHostInterface* usb) {
    if (!started_) {
        usb_host_override_ = usb;
    }
}

void CarPlayConnectivity::setTapPortForTest(TapPortInterface* tap) {
    if (!started_) {
        tap_port_override_ = tap;
    }
}

BtBackendKind CarPlayConnectivity::activeBtBackend() const {
    return bt_transport_ != NULL ? bt_transport_->backendKind() : kBtBackendNone;
}

iap2::AuthProvider& CarPlayConnectivity::effectiveAuthProvider() {
    return iap2_auth_ != NULL ? *iap2_auth_ : default_auth_;
}

void CarPlayConnectivity::setState(ConnectivityState next, const char* reason) {
    if (state_ == next) {
        return;
    }
    const ConnectivityState prev = state_;
    state_ = next;
    state_entered_ms_ = reactor_.now() / 1000000LL;
    CARPLAY_LOG_INFO(kTag, "state %s -> %s (mode=%s%s%s)",
                     connectivityStateName(prev),
                     connectivityStateName(next),
                     activeTransportModeName(active_mode_),
                     (reason != NULL && reason[0] != '\0') ? ", " : "",
                     (reason != NULL && reason[0] != '\0') ? reason : "");
    if (listener_ != NULL) {
        listener_->onConnectivityStateChanged(prev, next, active_mode_);
    }
}

void CarPlayConnectivity::reportError(const std::string& msg) {
    last_error_ = msg;
    CARPLAY_LOG_ERROR(kTag, "%s", msg.c_str());
    if (listener_ != NULL) {
        listener_->onConnectivityError(msg);
    }
}

iap2::IdentificationConfig CarPlayConnectivity::makeWirelessIdent(const std::string& ssid) const {
    std::vector<uint8_t> bt_mac = config_.bluetooth_mac;
    if (bt_mac.empty() && !airplay_cfg_.bt_mac.empty()) {
        uint8_t parsed[6];
        if (parseMacAddressBytes(airplay_cfg_.bt_mac, parsed)) {
            bt_mac.assign(parsed, parsed + 6);
        }
    }
    return iap2::IdentificationConfig::wirelessBluetooth(
        config_.accessory_name,
        config_.accessory_model,
        config_.accessory_manufacturer,
        config_.accessory_serial,
        config_.accessory_firmware_version,
        config_.accessory_hardware_version,
        bt_mac,
        ssid,
        config_.language,
        config_.ea_protocol);
}

iap2::IdentificationConfig CarPlayConnectivity::makeWiredIdent(uint8_t usb_interface_number) const {
    return iap2::IdentificationConfig::wiredUsb(
        config_.accessory_name,
        config_.accessory_model,
        config_.accessory_manufacturer,
        config_.accessory_serial,
        config_.accessory_firmware_version,
        config_.accessory_hardware_version,
        usb_interface_number,
        config_.language,
        config_.ea_protocol);
}

bool CarPlayConnectivity::start(SessionServer& server,
                                const info::AirPlayConfig& airplay_cfg,
                                const pairing::Identity& identity,
                                const CarPlayConnectivityConfig& config) {
    if (started_) {
        return true;
    }
    if (!reactor_.initialized() || !server.isListening()) {
        reportError("CarPlayConnectivity::start requires initialized Reactor and listening SessionServer");
        return false;
    }

    stopping_ = false;
    in_teardown_ = false;
    config_ = config;
    server_ = &server;
    airplay_cfg_ = airplay_cfg;
    identity_ = &identity;
    last_error_.clear();
    wireless_transport_ready_ = false;
    wired_transport_ready_ = false;
    pending_wifi_config_request_ = false;
    pending_wireless_start_session_ = false;
    wireless_station_seen_ = false;
    wired_ncm_ready_ = false;
    pending_wired_start_session_ = false;
    active_mode_ = kActiveNone;
    active_wifi_creds_ = WifiCredentials();
    last_advertised_wireless_ssid_.clear();
    has_compat_report_ = false;
    last_compat_report_ = AlpsCompatReport();
    alps_snapshot_safe_ = false;

    if (!config_.enable_wireless && !config_.enable_wired) {
        CARPLAY_LOG_INFO(kTag, "wireless and wired transports both disabled by config");
        return true;
    }

    started_ = true;
    server_->setWifiVideoQos(false);

    if (config_.enable_wireless) {
        startWirelessSubsystem();
    } else if (config_.enable_wired) {
        const BtTransportCapability cap =
            has_bt_cap_override_ ? bt_cap_override_ : probeBtTransportCapability();
        last_compat_report_ = probeAlpsSppCompat(
            cap, spp_mem_override_, true, config_.alps_config.slot_policy);
        has_compat_report_ = true;
        CARPLAY_LOG_INFO(kTag, "BT/ALPS compat (wired-only informational): %s",
                         formatAlpsCompatReport(last_compat_report_).c_str());
    }
    if (config_.enable_wired) {
        startWiredSubsystem();
    }

    if (config_.iap2_tick_interval_ms > 0) {
        iap2_tick_timer_ = reactor_.startTimer(config_.iap2_tick_interval_ms,
                                               config_.iap2_tick_interval_ms,
                                               &timer_handler_);
    }

    setState(kConnWaiting, "connectivity started");
    return true;
}

bool CarPlayConnectivity::startWirelessSubsystem() {
    std::string init_ssid = config_.wifi_ap_config.ssid;
    if (init_ssid.empty()) {
        init_ssid = config_.wifi_ap_config.ssid_prefix;
    }
    if (init_ssid.empty()) {
        init_ssid = "BMW-CarPlay";
    }
    last_advertised_wireless_ssid_ = init_ssid;

    const iap2::IdentificationConfig ident = makeWirelessIdent(init_ssid);
    const iap2::SessionConfig scfg = iap2::SessionConfig::wirelessBluetooth(ident);
    wireless_iap2_session_ = new iap2::Session(bt_adapter_,
                                               effectiveAuthProvider(),
                                               wireless_iap2_listener_,
                                               scfg);
    bt_adapter_.setSession(wireless_iap2_session_);
    bt_adapter_.setDownstreamListener(&bt_downstream_);

    wifi_creds_adapter_.setWifiAp(&wifi_ap_);
    wifi_creds_adapter_.setDownstreamListener(&wifi_downstream_);
    wifi_creds_adapter_.clearCredentials();
    wifi_ap_.setListener(&wifi_creds_adapter_);
    mdns_.setListener(&mdns_downstream_);

    if (bt_transport_override_ != NULL) {
        bt_transport_ = bt_transport_override_;
        bt_transport_->setListener(&bt_adapter_);
        if (has_bt_cap_override_) {
            last_compat_report_ = probeAlpsSppCompat(
                bt_cap_override_, spp_mem_override_, false, config_.alps_config.slot_policy);
            has_compat_report_ = true;
            alps_snapshot_safe_ = last_compat_report_.wireless_ready &&
                                  (last_compat_report_.alps.level == kCompatPass ||
                                   last_compat_report_.alps.level == kCompatWarn);
        }
    } else {
        const BtTransportCapability cap =
            has_bt_cap_override_ ? bt_cap_override_ : probeBtTransportCapability();
        logBtTransportCapability(cap);
        last_compat_report_ = probeAlpsSppCompat(
            cap, spp_mem_override_, false, config_.alps_config.slot_policy);
        has_compat_report_ = true;

        if (last_compat_report_.wireless_ready) {
            alps_snapshot_safe_ = true;
            CARPLAY_LOG_INFO(kTag, "ALPS compat gate passed: %s",
                             formatAlpsCompatReport(last_compat_report_).c_str());
            if (spp_mem_override_ != NULL || alps_link_override_ != NULL) {
                owned_bt_transport_.reset(new AlpsBtTransport(
                    reactor_,
                    bt_adapter_,
                    config_.alps_config,
                    spp_mem_override_,
                    alps_link_override_));
            } else {
                owned_bt_transport_ = createBtTransport(reactor_,
                                                        bt_adapter_,
                                                        cap,
                                                        config_.alps_config,
                                                        config_.rfcomm_config,
                                                        config_.sdp_socket_path);
            }
        } else {
            alps_snapshot_safe_ = false;
            CARPLAY_LOG_WARN(kTag,
                             "ALPS compat gate failed (%s); falling back to kernel RFCOMM if available",
                             formatAlpsCompatReport(last_compat_report_).c_str());
            if (cap.rfcommCapable()) {
                if (rfcomm_socket_ops_override_ != NULL) {
                    owned_bt_transport_.reset(new RfcommBtTransport(
                        reactor_,
                        bt_adapter_,
                        config_.rfcomm_config,
                        rfcomm_socket_ops_override_,
                        createBtSdpRegistrar(cap.rfcomm, config_.sdp_socket_path)));
                } else {
                    BtTransportCapability rfcomm_cap = cap;
                    rfcomm_cap.alps_library_present = false;
                    rfcomm_cap.alps_dbus_ready = false;
                    rfcomm_cap.alps_service_owned = false;
                    owned_bt_transport_ = createBtTransport(reactor_,
                                                            bt_adapter_,
                                                            rfcomm_cap,
                                                            config_.alps_config,
                                                            config_.rfcomm_config,
                                                            config_.sdp_socket_path);
                }
            } else {
                owned_bt_transport_.reset();
            }
        }
        bt_transport_ = owned_bt_transport_.get();
    }
    bt_adapter_.setTransport(bt_transport_);

    std::string bt_err;
    if (bt_transport_ == NULL || !bt_transport_->start(&bt_err)) {
        if (bt_transport_ == NULL) {
            CARPLAY_LOG_WARN(kTag,
                             "wireless disabled: ALPS incompatible/unavailable and kernel RFCOMM unavailable");
        } else {
            CARPLAY_LOG_WARN(kTag, "BT transport (%s) failed to start: %s",
                             bt_transport_->backendName(), bt_err.c_str());
        }
        bt_adapter_.setSession(NULL);
        bt_adapter_.setDownstreamListener(NULL);
        bt_adapter_.setTransport(NULL);
        if (wireless_iap2_session_ != NULL) {
            delete wireless_iap2_session_;
            wireless_iap2_session_ = NULL;
        }
        bt_transport_ = NULL;
        owned_bt_transport_.reset();
        alps_snapshot_safe_ = false;
        wireless_transport_ready_ = false;
        return false;
    }

    wireless_transport_ready_ = true;
    CARPLAY_LOG_INFO(kTag, "wireless BT transport started (backend=%s)",
                     bt_transport_->backendName());
    return true;
}

bool CarPlayConnectivity::startWiredSubsystem() {
    const iap2::IdentificationConfig ident = makeWiredIdent(0U);
    const iap2::SessionConfig scfg =
        iap2::SessionConfig::wiredUsb(ident, config_.wired_available_current_ma);
    wired_iap2_session_ = new iap2::Session(usb_adapter_,
                                            effectiveAuthProvider(),
                                            wired_iap2_listener_,
                                            scfg);
    usb_adapter_.setSession(wired_iap2_session_);
    usb_adapter_.setDownstreamListener(&usb_downstream_);

    if (usb_host_override_ != NULL) {
        usb_host_ = usb_host_override_;
    } else {
        owned_usb_host_ = new UsbHost(config_.usb_host_config);
        usb_host_ = owned_usb_host_;
    }

    if (tap_port_override_ != NULL) {
        tap_port_ = tap_port_override_;
    } else {
        owned_tap_port_ = new TapIface(config_.tap_config);
        tap_port_ = owned_tap_port_;
    }

    usb_bridge_ = new UsbCarPlayBridge(*usb_host_, *tap_port_, config_.usb_bridge_config);
    usb_adapter_.setBridge(usb_bridge_);

    if (!usb_bridge_->start(reactor_, &usb_adapter_)) {
        CARPLAY_LOG_WARN(kTag, "wired UsbCarPlayBridge failed to start");
        wired_transport_ready_ = false;
        return false;
    }

    wired_transport_ready_ = true;
    CARPLAY_LOG_INFO(kTag, "wired USB CarPlay bridge started (detach_usbfs=%s)",
                     config_.usb_bridge_config.detach_usbfs_driver ? "true" : "false");
    return true;
}

void CarPlayConnectivity::ensureWiredRestartIfEnabled() {
    if (!started_ || stopping_ || !config_.enable_wired || usb_bridge_ == NULL) {
        return;
    }
    if (wired_retry_timer_ != Reactor::kNoTimer) {
        reactor_.cancelTimer(wired_retry_timer_);
        wired_retry_timer_ = Reactor::kNoTimer;
    }
    if (usb_bridge_->state() == kBridgeStopped) {
        if (usb_bridge_->start(reactor_, &usb_adapter_)) {
            wired_transport_ready_ = true;
        }
    }
}

void CarPlayConnectivity::stop() {
    if (!started_ && state_ == kConnStopped) {
        return;
    }
    stopping_ = true;
    in_teardown_ = true;

    if (iap2_tick_timer_ != Reactor::kNoTimer) {
        reactor_.cancelTimer(iap2_tick_timer_);
        iap2_tick_timer_ = Reactor::kNoTimer;
    }
    if (wired_retry_timer_ != Reactor::kNoTimer) {
        reactor_.cancelTimer(wired_retry_timer_);
        wired_retry_timer_ = Reactor::kNoTimer;
    }

    if (server_ != NULL && server_->hasActiveSession()) {
        server_->closeActiveSession();
    }
    if (server_ != NULL) {
        server_->setWifiVideoQos(false);
    }

    // Tear down wireless side (Wi-Fi link log, mDNS, AP restore, iAP2, BT + ALPS slot 5 restore).
    wifi_link_log_.turn(static_cast<uint32_t>(reactor_.now() / 1000000LL), false);
    wifi_link_log_.enable("");
    alps_snapshot_safe_ = false;
    mdns_.setListener(NULL);
    mdns_.stop();

    wifi_ap_.setListener(NULL);
    wifi_creds_adapter_.setDownstreamListener(NULL);
    wifi_creds_adapter_.setWifiAp(NULL);
    wifi_creds_adapter_.clearCredentials();
    wifi_ap_.stopSync();
    active_wifi_creds_ = WifiCredentials();

    bt_adapter_.setSession(NULL);
    bt_adapter_.setDownstreamListener(NULL);
    bt_adapter_.setTransport(NULL);
    if (wireless_iap2_session_ != NULL) {
        if (wireless_iap2_session_->state() != iap2::kSessionIdle) {
            wireless_iap2_session_->reset(false);
        }
        delete wireless_iap2_session_;
        wireless_iap2_session_ = NULL;
    }
    if (bt_transport_ != NULL) {
        bt_transport_->stop();
        bt_transport_->setListener(NULL);
        bt_transport_ = NULL;
    }
    owned_bt_transport_.reset();

    // Tear down wired side (iAP2, USB bridge -> TAP close & USB interface release).
    usb_adapter_.setSession(NULL);
    usb_adapter_.setDownstreamListener(NULL);
    usb_adapter_.setBridge(NULL);
    if (wired_iap2_session_ != NULL) {
        if (wired_iap2_session_->state() != iap2::kSessionIdle) {
            wired_iap2_session_->reset(false);
        }
        delete wired_iap2_session_;
        wired_iap2_session_ = NULL;
    }
    if (usb_bridge_ != NULL) {
        usb_bridge_->stop();
        delete usb_bridge_;
        usb_bridge_ = NULL;
    }
    if (owned_usb_host_ != NULL) {
        delete owned_usb_host_;
        owned_usb_host_ = NULL;
    }
    if (owned_tap_port_ != NULL) {
        delete owned_tap_port_;
        owned_tap_port_ = NULL;
    }
    usb_host_ = NULL;
    tap_port_ = NULL;

    active_mode_ = kActiveNone;
    wireless_transport_ready_ = false;
    wired_transport_ready_ = false;
    pending_wifi_config_request_ = false;
    pending_wireless_start_session_ = false;
    wireless_station_seen_ = false;
    wired_ncm_ready_ = false;
    pending_wired_start_session_ = false;
    server_ = NULL;
    identity_ = NULL;
    started_ = false;
    in_teardown_ = false;

    setState(kConnStopped, "connectivity stopped");
}

void CarPlayConnectivity::onAirPlaySessionStarted() {
    if (!started_ || stopping_ || state_ == kConnStopped) {
        return;
    }
    const bool entering_active = (state_ != kConnActiveSession);
    setState(kConnActiveSession, "AirPlay session active");
    if (entering_active && active_mode_ == kActiveWireless && server_ != NULL) {
        const SocketHandle sock = server_->controlSocketHandle();
        if (sock != kInvalidSocket) {
            wifi_link_log_.connected(static_cast<int>(sock));
            wifi_link_log_.turn(static_cast<uint32_t>(reactor_.now() / 1000000LL), true);
        }
    }
}

void CarPlayConnectivity::onAirPlaySessionEnded() {
    if (!started_ || stopping_ || in_teardown_ || state_ == kConnStopped) {
        return;
    }
    if (active_mode_ == kActiveWireless) {
        teardownWirelessSession("AirPlay session ended", false);
    } else if (active_mode_ == kActiveWired) {
        if (usb_bridge_ != NULL &&
            usb_bridge_->state() != kBridgeStopped &&
            usb_bridge_->state() != kBridgeWaiting) {
            teardownWiredSession("AirPlay session ended", false, true);
        } else {
            active_mode_ = kActiveNone;
            if (server_ != NULL) {
                server_->setWifiVideoQos(false);
            }
            setState(kConnWaiting, "AirPlay session ended");
        }
    } else {
        if (server_ != NULL) {
            server_->setWifiVideoQos(false);
        }
        setState(kConnWaiting, "direct AirPlay session ended");
    }
}

void CarPlayConnectivity::onAirPlayIapMessage(const uint8_t* data, size_t len) {
    (void)data;
    CARPLAY_LOG_DEBUG(kTag, "received AirPlay type-130 iAP2 payload (%zu bytes)", len);
}

// ------------------------------------------------------------------------------------------------
// Wireless flow
// ------------------------------------------------------------------------------------------------

void CarPlayConnectivity::handleBtConnected(const BtAddr& peer) {
    if (!started_ || stopping_) {
        return;
    }
    if (active_mode_ != kActiveNone ||
        (state_ != kConnWaiting && state_ != kConnWirelessIap2)) {
        ++rejected_concurrent_attempts_;
        CARPLAY_LOG_WARN(kTag, "rejecting BT peer %s: busy in state %s (%s)",
                         peer.toString().c_str(),
                         connectivityStateName(state_),
                         activeTransportModeName(active_mode_));
        if (bt_transport_ != NULL) {
            bt_adapter_.setSession(NULL);
            bt_transport_->disconnect("busy with another CarPlay session");
            bt_adapter_.setSession(wireless_iap2_session_);
        }
        return;
    }

    CARPLAY_LOG_INFO(kTag, "BT peer connected (%s); starting wireless iAP2 bootstrap",
                     peer.toString().c_str());
    active_mode_ = kActiveWireless;
    if (server_ != NULL) {
        server_->setWifiVideoQos(true);
    }
    pending_wifi_config_request_ = false;
    pending_wireless_start_session_ = false;
    wireless_station_seen_ = false;
    setState(kConnWirelessIap2, "BT SPP connected");
}

void CarPlayConnectivity::handleBtDisconnected(const std::string& reason) {
    if (!started_ || stopping_ || in_teardown_) {
        return;
    }
    if (active_mode_ != kActiveWireless) {
        return;
    }
    if (state_ == kConnWirelessIap2 || state_ == kConnWirelessApStarting) {
        teardownWirelessSession("BT disconnected before Wi-Fi handoff: " + reason, true);
    } else {
        CARPLAY_LOG_INFO(kTag,
                         "BT RFCOMM disconnected after Wi-Fi handoff (%s); keeping AP/AirPlay alive",
                         reason.c_str());
    }
}

void CarPlayConnectivity::handleWirelessIap2Ready() {
    if (!started_ || stopping_ || active_mode_ != kActiveWireless) {
        return;
    }
    setState(kConnWirelessApStarting, "iAP2 identified & authenticated; starting Wi-Fi AP");

    if (wifi_ap_.state() == kWifiApRunning) {
        handleWifiApStarted(wifi_ap_.credentials());
        return;
    }

    std::string err;
    if (!wifi_ap_.start(config_.wifi_ap_config, &err)) {
        teardownWirelessSession("WifiAp start failed: " + err, true);
    }
}

void CarPlayConnectivity::handleWirelessIap2Error(const std::string& reason) {
    if (!started_ || stopping_ || in_teardown_) {
        return;
    }
    // If 0x5702 arrived while WifiAp was still starting asynchronously, wait for onWifiApStarted().
    if (pending_wifi_config_request_ &&
        wifi_ap_.state() == kWifiApStartingWaitCtrl &&
        reason.find("0x5702") != std::string::npos) {
        CARPLAY_LOG_INFO(kTag, "deferring 0x5703 response until Wi-Fi AP finishes starting");
        return;
    }
    handleWirelessIap2Failure(reason);
}

void CarPlayConnectivity::handleWirelessIap2Failure(const std::string& reason) {
    if (!started_ || stopping_ || in_teardown_) {
        return;
    }
    if (active_mode_ != kActiveWireless) {
        return;
    }
    if (state_ == kConnWirelessIap2 || state_ == kConnWirelessApStarting) {
        teardownWirelessSession("wireless iAP2 failure: " + reason, true);
    } else {
        CARPLAY_LOG_WARN(kTag, "ignoring late BT iAP2 error after handoff: %s", reason.c_str());
    }
}

bool CarPlayConnectivity::handleWirelessWifiRequested(iap2::WiFiConfiguration& out) {
    if (!started_ || stopping_ || active_mode_ != kActiveWireless) {
        return false;
    }
    if (wifi_creds_adapter_.provideWiFiConfiguration(out)) {
        return true;
    }
    if (wifi_ap_.state() == kWifiApStartingWaitCtrl) {
        pending_wifi_config_request_ = true;
    }
    return false;
}

bool CarPlayConnectivity::populateWirelessStartSession(iap2::StartSessionConfig& out) const {
    if (server_ == NULL || !wifi_creds_adapter_.hasCredentials()) {
        return false;
    }
    iap2::WiFiConfiguration wcfg;
    if (!wifi_creds_adapter_.provideWiFiConfiguration(wcfg)) {
        return false;
    }

    out = iap2::StartSessionConfig();
    out.wireless_ssid = wcfg.ssid;
    out.wireless_passphrase = wcfg.passphrase;
    out.has_wireless_passphrase =
        !wcfg.passphrase.empty() || wcfg.security_type == iap2::kWirelessSecurityNone;
    out.has_wireless_channel = true;
    out.wireless_channel = wcfg.channel;
    out.has_wireless_security_type = true;
    out.wireless_security_type = wcfg.security_type;

    out.wireless_ips = config_.wireless_ips_override;
    if (out.wireless_ips.empty()) {
        const std::string& ap_iface = (wifi_ap_.activeBackend() == kWifiApBackendNative)
            ? config_.wifi_ap_config.native_interface_name
            : config_.wifi_ap_config.interface_name;
        queryInterfaceIpAddresses(ap_iface, out.wireless_ips);
    }
    if (out.wireless_ips.empty() && active_wifi_creds_.has_bssid) {
        appendUnique(out.wireless_ips,
                     stripIpv6Scope(computeEui64LinkLocal(active_wifi_creds_.bssid)));
    }
    if (out.wireless_ips.empty()) {
        CARPLAY_LOG_WARN(kTag, "no wireless host IP discovered for 0x4301; using 127.0.0.1 fallback");
        out.wireless_ips.push_back("127.0.0.1");
    }

    out.has_airplay_port = true;
    out.airplay_port = server_->controlPort();
    out.device_identifier = airplay_cfg_.device_id;
    if (identity_ != NULL) {
        out.public_key = lowercaseHex(identity_->keys.public_key, sizeof(identity_->keys.public_key));
    }
    out.source_version = airplay_cfg_.source_version;
    return true;
}

bool CarPlayConnectivity::handleWirelessStartSessionRequested(
    const iap2::CarPlayAvailability& avail,
    iap2::StartSessionConfig& out) {
    if (!started_ || stopping_ || active_mode_ != kActiveWireless) {
        return false;
    }
    if (avail.wireless.present && avail.wireless.has_available && !avail.wireless.available) {
        CARPLAY_LOG_WARN(kTag, "phone reported wireless CarPlay unavailable in 0x4300");
        return false;
    }
    if (!wifi_creds_adapter_.hasCredentials()) {
        if (wifi_ap_.state() == kWifiApStartingWaitCtrl) {
            pending_wireless_start_session_ = true;
        }
        return false;
    }
    if (!populateWirelessStartSession(out)) {
        return false;
    }
    setState(kConnWirelessWaitingAirPlay, "wireless 0x4301 CarPlayStartSession sent");
    return true;
}

void CarPlayConnectivity::startMdnsForWireless(const WifiCredentials& creds) {
    if (!config_.start_mdns_on_wireless || server_ == NULL || identity_ == NULL) {
        return;
    }
    std::string err;
    if (!mdns_.available() && !mdns_.load(&err)) {
        CARPLAY_LOG_WARN(kTag, "mDNS advertiser unavailable (%s); continuing via iAP2 0x4301",
                         err.c_str());
        return;
    }
    MdnsServiceConfig mcfg;
    mcfg.service_name = !airplay_cfg_.device_name.empty() ? airplay_cfg_.device_name : creds.ssid;
    mcfg.regtype = dnssd::kAirPlayServiceType;
    mcfg.domain = dnssd::kAirPlayDefaultDomain;
    mcfg.port = server_->controlPort();
    if (!dnssd::buildAirPlayTxtRecord(airplay_cfg_, *identity_, mcfg.txt_record, &err)) {
        CARPLAY_LOG_WARN(kTag, "failed to build _airplay._tcp TXT record: %s", err.c_str());
        return;
    }
    if (!mdns_.start(mcfg, &err)) {
        CARPLAY_LOG_WARN(kTag, "MdnsAdvertiser::start failed: %s", err.c_str());
    }
}

void CarPlayConnectivity::handleWifiApStarted(const WifiCredentials& creds) {
    if (!started_ || stopping_ || in_teardown_) {
        return;
    }
    if (active_mode_ != kActiveWireless) {
        return;
    }
    active_wifi_creds_ = creds;
    const std::string& ap_iface = (wifi_ap_.activeBackend() == kWifiApBackendNative)
        ? config_.wifi_ap_config.native_interface_name
        : config_.wifi_ap_config.interface_name;
    wifi_link_log_.enable(ap_iface.c_str());
    if (listener_ != NULL) {
        listener_->onWirelessCredentialsReady(creds);
    }

    startMdnsForWireless(creds);
    setState(kConnWirelessWaitingAirPlay, "Wi-Fi AP ready");

    if (wireless_iap2_session_ != NULL && wireless_iap2_session_->isIdentified() &&
        creds.ssid != last_advertised_wireless_ssid_) {
        last_advertised_wireless_ssid_ = creds.ssid;
        wireless_iap2_session_->sendIdentificationUpdate(makeWirelessIdent(creds.ssid));
    }

    if (pending_wifi_config_request_ &&
        wireless_iap2_session_ != NULL &&
        wireless_iap2_session_->isReady()) {
        pending_wifi_config_request_ = false;
        iap2::Frame frame;
        std::string err;
        if (buildAccessoryWiFiConfigFrame(creds, frame, &err)) {
            wireless_iap2_session_->sendControlMessage(frame);
        } else {
            CARPLAY_LOG_ERROR(kTag, "failed to encode deferred 0x5703 frame: %s", err.c_str());
        }
    }

    if (pending_wireless_start_session_ &&
        wireless_iap2_session_ != NULL &&
        wireless_iap2_session_->isReady()) {
        pending_wireless_start_session_ = false;
        iap2::StartSessionConfig scfg;
        if (populateWirelessStartSession(scfg)) {
            wireless_iap2_session_->sendStartCarPlaySession(scfg);
        }
    }
}

void CarPlayConnectivity::handleWifiApStopped() {
    active_wifi_creds_ = WifiCredentials();
}

void CarPlayConnectivity::handleWifiApRestarting(int attempt, const std::string& reason) {
    CARPLAY_LOG_WARN(kTag, "Wi-Fi AP restarting (attempt=%d, reason=%s)", attempt, reason.c_str());
}

void CarPlayConnectivity::handleWifiApFailed(const std::string& reason) {
    if (!started_ || stopping_ || in_teardown_) {
        return;
    }
    if (active_mode_ == kActiveWireless) {
        teardownWirelessSession("Wi-Fi AP failed: " + reason, true);
    }
}

void CarPlayConnectivity::handleWifiStationConnected(const std::string& mac) {
    CARPLAY_LOG_INFO(kTag, "Wi-Fi station connected: %s", mac.c_str());
    if (active_mode_ == kActiveWireless) {
        wireless_station_seen_ = true;
    }
}

void CarPlayConnectivity::handleWifiStationDisconnected(const std::string& mac) {
    CARPLAY_LOG_INFO(kTag, "Wi-Fi station disconnected: %s", mac.c_str());
    if (!started_ || stopping_ || in_teardown_) {
        return;
    }
    if (active_mode_ == kActiveWireless &&
        wireless_station_seen_ &&
        wifi_ap_.connectedStations().empty() &&
        (state_ == kConnWirelessWaitingAirPlay || state_ == kConnActiveSession)) {
        teardownWirelessSession("Wi-Fi station disconnected: " + mac, true);
    }
}

void CarPlayConnectivity::handleMdnsRegistered(const std::string& assigned_name,
                                               const std::string& regtype,
                                               const std::string& domain) {
    CARPLAY_LOG_INFO(kTag, "mDNS registered \"%s.%s%s\"",
                     assigned_name.c_str(), regtype.c_str(), domain.c_str());
}

void CarPlayConnectivity::handleMdnsRenamed(const std::string& old_name,
                                            const std::string& new_name) {
    CARPLAY_LOG_WARN(kTag, "mDNS name conflict renamed \"%s\" -> \"%s\"",
                     old_name.c_str(), new_name.c_str());
}

void CarPlayConnectivity::handleMdnsError(DnsServiceErrorType code, const std::string& message) {
    CARPLAY_LOG_WARN(kTag, "mDNS error (%d): %s", static_cast<int>(code), message.c_str());
}

void CarPlayConnectivity::teardownWirelessSession(const std::string& reason, bool is_failure) {
    if (in_teardown_) {
        return;
    }
    in_teardown_ = true;
    if (is_failure) {
        ++failure_teardowns_;
        reportError(reason);
    } else {
        CARPLAY_LOG_INFO(kTag, "tearing down wireless session: %s", reason.c_str());
    }

    if (server_ != NULL && server_->hasActiveSession()) {
        server_->closeActiveSession();
    }
    if (server_ != NULL) {
        server_->setWifiVideoQos(false);
    }

    wifi_link_log_.turn(static_cast<uint32_t>(reactor_.now() / 1000000LL), false);
    wifi_link_log_.enable("");
    mdns_.stop();
    wifi_creds_adapter_.clearCredentials();
    wifi_ap_.stopSync();
    active_wifi_creds_ = WifiCredentials();

    if (wireless_iap2_session_ != NULL &&
        wireless_iap2_session_->state() != iap2::kSessionIdle) {
        const bool send_rst = bt_transport_ != NULL && bt_transport_->isConnected();
        wireless_iap2_session_->reset(send_rst);
    }
    if (bt_transport_ != NULL && bt_transport_->isConnected()) {
        bt_transport_->disconnect(reason);
    }

    pending_wifi_config_request_ = false;
    pending_wireless_start_session_ = false;
    wireless_station_seen_ = false;
    active_mode_ = kActiveNone;

    in_teardown_ = false;
    setState(kConnWaiting, reason.c_str());
    ensureWiredRestartIfEnabled();
}

// ------------------------------------------------------------------------------------------------
// Wired USB flow
// ------------------------------------------------------------------------------------------------

void CarPlayConnectivity::handleUsbBridgeStateChanged(BridgeState /*state*/) {}

void CarPlayConnectivity::handleUsbIap2Ready(const usb::Iap2InterfaceSelection& iap2) {
    if (!started_ || stopping_) {
        return;
    }
    if (active_mode_ != kActiveNone && active_mode_ != kActiveWired) {
        ++rejected_concurrent_attempts_;
        CARPLAY_LOG_WARN(kTag, "rejecting wired USB device: busy in state %s (%s)",
                         connectivityStateName(state_),
                         activeTransportModeName(active_mode_));
        usb_adapter_.setSession(NULL);
        if (usb_bridge_ != NULL) {
            usb_bridge_->stop();
            wired_transport_ready_ = false;
        }
        return;
    }

    active_mode_ = kActiveWired;
    if (server_ != NULL) {
        server_->setWifiVideoQos(false);
    }
    wired_ncm_ready_ = false;
    pending_wired_start_session_ = false;

    usb_adapter_.setSession(NULL);
    if (wired_iap2_session_ != NULL) {
        if (wired_iap2_session_->state() != iap2::kSessionIdle) {
            wired_iap2_session_->reset(false);
        }
        delete wired_iap2_session_;
        wired_iap2_session_ = NULL;
    }

    const iap2::IdentificationConfig ident = makeWiredIdent(iap2.interface_number);
    const iap2::SessionConfig scfg =
        iap2::SessionConfig::wiredUsb(ident, config_.wired_available_current_ma);
    wired_iap2_session_ = new iap2::Session(usb_adapter_,
                                            effectiveAuthProvider(),
                                            wired_iap2_listener_,
                                            scfg);
    usb_adapter_.setSession(wired_iap2_session_);
    setState(kConnWiredIap2, "USB iAP2 interface ready");
}

void CarPlayConnectivity::handleUsbNcmReady(const std::string& tap_ifname,
                                            uint32_t tap_ifindex,
                                            const uint8_t tap_mac[6]) {
    if (!started_ || stopping_ || active_mode_ != kActiveWired) {
        return;
    }
    wired_ncm_ready_ = true;
    wired_tap_ifname_ = tap_ifname;
    wired_tap_ifindex_ = tap_ifindex;
    if (tap_mac != NULL) {
        memcpy(wired_tap_mac_, tap_mac, 6U);
    }
    CARPLAY_LOG_INFO(kTag, "wired NCM/TAP ready on %s (ifindex=%u)",
                     wired_tap_ifname_.c_str(),
                     static_cast<unsigned>(wired_tap_ifindex_));

    if (pending_wired_start_session_ &&
        wired_iap2_session_ != NULL &&
        wired_iap2_session_->isReady()) {
        pending_wired_start_session_ = false;
        iap2::StartSessionConfig scfg;
        if (populateWiredStartSession(scfg)) {
            if (wired_iap2_session_->sendStartCarPlaySession(scfg)) {
                setState(kConnWiredWaitingAirPlay, "NCM ready & wired 0x4301 sent");
            }
        }
    }
}

void CarPlayConnectivity::handleUsbDeviceRemoved() {
    if (!started_ || stopping_ || in_teardown_) {
        return;
    }
    wired_ncm_ready_ = false;
    pending_wired_start_session_ = false;
    if (active_mode_ == kActiveWired) {
        teardownWiredSession("USB device removed", false, false);
    }
}

void CarPlayConnectivity::handleUsbBridgeError(const std::string& reason) {
    if (!started_ || stopping_ || in_teardown_) {
        return;
    }
    if (active_mode_ == kActiveWired) {
        teardownWiredSession("USB bridge error: " + reason, true, true);
    } else {
        reportError("USB bridge error: " + reason);
    }
}

void CarPlayConnectivity::handleWiredIap2Ready() {
    CARPLAY_LOG_INFO(kTag, "wired iAP2 identified & authenticated; awaiting 0x4300");
}

void CarPlayConnectivity::handleWiredIap2Failure(const std::string& reason) {
    if (!started_ || stopping_ || in_teardown_) {
        return;
    }
    if (active_mode_ == kActiveWired) {
        teardownWiredSession("wired iAP2 failure: " + reason, true, true);
    }
}

bool CarPlayConnectivity::populateWiredStartSession(iap2::StartSessionConfig& out) const {
    if (server_ == NULL || !wired_ncm_ready_) {
        return false;
    }
    std::string ipv6_str;
    Address tap_ll;
    if (tap_port_ != NULL && tap_port_->queryIpv6LinkLocal(tap_ll) && tap_ll.valid()) {
        ipv6_str = stripIpv6Scope(tap_ll);
    } else if (!config_.wired_ipv6_override.empty()) {
        Address parsed;
        if (Address::parse(config_.wired_ipv6_override, parsed) &&
            parsed.family() == Address::kIPv6) {
            ipv6_str = stripIpv6Scope(parsed);
        } else {
            ipv6_str = config_.wired_ipv6_override;
        }
    } else {
        ipv6_str = stripIpv6Scope(computeEui64LinkLocal(wired_tap_mac_));
    }
    if (ipv6_str.empty()) {
        return false;
    }

    out = iap2::StartSessionConfig();
    out.wired_ipv6_addresses.push_back(ipv6_str);
    out.has_airplay_port = true;
    out.airplay_port = server_->controlPort();
    out.device_identifier = !airplay_cfg_.device_id.empty()
        ? airplay_cfg_.device_id
        : formatMacAddress(wired_tap_mac_);
    if (identity_ != NULL) {
        out.public_key = lowercaseHex(identity_->keys.public_key, sizeof(identity_->keys.public_key));
    }
    out.source_version = airplay_cfg_.source_version;
    return true;
}

bool CarPlayConnectivity::handleWiredStartSessionRequested(
    const iap2::CarPlayAvailability& avail,
    iap2::StartSessionConfig& out) {
    if (!started_ || stopping_ || active_mode_ != kActiveWired) {
        return false;
    }
    if (avail.wired.present && avail.wired.has_available && !avail.wired.available) {
        CARPLAY_LOG_WARN(kTag, "phone reported wired CarPlay unavailable in 0x4300");
        return false;
    }
    if (!wired_ncm_ready_) {
        pending_wired_start_session_ = true;
        return false;
    }
    if (!populateWiredStartSession(out)) {
        return false;
    }
    setState(kConnWiredWaitingAirPlay, "wired 0x4301 CarPlayStartSession sent");
    return true;
}

void CarPlayConnectivity::teardownWiredSession(const std::string& reason,
                                               bool is_failure,
                                               bool schedule_restart) {
    if (in_teardown_) {
        return;
    }
    in_teardown_ = true;
    if (is_failure) {
        ++failure_teardowns_;
        reportError(reason);
    } else {
        CARPLAY_LOG_INFO(kTag, "tearing down wired session: %s", reason.c_str());
    }

    if (server_ != NULL && server_->hasActiveSession()) {
        server_->closeActiveSession();
    }
    if (server_ != NULL) {
        server_->setWifiVideoQos(false);
    }

    if (wired_iap2_session_ != NULL &&
        wired_iap2_session_->state() != iap2::kSessionIdle) {
        wired_iap2_session_->reset(false);
    }

    if (usb_bridge_ != NULL && usb_bridge_->state() != kBridgeStopped) {
        if (schedule_restart || is_failure) {
            // Stop the bridge to synchronously close TAP and release all USB interfaces.
            usb_bridge_->stop();
            wired_transport_ready_ = false;
            if (config_.enable_wired && config_.wired_failure_retry_ms > 0 &&
                wired_retry_timer_ == Reactor::kNoTimer) {
                wired_retry_timer_ = reactor_.startTimer(config_.wired_failure_retry_ms,
                                                         0,
                                                         &timer_handler_);
            }
        }
    }

    wired_ncm_ready_ = false;
    pending_wired_start_session_ = false;
    active_mode_ = kActiveNone;

    in_teardown_ = false;
    setState(kConnWaiting, reason.c_str());
}

// ------------------------------------------------------------------------------------------------
// Common iAP2 / Timer handlers
// ------------------------------------------------------------------------------------------------

void CarPlayConnectivity::handleIap2StateChanged(bool wireless,
                                                 iap2::SessionState old_state,
                                                 iap2::SessionState new_state) {
    CARPLAY_LOG_DEBUG(kTag, "%s iAP2 state %s -> %s",
                      wireless ? "wireless" : "wired",
                      iap2SessionStateName(old_state),
                      iap2SessionStateName(new_state));
}

void CarPlayConnectivity::handleTimer(uint32_t timer_id) {
    if (!started_ || stopping_) {
        return;
    }
    if (timer_id == wired_retry_timer_) {
        wired_retry_timer_ = Reactor::kNoTimer;
        if (active_mode_ == kActiveNone) {
            ensureWiredRestartIfEnabled();
        }
        return;
    }
    if (timer_id != iap2_tick_timer_) {
        return;
    }

    const int64_t now_ms = reactor_.now() / 1000000LL;
    if (state_ == kConnActiveSession && active_mode_ == kActiveWireless) {
        wifi_link_log_.turn(static_cast<uint32_t>(now_ms), true);
    }
    if (wireless_iap2_session_ != NULL &&
        wireless_iap2_session_->state() != iap2::kSessionIdle &&
        wireless_iap2_session_->state() != iap2::kSessionFailed) {
        wireless_iap2_session_->tick(now_ms);
    }
    if (wired_iap2_session_ != NULL &&
        wired_iap2_session_->state() != iap2::kSessionIdle &&
        wired_iap2_session_->state() != iap2::kSessionFailed) {
        wired_iap2_session_->tick(now_ms);
    }

    if (config_.handoff_timeout_ms > 0 &&
        (state_ == kConnWirelessApStarting ||
         state_ == kConnWirelessWaitingAirPlay ||
         state_ == kConnWiredConfiguring ||
         state_ == kConnWiredWaitingAirPlay)) {
        if (now_ms - state_entered_ms_ >= config_.handoff_timeout_ms) {
            if (active_mode_ == kActiveWireless) {
                teardownWirelessSession("wireless handoff timeout", true);
            } else if (active_mode_ == kActiveWired) {
                teardownWiredSession("wired handoff timeout", true, true);
            }
        }
    }
}

bool CarPlayConnectivity::appsProbeThunk(void* user, AppsSlot& out) {
    CarPlayConnectivity* self = static_cast<CarPlayConnectivity*>(user);
    if (self == NULL || self->bt_transport_ == NULL) {
        return false;
    }
    if (!self->alps_snapshot_safe_ && self->bt_transport_override_ == NULL) {
        return false;
    }
    return self->bt_transport_->readBmwAppsSlot(out);
}

}  // namespace platform
}  // namespace carplay
