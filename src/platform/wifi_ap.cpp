#include "carplay/platform/wifi_ap.hpp"

#include <string.h>

#include <sstream>

#include "carplay/platform/file_util.hpp"
#include "carplay/platform/log.hpp"
#include "carplay/platform/net_compat.hpp"

namespace carplay {
namespace platform {

namespace {

const char* const kTag = "wifi-ap";
const char* const kForbiddenSystemHostapdConf = "/etc/hostapd.conf";
const size_t kMaxSsidBytes = 32U;
const size_t kMinPassphraseBytes = 8U;
const size_t kMaxPassphraseBytes = 63U;

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

bool hasControlChars(const std::string& s) {
    for (size_t i = 0U; i < s.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x20U || c == 0x7fU) {
            return true;
        }
    }
    return false;
}

bool isValidInterfaceName(const std::string& name) {
    if (name.empty() || name.size() > 15U) {
        return false;
    }
    for (size_t i = 0U; i < name.size(); ++i) {
        const char c = name[i];
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok) {
            return false;
        }
    }
    return name != "." && name != "..";
}

bool isValidCountryCode(const std::string& cc) {
    return cc.size() == 2U && cc[0] >= 'A' && cc[0] <= 'Z' && cc[1] >= 'A' && cc[1] <= 'Z';
}

bool isValidIpv4Literal(const std::string& text) {
    if (text.empty() || text.find(':') != std::string::npos) {
        return false;
    }
    Address addr;
    return Address::parse(text, addr) && addr.family() == Address::kIPv4 && addr.port() == 0U;
}

bool generateRandomHex(pairing::RandomSource& rng, size_t hex_chars, std::string& out) {
    static const char kHex[] = "0123456789abcdef";
    out.clear();
    if (hex_chars == 0U) {
        return true;
    }
    const size_t num_bytes = (hex_chars + 1U) / 2U;
    std::vector<uint8_t> buf(num_bytes);
    if (!rng.fill(&buf[0], buf.size())) {
        return false;
    }
    out.reserve(hex_chars);
    for (size_t i = 0U; i < num_bytes && out.size() < hex_chars; ++i) {
        out.push_back(kHex[(buf[i] >> 4) & 0x0fU]);
        if (out.size() < hex_chars) {
            out.push_back(kHex[buf[i] & 0x0fU]);
        }
    }
    return true;
}

bool generateRandomPassphrase(pairing::RandomSource& rng, size_t length, std::string& out) {
    static const char kAlphabet[] =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    static const size_t kAlphaLen = sizeof(kAlphabet) - 1U;  // 56
    static const unsigned int kLimit = 256U - (256U % static_cast<unsigned int>(kAlphaLen));

    out.clear();
    if (length < kMinPassphraseBytes || length > kMaxPassphraseBytes) {
        return false;
    }
    out.reserve(length);
    uint8_t batch[32];
    while (out.size() < length) {
        if (!rng.fill(batch, sizeof(batch))) {
            out.clear();
            return false;
        }
        for (size_t i = 0U; i < sizeof(batch) && out.size() < length; ++i) {
            if (static_cast<unsigned int>(batch[i]) < kLimit) {
                out.push_back(kAlphabet[static_cast<unsigned int>(batch[i]) % kAlphaLen]);
            }
        }
    }
    return true;
}

bool tryReadSysfsMac(const std::string& interface_name, uint8_t mac_out[6]) {
    if (!isValidInterfaceName(interface_name)) {
        return false;
    }
    const std::string path = "/sys/class/net/" + interface_name + "/address";
    std::vector<uint8_t> raw;
    if (readFileBounded(path, 64U, raw) != kFileReadOk) {
        return false;
    }
    const std::string text(raw.begin(), raw.end());
    return parseMacAddressBytes(text, mac_out);
}

std::string formatMacBytes(const uint8_t mac[6]) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             static_cast<unsigned int>(mac[0]), static_cast<unsigned int>(mac[1]),
             static_cast<unsigned int>(mac[2]), static_cast<unsigned int>(mac[3]),
             static_cast<unsigned int>(mac[4]), static_cast<unsigned int>(mac[5]));
    return std::string(buf);
}

}  // namespace

const char* wifiApBackendName(WifiApBackend backend) {
    switch (backend) {
        case kWifiApBackendAuto:
            return "auto";
        case kWifiApBackendNative:
            return "native";
        case kWifiApBackendHostapd:
            return "hostapd";
    }
    return "unknown";
}

WifiApConfig::WifiApConfig()
    : interface_name("wlan1"),
      runtime_dir("/var/run/carplay"),
      ssid_prefix("BMW-CarPlay-"),
      random_ssid_suffix_hex_chars(6U),
      random_passphrase_length(16U),
      band(kWifiBandAuto),
      channel(36U),
      country_code("DE"),
      ieee80211n(true),
      max_num_sta(4),
      ap_isolate(false),
      hostapd_bin("/usr/sbin/hostapd"),
      enable_udhcpd(false),
      udhcpd_bin("/usr/sbin/udhcpd"),
      dhcp_start_ipv4("192.168.50.10"),
      dhcp_end_ipv4("192.168.50.50"),
      dhcp_subnet_mask("255.255.255.0"),
      dhcp_lease_sec(86400U),
      ctrl_poll_interval_ms(50),
      ctrl_wait_timeout_ms(5000),
      ctrl_cmd_timeout_ms(1000),
      health_check_interval_ms(250),
      auto_restart(true),
      max_restarts(3),
      restart_backoff_ms(500),
      stop_term_timeout_ms(2000),
      stop_kill_timeout_ms(1000),
      cleanup_files_on_stop(true),
      backend(kWifiApBackendAuto),
      native_interface_name(kNativeWlanInterface),
      native_ctrl_interface_dir(kNativeHostapdCtrlDir),
      native_ap_conf_path(kNativeApConfPath),
      native_hostapd_cli_bin(kNativeHostapdCliBin),
      native_fallback_channel(0U),
      native_wlan_timeout_ms(2000),
      native_ready_timeout_ms(5000),
      native_poll_interval_ms(100),
      native_restore_on_stop(true) {}

std::string WifiApConfig::effectiveHostapdConfPath() const {
    return hostapd_conf_path.empty() ? joinPath(runtime_dir, "hostapd-carplay.conf")
                                     : hostapd_conf_path;
}

std::string WifiApConfig::effectiveCtrlInterfaceDir() const {
    return ctrl_interface_dir.empty() ? joinPath(runtime_dir, "hostapd_ctrl")
                                      : ctrl_interface_dir;
}

std::string WifiApConfig::effectiveRemoteCtrlSocketPath() const {
    return joinPath(effectiveCtrlInterfaceDir(), interface_name);
}

std::string WifiApConfig::effectiveUdhcpdConfPath() const {
    return udhcpd_conf_path.empty() ? joinPath(runtime_dir, "udhcpd-carplay.conf")
                                    : udhcpd_conf_path;
}

std::string WifiApConfig::effectiveUdhcpdLeaseFile() const {
    return udhcpd_lease_file.empty() ? joinPath(runtime_dir, "udhcpd-carplay.leases")
                                     : udhcpd_lease_file;
}

std::string WifiApConfig::effectiveNativeRemoteCtrlSocketPath() const {
    return joinPath(native_ctrl_interface_dir, native_interface_name);
}

NativeWlanPaths WifiApConfig::effectiveNativePaths() const {
    NativeWlanPaths p;
    p.interface_name = native_interface_name;
    p.hostapd_ctrl_dir = native_ctrl_interface_dir;
    p.ap_conf_path = native_ap_conf_path;
    p.hostapd_cli_bin = native_hostapd_cli_bin;
    p.cli_timeout_ms = ctrl_cmd_timeout_ms > 0 ? ctrl_cmd_timeout_ms : 1000;
    return p;
}

WifiCredentials::WifiCredentials() : channel(36U), security_type(kIap2WifiSecurityWpa2), has_bssid(false) {
    memset(bssid, 0, sizeof(bssid));
}

std::vector<uint8_t> WifiCredentials::bssidVector() const {
    if (!has_bssid) {
        return std::vector<uint8_t>();
    }
    return std::vector<uint8_t>(bssid, bssid + 6);
}

bool isValid24GHzChannel(uint8_t channel) {
    return channel >= 1U && channel <= 13U;
}

bool isValid5GHzChannel(uint8_t channel) {
    static const uint8_t kChannels5G[] = {
        36U, 40U, 44U, 48U, 52U, 56U, 60U, 64U,
        100U, 104U, 108U, 112U, 116U, 120U, 124U, 128U, 132U, 136U, 140U, 144U,
        149U, 153U, 157U, 161U, 165U
    };
    for (size_t i = 0U; i < sizeof(kChannels5G); ++i) {
        if (kChannels5G[i] == channel) {
            return true;
        }
    }
    return false;
}

bool resolveWifiBandAndHwMode(WifiBand band,
                              uint8_t channel,
                              char& hw_mode_out,
                              std::string* error_out) {
    const bool is_24 = isValid24GHzChannel(channel);
    const bool is_5 = isValid5GHzChannel(channel);
    if (band == kWifiBand24GHz) {
        if (!is_24) {
            setError(error_out, "invalid 2.4 GHz Wi-Fi channel (expected 1..13)");
            return false;
        }
        hw_mode_out = 'g';
        return true;
    }
    if (band == kWifiBand5GHz) {
        if (!is_5) {
            setError(error_out, "invalid 5 GHz Wi-Fi channel");
            return false;
        }
        hw_mode_out = 'a';
        return true;
    }
    if (band == kWifiBandAuto) {
        if (is_24) {
            hw_mode_out = 'g';
            return true;
        }
        if (is_5) {
            hw_mode_out = 'a';
            return true;
        }
        setError(error_out, "invalid Wi-Fi channel for 2.4 GHz or 5 GHz");
        return false;
    }
    setError(error_out, "invalid WifiBand value");
    return false;
}

bool validateWifiApConfig(const WifiApConfig& cfg, std::string* error_out) {
    if (!isValidInterfaceName(cfg.interface_name)) {
        setError(error_out, "invalid Wi-Fi interface name");
        return false;
    }
    if (cfg.runtime_dir.empty() || hasControlChars(cfg.runtime_dir)) {
        setError(error_out, "invalid runtime_dir");
        return false;
    }
    const std::string hostapd_conf = cfg.effectiveHostapdConfPath();
    if (hostapd_conf.empty() || hasControlChars(hostapd_conf)) {
        setError(error_out, "invalid hostapd_conf_path");
        return false;
    }
    if (hostapd_conf == kForbiddenSystemHostapdConf) {
        setError(error_out, "refusing to use /etc/hostapd.conf; use a runtime config path");
        return false;
    }
    const std::string ctrl_dir = cfg.effectiveCtrlInterfaceDir();
    if (ctrl_dir.empty() || hasControlChars(ctrl_dir)) {
        setError(error_out, "invalid ctrl_interface_dir");
        return false;
    }
    if (hasControlChars(cfg.ctrl_interface_group)) {
        setError(error_out, "invalid ctrl_interface_group");
        return false;
    }
    if (!isValidCountryCode(cfg.country_code)) {
        setError(error_out, "country_code must be 2 uppercase ASCII letters");
        return false;
    }
    char hw_mode = '\0';
    if (!resolveWifiBandAndHwMode(cfg.band, cfg.channel, hw_mode, error_out)) {
        return false;
    }
    if (!cfg.ssid.empty()) {
        if (cfg.ssid.size() > kMaxSsidBytes || hasControlChars(cfg.ssid)) {
            setError(error_out, "SSID must be 1..32 bytes without control characters");
            return false;
        }
    } else {
        if (hasControlChars(cfg.ssid_prefix) || cfg.random_ssid_suffix_hex_chars == 0U ||
            cfg.ssid_prefix.size() + cfg.random_ssid_suffix_hex_chars > kMaxSsidBytes) {
            setError(error_out, "ssid_prefix + random_ssid_suffix_hex_chars must fit within 32 bytes");
            return false;
        }
    }
    if (!cfg.passphrase.empty()) {
        if (cfg.passphrase.size() < kMinPassphraseBytes ||
            cfg.passphrase.size() > kMaxPassphraseBytes || hasControlChars(cfg.passphrase)) {
            setError(error_out, "passphrase must be 8..63 printable ASCII characters");
            return false;
        }
    } else {
        if (cfg.random_passphrase_length < kMinPassphraseBytes ||
            cfg.random_passphrase_length > kMaxPassphraseBytes) {
            setError(error_out, "random_passphrase_length must be in [8, 63]");
            return false;
        }
    }
    if (!cfg.bssid.empty() && cfg.bssid.size() != 6U) {
        setError(error_out, "bssid override must be 6 bytes");
        return false;
    }
    if (cfg.hostapd_bin.empty() || hasControlChars(cfg.hostapd_bin)) {
        setError(error_out, "invalid hostapd_bin");
        return false;
    }
    if (cfg.max_num_sta < 0) {
        setError(error_out, "max_num_sta must be >= 0");
        return false;
    }
    if (cfg.enable_udhcpd) {
        if (cfg.udhcpd_bin.empty() || hasControlChars(cfg.udhcpd_bin) ||
            hasControlChars(cfg.effectiveUdhcpdConfPath()) ||
            hasControlChars(cfg.effectiveUdhcpdLeaseFile())) {
            setError(error_out, "invalid udhcpd path configuration");
            return false;
        }
        if (!isValidIpv4Literal(cfg.dhcp_start_ipv4) || !isValidIpv4Literal(cfg.dhcp_end_ipv4) ||
            !isValidIpv4Literal(cfg.dhcp_subnet_mask)) {
            setError(error_out, "invalid IPv4 address in udhcpd configuration");
            return false;
        }
        if (cfg.dhcp_lease_sec == 0U) {
            setError(error_out, "dhcp_lease_sec must be > 0");
            return false;
        }
    }
    if (cfg.ctrl_poll_interval_ms <= 0 || cfg.ctrl_wait_timeout_ms <= 0 ||
        cfg.ctrl_cmd_timeout_ms <= 0 || cfg.health_check_interval_ms <= 0 ||
        cfg.max_restarts < 0 || cfg.restart_backoff_ms < 0 ||
        cfg.stop_term_timeout_ms < 0 || cfg.stop_kill_timeout_ms < 0) {
        setError(error_out, "timing/supervision parameters must be non-negative (intervals > 0)");
        return false;
    }
    if (cfg.backend != kWifiApBackendAuto && cfg.backend != kWifiApBackendNative &&
        cfg.backend != kWifiApBackendHostapd) {
        setError(error_out, "invalid WifiApBackend value");
        return false;
    }
    if (!isValidInterfaceName(cfg.native_interface_name) ||
        cfg.native_ctrl_interface_dir.empty() || hasControlChars(cfg.native_ctrl_interface_dir) ||
        cfg.native_ap_conf_path.empty() || hasControlChars(cfg.native_ap_conf_path) ||
        cfg.native_hostapd_cli_bin.empty() || hasControlChars(cfg.native_hostapd_cli_bin) ||
        cfg.native_wlan_timeout_ms <= 0 || cfg.native_ready_timeout_ms <= 0 ||
        cfg.native_poll_interval_ms <= 0) {
        setError(error_out, "invalid car-native WLAN configuration parameters");
        return false;
    }
    return true;
}

bool generateWifiCredentials(const WifiApConfig& cfg,
                             pairing::RandomSource& rng,
                             WifiCredentials& out,
                             std::string* error_out) {
    out = WifiCredentials();
    if (!validateWifiApConfig(cfg, error_out)) {
        return false;
    }

    if (!cfg.ssid.empty()) {
        out.ssid = cfg.ssid;
    } else {
        std::string suffix;
        if (!generateRandomHex(rng, cfg.random_ssid_suffix_hex_chars, suffix)) {
            setError(error_out, "random source failed generating SSID suffix");
            return false;
        }
        out.ssid = cfg.ssid_prefix + suffix;
    }

    if (!cfg.passphrase.empty()) {
        out.passphrase = cfg.passphrase;
    } else {
        if (!generateRandomPassphrase(rng, cfg.random_passphrase_length, out.passphrase)) {
            setError(error_out, "random source failed generating WPA2 passphrase");
            return false;
        }
    }

    out.channel = cfg.channel;
    out.security_type = kIap2WifiSecurityWpa2;
    if (cfg.bssid.size() == 6U) {
        out.has_bssid = true;
        memcpy(out.bssid, &cfg.bssid[0], 6U);
    } else {
        out.has_bssid = false;
    }
    return true;
}

bool generateHostapdConfig(const WifiApConfig& cfg,
                           const WifiCredentials& creds,
                           std::string& out,
                           std::string* error_out) {
    out.clear();
    if (!validateWifiApConfig(cfg, error_out)) {
        return false;
    }
    if (creds.ssid.empty() || creds.ssid.size() > kMaxSsidBytes || hasControlChars(creds.ssid)) {
        setError(error_out, "invalid credentials SSID");
        return false;
    }
    if (creds.passphrase.size() < kMinPassphraseBytes ||
        creds.passphrase.size() > kMaxPassphraseBytes || hasControlChars(creds.passphrase)) {
        setError(error_out, "invalid credentials passphrase");
        return false;
    }

    char hw_mode = '\0';
    if (!resolveWifiBandAndHwMode(cfg.band, creds.channel, hw_mode, error_out)) {
        return false;
    }

    std::ostringstream oss;
    oss << "interface=" << cfg.interface_name << "\n"
        << "driver=nl80211\n"
        << "ctrl_interface=" << cfg.effectiveCtrlInterfaceDir() << "\n";
    if (!cfg.ctrl_interface_group.empty()) {
        oss << "ctrl_interface_group=" << cfg.ctrl_interface_group << "\n";
    }
    oss << "country_code=" << cfg.country_code << "\n"
        << "ieee80211d=1\n"
        << "hw_mode=" << hw_mode << "\n"
        << "channel=" << static_cast<unsigned int>(creds.channel) << "\n";
    if (cfg.ieee80211n) {
        oss << "ieee80211n=1\n"
            << "wmm_enabled=1\n";
    }
    if (cfg.max_num_sta > 0) {
        oss << "max_num_sta=" << cfg.max_num_sta << "\n";
    }
    if (cfg.ap_isolate) {
        oss << "ap_isolate=1\n";
    }
    oss << "ssid=" << creds.ssid << "\n"
        << "utf8_ssid=1\n"
        << "ignore_broadcast_ssid=0\n"
        << "auth_algs=1\n"
        << "wpa=2\n"
        << "wpa_key_mgmt=WPA-PSK\n"
        << "rsn_pairwise=CCMP\n"
        << "wpa_passphrase=" << creds.passphrase << "\n";

    out = oss.str();
    return true;
}

bool generateUdhcpdConfig(const WifiApConfig& cfg,
                          std::string& out,
                          std::string* error_out) {
    out.clear();
    if (!isValidInterfaceName(cfg.interface_name)) {
        setError(error_out, "invalid interface_name");
        return false;
    }
    if (hasControlChars(cfg.effectiveUdhcpdLeaseFile()) ||
        !isValidIpv4Literal(cfg.dhcp_start_ipv4) || !isValidIpv4Literal(cfg.dhcp_end_ipv4) ||
        !isValidIpv4Literal(cfg.dhcp_subnet_mask) || cfg.dhcp_lease_sec == 0U) {
        setError(error_out, "invalid udhcpd configuration parameters");
        return false;
    }

    // Intentionally omit `option router` and `option dns` so iOS keeps cellular data routing
    // while CarPlay runs over the Wi-Fi link (IPv6 link-local primary, optional IPv4 fallback).
    std::ostringstream oss;
    oss << "start " << cfg.dhcp_start_ipv4 << "\n"
        << "end " << cfg.dhcp_end_ipv4 << "\n"
        << "interface " << cfg.interface_name << "\n"
        << "lease_file " << cfg.effectiveUdhcpdLeaseFile() << "\n"
        << "option subnet " << cfg.dhcp_subnet_mask << "\n"
        << "option lease " << cfg.dhcp_lease_sec << "\n";
    out = oss.str();
    return true;
}

bool buildAccessoryWiFiConfigFrame(const WifiCredentials& creds,
                                   iap2::Frame& frame_out,
                                   std::string* error_out) {
    if (creds.ssid.empty() || creds.ssid.size() > kMaxSsidBytes) {
        setError(error_out, "invalid SSID for AccessoryWiFiConfigurationInformation");
        return false;
    }
    if (creds.passphrase.size() < kMinPassphraseBytes ||
        creds.passphrase.size() > kMaxPassphraseBytes) {
        setError(error_out, "invalid passphrase for AccessoryWiFiConfigurationInformation");
        return false;
    }
    const std::vector<uint8_t> bssid_vec = creds.bssidVector();
    return iap2::buildAccessoryWiFiConfiguration(
        creds.ssid, creds.passphrase, creds.channel, creds.security_type,
        creds.has_bssid ? &bssid_vec : NULL, frame_out, error_out);
}

const char* wifiApStateName(WifiApState state) {
    switch (state) {
        case kWifiApStopped:
            return "stopped";
        case kWifiApStartingWaitCtrl:
            return "starting_wait_ctrl";
        case kWifiApRunning:
            return "running";
        case kWifiApRestarting:
            return "restarting";
        case kWifiApStopping:
            return "stopping";
        case kWifiApFailed:
            return "failed";
    }
    return "unknown";
}

WifiAp::WifiAp(Reactor& reactor, pairing::RandomSource& rng)
    : reactor_(reactor),
      rng_(rng),
      listener_(NULL),
      default_ctrl_(reactor),
      default_wlan_ctrl_(reactor),
      hostapd_proc_override_(NULL),
      udhcpd_proc_override_(NULL),
      ctrl_override_(NULL),
      wlan_ctrl_override_(NULL),
      ap_reader_override_(NULL),
      native_capability_override_(-1),
      state_(kWifiApStopped),
      active_backend_(kWifiApBackendHostapd),
      restart_count_(0),
      timer_id_(Reactor::kNoTimer),
      ctrl_wait_deadline_ms_(0),
      stop_term_deadline_ms_(0),
      stop_kill_deadline_ms_(0),
      stop_kill_sent_(false),
      ctrl_attached_(false),
      ctrl_status_ok_(false),
      ctrl_probe_pending_(false),
      native_wlan_pending_(false),
      native_wlan_done_(false),
      native_switched_on_by_us_(false),
      native_creds_ready_(false),
      native_got_get_config_(false),
      native_ap_read_ok_(false),
      alive_state_(new AliveState()) {}

WifiAp::~WifiAp() {
    if (alive_state_ != NULL) {
        alive_state_->alive = false;
    }
    listener_ = NULL;
    stopSync();
    hostapd_proc_override_ = NULL;
    udhcpd_proc_override_ = NULL;
    ctrl_override_ = NULL;
    wlan_ctrl_override_ = NULL;
    ap_reader_override_ = NULL;
    if (alive_state_ != NULL) {
        if (--alive_state_->refs == 0) {
            delete alive_state_;
        }
        alive_state_ = NULL;
    }
}

void WifiAp::setHostapdProcessForTest(IChildProcess* proc) {
    if (proc != NULL && state_ != kWifiApStopped && state_ != kWifiApFailed) {
        CARPLAY_LOG_WARN(kTag, "ignoring setHostapdProcessForTest while WifiAp is active");
        return;
    }
    hostapd_proc_override_ = proc;
}

void WifiAp::setUdhcpdProcessForTest(IChildProcess* proc) {
    if (proc != NULL && state_ != kWifiApStopped && state_ != kWifiApFailed) {
        CARPLAY_LOG_WARN(kTag, "ignoring setUdhcpdProcessForTest while WifiAp is active");
        return;
    }
    udhcpd_proc_override_ = proc;
}

void WifiAp::setHostapdCtrlForTest(IHostapdCtrl* ctrl_ptr) {
    if (ctrl_ptr != NULL && state_ != kWifiApStopped && state_ != kWifiApFailed) {
        CARPLAY_LOG_WARN(kTag, "ignoring setHostapdCtrlForTest while WifiAp is active");
        return;
    }
    ctrl_override_ = ctrl_ptr;
}

void WifiAp::setWlanControllerForTest(IWlanController* wlan) {
    if (wlan != NULL && state_ != kWifiApStopped && state_ != kWifiApFailed) {
        CARPLAY_LOG_WARN(kTag, "ignoring setWlanControllerForTest while WifiAp is active");
        return;
    }
    wlan_ctrl_override_ = wlan;
}

void WifiAp::setAccessPointReaderForTest(IAccessPointReader* reader) {
    if (reader != NULL && state_ != kWifiApStopped && state_ != kWifiApFailed) {
        CARPLAY_LOG_WARN(kTag, "ignoring setAccessPointReaderForTest while WifiAp is active");
        return;
    }
    ap_reader_override_ = reader;
}

void WifiAp::setNativeCapabilityForTest(int override_state) {
    if (state_ != kWifiApStopped && state_ != kWifiApFailed) {
        CARPLAY_LOG_WARN(kTag, "ignoring setNativeCapabilityForTest while WifiAp is active");
        return;
    }
    native_capability_override_ = override_state;
}

IChildProcess* WifiAp::hostapdProc() {
    return hostapd_proc_override_ != NULL ? hostapd_proc_override_ : &default_hostapd_proc_;
}

IChildProcess* WifiAp::udhcpdProc() {
    return udhcpd_proc_override_ != NULL ? udhcpd_proc_override_ : &default_udhcpd_proc_;
}

IHostapdCtrl* WifiAp::ctrl() {
    return ctrl_override_ != NULL ? ctrl_override_ : &default_ctrl_;
}

IWlanController* WifiAp::wlanCtrl() {
    return wlan_ctrl_override_ != NULL ? wlan_ctrl_override_ : &default_wlan_ctrl_;
}

const IWlanController* WifiAp::wlanCtrl() const {
    return wlan_ctrl_override_ != NULL ? wlan_ctrl_override_ : &default_wlan_ctrl_;
}

IAccessPointReader* WifiAp::apReader() {
    return ap_reader_override_ != NULL ? ap_reader_override_ : &default_ap_reader_;
}

const IAccessPointReader* WifiAp::apReader() const {
    return ap_reader_override_ != NULL ? ap_reader_override_ : &default_ap_reader_;
}

bool WifiAp::isNativeCapable(const WifiApConfig& cfg) const {
    if (native_capability_override_ == 0) {
        return false;
    }
    if (native_capability_override_ > 0) {
        return true;
    }
    return wlanCtrl()->isAvailable() ||
           apReader()->isNativeEnvironmentPresent(cfg.effectiveNativePaths());
}

WifiApBackend WifiAp::resolveBackend(const WifiApConfig& cfg) const {
    if (cfg.backend == kWifiApBackendNative) {
        return kWifiApBackendNative;
    }
    if (cfg.backend == kWifiApBackendHostapd) {
        return kWifiApBackendHostapd;
    }
    return isNativeCapable(cfg) ? kWifiApBackendNative : kWifiApBackendHostapd;
}

int64_t WifiAp::nowMs() const {
    return reactor_.now() / 1000000LL;
}

void WifiAp::cancelTimer() {
    if (timer_id_ != Reactor::kNoTimer) {
        reactor_.cancelTimer(timer_id_);
        timer_id_ = Reactor::kNoTimer;
    }
}

void WifiAp::armTimer(int delay_ms, int period_ms) {
    cancelTimer();
    timer_id_ = reactor_.startTimer(delay_ms, period_ms, this);
}

bool WifiAp::prepareRuntimeFiles(std::string* error_out) {
    if (!ensurePrivateDirectory(config_.runtime_dir)) {
        setError(error_out, "failed to create runtime_dir: " + config_.runtime_dir);
        return false;
    }
    const std::string ctrl_dir = config_.effectiveCtrlInterfaceDir();
    if (!ensurePrivateDirectory(ctrl_dir)) {
        setError(error_out, "failed to create ctrl_interface_dir: " + ctrl_dir);
        return false;
    }

    std::string hostapd_conf;
    if (!generateHostapdConfig(config_, credentials_, hostapd_conf, error_out)) {
        return false;
    }
    const std::string conf_path = config_.effectiveHostapdConfPath();
    if (!writeFileAtomic(conf_path, reinterpret_cast<const uint8_t*>(hostapd_conf.data()),
                         hostapd_conf.size())) {
        setError(error_out, "failed to write hostapd config: " + conf_path);
        return false;
    }

    if (config_.enable_udhcpd) {
        std::string udhcpd_conf;
        if (!generateUdhcpdConfig(config_, udhcpd_conf, error_out)) {
            return false;
        }
        const std::string uconf_path = config_.effectiveUdhcpdConfPath();
        if (!writeFileAtomic(uconf_path, reinterpret_cast<const uint8_t*>(udhcpd_conf.data()),
                             udhcpd_conf.size())) {
            setError(error_out, "failed to write udhcpd config: " + uconf_path);
            return false;
        }
        const std::string lease_path = config_.effectiveUdhcpdLeaseFile();
        if (!pathExists(lease_path)) {
            writeFileAtomic(lease_path, reinterpret_cast<const uint8_t*>(""), 0U);
        }
    }
    return true;
}

void WifiAp::cleanupRuntimeFiles() {
    if (active_backend_ == kWifiApBackendNative || !config_.cleanup_files_on_stop) {
        return;
    }
    if (!config_.runtime_dir.empty()) {
        removeFile(config_.effectiveHostapdConfPath());
        if (config_.enable_udhcpd) {
            removeFile(config_.effectiveUdhcpdConfPath());
            removeFile(config_.effectiveUdhcpdLeaseFile());
        }
    }
}

bool WifiAp::spawnHostapd(std::string* error_out) {
    std::vector<std::string> args;
    args.push_back(config_.effectiveHostapdConfPath());
    return hostapdProc()->start(config_.hostapd_bin, args, config_.hostapd_log_path, error_out);
}

bool WifiAp::spawnUdhcpd(std::string* error_out) {
    if (!config_.enable_udhcpd) {
        return true;
    }
    std::vector<std::string> args;
    args.push_back("-f");
    args.push_back(config_.effectiveUdhcpdConfPath());
    return udhcpdProc()->start(config_.udhcpd_bin, args, config_.udhcpd_log_path, error_out);
}

bool WifiAp::start(const WifiApConfig& cfg, std::string* error_out) {
    if (state_ != kWifiApStopped && state_ != kWifiApFailed) {
        setError(error_out, std::string("cannot start WifiAp in state ") + wifiApStateName(state_));
        return false;
    }

    if (!validateWifiApConfig(cfg, error_out)) {
        return false;
    }

    const WifiApBackend resolved = resolveBackend(cfg);

    if (resolved == kWifiApBackendNative) {
        config_ = cfg;
        active_backend_ = kWifiApBackendNative;
        credentials_ = WifiCredentials();
        last_error_.clear();
        restart_count_ = 0;
        connected_stations_.clear();
        ctrl_attached_ = false;
        ctrl_status_ok_ = false;
        ctrl_probe_pending_ = false;
        native_wlan_pending_ = true;
        native_wlan_done_ = false;
        native_switched_on_by_us_ = false;
        native_creds_ready_ = false;
        native_got_get_config_ = false;
        native_ap_read_ok_ = false;
        native_ap_info_ = EvoApInfo();

        CARPLAY_LOG_INFO(kTag, "starting car-native Wi-Fi AP backend on %s (requested=%s)",
                         config_.native_interface_name.c_str(),
                         wifiApBackendName(config_.backend));

        state_ = kWifiApStartingWaitCtrl;
        wlanCtrl()->setListener(this);
        std::string err;
        if (!wlanCtrl()->beginEnable(static_cast<unsigned>(config_.native_wlan_timeout_ms), &err)) {
            wlanCtrl()->setListener(NULL);
            native_wlan_pending_ = false;
            last_error_ = err.empty() ? "car-native Wi-Fi AP unavailable" : err;
            setError(error_out, last_error_);
            state_ = kWifiApFailed;
            return false;
        }
        return true;
    }

    WifiCredentials creds;
    if (!generateWifiCredentials(cfg, rng_, creds, error_out)) {
        return false;
    }
    if (!creds.has_bssid) {
        uint8_t sys_mac[6];
        if (tryReadSysfsMac(cfg.interface_name, sys_mac)) {
            creds.has_bssid = true;
            memcpy(creds.bssid, sys_mac, 6U);
        }
    }

    config_ = cfg;
    active_backend_ = kWifiApBackendHostapd;
    credentials_ = creds;
    last_error_.clear();
    restart_count_ = 0;
    connected_stations_.clear();
    ctrl_attached_ = false;
    ctrl_status_ok_ = false;
    ctrl_probe_pending_ = false;
    native_wlan_pending_ = false;
    native_wlan_done_ = false;
    native_switched_on_by_us_ = false;
    native_creds_ready_ = false;
    native_got_get_config_ = false;
    native_ap_read_ok_ = false;
    native_ap_info_ = EvoApInfo();

    if (!prepareRuntimeFiles(error_out)) {
        last_error_ = error_out != NULL ? *error_out : "failed to prepare Wi-Fi runtime files";
        state_ = kWifiApFailed;
        return false;
    }

    if (!spawnHostapd(error_out)) {
        last_error_ = error_out != NULL ? *error_out : "failed to start hostapd";
        cleanupRuntimeFiles();
        state_ = kWifiApFailed;
        return false;
    }

    CARPLAY_LOG_INFO(kTag, "started hostapd on %s (ssid=\"%s\", channel=%u)",
                     config_.interface_name.c_str(), credentials_.ssid.c_str(),
                     static_cast<unsigned int>(credentials_.channel));

    state_ = kWifiApStartingWaitCtrl;
    ctrl_wait_deadline_ms_ = nowMs() + static_cast<int64_t>(config_.ctrl_wait_timeout_ms);
    ctrl()->setListener(this);
    armTimer(config_.ctrl_poll_interval_ms, config_.ctrl_poll_interval_ms);
    tryOpenAndProbeCtrl();
    return true;
}

void WifiAp::mergeNativeApInfo(const EvoApInfo& parsed) {
    if (!parsed.ssid.empty()) {
        native_ap_info_.ssid = parsed.ssid;
    }
    if (!parsed.passphrase.empty()) {
        native_ap_info_.passphrase = parsed.passphrase;
    }
    if (!parsed.bssid.empty()) {
        native_ap_info_.bssid = parsed.bssid;
    }
    if (!parsed.ip.empty()) {
        native_ap_info_.ip = parsed.ip;
    }
    if (parsed.channel > 0) {
        native_ap_info_.channel = parsed.channel;
    }
    if (parsed.freq_mhz > 0) {
        native_ap_info_.freq_mhz = parsed.freq_mhz;
    }
    if (!parsed.key_mgmt.empty()) {
        native_ap_info_.key_mgmt = parsed.key_mgmt;
    }
    if (!parsed.wpa.empty()) {
        native_ap_info_.wpa = parsed.wpa;
    }
    if (parsed.security_type != 0U) {
        native_ap_info_.security_type = parsed.security_type;
    }
}

void WifiAp::refreshNativeCredentials() {
    if (native_ap_info_.bssid.empty()) {
        uint8_t sys_mac[6];
        if (tryReadSysfsMac(config_.native_interface_name, sys_mac)) {
            native_ap_info_.bssid = formatMacBytes(sys_mac);
        }
    }
    if (native_ap_info_.channel <= 0 && native_ap_info_.freq_mhz <= 0) {
        unsigned mhz = 0U;
        if (apReader()->readFrequencyMhz(config_.native_interface_name, mhz) && mhz > 0U) {
            native_ap_info_.freq_mhz = static_cast<int>(mhz);
            native_ap_info_.channel = frequencyMhzToChannel(native_ap_info_.freq_mhz);
        }
    }
    WifiCredentials creds;
    if (native_ap_info_.toWifiCredentials(creds, config_.native_fallback_channel, NULL)) {
        credentials_ = creds;
        native_creds_ready_ = true;
    }
}

void WifiAp::maybeCompleteNativeStart() {
    if (active_backend_ != kWifiApBackendNative || state_ != kWifiApStartingWaitCtrl ||
        !native_wlan_done_) {
        return;
    }
    refreshNativeCredentials();
    if (!native_creds_ready_) {
        return;
    }

    const bool ready_via_ctrl = ctrl()->isOpen() && ctrl_status_ok_;
    const bool ready_via_reader = !ctrl()->isOpen() && native_ap_read_ok_;
    if (!ready_via_ctrl && !ready_via_reader) {
        return;
    }

    if (ready_via_reader || !ctrl_attached_) {
        syncNativeStationsFromReader();
        if (state_ != kWifiApStartingWaitCtrl) {
            return;
        }
    }

    state_ = kWifiApRunning;
    armTimer(config_.health_check_interval_ms, config_.health_check_interval_ms);
    CARPLAY_LOG_INFO(kTag, "car-native Wi-Fi AP ready on %s (bssid=%s, channel=%u)",
                     config_.native_interface_name.c_str(),
                     credentials_.has_bssid ? formatMacBytes(credentials_.bssid).c_str() : "unknown",
                     static_cast<unsigned int>(credentials_.channel));

    AliveGuard guard(alive_state_);
    if (listener_ != NULL) {
        listener_->onWifiApStarted(credentials_);
    }
    if (!guard.alive()) {
        return;
    }
}

void WifiAp::tryPollNativeReadiness() {
    if (active_backend_ != kWifiApBackendNative || state_ != kWifiApStartingWaitCtrl ||
        !native_wlan_done_) {
        return;
    }
    if (nowMs() >= ctrl_wait_deadline_ms_) {
        transitionToFailed("timed out waiting for car-native Wi-Fi AP readiness");
        return;
    }

    IHostapdCtrl* c = ctrl();
    if (!c->isOpen()) {
        if (!config_.runtime_dir.empty()) {
            ensurePrivateDirectory(config_.runtime_dir);
        }
        std::string err;
        if (c->open(config_.effectiveNativeRemoteCtrlSocketPath(), config_.runtime_dir, &err)) {
            ctrl_attached_ = false;
            ctrl_status_ok_ = false;
            ctrl_probe_pending_ = true;
            c->sendPing(config_.ctrl_cmd_timeout_ms);
            c->sendAttach(config_.ctrl_cmd_timeout_ms);
            c->sendStatus(config_.ctrl_cmd_timeout_ms);
            c->sendGetConfig(config_.ctrl_cmd_timeout_ms);
            c->sendAllSta(config_.ctrl_cmd_timeout_ms);
        }
    } else if (!ctrl_probe_pending_ && (!ctrl_status_ok_ || !native_got_get_config_)) {
        ctrl_probe_pending_ = true;
        if (!ctrl_attached_) {
            c->sendAttach(config_.ctrl_cmd_timeout_ms);
        }
        c->sendStatus(config_.ctrl_cmd_timeout_ms);
        if (!native_got_get_config_) {
            c->sendGetConfig(config_.ctrl_cmd_timeout_ms);
        }
        c->sendAllSta(config_.ctrl_cmd_timeout_ms);
    }

    if (!native_creds_ready_ || !c->isOpen()) {
        EvoApInfo read_ap;
        std::string source;
        std::string err;
        if (apReader()->readAccessPoint(config_.effectiveNativePaths(), read_ap, source, &err)) {
            native_ap_read_ok_ = true;
            mergeNativeApInfo(read_ap);
        }
    }

    maybeCompleteNativeStart();
}

void WifiAp::syncNativeStationsFromReader() {
    std::vector<std::string> raw_macs;
    if (!apReader()->readConnectedStations(config_.native_interface_name, raw_macs)) {
        return;
    }
    std::vector<std::string> norm_macs;
    for (size_t i = 0U; i < raw_macs.size(); ++i) {
        std::string norm;
        if (normalizeMacAddress(raw_macs[i], norm)) {
            norm_macs.push_back(norm);
        }
    }

    AliveGuard guard(alive_state_);
    std::vector<std::string> existing = connected_stations_;
    for (size_t i = 0U; i < existing.size(); ++i) {
        bool still_here = false;
        for (size_t j = 0U; j < norm_macs.size(); ++j) {
            if (existing[i] == norm_macs[j]) {
                still_here = true;
                break;
            }
        }
        if (!still_here) {
            removeConnectedStation(existing[i]);
            if (!guard.alive() || state_ != kWifiApRunning) {
                return;
            }
        }
    }

    for (size_t i = 0U; i < norm_macs.size(); ++i) {
        addConnectedStation(norm_macs[i]);
        if (!guard.alive() || state_ != kWifiApRunning) {
            return;
        }
    }
}

void WifiAp::onWlanEnableResult(bool ok,
                                const WlanRequestResult& result,
                                const std::string& error) {
    if (active_backend_ != kWifiApBackendNative || state_ != kWifiApStartingWaitCtrl) {
        return;
    }
    native_wlan_pending_ = false;
    native_switched_on_by_us_ = result.switched_on_by_us;

    if (!ok) {
        transitionToFailed(error.empty() ? "failed to enable car-native Wi-Fi AP via vMOST" : error);
        return;
    }

    native_wlan_done_ = true;
    ctrl_wait_deadline_ms_ = nowMs() + static_cast<int64_t>(config_.native_ready_timeout_ms);
    ctrl()->setListener(this);
    armTimer(config_.native_poll_interval_ms, config_.native_poll_interval_ms);
    tryPollNativeReadiness();
}

void WifiAp::onWlanDisableResult(bool ok,
                                 const WlanRequestResult& result,
                                 const std::string& error) {
    (void)result;
    if (active_backend_ != kWifiApBackendNative || state_ != kWifiApStopping) {
        return;
    }
    if (!ok) {
        CARPLAY_LOG_WARN(kTag, "car-native Wi-Fi AP restore off returned error: %s",
                         error.c_str());
    }
    native_wlan_pending_ = false;
    native_switched_on_by_us_ = false;
    wlanCtrl()->setListener(NULL);
    finishStop();
}

void WifiAp::tryOpenAndProbeCtrl() {
    if (active_backend_ == kWifiApBackendNative) {
        tryPollNativeReadiness();
        return;
    }
    if (state_ != kWifiApStartingWaitCtrl) {
        return;
    }
    if (!hostapdProc()->isRunning()) {
        handleUnexpectedHostapdExit("hostapd exited before control interface became ready");
        return;
    }
    if (nowMs() >= ctrl_wait_deadline_ms_) {
        transitionToFailed("timed out waiting for hostapd control interface");
        return;
    }

    IHostapdCtrl* c = ctrl();
    if (!c->isOpen()) {
        std::string err;
        if (!c->open(config_.effectiveRemoteCtrlSocketPath(), config_.runtime_dir, &err)) {
            return;  // will retry on next poll tick
        }
        ctrl_attached_ = false;
        ctrl_status_ok_ = false;
        ctrl_probe_pending_ = true;
        c->sendPing(config_.ctrl_cmd_timeout_ms);
        c->sendAttach(config_.ctrl_cmd_timeout_ms);
        c->sendStatus(config_.ctrl_cmd_timeout_ms);
        c->sendAllSta(config_.ctrl_cmd_timeout_ms);
        return;
    }

    if (!ctrl_probe_pending_ && (!ctrl_attached_ || !ctrl_status_ok_)) {
        ctrl_probe_pending_ = true;
        if (!ctrl_attached_) {
            c->sendAttach(config_.ctrl_cmd_timeout_ms);
        }
        c->sendStatus(config_.ctrl_cmd_timeout_ms);
        c->sendAllSta(config_.ctrl_cmd_timeout_ms);
    }
}

void WifiAp::stop() {
    if (state_ == kWifiApStopped) {
        return;
    }
    if (state_ == kWifiApFailed) {
        cancelTimer();
        cleanupRuntimeFiles();
        state_ = kWifiApStopped;
        ctrl_attached_ = false;
        ctrl_status_ok_ = false;
        ctrl_probe_pending_ = false;
        native_wlan_pending_ = false;
        native_wlan_done_ = false;
        native_switched_on_by_us_ = false;
        return;
    }
    if (state_ == kWifiApStopping) {
        return;
    }

    AliveGuard guard(alive_state_);
    cancelTimer();
    ctrl()->setListener(NULL);
    ctrl()->close();
    clearConnectedStations();
    if (!guard.alive()) {
        return;
    }

    if (active_backend_ == kWifiApBackendNative) {
        if (native_wlan_pending_) {
            wlanCtrl()->cancel();
            native_wlan_pending_ = false;
        }
        if (native_switched_on_by_us_ && config_.native_restore_on_stop) {
            state_ = kWifiApStopping;
            wlanCtrl()->setListener(this);
            native_wlan_pending_ = true;
            std::string err;
            if (!wlanCtrl()->beginDisable(static_cast<unsigned>(config_.native_wlan_timeout_ms),
                                          &err)) {
                CARPLAY_LOG_WARN(kTag, "car-native Wi-Fi AP restore failed: %s", err.c_str());
                wlanCtrl()->setListener(NULL);
                native_wlan_pending_ = false;
                native_switched_on_by_us_ = false;
                finishStop();
            }
            return;
        }
        wlanCtrl()->setListener(NULL);
        finishStop();
        return;
    }

    if (udhcpdProc()->isRunning()) {
        udhcpdProc()->sendTerm();
    }
    if (hostapdProc()->isRunning()) {
        hostapdProc()->sendTerm();
    }

    if (!hostapdProc()->isRunning() && !udhcpdProc()->isRunning()) {
        finishStop();
        return;
    }

    state_ = kWifiApStopping;
    const int64_t t = nowMs();
    stop_term_deadline_ms_ = t + static_cast<int64_t>(config_.stop_term_timeout_ms);
    stop_kill_deadline_ms_ = stop_term_deadline_ms_ + static_cast<int64_t>(config_.stop_kill_timeout_ms);
    stop_kill_sent_ = false;
    armTimer(20, 20);
}

void WifiAp::stopSync() {
    if (state_ == kWifiApStopped) {
        return;
    }
    if (state_ == kWifiApFailed) {
        cancelTimer();
        cleanupRuntimeFiles();
        state_ = kWifiApStopped;
        ctrl_attached_ = false;
        ctrl_status_ok_ = false;
        ctrl_probe_pending_ = false;
        native_wlan_pending_ = false;
        native_wlan_done_ = false;
        native_switched_on_by_us_ = false;
        return;
    }
    const bool already_destroying = (alive_state_ != NULL && !alive_state_->alive);
    AliveGuard guard(alive_state_);
    cancelTimer();
    ctrl()->setListener(NULL);
    ctrl()->close();
    clearConnectedStations();
    if (!already_destroying && !guard.alive()) {
        return;
    }

    if (active_backend_ == kWifiApBackendNative) {
        wlanCtrl()->setListener(NULL);
        wlanCtrl()->cancel();
        native_wlan_pending_ = false;
        if (native_switched_on_by_us_ && config_.native_restore_on_stop) {
            std::string err;
            if (!wlanCtrl()->restoreSync(static_cast<unsigned>(config_.native_wlan_timeout_ms),
                                         &err)) {
                CARPLAY_LOG_WARN(kTag, "car-native Wi-Fi AP sync restore failed: %s", err.c_str());
            }
            native_switched_on_by_us_ = false;
        }
        finishStop();
        return;
    }

    const int term_ms = config_.stop_term_timeout_ms > 0 ? config_.stop_term_timeout_ms : 500;
    const int kill_ms = config_.stop_kill_timeout_ms > 0 ? config_.stop_kill_timeout_ms : 500;
    if (udhcpdProc()->isRunning()) {
        udhcpdProc()->stop(term_ms, kill_ms);
    }
    if (hostapdProc()->isRunning()) {
        hostapdProc()->stop(term_ms, kill_ms);
    }
    finishStop();
}

void WifiAp::finishStop() {
    cancelTimer();
    cleanupRuntimeFiles();
    state_ = kWifiApStopped;
    ctrl_attached_ = false;
    ctrl_status_ok_ = false;
    ctrl_probe_pending_ = false;
    native_wlan_pending_ = false;
    native_wlan_done_ = false;

    AliveGuard guard(alive_state_);
    if (listener_ != NULL) {
        listener_->onWifiApStopped();
    }
    if (!guard.alive()) {
        return;
    }
}

void WifiAp::handleUnexpectedHostapdExit(const std::string& reason) {
    AliveGuard guard(alive_state_);
    cancelTimer();
    ctrl()->setListener(NULL);
    ctrl()->close();

    if (udhcpdProc()->isRunning()) {
        udhcpdProc()->stop(500, 500);
    }

    clearConnectedStations();
    if (!guard.alive()) {
        return;
    }

    if (active_backend_ == kWifiApBackendHostapd && config_.auto_restart &&
        restart_count_ < config_.max_restarts) {
        ++restart_count_;
        last_error_ = reason;
        state_ = kWifiApRestarting;
        CARPLAY_LOG_WARN(kTag, "hostapd exited unexpectedly (%s); scheduling restart %d/%d",
                         reason.c_str(), restart_count_, config_.max_restarts);

        if (listener_ != NULL) {
            listener_->onWifiApRestarting(restart_count_, reason);
        }
        if (!guard.alive()) {
            return;
        }
        if (state_ == kWifiApRestarting) {
            armTimer(config_.restart_backoff_ms, 0);
        }
        return;
    }

    transitionToFailed(reason);
}

void WifiAp::transitionToFailed(const std::string& reason) {
    AliveGuard guard(alive_state_);
    cancelTimer();
    ctrl()->setListener(NULL);
    ctrl()->close();

    if (active_backend_ == kWifiApBackendNative) {
        wlanCtrl()->setListener(NULL);
        wlanCtrl()->cancel();
        native_wlan_pending_ = false;
        if (native_switched_on_by_us_ && config_.native_restore_on_stop) {
            std::string err;
            if (!wlanCtrl()->restoreSync(static_cast<unsigned>(config_.native_wlan_timeout_ms),
                                         &err)) {
                CARPLAY_LOG_WARN(kTag, "car-native Wi-Fi AP restore on failure failed: %s",
                                 err.c_str());
            }
            native_switched_on_by_us_ = false;
        }
    } else {
        if (udhcpdProc()->isRunning()) {
            udhcpdProc()->stop(500, 500);
        }
        if (hostapdProc()->isRunning()) {
            hostapdProc()->stop(500, 500);
        }
        cleanupRuntimeFiles();
    }

    last_error_ = reason;
    state_ = kWifiApFailed;
    CARPLAY_LOG_ERROR(kTag, "Wi-Fi AP failed: %s", reason.c_str());

    clearConnectedStations();
    if (!guard.alive()) {
        return;
    }
    if (listener_ != NULL) {
        listener_->onWifiApFailed(reason);
    }
}

void WifiAp::onTimer(uint32_t timer_id) {
    if (timer_id != timer_id_) {
        return;
    }

    if (active_backend_ == kWifiApBackendNative) {
        if (state_ == kWifiApStartingWaitCtrl) {
            tryPollNativeReadiness();
            return;
        }
        if (state_ == kWifiApRunning) {
            if (!ctrl_attached_) {
                syncNativeStationsFromReader();
            }
            return;
        }
        return;
    }

    if (state_ == kWifiApStartingWaitCtrl) {
        tryOpenAndProbeCtrl();
        return;
    }

    if (state_ == kWifiApRunning) {
        if (!hostapdProc()->isRunning()) {
            handleUnexpectedHostapdExit("hostapd process exited");
            return;
        }
        if (config_.enable_udhcpd && !udhcpdProc()->isRunning()) {
            CARPLAY_LOG_WARN(kTag, "udhcpd exited unexpectedly; restarting udhcpd");
            std::string err;
            if (!spawnUdhcpd(&err)) {
                CARPLAY_LOG_WARN(kTag, "udhcpd restart failed: %s", err.c_str());
            }
        }
        return;
    }

    if (state_ == kWifiApRestarting) {
        timer_id_ = Reactor::kNoTimer;
        std::string err;
        if (!prepareRuntimeFiles(&err) || !spawnHostapd(&err)) {
            transitionToFailed(err.empty() ? "failed to respawn hostapd" : err);
            return;
        }
        ctrl_attached_ = false;
        ctrl_status_ok_ = false;
        ctrl_probe_pending_ = false;
        state_ = kWifiApStartingWaitCtrl;
        ctrl_wait_deadline_ms_ = nowMs() + static_cast<int64_t>(config_.ctrl_wait_timeout_ms);
        ctrl()->setListener(this);
        armTimer(config_.ctrl_poll_interval_ms, config_.ctrl_poll_interval_ms);
        tryOpenAndProbeCtrl();
        return;
    }

    if (state_ == kWifiApStopping) {
        const bool hostapd_up = hostapdProc()->isRunning();
        const bool udhcpd_up = udhcpdProc()->isRunning();
        if (!hostapd_up && !udhcpd_up) {
            finishStop();
            return;
        }
        const int64_t t = nowMs();
        if (!stop_kill_sent_ && t >= stop_term_deadline_ms_) {
            stop_kill_sent_ = true;
            if (hostapd_up) {
                hostapdProc()->sendKill();
            }
            if (udhcpd_up) {
                udhcpdProc()->sendKill();
            }
            if (!hostapdProc()->isRunning() && !udhcpdProc()->isRunning()) {
                finishStop();
            }
            return;
        }
        if (t >= stop_kill_deadline_ms_) {
            finishStop();
        }
    }
}

void WifiAp::onHostapdCommandReply(HostapdCommandKind cmd,
                                   bool ok,
                                   const std::string& reply) {
    if (state_ != kWifiApStartingWaitCtrl && state_ != kWifiApRunning) {
        return;
    }

    AliveGuard guard(alive_state_);

    if (cmd == kCmdPing) {
        if (!ok) {
            ctrl_probe_pending_ = false;
            ctrl()->close();
        }
        return;
    }

    if (cmd == kCmdAttach) {
        if (ok) {
            ctrl_attached_ = true;
        } else if (active_backend_ == kWifiApBackendHostapd) {
            ctrl_probe_pending_ = false;
        }
        return;
    }

    if (cmd == kCmdGetConfig) {
        if (active_backend_ == kWifiApBackendNative && ok) {
            EvoApInfo parsed;
            if (parseHostapdConfig(reply, parsed)) {
                native_got_get_config_ = true;
                mergeNativeApInfo(parsed);
            }
        }
        return;
    }

    if (cmd == kCmdStatus) {
        HostapdStatus st;
        if (ok && parseHostapdStatus(reply, st)) {
            if (active_backend_ == kWifiApBackendNative) {
                if (!st.bssid.empty()) {
                    native_ap_info_.bssid = st.bssid;
                }
                if (st.channel > 0) {
                    native_ap_info_.channel = st.channel;
                }
                if (st.freq > 0) {
                    native_ap_info_.freq_mhz = st.freq;
                    if (native_ap_info_.channel <= 0) {
                        native_ap_info_.channel = frequencyMhzToChannel(st.freq);
                    }
                }
                if (!st.ssid.empty() && native_ap_info_.ssid.empty()) {
                    native_ap_info_.ssid = st.ssid;
                }
            } else {
                if (!st.bssid.empty() && !credentials_.has_bssid) {
                    uint8_t mac_bytes[6];
                    if (parseMacAddressBytes(st.bssid, mac_bytes)) {
                        credentials_.has_bssid = true;
                        memcpy(credentials_.bssid, mac_bytes, 6U);
                    }
                }
            }
            if (st.state == "ENABLED") {
                ctrl_status_ok_ = true;
            }
        }
        return;
    }

    if (cmd == kCmdAllSta) {
        ctrl_probe_pending_ = false;
        if (ok) {
            std::vector<HostapdStationInfo> stations;
            if (parseHostapdAllSta(reply, stations)) {
                for (size_t i = 0U; i < stations.size(); ++i) {
                    addConnectedStation(stations[i].mac);
                    if (!guard.alive()) {
                        return;
                    }
                }
            }
        }

        if (active_backend_ == kWifiApBackendNative) {
            if (state_ == kWifiApStartingWaitCtrl && ctrl_status_ok_) {
                if (!native_creds_ready_) {
                    EvoApInfo read_ap;
                    std::string source;
                    if (apReader()->readAccessPoint(config_.effectiveNativePaths(), read_ap, source,
                                                    NULL)) {
                        native_ap_read_ok_ = true;
                        mergeNativeApInfo(read_ap);
                    }
                }
                maybeCompleteNativeStart();
            }
            return;
        }

        if (state_ == kWifiApStartingWaitCtrl && ctrl_attached_ && ctrl_status_ok_) {
            if (config_.enable_udhcpd) {
                std::string err;
                if (!spawnUdhcpd(&err)) {
                    transitionToFailed(err.empty() ? "failed to start udhcpd" : err);
                    return;
                }
            }
            state_ = kWifiApRunning;
            armTimer(config_.health_check_interval_ms, config_.health_check_interval_ms);
            CARPLAY_LOG_INFO(kTag, "Wi-Fi AP ready on %s (bssid=%s)",
                             config_.interface_name.c_str(),
                             credentials_.has_bssid ? formatMacBytes(credentials_.bssid).c_str()
                                                    : "unknown");

            if (listener_ != NULL) {
                listener_->onWifiApStarted(credentials_);
            }
        }
    }
}

void WifiAp::onHostapdEvent(const HostapdEvent& event) {
    if (state_ != kWifiApStartingWaitCtrl && state_ != kWifiApRunning) {
        return;
    }
    switch (event.type) {
        case kHostapdEventStaConnected:
            if (!event.mac.empty()) {
                addConnectedStation(event.mac);
            }
            break;
        case kHostapdEventStaDisconnected:
            if (!event.mac.empty()) {
                removeConnectedStation(event.mac);
            }
            break;
        case kHostapdEventApEnabled:
            if (state_ == kWifiApStartingWaitCtrl && ctrl()->isOpen() && !ctrl_status_ok_) {
                ctrl()->sendStatus(config_.ctrl_cmd_timeout_ms);
                if (active_backend_ == kWifiApBackendNative && !native_got_get_config_) {
                    ctrl()->sendGetConfig(config_.ctrl_cmd_timeout_ms);
                }
                ctrl()->sendAllSta(config_.ctrl_cmd_timeout_ms);
            }
            break;
        case kHostapdEventTerminating:
            if (active_backend_ == kWifiApBackendNative) {
                transitionToFailed("car-native hostapd terminating");
            } else if (!hostapdProc()->isRunning()) {
                handleUnexpectedHostapdExit("hostapd signaled CTRL-EVENT-TERMINATING");
            }
            break;
        case kHostapdEventApDisabled:
        case kHostapdEventInterfaceDisabled:
            if (active_backend_ == kWifiApBackendNative && state_ == kWifiApRunning) {
                transitionToFailed("car-native Wi-Fi AP disabled");
            }
            break;
        case kHostapdEventUnknown:
            break;
    }
}

void WifiAp::onHostapdCtrlError(const std::string& error) {
    if (state_ != kWifiApStartingWaitCtrl && state_ != kWifiApRunning) {
        return;
    }
    if (active_backend_ == kWifiApBackendNative) {
        ctrl_attached_ = false;
        ctrl_status_ok_ = false;
        ctrl_probe_pending_ = false;
        if (state_ == kWifiApRunning) {
            unsigned mhz = 0U;
            if (!apReader()->readFrequencyMhz(config_.native_interface_name, mhz) || mhz == 0U) {
                transitionToFailed("car-native hostapd control socket closed (" + error + ")");
            }
        }
        return;
    }
    if (!hostapdProc()->isRunning()) {
        handleUnexpectedHostapdExit("hostapd exited (" + error + ")");
        return;
    }
    // Process is still alive; drop back to wait-ctrl so socket reconnects if transient.
    ctrl_attached_ = false;
    ctrl_status_ok_ = false;
    ctrl_probe_pending_ = false;
    if (state_ == kWifiApRunning) {
        state_ = kWifiApStartingWaitCtrl;
        ctrl_wait_deadline_ms_ = nowMs() + static_cast<int64_t>(config_.ctrl_wait_timeout_ms);
        armTimer(config_.ctrl_poll_interval_ms, config_.ctrl_poll_interval_ms);
    }
}

bool WifiAp::isStationConnected(const std::string& mac) const {
    std::string norm;
    if (!normalizeMacAddress(mac, norm)) {
        return false;
    }
    for (size_t i = 0U; i < connected_stations_.size(); ++i) {
        if (connected_stations_[i] == norm) {
            return true;
        }
    }
    return false;
}

void WifiAp::addConnectedStation(const std::string& mac) {
    std::string norm;
    if (!normalizeMacAddress(mac, norm)) {
        return;
    }
    for (size_t i = 0U; i < connected_stations_.size(); ++i) {
        if (connected_stations_[i] == norm) {
            return;
        }
    }
    connected_stations_.push_back(norm);
    CARPLAY_LOG_INFO(kTag, "station connected: %s", norm.c_str());

    AliveGuard guard(alive_state_);
    if (listener_ != NULL) {
        listener_->onStationConnected(norm);
    }
}

void WifiAp::removeConnectedStation(const std::string& mac) {
    std::string norm;
    if (!normalizeMacAddress(mac, norm)) {
        return;
    }
    for (size_t i = 0U; i < connected_stations_.size(); ++i) {
        if (connected_stations_[i] == norm) {
            connected_stations_.erase(connected_stations_.begin() + static_cast<ptrdiff_t>(i));
            CARPLAY_LOG_INFO(kTag, "station disconnected: %s", norm.c_str());

            AliveGuard guard(alive_state_);
            if (listener_ != NULL) {
                listener_->onStationDisconnected(norm);
            }
            return;
        }
    }
}

void WifiAp::clearConnectedStations() {
    std::vector<std::string> removed;
    removed.swap(connected_stations_);
    AliveGuard guard(alive_state_);
    while (!removed.empty()) {
        const std::string mac = removed.back();
        removed.pop_back();
        if (listener_ != NULL) {
            listener_->onStationDisconnected(mac);
        }
        if (!guard.alive()) {
            return;
        }
    }
}

}  // namespace platform
}  // namespace carplay
