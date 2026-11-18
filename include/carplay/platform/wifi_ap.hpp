#ifndef CARPLAY_PLATFORM_WIFI_AP_HPP
#define CARPLAY_PLATFORM_WIFI_AP_HPP

// Wireless CarPlay Wi-Fi Access Point (hostapd + optional udhcpd) configuration, credential
// generation, and Reactor-driven orchestrator.
//
// Design constraints:
//   * NEVER reads or modifies `/etc/hostapd.conf`. Writes its own isolated config under
//     `runtime_dir` (default `/var/run/carplay/hostapd-carplay.conf`, mode 0600 inside 0700 dir).
//   * Uses `pairing::RandomSource` (`OsRandomSource` in production) for random SSID suffix and
//     WPA2-PSK passphrase generation; NEVER logs passphrases.
//   * Spawns `hostapd` (and optional `udhcpd -f`) via `IChildProcess` (`SupervisedProcess` by
//     default; no shell, `posix_spawnp`, SIGTERM->SIGKILL escalation, waitpid reaping).
//   * Integrates with `HostapdCtrl` over `Reactor` to detect readiness, track station
//     connect/disconnect events, and supervise/restart `hostapd` on unexpected exit.
//   * CarPlay primarily communicates over IPv6 link-local (`fe80::/64`) + mDNS; `udhcpd` IPv4
//     subnet support is optional (`enable_udhcpd`, disabled by default).

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/iap2_wire.hpp"
#include "carplay/pairing.hpp"
#include "carplay/platform/evo_supervisor.hpp"
#include "carplay/platform/hostapd_ctrl.hpp"
#include "carplay/platform/reactor.hpp"

namespace carplay {
namespace platform {

/// iAP2 AccessoryWiFiConfigurationInformation (0x5703) WiFiSecurityType for WPA2-PSK.
/// Matches `tests/test_phase1.cpp` (lines 482, 534); other enum values are unverified on vehicle.
static const uint8_t kIap2WifiSecurityWpa2 = 3U;

enum WifiBand {
    kWifiBandAuto = 0,
    kWifiBand24GHz = 1,
    kWifiBand5GHz = 2
};

struct WifiApConfig {
    /// Target wireless interface. Assumption: TI wl18xx on HU_ENTRYNAV2 exposes `wlan0` and
    /// `wlan1`; `wlan1` is used as the default CarPlay AP interface (unverified on vehicle).
    std::string interface_name;
    std::string runtime_dir;
    /// Empty -> `<runtime_dir>/hostapd-carplay.conf`. Must never be `/etc/hostapd.conf`.
    std::string hostapd_conf_path;
    /// Empty -> `<runtime_dir>/hostapd_ctrl`.
    std::string ctrl_interface_dir;
    std::string ctrl_interface_group;

    std::string ssid_prefix;
    /// Empty -> generated as `<ssid_prefix><random hex>` via RandomSource (<= 32 bytes).
    std::string ssid;
    /// Empty -> generated as random alphanumeric passphrase via RandomSource (8..63 bytes).
    std::string passphrase;
    size_t random_ssid_suffix_hex_chars;
    size_t random_passphrase_length;

    WifiBand band;
    uint8_t channel;
    std::string country_code;
    bool ieee80211n;
    int max_num_sta;
    bool ap_isolate;
    /// Optional 6-byte BSSID override; if empty, WifiAp reads sysfs / hostapd STATUS `bssid[0]`.
    std::vector<uint8_t> bssid;

    std::string hostapd_bin;
    std::string hostapd_log_path;

    /// Optional IPv4 DHCP server (`udhcpd -f`). CarPlay uses IPv6 link-local by default.
    bool enable_udhcpd;
    std::string udhcpd_bin;
    std::string udhcpd_conf_path;   // empty -> `<runtime_dir>/udhcpd-carplay.conf`
    std::string udhcpd_lease_file;  // empty -> `<runtime_dir>/udhcpd-carplay.leases`
    std::string udhcpd_log_path;
    std::string dhcp_start_ipv4;
    std::string dhcp_end_ipv4;
    std::string dhcp_subnet_mask;
    uint32_t dhcp_lease_sec;

    /// Supervision & Reactor timings.
    int ctrl_poll_interval_ms;
    int ctrl_wait_timeout_ms;
    int ctrl_cmd_timeout_ms;
    int health_check_interval_ms;
    bool auto_restart;
    int max_restarts;
    int restart_backoff_ms;
    int stop_term_timeout_ms;
    int stop_kill_timeout_ms;
    bool cleanup_files_on_stop;

    WifiApConfig();

    std::string effectiveHostapdConfPath() const;
    std::string effectiveCtrlInterfaceDir() const;
    std::string effectiveRemoteCtrlSocketPath() const;
    std::string effectiveUdhcpdConfPath() const;
    std::string effectiveUdhcpdLeaseFile() const;
};

struct WifiCredentials {
    std::string ssid;
    std::string passphrase;
    uint8_t channel;
    uint8_t security_type;
    bool has_bssid;
    uint8_t bssid[6];

    WifiCredentials();

    std::vector<uint8_t> bssidVector() const;
};

/// Pure channel / band helpers.
bool isValid24GHzChannel(uint8_t channel);
bool isValid5GHzChannel(uint8_t channel);
bool resolveWifiBandAndHwMode(WifiBand band,
                              uint8_t channel,
                              char& hw_mode_out,
                              std::string* error_out = NULL);

/// Pure validation of WifiApConfig (interface, paths, country code, channel/band, fixed SSID/PSK).
bool validateWifiApConfig(const WifiApConfig& cfg, std::string* error_out = NULL);

/// Generates runtime credentials from `cfg` + `rng` matching `iap2::buildAccessoryWiFiConfiguration`.
bool generateWifiCredentials(const WifiApConfig& cfg,
                             pairing::RandomSource& rng,
                             WifiCredentials& out,
                             std::string* error_out = NULL);

/// Generates our isolated WPA2-PSK CCMP `hostapd` config file text.
bool generateHostapdConfig(const WifiApConfig& cfg,
                           const WifiCredentials& creds,
                           std::string& out,
                           std::string* error_out = NULL);

/// Generates BusyBox `udhcpd` config text (intentionally omits router/DNS options).
bool generateUdhcpdConfig(const WifiApConfig& cfg,
                          std::string& out,
                          std::string* error_out = NULL);

/// Convenience wrapper over `iap2::buildAccessoryWiFiConfiguration` (0x5703).
bool buildAccessoryWiFiConfigFrame(const WifiCredentials& creds,
                                   iap2::Frame& frame_out,
                                   std::string* error_out = NULL);

enum WifiApState {
    kWifiApStopped = 0,
    kWifiApStartingWaitCtrl = 1,
    kWifiApRunning = 2,
    kWifiApRestarting = 3,
    kWifiApStopping = 4,
    kWifiApFailed = 5
};

const char* wifiApStateName(WifiApState state);

class WifiApListener {
public:
    virtual ~WifiApListener() {}
    virtual void onWifiApStarted(const WifiCredentials& creds) = 0;
    virtual void onWifiApStopped() = 0;
    virtual void onWifiApRestarting(int attempt, const std::string& reason) = 0;
    virtual void onWifiApFailed(const std::string& reason) = 0;
    virtual void onStationConnected(const std::string& mac) = 0;
    virtual void onStationDisconnected(const std::string& mac) = 0;
};

class WifiAp : private TimerHandler, private HostapdCtrlListener {
public:
    WifiAp(Reactor& reactor, pairing::RandomSource& rng);
    virtual ~WifiAp();

    void setListener(WifiApListener* listener) { listener_ = listener; }

    /// Test injection hooks (must be called while kWifiApStopped / kWifiApFailed; caller retains
    /// ownership; NULL restores the default owned implementation).
    void setHostapdProcessForTest(IChildProcess* proc);
    void setUdhcpdProcessForTest(IChildProcess* proc);
    void setHostapdCtrlForTest(IHostapdCtrl* ctrl);

    bool start(const WifiApConfig& cfg, std::string* error_out = NULL);
    void stop();
    void stopSync();

    WifiApState state() const { return state_; }
    const WifiApConfig& config() const { return config_; }
    const WifiCredentials& credentials() const { return credentials_; }
    const std::string& lastError() const { return last_error_; }
    int restartCount() const { return restart_count_; }
    const std::vector<std::string>& connectedStations() const { return connected_stations_; }
    bool isStationConnected(const std::string& mac) const;

private:
    WifiAp(const WifiAp&) = delete;
    WifiAp& operator=(const WifiAp&) = delete;

    virtual void onTimer(uint32_t timer_id);
    virtual void onHostapdCommandReply(HostapdCommandKind cmd,
                                       bool ok,
                                       const std::string& reply);
    virtual void onHostapdEvent(const HostapdEvent& event);
    virtual void onHostapdCtrlError(const std::string& error);

    IChildProcess* hostapdProc();
    IChildProcess* udhcpdProc();
    IHostapdCtrl* ctrl();

    bool prepareRuntimeFiles(std::string* error_out);
    void cleanupRuntimeFiles();
    bool spawnHostapd(std::string* error_out);
    bool spawnUdhcpd(std::string* error_out);
    void tryOpenAndProbeCtrl();
    void handleUnexpectedHostapdExit(const std::string& reason);
    void transitionToFailed(const std::string& reason);
    void finishStop();
    void clearConnectedStations();
    void addConnectedStation(const std::string& mac);
    void removeConnectedStation(const std::string& mac);
    void cancelTimer();
    void armTimer(int delay_ms, int period_ms);
    int64_t nowMs() const;

    Reactor& reactor_;
    pairing::RandomSource& rng_;
    WifiApListener* listener_;

    SupervisedProcess default_hostapd_proc_;
    SupervisedProcess default_udhcpd_proc_;
    HostapdCtrl default_ctrl_;
    IChildProcess* hostapd_proc_override_;
    IChildProcess* udhcpd_proc_override_;
    IHostapdCtrl* ctrl_override_;

    WifiApConfig config_;
    WifiCredentials credentials_;
    WifiApState state_;
    std::string last_error_;
    int restart_count_;
    std::vector<std::string> connected_stations_;

    struct AliveState {
        int refs;
        bool alive;
        AliveState() : refs(1), alive(true) {}
    };

    struct AliveGuard {
        AliveState* state;
        explicit AliveGuard(AliveState* s) : state(s) {
            if (state != NULL) {
                ++state->refs;
            }
        }
        ~AliveGuard() {
            if (state != NULL && --state->refs == 0) {
                delete state;
            }
        }
        bool alive() const { return state != NULL && state->alive; }
    };

    uint32_t timer_id_;
    int64_t ctrl_wait_deadline_ms_;
    int64_t stop_term_deadline_ms_;
    int64_t stop_kill_deadline_ms_;
    bool stop_kill_sent_;
    bool ctrl_attached_;
    bool ctrl_status_ok_;
    bool ctrl_probe_pending_;
    AliveState* alive_state_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_WIFI_AP_HPP
