// Derived from EntryNav2-Android-Auto 0.12.0 platform/evo_ap.hpp, platform/evo_ap.cpp,
// platform/evo_ap_config.cpp, PolyForm Noncommercial License 1.0.0
//
// Reads the BMW HU_ENTRYNAV2 car-native Wi-Fi access point configuration (managed by BMW's
// `wland` + `hostapd` on `wlan0`) and converts it into `WifiCredentials` for iAP2 0x5703
// (`AccessoryWiFiConfigurationInformation`). Never logs passphrases.

#ifndef CARPLAY_PLATFORM_EVO_AP_HPP
#define CARPLAY_PLATFORM_EVO_AP_HPP

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

namespace carplay {
namespace platform {

struct WifiCredentials;

// Verified: EntryNav2-Android-Auto-0.12.0/platform/evo_ap.cpp
static const char kNativeWlanInterface[] = "wlan0";
static const char kNativeHostapdCtrlDir[] = "/var/run/hostapd";
static const char kNativeApConfPath[] = "/tmp/wland/ap.conf";
static const char kNativeHostapdCliBin[] = "/usr/sbin/hostapd_cli";

struct NativeWlanPaths {
    std::string interface_name;
    std::string hostapd_ctrl_dir;
    std::string ap_conf_path;
    std::string hostapd_cli_bin;
    int cli_timeout_ms;

    NativeWlanPaths();

    std::string ctrlSocketPath() const;
};

struct EvoApInfo {
    std::string ssid;
    std::string passphrase;
    std::string bssid;  // normalized lowercase aa:bb:cc:dd:ee:ff when known
    std::string ip;     // optional IPv4 address if assigned on interface
    int channel;        // 0 if unknown
    int freq_mhz;       // 0 if unknown
    std::string key_mgmt;
    std::string wpa;
    uint8_t security_type;  // defaults to kIap2WifiSecurityWpa2 (2 = WPA/WPA2-PSK)

    EvoApInfo();

    /// Converts parsed AP info into `WifiCredentials` for iAP2 0x5703.
    /// Fails if SSID, passphrase, or channel (including fallback_channel if > 0) is invalid.
    bool toWifiCredentials(WifiCredentials& out,
                           uint8_t fallback_channel = 0U,
                           std::string* error_out = NULL) const;
};

/// Pure IEEE 802.11 frequency <-> channel conversions (2.4 GHz 1..14, 5 GHz UNII channels).
/// Returns 0 if unmapped.
int frequencyMhzToChannel(int freq_mhz);
int channelToFrequencyMhz(uint8_t channel);

/// Pure parser for `hostapd_cli get_config` / `HostapdCtrl GET_CONFIG` / `/tmp/wland/ap.conf`.
/// Validates SSID (1..32 bytes), WPA2/3 PSK passphrase (8..63 printable ASCII), key_mgmt, and wpa.
/// Never logs credentials.
bool parseHostapdConfig(const std::string& text, EvoApInfo& out);

/// Abstract reader interface so WifiAp's native-AP backend can be unit-tested with fakes.
class IAccessPointReader {
public:
    virtual ~IAccessPointReader() {}

    /// True if car-native WLAN artifacts (`/var/run/hostapd/wlan0`, `/tmp/wland/ap.conf`, or
    /// `vmostd` + native wireless interface) indicate BMW's WLAN stack manages Wi-Fi here.
    virtual bool isNativeEnvironmentPresent(const NativeWlanPaths& paths) const = 0;

    /// Reads AP SSID/passphrase/BSSID/channel via `hostapd_cli get_config`, falling back to
    /// `ap.conf`, plus interface MAC/IPv4/frequency queries. `ip` is optional for CarPlay (IPv6).
    virtual bool readAccessPoint(const NativeWlanPaths& paths,
                                 EvoApInfo& out,
                                 std::string& source_out,
                                 std::string* error_out = NULL) = 0;

    /// Reads current operating frequency in MHz (e.g. via nl80211).
    virtual bool readFrequencyMhz(const std::string& interface_name, unsigned& mhz_out) = 0;

    /// Reads normalized lowercase MAC addresses of associated stations (e.g. via nl80211).
    virtual bool readConnectedStations(const std::string& interface_name,
                                       std::vector<std::string>& macs_out) = 0;
};

/// Production implementation using evo_process::runCommand, readFileBounded, ioctls, and nl80211.
class EvoAccessPointReader : public IAccessPointReader {
public:
    virtual bool isNativeEnvironmentPresent(const NativeWlanPaths& paths) const;
    virtual bool readAccessPoint(const NativeWlanPaths& paths,
                                 EvoApInfo& out,
                                 std::string& source_out,
                                 std::string* error_out = NULL);
    virtual bool readFrequencyMhz(const std::string& interface_name, unsigned& mhz_out);
    virtual bool readConnectedStations(const std::string& interface_name,
                                       std::vector<std::string>& macs_out);
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_EVO_AP_HPP
