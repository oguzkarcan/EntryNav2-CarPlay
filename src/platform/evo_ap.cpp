// Derived from EntryNav2-Android-Auto 0.12.0 platform/evo_ap.cpp and
// platform/evo_ap_config.cpp, PolyForm Noncommercial License 1.0.0

#include "carplay/platform/evo_ap.hpp"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sstream>

#include "carplay/platform/evo_process.hpp"
#include "carplay/platform/file_util.hpp"
#include "carplay/platform/hostapd_ctrl.hpp"
#include "carplay/platform/vmost_client.hpp"
#include "carplay/platform/wifi_ap.hpp"
#include "carplay/platform/wifi_link.hpp"

#ifndef _WIN32
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace carplay {
namespace platform {

namespace {

const size_t kMaxApConfigBytes = 65536U;

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

bool parsePositiveInt(const std::string& s, int& out) {
    if (s.empty() || s[0] == '-') {
        return false;
    }
    char* end = NULL;
    errno = 0;
    const long v = strtol(s.c_str(), &end, 10);
    if (errno != 0 || end == NULL || *end != '\0' || v <= 0L || v > 2147483647L) {
        return false;
    }
    out = static_cast<int>(v);
    return true;
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

std::string formatMacLower(const uint8_t mac[6]) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             static_cast<unsigned int>(mac[0]), static_cast<unsigned int>(mac[1]),
             static_cast<unsigned int>(mac[2]), static_cast<unsigned int>(mac[3]),
             static_cast<unsigned int>(mac[4]), static_cast<unsigned int>(mac[5]));
    return std::string(buf);
}

bool queryHostapdCli(const NativeWlanPaths& paths, std::string& out) {
    if (paths.hostapd_cli_bin.empty() || paths.hostapd_ctrl_dir.empty() ||
        paths.interface_name.empty()) {
        return false;
    }
    std::vector<std::string> args;
    args.push_back("-p");
    args.push_back(paths.hostapd_ctrl_dir);
    args.push_back("-i");
    args.push_back(paths.interface_name);
    args.push_back("get_config");
    return runCommand(paths.hostapd_cli_bin, args, out, paths.cli_timeout_ms);
}

bool readInterfaceAddrs(const std::string& interface_name,
                        std::string& bssid_in_out,
                        std::string& ip_out) {
#ifdef _WIN32
    (void)interface_name;
    (void)bssid_in_out;
    ip_out.clear();
    return false;
#else
    if (interface_name.empty() || interface_name.size() >= IFNAMSIZ) {
        return false;
    }
    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return false;
    }

    ifreq request;
    memset(&request, 0, sizeof(request));
    strncpy(request.ifr_name, interface_name.c_str(), sizeof(request.ifr_name) - 1U);

    if (ioctl(fd, SIOCGIFADDR, &request) == 0) {
        char ip_buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(&request.ifr_addr)->sin_addr,
                      ip_buf, sizeof(ip_buf)) != NULL) {
            ip_out = ip_buf;
        }
    }

    if (bssid_in_out.empty()) {
        memset(&request, 0, sizeof(request));
        strncpy(request.ifr_name, interface_name.c_str(), sizeof(request.ifr_name) - 1U);
        if (ioctl(fd, SIOCGIFHWADDR, &request) == 0) {
            const uint8_t* b = reinterpret_cast<const uint8_t*>(request.ifr_hwaddr.sa_data);
            bssid_in_out = formatMacLower(b);
        }
    }
    close(fd);

    if (bssid_in_out.empty()) {
        const std::string sysfs = "/sys/class/net/" + interface_name + "/address";
        std::vector<uint8_t> raw;
        if (readFileBounded(sysfs, 64U, raw) == kFileReadOk) {
            std::string norm;
            if (normalizeMacAddress(std::string(raw.begin(), raw.end()), norm)) {
                bssid_in_out = norm;
            }
        }
    }
    return true;
#endif
}

}  // namespace

NativeWlanPaths::NativeWlanPaths()
    : interface_name(kNativeWlanInterface),
      hostapd_ctrl_dir(kNativeHostapdCtrlDir),
      ap_conf_path(kNativeApConfPath),
      hostapd_cli_bin(kNativeHostapdCliBin),
      cli_timeout_ms(1000) {}

std::string NativeWlanPaths::ctrlSocketPath() const {
    return joinPath(hostapd_ctrl_dir, interface_name);
}

EvoApInfo::EvoApInfo()
    : channel(0), freq_mhz(0), security_type(kIap2WifiSecurityWpa2) {}

bool EvoApInfo::toWifiCredentials(WifiCredentials& out,
                                  uint8_t fallback_channel,
                                  std::string* error_out) const {
    if (ssid.empty() || ssid.size() > 32U || hasControlChars(ssid)) {
        setError(error_out, "invalid native AP SSID");
        return false;
    }
    if (passphrase.size() < 8U || passphrase.size() > 63U) {
        setError(error_out, "invalid native AP passphrase");
        return false;
    }
    for (size_t i = 0U; i < passphrase.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(passphrase[i]);
        if (c < 0x20U || c > 0x7eU) {
            setError(error_out, "native AP passphrase contains non-ASCII characters");
            return false;
        }
    }

    int ch = channel;
    if (ch <= 0 && freq_mhz > 0) {
        ch = frequencyMhzToChannel(freq_mhz);
    }
    if (ch <= 0 && fallback_channel > 0U) {
        ch = static_cast<int>(fallback_channel);
    }
    if (ch <= 0 || ch > 255 ||
        (!isValid24GHzChannel(static_cast<uint8_t>(ch)) &&
         !isValid5GHzChannel(static_cast<uint8_t>(ch)))) {
        setError(error_out, "car-native AP channel could not be determined");
        return false;
    }

    WifiCredentials creds;
    creds.ssid = ssid;
    creds.passphrase = passphrase;
    creds.channel = static_cast<uint8_t>(ch);
    creds.security_type = security_type != 0U ? security_type : kIap2WifiSecurityWpa2;
    creds.has_bssid = false;
    if (!bssid.empty()) {
        uint8_t mac[6];
        if (!parseMacAddressBytes(bssid, mac)) {
            setError(error_out, "invalid native AP BSSID");
            return false;
        }
        creds.has_bssid = true;
        memcpy(creds.bssid, mac, 6U);
    }

    out = creds;
    return true;
}

int frequencyMhzToChannel(int freq_mhz) {
    if (freq_mhz == 2484) {
        return 14;
    }
    if (freq_mhz >= 2412 && freq_mhz <= 2472 && ((freq_mhz - 2407) % 5) == 0) {
        return (freq_mhz - 2407) / 5;
    }
    if (freq_mhz >= 5180 && freq_mhz <= 5825 && ((freq_mhz - 5000) % 5) == 0) {
        const int ch = (freq_mhz - 5000) / 5;
        if (ch > 0 && ch <= 255 && isValid5GHzChannel(static_cast<uint8_t>(ch))) {
            return ch;
        }
    }
    return 0;
}

int channelToFrequencyMhz(uint8_t channel) {
    if (channel == 14U) {
        return 2484;
    }
    if (isValid24GHzChannel(channel)) {
        return 2407 + static_cast<int>(channel) * 5;
    }
    if (isValid5GHzChannel(channel)) {
        return 5000 + static_cast<int>(channel) * 5;
    }
    return 0;
}

bool parseHostapdConfig(const std::string& text, EvoApInfo& out) {
    if (text.size() > kMaxApConfigBytes || text.find('\0') != std::string::npos) {
        return false;
    }

    EvoApInfo ap;
    std::string line;
    std::istringstream in(text);
    while (std::getline(in, line)) {
        if (!line.empty() && line[line.size() - 1U] == '\r') {
            line.erase(line.size() - 1U);
        }
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        const size_t eq = line.find('=');
        if (eq == std::string::npos || eq == 0U) {
            continue;
        }
        const std::string name = line.substr(0U, eq);
        const std::string value = line.substr(eq + 1U);

        if (name == "ssid") {
            ap.ssid = value;
        } else if (name == "passphrase" || name == "wpa_passphrase") {
            ap.passphrase = value;
        } else if (name == "bssid") {
            std::string norm;
            ap.bssid = normalizeMacAddress(value, norm) ? norm : value;
        } else if (name == "key_mgmt" || name == "wpa_key_mgmt") {
            ap.key_mgmt = value;
        } else if (name == "wpa") {
            ap.wpa = value;
        } else if (name == "channel") {
            int ch = 0;
            if (parsePositiveInt(value, ch) && ch <= 255) {
                ap.channel = ch;
            }
        } else if (name == "freq") {
            int f = 0;
            if (parsePositiveInt(value, f)) {
                ap.freq_mhz = f;
            }
        }
    }

    // A raw 64-hex PSK cannot be advertised in iAP2 AccessoryWiFiConfigurationInformation.
    if (ap.ssid.empty() || ap.ssid.size() > 32U || hasControlChars(ap.ssid) ||
        ap.passphrase.size() < 8U || ap.passphrase.size() > 63U) {
        return false;
    }
    if (!ap.wpa.empty() && ap.wpa != "2" && ap.wpa != "3") {
        return false;
    }
    if (!ap.key_mgmt.empty() && ap.key_mgmt != "WPA-PSK") {
        return false;
    }
    for (size_t i = 0U; i < ap.passphrase.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(ap.passphrase[i]);
        if (c < 0x20U || c > 0x7eU) {
            return false;
        }
    }

    if (ap.channel == 0 && ap.freq_mhz > 0) {
        ap.channel = frequencyMhzToChannel(ap.freq_mhz);
    } else if (ap.freq_mhz == 0 && ap.channel > 0 && ap.channel <= 255) {
        ap.freq_mhz = channelToFrequencyMhz(static_cast<uint8_t>(ap.channel));
    }

    out = ap;
    return true;
}

bool EvoAccessPointReader::isNativeEnvironmentPresent(const NativeWlanPaths& paths) const {
    if (!paths.ctrlSocketPath().empty() && pathExists(paths.ctrlSocketPath())) {
        return true;
    }
    if (!paths.ap_conf_path.empty() && pathExists(paths.ap_conf_path)) {
        return true;
    }
    if (isVmostDaemonPresent() && !paths.interface_name.empty()) {
#ifndef _WIN32
        if (if_nametoindex(paths.interface_name.c_str()) != 0U) {
            return true;
        }
#endif
        if (!paths.hostapd_cli_bin.empty() && pathExists(paths.hostapd_cli_bin)) {
            return true;
        }
    }
    return false;
}

bool EvoAccessPointReader::readAccessPoint(const NativeWlanPaths& paths,
                                           EvoApInfo& out,
                                           std::string& source_out,
                                           std::string* error_out) {
    EvoApInfo ap;
    std::string text;
    if (queryHostapdCli(paths, text) && parseHostapdConfig(text, ap)) {
        source_out = "hostapd_cli/" + paths.interface_name;
    } else {
        std::vector<uint8_t> raw;
        if (paths.ap_conf_path.empty() ||
            readFileBounded(paths.ap_conf_path, kMaxApConfigBytes, raw) != kFileReadOk) {
            setError(error_out, "unable to read car-native AP config from hostapd_cli or " +
                                    paths.ap_conf_path);
            return false;
        }
        text.assign(raw.begin(), raw.end());
        if (!parseHostapdConfig(text, ap)) {
            setError(error_out, "invalid or unsupported car-native AP config in " +
                                    paths.ap_conf_path);
            return false;
        }
        source_out = paths.ap_conf_path;
    }

    if (!readInterfaceAddrs(paths.interface_name, ap.bssid, ap.ip)) {
        setError(error_out, "failed to inspect interface " + paths.interface_name);
        return false;
    }
    if (!ap.bssid.empty()) {
        std::string norm;
        if (!normalizeMacAddress(ap.bssid, norm)) {
            setError(error_out, "invalid BSSID on " + paths.interface_name);
            return false;
        }
        ap.bssid = norm;
    }
    if (ap.channel == 0) {
        unsigned mhz = 0U;
        if (readFrequencyMhz(paths.interface_name, mhz) && mhz > 0U) {
            ap.freq_mhz = static_cast<int>(mhz);
            ap.channel = frequencyMhzToChannel(ap.freq_mhz);
        }
    }

    out = ap;
    return true;
}

bool EvoAccessPointReader::readFrequencyMhz(const std::string& interface_name,
                                            unsigned& mhz_out) {
    return readWifiFrequency(interface_name.c_str(), mhz_out);
}

bool EvoAccessPointReader::readConnectedStations(const std::string& interface_name,
                                                 std::vector<std::string>& macs_out) {
    macs_out.clear();
    std::vector<WifiStation> stations;
    if (!readWifiStations(interface_name.c_str(), stations)) {
        return false;
    }
    for (size_t i = 0U; i < stations.size(); ++i) {
        macs_out.push_back(formatMacLower(stations[i].mac));
    }
    return true;
}

}  // namespace platform
}  // namespace carplay
