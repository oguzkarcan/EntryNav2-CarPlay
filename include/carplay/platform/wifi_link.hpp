// Derived from EntryNav2-Android-Auto 0.12.0 & 0.13.0-rc.6 platform/wifi_link.hpp,
// PolyForm Noncommercial License 1.0.0
//
// Read-only kernel Wi-Fi link, BMW Apps ALPS BT slot 0, & TCP diagnostics:
//   * nl80211 generic netlink: connected station stats (signal, rx bitrate, frame counters) and
//     AP operating frequency (`NL80211_CMD_GET_STATION`, `NL80211_CMD_GET_INTERFACE`).
//   * TCP_INFO on an active TCP socket: smoothed RTT and total retransmits.
//   * Optional read-only BMW Apps (slot 0) Bluetooth probe sharing the WL18xx coex chip.
// No addresses/credentials are written to logs.

#ifndef CARPLAY_PLATFORM_WIFI_LINK_HPP
#define CARPLAY_PLATFORM_WIFI_LINK_HPP

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/platform/thread.hpp"

namespace carplay {
namespace platform {

class SppSnapshotReader;

static const int64_t kNoFigure = -0x7fffffffffffffffLL - 1;  // figure not reported by driver

/// Read-only status of the ALPS BMW Apps Bluetooth link (slot 0, My BMW / AAIdrive) that
/// shares the WL18xx chip with Wi-Fi (upstream #71, #111).
struct AppsSlot {
    bool read;
    bool connected;
    uint32_t state;
    uint8_t transport;

    AppsSlot() : read(false), connected(false), state(0U), transport(0U) {}
};

/// Queries slot 0 (`kAlpsBmwAppsSlot`) on an already-open `SppSnapshotReader` (read-only).
bool readBmwAppsSlot(SppSnapshotReader& reader, AppsSlot& out);

/// One station entry on the access point as reported by nl80211.
struct WifiStation {
    uint8_t mac[6];
    int64_t signal_dbm;
    int64_t signal_avg_dbm;
    int64_t tx_rate;                            // in 100 kbit/s
    int64_t rx_rate;                            // in 100 kbit/s
    int64_t tx_frames;                          // since station joined
    int64_t tx_retries;                         // since station joined
    int64_t tx_failed;                          // since station joined
    int64_t connected_s;                        // seconds since association

    WifiStation();
};

/// Pure parser for the netlink attribute payload following `genlmsghdr` in an nl80211
/// `NL80211_CMD_NEW_STATION` message. Returns false if no 6-byte `NL80211_ATTR_MAC` is present.
bool parseWifiStation(const uint8_t* attrs, size_t len, WifiStation& out);

/// Pure parser for `NL80211_ATTR_WIPHY_FREQ` (in MHz) from `NL80211_CMD_NEW_INTERFACE` attributes.
bool parseWifiFrequency(const uint8_t* attrs, size_t len, unsigned& mhz_out);

/// Queries nl80211 for all stations currently associated with `interface_name` (POSIX/Linux only).
bool readWifiStations(const char* interface_name, std::vector<WifiStation>& out);

/// Queries nl80211 for the operating frequency (MHz) of `interface_name` (POSIX/Linux only).
bool readWifiFrequency(const char* interface_name, unsigned& mhz_out);

struct TcpLink {
    uint32_t round_trip_us;
    uint32_t resent;  // segments retransmitted since socket opened

    TcpLink() : round_trip_us(0U), resent(0U) {}
};

/// Reads TCP_INFO from a connected TCP socket. False on non-TCP sockets (e.g. AF_UNIX / -1).
bool readTcpLink(int fd, TcpLink& out);

struct WifiSample {
    uint32_t at_ms;
    bool radio;         // true when nl80211 answered
    unsigned mhz;       // 0 if unknown
    unsigned stations;  // total stations reported on the AP
    bool has_station;   // true if the target station was matched
    WifiStation station;
    bool has_tcp;
    TcpLink tcp;
    AppsSlot apps;

    WifiSample();
};

/// Formats one diagnostic summary line; `before` provides delta baseline for the same link.
std::string describeWifiLink(const WifiSample& now, const WifiSample* before);

/// Periodic Wi-Fi/TCP link logger that holds a duplicated CLOEXEC copy of the session socket
/// until the session stops (or `kStartGraceMs` elapses without an active session).
class WifiLinkLog {
public:
    typedef bool (*AppsProbe)(void* user, AppsSlot& out);

    WifiLinkLog();
    ~WifiLinkLog();

    void enable(const char* interface_name);
    void setAppsProbe(AppsProbe probe, void* user);
    void connected(int fd);
    void turn(uint32_t now_ms, bool session_active);

private:
    WifiLinkLog(const WifiLinkLog&) = delete;
    WifiLinkLog& operator=(const WifiLinkLog&) = delete;

    void sample(uint32_t now_ms);
    void forget();

    Mutex lock_;
    std::string interface_;
    int fd_;
    bool first_;
    AppsProbe apps_probe_;
    void* apps_user_;
    bool seen_active_;
    bool has_before_;
    bool radio_gone_;
    uint32_t next_ms_;
    uint32_t since_ms_;
    unsigned radio_failures_;
    WifiSample before_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_WIFI_LINK_HPP
