// Derived from EntryNav2-Android-Auto 0.12.0 & 0.13.0-rc.6 platform/wifi_link.cpp,
// PolyForm Noncommercial License 1.0.0

#include "carplay/platform/wifi_link.hpp"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "carplay/platform/log.hpp"
#include "carplay/platform/spp_snapshot.hpp"

#ifndef _WIN32
#include <fcntl.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#else
// Pure-parser constants matching Linux uapi/linux/netlink.h & uapi/linux/nl80211.h for host tests.
struct carplay_nlattr {
    uint16_t nla_len;
    uint16_t nla_type;
};
#define nlattr carplay_nlattr
#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK (~0xC000)
#endif
enum {
    NL80211_ATTR_MAC = 6,
    NL80211_ATTR_STA_INFO = 21,
    NL80211_ATTR_WIPHY_FREQ = 38
};
enum {
    NL80211_STA_INFO_SIGNAL = 7,
    NL80211_STA_INFO_TX_BITRATE = 8,
    NL80211_STA_INFO_TX_PACKETS = 10,
    NL80211_STA_INFO_TX_RETRIES = 11,
    NL80211_STA_INFO_TX_FAILED = 12,
    NL80211_STA_INFO_SIGNAL_AVG = 13,
    NL80211_STA_INFO_RX_BITRATE = 14,
    NL80211_STA_INFO_CONNECTED_TIME = 16
};
enum {
    NL80211_RATE_INFO_BITRATE = 1
};
#endif

namespace carplay {
namespace platform {

namespace {

const char* const kTag = "wifi-link";
const uint32_t kPeriodMs = 10000U;
const uint32_t kStartGraceMs = 5000U;
const unsigned kRadioTries = 3U;
#ifndef _WIN32
const long kAnswerUs = 200000L;
#endif

size_t align4(size_t n) {
    return (n + 3U) & ~static_cast<size_t>(3U);
}

struct Attr {
    unsigned type;
    const uint8_t* data;
    size_t len;
};

bool nextAttr(const uint8_t*& p, size_t& left, Attr& a) {
    if (p == NULL || left < sizeof(nlattr)) {
        return false;
    }
    nlattr header;
    memcpy(&header, p, sizeof(header));
    if (header.nla_len < sizeof(header) || header.nla_len > left) {
        return false;
    }
    a.type = static_cast<unsigned>(header.nla_type & NLA_TYPE_MASK);
    a.data = p + sizeof(header);
    a.len = header.nla_len - sizeof(header);
    const size_t step = align4(header.nla_len) > left ? left : align4(header.nla_len);
    p += step;
    left -= step;
    return true;
}

int64_t readUnsignedNumber(const Attr& a) {
    if (a.len == 1U) {
        return a.data[0];
    }
    if (a.len == 2U) {
        uint16_t v = 0U;
        memcpy(&v, a.data, sizeof(v));
        return static_cast<int64_t>(v);
    }
    if (a.len == 4U) {
        uint32_t v = 0U;
        memcpy(&v, a.data, sizeof(v));
        return static_cast<int64_t>(v);
    }
    return kNoFigure;
}

int64_t readSignalDbm(const Attr& a) {
    if (a.len != 1U) {
        return kNoFigure;
    }
    // WL18xx leaves NL80211_STA_INFO_SIGNAL as 0 when the last packet was not measured (#80).
    const int64_t dbm = static_cast<int8_t>(a.data[0]);
    return dbm < 0 ? dbm : kNoFigure;
}

int64_t readBitrate(const Attr& nested) {
    const uint8_t* p = nested.data;
    size_t left = nested.len;
    Attr a;
    while (nextAttr(p, left, a)) {
        if (a.type == NL80211_RATE_INFO_BITRATE && a.len == 2U) {
            return readUnsignedNumber(a);
        }
    }
    return kNoFigure;
}

void parseStationInfo(const Attr& nested, WifiStation& out) {
    const uint8_t* p = nested.data;
    size_t left = nested.len;
    Attr a;
    while (nextAttr(p, left, a)) {
        switch (a.type) {
            case NL80211_STA_INFO_SIGNAL:
                out.signal_dbm = readSignalDbm(a);
                break;
            case NL80211_STA_INFO_SIGNAL_AVG:
                out.signal_avg_dbm = readSignalDbm(a);
                break;
            // NL80211_STA_INFO_TX_BITRATE omitted: wlcore firmware always reports 1.0 Mbit/s (#80).
            case NL80211_STA_INFO_RX_BITRATE:
                out.rx_rate = readBitrate(a);
                break;
            case NL80211_STA_INFO_TX_PACKETS:
                out.tx_frames = a.len == 4U ? readUnsignedNumber(a) : kNoFigure;
                break;
            case NL80211_STA_INFO_TX_RETRIES:
                out.tx_retries = a.len == 4U ? readUnsignedNumber(a) : kNoFigure;
                break;
            case NL80211_STA_INFO_TX_FAILED:
                out.tx_failed = a.len == 4U ? readUnsignedNumber(a) : kNoFigure;
                break;
            case NL80211_STA_INFO_CONNECTED_TIME:
                out.connected_s = a.len == 4U ? readUnsignedNumber(a) : kNoFigure;
                break;
            default:
                break;
        }
    }
}

#ifndef _WIN32
class Nl80211 {
public:
    Nl80211() : fd_(-1), family_(0U), interface_(0U), sequence_(0U) {}
    ~Nl80211() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }

    bool open(const char* interface_name) {
        if (interface_name == NULL || interface_name[0] == '\0') {
            return false;
        }
        interface_ = if_nametoindex(interface_name);
        if (interface_ == 0U) {
            return false;
        }
        fd_ = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
        if (fd_ < 0) {
            return false;
        }
        sockaddr_nl self;
        memset(&self, 0, sizeof(self));
        self.nl_family = AF_NETLINK;
        timeval limit;
        limit.tv_sec = 0;
        limit.tv_usec = kAnswerUs;
        if (bind(fd_, reinterpret_cast<sockaddr*>(&self), sizeof(self)) != 0 ||
            setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit)) != 0) {
            return false;
        }
        static const char kName[] = "nl80211";
        return ask(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, false, CTRL_ATTR_FAMILY_NAME,
                   kName, sizeof(kName), &onFamily, &family_) &&
               family_ != 0U;
    }

    bool stations(std::vector<WifiStation>& out) {
        out.clear();
        return ask(family_, NL80211_CMD_GET_STATION, true, NL80211_ATTR_IFINDEX,
                   &interface_, sizeof(interface_), &onStation, &out);
    }

    bool frequency(unsigned& mhz_out) {
        mhz_out = 0U;
        return ask(family_, NL80211_CMD_GET_INTERFACE, false, NL80211_ATTR_IFINDEX,
                   &interface_, sizeof(interface_), &onInterface, &mhz_out) &&
               mhz_out != 0U;
    }

private:
    typedef void (*OnAnswer)(const uint8_t* attrs, size_t len, void* user);

    static void onFamily(const uint8_t* attrs, size_t len, void* user) {
        Attr a;
        while (nextAttr(attrs, len, a)) {
            if (a.type == CTRL_ATTR_FAMILY_ID && a.len == 2U) {
                *static_cast<uint16_t*>(user) = static_cast<uint16_t>(readUnsignedNumber(a));
            }
        }
    }

    static void onStation(const uint8_t* attrs, size_t len, void* user) {
        WifiStation station;
        if (parseWifiStation(attrs, len, station)) {
            static_cast<std::vector<WifiStation>*>(user)->push_back(station);
        }
    }

    static void onInterface(const uint8_t* attrs, size_t len, void* user) {
        parseWifiFrequency(attrs, len, *static_cast<unsigned*>(user));
    }

    bool ask(uint16_t type,
             uint8_t command,
             bool dump,
             uint16_t attr_type,
             const void* attr,
             size_t attr_len,
             OnAnswer on,
             void* user) {
        nlmsghdr header;
        genlmsghdr generic;
        nlattr attribute;
        std::vector<uint8_t> request(
            sizeof(header) + sizeof(generic) + sizeof(attribute) + align4(attr_len), 0U);
        memset(&header, 0, sizeof(header));
        header.nlmsg_len = static_cast<uint32_t>(request.size());
        header.nlmsg_type = type;
        header.nlmsg_flags = static_cast<uint16_t>(NLM_F_REQUEST | (dump ? NLM_F_DUMP : 0));
        header.nlmsg_seq = ++sequence_;
        memset(&generic, 0, sizeof(generic));
        generic.cmd = command;
        generic.version = 1;
        attribute.nla_type = attr_type;
        attribute.nla_len = static_cast<uint16_t>(sizeof(attribute) + attr_len);
        memcpy(&request[0], &header, sizeof(header));
        memcpy(&request[sizeof(header)], &generic, sizeof(generic));
        memcpy(&request[sizeof(header) + sizeof(generic)], &attribute, sizeof(attribute));
        memcpy(&request[sizeof(header) + sizeof(generic) + sizeof(attribute)], attr, attr_len);

        sockaddr_nl kernel;
        memset(&kernel, 0, sizeof(kernel));
        kernel.nl_family = AF_NETLINK;
        if (sendto(fd_, &request[0], request.size(), 0,
                   reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)) !=
            static_cast<ssize_t>(request.size())) {
            return false;
        }

        uint8_t answer[8192];
        for (;;) {
            const ssize_t got = recv(fd_, answer, sizeof(answer), 0);
            if (got <= 0) {
                return false;
            }
            const uint8_t* p = answer;
            size_t left = static_cast<size_t>(got);
            bool answered = false;
            while (left >= sizeof(header)) {
                memcpy(&header, p, sizeof(header));
                if (header.nlmsg_len < sizeof(header) || header.nlmsg_len > left) {
                    return false;
                }
                const uint8_t* body = p + sizeof(header);
                const size_t body_len = header.nlmsg_len - sizeof(header);
                const size_t step =
                    align4(header.nlmsg_len) > left ? left : align4(header.nlmsg_len);
                p += step;
                left -= step;
                if (header.nlmsg_seq != sequence_) {
                    continue;
                }
                if (header.nlmsg_type == NLMSG_DONE) {
                    return true;
                }
                if (header.nlmsg_type == NLMSG_ERROR) {
                    return false;
                }
                if (body_len >= sizeof(generic)) {
                    on(body + sizeof(generic), body_len - sizeof(generic), user);
                    answered = true;
                }
            }
            if (!dump && answered) {
                return true;
            }
        }
    }

    int fd_;
    uint16_t family_;
    uint32_t interface_;
    uint32_t sequence_;
};

bool phoneAddress(int fd, const char* interface_name, uint8_t mac[6]) {
    sockaddr_in peer;
    socklen_t len = sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    if (getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &len) != 0 ||
        peer.sin_family != AF_INET) {
        return false;
    }
    arpreq request;
    memset(&request, 0, sizeof(request));
    memcpy(&request.arp_pa, &peer, sizeof(peer));
    strncpy(request.arp_dev, interface_name, sizeof(request.arp_dev) - 1U);
    if (ioctl(fd, SIOCGARP, &request) != 0 || !(request.arp_flags & ATF_COM)) {
        return false;
    }
    memcpy(mac, request.arp_ha.sa_data, 6U);
    return true;
}
#endif

void appendFmt1(std::string& line, const char* separator, const char* fmt, long long a) {
    char text[128];
    snprintf(text, sizeof(text), fmt, a);
    if (!line.empty()) {
        line += separator;
    }
    line += text;
}

void appendFmt2(std::string& line,
                const char* separator,
                const char* fmt,
                long long a,
                long long b) {
    char text[128];
    snprintf(text, sizeof(text), fmt, a, b);
    if (!line.empty()) {
        line += separator;
    }
    line += text;
}

std::string formatFrames(const WifiStation& now, const WifiStation* since) {
    std::string s;
    if (now.tx_frames != kNoFigure) {
        appendFmt1(s, ", ", "%lld frames sent",
                   now.tx_frames - (since != NULL ? since->tx_frames : 0));
    }
    if (now.tx_retries != kNoFigure) {
        appendFmt1(s, ", ", "%lld retried",
                   now.tx_retries - (since != NULL ? since->tx_retries : 0));
    }
    if (now.tx_failed != kNoFigure) {
        appendFmt1(s, ", ", "%lld lost",
                   now.tx_failed - (since != NULL ? since->tx_failed : 0));
    }
    return s;
}

bool continuesSameStation(const WifiStation& now, const WifiStation& before) {
    return memcmp(now.mac, before.mac, sizeof(now.mac)) == 0 &&
           (now.tx_frames == kNoFigure) == (before.tx_frames == kNoFigure) &&
           now.tx_frames >= before.tx_frames &&
           (now.tx_retries == kNoFigure) == (before.tx_retries == kNoFigure) &&
           now.tx_retries >= before.tx_retries &&
           (now.tx_failed == kNoFigure) == (before.tx_failed == kNoFigure) &&
           now.tx_failed >= before.tx_failed &&
           (now.connected_s == kNoFigure || before.connected_s == kNoFigure ||
            now.connected_s >= before.connected_s);
}

}  // namespace

WifiStation::WifiStation()
    : signal_dbm(kNoFigure),
      signal_avg_dbm(kNoFigure),
      tx_rate(kNoFigure),
      rx_rate(kNoFigure),
      tx_frames(kNoFigure),
      tx_retries(kNoFigure),
      tx_failed(kNoFigure),
      connected_s(kNoFigure) {
    memset(mac, 0, sizeof(mac));
}

WifiSample::WifiSample()
    : at_ms(0U), radio(false), mhz(0U), stations(0U), has_station(false), has_tcp(false) {}

bool parseWifiStation(const uint8_t* attrs, size_t len, WifiStation& out) {
    out = WifiStation();
    bool named = false;
    const uint8_t* p = attrs;
    size_t left = len;
    Attr a;
    while (nextAttr(p, left, a)) {
        if (a.type == NL80211_ATTR_MAC && a.len == sizeof(out.mac)) {
            memcpy(out.mac, a.data, sizeof(out.mac));
            named = true;
        } else if (a.type == NL80211_ATTR_STA_INFO) {
            parseStationInfo(a, out);
        }
    }
    return named;
}

bool parseWifiFrequency(const uint8_t* attrs, size_t len, unsigned& mhz_out) {
    const uint8_t* p = attrs;
    size_t left = len;
    Attr a;
    while (nextAttr(p, left, a)) {
        if (a.type == NL80211_ATTR_WIPHY_FREQ && a.len == 4U) {
            mhz_out = static_cast<unsigned>(readUnsignedNumber(a));
            return true;
        }
    }
    return false;
}

bool readWifiStations(const char* interface_name, std::vector<WifiStation>& out) {
#ifdef _WIN32
    (void)interface_name;
    out.clear();
    return false;
#else
    Nl80211 radio;
    if (!radio.open(interface_name)) {
        out.clear();
        return false;
    }
    return radio.stations(out);
#endif
}

bool readWifiFrequency(const char* interface_name, unsigned& mhz_out) {
#ifdef _WIN32
    (void)interface_name;
    mhz_out = 0U;
    return false;
#else
    Nl80211 radio;
    if (!radio.open(interface_name)) {
        mhz_out = 0U;
        return false;
    }
    return radio.frequency(mhz_out);
#endif
}

bool readTcpLink(int fd, TcpLink& out) {
    out = TcpLink();
#ifdef _WIN32
    (void)fd;
    return false;
#else
    if (fd < 0) {
        return false;
    }
    tcp_info info;
    socklen_t len = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) != 0) {
        return false;
    }
    out.round_trip_us = info.tcpi_rtt;
    out.resent = info.tcpi_total_retrans;
    return true;
#endif
}

std::string describeWifiLink(const WifiSample& now, const WifiSample* before) {
    std::string line;
    if (now.radio && now.mhz != 0U) {
        appendFmt1(line, "; ", "%lld MHz", static_cast<long long>(now.mhz));
    }
    if (now.radio && !now.has_station) {
        appendFmt1(line, "; ", "phone not found among the %lld station(s) of the access point",
                   static_cast<long long>(now.stations));
    }
    if (now.has_station) {
        const WifiStation& phone = now.station;
        if (phone.signal_dbm != kNoFigure && phone.signal_avg_dbm != kNoFigure) {
            appendFmt2(line, "; ", "signal %lld dBm (average %lld)",
                       static_cast<long long>(phone.signal_dbm),
                       static_cast<long long>(phone.signal_avg_dbm));
        } else if (phone.signal_dbm != kNoFigure) {
            appendFmt1(line, "; ", "signal %lld dBm", static_cast<long long>(phone.signal_dbm));
        } else if (phone.signal_avg_dbm != kNoFigure) {
            appendFmt1(line, "; ", "average signal %lld dBm",
                       static_cast<long long>(phone.signal_avg_dbm));
        }
        if (phone.rx_rate != kNoFigure) {
            appendFmt2(line, "; ", "from the phone %lld.%lld Mbit/s",
                       static_cast<long long>(phone.rx_rate / 10),
                       static_cast<long long>(phone.rx_rate % 10));
        }
        const bool same =
            before != NULL && before->has_station && continuesSameStation(phone, before->station);
        const std::string counted = formatFrames(phone, same ? &before->station : NULL);
        if (before != NULL && before->has_station && !same) {
            if (!line.empty()) {
                line += "; ";
            }
            line += "the phone joined the Wi-Fi again";
        }
        if (!counted.empty()) {
            if (same) {
                const uint32_t dt_ms = now.at_ms - before->at_ms;
                appendFmt1(line, "; ", "in %lld s: ", static_cast<long long>((dt_ms + 500U) / 1000U));
            } else {
                if (!line.empty()) {
                    line += "; ";
                }
                line += "since it joined: ";
            }
            line += counted;
        }
        if (phone.connected_s != kNoFigure) {
            appendFmt1(line, "; ", "on the Wi-Fi for %lld s",
                       static_cast<long long>(phone.connected_s));
        }
    }
    if (now.has_tcp) {
        appendFmt2(line, "; ", "TCP round trip %lld.%lld ms",
                   static_cast<long long>(now.tcp.round_trip_us / 1000U),
                   static_cast<long long>((now.tcp.round_trip_us % 1000U) / 100U));
        if (before != NULL && before->has_tcp && now.tcp.resent >= before->tcp.resent) {
            appendFmt1(line, ", ", "%lld segment(s) sent again",
                       static_cast<long long>(now.tcp.resent - before->tcp.resent));
        } else {
            appendFmt1(line, ", ", "%lld segment(s) sent again since it opened",
                       static_cast<long long>(now.tcp.resent));
        }
    }
    if (now.apps.read) {
        if (now.apps.connected) {
            if (!line.empty()) {
                line += "; ";
            }
            line += "BMW Apps Bluetooth link connected";
        } else if (now.apps.state == 1U && now.apps.transport == 0U) {
            if (!line.empty()) {
                line += "; ";
            }
            line += "BMW Apps Bluetooth link idle";
        } else {
            appendFmt2(line, "; ", "BMW Apps Bluetooth slot state %lld, link state %lld",
                       static_cast<long long>(now.apps.state),
                       static_cast<long long>(now.apps.transport));
        }
    }
    return line;
}

bool readBmwAppsSlot(SppSnapshotReader& reader, AppsSlot& out) {
    out = AppsSlot();
    if (!reader.isOpen()) {
        return false;
    }
    SppSlotSnapshot snap;
    if (!reader.read(kAlpsBmwAppsSlot, snap)) {
        return false;
    }
    out.read = true;
    out.connected = snap.connected;
    out.state = snap.state;
    out.transport = snap.transport_state;
    return true;
}

WifiLinkLog::WifiLinkLog()
    : fd_(-1),
      first_(false),
      apps_probe_(NULL),
      apps_user_(NULL),
      seen_active_(false),
      has_before_(false),
      radio_gone_(false),
      next_ms_(0U),
      since_ms_(0U),
      radio_failures_(0U) {}

WifiLinkLog::~WifiLinkLog() {
    LockGuard lock(lock_);
    forget();
}

void WifiLinkLog::enable(const char* interface_name) {
    LockGuard lock(lock_);
    interface_ = interface_name != NULL ? interface_name : "";
}

void WifiLinkLog::setAppsProbe(AppsProbe probe, void* user) {
    LockGuard lock(lock_);
    apps_probe_ = probe;
    apps_user_ = user;
}

void WifiLinkLog::forget() {
#ifndef _WIN32
    if (fd_ >= 0) {
        close(fd_);
    }
#endif
    fd_ = -1;
}

void WifiLinkLog::connected(int fd) {
    LockGuard lock(lock_);
    if (interface_.empty() || fd < 0) {
        return;
    }
    forget();
#ifndef _WIN32
    fd_ = fcntl(fd, F_DUPFD_CLOEXEC, 0);
#endif
    first_ = (fd_ >= 0);
    seen_active_ = false;
    has_before_ = false;
    radio_gone_ = false;
    radio_failures_ = 0U;
}

void WifiLinkLog::turn(uint32_t now_ms, bool session_active) {
    LockGuard lock(lock_);
    if (fd_ < 0) {
        return;
    }
    if (first_) {
        first_ = false;
        since_ms_ = now_ms;
        next_ms_ = now_ms;
    }
    if (!session_active) {
        if (seen_active_ || now_ms - since_ms_ >= kStartGraceMs) {
            forget();
        }
        return;
    }
    seen_active_ = true;
    if (static_cast<int32_t>(now_ms - next_ms_) < 0) {
        return;
    }
    next_ms_ = now_ms + kPeriodMs;
    sample(now_ms);
}

void WifiLinkLog::sample(uint32_t now_ms) {
    WifiSample now;
    now.at_ms = now_ms;
    now.has_tcp = readTcpLink(fd_, now.tcp);
#ifndef _WIN32
    if (!radio_gone_) {
        Nl80211 radio;
        std::vector<WifiStation> all;
        if (radio.open(interface_.c_str()) && radio.stations(all)) {
            radio_failures_ = 0U;
            now.radio = true;
            now.stations = static_cast<unsigned>(all.size());
            radio.frequency(now.mhz);
            uint8_t mac[6];
            if (phoneAddress(fd_, interface_.c_str(), mac)) {
                for (size_t i = 0U; i < all.size(); ++i) {
                    if (memcmp(all[i].mac, mac, sizeof(mac)) == 0) {
                        now.station = all[i];
                        now.has_station = true;
                        break;
                    }
                }
            } else if (all.size() == 1U) {
                now.station = all[0];
                now.has_station = true;
            }
        } else if (++radio_failures_ >= kRadioTries) {
            radio_gone_ = true;
            CARPLAY_LOG_INFO(
                kTag,
                "no Wi-Fi figures from kernel for %s (nl80211, errno %d): TCP figures only",
                interface_.c_str(), errno);
        }
    }
#endif
    if (apps_probe_ != NULL) {
        AppsSlot probed;
        if (apps_probe_(apps_user_, probed)) {
            now.apps = probed;
        }
    }
    const std::string line = describeWifiLink(now, has_before_ ? &before_ : NULL);
    if (!line.empty()) {
        CARPLAY_LOG_INFO(kTag, "%s", line.c_str());
    }
    before_ = now;
    has_before_ = true;
}

}  // namespace platform
}  // namespace carplay
