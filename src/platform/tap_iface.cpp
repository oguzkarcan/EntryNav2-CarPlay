#include "carplay/platform/tap_iface.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

#include "carplay/platform/log.hpp"

#ifdef __linux__
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace carplay {
namespace platform {

namespace {

static const size_t kMaxTapFramesPerWakeup = 32U;

int hexNibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

#ifdef __linux__
bool readProcFile(const char* path, std::string& out) {
    out.clear();
    int fd;
    do {
        fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return false;
    }
    char buf[4096];
    for (;;) {
        const ssize_t r = read(fd, buf, sizeof(buf));
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            out.clear();
            return false;
        }
        if (r == 0) {
            break;
        }
        out.append(buf, static_cast<size_t>(r));
        if (out.size() >= 65536U) {
            break;
        }
    }
    close(fd);
    return !out.empty();
}
#endif  // __linux__

}  // namespace

// ------------------------------------------------------------------------------------------------
// MAC / IPv6 helpers
// ------------------------------------------------------------------------------------------------

void deriveLocallyAdministeredMac(uint64_t seed, uint8_t mac_out[6]) {
    if (mac_out == NULL) {
        return;
    }
    // SplitMix64 step so sequential seeds (0, 1, 2, ...) spread cleanly across all 6 octets.
    uint64_t z = seed + 0x9e3779b97f4a7c15ULL;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    z = z ^ (z >> 31);

    for (size_t i = 0; i < 6U; ++i) {
        mac_out[i] = static_cast<uint8_t>((z >> (i * 8U)) & 0xffU);
    }
    // Bit 1 = 1 (locally administered), bit 0 = 0 (unicast).
    mac_out[0] = static_cast<uint8_t>((mac_out[0] | 0x02U) & 0xfeU);
    if ((mac_out[1] | mac_out[2] | mac_out[3] | mac_out[4] | mac_out[5]) == 0U) {
        mac_out[5] = 0x01U;
    }
}

void deriveLocallyAdministeredMacFromString(const std::string& seed, uint8_t mac_out[6]) {
    uint64_t hash = 14695981039346656037ULL;  // FNV-1a 64-bit offset basis
    for (size_t i = 0; i < seed.size(); ++i) {
        hash ^= static_cast<uint8_t>(seed[i]);
        hash *= 1099511628211ULL;
    }
    deriveLocallyAdministeredMac(hash, mac_out);
}

std::string formatMacAddress(const uint8_t mac[6]) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  static_cast<unsigned>(mac[0]), static_cast<unsigned>(mac[1]),
                  static_cast<unsigned>(mac[2]), static_cast<unsigned>(mac[3]),
                  static_cast<unsigned>(mac[4]), static_cast<unsigned>(mac[5]));
    return std::string(buf);
}

Address computeEui64LinkLocal(const uint8_t mac[6], uint32_t scope_id) {
    uint8_t ip[16];
    std::memset(ip, 0, sizeof(ip));
    ip[0] = 0xfeU;
    ip[1] = 0x80U;
    // Modified EUI-64 interface identifier (RFC 4291 Appendix A)
    ip[8] = static_cast<uint8_t>(mac[0] ^ 0x02U);
    ip[9] = mac[1];
    ip[10] = mac[2];
    ip[11] = 0xffU;
    ip[12] = 0xfeU;
    ip[13] = mac[3];
    ip[14] = mac[4];
    ip[15] = mac[5];
    return Address::ipv6(ip, 0U, scope_id);
}

bool parseProcNetIfInet6(const std::string& content,
                         const std::string& ifname,
                         Address& out) {
    out = Address();
    if (ifname.empty()) {
        return false;
    }
    std::istringstream iss(content);
    std::string line;
    while (std::getline(iss, line)) {
        // Format: <32-hex-addr> <hex-ifindex> <hex-prefix> <hex-scope> <hex-flags> <ifname>
        std::istringstream ls(line);
        std::string hex_addr, hex_idx, hex_plen, hex_scope, hex_flags, dev;
        if (!(ls >> hex_addr >> hex_idx >> hex_plen >> hex_scope >> hex_flags >> dev)) {
            continue;
        }
        if (dev != ifname || hex_addr.size() != 32U) {
            continue;
        }
        uint8_t bytes[16];
        bool ok = true;
        for (size_t i = 0; i < 16U; ++i) {
            const int hi = hexNibble(hex_addr[2U * i]);
            const int lo = hexNibble(hex_addr[2U * i + 1U]);
            if (hi < 0 || lo < 0) {
                ok = false;
                break;
            }
            bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        if (!ok) {
            continue;
        }
        // fe80::/10 link-local check
        if (bytes[0] != 0xfeU || (bytes[1] & 0xc0U) != 0x80U) {
            continue;
        }
        unsigned long idx = std::strtoul(hex_idx.c_str(), NULL, 16);
        out = Address::ipv6(bytes, 0U, static_cast<uint32_t>(idx));
        return true;
    }
    return false;
}

// ------------------------------------------------------------------------------------------------
// PosixTapOs
// ------------------------------------------------------------------------------------------------

bool PosixTapOs::openTap(const std::string& tun_path,
                         const std::string& requested_name,
                         SocketHandle& fd_out,
                         std::string& actual_name_out) {
    fd_out = kInvalidSocket;
    actual_name_out.clear();
#ifndef __linux__
    (void)tun_path;
    (void)requested_name;
    return false;
#else
    int fd;
    do {
        fd = open(tun_path.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        CARPLAY_LOG_WARN("tap", "open(%s) failed: %s (%d)", tun_path.c_str(), strerror(errno),
                         errno);
        return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = static_cast<short>(IFF_TAP | IFF_NO_PI);
    if (!requested_name.empty()) {
        if (requested_name.size() >= IFNAMSIZ) {
            CARPLAY_LOG_ERROR("tap", "interface name '%s' exceeds IFNAMSIZ-1",
                              requested_name.c_str());
            close(fd);
            return false;
        }
        std::memcpy(ifr.ifr_name, requested_name.c_str(), requested_name.size());
    }

    int rc;
    do {
        rc = ioctl(fd, TUNSETIFF, &ifr);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        CARPLAY_LOG_WARN("tap", "ioctl(TUNSETIFF, %s) failed: %s (%d)",
                         requested_name.c_str(), strerror(errno), errno);
        close(fd);
        return false;
    }

    ifr.ifr_name[IFNAMSIZ - 1U] = '\0';
    actual_name_out = ifr.ifr_name;
    fd_out = fd;
    return true;
#endif
}

bool PosixTapOs::configureInterface(const std::string& if_name,
                                    const uint8_t mac[6],
                                    uint16_t mtu,
                                    uint32_t& ifindex_out) {
    ifindex_out = 0;
#ifndef __linux__
    (void)if_name;
    (void)mac;
    (void)mtu;
    return false;
#else
    if (if_name.empty() || if_name.size() >= IFNAMSIZ) {
        return false;
    }
    const int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        CARPLAY_LOG_ERROR("tap", "control socket() failed: %s (%d)", strerror(errno), errno);
        return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::memcpy(ifr.ifr_name, if_name.c_str(), if_name.size());

    // 1. Set hardware MAC address before bringing interface up.
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    std::memcpy(ifr.ifr_hwaddr.sa_data, mac, 6U);
    if (ioctl(sock, SIOCSIFHWADDR, &ifr) < 0) {
        CARPLAY_LOG_ERROR("tap", "SIOCSIFHWADDR(%s) failed: %s (%d)", if_name.c_str(),
                          strerror(errno), errno);
        close(sock);
        return false;
    }

    // 2. Optional MTU.
    if (mtu > 0U) {
        std::memset(&ifr, 0, sizeof(ifr));
        std::memcpy(ifr.ifr_name, if_name.c_str(), if_name.size());
        ifr.ifr_mtu = static_cast<int>(mtu);
        if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
            CARPLAY_LOG_WARN("tap", "SIOCSIFMTU(%s, %u) failed: %s (%d)", if_name.c_str(),
                             static_cast<unsigned>(mtu), strerror(errno), errno);
        }
    }

    // 3. Bring interface UP (kernel IPv6 assigns fe80::/64 link-local automatically).
    std::memset(&ifr, 0, sizeof(ifr));
    std::memcpy(ifr.ifr_name, if_name.c_str(), if_name.size());
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        CARPLAY_LOG_ERROR("tap", "SIOCGIFFLAGS(%s) failed: %s (%d)", if_name.c_str(),
                          strerror(errno), errno);
        close(sock);
        return false;
    }
    ifr.ifr_flags = static_cast<short>(ifr.ifr_flags | IFF_UP | IFF_RUNNING);
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        CARPLAY_LOG_ERROR("tap", "SIOCSIFFLAGS(%s, IFF_UP) failed: %s (%d)", if_name.c_str(),
                          strerror(errno), errno);
        close(sock);
        return false;
    }

    // 4. Query kernel interface index.
    uint32_t idx = if_nametoindex(if_name.c_str());
    if (idx == 0U) {
        std::memset(&ifr, 0, sizeof(ifr));
        std::memcpy(ifr.ifr_name, if_name.c_str(), if_name.size());
        if (ioctl(sock, SIOCGIFINDEX, &ifr) == 0 && ifr.ifr_ifindex > 0) {
            idx = static_cast<uint32_t>(ifr.ifr_ifindex);
        }
    }
    close(sock);
    if (idx == 0U) {
        CARPLAY_LOG_ERROR("tap", "failed to resolve ifindex for %s", if_name.c_str());
        return false;
    }
    ifindex_out = idx;
    return true;
#endif
}

void PosixTapOs::closeTap(SocketHandle fd) {
#ifndef __linux__
    (void)fd;
#else
    if (fd >= 0) {
        ::close(fd);
    }
#endif
}

IoStatus PosixTapOs::readFrame(SocketHandle fd, uint8_t* buf, size_t cap, size_t& len_out) {
    len_out = 0;
#ifndef __linux__
    (void)fd;
    (void)buf;
    (void)cap;
    return kIoError;
#else
    if (fd < 0 || buf == NULL || cap == 0U) {
        return kIoError;
    }
    for (;;) {
        const ssize_t r = read(fd, buf, cap);
        if (r > 0) {
            len_out = static_cast<size_t>(r);
            return kIoOk;
        }
        if (r == 0) {
            return kIoClosed;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return kIoWouldBlock;
        }
        return kIoError;
    }
#endif
}

IoStatus PosixTapOs::writeFrame(SocketHandle fd, const uint8_t* data, size_t len) {
#ifndef __linux__
    (void)fd;
    (void)data;
    (void)len;
    return kIoError;
#else
    if (fd < 0 || data == NULL || len == 0U) {
        return kIoError;
    }
    for (;;) {
        const ssize_t w = write(fd, data, len);
        if (w >= 0) {
            return static_cast<size_t>(w) == len ? kIoOk : kIoError;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return kIoWouldBlock;
        }
        return kIoError;
    }
#endif
}

// ------------------------------------------------------------------------------------------------
// TapIface
// ------------------------------------------------------------------------------------------------

TapIface::TapIface(const TapConfig& config, TapOsInterface* os)
    : config_(config),
      os_(os != NULL ? os : &default_os_),
      reactor_(NULL),
      listener_(NULL),
      fd_(kInvalidSocket),
      fd_registered_(false),
      open_(false),
      ifindex_(0) {
    std::memset(mac_, 0, sizeof(mac_));
}

TapIface::~TapIface() { close(); }

void TapIface::setConfig(const TapConfig& config) {
    if (!open_) {
        config_ = config;
    }
}

void TapIface::getMacAddress(uint8_t mac_out[6]) const {
    if (mac_out != NULL) {
        std::memcpy(mac_out, mac_, 6U);
    }
}

bool TapIface::open(Reactor& reactor, TapListener* listener) {
    if (open_) {
        return false;
    }
    if (!reactor.initialized()) {
        return false;
    }

    uint8_t mac[6];
    if (config_.use_explicit_mac) {
        std::memcpy(mac, config_.explicit_mac, 6U);
        // Ensure unicast even if caller passed an odd octet 0.
        mac[0] = static_cast<uint8_t>(mac[0] & 0xfeU);
    } else {
        deriveLocallyAdministeredMac(config_.mac_seed, mac);
    }

    SocketHandle fd = kInvalidSocket;
    std::string actual_name;
    if (!os_->openTap(config_.tun_device_path, config_.interface_name, fd, actual_name)) {
        return false;
    }

    uint32_t ifindex = 0;
    if (!os_->configureInterface(actual_name, mac, config_.mtu, ifindex)) {
        os_->closeTap(fd);
        return false;
    }

    bool registered = false;
    if (fd != kInvalidSocket) {
        if (!reactor.add(fd, this, kPollIn)) {
            os_->closeTap(fd);
            return false;
        }
        registered = true;
    }

    const size_t rx_cap =
        config_.max_rx_frame_bytes >= 2048U ? config_.max_rx_frame_bytes : 2048U;
    rx_buf_.assign(rx_cap, 0U);
    tx_queue_.clear();

    reactor_ = &reactor;
    listener_ = listener;
    fd_ = fd;
    fd_registered_ = registered;
    open_ = true;
    actual_name_ = actual_name;
    ifindex_ = ifindex;
    std::memcpy(mac_, mac, 6U);

    CARPLAY_LOG_INFO("tap", "TAP %s up (ifindex=%u, mac=%s)", actual_name_.c_str(),
                     static_cast<unsigned>(ifindex_), formatMacAddress(mac_).c_str());
    return true;
}

void TapIface::close() {
    if (!open_) {
        return;
    }
    if (fd_registered_ && reactor_ != NULL && fd_ != kInvalidSocket) {
        reactor_->remove(fd_);
    }
    fd_registered_ = false;
    os_->closeTap(fd_);
    fd_ = kInvalidSocket;
    open_ = false;
    reactor_ = NULL;
    listener_ = NULL;
    actual_name_.clear();
    ifindex_ = 0;
    tx_queue_.clear();
}

TapWriteResult TapIface::writeFrame(const uint8_t* data, size_t len) {
    if (!open_ || data == NULL || len == 0U) {
        return kTapWriteError;
    }

    if (tx_queue_.empty()) {
        const IoStatus st = os_->writeFrame(fd_, data, len);
        if (st == kIoOk) {
            return kTapWriteSent;
        }
        if (st != kIoWouldBlock) {
            return kTapWriteError;
        }
    }

    if (config_.max_tx_queue_frames > 0U && tx_queue_.size() >= config_.max_tx_queue_frames) {
        return kTapWriteDroppedQueueFull;
    }

    tx_queue_.push_back(std::vector<uint8_t>(data, data + len));
    updatePollInterest();
    return kTapWriteQueued;
}

bool TapIface::queryIpv6LinkLocal(Address& out) const {
    out = Address();
    if (!open_ || actual_name_.empty()) {
        return false;
    }
#ifdef __linux__
    std::string proc_data;
    if (readProcFile("/proc/net/if_inet6", proc_data)) {
        if (parseProcNetIfInet6(proc_data, actual_name_, out)) {
            return true;
        }
    }
#endif
    return false;
}

void TapIface::updatePollInterest() {
    if (!open_ || !fd_registered_ || reactor_ == NULL || fd_ == kInvalidSocket) {
        return;
    }
    unsigned interest = kPollIn;
    if (!tx_queue_.empty()) {
        interest |= kPollOut;
    }
    reactor_->modify(fd_, interest);
}

void TapIface::onReadable() {
    if (!open_) {
        return;
    }
    for (size_t i = 0; i < kMaxTapFramesPerWakeup && open_; ++i) {
        size_t got = 0;
        const IoStatus st = os_->readFrame(fd_, &rx_buf_[0], rx_buf_.size(), got);
        if (st == kIoWouldBlock) {
            break;
        }
        if (st == kIoOk) {
            if (got > 0U && listener_ != NULL) {
                listener_->onTapFrame(&rx_buf_[0], got);
            }
            continue;
        }
        CARPLAY_LOG_ERROR("tap", "readFrame error on %s", actual_name_.c_str());
        TapListener* const l = listener_;
        close();
        if (l != NULL) {
            l->onTapError();
        }
        break;
    }
}

void TapIface::onWritable() {
    if (!open_) {
        return;
    }
    while (open_ && !tx_queue_.empty()) {
        const std::vector<uint8_t>& front = tx_queue_.front();
        const IoStatus st =
            os_->writeFrame(fd_, front.empty() ? NULL : &front[0], front.size());
        if (st == kIoOk) {
            tx_queue_.pop_front();
            continue;
        }
        if (st == kIoWouldBlock) {
            break;
        }
        CARPLAY_LOG_ERROR("tap", "writeFrame error on %s", actual_name_.c_str());
        TapListener* const l = listener_;
        close();
        if (l != NULL) {
            l->onTapError();
        }
        return;
    }
    updatePollInterest();
}

void TapIface::onError() {
    if (!open_) {
        return;
    }
    CARPLAY_LOG_ERROR("tap", "poll error/hup on %s", actual_name_.c_str());
    TapListener* const l = listener_;
    close();
    if (l != NULL) {
        l->onTapError();
    }
}

}  // namespace platform
}  // namespace carplay
