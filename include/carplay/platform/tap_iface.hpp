#ifndef CARPLAY_PLATFORM_TAP_IFACE_HPP
#define CARPLAY_PLATFORM_TAP_IFACE_HPP

// Linux TAP virtual Ethernet interface (/dev/net/tun, IFF_TAP | IFF_NO_PI) for CDC-NCM bridging.
//
// Kernel IPv6 behavior:
//   Once the TAP interface has a valid unicast MAC address (via SIOCSIFHWADDR) and is brought UP
//   (via SIOCSIFFLAGS with IFF_UP | IFF_RUNNING), the Linux kernel IPv6 stack automatically
//   configures a link-local address (fe80::/64) on the interface (assuming net.ipv6.conf.<if>.disable_ipv6
//   is 0). Standard POSIX sockets in SessionServer / MediaEngine can then bind/connect on that
//   fe80::...%<ifindex> address without any userspace TCP/IP stack.
//
// Testability:
//   * OS /dev/net/tun and SIOC* ioctls are abstracted behind TapOsInterface (PosixTapOs default).
//   * High-level interface TapPortInterface is implemented by TapIface and fakeable for bridge tests.

#include <stddef.h>
#include <stdint.h>

#include <deque>
#include <string>
#include <vector>

#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/reactor.hpp"

namespace carplay {
namespace platform {

enum TapWriteResult {
    kTapWriteSent = 0,
    kTapWriteQueued = 1,
    kTapWriteDroppedQueueFull = 2,
    kTapWriteError = 3
};

class TapListener {
public:
    virtual ~TapListener() {}
    /// Called on the Reactor thread for each Ethernet frame read from the TAP device.
    virtual void onTapFrame(const uint8_t* frame, size_t len) = 0;
    /// Called on the Reactor thread if the TAP fd suffers an unrecoverable error.
    virtual void onTapError() {}
};

struct TapConfig {
    std::string interface_name;  // requested name (e.g. "carplay0"); empty = kernel assigns tap%d
    std::string tun_device_path; // default "/dev/net/tun"
    uint64_t mac_seed;           // used to derive locally-administered unicast MAC when !use_explicit_mac
    bool use_explicit_mac;
    uint8_t explicit_mac[6];
    uint16_t mtu;                // 0 = leave kernel default (1500)
    size_t max_rx_frame_bytes;
    size_t max_tx_queue_frames;

    TapConfig()
        : interface_name("carplay0"),
          tun_device_path("/dev/net/tun"),
          mac_seed(0x454e563243504c59ULL),
          use_explicit_mac(false),
          mtu(1500U),
          max_rx_frame_bytes(2048U),
          max_tx_queue_frames(256U) {
        explicit_mac[0] = 0x02U;
        explicit_mac[1] = 0;
        explicit_mac[2] = 0;
        explicit_mac[3] = 0;
        explicit_mac[4] = 0;
        explicit_mac[5] = 0x01U;
    }
};

/// Low-level OS abstraction over /dev/net/tun and SIOC* netdevice ioctls.
class TapOsInterface {
public:
    virtual ~TapOsInterface() {}

    virtual bool openTap(const std::string& tun_path,
                         const std::string& requested_name,
                         SocketHandle& fd_out,
                         std::string& actual_name_out) = 0;

    virtual bool configureInterface(const std::string& if_name,
                                    const uint8_t mac[6],
                                    uint16_t mtu,
                                    uint32_t& ifindex_out) = 0;

    virtual void closeTap(SocketHandle fd) = 0;

    virtual IoStatus readFrame(SocketHandle fd, uint8_t* buf, size_t cap, size_t& len_out) = 0;
    virtual IoStatus writeFrame(SocketHandle fd, const uint8_t* data, size_t len) = 0;
};

class PosixTapOs : public TapOsInterface {
public:
    PosixTapOs() {}
    virtual ~PosixTapOs() {}

    virtual bool openTap(const std::string& tun_path,
                         const std::string& requested_name,
                         SocketHandle& fd_out,
                         std::string& actual_name_out);

    virtual bool configureInterface(const std::string& if_name,
                                    const uint8_t mac[6],
                                    uint16_t mtu,
                                    uint32_t& ifindex_out);

    virtual void closeTap(SocketHandle fd);

    virtual IoStatus readFrame(SocketHandle fd, uint8_t* buf, size_t cap, size_t& len_out);
    virtual IoStatus writeFrame(SocketHandle fd, const uint8_t* data, size_t len);

private:
    PosixTapOs(const PosixTapOs&) = delete;
    PosixTapOs& operator=(const PosixTapOs&) = delete;
};

/// High-level TAP interface abstraction implemented by TapIface and fakeable in tests.
class TapPortInterface {
public:
    virtual ~TapPortInterface() {}

    virtual bool open(Reactor& reactor, TapListener* listener) = 0;
    virtual void close() = 0;
    virtual bool isOpen() const = 0;

    virtual const std::string& interfaceName() const = 0;
    virtual uint32_t ifIndex() const = 0;
    virtual void getMacAddress(uint8_t mac_out[6]) const = 0;

    virtual TapWriteResult writeFrame(const uint8_t* data, size_t len) = 0;
    virtual bool queryIpv6LinkLocal(Address& out) const = 0;
};

class TapIface : public TapPortInterface, public IoHandler {
public:
    /// `os` may be NULL to use the default PosixTapOs (owned internally).
    /// If non-NULL, the caller retains ownership of `os`.
    explicit TapIface(const TapConfig& config = TapConfig(), TapOsInterface* os = NULL);
    virtual ~TapIface();

    virtual bool open(Reactor& reactor, TapListener* listener);
    virtual void close();
    virtual bool isOpen() const { return open_; }

    virtual const std::string& interfaceName() const { return actual_name_; }
    virtual uint32_t ifIndex() const { return ifindex_; }
    virtual void getMacAddress(uint8_t mac_out[6]) const;

    virtual TapWriteResult writeFrame(const uint8_t* data, size_t len);
    virtual bool queryIpv6LinkLocal(Address& out) const;

    size_t queuedTxFrames() const { return tx_queue_.size(); }
    void setConfig(const TapConfig& config);
    const TapConfig& config() const { return config_; }

    // IoHandler (Reactor thread)
    virtual void onReadable();
    virtual void onWritable();
    virtual void onError();

private:
    TapIface(const TapIface&) = delete;
    TapIface& operator=(const TapIface&) = delete;

    void updatePollInterest();

    TapConfig config_;
    PosixTapOs default_os_;
    TapOsInterface* os_;

    Reactor* reactor_;
    TapListener* listener_;
    SocketHandle fd_;
    bool fd_registered_;
    bool open_;
    std::string actual_name_;
    uint32_t ifindex_;
    uint8_t mac_[6];
    std::vector<uint8_t> rx_buf_;
    std::deque<std::vector<uint8_t> > tx_queue_;
};

/// Derives a deterministic locally-administered unicast MAC address from a 64-bit seed.
/// Sets bit 1 (locally administered) and clears bit 0 (unicast) of octet 0.
void deriveLocallyAdministeredMac(uint64_t seed, uint8_t mac_out[6]);

/// Derives a deterministic locally-administered unicast MAC address from an arbitrary string seed.
void deriveLocallyAdministeredMacFromString(const std::string& seed, uint8_t mac_out[6]);

/// Formats a 6-byte MAC address as lowercase "xx:xx:xx:xx:xx:xx".
std::string formatMacAddress(const uint8_t mac[6]);

/// Computes the standard SLAAC EUI-64 IPv6 link-local address (fe80::<EUI-64>) for `mac`.
Address computeEui64LinkLocal(const uint8_t mac[6], uint32_t scope_id = 0);

/// Parses Linux /proc/net/if_inet6 contents to find the fe80::/10 link-local IPv6 address
/// assigned to `ifname`.
bool parseProcNetIfInet6(const std::string& content,
                         const std::string& ifname,
                         Address& out);

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_TAP_IFACE_HPP
