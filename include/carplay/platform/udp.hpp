#ifndef CARPLAY_PLATFORM_UDP_HPP
#define CARPLAY_PLATFORM_UDP_HPP

// Non-blocking UDP socket (NTP timing, keep-alive, RTP audio). Reactor-thread only; the owner
// registers handle() with the Reactor.

#include <stddef.h>
#include <stdint.h>

#include "carplay/platform/net_compat.hpp"

namespace carplay {
namespace platform {

class UdpSocket {
public:
    /// The reference asks for 512 KiB of receive buffer on its audio sockets.
    static const size_t kAudioReceiveBuffer = 512 * 1024;

    UdpSocket();
    ~UdpSocket();

    /// Binds exactly `address` (port 0 = ephemeral; an IPv6 :: address is bound dual-stack).
    bool open(const Address& address);
    /// [::]:port dual-stack, falling back to 0.0.0.0:port when IPv6 is unavailable.
    bool openAny(uint16_t port);
    void close();

    /// kIoOk / kIoTruncated (datagram longer than cap; `got` == cap) / kIoWouldBlock / kIoError.
    /// `from` is the sender (IPv4-mapped senders reported as IPv4).
    IoStatus receiveFrom(uint8_t* buf, size_t cap, size_t& got, Address& from);
    /// kIoOk when the whole datagram was handed to the kernel.
    IoStatus sendTo(const uint8_t* data, size_t len, const Address& to);

    /// Requests SO_RCVBUF; granted_out is what the kernel reports back (Linux: doubled value,
    /// capped by net.core.rmem_max).
    bool setReceiveBuffer(size_t requested, size_t& granted_out);
    bool setWifiVideoTos();

    bool isOpen() const { return handle_ != kInvalidSocket; }
    SocketHandle handle() const { return handle_; }
    const Address& localAddress() const { return local_; }
    uint16_t port() const { return local_.port(); }
    bool dualStack() const { return dual_stack_; }

private:
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    bool openBound(const Address& address, bool dual_stack);

    SocketHandle handle_;
    Address local_;
    bool dual_stack_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_UDP_HPP
