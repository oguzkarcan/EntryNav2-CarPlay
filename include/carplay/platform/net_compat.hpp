#ifndef CARPLAY_PLATFORM_NET_COMPAT_HPP
#define CARPLAY_PLATFORM_NET_COMPAT_HPP

// Thin portability shim over BSD sockets (Linux, what ships) and Winsock2 (host tests only).
//
// This is the ONLY translation unit pair allowed to include <winsock2.h> / <sys/socket.h>; every
// other platform file talks to sockets through the functions below. The shim is deliberately small:
//   * SocketHandle hides int vs SOCKET; kInvalidSocket hides -1 vs INVALID_SOCKET.
//   * Every operation reports a portable IoStatus; kIoWouldBlock folds EAGAIN/EWOULDBLOCK/
//     WSAEWOULDBLOCK, and EINTR is retried internally where a retry is always correct.
//   * PollSet wraps poll() / WSAPoll() behind portable kPoll* flags.
//   * netInit() performs WSAStartup exactly once on Windows (no-op on POSIX). Every socket-creating
//     function calls it, so callers normally never need to.
//   * Addresses are converted with Address (below); IPv4-mapped IPv6 peers (::ffff:a.b.c.d, as seen
//     on a dual-stack listener) are reported as plain IPv4 so "same host" comparisons are stable.
//   * setReuseAddress(): SO_REUSEADDR on POSIX (rebind over TIME_WAIT); on Windows SO_REUSEADDR
//     would let another process steal the port, so SO_EXCLUSIVEADDRUSE is set instead (Windows
//     already allows rebinding over TIME_WAIT).
//   * Linux: sockets are created close-on-exec, sends use MSG_NOSIGNAL (no SIGPIPE).
//
// Not a general networking library: only what the reactor / tcp / udp layers need.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

namespace carplay {
namespace platform {

#ifdef _WIN32
typedef uintptr_t SocketHandle;  // SOCKET
static const SocketHandle kInvalidSocket = ~static_cast<SocketHandle>(0);
#else
typedef int SocketHandle;
static const SocketHandle kInvalidSocket = -1;
#endif

/// Monotonic clock in nanoseconds (CLOCK_MONOTONIC / QueryPerformanceCounter). Never goes back;
/// the epoch is arbitrary. Thread-safe.
int64_t monotonicNanos();

/// Monotonic clock in milliseconds (monotonicNanos() / 1e6).
int64_t monotonicMillis();

/// WSAStartup(2.2) once per process on Windows; always true on POSIX. Thread-safe.
bool netInit();

/// IPv4 / IPv6 endpoint (address + port + IPv6 scope id).
class Address {
public:
    enum Family { kNone = 0, kIPv4 = 4, kIPv6 = 6 };

    Address();

    static Address ipv4(const uint8_t bytes[4], uint16_t port);
    static Address ipv6(const uint8_t bytes[16], uint16_t port, uint32_t scope_id = 0);
    static Address ipv4Any(uint16_t port);
    static Address ipv6Any(uint16_t port);
    static Address ipv4Loopback(uint16_t port);
    static Address ipv6Loopback(uint16_t port);

    /// Parses "1.2.3.4", "1.2.3.4:80", "::1", "[::1]:80", "fe80::1%4", "[fe80::1%4]:80" and
    /// IPv4-embedded forms ("::ffff:1.2.3.4"). The scope id must be numeric (interface names are not
    /// resolved). An IPv4-mapped IPv6 literal is kept as IPv6 (use unmapped()). Returns false (out =
    /// kNone) on any syntax error, out-of-range octet/port, or trailing garbage.
    static bool parse(const std::string& text, Address& out);

    Family family() const { return family_; }
    bool valid() const { return family_ != kNone; }
    uint16_t port() const { return port_; }
    void setPort(uint16_t port) { port_ = port; }
    uint32_t scopeId() const { return scope_id_; }
    /// 4 bytes for IPv4, 16 for IPv6, 0 for kNone.
    size_t byteLength() const;
    const uint8_t* bytes() const { return bytes_; }

    bool isLoopback() const;
    bool isAny() const;
    bool isLinkLocal() const;   // fe80::/10 or 169.254/16
    bool isV4Mapped() const;    // ::ffff:a.b.c.d
    /// ::ffff:a.b.c.d -> a.b.c.d (port kept); any other address is returned unchanged.
    Address unmapped() const;
    /// a.b.c.d -> ::ffff:a.b.c.d (port kept); any other address is returned unchanged.
    Address v4Mapped() const;

    /// Address without port: "1.2.3.4", "fe80::1%4" (RFC 5952 lowercase, longest zero run
    /// compressed, IPv4-mapped shown as "::ffff:1.2.3.4"). "" for kNone.
    std::string hostString() const;
    /// With port: "1.2.3.4:80", "[fe80::1%4]:80". "" for kNone.
    std::string toString() const;

    /// Same family/bytes/scope (after unmapping IPv4-mapped addresses), port ignored. Two kNone
    /// addresses are NOT the same host.
    bool sameHost(const Address& other) const;
    /// Exact equality including port and scope (no unmapping).
    bool operator==(const Address& other) const;
    bool operator!=(const Address& other) const { return !(*this == other); }

private:
    Family family_;
    uint8_t bytes_[16];
    uint16_t port_;
    uint32_t scope_id_;
};

enum IoStatus {
    kIoOk = 0,
    kIoWouldBlock = 1,  // non-blocking operation could not make progress now
    kIoClosed = 2,      // orderly EOF from the peer (TCP recv returned 0) or socket not open
    kIoError = 3,       // hard error (see lastSocketError())
    kIoTruncated = 4    // UDP datagram larger than the caller buffer (the prefix was delivered)
};

enum SocketType { kSockStream = 0, kSockDatagram = 1 };

/// OS error code of the last failing shim call on this thread (errno / WSAGetLastError()).
int lastSocketError();
/// Human-readable text for an OS socket error code.
std::string socketErrorString(int code);

/// Creates a non-blocking (and on Linux close-on-exec) socket. kInvalidSocket on failure.
SocketHandle socketOpen(Address::Family family, SocketType type);
/// Closes the handle (no-op for kInvalidSocket) and sets it to kInvalidSocket.
void socketClose(SocketHandle& handle);
bool socketSetNonBlocking(SocketHandle handle);

static const int kWifiVideoTos = 0x80;  // Wi-Fi WMM AC_VI (IP_TOS/IPV6_TCLASS 0x80)

bool setReuseAddress(SocketHandle handle);
bool setV6Only(SocketHandle handle, bool v6only);
bool setNoDelay(SocketHandle handle, bool on);
bool setKeepAlive(SocketHandle handle, bool on);
/// SO_LINGER {on, 0}: close() sends RST and drops unsent data.
bool setLingerZero(SocketHandle handle);
/// Sets Wi-Fi video access-category QoS (IP_TOS / IPV6_TCLASS = 0x80, WMM AC_VI) as BMW's
/// native CarPlay SocketSetQoS does on wireless sockets. Do not use on wired USB sockets.
bool setWifiVideoTos(SocketHandle handle);
/// Reads IP_TOS (IPv4) or IPV6_TCLASS (IPv6) from the socket for diagnostics / tests.
bool getSocketTrafficClass(SocketHandle handle, int& tos_out);
/// Requests SO_RCVBUF / SO_SNDBUF and reports what the kernel actually granted (Linux reports the
/// doubled bookkeeping value, capped by net.core.rmem_max / wmem_max).
bool setReceiveBuffer(SocketHandle handle, size_t requested, size_t& granted_out);
bool setSendBuffer(SocketHandle handle, size_t requested, size_t& granted_out);
/// SO_ERROR (pending error, cleared by reading). Returns false if getsockopt itself failed.
bool takeSocketError(SocketHandle handle, int& error_out);

bool socketBind(SocketHandle handle, const Address& address);
bool socketListen(SocketHandle handle, int backlog);
/// Non-blocking accept. kIoOk -> accepted_out is a new non-blocking (close-on-exec) socket and
/// peer_out is its (unmapped) peer. kIoWouldBlock when no connection is pending.
IoStatus socketAccept(SocketHandle handle, SocketHandle& accepted_out, Address& peer_out);
/// Non-blocking connect: kIoOk = connected immediately, kIoWouldBlock = in progress (wait for
/// writability, then takeSocketError()), kIoError = failed.
IoStatus socketConnect(SocketHandle handle, const Address& remote);
bool socketLocalAddress(SocketHandle handle, Address& out);
bool socketPeerAddress(SocketHandle handle, Address& out);

IoStatus socketRecv(SocketHandle handle, uint8_t* buf, size_t cap, size_t& got);
IoStatus socketSend(SocketHandle handle, const uint8_t* data, size_t len, size_t& sent);
/// UDP receive. A datagram longer than cap yields kIoTruncated with got = cap.
IoStatus socketRecvFrom(SocketHandle handle, uint8_t* buf, size_t cap, size_t& got, Address& from);
/// UDP send. An IPv4 destination on an IPv6 (dual-stack) socket is sent to its IPv4-mapped form.
IoStatus socketSendTo(SocketHandle handle, const uint8_t* data, size_t len, const Address& to);
/// shutdown(SHUT_WR / SD_SEND).
bool socketShutdownWrite(SocketHandle handle);
/// Family of the socket (from its local address); kNone on failure.
Address::Family socketFamily(SocketHandle handle);

/// Portable readiness flags.
enum PollFlags {
    kPollIn = 1,
    kPollOut = 2,
    kPollErr = 4,   // reported only
    kPollHup = 8,   // reported only
    kPollNval = 16  // reported only
};

struct PollItem {
    SocketHandle handle;
    unsigned events;   // kPollIn | kPollOut
    unsigned revents;  // filled by PollSet::wait
};

/// Reusable poll()/WSAPoll() wrapper; keeps its native array between calls, so wait() does not
/// allocate once it has seen the largest set.
class PollSet {
public:
    PollSet();
    ~PollSet();
    /// Pre-allocates room for `n` items.
    void reserve(size_t n);
    /// Waits up to timeout_ms (< 0 = forever, 0 = poll) and fills revents. Returns the number of
    /// items with non-zero revents, 0 on timeout, -1 on error (EINTR is reported as 0).
    /// With count == 0 it simply sleeps for timeout_ms (WSAPoll rejects empty sets).
    int wait(PollItem* items, size_t count, int timeout_ms);

private:
    PollSet(const PollSet&) = delete;
    PollSet& operator=(const PollSet&) = delete;
    struct Impl;
    Impl* impl_;
};

/// Self-wake channel for the reactor: a non-blocking pipe on POSIX, a connected loopback TCP pair
/// on Windows (WSAPoll only accepts sockets). read_end is pollable for kPollIn.
bool wakePairOpen(SocketHandle& read_end, SocketHandle& write_end);
void wakePairClose(SocketHandle& read_end, SocketHandle& write_end);
/// Writes one byte (a full pipe is fine: a wake is already pending).
void wakeSignal(SocketHandle write_end);
/// Reads and discards everything currently pending on read_end.
void wakeDrain(SocketHandle read_end);

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_NET_COMPAT_HPP
