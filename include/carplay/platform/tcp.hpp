#ifndef CARPLAY_PLATFORM_TCP_HPP
#define CARPLAY_PLATFORM_TCP_HPP

// Non-blocking TCP listener / connection on top of net_compat. Neither class registers itself with
// the Reactor: the owner registers handle() with its own IoHandler, which keeps ownership explicit
// and lets one handler drive several sockets. All calls belong to the reactor thread.

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "carplay/platform/net_compat.hpp"

namespace carplay {
namespace platform {

class TcpConnection;

class TcpListener {
public:
    /// Return false to reject the peer. The rejected connection is reset (SO_LINGER 0) before any
    /// byte is read from it.
    typedef bool (*AcceptFilter)(void* ctx, const Address& peer);

    enum AcceptResult {
        kAccepted = 0,    // `out` now owns a connected, non-blocking socket
        kNoPending = 1,   // nothing to accept right now
        kRejected = 2,    // a pending connection was refused by the filter (call accept() again)
        kAcceptError = 3  // listener failure (e.g. EMFILE); `out` untouched
    };

    static const int kDefaultBacklog = 8;

    TcpListener();
    ~TcpListener();

    /// Binds exactly `address` (port 0 = ephemeral). SO_REUSEADDR (POSIX) / SO_EXCLUSIVEADDRUSE
    /// (Windows) is set first. An IPv6 address is bound v6-only unless it is the any-address ::, which
    /// is bound dual-stack (IPV6_V6ONLY off).
    bool listen(const Address& address, int backlog = kDefaultBacklog);
    /// Dual-stack any-address: [::]:port with IPV6_V6ONLY off; if IPv6 is unavailable, 0.0.0.0:port.
    bool listenAny(uint16_t port, int backlog = kDefaultBacklog);

    void setAcceptFilter(AcceptFilter filter, void* ctx);

    /// Accepts ONE pending connection into `out` (any previous socket in `out` is closed first on
    /// success). Call repeatedly from onReadable until kNoPending.
    AcceptResult accept(TcpConnection& out);

    void close();
    bool isOpen() const { return handle_ != kInvalidSocket; }
    SocketHandle handle() const { return handle_; }
    /// Bound local address (port resolved when bound to 0).
    const Address& localAddress() const { return local_; }
    uint16_t port() const { return local_.port(); }
    /// True if the socket accepts both IPv4 and IPv6 peers.
    bool dualStack() const { return dual_stack_; }

private:
    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;

    bool openBound(const Address& address, bool dual_stack, int backlog);

    SocketHandle handle_;
    Address local_;
    bool dual_stack_;
    AcceptFilter filter_;
    void* filter_ctx_;
};

class TcpConnection {
public:
    enum SendResult {
        kSendOk = 0,        // all bytes sent or queued
        kSendOverflow = 1,  // queue cap would be exceeded: NOTHING was sent or queued
        kSendClosed = 2,    // not open, or write side already shut down
        kSendError = 3      // socket error: the connection should be closed
    };

    static const size_t kDefaultWriteQueueLimit = 1024 * 1024;

    TcpConnection();
    ~TcpConnection();

    /// Starts a non-blocking connect. true = connected or in progress (see connecting()); register
    /// for kPollOut and call finishConnect() when writable.
    bool connect(const Address& remote);
    bool connecting() const { return connecting_; }
    /// After writability: kIoOk = connected, kIoWouldBlock = still pending, kIoError = failed.
    IoStatus finishConnect();

    /// Takes ownership of an already-connected socket (used by TcpListener).
    void adopt(SocketHandle handle, const Address& peer);

    /// Reads at most `cap` bytes. kIoOk (got > 0), kIoWouldBlock, kIoClosed (peer EOF), kIoError.
    IoStatus read(uint8_t* buf, size_t cap, size_t& got);
    /// Appends at most max_bytes to `out` (single recv).
    IoStatus readAppend(std::vector<uint8_t>& out, size_t max_bytes);

    /// All-or-nothing: if queuedBytes() + len exceeds the write-queue limit, returns kSendOverflow
    /// without sending anything (so stream framing is never torn). Otherwise sends as much as the
    /// kernel accepts and queues the rest; the caller must then watch kPollOut and call flush().
    /// A message larger than the limit can therefore never be sent: size the limit accordingly.
    SendResult send(const uint8_t* data, size_t len);
    SendResult send(const std::vector<uint8_t>& data);
    /// Writes queued bytes. kIoOk = queue now empty, kIoWouldBlock = bytes remain, kIoError.
    /// Performs a pending shutdownWrite() once the queue drains.
    IoStatus flush();
    bool wantsWrite() const { return queuedBytes() > 0; }
    size_t queuedBytes() const { return queue_.size() - queue_head_; }
    void setWriteQueueLimit(size_t bytes) { queue_limit_ = bytes; }
    size_t writeQueueLimit() const { return queue_limit_; }

    /// Half-close (FIN) after the queued bytes are written; later send() returns kSendClosed.
    bool shutdownWrite();
    /// Closes immediately; queued bytes are dropped. Safe to call repeatedly.
    void close();
    /// SO_LINGER {1, 0} then close: the peer gets RST instead of FIN.
    void abort();

    bool setNoDelay(bool on);
    bool setKeepAlive(bool on);
    bool setLingerZero();

    bool isOpen() const { return handle_ != kInvalidSocket; }
    SocketHandle handle() const { return handle_; }
    const Address& peerAddress() const { return peer_; }
    /// Local address (queried from the socket).
    Address localAddress() const;

private:
    TcpConnection(const TcpConnection&) = delete;
    TcpConnection& operator=(const TcpConnection&) = delete;

    void compactQueue();

    SocketHandle handle_;
    Address peer_;
    bool connecting_;
    bool write_shutdown_requested_;
    bool write_shutdown_done_;
    std::vector<uint8_t> queue_;
    size_t queue_head_;
    size_t queue_limit_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_TCP_HPP
