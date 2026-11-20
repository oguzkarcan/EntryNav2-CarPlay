#include "carplay/platform/tcp.hpp"

#include <cstddef>

namespace carplay {
namespace platform {

const int TcpListener::kDefaultBacklog;
const size_t TcpConnection::kDefaultWriteQueueLimit;

// ------------------------------------------------------------------------------------------------
// TcpListener
// ------------------------------------------------------------------------------------------------

TcpListener::TcpListener() : handle_(kInvalidSocket), dual_stack_(false), filter_(NULL), filter_ctx_(NULL) {}

TcpListener::~TcpListener() { close(); }

void TcpListener::close() {
    socketClose(handle_);
    local_ = Address();
    dual_stack_ = false;
}

bool TcpListener::openBound(const Address& address, bool dual_stack, int backlog) {
    close();
    SocketHandle h = socketOpen(address.family(), kSockStream);
    if (h == kInvalidSocket) {
        return false;
    }
    bool ok = setReuseAddress(h);
    if (ok && address.family() == Address::kIPv6) {
        ok = setV6Only(h, !dual_stack);
    }
    ok = ok && socketBind(h, address) && socketListen(h, backlog > 0 ? backlog : kDefaultBacklog) &&
         socketLocalAddress(h, local_);
    if (!ok) {
        socketClose(h);
        local_ = Address();
        return false;
    }
    handle_ = h;
    dual_stack_ = dual_stack;
    return true;
}

bool TcpListener::listen(const Address& address, int backlog) {
    if (!address.valid()) {
        return false;
    }
    const bool dual = address.family() == Address::kIPv6 && address.isAny();
    return openBound(address, dual, backlog);
}

bool TcpListener::listenAny(uint16_t port, int backlog) {
    if (openBound(Address::ipv6Any(port), true, backlog)) {
        return true;
    }
    return openBound(Address::ipv4Any(port), false, backlog);
}

void TcpListener::setAcceptFilter(AcceptFilter filter, void* ctx) {
    filter_ = filter;
    filter_ctx_ = ctx;
}

TcpListener::AcceptResult TcpListener::accept(TcpConnection& out) {
    if (handle_ == kInvalidSocket) {
        return kAcceptError;
    }
    SocketHandle c = kInvalidSocket;
    Address peer;
    const IoStatus st = socketAccept(handle_, c, peer);
    if (st == kIoWouldBlock) {
        return kNoPending;
    }
    if (st != kIoOk) {
        return kAcceptError;
    }
    if (filter_ != NULL && !filter_(filter_ctx_, peer)) {
        setLingerZero(c);  // RST: the foreign peer learns nothing and no byte is read
        socketClose(c);
        return kRejected;
    }
    out.adopt(c, peer);
    return kAccepted;
}

// ------------------------------------------------------------------------------------------------
// TcpConnection
// ------------------------------------------------------------------------------------------------

TcpConnection::TcpConnection()
    : handle_(kInvalidSocket),
      connecting_(false),
      write_shutdown_requested_(false),
      write_shutdown_done_(false),
      queue_head_(0),
      queue_limit_(kDefaultWriteQueueLimit) {}

TcpConnection::~TcpConnection() { close(); }

void TcpConnection::close() {
    socketClose(handle_);
    peer_ = Address();
    connecting_ = false;
    write_shutdown_requested_ = false;
    write_shutdown_done_ = false;
    queue_.clear();
    queue_head_ = 0;
}

void TcpConnection::abort() {
    if (handle_ != kInvalidSocket) {
        platform::setLingerZero(handle_);
    }
    close();
}

void TcpConnection::adopt(SocketHandle handle, const Address& peer) {
    close();
    handle_ = handle;
    peer_ = peer;
}

bool TcpConnection::connect(const Address& remote) {
    close();
    if (!remote.valid()) {
        return false;
    }
    SocketHandle h = socketOpen(remote.family(), kSockStream);
    if (h == kInvalidSocket) {
        return false;
    }
    const IoStatus st = socketConnect(h, remote);
    if (st == kIoError) {
        socketClose(h);
        return false;
    }
    handle_ = h;
    peer_ = remote.unmapped();
    connecting_ = (st == kIoWouldBlock);
    return true;
}

IoStatus TcpConnection::finishConnect() {
    if (handle_ == kInvalidSocket) {
        return kIoError;
    }
    if (!connecting_) {
        return kIoOk;
    }
    int err = 0;
    if (!takeSocketError(handle_, err) || err != 0) {
        return kIoError;
    }
    Address peer;
    if (!socketPeerAddress(handle_, peer)) {
        // Not yet connected (spurious writability) or the attempt failed without SO_ERROR.
        return kIoWouldBlock;
    }
    connecting_ = false;
    return kIoOk;
}

IoStatus TcpConnection::read(uint8_t* buf, size_t cap, size_t& got) {
    got = 0;
    if (handle_ == kInvalidSocket) {
        return kIoClosed;
    }
    return socketRecv(handle_, buf, cap, got);
}

IoStatus TcpConnection::readAppend(std::vector<uint8_t>& out, size_t max_bytes) {
    if (max_bytes == 0) {
        return kIoOk;
    }
    const size_t old = out.size();
    out.resize(old + max_bytes);
    size_t got = 0;
    const IoStatus st = read(&out[old], max_bytes, got);
    out.resize(old + got);
    return st;
}

void TcpConnection::compactQueue() {
    if (queue_head_ == queue_.size()) {
        queue_.clear();
        queue_head_ = 0;
    } else if (queue_head_ > 4096 && queue_head_ * 2 > queue_.size()) {
        queue_.erase(queue_.begin(), queue_.begin() + static_cast<std::ptrdiff_t>(queue_head_));
        queue_head_ = 0;
    }
}

TcpConnection::SendResult TcpConnection::send(const uint8_t* data, size_t len) {
    if (handle_ == kInvalidSocket || write_shutdown_requested_) {
        return kSendClosed;
    }
    if (len == 0) {
        return kSendOk;
    }
    if (len > queue_limit_ || queuedBytes() > queue_limit_ - len) {
        return kSendOverflow;
    }
    size_t offset = 0;
    if (queuedBytes() == 0 && !connecting_) {
        while (offset < len) {
            size_t sent = 0;
            const IoStatus st = socketSend(handle_, data + offset, len - offset, sent);
            if (st == kIoWouldBlock) {
                break;
            }
            if (st != kIoOk) {
                return kSendError;
            }
            offset += sent;
        }
    }
    if (offset < len) {
        queue_.insert(queue_.end(), data + offset, data + len);
    }
    return kSendOk;
}

TcpConnection::SendResult TcpConnection::send(const std::vector<uint8_t>& data) {
    return data.empty() ? send(NULL, 0) : send(&data[0], data.size());
}

IoStatus TcpConnection::flush() {
    if (handle_ == kInvalidSocket) {
        return kIoError;
    }
    if (connecting_) {
        const IoStatus c = finishConnect();
        if (c != kIoOk) {
            return c;
        }
    }
    while (queuedBytes() > 0) {
        size_t sent = 0;
        const IoStatus st = socketSend(handle_, &queue_[queue_head_], queuedBytes(), sent);
        if (st == kIoWouldBlock) {
            compactQueue();
            return kIoWouldBlock;
        }
        if (st != kIoOk) {
            return kIoError;
        }
        queue_head_ += sent;
    }
    compactQueue();
    if (write_shutdown_requested_ && !write_shutdown_done_) {
        write_shutdown_done_ = true;
        if (!socketShutdownWrite(handle_)) {
            return kIoError;
        }
    }
    return kIoOk;
}

bool TcpConnection::shutdownWrite() {
    if (handle_ == kInvalidSocket) {
        return false;
    }
    write_shutdown_requested_ = true;
    if (queuedBytes() == 0 && !connecting_ && !write_shutdown_done_) {
        write_shutdown_done_ = true;
        return socketShutdownWrite(handle_);
    }
    return true;
}

bool TcpConnection::setNoDelay(bool on) { return handle_ != kInvalidSocket && platform::setNoDelay(handle_, on); }

bool TcpConnection::setKeepAlive(bool on) {
    return handle_ != kInvalidSocket && platform::setKeepAlive(handle_, on);
}

bool TcpConnection::setLingerZero() { return handle_ != kInvalidSocket && platform::setLingerZero(handle_); }

bool TcpConnection::setWifiVideoTos() {
    return handle_ != kInvalidSocket && platform::setWifiVideoTos(handle_);
}

Address TcpConnection::localAddress() const {
    Address a;
    if (handle_ != kInvalidSocket) {
        socketLocalAddress(handle_, a);
    }
    return a;
}

}  // namespace platform
}  // namespace carplay
