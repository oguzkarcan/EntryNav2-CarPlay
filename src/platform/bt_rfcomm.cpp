#include "carplay/platform/bt_rfcomm.hpp"

#include <stdio.h>
#include <string.h>

#include <algorithm>

#ifndef _WIN32
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#else
#include <errno.h>
#endif

#include "carplay/platform/log.hpp"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace carplay {
namespace platform {

namespace {

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

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

#ifndef _WIN32
bool setNonBlockingAndCloexec(int fd, int& err_out) {
    int flags = ::fcntl(fd, F_GETFD, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
        err_out = errno;
        return false;
    }
    flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        err_out = errno;
        return false;
    }
    return true;
}

bool isUnixSocketPath(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    struct stat st;
    return ::stat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode);
}
#endif

}  // namespace

// ------------------------------------------------------------------------------------------------
// BtAddr
// ------------------------------------------------------------------------------------------------

BtAddr::BtAddr() { memset(b, 0, sizeof(b)); }

BtAddr BtAddr::any() { return BtAddr(); }

bool BtAddr::parse(const std::string& text, BtAddr& out) {
    if (text.size() != 17U) {
        return false;
    }
    uint8_t parsed[6];
    for (size_t i = 0; i < 6U; ++i) {
        const size_t pos = i * 3U;
        if (i > 0U && text[pos - 1U] != ':') {
            return false;
        }
        const int hi = hexNibble(text[pos]);
        const int lo = hexNibble(text[pos + 1U]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        // Standard string is MSB-first; BlueZ bdaddr_t stores LSB-first.
        parsed[5U - i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    memcpy(out.b, parsed, 6);
    return true;
}

bool BtAddr::isZero() const {
    for (size_t i = 0; i < 6U; ++i) {
        if (b[i] != 0) {
            return false;
        }
    }
    return true;
}

std::string BtAddr::toString() const {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             b[5], b[4], b[3], b[2], b[1], b[0]);
    return std::string(buf);
}

bool BtAddr::operator==(const BtAddr& other) const {
    return memcmp(b, other.b, sizeof(b)) == 0;
}

// ------------------------------------------------------------------------------------------------
// PosixBtSocketOps
// ------------------------------------------------------------------------------------------------

SocketHandle PosixBtSocketOps::createRfcommSocket(int& err_out) {
#ifdef _WIN32
    err_out = EAFNOSUPPORT;
    return kInvalidSocket;
#else
    const int fd = ::socket(kAfBluetooth, SOCK_STREAM, kBtProtoRfcomm);
    if (fd < 0) {
        err_out = errno;
        return kInvalidSocket;
    }
    if (!setNonBlockingAndCloexec(fd, err_out)) {
        ::close(fd);
        return kInvalidSocket;
    }
    err_out = 0;
    return fd;
#endif
}

bool PosixBtSocketOps::bindRfcomm(SocketHandle fd,
                                  const BtAddr& addr,
                                  uint8_t channel,
                                  int& err_out) {
#ifdef _WIN32
    (void)fd;
    (void)addr;
    (void)channel;
    err_out = EAFNOSUPPORT;
    return false;
#else
    SockAddrRc rc;
    memset(&rc, 0, sizeof(rc));
    rc.rc_family = static_cast<uint16_t>(kAfBluetooth);
    memcpy(rc.rc_bdaddr, addr.b, 6);
    rc.rc_channel = channel;
    if (::bind(fd, reinterpret_cast<const struct sockaddr*>(&rc),
               static_cast<socklen_t>(sizeof(rc))) != 0) {
        err_out = errno;
        return false;
    }
    err_out = 0;
    return true;
#endif
}

bool PosixBtSocketOps::getRfcommChannel(SocketHandle fd, uint8_t& channel_out, int& err_out) {
#ifdef _WIN32
    (void)fd;
    channel_out = 0;
    err_out = EAFNOSUPPORT;
    return false;
#else
    SockAddrRc rc;
    memset(&rc, 0, sizeof(rc));
    socklen_t len = static_cast<socklen_t>(sizeof(rc));
    if (::getsockname(fd, reinterpret_cast<struct sockaddr*>(&rc), &len) != 0) {
        err_out = errno;
        return false;
    }
    if (len < 9 || rc.rc_family != static_cast<uint16_t>(kAfBluetooth)) {
        err_out = EINVAL;
        return false;
    }
    channel_out = rc.rc_channel;
    err_out = 0;
    return true;
#endif
}

bool PosixBtSocketOps::listenSocket(SocketHandle fd, int backlog, int& err_out) {
#ifdef _WIN32
    (void)fd;
    (void)backlog;
    err_out = EAFNOSUPPORT;
    return false;
#else
    if (::listen(fd, backlog) != 0) {
        err_out = errno;
        return false;
    }
    err_out = 0;
    return true;
#endif
}

IoStatus PosixBtSocketOps::acceptRfcomm(SocketHandle listen_fd,
                                        SocketHandle& client_fd_out,
                                        BtAddr& peer_addr_out,
                                        uint8_t& peer_channel_out,
                                        int& err_out) {
    client_fd_out = kInvalidSocket;
    peer_addr_out = BtAddr::any();
    peer_channel_out = 0;
#ifdef _WIN32
    (void)listen_fd;
    err_out = EAFNOSUPPORT;
    return kIoError;
#else
    SockAddrRc rc;
    socklen_t len;
    int fd = -1;
    for (;;) {
        memset(&rc, 0, sizeof(rc));
        len = static_cast<socklen_t>(sizeof(rc));
        fd = ::accept(listen_fd, reinterpret_cast<struct sockaddr*>(&rc), &len);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                err_out = 0;
                return kIoWouldBlock;
            }
            err_out = errno;
            return kIoError;
        }
        break;
    }
    if (!setNonBlockingAndCloexec(fd, err_out)) {
        ::close(fd);
        return kIoError;
    }
    if (len >= 9 && rc.rc_family == static_cast<uint16_t>(kAfBluetooth)) {
        memcpy(peer_addr_out.b, rc.rc_bdaddr, 6);
        peer_channel_out = rc.rc_channel;
    }
    client_fd_out = fd;
    err_out = 0;
    return kIoOk;
#endif
}

IoStatus PosixBtSocketOps::recvBytes(SocketHandle fd,
                                     uint8_t* buf,
                                     size_t cap,
                                     size_t& got_out,
                                     int& err_out) {
    got_out = 0;
#ifdef _WIN32
    (void)fd;
    (void)buf;
    (void)cap;
    err_out = EAFNOSUPPORT;
    return kIoError;
#else
    if (cap == 0) {
        err_out = 0;
        return kIoOk;
    }
    for (;;) {
        const ssize_t n = ::recv(fd, buf, cap, 0);
        if (n > 0) {
            got_out = static_cast<size_t>(n);
            err_out = 0;
            return kIoOk;
        }
        if (n == 0) {
            err_out = 0;
            return kIoClosed;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            err_out = 0;
            return kIoWouldBlock;
        }
        err_out = errno;
        return kIoError;
    }
#endif
}

IoStatus PosixBtSocketOps::sendBytes(SocketHandle fd,
                                     const uint8_t* data,
                                     size_t len,
                                     size_t& sent_out,
                                     int& err_out) {
    sent_out = 0;
#ifdef _WIN32
    (void)fd;
    (void)data;
    (void)len;
    err_out = EAFNOSUPPORT;
    return kIoError;
#else
    if (len == 0) {
        err_out = 0;
        return kIoOk;
    }
    for (;;) {
        const ssize_t n = ::send(fd, data, len, MSG_NOSIGNAL);
        if (n > 0) {
            sent_out = static_cast<size_t>(n);
            err_out = 0;
            return kIoOk;
        }
        if (n == 0) {
            err_out = EPIPE;
            return kIoError;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            err_out = 0;
            return kIoWouldBlock;
        }
        err_out = errno;
        return kIoError;
    }
#endif
}

void PosixBtSocketOps::closeSocket(SocketHandle fd) {
    if (fd == kInvalidSocket) {
        return;
    }
#ifndef _WIN32
    ::close(fd);
#endif
}

std::string PosixBtSocketOps::errorString(int err) const {
    return socketErrorString(err);
}

// ------------------------------------------------------------------------------------------------
// BtRfcommServer
// ------------------------------------------------------------------------------------------------

BtRfcommServer::BtRfcommServer(Reactor& reactor,
                               BtRfcommListener& listener,
                               const BtRfcommConfig& config,
                               BtSocketOps* ops)
    : reactor_(reactor),
      listener_(&listener),
      config_(config),
      ops_(ops != NULL ? ops : &default_ops_),
      listen_handler_(this),
      client_handler_(this),
      listen_fd_(kInvalidSocket),
      bound_channel_(0),
      client_fd_(kInvalidSocket),
      peer_channel_(0),
      client_gen_(0),
      write_head_(0),
      read_buf_(config.read_chunk_size > 0 ? config.read_chunk_size : 4096U) {}

BtRfcommServer::~BtRfcommServer() {
    listener_ = NULL;
    stop();
}

bool BtRfcommServer::start(std::string* error_out) {
    stop();

    int err = 0;
    SocketHandle fd = ops_->createRfcommSocket(err);
    if (fd == kInvalidSocket) {
        const std::string msg = "RFCOMM socket() failed: " + ops_->errorString(err);
        setError(error_out, msg);
        CARPLAY_LOG_WARN("bt", "%s", msg.c_str());
        return false;
    }

    if (!ops_->bindRfcomm(fd, config_.local_addr, config_.channel, err)) {
        const std::string msg = "RFCOMM bind() failed: " + ops_->errorString(err);
        ops_->closeSocket(fd);
        setError(error_out, msg);
        CARPLAY_LOG_WARN("bt", "%s", msg.c_str());
        return false;
    }

    const int backlog = config_.backlog > 0 ? config_.backlog : 4;
    if (!ops_->listenSocket(fd, backlog, err)) {
        const std::string msg = "RFCOMM listen() failed: " + ops_->errorString(err);
        ops_->closeSocket(fd);
        setError(error_out, msg);
        CARPLAY_LOG_WARN("bt", "%s", msg.c_str());
        return false;
    }

    // Query bound channel AFTER listen(): Linux rfcomm_sock_bind() leaves rc_channel=0
    // and rfcomm_sock_listen() assigns the dynamic channel (1..30).
    uint8_t actual_channel = config_.channel;
    if (!ops_->getRfcommChannel(fd, actual_channel, err)) {
        const std::string msg = "RFCOMM getsockname() failed: " + ops_->errorString(err);
        ops_->closeSocket(fd);
        setError(error_out, msg);
        CARPLAY_LOG_WARN("bt", "%s", msg.c_str());
        return false;
    }

    if (!reactor_.add(fd, &listen_handler_, kPollIn)) {
        ops_->closeSocket(fd);
        const std::string msg = "RFCOMM reactor_.add() failed";
        setError(error_out, msg);
        CARPLAY_LOG_ERROR("bt", "%s", msg.c_str());
        return false;
    }

    listen_fd_ = fd;
    bound_channel_ = actual_channel;
    CARPLAY_LOG_INFO("bt", "RFCOMM server listening on channel %u",
                     static_cast<unsigned>(bound_channel_));
    return true;
}

void BtRfcommServer::stop() {
    closeClient(true, "server stopped");
    if (listen_fd_ != kInvalidSocket) {
        reactor_.remove(listen_fd_);
        ops_->closeSocket(listen_fd_);
        listen_fd_ = kInvalidSocket;
    }
    bound_channel_ = 0;
}

void BtRfcommServer::disconnect(const std::string& reason) {
    closeClient(true, reason);
}

BtRfcommServer::SendResult BtRfcommServer::send(const uint8_t* data, size_t len) {
    if (client_fd_ == kInvalidSocket) {
        return kSendClosed;
    }
    if (len == 0) {
        return kSendOk;
    }
    if (len > config_.write_queue_limit ||
        queuedBytes() > config_.write_queue_limit - len) {
        return kSendOverflow;
    }

    size_t offset = 0;
    if (queuedBytes() == 0) {
        while (offset < len) {
            size_t sent = 0;
            int err = 0;
            const IoStatus st = ops_->sendBytes(client_fd_, data + offset, len - offset, sent, err);
            if (st == kIoWouldBlock) {
                break;
            }
            if (st != kIoOk) {
                closeClient(true, "write error: " + ops_->errorString(err));
                return kSendError;
            }
            offset += sent;
        }
    }

    if (offset < len) {
        write_queue_.insert(write_queue_.end(), data + offset, data + len);
        updateClientInterest();
    }
    return kSendOk;
}

BtRfcommServer::SendResult BtRfcommServer::send(const std::vector<uint8_t>& data) {
    return data.empty() ? send(NULL, 0) : send(&data[0], data.size());
}

void BtRfcommServer::onListenReadable() {
    static const size_t kMaxAcceptsPerWakeup = 8U;
    for (size_t i = 0; i < kMaxAcceptsPerWakeup && listen_fd_ != kInvalidSocket; ++i) {
        SocketHandle new_fd = kInvalidSocket;
        BtAddr peer;
        uint8_t peer_ch = 0;
        int err = 0;
        const IoStatus st = ops_->acceptRfcomm(listen_fd_, new_fd, peer, peer_ch, err);
        if (st == kIoWouldBlock) {
            break;
        }
        if (st != kIoOk) {
            CARPLAY_LOG_WARN("bt", "RFCOMM accept error: %s", ops_->errorString(err).c_str());
            break;
        }

        if (client_fd_ != kInvalidSocket) {
            if (!config_.replace_active_connection) {
                CARPLAY_LOG_INFO("bt", "RFCOMM rejecting second peer %s (session already active)",
                                 peer.toString().c_str());
                ops_->closeSocket(new_fd);
                continue;
            }
            closeClient(true, "replaced by new connection");
            if (listen_fd_ == kInvalidSocket) {
                ops_->closeSocket(new_fd);
                return;
            }
        }

        adoptClient(new_fd, peer, peer_ch);
    }
}

void BtRfcommServer::onListenError() {
    CARPLAY_LOG_ERROR("bt", "RFCOMM listener socket error; stopping listener");
    stop();
}

void BtRfcommServer::adoptClient(SocketHandle fd, const BtAddr& peer, uint8_t channel) {
    if (!reactor_.add(fd, &client_handler_, kPollIn)) {
        CARPLAY_LOG_ERROR("bt", "RFCOMM failed to register accepted client with Reactor");
        ops_->closeSocket(fd);
        return;
    }
    client_fd_ = fd;
    peer_addr_ = peer;
    peer_channel_ = channel;
    ++client_gen_;
    write_queue_.clear();
    write_head_ = 0;

    CARPLAY_LOG_INFO("bt", "RFCOMM connected from %s (ch %u)",
                     peer.toString().c_str(), static_cast<unsigned>(channel));
    if (listener_ != NULL) {
        listener_->onBtConnected(peer_addr_, peer_channel_);
    }
}

void BtRfcommServer::closeClient(bool notify_listener, const std::string& reason) {
    if (client_fd_ == kInvalidSocket) {
        return;
    }
    reactor_.remove(client_fd_);
    ops_->closeSocket(client_fd_);
    client_fd_ = kInvalidSocket;
    peer_addr_ = BtAddr::any();
    peer_channel_ = 0;
    ++client_gen_;
    write_queue_.clear();
    write_head_ = 0;

    if (notify_listener && listener_ != NULL) {
        listener_->onBtDisconnected(reason);
    }
}

void BtRfcommServer::compactWriteQueue() {
    if (write_head_ == write_queue_.size()) {
        write_queue_.clear();
        write_head_ = 0;
    } else if (write_head_ > 4096U && write_head_ * 2U > write_queue_.size()) {
        write_queue_.erase(
            write_queue_.begin(),
            write_queue_.begin() + static_cast<std::ptrdiff_t>(write_head_));
        write_head_ = 0;
    }
}

void BtRfcommServer::updateClientInterest() {
    if (client_fd_ == kInvalidSocket) {
        return;
    }
    const unsigned interest = queuedBytes() > 0 ? (kPollIn | kPollOut) : kPollIn;
    reactor_.modify(client_fd_, interest);
}

void BtRfcommServer::onClientReadable() {
    static const size_t kMaxReadsPerWakeup = 16U;
    const uint32_t gen = client_gen_;

    for (size_t i = 0; i < kMaxReadsPerWakeup; ++i) {
        if (client_fd_ == kInvalidSocket || client_gen_ != gen) {
            return;
        }
        size_t got = 0;
        int err = 0;
        const IoStatus st = ops_->recvBytes(client_fd_, &read_buf_[0], read_buf_.size(), got, err);
        if (st == kIoOk) {
            if (got > 0 && listener_ != NULL) {
                listener_->onBtData(&read_buf_[0], got);
            }
            if (client_fd_ == kInvalidSocket || client_gen_ != gen) {
                return;
            }
            continue;
        }
        if (st == kIoWouldBlock) {
            break;
        }
        if (st == kIoClosed) {
            closeClient(true, "peer closed");
            return;
        }
        closeClient(true, "read error: " + ops_->errorString(err));
        return;
    }
}

void BtRfcommServer::onClientWritable() {
    if (client_fd_ == kInvalidSocket) {
        return;
    }
    while (queuedBytes() > 0) {
        size_t sent = 0;
        int err = 0;
        const IoStatus st = ops_->sendBytes(client_fd_, &write_queue_[write_head_], queuedBytes(), sent, err);
        if (st == kIoWouldBlock) {
            compactWriteQueue();
            updateClientInterest();
            return;
        }
        if (st != kIoOk) {
            closeClient(true, "write error: " + ops_->errorString(err));
            return;
        }
        write_head_ += sent;
    }
    compactWriteQueue();
    updateClientInterest();
}

void BtRfcommServer::onClientError() {
    closeClient(true, "socket error");
}

// ------------------------------------------------------------------------------------------------
// Runtime Capability Probe
// ------------------------------------------------------------------------------------------------

BtProbePaths::BtProbePaths()
    : sys_class_bluetooth("/sys/class/bluetooth"),
      sdpd_socket("/var/run/sdp"),
      bluetoothd_socket("/var/run/bluetoothd"),
      dbus_socket("/var/run/dbus/system_bus_socket"),
      probe_af_bluetooth(true) {
    libbluetooth_candidates.push_back("libbluetooth.so.3");
    libbluetooth_candidates.push_back("libbluetooth.so");
    libdbus_candidates.push_back("libdbus-1.so.3");
    libdbus_candidates.push_back("libdbus-1.so");
}

BtCapability probeBtCapability() {
    return probeBtCapability(BtProbePaths());
}

BtCapability probeBtCapability(const BtProbePaths& paths) {
    BtCapability cap;

#ifdef _WIN32
    (void)paths;
    cap.af_bluetooth_supported = false;
    cap.af_bluetooth_errno = EAFNOSUPPORT;
#else
    if (paths.probe_af_bluetooth) {
        const int fd = ::socket(kAfBluetooth, SOCK_STREAM, kBtProtoRfcomm);
        if (fd >= 0) {
            ::close(fd);
            cap.af_bluetooth_supported = true;
            cap.af_bluetooth_errno = 0;
        } else {
            cap.af_bluetooth_supported = false;
            cap.af_bluetooth_errno = errno;
        }
    }

    if (!paths.sys_class_bluetooth.empty()) {
        DIR* dir = ::opendir(paths.sys_class_bluetooth.c_str());
        if (dir != NULL) {
            struct dirent* ent = NULL;
            while ((ent = ::readdir(dir)) != NULL) {
                if (strncmp(ent->d_name, "hci", 3) == 0 &&
                    ent->d_name[3] >= '0' && ent->d_name[3] <= '9' &&
                    strchr(ent->d_name, ':') == NULL) {
                    cap.hci_devices.push_back(ent->d_name);
                }
            }
            ::closedir(dir);
            std::sort(cap.hci_devices.begin(), cap.hci_devices.end());
            cap.has_hci_device = !cap.hci_devices.empty();
        }
    }

    cap.sdpd_socket_present = isUnixSocketPath(paths.sdpd_socket);
    cap.bluetoothd_socket_present = isUnixSocketPath(paths.bluetoothd_socket);
    cap.dbus_socket_present = isUnixSocketPath(paths.dbus_socket);

    for (size_t i = 0; i < paths.libbluetooth_candidates.size(); ++i) {
        const std::string& lib = paths.libbluetooth_candidates[i];
        if (lib.empty()) {
            continue;
        }
        void* handle = ::dlopen(lib.c_str(), RTLD_LAZY | RTLD_LOCAL);
        if (handle != NULL) {
            cap.libbluetooth_loadable = true;
            cap.libbluetooth_name = lib;
            ::dlclose(handle);
            break;
        }
    }

    for (size_t i = 0; i < paths.libdbus_candidates.size(); ++i) {
        const std::string& lib = paths.libdbus_candidates[i];
        if (lib.empty()) {
            continue;
        }
        void* handle = ::dlopen(lib.c_str(), RTLD_LAZY | RTLD_LOCAL);
        if (handle != NULL) {
            cap.libdbus_loadable = true;
            cap.libdbus_name = lib;
            ::dlclose(handle);
            break;
        }
    }
#endif

    return cap;
}

std::string formatBtCapability(const BtCapability& cap) {
    std::string hci_list = "none";
    if (!cap.hci_devices.empty()) {
        hci_list.clear();
        for (size_t i = 0; i < cap.hci_devices.size(); ++i) {
            if (i > 0) {
                hci_list += ",";
            }
            hci_list += cap.hci_devices[i];
        }
    }

    char af_buf[64];
    if (cap.af_bluetooth_supported) {
        snprintf(af_buf, sizeof(af_buf), "yes");
    } else {
        snprintf(af_buf, sizeof(af_buf), "no(errno=%d)", cap.af_bluetooth_errno);
    }

    char out[512];
    snprintf(out, sizeof(out),
             "af_bluetooth=%s hci=%s sdpd=%s bluetoothd=%s dbus=%s libbluetooth=%s libdbus=%s",
             af_buf,
             hci_list.c_str(),
             cap.sdpd_socket_present ? "yes" : "no",
             cap.bluetoothd_socket_present ? "yes" : "no",
             cap.dbus_socket_present ? "yes" : "no",
             cap.libbluetooth_loadable ? cap.libbluetooth_name.c_str() : "no",
             cap.libdbus_loadable ? cap.libdbus_name.c_str() : "no");
    return std::string(out);
}

void logBtCapability(const BtCapability& cap) {
    CARPLAY_LOG_INFO("bt", "capability: %s", formatBtCapability(cap).c_str());
}

// ------------------------------------------------------------------------------------------------
// BluezSdpdRegistrar
// ------------------------------------------------------------------------------------------------

BluezSdpdRegistrar::BluezSdpdRegistrar(const std::string& socket_path,
                                       int timeout_ms,
                                       const BtAddr& device_addr)
    : socket_path_(socket_path),
      timeout_ms_(timeout_ms > 0 ? timeout_ms : 2000),
      device_addr_(device_addr),
      next_tid_(1) {}

bool BluezSdpdRegistrar::isSupported() const {
#ifdef _WIN32
    return false;
#else
    return isUnixSocketPath(socket_path_);
#endif
}

bool BluezSdpdRegistrar::registerRecord(const std::vector<uint8_t>& encoded_record,
                                        uint32_t& handle_out) {
    handle_out = 0;
    last_error_.clear();

    if (!isSupported()) {
        last_error_ = "sdpd UNIX socket not present: " + socket_path_;
        return false;
    }

    const uint16_t tid = next_tid_++;
    if (next_tid_ == 0) {
        next_tid_ = 1;
    }

    std::vector<uint8_t> req;
    if (!sdp::encodeSdpdRegisterRequest(tid, encoded_record, req,
                                        device_addr_.b, 0x00U, &last_error_)) {
        return false;
    }

    std::vector<uint8_t> rsp;
    if (!exchangePdu(req, rsp)) {
        return false;
    }

    const uint8_t* ptr = rsp.empty() ? NULL : &rsp[0];
    return sdp::parseSdpdRegisterResponse(ptr, rsp.size(), tid, handle_out, NULL, &last_error_);
}

bool BluezSdpdRegistrar::unregisterRecord(uint32_t handle) {
    last_error_.clear();

    if (!isSupported()) {
        last_error_ = "sdpd UNIX socket not present: " + socket_path_;
        return false;
    }

    const uint16_t tid = next_tid_++;
    if (next_tid_ == 0) {
        next_tid_ = 1;
    }

    std::vector<uint8_t> req;
    sdp::encodeSdpdRemoveRequest(tid, handle, req);

    std::vector<uint8_t> rsp;
    if (!exchangePdu(req, rsp)) {
        return false;
    }

    const uint8_t* ptr = rsp.empty() ? NULL : &rsp[0];
    return sdp::parseSdpdRemoveResponse(ptr, rsp.size(), tid, NULL, &last_error_);
}

bool BluezSdpdRegistrar::exchangePdu(const std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response_out) {
    response_out.clear();
#ifdef _WIN32
    (void)request;
    last_error_ = "sdpd UNIX socket unsupported on Windows";
    return false;
#else
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    if (socket_path_.empty() || socket_path_.size() >= sizeof(addr.sun_path)) {
        last_error_ = "invalid sdpd socket path";
        return false;
    }

    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        last_error_ = "socket(AF_UNIX) failed: " + socketErrorString(errno);
        return false;
    }

    int err = 0;
    if (!setNonBlockingAndCloexec(fd, err)) {
        ::close(fd);
        last_error_ = "fcntl(sdpd) failed: " + socketErrorString(err);
        return false;
    }

    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, socket_path_.data(), socket_path_.size());

    const int64_t deadline = monotonicMillis() + timeout_ms_;

    if (::connect(fd, reinterpret_cast<const struct sockaddr*>(&addr),
                  static_cast<socklen_t>(sizeof(addr))) != 0) {
        if (errno != EINPROGRESS && errno != EAGAIN) {
            last_error_ = "connect(" + socket_path_ + ") failed: " + socketErrorString(errno);
            ::close(fd);
            return false;
        }
        for (;;) {
            const int64_t rem = deadline - monotonicMillis();
            if (rem <= 0) {
                last_error_ = "connect(" + socket_path_ + ") timed out";
                ::close(fd);
                return false;
            }
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            const int prc = ::poll(&pfd, 1, static_cast<int>(rem));
            if (prc < 0) {
                if (errno == EINTR) {
                    continue;
                }
                last_error_ = "poll(connect) failed: " + socketErrorString(errno);
                ::close(fd);
                return false;
            }
            if (prc == 0) {
                last_error_ = "connect(" + socket_path_ + ") timed out";
                ::close(fd);
                return false;
            }
            int so_err = 0;
            socklen_t slen = sizeof(so_err);
            if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &slen) != 0 || so_err != 0) {
                last_error_ = "connect(" + socket_path_ + ") error: " +
                              socketErrorString(so_err != 0 ? so_err : errno);
                ::close(fd);
                return false;
            }
            break;
        }
    }

    // Send full request.
    size_t sent_total = 0;
    while (sent_total < request.size()) {
        const int64_t rem = deadline - monotonicMillis();
        if (rem <= 0) {
            last_error_ = "sdpd write timed out";
            ::close(fd);
            return false;
        }
        const ssize_t n = ::send(fd, &request[sent_total], request.size() - sent_total, MSG_NOSIGNAL);
        if (n > 0) {
            sent_total += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            const int prc = ::poll(&pfd, 1, static_cast<int>(rem));
            if (prc < 0 && errno == EINTR) {
                continue;
            }
            if (prc <= 0) {
                last_error_ = prc == 0 ? "sdpd write timed out"
                                       : ("poll(write) failed: " + socketErrorString(errno));
                ::close(fd);
                return false;
            }
            continue;
        }
        last_error_ = "sdpd write failed: " + socketErrorString(errno);
        ::close(fd);
        return false;
    }

    // Read 5-byte SDP PDU header + payload.
    uint8_t hdr[5];
    size_t got_total = 0;
    size_t expected_total = 5U;
    response_out.resize(5U);

    while (got_total < expected_total) {
        const int64_t rem = deadline - monotonicMillis();
        if (rem <= 0) {
            last_error_ = "sdpd read timed out";
            ::close(fd);
            return false;
        }
        const ssize_t n = ::recv(fd, &response_out[got_total], expected_total - got_total, 0);
        if (n > 0) {
            got_total += static_cast<size_t>(n);
            if (expected_total == 5U && got_total == 5U) {
                memcpy(hdr, &response_out[0], 5);
                const uint16_t plen = static_cast<uint16_t>(
                    (static_cast<uint16_t>(hdr[3]) << 8) | static_cast<uint16_t>(hdr[4]));
                if (plen > 1024U) {
                    last_error_ = "sdpd response payload too large";
                    ::close(fd);
                    return false;
                }
                expected_total = 5U + plen;
                response_out.resize(expected_total);
            }
            continue;
        }
        if (n == 0) {
            last_error_ = "sdpd closed connection prematurely";
            ::close(fd);
            return false;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            const int prc = ::poll(&pfd, 1, static_cast<int>(rem));
            if (prc < 0 && errno == EINTR) {
                continue;
            }
            if (prc <= 0) {
                last_error_ = prc == 0 ? "sdpd read timed out"
                                       : ("poll(read) failed: " + socketErrorString(errno));
                ::close(fd);
                return false;
            }
            continue;
        }
        last_error_ = "sdpd read failed: " + socketErrorString(errno);
        ::close(fd);
        return false;
    }

    ::close(fd);
    return true;
#endif
}

std::unique_ptr<sdp::SdpRegistrar> createBtSdpRegistrar(const BtCapability& cap,
                                                        const std::string& sdp_socket_path) {
    if (cap.sdpd_socket_present) {
        return std::unique_ptr<sdp::SdpRegistrar>(new BluezSdpdRegistrar(sdp_socket_path));
    }
    return std::unique_ptr<sdp::SdpRegistrar>(new sdp::NoopSdpRegistrar());
}

}  // namespace platform
}  // namespace carplay
