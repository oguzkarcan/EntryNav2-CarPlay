#ifndef CARPLAY_PLATFORM_BT_RFCOMM_HPP
#define CARPLAY_PLATFORM_BT_RFCOMM_HPP

// Bluetooth RFCOMM server transport, runtime capability probe, and BlueZ 4 sdpd
// registration backend for wireless CarPlay iAP2.
//
// Design constraints:
//   * Zero link-time dependency on libbluetooth or <bluetooth/*.h> headers (the CI
//     containers and target SDK do not carry them). Kernel AF_BLUETOOTH (31),
//     BTPROTO_RFCOMM (3), and Linux `struct sockaddr_rc` are defined locally.
//   * Non-blocking I/O integrated with the single-threaded `Reactor` (`IoHandler`).
//   * Socket syscalls are abstracted behind `BtSocketOps` so the server state machine
//     (accept, single active connection, read, partial write, write-queue back-pressure,
//     disconnect, reconnect) is unit-tested on the host with a socketpair-backed fake.
//   * Runtime capability probe (`probeBtCapability()`) inspects AF_BLUETOOTH socket
//     creation, /sys/class/bluetooth HCI devices, sdpd/bluetoothd/dbus UNIX sockets,
//     and dlopen("libbluetooth.so.3") without modifying system state.
//
// Threading & lifetime: `BtRfcommServer` belongs to the reactor thread only (same model
// as `SessionServer`). Destroy or call `stop()` before destroying `Reactor` or the
// `BtRfcommListener`.

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/sdp_record.hpp"

namespace carplay {
namespace platform {

static const int kAfBluetooth = 31;
static const int kBtProtoRfcomm = 3;

/// Bluetooth device address (6 bytes in BlueZ kernel `bdaddr_t` LSB-first order:
/// string "AA:BB:CC:DD:EE:FF" maps to b[5]=0xAA, ..., b[0]=0xFF).
struct BtAddr {
    uint8_t b[6];

    BtAddr();
    static BtAddr any();
    static bool parse(const std::string& text, BtAddr& out);

    bool isZero() const;
    std::string toString() const;
    bool operator==(const BtAddr& other) const;
    bool operator!=(const BtAddr& other) const { return !(*this == other); }
};

/// Binary-compatible with Linux kernel `struct sockaddr_rc` (<bluetooth/rfcomm.h>):
/// sa_family_t (uint16_t) + bdaddr_t (6B) + uint8_t rc_channel + 1B tail alignment pad.
struct SockAddrRc {
    uint16_t rc_family;
    uint8_t rc_bdaddr[6];
    uint8_t rc_channel;
    uint8_t rc_pad;
};

static_assert(sizeof(SockAddrRc) == 10, "SockAddrRc must match Linux struct sockaddr_rc (10 bytes)");

// ------------------------------------------------------------------------------------------------
// Socket Syscall Abstraction (for host unit testing without AF_BLUETOOTH kernel support)
// ------------------------------------------------------------------------------------------------

class BtSocketOps {
public:
    virtual ~BtSocketOps() {}

    /// Creates a non-blocking, close-on-exec RFCOMM stream socket.
    virtual SocketHandle createRfcommSocket(int& err_out) = 0;
    virtual bool bindRfcomm(SocketHandle fd,
                            const BtAddr& addr,
                            uint8_t channel,
                            int& err_out) = 0;
    virtual bool getRfcommChannel(SocketHandle fd, uint8_t& channel_out, int& err_out) = 0;
    virtual bool listenSocket(SocketHandle fd, int backlog, int& err_out) = 0;
    virtual IoStatus acceptRfcomm(SocketHandle listen_fd,
                                  SocketHandle& client_fd_out,
                                  BtAddr& peer_addr_out,
                                  uint8_t& peer_channel_out,
                                  int& err_out) = 0;
    virtual IoStatus recvBytes(SocketHandle fd,
                               uint8_t* buf,
                               size_t cap,
                               size_t& got_out,
                               int& err_out) = 0;
    virtual IoStatus sendBytes(SocketHandle fd,
                               const uint8_t* data,
                               size_t len,
                               size_t& sent_out,
                               int& err_out) = 0;
    virtual void closeSocket(SocketHandle fd) = 0;
    virtual std::string errorString(int err) const = 0;
};

/// Real POSIX AF_BLUETOOTH / BTPROTO_RFCOMM implementation (fails with EAFNOSUPPORT on Windows).
class PosixBtSocketOps : public BtSocketOps {
public:
    virtual SocketHandle createRfcommSocket(int& err_out);
    virtual bool bindRfcomm(SocketHandle fd,
                            const BtAddr& addr,
                            uint8_t channel,
                            int& err_out);
    virtual bool getRfcommChannel(SocketHandle fd, uint8_t& channel_out, int& err_out);
    virtual bool listenSocket(SocketHandle fd, int backlog, int& err_out);
    virtual IoStatus acceptRfcomm(SocketHandle listen_fd,
                                  SocketHandle& client_fd_out,
                                  BtAddr& peer_addr_out,
                                  uint8_t& peer_channel_out,
                                  int& err_out);
    virtual IoStatus recvBytes(SocketHandle fd,
                               uint8_t* buf,
                               size_t cap,
                               size_t& got_out,
                               int& err_out);
    virtual IoStatus sendBytes(SocketHandle fd,
                               const uint8_t* data,
                               size_t len,
                               size_t& sent_out,
                               int& err_out);
    virtual void closeSocket(SocketHandle fd);
    virtual std::string errorString(int err) const;
};

// ------------------------------------------------------------------------------------------------
// BtRfcommServer
// ------------------------------------------------------------------------------------------------

struct BtRfcommConfig {
    /// RFCOMM channel to bind (0 = dynamic kernel allocation 1..30; 1..30 = fixed channel).
    uint8_t channel;
    /// Local adapter address (all zero = BDADDR_ANY).
    BtAddr local_addr;
    /// listen() backlog.
    int backlog;
    /// Maximum outbound write-queue bytes before send() returns kSendOverflow.
    size_t write_queue_limit;
    /// Read buffer size per recv() call.
    size_t read_chunk_size;
    /// If false (default), incoming connections while a client is active are closed
    /// immediately (single active connection). If true, a new peer replaces the old one.
    bool replace_active_connection;

    BtRfcommConfig()
        : channel(0),
          local_addr(BtAddr::any()),
          backlog(4),
          write_queue_limit(256U * 1024U),
          read_chunk_size(4096U),
          replace_active_connection(false) {}
};

class BtRfcommListener {
public:
    virtual ~BtRfcommListener() {}
    virtual void onBtConnected(const BtAddr& peer, uint8_t channel) = 0;
    virtual void onBtData(const uint8_t* data, size_t len) = 0;
    virtual void onBtDisconnected(const std::string& reason) = 0;
};

class BtRfcommServer {
public:
    enum SendResult {
        kSendOk = 0,
        kSendOverflow = 1,  // write_queue_limit would be exceeded; nothing sent or queued
        kSendClosed = 2,    // no active client connection
        kSendError = 3      // socket write failed; connection was closed
    };

    BtRfcommServer(Reactor& reactor,
                   BtRfcommListener& listener,
                   const BtRfcommConfig& config = BtRfcommConfig(),
                   BtSocketOps* ops = NULL);
    ~BtRfcommServer();

    /// Binds and listens on the configured RFCOMM channel, registering with Reactor.
    bool start(std::string* error_out = NULL);
    /// Disconnects any active client and closes the listening socket.
    void stop();

    /// Closes the active client connection (notifying listener once if connected)
    /// while keeping the listening socket open for subsequent reconnects.
    void disconnect(const std::string& reason = "local disconnect");

    /// All-or-nothing send: queues unsent remainder and enables kPollOut until drained.
    SendResult send(const uint8_t* data, size_t len);
    SendResult send(const std::vector<uint8_t>& data);

    void setListener(BtRfcommListener* listener) { listener_ = listener; }

    bool isListening() const { return listen_fd_ != kInvalidSocket; }
    bool isConnected() const { return client_fd_ != kInvalidSocket; }
    uint8_t boundChannel() const { return bound_channel_; }
    const BtAddr& peerAddress() const { return peer_addr_; }
    uint8_t peerChannel() const { return peer_channel_; }
    size_t queuedBytes() const { return write_queue_.size() - write_head_; }
    SocketHandle listenHandle() const { return listen_fd_; }
    SocketHandle clientHandle() const { return client_fd_; }

private:
    BtRfcommServer(const BtRfcommServer&) = delete;
    BtRfcommServer& operator=(const BtRfcommServer&) = delete;

    class ListenIoHandler : public IoHandler {
    public:
        explicit ListenIoHandler(BtRfcommServer* owner) : owner_(owner) {}
        virtual void onReadable() { owner_->onListenReadable(); }
        virtual void onError() { owner_->onListenError(); }

    private:
        BtRfcommServer* owner_;
    };

    class ClientIoHandler : public IoHandler {
    public:
        explicit ClientIoHandler(BtRfcommServer* owner) : owner_(owner) {}
        virtual void onReadable() { owner_->onClientReadable(); }
        virtual void onWritable() { owner_->onClientWritable(); }
        virtual void onError() { owner_->onClientError(); }

    private:
        BtRfcommServer* owner_;
    };

    void onListenReadable();
    void onListenError();
    void onClientReadable();
    void onClientWritable();
    void onClientError();

    void adoptClient(SocketHandle fd, const BtAddr& peer, uint8_t channel);
    void closeClient(bool notify_listener, const std::string& reason);
    void compactWriteQueue();
    void updateClientInterest();

    Reactor& reactor_;
    BtRfcommListener* listener_;
    BtRfcommConfig config_;
    PosixBtSocketOps default_ops_;
    BtSocketOps* ops_;

    ListenIoHandler listen_handler_;
    ClientIoHandler client_handler_;

    SocketHandle listen_fd_;
    uint8_t bound_channel_;
    SocketHandle client_fd_;
    BtAddr peer_addr_;
    uint8_t peer_channel_;
    uint32_t client_gen_;

    std::vector<uint8_t> write_queue_;
    size_t write_head_;
    std::vector<uint8_t> read_buf_;
};

// ------------------------------------------------------------------------------------------------
// Runtime Bluetooth Capability Probe
// ------------------------------------------------------------------------------------------------

struct BtProbePaths {
    std::string sys_class_bluetooth;
    std::string sdpd_socket;
    std::string bluetoothd_socket;
    std::string dbus_socket;
    std::vector<std::string> libbluetooth_candidates;
    bool probe_af_bluetooth;

    BtProbePaths();
};

struct BtCapability {
    bool af_bluetooth_supported;
    int af_bluetooth_errno;
    bool has_hci_device;
    std::vector<std::string> hci_devices;
    bool sdpd_socket_present;
    bool bluetoothd_socket_present;
    bool dbus_socket_present;
    bool libbluetooth_loadable;
    std::string libbluetooth_name;

    BtCapability()
        : af_bluetooth_supported(false),
          af_bluetooth_errno(0),
          has_hci_device(false),
          sdpd_socket_present(false),
          bluetoothd_socket_present(false),
          dbus_socket_present(false),
          libbluetooth_loadable(false) {}

    bool rfcommSocketCapable() const { return af_bluetooth_supported && has_hci_device; }
};

BtCapability probeBtCapability();
BtCapability probeBtCapability(const BtProbePaths& paths);
std::string formatBtCapability(const BtCapability& cap);
void logBtCapability(const BtCapability& cap);

// ------------------------------------------------------------------------------------------------
// BlueZ 4 Legacy `sdpd` UNIX Socket Registrar + Runtime Selector
// ------------------------------------------------------------------------------------------------

class BluezSdpdRegistrar : public sdp::SdpRegistrar {
public:
    explicit BluezSdpdRegistrar(const std::string& socket_path = "/var/run/sdp",
                                int timeout_ms = 2000,
                                const BtAddr& device_addr = BtAddr::any());
    virtual ~BluezSdpdRegistrar() {}

    virtual const char* backendName() const { return "bluez-sdpd"; }
    virtual bool isSupported() const;
    virtual bool registerRecord(const std::vector<uint8_t>& encoded_record,
                                uint32_t& handle_out);
    virtual bool unregisterRecord(uint32_t handle);
    virtual const std::string& lastError() const { return last_error_; }

private:
    bool exchangePdu(const std::vector<uint8_t>& request,
                     std::vector<uint8_t>& response_out);

    std::string socket_path_;
    int timeout_ms_;
    BtAddr device_addr_;
    uint16_t next_tid_;
    std::string last_error_;
};

/// Chooses the appropriate SDP registration backend at runtime:
///   * BluezSdpdRegistrar if `cap.sdpd_socket_present` is true
///   * sdp::NoopSdpRegistrar otherwise (reports "unsupported")
std::unique_ptr<sdp::SdpRegistrar> createBtSdpRegistrar(
    const BtCapability& cap,
    const std::string& sdp_socket_path = "/var/run/sdp");

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_BT_RFCOMM_HPP
