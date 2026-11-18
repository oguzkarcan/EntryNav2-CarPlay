#include "test_support.hpp"

#include <string.h>

#include <deque>
#include <string>
#include <vector>

#ifndef _WIN32
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include "carplay/platform/bt_rfcomm.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/tcp.hpp"
#include "carplay/platform/thread.hpp"
#include "carplay/sdp_record.hpp"

namespace {

using carplay::platform::BtAddr;
using carplay::platform::BtCapability;
using carplay::platform::BtProbePaths;
using carplay::platform::BtRfcommConfig;
using carplay::platform::BtRfcommListener;
using carplay::platform::BtRfcommServer;
using carplay::platform::BtSocketOps;
using carplay::platform::IoStatus;
using carplay::platform::Reactor;
using carplay::platform::SockAddrRc;
using carplay::platform::SocketHandle;
using carplay::platform::kInvalidSocket;
using carplay::platform::kIoClosed;
using carplay::platform::kIoError;
using carplay::platform::kIoOk;
using carplay::platform::kIoWouldBlock;

void sleepMs(int ms) {
    carplay::platform::PollSet ps;
    ps.wait(NULL, 0, ms);
}

bool makeConnectedPair(SocketHandle fds[2]) {
    fds[0] = kInvalidSocket;
    fds[1] = kInvalidSocket;
#ifndef _WIN32
    int sv[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        return false;
    }
    for (int i = 0; i < 2; ++i) {
        int flags = ::fcntl(sv[i], F_GETFD, 0);
        if (flags < 0 || ::fcntl(sv[i], F_SETFD, flags | FD_CLOEXEC) < 0) {
            ::close(sv[0]);
            ::close(sv[1]);
            return false;
        }
        flags = ::fcntl(sv[i], F_GETFL, 0);
        if (flags < 0 || ::fcntl(sv[i], F_SETFL, flags | O_NONBLOCK) < 0) {
            ::close(sv[0]);
            ::close(sv[1]);
            return false;
        }
    }
    fds[0] = sv[0];
    fds[1] = sv[1];
    return true;
#else
    carplay::platform::TcpListener listener;
    if (!listener.listen(carplay::platform::Address::ipv4Loopback(0))) {
        return false;
    }
    const carplay::platform::Address addr = listener.localAddress();
    SocketHandle client = carplay::platform::socketOpen(carplay::platform::Address::kIPv4,
                                                        carplay::platform::kSockStream);
    if (client == kInvalidSocket) {
        return false;
    }
    const IoStatus cst = carplay::platform::socketConnect(client, addr);
    if (cst == kIoError) {
        carplay::platform::socketClose(client);
        return false;
    }
    SocketHandle accepted = kInvalidSocket;
    carplay::platform::Address peer;
    for (int tries = 0; tries < 50; ++tries) {
        const IoStatus ast = carplay::platform::socketAccept(listener.handle(), accepted, peer);
        if (ast == kIoOk) {
            break;
        }
        if (ast != kIoWouldBlock) {
            carplay::platform::socketClose(client);
            return false;
        }
        sleepMs(1);
    }
    if (accepted == kInvalidSocket) {
        carplay::platform::socketClose(client);
        return false;
    }
    fds[0] = accepted;
    fds[1] = client;
    return true;
#endif
}

void closeRawSocket(SocketHandle& fd) {
    if (fd == kInvalidSocket) {
        return;
    }
#ifndef _WIN32
    ::close(fd);
    fd = kInvalidSocket;
#else
    carplay::platform::socketClose(fd);
#endif
}

struct PendingAccept {
    SocketHandle server_side_fd;
    BtAddr peer_addr;
    uint8_t peer_channel;
};

class FakeBtSocketOps : public BtSocketOps {
public:
    FakeBtSocketOps()
        : fail_create(false),
          create_errno(97),
          assigned_dynamic_channel(9),
          max_send_chunk(0),
          force_next_send_would_block(false),
          listen_notify_read_(kInvalidSocket),
          listen_notify_write_(kInvalidSocket) {}

    ~FakeBtSocketOps() {
        closeRawSocket(listen_notify_read_);
        closeRawSocket(listen_notify_write_);
        while (!pending_.empty()) {
            closeRawSocket(pending_.front().server_side_fd);
            pending_.pop_front();
        }
    }

    bool fail_create;
    int create_errno;
    uint8_t assigned_dynamic_channel;
    size_t max_send_chunk;
    bool force_next_send_would_block;
    BtAddr bound_addr;
    uint8_t bound_channel;

    /// Queues an incoming connection and returns the remote peer socket handle.
    SocketHandle enqueueIncoming(const BtAddr& peer, uint8_t peer_ch) {
        SocketHandle pair[2];
        if (!makeConnectedPair(pair)) {
            return kInvalidSocket;
        }
        PendingAccept pa;
        pa.server_side_fd = pair[0];
        pa.peer_addr = peer;
        pa.peer_channel = peer_ch;
        pending_.push_back(pa);
        if (listen_notify_write_ != kInvalidSocket) {
            const uint8_t b = 1;
            size_t sent = 0;
            int err = 0;
            sendBytes(listen_notify_write_, &b, 1, sent, err);
        }
        return pair[1];
    }

    virtual SocketHandle createRfcommSocket(int& err_out) {
        if (fail_create) {
            err_out = create_errno;
            return kInvalidSocket;
        }
        SocketHandle pair[2];
        if (!makeConnectedPair(pair)) {
            err_out = 12;
            return kInvalidSocket;
        }
        listen_notify_read_ = pair[0];
        listen_notify_write_ = pair[1];
        err_out = 0;
        return listen_notify_read_;
    }

    virtual bool bindRfcomm(SocketHandle /*fd*/,
                            const BtAddr& addr,
                            uint8_t channel,
                            int& err_out) {
        bound_addr = addr;
        bound_channel = (channel == 0) ? assigned_dynamic_channel : channel;
        err_out = 0;
        return true;
    }

    virtual bool getRfcommChannel(SocketHandle /*fd*/, uint8_t& channel_out, int& err_out) {
        channel_out = bound_channel;
        err_out = 0;
        return true;
    }

    virtual bool listenSocket(SocketHandle /*fd*/, int /*backlog*/, int& err_out) {
        err_out = 0;
        return true;
    }

    virtual IoStatus acceptRfcomm(SocketHandle listen_fd,
                                  SocketHandle& client_fd_out,
                                  BtAddr& peer_addr_out,
                                  uint8_t& peer_channel_out,
                                  int& err_out) {
        if (pending_.empty()) {
            uint8_t drain[16];
            size_t got = 0;
            recvBytes(listen_fd, drain, sizeof(drain), got, err_out);
            err_out = 0;
            return kIoWouldBlock;
        }
        const PendingAccept pa = pending_.front();
        pending_.pop_front();
        uint8_t b = 0;
        size_t got = 0;
        recvBytes(listen_fd, &b, 1, got, err_out);

        client_fd_out = pa.server_side_fd;
        peer_addr_out = pa.peer_addr;
        peer_channel_out = pa.peer_channel;
        err_out = 0;
        return kIoOk;
    }

    virtual IoStatus recvBytes(SocketHandle fd,
                               uint8_t* buf,
                               size_t cap,
                               size_t& got_out,
                               int& err_out) {
        got_out = 0;
#ifndef _WIN32
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
#else
        const IoStatus st = carplay::platform::socketRecv(fd, buf, cap, got_out);
        err_out = (st == kIoError) ? carplay::platform::lastSocketError() : 0;
        return st;
#endif
    }

    virtual IoStatus sendBytes(SocketHandle fd,
                               const uint8_t* data,
                               size_t len,
                               size_t& sent_out,
                               int& err_out) {
        sent_out = 0;
        if (fd != listen_notify_write_ && force_next_send_would_block) {
            force_next_send_would_block = false;
            err_out = 0;
            return kIoWouldBlock;
        }
        size_t to_send = len;
        if (fd != listen_notify_write_ && max_send_chunk > 0 && to_send > max_send_chunk) {
            to_send = max_send_chunk;
            force_next_send_would_block = true;
        }
#ifndef _WIN32
        for (;;) {
            const ssize_t n = ::send(fd, data, to_send, 0);
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
#else
        const IoStatus st = carplay::platform::socketSend(fd, data, to_send, sent_out);
        err_out = (st == kIoError) ? carplay::platform::lastSocketError() : 0;
        return st;
#endif
    }

    virtual void closeSocket(SocketHandle fd) {
        if (fd == listen_notify_read_) {
            closeRawSocket(listen_notify_read_);
            closeRawSocket(listen_notify_write_);
            return;
        }
        closeRawSocket(fd);
    }

    virtual std::string errorString(int err) const {
        return carplay::platform::socketErrorString(err);
    }

private:
    std::deque<PendingAccept> pending_;
    SocketHandle listen_notify_read_;
    SocketHandle listen_notify_write_;
};

class RecordingBtListener : public BtRfcommListener {
public:
    RecordingBtListener()
        : connected_count(0),
          disconnected_count(0),
          disconnect_on_data(false),
          server_to_disconnect(NULL) {}

    int connected_count;
    int disconnected_count;
    BtAddr last_peer;
    uint8_t last_channel;
    std::vector<uint8_t> received;
    std::string last_disconnect_reason;
    bool disconnect_on_data;
    BtRfcommServer* server_to_disconnect;

    virtual void onBtConnected(const BtAddr& peer, uint8_t channel) {
        ++connected_count;
        last_peer = peer;
        last_channel = channel;
    }

    virtual void onBtData(const uint8_t* data, size_t len) {
        received.insert(received.end(), data, data + len);
        if (disconnect_on_data && server_to_disconnect != NULL) {
            disconnect_on_data = false;
            server_to_disconnect->disconnect("reentrant disconnect");
        }
    }

    virtual void onBtDisconnected(const std::string& reason) {
        ++disconnected_count;
        last_disconnect_reason = reason;
    }
};

void sendAllPeer(FakeBtSocketOps& ops, SocketHandle fd, const uint8_t* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t sent = 0;
        int err = 0;
        const IoStatus st = ops.sendBytes(fd, data + off, len - off, sent, err);
        if (st == kIoOk) {
            off += sent;
        } else if (st == kIoWouldBlock) {
            sleepMs(1);
        } else {
            break;
        }
    }
}

std::vector<uint8_t> recvAtLeastPeer(FakeBtSocketOps& ops, SocketHandle fd, size_t expected) {
    std::vector<uint8_t> out;
    uint8_t buf[256];
    for (int tries = 0; tries < 200 && out.size() < expected; ++tries) {
        size_t got = 0;
        int err = 0;
        const IoStatus st = ops.recvBytes(fd, buf, sizeof(buf), got, err);
        if (st == kIoOk && got > 0) {
            out.insert(out.end(), buf, buf + got);
            continue;
        }
        if (st == kIoClosed || st == kIoError) {
            break;
        }
        sleepMs(2);
    }
    return out;
}

#ifndef _WIN32
struct FakeSdpdServerArgs {
    int listen_fd;
    std::vector<uint8_t> received_reg_req;
    std::vector<uint8_t> received_rem_req;
    bool ok;

    FakeSdpdServerArgs() : listen_fd(-1), ok(false) {}
};

bool readExactFd(int fd, uint8_t* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        const ssize_t r = ::recv(fd, buf + off, n - off, 0);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            return false;
        }
        off += static_cast<size_t>(r);
    }
    return true;
}

bool writeExactFd(int fd, const uint8_t* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        const ssize_t w = ::send(fd, buf + off, n - off, 0);
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            return false;
        }
        off += static_cast<size_t>(w);
    }
    return true;
}

void fakeSdpdThread(void* ctx) {
    FakeSdpdServerArgs* args = static_cast<FakeSdpdServerArgs*>(ctx);
    // 1) Accept register request
    int c1 = ::accept(args->listen_fd, NULL, NULL);
    if (c1 < 0) {
        return;
    }
    uint8_t hdr[5];
    if (!readExactFd(c1, hdr, 5)) {
        ::close(c1);
        return;
    }
    const uint16_t plen1 = static_cast<uint16_t>((hdr[3] << 8) | hdr[4]);
    args->received_reg_req.assign(hdr, hdr + 5);
    args->received_reg_req.resize(5U + plen1);
    if (plen1 > 0 && !readExactFd(c1, &args->received_reg_req[5], plen1)) {
        ::close(c1);
        return;
    }
    const uint8_t reg_rsp[9] = {
        carplay::sdp::pdu::kSvcRegisterRsp,
        hdr[1], hdr[2],
        0x00, 0x04,
        0x00, 0x01, 0x00, 0x07
    };
    if (!writeExactFd(c1, reg_rsp, sizeof(reg_rsp))) {
        ::close(c1);
        return;
    }
    ::close(c1);

    // 2) Accept remove request
    int c2 = ::accept(args->listen_fd, NULL, NULL);
    if (c2 < 0) {
        return;
    }
    if (!readExactFd(c2, hdr, 5)) {
        ::close(c2);
        return;
    }
    const uint16_t plen2 = static_cast<uint16_t>((hdr[3] << 8) | hdr[4]);
    args->received_rem_req.assign(hdr, hdr + 5);
    args->received_rem_req.resize(5U + plen2);
    if (plen2 > 0 && !readExactFd(c2, &args->received_rem_req[5], plen2)) {
        ::close(c2);
        return;
    }
    const uint8_t rem_rsp[7] = {
        carplay::sdp::pdu::kSvcRemoveRsp,
        hdr[1], hdr[2],
        0x00, 0x02,
        0x00, 0x00
    };
    if (!writeExactFd(c2, rem_rsp, sizeof(rem_rsp))) {
        ::close(c2);
        return;
    }
    ::close(c2);
    args->ok = true;
}
#endif

}  // namespace

TEST_CASE(sdpPrimitiveEncodings) {
    std::vector<uint8_t> out;

    carplay::sdp::appendNil(out);
    CHECK_BYTES_EQ(test_support::hexToBytes("00"), out);

    out.clear();
    carplay::sdp::appendUint8(out, 0x05);
    CHECK_BYTES_EQ(test_support::hexToBytes("0805"), out);

    out.clear();
    carplay::sdp::appendUint16(out, 0x1234U);
    CHECK_BYTES_EQ(test_support::hexToBytes("091234"), out);

    out.clear();
    carplay::sdp::appendUint32(out, 0x12345678U);
    CHECK_BYTES_EQ(test_support::hexToBytes("0a12345678"), out);

    out.clear();
    carplay::sdp::appendBool(out, false);
    carplay::sdp::appendBool(out, true);
    CHECK_BYTES_EQ(test_support::hexToBytes("28002801"), out);

    out.clear();
    carplay::sdp::appendUuid16(out, carplay::sdp::uuid16::kL2cap);
    CHECK_BYTES_EQ(test_support::hexToBytes("190100"), out);

    out.clear();
    carplay::sdp::appendUuid32(out, 0x00001101U);
    CHECK_BYTES_EQ(test_support::hexToBytes("1a00001101"), out);

    out.clear();
    carplay::sdp::appendUuid128(out, carplay::sdp::defaultIap2AccessoryUuid128());
    CHECK_BYTES_EQ(test_support::hexToBytes("1c00000000decafadedecadeafdecacafe"), out);

    carplay::sdp::Uuid128 u;
    CHECK(carplay::sdp::parseUuid128("00000000-DECA-FADE-DECA-DEAFDECACAFF", u));
    CHECK(u == carplay::sdp::defaultAppleIapDeviceUuid128());
    CHECK_EQ(std::string("00000000-deca-fade-deca-deafdecacaff"),
             carplay::sdp::formatUuid128(u));
    CHECK(carplay::sdp::parseUuid128("00000000decafadedecadeafdecacafe", u));
    CHECK(u == carplay::sdp::defaultIap2AccessoryUuid128());

    CHECK(!carplay::sdp::parseUuid128("0000-0000", u));
    CHECK(!carplay::sdp::parseUuid128("00000000_deca_fade_deca_deafdecacafe", u));
    CHECK(!carplay::sdp::parseUuid128("zzzzzzzz-deca-fade-deca-deafdecacafe", u));
}

TEST_CASE(sdpVariableLengthEncodings) {
    std::vector<uint8_t> out;

    carplay::sdp::appendText(out, "iAP2");
    CHECK_BYTES_EQ(test_support::hexToBytes("250469415032"), out);

    out.clear();
    carplay::sdp::appendText(out, "");
    CHECK_BYTES_EQ(test_support::hexToBytes("2500"), out);

    // 300-byte text uses size descriptor 6 (uint16 BE length 0x012c)
    out.clear();
    const std::string long_text(300U, 'a');
    carplay::sdp::appendText(out, long_text);
    REQUIRE(out.size() == 303U);
    CHECK_EQ(static_cast<uint8_t>(0x26U), out[0]);
    CHECK_EQ(static_cast<uint8_t>(0x01U), out[1]);
    CHECK_EQ(static_cast<uint8_t>(0x2cU), out[2]);
    CHECK_EQ(static_cast<uint8_t>('a'), out[302]);

    // ProtocolDescriptorList sequence: DES { DES{L2CAP}, DES{RFCOMM, 5} }
    std::vector<uint8_t> l2cap;
    carplay::sdp::appendUuid16(l2cap, 0x0100U);
    std::vector<uint8_t> rfcomm;
    carplay::sdp::appendUuid16(rfcomm, 0x0003U);
    carplay::sdp::appendUint8(rfcomm, 5U);
    std::vector<uint8_t> protos_inner;
    carplay::sdp::appendSequence(protos_inner, l2cap);
    carplay::sdp::appendSequence(protos_inner, rfcomm);
    out.clear();
    carplay::sdp::appendSequence(out, protos_inner);
    CHECK_BYTES_EQ(test_support::hexToBytes("350c350319010035051900030805"), out);

    // Data Element Alternative (DEA)
    std::vector<uint8_t> alt_inner;
    carplay::sdp::appendUuid16(alt_inner, 0x1101U);
    carplay::sdp::appendUuid16(alt_inner, 0x1102U);
    out.clear();
    carplay::sdp::appendAlternative(out, alt_inner);
    CHECK_BYTES_EQ(test_support::hexToBytes("3d06191101191102"), out);

    // >255B DEA uses 0x3e + 2B length
    std::vector<uint8_t> big_inner(260U, 0x00U);
    out.clear();
    carplay::sdp::appendAlternative(out, big_inner);
    REQUIRE(out.size() == 263U);
    CHECK_EQ(static_cast<uint8_t>(0x3eU), out[0]);
    CHECK_EQ(static_cast<uint8_t>(0x01U), out[1]);
    CHECK_EQ(static_cast<uint8_t>(0x04U), out[2]);
}

TEST_CASE(sdpIap2RecordBuilder) {
    carplay::sdp::Iap2SdpConfig cfg;
    cfg.rfcomm_channel = 0;
    carplay::sdp::ServiceRecord rec;
    std::string err;
    CHECK(!carplay::sdp::buildIap2SdpRecord(cfg, rec, &err));
    CHECK(!err.empty());

    cfg.rfcomm_channel = 31;
    CHECK(!carplay::sdp::buildIap2SdpRecord(cfg, rec, &err));

    cfg.rfcomm_channel = 7;
    cfg.service_name = "Wireless iAP2";
    REQUIRE(carplay::sdp::buildIap2SdpRecord(cfg, rec, &err));
    CHECK_EQ(static_cast<size_t>(5U), rec.size());

    std::vector<uint8_t> encoded;
    REQUIRE(rec.encode(encoded, &err));

    // Hand-computed complete SDP record DES for channel 7, default UUID, "Wireless iAP2":
    //   35 4f                                           DES (79 bytes)
    //   09 0001  35 11 1c 00000000decafadedecadeafdecacafe
    //   09 0004  35 0c 35 03 19 0100 35 05 19 0003 08 07
    //   09 0005  35 03 19 1002
    //   09 0006  35 09 09 656e 09 006a 09 0100
    //   09 0100  25 0d 576972656c6573732069415032
    const std::vector<uint8_t> expected = test_support::hexToBytes(
        "354f"
        "090001" "3511" "1c" "00000000decafadedecadeafdecacafe"
        "090004" "350c" "3503190100" "35051900030807"
        "090005" "3503" "191002"
        "090006" "3509" "09656e" "09006a" "090100"
        "090100" "250d" "576972656c6573732069415032");
    CHECK_BYTES_EQ(expected, encoded);

    // Optional fields omitted when disabled / empty name, and extra UUID16 supported.
    cfg.service_name.clear();
    cfg.include_public_browse_group = false;
    cfg.extra_uuid16s.push_back(carplay::sdp::uuid16::kSerialPort);
    REQUIRE(carplay::sdp::buildIap2SdpRecord(cfg, rec, &err));
    CHECK_EQ(static_cast<size_t>(2U), rec.size());
    REQUIRE(rec.findAttribute(carplay::sdp::attr::kServiceClassIdList) != NULL);
    CHECK_BYTES_EQ(
        test_support::hexToBytes("35141c00000000decafadedecadeafdecacafe191101"),
        rec.findAttribute(carplay::sdp::attr::kServiceClassIdList)->encoded_value);
}

TEST_CASE(sdpdPduCodecAndNoopBackend) {
    const std::vector<uint8_t> rec = test_support::hexToBytes("3503090001");
    const uint8_t bdaddr[6] = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
    std::vector<uint8_t> pdu;
    std::string err;

    REQUIRE(carplay::sdp::encodeSdpdRegisterRequest(0x0042U, rec, pdu, bdaddr, 0x01U, &err));
    // plen = 6 + 1 + 5 = 12 (0x000c)
    CHECK_BYTES_EQ(
        test_support::hexToBytes("81 0042 000c 665544332211 01 3503090001"),
        pdu);

    std::vector<uint8_t> empty_rec;
    CHECK(!carplay::sdp::encodeSdpdRegisterRequest(1U, empty_rec, pdu, NULL, 0U, &err));

    // Register response success
    const std::vector<uint8_t> ok_rsp = test_support::hexToBytes("82 0042 0004 00010002");
    uint32_t handle = 0;
    uint16_t sdp_err = 0;
    REQUIRE(carplay::sdp::parseSdpdRegisterResponse(&ok_rsp[0], ok_rsp.size(), 0x0042U,
                                                    handle, &sdp_err, &err));
    CHECK_EQ(static_cast<uint32_t>(0x00010002U), handle);

    // TID mismatch
    CHECK(!carplay::sdp::parseSdpdRegisterResponse(&ok_rsp[0], ok_rsp.size(), 0x0043U,
                                                   handle, &sdp_err, &err));

    // Error response
    const std::vector<uint8_t> err_rsp = test_support::hexToBytes("01 0042 0002 0004");
    CHECK(!carplay::sdp::parseSdpdRegisterResponse(&err_rsp[0], err_rsp.size(), 0x0042U,
                                                   handle, &sdp_err, &err));
    CHECK_EQ(static_cast<uint16_t>(0x0004U), sdp_err);

    // Remove request & response
    carplay::sdp::encodeSdpdRemoveRequest(0x0043U, 0x00010002U, pdu);
    CHECK_BYTES_EQ(test_support::hexToBytes("85 0043 0004 00010002"), pdu);

    const std::vector<uint8_t> rem_ok = test_support::hexToBytes("86 0043 0002 0000");
    CHECK(carplay::sdp::parseSdpdRemoveResponse(&rem_ok[0], rem_ok.size(), 0x0043U,
                                                &sdp_err, &err));
    const std::vector<uint8_t> rem_fail = test_support::hexToBytes("86 0043 0002 0001");
    CHECK(!carplay::sdp::parseSdpdRemoveResponse(&rem_fail[0], rem_fail.size(), 0x0043U,
                                                 &sdp_err, &err));
    CHECK_EQ(static_cast<uint16_t>(0x0001U), sdp_err);

    // No-op registrar
    carplay::sdp::NoopSdpRegistrar noop;
    CHECK_EQ(std::string("noop"), std::string(noop.backendName()));
    CHECK(!noop.isSupported());
    uint32_t out_h = 123;
    CHECK(!noop.registerRecord(rec, out_h));
    CHECK_EQ(static_cast<uint32_t>(0U), out_h);
    CHECK_EQ(std::string("unsupported"), noop.lastError());
    CHECK(!noop.unregisterRecord(1U));
    CHECK_EQ(std::string("unsupported"), noop.lastError());
}

TEST_CASE(btAddrParsingAndLayout) {
    BtAddr addr;
    REQUIRE(BtAddr::parse("01:23:45:67:89:ab", addr));
    CHECK_EQ(static_cast<uint8_t>(0xabU), addr.b[0]);
    CHECK_EQ(static_cast<uint8_t>(0x89U), addr.b[1]);
    CHECK_EQ(static_cast<uint8_t>(0x67U), addr.b[2]);
    CHECK_EQ(static_cast<uint8_t>(0x45U), addr.b[3]);
    CHECK_EQ(static_cast<uint8_t>(0x23U), addr.b[4]);
    CHECK_EQ(static_cast<uint8_t>(0x01U), addr.b[5]);
    CHECK_EQ(std::string("01:23:45:67:89:AB"), addr.toString());
    CHECK(!addr.isZero());
    CHECK(BtAddr::any().isZero());

    CHECK(!BtAddr::parse("", addr));
    CHECK(!BtAddr::parse("01-23-45-67-89-AB", addr));
    CHECK(!BtAddr::parse("01:23:45:67:89:AB:CD", addr));
    CHECK(!BtAddr::parse("01:23:45:67:89:AG", addr));

    CHECK_EQ(static_cast<size_t>(10U), sizeof(SockAddrRc));
}

TEST_CASE(rfcommServerAcceptDataDisconnectReconnect) {
    Reactor reactor;
    REQUIRE(reactor.init());

    FakeBtSocketOps ops;
    ops.assigned_dynamic_channel = 12;

    BtRfcommConfig cfg;
    cfg.channel = 0;  // dynamic
    RecordingBtListener listener;
    BtRfcommServer server(reactor, listener, cfg, &ops);

    std::string err;
    REQUIRE(server.start(&err));
    CHECK(server.isListening());
    CHECK(!server.isConnected());
    CHECK_EQ(static_cast<uint8_t>(12U), server.boundChannel());

    // First client connects
    BtAddr peer1;
    REQUIRE(BtAddr::parse("AA:BB:CC:DD:EE:01", peer1));
    SocketHandle remote1 = ops.enqueueIncoming(peer1, 12);
    REQUIRE(remote1 != kInvalidSocket);

    for (int i = 0; i < 10 && listener.connected_count < 1; ++i) {
        reactor.runOnce(50);
    }
    REQUIRE(listener.connected_count == 1);
    CHECK(server.isConnected());
    CHECK(server.peerAddress() == peer1);
    CHECK_EQ(static_cast<uint8_t>(12U), server.peerChannel());

    // Peer sends data in two bursts
    const uint8_t msg1[] = {'h', 'e', 'l'};
    const uint8_t msg2[] = {'l', 'o'};
    sendAllPeer(ops, remote1, msg1, sizeof(msg1));
    sendAllPeer(ops, remote1, msg2, sizeof(msg2));
    for (int i = 0; i < 20 && listener.received.size() < 5U; ++i) {
        reactor.runOnce(20);
    }
    CHECK_EQ(std::string("hello"),
             std::string(listener.received.begin(), listener.received.end()));

    // Second client attempts connection while first is active -> rejected (single active connection)
    BtAddr peer2;
    REQUIRE(BtAddr::parse("AA:BB:CC:DD:EE:02", peer2));
    SocketHandle remote2 = ops.enqueueIncoming(peer2, 12);
    REQUIRE(remote2 != kInvalidSocket);
    for (int i = 0; i < 10; ++i) {
        reactor.runOnce(10);
    }
    CHECK_EQ(1, listener.connected_count);
    CHECK(server.peerAddress() == peer1);
    // remote2 should see EOF because server immediately closed the rejected fd
    uint8_t tmp[8];
    size_t got = 0;
    int rerr = 0;
    IoStatus rst = kIoWouldBlock;
    for (int i = 0; i < 20 && rst == kIoWouldBlock; ++i) {
        rst = ops.recvBytes(remote2, tmp, sizeof(tmp), got, rerr);
        if (rst == kIoWouldBlock) {
            sleepMs(2);
        }
    }
    CHECK(rst == kIoClosed || rst == kIoError);
    closeRawSocket(remote2);

    // Server sends reply to client 1
    const uint8_t reply[] = {0x40, 0x40, 0x00, 0x06, 0x1d, 0x02};
    CHECK_EQ(BtRfcommServer::kSendOk, server.send(reply, sizeof(reply)));
    const std::vector<uint8_t> got_reply = recvAtLeastPeer(ops, remote1, sizeof(reply));
    CHECK_BYTES_EQ(std::vector<uint8_t>(reply, reply + sizeof(reply)), got_reply);

    // Peer 1 disconnects cleanly
    closeRawSocket(remote1);
    for (int i = 0; i < 20 && listener.disconnected_count < 1; ++i) {
        reactor.runOnce(20);
    }
    CHECK_EQ(1, listener.disconnected_count);
    CHECK_EQ(std::string("peer closed"), listener.last_disconnect_reason);
    CHECK(!server.isConnected());
    CHECK(server.isListening());

    // Peer 3 reconnects cleanly on the same listener
    listener.received.clear();
    BtAddr peer3;
    REQUIRE(BtAddr::parse("AA:BB:CC:DD:EE:03", peer3));
    SocketHandle remote3 = ops.enqueueIncoming(peer3, 12);
    REQUIRE(remote3 != kInvalidSocket);
    for (int i = 0; i < 10 && listener.connected_count < 2; ++i) {
        reactor.runOnce(50);
    }
    REQUIRE(listener.connected_count == 2);
    CHECK(server.isConnected());
    CHECK(server.peerAddress() == peer3);

    const uint8_t msg3[] = {'o', 'k'};
    sendAllPeer(ops, remote3, msg3, sizeof(msg3));
    for (int i = 0; i < 20 && listener.received.size() < 2U; ++i) {
        reactor.runOnce(20);
    }
    CHECK_EQ(std::string("ok"),
             std::string(listener.received.begin(), listener.received.end()));

    // Local disconnect keeps listener open
    server.disconnect("done");
    CHECK_EQ(2, listener.disconnected_count);
    CHECK_EQ(std::string("done"), listener.last_disconnect_reason);
    CHECK(!server.isConnected());
    CHECK(server.isListening());
    closeRawSocket(remote3);

    server.stop();
    CHECK(!server.isListening());
}

TEST_CASE(rfcommServerPartialWriteAndBackpressure) {
    Reactor reactor;
    REQUIRE(reactor.init());

    FakeBtSocketOps ops;
    ops.max_send_chunk = 16U;

    BtRfcommConfig cfg;
    cfg.channel = 5;
    cfg.write_queue_limit = 64U;
    RecordingBtListener listener;
    BtRfcommServer server(reactor, listener, cfg, &ops);
    REQUIRE(server.start());
    CHECK_EQ(static_cast<uint8_t>(5U), server.boundChannel());

    // Send before connect -> kSendClosed
    const uint8_t probe_byte = 0x01;
    CHECK_EQ(BtRfcommServer::kSendClosed, server.send(&probe_byte, 1));

    BtAddr peer;
    REQUIRE(BtAddr::parse("11:22:33:44:55:66", peer));
    SocketHandle remote = ops.enqueueIncoming(peer, 5);
    REQUIRE(remote != kInvalidSocket);
    for (int i = 0; i < 10 && listener.connected_count < 1; ++i) {
        reactor.runOnce(50);
    }
    REQUIRE(server.isConnected());

    // Send 48 bytes: 16 sent immediately, 32 queued -> kPollOut drains the rest.
    std::vector<uint8_t> payload(48U);
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<uint8_t>(i);
    }
    CHECK_EQ(BtRfcommServer::kSendOk, server.send(payload));
    CHECK_EQ(static_cast<size_t>(32U), server.queuedBytes());

    // Back-pressure check: 32 queued + 33 > 64 -> kSendOverflow, nothing queued!
    std::vector<uint8_t> too_big(33U, 0xaaU);
    CHECK_EQ(BtRfcommServer::kSendOverflow, server.send(too_big));
    CHECK_EQ(static_cast<size_t>(32U), server.queuedBytes());

    // Drain remaining 32 bytes via Reactor onWritable()
    for (int i = 0; i < 20 && server.queuedBytes() > 0; ++i) {
        reactor.runOnce(20);
    }
    CHECK_EQ(static_cast<size_t>(0U), server.queuedBytes());
    const std::vector<uint8_t> got = recvAtLeastPeer(ops, remote, payload.size());
    CHECK_BYTES_EQ(payload, got);

    // Re-entrant disconnect from inside onBtData()
    listener.disconnect_on_data = true;
    listener.server_to_disconnect = &server;
    const uint8_t trigger[4] = {1, 2, 3, 4};
    sendAllPeer(ops, remote, trigger, sizeof(trigger));
    for (int i = 0; i < 20 && server.isConnected(); ++i) {
        reactor.runOnce(20);
    }
    CHECK(!server.isConnected());
    CHECK_EQ(1, listener.disconnected_count);
    CHECK_EQ(std::string("reentrant disconnect"), listener.last_disconnect_reason);

    closeRawSocket(remote);
    server.stop();
}

TEST_CASE(rfcommServerStartFailureAndReplaceActive) {
    Reactor reactor;
    REQUIRE(reactor.init());

    FakeBtSocketOps ops;
    ops.fail_create = true;
    ops.create_errno = 97;

    RecordingBtListener listener;
    BtRfcommServer fail_srv(reactor, listener, BtRfcommConfig(), &ops);
    std::string err;
    CHECK(!fail_srv.start(&err));
    CHECK(!err.empty());
    CHECK(!fail_srv.isListening());

    // Test replace_active_connection = true
    ops.fail_create = false;
    BtRfcommConfig cfg;
    cfg.channel = 3;
    cfg.replace_active_connection = true;
    BtRfcommServer srv(reactor, listener, cfg, &ops);
    REQUIRE(srv.start());

    BtAddr p1, p2;
    REQUIRE(BtAddr::parse("00:11:22:33:44:01", p1));
    REQUIRE(BtAddr::parse("00:11:22:33:44:02", p2));
    SocketHandle r1 = ops.enqueueIncoming(p1, 3);
    for (int i = 0; i < 10 && listener.connected_count < 1; ++i) {
        reactor.runOnce(50);
    }
    REQUIRE(srv.isConnected());

    SocketHandle r2 = ops.enqueueIncoming(p2, 3);
    for (int i = 0; i < 10 && listener.connected_count < 2; ++i) {
        reactor.runOnce(50);
    }
    CHECK_EQ(2, listener.connected_count);
    CHECK_EQ(1, listener.disconnected_count);
    CHECK(srv.peerAddress() == p2);

    srv.stop();
    CHECK_EQ(2, listener.disconnected_count);
    closeRawSocket(r1);
    closeRawSocket(r2);
}

TEST_CASE(probeCapabilityAndFormatting) {
    BtCapability cap;
    cap.af_bluetooth_supported = true;
    cap.has_hci_device = true;
    cap.hci_devices.push_back("hci0");
    cap.sdpd_socket_present = true;
    cap.bluetoothd_socket_present = false;
    cap.dbus_socket_present = true;
    cap.libbluetooth_loadable = true;
    cap.libbluetooth_name = "libbluetooth.so.3";

    CHECK(cap.rfcommSocketCapable());
    const std::string text = carplay::platform::formatBtCapability(cap);
    CHECK(text.find("af_bluetooth=yes") != std::string::npos);
    CHECK(text.find("hci=hci0") != std::string::npos);
    CHECK(text.find("sdpd=yes") != std::string::npos);
    CHECK(text.find("bluetoothd=no") != std::string::npos);
    CHECK(text.find("dbus=yes") != std::string::npos);
    CHECK(text.find("libbluetooth=libbluetooth.so.3") != std::string::npos);
    carplay::platform::logBtCapability(cap);

    std::unique_ptr<carplay::sdp::SdpRegistrar> reg =
        carplay::platform::createBtSdpRegistrar(cap, "/tmp/nonexistent-sdp");
    CHECK_EQ(std::string("bluez-sdpd"), std::string(reg->backendName()));

    cap.sdpd_socket_present = false;
    reg = carplay::platform::createBtSdpRegistrar(cap);
    CHECK_EQ(std::string("noop"), std::string(reg->backendName()));
    CHECK(!reg->isSupported());

#ifndef _WIN32
    // Test directory + socket detection against temporary filesystem entries
    char tmp_template[] = "/tmp/carplay_bt_probe_XXXXXX";
    char* tmp_dir = ::mkdtemp(tmp_template);
    REQUIRE(tmp_dir != NULL);

    const std::string sys_bt = std::string(tmp_dir) + "/sys_bt";
    REQUIRE(::mkdir(sys_bt.c_str(), 0700) == 0);
    const std::string hci0 = sys_bt + "/hci0";
    const std::string hci2 = sys_bt + "/hci2";
    const std::string hci_conn = sys_bt + "/hci0:1";
    const std::string ignored = sys_bt + "/other";
    REQUIRE(::mkdir(hci0.c_str(), 0700) == 0);
    REQUIRE(::mkdir(hci2.c_str(), 0700) == 0);
    REQUIRE(::mkdir(hci_conn.c_str(), 0700) == 0);
    REQUIRE(::mkdir(ignored.c_str(), 0700) == 0);

    const std::string sdp_sock = std::string(tmp_dir) + "/sdp";
    int sfd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    REQUIRE(sfd >= 0);
    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    memcpy(un.sun_path, sdp_sock.data(), sdp_sock.size());
    REQUIRE(::bind(sfd, reinterpret_cast<const struct sockaddr*>(&un), sizeof(un)) == 0);

    BtProbePaths paths;
    paths.sys_class_bluetooth = sys_bt;
    paths.sdpd_socket = sdp_sock;
    paths.bluetoothd_socket = std::string(tmp_dir) + "/missing_btd";
    paths.dbus_socket = std::string(tmp_dir) + "/missing_dbus";
    paths.libbluetooth_candidates.clear();
    paths.libbluetooth_candidates.push_back("/tmp/definitely_missing_libbluetooth.so");
    paths.probe_af_bluetooth = false;

    const BtCapability probed = carplay::platform::probeBtCapability(paths);
    CHECK(probed.has_hci_device);
    REQUIRE(probed.hci_devices.size() == 2U);
    CHECK_EQ(std::string("hci0"), probed.hci_devices[0]);
    CHECK_EQ(std::string("hci2"), probed.hci_devices[1]);
    CHECK(probed.sdpd_socket_present);
    CHECK(!probed.bluetoothd_socket_present);
    CHECK(!probed.dbus_socket_present);
    CHECK(!probed.libbluetooth_loadable);

    ::close(sfd);
    ::unlink(sdp_sock.c_str());
    ::rmdir(hci0.c_str());
    ::rmdir(hci2.c_str());
    ::rmdir(hci_conn.c_str());
    ::rmdir(ignored.c_str());
    ::rmdir(sys_bt.c_str());
    ::rmdir(tmp_dir);
#endif
}

TEST_CASE(bluezSdpdRegistrarUnixSocketRoundtrip) {
#ifdef _WIN32
    std::printf("    [SKIP] AF_UNIX sdpd roundtrip skipped on Windows\n");
#else
    char tmp_template[] = "/tmp/carplay_sdpd_XXXXXX";
    char* tmp_dir = ::mkdtemp(tmp_template);
    REQUIRE(tmp_dir != NULL);
    const std::string sock_path = std::string(tmp_dir) + "/sdp";

    int lfd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    REQUIRE(lfd >= 0);
    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    memcpy(un.sun_path, sock_path.data(), sock_path.size());
    REQUIRE(::bind(lfd, reinterpret_cast<const struct sockaddr*>(&un), sizeof(un)) == 0);
    REQUIRE(::listen(lfd, 4) == 0);

    FakeSdpdServerArgs args;
    args.listen_fd = lfd;
    carplay::platform::Thread srv_thread;
    REQUIRE(srv_thread.start(&fakeSdpdThread, &args));

    BtCapability cap;
    cap.sdpd_socket_present = true;
    std::unique_ptr<carplay::sdp::SdpRegistrar> reg =
        carplay::platform::createBtSdpRegistrar(cap, sock_path);
    CHECK_EQ(std::string("bluez-sdpd"), std::string(reg->backendName()));
    CHECK(reg->isSupported());

    carplay::sdp::Iap2SdpConfig scfg;
    scfg.rfcomm_channel = 9;
    carplay::sdp::ServiceRecord rec;
    REQUIRE(carplay::sdp::buildIap2SdpRecord(scfg, rec));
    std::vector<uint8_t> encoded;
    REQUIRE(rec.encode(encoded));

    uint32_t handle = 0;
    CHECK(reg->registerRecord(encoded, handle));
    CHECK_EQ(static_cast<uint32_t>(0x00010007U), handle);
    CHECK(reg->unregisterRecord(handle));

    srv_thread.join();
    CHECK(args.ok);
    REQUIRE(args.received_reg_req.size() == 5U + 7U + encoded.size());
    CHECK_EQ(carplay::sdp::pdu::kSvcRegisterReq, args.received_reg_req[0]);
    CHECK_BYTES_EQ(encoded, std::vector<uint8_t>(args.received_reg_req.begin() + 12,
                                                 args.received_reg_req.end()));
    CHECK_EQ(carplay::sdp::pdu::kSvcRemoveReq, args.received_rem_req[0]);

    ::close(lfd);
    ::unlink(sock_path.c_str());
    ::rmdir(tmp_dir);
#endif
}

TEST_CASE(realAfBluetoothProbeGracefulSkip) {
    const BtCapability cap = carplay::platform::probeBtCapability();
    const std::string summary = carplay::platform::formatBtCapability(cap);
    std::printf("    host BT probe: %s\n", summary.c_str());

    if (!cap.af_bluetooth_supported) {
        Reactor reactor;
        REQUIRE(reactor.init());
        RecordingBtListener listener;
        BtRfcommServer srv(reactor, listener);
        std::string err;
        CHECK(!srv.start(&err));
        CHECK(!err.empty());
        std::printf("    [SKIP] AF_BLUETOOTH unavailable on this host (%s)\n", err.c_str());
        return;
    }

    if (!cap.has_hci_device) {
        std::printf("    [SKIP] AF_BLUETOOTH supported but no HCI adapter present\n");
        return;
    }

    Reactor reactor;
    REQUIRE(reactor.init());
    RecordingBtListener listener;
    BtRfcommConfig cfg;
    cfg.channel = 0;
    BtRfcommServer srv(reactor, listener, cfg);
    std::string err;
    if (!srv.start(&err)) {
        std::printf("    [SKIP] real RFCOMM bind skipped (%s)\n", err.c_str());
        return;
    }
    CHECK(srv.isListening());
    CHECK(srv.boundChannel() >= 1 && srv.boundChannel() <= 30);
    srv.stop();
}

int main() {
    return test_support::runAll("test_bt_rfcomm");
}
