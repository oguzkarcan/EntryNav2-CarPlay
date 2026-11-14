#include "carplay/platform/udp.hpp"

namespace carplay {
namespace platform {

const size_t UdpSocket::kAudioReceiveBuffer;

UdpSocket::UdpSocket() : handle_(kInvalidSocket), dual_stack_(false) {}

UdpSocket::~UdpSocket() { close(); }

void UdpSocket::close() {
    socketClose(handle_);
    local_ = Address();
    dual_stack_ = false;
}

bool UdpSocket::openBound(const Address& address, bool dual_stack) {
    close();
    SocketHandle h = socketOpen(address.family(), kSockDatagram);
    if (h == kInvalidSocket) {
        return false;
    }
    bool ok = true;
    if (address.family() == Address::kIPv6) {
        ok = setV6Only(h, !dual_stack);
    }
    ok = ok && socketBind(h, address) && socketLocalAddress(h, local_);
    if (!ok) {
        socketClose(h);
        local_ = Address();
        return false;
    }
    handle_ = h;
    dual_stack_ = dual_stack;
    return true;
}

bool UdpSocket::open(const Address& address) {
    if (!address.valid()) {
        return false;
    }
    return openBound(address, address.family() == Address::kIPv6 && address.isAny());
}

bool UdpSocket::openAny(uint16_t port) {
    if (openBound(Address::ipv6Any(port), true)) {
        return true;
    }
    return openBound(Address::ipv4Any(port), false);
}

IoStatus UdpSocket::receiveFrom(uint8_t* buf, size_t cap, size_t& got, Address& from) {
    return socketRecvFrom(handle_, buf, cap, got, from);
}

IoStatus UdpSocket::sendTo(const uint8_t* data, size_t len, const Address& to) {
    return socketSendTo(handle_, data, len, to);
}

bool UdpSocket::setReceiveBuffer(size_t requested, size_t& granted_out) {
    granted_out = 0;
    return handle_ != kInvalidSocket && platform::setReceiveBuffer(handle_, requested, granted_out);
}

}  // namespace platform
}  // namespace carplay
