// Portability shim: the only file that includes the OS socket headers. See net_compat.hpp.

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#endif

#include <limits.h>
#include <string.h>

#include <stdio.h>

#include "carplay/platform/net_compat.hpp"

namespace carplay {
namespace platform {

// ------------------------------------------------------------------------------------------------
// Clock
// ------------------------------------------------------------------------------------------------

#ifdef _WIN32
int64_t monotonicNanos() {
    static LONG64 cached_freq = 0;
    LONG64 freq = InterlockedCompareExchange64(&cached_freq, 0, 0);
    if (freq == 0) {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);  // never fails on XP and later
        freq = f.QuadPart;
        InterlockedExchange64(&cached_freq, freq);
    }
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    const int64_t count = c.QuadPart;
    return (count / freq) * 1000000000LL + ((count % freq) * 1000000000LL) / freq;
}
#else
int64_t monotonicNanos() {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;  // cannot happen for CLOCK_MONOTONIC on Linux
    }
    return static_cast<int64_t>(ts.tv_sec) * 1000000000LL + static_cast<int64_t>(ts.tv_nsec);
}
#endif

int64_t monotonicMillis() { return monotonicNanos() / 1000000LL; }

// ------------------------------------------------------------------------------------------------
// Init / errors
// ------------------------------------------------------------------------------------------------

#ifdef _WIN32
namespace {
struct WinsockInit {
    bool ok;
    WinsockInit() : ok(false) {
        WSADATA data;
        ok = (WSAStartup(MAKEWORD(2, 2), &data) == 0);
    }
    // No WSACleanup: process teardown releases Winsock; cleaning up while other static objects
    // may still own sockets would be worse.
};
}  // namespace

bool netInit() {
    static WinsockInit init;  // thread-safe local static (GCC -fthreadsafe-statics default)
    return init.ok;
}

int lastSocketError() { return WSAGetLastError(); }

std::string socketErrorString(int code) {
    char buf[256];
    buf[0] = '\0';
    const DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                                   static_cast<DWORD>(code), 0, buf, sizeof(buf), NULL);
    std::string s(buf, n);
    while (!s.empty() && (s[s.size() - 1] == '\n' || s[s.size() - 1] == '\r' || s[s.size() - 1] == ' ')) {
        s.erase(s.size() - 1);
    }
    char num[32];
    snprintf(num, sizeof(num), " (%d)", code);
    return s + num;
}

static bool errWouldBlock(int e) { return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
#else
bool netInit() { return true; }

int lastSocketError() { return errno; }

std::string socketErrorString(int code) {
    char num[32];
    snprintf(num, sizeof(num), " (%d)", code);
    return std::string(strerror(code)) + num;  // reactor thread only; strerror is fine here
}

static bool errWouldBlock(int e) { return e == EAGAIN || e == EWOULDBLOCK; }
#endif

// ------------------------------------------------------------------------------------------------
// Address
// ------------------------------------------------------------------------------------------------

Address::Address() : family_(kNone), port_(0), scope_id_(0) { memset(bytes_, 0, sizeof(bytes_)); }

Address Address::ipv4(const uint8_t bytes[4], uint16_t port) {
    Address a;
    a.family_ = kIPv4;
    memcpy(a.bytes_, bytes, 4);
    a.port_ = port;
    return a;
}

Address Address::ipv6(const uint8_t bytes[16], uint16_t port, uint32_t scope_id) {
    Address a;
    a.family_ = kIPv6;
    memcpy(a.bytes_, bytes, 16);
    a.port_ = port;
    a.scope_id_ = scope_id;
    return a;
}

Address Address::ipv4Any(uint16_t port) {
    static const uint8_t b[4] = {0, 0, 0, 0};
    return ipv4(b, port);
}

Address Address::ipv6Any(uint16_t port) {
    static const uint8_t b[16] = {0};
    return ipv6(b, port, 0);
}

Address Address::ipv4Loopback(uint16_t port) {
    static const uint8_t b[4] = {127, 0, 0, 1};
    return ipv4(b, port);
}

Address Address::ipv6Loopback(uint16_t port) {
    static const uint8_t b[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    return ipv6(b, port, 0);
}

size_t Address::byteLength() const {
    return family_ == kIPv4 ? 4U : (family_ == kIPv6 ? 16U : 0U);
}

bool Address::isV4Mapped() const {
    if (family_ != kIPv6) {
        return false;
    }
    for (int i = 0; i < 10; ++i) {
        if (bytes_[i] != 0) {
            return false;
        }
    }
    return bytes_[10] == 0xff && bytes_[11] == 0xff;
}

Address Address::unmapped() const {
    if (!isV4Mapped()) {
        return *this;
    }
    return ipv4(bytes_ + 12, port_);
}

Address Address::v4Mapped() const {
    if (family_ != kIPv4) {
        return *this;
    }
    uint8_t b[16] = {0};
    b[10] = 0xff;
    b[11] = 0xff;
    memcpy(b + 12, bytes_, 4);
    return ipv6(b, port_, 0);
}

bool Address::isLoopback() const {
    const Address u = unmapped();
    if (u.family_ == kIPv4) {
        return u.bytes_[0] == 127;
    }
    if (u.family_ == kIPv6) {
        for (int i = 0; i < 15; ++i) {
            if (u.bytes_[i] != 0) {
                return false;
            }
        }
        return u.bytes_[15] == 1;
    }
    return false;
}

bool Address::isAny() const {
    const size_t n = byteLength();
    if (n == 0) {
        return false;
    }
    for (size_t i = 0; i < n; ++i) {
        if (bytes_[i] != 0) {
            return false;
        }
    }
    return true;
}

bool Address::isLinkLocal() const {
    const Address u = unmapped();
    if (u.family_ == kIPv4) {
        return u.bytes_[0] == 169 && u.bytes_[1] == 254;
    }
    if (u.family_ == kIPv6) {
        return u.bytes_[0] == 0xfe && (u.bytes_[1] & 0xc0) == 0x80;
    }
    return false;
}

bool Address::sameHost(const Address& other) const {
    const Address a = unmapped();
    const Address b = other.unmapped();
    if (a.family_ == kNone || a.family_ != b.family_) {
        return false;
    }
    if (memcmp(a.bytes_, b.bytes_, a.byteLength()) != 0) {
        return false;
    }
    return a.family_ == kIPv4 || a.scope_id_ == b.scope_id_;
}

bool Address::operator==(const Address& other) const {
    return family_ == other.family_ && port_ == other.port_ && scope_id_ == other.scope_id_ &&
           memcmp(bytes_, other.bytes_, sizeof(bytes_)) == 0;
}

namespace {

bool parseDecimal(const std::string& s, uint64_t max, uint64_t& out) {
    if (s.empty() || s.size() > 10) {
        return false;
    }
    uint64_t v = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') {
            return false;
        }
        v = v * 10U + static_cast<uint64_t>(s[i] - '0');
    }
    if (v > max) {
        return false;
    }
    out = v;
    return true;
}

bool parseIpv4Text(const std::string& s, uint8_t out[4]) {
    size_t start = 0;
    for (int part = 0; part < 4; ++part) {
        const size_t dot = s.find('.', start);
        const bool last = (part == 3);
        if (last ? dot != std::string::npos : dot == std::string::npos) {
            return false;
        }
        const std::string tok = s.substr(start, last ? std::string::npos : dot - start);
        if (tok.empty() || tok.size() > 3 || (tok.size() > 1 && tok[0] == '0')) {
            return false;  // no leading zeros (octal ambiguity)
        }
        uint64_t v = 0;
        if (!parseDecimal(tok, 255, v)) {
            return false;
        }
        out[part] = static_cast<uint8_t>(v);
        start = dot + 1;
    }
    return true;
}

int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool parseIpv6Text(const std::string& s, uint8_t out[16]) {
    const size_t n = s.size();
    if (n < 2) {
        return false;
    }
    uint16_t head[8];
    uint16_t tail[8];
    size_t nh = 0;
    size_t nt = 0;
    bool compressed = false;
    size_t i = 0;
    if (s[0] == ':') {
        if (s[1] != ':') {
            return false;
        }
        compressed = true;
        i = 2;
    }
    while (i < n) {
        size_t j = i;
        while (j < n && s[j] != ':') {
            ++j;
        }
        const std::string tok = s.substr(i, j - i);
        if (tok.empty()) {
            return false;
        }
        uint16_t* groups = compressed ? tail : head;
        size_t& count = compressed ? nt : nh;
        if (tok.find('.') != std::string::npos) {
            uint8_t v4[4];
            if (j != n || nh + nt + 2 > 8 || !parseIpv4Text(tok, v4)) {
                return false;
            }
            groups[count++] = static_cast<uint16_t>((v4[0] << 8) | v4[1]);
            groups[count++] = static_cast<uint16_t>((v4[2] << 8) | v4[3]);
            break;
        }
        if (tok.size() > 4 || nh + nt >= 8) {
            return false;
        }
        unsigned v = 0;
        for (size_t k = 0; k < tok.size(); ++k) {
            const int h = hexValue(tok[k]);
            if (h < 0) {
                return false;
            }
            v = (v << 4) | static_cast<unsigned>(h);
        }
        groups[count++] = static_cast<uint16_t>(v);
        if (j == n) {
            break;
        }
        if (j + 1 < n && s[j + 1] == ':') {
            if (compressed) {
                return false;  // second "::"
            }
            compressed = true;
            i = j + 2;
        } else {
            i = j + 1;
            if (i == n) {
                return false;  // trailing single ':'
            }
        }
    }
    const size_t total = nh + nt;
    if (compressed ? total > 7 : total != 8) {
        return false;
    }
    uint16_t all[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (size_t k = 0; k < nh; ++k) {
        all[k] = head[k];
    }
    for (size_t k = 0; k < nt; ++k) {
        all[8 - nt + k] = tail[k];
    }
    for (int k = 0; k < 8; ++k) {
        out[2 * k] = static_cast<uint8_t>(all[k] >> 8);
        out[2 * k + 1] = static_cast<uint8_t>(all[k] & 0xff);
    }
    return true;
}

// "addr" or "addr%scope" -> IPv6 address.
bool parseIpv6WithScope(const std::string& s, uint16_t port, Address& out) {
    const size_t pct = s.find('%');
    uint64_t scope = 0;
    std::string host = s;
    if (pct != std::string::npos) {
        host = s.substr(0, pct);
        if (!parseDecimal(s.substr(pct + 1), 0xffffffffULL, scope)) {
            return false;
        }
    }
    uint8_t b[16];
    if (!parseIpv6Text(host, b)) {
        return false;
    }
    out = Address::ipv6(b, port, static_cast<uint32_t>(scope));
    return true;
}

}  // namespace

bool Address::parse(const std::string& text, Address& out) {
    out = Address();
    if (text.empty() || text.size() > 128) {
        return false;
    }
    Address result;
    if (text[0] == '[') {
        const size_t close = text.find(']');
        if (close == std::string::npos) {
            return false;
        }
        uint64_t port = 0;
        const std::string rest = text.substr(close + 1);
        if (!rest.empty()) {
            if (rest[0] != ':' || !parseDecimal(rest.substr(1), 65535, port)) {
                return false;
            }
        }
        if (!parseIpv6WithScope(text.substr(1, close - 1), static_cast<uint16_t>(port), result)) {
            return false;
        }
    } else {
        const size_t first = text.find(':');
        const size_t last = text.rfind(':');
        if (first != std::string::npos && first != last) {
            if (!parseIpv6WithScope(text, 0, result)) {
                return false;
            }
        } else {
            uint64_t port = 0;
            std::string host = text;
            if (first != std::string::npos) {
                host = text.substr(0, first);
                if (!parseDecimal(text.substr(first + 1), 65535, port)) {
                    return false;
                }
            }
            uint8_t b[4];
            if (!parseIpv4Text(host, b)) {
                return false;
            }
            result = ipv4(b, static_cast<uint16_t>(port));
        }
    }
    out = result;
    return true;
}

std::string Address::hostString() const {
    char buf[96];
    if (family_ == kIPv4) {
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", bytes_[0], bytes_[1], bytes_[2], bytes_[3]);
        return buf;
    }
    if (family_ != kIPv6) {
        return std::string();
    }
    std::string s;
    if (isV4Mapped()) {
        snprintf(buf, sizeof(buf), "::ffff:%u.%u.%u.%u", bytes_[12], bytes_[13], bytes_[14],
                      bytes_[15]);
        s = buf;
    } else {
        unsigned g[8];
        for (int k = 0; k < 8; ++k) {
            g[k] = (static_cast<unsigned>(bytes_[2 * k]) << 8) | bytes_[2 * k + 1];
        }
        int best_start = -1;
        int best_len = 0;
        for (int k = 0; k < 8;) {
            if (g[k] != 0) {
                ++k;
                continue;
            }
            int e = k;
            while (e < 8 && g[e] == 0) {
                ++e;
            }
            if (e - k > best_len) {
                best_len = e - k;
                best_start = k;
            }
            k = e;
        }
        if (best_len < 2) {
            best_start = -1;  // RFC 5952 4.2.2: never compress a single zero group
        }
        for (int k = 0; k < 8; ++k) {
            if (k == best_start) {
                s += "::";
                k += best_len - 1;
                continue;
            }
            if (!s.empty() && s[s.size() - 1] != ':') {
                s += ':';
            }
            snprintf(buf, sizeof(buf), "%x", g[k]);
            s += buf;
        }
    }
    if (scope_id_ != 0) {
        snprintf(buf, sizeof(buf), "%%%lu", static_cast<unsigned long>(scope_id_));
        s += buf;
    }
    return s;
}

std::string Address::toString() const {
    if (family_ == kNone) {
        return std::string();
    }
    char port[16];
    snprintf(port, sizeof(port), ":%u", static_cast<unsigned>(port_));
    if (family_ == kIPv6) {
        return "[" + hostString() + "]" + port;
    }
    return hostString() + port;
}

// ------------------------------------------------------------------------------------------------
// Native conversion
// ------------------------------------------------------------------------------------------------

namespace {

#ifdef _WIN32
typedef int NativeLen;
#else
typedef socklen_t NativeLen;
#endif

bool toNative(const Address& a, struct sockaddr_storage& ss, NativeLen& len) {
    memset(&ss, 0, sizeof(ss));
    if (a.family() == Address::kIPv4) {
        struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(&ss);
        sin->sin_family = AF_INET;
        sin->sin_port = htons(a.port());
        memcpy(&sin->sin_addr, a.bytes(), 4);
        len = static_cast<NativeLen>(sizeof(*sin));
        return true;
    }
    if (a.family() == Address::kIPv6) {
        struct sockaddr_in6* sin6 = reinterpret_cast<struct sockaddr_in6*>(&ss);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(a.port());
        memcpy(&sin6->sin6_addr, a.bytes(), 16);
        sin6->sin6_scope_id = a.scopeId();
        len = static_cast<NativeLen>(sizeof(*sin6));
        return true;
    }
    return false;
}

bool fromNative(const struct sockaddr_storage& ss, NativeLen len, Address& out) {
    if (ss.ss_family == AF_INET && len >= static_cast<NativeLen>(sizeof(struct sockaddr_in))) {
        const struct sockaddr_in* sin = reinterpret_cast<const struct sockaddr_in*>(&ss);
        uint8_t b[4];
        memcpy(b, &sin->sin_addr, 4);
        out = Address::ipv4(b, ntohs(sin->sin_port));
        return true;
    }
    if (ss.ss_family == AF_INET6 && len >= static_cast<NativeLen>(sizeof(struct sockaddr_in6))) {
        const struct sockaddr_in6* sin6 = reinterpret_cast<const struct sockaddr_in6*>(&ss);
        uint8_t b[16];
        memcpy(b, &sin6->sin6_addr, 16);
        out = Address::ipv6(b, ntohs(sin6->sin6_port), sin6->sin6_scope_id).unmapped();
        return true;
    }
    out = Address();
    return false;
}

bool setIntOption(SocketHandle h, int level, int name, int value) {
#ifdef _WIN32
    return setsockopt(h, level, name, reinterpret_cast<const char*>(&value), sizeof(value)) == 0;
#else
    return setsockopt(h, level, name, &value, sizeof(value)) == 0;
#endif
}

bool getIntOption(SocketHandle h, int level, int name, int& value) {
    NativeLen len = static_cast<NativeLen>(sizeof(value));
    value = 0;
#ifdef _WIN32
    return getsockopt(h, level, name, reinterpret_cast<char*>(&value), &len) == 0;
#else
    return getsockopt(h, level, name, &value, &len) == 0;
#endif
}

// Destination as the socket's family needs it (IPv4 on an IPv6 dual-stack socket -> mapped).
Address destinationFor(SocketHandle h, const Address& to) {
    if (to.family() == Address::kIPv4 && socketFamily(h) == Address::kIPv6) {
        return to.v4Mapped();
    }
    return to;
}

int clampLen(size_t n) { return n > static_cast<size_t>(INT_MAX) ? INT_MAX : static_cast<int>(n); }

}  // namespace

// ------------------------------------------------------------------------------------------------
// Socket operations
// ------------------------------------------------------------------------------------------------

bool socketSetNonBlocking(SocketHandle h) {
#ifdef _WIN32
    u_long on = 1;
    return ioctlsocket(h, FIONBIO, &on) == 0;
#else
    const int flags = fcntl(h, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return fcntl(h, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

#ifndef _WIN32
static bool setCloseOnExec(int fd) {
    const int flags = fcntl(fd, F_GETFD, 0);
    return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}
#endif

SocketHandle socketOpen(Address::Family family, SocketType type) {
    if (!netInit() || family == Address::kNone) {
        return kInvalidSocket;
    }
    const int af = (family == Address::kIPv6) ? AF_INET6 : AF_INET;
    const int st = (type == kSockStream) ? SOCK_STREAM : SOCK_DGRAM;
#ifdef _WIN32
    SocketHandle h = socket(af, st, 0);
    if (h == kInvalidSocket) {
        return kInvalidSocket;
    }
    if (type == kSockDatagram) {
        // Without this an ICMP port-unreachable makes the next recvfrom fail with WSAECONNRESET.
        BOOL report = FALSE;
        DWORD ignored = 0;
        WSAIoctl(h, SIO_UDP_CONNRESET, &report, sizeof(report), NULL, 0, &ignored, NULL, NULL);
    }
#else
    int flags = st;
#ifdef SOCK_CLOEXEC
    flags |= SOCK_CLOEXEC;
#endif
    SocketHandle h = socket(af, flags, 0);
    if (h < 0) {
        return kInvalidSocket;
    }
    if (!setCloseOnExec(h)) {
        socketClose(h);
        return kInvalidSocket;
    }
#endif
    if (!socketSetNonBlocking(h)) {
        socketClose(h);
        return kInvalidSocket;
    }
    return h;
}

void socketClose(SocketHandle& h) {
    if (h == kInvalidSocket) {
        return;
    }
#ifdef _WIN32
    closesocket(h);
#else
    // Do not retry close() on EINTR: on Linux the descriptor is released regardless.
    close(h);
#endif
    h = kInvalidSocket;
}

bool setReuseAddress(SocketHandle h) {
#ifdef _WIN32
    return setIntOption(h, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1);
#else
    return setIntOption(h, SOL_SOCKET, SO_REUSEADDR, 1);
#endif
}

bool setV6Only(SocketHandle h, bool v6only) {
    return setIntOption(h, IPPROTO_IPV6, IPV6_V6ONLY, v6only ? 1 : 0);
}

bool setNoDelay(SocketHandle h, bool on) { return setIntOption(h, IPPROTO_TCP, TCP_NODELAY, on ? 1 : 0); }

bool setKeepAlive(SocketHandle h, bool on) { return setIntOption(h, SOL_SOCKET, SO_KEEPALIVE, on ? 1 : 0); }

bool setLingerZero(SocketHandle h) {
    struct linger lg;
    lg.l_onoff = 1;
    lg.l_linger = 0;
#ifdef _WIN32
    return setsockopt(h, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&lg), sizeof(lg)) == 0;
#else
    return setsockopt(h, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg)) == 0;
#endif
}

static bool setBufferOption(SocketHandle h, int name, size_t requested, size_t& granted_out) {
    granted_out = 0;
    const int req = clampLen(requested);
    const bool set_ok = setIntOption(h, SOL_SOCKET, name, req);
    int got = 0;
    if (!getIntOption(h, SOL_SOCKET, name, got) || got < 0) {
        return false;
    }
    granted_out = static_cast<size_t>(got);
    return set_ok;
}

bool setReceiveBuffer(SocketHandle h, size_t requested, size_t& granted_out) {
    return setBufferOption(h, SO_RCVBUF, requested, granted_out);
}

bool setSendBuffer(SocketHandle h, size_t requested, size_t& granted_out) {
    return setBufferOption(h, SO_SNDBUF, requested, granted_out);
}

bool takeSocketError(SocketHandle h, int& error_out) {
    return getIntOption(h, SOL_SOCKET, SO_ERROR, error_out);
}

bool socketBind(SocketHandle h, const Address& address) {
    struct sockaddr_storage ss;
    NativeLen len = 0;
    if (!toNative(address, ss, len)) {
        return false;
    }
    return bind(h, reinterpret_cast<struct sockaddr*>(&ss), len) == 0;
}

bool socketListen(SocketHandle h, int backlog) { return listen(h, backlog) == 0; }

IoStatus socketAccept(SocketHandle h, SocketHandle& accepted_out, Address& peer_out) {
    accepted_out = kInvalidSocket;
    for (;;) {
        struct sockaddr_storage ss;
        NativeLen len = static_cast<NativeLen>(sizeof(ss));
        SocketHandle c = accept(h, reinterpret_cast<struct sockaddr*>(&ss), &len);
        if (c == kInvalidSocket
#ifndef _WIN32
            || c < 0
#endif
        ) {
            const int e = lastSocketError();
#ifndef _WIN32
            if (e == EINTR) {
                continue;
            }
            // The connection died between SYN and accept: not a listener failure.
            if (e == ECONNABORTED || e == EPROTO) {
                return kIoWouldBlock;
            }
#else
            if (e == WSAECONNRESET) {
                return kIoWouldBlock;
            }
#endif
            return errWouldBlock(e) ? kIoWouldBlock : kIoError;
        }
#ifndef _WIN32
        if (!setCloseOnExec(c)) {
            socketClose(c);
            return kIoError;
        }
#endif
        if (!socketSetNonBlocking(c) || !fromNative(ss, len, peer_out)) {
            socketClose(c);
            return kIoError;
        }
        accepted_out = c;
        return kIoOk;
    }
}

IoStatus socketConnect(SocketHandle h, const Address& remote) {
    struct sockaddr_storage ss;
    NativeLen len = 0;
    if (!toNative(destinationFor(h, remote), ss, len)) {
        return kIoError;
    }
    if (connect(h, reinterpret_cast<struct sockaddr*>(&ss), len) == 0) {
        return kIoOk;
    }
    const int e = lastSocketError();
#ifdef _WIN32
    return errWouldBlock(e) ? kIoWouldBlock : kIoError;
#else
    // EINTR: the connection attempt continues asynchronously, exactly like EINPROGRESS.
    return (e == EINPROGRESS || e == EINTR) ? kIoWouldBlock : kIoError;
#endif
}

bool socketLocalAddress(SocketHandle h, Address& out) {
    struct sockaddr_storage ss;
    NativeLen len = static_cast<NativeLen>(sizeof(ss));
    if (getsockname(h, reinterpret_cast<struct sockaddr*>(&ss), &len) != 0) {
        out = Address();
        return false;
    }
    return fromNative(ss, len, out);
}

bool socketPeerAddress(SocketHandle h, Address& out) {
    struct sockaddr_storage ss;
    NativeLen len = static_cast<NativeLen>(sizeof(ss));
    if (getpeername(h, reinterpret_cast<struct sockaddr*>(&ss), &len) != 0) {
        out = Address();
        return false;
    }
    return fromNative(ss, len, out);
}

Address::Family socketFamily(SocketHandle h) {
    struct sockaddr_storage ss;
    NativeLen len = static_cast<NativeLen>(sizeof(ss));
    if (getsockname(h, reinterpret_cast<struct sockaddr*>(&ss), &len) != 0) {
        return Address::kNone;
    }
    if (ss.ss_family == AF_INET6) {
        return Address::kIPv6;
    }
    return ss.ss_family == AF_INET ? Address::kIPv4 : Address::kNone;
}

IoStatus socketRecv(SocketHandle h, uint8_t* buf, size_t cap, size_t& got) {
    got = 0;
    if (h == kInvalidSocket) {
        return kIoClosed;
    }
    if (cap == 0) {
        return kIoOk;
    }
    for (;;) {
#ifdef _WIN32
        const int r = recv(h, reinterpret_cast<char*>(buf), clampLen(cap), 0);
#else
        const ssize_t r = recv(h, buf, cap, 0);
#endif
        if (r > 0) {
            got = static_cast<size_t>(r);
            return kIoOk;
        }
        if (r == 0) {
            return kIoClosed;
        }
        const int e = lastSocketError();
#ifndef _WIN32
        if (e == EINTR) {
            continue;
        }
#endif
        return errWouldBlock(e) ? kIoWouldBlock : kIoError;
    }
}

IoStatus socketSend(SocketHandle h, const uint8_t* data, size_t len, size_t& sent) {
    sent = 0;
    if (h == kInvalidSocket) {
        return kIoClosed;
    }
    if (len == 0) {
        return kIoOk;
    }
    for (;;) {
#ifdef _WIN32
        const int r = send(h, reinterpret_cast<const char*>(data), clampLen(len), 0);
#else
        const ssize_t r = send(h, data, len, MSG_NOSIGNAL);
#endif
        if (r >= 0) {
            sent = static_cast<size_t>(r);
            return kIoOk;
        }
        const int e = lastSocketError();
#ifndef _WIN32
        if (e == EINTR) {
            continue;
        }
#endif
        return errWouldBlock(e) ? kIoWouldBlock : kIoError;
    }
}

IoStatus socketRecvFrom(SocketHandle h, uint8_t* buf, size_t cap, size_t& got, Address& from) {
    got = 0;
    from = Address();
    if (h == kInvalidSocket) {
        return kIoClosed;
    }
    for (;;) {
        struct sockaddr_storage ss;
        NativeLen slen = static_cast<NativeLen>(sizeof(ss));
#ifdef _WIN32
        const int r = recvfrom(h, reinterpret_cast<char*>(buf), clampLen(cap), 0,
                               reinterpret_cast<struct sockaddr*>(&ss), &slen);
        if (r < 0) {
            const int e = lastSocketError();
            if (e == WSAEMSGSIZE) {
                got = cap;
                fromNative(ss, slen, from);
                return kIoTruncated;
            }
            return errWouldBlock(e) ? kIoWouldBlock : kIoError;
        }
        got = static_cast<size_t>(r);
        fromNative(ss, slen, from);
        return kIoOk;
#else
        // MSG_TRUNC: Linux returns the real datagram length, so truncation is detectable.
        const ssize_t r = recvfrom(h, buf, cap, MSG_TRUNC, reinterpret_cast<struct sockaddr*>(&ss), &slen);
        if (r < 0) {
            const int e = lastSocketError();
            if (e == EINTR) {
                continue;
            }
            return errWouldBlock(e) ? kIoWouldBlock : kIoError;
        }
        fromNative(ss, slen, from);
        if (static_cast<size_t>(r) > cap) {
            got = cap;
            return kIoTruncated;
        }
        got = static_cast<size_t>(r);
        return kIoOk;
#endif
    }
}

IoStatus socketSendTo(SocketHandle h, const uint8_t* data, size_t len, const Address& to) {
    if (h == kInvalidSocket) {
        return kIoClosed;
    }
    struct sockaddr_storage ss;
    NativeLen slen = 0;
    if (!toNative(destinationFor(h, to), ss, slen)) {
        return kIoError;
    }
    for (;;) {
#ifdef _WIN32
        const int r = sendto(h, reinterpret_cast<const char*>(data), clampLen(len), 0,
                             reinterpret_cast<struct sockaddr*>(&ss), slen);
#else
        const ssize_t r = sendto(h, data, len, MSG_NOSIGNAL, reinterpret_cast<struct sockaddr*>(&ss), slen);
#endif
        if (r >= 0) {
            return static_cast<size_t>(r) == len ? kIoOk : kIoError;
        }
        const int e = lastSocketError();
#ifndef _WIN32
        if (e == EINTR) {
            continue;
        }
#endif
        return errWouldBlock(e) ? kIoWouldBlock : kIoError;
    }
}

bool socketShutdownWrite(SocketHandle h) {
#ifdef _WIN32
    return shutdown(h, SD_SEND) == 0;
#else
    return shutdown(h, SHUT_WR) == 0;
#endif
}

// ------------------------------------------------------------------------------------------------
// PollSet
// ------------------------------------------------------------------------------------------------

#ifdef _WIN32
typedef WSAPOLLFD NativePollFd;
#else
typedef struct pollfd NativePollFd;
#endif

struct PollSet::Impl {
    std::vector<NativePollFd> fds;
};

PollSet::PollSet() : impl_(new Impl()) {}

PollSet::~PollSet() { delete impl_; }

void PollSet::reserve(size_t n) { impl_->fds.reserve(n); }

int PollSet::wait(PollItem* items, size_t count, int timeout_ms) {
    if (count == 0) {
        if (timeout_ms < 0) {
            return -1;  // would sleep forever with nothing to wake it
        }
#ifdef _WIN32
        Sleep(static_cast<DWORD>(timeout_ms));
#else
        poll(NULL, 0, timeout_ms);
#endif
        return 0;
    }
    std::vector<NativePollFd>& fds = impl_->fds;
    if (fds.size() < count) {
        fds.resize(count);
    }
    for (size_t i = 0; i < count; ++i) {
        fds[i].fd = items[i].handle;
        short ev = 0;
        if (items[i].events & kPollIn) ev = static_cast<short>(ev | POLLIN);
        if (items[i].events & kPollOut) ev = static_cast<short>(ev | POLLOUT);
        fds[i].events = ev;
        fds[i].revents = 0;
        items[i].revents = 0;
    }
#ifdef _WIN32
    const int r = WSAPoll(&fds[0], static_cast<ULONG>(count), timeout_ms);
    if (r < 0) {
        return -1;
    }
#else
    const int r = poll(&fds[0], static_cast<nfds_t>(count), timeout_ms);
    if (r < 0) {
        return (errno == EINTR) ? 0 : -1;
    }
#endif
    int ready = 0;
    for (size_t i = 0; i < count; ++i) {
        const short re = fds[i].revents;
        unsigned out = 0;
        if (re & POLLIN) out |= kPollIn;
        if (re & POLLOUT) out |= kPollOut;
        if (re & POLLERR) out |= kPollErr;
        if (re & POLLHUP) out |= kPollHup;
        if (re & POLLNVAL) out |= kPollNval;
        items[i].revents = out;
        if (out != 0) {
            ++ready;
        }
    }
    return ready;
}

// ------------------------------------------------------------------------------------------------
// Wake pair
// ------------------------------------------------------------------------------------------------

#ifdef _WIN32
// Blocks (bounded) until `h` is ready for `events`.
static bool waitReady(SocketHandle h, short events, int timeout_ms) {
    WSAPOLLFD p;
    p.fd = h;
    p.events = events;
    p.revents = 0;
    return WSAPoll(&p, 1, timeout_ms) == 1 && (p.revents & events) != 0;
}

bool wakePairOpen(SocketHandle& read_end, SocketHandle& write_end) {
    read_end = kInvalidSocket;
    write_end = kInvalidSocket;
    SocketHandle lst = socketOpen(Address::kIPv4, kSockStream);
    if (lst == kInvalidSocket) {
        return false;
    }
    Address bound;
    SocketHandle client = kInvalidSocket;
    SocketHandle server = kInvalidSocket;
    Address peer;
    Address client_local;
    bool ok = socketBind(lst, Address::ipv4Loopback(0)) && socketListen(lst, 1) &&
              socketLocalAddress(lst, bound);
    if (ok) {
        client = socketOpen(Address::kIPv4, kSockStream);
        ok = client != kInvalidSocket && socketConnect(client, bound) != kIoError &&
             waitReady(lst, POLLRDNORM, 5000) && socketAccept(lst, server, peer) == kIoOk &&
             waitReady(client, POLLWRNORM, 5000) && socketLocalAddress(client, client_local) &&
             peer == client_local;  // refuse a foreign local process that raced us to the listener
    }
    socketClose(lst);
    if (!ok) {
        socketClose(client);
        socketClose(server);
        return false;
    }
    setNoDelay(client, true);
    read_end = server;
    write_end = client;
    return true;
}

void wakePairClose(SocketHandle& read_end, SocketHandle& write_end) {
    socketClose(read_end);
    socketClose(write_end);
}

void wakeSignal(SocketHandle write_end) {
    const char b = 1;
    send(write_end, &b, 1, 0);  // WSAEWOULDBLOCK: plenty of wake bytes already pending
}

void wakeDrain(SocketHandle read_end) {
    char buf[64];
    while (recv(read_end, buf, sizeof(buf), 0) > 0) {
    }
}
#else
bool wakePairOpen(SocketHandle& read_end, SocketHandle& write_end) {
    read_end = kInvalidSocket;
    write_end = kInvalidSocket;
    int fds[2];
    if (pipe(fds) != 0) {
        return false;
    }
    for (int i = 0; i < 2; ++i) {
        const int fl = fcntl(fds[i], F_GETFL, 0);
        if (fl < 0 || fcntl(fds[i], F_SETFL, fl | O_NONBLOCK) != 0 || !setCloseOnExec(fds[i])) {
            close(fds[0]);
            close(fds[1]);
            return false;
        }
    }
    read_end = fds[0];
    write_end = fds[1];
    return true;
}

void wakePairClose(SocketHandle& read_end, SocketHandle& write_end) {
    if (read_end >= 0) close(read_end);
    if (write_end >= 0) close(write_end);
    read_end = kInvalidSocket;
    write_end = kInvalidSocket;
}

void wakeSignal(SocketHandle write_end) {
    const char b = 1;
    ssize_t r;
    do {
        r = write(write_end, &b, 1);
    } while (r < 0 && errno == EINTR);
    // EAGAIN: the pipe is full, so a wake-up is already pending.
}

void wakeDrain(SocketHandle read_end) {
    char buf[64];
    for (;;) {
        const ssize_t r = read(read_end, buf, sizeof(buf));
        if (r > 0) {
            continue;
        }
        if (r < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
}
#endif

}  // namespace platform
}  // namespace carplay
