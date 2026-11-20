// Platform base: Address, monotonic clock, OS randomness, logger, UDP and IPv6 / dual-stack TCP.
// Loopback + ephemeral ports only; every wait is a bounded poll loop (no sleeps).

#include <string.h>

#include <cstdio>
#include <string>
#include <vector>

#include "carplay/platform/log.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/os_random.hpp"
#include "carplay/platform/tcp.hpp"
#include "carplay/platform/udp.hpp"
#include "test_support.hpp"

using namespace carplay::platform;

namespace {

const int64_t kDeadlineMs = 5000;

// Waits (bounded) until `h` reports any of `events`.
bool waitFor(SocketHandle h, unsigned events) {
    PollSet ps;
    const int64_t end = monotonicMillis() + kDeadlineMs;
    while (monotonicMillis() < end) {
        PollItem it;
        it.handle = h;
        it.events = events;
        it.revents = 0;
        if (ps.wait(&it, 1, 50) > 0 && (it.revents & (events | kPollErr | kPollHup))) {
            return true;
        }
    }
    return false;
}

bool parseOk(const char* text, Address& out) { return Address::parse(text, out); }

std::string roundTrip(const char* text) {
    Address a;
    if (!Address::parse(text, a)) {
        return "<parse error>";
    }
    return a.port() != 0 ? a.toString() : a.hostString();
}

}  // namespace

// ------------------------------------------------------------------------------------------------
// Address
// ------------------------------------------------------------------------------------------------

TEST_CASE(addressParsesAndFormats) {
    CHECK_EQ(std::string("1.2.3.4"), roundTrip("1.2.3.4"));
    CHECK_EQ(std::string("192.168.1.10:7000"), roundTrip("192.168.1.10:7000"));
    CHECK_EQ(std::string("::"), roundTrip("::"));
    CHECK_EQ(std::string("::1"), roundTrip("::1"));
    CHECK_EQ(std::string("::1"), roundTrip("0:0:0:0:0:0:0:1"));
    CHECK_EQ(std::string("[::1]:7000"), roundTrip("[::1]:7000"));
    CHECK_EQ(std::string("fe80::1%4"), roundTrip("fe80::1%4"));
    CHECK_EQ(std::string("[fe80::abcd:1%12]:5000"), roundTrip("[FE80::ABCD:1%12]:5000"));
    // RFC 5952: longest run compressed (first on ties), never a single zero group.
    CHECK_EQ(std::string("2001:db8::1:0:0:1"), roundTrip("2001:db8:0:0:1:0:0:1"));
    CHECK_EQ(std::string("2001:db8:0:1:1:1:1:1"), roundTrip("2001:db8:0:1:1:1:1:1"));
    CHECK_EQ(std::string("2001:0:0:1::1"), roundTrip("2001:0:0:1:0:0:0:1"));
    CHECK_EQ(std::string("1::"), roundTrip("1:0:0:0:0:0:0:0"));
    CHECK_EQ(std::string("::ffff:10.0.0.1"), roundTrip("::ffff:10.0.0.1"));
    CHECK_EQ(std::string("::ffff:10.0.0.1"), roundTrip("::ffff:a00:1"));
    CHECK_EQ(std::string("64:ff9b::102:304"), roundTrip("64:ff9b::1.2.3.4"));

    Address a;
    REQUIRE(parseOk("[fe80::1%3]:65535", a));
    CHECK(a.family() == Address::kIPv6);
    CHECK_EQ(65535, static_cast<int>(a.port()));
    CHECK_EQ(3u, static_cast<unsigned>(a.scopeId()));
    CHECK(a.isLinkLocal());
    CHECK(!a.isLoopback());
    CHECK_EQ(16u, static_cast<unsigned>(a.byteLength()));
}

TEST_CASE(addressRejectsMalformed) {
    const char* bad[] = {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3.4:", "1.2.3.4:65536",
                         "1.2.3.4:x", "1.2.3.4%1", ":::", "1:::2", "1::2::3", "1:2:3:4:5:6:7:8:9",
                         "1:2:3:4:5:6:7", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "12345::", "g::1",
                         "[::1", "[::1]x", "[::1]:", "::1%", "::1%x", "::1.2.3.4.5", "1.2.3.4::",
                         "::ffff:1.2.3.4:5", " 1.2.3.4", "localhost"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        Address a;
        if (Address::parse(bad[i], a)) {
            ::test_support::recordFailure(__FILE__, __LINE__, std::string("accepted: ") + bad[i]);
        }
        CHECK(!a.valid());
    }
}

TEST_CASE(addressSameHostAndEquality) {
    Address v4;
    Address mapped;
    Address other;
    REQUIRE(Address::parse("10.0.0.7:1000", v4));
    REQUIRE(Address::parse("[::ffff:10.0.0.7]:2000", mapped));
    REQUIRE(Address::parse("10.0.0.8:1000", other));
    CHECK(v4.sameHost(mapped));
    CHECK(mapped.sameHost(v4));
    CHECK(!v4.sameHost(other));
    CHECK(v4 != mapped);
    CHECK(mapped.unmapped().sameHost(v4));
    CHECK(mapped.unmapped().family() == Address::kIPv4);
    CHECK_EQ(2000, static_cast<int>(mapped.unmapped().port()));
    CHECK(v4.v4Mapped().isV4Mapped());
    CHECK(v4.v4Mapped().sameHost(v4));

    Address ll1;
    Address ll2;
    Address ll3;
    REQUIRE(Address::parse("[fe80::1%2]:1", ll1));
    REQUIRE(Address::parse("[fe80::1%2]:9", ll2));
    REQUIRE(Address::parse("[fe80::1%3]:1", ll3));
    CHECK(ll1.sameHost(ll2));
    CHECK(!(ll1 == ll2));
    CHECK(!ll1.sameHost(ll3));  // different interface
    CHECK(!Address().sameHost(Address()));

    Address copy = ll1;
    CHECK(copy == ll1);
    CHECK(Address::ipv4Loopback(5).isLoopback());
    CHECK(Address::ipv6Loopback(5).isLoopback());
    CHECK(Address::ipv6Any(0).isAny());
    CHECK(Address::ipv4Any(0).isAny());
    CHECK_EQ(std::string("127.0.0.1:5"), Address::ipv4Loopback(5).toString());
    CHECK_EQ(std::string("[::1]:5"), Address::ipv6Loopback(5).toString());
    CHECK_EQ(std::string(""), Address().toString());
}

// ------------------------------------------------------------------------------------------------
// Clock, RNG, log
// ------------------------------------------------------------------------------------------------

TEST_CASE(monotonicClockNeverGoesBack) {
    int64_t prev = monotonicNanos();
    CHECK(prev >= 0);
    for (int i = 0; i < 20000; ++i) {
        const int64_t now = monotonicNanos();
        if (now < prev) {
            CHECK(now >= prev);
            break;
        }
        prev = now;
    }
    const int64_t start = monotonicNanos();
    while (monotonicNanos() == start) {
    }
    CHECK(monotonicNanos() > start);  // it advances
    CHECK(monotonicMillis() >= 0);
}

TEST_CASE(osRandomHonoursLengthsAndVaries) {
    OsRandomSource rng;
    CHECK(rng.fill(NULL, 0));
    uint8_t one = 0;
    CHECK(rng.fill(&one, 1));
    std::vector<uint8_t> a(4096, 0);
    std::vector<uint8_t> b(4096, 0);
    REQUIRE(rng.fill(&a[0], a.size()));
    REQUIRE(rng.fill(&b[0], b.size()));
    CHECK(a != b);
    // Every byte value should appear in 4096 random bytes far more often than not; just require a
    // non-degenerate spread (> 200 distinct values) to catch constant / stuck output.
    bool seen[256];
    memset(seen, 0, sizeof(seen));
    for (size_t i = 0; i < a.size(); ++i) {
        seen[a[i]] = true;
    }
    int distinct = 0;
    for (int i = 0; i < 256; ++i) {
        distinct += seen[i] ? 1 : 0;
    }
    CHECK(distinct > 200);
    // Exact length: bytes past the requested range are untouched.
    uint8_t guard[8];
    memset(guard, 0xa5, sizeof(guard));
    REQUIRE(rng.fill(guard, 4));
    for (int i = 4; i < 8; ++i) {
        CHECK_EQ(0xa5, static_cast<int>(guard[i]));
    }
    CHECK(randomSelfTest(rng));
}

namespace {

class ConstantRng : public carplay::pairing::RandomSource {
public:
    virtual bool fill(uint8_t* out, size_t len) {
        memset(out, 7, len);
        return true;
    }
};

struct LogCapture {
    std::vector<std::string> lines;
    std::vector<LogLevel> levels;
};

void captureSink(void* ctx, LogLevel level, const char* tag, const char* message) {
    LogCapture* c = static_cast<LogCapture*>(ctx);
    c->levels.push_back(level);
    c->lines.push_back(std::string(tag) + "|" + message);
}

}  // namespace

TEST_CASE(randomSelfTestRejectsConstantSource) {
    ConstantRng bad;
    CHECK(!randomSelfTest(bad));
}

TEST_CASE(logLevelsSinkAndTruncation) {
    LogCapture cap;
    const LogLevel saved = logLevel();
    setLogSink(&captureSink, &cap);
    setLogLevel(kLogInfo);
    CARPLAY_LOG_INFO("net", "port %u peer %s", 7000u, "1.2.3.4");
    CARPLAY_LOG_DEBUG("net", "hidden %d", 1);
    CARPLAY_LOG_ERROR("net", "size %zu big %lld", static_cast<size_t>(42), 123456789012LL);
    setLogLevel(kLogWarn);
    CARPLAY_LOG_INFO("net", "dropped");
    CARPLAY_LOG_WARN("net", "kept");
    const std::string longText(2000, 'x');
    CARPLAY_LOG_WARN("t", "%s", longText.c_str());
    setLogSink(NULL, NULL);
    setLogLevel(saved);

    REQUIRE(cap.lines.size() == 4u);
    CHECK_EQ(std::string("net|port 7000 peer 1.2.3.4"), cap.lines[0]);
    CHECK_EQ(std::string("net|size 42 big 123456789012"), cap.lines[1]);
    CHECK(cap.levels[1] == kLogError);
    CHECK_EQ(std::string("net|kept"), cap.lines[2]);
    CHECK_EQ(static_cast<size_t>(2 + kLogMaxMessage - 1), cap.lines[3].size());
    CHECK(cap.lines[3].compare(cap.lines[3].size() - 3, 3, "...") == 0);
    CHECK_EQ('D', logLevelChar(kLogDebug));
}

// ------------------------------------------------------------------------------------------------
// UDP
// ------------------------------------------------------------------------------------------------

TEST_CASE(udpRoundTripReportsSender) {
    UdpSocket a;
    UdpSocket b;
    REQUIRE(a.open(Address::ipv4Loopback(0)));
    REQUIRE(b.open(Address::ipv4Loopback(0)));
    CHECK(a.port() != 0);
    CHECK(b.port() != a.port());
    const uint8_t ping[5] = {'p', 'i', 'n', 'g', 0};
    REQUIRE(a.sendTo(ping, sizeof(ping), b.localAddress()) == kIoOk);
    REQUIRE(waitFor(b.handle(), kPollIn));
    uint8_t buf[64];
    size_t got = 0;
    Address from;
    REQUIRE(b.receiveFrom(buf, sizeof(buf), got, from) == kIoOk);
    CHECK_EQ(sizeof(ping), got);
    CHECK(memcmp(buf, ping, sizeof(ping)) == 0);
    CHECK(from == a.localAddress());
    // Reply to the reported sender.
    REQUIRE(b.sendTo(buf, got, from) == kIoOk);
    REQUIRE(waitFor(a.handle(), kPollIn));
    Address from2;
    REQUIRE(a.receiveFrom(buf, sizeof(buf), got, from2) == kIoOk);
    CHECK(from2 == b.localAddress());
    // Nothing left: would block.
    CHECK(a.receiveFrom(buf, sizeof(buf), got, from2) == kIoWouldBlock);
}

TEST_CASE(udpTruncationAndReceiveBuffer) {
    UdpSocket a;
    UdpSocket b;
    REQUIRE(a.open(Address::ipv4Loopback(0)));
    REQUIRE(b.open(Address::ipv4Loopback(0)));
    uint8_t big[100];
    for (size_t i = 0; i < sizeof(big); ++i) {
        big[i] = static_cast<uint8_t>(i);
    }
    REQUIRE(a.sendTo(big, sizeof(big), b.localAddress()) == kIoOk);
    REQUIRE(waitFor(b.handle(), kPollIn));
    uint8_t small[10];
    size_t got = 0;
    Address from;
    CHECK(b.receiveFrom(small, sizeof(small), got, from) == kIoTruncated);
    CHECK_EQ(sizeof(small), got);
    CHECK(memcmp(small, big, sizeof(small)) == 0);
    CHECK(from == a.localAddress());

    size_t granted = 0;
    CHECK(b.setReceiveBuffer(UdpSocket::kAudioReceiveBuffer, granted));
    CHECK(granted > 0);
    std::printf("  [INFO] SO_RCVBUF requested %u, granted %u\n",
                static_cast<unsigned>(UdpSocket::kAudioReceiveBuffer), static_cast<unsigned>(granted));
}

TEST_CASE(udpDualStackReceivesIpv4AsPlainIpv4) {
    UdpSocket any;
    REQUIRE(any.openAny(0));
    UdpSocket v4;
    REQUIRE(v4.open(Address::ipv4Loopback(0)));
    const uint8_t msg[3] = {1, 2, 3};
    REQUIRE(v4.sendTo(msg, sizeof(msg), Address::ipv4Loopback(any.port())) == kIoOk);
    REQUIRE(waitFor(any.handle(), kPollIn));
    uint8_t buf[8];
    size_t got = 0;
    Address from;
    REQUIRE(any.receiveFrom(buf, sizeof(buf), got, from) == kIoOk);
    CHECK(from.family() == Address::kIPv4);  // unmapped even on a dual-stack socket
    CHECK(from == v4.localAddress());
    // And the dual-stack socket can answer an IPv4 destination.
    REQUIRE(any.sendTo(buf, got, from) == kIoOk);
    REQUIRE(waitFor(v4.handle(), kPollIn));
    Address back;
    REQUIRE(v4.receiveFrom(buf, sizeof(buf), got, back) == kIoOk);
    CHECK_EQ(static_cast<int>(any.port()), static_cast<int>(back.port()));
    std::printf("  [INFO] UDP openAny dual-stack: %s\n", any.dualStack() ? "yes" : "no (IPv4 fallback)");
}

// ------------------------------------------------------------------------------------------------
// TCP without the reactor
// ------------------------------------------------------------------------------------------------

namespace {

// Connects `client` to `listener` and accepts into `server` (bounded loops).
bool connectPair(TcpListener& listener, const Address& target, TcpConnection& client, TcpConnection& server) {
    if (!client.connect(target)) {
        return false;
    }
    if (!waitFor(listener.handle(), kPollIn)) {
        return false;
    }
    const int64_t end = monotonicMillis() + kDeadlineMs;
    TcpListener::AcceptResult r = TcpListener::kNoPending;
    while (r == TcpListener::kNoPending && monotonicMillis() < end) {
        r = listener.accept(server);
    }
    if (r != TcpListener::kAccepted || !waitFor(client.handle(), kPollOut)) {
        return false;
    }
    while (client.finishConnect() == kIoWouldBlock && monotonicMillis() < end) {
    }
    return !client.connecting();
}

bool exchange(TcpConnection& from, TcpConnection& to, const std::string& text) {
    if (from.send(reinterpret_cast<const uint8_t*>(text.data()), text.size()) != TcpConnection::kSendOk) {
        return false;
    }
    std::vector<uint8_t> got;
    const int64_t end = monotonicMillis() + kDeadlineMs;
    while (got.size() < text.size() && monotonicMillis() < end) {
        if (!waitFor(to.handle(), kPollIn)) {
            return false;
        }
        const IoStatus st = to.readAppend(got, 4096);
        if (st == kIoClosed || st == kIoError) {
            return false;
        }
    }
    return std::string(got.begin(), got.end()) == text;
}

}  // namespace

TEST_CASE(tcpDualStackListenerAcceptsIpv4Peer) {
    TcpListener lst;
    REQUIRE(lst.listenAny(0));
    CHECK(lst.port() != 0);
    TcpConnection client;
    TcpConnection server;
    REQUIRE(connectPair(lst, Address::ipv4Loopback(lst.port()), client, server));
    CHECK(server.peerAddress().family() == Address::kIPv4);  // ::ffff:127.0.0.1 reported unmapped
    CHECK(server.peerAddress() == client.localAddress());
    CHECK(client.peerAddress() == Address::ipv4Loopback(lst.port()));
    CHECK(client.setNoDelay(true));
    CHECK(client.setKeepAlive(true));
    CHECK(server.setLingerZero());
    CHECK(exchange(client, server, "hello"));
    CHECK(exchange(server, client, "world"));
    std::printf("  [INFO] TCP listenAny dual-stack: %s\n", lst.dualStack() ? "yes" : "no (IPv4 fallback)");
}

TEST_CASE(tcpIpv6LoopbackWhenAvailable) {
    TcpListener lst;
    if (!lst.listen(Address::ipv6Loopback(0))) {
        std::printf("  [SKIP] IPv6 loopback unavailable on this host\n");
        return;
    }
    TcpConnection client;
    TcpConnection server;
    REQUIRE(connectPair(lst, Address::ipv6Loopback(lst.port()), client, server));
    CHECK(server.peerAddress().family() == Address::kIPv6);
    CHECK(server.peerAddress().isLoopback());
    CHECK(server.peerAddress().sameHost(Address::ipv6Loopback(0)));
    CHECK(exchange(client, server, "six"));

    UdpSocket a;
    UdpSocket b;
    REQUIRE(a.open(Address::ipv6Loopback(0)));
    REQUIRE(b.open(Address::ipv6Loopback(0)));
    const uint8_t msg[2] = {6, 6};
    REQUIRE(a.sendTo(msg, sizeof(msg), b.localAddress()) == kIoOk);
    REQUIRE(waitFor(b.handle(), kPollIn));
    uint8_t buf[4];
    size_t got = 0;
    Address from;
    REQUIRE(b.receiveFrom(buf, sizeof(buf), got, from) == kIoOk);
    CHECK(from == a.localAddress());
    CHECK(from.family() == Address::kIPv6);
}

TEST_CASE(tcpListenerReportsBoundPortAndRefusesReuse) {
    TcpListener a;
    REQUIRE(a.listen(Address::ipv4Loopback(0)));
    CHECK(a.port() != 0);
    CHECK(a.localAddress().isLoopback());
    TcpListener b;
    CHECK(!b.listen(Address::ipv4Loopback(a.port())));  // port in use by a live listener
    CHECK(!b.isOpen());
    a.close();
    CHECK(!a.isOpen());
}

TEST_CASE(tcpSendOnClosedConnection) {
    TcpConnection c;
    const uint8_t x = 1;
    CHECK(c.send(&x, 1) == TcpConnection::kSendClosed);
    size_t got = 0;
    uint8_t buf[1];
    CHECK(c.read(buf, 1, got) == kIoClosed);
    CHECK(!c.shutdownWrite());
}

TEST_CASE(wifiVideoTosOption) {
    int tos = -1;
    CHECK(!setWifiVideoTos(kInvalidSocket));
    CHECK(!getSocketTrafficClass(kInvalidSocket, tos));

    // IPv4 UDP socket starts with default 0, then switches to kWifiVideoTos (0x80 / WMM AC_VI).
    UdpSocket udp4;
    REQUIRE(udp4.open(Address::ipv4Loopback(0)));
    CHECK(getSocketTrafficClass(udp4.handle(), tos));
    CHECK_EQ(0, tos);
    CHECK(udp4.setWifiVideoTos());
    CHECK(getSocketTrafficClass(udp4.handle(), tos));
    CHECK_EQ(kWifiVideoTos, tos);

    // IPv4 TCP connection socket sets IP_TOS = 0x80.
    TcpListener l;
    REQUIRE(l.listen(Address::ipv4Loopback(0)));
    TcpConnection c;
    REQUIRE(c.connect(Address::ipv4Loopback(l.port())));
    CHECK(waitFor(c.handle(), kPollOut));
    CHECK_EQ(kIoOk, c.finishConnect());
    CHECK(c.setWifiVideoTos());
    CHECK(getSocketTrafficClass(c.handle(), tos));
    CHECK_EQ(kWifiVideoTos, tos);

    // IPv6 UDP socket sets IPV6_TCLASS = 0x80 when IPv6 loopback is available.
    UdpSocket udp6;
    if (udp6.open(Address::ipv6Loopback(0))) {
        CHECK(getSocketTrafficClass(udp6.handle(), tos));
        CHECK_EQ(0, tos);
        CHECK(udp6.setWifiVideoTos());
        CHECK(getSocketTrafficClass(udp6.handle(), tos));
        CHECK_EQ(kWifiVideoTos, tos);
    }
}

int main() { return test_support::runAll("test_platform_net"); }
