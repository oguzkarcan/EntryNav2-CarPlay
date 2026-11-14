// Reactor + TCP: echo, partial writes / write-queue overflow, large transfer, close notifications,
// accept filter, re-entrant unregistration, timers (fake and real clock), cross-thread post/stop.
// Every wait is a runOnce() loop bounded by a generous deadline; there are no sleeps.

#include <string.h>

#include <cstdio>
#include <string>
#include <vector>

#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/tcp.hpp"
#include "carplay/platform/thread.hpp"
#include "test_support.hpp"

using namespace carplay::platform;

namespace {

const int64_t kDeadlineMs = 10000;  // generous for slow emulated ARM CI

template <typename Pred>
bool runUntil(Reactor& r, Pred pred) {
    const int64_t end = monotonicMillis() + kDeadlineMs;
    while (!pred()) {
        if (monotonicMillis() > end) {
            return false;
        }
        if (r.runOnce(20) < 0) {
            return false;
        }
    }
    return true;
}

uint8_t patternByte(size_t i) { return static_cast<uint8_t>((i * 7U) ^ (i >> 9)); }

std::vector<uint8_t> pattern(size_t offset, size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) {
        v[i] = patternByte(offset + i);
    }
    return v;
}

// A TCP endpoint driven by the reactor: collects everything it reads, flushes its queue on
// writability, and records EOF / errors.
class Peer : public IoHandler {
public:
    Peer(Reactor& r) : reactor(r), eof(false), error(false), reads(0), echo(false), read_enabled(true) {}
    virtual ~Peer() { detach(); }

    bool attach() {
        return reactor.add(conn.handle(), this, interest());
    }
    void detach() {
        if (conn.isOpen() && reactor.contains(conn.handle())) {
            reactor.remove(conn.handle());
        }
    }
    unsigned interest() const {
        unsigned i = read_enabled ? static_cast<unsigned>(kPollIn) : 0U;
        if (conn.wantsWrite() || conn.connecting()) {
            i |= kPollOut;
        }
        return i;
    }
    void refresh() {
        if (conn.isOpen() && reactor.contains(conn.handle())) {
            reactor.modify(conn.handle(), interest());
        }
    }
    TcpConnection::SendResult send(const std::vector<uint8_t>& data) {
        const TcpConnection::SendResult r = conn.send(data);
        refresh();
        return r;
    }

    virtual void onReadable() {
        ++reads;
        uint8_t buf[16384];
        for (;;) {
            size_t got = 0;
            const IoStatus st = conn.read(buf, sizeof(buf), got);
            if (st == kIoOk) {
                received.insert(received.end(), buf, buf + got);
                if (echo) {
                    const std::vector<uint8_t> chunk(buf, buf + got);
                    if (conn.send(chunk) != TcpConnection::kSendOk) {
                        error = true;
                    }
                }
                continue;
            }
            if (st == kIoClosed) {
                eof = true;
                detach();
            } else if (st == kIoError) {
                error = true;
                detach();
            }
            break;
        }
        refresh();
    }
    virtual void onWritable() {
        if (conn.flush() == kIoError) {
            error = true;
            detach();
            return;
        }
        refresh();
    }
    virtual void onError() {
        error = true;
        detach();
    }

    Reactor& reactor;
    TcpConnection conn;
    std::vector<uint8_t> received;
    bool eof;
    bool error;
    int reads;
    bool echo;
    bool read_enabled;
};

// Listener handler: accepts into a fixed pool of Peers.
class Server : public IoHandler {
public:
    explicit Server(Reactor& r) : reactor(r), accepted(0), rejected(0), echo(false), reject_all(false) {
        for (size_t i = 0; i < kPool; ++i) {
            peers[i] = new Peer(r);
        }
    }
    virtual ~Server() {
        if (listener.isOpen() && reactor.contains(listener.handle())) {
            reactor.remove(listener.handle());
        }
        for (size_t i = 0; i < kPool; ++i) {
            delete peers[i];
        }
    }
    bool start() {
        listener.setAcceptFilter(&Server::filter, this);
        return listener.listen(Address::ipv4Loopback(0)) && reactor.add(listener.handle(), this, kPollIn);
    }
    static bool filter(void* ctx, const Address& peer) {
        Server* s = static_cast<Server*>(ctx);
        s->last_filtered = peer;
        return !s->reject_all;
    }
    virtual void onReadable() {
        for (;;) {
            if (accepted >= static_cast<int>(kPool)) {
                return;
            }
            Peer* p = peers[accepted];
            const TcpListener::AcceptResult r = listener.accept(p->conn);
            if (r == TcpListener::kAccepted) {
                p->echo = echo;
                p->attach();
                ++accepted;
            } else if (r == TcpListener::kRejected) {
                ++rejected;
            } else {
                return;
            }
        }
    }
    virtual void onError() {}

    static const size_t kPool = 4;
    Reactor& reactor;
    TcpListener listener;
    Peer* peers[kPool];
    int accepted;
    int rejected;
    bool echo;
    bool reject_all;
    Address last_filtered;
};

bool connectClient(Reactor& r, Server& s, Peer& client) {
    if (!client.conn.connect(Address::ipv4Loopback(s.listener.port())) || !client.attach()) {
        return false;
    }
    const int want = s.accepted + 1;
    return runUntil(r, [&]() { return s.accepted >= want && !client.conn.connecting(); }) ||
           (client.conn.finishConnect() == kIoOk && s.accepted >= want);
}

}  // namespace

// ------------------------------------------------------------------------------------------------
// TCP through the reactor
// ------------------------------------------------------------------------------------------------

TEST_CASE(tcpEchoThroughReactor) {
    Reactor r;
    REQUIRE(r.init());
    Server s(r);
    s.echo = true;
    REQUIRE(s.start());
    Peer client(r);
    REQUIRE(connectClient(r, s, client));
    CHECK(s.last_filtered == client.conn.localAddress());
    const std::string msg = "GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n";
    REQUIRE(client.send(std::vector<uint8_t>(msg.begin(), msg.end())) == TcpConnection::kSendOk);
    REQUIRE(runUntil(r, [&]() { return client.received.size() >= msg.size(); }));
    CHECK_EQ(msg, std::string(client.received.begin(), client.received.end()));
    CHECK_EQ(3u, static_cast<unsigned>(r.socketCount()));  // listener + client + accepted peer
}

TEST_CASE(largeTransferIsByteExact) {
    Reactor r;
    REQUIRE(r.init());
    Server s(r);
    s.echo = true;
    REQUIRE(s.start());
    Peer client(r);
    REQUIRE(connectClient(r, s, client));
    const size_t total = 3 * 1024 * 1024 + 123;
    client.conn.setWriteQueueLimit(total);
    s.peers[0]->conn.setWriteQueueLimit(total);
    REQUIRE(client.send(pattern(0, total)) == TcpConnection::kSendOk);
    REQUIRE(runUntil(r, [&]() { return client.received.size() >= total || client.error; }));
    CHECK(!client.error);
    CHECK_EQ(total, client.received.size());
    CHECK(client.received == pattern(0, total));
    CHECK(s.peers[0]->received == pattern(0, total));
}

TEST_CASE(partialWritesQueueAndOverflowIsAllOrNothing) {
    Reactor r;
    REQUIRE(r.init());
    Server s(r);
    REQUIRE(s.start());
    size_t granted = 0;
    setReceiveBuffer(s.listener.handle(), 8192, granted);  // inherited by the accepted socket
    Peer client(r);
    REQUIRE(connectClient(r, s, client));
    Peer& server = *s.peers[0];
    server.read_enabled = false;  // the receiver stalls: the sender's kernel buffers must fill
    server.refresh();
    setSendBuffer(client.conn.handle(), 8192, granted);

    const size_t limit = 256 * 1024;
    client.conn.setWriteQueueLimit(limit);
    size_t offset = 0;
    const size_t chunk = 16 * 1024;
    for (int i = 0; i < 4096 && client.conn.queuedBytes() == 0; ++i) {
        REQUIRE(client.send(pattern(offset, chunk)) == TcpConnection::kSendOk);
        offset += chunk;
    }
    REQUIRE(client.conn.queuedBytes() > 0);  // a partial write happened
    std::printf("  [INFO] kernel absorbed %u bytes before queueing\n",
                static_cast<unsigned>(offset - client.conn.queuedBytes()));
    // Top the queue up to exactly the limit, then one more byte must overflow without effect.
    size_t room = limit - client.conn.queuedBytes();
    if (room > 0) {
        REQUIRE(client.send(pattern(offset, room)) == TcpConnection::kSendOk);
        offset += room;
    }
    CHECK_EQ(limit, client.conn.queuedBytes());
    CHECK(client.send(pattern(offset, 1)) == TcpConnection::kSendOverflow);
    CHECK_EQ(limit, client.conn.queuedBytes());
    CHECK(client.send(pattern(offset, limit + 1)) == TcpConnection::kSendOverflow);

    // Resume reading: everything must arrive in order, nothing from the refused sends.
    server.read_enabled = true;
    server.refresh();
    REQUIRE(runUntil(r, [&]() { return server.received.size() >= offset || server.error; }));
    CHECK_EQ(offset, server.received.size());
    CHECK(server.received == pattern(0, offset));
    CHECK_EQ(0u, static_cast<unsigned>(client.conn.queuedBytes()));
    // Bytes keep flowing after the queue drained.
    REQUIRE(client.send(pattern(offset, 10)) == TcpConnection::kSendOk);
    REQUIRE(runUntil(r, [&]() { return server.received.size() >= offset + 10; }));
    CHECK(server.received == pattern(0, offset + 10));
}

TEST_CASE(closeNotificationsBothDirections) {
    Reactor r;
    REQUIRE(r.init());
    Server s(r);
    REQUIRE(s.start());

    // Client closes -> server peer sees EOF.
    Peer c1(r);
    REQUIRE(connectClient(r, s, c1));
    c1.detach();
    c1.conn.close();
    REQUIRE(runUntil(r, [&]() { return s.peers[0]->eof || s.peers[0]->error; }));
    CHECK(s.peers[0]->eof);

    // Server closes -> client sees EOF.
    Peer c2(r);
    REQUIRE(connectClient(r, s, c2));
    s.peers[1]->detach();
    s.peers[1]->conn.close();
    REQUIRE(runUntil(r, [&]() { return c2.eof || c2.error; }));
    CHECK(c2.eof);

    // Half-close: the client's FIN arrives after its queued bytes, and the server can still answer.
    Peer c3(r);
    REQUIRE(connectClient(r, s, c3));
    REQUIRE(c3.send(pattern(0, 1000)) == TcpConnection::kSendOk);
    CHECK(c3.conn.shutdownWrite());
    const uint8_t x = 9;
    CHECK(c3.conn.send(&x, 1) == TcpConnection::kSendClosed);
    Peer& p3 = *s.peers[2];
    REQUIRE(runUntil(r, [&]() { return p3.eof || p3.error; }));
    CHECK(p3.eof);
    CHECK(p3.received == pattern(0, 1000));
    REQUIRE(p3.conn.send(pattern(5, 77)) == TcpConnection::kSendOk);
    REQUIRE(runUntil(r, [&]() { return c3.received.size() >= 77 || c3.error; }));
    CHECK(c3.received == pattern(5, 77));

    // Abort (SO_LINGER 0): the peer sees a reset or EOF, never a hang.
    Peer c4(r);
    REQUIRE(connectClient(r, s, c4));
    c4.detach();
    c4.conn.abort();
    REQUIRE(runUntil(r, [&]() { return s.peers[3]->eof || s.peers[3]->error; }));
}

TEST_CASE(acceptFilterRejectsBeforeAnyByte) {
    Reactor r;
    REQUIRE(r.init());
    Server s(r);
    s.reject_all = true;
    REQUIRE(s.start());
    Peer client(r);
    REQUIRE(client.conn.connect(Address::ipv4Loopback(s.listener.port())));
    REQUIRE(client.attach());
    const std::string secret = "POST /pair-setup";
    client.send(std::vector<uint8_t>(secret.begin(), secret.end()));
    REQUIRE(runUntil(r, [&]() { return s.rejected >= 1 && (client.eof || client.error); }));
    CHECK_EQ(0, s.accepted);
    CHECK(s.last_filtered.isLoopback());
    CHECK(s.last_filtered.family() == Address::kIPv4);
    CHECK(s.peers[0]->received.empty());
}

namespace {

// Two handlers; whichever runs first removes both registrations.
class Remover : public IoHandler {
public:
    Remover(Reactor& r) : reactor(r), other(NULL), calls(0) {}
    virtual void onReadable() {
        ++calls;
        reactor.remove(conn.handle());       // itself
        reactor.remove(other->conn.handle()); // and the other, possibly ready in the same round
    }
    virtual void onWritable() { ++calls; }
    virtual void onError() { ++calls; }
    Reactor& reactor;
    Remover* other;
    TcpConnection conn;
    int calls;
};

}  // namespace

TEST_CASE(handlerMayUnregisterItselfAndOthersInCallback) {
    Reactor r;
    REQUIRE(r.init());
    Server s(r);
    REQUIRE(s.start());
    Remover a(r);
    Remover b(r);
    a.other = &b;
    b.other = &a;
    // Connect both (accepted into the server pool), then make both readable at once.
    REQUIRE(a.conn.connect(Address::ipv4Loopback(s.listener.port())));
    REQUIRE(b.conn.connect(Address::ipv4Loopback(s.listener.port())));
    REQUIRE(runUntil(r, [&]() { return s.accepted >= 2; }));
    const uint8_t ping[4] = {1, 2, 3, 4};
    REQUIRE(s.peers[0]->conn.send(ping, 4) == TcpConnection::kSendOk);
    REQUIRE(s.peers[1]->conn.send(ping, 4) == TcpConnection::kSendOk);
    // Wait OUTSIDE the reactor until both sockets are readable, so one runOnce sees both.
    {
        PollSet ps;
        const int64_t end = monotonicMillis() + kDeadlineMs;
        bool both = false;
        while (!both && monotonicMillis() < end) {
            PollItem items[2];
            items[0].handle = a.conn.handle();
            items[1].handle = b.conn.handle();
            items[0].events = items[1].events = kPollIn;
            ps.wait(items, 2, 20);
            both = (items[0].revents & kPollIn) && (items[1].revents & kPollIn);
        }
        REQUIRE(both);
    }
    REQUIRE(r.add(a.conn.handle(), &a, kPollIn));
    REQUIRE(r.add(b.conn.handle(), &b, kPollIn));
    CHECK(r.runOnce(1000) >= 1);
    CHECK_EQ(1, a.calls + b.calls);  // the removed one was never called, although it was ready
    CHECK(!r.contains(a.conn.handle()));
    CHECK(!r.contains(b.conn.handle()));
    // A removed registration can be re-added and works again.
    REQUIRE(r.add(a.conn.handle(), &a, kPollIn));
    a.other = &a;
    const int before = a.calls;
    REQUIRE(runUntil(r, [&]() { return a.calls > before; }));
}

TEST_CASE(registrationLimitsAndValidation) {
    Reactor r;
    CHECK(r.runOnce(0) < 0);  // not initialised
    REQUIRE(r.init());
    Peer p(r);
    CHECK(!r.add(kInvalidSocket, &p, kPollIn));
    std::vector<TcpListener*> lst;
    bool hit_limit = false;
    for (size_t i = 0; i < Reactor::kMaxSockets + 1; ++i) {
        TcpListener* l = new TcpListener();
        lst.push_back(l);
        REQUIRE(l->listen(Address::ipv4Loopback(0)));
        if (!r.add(l->handle(), &p, kPollIn)) {
            hit_limit = true;
            CHECK_EQ(Reactor::kMaxSockets, i);
            break;
        }
        CHECK(!r.add(l->handle(), &p, kPollIn));  // duplicate
    }
    CHECK(hit_limit);
    CHECK_EQ(Reactor::kMaxSockets, r.socketCount());
    CHECK(r.runOnce(0) == 0);
    for (size_t i = 0; i < lst.size(); ++i) {
        r.remove(lst[i]->handle());
        delete lst[i];
    }
    CHECK_EQ(0u, static_cast<unsigned>(r.socketCount()));
    CHECK(!r.modify(kInvalidSocket, kPollIn));
}

// ------------------------------------------------------------------------------------------------
// Timers
// ------------------------------------------------------------------------------------------------

namespace {

int64_t g_fake_ns = 0;
int64_t fakeClock() { return g_fake_ns; }
const int64_t kMs = 1000000LL;

class Recorder : public TimerHandler {
public:
    Recorder() : reactor(NULL), cancel_after(0), cancel_other(0) {}
    virtual void onTimer(uint32_t id) {
        fired.push_back(id);
        times.push_back(reactor != NULL ? reactor->now() : 0);
        if (cancel_after != 0 && fired.size() == cancel_after) {
            reactor->cancelTimer(id);
        }
        if (cancel_other != 0) {
            reactor->cancelTimer(cancel_other);
            cancel_other = 0;
        }
    }
    Reactor* reactor;
    std::vector<uint32_t> fired;
    std::vector<int64_t> times;
    size_t cancel_after;
    uint32_t cancel_other;
};

}  // namespace

TEST_CASE(timersFireInDeadlineOrderAndCancel) {
    g_fake_ns = 1000 * kMs;
    Reactor r(&fakeClock);
    REQUIRE(r.init());
    Recorder rec;
    rec.reactor = &r;
    const uint32_t t30 = r.startTimer(30, 0, &rec);
    const uint32_t t10 = r.startTimer(10, 0, &rec);
    const uint32_t t20 = r.startTimer(20, 0, &rec);
    const uint32_t tc = r.startTimer(15, 0, &rec);
    const uint32_t t20b = r.startTimer(20, 0, &rec);  // same deadline as t20: start order
    REQUIRE(t30 != Reactor::kNoTimer && t10 != t30 && t20 != t10);
    CHECK(r.cancelTimer(tc));
    CHECK(!r.cancelTimer(tc));
    CHECK(!r.cancelTimer(Reactor::kNoTimer));
    CHECK_EQ(4u, static_cast<unsigned>(r.timerCount()));

    g_fake_ns += 9 * kMs;
    r.runOnce(0);
    CHECK(rec.fired.empty());
    g_fake_ns += 1 * kMs;
    r.runOnce(0);
    REQUIRE(rec.fired.size() == 1u);
    CHECK_EQ(t10, rec.fired[0]);
    g_fake_ns += 25 * kMs;  // 35 ms: 20, 20b and 30 are all due
    r.runOnce(0);
    REQUIRE(rec.fired.size() == 4u);
    CHECK_EQ(t20, rec.fired[1]);
    CHECK_EQ(t20b, rec.fired[2]);
    CHECK_EQ(t30, rec.fired[3]);
    CHECK_EQ(0u, static_cast<unsigned>(r.timerCount()));
    CHECK(!r.cancelTimer(t30));  // finished
    CHECK(r.startTimer(-1, 0, &rec) == Reactor::kNoTimer);
    CHECK(r.startTimer(1, 0, NULL) == Reactor::kNoTimer);
}

TEST_CASE(periodicTimerHasNoDriftAndCoalescesMissedTicks) {
    g_fake_ns = 5000 * kMs;
    const int64_t t0 = g_fake_ns;
    Reactor r(&fakeClock);
    REQUIRE(r.init());
    Recorder rec;
    rec.reactor = &r;
    const uint32_t id = r.startTimer(10, 10, &rec);
    REQUIRE(id != Reactor::kNoTimer);
    // Advance in uneven 3 ms steps: callbacks run late, but the grid must not shift.
    for (int step = 0; step < 34; ++step) {  // 102 ms
        g_fake_ns += 3 * kMs;
        r.runOnce(0);
    }
    CHECK_EQ(10u, static_cast<unsigned>(rec.fired.size()));
    // Jump 55 ms (5.5 periods): exactly one coalesced callback, next tick back on the 10 ms grid.
    g_fake_ns = t0 + 102 * kMs + 55 * kMs;  // 157 ms
    r.runOnce(0);
    CHECK_EQ(11u, static_cast<unsigned>(rec.fired.size()));
    g_fake_ns = t0 + 159 * kMs;
    r.runOnce(0);
    CHECK_EQ(11u, static_cast<unsigned>(rec.fired.size()));
    g_fake_ns = t0 + 160 * kMs;
    r.runOnce(0);
    CHECK_EQ(12u, static_cast<unsigned>(rec.fired.size()));
    CHECK(r.cancelTimer(id));
    g_fake_ns += 100 * kMs;
    r.runOnce(0);
    CHECK_EQ(12u, static_cast<unsigned>(rec.fired.size()));
}

TEST_CASE(timerCallbacksMayCancelThemselvesAndOthers) {
    g_fake_ns = 0;
    Reactor r(&fakeClock);
    REQUIRE(r.init());
    Recorder self;
    self.reactor = &r;
    self.cancel_after = 3;
    const uint32_t periodic = r.startTimer(1, 1, &self);
    REQUIRE(periodic != Reactor::kNoTimer);
    for (int i = 0; i < 10; ++i) {
        g_fake_ns += kMs;
        r.runOnce(0);
    }
    CHECK_EQ(3u, static_cast<unsigned>(self.fired.size()));

    Recorder first;
    Recorder victim;
    first.reactor = &r;
    victim.reactor = &r;
    r.startTimer(5, 0, &first);
    const uint32_t v = r.startTimer(5, 0, &victim);  // due in the same round, after `first`
    first.cancel_other = v;
    g_fake_ns += 5 * kMs;
    r.runOnce(0);
    CHECK_EQ(1u, static_cast<unsigned>(first.fired.size()));
    CHECK(victim.fired.empty());
}

TEST_CASE(realClockPeriodicTimerCount) {
    Reactor r;
    REQUIRE(r.init());
    Recorder rec;
    rec.reactor = &r;
    const int64_t start = monotonicNanos();
    const uint32_t id = r.startTimer(2, 2, &rec);
    REQUIRE(id != Reactor::kNoTimer);
    REQUIRE(runUntil(r, [&]() { return rec.fired.size() >= 5; }));
    // The 5th tick's deadline is start + 10 ms; it can never fire earlier.
    CHECK(rec.times[4] - start >= 10 * kMs);
    for (size_t i = 1; i < rec.times.size(); ++i) {
        CHECK(rec.times[i] >= rec.times[i - 1]);
    }
    r.cancelTimer(id);
}

// ------------------------------------------------------------------------------------------------
// Cross-thread post / stop
// ------------------------------------------------------------------------------------------------

namespace {

struct PostState {
    Reactor* reactor;
    int executed;          // touched only on the reactor thread
    int posted;            // touched only on the poster thread until join
    int retries;
    int count;
};

void incrementTask(void* ctx) { ++static_cast<PostState*>(ctx)->executed; }

void posterThread(void* arg) {
    PostState* st = static_cast<PostState*>(arg);
    for (int i = 0; i < st->count; ++i) {
        // A full queue (kMaxPostedTasks) is legitimate back-pressure: retry until accepted.
        while (!st->reactor->post(&incrementTask, st)) {
            ++st->retries;
        }
        ++st->posted;
    }
}

void stopperThread(void* arg) { static_cast<Reactor*>(arg)->stop(); }

}  // namespace

TEST_CASE(postFromAnotherThreadWakesReactor) {
    Reactor r;
    REQUIRE(r.init());
    PostState st;
    st.reactor = &r;
    st.executed = 0;
    st.posted = 0;
    st.retries = 0;
    st.count = 1000;
    Thread t;
    REQUIRE(t.start(&posterThread, &st));
    const int64_t end = monotonicMillis() + kDeadlineMs;
    while (st.executed < st.count && monotonicMillis() < end) {
        // Infinite wait: only the wake-up channel can end each iteration (no sockets, no timers).
        r.runOnce(-1);
    }
    t.join();
    CHECK_EQ(st.count, st.executed);
    CHECK_EQ(st.count, st.posted);
    CHECK(!r.post(NULL, NULL));
    // Fill the queue from this thread: the bound is enforced.
    int accepted = 0;
    while (r.post(&incrementTask, &st) && accepted < 10000) {
        ++accepted;
    }
    CHECK_EQ(static_cast<int>(Reactor::kMaxPostedTasks), accepted);
    CHECK_EQ(accepted, r.runOnce(0));
}

TEST_CASE(stopFromAnotherThreadEndsRun) {
    Reactor r;
    REQUIRE(r.init());
    Thread t;
    REQUIRE(t.start(&stopperThread, &r));
    CHECK(r.run());  // blocks in poll(-1) until stop() wakes it
    t.join();
    CHECK(!r.stopRequested());  // reset when run() returns, so run() can be called again
}

int main() { return test_support::runAll("test_platform_reactor"); }
