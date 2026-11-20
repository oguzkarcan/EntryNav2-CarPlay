// Derived from EntryNav2-Android-Auto 0.12.0 tests/test_wifi_link.cpp & platform/evo_wlan tests,
// PolyForm Noncommercial License 1.0.0
//
// Host tests for vmost_client additions, evo_wlan (sync + Reactor async), evo_ap
// (hostapd config parser, channel/freq math, iAP2 0x5703 credentials), and wifi_link
// (nl80211 attribute parsers, TCP_INFO, describeWifiLink formatting, WifiLinkLog).

#include "carplay/iap2_wire.hpp"
#include "carplay/platform/evo_ap.hpp"
#include "carplay/platform/evo_wlan.hpp"
#include "carplay/platform/file_util.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/vmost_client.hpp"
#include "carplay/platform/wifi_ap.hpp"
#include "carplay/platform/wifi_link.hpp"
#include "test_support.hpp"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <deque>
#include <string>
#include <vector>

#ifndef _WIN32
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/nl80211.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace plat = carplay::platform;
namespace iap2 = carplay::iap2;

namespace {

int64_t g_fake_clock_ns = 1000000000LL;

int64_t fakeClockNs() {
    return g_fake_clock_ns;
}

void advanceFakeClockMs(int64_t ms) {
    g_fake_clock_ns += ms * 1000000LL;
}

class TempDirGuard {
public:
    explicit TempDirGuard(const std::string& tag) {
        char buf[128];
#ifndef _WIN32
        snprintf(buf, sizeof(buf), "/tmp/carplay_test_%s_%ld", tag.c_str(),
                 static_cast<long>(getpid()));
#else
        snprintf(buf, sizeof(buf), "carplay_test_%s", tag.c_str());
#endif
        path_ = buf;
        plat::ensurePrivateDirectory(path_);
    }

    ~TempDirGuard() {
        for (size_t i = files_.size(); i > 0U; --i) {
            plat::removeFile(files_[i - 1U]);
        }
        plat::removeDirectory(path_);
    }

    const std::string& path() const { return path_; }
    void trackFile(const std::string& p) { files_.push_back(p); }

private:
    std::string path_;
    std::vector<std::string> files_;
};

// Matches the binary layout parsed by plat::parseVmostMsg() in src/platform/vmost_client.cpp.
struct FakeRawVmostMsg {
    uint16_t addr;
    uint8_t fblock;
    uint8_t inst;
    uint16_t fkt;
    uint16_t pad1;
    uint32_t op;
    uint16_t len;
    uint16_t pad2;
    const uint8_t* data;
};

#ifndef _WIN32
struct FakeVmostReply {
    uint16_t fkt;
    uint32_t op;
    std::vector<uint8_t> data;
};

struct SentVmostRecord {
    uint8_t fblock;
    uint8_t inst;
    uint16_t fkt;
    uint32_t op;
    std::vector<uint8_t> data;
};

struct FakeVmostBus {
    int client_fd;
    int server_fd;
    plat::VmostCallback callback;
    void* user;
    bool connected;
    bool registered;
    bool auto_respond;
    int initial_state;
    uint32_t select_reply_op;
    bool send_state_after_on_select;
    int connect_calls;
    int deregister_calls;
    int disconnect_calls;
    std::vector<SentVmostRecord> sent;
    std::deque<FakeVmostReply> queued;

    FakeVmostBus()
        : client_fd(-1),
          server_fd(-1),
          callback(NULL),
          user(NULL),
          connected(false),
          registered(false),
          auto_respond(true),
          initial_state(0),
          select_reply_op(plat::kMostOpResultAck),
          send_state_after_on_select(true),
          connect_calls(0),
          deregister_calls(0),
          disconnect_calls(0) {}

    bool openPair() {
        closePair();
        int fds[2] = {-1, -1};
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
            return false;
        }
        for (int i = 0; i < 2; ++i) {
            const int fl = fcntl(fds[i], F_GETFL, 0);
            if (fl < 0 || fcntl(fds[i], F_SETFL, fl | O_NONBLOCK) != 0) {
                ::close(fds[0]);
                ::close(fds[1]);
                return false;
            }
        }
        client_fd = fds[0];
        server_fd = fds[1];
        return true;
    }

    void closePair() {
        if (client_fd >= 0) {
            ::close(client_fd);
            client_fd = -1;
        }
        if (server_fd >= 0) {
            ::close(server_fd);
            server_fd = -1;
        }
    }

    ~FakeVmostBus() { closePair(); }

    void pushReply(uint16_t fkt, uint32_t op, const uint8_t* bytes, size_t len) {
        FakeVmostReply r;
        r.fkt = fkt;
        r.op = op;
        if (bytes != NULL && len > 0U) {
            r.data.assign(bytes, bytes + len);
        }
        queued.push_back(r);
        if (server_fd >= 0) {
            const uint8_t b = 1U;
            const ssize_t wr = ::send(server_fd, &b, 1U, 0);
            (void)wr;
        }
    }
};

FakeVmostBus* g_bus = NULL;

int fakeVmostConnect(plat::VmostCallback cb, void* user, int flags) {
    (void)flags;
    if (g_bus == NULL) {
        return -1;
    }
    ++g_bus->connect_calls;
    g_bus->callback = cb;
    g_bus->user = user;
    g_bus->connected = true;
    return 0;
}

int fakeVmostShadowRegister(uint8_t fblock, uint8_t inst) {
    if (g_bus == NULL || fblock != plat::kWlanFblock || inst != plat::kWlanApInstance) {
        return -1;
    }
    g_bus->registered = true;
    return 0;
}

int fakeVmostShadowDeregister(uint8_t fblock, uint8_t inst) {
    (void)fblock;
    (void)inst;
    if (g_bus == NULL) {
        return -1;
    }
    ++g_bus->deregister_calls;
    g_bus->registered = false;
    return 0;
}

int fakeVmostFdGet(int* fd) {
    if (g_bus == NULL || fd == NULL || g_bus->client_fd < 0) {
        return -1;
    }
    *fd = g_bus->client_fd;
    return 0;
}

int fakeVmostProcessMessages() {
    if (g_bus == NULL || g_bus->client_fd < 0) {
        return -1;
    }
    uint8_t buf[64];
    while (::recv(g_bus->client_fd, buf, sizeof(buf), 0) > 0) {
    }
    while (!g_bus->queued.empty()) {
        const FakeVmostReply r = g_bus->queued.front();
        g_bus->queued.pop_front();
        FakeRawVmostMsg raw;
        memset(&raw, 0, sizeof(raw));
        raw.addr = 0x100U;
        raw.fblock = plat::kWlanFblock;
        raw.inst = plat::kWlanApInstance;
        raw.fkt = r.fkt;
        raw.op = r.op;
        raw.len = static_cast<uint16_t>(r.data.size());
        raw.data = r.data.empty() ? NULL : &r.data[0];
        if (g_bus->callback != NULL) {
            g_bus->callback(&raw, g_bus->user);
        }
    }
    return 0;
}

int fakeVmostDisconnect() {
    if (g_bus == NULL) {
        return -1;
    }
    ++g_bus->disconnect_calls;
    g_bus->connected = false;
    g_bus->callback = NULL;
    g_bus->user = NULL;
    return 0;
}

int fakeVmostSend(void* msg) {
    if (g_bus == NULL || msg == NULL) {
        return -1;
    }
    const plat::VmostMsgOut* out = static_cast<const plat::VmostMsgOut*>(msg);
    SentVmostRecord rec;
    rec.fblock = out->fblock;
    rec.inst = out->inst;
    rec.fkt = out->fkt;
    rec.op = out->op;
    if (out->data != NULL && out->len > 0U) {
        rec.data.assign(out->data, out->data + out->len);
    }
    g_bus->sent.push_back(rec);

    if (g_bus->auto_respond) {
        if (out->fkt == plat::kWlanState3 && out->op == plat::kMostOpGet) {
            const uint8_t s = static_cast<uint8_t>(g_bus->initial_state);
            g_bus->pushReply(plat::kWlanState3, plat::kMostOpStatus, &s, 1U);
        } else if (out->fkt == plat::kSelectWlanState3 && out->op == plat::kMostOpStartResultAck) {
            const uint8_t target = (out->len >= 3U && out->data != NULL) ? out->data[2] : 0U;
            if (g_bus->select_reply_op == plat::kMostOpResultAck) {
                g_bus->pushReply(plat::kSelectWlanState3, plat::kMostOpProcessingAck, NULL, 0U);
            }
            g_bus->pushReply(plat::kSelectWlanState3, g_bus->select_reply_op, NULL, 0U);
            if (g_bus->select_reply_op == plat::kMostOpResultAck &&
                g_bus->send_state_after_on_select) {
                g_bus->pushReply(plat::kWlanState3, plat::kMostOpStatus, &target, 1U);
            }
        }
    }
    return 0;
}

plat::VmostApi makeFakeVmostApi() {
    plat::VmostApi api;
    api.connect = &fakeVmostConnect;
    api.shadowRegister = &fakeVmostShadowRegister;
    api.shadowDeregister = &fakeVmostShadowDeregister;
    api.fileDescriptorGet = &fakeVmostFdGet;
    api.processMessages = &fakeVmostProcessMessages;
    api.disconnect = &fakeVmostDisconnect;
    api.send = &fakeVmostSend;
    return api;
}

class RecordingWlanListener : public plat::WlanControllerListener {
public:
    RecordingWlanListener()
        : enable_calls(0), disable_calls(0), last_enable_ok(false), last_disable_ok(false),
          delete_ctrl_on_enable(NULL) {}

    virtual void onWlanEnableResult(bool ok,
                                    const plat::WlanRequestResult& result,
                                    const std::string& error) {
        ++enable_calls;
        last_enable_ok = ok;
        last_enable_result = result;
        last_error = error;
        if (delete_ctrl_on_enable != NULL) {
            plat::EvoWlanController* p = delete_ctrl_on_enable;
            delete_ctrl_on_enable = NULL;
            delete p;
        }
    }

    virtual void onWlanDisableResult(bool ok,
                                     const plat::WlanRequestResult& result,
                                     const std::string& error) {
        ++disable_calls;
        last_disable_ok = ok;
        last_disable_result = result;
        last_error = error;
    }

    int enable_calls;
    int disable_calls;
    bool last_enable_ok;
    bool last_disable_ok;
    plat::WlanRequestResult last_enable_result;
    plat::WlanRequestResult last_disable_result;
    std::string last_error;
    plat::EvoWlanController* delete_ctrl_on_enable;
};
#endif

// Helper to build nl80211 netlink attributes for pure parser tests.
void appendAttr(std::vector<uint8_t>& buf, uint16_t type, const void* data, size_t len) {
    struct RawAttrHdr {
        uint16_t nla_len;
        uint16_t nla_type;
    };
    const size_t raw_len = sizeof(RawAttrHdr) + len;
    const size_t padded_len = (raw_len + 3U) & ~static_cast<size_t>(3U);
    const size_t start = buf.size();
    buf.resize(start + padded_len, 0U);
    RawAttrHdr hdr;
    hdr.nla_len = static_cast<uint16_t>(raw_len);
    hdr.nla_type = type;
    memcpy(&buf[start], &hdr, sizeof(hdr));
    if (len > 0U && data != NULL) {
        memcpy(&buf[start + sizeof(hdr)], data, len);
    }
}

void appendAttrU32(std::vector<uint8_t>& buf, uint16_t type, uint32_t value) {
    appendAttr(buf, type, &value, sizeof(value));
}

void appendAttrU16(std::vector<uint8_t>& buf, uint16_t type, uint16_t value) {
    appendAttr(buf, type, &value, sizeof(value));
}

void appendAttrI8(std::vector<uint8_t>& buf, uint16_t type, int8_t value) {
    appendAttr(buf, type, &value, sizeof(value));
}

}  // namespace

TEST_CASE(selectWlanState3AndVmostWireFormats) {
    // Wire offset verification against parseVmostMsg().
    CHECK_EQ(static_cast<size_t>(0U), offsetof(FakeRawVmostMsg, addr));
    CHECK_EQ(static_cast<size_t>(2U), offsetof(FakeRawVmostMsg, fblock));
    CHECK_EQ(static_cast<size_t>(3U), offsetof(FakeRawVmostMsg, inst));
    CHECK_EQ(static_cast<size_t>(4U), offsetof(FakeRawVmostMsg, fkt));
    CHECK_EQ(static_cast<size_t>(8U), offsetof(FakeRawVmostMsg, op));
    CHECK_EQ(static_cast<size_t>(12U), offsetof(FakeRawVmostMsg, len));
    CHECK_EQ(static_cast<size_t>(16U), offsetof(FakeRawVmostMsg, data));

    uint8_t payload[3];
    CHECK_EQ(static_cast<size_t>(3U),
             plat::buildSelectWlanState3(payload, plat::kDefaultWlanSenderHandle, true));
    CHECK_BYTES_EQ(test_support::hexToBytes("574101"),
                   std::vector<uint8_t>(payload, payload + 3U));

    CHECK_EQ(static_cast<size_t>(3U),
             plat::buildSelectWlanState3(payload, plat::kDefaultWlanSenderHandle, false));
    CHECK_BYTES_EQ(test_support::hexToBytes("574100"),
                   std::vector<uint8_t>(payload, payload + 3U));

    CHECK_EQ(static_cast<size_t>(3U), plat::buildSelectWlanState3(payload, 0x1234U, true));
    CHECK_BYTES_EQ(test_support::hexToBytes("123401"),
                   std::vector<uint8_t>(payload, payload + 3U));

    plat::VmostMsgOut m;
    plat::buildVmostGet(m, plat::kWlanFblock, plat::kWlanApInstance, plat::kWlanState3, payload, 0U);
    CHECK_EQ(static_cast<uint16_t>(0xFFFFU), m.addr);
    CHECK_EQ(plat::kWlanFblock, m.fblock);
    CHECK_EQ(plat::kWlanApInstance, m.inst);
    CHECK_EQ(plat::kWlanState3, m.fkt);
    CHECK_EQ(plat::kMostOpGet, m.op);
    CHECK_EQ(static_cast<uint16_t>(0U), m.len);

    plat::buildVmostStartResultAck(m, plat::kWlanFblock, plat::kWlanApInstance,
                                   plat::kSelectWlanState3, payload, 3U);
    CHECK_EQ(static_cast<uint16_t>(0xFFFFU), m.addr);
    CHECK_EQ(plat::kMostOpStartResultAck, m.op);
    CHECK_EQ(static_cast<uint16_t>(3U), m.len);

    // parseVmostMsg valid & malformed checks.
    const uint8_t state_byte = 1U;
    FakeRawVmostMsg raw;
    memset(&raw, 0, sizeof(raw));
    raw.addr = 0x123U;
    raw.fblock = plat::kWlanFblock;
    raw.inst = plat::kWlanApInstance;
    raw.fkt = plat::kWlanState3;
    raw.op = plat::kMostOpStatus;
    raw.len = 1U;
    raw.data = &state_byte;
    plat::VmostMsgView view;
    REQUIRE(plat::parseVmostMsg(&raw, view));
    CHECK_EQ(static_cast<uint16_t>(0x123U), view.addr);
    CHECK_EQ(plat::kWlanFblock, view.fblock);
    CHECK_EQ(plat::kWlanApInstance, view.inst);
    CHECK_EQ(plat::kWlanState3, view.fkt);
    CHECK_EQ(plat::kMostOpStatus, view.op);
    CHECK_EQ(static_cast<uint16_t>(1U), view.len);
    CHECK_EQ(static_cast<uint8_t>(1U), view.data[0]);

    CHECK(!plat::parseVmostMsg(NULL, view));
    FakeRawVmostMsg bad = raw;
    bad.len = 4097U;
    CHECK(!plat::parseVmostMsg(&bad, view));
    bad = raw;
    bad.data = NULL;
    CHECK(!plat::parseVmostMsg(&bad, view));
    bad = raw;
    bad.op = 0x10U;
    CHECK(!plat::parseVmostMsg(&bad, view));
}

TEST_CASE(vmostClientLoaderStates) {
#ifndef _WIN32
    TempDirGuard tmp("vmost_loader");
    const std::string sock_path = plat::joinPath(tmp.path(), "vmost_sockstream");
    tmp.trackFile(sock_path);

    // 1. Missing socket -> kNoDaemon & isVmostDaemonPresent() == false.
    plat::setVmostForTest(sock_path.c_str(), "/nonexistent/libvmostclient.so.1");
    CHECK(!plat::isVmostDaemonPresent());
    plat::VmostClient client;
    CHECK_EQ(plat::VmostClient::kNoDaemon, client.load());

    // 2. Real UNIX socket present, missing library -> kNoLibrary & isVmostDaemonPresent() == true.
    const int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    REQUIRE(srv >= 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, sock_path.c_str(), sock_path.size() + 1U);
    unlink(sock_path.c_str());
    REQUIRE(bind(srv, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0);

    CHECK(plat::isVmostDaemonPresent());
    CHECK_EQ(plat::VmostClient::kNoLibrary, client.load());
    ::close(srv);

    // 3. In-memory API overrides: incomplete -> kNoSymbols, complete -> kLoaded.
    plat::VmostApi incomplete;
    client.setApiOverride(&incomplete);
    CHECK_EQ(plat::VmostClient::kNoSymbols, client.load());

    const plat::VmostApi complete = makeFakeVmostApi();
    client.setApiOverride(&complete);
    CHECK_EQ(plat::VmostClient::kLoaded, client.load());
    client.setApiOverride(NULL);
    plat::setVmostForTest(NULL, NULL);
#endif
}

TEST_CASE(evoWlanSyncRequestReleaseRestore) {
#ifndef _WIN32
    const plat::VmostApi api = makeFakeVmostApi();

    // 1. Car AP initially OFF (0): sends 0xC10 Get, then 0xC11 StartResultAck(57 41 01).
    {
        FakeVmostBus bus;
        REQUIRE(bus.openPair());
        bus.initial_state = 0;
        g_bus = &bus;

        plat::WlanRequestResult res;
        REQUIRE(plat::requestWlanAccessPoint(300U, &res, &api));
        CHECK(res.connected);
        CHECK_EQ(0, res.state_before);
        CHECK(res.sent);
        CHECK(res.switched_on_by_us);
        CHECK_EQ(static_cast<int>(plat::kMostOpResultAck), res.reply_op);
        CHECK_EQ(1, res.state_after);
        CHECK(!bus.connected);
        CHECK(!bus.registered);
        CHECK_EQ(1, bus.deregister_calls);
        CHECK_EQ(1, bus.disconnect_calls);

        REQUIRE(bus.sent.size() == 2U);
        CHECK_EQ(plat::kWlanState3, bus.sent[0].fkt);
        CHECK_EQ(plat::kMostOpGet, bus.sent[0].op);
        CHECK_EQ(plat::kSelectWlanState3, bus.sent[1].fkt);
        CHECK_EQ(plat::kMostOpStartResultAck, bus.sent[1].op);
        CHECK_BYTES_EQ(test_support::hexToBytes("574101"), bus.sent[1].data);
        g_bus = NULL;
    }

    // 2. Car AP already ON (1): reads 0xC10 Get only, NEVER sends 0xC11.
    {
        FakeVmostBus bus;
        REQUIRE(bus.openPair());
        bus.initial_state = 1;
        g_bus = &bus;

        plat::WlanRequestResult res;
        REQUIRE(plat::requestWlanAccessPoint(300U, &res, &api));
        CHECK(res.connected);
        CHECK_EQ(1, res.state_before);
        CHECK(!res.sent);
        CHECK(!res.switched_on_by_us);
        REQUIRE(bus.sent.size() == 1U);
        CHECK_EQ(plat::kWlanState3, bus.sent[0].fkt);
        g_bus = NULL;
    }

    // 3. Rejection via kMostOpError (0x9) and kMostOpErrorAck (0xF).
    for (int i = 0; i < 2; ++i) {
        FakeVmostBus bus;
        REQUIRE(bus.openPair());
        bus.initial_state = 0;
        bus.select_reply_op = (i == 0) ? plat::kMostOpError : plat::kMostOpErrorAck;
        g_bus = &bus;

        plat::WlanRequestResult res;
        CHECK(!plat::requestWlanAccessPoint(300U, &res, &api));
        CHECK(res.sent);
        CHECK_EQ(static_cast<int>(bus.select_reply_op), res.reply_op);
        g_bus = NULL;
    }

    // 4. restoreWlanAccessPoint: no-op when switched_on_by_us == false; sends OFF when true.
    {
        FakeVmostBus bus;
        REQUIRE(bus.openPair());
        g_bus = &bus;

        plat::WlanRequestResult noop_res;
        REQUIRE(plat::restoreWlanAccessPoint(false, 200U, &noop_res, &api));
        CHECK_EQ(0, bus.connect_calls);
        CHECK(!noop_res.sent);

        plat::WlanRequestResult off_res;
        REQUIRE(plat::restoreWlanAccessPoint(true, 200U, &off_res, &api));
        CHECK_EQ(1, bus.connect_calls);
        CHECK(off_res.sent);
        REQUIRE(bus.sent.size() == 1U);
        CHECK_EQ(plat::kSelectWlanState3, bus.sent[0].fkt);
        CHECK_BYTES_EQ(test_support::hexToBytes("574100"), bus.sent[0].data);
        g_bus = NULL;
    }
#endif
}

TEST_CASE(evoWlanControllerReactorAsyncAndSelfDestruct) {
#ifndef _WIN32
    g_fake_clock_ns = 1000000000LL;
    plat::Reactor reactor(&fakeClockNs);
    REQUIRE(reactor.init());
    const plat::VmostApi api = makeFakeVmostApi();

    // 1. Off -> On async flow + Disable async flow.
    {
        FakeVmostBus bus;
        REQUIRE(bus.openPair());
        bus.initial_state = 0;
        g_bus = &bus;

        RecordingWlanListener listener;
        plat::EvoWlanController ctrl(reactor);
        ctrl.setApiOverride(&api);
        ctrl.setListener(&listener);
        CHECK(ctrl.isAvailable());

        std::string err;
        REQUIRE(ctrl.beginEnable(1000U, &err));
        CHECK(ctrl.isBusy());
        // First runOnce handles WLANState3.Status(0) -> sends SelectWLANState3(1);
        // second handles ResultAck + WLANState3.Status(1) -> completes!
        for (int i = 0; i < 6 && listener.enable_calls == 0; ++i) {
            reactor.runOnce(20);
        }
        CHECK(!ctrl.isBusy());
        REQUIRE(listener.enable_calls == 1);
        CHECK(listener.last_enable_ok);
        CHECK_EQ(0, listener.last_enable_result.state_before);
        CHECK(listener.last_enable_result.switched_on_by_us);
        CHECK_EQ(1, listener.last_enable_result.state_after);

        // beginDisable -> sends 57 41 00 -> completes via reactor.
        REQUIRE(ctrl.beginDisable(500U, &err));
        for (int i = 0; i < 6 && listener.disable_calls == 0; ++i) {
            reactor.runOnce(20);
        }
        REQUIRE(listener.disable_calls == 1);
        CHECK(listener.last_disable_ok);
        CHECK(bus.sent.size() >= 3U);
        CHECK_BYTES_EQ(test_support::hexToBytes("574100"), bus.sent.back().data);
        g_bus = NULL;
    }

    // 2. Silent wland timeout path + cancel().
    {
        FakeVmostBus bus;
        REQUIRE(bus.openPair());
        bus.auto_respond = false;
        g_bus = &bus;

        RecordingWlanListener listener;
        plat::EvoWlanController ctrl(reactor);
        ctrl.setApiOverride(&api);
        ctrl.setListener(&listener);

        std::string err;
        REQUIRE(ctrl.beginEnable(200U, &err));
        CHECK_EQ(static_cast<size_t>(1U), bus.sent.size());  // Get sent
        advanceFakeClockMs(200);
        reactor.runOnce(0);  // GetState timeout -> sends SelectWLANState3(1)
        REQUIRE(bus.sent.size() == 2U);
        CHECK_BYTES_EQ(test_support::hexToBytes("574101"), bus.sent[1].data);
        advanceFakeClockMs(100);
        reactor.runOnce(0);  // WaitAck timeout -> succeeds with switched_on_by_us = true
        REQUIRE(listener.enable_calls == 1);
        CHECK(listener.last_enable_ok);
        CHECK(listener.last_enable_result.switched_on_by_us);

        // cancel() suppresses callback.
        REQUIRE(ctrl.beginDisable(500U, &err));
        CHECK(ctrl.isBusy());
        ctrl.cancel();
        CHECK(!ctrl.isBusy());
        advanceFakeClockMs(1000);
        reactor.runOnce(0);
        CHECK_EQ(0, listener.disable_calls);
        g_bus = NULL;
    }

    // 3. Self-destruction of EvoWlanController inside onWlanEnableResult callback (AliveGuard check).
    {
        FakeVmostBus bus;
        REQUIRE(bus.openPair());
        bus.initial_state = 1;  // completes in one hop on StateBefore == 1
        g_bus = &bus;

        RecordingWlanListener listener;
        plat::EvoWlanController* heap_ctrl = new plat::EvoWlanController(reactor);
        heap_ctrl->setApiOverride(&api);
        heap_ctrl->setListener(&listener);
        listener.delete_ctrl_on_enable = heap_ctrl;

        std::string err;
        REQUIRE(heap_ctrl->beginEnable(500U, &err));
        for (int i = 0; i < 4 && listener.enable_calls == 0; ++i) {
            reactor.runOnce(20);
        }
        CHECK_EQ(1, listener.enable_calls);
        CHECK(listener.delete_ctrl_on_enable == NULL);
        g_bus = NULL;
    }
#endif
}

TEST_CASE(evoApConfigParsingAndCredentials) {
    // Channel <-> frequency helpers (2.4 GHz & 5 GHz UNII).
    CHECK_EQ(1, plat::frequencyMhzToChannel(2412));
    CHECK_EQ(6, plat::frequencyMhzToChannel(2437));
    CHECK_EQ(13, plat::frequencyMhzToChannel(2472));
    CHECK_EQ(14, plat::frequencyMhzToChannel(2484));
    CHECK_EQ(36, plat::frequencyMhzToChannel(5180));
    CHECK_EQ(44, plat::frequencyMhzToChannel(5220));
    CHECK_EQ(149, plat::frequencyMhzToChannel(5745));
    CHECK_EQ(165, plat::frequencyMhzToChannel(5825));
    CHECK_EQ(0, plat::frequencyMhzToChannel(2400));
    CHECK_EQ(0, plat::frequencyMhzToChannel(5175));
    CHECK_EQ(2437, plat::channelToFrequencyMhz(6U));
    CHECK_EQ(5180, plat::channelToFrequencyMhz(36U));
    CHECK_EQ(0, plat::channelToFrequencyMhz(37U));

    // Valid hostapd_cli get_config output (with comments, CRLF, bssid, freq).
    const std::string get_config_txt =
        "# BMW native AP config\r\n"
        "; comment line\r\n"
        "bssid=02:AA:BB:CC:DD:EE\r\n"
        "ssid=BMW-DIRECT-12345\r\n"
        "passphrase=SecretPass99\r\n"
        "wpa=2\r\n"
        "key_mgmt=WPA-PSK\r\n"
        "freq=5180\r\n";
    plat::EvoApInfo ap;
    REQUIRE(plat::parseHostapdConfig(get_config_txt, ap));
    CHECK_EQ(std::string("02:aa:bb:cc:dd:ee"), ap.bssid);
    CHECK_EQ(std::string("BMW-DIRECT-12345"), ap.ssid);
    CHECK_EQ(std::string("SecretPass99"), ap.passphrase);
    CHECK_EQ(36, ap.channel);
    CHECK_EQ(5180, ap.freq_mhz);
    CHECK_EQ(plat::kIap2WifiSecurityWpa2, ap.security_type);

    plat::WifiCredentials creds;
    std::string err;
    REQUIRE(ap.toWifiCredentials(creds, 0U, &err));
    CHECK_EQ(std::string("BMW-DIRECT-12345"), creds.ssid);
    CHECK_EQ(std::string("SecretPass99"), creds.passphrase);
    CHECK_EQ(static_cast<uint8_t>(36U), creds.channel);
    CHECK(creds.has_bssid);
    CHECK_BYTES_EQ(test_support::hexToBytes("02aabbccddee"), creds.bssidVector());

    // Encodes valid iAP2 0x5703 AccessoryWiFiConfigurationInformation.
    iap2::Frame frame;
    REQUIRE(plat::buildAccessoryWiFiConfigFrame(creds, frame, &err));
    CHECK_EQ(iap2::msg::kAccessoryWiFiConfiguration, frame.message_id);
    iap2::ParameterList params;
    REQUIRE(iap2::ParameterList::decode(frame.payload, params, &err));
    std::string dec_ssid;
    std::string dec_psk;
    uint8_t dec_sec = 0U;
    uint8_t dec_ch = 0U;
    CHECK(params.readString(1U, dec_ssid));
    CHECK(params.readString(2U, dec_psk));
    CHECK(params.readU8(3U, dec_sec));
    CHECK(params.readU8(4U, dec_ch));
    CHECK_EQ(creds.ssid, dec_ssid);
    CHECK_EQ(creds.passphrase, dec_psk);
    CHECK_EQ(plat::kIap2WifiSecurityWpa2, dec_sec);
    CHECK_EQ(static_cast<uint8_t>(36U), dec_ch);

    // /tmp/wland/ap.conf style without channel/freq requires fallback_channel.
    const std::string ap_conf_no_chan =
        "ssid=BMW-EVO\n"
        "wpa_passphrase=Wpa2Pass123\n"
        "wpa=3\n"
        "wpa_key_mgmt=WPA-PSK\n";
    REQUIRE(plat::parseHostapdConfig(ap_conf_no_chan, ap));
    CHECK(!ap.toWifiCredentials(creds, 0U, &err));
    REQUIRE(ap.toWifiCredentials(creds, 36U, &err));
    CHECK_EQ(static_cast<uint8_t>(36U), creds.channel);

    // Rejected invalid configs (64-hex PSK, short passphrase, bad wpa, bad key_mgmt, NUL byte).
    CHECK(!plat::parseHostapdConfig(
        "ssid=X\npsk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n", ap));
    CHECK(!plat::parseHostapdConfig("ssid=X\nwpa_passphrase=short\n", ap));
    CHECK(!plat::parseHostapdConfig("ssid=X\nwpa_passphrase=ValidPass123\nwpa=1\n", ap));
    CHECK(!plat::parseHostapdConfig("ssid=X\nwpa_passphrase=ValidPass123\nkey_mgmt=NONE\n", ap));
    CHECK(!plat::parseHostapdConfig(std::string("ssid=X\0wpa_passphrase=ValidPass123", 33U), ap));

    // EvoAccessPointReader environment presence check using TempDirGuard.
    TempDirGuard tmp("evo_ap");
    plat::NativeWlanPaths paths;
    paths.interface_name = "wlan_fake";
    paths.hostapd_ctrl_dir = plat::joinPath(tmp.path(), "ctrl");
    paths.ap_conf_path = plat::joinPath(tmp.path(), "ap.conf");
    tmp.trackFile(paths.ap_conf_path);
    plat::EvoAccessPointReader reader;
    CHECK(!reader.isNativeEnvironmentPresent(paths));
    REQUIRE(plat::writeFileAtomic(paths.ap_conf_path,
                                  reinterpret_cast<const uint8_t*>("ssid=test\n"), 10U));
    CHECK(reader.isNativeEnvironmentPresent(paths));
}

TEST_CASE(wifiLinkParsersFormattingAndLog) {
    // 1. parseWifiStation with full nl80211 attributes + bounds checks.
    std::vector<uint8_t> sta_info;
    appendAttrI8(sta_info, NL80211_STA_INFO_SIGNAL, -52);
    appendAttrI8(sta_info, NL80211_STA_INFO_SIGNAL_AVG, -55);
    std::vector<uint8_t> tx_rate_attr;
    appendAttrU16(tx_rate_attr, NL80211_RATE_INFO_BITRATE, 8667U);
    appendAttr(sta_info, NL80211_STA_INFO_TX_BITRATE, &tx_rate_attr[0], tx_rate_attr.size());
    std::vector<uint8_t> rx_rate_attr;
    appendAttrU16(rx_rate_attr, NL80211_RATE_INFO_BITRATE, 4333U);
    appendAttr(sta_info, NL80211_STA_INFO_RX_BITRATE, &rx_rate_attr[0], rx_rate_attr.size());
    appendAttrU32(sta_info, NL80211_STA_INFO_TX_PACKETS, 1000U);
    appendAttrU32(sta_info, NL80211_STA_INFO_TX_RETRIES, 12U);
    appendAttrU32(sta_info, NL80211_STA_INFO_TX_FAILED, 1U);
    appendAttrU32(sta_info, NL80211_STA_INFO_CONNECTED_TIME, 42U);

    const uint8_t mac[6] = {0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU};
    std::vector<uint8_t> attrs;
    appendAttr(attrs, NL80211_ATTR_MAC, mac, 6U);
    appendAttr(attrs, NL80211_ATTR_STA_INFO, &sta_info[0], sta_info.size());

    plat::WifiStation st;
    REQUIRE(plat::parseWifiStation(&attrs[0], attrs.size(), st));
    CHECK_BYTES_EQ(std::vector<uint8_t>(mac, mac + 6U),
                   std::vector<uint8_t>(st.mac, st.mac + 6U));
    CHECK_EQ(static_cast<int64_t>(-52), st.signal_dbm);
    CHECK_EQ(static_cast<int64_t>(-55), st.signal_avg_dbm);
    // wlcore firmware always reports 1.0 Mbit/s TX bitrate, so tx_rate is omitted (#80).
    CHECK_EQ(plat::kNoFigure, st.tx_rate);
    CHECK_EQ(static_cast<int64_t>(4333), st.rx_rate);
    CHECK_EQ(static_cast<int64_t>(1000), st.tx_frames);
    CHECK_EQ(static_cast<int64_t>(12), st.tx_retries);
    CHECK_EQ(static_cast<int64_t>(1), st.tx_failed);
    CHECK_EQ(static_cast<int64_t>(42), st.connected_s);

    // WL18xx leaves NL80211_STA_INFO_SIGNAL as 0 dBm when the last frame was unmeasured (#80).
    {
        std::vector<uint8_t> unmeasured_sta;
        appendAttrI8(unmeasured_sta, NL80211_STA_INFO_SIGNAL, 0);
        appendAttrI8(unmeasured_sta, NL80211_STA_INFO_SIGNAL_AVG, -58);
        std::vector<uint8_t> unmeasured_attrs;
        appendAttr(unmeasured_attrs, NL80211_ATTR_MAC, mac, 6U);
        appendAttr(unmeasured_attrs, NL80211_ATTR_STA_INFO,
                   &unmeasured_sta[0], unmeasured_sta.size());
        plat::WifiStation st0;
        REQUIRE(plat::parseWifiStation(&unmeasured_attrs[0], unmeasured_attrs.size(), st0));
        CHECK_EQ(plat::kNoFigure, st0.signal_dbm);
        CHECK_EQ(static_cast<int64_t>(-58), st0.signal_avg_dbm);

        plat::WifiSample avg_only;
        avg_only.has_station = true;
        avg_only.station = st0;
        CHECK_EQ(std::string("average signal -58 dBm"), plat::describeWifiLink(avg_only, NULL));
    }

    // Missing MAC fails; truncated / malformed nla_len fails cleanly.
    CHECK(!plat::parseWifiStation(&sta_info[0], sta_info.size(), st));
    const uint8_t bad_len[4] = {0x02U, 0x00U, 0x06U, 0x00U};  // nla_len = 2 (<4)
    CHECK(!plat::parseWifiStation(bad_len, sizeof(bad_len), st));

    // parseWifiFrequency.
    std::vector<uint8_t> iface_attrs;
    appendAttrU32(iface_attrs, NL80211_ATTR_WIPHY_FREQ, 5180U);
    unsigned mhz = 0U;
    REQUIRE(plat::parseWifiFrequency(&iface_attrs[0], iface_attrs.size(), mhz));
    CHECK_EQ(5180U, mhz);
    CHECK(!plat::parseWifiFrequency(bad_len, sizeof(bad_len), mhz));

    // 2. describeWifiLink exact outputs.
    plat::WifiSample empty_s;
    CHECK_EQ(std::string(""), plat::describeWifiLink(empty_s, NULL));

    plat::WifiSample s1;
    s1.at_ms = 1000U;
    s1.radio = true;
    s1.mhz = 5180U;
    s1.stations = 1U;
    s1.has_station = true;
    memcpy(s1.station.mac, mac, 6U);
    s1.station.signal_dbm = -52;
    s1.station.signal_avg_dbm = -55;
    s1.station.tx_rate = 8667;
    s1.station.rx_rate = 4333;
    s1.station.tx_frames = 100;
    s1.station.tx_retries = 1;
    s1.station.connected_s = 15;
    s1.has_tcp = true;
    s1.tcp.round_trip_us = 2300U;
    s1.tcp.resent = 0U;

    const std::string line1 = plat::describeWifiLink(s1, NULL);
    CHECK_EQ(std::string("5180 MHz; signal -52 dBm (average -55); "
                         "from the phone 433.3 Mbit/s; since it joined: 100 frames sent, "
                         "1 retried; on the Wi-Fi for 15 s; TCP round trip 2.3 ms, "
                         "0 segment(s) sent again since it opened"),
             line1);

    // BMW Apps slot 0 status formatting (#111).
    {
        plat::WifiSample apps_conn;
        apps_conn.apps.read = true;
        apps_conn.apps.connected = true;
        apps_conn.apps.state = 3U;
        apps_conn.apps.transport = 4U;
        CHECK_EQ(std::string("BMW Apps Bluetooth link connected"),
                 plat::describeWifiLink(apps_conn, NULL));

        plat::WifiSample apps_idle;
        apps_idle.apps.read = true;
        apps_idle.apps.connected = false;
        apps_idle.apps.state = 1U;
        apps_idle.apps.transport = 0U;
        CHECK_EQ(std::string("BMW Apps Bluetooth link idle"),
                 plat::describeWifiLink(apps_idle, NULL));

        plat::WifiSample apps_other;
        apps_other.apps.read = true;
        apps_other.apps.connected = false;
        apps_other.apps.state = 2U;
        apps_other.apps.transport = 3U;
        CHECK_EQ(std::string("BMW Apps Bluetooth slot state 2, link state 3"),
                 plat::describeWifiLink(apps_other, NULL));
    }

    plat::WifiSample s2 = s1;
    s2.at_ms = 11000U;
    s2.station.tx_frames = 150;
    s2.station.tx_retries = 3;
    s2.station.connected_s = 25;
    s2.tcp.resent = 2U;
    const std::string line2 = plat::describeWifiLink(s2, &s1);
    CHECK(line2.find("in 10 s: 50 frames sent, 2 retried") != std::string::npos);
    CHECK(line2.find("2 segment(s) sent again") != std::string::npos);
    CHECK(line2.find("since it opened") == std::string::npos);

    // Reconnect (counter reset) prints "the phone joined the Wi-Fi again".
    plat::WifiSample s3 = s1;
    s3.at_ms = 21000U;
    s3.station.tx_frames = 10;
    s3.station.tx_retries = 0;
    s3.station.connected_s = 2;
    const std::string line3 = plat::describeWifiLink(s3, &s2);
    CHECK(line3.find("the phone joined the Wi-Fi again") != std::string::npos);

    // Phone not found among stations.
    plat::WifiSample not_found;
    not_found.radio = true;
    not_found.mhz = 2437U;
    not_found.stations = 2U;
    not_found.has_station = false;
    CHECK_EQ(std::string("2437 MHz; phone not found among the 2 station(s) of the access point"),
             plat::describeWifiLink(not_found, NULL));

    // 3. readTcpLink & WifiLinkLog on a real loopback TCP socket (and AF_UNIX rejection).
#ifndef _WIN32
    plat::TcpLink tcp_info;
    CHECK(!plat::readTcpLink(-1, tcp_info));
    int unix_pair[2] = {-1, -1};
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, unix_pair) == 0);
    CHECK(!plat::readTcpLink(unix_pair[0], tcp_info));
    ::close(unix_pair[0]);
    ::close(unix_pair[1]);

    const int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(listen_fd >= 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    REQUIRE(bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    REQUIRE(listen(listen_fd, 1) == 0);
    socklen_t addr_len = sizeof(addr);
    REQUIRE(getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &addr_len) == 0);

    const int cli_fd = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(cli_fd >= 0);
    REQUIRE(connect(cli_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    const int acc_fd = accept(listen_fd, NULL, NULL);
    REQUIRE(acc_fd >= 0);

    CHECK(plat::readTcpLink(cli_fd, tcp_info));

    struct ProbeState {
        int calls;
    } probe_state = {0};
    struct ProbeFn {
        static bool run(void* user, plat::AppsSlot& out) {
            ProbeState* st = static_cast<ProbeState*>(user);
            st->calls += 1;
            out.read = true;
            out.connected = false;
            out.state = 1U;
            out.transport = 0U;
            return true;
        }
    };

    plat::WifiLinkLog log;
    log.enable("lo");
    log.setAppsProbe(&ProbeFn::run, &probe_state);
    log.connected(cli_fd);
    ::close(cli_fd);  // WifiLinkLog holds its own F_DUPFD_CLOEXEC fd.
    log.turn(0xfffffff0U, true);
    log.turn(0xfffffff5U, true);
    log.turn(0x00002710U, true);
    CHECK_EQ(2, probe_state.calls);
    log.turn(0x00002720U, false);  // stops & closes internal dup fd after seen_active_

    ::close(acc_fd);
    ::close(listen_fd);
#endif
}

int main() {
    return test_support::runAll("test_evo_wlan");
}
