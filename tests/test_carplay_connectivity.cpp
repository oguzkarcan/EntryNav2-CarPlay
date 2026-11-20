// Unit tests for CarPlayConnectivity state machine, defaults, timeouts, and AuthProvider fallback.

#include "carplay/iap2_link.hpp"
#include "carplay/iap2_session.hpp"
#include "carplay/iap2_wire.hpp"
#include "carplay/pairing.hpp"
#include "carplay/platform/bt_transport.hpp"
#include "carplay/platform/carplay_connectivity.hpp"
#include "carplay/platform/carplay_daemon.hpp"
#include "carplay/platform/log.hpp"
#include "carplay/platform/media_engine.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/os_random.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/session_server.hpp"
#include "carplay/platform/spp_snapshot.hpp"
#include "carplay/platform/tap_iface.hpp"
#include "carplay/platform/usb_host.hpp"
#include "test_support.hpp"

#include <string.h>

#include <string>
#include <vector>

namespace {

namespace info = carplay::info;
namespace iap2 = carplay::iap2;
namespace pairing = carplay::pairing;
namespace plat = carplay::platform;
namespace session = carplay::session;

typedef std::vector<uint8_t> Bytes;

int64_t g_fake_now_ns = 10000000000LL;
int64_t fakeClockNs() { return g_fake_now_ns; }

class NoopSessionListener : public session::SessionListener {};
class NoopMediaHandler : public session::MediaHandler {};

class RecordingConnListener : public plat::CarPlayConnectivityListener {
public:
    struct Transition {
        plat::ConnectivityState from;
        plat::ConnectivityState to;
        plat::ActiveTransportMode mode;
    };

    virtual void onConnectivityStateChanged(plat::ConnectivityState old_state,
                                            plat::ConnectivityState new_state,
                                            plat::ActiveTransportMode mode) {
        Transition t;
        t.from = old_state;
        t.to = new_state;
        t.mode = mode;
        transitions.push_back(t);
    }

    virtual void onConnectivityError(const std::string& reason) {
        errors.push_back(reason);
    }

    virtual void onWirelessCredentialsReady(const plat::WifiCredentials& creds) {
        creds_list.push_back(creds);
    }

    std::vector<Transition> transitions;
    std::vector<std::string> errors;
    std::vector<plat::WifiCredentials> creds_list;
};

class MockBtTransport : public plat::BtTransport {
public:
    MockBtTransport()
        : listener_(NULL),
          started_(false),
          connected_(false),
          start_calls(0),
          stop_calls(0),
          disconnect_calls(0) {}

    virtual plat::BtBackendKind backendKind() const { return plat::kBtBackendAlpsSpp; }
    virtual const char* backendName() const { return "mock-bt"; }
    virtual bool start(std::string* /*error_out*/ = NULL) {
        ++start_calls;
        started_ = true;
        return true;
    }
    virtual void stop() {
        ++stop_calls;
        connected_ = false;
        started_ = false;
    }
    virtual void disconnect(const std::string& reason = "local") {
        ++disconnect_calls;
        if (connected_) {
            connected_ = false;
            if (listener_ != NULL) {
                listener_->onBtTransportDisconnected(reason);
            }
        }
    }
    virtual bool sendBytes(const uint8_t* data, size_t len) {
        if (!started_ || !connected_ || data == NULL || len == 0U) {
            return false;
        }
        tx.insert(tx.end(), data, data + len);
        return true;
    }
    virtual void setListener(plat::BtTransportListener* listener) { listener_ = listener; }
    virtual bool isStarted() const { return started_; }
    virtual bool isConnected() const { return connected_; }
    virtual const plat::BtAddr& peerAddress() const { return peer_; }

    void connectPeer(const plat::BtAddr& p) {
        peer_ = p;
        connected_ = true;
        if (listener_ != NULL) {
            listener_->onBtTransportConnected(p);
        }
    }

    void rx(const Bytes& bytes) {
        if (connected_ && listener_ != NULL && !bytes.empty()) {
            listener_->onBtTransportData(&bytes[0], bytes.size());
        }
    }

    plat::BtTransportListener* listener_;
    plat::BtAddr peer_;
    bool started_;
    bool connected_;
    int start_calls;
    int stop_calls;
    int disconnect_calls;
    Bytes tx;
};

class MockAuthProvider : public iap2::AuthProvider {
public:
    virtual bool getCertificate(Bytes& out) {
        out.assign(32U, 0xABU);
        return true;
    }
    virtual bool signChallenge(const uint8_t* c, size_t n, Bytes& sig) {
        if (c == NULL || n == 0U) return false;
        sig.assign(c, c + n);
        return true;
    }
};

class MockWlanCtrl : public plat::IWlanController {
public:
    MockWlanCtrl() : listener_(NULL), enable_calls(0), restore_calls(0) {}
    virtual void setListener(plat::WlanControllerListener* listener) { listener_ = listener; }
    virtual bool isAvailable() const { return true; }
    virtual bool isBusy() const { return false; }
    virtual bool beginEnable(unsigned /*timeout_ms*/, std::string* /*error_out*/ = NULL) {
        ++enable_calls;
        plat::WlanRequestResult r;
        r.connected = true;
        r.state_before = 0;
        r.sent = true;
        r.state_after = 1;
        r.switched_on_by_us = true;
        if (listener_ != NULL) {
            listener_->onWlanEnableResult(true, r, "");
        }
        return true;
    }
    virtual bool beginDisable(unsigned /*timeout_ms*/, std::string* /*error_out*/ = NULL) {
        return true;
    }
    virtual void cancel() {}
    virtual bool restoreSync(unsigned /*timeout_ms*/, std::string* /*error_out*/ = NULL) {
        ++restore_calls;
        return true;
    }
    plat::WlanControllerListener* listener_;
    int enable_calls;
    int restore_calls;
};

class MockApReader : public plat::IAccessPointReader {
public:
    virtual bool isNativeEnvironmentPresent(const plat::NativeWlanPaths&) const { return true; }
    virtual bool readAccessPoint(const plat::NativeWlanPaths&,
                                 plat::EvoApInfo& out,
                                 std::string& src,
                                 std::string* /*err*/ = NULL) {
        out = plat::EvoApInfo();
        out.ssid = "BMW-Mock-AP";
        out.passphrase = "SecretPass123";
        out.bssid = "02:11:22:33:44:55";
        out.channel = 36;
        out.security_type = plat::kIap2WifiSecurityWpa2;
        src = "mock-ap";
        return true;
    }
    virtual bool readFrequencyMhz(const std::string&, unsigned& mhz) {
        mhz = 5180U;
        return true;
    }
    virtual bool readConnectedStations(const std::string&, std::vector<std::string>& macs) {
        macs.clear();
        return true;
    }
};

class MockHostapdCtrl : public plat::IHostapdCtrl {
public:
    virtual void setListener(plat::HostapdCtrlListener*) {}
    virtual bool open(const std::string&, const std::string&, std::string* err) {
        if (err) *err = "unused";
        return false;
    }
    virtual void close() {}
    virtual bool isOpen() const { return false; }
    virtual bool sendPing(int) { return false; }
    virtual bool sendAttach(int) { return false; }
    virtual bool sendDetach(int) { return false; }
    virtual bool sendStatus(int) { return false; }
    virtual bool sendGetConfig(int) { return false; }
    virtual bool sendAllSta(int) { return false; }
    virtual bool sendEnable(int) { return false; }
    virtual bool sendDisable(int) { return false; }
    virtual bool sendCommand(plat::HostapdCommandKind, const std::string&, int) { return false; }
};

Bytes buildPeerFramePacket(uint8_t& dev_seq,
                           uint8_t ack,
                           uint8_t session_id,
                           uint16_t msg_id,
                           const iap2::ParameterList& params = iap2::ParameterList()) {
    iap2::Frame f;
    CHECK(iap2::Frame::build(msg_id, params, f));
    Bytes csm;
    CHECK(f.encode(csm));
    dev_seq = static_cast<uint8_t>(dev_seq + 1U);
    iap2::LinkPacket pkt;
    pkt.control = iap2::kCtrlAck;
    pkt.seq = dev_seq;
    pkt.ack = ack;
    pkt.session_id = session_id;
    pkt.payload = csm;
    Bytes raw;
    CHECK(pkt.encode(raw));
    return raw;
}

TEST_CASE(safeDefaultsAndStateNames) {
    plat::CarPlayDaemonConfig dcfg;
    CHECK(!dcfg.enable_wireless);
    CHECK(!dcfg.enable_wired);
    CHECK(!dcfg.connectivity_config.enable_wireless);
    CHECK(!dcfg.connectivity_config.enable_wired);
    CHECK(!dcfg.connectivity_config.usb_host_config.detach_usbfs_driver);
    CHECK(!dcfg.connectivity_config.usb_bridge_config.detach_usbfs_driver);

    CHECK_EQ(std::string("stopped"), std::string(plat::connectivityStateName(plat::kConnStopped)));
    CHECK_EQ(std::string("waiting"), std::string(plat::connectivityStateName(plat::kConnWaiting)));
    CHECK_EQ(std::string("wireless_iap2"),
             std::string(plat::connectivityStateName(plat::kConnWirelessIap2)));
    CHECK_EQ(std::string("wireless_ap_starting"),
             std::string(plat::connectivityStateName(plat::kConnWirelessApStarting)));
    CHECK_EQ(std::string("wireless_waiting_airplay"),
             std::string(plat::connectivityStateName(plat::kConnWirelessWaitingAirPlay)));
    CHECK_EQ(std::string("wired_configuring"),
             std::string(plat::connectivityStateName(plat::kConnWiredConfiguring)));
    CHECK_EQ(std::string("wired_iap2"),
             std::string(plat::connectivityStateName(plat::kConnWiredIap2)));
    CHECK_EQ(std::string("wired_waiting_airplay"),
             std::string(plat::connectivityStateName(plat::kConnWiredWaitingAirPlay)));
    CHECK_EQ(std::string("active_session"),
             std::string(plat::connectivityStateName(plat::kConnActiveSession)));

    CHECK_EQ(std::string("none"), std::string(plat::activeTransportModeName(plat::kActiveNone)));
    CHECK_EQ(std::string("wireless"),
             std::string(plat::activeTransportModeName(plat::kActiveWireless)));
    CHECK_EQ(std::string("wired"), std::string(plat::activeTransportModeName(plat::kActiveWired)));
}

TEST_CASE(disabledTransportsStayStoppedWithoutErrors) {
    plat::Reactor reactor(&fakeClockNs);
    REQUIRE(reactor.init());
    plat::OsRandomSource rng;
    pairing::Identity id;
    REQUIRE(pairing::generateIdentity(rng, id));
    pairing::InMemoryPairingStore store;
    info::AirPlayConfig ap_cfg = info::bmwEntryNav2_800x480(false);
    NoopSessionListener sl;
    NoopMediaHandler mh;
    plat::SessionServerConfig scfg;
    scfg.control_port = 0U;
    plat::SessionServer server(reactor, ap_cfg, id, store, rng, sl, mh, NULL, scfg);
    REQUIRE(server.start(plat::Address::ipv4Loopback(0U)));

    plat::CarPlayConnectivity conn(reactor, rng);
    RecordingConnListener listener;
    conn.setListener(&listener);

    plat::CarPlayConnectivityConfig ccfg;
    CHECK(conn.start(server, ap_cfg, id, ccfg));
    CHECK(!conn.isStarted());
    CHECK_EQ(plat::kConnStopped, conn.state());
    CHECK_EQ(plat::kActiveNone, conn.activeTransport());
    CHECK(listener.errors.empty());

    // AirPlay session notifications are safe no-ops when connectivity is stopped.
    conn.onAirPlaySessionStarted();
    conn.onAirPlaySessionEnded();
    CHECK_EQ(plat::kConnStopped, conn.state());

    conn.stop();
    server.stop();
}

TEST_CASE(unavailableAuthProviderFailsAuthCleanly) {
    g_fake_now_ns = 10000000000LL;
    plat::Reactor reactor(&fakeClockNs);
    REQUIRE(reactor.init());
    plat::OsRandomSource rng;
    pairing::Identity id;
    REQUIRE(pairing::generateIdentity(rng, id));
    pairing::InMemoryPairingStore store;
    info::AirPlayConfig ap_cfg = info::bmwEntryNav2_800x480(false);
    NoopSessionListener sl;
    NoopMediaHandler mh;
    plat::SessionServerConfig scfg;
    scfg.control_port = 0U;
    plat::SessionServer server(reactor, ap_cfg, id, store, rng, sl, mh, NULL, scfg);
    REQUIRE(server.start(plat::Address::ipv4Loopback(0U)));

    plat::CarPlayConnectivity conn(reactor, rng);
    RecordingConnListener listener;
    MockBtTransport mock_bt;
    conn.setListener(&listener);
    conn.setBtTransportForTest(&mock_bt);
    // Intentionally leave iap2 AuthProvider unset (NULL -> UnavailableAuthProvider).

    plat::CarPlayConnectivityConfig ccfg;
    ccfg.enable_wireless = true;
    ccfg.iap2_tick_interval_ms = 0;
    REQUIRE(conn.start(server, ap_cfg, id, ccfg));
    CHECK(conn.isStarted());
    CHECK_EQ(plat::kConnWaiting, conn.state());
    CHECK_EQ(1, mock_bt.start_calls);

    plat::BtAddr peer;
    REQUIRE(plat::BtAddr::parse("AA:BB:CC:DD:EE:01", peer));
    mock_bt.connectPeer(peer);
    CHECK_EQ(plat::kConnWirelessIap2, conn.state());

    // Drive iAP2 detect + SYN/ACK + RequestAuthCert (0xAA00).
    Bytes detect(iap2::kDetectSequence, iap2::kDetectSequence + iap2::kDetectSequenceBytes);
    mock_bt.rx(detect);
    CHECK(mock_bt.tx.size() > iap2::kDetectSequenceBytes);
    // Extract accessory SYN seq from tx.
    const size_t syn_off = iap2::kDetectSequenceBytes;
    iap2::LinkPacket acc_syn;
    REQUIRE(iap2::LinkPacket::decode(&mock_bt.tx[syn_off], mock_bt.tx.size() - syn_off, acc_syn));

    iap2::SynPayload dev_syn;
    dev_syn.sessions.push_back(iap2::SynSession(10U, iap2::kSessionTypeControl, 2U));
    iap2::LinkPacket syn_ack;
    syn_ack.control = static_cast<uint8_t>(iap2::kCtrlSyn | iap2::kCtrlAck);
    syn_ack.seq = 50U;
    syn_ack.ack = acc_syn.seq;
    REQUIRE(dev_syn.encode(syn_ack.payload));
    Bytes raw_syn_ack;
    REQUIRE(syn_ack.encode(raw_syn_ack));
    mock_bt.rx(raw_syn_ack);

    uint8_t dev_seq = 50U;
    const Bytes req_cert = buildPeerFramePacket(dev_seq, acc_syn.seq, 10U,
                                                iap2::msg::kRequestAuthenticationCertificate);
    mock_bt.rx(req_cert);

    // UnavailableAuthProvider returns false -> connectivity tears down cleanly back to kConnWaiting!
    CHECK_EQ(plat::kConnWaiting, conn.state());
    CHECK_EQ(plat::kActiveNone, conn.activeTransport());
    CHECK_EQ(1, mock_bt.disconnect_calls);
    CHECK_EQ(1ULL, conn.failureTeardowns());

    conn.stop();
    CHECK_EQ(plat::kConnStopped, conn.state());
    CHECK_EQ(1, mock_bt.stop_calls);
    server.stop();
}

TEST_CASE(wirelessHandoffTimeoutTearsDownApAndReturnsToWaiting) {
    g_fake_now_ns = 20000000000LL;
    plat::Reactor reactor(&fakeClockNs);
    REQUIRE(reactor.init());
    plat::OsRandomSource rng;
    pairing::Identity id;
    REQUIRE(pairing::generateIdentity(rng, id));
    pairing::InMemoryPairingStore store;
    info::AirPlayConfig ap_cfg = info::bmwEntryNav2_800x480(false);
    NoopSessionListener sl;
    NoopMediaHandler mh;
    plat::SessionServerConfig scfg;
    scfg.control_port = 0U;
    plat::SessionServer server(reactor, ap_cfg, id, store, rng, sl, mh, NULL, scfg);
    REQUIRE(server.start(plat::Address::ipv4Loopback(0U)));

    plat::CarPlayConnectivity conn(reactor, rng);
    RecordingConnListener listener;
    MockBtTransport mock_bt;
    MockAuthProvider mock_auth;
    MockWlanCtrl mock_wlan;
    MockApReader mock_ap_reader;
    MockHostapdCtrl mock_ctrl;

    conn.setListener(&listener);
    conn.setBtTransportForTest(&mock_bt);
    conn.setIap2AuthProvider(&mock_auth);
    conn.wifiAp().setWlanControllerForTest(&mock_wlan);
    conn.wifiAp().setAccessPointReaderForTest(&mock_ap_reader);
    conn.wifiAp().setHostapdCtrlForTest(&mock_ctrl);
    conn.wifiAp().setNativeCapabilityForTest(1);

    plat::CarPlayConnectivityConfig ccfg;
    ccfg.enable_wireless = true;
    ccfg.iap2_tick_interval_ms = 20;
    ccfg.handoff_timeout_ms = 200;
    ccfg.start_mdns_on_wireless = false;
    ccfg.wifi_ap_config.backend = plat::kWifiApBackendNative;
    REQUIRE(conn.start(server, ap_cfg, id, ccfg));

    plat::BtAddr peer;
    REQUIRE(plat::BtAddr::parse("AA:BB:CC:DD:EE:02", peer));
    mock_bt.connectPeer(peer);

    // Complete detect + SYN/ACK + Ident + Auth -> brings up AP -> kConnWirelessWaitingAirPlay.
    mock_bt.rx(Bytes(iap2::kDetectSequence, iap2::kDetectSequence + iap2::kDetectSequenceBytes));
    iap2::LinkPacket acc_syn;
    REQUIRE(iap2::LinkPacket::decode(&mock_bt.tx[iap2::kDetectSequenceBytes],
                                     mock_bt.tx.size() - iap2::kDetectSequenceBytes, acc_syn));
    iap2::SynPayload dev_syn;
    dev_syn.sessions.push_back(iap2::SynSession(10U, iap2::kSessionTypeControl, 2U));
    iap2::LinkPacket syn_ack;
    syn_ack.control = static_cast<uint8_t>(iap2::kCtrlSyn | iap2::kCtrlAck);
    syn_ack.seq = 10U;
    syn_ack.ack = acc_syn.seq;
    REQUIRE(dev_syn.encode(syn_ack.payload));
    Bytes raw_syn_ack;
    REQUIRE(syn_ack.encode(raw_syn_ack));
    mock_bt.rx(raw_syn_ack);

    uint8_t dev_seq = 10U;
    mock_bt.rx(buildPeerFramePacket(dev_seq, acc_syn.seq, 10U, iap2::msg::kStartIdentification));
    mock_bt.rx(buildPeerFramePacket(dev_seq, acc_syn.seq, 10U, iap2::msg::kIdentificationAccepted));
    mock_bt.rx(buildPeerFramePacket(dev_seq, acc_syn.seq, 10U, iap2::msg::kRequestAuthenticationCertificate));
    iap2::ParameterList chal;
    chal.addRaw(iap2::param::kAuthChallengeData, Bytes(16U, 0x11U));
    mock_bt.rx(buildPeerFramePacket(dev_seq, acc_syn.seq, 10U,
                                    iap2::msg::kRequestAuthenticationChallengeResponse, chal));
    mock_bt.rx(buildPeerFramePacket(dev_seq, acc_syn.seq, 10U, iap2::msg::kAuthenticationSucceeded));

    CHECK_EQ(plat::kConnWirelessWaitingAirPlay, conn.state());
    CHECK_EQ(plat::kWifiApRunning, conn.wifiAp().state());
    CHECK_EQ(1, mock_wlan.enable_calls);

    // Advance fake clock past handoff_timeout_ms (200 ms) and pump reactor timer -> AP must be restored!
    g_fake_now_ns += 250LL * 1000000LL;
    reactor.runOnce(0);

    CHECK_EQ(plat::kConnWaiting, conn.state());
    CHECK_EQ(plat::kActiveNone, conn.activeTransport());
    CHECK_EQ(plat::kWifiApStopped, conn.wifiAp().state());
    CHECK_EQ(1, mock_wlan.restore_calls);
    CHECK_EQ(1ULL, conn.failureTeardowns());

    conn.stop();
    server.stop();
}

class FakeGateSppMemory : public plat::SppMemoryBackend {
public:
    FakeGateSppMemory()
        : open_calls(0),
          is_open_(false),
          pid_(777),
          base_(0x10000000U),
          identity_("999999") {
        layout_.app = 0x20000U;
        layout_.info = 0x24000U;
        layout_.connections = 0x25000U;
        layout_.app_got = 0x1000U;
        layout_.info_got = 0x1004U;
        layout_.connections_got = 0x1008U;
        mem_.assign(0x26000U, 0U);
        writeU32(layout_.app_got, base_ + layout_.app);
        writeU32(layout_.info_got, base_ + layout_.info);
        writeU32(layout_.connections_got, base_ + layout_.connections);
        setSlot(plat::kAlpsBmwAppsSlot, plat::genericSppUuidPair(), 1U, 0U);
        setSlot(plat::kAlpsNativeCarPlaySlot, plat::genericSppUuidPair(), 1U, 0U);
        setSlot(plat::kAlpsSpareSlot, plat::genericSppUuidPair(), 1U, 0U);
    }

    virtual bool openProcess(plat::SppProcessTarget& target_out, std::string* /*error_out*/) {
        ++open_calls;
        is_open_ = true;
        target_out.pid = pid_;
        target_out.base_address = base_;
        target_out.layout = layout_;
        target_out.identity = identity_;
        return true;
    }
    virtual void closeProcess() { is_open_ = false; }
    virtual bool isOpen() const { return is_open_; }
    virtual bool readStartIdentity(int req_pid, std::string& identity_out) {
        if (req_pid != pid_) return false;
        identity_out = identity_;
        return true;
    }
    virtual bool readBytes(uint32_t address, void* out, size_t len) {
        if (!is_open_ || address < base_) return false;
        const uint32_t rel = address - base_;
        if (rel >= mem_.size() || len > mem_.size() - rel) return false;
        memcpy(out, &mem_[rel], len);
        return true;
    }
    virtual void sleepMs(uint32_t /*ms*/) {}

    void writeU32(uint32_t rel, uint32_t v) {
        mem_[rel + 0U] = static_cast<uint8_t>(v & 0xffU);
        mem_[rel + 1U] = static_cast<uint8_t>((v >> 8) & 0xffU);
        mem_[rel + 2U] = static_cast<uint8_t>((v >> 16) & 0xffU);
        mem_[rel + 3U] = static_cast<uint8_t>((v >> 24) & 0xffU);
    }

    void setSlot(unsigned slot, const Bytes& uuid_pair, uint32_t app_state, uint32_t conn_flag) {
        writeU32(layout_.app + plat::kAlpsAppStateOffset + slot * 4U, app_state);
        uint8_t* rec = &mem_[layout_.app + plat::kAlpsAppRecordOffset + slot * plat::kAlpsAppRecordStride];
        memset(rec, 0, plat::kAlpsAppRecordStride);
        uint8_t* inf = &mem_[layout_.info + slot * plat::kAlpsSppInfoStride];
        memset(inf, 0, plat::kAlpsSppInfoStride);
        uint8_t* conn = &mem_[layout_.connections + slot * plat::kAlpsSppConnectedStride];
        memset(conn, 0, plat::kAlpsSppConnectedStride);
        conn[0] = conn_flag ? 1U : 0U;

        static const size_t kLen[4] = {0U, 2U, 4U, 16U};
        static const uint8_t kTag[4] = {0U, 1U, 2U, 4U};
        size_t pos = 0U;
        for (unsigned i = 0U; i < 2U && pos < uuid_pair.size(); ++i) {
            const uint8_t kind = uuid_pair[pos++];
            if (kind < 1U || kind > 3U || kLen[kind] > uuid_pair.size() - pos) return;
            rec[32U + i] = kind;
            memcpy(rec + 16U * i, &uuid_pair[pos], kLen[kind]);
            const unsigned tag_off = (i == 0U) ? 38U : 55U;
            const unsigned dat_off = (i == 0U) ? 39U : 56U;
            inf[tag_off] = kTag[kind];
            memcpy(inf + dat_off, &uuid_pair[pos], kLen[kind]);
            pos += kLen[kind];
        }
    }

    int open_calls;
    bool is_open_;
    int pid_;
    uint32_t base_;
    plat::SppLayout layout_;
    std::string identity_;
    Bytes mem_;
};

class FakeGateBtSocketOps : public plat::BtSocketOps {
public:
    FakeGateBtSocketOps() : create_calls(0), bound_channel(5U) {}

    virtual plat::SocketHandle createRfcommSocket(int& err_out) {
        ++create_calls;
        err_out = 0;
        return plat::socketOpen(plat::Address::kIPv4, plat::kSockStream);
    }
    virtual bool bindRfcomm(plat::SocketHandle /*fd*/,
                            const plat::BtAddr& /*addr*/,
                            uint8_t channel,
                            int& err_out) {
        if (channel != 0U) {
            bound_channel = channel;
        }
        err_out = 0;
        return true;
    }
    virtual bool getRfcommChannel(plat::SocketHandle /*fd*/,
                                  uint8_t& channel_out,
                                  int& err_out) {
        channel_out = bound_channel;
        err_out = 0;
        return true;
    }
    virtual bool listenSocket(plat::SocketHandle /*fd*/, int /*backlog*/, int& err_out) {
        err_out = 0;
        return true;
    }
    virtual plat::IoStatus acceptRfcomm(plat::SocketHandle /*listen_fd*/,
                                        plat::SocketHandle& client_fd_out,
                                        plat::BtAddr& /*peer_addr_out*/,
                                        uint8_t& /*peer_channel_out*/,
                                        int& err_out) {
        client_fd_out = plat::kInvalidSocket;
        err_out = 0;
        return plat::kIoWouldBlock;
    }
    virtual plat::IoStatus recvBytes(plat::SocketHandle /*fd*/,
                                     uint8_t* /*buf*/,
                                     size_t /*cap*/,
                                     size_t& got_out,
                                     int& err_out) {
        got_out = 0;
        err_out = 0;
        return plat::kIoWouldBlock;
    }
    virtual plat::IoStatus sendBytes(plat::SocketHandle /*fd*/,
                                     const uint8_t* /*data*/,
                                     size_t /*len*/,
                                     size_t& sent_out,
                                     int& err_out) {
        sent_out = 0;
        err_out = 0;
        return plat::kIoWouldBlock;
    }
    virtual void closeSocket(plat::SocketHandle fd) {
        plat::socketClose(fd);
    }
    virtual std::string errorString(int err) const {
        return plat::socketErrorString(err);
    }

    int create_calls;
    uint8_t bound_channel;
};

class FakeGateUsbHost : public plat::UsbHostInterface {
public:
    FakeGateUsbHost() : started(false) {}
    virtual bool start(plat::Reactor&, plat::UsbHostListener*) { started = true; return true; }
    virtual void stop() { started = false; }
    virtual bool isDeviceOpen() const { return false; }
    virtual const plat::UsbDeviceInfo& currentDevice() const { return info_; }
    virtual const carplay::usb::DeviceDescriptor& deviceDescriptor() const { return dev_desc_; }
    virtual const std::vector<carplay::usb::ConfigurationDescriptor>& configurations() const {
        return configs_;
    }
    virtual bool setConfiguration(uint8_t) { return true; }
    virtual bool claimInterface(uint8_t, bool) { return true; }
    virtual bool claimInterfaceWithStatus(uint8_t, bool, bool,
                                          plat::UsbClaimStatus& status_out,
                                          std::string& driver_out) {
        status_out = plat::kUsbClaimOk;
        driver_out.clear();
        return true;
    }
    virtual bool releaseInterface(uint8_t) { return true; }
    virtual bool setInterface(uint8_t, uint8_t) { return true; }
    virtual bool resetDevice() { return true; }
    virtual bool controlTransfer(uint8_t, uint8_t, uint16_t, uint16_t, Bytes&, uint32_t, int*) { return true; }
    virtual bool readStringDescriptor(uint8_t, std::string&) { return false; }
    virtual bool queryActiveConfiguration(uint8_t& out) { out = 0U; return true; }
    virtual bool queryAppleUsbMode(Bytes&) { return false; }
    virtual bool requestCarPlayModeSwitch(const plat::AppleCarPlaySwitchRequest&) { return true; }
    virtual uint64_t submitBulkIn(uint8_t, size_t, void*) { return 0U; }
    virtual uint64_t submitBulkOut(uint8_t, const uint8_t*, size_t, bool, void*) { return 0U; }
    virtual bool discardUrb(uint64_t) { return true; }
    virtual void ignoreCurrentDevice() {}
    virtual void closeCurrentDevice() {}
    bool started;
    plat::UsbDeviceInfo info_;
    carplay::usb::DeviceDescriptor dev_desc_;
    std::vector<carplay::usb::ConfigurationDescriptor> configs_;
};

class FakeGateTapPort : public plat::TapPortInterface {
public:
    virtual bool open(plat::Reactor&, plat::TapListener*) { return true; }
    virtual void close() {}
    virtual bool isOpen() const { return false; }
    virtual const std::string& interfaceName() const { return name_; }
    virtual uint32_t ifIndex() const { return 1U; }
    virtual void getMacAddress(uint8_t mac_out[6]) const { memset(mac_out, 0, 6U); }
    virtual plat::TapWriteResult writeFrame(const uint8_t*, size_t) { return plat::kTapWriteSent; }
    virtual bool queryIpv6LinkLocal(plat::Address&) const { return false; }
    std::string name_;
};

struct CapturedLogs {
    std::vector<std::string> lines;
    static void sink(void* ctx, plat::LogLevel /*level*/, const char* tag, const char* msg) {
        CapturedLogs* self = static_cast<CapturedLogs*>(ctx);
        self->lines.push_back(std::string(tag) + ": " + msg);
    }
    bool contains(const std::string& needle) const {
        for (size_t i = 0U; i < lines.size(); ++i) {
            if (lines[i].find(needle) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
};

TEST_CASE(alpsCompatGateFallsBackToRfcommOnUnknownBuildAndFailedChecks) {
    plat::Reactor reactor(&fakeClockNs);
    REQUIRE(reactor.init());
    plat::OsRandomSource rng;
    pairing::Identity id;
    REQUIRE(pairing::generateIdentity(rng, id));
    pairing::InMemoryPairingStore store;
    info::AirPlayConfig ap_cfg = info::bmwEntryNav2_800x480(false);
    NoopSessionListener sl;
    NoopMediaHandler mh;
    plat::SessionServerConfig scfg;
    scfg.control_port = 0U;
    plat::SessionServer server(reactor, ap_cfg, id, store, rng, sl, mh, NULL, scfg);
    REQUIRE(server.start(plat::Address::ipv4Loopback(0U)));

    // 1. Unknown libevo_btappl.so build (15024/480/36): must NOT open/read offsets,
    //    must log formatted report, and must fall back to kernel RFCOMM.
    {
        CapturedLogs logs;
        plat::setLogSink(&CapturedLogs::sink, &logs);

        plat::CarPlayConnectivity conn(reactor, rng);
        FakeGateSppMemory spp_mem;
        FakeGateBtSocketOps rfcomm_ops;

        plat::BtTransportCapability cap;
        cap.alps_library_present = false;
        cap.alps_detail = "unknown ALPS structure (app=15024, spp_info=480, spp_connected=36)";
        cap.alps_dbus_ready = true;
        cap.rfcomm.af_bluetooth_supported = true;
        cap.rfcomm.has_hci_device = true;
        cap.rfcomm.hci_devices.push_back("hci0");

        conn.setBtCapabilityForTest(cap);
        conn.setSppMemoryBackendForTest(&spp_mem);
        conn.setRfcommSocketOpsForTest(&rfcomm_ops);

        plat::CarPlayConnectivityConfig ccfg;
        ccfg.enable_wireless = true;
        ccfg.iap2_tick_interval_ms = 0;
        REQUIRE(conn.start(server, ap_cfg, id, ccfg));

        CHECK(conn.hasAlpsCompatReport());
        CHECK(!conn.lastAlpsCompatReport().wireless_ready);
        CHECK_EQ(plat::kCompatFail, conn.lastAlpsCompatReport().alps.level);
        CHECK_EQ(0, spp_mem.open_calls);  // Never read offsets of an unknown build!
        CHECK(conn.wirelessTransportReady());
        CHECK_EQ(plat::kBtBackendRfcomm, conn.activeBtBackend());
        CHECK_EQ(1, rfcomm_ops.create_calls);
        CHECK(logs.contains("ALPS compat gate failed"));
        CHECK(logs.contains("15024"));

        conn.stop();
        plat::setLogSink(NULL, NULL);
    }

    // 2. Known ALPS library sizes, but D-Bus/SPP check fails (alps_dbus_ready = false)
    //    with RFCOMM available -> gate rejects ALPS SPP and falls back to RFCOMM.
    {
        plat::CarPlayConnectivity conn(reactor, rng);
        FakeGateSppMemory spp_mem;
        FakeGateBtSocketOps rfcomm_ops;

        plat::BtTransportCapability cap;
        cap.alps_library_present = true;
        cap.alps_dbus_ready = false;
        cap.alps_detail = "dbus_service_missing";
        cap.rfcomm.af_bluetooth_supported = true;
        cap.rfcomm.has_hci_device = true;
        cap.rfcomm.hci_devices.push_back("hci0");

        conn.setBtCapabilityForTest(cap);
        conn.setSppMemoryBackendForTest(&spp_mem);
        conn.setRfcommSocketOpsForTest(&rfcomm_ops);

        plat::CarPlayConnectivityConfig ccfg;
        ccfg.enable_wireless = true;
        ccfg.iap2_tick_interval_ms = 0;
        REQUIRE(conn.start(server, ap_cfg, id, ccfg));

        CHECK(conn.hasAlpsCompatReport());
        CHECK(!conn.lastAlpsCompatReport().wireless_ready);
        CHECK_EQ(plat::kCompatFail, conn.lastAlpsCompatReport().spp.level);
        CHECK(conn.wirelessTransportReady());
        CHECK_EQ(plat::kBtBackendRfcomm, conn.activeBtBackend());
        CHECK_EQ(1, rfcomm_ops.create_calls);

        conn.stop();
    }

    // 3. Slot 5 busy & slot 0 protected -> alps/uuid checks fail; with RFCOMM absent,
    //    wireless is disabled cleanly while wired USB still starts.
    {
        plat::CarPlayConnectivity conn(reactor, rng);
        FakeGateSppMemory spp_mem;
        spp_mem.setSlot(plat::kAlpsSpareSlot, plat::genericSppUuidPair(), 2U, 1U);  // busy
        FakeGateUsbHost fake_usb;
        FakeGateTapPort fake_tap;

        plat::BtTransportCapability cap;
        cap.alps_library_present = true;
        cap.alps_dbus_ready = true;
        cap.rfcomm.af_bluetooth_supported = false;
        cap.rfcomm.has_hci_device = false;

        conn.setBtCapabilityForTest(cap);
        conn.setSppMemoryBackendForTest(&spp_mem);
        conn.setUsbHostForTest(&fake_usb);
        conn.setTapPortForTest(&fake_tap);

        plat::CarPlayConnectivityConfig ccfg;
        ccfg.enable_wireless = true;
        ccfg.enable_wired = true;
        ccfg.iap2_tick_interval_ms = 0;
        REQUIRE(conn.start(server, ap_cfg, id, ccfg));

        CHECK(conn.hasAlpsCompatReport());
        CHECK(!conn.lastAlpsCompatReport().wireless_ready);
        CHECK_EQ(plat::kCompatFail, conn.lastAlpsCompatReport().alps.level);
        CHECK_EQ(plat::kCompatFail, conn.lastAlpsCompatReport().uuid.level);
        CHECK(!conn.wirelessTransportReady());
        CHECK_EQ(plat::kBtBackendNone, conn.activeBtBackend());
        CHECK(conn.btTransport() == NULL);
        CHECK(conn.wiredTransportReady());
        CHECK(fake_usb.started);

        conn.stop();
    }

    server.stop();
}

TEST_CASE(wiredOnlyModeRunsAlpsCompatAsInformational) {
    plat::Reactor reactor(&fakeClockNs);
    REQUIRE(reactor.init());
    plat::OsRandomSource rng;
    pairing::Identity id;
    REQUIRE(pairing::generateIdentity(rng, id));
    pairing::InMemoryPairingStore store;
    info::AirPlayConfig ap_cfg = info::bmwEntryNav2_800x480(false);
    NoopSessionListener sl;
    NoopMediaHandler mh;
    plat::SessionServerConfig scfg;
    scfg.control_port = 0U;
    plat::SessionServer server(reactor, ap_cfg, id, store, rng, sl, mh, NULL, scfg);
    REQUIRE(server.start(plat::Address::ipv4Loopback(0U)));

    CapturedLogs logs;
    plat::setLogSink(&CapturedLogs::sink, &logs);

    plat::CarPlayConnectivity conn(reactor, rng);
    FakeGateSppMemory spp_mem;
    FakeGateUsbHost fake_usb;
    FakeGateTapPort fake_tap;

    plat::BtTransportCapability cap;
    cap.alps_library_present = false;
    cap.alps_detail = "unknown ALPS structure (app=15024, spp_info=480, spp_connected=36)";
    cap.alps_dbus_ready = false;
    cap.rfcomm.af_bluetooth_supported = false;
    cap.rfcomm.has_hci_device = false;

    conn.setBtCapabilityForTest(cap);
    conn.setSppMemoryBackendForTest(&spp_mem);
    conn.setUsbHostForTest(&fake_usb);
    conn.setTapPortForTest(&fake_tap);

    plat::CarPlayConnectivityConfig ccfg;
    ccfg.enable_wireless = false;
    ccfg.enable_wired = true;
    ccfg.iap2_tick_interval_ms = 0;
    REQUIRE(conn.start(server, ap_cfg, id, ccfg));

    CHECK(conn.isStarted());
    CHECK(conn.wiredTransportReady());
    CHECK(!conn.wirelessTransportReady());
    CHECK_EQ(plat::kBtBackendNone, conn.activeBtBackend());
    CHECK_EQ(0, spp_mem.open_calls);
    CHECK(conn.hasAlpsCompatReport());
    CHECK(conn.lastAlpsCompatReport().usb_mode);
    CHECK_EQ(plat::kCompatInfo, conn.lastAlpsCompatReport().alps.level);
    CHECK_EQ(plat::kCompatInfo, conn.lastAlpsCompatReport().spp.level);
    CHECK(logs.contains("wired-only informational"));
    CHECK(logs.contains("usb_mode=yes"));

    conn.stop();
    plat::setLogSink(NULL, NULL);
    server.stop();
}

class StopOnErrorListener : public plat::CarPlayConnectivityListener {
public:
    explicit StopOnErrorListener(plat::CarPlayConnectivity* conn)
        : conn_(conn), stop_on_error(false), stop_on_creds(false), errors(0), creds(0) {}

    virtual void onConnectivityError(const std::string& /*reason*/) {
        ++errors;
        if (stop_on_error && conn_ != NULL) {
            conn_->stop();
        }
    }
    virtual void onWirelessCredentialsReady(const plat::WifiCredentials& /*c*/) {
        ++creds;
        if (stop_on_creds && conn_ != NULL) {
            conn_->stop();
        }
    }

    plat::CarPlayConnectivity* conn_;
    bool stop_on_error;
    bool stop_on_creds;
    int errors;
    int creds;
};

class FailingStartUsbHost : public FakeGateUsbHost {
public:
    virtual bool start(plat::Reactor&, plat::UsbHostListener*) {
        started = false;
        return false;
    }
};

class ReadyBulkUsbHost : public FakeGateUsbHost {
public:
    ReadyBulkUsbHost() : next_urb_(1U) {}
    virtual uint64_t submitBulkIn(uint8_t, size_t, void*) { return next_urb_++; }
    virtual uint64_t submitBulkOut(uint8_t, const uint8_t*, size_t, bool, void*) { return next_urb_++; }
    uint64_t next_urb_;
};

TEST_CASE(waveCReviewRegressionGuards) {
    g_fake_now_ns = 30000000000LL;
    plat::Reactor reactor(&fakeClockNs);
    REQUIRE(reactor.init());
    plat::OsRandomSource rng;
    pairing::Identity id;
    REQUIRE(pairing::generateIdentity(rng, id));
    pairing::InMemoryPairingStore store;
    info::AirPlayConfig ap_cfg = info::bmwEntryNav2_800x480(false);
    NoopSessionListener sl;
    NoopMediaHandler mh;
    plat::SessionServerConfig scfg;
    scfg.control_port = 0U;
    plat::SessionServer server(reactor, ap_cfg, id, store, rng, sl, mh, NULL, scfg);
    REQUIRE(server.start(plat::Address::ipv4Loopback(0U)));

    // 1. Rejected BT peer while direct AirPlay is active must NOT start wireless iAP2 session.
    //    Also, wired USB arrival while direct AirPlay is active must be rejected and later restart.
    {
        plat::CarPlayConnectivity conn(reactor, rng);
        MockBtTransport mock_bt;
        ReadyBulkUsbHost fake_usb;
        FakeGateTapPort fake_tap;
        conn.setBtTransportForTest(&mock_bt);
        conn.setUsbHostForTest(&fake_usb);
        conn.setTapPortForTest(&fake_tap);

        plat::CarPlayConnectivityConfig ccfg;
        ccfg.enable_wireless = true;
        ccfg.enable_wired = true;
        ccfg.iap2_tick_interval_ms = 20;
        REQUIRE(conn.start(server, ap_cfg, id, ccfg));
        CHECK_EQ(plat::kConnWaiting, conn.state());
        CHECK(fake_usb.started);

        // Simulate direct AirPlay session active (active_mode == kActiveNone, state == kConnActiveSession).
        conn.onAirPlaySessionStarted();
        CHECK_EQ(plat::kConnActiveSession, conn.state());

        plat::BtAddr peer;
        REQUIRE(plat::BtAddr::parse("AA:BB:CC:DD:EE:03", peer));
        mock_bt.connectPeer(peer);
        CHECK_EQ(1ULL, conn.rejectedConcurrentAttempts());
        CHECK_EQ(1, mock_bt.disconnect_calls);
        CHECK(mock_bt.tx.empty());
        REQUIRE(conn.wirelessIap2Session() != NULL);
        CHECK_EQ(carplay::iap2::kSessionIdle, conn.wirelessIap2Session()->state());

        // Wired USB interface arriving during direct AirPlay is also rejected.
        carplay::usb::ConfigurationDescriptor cfg;
        cfg.configuration_value = 1U;
        carplay::usb::InterfaceDescriptor iface;
        iface.number = 2U;
        iface.interface_class = carplay::usb::kAppleIap2Class;
        iface.interface_subclass = carplay::usb::kAppleIap2SubClass;
        iface.interface_protocol = carplay::usb::kAppleIap2Protocol;
        carplay::usb::EndpointDescriptor ep_in;
        ep_in.address = 0x81U;
        ep_in.attributes = carplay::usb::kEpTypeBulk;
        ep_in.max_packet_size = 512U;
        carplay::usb::EndpointDescriptor ep_out;
        ep_out.address = 0x01U;
        ep_out.attributes = carplay::usb::kEpTypeBulk;
        ep_out.max_packet_size = 512U;
        iface.endpoints.push_back(ep_in);
        iface.endpoints.push_back(ep_out);
        cfg.interfaces.push_back(iface);
        std::vector<carplay::usb::ConfigurationDescriptor> cfgs(1U, cfg);
        const_cast<plat::UsbCarPlayBridge*>(conn.usbBridge())->onUsbDeviceArrived(
            plat::UsbDeviceInfo(), carplay::usb::DeviceDescriptor(), cfgs);
        CHECK_EQ(2ULL, conn.rejectedConcurrentAttempts());
        CHECK(!conn.wiredTransportReady());
        CHECK_EQ(plat::kConnActiveSession, conn.state());

        // Ending direct AirPlay restarts wired scanning and allows subsequent BT connect.
        conn.onAirPlaySessionEnded();
        CHECK_EQ(plat::kConnWaiting, conn.state());
        CHECK(conn.wiredTransportReady());

        mock_bt.connectPeer(peer);
        CHECK_EQ(plat::kConnWirelessIap2, conn.state());
        CHECK(!mock_bt.tx.empty());
        CHECK_EQ(carplay::iap2::kSessionDetecting, conn.wirelessIap2Session()->state());

        conn.stop();
    }

    // 2. Reentrant stop() from onConnectivityError() during teardown must stay kConnStopped.
    {
        plat::CarPlayConnectivity conn(reactor, rng);
        StopOnErrorListener listener(&conn);
        listener.stop_on_error = true;
        MockBtTransport mock_bt;
        conn.setListener(&listener);
        conn.setBtTransportForTest(&mock_bt);

        plat::CarPlayConnectivityConfig ccfg;
        ccfg.enable_wireless = true;
        ccfg.iap2_tick_interval_ms = 0;
        REQUIRE(conn.start(server, ap_cfg, id, ccfg));

        plat::BtAddr peer;
        REQUIRE(plat::BtAddr::parse("AA:BB:CC:DD:EE:04", peer));
        mock_bt.connectPeer(peer);
        CHECK_EQ(plat::kConnWirelessIap2, conn.state());

        mock_bt.disconnect("unexpected drop");
        CHECK_EQ(1, listener.errors);
        CHECK(!conn.isStarted());
        CHECK_EQ(plat::kConnStopped, conn.state());
        CHECK_EQ(plat::kActiveNone, conn.activeTransport());
    }

    // 3. Reentrant stop() from onWirelessCredentialsReady() must stay kConnStopped.
    {
        plat::CarPlayConnectivity conn(reactor, rng);
        StopOnErrorListener listener(&conn);
        listener.stop_on_creds = true;
        MockBtTransport mock_bt;
        MockAuthProvider mock_auth;
        MockWlanCtrl mock_wlan;
        MockApReader mock_ap_reader;
        MockHostapdCtrl mock_ctrl;
        conn.setListener(&listener);
        conn.setBtTransportForTest(&mock_bt);
        conn.setIap2AuthProvider(&mock_auth);
        conn.wifiAp().setWlanControllerForTest(&mock_wlan);
        conn.wifiAp().setAccessPointReaderForTest(&mock_ap_reader);
        conn.wifiAp().setHostapdCtrlForTest(&mock_ctrl);
        conn.wifiAp().setNativeCapabilityForTest(1);

        plat::CarPlayConnectivityConfig ccfg;
        ccfg.enable_wireless = true;
        ccfg.iap2_tick_interval_ms = 0;
        ccfg.start_mdns_on_wireless = false;
        ccfg.wifi_ap_config.backend = plat::kWifiApBackendNative;
        REQUIRE(conn.start(server, ap_cfg, id, ccfg));

        plat::BtAddr peer;
        REQUIRE(plat::BtAddr::parse("AA:BB:CC:DD:EE:05", peer));
        mock_bt.connectPeer(peer);
        mock_bt.rx(Bytes(iap2::kDetectSequence, iap2::kDetectSequence + iap2::kDetectSequenceBytes));
        iap2::LinkPacket acc_syn;
        REQUIRE(iap2::LinkPacket::decode(&mock_bt.tx[iap2::kDetectSequenceBytes],
                                         mock_bt.tx.size() - iap2::kDetectSequenceBytes, acc_syn));
        iap2::SynPayload dev_syn;
        dev_syn.sessions.push_back(iap2::SynSession(10U, iap2::kSessionTypeControl, 2U));
        iap2::LinkPacket syn_ack;
        syn_ack.control = static_cast<uint8_t>(iap2::kCtrlSyn | iap2::kCtrlAck);
        syn_ack.seq = 12U;
        syn_ack.ack = acc_syn.seq;
        REQUIRE(dev_syn.encode(syn_ack.payload));
        Bytes raw_syn_ack;
        REQUIRE(syn_ack.encode(raw_syn_ack));
        mock_bt.rx(raw_syn_ack);

        uint8_t dev_seq = 12U;
        mock_bt.rx(buildPeerFramePacket(dev_seq, acc_syn.seq, 10U, iap2::msg::kStartIdentification));
        mock_bt.rx(buildPeerFramePacket(dev_seq, acc_syn.seq, 10U, iap2::msg::kIdentificationAccepted));
        mock_bt.rx(buildPeerFramePacket(dev_seq, acc_syn.seq, 10U, iap2::msg::kRequestAuthenticationCertificate));
        iap2::ParameterList chal;
        chal.addRaw(iap2::param::kAuthChallengeData, Bytes(16U, 0x22U));
        mock_bt.rx(buildPeerFramePacket(dev_seq, acc_syn.seq, 10U,
                                        iap2::msg::kRequestAuthenticationChallengeResponse, chal));
        mock_bt.rx(buildPeerFramePacket(dev_seq, acc_syn.seq, 10U, iap2::msg::kAuthenticationSucceeded));

        CHECK_EQ(1, listener.creds);
        CHECK(!conn.isStarted());
        CHECK_EQ(plat::kConnStopped, conn.state());
        CHECK_EQ(plat::kWifiApStopped, conn.wifiAp().state());
    }

    // 4. Failed wired start cleans up half-initialized bridge/session pointers.
    {
        plat::CarPlayConnectivity conn(reactor, rng);
        FailingStartUsbHost fail_usb;
        FakeGateTapPort fake_tap;
        conn.setUsbHostForTest(&fail_usb);
        conn.setTapPortForTest(&fake_tap);

        plat::CarPlayConnectivityConfig ccfg;
        ccfg.enable_wired = true;
        ccfg.iap2_tick_interval_ms = 0;
        REQUIRE(conn.start(server, ap_cfg, id, ccfg));
        CHECK(!conn.wiredTransportReady());
        CHECK(conn.usbBridge() == NULL);
        CHECK(conn.wiredIap2Session() == NULL);
        conn.stop();
    }

    server.stop();
}

}  // namespace

int main() {
    return test_support::runAll("test_carplay_connectivity");
}
