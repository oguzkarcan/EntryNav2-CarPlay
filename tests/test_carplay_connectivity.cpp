// Unit tests for CarPlayConnectivity state machine, defaults, timeouts, and AuthProvider fallback.

#include "carplay/iap2_link.hpp"
#include "carplay/iap2_session.hpp"
#include "carplay/iap2_wire.hpp"
#include "carplay/pairing.hpp"
#include "carplay/platform/bt_transport.hpp"
#include "carplay/platform/carplay_connectivity.hpp"
#include "carplay/platform/carplay_daemon.hpp"
#include "carplay/platform/media_engine.hpp"
#include "carplay/platform/os_random.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/session_server.hpp"
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

}  // namespace

int main() {
    return test_support::runAll("test_carplay_connectivity");
}
