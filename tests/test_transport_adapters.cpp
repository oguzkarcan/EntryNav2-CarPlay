// Cross-package adapter tests verifying:
//   * B1 iAP2 Session <-> B2 BtTransport (`BtSessionAdapter`)
//   * B1 iAP2 Session <-> B4 UsbCarPlayBridge (`UsbBridgeIap2ByteSink` & `UsbBridgeSessionAdapter`)
//   * B3 native AP (`EvoApInfo` / `WifiCredentials` / `WifiAp`) <-> B1 0x5703 WiFiConfiguration

#include "carplay/iap2_session.hpp"
#include "carplay/iap2_wire.hpp"
#include "carplay/pairing.hpp"
#include "carplay/platform/bt_transport.hpp"
#include "carplay/platform/evo_ap.hpp"
#include "carplay/platform/evo_wlan.hpp"
#include "carplay/platform/hostapd_ctrl.hpp"
#include "carplay/platform/os_random.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/tap_iface.hpp"
#include "carplay/platform/transport_adapters.hpp"
#include "carplay/platform/usb_carplay_bridge.hpp"
#include "carplay/platform/usb_host.hpp"
#include "carplay/platform/wifi_ap.hpp"
#include "test_support.hpp"

#include <cstring>
#include <deque>
#include <string>
#include <vector>

namespace iap2 = carplay::iap2;
namespace plat = carplay::platform;
namespace usb = carplay::usb;

typedef std::vector<uint8_t> Bytes;

namespace {

int64_t g_fake_clock_ns = 1000000000LL;

int64_t fakeClockNs() {
    return g_fake_clock_ns;
}

void pushU16Le(Bytes& v, uint16_t val) {
    v.push_back(static_cast<uint8_t>(val & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 8) & 0xffU));
}

void pushU32Le(Bytes& v, uint32_t val) {
    v.push_back(static_cast<uint8_t>(val & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 8) & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 16) & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 24) & 0xffU));
}

Bytes buildSyntheticCarPlayBlob() {
    Bytes body;
    // Interface 0: Apple iAP2 (0xff/0xf0/0x00), Bulk IN 0x81, Bulk OUT 0x01
    body.push_back(9U);
    body.push_back(usb::kDescTypeInterface);
    body.push_back(0U);
    body.push_back(0U);
    body.push_back(2U);
    body.push_back(usb::kAppleIap2Class);
    body.push_back(usb::kAppleIap2SubClass);
    body.push_back(usb::kAppleIap2Protocol);
    body.push_back(0U);
    body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x81U);
    body.push_back(usb::kEpTypeBulk); pushU16Le(body, 512U); body.push_back(0U);
    body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x01U);
    body.push_back(usb::kEpTypeBulk); pushU16Le(body, 512U); body.push_back(0U);

    // Interface 1: CDC-NCM Control
    body.push_back(9U);
    body.push_back(usb::kDescTypeInterface);
    body.push_back(1U);
    body.push_back(0U);
    body.push_back(1U);
    body.push_back(usb::kClassCommunications);
    body.push_back(usb::kSubClassCdcNcm);
    body.push_back(0U);
    body.push_back(0U);
    body.push_back(5U); body.push_back(usb::kDescTypeCsInterface); body.push_back(usb::kCdcSubtypeHeader);
    pushU16Le(body, 0x0120U);
    body.push_back(5U); body.push_back(usb::kDescTypeCsInterface); body.push_back(usb::kCdcSubtypeUnion);
    body.push_back(1U); body.push_back(2U);
    body.push_back(13U); body.push_back(usb::kDescTypeCsInterface); body.push_back(usb::kCdcSubtypeEthernet);
    body.push_back(4U); pushU32Le(body, 0U); pushU16Le(body, 1514U); pushU16Le(body, 0U); body.push_back(0U);
    body.push_back(6U); body.push_back(usb::kDescTypeCsInterface); body.push_back(usb::kCdcSubtypeNcm);
    pushU16Le(body, 0x0100U); body.push_back(0x0fU);
    body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x82U);
    body.push_back(usb::kEpTypeInterrupt); pushU16Le(body, 16U); body.push_back(9U);

    // Interface 2 alt 0 (idle) and alt 1 (active)
    body.push_back(9U); body.push_back(usb::kDescTypeInterface); body.push_back(2U); body.push_back(0U);
    body.push_back(0U); body.push_back(usb::kClassCdcData); body.push_back(0U); body.push_back(usb::kProtocolCdcNcmData);
    body.push_back(0U);
    body.push_back(9U); body.push_back(usb::kDescTypeInterface); body.push_back(2U); body.push_back(1U);
    body.push_back(2U); body.push_back(usb::kClassCdcData); body.push_back(0U); body.push_back(usb::kProtocolCdcNcmData);
    body.push_back(0U);
    body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x83U);
    body.push_back(usb::kEpTypeBulk); pushU16Le(body, 512U); body.push_back(0U);
    body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x03U);
    body.push_back(usb::kEpTypeBulk); pushU16Le(body, 512U); body.push_back(0U);

    Bytes blob;
    blob.push_back(18U); blob.push_back(usb::kDescTypeDevice); pushU16Le(blob, 0x0200U);
    blob.push_back(0U); blob.push_back(0U); blob.push_back(0U); blob.push_back(64U);
    pushU16Le(blob, usb::kAppleVendorId); pushU16Le(blob, 0x12a8U); pushU16Le(blob, 0x0100U);
    blob.push_back(1U); blob.push_back(2U); blob.push_back(3U); blob.push_back(1U);

    blob.push_back(9U); blob.push_back(usb::kDescTypeConfiguration);
    pushU16Le(blob, static_cast<uint16_t>(9U + body.size()));
    blob.push_back(3U);
    blob.push_back(4U);
    blob.push_back(0U); blob.push_back(0xc0U); blob.push_back(250U);
    blob.insert(blob.end(), body.begin(), body.end());
    return blob;
}

class FakeAuthProvider : public iap2::AuthProvider {
public:
    Bytes cert;
    uint8_t sig_xor;

    FakeAuthProvider() : sig_xor(0x5aU) {
        cert.resize(128U, 0U);
        for (size_t i = 0U; i < cert.size(); ++i) {
            cert[i] = static_cast<uint8_t>((i * 7U + 3U) & 0xffU);
        }
    }

    virtual bool getCertificate(Bytes& certificate_out) {
        certificate_out = cert;
        return true;
    }

    virtual bool signChallenge(const uint8_t* challenge,
                               size_t challenge_len,
                               Bytes& signature_out) {
        if (challenge == NULL || challenge_len == 0U) {
            return false;
        }
        signature_out.resize(challenge_len);
        for (size_t i = 0U; i < challenge_len; ++i) {
            signature_out[i] = static_cast<uint8_t>(challenge[i] ^ sig_xor);
        }
        return true;
    }
};

/// Minimal fake iPhone iAP2 link + CSM peer operating on arbitrary byte streams.
class FakeIap2Peer {
public:
    Bytes tx_to_accessory;
    std::vector<iap2::Frame> received_frames;
    bool detect_seen;
    bool rst_seen;
    bool syn_seen;
    uint8_t dev_seq;
    uint8_t last_acc_seq;
    uint8_t session_id;
    iap2::SynPayload dev_syn;
    iap2::CsmFramer framer;

    FakeIap2Peer()
        : detect_seen(false),
          rst_seen(false),
          syn_seen(false),
          dev_seq(100U),
          last_acc_seq(0U),
          session_id(10U) {
        dev_syn.version = 1;
        dev_syn.max_outstanding = 3;
        dev_syn.max_packet_length = 256;
        dev_syn.retransmission_timeout_ms = 1000;
        dev_syn.cumulative_ack_timeout_ms = 50;
        dev_syn.max_retransmissions = 5;
        dev_syn.max_cumulative_acks = 1;
        dev_syn.sessions.push_back(iap2::SynSession(10U, iap2::kSessionTypeControl, 1U));
    }

    void consumeFromAccessory(Bytes& buf) {
        size_t pos = 0U;
        while (pos < buf.size()) {
            if (pos + iap2::kDetectSequenceBytes <= buf.size() &&
                std::memcmp(&buf[pos], iap2::kDetectSequence, iap2::kDetectSequenceBytes) == 0) {
                detect_seen = true;
                pos += iap2::kDetectSequenceBytes;
                continue;
            }
            if (pos + iap2::kLinkHeaderBytes <= buf.size() &&
                buf[pos] == 0xffU && buf[pos + 1U] == 0x5aU) {
                const uint16_t len = static_cast<uint16_t>(
                    (static_cast<uint16_t>(buf[pos + 2U]) << 8) | buf[pos + 3U]);
                iap2::LinkPacket pkt;
                REQUIRE(len >= iap2::kLinkHeaderBytes && pos + len <= buf.size());
                REQUIRE(iap2::LinkPacket::decode(&buf[pos], len, pkt));
                pos += len;
                handleAccessoryPacket(pkt);
                continue;
            }
            REQUIRE(false);
        }
        buf.clear();
    }

    void handleAccessoryPacket(const iap2::LinkPacket& pkt) {
        if ((pkt.control & iap2::kCtrlRst) != 0U) {
            rst_seen = true;
            return;
        }
        if ((pkt.control & iap2::kCtrlSyn) != 0U) {
            syn_seen = true;
            last_acc_seq = pkt.seq;
            iap2::SynPayload acc_syn;
            REQUIRE(iap2::SynPayload::decode(pkt.payload, acc_syn));
            const iap2::SynSession* ctrl = acc_syn.findSessionByType(iap2::kSessionTypeControl);
            if (ctrl != NULL) {
                session_id = ctrl->id;
            }
            return;
        }
        if (!pkt.payload.empty()) {
            last_acc_seq = pkt.seq;
            REQUIRE(framer.push(&pkt.payload[0], pkt.payload.size(), received_frames));
            sendAck();
        }
    }

    void sendDetect() {
        tx_to_accessory.insert(tx_to_accessory.end(),
                               iap2::kDetectSequence,
                               iap2::kDetectSequence + iap2::kDetectSequenceBytes);
    }

    void sendSynAck() {
        iap2::LinkPacket pkt;
        pkt.control = static_cast<uint8_t>(iap2::kCtrlSyn | iap2::kCtrlAck);
        pkt.seq = dev_seq;
        pkt.ack = last_acc_seq;
        pkt.session_id = 0U;
        REQUIRE(dev_syn.encode(pkt.payload));
        Bytes raw;
        REQUIRE(pkt.encode(raw));
        tx_to_accessory.insert(tx_to_accessory.end(), raw.begin(), raw.end());
    }

    void sendAck() {
        iap2::LinkPacket pkt;
        pkt.control = iap2::kCtrlAck;
        pkt.seq = dev_seq;
        pkt.ack = last_acc_seq;
        pkt.session_id = 0U;
        Bytes raw;
        REQUIRE(pkt.encode(raw));
        tx_to_accessory.insert(tx_to_accessory.end(), raw.begin(), raw.end());
    }

    void sendControlFrame(uint16_t msg_id,
                          const iap2::ParameterList& params = iap2::ParameterList()) {
        iap2::Frame f;
        REQUIRE(iap2::Frame::build(msg_id, params, f));
        Bytes csm;
        REQUIRE(f.encode(csm));
        std::vector<Bytes> chunks;
        const size_t max_pl = dev_syn.max_packet_length - iap2::kLinkPacketOverheadBytes;
        REQUIRE(iap2::CsmFramer::splitForLink(csm, max_pl, chunks));
        for (size_t i = 0U; i < chunks.size(); ++i) {
            dev_seq = static_cast<uint8_t>(dev_seq + 1U);
            iap2::LinkPacket pkt;
            pkt.control = iap2::kCtrlAck;
            pkt.seq = dev_seq;
            pkt.ack = last_acc_seq;
            pkt.session_id = session_id;
            pkt.payload = chunks[i];
            Bytes raw;
            REQUIRE(pkt.encode(raw));
            tx_to_accessory.insert(tx_to_accessory.end(), raw.begin(), raw.end());
        }
    }

    const iap2::Frame* findLastFrame(uint16_t msg_id) const {
        for (size_t i = received_frames.size(); i > 0U; --i) {
            if (received_frames[i - 1U].message_id == msg_id) {
                return &received_frames[i - 1U];
            }
        }
        return NULL;
    }
};

class AdapterSessionListener : public iap2::SessionListener {
public:
    explicit AdapterSessionListener(const plat::WifiApCredentialsAdapter* wifi_provider = NULL)
        : wifi_provider_(wifi_provider),
          ready_count(0),
          wifi_requests(0) {}

    virtual void onReady() { ++ready_count; }
    virtual bool onWiFiCredentialsRequested(iap2::WiFiConfiguration& out) {
        ++wifi_requests;
        if (wifi_provider_ == NULL) {
            return false;
        }
        return wifi_provider_->provideWiFiConfiguration(out);
    }
    virtual void onError(const std::string& msg) { errors.push_back(msg); }

    const plat::WifiApCredentialsAdapter* wifi_provider_;
    int ready_count;
    int wifi_requests;
    std::vector<std::string> errors;
};

class FakeBtTransport : public plat::BtTransport {
public:
    FakeBtTransport()
        : listener_(NULL), started_(false), connected_(false), fail_writes_(false) {}

    virtual plat::BtBackendKind backendKind() const { return plat::kBtBackendAlpsSpp; }
    virtual const char* backendName() const { return "fake-bt"; }

    virtual bool start(std::string* /*error_out*/ = NULL) {
        started_ = true;
        return true;
    }

    virtual void stop() {
        connected_ = false;
        started_ = false;
    }

    virtual void disconnect(const std::string& reason = "local disconnect") {
        if (connected_) {
            connected_ = false;
            if (listener_ != NULL) {
                listener_->onBtTransportDisconnected(reason);
            }
        }
    }

    virtual bool sendBytes(const uint8_t* data, size_t len) {
        if (!started_ || !connected_ || fail_writes_ || data == NULL || len == 0U) {
            return false;
        }
        tx_bytes.insert(tx_bytes.end(), data, data + len);
        return true;
    }

    virtual void setListener(plat::BtTransportListener* listener) { listener_ = listener; }
    virtual bool isStarted() const { return started_; }
    virtual bool isConnected() const { return connected_; }
    virtual const plat::BtAddr& peerAddress() const { return peer_; }

    void simulateConnect(const plat::BtAddr& peer) {
        peer_ = peer;
        connected_ = true;
        if (listener_ != NULL) {
            listener_->onBtTransportConnected(peer);
        }
    }

    void simulateRx(const Bytes& data) {
        if (connected_ && listener_ != NULL && !data.empty()) {
            listener_->onBtTransportData(&data[0], data.size());
        }
    }

    void simulateDisconnect(const std::string& reason) {
        connected_ = false;
        if (listener_ != NULL) {
            listener_->onBtTransportDisconnected(reason);
        }
    }

    Bytes tx_bytes;
    plat::BtTransportListener* listener_;
    plat::BtAddr peer_;
    bool started_;
    bool connected_;
    bool fail_writes_;
};

class RecordingBtListener : public plat::BtTransportListener {
public:
    RecordingBtListener() : connects(0), disconnects(0), rx_bytes(0) {}

    virtual void onBtTransportConnected(const plat::BtAddr& peer) {
        ++connects;
        last_peer = peer;
    }
    virtual void onBtTransportData(const uint8_t* /*data*/, size_t len) {
        rx_bytes += len;
    }
    virtual void onBtTransportDisconnected(const std::string& reason) {
        ++disconnects;
        last_reason = reason;
    }

    int connects;
    int disconnects;
    size_t rx_bytes;
    plat::BtAddr last_peer;
    std::string last_reason;
};

class FakeUsbHost : public plat::UsbHostInterface {
public:
    struct PendingIn {
        uint64_t id;
        uint8_t ep;
        void* ctx;
    };

    struct PendingOut {
        uint64_t id;
        uint8_t ep;
        void* ctx;
    };

    FakeUsbHost()
        : listener_(NULL), started_(false), open_(false), next_id_(1U) {}

    virtual bool start(plat::Reactor& /*reactor*/, plat::UsbHostListener* listener) {
        listener_ = listener;
        started_ = true;
        return true;
    }

    virtual void stop() {
        started_ = false;
        open_ = false;
        pending_in_.clear();
        pending_out_.clear();
        listener_ = NULL;
    }

    virtual bool isDeviceOpen() const { return open_; }
    virtual const plat::UsbDeviceInfo& currentDevice() const { return info_; }
    virtual const usb::DeviceDescriptor& deviceDescriptor() const { return dev_desc_; }
    virtual const std::vector<usb::ConfigurationDescriptor>& configurations() const {
        return configs_;
    }

    virtual bool setConfiguration(uint8_t config_value) {
        info_.configuration_value = config_value;
        return true;
    }
    virtual bool claimInterface(uint8_t /*interface_number*/, bool /*detach_kernel_driver*/) {
        return true;
    }
    virtual bool claimInterfaceWithStatus(uint8_t /*interface_number*/,
                                          bool /*detach_kernel_driver*/,
                                          bool /*detach_usbfs_driver*/,
                                          plat::UsbClaimStatus& status_out,
                                          std::string& driver_out) {
        status_out = plat::kUsbClaimOk;
        driver_out.clear();
        return true;
    }
    virtual bool releaseInterface(uint8_t /*interface_number*/) { return true; }
    virtual bool setInterface(uint8_t /*interface_number*/, uint8_t /*alt_setting*/) {
        return true;
    }
    virtual bool resetDevice() { return true; }

    virtual bool controlTransfer(uint8_t request_type,
                                 uint8_t request,
                                 uint16_t /*value*/,
                                 uint16_t /*index*/,
                                 Bytes& data_io,
                                 uint32_t /*timeout_ms*/,
                                 int* actual_len_out = NULL) {
        if (request_type == carplay::ncm::kReqTypeClassIn &&
            request == carplay::ncm::kReqGetNtbParameters) {
            carplay::ncm::NtbParameters p;
            p.formats_supported = 0x0001U;  // NTB-16
            p.ntb_in_max_size = 16384U;
            p.ndp_in_divisor = 4U;
            p.ndp_in_alignment = 4U;
            p.ntb_out_max_size = 16384U;
            p.ndp_out_divisor = 4U;
            p.ndp_out_alignment = 4U;
            p.ntb_out_max_datagrams = 16U;
            carplay::ncm::encodeNtbParameters(p, data_io);
            if (actual_len_out != NULL) {
                *actual_len_out = static_cast<int>(data_io.size());
            }
            return true;
        }
        return true;
    }

    virtual bool readStringDescriptor(uint8_t /*string_index*/, std::string& out) {
        out = "021122334455";
        return true;
    }
    virtual bool queryActiveConfiguration(uint8_t& config_value_out) {
        config_value_out = info_.configuration_value;
        return true;
    }
    virtual bool queryAppleUsbMode(Bytes& mode_out) {
        mode_out.clear();
        return true;
    }
    virtual bool requestCarPlayModeSwitch(const plat::AppleCarPlaySwitchRequest& /*req*/) {
        return true;
    }

    virtual uint64_t submitBulkIn(uint8_t endpoint, size_t /*max_bytes*/, void* user_ctx) {
        const uint64_t id = next_id_++;
        PendingIn p;
        p.id = id;
        p.ep = endpoint;
        p.ctx = user_ctx;
        pending_in_.push_back(p);
        return id;
    }

    virtual uint64_t submitBulkOut(uint8_t endpoint,
                                   const uint8_t* data,
                                   size_t len,
                                   bool /*zero_packet*/,
                                   void* user_ctx) {
        if (!open_) {
            return 0U;
        }
        const uint64_t id = next_id_++;
        if (endpoint == 0x01U && data != NULL && len > 0U) {
            iap2_out_bytes.insert(iap2_out_bytes.end(), data, data + len);
        }
        PendingOut p;
        p.id = id;
        p.ep = endpoint;
        p.ctx = user_ctx;
        pending_out_.push_back(p);
        return id;
    }

    virtual bool discardUrb(uint64_t /*urb_id*/) { return true; }
    virtual void ignoreCurrentDevice() {}
    virtual void closeCurrentDevice() {
        open_ = false;
        pending_in_.clear();
        pending_out_.clear();
    }

    void flushPendingOut() {
        while (!pending_out_.empty()) {
            const PendingOut p = pending_out_.front();
            pending_out_.pop_front();
            if (listener_ != NULL) {
                listener_->onUsbUrbComplete(p.id, p.ep, false, 0, NULL, 0U, p.ctx);
            }
        }
    }

    void simulateArrival(const Bytes& blob) {
        std::string err;
        REQUIRE(!blob.empty());
        REQUIRE(usb::parseUsbfsDescriptors(&blob[0], blob.size(), dev_desc_, configs_, &err));
        info_ = plat::UsbDeviceInfo();
        info_.vendor_id = dev_desc_.id_vendor;
        info_.product_id = dev_desc_.id_product;
        info_.bus_num = 1U;
        info_.dev_num = 2U;
        info_.configuration_value = 0U;
        open_ = true;
        if (listener_ != NULL) {
            listener_->onUsbDeviceArrived(info_, dev_desc_, configs_);
        }
    }

    void deliverIap2In(const Bytes& payload) {
        flushPendingOut();
        for (size_t i = 0U; i < pending_in_.size(); ++i) {
            if (pending_in_[i].ep == 0x81U) {
                const PendingIn p = pending_in_[i];
                pending_in_.erase(pending_in_.begin() + static_cast<ptrdiff_t>(i));
                if (listener_ != NULL && !payload.empty()) {
                    listener_->onUsbUrbComplete(p.id, p.ep, true, 0, &payload[0], payload.size(),
                                                p.ctx);
                }
                flushPendingOut();
                return;
            }
        }
        REQUIRE(false);
    }

    void simulateRemoval() {
        open_ = false;
        pending_in_.clear();
        pending_out_.clear();
        if (listener_ != NULL) {
            listener_->onUsbDeviceRemoved();
        }
    }

    Bytes iap2_out_bytes;
    plat::UsbHostListener* listener_;
    bool started_;
    bool open_;
    uint64_t next_id_;
    plat::UsbDeviceInfo info_;
    usb::DeviceDescriptor dev_desc_;
    std::vector<usb::ConfigurationDescriptor> configs_;
    std::vector<PendingIn> pending_in_;
    std::deque<PendingOut> pending_out_;
};

class FakeTapPort : public plat::TapPortInterface {
public:
    FakeTapPort() : open_(false), ifname_("carplay0"), ifindex_(7U) {
        mac_[0] = 0x02U; mac_[1] = 0xaaU; mac_[2] = 0xbbU;
        mac_[3] = 0xccU; mac_[4] = 0xddU; mac_[5] = 0xeeU;
    }

    virtual bool open(plat::Reactor& /*reactor*/, plat::TapListener* /*listener*/) {
        open_ = true;
        return true;
    }
    virtual void close() { open_ = false; }
    virtual bool isOpen() const { return open_; }
    virtual const std::string& interfaceName() const { return ifname_; }
    virtual uint32_t ifIndex() const { return ifindex_; }
    virtual void getMacAddress(uint8_t mac_out[6]) const { std::memcpy(mac_out, mac_, 6U); }
    virtual plat::TapWriteResult writeFrame(const uint8_t* /*data*/, size_t /*len*/) {
        return plat::kTapWriteSent;
    }
    virtual bool queryIpv6LinkLocal(plat::Address& /*out*/) const { return false; }

    bool open_;
    std::string ifname_;
    uint32_t ifindex_;
    uint8_t mac_[6];
};

class RecordingUsbBridgeListener : public plat::UsbCarPlayBridgeListener {
public:
    RecordingUsbBridgeListener()
        : iap2_ready_count(0), ncm_ready_count(0), removed_count(0), rx_bytes(0),
          tap_ifindex(0U) {}

    virtual void onBridgeStateChanged(plat::BridgeState s) { states.push_back(s); }
    virtual void onIap2Ready(const usb::Iap2InterfaceSelection& /*iap2*/) { ++iap2_ready_count; }
    virtual void onIap2Data(const uint8_t* /*data*/, size_t len) { rx_bytes += len; }
    virtual void onNcmReady(const std::string& ifname,
                            uint32_t ifidx,
                            const uint8_t /*tap_mac*/[6]) {
        ++ncm_ready_count;
        tap_ifname = ifname;
        tap_ifindex = ifidx;
    }
    virtual void onDeviceRemoved() { ++removed_count; }
    virtual void onBridgeError(const std::string& reason) { errors.push_back(reason); }

    std::vector<plat::BridgeState> states;
    int iap2_ready_count;
    int ncm_ready_count;
    int removed_count;
    size_t rx_bytes;
    std::string tap_ifname;
    uint32_t tap_ifindex;
    std::vector<std::string> errors;
};

class FakeWlanController : public plat::IWlanController {
public:
    FakeWlanController()
        : listener_(NULL), available_(true), busy_(false), enable_calls(0), restore_calls(0) {}

    virtual void setListener(plat::WlanControllerListener* listener) { listener_ = listener; }
    virtual bool isAvailable() const { return available_; }
    virtual bool isBusy() const { return busy_; }
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
    bool available_;
    bool busy_;
    int enable_calls;
    int restore_calls;
};

class FakeAccessPointReader : public plat::IAccessPointReader {
public:
    explicit FakeAccessPointReader(const std::string& raw_cfg) : raw_cfg_(raw_cfg) {}

    virtual bool isNativeEnvironmentPresent(const plat::NativeWlanPaths& /*paths*/) const {
        return true;
    }
    virtual bool readAccessPoint(const plat::NativeWlanPaths& /*paths*/,
                                 plat::EvoApInfo& out,
                                 std::string& source_out,
                                 std::string* error_out = NULL) {
        if (!plat::parseHostapdConfig(raw_cfg_, out)) {
            if (error_out != NULL) {
                *error_out = "parseHostapdConfig failed";
            }
            return false;
        }
        source_out = "fake-native-ap";
        return true;
    }
    virtual bool readFrequencyMhz(const std::string& /*interface_name*/, unsigned& mhz_out) {
        mhz_out = 5180U;
        return true;
    }
    virtual bool readConnectedStations(const std::string& /*interface_name*/,
                                       std::vector<std::string>& macs_out) {
        macs_out.clear();
        return true;
    }

    std::string raw_cfg_;
};

class FakeHostapdCtrl : public plat::IHostapdCtrl {
public:
    virtual void setListener(plat::HostapdCtrlListener* /*listener*/) {}
    virtual bool open(const std::string& /*remote*/,
                      const std::string& /*local*/,
                      std::string* error_out) {
        if (error_out != NULL) {
            *error_out = "not opened";
        }
        return false;
    }
    virtual void close() {}
    virtual bool isOpen() const { return false; }
    virtual bool sendPing(int /*timeout_ms*/) { return false; }
    virtual bool sendAttach(int /*timeout_ms*/) { return false; }
    virtual bool sendDetach(int /*timeout_ms*/) { return false; }
    virtual bool sendStatus(int /*timeout_ms*/) { return false; }
    virtual bool sendGetConfig(int /*timeout_ms*/) { return false; }
    virtual bool sendAllSta(int /*timeout_ms*/) { return false; }
    virtual bool sendEnable(int /*timeout_ms*/) { return false; }
    virtual bool sendDisable(int /*timeout_ms*/) { return false; }
    virtual bool sendCommand(plat::HostapdCommandKind /*kind*/,
                             const std::string& /*cmd*/,
                             int /*timeout_ms*/) { return false; }
};

class RecordingWifiApListener : public plat::WifiApListener {
public:
    RecordingWifiApListener() : started_count(0), stopped_count(0), station_count(0) {}
    virtual void onWifiApStarted(const plat::WifiCredentials& creds) {
        ++started_count;
        last_creds = creds;
    }
    virtual void onWifiApStopped() { ++stopped_count; }
    virtual void onWifiApRestarting(int /*attempt*/, const std::string& /*reason*/) {}
    virtual void onWifiApFailed(const std::string& /*reason*/) {}
    virtual void onStationConnected(const std::string& /*mac*/) { ++station_count; }
    virtual void onStationDisconnected(const std::string& /*mac*/) {}

    int started_count;
    int stopped_count;
    int station_count;
    plat::WifiCredentials last_creds;
};

void driveHandshakeToReady(FakeIap2Peer& peer,
                           Bytes& acc_tx,
                           void (*deliverFn)(void* ctx, const Bytes& data),
                           void* ctx,
                           const iap2::Session& session) {
    // 1) Accessory -> DETECT; Peer answers DETECT; Accessory -> SYN; Peer -> SYN|ACK
    peer.consumeFromAccessory(acc_tx);
    REQUIRE(peer.detect_seen);
    peer.sendDetect();
    Bytes batch = peer.tx_to_accessory;
    peer.tx_to_accessory.clear();
    deliverFn(ctx, batch);
    peer.consumeFromAccessory(acc_tx);
    REQUIRE(peer.syn_seen);
    peer.sendSynAck();
    batch = peer.tx_to_accessory;
    peer.tx_to_accessory.clear();
    deliverFn(ctx, batch);
    peer.consumeFromAccessory(acc_tx);
    REQUIRE(session.state() == iap2::kSessionConnected);

    // 2) Identification (0x1D00 -> 0x1D01 -> 0x1D02)
    peer.sendControlFrame(iap2::msg::kStartIdentification);
    batch = peer.tx_to_accessory;
    peer.tx_to_accessory.clear();
    deliverFn(ctx, batch);
    peer.consumeFromAccessory(acc_tx);
    REQUIRE(peer.findLastFrame(iap2::msg::kIdentificationInformation) != NULL);

    peer.sendControlFrame(iap2::msg::kIdentificationAccepted);
    batch = peer.tx_to_accessory;
    peer.tx_to_accessory.clear();
    deliverFn(ctx, batch);
    peer.consumeFromAccessory(acc_tx);
    REQUIRE(session.state() == iap2::kSessionIdentified);

    // 3) Authentication (0xAA00 -> 0xAA01, 0xAA02 -> 0xAA03 -> 0xAA05)
    peer.sendControlFrame(iap2::msg::kRequestAuthenticationCertificate);
    batch = peer.tx_to_accessory;
    peer.tx_to_accessory.clear();
    deliverFn(ctx, batch);
    peer.consumeFromAccessory(acc_tx);
    REQUIRE(peer.findLastFrame(iap2::msg::kAuthenticationCertificate) != NULL);

    iap2::ParameterList ch_params;
    Bytes ch(16U, 0x22U);
    ch_params.addRaw(iap2::param::kAuthChallengeData, ch);
    peer.sendControlFrame(iap2::msg::kRequestAuthenticationChallengeResponse, ch_params);
    batch = peer.tx_to_accessory;
    peer.tx_to_accessory.clear();
    deliverFn(ctx, batch);
    peer.consumeFromAccessory(acc_tx);
    REQUIRE(peer.findLastFrame(iap2::msg::kAuthenticationResponse) != NULL);

    peer.sendControlFrame(iap2::msg::kAuthenticationSucceeded);
    batch = peer.tx_to_accessory;
    peer.tx_to_accessory.clear();
    deliverFn(ctx, batch);
    peer.consumeFromAccessory(acc_tx);
    REQUIRE(session.isReady());
}

void deliverBt(void* ctx, const Bytes& data) {
    static_cast<FakeBtTransport*>(ctx)->simulateRx(data);
}

void deliverUsb(void* ctx, const Bytes& data) {
    static_cast<FakeUsbHost*>(ctx)->deliverIap2In(data);
}

TEST_CASE(btSessionAdapterAndNativeWifi0x5703) {
    // 1) Parse BMW native AP config (wpa=2, WPA-PSK, freq=5180) and wire WifiApCredentialsAdapter.
    plat::EvoApInfo ap_info;
    REQUIRE(plat::parseHostapdConfig(
        "bssid=02:aa:bb:cc:dd:ee\n"
        "ssid=BMW-DIRECT-54321\n"
        "passphrase=NativePassphrase1\n"
        "wpa=2\n"
        "key_mgmt=WPA-PSK\n"
        "freq=5180\n",
        ap_info));
    CHECK_EQ(static_cast<uint8_t>(iap2::kWirelessSecurityWpaWpa2), ap_info.security_type);

    plat::WifiCredentials native_creds;
    std::string err;
    REQUIRE(ap_info.toWifiCredentials(native_creds, 0U, &err));
    CHECK_EQ(static_cast<uint8_t>(iap2::kWirelessSecurityWpaWpa2), native_creds.security_type);

    RecordingWifiApListener wifi_downstream;
    plat::WifiApCredentialsAdapter wifi_adapter(NULL, &wifi_downstream);
    CHECK(!wifi_adapter.hasCredentials());
    wifi_adapter.onWifiApStarted(native_creds);
    CHECK(wifi_adapter.hasCredentials());
    CHECK_EQ(1, wifi_downstream.started_count);

    // 2) Construct BtSessionAdapter FIRST, then Session & BtTransport (tests cycle-free wiring).
    FakeBtTransport bt;
    RecordingBtListener bt_downstream;
    plat::BtSessionAdapter bt_adapter(&bt, NULL, &bt_downstream);
    bt.setListener(&bt_adapter);
    REQUIRE(bt.start(&err));

    const uint8_t bt_mac_raw[6] = {0x10U, 0x20U, 0x30U, 0x40U, 0x50U, 0x60U};
    const Bytes bt_mac(bt_mac_raw, bt_mac_raw + 6);
    iap2::IdentificationConfig ident = iap2::IdentificationConfig::wirelessBluetooth(
        "BMW EntryNav2", "HU_ENTRYNAV2", "BMW", "SN123", "1.0", "1.0", bt_mac, native_creds.ssid);
    iap2::SessionConfig s_cfg = iap2::SessionConfig::wirelessBluetooth(ident);

    FakeAuthProvider auth;
    AdapterSessionListener session_listener(&wifi_adapter);
    iap2::Session session(bt_adapter, auth, session_listener, s_cfg);
    bt_adapter.setSession(&session);

    // 3) Connect BT -> auto-starts iAP2 session and completes wireless handshake.
    plat::BtAddr peer_addr;
    REQUIRE(plat::BtAddr::parse("AA:BB:CC:DD:EE:FF", peer_addr));
    bt.simulateConnect(peer_addr);
    CHECK_EQ(1, bt_downstream.connects);
    CHECK(session.state() == iap2::kSessionDetecting);

    FakeIap2Peer peer;
    driveHandshakeToReady(peer, bt.tx_bytes, deliverBt, &bt, session);
    CHECK_EQ(1, session_listener.ready_count);

    // 4) Device requests 0x5702 -> Session responds with 0x5703 using WifiApCredentialsAdapter.
    peer.sendControlFrame(iap2::msg::kRequestAccessoryWiFiConfiguration);
    Bytes req = peer.tx_to_accessory;
    peer.tx_to_accessory.clear();
    bt.simulateRx(req);
    peer.consumeFromAccessory(bt.tx_bytes);

    CHECK_EQ(1, session_listener.wifi_requests);
    const iap2::Frame* wifi_cfg_frame = peer.findLastFrame(iap2::msg::kAccessoryWiFiConfiguration);
    REQUIRE(wifi_cfg_frame != NULL);
    iap2::ParameterList decoded;
    REQUIRE(iap2::ParameterList::decode(wifi_cfg_frame->payload, decoded, &err));
    Bytes bssid_out;
    std::string ssid_out;
    std::string psk_out;
    uint8_t sec_out = 0U;
    uint8_t ch_out = 0U;
    CHECK(decoded.readBytes(0U, bssid_out));
    CHECK_BYTES_EQ(native_creds.bssidVector(), bssid_out);
    CHECK(decoded.readString(1U, ssid_out));
    CHECK_EQ(native_creds.ssid, ssid_out);
    CHECK(decoded.readString(2U, psk_out));
    CHECK_EQ(native_creds.passphrase, psk_out);
    CHECK(decoded.readU8(3U, sec_out));
    CHECK_EQ(static_cast<uint8_t>(iap2::kWirelessSecurityWpaWpa2), sec_out);
    CHECK(decoded.readU8(4U, ch_out));
    CHECK_EQ(static_cast<uint8_t>(36U), ch_out);

    // 5) Disconnect resets Session without trying to emit RST onto disconnected BT transport.
    bt.tx_bytes.clear();
    bt.simulateDisconnect("rfcomm hangup");
    CHECK_EQ(1, bt_downstream.disconnects);
    CHECK(session.state() == iap2::kSessionIdle);
    CHECK(bt.tx_bytes.empty());

    // Reconnect starts cleanly again.
    bt.simulateConnect(peer_addr);
    CHECK_EQ(2, bt_downstream.connects);
    CHECK(session.state() == iap2::kSessionDetecting);
    CHECK(!bt.tx_bytes.empty());

    wifi_adapter.onWifiApStopped();
    CHECK(!wifi_adapter.hasCredentials());
    CHECK_EQ(1, wifi_downstream.stopped_count);
}

TEST_CASE(usbBridgeSessionAdapterFullFlow) {
    plat::Reactor reactor(fakeClockNs);
    REQUIRE(reactor.init());

    FakeUsbHost usb_host;
    FakeTapPort tap;
    plat::UsbCarPlayBridge bridge(usb_host, tap);
    RecordingUsbBridgeListener bridge_downstream;

    plat::UsbBridgeSessionAdapter usb_adapter(&bridge, NULL, &bridge_downstream);
    REQUIRE(bridge.start(reactor, &usb_adapter));

    iap2::IdentificationConfig ident = iap2::IdentificationConfig::wiredUsb(
        "BMW EntryNav2", "HU_ENTRYNAV2", "BMW", "SN123", "1.0", "1.0", 0U);
    iap2::SessionConfig s_cfg = iap2::SessionConfig::wiredUsb(ident, 2400U);

    FakeAuthProvider auth;
    AdapterSessionListener session_listener;
    iap2::Session session(usb_adapter, auth, session_listener, s_cfg);
    usb_adapter.setSession(&session);

    // Standalone ByteSink adapter also compiles and forwards.
    plat::UsbBridgeIap2ByteSink direct_sink(bridge);
    const uint8_t probe_byte = 0xffU;
    CHECK(!direct_sink.sendBytes(&probe_byte, 1U));  // not ready yet

    // Attach iPhone -> bridge claims iAP2 + NCM -> onIap2Ready starts Session.
    usb_host.simulateArrival(buildSyntheticCarPlayBlob());
    CHECK_EQ(1, bridge_downstream.iap2_ready_count);
    CHECK_EQ(1, bridge_downstream.ncm_ready_count);
    CHECK_EQ(std::string("carplay0"), bridge_downstream.tap_ifname);
    CHECK_EQ(static_cast<uint32_t>(7U), bridge_downstream.tap_ifindex);
    CHECK(session.state() == iap2::kSessionSyncing);

    FakeIap2Peer peer;
    driveHandshakeToReady(peer, usb_host.iap2_out_bytes, deliverUsb, &usb_host, session);
    CHECK_EQ(1, session_listener.ready_count);
    CHECK(bridge_downstream.rx_bytes > 0U);

    // Unplug resets session cleanly without attempting USB Bulk OUT writes.
    usb_host.iap2_out_bytes.clear();
    usb_host.simulateRemoval();
    CHECK_EQ(1, bridge_downstream.removed_count);
    CHECK(session.state() == iap2::kSessionIdle);
    CHECK(usb_host.iap2_out_bytes.empty());

    bridge.stop();
}

TEST_CASE(wifiApNativeBackendTo0x5703Credentials) {
    plat::Reactor reactor(fakeClockNs);
    REQUIRE(reactor.init());
    plat::OsRandomSource rng;
    plat::WifiAp ap(reactor, rng);

    FakeWlanController wlan_ctrl;
    FakeAccessPointReader ap_reader(
        "bssid=02:11:22:33:44:55\n"
        "ssid=BMW-AP-NATIVE\n"
        "passphrase=CarPlayNative99\n"
        "wpa=2\n"
        "key_mgmt=WPA-PSK\n"
        "channel=44\n");
    FakeHostapdCtrl ctrl;
    ap.setWlanControllerForTest(&wlan_ctrl);
    ap.setAccessPointReaderForTest(&ap_reader);
    ap.setHostapdCtrlForTest(&ctrl);
    ap.setNativeCapabilityForTest(1);

    // Verify pull-mode WifiApCredentialsAdapter reading directly from WifiAp.
    RecordingWifiApListener downstream;
    plat::WifiApCredentialsAdapter creds_adapter(&ap, &downstream);
    ap.setListener(&creds_adapter);

    iap2::WiFiConfiguration cfg_out;
    std::string err;
    CHECK(!plat::populateIap2WiFiConfiguration(ap, cfg_out, &err));
    CHECK(!creds_adapter.provideWiFiConfiguration(cfg_out, &err));

    plat::WifiApConfig ap_cfg;
    ap_cfg.backend = plat::kWifiApBackendNative;
    ap_cfg.runtime_dir = "/tmp/carplay_unused_test_dir";
    REQUIRE(ap.start(ap_cfg, &err));
    CHECK_EQ(plat::kWifiApRunning, ap.state());
    CHECK_EQ(1, downstream.started_count);

    REQUIRE(plat::populateIap2WiFiConfiguration(ap, cfg_out, &err));
    CHECK_EQ(std::string("BMW-AP-NATIVE"), cfg_out.ssid);
    CHECK_EQ(std::string("CarPlayNative99"), cfg_out.passphrase);
    CHECK_EQ(static_cast<uint8_t>(44U), cfg_out.channel);
    CHECK_EQ(static_cast<uint8_t>(iap2::kWirelessSecurityWpaWpa2), cfg_out.security_type);
    CHECK_BYTES_EQ(test_support::hexToBytes("021122334455"), cfg_out.bssid);

    iap2::WiFiConfiguration via_adapter;
    REQUIRE(creds_adapter.provideWiFiConfiguration(via_adapter, &err));
    CHECK_EQ(cfg_out.ssid, via_adapter.ssid);
    CHECK_EQ(cfg_out.security_type, via_adapter.security_type);

    ap.stopSync();
    CHECK_EQ(1, downstream.stopped_count);
    CHECK(!creds_adapter.provideWiFiConfiguration(via_adapter, &err));

    // Validation corner cases for toIap2WiFiConfiguration.
    plat::WifiCredentials open_creds;
    open_creds.ssid = "OpenCar";
    open_creds.channel = 6U;
    open_creds.security_type = iap2::kWirelessSecurityNone;
    REQUIRE(plat::toIap2WiFiConfiguration(open_creds, cfg_out, &err));
    CHECK_EQ(static_cast<uint8_t>(0U), cfg_out.security_type);

    plat::WifiCredentials bad_short_psk = open_creds;
    bad_short_psk.security_type = iap2::kWirelessSecurityWpaWpa2;
    bad_short_psk.passphrase = "short";
    CHECK(!plat::toIap2WiFiConfiguration(bad_short_psk, cfg_out, &err));

    ap.setListener(NULL);
    ap.setWlanControllerForTest(NULL);
    ap.setAccessPointReaderForTest(NULL);
    ap.setHostapdCtrlForTest(NULL);
}

}  // namespace

int main() {
    return test_support::runAll("transport_adapters");
}
