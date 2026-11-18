#include "carplay/iap2_session.hpp"
#include "test_support.hpp"

#include <cstring>
#include <string>
#include <vector>

namespace iap2 = carplay::iap2;

typedef std::vector<uint8_t> Bytes;

namespace {

class FakeAuthProvider : public iap2::AuthProvider {
public:
    bool fail_cert;
    bool fail_sign;
    Bytes cert;
    Bytes last_challenge;
    uint8_t sig_xor;

    FakeAuthProvider() : fail_cert(false), fail_sign(false), sig_xor(0x5aU) {
        cert.resize(600, 0);
        for (size_t i = 0; i < cert.size(); ++i) {
            cert[i] = static_cast<uint8_t>((i * 13U + 7U) & 0xffU);
        }
    }

    virtual bool getCertificate(Bytes& certificate_out) {
        if (fail_cert) {
            return false;
        }
        certificate_out = cert;
        return true;
    }

    virtual bool signChallenge(const uint8_t* challenge,
                               size_t challenge_len,
                               Bytes& signature_out) {
        if (fail_sign || challenge == NULL || challenge_len == 0U) {
            return false;
        }
        last_challenge.assign(challenge, challenge + challenge_len);
        signature_out.resize(challenge_len);
        for (size_t i = 0; i < challenge_len; ++i) {
            signature_out[i] = static_cast<uint8_t>(challenge[i] ^ sig_xor);
        }
        return true;
    }
};

class RecordingSessionListener : public iap2::SessionListener {
public:
    std::vector<iap2::SessionState> states;
    int ident_accepted_count;
    std::vector<std::vector<uint16_t> > ident_retries;
    std::vector<std::vector<uint16_t> > ident_rejections;
    std::vector<iap2::ParameterList> ident_updates;
    int auth_succeeded_count;
    std::vector<std::string> auth_failures;
    int ready_count;
    bool provide_wifi;
    iap2::WiFiConfiguration wifi_to_supply;
    int wifi_requests;
    std::vector<iap2::WiFiInformation> wifi_infos;
    std::vector<iap2::DeviceTransportIdentifier> transport_ids;
    std::vector<iap2::CarPlayAvailability> availabilities;
    std::vector<bool> wireless_updates;
    std::vector<iap2::Frame> power_update_frames;
    std::vector<bool> power_updates;
    std::vector<bool> location_updates;
    std::vector<bool> vehicle_status_updates;
    std::vector<iap2::Frame> unhandled;
    std::vector<std::string> errors;

    RecordingSessionListener()
        : ident_accepted_count(0),
          auth_succeeded_count(0),
          ready_count(0),
          provide_wifi(true),
          wifi_requests(0) {
        wifi_to_supply.ssid = "BMW-CarPlay-AP";
        wifi_to_supply.passphrase = "secret-passphrase";
        wifi_to_supply.channel = 36;
        wifi_to_supply.security_type = 3;
        const uint8_t bssid[6] = {0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U};
        wifi_to_supply.bssid.assign(bssid, bssid + 6);
    }

    virtual void onStateChanged(iap2::SessionState /*old_state*/, iap2::SessionState new_state) {
        states.push_back(new_state);
    }
    virtual void onIdentificationAccepted() {
        ++ident_accepted_count;
    }
    virtual void onIdentificationRetry(const std::vector<uint16_t>& omitted_messages) {
        ident_retries.push_back(omitted_messages);
    }
    virtual void onIdentificationRejected(const std::vector<uint16_t>& rejected_params) {
        ident_rejections.push_back(rejected_params);
    }
    virtual void onIdentificationUpdate(const iap2::ParameterList& params) {
        ident_updates.push_back(params);
    }
    virtual void onAuthenticationSucceeded() {
        ++auth_succeeded_count;
    }
    virtual void onAuthenticationFailed(const std::string& reason) {
        auth_failures.push_back(reason);
    }
    virtual void onReady() {
        ++ready_count;
    }
    virtual bool onWiFiCredentialsRequested(iap2::WiFiConfiguration& out) {
        ++wifi_requests;
        if (!provide_wifi) {
            return false;
        }
        out = wifi_to_supply;
        return true;
    }
    virtual void onWiFiInformation(const iap2::WiFiInformation& info) {
        wifi_infos.push_back(info);
    }
    virtual void onDeviceTransportIdentifier(const iap2::DeviceTransportIdentifier& id) {
        transport_ids.push_back(id);
    }
    virtual void onCarPlayAvailability(const iap2::CarPlayAvailability& availability) {
        availabilities.push_back(availability);
    }
    virtual void onWirelessCarPlayAvailability(bool available) {
        wireless_updates.push_back(available);
    }
    virtual void onPowerUpdate(const iap2::Frame& frame) {
        power_update_frames.push_back(frame);
    }
    virtual void onPowerUpdatesChanged(bool active) {
        power_updates.push_back(active);
    }
    virtual void onLocationUpdatesChanged(bool active) {
        location_updates.push_back(active);
    }
    virtual void onVehicleStatusUpdatesChanged(bool active) {
        vehicle_status_updates.push_back(active);
    }
    virtual void onUnhandledMessage(const iap2::Frame& frame) {
        unhandled.push_back(frame);
    }
    virtual void onError(const std::string& message) {
        errors.push_back(message);
    }
};

class WireSink : public iap2::ByteSink {
public:
    Bytes out;
    virtual bool sendBytes(const uint8_t* data, size_t len) {
        out.insert(out.end(), data, data + len);
        return true;
    }
    void clear() { out.clear(); }
};

/// Minimal independent fake iPhone iAP2 link+CSM peer for loopback tests.
class FakeDevice {
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

    FakeDevice()
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

    void consumeFromAccessory(WireSink& acc_sink) {
        Bytes& buf = acc_sink.out;
        size_t pos = 0;
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

    void sendControlFrame(uint16_t msg_id, const iap2::ParameterList& params = iap2::ParameterList()) {
        iap2::Frame f;
        REQUIRE(iap2::Frame::build(msg_id, params, f));
        Bytes csm;
        REQUIRE(f.encode(csm));
        std::vector<Bytes> chunks;
        const size_t max_pl = dev_syn.max_packet_length - iap2::kLinkPacketOverheadBytes;
        REQUIRE(iap2::CsmFramer::splitForLink(csm, max_pl, chunks));
        for (size_t i = 0; i < chunks.size(); ++i) {
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

    void sendRst() {
        iap2::LinkPacket pkt;
        pkt.control = iap2::kCtrlRst;
        pkt.seq = 0U;
        pkt.ack = 0U;
        pkt.session_id = 0U;
        Bytes raw;
        REQUIRE(pkt.encode(raw));
        tx_to_accessory.insert(tx_to_accessory.end(), raw.begin(), raw.end());
    }

    void flushToAccessory(iap2::Session& session, WireSink& acc_sink) {
        int guard = 0;
        while (!tx_to_accessory.empty() || !acc_sink.out.empty()) {
            REQUIRE(++guard < 64);
            if (!tx_to_accessory.empty()) {
                const Bytes batch = tx_to_accessory;
                tx_to_accessory.clear();
                REQUIRE(session.feed(batch));
            }
            if (!acc_sink.out.empty()) {
                consumeFromAccessory(acc_sink);
            }
        }
    }
};

iap2::IdentificationConfig makeFullIdentConfig() {
    iap2::IdentificationConfig id;
    id.name = "BMW EntryNav2";
    id.model = "HU_ENTRYNAV2";
    id.manufacturer = "BMW";
    id.serial_number = "F20-123456";
    id.firmware_version = "202402191339";
    id.hardware_version = "HW-EVO-1";
    id.messages_sent_by_accessory.push_back(iap2::msg::kAccessoryWiFiConfiguration);
    id.messages_sent_by_accessory.push_back(iap2::msg::kCarPlayStartSession);
    id.messages_received_from_device.push_back(iap2::msg::kCarPlayAvailability);
    id.messages_received_from_device.push_back(iap2::msg::kRequestAccessoryWiFiConfiguration);
    id.power_providing_capability = iap2::kPowerCapabilityAdvanced;
    id.max_current_drawn_ma = 0U;
    id.current_language = "en";
    id.supported_languages.push_back("en");
    id.supported_languages.push_back("tr");
    id.supported_languages.push_back("de");

    id.usb_device_transport.enabled = true;
    id.usb_device_transport.component_id = 1U;
    id.usb_device_transport.name = "USB CarPlay";
    id.usb_device_transport.audio_sample_rates.push_back(44U);

    id.bluetooth_transport.enabled = true;
    id.bluetooth_transport.component_id = 2U;
    id.bluetooth_transport.name = "BMW BT";
    const uint8_t mac[6] = {0xaaU, 0xbbU, 0xccU, 0xddU, 0xeeU, 0xffU};
    id.bluetooth_transport.mac_address.assign(mac, mac + 6);

    id.wireless_carplay_transport.enabled = true;
    id.wireless_carplay_transport.component_id = 3U;
    id.wireless_carplay_transport.name = "Wireless CarPlay";

    id.vehicle_information.enabled = true;
    id.vehicle_information.component_id = 1U;
    id.vehicle_information.name = "BMW F20";
    id.vehicle_information.display_name = "BMW 1 Series";
    id.vehicle_information.engine_types.push_back(0U);
    return id;
}

}  // namespace

TEST_CASE(identificationInformationEncodingAllFields) {
    iap2::IdentificationConfig cfg = makeFullIdentConfig();
    iap2::Frame frame;
    std::string err;
    REQUIRE(iap2::buildIdentificationInformation(cfg, frame, &err));
    CHECK_EQ(iap2::msg::kIdentificationInformation, frame.message_id);

    iap2::ParameterList root;
    REQUIRE(iap2::ParameterList::decode(frame.payload, root, &err));

    std::string s;
    CHECK(root.readString(iap2::param::kIdentName, s) && s == "BMW EntryNav2");
    CHECK(root.readString(iap2::param::kIdentModelIdentifier, s) && s == "HU_ENTRYNAV2");
    CHECK(root.readString(iap2::param::kIdentManufacturer, s) && s == "BMW");
    CHECK(root.readString(iap2::param::kIdentSerialNumber, s) && s == "F20-123456");
    CHECK(root.readString(iap2::param::kIdentFirmwareVersion, s) && s == "202402191339");
    CHECK(root.readString(iap2::param::kIdentHardwareVersion, s) && s == "HW-EVO-1");
    CHECK(root.readString(iap2::param::kIdentCurrentLanguage, s) && s == "en");

    std::vector<uint16_t> msgs;
    CHECK(root.readU16List(iap2::param::kIdentMessagesSentByAccessory, msgs));
    CHECK_EQ(2U, msgs.size());
    CHECK(root.readU16List(iap2::param::kIdentMessagesReceivedFromDevice, msgs));
    CHECK_EQ(2U, msgs.size());

    uint8_t pwr = 0;
    uint16_t cur = 99;
    CHECK(root.readU8(iap2::param::kIdentPowerProvidingCapability, pwr) && pwr == 2U);
    CHECK(root.readU16(iap2::param::kIdentMaxCurrentDrawnFromDevice, cur) && cur == 0U);

    // NUL-separated STRING_LIST in SupportedLanguage (param 13)
    std::vector<std::string> langs;
    REQUIRE(root.readStrings(iap2::param::kIdentSupportedLanguage, langs));
    REQUIRE(langs.size() == 3U);
    CHECK_EQ(std::string("en"), langs[0]);
    CHECK_EQ(std::string("tr"), langs[1]);
    CHECK_EQ(std::string("de"), langs[2]);

    // Transport & vehicle groups
    iap2::ParameterList grp;
    REQUIRE(root.readGroup(iap2::param::kIdentUsbDeviceTransportComponent, grp, &err));
    CHECK(grp.findFirst(iap2::param::kTransportSupportsIap2Connection) != NULL);

    REQUIRE(root.readGroup(iap2::param::kIdentBluetoothTransportComponent, grp, &err));
    Bytes mac;
    CHECK(grp.readBytes(iap2::param::kBtTransportMacAddress, mac) && mac.size() == 6U);

    REQUIRE(root.readGroup(iap2::param::kIdentWirelessCarPlayTransportComponent, grp, &err));
    CHECK_EQ(24U, iap2::param::kIdentWirelessCarPlayTransportComponent);
    uint16_t wireless_tid = 0;
    CHECK(grp.readU16(iap2::param::kWirelessCarPlayTransportIdentifier, wireless_tid));
    CHECK_EQ(1U, wireless_tid);
    CHECK(grp.findFirst(iap2::param::kWirelessCarPlayIsAvailable) != NULL);
    CHECK(grp.findFirst(iap2::param::kWirelessCarPlayIsEnabled) != NULL);

    REQUIRE(root.readGroup(iap2::param::kIdentVehicleInformationComponent, grp, &err));
    CHECK_EQ(6U, iap2::param::kVehicleInfoDisplayName);
    CHECK(grp.readString(iap2::param::kVehicleInfoDisplayName, s) && s == "BMW 1 Series");

    // Invalid BT MAC rejected.
    cfg.bluetooth_transport.mac_address.push_back(0x00U);
    CHECK(!iap2::buildIdentificationInformation(cfg, frame, &err));
}

TEST_CASE(fullLoopbackDetectSyncIdentAuthWifiConfig) {
    WireSink sink;
    FakeAuthProvider auth;
    RecordingSessionListener listener;
    iap2::SessionConfig cfg;
    cfg.identification = makeFullIdentConfig();
    iap2::Session session(sink, auth, listener, cfg);
    FakeDevice dev;

    // 1. Detect
    session.tick(0);
    session.start();
    CHECK_EQ(iap2::kSessionDetecting, session.state());
    dev.consumeFromAccessory(sink);
    REQUIRE(dev.detect_seen);

    dev.sendDetect();
    dev.flushToAccessory(session, sink);
    CHECK_EQ(iap2::kSessionSyncing, session.state());
    REQUIRE(dev.syn_seen);

    // 2. Link sync (max_packet_length=256 forces multi-packet split on 600B cert!)
    dev.sendSynAck();
    dev.flushToAccessory(session, sink);
    CHECK_EQ(iap2::kSessionConnected, session.state());
    CHECK_EQ(10U, session.controlSessionId());

    // 3. Identification: device sends StartIdentification (0x1D00)
    dev.sendControlFrame(iap2::msg::kStartIdentification);
    dev.flushToAccessory(session, sink);
    CHECK_EQ(iap2::kSessionIdentifying, session.state());
    REQUIRE(dev.received_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kIdentificationInformation, dev.received_frames[0].message_id);
    dev.received_frames.clear();

    dev.sendControlFrame(iap2::msg::kIdentificationAccepted);
    dev.flushToAccessory(session, sink);
    CHECK_EQ(iap2::kSessionIdentified, session.state());
    CHECK_EQ(1, listener.ident_accepted_count);
    CHECK(session.isIdentified());
    CHECK(!session.isReady());

    // 4. Authentication via FakeAuthProvider (certificate split across 3 link packets!)
    dev.sendControlFrame(iap2::msg::kRequestAuthenticationCertificate);
    dev.flushToAccessory(session, sink);
    CHECK_EQ(iap2::kSessionAuthenticating, session.state());
    REQUIRE(dev.received_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kAuthenticationCertificate, dev.received_frames[0].message_id);
    iap2::ParameterList cert_params;
    REQUIRE(iap2::ParameterList::decode(dev.received_frames[0].payload, cert_params));
    Bytes got_cert;
    REQUIRE(cert_params.readBytes(iap2::param::kAuthCertificateData, got_cert));
    CHECK_BYTES_EQ(auth.cert, got_cert);
    dev.received_frames.clear();

    const Bytes challenge = test_support::hexToBytes("0102030405060708090a0b0c0d0e0f10");
    iap2::ParameterList ch_params;
    ch_params.addRaw(iap2::param::kAuthChallengeData, challenge);
    dev.sendControlFrame(iap2::msg::kRequestAuthenticationChallengeResponse, ch_params);
    dev.flushToAccessory(session, sink);
    REQUIRE(dev.received_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kAuthenticationResponse, dev.received_frames[0].message_id);
    iap2::ParameterList sig_params;
    REQUIRE(iap2::ParameterList::decode(dev.received_frames[0].payload, sig_params));
    Bytes got_sig;
    REQUIRE(sig_params.readBytes(iap2::param::kAuthChallengeResponseData, got_sig));
    CHECK_EQ(challenge.size(), got_sig.size());
    CHECK_EQ(static_cast<uint8_t>(0x01U ^ 0x5aU), got_sig[0]);
    dev.received_frames.clear();

    dev.sendControlFrame(iap2::msg::kAuthenticationSucceeded);
    dev.flushToAccessory(session, sink);
    CHECK_EQ(iap2::kSessionReady, session.state());
    CHECK(session.isReady());
    CHECK(session.isAuthenticated());
    CHECK_EQ(1, listener.auth_succeeded_count);
    CHECK_EQ(1, listener.ready_count);

    // 5. Post-auth: CarPlayAvailability (0x4300)
    iap2::ParameterList wired_grp;
    wired_grp.addU8(0, 1);
    wired_grp.addString(1, "00:11:22:33:44:55");
    iap2::ParameterList cp_avail;
    cp_avail.addGroup(0, wired_grp);
    dev.sendControlFrame(iap2::msg::kCarPlayAvailability, cp_avail);
    dev.flushToAccessory(session, sink);
    REQUIRE(listener.availabilities.size() == 1U);
    CHECK(listener.availabilities[0].wired.present && listener.availabilities[0].wired.available);
    CHECK_EQ(std::string("00:11:22:33:44:55"), listener.availabilities[0].wired.identifier);

    // WirelessCarPlayUpdate (0x4E0D)
    iap2::ParameterList wcp;
    wcp.addU8(0, 1);
    dev.sendControlFrame(iap2::msg::kWirelessCarPlayUpdate, wcp);
    dev.flushToAccessory(session, sink);
    REQUIRE(listener.wireless_updates.size() == 1U);
    CHECK(listener.wireless_updates[0]);

    // DeviceTransportIdentifierNotification (0x4E0E)
    iap2::ParameterList tid;
    tid.addString(0, "AA:BB:CC:DD:EE:FF");
    dev.sendControlFrame(iap2::msg::kDeviceTransportIdentifier, tid);
    dev.flushToAccessory(session, sink);
    REQUIRE(listener.transport_ids.size() == 1U);
    CHECK_EQ(std::string("AA:BB:CC:DD:EE:FF"), listener.transport_ids[0].bluetooth_mac);

    // Accessory sends StartPowerUpdates (0xAE00) -> Device sends PowerUpdate (0xAE01) -> sendPowerSourceUpdate (0xAE03)
    REQUIRE(session.sendStartPowerUpdates());
    dev.flushToAccessory(session, sink);
    CHECK(session.powerUpdatesActive());
    REQUIRE(dev.received_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kStartPowerUpdates, dev.received_frames[0].message_id);
    dev.received_frames.clear();

    iap2::ParameterList pwr_upd;
    pwr_upd.addU16(4, 1000U);
    dev.sendControlFrame(iap2::msg::kPowerUpdate, pwr_upd);
    dev.flushToAccessory(session, sink);
    CHECK_EQ(1U, listener.power_update_frames.size());

    REQUIRE(session.sendPowerSourceUpdate(2400U, true, true));
    dev.flushToAccessory(session, sink);
    REQUIRE(dev.received_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kPowerSourceUpdate, dev.received_frames[0].message_id);
    dev.received_frames.clear();

    // RequestAccessoryWiFiConfiguration (0x5702) -> 0x5703 response!
    dev.sendControlFrame(iap2::msg::kRequestAccessoryWiFiConfiguration);
    dev.flushToAccessory(session, sink);
    CHECK_EQ(1, listener.wifi_requests);
    REQUIRE(dev.received_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kAccessoryWiFiConfiguration, dev.received_frames[0].message_id);
    iap2::ParameterList wifi_resp;
    REQUIRE(iap2::ParameterList::decode(dev.received_frames[0].payload, wifi_resp));
    std::string ssid, pass;
    uint8_t sec = 0, ch = 0;
    Bytes bssid;
    CHECK(wifi_resp.readBytes(0, bssid) && bssid.size() == 6U);
    CHECK(wifi_resp.readString(1, ssid) && ssid == "BMW-CarPlay-AP");
    CHECK(wifi_resp.readString(2, pass) && pass == "secret-passphrase");
    CHECK(wifi_resp.readU8(3, sec) && sec == 3U);
    CHECK(wifi_resp.readU8(4, ch) && ch == 36U);
    dev.received_frames.clear();

    // RequestWiFiInformation (0x5700) -> WiFiInformation (0x5701)
    REQUIRE(session.requestWiFiInformation());
    dev.flushToAccessory(session, sink);
    REQUIRE(dev.received_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kRequestWiFiInformation, dev.received_frames[0].message_id);
    dev.received_frames.clear();

    iap2::ParameterList winfo;
    winfo.addU8(0, 0);
    winfo.addU8(1, 3);
    winfo.addString(2, "iPhone-Hotspot");
    winfo.addString(3, "pw");
    dev.sendControlFrame(iap2::msg::kWiFiInformation, winfo);
    dev.flushToAccessory(session, sink);
    REQUIRE(listener.wifi_infos.size() == 1U);
    CHECK(listener.wifi_infos[0].ok());
    CHECK_EQ(std::string("iPhone-Hotspot"), listener.wifi_infos[0].ssid);

    // StartCarPlaySession (0x4301)
    iap2::StartSessionConfig cp_cfg;
    cp_cfg.wireless_ssid = "BMW-CarPlay-AP";
    cp_cfg.wireless_passphrase = "secret-passphrase";
    cp_cfg.has_wireless_channel = true;
    cp_cfg.wireless_channel = 36;
    cp_cfg.has_airplay_port = true;
    cp_cfg.airplay_port = 7000;
    REQUIRE(session.sendStartCarPlaySession(cp_cfg));
    dev.flushToAccessory(session, sink);
    REQUIRE(dev.received_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kCarPlayStartSession, dev.received_frames[0].message_id);
    CHECK(listener.errors.empty());
}

TEST_CASE(standardOrderAuthBeforeIdentAndPrematurePostAuthBlocked) {
    WireSink sink;
    FakeAuthProvider auth;
    RecordingSessionListener listener;
    iap2::SessionConfig cfg;
    cfg.identification = makeFullIdentConfig();
    iap2::Session session(sink, auth, listener, cfg);
    FakeDevice dev;

    session.start();
    dev.consumeFromAccessory(sink);
    dev.sendDetect();
    dev.flushToAccessory(session, sink);
    dev.sendSynAck();
    dev.flushToAccessory(session, sink);
    CHECK_EQ(iap2::kSessionConnected, session.state());

    // Premature 0x5702 before auth+ident must NOT disclose Wi-Fi credentials!
    dev.sendControlFrame(iap2::msg::kRequestAccessoryWiFiConfiguration);
    dev.flushToAccessory(session, sink);
    CHECK_EQ(0, listener.wifi_requests);
    CHECK(dev.received_frames.empty());
    CHECK(!listener.errors.empty());
    listener.errors.clear();

    // Auth first.
    dev.sendControlFrame(iap2::msg::kRequestAuthenticationCertificate);
    dev.flushToAccessory(session, sink);
    iap2::ParameterList ch;
    ch.addRaw(iap2::param::kAuthChallengeData, Bytes(16, 0x11U));
    dev.sendControlFrame(iap2::msg::kRequestAuthenticationChallengeResponse, ch);
    dev.flushToAccessory(session, sink);
    dev.sendControlFrame(iap2::msg::kAuthenticationSucceeded);
    dev.flushToAccessory(session, sink);
    CHECK_EQ(iap2::kSessionAuthenticated, session.state());
    CHECK(!session.isReady());

    // Then Identification.
    dev.sendControlFrame(iap2::msg::kStartIdentification);
    dev.flushToAccessory(session, sink);
    dev.sendControlFrame(iap2::msg::kIdentificationAccepted);
    dev.flushToAccessory(session, sink);
    CHECK_EQ(iap2::kSessionReady, session.state());
    CHECK_EQ(1, listener.ready_count);
    dev.received_frames.clear();

    // Now 0x5702 succeeds.
    dev.sendControlFrame(iap2::msg::kRequestAccessoryWiFiConfiguration);
    dev.flushToAccessory(session, sink);
    CHECK_EQ(1, listener.wifi_requests);
    REQUIRE(dev.received_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kAccessoryWiFiConfiguration, dev.received_frames[0].message_id);
}

TEST_CASE(failurePathsAuthIdentRejectTimeoutAndReset) {
    // 1. AuthProvider::getCertificate fails.
    {
        WireSink sink;
        FakeAuthProvider auth;
        auth.fail_cert = true;
        RecordingSessionListener listener;
        iap2::Session session(sink, auth, listener);
        FakeDevice dev;
        session.start();
        dev.consumeFromAccessory(sink);
        dev.sendDetect();
        dev.flushToAccessory(session, sink);
        dev.sendSynAck();
        dev.flushToAccessory(session, sink);

        dev.sendControlFrame(iap2::msg::kRequestAuthenticationCertificate);
        dev.flushToAccessory(session, sink);
        CHECK_EQ(iap2::kSessionFailed, session.state());
        CHECK_EQ(1U, listener.auth_failures.size());
    }

    // 2. AuthProvider::signChallenge fails.
    {
        WireSink sink;
        FakeAuthProvider auth;
        auth.fail_sign = true;
        RecordingSessionListener listener;
        iap2::Session session(sink, auth, listener);
        FakeDevice dev;
        session.start();
        dev.consumeFromAccessory(sink);
        dev.sendDetect();
        dev.flushToAccessory(session, sink);
        dev.sendSynAck();
        dev.flushToAccessory(session, sink);

        dev.sendControlFrame(iap2::msg::kRequestAuthenticationCertificate);
        dev.flushToAccessory(session, sink);
        iap2::ParameterList ch;
        ch.addRaw(iap2::param::kAuthChallengeData, Bytes(8, 0x22U));
        dev.sendControlFrame(iap2::msg::kRequestAuthenticationChallengeResponse, ch);
        dev.flushToAccessory(session, sink);
        CHECK_EQ(iap2::kSessionFailed, session.state());
        CHECK_EQ(1U, listener.auth_failures.size());
    }

    // 3. Device sends AuthenticationFailed (0xAA04).
    {
        WireSink sink;
        FakeAuthProvider auth;
        RecordingSessionListener listener;
        iap2::Session session(sink, auth, listener);
        FakeDevice dev;
        session.start();
        dev.consumeFromAccessory(sink);
        dev.sendDetect();
        dev.flushToAccessory(session, sink);
        dev.sendSynAck();
        dev.flushToAccessory(session, sink);

        dev.sendControlFrame(iap2::msg::kRequestAuthenticationCertificate);
        dev.flushToAccessory(session, sink);
        dev.sendControlFrame(iap2::msg::kAuthenticationFailed);
        dev.flushToAccessory(session, sink);
        CHECK_EQ(iap2::kSessionFailed, session.state());
        CHECK_EQ(1U, listener.auth_failures.size());
    }

    // 4. Device sends IdentificationRejected (0x1D03).
    {
        WireSink sink;
        FakeAuthProvider auth;
        RecordingSessionListener listener;
        iap2::Session session(sink, auth, listener);
        FakeDevice dev;
        session.start();
        dev.consumeFromAccessory(sink);
        dev.sendDetect();
        dev.flushToAccessory(session, sink);
        dev.sendSynAck();
        dev.flushToAccessory(session, sink);

        dev.sendControlFrame(iap2::msg::kStartIdentification);
        dev.flushToAccessory(session, sink);

        iap2::ParameterList rej;
        rej.addVoid(iap2::param::kIdentSerialNumber);
        dev.sendControlFrame(iap2::msg::kIdentificationRejected, rej);
        dev.flushToAccessory(session, sink);
        CHECK_EQ(iap2::kSessionFailed, session.state());
        REQUIRE(listener.ident_rejections.size() == 1U);
        REQUIRE(listener.ident_rejections[0].size() == 1U);
        CHECK_EQ(iap2::param::kIdentSerialNumber, listener.ident_rejections[0][0]);
    }

    // 5. Detect timeout & Auth timeout via fake clock tick(now_ms).
    {
        WireSink sink;
        FakeAuthProvider auth;
        RecordingSessionListener listener;
        iap2::SessionConfig cfg;
        cfg.detect_timeout_ms = 2500U;
        cfg.link.detect_interval_ms = 1000U;
        cfg.link.max_detect_attempts = 10U;
        iap2::Session session(sink, auth, listener, cfg);
        session.tick(0);
        session.start();
        session.tick(2499);
        CHECK_EQ(iap2::kSessionDetecting, session.state());
        session.tick(2500);
        CHECK_EQ(iap2::kSessionFailed, session.state());
        CHECK(!listener.errors.empty());
    }

    {
        WireSink sink;
        FakeAuthProvider auth;
        RecordingSessionListener listener;
        iap2::SessionConfig cfg;
        cfg.authentication_timeout_ms = 3000U;
        iap2::Session session(sink, auth, listener, cfg);
        FakeDevice dev;
        session.tick(1000);
        session.start();
        dev.consumeFromAccessory(sink);
        dev.sendDetect();
        dev.flushToAccessory(session, sink);
        dev.sendSynAck();
        dev.flushToAccessory(session, sink);
        dev.sendControlFrame(iap2::msg::kRequestAuthenticationCertificate);
        dev.flushToAccessory(session, sink);
        CHECK_EQ(iap2::kSessionAuthenticating, session.state());

        session.tick(3999);
        CHECK_EQ(iap2::kSessionAuthenticating, session.state());
        session.tick(4000);
        CHECK_EQ(iap2::kSessionFailed, session.state());
        CHECK_EQ(1U, listener.auth_failures.size());
    }

    // 6. CancelIdentification + IdentificationInformationUpdate + Peer RST.
    {
        WireSink sink;
        FakeAuthProvider auth;
        RecordingSessionListener listener;
        iap2::SessionConfig cfg;
        cfg.identification = makeFullIdentConfig();
        iap2::Session session(sink, auth, listener, cfg);
        FakeDevice dev;
        session.start();
        dev.consumeFromAccessory(sink);
        dev.sendDetect();
        dev.flushToAccessory(session, sink);
        dev.sendSynAck();
        dev.flushToAccessory(session, sink);

        dev.sendControlFrame(iap2::msg::kStartIdentification);
        dev.flushToAccessory(session, sink);
        CHECK_EQ(iap2::kSessionIdentifying, session.state());

        dev.sendControlFrame(iap2::msg::kCancelIdentification);
        dev.flushToAccessory(session, sink);
        CHECK_EQ(iap2::kSessionConnected, session.state());

        // Re-identify and send update.
        dev.sendControlFrame(iap2::msg::kStartIdentification);
        dev.flushToAccessory(session, sink);
        dev.sendControlFrame(iap2::msg::kIdentificationAccepted);
        dev.flushToAccessory(session, sink);
        REQUIRE(session.sendIdentificationUpdate(cfg.identification));
        dev.flushToAccessory(session, sink);

        iap2::ParameterList upd;
        upd.addString(iap2::param::kIdentCurrentLanguage, "tr");
        dev.sendControlFrame(iap2::msg::kIdentificationInformationUpdate, upd);
        dev.flushToAccessory(session, sink);
        CHECK_EQ(1U, listener.ident_updates.size());

        // Peer RST fails active session.
        dev.sendRst();
        dev.flushToAccessory(session, sink);
        CHECK_EQ(iap2::kSessionFailed, session.state());
    }

    // 7. 0x1D03 retry omits unsupported messages once; refuses second rejection or auth msg rejection.
    {
        WireSink sink;
        FakeAuthProvider auth;
        RecordingSessionListener listener;
        iap2::SessionConfig cfg;
        cfg.identification = makeFullIdentConfig();
        iap2::Session session(sink, auth, listener, cfg);
        FakeDevice dev;
        session.start();
        dev.consumeFromAccessory(sink);
        dev.sendDetect();
        dev.flushToAccessory(session, sink);
        dev.sendSynAck();
        dev.flushToAccessory(session, sink);

        dev.sendControlFrame(iap2::msg::kStartIdentification);
        dev.flushToAccessory(session, sink);
        REQUIRE(dev.received_frames.size() == 1U);
        dev.received_frames.clear();

        // Reject CarPlay 0x4301 (sent) and 0x4300 (received) -> retry omitting them.
        iap2::ParameterList rej;
        std::vector<uint16_t> unsup_sent(1, iap2::msg::kCarPlayStartSession);
        std::vector<uint16_t> unsup_recv(1, iap2::msg::kCarPlayAvailability);
        rej.addU16List(iap2::param::kIdentMessagesSentByAccessory, unsup_sent);
        rej.addU16List(iap2::param::kIdentMessagesReceivedFromDevice, unsup_recv);
        dev.sendControlFrame(iap2::msg::kIdentificationRejected, rej);
        dev.flushToAccessory(session, sink);

        CHECK_EQ(iap2::kSessionIdentifying, session.state());
        REQUIRE(listener.ident_retries.size() == 1U);
        CHECK_EQ(2U, listener.ident_retries[0].size());
        REQUIRE(dev.received_frames.size() == 1U);
        CHECK_EQ(iap2::msg::kIdentificationInformation, dev.received_frames[0].message_id);

        iap2::ParameterList retried;
        REQUIRE(iap2::ParameterList::decode(dev.received_frames[0].payload, retried));
        std::vector<uint16_t> sent_list;
        std::vector<uint16_t> recv_list;
        CHECK(retried.readU16List(iap2::param::kIdentMessagesSentByAccessory, sent_list));
        CHECK(retried.readU16List(iap2::param::kIdentMessagesReceivedFromDevice, recv_list));
        CHECK_EQ(1U, sent_list.size());
        CHECK_EQ(iap2::msg::kAccessoryWiFiConfiguration, sent_list[0]);
        CHECK_EQ(1U, recv_list.size());
        CHECK_EQ(iap2::msg::kRequestAccessoryWiFiConfiguration, recv_list[0]);
        dev.received_frames.clear();

        // Second rejection must fail rather than looping forever.
        dev.sendControlFrame(iap2::msg::kIdentificationRejected, rej);
        dev.flushToAccessory(session, sink);
        CHECK_EQ(iap2::kSessionFailed, session.state());
        CHECK_EQ(1U, listener.ident_rejections.size());
    }
}

int main() {
    return test_support::runAll("test_iap2_session");
}
