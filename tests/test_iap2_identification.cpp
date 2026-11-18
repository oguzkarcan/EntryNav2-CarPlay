// Derived in part from DiPlay
// (shared/src/test/java/com/shilapi/xcertplay/transport/Iap2WirelessControlClientTest.kt,
//  shared/src/test/java/com/shilapi/xcertplay/transport/Iap2WiredControlClientTest.kt,
//  shared/src/test/java/com/shilapi/xcertplay/transport/Iap2IdentificationRetryTest.kt,
//  shared/src/test/java/com/shilapi/xcertplay/transport/Iap2WirelessLinkRoleTest.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.

#include "carplay/iap2_session.hpp"
#include "test_support.hpp"

#include <cstring>
#include <string>
#include <vector>

namespace iap2 = carplay::iap2;

typedef std::vector<uint8_t> Bytes;

namespace {

std::string bytesToHex(const Bytes& data) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2U);
    for (size_t i = 0; i < data.size(); ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0x0fU]);
        out.push_back(kHex[data[i] & 0x0fU]);
    }
    return out;
}

void appendU16Be(Bytes& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xffU));
    out.push_back(static_cast<uint8_t>(v & 0xffU));
}

void appendParamRaw(Bytes& out, uint16_t id, const Bytes& payload) {
    appendU16Be(out, static_cast<uint16_t>(4U + payload.size()));
    appendU16Be(out, id);
    out.insert(out.end(), payload.begin(), payload.end());
}

void appendParamStr(Bytes& out, uint16_t id, const std::string& s) {
    Bytes p(s.begin(), s.end());
    p.push_back(0U);
    appendParamRaw(out, id, p);
}

void appendParamU8(Bytes& out, uint16_t id, uint8_t v) {
    Bytes p(1U, v);
    appendParamRaw(out, id, p);
}

void appendParamU16(Bytes& out, uint16_t id, uint16_t v) {
    Bytes p;
    appendU16Be(p, v);
    appendParamRaw(out, id, p);
}

void appendParamVoid(Bytes& out, uint16_t id) {
    appendParamRaw(out, id, Bytes());
}

void appendParamU16List(Bytes& out, uint16_t id, const uint16_t* ids, size_t count) {
    Bytes p;
    for (size_t i = 0; i < count; ++i) {
        appendU16Be(p, ids[i]);
    }
    appendParamRaw(out, id, p);
}

Bytes wrapCsmFrame(uint16_t msg_id, const Bytes& payload) {
    Bytes frame;
    appendU16Be(frame, 0x4040U);
    appendU16Be(frame, static_cast<uint16_t>(6U + payload.size()));
    appendU16Be(frame, msg_id);
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

class FakeAuthProvider : public iap2::AuthProvider {
public:
    Bytes cert;
    uint8_t sig_xor;

    FakeAuthProvider() : sig_xor(0x5aU) {
        cert.resize(64U, 0x30U);
    }

    virtual bool getCertificate(Bytes& certificate_out) {
        certificate_out = cert;
        return true;
    }

    virtual bool signChallenge(const uint8_t* challenge,
                               size_t challenge_len,
                               Bytes& signature_out) {
        signature_out.resize(challenge_len);
        for (size_t i = 0; i < challenge_len; ++i) {
            signature_out[i] = static_cast<uint8_t>(challenge[i] ^ sig_xor);
        }
        return true;
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

class ScriptedPhone {
public:
    Bytes tx;
    std::vector<iap2::Frame> rx_frames;
    bool detect_seen;
    bool syn_seen;
    uint8_t dev_seq;
    uint8_t last_acc_seq;
    uint8_t session_id;
    iap2::SynPayload dev_syn;
    iap2::CsmFramer framer;

    explicit ScriptedPhone(bool zero_ack_mode)
        : detect_seen(false),
          syn_seen(false),
          dev_seq(50U),
          last_acc_seq(0U),
          session_id(iap2::kDefaultControlSessionId) {
        dev_syn.version = iap2::kLinkVersion;
        dev_syn.max_outstanding = 4U;
        dev_syn.max_packet_length = 4096U;
        if (zero_ack_mode) {
            dev_syn.retransmission_timeout_ms = 0U;
            dev_syn.cumulative_ack_timeout_ms = 0U;
            dev_syn.max_retransmissions = 0U;
            dev_syn.max_cumulative_acks = 0U;
        } else {
            dev_syn.retransmission_timeout_ms = 4000U;
            dev_syn.cumulative_ack_timeout_ms = 500U;
            dev_syn.max_retransmissions = 4U;
            dev_syn.max_cumulative_acks = 3U;
        }
        dev_syn.sessions.push_back(iap2::SynSession(
            iap2::kDefaultControlSessionId,
            iap2::kSessionTypeControl,
            iap2::kDefaultControlSessionVersion));
        dev_syn.sessions.push_back(iap2::SynSession(
            iap2::kDefaultEaSessionId,
            iap2::kSessionTypeExternalAccessory,
            iap2::kDefaultEaSessionVersion));
        dev_syn.sessions.push_back(iap2::SynSession(
            iap2::kDefaultFileTransferSessionId,
            iap2::kSessionTypeFileTransfer,
            iap2::kDefaultFileTransferSessionVersion));
    }

    void consume(WireSink& sink) {
        Bytes& buf = sink.out;
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
                if ((pkt.control & iap2::kCtrlSyn) != 0U) {
                    syn_seen = true;
                    last_acc_seq = pkt.seq;
                } else if (!pkt.payload.empty()) {
                    last_acc_seq = pkt.seq;
                    REQUIRE(framer.push(&pkt.payload[0], pkt.payload.size(), rx_frames));
                    if (dev_syn.max_retransmissions > 0U) {
                        sendAck();
                    }
                }
                continue;
            }
            REQUIRE(false);
        }
        buf.clear();
    }

    void sendDetect() {
        tx.insert(tx.end(),
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
        tx.insert(tx.end(), raw.begin(), raw.end());
    }

    void sendAck() {
        iap2::LinkPacket pkt;
        pkt.control = iap2::kCtrlAck;
        pkt.seq = dev_seq;
        pkt.ack = last_acc_seq;
        pkt.session_id = 0U;
        Bytes raw;
        REQUIRE(pkt.encode(raw));
        tx.insert(tx.end(), raw.begin(), raw.end());
    }

    void sendFrame(uint16_t msg_id, const iap2::ParameterList& params = iap2::ParameterList()) {
        iap2::Frame f;
        REQUIRE(iap2::Frame::build(msg_id, params, f));
        Bytes csm;
        REQUIRE(f.encode(csm));
        dev_seq = static_cast<uint8_t>(dev_seq + 1U);
        iap2::LinkPacket pkt;
        pkt.control = iap2::kCtrlAck;
        pkt.seq = dev_seq;
        pkt.ack = last_acc_seq;
        pkt.session_id = session_id;
        pkt.payload = csm;
        Bytes raw;
        REQUIRE(pkt.encode(raw));
        tx.insert(tx.end(), raw.begin(), raw.end());
    }

    void exchange(iap2::Session& session, WireSink& sink) {
        int guard = 0;
        while (!tx.empty() || !sink.out.empty()) {
            REQUIRE(++guard < 64);
            if (!tx.empty()) {
                Bytes batch = tx;
                tx.clear();
                REQUIRE(session.feed(batch));
            }
            if (!sink.out.empty()) {
                consume(sink);
            }
        }
    }
};

class ScriptedListener : public iap2::SessionListener {
public:
    int ready_count;
    std::vector<std::vector<uint16_t> > retries;
    std::vector<bool> wireless_avail;
    std::vector<iap2::DeviceTransportIdentifier> transport_ids;
    std::vector<iap2::CarPlayAvailability> carplay_avail;
    std::vector<std::string> errors;

    ScriptedListener() : ready_count(0) {}

    virtual void onReady() { ++ready_count; }
    virtual void onIdentificationRetry(const std::vector<uint16_t>& omitted) {
        retries.push_back(omitted);
    }
    virtual void onWirelessCarPlayAvailability(bool avail) {
        wireless_avail.push_back(avail);
    }
    virtual void onDeviceTransportIdentifier(const iap2::DeviceTransportIdentifier& id) {
        transport_ids.push_back(id);
    }
    virtual void onCarPlayAvailability(const iap2::CarPlayAvailability& availability) {
        carplay_avail.push_back(availability);
    }
    virtual void onError(const std::string& msg) { errors.push_back(msg); }
};

iap2::StartSessionConfig makeWirelessEndpointCfg() {
    iap2::StartSessionConfig cfg;
    cfg.wireless_ssid = "LIVI";
    cfg.wireless_passphrase = "secret123";
    cfg.has_wireless_passphrase = true;
    cfg.has_wireless_channel = true;
    cfg.wireless_channel = 36U;
    cfg.has_wireless_security_type = true;
    cfg.wireless_security_type = iap2::kWirelessSecurityWpa3Transition;
    cfg.wireless_ips.push_back("192.168.2.1");
    cfg.has_airplay_port = true;
    cfg.airplay_port = 49152U;
    cfg.device_identifier = "dev-1";
    cfg.public_key = "aabbcc";
    cfg.source_version = "1.0";
    return cfg;
}

}  // namespace

TEST_CASE(goldenVectorsFromDiPlay) {
    // 1. 0x5703 AccessoryWiFiConfiguration golden vector (Iap2WirelessControlClientTest.kt:53-56)
    {
        iap2::Frame frame;
        REQUIRE(iap2::buildAccessoryWiFiConfiguration(
            "LIVI", "secret123", 36U, iap2::kWirelessSecurityWpa3Transition, NULL, frame));
        Bytes encoded;
        REQUIRE(frame.encode(encoded));
        CHECK_EQ(
            std::string("404000275703000900014c49564900000e00027365637265743132330000050003030005000424"),
            bytesToHex(encoded));
    }

    // 2. Wireless 0x4301 CarPlayStartSession golden vector (Iap2WirelessControlClientTest.kt:63-67)
    {
        iap2::Frame frame;
        REQUIRE(iap2::buildStartCarPlaySession(makeWirelessEndpointCfg(), frame));
        Bytes encoded;
        REQUIRE(frame.encode(encoded));
        CHECK_EQ(
            std::string("40400060430100350001000900004c49564900000e000173656372657431323300000500022400100003"
                        "3139322e3136382e322e31000005000403000800020000c000000a00036465762d3100000b000461"
                        "61626263630000080005312e3000"),
            bytesToHex(encoded));
    }

    // 3. Open network encodes empty NUL passphrase in both 0x5703 and 0x4301 (Iap2WirelessControlClientTest.kt:164-174)
    {
        iap2::Frame wifi_frame;
        REQUIRE(iap2::buildAccessoryWiFiConfiguration(
            "Guest", "", 36U, iap2::kWirelessSecurityNone, NULL, wifi_frame));
        iap2::ParameterList wifi_params;
        REQUIRE(iap2::ParameterList::decode(wifi_frame.payload, wifi_params));
        std::string pass;
        uint8_t sec = 99U;
        CHECK(wifi_params.readString(2U, pass) && pass.empty());
        CHECK(wifi_params.readU8(3U, sec) && sec == 0U);

        iap2::StartSessionConfig open_cfg;
        open_cfg.wireless_ssid = "Guest";
        open_cfg.wireless_passphrase = "";
        open_cfg.has_wireless_passphrase = false;
        open_cfg.has_wireless_channel = true;
        open_cfg.wireless_channel = 36U;
        open_cfg.has_wireless_security_type = true;
        open_cfg.wireless_security_type = iap2::kWirelessSecurityNone;
        open_cfg.wireless_ips.push_back("fe80::1234");
        open_cfg.has_airplay_port = true;
        open_cfg.airplay_port = 7000U;
        open_cfg.device_identifier = "dev-1";
        open_cfg.public_key = "aabbcc";
        open_cfg.source_version = "1.0";

        iap2::Frame cp_frame;
        REQUIRE(iap2::buildStartCarPlaySession(open_cfg, cp_frame));
        iap2::ParameterList cp_params;
        REQUIRE(iap2::ParameterList::decode(cp_frame.payload, cp_params));
        iap2::ParameterList wireless_grp;
        REQUIRE(cp_params.readGroup(1U, wireless_grp));
        CHECK(wireless_grp.readString(1U, pass) && pass.empty());
        CHECK(wireless_grp.readU8(4U, sec) && sec == 0U);
    }

    // 4. Five standard subscriptions match DiPlay Iap2Messages.kt:278-313
    {
        std::vector<iap2::Frame> subs;
        REQUIRE(iap2::buildStandardSubscriptions(subs));
        REQUIRE(subs.size() == 5U);
        CHECK_EQ(iap2::msg::kStartNowPlayingUpdates, subs[0].message_id);
        CHECK_EQ(iap2::msg::kStartRouteGuidanceUpdates, subs[1].message_id);
        CHECK_EQ(iap2::msg::kStartPowerUpdates, subs[2].message_id);
        CHECK_EQ(iap2::msg::kStartCommunicationsUpdates, subs[3].message_id);
        CHECK_EQ(iap2::msg::kStartCallStateUpdates, subs[4].message_id);

        iap2::ParameterList rg;
        REQUIRE(iap2::ParameterList::decode(subs[1].payload, rg));
        uint16_t rg_id = 0;
        CHECK(rg.readU16(0U, rg_id) && rg_id == 42U);
    }
}

TEST_CASE(identificationGoldenByteVectorsWiredAndWireless) {
    // 1. Wired USB preset golden byte vector (DiPlay Iap2IdentificationClient.kt)
    {
        const iap2::IdentificationConfig cfg = iap2::IdentificationConfig::wiredUsb(
            "LIVI", "LIVI", "LIVI", "0123456", "1.0.0", "1.0", 4U);
        iap2::Frame frame;
        REQUIRE(iap2::buildIdentificationInformation(cfg, frame));
        Bytes actual;
        REQUIRE(frame.encode(actual));

        // Independently construct expected DiPlay wire layout byte-for-byte.
        Bytes body;
        appendParamStr(body, 0U, "LIVI");
        appendParamStr(body, 1U, "LIVI");
        appendParamStr(body, 2U, "LIVI");
        appendParamStr(body, 3U, "0123456");
        appendParamStr(body, 4U, "1.0.0");
        appendParamStr(body, 5U, "1.0");
        const uint16_t sent[] = {
            0xaa01U, 0xaa03U, 0x5000U, 0x5002U, 0x5200U, 0x5203U, 0xae00U,
            0xae02U, 0x4157U, 0x4159U, 0x4154U, 0x4156U, 0xae03U, 0x4301U
        };
        appendParamU16List(body, 6U, sent, sizeof(sent) / sizeof(sent[0]));
        const uint16_t recvd[] = {
            0xaa00U, 0xaa02U, 0xaa04U, 0xaa05U, 0xea00U, 0xea01U, 0x5001U,
            0x5201U, 0x5202U, 0x5204U, 0xae01U, 0x4158U, 0x4155U, 0x4300U
        };
        appendParamU16List(body, 7U, recvd, sizeof(recvd) / sizeof(recvd[0]));
        appendParamU8(body, 8U, 2U);
        appendParamU16(body, 9U, 20U);

        Bytes ea;
        appendParamU8(ea, 0U, 1U);
        appendParamStr(ea, 1U, "com.shilapi.xcertplay");
        appendParamU8(ea, 2U, 0U);
        appendParamRaw(body, 10U, ea);

        appendParamStr(body, 12U, "en");
        appendParamStr(body, 13U, "en");

        Bytes usb;
        appendParamU16(usb, 0U, 0U);
        appendParamStr(usb, 1U, "USBHostTransport");
        appendParamVoid(usb, 2U);
        appendParamU8(usb, 3U, 4U);
        appendParamVoid(usb, 4U);
        appendParamRaw(body, 16U, usb);

        Bytes rg;
        appendParamU16(rg, 0U, 42U);
        appendParamStr(rg, 1U, "RouteGuidance");
        appendParamU16(rg, 2U, 64U);
        appendParamU16(rg, 4U, 64U);
        appendParamU16(rg, 6U, 8U);
        appendParamU16(rg, 7U, 64U);
        appendParamU16(rg, 8U, 8U);
        appendParamRaw(body, 30U, rg);

        const Bytes expected = wrapCsmFrame(0x1d01U, body);
        CHECK_BYTES_EQ(expected, actual);
    }

    // 2. Wireless Bluetooth preset golden byte vector (DiPlay BLUETOOTH_BOOTSTRAP)
    {
        const uint8_t mac_arr[6] = {0xaaU, 0xbbU, 0xccU, 0xddU, 0xeeU, 0xffU};
        const Bytes mac(mac_arr, mac_arr + 6);
        const iap2::IdentificationConfig cfg = iap2::IdentificationConfig::wirelessBluetooth(
            "LIVI", "LIVI", "LIVI", "0123456", "1.0.0", "1.0", mac, "LIVI");
        iap2::Frame frame;
        REQUIRE(iap2::buildIdentificationInformation(cfg, frame));
        Bytes actual;
        REQUIRE(frame.encode(actual));

        Bytes body;
        appendParamStr(body, 0U, "LIVI");
        appendParamStr(body, 1U, "LIVI");
        appendParamStr(body, 2U, "LIVI");
        appendParamStr(body, 3U, "0123456");
        appendParamStr(body, 4U, "1.0.0");
        appendParamStr(body, 5U, "1.0");
        const uint16_t sent[] = {
            0xaa01U, 0xaa03U, 0x5000U, 0x5002U, 0x5200U, 0x5203U, 0xae00U,
            0xae02U, 0x4157U, 0x4159U, 0x4154U, 0x4156U, 0x4301U, 0x5703U
        };
        appendParamU16List(body, 6U, sent, sizeof(sent) / sizeof(sent[0]));
        const uint16_t recvd[] = {
            0xaa00U, 0xaa02U, 0xaa04U, 0xaa05U, 0xea00U, 0xea01U, 0x5001U,
            0x5201U, 0x5202U, 0x5204U, 0xae01U, 0x4158U, 0x4155U, 0x4300U,
            0x4e0dU, 0x4e0eU, 0x5702U
        };
        appendParamU16List(body, 7U, recvd, sizeof(recvd) / sizeof(recvd[0]));
        appendParamU8(body, 8U, 0U);
        appendParamU16(body, 9U, 20U);

        Bytes ea;
        appendParamU8(ea, 0U, 1U);
        appendParamStr(ea, 1U, "com.shilapi.xcertplay");
        appendParamU8(ea, 2U, 0U);
        appendParamRaw(body, 10U, ea);

        appendParamStr(body, 12U, "en");
        appendParamStr(body, 13U, "en");

        Bytes bt;
        appendParamU16(bt, 0U, 0U);
        appendParamStr(bt, 1U, "blue");
        appendParamVoid(bt, 2U);
        appendParamRaw(bt, 3U, mac);
        appendParamStr(bt, 4U, "blue");
        appendParamVoid(bt, 5U);
        appendParamRaw(body, 17U, bt);

        Bytes wcp;
        appendParamU16(wcp, 0U, 1U);
        appendParamStr(wcp, 1U, "LIVI");
        appendParamVoid(wcp, 2U);
        appendParamU16(wcp, 3U, 1U);
        appendParamVoid(wcp, 4U);
        appendParamVoid(wcp, 5U);
        appendParamRaw(body, 24U, wcp);

        Bytes rg;
        appendParamU16(rg, 0U, 42U);
        appendParamStr(rg, 1U, "RouteGuidance");
        appendParamU16(rg, 2U, 64U);
        appendParamU16(rg, 4U, 64U);
        appendParamU16(rg, 6U, 8U);
        appendParamU16(rg, 7U, 64U);
        appendParamU16(rg, 8U, 8U);
        appendParamRaw(body, 30U, rg);

        const Bytes expected = wrapCsmFrame(0x1d01U, body);
        CHECK_BYTES_EQ(expected, actual);
    }

    // 3. Runtime tunnel preset permits Location & VehicleStatus unlike Bluetooth bootstrap
    {
        const uint8_t mac_arr[6] = {0xaaU, 0xbbU, 0xccU, 0xddU, 0xeeU, 0xffU};
        const Bytes mac(mac_arr, mac_arr + 6);
        const iap2::IdentificationConfig tun = iap2::IdentificationConfig::wirelessRuntimeTunnel(
            "BMW", "EVO", "BMW", "123", "1.0", "1.0", mac, "BMW-WiFi", "en",
            "com.shilapi.xcertplay", true, true, true);
        iap2::Frame frame;
        REQUIRE(iap2::buildIdentificationInformation(tun, frame));
        iap2::ParameterList root;
        REQUIRE(iap2::ParameterList::decode(frame.payload, root));
        iap2::ParameterList grp;
        CHECK(root.readGroup(iap2::param::kIdentVehicleInformationComponent, grp));
        CHECK(root.readGroup(iap2::param::kIdentVehicleStatusComponent, grp));
        CHECK(root.readGroup(iap2::param::kIdentLocationInformationComponent, grp));
        CHECK(grp.findFirst(iap2::param::kLocationVehicleSpeed) != NULL);
    }
}

TEST_CASE(scriptedWiredCarPlayFlow) {
    WireSink sink;
    FakeAuthProvider auth;
    ScriptedListener listener;
    const iap2::IdentificationConfig ident = iap2::IdentificationConfig::wiredUsb(
        "BMW", "HU_ENTRYNAV2", "BMW", "S1", "1.0", "1.0", 4U);
    iap2::StartSessionConfig cp_cfg;
    cp_cfg.wired_ipv6_addresses.push_back("fe80::2");
    cp_cfg.has_airplay_port = true;
    cp_cfg.airplay_port = 7000U;
    cp_cfg.device_identifier = "02:00:00:00:00:02";
    cp_cfg.public_key = "abcd";
    cp_cfg.source_version = "1.0";

    const iap2::SessionConfig cfg = iap2::SessionConfig::wiredUsb(ident, 2400U, &cp_cfg);
    iap2::Session session(sink, auth, listener, cfg);
    ScriptedPhone phone(true);

    // Link starts immediately with detect + SYN in wired zero-ack mode.
    session.start();
    phone.consume(sink);
    REQUIRE(phone.detect_seen);
    REQUIRE(phone.syn_seen);

    phone.sendSynAck();
    phone.exchange(session, sink);
    CHECK_EQ(iap2::kSessionConnected, session.state());

    // Identification & Auth
    phone.sendFrame(iap2::msg::kStartIdentification);
    phone.exchange(session, sink);
    REQUIRE(phone.rx_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kIdentificationInformation, phone.rx_frames[0].message_id);
    phone.rx_frames.clear();

    phone.sendFrame(iap2::msg::kIdentificationAccepted);
    phone.exchange(session, sink);

    phone.sendFrame(iap2::msg::kRequestAuthenticationCertificate);
    phone.exchange(session, sink);
    iap2::ParameterList ch;
    ch.addRaw(iap2::param::kAuthChallengeData, Bytes(16, 0x44U));
    phone.sendFrame(iap2::msg::kRequestAuthenticationChallengeResponse, ch);
    phone.exchange(session, sink);
    phone.rx_frames.clear();

    // AuthenticationSucceeded -> automatically sends PowerSourceUpdate (0xAE03) + 5 subscriptions!
    phone.sendFrame(iap2::msg::kAuthenticationSucceeded);
    phone.exchange(session, sink);
    CHECK(session.isReady());
    CHECK_EQ(1, listener.ready_count);
    CHECK_EQ(iap2::kWirelessStageSubscribed, session.wirelessStatus().stage);

    REQUIRE(phone.rx_frames.size() == 6U);
    CHECK_EQ(iap2::msg::kPowerSourceUpdate, phone.rx_frames[0].message_id);
    CHECK_EQ(iap2::msg::kStartNowPlayingUpdates, phone.rx_frames[1].message_id);
    CHECK_EQ(iap2::msg::kStartRouteGuidanceUpdates, phone.rx_frames[2].message_id);
    CHECK_EQ(iap2::msg::kStartPowerUpdates, phone.rx_frames[3].message_id);
    CHECK_EQ(iap2::msg::kStartCommunicationsUpdates, phone.rx_frames[4].message_id);
    CHECK_EQ(iap2::msg::kStartCallStateUpdates, phone.rx_frames[5].message_id);
    phone.rx_frames.clear();

    // Phone sends 0x4300 -> Session automatically answers with wired 0x4301!
    iap2::ParameterList wired_grp;
    wired_grp.addU8(0, 1);
    iap2::ParameterList avail;
    avail.addGroup(0, wired_grp);
    phone.sendFrame(iap2::msg::kCarPlayAvailability, avail);
    phone.exchange(session, sink);

    REQUIRE(phone.rx_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kCarPlayStartSession, phone.rx_frames[0].message_id);
    CHECK_EQ(1U, session.wirelessStatus().carplay_start_sessions_sent);
    CHECK_EQ(iap2::kWirelessStageCarPlayStartSent, session.wirelessStatus().stage);
    CHECK(listener.errors.empty());
}

TEST_CASE(scriptedWirelessBluetoothCarPlayFlow) {
    WireSink sink;
    FakeAuthProvider auth;
    ScriptedListener listener;

    const uint8_t mac_arr[6] = {0xaaU, 0xbbU, 0xccU, 0xddU, 0xeeU, 0xffU};
    const Bytes mac(mac_arr, mac_arr + 6);
    const iap2::IdentificationConfig ident = iap2::IdentificationConfig::wirelessBluetooth(
        "LIVI", "LIVI", "LIVI", "0123456", "1.0.0", "1.0", mac, "LIVI");

    iap2::WiFiConfiguration wifi_cfg;
    wifi_cfg.ssid = "LIVI";
    wifi_cfg.passphrase = "secret123";
    wifi_cfg.channel = 36U;
    wifi_cfg.security_type = iap2::kWirelessSecurityWpa3Transition;

    const iap2::StartSessionConfig cp_cfg = makeWirelessEndpointCfg();
    const iap2::SessionConfig cfg = iap2::SessionConfig::wirelessBluetooth(ident, &wifi_cfg, &cp_cfg);
    iap2::Session session(sink, auth, listener, cfg);
    ScriptedPhone phone(false);

    // 1. Wireless Bluetooth waits for peer detect before sending SYN.
    session.start();
    phone.consume(sink);
    CHECK(phone.detect_seen);
    CHECK(!phone.syn_seen);

    phone.sendDetect();
    phone.exchange(session, sink);
    CHECK(phone.syn_seen);

    phone.sendSynAck();
    phone.exchange(session, sink);
    CHECK_EQ(iap2::kSessionConnected, session.state());

    // 2. Identification with 0x1D03 unsupported-message retry (e.g. older iOS rejecting 0x5204 LaneGuidance)
    phone.sendFrame(iap2::msg::kStartIdentification);
    phone.exchange(session, sink);
    REQUIRE(phone.rx_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kIdentificationInformation, phone.rx_frames[0].message_id);
    phone.rx_frames.clear();

    iap2::ParameterList rej;
    std::vector<uint16_t> unsup(1, iap2::msg::kLaneGuidanceInfoUpdate);
    rej.addU16List(iap2::param::kIdentMessagesReceivedFromDevice, unsup);
    phone.sendFrame(iap2::msg::kIdentificationRejected, rej);
    phone.exchange(session, sink);
    REQUIRE(listener.retries.size() == 1U);
    CHECK_EQ(iap2::msg::kLaneGuidanceInfoUpdate, listener.retries[0][0]);
    REQUIRE(phone.rx_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kIdentificationInformation, phone.rx_frames[0].message_id);
    phone.rx_frames.clear();

    phone.sendFrame(iap2::msg::kIdentificationAccepted);
    phone.exchange(session, sink);
    CHECK_EQ(iap2::kWirelessStageIdentified, session.wirelessStatus().stage);

    // 3. Authentication
    phone.sendFrame(iap2::msg::kRequestAuthenticationCertificate);
    phone.exchange(session, sink);
    iap2::ParameterList ch;
    ch.addRaw(iap2::param::kAuthChallengeData, Bytes(16, 0x22U));
    phone.sendFrame(iap2::msg::kRequestAuthenticationChallengeResponse, ch);
    phone.exchange(session, sink);
    phone.rx_frames.clear();

    // 4. AuthenticationSucceeded -> proactively sends the 5 subscriptions!
    phone.sendFrame(iap2::msg::kAuthenticationSucceeded);
    phone.exchange(session, sink);
    CHECK(session.isReady());
    CHECK_EQ(1, listener.ready_count);
    CHECK_EQ(iap2::kWirelessStageSubscribed, session.wirelessStatus().stage);
    REQUIRE(phone.rx_frames.size() == 5U);
    CHECK_EQ(iap2::msg::kStartNowPlayingUpdates, phone.rx_frames[0].message_id);
    CHECK_EQ(iap2::msg::kStartRouteGuidanceUpdates, phone.rx_frames[1].message_id);
    CHECK_EQ(iap2::msg::kStartPowerUpdates, phone.rx_frames[2].message_id);
    CHECK_EQ(iap2::msg::kStartCommunicationsUpdates, phone.rx_frames[3].message_id);
    CHECK_EQ(iap2::msg::kStartCallStateUpdates, phone.rx_frames[4].message_id);
    phone.rx_frames.clear();

    // 5. Phone sends WirelessCarPlayUpdate (0x4E0D)
    iap2::ParameterList wcp;
    wcp.addU8(0U, 1U);
    phone.sendFrame(iap2::msg::kWirelessCarPlayUpdate, wcp);
    phone.exchange(session, sink);
    CHECK(session.wirelessStatus().wireless_carplay_available_seen);
    REQUIRE(listener.wireless_avail.size() == 1U);
    CHECK(listener.wireless_avail[0]);

    // 6. Phone requests Wi-Fi credentials (0x5702) -> Session replies with golden 0x5703;
    //    enforces pre-transport limit of 5 sends!
    for (int i = 0; i < 6; ++i) {
        phone.sendFrame(iap2::msg::kRequestAccessoryWiFiConfiguration);
    }
    phone.exchange(session, sink);
    CHECK_EQ(5U, session.wirelessStatus().pre_transport_wifi_configs_sent);
    CHECK_EQ(5U, session.wirelessStatus().wifi_configs_sent);
    CHECK_EQ(iap2::kWirelessStageWiFiConfigSent, session.wirelessStatus().stage);
    REQUIRE(phone.rx_frames.size() == 5U);
    Bytes first_5703;
    REQUIRE(phone.rx_frames[0].encode(first_5703));
    CHECK_EQ(
        std::string("404000275703000900014c49564900000e00027365637265743132330000050003030005000424"),
        bytesToHex(first_5703));
    phone.rx_frames.clear();

    // 7. Phone sends CarPlayAvailability (0x4300) -> Session proactively sends golden wireless 0x4301!
    iap2::ParameterList wireless_grp;
    wireless_grp.addU8(0U, 1U);
    iap2::ParameterList cp_avail;
    cp_avail.addGroup(1U, wireless_grp);
    phone.sendFrame(iap2::msg::kCarPlayAvailability, cp_avail);
    phone.exchange(session, sink);
    CHECK_EQ(1U, session.wirelessStatus().carplay_start_sessions_sent);
    CHECK_EQ(iap2::kWirelessStageCarPlayStartSent, session.wirelessStatus().stage);
    REQUIRE(phone.rx_frames.size() == 1U);
    Bytes sent_4301;
    REQUIRE(phone.rx_frames[0].encode(sent_4301));
    CHECK_EQ(
        std::string("40400060430100350001000900004c49564900000e000173656372657431323300000500022400100003"
                    "3139322e3136382e322e31000005000403000800020000c000000a00036465762d3100000b000461"
                    "61626263630000080005312e3000"),
        bytesToHex(sent_4301));
    phone.rx_frames.clear();

    // 8. Phone sends DeviceTransportIdentifier (0x4E0E) -> Session proactively resends 0x5703!
    //    Post-transport cap is 2 total (1 proactive + 1 from follow-up 0x5702).
    iap2::ParameterList tid;
    tid.addString(0U, "11:22:33:44:55:66");
    phone.sendFrame(iap2::msg::kDeviceTransportIdentifier, tid);
    phone.exchange(session, sink);
    CHECK(session.wirelessStatus().transport_notification_seen);
    CHECK_EQ(1U, session.wirelessStatus().post_transport_wifi_configs_sent);
    CHECK_EQ(iap2::kWirelessStagePostTransportWiFiConfigSent, session.wirelessStatus().stage);
    REQUIRE(phone.rx_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kAccessoryWiFiConfiguration, phone.rx_frames[0].message_id);
    phone.rx_frames.clear();

    phone.sendFrame(iap2::msg::kRequestAccessoryWiFiConfiguration);
    phone.sendFrame(iap2::msg::kRequestAccessoryWiFiConfiguration);
    phone.exchange(session, sink);
    CHECK_EQ(2U, session.wirelessStatus().post_transport_wifi_configs_sent);
    CHECK_EQ(7U, session.wirelessStatus().wifi_configs_sent);
    REQUIRE(phone.rx_frames.size() == 1U);
    CHECK_EQ(iap2::msg::kAccessoryWiFiConfiguration, phone.rx_frames[0].message_id);
    CHECK(listener.errors.empty());
}

int main() {
    return test_support::runAll("test_iap2_identification");
}
