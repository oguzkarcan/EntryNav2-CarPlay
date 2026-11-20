#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "carplay/auth_provider.hpp"
#include "carplay/iap2_session.hpp"
#include "carplay/iap2_wire.hpp"

namespace {

class FuzzByteSink : public carplay::iap2::ByteSink {
public:
    virtual bool sendBytes(const uint8_t* /*data*/, size_t /*len*/) { return true; }
};

class FuzzAuthProvider : public carplay::iap2::AuthProvider {
public:
    virtual bool getCertificate(std::vector<uint8_t>& certificate_out) {
        certificate_out.assign(16U, 0x30U);
        return true;
    }
    virtual bool signChallenge(const uint8_t* challenge,
                               size_t challenge_len,
                               std::vector<uint8_t>& signature_out) {
        if (challenge == NULL || challenge_len == 0U) {
            return false;
        }
        signature_out.assign(64U, 0x5aU);
        return true;
    }
};

class FuzzSessionListener : public carplay::iap2::SessionListener {
public:
    virtual bool onWiFiCredentialsRequested(carplay::iap2::WiFiConfiguration& out) {
        out.ssid = "BMW-Fuzz";
        out.passphrase = "12345678";
        out.channel = 36U;
        out.security_type = carplay::iap2::kWirelessSecurityWpaWpa2;
        return true;
    }
    virtual bool onCarPlayStartSessionRequested(const carplay::iap2::CarPlayAvailability& /*avail*/,
                                                carplay::iap2::StartSessionConfig& out) {
        out.wired_ipv6_addresses.push_back("fe80::1");
        out.has_airplay_port = true;
        out.airplay_port = 7000U;
        return true;
    }
};

void exerciseParamList(const carplay::iap2::ParameterList& list, int depth) {
    if (depth > 8) {
        return;
    }
    for (size_t i = 0; i < list.items().size(); ++i) {
        const uint16_t id = list.items()[i].id;
        uint8_t u8 = 0;
        uint16_t u16 = 0;
        uint32_t u32 = 0;
        uint64_t u64 = 0;
        std::string s;
        std::vector<std::string> vs;
        std::vector<uint16_t> vu16;
        list.readU8(id, u8);
        list.readU16(id, u16);
        list.readU32(id, u32);
        list.readU64(id, u64);
        list.readString(id, s);
        list.readStrings(id, vs);
        list.readU16List(id, vu16);
        carplay::iap2::ParameterList sub;
        if (list.readGroup(id, sub)) {
            exerciseParamList(sub, depth + 1);
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == NULL && size > 0U) {
        return 0;
    }

    std::string err;
    carplay::iap2::ParameterList plist;
    if (carplay::iap2::ParameterList::decode(data, size, plist, &err)) {
        exerciseParamList(plist, 0);
        std::vector<uint8_t> reencoded;
        plist.encode(reencoded, &err);
    }

    carplay::iap2::CsmFramer framer;
    std::vector<carplay::iap2::Frame> frames;
    framer.push(data, size, frames, &err);
    for (size_t i = 0; i < frames.size(); ++i) {
        carplay::iap2::ParameterList fp;
        if (carplay::iap2::ParameterList::decode(frames[i].payload, fp, &err)) {
            exerciseParamList(fp, 0);
        }
        carplay::iap2::CarPlayAvailability avail;
        carplay::iap2::parseCarPlayAvailability(frames[i], avail, &err);
        carplay::iap2::WiFiInformation winfo;
        carplay::iap2::parseWiFiInformation(frames[i], winfo, &err);
        bool wcp_avail = false;
        carplay::iap2::parseWirelessCarPlayAvailability(frames[i], wcp_avail, &err);
        carplay::iap2::DeviceTransportIdentifier tid;
        carplay::iap2::parseDeviceTransportIdentifier(frames[i], tid, &err);
    }

    if (size >= 2U) {
        carplay::iap2::Frame raw_frame;
        raw_frame.message_id = static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
        raw_frame.payload.assign(data + 2U, data + size);
        carplay::iap2::CarPlayAvailability avail;
        carplay::iap2::parseCarPlayAvailability(raw_frame, avail, &err);
        carplay::iap2::WiFiInformation winfo;
        carplay::iap2::parseWiFiInformation(raw_frame, winfo, &err);
        bool wcp_avail = false;
        carplay::iap2::parseWirelessCarPlayAvailability(raw_frame, wcp_avail, &err);
        carplay::iap2::DeviceTransportIdentifier tid;
        carplay::iap2::parseDeviceTransportIdentifier(raw_frame, tid, &err);
    }

    // Drive full iap2::Session in wireless and wired modes.
    FuzzByteSink sink;
    FuzzAuthProvider auth;
    FuzzSessionListener listener;
    const carplay::iap2::IdentificationConfig wident =
        carplay::iap2::IdentificationConfig::wirelessBluetooth(
            "BMW", "EntryNav2", "BMW", "001", "1.0", "HW", std::vector<uint8_t>(), "BMW-CarPlay");
    carplay::iap2::Session wsess(
        sink, auth, listener, carplay::iap2::SessionConfig::wirelessBluetooth(wident));
    wsess.start();
    wsess.feed(data, size);
    wsess.tick(100);

    const carplay::iap2::IdentificationConfig uident =
        carplay::iap2::IdentificationConfig::wiredUsb("BMW", "EntryNav2", "BMW", "001", "1.0", "HW");
    carplay::iap2::Session usess(
        sink, auth, listener, carplay::iap2::SessionConfig::wiredUsb(uident));
    usess.start();
    usess.feed(data, size);
    usess.tick(100);
    return 0;
}
