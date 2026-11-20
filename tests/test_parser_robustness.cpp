// Deterministic parser robustness host test (GCC 4.7 / -std=gnu++0x safe).
// Exercises every phone- and network-facing parser over structured-mutated and
// pseudo-random inputs with a fixed seed to ensure zero crashes, assertions,
// hangs, or out-of-bounds reads under standard and ASan/UBSan builds.

#include "test_support.hpp"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <limits>
#include <string>
#include <vector>

#include "carplay/airplay_info.hpp"
#include "carplay/airplay_session.hpp"
#include "carplay/audio_rtp.hpp"
#include "carplay/auth_provider.hpp"
#include "carplay/bplist_codec.hpp"
#include "carplay/cdc_ncm.hpp"
#include "carplay/control_cipher.hpp"
#include "carplay/dnssd_txt.hpp"
#include "carplay/event_channel.hpp"
#include "carplay/iap2_link.hpp"
#include "carplay/iap2_session.hpp"
#include "carplay/iap2_wire.hpp"
#include "carplay/ntp_timing.hpp"
#include "carplay/pairing.hpp"
#include "carplay/rtsp_message.hpp"
#include "carplay/screen_stream.hpp"
#include "carplay/sdp_record.hpp"
#include "carplay/srp6a.hpp"
#include "carplay/tlv8_codec.hpp"
#include "carplay/usb_descriptors.hpp"

namespace {

struct Prng {
    uint64_t s;
    explicit Prng(uint64_t seed) : s(seed ? seed : 0x9e3779b97f4a7c15ULL) {}

    uint64_t next() {
        uint64_t x = s;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s = x;
        return x;
    }

    uint32_t nextU32(uint32_t bound) {
        return bound ? static_cast<uint32_t>(next() % bound) : 0U;
    }

    void fillRandom(std::vector<uint8_t>& out, size_t max_len) {
        const size_t n = static_cast<size_t>(nextU32(static_cast<uint32_t>(max_len + 1U)));
        out.resize(n);
        for (size_t i = 0; i < n; ++i) {
            out[i] = static_cast<uint8_t>(next() & 0xffU);
        }
    }

    void mutate(const std::vector<uint8_t>& base, std::vector<uint8_t>& out, size_t max_len) {
        if (base.empty() || nextU32(4U) == 0U) {
            fillRandom(out, max_len);
            return;
        }
        out = base;
        const uint32_t ops = 1U + nextU32(4U);
        for (uint32_t k = 0; k < ops; ++k) {
            const uint32_t op = nextU32(4U);
            if (op == 0U && !out.empty()) {
                const size_t idx = static_cast<size_t>(nextU32(static_cast<uint32_t>(out.size())));
                out[idx] ^= static_cast<uint8_t>(1U << nextU32(8U));
            } else if (op == 1U && !out.empty()) {
                const size_t idx = static_cast<size_t>(nextU32(static_cast<uint32_t>(out.size())));
                out[idx] = static_cast<uint8_t>(next() & 0xffU);
            } else if (op == 2U && out.size() > 1U) {
                const size_t new_len = 1U + static_cast<size_t>(nextU32(static_cast<uint32_t>(out.size())));
                out.resize(new_len);
            } else if (out.size() + 8U <= max_len) {
                const size_t add = 1U + static_cast<size_t>(nextU32(8U));
                for (size_t j = 0; j < add; ++j) {
                    out.push_back(static_cast<uint8_t>(next() & 0xffU));
                }
            }
        }
    }
};

class DummyIap2Sink : public carplay::iap2::ByteSink {
public:
    virtual bool sendBytes(const uint8_t* /*data*/, size_t /*len*/) { return true; }
};

class DummyLinkListener : public carplay::iap2::LinkListener {};

class DummyAuth : public carplay::iap2::AuthProvider {
public:
    virtual bool getCertificate(std::vector<uint8_t>& cert) {
        cert.assign(16U, 0x30U);
        return true;
    }
    virtual bool signChallenge(const uint8_t* ch, size_t len, std::vector<uint8_t>& sig) {
        if (ch == NULL || len == 0U) return false;
        sig.assign(64U, 0x5aU);
        return true;
    }
};

class DummySessionListener : public carplay::iap2::SessionListener {
public:
    virtual bool onWiFiCredentialsRequested(carplay::iap2::WiFiConfiguration& out) {
        out.ssid = "BMW-Robust";
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

class DetRandom : public carplay::pairing::RandomSource {
public:
    DetRandom() : c_(1U) {}
    virtual bool fill(uint8_t* out, size_t len) {
        if (out == NULL && len > 0U) return false;
        for (size_t i = 0; i < len; ++i) {
            out[i] = static_cast<uint8_t>((c_++ * 73U + 19U) & 0xffU);
        }
        return true;
    }
private:
    uint32_t c_;
};

class DummyAirPlayListener : public carplay::session::SessionListener {};

class DummyMediaHandler : public carplay::session::MediaHandler {
public:
    virtual bool onScreen(carplay::session::Session&, int32_t, const carplay::bplist::Value&, int32_t& p) {
        p = 7010;
        return true;
    }
    virtual bool onAudio(carplay::session::Session&, int32_t t, const carplay::bplist::Value&, carplay::bplist::Value& r) {
        carplay::bplist::Value::Dict d;
        d.push_back(std::make_pair(std::string("type"), carplay::bplist::Value::makeInt(t)));
        d.push_back(std::make_pair(std::string("dataPort"), carplay::bplist::Value::makeInt(7020)));
        r = carplay::bplist::Value::makeDict(d);
        return true;
    }
    virtual bool onDataStream(carplay::session::Session&, const carplay::bplist::Value&, carplay::bplist::Value& r) {
        carplay::bplist::Value::Dict d;
        d.push_back(std::make_pair(std::string("dataPort"), carplay::bplist::Value::makeInt(7030)));
        r = carplay::bplist::Value::makeDict(d);
        return true;
    }
    virtual bool onFeedback(carplay::session::Session&, carplay::bplist::Value& r) {
        r = carplay::bplist::Value::makeDict();
        return true;
    }
};

class DummyTransportHost : public carplay::session::TransportHost {
public:
    virtual bool openTiming(int32_t, int32_t& p) { p = 7040; return true; }
    virtual bool openEvent(int32_t& p) { p = 7050; return true; }
    virtual bool openKeepAlive(int32_t& p) { p = 7060; return true; }
    virtual void closeAll() {}
};

const carplay::pairing::Identity& testIdentity() {
    static bool init = false;
    static carplay::pairing::Identity id;
    if (!init) {
        uint8_t seed[carplay::crypto::kEd25519SeedBytes];
        for (size_t i = 0; i < sizeof(seed); ++i) {
            seed[i] = static_cast<uint8_t>(i + 1U);
        }
        id.initFromSeed(seed, "00000000-0000-4000-8000-000000000001");
        init = true;
    }
    return id;
}

std::vector<uint8_t> strBytes(const char* s) {
    const size_t n = strlen(s);
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(s),
                                reinterpret_cast<const uint8_t*>(s) + n);
}

}  // namespace

TEST_CASE(iap2LinkAndSessionRobustness) {
    Prng rng(0x1122334455667788ULL);
    std::vector<std::vector<uint8_t> > seeds;
    seeds.push_back(test_support::hexToBytes("ff550200ee10"));
    seeds.push_back(test_support::hexToBytes("ff5a001b80010000e1010403020a003200ff5a01000a00010b0201f3"));
    seeds.push_back(test_support::hexToBytes("4040000a1d0000040001"));
    seeds.push_back(test_support::hexToBytes("404000125701000600004100000600020200"));

    DummyIap2Sink sink;
    DummyLinkListener link_listener;
    DummyAuth auth;
    DummySessionListener sess_listener;
    const carplay::iap2::IdentificationConfig id_cfg =
        carplay::iap2::IdentificationConfig::wirelessBluetooth(
            "BMW", "EntryNav2", "BMW", "001", "1.0", "HW", std::vector<uint8_t>(), "BMW");

    std::vector<uint8_t> buf;
    for (int i = 0; i < 2500; ++i) {
        rng.mutate(seeds[i % seeds.size()], buf, 512U);
        const uint8_t* ptr = buf.empty() ? NULL : &buf[0];

        carplay::iap2::LinkPacket pkt;
        std::string err;
        if (carplay::iap2::LinkPacket::decode(ptr, buf.size(), pkt, &err)) {
            std::vector<uint8_t> enc;
            pkt.encode(enc, &err);
            carplay::iap2::SynPayload syn;
            carplay::iap2::SynPayload::decode(pkt.payload, syn, &err);
        }

        carplay::iap2::Link link(sink, link_listener, carplay::iap2::LinkConfig::wirelessBluetooth());
        link.start();
        link.feed(ptr, buf.size());
        link.tick(100);

        carplay::iap2::ParameterList plist;
        carplay::iap2::ParameterList::decode(ptr, buf.size(), plist, &err);

        carplay::iap2::CsmFramer framer;
        std::vector<carplay::iap2::Frame> frames;
        framer.push(ptr, buf.size(), frames, &err);
        for (size_t f = 0; f < frames.size(); ++f) {
            carplay::iap2::CarPlayAvailability av;
            carplay::iap2::parseCarPlayAvailability(frames[f], av, &err);
            carplay::iap2::WiFiInformation wi;
            carplay::iap2::parseWiFiInformation(frames[f], wi, &err);
            carplay::iap2::DeviceTransportIdentifier ti;
            carplay::iap2::parseDeviceTransportIdentifier(frames[f], ti, &err);
        }

        carplay::iap2::Session sess(
            sink, auth, sess_listener, carplay::iap2::SessionConfig::wirelessBluetooth(id_cfg));
        sess.start();
        sess.feed(ptr, buf.size());
        sess.tick(100);
    }
    CHECK(true);
}

TEST_CASE(cdcNcmAndUsbDescriptorRobustness) {
    Prng rng(0x2233445566778899ULL);
    std::vector<std::vector<uint8_t> > ncm_seeds;
    ncm_seeds.push_back(test_support::hexToBytes(
        "4e434d480c00010024000c004e434d30100000001c000800000000006000000000041140"));
    std::vector<std::vector<uint8_t> > usb_seeds;
    usb_seeds.push_back(test_support::hexToBytes(
        "1201000200000040ac05a812000101020301"
        "09022000020100c0fa0904000001020d00000705810310000a09040100000a000100"));

    std::vector<uint8_t> buf;
    for (int i = 0; i < 3000; ++i) {
        std::string err;
        rng.mutate(ncm_seeds[0], buf, 1024U);
        const uint8_t* nptr = buf.empty() ? NULL : &buf[0];
        carplay::ncm::NtbParameters params;
        carplay::ncm::parseNtbParameters(nptr, buf.size(), params, &err);
        carplay::ncm::Ntb16Frame frame;
        carplay::ncm::parseNtb16(nptr, buf.size(), carplay::ncm::NtbParseOptions(), frame, &err);
        carplay::ncm::Ntb16StreamDecoder dec;
        std::vector<carplay::ncm::Ntb16Frame> frames;
        dec.push(nptr, buf.size(), frames);

        rng.mutate(usb_seeds[0], buf, 512U);
        const uint8_t* uptr = buf.empty() ? NULL : &buf[0];
        carplay::usb::DeviceDescriptor dev;
        carplay::usb::parseDeviceDescriptor(uptr, buf.size(), dev, &err);
        carplay::usb::ConfigurationDescriptor cfg;
        size_t consumed = 0U;
        carplay::usb::parseConfigurationDescriptor(uptr, buf.size(), cfg, &consumed, &err);
        std::vector<carplay::usb::ConfigurationDescriptor> configs;
        if (carplay::usb::parseUsbfsDescriptors(uptr, buf.size(), dev, configs, &err)) {
            (void)carplay::usb::selectCarPlayInterfaces(configs);
        }
        std::string str_out;
        carplay::usb::decodeUsbStringDescriptor(uptr, buf.size(), str_out, &err);
    }
    CHECK(true);
}

TEST_CASE(rtspBplistTlv8SdpDnssdRobustness) {
    Prng rng(0x33445566778899aaULL);
    const std::vector<uint8_t> rtsp_seed = strBytes("POST /setup RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 4\r\n\r\nTEST");
    const std::vector<uint8_t> bplist_seed = test_support::hexToBytes(
        "62706c6973743030d101025474797065120000006e080b100000000000000101000000000000000300000000000000000000000000000015");
    const std::vector<uint8_t> tlv_seed = test_support::hexToBytes("000101060101");
    const std::vector<uint8_t> sdp_seed = test_support::hexToBytes("821234000400010002");
    const std::vector<uint8_t> txt_seed = strBytes("\x0c" "deviceid=11\x04rsf=");

    std::vector<uint8_t> buf;
    for (int i = 0; i < 3000; ++i) {
        std::string err;

        rng.mutate(rtsp_seed, buf, 1024U);
        carplay::rtsp::Parser rtsp_p;
        std::vector<carplay::rtsp::Request> reqs;
        rtsp_p.feed(buf.empty() ? NULL : &buf[0], buf.size(), reqs);

        rng.mutate(bplist_seed, buf, 512U);
        carplay::bplist::Value bp;
        if (carplay::bplist::decode(buf.empty() ? NULL : &buf[0], buf.size(), bp, &err)) {
            if (bp.isDate()) {
                (void)bp.asDateUnixMillis();
            }
            std::vector<uint8_t> enc;
            carplay::bplist::encode(bp, enc, &err);
        }

        rng.mutate(tlv_seed, buf, 512U);
        std::vector<carplay::tlv8::Item> items;
        if (carplay::tlv8::decode(buf.empty() ? NULL : &buf[0], buf.size(), items, &err)) {
            (void)carplay::tlv8::splitBySeparator(items);
            (void)carplay::tlv8::encode(items);
        }

        rng.mutate(sdp_seed, buf, 256U);
        uint32_t handle = 0U;
        uint16_t serr = 0U;
        carplay::sdp::parseSdpdRegisterResponse(buf.empty() ? NULL : &buf[0], buf.size(), 0x1234U, handle, &serr, &err);
        carplay::sdp::parseSdpdRemoveResponse(buf.empty() ? NULL : &buf[0], buf.size(), 0x1234U, &serr, &err);

        rng.mutate(txt_seed, buf, 512U);
        std::vector<carplay::dnssd::TxtEntry> txt;
        carplay::dnssd::decodeTxtRecord(buf.empty() ? NULL : &buf[0], buf.size(), txt, &err);
    }
    CHECK(true);
}

TEST_CASE(mediaSessionAndCryptoRobustness) {
    Prng rng(0x445566778899aabbULL);
    const std::vector<uint8_t> rtp_seed = test_support::hexToBytes(
        "80600001000001e01234567800000000000000000000000000000000");
    const std::vector<uint8_t> scr_seed = test_support::hexToBytes(
        "04000000000100000000000000005f40"
        "0164001fffe100046764001f01000368ee3c");
    const std::vector<uint8_t> ntp_seed(48U, 0xe3U);
    const std::vector<uint8_t> pair_seed = test_support::hexToBytes("000100060101");

    static const uint8_t kKey[32] = {1U, 2U, 3U};
    DetRandom det_rng;
    carplay::pairing::InMemoryPairingStore store;
    DummyAirPlayListener ap_listener;
    DummyMediaHandler media;
    DummyTransportHost transport;
    const carplay::info::AirPlayConfig ap_cfg = carplay::info::bmwEntryNav2_800x480(true);

    std::vector<uint8_t> buf;
    for (int i = 0; i < 2000; ++i) {
        std::string err;

        // Audio RTP + JitterBuffer
        rng.mutate(rtp_seed, buf, 512U);
        const uint8_t* ptr = buf.empty() ? NULL : &buf[0];
        carplay::audio::RtpHeader rh;
        carplay::audio::parseRtpHeader(ptr, buf.size(), rh);
        std::vector<uint8_t> out;
        carplay::audio::openPacket(kKey, ptr, buf.size(), rh, out);
        carplay::audio::openPacketToRtp(kKey, ptr, buf.size(), out, &rh);
        if (buf.size() >= 3U) {
            carplay::audio::JitterBuffer jb(8U, 2U);
            jb.push(static_cast<uint16_t>((buf[0] << 8) | buf[1]), 0U, ptr + 2U, buf.size() - 2U);
            carplay::audio::JitterBuffer::Packet jp;
            jb.pop(jp);
        }

        // Screen stream
        rng.mutate(scr_seed, buf, 512U);
        ptr = buf.empty() ? NULL : &buf[0];
        carplay::stream::ScreenPacketHeader sh;
        carplay::stream::parseScreenHeader(ptr, buf.size(), sh, &err);
        (void)carplay::stream::detectConfigCodec(ptr, buf.size());
        uint8_t nal_len = 0U;
        carplay::stream::avcCToAnnexB(ptr, buf.size(), out, &nal_len);
        carplay::stream::lengthPrefixedToAnnexB(buf);

        // EventChannel + AirPlay Session + ControlCipher + NTP
        carplay::session::EventChannel ev;
        if (ev.start(kKey)) {
            std::vector<carplay::rtsp::Request> ev_reqs;
            ev.onBytes(ptr, buf.size(), out, &ev_reqs);
        }
        carplay::ControlCipher cipher(kKey, kKey);
        cipher.feed(ptr, buf.size(), out);

        carplay::ntp::ClockSync cs(0);
        uint8_t ntp_resp[carplay::ntp::kPacketBytes];
        bool has_ntp = false;
        cs.onPacket(ntp_seed.data(), ntp_seed.size(), 1000000LL, ntp_resp, has_ntp);
        if (!buf.empty()) {
            cs.onPacket(&buf[0], buf.size(), 2000000LL, ntp_resp, has_ntp);
        }

        carplay::session::Session sess(ap_cfg, testIdentity(), store, det_rng, ap_listener, media, transport);
        sess.onControlBytes(ptr, buf.size(), out);

        // Pairing
        rng.mutate(pair_seed, buf, 128U);
        ptr = buf.empty() ? NULL : &buf[0];
        carplay::pairing::PairSetup ps(testIdentity(), store, det_rng);
        ps.handle(ptr, buf.size(), out);
        carplay::pairing::PairVerify pv(testIdentity(), store, det_rng);
        pv.handle(ptr, buf.size(), out);
    }

    // Bounded SRP verify test (expensive ModPow so 50 iterations).
    const uint8_t salt[carplay::srp::kSaltBytes] = {1};
    const uint8_t b[carplay::srp::kPrivateKeyBytes] = {7};
    carplay::srp::Srp6aServer srp;
    srp.start(carplay::pairing::kSetupUsername, carplay::pairing::kSetupCode, salt, b);
    for (int i = 0; i < 50; ++i) {
        rng.fillRandom(buf, 64U);
        std::vector<uint8_t> k, m2;
        const size_t split = buf.size() / 2U;
        srp.verify(buf.empty() ? NULL : &buf[0], split,
                   buf.size() > split ? &buf[split] : NULL, buf.size() - split, k, m2);
    }
    CHECK(true);
}

TEST_CASE(bplistDateConversionOverflowRegression) {
    // Reproducer from fuzz_bplist_codec (crash-8cb8c2ff432eb52d1038f01a63524e2d44c62053):
    // bplist00 Date (0x33) holding an extreme IEEE-754 double whose conversion to
    // Unix milliseconds overflowed int64_t in Value::asDateUnixMillis().
    const std::vector<uint8_t> crash_input = test_support::hexToBytes(
        "62706c697374303033fefeab757970a5edffffff6e080b6c6973000000000101"
        "000000000000000300000000000000000000000000000015");
    carplay::bplist::Value v;
    std::string err;
    REQUIRE(carplay::bplist::decode(crash_input, v, &err));
    REQUIRE(v.isDate());
    CHECK_EQ(std::numeric_limits<int64_t>::min(), v.asDateUnixMillis());

    CHECK_EQ(std::numeric_limits<int64_t>::max(),
             carplay::bplist::Value::makeDateAppleSeconds(1e30).asDateUnixMillis());
    CHECK_EQ(std::numeric_limits<int64_t>::min(),
             carplay::bplist::Value::makeDateAppleSeconds(-1e30).asDateUnixMillis());
    CHECK_EQ(static_cast<int64_t>(0),
             carplay::bplist::Value::makeDateAppleSeconds(
                 std::numeric_limits<double>::quiet_NaN()).asDateUnixMillis());
}

int main() {
    return test_support::runAll("test_parser_robustness");
}
