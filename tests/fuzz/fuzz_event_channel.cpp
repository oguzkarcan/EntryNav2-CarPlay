#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

#include "carplay/airplay_info.hpp"
#include "carplay/airplay_session.hpp"
#include "carplay/bplist_codec.hpp"
#include "carplay/control_cipher.hpp"
#include "carplay/event_channel.hpp"
#include "carplay/pairing.hpp"

namespace {

class DetRandomSource : public carplay::pairing::RandomSource {
public:
    DetRandomSource() : counter_(1U) {}
    virtual bool fill(uint8_t* out, size_t len) {
        if (out == NULL && len > 0U) return false;
        for (size_t i = 0; i < len; ++i) {
            out[i] = static_cast<uint8_t>((counter_++ * 73U + 19U) & 0xffU);
        }
        return true;
    }
private:
    uint32_t counter_;
};

class FuzzSessionListener : public carplay::session::SessionListener {};

class FuzzMediaHandler : public carplay::session::MediaHandler {
public:
    virtual bool onScreen(carplay::session::Session& /*session*/,
                          int32_t /*type*/,
                          const carplay::bplist::Value& /*stream*/,
                          int32_t& data_port_out) {
        data_port_out = 7010;
        return true;
    }
    virtual bool onAudio(carplay::session::Session& /*session*/,
                         int32_t type,
                         const carplay::bplist::Value& /*stream*/,
                         carplay::bplist::Value& response_out) {
        carplay::bplist::Value::Dict d;
        d.push_back(std::make_pair(std::string("type"), carplay::bplist::Value::makeInt(type)));
        d.push_back(std::make_pair(std::string("dataPort"), carplay::bplist::Value::makeInt(7020)));
        d.push_back(std::make_pair(std::string("controlPort"), carplay::bplist::Value::makeInt(7021)));
        response_out = carplay::bplist::Value::makeDict(d);
        return true;
    }
    virtual bool onDataStream(carplay::session::Session& /*session*/,
                              const carplay::bplist::Value& /*stream*/,
                              carplay::bplist::Value& response_out) {
        carplay::bplist::Value::Dict d;
        d.push_back(std::make_pair(std::string("type"), carplay::bplist::Value::makeInt(130)));
        d.push_back(std::make_pair(std::string("dataPort"), carplay::bplist::Value::makeInt(7030)));
        response_out = carplay::bplist::Value::makeDict(d);
        return true;
    }
    virtual bool onFeedback(carplay::session::Session& /*session*/,
                            carplay::bplist::Value& response_out) {
        response_out = carplay::bplist::Value::makeDict();
        return true;
    }
};

class FuzzTransportHost : public carplay::session::TransportHost {
public:
    virtual bool openTiming(int32_t /*peer_timing_port*/, int32_t& local_port_out) {
        local_port_out = 7040;
        return true;
    }
    virtual bool openEvent(int32_t& local_port_out) {
        local_port_out = 7050;
        return true;
    }
    virtual bool openKeepAlive(int32_t& local_port_out) {
        local_port_out = 7060;
        return true;
    }
    virtual void closeAll() {}
};

const carplay::pairing::Identity& sharedIdentity() {
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

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if ((data == NULL && size > 0U) || size > 2U * 1024U * 1024U) {
        return 0;
    }

    static const uint8_t kSecret[carplay::crypto::kKeyBytes] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };

    uint8_t ev_read[carplay::crypto::kKeyBytes];
    uint8_t ev_write[carplay::crypto::kKeyBytes];
    carplay::pairing::deriveEventKeys(kSecret, ev_read, ev_write);

    // 1. EventChannel raw ciphertext path.
    {
        carplay::session::EventChannel ev;
        if (ev.start(kSecret)) {
            std::vector<uint8_t> wire_out;
            std::vector<carplay::rtsp::Request> reqs;
            ev.onBytes(data, size, wire_out, &reqs);
        }
    }

    // 2. EventChannel sealed-payload path (exercises inner RTSP + 200 OK + bplist response/request).
    if (size > 0U) {
        carplay::ControlCipher peer_cipher(ev_write, ev_read);
        std::vector<uint8_t> sealed;
        if (peer_cipher.encrypt(data, size, sealed)) {
            carplay::session::EventChannel ev;
            if (ev.start(kSecret)) {
                std::vector<uint8_t> wire_out;
                std::vector<carplay::rtsp::Request> reqs;
                ev.onBytes(sealed.empty() ? NULL : &sealed[0], sealed.size(), wire_out, &reqs);
            }
        }
    }

    // 3. AirPlay Session control bytes (both strict policy and unverified-allowed for SETUP/COMMAND/TEARDOWN).
    const carplay::info::AirPlayConfig ap_cfg = carplay::info::bmwEntryNav2_800x480(true);
    DetRandomSource rng;
    carplay::pairing::InMemoryPairingStore store;
    FuzzSessionListener listener;
    FuzzMediaHandler media;
    FuzzTransportHost transport;

    {
        carplay::session::SessionPolicy pol;
        pol.require_verified_for_session_requests = true;
        carplay::session::Session sess(ap_cfg, sharedIdentity(), store, rng, listener, media, transport, NULL, pol);
        std::vector<uint8_t> out;
        sess.onControlBytes(data, size, out);
        sess.close();
    }
    {
        carplay::session::SessionPolicy pol;
        pol.require_verified_for_session_requests = false;
        pol.max_unverified_requests = 0U;
        carplay::session::Session sess(ap_cfg, sharedIdentity(), store, rng, listener, media, transport, NULL, pol);
        std::vector<uint8_t> out;
        sess.onControlBytes(data, size, out);
        sess.close();
    }

    // 4. teardownStreamTypes on decoded bplist.
    carplay::bplist::Value body;
    if (carplay::bplist::decode(data, size, body)) {
        bool whole = false;
        std::vector<int32_t> types;
        carplay::session::teardownStreamTypes(&body, whole, types);
        int64_t lv = 0;
        int32_t iv = 0;
        carplay::session::plistNumberToLong(body, lv);
        carplay::session::plistNumberToInt(body, iv);
    }

    return 0;
}
