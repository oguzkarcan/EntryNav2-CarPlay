#include <stddef.h>
#include <stdint.h>
#include <vector>

#include "carplay/control_cipher.hpp"
#include "carplay/ntp_timing.hpp"
#include "carplay/pairing.hpp"
#include "carplay/srp6a.hpp"

namespace {

class DetRandomSource : public carplay::pairing::RandomSource {
public:
    DetRandomSource() : counter_(1U) {}
    virtual bool fill(uint8_t* out, size_t len) {
        if (out == NULL && len > 0U) return false;
        for (size_t i = 0; i < len; ++i) {
            out[i] = static_cast<uint8_t>((counter_++ * 37U + 11U) & 0xffU);
        }
        return true;
    }
private:
    uint32_t counter_;
};

const carplay::pairing::Identity& sharedIdentity() {
    static bool init = false;
    static carplay::pairing::Identity id;
    if (!init) {
        uint8_t seed[carplay::crypto::kEd25519SeedBytes];
        for (size_t i = 0; i < sizeof(seed); ++i) {
            seed[i] = static_cast<uint8_t>(i + 0x40U);
        }
        id.initFromSeed(seed, "00000000-0000-4000-8000-000000000002");
        init = true;
    }
    return id;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if ((data == NULL && size > 0U) || size > 256U * 1024U) {
        return 0;
    }

    DetRandomSource rng;
    carplay::pairing::InMemoryPairingStore store;
    const uint8_t dummy_ltpk[carplay::crypto::kEd25519PublicKeyBytes] = {1U};
    store.save("controller-1", dummy_ltpk);

    // 1. PairSetup / PairVerify single-shot + multi-message framing ([u16 len | msg]...).
    {
        carplay::pairing::PairSetup ps(sharedIdentity(), store, rng);
        std::vector<uint8_t> resp;
        ps.handle(data, size, resp);

        carplay::pairing::PairSetup ps_seq(sharedIdentity(), store, rng);
        size_t pos = 0U;
        while (pos + 2U <= size) {
            const size_t mlen = static_cast<size_t>((static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1U]);
            pos += 2U;
            const size_t take = (size - pos < mlen) ? (size - pos) : mlen;
            ps_seq.handle(take > 0U ? (data + pos) : NULL, take, resp);
            pos += take;
        }
    }
    {
        carplay::pairing::PairVerify pv(sharedIdentity(), store, rng);
        std::vector<uint8_t> resp;
        pv.handle(data, size, resp);

        carplay::pairing::PairVerify pv_seq(sharedIdentity(), store, rng);
        size_t pos = 0U;
        while (pos + 2U <= size) {
            const size_t mlen = static_cast<size_t>((static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1U]);
            pos += 2U;
            const size_t take = (size - pos < mlen) ? (size - pos) : mlen;
            pv_seq.handle(take > 0U ? (data + pos) : NULL, take, resp);
            pos += take;
        }
    }

    // 2. SRP-6a verify with bounded A & proof splits (skip if > 600 bytes to keep throughput high).
    if (size >= 2U && size <= 600U) {
        static carplay::srp::Srp6aServer srp;
        static bool srp_init = false;
        if (!srp_init) {
            const uint8_t salt[carplay::srp::kSaltBytes] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
            const uint8_t b[carplay::srp::kPrivateKeyBytes] = {7};
            srp.start(carplay::pairing::kSetupUsername, carplay::pairing::kSetupCode, salt, b);
            srp_init = true;
        }
        const size_t split = (size > 64U) ? (size - 64U) : (size / 2U);
        std::vector<uint8_t> k;
        std::vector<uint8_t> m2;
        srp.verify(data, split, data + split, size - split, k, m2);
    }

    // 3. ControlCipher::feed + NTP ClockSync::onPacket.
    {
        static const uint8_t kRk[carplay::crypto::kKeyBytes] = {0x11};
        static const uint8_t kWk[carplay::crypto::kKeyBytes] = {0x22};
        carplay::ControlCipher cipher(kRk, kWk);
        std::vector<uint8_t> pt;
        cipher.feed(data, size, pt);
    }
    {
        carplay::ntp::ClockSync cs(0);
        uint8_t req[carplay::ntp::kPacketBytes];
        cs.makeRequest(1000000000LL, req);
        uint8_t resp[carplay::ntp::kPacketBytes];
        bool has_resp = false;
        cs.onPacket(data, size, 1005000000LL, resp, has_resp);
    }
    return 0;
}
