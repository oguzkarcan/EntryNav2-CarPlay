#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "carplay/sdp_record.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == NULL && size > 0U) {
        return 0;
    }

    std::string err;
    uint32_t handle = 0U;
    uint16_t sdp_err = 0U;
    const uint16_t tid = (size >= 3U)
        ? static_cast<uint16_t>((static_cast<uint16_t>(data[1]) << 8) | data[2])
        : 0U;

    carplay::sdp::parseSdpdRegisterResponse(data, size, tid, handle, &sdp_err, &err);
    carplay::sdp::parseSdpdRegisterResponse(data, size, 0x1234U, handle, &sdp_err, &err);
    carplay::sdp::parseSdpdRemoveResponse(data, size, tid, &sdp_err, &err);
    carplay::sdp::parseSdpdRemoveResponse(data, size, 0x1234U, &sdp_err, &err);

    if (size <= 128U && data != NULL) {
        const std::string text(reinterpret_cast<const char*>(data), size);
        carplay::sdp::Uuid128 uuid;
        if (carplay::sdp::parseUuid128(text, uuid)) {
            (void)carplay::sdp::formatUuid128(uuid);
            carplay::sdp::Iap2SdpConfig cfg;
            cfg.service_uuid = uuid;
            cfg.rfcomm_channel = 5U;
            cfg.service_name = text;
            carplay::sdp::ServiceRecord rec;
            if (carplay::sdp::buildIap2SdpRecord(cfg, rec, &err)) {
                std::vector<uint8_t> enc;
                if (rec.encode(enc, &err)) {
                    std::vector<uint8_t> pdu;
                    carplay::sdp::encodeSdpdRegisterRequest(tid, enc, pdu, NULL, 0U, &err);
                }
            }
        }
    }
    return 0;
}
