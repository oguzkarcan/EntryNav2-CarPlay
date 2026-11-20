#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "carplay/screen_stream.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == NULL && size > 0U) {
        return 0;
    }

    carplay::stream::ScreenPacketHeader hdr;
    std::string err;
    carplay::stream::parseScreenHeader(data, size, hdr, &err);

    (void)carplay::stream::detectConfigCodec(data, size);

    std::vector<uint8_t> annexb;
    uint8_t nal_len_bytes = 0U;
    carplay::stream::avcCToAnnexB(data, size, annexb, &nal_len_bytes);

    std::vector<uint8_t> mutable_buf(data, data + size);
    carplay::stream::lengthPrefixedToAnnexB(mutable_buf);

    if (size >= 28U) {
        static const uint8_t kKey[32] = {0};
        const uint8_t* nonce = data;
        const uint8_t* tag = data + 12U;
        std::vector<uint8_t> ct(data + 28U, data + size);
        carplay::stream::decryptFrameInPlace(
            kKey, nonce, data, 12U, ct.empty() ? NULL : &ct[0], ct.size(), tag);
    }
    return 0;
}
