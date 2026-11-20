#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "carplay/cdc_ncm.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == NULL && size > 0U) {
        return 0;
    }

    std::string err;
    carplay::ncm::NtbParameters params;
    if (carplay::ncm::parseNtbParameters(data, size, params, &err)) {
        std::vector<uint8_t> enc;
        carplay::ncm::encodeNtbParameters(params, enc);
    }

    carplay::ncm::Ntb16Frame frame;
    carplay::ncm::NtbParseOptions opts;
    opts.check_in_alignment = false;
    opts.verify_crc32 = true;
    carplay::ncm::parseNtb16(data, size, opts, frame, &err);

    opts.check_in_alignment = true;
    opts.verify_crc32 = false;
    carplay::ncm::parseNtb16(data, size, opts, frame, &err);

    carplay::ncm::Ntb16StreamDecoder dec;
    std::vector<carplay::ncm::Ntb16Frame> frames;
    carplay::ncm::NtbStreamStats stats;
    dec.push(data, size, frames, &stats);

    if (size > 1U) {
        carplay::ncm::Ntb16StreamDecoder chunked(carplay::ncm::NtbParseOptions(), 64U, 131072U);
        const size_t step = (data[0] % 31U) + 1U;
        size_t pos = 0U;
        while (pos < size) {
            const size_t n = (size - pos < step) ? (size - pos) : step;
            frames.clear();
            chunked.push(data + pos, n, frames, &stats);
            pos += n;
        }
    }
    return 0;
}
