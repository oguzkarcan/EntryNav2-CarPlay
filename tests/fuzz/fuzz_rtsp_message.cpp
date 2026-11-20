#include <stddef.h>
#include <stdint.h>
#include <vector>

#include "carplay/rtsp_message.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == NULL && size > 0U) {
        return 0;
    }

    carplay::rtsp::Parser parser;
    std::vector<carplay::rtsp::Request> reqs;
    parser.feed(data, size, reqs);

    for (size_t i = 0; i < reqs.size(); ++i) {
        (void)reqs[i].findHeader("CSeq");
        (void)reqs[i].findHeader("Content-Length");
        (void)reqs[i].isResponse();
        carplay::rtsp::Response resp(200);
        resp.body = reqs[i].body;
        std::vector<uint8_t> wire;
        carplay::rtsp::buildResponse(reqs[i], resp, wire);
        if (i == 0U) {
            std::vector<uint8_t> req_wire;
            carplay::rtsp::buildRequest(reqs[i].method, reqs[i].path, reqs[i].protocol,
                                        reqs[i].headers, reqs[i].body, req_wire);
        }
    }

    if (size > 1U) {
        carplay::rtsp::Parser small_cap(512U, 4096U);
        std::vector<carplay::rtsp::Request> chunk_reqs;
        const size_t step = (data[0] % 19U) + 1U;
        size_t pos = 0U;
        while (pos < size) {
            const size_t n = (size - pos < step) ? (size - pos) : step;
            if (!small_cap.feed(data + pos, n, chunk_reqs)) {
                break;
            }
            pos += n;
        }
    }
    return 0;
}
