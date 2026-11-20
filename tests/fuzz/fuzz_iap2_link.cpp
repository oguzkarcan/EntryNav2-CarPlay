#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "carplay/iap2_link.hpp"

namespace {

class FuzzByteSink : public carplay::iap2::ByteSink {
public:
    virtual bool sendBytes(const uint8_t* /*data*/, size_t /*len*/) { return true; }
};

class FuzzLinkListener : public carplay::iap2::LinkListener {};

void runLinkFuzz(const carplay::iap2::LinkConfig& cfg, const uint8_t* data, size_t size) {
    FuzzByteSink sink;
    FuzzLinkListener listener;
    carplay::iap2::Link link(sink, listener, cfg);
    link.start();
    link.feed(data, size);
    link.tick(100);
    // Also exercise chunked delivery when input has >1 byte.
    if (size > 1U) {
        carplay::iap2::Link chunked(sink, listener, cfg);
        chunked.start();
        size_t pos = 0U;
        size_t step = (data[0] % 13U) + 1U;
        int64_t now_ms = 0;
        while (pos < size) {
            const size_t n = (size - pos < step) ? (size - pos) : step;
            chunked.feed(data + pos, n);
            now_ms += 50;
            chunked.tick(now_ms);
            pos += n;
        }
        if (chunked.state() == carplay::iap2::kLinkConnected) {
            const uint8_t msg[4] = {0x40U, 0x40U, 0x00U, 0x06U};
            chunked.sendPayload(carplay::iap2::kDefaultControlSessionId, msg, sizeof(msg));
            chunked.tick(now_ms + 5000);
        }
        chunked.reset(false);
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == NULL && size > 0U) {
        return 0;
    }

    carplay::iap2::LinkPacket pkt;
    std::string err;
    if (carplay::iap2::LinkPacket::decode(data, size, pkt, &err)) {
        std::vector<uint8_t> encoded;
        pkt.encode(encoded, &err);
        carplay::iap2::SynPayload syn;
        if (carplay::iap2::SynPayload::decode(pkt.payload, syn, &err)) {
            std::vector<uint8_t> syn_enc;
            syn.encode(syn_enc, &err);
            (void)syn.findSessionByType(carplay::iap2::kSessionTypeControl);
        }
    }

    carplay::iap2::SynPayload raw_syn;
    if (carplay::iap2::SynPayload::decode(data, size, raw_syn, &err)) {
        std::vector<uint8_t> syn_enc;
        raw_syn.encode(syn_enc, &err);
    }

    runLinkFuzz(carplay::iap2::LinkConfig::wirelessBluetooth(), data, size);
    runLinkFuzz(carplay::iap2::LinkConfig::wiredUsb(), data, size);
    return 0;
}
