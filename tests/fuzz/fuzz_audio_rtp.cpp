#include <stddef.h>
#include <stdint.h>
#include <vector>

#include "carplay/audio_rtp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == NULL && size > 0U) {
        return 0;
    }

    static const uint8_t kKey[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    carplay::audio::RtpHeader hdr;
    carplay::audio::parseRtpHeader(data, size, hdr);

    std::vector<uint8_t> payload_out;
    carplay::audio::openPacket(kKey, data, size, hdr, payload_out);
    std::vector<uint8_t> rtp_out;
    carplay::audio::openPacketToRtp(kKey, data, size, rtp_out, &hdr);

    std::vector<int16_t> samples;
    carplay::audio::lpcmToInt16(data, size, samples, carplay::audio::kBigEndianSamples);
    carplay::audio::lpcmToInt16(data, size, samples, carplay::audio::kLittleEndianSamples);

    if (size >= 8U) {
        uint64_t bits = 0ULL;
        for (size_t i = 0; i < 8U; ++i) {
            bits = (bits << 8) | data[i];
        }
        (void)carplay::audio::formatFromBits(bits, 100);
    }

    // Drive JitterBuffer using 3-byte commands (u16 seq, u8 payload_len slice).
    if (size >= 3U) {
        carplay::audio::JitterBuffer jb(16U, 4U);
        size_t pos = 0U;
        while (pos + 3U <= size) {
            const uint16_t seq = static_cast<uint16_t>((static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1U]);
            const uint8_t plen = data[pos + 2U] & 0x1fU;
            pos += 3U;
            const size_t avail = (size - pos < plen) ? (size - pos) : plen;
            jb.push(seq, static_cast<uint32_t>(seq) * 480U, avail > 0U ? (data + pos) : NULL, avail);
            pos += avail;
            carplay::audio::JitterBuffer::Packet pkt;
            while (jb.pop(pkt) != carplay::audio::JitterBuffer::kPopEmpty) {
            }
        }
        jb.flush();
    }
    return 0;
}
