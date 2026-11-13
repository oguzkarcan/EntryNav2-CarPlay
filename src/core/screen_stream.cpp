#include "carplay/screen_stream.hpp"
#include "carplay/airplay_crypto.hpp"

#include <cstring>

namespace carplay {
namespace stream {

namespace {

uint16_t readU16Le(const uint8_t* p) {
    return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t readU32Le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

uint32_t readU32Be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

uint16_t readU16Be(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint64_t readU64Le(const uint8_t* p) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(p[i]) << (8U * i);
    }
    return v;
}

float readFloat32Le(const uint8_t* p) {
    const uint32_t bits = readU32Le(p);
    float f = 0.0f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

bool hasAnnexBStartCode(const uint8_t* data, size_t len) {
    if (len >= 4 && data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 1) {
        return true;
    }
    if (len >= 3 && data[0] == 0 && data[1] == 0 && data[2] == 1) {
        return true;
    }
    return false;
}

bool looksLikeAvcC(const uint8_t* d, size_t len) {
    if (len < 7 || d[0] != 0x01U) return false;
    const uint8_t len_minus_one = static_cast<uint8_t>(d[4] & 0x03U);
    if (len_minus_one != 3U && len_minus_one != 1U && len_minus_one != 0U) {
        return false;
    }
    const uint8_t sps_count = static_cast<uint8_t>(d[5] & 0x1fU);
    size_t pos = 6;
    for (uint8_t i = 0; i < sps_count; ++i) {
        if (pos + 2 > len) return false;
        const uint16_t n = readU16Be(d + pos);
        pos += 2;
        if (n == 0 || pos + n > len) return false;
        pos += n;
    }
    if (pos >= len) return false;
    const uint8_t pps_count = d[pos++];
    for (uint8_t i = 0; i < pps_count; ++i) {
        if (pos + 2 > len) return false;
        const uint16_t n = readU16Be(d + pos);
        pos += 2;
        if (n == 0 || pos + n > len) return false;
        pos += n;
    }
    return pos <= len && (sps_count > 0 || pps_count > 0);
}

bool looksLikeHvcC(const uint8_t* d, size_t len) {
    if (len < 23 || d[0] != 0x01U) return false;
    const uint8_t num_arrays = d[22];
    size_t pos = 23;
    for (uint8_t a = 0; a < num_arrays; ++a) {
        if (pos + 3 > len) return false;
        const uint16_t num_nalus = readU16Be(d + pos + 1);
        pos += 3;
        for (uint16_t j = 0; j < num_nalus; ++j) {
            if (pos + 2 > len) return false;
            const uint16_t n = readU16Be(d + pos);
            pos += 2;
            if (pos + n > len) return false;
            pos += n;
        }
    }
    return num_arrays > 0 && pos <= len;
}

}  // namespace

uint64_t ntpToNanos(uint64_t ntp_fixed) {
    const uint64_t seconds = (ntp_fixed >> 32) & 0xffffffffULL;
    const uint64_t frac = ntp_fixed & 0xffffffffULL;
    const uint64_t subsec_nanos = (frac * 1000000000ULL) >> 32;
    return seconds * 1000000000ULL + subsec_nanos;
}

bool parseScreenHeader(const uint8_t* header_bytes,
                       size_t len,
                       ScreenPacketHeader& out,
                       std::string* error_out) {
    if (header_bytes == NULL || len < kScreenHeaderBytes) {
        if (error_out != NULL) {
            *error_out = "screen packet header must be at least 128 bytes";
        }
        return false;
    }
    out = ScreenPacketHeader();
    out.payload_size = readU32Le(header_bytes + 0);
    out.opcode = readU16Le(header_bytes + kOpcodeOffset);
    out.flags = readU16Le(header_bytes + kOpcodeOffset + 2U);
    out.ntp_timestamp = readU64Le(header_bytes + kSenderNtpOffset);
    out.sender_nanos = ntpToNanos(out.ntp_timestamp);
    if (out.opcode == kOpVideoConfig) {
        out.width_px = readFloat32Le(header_bytes + 16U);
        out.height_px = readFloat32Le(header_bytes + 20U);
    }
    return true;
}

bool decryptFrame(const uint8_t key[32],
                  uint64_t counter,
                  const uint8_t* aad,
                  size_t aad_len,
                  const uint8_t* ciphertext,
                  size_t ciphertext_len,
                  const uint8_t tag[16],
                  std::vector<uint8_t>& plaintext_out) {
    uint8_t nonce[crypto::kNonceBytes];
    crypto::makeCounterNonce(counter, nonce);
    plaintext_out.assign(ciphertext_len, 0);
    uint8_t* pt_ptr = ciphertext_len > 0 ? &plaintext_out[0] : NULL;
    if (!crypto::chacha20Poly1305OpenDetached(key, nonce, aad, aad_len, ciphertext, ciphertext_len, tag, pt_ptr)) {
        plaintext_out.clear();
        return false;
    }
    return true;
}

bool decryptFrameInPlace(const uint8_t key[32],
                         const uint8_t nonce[12],
                         const uint8_t* aad,
                         size_t aad_len,
                         uint8_t* data,
                         size_t len,
                         const uint8_t tag[16]) {
    return crypto::chacha20Poly1305OpenDetached(key, nonce, aad, aad_len, data, len, tag, data);
}

bool lengthPrefixedToAnnexBInPlace(uint8_t* data, size_t len) {
    if (len == 0) {
        return true;
    }
    if (data == NULL) {
        return false;
    }
    size_t pos = 0;
    while (pos < len) {
        if (pos + 4U > len) {
            return false;
        }
        const uint32_t nalu_len = readU32Be(data + pos);
        if (nalu_len == 0 || static_cast<uint64_t>(pos) + 4ULL + static_cast<uint64_t>(nalu_len) > len) {
            return false;
        }
        data[pos] = 0x00U;
        data[pos + 1] = 0x00U;
        data[pos + 2] = 0x00U;
        data[pos + 3] = 0x01U;
        pos += 4U + static_cast<size_t>(nalu_len);
    }
    return true;
}

bool lengthPrefixedToAnnexB(std::vector<uint8_t>& buffer) {
    if (buffer.empty()) {
        return true;
    }
    return lengthPrefixedToAnnexBInPlace(&buffer[0], buffer.size());
}

VideoCodecType detectConfigCodec(const uint8_t* data, size_t len) {
    if (data == NULL || len == 0) {
        return CODEC_UNKNOWN;
    }
    if (hasAnnexBStartCode(data, len)) {
        return CODEC_ANNEX_B;
    }
    // Check hvcC before avcC because hvcC is stricter (min 23 bytes + 22-byte header arrays).
    if (looksLikeHvcC(data, len)) {
        return CODEC_HEVC_HVCC;
    }
    if (looksLikeAvcC(data, len)) {
        return CODEC_H264_AVCC;
    }
    return CODEC_UNKNOWN;
}

bool avcCToAnnexB(const uint8_t* avcc,
                  size_t len,
                  std::vector<uint8_t>& annexb_out,
                  uint8_t* nal_length_bytes_out) {
    annexb_out.clear();
    if (avcc == NULL || !looksLikeAvcC(avcc, len)) {
        return false;
    }
    if (nal_length_bytes_out != NULL) {
        *nal_length_bytes_out = static_cast<uint8_t>((avcc[4] & 0x03U) + 1U);
    }
    static const uint8_t kStartCode[4] = {0x00U, 0x00U, 0x00U, 0x01U};

    const uint8_t sps_count = static_cast<uint8_t>(avcc[5] & 0x1fU);
    size_t pos = 6U;
    for (uint8_t i = 0; i < sps_count; ++i) {
        const uint16_t sps_len = readU16Be(avcc + pos);
        pos += 2U;
        annexb_out.insert(annexb_out.end(), kStartCode, kStartCode + 4U);
        annexb_out.insert(annexb_out.end(), avcc + pos, avcc + pos + sps_len);
        pos += sps_len;
    }
    const uint8_t pps_count = avcc[pos++];
    for (uint8_t i = 0; i < pps_count; ++i) {
        const uint16_t pps_len = readU16Be(avcc + pos);
        pos += 2U;
        annexb_out.insert(annexb_out.end(), kStartCode, kStartCode + 4U);
        annexb_out.insert(annexb_out.end(), avcc + pos, avcc + pos + pps_len);
        pos += pps_len;
    }
    return !annexb_out.empty();
}

}  // namespace stream
}  // namespace carplay
