#ifndef CARPLAY_SCREEN_STREAM_HPP
#define CARPLAY_SCREEN_STREAM_HPP

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace carplay {
namespace stream {

static const size_t kScreenHeaderBytes = 128U;
static const size_t kOpcodeOffset = 4U;
static const size_t kSenderNtpOffset = 8U;

enum ScreenOpcode {
    kOpVideoFrame = 0U,
    kOpVideoConfig = 1U
};

enum VideoCodecType {
    CODEC_UNKNOWN = 0,
    CODEC_H264_AVCC,
    CODEC_HEVC_HVCC,
    CODEC_ANNEX_B
};

struct ScreenPacketHeader {
    uint32_t payload_size;
    uint16_t opcode;
    uint16_t flags;
    uint64_t ntp_timestamp;
    uint64_t sender_nanos;
    float width_px;
    float height_px;

    ScreenPacketHeader()
        : payload_size(0),
          opcode(0),
          flags(0),
          ntp_timestamp(0),
          sender_nanos(0),
          width_px(0.0f),
          height_px(0.0f) {}
};

/// Parses a 128-byte AirPlay screen stream header.
bool parseScreenHeader(const uint8_t* header_bytes,
                       size_t len,
                       ScreenPacketHeader& out,
                       std::string* error_out = NULL);

/// Converts NTP 32.32 fixed-point timestamp (upper 32s = sec, lower 32s = frac) to nanoseconds.
uint64_t ntpToNanos(uint64_t ntp_fixed);

/// Decrypts an AirPlay screen frame payload in-place or out-of-place using ChaCha20-Poly1305 IETF AEAD
/// (`counter` -> 12-byte counter nonce, detached 16-byte MAC tag).
bool decryptFrame(const uint8_t key[32],
                  uint64_t counter,
                  const uint8_t* aad,
                  size_t aad_len,
                  const uint8_t* ciphertext,
                  size_t ciphertext_len,
                  const uint8_t tag[16],
                  std::vector<uint8_t>& plaintext_out);

/// Decrypts an encrypted screen frame in-place over `data[0..len)` using `tag[16]`.
bool decryptFrameInPlace(const uint8_t key[32],
                         const uint8_t nonce[12],
                         const uint8_t* aad,
                         size_t aad_len,
                         uint8_t* data,
                         size_t len,
                         const uint8_t tag[16]);

/// Converts 4-byte big-endian length-prefixed AVCC/HVCC NAL units in-place to Annex B `00 00 00 01`.
/// Returns false if any NAL unit length is malformed or extends past `len`.
bool lengthPrefixedToAnnexBInPlace(uint8_t* data, size_t len);
bool lengthPrefixedToAnnexB(std::vector<uint8_t>& buffer);

/// Detects whether a screen config payload is an ISO/BMFF `avcC`, `hvcC`, or raw Annex B stream.
VideoCodecType detectConfigCodec(const uint8_t* data, size_t len);

/// Extracts SPS and PPS NAL units from an H.264 `avcC` decoder configuration record into Annex B format
/// (`00 00 00 01 | SPS | 00 00 00 01 | PPS`) suitable for BMW EntryNav2 EvoVideo.
bool avcCToAnnexB(const uint8_t* avcc,
                  size_t len,
                  std::vector<uint8_t>& annexb_out,
                  uint8_t* nal_length_bytes_out = NULL);

}  // namespace stream
}  // namespace carplay

#endif  // CARPLAY_SCREEN_STREAM_HPP
