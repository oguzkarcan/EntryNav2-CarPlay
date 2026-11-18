// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/airplay/AudioStream.kt,
//  shared/src/main/java/com/shilapi/xcertplay/airplay/MicrophonePacketizer.kt,
//  shared/src/main/java/com/shilapi/xcertplay/airplay/CarPlayMediaEngine.kt,
//  shared/src/main/java/com/shilapi/xcertplay/airplay/BufferedAudioStream.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.

#include "carplay/audio_rtp.hpp"

#include <string.h>

#include "carplay/airplay_crypto.hpp"

namespace carplay {
namespace audio {

namespace {

uint16_t readU16Be(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t readU32Be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

void writeU16Be(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

void writeU32Be(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

// Signed distance a - b on the 16-bit sequence circle, in [-32768, 32767].
int seqDiff(uint16_t a, uint16_t b) {
    const uint16_t d = static_cast<uint16_t>(a - b);
    return d < 0x8000U ? static_cast<int>(d) : static_cast<int>(d) - 0x10000;
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// RTP header
// ---------------------------------------------------------------------------------------------

bool parseRtpHeader(const uint8_t* data, size_t len, RtpHeader& out) {
    if (data == NULL || len < kRtpHeaderBytes) {
        return false;
    }
    out.version = static_cast<uint8_t>(data[0] >> 6);
    out.padding = (data[0] & 0x20U) != 0;
    out.extension = (data[0] & 0x10U) != 0;
    out.csrc_count = static_cast<uint8_t>(data[0] & 0x0fU);
    out.marker = (data[1] & 0x80U) != 0;
    out.payload_type = static_cast<uint8_t>(data[1] & 0x7fU);
    out.sequence = readU16Be(data + 2);
    out.timestamp = readU32Be(data + 4);
    out.ssrc = readU32Be(data + 8);
    return true;
}

void buildRtpHeader(uint8_t payload_type,
                    bool marker,
                    uint16_t sequence,
                    uint32_t timestamp,
                    uint32_t ssrc,
                    uint8_t header_out[kRtpHeaderBytes]) {
    header_out[0] = 0x80U;
    header_out[1] = static_cast<uint8_t>((payload_type & 0x7fU) | (marker ? 0x80U : 0x00U));
    writeU16Be(header_out + 2, sequence);
    writeU32Be(header_out + 4, timestamp);
    writeU32Be(header_out + 8, ssrc);
}

// ---------------------------------------------------------------------------------------------
// Packet open / seal
// ---------------------------------------------------------------------------------------------

namespace {

// Shared decrypt core: writes the plaintext into `out` starting at `out_offset`.
OpenResult openInto(const uint8_t key[32],
                    const uint8_t* packet,
                    size_t len,
                    RtpHeader* header_out,
                    std::vector<uint8_t>& out,
                    size_t out_offset) {
    out.clear();
    if (packet != NULL && len >= kRtpHeaderBytes && header_out != NULL) {
        parseRtpHeader(packet, len, *header_out);
    }
    if (packet == NULL || len < kMinPacketBytes) {
        return kOpenTooShort;
    }
    // AudioStream.kt:131-135 - aad = wire[4..12), sealed = wire[12..len-8), nonce = 0000|tail8.
    const size_t sealed_end = len - kNonceTailBytes;
    const size_t ciphertext_len = sealed_end - kRtpHeaderBytes - kTagBytes;
    uint8_t nonce[crypto::kNonceBytes];
    memset(nonce, 0, sizeof(nonce));
    memcpy(nonce + 4, packet + sealed_end, kNonceTailBytes);

    out.resize(out_offset + ciphertext_len);
    if (out_offset > 0) {
        memcpy(&out[0], packet, out_offset);
    }
    uint8_t dummy = 0;
    uint8_t* plain = ciphertext_len > 0 ? &out[out_offset] : &dummy;
    const bool ok = crypto::chacha20Poly1305OpenDetached(key,
                                                         nonce,
                                                         packet + kAadOffset,
                                                         kAadBytes,
                                                         packet + kRtpHeaderBytes,
                                                         ciphertext_len,
                                                         packet + kRtpHeaderBytes + ciphertext_len,
                                                         plain);
    if (!ok) {
        if (!out.empty()) {
            crypto::wipe(&out[0], out.size());
        }
        out.clear();
        return kOpenAuthFailed;
    }
    return kOpenOk;
}

}  // namespace

OpenResult openPacket(const uint8_t key[32],
                      const uint8_t* packet,
                      size_t len,
                      RtpHeader& header_out,
                      std::vector<uint8_t>& payload_out) {
    return openInto(key, packet, len, &header_out, payload_out, 0);
}

OpenResult openPacketToRtp(const uint8_t key[32],
                           const uint8_t* packet,
                           size_t len,
                           std::vector<uint8_t>& rtp_out,
                           RtpHeader* header_out) {
    if (packet == NULL || len < kMinPacketBytes) {
        rtp_out.clear();
        if (packet != NULL && header_out != NULL) {
            parseRtpHeader(packet, len, *header_out);
        }
        return kOpenTooShort;
    }
    return openInto(key, packet, len, header_out, rtp_out, kRtpHeaderBytes);
}

bool sealPacketWithTail(const uint8_t key[32],
                        const uint8_t header[kRtpHeaderBytes],
                        const uint8_t* payload,
                        size_t payload_len,
                        const uint8_t nonce_tail[kNonceTailBytes],
                        std::vector<uint8_t>& packet_out) {
    packet_out.clear();
    if (payload == NULL && payload_len != 0) {
        return false;
    }
    uint8_t nonce[crypto::kNonceBytes];
    memset(nonce, 0, sizeof(nonce));
    memcpy(nonce + 4, nonce_tail, kNonceTailBytes);

    packet_out.resize(kSealOverheadBytes + payload_len);
    memcpy(&packet_out[0], header, kRtpHeaderBytes);
    uint8_t dummy = 0;
    uint8_t* cipher = payload_len > 0 ? &packet_out[kRtpHeaderBytes] : &dummy;
    const uint8_t empty = 0;
    const bool ok = crypto::chacha20Poly1305SealDetached(key,
                                                         nonce,
                                                         header + kAadOffset,
                                                         kAadBytes,
                                                         payload_len > 0 ? payload : &empty,
                                                         payload_len,
                                                         cipher,
                                                         &packet_out[kRtpHeaderBytes + payload_len]);
    if (!ok) {
        packet_out.clear();
        return false;
    }
    memcpy(&packet_out[kRtpHeaderBytes + payload_len + kTagBytes], nonce_tail, kNonceTailBytes);
    return true;
}

bool sealPacket(const uint8_t key[32],
                const uint8_t header[kRtpHeaderBytes],
                const uint8_t* payload,
                size_t payload_len,
                uint64_t nonce_counter,
                std::vector<uint8_t>& packet_out) {
    uint8_t tail[kNonceTailBytes];
    for (size_t i = 0; i < kNonceTailBytes; ++i) {
        tail[i] = static_cast<uint8_t>(nonce_counter >> (8U * i));
    }
    return sealPacketWithTail(key, header, payload, payload_len, tail, packet_out);
}

// ---------------------------------------------------------------------------------------------
// Format mapping
// ---------------------------------------------------------------------------------------------

uint32_t opusClockRate(uint64_t format_bits) {
    if ((format_bits & kFormatOpus48k) != 0) {
        return 48000U;
    }
    if ((format_bits & kFormatOpus24k) != 0) {
        return 24000U;
    }
    if ((format_bits & kFormatOpus16k) != 0) {
        return 16000U;
    }
    return 48000U;
}

namespace {

struct PcmEntry {
    uint64_t bits;
    uint32_t rate;
    uint32_t channels;
};

const PcmEntry kPcmTable[] = {
    {0x4ULL, 8000U, 1U},     {0x8ULL, 8000U, 2U},     {0x10ULL, 16000U, 1U},  {0x20ULL, 16000U, 2U},
    {0x40ULL, 24000U, 1U},   {0x80ULL, 24000U, 2U},   {0x100ULL, 32000U, 1U}, {0x200ULL, 32000U, 2U},
    {0x400ULL, 44100U, 1U},  {0x800ULL, 44100U, 2U},  {0x4000ULL, 48000U, 1U}, {0x8000ULL, 48000U, 2U},
};

}  // namespace

AudioFormat formatFromBits(uint64_t format_bits, int payload_type, const std::string& audio_type) {
    AudioFormat f;
    f.payload_type = payload_type;
    f.audio_type = audio_type;
    const bool is_opus = (format_bits & (kFormatOpus16k | kFormatOpus24k | kFormatOpus48k)) != 0;
    const bool is_aac = (format_bits & (kFormatAacLc44kStereo | kFormatAacLc48kStereo)) != 0;
    if (is_opus) {
        f.codec = kCodecOpus;
        f.sample_rate = 48000U;
        f.channels = 1U;
        f.rtp_clock_rate = opusClockRate(format_bits);
        return f;
    }
    if (is_aac) {
        f.codec = kCodecAacLc;
        f.sample_rate = (format_bits & kFormatAacLc48kStereo) != 0 ? 48000U : 44100U;
        f.channels = 2U;
        f.rtp_clock_rate = f.sample_rate;
        return f;
    }
    // PCM_FORMAT[bits] in the reference is an exact-key map lookup.
    for (size_t i = 0; i < sizeof(kPcmTable) / sizeof(kPcmTable[0]); ++i) {
        if (kPcmTable[i].bits == format_bits) {
            f.codec = kCodecLpcm;
            f.sample_rate = kPcmTable[i].rate;
            f.channels = kPcmTable[i].channels;
            f.rtp_clock_rate = f.sample_rate;
            return f;
        }
    }
    f.codec = kCodecLpcm;
    f.sample_rate = 44100U;
    f.channels = 2U;
    f.rtp_clock_rate = 44100U;
    return f;
}

// ---------------------------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------------------------

std::string unsignedDecimal(uint64_t value) {
    char buf[24];
    size_t pos = sizeof(buf);
    buf[--pos] = '\0';
    do {
        buf[--pos] = static_cast<char>('0' + static_cast<int>(value % 10U));
        value /= 10U;
    } while (value != 0);
    return std::string(buf + pos);
}

std::string dataStreamSalt(uint64_t stream_connection_id) {
    return std::string(kDataStreamSaltPrefix) + unsignedDecimal(stream_connection_id);
}

bool deriveDataStreamKey(const uint8_t* shared_secret,
                         size_t shared_secret_len,
                         uint64_t stream_connection_id,
                         const std::string& info_label,
                         uint8_t key_out[32]) {
    if (shared_secret == NULL || shared_secret_len == 0) {
        return false;
    }
    const std::string salt = dataStreamSalt(stream_connection_id);
    return crypto::hkdfSha512(shared_secret,
                              shared_secret_len,
                              reinterpret_cast<const uint8_t*>(salt.data()),
                              salt.size(),
                              reinterpret_cast<const uint8_t*>(info_label.data()),
                              info_label.size(),
                              key_out,
                              32U);
}

bool deriveAudioOutputKey(const uint8_t* shared_secret,
                          size_t shared_secret_len,
                          uint64_t stream_connection_id,
                          uint8_t key_out[32]) {
    return deriveDataStreamKey(shared_secret, shared_secret_len, stream_connection_id,
                               std::string(kDataStreamOutputKeyInfo), key_out);
}

bool deriveAudioInputKey(const uint8_t* shared_secret,
                         size_t shared_secret_len,
                         uint64_t stream_connection_id,
                         uint8_t key_out[32]) {
    return deriveDataStreamKey(shared_secret, shared_secret_len, stream_connection_id,
                               std::string(kDataStreamInputKeyInfo), key_out);
}

// ---------------------------------------------------------------------------------------------
// LPCM
// ---------------------------------------------------------------------------------------------

size_t lpcmToInt16(const uint8_t* payload,
                   size_t len,
                   std::vector<int16_t>& samples_out,
                   SampleByteOrder order) {
    const size_t count = payload != NULL ? len / 2U : 0U;
    samples_out.resize(count);
    for (size_t i = 0; i < count; ++i) {
        const uint8_t a = payload[2U * i];
        const uint8_t b = payload[2U * i + 1U];
        const uint16_t u = order == kBigEndianSamples
                               ? static_cast<uint16_t>((static_cast<uint16_t>(a) << 8) | b)
                               : static_cast<uint16_t>((static_cast<uint16_t>(b) << 8) | a);
        // Two's complement reinterpretation without implementation-defined narrowing.
        samples_out[i] = u < 0x8000U ? static_cast<int16_t>(u)
                                     : static_cast<int16_t>(static_cast<int>(u) - 0x10000);
    }
    return count;
}

void int16ToLpcm(const int16_t* samples,
                 size_t count,
                 std::vector<uint8_t>& payload_out,
                 SampleByteOrder order) {
    if (samples == NULL) {
        count = 0;
    }
    payload_out.resize(count * 2U);
    for (size_t i = 0; i < count; ++i) {
        const uint16_t u = static_cast<uint16_t>(samples[i]);
        const uint8_t hi = static_cast<uint8_t>(u >> 8);
        const uint8_t lo = static_cast<uint8_t>(u);
        payload_out[2U * i] = order == kBigEndianSamples ? hi : lo;
        payload_out[2U * i + 1U] = order == kBigEndianSamples ? lo : hi;
    }
}

// ---------------------------------------------------------------------------------------------
// JitterBuffer
// ---------------------------------------------------------------------------------------------

const size_t JitterBuffer::kDefaultCapacity;
const uint16_t JitterBuffer::kDefaultReorderDepth;

JitterBuffer::JitterBuffer(size_t capacity, uint16_t reorder_depth)
    : slots_(), head_(0), count_(0), reorder_depth_(1), next_seq_(0), highest_seq_(0), started_(false),
      stats_() {
    if (capacity < 2U) {
        capacity = 2U;
    }
    if (capacity > 32768U) {
        capacity = 32768U;
    }
    slots_.resize(capacity);
    if (reorder_depth < 1U) {
        reorder_depth = 1U;
    }
    if (reorder_depth > capacity - 1U) {
        reorder_depth = static_cast<uint16_t>(capacity - 1U);
    }
    reorder_depth_ = reorder_depth;
}

void JitterBuffer::advanceOne() {
    head_ = (head_ + 1U) % slots_.size();
    next_seq_ = static_cast<uint16_t>(next_seq_ + 1U);
}

JitterBuffer::PushResult JitterBuffer::push(uint16_t sequence,
                                            uint32_t timestamp,
                                            const uint8_t* payload,
                                            size_t len) {
    ++stats_.received;
    if (payload == NULL) {
        len = 0;
    }
    if (!started_) {
        started_ = true;
        next_seq_ = sequence;
        highest_seq_ = sequence;
        head_ = 0;
    }

    const int rel = seqDiff(sequence, next_seq_);
    if (rel < 0) {
        ++stats_.late;
        return kPushTooLate;
    }

    PushResult result = kPushAccepted;
    const size_t cap = slots_.size();
    size_t delta = static_cast<size_t>(rel);
    if (delta >= cap) {
        // Advance the window so `sequence` lands in the last slot.
        const size_t need = delta - cap + 1U;
        size_t dropped = 0;
        const size_t examine = need < cap ? need : cap;
        for (size_t i = 0; i < examine; ++i) {
            Slot& s = slots_[(head_ + i) % cap];
            if (s.used) {
                s.used = false;
                s.payload.clear();
                --count_;
                ++dropped;
            }
        }
        stats_.overflow_dropped += dropped;
        stats_.lost += need - dropped;
        head_ = (head_ + need) % cap;
        next_seq_ = static_cast<uint16_t>(next_seq_ + need);
        delta = cap - 1U;
        result = kPushOverflowDroppedOldest;
    }

    Slot& slot = slots_[(head_ + delta) % cap];
    if (slot.used) {
        ++stats_.duplicates;
        return kPushDuplicate;
    }
    slot.used = true;
    slot.sequence = sequence;
    slot.timestamp = timestamp;
    if (len > 0) {
        slot.payload.assign(payload, payload + len);
    } else {
        slot.payload.clear();
    }
    ++count_;
    ++stats_.accepted;
    if (seqDiff(sequence, highest_seq_) < 0) {
        ++stats_.reordered;
    } else {
        highest_seq_ = sequence;
    }
    return result;
}

JitterBuffer::PopResult JitterBuffer::pop(Packet& out) {
    if (!started_ || count_ == 0) {
        return kPopEmpty;
    }
    Slot& slot = slots_[head_];
    if (slot.used) {
        out.sequence = slot.sequence;
        out.timestamp = slot.timestamp;
        out.payload.swap(slot.payload);
        slot.payload.clear();
        slot.used = false;
        --count_;
        ++stats_.delivered;
        advanceOne();
        return kPopPacket;
    }
    // Missing head with later packets buffered: declare it lost once far enough behind.
    if (seqDiff(highest_seq_, next_seq_) >= static_cast<int>(reorder_depth_)) {
        out.sequence = next_seq_;
        out.timestamp = 0;
        out.payload.clear();
        ++stats_.lost;
        advanceOne();
        return kPopLost;
    }
    return kPopEmpty;
}

void JitterBuffer::flush() {
    for (size_t i = 0; i < slots_.size(); ++i) {
        slots_[i].used = false;
        slots_[i].payload.clear();
    }
    head_ = 0;
    count_ = 0;
    next_seq_ = 0;
    highest_seq_ = 0;
    started_ = false;
}

void JitterBuffer::reset() {
    flush();
    stats_ = Stats();
}

}  // namespace audio
}  // namespace carplay
