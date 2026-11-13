#ifndef CARPLAY_AUDIO_RTP_HPP
#define CARPLAY_AUDIO_RTP_HPP

// CarPlay realtime audio (stream types 100 / 101 / 102) RTP handling.
//
// Pure byte-in / byte-out logic: no sockets, no threads, no clocks. The socket layer (later
// phase) receives one UDP datagram per RTP packet and hands it to openPacket(); decrypted
// payloads go through the JitterBuffer and then to a decoder (AAC-LC / Opus decoders are out
// of scope here) or, for LPCM, through lpcmToInt16().
//
// Wire layout (DiPlay AudioStream.kt runData, lines ~131-139, and MicrophonePacketizer.kt):
//
//   [12-byte RTP header (clear)][ChaCha20-Poly1305 ciphertext][16-byte tag][8-byte nonce tail]
//
//   AAD   = RTP header bytes 4..11 (timestamp + SSRC); bytes 0..3 are NOT authenticated.
//   nonce = [0,0,0,0 | tail8], the 8 trailing packet bytes copied verbatim into nonce[4..11]
//           (the sender writes a little-endian u64 counter there, see MicrophonePacketizer.kt).

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

namespace carplay {
namespace audio {

static const size_t kRtpHeaderBytes = 12U;
static const size_t kAadOffset = 4U;
static const size_t kAadBytes = 8U;
static const size_t kTagBytes = 16U;
static const size_t kNonceTailBytes = 8U;
static const size_t kSealOverheadBytes = kRtpHeaderBytes + kTagBytes + kNonceTailBytes;  // 36
static const size_t kMinPacketBytes = kSealOverheadBytes;

// CarPlay audio stream types (AirPlaySession.kt / CarPlayMediaEngine.kt / BufferedAudioStream.kt).
static const int kStreamTypeMainAudio = 100;
static const int kStreamTypeAltAudio = 101;
static const int kStreamTypeMainHighAudio = 102;
static const int kStreamTypeMainBufferedAudio = 103;  // NOT implemented here (TCP, shk key).

// ---------------------------------------------------------------------------------------------
// RTP header
// ---------------------------------------------------------------------------------------------

struct RtpHeader {
    uint8_t version;       // 2 bits
    bool padding;          // P
    bool extension;        // X
    uint8_t csrc_count;    // CC, 4 bits
    bool marker;           // M
    uint8_t payload_type;  // 7 bits
    uint16_t sequence;
    uint32_t timestamp;
    uint32_t ssrc;

    RtpHeader()
        : version(0),
          padding(false),
          extension(false),
          csrc_count(0),
          marker(false),
          payload_type(0),
          sequence(0),
          timestamp(0),
          ssrc(0) {}
};

/// Parses the fixed 12-byte RTP header fields. Returns false if len < 12. No validation of the
/// version / CC / X bits is done (the reference does none either; the payload always starts at
/// byte 12 on CarPlay audio).
bool parseRtpHeader(const uint8_t* data, size_t len, RtpHeader& out);

/// Writes a 12-byte RTP header: V=2, P=0, X=0, CC=0, M=marker, PT=payload_type & 0x7f,
/// big-endian sequence / timestamp / ssrc (MicrophonePacketizer.kt sealPacket layout).
void buildRtpHeader(uint8_t payload_type,
                    bool marker,
                    uint16_t sequence,
                    uint32_t timestamp,
                    uint32_t ssrc,
                    uint8_t header_out[kRtpHeaderBytes]);

// ---------------------------------------------------------------------------------------------
// Packet open / seal
// ---------------------------------------------------------------------------------------------

enum OpenResult {
    kOpenOk = 0,
    kOpenTooShort,    // len < 36 (header + tag + nonce tail)
    kOpenAuthFailed   // ChaCha20-Poly1305 tag did not verify
};

/// Decrypts one audio datagram. On kOpenOk fills header_out and payload_out (the decrypted RTP
/// payload, possibly empty). On failure payload_out is cleared; header_out is filled whenever
/// len >= 12 (useful for diagnostics, like the reference's `sample` on auth failure).
OpenResult openPacket(const uint8_t key[32],
                      const uint8_t* packet,
                      size_t len,
                      RtpHeader& header_out,
                      std::vector<uint8_t>& payload_out);

/// Same as openPacket but produces the reference's `rtp` form: the 12 clear header bytes
/// followed by the decrypted payload (AudioStream.kt: `wire.copyOf(RTP_HEADER_LEN) + payload`).
/// header_out may be NULL.
OpenResult openPacketToRtp(const uint8_t key[32],
                           const uint8_t* packet,
                           size_t len,
                           std::vector<uint8_t>& rtp_out,
                           RtpHeader* header_out = NULL);

/// Exact inverse of openPacket: header (12 bytes, copied verbatim) | ciphertext | tag | tail8.
/// The nonce is [0,0,0,0 | nonce_tail]. Returns false only on crypto failure.
bool sealPacketWithTail(const uint8_t key[32],
                        const uint8_t header[kRtpHeaderBytes],
                        const uint8_t* payload,
                        size_t payload_len,
                        const uint8_t nonce_tail[kNonceTailBytes],
                        std::vector<uint8_t>& packet_out);

/// Convenience: the tail is the little-endian u64 `nonce_counter` (MicrophonePacketizer.kt
/// putU64Le), i.e. the nonce equals crypto::makeCounterNonce(nonce_counter).
bool sealPacket(const uint8_t key[32],
                const uint8_t header[kRtpHeaderBytes],
                const uint8_t* payload,
                size_t payload_len,
                uint64_t nonce_counter,
                std::vector<uint8_t>& packet_out);

// ---------------------------------------------------------------------------------------------
// audioFormat bits -> codec mapping (port of AudioStreamCodec.fromFormatBits)
// ---------------------------------------------------------------------------------------------

enum CodecKind {
    kCodecAacLc = 0,
    kCodecOpus,
    kCodecLpcm
};

struct AudioFormat {
    CodecKind codec;
    uint32_t sample_rate;     // decode/render rate (Opus is always decoded at 48 kHz)
    uint32_t channels;
    int payload_type;         // the reference passes the stream type (100/101/102) here
    uint32_t rtp_clock_rate;  // RTP timestamp rate; == sample_rate except for Opus
    std::string audio_type;   // "media", "telephony", "speechrecognition", "default", ...

    AudioFormat()
        : codec(kCodecLpcm), sample_rate(44100U), channels(2U), payload_type(0), rtp_clock_rate(44100U),
          audio_type("media") {}
};

static const uint64_t kFormatAacLc44kStereo = 0x400000ULL;
static const uint64_t kFormatAacLc48kStereo = 0x800000ULL;
static const uint64_t kFormatOpus16k = 0x10000000ULL;
static const uint64_t kFormatOpus24k = 0x20000000ULL;
static const uint64_t kFormatOpus48k = 0x40000000ULL;

/// MicrophoneConfig.opusClockRate: 0x40000000 -> 48000, 0x20000000 -> 24000,
/// 0x10000000 -> 16000 (checked in that order), otherwise 48000.
uint32_t opusClockRate(uint64_t format_bits);

/// Port of AudioStreamCodec.fromFormatBits. Precedence: any Opus bit -> Opus 48k mono with
/// rtp_clock_rate = opusClockRate(bits); else any AAC-LC bit -> AAC-LC stereo (48k if 0x800000
/// set, else 44.1k); else an EXACT match in the PCM table (0x4..0x8000); else LPCM 44100/2.
AudioFormat formatFromBits(uint64_t format_bits, int payload_type, const std::string& audio_type = "media");

// ---------------------------------------------------------------------------------------------
// Per-stream key derivation (CarPlayMediaEngine.kt dataStreamKey / outputKey, lines ~620-678)
// ---------------------------------------------------------------------------------------------

static const char kDataStreamSaltPrefix[] = "DataStream-Salt";
/// Downlink (iPhone -> accessory) audio, screen and data-stream decryption key label.
static const char kDataStreamOutputKeyInfo[] = "DataStream-Output-Encryption-Key";
/// Uplink (accessory -> iPhone) microphone encryption key label.
static const char kDataStreamInputKeyInfo[] = "DataStream-Input-Encryption-Key";

/// Unsigned decimal rendering of a 64-bit id ("18446744073709551615" for 2^64-1).
std::string unsignedDecimal(uint64_t value);

/// "DataStream-Salt" + unsignedDecimal(stream_connection_id).
std::string dataStreamSalt(uint64_t stream_connection_id);

/// HKDF-SHA512(ikm = shared_secret, salt = dataStreamSalt(id), info = info_label, L = 32).
bool deriveDataStreamKey(const uint8_t* shared_secret,
                         size_t shared_secret_len,
                         uint64_t stream_connection_id,
                         const std::string& info_label,
                         uint8_t key_out[32]);

/// Realtime audio (types 100/101/102) downlink key: info "DataStream-Output-Encryption-Key".
bool deriveAudioOutputKey(const uint8_t* shared_secret,
                          size_t shared_secret_len,
                          uint64_t stream_connection_id,
                          uint8_t key_out[32]);

/// Microphone uplink key for the same stream: info "DataStream-Input-Encryption-Key".
bool deriveAudioInputKey(const uint8_t* shared_secret,
                         size_t shared_secret_len,
                         uint64_t stream_connection_id,
                         uint8_t key_out[32]);

// ---------------------------------------------------------------------------------------------
// LPCM
// ---------------------------------------------------------------------------------------------

enum SampleByteOrder {
    kBigEndianSamples = 0,  // CarPlay wire LPCM (downlink AND microphone uplink)
    kLittleEndianSamples
};

/// Converts an LPCM RTP payload of interleaved signed 16-bit samples to host-order int16.
/// CarPlay wire LPCM is big-endian (AndroidMediaSink.kt:2255 byte-swaps the RTP payload with
/// byteSwapS16 before writing it to an ENCODING_PCM_16BIT (little-endian) AudioTrack;
/// MicrophonePacketizer.kt:128 "CarPlay's wired microphone payload is big-endian").
/// A trailing odd byte is ignored. Returns the number of samples written (out is resized).
size_t lpcmToInt16(const uint8_t* payload,
                   size_t len,
                   std::vector<int16_t>& samples_out,
                   SampleByteOrder order = kBigEndianSamples);

/// Inverse of lpcmToInt16 (for the microphone uplink). Appends nothing; out is resized.
void int16ToLpcm(const int16_t* samples,
                 size_t count,
                 std::vector<uint8_t>& payload_out,
                 SampleByteOrder order = kBigEndianSamples);

// ---------------------------------------------------------------------------------------------
// Jitter / reorder buffer
// ---------------------------------------------------------------------------------------------

/// Fixed-capacity, sequence-ordered reorder buffer, 16-bit wraparound safe. Purely driven by
/// push()/pop(); never sleeps or reads a clock.
///
///  - The first pushed packet after construction / flush() anchors the expected sequence.
///  - A packet whose sequence is older than the next sequence to deliver is kPushTooLate
///    (already delivered, or already declared lost).
///  - A packet that does not fit in the window (seq - next >= capacity) advances the window:
///    buffered packets falling out of it are dropped (counted in overflow_dropped), never
///    received slots skipped over are counted lost, and kPushOverflowDroppedOldest is returned
///    (the new packet IS stored).
///  - pop() delivers the next packet if present. If it is missing while later packets are
///    buffered, it waits until the highest received sequence is at least `reorder_depth`
///    ahead of the missing one, then returns kPopLost once for it (consumer conceals).
///  - Payload buffers are recycled: pop() swaps the slot buffer with out.payload, so reusing
///    one Packet object keeps the steady state allocation-free once buffers have grown.
class JitterBuffer {
public:
    static const size_t kDefaultCapacity = 64U;
    static const uint16_t kDefaultReorderDepth = 4U;

    enum PushResult {
        kPushAccepted = 0,
        kPushDuplicate,
        kPushTooLate,
        kPushOverflowDroppedOldest
    };

    enum PopResult {
        kPopEmpty = 0,  // nothing deliverable yet
        kPopPacket,     // out holds the next in-order packet
        kPopLost        // out.sequence is a lost packet (payload empty); conceal it
    };

    struct Packet {
        uint16_t sequence;
        uint32_t timestamp;
        std::vector<uint8_t> payload;

        Packet() : sequence(0), timestamp(0) {}
    };

    struct Stats {
        uint64_t received;          // every push() call
        uint64_t accepted;          // stored packets (incl. overflow case)
        uint64_t duplicates;
        uint64_t late;
        uint64_t lost;              // missing sequences skipped (pop gap or overflow skip)
        uint64_t reordered;         // stored packets older than the highest seen sequence
        uint64_t overflow_dropped;  // buffered packets evicted by window overflow
        uint64_t delivered;         // kPopPacket results

        Stats()
            : received(0), accepted(0), duplicates(0), late(0), lost(0), reordered(0),
              overflow_dropped(0), delivered(0) {}
    };

    /// capacity is clamped to [2, 32768]; reorder_depth to [1, capacity - 1].
    explicit JitterBuffer(size_t capacity = kDefaultCapacity, uint16_t reorder_depth = kDefaultReorderDepth);

    PushResult push(uint16_t sequence, uint32_t timestamp, const uint8_t* payload, size_t len);
    PopResult pop(Packet& out);

    /// Drops buffered packets and re-anchors on the next push (FLUSH / TEARDOWN). Keeps stats.
    void flush();
    /// flush() + zero the counters.
    void reset();

    size_t size() const { return count_; }
    size_t capacity() const { return slots_.size(); }
    uint16_t reorderDepth() const { return reorder_depth_; }
    bool anchored() const { return started_; }
    uint16_t nextSequence() const { return next_seq_; }
    const Stats& stats() const { return stats_; }

private:
    struct Slot {
        bool used;
        uint16_t sequence;
        uint32_t timestamp;
        std::vector<uint8_t> payload;

        Slot() : used(false), sequence(0), timestamp(0) {}
    };

    void advanceOne();

    std::vector<Slot> slots_;
    size_t head_;
    size_t count_;
    uint16_t reorder_depth_;
    uint16_t next_seq_;
    uint16_t highest_seq_;
    bool started_;
    Stats stats_;
};

}  // namespace audio
}  // namespace carplay

#endif  // CARPLAY_AUDIO_RTP_HPP
