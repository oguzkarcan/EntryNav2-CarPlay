#ifndef CARPLAY_MIC_UPLINK_HPP
#define CARPLAY_MIC_UPLINK_HPP

// CarPlay microphone uplink (accessory -> iPhone) as pure logic: stream-SETUP parsing and RTP
// packetisation. No sockets, no ALSA, no clocks; the platform layer captures host-order int16 PCM,
// feeds it to MicPacketizer and sends each produced datagram to the phone's UDP `dataPort` at the
// control peer's address.
//
// Behaviour ported from DiPlay (GPLv3, read for behaviour only):
//   - CarPlayMediaEngine.kt:178        audioType = stream["audioType"] lowercased, default "default"
//   - CarPlayMediaEngine.kt:190-194    format = AudioStreamCodec.fromFormatBits(audioFormat ?: 0, type, ..)
//   - CarPlayMediaEngine.kt:624-663    microphoneConfig: only type 100, wantsMicrophone, destination port
//                                      = the stream's own "dataPort" (1..65535), key = DataStream INPUT
//                                      key of streamConnectionID, payloadType = the stream TYPE (100),
//                                      frameMillis from framesPerPacket / pcmFrameMillis
//   - CarPlayMediaEngine.kt:689-697    wantsMicrophone(audioType, stream)
//   - MicrophonePacketizer.kt:25-41    samplesPerPacket / rtpClockRate / rtpSamplesPerPacket / frameBytes
//   - MicrophonePacketizer.kt:63-70    pcmFrameMillis (20/10/5 ms fitting a 1452-byte UDP payload)
//   - MicrophonePacketizer.kt:75-79    counters start at sequence 0, timestamp 0, nonce 0
//   - MicrophonePacketizer.kt:95-126   sealPacket: header [0x80, pt & 0x7f, seq16 BE, ts32 BE, SSRC 0],
//                                      nonce [0,0,0,0 | nonce u64 LE], AAD = header[4..12), packet =
//                                      header | ct | tag16 | nonce u64 LE; afterwards sequence =
//                                      (sequence + 1) & 0xffff, timestamp += samples, nonce += 1
//   - MicrophonePacketizer.kt:128-139  toWirePcm: samples are BIG-endian on the wire
//   - MicrophoneUplink.kt:282-284, 392-421  one frame of frameBytes per packet, samples =
//                                      rtpSamplesPerPacket
//
// Opus uplink is out of scope: a stream whose format is Opus (or AAC) is reported as unsupported.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/audio_rtp.hpp"
#include "carplay/bplist_codec.hpp"

namespace carplay {
namespace audio {

/// Bytes a sealed packet adds to its payload (RTP header + tag + nonce tail) = 36.
static const size_t kMicSealOverhead = kSealOverheadBytes;
/// 1500-byte link MTU minus IPv6 (40) and UDP (8) headers.
static const size_t kMicMaxUdpPayload = 1452U;
/// Opus constants of the reference (only used to report what an Opus stream would need).
static const uint32_t kMicOpusSamplesPerPacket = 960U;
static const uint32_t kMicOpusFrameMillis = 20U;

/// CarPlayMediaEngine.kt:178 + 190-194: the stream's lowercased `audioType` (default "default" when
/// absent or not a string) and formatFromBits(`audioFormat` as a number, else 0, payload_type = type).
AudioFormat streamAudioFormat(const bplist::Value& stream, int32_t type);

/// The `audioFormat` number of a SETUP entry (Kotlin (x as? Number)?.toLong() ?: 0).
uint64_t streamAudioFormatBits(const bplist::Value& stream);

/// wantsMicrophone (CarPlayMediaEngine.kt:689-697). audio_type must already be lowercased.
bool streamWantsMicrophone(const std::string& audio_type, const bplist::Value& stream);

/// MicrophoneConfig.pcmFrameMillis: the first of 20, 10, 5 ms whose sealed packet
/// (36 + rate * ms / 1000 * channels * 2 bytes, integer arithmetic) fits kMicMaxUdpPayload; else 5.
uint32_t micPcmFrameMillis(uint32_t sample_rate, uint32_t channels);

/// What the uplink of one SETUP stream needs (MicrophoneConfig minus host / key).
struct MicStreamParams {
    int32_t data_port;               // phone's UDP port for the microphone datagrams (stream "dataPort")
    uint8_t payload_type;            // RTP payload type = stream type (100)
    uint64_t format_bits;            // raw audioFormat
    AudioFormat format;              // streamAudioFormat()
    int32_t frames_per_packet;       // stream "framesPerPacket" (0 when absent)
    uint32_t frame_millis;           // 20 for Opus; round(fpp * 1000 / rate) in [5, 60]; else pcmFrameMillis
    uint32_t samples_per_packet;     // per channel: 960 for Opus, else max(1, rate * frame_millis / 1000)
    uint32_t rtp_samples_per_packet; // RTP timestamp step: Opus opusClockRate * 20 / 1000, else samples_per_packet
    bool supported;                  // LPCM with 1 or 2 channels (Opus / AAC uplink out of scope)

    MicStreamParams()
        : data_port(0), payload_type(0), format_bits(0), format(), frames_per_packet(0), frame_millis(0),
          samples_per_packet(0), rtp_samples_per_packet(0), supported(false) {}

    /// Host-order int16 samples per packet (samples_per_packet * channels).
    size_t samplesPerFrame() const { return static_cast<size_t>(samples_per_packet) * format.channels; }
    /// Wire payload bytes per packet (MicrophoneConfig.frameBytes).
    size_t frameBytes() const { return samplesPerFrame() * 2U; }
};

/// microphoneConfig (CarPlayMediaEngine.kt:624-663) without the host / key: returns true and fills
/// `out` when the stream wants a microphone: microphone_enabled (AirPlayConfig::microphone), type ==
/// 100, streamWantsMicrophone, and a numeric "dataPort" in 1..65535. The key comes separately from
/// Session::streamInputKey(stream) (the reference also returns no microphone when that fails), the
/// destination host is the control peer's address. `out.supported` is false for Opus / AAC: the
/// caller must then not start capture.
bool parseMicrophoneStream(int32_t type, const bplist::Value& stream, bool microphone_enabled, MicStreamParams& out);

/// MicrophoneCounters (all start at 0).
struct MicCounters {
    uint16_t sequence;
    uint32_t timestamp;
    uint64_t nonce;
    MicCounters() : sequence(0), timestamp(0), nonce(0) {}
};

/// MicrophonePacketizer.sealPacket: seals `body` (already in wire byte order) and advances the
/// counters (sequence + 1 mod 2^16, timestamp + rtp_samples mod 2^32, nonce + 1). Returns false (and
/// leaves the counters untouched) only on a crypto / argument failure.
bool sealMicrophonePacket(const uint8_t key[32],
                          uint8_t payload_type,
                          MicCounters& counters,
                          const uint8_t* body,
                          size_t body_len,
                          uint32_t rtp_samples,
                          std::vector<uint8_t>& packet_out);

/// Frames captured host-order int16 PCM into sealed LPCM datagrams for one microphone stream.
/// Non-copyable; the key is wiped on reset()/destruction.
class MicPacketizer {
public:
    MicPacketizer();
    ~MicPacketizer();

    /// Starts a new uplink (counters at 0, pending samples dropped). false when params are not
    /// supported (not LPCM, channels not 1/2, samples_per_packet 0) or key is NULL.
    bool configure(const MicStreamParams& params, const uint8_t key[32]);
    bool configured() const { return configured_; }

    /// Seals exactly one frame (params.samplesPerFrame() host-order samples, interleaved). false when
    /// not configured or count differs.
    bool sealFrame(const int16_t* samples, size_t count, std::vector<uint8_t>& packet_out);

    /// Buffers any number of samples and appends one datagram per complete frame to packets_out
    /// (the reference fills a frame buffer from the recorder and sends each full frame). Returns the
    /// number of packets appended; leftover samples stay buffered for the next call.
    size_t push(const int16_t* samples, size_t count, std::vector<std::vector<uint8_t> >& packets_out);

    /// Wipes the key and forgets everything (configured() becomes false).
    void reset();

    const MicCounters& counters() const { return counters_; }
    const MicStreamParams& params() const { return params_; }
    size_t pendingSamples() const { return pending_.size(); }

private:
    MicPacketizer(const MicPacketizer&) = delete;
    MicPacketizer& operator=(const MicPacketizer&) = delete;

    bool configured_;
    uint8_t key_[32];
    MicStreamParams params_;
    MicCounters counters_;
    std::vector<int16_t> pending_;
    std::vector<uint8_t> wire_;
};

}  // namespace audio
}  // namespace carplay

#endif  // CARPLAY_MIC_UPLINK_HPP
