#include "carplay/mic_uplink.hpp"

#include <math.h>
#include <string.h>

#include "carplay/airplay_crypto.hpp"
#include "carplay/airplay_session.hpp"  // plistNumberToLong / plistNumberToInt (Kotlin Number casts)

namespace carplay {
namespace audio {

namespace {

const int32_t kStreamTypeMainAudioI = 100;

std::string lowerAscii(const std::string& s) {
    std::string out(s);
    for (size_t i = 0; i < out.size(); ++i) {
        if (out[i] >= 'A' && out[i] <= 'Z') out[i] = static_cast<char>(out[i] - 'A' + 'a');
    }
    return out;
}

// (stream[key] as? Number)?.toInt(); false when absent or not a number.
bool numberField(const bplist::Value& stream, const char* key, int32_t& out) {
    const bplist::Value* v = stream.find(key);
    return v != NULL && session::plistNumberToInt(*v, out);
}

}  // namespace

uint64_t streamAudioFormatBits(const bplist::Value& stream) {
    const bplist::Value* v = stream.find("audioFormat");
    int64_t bits = 0;
    if (v == NULL || !session::plistNumberToLong(*v, bits)) return 0U;
    return static_cast<uint64_t>(bits);
}

AudioFormat streamAudioFormat(const bplist::Value& stream, int32_t type) {
    std::string audio_type = "default";
    const bplist::Value* at = stream.find("audioType");
    if (at != NULL && at->isString()) audio_type = lowerAscii(at->asString());
    return formatFromBits(streamAudioFormatBits(stream), type, audio_type);
}

bool streamWantsMicrophone(const std::string& audio_type, const bplist::Value& stream) {
    if (audio_type == "telephony" || audio_type == "speechrecognition") return true;
    if (audio_type != "default" && audio_type != "compatibility") return false;
    const bplist::Value* input = stream.find("input");
    if (input != NULL && input->isBool()) return input->asBool();
    int32_t n = 0;
    if (input != NULL && session::plistNumberToInt(*input, n)) return n != 0;
    int32_t port = 0;
    return numberField(stream, "dataPort", port) && port >= 1 && port <= 65535;
}

uint32_t micPcmFrameMillis(uint32_t sample_rate, uint32_t channels) {
    const uint32_t candidates[3] = {20U, 10U, 5U};
    for (size_t i = 0; i < 3; ++i) {
        const uint64_t bytes = static_cast<uint64_t>(sample_rate) * candidates[i] / 1000U * channels * 2U;
        if (kMicSealOverhead + bytes <= kMicMaxUdpPayload) return candidates[i];
    }
    return 5U;
}

bool parseMicrophoneStream(int32_t type, const bplist::Value& stream, bool microphone_enabled, MicStreamParams& out) {
    if (!microphone_enabled || type != kStreamTypeMainAudioI || !stream.isDict()) return false;
    const AudioFormat format = streamAudioFormat(stream, type);
    if (!streamWantsMicrophone(format.audio_type, stream)) return false;
    int32_t port = 0;
    if (!numberField(stream, "dataPort", port) || port < 1 || port > 65535) return false;

    MicStreamParams p;
    p.data_port = port;
    p.payload_type = static_cast<uint8_t>(type & 0x7f);
    p.format_bits = streamAudioFormatBits(stream);
    p.format = format;
    int32_t fpp = 0;
    if (!numberField(stream, "framesPerPacket", fpp)) fpp = 0;
    p.frames_per_packet = fpp;
    const bool opus = format.codec == kCodecOpus;
    if (opus) {
        p.frame_millis = kMicOpusFrameMillis;
    } else if (fpp > 0) {
        // Math.round(fpp * 1000.0 / sampleRate).toInt().coerceIn(5, 60)
        const double ms = floor(static_cast<double>(fpp) * 1000.0 / format.sample_rate + 0.5);
        p.frame_millis = ms < 5.0 ? 5U : (ms > 60.0 ? 60U : static_cast<uint32_t>(ms));
    } else {
        p.frame_millis = micPcmFrameMillis(format.sample_rate, format.channels);
    }
    if (opus) {
        p.samples_per_packet = kMicOpusSamplesPerPacket;
        p.rtp_samples_per_packet = opusClockRate(p.format_bits) * kMicOpusFrameMillis / 1000U;
    } else {
        const uint32_t n = format.sample_rate * p.frame_millis / 1000U;
        p.samples_per_packet = n < 1U ? 1U : n;
        p.rtp_samples_per_packet = p.samples_per_packet;
    }
    p.supported = format.codec == kCodecLpcm && (format.channels == 1U || format.channels == 2U);
    out = p;
    return true;
}

bool sealMicrophonePacket(const uint8_t key[32],
                          uint8_t payload_type,
                          MicCounters& counters,
                          const uint8_t* body,
                          size_t body_len,
                          uint32_t rtp_samples,
                          std::vector<uint8_t>& packet_out) {
    if (key == NULL) return false;
    uint8_t header[kRtpHeaderBytes];
    // SSRC is never written by the reference (stays 0); marker 0.
    buildRtpHeader(payload_type, false, counters.sequence, counters.timestamp, 0U, header);
    if (!sealPacket(key, header, body, body_len, counters.nonce, packet_out)) return false;
    counters.sequence = static_cast<uint16_t>(counters.sequence + 1U);
    counters.timestamp = static_cast<uint32_t>(counters.timestamp + rtp_samples);
    counters.nonce = counters.nonce + 1U;
    return true;
}

MicPacketizer::MicPacketizer() : configured_(false), params_(), counters_(), pending_(), wire_() {
    memset(key_, 0, sizeof(key_));
}

MicPacketizer::~MicPacketizer() { reset(); }

void MicPacketizer::reset() {
    crypto::wipe(key_, sizeof(key_));
    configured_ = false;
    params_ = MicStreamParams();
    counters_ = MicCounters();
    // Captured cabin audio: do not leave it behind in freed heap memory.
    if (!pending_.empty()) crypto::wipe(&pending_[0], pending_.size() * sizeof(pending_[0]));
    pending_.clear();
    if (!wire_.empty()) crypto::wipe(&wire_[0], wire_.size());
    wire_.clear();
}

bool MicPacketizer::configure(const MicStreamParams& params, const uint8_t key[32]) {
    reset();
    if (key == NULL || !params.supported || params.format.codec != kCodecLpcm) return false;
    if (params.format.channels != 1U && params.format.channels != 2U) return false;
    if (params.samples_per_packet == 0U) return false;
    memcpy(key_, key, sizeof(key_));
    params_ = params;
    configured_ = true;
    return true;
}

bool MicPacketizer::sealFrame(const int16_t* samples, size_t count, std::vector<uint8_t>& packet_out) {
    if (!configured_ || samples == NULL || count != params_.samplesPerFrame()) return false;
    int16ToLpcm(samples, count, wire_, kBigEndianSamples);
    return sealMicrophonePacket(key_, params_.payload_type, counters_, &wire_[0], wire_.size(),
                                params_.rtp_samples_per_packet, packet_out);
}

size_t MicPacketizer::push(const int16_t* samples, size_t count, std::vector<std::vector<uint8_t> >& packets_out) {
    if (!configured_ || samples == NULL || count == 0) return 0;
    pending_.insert(pending_.end(), samples, samples + count);
    const size_t frame = params_.samplesPerFrame();
    size_t produced = 0;
    size_t offset = 0;
    while (pending_.size() - offset >= frame) {
        std::vector<uint8_t> packet;
        if (!sealFrame(&pending_[offset], frame, packet)) break;
        packets_out.push_back(packet);
        ++produced;
        offset += frame;
    }
    pending_.erase(pending_.begin(), pending_.begin() + static_cast<long>(offset));
    return produced;
}

}  // namespace audio
}  // namespace carplay
