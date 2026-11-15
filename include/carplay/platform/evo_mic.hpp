#ifndef CARPLAY_PLATFORM_EVO_MIC_HPP
#define CARPLAY_PLATFORM_EVO_MIC_HPP

// BMW HU_ENTRYNAV2 ALSA microphone capture ("mic1") and composite MediaSink wiring.
//
// Reads 20 ms chunks (sample_rate / 50 frames) via libasound.so.2 loaded at runtime (or an
// injected AlsaApi for tests) on a dedicated worker thread that stays idle until startCapture() /
// onMicrophoneStarted() is called.

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "carplay/mic_uplink.hpp"
#include "carplay/platform/evo_audio.hpp"
#include "carplay/platform/media_engine.hpp"

namespace carplay {
namespace platform {

struct EvoMicConfig {
    std::string mic_device;   // default "mic1"
    unsigned int latency_us;  // default 100000 (100 ms)
    int soft_resample;        // default 1

    EvoMicConfig();
};

class EvoMic {
public:
    typedef void (*PcmCallback)(const int16_t* samples, size_t sample_count, void* user);

    struct Stats {
        uint64_t captures_started;
        uint64_t captures_stopped;
        uint64_t open_failures;
        uint64_t frames_captured;
        uint64_t xrun_recoveries;
        uint64_t read_errors;
        bool capturing;

        Stats()
            : captures_started(0),
              captures_stopped(0),
              open_failures(0),
              frames_captured(0),
              xrun_recoveries(0),
              read_errors(0),
              capturing(false) {}
    };

    explicit EvoMic(const EvoMicConfig& config = EvoMicConfig());
    EvoMic(const AlsaApi& api, const EvoMicConfig& config = EvoMicConfig());
    ~EvoMic();

    /// Injects a custom AlsaApi (must be called before start()).
    void setAlsaApi(const AlsaApi& api);

    /// Starts the idle capture worker thread delivering samples to `cb(samples, sample_count, user)`.
    bool start(PcmCallback cb, void* user);
    /// Starts the idle capture worker thread delivering samples to `engine.submitMicrophonePcm()`.
    bool start(MediaEngine& engine);
    /// Stops any active capture and joins the worker thread.
    void stop();
    bool running() const;

    /// Non-blocking capture control (safe from the reactor thread).
    bool startCapture(const audio::MicStreamParams& params);
    void stopCapture();

    Stats stats() const;
    const EvoMicConfig& config() const { return config_; }

private:
    EvoMic(const EvoMic&) = delete;
    EvoMic& operator=(const EvoMic&) = delete;

    struct Impl;
    EvoMicConfig config_;
    Impl* impl_;
};

/// Composite MediaSink wiring EvoAudioSink + EvoMic (plus an optional delegate MediaSink).
class EvoAudioMediaSink : public MediaSink {
public:
    EvoAudioMediaSink(EvoAudioSink& audio_sink, EvoMic& mic, MediaSink* delegate = NULL);
    virtual ~EvoAudioMediaSink() {}

    void setDelegate(MediaSink* delegate) { delegate_ = delegate; }

    virtual void onScreenStreamActive(int32_t type, bool active);
    virtual void onVideoConfig(int32_t type,
                               stream::VideoCodecType codec,
                               const uint8_t* annexb_data,
                               size_t annexb_len,
                               const uint8_t* raw_config,
                               size_t raw_len,
                               float width_px,
                               float height_px);
    virtual void onVideoFrame(int32_t type,
                              const uint8_t* annexb_data,
                              size_t len,
                              uint64_t sender_nanos,
                              int64_t arrival_mono_nanos);

    virtual void onAudioStarted(const AudioStreamId& id,
                                const audio::AudioFormat& format,
                                uint32_t first_sample);
    virtual void onAudioRtp(const AudioStreamId& id,
                            const audio::AudioFormat& format,
                            const audio::RtpHeader& header,
                            const uint8_t* payload,
                            size_t payload_len);
    virtual void onAudioPcm(const AudioStreamId& id,
                            const audio::AudioFormat& format,
                            const int16_t* samples,
                            size_t sample_count,
                            uint16_t sequence,
                            uint32_t rtp_timestamp);
    virtual void onAudioPacketLost(const AudioStreamId& id,
                                   const audio::AudioFormat& format,
                                   uint16_t lost_sequence);
    virtual void onAudioStopped(const AudioStreamId& id);
    virtual void onAudioDuck(bool ducked);

    virtual void onMicrophoneStarted(const AudioStreamId& id,
                                     const audio::MicStreamParams& params,
                                     const Address& peer_dest);
    virtual void onMicrophoneStopped(const AudioStreamId& id);

    virtual void onIapMessage(const uint8_t* data, size_t len);

private:
    EvoAudioMediaSink(const EvoAudioMediaSink&) = delete;
    EvoAudioMediaSink& operator=(const EvoAudioMediaSink&) = delete;

    EvoAudioSink& audio_sink_;
    EvoMic& mic_;
    MediaSink* delegate_;
    bool has_active_mic_;
    AudioStreamId active_mic_id_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_EVO_MIC_HPP
