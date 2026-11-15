#ifndef CARPLAY_PLATFORM_EVO_AUDIO_HPP
#define CARPLAY_PLATFORM_EVO_AUDIO_HPP

// BMW HU_ENTRYNAV2 ALSA audio playback sinks and runtime libasound.so.2 loader.
//
// Zero link-time dependency on libasound: AlsaLoader resolves libasound.so.2 entry points at
// runtime via dlopen/dlsym (using memcpy for pedantic ISO C++ safety). Tests can inject a custom
// AlsaApi struct directly.
//
// Non-blocking reactor seam:
//   * onAudioStarted / onAudioPcm / onAudioPacketLost / onAudioStopped / onAudioDuck never block
//     on ALSA I/O. PCM frames are copied into a bounded per-stream ring buffer and consumed by a
//     dedicated playback worker thread.
//   * Target ALSA devices (/etc/asound.conf):
//       - stream.type == 101                                       -> "carplay_alt" (1ch mono)
//       - audio_type == "telephony" or "speechrecognition"         -> "tel_out1" (1ch mono)
//       - otherwise (100/102 "media", "default", "alert", ...)     -> "entertainment" (2ch stereo)
//   * Stereo -> mono downmix ((L + R) / 2) and mono -> stereo upmix are applied automatically when
//     a stream's source channel count differs from the target ALSA channel count.
//   * Ducking attenuates main media ("entertainment") streams while leaving "carplay_alt" and
//     "tel_out1" at full unity volume.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/audio_rtp.hpp"
#include "carplay/platform/media_engine.hpp"

namespace carplay {
namespace platform {

// ALSA ABI constants (from <alsa/asoundlib.h>).
namespace alsa {
static const int kStreamPlayback = 0;       // SND_PCM_STREAM_PLAYBACK
static const int kStreamCapture = 1;        // SND_PCM_STREAM_CAPTURE
static const int kFormatS16Le = 2;          // SND_PCM_FORMAT_S16_LE
static const int kAccessRwInterleaved = 3;  // SND_PCM_ACCESS_RW_INTERLEAVED
static const int kOpenBlock = 0;            // blocking mode
}  // namespace alsa

/// Function table for libasound.so.2 symbols resolved at runtime (or mocked in unit tests).
struct AlsaApi {
    typedef int (*OpenFn)(void** pcm, const char* name, int stream, int mode);
    typedef int (*SetParamsFn)(void* pcm,
                               int format,
                               int access,
                               unsigned int channels,
                               unsigned int rate,
                               int soft_resample,
                               unsigned int latency_us);
    typedef long (*WriteiFn)(void* pcm, const void* buffer, unsigned long size);
    typedef long (*ReadiFn)(void* pcm, void* buffer, unsigned long size);
    typedef int (*RecoverFn)(void* pcm, int err, int silent);
    typedef int (*PrepareFn)(void* pcm);
    typedef int (*DropFn)(void* pcm);
    typedef int (*DrainFn)(void* pcm);
    typedef int (*CloseFn)(void* pcm);
    typedef const char* (*StrerrorFn)(int errnum);

    OpenFn snd_pcm_open;
    SetParamsFn snd_pcm_set_params;
    WriteiFn snd_pcm_writei;
    ReadiFn snd_pcm_readi;
    RecoverFn snd_pcm_recover;
    PrepareFn snd_pcm_prepare;
    DropFn snd_pcm_drop;
    DrainFn snd_pcm_drain;
    CloseFn snd_pcm_close;
    StrerrorFn snd_strerror;

    AlsaApi();

    bool isCompletePlayback() const;
    bool isCompleteCapture() const;
    bool isComplete() const;
};

/// Loads libasound.so.2 at runtime via dlopen/dlsym (no-op stub returning false on _WIN32).
class AlsaLoader {
public:
    static const char* const kDefaultLibrary;  // "libasound.so.2"

    AlsaLoader();
    ~AlsaLoader();

    bool load(const char* library_path = kDefaultLibrary, std::string* error_out = NULL);
    void unload();

    bool loaded() const { return loaded_; }
    const AlsaApi& api() const { return api_; }
    const std::string& lastError() const { return last_error_; }

private:
    AlsaLoader(const AlsaLoader&) = delete;
    AlsaLoader& operator=(const AlsaLoader&) = delete;

    void* lib_;
    AlsaApi api_;
    bool loaded_;
    std::string last_error_;
};

/// Configuration for ALSA playback routing, channel adaptation, buffering, and ducking.
struct EvoAudioConfig {
    std::string media_device;      // default "entertainment"
    std::string alt_device;        // default "carplay_alt"
    std::string telephony_device;  // default "tel_out1"

    /// Target ALSA channel count per role (0 = match incoming stream format.channels).
    unsigned int media_channels;      // default 2
    unsigned int alt_channels;        // default 1
    unsigned int telephony_channels;  // default 1

    unsigned int latency_us;          // default 100000 (100 ms)
    int soft_resample;                // default 1
    uint32_t max_queue_ms;            // default 500 ms bounded queue per stream
    int32_t duck_gain_q15;            // default 8192 (~0.25, -12 dB; 32768 = unity)
    bool duck_on_alt_stream;          // default false: auto-duck media when alt stream is open
    bool conceal_packet_loss;         // default false: queue 20 ms silence on onAudioPacketLost

    EvoAudioConfig();
};

/// Selects the target ALSA PCM device name for a CarPlay audio stream.
std::string selectAlsaDevice(const AudioStreamId& id, const EvoAudioConfig& cfg);

/// Selects the target ALSA channel count for a CarPlay audio stream.
unsigned int selectAlsaChannels(const AudioStreamId& id,
                                const audio::AudioFormat& format,
                                const EvoAudioConfig& cfg);

/// Converts interleaved int16 PCM between mono and stereo (or copies when channel counts match).
/// Stereo -> mono uses (L + R) / 2; mono -> stereo duplicates M -> (M, M).
/// Returns number of frames written to `out`.
size_t adaptChannelsS16(const int16_t* samples,
                        size_t frame_count,
                        unsigned int src_channels,
                        unsigned int dst_channels,
                        std::vector<int16_t>& out);

/// Applies Q15 gain (32768 == 1.0) in-place with int16 saturation.
void applyGainQ15S16(int16_t* samples, size_t sample_count, int32_t gain_q15);

/// Non-blocking ALSA playback sink managing concurrent CarPlay audio streams on a worker thread.
class EvoAudioSink {
public:
    struct Stats {
        uint64_t streams_opened;
        uint64_t streams_closed;
        uint64_t open_failures;
        uint64_t frames_written;
        uint64_t overrun_frames;
        uint64_t underrun_recoveries;
        uint64_t write_errors;
        uint64_t packet_loss_events;
        size_t active_streams;

        Stats()
            : streams_opened(0),
              streams_closed(0),
              open_failures(0),
              frames_written(0),
              overrun_frames(0),
              underrun_recoveries(0),
              write_errors(0),
              packet_loss_events(0),
              active_streams(0) {}
    };

    explicit EvoAudioSink(const EvoAudioConfig& config = EvoAudioConfig());
    EvoAudioSink(const AlsaApi& api, const EvoAudioConfig& config = EvoAudioConfig());
    ~EvoAudioSink();

    /// Injects a custom AlsaApi (must be called before start()).
    void setAlsaApi(const AlsaApi& api);

    /// Starts the playback worker thread. If no AlsaApi was injected, loads libasound.so.2.
    /// Returns false if libasound symbols are unavailable or thread creation fails.
    bool start();
    /// Stops all streams, joins the worker thread, and releases ALSA handles.
    void stop();
    bool running() const;

    /// MediaSink-compatible audio lifecycle (non-blocking; safe to call from the reactor thread).
    void onAudioStarted(const AudioStreamId& id,
                        const audio::AudioFormat& format,
                        uint32_t first_sample);
    void onAudioPcm(const AudioStreamId& id,
                    const audio::AudioFormat& format,
                    const int16_t* samples,
                    size_t sample_count,
                    uint16_t sequence,
                    uint32_t rtp_timestamp);
    void onAudioPacketLost(const AudioStreamId& id,
                           const audio::AudioFormat& format,
                           uint16_t lost_sequence);
    void onAudioStopped(const AudioStreamId& id);
    void onAudioDuck(bool ducked);

    void setDucked(bool ducked);
    bool isDucked() const;

    /// Closes all active streams without stopping the worker thread.
    void stopAll();

    Stats stats() const;
    const EvoAudioConfig& config() const { return config_; }

private:
    EvoAudioSink(const EvoAudioSink&) = delete;
    EvoAudioSink& operator=(const EvoAudioSink&) = delete;

    struct Impl;
    EvoAudioConfig config_;
    Impl* impl_;
};

typedef EvoAudioSink EvoAudioRouter;

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_EVO_AUDIO_HPP
