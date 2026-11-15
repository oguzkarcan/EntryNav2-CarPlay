#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <pthread.h>
#endif

#include "carplay/platform/evo_mic.hpp"

#include <string>
#include <vector>

#include "carplay/platform/log.hpp"
#include "carplay/platform/thread.hpp"

namespace carplay {
namespace platform {

namespace {

static const char* const kTag = "evo_mic";

struct MicSyncLockCond {
#ifdef _WIN32
    CRITICAL_SECTION cs;
    CONDITION_VARIABLE cv;
    MicSyncLockCond() {
        InitializeCriticalSection(&cs);
        InitializeConditionVariable(&cv);
    }
    ~MicSyncLockCond() { DeleteCriticalSection(&cs); }
    void lock() { EnterCriticalSection(&cs); }
    void unlock() { LeaveCriticalSection(&cs); }
    void wait() { SleepConditionVariableCS(&cv, &cs, INFINITE); }
    void signal() { WakeConditionVariable(&cv); }
    void broadcast() { WakeAllConditionVariable(&cv); }
#else
    pthread_mutex_t mu;
    pthread_cond_t cv;
    MicSyncLockCond() {
        pthread_mutex_init(&mu, NULL);
        pthread_cond_init(&cv, NULL);
    }
    ~MicSyncLockCond() {
        pthread_cond_destroy(&cv);
        pthread_mutex_destroy(&mu);
    }
    void lock() { pthread_mutex_lock(&mu); }
    void unlock() { pthread_mutex_unlock(&mu); }
    void wait() { pthread_cond_wait(&cv, &mu); }
    void signal() { pthread_cond_signal(&cv); }
    void broadcast() { pthread_cond_broadcast(&cv); }
#endif

private:
    MicSyncLockCond(const MicSyncLockCond&) = delete;
    MicSyncLockCond& operator=(const MicSyncLockCond&) = delete;
};

struct MicScopedLock {
    explicit MicScopedLock(MicSyncLockCond& s) : s_(s) { s_.lock(); }
    ~MicScopedLock() { s_.unlock(); }

private:
    MicScopedLock(const MicScopedLock&) = delete;
    MicScopedLock& operator=(const MicScopedLock&) = delete;
    MicSyncLockCond& s_;
};

}  // namespace

// =================================================================================================
// EvoMicConfig / EvoMic
// =================================================================================================

EvoMicConfig::EvoMicConfig()
    : mic_device("mic1"), latency_us(100000U), soft_resample(1) {}

struct EvoMic::Impl {
    EvoMicConfig config;
    AlsaLoader loader;
    AlsaApi api;
    bool has_injected_api;

    MicSyncLockCond sync;
    Thread worker;
    bool started;
    bool quit;
    bool want_capture;
    uint64_t capture_gen;
    uint32_t sample_rate;
    uint32_t channels;
    uint32_t frames_per_read;

    PcmCallback cb;
    void* user;
    MediaEngine* engine;
    Stats stats;

    explicit Impl(const EvoMicConfig& cfg)
        : config(cfg),
          has_injected_api(false),
          started(false),
          quit(false),
          want_capture(false),
          capture_gen(0),
          sample_rate(16000U),
          channels(1U),
          frames_per_read(320U),
          cb(NULL),
          user(NULL),
          engine(NULL) {}

    ~Impl() { stop(); }

    static void workerEntry(void* arg) { static_cast<Impl*>(arg)->workerLoop(); }

    bool startInternal(PcmCallback pcm_cb, void* pcm_user, MediaEngine* target_engine) {
        MicScopedLock lock(sync);
        if (started) {
            cb = pcm_cb;
            user = pcm_user;
            engine = target_engine;
            return true;
        }
        if (!has_injected_api) {
            std::string err;
            if (!loader.load(AlsaLoader::kDefaultLibrary, &err)) {
                CARPLAY_LOG_ERROR(kTag, "cannot load ALSA: %s", err.c_str());
                return false;
            }
            api = loader.api();
        }
        if (!api.isCompleteCapture()) {
            CARPLAY_LOG_ERROR(kTag, "ALSA capture API incomplete");
            return false;
        }
        cb = pcm_cb;
        user = pcm_user;
        engine = target_engine;
        quit = false;
        want_capture = false;
        if (!worker.start(&Impl::workerEntry, this)) {
            CARPLAY_LOG_ERROR(kTag, "cannot start mic capture thread");
            return false;
        }
        started = true;
        return true;
    }

    void stop() {
        {
            MicScopedLock lock(sync);
            if (!started) {
                return;
            }
            quit = true;
            want_capture = false;
            capture_gen += 1;
            sync.broadcast();
        }
        worker.join();
        {
            MicScopedLock lock(sync);
            started = false;
            stats.capturing = false;
        }
    }

    void workerLoop() {
        std::vector<int16_t> buf;
        for (;;) {
            uint64_t my_gen = 0;
            uint32_t rate = 0;
            uint32_t ch = 0;
            uint32_t fpr = 0;
            {
                MicScopedLock lock(sync);
                while (!quit && !want_capture) {
                    sync.wait();
                }
                if (quit) {
                    return;
                }
                my_gen = capture_gen;
                rate = sample_rate;
                ch = channels;
                fpr = frames_per_read;
            }

            void* pcm = NULL;
            int err =
                api.snd_pcm_open(&pcm, config.mic_device.c_str(), alsa::kStreamCapture,
                                 alsa::kOpenBlock);
            if (err >= 0) {
                err = api.snd_pcm_set_params(pcm,
                                             alsa::kFormatS16Le,
                                             alsa::kAccessRwInterleaved,
                                             ch,
                                             rate,
                                             config.soft_resample,
                                             config.latency_us);
                if (err < 0 && pcm != NULL) {
                    api.snd_pcm_close(pcm);
                    pcm = NULL;
                }
            } else {
                pcm = NULL;
            }

            if (err < 0 || pcm == NULL) {
                CARPLAY_LOG_ERROR(kTag, "cannot open ALSA capture %s (%u Hz, %u ch): %s",
                                  config.mic_device.c_str(), rate, ch, api.snd_strerror(err));
                MicScopedLock lock(sync);
                stats.open_failures += 1;
                while (!quit && want_capture && capture_gen == my_gen) {
                    sync.wait();
                }
                if (quit) {
                    return;
                }
                continue;
            }

            {
                MicScopedLock lock(sync);
                if (quit || !want_capture || capture_gen != my_gen) {
                    // Cancelled while opening.
                    sync.unlock();
                    api.snd_pcm_close(pcm);
                    sync.lock();
                    continue;
                }
                stats.captures_started += 1;
                stats.capturing = true;
            }

            CARPLAY_LOG_INFO(kTag, "capturing %s (%u Hz, %u ch, %u frames/read)",
                             config.mic_device.c_str(), rate, ch, fpr);

            buf.resize(static_cast<size_t>(fpr) * ch);
            bool fatal_read_error = false;
            int zero_reads = 0;

            for (;;) {
                {
                    MicScopedLock lock(sync);
                    if (quit || !want_capture || capture_gen != my_gen) {
                        break;
                    }
                }
                const long n = api.snd_pcm_readi(pcm, &buf[0], fpr);
                if (n < 0) {
                    const int rerr = static_cast<int>(n);
                    const int rec = api.snd_pcm_recover(pcm, rerr, 1);
                    if (rec < 0) {
                        CARPLAY_LOG_ERROR(kTag, "ALSA capture read/recover failed on %s: %s",
                                          config.mic_device.c_str(), api.snd_strerror(rec));
                        MicScopedLock lock(sync);
                        stats.read_errors += 1;
                        fatal_read_error = true;
                        break;
                    }
                    MicScopedLock lock(sync);
                    stats.xrun_recoveries += 1;
                    continue;
                }
                if (n == 0) {
                    if (++zero_reads > 8) {
                        MicScopedLock lock(sync);
                        stats.read_errors += 1;
                        fatal_read_error = true;
                        break;
                    }
                    continue;
                }
                zero_reads = 0;

                bool deliver = false;
                PcmCallback cur_cb = NULL;
                void* cur_user = NULL;
                MediaEngine* cur_engine = NULL;
                {
                    MicScopedLock lock(sync);
                    if (!quit && want_capture && capture_gen == my_gen) {
                        deliver = true;
                        cur_cb = cb;
                        cur_user = user;
                        cur_engine = engine;
                        stats.frames_captured += static_cast<uint64_t>(n);
                    }
                }
                if (deliver) {
                    const size_t sample_count = static_cast<size_t>(n) * ch;
                    if (cur_cb != NULL) {
                        cur_cb(&buf[0], sample_count, cur_user);
                    } else if (cur_engine != NULL) {
                        cur_engine->submitMicrophonePcm(&buf[0], sample_count);
                    }
                }
            }

            api.snd_pcm_close(pcm);
            {
                MicScopedLock lock(sync);
                stats.capturing = false;
                stats.captures_stopped += 1;
                if (fatal_read_error) {
                    while (!quit && want_capture && capture_gen == my_gen) {
                        sync.wait();
                    }
                }
                if (quit) {
                    return;
                }
            }
        }
    }
};

EvoMic::EvoMic(const EvoMicConfig& config) : config_(config), impl_(new Impl(config)) {}

EvoMic::EvoMic(const AlsaApi& api, const EvoMicConfig& config)
    : config_(config), impl_(new Impl(config)) {
    impl_->api = api;
    impl_->has_injected_api = true;
}

EvoMic::~EvoMic() {
    stop();
    delete impl_;
    impl_ = NULL;
}

void EvoMic::setAlsaApi(const AlsaApi& api) {
    MicScopedLock lock(impl_->sync);
    impl_->api = api;
    impl_->has_injected_api = true;
}

bool EvoMic::start(PcmCallback cb, void* user) {
    if (cb == NULL) {
        return false;
    }
    return impl_->startInternal(cb, user, NULL);
}

bool EvoMic::start(MediaEngine& engine) {
    return impl_->startInternal(NULL, NULL, &engine);
}

void EvoMic::stop() { impl_->stop(); }

bool EvoMic::running() const {
    MicScopedLock lock(impl_->sync);
    return impl_->started;
}

bool EvoMic::startCapture(const audio::MicStreamParams& params) {
    if (!params.supported || params.format.sample_rate == 0 ||
        (params.format.channels != 1U && params.format.channels != 2U)) {
        return false;
    }
    MicScopedLock lock(impl_->sync);
    if (!impl_->started || impl_->quit) {
        return false;
    }
    impl_->sample_rate = params.format.sample_rate;
    impl_->channels = params.format.channels;
    uint32_t fpr = params.format.sample_rate / 50U;
    if (fpr == 0) {
        fpr = 1U;
    }
    impl_->frames_per_read = fpr;
    impl_->want_capture = true;
    impl_->capture_gen += 1;
    impl_->sync.signal();
    return true;
}

void EvoMic::stopCapture() {
    MicScopedLock lock(impl_->sync);
    if (!impl_->started) {
        return;
    }
    impl_->want_capture = false;
    impl_->capture_gen += 1;
    impl_->sync.signal();
}

EvoMic::Stats EvoMic::stats() const {
    MicScopedLock lock(impl_->sync);
    return impl_->stats;
}

// =================================================================================================
// EvoAudioMediaSink
// =================================================================================================

EvoAudioMediaSink::EvoAudioMediaSink(EvoAudioSink& audio_sink, EvoMic& mic, MediaSink* delegate)
    : audio_sink_(audio_sink),
      mic_(mic),
      delegate_(delegate),
      has_active_mic_(false),
      active_mic_id_() {}

void EvoAudioMediaSink::onScreenStreamActive(int32_t type, bool active) {
    if (delegate_ != NULL) {
        delegate_->onScreenStreamActive(type, active);
    }
}

void EvoAudioMediaSink::onVideoConfig(int32_t type,
                                      stream::VideoCodecType codec,
                                      const uint8_t* annexb_data,
                                      size_t annexb_len,
                                      const uint8_t* raw_config,
                                      size_t raw_len,
                                      float width_px,
                                      float height_px) {
    if (delegate_ != NULL) {
        delegate_->onVideoConfig(type, codec, annexb_data, annexb_len, raw_config, raw_len,
                                 width_px, height_px);
    }
}

void EvoAudioMediaSink::onVideoFrame(int32_t type,
                                     const uint8_t* annexb_data,
                                     size_t len,
                                     uint64_t sender_nanos,
                                     int64_t arrival_mono_nanos) {
    if (delegate_ != NULL) {
        delegate_->onVideoFrame(type, annexb_data, len, sender_nanos, arrival_mono_nanos);
    }
}

void EvoAudioMediaSink::onAudioStarted(const AudioStreamId& id,
                                       const audio::AudioFormat& format,
                                       uint32_t first_sample) {
    audio_sink_.onAudioStarted(id, format, first_sample);
    if (delegate_ != NULL) {
        delegate_->onAudioStarted(id, format, first_sample);
    }
}

void EvoAudioMediaSink::onAudioRtp(const AudioStreamId& id,
                                   const audio::AudioFormat& format,
                                   const audio::RtpHeader& header,
                                   const uint8_t* payload,
                                   size_t payload_len) {
    if (delegate_ != NULL) {
        delegate_->onAudioRtp(id, format, header, payload, payload_len);
    }
}

void EvoAudioMediaSink::onAudioPcm(const AudioStreamId& id,
                                   const audio::AudioFormat& format,
                                   const int16_t* samples,
                                   size_t sample_count,
                                   uint16_t sequence,
                                   uint32_t rtp_timestamp) {
    audio_sink_.onAudioPcm(id, format, samples, sample_count, sequence, rtp_timestamp);
    if (delegate_ != NULL) {
        delegate_->onAudioPcm(id, format, samples, sample_count, sequence, rtp_timestamp);
    }
}

void EvoAudioMediaSink::onAudioPacketLost(const AudioStreamId& id,
                                          const audio::AudioFormat& format,
                                          uint16_t lost_sequence) {
    audio_sink_.onAudioPacketLost(id, format, lost_sequence);
    if (delegate_ != NULL) {
        delegate_->onAudioPacketLost(id, format, lost_sequence);
    }
}

void EvoAudioMediaSink::onAudioStopped(const AudioStreamId& id) {
    audio_sink_.onAudioStopped(id);
    if (delegate_ != NULL) {
        delegate_->onAudioStopped(id);
    }
}

void EvoAudioMediaSink::onAudioDuck(bool ducked) {
    audio_sink_.onAudioDuck(ducked);
    if (delegate_ != NULL) {
        delegate_->onAudioDuck(ducked);
    }
}

void EvoAudioMediaSink::onMicrophoneStarted(const AudioStreamId& id,
                                            const audio::MicStreamParams& params,
                                            const Address& peer_dest) {
    has_active_mic_ = true;
    active_mic_id_ = id;
    mic_.startCapture(params);
    if (delegate_ != NULL) {
        delegate_->onMicrophoneStarted(id, params, peer_dest);
    }
}

void EvoAudioMediaSink::onMicrophoneStopped(const AudioStreamId& id) {
    if (has_active_mic_ && active_mic_id_ == id) {
        has_active_mic_ = false;
        mic_.stopCapture();
    }
    if (delegate_ != NULL) {
        delegate_->onMicrophoneStopped(id);
    }
}

void EvoAudioMediaSink::onIapMessage(const uint8_t* data, size_t len) {
    if (delegate_ != NULL) {
        delegate_->onIapMessage(data, len);
    }
}

}  // namespace platform
}  // namespace carplay
