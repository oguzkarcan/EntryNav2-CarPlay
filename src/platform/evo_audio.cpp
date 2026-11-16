#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#include <pthread.h>
#endif

#include "carplay/platform/evo_audio.hpp"

#include <string.h>

#include <algorithm>
#include <string>
#include <vector>

#include "carplay/platform/log.hpp"
#include "carplay/platform/thread.hpp"

namespace carplay {
namespace platform {

namespace {

static const char* const kTag = "evo_audio";
static const int32_t kUnityGainQ15 = 32768;

std::string toLowerAscii(const std::string& s) {
    std::string out(s);
    for (size_t i = 0; i < out.size(); ++i) {
        if (out[i] >= 'A' && out[i] <= 'Z') {
            out[i] = static_cast<char>(out[i] - 'A' + 'a');
        }
    }
    return out;
}

enum StreamRole {
    kRoleMedia = 0,
    kRoleAlt = 1,
    kRoleTelephony = 2
};

StreamRole classifyStreamRole(const AudioStreamId& id) {
    if (id.type == audio::kStreamTypeAltAudio) {
        return kRoleAlt;
    }
    const std::string lower = toLowerAscii(id.audio_type);
    if (lower == "telephony" || lower == "speechrecognition") {
        return kRoleTelephony;
    }
    return kRoleMedia;
}

#ifndef _WIN32
template <typename Fn>
bool resolveSymbol(void* lib, const char* name, Fn& out, std::string& error_out) {
    typedef char CheckFnSize[sizeof(Fn) == sizeof(void*) ? 1 : -1];
    (void)sizeof(CheckFnSize);
    (void)dlerror();
    void* sym = dlsym(lib, name);
    const char* err = dlerror();
    if (sym == NULL || err != NULL) {
        error_out = std::string("missing ALSA symbol ") + name +
                    (err != NULL ? (std::string(": ") + err) : std::string());
        out = NULL;
        return false;
    }
    memcpy(&out, &sym, sizeof(out));
    return true;
}
#endif

// Portable mutex + condition variable pair (pthread on POSIX, Win32 CRITICAL_SECTION +
// CONDITION_VARIABLE on Windows).
struct SyncLockCond {
#ifdef _WIN32
    CRITICAL_SECTION cs;
    CONDITION_VARIABLE cv;
    SyncLockCond() {
        InitializeCriticalSection(&cs);
        InitializeConditionVariable(&cv);
    }
    ~SyncLockCond() { DeleteCriticalSection(&cs); }
    void lock() { EnterCriticalSection(&cs); }
    void unlock() { LeaveCriticalSection(&cs); }
    void wait() { SleepConditionVariableCS(&cv, &cs, INFINITE); }
    void signal() { WakeConditionVariable(&cv); }
    void broadcast() { WakeAllConditionVariable(&cv); }
#else
    pthread_mutex_t mu;
    pthread_cond_t cv;
    SyncLockCond() {
        pthread_mutex_init(&mu, NULL);
        pthread_cond_init(&cv, NULL);
    }
    ~SyncLockCond() {
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
    SyncLockCond(const SyncLockCond&) = delete;
    SyncLockCond& operator=(const SyncLockCond&) = delete;
};

struct ScopedSyncLock {
    explicit ScopedSyncLock(SyncLockCond& s) : s_(s) { s_.lock(); }
    ~ScopedSyncLock() { s_.unlock(); }

private:
    ScopedSyncLock(const ScopedSyncLock&) = delete;
    ScopedSyncLock& operator=(const ScopedSyncLock&) = delete;
    SyncLockCond& s_;
};

// Bounded frame-aligned ring buffer for interleaved int16 PCM samples.
struct PcmRingBuffer {
    std::vector<int16_t> buf;
    size_t head;
    size_t count;

    PcmRingBuffer() : head(0), count(0) {}

    void reset(size_t capacity_samples) {
        buf.assign(capacity_samples, 0);
        head = 0;
        count = 0;
    }

    void clear() {
        head = 0;
        count = 0;
    }

    bool empty() const { return count == 0; }

    // Drops oldest whole frames on overflow; returns number of dropped frames.
    size_t pushFrames(const int16_t* samples, size_t frame_count, unsigned int channels) {
        if (samples == NULL || frame_count == 0 || channels == 0 || buf.empty()) {
            return 0;
        }
        const size_t cap = buf.size();
        const size_t cap_frames = cap / channels;
        if (cap_frames == 0) {
            return frame_count;
        }
        size_t dropped_frames = 0;
        size_t to_write_frames = frame_count;
        const int16_t* src = samples;
        if (to_write_frames > cap_frames) {
            dropped_frames += (to_write_frames - cap_frames);
            src += (to_write_frames - cap_frames) * channels;
            to_write_frames = cap_frames;
        }
        const size_t incoming_samples = to_write_frames * channels;
        const size_t max_usable_samples = cap_frames * channels;
        if (count + incoming_samples > max_usable_samples) {
            const size_t need_drop_samples = (count + incoming_samples) - max_usable_samples;
            const size_t drop_frames = (need_drop_samples + channels - 1U) / channels;
            const size_t drop_samples = drop_frames * channels;
            if (drop_samples >= count) {
                dropped_frames += count / channels;
                head = 0;
                count = 0;
            } else {
                dropped_frames += drop_frames;
                head = (head + drop_samples) % cap;
                count -= drop_samples;
            }
        }
        const size_t tail = (head + count) % cap;
        size_t first = cap - tail;
        if (first > incoming_samples) {
            first = incoming_samples;
        }
        memcpy(&buf[tail], src, first * sizeof(int16_t));
        if (incoming_samples > first) {
            memcpy(&buf[0], src + first, (incoming_samples - first) * sizeof(int16_t));
        }
        count += incoming_samples;
        return dropped_frames;
    }

    size_t popFrames(size_t max_frames, unsigned int channels, std::vector<int16_t>& out) {
        out.clear();
        if (channels == 0 || count < channels || max_frames == 0) {
            return 0;
        }
        const size_t avail_frames = count / channels;
        const size_t take_frames = (max_frames < avail_frames) ? max_frames : avail_frames;
        const size_t take_samples = take_frames * channels;
        const size_t cap = buf.size();
        out.resize(take_samples);
        size_t first = cap - head;
        if (first > take_samples) {
            first = take_samples;
        }
        memcpy(&out[0], &buf[head], first * sizeof(int16_t));
        if (take_samples > first) {
            memcpy(&out[first], &buf[0], (take_samples - first) * sizeof(int16_t));
        }
        head = (head + take_samples) % cap;
        count -= take_samples;
        return take_frames;
    }
};

}  // namespace

// =================================================================================================
// AlsaApi / AlsaLoader
// =================================================================================================

AlsaApi::AlsaApi()
    : snd_pcm_open(NULL),
      snd_pcm_set_params(NULL),
      snd_pcm_writei(NULL),
      snd_pcm_readi(NULL),
      snd_pcm_recover(NULL),
      snd_pcm_prepare(NULL),
      snd_pcm_drop(NULL),
      snd_pcm_drain(NULL),
      snd_pcm_close(NULL),
      snd_strerror(NULL) {}

bool AlsaApi::isCompletePlayback() const {
    return snd_pcm_open != NULL && snd_pcm_set_params != NULL && snd_pcm_writei != NULL &&
           snd_pcm_recover != NULL && snd_pcm_drop != NULL && snd_pcm_close != NULL &&
           snd_strerror != NULL;
}

bool AlsaApi::isCompleteCapture() const {
    return snd_pcm_open != NULL && snd_pcm_set_params != NULL && snd_pcm_readi != NULL &&
           snd_pcm_recover != NULL && snd_pcm_close != NULL && snd_strerror != NULL;
}

bool AlsaApi::isComplete() const {
    return isCompletePlayback() && isCompleteCapture() && snd_pcm_prepare != NULL &&
           snd_pcm_drain != NULL;
}

const char* const AlsaLoader::kDefaultLibrary = "libasound.so.2";

AlsaLoader::AlsaLoader() : lib_(NULL), loaded_(false) {}

AlsaLoader::~AlsaLoader() { unload(); }

bool AlsaLoader::load(const char* library_path, std::string* error_out) {
    unload();
    if (library_path == NULL || library_path[0] == '\0') {
        last_error_ = "empty ALSA library path";
        if (error_out != NULL) {
            *error_out = last_error_;
        }
        return false;
    }
#ifdef _WIN32
    (void)library_path;
    last_error_ = "ALSA is not supported on Windows";
    if (error_out != NULL) {
        *error_out = last_error_;
    }
    return false;
#else
    (void)dlerror();
    lib_ = dlopen(library_path, RTLD_NOW | RTLD_LOCAL);
    if (lib_ == NULL) {
        const char* err = dlerror();
        last_error_ = std::string("dlopen(") + library_path + ") failed" +
                      (err != NULL ? (std::string(": ") + err) : std::string());
        if (error_out != NULL) {
            *error_out = last_error_;
        }
        return false;
    }

    AlsaApi resolved;
    std::string sym_err;
    const bool ok =
        resolveSymbol(lib_, "snd_pcm_open", resolved.snd_pcm_open, sym_err) &&
        resolveSymbol(lib_, "snd_pcm_set_params", resolved.snd_pcm_set_params, sym_err) &&
        resolveSymbol(lib_, "snd_pcm_writei", resolved.snd_pcm_writei, sym_err) &&
        resolveSymbol(lib_, "snd_pcm_readi", resolved.snd_pcm_readi, sym_err) &&
        resolveSymbol(lib_, "snd_pcm_recover", resolved.snd_pcm_recover, sym_err) &&
        resolveSymbol(lib_, "snd_pcm_prepare", resolved.snd_pcm_prepare, sym_err) &&
        resolveSymbol(lib_, "snd_pcm_drop", resolved.snd_pcm_drop, sym_err) &&
        resolveSymbol(lib_, "snd_pcm_drain", resolved.snd_pcm_drain, sym_err) &&
        resolveSymbol(lib_, "snd_pcm_close", resolved.snd_pcm_close, sym_err) &&
        resolveSymbol(lib_, "snd_strerror", resolved.snd_strerror, sym_err);
    if (!ok) {
        dlclose(lib_);
        lib_ = NULL;
        last_error_ = sym_err;
        if (error_out != NULL) {
            *error_out = last_error_;
        }
        return false;
    }

    api_ = resolved;
    loaded_ = true;
    last_error_.clear();
    if (error_out != NULL) {
        error_out->clear();
    }
    return true;
#endif
}

void AlsaLoader::unload() {
#ifndef _WIN32
    if (lib_ != NULL) {
        dlclose(lib_);
        lib_ = NULL;
    }
#endif
    api_ = AlsaApi();
    loaded_ = false;
}

// =================================================================================================
// Config & Helpers
// =================================================================================================

EvoAudioConfig::EvoAudioConfig()
    : media_device("entertainment"),
      alt_device("carplay_alt"),
      telephony_device("tel_out1"),
      media_channels(2U),
      alt_channels(1U),
      telephony_channels(1U),
      latency_us(100000U),
      soft_resample(1),
      max_queue_ms(500U),
      duck_gain_q15(8192),
      duck_on_alt_stream(false),
      conceal_packet_loss(false) {}

std::string selectAlsaDevice(const AudioStreamId& id, const EvoAudioConfig& cfg) {
    switch (classifyStreamRole(id)) {
        case kRoleAlt:
            return cfg.alt_device;
        case kRoleTelephony:
            return cfg.telephony_device;
        case kRoleMedia:
        default:
            return cfg.media_device;
    }
}

unsigned int selectAlsaChannels(const AudioStreamId& id,
                                const audio::AudioFormat& format,
                                const EvoAudioConfig& cfg) {
    unsigned int configured = 0;
    switch (classifyStreamRole(id)) {
        case kRoleAlt:
            configured = cfg.alt_channels;
            break;
        case kRoleTelephony:
            configured = cfg.telephony_channels;
            break;
        case kRoleMedia:
        default:
            configured = cfg.media_channels;
            break;
    }
    if (configured > 0) {
        return configured;
    }
    return format.channels > 0 ? format.channels : 2U;
}

size_t adaptChannelsS16(const int16_t* samples,
                        size_t frame_count,
                        unsigned int src_channels,
                        unsigned int dst_channels,
                        std::vector<int16_t>& out) {
    out.clear();
    if (samples == NULL || frame_count == 0 || src_channels == 0 || dst_channels == 0) {
        return 0;
    }
    if (src_channels == dst_channels) {
        const size_t total = frame_count * src_channels;
        out.assign(samples, samples + total);
        return frame_count;
    }
    if (src_channels == 2U && dst_channels == 1U) {
        out.resize(frame_count);
        for (size_t i = 0; i < frame_count; ++i) {
            const int32_t l = samples[i * 2U];
            const int32_t r = samples[i * 2U + 1U];
            out[i] = static_cast<int16_t>((l + r) / 2);
        }
        return frame_count;
    }
    if (src_channels == 1U && dst_channels == 2U) {
        out.resize(frame_count * 2U);
        for (size_t i = 0; i < frame_count; ++i) {
            const int16_t m = samples[i];
            out[i * 2U] = m;
            out[i * 2U + 1U] = m;
        }
        return frame_count;
    }
    // Generic fallback for >2 channels: copy up to min(src, dst), zero-pad remaining channels.
    out.assign(frame_count * dst_channels, 0);
    const unsigned int copy_ch = (src_channels < dst_channels) ? src_channels : dst_channels;
    for (size_t f = 0; f < frame_count; ++f) {
        for (unsigned int c = 0; c < copy_ch; ++c) {
            out[f * dst_channels + c] = samples[f * src_channels + c];
        }
    }
    return frame_count;
}

void applyGainQ15S16(int16_t* samples, size_t sample_count, int32_t gain_q15) {
    if (samples == NULL || sample_count == 0 || gain_q15 == kUnityGainQ15) {
        return;
    }
    for (size_t i = 0; i < sample_count; ++i) {
        // 64-bit product: INT16_MIN * gain overflows int32 once |gain| > 65536.
        int64_t v = (static_cast<int64_t>(samples[i]) * gain_q15) / kUnityGainQ15;
        if (v > 32767) {
            v = 32767;
        } else if (v < -32768) {
            v = -32768;
        }
        samples[i] = static_cast<int16_t>(v);
    }
}

// =================================================================================================
// EvoAudioSink
// =================================================================================================

struct EvoAudioSink::Impl {
    enum EntryState {
        kNeedOpen = 0,
        kOpening,
        kOpen,
        kFailed
    };

    struct StreamEntry {
        AudioStreamId id;
        audio::AudioFormat format;
        StreamRole role;
        std::string device_name;
        unsigned int src_channels;
        unsigned int target_channels;
        unsigned int target_rate;
        EntryState state;
        bool closing;
        void* pcm;
        PcmRingBuffer ring;

        StreamEntry(const AudioStreamId& sid,
                    const audio::AudioFormat& fmt,
                    StreamRole r,
                    const std::string& dev,
                    unsigned int src_ch,
                    unsigned int dst_ch,
                    unsigned int rate,
                    size_t ring_samples)
            : id(sid),
              format(fmt),
              role(r),
              device_name(dev),
              src_channels(src_ch),
              target_channels(dst_ch),
              target_rate(rate),
              state(kNeedOpen),
              closing(false),
              pcm(NULL) {
            ring.reset(ring_samples);
        }
    };

    EvoAudioConfig config;
    AlsaLoader loader;
    AlsaApi api;
    bool has_injected_api;

    SyncLockCond sync;
    Thread worker;
    bool started;
    bool quit;
    bool ducked;
    size_t rr_cursor;
    std::vector<StreamEntry*> active_streams;
    std::vector<StreamEntry*> closing_streams;
    Stats stats;

    explicit Impl(const EvoAudioConfig& cfg)
        : config(cfg),
          has_injected_api(false),
          started(false),
          quit(false),
          ducked(false),
          rr_cursor(0) {}

    ~Impl() {
        stop();
        // Clean up any entries created when worker was never started (or already joined).
        for (size_t i = 0; i < closing_streams.size(); ++i) {
            delete closing_streams[i];
        }
        closing_streams.clear();
        for (size_t i = 0; i < active_streams.size(); ++i) {
            delete active_streams[i];
        }
        active_streams.clear();
    }

    static void workerEntry(void* arg) { static_cast<Impl*>(arg)->workerLoop(); }

    bool start() {
        ScopedSyncLock lock(sync);
        if (started) {
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
        if (!api.isCompletePlayback()) {
            CARPLAY_LOG_ERROR(kTag, "ALSA playback API incomplete");
            return false;
        }
        quit = false;
        if (!worker.start(&Impl::workerEntry, this)) {
            CARPLAY_LOG_ERROR(kTag, "cannot start audio playback thread");
            return false;
        }
        started = true;
        return true;
    }

    void stop() {
        {
            ScopedSyncLock lock(sync);
            if (!started) {
                return;
            }
            quit = true;
            moveAllToClosingLocked();
            sync.broadcast();
        }
        worker.join();
        {
            ScopedSyncLock lock(sync);
            started = false;
        }
    }

    StreamEntry* findActiveLocked(const AudioStreamId& id) {
        for (size_t i = 0; i < active_streams.size(); ++i) {
            if (active_streams[i]->id == id && !active_streams[i]->closing) {
                return active_streams[i];
            }
        }
        return NULL;
    }

    bool hasActiveAltStreamLocked() const {
        for (size_t i = 0; i < active_streams.size(); ++i) {
            const StreamEntry* e = active_streams[i];
            if (!e->closing && e->role == kRoleAlt && e->state != kFailed) {
                return true;
            }
        }
        return false;
    }

    void moveAllToClosingLocked() {
        for (size_t i = 0; i < active_streams.size(); ++i) {
            StreamEntry* e = active_streams[i];
            e->closing = true;
            e->ring.clear();
            closing_streams.push_back(e);
        }
        active_streams.clear();
    }

    void retireActiveByIndexLocked(size_t idx) {
        StreamEntry* e = active_streams[idx];
        active_streams.erase(active_streams.begin() + static_cast<ptrdiff_t>(idx));
        e->closing = true;
        e->ring.clear();
        closing_streams.push_back(e);
    }

    StreamEntry* createStreamLocked(const AudioStreamId& id, const audio::AudioFormat& format) {
        if (format.codec != audio::kCodecLpcm || format.sample_rate == 0 ||
            format.channels == 0 || format.channels > 2) {
            return NULL;
        }
        for (size_t i = 0; i < active_streams.size(); ++i) {
            if (active_streams[i]->id == id) {
                retireActiveByIndexLocked(i);
                break;
            }
        }
        const StreamRole role = classifyStreamRole(id);
        const std::string dev = selectAlsaDevice(id, config);
        const unsigned int dst_ch = selectAlsaChannels(id, format, config);
        uint64_t cap_frames =
            (static_cast<uint64_t>(format.sample_rate) * config.max_queue_ms) / 1000ULL;
        if (cap_frames == 0) {
            cap_frames = 1ULL;
        }
        const size_t ring_samples = static_cast<size_t>(cap_frames) * format.channels;
        StreamEntry* entry = new StreamEntry(
            id, format, role, dev, format.channels, dst_ch, format.sample_rate, ring_samples);
        active_streams.push_back(entry);
        return entry;
    }

    void closeAndDeleteList(std::vector<StreamEntry*>& list) {
        for (size_t i = 0; i < list.size(); ++i) {
            StreamEntry* e = list[i];
            if (e->pcm != NULL) {
                api.snd_pcm_drop(e->pcm);
                api.snd_pcm_close(e->pcm);
                e->pcm = NULL;
                ScopedSyncLock lock(sync);
                stats.streams_closed += 1;
            }
            delete e;
        }
        list.clear();
    }

    bool hasWorkLocked() const {
        if (quit || !closing_streams.empty()) {
            return true;
        }
        for (size_t i = 0; i < active_streams.size(); ++i) {
            const StreamEntry* e = active_streams[i];
            if (e->closing) {
                continue;
            }
            if (e->state == kNeedOpen) {
                return true;
            }
            if (e->state == kOpen && !e->ring.empty()) {
                return true;
            }
        }
        return false;
    }

    void workerLoop() {
        std::vector<StreamEntry*> to_close;
        std::vector<int16_t> pop_buf;
        std::vector<int16_t> out_buf;

        for (;;) {
            StreamEntry* to_open = NULL;
            std::string open_dev;
            unsigned int open_ch = 0;
            unsigned int open_rate = 0;

            StreamEntry* to_write = NULL;
            void* write_pcm = NULL;
            std::string write_dev;
            unsigned int write_src_ch = 0;
            unsigned int write_dst_ch = 0;
            bool apply_duck = false;
            int32_t duck_gain = config.duck_gain_q15;
            size_t popped_frames = 0;

            {
                ScopedSyncLock lock(sync);
                while (!hasWorkLocked()) {
                    sync.wait();
                }

                // 1. Always drain closing streams first so old ALSA handles close before re-open.
                if (!closing_streams.empty()) {
                    to_close.swap(closing_streams);
                } else if (quit) {
                    moveAllToClosingLocked();
                    to_close.swap(closing_streams);
                } else {
                    // 2. Open any stream waiting to be opened.
                    for (size_t i = 0; i < active_streams.size(); ++i) {
                        StreamEntry* e = active_streams[i];
                        if (!e->closing && e->state == kNeedOpen) {
                            e->state = kOpening;
                            to_open = e;
                            open_dev = e->device_name;
                            open_ch = e->target_channels;
                            open_rate = e->target_rate;
                            break;
                        }
                    }

                    // 3. Otherwise round-robin across open streams with queued PCM frames.
                    if (to_open == NULL && !active_streams.empty()) {
                        const size_t n = active_streams.size();
                        if (rr_cursor >= n) {
                            rr_cursor = 0;
                        }
                        for (size_t off = 0; off < n; ++off) {
                            const size_t idx = (rr_cursor + off) % n;
                            StreamEntry* e = active_streams[idx];
                            if (!e->closing && e->state == kOpen && e->pcm != NULL &&
                                !e->ring.empty()) {
                                size_t chunk_frames = e->target_rate / 50U;
                                if (chunk_frames < 64U) {
                                    chunk_frames = 64U;
                                }
                                popped_frames =
                                    e->ring.popFrames(chunk_frames, e->src_channels, pop_buf);
                                if (popped_frames > 0) {
                                    to_write = e;
                                    write_pcm = e->pcm;
                                    write_dev = e->device_name;
                                    write_src_ch = e->src_channels;
                                    write_dst_ch = e->target_channels;
                                    apply_duck = (e->role == kRoleMedia) &&
                                                 (ducked || (config.duck_on_alt_stream &&
                                                             hasActiveAltStreamLocked()));
                                    rr_cursor = (idx + 1U) % n;
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if (!to_close.empty()) {
                closeAndDeleteList(to_close);
                ScopedSyncLock lock(sync);
                if (quit && active_streams.empty() && closing_streams.empty()) {
                    return;
                }
                continue;
            }

            {
                ScopedSyncLock lock(sync);
                if (quit && active_streams.empty() && closing_streams.empty()) {
                    return;
                }
            }

            if (to_open != NULL) {
                void* pcm = NULL;
                int err = api.snd_pcm_open(&pcm, open_dev.c_str(), alsa::kStreamPlayback,
                                           alsa::kOpenBlock);
                if (err >= 0) {
                    err = api.snd_pcm_set_params(pcm,
                                                 alsa::kFormatS16Le,
                                                 alsa::kAccessRwInterleaved,
                                                 open_ch,
                                                 open_rate,
                                                 config.soft_resample,
                                                 config.latency_us);
                    if (err < 0 && pcm != NULL) {
                        api.snd_pcm_close(pcm);
                        pcm = NULL;
                    }
                } else {
                    pcm = NULL;
                }

                ScopedSyncLock lock(sync);
                if (to_open->closing || quit) {
                    if (pcm != NULL) {
                        // Store on entry so the closing pass drops & closes it cleanly.
                        to_open->pcm = pcm;
                    }
                } else if (err < 0 || pcm == NULL) {
                    CARPLAY_LOG_ERROR(kTag, "cannot open ALSA playback %s (%u Hz, %u ch): %s",
                                      open_dev.c_str(), open_rate, open_ch, api.snd_strerror(err));
                    to_open->state = kFailed;
                    to_open->ring.clear();
                    stats.open_failures += 1;
                } else {
                    to_open->pcm = pcm;
                    to_open->state = kOpen;
                    stats.streams_opened += 1;
                    CARPLAY_LOG_INFO(kTag, "opened ALSA playback %s (%u Hz, %u ch)",
                                     open_dev.c_str(), open_rate, open_ch);
                }
                continue;
            }

            if (to_write != NULL && popped_frames > 0) {
                const size_t out_frames = adaptChannelsS16(
                    &pop_buf[0], popped_frames, write_src_ch, write_dst_ch, out_buf);
                if (apply_duck && out_frames > 0) {
                    applyGainQ15S16(&out_buf[0], out_buf.size(), duck_gain);
                }

                size_t written_frames = 0;
                uint64_t chunk_written = 0;
                uint64_t chunk_recoveries = 0;
                bool fatal = false;
                int zero_writes = 0;

                while (written_frames < out_frames) {
                    {
                        ScopedSyncLock lock(sync);
                        if (to_write->closing || quit) {
                            break;
                        }
                    }
                    const int16_t* ptr = &out_buf[written_frames * write_dst_ch];
                    const unsigned long rem =
                        static_cast<unsigned long>(out_frames - written_frames);
                    const long n = api.snd_pcm_writei(write_pcm, ptr, rem);
                    if (n > 0) {
                        written_frames += static_cast<size_t>(n);
                        chunk_written += static_cast<uint64_t>(n);
                        zero_writes = 0;
                        continue;
                    }
                    if (n == 0) {
                        if (++zero_writes > 8) {
                            fatal = true;
                            break;
                        }
                        continue;
                    }
                    const int err = static_cast<int>(n);
                    const int rec = api.snd_pcm_recover(write_pcm, err, 1);
                    if (rec < 0) {
                        CARPLAY_LOG_ERROR(kTag, "ALSA write/recover failed on %s: %s",
                                          write_dev.c_str(), api.snd_strerror(rec));
                        fatal = true;
                        break;
                    }
                    chunk_recoveries += 1;
                }

                void* drop_pcm = NULL;
                {
                    ScopedSyncLock lock(sync);
                    stats.frames_written += chunk_written;
                    stats.underrun_recoveries += chunk_recoveries;
                    if (fatal) {
                        stats.write_errors += 1;
                        if (!to_write->closing && to_write->pcm == write_pcm) {
                            drop_pcm = to_write->pcm;
                            to_write->pcm = NULL;
                            to_write->state = kFailed;
                            to_write->ring.clear();
                        }
                    }
                }
                if (drop_pcm != NULL) {
                    api.snd_pcm_drop(drop_pcm);
                    api.snd_pcm_close(drop_pcm);
                    ScopedSyncLock lock(sync);
                    stats.streams_closed += 1;
                }
            }
        }
    }
};

EvoAudioSink::EvoAudioSink(const EvoAudioConfig& config)
    : config_(config), impl_(new Impl(config)) {}

EvoAudioSink::EvoAudioSink(const AlsaApi& api, const EvoAudioConfig& config)
    : config_(config), impl_(new Impl(config)) {
    impl_->api = api;
    impl_->has_injected_api = true;
}

EvoAudioSink::~EvoAudioSink() {
    stop();
    delete impl_;
    impl_ = NULL;
}

void EvoAudioSink::setAlsaApi(const AlsaApi& api) {
    ScopedSyncLock lock(impl_->sync);
    impl_->api = api;
    impl_->has_injected_api = true;
}

bool EvoAudioSink::start() { return impl_->start(); }

void EvoAudioSink::stop() { impl_->stop(); }

bool EvoAudioSink::running() const {
    ScopedSyncLock lock(impl_->sync);
    return impl_->started;
}

void EvoAudioSink::onAudioStarted(const AudioStreamId& id,
                                  const audio::AudioFormat& format,
                                  uint32_t /*first_sample*/) {
    ScopedSyncLock lock(impl_->sync);
    if (!impl_->started || impl_->quit) {
        return;
    }
    if (impl_->createStreamLocked(id, format) != NULL) {
        impl_->sync.signal();
    }
}

void EvoAudioSink::onAudioPcm(const AudioStreamId& id,
                              const audio::AudioFormat& format,
                              const int16_t* samples,
                              size_t sample_count,
                              uint16_t /*sequence*/,
                              uint32_t /*rtp_timestamp*/) {
    if (samples == NULL || sample_count == 0 || format.channels == 0) {
        return;
    }
    const size_t frame_count = sample_count / format.channels;
    if (frame_count == 0) {
        return;
    }

    ScopedSyncLock lock(impl_->sync);
    if (!impl_->started || impl_->quit) {
        return;
    }
    Impl::StreamEntry* e = impl_->findActiveLocked(id);
    // A format change without a fresh onAudioStarted must reopen the stream:
    // pushFrames() sizes its copy from the entry's channel count, not `format`.
    if (e == NULL || e->src_channels != format.channels || e->target_rate != format.sample_rate) {
        e = impl_->createStreamLocked(id, format);
        if (e == NULL) {
            return;
        }
    }
    if (e->state == Impl::kFailed) {
        return;
    }
    const size_t dropped = e->ring.pushFrames(samples, frame_count, e->src_channels);
    impl_->stats.overrun_frames += static_cast<uint64_t>(dropped);
    impl_->sync.signal();
}

void EvoAudioSink::onAudioPacketLost(const AudioStreamId& id,
                                     const audio::AudioFormat& format,
                                     uint16_t /*lost_sequence*/) {
    ScopedSyncLock lock(impl_->sync);
    impl_->stats.packet_loss_events += 1;
    if (!impl_->started || impl_->quit || !impl_->config.conceal_packet_loss) {
        return;
    }
    if (format.channels == 0 || format.sample_rate == 0) {
        return;
    }
    Impl::StreamEntry* e = impl_->findActiveLocked(id);
    if (e == NULL || e->state == Impl::kFailed) {
        return;
    }
    size_t conceal_frames = format.sample_rate / 50U;
    if (conceal_frames == 0) {
        conceal_frames = 1U;
    }
    std::vector<int16_t> zeros(conceal_frames * e->src_channels, 0);
    const size_t dropped = e->ring.pushFrames(&zeros[0], conceal_frames, e->src_channels);
    impl_->stats.overrun_frames += static_cast<uint64_t>(dropped);
    impl_->sync.signal();
}

void EvoAudioSink::onAudioStopped(const AudioStreamId& id) {
    ScopedSyncLock lock(impl_->sync);
    for (size_t i = 0; i < impl_->active_streams.size(); ++i) {
        if (impl_->active_streams[i]->id == id) {
            impl_->retireActiveByIndexLocked(i);
            impl_->sync.signal();
            break;
        }
    }
}

void EvoAudioSink::onAudioDuck(bool ducked) { setDucked(ducked); }

void EvoAudioSink::setDucked(bool ducked) {
    ScopedSyncLock lock(impl_->sync);
    impl_->ducked = ducked;
}

bool EvoAudioSink::isDucked() const {
    ScopedSyncLock lock(impl_->sync);
    return impl_->ducked || (impl_->config.duck_on_alt_stream && impl_->hasActiveAltStreamLocked());
}

void EvoAudioSink::stopAll() {
    ScopedSyncLock lock(impl_->sync);
    if (!impl_->active_streams.empty()) {
        impl_->moveAllToClosingLocked();
        impl_->sync.signal();
    }
}

EvoAudioSink::Stats EvoAudioSink::stats() const {
    ScopedSyncLock lock(impl_->sync);
    Stats copy = impl_->stats;
    copy.active_streams = impl_->active_streams.size();
    return copy;
}

}  // namespace platform
}  // namespace carplay
