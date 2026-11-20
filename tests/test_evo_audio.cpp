// Unit and integration tests for Phase 3 F3-P5: EvoAudioSink, EvoMic, EvoAudioMediaSink,
// AlsaLoader, routing, channel adaptation, ducking, recovery, and MediaEngine UDP loopback.

#include "carplay/airplay_crypto.hpp"
#include "carplay/airplay_info.hpp"
#include "carplay/airplay_session.hpp"
#include "carplay/audio_rtp.hpp"
#include "carplay/bplist_codec.hpp"
#include "carplay/mic_uplink.hpp"
#include "carplay/pairing.hpp"
#include "carplay/platform/evo_audio.hpp"
#include "carplay/platform/evo_mic.hpp"
#include "carplay/platform/media_engine.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/thread.hpp"
#include "carplay/platform/udp.hpp"
#include "carplay/rtsp_message.hpp"
#include "carplay/tlv8_codec.hpp"
#include "test_support.hpp"

#include <errno.h>
#include <string.h>

#include <string>
#include <vector>

namespace audio = carplay::audio;
namespace bplist = carplay::bplist;
namespace crypto = carplay::crypto;
namespace info = carplay::info;
namespace pairing = carplay::pairing;
namespace plat = carplay::platform;
namespace rtsp = carplay::rtsp;
namespace session = carplay::session;
namespace tlv8 = carplay::tlv8;

namespace {

static const int kMockErrPipe = -EPIPE;
static const int kMockErrIntr = -EINTR;
static const int kMockErrFatal = -EIO;
#ifdef ESTRPIPE
static const int kMockErrStrpipe = -ESTRPIPE;
#else
static const int kMockErrStrpipe = -86;
#endif

void sleepMillis(int ms) {
    plat::PollSet ps;
    ps.wait(NULL, 0, ms);
}

// =================================================================================================
// Thread-safe Mock ALSA backend
// =================================================================================================

struct MockHandle {
    std::string name;
    size_t index;
    int stream;
    int mode;
    bool params_set;
    int format;
    int access;
    unsigned int channels;
    unsigned int rate;
    int soft_resample;
    unsigned int latency_us;
    bool dropped;
    bool closed;
    std::vector<int16_t> written_samples;
    size_t write_calls;
    size_t read_calls;
    size_t recover_calls;
    int last_recover_err;

    MockHandle()
        : index(0),
          stream(0),
          mode(0),
          params_set(false),
          format(0),
          access(0),
          channels(0),
          rate(0),
          soft_resample(0),
          latency_us(0),
          dropped(false),
          closed(false),
          write_calls(0),
          read_calls(0),
          recover_calls(0),
          last_recover_err(0) {}
};

struct HandleEvent {
    bool is_open;
    std::string device;
    size_t handle_index;
};

struct MockAlsaState {
    plat::Mutex mu;
    std::vector<MockHandle*> handles;
    std::vector<HandleEvent> event_log;
    size_t open_count;
    size_t close_count;
    size_t active_open_count;
    size_t busy_open_rejections;
    int fail_open_err;
    int fail_set_params_err;
    std::string fail_open_device;

    // Playback error / slow-consumer injection.
    int next_write_err;          // if < 0, injected once then cleared
    bool fail_recover;           // if true, snd_pcm_recover returns kMockErrFatal
    int write_delay_ms;          // artificial delay inside snd_pcm_writei
    bool block_writei;           // deterministic gate for tests
    size_t writei_blocked_count; // incremented when mockWritei enters gate

    // Capture data & error injection.
    std::vector<int16_t> capture_pattern;
    size_t capture_cursor;
    int next_read_err;           // if < 0, injected once then cleared
    bool persistent_read_err;    // if true, keeps returning kMockErrFatal

    MockAlsaState()
        : open_count(0),
          close_count(0),
          active_open_count(0),
          busy_open_rejections(0),
          fail_open_err(0),
          fail_set_params_err(0),
          next_write_err(0),
          fail_recover(false),
          write_delay_ms(0),
          block_writei(false),
          writei_blocked_count(0),
          capture_cursor(0),
          next_read_err(0),
          persistent_read_err(false) {}

    ~MockAlsaState() { clearHandles(); }

    void reset() {
        plat::LockGuard lock(mu);
        for (size_t i = 0; i < handles.size(); ++i) {
            delete handles[i];
        }
        handles.clear();
        event_log.clear();
        open_count = 0;
        close_count = 0;
        active_open_count = 0;
        busy_open_rejections = 0;
        fail_open_err = 0;
        fail_set_params_err = 0;
        fail_open_device.clear();
        next_write_err = 0;
        fail_recover = false;
        write_delay_ms = 0;
        block_writei = false;
        writei_blocked_count = 0;
        capture_pattern.clear();
        capture_cursor = 0;
        next_read_err = 0;
        persistent_read_err = false;
    }

    void clearHandles() {
        plat::LockGuard lock(mu);
        for (size_t i = 0; i < handles.size(); ++i) {
            delete handles[i];
        }
        handles.clear();
    }

    MockHandle* findByName(const std::string& name, size_t occurrence = 0) {
        plat::LockGuard lock(mu);
        size_t seen = 0;
        for (size_t i = 0; i < handles.size(); ++i) {
            if (handles[i]->name == name) {
                if (seen == occurrence) {
                    return handles[i];
                }
                ++seen;
            }
        }
        return NULL;
    }

    size_t countByName(const std::string& name) {
        plat::LockGuard lock(mu);
        size_t count = 0;
        for (size_t i = 0; i < handles.size(); ++i) {
            if (handles[i]->name == name) {
                ++count;
            }
        }
        return count;
    }

    bool verifyCloseBeforeOpen(const std::string& name) {
        plat::LockGuard lock(mu);
        bool currently_open = false;
        size_t open_idx = 0;
        for (size_t i = 0; i < event_log.size(); ++i) {
            if (event_log[i].device != name) {
                continue;
            }
            if (event_log[i].is_open) {
                if (currently_open) {
                    return false;
                }
                currently_open = true;
                open_idx = event_log[i].handle_index;
            } else {
                if (!currently_open || event_log[i].handle_index != open_idx) {
                    return false;
                }
                currently_open = false;
            }
        }
        return true;
    }

    size_t totalWrittenSamples(const std::string& name) {
        plat::LockGuard lock(mu);
        size_t total = 0;
        for (size_t i = 0; i < handles.size(); ++i) {
            if (handles[i]->name == name) {
                total += handles[i]->written_samples.size();
            }
        }
        return total;
    }

    std::vector<int16_t> copyWritten(const std::string& name, size_t occurrence = 0) {
        plat::LockGuard lock(mu);
        size_t seen = 0;
        for (size_t i = 0; i < handles.size(); ++i) {
            if (handles[i]->name == name) {
                if (seen == occurrence) {
                    return handles[i]->written_samples;
                }
                ++seen;
            }
        }
        return std::vector<int16_t>();
    }
};

MockAlsaState& mockState() {
    static MockAlsaState s;
    return s;
}

int mockOpen(void** pcm, const char* name, int stream, int mode) {
    MockAlsaState& st = mockState();
    plat::LockGuard lock(st.mu);
    if (pcm == NULL || name == NULL) {
        return -EINVAL;
    }
    if (st.fail_open_err < 0 &&
        (st.fail_open_device.empty() || st.fail_open_device == name)) {
        *pcm = NULL;
        return st.fail_open_err;
    }
    // Enforce per-device exclusivity like real dshare PCMs on EntryNav2.
    for (size_t i = 0; i < st.handles.size(); ++i) {
        if (!st.handles[i]->closed && st.handles[i]->name == name) {
            st.busy_open_rejections += 1;
            *pcm = NULL;
            return -EBUSY;
        }
    }
    MockHandle* h = new MockHandle();
    h->name = name;
    h->index = st.handles.size();
    h->stream = stream;
    h->mode = mode;
    st.handles.push_back(h);
    HandleEvent ev;
    ev.is_open = true;
    ev.device = h->name;
    ev.handle_index = h->index;
    st.event_log.push_back(ev);
    st.open_count += 1;
    st.active_open_count += 1;
    *pcm = h;
    return 0;
}

int mockSetParams(void* pcm,
                  int format,
                  int access,
                  unsigned int channels,
                  unsigned int rate,
                  int soft_resample,
                  unsigned int latency_us) {
    MockAlsaState& st = mockState();
    plat::LockGuard lock(st.mu);
    MockHandle* h = static_cast<MockHandle*>(pcm);
    if (h == NULL) {
        return -EINVAL;
    }
    if (st.fail_set_params_err < 0) {
        return st.fail_set_params_err;
    }
    h->params_set = true;
    h->format = format;
    h->access = access;
    h->channels = channels;
    h->rate = rate;
    h->soft_resample = soft_resample;
    h->latency_us = latency_us;
    return 0;
}

long mockWritei(void* pcm, const void* buffer, unsigned long size) {
    MockAlsaState& st = mockState();
    bool signaled_block = false;
    for (;;) {
        {
            plat::LockGuard lock(st.mu);
            if (!st.block_writei) {
                break;
            }
            if (!signaled_block) {
                st.writei_blocked_count += 1;
                signaled_block = true;
            }
        }
        sleepMillis(1);
    }
    int delay_ms = 0;
    {
        plat::LockGuard lock(st.mu);
        delay_ms = st.write_delay_ms;
    }
    if (delay_ms > 0) {
        sleepMillis(delay_ms);
    }
    plat::LockGuard lock(st.mu);
    MockHandle* h = static_cast<MockHandle*>(pcm);
    if (h == NULL || buffer == NULL || !h->params_set || h->channels == 0) {
        return -EINVAL;
    }
    if (st.next_write_err < 0) {
        const int err = st.next_write_err;
        st.next_write_err = 0;
        return err;
    }
    h->write_calls += 1;
    const size_t nsamples = static_cast<size_t>(size) * h->channels;
    const int16_t* samples = static_cast<const int16_t*>(buffer);
    h->written_samples.insert(h->written_samples.end(), samples, samples + nsamples);
    return static_cast<long>(size);
}

long mockReadi(void* pcm, void* buffer, unsigned long size) {
    MockAlsaState& st = mockState();
    bool need_sleep = false;
    {
        plat::LockGuard lock(st.mu);
        MockHandle* h = static_cast<MockHandle*>(pcm);
        if (h == NULL || buffer == NULL || !h->params_set || h->channels == 0) {
            return -EINVAL;
        }
        h->read_calls += 1;
        if (st.persistent_read_err) {
            return kMockErrFatal;
        }
        if (st.next_read_err < 0) {
            const int err = st.next_read_err;
            st.next_read_err = 0;
            return err;
        }
        const size_t nsamples = static_cast<size_t>(size) * h->channels;
        int16_t* dst = static_cast<int16_t*>(buffer);
        if (st.capture_pattern.empty()) {
            memset(dst, 0, nsamples * sizeof(int16_t));
        } else {
            for (size_t i = 0; i < nsamples; ++i) {
                dst[i] = st.capture_pattern[st.capture_cursor % st.capture_pattern.size()];
                st.capture_cursor += 1;
            }
        }
        need_sleep = true;
    }
    if (need_sleep) {
        sleepMillis(2);
    }
    return static_cast<long>(size);
}

int mockRecover(void* pcm, int err, int /*silent*/) {
    MockAlsaState& st = mockState();
    plat::LockGuard lock(st.mu);
    MockHandle* h = static_cast<MockHandle*>(pcm);
    if (h == NULL) {
        return -EINVAL;
    }
    h->recover_calls += 1;
    h->last_recover_err = err;
    if (st.fail_recover || err == kMockErrFatal) {
        return kMockErrFatal;
    }
    return 0;
}

int mockPrepare(void* /*pcm*/) { return 0; }

int mockDrop(void* pcm) {
    MockAlsaState& st = mockState();
    plat::LockGuard lock(st.mu);
    MockHandle* h = static_cast<MockHandle*>(pcm);
    if (h != NULL) {
        h->dropped = true;
    }
    return 0;
}

int mockDrain(void* /*pcm*/) { return 0; }

int mockClose(void* pcm) {
    MockAlsaState& st = mockState();
    plat::LockGuard lock(st.mu);
    MockHandle* h = static_cast<MockHandle*>(pcm);
    if (h != NULL && !h->closed) {
        h->closed = true;
        HandleEvent ev;
        ev.is_open = false;
        ev.device = h->name;
        ev.handle_index = h->index;
        st.event_log.push_back(ev);
        st.close_count += 1;
        if (st.active_open_count > 0) {
            st.active_open_count -= 1;
        }
    }
    return 0;
}

const char* mockStrerror(int errnum) {
    if (errnum == kMockErrPipe) return "Broken pipe (mock)";
    if (errnum == kMockErrIntr) return "Interrupted system call (mock)";
    if (errnum == kMockErrStrpipe) return "Streams pipe error (mock)";
    if (errnum == kMockErrFatal) return "Input/output error (mock)";
    return "ALSA mock error";
}

plat::AlsaApi makeMockApi() {
    plat::AlsaApi api;
    api.snd_pcm_open = &mockOpen;
    api.snd_pcm_set_params = &mockSetParams;
    api.snd_pcm_writei = &mockWritei;
    api.snd_pcm_readi = &mockReadi;
    api.snd_pcm_recover = &mockRecover;
    api.snd_pcm_prepare = &mockPrepare;
    api.snd_pcm_drop = &mockDrop;
    api.snd_pcm_drain = &mockDrain;
    api.snd_pcm_close = &mockClose;
    api.snd_strerror = &mockStrerror;
    return api;
}

bool waitForCondition(bool (*pred)(void*), void* ctx, int timeout_ms = 3000) {
    const int64_t deadline = plat::monotonicMillis() + timeout_ms;
    while (plat::monotonicMillis() < deadline) {
        if (pred(ctx)) {
            return true;
        }
        sleepMillis(2);
    }
    return pred(ctx);
}

struct WrittenCountCtx {
    std::string device;
    size_t min_samples;
};

bool hasWrittenSamples(void* ctx) {
    const WrittenCountCtx* c = static_cast<const WrittenCountCtx*>(ctx);
    return mockState().totalWrittenSamples(c->device) >= c->min_samples;
}

bool hasActiveOpensZero(void* /*ctx*/) {
    MockAlsaState& st = mockState();
    plat::LockGuard lock(st.mu);
    return st.active_open_count == 0;
}

bool hasCloseCountAtLeast(void* ctx) {
    const size_t target = *static_cast<const size_t*>(ctx);
    MockAlsaState& st = mockState();
    plat::LockGuard lock(st.mu);
    return st.close_count >= target;
}

bool hasOpenFailureAtLeast(void* ctx) {
    const plat::EvoAudioSink* sink = static_cast<const plat::EvoAudioSink*>(ctx);
    return sink->stats().open_failures >= 1U;
}

bool hasWriteErrorAtLeast(void* ctx) {
    const plat::EvoAudioSink* sink = static_cast<const plat::EvoAudioSink*>(ctx);
    return sink->stats().write_errors >= 1U;
}

bool hasWriteiBlockedAtLeast(void* ctx) {
    const size_t target = *static_cast<const size_t*>(ctx);
    MockAlsaState& st = mockState();
    plat::LockGuard lock(st.mu);
    return st.writei_blocked_count >= target;
}

struct DeviceOccurrenceCtx {
    std::string device;
    size_t occurrence;
    size_t min_samples;
};

bool hasDeviceOccurrenceWritten(void* ctx) {
    const DeviceOccurrenceCtx* c = static_cast<const DeviceOccurrenceCtx*>(ctx);
    return mockState().copyWritten(c->device, c->occurrence).size() >= c->min_samples;
}

bool hasDeviceOccurrenceConfigured(void* ctx) {
    const DeviceOccurrenceCtx* c = static_cast<const DeviceOccurrenceCtx*>(ctx);
    MockAlsaState& st = mockState();
    plat::LockGuard lock(st.mu);
    size_t seen = 0;
    for (size_t i = 0; i < st.handles.size(); ++i) {
        if (st.handles[i]->name == c->device) {
            ++seen;
            if (seen == c->occurrence) {
                return st.handles[i]->params_set;
            }
        }
    }
    return false;
}

// =================================================================================================
// Mic capture helper
// =================================================================================================

struct MicCaptureRecorder {
    plat::Mutex mu;
    std::vector<int16_t> samples;
    size_t callbacks;
    std::vector<size_t> chunk_sizes;

    MicCaptureRecorder() : callbacks(0) {}

    static void onSamples(const int16_t* data, size_t count, void* user) {
        MicCaptureRecorder* self = static_cast<MicCaptureRecorder*>(user);
        plat::LockGuard lock(self->mu);
        self->callbacks += 1;
        self->chunk_sizes.push_back(count);
        if (data != NULL && count > 0) {
            self->samples.insert(self->samples.end(), data, data + count);
        }
    }

    size_t sampleCount() {
        plat::LockGuard lock(mu);
        return samples.size();
    }
};

struct MicTargetCtx {
    MicCaptureRecorder* rec;
    size_t min_samples;
};

bool hasCapturedSamples(void* ctx) {
    MicTargetCtx* c = static_cast<MicTargetCtx*>(ctx);
    return c->rec->sampleCount() >= c->min_samples;
}

bool micHasStartedCount(void* ctx) {
    const std::pair<plat::EvoMic*, uint64_t>* p =
        static_cast<const std::pair<plat::EvoMic*, uint64_t>*>(ctx);
    return p->first->stats().captures_started >= p->second;
}

bool micStoppedAll(void* ctx) {
    const plat::EvoMic* m = static_cast<const plat::EvoMic*>(ctx);
    const plat::EvoMic::Stats s = m->stats();
    return !s.capturing && s.captures_stopped >= s.captures_started;
}

bool micHasReadError(void* ctx) {
    const plat::EvoMic* m = static_cast<const plat::EvoMic*>(ctx);
    return m->stats().read_errors >= 1U;
}

bool micHasOpenFailure(void* ctx) {
    const plat::EvoMic* m = static_cast<const plat::EvoMic*>(ctx);
    return m->stats().open_failures >= 1U;
}

// =================================================================================================
// Minimal Session + PairVerify helpers for MediaEngine mic UDP loopback test
// =================================================================================================

class DetRng : public pairing::RandomSource {
public:
    explicit DetRng(uint8_t seed_base) : counter_(seed_base) {}
    virtual bool fill(uint8_t* out, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            out[i] = static_cast<uint8_t>((counter_ * 37U + i * 13U) & 0xffU);
        }
        counter_ += 1;
        return true;
    }

private:
    uint32_t counter_;
};

class DummyTransport : public session::TransportHost {
public:
    virtual bool openTiming(int32_t /*peer_timing_port*/, int32_t& local_port_out) {
        local_port_out = 40001;
        return true;
    }
    virtual bool openEvent(int32_t& local_port_out) {
        local_port_out = 40002;
        return true;
    }
    virtual bool openKeepAlive(int32_t& local_port_out) {
        local_port_out = 40003;
        return true;
    }
    virtual void closeAll() {}
};

bool performPairVerify(session::Session& sess,
                       const pairing::Identity& controller_id,
                       std::vector<uint8_t>& shared_secret_out) {
    uint8_t eph_sk[crypto::kKeyBytes];
    for (size_t i = 0; i < crypto::kKeyBytes; ++i) {
        eph_sk[i] = static_cast<uint8_t>(0x30 + i);
    }
    crypto::X25519KeyPair eph;
    crypto::x25519FromSecret(eph_sk, eph);

    std::vector<tlv8::Item> m1_items;
    m1_items.push_back(tlv8::Item::fromByte(tlv8::kTagState, 1));
    m1_items.push_back(tlv8::Item(tlv8::kTagPublicKey, eph.public_key, crypto::kKeyBytes));
    const std::vector<uint8_t> m1_body = tlv8::encode(m1_items);

    rtsp::HeaderList hdr1;
    hdr1.push_back(rtsp::Header("Content-Type", rtsp::kContentTypePairingTlv8));
    hdr1.push_back(rtsp::Header("CSeq", "1"));
    std::vector<uint8_t> req1_bytes;
    rtsp::buildRequest("POST", "/pair-verify", "RTSP/1.0", hdr1, m1_body, req1_bytes);

    std::vector<uint8_t> resp1_bytes;
    if (!sess.onControlBytes(&req1_bytes[0], req1_bytes.size(), resp1_bytes)) {
        return false;
    }
    rtsp::Parser p;
    std::vector<rtsp::Request> msgs1;
    if (!p.feed(resp1_bytes, msgs1) || msgs1.size() != 1U || msgs1[0].path != "200") {
        return false;
    }
    std::vector<tlv8::Item> m2_items;
    if (!tlv8::decode(msgs1[0].body, m2_items)) {
        return false;
    }
    const tlv8::Item* srv_pk = tlv8::findFirst(m2_items, tlv8::kTagPublicKey);
    const tlv8::Item* enc_data = tlv8::findFirst(m2_items, tlv8::kTagEncryptedData);
    if (srv_pk == NULL || srv_pk->value.size() != crypto::kKeyBytes || enc_data == NULL) {
        return false;
    }

    uint8_t shared[crypto::kKeyBytes];
    if (!crypto::x25519SharedSecret(eph.secret_key, &srv_pk->value[0], shared)) {
        return false;
    }
    shared_secret_out.assign(shared, shared + crypto::kKeyBytes);

    std::vector<uint8_t> pv_key;
    crypto::hkdfSha512(shared_secret_out, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info",
                       32, pv_key);
    uint8_t n2[crypto::kNonceBytes] = {0};
    memcpy(n2 + 4, "PV-Msg02", 8);
    std::vector<uint8_t> m2_plain;
    if (!crypto::chacha20Poly1305Open(&pv_key[0], n2, NULL, 0, &enc_data->value[0],
                                      enc_data->value.size(), m2_plain)) {
        return false;
    }

    // Build M3: sign (ctrlEph | ctrlId | accEph) with controller_id.keys.secret_key.
    std::vector<uint8_t> info_msg(eph.public_key, eph.public_key + crypto::kKeyBytes);
    info_msg.insert(info_msg.end(), controller_id.pairing_id.begin(),
                    controller_id.pairing_id.end());
    info_msg.insert(info_msg.end(), srv_pk->value.begin(), srv_pk->value.end());
    uint8_t sig[crypto::kEd25519SignatureBytes];
    crypto::ed25519Sign(controller_id.keys.secret_key, &info_msg[0], info_msg.size(), sig);

    std::vector<tlv8::Item> sub_items;
    sub_items.push_back(tlv8::Item::fromString(tlv8::kTagIdentifier, controller_id.pairing_id));
    sub_items.push_back(
        tlv8::Item(tlv8::kTagSignature, sig, crypto::kEd25519SignatureBytes));
    const std::vector<uint8_t> sub_plain = tlv8::encode(sub_items);

    uint8_t n3[crypto::kNonceBytes] = {0};
    memcpy(n3 + 4, "PV-Msg03", 8);
    std::vector<uint8_t> sub_enc;
    crypto::chacha20Poly1305Seal(&pv_key[0], n3, NULL, 0, &sub_plain[0], sub_plain.size(), sub_enc);

    std::vector<tlv8::Item> m3_items;
    m3_items.push_back(tlv8::Item::fromByte(tlv8::kTagState, 3));
    m3_items.push_back(tlv8::Item(tlv8::kTagEncryptedData, sub_enc));
    const std::vector<uint8_t> m3_body = tlv8::encode(m3_items);

    rtsp::HeaderList hdr3;
    hdr3.push_back(rtsp::Header("Content-Type", rtsp::kContentTypePairingTlv8));
    hdr3.push_back(rtsp::Header("CSeq", "2"));
    std::vector<uint8_t> req3_bytes;
    rtsp::buildRequest("POST", "/pair-verify", "RTSP/1.0", hdr3, m3_body, req3_bytes);

    std::vector<uint8_t> resp3_bytes;
    if (!sess.onControlBytes(&req3_bytes[0], req3_bytes.size(), resp3_bytes)) {
        return false;
    }
    p.reset();
    std::vector<rtsp::Request> msgs3;
    return p.feed(resp3_bytes, msgs3) && msgs3.size() == 1U && msgs3[0].path == "200";
}

}  // namespace

// =================================================================================================
// Tests
// =================================================================================================

TEST_CASE(deviceRoutingAndChannelHelpers) {
    plat::EvoAudioConfig cfg;
    CHECK_EQ(std::string("entertainment"), cfg.media_device);
    CHECK_EQ(std::string("carplay_alt"), cfg.alt_device);
    CHECK_EQ(std::string("tel_out1"), cfg.telephony_device);

    CHECK_EQ(std::string("entertainment"),
             plat::selectAlsaDevice(plat::AudioStreamId(100, "media"), cfg));
    CHECK_EQ(std::string("entertainment"),
             plat::selectAlsaDevice(plat::AudioStreamId(100, "default"), cfg));
    CHECK_EQ(std::string("entertainment"),
             plat::selectAlsaDevice(plat::AudioStreamId(100, "alert"), cfg));
    CHECK_EQ(std::string("entertainment"),
             plat::selectAlsaDevice(plat::AudioStreamId(102, "media"), cfg));
    CHECK_EQ(std::string("carplay_alt"),
             plat::selectAlsaDevice(plat::AudioStreamId(101, "default"), cfg));
    CHECK_EQ(std::string("carplay_alt"),
             plat::selectAlsaDevice(plat::AudioStreamId(101, "media"), cfg));
    CHECK_EQ(std::string("tel_out1"),
             plat::selectAlsaDevice(plat::AudioStreamId(100, "telephony"), cfg));
    CHECK_EQ(std::string("tel_out1"),
             plat::selectAlsaDevice(plat::AudioStreamId(100, "speechrecognition"), cfg));
    CHECK_EQ(std::string("tel_out1"),
             plat::selectAlsaDevice(plat::AudioStreamId(100, "SpeechRecognition"), cfg));

    audio::AudioFormat fmt;
    fmt.channels = 2U;
    CHECK_EQ(2U, plat::selectAlsaChannels(plat::AudioStreamId(100, "media"), fmt, cfg));
    CHECK_EQ(1U, plat::selectAlsaChannels(plat::AudioStreamId(101, "default"), fmt, cfg));
    CHECK_EQ(1U, plat::selectAlsaChannels(plat::AudioStreamId(100, "telephony"), fmt, cfg));

    cfg.alt_channels = 2U;
    CHECK_EQ(2U, plat::selectAlsaChannels(plat::AudioStreamId(101, "default"), fmt, cfg));
    cfg.alt_channels = 0U;  // match stream format
    fmt.channels = 1U;
    CHECK_EQ(1U, plat::selectAlsaChannels(plat::AudioStreamId(101, "default"), fmt, cfg));

    // Stereo -> Mono downmix (L + R) / 2, checking extremes without overflow.
    const int16_t stereo_in[8] = {1000, 2000, -1000, 1000, 32767, 32767, -32768, -32768};
    std::vector<int16_t> out;
    CHECK_EQ(4U, plat::adaptChannelsS16(stereo_in, 4U, 2U, 1U, out));
    REQUIRE(out.size() == 4U);
    CHECK_EQ(static_cast<int16_t>(1500), out[0]);
    CHECK_EQ(static_cast<int16_t>(0), out[1]);
    CHECK_EQ(static_cast<int16_t>(32767), out[2]);
    CHECK_EQ(static_cast<int16_t>(-32768), out[3]);

    // Mono -> Stereo upmix.
    const int16_t mono_in[2] = {1234, -5678};
    CHECK_EQ(2U, plat::adaptChannelsS16(mono_in, 2U, 1U, 2U, out));
    REQUIRE(out.size() == 4U);
    CHECK_EQ(static_cast<int16_t>(1234), out[0]);
    CHECK_EQ(static_cast<int16_t>(1234), out[1]);
    CHECK_EQ(static_cast<int16_t>(-5678), out[2]);
    CHECK_EQ(static_cast<int16_t>(-5678), out[3]);

    // Q15 gain attenuation (-12 dB = 8192 = 0.25) and saturation.
    int16_t gain_buf[4] = {4000, -4000, 32767, -32768};
    plat::applyGainQ15S16(gain_buf, 4U, 8192);
    CHECK_EQ(static_cast<int16_t>(1000), gain_buf[0]);
    CHECK_EQ(static_cast<int16_t>(-1000), gain_buf[1]);
    CHECK_EQ(static_cast<int16_t>(8191), gain_buf[2]);
    CHECK_EQ(static_cast<int16_t>(-8192), gain_buf[3]);

    int16_t sat_buf[2] = {30000, -30000};
    plat::applyGainQ15S16(sat_buf, 2U, 65536);  // 2.0x gain saturates
    CHECK_EQ(static_cast<int16_t>(32767), sat_buf[0]);
    CHECK_EQ(static_cast<int16_t>(-32768), sat_buf[1]);
}

TEST_CASE(alsaLoaderFailureModes) {
    plat::AlsaLoader loader;
    CHECK(!loader.loaded());

    std::string err;
    CHECK(!loader.load("", &err));
    CHECK(!loader.loaded());
    CHECK(!err.empty());

    CHECK(!loader.load("/nonexistent/dir/libasound_missing.so.2", &err));
    CHECK(!loader.loaded());
    CHECK(!err.empty());

#ifndef _WIN32
    // Existing POSIX shared library that lacks ALSA symbols -> incomplete symbol failure.
    CHECK(!loader.load("libm.so.6", &err));
    CHECK(!loader.loaded());
    CHECK(!loader.lastError().empty());
#endif

    // Incomplete injected AlsaApi must fail start() cleanly without crashing.
    plat::AlsaApi partial;
    partial.snd_pcm_open = &mockOpen;
    plat::EvoAudioSink sink(partial);
    CHECK(!sink.start());
    CHECK(!sink.running());

    plat::EvoMic mic(partial);
    MicCaptureRecorder rec;
    CHECK(!mic.start(&MicCaptureRecorder::onSamples, &rec));
    CHECK(!mic.running());
}

TEST_CASE(concurrentPlaybackDownmixAndDucking) {
    mockState().reset();
    plat::EvoAudioConfig cfg;
    cfg.duck_gain_q15 = 8192;  // 0.25 (-12 dB)
    cfg.duck_ramp_ms = 0U;     // instant-switch test
    plat::EvoAudioSink sink(makeMockApi(), cfg);
    REQUIRE(sink.start());
    CHECK(sink.running());

    const plat::AudioStreamId media_id(100, "media");
    const plat::AudioStreamId alt_id(101, "default");
    const plat::AudioStreamId tel_id(100, "telephony");

    audio::AudioFormat media_fmt;
    media_fmt.codec = audio::kCodecLpcm;
    media_fmt.sample_rate = 44100U;
    media_fmt.channels = 2U;

    audio::AudioFormat alt_fmt;
    alt_fmt.codec = audio::kCodecLpcm;
    alt_fmt.sample_rate = 44100U;
    alt_fmt.channels = 2U;  // stereo source -> downmixed to 1ch on carplay_alt

    audio::AudioFormat tel_fmt;
    tel_fmt.codec = audio::kCodecLpcm;
    tel_fmt.sample_rate = 16000U;
    tel_fmt.channels = 1U;

    sink.onAudioStarted(media_id, media_fmt, 0U);
    sink.onAudioStarted(alt_id, alt_fmt, 0U);
    sink.onAudioStarted(tel_id, tel_fmt, 0U);

    // 1. Unity-gain media frames (8 stereo frames = 16 samples).
    const int16_t media_pcm1[16] = {
        400, -400, 800, -800, 1200, -1200, 1600, -1600,
        2000, -2000, 2400, -2400, 2800, -2800, 3200, -3200};
    sink.onAudioPcm(media_id, media_fmt, media_pcm1, 16U, 1U, 100U);

    // Wait until unity media frames are written before turning ducking on.
    WrittenCountCtx w_media1 = {"entertainment", 16U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_media1));

    // 2. Enable ducking: media gets 0.25x, carplay_alt and tel_out1 stay at 1.0x!
    sink.onAudioDuck(true);
    CHECK(sink.isDucked());

    const int16_t media_pcm2[4] = {4000, -8000, 1200, -1600};
    sink.onAudioPcm(media_id, media_fmt, media_pcm2, 4U, 2U, 108U);

    // carplay_alt receives stereo (1000, 3000) -> downmixed mono 2000, NOT ducked!
    const int16_t alt_pcm[4] = {1000, 3000, -2000, -6000};
    sink.onAudioPcm(alt_id, alt_fmt, alt_pcm, 4U, 1U, 200U);

    // tel_out1 receives mono 5000, -5000, NOT ducked!
    const int16_t tel_pcm[2] = {5000, -5000};
    sink.onAudioPcm(tel_id, tel_fmt, tel_pcm, 2U, 1U, 300U);

    WrittenCountCtx w_media2 = {"entertainment", 20U};
    WrittenCountCtx w_alt = {"carplay_alt", 2U};
    WrittenCountCtx w_tel = {"tel_out1", 2U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_media2));
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_alt));
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_tel));

    // 3. Unduck and push one more stereo frame -> restored to unity gain.
    sink.onAudioDuck(false);
    CHECK(!sink.isDucked());
    const int16_t media_pcm3[2] = {4444, -4444};
    sink.onAudioPcm(media_id, media_fmt, media_pcm3, 2U, 3U, 110U);
    WrittenCountCtx w_media3 = {"entertainment", 22U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_media3));

    // Verify open parameters on all 3 mock ALSA handles.
    MockHandle* h_ent = mockState().findByName("entertainment");
    MockHandle* h_alt = mockState().findByName("carplay_alt");
    MockHandle* h_tel = mockState().findByName("tel_out1");
    REQUIRE(h_ent != NULL && h_alt != NULL && h_tel != NULL);
    {
        plat::LockGuard lock(mockState().mu);
        CHECK_EQ(plat::alsa::kStreamPlayback, h_ent->stream);
        CHECK_EQ(plat::alsa::kFormatS16Le, h_ent->format);
        CHECK_EQ(plat::alsa::kAccessRwInterleaved, h_ent->access);
        CHECK_EQ(2U, h_ent->channels);
        CHECK_EQ(44100U, h_ent->rate);
        CHECK_EQ(1, h_ent->soft_resample);
        CHECK_EQ(100000U, h_ent->latency_us);

        CHECK_EQ(1U, h_alt->channels);
        CHECK_EQ(44100U, h_alt->rate);

        CHECK_EQ(1U, h_tel->channels);
        CHECK_EQ(16000U, h_tel->rate);
    }

    const std::vector<int16_t> ent_written = mockState().copyWritten("entertainment");
    REQUIRE(ent_written.size() == 22U);
    CHECK_EQ(static_cast<int16_t>(400), ent_written[0]);
    CHECK_EQ(static_cast<int16_t>(-3200), ent_written[15]);
    // Ducked frames (indices 16..19): 0.25x
    CHECK_EQ(static_cast<int16_t>(1000), ent_written[16]);
    CHECK_EQ(static_cast<int16_t>(-2000), ent_written[17]);
    CHECK_EQ(static_cast<int16_t>(300), ent_written[18]);
    CHECK_EQ(static_cast<int16_t>(-400), ent_written[19]);
    // Unducked frame (indices 20..21): 1.0x
    CHECK_EQ(static_cast<int16_t>(4444), ent_written[20]);
    CHECK_EQ(static_cast<int16_t>(-4444), ent_written[21]);

    const std::vector<int16_t> alt_written = mockState().copyWritten("carplay_alt");
    REQUIRE(alt_written.size() == 2U);
    CHECK_EQ(static_cast<int16_t>(2000), alt_written[0]);
    CHECK_EQ(static_cast<int16_t>(-4000), alt_written[1]);

    const std::vector<int16_t> tel_written = mockState().copyWritten("tel_out1");
    REQUIRE(tel_written.size() == 2U);
    CHECK_EQ(static_cast<int16_t>(5000), tel_written[0]);
    CHECK_EQ(static_cast<int16_t>(-5000), tel_written[1]);

    // Stopping one stream drops and closes its ALSA handle.
    sink.onAudioStopped(alt_id);
    const size_t target_close1 = 1U;
    REQUIRE(waitForCondition(&hasCloseCountAtLeast, const_cast<size_t*>(&target_close1)));
    {
        plat::LockGuard lock(mockState().mu);
        CHECK(h_alt->dropped);
        CHECK(h_alt->closed);
    }

    // stop() closes remaining streams cleanly.
    sink.stop();
    CHECK(!sink.running());
    CHECK(hasActiveOpensZero(NULL));
    const plat::EvoAudioSink::Stats st = sink.stats();
    CHECK_EQ(3U, static_cast<unsigned int>(st.streams_opened));
    CHECK_EQ(3U, static_cast<unsigned int>(st.streams_closed));
    CHECK_EQ(15U, static_cast<unsigned int>(st.frames_written));
}

TEST_CASE(autoDuckOnAltStreamAndLossConcealment) {
    mockState().reset();
    plat::EvoAudioConfig cfg;
    cfg.duck_on_alt_stream = true;
    cfg.conceal_packet_loss = true;
    cfg.duck_gain_q15 = 8192;
    cfg.duck_ramp_ms = 0U;  // instant-switch test

    plat::EvoAudioSink sink(makeMockApi(), cfg);
    REQUIRE(sink.start());

    const plat::AudioStreamId media_id(100, "media");
    const plat::AudioStreamId alt_id(101, "default");

    audio::AudioFormat fmt;
    fmt.codec = audio::kCodecLpcm;
    fmt.sample_rate = 16000U;
    fmt.channels = 2U;

    sink.onAudioStarted(media_id, fmt, 0U);
    sink.onAudioStarted(alt_id, fmt, 0U);
    CHECK(sink.isDucked());

    const int16_t media_pcm[4] = {4000, -4000, 8000, -8000};
    sink.onAudioPcm(media_id, fmt, media_pcm, 4U, 1U, 0U);
    WrittenCountCtx w1 = {"entertainment", 4U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w1));

    // Packet loss concealment inserts 20 ms of zeros (16000 / 50 = 320 frames = 640 samples).
    sink.onAudioPacketLost(media_id, fmt, 2U);
    WrittenCountCtx w2 = {"entertainment", 4U + 640U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w2));

    // Close alt stream -> media auto-unducks.
    sink.onAudioStopped(alt_id);
    const size_t target_close1 = 1U;
    REQUIRE(waitForCondition(&hasCloseCountAtLeast, const_cast<size_t*>(&target_close1)));
    CHECK(!sink.isDucked());

    const int16_t media_pcm2[2] = {4000, -4000};
    sink.onAudioPcm(media_id, fmt, media_pcm2, 2U, 3U, 322U);
    WrittenCountCtx w3 = {"entertainment", 4U + 640U + 2U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w3));

    const std::vector<int16_t> ent = mockState().copyWritten("entertainment");
    REQUIRE(ent.size() == 646U);
    CHECK_EQ(static_cast<int16_t>(1000), ent[0]);   // auto-ducked
    CHECK_EQ(static_cast<int16_t>(-2000), ent[3]);  // auto-ducked
    CHECK_EQ(static_cast<int16_t>(0), ent[4]);      // concealed zero
    CHECK_EQ(static_cast<int16_t>(0), ent[643]);    // concealed zero
    CHECK_EQ(static_cast<int16_t>(4000), ent[644]); // restored unity
    CHECK_EQ(static_cast<int16_t>(-4000), ent[645]);

    CHECK_EQ(1U, static_cast<unsigned int>(sink.stats().packet_loss_events));
    sink.stop();
}

TEST_CASE(alsaRecoveryFatalErrorsAndReopen) {
    mockState().reset();
    plat::EvoAudioSink sink(makeMockApi());
    REQUIRE(sink.start());

    const plat::AudioStreamId media_id(100, "media");
    audio::AudioFormat fmt;
    fmt.codec = audio::kCodecLpcm;
    fmt.sample_rate = 16000U;
    fmt.channels = 2U;

    // 1. Recoverable underrun (-EPIPE) followed by retry success.
    {
        plat::LockGuard lock(mockState().mu);
        mockState().next_write_err = kMockErrPipe;
    }
    sink.onAudioStarted(media_id, fmt, 0U);
    const int16_t pcm1[4] = {100, 200, 300, 400};
    sink.onAudioPcm(media_id, fmt, pcm1, 4U, 1U, 0U);
    WrittenCountCtx w1 = {"entertainment", 4U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w1));
    CHECK(sink.stats().underrun_recoveries >= 1U);
    CHECK_EQ(0U, static_cast<unsigned int>(sink.stats().write_errors));

    // 2. Recoverable -EINTR and -ESTRPIPE.
    {
        plat::LockGuard lock(mockState().mu);
        mockState().next_write_err = kMockErrIntr;
    }
    sink.onAudioPcm(media_id, fmt, pcm1, 4U, 2U, 2U);
    WrittenCountCtx w2 = {"entertainment", 8U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w2));
    {
        plat::LockGuard lock(mockState().mu);
        mockState().next_write_err = kMockErrStrpipe;
    }
    sink.onAudioPcm(media_id, fmt, pcm1, 4U, 3U, 4U);
    WrittenCountCtx w3 = {"entertainment", 12U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w3));
    CHECK_EQ(3U, static_cast<unsigned int>(sink.stats().underrun_recoveries));

    // 3. Fatal unrecoverable write error -> stream fails and closes PCM cleanly.
    {
        plat::LockGuard lock(mockState().mu);
        mockState().fail_recover = true;
        mockState().next_write_err = kMockErrFatal;
    }
    sink.onAudioPcm(media_id, fmt, pcm1, 4U, 4U, 6U);
    REQUIRE(waitForCondition(&hasWriteErrorAtLeast, &sink));
    REQUIRE(waitForCondition(&hasActiveOpensZero, NULL));

    // 4. Open failure on a new stream is recorded cleanly without hanging.
    {
        plat::LockGuard lock(mockState().mu);
        mockState().fail_recover = false;
        mockState().fail_open_err = -EBUSY;
    }
    sink.onAudioStarted(plat::AudioStreamId(101, "default"), fmt, 0U);
    REQUIRE(waitForCondition(&hasOpenFailureAtLeast, &sink));

    // 5. Re-SETUP of media stream recovers cleanly once open succeeds again.
    {
        plat::LockGuard lock(mockState().mu);
        mockState().fail_open_err = 0;
    }
    sink.onAudioStarted(media_id, fmt, 0U);
    sink.onAudioPcm(media_id, fmt, pcm1, 4U, 5U, 8U);
    WrittenCountCtx w4 = {"entertainment", 16U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w4));

    sink.stop();
    CHECK(hasActiveOpensZero(NULL));
}

TEST_CASE(ringBufferBoundedOverflow) {
    mockState().reset();
    {
        plat::LockGuard lock(mockState().mu);
        // Slow consumer: 15 ms per snd_pcm_writei call.
        mockState().write_delay_ms = 15;
    }
    plat::EvoAudioConfig cfg;
    cfg.max_queue_ms = 20U;  // 20 ms at 16 kHz = 320 frames (640 stereo samples)
    plat::EvoAudioSink sink(makeMockApi(), cfg);
    REQUIRE(sink.start());

    const plat::AudioStreamId media_id(100, "media");
    audio::AudioFormat fmt;
    fmt.codec = audio::kCodecLpcm;
    fmt.sample_rate = 16000U;
    fmt.channels = 2U;

    sink.onAudioStarted(media_id, fmt, 0U);
    // Push 10 x 100-frame chunks = 1000 frames (1000 > 320 capacity) synchronously on caller thread.
    std::vector<int16_t> chunk(200U);
    for (int b = 0; b < 10; ++b) {
        for (size_t i = 0; i < chunk.size(); ++i) {
            chunk[i] = static_cast<int16_t>(b + 1);
        }
        sink.onAudioPcm(media_id, fmt, &chunk[0], chunk.size(), static_cast<uint16_t>(b),
                        static_cast<uint32_t>(b * 100));
    }

    const plat::EvoAudioSink::Stats st = sink.stats();
    CHECK(st.overrun_frames > 0U);

    // Let consumer drain remaining surviving frames, then stop cleanly.
    {
        plat::LockGuard lock(mockState().mu);
        mockState().write_delay_ms = 0;
    }
    WrittenCountCtx w = {"entertainment", 640U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w));

    sink.stop();
    CHECK(hasActiveOpensZero(NULL));
    // Verify newest chunk (value 10) survived in output.
    const std::vector<int16_t> ent = mockState().copyWritten("entertainment");
    REQUIRE(!ent.empty());
    CHECK_EQ(static_cast<int16_t>(10), ent.back());
}

TEST_CASE(evoMicCaptureRatesRecoveryAndRapidRestarts) {
    mockState().reset();
    {
        plat::LockGuard lock(mockState().mu);
        for (int i = 0; i < 64; ++i) {
            mockState().capture_pattern.push_back(static_cast<int16_t>(1000 + i));
        }
    }

    plat::EvoMic mic(makeMockApi());
    MicCaptureRecorder rec;
    REQUIRE(mic.start(&MicCaptureRecorder::onSamples, &rec));
    CHECK(mic.running());
    CHECK(!mic.stats().capturing);

    // 1. Start at 16 kHz mono -> 20 ms = 320 frames/read.
    audio::MicStreamParams p16;
    p16.supported = true;
    p16.format.codec = audio::kCodecLpcm;
    p16.format.sample_rate = 16000U;
    p16.format.channels = 1U;
    {
        plat::LockGuard lock(mockState().mu);
        mockState().next_read_err = kMockErrPipe;  // inject xrun on first read
    }
    REQUIRE(mic.startCapture(p16));

    MicTargetCtx target1 = {&rec, 640U};
    REQUIRE(waitForCondition(&hasCapturedSamples, &target1));
    CHECK(mic.stats().xrun_recoveries >= 1U);
    {
        plat::LockGuard lock(rec.mu);
        REQUIRE(!rec.chunk_sizes.empty());
        CHECK_EQ(320U, rec.chunk_sizes[0]);
        CHECK_EQ(static_cast<int16_t>(1000), rec.samples[0]);
    }
    MockHandle* h16 = mockState().findByName("mic1", 0);
    REQUIRE(h16 != NULL);
    {
        plat::LockGuard lock(mockState().mu);
        CHECK_EQ(plat::alsa::kStreamCapture, h16->stream);
        CHECK_EQ(1U, h16->channels);
        CHECK_EQ(16000U, h16->rate);
    }

    // 2. Stop capture -> closes PCM without joining worker thread.
    mic.stopCapture();
    REQUIRE(waitForCondition(&micStoppedAll, &mic));
    CHECK(mic.running());

    // 3. Restart at 24 kHz mono -> 20 ms = 480 frames/read.
    {
        plat::LockGuard lock(rec.mu);
        rec.samples.clear();
        rec.chunk_sizes.clear();
    }
    audio::MicStreamParams p24 = p16;
    p24.format.sample_rate = 24000U;
    REQUIRE(mic.startCapture(p24));

    std::pair<plat::EvoMic*, uint64_t> wait2(&mic, 2ULL);
    REQUIRE(waitForCondition(&micHasStartedCount, &wait2));
    MicTargetCtx target2 = {&rec, 480U};
    REQUIRE(waitForCondition(&hasCapturedSamples, &target2));

    MockHandle* h24 = mockState().findByName("mic1", 1);
    REQUIRE(h24 != NULL);
    {
        plat::LockGuard lock(mockState().mu);
        CHECK_EQ(24000U, h24->rate);
    }
    {
        plat::LockGuard lock(rec.mu);
        REQUIRE(!rec.chunk_sizes.empty());
        CHECK_EQ(480U, rec.chunk_sizes[0]);
    }

    // 4. Rapid start/stop/restart cycles without deadlocks or leaks.
    for (int i = 0; i < 6; ++i) {
        mic.stopCapture();
        mic.startCapture((i % 2 == 0) ? p16 : p24);
    }
    mic.stopCapture();
    REQUIRE(waitForCondition(&micStoppedAll, &mic));

    // 5. Fatal capture read error exits capture loop cleanly without spinning.
    {
        plat::LockGuard lock(mockState().mu);
        mockState().persistent_read_err = true;
    }
    REQUIRE(mic.startCapture(p16));
    REQUIRE(waitForCondition(&micHasReadError, &mic));
    REQUIRE(waitForCondition(&micStoppedAll, &mic));

    // 6. Open failure handled gracefully.
    {
        plat::LockGuard lock(mockState().mu);
        mockState().persistent_read_err = false;
        mockState().fail_open_err = -ENODEV;
    }
    REQUIRE(mic.startCapture(p24));
    REQUIRE(waitForCondition(&micHasOpenFailure, &mic));

    // Unsupported Opus mic params must be refused.
    audio::MicStreamParams opus = p16;
    opus.supported = false;
    CHECK(!mic.startCapture(opus));

    mic.stop();
    CHECK(!mic.running());
    CHECK(hasActiveOpensZero(NULL));
}

TEST_CASE(evoMicToMediaEngineUdpLoopbackAndCompositeSink) {
    mockState().reset();
    {
        plat::LockGuard lock(mockState().mu);
        for (int i = 0; i < 320; ++i) {
            mockState().capture_pattern.push_back(static_cast<int16_t>((i * 19) - 3000));
        }
    }

    plat::Reactor reactor;
    REQUIRE(reactor.init());

    plat::EvoAudioSink audio_sink(makeMockApi());
    plat::EvoMic mic(makeMockApi());
    plat::EvoAudioMediaSink composite_sink(audio_sink, mic);
    REQUIRE(audio_sink.start());

    plat::MediaEngineConfig me_cfg;
    me_cfg.mic_silent_start_ms = 0;  // start non-telephony mic immediately on SETUP
    plat::MediaEngine media_engine(reactor, composite_sink, me_cfg);
    REQUIRE(mic.start(media_engine));

    // Set up a loopback UDP receiver acting as the iPhone's microphone RTP port.
    plat::UdpSocket phone_udp;
    REQUIRE(phone_udp.open(plat::Address::ipv4Loopback(0)));
    media_engine.setControlPeer(plat::Address::ipv4Loopback(7000));

    // Establish one verified Session so MediaEngine derives real input/output stream keys.
    pairing::Identity acc_id;
    DetRng acc_rng(1);
    REQUIRE(pairing::generateIdentity(acc_rng, acc_id));
    pairing::Identity ctrl_id;
    DetRng ctrl_rng(9);
    REQUIRE(pairing::generateIdentity(ctrl_rng, ctrl_id));

    pairing::InMemoryPairingStore store;
    REQUIRE(store.save(ctrl_id.pairing_id, ctrl_id.keys.public_key));

    session::SessionListener listener;
    DummyTransport transport;
    const info::AirPlayConfig ap_cfg = info::bmwEntryNav2_800x480(false);
    session::Session sess(ap_cfg, acc_id, store, acc_rng, listener,
                          media_engine, transport);

    std::vector<uint8_t> shared_secret;
    REQUIRE(performPairVerify(sess, ctrl_id, shared_secret));

    const uint64_t kConnId = 0x123456789abcdef0ULL;
    bplist::Value stream = bplist::Value::makeDict();
    stream.set("type", bplist::Value::makeInt(100));
    stream.set("audioType", bplist::Value::makeString("speechRecognition"));
    stream.set("audioFormat", bplist::Value::makeInt(0x10));  // 16 kHz mono LPCM
    stream.set("streamConnectionID", bplist::Value::makeInt(static_cast<int64_t>(kConnId)));
    stream.set("dataPort", bplist::Value::makeInt(static_cast<int64_t>(phone_udp.port())));

    bplist::Value resp;
    REQUIRE(media_engine.onAudio(sess, 100, stream, resp));
    CHECK(media_engine.microphoneActive());

    // Derive the phone-side uplink key to decrypt what MediaEngine sends.
    uint8_t input_key[32];
    REQUIRE(audio::deriveAudioInputKey(&shared_secret[0], shared_secret.size(), kConnId, input_key));

    // Pump reactor until we receive and decrypt 2 valid microphone RTP packets (2 x 320 samples).
    std::vector<int16_t> decoded_samples;
    size_t packets_rx = 0;
    const int64_t deadline = plat::monotonicMillis() + 3000;
    while (packets_rx < 2U && plat::monotonicMillis() < deadline) {
        reactor.runOnce(10);
        uint8_t pkt[2048];
        size_t got = 0;
        plat::Address from;
        while (phone_udp.receiveFrom(pkt, sizeof(pkt), got, from) == plat::kIoOk) {
            audio::RtpHeader hdr;
            std::vector<uint8_t> payload;
            REQUIRE(audio::openPacket(input_key, pkt, got, hdr, payload) == audio::kOpenOk);
            CHECK_EQ(100U, static_cast<unsigned int>(hdr.payload_type));
            CHECK_EQ(static_cast<uint16_t>(packets_rx), hdr.sequence);
            CHECK_EQ(640U, payload.size());
            std::vector<int16_t> pcm;
            audio::lpcmToInt16(&payload[0], payload.size(), pcm, audio::kBigEndianSamples);
            decoded_samples.insert(decoded_samples.end(), pcm.begin(), pcm.end());
            packets_rx += 1;
        }
    }
    REQUIRE(packets_rx >= 2U);
    REQUIRE(decoded_samples.size() >= 640U);
    for (int i = 0; i < 320; ++i) {
        CHECK_EQ(static_cast<int16_t>((i * 19) - 3000), decoded_samples[static_cast<size_t>(i)]);
        CHECK_EQ(static_cast<int16_t>((i * 19) - 3000),
                 decoded_samples[static_cast<size_t>(320 + i)]);
    }

    // Teardown stops microphone capture via composite EvoAudioMediaSink::onMicrophoneStopped.
    media_engine.onTeardown(sess, 100);
    CHECK(!media_engine.microphoneActive());
    REQUIRE(waitForCondition(&micStoppedAll, &mic));

    // Stop mic thread before destroying MediaEngine (per MediaEngine lifetime contract).
    mic.stop();
    audio_sink.stop();
    sess.close();
    CHECK(hasActiveOpensZero(NULL));
}

TEST_CASE(applyGainQ15Boundaries) {
    const int16_t kMin16 = static_cast<int16_t>(-32768);
    const int16_t kMax16 = static_cast<int16_t>(32767);

    // Gain 0 zeroes every sample including extremes.
    int16_t zero_buf[5] = {kMin16, -100, 0, 100, kMax16};
    plat::applyGainQ15S16(zero_buf, 5U, 0);
    for (size_t i = 0; i < 5U; ++i) {
        CHECK_EQ(static_cast<int16_t>(0), zero_buf[i]);
    }

    // Gain 32767 scales just below unity without overflow.
    int16_t near_unity[2] = {kMin16, kMax16};
    plat::applyGainQ15S16(near_unity, 2U, 32767);
    CHECK_EQ(static_cast<int16_t>(-32767), near_unity[0]);
    CHECK_EQ(static_cast<int16_t>(32766), near_unity[1]);

    // Gain 32768 is bit-exact pass-through for all int16 values.
    const int16_t orig[7] = {kMin16, -12345, -1, 0, 1, 12345, kMax16};
    int16_t unity_buf[7];
    memcpy(unity_buf, orig, sizeof(orig));
    plat::applyGainQ15S16(unity_buf, 7U, 32768);
    for (size_t i = 0; i < 7U; ++i) {
        CHECK_EQ(orig[i], unity_buf[i]);
    }

    // Gain > 65536 with INT16_MIN / INT16_MAX must saturate, never int32-overflow.
    int16_t high_gain_buf[4] = {kMin16, -20000, 20000, kMax16};
    plat::applyGainQ15S16(high_gain_buf, 4U, 100000);
    CHECK_EQ(kMin16, high_gain_buf[0]);
    CHECK_EQ(kMin16, high_gain_buf[1]);
    CHECK_EQ(kMax16, high_gain_buf[2]);
    CHECK_EQ(kMax16, high_gain_buf[3]);
}

TEST_CASE(formatChangeOnOpenStreamClosesBeforeReopen) {
    mockState().reset();
    plat::EvoAudioConfig cfg;
    cfg.media_channels = 0U;  // follow stream format channels to test 1ch <-> 2ch transitions
    cfg.duck_ramp_ms = 0U;
    plat::EvoAudioSink sink(makeMockApi(), cfg);
    REQUIRE(sink.start());

    const plat::AudioStreamId media_id(100, "media");

    // 1. Open at 44100 Hz stereo.
    audio::AudioFormat fmt44_2ch;
    fmt44_2ch.codec = audio::kCodecLpcm;
    fmt44_2ch.sample_rate = 44100U;
    fmt44_2ch.channels = 2U;
    sink.onAudioStarted(media_id, fmt44_2ch, 0U);
    const int16_t pcm1[4] = {100, -100, 200, -200};
    sink.onAudioPcm(media_id, fmt44_2ch, pcm1, 4U, 1U, 0U);
    DeviceOccurrenceCtx w0 = {"entertainment", 0U, 4U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &w0));

    // 2. Reconfigure via second onAudioStarted with 16000 Hz mono.
    audio::AudioFormat fmt16_1ch;
    fmt16_1ch.codec = audio::kCodecLpcm;
    fmt16_1ch.sample_rate = 16000U;
    fmt16_1ch.channels = 1U;
    sink.onAudioStarted(media_id, fmt16_1ch, 0U);
    const int16_t pcm2[3] = {1000, -2000, 3000};
    sink.onAudioPcm(media_id, fmt16_1ch, pcm2, 3U, 2U, 10U);
    DeviceOccurrenceCtx w1 = {"entertainment", 1U, 3U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &w1));

    // 3. Reconfigure via onAudioPcm directly to 48000 Hz stereo (no onAudioStarted).
    audio::AudioFormat fmt48_2ch;
    fmt48_2ch.codec = audio::kCodecLpcm;
    fmt48_2ch.sample_rate = 48000U;
    fmt48_2ch.channels = 2U;
    const int16_t pcm3[4] = {500, -500, 600, -600};
    sink.onAudioPcm(media_id, fmt48_2ch, pcm3, 4U, 3U, 20U);
    DeviceOccurrenceCtx w2 = {"entertainment", 2U, 4U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &w2));

    sink.stop();
    CHECK(hasActiveOpensZero(NULL));
    CHECK(mockState().verifyCloseBeforeOpen("entertainment"));
    {
        plat::LockGuard lock(mockState().mu);
        CHECK_EQ(static_cast<size_t>(0), mockState().busy_open_rejections);
    }

    MockHandle* h0 = mockState().findByName("entertainment", 0U);
    MockHandle* h1 = mockState().findByName("entertainment", 1U);
    MockHandle* h2 = mockState().findByName("entertainment", 2U);
    REQUIRE(h0 != NULL && h1 != NULL && h2 != NULL);
    {
        plat::LockGuard lock(mockState().mu);
        CHECK_EQ(44100U, h0->rate);
        CHECK_EQ(2U, h0->channels);
        CHECK_EQ(16000U, h1->rate);
        CHECK_EQ(1U, h1->channels);
        CHECK_EQ(48000U, h2->rate);
        CHECK_EQ(2U, h2->channels);
    }
    const std::vector<int16_t> w_h1 = mockState().copyWritten("entertainment", 1U);
    REQUIRE(w_h1.size() == 3U);
    CHECK_EQ(static_cast<int16_t>(1000), w_h1[0]);
    CHECK_EQ(static_cast<int16_t>(3000), w_h1[2]);
    const std::vector<int16_t> w_h2 = mockState().copyWritten("entertainment", 2U);
    REQUIRE(w_h2.size() == 4U);
    CHECK_EQ(static_cast<int16_t>(500), w_h2[0]);
    CHECK_EQ(static_cast<int16_t>(-600), w_h2[3]);
}

TEST_CASE(evoMicRestartWithoutStopClosesBeforeReopen) {
    mockState().reset();
    {
        plat::LockGuard lock(mockState().mu);
        for (int i = 0; i < 32; ++i) {
            mockState().capture_pattern.push_back(static_cast<int16_t>(200 + i));
        }
    }

    plat::EvoMic mic(makeMockApi());
    MicCaptureRecorder rec;
    REQUIRE(mic.start(&MicCaptureRecorder::onSamples, &rec));

    audio::MicStreamParams p16;
    p16.supported = true;
    p16.format.codec = audio::kCodecLpcm;
    p16.format.sample_rate = 16000U;
    p16.format.channels = 1U;
    REQUIRE(mic.startCapture(p16));

    MicTargetCtx target1 = {&rec, 320U};
    REQUIRE(waitForCondition(&hasCapturedSamples, &target1));

    // Restart at 24 kHz WITHOUT an intervening stopCapture().
    {
        plat::LockGuard lock(rec.mu);
        rec.samples.clear();
        rec.chunk_sizes.clear();
    }
    audio::MicStreamParams p24 = p16;
    p24.format.sample_rate = 24000U;
    REQUIRE(mic.startCapture(p24));

    std::pair<plat::EvoMic*, uint64_t> wait2(&mic, 2ULL);
    REQUIRE(waitForCondition(&micHasStartedCount, &wait2));
    MicTargetCtx target2 = {&rec, 480U};
    REQUIRE(waitForCondition(&hasCapturedSamples, &target2));

    mic.stop();
    CHECK(hasActiveOpensZero(NULL));
    CHECK(mockState().verifyCloseBeforeOpen("mic1"));

    MockHandle* h0 = mockState().findByName("mic1", 0U);
    MockHandle* h1 = mockState().findByName("mic1", 1U);
    REQUIRE(h0 != NULL && h1 != NULL);
    {
        plat::LockGuard lock(mockState().mu);
        CHECK_EQ(static_cast<size_t>(0), mockState().busy_open_rejections);
        CHECK(h0->closed);
        CHECK_EQ(16000U, h0->rate);
        CHECK_EQ(24000U, h1->rate);
    }
}

TEST_CASE(sameDeviceOwnershipParkingAntiPingPongAndResume) {
    mockState().reset();
    plat::EvoAudioSink sink(makeMockApi());
    REQUIRE(sink.start());

    const plat::AudioStreamId tel_id(100, "telephony");
    const plat::AudioStreamId siri_id(100, "speechRecognition");

    audio::AudioFormat tel_fmt;
    tel_fmt.codec = audio::kCodecLpcm;
    tel_fmt.sample_rate = 16000U;
    tel_fmt.channels = 1U;

    audio::AudioFormat siri_fmt;
    siri_fmt.codec = audio::kCodecLpcm;
    siri_fmt.sample_rate = 24000U;
    siri_fmt.channels = 1U;

    // 1. Telephony owns tel_out1.
    sink.onAudioStarted(tel_id, tel_fmt, 0U);
    const int16_t tel_pcm1[2] = {111, 222};
    sink.onAudioPcm(tel_id, tel_fmt, tel_pcm1, 2U, 1U, 0U);
    DeviceOccurrenceCtx w0 = {"tel_out1", 0U, 2U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &w0));

    // 2. speechRecognition starts on tel_out1 -> closes tel_id handle first, opens siri_id.
    sink.onAudioStarted(siri_id, siri_fmt, 0U);
    const int16_t siri_pcm1[2] = {333, 444};
    sink.onAudioPcm(siri_id, siri_fmt, siri_pcm1, 2U, 1U, 0U);
    DeviceOccurrenceCtx w1 = {"tel_out1", 1U, 2U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &w1));

    CHECK_EQ(static_cast<size_t>(1), sink.stats().parked_streams);
    CHECK_EQ(static_cast<uint64_t>(0), sink.stats().open_failures);

    // 3. Anti-ping-pong: send 50 PCM packets on parked tel_id (including a format variation).
    size_t opens_before = 0;
    size_t closes_before = 0;
    {
        plat::LockGuard lock(mockState().mu);
        opens_before = mockState().open_count;
        closes_before = mockState().close_count;
    }
    const int16_t parked_sentinel[4] = {-9999, -9999, -9999, -9999};
    audio::AudioFormat alt_parked_fmt = tel_fmt;
    alt_parked_fmt.sample_rate = 48000U;
    alt_parked_fmt.channels = 2U;
    for (int i = 0; i < 50; ++i) {
        const audio::AudioFormat& f = (i % 5 == 0) ? alt_parked_fmt : tel_fmt;
        const size_t n = 4U;
        sink.onAudioPcm(tel_id, f, parked_sentinel, n, static_cast<uint16_t>(i + 2), 0U);
    }
    // Pump another siri packet through the worker to verify no reopen/close happened.
    const int16_t siri_pcm2[2] = {555, 666};
    sink.onAudioPcm(siri_id, siri_fmt, siri_pcm2, 2U, 2U, 2U);
    DeviceOccurrenceCtx w1_more = {"tel_out1", 1U, 4U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &w1_more));

    {
        plat::LockGuard lock(mockState().mu);
        CHECK_EQ(opens_before, mockState().open_count);
        CHECK_EQ(closes_before, mockState().close_count);
        CHECK_EQ(static_cast<size_t>(0), mockState().busy_open_rejections);
    }
    CHECK(sink.stats().parked_frames_discarded >= 100U);
    const std::vector<int16_t> siri_samples = mockState().copyWritten("tel_out1", 1U);
    for (size_t i = 0; i < siri_samples.size(); ++i) {
        CHECK(siri_samples[i] != -9999);
    }

    // 4. Stop speechRecognition -> parked tel_id resumes with its own format and fresh audio.
    sink.onAudioStopped(siri_id);
    DeviceOccurrenceCtx o2 = {"tel_out1", 3U, 0U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceConfigured, &o2));
    CHECK_EQ(static_cast<size_t>(0), sink.stats().parked_streams);

    MockHandle* h2 = mockState().findByName("tel_out1", 2U);
    REQUIRE(h2 != NULL);
    {
        plat::LockGuard lock(mockState().mu);
        CHECK_EQ(16000U, h2->rate);
        CHECK(h2->written_samples.empty());  // no stale parked PCM replayed
    }

    const int16_t tel_pcm2[2] = {777, 888};
    sink.onAudioPcm(tel_id, tel_fmt, tel_pcm2, 2U, 100U, 0U);
    DeviceOccurrenceCtx w2 = {"tel_out1", 2U, 2U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &w2));
    const std::vector<int16_t> resumed_samples = mockState().copyWritten("tel_out1", 2U);
    REQUIRE(resumed_samples.size() == 2U);
    CHECK_EQ(static_cast<int16_t>(777), resumed_samples[0]);
    CHECK_EQ(static_cast<int16_t>(888), resumed_samples[1]);

    sink.stop();
    CHECK(hasActiveOpensZero(NULL));
    CHECK(mockState().verifyCloseBeforeOpen("tel_out1"));
    {
        plat::LockGuard lock(mockState().mu);
        CHECK_EQ(static_cast<size_t>(0), mockState().busy_open_rejections);
    }
}

TEST_CASE(threeStreamsOnOneDeviceResumeInMostRecentOrderAndConcurrentDevices) {
    mockState().reset();
    plat::EvoAudioConfig cfg;
    cfg.duck_ramp_ms = 0U;
    plat::EvoAudioSink sink(makeMockApi(), cfg);
    REQUIRE(sink.start());

    const plat::AudioStreamId s1(100, "media");
    const plat::AudioStreamId s2(100, "default");
    const plat::AudioStreamId s3(100, "alert");
    const plat::AudioStreamId alt_id(101, "default");
    const plat::AudioStreamId tel_id(100, "telephony");

    audio::AudioFormat f1;
    f1.codec = audio::kCodecLpcm;
    f1.sample_rate = 44100U;
    f1.channels = 2U;
    audio::AudioFormat f2 = f1;
    f2.sample_rate = 48000U;
    audio::AudioFormat f3 = f1;
    f3.sample_rate = 16000U;

    // Concurrent streams on other devices stay unaffected.
    audio::AudioFormat mono16 = f3;
    mono16.channels = 1U;
    sink.onAudioStarted(alt_id, mono16, 0U);
    sink.onAudioStarted(tel_id, mono16, 0U);

    sink.onAudioStarted(s1, f1, 0U);
    const int16_t p1[2] = {10, 10};
    sink.onAudioPcm(s1, f1, p1, 2U, 1U, 0U);
    DeviceOccurrenceCtx ent_w0 = {"entertainment", 0U, 2U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &ent_w0));

    sink.onAudioStarted(s2, f2, 0U);
    const int16_t p2[2] = {20, 20};
    sink.onAudioPcm(s2, f2, p2, 2U, 1U, 0U);
    DeviceOccurrenceCtx ent_w1 = {"entertainment", 1U, 2U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &ent_w1));

    sink.onAudioStarted(s3, f3, 0U);
    const int16_t p3[2] = {30, 30};
    sink.onAudioPcm(s3, f3, p3, 2U, 1U, 0U);
    DeviceOccurrenceCtx ent_w2 = {"entertainment", 2U, 2U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &ent_w2));

    CHECK_EQ(static_cast<size_t>(2), sink.stats().parked_streams);

    // Concurrent devices continue playing without interference.
    const int16_t p_other[1] = {555};
    sink.onAudioPcm(alt_id, mono16, p_other, 1U, 1U, 0U);
    sink.onAudioPcm(tel_id, mono16, p_other, 1U, 1U, 0U);
    WrittenCountCtx w_alt = {"carplay_alt", 1U};
    WrittenCountCtx w_tel = {"tel_out1", 1U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_alt));
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_tel));

    // Stop S3 -> S2 (most recently started parked stream) resumes.
    sink.onAudioStopped(s3);
    DeviceOccurrenceCtx ent_o3 = {"entertainment", 4U, 0U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceConfigured, &ent_o3));
    MockHandle* h3 = mockState().findByName("entertainment", 3U);
    REQUIRE(h3 != NULL);
    {
        plat::LockGuard lock(mockState().mu);
        CHECK_EQ(48000U, h3->rate);
    }
    const int16_t p2b[2] = {21, 21};
    sink.onAudioPcm(s2, f2, p2b, 2U, 2U, 0U);
    DeviceOccurrenceCtx ent_w3 = {"entertainment", 3U, 2U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &ent_w3));

    // Stop S2 -> S1 resumes.
    sink.onAudioStopped(s2);
    DeviceOccurrenceCtx ent_o4 = {"entertainment", 5U, 0U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceConfigured, &ent_o4));
    MockHandle* h4 = mockState().findByName("entertainment", 4U);
    REQUIRE(h4 != NULL);
    {
        plat::LockGuard lock(mockState().mu);
        CHECK_EQ(44100U, h4->rate);
    }
    const int16_t p1b[2] = {12, 12};
    sink.onAudioPcm(s1, f1, p1b, 2U, 2U, 0U);
    DeviceOccurrenceCtx ent_w4 = {"entertainment", 4U, 2U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &ent_w4));

    sink.stop();
    CHECK(hasActiveOpensZero(NULL));
    CHECK(mockState().verifyCloseBeforeOpen("entertainment"));
    CHECK(mockState().verifyCloseBeforeOpen("carplay_alt"));
    CHECK(mockState().verifyCloseBeforeOpen("tel_out1"));
    {
        plat::LockGuard lock(mockState().mu);
        CHECK_EQ(static_cast<size_t>(0), mockState().busy_open_rejections);
    }
}

TEST_CASE(implicitStartParkedStopOwnerFailAndParkedAltDucking) {
    mockState().reset();
    plat::EvoAudioConfig cfg;
    cfg.duck_on_alt_stream = true;
    // Share a device between alt and telephony to verify a parked alt stream does not duck.
    cfg.alt_device = "shared_dev";
    cfg.telephony_device = "shared_dev";
    cfg.duck_ramp_ms = 0U;

    plat::EvoAudioSink sink(makeMockApi(), cfg);
    REQUIRE(sink.start());

    const plat::AudioStreamId alt_id(101, "default");
    const plat::AudioStreamId tel_id(100, "telephony");
    const plat::AudioStreamId tel_implicit(100, "speechRecognition");

    audio::AudioFormat mono16;
    mono16.codec = audio::kCodecLpcm;
    mono16.sample_rate = 16000U;
    mono16.channels = 1U;

    // 1. Alt owns shared_dev -> media is auto-ducked.
    sink.onAudioStarted(alt_id, mono16, 0U);
    CHECK(sink.isDucked());
    const int16_t s1[1] = {101};
    sink.onAudioPcm(alt_id, mono16, s1, 1U, 1U, 0U);
    DeviceOccurrenceCtx sh_w0 = {"shared_dev", 0U, 1U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &sh_w0));

    // 2. Implicit start of speechRecognition via onAudioPcm -> takes ownership, parks alt_id!
    const int16_t s2[1] = {202};
    sink.onAudioPcm(tel_implicit, mono16, s2, 1U, 1U, 0U);
    DeviceOccurrenceCtx sh_w1 = {"shared_dev", 1U, 1U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &sh_w1));
    // Parked alt stream is inaudible, so it must NOT duck media.
    CHECK(!sink.isDucked());

    // 3. Explicit start of telephony parks tel_implicit; subsequent onAudioPcm on parked
    //    tel_implicit must NOT reclaim ownership (implicit start counts once only).
    sink.onAudioStarted(tel_id, mono16, 0U);
    const int16_t s3[1] = {303};
    sink.onAudioPcm(tel_id, mono16, s3, 1U, 1U, 0U);
    DeviceOccurrenceCtx sh_w2 = {"shared_dev", 2U, 1U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceWritten, &sh_w2));

    const int16_t ignored_implicit[1] = {-777};
    sink.onAudioPcm(tel_implicit, mono16, ignored_implicit, 1U, 2U, 1U);
    CHECK_EQ(static_cast<size_t>(2), sink.stats().parked_streams);

    // Stopping a parked stream does not disturb the owner.
    sink.onAudioStopped(tel_implicit);
    CHECK_EQ(static_cast<size_t>(1), sink.stats().parked_streams);

    // 4. Fatal write error on owner (tel_id) promotes parked alt_id back to owner!
    {
        plat::LockGuard lock(mockState().mu);
        mockState().fail_recover = true;
        mockState().next_write_err = kMockErrFatal;
    }
    const int16_t s4[1] = {404};
    sink.onAudioPcm(tel_id, mono16, s4, 1U, 2U, 1U);
    REQUIRE(waitForCondition(&hasWriteErrorAtLeast, &sink));
    DeviceOccurrenceCtx sh_o3 = {"shared_dev", 4U, 0U};
    REQUIRE(waitForCondition(&hasDeviceOccurrenceConfigured, &sh_o3));
    CHECK(sink.isDucked());

    sink.stop();
    CHECK(hasActiveOpensZero(NULL));
    CHECK(mockState().verifyCloseBeforeOpen("shared_dev"));
}

TEST_CASE(duckingRampMonotonicityChunksReversalAndZeroInstant) {
    // Default config must have a 10..20 ms ramp.
    const plat::EvoAudioConfig default_cfg;
    CHECK(default_cfg.duck_ramp_ms >= 10U && default_cfg.duck_ramp_ms <= 20U);

    // 1. Linear ramp: 10 ms at 10000 Hz = 100 frames.
    mockState().reset();
    plat::EvoAudioConfig cfg;
    cfg.duck_gain_q15 = 8192;  // 0.25x -> 32000 becomes 8000
    cfg.duck_ramp_ms = 10U;
    plat::EvoAudioSink sink(makeMockApi(), cfg);
    REQUIRE(sink.start());

    const plat::AudioStreamId media_id(100, "media");
    audio::AudioFormat fmt;
    fmt.codec = audio::kCodecLpcm;
    fmt.sample_rate = 10000U;
    fmt.channels = 2U;
    sink.onAudioStarted(media_id, fmt, 0U);

    // Steady unity pass-through must be bit-exact (including extremes).
    const int16_t bit_exact[4] = {32767, -32768, 12345, -1};
    sink.onAudioPcm(media_id, fmt, bit_exact, 4U, 1U, 0U);
    WrittenCountCtx w_exact = {"entertainment", 4U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_exact));
    {
        const std::vector<int16_t> out = mockState().copyWritten("entertainment");
        REQUIRE(out.size() == 4U);
        for (size_t i = 0; i < 4U; ++i) {
            CHECK_EQ(bit_exact[i], out[i]);
        }
    }

    // Ramp down across chunk boundary: 40 frames + 80 frames = 120 frames (ramp length 100).
    sink.onAudioDuck(true);
    std::vector<int16_t> chunk40(40U * 2U);
    for (size_t f = 0; f < 40U; ++f) {
        chunk40[f * 2U] = 32000;
        chunk40[f * 2U + 1U] = -32000;
    }
    sink.onAudioPcm(media_id, fmt, &chunk40[0], chunk40.size(), 2U, 0U);
    WrittenCountCtx w_c1 = {"entertainment", 4U + 80U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_c1));

    std::vector<int16_t> chunk80(80U * 2U);
    for (size_t f = 0; f < 80U; ++f) {
        chunk80[f * 2U] = 32000;
        chunk80[f * 2U + 1U] = -32000;
    }
    sink.onAudioPcm(media_id, fmt, &chunk80[0], chunk80.size(), 3U, 40U);
    WrittenCountCtx w_c2 = {"entertainment", 4U + 240U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_c2));

    {
        const std::vector<int16_t> out = mockState().copyWritten("entertainment");
        REQUIRE(out.size() == 244U);
        const size_t base = 4U;
        // Same gain on L and R, monotonically non-increasing from < 32000 down to 8000 at frame 99.
        CHECK(out[base] < 32000);
        CHECK(out[base + 39U * 2U] > 8000);  // still mid-ramp at end of chunk 1
        for (size_t f = 0; f < 100U; ++f) {
            const int16_t l = out[base + f * 2U];
            const int16_t r = out[base + f * 2U + 1U];
            CHECK_EQ(l, static_cast<int16_t>(-r));
            CHECK(l >= 8000 && l <= 32000);
            if (f > 0U) {
                CHECK(l <= out[base + (f - 1U) * 2U]);
            }
        }
        CHECK_EQ(static_cast<int16_t>(8000), out[base + 99U * 2U]);
        for (size_t f = 100U; f < 120U; ++f) {
            CHECK_EQ(static_cast<int16_t>(8000), out[base + f * 2U]);
        }
    }

    // Ramp up back to unity over 100 frames.
    sink.onAudioDuck(false);
    std::vector<int16_t> chunk120(120U * 2U);
    for (size_t f = 0; f < 120U; ++f) {
        chunk120[f * 2U] = 32000;
        chunk120[f * 2U + 1U] = -32000;
    }
    sink.onAudioPcm(media_id, fmt, &chunk120[0], chunk120.size(), 4U, 120U);
    WrittenCountCtx w_up = {"entertainment", 4U + 240U + 240U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_up));

    {
        const std::vector<int16_t> out = mockState().copyWritten("entertainment");
        REQUIRE(out.size() == 484U);
        const size_t base = 244U;
        CHECK(out[base] > 8000 && out[base] < 32000);
        for (size_t f = 0; f < 100U; ++f) {
            const int16_t l = out[base + f * 2U];
            CHECK(l >= 8000 && l <= 32000);
            if (f > 0U) {
                CHECK(l >= out[base + (f - 1U) * 2U]);
            }
        }
        CHECK_EQ(static_cast<int16_t>(32000), out[base + 99U * 2U]);
        for (size_t f = 100U; f < 120U; ++f) {
            CHECK_EQ(static_cast<int16_t>(32000), out[base + f * 2U]);
        }
    }

    // Mid-ramp reversal: duck ON for 50 frames, then flip OFF mid-ramp and send 120 frames.
    sink.onAudioDuck(true);
    std::vector<int16_t> chunk50(50U * 2U);
    for (size_t f = 0; f < 50U; ++f) {
        chunk50[f * 2U] = 32000;
        chunk50[f * 2U + 1U] = -32000;
    }
    sink.onAudioPcm(media_id, fmt, &chunk50[0], chunk50.size(), 5U, 240U);
    WrittenCountCtx w_mid = {"entertainment", 484U + 100U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_mid));

    sink.onAudioDuck(false);
    sink.onAudioPcm(media_id, fmt, &chunk120[0], chunk120.size(), 6U, 290U);
    WrittenCountCtx w_rev = {"entertainment", 584U + 240U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_rev));

    {
        const std::vector<int16_t> out = mockState().copyWritten("entertainment");
        REQUIRE(out.size() == 824U);
        const int16_t mid_val = out[584U - 2U];
        CHECK(mid_val > 8000 && mid_val < 32000);
        const size_t base = 584U;
        CHECK(out[base] >= mid_val && out[base] < 32000);
        for (size_t f = 1; f < 100U; ++f) {
            CHECK(out[base + f * 2U] >= out[base + (f - 1U) * 2U]);
            CHECK(out[base + f * 2U] <= 32000);
        }
        CHECK_EQ(static_cast<int16_t>(32000), out[base + 99U * 2U]);
    }
    sink.stop();

    // 2. Ramp length 0 reproduces instant switch.
    mockState().reset();
    cfg.duck_ramp_ms = 0U;
    plat::EvoAudioSink instant_sink(makeMockApi(), cfg);
    REQUIRE(instant_sink.start());
    instant_sink.onAudioStarted(media_id, fmt, 0U);
    instant_sink.onAudioDuck(true);
    const int16_t one_frame[2] = {32000, -32000};
    instant_sink.onAudioPcm(media_id, fmt, one_frame, 2U, 1U, 0U);
    WrittenCountCtx w_i1 = {"entertainment", 2U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_i1));
    instant_sink.onAudioDuck(false);
    instant_sink.onAudioPcm(media_id, fmt, one_frame, 2U, 2U, 1U);
    WrittenCountCtx w_i2 = {"entertainment", 4U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_i2));
    {
        const std::vector<int16_t> out = mockState().copyWritten("entertainment");
        REQUIRE(out.size() == 4U);
        CHECK_EQ(static_cast<int16_t>(8000), out[0]);
        CHECK_EQ(static_cast<int16_t>(-8000), out[1]);
        CHECK_EQ(static_cast<int16_t>(32000), out[2]);
        CHECK_EQ(static_cast<int16_t>(-32000), out[3]);
    }
    instant_sink.stop();
}

TEST_CASE(deterministicRingBufferWrapAround) {
    mockState().reset();
    {
        plat::LockGuard lock(mockState().mu);
        mockState().block_writei = true;
    }

    plat::EvoAudioConfig cfg;
    cfg.max_queue_ms = 20U;  // 20 ms at 10000 Hz = 200 frames (400 stereo samples)
    cfg.duck_ramp_ms = 0U;
    plat::EvoAudioSink sink(makeMockApi(), cfg);
    REQUIRE(sink.start());

    const plat::AudioStreamId media_id(100, "media");
    audio::AudioFormat fmt;
    fmt.codec = audio::kCodecLpcm;
    fmt.sample_rate = 10000U;
    fmt.channels = 2U;

    sink.onAudioStarted(media_id, fmt, 0U);
    // Sentinel frame causes worker to enter mockWritei and pause deterministically on the gate.
    const int16_t sentinel[2] = {999, -999};
    sink.onAudioPcm(media_id, fmt, sentinel, 2U, 0U, 0U);
    const size_t gate_target = 1U;
    REQUIRE(waitForCondition(&hasWriteiBlockedAtLeast, const_cast<size_t*>(&gate_target)));

    // Push 120 + 120 + 60 = 300 frames into 200-frame ring capacity while worker is paused.
    // This wraps tail across the end of the buffer and advances head across the end as well.
    std::vector<int16_t> b1(120U * 2U);
    for (size_t i = 0; i < 120U; ++i) {
        b1[i * 2U] = static_cast<int16_t>(1 + i);
        b1[i * 2U + 1U] = static_cast<int16_t>(-(1 + static_cast<int>(i)));
    }
    sink.onAudioPcm(media_id, fmt, &b1[0], b1.size(), 1U, 1U);

    std::vector<int16_t> b2(120U * 2U);
    for (size_t i = 0; i < 120U; ++i) {
        b2[i * 2U] = static_cast<int16_t>(121 + i);
        b2[i * 2U + 1U] = static_cast<int16_t>(-(121 + static_cast<int>(i)));
    }
    sink.onAudioPcm(media_id, fmt, &b2[0], b2.size(), 2U, 121U);

    std::vector<int16_t> b3(60U * 2U);
    for (size_t i = 0; i < 60U; ++i) {
        b3[i * 2U] = static_cast<int16_t>(241 + i);
        b3[i * 2U + 1U] = static_cast<int16_t>(-(241 + static_cast<int>(i)));
    }
    sink.onAudioPcm(media_id, fmt, &b3[0], b3.size(), 3U, 241U);

    CHECK_EQ(static_cast<uint64_t>(100), sink.stats().overrun_frames);

    // Release gate and wait for all 200 surviving frames + sentinel (201 frames = 402 samples).
    {
        plat::LockGuard lock(mockState().mu);
        mockState().block_writei = false;
    }
    WrittenCountCtx w_all = {"entertainment", 402U};
    REQUIRE(waitForCondition(&hasWrittenSamples, &w_all));

    const std::vector<int16_t> ent = mockState().copyWritten("entertainment");
    REQUIRE(ent.size() == 402U);
    CHECK_EQ(static_cast<int16_t>(999), ent[0]);
    CHECK_EQ(static_cast<int16_t>(-999), ent[1]);
    for (size_t i = 0; i < 200U; ++i) {
        const int16_t expected = static_cast<int16_t>(101U + i);
        CHECK_EQ(expected, ent[2U + i * 2U]);
        CHECK_EQ(static_cast<int16_t>(-expected), ent[2U + i * 2U + 1U]);
    }

    sink.stop();
    CHECK(hasActiveOpensZero(NULL));
}

int main() { return test_support::runAll("test_evo_audio"); }
