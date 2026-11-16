#ifndef CARPLAY_PLATFORM_EVO_KNOB_HPP
#define CARPLAY_PLATFORM_EVO_KNOB_HPP

// BMW iDrive controller (ZBE3 E5.01 / CCS35up E5.03), steering wheel MFL (15.02),
// and volume (15.0C / 15.02 / 20.00) reader over vMOST (libvmostclient.so.1).
//
// Filter-opening Get strategy:
//   vmostd runs with EnableFunctionBasedFiltering=true. On connect, EvoKnob shadow-registers
//   0xE5.{01,03,05}, 0x15.{0C,02}, and 0x20.00, then sends read-only Get (OpType 1) requests
//   for CCS35up (0xC46, 0xC47, 0xC4F), MFL/Volume, and AudioMaster volume level.
//   If query_older_immediately is true (recommended for 2017 F20 LCI), E5.01 (0xC10, 0xC20)
//   Gets are sent immediately on connect; otherwise they are sent after CcsProtocol::kSilenceMs
//   (2000 ms) of silence from E5.03. CcsProtocol locks onto the first protocol that answers.

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "carplay/airplay_hid.hpp"
#include "carplay/platform/evo_ccs.hpp"
#include "carplay/platform/thread.hpp"
#include "carplay/platform/vmost_client.hpp"

namespace carplay {
namespace platform {

#ifndef CARPLAY_PLATFORM_EVO_INPUT_MODE_DEFINED
#define CARPLAY_PLATFORM_EVO_INPUT_MODE_DEFINED
enum InputMode {
    kInputOff = 0,
    kInputObserve = 1,
    kInputForward = 2
};
#endif

#ifndef CARPLAY_PLATFORM_EVO_CALLBACK_SYNC_DEFINED
#define CARPLAY_PLATFORM_EVO_CALLBACK_SYNC_DEFINED

namespace detail {

#ifdef _WIN32
typedef unsigned long CallbackThreadId;
CallbackThreadId currentCallbackThreadId();
inline bool sameCallbackThread(CallbackThreadId a, CallbackThreadId b) { return a == b; }
#else
typedef pthread_t CallbackThreadId;
inline CallbackThreadId currentCallbackThreadId() { return pthread_self(); }
inline bool sameCallbackThread(CallbackThreadId a, CallbackThreadId b) {
    return pthread_equal(a, b) != 0;
}
#endif

class EvoStateSync {
public:
#ifdef _WIN32
    EvoStateSync();
    ~EvoStateSync();
    void lock();
    void unlock();
    void wait();
    void broadcast();
#else
    EvoStateSync() {
        pthread_mutex_init(&mu_, NULL);
        pthread_cond_init(&cv_, NULL);
    }
    ~EvoStateSync() {
        pthread_cond_destroy(&cv_);
        pthread_mutex_destroy(&mu_);
    }
    void lock() { pthread_mutex_lock(&mu_); }
    void unlock() { pthread_mutex_unlock(&mu_); }
    void wait() { pthread_cond_wait(&cv_, &mu_); }
    void broadcast() { pthread_cond_broadcast(&cv_); }
#endif

private:
    EvoStateSync(const EvoStateSync&) = delete;
    EvoStateSync& operator=(const EvoStateSync&) = delete;
#ifdef _WIN32
    void* srw_;
    void* cv_;
#else
    pthread_mutex_t mu_;
    pthread_cond_t cv_;
#endif
};

class EvoStateLock {
public:
    explicit EvoStateLock(EvoStateSync& s) : s_(s) { s_.lock(); }
    ~EvoStateLock() { s_.unlock(); }

private:
    EvoStateLock(const EvoStateLock&) = delete;
    EvoStateLock& operator=(const EvoStateLock&) = delete;
    EvoStateSync& s_;
};

template <typename Fn>
struct EvoCallbackSlot {
    enum { kInlineActive = 16 };

    struct ActiveCall {
        CallbackThreadId tid;
        uint64_t gen;

        ActiveCall() : tid(), gen(0U) {}
    };

    Fn fn;
    void* user;
    uint64_t gen;
    unsigned waiters;
    unsigned inline_count;
    ActiveCall inline_active[kInlineActive];
    std::vector<ActiveCall> overflow_active;

    EvoCallbackSlot()
        : fn(NULL), user(NULL), gen(0U), waiters(0U), inline_count(0U) {}

    bool tryEnterLocked(CallbackThreadId tid, Fn& fn_out, void*& user_out, uint64_t& gen_out) {
        if (fn == NULL) {
            return false;
        }
        fn_out = fn;
        user_out = user;
        gen_out = gen;
        ActiveCall ac;
        ac.tid = tid;
        ac.gen = gen;
        if (inline_count < static_cast<unsigned>(kInlineActive)) {
            inline_active[inline_count++] = ac;
        } else {
            overflow_active.push_back(ac);
        }
        return true;
    }

    void exitLocked(CallbackThreadId tid, uint64_t call_gen, EvoStateSync& sync) {
        bool removed = false;
        for (size_t i = overflow_active.size(); i > 0U; --i) {
            const ActiveCall& ac = overflow_active[i - 1U];
            if (ac.gen == call_gen && sameCallbackThread(ac.tid, tid)) {
                overflow_active[i - 1U] = overflow_active.back();
                overflow_active.pop_back();
                removed = true;
                break;
            }
        }
        if (!removed) {
            for (unsigned i = inline_count; i > 0U; --i) {
                const ActiveCall& ac = inline_active[i - 1U];
                if (ac.gen == call_gen && sameCallbackThread(ac.tid, tid)) {
                    inline_active[i - 1U] = inline_active[--inline_count];
                    break;
                }
            }
        }
        if (waiters > 0U) {
            sync.broadcast();
        }
    }

    bool hasOtherInFlightUpTo(CallbackThreadId self_tid, uint64_t max_gen) const {
        for (unsigned i = 0U; i < inline_count; ++i) {
            if (inline_active[i].gen <= max_gen &&
                !sameCallbackThread(inline_active[i].tid, self_tid)) {
                return true;
            }
        }
        for (size_t i = 0U; i < overflow_active.size(); ++i) {
            if (overflow_active[i].gen <= max_gen &&
                !sameCallbackThread(overflow_active[i].tid, self_tid)) {
                return true;
            }
        }
        return false;
    }

    void setAndWaitLocked(Fn new_fn, void* new_user, CallbackThreadId self_tid, EvoStateSync& sync) {
        if (new_fn == fn && new_user == user && new_fn != NULL) {
            if (gen > 0U) {
                const uint64_t prior_gen = gen - 1U;
                while (hasOtherInFlightUpTo(self_tid, prior_gen)) {
                    ++waiters;
                    sync.wait();
                    --waiters;
                }
            }
            return;
        }
        const uint64_t wait_gen = gen;
        fn = new_fn;
        user = new_user;
        ++gen;
        while (hasOtherInFlightUpTo(self_tid, wait_gen)) {
            ++waiters;
            sync.wait();
            --waiters;
        }
    }
};

}  // namespace detail

#endif  // CARPLAY_PLATFORM_EVO_CALLBACK_SYNC_DEFINED

static const uint8_t kControllerFblock = 0xE5U;
static const uint8_t kVolumeFblock = 0x15U;
static const uint8_t kVolumeCsInstance = 0x0CU;
static const uint8_t kVolumeMflInstance = 0x02U;
static const uint16_t kVolumeCsFkt = 0xC01U;
static const uint16_t kVolumeMflFkt = 0x401U;
static const uint16_t kMflTelephoneFkt = 0x400U;
static const uint16_t kMflPttFkt = 0x512U;
static const uint8_t kAudioMasterFblock = 0x20U;
static const uint8_t kAudioMasterInstance = 0x00U;
static const uint16_t kVolumeLevelFkt = 0xC08U;

/// Normalizes CCS35up PushButtonsState (0xC47/0xC4F):
///   1/2/3 -> 1 (pressed / long press)
///   0/4   -> 0 (released / finger resting on capacitive key)
///   other -> retains prev[i] (e.g. 7 = no information)
void normalizePushButtons(const uint8_t* in, size_t n, uint8_t* prev, uint8_t* out);

/// Decodes MFL 0x15.02 fkt 0x400 TelephoneButton: 1=pressed, 0=released, -1=other/no-info.
int decodeTelephoneButton(const VmostMsgView& m);

/// Decodes MFL 0x15.02 fkt 0x512 PTTButton1 (voice/Siri): 1=pressed, 0=released, -1=other/no-info.
int decodePttButton(const VmostMsgView& m);

/// Decodes volume steps from CECenterStack (15.0C.C01) or MFL (15.02.401).
/// Returns 1 when a valid step is present (AudioVolume 1 or 2), 0 otherwise.
int decodeVolumeButton(const VmostMsgView& m, unsigned* steps, uint8_t* raw_dir = NULL);

struct VolumeLevel {
    unsigned value;
    unsigned min;
    unsigned max;

    VolumeLevel() : value(0), min(0), max(0) {}
};

/// Decodes AudioMaster 20.00.C08 Status [PosX, PosY, value, min, max].
bool decodeVolumeLevel(const VmostMsgView& m, VolumeLevel& out);

struct EvoKnobConfig {
    InputMode mode;
    bool query_older_immediately;
    bool use_api_override;
    VmostApi api_override;

    EvoKnobConfig()
        : mode(kInputForward),
          query_older_immediately(false),
          use_api_override(false) {}
};

class EvoKnob {
public:
    typedef void (*EventCallback)(const CcsEvent& ev, void* user);
    typedef void (*Zbe3Callback)(const hid::Zbe3Event& hw, void* user);
    typedef void (*MflButtonCallback)(bool pressed, void* user);
    typedef void (*HardKeyCallback)(CcsKey key, bool pressed, const char* name, void* user);
    typedef void (*VolumeCallback)(unsigned steps, uint8_t direction, void* user);
    typedef void (*VolumeLevelCallback)(const VolumeLevel& level, void* user);

    EvoKnob();
    ~EvoKnob();

    void setEventCallback(EventCallback cb, void* user);
    void setZbe3Callback(Zbe3Callback cb, void* user);
    void setMflTelephoneCallback(MflButtonCallback cb, void* user);
    void setMflPttCallback(MflButtonCallback cb, void* user);
    void setHardKeyCallback(HardKeyCallback cb, void* user);
    void setVolumeCallback(VolumeCallback cb, void* user);
    void setVolumeLevelCallback(VolumeLevelCallback cb, void* user);

    void setQueryOlderImmediately(bool immediate);
    void setApiOverride(const VmostApi* api);

    bool start(InputMode mode, EventCallback cb, void* user);
    bool start(const EvoKnobConfig& cfg, EventCallback cb, void* user);
    void stop();

    void setOwned(bool owned);
    bool owned() const;

    /// During an active iDrive phone call, COM and MFL telephone stay with iDrive.
    void setPhoneToIdrive(bool phone_to_idrive);
    bool phoneToIdrive() const;

    /// Direct message injection (vMOST callback thread or unit tests).
    void onMessage(const VmostMsgView& m);

    /// Unit test helper: configures mode/callbacks without loading libvmostclient or spawning thread.
    void attachForTest(InputMode mode, EventCallback cb, void* user);
    void pollTurnForTest();

    CcsProtocol::Kind protocol() const;
    unsigned messagesReceived() const { return messages_; }
    unsigned e5MessagesReceived() const { return e5_messages_; }
    unsigned filterGetsSent() const { return gets_; }

private:
    EvoKnob(const EvoKnob&) = delete;
    EvoKnob& operator=(const EvoKnob&) = delete;

    static void threadEntry(void* self);
    static void vmostCallback(void* msg, void* user);

    void run();
    bool load();
    void readOlderProtocol();
    void releaseHeldKeys(const char* why);
    void emitZbe3(const hid::Zbe3Event& hw);

    InputMode mode_;
    bool query_older_immediately_;

    detail::EvoCallbackSlot<EventCallback> event_slot_;
    detail::EvoCallbackSlot<Zbe3Callback> zbe3_slot_;
    detail::EvoCallbackSlot<MflButtonCallback> mfl_tel_slot_;
    detail::EvoCallbackSlot<MflButtonCallback> mfl_ptt_slot_;
    detail::EvoCallbackSlot<HardKeyCallback> hard_key_slot_;
    detail::EvoCallbackSlot<VolumeCallback> vol_slot_;
    detail::EvoCallbackSlot<VolumeLevelCallback> level_slot_;

    mutable detail::EvoStateSync state_sync_;
    bool running_;
    bool owned_;
    bool phone_to_idrive_;

    bool started_;
    Thread thread_;
    VmostClient vmost_;
    bool connected_;

    uint8_t registered_[4];
    int n_registered_;
    uint8_t vol_registered_[2];
    int n_vol_registered_;
    bool level_registered_;

    uint8_t push_prev_[8];
    CcsDecoder decoder_;
    CcsProtocol protocol_;
    bool other_protocol_logged_;

    bool tel_down_;
    bool tel_forwarded_;
    bool ptt_down_;
    bool ptt_forwarded_;

    bool sent_push_;
    uint8_t sent_buttons_;
    uint8_t hard_key_down_;

    unsigned gets_;
    unsigned messages_;
    unsigned e5_messages_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_EVO_KNOB_HPP
