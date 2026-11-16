#ifndef CARPLAY_PLATFORM_EVO_TOUCH_HPP
#define CARPLAY_PLATFORM_EVO_TOUCH_HPP

// BMW HU_ENTRYNAV2 / NBT Evo touchscreen reader (UDP port 30567).
//
// Vehicle mode:
//   * Passive read-only AF_PACKET SOCK_DGRAM socket with BPF filter on UDP dport 30567.
//   * While CarPlay owns the screen (owned == true) and a touch sender has been seen,
//     opens a connected UDP 30567 socket (SO_REUSEADDR + SO_REUSEPORT) to the touch sender
//     so the kernel routes touches exclusively to us instead of iDrive. Closed on !owned or stop().
//
// Host/test mode:
//   * startUdpForTest(bind_udp_port, ...) opens a standard localhost UDP socket without CAP_NET_RAW.
//   * feedUdpPayload(...) allows direct synchronous PDU injection in unit tests.

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "carplay/platform/evo_touch_frame.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/thread.hpp"
#include "carplay/platform/udp.hpp"

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

static const uint16_t kTouchPort = 30567U;
static const uint32_t kTouchTimeoutReleaseMs = 400U;

struct UdpView {
    uint32_t src;
    uint16_t sport;
    uint16_t dport;
    const uint8_t* data;
    size_t len;

    UdpView() : src(0U), sport(0U), dport(0U), data(NULL), len(0U) {}
};

/// Parses an unfragmented IPv4/UDP packet starting at the IPv4 header.
bool parseIpv4Udp(const uint8_t* p, size_t n, UdpView& out);

/// True when `b[0..n)` begins with the 0xB0 0x04 0x80 0x02 touch PDU magic.
bool isTouchPdu(const uint8_t* b, size_t n);

/// Pure touch state machine (no I/O): deduplicates, blocks pre-picture touches,
/// tracks multi-touch slots, scales/clamps to display dimensions, and releases on loss.
class TouchTracker {
public:
    enum { NS = kTouchMaxContacts };

    TouchTracker(double sx = 1.0,
                 double sy = 1.0,
                 double ox = 0.0,
                 double oy = 0.0,
                 int max_x = 1279,
                 int max_y = 719);

    int feed(const uint8_t* buf, size_t n, TouchEventOut* out, int max);
    int releaseAll(TouchEventOut* out, int max);

    int activeCount() const;
    unsigned messages() const { return messages_; }
    int lastContacts(RawTouchContact* out, int max) const;
    void reset();

    void setPictureStarted(bool started) { picture_started_ = started; }
    void setLimits(int max_x, int max_y) {
        max_x_ = max_x;
        max_y_ = max_y;
    }
    void setDisplaySize(uint32_t width_pixels, uint32_t height_pixels) {
        max_x_ = width_pixels > 0U ? static_cast<int>(width_pixels) - 1 : 0;
        max_y_ = height_pixels > 0U ? static_cast<int>(height_pixels) - 1 : 0;
    }
    void setScaleOffset(double sx, double sy, double ox, double oy) {
        sx_ = sx;
        sy_ = sy;
        ox_ = ox;
        oy_ = oy;
    }

private:
    void fillActive(TouchEventOut& e, int which) const;
    void emitUp(TouchEventOut& e, int k, int x, int y);

    double sx_;
    double sy_;
    double ox_;
    double oy_;
    int max_x_;
    int max_y_;
    bool active_[NS];
    bool need_down_[NS];
    bool blocked_[NS];
    bool picture_started_;
    int cx_[NS];
    int cy_[NS];
    TouchReassembler reasm_;
    bool have_msg_;
    uint8_t prev_seq0_;
    uint8_t prev_seq1_;
    unsigned messages_;
    RawTouchContact last_[NS];
    int last_n_;
};

class EvoTouch {
public:
    typedef void (*Callback)(const TouchEventOut& ev, void* user);

    EvoTouch();
    ~EvoTouch();

    void setDisplaySize(uint32_t width_pixels, uint32_t height_pixels);
    void setCanvas(uint32_t width_pixels, uint32_t height_pixels) {
        setDisplaySize(width_pixels, height_pixels);
    }
    void setScaleOffset(double sx, double sy, double ox, double oy);

    /// Replaces the touch callback; waits until any in-flight invocation of a prior callback on
    /// another thread has returned (re-entrant calls from inside the callback do not deadlock).
    void setCallback(Callback cb, void* user);

    /// Vehicle mode: AF_PACKET BPF tap on UDP 30567 + connected steal socket while owned.
    bool start(InputMode mode, Callback cb, void* user);

    /// Test mode: standard localhost UDP socket (bind_udp_port = 0 -> ephemeral).
    bool startUdpForTest(uint16_t bind_udp_port, InputMode mode, Callback cb, void* user);
    uint16_t boundUdpPort() const;

    void stop();

    void setOwned(bool owned);
    bool owned() const;

    void setPictureStarted(bool started);
    bool pictureStarted() const;

    /// Direct synchronous injection / timeout helpers for unit tests (without sockets).
    void attachForTest(InputMode mode, Callback cb, void* user);
    int feedUdpPayload(const uint8_t* payload,
                       size_t len,
                       uint32_t src_ip = 0x7F000001U,
                       uint16_t src_port = 30501U,
                       uint32_t now_ms = 0U);
    void checkTimeoutForTest(uint32_t now_ms);

    int activeCount() const;
    unsigned tappedPackets() const { return tapped_; }
    unsigned touchPdusReceived() const;
    unsigned stolenPackets() const { return stolen_; }

private:
    EvoTouch(const EvoTouch&) = delete;
    EvoTouch& operator=(const EvoTouch&) = delete;

    static void threadEntry(void* self);
    void run();
    bool openTap();
    void updateSteal(bool want);
    int handle(const UdpView& u, uint32_t now_ms);
    void dispatchEvents(const TouchEventOut* ev,
                        int n,
                        Callback cb,
                        void* user,
                        uint64_t gen,
                        bool call_cb,
                        bool require_owned,
                        detail::CallbackThreadId tid);
    void releaseOnLostOwnership();
    void releaseOnTimeout(uint32_t now_ms);

    InputMode mode_;
    detail::EvoCallbackSlot<Callback> cb_slot_;

    mutable detail::EvoStateSync state_sync_;
    bool running_;
    bool owned_;
    bool picture_started_;

    bool started_;
    bool udp_test_mode_;
    Thread thread_;
    UdpSocket udp_sock_;
    int tap_;
    int steal_;
    int ifindex_;
    uint32_t peer_ip_;
    uint16_t peer_port_;
    bool have_peer_;
    bool steal_refused_;
    uint32_t last_frame_ms_;
    TouchTracker tracker_;
    unsigned tapped_;
    unsigned touch_pdus_;
    unsigned other_pdus_;
    unsigned events_;
    unsigned sent_;
    unsigned stolen_;
    bool finger_sent_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_EVO_TOUCH_HPP
