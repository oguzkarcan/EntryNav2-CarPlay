#include "carplay/platform/reactor.hpp"

#include <limits.h>

namespace carplay {
namespace platform {

const size_t Reactor::kMaxSockets;
const size_t Reactor::kMaxTimers;
const size_t Reactor::kMaxPostedTasks;
const uint32_t Reactor::kNoTimer;

namespace {
const int64_t kNanosPerMilli = 1000000LL;
const int64_t kInt64Max = 0x7fffffffffffffffLL;  // INT64_MAX needs __STDC_LIMIT_MACROS on old glibc
}

Reactor::Reactor(ClockFn clock)
    : clock_(clock != NULL ? clock : &monotonicNanos),
      wake_read_(kInvalidSocket),
      wake_write_(kInvalidSocket),
      next_generation_(1),
      next_timer_id_(1),
      next_timer_seq_(0),
      dispatching_(false),
      slots_dirty_(false),
      wake_pending_(false),
      stop_requested_(false) {}

Reactor::~Reactor() { wakePairClose(wake_read_, wake_write_); }

bool Reactor::init() {
    if (initialized()) {
        return true;
    }
    if (!wakePairOpen(wake_read_, wake_write_)) {
        return false;
    }
    slots_.reserve(kMaxSockets);
    poll_items_.reserve(kMaxSockets + 1);
    poll_slot_gen_.reserve(kMaxSockets + 1);
    poll_slot_index_.reserve(kMaxSockets + 1);
    poll_set_.reserve(kMaxSockets + 1);
    timers_.reserve(kMaxTimers);
    run_tasks_.reserve(kMaxPostedTasks);
    LockGuard lock(mutex_);
    posted_.reserve(kMaxPostedTasks);
    return true;
}

// ------------------------------------------------------------------------------------------------
// Sockets
// ------------------------------------------------------------------------------------------------

int Reactor::findSlot(SocketHandle handle) const {
    for (size_t i = 0; i < slots_.size(); ++i) {
        if (slots_[i].active && slots_[i].handle == handle) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

size_t Reactor::socketCount() const {
    size_t n = 0;
    for (size_t i = 0; i < slots_.size(); ++i) {
        if (slots_[i].active) {
            ++n;
        }
    }
    return n;
}

bool Reactor::contains(SocketHandle handle) const { return findSlot(handle) >= 0; }

bool Reactor::add(SocketHandle handle, IoHandler* handler, unsigned interest) {
    if (!initialized() || handle == kInvalidSocket || handler == NULL || findSlot(handle) >= 0 ||
        socketCount() >= kMaxSockets) {
        return false;
    }
    Slot s;
    s.handle = handle;
    s.handler = handler;
    s.interest = interest & (kPollIn | kPollOut);
    s.generation = next_generation_++;
    if (next_generation_ == 0) {
        next_generation_ = 1;
    }
    s.active = true;
    slots_.push_back(s);
    return true;
}

bool Reactor::modify(SocketHandle handle, unsigned interest) {
    const int i = findSlot(handle);
    if (i < 0) {
        return false;
    }
    slots_[static_cast<size_t>(i)].interest = interest & (kPollIn | kPollOut);
    return true;
}

bool Reactor::remove(SocketHandle handle) {
    const int i = findSlot(handle);
    if (i < 0) {
        return false;
    }
    Slot& s = slots_[static_cast<size_t>(i)];
    s.active = false;
    s.handler = NULL;
    slots_dirty_ = true;
    if (!dispatching_) {
        compactSlots();
    }
    return true;
}

void Reactor::compactSlots() {
    if (!slots_dirty_) {
        return;
    }
    size_t w = 0;
    for (size_t r = 0; r < slots_.size(); ++r) {
        if (slots_[r].active) {
            if (w != r) {
                slots_[w] = slots_[r];
            }
            ++w;
        }
    }
    slots_.resize(w);
    slots_dirty_ = false;
}

// ------------------------------------------------------------------------------------------------
// Timers
// ------------------------------------------------------------------------------------------------

uint32_t Reactor::startTimer(int64_t delay_ms, int64_t period_ms, TimerHandler* handler) {
    if (delay_ms < 0 || period_ms < 0 || delay_ms > kInt64Max / kNanosPerMilli ||
        period_ms > kInt64Max / kNanosPerMilli) {
        return kNoTimer;
    }
    return startTimerNanos(delay_ms * kNanosPerMilli, period_ms * kNanosPerMilli, handler);
}

uint32_t Reactor::startTimerNanos(int64_t delay_ns, int64_t period_ns, TimerHandler* handler) {
    if (handler == NULL || delay_ns < 0 || period_ns < 0 || timerCount() >= kMaxTimers) {
        return kNoTimer;
    }
    // Pick an id not used by an active timer (ids wrap after 2^32 timers).
    uint32_t id = 0;
    for (;;) {
        id = next_timer_id_++;
        if (next_timer_id_ == 0) {
            next_timer_id_ = 1;
        }
        if (id == kNoTimer) {
            continue;
        }
        bool used = false;
        for (size_t i = 0; i < timers_.size(); ++i) {
            if (timers_[i].active && timers_[i].id == id) {
                used = true;
                break;
            }
        }
        if (!used) {
            break;
        }
    }
    Timer t;
    t.id = id;
    t.deadline = clock_() + delay_ns;
    t.period = period_ns;
    t.seq = next_timer_seq_++;
    t.handler = handler;
    t.active = true;
    timers_.push_back(t);
    return id;
}

bool Reactor::cancelTimer(uint32_t id) {
    if (id == kNoTimer) {
        return false;
    }
    for (size_t i = 0; i < timers_.size(); ++i) {
        if (timers_[i].active && timers_[i].id == id) {
            timers_[i].active = false;
            timers_[i].handler = NULL;
            return true;
        }
    }
    return false;
}

size_t Reactor::timerCount() const {
    size_t n = 0;
    for (size_t i = 0; i < timers_.size(); ++i) {
        if (timers_[i].active) {
            ++n;
        }
    }
    return n;
}

int Reactor::computeTimeout(int timeout_ms) const {
    bool have = false;
    int64_t earliest = 0;
    for (size_t i = 0; i < timers_.size(); ++i) {
        if (timers_[i].active && (!have || timers_[i].deadline < earliest)) {
            earliest = timers_[i].deadline;
            have = true;
        }
    }
    if (!have) {
        return timeout_ms;
    }
    const int64_t delta = earliest - clock_();
    int64_t ms = 0;
    if (delta > 0) {
        ms = (delta + kNanosPerMilli - 1) / kNanosPerMilli;  // round up: never wake early and spin
    }
    if (ms > INT_MAX) {
        ms = INT_MAX;
    }
    if (timeout_ms >= 0 && timeout_ms < ms) {
        return timeout_ms;
    }
    return static_cast<int>(ms);
}

int Reactor::runTimers() {
    int fired = 0;
    const int64_t now = clock_();
    // Bounded: a callback that keeps starting zero-delay timers cannot starve the poll loop.
    for (size_t guard = 0; guard < 2 * kMaxTimers; ++guard) {
        int best = -1;
        for (size_t i = 0; i < timers_.size(); ++i) {
            const Timer& t = timers_[i];
            if (!t.active || t.deadline > now) {
                continue;
            }
            if (best < 0 || t.deadline < timers_[static_cast<size_t>(best)].deadline ||
                (t.deadline == timers_[static_cast<size_t>(best)].deadline &&
                 t.seq < timers_[static_cast<size_t>(best)].seq)) {
                best = static_cast<int>(i);
            }
        }
        if (best < 0) {
            break;
        }
        Timer& t = timers_[static_cast<size_t>(best)];
        const uint32_t id = t.id;
        TimerHandler* const handler = t.handler;
        if (t.period > 0) {
            t.deadline += t.period;
            if (t.deadline <= now) {
                const int64_t missed = (now - t.deadline) / t.period + 1;
                t.deadline += missed * t.period;  // coalesce missed ticks, stay on the grid
            }
            t.seq = next_timer_seq_++;
        } else {
            t.active = false;
            t.handler = NULL;
        }
        // `t` may dangle after the callback (startTimer can grow timers_).
        handler->onTimer(id);
        ++fired;
    }
    size_t w = 0;
    for (size_t r = 0; r < timers_.size(); ++r) {
        if (timers_[r].active) {
            if (w != r) {
                timers_[w] = timers_[r];
            }
            ++w;
        }
    }
    timers_.resize(w);
    return fired;
}

// ------------------------------------------------------------------------------------------------
// Posting
// ------------------------------------------------------------------------------------------------

bool Reactor::post(TaskFn fn, void* ctx) {
    if (fn == NULL || !initialized()) {
        return false;
    }
    bool need_wake = false;
    {
        LockGuard lock(mutex_);
        if (posted_.size() >= kMaxPostedTasks) {
            return false;
        }
        Task t;
        t.fn = fn;
        t.ctx = ctx;
        posted_.push_back(t);
        need_wake = !wake_pending_;
        wake_pending_ = true;
    }
    if (need_wake) {
        wakeSignal(wake_write_);
    }
    return true;
}

size_t Reactor::cancelPosted(TaskFn fn, void* ctx) {
    size_t dropped = 0;
    {
        LockGuard lock(mutex_);
        size_t w = 0;
        for (size_t r = 0; r < posted_.size(); ++r) {
            if (posted_[r].fn == fn && posted_[r].ctx == ctx) {
                ++dropped;
                continue;
            }
            if (w != r) {
                posted_[w] = posted_[r];
            }
            ++w;
        }
        posted_.resize(w);
    }
    // The batch runTasks() is iterating right now (when called from inside a task): keep the
    // vector's size, just neutralise the entries.
    for (size_t i = 0; i < run_tasks_.size(); ++i) {
        if (run_tasks_[i].fn == fn && run_tasks_[i].ctx == ctx) {
            run_tasks_[i].fn = NULL;
            ++dropped;
        }
    }
    return dropped;
}

void Reactor::stop() {
    bool need_wake = false;
    {
        LockGuard lock(mutex_);
        stop_requested_ = true;
        need_wake = !wake_pending_;
        wake_pending_ = true;
    }
    if (need_wake && initialized()) {
        wakeSignal(wake_write_);
    }
}

bool Reactor::stopRequested() const {
    LockGuard lock(mutex_);
    return stop_requested_;
}

int Reactor::runTasks() {
    {
        LockGuard lock(mutex_);
        wake_pending_ = false;
        if (posted_.empty()) {
            return 0;
        }
        run_tasks_.swap(posted_);  // both vectors hold kMaxPostedTasks capacity: no allocation
    }
    int n = 0;
    for (size_t i = 0; i < run_tasks_.size(); ++i) {
        const Task t = run_tasks_[i];
        if (t.fn == NULL) {
            continue;  // cancelled by cancelPosted() from an earlier task of this batch
        }
        run_tasks_[i].fn = NULL;  // a task that cancels itself must not be counted as dropped
        t.fn(t.ctx);
        ++n;
    }
    run_tasks_.clear();
    return n;
}

// ------------------------------------------------------------------------------------------------
// Loop
// ------------------------------------------------------------------------------------------------

int Reactor::dispatchSockets(size_t count) {
    int calls = 0;
    for (size_t i = 1; i < count; ++i) {
        const unsigned re = poll_items_[i].revents;
        if (re == 0) {
            continue;
        }
        const size_t idx = poll_slot_index_[i];
        const uint32_t gen = poll_slot_gen_[i];
        // Re-validated before every callback: an earlier callback may have removed it.
#define CARPLAY_SLOT_ALIVE() \
    (idx < slots_.size() && slots_[idx].active && slots_[idx].generation == gen)
        if (!CARPLAY_SLOT_ALIVE()) {
            continue;
        }
        if (re & (kPollErr | kPollNval)) {
            slots_[idx].handler->onError();
            ++calls;
            continue;
        }
        if ((re & kPollIn) || ((re & kPollHup) && (slots_[idx].interest & kPollIn))) {
            slots_[idx].handler->onReadable();
            ++calls;
        } else if (re & kPollHup) {
            slots_[idx].handler->onError();
            ++calls;
            continue;
        }
        if ((re & kPollOut) && CARPLAY_SLOT_ALIVE() && (slots_[idx].interest & kPollOut)) {
            slots_[idx].handler->onWritable();
            ++calls;
        }
#undef CARPLAY_SLOT_ALIVE
    }
    return calls;
}

int Reactor::runOnce(int timeout_ms) {
    if (!initialized()) {
        return -1;
    }
    compactSlots();
    poll_items_.clear();
    poll_slot_gen_.clear();
    poll_slot_index_.clear();
    PollItem wake;
    wake.handle = wake_read_;
    wake.events = kPollIn;
    wake.revents = 0;
    poll_items_.push_back(wake);
    poll_slot_gen_.push_back(0);
    poll_slot_index_.push_back(0);
    for (size_t i = 0; i < slots_.size(); ++i) {
        if (!slots_[i].active || slots_[i].interest == 0) {
            continue;  // interest 0 = paused: not polled, no callbacks
        }
        PollItem p;
        p.handle = slots_[i].handle;
        p.events = slots_[i].interest;
        p.revents = 0;
        poll_items_.push_back(p);
        poll_slot_gen_.push_back(slots_[i].generation);
        poll_slot_index_.push_back(i);
    }
    const int wait_ms = computeTimeout(timeout_ms);
    const int r = poll_set_.wait(&poll_items_[0], poll_items_.size(), wait_ms);
    if (r < 0) {
        return -1;
    }
    int calls = 0;
    if (r > 0) {
        if (poll_items_[0].revents != 0) {
            wakeDrain(wake_read_);
        }
        dispatching_ = true;
        calls += dispatchSockets(poll_items_.size());
        dispatching_ = false;
        compactSlots();
    }
    calls += runTasks();
    calls += runTimers();
    return calls;
}

bool Reactor::run() {
    bool ok = true;
    while (!stopRequested()) {
        if (runOnce(-1) < 0) {
            ok = false;
            break;
        }
    }
    LockGuard lock(mutex_);
    stop_requested_ = false;
    return ok;
}

}  // namespace platform
}  // namespace carplay
