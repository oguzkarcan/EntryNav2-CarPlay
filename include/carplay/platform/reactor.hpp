#ifndef CARPLAY_PLATFORM_REACTOR_HPP
#define CARPLAY_PLATFORM_REACTOR_HPP

// Single-threaded poll() reactor.
//
// Concurrency model: ONE thread (the reactor thread) calls runOnce()/run() and every add/modify/
// remove/startTimer/cancelTimer, and owns all registered sockets and the objects behind them (e.g.
// the airplay Session). Nothing in the session path takes a lock. The only thread-safe entry points
// are post() and stop(): they queue work under a mutex and wake the poll through a self-pipe
// (POSIX) or loopback socket pair (Windows).
//
// Re-entrancy: handlers may add, modify or remove ANY registration (including their own) and start
// or cancel ANY timer from inside a callback. A removed registration never receives another
// callback, even if it was ready in the same poll round; a socket added during dispatch is first
// polled in the next round. Slots carry a generation number, so a handle value reused by the OS
// within one round is never confused with the old registration.
//
// Dispatch per ready socket (in registration order):
//   kPollErr / kPollNval                        -> onError()
//   else kPollIn, or kPollHup                   -> onReadable()  (handler sees data or EOF)
//   then, if still registered, kPollOut          -> onWritable()
//   (kPollHup on a socket without read interest -> onError())
//
// Timers: one-shot (period 0) and periodic, monotonic. A periodic timer's next deadline is the
// previous DEADLINE + period (no drift accumulation); if the loop fell behind by several periods,
// the missed ticks are coalesced into one callback and the next deadline is the first grid point in
// the future. Equal deadlines fire in start order.
//
// Limits (fixed, memory reserved in init(); the steady-state loop does not allocate):
//   kMaxSockets user registrations (+1 internal wake handle), kMaxTimers active timers,
//   kMaxPostedTasks queued tasks (post() returns false when full).
//
// Posted tasks hold a raw ctx pointer: an object that posts to itself must call cancelPosted() in
// its destructor (see MediaEngine), otherwise a task still queued would run on freed memory.

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/thread.hpp"

namespace carplay {
namespace platform {

class IoHandler {
public:
    virtual ~IoHandler() {}
    virtual void onReadable() = 0;
    virtual void onWritable() {}
    virtual void onError() = 0;
};

class TimerHandler {
public:
    virtual ~TimerHandler() {}
    virtual void onTimer(uint32_t timer_id) = 0;
};

/// Posted task: fn(ctx) runs on the reactor thread.
typedef void (*TaskFn)(void* ctx);

/// Time source in nanoseconds (default monotonicNanos); tests may inject a fake clock.
typedef int64_t (*ClockFn)();

class Reactor {
public:
    static const size_t kMaxSockets = 64;
    static const size_t kMaxTimers = 64;
    static const size_t kMaxPostedTasks = 256;
    static const uint32_t kNoTimer = 0;

    explicit Reactor(ClockFn clock = &monotonicNanos);
    ~Reactor();

    /// Creates the wake channel and reserves memory. Must succeed before anything else.
    bool init();
    bool initialized() const { return wake_read_ != kInvalidSocket; }

    /// Registers `handle` with interest kPollIn and/or kPollOut. false if already registered,
    /// invalid, NULL handler, or kMaxSockets reached. The reactor never closes the handle.
    bool add(SocketHandle handle, IoHandler* handler, unsigned interest);
    bool modify(SocketHandle handle, unsigned interest);
    /// Unregisters; false if unknown. Safe from inside any callback.
    bool remove(SocketHandle handle);
    bool contains(SocketHandle handle) const;
    size_t socketCount() const;

    /// Starts a timer firing after delay_ms, then every period_ms if period_ms > 0. Returns a
    /// non-zero id, or kNoTimer if the table is full / handler NULL / negative values.
    uint32_t startTimer(int64_t delay_ms, int64_t period_ms, TimerHandler* handler);
    /// Nanosecond-resolution variant.
    uint32_t startTimerNanos(int64_t delay_ns, int64_t period_ns, TimerHandler* handler);
    /// Cancels; false if unknown or already finished. Safe from inside any callback.
    bool cancelTimer(uint32_t id);
    size_t timerCount() const;

    /// Thread-safe: queues fn(ctx) for the reactor thread and wakes it. false when the queue is full
    /// (kMaxPostedTasks) or the reactor is not initialised.
    bool post(TaskFn fn, void* ctx);
    /// Reactor thread only (or while no thread runs the loop): drops every queued task that was
    /// posted with exactly this fn and ctx, including tasks of the batch currently being run, and
    /// returns how many were dropped. An object that posts tasks to itself calls this from its
    /// destructor so that no queued task outlives it. Posting threads must have stopped posting
    /// for that ctx before (a post racing with the cancel may land after it).
    size_t cancelPosted(TaskFn fn, void* ctx);

    /// One iteration: waits up to timeout_ms (< 0: until an event, timer or post; 0: no wait), then
    /// dispatches socket events, posted tasks and due timers. Returns the number of callbacks run
    /// (sockets + tasks + timers), or -1 if poll failed or the reactor is not initialised.
    int runOnce(int timeout_ms);
    /// Loops runOnce(-1) until stop(). Returns false on a poll error.
    bool run();
    /// Thread-safe: makes run() return after the current iteration.
    void stop();
    bool stopRequested() const;

    int64_t now() const { return clock_(); }

private:
    Reactor(const Reactor&) = delete;
    Reactor& operator=(const Reactor&) = delete;

    struct Slot {
        SocketHandle handle;
        IoHandler* handler;
        unsigned interest;
        uint32_t generation;
        bool active;
    };
    struct Timer {
        uint32_t id;
        int64_t deadline;
        int64_t period;
        uint64_t seq;
        TimerHandler* handler;
        bool active;
    };
    struct Task {
        TaskFn fn;
        void* ctx;
    };

    int findSlot(SocketHandle handle) const;
    void compactSlots();
    int computeTimeout(int timeout_ms) const;
    int dispatchSockets(size_t count);
    int runTasks();
    int runTimers();

    ClockFn clock_;
    SocketHandle wake_read_;
    SocketHandle wake_write_;
    std::vector<Slot> slots_;
    std::vector<PollItem> poll_items_;
    std::vector<uint32_t> poll_slot_gen_;   // generation of the slot behind poll_items_[i + 1]
    std::vector<size_t> poll_slot_index_;
    std::vector<Timer> timers_;
    std::vector<Task> run_tasks_;
    PollSet poll_set_;
    uint32_t next_generation_;
    uint32_t next_timer_id_;
    uint64_t next_timer_seq_;
    bool dispatching_;
    bool slots_dirty_;

    // Guarded by mutex_ (shared with posting threads).
    mutable Mutex mutex_;
    std::vector<Task> posted_;
    bool wake_pending_;
    bool stop_requested_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_REACTOR_HPP
