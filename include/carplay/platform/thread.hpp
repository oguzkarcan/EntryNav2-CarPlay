#ifndef CARPLAY_PLATFORM_THREAD_HPP
#define CARPLAY_PLATFORM_THREAD_HPP

// Minimal mutex / thread wrappers: pthreads on POSIX (link -lpthread), Win32 SRWLOCK and
// CreateThread on Windows. Used instead of std::mutex / std::thread because those depend on the
// MinGW thread model (absent with "win32" threads on older toolchains) and need -pthread at both
// compile and link time on old GCC/glibc; the internal wrappers have the same behaviour everywhere.

#include <stddef.h>

#ifndef _WIN32
#include <pthread.h>
#endif

namespace carplay {
namespace platform {

/// Non-recursive mutex (glibc's pthread_mutex_init with default attributes does not fail;
/// SRWLOCK initialisation cannot fail).
class Mutex {
public:
    Mutex();
    ~Mutex();
    void lock();
    void unlock();

private:
    Mutex(const Mutex&) = delete;
    Mutex& operator=(const Mutex&) = delete;
#ifdef _WIN32
    void* srw_;  // SRWLOCK storage (a single pointer, SRWLOCK_INIT == NULL)
#else
    pthread_mutex_t m_;
#endif
};

class LockGuard {
public:
    explicit LockGuard(Mutex& m) : m_(m) { m_.lock(); }
    ~LockGuard() { m_.unlock(); }

private:
    LockGuard(const LockGuard&) = delete;
    LockGuard& operator=(const LockGuard&) = delete;
    Mutex& m_;
};

/// Joinable thread running fn(arg). The destructor joins a still-running thread.
class Thread {
public:
    typedef void (*Fn)(void* arg);
    Thread();
    ~Thread();
    /// Starts the thread; false if already started or the OS refused.
    bool start(Fn fn, void* arg);
    /// Waits for the thread to finish (no-op if not started).
    void join();
    bool running() const { return started_; }

private:
    Thread(const Thread&) = delete;
    Thread& operator=(const Thread&) = delete;
    Fn fn_;
    void* arg_;
    bool started_;
#ifdef _WIN32
    void* handle_;
    static unsigned long __stdcall trampoline(void* self);
#else
    pthread_t tid_;
    static void* trampoline(void* self);
#endif
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_THREAD_HPP
