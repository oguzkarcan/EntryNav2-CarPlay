#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include "carplay/platform/thread.hpp"

namespace carplay {
namespace platform {

#ifdef _WIN32
Mutex::Mutex() : srw_(NULL) {}
Mutex::~Mutex() {}
void Mutex::lock() { AcquireSRWLockExclusive(reinterpret_cast<PSRWLOCK>(&srw_)); }
void Mutex::unlock() { ReleaseSRWLockExclusive(reinterpret_cast<PSRWLOCK>(&srw_)); }

Thread::Thread() : fn_(NULL), arg_(NULL), started_(false), handle_(NULL) {}

unsigned long __stdcall Thread::trampoline(void* self) {
    Thread* t = static_cast<Thread*>(self);
    t->fn_(t->arg_);
    return 0;
}

bool Thread::start(Fn fn, void* arg) {
    if (started_ || fn == NULL) {
        return false;
    }
    fn_ = fn;
    arg_ = arg;
    handle_ = CreateThread(NULL, 0, &Thread::trampoline, this, 0, NULL);
    started_ = (handle_ != NULL);
    return started_;
}

void Thread::join() {
    if (!started_) {
        return;
    }
    WaitForSingleObject(static_cast<HANDLE>(handle_), INFINITE);
    CloseHandle(static_cast<HANDLE>(handle_));
    handle_ = NULL;
    started_ = false;
}
#else
Mutex::Mutex() { pthread_mutex_init(&m_, NULL); }
Mutex::~Mutex() { pthread_mutex_destroy(&m_); }
void Mutex::lock() { pthread_mutex_lock(&m_); }
void Mutex::unlock() { pthread_mutex_unlock(&m_); }

Thread::Thread() : fn_(NULL), arg_(NULL), started_(false), tid_() {}

void* Thread::trampoline(void* self) {
    Thread* t = static_cast<Thread*>(self);
    t->fn_(t->arg_);
    return NULL;
}

bool Thread::start(Fn fn, void* arg) {
    if (started_ || fn == NULL) {
        return false;
    }
    fn_ = fn;
    arg_ = arg;
    started_ = (pthread_create(&tid_, NULL, &Thread::trampoline, this) == 0);
    return started_;
}

void Thread::join() {
    if (!started_) {
        return;
    }
    pthread_join(tid_, NULL);
    started_ = false;
}
#endif

Thread::~Thread() { join(); }

}  // namespace platform
}  // namespace carplay
