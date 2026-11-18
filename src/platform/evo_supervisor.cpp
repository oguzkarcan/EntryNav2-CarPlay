#include "carplay/platform/evo_supervisor.hpp"

#include <errno.h>
#include <string.h>

#include "carplay/platform/net_compat.hpp"

#ifndef _WIN32
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char** environ;
#endif

namespace carplay {
namespace platform {

namespace {

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

#ifndef _WIN32
void sleepStepMs(int ms) {
    if (ms <= 0) {
        return;
    }
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = static_cast<long>(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

std::string errnoMessage(const std::string& prefix, int err_no) {
    char buf[128];
    buf[0] = '\0';
#if defined(_GNU_SOURCE) && !defined(__ANDROID__)
    const char* msg = strerror_r(err_no, buf, sizeof(buf));
    return prefix + ": " + (msg != NULL ? msg : "");
#else
    if (strerror_r(err_no, buf, sizeof(buf)) == 0) {
        return prefix + ": " + buf;
    }
    return prefix;
#endif
}
#endif

}  // namespace

SupervisedProcess::SupervisedProcess() : pid_(-1), running_(false) {}

SupervisedProcess::~SupervisedProcess() {
    if (running_) {
        stop(500, 500);
    }
}

bool SupervisedProcess::start(const std::string& executable,
                              const std::vector<std::string>& args,
                              const std::string& log_path,
                              std::string* error_out) {
    if (running_ && !pollExited()) {
        setError(error_out, "supervised process already running");
        return false;
    }
    if (executable.empty()) {
        setError(error_out, "executable must not be empty");
        return false;
    }

#ifdef _WIN32
    (void)args;
    (void)log_path;
    setError(error_out, "SupervisedProcess is not supported on Windows");
    return false;
#else
    pid_ = -1;
    running_ = false;
    status_ = ProcessExitStatus();

    const int devnull_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (devnull_fd < 0) {
        setError(error_out, errnoMessage("open(/dev/null) failed", errno));
        return false;
    }

    int out_fd = -1;
    if (log_path.empty()) {
        out_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    } else {
        out_fd = open(log_path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    }
    if (out_fd < 0) {
        const int err_no = errno;
        close(devnull_fd);
        setError(error_out, errnoMessage("open(stdio log) failed", err_no));
        return false;
    }

    std::vector<char*> argv;
    argv.reserve(args.size() + 2U);
    argv.push_back(const_cast<char*>(executable.c_str()));
    for (size_t i = 0U; i < args.size(); ++i) {
        argv.push_back(const_cast<char*>(args[i].c_str()));
    }
    argv.push_back(NULL);

    posix_spawn_file_actions_t actions;
    const int fa_err = posix_spawn_file_actions_init(&actions);
    if (fa_err != 0) {
        close(devnull_fd);
        close(out_fd);
        setError(error_out, errnoMessage("posix_spawn_file_actions_init failed", fa_err));
        return false;
    }

    posix_spawnattr_t attr;
    const int attr_err = posix_spawnattr_init(&attr);
    if (attr_err != 0) {
        posix_spawn_file_actions_destroy(&actions);
        close(devnull_fd);
        close(out_fd);
        setError(error_out, errnoMessage("posix_spawnattr_init failed", attr_err));
        return false;
    }

    sigset_t empty_mask;
    sigemptyset(&empty_mask);

    const bool prep_ok =
        posix_spawn_file_actions_adddup2(&actions, devnull_fd, STDIN_FILENO) == 0 &&
        posix_spawn_file_actions_adddup2(&actions, out_fd, STDOUT_FILENO) == 0 &&
        posix_spawn_file_actions_adddup2(&actions, out_fd, STDERR_FILENO) == 0 &&
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK) == 0 &&
        posix_spawnattr_setsigmask(&attr, &empty_mask) == 0;

    pid_t child_pid = -1;
    const int spawn_rc = prep_ok
                             ? posix_spawnp(&child_pid, executable.c_str(), &actions, &attr,
                                            &argv[0], environ)
                             : EINVAL;

    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&actions);
    close(devnull_fd);
    close(out_fd);

    if (spawn_rc != 0 || child_pid <= 0) {
        setError(error_out, errnoMessage("posix_spawnp(" + executable + ") failed",
                                         spawn_rc != 0 ? spawn_rc : ECHILD));
        return false;
    }

    pid_ = static_cast<int>(child_pid);
    running_ = true;
    return true;
#endif
}

bool SupervisedProcess::pollExited(ProcessExitStatus* status_out) {
#ifdef _WIN32
    if (status_out != NULL) {
        *status_out = status_;
    }
    return true;
#else
    if (!running_ || pid_ <= 0) {
        if (status_out != NULL) {
            *status_out = status_;
        }
        return true;
    }

    int st = 0;
    pid_t r = 0;
    do {
        r = waitpid(static_cast<pid_t>(pid_), &st, WNOHANG);
    } while (r < 0 && errno == EINTR);

    if (r == 0) {
        return false;  // still running
    }

    running_ = false;
    status_.exited = true;
    if (r == static_cast<pid_t>(pid_)) {
        if (WIFEXITED(st)) {
            status_.exit_code = WEXITSTATUS(st);
            status_.signal = 0;
        } else if (WIFSIGNALED(st)) {
            status_.exit_code = -1;
            status_.signal = WTERMSIG(st);
        }
    } else {
        // ECHILD or unexpected error; treat as exited so callers don't spin.
        status_.exit_code = -1;
        status_.signal = 0;
    }
    pid_ = -1;
    if (status_out != NULL) {
        *status_out = status_;
    }
    return true;
#endif
}

bool SupervisedProcess::isRunning() {
    return !pollExited(NULL);
}

bool SupervisedProcess::sendSignal(int sig) {
#ifdef _WIN32
    (void)sig;
    return false;
#else
    if (!running_ || pid_ <= 0) {
        return false;
    }
    if (kill(static_cast<pid_t>(pid_), sig) != 0) {
        if (errno == ESRCH) {
            pollExited(NULL);
        }
        return false;
    }
    return true;
#endif
}

bool SupervisedProcess::sendTerm() {
#ifdef _WIN32
    return false;
#else
    return sendSignal(SIGTERM);
#endif
}

bool SupervisedProcess::sendKill() {
#ifdef _WIN32
    return false;
#else
    return sendSignal(SIGKILL);
#endif
}

bool SupervisedProcess::stop(int term_timeout_ms, int kill_timeout_ms) {
#ifdef _WIN32
    (void)term_timeout_ms;
    (void)kill_timeout_ms;
    return true;
#else
    if (pollExited(NULL)) {
        return true;
    }

    sendTerm();
    const int64_t term_deadline =
        monotonicMillis() + static_cast<int64_t>(term_timeout_ms > 0 ? term_timeout_ms : 0);
    while (!pollExited(NULL)) {
        const int64_t rem = term_deadline - monotonicMillis();
        if (rem <= 0) {
            break;
        }
        sleepStepMs(rem > 10 ? 10 : static_cast<int>(rem));
    }

    if (!running_) {
        return true;
    }

    sendKill();
    const int64_t kill_deadline =
        monotonicMillis() + static_cast<int64_t>(kill_timeout_ms > 0 ? kill_timeout_ms : 0);
    while (!pollExited(NULL)) {
        const int64_t rem = kill_deadline - monotonicMillis();
        if (rem <= 0) {
            break;
        }
        sleepStepMs(rem > 10 ? 10 : static_cast<int>(rem));
    }

    return pollExited(NULL);
#endif
}

}  // namespace platform
}  // namespace carplay
