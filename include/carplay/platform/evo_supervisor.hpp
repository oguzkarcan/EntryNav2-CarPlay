#ifndef CARPLAY_PLATFORM_EVO_SUPERVISOR_HPP
#define CARPLAY_PLATFORM_EVO_SUPERVISOR_HPP

// Long-running supervised child process helper (`posix_spawnp`, no shell).
//
// Provides an injectable `IChildProcess` interface so orchestrators like `WifiAp` can be
// unit-tested with in-memory fakes, and a POSIX implementation `SupervisedProcess` using:
//   * `posix_spawnp` (no shell, empty child signal mask, stdio redirected to `/dev/null` or log)
//   * non-blocking `waitpid(..., WNOHANG)` reaping via `pollExited()` / `isRunning()`
//   * explicit `SIGTERM` / `SIGKILL` signals or bounded synchronous `stop()` escalation

#include <string>
#include <vector>

namespace carplay {
namespace platform {

struct ProcessExitStatus {
    bool exited;
    int exit_code;  // >= 0 when exited normally via _exit/return; -1 otherwise
    int signal;     // > 0 when terminated by signal; 0 otherwise

    ProcessExitStatus() : exited(false), exit_code(-1), signal(0) {}
};

class IChildProcess {
public:
    virtual ~IChildProcess() {}

    virtual bool start(const std::string& executable,
                       const std::vector<std::string>& args,
                       const std::string& log_path = std::string(),
                       std::string* error_out = NULL) = 0;

    /// Non-blocking check (calls waitpid(..., WNOHANG) on POSIX).
    /// Returns true if the child is no longer running (either never started or exited & reaped).
    virtual bool pollExited(ProcessExitStatus* status_out = NULL) = 0;

    /// Convenience inverse of pollExited().
    virtual bool isRunning() = 0;

    virtual int pid() const = 0;
    virtual ProcessExitStatus exitStatus() const = 0;

    virtual bool sendTerm() = 0;
    virtual bool sendKill() = 0;

    /// Bounded synchronous stop: SIGTERM -> wait up to `term_timeout_ms` -> SIGKILL -> wait up to
    /// `kill_timeout_ms`. Reaps the child on exit.
    virtual bool stop(int term_timeout_ms = 2000, int kill_timeout_ms = 1000) = 0;
};

class SupervisedProcess : public IChildProcess {
public:
    SupervisedProcess();
    virtual ~SupervisedProcess();

    virtual bool start(const std::string& executable,
                       const std::vector<std::string>& args,
                       const std::string& log_path = std::string(),
                       std::string* error_out = NULL);

    virtual bool pollExited(ProcessExitStatus* status_out = NULL);
    virtual bool isRunning();

    virtual int pid() const { return pid_; }
    virtual ProcessExitStatus exitStatus() const { return status_; }

    virtual bool sendTerm();
    virtual bool sendKill();
    virtual bool stop(int term_timeout_ms = 2000, int kill_timeout_ms = 1000);

private:
    SupervisedProcess(const SupervisedProcess&) = delete;
    SupervisedProcess& operator=(const SupervisedProcess&) = delete;

    bool sendSignal(int sig);

    int pid_;
    bool running_;
    ProcessExitStatus status_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_EVO_SUPERVISOR_HPP
