#ifndef CARPLAY_PLATFORM_DDP_HANDOFF_HPP
#define CARPLAY_PLATFORM_DDP_HANDOFF_HPP

// Non-blocking DDPServer (DistributedDeviceProtocol.service) handoff for /dev/i2c-0.
//
// Visit 3 hardware findings on BMW HU_ENTRYNAV2 (verified 2026-11-21):
//   * DistributedDeviceProtocol.service has KillMode=none, no ExecStop, Restart=no,
//     WatchdogSec=75, User=auxmms, Group=mplayer.
//   * `systemctl stop DistributedDeviceProtocol.service` alone leaves DDPServer alive and
//     holding /dev/i2c-0.
//   * Sending SIGTERM to the verified DDPServer process (.../MediaPlayer/bin/DDPServer)
//     makes it exit cleanly within ~1s, freeing /dev/i2c-0. Never use SIGKILL (-9).
//   * Restarting DDPServer afterward does NOT recover /dev/i2c-0 or Bluetooth audio; only a
//     full `systemctl reboot` restores them. Therefore we never restart DDPServer after handoff
//     and instead record `ddp_needs_reboot` when configured (`ddp_restore=reboot_prompt`).
//
// Everything runs on the single-threaded Reactor using fork/execv + O_NONBLOCK pipe + timer,
// with zero system()/popen() calls and zero blocking sleeps.

#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/platform/reactor.hpp"

namespace carplay {
namespace platform {

enum DdpRestoreMode {
    kDdpRestoreRebootPrompt = 0,
    kDdpRestoreNone = 1
};

/// Parses "reboot_prompt" or "none". Returns false on any other string.
bool parseDdpRestoreMode(const std::string& text, DdpRestoreMode& out);
const char* ddpRestoreModeName(DdpRestoreMode mode);

/// Returns true if `exe_path` resolves to a binary ending in `suffix`
/// (stripping any Linux " (deleted)" suffix from /proc/<pid>/exe).
bool isDdpServerExePath(const std::string& exe_path, const std::string& suffix);

struct DdpProcHolder {
    int64_t pid;
    std::string exe_or_comm;

    DdpProcHolder() : pid(0) {}
    DdpProcHolder(int64_t p, const std::string& label) : pid(p), exe_or_comm(label) {}
};

struct DdpHandoffConfig {
    bool enabled;                  // default: false (opt-in)
    std::string systemctl_path;    // default: "/bin/systemctl"
    std::string service_name;      // default: "DistributedDeviceProtocol.service"
    std::string ddp_exe_suffix;    // default: "/MediaPlayer/bin/DDPServer"
    std::string proc_root;         // default: "/proc"
    std::string i2c_device_path;   // default: "/dev/i2c-0"
    int64_t wait_exit_timeout_ms;  // clamped to [50, 5000], default: 5000
    int64_t poll_interval_ms;      // default: 50
    DdpRestoreMode restore_mode;   // default: kDdpRestoreRebootPrompt

    DdpHandoffConfig()
        : enabled(false),
          systemctl_path("/bin/systemctl"),
          service_name("DistributedDeviceProtocol.service"),
          ddp_exe_suffix("/MediaPlayer/bin/DDPServer"),
          proc_root("/proc"),
          i2c_device_path("/dev/i2c-0"),
          wait_exit_timeout_ms(5000),
          poll_interval_ms(50),
          restore_mode(kDdpRestoreRebootPrompt) {}
};

/// OS process & /proc inspection boundary for host fake injection.
class DdpHandoffOps {
public:
    virtual ~DdpHandoffOps() {}

    /// Spawns `systemctl_path stop service_name` non-blockingly via fork/execv.
    /// `pipe_fd_out` may be -1 in test doubles that poll solely via pollSystemctlStop().
    virtual bool startSystemctlStop(const std::string& systemctl_path,
                                    const std::string& service_name,
                                    int64_t& child_pid_out,
                                    int& pipe_fd_out,
                                    std::string& error_out) = 0;

    /// Non-blocking waitpid(WNOHANG) check for the systemctl child process.
    virtual bool pollSystemctlStop(int64_t child_pid,
                                   bool& exited_out,
                                   int& exit_code_out,
                                   std::string& error_out) = 0;

    /// Best-effort cleanup of an in-flight systemctl child/pipe (on timeout or cancel()).
    virtual void cleanupSystemctlStop(int64_t& child_pid_inout, int& pipe_fd_inout) = 0;

    /// Finds live non-zombie PIDs in `proc_root` whose /proc/<pid>/exe ends with `exe_suffix`.
    virtual bool findDdpServerPids(const std::string& proc_root,
                                   const std::string& exe_suffix,
                                   std::vector<int64_t>& pids_out,
                                   std::string& error_out) = 0;

    /// Sends SIGTERM (never SIGKILL) to `pid`.
    virtual bool sendSigTerm(int64_t pid, int& errno_out) = 0;

    /// Finds live PIDs in `proc_root` (excluding self) holding any open fd on `i2c_device_path`.
    virtual bool findI2cHolders(const std::string& proc_root,
                                const std::string& i2c_device_path,
                                std::vector<DdpProcHolder>& holders_out,
                                std::string& error_out) = 0;
};

class PosixDdpHandoffOps : public DdpHandoffOps {
public:
    virtual bool startSystemctlStop(const std::string& systemctl_path,
                                    const std::string& service_name,
                                    int64_t& child_pid_out,
                                    int& pipe_fd_out,
                                    std::string& error_out);

    virtual bool pollSystemctlStop(int64_t child_pid,
                                   bool& exited_out,
                                   int& exit_code_out,
                                   std::string& error_out);

    virtual void cleanupSystemctlStop(int64_t& child_pid_inout, int& pipe_fd_inout);

    virtual bool findDdpServerPids(const std::string& proc_root,
                                   const std::string& exe_suffix,
                                   std::vector<int64_t>& pids_out,
                                   std::string& error_out);

    virtual bool sendSigTerm(int64_t pid, int& errno_out);

    virtual bool findI2cHolders(const std::string& proc_root,
                                const std::string& i2c_device_path,
                                std::vector<DdpProcHolder>& holders_out,
                                std::string& error_out);
};

/// Writes the persistent/runtime reboot-required marker file atomically (`ddp_needs_reboot=1`).
bool writeDdpNeedsRebootFile(const std::string& path, const std::string& reason);

/// Non-blocking Reactor-driven handoff state machine.
class DdpHandoff {
public:
    class Callback {
    public:
        virtual ~Callback() {}
        virtual void onDdpHandoffFinished(bool ok,
                                          bool did_stop_ddp,
                                          const std::string& detail) = 0;
    };

    DdpHandoff(Reactor& reactor, const DdpHandoffConfig& config, DdpHandoffOps* ops_override = NULL);
    ~DdpHandoff();

    /// Begins the asynchronous handoff sequence. Result is delivered once via `callback`
    /// (unless `cancel()` is called first).
    bool begin(Callback* callback);

    /// Aborts any in-flight systemctl/wait sequence without delivering a completion callback.
    void cancel();

    bool isRunning() const { return state_ != kIdle; }

private:
    DdpHandoff(const DdpHandoff&);
    DdpHandoff& operator=(const DdpHandoff&);

    enum State {
        kIdle = 0,
        kStoppingService = 1,
        kWaitingExit = 2
    };

    class PipeHandler : public IoHandler {
    public:
        explicit PipeHandler(DdpHandoff* owner) : owner_(owner) {}
        virtual void onReadable() { owner_->handlePipeEvent(false); }
        virtual void onError() { owner_->handlePipeEvent(true); }

    private:
        DdpHandoff* owner_;
    };

    class PollTimer : public TimerHandler {
    public:
        explicit PollTimer(DdpHandoff* owner) : owner_(owner) {}
        virtual void onTimer(uint32_t timer_id) { owner_->handleTimer(timer_id); }

    private:
        DdpHandoff* owner_;
    };

    void handlePipeEvent(bool is_error);
    void handleTimer(uint32_t timer_id);
    void checkSystemctlAndAdvance();
    void terminateDdpAndVerifyBus();
    void evaluateWaitExit();
    void finish(bool ok, const std::string& detail);
    void cleanupAsyncResources();
    int64_t effectiveTimeoutMs() const;
    int64_t effectivePollMs() const;

    Reactor& reactor_;
    DdpHandoffConfig config_;
    PosixDdpHandoffOps default_ops_;
    DdpHandoffOps* ops_;

    Callback* callback_;
    State state_;
    int64_t systemctl_pid_;
    int systemctl_fd_;
    bool systemctl_registered_;
    uint32_t timer_id_;
    int64_t deadline_ns_;
    bool saw_ddp_before_stop_;
    bool sent_sigterm_;
    std::vector<int64_t> signalled_pids_;

    PipeHandler pipe_handler_;
    PollTimer poll_timer_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_DDP_HANDOFF_HPP
