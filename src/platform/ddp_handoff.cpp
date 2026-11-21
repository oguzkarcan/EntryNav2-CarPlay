#include "carplay/platform/ddp_handoff.hpp"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sstream>

#include "carplay/platform/file_util.hpp"
#include "carplay/platform/log.hpp"

namespace carplay {
namespace platform {

namespace {

const char* const kTag = "ddp_handoff";

std::string stripDeletedSuffix(const std::string& path) {
    static const char kDeleted[] = " (deleted)";
    static const size_t kDeletedLen = sizeof(kDeleted) - 1U;
    if (path.size() > kDeletedLen &&
        path.compare(path.size() - kDeletedLen, kDeletedLen, kDeleted) == 0) {
        return path.substr(0U, path.size() - kDeletedLen);
    }
    return path;
}

bool isNumericName(const char* name) {
    if (name == NULL || *name == '\0') {
        return false;
    }
    for (const char* p = name; *p != '\0'; ++p) {
        if (!isdigit(static_cast<unsigned char>(*p))) {
            return false;
        }
    }
    return true;
}

bool readLinkBounded(const std::string& path, std::string& target_out) {
    char buf[PATH_MAX + 32];
    const ssize_t n = readlink(path.c_str(), buf, sizeof(buf) - 1U);
    if (n <= 0) {
        return false;
    }
    buf[n] = '\0';
    target_out.assign(buf, static_cast<size_t>(n));
    return true;
}

char readProcStatState(const std::string& proc_dir) {
    std::vector<uint8_t> raw;
    if (readFileBounded(joinPath(proc_dir, "stat"), 4096U, raw) != kFileReadOk || raw.empty()) {
        return '\0';
    }
    const std::string text(raw.begin(), raw.end());
    const size_t rparen = text.rfind(')');
    if (rparen == std::string::npos || rparen + 2U >= text.size()) {
        return '\0';
    }
    size_t pos = rparen + 1U;
    while (pos < text.size() && isspace(static_cast<unsigned char>(text[pos]))) {
        ++pos;
    }
    return (pos < text.size()) ? text[pos] : '\0';
}

std::string readProcLabel(const std::string& proc_dir) {
    std::string exe;
    if (readLinkBounded(joinPath(proc_dir, "exe"), exe)) {
        return stripDeletedSuffix(exe);
    }
    std::vector<uint8_t> raw;
    if (readFileBounded(joinPath(proc_dir, "comm"), 256U, raw) == kFileReadOk && !raw.empty()) {
        std::string comm(raw.begin(), raw.end());
        while (!comm.empty() && (comm[comm.size() - 1U] == '\n' || comm[comm.size() - 1U] == '\r')) {
            comm.erase(comm.size() - 1U);
        }
        if (!comm.empty()) {
            return comm;
        }
    }
    return "unknown";
}

bool setFdCloexec(int fd) {
    const int flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0) {
        return false;
    }
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

bool setFdNonBlock(int fd) {
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

std::string resolveCanonicalPath(const std::string& path) {
    char buf[PATH_MAX];
    if (realpath(path.c_str(), buf) != NULL) {
        return std::string(buf);
    }
    return path;
}

bool hasPid(const std::vector<int64_t>& pids, int64_t target) {
    for (size_t i = 0U; i < pids.size(); ++i) {
        if (pids[i] == target) {
            return true;
        }
    }
    return false;
}

}  // namespace

bool parseDdpRestoreMode(const std::string& text, DdpRestoreMode& out) {
    if (text == "reboot_prompt") {
        out = kDdpRestoreRebootPrompt;
        return true;
    }
    if (text == "none") {
        out = kDdpRestoreNone;
        return true;
    }
    return false;
}

const char* ddpRestoreModeName(DdpRestoreMode mode) {
    switch (mode) {
        case kDdpRestoreRebootPrompt:
            return "reboot_prompt";
        case kDdpRestoreNone:
            return "none";
    }
    return "reboot_prompt";
}

bool isDdpServerExePath(const std::string& exe_path, const std::string& suffix) {
    if (suffix.empty()) {
        return false;
    }
    const std::string clean = stripDeletedSuffix(exe_path);
    if (clean.size() < suffix.size()) {
        return false;
    }
    return clean.compare(clean.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool PosixDdpHandoffOps::startSystemctlStop(const std::string& systemctl_path,
                                              const std::string& service_name,
                                              int64_t& child_pid_out,
                                              int& pipe_fd_out,
                                              std::string& error_out) {
    child_pid_out = -1;
    pipe_fd_out = -1;

    if (systemctl_path.empty() || service_name.empty()) {
        error_out = "systemctl_path or service_name is empty";
        return false;
    }

    int pipefd[2] = {-1, -1};
    if (pipe(pipefd) != 0) {
        error_out = std::string("pipe failed: ") + strerror(errno);
        return false;
    }
    if (!setFdCloexec(pipefd[0]) || !setFdCloexec(pipefd[1]) || !setFdNonBlock(pipefd[0])) {
        const int saved = errno;
        close(pipefd[0]);
        close(pipefd[1]);
        error_out = std::string("fcntl on systemctl pipe failed: ") + strerror(saved);
        return false;
    }

    const pid_t pid = fork();
    if (pid < 0) {
        const int saved = errno;
        close(pipefd[0]);
        close(pipefd[1]);
        error_out = std::string("fork failed: ") + strerror(saved);
        return false;
    }

    if (pid == 0) {
        close(pipefd[0]);
        const int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            if (devnull > STDERR_FILENO) {
                close(devnull);
            }
        }
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        if (pipefd[1] > STDERR_FILENO) {
            close(pipefd[1]);
        }

        const char* argv[] = {
            systemctl_path.c_str(),
            "stop",
            service_name.c_str(),
            NULL
        };
        execv(systemctl_path.c_str(), const_cast<char* const*>(argv));
        _exit(127);
    }

    close(pipefd[1]);
    child_pid_out = static_cast<int64_t>(pid);
    pipe_fd_out = pipefd[0];
    return true;
}

bool PosixDdpHandoffOps::pollSystemctlStop(int64_t child_pid,
                                             bool& exited_out,
                                             int& exit_code_out,
                                             std::string& error_out) {
    exited_out = false;
    exit_code_out = -1;
    if (child_pid <= 0) {
        error_out = "invalid systemctl child pid";
        return false;
    }

    int status = 0;
    const pid_t r = waitpid(static_cast<pid_t>(child_pid), &status, WNOHANG);
    if (r == 0) {
        return true;
    }
    if (r < 0) {
        if (errno == EINTR) {
            return true;
        }
        error_out = std::string("waitpid(systemctl) failed: ") + strerror(errno);
        return false;
    }

    exited_out = true;
    if (WIFEXITED(status)) {
        exit_code_out = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        exit_code_out = 128 + WTERMSIG(status);
    } else {
        exit_code_out = 1;
    }
    return true;
}

void PosixDdpHandoffOps::cleanupSystemctlStop(int64_t& child_pid_inout, int& pipe_fd_inout) {
    if (pipe_fd_inout >= 0) {
        close(pipe_fd_inout);
        pipe_fd_inout = -1;
    }
    if (child_pid_inout > 0) {
        const pid_t pid = static_cast<pid_t>(child_pid_inout);
        int status = 0;
        if (waitpid(pid, &status, WNOHANG) == 0) {
            kill(pid, SIGTERM);
            waitpid(pid, &status, WNOHANG);
        }
        child_pid_inout = -1;
    }
}

bool PosixDdpHandoffOps::findDdpServerPids(const std::string& proc_root,
                                            const std::string& exe_suffix,
                                            std::vector<int64_t>& pids_out,
                                            std::string& error_out) {
    pids_out.clear();
    DIR* dir = opendir(proc_root.c_str());
    if (dir == NULL) {
        error_out = std::string("opendir(") + proc_root + ") failed: " + strerror(errno);
        return false;
    }

    const int64_t self_pid = static_cast<int64_t>(getpid());
    struct dirent* ent = NULL;
    while ((ent = readdir(dir)) != NULL) {
        if (!isNumericName(ent->d_name)) {
            continue;
        }
        const int64_t pid = strtoll(ent->d_name, NULL, 10);
        if (pid <= 0 || pid == self_pid) {
            continue;
        }
        const std::string proc_dir = joinPath(proc_root, ent->d_name);
        if (readProcStatState(proc_dir) == 'Z') {
            continue;
        }
        std::string exe_target;
        if (!readLinkBounded(joinPath(proc_dir, "exe"), exe_target)) {
            continue;
        }
        if (isDdpServerExePath(exe_target, exe_suffix)) {
            pids_out.push_back(pid);
        }
    }

    closedir(dir);
    return true;
}

bool PosixDdpHandoffOps::sendSigTerm(int64_t pid, int& errno_out) {
    errno_out = 0;
    if (pid <= 0) {
        errno_out = EINVAL;
        return false;
    }
    if (kill(static_cast<pid_t>(pid), SIGTERM) == 0) {
        return true;
    }
    errno_out = errno;
    return false;
}

bool PosixDdpHandoffOps::findI2cHolders(const std::string& proc_root,
                                         const std::string& i2c_device_path,
                                         std::vector<DdpProcHolder>& holders_out,
                                         std::string& error_out) {
    holders_out.clear();
    if (i2c_device_path.empty()) {
        return true;
    }

    DIR* proc = opendir(proc_root.c_str());
    if (proc == NULL) {
        error_out = std::string("opendir(") + proc_root + ") failed: " + strerror(errno);
        return false;
    }

    const std::string canonical_target = resolveCanonicalPath(i2c_device_path);
    const int64_t self_pid = static_cast<int64_t>(getpid());

    struct dirent* pent = NULL;
    while ((pent = readdir(proc)) != NULL) {
        if (!isNumericName(pent->d_name)) {
            continue;
        }
        const int64_t pid = strtoll(pent->d_name, NULL, 10);
        if (pid <= 0 || pid == self_pid) {
            continue;
        }
        const std::string proc_dir = joinPath(proc_root, pent->d_name);
        if (readProcStatState(proc_dir) == 'Z') {
            continue;
        }

        const std::string fd_dir_path = joinPath(proc_dir, "fd");
        DIR* fd_dir = opendir(fd_dir_path.c_str());
        if (fd_dir == NULL) {
            continue;
        }

        bool matches = false;
        struct dirent* fent = NULL;
        while ((fent = readdir(fd_dir)) != NULL) {
            if (!isNumericName(fent->d_name)) {
                continue;
            }
            std::string target;
            if (!readLinkBounded(joinPath(fd_dir_path, fent->d_name), target)) {
                continue;
            }
            const std::string clean_target = stripDeletedSuffix(target);
            if (clean_target == i2c_device_path || clean_target == canonical_target) {
                matches = true;
                break;
            }
        }
        closedir(fd_dir);

        if (matches) {
            holders_out.push_back(DdpProcHolder(pid, readProcLabel(proc_dir)));
        }
    }

    closedir(proc);
    return true;
}

bool writeDdpNeedsRebootFile(const std::string& path, const std::string& reason) {
    if (path.empty()) {
        return false;
    }
    std::ostringstream oss;
    oss << "ddp_needs_reboot=1\n";
    if (!reason.empty()) {
        oss << "reason=" << reason << "\n";
    }
    const std::string payload = oss.str();
    return writeFileAtomic(path, reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
}

DdpHandoff::DdpHandoff(Reactor& reactor, const DdpHandoffConfig& config, DdpHandoffOps* ops_override)
    : reactor_(reactor),
      config_(config),
      ops_((ops_override != NULL) ? ops_override : static_cast<DdpHandoffOps*>(&default_ops_)),
      callback_(NULL),
      state_(kIdle),
      systemctl_pid_(-1),
      systemctl_fd_(-1),
      systemctl_registered_(false),
      timer_id_(Reactor::kNoTimer),
      deadline_ns_(0),
      saw_ddp_before_stop_(false),
      sent_sigterm_(false),
      pipe_handler_(this),
      poll_timer_(this) {}

DdpHandoff::~DdpHandoff() { cancel(); }

int64_t DdpHandoff::effectiveTimeoutMs() const {
    if (config_.wait_exit_timeout_ms < 50) {
        return 50;
    }
    if (config_.wait_exit_timeout_ms > 5000) {
        return 5000;
    }
    return config_.wait_exit_timeout_ms;
}

int64_t DdpHandoff::effectivePollMs() const {
    if (config_.poll_interval_ms < 10) {
        return 10;
    }
    if (config_.poll_interval_ms > 250) {
        return 250;
    }
    return config_.poll_interval_ms;
}

bool DdpHandoff::begin(Callback* callback) {
    if (state_ != kIdle) {
        return false;
    }
    callback_ = callback;
    saw_ddp_before_stop_ = false;
    sent_sigterm_ = false;
    signalled_pids_.clear();

    if (!config_.enabled) {
        finish(true, "ddp_handoff disabled");
        return true;
    }

    std::vector<int64_t> pre_pids;
    std::string proc_err;
    if (ops_->findDdpServerPids(config_.proc_root, config_.ddp_exe_suffix, pre_pids, proc_err)) {
        saw_ddp_before_stop_ = !pre_pids.empty();
    } else {
        CARPLAY_LOG_WARN(kTag, "pre-stop DDPServer scan warning: %s", proc_err.c_str());
    }

    CARPLAY_LOG_INFO(kTag, "stopping %s before opening %s (wait <= %lld ms)",
                     config_.service_name.c_str(),
                     config_.i2c_device_path.c_str(),
                     static_cast<long long>(effectiveTimeoutMs()));

    std::string start_err;
    if (!ops_->startSystemctlStop(config_.systemctl_path, config_.service_name,
                                  systemctl_pid_, systemctl_fd_, start_err)) {
        CARPLAY_LOG_ERROR(kTag, "failed to launch %s stop %s: %s",
                          config_.systemctl_path.c_str(),
                          config_.service_name.c_str(),
                          start_err.c_str());
        finish(false, std::string("systemctl stop launch failed: ") + start_err);
        return true;
    }

    state_ = kStoppingService;
    deadline_ns_ = reactor_.now() + effectiveTimeoutMs() * 1000000LL;

    if (systemctl_fd_ >= 0) {
        if (reactor_.add(static_cast<SocketHandle>(systemctl_fd_),
                         &pipe_handler_,
                         kPollIn)) {
            systemctl_registered_ = true;
        }
    }

    timer_id_ = reactor_.startTimer(effectivePollMs(), effectivePollMs(), &poll_timer_);
    if (timer_id_ == Reactor::kNoTimer) {
        cleanupAsyncResources();
        state_ = kIdle;
        finish(false, "failed to start DDP handoff Reactor timer");
        return true;
    }

    // Immediate non-blocking check in case a test double completed synchronously.
    checkSystemctlAndAdvance();
    return true;
}

void DdpHandoff::cancel() {
    cleanupAsyncResources();
    state_ = kIdle;
    callback_ = NULL;
}

void DdpHandoff::handlePipeEvent(bool is_error) {
    if (state_ != kStoppingService || systemctl_fd_ < 0) {
        return;
    }
    char buf[512];
    bool drain_eof = is_error;
    for (;;) {
        const ssize_t n = read(systemctl_fd_, buf, sizeof(buf));
        if (n > 0) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            break;
        }
        drain_eof = true;
        break;
    }
    if (drain_eof && systemctl_registered_) {
        reactor_.remove(static_cast<SocketHandle>(systemctl_fd_));
        systemctl_registered_ = false;
    }
    checkSystemctlAndAdvance();
}

void DdpHandoff::handleTimer(uint32_t timer_id) {
    if (timer_id != timer_id_ || state_ == kIdle) {
        return;
    }
    if (state_ == kStoppingService) {
        checkSystemctlAndAdvance();
        return;
    }
    if (state_ == kWaitingExit) {
        evaluateWaitExit();
    }
}

void DdpHandoff::checkSystemctlAndAdvance() {
    if (state_ != kStoppingService) {
        return;
    }
    bool exited = false;
    int exit_code = -1;
    std::string poll_err;
    if (!ops_->pollSystemctlStop(systemctl_pid_, exited, exit_code, poll_err)) {
        CARPLAY_LOG_ERROR(kTag, "pollSystemctlStop error: %s", poll_err.c_str());
        finish(false, std::string("systemctl stop poll failed: ") + poll_err);
        return;
    }

    if (!exited) {
        if (reactor_.now() >= deadline_ns_) {
            CARPLAY_LOG_ERROR(kTag, "systemctl stop %s timed out after %lld ms; aborting I2C session",
                              config_.service_name.c_str(),
                              static_cast<long long>(effectiveTimeoutMs()));
            finish(false, "systemctl stop timed out; /dev/i2c-0 handoff aborted");
        }
        return;
    }

    if (systemctl_registered_) {
        reactor_.remove(static_cast<SocketHandle>(systemctl_fd_));
        systemctl_registered_ = false;
    }
    if (systemctl_fd_ >= 0) {
        close(systemctl_fd_);
        systemctl_fd_ = -1;
    }
    systemctl_pid_ = -1;

    if (exit_code != 0) {
        CARPLAY_LOG_WARN(kTag, "systemctl stop %s exited with status %d; continuing to /proc check",
                         config_.service_name.c_str(), exit_code);
    }

    terminateDdpAndVerifyBus();
}

void DdpHandoff::terminateDdpAndVerifyBus() {
    std::vector<int64_t> pids;
    std::string scan_err;
    if (!ops_->findDdpServerPids(config_.proc_root, config_.ddp_exe_suffix, pids, scan_err)) {
        CARPLAY_LOG_ERROR(kTag, "DDPServer /proc scan failed: %s", scan_err.c_str());
        finish(false, std::string("DDPServer /proc scan failed: ") + scan_err);
        return;
    }

    for (size_t i = 0U; i < pids.size(); ++i) {
        const int64_t pid = pids[i];
        CARPLAY_LOG_INFO(kTag, "sending SIGTERM to verified DDPServer pid=%lld",
                         static_cast<long long>(pid));
        int err = 0;
        if (ops_->sendSigTerm(pid, err)) {
            sent_sigterm_ = true;
            if (!hasPid(signalled_pids_, pid)) {
                signalled_pids_.push_back(pid);
            }
        } else if (err == ESRCH) {
            // Exited right as we found it.
            if (!hasPid(signalled_pids_, pid)) {
                signalled_pids_.push_back(pid);
            }
        } else {
            CARPLAY_LOG_ERROR(kTag, "kill(%lld, SIGTERM) failed: %s; aborting I2C session",
                              static_cast<long long>(pid), strerror(err));
            finish(false, std::string("SIGTERM to DDPServer failed: ") + strerror(err));
            return;
        }
    }

    state_ = kWaitingExit;
    evaluateWaitExit();
}

void DdpHandoff::evaluateWaitExit() {
    if (state_ != kWaitingExit) {
        return;
    }

    std::vector<int64_t> live_ddp;
    std::string scan_err;
    if (!ops_->findDdpServerPids(config_.proc_root, config_.ddp_exe_suffix, live_ddp, scan_err)) {
        CARPLAY_LOG_ERROR(kTag, "DDPServer wait scan failed: %s", scan_err.c_str());
        finish(false, std::string("DDPServer wait scan failed: ") + scan_err);
        return;
    }

    // If a lingering DDPServer was missed or respawned before settle, SIGTERM it once (never -9).
    for (size_t i = 0U; i < live_ddp.size(); ++i) {
        if (!hasPid(signalled_pids_, live_ddp[i])) {
            int err = 0;
            if (ops_->sendSigTerm(live_ddp[i], err)) {
                sent_sigterm_ = true;
                signalled_pids_.push_back(live_ddp[i]);
            }
        }
    }

    std::vector<DdpProcHolder> holders;
    std::string holder_err;
    if (!ops_->findI2cHolders(config_.proc_root, config_.i2c_device_path, holders, holder_err)) {
        CARPLAY_LOG_ERROR(kTag, "I2C fd holder check failed: %s", holder_err.c_str());
        finish(false, std::string("I2C fd holder check failed: ") + holder_err);
        return;
    }

    if (live_ddp.empty() && holders.empty()) {
        CARPLAY_LOG_INFO(kTag, "%s is free (0 DDPServer PIDs, 0 %s holders)",
                         config_.i2c_device_path.c_str(),
                         config_.i2c_device_path.c_str());
        finish(true, "DDPServer stopped and /dev/i2c-0 verified clear");
        return;
    }

    // If no DDPServer is alive at all, yet some unrelated process holds /dev/i2c-0,
    // fail fast rather than risking bus contention or waiting out 5s needlessly? Wait:
    // keep waiting if a just-SIGTERM'd DDPServer PID hasn't closed fd yet; fail at deadline
    // OR fail immediately only if no DDPServer PID is alive AND wait settles? Even simpler:
    // wait up to deadline_ns_ (<= 5s) so any closing fds settle, or if live_ddp.empty() and
    // holders belong to a completely different PID we don't know is exiting, wait/abort cleanly
    // at deadline (or if live_ddp.empty() and sent_sigterm_==false -> immediate abort!).
    if (live_ddp.empty() && !sent_sigterm_) {
        std::ostringstream oss;
        oss << config_.i2c_device_path << " still held by pid=" << holders[0].pid
            << " (" << holders[0].exe_or_comm << "); aborting session without touching I2C bus";
        CARPLAY_LOG_ERROR(kTag, "%s", oss.str().c_str());
        finish(false, oss.str());
        return;
    }

    if (reactor_.now() >= deadline_ns_) {
        std::ostringstream oss;
        oss << "timeout waiting <= " << effectiveTimeoutMs() << " ms for DDPServer/I2C release:";
        if (!live_ddp.empty()) {
            oss << " live_ddp_pid=" << live_ddp[0];
        }
        if (!holders.empty()) {
            oss << " i2c_holder_pid=" << holders[0].pid << "(" << holders[0].exe_or_comm << ")";
        }
        CARPLAY_LOG_ERROR(kTag, "%s; aborting without touching %s",
                          oss.str().c_str(), config_.i2c_device_path.c_str());
        finish(false, oss.str());
    }
}

void DdpHandoff::finish(bool ok, const std::string& detail) {
    Callback* cb = callback_;
    const bool did_stop_ddp = saw_ddp_before_stop_ || !signalled_pids_.empty();
    cleanupAsyncResources();
    state_ = kIdle;
    callback_ = NULL;
    if (cb != NULL) {
        cb->onDdpHandoffFinished(ok, did_stop_ddp, detail);
    }
}

void DdpHandoff::cleanupAsyncResources() {
    if (timer_id_ != Reactor::kNoTimer) {
        reactor_.cancelTimer(timer_id_);
        timer_id_ = Reactor::kNoTimer;
    }
    if (systemctl_registered_ && systemctl_fd_ >= 0) {
        reactor_.remove(static_cast<SocketHandle>(systemctl_fd_));
        systemctl_registered_ = false;
    }
    ops_->cleanupSystemctlStop(systemctl_pid_, systemctl_fd_);
}

}  // namespace platform
}  // namespace carplay
