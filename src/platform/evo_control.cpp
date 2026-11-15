#include "carplay/platform/evo_control.hpp"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#else
#include <io.h>
#include <process.h>
#endif

#include "carplay/platform/file_util.hpp"
#include "carplay/platform/log.hpp"
#include "carplay/platform/net_compat.hpp"

namespace carplay {
namespace platform {

namespace {

uint32_t nowMonoMs() {
    return static_cast<uint32_t>(monotonicMillis());
}

int currentPid() {
#ifndef _WIN32
    return static_cast<int>(getpid());
#else
    return static_cast<int>(_getpid());
#endif
}

bool pidAlive(int pid) {
    if (pid <= 0) {
        return false;
    }
#ifndef _WIN32
    return kill(static_cast<pid_t>(pid), 0) == 0 || errno == EPERM;
#else
    return true;
#endif
}

#ifndef _WIN32
socklen_t makeControlAddress(const char* name, struct sockaddr_un& out) {
    memset(&out, 0, sizeof(out));
    out.sun_family = AF_UNIX;
    size_t n = name ? strlen(name) : 0;
    if (n > sizeof(out.sun_path) - 1) {
        n = sizeof(out.sun_path) - 1;
    }
    if (n > 0) {
        memcpy(out.sun_path + 1, name, n);
    }
    return static_cast<socklen_t>(offsetof(struct sockaddr_un, sun_path) + 1 + n);
}

bool bindControlReplyAddress(int fd) {
    struct sockaddr_un own;
    memset(&own, 0, sizeof(own));
    own.sun_family = AF_UNIX;
    return bind(fd, reinterpret_cast<struct sockaddr*>(&own), sizeof(sa_family_t)) == 0;
}
#endif

}  // namespace

bool parseControlCommand(const char* data, size_t len, ControlCommand& out) {
    if (!data || len == 0 || len > 64) {
        return false;
    }
    char buf[65];
    memcpy(buf, data, len);
    buf[len] = '\0';
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' || buf[len - 1] == ' ')) {
        buf[--len] = '\0';
    }
    if (len == 0) {
        return false;
    }
    char verb[16] = "";
    int arg = 0;
    char extra[8] = "";
    const int n = sscanf(buf, "%15s %d %7s", verb, &arg, extra);
    if (n < 1 || n > 2) {
        return false;
    }
    static const char* const kKnown[] = {
        "ping", "show", "hide", "quit", "gear", "await",
        "pdc", "daynight", "drivemode", "call", "popup"
    };
    bool ok = false;
    for (size_t i = 0; i < sizeof(kKnown) / sizeof(kKnown[0]); ++i) {
        if (strcmp(verb, kKnown[i]) == 0) {
            ok = true;
            break;
        }
    }
    if (!ok) {
        return false;
    }
    const bool needs_arg =
        strcmp(verb, "gear") == 0 ||
        strcmp(verb, "pdc") == 0 ||
        strcmp(verb, "daynight") == 0 ||
        strcmp(verb, "call") == 0 ||
        strcmp(verb, "popup") == 0;
    if (needs_arg != (n == 2) && strcmp(verb, "drivemode") != 0) {
        return false;
    }
    out.verb = verb;
    out.arg = (n == 2) ? arg : 0;
    out.has_arg = (n == 2);
    return true;
}

bool parseServiceStateLine(const char* line, ServiceState& out) {
    if (!line) {
        return false;
    }
    char st[24] = "";
    int pid = 0;
    int ov = 0;
    const int n = sscanf(line, "%23s %d %d", st, &pid, &ov);
    if (n < 2) {
        return false;
    }
    out = ServiceState(st, pid, (n >= 3) ? ov : 0);
    return true;
}

ServiceState readServiceStateFile(const char* state_file, const char* control_name) {
    ServiceState d;
    if (state_file && state_file[0] != '\0') {
        FILE* f = fopen(state_file, "r");
        if (f) {
            char line[128] = "";
            const bool got = fgets(line, sizeof(line), f) != NULL;
            fclose(f);
            ServiceState parsed;
            if (got && parseServiceStateLine(line, parsed) && pidAlive(parsed.pid)) {
                return parsed;
            }
            removeFile(state_file);
        }
    }
    if (control_name && control_name[0] != '\0' && controlAnswers(control_name, 200)) {
        strcpy(d.state, "running");
        d.pid = -1;
        d.overlay = 0;
    }
    return d;
}

bool sendControl(const char* name, const char* message) {
    if (!name || !name[0] || !message) {
        return false;
    }
#ifndef _WIN32
    const int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return false;
    }
    struct sockaddr_un to;
    const socklen_t length = makeControlAddress(name, to);
    const size_t size = strlen(message);
    const ssize_t rc = sendto(fd, message, size, MSG_DONTWAIT,
                              reinterpret_cast<struct sockaddr*>(&to), length);
    close(fd);
    return rc == static_cast<ssize_t>(size);
#else
    (void)name;
    (void)message;
    return false;
#endif
}

bool controlAnswers(const char* name, int wait_ms) {
    if (!name || !name[0]) {
        return false;
    }
#ifndef _WIN32
    const int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return false;
    }
    struct sockaddr_un to;
    const socklen_t length = makeControlAddress(name, to);
    bool answered = false;
    if (bindControlReplyAddress(fd) &&
        connect(fd, reinterpret_cast<struct sockaddr*>(&to), length) == 0 &&
        send(fd, "ping", 4, MSG_DONTWAIT) == 4) {
        struct pollfd wait_fd;
        wait_fd.fd = fd;
        wait_fd.events = POLLIN;
        wait_fd.revents = 0;
        if (poll(&wait_fd, 1, wait_ms) > 0) {
            char reply[8];
            const ssize_t n = recv(fd, reply, sizeof(reply), MSG_DONTWAIT);
            answered = (n >= 4 && memcmp(reply, "pong", 4) == 0);
        }
    }
    close(fd);
    return answered;
#else
    (void)wait_ms;
    return false;
#endif
}

bool writeAppKeyFile(const char* path, const char* key_name) {
    if (!path || !path[0] || !key_name) {
        return false;
    }
    char line[64];
    const int n = snprintf(line, sizeof(line), "appkey %s\n", key_name);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(line)) {
        return false;
    }
    return writeFileAtomic(path, reinterpret_cast<const uint8_t*>(line), static_cast<size_t>(n));
}

bool writeDayNightFile(const char* path, int val) {
    if (!path || !path[0] || (val != 1 && val != 2)) {
        return false;
    }
    char line[32];
    const int n = snprintf(line, sizeof(line), "daynight %d\n", val);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(line)) {
        return false;
    }
    return writeFileAtomic(path, reinterpret_cast<const uint8_t*>(line), static_cast<size_t>(n));
}

bool readDayNightFile(const char* path, int& val_out) {
    if (!path || !path[0]) {
        return false;
    }
    FILE* f = fopen(path, "r");
    if (!f) {
        return false;
    }
    int v = 0;
    const int fields = fscanf(f, "daynight %d", &v);
    fclose(f);
    if (fields == 1 && (v == 1 || v == 2)) {
        val_out = v;
        return true;
    }
    return false;
}

EvoControl::EvoControl()
    : fd_(-1),
      started_(false),
      running_(false),
      last_write_ms_(0),
      cb_(NULL),
      user_(NULL) {}

EvoControl::~EvoControl() {
    stop();
}

bool EvoControl::start(const char* name, const char* state_file, Callback cb, void* user) {
    if (started_) {
        return true;
    }
    if (!name || !name[0]) {
        return false;
    }
#ifndef _WIN32
    fd_ = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd_ < 0) {
        CARPLAY_LOG_WARN("control", "EvoControl: socket(AF_UNIX) failed: %s", strerror(errno));
        return false;
    }
    struct sockaddr_un addr;
    const socklen_t len = makeControlAddress(name, addr);
    if (bind(fd_, reinterpret_cast<struct sockaddr*>(&addr), len) != 0) {
        CARPLAY_LOG_WARN("control", "EvoControl: control channel \"%s\" unavailable (%s)",
                         name, strerror(errno));
        close(fd_);
        fd_ = -1;
        return false;
    }
    name_ = name;
    state_file_ = state_file ? state_file : "";
    last_line_.clear();
    last_write_ms_ = 0;
    cb_ = cb;
    user_ = user;
    running_ = true;
    if (!thread_.start(&EvoControl::threadMain, this)) {
        running_ = false;
        close(fd_);
        fd_ = -1;
        return false;
    }
    started_ = true;
    return true;
#else
    (void)state_file;
    (void)cb;
    (void)user;
    return false;
#endif
}

void EvoControl::stop() {
    if (!started_) {
        return;
    }
    running_ = false;
    thread_.join();
    started_ = false;
#ifndef _WIN32
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
#endif
    LockGuard lock(write_mu_);
    if (!state_file_.empty()) {
        removeFile(state_file_);
    }
    last_line_.clear();
}

void EvoControl::writeState(const char* state, int overlay) {
    writeStateWithPid(state, currentPid(), overlay);
}

void EvoControl::writeStateWithPid(const char* state, int pid, int overlay) {
    LockGuard lock(write_mu_);
    if (state_file_.empty() || !state || !state[0]) {
        return;
    }
    char line[64];
    const int n = snprintf(line, sizeof(line), "%s %d %d\n", state, pid, overlay);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(line)) {
        return;
    }
    const uint32_t now = nowMonoMs();
    if (last_line_ == line && static_cast<uint32_t>(now - last_write_ms_) < 5000U) {
        return;
    }
    const std::string tmp = state_file_ + ".tmp";
#ifndef _WIN32
    const int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        return;
    }
    const ssize_t w = write(fd, line, static_cast<size_t>(n));
    close(fd);
    if (w == static_cast<ssize_t>(n) && rename(tmp.c_str(), state_file_.c_str()) == 0) {
        last_line_ = line;
        last_write_ms_ = now;
    } else {
        unlink(tmp.c_str());
    }
#else
    if (writeFileAtomic(state_file_, reinterpret_cast<const uint8_t*>(line), static_cast<size_t>(n))) {
        last_line_ = line;
        last_write_ms_ = now;
    }
#endif
}

void EvoControl::threadMain(void* self) {
    static_cast<EvoControl*>(self)->run();
}

void EvoControl::run() {
#ifndef _WIN32
    char buf[96];
    while (running_) {
        struct pollfd p;
        p.fd = fd_;
        p.events = POLLIN;
        p.revents = 0;
        if (poll(&p, 1, 100) <= 0) {
            continue;
        }
        struct sockaddr_un from;
        socklen_t fl = sizeof(from);
        const ssize_t n = recvfrom(fd_, buf, sizeof(buf), MSG_DONTWAIT,
                                   reinterpret_cast<struct sockaddr*>(&from), &fl);
        if (n <= 0) {
            continue;
        }
        ControlCommand cmd;
        if (!parseControlCommand(buf, static_cast<size_t>(n), cmd)) {
            continue;
        }
        if (cmd.verb == "ping") {
            if (fl > sizeof(sa_family_t) && fl <= sizeof(from)) {
                const ssize_t s = sendto(fd_, "pong", 4, MSG_DONTWAIT,
                                         reinterpret_cast<struct sockaddr*>(&from), fl);
                (void)s;
            }
            continue;
        }
        if (cb_) {
            cb_(cmd, user_);
        }
    }
#endif
}

}  // namespace platform
}  // namespace carplay
