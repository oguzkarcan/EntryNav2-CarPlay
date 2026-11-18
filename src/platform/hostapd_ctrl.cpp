#include "carplay/platform/hostapd_ctrl.hpp"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sstream>

#include "carplay/platform/file_util.hpp"
#include "carplay/platform/log.hpp"

#ifndef _WIN32
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace carplay {
namespace platform {

namespace {

const char* const kTag = "hostapd-ctrl";

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

std::string trimCopy(const std::string& s) {
    size_t start = 0U;
    while (start < s.size() &&
           (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n')) {
        ++start;
    }
    size_t end = s.size();
    while (end > start &&
           (s[end - 1U] == ' ' || s[end - 1U] == '\t' || s[end - 1U] == '\r' ||
            s[end - 1U] == '\n')) {
        --end;
    }
    return s.substr(start, end - start);
}

int hexVal(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

bool parseSignedInt(const std::string& s, int& out) {
    if (s.empty()) {
        return false;
    }
    char* end = NULL;
    errno = 0;
    const long v = strtol(s.c_str(), &end, 10);
    if (errno != 0 || end == NULL || *end != '\0') {
        return false;
    }
    if (v < -2147483647L - 1L || v > 2147483647L) {
        return false;
    }
    out = static_cast<int>(v);
    return true;
}

bool parseU64(const std::string& s, uint64_t& out) {
    if (s.empty() || s[0] == '-') {
        return false;
    }
    char* end = NULL;
    errno = 0;
    const unsigned long long v = strtoull(s.c_str(), &end, 10);
    if (errno != 0 || end == NULL || *end != '\0') {
        return false;
    }
    out = static_cast<uint64_t>(v);
    return true;
}

bool isFailureReply(const std::string& trimmed) {
    return trimmed == "FAIL" || trimmed == "UNKNOWN COMMAND" ||
           trimmed.compare(0, 4, "FAIL") == 0;
}

#ifndef _WIN32
uint32_t nextLocalSeq() {
    static uint32_t g_seq = 0U;
    return ++g_seq;
}

bool setSocketNonBlockCloexec(int fd) {
    const int fd_flags = fcntl(fd, F_GETFD, 0);
    if (fd_flags < 0 || fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) != 0) {
        return false;
    }
    const int fl_flags = fcntl(fd, F_GETFL, 0);
    if (fl_flags < 0 || fcntl(fd, F_SETFL, fl_flags | O_NONBLOCK) != 0) {
        return false;
    }
    return true;
}
#endif

}  // namespace

bool parseMacAddressBytes(const std::string& input, uint8_t out[6]) {
    const std::string s = trimCopy(input);
    if (s.size() != 17U) {
        return false;
    }
    const char sep = s[2];
    if (sep != ':' && sep != '-') {
        return false;
    }
    for (size_t i = 0U; i < 6U; ++i) {
        const size_t idx = i * 3U;
        const int hi = hexVal(s[idx]);
        const int lo = hexVal(s[idx + 1U]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        if (i < 5U && s[idx + 2U] != sep) {
            return false;
        }
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

bool normalizeMacAddress(const std::string& input, std::string& out) {
    uint8_t bytes[6];
    if (!parseMacAddressBytes(input, bytes)) {
        out.clear();
        return false;
    }
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             static_cast<unsigned int>(bytes[0]), static_cast<unsigned int>(bytes[1]),
             static_cast<unsigned int>(bytes[2]), static_cast<unsigned int>(bytes[3]),
             static_cast<unsigned int>(bytes[4]), static_cast<unsigned int>(bytes[5]));
    out = buf;
    return true;
}

bool parseHostapdStatus(const std::string& text, HostapdStatus& out) {
    out = HostapdStatus();
    const std::string trimmed_all = trimCopy(text);
    if (trimmed_all.empty() || isFailureReply(trimmed_all)) {
        return false;
    }

    std::istringstream iss(text);
    std::string line;
    bool any_kv = false;
    while (std::getline(iss, line)) {
        const std::string t = trimCopy(line);
        if (t.empty()) {
            continue;
        }
        const size_t eq = t.find('=');
        if (eq == std::string::npos || eq == 0U) {
            continue;
        }
        any_kv = true;
        const std::string k = t.substr(0U, eq);
        const std::string v = t.substr(eq + 1U);
        out.raw.push_back(std::make_pair(k, v));

        if (k == "state") {
            out.state = v;
        } else if (k == "phy") {
            out.phy = v;
        } else if (k == "freq") {
            int val = 0;
            if (parseSignedInt(v, val)) {
                out.freq = val;
            }
        } else if (k == "channel") {
            int val = 0;
            if (parseSignedInt(v, val)) {
                out.channel = val;
            }
        } else if (k == "bss[0]") {
            out.bss = v;
        } else if (k == "bssid[0]") {
            std::string norm;
            out.bssid = normalizeMacAddress(v, norm) ? norm : v;
        } else if (k == "ssid[0]") {
            out.ssid = v;
        } else if (k == "num_sta[0]") {
            int val = -1;
            if (parseSignedInt(v, val)) {
                out.num_sta = val;
            }
        }
    }
    return any_kv;
}

bool parseHostapdAllSta(const std::string& text, std::vector<HostapdStationInfo>& out) {
    out.clear();
    const std::string trimmed_all = trimCopy(text);
    if (trimmed_all.empty()) {
        return true;
    }
    if (isFailureReply(trimmed_all)) {
        return false;
    }

    std::istringstream iss(text);
    std::string line;
    bool have_current = false;
    HostapdStationInfo current;

    while (std::getline(iss, line)) {
        const std::string t = trimCopy(line);
        if (t.empty()) {
            continue;
        }
        const size_t eq = t.find('=');
        if (eq == std::string::npos) {
            std::string mac_norm;
            if (!normalizeMacAddress(t, mac_norm)) {
                out.clear();
                return false;
            }
            if (have_current) {
                out.push_back(current);
            }
            current = HostapdStationInfo();
            current.mac = mac_norm;
            have_current = true;
            continue;
        }

        if (!have_current || eq == 0U) {
            continue;
        }
        const std::string k = t.substr(0U, eq);
        const std::string v = t.substr(eq + 1U);
        current.raw.push_back(std::make_pair(k, v));

        if (k == "flags") {
            current.flags = v;
        } else if (k == "aid") {
            int val = -1;
            if (parseSignedInt(v, val)) {
                current.aid = val;
            }
        } else if (k == "connected_time") {
            uint64_t val = 0ULL;
            if (parseU64(v, val)) {
                current.connected_time = val;
            }
        } else if (k == "rx_packets") {
            uint64_t val = 0ULL;
            if (parseU64(v, val)) {
                current.rx_packets = val;
            }
        } else if (k == "tx_packets") {
            uint64_t val = 0ULL;
            if (parseU64(v, val)) {
                current.tx_packets = val;
            }
        }
    }

    if (have_current) {
        out.push_back(current);
    }
    return true;
}

bool isUnsolicitedHostapdMessage(const std::string& msg) {
    if (msg.size() < 3U || msg[0] != '<') {
        return false;
    }
    size_t i = 1U;
    while (i < msg.size() && msg[i] >= '0' && msg[i] <= '9') {
        ++i;
    }
    return i > 1U && i < msg.size() && msg[i] == '>';
}

bool parseHostapdEvent(const std::string& msg, HostapdEvent& out) {
    out = HostapdEvent();
    std::string body = trimCopy(msg);
    if (body.empty()) {
        return false;
    }
    if (isUnsolicitedHostapdMessage(body)) {
        const size_t gt = body.find('>');
        int lvl = -1;
        if (parseSignedInt(body.substr(1U, gt - 1U), lvl)) {
            out.level = lvl;
        }
        body = trimCopy(body.substr(gt + 1U));
    }
    if (body.empty()) {
        return false;
    }
    out.raw_body = body;

    const size_t sp = body.find_first_of(" \t");
    out.name = (sp == std::string::npos) ? body : body.substr(0U, sp);
    std::string arg;
    if (sp != std::string::npos) {
        const std::string rest = trimCopy(body.substr(sp + 1U));
        const size_t sp2 = rest.find_first_of(" \t");
        arg = (sp2 == std::string::npos) ? rest : rest.substr(0U, sp2);
    }

    if (out.name == "AP-STA-CONNECTED") {
        out.type = kHostapdEventStaConnected;
        std::string mac_norm;
        if (!arg.empty() && normalizeMacAddress(arg, mac_norm)) {
            out.mac = mac_norm;
        }
    } else if (out.name == "AP-STA-DISCONNECTED") {
        out.type = kHostapdEventStaDisconnected;
        std::string mac_norm;
        if (!arg.empty() && normalizeMacAddress(arg, mac_norm)) {
            out.mac = mac_norm;
        }
    } else if (out.name == "AP-ENABLED") {
        out.type = kHostapdEventApEnabled;
    } else if (out.name == "AP-DISABLED") {
        out.type = kHostapdEventApDisabled;
    } else if (out.name == "INTERFACE-DISABLED") {
        out.type = kHostapdEventInterfaceDisabled;
    } else if (out.name == "CTRL-EVENT-TERMINATING") {
        out.type = kHostapdEventTerminating;
    } else {
        out.type = kHostapdEventUnknown;
    }
    return true;
}

bool isHostapdReplyOk(HostapdCommandKind kind, const std::string& reply) {
    const std::string t = trimCopy(reply);
    switch (kind) {
        case kCmdPing:
            return t == "PONG";
        case kCmdAttach:
        case kCmdDetach:
        case kCmdEnable:
        case kCmdDisable:
            return t == "OK";
        case kCmdStatus:
        case kCmdGetConfig:
            return !t.empty() && !isFailureReply(t);
        case kCmdAllSta:
            return !isFailureReply(t);
        case kCmdRaw:
            return !isFailureReply(t);
    }
    return false;
}

HostapdCtrl::HostapdCtrl(Reactor& reactor)
    : reactor_(reactor),
      listener_(NULL),
      fd_(kInvalidSocket),
      timeout_timer_id_(Reactor::kNoTimer),
      generation_(0U),
      alive_state_(new AliveState()) {}

HostapdCtrl::~HostapdCtrl() {
    if (alive_state_ != NULL) {
        alive_state_->alive = false;
    }
    listener_ = NULL;
    close();
    if (alive_state_ != NULL) {
        if (--alive_state_->refs == 0) {
            delete alive_state_;
        }
        alive_state_ = NULL;
    }
}

void HostapdCtrl::setListener(HostapdCtrlListener* listener) {
    listener_ = listener;
}

bool HostapdCtrl::open(const std::string& remote_ctrl_path,
                       const std::string& local_bind_dir,
                       std::string* error_out) {
#ifdef _WIN32
    (void)remote_ctrl_path;
    (void)local_bind_dir;
    setError(error_out, "hostapd UNIX control socket is not supported on Windows");
    return false;
#else
    close();

    if (remote_ctrl_path.empty() || local_bind_dir.empty()) {
        setError(error_out, "control socket paths must not be empty");
        return false;
    }

    struct sockaddr_un remote_addr;
    if (remote_ctrl_path.size() >= sizeof(remote_addr.sun_path)) {
        setError(error_out, "remote control socket path too long");
        return false;
    }

    char name_buf[64];
    snprintf(name_buf, sizeof(name_buf), "carplay_wpa_ctrl_%ld_%u.sock",
             static_cast<long>(getpid()), static_cast<unsigned int>(nextLocalSeq()));
    const std::string local_candidate = joinPath(local_bind_dir, name_buf);

    struct sockaddr_un local_addr;
    if (local_candidate.size() >= sizeof(local_addr.sun_path)) {
        setError(error_out, "local bind socket path too long");
        return false;
    }

    const int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        setError(error_out, "socket(AF_UNIX, SOCK_DGRAM) failed: " + socketErrorString(errno));
        return false;
    }
    if (!setSocketNonBlockCloexec(fd)) {
        const int err_no = errno;
        ::close(fd);
        setError(error_out, "fcntl on control socket failed: " + socketErrorString(err_no));
        return false;
    }

    unlink(local_candidate.c_str());
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sun_family = AF_UNIX;
    memcpy(local_addr.sun_path, local_candidate.c_str(), local_candidate.size() + 1U);

    if (bind(fd, reinterpret_cast<struct sockaddr*>(&local_addr), sizeof(local_addr)) != 0) {
        const int err_no = errno;
        ::close(fd);
        setError(error_out, "bind(" + local_candidate + ") failed: " + socketErrorString(err_no));
        return false;
    }
    chmod(local_candidate.c_str(), 0600);

    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sun_family = AF_UNIX;
    memcpy(remote_addr.sun_path, remote_ctrl_path.c_str(), remote_ctrl_path.size() + 1U);

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&remote_addr), sizeof(remote_addr)) != 0) {
        const int err_no = errno;
        ::close(fd);
        unlink(local_candidate.c_str());
        setError(error_out, "connect(" + remote_ctrl_path + ") failed: " + socketErrorString(err_no));
        return false;
    }

    if (!reactor_.add(static_cast<SocketHandle>(fd), this, kPollIn)) {
        ::close(fd);
        unlink(local_candidate.c_str());
        setError(error_out, "failed to register hostapd control socket in Reactor");
        return false;
    }

    fd_ = static_cast<SocketHandle>(fd);
    local_path_ = local_candidate;
    remote_path_ = remote_ctrl_path;
    ++generation_;
    return true;
#endif
}

void HostapdCtrl::close() {
    cancelTimeout();
    queue_.clear();
#ifndef _WIN32
    if (fd_ != kInvalidSocket) {
        reactor_.remove(fd_);
        ::close(fd_);
        fd_ = kInvalidSocket;
    }
    if (!local_path_.empty()) {
        unlink(local_path_.c_str());
        local_path_.clear();
    }
#endif
    remote_path_.clear();
    ++generation_;
}

bool HostapdCtrl::isOpen() const {
    return fd_ != kInvalidSocket;
}

bool HostapdCtrl::sendPing(int timeout_ms) {
    return sendCommand(kCmdPing, "PING", timeout_ms);
}

bool HostapdCtrl::sendAttach(int timeout_ms) {
    return sendCommand(kCmdAttach, "ATTACH", timeout_ms);
}

bool HostapdCtrl::sendDetach(int timeout_ms) {
    return sendCommand(kCmdDetach, "DETACH", timeout_ms);
}

bool HostapdCtrl::sendStatus(int timeout_ms) {
    return sendCommand(kCmdStatus, "STATUS", timeout_ms);
}

bool HostapdCtrl::sendGetConfig(int timeout_ms) {
    return sendCommand(kCmdGetConfig, "GET_CONFIG", timeout_ms);
}

bool HostapdCtrl::sendAllSta(int timeout_ms) {
    return sendCommand(kCmdAllSta, "ALL_STA", timeout_ms);
}

bool HostapdCtrl::sendEnable(int timeout_ms) {
    return sendCommand(kCmdEnable, "ENABLE", timeout_ms);
}

bool HostapdCtrl::sendDisable(int timeout_ms) {
    return sendCommand(kCmdDisable, "DISABLE", timeout_ms);
}

bool HostapdCtrl::sendCommand(HostapdCommandKind kind,
                              const std::string& cmd,
                              int timeout_ms) {
    if (!isOpen() || cmd.empty() || timeout_ms <= 0) {
        return false;
    }
    if (queue_.size() >= kMaxPendingCommands) {
        return false;
    }
    QueuedCommand q;
    q.kind = kind;
    q.text = cmd;
    q.timeout_ms = timeout_ms;
    q.sent = false;
    queue_.push_back(q);
    if (queue_.size() == 1U) {
        pumpNextCommand();
    }
    return true;
}

void HostapdCtrl::pumpNextCommand() {
#ifdef _WIN32
    return;
#else
    if (!isOpen() || queue_.empty()) {
        return;
    }
    QueuedCommand& head = queue_.front();
    if (head.sent) {
        return;
    }
    const ssize_t n = ::send(fd_, head.text.data(), head.text.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n == static_cast<ssize_t>(head.text.size())) {
        head.sent = true;
        reactor_.modify(fd_, kPollIn);
        armTimeout(head.timeout_ms);
        return;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        reactor_.modify(fd_, kPollIn | kPollOut);
        armTimeout(head.timeout_ms);
        return;
    }

    const std::string err_msg =
        n < 0 ? ("hostapd send failed: " + socketErrorString(errno)) : "hostapd short datagram send";
    const HostapdCommandKind kind = head.kind;
    queue_.pop_front();
    cancelTimeout();
    CARPLAY_LOG_WARN(kTag, "%s", err_msg.c_str());

    AliveGuard guard(alive_state_);
    const uint32_t gen = generation_;
    if (listener_ != NULL) {
        listener_->onHostapdCommandReply(kind, false, err_msg);
    }
    if (!guard.alive()) {
        return;
    }
    if (gen == generation_ && !queue_.empty()) {
        pumpNextCommand();
    }
#endif
}

void HostapdCtrl::armTimeout(int timeout_ms) {
    cancelTimeout();
    timeout_timer_id_ = reactor_.startTimer(timeout_ms, 0, this);
}

void HostapdCtrl::cancelTimeout() {
    if (timeout_timer_id_ != Reactor::kNoTimer) {
        reactor_.cancelTimer(timeout_timer_id_);
        timeout_timer_id_ = Reactor::kNoTimer;
    }
}

void HostapdCtrl::onReadable() {
#ifdef _WIN32
    return;
#else
    AliveGuard guard(alive_state_);
    const uint32_t gen = generation_;

    static const int kMaxReadsPerWakeup = 32;
    for (int i = 0; i < kMaxReadsPerWakeup; ++i) {
        if (!isOpen() || gen != generation_) {
            break;
        }
        char buf[kMaxDatagramBytes];
        const ssize_t n = ::recv(fd_, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            const std::string err = "hostapd recv failed: " + socketErrorString(errno);
            CARPLAY_LOG_WARN(kTag, "%s", err.c_str());
            close();
            if (listener_ != NULL) {
                listener_->onHostapdCtrlError(err);
            }
            break;
        }
        if (n == 0) {
            continue;
        }
        handleDatagram(std::string(buf, static_cast<size_t>(n)));
        if (!guard.alive()) {
            return;
        }
    }
#endif
}

void HostapdCtrl::onWritable() {
    if (isOpen()) {
        pumpNextCommand();
    }
}

void HostapdCtrl::onError() {
    const std::string err = "hostapd control socket error";
    CARPLAY_LOG_WARN(kTag, "%s", err.c_str());
    AliveGuard guard(alive_state_);
    close();
    if (listener_ != NULL) {
        listener_->onHostapdCtrlError(err);
    }
    if (!guard.alive()) {
        return;
    }
}

void HostapdCtrl::onTimer(uint32_t timer_id) {
    if (timer_id != timeout_timer_id_) {
        return;
    }
    timeout_timer_id_ = Reactor::kNoTimer;
    if (queue_.empty()) {
        return;
    }

    const HostapdCommandKind kind = queue_.front().kind;
    queue_.pop_front();
    if (isOpen()) {
        reactor_.modify(fd_, kPollIn);
    }

    AliveGuard guard(alive_state_);
    const uint32_t gen = generation_;
    if (listener_ != NULL) {
        listener_->onHostapdCommandReply(kind, false, "timeout");
    }
    if (!guard.alive()) {
        return;
    }
    if (gen == generation_ && !queue_.empty()) {
        pumpNextCommand();
    }
}

void HostapdCtrl::handleDatagram(const std::string& msg) {
    AliveGuard guard(alive_state_);
    const uint32_t gen = generation_;
    if (isUnsolicitedHostapdMessage(msg)) {
        HostapdEvent ev;
        if (parseHostapdEvent(msg, ev) && listener_ != NULL) {
            listener_->onHostapdEvent(ev);
        }
        return;
    }

    if (queue_.empty() || !queue_.front().sent) {
        CARPLAY_LOG_DEBUG(kTag, "ignoring unexpected hostapd reply (%zu bytes)", msg.size());
        return;
    }

    const HostapdCommandKind kind = queue_.front().kind;
    queue_.pop_front();
    cancelTimeout();
    const bool ok = isHostapdReplyOk(kind, msg);

    if (listener_ != NULL) {
        listener_->onHostapdCommandReply(kind, ok, msg);
    }
    if (!guard.alive()) {
        return;
    }
    if (gen == generation_ && !queue_.empty()) {
        pumpNextCommand();
    }
}

}  // namespace platform
}  // namespace carplay
