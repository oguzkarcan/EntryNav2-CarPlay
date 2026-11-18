// Derived from EntryNav2-Android-Auto 0.12.0 platform/evo_wlan.cpp, PolyForm Noncommercial License 1.0.0

#include "carplay/platform/evo_wlan.hpp"

#include <stdio.h>
#include <string.h>

#include "carplay/platform/log.hpp"
#include "carplay/platform/net_compat.hpp"

namespace carplay {
namespace platform {

namespace {

const char* const kTag = "evo-wlan";

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

bool isErrorReplyOp(uint32_t op) {
    return op == kMostOpError || op == kMostOpErrorAck;
}

bool isFinalReplyOp(uint32_t op) {
    return op == kMostOpResultAck || op == kMostOpError || op == kMostOpErrorAck;
}

struct SyncSession {
    VmostClient vmost;
    WlanRequestResult* r;
    bool sent;
    bool got_state;
    bool final_reply;

    explicit SyncSession(WlanRequestResult* result)
        : r(result), sent(false), got_state(false), final_reply(false) {}
};

void onSyncMessage(void* msg, void* user) {
    SyncSession* s = static_cast<SyncSession*>(user);
    VmostMsgView v;
    if (s == NULL || !parseVmostMsg(msg, v) || v.fblock != kWlanFblock ||
        v.inst != kWlanApInstance) {
        return;
    }
    ++s->r->messages;
    if (v.fkt == kWlanState3 && v.op == kMostOpStatus && v.len >= 1U) {
        if (s->sent) {
            s->r->state_after = static_cast<int>(v.data[0]);
        } else {
            s->r->state_before = static_cast<int>(v.data[0]);
        }
        s->got_state = true;
    } else if (v.fkt == kSelectWlanState3) {
        s->r->reply_op = static_cast<int>(v.op);
        if (isFinalReplyOp(v.op)) {
            s->final_reply = true;
        }
    }
}

void pumpSync(SyncSession& s,
              SocketHandle fd,
              unsigned ms,
              bool (*done)(const SyncSession&)) {
    PollSet poll_set;
    const int64_t end_ms = monotonicMillis() + static_cast<int64_t>(ms);
    while (!done(s)) {
        const int64_t rem = end_ms - monotonicMillis();
        if (rem <= 0) {
            break;
        }
        PollItem item;
        item.handle = fd;
        item.events = kPollIn;
        item.revents = 0U;
        const int slice = rem > 50 ? 50 : static_cast<int>(rem);
        const int r = poll_set.wait(&item, 1U, slice);
        if (r < 0) {
            break;
        }
        if (r > 0 && (item.revents & (kPollErr | kPollHup | kPollNval)) != 0U) {
            break;
        }
        if (r > 0 && (item.revents & kPollIn) != 0U) {
            if (s.vmost.processMessages() != 0) {
                break;
            }
        }
    }
}

bool haveSyncState(const SyncSession& s) {
    return s.got_state;
}

bool haveSyncFinal(const SyncSession& s) {
    return s.final_reply;
}

bool openSyncVmost(SyncSession& s,
                   const VmostApi* api_override,
                   int& fd_out,
                   std::string* error_out) {
    if (api_override != NULL) {
        s.vmost.setApiOverride(api_override);
    }
    switch (s.vmost.load()) {
        case VmostClient::kLoaded:
            break;
        case VmostClient::kNoDaemon:
            setError(error_out, "vmostd socket missing");
            return false;
        case VmostClient::kNoLibrary:
            setError(error_out, "libvmostclient.so.1 unavailable: " + s.vmost.error());
            return false;
        case VmostClient::kNoSymbols:
            setError(error_out, "vMOST functions missing");
            return false;
    }
    if (s.vmost.connect(&onSyncMessage, &s, 0) != 0) {
        s.vmost.unload();
        setError(error_out, "vmostd refused connection");
        return false;
    }
    const int rc = s.vmost.shadowRegister(kWlanFblock, kWlanApInstance);
    fd_out = -1;
    if (rc != 0 || s.vmost.fileDescriptorGet(&fd_out) != 0 || fd_out < 0) {
        if (rc == 0) {
            s.vmost.shadowDeregister(kWlanFblock, kWlanApInstance);
        }
        s.vmost.disconnect();
        s.vmost.unload();
        setError(error_out, "WLAN.01 shadow registration refused");
        return false;
    }
    s.r->connected = true;
    return true;
}

void closeSyncVmost(SyncSession& s) {
    s.vmost.shadowDeregister(kWlanFblock, kWlanApInstance);
    s.vmost.disconnect();
    s.vmost.unload();
}

}  // namespace

size_t buildSelectWlanState3(uint8_t out[3], uint16_t sender_handle, bool on) {
    out[0] = static_cast<uint8_t>((sender_handle >> 8) & 0xffU);
    out[1] = static_cast<uint8_t>(sender_handle & 0xffU);
    out[2] = on ? 1U : 0U;
    return 3U;
}

WlanRequestResult::WlanRequestResult()
    : connected(false),
      state_before(-1),
      sent(false),
      state_after(-1),
      reply_op(-1),
      messages(0U),
      switched_on_by_us(false) {}

bool requestWlanAccessPoint(unsigned wait_ms,
                            WlanRequestResult* result,
                            const VmostApi* api_override) {
    WlanRequestResult local;
    WlanRequestResult& r = result != NULL ? *result : local;
    r = WlanRequestResult();

    SyncSession s(&r);
    int raw_fd = -1;
    std::string err;
    if (!openSyncVmost(s, api_override, raw_fd, &err)) {
        CARPLAY_LOG_INFO(kTag, "hotspot not requested: %s", err.c_str());
        return false;
    }

    const SocketHandle fd = static_cast<SocketHandle>(raw_fd);
    static const uint8_t kDummy[4] = {0U, 0U, 0U, 0U};
    VmostMsgOut m;
    buildVmostGet(m, kWlanFblock, kWlanApInstance, kWlanState3, kDummy, 0U);
    int rc = s.vmost.send(&m);
    if (rc == 0) {
        const unsigned get_wait_ms = (wait_ms > 0U && wait_ms < 1000U) ? wait_ms : 1000U;
        pumpSync(s, fd, get_wait_ms, &haveSyncState);
    }

    bool ok = false;
    if (r.state_before == 1) {
        CARPLAY_LOG_INFO(kTag, "wland already reports hotspot on (state=1): nothing sent");
        r.switched_on_by_us = false;
        ok = true;
    } else {
        uint8_t payload[3];
        buildSelectWlanState3(payload, kDefaultWlanSenderHandle, true);
        buildVmostStartResultAck(m, kWlanFblock, kWlanApInstance, kSelectWlanState3, payload,
                                 sizeof(payload));
        rc = s.vmost.send(&m);
        r.sent = (rc == 0);
        r.switched_on_by_us = r.sent;
        s.sent = r.sent;
        s.got_state = false;
        CARPLAY_LOG_INFO(kTag,
                         "state_before=%d: requesting CarPlay switch-on (0xA0.01.0xC11 %02x %02x 01): %s",
                         r.state_before, static_cast<unsigned int>(payload[0]),
                         static_cast<unsigned int>(payload[1]), r.sent ? "sent" : "refused");
        if (r.sent) {
            pumpSync(s, fd, wait_ms, &haveSyncFinal);
        }
        if (r.sent && !s.got_state && r.reply_op >= 0 &&
            !isErrorReplyOp(static_cast<uint32_t>(r.reply_op))) {
            const unsigned post_ms = (wait_ms > 0U && wait_ms < 500U) ? wait_ms : 500U;
            pumpSync(s, fd, post_ms, &haveSyncState);
        }
        ok = r.sent && (r.reply_op < 0 || !isErrorReplyOp(static_cast<uint32_t>(r.reply_op)));
        CARPLAY_LOG_INFO(kTag, "enable done: ok=%d reply_op=%d state_after=%d messages=%u",
                         ok ? 1 : 0, r.reply_op, r.state_after, r.messages);
    }

    closeSyncVmost(s);
    return ok;
}

bool releaseWlanAccessPoint(unsigned wait_ms,
                            WlanRequestResult* result,
                            const VmostApi* api_override) {
    WlanRequestResult local;
    WlanRequestResult& r = result != NULL ? *result : local;
    r = WlanRequestResult();

    SyncSession s(&r);
    int raw_fd = -1;
    std::string err;
    if (!openSyncVmost(s, api_override, raw_fd, &err)) {
        CARPLAY_LOG_WARN(kTag, "hotspot release skipped: %s", err.c_str());
        return false;
    }

    const SocketHandle fd = static_cast<SocketHandle>(raw_fd);
    uint8_t payload[3];
    buildSelectWlanState3(payload, kDefaultWlanSenderHandle, false);
    VmostMsgOut m;
    buildVmostStartResultAck(m, kWlanFblock, kWlanApInstance, kSelectWlanState3, payload,
                             sizeof(payload));
    const int rc = s.vmost.send(&m);
    r.sent = (rc == 0);
    s.sent = r.sent;
    if (r.sent && wait_ms > 0U) {
        pumpSync(s, fd, wait_ms, &haveSyncFinal);
    }
    const bool ok =
        r.sent && (r.reply_op < 0 || !isErrorReplyOp(static_cast<uint32_t>(r.reply_op)));
    CARPLAY_LOG_INFO(kTag, "release done: ok=%d reply_op=%d state_after=%d", ok ? 1 : 0,
                     r.reply_op, r.state_after);

    closeSyncVmost(s);
    return ok;
}

bool restoreWlanAccessPoint(bool switched_on_by_us,
                            unsigned wait_ms,
                            WlanRequestResult* result,
                            const VmostApi* api_override) {
    if (!switched_on_by_us) {
        if (result != NULL) {
            *result = WlanRequestResult();
        }
        return true;
    }
    return releaseWlanAccessPoint(wait_ms, result, api_override);
}

EvoWlanController::EvoWlanController(Reactor& reactor)
    : reactor_(reactor),
      listener_(NULL),
      api_override_(NULL),
      fd_(kInvalidSocket),
      mode_(kModeIdle),
      timer_id_(Reactor::kNoTimer),
      total_deadline_ms_(0),
      total_timeout_ms_(0U),
      got_state_before_(false),
      got_final_reply_(false),
      got_state_after_(false),
      alive_state_(new AliveState()) {}

EvoWlanController::~EvoWlanController() {
    if (alive_state_ != NULL) {
        alive_state_->alive = false;
    }
    listener_ = NULL;
    cancel();
    if (alive_state_ != NULL) {
        if (--alive_state_->refs == 0) {
            delete alive_state_;
        }
        alive_state_ = NULL;
    }
}

void EvoWlanController::setApiOverride(const VmostApi* api) {
    if (mode_ != kModeIdle) {
        CARPLAY_LOG_WARN(kTag, "ignoring setApiOverride while EvoWlanController is busy");
        return;
    }
    api_override_ = api;
    vmost_.setApiOverride(api);
}

bool EvoWlanController::isAvailable() const {
    if (api_override_ != NULL) {
        return api_override_->complete();
    }
    return isVmostDaemonPresent();
}

int64_t EvoWlanController::nowMs() const {
    return reactor_.now() / 1000000LL;
}

void EvoWlanController::cancelTimer() {
    if (timer_id_ != Reactor::kNoTimer) {
        reactor_.cancelTimer(timer_id_);
        timer_id_ = Reactor::kNoTimer;
    }
}

void EvoWlanController::armTimer(int delay_ms) {
    cancelTimer();
    const int d = delay_ms > 0 ? delay_ms : 1;
    timer_id_ = reactor_.startTimer(d, 0, this);
}

bool EvoWlanController::openSession(std::string* error_out) {
    vmost_.setApiOverride(api_override_);
    switch (vmost_.load()) {
        case VmostClient::kLoaded:
            break;
        case VmostClient::kNoDaemon:
            setError(error_out, "vmostd socket missing");
            return false;
        case VmostClient::kNoLibrary:
            setError(error_out, "libvmostclient.so.1 unavailable: " + vmost_.error());
            return false;
        case VmostClient::kNoSymbols:
            setError(error_out, "vMOST symbols missing");
            return false;
    }
    if (vmost_.connect(&EvoWlanController::onMessageStatic, this, 0) != 0) {
        vmost_.unload();
        setError(error_out, "vmostd refused connection");
        return false;
    }
    const int rc = vmost_.shadowRegister(kWlanFblock, kWlanApInstance);
    int raw_fd = -1;
    if (rc != 0 || vmost_.fileDescriptorGet(&raw_fd) != 0 || raw_fd < 0) {
        if (rc == 0) {
            vmost_.shadowDeregister(kWlanFblock, kWlanApInstance);
        }
        vmost_.disconnect();
        vmost_.unload();
        setError(error_out, "WLAN.01 shadow registration failed");
        return false;
    }

    const SocketHandle sock = static_cast<SocketHandle>(raw_fd);
    if (!reactor_.add(sock, this, kPollIn)) {
        vmost_.shadowDeregister(kWlanFblock, kWlanApInstance);
        vmost_.disconnect();
        vmost_.unload();
        setError(error_out, "failed to register vMOST descriptor in Reactor");
        return false;
    }

    fd_ = sock;
    result_.connected = true;
    return true;
}

void EvoWlanController::closeSession() {
    cancelTimer();
    if (fd_ != kInvalidSocket) {
        reactor_.remove(fd_);
        fd_ = kInvalidSocket;
    }
    if (result_.connected) {
        vmost_.shadowDeregister(kWlanFblock, kWlanApInstance);
        vmost_.disconnect();
        if (api_override_ == NULL) {
            vmost_.unload();
        }
    }
}

bool EvoWlanController::sendGetState(std::string* error_out) {
    static const uint8_t kDummy[4] = {0U, 0U, 0U, 0U};
    VmostMsgOut m;
    buildVmostGet(m, kWlanFblock, kWlanApInstance, kWlanState3, kDummy, 0U);
    if (vmost_.send(&m) != 0) {
        setError(error_out, "failed to send WLANState3.Get");
        return false;
    }
    return true;
}

bool EvoWlanController::sendSelectState(bool on, std::string* error_out) {
    uint8_t payload[3];
    buildSelectWlanState3(payload, kDefaultWlanSenderHandle, on);
    VmostMsgOut m;
    buildVmostStartResultAck(m, kWlanFblock, kWlanApInstance, kSelectWlanState3, payload,
                             sizeof(payload));
    if (vmost_.send(&m) != 0) {
        setError(error_out, on ? "failed to send SelectWLANState3(1)"
                               : "failed to send SelectWLANState3(0)");
        return false;
    }
    result_.sent = true;
    if (on) {
        result_.switched_on_by_us = true;
    }
    return true;
}

bool EvoWlanController::beginEnable(unsigned timeout_ms, std::string* error_out) {
    if (mode_ != kModeIdle) {
        setError(error_out, "vMOST WLAN operation already in progress");
        return false;
    }

    result_ = WlanRequestResult();
    got_state_before_ = false;
    got_final_reply_ = false;
    got_state_after_ = false;

    if (!openSession(error_out)) {
        return false;
    }
    if (!sendGetState(error_out)) {
        closeSession();
        return false;
    }

    total_timeout_ms_ = timeout_ms > 0U ? timeout_ms : 2000U;
    total_deadline_ms_ = nowMs() + static_cast<int64_t>(total_timeout_ms_);
    mode_ = kModeEnableGetState;
    const unsigned get_wait_ms = total_timeout_ms_ < 1000U ? total_timeout_ms_ : 1000U;
    armTimer(static_cast<int>(get_wait_ms));
    return true;
}

bool EvoWlanController::beginDisable(unsigned timeout_ms, std::string* error_out) {
    if (mode_ != kModeIdle) {
        setError(error_out, "vMOST WLAN operation already in progress");
        return false;
    }

    result_ = WlanRequestResult();
    got_state_before_ = false;
    got_final_reply_ = false;
    got_state_after_ = false;

    if (!openSession(error_out)) {
        return false;
    }
    if (!sendSelectState(false, error_out)) {
        closeSession();
        return false;
    }

    total_timeout_ms_ = timeout_ms > 0U ? timeout_ms : 1000U;
    total_deadline_ms_ = nowMs() + static_cast<int64_t>(total_timeout_ms_);
    mode_ = kModeDisableWaitAck;
    armTimer(static_cast<int>(total_timeout_ms_));
    return true;
}

void EvoWlanController::cancel() {
    if (mode_ == kModeIdle && fd_ == kInvalidSocket) {
        return;
    }
    closeSession();
    mode_ = kModeIdle;
}

bool EvoWlanController::restoreSync(unsigned timeout_ms, std::string* error_out) {
    cancel();
    WlanRequestResult res;
    if (!releaseWlanAccessPoint(timeout_ms, &res, api_override_)) {
        setError(error_out, "failed to switch off car-native Wi-Fi AP via vMOST");
        return false;
    }
    return true;
}

void EvoWlanController::onMessageStatic(void* msg, void* user) {
    EvoWlanController* self = static_cast<EvoWlanController*>(user);
    if (self == NULL || msg == NULL) {
        return;
    }
    VmostMsgView v;
    if (!parseVmostMsg(msg, v)) {
        return;
    }
    self->onMessage(v);
}

void EvoWlanController::onMessage(const VmostMsgView& v) {
    if (v.fblock != kWlanFblock || v.inst != kWlanApInstance) {
        return;
    }
    ++result_.messages;
    if (v.fkt == kWlanState3 && v.op == kMostOpStatus && v.len >= 1U) {
        if (result_.sent) {
            result_.state_after = static_cast<int>(v.data[0]);
            got_state_after_ = true;
        } else {
            result_.state_before = static_cast<int>(v.data[0]);
            got_state_before_ = true;
        }
    } else if (v.fkt == kSelectWlanState3) {
        result_.reply_op = static_cast<int>(v.op);
        if (isFinalReplyOp(v.op)) {
            got_final_reply_ = true;
        }
    }
}

void EvoWlanController::stepAfterIo() {
    if (mode_ == kModeEnableGetState) {
        if (!got_state_before_) {
            return;
        }
        if (result_.state_before == 1) {
            result_.switched_on_by_us = false;
            CARPLAY_LOG_INFO(kTag, "wland reports hotspot already ON (state=1)");
            completeOperation(true, true, "");
            return;
        }
        std::string err;
        if (!sendSelectState(true, &err)) {
            completeOperation(true, false, err);
            return;
        }
        mode_ = kModeEnableWaitAck;
        const int64_t rem = total_deadline_ms_ - nowMs();
        armTimer(rem > 0 ? static_cast<int>(rem) : 1);
        return;
    }

    if (mode_ == kModeEnableWaitAck) {
        if (got_final_reply_) {
            if (result_.reply_op >= 0 && isErrorReplyOp(static_cast<uint32_t>(result_.reply_op))) {
                completeOperation(true, false, "wland rejected SelectWLANState3(1)");
                return;
            }
            if (got_state_after_) {
                completeOperation(true, true, "");
                return;
            }
            mode_ = kModeEnableWaitStateAfter;
            const int64_t rem = total_deadline_ms_ - nowMs();
            const int post_ms = (rem > 0 && rem < 200) ? static_cast<int>(rem) : 200;
            armTimer(post_ms);
            return;
        }
        if (got_state_after_ && result_.state_after == 1) {
            completeOperation(true, true, "");
        }
        return;
    }

    if (mode_ == kModeEnableWaitStateAfter) {
        if (got_state_after_) {
            completeOperation(true, true, "");
        }
        return;
    }

    if (mode_ == kModeDisableWaitAck) {
        if (got_final_reply_) {
            if (result_.reply_op >= 0 && isErrorReplyOp(static_cast<uint32_t>(result_.reply_op))) {
                completeOperation(false, false, "wland rejected SelectWLANState3(0)");
            } else {
                completeOperation(false, true, "");
            }
        }
    }
}

void EvoWlanController::completeOperation(bool is_enable, bool ok, const std::string& error) {
    const WlanRequestResult snapshot = result_;
    closeSession();
    mode_ = kModeIdle;

    AliveGuard guard(alive_state_);
    if (listener_ != NULL) {
        if (is_enable) {
            listener_->onWlanEnableResult(ok, snapshot, error);
        } else {
            listener_->onWlanDisableResult(ok, snapshot, error);
        }
    }
    if (!guard.alive()) {
        return;
    }
}

void EvoWlanController::onReadable() {
    if (mode_ == kModeIdle || fd_ == kInvalidSocket) {
        return;
    }
    if (vmost_.processMessages() != 0) {
        const bool is_enable = (mode_ != kModeDisableWaitAck);
        completeOperation(is_enable, false, "vmostd processMessages failed");
        return;
    }
    stepAfterIo();
}

void EvoWlanController::onError() {
    if (mode_ == kModeIdle) {
        return;
    }
    const bool is_enable = (mode_ != kModeDisableWaitAck);
    completeOperation(is_enable, false, "vmostd descriptor error");
}

void EvoWlanController::onTimer(uint32_t timer_id) {
    if (timer_id != timer_id_) {
        return;
    }
    timer_id_ = Reactor::kNoTimer;

    if (mode_ == kModeEnableGetState) {
        std::string err;
        if (!sendSelectState(true, &err)) {
            completeOperation(true, false, err);
            return;
        }
        mode_ = kModeEnableWaitAck;
        const int64_t rem = total_deadline_ms_ - nowMs();
        armTimer(rem > 0 ? static_cast<int>(rem) : 1);
        return;
    }

    if (mode_ == kModeEnableWaitAck) {
        CARPLAY_LOG_INFO(kTag,
                         "SelectWLANState3(1) reply timed out (sent=%d); continuing to readiness check",
                         result_.sent ? 1 : 0);
        completeOperation(true, result_.sent, result_.sent ? "" : "vMOST switch-on timed out");
        return;
    }

    if (mode_ == kModeEnableWaitStateAfter) {
        completeOperation(true, true, "");
        return;
    }

    if (mode_ == kModeDisableWaitAck) {
        completeOperation(false, false, "timed out waiting for SelectWLANState3(0) reply");
    }
}

}  // namespace platform
}  // namespace carplay
