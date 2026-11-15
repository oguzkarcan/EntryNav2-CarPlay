#include "carplay/platform/session_server.hpp"

namespace carplay {
namespace platform {

namespace {

static const char kAltScreenUuid[] = "e5f7a68d-7b0f-4305-984b-974f677a150b";

// Work done per readiness callback is bounded so that one busy (or hostile) socket cannot keep
// the single reactor thread away from the other sockets and the timers. poll() is level
// triggered: whatever is left is picked up in the next round.
static const int kMaxAcceptsPerWakeup = 8;
static const int kMaxTcpReadsPerWakeup = 16;
static const int kMaxDatagramsPerWakeup = 32;

void unregisterAndClose(Reactor& reactor, TcpListener& listener) {
    if (listener.isOpen()) {
        reactor.remove(listener.handle());
        listener.close();
    }
}

void unregisterAndClose(Reactor& reactor, TcpConnection& conn) {
    if (conn.isOpen()) {
        reactor.remove(conn.handle());
        conn.close();
    }
}

void unregisterAndClose(Reactor& reactor, UdpSocket& sock) {
    if (sock.isOpen()) {
        reactor.remove(sock.handle());
        sock.close();
    }
}

}  // namespace

SessionServer::SessionServer(Reactor& reactor,
                             const info::AirPlayConfig& config,
                             const pairing::Identity& identity,
                             pairing::PairingStore& store,
                             pairing::RandomSource& rng,
                             session::SessionListener& listener,
                             session::MediaHandler& media,
                             session::AuthProvider* auth,
                             const SessionServerConfig& server_config)
    : reactor_(reactor),
      config_(config),
      identity_(identity),
      store_(store),
      rng_(rng),
      listener_(listener),
      media_(media),
      media_engine_(NULL),
      auth_(auth),
      server_cfg_(server_config),
      control_accept_handler_(this),
      control_conn_handler_(this),
      event_accept_handler_(this),
      event_conn_handler_(this),
      timing_handler_(this),
      keepalive_handler_(this),
      timer_handler_(this),
      session_(NULL),
      in_session_call_(false),
      deferred_destroy_(false),
      control_read_paused_(false),
      clock_sync_(server_config.initial_ntp_offset_ns),
      ntp_timer_id_(Reactor::kNoTimer),
      unverified_timer_id_(Reactor::kNoTimer),
      has_saved_night_mode_(false),
      saved_night_mode_(false),
      rate_limited_accepts_(0),
      busy_rejected_accepts_(0),
      event_rejected_peers_(0),
      timing_stranger_drops_(0),
      keepalive_packets_(0),
      last_keepalive_mono_ns_(0),
      unverified_timeouts_(0) {
    initCommon();
}

SessionServer::SessionServer(Reactor& reactor,
                             const info::AirPlayConfig& config,
                             const pairing::Identity& identity,
                             pairing::PairingStore& store,
                             pairing::RandomSource& rng,
                             session::SessionListener& listener,
                             MediaEngine& media_engine,
                             session::AuthProvider* auth,
                             const SessionServerConfig& server_config)
    : reactor_(reactor),
      config_(config),
      identity_(identity),
      store_(store),
      rng_(rng),
      listener_(listener),
      media_(media_engine),
      media_engine_(&media_engine),
      auth_(auth),
      server_cfg_(server_config),
      control_accept_handler_(this),
      control_conn_handler_(this),
      event_accept_handler_(this),
      event_conn_handler_(this),
      timing_handler_(this),
      keepalive_handler_(this),
      timer_handler_(this),
      session_(NULL),
      in_session_call_(false),
      deferred_destroy_(false),
      control_read_paused_(false),
      clock_sync_(server_config.initial_ntp_offset_ns),
      ntp_timer_id_(Reactor::kNoTimer),
      unverified_timer_id_(Reactor::kNoTimer),
      has_saved_night_mode_(false),
      saved_night_mode_(false),
      rate_limited_accepts_(0),
      busy_rejected_accepts_(0),
      event_rejected_peers_(0),
      timing_stranger_drops_(0),
      keepalive_packets_(0),
      last_keepalive_mono_ns_(0),
      unverified_timeouts_(0) {
    initCommon();
    media_engine_->setSyncedNtpCallback(&SessionServer::syncedNtpThunk, this);
    media_engine_->setCloseSessionCallback(&SessionServer::closeSessionThunk, this);
}

void SessionServer::initCommon() {
    control_listener_.setAcceptFilter(&SessionServer::controlAcceptFilter, this);
    event_listener_.setAcceptFilter(&SessionServer::eventAcceptFilter, this);
}

SessionServer::~SessionServer() {
    stop();
    if (media_engine_ != NULL) {
        // The engine may outlive this server: it must not keep calling into it.
        media_engine_->clearSessionCallbacks(this);
    }
}

uint64_t SessionServer::syncedNtpThunk(void* ctx) {
    const SessionServer* self = static_cast<const SessionServer*>(ctx);
    return self->syncedNtp();
}

void SessionServer::closeSessionThunk(void* ctx) {
    SessionServer* self = static_cast<SessionServer*>(ctx);
    self->closeActiveSession();
}

bool SessionServer::start() {
    if (control_listener_.isOpen()) {
        return true;
    }
    if (!control_listener_.listenAny(server_cfg_.control_port)) {
        return false;
    }
    if (!reactor_.add(control_listener_.handle(), &control_accept_handler_, kPollIn)) {
        control_listener_.close();
        return false;
    }
    return true;
}

bool SessionServer::start(const Address& bind_address) {
    if (control_listener_.isOpen()) {
        return true;
    }
    if (!control_listener_.listen(bind_address)) {
        return false;
    }
    if (!reactor_.add(control_listener_.handle(), &control_accept_handler_, kPollIn)) {
        control_listener_.close();
        return false;
    }
    return true;
}

void SessionServer::stop() {
    closeActiveSession();
    unregisterAndClose(reactor_, control_listener_);
}

bool SessionServer::controlAcceptFilter(void* ctx, const Address& peer) {
    SessionServer* self = static_cast<SessionServer*>(ctx);
    const int64_t now_ms = self->reactor_.now() / 1000000LL;

    // 1. Sliding-window rate limit check.
    if (self->server_cfg_.max_accepts_per_window > 0 &&
        self->server_cfg_.accept_window_ms > 0) {
        const int64_t cutoff = now_ms - self->server_cfg_.accept_window_ms;
        size_t keep_from = 0;
        while (keep_from < self->accept_timestamps_ms_.size() &&
               self->accept_timestamps_ms_[keep_from] <= cutoff) {
            keep_from += 1;
        }
        if (keep_from > 0) {
            self->accept_timestamps_ms_.erase(
                self->accept_timestamps_ms_.begin(),
                self->accept_timestamps_ms_.begin() + static_cast<ptrdiff_t>(keep_from));
        }
        if (self->accept_timestamps_ms_.size() >= self->server_cfg_.max_accepts_per_window) {
            self->rate_limited_accepts_ += 1;
            return false;
        }
    }

    // 2. Single-active-session policy.
    if (self->session_ != NULL && self->session_->closed()) {
        // Closed behind the server's back (Session::close() called directly) and not reaped yet:
        // reap it now, otherwise accept() would adopt over a still-registered control socket and
        // the old Session object would leak.
        self->closeActiveSession();
    }
    if (self->session_ != NULL && !self->session_->closed()) {
        if (self->session_->encrypted()) {
            if (!self->server_cfg_.replace_verified_from_same_host ||
                !peer.sameHost(self->control_conn_.peerAddress())) {
                self->busy_rejected_accepts_ += 1;
                return false;
            }
        } else {
            if (!self->server_cfg_.replace_unverified_session) {
                self->busy_rejected_accepts_ += 1;
                return false;
            }
        }
        // Allowed to replace the existing session: close it now so control_conn_ is free.
        self->closeActiveSession();
    }

    if (self->server_cfg_.max_accepts_per_window > 0 &&
        self->server_cfg_.accept_window_ms > 0) {
        self->accept_timestamps_ms_.push_back(now_ms);
    }
    return true;
}

bool SessionServer::eventAcceptFilter(void* ctx, const Address& peer) {
    SessionServer* self = static_cast<SessionServer*>(ctx);
    if (self->session_ == NULL ||
        self->session_->closed() ||
        !self->session_->eventExpected() ||
        self->event_conn_.isOpen() ||
        !self->control_conn_.isOpen()) {
        self->event_rejected_peers_ += 1;
        return false;
    }
    if (!peer.sameHost(self->control_conn_.peerAddress())) {
        self->event_rejected_peers_ += 1;
        return false;
    }
    return true;
}

void SessionServer::onControlAcceptReadable() {
    for (int n = 0; n < kMaxAcceptsPerWakeup; ++n) {
        TcpListener::AcceptResult ar = control_listener_.accept(control_conn_);
        if (ar == TcpListener::kRejected) {
            continue;
        }
        if (ar != TcpListener::kAccepted) {
            break;
        }

        control_conn_.setNoDelay(true);
        control_conn_.setKeepAlive(true);
        control_conn_.setWriteQueueLimit(server_cfg_.control_write_queue_limit);
        control_read_paused_ = false;

        if (media_engine_ != NULL) {
            media_engine_->setControlPeer(control_conn_.peerAddress());
        }

        session_ = new session::Session(config_,
                                        identity_,
                                        store_,
                                        rng_,
                                        listener_,
                                        media_,
                                        *this,
                                        auth_,
                                        server_cfg_.session_policy);
        if (has_saved_night_mode_) {
            std::vector<uint8_t> unused_wire;
            session_->setNightMode(saved_night_mode_, unused_wire);
        }

        if (!reactor_.add(control_conn_.handle(), &control_conn_handler_, kPollIn)) {
            closeActiveSession();
            break;
        }

        if (server_cfg_.unverified_timeout_ms > 0) {
            unverified_timer_id_ =
                reactor_.startTimer(server_cfg_.unverified_timeout_ms, 0, &timer_handler_);
        }
        break;
    }
}

void SessionServer::onControlConnReadable() {
    if (session_ == NULL || !control_conn_.isOpen()) {
        return;
    }
    uint8_t buf[16 * 1024];
    for (int n = 0; n < kMaxTcpReadsPerWakeup; ++n) {
        if (control_read_paused_) {
            break;
        }
        size_t got = 0;
        IoStatus st = control_conn_.read(buf, sizeof(buf), got);
        if (st == kIoOk && got > 0) {
            std::vector<uint8_t> out;
            in_session_call_ = true;
            const bool ok = session_->onControlBytes(buf, got, out);
            in_session_call_ = false;

            if (session_ != NULL &&
                session_->encrypted() &&
                unverified_timer_id_ != Reactor::kNoTimer) {
                reactor_.cancelTimer(unverified_timer_id_);
                unverified_timer_id_ = Reactor::kNoTimer;
            }

            if (ok && !out.empty() && control_conn_.isOpen()) {
                if (!sendOnControl(out)) {
                    closeActiveSession();
                    return;
                }
            }

            if (!ok || deferred_destroy_ || session_ == NULL || session_->closed()) {
                closeActiveSession();
                return;
            }
            continue;
        }
        if (st == kIoWouldBlock) {
            break;
        }
        // Peer EOF (kIoClosed) or socket error (kIoError).
        closeActiveSession();
        return;
    }
}

void SessionServer::onControlConnWritable() {
    if (!control_conn_.isOpen()) {
        return;
    }
    IoStatus st = control_conn_.flush();
    if (st == kIoError) {
        closeActiveSession();
        return;
    }
    updateControlInterest();
}

void SessionServer::onControlConnError() {
    closeActiveSession();
}

bool SessionServer::sendOnControl(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) {
        return true;
    }
    if (!control_conn_.isOpen()) {
        return false;
    }
    TcpConnection::SendResult sr = control_conn_.send(bytes);
    if (sr != TcpConnection::kSendOk) {
        return false;
    }
    updateControlInterest();
    return true;
}

void SessionServer::updateControlInterest() {
    if (!control_conn_.isOpen()) {
        return;
    }
    const size_t queued = control_conn_.queuedBytes();
    if (server_cfg_.control_read_pause_watermark > 0 &&
        queued >= server_cfg_.control_read_pause_watermark) {
        control_read_paused_ = true;
    } else if (control_read_paused_ &&
               queued < server_cfg_.control_read_pause_watermark) {
        control_read_paused_ = false;
    }

    unsigned interest = 0;
    if (!control_read_paused_) {
        interest |= kPollIn;
    }
    if (control_conn_.wantsWrite()) {
        interest |= kPollOut;
    }
    if (interest == 0) {
        interest = kPollIn;
    }
    reactor_.modify(control_conn_.handle(), interest);
}

// =============================================================================================
// TransportHost: Timing / Event / Keep-Alive
// =============================================================================================

bool SessionServer::openTiming(int32_t peer_timing_port, int32_t& local_port_out) {
    if (ntp_timer_id_ != Reactor::kNoTimer) {
        reactor_.cancelTimer(ntp_timer_id_);
        ntp_timer_id_ = Reactor::kNoTimer;
    }
    if (!timing_sock_.isOpen()) {
        if (!timing_sock_.openAny(0)) {
            return false;
        }
        if (!reactor_.add(timing_sock_.handle(), &timing_handler_, kPollIn)) {
            timing_sock_.close();
            return false;
        }
    }
    clock_sync_ = ntp::ClockSync(server_cfg_.initial_ntp_offset_ns);
    timing_peer_ = Address();

    if (peer_timing_port > 0 && peer_timing_port <= 65535 && control_conn_.isOpen()) {
        timing_peer_ = control_conn_.peerAddress();
        timing_peer_.setPort(static_cast<uint16_t>(peer_timing_port));
        sendTimingRequest();
        if (server_cfg_.ntp_request_interval_ms > 0) {
            ntp_timer_id_ = reactor_.startTimer(server_cfg_.ntp_request_interval_ms,
                                                server_cfg_.ntp_request_interval_ms,
                                                &timer_handler_);
        }
    }

    local_port_out = static_cast<int32_t>(timing_sock_.port());
    return true;
}

bool SessionServer::sendTimingRequest() {
    if (!timing_sock_.isOpen() || !timing_peer_.valid() || timing_peer_.port() == 0) {
        return false;
    }
    uint8_t pkt[ntp::kPacketBytes];
    clock_sync_.makeRequest(reactor_.now(), pkt);
    return timing_sock_.sendTo(pkt, sizeof(pkt), timing_peer_) == kIoOk;
}

void SessionServer::onTimingReadable() {
    uint8_t buf[512];
    for (int n = 0; n < kMaxDatagramsPerWakeup; ++n) {
        size_t got = 0;
        Address from;
        IoStatus st = timing_sock_.receiveFrom(buf, sizeof(buf), got, from);
        if (st == kIoWouldBlock) {
            break;
        }
        if (st != kIoOk && st != kIoTruncated) {
            break;
        }
        if (got < ntp::kPacketBytes) {
            continue;
        }
        if (!control_conn_.isOpen() || !from.sameHost(control_conn_.peerAddress())) {
            timing_stranger_drops_ += 1;
            continue;
        }
        uint8_t reply[ntp::kPacketBytes];
        bool has_reply = false;
        clock_sync_.onPacket(buf, got, reactor_.now(), reply, has_reply);
        if (has_reply) {
            timing_sock_.sendTo(reply, sizeof(reply), from);
        }
    }
}

bool SessionServer::openEvent(int32_t& local_port_out) {
    if (!event_listener_.isOpen()) {
        if (!event_listener_.listenAny(0)) {
            return false;
        }
        if (!reactor_.add(event_listener_.handle(), &event_accept_handler_, kPollIn)) {
            event_listener_.close();
            return false;
        }
    }
    local_port_out = static_cast<int32_t>(event_listener_.port());
    return true;
}

void SessionServer::onEventAcceptReadable() {
    for (int n = 0; n < kMaxAcceptsPerWakeup; ++n) {
        TcpListener::AcceptResult ar = event_listener_.accept(event_conn_);
        if (ar == TcpListener::kRejected) {
            continue;
        }
        if (ar != TcpListener::kAccepted) {
            break;
        }
        if (session_ == NULL || session_->closed()) {
            event_conn_.close();
            break;
        }

        event_conn_.setLingerZero();
        event_conn_.setNoDelay(true);
        event_conn_.setWriteQueueLimit(server_cfg_.event_write_queue_limit);

        std::vector<uint8_t> wire_out;
        in_session_call_ = true;
        const bool accepted_ok = session_->onEventAccepted(wire_out);
        in_session_call_ = false;

        if (!accepted_ok) {
            event_conn_.close();
            if (deferred_destroy_ || session_ == NULL || session_->closed()) {
                closeActiveSession();
            }
            break;
        }

        if (!reactor_.add(event_conn_.handle(), &event_conn_handler_, kPollIn)) {
            event_conn_.close();
            closeActiveSession();
            break;
        }

        if (!wire_out.empty()) {
            if (!sendOnEvent(wire_out)) {
                closeActiveSession();
                return;
            }
        }
        break;
    }
}

void SessionServer::onEventConnReadable() {
    if (session_ == NULL || !event_conn_.isOpen()) {
        return;
    }
    uint8_t buf[16 * 1024];
    for (int n = 0; n < kMaxTcpReadsPerWakeup; ++n) {
        size_t got = 0;
        IoStatus st = event_conn_.read(buf, sizeof(buf), got);
        if (st == kIoOk && got > 0) {
            std::vector<uint8_t> wire_out;
            in_session_call_ = true;
            const bool ok = session_->onEventBytes(buf, got, wire_out);
            in_session_call_ = false;

            if (ok && !wire_out.empty() && event_conn_.isOpen()) {
                if (!sendOnEvent(wire_out)) {
                    closeActiveSession();
                    return;
                }
            }
            if (!ok || deferred_destroy_ || session_ == NULL || session_->closed()) {
                closeActiveSession();
                return;
            }
            continue;
        }
        if (st == kIoWouldBlock) {
            break;
        }
        // Like AirPlaySession.kt runEventRead's finally block: event EOF/error closes the session.
        if (session_ != NULL && !session_->closed()) {
            in_session_call_ = true;
            session_->onEventDisconnected();
            in_session_call_ = false;
        }
        closeActiveSession();
        return;
    }
}

void SessionServer::onEventConnWritable() {
    if (!event_conn_.isOpen()) {
        return;
    }
    IoStatus st = event_conn_.flush();
    if (st == kIoError) {
        closeActiveSession();
        return;
    }
    updateEventInterest();
}

void SessionServer::onEventConnError() {
    closeActiveSession();
}

bool SessionServer::sendOnEvent(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) {
        return true;
    }
    if (!event_conn_.isOpen()) {
        return false;
    }
    TcpConnection::SendResult sr = event_conn_.send(bytes);
    if (sr != TcpConnection::kSendOk) {
        return false;
    }
    updateEventInterest();
    return true;
}

void SessionServer::updateEventInterest() {
    if (!event_conn_.isOpen()) {
        return;
    }
    unsigned interest = kPollIn;
    if (event_conn_.wantsWrite()) {
        interest |= kPollOut;
    }
    reactor_.modify(event_conn_.handle(), interest);
}

bool SessionServer::openKeepAlive(int32_t& local_port_out) {
    if (!keepalive_sock_.isOpen()) {
        if (!keepalive_sock_.openAny(0)) {
            return false;
        }
        if (!reactor_.add(keepalive_sock_.handle(), &keepalive_handler_, kPollIn)) {
            keepalive_sock_.close();
            return false;
        }
    }
    local_port_out = static_cast<int32_t>(keepalive_sock_.port());
    return true;
}

void SessionServer::onKeepAliveReadable() {
    uint8_t buf[512];
    for (int n = 0; n < kMaxDatagramsPerWakeup; ++n) {
        size_t got = 0;
        Address from;
        IoStatus st = keepalive_sock_.receiveFrom(buf, sizeof(buf), got, from);
        if (st == kIoWouldBlock) {
            break;
        }
        if (st != kIoOk && st != kIoTruncated) {
            break;
        }
        if (control_conn_.isOpen() && from.sameHost(control_conn_.peerAddress())) {
            keepalive_packets_ += 1;
            last_keepalive_mono_ns_ = reactor_.now();
        }
    }
}

void SessionServer::closeSetupPorts() {
    if (ntp_timer_id_ != Reactor::kNoTimer) {
        reactor_.cancelTimer(ntp_timer_id_);
        ntp_timer_id_ = Reactor::kNoTimer;
    }
    unregisterAndClose(reactor_, timing_sock_);
    timing_peer_ = Address();
    unregisterAndClose(reactor_, keepalive_sock_);
    unregisterAndClose(reactor_, event_listener_);
}

void SessionServer::closeAll() {
    closeSetupPorts();
    unregisterAndClose(reactor_, event_conn_);
}

void SessionServer::onServerTimer(uint32_t timer_id) {
    if (timer_id == ntp_timer_id_) {
        sendTimingRequest();
        return;
    }
    if (timer_id == unverified_timer_id_) {
        unverified_timer_id_ = Reactor::kNoTimer;
        if (session_ != NULL && !session_->closed() && !session_->encrypted()) {
            unverified_timeouts_ += 1;
            closeActiveSession();
        }
        return;
    }
}

void SessionServer::closeActiveSession() {
    if (unverified_timer_id_ != Reactor::kNoTimer) {
        reactor_.cancelTimer(unverified_timer_id_);
        unverified_timer_id_ = Reactor::kNoTimer;
    }
    if (session_ != NULL) {
        if (!session_->closed()) {
            const bool prev_in_call = in_session_call_;
            in_session_call_ = true;
            session_->close();
            in_session_call_ = prev_in_call;
        }
        if (in_session_call_) {
            deferred_destroy_ = true;
            return;
        }
    }
    destroySessionIfNeeded();
}

void SessionServer::destroySessionIfNeeded() {
    deferred_destroy_ = false;
    closeAll();
    unregisterAndClose(reactor_, control_conn_);
    control_read_paused_ = false;
    if (media_engine_ != NULL) {
        media_engine_->setControlPeer(Address());
    }
    if (session_ != NULL) {
        session::Session* old = session_;
        session_ = NULL;
        delete old;
    }
}

// =============================================================================================
// Outbound EventChannel helpers
// =============================================================================================

bool SessionServer::sendHidReport(uint32_t uid, const std::vector<uint8_t>& report) {
    if (session_ == NULL || session_->closed() || !event_conn_.isOpen()) {
        return false;
    }
    std::vector<uint8_t> wire;
    if (!session_->events().sendHidReport(uid, report, wire)) {
        if (!session_->events().ready()) {
            closeActiveSession();
        }
        return false;
    }
    if (!sendOnEvent(wire)) {
        closeActiveSession();
        return false;
    }
    return true;
}

bool SessionServer::sendHidReports(uint32_t uid, const hid::ReportSequence& reports) {
    if (session_ == NULL || session_->closed() || !event_conn_.isOpen()) {
        return false;
    }
    std::vector<uint8_t> wire;
    const bool ok = session_->events().sendReportSequence(uid, reports, wire);
    if (!wire.empty()) {
        if (!sendOnEvent(wire)) {
            closeActiveSession();
            return false;
        }
    }
    if (!ok && !session_->events().ready()) {
        closeActiveSession();
    }
    return ok;
}

bool SessionServer::requestSiri() {
    if (session_ == NULL || session_->closed() || !event_conn_.isOpen()) {
        return false;
    }
    std::vector<uint8_t> wire;
    if (!session_->events().requestSiri(wire)) {
        if (!session_->events().ready()) {
            closeActiveSession();
        }
        return false;
    }
    if (!sendOnEvent(wire)) {
        closeActiveSession();
        return false;
    }
    return true;
}

bool SessionServer::setNightMode(bool night) {
    has_saved_night_mode_ = true;
    saved_night_mode_ = night;
    if (session_ == NULL || session_->closed()) {
        return false;
    }
    std::vector<uint8_t> wire;
    const bool sent_now = session_->setNightMode(night, wire);
    if (sent_now && !wire.empty()) {
        if (!sendOnEvent(wire)) {
            closeActiveSession();
            return false;
        }
        return true;
    }
    return false;
}

bool SessionServer::sendIapMessage(const std::vector<uint8_t>& data) {
    if (session_ == NULL || session_->closed() || !event_conn_.isOpen()) {
        return false;
    }
    std::vector<uint8_t> wire;
    if (!session_->events().sendIapMessage(data, wire)) {
        if (!session_->events().ready()) {
            closeActiveSession();
        }
        return false;
    }
    if (!sendOnEvent(wire)) {
        closeActiveSession();
        return false;
    }
    return true;
}

bool SessionServer::sendEventCommand(const bplist::Value& command,
                                     const rtsp::HeaderList* extra_headers) {
    if (session_ == NULL || session_->closed() || !event_conn_.isOpen()) {
        return false;
    }
    std::vector<uint8_t> wire;
    if (!session_->events().sendCommand(command, wire, extra_headers)) {
        if (!session_->events().ready()) {
            closeActiveSession();
        }
        return false;
    }
    if (!sendOnEvent(wire)) {
        closeActiveSession();
        return false;
    }
    return true;
}

bool SessionServer::requestKeyFrame(int32_t screen_type) {
    if (session_ == NULL || session_->closed() || !event_conn_.isOpen()) {
        return false;
    }
    std::vector<uint8_t> wire;
    bool ok = false;
    if (screen_type == 111) {
        bplist::Value params = bplist::Value::makeDict();
        params.set("uuid", bplist::Value::makeString(kAltScreenUuid));
        ok = session_->events().sendTypedCommand("forceKeyFrame", &params, wire);
    } else {
        ok = session_->events().sendTypedCommand("forceKeyFrame", NULL, wire);
    }
    if (!ok) {
        if (!session_->events().ready()) {
            closeActiveSession();
        }
        return false;
    }
    if (!sendOnEvent(wire)) {
        closeActiveSession();
        return false;
    }
    return true;
}

}  // namespace platform
}  // namespace carplay
