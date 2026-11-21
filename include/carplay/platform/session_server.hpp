#ifndef CARPLAY_PLATFORM_SESSION_SERVER_HPP
#define CARPLAY_PLATFORM_SESSION_SERVER_HPP

// Reactor-driven CarPlay AirPlay control server and TransportHost implementation.
//
// Owns:
//   * Control TCP listener (default :7000, or ephemeral 0 in tests) with accept-rate
//     limiting and single-active-session peer protection;
//   * Active control TcpConnection + session::Session with write-queue backpressure,
//     read-pause watermark, and pre-verification handshake timeout;
//   * Event TCP listener + connection (accepting ONLY from the active control peer's
//     host address while Session::eventExpected() is true);
//   * NTP timing UDP socket + periodic PT 210 sender + PT 210/211 handler (ignoring
//     off-session strangers);
//   * Low-power keep-alive UDP socket;
//   * Convenience outbound EventChannel helpers (HID reports, Siri, night mode, iAP2,
//     forceKeyFrame) that encrypt and flush/queue onto the event TCP socket.
//
// Threading and lifetime: reactor thread only, the destructor included. Session / media callbacks
// may call back into the server (closeActiveSession(), the outbound helpers): a close requested
// from inside a Session call is carried out when that call returns. The server must not be
// destroyed from inside one of its own callbacks. A MediaEngine passed to the convenience
// constructor may outlive the server (the destructor detaches from it).

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/airplay_hid.hpp"
#include "carplay/airplay_info.hpp"
#include "carplay/airplay_session.hpp"
#include "carplay/ntp_timing.hpp"
#include "carplay/pairing.hpp"
#include "carplay/platform/media_engine.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/tcp.hpp"
#include "carplay/platform/udp.hpp"

namespace carplay {
namespace platform {

struct SessionServerConfig {
    /// Control TCP port to listen on (7000 on vehicle, 0 = ephemeral in host tests).
    uint16_t control_port;
    /// Core Session hardening policy.
    session::SessionPolicy session_policy;
    /// Maximum queued outbound bytes on the control TCP socket before kSendOverflow closes it.
    size_t control_write_queue_limit;
    /// Maximum queued outbound bytes on the event TCP socket before kSendOverflow closes it.
    size_t event_write_queue_limit;
    /// When queued outbound control bytes reach this watermark, kPollIn is paused on the
    /// control socket until onWritable() drains the queue below the watermark.
    size_t control_read_pause_watermark;
    /// Maximum time (ms) allowed between TCP accept and completing pair-verify (encrypted()).
    /// 0 disables the timeout.
    int64_t unverified_timeout_ms;
    /// Interval (ms) between outbound NTP PT 210 timing requests once timing is started.
    /// <= 0 sends only the initial PT 210 request on SETUP (tests may also call sendTimingRequest()).
    int64_t ntp_request_interval_ms;
    /// Initial offset (ns) passed to ntp::ClockSync (wallClockNtpOffsetNs).
    int64_t initial_ntp_offset_ns;
    /// Sliding-window rate limit on control TCP accepts: at most `max_accepts_per_window`
    /// connections accepted within `accept_window_ms` (0 = unlimited).
    size_t max_accepts_per_window;
    int64_t accept_window_ms;
    /// When true (default), a new control connection arriving while the existing session is
    /// still unverified (!encrypted()) closes and replaces the unverified session.
    bool replace_unverified_session;
    /// When true, a new control connection from the SAME host replaces even a verified session.
    /// Connections from a DIFFERENT host while a verified session is active are always rejected.
    bool replace_verified_from_same_host;
    /// When true (wireless Wi-Fi AP sessions), mark accepted control/event TCP sockets with
    /// IP_TOS / IPV6_TCLASS = 0x80 (WMM AC_VI) as BMW's native CarPlay SocketSetQoS does.
    /// Leave false for wired USB (NCM/TAP) sessions.
    bool wifi_video_qos;

    SessionServerConfig()
        : control_port(7000),
          session_policy(),
          control_write_queue_limit(TcpConnection::kDefaultWriteQueueLimit),
          event_write_queue_limit(256U * 1024U),
          control_read_pause_watermark(512U * 1024U),
          unverified_timeout_ms(10000),
          ntp_request_interval_ms(1000),
          initial_ntp_offset_ns(0),
          max_accepts_per_window(16),
          accept_window_ms(1000),
          replace_unverified_session(true),
          replace_verified_from_same_host(false),
          wifi_video_qos(false) {}
};

class SessionServer : public session::TransportHost {
public:
    /// Constructor wiring an external MediaHandler.
    SessionServer(Reactor& reactor,
                  const info::AirPlayConfig& config,
                  const pairing::Identity& identity,
                  pairing::PairingStore& store,
                  pairing::RandomSource& rng,
                  session::SessionListener& listener,
                  session::MediaHandler& media,
                  session::AuthProvider* auth = NULL,
                  const SessionServerConfig& server_config = SessionServerConfig());

    /// Convenience constructor wiring a MediaEngine (automatically connects peer address,
    /// synced NTP clock, and stream-error session termination callbacks).
    SessionServer(Reactor& reactor,
                  const info::AirPlayConfig& config,
                  const pairing::Identity& identity,
                  pairing::PairingStore& store,
                  pairing::RandomSource& rng,
                  session::SessionListener& listener,
                  MediaEngine& media_engine,
                  session::AuthProvider* auth = NULL,
                  const SessionServerConfig& server_config = SessionServerConfig());

    virtual ~SessionServer();

    /// Binds the control TCP listener on dual-stack any-address (`server_config.control_port`).
    bool start();
    /// Binds the control TCP listener on a specific local address.
    bool start(const Address& bind_address);
    /// Closes the active session (if any) and the control listener.
    void stop();

    bool isListening() const { return control_listener_.isOpen(); }
    uint16_t controlPort() const { return control_listener_.port(); }

    bool hasActiveSession() const { return session_ != NULL && !session_->closed(); }
    /// Prefer closeActiveSession() over activeSession()->close(): the latter leaves the control
    /// socket and the Session object to be reaped by the next socket event or accept.
    session::Session* activeSession() { return session_; }
    const session::Session* activeSession() const { return session_; }
    const Address& controlPeerAddress() const { return control_conn_.peerAddress(); }
    /// Replaces the AirPlay/MFi auth provider before connectivity/sessions begin.
    void setAuthProvider(session::AuthProvider* auth) { auth_ = auth; }

    void closeActiveSession();

    /// Enables or disables Wi-Fi video QoS (IP_TOS / IPV6_TCLASS = 0x80) for subsequent
    /// control/event TCP accepts and delegates the setting to the attached MediaEngine.
    void setWifiVideoQos(bool enabled) {
        server_cfg_.wifi_video_qos = enabled;
        if (media_engine_ != NULL) {
            media_engine_->setWifiVideoQos(enabled);
        }
    }
    bool wifiVideoQos() const { return server_cfg_.wifi_video_qos; }

    // ---- session::TransportHost implementation ----
    virtual bool openTiming(int32_t peer_timing_port, int32_t& local_port_out);
    virtual bool openEvent(int32_t& local_port_out);
    virtual bool openKeepAlive(int32_t& local_port_out);
    virtual void closeSetupPorts();
    virtual void closeAll();

    // ---- Timing / ClockSync ----
    const ntp::ClockSync& clockSync() const { return clock_sync_; }
    uint64_t syncedNtp() const { return clock_sync_.syncedNtp(reactor_.now()); }
    /// Sends one PT 210 timing request immediately if the timing socket and peer port are open.
    bool sendTimingRequest();
    uint16_t timingPort() const { return timing_sock_.port(); }
    uint16_t eventPort() const { return event_listener_.port(); }
    uint16_t keepAlivePort() const { return keepalive_sock_.port(); }
    bool hasEventConnection() const { return event_conn_.isOpen(); }

    // ---- Outbound EventChannel commands (reactor thread) ----
    bool sendHidReport(uint32_t uid, const std::vector<uint8_t>& report);
    bool sendHidReports(uint32_t uid, const hid::ReportSequence& reports);
    bool requestSiri();
    /// Stores `night` and, if an event channel is active, sends `setNightMode` immediately;
    /// otherwise flushes automatically when the event connection is accepted.
    bool setNightMode(bool night);
    bool sendIapMessage(const std::vector<uint8_t>& data);
    bool sendEventCommand(const bplist::Value& command,
                          const rtsp::HeaderList* extra_headers = NULL);
    /// Sends `{type: "forceKeyFrame"}` (or with `params: {uuid: ALT_UUID}` for type 111).
    bool requestKeyFrame(int32_t screen_type = 110);

    // ---- Diagnostics / counters ----
    uint64_t rateLimitedAccepts() const { return rate_limited_accepts_; }
    uint64_t busyRejectedAccepts() const { return busy_rejected_accepts_; }
    uint64_t eventRejectedPeers() const { return event_rejected_peers_; }
    uint64_t timingStrangerDrops() const { return timing_stranger_drops_; }
    uint64_t keepAlivePacketsReceived() const { return keepalive_packets_; }
    int64_t lastKeepAliveMonoNanos() const { return last_keepalive_mono_ns_; }
    uint64_t unverifiedTimeouts() const { return unverified_timeouts_; }
    bool controlReadPaused() const { return control_read_paused_; }
    size_t controlQueuedBytes() const { return control_conn_.queuedBytes(); }
    size_t eventQueuedBytes() const { return event_conn_.queuedBytes(); }
    SocketHandle controlSocketHandle() const { return control_conn_.handle(); }
    SocketHandle eventSocketHandle() const { return event_conn_.handle(); }

private:
    SessionServer(const SessionServer&) = delete;
    SessionServer& operator=(const SessionServer&) = delete;

    struct ControlAcceptHandler : public IoHandler {
        SessionServer* server;
        explicit ControlAcceptHandler(SessionServer* s) : server(s) {}
        virtual void onReadable() { server->onControlAcceptReadable(); }
        virtual void onError() {}
    };

    struct ControlConnHandler : public IoHandler {
        SessionServer* server;
        explicit ControlConnHandler(SessionServer* s) : server(s) {}
        virtual void onReadable() { server->onControlConnReadable(); }
        virtual void onWritable() { server->onControlConnWritable(); }
        virtual void onError() { server->onControlConnError(); }
    };

    struct EventAcceptHandler : public IoHandler {
        SessionServer* server;
        explicit EventAcceptHandler(SessionServer* s) : server(s) {}
        virtual void onReadable() { server->onEventAcceptReadable(); }
        virtual void onError() {}
    };

    struct EventConnHandler : public IoHandler {
        SessionServer* server;
        explicit EventConnHandler(SessionServer* s) : server(s) {}
        virtual void onReadable() { server->onEventConnReadable(); }
        virtual void onWritable() { server->onEventConnWritable(); }
        virtual void onError() { server->onEventConnError(); }
    };

    struct TimingHandler : public IoHandler {
        SessionServer* server;
        explicit TimingHandler(SessionServer* s) : server(s) {}
        virtual void onReadable() { server->onTimingReadable(); }
        virtual void onError() {}
    };

    struct KeepAliveHandler : public IoHandler {
        SessionServer* server;
        explicit KeepAliveHandler(SessionServer* s) : server(s) {}
        virtual void onReadable() { server->onKeepAliveReadable(); }
        virtual void onError() {}
    };

    struct ServerTimerHandler : public TimerHandler {
        SessionServer* server;
        explicit ServerTimerHandler(SessionServer* s) : server(s) {}
        virtual void onTimer(uint32_t timer_id) { server->onServerTimer(timer_id); }
    };

    void initCommon();
    static bool controlAcceptFilter(void* ctx, const Address& peer);
    static bool eventAcceptFilter(void* ctx, const Address& peer);
    static uint64_t syncedNtpThunk(void* ctx);
    static void closeSessionThunk(void* ctx);

    void onControlAcceptReadable();
    void onControlConnReadable();
    void onControlConnWritable();
    void onControlConnError();

    void onEventAcceptReadable();
    void onEventConnReadable();
    void onEventConnWritable();
    void onEventConnError();

    void onTimingReadable();
    void onKeepAliveReadable();
    void onServerTimer(uint32_t timer_id);

    bool sendOnControl(const std::vector<uint8_t>& bytes);
    bool sendOnEvent(const std::vector<uint8_t>& bytes);
    void updateControlInterest();
    void updateEventInterest();
    void destroySessionIfNeeded();

    Reactor& reactor_;
    info::AirPlayConfig config_;
    const pairing::Identity& identity_;
    pairing::PairingStore& store_;
    pairing::RandomSource& rng_;
    session::SessionListener& listener_;
    session::MediaHandler& media_;
    MediaEngine* media_engine_;
    session::AuthProvider* auth_;
    SessionServerConfig server_cfg_;

    ControlAcceptHandler control_accept_handler_;
    ControlConnHandler control_conn_handler_;
    EventAcceptHandler event_accept_handler_;
    EventConnHandler event_conn_handler_;
    TimingHandler timing_handler_;
    KeepAliveHandler keepalive_handler_;
    ServerTimerHandler timer_handler_;

    TcpListener control_listener_;
    TcpConnection control_conn_;
    session::Session* session_;
    bool in_session_call_;
    bool deferred_destroy_;
    bool control_read_paused_;

    TcpListener event_listener_;
    TcpConnection event_conn_;

    UdpSocket timing_sock_;
    Address timing_peer_;
    ntp::ClockSync clock_sync_;
    uint32_t ntp_timer_id_;
    uint32_t unverified_timer_id_;

    UdpSocket keepalive_sock_;

    bool has_saved_night_mode_;
    bool saved_night_mode_;

    std::vector<int64_t> accept_timestamps_ms_;
    uint64_t rate_limited_accepts_;
    uint64_t busy_rejected_accepts_;
    uint64_t event_rejected_peers_;
    uint64_t timing_stranger_drops_;
    uint64_t keepalive_packets_;
    int64_t last_keepalive_mono_ns_;
    uint64_t unverified_timeouts_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_SESSION_SERVER_HPP
