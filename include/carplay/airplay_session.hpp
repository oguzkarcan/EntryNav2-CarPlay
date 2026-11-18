#ifndef CARPLAY_AIRPLAY_SESSION_HPP
#define CARPLAY_AIRPLAY_SESSION_HPP

// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/airplay/AirPlaySession.kt,
//  shared/src/main/java/com/shilapi/xcertplay/airplay/CarPlayMediaEngine.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.
//
// One CarPlay AirPlay CONTROL connection (accessory side) as a pure, sans-I/O state machine.
// Port of DiPlay AirPlaySession.kt (runControl / handle / handleSetup / handleStreams / handleCommand /
// handleTeardown / acceptEvent / close) with the socket, thread and clock work delegated to abstract
// interfaces (TransportHost, MediaHandler) implemented by the platform layer and by the tests.
//
// Data flow:
//   control socket bytes --> onControlBytes(data, len, out) --> `out` = bytes to write back
//   event socket accepted --> onEventAccepted(out)              (starts the encrypted event channel)
//   event socket bytes    --> onEventBytes(data, len, out)
//   HID / Siri / night mode / iAP --> events().sendXxx(..., out) (out = bytes for the event socket)
//
// ---------------------------------------------------------------------------------------------
// Plaintext -> encrypted transition (runControl, AirPlaySession.kt:450-536)
//
// Before pair-verify succeeds the control connection is plaintext RTSP. The response to the pair-verify
// M3 (i.e. the M4 TLV) is written IN PLAINTEXT; immediately after it has been produced the session
// creates ControlCipher(read, write) from PairVerify::controlKeys() (read = "Control-Write-Encryption-
// Key", write = "Control-Read-Encryption-Key"). From then on every inbound byte is decrypted first and
// every response is encrypted. Each response is encrypted according to the cipher state at the moment
// it is produced.
//
// Where exactly the switch happens in the INPUT stream: in this implementation the cipher takes over at
// the first byte that follows the request whose response enabled it, independent of how the input was
// chunked. (While plaintext, input is parsed one byte at a time so the session always knows that
// boundary.) Consequently byte-by-byte delivery, arbitrary splits and one big chunk all give identical
// output. runControl behaves identically whenever the M3 request ends a socket read, which is always
// the case for a real iPhone (it waits for M4 before it can derive its keys and send anything
// encrypted). It differs only for a peer that puts bytes after M3 in the SAME read: runControl parses
// those as further PLAINTEXT requests (and encrypts their responses), whereas here they are decrypted.
// A legitimate peer never does that; treating them as ciphertext removes the chunking dependence.
// ---------------------------------------------------------------------------------------------
//
// Not thread-safe; the platform layer serialises calls (control reader, event reader and HID senders).
// Callbacks are invoked synchronously from inside these calls and may call close() re-entrantly; they
// must not throw (handler failures are signalled by return values and become a 500 response, which is
// the reference's catch block).

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "carplay/airplay_crypto.hpp"
#include "carplay/airplay_info.hpp"
#include "carplay/bplist_codec.hpp"
#include "carplay/control_cipher.hpp"
#include "carplay/event_channel.hpp"
#include "carplay/pairing.hpp"
#include "carplay/rtsp_message.hpp"

namespace carplay {
namespace session {

class Session;

/// Identity the phone reports in the session SETUP (AirPlayDeviceInfo). wifi_mac is lowercased.
struct DeviceInfo {
    std::string name;
    std::string device_id;
    std::string wifi_mac;
    std::string model;
};

/// Session lifecycle and command callbacks (AirPlaySessionListener). All default to no-ops.
/// Out of scope (not modelled): onTcpAccepted, onVideoFrameRendered, onCornerMask, onTransportError,
/// onRemoteControlMessage, onVideoPlaybackUiRequested, cluster callbacks.
class SessionListener {
public:
    virtual ~SessionListener() {}
    /// RECORD received.
    virtual void onSessionActive(Session& /*session*/) {}
    /// Exactly once, from close().
    virtual void onSessionEnded(Session& /*session*/) {}
    /// Session SETUP carried a non-empty name, deviceID or macAddress.
    virtual void onDeviceInfo(Session& /*session*/, const DeviceInfo& /*info*/) {}
    /// Inbound POST /command {type:"requestUI"}.
    virtual void onHostUiRequested(Session& /*session*/) {}
    /// Every inbound POST /command except X-Apple-StreamID remote-control messages; params is the
    /// command's `params` dict (empty dict when absent or not a dict).
    virtual void onCommand(Session& /*session*/, const std::string& /*type*/, const bplist::Value& /*params*/) {}
    virtual void onDebugLog(const std::string& /*message*/) {}
};

/// Media stream seam (AirPlayMediaHandler). Every `stream` argument is the SETUP `streams[]` entry
/// (a dict, untrusted: implementations must type-check every field). Defaults decline / do nothing.
/// A MediaHandler derives its stream keys through the Session helpers (streamOutputKey, ...).
class MediaHandler {
public:
    virtual ~MediaHandler() {}
    /// Type 110 (main) / 111 (alt) screen. Return true and the local TCP data port to accept.
    virtual bool onScreen(Session& /*session*/, int32_t /*type*/, const bplist::Value& /*stream*/,
                          int32_t& /*data_port_out*/) {
        return false;
    }
    /// Types 100/101/102. Return true and the response entry (reference: {type, dataPort, controlPort,
    /// streamConnectionID}) to accept.
    virtual bool onAudio(Session& /*session*/, int32_t /*type*/, const bplist::Value& /*stream*/,
                         bplist::Value& /*response_out*/) {
        return false;
    }
    /// Type 130 (iAP2 tunnel: {type:130, streamID:1, dataPort, [streamConnectionID]}).
    virtual bool onDataStream(Session& /*session*/, const bplist::Value& /*stream*/, bplist::Value& /*response_out*/) {
        return false;
    }
    /// Type 103 main buffered audio; only offered when config.bufferedAudioOutputEnabled().
    virtual bool onBufferedAudio(Session& /*session*/, const bplist::Value& /*stream*/, bplist::Value& /*response_out*/) {
        return false;
    }
    /// SETRATE / SETRATEANCHORTIME / GETANCHOR / FLUSHBUFFERED (only when buffered audio is enabled).
    /// `body` is the decoded dict. Return true + a plist to answer with it, false for an empty 200.
    virtual bool onBufferedAudioControl(Session& /*session*/, const std::string& /*method*/,
                                        const bplist::Value& /*body*/, bplist::Value& /*response_out*/) {
        return false;
    }
    /// POST /feedback. Return true + plist body, or false for an empty 200.
    virtual bool onFeedback(Session& /*session*/, bplist::Value& /*response_out*/) { return false; }
    /// One call per active stream type removed by TEARDOWN. For a whole-session TEARDOWN every call is
    /// made BEFORE the active set is cleared (reference order, AirPlaySession.kt handleTeardown), so
    /// Session::hasActiveStream() still reports the streams being torn down; for a per-type TEARDOWN the
    /// type has already been removed when its call runs (also the reference order).
    virtual void onTeardown(Session& /*session*/, int32_t /*type*/) {}
    /// duckAudio (true) / unduckAudio (false).
    virtual void onAudioDuck(Session& /*session*/, bool /*ducked*/) {}
    /// After every onControlBytes() call that produced at least one response (notifySetupResponseSent;
    /// the reference calls it after flushing each read's responses). The bytes are in `out` when this
    /// runs; the platform writes them right after the call returns.
    virtual void onSetupResponseSent(Session& /*session*/) {}
    /// From close(), before TransportHost::closeAll().
    virtual void onSessionClosed(Session& /*session*/) {}
};

/// Replaces the sockets the reference opens inside handleSetup (NTP timing UDP, event TCP server,
/// keep-alive UDP). The session only needs the local port numbers for the SETUP response.
///
/// REPEATED SETUP: every session SETUP (a SETUP without `streams`) calls openTiming, openEvent and, if
/// asked for, openKeepAlive again, on the same TransportHost. Implementations MUST be idempotent: either
/// reuse the already open socket (returning the same port) or close it and open a replacement; they
/// must never leak the earlier socket. (The reference throws "NtpClock is already running" on a second
/// SETUP and leaks its event server; neither behaviour is wanted here.)
///
/// FAILED SETUP: when openTiming, openEvent or openKeepAlive returns false, the session calls
/// closeSetupPorts() before answering 500, so a timing socket opened earlier in the same SETUP does not
/// leak.
class TransportHost {
public:
    virtual ~TransportHost() {}
    /// Open the local NTP timing socket; if peer_timing_port > 0 also start querying the phone's
    /// timing port (reference openTiming: ntp.listen() + ntp.start(peer, port)). peer_timing_port is
    /// 0 when absent or outside 1..65535. false -> SETUP answered with 500.
    virtual bool openTiming(int32_t peer_timing_port, int32_t& local_port_out) = 0;
    /// Open the event TCP server. The socket layer must accept only the control peer's address
    /// (reference acceptFrom(expected), AirPlaySession.kt:876), only while Session::eventExpected(),
    /// and then call Session::onEventAccepted.
    virtual bool openEvent(int32_t& local_port_out) = 0;
    /// Open the keep-alive UDP socket (only when the phone asked for keepAliveLowPower).
    virtual bool openKeepAlive(int32_t& local_port_out) = 0;
    /// Close the timing / event-server / keep-alive sockets after a failed session SETUP. The default
    /// closes everything (closeAll()); override to keep an already accepted event connection open.
    virtual void closeSetupPorts() { closeAll(); }
    /// Close every socket opened above (from Session::close(); may also run from closeSetupPorts(), so
    /// it must tolerate being called more than once).
    virtual void closeAll() = 0;
};

/// Phase 5 seam for MFi / BAA authentication (/auth-setup).
///
/// /auth-setup is currently ALWAYS answered with 400: without a provider exactly like the reference
/// (mfi == null), and WITH a provider too, because the MFiSAP responder (X25519 + SHA-1/SHA-256 +
/// AES-128-CTR, DiPlay MfiSapAuthSetup.kt) is deferred to Phase 5. The provider is stored but not yet
/// called.
class AuthProvider {
public:
    virtual ~AuthProvider() {}
    virtual bool getCertificate(std::vector<uint8_t>& out) = 0;
    virtual bool signChallenge(const uint8_t* data, size_t len, std::vector<uint8_t>& signature_out) = 0;
};

/// Hardening knobs beyond the reference.
struct SessionPolicy {
    /// When true (default) every request arriving before the control channel is encrypted (i.e. before
    /// pair-verify succeeded) is refused with "403 Forbidden" and has NO side effects, except the
    /// routes /pair-setup, /pair-verify, /auth-setup, /info and /fp-setup (the last only ever gets the
    /// reference's empty 200). SETUP / SET_PARAMETER / RECORD / TEARDOWN / buffered-audio methods are
    /// refused regardless of their path. When false the session answers everything like the reference.
    bool require_verified_for_session_requests;
    /// At most this many `streams[]` entries are examined per SETUP; later ones are ignored.
    size_t max_streams_per_setup;
    /// Budget of requests handled on this connection BEFORE pair-verify succeeds (every request counts,
    /// whatever its route or answer, including the pair-verify M3 that enables encryption). The request
    /// that would exceed it is not answered and the session closes (onControlBytes returns false).
    /// Rationale: an unauthenticated peer could otherwise loop /info (~100x amplification) or pair-setup
    /// M1/M3 (tens of ms of SRP-6a each) forever on one connection. A normal bring-up needs 6 (1 /info
    /// + 3 pair-setup + 2 pair-verify). 0 = unlimited (reference behaviour). Default 32.
    size_t max_unverified_requests;
    /// When true (default) a /pair-setup or /pair-verify request arriving on an ENCRYPTED control
    /// connection is answered "403 Forbidden" and never reaches PairSetup / PairVerify. Without this,
    /// such a request (reference behaviour) resets PairVerify, wiping the verified shared secret that
    /// stream-key derivation and the event channel depend on. This default is NOT verified against a
    /// real iPhone; if an iPhone turns out to re-pair on an open connection, set it to false to restore
    /// the reference behaviour.
    bool refuse_pairing_after_verified;

    SessionPolicy()
        : require_verified_for_session_requests(true),
          max_streams_per_setup(32),
          max_unverified_requests(32),
          refuse_pairing_after_verified(true) {}
};

/// Status of the pre-verification refusal.
static const int kStatusForbidden = 403;

class Session {
public:
    /// All references (and auth, if non-NULL) must outlive the session.
    Session(const info::AirPlayConfig& config,
            const pairing::Identity& identity,
            pairing::PairingStore& store,
            pairing::RandomSource& rng,
            SessionListener& listener,
            MediaHandler& media,
            TransportHost& transport,
            AuthProvider* auth = NULL,
            const SessionPolicy& policy = SessionPolicy());

    /// Wipes key material WITHOUT invoking callbacks; call close() first for an orderly shutdown.
    ~Session();

    /// Feeds bytes read from the control socket (any split) and APPENDS the bytes to write back to
    /// `out`. Returns false when the connection must be closed: decrypt failure, RTSP framing violation
    /// (header > 16 KiB, body > 1 MiB, bad Content-Length), encryption failure, pre-verify request
    /// budget exceeded (SessionPolicy::max_unverified_requests), or the session is (or
    /// became, e.g. via a callback) closed. On false the session has been close()d; `out` may still hold
    /// responses produced earlier in the same call (the reference never flushes them; the caller may
    /// drop them).
    bool onControlBytes(const uint8_t* data, size_t len, std::vector<uint8_t>& out);

    /// Peer closed the control connection (EOF) or the platform wants to end it: same as close().
    void onControlDisconnected() { close(); }

    // ---- Event channel ----

    /// The phone connected to the event port (address already checked by the socket layer). Starts the
    /// event channel from the pair-verify shared secret and flushes a pending night mode into
    /// `wire_out`. Returns true when the channel is ready. On false the caller closes THIS event
    /// socket, drops `wire_out`, and checks closed() for the session:
    ///  - session closed (or no verified shared secret: the session closes, like acceptEvent);
    ///  - an event channel is already active: refused, the session AND the active channel are left
    ///    untouched (a second connection must not replace the first);
    ///  - flushing the pending night mode failed: the new event channel is closed again, the session
    ///    stays open (event-channel failures never take down the control connection by themselves; the
    ///    night mode stays pending and a later accept may retry).
    bool onEventAccepted(std::vector<uint8_t>& wire_out);
    /// True while the socket layer should accept an event connection: a session SETUP succeeded on this
    /// verified (encrypted) connection, the session is open and no event channel is active. The socket
    /// layer combines this with the reference's address rule (accept only the control peer's address);
    /// core knows no addresses.
    bool eventExpected() const;
    /// Bytes from the event socket. On failure (decrypt / framing) the session closes (runEventRead's
    /// finally block) and false is returned.
    bool onEventBytes(const uint8_t* data,
                      size_t len,
                      std::vector<uint8_t>& wire_out,
                      std::vector<rtsp::Request>* requests_out = NULL);
    /// The event socket hit EOF / an error: like the reference, the whole session closes.
    void onEventDisconnected() { close(); }
    EventChannel& events() { return events_; }
    const EventChannel& events() const { return events_; }
    /// Convenience for EventChannel::setNightMode (pending until the channel is ready).
    bool setNightMode(bool night, std::vector<uint8_t>& wire_out) { return events_.setNightMode(night, wire_out); }

    // ---- Lifecycle ----

    /// Idempotent: MediaHandler::onSessionClosed, TransportHost::closeAll, event channel closed, key
    /// material wiped, SessionListener::onSessionEnded exactly once.
    void close();
    bool closed() const { return closed_; }

    // ---- State ----

    /// Control channel encryption active (pair-verify completed on this connection).
    bool encrypted() const { return cipher_.get() != NULL; }
    /// Active stream types in first-SETUP order (the reference's LinkedHashSet).
    const std::vector<int32_t>& activeStreams() const { return active_streams_; }
    bool hasActiveStream(int32_t type) const;
    /// Last DeviceInfo reported by a session SETUP (empty fields before).
    const DeviceInfo& deviceInfo() const { return device_info_; }
    const info::AirPlayConfig& config() const { return config_; }
    const SessionPolicy& policy() const { return policy_; }
    /// A session SETUP (timing / event ports) has been answered with 200 on this connection.
    bool sessionSetupDone() const { return session_setup_done_; }
    /// Requests handled so far before pair-verify succeeded (see max_unverified_requests).
    size_t unverifiedRequests() const { return unverified_requests_; }

    // ---- Keys for the platform / media layers (all false unless pair-verify succeeded) ----

    /// The X25519 pair-verify shared secret (reference session.sharedSecret).
    bool sharedSecret(uint8_t out[crypto::kKeyBytes]) const;
    /// Verified controller pairing id (empty unless verified).
    const std::string& controllerId() const;

    /// HKDF-SHA512(shared, "DataStream-Salt" + decimal(id), info_label, 32).
    bool deriveStreamKey(uint64_t id, const std::string& info_label, uint8_t key_out[crypto::kKeyBytes]) const;
    /// Realtime audio: out = "DataStream-Output-Encryption-Key" (downlink), in =
    /// "DataStream-Input-Encryption-Key" (microphone uplink); either pointer may be NULL.
    bool deriveAudioStreamKeys(uint64_t stream_connection_id,
                               uint8_t* out_key,
                               uint8_t* in_key) const;
    /// Screen stream key (CarPlayMediaEngine.kt:135 onScreen -> outputKey 620-622 -> dataStreamKey
    /// 665-678): the DataStream OUTPUT key of the stream's streamConnectionID, i.e. the same recipe as
    /// the audio downlink key.
    bool deriveScreenStreamKey(uint64_t stream_connection_id, uint8_t key_out[crypto::kKeyBytes]) const;
    /// iAP2 data stream (type 130) key: DataStream OUTPUT key of the stream's `seed`
    /// (CarPlayMediaEngine.kt:383-395).
    bool deriveDataStreamSeedKey(uint64_t seed, uint8_t key_out[crypto::kKeyBytes]) const;

    /// Plist-dict convenience: reads `field` ("streamConnectionID" / "seed") from a SETUP stream entry
    /// via plistUnsignedId() and derives the OUTPUT (downlink) / INPUT (uplink) key.
    bool streamOutputKey(const bplist::Value& stream, uint8_t key_out[crypto::kKeyBytes],
                         const char* field = "streamConnectionID") const;
    bool streamInputKey(const bplist::Value& stream, uint8_t key_out[crypto::kKeyBytes],
                        const char* field = "streamConnectionID") const;

    /// unsignedPlistDecimal (CarPlayMediaEngine.kt:715-722): a non-negative integer as is, a NEGATIVE
    /// 64-bit integer reinterpreted as unsigned (Long.toUnsignedString), TYPE_UINT64 as is. Reals and
    /// non-numbers are rejected (the reference would truncate a real).
    static bool plistUnsignedId(const bplist::Value& v, uint64_t& out);

private:
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    enum Route {
        kRouteSetup,
        kRouteSetParameter,
        kRouteRecord,
        kRouteTeardown,
        kRouteBufferedAudio,
        kRoutePairSetup,
        kRoutePairVerify,
        kRouteAuthSetup,
        kRouteInfo,
        kRouteCommand,
        kRouteFeedback,
        kRouteDefault
    };

    Route routeOf(const rtsp::Request& request) const;
    bool allowedBeforeVerify(Route route, const rtsp::Request& request) const;
    /// Handles one request and appends its (possibly encrypted) response. false = fatal.
    bool processRequest(const rtsp::Request& request, std::vector<uint8_t>& out);
    /// false = internal failure (-> 500).
    bool handle(const rtsp::Request& request, rtsp::Response& response);
    bool handleSetup(const rtsp::Request& request, rtsp::Response& response);
    bool handleStreams(const bplist::Value::Array& streams, rtsp::Response& response);
    bool handleCommand(const rtsp::Request& request, rtsp::Response& response);
    bool handleTeardown(const rtsp::Request& request, rtsp::Response& response);
    bool handleBufferedAudio(const rtsp::Request& request, rtsp::Response& response);
    bool plistResponse(const bplist::Value& value, rtsp::Response& response);
    void addActiveStream(int32_t type);
    bool removeActiveStream(int32_t type);
    void debugLog(const std::string& message);

    const info::AirPlayConfig& config_;
    SessionListener& listener_;
    MediaHandler& media_;
    TransportHost& transport_;
    AuthProvider* auth_;
    SessionPolicy policy_;

    pairing::PairSetup pair_setup_;
    pairing::PairVerify pair_verify_;
    std::unique_ptr<ControlCipher> cipher_;
    rtsp::Parser parser_;
    EventChannel events_;
    std::vector<int32_t> active_streams_;
    DeviceInfo device_info_;
    bool closed_;
    bool session_setup_done_;
    size_t unverified_requests_;
    std::string empty_;
};

/// Port of teardownStreamTypes (AirPlaySession.kt:1037-1045). `body` may be NULL (undecodable).
/// whole_session_out = true when the body names no stream (no dict / no `streams` array / no entry
/// with a numeric `type`): every active stream is torn down. Otherwise types_out lists the named types
/// in order, minus type-130 entries whose numeric streamID is not 1 (video-in-car data streams).
void teardownStreamTypes(const bplist::Value* body, bool& whole_session_out, std::vector<int32_t>& types_out);

/// Kotlin `(value as? Number)?.toLong()` for plist numbers: TYPE_INT as is, TYPE_UINT64 reinterpreted
/// (low 64 bits), TYPE_REAL truncated toward zero with saturation (NaN -> 0). false for non-numbers.
bool plistNumberToLong(const bplist::Value& v, int64_t& out);
/// `...?.toInt()`: low 32 bits of plistNumberToLong.
bool plistNumberToInt(const bplist::Value& v, int32_t& out);

}  // namespace session
}  // namespace carplay

#endif  // CARPLAY_AIRPLAY_SESSION_HPP
