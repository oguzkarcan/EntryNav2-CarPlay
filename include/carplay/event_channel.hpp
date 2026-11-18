#ifndef CARPLAY_EVENT_CHANNEL_HPP
#define CARPLAY_EVENT_CHANNEL_HPP

// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/airplay/AirPlaySession.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.
//
// Encrypted AirPlay/CarPlay EVENT channel endpoint (accessory side), sans-I/O.
//
// After the session SETUP the accessory advertises an `eventPort`; the iPhone connects to it and the
// accessory then SENDS RTSP requests (`POST /command` with a binary-plist body) on that connection:
// HID reports, Siri, night mode, iAP2 tunnel messages, ... The iPhone answers each with a response and
// may itself send requests, which are answered with a plain 200.
//
// Port of DiPlay AirPlaySession.kt: sendCommandLocked (324-345), sendHidReport (441-448), invokeSiri
// (387-390), setNightMode + sendPendingNightModeLocked (427-439), sendIapMessage (392-398, timeout
// variant out of scope), acceptEvent key derivation (890-902) and runEventRead (918-967).
//
// Wire bytes of one command BEFORE encryption (exactly as sendCommandLocked):
//
//   POST /command RTSP/1.0\r\n
//   [extra headers, in order]\r\n
//   Content-Type: application/x-apple-binary-plist\r\n
//   Content-Length: <body bytes>\r\n
//   CSeq: <n>\r\n
//   \r\n
//   <bplist00 body>
//
// n starts at 1 and increments once per command that reaches the encoder (like the reference's
// eventCseq it is NOT reset by start()/close(): a re-accepted event connection continues the count).
// The whole message is then ControlCipher-encrypted (one or more frames).
//
// Keys: pairing::deriveEventKeys(shared) -> read = "Events-Read-Encryption-Key", write =
// "Events-Write-Encryption-Key" (salt "Events-Salt"), NOT swapped like the control channel.
//
// No sockets, threads or clocks: every send/receive appends the bytes to write to `wire_out`; the
// caller writes them to the event TCP socket. Not thread-safe (the platform layer serialises access,
// which replaces the reference's eventWriteLock). Non-copyable; key material is wiped on close().

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "carplay/airplay_crypto.hpp"
#include "carplay/airplay_hid.hpp"
#include "carplay/bplist_codec.hpp"
#include "carplay/control_cipher.hpp"
#include "carplay/rtsp_message.hpp"

namespace carplay {
namespace session {

class EventChannel {
public:
    EventChannel();
    ~EventChannel();

    /// Derives the event keys from the pair-verify shared secret and (re)creates the cipher and the
    /// inbound parser. Does NOT flush a pending night mode (call flushPendingNightMode(), as the
    /// session does in onEventAccepted). Returns false (channel not ready) on NULL input or KDF failure.
    bool start(const uint8_t shared_secret[crypto::kKeyBytes]);

    /// True between a successful start() and close() / a fatal cipher or parser error.
    bool ready() const { return cipher_.get() != NULL; }

    /// Drops the cipher (keys wiped) and any buffered inbound bytes. Keeps the CSeq counter and a
    /// pending night mode. Idempotent.
    void close();

    // ---- Outbound commands (each APPENDS encrypted bytes to wire_out; false = nothing appended) ----

    /// Generic command: bplist-encodes `command` and sends it as POST /command. `extra_headers` are
    /// emitted first, in order (the reference passes "X-Apple-StreamID: <id>" here). Returns false when
    /// not ready, on a bplist encode failure, or if encryption fails (the channel then closes itself;
    /// the reference closes the whole session in that case, see Session::events()).
    bool sendCommand(const bplist::Value& command,
                     std::vector<uint8_t>& wire_out,
                     const rtsp::HeaderList* extra_headers = NULL);

    /// {type: <type>, params: <params>} (params omitted when NULL), e.g. "forceKeyFrame", "requestUI",
    /// "changeModes". Reference recovery command for the main screen is {type:"forceKeyFrame"}.
    bool sendTypedCommand(const std::string& type,
                          const bplist::Value* params,
                          std::vector<uint8_t>& wire_out);

    /// {type:"hidSendReport", uuid: hid::uidString(uid), hidReport: <report data>} in that key order.
    bool sendHidReport(uint32_t uid, const std::vector<uint8_t>& report, std::vector<uint8_t>& wire_out);

    /// One hidSendReport per element, in order (hid::momentaryKnobReports, mediaPressReports, ...).
    /// Like the reference senders it keeps going after a failed element; returns true only if every
    /// element was sent (an empty sequence returns true).
    bool sendReportSequence(uint32_t uid, const hid::ReportSequence& reports, std::vector<uint8_t>& wire_out);

    /// invokeSiri(): {type:"requestSiri", params:{siriAction:2}} then the same with siriAction 3.
    /// Returns true only if both were sent.
    bool requestSiri(std::vector<uint8_t>& wire_out);

    /// setNightMode(): stores the value as pending, then tries to send
    /// {type:"setNightMode", params:{nightMode:<bool>}}; the pending value is cleared only when sent.
    /// A newer call replaces an unsent older value. Returns whether it was sent now.
    bool setNightMode(bool night, std::vector<uint8_t>& wire_out);

    /// sendPendingNightModeLocked(): true when nothing is pending or the pending value was sent.
    bool flushPendingNightMode(std::vector<uint8_t>& wire_out);
    bool hasPendingNightMode() const { return has_pending_night_; }

    /// sendIapMessage(data) (timeout 0): {type:"iAPSendMessage", params:{data:<data>}}.
    bool sendIapMessage(const std::vector<uint8_t>& data, std::vector<uint8_t>& wire_out);

    // ---- Inbound ----

    /// Feeds bytes read from the event socket (any split). Decrypts, parses, and for every complete
    /// message: a response (status line "RTSP/..." / "HTTP/...") is consumed silently (counted, status
    /// remembered); a request from the phone is answered with an encrypted "200 OK" echoing its CSeq
    /// (appended to wire_out) and, if requests_out is non-NULL, appended there. Returns false (and
    /// closes the channel) when not ready, on an authentication failure or an RTSP framing violation;
    /// the caller then closes the connection (the session closes itself, like runEventRead).
    bool onBytes(const uint8_t* data,
                 size_t len,
                 std::vector<uint8_t>& wire_out,
                 std::vector<rtsp::Request>* requests_out = NULL);

    /// CSeq of the most recently encoded command (0 before the first).
    uint32_t lastCseq() const { return cseq_; }
    /// Number of responses the phone sent back (consumed silently).
    uint64_t responsesReceived() const { return responses_received_; }
    /// Status code of the last response (0 if none or unparseable).
    int lastResponseStatus() const { return last_response_status_; }
    /// Number of requests from the phone answered with 200.
    uint64_t requestsAnswered() const { return requests_answered_; }

private:
    EventChannel(const EventChannel&) = delete;
    EventChannel& operator=(const EventChannel&) = delete;

    std::unique_ptr<ControlCipher> cipher_;
    rtsp::Parser parser_;
    uint32_t cseq_;
    bool has_pending_night_;
    bool pending_night_;
    uint64_t responses_received_;
    int last_response_status_;
    uint64_t requests_answered_;
};

}  // namespace session
}  // namespace carplay

#endif  // CARPLAY_EVENT_CHANNEL_HPP
