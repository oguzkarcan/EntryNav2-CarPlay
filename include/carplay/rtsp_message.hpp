#ifndef CARPLAY_RTSP_MESSAGE_HPP
#define CARPLAY_RTSP_MESSAGE_HPP

// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/airplay/RtspMessage.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.
//
// RTSP/HTTP-style message framing for the CarPlay control channel (TCP :7000)
// and the event channel. Port of DiPlay's RtspMessage.kt.
//
// Pure byte-in / byte-out: no sockets, threads or OS headers. Encryption
// (ControlCipher) wraps this framing in a separate layer.

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

namespace carplay {
namespace rtsp {

/// Reference caps (RtspMessage.kt): real headers are < 1 KiB; the largest
/// legitimate body is a corner-mask PNG inside a plist (~576 KiB).
static const size_t kMaxHeaderBytes = 16 * 1024;
static const size_t kMaxBodyBytes = 1024 * 1024;

extern const char* const kContentTypeBinaryPlist;  // "application/x-apple-binary-plist"
extern const char* const kContentTypePairingTlv8;  // "application/pairing+tlv8"
extern const char* const kContentTypeOctetStream;  // "application/octet-stream"

typedef std::pair<std::string, std::string> Header;
typedef std::vector<Header> HeaderList;

/// A parsed message. For requests: method/path/protocol come from the request
/// line. The event channel also carries responses on the same framing; those
/// parse with method = "RTSP/1.0" (or "HTTP/1.1"), path = status code, protocol =
/// reason phrase — see isResponse().
///
/// Header names are stored lowercased (ASCII) and trimmed, values trimmed, in
/// first-seen order. A repeated name keeps its first position but takes the
/// last value (the reference stores them in a HashMap: last wins).
struct Request {
    std::string method;
    std::string path;
    std::string protocol;
    HeaderList headers;
    std::vector<uint8_t> body;

    /// Case-insensitive lookup; returns NULL if absent.
    const std::string* findHeader(const std::string& name) const;

    /// Case-insensitive lookup; returns `fallback` if absent.
    std::string header(const std::string& name, const std::string& fallback = std::string()) const;

    bool hasHeader(const std::string& name) const { return findHeader(name) != NULL; }

    /// True if the first token starts with "RTSP/" or "HTTP/", i.e. this is a
    /// status line (response), not a request. The session skips these on the
    /// event channel.
    bool isResponse() const;
};

/// Free-function form of Request::isResponse().
bool isResponseLine(const Request& message);

/// Incremental parser. Feed it arbitrary chunks; every complete message is
/// appended to `out`. Results are independent of chunking (byte-by-byte,
/// arbitrary splits or pipelined messages in one buffer give identical output).
///
/// Framing: header block terminated by CRLFCRLF, lines split on CRLF, request
/// line split on single spaces into at most 3 parts (missing path -> "",
/// missing protocol -> "RTSP/1.0"), header lines without ':' ignored.
/// Content-Length: missing or not a decimal integer -> 0, negative -> 0,
/// larger than max_body_bytes -> protocol violation.
///
/// Memory is bounded: at most max_header_bytes + 4 header bytes plus one body
/// of at most max_body_bytes are buffered. Header-terminator search is
/// incremental (O(1) per byte).
class Parser {
public:
    explicit Parser(size_t max_header_bytes = kMaxHeaderBytes, size_t max_body_bytes = kMaxBodyBytes);

    /// Returns false on a protocol violation. The parser then stays failed and
    /// every later feed() returns false without producing messages, until reset().
    /// Messages completed before the violation inside the same call are still
    /// appended to `out`.
    bool feed(const uint8_t* data, size_t len, std::vector<Request>& out);
    bool feed(const std::vector<uint8_t>& data, std::vector<Request>& out);

    bool failed() const { return failed_; }
    const std::string& error() const { return error_; }

    /// Number of bytes of a partial message currently buffered.
    size_t bufferedBytes() const;

    /// Discards buffered data and clears the failed state.
    void reset();

private:
    enum State { kStateHeader, kStateBody };

    bool fail(const std::string& msg);
    bool finishHeader();

    size_t max_header_bytes_;
    size_t max_body_bytes_;
    State state_;
    std::vector<uint8_t> head_;  // header block bytes incl. trailing CRLFCRLF
    int match_;                  // CRLFCRLF matcher progress 0..4
    Request current_;
    size_t body_needed_;
    bool failed_;
    std::string error_;
};

/// Response description. Empty `protocol` echoes the request's protocol.
/// Empty `status_text` uses the table: 200 OK, 400 Bad Request, 404 Not Found,
/// 500 Internal Server Error, anything else "OK" (as the reference).
struct Response {
    std::string protocol;
    int status;
    std::string status_text;
    HeaderList headers;  // emitted in order
    std::vector<uint8_t> body;

    Response() : status(200) {}
    explicit Response(int s) : status(s) {}
};

/// Standard reason phrase for `status` (the reference table, default "OK").
const char* statusText(int status);

/// Serializes a response exactly like RtspMessage.buildResponse:
///   "<protocol> <status> <text>\r\n", response headers in order, then
///   "CSeq: <request cseq>" if the request carried one, then
///   "Content-Length: <body size>" (always, even 0), "\r\n", body.
/// If the response headers already contain CSeq (only when the request has a
/// CSeq) or Content-Length (matched case-insensitively), that entry's value is
/// replaced in place instead of being duplicated (LinkedHashMap semantics).
/// `out` is overwritten.
void buildResponse(const Request& request, const Response& response, std::vector<uint8_t>& out);

/// Serializes a request: "<method> <path> <protocol>\r\n", then `headers`
/// verbatim in the given order ("Name: value\r\n"), "\r\n", body.
///
/// Content-Length policy: if `headers` contains Content-Length (any case), its
/// value is replaced in place with body.size(); otherwise "Content-Length: N"
/// is appended after the given headers. To reproduce the reference's event
/// channel bytes (sendCommandLocked) pass, in order:
///   [X-Apple-StreamID (optional)], Content-Type, Content-Length (any value), CSeq.
/// `out` is overwritten.
void buildRequest(const std::string& method,
                  const std::string& path,
                  const std::string& protocol,
                  const HeaderList& headers,
                  const std::vector<uint8_t>& body,
                  std::vector<uint8_t>& out);

/// Decimal string for an unsigned / signed integer (GCC 4.7-safe std::to_string substitute).
std::string toDecimal(int64_t value);
std::string toDecimalUnsigned(uint64_t value);

}  // namespace rtsp
}  // namespace carplay

#endif  // CARPLAY_RTSP_MESSAGE_HPP
