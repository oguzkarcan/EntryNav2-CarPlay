// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/airplay/RtspMessage.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.

#include "carplay/rtsp_message.hpp"

#include <algorithm>

namespace carplay {
namespace rtsp {

const char* const kContentTypeBinaryPlist = "application/x-apple-binary-plist";
const char* const kContentTypePairingTlv8 = "application/pairing+tlv8";
const char* const kContentTypeOctetStream = "application/octet-stream";

namespace {

const char* const kDefaultProtocol = "RTSP/1.0";

char asciiLower(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

std::string toLowerAscii(const std::string& s) {
    std::string r(s);
    for (size_t i = 0; i < r.size(); ++i) {
        r[i] = asciiLower(r[i]);
    }
    return r;
}

bool equalsIgnoreCase(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (asciiLower(a[i]) != asciiLower(b[i])) return false;
    }
    return true;
}

// ASCII subset of Kotlin's Char.isWhitespace (Java Character.isWhitespace).
bool isTrimSpace(char c) {
    const unsigned char u = static_cast<unsigned char>(c);
    return u == ' ' || (u >= 0x09 && u <= 0x0d) || (u >= 0x1c && u <= 0x1f);
}

std::string trim(const std::string& s) {
    size_t b = 0;
    size_t e = s.size();
    while (b < e && isTrimSpace(s[b])) ++b;
    while (e > b && isTrimSpace(s[e - 1])) --e;
    return s.substr(b, e - b);
}

bool startsWith(const std::string& s, const char* prefix) {
    size_t i = 0;
    for (; prefix[i] != '\0'; ++i) {
        if (i >= s.size() || s[i] != prefix[i]) return false;
    }
    return true;
}

// Kotlin String.toIntOrNull()?.coerceAtLeast(0) ?: 0, except that a positive
// value too large for an Int is reported as "too large" instead of 0, so it is
// rejected by the body cap rather than silently treated as an empty body.
// Returns false when the value is positive and exceeds `limit`.
bool parseContentLength(const std::string& s, size_t limit, size_t& out) {
    out = 0;
    if (s.empty()) return true;
    size_t i = 0;
    bool negative = false;
    if (s[0] == '+' || s[0] == '-') {
        negative = (s[0] == '-');
        i = 1;
    }
    if (i >= s.size()) return true;  // sign only: unparseable -> 0
    uint64_t value = 0;
    bool overflow = false;
    for (size_t k = i; k < s.size(); ++k) {
        const char c = s[k];
        if (c < '0' || c > '9') return true;  // unparseable -> 0
        if (!overflow) {
            value = value * 10U + static_cast<uint64_t>(c - '0');
            if (value > static_cast<uint64_t>(limit)) overflow = true;
        }
    }
    if (negative) return true;  // negative -> 0
    if (overflow) return false;
    out = static_cast<size_t>(value);
    return true;
}

void appendString(std::vector<uint8_t>& out, const std::string& s) {
    out.insert(out.end(), s.begin(), s.end());
}

void appendHeader(std::vector<uint8_t>& out, const std::string& name, const std::string& value) {
    appendString(out, name);
    out.push_back(':');
    out.push_back(' ');
    appendString(out, value);
    out.push_back('\r');
    out.push_back('\n');
}

// Sets `name` to `value`: replaces the first case-insensitive match in place
// (dropping later duplicates), or appends it if absent.
void upsertHeader(HeaderList& headers, const std::string& name, const std::string& value) {
    bool found = false;
    HeaderList::iterator it = headers.begin();
    while (it != headers.end()) {
        if (equalsIgnoreCase(it->first, name)) {
            if (!found) {
                it->second = value;
                found = true;
                ++it;
            } else {
                it = headers.erase(it);
            }
        } else {
            ++it;
        }
    }
    if (!found) {
        headers.push_back(Header(name, value));
    }
}

}  // namespace

std::string toDecimalUnsigned(uint64_t value) {
    char buf[24];
    size_t n = 0;
    do {
        buf[n++] = static_cast<char>('0' + static_cast<int>(value % 10U));
        value /= 10U;
    } while (value != 0);
    std::string r;
    r.reserve(n);
    while (n > 0) r.push_back(buf[--n]);
    return r;
}

std::string toDecimal(int64_t value) {
    if (value >= 0) return toDecimalUnsigned(static_cast<uint64_t>(value));
    // Two's complement magnitude without overflowing on INT64_MIN.
    const uint64_t mag = static_cast<uint64_t>(-(value + 1)) + 1U;
    return "-" + toDecimalUnsigned(mag);
}

// ---------------------------------------------------------------- Request

const std::string* Request::findHeader(const std::string& name) const {
    const std::string key = toLowerAscii(trim(name));
    for (size_t i = 0; i < headers.size(); ++i) {
        if (equalsIgnoreCase(headers[i].first, key)) return &headers[i].second;
    }
    return NULL;
}

std::string Request::header(const std::string& name, const std::string& fallback) const {
    const std::string* v = findHeader(name);
    return v != NULL ? *v : fallback;
}

bool Request::isResponse() const {
    return startsWith(method, "RTSP/") || startsWith(method, "HTTP/");
}

bool isResponseLine(const Request& message) {
    return message.isResponse();
}

// ----------------------------------------------------------------- Parser

Parser::Parser(size_t max_header_bytes, size_t max_body_bytes)
    : max_header_bytes_(max_header_bytes),
      max_body_bytes_(max_body_bytes),
      state_(kStateHeader),
      match_(0),
      body_needed_(0),
      failed_(false) {}

void Parser::reset() {
    state_ = kStateHeader;
    head_.clear();
    match_ = 0;
    current_ = Request();
    body_needed_ = 0;
    failed_ = false;
    error_.clear();
}

size_t Parser::bufferedBytes() const {
    return state_ == kStateHeader ? head_.size() : current_.body.size();
}

bool Parser::fail(const std::string& msg) {
    failed_ = true;
    error_ = msg;
    head_.clear();
    std::vector<uint8_t>().swap(head_);
    current_ = Request();
    return false;
}

bool Parser::finishHeader() {
    // head_ ends with CRLFCRLF; the header text is everything before it.
    const std::string text(head_.begin(), head_.end() - 4);
    head_.clear();
    match_ = 0;

    // Split on CRLF (Kotlin split("\r\n") keeps empty segments).
    std::vector<std::string> lines;
    size_t pos = 0;
    for (;;) {
        const size_t crlf = text.find("\r\n", pos);
        if (crlf == std::string::npos) {
            lines.push_back(text.substr(pos));
            break;
        }
        lines.push_back(text.substr(pos, crlf - pos));
        pos = crlf + 2;
    }

    current_ = Request();
    // Request line: split(" ", limit = 3).
    const std::string& line0 = lines[0];
    const size_t sp1 = line0.find(' ');
    if (sp1 == std::string::npos) {
        current_.method = line0;
        current_.protocol = kDefaultProtocol;
    } else {
        current_.method = line0.substr(0, sp1);
        const size_t sp2 = line0.find(' ', sp1 + 1);
        if (sp2 == std::string::npos) {
            current_.path = line0.substr(sp1 + 1);
            current_.protocol = kDefaultProtocol;
        } else {
            current_.path = line0.substr(sp1 + 1, sp2 - sp1 - 1);
            current_.protocol = line0.substr(sp2 + 1);
        }
    }

    for (size_t i = 1; i < lines.size(); ++i) {
        const std::string& line = lines[i];
        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        const std::string name = toLowerAscii(trim(line.substr(0, colon)));
        const std::string value = trim(line.substr(colon + 1));
        bool replaced = false;
        for (size_t k = 0; k < current_.headers.size(); ++k) {
            if (current_.headers[k].first == name) {
                current_.headers[k].second = value;  // last wins
                replaced = true;
                break;
            }
        }
        if (!replaced) current_.headers.push_back(Header(name, value));
    }

    size_t content_length = 0;
    const std::string* cl = current_.findHeader("content-length");
    if (cl != NULL && !parseContentLength(*cl, max_body_bytes_, content_length)) {
        return fail("RTSP body of " + *cl + " bytes over " + toDecimalUnsigned(max_body_bytes_));
    }
    body_needed_ = content_length;
    current_.body.reserve(content_length);
    state_ = kStateBody;
    return true;
}

bool Parser::feed(const uint8_t* data, size_t len, std::vector<Request>& out) {
    if (failed_) return false;
    if (data == NULL && len > 0) return fail("null input");

    size_t i = 0;
    for (;;) {
        if (state_ == kStateBody) {
            const size_t n = std::min(body_needed_, len - i);
            if (n > 0) {
                current_.body.insert(current_.body.end(), data + i, data + i + n);
                i += n;
                body_needed_ -= n;
            }
            if (body_needed_ != 0) break;  // input exhausted mid-body
            out.push_back(Request());
            std::swap(out.back(), current_);
            current_ = Request();
            state_ = kStateHeader;
            continue;
        }
        if (i >= len) break;

        // Header state: incremental CRLFCRLF match, O(1) per byte.
        const uint8_t b = data[i++];
        head_.push_back(b);
        const uint8_t expected = (match_ % 2 == 0) ? '\r' : '\n';
        if (b == expected) {
            ++match_;
        } else {
            match_ = (b == '\r') ? 1 : 0;
        }
        if (match_ == 4) {
            if (!finishHeader()) return false;
        } else if (head_.size() >= max_header_bytes_ + 4) {
            // No terminator starting at an offset <= max_header_bytes.
            return fail("RTSP header over " + toDecimalUnsigned(max_header_bytes_) + " bytes");
        }
    }
    return true;
}

bool Parser::feed(const std::vector<uint8_t>& data, std::vector<Request>& out) {
    return feed(data.empty() ? NULL : &data[0], data.size(), out);
}

// --------------------------------------------------------------- Builders

const char* statusText(int status) {
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 500: return "Internal Server Error";
        default: return "OK";
    }
}

void buildResponse(const Request& request, const Response& response, std::vector<uint8_t>& out) {
    out.clear();
    const std::string& protocol = response.protocol.empty() ? request.protocol : response.protocol;
    const std::string text = response.status_text.empty() ? std::string(statusText(response.status))
                                                          : response.status_text;
    HeaderList headers(response.headers);
    const std::string* cseq = request.findHeader("cseq");
    if (cseq != NULL) upsertHeader(headers, "CSeq", *cseq);
    upsertHeader(headers, "Content-Length", toDecimalUnsigned(response.body.size()));

    appendString(out, protocol);
    out.push_back(' ');
    appendString(out, toDecimal(static_cast<int64_t>(response.status)));
    out.push_back(' ');
    appendString(out, text);
    out.push_back('\r');
    out.push_back('\n');
    for (size_t i = 0; i < headers.size(); ++i) {
        appendHeader(out, headers[i].first, headers[i].second);
    }
    out.push_back('\r');
    out.push_back('\n');
    out.insert(out.end(), response.body.begin(), response.body.end());
}

void buildRequest(const std::string& method,
                  const std::string& path,
                  const std::string& protocol,
                  const HeaderList& headers,
                  const std::vector<uint8_t>& body,
                  std::vector<uint8_t>& out) {
    out.clear();
    HeaderList h(headers);
    upsertHeader(h, "Content-Length", toDecimalUnsigned(body.size()));

    appendString(out, method);
    out.push_back(' ');
    appendString(out, path);
    out.push_back(' ');
    appendString(out, protocol);
    out.push_back('\r');
    out.push_back('\n');
    for (size_t i = 0; i < h.size(); ++i) {
        appendHeader(out, h[i].first, h[i].second);
    }
    out.push_back('\r');
    out.push_back('\n');
    out.insert(out.end(), body.begin(), body.end());
}

}  // namespace rtsp
}  // namespace carplay
