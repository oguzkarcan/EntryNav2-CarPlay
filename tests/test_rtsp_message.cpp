// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/airplay/RtspMessage.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.
//
// Phase 2 P1: RTSP/HTTP message framing (port of DiPlay RtspMessage.kt).

#include "carplay/rtsp_message.hpp"
#include "test_support.hpp"

#include <algorithm>
#include <string>
#include <vector>

using carplay::rtsp::HeaderList;
using carplay::rtsp::Header;
using carplay::rtsp::Parser;
using carplay::rtsp::Request;
using carplay::rtsp::Response;

namespace {

std::vector<uint8_t> bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::string str(const std::vector<uint8_t>& v) {
    return std::string(v.begin(), v.end());
}

bool parseAll(const std::vector<uint8_t>& data, std::vector<Request>& out) {
    Parser p;
    return p.feed(data, out);
}

bool sameRequest(const Request& a, const Request& b) {
    return a.method == b.method && a.path == b.path && a.protocol == b.protocol &&
           a.headers == b.headers && a.body == b.body;
}

std::vector<uint8_t> binaryBody() {
    std::vector<uint8_t> b;
    for (int i = 0; i < 300; ++i) b.push_back(static_cast<uint8_t>((i * 7) & 0xff));
    return b;
}

std::vector<uint8_t> sampleStream() {
    std::vector<uint8_t> s = bytes(
        "POST /pair-verify RTSP/1.0\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: 300\r\n"
        "CSeq: 1\r\n\r\n");
    const std::vector<uint8_t> b = binaryBody();
    s.insert(s.end(), b.begin(), b.end());
    const std::vector<uint8_t> t = bytes(
        "GET /info RTSP/1.0\r\nCSeq: 2\r\n\r\n"
        "SET_PARAMETER rtsp://x RTSP/1.0\r\nContent-Length: 6\r\nCSeq: 3\r\n\r\n"
        "\r\n\r\n\0\x01");
    s.insert(s.end(), t.begin(), t.end());
    s.push_back(0);
    s.push_back(1);
    return s;
}

}  // namespace

TEST_CASE(singleRequestWithBinaryBody) {
    std::vector<uint8_t> data = bytes(
        "POST /pair-setup RTSP/1.0\r\nContent-Type: application/pairing+tlv8\r\n"
        "Content-Length: 300\r\nCSeq: 7\r\n\r\n");
    const std::vector<uint8_t> body = binaryBody();
    data.insert(data.end(), body.begin(), body.end());
    std::vector<Request> out;
    REQUIRE(parseAll(data, out));
    REQUIRE(out.size() == 1U);
    CHECK_EQ(std::string("POST"), out[0].method);
    CHECK_EQ(std::string("/pair-setup"), out[0].path);
    CHECK_EQ(std::string("RTSP/1.0"), out[0].protocol);
    CHECK_EQ(std::string("7"), out[0].header("cseq"));
    CHECK_EQ(std::string(carplay::rtsp::kContentTypePairingTlv8), out[0].header("Content-Type"));
    CHECK_BYTES_EQ(body, out[0].body);
    CHECK(!out[0].isResponse());
}

TEST_CASE(byteByByteEqualsWholeBuffer) {
    const std::vector<uint8_t> data = sampleStream();
    std::vector<Request> whole;
    REQUIRE(parseAll(data, whole));
    REQUIRE(whole.size() == 3U);
    CHECK_EQ(std::string("SET_PARAMETER"), whole[2].method);
    CHECK_EQ(std::string("rtsp://x"), whole[2].path);
    CHECK_EQ(6U, whole[2].body.size());

    Parser p;
    std::vector<Request> bb;
    for (size_t i = 0; i < data.size(); ++i) {
        REQUIRE(p.feed(&data[i], 1, bb));
    }
    CHECK_EQ(0U, p.bufferedBytes());
    REQUIRE(bb.size() == whole.size());
    for (size_t i = 0; i < whole.size(); ++i) CHECK(sameRequest(whole[i], bb[i]));

    // Several arbitrary chunkings.
    const size_t chunks[] = {2, 3, 5, 13, 64, 333};
    for (size_t c = 0; c < sizeof(chunks) / sizeof(chunks[0]); ++c) {
        Parser q;
        std::vector<Request> got;
        for (size_t off = 0; off < data.size(); off += chunks[c]) {
            const size_t n = std::min(chunks[c], data.size() - off);
            REQUIRE(q.feed(&data[off], n, got));
        }
        REQUIRE(got.size() == whole.size());
        for (size_t i = 0; i < whole.size(); ++i) CHECK(sameRequest(whole[i], got[i]));
    }
}

TEST_CASE(pipelinedPlusPartialThird) {
    const std::string a = "GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n";
    const std::string b = "POST /feedback RTSP/1.0\r\nCSeq: 2\r\nContent-Length: 3\r\n\r\nabc";
    const std::string c = "TEARDOWN rtsp://h/1 RTSP/1.0\r\nCSeq: 3\r\nContent-Length: 4\r\n\r\nwxyz";
    const std::string first = a + b + c.substr(0, 20);
    Parser p;
    std::vector<Request> out;
    REQUIRE(p.feed(bytes(first), out));
    REQUIRE(out.size() == 2U);
    CHECK_EQ(std::string("/info"), out[0].path);
    CHECK_EQ(std::string("abc"), str(out[1].body));
    CHECK_EQ(20U, p.bufferedBytes());

    // Header completes but body still partial.
    const std::string mid = c.substr(20, c.size() - 22);
    REQUIRE(p.feed(bytes(mid), out));
    CHECK_EQ(2U, out.size());

    REQUIRE(p.feed(bytes(c.substr(c.size() - 2)), out));
    REQUIRE(out.size() == 3U);
    CHECK_EQ(std::string("TEARDOWN"), out[2].method);
    CHECK_EQ(std::string("3"), out[2].header("CSEQ"));
    CHECK_EQ(std::string("wxyz"), str(out[2].body));
    CHECK_EQ(0U, p.bufferedBytes());
}

TEST_CASE(headerCaseInsensitivityAndTrimming) {
    std::vector<Request> out;
    REQUIRE(parseAll(bytes("OPTIONS * RTSP/1.0\r\n"
                           "  X-Apple-ProtocolVersion :   1  \r\n"
                           "\tCSeq:\t42\t\r\n"
                           "NoColonLineIgnored\r\n"
                           "Empty:\r\n"
                           "dup: one\r\n"
                           "DUP: two\r\n"
                           "Content-Length: 0\r\n\r\n"),
                     out));
    REQUIRE(out.size() == 1U);
    const Request& r = out[0];
    CHECK_EQ(std::string("1"), r.header("x-apple-protocolversion"));
    CHECK_EQ(std::string("1"), r.header("X-APPLE-PROTOCOLVERSION"));
    CHECK_EQ(std::string("42"), r.header("cseq"));
    CHECK(r.hasHeader("empty"));
    CHECK_EQ(std::string(""), r.header("empty", "fallback"));
    CHECK_EQ(std::string("fallback"), r.header("missing", "fallback"));
    CHECK(r.findHeader("NoColonLineIgnored") == NULL);
    CHECK_EQ(std::string("two"), r.header("dup"));  // last wins
    REQUIRE(r.headers.size() == 5U);
    CHECK_EQ(std::string("x-apple-protocolversion"), r.headers[0].first);
    CHECK_EQ(std::string("cseq"), r.headers[1].first);
    CHECK_EQ(std::string("dup"), r.headers[3].first);
}

TEST_CASE(missingContentLengthMeansEmptyBody) {
    std::vector<Request> out;
    REQUIRE(parseAll(bytes("GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\nGET /x RTSP/1.0\r\n\r\n"), out));
    REQUIRE(out.size() == 2U);
    CHECK(out[0].body.empty());
    CHECK_EQ(std::string("/x"), out[1].path);
}

TEST_CASE(bodyWithCrlfCrlfAndNuls) {
    std::string body("a\r\n\r\nGET / RTSP/1.0\r\n\r\n", 24);
    body.push_back('\0');
    body.push_back('\0');
    body.push_back('z');
    const std::string msg = "POST /audio RTSP/1.0\r\nContent-Length: " +
                            carplay::rtsp::toDecimalUnsigned(body.size()) + "\r\n\r\n" + body;
    Parser p;
    std::vector<Request> out;
    const std::vector<uint8_t> data = bytes(msg);
    for (size_t i = 0; i < data.size(); ++i) REQUIRE(p.feed(&data[i], 1, out));
    REQUIRE(out.size() == 1U);
    CHECK_EQ(body, str(out[0].body));
    CHECK_EQ(27U, out[0].body.size());
}

TEST_CASE(headerOverLimitWithoutTerminatorFails) {
    Parser p;
    std::vector<Request> out;
    std::string big = "GET / RTSP/1.0\r\nX-Pad: ";
    big.append(16 * 1024, 'a');
    REQUIRE(p.feed(bytes(big), out) == false);
    CHECK(p.failed());
    CHECK(!p.error().empty());
    CHECK(out.empty());
    CHECK_EQ(0U, p.bufferedBytes());

    // Byte-by-byte fails at the same point, never buffering more than limit + 4.
    Parser q;
    const std::vector<uint8_t> data = bytes(big);
    size_t i = 0;
    for (; i < data.size(); ++i) {
        CHECK(q.bufferedBytes() < 16U * 1024U + 4U);
        if (!q.feed(&data[i], 1, out)) break;
    }
    CHECK_EQ(16U * 1024U + 3U, i);
    CHECK(q.failed());

    // Exactly the limit (header text == 16 KiB) is still accepted.
    std::string ok = "GET / RTSP/1.0\r\nX: ";
    ok.append(16 * 1024 - ok.size(), 'b');
    ok += "\r\n\r\n";
    Parser r;
    REQUIRE(r.feed(bytes(ok), out));
    CHECK_EQ(1U, out.size());

    // A configurable smaller limit.
    Parser s(32, 1024);
    std::vector<Request> out2;
    CHECK(!s.feed(bytes("GET /0123456789012345678901234567890123 RTSP/1.0\r\n\r\n"), out2));
}

TEST_CASE(contentLengthOverLimitFails) {
    Parser p;
    std::vector<Request> out;
    CHECK(!p.feed(bytes("POST / RTSP/1.0\r\nContent-Length: 1048577\r\n\r\n"), out));
    CHECK(p.failed());
    CHECK(out.empty());

    Parser q;
    CHECK(!q.feed(bytes("POST / RTSP/1.0\r\nContent-Length: 99999999999999999999999\r\n\r\n"), out));

    // Exactly 1 MiB is allowed (waits for the body).
    Parser r;
    CHECK(r.feed(bytes("POST / RTSP/1.0\r\nContent-Length: 1048576\r\n\r\n"), out));
    CHECK(!r.failed());
    CHECK(out.empty());

    // Messages completed earlier in the same feed are still delivered.
    Parser s;
    std::vector<Request> out2;
    CHECK(!s.feed(bytes("GET /a RTSP/1.0\r\n\r\nPOST / RTSP/1.0\r\nContent-Length: 2000000\r\n\r\n"), out2));
    CHECK_EQ(1U, out2.size());
}

TEST_CASE(garbageOrNegativeContentLengthIsZero) {
    const char* values[] = {"abc", "-5", "12x", "", "+", "-", " ", "-99999999999999999999", "1.5"};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        std::vector<Request> out;
        const std::string msg = std::string("POST /x RTSP/1.0\r\nContent-Length: ") + values[i] +
                                "\r\n\r\nGET /next RTSP/1.0\r\n\r\n";
        REQUIRE(parseAll(bytes(msg), out));
        REQUIRE(out.size() == 2U);
        CHECK(out[0].body.empty());
        CHECK_EQ(std::string("/next"), out[1].path);
    }
    std::vector<Request> out;
    REQUIRE(parseAll(bytes("POST /x RTSP/1.0\r\nContent-Length: +3\r\n\r\nabc"), out));
    REQUIRE(out.size() == 1U);
    CHECK_EQ(std::string("abc"), str(out[0].body));
}

TEST_CASE(requestLineVariants) {
    std::vector<Request> out;
    REQUIRE(parseAll(bytes("GET /info\r\n\r\nFLUSH\r\n\r\nX a b c d\r\n\r\n\r\n\r\n"), out));
    REQUIRE(out.size() == 4U);
    CHECK_EQ(std::string("GET"), out[0].method);
    CHECK_EQ(std::string("/info"), out[0].path);
    CHECK_EQ(std::string("RTSP/1.0"), out[0].protocol);
    CHECK_EQ(std::string("FLUSH"), out[1].method);
    CHECK_EQ(std::string(""), out[1].path);
    CHECK_EQ(std::string("RTSP/1.0"), out[1].protocol);
    CHECK_EQ(std::string("b c d"), out[2].protocol);  // limit = 3
    CHECK_EQ(std::string(""), out[3].method);         // empty header block, as reference
}

TEST_CASE(responseLineDetection) {
    std::vector<Request> out;
    REQUIRE(parseAll(bytes("RTSP/1.0 200 OK\r\nCSeq: 5\r\nContent-Length: 0\r\n\r\n"
                           "HTTP/1.1 404 Not Found\r\n\r\n"
                           "POST /command RTSP/1.0\r\n\r\n"),
                     out));
    REQUIRE(out.size() == 3U);
    CHECK(out[0].isResponse());
    CHECK(carplay::rtsp::isResponseLine(out[0]));
    CHECK_EQ(std::string("200"), out[0].path);
    CHECK_EQ(std::string("OK"), out[0].protocol);
    CHECK(out[1].isResponse());
    CHECK(!out[2].isResponse());
    CHECK(!carplay::rtsp::isResponseLine(out[2]));
}

TEST_CASE(buildResponseExactBytes) {
    std::vector<Request> reqs;
    REQUIRE(parseAll(bytes("GET /info RTSP/1.0\r\nCSeq: 9\r\n\r\n"
                           "GET /x HTTP/1.1\r\n\r\n"),
                     reqs));
    REQUIRE(reqs.size() == 2U);
    std::vector<uint8_t> out;

    Response ok;
    ok.headers.push_back(Header("Content-Type", carplay::rtsp::kContentTypeBinaryPlist));
    ok.headers.push_back(Header("Server", "AirTunes/320.17"));
    ok.body = bytes("xyz");
    carplay::rtsp::buildResponse(reqs[0], ok, out);
    CHECK_EQ(std::string("RTSP/1.0 200 OK\r\n"
                         "Content-Type: application/x-apple-binary-plist\r\n"
                         "Server: AirTunes/320.17\r\n"
                         "CSeq: 9\r\n"
                         "Content-Length: 3\r\n\r\nxyz"),
             str(out));

    carplay::rtsp::buildResponse(reqs[0], Response(400), out);
    CHECK_EQ(std::string("RTSP/1.0 400 Bad Request\r\nCSeq: 9\r\nContent-Length: 0\r\n\r\n"), str(out));
    carplay::rtsp::buildResponse(reqs[0], Response(404), out);
    CHECK_EQ(std::string("RTSP/1.0 404 Not Found\r\nCSeq: 9\r\nContent-Length: 0\r\n\r\n"), str(out));
    carplay::rtsp::buildResponse(reqs[0], Response(500), out);
    CHECK_EQ(std::string("RTSP/1.0 500 Internal Server Error\r\nCSeq: 9\r\nContent-Length: 0\r\n\r\n"),
             str(out));
    carplay::rtsp::buildResponse(reqs[0], Response(470), out);
    CHECK_EQ(std::string("RTSP/1.0 470 OK\r\nCSeq: 9\r\nContent-Length: 0\r\n\r\n"), str(out));

    // Protocol echo (HTTP/1.1, no CSeq) and explicit override.
    carplay::rtsp::buildResponse(reqs[1], Response(), out);
    CHECK_EQ(std::string("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), str(out));
    Response custom(453);
    custom.protocol = "RTSP/1.0";
    custom.status_text = "Not Enough Bandwidth";
    carplay::rtsp::buildResponse(reqs[1], custom, out);
    CHECK_EQ(std::string("RTSP/1.0 453 Not Enough Bandwidth\r\nContent-Length: 0\r\n\r\n"), str(out));

    // Pre-existing CSeq / Content-Length are overridden in place, not duplicated.
    Response dup;
    dup.headers.push_back(Header("Content-Length", "999"));
    dup.headers.push_back(Header("A", "1"));
    dup.headers.push_back(Header("CSeq", "1"));
    carplay::rtsp::buildResponse(reqs[0], dup, out);
    CHECK_EQ(std::string("RTSP/1.0 200 OK\r\nContent-Length: 0\r\nA: 1\r\nCSeq: 9\r\n\r\n"), str(out));
}

TEST_CASE(buildRequestMatchesReferenceCommand) {
    const std::vector<uint8_t> body = bytes(std::string("bplist00\0\x01\r\n\r\n", 14));
    HeaderList h;
    h.push_back(Header("X-Apple-StreamID", "12345"));
    h.push_back(Header("Content-Type", carplay::rtsp::kContentTypeBinaryPlist));
    h.push_back(Header("Content-Length", ""));  // value is filled in
    h.push_back(Header("CSeq", "4"));
    std::vector<uint8_t> out;
    carplay::rtsp::buildRequest("POST", "/command", "RTSP/1.0", h, body, out);
    std::vector<uint8_t> expected = bytes(
        "POST /command RTSP/1.0\r\n"
        "X-Apple-StreamID: 12345\r\n"
        "Content-Type: application/x-apple-binary-plist\r\n"
        "Content-Length: 14\r\n"
        "CSeq: 4\r\n\r\n");
    expected.insert(expected.end(), body.begin(), body.end());
    CHECK_BYTES_EQ(expected, out);

    // Without a Content-Length entry it is appended last.
    HeaderList h2;
    h2.push_back(Header("CSeq", "1"));
    carplay::rtsp::buildRequest("GET", "/info", "RTSP/1.0", h2, std::vector<uint8_t>(), out);
    CHECK_EQ(std::string("GET /info RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n"), str(out));

    // Round trip.
    carplay::rtsp::buildRequest("POST", "/command", "RTSP/1.0", h, body, out);
    std::vector<Request> parsed;
    REQUIRE(parseAll(out, parsed));
    REQUIRE(parsed.size() == 1U);
    CHECK_EQ(std::string("POST"), parsed[0].method);
    CHECK_EQ(std::string("/command"), parsed[0].path);
    CHECK_EQ(std::string("RTSP/1.0"), parsed[0].protocol);
    CHECK_EQ(std::string("12345"), parsed[0].header("x-apple-streamid"));
    CHECK_EQ(std::string("4"), parsed[0].header("CSeq"));
    CHECK_BYTES_EQ(body, parsed[0].body);
}

TEST_CASE(parserUnusableAfterFailureUntilReset) {
    Parser p;
    std::vector<Request> out;
    CHECK(!p.feed(bytes("POST / RTSP/1.0\r\nContent-Length: 2000000\r\n\r\n"), out));
    CHECK(!p.feed(bytes("GET /info RTSP/1.0\r\n\r\n"), out));
    CHECK(!p.feed(NULL, 0, out));
    CHECK(out.empty());
    CHECK(p.failed());
    p.reset();
    CHECK(!p.failed());
    CHECK(p.feed(bytes("GET /info RTSP/1.0\r\n\r\n"), out));
    CHECK_EQ(1U, out.size());
}

TEST_CASE(toDecimalHelpers) {
    CHECK_EQ(std::string("0"), carplay::rtsp::toDecimalUnsigned(0));
    CHECK_EQ(std::string("18446744073709551615"), carplay::rtsp::toDecimalUnsigned(0xffffffffffffffffULL));
    CHECK_EQ(std::string("-42"), carplay::rtsp::toDecimal(-42));
    CHECK_EQ(std::string("-9223372036854775808"),
             carplay::rtsp::toDecimal(static_cast<int64_t>(-9223372036854775807LL - 1)));
}

TEST_CASE(contentTypeConstants) {
    CHECK_EQ(std::string("application/x-apple-binary-plist"), std::string(carplay::rtsp::kContentTypeBinaryPlist));
    CHECK_EQ(std::string("application/pairing+tlv8"), std::string(carplay::rtsp::kContentTypePairingTlv8));
    CHECK_EQ(std::string("application/octet-stream"), std::string(carplay::rtsp::kContentTypeOctetStream));
}

int main() { return test_support::runAll("test_rtsp_message"); }
