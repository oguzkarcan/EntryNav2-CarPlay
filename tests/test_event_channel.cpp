// EventChannel tests. The phone side is built independently: its ControlCipher keys come from a
// direct HKDF of the "Events-Salt" labels (phone read = accessory write = "Events-Write-Encryption-Key",
// phone write = accessory read = "Events-Read-Encryption-Key"), not from pairing::deriveEventKeys.

#include "carplay/airplay_crypto.hpp"
#include "carplay/airplay_hid.hpp"
#include "carplay/bplist_codec.hpp"
#include "carplay/control_cipher.hpp"
#include "carplay/event_channel.hpp"
#include "carplay/rtsp_message.hpp"
#include "test_support.hpp"

#include <memory>
#include <string>
#include <vector>

namespace crypto = carplay::crypto;
namespace bplist = carplay::bplist;
namespace rtsp = carplay::rtsp;
namespace hid = carplay::hid;
using carplay::ControlCipher;
using carplay::session::EventChannel;

typedef std::vector<uint8_t> Bytes;

namespace {

Bytes strBytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

Bytes sharedSecret() {
    Bytes s(32);
    for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(0xa0 + i);
    return s;
}

Bytes hkdf(const Bytes& ikm, const std::string& salt, const std::string& info) {
    Bytes out;
    crypto::hkdfSha512(ikm, salt, info, 32, out);
    return out;
}

// The iPhone's end of the event connection.
struct PhoneEvents {
    std::unique_ptr<ControlCipher> cipher;
    rtsp::Parser parser;

    explicit PhoneEvents(const Bytes& shared) {
        const Bytes read_key = hkdf(shared, "Events-Salt", "Events-Write-Encryption-Key");
        const Bytes write_key = hkdf(shared, "Events-Salt", "Events-Read-Encryption-Key");
        cipher.reset(new ControlCipher(&read_key[0], &write_key[0]));
    }

    bool decrypt(const Bytes& wire, Bytes& plain) {
        plain.clear();
        return cipher->feed(wire, plain);
    }

    bool messages(const Bytes& wire, std::vector<rtsp::Request>& out) {
        Bytes plain;
        if (!decrypt(wire, plain)) return false;
        return parser.feed(plain, out);
    }

    Bytes encrypt(const Bytes& plain) {
        Bytes out;
        cipher->encrypt(plain, out);
        return out;
    }
};

Bytes expectedCommand(const bplist::Value& body_value, uint32_t cseq, const std::string& extra = "") {
    Bytes body;
    bplist::encode(body_value, body);
    std::string head = "POST /command RTSP/1.0\r\n" + extra +
                       "Content-Type: application/x-apple-binary-plist\r\n" +
                       "Content-Length: " + rtsp::toDecimalUnsigned(body.size()) + "\r\n" +
                       "CSeq: " + rtsp::toDecimalUnsigned(cseq) + "\r\n\r\n";
    Bytes out = strBytes(head);
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

bplist::Value typed(const std::string& type) {
    bplist::Value v = bplist::Value::makeDict();
    v.set("type", bplist::Value::makeString(type));
    return v;
}

std::vector<std::string> keysOf(const bplist::Value& dict) {
    std::vector<std::string> k;
    for (size_t i = 0; i < dict.asDict().size(); ++i) k.push_back(dict.asDict()[i].first);
    return k;
}

bool decodeBody(const rtsp::Request& r, bplist::Value& v) { return bplist::decode(r.body, v) && v.isDict(); }

}  // namespace

TEST_CASE(notReadyRefusesEverything) {
    EventChannel ch;
    CHECK(!ch.ready());
    Bytes wire;
    CHECK(!ch.sendCommand(typed("forceKeyFrame"), wire));
    CHECK(!ch.sendHidReport(hid::kUidKnob, hid::knobReport(hid::KnobState()), wire));
    CHECK(!ch.requestSiri(wire));
    CHECK(!ch.sendIapMessage(Bytes(3, 1), wire));
    const uint8_t junk[4] = {1, 2, 3, 4};
    CHECK(!ch.onBytes(junk, sizeof(junk), wire));
    CHECK(wire.empty());
    CHECK_EQ(0U, ch.lastCseq());
    CHECK(!ch.start(NULL));
    CHECK(!ch.ready());
}

TEST_CASE(firstTwoCommandsExactPlaintext) {
    const Bytes shared = sharedSecret();
    EventChannel ch;
    REQUIRE(ch.start(&shared[0]));
    REQUIRE(ch.ready());
    PhoneEvents phone(shared);

    Bytes wire;
    REQUIRE(ch.sendTypedCommand("forceKeyFrame", NULL, wire));
    Bytes plain;
    REQUIRE(phone.decrypt(wire, plain));
    CHECK_BYTES_EQ(expectedCommand(typed("forceKeyFrame"), 1), plain);
    // One frame: [len16 | ciphertext | tag16].
    CHECK_EQ(plain.size() + 18U, wire.size());

    wire.clear();
    bplist::Value params = bplist::Value::makeDict();
    params.set("uuid", bplist::Value::makeString("b7e6c5a0-1111-4000-8000-000000000001"));
    REQUIRE(ch.sendTypedCommand("requestUI", &params, wire));
    REQUIRE(phone.decrypt(wire, plain));
    bplist::Value expected = typed("requestUI");
    expected.set("params", params);
    CHECK_BYTES_EQ(expectedCommand(expected, 2), plain);
    CHECK_EQ(2U, ch.lastCseq());

    // Extra headers go first, before Content-Type (sendRemoteControlMessage layout).
    wire.clear();
    rtsp::HeaderList extra;
    extra.push_back(rtsp::Header("X-Apple-StreamID", "3"));
    REQUIRE(ch.sendCommand(typed("x"), wire, &extra));
    REQUIRE(phone.decrypt(wire, plain));
    CHECK_BYTES_EQ(expectedCommand(typed("x"), 3, "X-Apple-StreamID: 3\r\n"), plain);
}

TEST_CASE(hidSendReportTouchAndKnob) {
    const Bytes shared = sharedSecret();
    EventChannel ch;
    REQUIRE(ch.start(&shared[0]));
    PhoneEvents phone(shared);

    std::vector<hid::TouchContact> contacts;
    contacts.push_back(hid::TouchContact(0, true, 400, 240));
    const Bytes touch = hid::touchReport(contacts, 800, 480);
    hid::KnobState knob;
    knob.select = true;
    knob.wheel = -1;
    const Bytes knob_report = hid::knobReport(knob);

    Bytes wire;
    REQUIRE(ch.sendHidReport(hid::kUidTouchscreen, touch, wire));
    REQUIRE(ch.sendHidReport(hid::kUidKnob, knob_report, wire));
    std::vector<rtsp::Request> msgs;
    REQUIRE(phone.messages(wire, msgs));
    REQUIRE(msgs.size() == 2U);

    const char* uuids[2] = {"2a2a2a2a", "2a2a2a2b"};
    const Bytes reports[2] = {touch, knob_report};
    for (size_t i = 0; i < 2; ++i) {
        CHECK_EQ(std::string("POST"), msgs[i].method);
        CHECK_EQ(std::string("/command"), msgs[i].path);
        CHECK_EQ(rtsp::toDecimalUnsigned(i + 1), msgs[i].header("cseq"));
        bplist::Value v;
        REQUIRE(decodeBody(msgs[i], v));
        std::vector<std::string> keys = keysOf(v);
        REQUIRE(keys.size() == 3U);
        CHECK_EQ(std::string("type"), keys[0]);
        CHECK_EQ(std::string("uuid"), keys[1]);
        CHECK_EQ(std::string("hidReport"), keys[2]);
        std::string s;
        CHECK(v.getString("type", s) && s == "hidSendReport");
        CHECK(v.getString("uuid", s) && s == uuids[i]);
        const bplist::Value* data = v.find("hidReport");
        REQUIRE(data != NULL && data->isData());
        CHECK_BYTES_EQ(reports[i], data->asData());
    }
    CHECK_EQ(12U, touch.size());
    CHECK_EQ(4U, knob_report.size());
}

TEST_CASE(reportSequenceSiriIapNightMode) {
    const Bytes shared = sharedSecret();
    EventChannel ch;
    PhoneEvents phone(shared);
    Bytes wire;

    // Night mode before the channel is ready: pending, newest value wins, nothing on the wire.
    CHECK(!ch.setNightMode(true, wire));
    CHECK(!ch.setNightMode(false, wire));
    CHECK(ch.hasPendingNightMode());
    CHECK(wire.empty());
    REQUIRE(ch.start(&shared[0]));
    CHECK(ch.hasPendingNightMode());  // start() alone does not flush
    REQUIRE(ch.flushPendingNightMode(wire));
    CHECK(!ch.hasPendingNightMode());
    CHECK(ch.flushPendingNightMode(wire));  // nothing pending -> true, nothing sent

    hid::KnobState k;
    k.home = true;
    const hid::ReportSequence seq = hid::momentaryKnobReports(k);
    REQUIRE(seq.size() == 2U);
    REQUIRE(ch.sendReportSequence(hid::kUidKnob, seq, wire));
    REQUIRE(ch.requestSiri(wire));
    const Bytes iap = test_support::hexToBytes("40400a0b0c");
    REQUIRE(ch.sendIapMessage(iap, wire));
    CHECK(ch.setNightMode(true, wire));  // ready: sent immediately

    std::vector<rtsp::Request> msgs;
    REQUIRE(phone.messages(wire, msgs));
    REQUIRE(msgs.size() == 7U);  // night(false), knob x2, siri x2, iAP, night(true)

    bplist::Value v;
    std::string s;
    bool b = true;
    REQUIRE(decodeBody(msgs[0], v));
    CHECK(v.getString("type", s) && s == "setNightMode");
    REQUIRE(v.find("params") != NULL);
    CHECK(v.find("params")->getBool("nightMode", b) && !b);

    for (size_t i = 0; i < 2; ++i) {
        REQUIRE(decodeBody(msgs[1 + i], v));
        CHECK_BYTES_EQ(seq[i], v.find("hidReport")->asData());
        CHECK(v.getString("uuid", s) && s == "2a2a2a2b");
    }
    for (size_t i = 0; i < 2; ++i) {
        REQUIRE(decodeBody(msgs[3 + i], v));
        CHECK(v.getString("type", s) && s == "requestSiri");
        int64_t action = 0;
        CHECK(v.find("params")->getInt("siriAction", action));
        CHECK_EQ(static_cast<int64_t>(2 + i), action);
    }
    REQUIRE(decodeBody(msgs[5], v));
    CHECK(v.getString("type", s) && s == "iAPSendMessage");
    CHECK_BYTES_EQ(iap, v.find("params")->find("data")->asData());
    REQUIRE(decodeBody(msgs[6], v));
    CHECK(v.find("params")->getBool("nightMode", b) && b);
    for (size_t i = 0; i < msgs.size(); ++i) CHECK_EQ(rtsp::toDecimalUnsigned(i + 1), msgs[i].header("cseq"));
}

TEST_CASE(inboundRequestAnsweredResponseConsumed) {
    const Bytes shared = sharedSecret();
    EventChannel ch;
    REQUIRE(ch.start(&shared[0]));
    PhoneEvents phone(shared);

    // Phone -> accessory: a request (answered) and a response to our command (consumed).
    Bytes in = phone.encrypt(strBytes("POST /command RTSP/1.0\r\nCSeq: 7\r\nContent-Length: 2\r\n\r\nhi"));
    const Bytes resp = phone.encrypt(strBytes("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n"));
    in.insert(in.end(), resp.begin(), resp.end());

    Bytes wire;
    std::vector<rtsp::Request> requests;
    REQUIRE(ch.onBytes(&in[0], in.size(), wire, &requests));
    REQUIRE(requests.size() == 1U);
    CHECK_EQ(std::string("POST"), requests[0].method);
    CHECK_BYTES_EQ(strBytes("hi"), requests[0].body);
    CHECK_EQ(1U, static_cast<unsigned>(ch.responsesReceived()));
    CHECK_EQ(200, ch.lastResponseStatus());
    CHECK_EQ(1U, static_cast<unsigned>(ch.requestsAnswered()));

    Bytes plain;
    REQUIRE(phone.decrypt(wire, plain));
    CHECK_BYTES_EQ(strBytes("RTSP/1.0 200 OK\r\nCSeq: 7\r\nContent-Length: 0\r\n\r\n"), plain);

    // A response alone produces no output.
    wire.clear();
    const Bytes r2 = phone.encrypt(strBytes("RTSP/1.0 400 Bad Request\r\nCSeq: 2\r\nContent-Length: 0\r\n\r\n"));
    REQUIRE(ch.onBytes(&r2[0], r2.size(), wire));
    CHECK(wire.empty());
    CHECK_EQ(400, ch.lastResponseStatus());
}

TEST_CASE(splitInboundDeliveryMatchesOneChunk) {
    const Bytes shared = sharedSecret();
    PhoneEvents phone(shared);
    Bytes in;
    for (int i = 0; i < 3; ++i) {
        const Bytes r = phone.encrypt(strBytes("GET_PARAMETER * RTSP/1.0\r\nCSeq: " + rtsp::toDecimal(10 + i) +
                                               "\r\n\r\n"));
        in.insert(in.end(), r.begin(), r.end());
    }
    const Bytes resp = phone.encrypt(strBytes("RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n"));
    in.insert(in.end(), resp.begin(), resp.end());

    EventChannel whole;
    EventChannel bytewise;
    REQUIRE(whole.start(&shared[0]));
    REQUIRE(bytewise.start(&shared[0]));
    Bytes out_whole;
    Bytes out_bytes;
    REQUIRE(whole.onBytes(&in[0], in.size(), out_whole));
    for (size_t i = 0; i < in.size(); ++i) REQUIRE(bytewise.onBytes(&in[i], 1, out_bytes));
    CHECK(!out_whole.empty());
    CHECK_BYTES_EQ(out_whole, out_bytes);
    CHECK_EQ(3U, static_cast<unsigned>(bytewise.requestsAnswered()));
    CHECK_EQ(1U, static_cast<unsigned>(bytewise.responsesReceived()));

    std::vector<rtsp::Request> answers;
    REQUIRE(phone.messages(out_bytes, answers));
    REQUIRE(answers.size() == 3U);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(answers[i].isResponse());
        CHECK_EQ(std::string("200"), answers[i].path);
        CHECK_EQ(rtsp::toDecimalUnsigned(10 + i), answers[i].header("cseq"));
    }
}

TEST_CASE(tamperedInboundBytesFail) {
    const Bytes shared = sharedSecret();
    EventChannel ch;
    REQUIRE(ch.start(&shared[0]));
    PhoneEvents phone(shared);
    Bytes in = phone.encrypt(strBytes("GET_PARAMETER * RTSP/1.0\r\nCSeq: 1\r\n\r\n"));
    in[5] ^= 0x01;
    Bytes wire;
    CHECK(!ch.onBytes(&in[0], in.size(), wire));
    CHECK(wire.empty());
    CHECK(!ch.ready());
    CHECK(!ch.sendTypedCommand("forceKeyFrame", NULL, wire));

    // Wrong keys (accessory started from another secret) also fail authentication.
    Bytes other = sharedSecret();
    other[0] ^= 0xff;
    EventChannel ch2;
    REQUIRE(ch2.start(&other[0]));
    const Bytes good = phone.encrypt(strBytes("GET_PARAMETER * RTSP/1.0\r\nCSeq: 2\r\n\r\n"));
    CHECK(!ch2.onBytes(&good[0], good.size(), wire));

    // A framing violation inside valid ciphertext also fails.
    EventChannel ch3;
    REQUIRE(ch3.start(&shared[0]));
    PhoneEvents phone3(shared);
    const Bytes bad = phone3.encrypt(strBytes("POST /x RTSP/1.0\r\nContent-Length: 99999999\r\n\r\n"));
    CHECK(!ch3.onBytes(&bad[0], bad.size(), wire));
    CHECK(!ch3.ready());
}

TEST_CASE(restartKeepsCseqAndResetsCipher) {
    const Bytes shared = sharedSecret();
    EventChannel ch;
    REQUIRE(ch.start(&shared[0]));
    Bytes wire;
    REQUIRE(ch.sendTypedCommand("a", NULL, wire));
    ch.close();
    CHECK(!ch.ready());
    CHECK(!ch.sendTypedCommand("b", NULL, wire));
    REQUIRE(ch.start(&shared[0]));
    wire.clear();
    REQUIRE(ch.sendTypedCommand("c", NULL, wire));
    PhoneEvents phone(shared);  // fresh counters: the new cipher starts at nonce 0
    Bytes plain;
    REQUIRE(phone.decrypt(wire, plain));
    CHECK_BYTES_EQ(expectedCommand(typed("c"), 2), plain);
}

int main() { return test_support::runAll("test_event_channel"); }
