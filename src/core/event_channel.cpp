// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/airplay/AirPlaySession.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.

#include "carplay/event_channel.hpp"

#include "carplay/pairing.hpp"

namespace carplay {
namespace session {

namespace {

int parseStatus(const std::string& s) {
    if (s.empty() || s.size() > 3) return 0;
    int v = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return 0;
        v = v * 10 + (s[i] - '0');
    }
    return v;
}

}  // namespace

EventChannel::EventChannel()
    : parser_(),
      cseq_(0),
      has_pending_night_(false),
      pending_night_(false),
      responses_received_(0),
      last_response_status_(0),
      requests_answered_(0) {}

EventChannel::~EventChannel() { close(); }

bool EventChannel::start(const uint8_t shared_secret[crypto::kKeyBytes]) {
    close();
    if (shared_secret == NULL) return false;
    uint8_t read_key[crypto::kKeyBytes];
    uint8_t write_key[crypto::kKeyBytes];
    const bool ok = pairing::deriveEventKeys(shared_secret, read_key, write_key);
    if (ok) cipher_.reset(new ControlCipher(read_key, write_key));
    crypto::wipe(read_key, sizeof(read_key));
    crypto::wipe(write_key, sizeof(write_key));
    parser_.reset();
    return ok;
}

void EventChannel::close() {
    cipher_.reset();  // ControlCipher's destructor wipes keys and buffered bytes
    parser_.reset();
}

bool EventChannel::sendCommand(const bplist::Value& command,
                               std::vector<uint8_t>& wire_out,
                               const rtsp::HeaderList* extra_headers) {
    if (!ready()) return false;
    std::vector<uint8_t> body;
    if (!bplist::encode(command, body)) return false;
    ++cseq_;
    rtsp::HeaderList headers;
    if (extra_headers != NULL) headers = *extra_headers;
    headers.push_back(rtsp::Header("Content-Type", rtsp::kContentTypeBinaryPlist));
    headers.push_back(rtsp::Header("Content-Length", "0"));  // replaced in place by buildRequest
    headers.push_back(rtsp::Header("CSeq", rtsp::toDecimalUnsigned(cseq_)));
    std::vector<uint8_t> plain;
    rtsp::buildRequest("POST", "/command", "RTSP/1.0", headers, body, plain);
    if (!cipher_->encrypt(plain, wire_out)) {
        close();
        return false;
    }
    return true;
}

bool EventChannel::sendTypedCommand(const std::string& type,
                                    const bplist::Value* params,
                                    std::vector<uint8_t>& wire_out) {
    bplist::Value cmd = bplist::Value::makeDict();
    cmd.set("type", bplist::Value::makeString(type));
    if (params != NULL) cmd.set("params", *params);
    return sendCommand(cmd, wire_out);
}

bool EventChannel::sendHidReport(uint32_t uid,
                                 const std::vector<uint8_t>& report,
                                 std::vector<uint8_t>& wire_out) {
    bplist::Value cmd = bplist::Value::makeDict();
    cmd.set("type", bplist::Value::makeString("hidSendReport"));
    cmd.set("uuid", bplist::Value::makeString(hid::uidString(uid)));
    cmd.set("hidReport", bplist::Value::makeData(report));
    return sendCommand(cmd, wire_out);
}

bool EventChannel::sendReportSequence(uint32_t uid,
                                      const hid::ReportSequence& reports,
                                      std::vector<uint8_t>& wire_out) {
    bool all = true;
    for (size_t i = 0; i < reports.size(); ++i) {
        if (!sendHidReport(uid, reports[i], wire_out)) all = false;
    }
    return all;
}

bool EventChannel::requestSiri(std::vector<uint8_t>& wire_out) {
    bool all = true;
    for (int action = 2; action <= 3; ++action) {
        bplist::Value params = bplist::Value::makeDict();
        params.set("siriAction", bplist::Value::makeInt(action));
        if (!sendTypedCommand("requestSiri", &params, wire_out)) all = false;
    }
    return all;
}

bool EventChannel::setNightMode(bool night, std::vector<uint8_t>& wire_out) {
    has_pending_night_ = true;
    pending_night_ = night;
    return flushPendingNightMode(wire_out);
}

bool EventChannel::flushPendingNightMode(std::vector<uint8_t>& wire_out) {
    if (!has_pending_night_) return true;
    bplist::Value params = bplist::Value::makeDict();
    params.set("nightMode", bplist::Value::makeBool(pending_night_));
    const bool sent = sendTypedCommand("setNightMode", &params, wire_out);
    if (sent) has_pending_night_ = false;
    return sent;
}

bool EventChannel::sendIapMessage(const std::vector<uint8_t>& data, std::vector<uint8_t>& wire_out) {
    bplist::Value params = bplist::Value::makeDict();
    params.set("data", bplist::Value::makeData(data));
    return sendTypedCommand("iAPSendMessage", &params, wire_out);
}

bool EventChannel::onBytes(const uint8_t* data,
                           size_t len,
                           std::vector<uint8_t>& wire_out,
                           std::vector<rtsp::Request>* requests_out) {
    if (!ready()) return false;
    if (data == NULL && len > 0) {
        close();
        return false;
    }
    std::vector<uint8_t> plain;
    if (!cipher_->feed(data, len, plain)) {
        close();
        return false;
    }
    std::vector<rtsp::Request> messages;
    if (!parser_.feed(plain, messages)) {
        close();
        return false;
    }
    for (size_t i = 0; i < messages.size(); ++i) {
        const rtsp::Request& m = messages[i];
        if (m.isResponse()) {
            ++responses_received_;
            last_response_status_ = parseStatus(m.path);
            continue;
        }
        std::vector<uint8_t> response;
        rtsp::buildResponse(m, rtsp::Response(200), response);
        if (!cipher_->encrypt(response, wire_out)) {
            close();
            return false;
        }
        ++requests_answered_;
        if (requests_out != NULL) requests_out->push_back(m);
    }
    return true;
}

}  // namespace session
}  // namespace carplay
