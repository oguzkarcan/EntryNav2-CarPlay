#include "carplay/airplay_session.hpp"

#include "carplay/audio_rtp.hpp"

#include <limits>

namespace carplay {
namespace session {

namespace {

std::string toLowerAscii(const std::string& s) {
    std::string out(s);
    for (size_t i = 0; i < out.size(); ++i) {
        if (out[i] >= 'A' && out[i] <= 'Z') out[i] = static_cast<char>(out[i] - 'A' + 'a');
    }
    return out;
}

bool endsWith(const std::string& s, const char* suffix) {
    const std::string suf(suffix);
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

bool isBufferedAudioMethod(const std::string& m) {
    return m == "SETRATE" || m == "SETRATEANCHORTIME" || m == "GETANCHOR" || m == "FLUSHBUFFERED";
}

/// Kotlin String.toLongOrNull(): optional sign, at least one decimal digit, int64 range.
bool parseLongStrict(const std::string& s, int64_t& out) {
    size_t i = 0;
    bool negative = false;
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) {
        negative = s[i] == '-';
        ++i;
    }
    if (i >= s.size()) return false;
    const uint64_t max_pos = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    const uint64_t limit = negative ? (max_pos + 1U) : max_pos;
    uint64_t v = 0;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        const uint64_t d = static_cast<uint64_t>(s[i] - '0');
        if (v > (limit - d) / 10U) return false;
        v = v * 10U + d;
    }
    out = negative ? static_cast<int64_t>(0U - v) : static_cast<int64_t>(v);
    return true;
}

std::string stringField(const bplist::Value& dict, const char* key) {
    std::string out;
    dict.getString(key, out);  // non-strings -> "" (Kotlin `value as? String ?: ""`)
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------------------------

bool plistNumberToLong(const bplist::Value& v, int64_t& out) {
    switch (v.type()) {
        case bplist::Value::TYPE_INT:
            out = v.asInt();
            return true;
        case bplist::Value::TYPE_UINT64:
            out = static_cast<int64_t>(v.asUInt());
            return true;
        case bplist::Value::TYPE_REAL: {
            const double d = v.asReal();
            if (d != d) {
                out = 0;  // NaN
            } else if (d >= 9223372036854775807.0) {
                out = std::numeric_limits<int64_t>::max();
            } else if (d <= -9223372036854775808.0) {
                out = std::numeric_limits<int64_t>::min();
            } else {
                out = static_cast<int64_t>(d);
            }
            return true;
        }
        default:
            return false;
    }
}

bool plistNumberToInt(const bplist::Value& v, int32_t& out) {
    int64_t l = 0;
    if (!plistNumberToLong(v, l)) return false;
    out = static_cast<int32_t>(static_cast<uint32_t>(static_cast<uint64_t>(l) & 0xffffffffU));
    return true;
}

void teardownStreamTypes(const bplist::Value* body, bool& whole_session_out, std::vector<int32_t>& types_out) {
    types_out.clear();
    whole_session_out = true;
    if (body == NULL || !body->isDict()) return;
    const bplist::Value* streams = body->find("streams");
    if (streams == NULL || !streams->isArray()) return;
    const bplist::Value::Array& arr = streams->asArray();
    bool any_entry = false;
    for (size_t i = 0; i < arr.size(); ++i) {
        const bplist::Value& entry = arr[i];
        if (!entry.isDict()) continue;
        const bplist::Value* t = entry.find("type");
        int32_t type = 0;
        if (t == NULL || !plistNumberToInt(*t, type)) continue;
        any_entry = true;
        const bplist::Value* sid = entry.find("streamID");
        int64_t stream_id = 0;
        const bool has_sid = sid != NULL && plistNumberToLong(*sid, stream_id);
        if (type == info::kStreamTypeData && has_sid && stream_id != 1) continue;
        types_out.push_back(type);
    }
    whole_session_out = !any_entry;
}

// ---------------------------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------------------------

Session::Session(const info::AirPlayConfig& config,
                 const pairing::Identity& identity,
                 pairing::PairingStore& store,
                 pairing::RandomSource& rng,
                 SessionListener& listener,
                 MediaHandler& media,
                 TransportHost& transport,
                 AuthProvider* auth,
                 const SessionPolicy& policy)
    : config_(config),
      listener_(listener),
      media_(media),
      transport_(transport),
      auth_(auth),
      policy_(policy),
      pair_setup_(identity, store, rng),
      pair_verify_(identity, store, rng),
      cipher_(),
      parser_(),
      events_(),
      active_streams_(),
      device_info_(),
      closed_(false),
      session_setup_done_(false),
      unverified_requests_(0),
      empty_() {}

Session::~Session() {
    cipher_.reset();
    events_.close();
    pair_setup_.reset();
    pair_verify_.reset();
}

void Session::debugLog(const std::string& message) { listener_.onDebugLog(message); }

bool Session::hasActiveStream(int32_t type) const {
    for (size_t i = 0; i < active_streams_.size(); ++i) {
        if (active_streams_[i] == type) return true;
    }
    return false;
}

void Session::addActiveStream(int32_t type) {
    if (!hasActiveStream(type)) active_streams_.push_back(type);
}

bool Session::removeActiveStream(int32_t type) {
    for (size_t i = 0; i < active_streams_.size(); ++i) {
        if (active_streams_[i] == type) {
            active_streams_.erase(active_streams_.begin() + static_cast<long>(i));
            return true;
        }
    }
    return false;
}

bool Session::onControlBytes(const uint8_t* data, size_t len, std::vector<uint8_t>& out) {
    if (closed_) return false;
    if (data == NULL && len > 0) {
        close();
        return false;
    }
    size_t responses = 0;
    size_t i = 0;
    std::vector<rtsp::Request> messages;
    while (i < len) {
        messages.clear();
        if (cipher_.get() == NULL) {
            // Plaintext: one byte at a time so the request that enables encryption ends exactly at a
            // known input offset; everything after it is ciphertext (see header comment).
            if (!parser_.feed(data + i, 1, messages)) {
                debugLog("airplay control closing: " + parser_.error());
                close();
                return false;
            }
            ++i;
        } else {
            std::vector<uint8_t> plain;
            if (!cipher_->feed(data + i, len - i, plain)) {
                debugLog("airplay control closing: control decrypt failed");
                close();
                return false;
            }
            i = len;
            if (!parser_.feed(plain, messages)) {
                debugLog("airplay control closing: " + parser_.error());
                close();
                return false;
            }
        }
        for (size_t m = 0; m < messages.size(); ++m) {
            if (!processRequest(messages[m], out)) {
                close();
                return false;
            }
            ++responses;
        }
    }
    if (responses > 0 && !closed_) media_.onSetupResponseSent(*this);
    return !closed_;
}

bool Session::processRequest(const rtsp::Request& request, std::vector<uint8_t>& out) {
    if (closed_) return false;
    if (cipher_.get() == NULL) {
        ++unverified_requests_;
        if (policy_.max_unverified_requests > 0 && unverified_requests_ > policy_.max_unverified_requests) {
            debugLog("airplay control closing: pre-verify request budget exceeded");
            return false;  // caller closes; no response for this request
        }
    }
    rtsp::Response response;
    if (!handle(request, response)) {
        debugLog("airplay handler failed " + request.method + " " + request.path);
        response = rtsp::Response(500);
    }
    if (closed_) return false;  // a callback closed the session
    std::vector<uint8_t> wire;
    rtsp::buildResponse(request, response, wire);
    if (cipher_.get() != NULL) {
        if (!cipher_->encrypt(wire, out)) return false;
    } else {
        out.insert(out.end(), wire.begin(), wire.end());
    }
    if (cipher_.get() == NULL && pair_verify_.verified()) {
        uint8_t read_key[crypto::kKeyBytes];
        uint8_t write_key[crypto::kKeyBytes];
        if (pair_verify_.controlKeys(read_key, write_key)) {
            cipher_.reset(new ControlCipher(read_key, write_key));
            debugLog("airplay control encryption enabled");
        }
        crypto::wipe(read_key, sizeof(read_key));
        crypto::wipe(write_key, sizeof(write_key));
    }
    return true;
}

Session::Route Session::routeOf(const rtsp::Request& request) const {
    const std::string& m = request.method;
    if (m == "SETUP") return kRouteSetup;
    if (m == "SET_PARAMETER") return kRouteSetParameter;
    if (m == "RECORD") return kRouteRecord;
    if (m == "TEARDOWN") return kRouteTeardown;
    if (config_.bufferedAudioOutputEnabled() && isBufferedAudioMethod(m)) return kRouteBufferedAudio;
    const std::string path = toLowerAscii(request.path);
    if (endsWith(path, "/pair-setup")) return kRoutePairSetup;
    if (endsWith(path, "/pair-verify")) return kRoutePairVerify;
    if (endsWith(path, "/auth-setup")) return kRouteAuthSetup;
    if (endsWith(path, "/info")) return kRouteInfo;
    if (m == "POST" && endsWith(path, "/command")) return kRouteCommand;
    if (m == "POST" && endsWith(path, "/feedback")) return kRouteFeedback;
    return kRouteDefault;
}

bool Session::allowedBeforeVerify(Route route, const rtsp::Request& request) const {
    switch (route) {
        case kRoutePairSetup:
        case kRoutePairVerify:
        case kRouteAuthSetup:
        case kRouteInfo:
            return true;
        case kRouteDefault:
            // Only gets the reference's empty 200 (no side effects); listed by the reference's
            // AirPlayControlDiagnostics among the pre-encryption routes.
            return endsWith(toLowerAscii(request.path), "/fp-setup");
        default:
            return false;
    }
}

bool Session::plistResponse(const bplist::Value& value, rtsp::Response& response) {
    response = rtsp::Response(200);
    if (!bplist::encode(value, response.body)) return false;
    response.headers.push_back(rtsp::Header("Content-Type", rtsp::kContentTypeBinaryPlist));
    return true;
}

bool Session::handle(const rtsp::Request& request, rtsp::Response& response) {
    response = rtsp::Response(200);
    const Route route = routeOf(request);
    if (policy_.require_verified_for_session_requests && cipher_.get() == NULL &&
        !allowedBeforeVerify(route, request)) {
        response = rtsp::Response(kStatusForbidden);
        response.status_text = "Forbidden";
        debugLog("airplay refused " + request.method + " " + request.path + " before pair-verify");
        return true;
    }
    if (policy_.refuse_pairing_after_verified && cipher_.get() != NULL &&
        (route == kRoutePairSetup || route == kRoutePairVerify)) {
        // Would reset PairVerify and wipe the shared secret the stream keys / event channel rely on.
        response = rtsp::Response(kStatusForbidden);
        response.status_text = "Forbidden";
        debugLog("airplay refused " + request.method + " " + request.path + " on the encrypted connection");
        return true;
    }
    switch (route) {
        case kRouteSetup:
            return handleSetup(request, response);
        case kRouteSetParameter:
            return true;  // corner-mask handling out of scope
        case kRouteRecord:
            listener_.onSessionActive(*this);
            return true;
        case kRouteTeardown:
            return handleTeardown(request, response);
        case kRouteBufferedAudio:
            return handleBufferedAudio(request, response);
        case kRoutePairSetup:
            pair_setup_.handle(request.body, response.body);
            response.headers.push_back(rtsp::Header("Content-Type", rtsp::kContentTypePairingTlv8));
            return true;
        case kRoutePairVerify:
            pair_verify_.handle(request.body, response.body);
            response.headers.push_back(rtsp::Header("Content-Type", rtsp::kContentTypePairingTlv8));
            return true;
        case kRouteAuthSetup:
            // MFiSAP deferred to Phase 5: 400 with or without an AuthProvider (see AuthProvider).
            (void)auth_;
            response = rtsp::Response(400);
            return true;
        case kRouteInfo:
            if (!info::encodeInfo(config_, response.body)) return false;
            response.headers.push_back(rtsp::Header("Content-Type", rtsp::kContentTypeBinaryPlist));
            return true;
        case kRouteCommand:
            return handleCommand(request, response);
        case kRouteFeedback: {
            bplist::Value body;
            if (!media_.onFeedback(*this, body)) return true;
            return plistResponse(body, response);
        }
        case kRouteDefault:
        default:
            return true;  // FLUSH, GET_PARAMETER, OPTIONS, unknown -> empty 200
    }
}

bool Session::handleSetup(const rtsp::Request& request, rtsp::Response& response) {
    bplist::Value dict;
    if (!bplist::decode(request.body, dict) || !dict.isDict()) {
        response = rtsp::Response(400);
        return true;
    }
    const bplist::Value* streams = dict.find("streams");
    if (streams != NULL && streams->isArray()) return handleStreams(streams->asArray(), response);

    DeviceInfo device;
    device.name = stringField(dict, "name");
    device.device_id = stringField(dict, "deviceID");
    device.wifi_mac = toLowerAscii(stringField(dict, "macAddress"));
    device.model = stringField(dict, "model");
    if (!device.name.empty() || !device.device_id.empty() || !device.wifi_mac.empty()) {
        device_info_ = device;
        listener_.onDeviceInfo(*this, device_info_);
        if (closed_) return true;
    }

    int32_t peer_timing_port = 0;
    const bplist::Value* tp = dict.find("timingPort");
    if (tp == NULL || !plistNumberToInt(*tp, peer_timing_port) || peer_timing_port < 1 ||
        peer_timing_port > 65535) {
        peer_timing_port = 0;
    }

    bplist::Value out = bplist::Value::makeDict();
    int32_t port = 0;
    if (!transport_.openTiming(peer_timing_port, port)) {
        transport_.closeSetupPorts();
        return false;
    }
    out.set("timingPort", bplist::Value::makeInt(port));
    port = 0;
    if (!transport_.openEvent(port)) {
        transport_.closeSetupPorts();
        return false;
    }
    out.set("eventPort", bplist::Value::makeInt(port));
    const bplist::Value* ka = dict.find("keepAliveLowPower");
    if (ka != NULL && ((ka->isBool() && ka->asBool()) || (ka->isInt() && ka->asInt() == 1))) {
        port = 0;
        if (!transport_.openKeepAlive(port)) {
            transport_.closeSetupPorts();
            return false;
        }
        out.set("keepAlivePort", bplist::Value::makeInt(port));
    }
    const bplist::Value* proposed = dict.find("features");
    const std::vector<std::string> features =
        info::setupEnabledFeatures(config_, (proposed != NULL && proposed->isArray()) ? proposed : NULL);
    bplist::Value::Array arr;
    for (size_t i = 0; i < features.size(); ++i) arr.push_back(bplist::Value::makeString(features[i]));
    out.set("enabledFeatures", bplist::Value::makeArray(arr));
    if (!plistResponse(out, response)) return false;
    session_setup_done_ = true;
    return true;
}

bool Session::handleStreams(const bplist::Value::Array& streams, rtsp::Response& response) {
    bplist::Value::Array result;
    const size_t n = streams.size() < policy_.max_streams_per_setup ? streams.size() : policy_.max_streams_per_setup;
    for (size_t i = 0; i < n && !closed_; ++i) {
        const bplist::Value& stream = streams[i];
        if (!stream.isDict()) continue;
        const bplist::Value* t = stream.find("type");
        int32_t type = 0;
        if (t == NULL || !plistNumberToInt(*t, type)) continue;
        switch (type) {
            case info::kStreamTypeMainScreen:
            case info::kStreamTypeAltScreen: {
                int32_t port = 0;
                if (media_.onScreen(*this, type, stream, port)) {
                    addActiveStream(type);
                    bplist::Value entry = bplist::Value::makeDict();
                    entry.set("type", bplist::Value::makeInt(type));
                    entry.set("dataPort", bplist::Value::makeInt(port));
                    result.push_back(entry);
                }
                break;
            }
            case info::kStreamTypeMainAudio:
            case info::kStreamTypeAltAudio:
            case info::kStreamTypeMainHighAudio: {
                bplist::Value entry;
                if (media_.onAudio(*this, type, stream, entry)) {
                    addActiveStream(type);
                    result.push_back(entry);
                }
                break;
            }
            case info::kStreamTypeMainBufferedAudio: {
                bplist::Value entry;
                if (config_.bufferedAudioOutputEnabled() && media_.onBufferedAudio(*this, stream, entry)) {
                    addActiveStream(type);
                    result.push_back(entry);
                }
                break;
            }
            case info::kStreamTypeData: {
                bplist::Value entry;
                if (media_.onDataStream(*this, stream, entry)) {
                    addActiveStream(type);
                    result.push_back(entry);
                }
                break;
            }
            default:
                debugLog("airplay unsupported stream type=" + rtsp::toDecimal(type));
                break;
        }
    }
    if (streams.size() > n) debugLog("airplay SETUP streams beyond the per-SETUP cap ignored");
    bplist::Value out = bplist::Value::makeDict();
    out.set("streams", bplist::Value::makeArray(result));
    return plistResponse(out, response);
}

bool Session::handleCommand(const rtsp::Request& request, rtsp::Response& response) {
    bplist::Value body;
    if (!bplist::decode(request.body, body) || !body.isDict()) body = bplist::Value::makeDict();
    const std::string type = stringField(body, "type");
    const bplist::Value* p = body.find("params");
    const bplist::Value params = (p != NULL && p->isDict()) ? *p : bplist::Value::makeDict();

    // Video-in-car remote-control messages (X-Apple-StreamID + params.data): acknowledged, not
    // dispatched (out of scope; the reference calls onRemoteControlMessage).
    const std::string* sid = request.findHeader("x-apple-streamid");
    const bplist::Value* data = params.find("data");
    int64_t stream_id = 0;
    if (sid != NULL && parseLongStrict(*sid, stream_id) && data != NULL && data->isData()) {
        debugLog("airplay remote-control message on streamID " + rtsp::toDecimal(stream_id) + " ignored");
        return true;
    }
    if (type == "duckAudio") {
        media_.onAudioDuck(*this, true);
    } else if (type == "unduckAudio") {
        media_.onAudioDuck(*this, false);
    }
    if (closed_) return true;
    // requestUI with the video-in-car URL is out of scope and handled as a plain requestUI.
    if (type == "requestUI") listener_.onHostUiRequested(*this);
    if (closed_) return true;
    listener_.onCommand(*this, type, params);
    (void)response;
    return true;
}

bool Session::handleTeardown(const rtsp::Request& request, rtsp::Response& response) {
    bplist::Value body;
    const bool decoded = bplist::decode(request.body, body);
    bool whole = true;
    std::vector<int32_t> types;
    teardownStreamTypes(decoded ? &body : NULL, whole, types);
    if (whole) {
        // Reference order (AirPlaySession.kt handleTeardown): every onTeardown first, then clear, so a
        // callback still sees the streams being torn down in hasActiveStream().
        const std::vector<int32_t> active(active_streams_);
        for (size_t i = 0; i < active.size() && !closed_; ++i) media_.onTeardown(*this, active[i]);
        active_streams_.clear();
    } else {
        for (size_t i = 0; i < types.size() && !closed_; ++i) {
            if (removeActiveStream(types[i])) media_.onTeardown(*this, types[i]);
        }
    }
    response = rtsp::Response(200);
    return true;
}

bool Session::handleBufferedAudio(const rtsp::Request& request, rtsp::Response& response) {
    bplist::Value body;
    if (request.body.empty() && request.method == "GETANCHOR") {
        body = bplist::Value::makeDict();
    } else if (!bplist::decode(request.body, body) || !body.isDict()) {
        response = rtsp::Response(400);
        return true;
    }
    bplist::Value out;
    if (!media_.onBufferedAudioControl(*this, request.method, body, out)) return true;
    return plistResponse(out, response);
}

// ---- Event channel ----

bool Session::eventExpected() const {
    return !closed_ && cipher_.get() != NULL && session_setup_done_ && !events_.ready();
}

bool Session::onEventAccepted(std::vector<uint8_t>& wire_out) {
    if (closed_) return false;
    if (events_.ready()) {
        debugLog("airplay event rejected: an event channel is already active");
        return false;  // the active channel and the session are left untouched
    }
    uint8_t shared[crypto::kKeyBytes];
    if (!pair_verify_.sharedSecret(shared)) {
        debugLog("airplay event rejected: pair-verify shared secret unavailable");
        close();
        return false;
    }
    const bool ok = events_.start(shared);
    crypto::wipe(shared, sizeof(shared));
    if (!ok) {
        close();
        return false;
    }
    if (!events_.flushPendingNightMode(wire_out)) {
        // Encode / encrypt failure on a fresh channel: drop the channel, keep the session (the night
        // mode stays pending). The caller closes the event socket and drops wire_out.
        debugLog("airplay event channel closed: pending night mode could not be sent");
        events_.close();
        return false;
    }
    return true;
}

bool Session::onEventBytes(const uint8_t* data,
                           size_t len,
                           std::vector<uint8_t>& wire_out,
                           std::vector<rtsp::Request>* requests_out) {
    if (closed_) return false;
    if (!events_.onBytes(data, len, wire_out, requests_out)) {
        debugLog("airplay event connection failed");
        close();
        return false;
    }
    return true;
}

// ---- Lifecycle ----

void Session::close() {
    if (closed_) return;
    closed_ = true;
    media_.onSessionClosed(*this);
    transport_.closeAll();
    events_.close();
    cipher_.reset();
    parser_.reset();
    pair_setup_.reset();
    pair_verify_.reset();
    active_streams_.clear();
    session_setup_done_ = false;
    listener_.onSessionEnded(*this);
}

// ---- Keys ----

bool Session::sharedSecret(uint8_t out[crypto::kKeyBytes]) const {
    if (out == NULL) return false;
    return pair_verify_.sharedSecret(out);
}

const std::string& Session::controllerId() const { return pair_verify_.verified() ? pair_verify_.controllerId() : empty_; }

bool Session::deriveStreamKey(uint64_t id, const std::string& info_label, uint8_t key_out[crypto::kKeyBytes]) const {
    if (key_out == NULL) return false;
    uint8_t shared[crypto::kKeyBytes];
    if (!pair_verify_.sharedSecret(shared)) return false;
    const bool ok = audio::deriveDataStreamKey(shared, sizeof(shared), id, info_label, key_out);
    crypto::wipe(shared, sizeof(shared));
    return ok;
}

bool Session::deriveAudioStreamKeys(uint64_t stream_connection_id, uint8_t* out_key, uint8_t* in_key) const {
    if (out_key == NULL && in_key == NULL) return false;
    uint8_t shared[crypto::kKeyBytes];
    if (!pair_verify_.sharedSecret(shared)) return false;
    bool ok = true;
    if (out_key != NULL) ok = audio::deriveAudioOutputKey(shared, sizeof(shared), stream_connection_id, out_key);
    if (ok && in_key != NULL) ok = audio::deriveAudioInputKey(shared, sizeof(shared), stream_connection_id, in_key);
    crypto::wipe(shared, sizeof(shared));
    return ok;
}

bool Session::deriveScreenStreamKey(uint64_t stream_connection_id, uint8_t key_out[crypto::kKeyBytes]) const {
    return deriveStreamKey(stream_connection_id, audio::kDataStreamOutputKeyInfo, key_out);
}

bool Session::deriveDataStreamSeedKey(uint64_t seed, uint8_t key_out[crypto::kKeyBytes]) const {
    return deriveStreamKey(seed, audio::kDataStreamOutputKeyInfo, key_out);
}

bool Session::plistUnsignedId(const bplist::Value& v, uint64_t& out) {
    if (v.isUInt()) {
        out = v.asUInt();
        return true;
    }
    if (v.isInt()) {  // negative int64: Long.toUnsignedString reinterpretation
        out = static_cast<uint64_t>(v.asInt());
        return true;
    }
    return false;
}

bool Session::streamOutputKey(const bplist::Value& stream, uint8_t key_out[crypto::kKeyBytes], const char* field) const {
    const bplist::Value* v = stream.find(field == NULL ? "streamConnectionID" : field);
    uint64_t id = 0;
    if (v == NULL || !plistUnsignedId(*v, id)) return false;
    return deriveStreamKey(id, audio::kDataStreamOutputKeyInfo, key_out);
}

bool Session::streamInputKey(const bplist::Value& stream, uint8_t key_out[crypto::kKeyBytes], const char* field) const {
    const bplist::Value* v = stream.find(field == NULL ? "streamConnectionID" : field);
    uint64_t id = 0;
    if (v == NULL || !plistUnsignedId(*v, id)) return false;
    return deriveStreamKey(id, audio::kDataStreamInputKeyInfo, key_out);
}

}  // namespace session
}  // namespace carplay
