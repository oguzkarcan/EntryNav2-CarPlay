#include "carplay/iap2_session.hpp"

#include <sstream>

namespace carplay {
namespace iap2 {

namespace {

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

uint16_t readU16Be(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

bool buildIdentificationParams(const IdentificationConfig& cfg,
                               ParameterList& root,
                               std::string* error_out) {
    root.clear();

    if (!cfg.name.empty()) {
        root.addString(param::kIdentName, cfg.name);
    }
    if (!cfg.model.empty()) {
        root.addString(param::kIdentModelIdentifier, cfg.model);
    }
    if (!cfg.manufacturer.empty()) {
        root.addString(param::kIdentManufacturer, cfg.manufacturer);
    }
    if (!cfg.serial_number.empty()) {
        root.addString(param::kIdentSerialNumber, cfg.serial_number);
    }
    if (!cfg.firmware_version.empty()) {
        root.addString(param::kIdentFirmwareVersion, cfg.firmware_version);
    }
    if (!cfg.hardware_version.empty()) {
        root.addString(param::kIdentHardwareVersion, cfg.hardware_version);
    }
    if (!cfg.messages_sent_by_accessory.empty()) {
        root.addU16List(param::kIdentMessagesSentByAccessory, cfg.messages_sent_by_accessory);
    }
    if (!cfg.messages_received_from_device.empty()) {
        root.addU16List(param::kIdentMessagesReceivedFromDevice, cfg.messages_received_from_device);
    }

    root.addU8(param::kIdentPowerProvidingCapability, cfg.power_providing_capability);
    root.addU16(param::kIdentMaxCurrentDrawnFromDevice, cfg.max_current_drawn_ma);

    if (!cfg.current_language.empty()) {
        root.addString(param::kIdentCurrentLanguage, cfg.current_language);
    }
    for (size_t i = 0; i < cfg.supported_languages.size(); ++i) {
        root.addString(param::kIdentSupportedLanguage, cfg.supported_languages[i]);
    }

    if (cfg.usb_device_transport.enabled) {
        ParameterList grp;
        grp.addU16(param::kTransportComponentId, cfg.usb_device_transport.component_id);
        if (!cfg.usb_device_transport.name.empty()) {
            grp.addString(param::kTransportComponentName, cfg.usb_device_transport.name);
        }
        if (cfg.usb_device_transport.supports_iap2) {
            grp.addVoid(param::kTransportSupportsIap2Connection);
        }
        for (size_t i = 0; i < cfg.usb_device_transport.audio_sample_rates.size(); ++i) {
            grp.addU8(param::kUsbDeviceSupportedAudioSampleRate,
                      cfg.usb_device_transport.audio_sample_rates[i]);
        }
        root.addGroup(param::kIdentUsbDeviceTransportComponent, grp);
    }

    if (cfg.bluetooth_transport.enabled) {
        if (!cfg.bluetooth_transport.mac_address.empty() &&
            cfg.bluetooth_transport.mac_address.size() != 6U) {
            setError(error_out, "Bluetooth transport MAC address must be 6 bytes");
            return false;
        }
        ParameterList grp;
        grp.addU16(param::kTransportComponentId, cfg.bluetooth_transport.component_id);
        if (!cfg.bluetooth_transport.name.empty()) {
            grp.addString(param::kTransportComponentName, cfg.bluetooth_transport.name);
        }
        if (cfg.bluetooth_transport.supports_iap2) {
            grp.addVoid(param::kTransportSupportsIap2Connection);
        }
        if (cfg.bluetooth_transport.mac_address.size() == 6U) {
            grp.addRaw(param::kBtTransportMacAddress, cfg.bluetooth_transport.mac_address);
        }
        root.addGroup(param::kIdentBluetoothTransportComponent, grp);
    }

    if (cfg.wireless_carplay_transport.enabled) {
        ParameterList grp;
        grp.addU16(param::kTransportComponentId, cfg.wireless_carplay_transport.component_id);
        if (!cfg.wireless_carplay_transport.name.empty()) {
            grp.addString(param::kTransportComponentName, cfg.wireless_carplay_transport.name);
        }
        if (cfg.wireless_carplay_transport.supports_iap2) {
            grp.addVoid(param::kTransportSupportsIap2Connection);
        }
        if (cfg.wireless_carplay_transport.supports_carplay) {
            grp.addVoid(param::kWirelessCarPlaySupportsCarPlay);
        }
        root.addGroup(param::kIdentWirelessCarPlayTransportComponent, grp);
    }

    if (cfg.vehicle_information.enabled) {
        ParameterList grp;
        grp.addU16(param::kVehicleInfoComponentId, cfg.vehicle_information.component_id);
        if (!cfg.vehicle_information.name.empty()) {
            grp.addString(param::kVehicleInfoComponentName, cfg.vehicle_information.name);
        }
        for (size_t i = 0; i < cfg.vehicle_information.engine_types.size(); ++i) {
            grp.addU8(param::kVehicleInfoEngineType, cfg.vehicle_information.engine_types[i]);
        }
        if (!cfg.vehicle_information.display_name.empty()) {
            grp.addString(param::kVehicleInfoDisplayName, cfg.vehicle_information.display_name);
        }
        root.addGroup(param::kIdentVehicleInformationComponent, grp);
    }

    return true;
}

}  // namespace

bool buildIdentificationInformation(const IdentificationConfig& cfg,
                                    Frame& frame_out,
                                    std::string* error_out) {
    ParameterList root;
    if (!buildIdentificationParams(cfg, root, error_out)) {
        return false;
    }
    return Frame::build(msg::kIdentificationInformation, root, frame_out, error_out);
}

bool buildIdentificationUpdate(const IdentificationConfig& cfg,
                               Frame& frame_out,
                               std::string* error_out) {
    ParameterList root;
    if (!buildIdentificationParams(cfg, root, error_out)) {
        return false;
    }
    return Frame::build(msg::kIdentificationInformationUpdate, root, frame_out, error_out);
}

void Session::LinkAdapter::onLinkStateChanged(LinkState new_state) {
    owner_.onLinkStateChangedImpl(new_state);
}

void Session::LinkAdapter::onLinkConnected(const SynPayload& negotiated) {
    owner_.onLinkConnectedImpl(negotiated);
}

void Session::LinkAdapter::onLinkPayload(uint8_t session_id, const uint8_t* data, size_t len) {
    owner_.onLinkPayloadImpl(session_id, data, len);
}

void Session::LinkAdapter::onLinkReset(bool by_peer) {
    owner_.onLinkResetImpl(by_peer);
}

void Session::LinkAdapter::onLinkError(const std::string& reason) {
    owner_.onLinkErrorImpl(reason);
}

Session::Session(ByteSink& sink,
                 AuthProvider& auth,
                 SessionListener& listener,
                 const SessionConfig& config)
    : auth_(auth),
      listener_(listener),
      config_(config),
      link_adapter_(*this),
      link_(sink, link_adapter_, config.link),
      state_(kSessionIdle),
      control_session_id_(0),
      identified_(false),
      authenticated_(false),
      power_updates_active_(false),
      location_updates_active_(false),
      has_time_(false),
      last_now_ms_(0),
      has_state_time_(false),
      state_entered_ms_(0) {}

void Session::setState(SessionState next) {
    if (state_ != next) {
        const SessionState prev = state_;
        state_ = next;
        state_entered_ms_ = last_now_ms_;
        has_state_time_ = has_time_;
        listener_.onStateChanged(prev, next);
    }
}

void Session::failSession(const std::string& reason) {
    if (state_ != kSessionFailed) {
        setState(kSessionFailed);
    }
    listener_.onError(reason);
}

void Session::start() {
    framer_.reset();
    control_session_id_ = 0;
    identified_ = false;
    authenticated_ = false;
    power_updates_active_ = false;
    location_updates_active_ = false;
    setState(kSessionDetecting);
    link_.start();
}

void Session::reset(bool send_rst) {
    framer_.reset();
    control_session_id_ = 0;
    identified_ = false;
    authenticated_ = false;
    power_updates_active_ = false;
    location_updates_active_ = false;
    link_.reset(send_rst);
    setState(kSessionIdle);
}

bool Session::feed(const uint8_t* data, size_t len) {
    return link_.feed(data, len);
}

bool Session::feed(const std::vector<uint8_t>& bytes) {
    return link_.feed(bytes);
}

void Session::onLinkStateChangedImpl(LinkState new_state) {
    if (state_ == kSessionFailed) {
        return;
    }
    if (new_state == kLinkDetecting) {
        if (state_ == kSessionIdle) {
            setState(kSessionDetecting);
        }
    } else if (new_state == kLinkSynSent) {
        if (state_ == kSessionIdle || state_ == kSessionDetecting) {
            setState(kSessionSyncing);
        }
    } else if (new_state == kLinkFailed) {
        setState(kSessionFailed);
    }
}

void Session::onLinkConnectedImpl(const SynPayload& negotiated) {
    const SynSession* ctrl = negotiated.findSessionByType(kSessionTypeControl);
    if (ctrl == NULL) {
        failSession("negotiated SYN contains no control session");
        return;
    }
    framer_.reset();
    control_session_id_ = ctrl->id;
    identified_ = false;
    authenticated_ = false;
    power_updates_active_ = false;
    location_updates_active_ = false;
    setState(kSessionConnected);
}

void Session::onLinkResetImpl(bool by_peer) {
    framer_.reset();
    control_session_id_ = 0;
    identified_ = false;
    authenticated_ = false;
    power_updates_active_ = false;
    location_updates_active_ = false;
    if (by_peer && state_ != kSessionIdle && state_ != kSessionFailed) {
        failSession("iAP2 link reset by peer");
    }
}

void Session::onLinkErrorImpl(const std::string& reason) {
    if (state_ != kSessionIdle && state_ != kSessionFailed) {
        setState(kSessionFailed);
    }
    listener_.onError(reason);
}

void Session::onLinkPayloadImpl(uint8_t session_id, const uint8_t* data, size_t len) {
    if (state_ == kSessionIdle || state_ == kSessionFailed) {
        return;
    }
    if (session_id != control_session_id_) {
        return;
    }
    std::vector<Frame> frames;
    std::string err;
    if (!framer_.push(data, len, frames, &err)) {
        failSession(err);
        return;
    }
    for (size_t i = 0; i < frames.size(); ++i) {
        handleFrame(frames[i]);
        if (state_ == kSessionFailed || state_ == kSessionIdle) {
            break;
        }
    }
}

bool Session::sendControlMessage(const Frame& frame) {
    if (link_.state() != kLinkConnected || control_session_id_ == 0U) {
        return false;
    }
    std::vector<uint8_t> wire;
    std::string err;
    if (!CsmFramer::encodeFrame(frame, wire, &err)) {
        listener_.onError(err);
        return false;
    }
    const size_t max_payload = link_.maxPayloadBytes();
    if (max_payload == 0U) {
        listener_.onError("link maxPayloadBytes is 0");
        return false;
    }
    std::vector<std::vector<uint8_t> > packets;
    if (!CsmFramer::splitForLink(wire, max_payload, packets, &err)) {
        listener_.onError(err);
        return false;
    }
    for (size_t i = 0; i < packets.size(); ++i) {
        if (!link_.sendPayload(control_session_id_, packets[i])) {
            return false;
        }
    }
    return true;
}

bool Session::sendIdentificationUpdate(const IdentificationConfig& cfg) {
    if (link_.state() != kLinkConnected || !identified_) {
        return false;
    }
    Frame frame;
    std::string err;
    if (!buildIdentificationUpdate(cfg, frame, &err)) {
        listener_.onError(err);
        return false;
    }
    return sendControlMessage(frame);
}

bool Session::sendStartCarPlaySession(const StartSessionConfig& cfg) {
    if (!isReady()) {
        return false;
    }
    Frame frame;
    std::string err;
    if (!buildStartCarPlaySession(cfg, frame, &err)) {
        listener_.onError(err);
        return false;
    }
    return sendControlMessage(frame);
}

bool Session::requestWiFiInformation() {
    if (!isReady()) {
        return false;
    }
    Frame frame(msg::kRequestWiFiInformation, std::vector<uint8_t>());
    return sendControlMessage(frame);
}

bool Session::sendPowerSourceUpdate(uint16_t available_current_ma,
                                    bool has_charging,
                                    bool charging) {
    if (!isReady()) {
        return false;
    }
    Frame frame;
    std::string err;
    if (!buildPowerSourceUpdate(available_current_ma, has_charging, charging, frame, &err)) {
        listener_.onError(err);
        return false;
    }
    return sendControlMessage(frame);
}

bool Session::sendLocationInformation(const std::string& nmea_sentence) {
    if (!isReady()) {
        return false;
    }
    Frame frame;
    std::string err;
    if (!buildLocationInformation(nmea_sentence, frame, &err)) {
        listener_.onError(err);
        return false;
    }
    return sendControlMessage(frame);
}

void Session::handleFrame(const Frame& frame) {
    switch (frame.message_id) {
        case msg::kStartIdentification:
            handleStartIdentification();
            return;
        case msg::kIdentificationAccepted:
            handleIdentificationAccepted();
            return;
        case msg::kIdentificationRejected:
            handleIdentificationRejected(frame);
            return;
        case msg::kCancelIdentification:
            handleCancelIdentification();
            return;
        case msg::kIdentificationInformationUpdate:
            handleIdentificationUpdate(frame);
            return;
        case msg::kRequestAuthenticationCertificate:
            handleRequestAuthCertificate();
            return;
        case msg::kRequestAuthenticationChallengeResponse:
            handleRequestAuthChallengeResponse(frame);
            return;
        case msg::kAuthenticationFailed:
            handleAuthFailed();
            return;
        case msg::kAuthenticationSucceeded:
            handleAuthSucceeded();
            return;
        default:
            break;
    }

    if (!isReady()) {
        std::ostringstream oss;
        oss << "unexpected iAP2 message 0x" << std::hex << frame.message_id
            << " before identification and authentication completed";
        listener_.onError(oss.str());
        return;
    }

    std::string err;
    switch (frame.message_id) {
        case msg::kCarPlayAvailability: {
            CarPlayAvailability avail;
            if (!parseCarPlayAvailability(frame, avail, &err)) {
                listener_.onError(err);
                return;
            }
            listener_.onCarPlayAvailability(avail);
            return;
        }
        case msg::kWirelessCarPlayUpdate: {
            bool available = false;
            if (!parseWirelessCarPlayAvailability(frame, available, &err)) {
                listener_.onError(err);
                return;
            }
            listener_.onWirelessCarPlayAvailability(available);
            return;
        }
        case msg::kDeviceTransportIdentifier: {
            DeviceTransportIdentifier tid;
            if (!parseDeviceTransportIdentifier(frame, tid, &err)) {
                listener_.onError(err);
                return;
            }
            listener_.onDeviceTransportIdentifier(tid);
            return;
        }
        case msg::kWiFiInformation: {
            WiFiInformation info;
            if (!parseWiFiInformation(frame, info, &err)) {
                listener_.onError(err);
                return;
            }
            listener_.onWiFiInformation(info);
            return;
        }
        case msg::kRequestAccessoryWiFiConfiguration:
            handleRequestAccessoryWiFiConfig();
            return;
        case msg::kStartPowerUpdates:
            power_updates_active_ = true;
            listener_.onPowerUpdatesChanged(true);
            return;
        case msg::kStopPowerUpdates:
            power_updates_active_ = false;
            listener_.onPowerUpdatesChanged(false);
            return;
        case msg::kStartLocationInformation:
            location_updates_active_ = true;
            listener_.onLocationUpdatesChanged(true);
            return;
        case msg::kStopLocationInformation:
            location_updates_active_ = false;
            listener_.onLocationUpdatesChanged(false);
            return;
        default:
            listener_.onUnhandledMessage(frame);
            return;
    }
}

void Session::handleStartIdentification() {
    Frame frame;
    std::string err;
    if (!buildIdentificationInformation(config_.identification, frame, &err)) {
        failSession(err);
        return;
    }
    setState(kSessionIdentifying);
    sendControlMessage(frame);
}

void Session::handleIdentificationAccepted() {
    identified_ = true;
    listener_.onIdentificationAccepted();
    if (state_ == kSessionFailed || state_ == kSessionIdle) {
        return;
    }
    if (authenticated_) {
        setState(kSessionReady);
        listener_.onReady();
    } else {
        setState(kSessionIdentified);
    }
}

void Session::handleIdentificationRejected(const Frame& frame) {
    identified_ = false;
    std::vector<uint16_t> rejected;
    ParameterList params;
    if (ParameterList::decode(frame.payload, params, NULL)) {
        const std::vector<Parameter>& items = params.items();
        for (size_t i = 0; i < items.size(); ++i) {
            if (items[i].id == param::kIdentRejectedParamId && !items[i].payload.empty()) {
                for (size_t off = 0; off + 1U < items[i].payload.size(); off += 2U) {
                    rejected.push_back(readU16Be(&items[i].payload[off]));
                }
            } else if (items[i].payload.empty()) {
                rejected.push_back(items[i].id);
            }
        }
    }
    setState(kSessionFailed);
    listener_.onIdentificationRejected(rejected);
    listener_.onError("iAP2 identification rejected by device");
}

void Session::handleCancelIdentification() {
    identified_ = false;
    if (state_ == kSessionIdentifying || state_ == kSessionIdentified) {
        setState(authenticated_ ? kSessionAuthenticated : kSessionConnected);
    }
}

void Session::handleIdentificationUpdate(const Frame& frame) {
    ParameterList params;
    std::string err;
    if (!ParameterList::decode(frame.payload, params, &err)) {
        listener_.onError(err);
        return;
    }
    listener_.onIdentificationUpdate(params);
}

void Session::handleRequestAuthCertificate() {
    setState(kSessionAuthenticating);
    std::vector<uint8_t> cert;
    if (!auth_.getCertificate(cert) || cert.empty()) {
        const std::string msg = "failed to retrieve accessory authentication certificate";
        setState(kSessionFailed);
        listener_.onAuthenticationFailed(msg);
        listener_.onError(msg);
        return;
    }

    ParameterList params;
    params.addRaw(param::kAuthCertificateData, cert);
    Frame frame;
    std::string err;
    if (!Frame::build(msg::kAuthenticationCertificate, params, frame, &err)) {
        failSession(err);
        return;
    }
    sendControlMessage(frame);
}

void Session::handleRequestAuthChallengeResponse(const Frame& frame) {
    setState(kSessionAuthenticating);
    ParameterList params;
    std::string err;
    if (!ParameterList::decode(frame.payload, params, &err)) {
        setState(kSessionFailed);
        listener_.onAuthenticationFailed(err);
        listener_.onError(err);
        return;
    }
    std::vector<uint8_t> challenge;
    if (!params.readBytes(param::kAuthChallengeData, challenge) || challenge.empty()) {
        const std::string msg = "missing or empty authentication challenge";
        setState(kSessionFailed);
        listener_.onAuthenticationFailed(msg);
        listener_.onError(msg);
        return;
    }
    std::vector<uint8_t> sig;
    if (!auth_.signChallenge(&challenge[0], challenge.size(), sig) || sig.empty()) {
        const std::string msg = "failed to sign authentication challenge";
        setState(kSessionFailed);
        listener_.onAuthenticationFailed(msg);
        listener_.onError(msg);
        return;
    }

    ParameterList resp_params;
    resp_params.addRaw(param::kAuthChallengeResponseData, sig);
    Frame resp;
    if (!Frame::build(msg::kAuthenticationResponse, resp_params, resp, &err)) {
        failSession(err);
        return;
    }
    sendControlMessage(resp);
}

void Session::handleAuthFailed() {
    authenticated_ = false;
    const std::string msg = "device rejected authentication";
    setState(kSessionFailed);
    listener_.onAuthenticationFailed(msg);
    listener_.onError(msg);
}

void Session::handleAuthSucceeded() {
    authenticated_ = true;
    listener_.onAuthenticationSucceeded();
    if (state_ == kSessionFailed || state_ == kSessionIdle) {
        return;
    }
    if (identified_) {
        setState(kSessionReady);
        listener_.onReady();
    } else {
        setState(kSessionAuthenticated);
    }
}

void Session::handleRequestAccessoryWiFiConfig() {
    WiFiConfiguration wifi_cfg;
    if (!listener_.onWiFiCredentialsRequested(wifi_cfg)) {
        listener_.onError("Wi-Fi credentials requested (0x5702) but listener declined");
        return;
    }
    Frame frame;
    std::string err;
    const std::vector<uint8_t>* bssid_ptr = wifi_cfg.bssid.empty() ? NULL : &wifi_cfg.bssid;
    if (!buildAccessoryWiFiConfiguration(wifi_cfg.ssid,
                                         wifi_cfg.passphrase,
                                         wifi_cfg.channel,
                                         wifi_cfg.security_type,
                                         bssid_ptr,
                                         frame,
                                         &err)) {
        listener_.onError(err);
        return;
    }
    sendControlMessage(frame);
}

void Session::tick(int64_t now_ms) {
    has_time_ = true;
    last_now_ms_ = now_ms;

    link_.tick(now_ms);

    if (state_ == kSessionIdle || state_ == kSessionFailed || state_ == kSessionReady) {
        return;
    }

    if (!has_state_time_) {
        state_entered_ms_ = now_ms;
        has_state_time_ = true;
        return;
    }

    const int64_t elapsed = now_ms - state_entered_ms_;
    switch (state_) {
        case kSessionDetecting:
            if (config_.detect_timeout_ms > 0U &&
                elapsed >= static_cast<int64_t>(config_.detect_timeout_ms)) {
                link_.reset(false);
                failSession("iAP2 detect timeout");
            }
            break;
        case kSessionSyncing:
            if (config_.sync_timeout_ms > 0U &&
                elapsed >= static_cast<int64_t>(config_.sync_timeout_ms)) {
                link_.reset(true);
                failSession("iAP2 link sync timeout");
            }
            break;
        case kSessionConnected:
        case kSessionIdentifying:
        case kSessionAuthenticated:
            if (config_.identification_timeout_ms > 0U &&
                elapsed >= static_cast<int64_t>(config_.identification_timeout_ms)) {
                link_.reset(true);
                failSession("iAP2 identification timeout");
            }
            break;
        case kSessionIdentified:
        case kSessionAuthenticating:
            if (config_.authentication_timeout_ms > 0U &&
                elapsed >= static_cast<int64_t>(config_.authentication_timeout_ms)) {
                const std::string msg = "iAP2 authentication timeout";
                link_.reset(true);
                setState(kSessionFailed);
                listener_.onAuthenticationFailed(msg);
                listener_.onError(msg);
            }
            break;
        default:
            break;
    }
}

}  // namespace iap2
}  // namespace carplay
