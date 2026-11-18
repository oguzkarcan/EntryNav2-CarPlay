// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/iap2/catalog/Iap2Endpoint.kt,
//  shared/src/main/java/com/shilapi/xcertplay/transport/Iap2IdentificationClient.kt,
//  shared/src/main/java/com/shilapi/xcertplay/transport/Iap2WiredControlClient.kt,
//  shared/src/main/java/com/shilapi/xcertplay/transport/Iap2WirelessControlClient.kt,
//  shared/src/main/java/com/shilapi/xcertplay/transport/Iap2VehicleStatus.kt,
//  shared/src/main/java/com/shilapi/xcertplay/transport/Iap2LocationClient.kt,
//  shared/src/main/java/com/shilapi/xcertplay/mfi/Iap2MfiAuthenticationClient.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.

#include "carplay/iap2_session.hpp"

#include <algorithm>
#include <sstream>

namespace carplay {
namespace iap2 {

namespace {

static const size_t kMaxRejectedMessageIds = 32U;

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

uint16_t readU16Be(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

bool containsU16(const std::vector<uint16_t>& vec, uint16_t value) {
    for (size_t i = 0; i < vec.size(); ++i) {
        if (vec[i] == value) {
            return true;
        }
    }
    return false;
}

bool isAuthMessage(uint16_t msg_id) {
    return msg_id == msg::kRequestAuthenticationCertificate ||
           msg_id == msg::kAuthenticationCertificate ||
           msg_id == msg::kRequestAuthenticationChallengeResponse ||
           msg_id == msg::kAuthenticationResponse ||
           msg_id == msg::kAuthenticationFailed ||
           msg_id == msg::kAuthenticationSucceeded;
}

void appendBaseSentMessages(std::vector<uint16_t>& out, bool include_power_source) {
    out.push_back(msg::kAuthenticationCertificate);              // 0xAA01
    out.push_back(msg::kAuthenticationResponse);                 // 0xAA03
    out.push_back(msg::kStartNowPlayingUpdates);                 // 0x5000
    out.push_back(msg::kStopNowPlayingUpdates);                  // 0x5002
    out.push_back(msg::kStartRouteGuidanceUpdates);              // 0x5200
    out.push_back(msg::kStopRouteGuidanceUpdates);               // 0x5203
    out.push_back(msg::kStartPowerUpdates);                      // 0xAE00
    out.push_back(msg::kStopPowerUpdates);                       // 0xAE02
    out.push_back(msg::kStartCommunicationsUpdates);             // 0x4157
    out.push_back(msg::kStopCommunicationsUpdates);              // 0x4159
    out.push_back(msg::kStartCallStateUpdates);                  // 0x4154
    out.push_back(msg::kStopCallStateUpdates);                   // 0x4156
    if (include_power_source) {
        out.push_back(msg::kPowerSourceUpdate);                  // 0xAE03
    }
    out.push_back(msg::kCarPlayStartSession);                    // 0x4301
}

void appendBaseReceivedMessages(std::vector<uint16_t>& out) {
    out.push_back(msg::kRequestAuthenticationCertificate);       // 0xAA00
    out.push_back(msg::kRequestAuthenticationChallengeResponse); // 0xAA02
    out.push_back(msg::kAuthenticationFailed);                   // 0xAA04
    out.push_back(msg::kAuthenticationSucceeded);                // 0xAA05
    out.push_back(msg::kExternalAccessoryOpenSession);           // 0xEA00
    out.push_back(msg::kExternalAccessoryCloseSession);          // 0xEA01
    out.push_back(msg::kNowPlayingUpdate);                       // 0x5001
    out.push_back(msg::kRouteGuidanceUpdate);                    // 0x5201
    out.push_back(msg::kRouteGuidanceManeuverUpdate);            // 0x5202
    out.push_back(msg::kLaneGuidanceInfoUpdate);                 // 0x5204
    out.push_back(msg::kPowerUpdate);                            // 0xAE01
    out.push_back(msg::kCommunicationsUpdate);                   // 0x4158
    out.push_back(msg::kCallStateUpdate);                        // 0x4155
    out.push_back(msg::kCarPlayAvailability);                    // 0x4300
}

std::vector<uint16_t> filterMessages(const std::vector<uint16_t>& msgs,
                                     const std::vector<uint16_t>& omitted) {
    if (omitted.empty()) {
        return msgs;
    }
    std::vector<uint16_t> filtered;
    filtered.reserve(msgs.size());
    for (size_t i = 0; i < msgs.size(); ++i) {
        if (!containsU16(omitted, msgs[i])) {
            filtered.push_back(msgs[i]);
        }
    }
    return filtered;
}

bool buildIdentificationParams(const IdentificationConfig& cfg,
                               const std::vector<uint16_t>& omitted_messages,
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

    const std::vector<uint16_t> sent =
        filterMessages(cfg.messages_sent_by_accessory, omitted_messages);
    if (!sent.empty()) {
        root.addU16List(param::kIdentMessagesSentByAccessory, sent);
    }
    const std::vector<uint16_t> recvd =
        filterMessages(cfg.messages_received_from_device, omitted_messages);
    if (!recvd.empty()) {
        root.addU16List(param::kIdentMessagesReceivedFromDevice, recvd);
    }

    root.addU8(param::kIdentPowerProvidingCapability, cfg.power_providing_capability);
    root.addU16(param::kIdentMaxCurrentDrawnFromDevice, cfg.max_current_drawn_ma);

    if (cfg.ea_protocol.enabled) {
        if (cfg.ea_protocol.name.empty()) {
            setError(error_out, "EA protocol name must not be empty");
            return false;
        }
        ParameterList grp;
        grp.addU8(param::kEaProtocolId, cfg.ea_protocol.protocol_id);
        grp.addString(param::kEaProtocolName, cfg.ea_protocol.name);
        grp.addU8(param::kEaProtocolMatchAction, cfg.ea_protocol.match_action);
        root.addGroup(param::kIdentSupportedEaProtocol, grp);
    }

    if (!cfg.current_language.empty()) {
        root.addString(param::kIdentCurrentLanguage, cfg.current_language);
    }
    if (!cfg.supported_languages.empty()) {
        root.addStrings(param::kIdentSupportedLanguage, cfg.supported_languages);
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

    if (cfg.usb_host_transport.enabled) {
        ParameterList grp;
        grp.addU16(param::kTransportComponentId, cfg.usb_host_transport.component_id);
        if (!cfg.usb_host_transport.name.empty()) {
            grp.addString(param::kTransportComponentName, cfg.usb_host_transport.name);
        }
        if (cfg.usb_host_transport.supports_iap2) {
            grp.addVoid(param::kTransportSupportsIap2Connection);
        }
        grp.addU8(param::kUsbHostInterfaceNumber, cfg.usb_host_transport.interface_number);
        if (cfg.usb_host_transport.is_available) {
            grp.addVoid(param::kUsbHostIsAvailable);
        }
        root.addGroup(param::kIdentUsbHostTransportComponent, grp);
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
        if (!cfg.bluetooth_transport.transport_name.empty()) {
            grp.addString(param::kBtTransportName, cfg.bluetooth_transport.transport_name);
        }
        if (cfg.bluetooth_transport.is_available) {
            grp.addVoid(param::kBtTransportIsAvailable);
        }
        root.addGroup(param::kIdentBluetoothTransportComponent, grp);
    }

    if (cfg.wireless_carplay_transport.enabled) {
        ParameterList grp;
        grp.addU16(param::kTransportComponentId, cfg.wireless_carplay_transport.component_id);
        const std::string& ssid = !cfg.wireless_carplay_transport.ssid.empty()
            ? cfg.wireless_carplay_transport.ssid
            : cfg.wireless_carplay_transport.name;
        if (!ssid.empty()) {
            grp.addString(param::kWirelessCarPlaySsid, ssid);
        }
        if (cfg.wireless_carplay_transport.supports_iap2) {
            grp.addVoid(param::kTransportSupportsIap2Connection);
        }
        if (cfg.wireless_carplay_transport.has_transport_identifier) {
            grp.addU16(param::kWirelessCarPlayTransportIdentifier,
                       cfg.wireless_carplay_transport.transport_identifier);
        }
        if (cfg.wireless_carplay_transport.is_available) {
            grp.addVoid(param::kWirelessCarPlayIsAvailable);
        }
        if (cfg.wireless_carplay_transport.is_enabled) {
            grp.addVoid(param::kWirelessCarPlayIsEnabled);
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
        if (!cfg.vehicle_information.maps_display_name.empty()) {
            grp.addString(param::kVehicleInfoMapsDisplayName,
                          cfg.vehicle_information.maps_display_name);
        }
        for (size_t i = 0; i < cfg.vehicle_information.charging_connectors.size(); ++i) {
            grp.addU8(param::kVehicleInfoSupportedChargingConnectors,
                      cfg.vehicle_information.charging_connectors[i]);
        }
        root.addGroup(param::kIdentVehicleInformationComponent, grp);
    }

    if (cfg.vehicle_status.enabled) {
        ParameterList grp;
        grp.addU16(param::kVehicleStatusComponentId, cfg.vehicle_status.component_id);
        if (!cfg.vehicle_status.name.empty()) {
            grp.addString(param::kVehicleStatusComponentName, cfg.vehicle_status.name);
        }
        if (cfg.vehicle_status.range) {
            grp.addVoid(param::kVehicleStatusRange);
        }
        if (cfg.vehicle_status.range_warning) {
            grp.addVoid(param::kVehicleStatusRangeWarning);
        }
        if (cfg.vehicle_status.range_electric) {
            grp.addVoid(param::kVehicleStatusRangeElectric);
        }
        if (cfg.vehicle_status.range_warning_electric) {
            grp.addVoid(param::kVehicleStatusRangeWarningElectric);
        }
        if (cfg.vehicle_status.electric_charge_info) {
            grp.addVoid(param::kVehicleStatusElectricChargeInfo);
        }
        if (cfg.vehicle_status.max_range_info) {
            grp.addVoid(param::kVehicleStatusMaxRangeInfo);
        }
        root.addGroup(param::kIdentVehicleStatusComponent, grp);
    }

    if (cfg.location_information.enabled) {
        ParameterList grp;
        grp.addU16(param::kLocationComponentId, cfg.location_information.component_id);
        if (!cfg.location_information.name.empty()) {
            grp.addString(param::kLocationComponentName, cfg.location_information.name);
        }
        if (cfg.location_information.gga) {
            grp.addVoid(param::kLocationGga);
        }
        if (cfg.location_information.rmc) {
            grp.addVoid(param::kLocationRmc);
        }
        if (cfg.location_information.vehicle_speed) {
            grp.addVoid(param::kLocationVehicleSpeed);
        }
        root.addGroup(param::kIdentLocationInformationComponent, grp);
    }

    if (cfg.route_guidance_display.enabled) {
        ParameterList grp;
        grp.addU16(param::kRouteGuidanceComponentId, cfg.route_guidance_display.component_id);
        if (!cfg.route_guidance_display.name.empty()) {
            grp.addString(param::kRouteGuidanceComponentName, cfg.route_guidance_display.name);
        }
        grp.addU16(param::kRouteGuidanceMaxCurrentRoadNameLen,
                   cfg.route_guidance_display.max_current_road_name_len);
        grp.addU16(param::kRouteGuidanceMaxAfterManeuverRoadNameLen,
                   cfg.route_guidance_display.max_after_maneuver_road_name_len);
        grp.addU16(param::kRouteGuidanceMaxManeuverCapacity,
                   cfg.route_guidance_display.max_maneuver_capacity);
        grp.addU16(param::kRouteGuidanceMaxLaneDescLen,
                   cfg.route_guidance_display.max_lane_desc_len);
        grp.addU16(param::kRouteGuidanceMaxLaneStorageCapacity,
                   cfg.route_guidance_display.max_lane_storage_capacity);
        root.addGroup(param::kIdentRouteGuidanceDisplayComponent, grp);
    }

    return true;
}

void enableOptionalComponents(IdentificationConfig& cfg,
                              bool enable_location,
                              bool enable_vehicle_status,
                              bool enable_vehicle_speed) {
    if (enable_location) {
        cfg.messages_sent_by_accessory.push_back(msg::kLocationInformation);        // 0xFFFB
        cfg.messages_received_from_device.push_back(msg::kStartLocationInformation);// 0xFFFA
        cfg.messages_received_from_device.push_back(msg::kStopLocationInformation); // 0xFFFC
        cfg.location_information.enabled = true;
        cfg.location_information.component_id = 0U;
        cfg.location_information.name = cfg.name;
        cfg.location_information.gga = true;
        cfg.location_information.rmc = true;
        cfg.location_information.vehicle_speed = enable_vehicle_speed;
    }
    if (enable_vehicle_status) {
        cfg.messages_sent_by_accessory.push_back(msg::kVehicleStatusUpdate);         // 0xA101
        cfg.messages_received_from_device.push_back(msg::kStartVehicleStatusUpdates);// 0xA100
        cfg.messages_received_from_device.push_back(msg::kStopVehicleStatusUpdates); // 0xA102

        cfg.vehicle_information.enabled = true;
        cfg.vehicle_information.component_id = 3U;
        cfg.vehicle_information.name = cfg.manufacturer;
        cfg.vehicle_information.engine_types.clear();
        cfg.vehicle_information.engine_types.push_back(2U);  // Electric (Iap2VehicleStatus.kt:52)
        cfg.vehicle_information.display_name = cfg.manufacturer;
        cfg.vehicle_information.maps_display_name = cfg.manufacturer;
        cfg.vehicle_information.charging_connectors.clear();
        cfg.vehicle_information.charging_connectors.push_back(1U);  // CCS2
        cfg.vehicle_information.charging_connectors.push_back(4U);  // Type 2

        cfg.vehicle_status.enabled = true;
        cfg.vehicle_status.component_id = 4U;
        cfg.vehicle_status.name = cfg.manufacturer;
    }
}

}  // namespace

IdentificationConfig IdentificationConfig::wiredUsb(
    const std::string& name,
    const std::string& model,
    const std::string& manufacturer,
    const std::string& serial_number,
    const std::string& firmware_version,
    const std::string& hardware_version,
    uint8_t usb_interface_number,
    const std::string& language,
    const std::string& ea_protocol,
    bool enable_location,
    bool enable_vehicle_status,
    bool enable_vehicle_speed) {
    IdentificationConfig cfg;
    cfg.name = name;
    cfg.model = model;
    cfg.manufacturer = manufacturer;
    cfg.serial_number = serial_number;
    cfg.firmware_version = firmware_version;
    cfg.hardware_version = hardware_version;

    appendBaseSentMessages(cfg.messages_sent_by_accessory, true);
    appendBaseReceivedMessages(cfg.messages_received_from_device);

    cfg.power_providing_capability = kPowerCapabilityAdvanced;
    cfg.max_current_drawn_ma = 20U;

    cfg.ea_protocol.enabled = !ea_protocol.empty();
    cfg.ea_protocol.protocol_id = 1U;
    cfg.ea_protocol.name = ea_protocol;
    cfg.ea_protocol.match_action = 0U;

    cfg.current_language = language;
    if (!language.empty()) {
        cfg.supported_languages.push_back(language);
    }

    cfg.usb_host_transport.enabled = true;
    cfg.usb_host_transport.component_id = 0U;
    cfg.usb_host_transport.name = "USBHostTransport";
    cfg.usb_host_transport.supports_iap2 = true;
    cfg.usb_host_transport.interface_number = usb_interface_number;
    cfg.usb_host_transport.is_available = true;

    cfg.route_guidance_display.enabled = true;
    enableOptionalComponents(cfg, enable_location, enable_vehicle_status, enable_vehicle_speed);
    return cfg;
}

IdentificationConfig IdentificationConfig::wirelessBluetooth(
    const std::string& name,
    const std::string& model,
    const std::string& manufacturer,
    const std::string& serial_number,
    const std::string& firmware_version,
    const std::string& hardware_version,
    const std::vector<uint8_t>& bluetooth_mac,
    const std::string& ssid,
    const std::string& language,
    const std::string& ea_protocol) {
    // Matches DiPlay forWirelessLink(BLUETOOTH_BOOTSTRAP): never advertises Location or VehicleStatus
    // over Bluetooth RFCOMM so iOS does not bind them to the closing bootstrap link.
    return wirelessRuntimeTunnel(
        name,
        model,
        manufacturer,
        serial_number,
        firmware_version,
        hardware_version,
        bluetooth_mac,
        ssid,
        language,
        ea_protocol,
        false,
        false,
        false);
}

IdentificationConfig IdentificationConfig::wirelessRuntimeTunnel(
    const std::string& name,
    const std::string& model,
    const std::string& manufacturer,
    const std::string& serial_number,
    const std::string& firmware_version,
    const std::string& hardware_version,
    const std::vector<uint8_t>& bluetooth_mac,
    const std::string& ssid,
    const std::string& language,
    const std::string& ea_protocol,
    bool enable_location,
    bool enable_vehicle_status,
    bool enable_vehicle_speed) {
    IdentificationConfig cfg;
    cfg.name = name;
    cfg.model = model;
    cfg.manufacturer = manufacturer;
    cfg.serial_number = serial_number;
    cfg.firmware_version = firmware_version;
    cfg.hardware_version = hardware_version;

    appendBaseSentMessages(cfg.messages_sent_by_accessory, false);
    cfg.messages_sent_by_accessory.push_back(msg::kAccessoryWiFiConfiguration);  // 0x5703

    appendBaseReceivedMessages(cfg.messages_received_from_device);
    cfg.messages_received_from_device.push_back(msg::kWirelessCarPlayUpdate);            // 0x4E0D
    cfg.messages_received_from_device.push_back(msg::kDeviceTransportIdentifier);        // 0x4E0E
    cfg.messages_received_from_device.push_back(msg::kRequestAccessoryWiFiConfiguration);// 0x5702

    cfg.power_providing_capability = kPowerCapabilityNone;
    cfg.max_current_drawn_ma = 20U;

    cfg.ea_protocol.enabled = !ea_protocol.empty();
    cfg.ea_protocol.protocol_id = 1U;
    cfg.ea_protocol.name = ea_protocol;
    cfg.ea_protocol.match_action = 0U;

    cfg.current_language = language;
    if (!language.empty()) {
        cfg.supported_languages.push_back(language);
    }

    cfg.bluetooth_transport.enabled = true;
    cfg.bluetooth_transport.component_id = 0U;
    cfg.bluetooth_transport.name = "blue";
    cfg.bluetooth_transport.supports_iap2 = true;
    cfg.bluetooth_transport.mac_address = bluetooth_mac;
    cfg.bluetooth_transport.transport_name = "blue";
    cfg.bluetooth_transport.is_available = true;

    cfg.wireless_carplay_transport.enabled = true;
    cfg.wireless_carplay_transport.component_id = 1U;
    cfg.wireless_carplay_transport.ssid = ssid;
    cfg.wireless_carplay_transport.supports_iap2 = true;
    cfg.wireless_carplay_transport.has_transport_identifier = true;
    cfg.wireless_carplay_transport.transport_identifier = 1U;
    cfg.wireless_carplay_transport.is_available = true;
    cfg.wireless_carplay_transport.is_enabled = true;

    cfg.route_guidance_display.enabled = true;
    enableOptionalComponents(cfg, enable_location, enable_vehicle_status, enable_vehicle_speed);
    return cfg;
}

SessionConfig SessionConfig::wiredUsb(const IdentificationConfig& ident,
                                      uint16_t available_current_ma,
                                      const StartSessionConfig* start_session_cfg) {
    SessionConfig cfg;
    cfg.link = LinkConfig::wiredUsb();
    cfg.identification = ident;
    cfg.control_mode = kTransportControlWired;
    cfg.wired_available_current_ma = available_current_ma;
    if (start_session_cfg != NULL) {
        cfg.has_start_session = true;
        cfg.start_session = *start_session_cfg;
    }
    return cfg;
}

SessionConfig SessionConfig::wirelessBluetooth(const IdentificationConfig& ident,
                                               const WiFiConfiguration* wifi_cfg,
                                               const StartSessionConfig* start_session_cfg) {
    SessionConfig cfg;
    cfg.link = LinkConfig::wirelessBluetooth();
    cfg.identification = ident;
    cfg.control_mode = kTransportControlWireless;
    if (wifi_cfg != NULL) {
        cfg.has_wifi_config = true;
        cfg.wifi_config = *wifi_cfg;
    }
    if (start_session_cfg != NULL) {
        cfg.has_start_session = true;
        cfg.start_session = *start_session_cfg;
    }
    return cfg;
}

SessionConfig SessionConfig::wirelessTunnel(const IdentificationConfig& ident,
                                            const StartSessionConfig* start_session_cfg) {
    SessionConfig cfg;
    cfg.link = LinkConfig::wirelessTunnel();
    cfg.identification = ident;
    cfg.control_mode = kTransportControlWireless;
    if (start_session_cfg != NULL) {
        cfg.has_start_session = true;
        cfg.start_session = *start_session_cfg;
    }
    return cfg;
}

bool buildIdentificationInformation(const IdentificationConfig& cfg,
                                    Frame& frame_out,
                                    std::string* error_out) {
    const std::vector<uint16_t> empty;
    return buildIdentificationInformation(cfg, empty, frame_out, error_out);
}

bool buildIdentificationInformation(const IdentificationConfig& cfg,
                                    const std::vector<uint16_t>& omitted_messages,
                                    Frame& frame_out,
                                    std::string* error_out) {
    ParameterList root;
    if (!buildIdentificationParams(cfg, omitted_messages, root, error_out)) {
        return false;
    }
    return Frame::build(msg::kIdentificationInformation, root, frame_out, error_out);
}

bool buildIdentificationUpdate(const IdentificationConfig& cfg,
                               Frame& frame_out,
                               std::string* error_out) {
    ParameterList root;
    const std::vector<uint16_t> empty;
    if (!buildIdentificationParams(cfg, empty, root, error_out)) {
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
      vehicle_status_updates_active_(false),
      ident_retry_attempted_(false),
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

void Session::advanceWirelessStage(WirelessControlStage next) {
    if (static_cast<int>(wireless_status_.stage) < static_cast<int>(next)) {
        wireless_status_.stage = next;
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
    vehicle_status_updates_active_ = false;
    ident_retry_attempted_ = false;
    omitted_messages_.clear();
    wireless_status_ = WirelessControlStatus();
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
    vehicle_status_updates_active_ = false;
    ident_retry_attempted_ = false;
    omitted_messages_.clear();
    wireless_status_ = WirelessControlStatus();
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
    vehicle_status_updates_active_ = false;
    ident_retry_attempted_ = false;
    omitted_messages_.clear();
    wireless_status_ = WirelessControlStatus();
    setState(kSessionConnected);
}

void Session::onLinkResetImpl(bool by_peer) {
    framer_.reset();
    control_session_id_ = 0;
    identified_ = false;
    authenticated_ = false;
    power_updates_active_ = false;
    location_updates_active_ = false;
    vehicle_status_updates_active_ = false;
    ident_retry_attempted_ = false;
    omitted_messages_.clear();
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

bool Session::sendStandardSubscriptions() {
    if (!isReady()) {
        return false;
    }
    std::vector<Frame> subs;
    std::string err;
    if (!buildStandardSubscriptions(subs, &err)) {
        listener_.onError(err);
        return false;
    }
    for (size_t i = 0; i < subs.size(); ++i) {
        if (!sendControlMessage(subs[i])) {
            return false;
        }
    }
    if (!power_updates_active_) {
        power_updates_active_ = true;
        listener_.onPowerUpdatesChanged(true);
    }
    return true;
}

bool Session::sendStartPowerUpdates() {
    if (!isReady()) {
        return false;
    }
    Frame frame;
    std::string err;
    if (!buildStartPowerUpdates(frame, &err)) {
        listener_.onError(err);
        return false;
    }
    if (!sendControlMessage(frame)) {
        return false;
    }
    if (!power_updates_active_) {
        power_updates_active_ = true;
        listener_.onPowerUpdatesChanged(true);
    }
    return true;
}

bool Session::sendStopPowerUpdates() {
    if (!isReady()) {
        return false;
    }
    Frame frame(msg::kStopPowerUpdates, std::vector<uint8_t>());
    if (!sendControlMessage(frame)) {
        return false;
    }
    if (power_updates_active_) {
        power_updates_active_ = false;
        listener_.onPowerUpdatesChanged(false);
    }
    return true;
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
    if (!sendControlMessage(frame)) {
        return false;
    }
    ++wireless_status_.carplay_start_sessions_sent;
    advanceWirelessStage(kWirelessStageCarPlayStartSent);
    return true;
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

void Session::enterReadyState() {
    setState(kSessionReady);
    if (state_ != kSessionReady) {
        return;
    }
    if (config_.control_mode == kTransportControlWired) {
        if (!sendPowerSourceUpdate(config_.wired_available_current_ma, true, true)) {
            return;
        }
        if (!sendStandardSubscriptions()) {
            return;
        }
        advanceWirelessStage(kWirelessStageSubscribed);
    } else if (config_.control_mode == kTransportControlWireless) {
        if (!sendStandardSubscriptions()) {
            return;
        }
        advanceWirelessStage(kWirelessStageSubscribed);
    }
    listener_.onReady();
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
        case msg::kCarPlayAvailability:
            handleCarPlayAvailability(frame);
            return;
        case msg::kWirelessCarPlayUpdate: {
            bool available = false;
            if (!parseWirelessCarPlayAvailability(frame, available, &err)) {
                listener_.onError(err);
                return;
            }
            if (available) {
                wireless_status_.wireless_carplay_available_seen = true;
            }
            listener_.onWirelessCarPlayAvailability(available);
            return;
        }
        case msg::kDeviceTransportIdentifier:
            handleDeviceTransportIdentifier(frame);
            return;
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
        case msg::kPowerUpdate:
            listener_.onPowerUpdate(frame);
            return;
        case msg::kStartLocationInformation:
            location_updates_active_ = true;
            listener_.onLocationUpdatesChanged(true);
            return;
        case msg::kStopLocationInformation:
            location_updates_active_ = false;
            listener_.onLocationUpdatesChanged(false);
            return;
        case msg::kStartVehicleStatusUpdates:
            vehicle_status_updates_active_ = true;
            listener_.onVehicleStatusUpdatesChanged(true);
            return;
        case msg::kStopVehicleStatusUpdates:
            vehicle_status_updates_active_ = false;
            listener_.onVehicleStatusUpdatesChanged(false);
            return;
        default:
            listener_.onUnhandledMessage(frame);
            return;
    }
}

void Session::handleStartIdentification() {
    Frame frame;
    std::string err;
    if (!buildIdentificationInformation(config_.identification, omitted_messages_, frame, &err)) {
        failSession(err);
        return;
    }
    setState(kSessionIdentifying);
    sendControlMessage(frame);
}

void Session::handleIdentificationAccepted() {
    identified_ = true;
    advanceWirelessStage(kWirelessStageIdentified);
    listener_.onIdentificationAccepted();
    if (state_ == kSessionFailed || state_ == kSessionIdle) {
        return;
    }
    if (authenticated_) {
        advanceWirelessStage(kWirelessStageAuthenticated);
        enterReadyState();
    } else {
        setState(kSessionIdentified);
    }
}

void Session::handleIdentificationRejected(const Frame& frame) {
    identified_ = false;
    std::vector<uint16_t> rejected_params;
    std::vector<uint16_t> unsupported_msgs;
    bool only_msg_lists = false;
    bool malformed_msg_list = false;

    ParameterList params;
    if (ParameterList::decode(frame.payload, params, NULL)) {
        const std::vector<Parameter>& items = params.items();
        only_msg_lists = !items.empty();
        for (size_t i = 0; i < items.size(); ++i) {
            const Parameter& item = items[i];
            if (item.id == param::kIdentMessagesSentByAccessory ||
                item.id == param::kIdentMessagesReceivedFromDevice) {
                if (!containsU16(rejected_params, item.id)) {
                    rejected_params.push_back(item.id);
                }
                if (item.payload.empty() || (item.payload.size() % 2U) != 0U) {
                    malformed_msg_list = true;
                } else {
                    for (size_t off = 0; off + 1U < item.payload.size(); off += 2U) {
                        const uint16_t msg_id = readU16Be(&item.payload[off]);
                        if (isAuthMessage(msg_id)) {
                            malformed_msg_list = true;
                        }
                        if (!containsU16(unsupported_msgs, msg_id)) {
                            if (unsupported_msgs.size() >= kMaxRejectedMessageIds) {
                                malformed_msg_list = true;
                                break;
                            }
                            unsupported_msgs.push_back(msg_id);
                        }
                    }
                }
            } else {
                only_msg_lists = false;
                rejected_params.push_back(item.id);
            }
        }
    }

    if (config_.retry_identification_on_unsupported_messages &&
        !ident_retry_attempted_ &&
        only_msg_lists &&
        !malformed_msg_list &&
        !unsupported_msgs.empty()) {
        ident_retry_attempted_ = true;
        std::sort(unsupported_msgs.begin(), unsupported_msgs.end());
        omitted_messages_ = unsupported_msgs;
        Frame retry_frame;
        std::string err;
        if (!buildIdentificationInformation(config_.identification,
                                            omitted_messages_,
                                            retry_frame,
                                            &err)) {
            failSession(err);
            return;
        }
        listener_.onIdentificationRetry(omitted_messages_);
        setState(kSessionIdentifying);
        sendControlMessage(retry_frame);
        return;
    }

    setState(kSessionFailed);
    listener_.onIdentificationRejected(rejected_params);
    listener_.onError("iAP2 identification rejected by device");
}

void Session::handleCancelIdentification() {
    identified_ = false;
    ident_retry_attempted_ = false;
    omitted_messages_.clear();
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
    if (!auth_.getCertificate(cert) || cert.empty() || cert.size() > kMaxCertificateBytes) {
        const std::string msg = "failed to retrieve valid accessory authentication certificate";
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
    if (!params.readBytes(param::kAuthChallengeData, challenge) ||
        challenge.empty() ||
        challenge.size() > kMaxChallengeBytes) {
        const std::string msg = "missing or invalid authentication challenge";
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
    advanceWirelessStage(kWirelessStageAuthenticated);
    listener_.onAuthenticationSucceeded();
    if (state_ == kSessionFailed || state_ == kSessionIdle) {
        return;
    }
    if (identified_) {
        enterReadyState();
    } else {
        setState(kSessionAuthenticated);
    }
}

bool Session::resolveWiFiConfiguration(WiFiConfiguration& out) {
    if (listener_.onWiFiCredentialsRequested(out)) {
        return true;
    }
    if (config_.has_wifi_config) {
        out = config_.wifi_config;
        return true;
    }
    return false;
}

bool Session::sendWiFiConfiguration(const WiFiConfiguration& wifi_cfg, bool post_transport) {
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
        return false;
    }
    if (!sendControlMessage(frame)) {
        return false;
    }
    ++wireless_status_.wifi_configs_sent;
    if (post_transport) {
        ++wireless_status_.post_transport_wifi_configs_sent;
        advanceWirelessStage(kWirelessStagePostTransportWiFiConfigSent);
    } else {
        ++wireless_status_.pre_transport_wifi_configs_sent;
        advanceWirelessStage(kWirelessStageWiFiConfigSent);
    }
    return true;
}

void Session::handleRequestAccessoryWiFiConfig() {
    if (config_.control_mode == kTransportControlWireless) {
        const bool post_transport = wireless_status_.transport_notification_seen;
        const uint32_t sent_count = post_transport
            ? wireless_status_.post_transport_wifi_configs_sent
            : wireless_status_.pre_transport_wifi_configs_sent;
        const uint32_t limit = post_transport
            ? kMaxPostTransportWiFiConfigSends
            : kMaxPreTransportWiFiConfigSends;
        if (sent_count >= limit) {
            return;
        }
        WiFiConfiguration wifi_cfg;
        if (!resolveWiFiConfiguration(wifi_cfg)) {
            listener_.onError("Wi-Fi credentials requested (0x5702) but listener declined");
            return;
        }
        sendWiFiConfiguration(wifi_cfg, post_transport);
        return;
    }

    WiFiConfiguration wifi_cfg;
    if (!resolveWiFiConfiguration(wifi_cfg)) {
        listener_.onError("Wi-Fi credentials requested (0x5702) but listener declined");
        return;
    }
    sendWiFiConfiguration(wifi_cfg, wireless_status_.transport_notification_seen);
}

void Session::handleDeviceTransportIdentifier(const Frame& frame) {
    DeviceTransportIdentifier tid;
    std::string err;
    if (!parseDeviceTransportIdentifier(frame, tid, &err)) {
        listener_.onError(err);
        return;
    }
    wireless_status_.transport_notification_seen = true;
    advanceWirelessStage(kWirelessStageTransportNotified);
    listener_.onDeviceTransportIdentifier(tid);

    if (config_.control_mode == kTransportControlWireless &&
        isReady() &&
        wireless_status_.post_transport_wifi_configs_sent < kMaxPostTransportWiFiConfigSends) {
        WiFiConfiguration wifi_cfg;
        if (resolveWiFiConfiguration(wifi_cfg)) {
            sendWiFiConfiguration(wifi_cfg, true);
        }
    }
}

void Session::handleCarPlayAvailability(const Frame& frame) {
    CarPlayAvailability avail;
    std::string err;
    if (!parseCarPlayAvailability(frame, avail, &err)) {
        listener_.onError(err);
        return;
    }
    listener_.onCarPlayAvailability(avail);

    if (config_.control_mode == kTransportControlWired ||
        config_.control_mode == kTransportControlWireless) {
        StartSessionConfig start_cfg;
        bool have_cfg = listener_.onCarPlayStartSessionRequested(avail, start_cfg);
        if (!have_cfg && config_.has_start_session) {
            start_cfg = config_.start_session;
            have_cfg = true;
        }
        if (have_cfg && isReady()) {
            sendStartCarPlaySession(start_cfg);
        }
    }
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
