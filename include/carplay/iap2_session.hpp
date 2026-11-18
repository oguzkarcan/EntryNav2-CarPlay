#ifndef CARPLAY_IAP2_SESSION_HPP
#define CARPLAY_IAP2_SESSION_HPP

// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/iap2/catalog/Iap2Endpoint.kt,
//  shared/src/main/java/com/shilapi/xcertplay/transport/Iap2IdentificationClient.kt,
//  shared/src/main/java/com/shilapi/xcertplay/transport/Iap2WiredControlClient.kt,
//  shared/src/main/java/com/shilapi/xcertplay/transport/Iap2WirelessControlClient.kt,
//  shared/src/main/java/com/shilapi/xcertplay/transport/Iap2VehicleStatus.kt,
//  shared/src/main/java/com/shilapi/xcertplay/transport/Iap2LocationClient.kt,
//  shared/src/main/java/com/shilapi/xcertplay/mfi/Iap2MfiAuthenticationClient.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.
//
// Transport-agnostic iAP2 Control Session state machine layered on top of
// carplay::iap2::Link, CsmFramer/ParameterList codecs, and AuthProvider.
//
// Supports both standard iAP2 phase orderings:
//   - detect -> link sync -> identification -> authentication -> post-auth
//   - detect -> link sync -> authentication -> identification -> post-auth
//
// Also supports DiPlay-verified wired USB and wireless Bluetooth / Type-130
// tunnel control flows (proactive subscriptions, 0x1D03 retry without
// unsupported messages, 0x5702/0x5703 caps, 0x4E0E post-transport Wi-Fi resend,
// and automatic 0x4300 -> 0x4301 CarPlay start-session handshake).
//
// No internal clock, sockets, or threads. Timeouts and link retransmissions
// are driven deterministically via tick(now_ms).

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/auth_provider.hpp"
#include "carplay/iap2_link.hpp"
#include "carplay/iap2_wire.hpp"

namespace carplay {
namespace iap2 {

/// Consolidated table of iAP2 parameter IDs not already defined in iap2_wire.hpp.
/// Verified entries cite DiPlay source files/lines; remaining constants stay marked
/// "unverified".
namespace param {

// IdentificationInformation (0x1D01) / IdentificationInformationUpdate (0x1D06)
static const uint16_t kIdentName = 0U;                              // verified: DiPlay Iap2Endpoint.kt:82 (UTF-8 string)
static const uint16_t kIdentModelIdentifier = 1U;                   // verified: DiPlay Iap2Endpoint.kt:83 (UTF-8 string)
static const uint16_t kIdentManufacturer = 2U;                      // verified: DiPlay Iap2Endpoint.kt:84 (UTF-8 string)
static const uint16_t kIdentSerialNumber = 3U;                      // verified: DiPlay Iap2Endpoint.kt:85 (UTF-8 string)
static const uint16_t kIdentFirmwareVersion = 4U;                   // verified: DiPlay Iap2Endpoint.kt:86 (UTF-8 string)
static const uint16_t kIdentHardwareVersion = 5U;                   // verified: DiPlay Iap2Endpoint.kt:87 (UTF-8 string)
static const uint16_t kIdentMessagesSentByAccessory = 6U;           // verified: DiPlay Iap2Endpoint.kt:88 (packed u16 BE list)
static const uint16_t kIdentMessagesReceivedFromDevice = 7U;        // verified: DiPlay Iap2Endpoint.kt:89 (packed u16 BE list)
static const uint16_t kIdentPowerProvidingCapability = 8U;          // verified: DiPlay Iap2Endpoint.kt:90 (u8 enum)
static const uint16_t kIdentMaxCurrentDrawnFromDevice = 9U;         // verified: DiPlay Iap2Endpoint.kt:91 (u16 mA)
static const uint16_t kIdentSupportedEaProtocol = 10U;              // verified: DiPlay Iap2Endpoint.kt:92 (group)
static const uint16_t kIdentAppMatchTeamId = 11U;                   // unverified (not used in DiPlay)
static const uint16_t kIdentCurrentLanguage = 12U;                  // verified: DiPlay Iap2Endpoint.kt:93 (UTF-8 string)
static const uint16_t kIdentSupportedLanguage = 13U;                // verified: DiPlay Iap2Endpoint.kt:94 (NUL-separated UTF-8 STRING_LIST)
static const uint16_t kIdentSerialTransportComponent = 14U;         // unverified (not used in DiPlay)
static const uint16_t kIdentUsbDeviceTransportComponent = 15U;      // unverified (not used in DiPlay)
static const uint16_t kIdentUsbHostTransportComponent = 16U;        // verified: DiPlay Iap2Endpoint.kt:96 (group)
static const uint16_t kIdentBluetoothTransportComponent = 17U;      // verified: DiPlay Iap2Endpoint.kt:108 (group)
static const uint16_t kIdentHidComponent = 18U;                     // unverified (not used in DiPlay)
static const uint16_t kIdentVehicleInformationComponent = 20U;      // verified: DiPlay Iap2Endpoint.kt:120 (group)
static const uint16_t kIdentVehicleStatusComponent = 21U;           // verified: DiPlay Iap2Endpoint.kt:121 (group)
static const uint16_t kIdentLocationInformationComponent = 22U;     // verified: DiPlay Iap2Endpoint.kt:122 (group)
static const uint16_t kIdentWirelessCarPlayTransportComponent = 24U;// verified: DiPlay Iap2Endpoint.kt:124 (group; corrected from 34U)
static const uint16_t kIdentRouteGuidanceDisplayComponent = 30U;    // verified: DiPlay Iap2Endpoint.kt:137 (group)

// SupportedExternalAccessoryProtocol sub-parameters (inside group 10)
static const uint16_t kEaProtocolId = 0U;                           // verified: DiPlay Iap2IdentificationClient.kt:348 (u8)
static const uint16_t kEaProtocolName = 1U;                         // verified: DiPlay Iap2IdentificationClient.kt:349 (UTF-8 string)
static const uint16_t kEaProtocolMatchAction = 2U;                  // verified: DiPlay Iap2IdentificationClient.kt:350 (u8)

// Transport Component sub-parameters (inside groups 15, 16, 17, 24)
static const uint16_t kTransportComponentId = 0U;                   // verified: DiPlay Iap2Endpoint.kt:100,112,128 (u16)
static const uint16_t kTransportComponentName = 1U;                 // verified: DiPlay Iap2Endpoint.kt:101,113 (UTF-8 string)
static const uint16_t kTransportSupportsIap2Connection = 2U;        // verified: DiPlay Iap2Endpoint.kt:102,114,130 (void)
static const uint16_t kUsbDeviceSupportedAudioSampleRate = 3U;      // unverified (group 15 not used in DiPlay)
static const uint16_t kUsbHostInterfaceNumber = 3U;                 // verified: DiPlay Iap2Endpoint.kt:103 (u8)
static const uint16_t kUsbHostIsAvailable = 4U;                     // verified: DiPlay Iap2Endpoint.kt:104 (void)
static const uint16_t kBtTransportMacAddress = 3U;                  // verified: DiPlay Iap2Endpoint.kt:115 (6-byte MAC)
static const uint16_t kBtTransportName = 4U;                        // verified: DiPlay Iap2Endpoint.kt:116 (UTF-8 string)
static const uint16_t kBtTransportIsAvailable = 5U;                 // verified: DiPlay Iap2Endpoint.kt:117 (void)
static const uint16_t kWirelessCarPlaySsid = 1U;                    // verified: DiPlay Iap2Endpoint.kt:129 (UTF-8 string)
static const uint16_t kWirelessCarPlayTransportIdentifier = 3U;     // verified: DiPlay Iap2Endpoint.kt:131 (u16; replaces void kWirelessCarPlaySupportsCarPlay)
static const uint16_t kWirelessCarPlayIsAvailable = 4U;             // verified: DiPlay Iap2Endpoint.kt:132 (void)
static const uint16_t kWirelessCarPlayIsEnabled = 5U;               // verified: DiPlay Iap2Endpoint.kt:133 (void)

// VehicleInformationComponent sub-parameters (inside group 20)
static const uint16_t kVehicleInfoComponentId = 0U;                 // verified: DiPlay Iap2VehicleStatus.kt:57 (u16)
static const uint16_t kVehicleInfoComponentName = 1U;               // verified: DiPlay Iap2VehicleStatus.kt:58 (UTF-8 string)
static const uint16_t kVehicleInfoEngineType = 2U;                  // verified: DiPlay Iap2VehicleStatus.kt:59 (u8 repeated)
static const uint16_t kVehicleInfoDisplayName = 6U;                 // verified: DiPlay Iap2VehicleStatus.kt:60 (UTF-8 string; corrected from 3U)
static const uint16_t kVehicleInfoMapsDisplayName = 8U;             // verified: DiPlay Iap2VehicleStatus.kt:61 (UTF-8 string)
static const uint16_t kVehicleInfoSupportedChargingConnectors = 11U;// verified: DiPlay Iap2VehicleStatus.kt:62 (u8 repeated)

// VehicleStatusComponent sub-parameters (inside group 21)
static const uint16_t kVehicleStatusComponentId = 0U;               // verified: DiPlay Iap2VehicleStatus.kt:65 (u16)
static const uint16_t kVehicleStatusComponentName = 1U;             // verified: DiPlay Iap2VehicleStatus.kt:66 (UTF-8 string)
static const uint16_t kVehicleStatusRange = 3U;                     // verified: DiPlay Iap2VehicleStatus.kt:67 (void)
static const uint16_t kVehicleStatusRangeWarning = 6U;              // verified: DiPlay Iap2VehicleStatus.kt:68 (void)
static const uint16_t kVehicleStatusRangeElectric = 11U;            // verified: DiPlay Iap2VehicleStatus.kt:69 (void)
static const uint16_t kVehicleStatusRangeWarningElectric = 15U;     // verified: DiPlay Iap2VehicleStatus.kt:70 (void)
static const uint16_t kVehicleStatusElectricChargeInfo = 21U;       // verified: DiPlay Iap2VehicleStatus.kt:71 (void)
static const uint16_t kVehicleStatusMaxRangeInfo = 30U;             // verified: DiPlay Iap2VehicleStatus.kt:72 (void)

// LocationInformationComponent sub-parameters (inside group 22)
static const uint16_t kLocationComponentId = 0U;                    // verified: DiPlay Iap2IdentificationClient.kt:383 (u16)
static const uint16_t kLocationComponentName = 1U;                  // verified: DiPlay Iap2IdentificationClient.kt:384 (UTF-8 string)
static const uint16_t kLocationGga = 17U;                           // verified: DiPlay Iap2IdentificationClient.kt:385 (void, GPGGA)
static const uint16_t kLocationRmc = 18U;                           // verified: DiPlay Iap2IdentificationClient.kt:386 (void, GPRMC)
static const uint16_t kLocationVehicleSpeed = 20U;                  // verified: DiPlay Iap2IdentificationClient.kt:387 (void, $PASCD)

// RouteGuidanceDisplayComponent sub-parameters (inside group 30)
static const uint16_t kRouteGuidanceComponentId = 0U;               // verified: DiPlay Iap2Endpoint.kt:141 (u16)
static const uint16_t kRouteGuidanceComponentName = 1U;             // verified: DiPlay Iap2Endpoint.kt:142 (UTF-8 string)
static const uint16_t kRouteGuidanceMaxCurrentRoadNameLen = 2U;     // verified: DiPlay Iap2Endpoint.kt:143 (u16)
static const uint16_t kRouteGuidanceMaxAfterManeuverRoadNameLen = 4U;// verified: DiPlay Iap2Endpoint.kt:144 (u16)
static const uint16_t kRouteGuidanceMaxManeuverCapacity = 6U;       // verified: DiPlay Iap2Endpoint.kt:145 (u16)
static const uint16_t kRouteGuidanceMaxLaneDescLen = 7U;            // verified: DiPlay Iap2Endpoint.kt:148 (u16)
static const uint16_t kRouteGuidanceMaxLaneStorageCapacity = 8U;    // verified: DiPlay Iap2Endpoint.kt:149 (u16)

// Authentication (0xAA01, 0xAA02, 0xAA03, 0xAA06)
static const uint16_t kAuthCertificateData = 0U;                    // verified: DiPlay Iap2Endpoint.kt:190 (DER bytes)
static const uint16_t kAuthChallengeData = 0U;                      // verified: DiPlay Iap2Endpoint.kt:197 (challenge bytes)
static const uint16_t kAuthChallengeResponseData = 0U;              // verified: DiPlay Iap2Endpoint.kt:204 (signature bytes)
static const uint16_t kAuthCertificateSerial = 0U;                  // unverified (0xAA06 has no fields in DiPlay Iap2Endpoint.kt:218)

}  // namespace param

enum PowerCapability {
    kPowerCapabilityNone = 0,
    kPowerCapabilityReserved = 1,
    kPowerCapabilityAdvanced = 2
};

struct EaProtocolConfig {
    bool enabled;
    uint8_t protocol_id;
    std::string name;
    uint8_t match_action;

    EaProtocolConfig()
        : enabled(false), protocol_id(1U), match_action(0U) {}
};

struct UsbHostTransportConfig {
    bool enabled;
    uint16_t component_id;
    std::string name;
    bool supports_iap2;
    uint8_t interface_number;
    bool is_available;

    UsbHostTransportConfig()
        : enabled(false),
          component_id(0U),
          name("USBHostTransport"),
          supports_iap2(true),
          interface_number(0U),
          is_available(true) {}
};

struct UsbDeviceTransportConfig {
    bool enabled;
    uint16_t component_id;
    std::string name;
    bool supports_iap2;
    std::vector<uint8_t> audio_sample_rates;

    UsbDeviceTransportConfig()
        : enabled(false), component_id(1), supports_iap2(true) {}
};

struct BluetoothTransportConfig {
    bool enabled;
    uint16_t component_id;
    std::string name;
    bool supports_iap2;
    std::vector<uint8_t> mac_address;  // 6 bytes when present
    std::string transport_name;
    bool is_available;

    BluetoothTransportConfig()
        : enabled(false),
          component_id(0),
          supports_iap2(true),
          is_available(false) {}
};

struct WirelessCarPlayTransportConfig {
    bool enabled;
    uint16_t component_id;
    std::string ssid;
    std::string name;  // fallback for ssid if ssid is empty
    bool supports_iap2;
    bool has_transport_identifier;
    uint16_t transport_identifier;
    bool is_available;
    bool is_enabled;

    WirelessCarPlayTransportConfig()
        : enabled(false),
          component_id(1),
          supports_iap2(true),
          has_transport_identifier(true),
          transport_identifier(1),
          is_available(true),
          is_enabled(true) {}
};

struct VehicleInformationConfig {
    bool enabled;
    uint16_t component_id;
    std::string name;
    std::string display_name;
    std::string maps_display_name;
    std::vector<uint8_t> engine_types;
    std::vector<uint8_t> charging_connectors;

    VehicleInformationConfig()
        : enabled(false), component_id(3) {}
};

struct VehicleStatusConfig {
    bool enabled;
    uint16_t component_id;
    std::string name;
    bool range;
    bool range_warning;
    bool range_electric;
    bool range_warning_electric;
    bool electric_charge_info;
    bool max_range_info;

    VehicleStatusConfig()
        : enabled(false),
          component_id(4),
          range(true),
          range_warning(true),
          range_electric(true),
          range_warning_electric(true),
          electric_charge_info(true),
          max_range_info(true) {}
};

struct LocationInformationConfig {
    bool enabled;
    uint16_t component_id;
    std::string name;
    bool gga;
    bool rmc;
    bool vehicle_speed;

    LocationInformationConfig()
        : enabled(false),
          component_id(0),
          gga(true),
          rmc(true),
          vehicle_speed(false) {}
};

struct RouteGuidanceDisplayConfig {
    bool enabled;
    uint16_t component_id;
    std::string name;
    uint16_t max_current_road_name_len;
    uint16_t max_after_maneuver_road_name_len;
    uint16_t max_maneuver_capacity;
    uint16_t max_lane_desc_len;
    uint16_t max_lane_storage_capacity;

    RouteGuidanceDisplayConfig()
        : enabled(false),
          component_id(42U),
          name("RouteGuidance"),
          max_current_road_name_len(64U),
          max_after_maneuver_road_name_len(64U),
          max_maneuver_capacity(8U),
          max_lane_desc_len(64U),
          max_lane_storage_capacity(8U) {}
};

struct IdentificationConfig {
    std::string name;
    std::string model;
    std::string manufacturer;
    std::string serial_number;
    std::string firmware_version;
    std::string hardware_version;

    std::vector<uint16_t> messages_sent_by_accessory;
    std::vector<uint16_t> messages_received_from_device;

    uint8_t power_providing_capability;
    uint16_t max_current_drawn_ma;

    EaProtocolConfig ea_protocol;

    std::string current_language;
    std::vector<std::string> supported_languages;

    UsbHostTransportConfig usb_host_transport;
    UsbDeviceTransportConfig usb_device_transport;
    BluetoothTransportConfig bluetooth_transport;
    WirelessCarPlayTransportConfig wireless_carplay_transport;
    VehicleInformationConfig vehicle_information;
    VehicleStatusConfig vehicle_status;
    LocationInformationConfig location_information;
    RouteGuidanceDisplayConfig route_guidance_display;

    IdentificationConfig()
        : power_providing_capability(kPowerCapabilityNone),
          max_current_drawn_ma(0) {}

    /// Wired USB identification preset matching DiPlay Iap2IdentificationClient.kt.
    static IdentificationConfig wiredUsb(
        const std::string& name,
        const std::string& model,
        const std::string& manufacturer,
        const std::string& serial_number,
        const std::string& firmware_version,
        const std::string& hardware_version,
        uint8_t usb_interface_number = 0U,
        const std::string& language = "en",
        const std::string& ea_protocol = "com.shilapi.xcertplay",
        bool enable_location = false,
        bool enable_vehicle_status = false,
        bool enable_vehicle_speed = false);

    /// Wireless Bluetooth RFCOMM bootstrap preset matching DiPlay BLUETOOTH_BOOTSTRAP.
    /// Deliberately omits Location/VehicleStatus so iOS does not bind them to RFCOMM.
    static IdentificationConfig wirelessBluetooth(
        const std::string& name,
        const std::string& model,
        const std::string& manufacturer,
        const std::string& serial_number,
        const std::string& firmware_version,
        const std::string& hardware_version,
        const std::vector<uint8_t>& bluetooth_mac,
        const std::string& ssid,
        const std::string& language = "en",
        const std::string& ea_protocol = "com.shilapi.xcertplay");

    /// Wireless Wi-Fi Type-130 runtime tunnel preset matching DiPlay RUNTIME_TUNNEL.
    static IdentificationConfig wirelessRuntimeTunnel(
        const std::string& name,
        const std::string& model,
        const std::string& manufacturer,
        const std::string& serial_number,
        const std::string& firmware_version,
        const std::string& hardware_version,
        const std::vector<uint8_t>& bluetooth_mac,
        const std::string& ssid,
        const std::string& language = "en",
        const std::string& ea_protocol = "com.shilapi.xcertplay",
        bool enable_location = false,
        bool enable_vehicle_status = false,
        bool enable_vehicle_speed = false);
};

struct WiFiConfiguration {
    std::string ssid;
    std::string passphrase;
    uint8_t channel;
    uint8_t security_type;
    std::vector<uint8_t> bssid;  // optional 6-byte BSSID

    WiFiConfiguration() : channel(0), security_type(0) {}
};

enum SessionState {
    kSessionIdle = 0,
    kSessionDetecting,
    kSessionSyncing,
    kSessionConnected,       // Link synced; awaiting StartIdentification or Auth
    kSessionIdentifying,     // IdentificationInformation sent; awaiting Accepted/Rejected
    kSessionIdentified,      // IdentificationAccepted received; awaiting Auth
    kSessionAuthenticating,  // Auth certificate/challenge in progress
    kSessionAuthenticated,   // AuthenticationSucceeded received; awaiting Identification
    kSessionReady,           // Both identified & authenticated; post-auth active
    kSessionFailed
};

enum TransportControlMode {
    kTransportControlManual = 0,
    kTransportControlWired = 1,
    kTransportControlWireless = 2
};

/// Post-auth control progress matching DiPlay Iap2WirelessControlStage.
enum WirelessControlStage {
    kWirelessStageIdle = 0,
    kWirelessStageIdentified,
    kWirelessStageAuthenticated,
    kWirelessStageSubscribed,
    kWirelessStageWiFiConfigSent,
    kWirelessStageCarPlayStartSent,
    kWirelessStageTransportNotified,
    kWirelessStagePostTransportWiFiConfigSent
};

struct WirelessControlStatus {
    WirelessControlStage stage;
    uint32_t wifi_configs_sent;
    uint32_t pre_transport_wifi_configs_sent;
    uint32_t post_transport_wifi_configs_sent;
    uint32_t carplay_start_sessions_sent;
    bool transport_notification_seen;
    bool wireless_carplay_available_seen;

    WirelessControlStatus()
        : stage(kWirelessStageIdle),
          wifi_configs_sent(0),
          pre_transport_wifi_configs_sent(0),
          post_transport_wifi_configs_sent(0),
          carplay_start_sessions_sent(0),
          transport_notification_seen(false),
          wireless_carplay_available_seen(false) {}
};

struct SessionConfig {
    LinkConfig link;
    IdentificationConfig identification;
    TransportControlMode control_mode;
    bool retry_identification_on_unsupported_messages;
    uint16_t wired_available_current_ma;
    bool has_wifi_config;
    WiFiConfiguration wifi_config;
    bool has_start_session;
    StartSessionConfig start_session;

    uint32_t detect_timeout_ms;
    uint32_t sync_timeout_ms;
    uint32_t identification_timeout_ms;
    uint32_t authentication_timeout_ms;

    SessionConfig()
        : control_mode(kTransportControlManual),
          retry_identification_on_unsupported_messages(true),
          wired_available_current_ma(2400U),
          has_wifi_config(false),
          has_start_session(false),
          detect_timeout_ms(5000U),
          sync_timeout_ms(5000U),
          identification_timeout_ms(10000U),
          authentication_timeout_ms(10000U) {}

    static SessionConfig wiredUsb(const IdentificationConfig& ident,
                                  uint16_t available_current_ma = 2400U,
                                  const StartSessionConfig* start_session_cfg = NULL);

    static SessionConfig wirelessBluetooth(const IdentificationConfig& ident,
                                           const WiFiConfiguration* wifi_cfg = NULL,
                                           const StartSessionConfig* start_session_cfg = NULL);

    static SessionConfig wirelessTunnel(const IdentificationConfig& ident,
                                        const StartSessionConfig* start_session_cfg = NULL);
};

class SessionListener {
public:
    virtual ~SessionListener() {}

    virtual void onStateChanged(SessionState /*old_state*/, SessionState /*new_state*/) {}
    virtual void onIdentificationAccepted() {}
    virtual void onIdentificationRetry(const std::vector<uint16_t>& /*omitted_messages*/) {}
    virtual void onIdentificationRejected(const std::vector<uint16_t>& /*rejected_params*/) {}
    virtual void onIdentificationUpdate(const ParameterList& /*params*/) {}
    virtual void onAuthenticationSucceeded() {}
    virtual void onAuthenticationFailed(const std::string& /*reason*/) {}
    virtual void onReady() {}

    /// Called when RequestAccessoryWiFiConfiguration (0x5702) arrives (or on 0x4E0E resend).
    /// Populate `out` and return true to answer with 0x5703 (or configure SessionConfig::wifi_config).
    virtual bool onWiFiCredentialsRequested(WiFiConfiguration& /*out*/) { return false; }

    /// Called on CarPlayAvailability (0x4300) when control_mode is wired or wireless.
    /// Populate `out` and return true to answer with 0x4301 (or configure SessionConfig::start_session).
    virtual bool onCarPlayStartSessionRequested(const CarPlayAvailability& /*availability*/,
                                                StartSessionConfig& /*out*/) { return false; }

    virtual void onWiFiInformation(const WiFiInformation& /*info*/) {}
    virtual void onDeviceTransportIdentifier(const DeviceTransportIdentifier& /*id*/) {}
    virtual void onCarPlayAvailability(const CarPlayAvailability& /*availability*/) {}
    virtual void onWirelessCarPlayAvailability(bool /*available*/) {}
    virtual void onPowerUpdate(const Frame& /*frame*/) {}
    virtual void onPowerUpdatesChanged(bool /*active*/) {}
    virtual void onLocationUpdatesChanged(bool /*active*/) {}
    virtual void onVehicleStatusUpdatesChanged(bool /*active*/) {}
    virtual void onUnhandledMessage(const Frame& /*frame*/) {}
    virtual void onError(const std::string& /*message*/) {}
};

/// Encodes IdentificationInformation (0x1D01) from `cfg`.
bool buildIdentificationInformation(const IdentificationConfig& cfg,
                                    Frame& frame_out,
                                    std::string* error_out = NULL);

/// Encodes IdentificationInformation (0x1D01) omitting unsupported message IDs in `omitted_messages`.
bool buildIdentificationInformation(const IdentificationConfig& cfg,
                                    const std::vector<uint16_t>& omitted_messages,
                                    Frame& frame_out,
                                    std::string* error_out = NULL);

/// Encodes IdentificationInformationUpdate (0x1D06) from `cfg`.
bool buildIdentificationUpdate(const IdentificationConfig& cfg,
                               Frame& frame_out,
                               std::string* error_out = NULL);

class Session {
public:
    static const uint32_t kMaxPreTransportWiFiConfigSends = 5U;   // verified: DiPlay Iap2WirelessControlClient.kt:243
    static const uint32_t kMaxPostTransportWiFiConfigSends = 2U;  // verified: DiPlay Iap2WirelessControlClient.kt:244

    Session(ByteSink& sink,
            AuthProvider& auth,
            SessionListener& listener,
            const SessionConfig& config = SessionConfig());

    void start();
    void reset(bool send_rst = true);

    bool feed(const uint8_t* data, size_t len);
    bool feed(const std::vector<uint8_t>& bytes);

    void tick(int64_t now_ms);

    SessionState state() const { return state_; }
    bool isReady() const { return state_ == kSessionReady; }
    bool isIdentified() const { return identified_; }
    bool isAuthenticated() const { return authenticated_; }
    bool powerUpdatesActive() const { return power_updates_active_; }
    bool locationUpdatesActive() const { return location_updates_active_; }
    bool vehicleStatusUpdatesActive() const { return vehicle_status_updates_active_; }
    uint8_t controlSessionId() const { return control_session_id_; }
    const WirelessControlStatus& wirelessStatus() const { return wireless_status_; }

    Link& link() { return link_; }
    const Link& link() const { return link_; }
    const SessionConfig& config() const { return config_; }

    /// Sends IdentificationInformationUpdate (0x1D06) once identified.
    bool sendIdentificationUpdate(const IdentificationConfig& cfg);

    /// Post-auth control-session commands (require isReady()).
    bool sendStandardSubscriptions();
    bool sendStartPowerUpdates();
    bool sendStopPowerUpdates();
    bool sendStartCarPlaySession(const StartSessionConfig& cfg);
    bool requestWiFiInformation();
    bool sendPowerSourceUpdate(uint16_t available_current_ma,
                               bool has_charging,
                               bool charging);
    bool sendLocationInformation(const std::string& nmea_sentence);

    /// Sends an arbitrary CSM frame over the control link session.
    bool sendControlMessage(const Frame& frame);

private:
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    class LinkAdapter : public LinkListener {
    public:
        explicit LinkAdapter(Session& owner) : owner_(owner) {}
        virtual void onLinkStateChanged(LinkState new_state);
        virtual void onLinkConnected(const SynPayload& negotiated);
        virtual void onLinkPayload(uint8_t session_id, const uint8_t* data, size_t len);
        virtual void onLinkReset(bool by_peer);
        virtual void onLinkError(const std::string& reason);
    private:
        Session& owner_;
    };

    void setState(SessionState next);
    void failSession(const std::string& reason);
    void enterReadyState();
    void advanceWirelessStage(WirelessControlStage next);
    bool resolveWiFiConfiguration(WiFiConfiguration& out);
    bool sendWiFiConfiguration(const WiFiConfiguration& wifi_cfg, bool post_transport);

    void onLinkStateChangedImpl(LinkState new_state);
    void onLinkConnectedImpl(const SynPayload& negotiated);
    void onLinkPayloadImpl(uint8_t session_id, const uint8_t* data, size_t len);
    void onLinkResetImpl(bool by_peer);
    void onLinkErrorImpl(const std::string& reason);

    void handleFrame(const Frame& frame);
    void handleStartIdentification();
    void handleIdentificationAccepted();
    void handleIdentificationRejected(const Frame& frame);
    void handleCancelIdentification();
    void handleIdentificationUpdate(const Frame& frame);
    void handleRequestAuthCertificate();
    void handleRequestAuthChallengeResponse(const Frame& frame);
    void handleAuthFailed();
    void handleAuthSucceeded();
    void handleRequestAccessoryWiFiConfig();
    void handleDeviceTransportIdentifier(const Frame& frame);
    void handleCarPlayAvailability(const Frame& frame);

    AuthProvider& auth_;
    SessionListener& listener_;
    SessionConfig config_;
    LinkAdapter link_adapter_;
    Link link_;
    CsmFramer framer_;

    SessionState state_;
    uint8_t control_session_id_;
    bool identified_;
    bool authenticated_;
    bool power_updates_active_;
    bool location_updates_active_;
    bool vehicle_status_updates_active_;
    bool ident_retry_attempted_;
    std::vector<uint16_t> omitted_messages_;
    WirelessControlStatus wireless_status_;

    bool has_time_;
    int64_t last_now_ms_;
    bool has_state_time_;
    int64_t state_entered_ms_;
};

}  // namespace iap2
}  // namespace carplay

#endif  // CARPLAY_IAP2_SESSION_HPP
