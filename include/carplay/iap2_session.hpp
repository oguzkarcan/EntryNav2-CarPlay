#ifndef CARPLAY_IAP2_SESSION_HPP
#define CARPLAY_IAP2_SESSION_HPP

// Transport-agnostic iAP2 Control Session state machine layered on top of
// carplay::iap2::Link, CsmFramer/ParameterList codecs, and AuthProvider.
//
// Supports both standard iAP2 phase orderings:
//   - detect -> link sync -> identification -> authentication -> post-auth
//   - detect -> link sync -> authentication -> identification -> post-auth
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
/// Every constant in this namespace is marked "unverified" (not yet verified
/// against live iPhone packet captures) and kept here so IDs can be adjusted
/// in a single location.
namespace param {

// IdentificationInformation (0x1D01) / IdentificationInformationUpdate (0x1D06)
static const uint16_t kIdentName = 0U;                              // unverified (UTF-8 string)
static const uint16_t kIdentModelIdentifier = 1U;                   // unverified (UTF-8 string)
static const uint16_t kIdentManufacturer = 2U;                      // unverified (UTF-8 string)
static const uint16_t kIdentSerialNumber = 3U;                      // unverified (UTF-8 string)
static const uint16_t kIdentFirmwareVersion = 4U;                   // unverified (UTF-8 string)
static const uint16_t kIdentHardwareVersion = 5U;                   // unverified (UTF-8 string)
static const uint16_t kIdentMessagesSentByAccessory = 6U;           // unverified (packed u16 BE list)
static const uint16_t kIdentMessagesReceivedFromDevice = 7U;        // unverified (packed u16 BE list)
static const uint16_t kIdentPowerProvidingCapability = 8U;          // unverified (u8 enum)
static const uint16_t kIdentMaxCurrentDrawnFromDevice = 9U;         // unverified (u16 mA)
static const uint16_t kIdentSupportedEaProtocol = 10U;              // unverified (group)
static const uint16_t kIdentAppMatchTeamId = 11U;                   // unverified (UTF-8 string)
static const uint16_t kIdentCurrentLanguage = 12U;                  // unverified (UTF-8 string)
static const uint16_t kIdentSupportedLanguage = 13U;                // unverified (repeated UTF-8 string)
static const uint16_t kIdentSerialTransportComponent = 14U;         // unverified (group)
static const uint16_t kIdentUsbDeviceTransportComponent = 15U;      // unverified (group)
static const uint16_t kIdentUsbHostTransportComponent = 16U;        // unverified (group)
static const uint16_t kIdentBluetoothTransportComponent = 17U;      // unverified (group)
static const uint16_t kIdentHidComponent = 18U;                     // unverified (group)
static const uint16_t kIdentVehicleInformationComponent = 20U;      // unverified (group)
static const uint16_t kIdentVehicleStatusComponent = 21U;           // unverified (group)
static const uint16_t kIdentLocationInformationComponent = 22U;     // unverified (group)
static const uint16_t kIdentWirelessCarPlayTransportComponent = 34U;// unverified (group)

// Transport Component sub-parameters (inside 15, 16, 17, 34)
static const uint16_t kTransportComponentId = 0U;                   // unverified (u16)
static const uint16_t kTransportComponentName = 1U;                 // unverified (UTF-8 string)
static const uint16_t kTransportSupportsIap2Connection = 2U;        // unverified (void)
static const uint16_t kUsbDeviceSupportedAudioSampleRate = 3U;      // unverified (u8 repeated)
static const uint16_t kBtTransportMacAddress = 3U;                  // unverified (6-byte MAC)
static const uint16_t kWirelessCarPlaySupportsCarPlay = 3U;         // unverified (void)

// VehicleInformationComponent sub-parameters (inside 20)
static const uint16_t kVehicleInfoComponentId = 0U;                 // unverified (u16)
static const uint16_t kVehicleInfoComponentName = 1U;               // unverified (UTF-8 string)
static const uint16_t kVehicleInfoEngineType = 2U;                  // unverified (u8 repeated)
static const uint16_t kVehicleInfoDisplayName = 3U;                 // unverified (UTF-8 string)

// IdentificationRejected (0x1D03)
static const uint16_t kIdentRejectedParamId = 0U;                   // unverified (u16 / repeated)

// Authentication (0xAA01, 0xAA02, 0xAA03, 0xAA06)
static const uint16_t kAuthCertificateData = 0U;                    // unverified (DER bytes)
static const uint16_t kAuthChallengeData = 0U;                      // unverified (challenge bytes)
static const uint16_t kAuthChallengeResponseData = 0U;              // unverified (signature bytes)
static const uint16_t kAuthCertificateSerial = 0U;                  // unverified (UTF-8 string / bytes)

}  // namespace param

enum PowerCapability {
    kPowerCapabilityNone = 0,
    kPowerCapabilityReserved = 1,
    kPowerCapabilityAdvanced = 2
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

    BluetoothTransportConfig()
        : enabled(false), component_id(2), supports_iap2(true) {}
};

struct WirelessCarPlayTransportConfig {
    bool enabled;
    uint16_t component_id;
    std::string name;
    bool supports_iap2;
    bool supports_carplay;

    WirelessCarPlayTransportConfig()
        : enabled(false), component_id(3), supports_iap2(true), supports_carplay(true) {}
};

struct VehicleInformationConfig {
    bool enabled;
    uint16_t component_id;
    std::string name;
    std::string display_name;
    std::vector<uint8_t> engine_types;

    VehicleInformationConfig()
        : enabled(false), component_id(1) {}
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

    std::string current_language;
    std::vector<std::string> supported_languages;

    UsbDeviceTransportConfig usb_device_transport;
    BluetoothTransportConfig bluetooth_transport;
    WirelessCarPlayTransportConfig wireless_carplay_transport;
    VehicleInformationConfig vehicle_information;

    IdentificationConfig()
        : power_providing_capability(kPowerCapabilityNone),
          max_current_drawn_ma(0) {}
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

struct SessionConfig {
    LinkConfig link;
    IdentificationConfig identification;

    uint32_t detect_timeout_ms;
    uint32_t sync_timeout_ms;
    uint32_t identification_timeout_ms;
    uint32_t authentication_timeout_ms;

    SessionConfig()
        : detect_timeout_ms(5000U),
          sync_timeout_ms(5000U),
          identification_timeout_ms(10000U),
          authentication_timeout_ms(10000U) {}
};

class SessionListener {
public:
    virtual ~SessionListener() {}

    virtual void onStateChanged(SessionState /*old_state*/, SessionState /*new_state*/) {}
    virtual void onIdentificationAccepted() {}
    virtual void onIdentificationRejected(const std::vector<uint16_t>& /*rejected_params*/) {}
    virtual void onIdentificationUpdate(const ParameterList& /*params*/) {}
    virtual void onAuthenticationSucceeded() {}
    virtual void onAuthenticationFailed(const std::string& /*reason*/) {}
    virtual void onReady() {}

    /// Called when RequestAccessoryWiFiConfiguration (0x5702) arrives.
    /// Populate `out` and return true to answer with 0x5703.
    virtual bool onWiFiCredentialsRequested(WiFiConfiguration& /*out*/) { return false; }

    virtual void onWiFiInformation(const WiFiInformation& /*info*/) {}
    virtual void onDeviceTransportIdentifier(const DeviceTransportIdentifier& /*id*/) {}
    virtual void onCarPlayAvailability(const CarPlayAvailability& /*availability*/) {}
    virtual void onWirelessCarPlayAvailability(bool /*available*/) {}
    virtual void onPowerUpdatesChanged(bool /*active*/) {}
    virtual void onLocationUpdatesChanged(bool /*active*/) {}
    virtual void onUnhandledMessage(const Frame& /*frame*/) {}
    virtual void onError(const std::string& /*message*/) {}
};

/// Encodes IdentificationInformation (0x1D01) from `cfg`.
bool buildIdentificationInformation(const IdentificationConfig& cfg,
                                    Frame& frame_out,
                                    std::string* error_out = NULL);

/// Encodes IdentificationInformationUpdate (0x1D06) from `cfg`.
bool buildIdentificationUpdate(const IdentificationConfig& cfg,
                               Frame& frame_out,
                               std::string* error_out = NULL);

class Session {
public:
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
    uint8_t controlSessionId() const { return control_session_id_; }

    Link& link() { return link_; }
    const Link& link() const { return link_; }
    const SessionConfig& config() const { return config_; }

    /// Sends IdentificationInformationUpdate (0x1D06) once identified.
    bool sendIdentificationUpdate(const IdentificationConfig& cfg);

    /// Post-auth control-session commands (require isReady()).
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

    bool has_time_;
    int64_t last_now_ms_;
    bool has_state_time_;
    int64_t state_entered_ms_;
};

}  // namespace iap2
}  // namespace carplay

#endif  // CARPLAY_IAP2_SESSION_HPP
