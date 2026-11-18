#ifndef CARPLAY_SDP_RECORD_HPP
#define CARPLAY_SDP_RECORD_HPP

// Pure C++11 Bluetooth Service Discovery Protocol (SDP) data-element encoder,
// iAP2-over-Bluetooth service record builder, BlueZ 4 legacy `sdpd` PDU codec,
// and backend-agnostic SdpRegistrar interface.
//
// Specification references:
//   * Bluetooth Core Specification Vol 3, Part B (SDP): data element headers
//     (Section 3), PDU header & ErrorResponse (Section 4), standard service
//     attributes (Section 5).
//   * Bluetooth SIG Assigned Numbers: L2CAP (0x0100), RFCOMM (0x0003),
//     PublicBrowseRoot (0x1002), SerialPort (0x1101).
//   * BlueZ 4 local sdpd UNIX socket registration PDUs (0x81..0x86 on /var/run/sdp).
//
// NOTE on iAP2 Bluetooth service UUIDs:
//   verified: EntryNav2-Android-Auto-0.12.0/platform/spp_baseline.hpp and
//   tests/fixtures/spp-bmw-uuids.txt (observed BMW HU_ENTRYNAV2 CarPlay slot 1),
//   and DiPlay-main/.../CarPlayController.kt:3239 (IAP2_IPHONE_UUID). Overridable
//   via Iap2SdpConfig::service_uuid.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <utility>
#include <vector>

namespace carplay {
namespace sdp {

/// Standard SDP Attribute IDs (Bluetooth Core Spec Vol 3, Part B, Section 5.1).
namespace attr {
static const uint16_t kServiceRecordHandle = 0x0000U;
static const uint16_t kServiceClassIdList = 0x0001U;
static const uint16_t kServiceRecordState = 0x0002U;
static const uint16_t kServiceId = 0x0003U;
static const uint16_t kProtocolDescriptorList = 0x0004U;
static const uint16_t kBrowseGroupList = 0x0005U;
static const uint16_t kLanguageBaseAttributeIdList = 0x0006U;
static const uint16_t kServiceName = 0x0100U;
static const uint16_t kServiceDescription = 0x0101U;
static const uint16_t kProviderName = 0x0102U;
}  // namespace attr

/// Standard Bluetooth SIG 16-bit UUIDs.
namespace uuid16 {
static const uint16_t kSdp = 0x0001U;
static const uint16_t kRfcomm = 0x0003U;
static const uint16_t kL2cap = 0x0100U;
static const uint16_t kPublicBrowseRoot = 0x1002U;
static const uint16_t kSerialPort = 0x1101U;
}  // namespace uuid16

/// BlueZ 4 legacy `sdpd` local registration PDU IDs (plus standard SDP_ERROR_RSP).
namespace pdu {
static const uint8_t kErrorRsp = 0x01U;
static const uint8_t kSvcRegisterReq = 0x81U;
static const uint8_t kSvcRegisterRsp = 0x82U;
static const uint8_t kSvcUpdateReq = 0x83U;
static const uint8_t kSvcUpdateRsp = 0x84U;
static const uint8_t kSvcRemoveReq = 0x85U;
static const uint8_t kSvcRemoveRsp = 0x86U;
}  // namespace pdu

/// 128-bit UUID in network (big-endian) byte order.
struct Uuid128 {
    uint8_t bytes[16];

    Uuid128();
    static Uuid128 fromArray(const uint8_t raw[16]);
    bool operator==(const Uuid128& other) const;
    bool operator!=(const Uuid128& other) const { return !(*this == other); }
};

/// Parses "00000000-deca-fade-deca-deafdecacafe" (case-insensitive, hyphens optional)
/// into big-endian bytes. Returns false on invalid length or non-hex characters.
bool parseUuid128(const std::string& text, Uuid128& out);
/// Formats as lowercase hyphenated canonical UUID string.
std::string formatUuid128(const Uuid128& uuid);

/// verified: EntryNav2-Android-Auto-0.12.0/platform/spp_baseline.hpp,
/// tests/fixtures/spp-bmw-uuids.txt, and DiPlay-main/.../CarPlayController.kt:3239
/// (00000000-deca-fade-deca-deafdecacafe: local iAP2 SDP record UUID).
Uuid128 defaultIap2AccessoryUuid128();

/// verified: EntryNav2-Android-Auto-0.12.0/platform/spp_baseline.hpp and
/// tests/fixtures/spp-bmw-uuids.txt
/// (00000000-deca-fade-deca-deafdecacaff: iOS initiator iAP/iAP2 UUID).
Uuid128 defaultAppleIapDeviceUuid128();

// ------------------------------------------------------------------------------------------------
// SDP Data Element Encoder (Bluetooth Core Spec Vol 3, Part B, Section 3)
// ------------------------------------------------------------------------------------------------

void appendNil(std::vector<uint8_t>& out);
void appendUint8(std::vector<uint8_t>& out, uint8_t value);
void appendUint16(std::vector<uint8_t>& out, uint16_t value);
void appendUint32(std::vector<uint8_t>& out, uint32_t value);
void appendBool(std::vector<uint8_t>& out, bool value);
void appendUuid16(std::vector<uint8_t>& out, uint16_t uuid);
void appendUuid32(std::vector<uint8_t>& out, uint32_t uuid);
void appendUuid128(std::vector<uint8_t>& out, const uint8_t uuid[16]);
void appendUuid128(std::vector<uint8_t>& out, const Uuid128& uuid);
void appendText(std::vector<uint8_t>& out, const std::string& text);
void appendSequence(std::vector<uint8_t>& out, const std::vector<uint8_t>& inner);
void appendAlternative(std::vector<uint8_t>& out, const std::vector<uint8_t>& inner);

// ------------------------------------------------------------------------------------------------
// Service Record Container & iAP2 Builder
// ------------------------------------------------------------------------------------------------

struct Attribute {
    uint16_t id;
    std::vector<uint8_t> encoded_value;

    Attribute() : id(0) {}
    Attribute(uint16_t attr_id, const std::vector<uint8_t>& val)
        : id(attr_id), encoded_value(val) {}
};

class ServiceRecord {
public:
    void clear() { attrs_.clear(); }
    bool empty() const { return attrs_.empty(); }
    size_t size() const { return attrs_.size(); }
    const std::vector<Attribute>& attributes() const { return attrs_; }

    /// Inserts or replaces an attribute, keeping attributes sorted by ascending ID.
    void setAttribute(uint16_t id, const std::vector<uint8_t>& encoded_value);
    const Attribute* findAttribute(uint16_t id) const;

    /// Encodes the record as a Data Element Sequence (DES) of (uint16 id, value) pairs.
    bool encode(std::vector<uint8_t>& out, std::string* error_out = NULL) const;

private:
    std::vector<Attribute> attrs_;
};

struct Iap2SdpConfig {
    /// RFCOMM server channel (must be in 1..30).
    uint8_t rfcomm_channel;
    /// Primary 128-bit ServiceClassIDList UUID (defaults to verified iAP2 accessory UUID).
    Uuid128 service_uuid;
    /// Optional additional 16-bit service class UUIDs appended after `service_uuid`
    /// (e.g. uuid16::kSerialPort if testing SPP fallback).
    std::vector<uint16_t> extra_uuid16s;
    /// Emit BrowseGroupList containing PublicBrowseRoot (0x1002).
    bool include_public_browse_group;
    /// Emit LanguageBaseAttributeIDList ("en", UTF-8, base 0x0100) when service_name is non-empty.
    bool include_language_base;
    /// ServiceName (attribute 0x0100); omitted if empty.
    std::string service_name;

    Iap2SdpConfig()
        : rfcomm_channel(1),
          service_uuid(defaultIap2AccessoryUuid128()),
          include_public_browse_group(true),
          include_language_base(true),
          service_name("Wireless iAP2") {}
};

/// Builds a ServiceRecord for iAP2-over-RFCOMM. Returns false if rfcomm_channel is not in 1..30.
bool buildIap2SdpRecord(const Iap2SdpConfig& config,
                        ServiceRecord& out,
                        std::string* error_out = NULL);

// ------------------------------------------------------------------------------------------------
// BlueZ 4 Legacy `sdpd` UNIX Socket PDU Codec
// ------------------------------------------------------------------------------------------------

/// Encodes an SDP_SVC_REGISTER_REQ (0x81) PDU carrying `bdaddr` (NULL -> all-zero BDADDR_ANY),
/// `flags` (0 by default), and the encoded ServiceRecord DES bytes.
bool encodeSdpdRegisterRequest(uint16_t tid,
                               const std::vector<uint8_t>& encoded_record,
                               std::vector<uint8_t>& pdu_out,
                               const uint8_t bdaddr[6] = NULL,
                               uint8_t flags = 0,
                               std::string* error_out = NULL);

/// Parses an SDP_SVC_REGISTER_RSP (0x82) or SDP_ERROR_RSP (0x01) PDU.
/// On success, sets `handle_out` and returns true.
bool parseSdpdRegisterResponse(const uint8_t* data,
                               size_t len,
                               uint16_t expected_tid,
                               uint32_t& handle_out,
                               uint16_t* sdp_error_out = NULL,
                               std::string* error_out = NULL);

/// Encodes an SDP_SVC_REMOVE_REQ (0x85) PDU for `handle`.
void encodeSdpdRemoveRequest(uint16_t tid, uint32_t handle, std::vector<uint8_t>& pdu_out);

/// Parses an SDP_SVC_REMOVE_RSP (0x86) or SDP_ERROR_RSP (0x01) PDU.
bool parseSdpdRemoveResponse(const uint8_t* data,
                             size_t len,
                             uint16_t expected_tid,
                             uint16_t* sdp_error_out = NULL,
                             std::string* error_out = NULL);

// ------------------------------------------------------------------------------------------------
// Registration Backend Interface + Pure No-op Fallback
// ------------------------------------------------------------------------------------------------

class SdpRegistrar {
public:
    virtual ~SdpRegistrar() {}
    virtual const char* backendName() const = 0;
    virtual bool isSupported() const = 0;
    virtual bool registerRecord(const std::vector<uint8_t>& encoded_record,
                                uint32_t& handle_out) = 0;
    virtual bool unregisterRecord(uint32_t handle) = 0;
    virtual const std::string& lastError() const = 0;
};

/// No-op SDP backend used when no supported SDP daemon/stack is detected at runtime.
class NoopSdpRegistrar : public SdpRegistrar {
public:
    NoopSdpRegistrar() : last_error_("unsupported") {}
    virtual ~NoopSdpRegistrar() {}

    virtual const char* backendName() const { return "noop"; }
    virtual bool isSupported() const { return false; }
    virtual bool registerRecord(const std::vector<uint8_t>& encoded_record,
                                uint32_t& handle_out);
    virtual bool unregisterRecord(uint32_t handle);
    virtual const std::string& lastError() const { return last_error_; }

private:
    std::string last_error_;
};

}  // namespace sdp
}  // namespace carplay

#endif  // CARPLAY_SDP_RECORD_HPP
