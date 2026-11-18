#include "carplay/sdp_record.hpp"

#include <stdio.h>
#include <string.h>

namespace carplay {
namespace sdp {

namespace {

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

void pushU16Be(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xffU));
    out.push_back(static_cast<uint8_t>(v & 0xffU));
}

void pushU32Be(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xffU));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xffU));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xffU));
    out.push_back(static_cast<uint8_t>(v & 0xffU));
}

uint16_t readU16Be(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) |
                                 static_cast<uint16_t>(p[1]));
}

uint32_t readU32Be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

int hexNibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

void appendVariable(uint8_t type_descriptor,
                    const uint8_t* data,
                    size_t len,
                    std::vector<uint8_t>& out) {
    const uint8_t prefix = static_cast<uint8_t>((type_descriptor & 0x1fU) << 3);
    if (len <= 0xffU) {
        out.push_back(static_cast<uint8_t>(prefix | 5U));
        out.push_back(static_cast<uint8_t>(len));
    } else if (len <= 0xffffU) {
        out.push_back(static_cast<uint8_t>(prefix | 6U));
        pushU16Be(out, static_cast<uint16_t>(len));
    } else {
        out.push_back(static_cast<uint8_t>(prefix | 7U));
        pushU32Be(out, static_cast<uint32_t>(len));
    }
    if (len > 0 && data != NULL) {
        out.insert(out.end(), data, data + len);
    }
}

}  // namespace

// ------------------------------------------------------------------------------------------------
// Uuid128
// ------------------------------------------------------------------------------------------------

Uuid128::Uuid128() { memset(bytes, 0, sizeof(bytes)); }

Uuid128 Uuid128::fromArray(const uint8_t raw[16]) {
    Uuid128 u;
    if (raw != NULL) {
        memcpy(u.bytes, raw, 16);
    }
    return u;
}

bool Uuid128::operator==(const Uuid128& other) const {
    return memcmp(bytes, other.bytes, sizeof(bytes)) == 0;
}

bool parseUuid128(const std::string& text, Uuid128& out) {
    const bool hyphenated = (text.size() == 36);
    if (!hyphenated && text.size() != 32) {
        return false;
    }
    uint8_t parsed[16];
    size_t byte_idx = 0;
    size_t i = 0;
    while (i < text.size()) {
        if (hyphenated && (i == 8 || i == 13 || i == 18 || i == 23)) {
            if (text[i] != '-') {
                return false;
            }
            ++i;
            continue;
        }
        if (i + 1 >= text.size() || byte_idx >= 16) {
            return false;
        }
        const int hi = hexNibble(text[i]);
        const int lo = hexNibble(text[i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        parsed[byte_idx++] = static_cast<uint8_t>((hi << 4) | lo);
        i += 2;
    }
    if (byte_idx != 16) {
        return false;
    }
    memcpy(out.bytes, parsed, 16);
    return true;
}

std::string formatUuid128(const Uuid128& uuid) {
    char buf[37];
    snprintf(
        buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid.bytes[0], uuid.bytes[1], uuid.bytes[2], uuid.bytes[3],
        uuid.bytes[4], uuid.bytes[5],
        uuid.bytes[6], uuid.bytes[7],
        uuid.bytes[8], uuid.bytes[9],
        uuid.bytes[10], uuid.bytes[11], uuid.bytes[12], uuid.bytes[13], uuid.bytes[14], uuid.bytes[15]);
    return std::string(buf);
}

Uuid128 defaultIap2AccessoryUuid128() {
    // verified: EntryNav2-Android-Auto-0.12.0/platform/spp_baseline.hpp,
    // tests/fixtures/spp-bmw-uuids.txt (CarPlay slot 1 local SDP record UUID),
    // and DiPlay-main/.../CarPlayController.kt:3239 (IAP2_IPHONE_UUID).
    static const uint8_t kRaw[16] = {
        0x00, 0x00, 0x00, 0x00,
        0xde, 0xca, 0xfa, 0xde,
        0xde, 0xca, 0xde, 0xaf,
        0xde, 0xca, 0xca, 0xfe
    };
    return Uuid128::fromArray(kRaw);
}

Uuid128 defaultAppleIapDeviceUuid128() {
    // verified: EntryNav2-Android-Auto-0.12.0/platform/spp_baseline.hpp and
    // tests/fixtures/spp-bmw-uuids.txt (CarPlay slot 1 initiator UUID).
    static const uint8_t kRaw[16] = {
        0x00, 0x00, 0x00, 0x00,
        0xde, 0xca, 0xfa, 0xde,
        0xde, 0xca, 0xde, 0xaf,
        0xde, 0xca, 0xca, 0xff
    };
    return Uuid128::fromArray(kRaw);
}

// ------------------------------------------------------------------------------------------------
// SDP Data Element Encoder
// ------------------------------------------------------------------------------------------------

void appendNil(std::vector<uint8_t>& out) {
    out.push_back(0x00U);  // Type 0 (Nil), Size 0
}

void appendUint8(std::vector<uint8_t>& out, uint8_t value) {
    out.push_back(0x08U);  // Type 1 (uint), Size 0 (1B)
    out.push_back(value);
}

void appendUint16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(0x09U);  // Type 1 (uint), Size 1 (2B)
    pushU16Be(out, value);
}

void appendUint32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(0x0aU);  // Type 1 (uint), Size 2 (4B)
    pushU32Be(out, value);
}

void appendBool(std::vector<uint8_t>& out, bool value) {
    out.push_back(0x28U);  // Type 5 (bool), Size 0 (1B)
    out.push_back(value ? 0x01U : 0x00U);
}

void appendUuid16(std::vector<uint8_t>& out, uint16_t uuid) {
    out.push_back(0x19U);  // Type 3 (UUID), Size 1 (2B)
    pushU16Be(out, uuid);
}

void appendUuid32(std::vector<uint8_t>& out, uint32_t uuid) {
    out.push_back(0x1aU);  // Type 3 (UUID), Size 2 (4B)
    pushU32Be(out, uuid);
}

void appendUuid128(std::vector<uint8_t>& out, const uint8_t uuid[16]) {
    out.push_back(0x1cU);  // Type 3 (UUID), Size 4 (16B)
    if (uuid != NULL) {
        out.insert(out.end(), uuid, uuid + 16);
    } else {
        out.insert(out.end(), 16, 0x00U);
    }
}

void appendUuid128(std::vector<uint8_t>& out, const Uuid128& uuid) {
    appendUuid128(out, uuid.bytes);
}

void appendText(std::vector<uint8_t>& out, const std::string& text) {
    const uint8_t* ptr = text.empty() ? NULL : reinterpret_cast<const uint8_t*>(text.data());
    appendVariable(4U, ptr, text.size(), out);
}

void appendSequence(std::vector<uint8_t>& out, const std::vector<uint8_t>& inner) {
    const uint8_t* ptr = inner.empty() ? NULL : &inner[0];
    appendVariable(6U, ptr, inner.size(), out);
}

void appendAlternative(std::vector<uint8_t>& out, const std::vector<uint8_t>& inner) {
    const uint8_t* ptr = inner.empty() ? NULL : &inner[0];
    appendVariable(7U, ptr, inner.size(), out);
}

// ------------------------------------------------------------------------------------------------
// ServiceRecord & Builder
// ------------------------------------------------------------------------------------------------

void ServiceRecord::setAttribute(uint16_t id, const std::vector<uint8_t>& encoded_value) {
    for (size_t i = 0; i < attrs_.size(); ++i) {
        if (attrs_[i].id == id) {
            attrs_[i].encoded_value = encoded_value;
            return;
        }
        if (attrs_[i].id > id) {
            attrs_.insert(attrs_.begin() + static_cast<std::ptrdiff_t>(i),
                          Attribute(id, encoded_value));
            return;
        }
    }
    attrs_.push_back(Attribute(id, encoded_value));
}

const Attribute* ServiceRecord::findAttribute(uint16_t id) const {
    for (size_t i = 0; i < attrs_.size(); ++i) {
        if (attrs_[i].id == id) {
            return &attrs_[i];
        }
    }
    return NULL;
}

bool ServiceRecord::encode(std::vector<uint8_t>& out, std::string* error_out) const {
    out.clear();
    if (attrs_.empty()) {
        setError(error_out, "SDP service record has no attributes");
        return false;
    }
    std::vector<uint8_t> inner;
    for (size_t i = 0; i < attrs_.size(); ++i) {
        if (attrs_[i].encoded_value.empty()) {
            setError(error_out, "SDP attribute has empty encoded value");
            return false;
        }
        appendUint16(inner, attrs_[i].id);
        inner.insert(inner.end(),
                     attrs_[i].encoded_value.begin(),
                     attrs_[i].encoded_value.end());
    }
    appendSequence(out, inner);
    return true;
}

bool buildIap2SdpRecord(const Iap2SdpConfig& config,
                        ServiceRecord& out,
                        std::string* error_out) {
    out.clear();
    if (config.rfcomm_channel < 1U || config.rfcomm_channel > 30U) {
        setError(error_out, "RFCOMM channel must be in range 1..30");
        return false;
    }

    // 0x0001: ServiceClassIDList = DES { UUID128 [, extra UUID16s...] }
    {
        std::vector<uint8_t> sc_inner;
        appendUuid128(sc_inner, config.service_uuid);
        for (size_t i = 0; i < config.extra_uuid16s.size(); ++i) {
            appendUuid16(sc_inner, config.extra_uuid16s[i]);
        }
        std::vector<uint8_t> sc_list;
        appendSequence(sc_list, sc_inner);
        out.setAttribute(attr::kServiceClassIdList, sc_list);
    }

    // 0x0004: ProtocolDescriptorList = DES { DES{L2CAP}, DES{RFCOMM, channel} }
    {
        std::vector<uint8_t> l2cap_inner;
        appendUuid16(l2cap_inner, uuid16::kL2cap);
        std::vector<uint8_t> rfcomm_inner;
        appendUuid16(rfcomm_inner, uuid16::kRfcomm);
        appendUint8(rfcomm_inner, config.rfcomm_channel);

        std::vector<uint8_t> proto_inner;
        appendSequence(proto_inner, l2cap_inner);
        appendSequence(proto_inner, rfcomm_inner);

        std::vector<uint8_t> proto_list;
        appendSequence(proto_list, proto_inner);
        out.setAttribute(attr::kProtocolDescriptorList, proto_list);
    }

    // 0x0005: BrowseGroupList = DES { PublicBrowseRoot (0x1002) }
    if (config.include_public_browse_group) {
        std::vector<uint8_t> bg_inner;
        appendUuid16(bg_inner, uuid16::kPublicBrowseRoot);
        std::vector<uint8_t> bg_list;
        appendSequence(bg_list, bg_inner);
        out.setAttribute(attr::kBrowseGroupList, bg_list);
    }

    // 0x0006: LanguageBaseAttributeIDList ("en" = 0x656e, UTF-8 = 0x006a, base = 0x0100)
    if (!config.service_name.empty() && config.include_language_base) {
        std::vector<uint8_t> lang_inner;
        appendUint16(lang_inner, 0x656eU);  // ISO 639-1 "en"
        appendUint16(lang_inner, 0x006aU);  // IANA MIBenum UTF-8
        appendUint16(lang_inner, 0x0100U);  // Primary language attribute ID base
        std::vector<uint8_t> lang_list;
        appendSequence(lang_list, lang_inner);
        out.setAttribute(attr::kLanguageBaseAttributeIdList, lang_list);
    }

    // 0x0100: ServiceName
    if (!config.service_name.empty()) {
        std::vector<uint8_t> name_el;
        appendText(name_el, config.service_name);
        out.setAttribute(attr::kServiceName, name_el);
    }

    return true;
}

// ------------------------------------------------------------------------------------------------
// BlueZ 4 Legacy `sdpd` PDU Codec
// ------------------------------------------------------------------------------------------------

bool encodeSdpdRegisterRequest(uint16_t tid,
                               const std::vector<uint8_t>& encoded_record,
                               std::vector<uint8_t>& pdu_out,
                               const uint8_t bdaddr[6],
                               uint8_t flags,
                               std::string* error_out) {
    pdu_out.clear();
    if (encoded_record.empty()) {
        setError(error_out, "encoded SDP record is empty");
        return false;
    }
    const size_t param_len = 7U + encoded_record.size();
    if (param_len > 0xffffU) {
        setError(error_out, "encoded SDP record exceeds 16-bit PDU length");
        return false;
    }

    pdu_out.reserve(5U + param_len);
    pdu_out.push_back(pdu::kSvcRegisterReq);
    pushU16Be(pdu_out, tid);
    pushU16Be(pdu_out, static_cast<uint16_t>(param_len));
    if (bdaddr != NULL) {
        pdu_out.insert(pdu_out.end(), bdaddr, bdaddr + 6);
    } else {
        pdu_out.insert(pdu_out.end(), 6, 0x00U);
    }
    pdu_out.push_back(flags);
    pdu_out.insert(pdu_out.end(), encoded_record.begin(), encoded_record.end());
    return true;
}

bool parseSdpdRegisterResponse(const uint8_t* data,
                               size_t len,
                               uint16_t expected_tid,
                               uint32_t& handle_out,
                               uint16_t* sdp_error_out,
                               std::string* error_out) {
    handle_out = 0;
    if (sdp_error_out != NULL) {
        *sdp_error_out = 0;
    }
    if (data == NULL || len < 5U) {
        setError(error_out, "truncated SDP register response header");
        return false;
    }
    const uint8_t pdu_id = data[0];
    const uint16_t tid = readU16Be(data + 1);
    const uint16_t plen = readU16Be(data + 3);
    if (len < static_cast<size_t>(5U) + plen) {
        setError(error_out, "truncated SDP register response payload");
        return false;
    }
    if (tid != expected_tid) {
        setError(error_out, "SDP register response transaction ID mismatch");
        return false;
    }
    if (pdu_id == pdu::kErrorRsp) {
        uint16_t err_code = 0;
        if (plen >= 2U) {
            err_code = readU16Be(data + 5);
        }
        if (sdp_error_out != NULL) {
            *sdp_error_out = err_code;
        }
        char buf[64];
        snprintf(buf, sizeof(buf), "sdpd returned error 0x%04x", static_cast<unsigned>(err_code));
        setError(error_out, buf);
        return false;
    }
    if (pdu_id != pdu::kSvcRegisterRsp || plen < 4U) {
        setError(error_out, "unexpected SDP register response PDU");
        return false;
    }
    handle_out = readU32Be(data + 5);
    return true;
}

void encodeSdpdRemoveRequest(uint16_t tid, uint32_t handle, std::vector<uint8_t>& pdu_out) {
    pdu_out.clear();
    pdu_out.reserve(9U);
    pdu_out.push_back(pdu::kSvcRemoveReq);
    pushU16Be(pdu_out, tid);
    pushU16Be(pdu_out, 4U);
    pushU32Be(pdu_out, handle);
}

bool parseSdpdRemoveResponse(const uint8_t* data,
                             size_t len,
                             uint16_t expected_tid,
                             uint16_t* sdp_error_out,
                             std::string* error_out) {
    if (sdp_error_out != NULL) {
        *sdp_error_out = 0;
    }
    if (data == NULL || len < 5U) {
        setError(error_out, "truncated SDP remove response header");
        return false;
    }
    const uint8_t pdu_id = data[0];
    const uint16_t tid = readU16Be(data + 1);
    const uint16_t plen = readU16Be(data + 3);
    if (len < static_cast<size_t>(5U) + plen) {
        setError(error_out, "truncated SDP remove response payload");
        return false;
    }
    if (tid != expected_tid) {
        setError(error_out, "SDP remove response transaction ID mismatch");
        return false;
    }
    if (pdu_id == pdu::kErrorRsp) {
        uint16_t err_code = 0;
        if (plen >= 2U) {
            err_code = readU16Be(data + 5);
        }
        if (sdp_error_out != NULL) {
            *sdp_error_out = err_code;
        }
        char buf[64];
        snprintf(buf, sizeof(buf), "sdpd returned error 0x%04x", static_cast<unsigned>(err_code));
        setError(error_out, buf);
        return false;
    }
    if (pdu_id != pdu::kSvcRemoveRsp) {
        setError(error_out, "unexpected SDP remove response PDU");
        return false;
    }
    if (plen == 1U) {
        setError(error_out, "malformed SDP remove response status length");
        return false;
    }
    if (plen >= 2U) {
        const uint16_t status = readU16Be(data + 5);
        if (status != 0) {
            if (sdp_error_out != NULL) {
                *sdp_error_out = status;
            }
            char buf[64];
            snprintf(buf, sizeof(buf), "sdpd remove failed with status 0x%04x",
                     static_cast<unsigned>(status));
            setError(error_out, buf);
            return false;
        }
    }
    return true;
}

// ------------------------------------------------------------------------------------------------
// NoopSdpRegistrar
// ------------------------------------------------------------------------------------------------

bool NoopSdpRegistrar::registerRecord(const std::vector<uint8_t>& /*encoded_record*/,
                                      uint32_t& handle_out) {
    handle_out = 0;
    last_error_ = "unsupported";
    return false;
}

bool NoopSdpRegistrar::unregisterRecord(uint32_t /*handle*/) {
    last_error_ = "unsupported";
    return false;
}

}  // namespace sdp
}  // namespace carplay
