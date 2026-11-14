#ifndef CARPLAY_TLV8_CODEC_HPP
#define CARPLAY_TLV8_CODEC_HPP

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace carplay {
namespace tlv8 {

static const uint8_t kSeparatorType = 0xff;
static const size_t kMaxFragmentBytes = 255;

/// Common HAP / AirPlay Pairing TLV8 tags (HAP Specification Table 4-4 / 4-6).
enum Tag {
    kTagMethod = 0x00,
    kTagIdentifier = 0x01,
    kTagSalt = 0x02,
    kTagPublicKey = 0x03,
    kTagProof = 0x04,
    kTagEncryptedData = 0x05,
    kTagState = 0x06,
    kTagError = 0x07,
    kTagRetryDelay = 0x08,
    kTagCertificate = 0x09,
    kTagSignature = 0x0a,
    kTagPermissions = 0x0b,
    kTagFragmentData = 0x0c,
    kTagFragmentLast = 0x0d,
    kTagFlags = 0x13,
    kTagSeparator = 0xff
};

struct Item {
    uint8_t type;
    std::vector<uint8_t> value;

    Item() : type(0) {}
    Item(uint8_t t, const std::vector<uint8_t>& v) : type(t), value(v) {}
    Item(uint8_t t, const uint8_t* data, size_t len) : type(t) {
        if (data != NULL && len > 0) {
            value.assign(data, data + len);
        }
    }

    static Item fromByte(uint8_t t, uint8_t b);

    static Item fromString(uint8_t t, const std::string& s) {
        return Item(t, reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    static Item separator();
};

/// Encodes TLV8 items, splitting values > 255 bytes into consecutive fragments
/// and inserting 0xff 0x00 separators automatically when two non-separator
/// items share the same tag back-to-back.
std::vector<uint8_t> encode(const std::vector<Item>& items);

/// Decodes TLV8 wire bytes into items, reassembling multi-fragment payloads (> 255 bytes).
/// Returns false and sets `error_out` if truncated.
bool decode(const uint8_t* data,
            size_t len,
            std::vector<Item>& items_out,
            std::string* error_out = NULL);

bool decode(const std::vector<uint8_t>& bytes,
            std::vector<Item>& items_out,
            std::string* error_out = NULL);

/// Finds the first decoded item matching `type` (excluding separators unless `type == 0xff`).
const Item* findFirst(const std::vector<Item>& items, uint8_t type);

/// Collects all values matching `type` in order.
std::vector<const Item*> findAll(const std::vector<Item>& items, uint8_t type);

/// Reads a single-byte integer item by tag. Returns false if missing or size != 1.
bool readU8(const std::vector<Item>& items, uint8_t type, uint8_t& out);

/// Reads a UTF-8 string item by tag. Returns false if missing.
bool readString(const std::vector<Item>& items, uint8_t type, std::string& out);

/// Splits items into logical groups delimited by 0xff separator items.
std::vector<std::vector<Item> > splitBySeparator(const std::vector<Item>& items);

}  // namespace tlv8
}  // namespace carplay

#endif  // CARPLAY_TLV8_CODEC_HPP
