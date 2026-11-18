#ifndef CARPLAY_DNSSD_TXT_HPP
#define CARPLAY_DNSSD_TXT_HPP

// Pure DNS-SD (RFC 6763) TXT record builder/parser and AirPlay (`_airplay._tcp`) TXT set builder.
//
// Zero OS headers or I/O. Produces the length-prefixed `[u8 len | entry_bytes]...` buffer
// expected by Apple's `DNSServiceRegister` / `DNSServiceUpdateRecord` (and optionally the DNS wire
// RDATA form where an empty record is `{0x00}`).
//
// AirPlay TXT keys are fed directly from `carplay::info::AirPlayConfig` and
// `carplay::pairing::Identity` already in the repository:
//   * deviceid -> config.device_id
//   * features -> info::features(config) formatted as `0x<lo32>,0x<hi32>` (unverified format detail)
//   * flags    -> options.status_flags (default 4 -> "0x4", matching /info statusFlags)
//   * model    -> config.model
//   * pi       -> identity.pairing_id
//   * pk       -> lowercase hex of identity.keys.public_key (32 bytes -> 64 hex chars)
//   * srcvers  -> config.source_version

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/airplay_info.hpp"
#include "carplay/pairing.hpp"

namespace carplay {
namespace dnssd {

static const size_t kMaxTxtEntryBytes = 255U;

extern const char* const kAirPlayServiceType;    // "_airplay._tcp"
extern const char* const kAirPlayDefaultDomain;  // "local."
static const uint16_t kAirPlayDefaultPort = 7000U;

struct TxtEntry {
    std::string key;
    bool has_value;
    std::vector<uint8_t> value;

    TxtEntry() : has_value(false) {}

    static TxtEntry fromString(const std::string& k, const std::string& v) {
        TxtEntry e;
        e.key = k;
        e.has_value = true;
        e.value.assign(v.begin(), v.end());
        return e;
    }

    static TxtEntry fromBytes(const std::string& k, const uint8_t* data, size_t len) {
        TxtEntry e;
        e.key = k;
        e.has_value = true;
        if (len > 0U && data != NULL) {
            e.value.assign(data, data + len);
        }
        return e;
    }

    static TxtEntry flag(const std::string& k) {
        TxtEntry e;
        e.key = k;
        e.has_value = false;
        return e;
    }

    std::string valueString() const {
        return std::string(value.begin(), value.end());
    }
};

/// RFC 6763 §6.4 key validation: non-empty, US-ASCII printable (0x20..0x7E) excluding '=' (0x3D).
bool isValidTxtKey(const std::string& key);

/// Encodes `entries` as `[len_u8 | key[=value]]...` (empty vector when `entries` is empty).
/// Validates keys, entry length <= 255 bytes, and rejects case-insensitive duplicate keys.
bool encodeTxtRecord(const std::vector<TxtEntry>& entries,
                     std::vector<uint8_t>& out,
                     std::string* error_out = NULL);

/// Encodes `entries` as DNS TXT RDATA (`{0x00}` when empty; otherwise identical to encodeTxtRecord).
bool encodeTxtRdata(const std::vector<TxtEntry>& entries,
                    std::vector<uint8_t>& out,
                    std::string* error_out = NULL);

/// Decodes length-prefixed TXT bytes (`[len_u8 | entry_bytes]...`) back into `entries_out`.
/// A single zero-length entry `{0x00}` (RFC 6763 empty TXT RDATA) decodes to an empty list when it
/// is the sole byte, while zero-length entries mixed with others are rejected.
bool decodeTxtRecord(const uint8_t* data,
                     size_t len,
                     std::vector<TxtEntry>& entries_out,
                     std::string* error_out = NULL);

bool decodeTxtRecord(const std::vector<uint8_t>& data,
                     std::vector<TxtEntry>& entries_out,
                     std::string* error_out = NULL);

class TxtRecordBuilder {
public:
    void clear() { entries_.clear(); }
    bool empty() const { return entries_.empty(); }
    size_t size() const { return entries_.size(); }
    const std::vector<TxtEntry>& entries() const { return entries_; }

    bool add(const std::string& key, const std::string& value, std::string* error_out = NULL);
    bool addBytes(const std::string& key,
                  const uint8_t* value,
                  size_t len,
                  std::string* error_out = NULL);
    bool addFlag(const std::string& key, std::string* error_out = NULL);

    bool encode(std::vector<uint8_t>& out, std::string* error_out = NULL) const;
    bool encodeRdata(std::vector<uint8_t>& out, std::string* error_out = NULL) const;

private:
    bool addEntry(const TxtEntry& entry, std::string* error_out);
    std::vector<TxtEntry> entries_;
};

/// Formats a 64-bit AirPlay feature mask into the TXT `features` string (`0x<lo32>,0x<hi32>` when
/// hi32 != 0, or `0x<lo32>` otherwise). Note: exact hex case/splitting vs real iPhone capture is
/// unverified on vehicle; matches standard open AirPlay TXT conventions.
std::string formatAirPlayFeaturesTxt(uint64_t features_mask);

/// Formats `/info` `statusFlags` as `0x<hex>` (e.g. 4 -> "0x4"). Unverified on real iPhone capture.
std::string formatAirPlayFlagsTxt(uint32_t status_flags);

struct AirPlayTxtOptions {
    uint32_t status_flags;  // default 4 (matching src/core/airplay_info.cpp statusFlags = 4)
    std::vector<TxtEntry> extra_entries;

    AirPlayTxtOptions() : status_flags(4U) {}
};

/// Builds the `_airplay._tcp` TXT key-value list from existing repo identity & config.
/// Returns false if required identity/config fields are empty/invalid or any TXT constraint fails.
bool buildAirPlayTxtEntries(const info::AirPlayConfig& config,
                            const pairing::Identity& identity,
                            std::vector<TxtEntry>& out,
                            std::string* error_out = NULL,
                            const AirPlayTxtOptions& options = AirPlayTxtOptions());

/// Builds and length-prefix encodes the `_airplay._tcp` TXT record for `DNSServiceRegister`.
bool buildAirPlayTxtRecord(const info::AirPlayConfig& config,
                           const pairing::Identity& identity,
                           std::vector<uint8_t>& out,
                           std::string* error_out = NULL,
                           const AirPlayTxtOptions& options = AirPlayTxtOptions());

}  // namespace dnssd
}  // namespace carplay

#endif  // CARPLAY_DNSSD_TXT_HPP
