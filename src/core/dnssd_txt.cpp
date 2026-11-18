#include "carplay/dnssd_txt.hpp"

#include <cstdio>
#include <sstream>

namespace carplay {
namespace dnssd {

const char* const kAirPlayServiceType = "_airplay._tcp";
const char* const kAirPlayDefaultDomain = "local.";

namespace {

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

char toAsciiLower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return static_cast<char>(c - 'A' + 'a');
    }
    return c;
}

std::string asciiLower(const std::string& s) {
    std::string out = s;
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = toAsciiLower(out[i]);
    }
    return out;
}

std::string toLowerHex(const uint8_t* data, size_t len) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2U);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0x0fU]);
        out.push_back(kHex[data[i] & 0x0fU]);
    }
    return out;
}

bool validateEntry(const TxtEntry& entry, size_t& wire_len_out, std::string* error_out) {
    if (!isValidTxtKey(entry.key)) {
        setError(error_out, "invalid DNS-SD TXT key: \"" + entry.key + "\"");
        return false;
    }
    const size_t total = entry.key.size() + (entry.has_value ? (1U + entry.value.size()) : 0U);
    if (total == 0U || total > kMaxTxtEntryBytes) {
        std::ostringstream oss;
        oss << "DNS-SD TXT entry \"" << entry.key << "\" length " << total
            << " exceeds 255-byte limit";
        setError(error_out, oss.str());
        return false;
    }
    wire_len_out = total;
    return true;
}

}  // namespace

bool isValidTxtKey(const std::string& key) {
    if (key.empty() || key.size() > kMaxTxtEntryBytes) {
        return false;
    }
    for (size_t i = 0; i < key.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(key[i]);
        // RFC 6763 §6.4: printable US-ASCII (0x20..0x7E) excluding '=' (0x3D).
        if (c < 0x20U || c > 0x7eU || c == '=') {
            return false;
        }
    }
    return true;
}

bool encodeTxtRecord(const std::vector<TxtEntry>& entries,
                     std::vector<uint8_t>& out,
                     std::string* error_out) {
    out.clear();
    std::vector<std::string> seen_lower;
    seen_lower.reserve(entries.size());

    size_t total_bytes = 0U;
    std::vector<size_t> lengths;
    lengths.reserve(entries.size());

    for (size_t i = 0; i < entries.size(); ++i) {
        size_t entry_len = 0U;
        if (!validateEntry(entries[i], entry_len, error_out)) {
            return false;
        }
        const std::string lower = asciiLower(entries[i].key);
        for (size_t j = 0; j < seen_lower.size(); ++j) {
            if (seen_lower[j] == lower) {
                setError(error_out, "duplicate DNS-SD TXT key: \"" + entries[i].key + "\"");
                return false;
            }
        }
        seen_lower.push_back(lower);
        lengths.push_back(entry_len);
        total_bytes += 1U + entry_len;
    }

    out.reserve(total_bytes);
    for (size_t i = 0; i < entries.size(); ++i) {
        out.push_back(static_cast<uint8_t>(lengths[i]));
        out.insert(out.end(), entries[i].key.begin(), entries[i].key.end());
        if (entries[i].has_value) {
            out.push_back(static_cast<uint8_t>('='));
            out.insert(out.end(), entries[i].value.begin(), entries[i].value.end());
        }
    }
    return true;
}

bool encodeTxtRdata(const std::vector<TxtEntry>& entries,
                    std::vector<uint8_t>& out,
                    std::string* error_out) {
    if (!encodeTxtRecord(entries, out, error_out)) {
        return false;
    }
    if (out.empty()) {
        out.push_back(0x00U);
    }
    return true;
}

bool decodeTxtRecord(const uint8_t* data,
                     size_t len,
                     std::vector<TxtEntry>& entries_out,
                     std::string* error_out) {
    entries_out.clear();
    if (len > 0U && data == NULL) {
        setError(error_out, "null DNS-SD TXT buffer");
        return false;
    }
    if (len == 0U) {
        return true;
    }
    if (len == 1U && data[0] == 0x00U) {
        return true;  // RFC 6763 §6.1 empty TXT RDATA
    }

    size_t pos = 0U;
    while (pos < len) {
        const size_t item_len = data[pos];
        ++pos;
        if (item_len == 0U) {
            setError(error_out, "unexpected zero-length DNS-SD TXT item");
            entries_out.clear();
            return false;
        }
        if (pos + item_len > len) {
            setError(error_out, "truncated DNS-SD TXT item");
            entries_out.clear();
            return false;
        }
        const uint8_t* item = data + pos;
        size_t eq_pos = item_len;
        for (size_t i = 0; i < item_len; ++i) {
            if (item[i] == static_cast<uint8_t>('=')) {
                eq_pos = i;
                break;
            }
        }
        TxtEntry entry;
        entry.key.assign(reinterpret_cast<const char*>(item), eq_pos);
        if (!isValidTxtKey(entry.key)) {
            setError(error_out, "invalid key in decoded DNS-SD TXT item");
            entries_out.clear();
            return false;
        }
        if (eq_pos < item_len) {
            entry.has_value = true;
            const size_t val_offset = eq_pos + 1U;
            if (val_offset < item_len) {
                entry.value.assign(item + val_offset, item + item_len);
            }
        } else {
            entry.has_value = false;
        }
        entries_out.push_back(entry);
        pos += item_len;
    }
    return true;
}

bool decodeTxtRecord(const std::vector<uint8_t>& data,
                     std::vector<TxtEntry>& entries_out,
                     std::string* error_out) {
    const uint8_t* ptr = data.empty() ? NULL : &data[0];
    return decodeTxtRecord(ptr, data.size(), entries_out, error_out);
}

bool TxtRecordBuilder::addEntry(const TxtEntry& entry, std::string* error_out) {
    size_t wire_len = 0U;
    if (!validateEntry(entry, wire_len, error_out)) {
        return false;
    }
    const std::string lower = asciiLower(entry.key);
    for (size_t i = 0; i < entries_.size(); ++i) {
        if (asciiLower(entries_[i].key) == lower) {
            setError(error_out, "duplicate DNS-SD TXT key: \"" + entry.key + "\"");
            return false;
        }
    }
    entries_.push_back(entry);
    return true;
}

bool TxtRecordBuilder::add(const std::string& key,
                           const std::string& value,
                           std::string* error_out) {
    return addEntry(TxtEntry::fromString(key, value), error_out);
}

bool TxtRecordBuilder::addBytes(const std::string& key,
                                const uint8_t* value,
                                size_t len,
                                std::string* error_out) {
    if (len > 0U && value == NULL) {
        setError(error_out, "null value buffer for DNS-SD TXT key: \"" + key + "\"");
        return false;
    }
    return addEntry(TxtEntry::fromBytes(key, value, len), error_out);
}

bool TxtRecordBuilder::addFlag(const std::string& key, std::string* error_out) {
    return addEntry(TxtEntry::flag(key), error_out);
}

bool TxtRecordBuilder::encode(std::vector<uint8_t>& out, std::string* error_out) const {
    return encodeTxtRecord(entries_, out, error_out);
}

bool TxtRecordBuilder::encodeRdata(std::vector<uint8_t>& out, std::string* error_out) const {
    return encodeTxtRdata(entries_, out, error_out);
}

std::string formatAirPlayFeaturesTxt(uint64_t features_mask) {
    const uint32_t lo = static_cast<uint32_t>(features_mask & 0xffffffffULL);
    const uint32_t hi = static_cast<uint32_t>((features_mask >> 32) & 0xffffffffULL);
    char buf[32];
    if (hi != 0U) {
        std::snprintf(buf, sizeof(buf), "0x%x,0x%x",
                      static_cast<unsigned int>(lo), static_cast<unsigned int>(hi));
    } else {
        std::snprintf(buf, sizeof(buf), "0x%x", static_cast<unsigned int>(lo));
    }
    return std::string(buf);
}

std::string formatAirPlayFlagsTxt(uint32_t status_flags) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%x", static_cast<unsigned int>(status_flags));
    return std::string(buf);
}

bool buildAirPlayTxtEntries(const info::AirPlayConfig& config,
                            const pairing::Identity& identity,
                            std::vector<TxtEntry>& out,
                            std::string* error_out,
                            const AirPlayTxtOptions& options) {
    out.clear();
    if (!identity.valid()) {
        setError(error_out, "accessory identity is not initialized");
        return false;
    }
    if (config.device_id.empty()) {
        setError(error_out, "AirPlayConfig::device_id must not be empty");
        return false;
    }
    if (config.model.empty()) {
        setError(error_out, "AirPlayConfig::model must not be empty");
        return false;
    }
    if (config.source_version.empty()) {
        setError(error_out, "AirPlayConfig::source_version must not be empty");
        return false;
    }

    TxtRecordBuilder builder;
    if (!builder.add("deviceid", config.device_id, error_out) ||
        !builder.add("features", formatAirPlayFeaturesTxt(info::features(config)), error_out) ||
        !builder.add("flags", formatAirPlayFlagsTxt(options.status_flags), error_out) ||
        !builder.add("model", config.model, error_out) ||
        !builder.add("pi", identity.pairing_id, error_out) ||
        !builder.add("pk", toLowerHex(identity.keys.public_key, crypto::kEd25519PublicKeyBytes),
                     error_out) ||
        !builder.add("srcvers", config.source_version, error_out)) {
        return false;
    }

    for (size_t i = 0; i < options.extra_entries.size(); ++i) {
        const TxtEntry& extra = options.extra_entries[i];
        bool ok = false;
        if (extra.has_value) {
            const uint8_t* ptr = extra.value.empty() ? NULL : &extra.value[0];
            ok = builder.addBytes(extra.key, ptr, extra.value.size(), error_out);
        } else {
            ok = builder.addFlag(extra.key, error_out);
        }
        if (!ok) {
            return false;
        }
    }

    out = builder.entries();
    return true;
}

bool buildAirPlayTxtRecord(const info::AirPlayConfig& config,
                           const pairing::Identity& identity,
                           std::vector<uint8_t>& out,
                           std::string* error_out,
                           const AirPlayTxtOptions& options) {
    std::vector<TxtEntry> entries;
    if (!buildAirPlayTxtEntries(config, identity, entries, error_out, options)) {
        out.clear();
        return false;
    }
    return encodeTxtRecord(entries, out, error_out);
}

}  // namespace dnssd
}  // namespace carplay
