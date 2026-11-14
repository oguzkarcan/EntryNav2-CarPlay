#include "carplay/tlv8_codec.hpp"

#include <sstream>

namespace carplay {
namespace tlv8 {

namespace {

void setError(std::string* error_out, const std::string& msg) {
    if (error_out != NULL) {
        *error_out = msg;
    }
}

void appendItemEncoded(std::vector<uint8_t>& out, uint8_t type, const std::vector<uint8_t>& value) {
    if (type == kSeparatorType) {
        // HAP separator is always zero-length (0xff, 0x00).
        out.push_back(kSeparatorType);
        out.push_back(0);
        return;
    }
    if (value.empty()) {
        out.push_back(type);
        out.push_back(0);
        return;
    }
    size_t offset = 0;
    while (offset < value.size()) {
        size_t chunk = value.size() - offset;
        if (chunk > kMaxFragmentBytes) {
            chunk = kMaxFragmentBytes;
        }
        out.push_back(type);
        out.push_back(static_cast<uint8_t>(chunk));
        out.insert(out.end(),
                   value.begin() + static_cast<ptrdiff_t>(offset),
                   value.begin() + static_cast<ptrdiff_t>(offset + chunk));
        offset += chunk;
    }
}

}  // namespace

Item Item::fromByte(uint8_t t, uint8_t b) {
    Item item;
    item.type = t;
    item.value.push_back(b);
    return item;
}

Item Item::separator() {
    Item item;
    item.type = kSeparatorType;
    return item;
}

std::vector<uint8_t> encode(const std::vector<Item>& items) {
    std::vector<uint8_t> out;
    bool have_prev_non_sep = false;
    uint8_t prev_type = 0;

    for (size_t i = 0; i < items.size(); ++i) {
        const Item& item = items[i];
        if (item.type == kSeparatorType) {
            appendItemEncoded(out, kSeparatorType, std::vector<uint8_t>());
            have_prev_non_sep = false;
            continue;
        }
        if (have_prev_non_sep && prev_type == item.type) {
            // Two separate logical items with the same tag must be delimited by 0xff 0x00.
            out.push_back(kSeparatorType);
            out.push_back(0);
        }
        appendItemEncoded(out, item.type, item.value);
        have_prev_non_sep = true;
        prev_type = item.type;
    }
    return out;
}

bool decode(const uint8_t* data,
            size_t len,
            std::vector<Item>& items_out,
            std::string* error_out) {
    items_out.clear();
    if (len > 0 && data == NULL) {
        setError(error_out, "null buffer with non-zero length");
        return false;
    }

    bool can_append_fragment = false;
    uint8_t prev_type = 0;
    size_t pos = 0;

    while (pos < len) {
        if (pos + 2 > len) {
            std::ostringstream oss;
            oss << "truncated TLV8 header at offset " << pos;
            setError(error_out, oss.str());
            items_out.clear();
            return false;
        }
        const uint8_t type = data[pos];
        const size_t frag_len = static_cast<size_t>(data[pos + 1]);
        pos += 2;

        if (pos + frag_len > len) {
            std::ostringstream oss;
            oss << "truncated TLV8 value for tag 0x" << std::hex << static_cast<unsigned int>(type)
                << " at offset " << std::dec << pos << " (need " << frag_len << ", have " << (len - pos) << ")";
            setError(error_out, oss.str());
            items_out.clear();
            return false;
        }

        if (type == kSeparatorType) {
            if (frag_len != 0) {
                setError(error_out, "TLV8 separator (0xff) must have zero length");
                items_out.clear();
                return false;
            }
            items_out.push_back(Item::separator());
            can_append_fragment = false;
            continue;
        }

        if (can_append_fragment && type == prev_type && !items_out.empty()) {
            std::vector<uint8_t>& dst = items_out.back().value;
            dst.insert(dst.end(), data + pos, data + pos + frag_len);
        } else {
            items_out.push_back(Item(type, data + pos, frag_len));
        }

        pos += frag_len;
        prev_type = type;
        // HAP Spec: a value longer than 255 bytes is fragmented into 255-byte chunks followed by a tail < 255.
        can_append_fragment = (frag_len == kMaxFragmentBytes);
    }
    return true;
}

bool decode(const std::vector<uint8_t>& bytes,
            std::vector<Item>& items_out,
            std::string* error_out) {
    const uint8_t* ptr = bytes.empty() ? NULL : &bytes[0];
    return decode(ptr, bytes.size(), items_out, error_out);
}

const Item* findFirst(const std::vector<Item>& items, uint8_t type) {
    for (size_t i = 0; i < items.size(); ++i) {
        if (items[i].type == type) {
            return &items[i];
        }
    }
    return NULL;
}

std::vector<const Item*> findAll(const std::vector<Item>& items, uint8_t type) {
    std::vector<const Item*> matches;
    for (size_t i = 0; i < items.size(); ++i) {
        if (items[i].type == type) {
            matches.push_back(&items[i]);
        }
    }
    return matches;
}

bool readU8(const std::vector<Item>& items, uint8_t type, uint8_t& out) {
    const Item* item = findFirst(items, type);
    if (item == NULL || item->value.size() != 1) {
        return false;
    }
    out = item->value[0];
    return true;
}

bool readString(const std::vector<Item>& items, uint8_t type, std::string& out) {
    const Item* item = findFirst(items, type);
    if (item == NULL) {
        return false;
    }
    if (item->value.empty()) {
        out.clear();
    } else {
        out.assign(reinterpret_cast<const char*>(&item->value[0]), item->value.size());
    }
    return true;
}

std::vector<std::vector<Item> > splitBySeparator(const std::vector<Item>& items) {
    std::vector<std::vector<Item> > groups;
    groups.push_back(std::vector<Item>());
    for (size_t i = 0; i < items.size(); ++i) {
        if (items[i].type == kSeparatorType) {
            if (!groups.back().empty()) {
                groups.push_back(std::vector<Item>());
            }
        } else {
            groups.back().push_back(items[i]);
        }
    }
    if (groups.size() > 1 && groups.back().empty()) {
        groups.pop_back();
    }
    return groups;
}

}  // namespace tlv8
}  // namespace carplay
