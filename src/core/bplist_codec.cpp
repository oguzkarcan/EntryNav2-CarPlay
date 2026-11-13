#include "carplay/bplist_codec.hpp"

#include <cmath>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <sstream>

namespace carplay {
namespace bplist {

namespace {

static const char kMagic[8] = {'b', 'p', 'l', 'i', 's', 't', '0', '0'};
static const size_t kHeaderBytes = 8;
static const size_t kTrailerBytes = 32;

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

uint64_t readBeUint(const uint8_t* p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        v = (v << 8) | static_cast<uint64_t>(p[i]);
    }
    return v;
}

void appendBeUint(std::vector<uint8_t>& out, uint64_t val, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        const size_t shift = (n - 1 - i) * 8;
        out.push_back(static_cast<uint8_t>((val >> shift) & 0xffU));
    }
}

bool isPureAscii(const std::string& s) {
    for (size_t i = 0; i < s.size(); ++i) {
        if (static_cast<uint8_t>(s[i]) >= 0x80U) {
            return false;
        }
    }
    return true;
}

bool utf8ToUtf16Units(const std::string& utf8, std::vector<uint16_t>& units_out) {
    units_out.clear();
    const size_t n = utf8.size();
    size_t i = 0;
    while (i < n) {
        const uint8_t b0 = static_cast<uint8_t>(utf8[i]);
        uint32_t cp = 0;
        if (b0 < 0x80U) {
            cp = b0;
            i += 1;
        } else if ((b0 & 0xe0U) == 0xc0U) {
            if (i + 1 >= n) return false;
            const uint8_t b1 = static_cast<uint8_t>(utf8[i + 1]);
            if ((b1 & 0xc0U) != 0x80U) return false;
            cp = (static_cast<uint32_t>(b0 & 0x1fU) << 6) | static_cast<uint32_t>(b1 & 0x3fU);
            if (cp < 0x80U) return false;
            i += 2;
        } else if ((b0 & 0xf0U) == 0xe0U) {
            if (i + 2 >= n) return false;
            const uint8_t b1 = static_cast<uint8_t>(utf8[i + 1]);
            const uint8_t b2 = static_cast<uint8_t>(utf8[i + 2]);
            if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U) return false;
            cp = (static_cast<uint32_t>(b0 & 0x0fU) << 12) |
                 (static_cast<uint32_t>(b1 & 0x3fU) << 6) |
                 static_cast<uint32_t>(b2 & 0x3fU);
            if (cp < 0x800U || (cp >= 0xd800U && cp <= 0xdfffU)) return false;
            i += 3;
        } else if ((b0 & 0xf8U) == 0xf0U) {
            if (i + 3 >= n) return false;
            const uint8_t b1 = static_cast<uint8_t>(utf8[i + 1]);
            const uint8_t b2 = static_cast<uint8_t>(utf8[i + 2]);
            const uint8_t b3 = static_cast<uint8_t>(utf8[i + 3]);
            if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U || (b3 & 0xc0U) != 0x80U) return false;
            cp = (static_cast<uint32_t>(b0 & 0x07U) << 18) |
                 (static_cast<uint32_t>(b1 & 0x3fU) << 12) |
                 (static_cast<uint32_t>(b2 & 0x3fU) << 6) |
                 static_cast<uint32_t>(b3 & 0x3fU);
            if (cp < 0x10000U || cp > 0x10ffffU) return false;
            i += 4;
        } else {
            return false;
        }

        if (cp <= 0xffffU) {
            units_out.push_back(static_cast<uint16_t>(cp));
        } else {
            const uint32_t adj = cp - 0x10000U;
            units_out.push_back(static_cast<uint16_t>(0xd800U + (adj >> 10)));
            units_out.push_back(static_cast<uint16_t>(0xdc00U + (adj & 0x3ffU)));
        }
    }
    return true;
}

void appendUtf8CodePoint(std::string& out, uint32_t cp) {
    if (cp <= 0x7fU) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7ffU) {
        out.push_back(static_cast<char>(0xc0U | (cp >> 6)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
    } else if (cp <= 0xffffU) {
        out.push_back(static_cast<char>(0xe0U | (cp >> 12)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 6) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
    } else {
        out.push_back(static_cast<char>(0xf0U | (cp >> 18)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 12) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 6) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
    }
}

bool utf16BeToUtf8(const uint8_t* p, size_t unit_count, std::string& utf8_out) {
    utf8_out.clear();
    for (size_t i = 0; i < unit_count; ++i) {
        const uint16_t u1 = static_cast<uint16_t>((static_cast<uint16_t>(p[2 * i]) << 8) | p[2 * i + 1]);
        if (u1 >= 0xd800U && u1 <= 0xdbffU) {
            if (i + 1 >= unit_count) return false;
            const uint16_t u2 = static_cast<uint16_t>((static_cast<uint16_t>(p[2 * (i + 1)]) << 8) | p[2 * (i + 1) + 1]);
            if (u2 < 0xdc00U || u2 > 0xdfffU) return false;
            const uint32_t cp = 0x10000U + ((static_cast<uint32_t>(u1 - 0xd800U) << 10) | (u2 - 0xdc00U));
            appendUtf8CodePoint(utf8_out, cp);
            ++i;
        } else if (u1 >= 0xdc00U && u1 <= 0xdfffU) {
            return false;
        } else {
            appendUtf8CodePoint(utf8_out, u1);
        }
    }
    return true;
}

class Encoder {
public:
    bool run(const Value& root, std::vector<uint8_t>& bytes_out, std::string* error_out) {
        nodes_.clear();
        string_pool_.clear();

        size_t root_idx = 0;
        if (!collect(root, root_idx, error_out)) {
            return false;
        }

        const size_t num_objects = nodes_.size();
        const uint8_t ref_size = minByteSize(static_cast<uint64_t>(num_objects));

        bytes_out.clear();
        bytes_out.insert(bytes_out.end(), kMagic, kMagic + kHeaderBytes);

        std::vector<uint64_t> offsets(num_objects, 0);
        for (size_t i = 0; i < num_objects; ++i) {
            offsets[i] = static_cast<uint64_t>(bytes_out.size());
            if (!writeObject(nodes_[i], ref_size, bytes_out, error_out)) {
                return false;
            }
        }

        const uint64_t offset_table_offset = static_cast<uint64_t>(bytes_out.size());
        const uint8_t offset_int_size = minByteSize(offset_table_offset);
        for (size_t i = 0; i < num_objects; ++i) {
            appendBeUint(bytes_out, offsets[i], offset_int_size);
        }

        // 32-byte trailer: 6 zero bytes + offset_int_size + object_ref_size + num_objects + top_obj + offset_table_offset
        for (size_t i = 0; i < 6; ++i) {
            bytes_out.push_back(0);
        }
        bytes_out.push_back(offset_int_size);
        bytes_out.push_back(ref_size);
        appendBeUint(bytes_out, static_cast<uint64_t>(num_objects), 8);
        appendBeUint(bytes_out, static_cast<uint64_t>(root_idx), 8);
        appendBeUint(bytes_out, offset_table_offset, 8);
        return true;
    }

private:
    struct Node {
        const Value* value;
        std::vector<size_t> key_indices;
        std::vector<size_t> child_indices;
    };

    static uint8_t minByteSize(uint64_t max_val) {
        if (max_val <= 0xffULL) return 1;
        if (max_val <= 0xffffULL) return 2;
        if (max_val <= 0xffffffffULL) return 4;
        return 8;
    }

    static void writeMarkerAndCount(std::vector<uint8_t>& out, uint8_t base_tag, size_t count) {
        if (count < 15) {
            out.push_back(static_cast<uint8_t>(base_tag | count));
        } else {
            out.push_back(static_cast<uint8_t>(base_tag | 0x0fU));
            writeIntScalar(out, static_cast<int64_t>(count));
        }
    }

    static void writeIntScalar(std::vector<uint8_t>& out, int64_t v) {
        if (v >= 0) {
            const uint64_t u = static_cast<uint64_t>(v);
            if (u <= 0xffULL) {
                out.push_back(0x10);
                appendBeUint(out, u, 1);
            } else if (u <= 0xffffULL) {
                out.push_back(0x11);
                appendBeUint(out, u, 2);
            } else if (u <= 0xffffffffULL) {
                out.push_back(0x12);
                appendBeUint(out, u, 4);
            } else {
                out.push_back(0x13);
                appendBeUint(out, u, 8);
            }
        } else {
            out.push_back(0x13);
            appendBeUint(out, static_cast<uint64_t>(v), 8);
        }
    }

    bool collect(const Value& val, size_t& index_out, std::string* error_out) {
        if (val.isString()) {
            std::map<std::string, size_t>::const_iterator it = string_pool_.find(val.asString());
            if (it != string_pool_.end()) {
                index_out = it->second;
                return true;
            }
        }

        const size_t my_idx = nodes_.size();
        Node node;
        node.value = &val;
        nodes_.push_back(node);

        if (val.isString()) {
            string_pool_[val.asString()] = my_idx;
        } else if (val.isArray()) {
            const Value::Array& arr = val.asArray();
            std::vector<size_t> children(arr.size(), 0);
            for (size_t i = 0; i < arr.size(); ++i) {
                if (!collect(arr[i], children[i], error_out)) {
                    return false;
                }
            }
            nodes_[my_idx].child_indices = children;
        } else if (val.isDict()) {
            const Value::Dict& dict = val.asDict();
            std::vector<size_t> keys(dict.size(), 0);
            std::vector<size_t> vals(dict.size(), 0);
            for (size_t i = 0; i < dict.size(); ++i) {
                std::map<std::string, size_t>::const_iterator it = string_pool_.find(dict[i].first);
                if (it != string_pool_.end()) {
                    keys[i] = it->second;
                } else {
                    keys_.push_back(Value::makeString(dict[i].first));
                    if (!collect(keys_.back(), keys[i], error_out)) {
                        return false;
                    }
                }
            }
            for (size_t i = 0; i < dict.size(); ++i) {
                if (!collect(dict[i].second, vals[i], error_out)) {
                    return false;
                }
            }
            nodes_[my_idx].key_indices = keys;
            nodes_[my_idx].child_indices = vals;
        }

        index_out = my_idx;
        return true;
    }

    bool writeObject(const Node& node, uint8_t ref_size, std::vector<uint8_t>& out, std::string* error_out) const {
        const Value& v = *node.value;
        switch (v.type()) {
            case Value::TYPE_NULL:
                out.push_back(0x00);
                return true;
            case Value::TYPE_BOOL:
                out.push_back(v.asBool() ? 0x09 : 0x08);
                return true;
            case Value::TYPE_INT:
                writeIntScalar(out, v.asInt());
                return true;
            case Value::TYPE_REAL: {
                out.push_back(0x23);
                uint64_t bits = 0;
                const double d = v.asReal();
                std::memcpy(&bits, &d, sizeof(bits));
                appendBeUint(out, bits, 8);
                return true;
            }
            case Value::TYPE_DATE: {
                out.push_back(0x33);
                uint64_t bits = 0;
                const double d = v.asDateAppleSeconds();
                std::memcpy(&bits, &d, sizeof(bits));
                appendBeUint(out, bits, 8);
                return true;
            }
            case Value::TYPE_UID: {
                const uint64_t u = v.asUid();
                uint8_t nbytes = 1;
                if (u > 0xffffffffULL) {
                    nbytes = 8;
                } else if (u > 0xffffULL) {
                    nbytes = 4;
                } else if (u > 0xffULL) {
                    nbytes = 2;
                }
                out.push_back(static_cast<uint8_t>(0x80U | (nbytes - 1)));
                appendBeUint(out, u, nbytes);
                return true;
            }
            case Value::TYPE_DATA: {
                const std::vector<uint8_t>& data = v.asData();
                writeMarkerAndCount(out, 0x40, data.size());
                out.insert(out.end(), data.begin(), data.end());
                return true;
            }
            case Value::TYPE_STRING: {
                const std::string& s = v.asString();
                if (isPureAscii(s)) {
                    writeMarkerAndCount(out, 0x50, s.size());
                    out.insert(out.end(), s.begin(), s.end());
                } else {
                    std::vector<uint16_t> units;
                    if (!utf8ToUtf16Units(s, units)) {
                        setError(error_out, "invalid UTF-8 string in bplist encode");
                        return false;
                    }
                    writeMarkerAndCount(out, 0x60, units.size());
                    for (size_t i = 0; i < units.size(); ++i) {
                        appendBeUint(out, units[i], 2);
                    }
                }
                return true;
            }
            case Value::TYPE_ARRAY: {
                writeMarkerAndCount(out, 0xa0, node.child_indices.size());
                for (size_t i = 0; i < node.child_indices.size(); ++i) {
                    appendBeUint(out, static_cast<uint64_t>(node.child_indices[i]), ref_size);
                }
                return true;
            }
            case Value::TYPE_DICT: {
                writeMarkerAndCount(out, 0xd0, node.child_indices.size());
                for (size_t i = 0; i < node.key_indices.size(); ++i) {
                    appendBeUint(out, static_cast<uint64_t>(node.key_indices[i]), ref_size);
                }
                for (size_t i = 0; i < node.child_indices.size(); ++i) {
                    appendBeUint(out, static_cast<uint64_t>(node.child_indices[i]), ref_size);
                }
                return true;
            }
        }
        return false;
    }

    std::vector<Node> nodes_;
    std::deque<Value> keys_;
    std::map<std::string, size_t> string_pool_;
};

class Decoder {
public:
    Decoder(const uint8_t* data, size_t len, const Limits& limits)
        : data_(data),
          len_(len),
          limits_(limits),
          offset_int_size_(0),
          object_ref_size_(0),
          num_objects_(0),
          top_object_(0),
          offset_table_offset_(0),
          read_count_(0),
          total_decoded_bytes_(0) {}

    bool run(Value& root_out, std::string* error_out) {
        if (data_ == NULL || len_ < kHeaderBytes + kTrailerBytes) {
            setError(error_out, "bplist buffer too short");
            return false;
        }
        if (std::memcmp(data_, kMagic, kHeaderBytes) != 0) {
            setError(error_out, "missing bplist00 magic header");
            return false;
        }

        const size_t trailer_pos = len_ - kTrailerBytes;
        const uint8_t* trailer = data_ + trailer_pos;
        offset_int_size_ = trailer[6];
        object_ref_size_ = trailer[7];
        if (!isValidIntSize(offset_int_size_) || object_ref_size_ == 0 || object_ref_size_ > 8) {
            setError(error_out, "invalid bplist trailer integer sizes");
            return false;
        }

        num_objects_ = readBeUint(trailer + 8, 8);
        top_object_ = readBeUint(trailer + 16, 8);
        offset_table_offset_ = readBeUint(trailer + 24, 8);

        if (num_objects_ == 0 || top_object_ >= num_objects_) {
            setError(error_out, "invalid bplist object count or top object index");
            return false;
        }
        if (offset_table_offset_ < kHeaderBytes || offset_table_offset_ >= trailer_pos) {
            setError(error_out, "invalid bplist offset table offset");
            return false;
        }
        const uint64_t avail_table_bytes = static_cast<uint64_t>(trailer_pos) - offset_table_offset_;
        if (avail_table_bytes / offset_int_size_ < num_objects_) {
            setError(error_out, "bplist offset table truncated or num_objects out of bounds");
            return false;
        }
        if (num_objects_ > limits_.max_reads) {
            setError(error_out, "bplist num_objects exceeds read limit");
            return false;
        }

        active_.assign(static_cast<size_t>(num_objects_), 0);
        return readObject(static_cast<size_t>(top_object_), 0, root_out, error_out);
    }

private:
    static bool isValidIntSize(uint8_t s) {
        return s == 1 || s == 2 || s == 3 || s == 4 || s == 8;
    }

    bool bumpReads(size_t n, std::string* error_out) {
        if (n > limits_.max_reads || read_count_ + n > limits_.max_reads) {
            setError(error_out, "bplist read limit exceeded (possible amplification attack)");
            return false;
        }
        read_count_ += n;
        return true;
    }

    bool consumePayloadBytes(size_t n, std::string* error_out) {
        if (n > limits_.max_object_bytes || total_decoded_bytes_ + n > limits_.max_total_decoded_bytes) {
            setError(error_out, "bplist payload byte budget exceeded");
            return false;
        }
        total_decoded_bytes_ += n;
        return true;
    }

    bool lookupObjectOffset(size_t obj_idx, size_t& off_out, std::string* error_out) const {
        if (static_cast<uint64_t>(obj_idx) >= num_objects_) {
            setError(error_out, "bplist object reference out of range");
            return false;
        }
        const uint64_t entry_pos = offset_table_offset_ + static_cast<uint64_t>(obj_idx) * offset_int_size_;
        const uint64_t raw_off = readBeUint(data_ + entry_pos, offset_int_size_);
        if (raw_off < kHeaderBytes || raw_off >= offset_table_offset_) {
            setError(error_out, "bplist object offset points outside object table");
            return false;
        }
        off_out = static_cast<size_t>(raw_off);
        return true;
    }

    bool readLength(size_t& cursor, uint8_t low_nibble, size_t& length_out, std::string* error_out) const {
        if (low_nibble < 0x0fU) {
            length_out = low_nibble;
            return true;
        }
        if (cursor >= static_cast<size_t>(offset_table_offset_)) {
            setError(error_out, "truncated bplist extended length marker");
            return false;
        }
        const uint8_t marker = data_[cursor++];
        if ((marker & 0xf0U) != 0x10U) {
            setError(error_out, "expected integer marker for extended length");
            return false;
        }
        const uint8_t shift = static_cast<uint8_t>(marker & 0x0fU);
        if (shift > 3) {
            setError(error_out, "bplist extended length integer too wide");
            return false;
        }
        const size_t int_bytes = static_cast<size_t>(1U) << shift;
        if (cursor + int_bytes > static_cast<size_t>(offset_table_offset_)) {
            setError(error_out, "truncated bplist extended length value");
            return false;
        }
        const uint64_t val = readBeUint(data_ + cursor, int_bytes);
        cursor += int_bytes;
        if (int_bytes == 8 && (val & 0x8000000000000000ULL) != 0) {
            setError(error_out, "negative bplist extended length");
            return false;
        }
        if (val > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
            setError(error_out, "bplist length overflows size_t");
            return false;
        }
        length_out = static_cast<size_t>(val);
        return true;
    }

    bool readIntValue(size_t& cursor, uint8_t low_nibble, int64_t& val_out, std::string* error_out) const {
        if (low_nibble > 4) {
            setError(error_out, "bplist integer width exceeds 16 bytes");
            return false;
        }
        const size_t nbytes = static_cast<size_t>(1U) << low_nibble;
        if (cursor + nbytes > static_cast<size_t>(offset_table_offset_)) {
            setError(error_out, "truncated bplist integer");
            return false;
        }
        if (nbytes == 1 || nbytes == 2 || nbytes == 4) {
            val_out = static_cast<int64_t>(readBeUint(data_ + cursor, nbytes));
        } else if (nbytes == 8) {
            val_out = static_cast<int64_t>(readBeUint(data_ + cursor, 8));
        } else {
            // 16-byte signed big-endian integer (only valid if representable in int64_t).
            const uint64_t hi = readBeUint(data_ + cursor, 8);
            const uint64_t lo = readBeUint(data_ + cursor + 8, 8);
            const bool lo_msb = (lo & 0x8000000000000000ULL) != 0;
            if ((hi == 0 && !lo_msb) || (hi == 0xffffffffffffffffULL && lo_msb)) {
                val_out = static_cast<int64_t>(lo);
            } else {
                setError(error_out, "128-bit bplist integer overflows int64");
                return false;
            }
        }
        cursor += nbytes;
        return true;
    }

    bool readObject(size_t obj_idx, size_t depth, Value& out, std::string* error_out) {
        if (depth > limits_.max_depth) {
            setError(error_out, "bplist nesting depth exceeds limit");
            return false;
        }
        if (!bumpReads(1, error_out)) {
            return false;
        }
        if (obj_idx >= active_.size()) {
            setError(error_out, "bplist object index out of bounds");
            return false;
        }
        if (active_[obj_idx] != 0) {
            setError(error_out, "cyclic bplist object reference detected");
            return false;
        }

        size_t pos = 0;
        if (!lookupObjectOffset(obj_idx, pos, error_out)) {
            return false;
        }

        active_[obj_idx] = 1;
        const size_t obj_end = static_cast<size_t>(offset_table_offset_);
        const uint8_t marker = data_[pos++];
        const uint8_t kind = static_cast<uint8_t>(marker & 0xf0U);
        const uint8_t info = static_cast<uint8_t>(marker & 0x0fU);

        bool ok = false;
        if (kind == 0x00U) {
            if (marker == 0x00U || marker == 0x0fU) {
                out = Value::makeNull();
                ok = true;
            } else if (marker == 0x08U) {
                out = Value::makeBool(false);
                ok = true;
            } else if (marker == 0x09U) {
                out = Value::makeBool(true);
                ok = true;
            } else {
                setError(error_out, "unsupported bplist singleton marker");
            }
        } else if (kind == 0x10U) {
            int64_t iv = 0;
            if (readIntValue(pos, info, iv, error_out)) {
                out = Value::makeInt(iv);
                ok = true;
            }
        } else if (kind == 0x20U) {
            if (info == 2) {
                if (pos + 4 <= obj_end) {
                    const uint32_t bits = static_cast<uint32_t>(readBeUint(data_ + pos, 4));
                    float f = 0.0f;
                    std::memcpy(&f, &bits, sizeof(f));
                    out = Value::makeReal(static_cast<double>(f));
                    ok = true;
                } else {
                    setError(error_out, "truncated bplist float32");
                }
            } else if (info == 3) {
                if (pos + 8 <= obj_end) {
                    const uint64_t bits = readBeUint(data_ + pos, 8);
                    double d = 0.0;
                    std::memcpy(&d, &bits, sizeof(d));
                    out = Value::makeReal(d);
                    ok = true;
                } else {
                    setError(error_out, "truncated bplist float64");
                }
            } else {
                setError(error_out, "unsupported bplist real byte width");
            }
        } else if (marker == 0x33U) {
            if (pos + 8 <= obj_end) {
                const uint64_t bits = readBeUint(data_ + pos, 8);
                double d = 0.0;
                std::memcpy(&d, &bits, sizeof(d));
                out = Value::makeDateAppleSeconds(d);
                ok = true;
            } else {
                setError(error_out, "truncated bplist date");
            }
        } else if (kind == 0x40U) {
            size_t len = 0;
            if (readLength(pos, info, len, error_out)) {
                if (len > obj_end - pos) {
                    setError(error_out, "truncated bplist data blob");
                } else if (consumePayloadBytes(len, error_out)) {
                    out = Value::makeData(data_ + pos, len);
                    ok = true;
                }
            }
        } else if (kind == 0x50U) {
            size_t len = 0;
            if (readLength(pos, info, len, error_out)) {
                if (len > obj_end - pos) {
                    setError(error_out, "truncated bplist ASCII string");
                } else if (consumePayloadBytes(len, error_out)) {
                    std::string s(reinterpret_cast<const char*>(data_ + pos), len);
                    out = Value::makeString(s);
                    ok = true;
                }
            }
        } else if (kind == 0x60U) {
            size_t char_count = 0;
            if (readLength(pos, info, char_count, error_out)) {
                if (char_count > (obj_end - pos) / 2U) {
                    setError(error_out, "truncated bplist UTF-16BE string");
                } else if (consumePayloadBytes(char_count * 2U, error_out)) {
                    std::string utf8;
                    if (!utf16BeToUtf8(data_ + pos, char_count, utf8)) {
                        setError(error_out, "invalid UTF-16BE string in bplist");
                    } else {
                        out = Value::makeString(utf8);
                        ok = true;
                    }
                }
            }
        } else if (kind == 0x80U) {
            const size_t uid_bytes = static_cast<size_t>(info) + 1U;
            if (uid_bytes > 8) {
                setError(error_out, "bplist UID width exceeds 8 bytes");
            } else if (pos + uid_bytes > obj_end) {
                setError(error_out, "truncated bplist UID");
            } else {
                out = Value::makeUid(readBeUint(data_ + pos, uid_bytes));
                ok = true;
            }
        } else if (kind == 0xa0U) {
            size_t count = 0;
            if (readLength(pos, info, count, error_out)) {
                if (count > (obj_end - pos) / object_ref_size_) {
                    setError(error_out, "bplist array truncated");
                } else if (count > limits_.max_reads - read_count_) {
                    setError(error_out, "bplist array size exceeds read budget");
                } else {
                    Value::Array arr(count);
                    bool elems_ok = true;
                    for (size_t i = 0; i < count; ++i) {
                        const uint64_t ref = readBeUint(data_ + pos + i * object_ref_size_, object_ref_size_);
                        if (!readObject(static_cast<size_t>(ref), depth + 1, arr[i], error_out)) {
                            elems_ok = false;
                            break;
                        }
                    }
                    if (elems_ok) {
                        out = Value::makeArray(arr);
                        ok = true;
                    }
                }
            }
        } else if (kind == 0xd0U) {
            size_t count = 0;
            if (readLength(pos, info, count, error_out)) {
                if (count > (obj_end - pos) / (2U * object_ref_size_)) {
                    setError(error_out, "bplist dictionary truncated");
                } else if (count * 2U > limits_.max_reads - read_count_) {
                    setError(error_out, "bplist dictionary size exceeds read budget");
                } else {
                    Value::Dict dict;
                    dict.reserve(count);
                    const size_t keys_off = pos;
                    const size_t vals_off = pos + count * object_ref_size_;
                    bool entries_ok = true;
                    for (size_t i = 0; i < count; ++i) {
                        const uint64_t kref = readBeUint(data_ + keys_off + i * object_ref_size_, object_ref_size_);
                        const uint64_t vref = readBeUint(data_ + vals_off + i * object_ref_size_, object_ref_size_);
                        Value key_val;
                        if (!readObject(static_cast<size_t>(kref), depth + 1, key_val, error_out)) {
                            entries_ok = false;
                            break;
                        }
                        if (!key_val.isString()) {
                            setError(error_out, "bplist dictionary key is not a string");
                            entries_ok = false;
                            break;
                        }
                        Value elem_val;
                        if (!readObject(static_cast<size_t>(vref), depth + 1, elem_val, error_out)) {
                            entries_ok = false;
                            break;
                        }
                        dict.push_back(std::make_pair(key_val.asString(), elem_val));
                    }
                    if (entries_ok) {
                        out = Value::makeDict(dict);
                        ok = true;
                    }
                }
            }
        } else {
            std::ostringstream oss;
            oss << "unsupported bplist object marker 0x" << std::hex << static_cast<unsigned int>(marker);
            setError(error_out, oss.str());
        }

        active_[obj_idx] = 0;
        return ok;
    }

    const uint8_t* data_;
    size_t len_;
    Limits limits_;
    uint8_t offset_int_size_;
    uint8_t object_ref_size_;
    uint64_t num_objects_;
    uint64_t top_object_;
    uint64_t offset_table_offset_;
    size_t read_count_;
    size_t total_decoded_bytes_;
    std::vector<uint8_t> active_;
};

}  // namespace

Value::Value()
    : type_(TYPE_NULL),
      bool_val_(false),
      int_val_(0),
      real_val_(0.0),
      uid_val_(0) {}

Value Value::makeNull() {
    return Value();
}

Value Value::makeBool(bool v) {
    Value out;
    out.type_ = TYPE_BOOL;
    out.bool_val_ = v;
    return out;
}

Value Value::makeInt(int64_t v) {
    Value out;
    out.type_ = TYPE_INT;
    out.int_val_ = v;
    return out;
}

Value Value::makeReal(double v) {
    Value out;
    out.type_ = TYPE_REAL;
    out.real_val_ = v;
    return out;
}

Value Value::makeDateAppleSeconds(double apple_seconds) {
    Value out;
    out.type_ = TYPE_DATE;
    out.real_val_ = apple_seconds;
    return out;
}

Value Value::makeDateUnixMillis(int64_t unix_millis) {
    const double apple_sec = (static_cast<double>(unix_millis) / 1000.0) - kAppleEpochOffsetSeconds;
    return makeDateAppleSeconds(apple_sec);
}

Value Value::makeString(const std::string& v) {
    Value out;
    out.type_ = TYPE_STRING;
    out.str_val_ = v;
    return out;
}

Value Value::makeData(const std::vector<uint8_t>& v) {
    Value out;
    out.type_ = TYPE_DATA;
    out.data_val_ = v;
    return out;
}

Value Value::makeData(const uint8_t* ptr, size_t len) {
    Value out;
    out.type_ = TYPE_DATA;
    if (ptr != NULL && len > 0) {
        out.data_val_.assign(ptr, ptr + len);
    }
    return out;
}

Value Value::makeUid(uint64_t uid) {
    Value out;
    out.type_ = TYPE_UID;
    out.uid_val_ = uid;
    return out;
}

Value Value::makeArray(const Array& arr) {
    Value out;
    out.type_ = TYPE_ARRAY;
    out.array_val_ = arr;
    return out;
}

Value Value::makeDict(const Dict& dict) {
    Value out;
    out.type_ = TYPE_DICT;
    out.dict_val_ = dict;
    return out;
}

int64_t Value::asDateUnixMillis() const {
    const double ms = (real_val_ + kAppleEpochOffsetSeconds) * 1000.0;
    return static_cast<int64_t>(ms >= 0.0 ? std::floor(ms + 0.5) : std::ceil(ms - 0.5));
}

void Value::set(const std::string& key, const Value& val) {
    if (type_ != TYPE_DICT) {
        *this = makeDict();
    }
    for (size_t i = 0; i < dict_val_.size(); ++i) {
        if (dict_val_[i].first == key) {
            dict_val_[i].second = val;
            return;
        }
    }
    dict_val_.push_back(std::make_pair(key, val));
}

const Value* Value::find(const std::string& key) const {
    if (type_ != TYPE_DICT) {
        return NULL;
    }
    for (size_t i = 0; i < dict_val_.size(); ++i) {
        if (dict_val_[i].first == key) {
            return &dict_val_[i].second;
        }
    }
    return NULL;
}

bool Value::getString(const std::string& key, std::string& out) const {
    const Value* v = find(key);
    if (v == NULL || !v->isString()) return false;
    out = v->asString();
    return true;
}

bool Value::getInt(const std::string& key, int64_t& out) const {
    const Value* v = find(key);
    if (v == NULL || !v->isInt()) return false;
    out = v->asInt();
    return true;
}

bool Value::getBool(const std::string& key, bool& out) const {
    const Value* v = find(key);
    if (v == NULL || !v->isBool()) return false;
    out = v->asBool();
    return true;
}

bool Value::operator==(const Value& other) const {
    if (type_ != other.type_) return false;
    switch (type_) {
        case TYPE_NULL:
            return true;
        case TYPE_BOOL:
            return bool_val_ == other.bool_val_;
        case TYPE_INT:
            return int_val_ == other.int_val_;
        case TYPE_REAL:
        case TYPE_DATE:
            return real_val_ == other.real_val_;
        case TYPE_UID:
            return uid_val_ == other.uid_val_;
        case TYPE_STRING:
            return str_val_ == other.str_val_;
        case TYPE_DATA:
            return data_val_ == other.data_val_;
        case TYPE_ARRAY:
            return array_val_ == other.array_val_;
        case TYPE_DICT:
            return dict_val_ == other.dict_val_;
    }
    return false;
}

bool encode(const Value& root, std::vector<uint8_t>& bytes_out, std::string* error_out) {
    Encoder enc;
    return enc.run(root, bytes_out, error_out);
}

bool decode(const uint8_t* data,
            size_t len,
            Value& root_out,
            std::string* error_out,
            const Limits& limits) {
    Decoder dec(data, len, limits);
    return dec.run(root_out, error_out);
}

bool decode(const std::vector<uint8_t>& bytes,
            Value& root_out,
            std::string* error_out,
            const Limits& limits) {
    const uint8_t* ptr = bytes.empty() ? NULL : &bytes[0];
    return decode(ptr, bytes.size(), root_out, error_out, limits);
}

}  // namespace bplist
}  // namespace carplay
