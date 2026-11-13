#ifndef CARPLAY_BPLIST_CODEC_HPP
#define CARPLAY_BPLIST_CODEC_HPP

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

namespace carplay {
namespace bplist {

/// Apple Core Foundation reference epoch offset (2001-01-01T00:00:00Z - 1970-01-01T00:00:00Z).
static const double kAppleEpochOffsetSeconds = 978307200.0;

struct Limits {
    size_t max_depth;
    size_t max_reads;
    size_t max_object_bytes;
    size_t max_total_decoded_bytes;

    static Limits defaults() {
        Limits lim;
        lim.max_depth = 32;
        lim.max_reads = 100000;
        lim.max_object_bytes = 4U * 1024U * 1024U;
        lim.max_total_decoded_bytes = 16U * 1024U * 1024U;
        return lim;
    }
};

class Value {
public:
    enum Type {
        TYPE_NULL = 0,
        TYPE_BOOL,
        TYPE_INT,
        TYPE_REAL,
        TYPE_DATE,
        TYPE_STRING,
        TYPE_DATA,
        TYPE_UID,
        TYPE_ARRAY,
        TYPE_DICT,
        /// Unsigned 64-bit integer in [2^63, 2^64-1] (appended last so existing enum values are stable).
        TYPE_UINT64
    };

    // Integer representation rule (canonical, used by both makeUInt() and the decoder):
    //   * Any integer that fits in int64_t is TYPE_INT (signed, asInt()).
    //   * Only integers in [2^63, 2^64-1] are TYPE_UINT64 (asUInt()).
    // On the wire such values are a 16-byte (0x14) integer with hi == 0, as written by
    // CFBinaryPList (e.g. an iPhone's streamConnectionID). A 0x14 integer with hi == 0 and
    // the low-word MSB clear decodes as TYPE_INT; hi == all-ones with the low-word MSB set
    // decodes as a negative TYPE_INT; every other 0x14 value is rejected as over-wide.
    // 1/2/4/8-byte integers keep Apple semantics (8-byte is signed two's complement).

    typedef std::vector<Value> Array;
    typedef std::vector<std::pair<std::string, Value> > Dict;

    Value();

    static Value makeNull();
    static Value makeBool(bool v);
    static Value makeInt(int64_t v);
    /// Canonical unsigned constructor: TYPE_INT if v <= INT64_MAX, else TYPE_UINT64.
    static Value makeUInt(uint64_t v);
    static Value makeReal(double v);
    static Value makeDateAppleSeconds(double apple_seconds);
    static Value makeDateUnixMillis(int64_t unix_millis);
    static Value makeString(const std::string& v);
    static Value makeData(const std::vector<uint8_t>& v);
    static Value makeData(const uint8_t* ptr, size_t len);
    static Value makeUid(uint64_t uid);
    static Value makeArray(const Array& arr = Array());
    static Value makeDict(const Dict& dict = Dict());

    Type type() const { return type_; }
    bool isNull() const { return type_ == TYPE_NULL; }
    bool isBool() const { return type_ == TYPE_BOOL; }
    bool isInt() const { return type_ == TYPE_INT; }
    bool isReal() const { return type_ == TYPE_REAL; }
    bool isDate() const { return type_ == TYPE_DATE; }
    bool isString() const { return type_ == TYPE_STRING; }
    bool isData() const { return type_ == TYPE_DATA; }
    bool isUid() const { return type_ == TYPE_UID; }
    bool isArray() const { return type_ == TYPE_ARRAY; }
    bool isDict() const { return type_ == TYPE_DICT; }
    /// True for any non-negative integer: TYPE_INT with value >= 0, or TYPE_UINT64.
    /// Note isInt() stays type-exact and is false for TYPE_UINT64.
    bool isUInt() const { return type_ == TYPE_UINT64 || (type_ == TYPE_INT && int_val_ >= 0); }

    bool asBool() const { return bool_val_; }
    int64_t asInt() const { return int_val_; }
    /// Unsigned value; only meaningful when isUInt() is true (returns 0 otherwise).
    uint64_t asUInt() const;
    double asReal() const { return real_val_; }
    double asDateAppleSeconds() const { return real_val_; }
    int64_t asDateUnixMillis() const;
    const std::string& asString() const { return str_val_; }
    const std::vector<uint8_t>& asData() const { return data_val_; }
    uint64_t asUid() const { return uid_val_; }
    const Array& asArray() const { return array_val_; }
    Array& asArray() { return array_val_; }
    const Dict& asDict() const { return dict_val_; }
    Dict& asDict() { return dict_val_; }

    /// Dictionary helpers (for TYPE_DICT).
    void set(const std::string& key, const Value& val);
    const Value* find(const std::string& key) const;
    bool getString(const std::string& key, std::string& out) const;
    /// Succeeds only for TYPE_INT (fits int64_t); returns false for TYPE_UINT64 (>= 2^63).
    bool getInt(const std::string& key, int64_t& out) const;
    /// Succeeds for a non-negative TYPE_INT or a TYPE_UINT64; false for negatives/non-integers.
    bool getUInt(const std::string& key, uint64_t& out) const;
    bool getBool(const std::string& key, bool& out) const;

    bool operator==(const Value& other) const;
    bool operator!=(const Value& other) const { return !(*this == other); }

private:
    Type type_;
    bool bool_val_;
    int64_t int_val_;
    double real_val_;
    uint64_t uid_val_;
    uint64_t uint_val_;
    std::string str_val_;
    std::vector<uint8_t> data_val_;
    Array array_val_;
    Dict dict_val_;
};

/// Renders a non-negative integer Value (isUInt()) as an unsigned decimal string,
/// e.g. "18446744073709551615". Returns false (out untouched) for negatives/non-integers.
/// Use this for derived identifiers such as HKDF salt "DataStream-Salt<streamConnectionID>".
bool toUnsignedDecimal(const Value& v, std::string& out);

/// Encodes a Value tree into Apple `bplist00` binary plist format.
bool encode(const Value& root, std::vector<uint8_t>& bytes_out, std::string* error_out = NULL);

/// Decodes an Apple `bplist00` buffer into a Value tree, enforcing hostile-input bounds.
bool decode(const uint8_t* data,
            size_t len,
            Value& root_out,
            std::string* error_out = NULL,
            const Limits& limits = Limits::defaults());

bool decode(const std::vector<uint8_t>& bytes,
            Value& root_out,
            std::string* error_out = NULL,
            const Limits& limits = Limits::defaults());

}  // namespace bplist
}  // namespace carplay

#endif  // CARPLAY_BPLIST_CODEC_HPP
