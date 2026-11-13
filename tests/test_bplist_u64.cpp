// bplist00 unsigned 64-bit integer support (0x14 16-byte integers with hi == 0).
// An iPhone may send streamConnectionID >= 2^63 in this form.

#include "carplay/bplist_codec.hpp"
#include "test_support.hpp"

#include <limits>
#include <string>
#include <vector>

using carplay::bplist::Value;
using test_support::hexToBytes;

namespace {

const uint64_t kU64Max = 0xffffffffffffffffULL;
const uint64_t k2Pow63 = 0x8000000000000000ULL;
const uint64_t kI64Max = 0x7fffffffffffffffULL;

void appendBe(std::vector<uint8_t>& out, uint64_t v, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        out.push_back(static_cast<uint8_t>((v >> ((n - 1 - i) * 8)) & 0xffU));
    }
}

// Builds a bplist00 from raw object blobs (1-byte offsets/refs; objects must be small).
std::vector<uint8_t> buildBplist(const std::vector<std::vector<uint8_t> >& objects, uint64_t top) {
    std::vector<uint8_t> out = hexToBytes("62706c6973743030");  // "bplist00"
    std::vector<uint64_t> offsets;
    for (size_t i = 0; i < objects.size(); ++i) {
        offsets.push_back(static_cast<uint64_t>(out.size()));
        out.insert(out.end(), objects[i].begin(), objects[i].end());
    }
    const uint64_t off_table = static_cast<uint64_t>(out.size());
    for (size_t i = 0; i < offsets.size(); ++i) {
        appendBe(out, offsets[i], 1);
    }
    for (size_t i = 0; i < 6; ++i) out.push_back(0);
    out.push_back(1);  // offset_int_size
    out.push_back(1);  // object_ref_size
    appendBe(out, static_cast<uint64_t>(objects.size()), 8);
    appendBe(out, top, 8);
    appendBe(out, off_table, 8);
    return out;
}

std::vector<uint8_t> int128Object(uint64_t hi, uint64_t lo) {
    std::vector<uint8_t> obj;
    obj.push_back(0x14);
    appendBe(obj, hi, 8);
    appendBe(obj, lo, 8);
    return obj;
}

bool decodeSingleInt128(uint64_t hi, uint64_t lo, Value& out) {
    std::vector<std::vector<uint8_t> > objs;
    objs.push_back(int128Object(hi, lo));
    std::string err;
    return carplay::bplist::decode(buildBplist(objs, 0), out, &err);
}

// { "streamConnectionID": <0x14 hi=0 lo> }
std::vector<uint8_t> streamConnectionDict(uint64_t lo) {
    std::vector<std::vector<uint8_t> > objs;
    objs.push_back(hexToBytes("d1 01 02"));
    std::vector<uint8_t> key = hexToBytes("5f 10 12");
    const std::string name("streamConnectionID");
    key.insert(key.end(), name.begin(), name.end());
    objs.push_back(key);
    objs.push_back(int128Object(0, lo));
    return buildBplist(objs, 0);
}

bool roundTrip(const Value& in, Value& out) {
    std::vector<uint8_t> bytes;
    std::string err;
    if (!carplay::bplist::encode(in, bytes, &err)) return false;
    return carplay::bplist::decode(bytes, out, &err);
}

}  // namespace

TEST_CASE(decodeInt128HiZeroAllOnesIsUInt64Max) {
    Value v;
    REQUIRE(decodeSingleInt128(0, kU64Max, v));
    CHECK(v.type() == Value::TYPE_UINT64);
    CHECK(!v.isInt());
    CHECK(v.isUInt());
    CHECK_EQ(kU64Max, v.asUInt());
}

TEST_CASE(decodeInt128HiZeroMsbOnlyIs2Pow63) {
    Value v;
    REQUIRE(decodeSingleInt128(0, k2Pow63, v));
    CHECK(v.type() == Value::TYPE_UINT64);
    CHECK_EQ(k2Pow63, v.asUInt());
}

TEST_CASE(decodeInt128HiZeroMsbClearIsSignedInt) {
    Value v;
    REQUIRE(decodeSingleInt128(0, kI64Max, v));
    CHECK(v.isInt());
    CHECK_EQ(static_cast<int64_t>(kI64Max), v.asInt());
    CHECK(v.isUInt());
    CHECK_EQ(kI64Max, v.asUInt());
}

TEST_CASE(decodeInt128NegativeFormStillWorks) {
    Value v;
    REQUIRE(decodeSingleInt128(kU64Max, kU64Max, v));
    CHECK(v.isInt());
    CHECK_EQ(static_cast<int64_t>(-1), v.asInt());
    CHECK(!v.isUInt());

    Value m;
    REQUIRE(decodeSingleInt128(kU64Max, k2Pow63, m));
    CHECK(m.isInt());
    CHECK_EQ(std::numeric_limits<int64_t>::min(), m.asInt());
}

TEST_CASE(decodeInt128OverWideRejected) {
    Value v;
    CHECK(!decodeSingleInt128(1, 0, v));
    CHECK(!decodeSingleInt128(1, kU64Max, v));
    CHECK(!decodeSingleInt128(k2Pow63, 0, v));
    CHECK(!decodeSingleInt128(0x00000000ffffffffULL, 5, v));
    // hi all-ones but lo MSB clear is not a valid sign extension.
    CHECK(!decodeSingleInt128(kU64Max, kI64Max, v));
    CHECK(!decodeSingleInt128(kU64Max, 0, v));
}

TEST_CASE(roundTripBoundaryValues) {
    const uint64_t uvals[] = {k2Pow63, kU64Max, kI64Max, 0, 1, k2Pow63 + 12345U};
    for (size_t i = 0; i < sizeof(uvals) / sizeof(uvals[0]); ++i) {
        const Value in = Value::makeUInt(uvals[i]);
        Value out;
        REQUIRE(roundTrip(in, out));
        CHECK(in == out);
        CHECK(out.isUInt());
        CHECK_EQ(uvals[i], out.asUInt());
        CHECK_EQ(uvals[i] > kI64Max, out.type() == Value::TYPE_UINT64);
    }

    Value neg;
    REQUIRE(roundTrip(Value::makeInt(-1), neg));
    CHECK(neg.isInt());
    CHECK_EQ(static_cast<int64_t>(-1), neg.asInt());

    Value zero;
    REQUIRE(roundTrip(Value::makeInt(0), zero));
    CHECK(zero == Value::makeUInt(0));
}

TEST_CASE(makeUIntIsCanonical) {
    CHECK(Value::makeUInt(kI64Max).type() == Value::TYPE_INT);
    CHECK(Value::makeUInt(k2Pow63).type() == Value::TYPE_UINT64);
    CHECK(Value::makeUInt(7) == Value::makeInt(7));
    CHECK(Value::makeUInt(k2Pow63) != Value::makeInt(std::numeric_limits<int64_t>::min()));
}

TEST_CASE(encodeUInt64MaxUsesMarker0x14) {
    std::vector<uint8_t> bytes;
    REQUIRE(carplay::bplist::encode(Value::makeUInt(kU64Max), bytes));
    const std::vector<uint8_t> expected = hexToBytes(
        "62706c6973743030"
        "14 0000000000000000 ffffffffffffffff"
        "08"
        "000000000000 01 01"
        "0000000000000001 0000000000000000 0000000000000019");
    CHECK_BYTES_EQ(expected, bytes);

    // Encoder output matches the hand-built CFBinaryPList-style form.
    std::vector<std::vector<uint8_t> > objs;
    objs.push_back(int128Object(0, kU64Max));
    CHECK_BYTES_EQ(buildBplist(objs, 0), bytes);

    // Values < 2^63 keep the minimal encoding (2^63-1 -> 8-byte 0x13).
    std::vector<uint8_t> small;
    REQUIRE(carplay::bplist::encode(Value::makeUInt(kI64Max), small));
    REQUIRE(small.size() > 8);
    CHECK_EQ(0x13, static_cast<int>(small[8]));
}

TEST_CASE(dictGetIntVsGetUInt) {
    Value root;
    REQUIRE(carplay::bplist::decode(streamConnectionDict(kU64Max), root));
    REQUIRE(root.isDict());

    int64_t si = 0;
    CHECK(!root.getInt("streamConnectionID", si));
    uint64_t u = 0;
    CHECK(root.getUInt("streamConnectionID", u));
    CHECK_EQ(kU64Max, u);

    Value root2;
    REQUIRE(carplay::bplist::decode(streamConnectionDict(k2Pow63), root2));
    CHECK(!root2.getInt("streamConnectionID", si));
    CHECK(root2.getUInt("streamConnectionID", u));
    CHECK_EQ(k2Pow63, u);

    Value d = Value::makeDict();
    d.set("small", Value::makeInt(42));
    d.set("neg", Value::makeInt(-5));
    d.set("str", Value::makeString("x"));
    CHECK(d.getInt("small", si));
    CHECK_EQ(static_cast<int64_t>(42), si);
    CHECK(d.getUInt("small", u));
    CHECK_EQ(static_cast<uint64_t>(42), u);
    CHECK(!d.getUInt("neg", u));
    CHECK(d.getInt("neg", si));
    CHECK_EQ(static_cast<int64_t>(-5), si);
    CHECK(!d.getUInt("str", u));
    CHECK(!d.getUInt("missing", u));
}

TEST_CASE(toUnsignedDecimalRendering) {
    std::string s;
    CHECK(carplay::bplist::toUnsignedDecimal(Value::makeUInt(kU64Max), s));
    CHECK_EQ(std::string("18446744073709551615"), s);
    CHECK(carplay::bplist::toUnsignedDecimal(Value::makeUInt(k2Pow63), s));
    CHECK_EQ(std::string("9223372036854775808"), s);
    CHECK(carplay::bplist::toUnsignedDecimal(Value::makeInt(0), s));
    CHECK_EQ(std::string("0"), s);
    CHECK(carplay::bplist::toUnsignedDecimal(Value::makeInt(1234567890123LL), s));
    CHECK_EQ(std::string("1234567890123"), s);

    s = "unchanged";
    CHECK(!carplay::bplist::toUnsignedDecimal(Value::makeInt(-1), s));
    CHECK(!carplay::bplist::toUnsignedDecimal(Value::makeString("1"), s));
    CHECK_EQ(std::string("unchanged"), s);

    Value root;
    REQUIRE(carplay::bplist::decode(streamConnectionDict(kU64Max), root));
    const Value* id = root.find("streamConnectionID");
    REQUIRE(id != NULL);
    CHECK(carplay::bplist::toUnsignedDecimal(*id, s));
    CHECK_EQ(std::string("DataStream-Salt18446744073709551615"), "DataStream-Salt" + s);
}

TEST_CASE(testSupportHexHelpers) {
    std::vector<uint8_t> b;
    CHECK(test_support::hexToBytes("00 Ff:10-a0", b));
    CHECK_EQ(std::string("00ff10a0"), test_support::bytesToHex(b));
    CHECK(!test_support::hexToBytes("abc", b));
    CHECK(!test_support::hexToBytes("zz", b));
    CHECK_EQ(std::string(), test_support::bytesToHex(std::vector<uint8_t>()));
}

int main() {
    return test_support::runAll("test_bplist_u64");
}
