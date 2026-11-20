#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "carplay/bplist_codec.hpp"

namespace {

void inspectValue(const carplay::bplist::Value& v, int depth) {
    if (depth > 32) {
        return;
    }
    (void)v.isUInt();
    std::string dec;
    carplay::bplist::toUnsignedDecimal(v, dec);
    if (v.isDate()) {
        (void)v.asDateUnixMillis();
    }
    if (v.isArray()) {
        const carplay::bplist::Value::Array& arr = v.asArray();
        for (size_t i = 0; i < arr.size() && i < 64U; ++i) {
            inspectValue(arr[i], depth + 1);
        }
    } else if (v.isDict()) {
        const carplay::bplist::Value::Dict& d = v.asDict();
        for (size_t i = 0; i < d.size() && i < 64U; ++i) {
            std::string s;
            int64_t iv = 0;
            uint64_t uv = 0;
            bool bv = false;
            (void)v.getString(d[i].first, s);
            (void)v.getInt(d[i].first, iv);
            (void)v.getUInt(d[i].first, uv);
            (void)v.getBool(d[i].first, bv);
            inspectValue(d[i].second, depth + 1);
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == NULL && size > 0U) {
        return 0;
    }

    carplay::bplist::Value root;
    std::string err;
    if (carplay::bplist::decode(data, size, root, &err)) {
        inspectValue(root, 0);
        std::vector<uint8_t> encoded;
        if (carplay::bplist::encode(root, encoded, &err)) {
            carplay::bplist::Value roundtrip;
            carplay::bplist::decode(encoded, roundtrip, &err);
        }
    }

    carplay::bplist::Limits tight;
    tight.max_depth = 4U;
    tight.max_reads = 64U;
    tight.max_object_bytes = 256U;
    tight.max_total_decoded_bytes = 1024U;
    carplay::bplist::Value root2;
    carplay::bplist::decode(data, size, root2, &err, tight);
    return 0;
}
