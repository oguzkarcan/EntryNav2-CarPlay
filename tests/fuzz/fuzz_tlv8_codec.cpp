#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "carplay/tlv8_codec.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == NULL && size > 0U) {
        return 0;
    }

    std::vector<carplay::tlv8::Item> items;
    std::string err;
    if (carplay::tlv8::decode(data, size, items, &err)) {
        uint8_t u8 = 0;
        std::string s;
        for (size_t i = 0; i < items.size(); ++i) {
            carplay::tlv8::readU8(items, items[i].type, u8);
            carplay::tlv8::readString(items, items[i].type, s);
            (void)carplay::tlv8::findAll(items, items[i].type);
        }
        (void)carplay::tlv8::splitBySeparator(items);
        std::vector<uint8_t> reenc = carplay::tlv8::encode(items);
        std::vector<carplay::tlv8::Item> items2;
        carplay::tlv8::decode(reenc, items2, &err);
    }
    return 0;
}
