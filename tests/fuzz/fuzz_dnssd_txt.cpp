#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "carplay/dnssd_txt.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == NULL && size > 0U) {
        return 0;
    }

    std::vector<carplay::dnssd::TxtEntry> entries;
    std::string err;
    if (carplay::dnssd::decodeTxtRecord(data, size, entries, &err)) {
        std::vector<uint8_t> enc;
        std::vector<uint8_t> rdata;
        carplay::dnssd::encodeTxtRecord(entries, enc, &err);
        carplay::dnssd::encodeTxtRdata(entries, rdata, &err);
        for (size_t i = 0; i < entries.size(); ++i) {
            (void)entries[i].valueString();
            (void)carplay::dnssd::isValidTxtKey(entries[i].key);
        }
    }

    if (size <= 512U && data != NULL) {
        const std::string key(reinterpret_cast<const char*>(data), size);
        (void)carplay::dnssd::isValidTxtKey(key);
    }
    return 0;
}
