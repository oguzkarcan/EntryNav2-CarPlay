#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "carplay/usb_descriptors.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == NULL && size > 0U) {
        return 0;
    }

    std::string err;
    carplay::usb::DeviceDescriptor dev;
    carplay::usb::parseDeviceDescriptor(data, size, dev, &err);

    carplay::usb::ConfigurationDescriptor cfg;
    size_t consumed = 0U;
    if (carplay::usb::parseConfigurationDescriptor(data, size, cfg, &consumed, &err)) {
        std::vector<carplay::usb::ConfigurationDescriptor> one(1U, cfg);
        (void)carplay::usb::selectCarPlayInterfaces(one);
    }

    std::vector<carplay::usb::ConfigurationDescriptor> configs;
    if (carplay::usb::parseUsbfsDescriptors(data, size, dev, configs, &err)) {
        (void)carplay::usb::selectCarPlayInterfaces(configs);
    }

    std::string str_out;
    carplay::usb::decodeUsbStringDescriptor(data, size, str_out, &err);

    if (size <= 64U && data != NULL) {
        const std::string mac_str(reinterpret_cast<const char*>(data), size);
        uint8_t mac[6];
        carplay::usb::parseUsbMacString(mac_str, mac);
    }
    return 0;
}
