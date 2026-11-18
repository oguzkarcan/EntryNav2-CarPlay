// Derived in part from DiPlay-main:
//   shared/src/main/java/com/shilapi/xcertplay/transport/IphoneCarPlayConfiguration.kt
//   shared/src/main/java/com/shilapi/xcertplay/transport/NcmFunctionDiscovery.kt
// GPL-3.0, Copyright (c) DiPlay contributors.

#include "carplay/usb_descriptors.hpp"

#include <sstream>

namespace carplay {
namespace usb {

namespace {

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

uint16_t readU16Le(const uint8_t* p) {
    return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                                 (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t readU32Le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

int hexVal(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

Iap2InterfaceSelection findIap2InConfig(const ConfigurationDescriptor& cfg,
                                        const Iap2SelectionCriteria& criteria) {
    Iap2InterfaceSelection best;
    int best_rank = -1;
    for (size_t i = 0; i < cfg.interfaces.size(); ++i) {
        const InterfaceDescriptor& iface = cfg.interfaces[i];
        if (iface.interface_class != criteria.interface_class ||
            iface.interface_subclass != criteria.interface_subclass) {
            continue;
        }
        const bool exact_proto = (iface.interface_protocol == criteria.interface_protocol);
        if (!exact_proto && !criteria.any_protocol) {
            continue;
        }
        const EndpointDescriptor* bulk_in = iface.findBulkIn();
        const EndpointDescriptor* bulk_out = iface.findBulkOut();
        if (bulk_in == NULL || bulk_out == NULL) {
            continue;
        }
        const int rank = (exact_proto ? 2 : 0) + (iface.alternate_setting == 0 ? 1 : 0);
        if (rank > best_rank) {
            best_rank = rank;
            best.found = true;
            best.interface_number = iface.number;
            best.alternate_setting = iface.alternate_setting;
            best.interface_class = iface.interface_class;
            best.interface_subclass = iface.interface_subclass;
            best.interface_protocol = iface.interface_protocol;
            best.bulk_in_ep = bulk_in->address;
            best.bulk_in_max_packet = bulk_in->packetSize();
            best.bulk_out_ep = bulk_out->address;
            best.bulk_out_max_packet = bulk_out->packetSize();
        }
    }
    return best;
}

// verified: DiPlay-main/.../IphoneCarPlayConfiguration.kt (usbMuxInterface / usbMuxEndpoints)
UsbmuxInterfaceSelection findUsbmuxInConfig(const ConfigurationDescriptor& cfg) {
    UsbmuxInterfaceSelection best;
    int best_rank = -1;
    for (size_t i = 0; i < cfg.interfaces.size(); ++i) {
        const InterfaceDescriptor& iface = cfg.interfaces[i];
        if (iface.interface_class != kAppleUsbmuxClass ||
            iface.interface_subclass != kAppleUsbmuxSubClass ||
            iface.interface_protocol != kAppleUsbmuxProtocol) {
            continue;
        }

        const EndpointDescriptor* pref_out = NULL;
        const EndpointDescriptor* unique_out = NULL;
        size_t out_count = 0U;
        const EndpointDescriptor* pref_in = NULL;
        const EndpointDescriptor* unique_in = NULL;
        size_t in_count = 0U;

        for (size_t e = 0; e < iface.endpoints.size(); ++e) {
            const EndpointDescriptor& ep = iface.endpoints[e];
            if (!ep.isBulk()) {
                continue;
            }
            if (ep.isOut()) {
                ++out_count;
                unique_out = &ep;
                if (ep.address == kPreferredUsbmuxOutEp && pref_out == NULL) {
                    pref_out = &ep;
                }
            } else if (ep.isIn()) {
                ++in_count;
                unique_in = &ep;
                if (ep.address == kPreferredUsbmuxInEp && pref_in == NULL) {
                    pref_in = &ep;
                }
            }
        }

        const EndpointDescriptor* chosen_out =
            (pref_out != NULL) ? pref_out : (out_count == 1U ? unique_out : NULL);
        const EndpointDescriptor* chosen_in =
            (pref_in != NULL) ? pref_in : (in_count == 1U ? unique_in : NULL);
        if (chosen_out == NULL || chosen_in == NULL) {
            continue;
        }

        const int rank = (pref_out != NULL && pref_in != NULL ? 2 : 0) +
                         (iface.alternate_setting == 0 ? 1 : 0);
        if (rank > best_rank) {
            best_rank = rank;
            best.found = true;
            best.interface_number = iface.number;
            best.alternate_setting = iface.alternate_setting;
            best.bulk_in_ep = chosen_in->address;
            best.bulk_in_max_packet = chosen_in->packetSize();
            best.bulk_out_ep = chosen_out->address;
            best.bulk_out_max_packet = chosen_out->packetSize();
        }
    }
    return best;
}

bool pickDataAltSetting(const ConfigurationDescriptor& cfg,
                        uint8_t data_iface_num,
                        NcmInterfaceSelection& out) {
    const InterfaceDescriptor* best_active = NULL;
    int best_alt_rank = -1;
    bool found_idle = false;
    uint8_t idle_alt = 0;

    for (size_t i = 0; i < cfg.interfaces.size(); ++i) {
        const InterfaceDescriptor& iface = cfg.interfaces[i];
        if (iface.number != data_iface_num) {
            continue;
        }
        if (iface.interface_class != kClassCdcData) {
            continue;
        }
        const EndpointDescriptor* bulk_in = iface.findBulkIn();
        const EndpointDescriptor* bulk_out = iface.findBulkOut();
        if (bulk_in != NULL && bulk_out != NULL) {
            // verified: DiPlay NcmFunctionDiscovery.kt prefers DATA_ALTERNATE_SETTING (1),
            // tolerating other active alt settings (or alt 0 when no higher alt exists).
            const int alt_rank =
                (iface.alternate_setting == kNcmDataAltSetting)
                    ? 2
                    : (iface.alternate_setting > 0U ? 1 : 0);
            if (best_active == NULL || alt_rank > best_alt_rank) {
                best_active = &iface;
                best_alt_rank = alt_rank;
            }
        } else if (iface.endpoints.empty() || (bulk_in == NULL && bulk_out == NULL)) {
            if (!found_idle || iface.alternate_setting == 0) {
                found_idle = true;
                idle_alt = iface.alternate_setting;
            }
        }
    }

    if (best_active == NULL) {
        return false;
    }

    const EndpointDescriptor* bulk_in = best_active->findBulkIn();
    const EndpointDescriptor* bulk_out = best_active->findBulkOut();
    out.data_interface = best_active->number;
    out.data_alt_setting = best_active->alternate_setting;
    out.has_idle_alt_setting = found_idle;
    out.idle_alt_setting = idle_alt;
    out.bulk_in_ep = bulk_in->address;
    out.bulk_in_max_packet = bulk_in->packetSize();
    out.bulk_out_ep = bulk_out->address;
    out.bulk_out_max_packet = bulk_out->packetSize();
    return true;
}

NcmInterfaceSelection findNcmInConfig(const ConfigurationDescriptor& cfg) {
    for (size_t i = 0; i < cfg.interfaces.size(); ++i) {
        const InterfaceDescriptor& ctrl = cfg.interfaces[i];
        if (ctrl.interface_class != kClassCommunications ||
            ctrl.interface_subclass != kSubClassCdcNcm) {
            continue;
        }

        NcmInterfaceSelection sel;
        sel.control_interface = ctrl.number;
        sel.control_alt_setting = ctrl.alternate_setting;
        const EndpointDescriptor* intr_in = ctrl.findInterruptIn();
        if (intr_in != NULL) {
            sel.has_interrupt_in = true;
            sel.interrupt_in_ep = intr_in->address;
            sel.interrupt_in_max_packet = intr_in->packetSize();
        }
        if (ctrl.cdc_ethernet.present) {
            sel.has_mac_string_index = (ctrl.cdc_ethernet.i_mac_address != 0);
            sel.mac_string_index = ctrl.cdc_ethernet.i_mac_address;
            sel.max_segment_size = ctrl.cdc_ethernet.max_segment_size;
        }
        if (ctrl.cdc_ncm.present) {
            sel.bcd_ncm_version = ctrl.cdc_ncm.bcd_ncm_version;
            sel.ncm_capabilities = ctrl.cdc_ncm.network_capabilities;
        }

        // 1. Prefer CDC Union Functional Descriptor subordinate interface.
        if (ctrl.cdc_union.present) {
            for (size_t s = 0; s < ctrl.cdc_union.subordinate_interfaces.size(); ++s) {
                const uint8_t sub_num = ctrl.cdc_union.subordinate_interfaces[s];
                if (pickDataAltSetting(cfg, sub_num, sel)) {
                    sel.found = true;
                    return sel;
                }
            }
        }

        // 2. Fallback: look for a matching IAD grouping control + data interfaces.
        for (size_t a = 0; a < cfg.iads.size(); ++a) {
            const InterfaceAssociationDescriptor& iad = cfg.iads[a];
            if (iad.function_class != kClassCommunications ||
                iad.function_subclass != kSubClassCdcNcm) {
                continue;
            }
            if (ctrl.number < iad.first_interface ||
                ctrl.number >= static_cast<unsigned>(iad.first_interface) + iad.interface_count) {
                continue;
            }
            for (unsigned off = 0; off < iad.interface_count; ++off) {
                const uint8_t candidate = static_cast<uint8_t>(iad.first_interface + off);
                if (candidate == ctrl.number) {
                    continue;
                }
                if (pickDataAltSetting(cfg, candidate, sel)) {
                    sel.found = true;
                    return sel;
                }
            }
        }

        // 3. Last resort: any CDC Data interface in the same configuration (preferring NCM protocol).
        for (size_t d = 0; d < cfg.interfaces.size(); ++d) {
            const InterfaceDescriptor& data_if = cfg.interfaces[d];
            if (data_if.interface_class == kClassCdcData &&
                data_if.interface_protocol == kProtocolCdcNcmData &&
                pickDataAltSetting(cfg, data_if.number, sel)) {
                sel.found = true;
                return sel;
            }
        }
        for (size_t d = 0; d < cfg.interfaces.size(); ++d) {
            const InterfaceDescriptor& data_if = cfg.interfaces[d];
            if (data_if.interface_class == kClassCdcData &&
                pickDataAltSetting(cfg, data_if.number, sel)) {
                sel.found = true;
                return sel;
            }
        }
    }
    return NcmInterfaceSelection();
}

}  // namespace

const EndpointDescriptor* InterfaceDescriptor::findBulkIn() const {
    for (size_t i = 0; i < endpoints.size(); ++i) {
        if (endpoints[i].isBulk() && endpoints[i].isIn()) {
            return &endpoints[i];
        }
    }
    return NULL;
}

const EndpointDescriptor* InterfaceDescriptor::findBulkOut() const {
    for (size_t i = 0; i < endpoints.size(); ++i) {
        if (endpoints[i].isBulk() && endpoints[i].isOut()) {
            return &endpoints[i];
        }
    }
    return NULL;
}

const EndpointDescriptor* InterfaceDescriptor::findInterruptIn() const {
    for (size_t i = 0; i < endpoints.size(); ++i) {
        if (endpoints[i].isInterrupt() && endpoints[i].isIn()) {
            return &endpoints[i];
        }
    }
    return NULL;
}

bool parseDeviceDescriptor(const uint8_t* data,
                           size_t len,
                           DeviceDescriptor& out,
                           std::string* error_out) {
    out = DeviceDescriptor();
    if (data == NULL || len < 18U) {
        setError(error_out, "device descriptor truncated (< 18 bytes)");
        return false;
    }
    if (data[0] != 18U || data[1] != kDescTypeDevice) {
        setError(error_out, "invalid USB device descriptor header");
        return false;
    }
    out.bcd_usb = readU16Le(data + 2);
    out.device_class = data[4];
    out.device_subclass = data[5];
    out.device_protocol = data[6];
    out.max_packet_size0 = data[7];
    out.id_vendor = readU16Le(data + 8);
    out.id_product = readU16Le(data + 10);
    out.bcd_device = readU16Le(data + 12);
    out.i_manufacturer = data[14];
    out.i_product = data[15];
    out.i_serial_number = data[16];
    out.num_configurations = data[17];
    return true;
}

bool parseConfigurationDescriptor(const uint8_t* data,
                                  size_t len,
                                  ConfigurationDescriptor& out,
                                  size_t* bytes_consumed_out,
                                  std::string* error_out) {
    out = ConfigurationDescriptor();
    if (bytes_consumed_out != NULL) {
        *bytes_consumed_out = 0;
    }
    if (data == NULL || len < 9U) {
        setError(error_out, "configuration descriptor truncated (< 9 bytes)");
        return false;
    }
    const uint8_t hdr_len = data[0];
    const uint8_t hdr_type = data[1];
    if (hdr_len < 9U || hdr_type != kDescTypeConfiguration || hdr_len > len) {
        setError(error_out, "invalid USB configuration descriptor header");
        return false;
    }
    const uint16_t total_len = readU16Le(data + 2);
    if (total_len < hdr_len || total_len > len) {
        std::ostringstream oss;
        oss << "configuration descriptor wTotalLength=" << total_len
            << " invalid for buffer len=" << len;
        setError(error_out, oss.str());
        return false;
    }

    out.total_length = total_len;
    out.num_interfaces = data[4];
    out.configuration_value = data[5];
    out.i_configuration = data[6];
    out.attributes = data[7];
    out.max_power = data[8];

    size_t offset = hdr_len;
    while (offset < total_len) {
        if (offset + 2U > total_len) {
            setError(error_out, "truncated sub-descriptor header in configuration");
            return false;
        }
        const uint8_t sub_len = data[offset];
        const uint8_t sub_type = data[offset + 1];
        if (sub_len < 2U || offset + sub_len > total_len) {
            std::ostringstream oss;
            oss << "invalid sub-descriptor length " << static_cast<unsigned>(sub_len)
                << " at offset " << offset;
            setError(error_out, oss.str());
            return false;
        }

        if (sub_type == kDescTypeInterface) {
            if (sub_len < 9U) {
                setError(error_out, "interface descriptor shorter than 9 bytes");
                return false;
            }
            InterfaceDescriptor iface;
            iface.number = data[offset + 2];
            iface.alternate_setting = data[offset + 3];
            iface.num_endpoints = data[offset + 4];
            iface.interface_class = data[offset + 5];
            iface.interface_subclass = data[offset + 6];
            iface.interface_protocol = data[offset + 7];
            iface.i_interface = data[offset + 8];
            out.interfaces.push_back(iface);
        } else if (sub_type == kDescTypeEndpoint) {
            if (sub_len < 7U) {
                setError(error_out, "endpoint descriptor shorter than 7 bytes");
                return false;
            }
            if (out.interfaces.empty()) {
                setError(error_out, "endpoint descriptor before any interface descriptor");
                return false;
            }
            EndpointDescriptor ep;
            ep.address = data[offset + 2];
            ep.attributes = data[offset + 3];
            ep.max_packet_size = readU16Le(data + offset + 4);
            ep.interval = data[offset + 6];
            out.interfaces.back().endpoints.push_back(ep);
        } else if (sub_type == kDescTypeInterfaceAssociation) {
            if (sub_len < 8U) {
                setError(error_out, "IAD descriptor shorter than 8 bytes");
                return false;
            }
            InterfaceAssociationDescriptor iad;
            iad.first_interface = data[offset + 2];
            iad.interface_count = data[offset + 3];
            iad.function_class = data[offset + 4];
            iad.function_subclass = data[offset + 5];
            iad.function_protocol = data[offset + 6];
            iad.i_function = data[offset + 7];
            out.iads.push_back(iad);
        } else if (sub_type == kDescTypeCsInterface) {
            if (sub_len < 3U) {
                setError(error_out, "CS_INTERFACE descriptor shorter than 3 bytes");
                return false;
            }
            if (!out.interfaces.empty()) {
                InterfaceDescriptor& cur = out.interfaces.back();
                const uint8_t subtype = data[offset + 2];
                if (subtype == kCdcSubtypeHeader) {
                    if (sub_len < 5U) {
                        setError(error_out, "CDC Header functional descriptor < 5 bytes");
                        return false;
                    }
                    cur.cdc_header.present = true;
                    cur.cdc_header.bcd_cdc = readU16Le(data + offset + 3);
                } else if (subtype == kCdcSubtypeUnion) {
                    if (sub_len < 4U) {
                        setError(error_out, "CDC Union functional descriptor < 4 bytes");
                        return false;
                    }
                    cur.cdc_union.present = true;
                    cur.cdc_union.control_interface = data[offset + 3];
                    cur.cdc_union.subordinate_interfaces.clear();
                    for (size_t k = 4U; k < sub_len; ++k) {
                        cur.cdc_union.subordinate_interfaces.push_back(data[offset + k]);
                    }
                } else if (subtype == kCdcSubtypeEthernet) {
                    if (sub_len < 13U) {
                        setError(error_out, "CDC Ethernet functional descriptor < 13 bytes");
                        return false;
                    }
                    cur.cdc_ethernet.present = true;
                    cur.cdc_ethernet.i_mac_address = data[offset + 3];
                    cur.cdc_ethernet.ethernet_statistics = readU32Le(data + offset + 4);
                    cur.cdc_ethernet.max_segment_size = readU16Le(data + offset + 8);
                    cur.cdc_ethernet.number_mc_filters = readU16Le(data + offset + 10);
                    cur.cdc_ethernet.number_power_filters = data[offset + 12];
                } else if (subtype == kCdcSubtypeNcm) {
                    if (sub_len < 6U) {
                        setError(error_out, "CDC NCM functional descriptor < 6 bytes");
                        return false;
                    }
                    cur.cdc_ncm.present = true;
                    cur.cdc_ncm.bcd_ncm_version = readU16Le(data + offset + 3);
                    cur.cdc_ncm.network_capabilities = data[offset + 5];
                }
            }
        }
        // Other descriptor types (HID, CS_ENDPOINT, vendor, etc.) are skipped cleanly.

        offset += sub_len;
    }

    if (bytes_consumed_out != NULL) {
        *bytes_consumed_out = total_len;
    }
    return true;
}

bool parseUsbfsDescriptors(const uint8_t* data,
                           size_t len,
                           DeviceDescriptor& device_out,
                           std::vector<ConfigurationDescriptor>& configs_out,
                           std::string* error_out) {
    configs_out.clear();
    if (!parseDeviceDescriptor(data, len, device_out, error_out)) {
        return false;
    }
    if (device_out.num_configurations == 0U) {
        setError(error_out, "device descriptor reports 0 configurations");
        return false;
    }

    size_t offset = 18U;
    for (uint8_t c = 0; c < device_out.num_configurations; ++c) {
        if (offset >= len) {
            std::ostringstream oss;
            oss << "missing configuration descriptor " << static_cast<unsigned>(c)
                << " of " << static_cast<unsigned>(device_out.num_configurations);
            setError(error_out, oss.str());
            configs_out.clear();
            return false;
        }
        ConfigurationDescriptor cfg;
        size_t consumed = 0;
        if (!parseConfigurationDescriptor(data + offset, len - offset, cfg, &consumed, error_out)) {
            configs_out.clear();
            return false;
        }
        configs_out.push_back(cfg);
        offset += consumed;
    }
    return true;
}

CarPlayUsbSelection selectCarPlayInterfaces(const std::vector<ConfigurationDescriptor>& configs,
                                            const Iap2SelectionCriteria& criteria) {
    CarPlayUsbSelection best;
    int best_score = 0;

    for (size_t i = 0; i < configs.size(); ++i) {
        const ConfigurationDescriptor& cfg = configs[i];
        const Iap2InterfaceSelection iap2 = findIap2InConfig(cfg, criteria);
        const UsbmuxInterfaceSelection usbmux = findUsbmuxInConfig(cfg);
        const NcmInterfaceSelection ncm = findNcmInConfig(cfg);

        bool has_usbmux = usbmux.found;
        bool has_apple_ethernet = false;
        for (size_t k = 0; k < cfg.interfaces.size(); ++k) {
            const InterfaceDescriptor& iface = cfg.interfaces[k];
            if (iface.interface_class == kAppleUsbmuxClass &&
                iface.interface_subclass == kAppleUsbmuxSubClass &&
                iface.interface_protocol == kAppleUsbmuxProtocol) {
                has_usbmux = true;
            }
            if (iface.interface_class == kAppleEthernetClass &&
                iface.interface_subclass == kAppleEthernetSubClass &&
                iface.interface_protocol == kAppleEthernetProtocol) {
                has_apple_ethernet = true;
            }
        }

        // verified: DiPlay IphoneCarPlayConfiguration.kt — CarPlay mode adds Apple Ethernet (ff/fd/01)
        // alongside USBMUX + CDC-NCM. Plain PTP + USBMUX (no NCM and no iAP2) must score 0.
        int score = 0;
        if (has_usbmux && ncm.found && has_apple_ethernet && iap2.found) {
            score = 6;
        } else if ((has_usbmux || iap2.found) && ncm.found && has_apple_ethernet) {
            score = 5;
        } else if (iap2.found && ncm.found) {
            score = 4;
        } else if (has_usbmux && ncm.found) {
            score = 3;
        } else if (iap2.found) {
            score = 2;
        } else if (ncm.found) {
            score = 1;
        }

        if (score > best_score) {
            best_score = score;
            best = CarPlayUsbSelection();
            best.found_config = true;
            best.configuration_value = cfg.configuration_value;
            best.iap2 = iap2;
            best.usbmux = usbmux;
            best.ncm = ncm;
            best.has_usbmux = has_usbmux;
            best.has_apple_ethernet = has_apple_ethernet;
            best.is_carplay_mode = ((has_usbmux || iap2.found) && ncm.found && has_apple_ethernet);
        }
    }

    return best;
}

bool decodeUsbStringDescriptor(const uint8_t* data,
                               size_t len,
                               std::string& out,
                               std::string* error_out) {
    out.clear();
    if (data == NULL || len < 2U) {
        setError(error_out, "string descriptor truncated (< 2 bytes)");
        return false;
    }
    const uint8_t b_len = data[0];
    if (b_len < 2U || b_len > len || data[1] != kDescTypeString || (b_len & 1U) != 0U) {
        setError(error_out, "invalid USB string descriptor header");
        return false;
    }
    for (size_t i = 2U; i + 1U < b_len; i += 2U) {
        const uint16_t ch = readU16Le(data + i);
        if (ch < 0x80U) {
            out.push_back(static_cast<char>(ch));
        } else if (ch < 0x800U) {
            out.push_back(static_cast<char>(0xc0U | ((ch >> 6) & 0x1fU)));
            out.push_back(static_cast<char>(0x80U | (ch & 0x3fU)));
        } else {
            out.push_back(static_cast<char>(0xe0U | ((ch >> 12) & 0x0fU)));
            out.push_back(static_cast<char>(0x80U | ((ch >> 6) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | (ch & 0x3fU)));
        }
    }
    return true;
}

bool parseUsbMacString(const std::string& hex_mac, uint8_t mac_out[6]) {
    if (mac_out == NULL) {
        return false;
    }
    uint8_t nibbles[12];
    size_t count = 0;
    for (size_t i = 0; i < hex_mac.size(); ++i) {
        const char c = hex_mac[i];
        if (c == ':' || c == '-' || c == ' ') {
            continue;
        }
        const int v = hexVal(c);
        if (v < 0 || count >= 12U) {
            return false;
        }
        nibbles[count++] = static_cast<uint8_t>(v);
    }
    if (count != 12U) {
        return false;
    }
    for (size_t i = 0; i < 6U; ++i) {
        mac_out[i] = static_cast<uint8_t>((nibbles[2U * i] << 4) | nibbles[2U * i + 1U]);
    }
    return true;
}

}  // namespace usb
}  // namespace carplay
