#ifndef CARPLAY_USB_DESCRIPTORS_HPP
#define CARPLAY_USB_DESCRIPTORS_HPP

// Pure USB 2.0, Interface Association, CDC / CDC-NCM 1.0 descriptor parser and
// CarPlay interface selector (iAP2 bulk + CDC-NCM control/data).
//
// Standard USB 2.0 / CDC 1.2 / CDC-NCM 1.0 descriptor layouts and constants are from
// the public USB-IF specifications. Apple vendor-specific interface codes are marked
// "unverified" until validated against a live iPhone USB descriptor dump.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

namespace carplay {
namespace usb {

// Standard USB 2.0 descriptor types (USB 2.0 Table 9-5).
static const uint8_t kDescTypeDevice = 0x01U;
static const uint8_t kDescTypeConfiguration = 0x02U;
static const uint8_t kDescTypeString = 0x03U;
static const uint8_t kDescTypeInterface = 0x04U;
static const uint8_t kDescTypeEndpoint = 0x05U;
static const uint8_t kDescTypeInterfaceAssociation = 0x0bU;
static const uint8_t kDescTypeCsInterface = 0x24U;
static const uint8_t kDescTypeCsEndpoint = 0x25U;

// Standard USB class / CDC subclass codes (USB-IF CDC 1.2 / CDC-NCM 1.0).
static const uint8_t kClassCommunications = 0x02U;
static const uint8_t kSubClassCdcNcm = 0x0dU;
static const uint8_t kClassCdcData = 0x0aU;
static const uint8_t kProtocolCdcNcmData = 0x01U;
static const uint8_t kClassVendorSpecific = 0xffU;

// CDC Class-Specific Interface Functional Descriptor subtypes (bDescriptorType == 0x24).
static const uint8_t kCdcSubtypeHeader = 0x00U;
static const uint8_t kCdcSubtypeUnion = 0x06U;
static const uint8_t kCdcSubtypeEthernet = 0x0fU;
static const uint8_t kCdcSubtypeNcm = 0x1aU;

// Endpoint address direction and transfer type masks (USB 2.0 Section 9.6.6).
static const uint8_t kEpDirMask = 0x80U;
static const uint8_t kEpDirIn = 0x80U;
static const uint8_t kEpDirOut = 0x00U;
static const uint8_t kEpNumberMask = 0x0fU;
static const uint8_t kEpTypeMask = 0x03U;
static const uint8_t kEpTypeControl = 0x00U;
static const uint8_t kEpTypeIsochronous = 0x01U;
static const uint8_t kEpTypeBulk = 0x02U;
static const uint8_t kEpTypeInterrupt = 0x03U;

// Public USB-IF Vendor ID for Apple Inc.
static const uint16_t kAppleVendorId = 0x05acU;

// Apple USB interface class/subclass/protocol identifiers.
static const uint8_t kAppleIap2Class = 0xffU;      // unverified: Apple vendor-specific iAP2 class
static const uint8_t kAppleIap2SubClass = 0xf0U;   // unverified: Apple iAP2 USB bulk subclass
static const uint8_t kAppleIap2Protocol = 0x00U;   // unverified: Apple iAP2 USB bulk protocol
static const uint8_t kAppleUsbmuxClass = 0xffU;    // unverified: Apple usbmux class
static const uint8_t kAppleUsbmuxSubClass = 0xfeU; // unverified: Apple usbmux subclass
static const uint8_t kAppleUsbmuxProtocol = 0x02U; // unverified: Apple usbmux protocol
static const uint8_t kAppleEapClass = 0xffU;       // unverified: Apple Ethernet/EAP class
static const uint8_t kAppleEapSubClass = 0xfdU;    // unverified: Apple Ethernet/EAP subclass
static const uint8_t kAppleEapProtocol = 0x01U;    // unverified: Apple Ethernet/EAP protocol

struct DeviceDescriptor {
    uint16_t bcd_usb;
    uint8_t device_class;
    uint8_t device_subclass;
    uint8_t device_protocol;
    uint8_t max_packet_size0;
    uint16_t id_vendor;
    uint16_t id_product;
    uint16_t bcd_device;
    uint8_t i_manufacturer;
    uint8_t i_product;
    uint8_t i_serial_number;
    uint8_t num_configurations;

    DeviceDescriptor()
        : bcd_usb(0),
          device_class(0),
          device_subclass(0),
          device_protocol(0),
          max_packet_size0(0),
          id_vendor(0),
          id_product(0),
          bcd_device(0),
          i_manufacturer(0),
          i_product(0),
          i_serial_number(0),
          num_configurations(0) {}
};

struct EndpointDescriptor {
    uint8_t address;
    uint8_t attributes;
    uint16_t max_packet_size;
    uint8_t interval;

    EndpointDescriptor() : address(0), attributes(0), max_packet_size(0), interval(0) {}

    bool isIn() const { return (address & kEpDirMask) == kEpDirIn; }
    bool isOut() const { return (address & kEpDirMask) == kEpDirOut; }
    uint8_t number() const { return static_cast<uint8_t>(address & kEpNumberMask); }
    uint8_t transferType() const { return static_cast<uint8_t>(attributes & kEpTypeMask); }
    bool isBulk() const { return transferType() == kEpTypeBulk; }
    bool isInterrupt() const { return transferType() == kEpTypeInterrupt; }
    uint16_t packetSize() const { return static_cast<uint16_t>(max_packet_size & 0x07ffU); }
};

struct CdcHeaderFunctional {
    bool present;
    uint16_t bcd_cdc;

    CdcHeaderFunctional() : present(false), bcd_cdc(0) {}
};

struct CdcUnionFunctional {
    bool present;
    uint8_t control_interface;
    std::vector<uint8_t> subordinate_interfaces;

    CdcUnionFunctional() : present(false), control_interface(0) {}
};

struct CdcEthernetFunctional {
    bool present;
    uint8_t i_mac_address;
    uint32_t ethernet_statistics;
    uint16_t max_segment_size;
    uint16_t number_mc_filters;
    uint8_t number_power_filters;

    CdcEthernetFunctional()
        : present(false),
          i_mac_address(0),
          ethernet_statistics(0),
          max_segment_size(0),
          number_mc_filters(0),
          number_power_filters(0) {}
};

struct CdcNcmFunctional {
    bool present;
    uint16_t bcd_ncm_version;
    uint8_t network_capabilities;

    CdcNcmFunctional() : present(false), bcd_ncm_version(0), network_capabilities(0) {}
};

struct InterfaceDescriptor {
    uint8_t number;
    uint8_t alternate_setting;
    uint8_t num_endpoints;
    uint8_t interface_class;
    uint8_t interface_subclass;
    uint8_t interface_protocol;
    uint8_t i_interface;
    std::vector<EndpointDescriptor> endpoints;
    CdcHeaderFunctional cdc_header;
    CdcUnionFunctional cdc_union;
    CdcEthernetFunctional cdc_ethernet;
    CdcNcmFunctional cdc_ncm;

    InterfaceDescriptor()
        : number(0),
          alternate_setting(0),
          num_endpoints(0),
          interface_class(0),
          interface_subclass(0),
          interface_protocol(0),
          i_interface(0) {}

    const EndpointDescriptor* findBulkIn() const;
    const EndpointDescriptor* findBulkOut() const;
    const EndpointDescriptor* findInterruptIn() const;
};

struct InterfaceAssociationDescriptor {
    uint8_t first_interface;
    uint8_t interface_count;
    uint8_t function_class;
    uint8_t function_subclass;
    uint8_t function_protocol;
    uint8_t i_function;

    InterfaceAssociationDescriptor()
        : first_interface(0),
          interface_count(0),
          function_class(0),
          function_subclass(0),
          function_protocol(0),
          i_function(0) {}
};

struct ConfigurationDescriptor {
    uint16_t total_length;
    uint8_t num_interfaces;
    uint8_t configuration_value;
    uint8_t i_configuration;
    uint8_t attributes;
    uint8_t max_power;
    std::vector<InterfaceAssociationDescriptor> iads;
    std::vector<InterfaceDescriptor> interfaces;

    ConfigurationDescriptor()
        : total_length(0),
          num_interfaces(0),
          configuration_value(0),
          i_configuration(0),
          attributes(0),
          max_power(0) {}
};

struct Iap2SelectionCriteria {
    uint8_t interface_class;
    uint8_t interface_subclass;
    uint8_t interface_protocol;
    bool any_protocol;

    Iap2SelectionCriteria()
        : interface_class(kAppleIap2Class),
          interface_subclass(kAppleIap2SubClass),
          interface_protocol(kAppleIap2Protocol),
          any_protocol(true) {}
};

struct Iap2InterfaceSelection {
    bool found;
    uint8_t interface_number;
    uint8_t alternate_setting;
    uint8_t interface_class;
    uint8_t interface_subclass;
    uint8_t interface_protocol;
    uint8_t bulk_in_ep;
    uint16_t bulk_in_max_packet;
    uint8_t bulk_out_ep;
    uint16_t bulk_out_max_packet;

    Iap2InterfaceSelection()
        : found(false),
          interface_number(0),
          alternate_setting(0),
          interface_class(0),
          interface_subclass(0),
          interface_protocol(0),
          bulk_in_ep(0),
          bulk_in_max_packet(0),
          bulk_out_ep(0),
          bulk_out_max_packet(0) {}
};

struct NcmInterfaceSelection {
    bool found;
    uint8_t control_interface;
    uint8_t control_alt_setting;
    bool has_interrupt_in;
    uint8_t interrupt_in_ep;
    uint16_t interrupt_in_max_packet;
    uint8_t data_interface;
    uint8_t data_alt_setting;
    bool has_idle_alt_setting;
    uint8_t idle_alt_setting;
    uint8_t bulk_in_ep;
    uint16_t bulk_in_max_packet;
    uint8_t bulk_out_ep;
    uint16_t bulk_out_max_packet;
    bool has_mac_string_index;
    uint8_t mac_string_index;
    uint16_t max_segment_size;
    uint16_t bcd_ncm_version;
    uint8_t ncm_capabilities;

    NcmInterfaceSelection()
        : found(false),
          control_interface(0),
          control_alt_setting(0),
          has_interrupt_in(false),
          interrupt_in_ep(0),
          interrupt_in_max_packet(0),
          data_interface(0),
          data_alt_setting(0),
          has_idle_alt_setting(false),
          idle_alt_setting(0),
          bulk_in_ep(0),
          bulk_in_max_packet(0),
          bulk_out_ep(0),
          bulk_out_max_packet(0),
          has_mac_string_index(false),
          mac_string_index(0),
          max_segment_size(0),
          bcd_ncm_version(0),
          ncm_capabilities(0) {}
};

struct CarPlayUsbSelection {
    bool found_config;
    uint8_t configuration_value;
    Iap2InterfaceSelection iap2;
    NcmInterfaceSelection ncm;
    bool has_usbmux;
    bool has_apple_ethernet;

    CarPlayUsbSelection()
        : found_config(false),
          configuration_value(0),
          has_usbmux(false),
          has_apple_ethernet(false) {}
};

/// Parses an 18-byte USB Device Descriptor.
bool parseDeviceDescriptor(const uint8_t* data,
                           size_t len,
                           DeviceDescriptor& out,
                           std::string* error_out = NULL);

/// Parses one USB Configuration Descriptor and all nested interface/endpoint/IAD/CDC
/// descriptors up to wTotalLength. If `bytes_consumed_out != NULL`, reports wTotalLength.
bool parseConfigurationDescriptor(const uint8_t* data,
                                  size_t len,
                                  ConfigurationDescriptor& out,
                                  size_t* bytes_consumed_out = NULL,
                                  std::string* error_out = NULL);

/// Parses a concatenated usbfs / sysfs `descriptors` blob:
/// 18-byte Device Descriptor followed by `num_configurations` Configuration Descriptors.
bool parseUsbfsDescriptors(const uint8_t* data,
                           size_t len,
                           DeviceDescriptor& device_out,
                           std::vector<ConfigurationDescriptor>& configs_out,
                           std::string* error_out = NULL);

/// Selects the best configuration carrying Apple iAP2 and/or CDC-NCM interfaces.
/// Priority: (iAP2 + CDC-NCM) > (iAP2 only) > (CDC-NCM only).
CarPlayUsbSelection selectCarPlayInterfaces(
    const std::vector<ConfigurationDescriptor>& configs,
    const Iap2SelectionCriteria& criteria = Iap2SelectionCriteria());

/// Decodes a USB String Descriptor (bDescriptorType == 0x03, UTF-16LE) into a UTF-8/ASCII string.
bool decodeUsbStringDescriptor(const uint8_t* data,
                               size_t len,
                               std::string& out,
                               std::string* error_out = NULL);

/// Parses a 12-hex-digit CDC Ethernet iMACAddress string (e.g. "02aabbccddee" or with ':')
/// into 6 raw MAC bytes.
bool parseUsbMacString(const std::string& hex_mac, uint8_t mac_out[6]);

}  // namespace usb
}  // namespace carplay

#endif  // CARPLAY_USB_DESCRIPTORS_HPP
