#include "carplay/cdc_ncm.hpp"
#include "carplay/usb_descriptors.hpp"
#include "test_support.hpp"

#include <cstring>
#include <string>
#include <vector>

namespace {

using namespace carplay;

void pushU16Le(std::vector<uint8_t>& v, uint16_t val) {
    v.push_back(static_cast<uint8_t>(val & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 8) & 0xffU));
}

void pushU32Le(std::vector<uint8_t>& v, uint32_t val) {
    v.push_back(static_cast<uint8_t>(val & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 8) & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 16) & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 24) & 0xffU));
}

std::vector<uint8_t> makeDeviceDesc(uint16_t vid, uint16_t pid, uint8_t num_configs) {
    std::vector<uint8_t> d;
    d.push_back(18U);                     // bLength
    d.push_back(usb::kDescTypeDevice);    // bDescriptorType
    pushU16Le(d, 0x0200U);                // bcdUSB 2.00
    d.push_back(0x00U);                   // bDeviceClass
    d.push_back(0x00U);                   // bDeviceSubClass
    d.push_back(0x00U);                   // bDeviceProtocol
    d.push_back(64U);                     // bMaxPacketSize0
    pushU16Le(d, vid);                    // idVendor
    pushU16Le(d, pid);                    // idProduct
    pushU16Le(d, 0x0100U);                // bcdDevice
    d.push_back(1U);                      // iManufacturer
    d.push_back(2U);                      // iProduct
    d.push_back(3U);                      // iSerialNumber
    d.push_back(num_configs);             // bNumConfigurations
    return d;
}

void appendIface(std::vector<uint8_t>& body,
                 uint8_t num,
                 uint8_t alt,
                 uint8_t num_eps,
                 uint8_t cls,
                 uint8_t sub,
                 uint8_t proto,
                 uint8_t str_idx = 0) {
    body.push_back(9U);
    body.push_back(usb::kDescTypeInterface);
    body.push_back(num);
    body.push_back(alt);
    body.push_back(num_eps);
    body.push_back(cls);
    body.push_back(sub);
    body.push_back(proto);
    body.push_back(str_idx);
}

void appendEndpoint(std::vector<uint8_t>& body,
                    uint8_t addr,
                    uint8_t attr,
                    uint16_t max_pkt,
                    uint8_t interval = 0) {
    body.push_back(7U);
    body.push_back(usb::kDescTypeEndpoint);
    body.push_back(addr);
    body.push_back(attr);
    pushU16Le(body, max_pkt);
    body.push_back(interval);
}

void appendIad(std::vector<uint8_t>& body,
               uint8_t first_if,
               uint8_t count,
               uint8_t cls,
               uint8_t sub,
               uint8_t proto) {
    body.push_back(8U);
    body.push_back(usb::kDescTypeInterfaceAssociation);
    body.push_back(first_if);
    body.push_back(count);
    body.push_back(cls);
    body.push_back(sub);
    body.push_back(proto);
    body.push_back(0U);
}

void appendCdcHeader(std::vector<uint8_t>& body, uint16_t bcd_cdc) {
    body.push_back(5U);
    body.push_back(usb::kDescTypeCsInterface);
    body.push_back(usb::kCdcSubtypeHeader);
    pushU16Le(body, bcd_cdc);
}

void appendCdcUnion(std::vector<uint8_t>& body, uint8_t master_if, uint8_t slave_if) {
    body.push_back(5U);
    body.push_back(usb::kDescTypeCsInterface);
    body.push_back(usb::kCdcSubtypeUnion);
    body.push_back(master_if);
    body.push_back(slave_if);
}

void appendCdcEthernet(std::vector<uint8_t>& body, uint8_t i_mac, uint16_t max_seg) {
    body.push_back(13U);
    body.push_back(usb::kDescTypeCsInterface);
    body.push_back(usb::kCdcSubtypeEthernet);
    body.push_back(i_mac);
    pushU32Le(body, 0U);      // bmEthernetStatistics
    pushU16Le(body, max_seg); // wMaxSegmentSize
    pushU16Le(body, 0U);      // wNumberMCFilters
    body.push_back(0U);       // bNumberPowerFilters
}

void appendCdcNcm(std::vector<uint8_t>& body, uint16_t bcd_ncm, uint8_t caps) {
    body.push_back(6U);
    body.push_back(usb::kDescTypeCsInterface);
    body.push_back(usb::kCdcSubtypeNcm);
    pushU16Le(body, bcd_ncm);
    body.push_back(caps);
}

std::vector<uint8_t> wrapConfig(uint8_t cfg_val, uint8_t num_ifaces, const std::vector<uint8_t>& body) {
    std::vector<uint8_t> c;
    c.push_back(9U);
    c.push_back(usb::kDescTypeConfiguration);
    pushU16Le(c, static_cast<uint16_t>(9U + body.size()));
    c.push_back(num_ifaces);
    c.push_back(cfg_val);
    c.push_back(0U);    // iConfiguration
    c.push_back(0xc0U); // self-powered
    c.push_back(250U);  // 500 mA
    c.insert(c.end(), body.begin(), body.end());
    return c;
}

std::vector<uint8_t> makeSampleEthernetFrame(uint8_t seed, size_t payload_len) {
    std::vector<uint8_t> f(14U + payload_len, 0U);
    // dst MAC
    f[0] = 0x33U;
    f[1] = 0x33U;
    f[2] = 0x00U;
    f[3] = 0x00U;
    f[4] = 0x00U;
    f[5] = 0x01U;
    // src MAC
    f[6] = 0x02U;
    f[7] = 0x11U;
    f[8] = 0x22U;
    f[9] = 0x33U;
    f[10] = 0x44U;
    f[11] = seed;
    // EtherType IPv6 (0x86dd)
    f[12] = 0x86U;
    f[13] = 0xddU;
    for (size_t i = 0; i < payload_len; ++i) {
        f[14U + i] = static_cast<uint8_t>((seed + i) & 0xffU);
    }
    return f;
}

}  // namespace

TEST_CASE(deviceDescriptorParseAndRejects) {
    const std::vector<uint8_t> dev_bytes = makeDeviceDesc(usb::kAppleVendorId, 0x12a8U, 2U);
    usb::DeviceDescriptor dd;
    std::string err;
    REQUIRE(usb::parseDeviceDescriptor(&dev_bytes[0], dev_bytes.size(), dd, &err));
    CHECK_EQ(0x0200U, dd.bcd_usb);
    CHECK_EQ(usb::kAppleVendorId, dd.id_vendor);
    CHECK_EQ(0x12a8U, dd.id_product);
    CHECK_EQ(64U, dd.max_packet_size0);
    CHECK_EQ(2U, dd.num_configurations);

    // Truncated
    CHECK(!usb::parseDeviceDescriptor(&dev_bytes[0], 17U, dd, &err));
    // Wrong descriptor type
    std::vector<uint8_t> bad = dev_bytes;
    bad[1] = 0x02U;
    CHECK(!usb::parseDeviceDescriptor(&bad[0], bad.size(), dd, &err));
    // Wrong bLength
    bad = dev_bytes;
    bad[0] = 16U;
    CHECK(!usb::parseDeviceDescriptor(&bad[0], bad.size(), dd, &err));
}

TEST_CASE(syntheticIphoneDescriptorAndSelection) {
    // Config 1: PTP (06/01/01) + USBMUX (ff/fe/02) — no CarPlay NCM, no iAP2
    std::vector<uint8_t> body1;
    appendIface(body1, 0U, 0U, 2U, 0x06U, 0x01U, 0x01U);
    appendEndpoint(body1, 0x81U, usb::kEpTypeBulk, 512U);
    appendEndpoint(body1, 0x02U, usb::kEpTypeBulk, 512U);
    appendIface(body1, 1U, 0U, 2U, usb::kAppleUsbmuxClass, usb::kAppleUsbmuxSubClass,
                usb::kAppleUsbmuxProtocol);
    appendEndpoint(body1, 0x83U, usb::kEpTypeBulk, 512U);
    appendEndpoint(body1, 0x04U, usb::kEpTypeBulk, 512U);
    const std::vector<uint8_t> cfg1 = wrapConfig(1U, 2U, body1);

    // Config 2: iAP2 (ff/f0/00) + USBMUX (ff/fe/02) + CDC-NCM (02/0d + 0a/00 alt 0 & alt 1)
    std::vector<uint8_t> body2;
    // Interface 0: Apple iAP2
    appendIface(body2, 0U, 0U, 2U, usb::kAppleIap2Class, usb::kAppleIap2SubClass,
                usb::kAppleIap2Protocol);
    appendEndpoint(body2, 0x81U, usb::kEpTypeBulk, 512U);
    appendEndpoint(body2, 0x01U, usb::kEpTypeBulk, 512U);
    // Interface 1: Apple USBMUX
    appendIface(body2, 1U, 0U, 2U, usb::kAppleUsbmuxClass, usb::kAppleUsbmuxSubClass,
                usb::kAppleUsbmuxProtocol);
    appendEndpoint(body2, 0x82U, usb::kEpTypeBulk, 512U);
    appendEndpoint(body2, 0x02U, usb::kEpTypeBulk, 512U);
    // IAD grouping Interfaces 2..3 for CDC-NCM
    appendIad(body2, 2U, 2U, usb::kClassCommunications, usb::kSubClassCdcNcm, 0x00U);
    // Interface 2: CDC-NCM Control
    appendIface(body2, 2U, 0U, 1U, usb::kClassCommunications, usb::kSubClassCdcNcm, 0x00U);
    appendCdcHeader(body2, 0x0120U);
    appendCdcUnion(body2, 2U, 3U);
    appendCdcEthernet(body2, 5U, 1514U);
    appendCdcNcm(body2, 0x0100U, 0x0fU);
    appendEndpoint(body2, 0x83U, usb::kEpTypeInterrupt, 16U, 9U);
    // Interface 3 alt 0: idle (0 endpoints)
    appendIface(body2, 3U, 0U, 0U, usb::kClassCdcData, 0x00U, usb::kProtocolCdcNcmData);
    // Interface 3 alt 1: active (2 bulk endpoints)
    appendIface(body2, 3U, 1U, 2U, usb::kClassCdcData, 0x00U, usb::kProtocolCdcNcmData);
    appendEndpoint(body2, 0x84U, usb::kEpTypeBulk, 512U);
    appendEndpoint(body2, 0x04U, usb::kEpTypeBulk, 512U);
    const std::vector<uint8_t> cfg2 = wrapConfig(4U, 4U, body2);

    std::vector<uint8_t> blob = makeDeviceDesc(usb::kAppleVendorId, 0x12a8U, 2U);
    blob.insert(blob.end(), cfg1.begin(), cfg1.end());
    blob.insert(blob.end(), cfg2.begin(), cfg2.end());

    usb::DeviceDescriptor dev;
    std::vector<usb::ConfigurationDescriptor> configs;
    std::string err;
    REQUIRE(usb::parseUsbfsDescriptors(&blob[0], blob.size(), dev, configs, &err));
    CHECK_EQ(2U, configs.size());
    CHECK_EQ(1U, configs[0].configuration_value);
    CHECK_EQ(4U, configs[1].configuration_value);
    CHECK_EQ(1U, configs[1].iads.size());

    const usb::CarPlayUsbSelection sel = usb::selectCarPlayInterfaces(configs);
    CHECK(sel.found_config);
    CHECK_EQ(4U, sel.configuration_value);
    CHECK(sel.has_usbmux);
    CHECK(sel.iap2.found);
    CHECK_EQ(0U, sel.iap2.interface_number);
    CHECK_EQ(0x81U, sel.iap2.bulk_in_ep);
    CHECK_EQ(0x01U, sel.iap2.bulk_out_ep);
    CHECK_EQ(512U, sel.iap2.bulk_in_max_packet);
    CHECK(sel.ncm.found);
    CHECK_EQ(2U, sel.ncm.control_interface);
    CHECK(sel.ncm.has_interrupt_in);
    CHECK_EQ(0x83U, sel.ncm.interrupt_in_ep);
    CHECK_EQ(3U, sel.ncm.data_interface);
    CHECK_EQ(1U, sel.ncm.data_alt_setting);
    CHECK(sel.ncm.has_idle_alt_setting);
    CHECK_EQ(0U, sel.ncm.idle_alt_setting);
    CHECK_EQ(0x84U, sel.ncm.bulk_in_ep);
    CHECK_EQ(0x04U, sel.ncm.bulk_out_ep);
    CHECK(sel.ncm.has_mac_string_index);
    CHECK_EQ(5U, sel.ncm.mac_string_index);
    CHECK_EQ(1514U, sel.ncm.max_segment_size);
    CHECK_EQ(0x0100U, sel.ncm.bcd_ncm_version);
    CHECK_EQ(0x0fU, sel.ncm.ncm_capabilities);
}

TEST_CASE(descriptorSelectionFallbacksAndStrings) {
    // Config without Union descriptor: should fall back via IAD / CDC Data interface.
    std::vector<uint8_t> body;
    appendIad(body, 0U, 2U, usb::kClassCommunications, usb::kSubClassCdcNcm, 0U);
    appendIface(body, 0U, 0U, 0U, usb::kClassCommunications, usb::kSubClassCdcNcm, 0U);
    appendCdcNcm(body, 0x0100U, 0x01U);
    appendIface(body, 1U, 0U, 2U, usb::kClassCdcData, 0U, usb::kProtocolCdcNcmData);
    appendEndpoint(body, 0x85U, usb::kEpTypeBulk, 512U);
    appendEndpoint(body, 0x06U, usb::kEpTypeBulk, 512U);
    const std::vector<uint8_t> cfg = wrapConfig(2U, 2U, body);

    std::vector<usb::ConfigurationDescriptor> configs(1U);
    std::string err;
    REQUIRE(usb::parseConfigurationDescriptor(&cfg[0], cfg.size(), configs[0], NULL, &err));
    const usb::CarPlayUsbSelection sel = usb::selectCarPlayInterfaces(configs);
    CHECK(sel.found_config);
    CHECK(!sel.iap2.found);
    CHECK(sel.ncm.found);
    CHECK_EQ(0U, sel.ncm.control_interface);
    CHECK_EQ(1U, sel.ncm.data_interface);
    CHECK_EQ(0U, sel.ncm.data_alt_setting);
    CHECK_EQ(0x85U, sel.ncm.bulk_in_ep);
    CHECK_EQ(0x06U, sel.ncm.bulk_out_ep);

    // Malformed config: endpoint before interface
    std::vector<uint8_t> bad_body;
    appendEndpoint(bad_body, 0x81U, usb::kEpTypeBulk, 512U);
    const std::vector<uint8_t> bad_cfg = wrapConfig(1U, 1U, bad_body);
    usb::ConfigurationDescriptor parsed_bad;
    CHECK(!usb::parseConfigurationDescriptor(&bad_cfg[0], bad_cfg.size(), parsed_bad, NULL, &err));

    // Malformed config: sub_len = 0
    std::vector<uint8_t> zero_len = cfg;
    zero_len[9] = 0U;
    CHECK(!usb::parseConfigurationDescriptor(&zero_len[0], zero_len.size(), parsed_bad, NULL, &err));

    // UTF-16LE USB String descriptor ("02AABBCCDDEE")
    const char mac_ascii[] = "02AABBCCDDEE";
    std::vector<uint8_t> str_desc;
    str_desc.push_back(static_cast<uint8_t>(2U + 12U * 2U));
    str_desc.push_back(usb::kDescTypeString);
    for (size_t i = 0; i < 12U; ++i) {
        str_desc.push_back(static_cast<uint8_t>(mac_ascii[i]));
        str_desc.push_back(0U);
    }
    std::string decoded;
    REQUIRE(usb::decodeUsbStringDescriptor(&str_desc[0], str_desc.size(), decoded, &err));
    CHECK_EQ(std::string("02AABBCCDDEE"), decoded);

    uint8_t mac[6];
    REQUIRE(usb::parseUsbMacString(decoded, mac));
    CHECK_EQ(0x02U, mac[0]);
    CHECK_EQ(0xaaU, mac[1]);
    CHECK_EQ(0xeeU, mac[5]);
    CHECK(!usb::parseUsbMacString("02AABB", mac));
    CHECK(!usb::parseUsbMacString("02AABBCCDDZZ", mac));
}

TEST_CASE(ntbParametersParseEncodeAndValidate) {
    ncm::NtbParameters p;
    p.length = 28U;
    p.formats_supported = 0x0003U;
    p.ntb_in_max_size = 16384U;
    p.ndp_in_divisor = 8U;
    p.ndp_in_payload_remainder = 2U;
    p.ndp_in_alignment = 16U;
    p.ntb_out_max_size = 8192U;
    p.ndp_out_divisor = 4U;
    p.ndp_out_payload_remainder = 0U;
    p.ndp_out_alignment = 8U;
    p.ntb_out_max_datagrams = 16U;

    std::vector<uint8_t> wire;
    ncm::encodeNtbParameters(p, wire);
    CHECK_EQ(28U, wire.size());

    ncm::NtbParameters decoded;
    std::string err;
    REQUIRE(ncm::parseNtbParameters(&wire[0], wire.size(), decoded, &err));
    CHECK_EQ(p.ntb_in_max_size, decoded.ntb_in_max_size);
    CHECK_EQ(p.ndp_in_divisor, decoded.ndp_in_divisor);
    CHECK_EQ(p.ndp_in_payload_remainder, decoded.ndp_in_payload_remainder);
    CHECK_EQ(p.ndp_in_alignment, decoded.ndp_in_alignment);
    CHECK_EQ(p.ntb_out_max_size, decoded.ntb_out_max_size);
    CHECK_EQ(p.ntb_out_max_datagrams, decoded.ntb_out_max_datagrams);

    // Invalid: remainder >= divisor
    ncm::NtbParameters bad = p;
    bad.ndp_in_payload_remainder = 8U;
    ncm::encodeNtbParameters(bad, wire);
    CHECK(!ncm::parseNtbParameters(&wire[0], wire.size(), decoded, &err));

    // Invalid: non-power-of-two divisor
    bad = p;
    bad.ndp_out_divisor = 6U;
    ncm::encodeNtbParameters(bad, wire);
    CHECK(!ncm::parseNtbParameters(&wire[0], wire.size(), decoded, &err));

    // Invalid: NTB-16 unsupported
    bad = p;
    bad.formats_supported = 0x0002U;
    ncm::encodeNtbParameters(bad, wire);
    CHECK(!ncm::parseNtbParameters(&wire[0], wire.size(), decoded, &err));

    // Invalid: too small max size
    bad = p;
    bad.ntb_in_max_size = 1024U;
    ncm::encodeNtbParameters(bad, wire);
    CHECK(!ncm::parseNtbParameters(&wire[0], wire.size(), decoded, &err));
}

TEST_CASE(ntb16SingleAndMultiFrameRoundTrips) {
    ncm::NtbParameters params;
    params.ntb_in_max_size = 16384U;
    params.ndp_in_divisor = 8U;
    params.ndp_in_payload_remainder = 2U;
    params.ndp_in_alignment = 16U;
    params.ntb_out_max_size = 16384U;
    params.ndp_out_divisor = 8U;
    params.ndp_out_payload_remainder = 2U;
    params.ndp_out_alignment = 16U;
    params.ntb_out_max_datagrams = 10U;

    std::vector<std::vector<uint8_t> > frames;
    frames.push_back(makeSampleEthernetFrame(1U, 46U));
    frames.push_back(makeSampleEthernetFrame(2U, 127U));
    frames.push_back(makeSampleEthernetFrame(3U, 512U));
    frames.push_back(makeSampleEthernetFrame(4U, 1480U));

    std::vector<uint8_t> ntb_bytes;
    std::string err;
    const ncm::NtbBuildOptions bopts = ncm::NtbBuildOptions::fromParameters(params);
    REQUIRE(ncm::buildNtb16(frames, 0x1234U, bopts, ntb_bytes, &err));

    // Verify NDP16 offset alignment (16) and datagram alignment (idx % 8 == 2).
    const uint16_t ndp_off =
        static_cast<uint16_t>(ntb_bytes[10]) | (static_cast<uint16_t>(ntb_bytes[11]) << 8);
    CHECK_EQ(0U, ndp_off % 16U);

    // Parse with strict alignment enabled.
    const ncm::NtbParseOptions popts = ncm::NtbParseOptions::fromParameters(params, true);
    ncm::Ntb16Frame parsed;
    REQUIRE(ncm::parseNtb16(&ntb_bytes[0], ntb_bytes.size(), popts, parsed, &err));
    CHECK_EQ(0x1234U, parsed.sequence);
    CHECK_EQ(ntb_bytes.size(), parsed.block_length);
    REQUIRE(parsed.datagrams.size() == frames.size());
    for (size_t i = 0; i < frames.size(); ++i) {
        CHECK_BYTES_EQ(frames[i], parsed.datagrams[i]);
    }
}

TEST_CASE(ntb16BatchingAndMaxDatagrams) {
    std::vector<std::vector<uint8_t> > frames;
    for (size_t i = 0; i < 5U; ++i) {
        frames.push_back(makeSampleEthernetFrame(static_cast<uint8_t>(i + 1U), 200U));  // 214 bytes each
    }

    ncm::NtbBuildOptions opts;
    opts.max_ntb_size = 600U;
    opts.ndp_alignment = 4U;
    opts.ndp_divisor = 4U;
    opts.ndp_payload_remainder = 0U;
    opts.max_datagrams = 0U;

    std::vector<uint8_t> ntb1;
    size_t packed1 = 0;
    std::string err;
    REQUIRE(ncm::packNtb16Batch(frames, 0U, 1U, opts, ntb1, packed1, &err));
    CHECK_EQ(2U, packed1);  // 12 + 2*216 + 20 = 464 <= 600; 3 frames would exceed 600

    std::vector<uint8_t> ntb2;
    size_t packed2 = 0;
    REQUIRE(ncm::packNtb16Batch(frames, packed1, 2U, opts, ntb2, packed2, &err));
    CHECK_EQ(2U, packed2);

    std::vector<uint8_t> ntb3;
    size_t packed3 = 0;
    REQUIRE(ncm::packNtb16Batch(frames, packed1 + packed2, 3U, opts, ntb3, packed3, &err));
    CHECK_EQ(1U, packed3);

    // Also test max_datagrams cap
    opts.max_ntb_size = 8192U;
    opts.max_datagrams = 3U;
    std::vector<uint8_t> ntb_capped;
    size_t packed_cap = 0;
    REQUIRE(ncm::packNtb16Batch(frames, 0U, 10U, opts, ntb_capped, packed_cap, &err));
    CHECK_EQ(3U, packed_cap);

    // Oversized single frame fails
    opts.max_ntb_size = 100U;
    CHECK(!ncm::packNtb16Batch(frames, 0U, 11U, opts, ntb_capped, packed_cap, &err));
}

TEST_CASE(ntb16ChainedNdpAndCrc32Mode) {
    // 1. NCM1 CRC-32 build & parse round-trip
    std::vector<std::vector<uint8_t> > frames;
    frames.push_back(makeSampleEthernetFrame(0x10U, 64U));
    frames.push_back(makeSampleEthernetFrame(0x20U, 90U));

    ncm::NtbBuildOptions bopts;
    bopts.max_ntb_size = 4096U;
    bopts.append_crc32 = true;
    std::vector<uint8_t> crc_ntb;
    std::string err;
    REQUIRE(ncm::buildNtb16(frames, 77U, bopts, crc_ntb, &err));

    ncm::Ntb16Frame parsed;
    REQUIRE(ncm::parseNtb16(&crc_ntb[0], crc_ntb.size(), ncm::NtbParseOptions(), parsed, &err));
    REQUIRE(parsed.datagrams.size() == 2U);
    CHECK_BYTES_EQ(frames[0], parsed.datagrams[0]);
    CHECK_BYTES_EQ(frames[1], parsed.datagrams[1]);

    // Corrupt a payload byte -> CRC-32 mismatch must reject
    crc_ntb[14] ^= 0x01U;
    CHECK(!ncm::parseNtb16(&crc_ntb[0], crc_ntb.size(), ncm::NtbParseOptions(), parsed, &err));

    // 2. Hand-built chained NDP16 (NTH16 -> NDP1 -> NDP2) + trailing USB padding past wBlockLength
    std::vector<uint8_t> chained(128U, 0U);
    // NTH16 at 0..12
    chained[0] = 'N'; chained[1] = 'C'; chained[2] = 'M'; chained[3] = 'H';
    chained[4] = 12U; chained[5] = 0U;   // wHeaderLength
    chained[6] = 5U;  chained[7] = 0U;   // wSequence
    chained[8] = 100U; chained[9] = 0U;  // wBlockLength (less than USB buffer 128)
    chained[10] = 12U; chained[11] = 0U; // wNdpIndex = 12

    // NDP1 at 12..28 (16 bytes): points to dg1 @ 48 len 16, wNextNdpIndex = 28
    chained[12] = 'N'; chained[13] = 'C'; chained[14] = 'M'; chained[15] = '0';
    chained[16] = 16U; chained[17] = 0U;
    chained[18] = 28U; chained[19] = 0U; // wNextNdpIndex = 28
    chained[20] = 48U; chained[21] = 0U;
    chained[22] = 16U; chained[23] = 0U;

    // NDP2 at 28..44 (16 bytes): points to dg2 @ 64 len 20, wNextNdpIndex = 0
    chained[28] = 'N'; chained[29] = 'C'; chained[30] = 'M'; chained[31] = '0';
    chained[32] = 16U; chained[33] = 0U;
    chained[34] = 0U;  chained[35] = 0U;
    chained[36] = 64U; chained[37] = 0U;
    chained[38] = 20U; chained[39] = 0U;

    for (size_t i = 0; i < 16U; ++i) {
        chained[48U + i] = static_cast<uint8_t>(0xa0U + i);
    }
    for (size_t i = 0; i < 20U; ++i) {
        chained[64U + i] = static_cast<uint8_t>(0xb0U + i);
    }

    REQUIRE(ncm::parseNtb16(&chained[0], chained.size(), ncm::NtbParseOptions(), parsed, &err));
    CHECK_EQ(5U, parsed.sequence);
    CHECK_EQ(100U, parsed.block_length);
    REQUIRE(parsed.datagrams.size() == 2U);
    CHECK_EQ(16U, parsed.datagrams[0].size());
    CHECK_EQ(20U, parsed.datagrams[1].size());
    CHECK_EQ(0xa0U, parsed.datagrams[0][0]);
    CHECK_EQ(0xb0U, parsed.datagrams[1][0]);
}

TEST_CASE(ntb16MalformedRejection) {
    std::vector<std::vector<uint8_t> > frames;
    frames.push_back(makeSampleEthernetFrame(1U, 30U));
    std::vector<uint8_t> valid;
    std::string err;
    REQUIRE(ncm::buildNtb16(frames, 1U, ncm::NtbBuildOptions(), valid, &err));

    ncm::Ntb16Frame out;
    const ncm::NtbParseOptions opts;

    // 1. Truncated buffer
    CHECK(!ncm::parseNtb16(&valid[0], 11U, opts, out, &err));
    CHECK(!ncm::parseNtb16(&valid[0], valid.size() - 1U, opts, out, &err));

    // 2. Bad NTH16 signature
    std::vector<uint8_t> bad = valid;
    bad[0] = 'X';
    CHECK(!ncm::parseNtb16(&bad[0], bad.size(), opts, out, &err));

    // 3. Bad wHeaderLength
    bad = valid;
    bad[4] = 10U;
    CHECK(!ncm::parseNtb16(&bad[0], bad.size(), opts, out, &err));

    // 4. wBlockLength exceeds max_ntb_size
    ncm::NtbParseOptions small_max;
    small_max.max_ntb_size = static_cast<uint32_t>(valid.size() - 1U);
    CHECK(!ncm::parseNtb16(&valid[0], valid.size(), small_max, out, &err));

    // 5. wNdpIndex inside NTH16
    bad = valid;
    bad[10] = 8U;
    bad[11] = 0U;
    CHECK(!ncm::parseNtb16(&bad[0], bad.size(), opts, out, &err));

    // 6. Bad NDP16 signature
    const uint16_t ndp_off = static_cast<uint16_t>(valid[10]) | (static_cast<uint16_t>(valid[11]) << 8);
    bad = valid;
    bad[ndp_off] = 'Z';
    CHECK(!ncm::parseNtb16(&bad[0], bad.size(), opts, out, &err));

    // 7. NDP16 cycle (wNextNdpIndex points to itself)
    bad = valid;
    bad[ndp_off + 6U] = static_cast<uint8_t>(ndp_off & 0xffU);
    bad[ndp_off + 7U] = static_cast<uint8_t>((ndp_off >> 8) & 0xffU);
    CHECK(!ncm::parseNtb16(&bad[0], bad.size(), opts, out, &err));

    // 8. Half-zero datagram pointer {dg_idx != 0, dg_len == 0}
    bad = valid;
    bad[ndp_off + 10U] = 0U;
    bad[ndp_off + 11U] = 0U;
    CHECK(!ncm::parseNtb16(&bad[0], bad.size(), opts, out, &err));

    // 9. Datagram index + length overflow past wBlockLength
    bad = valid;
    bad[ndp_off + 8U] = 0xf0U;
    bad[ndp_off + 9U] = 0xffU;
    bad[ndp_off + 10U] = 0x40U;
    bad[ndp_off + 11U] = 0x00U;
    CHECK(!ncm::parseNtb16(&bad[0], bad.size(), opts, out, &err));

    // 10. Datagram overlaps NDP16
    bad = valid;
    bad[ndp_off + 8U] = static_cast<uint8_t>(ndp_off & 0xffU);
    bad[ndp_off + 9U] = static_cast<uint8_t>((ndp_off >> 8) & 0xffU);
    bad[ndp_off + 10U] = 4U;
    bad[ndp_off + 11U] = 0U;
    CHECK(!ncm::parseNtb16(&bad[0], bad.size(), opts, out, &err));

    // 11. Missing {0, 0} terminator inside NDP16
    bad = valid;
    bad[ndp_off + 12U] = 12U;
    bad[ndp_off + 13U] = 0U;
    bad[ndp_off + 14U] = 4U;
    bad[ndp_off + 15U] = 0U;
    CHECK(!ncm::parseNtb16(&bad[0], bad.size(), opts, out, &err));
}

int main() { return test_support::runAll("test_usb_ncm"); }
