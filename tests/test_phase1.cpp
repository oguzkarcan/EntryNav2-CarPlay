#include "carplay/airplay_crypto.hpp"
#include "carplay/airplay_hid.hpp"
#include "carplay/bplist_codec.hpp"
#include "carplay/iap2_wire.hpp"
#include "carplay/screen_stream.hpp"
#include "carplay/tlv8_codec.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace {

int g_tests_run = 0;
int g_tests_failed = 0;

void failAt(const char* expr, const char* file, int line, const std::string& detail = std::string()) {
    std::fprintf(stderr, "  FAIL %s:%d: %s%s%s\n",
                 file, line, expr, detail.empty() ? "" : " -> ", detail.c_str());
    ++g_tests_failed;
}

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            failAt(#cond, __FILE__, __LINE__);                          \
            return false;                                               \
        }                                                               \
    } while (0)

#define RUN_TEST(fn)                                                    \
    do {                                                                \
        ++g_tests_run;                                                  \
        if (fn()) {                                                     \
            std::printf("  [PASS] %s\n", #fn);                          \
        } else {                                                        \
            std::printf("  [FAIL] %s\n", #fn);                          \
        }                                                               \
    } while (0)

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2U);
    for (size_t i = 0; i + 1 < hex.size(); i += 2U) {
        const std::string byte_str = hex.substr(i, 2U);
        out.push_back(static_cast<uint8_t>(std::strtoul(byte_str.c_str(), NULL, 16)));
    }
    return out;
}

void writeU16BeTest(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xffU));
    out.push_back(static_cast<uint8_t>(v & 0xffU));
}

void writeU32BeTest(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xffU));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xffU));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xffU));
    out.push_back(static_cast<uint8_t>(v & 0xffU));
}

std::vector<uint8_t> buildRawBplist(const std::vector<std::vector<uint8_t> >& objects,
                                    uint8_t offset_size = 1,
                                    uint8_t ref_size = 1) {
    const uint8_t magic[8] = {'b', 'p', 'l', 'i', 's', 't', '0', '0'};
    std::vector<uint8_t> out(magic, magic + 8);
    std::vector<uint64_t> offsets;
    for (size_t i = 0; i < objects.size(); ++i) {
        offsets.push_back(static_cast<uint64_t>(out.size()));
        out.insert(out.end(), objects[i].begin(), objects[i].end());
    }
    const uint64_t off_table = static_cast<uint64_t>(out.size());
    for (size_t i = 0; i < offsets.size(); ++i) {
        for (size_t b = 0; b < offset_size; ++b) {
            out.push_back(static_cast<uint8_t>((offsets[i] >> ((offset_size - 1U - b) * 8U)) & 0xffU));
        }
    }
    for (size_t i = 0; i < 6; ++i) out.push_back(0);
    out.push_back(offset_size);
    out.push_back(ref_size);
    const uint64_t nobj = static_cast<uint64_t>(objects.size());
    for (int b = 7; b >= 0; --b) out.push_back(static_cast<uint8_t>((nobj >> (b * 8)) & 0xffU));
    for (int b = 7; b >= 0; --b) out.push_back(0);  // top object = 0
    for (int b = 7; b >= 0; --b) out.push_back(static_cast<uint8_t>((off_table >> (b * 8)) & 0xffU));
    return out;
}

// ---------------- Crypto Tests ----------------

bool testCryptoRfc8439Vector() {
    using namespace carplay::crypto;
    const std::vector<uint8_t> key = hexToBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const std::vector<uint8_t> nonce = hexToBytes("070000004041424344454647");
    const std::vector<uint8_t> aad = hexToBytes("50515253c0c1c2c3c4c5c6c7");
    const std::string pt_str = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const std::vector<uint8_t> expected_tag = hexToBytes("1ae10b594f09e26a7e902ecbd0600691");

    std::vector<uint8_t> ct(pt_str.size(), 0);
    uint8_t tag[kTagBytes];
    CHECK(chacha20Poly1305SealDetached(
        &key[0], &nonce[0], &aad[0], aad.size(),
        reinterpret_cast<const uint8_t*>(pt_str.data()), pt_str.size(), &ct[0], tag));
    CHECK(std::memcmp(tag, &expected_tag[0], kTagBytes) == 0);

    std::vector<uint8_t> recovered(pt_str.size(), 0);
    CHECK(chacha20Poly1305OpenDetached(
        &key[0], &nonce[0], &aad[0], aad.size(), &ct[0], ct.size(), tag, &recovered[0]));
    CHECK(std::memcmp(&recovered[0], pt_str.data(), pt_str.size()) == 0);

    // Tamper tests (tag, ciphertext, AAD, wrong nonce).
    uint8_t bad_tag[kTagBytes];
    std::memcpy(bad_tag, tag, kTagBytes);
    bad_tag[0] ^= 0x01U;
    CHECK(!chacha20Poly1305OpenDetached(
        &key[0], &nonce[0], &aad[0], aad.size(), &ct[0], ct.size(), bad_tag, &recovered[0]));

    std::vector<uint8_t> bad_ct = ct;
    bad_ct[5] ^= 0x80U;
    CHECK(!chacha20Poly1305OpenDetached(
        &key[0], &nonce[0], &aad[0], aad.size(), &bad_ct[0], bad_ct.size(), tag, &recovered[0]));

    std::vector<uint8_t> bad_nonce = nonce;
    bad_nonce[11] ^= 0x01U;
    CHECK(!chacha20Poly1305OpenDetached(
        &key[0], &bad_nonce[0], &aad[0], aad.size(), &ct[0], ct.size(), tag, &recovered[0]));

    return true;
}

bool testCryptoX25519Ed25519HkdfNonces() {
    using namespace carplay::crypto;
    uint8_t sec_a[kKeyBytes], sec_b[kKeyBytes];
    for (size_t i = 0; i < kKeyBytes; ++i) {
        sec_a[i] = static_cast<uint8_t>(i + 1);
        sec_b[i] = static_cast<uint8_t>(200 - i);
    }
    X25519KeyPair a, b;
    x25519FromSecret(sec_a, a);
    x25519FromSecret(sec_b, b);

    uint8_t shared_ab[kKeyBytes], shared_ba[kKeyBytes];
    CHECK(x25519SharedSecret(a.secret_key, b.public_key, shared_ab));
    CHECK(x25519SharedSecret(b.secret_key, a.public_key, shared_ba));
    CHECK(constantTimeEqual(shared_ab, shared_ba, kKeyBytes));

    // All-zero low-order X25519 peer key must be rejected.
    uint8_t zero_pk[kKeyBytes];
    std::memset(zero_pk, 0, sizeof(zero_pk));
    uint8_t bad_shared[kKeyBytes];
    CHECK(!x25519SharedSecret(a.secret_key, zero_pk, bad_shared));

    // Ed25519 sign/verify + seed preservation.
    uint8_t seed[kEd25519SeedBytes];
    uint8_t seed_copy[kEd25519SeedBytes];
    for (size_t i = 0; i < kEd25519SeedBytes; ++i) {
        seed[i] = static_cast<uint8_t>(0x30 + i);
        seed_copy[i] = seed[i];
    }
    Ed25519KeyPair ed;
    ed25519FromSeed(seed, ed);
    CHECK(std::memcmp(seed, seed_copy, sizeof(seed)) == 0);

    const std::string msg = "EntryNav2-CarPlay PairVerify Proof";
    uint8_t sig[kEd25519SignatureBytes];
    ed25519Sign(ed.secret_key, reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sig);
    CHECK(ed25519Verify(ed.public_key, reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sig));
    sig[10] ^= 0x40U;
    CHECK(!ed25519Verify(ed.public_key, reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sig));

    // HKDF-SHA512 domain separation + HAP label/counter nonces.
    std::vector<uint8_t> ikm(shared_ab, shared_ab + kKeyBytes);
    std::vector<uint8_t> k1, k2;
    CHECK(hkdfSha512(ikm, "Control-Salt", "Control-Read-Encryption-Key", 32, k1));
    CHECK(hkdfSha512(ikm, "Control-Salt", "Control-Write-Encryption-Key", 32, k2));
    CHECK(k1 != k2);

    uint8_t pv_nonce[kNonceBytes];
    CHECK(makeLabelNonce("PV-Msg02", pv_nonce));
    CHECK(pv_nonce[0] == 0 && pv_nonce[3] == 0 && pv_nonce[4] == 'P' && pv_nonce[11] == '2');

    uint8_t ctr_nonce[kNonceBytes];
    makeCounterNonce(0x0102030405060708ULL, ctr_nonce);
    CHECK(ctr_nonce[0] == 0 && ctr_nonce[3] == 0 && ctr_nonce[4] == 0x08 && ctr_nonce[11] == 0x01);

    std::vector<uint8_t> sealed, opened;
    CHECK(chacha20Poly1305Seal(&k1[0], pv_nonce, NULL, 0,
                               reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sealed));
    CHECK(sealed.size() == msg.size() + kTagBytes);
    CHECK(chacha20Poly1305Open(&k1[0], pv_nonce, NULL, 0, &sealed[0], sealed.size(), opened));
    CHECK(std::string(opened.begin(), opened.end()) == msg);

    return true;
}

// ---------------- TLV8 Tests ----------------

bool testTlv8FragmentationAndSeparators() {
    using namespace carplay::tlv8;

    std::vector<uint8_t> big_cert(600, 0);
    for (size_t i = 0; i < big_cert.size(); ++i) {
        big_cert[i] = static_cast<uint8_t>((i * 7U + 3U) & 0xffU);
    }

    std::vector<Item> items;
    items.push_back(Item::fromByte(kTagState, 0x03));
    items.push_back(Item::fromString(kTagIdentifier, "BMW-EVO"));
    // Back-to-back same tag must insert 0xff separator automatically.
    items.push_back(Item::fromString(kTagIdentifier, "SECOND"));
    items.push_back(Item(kTagCertificate, big_cert));

    const std::vector<uint8_t> wire = encode(items);
    // Expected overhead: 600 bytes split as 255 + 255 + 90 -> three headers for cert,
    // plus 2-byte auto-inserted 0xff 0x00 separator between repeated identifiers.
    CHECK(wire.size() > 600U + 12U);

    std::vector<Item> decoded;
    std::string err;
    CHECK(decode(wire, decoded, &err));

    uint8_t st = 0;
    CHECK(readU8(decoded, kTagState, st) && st == 0x03);
    const Item* cert = findFirst(decoded, kTagCertificate);
    CHECK(cert != NULL && cert->value == big_cert);

    std::vector<const Item*> ids = findAll(decoded, kTagIdentifier);
    CHECK(ids.size() == 2U);
    CHECK(std::string(ids[0]->value.begin(), ids[0]->value.end()) == "BMW-EVO");
    CHECK(std::string(ids[1]->value.begin(), ids[1]->value.end()) == "SECOND");

    const std::vector<std::vector<Item> > groups = splitBySeparator(decoded);
    CHECK(groups.size() == 2U);

    // Reject truncated TLV8 and non-empty 0xff separator.
    const uint8_t truncated[] = {0x06, 0x05, 0x01, 0x02};
    CHECK(!decode(truncated, sizeof(truncated), decoded, &err));
    const uint8_t bad_sep[] = {0xff, 0x01, 0x00};
    CHECK(!decode(bad_sep, sizeof(bad_sep), decoded, &err));

    return true;
}

// ---------------- Bplist Tests ----------------

bool testBplistSafariDateVector() {
    using namespace carplay::bplist;
    const std::vector<uint8_t> bytes = hexToBytes(
        "62706c6973743030d201020308546974656d5474797065d2040506075f1010436f6e74656e742d4c6f636174696f6e"
        "5a53746172742d446174655f101968747470733a2f2f6578616d706c652e636f6d2f762e6d70343341c83698a00000"
        "005f1013696e73657274506c617951756575654974656d080d12171c2f3a565f000000000000010100000000000000"
        "0900000000000000000000000000000075");
    Value root;
    std::string err;
    CHECK(decode(bytes, root, &err));
    CHECK(root.isDict());

    std::string type_str;
    CHECK(root.getString("type", type_str));
    CHECK(type_str == "insertPlayQueueItem");

    const Value* item = root.find("item");
    CHECK(item != NULL && item->isDict());

    std::string loc;
    CHECK(item->getString("Content-Location", loc));
    CHECK(loc == "https://example.com/v.mp4");

    const Value* start_date = item->find("Start-Date");
    CHECK(start_date != NULL && start_date->isDate());
    CHECK(start_date->asDateUnixMillis() == 1790769600000LL);

    return true;
}

bool testBplistRoundTripAndUnicodeAndLargeBlob() {
    using namespace carplay::bplist;

    Value root = Value::makeDict();
    root.set("name", Value::makeString("EntryNav2-CarPlay"));
    root.set("city", Value::makeString("\xc4\xb0stanbul-\xc5\x9ei\xc5\x9fli"));  // UTF-8 Turkish chars -> UTF-16BE
    root.set("flag", Value::makeBool(true));
    root.set("empty", Value::makeNull());
    root.set("neg", Value::makeInt(-42));
    root.set("big64", Value::makeInt(0x123456789abcLL));
    root.set("fps", Value::makeReal(60.5));
    root.set("when", Value::makeDateUnixMillis(1790769600000LL));
    root.set("uid", Value::makeUid(0x2a2a2a2aULL));

    std::vector<uint8_t> pic(500000, 0x07U);
    root.set("picture", Value::makeData(pic));

    Value nested = Value::makeBool(true);
    for (int i = 0; i < 20; ++i) {
        Value::Array arr;
        arr.push_back(nested);
        nested = Value::makeArray(arr);
    }
    root.set("deep20", nested);

    std::vector<uint8_t> encoded;
    std::string err;
    CHECK(encode(root, encoded, &err));

    Value decoded;
    CHECK(decode(encoded, decoded, &err));
    CHECK(decoded == root);

    const Value* pic_dec = decoded.find("picture");
    CHECK(pic_dec != NULL && pic_dec->asData().size() == 500000U);

    return true;
}

bool testBplistHostileInputsRejected() {
    using namespace carplay::bplist;
    Value out;
    std::string err;

    // 1. Direct cyclic dictionary (dict[key=1, val=0]).
    {
        std::vector<std::vector<uint8_t> > objs;
        const uint8_t dict[] = {0xd1, 1, 0};
        const uint8_t key[] = {0x51, 'k'};
        objs.push_back(std::vector<uint8_t>(dict, dict + sizeof(dict)));
        objs.push_back(std::vector<uint8_t>(key, key + sizeof(key)));
        CHECK(!decode(buildRawBplist(objs), out, &err));
    }

    // 2. Exponential array bomb (30 levels referencing child twice -> 2^30 reads).
    {
        std::vector<std::vector<uint8_t> > objs;
        for (uint8_t i = 0; i < 30; ++i) {
            const uint8_t arr[] = {0xa2, static_cast<uint8_t>(i + 1), static_cast<uint8_t>(i + 1)};
            objs.push_back(std::vector<uint8_t>(arr, arr + sizeof(arr)));
        }
        const uint8_t leaf[] = {0x09};
        objs.push_back(std::vector<uint8_t>(leaf, leaf + sizeof(leaf)));
        CHECK(!decode(buildRawBplist(objs), out, &err));
    }

    // 3. 250,000 references to one empty array (exceeds max_reads).
    {
        std::vector<std::vector<uint8_t> > objs;
        std::vector<uint8_t> big_arr;
        big_arr.push_back(0xaf);
        big_arr.push_back(0x12);
        writeU32BeTest(big_arr, 250000U);
        big_arr.insert(big_arr.end(), 250000U, 1U);
        const uint8_t empty_arr[] = {0xa0};
        objs.push_back(big_arr);
        objs.push_back(std::vector<uint8_t>(empty_arr, empty_arr + sizeof(empty_arr)));
        CHECK(!decode(buildRawBplist(objs, 4, 1), out, &err));
    }

    // 4. 200 KB blob referenced 1000 times (~200 MB decoded payload bomb > 16 MB cap).
    {
        std::vector<std::vector<uint8_t> > objs;
        std::vector<uint8_t> arr;
        arr.push_back(0xaf);
        arr.push_back(0x11);
        writeU16BeTest(arr, 1000U);
        arr.insert(arr.end(), 1000U, 1U);
        std::vector<uint8_t> blob;
        blob.push_back(0x4f);
        blob.push_back(0x12);
        writeU32BeTest(blob, 200000U);
        blob.insert(blob.end(), 200000U, 0x55U);
        objs.push_back(arr);
        objs.push_back(blob);
        CHECK(!decode(buildRawBplist(objs, 4, 1), out, &err));
    }

    // 5. Non-string dictionary key rejected.
    {
        std::vector<std::vector<uint8_t> > objs;
        const uint8_t dict[] = {0xd1, 1, 2};
        const uint8_t bad_key[] = {0xa0};
        const uint8_t val[] = {0x08};
        objs.push_back(std::vector<uint8_t>(dict, dict + sizeof(dict)));
        objs.push_back(std::vector<uint8_t>(bad_key, bad_key + sizeof(bad_key)));
        objs.push_back(std::vector<uint8_t>(val, val + sizeof(val)));
        CHECK(!decode(buildRawBplist(objs), out, &err));
    }

    // 6. Over-wide integer (0x1f -> 32KB) and wide UID (0x8f -> 16B) rejected.
    {
        std::vector<std::vector<uint8_t> > objs;
        objs.push_back(std::vector<uint8_t>(1, 0x1f));
        CHECK(!decode(buildRawBplist(objs), out, &err));

        objs.clear();
        std::vector<uint8_t> wide_uid(17, 0);
        wide_uid[0] = 0x8f;
        objs.push_back(wide_uid);
        CHECK(!decode(buildRawBplist(objs), out, &err));
    }

    return true;
}

// ---------------- iAP2 Wire Tests ----------------

bool testIap2FramerAndRepeatedParams() {
    using namespace carplay::iap2;

    ParameterList inner;
    inner.addString(0, "wired-ip");

    ParameterList params;
    params.addString(1, "first");
    params.addString(1, "second");
    params.addU16(2, 0x1234U);
    params.addI32(3, -123456);
    params.addGroup(4, inner);

    Frame f1, f2;
    std::string err;
    CHECK(Frame::build(msg::kIdentificationInformation, params, f1, &err));
    CHECK(buildLocationInformation("$GPGGA,1\r\n", f2, &err));

    std::vector<uint8_t> wire1, wire2;
    CHECK(f1.encode(wire1, &err));
    CHECK(f2.encode(wire2, &err));

    // Link packet splitting.
    std::vector<std::vector<uint8_t> > packets;
    CHECK(CsmFramer::splitForLink(wire1, 7, packets, &err));
    CHECK(packets.size() >= 2U);

    // Feed split packets + concatenated second frame byte-by-byte / mixed.
    CsmFramer framer;
    std::vector<Frame> received;
    for (size_t i = 0; i < packets.size(); ++i) {
        CHECK(framer.push(&packets[i][0], packets[i].size(), received, &err));
    }
    CHECK(received.size() == 1U);
    CHECK(framer.bufferedBytes() == 0);

    CHECK(framer.push(&wire2[0], 3, received, &err));
    CHECK(received.size() == 1U);
    CHECK(framer.push(&wire2[3], wire2.size() - 3, received, &err));
    CHECK(received.size() == 2U);
    CHECK(received[1].message_id == msg::kLocationInformation);

    // Check repeated ID preservation & group decode.
    ParameterList decoded;
    CHECK(ParameterList::decode(received[0].payload, decoded, &err));
    std::vector<const Parameter*> ones = decoded.findAll(1);
    CHECK(ones.size() == 2U);
    int32_t signed_val = 0;
    CHECK(decoded.readI32(3, signed_val) && signed_val == -123456);
    ParameterList inner_dec;
    std::string ip;
    CHECK(decoded.readGroup(4, inner_dec, &err) && inner_dec.readString(0, ip) && ip == "wired-ip");

    // Reject bad start marker.
    const uint8_t bad_marker[] = {0x40, 0x41, 0x00, 0x06, 0x00, 0x00};
    framer.reset();
    CHECK(!framer.push(bad_marker, sizeof(bad_marker), received, &err));

    return true;
}

bool testIap2WiredAndWirelessCarPlay() {
    using namespace carplay::iap2;

    StartSessionConfig cfg;
    cfg.wired_ipv6_addresses.push_back("fe80::2");
    cfg.wired_reserved = 1U;
    cfg.has_wired_reserved = true;
    cfg.wireless_ssid = "LIVI";
    cfg.wireless_passphrase = "secret";
    cfg.has_wireless_channel = true;
    cfg.wireless_channel = 36;
    cfg.wireless_ips.push_back("192.168.1.1");
    cfg.wireless_ips.push_back("192.168.1.2");
    cfg.has_wireless_security_type = true;
    cfg.wireless_security_type = 3;
    cfg.has_airplay_port = true;
    cfg.airplay_port = 7000;
    cfg.device_identifier = "00:11:22:33:44:55";
    cfg.public_key = "pub-b64";
    cfg.source_version = "27.0";
    cfg.sdk_version = "27.0";
    cfg.cluster_asset_id = "cluster";
    cfg.has_cluster_asset_version = true;
    cfg.cluster_asset_version = 4;
    cfg.has_mutual_auth = true;
    cfg.mutual_auth = 1;

    Frame frame;
    std::string err;
    CHECK(buildStartCarPlaySession(cfg, frame, &err));
    CHECK(frame.message_id == msg::kCarPlayStartSession);

    ParameterList root, wired, wireless, cluster;
    CHECK(ParameterList::decode(frame.payload, root, &err));
    CHECK(root.readGroup(0, wired, &err));
    CHECK(root.readGroup(1, wireless, &err));
    CHECK(root.readGroup(7, cluster, &err));

    std::string wired_ip, ssid, sdk, cid;
    uint32_t port = 0, cver = 0;
    uint8_t mauth = 0;
    CHECK(wired.readString(0, wired_ip) && wired_ip == "fe80::2");
    CHECK(wireless.readString(0, ssid) && ssid == "LIVI");
    CHECK(wireless.findAll(3).size() == 2U);
    CHECK(root.readU32(2, port) && port == 7000U);
    CHECK(root.readString(6, sdk) && sdk == "27.0");
    CHECK(cluster.readString(0, cid) && cid == "cluster");
    CHECK(cluster.readU32(1, cver) && cver == 4U);
    CHECK(root.readU8(8, mauth) && mauth == 1U);

    // WirelessCarPlayUpdate & WiFiInformation & AccessoryWiFiConfig.
    ParameterList wc_yes;
    wc_yes.addU8(0, 1);
    Frame wc_frame;
    CHECK(Frame::build(msg::kWirelessCarPlayUpdate, wc_yes, wc_frame, &err));
    bool avail = false;
    CHECK(parseWirelessCarPlayAvailability(wc_frame, avail, &err) && avail);

    ParameterList wc_bad;
    wc_bad.addU8(0, 2);
    CHECK(Frame::build(msg::kWirelessCarPlayUpdate, wc_bad, wc_frame, &err));
    CHECK(!parseWirelessCarPlayAvailability(wc_frame, avail, &err));

    const uint8_t bssid_raw[] = {1, 2, 3, 4, 5, 6};
    const std::vector<uint8_t> bssid(bssid_raw, bssid_raw + 6);
    Frame wifi_cfg;
    CHECK(buildAccessoryWiFiConfiguration("BMW_WIFI", "pass1234", 44, 3, &bssid, wifi_cfg, &err));
    ParameterList wifi_params;
    std::vector<uint8_t> bssid_out;
    CHECK(ParameterList::decode(wifi_cfg.payload, wifi_params, &err));
    CHECK(wifi_params.readBytes(0, bssid_out) && bssid_out == bssid);

    return true;
}

// ---------------- HID Tests ----------------

bool testAirPlayHidAndZbe3Mapping() {
    using namespace carplay::hid;

    // Reference layouts (AirPlayHid.kt); exact bytes are covered by tests/test_airplay_hid.cpp.
    const DescriptorSummary touch_sum = inspectDescriptor(touchscreenDescriptor(800, 480));
    CHECK(touch_sum.valid && touch_sum.has_absolute_input && !touch_sum.has_relative_input);
    CHECK(touchscreenDescriptor(800, 480).size() == 109U);

    const DescriptorSummary knob_sum = inspectDescriptor(knobDescriptor());
    CHECK(knob_sum.valid && knob_sum.has_absolute_input && knob_sum.has_relative_input);

    const DescriptorSummary media_sum = inspectDescriptor(mediaDescriptor());
    const DescriptorSummary tel_sum = inspectDescriptor(telephonyDescriptor());
    CHECK(media_sum.valid && tel_sum.valid);

    // 2-contact touch report in display pixels; slot 1 down at (300,400).
    std::vector<TouchContact> contacts(1, TouchContact(1, true, 300, 400));
    const std::vector<uint8_t> trep = touchReport(contacts, 800, 480);
    CHECK(trep.size() == 12U);
    CHECK(trep[0] == 0U && trep[1] == 0U && trep[6] == 1U && trep[7] == 1U);
    CHECK(trep[8] == 0x2cU && trep[9] == 0x01U && trep[10] == 0x90U && trep[11] == 0x01U);

    // BMW ZBE3 hardware mapping.
    Zbe3Event hw;
    hw.dir_mask = zbe3::kDirUp;
    hw.center_pressed = true;
    hw.button_mask = static_cast<uint8_t>(zbe3::kBtnMenu | zbe3::kBtnBack | zbe3::kBtnMedia | zbe3::kBtnCom);
    hw.rotary_delta = -2;

    KnobState knob;
    int32_t media = MEDIA_NONE;
    int32_t tel = TELEPHONY_NONE;
    mapZbe3ToCarPlay(hw, knob, media, tel);
    // Up tilt adds -1 to the rotary -2 (reference D-pad -> wheel convention).
    CHECK(knob.select && knob.home && knob.back && knob.wheel == -3 && knob.x == 0 && knob.y == 0);
    CHECK(media == MEDIA_PLAY_PAUSE);
    CHECK(tel == TELEPHONY_HOOK_SWITCH);

    const std::vector<uint8_t> krep = knobReport(knob);
    CHECK(krep.size() == 4U);
    CHECK(krep[0] == 0x07U);  // Select | Home<<1 | Back<<2
    CHECK(krep[1] == 0U && krep[2] == 0U);
    CHECK(static_cast<int8_t>(krep[3]) == -3);

    const std::vector<uint8_t> mrep = mediaReport(MEDIA_NEXT);
    CHECK(mrep.size() == 1U && mrep[0] == 4U);
    const std::vector<uint8_t> prep = telephonyReport(TELEPHONY_HOOK_SWITCH);
    CHECK(prep.size() == 1U && prep[0] == 1U);

    return true;
}

// ---------------- Screen Stream Tests ----------------

bool testScreenHeaderDecryptAndAnnexB() {
    using namespace carplay::stream;

    // 128-byte header: payload_size=64, opcode=1 (Config), NTP=1.5s (sec=1, frac=0x80000000), 800x480
    std::vector<uint8_t> hdr(kScreenHeaderBytes, 0);
    hdr[0] = 64;  // payload size = 64 LE
    hdr[4] = 1;   // opcode = 1 (video config)
    const uint64_t ntp = (1ULL << 32) | 0x80000000ULL;
    for (size_t i = 0; i < 8; ++i) {
        hdr[8 + i] = static_cast<uint8_t>((ntp >> (8U * i)) & 0xffU);
    }
    const float w = 800.0f;
    const float h = 480.0f;
    std::memcpy(&hdr[16], &w, 4);
    std::memcpy(&hdr[20], &h, 4);

    ScreenPacketHeader parsed;
    std::string err;
    CHECK(parseScreenHeader(&hdr[0], hdr.size(), parsed, &err));
    CHECK(parsed.payload_size == 64U);
    CHECK(parsed.opcode == kOpVideoConfig);
    CHECK(parsed.sender_nanos == 1500000000ULL);
    CHECK(parsed.width_px == 800.0f && parsed.height_px == 480.0f);

    // Encrypt + Decrypt screen frame + In-place 4-byte length -> Annex B start codes.
    uint8_t key[32];
    for (size_t i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(0xa0 + i);
    uint8_t nonce[12];
    carplay::crypto::makeCounterNonce(42ULL, nonce);

    // Two AVCC length-prefixed NALUs: [len=3][65, 88, 84] + [len=2][41, 9a]
    const uint8_t avcc_nalus[] = {
        0x00, 0x00, 0x00, 0x03, 0x65, 0x88, 0x84,
        0x00, 0x00, 0x00, 0x02, 0x41, 0x9a
    };
    std::vector<uint8_t> cipher(sizeof(avcc_nalus), 0);
    uint8_t tag[16];
    CHECK(carplay::crypto::chacha20Poly1305SealDetached(
        key, nonce, &hdr[0], hdr.size(), avcc_nalus, sizeof(avcc_nalus), &cipher[0], tag));

    std::vector<uint8_t> plain;
    CHECK(decryptFrame(key, 42ULL, &hdr[0], hdr.size(), &cipher[0], cipher.size(), tag, plain));
    CHECK(lengthPrefixedToAnnexB(plain));
    CHECK(plain[0] == 0x00 && plain[1] == 0x00 && plain[2] == 0x00 && plain[3] == 0x01);
    CHECK(plain[4] == 0x65 && plain[7] == 0x00 && plain[10] == 0x01 && plain[11] == 0x41);

    // In-place decrypt test on same ciphertext buffer.
    CHECK(decryptFrameInPlace(key, nonce, &hdr[0], hdr.size(), &cipher[0], cipher.size(), tag));
    CHECK(std::memcmp(&cipher[0], avcc_nalus, sizeof(avcc_nalus)) == 0);

    // Malformed NALU length must fail safely.
    uint8_t bad_nal[] = {0x00, 0x00, 0x00, 0x20, 0x65};
    CHECK(!lengthPrefixedToAnnexBInPlace(bad_nal, sizeof(bad_nal)));

    // Minimal valid avcC -> Annex B SPS/PPS extraction.
    const uint8_t sample_avcc[] = {
        0x01, 0x64, 0x00, 0x1f, 0xff,
        0xe1, 0x00, 0x04, 0x67, 0x64, 0x00, 0x1f,  // 1 SPS
        0x01, 0x00, 0x03, 0x68, 0xeb, 0xe3         // 1 PPS
    };
    CHECK(detectConfigCodec(sample_avcc, sizeof(sample_avcc)) == CODEC_H264_AVCC);
    std::vector<uint8_t> sps_pps;
    uint8_t nal_len_bytes = 0;
    CHECK(avcCToAnnexB(sample_avcc, sizeof(sample_avcc), sps_pps, &nal_len_bytes));
    CHECK(nal_len_bytes == 4U);
    CHECK(sps_pps.size() == 4U + 4U + 4U + 3U);
    CHECK(sps_pps[4] == 0x67 && sps_pps[12] == 0x68);

    return true;
}

}  // namespace

int main() {
    std::printf("EntryNav2-CarPlay Phase 1 Test Suite\n");
    std::printf("=====================================\n");

    RUN_TEST(testCryptoRfc8439Vector);
    RUN_TEST(testCryptoX25519Ed25519HkdfNonces);
    RUN_TEST(testTlv8FragmentationAndSeparators);
    RUN_TEST(testBplistSafariDateVector);
    RUN_TEST(testBplistRoundTripAndUnicodeAndLargeBlob);
    RUN_TEST(testBplistHostileInputsRejected);
    RUN_TEST(testIap2FramerAndRepeatedParams);
    RUN_TEST(testIap2WiredAndWirelessCarPlay);
    RUN_TEST(testAirPlayHidAndZbe3Mapping);
    RUN_TEST(testScreenHeaderDecryptAndAnnexB);

    std::printf("=====================================\n");
    std::printf("Summary: %d/%d tests passed\n", g_tests_run - g_tests_failed, g_tests_run);
    return g_tests_failed == 0 ? 0 : 1;
}
