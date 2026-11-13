// Host tests for carplay::audio (audio_rtp).

#include <string.h>

#include <string>
#include <vector>

#include "carplay/airplay_crypto.hpp"
#include "carplay/audio_rtp.hpp"
#include "test_support.hpp"

using namespace carplay;
using namespace carplay::audio;

namespace {

void fillKey(uint8_t key[32], uint8_t base) {
    for (int i = 0; i < 32; ++i) {
        key[i] = static_cast<uint8_t>(base + i);
    }
}

std::vector<uint8_t> makePayload(size_t n, uint8_t seed) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) {
        v[i] = static_cast<uint8_t>(seed + i * 7U);
    }
    return v;
}

// Independently built packet: header | chacha20Poly1305Seal(nonce=0000|tail, aad=header[4..12)) | tail.
std::vector<uint8_t> buildKnownAnswerPacket(const uint8_t key[32],
                                            const uint8_t header[12],
                                            const std::vector<uint8_t>& payload,
                                            const uint8_t tail[8]) {
    uint8_t nonce[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    memcpy(nonce + 4, tail, 8);
    std::vector<uint8_t> sealed;
    crypto::chacha20Poly1305Seal(key, nonce, header + 4, 8, payload.empty() ? NULL : &payload[0], payload.size(),
                                 sealed);
    std::vector<uint8_t> pkt(header, header + 12);
    pkt.insert(pkt.end(), sealed.begin(), sealed.end());
    pkt.insert(pkt.end(), tail, tail + 8);
    return pkt;
}

std::vector<uint8_t> bytesOf(uint8_t a, uint8_t b) {
    std::vector<uint8_t> v;
    v.push_back(a);
    v.push_back(b);
    return v;
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// Packet crypto
// ---------------------------------------------------------------------------------------------

TEST_CASE(sealThenOpenRoundTrip) {
    uint8_t key[32];
    fillKey(key, 0x10);
    uint8_t header[12];
    buildRtpHeader(100, true, 0x1234, 0xdeadbeefU, 0x01020304U, header);
    const std::vector<uint8_t> payload = makePayload(480, 3);
    std::vector<uint8_t> pkt;
    REQUIRE(sealPacket(key, header, &payload[0], payload.size(), 77ULL, pkt));
    CHECK_EQ(payload.size() + 36U, pkt.size());

    RtpHeader h;
    std::vector<uint8_t> out;
    CHECK_EQ(static_cast<int>(kOpenOk), static_cast<int>(openPacket(key, &pkt[0], pkt.size(), h, out)));
    CHECK_BYTES_EQ(payload, out);
    CHECK_EQ(2, static_cast<int>(h.version));
    CHECK(h.marker);
    CHECK_EQ(100, static_cast<int>(h.payload_type));
    CHECK_EQ(0x1234, static_cast<int>(h.sequence));
    CHECK_EQ(0xdeadbeefU, h.timestamp);
    CHECK_EQ(0x01020304U, h.ssrc);

    // Reference "rtp" form = clear header + payload.
    std::vector<uint8_t> rtp;
    RtpHeader h2;
    CHECK_EQ(static_cast<int>(kOpenOk), static_cast<int>(openPacketToRtp(key, &pkt[0], pkt.size(), rtp, &h2)));
    std::vector<uint8_t> expected(header, header + 12);
    expected.insert(expected.end(), payload.begin(), payload.end());
    CHECK_BYTES_EQ(expected, rtp);
    CHECK_EQ(0x1234, static_cast<int>(h2.sequence));

    // Nonce tail is the LE u64 counter.
    CHECK_BYTES_EQ(test_support::hexToBytes("4d00000000000000"),
                   std::vector<uint8_t>(pkt.end() - 8, pkt.end()));
}

TEST_CASE(knownAnswerPacketMatchesIndependentConstruction) {
    uint8_t key[32];
    fillKey(key, 0xa0);
    const std::vector<uint8_t> header = test_support::hexToBytes("80e4 0102 11223344 55667788");
    // Deliberately non-counter-looking tail bytes: must land verbatim in nonce[4..12).
    const uint8_t tail[8] = {0xf0, 0x01, 0xe2, 0x03, 0xd4, 0x05, 0xc6, 0x07};
    const std::vector<uint8_t> payload = makePayload(64, 0x55);
    const std::vector<uint8_t> kat = buildKnownAnswerPacket(key, &header[0], payload, tail);

    RtpHeader h;
    std::vector<uint8_t> out;
    CHECK_EQ(static_cast<int>(kOpenOk), static_cast<int>(openPacket(key, &kat[0], kat.size(), h, out)));
    CHECK_BYTES_EQ(payload, out);
    CHECK(h.marker);
    CHECK_EQ(100, static_cast<int>(h.payload_type));
    CHECK_EQ(0x0102, static_cast<int>(h.sequence));
    CHECK_EQ(0x11223344U, h.timestamp);
    CHECK_EQ(0x55667788U, h.ssrc);

    std::vector<uint8_t> mine;
    REQUIRE(sealPacketWithTail(key, &header[0], &payload[0], payload.size(), tail, mine));
    CHECK_BYTES_EQ(kat, mine);

    // sealPacket(counter) == sealPacketWithTail(LE counter).
    const uint8_t le_tail[8] = {0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    std::vector<uint8_t> a;
    std::vector<uint8_t> b;
    REQUIRE(sealPacket(key, &header[0], &payload[0], payload.size(), 0x0001020304050607ULL, a));
    REQUIRE(sealPacketWithTail(key, &header[0], &payload[0], payload.size(), le_tail, b));
    CHECK_BYTES_EQ(a, b);
}

TEST_CASE(onlyHeaderBytes4To11AreAuthenticated) {
    uint8_t key[32];
    fillKey(key, 0x33);
    uint8_t header[12];
    buildRtpHeader(96, false, 7, 1000, 0xabcdef01U, header);
    const std::vector<uint8_t> payload = makePayload(40, 9);
    std::vector<uint8_t> pkt;
    REQUIRE(sealPacket(key, header, &payload[0], payload.size(), 5, pkt));

    for (size_t i = 0; i < pkt.size(); ++i) {
        std::vector<uint8_t> bad = pkt;
        bad[i] ^= 0x01U;
        RtpHeader h;
        std::vector<uint8_t> out;
        const OpenResult r = openPacket(key, &bad[0], bad.size(), h, out);
        if (i < 4) {
            // V/P/X/CC, M/PT, sequence are not AAD.
            CHECK_EQ(static_cast<int>(kOpenOk), static_cast<int>(r));
            CHECK_BYTES_EQ(payload, out);
        } else {
            // timestamp/SSRC (AAD), ciphertext, tag and nonce tail all break authentication.
            CHECK_EQ(static_cast<int>(kOpenAuthFailed), static_cast<int>(r));
            CHECK(out.empty());
        }
    }
    // Wrong key.
    uint8_t other[32];
    fillKey(other, 0x34);
    RtpHeader h;
    std::vector<uint8_t> out;
    CHECK_EQ(static_cast<int>(kOpenAuthFailed), static_cast<int>(openPacket(other, &pkt[0], pkt.size(), h, out)));
    CHECK_EQ(7, static_cast<int>(h.sequence));  // header still parsed for diagnostics
}

TEST_CASE(shortPacketsRejectedAndEmptyPayloadOk) {
    uint8_t key[32];
    fillKey(key, 1);
    std::vector<uint8_t> buf(64, 0x80);
    const size_t lens[] = {0U, 12U, 35U};
    for (size_t i = 0; i < 3; ++i) {
        RtpHeader h;
        std::vector<uint8_t> out(3, 1);
        CHECK_EQ(static_cast<int>(kOpenTooShort), static_cast<int>(openPacket(key, &buf[0], lens[i], h, out)));
        CHECK(out.empty());
        std::vector<uint8_t> rtp(3, 1);
        CHECK_EQ(static_cast<int>(kOpenTooShort), static_cast<int>(openPacketToRtp(key, &buf[0], lens[i], rtp)));
        CHECK(rtp.empty());
    }
    RtpHeader h;
    std::vector<uint8_t> out;
    CHECK_EQ(static_cast<int>(kOpenTooShort), static_cast<int>(openPacket(key, NULL, 0, h, out)));

    uint8_t header[12];
    buildRtpHeader(100, false, 1, 2, 3, header);
    std::vector<uint8_t> pkt;
    REQUIRE(sealPacket(key, header, NULL, 0, 0, pkt));
    CHECK_EQ(36U, pkt.size());
    out.assign(5, 9);
    CHECK_EQ(static_cast<int>(kOpenOk), static_cast<int>(openPacket(key, &pkt[0], pkt.size(), h, out)));
    CHECK(out.empty());
    std::vector<uint8_t> rtp;
    CHECK_EQ(static_cast<int>(kOpenOk), static_cast<int>(openPacketToRtp(key, &pkt[0], pkt.size(), rtp)));
    CHECK_BYTES_EQ(std::vector<uint8_t>(header, header + 12), rtp);
}

TEST_CASE(rtpHeaderFieldParsing) {
    const std::vector<uint8_t> raw = test_support::hexToBytes("b5 e1 fffe 80000001 00000002");
    RtpHeader h;
    REQUIRE(parseRtpHeader(&raw[0], raw.size(), h));
    CHECK_EQ(2, static_cast<int>(h.version));
    CHECK(h.padding);
    CHECK(h.extension);
    CHECK_EQ(5, static_cast<int>(h.csrc_count));
    CHECK(h.marker);
    CHECK_EQ(0x61, static_cast<int>(h.payload_type));
    CHECK_EQ(0xfffe, static_cast<int>(h.sequence));
    CHECK_EQ(0x80000001U, h.timestamp);
    CHECK_EQ(2U, h.ssrc);
    CHECK(!parseRtpHeader(&raw[0], 11, h));

    uint8_t built[12];
    buildRtpHeader(0xe4, false, 0xfffe, 0x80000001U, 2U, built);  // PT masked to 0x64
    CHECK_BYTES_EQ(test_support::hexToBytes("80 64 fffe 80000001 00000002"), std::vector<uint8_t>(built, built + 12));
}

// ---------------------------------------------------------------------------------------------
// Format mapping (AudioStreamCodecTest.kt + the AudioStreamCodec table)
// ---------------------------------------------------------------------------------------------

TEST_CASE(opusDecodesAt48kButKeepsNegotiatedRtpClock) {
    const uint64_t bits[] = {0x10000000ULL, 0x20000000ULL, 0x40000000ULL};
    const uint32_t clocks[] = {16000U, 24000U, 48000U};
    for (int i = 0; i < 3; ++i) {
        const AudioFormat f = formatFromBits(bits[i], 100, "telephony");
        CHECK_EQ(static_cast<int>(kCodecOpus), static_cast<int>(f.codec));
        CHECK_EQ(48000U, f.sample_rate);
        CHECK_EQ(1U, f.channels);
        CHECK_EQ(clocks[i], f.rtp_clock_rate);
        CHECK_EQ(100, f.payload_type);
        CHECK_EQ(std::string("telephony"), f.audio_type);
    }
    // Several Opus bits: 48k wins over 24k over 16k; Opus wins over AAC/PCM bits.
    CHECK_EQ(48000U, formatFromBits(0x70000000ULL, 100).rtp_clock_rate);
    CHECK_EQ(24000U, formatFromBits(0x30000000ULL, 100).rtp_clock_rate);
    CHECK_EQ(static_cast<int>(kCodecOpus), static_cast<int>(formatFromBits(0x10800010ULL, 100).codec));
    CHECK_EQ(48000U, opusClockRate(0));
    CHECK_EQ(16000U, opusClockRate(0x10000000ULL));
}

TEST_CASE(otherFormatsCountAtTheirSampleRate) {
    AudioFormat f = formatFromBits(0x800000ULL, 102);
    CHECK_EQ(static_cast<int>(kCodecAacLc), static_cast<int>(f.codec));
    CHECK_EQ(48000U, f.sample_rate);
    CHECK_EQ(48000U, f.rtp_clock_rate);
    CHECK_EQ(2U, f.channels);
    CHECK_EQ(std::string("media"), f.audio_type);
    f = formatFromBits(0x400000ULL, 102);
    CHECK_EQ(static_cast<int>(kCodecAacLc), static_cast<int>(f.codec));
    CHECK_EQ(44100U, f.rtp_clock_rate);
    f = formatFromBits(0xc00000ULL, 102);  // both AAC bits -> 48k
    CHECK_EQ(48000U, f.sample_rate);
    f = formatFromBits(0x10ULL, 100);
    CHECK_EQ(static_cast<int>(kCodecLpcm), static_cast<int>(f.codec));
    CHECK_EQ(16000U, f.rtp_clock_rate);
    CHECK_EQ(1U, f.channels);
}

TEST_CASE(pcmTableAndFallback) {
    struct Row {
        uint64_t bits;
        uint32_t rate;
        uint32_t ch;
    };
    const Row rows[] = {
        {0x4ULL, 8000U, 1U},    {0x8ULL, 8000U, 2U},    {0x10ULL, 16000U, 1U},   {0x20ULL, 16000U, 2U},
        {0x40ULL, 24000U, 1U},  {0x80ULL, 24000U, 2U},  {0x100ULL, 32000U, 1U},  {0x200ULL, 32000U, 2U},
        {0x400ULL, 44100U, 1U}, {0x800ULL, 44100U, 2U}, {0x4000ULL, 48000U, 1U}, {0x8000ULL, 48000U, 2U},
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); ++i) {
        const AudioFormat f = formatFromBits(rows[i].bits, 101, "default");
        CHECK_EQ(static_cast<int>(kCodecLpcm), static_cast<int>(f.codec));
        CHECK_EQ(rows[i].rate, f.sample_rate);
        CHECK_EQ(rows[i].rate, f.rtp_clock_rate);
        CHECK_EQ(rows[i].ch, f.channels);
        CHECK_EQ(101, f.payload_type);
    }
    // Fallback: 0, unknown bits, and combined PCM bits (exact-key lookup) -> LPCM 44100/2.
    const uint64_t fallback[] = {0ULL, 0x1ULL, 0x2ULL, 0x1000ULL, 0x30ULL, 0x100000000ULL};
    for (size_t i = 0; i < sizeof(fallback) / sizeof(fallback[0]); ++i) {
        const AudioFormat f = formatFromBits(fallback[i], 100);
        CHECK_EQ(static_cast<int>(kCodecLpcm), static_cast<int>(f.codec));
        CHECK_EQ(44100U, f.sample_rate);
        CHECK_EQ(2U, f.channels);
        CHECK_EQ(44100U, f.rtp_clock_rate);
    }
}

// ---------------------------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------------------------

TEST_CASE(streamKeyDerivationRecipe) {
    CHECK_EQ(std::string("0"), unsignedDecimal(0));
    CHECK_EQ(std::string("18446744073709551615"), unsignedDecimal(0xffffffffffffffffULL));
    CHECK_EQ(std::string("9223372036854775808"), unsignedDecimal(0x8000000000000000ULL));
    CHECK_EQ(std::string("DataStream-Salt18446744073709551615"), dataStreamSalt(0xffffffffffffffffULL));
    CHECK_EQ(std::string("DataStream-Salt9223372036854775808"), dataStreamSalt(0x8000000000000000ULL));
    CHECK_EQ(std::string("DataStream-Salt42"), dataStreamSalt(42));

    uint8_t shared[32];
    fillKey(shared, 0x40);
    const uint64_t ids[] = {0x8000000000000000ULL, 0xffffffffffffffffULL, 1234567890123ULL};
    const char* salts[] = {"DataStream-Salt9223372036854775808", "DataStream-Salt18446744073709551615",
                           "DataStream-Salt1234567890123"};
    uint8_t keys[3][32];
    for (int i = 0; i < 3; ++i) {
        uint8_t out_key[32];
        uint8_t in_key[32];
        REQUIRE(deriveAudioOutputKey(shared, sizeof(shared), ids[i], out_key));
        REQUIRE(deriveAudioInputKey(shared, sizeof(shared), ids[i], in_key));
        uint8_t ref_out[32];
        uint8_t ref_in[32];
        const std::string salt(salts[i]);
        const std::string out_info("DataStream-Output-Encryption-Key");
        const std::string in_info("DataStream-Input-Encryption-Key");
        REQUIRE(crypto::hkdfSha512(shared, 32, reinterpret_cast<const uint8_t*>(salt.data()), salt.size(),
                                   reinterpret_cast<const uint8_t*>(out_info.data()), out_info.size(), ref_out, 32));
        REQUIRE(crypto::hkdfSha512(shared, 32, reinterpret_cast<const uint8_t*>(salt.data()), salt.size(),
                                   reinterpret_cast<const uint8_t*>(in_info.data()), in_info.size(), ref_in, 32));
        CHECK_BYTES_EQ(std::vector<uint8_t>(ref_out, ref_out + 32), std::vector<uint8_t>(out_key, out_key + 32));
        CHECK_BYTES_EQ(std::vector<uint8_t>(ref_in, ref_in + 32), std::vector<uint8_t>(in_key, in_key + 32));
        CHECK(memcmp(out_key, in_key, 32) != 0);
        memcpy(keys[i], out_key, 32);

        // Deterministic.
        uint8_t again[32];
        REQUIRE(deriveDataStreamKey(shared, 32, ids[i], std::string(kDataStreamOutputKeyInfo), again));
        CHECK(memcmp(again, out_key, 32) == 0);
    }
    CHECK(memcmp(keys[0], keys[1], 32) != 0);
    CHECK(memcmp(keys[1], keys[2], 32) != 0);

    uint8_t k[32];
    CHECK(!deriveAudioOutputKey(NULL, 0, 1, k));

    // End-to-end: the derived key decrypts what a simulated iPhone seals with the same recipe.
    uint8_t header[12];
    buildRtpHeader(100, false, 1, 2, 3, header);
    const std::vector<uint8_t> payload = makePayload(16, 1);
    std::vector<uint8_t> pkt;
    REQUIRE(sealPacket(keys[1], header, &payload[0], payload.size(), 0, pkt));
    RtpHeader h;
    std::vector<uint8_t> out;
    CHECK_EQ(static_cast<int>(kOpenOk), static_cast<int>(openPacket(keys[1], &pkt[0], pkt.size(), h, out)));
    CHECK_EQ(static_cast<int>(kOpenAuthFailed), static_cast<int>(openPacket(keys[0], &pkt[0], pkt.size(), h, out)));
}

// ---------------------------------------------------------------------------------------------
// LPCM
// ---------------------------------------------------------------------------------------------

TEST_CASE(lpcmBigEndianToHostSamples) {
    const std::vector<uint8_t> wire = test_support::hexToBytes("0001 ffff 8000 7fff 1234 ab");
    std::vector<int16_t> s;
    CHECK_EQ(5U, lpcmToInt16(&wire[0], wire.size(), s));
    REQUIRE(s.size() == 5U);
    CHECK_EQ(1, static_cast<int>(s[0]));
    CHECK_EQ(-1, static_cast<int>(s[1]));
    CHECK_EQ(-32768, static_cast<int>(s[2]));
    CHECK_EQ(32767, static_cast<int>(s[3]));
    CHECK_EQ(0x1234, static_cast<int>(s[4]));

    CHECK_EQ(5U, lpcmToInt16(&wire[0], wire.size(), s, kLittleEndianSamples));
    CHECK_EQ(0x0100, static_cast<int>(s[0]));
    CHECK_EQ(0x0080, static_cast<int>(s[2]));
    CHECK_EQ(0x3412, static_cast<int>(s[4]));

    std::vector<uint8_t> back;
    const int16_t samples[] = {1, -1, -32768, 32767, 0x1234};
    int16ToLpcm(samples, 5, back);
    CHECK_BYTES_EQ(test_support::hexToBytes("0001 ffff 8000 7fff 1234"), back);
    int16ToLpcm(samples, 1, back, kLittleEndianSamples);
    CHECK_BYTES_EQ(bytesOf(0x01, 0x00), back);

    CHECK_EQ(0U, lpcmToInt16(NULL, 0, s));
    CHECK(s.empty());
}

// ---------------------------------------------------------------------------------------------
// Jitter buffer
// ---------------------------------------------------------------------------------------------

namespace {

JitterBuffer::PushResult pushSeq(JitterBuffer& jb, uint16_t seq) {
    const uint8_t data[2] = {static_cast<uint8_t>(seq >> 8), static_cast<uint8_t>(seq)};
    return jb.push(seq, static_cast<uint32_t>(seq) * 480U, data, 2);
}

// Pops everything currently deliverable; returns "seq" for packets, "Lseq" for lost.
std::string drain(JitterBuffer& jb) {
    std::string s;
    JitterBuffer::Packet p;
    for (;;) {
        const JitterBuffer::PopResult r = jb.pop(p);
        if (r == JitterBuffer::kPopEmpty) {
            break;
        }
        if (!s.empty()) {
            s += ",";
        }
        if (r == JitterBuffer::kPopLost) {
            s += "L";
            CHECK(p.payload.empty());
        } else {
            CHECK(p.payload == bytesOf(static_cast<uint8_t>(p.sequence >> 8), static_cast<uint8_t>(p.sequence)));
            CHECK_EQ(static_cast<uint32_t>(p.sequence) * 480U, p.timestamp);
        }
        s += test_support::toDisplay(static_cast<unsigned>(p.sequence));
    }
    return s;
}

}  // namespace

TEST_CASE(jitterInOrder) {
    JitterBuffer jb(8, 2);
    CHECK_EQ(std::string(""), drain(jb));
    for (uint16_t s = 10; s < 14; ++s) {
        CHECK_EQ(static_cast<int>(JitterBuffer::kPushAccepted), static_cast<int>(pushSeq(jb, s)));
    }
    CHECK_EQ(4U, jb.size());
    CHECK_EQ(std::string("10,11,12,13"), drain(jb));
    CHECK_EQ(0U, jb.size());
    CHECK_EQ(4U, static_cast<unsigned>(jb.stats().delivered));
    CHECK_EQ(0U, static_cast<unsigned>(jb.stats().reordered));
    CHECK_EQ(0U, static_cast<unsigned>(jb.stats().lost));
}

TEST_CASE(jitterSwappedPairAndDuplicate) {
    JitterBuffer jb(8, 2);
    pushSeq(jb, 100);
    CHECK_EQ(std::string("100"), drain(jb));
    pushSeq(jb, 102);
    CHECK_EQ(std::string(""), drain(jb));  // 101 missing, only 1 ahead (< depth 2)
    CHECK_EQ(static_cast<int>(JitterBuffer::kPushAccepted), static_cast<int>(pushSeq(jb, 101)));
    CHECK_EQ(static_cast<int>(JitterBuffer::kPushDuplicate), static_cast<int>(pushSeq(jb, 102)));
    CHECK_EQ(std::string("101,102"), drain(jb));
    CHECK_EQ(1U, static_cast<unsigned>(jb.stats().reordered));
    CHECK_EQ(1U, static_cast<unsigned>(jb.stats().duplicates));
    CHECK_EQ(4U, static_cast<unsigned>(jb.stats().received));
    CHECK_EQ(3U, static_cast<unsigned>(jb.stats().accepted));
    // Re-sending a delivered packet is too late.
    CHECK_EQ(static_cast<int>(JitterBuffer::kPushTooLate), static_cast<int>(pushSeq(jb, 102)));
}

TEST_CASE(jitterGapSignalsLossAfterReorderDepthThenLate) {
    JitterBuffer jb(16, 3);
    pushSeq(jb, 1);
    CHECK_EQ(std::string("1"), drain(jb));
    pushSeq(jb, 3);
    CHECK_EQ(std::string(""), drain(jb));
    pushSeq(jb, 4);
    CHECK_EQ(std::string(""), drain(jb));  // highest 4 - missing 2 = 2 < 3
    pushSeq(jb, 5);
    CHECK_EQ(std::string("L2,3,4,5"), drain(jb));  // 5 - 2 = 3 -> lost
    CHECK_EQ(1U, static_cast<unsigned>(jb.stats().lost));
    CHECK_EQ(static_cast<int>(JitterBuffer::kPushTooLate), static_cast<int>(pushSeq(jb, 2)));
    CHECK_EQ(1U, static_cast<unsigned>(jb.stats().late));
    // Consecutive gap of two.
    pushSeq(jb, 8);
    pushSeq(jb, 9);
    CHECK_EQ(std::string("L6"), drain(jb));  // 9-6=3 lost; 9-7=2 still waiting
    pushSeq(jb, 10);
    CHECK_EQ(std::string("L7,8,9,10"), drain(jb));
    CHECK_EQ(3U, static_cast<unsigned>(jb.stats().lost));
}

TEST_CASE(jitterWraparound) {
    {
        JitterBuffer jb(8, 2);
        pushSeq(jb, 65534);
        pushSeq(jb, 65535);
        pushSeq(jb, 0);
        pushSeq(jb, 1);
        CHECK_EQ(std::string("65534,65535,0,1"), drain(jb));
        CHECK_EQ(0U, static_cast<unsigned>(jb.stats().reordered));
        CHECK_EQ(static_cast<int>(JitterBuffer::kPushTooLate), static_cast<int>(pushSeq(jb, 65535)));
    }
    {
        JitterBuffer jb(8, 2);
        pushSeq(jb, 65534);
        CHECK_EQ(std::string("65534"), drain(jb));
        pushSeq(jb, 0);
        pushSeq(jb, 65535);
        pushSeq(jb, 1);
        CHECK_EQ(std::string("65535,0,1"), drain(jb));
        CHECK_EQ(1U, static_cast<unsigned>(jb.stats().reordered));
    }
    {
        // Loss across the wrap.
        JitterBuffer jb(8, 2);
        pushSeq(jb, 65534);
        pushSeq(jb, 0);
        pushSeq(jb, 1);
        CHECK_EQ(std::string("65534,L65535,0,1"), drain(jb));
    }
}

TEST_CASE(jitterOverflowDropsOldest) {
    JitterBuffer jb(4, 3);
    pushSeq(jb, 10);
    pushSeq(jb, 11);
    pushSeq(jb, 12);
    pushSeq(jb, 13);
    CHECK_EQ(4U, jb.size());
    CHECK_EQ(static_cast<int>(JitterBuffer::kPushOverflowDroppedOldest), static_cast<int>(pushSeq(jb, 14)));
    CHECK_EQ(4U, jb.size());
    CHECK_EQ(1U, static_cast<unsigned>(jb.stats().overflow_dropped));
    CHECK_EQ(std::string("11,12,13,14"), drain(jb));

    // A big forward jump drops everything buffered and counts skipped holes as lost.
    pushSeq(jb, 15);
    pushSeq(jb, 17);
    CHECK_EQ(static_cast<int>(JitterBuffer::kPushOverflowDroppedOldest), static_cast<int>(pushSeq(jb, 1015)));
    CHECK_EQ(1U, jb.size());
    CHECK_EQ(3U, static_cast<unsigned>(jb.stats().overflow_dropped));
    // window moved from next=15 to next=1012: 997 skipped, 2 of them were buffered.
    CHECK_EQ(995U, static_cast<unsigned>(jb.stats().lost));
    // Remaining holes are signalled one by one as the reorder depth is exceeded.
    CHECK_EQ(std::string("L1012"), drain(jb));  // 1015 - 1012 = 3 >= depth; 1015 - 1013 = 2 waits
    pushSeq(jb, 1016);
    CHECK_EQ(std::string("L1013"), drain(jb));
    pushSeq(jb, 1017);
    CHECK_EQ(std::string("L1014,1015,1016,1017"), drain(jb));
    CHECK_EQ(998U, static_cast<unsigned>(jb.stats().lost));
}

TEST_CASE(jitterFlushAndReset) {
    JitterBuffer jb(8, 2);
    pushSeq(jb, 500);
    pushSeq(jb, 502);
    jb.flush();
    CHECK_EQ(0U, jb.size());
    CHECK(!jb.anchored());
    CHECK_EQ(std::string(""), drain(jb));
    // Re-anchors on any sequence after FLUSH, even an "older" one.
    CHECK_EQ(static_cast<int>(JitterBuffer::kPushAccepted), static_cast<int>(pushSeq(jb, 7)));
    CHECK_EQ(std::string("7"), drain(jb));
    CHECK_EQ(3U, static_cast<unsigned>(jb.stats().received));
    jb.reset();
    CHECK_EQ(0U, static_cast<unsigned>(jb.stats().received));
    CHECK_EQ(0U, static_cast<unsigned>(jb.stats().delivered));

    // Clamping.
    JitterBuffer tiny(0, 0);
    CHECK_EQ(2U, tiny.capacity());
    CHECK_EQ(1, static_cast<int>(tiny.reorderDepth()));
    JitterBuffer deep(4, 100);
    CHECK_EQ(3, static_cast<int>(deep.reorderDepth()));
    JitterBuffer def;
    CHECK_EQ(JitterBuffer::kDefaultCapacity, def.capacity());
}

TEST_CASE(jitterPayloadBuffersRecycled) {
    JitterBuffer jb(4, 2);
    JitterBuffer::Packet p;
    std::vector<uint8_t> big(1000, 0x5a);
    for (uint16_t s = 0; s < 20; ++s) {
        REQUIRE(jb.push(s, s, &big[0], big.size()) == JitterBuffer::kPushAccepted);
        REQUIRE(jb.pop(p) == JitterBuffer::kPopPacket);
        CHECK_EQ(1000U, p.payload.size());
        CHECK_EQ(static_cast<int>(s), static_cast<int>(p.sequence));
    }
    // Empty payload packets are fine too.
    REQUIRE(jb.push(20, 0, NULL, 0) == JitterBuffer::kPushAccepted);
    REQUIRE(jb.pop(p) == JitterBuffer::kPopPacket);
    CHECK(p.payload.empty());
}

int main() { return test_support::runAll("test_audio_rtp"); }
