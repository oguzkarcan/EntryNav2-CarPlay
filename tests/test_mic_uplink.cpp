// Derived in part from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/airplay/MicrophonePacketizer.kt,
//  shared/src/main/java/com/shilapi/xcertplay/airplay/CarPlayMediaEngine.kt,
//  shared/src/test/java/com/shilapi/xcertplay/airplay/MicrophonePacketizerTest.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.
//
// Microphone uplink (port of DiPlay MicrophonePacketizer.kt / CarPlayMediaEngine.microphoneConfig).
// Packets are checked against an independent construction (direct ChaCha20-Poly1305 over the
// hand-built header) and opened with audio::openPacket under the phone-side key derivation.

#include "carplay/airplay_crypto.hpp"
#include "carplay/audio_rtp.hpp"
#include "carplay/bplist_codec.hpp"
#include "carplay/mic_uplink.hpp"
#include "test_support.hpp"

#include <string.h>

#include <string>
#include <vector>

namespace audio = carplay::audio;
namespace crypto = carplay::crypto;
namespace bplist = carplay::bplist;
using test_support::hexToBytes;

typedef std::vector<uint8_t> Bytes;

namespace {

bplist::Value dict() { return bplist::Value::makeDict(); }
bplist::Value num(int64_t v) { return bplist::Value::makeInt(v); }
bplist::Value str(const std::string& s) { return bplist::Value::makeString(s); }

bplist::Value micStream(const char* audio_type, int64_t format, int64_t port) {
    bplist::Value s = dict();
    s.set("type", num(100));
    s.set("audioType", str(audio_type));
    s.set("audioFormat", num(format));
    s.set("streamConnectionID", num(42));
    if (port >= 0) s.set("dataPort", num(port));
    return s;
}

Bytes testKey() {
    Bytes k(32);
    for (size_t i = 0; i < 32; ++i) k[i] = static_cast<uint8_t>(0xa0 + i);
    return k;
}

// Independent sealed packet: header [80, pt, seq BE, ts BE, 0000 0000], nonce 0000|LE64(counter),
// AAD = header[4..12), packet = header | ct | tag | LE64(counter).
Bytes expectedPacket(const Bytes& key, uint8_t pt, uint16_t seq, uint32_t ts, uint64_t counter, const Bytes& body) {
    Bytes hd(12, 0);
    hd[0] = 0x80;
    hd[1] = pt;
    hd[2] = static_cast<uint8_t>(seq >> 8);
    hd[3] = static_cast<uint8_t>(seq);
    for (int i = 0; i < 4; ++i) hd[4 + i] = static_cast<uint8_t>(ts >> (24 - 8 * i));
    Bytes nonce(12, 0);
    for (int i = 0; i < 8; ++i) nonce[4 + i] = static_cast<uint8_t>(counter >> (8 * i));
    Bytes sealed;
    crypto::chacha20Poly1305Seal(&key[0], &nonce[0], &hd[4], 8, body.empty() ? NULL : &body[0], body.size(), sealed);
    Bytes pkt = hd;
    pkt.insert(pkt.end(), sealed.begin(), sealed.end());
    pkt.insert(pkt.end(), nonce.begin() + 4, nonce.end());
    return pkt;
}

}  // namespace

TEST_CASE(wantsMicrophoneRules) {
    bplist::Value s = dict();
    CHECK(audio::streamWantsMicrophone("telephony", s));
    CHECK(audio::streamWantsMicrophone("speechrecognition", s));
    CHECK(!audio::streamWantsMicrophone("speechRecognition", s));  // must be lowercased first
    CHECK(!audio::streamWantsMicrophone("media", s));
    CHECK(!audio::streamWantsMicrophone("alert", s));
    CHECK(!audio::streamWantsMicrophone("default", s));  // no input, no dataPort
    s.set("dataPort", num(5000));
    CHECK(audio::streamWantsMicrophone("default", s));
    CHECK(audio::streamWantsMicrophone("compatibility", s));
    s.set("input", bplist::Value::makeBool(false));  // an explicit input flag wins over dataPort
    CHECK(!audio::streamWantsMicrophone("default", s));
    s.set("input", num(1));
    CHECK(audio::streamWantsMicrophone("default", s));
    s.set("input", num(0));
    CHECK(!audio::streamWantsMicrophone("default", s));
    s.set("input", str("yes"));  // not Boolean / Number -> falls back to the dataPort rule
    CHECK(audio::streamWantsMicrophone("default", s));
    s.set("dataPort", num(70000));
    CHECK(!audio::streamWantsMicrophone("default", s));
}

TEST_CASE(pcmFrameMillisFitsOneMtu) {
    CHECK_EQ(20U, audio::micPcmFrameMillis(16000, 1));   // 36 + 640
    CHECK_EQ(20U, audio::micPcmFrameMillis(24000, 1));   // 36 + 960
    CHECK_EQ(20U, audio::micPcmFrameMillis(32000, 1));   // 36 + 1280
    CHECK_EQ(10U, audio::micPcmFrameMillis(44100, 1));   // 20 ms = 1800 > 1452
    CHECK_EQ(10U, audio::micPcmFrameMillis(48000, 1));   // the reference's "48 kHz mono sends 10 ms"
    CHECK_EQ(5U, audio::micPcmFrameMillis(48000, 2));    // 10 ms = 1956
    CHECK_EQ(5U, audio::micPcmFrameMillis(192000, 2));   // nothing fits: last candidate
}

TEST_CASE(parseMicrophoneStreamFollowsMicrophoneConfig) {
    audio::MicStreamParams p;
    // 16 kHz mono speech, no framesPerPacket: 20 ms -> 320 samples.
    bplist::Value s = micStream("speechRecognition", 0x10, 50000);
    REQUIRE(audio::parseMicrophoneStream(100, s, true, p));
    CHECK(p.supported);
    CHECK_EQ(50000, p.data_port);
    CHECK_EQ(100U, static_cast<unsigned>(p.payload_type));
    CHECK(p.format_bits == 0x10U);
    CHECK_EQ(16000U, p.format.sample_rate);
    CHECK_EQ(1U, p.format.channels);
    CHECK_EQ(0, p.frames_per_packet);
    CHECK_EQ(20U, p.frame_millis);
    CHECK_EQ(320U, p.samples_per_packet);
    CHECK_EQ(320U, p.rtp_samples_per_packet);
    CHECK_EQ(320U, p.samplesPerFrame());
    CHECK_EQ(640U, p.frameBytes());

    // framesPerPacket: round(fpp * 1000 / rate) clamped to [5, 60]; samples follow the millis.
    s.set("framesPerPacket", num(480));  // 24 kHz Siri packet at 16 kHz -> 30 ms
    REQUIRE(audio::parseMicrophoneStream(100, s, true, p));
    CHECK_EQ(30U, p.frame_millis);
    CHECK_EQ(480U, p.samples_per_packet);
    s.set("framesPerPacket", num(1));
    REQUIRE(audio::parseMicrophoneStream(100, s, true, p));
    CHECK_EQ(5U, p.frame_millis);
    CHECK_EQ(80U, p.samples_per_packet);
    s.set("framesPerPacket", num(4000));
    REQUIRE(audio::parseMicrophoneStream(100, s, true, p));
    CHECK_EQ(60U, p.frame_millis);
    s.set("framesPerPacket", num(-5));  // not > 0: default rule
    REQUIRE(audio::parseMicrophoneStream(100, s, true, p));
    CHECK_EQ(20U, p.frame_millis);
    bplist::Value s441 = micStream("telephony", 0x400, 50000);
    s441.set("framesPerPacket", num(441));  // 10 ms at 44.1 kHz
    REQUIRE(audio::parseMicrophoneStream(100, s441, true, p));
    CHECK_EQ(10U, p.frame_millis);
    CHECK_EQ(441U, p.samples_per_packet);

    // 48 kHz mono without framesPerPacket: 10 ms (MTU rule).
    REQUIRE(audio::parseMicrophoneStream(100, micStream("telephony", 0x4000, 50000), true, p));
    CHECK_EQ(10U, p.frame_millis);
    CHECK_EQ(480U, p.samples_per_packet);

    // Opus: reported, but unsupported (out of scope); 20 ms, 960 samples, RTP step on the Opus clock.
    REQUIRE(audio::parseMicrophoneStream(100, micStream("telephony", 0x20000000, 50000), true, p));
    CHECK(!p.supported);
    CHECK(p.format.codec == audio::kCodecOpus);
    CHECK_EQ(20U, p.frame_millis);
    CHECK_EQ(960U, p.samples_per_packet);
    CHECK_EQ(480U, p.rtp_samples_per_packet);  // 24 kHz clock

    // No microphone.
    CHECK(!audio::parseMicrophoneStream(100, micStream("telephony", 0x10, 50000), false, p));
    CHECK(!audio::parseMicrophoneStream(101, micStream("telephony", 0x10, 50000), true, p));
    CHECK(!audio::parseMicrophoneStream(100, micStream("media", 0x10, 50000), true, p));
    CHECK(!audio::parseMicrophoneStream(100, micStream("telephony", 0x10, -1), true, p));
    CHECK(!audio::parseMicrophoneStream(100, micStream("telephony", 0x10, 0), true, p));
    CHECK(!audio::parseMicrophoneStream(100, micStream("telephony", 0x10, 65536), true, p));
    CHECK(!audio::parseMicrophoneStream(100, str("not a dict"), true, p));
    bplist::Value bad_port = micStream("telephony", 0x10, -1);
    bad_port.set("dataPort", str("50000"));
    CHECK(!audio::parseMicrophoneStream(100, bad_port, true, p));

    // streamAudioFormat: audioType lowercased, default "default"; missing audioFormat -> 0 fallback.
    bplist::Value bare = dict();
    const audio::AudioFormat f = audio::streamAudioFormat(bare, 100);
    CHECK_EQ(std::string("default"), f.audio_type);
    CHECK(f.codec == audio::kCodecLpcm);
    CHECK_EQ(44100U, f.sample_rate);
    CHECK(audio::streamAudioFormatBits(bare) == 0U);
    bare.set("audioFormat", bplist::Value::makeUInt(0x8000000000000010ULL));
    CHECK(audio::streamAudioFormatBits(bare) == 0x8000000000000010ULL);
}

TEST_CASE(sealMatchesIndependentConstructionAndCountersAdvance) {
    const Bytes key = testKey();
    const Bytes body = hexToBytes("0102030405060708");
    audio::MicCounters c;
    Bytes pkt;
    REQUIRE(audio::sealMicrophonePacket(&key[0], 100, c, &body[0], body.size(), 4, pkt));
    CHECK_BYTES_EQ(expectedPacket(key, 100, 0, 0, 0, body), pkt);
    CHECK_EQ(1U, static_cast<unsigned>(c.sequence));
    CHECK_EQ(4U, c.timestamp);
    CHECK(c.nonce == 1U);
    // Wraparound: sequence mod 2^16, timestamp mod 2^32, payload type masked to 7 bits.
    c.sequence = 0xffff;
    c.timestamp = 0xfffffffeU;
    c.nonce = 0x0102030405060708ULL;
    REQUIRE(audio::sealMicrophonePacket(&key[0], 0xe4, c, &body[0], body.size(), 4, pkt));
    CHECK_BYTES_EQ(expectedPacket(key, 0x64, 0xffff, 0xfffffffeU, 0x0102030405060708ULL, body), pkt);
    CHECK_EQ(0U, static_cast<unsigned>(c.sequence));
    CHECK_EQ(2U, c.timestamp);
    CHECK(c.nonce == 0x0102030405060709ULL);
    // Failure leaves the counters alone.
    const audio::MicCounters before = c;
    CHECK(!audio::sealMicrophonePacket(NULL, 100, c, &body[0], body.size(), 4, pkt));
    CHECK(!audio::sealMicrophonePacket(&key[0], 100, c, NULL, 3, 4, pkt));
    CHECK_EQ(static_cast<unsigned>(before.sequence), static_cast<unsigned>(c.sequence));
    CHECK(before.nonce == c.nonce);
}

TEST_CASE(packetizerFramesBigEndianAndOpensWithPhoneKey) {
    // Phone-side derivation of the uplink key from a shared secret (DataStream-Input-Encryption-Key).
    Bytes shared(32);
    for (size_t i = 0; i < 32; ++i) shared[i] = static_cast<uint8_t>(i * 7 + 1);
    Bytes phone_key;
    crypto::hkdfSha512(shared, "DataStream-Salt42", "DataStream-Input-Encryption-Key", 32, phone_key);
    uint8_t acc_key[32];
    REQUIRE(audio::deriveAudioInputKey(&shared[0], shared.size(), 42, acc_key));
    CHECK_BYTES_EQ(phone_key, Bytes(acc_key, acc_key + 32));

    audio::MicStreamParams p;
    bplist::Value s = micStream("telephony", 0x20, 50000);  // 16 kHz STEREO (format channels honoured)
    s.set("framesPerPacket", num(80));                       // 5 ms
    REQUIRE(audio::parseMicrophoneStream(100, s, true, p));
    REQUIRE(p.supported);
    CHECK_EQ(2U, p.format.channels);
    CHECK_EQ(80U, p.samples_per_packet);
    CHECK_EQ(160U, p.samplesPerFrame());

    audio::MicPacketizer mic;
    CHECK(!mic.configured());
    REQUIRE(mic.configure(p, acc_key));
    std::vector<int16_t> pcm(160 * 4 + 7);
    for (size_t i = 0; i < pcm.size(); ++i) pcm[i] = static_cast<int16_t>(static_cast<int>(i * 211) - 32768);
    pcm[3] = -1;
    pcm[4] = 0x1234;
    // Delivered in odd chunks; leftovers carry over.
    std::vector<Bytes> packets;
    size_t off = 0;
    const size_t chunks[] = {1, 150, 100, 3, 293, 100};
    for (size_t k = 0; k < sizeof(chunks) / sizeof(chunks[0]); ++k) {
        mic.push(&pcm[off], chunks[k], packets);
        off += chunks[k];
    }
    REQUIRE(off == pcm.size());
    REQUIRE(packets.size() == 4U);
    CHECK_EQ(7U, mic.pendingSamples());
    for (size_t k = 0; k < 4; ++k) {
        audio::RtpHeader h;
        Bytes payload;
        REQUIRE(audio::openPacket(&phone_key[0], &packets[k][0], packets[k].size(), h, payload) == audio::kOpenOk);
        CHECK_EQ(k, static_cast<size_t>(h.sequence));
        CHECK_EQ(80U * k, h.timestamp);
        CHECK_EQ(0U, h.ssrc);
        CHECK_EQ(100U, static_cast<unsigned>(h.payload_type));
        REQUIRE(payload.size() == 320U);
        // Big-endian on the wire (MicrophonePacketizer.toWirePcm).
        const uint16_t first = static_cast<uint16_t>(pcm[160 * k]);
        CHECK_EQ(static_cast<unsigned>(first >> 8), static_cast<unsigned>(payload[0]));
        CHECK_EQ(static_cast<unsigned>(first & 0xff), static_cast<unsigned>(payload[1]));
        std::vector<int16_t> got;
        audio::lpcmToInt16(&payload[0], payload.size(), got);
        CHECK(got == std::vector<int16_t>(pcm.begin() + static_cast<long>(160 * k),
                                          pcm.begin() + static_cast<long>(160 * (k + 1))));
        // Same bytes as the independent construction.
        Bytes be;
        for (size_t i = 0; i < 160; ++i) {
            const uint16_t u = static_cast<uint16_t>(pcm[160 * k + i]);
            be.push_back(static_cast<uint8_t>(u >> 8));
            be.push_back(static_cast<uint8_t>(u));
        }
        CHECK_BYTES_EQ(expectedPacket(phone_key, 100, static_cast<uint16_t>(k), static_cast<uint32_t>(80 * k), k, be),
                       packets[k]);
    }
    CHECK_EQ(4U, static_cast<unsigned>(mic.counters().sequence));
    CHECK_EQ(320U, mic.counters().timestamp);
    CHECK(mic.counters().nonce == 4U);

    // sealFrame needs exactly one frame.
    Bytes one;
    CHECK(!mic.sealFrame(&pcm[0], 159, one));
    REQUIRE(mic.sealFrame(&pcm[0], 160, one));
    CHECK_EQ(36U + 320U, one.size());

    // configure() restarts the counters; Opus / bad params / NULL key are refused.
    REQUIRE(mic.configure(p, acc_key));
    CHECK(mic.counters().nonce == 0U);
    CHECK_EQ(0U, mic.pendingSamples());
    audio::MicStreamParams opus;
    REQUIRE(audio::parseMicrophoneStream(100, micStream("telephony", 0x40000000, 50000), true, opus));
    CHECK(!mic.configure(opus, acc_key));
    CHECK(!mic.configured());
    CHECK(!mic.configure(p, NULL));
    audio::MicStreamParams zero = p;
    zero.samples_per_packet = 0;
    CHECK(!mic.configure(zero, acc_key));
    std::vector<Bytes> none;
    CHECK_EQ(0U, mic.push(&pcm[0], pcm.size(), none));  // not configured
    CHECK(none.empty());
    mic.reset();
    CHECK(!mic.configured());
}

int main() { return test_support::runAll("test_mic_uplink"); }
