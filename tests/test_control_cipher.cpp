// ControlCipher: ChaCha20-Poly1305 control-channel framing ([u16 LE len][ct][tag16], AAD = len bytes).

#include "carplay/control_cipher.hpp"
#include "carplay/airplay_crypto.hpp"
#include "test_support.hpp"

#include <string.h>

#include <string>
#include <vector>

using carplay::ControlCipher;
namespace crypto = carplay::crypto;

namespace {

struct Keys {
    uint8_t a_to_b[32];
    uint8_t b_to_a[32];
    Keys() {
        for (int i = 0; i < 32; ++i) {
            a_to_b[i] = static_cast<uint8_t>(0x10 + i);
            b_to_a[i] = static_cast<uint8_t>(0xa0 + i);
        }
    }
};

std::vector<uint8_t> pattern(size_t n, uint8_t seed) {
    std::vector<uint8_t> v(n);
    uint32_t x = 0x12345678U ^ seed;
    for (size_t i = 0; i < n; ++i) {
        x = x * 1103515245U + 12345U;
        v[i] = static_cast<uint8_t>(x >> 16);
    }
    return v;
}

// Walks a frame stream and returns each frame's payload length; false if malformed.
bool frameLengths(const std::vector<uint8_t>& wire, std::vector<size_t>& lens) {
    lens.clear();
    size_t pos = 0;
    while (pos < wire.size()) {
        if (wire.size() - pos < 2) return false;
        const size_t l = static_cast<size_t>(wire[pos]) | (static_cast<size_t>(wire[pos + 1]) << 8);
        if (wire.size() - pos < 2 + l + 16) return false;
        lens.push_back(l);
        pos += 2 + l + 16;
    }
    return true;
}

// Builds a frame independently with the raw crypto primitives.
std::vector<uint8_t> manualFrame(const uint8_t key[32], uint64_t counter, const std::vector<uint8_t>& pt) {
    uint8_t aad[2];
    aad[0] = static_cast<uint8_t>(pt.size() & 0xff);
    aad[1] = static_cast<uint8_t>((pt.size() >> 8) & 0xff);
    uint8_t nonce[12];
    crypto::makeCounterNonce(counter, nonce);
    std::vector<uint8_t> sealed;
    crypto::chacha20Poly1305Seal(key, nonce, aad, 2, pt.empty() ? NULL : &pt[0], pt.size(), sealed);
    std::vector<uint8_t> frame;
    frame.reserve(2 + sealed.size());
    frame.push_back(aad[0]);
    frame.push_back(aad[1]);
    frame.insert(frame.end(), sealed.begin(), sealed.end());
    return frame;
}

}  // namespace

TEST_CASE(roundTripVariousSizes) {
    Keys k;
    const size_t sizes[] = {0, 1, 16383, 16384, 16385, 40000};
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); ++s) {
        const size_t n = sizes[s];
        ControlCipher a(k.b_to_a, k.a_to_b);
        ControlCipher b(k.a_to_b, k.b_to_a);
        const std::vector<uint8_t> pt = pattern(n, static_cast<uint8_t>(s));
        std::vector<uint8_t> wire;
        REQUIRE(a.encrypt(pt, wire));

        const size_t expected_frames = n == 0 ? 1 : (n + 16383) / 16384;
        std::vector<size_t> lens;
        REQUIRE(frameLengths(wire, lens));
        CHECK_EQ(expected_frames, lens.size());
        CHECK_EQ(n + 18 * expected_frames, wire.size());
        size_t total = 0;
        for (size_t i = 0; i < lens.size(); ++i) {
            total += lens[i];
            if (i + 1 < lens.size()) CHECK_EQ(static_cast<size_t>(16384), lens[i]);
        }
        CHECK_EQ(n, total);
        CHECK_EQ(static_cast<uint64_t>(expected_frames), a.writeCounter());

        std::vector<uint8_t> out;
        REQUIRE(b.feed(wire, out));
        CHECK_BYTES_EQ(pt, out);
        CHECK_EQ(static_cast<uint64_t>(expected_frames), b.readCounter());
        CHECK_EQ(static_cast<size_t>(0), b.bufferedBytes());
        CHECK(!b.failed());

        // Reverse direction too.
        std::vector<uint8_t> wire2, out2;
        REQUIRE(b.encrypt(pt, wire2));
        REQUIRE(a.feed(wire2, out2));
        CHECK_BYTES_EQ(pt, out2);
    }
}

TEST_CASE(fortyThousandBytesSplitsIntoThreeFrames) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    std::vector<uint8_t> wire;
    REQUIRE(a.encrypt(pattern(40000, 9), wire));
    std::vector<size_t> lens;
    REQUIRE(frameLengths(wire, lens));
    REQUIRE(lens.size() == 3);
    CHECK_EQ(static_cast<size_t>(16384), lens[0]);
    CHECK_EQ(static_cast<size_t>(16384), lens[1]);
    CHECK_EQ(static_cast<size_t>(7232), lens[2]);
    CHECK_EQ(static_cast<size_t>(40000 + 18 * 3), wire.size());
}

TEST_CASE(emptyPlaintextEmitsOneEmptyFrame) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    std::vector<uint8_t> wire;
    REQUIRE(a.encrypt(NULL, 0, wire));
    CHECK_EQ(static_cast<size_t>(18), wire.size());
    CHECK_EQ(0, static_cast<int>(wire[0]));
    CHECK_EQ(0, static_cast<int>(wire[1]));
    CHECK_EQ(static_cast<uint64_t>(1), a.writeCounter());
    CHECK_BYTES_EQ(manualFrame(k.a_to_b, 0, std::vector<uint8_t>()), wire);
}

TEST_CASE(encryptAppendsToExistingOutput) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    std::vector<uint8_t> wire(3, 0xee);
    REQUIRE(a.encrypt(pattern(5, 1), wire));
    REQUIRE(wire.size() == 3 + 5 + 18);
    CHECK_EQ(0xee, static_cast<int>(wire[0]));
    CHECK_EQ(0xee, static_cast<int>(wire[2]));
    CHECK_EQ(5, static_cast<int>(wire[3]));
}

TEST_CASE(knownAnswerFirstAndSecondFrame) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    const std::string s1 = "GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n";
    const std::string s2 = "second";
    const std::vector<uint8_t> p1(s1.begin(), s1.end());
    const std::vector<uint8_t> p2(s2.begin(), s2.end());

    std::vector<uint8_t> f1, f2;
    REQUIRE(a.encrypt(p1, f1));
    REQUIRE(a.encrypt(p2, f2));
    CHECK_BYTES_EQ(manualFrame(k.a_to_b, 0, p1), f1);
    CHECK_BYTES_EQ(manualFrame(k.a_to_b, 1, p2), f2);

    // Explicit header bytes: LE length.
    CHECK_EQ(static_cast<int>(p1.size()), static_cast<int>(f1[0]));
    CHECK_EQ(0, static_cast<int>(f1[1]));

    // Fixed-vector sanity: the nonce layout is 4 zero bytes + LE counter.
    uint8_t nonce[12];
    crypto::makeCounterNonce(0x0102030405060708ULL, nonce);
    CHECK_BYTES_EQ(test_support::hexToBytes("00000000 0807060504030201"), std::vector<uint8_t>(nonce, nonce + 12));
}

TEST_CASE(byteByByteFeedEqualsSingleFeed) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    std::vector<uint8_t> wire;
    const std::vector<uint8_t> pt = pattern(20000, 3);
    REQUIRE(a.encrypt(pt, wire));
    REQUIRE(a.encrypt(pattern(0, 0), wire));
    REQUIRE(a.encrypt(pattern(7, 4), wire));

    ControlCipher single(k.a_to_b, k.b_to_a);
    std::vector<uint8_t> out_single;
    REQUIRE(single.feed(wire, out_single));

    ControlCipher bytewise(k.a_to_b, k.b_to_a);
    std::vector<uint8_t> out_bytes;
    size_t max_buffered = 0;
    for (size_t i = 0; i < wire.size(); ++i) {
        REQUIRE(bytewise.feed(&wire[i], 1, out_bytes));
        if (bytewise.bufferedBytes() > max_buffered) max_buffered = bytewise.bufferedBytes();
    }
    CHECK_BYTES_EQ(out_single, out_bytes);
    CHECK_EQ(out_single.size(), static_cast<size_t>(20007));
    CHECK_EQ(single.readCounter(), bytewise.readCounter());
    CHECK_EQ(static_cast<uint64_t>(4), bytewise.readCounter());
    CHECK_EQ(static_cast<size_t>(0), bytewise.bufferedBytes());
    CHECK(max_buffered < ControlCipher::kMaxFrameBytes);
}

TEST_CASE(multipleFramesInOneFeedAndPartialHeld) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    ControlCipher b(k.a_to_b, k.b_to_a);
    std::vector<uint8_t> wire;
    REQUIRE(a.encrypt(pattern(10, 1), wire));
    REQUIRE(a.encrypt(pattern(20, 2), wire));
    REQUIRE(a.encrypt(pattern(30, 3), wire));
    const size_t first_two = (10 + 18) + (20 + 18);

    // Two complete frames + 1 byte of the third (only half of its header).
    std::vector<uint8_t> out;
    REQUIRE(b.feed(&wire[0], first_two + 1, out));
    std::vector<uint8_t> expect = pattern(10, 1);
    const std::vector<uint8_t> p2 = pattern(20, 2);
    expect.insert(expect.end(), p2.begin(), p2.end());
    CHECK_BYTES_EQ(expect, out);
    CHECK_EQ(static_cast<uint64_t>(2), b.readCounter());
    CHECK_EQ(static_cast<size_t>(1), b.bufferedBytes());

    // Header complete + some payload.
    REQUIRE(b.feed(&wire[first_two + 1], 10, out));
    CHECK_EQ(static_cast<size_t>(11), b.bufferedBytes());
    CHECK_EQ(static_cast<uint64_t>(2), b.readCounter());

    // Empty feed is a no-op.
    REQUIRE(b.feed(NULL, 0, out));
    CHECK_EQ(static_cast<size_t>(11), b.bufferedBytes());

    // Remainder completes it.
    REQUIRE(b.feed(&wire[first_two + 11], wire.size() - first_two - 11, out));
    const std::vector<uint8_t> p3 = pattern(30, 3);
    expect.insert(expect.end(), p3.begin(), p3.end());
    CHECK_BYTES_EQ(expect, out);
    CHECK_EQ(static_cast<uint64_t>(3), b.readCounter());
    CHECK_EQ(static_cast<size_t>(0), b.bufferedBytes());
}

TEST_CASE(partialFrameCompletedTogetherWithFollowingFrames) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    ControlCipher b(k.a_to_b, k.b_to_a);
    std::vector<uint8_t> wire;
    REQUIRE(a.encrypt(pattern(100, 1), wire));
    REQUIRE(a.encrypt(pattern(200, 2), wire));
    REQUIRE(a.encrypt(pattern(300, 3), wire));
    std::vector<uint8_t> out;
    REQUIRE(b.feed(&wire[0], 50, out));
    CHECK(out.empty());
    CHECK_EQ(static_cast<size_t>(50), b.bufferedBytes());
    REQUIRE(b.feed(&wire[50], wire.size() - 50, out));
    CHECK_EQ(static_cast<size_t>(600), out.size());
    CHECK_EQ(static_cast<uint64_t>(3), b.readCounter());
    CHECK_EQ(static_cast<size_t>(0), b.bufferedBytes());
}

namespace {

// Corrupts byte `index` of the second frame; verifies the first frame's plaintext is delivered,
// feed fails, the cipher is permanently failed and the read counter stays at 1.
void checkCorruption(size_t index_in_second_frame) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    ControlCipher b(k.a_to_b, k.b_to_a);
    std::vector<uint8_t> wire;
    REQUIRE(a.encrypt(pattern(40, 1), wire));
    const size_t first = wire.size();
    REQUIRE(a.encrypt(pattern(40, 2), wire));
    REQUIRE(a.encrypt(pattern(40, 3), wire));
    wire[first + index_in_second_frame] ^= 0x01;

    std::vector<uint8_t> out;
    CHECK(!b.feed(wire, out));
    CHECK(b.failed());
    CHECK_BYTES_EQ(pattern(40, 1), out);  // only the good, earlier frame
    CHECK_EQ(static_cast<uint64_t>(1), b.readCounter());
    CHECK_EQ(static_cast<size_t>(0), b.bufferedBytes());

    // Stays failed for both directions, even with valid input.
    ControlCipher a2(k.b_to_a, k.a_to_b);
    std::vector<uint8_t> good, out2;
    REQUIRE(a2.encrypt(pattern(5, 5), good));
    CHECK(!b.feed(good, out2));
    CHECK(out2.empty());
    std::vector<uint8_t> enc;
    CHECK(!b.encrypt(pattern(5, 5), enc));
    CHECK(enc.empty());
    CHECK(b.failed());
}

}  // namespace

TEST_CASE(flippedCiphertextBitFails) { checkCorruption(2 + 7); }

TEST_CASE(flippedTagBitFails) { checkCorruption(2 + 40 + 15); }

TEST_CASE(flippedLengthByteFails) {
    // Length 40 -> 41: the frame now swallows a byte of the next frame and the AAD changes.
    checkCorruption(0);
}

TEST_CASE(flippedLengthByteSingleFrameIsHeldThenFails) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    ControlCipher b(k.a_to_b, k.b_to_a);
    std::vector<uint8_t> wire;
    REQUIRE(a.encrypt(pattern(40, 1), wire));
    wire[0] ^= 0x01;  // claims 41 bytes; frame now one byte short -> buffered
    std::vector<uint8_t> out;
    REQUIRE(b.feed(wire, out));
    CHECK_EQ(wire.size(), b.bufferedBytes());
    const uint8_t extra = 0;
    CHECK(!b.feed(&extra, 1, out));
    CHECK(b.failed());
    CHECK(out.empty());
    CHECK_EQ(static_cast<uint64_t>(0), b.readCounter());
}

TEST_CASE(failureInsideBufferedFrameFails) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    ControlCipher b(k.a_to_b, k.b_to_a);
    std::vector<uint8_t> wire;
    REQUIRE(a.encrypt(pattern(64, 1), wire));
    wire[wire.size() - 1] ^= 0x80;
    std::vector<uint8_t> out;
    REQUIRE(b.feed(&wire[0], 10, out));
    CHECK(!b.feed(&wire[10], wire.size() - 10, out));
    CHECK(out.empty());
    CHECK(b.failed());
    CHECK_EQ(static_cast<size_t>(0), b.bufferedBytes());
}

TEST_CASE(replayFails) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    ControlCipher b(k.a_to_b, k.b_to_a);
    std::vector<uint8_t> f1;
    REQUIRE(a.encrypt(pattern(12, 1), f1));
    std::vector<uint8_t> out;
    REQUIRE(b.feed(f1, out));
    CHECK(!b.feed(f1, out));  // same frame again: counter 1 != 0
    CHECK(b.failed());
    CHECK_BYTES_EQ(pattern(12, 1), out);
    CHECK_EQ(static_cast<uint64_t>(1), b.readCounter());
}

TEST_CASE(reorderFails) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    ControlCipher b(k.a_to_b, k.b_to_a);
    std::vector<uint8_t> f1, f2;
    REQUIRE(a.encrypt(pattern(12, 1), f1));
    REQUIRE(a.encrypt(pattern(12, 2), f2));
    std::vector<uint8_t> out;
    CHECK(!b.feed(f2, out));
    CHECK(out.empty());
    CHECK(b.failed());
    CHECK_EQ(static_cast<uint64_t>(0), b.readCounter());
}

TEST_CASE(nonChunkLengthsAcceptedOnRead) {
    Keys k;
    ControlCipher b(k.a_to_b, k.b_to_a);
    const std::vector<uint8_t> p1 = pattern(1024, 1);
    const std::vector<uint8_t> p2 = pattern(65535, 2);
    const std::vector<uint8_t> p3 = pattern(16385, 3);
    std::vector<uint8_t> wire = manualFrame(k.a_to_b, 0, p1);
    const std::vector<uint8_t> f2 = manualFrame(k.a_to_b, 1, p2);
    const std::vector<uint8_t> f3 = manualFrame(k.a_to_b, 2, p3);
    CHECK_EQ(0xff, static_cast<int>(f2[0]));
    CHECK_EQ(0xff, static_cast<int>(f2[1]));
    CHECK_EQ(static_cast<size_t>(65535 + 18), f2.size());
    wire.insert(wire.end(), f2.begin(), f2.end());
    wire.insert(wire.end(), f3.begin(), f3.end());

    std::vector<uint8_t> expect = p1;
    expect.insert(expect.end(), p2.begin(), p2.end());
    expect.insert(expect.end(), p3.begin(), p3.end());

    std::vector<uint8_t> out;
    REQUIRE(b.feed(wire, out));
    CHECK(out == expect);
    CHECK_EQ(static_cast<uint64_t>(3), b.readCounter());

    // Same stream in odd-sized pieces, max buffering bounded by one maximal frame.
    ControlCipher c(k.a_to_b, k.b_to_a);
    std::vector<uint8_t> out2;
    size_t pos = 0;
    size_t step = 1;
    while (pos < wire.size()) {
        const size_t n = (wire.size() - pos) < step ? (wire.size() - pos) : step;
        REQUIRE(c.feed(&wire[pos], n, out2));
        CHECK(c.bufferedBytes() < ControlCipher::kMaxFrameBytes);
        pos += n;
        step = step * 3 + 1;
        if (step > 70000) step = 7;
    }
    CHECK(out2 == expect);
    CHECK_EQ(static_cast<uint64_t>(3), c.readCounter());
}

TEST_CASE(wrongDirectionKeyFails) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    // b mistakenly uses the same orientation as a (reads with b_to_a).
    ControlCipher b(k.b_to_a, k.a_to_b);
    std::vector<uint8_t> wire, out;
    REQUIRE(a.encrypt(pattern(32, 1), wire));
    CHECK(!b.feed(wire, out));
    CHECK(out.empty());
    CHECK(b.failed());
}

TEST_CASE(countersReportedCorrectly) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    ControlCipher b(k.a_to_b, k.b_to_a);
    CHECK_EQ(static_cast<uint64_t>(0), a.readCounter());
    CHECK_EQ(static_cast<uint64_t>(0), a.writeCounter());
    std::vector<uint8_t> wire, out;
    REQUIRE(a.encrypt(pattern(16384 * 2 + 1, 1), wire));  // 3 frames
    REQUIRE(a.encrypt(NULL, 0, wire));                     // 1 frame
    CHECK_EQ(static_cast<uint64_t>(4), a.writeCounter());
    CHECK_EQ(static_cast<uint64_t>(0), a.readCounter());
    REQUIRE(b.feed(wire, out));
    CHECK_EQ(static_cast<uint64_t>(4), b.readCounter());
    CHECK_EQ(static_cast<uint64_t>(0), b.writeCounter());
}

TEST_CASE(invalidArgumentsRejectedWithoutFailing) {
    Keys k;
    ControlCipher a(k.b_to_a, k.a_to_b);
    std::vector<uint8_t> out;
    CHECK(!a.encrypt(NULL, 5, out));
    CHECK(out.empty());
    CHECK(!a.feed(NULL, 5, out));
    CHECK(!a.failed());
    CHECK_EQ(static_cast<uint64_t>(0), a.writeCounter());
}

int main() { return test_support::runAll("test_control_cipher"); }
