// Host tests for carplay::ntp (ntp_timing).

#include <string.h>

#include <limits>
#include <vector>

#include "carplay/ntp_timing.hpp"
#include "test_support.hpp"

using namespace carplay::ntp;

namespace {

std::vector<uint8_t> vec(const uint8_t* p, size_t n) { return std::vector<uint8_t>(p, p + n); }

int64_t absDiff(int64_t a, int64_t b) { return a > b ? a - b : b - a; }

// Arbitrary but realistic wall-clock offset (NTP seconds ~3.9e9, i.e. year 2023+).
const int64_t kBase = 3900000000LL * 1000000000LL;

// One request/response exchange against a simulated phone whose clock is
// ntpFromNanos(mono + phone_offset_ns). One-way delay `d`, phone processing time `proc`.
ClockSync::Outcome exchange(ClockSync& cs, int64_t& mono, int64_t phone_offset_ns, int64_t d, int64_t proc) {
    uint8_t req[kPacketBytes];
    cs.makeRequest(mono, req);
    const uint64_t t2 = ntpFromNanos(mono + d + phone_offset_ns);
    const uint64_t t3 = ntpFromNanos(mono + d + proc + phone_offset_ns);
    uint8_t resp[kPacketBytes];
    buildResponse(req, sizeof(req), t2, t3, resp);
    const int64_t t4_mono = mono + 2 * d + proc;
    uint8_t out[kPacketBytes];
    bool has = true;
    const ClockSync::Outcome o = cs.onPacket(resp, sizeof(resp), t4_mono, out, has);
    CHECK(!has);
    mono += 1000000000LL;  // reference REQUEST_INTERVAL_MS = 1 s
    return o;
}

}  // namespace

TEST_CASE(packetBuildAndParseExactBytes) {
    uint8_t req[kPacketBytes];
    buildRequest(0x0102030405060708ULL, req);
    CHECK_BYTES_EQ(test_support::hexToBytes("80d20007 00000000 0000000000000000 0000000000000000 0102030405060708"),
                   vec(req, sizeof(req)));

    Packet p;
    REQUIRE(parsePacket(req, sizeof(req), p));
    CHECK_EQ(210, static_cast<int>(p.payload_type));
    CHECK_EQ(0x0102030405060708ULL, p.transmit);
    CHECK_EQ(0ULL, p.originate);

    uint8_t resp[kPacketBytes];
    REQUIRE(buildResponse(req, sizeof(req), 0x1111111122222222ULL, 0x3333333344444444ULL, resp));
    CHECK_BYTES_EQ(test_support::hexToBytes("80d30007 00000000 0102030405060708 1111111122222222 3333333344444444"),
                   vec(resp, sizeof(resp)));
    REQUIRE(parsePacket(resp, sizeof(resp), p));
    CHECK_EQ(211, static_cast<int>(p.payload_type));
    CHECK_EQ(0x0102030405060708ULL, p.originate);
    CHECK_EQ(0x1111111122222222ULL, p.receive);
    CHECK_EQ(0x3333333344444444ULL, p.transmit);

    // In-place response (request aliases output) still echoes the originate.
    uint8_t inplace[kPacketBytes];
    memcpy(inplace, req, sizeof(req));
    REQUIRE(buildResponse(inplace, sizeof(inplace), 1, 2, inplace));
    CHECK_BYTES_EQ(vec(resp + 8, 8), vec(inplace + 8, 8));

    // Validation: length and payload type only (like NtpClock.handleMessage).
    CHECK(!parsePacket(req, 31, p));
    CHECK(!parsePacket(NULL, 32, p));
    uint8_t bad[kPacketBytes];
    memcpy(bad, req, sizeof(bad));
    bad[1] = 200;
    CHECK(!parsePacket(bad, sizeof(bad), p));
    uint8_t longer[40];
    memset(longer, 0, sizeof(longer));
    memcpy(longer, resp, sizeof(resp));
    longer[2] = 0;
    longer[3] = 0;  // u16 length field not checked
    CHECK(parsePacket(longer, sizeof(longer), p));
    CHECK(!buildResponse(req, 31, 1, 2, resp));
}

TEST_CASE(nanosNtpConversions) {
    CHECK_EQ(0ULL, ntpFromNanos(0));
    CHECK_EQ(0x100000000ULL, ntpFromNanos(1000000000LL));
    CHECK_EQ(0x80000000ULL, ntpFromNanos(500000000LL));
    CHECK_EQ(0x4ULL, ntpFromNanos(1));  // floor(2^32 / 1e9) = 4
    // Negative values use floorDiv/floorMod and wrap to 64 bits.
    CHECK_EQ(0xFFFFFFFFFFFFFFFBULL, ntpFromNanos(-1));
    CHECK_EQ(0xFFFFFFFF00000000ULL, ntpFromNanos(-1000000000LL));
    CHECK_EQ(0xFFFFFFFF80000000ULL, ntpFromNanos(-500000000LL));

    CHECK_EQ(500000000LL, nanosFromNtp(0x80000000ULL));
    CHECK_EQ(0LL, nanosFromNtp(1));
    CHECK_EQ(999999999LL, nanosFromNtp(0xFFFFFFFFULL));
    CHECK_EQ(1000000000LL, nanosFromNtp(0x100000000ULL));
    CHECK_EQ(4294967295999999999LL, nanosFromNtp(0xFFFFFFFFFFFFFFFFULL));
    const int64_t samples[] = {1LL, 1234567891LL, 999999999LL, kBase + 123456789LL};
    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i) {
        const int64_t back = nanosFromNtp(ntpFromNanos(samples[i]));
        CHECK(back <= samples[i] && back >= samples[i] - 1);
    }

    CHECK_EQ(0x83AA7E8000000000ULL, ntpFromUnixNanos(0));
    CHECK_EQ(2208988800LL * 1000000000LL - 1000LL, wallClockNtpOffsetNs(0x83AA7E8000000000ULL, 1000));

    CHECK_EQ(1LL, ntpDiff(0, 0xFFFFFFFFFFFFFFFFULL));
    CHECK_EQ(-1LL, ntpDiff(0xFFFFFFFFFFFFFFFFULL, 0));
    CHECK(ntpDiff(0x8000000000000000ULL, 0) == std::numeric_limits<int64_t>::min());
    CHECK_EQ(0x7FFFFFFFFFFFFFFFLL, ntpDiff(0x7FFFFFFFFFFFFFFFULL, 0));
    CHECK(ntpDeltaToSeconds(0x180000000LL) == 1.5);
}

TEST_CASE(clockSyncAnswersPeerRequests) {
    ClockSync cs(kBase);
    uint8_t req[kPacketBytes];
    buildRequest(0xAABBCCDD11223344ULL, req);
    uint8_t out[kPacketBytes];
    bool has = false;
    CHECK_EQ(static_cast<int>(ClockSync::kRepliedToRequest),
             static_cast<int>(cs.onPacket(req, sizeof(req), 5000000000LL, out, has)));
    CHECK(has);
    Packet p;
    REQUIRE(parsePacket(out, sizeof(out), p));
    CHECK_EQ(211, static_cast<int>(p.payload_type));
    CHECK_EQ(0xAABBCCDD11223344ULL, p.originate);
    CHECK_EQ(cs.syncedNtp(5000000000LL), p.receive);
    CHECK_EQ(cs.syncedNtp(5000000000LL), p.transmit);
    CHECK_EQ(0x07, static_cast<int>(out[3]));
    CHECK(!cs.synced());  // answering does not touch our clock

    // Garbage is ignored.
    CHECK_EQ(static_cast<int>(ClockSync::kIgnored), static_cast<int>(cs.onPacket(req, 20, 0, out, has)));
    CHECK(!has);
}

TEST_CASE(clockSyncConvergesStepThenSlew) {
    ClockSync cs(kBase);
    CHECK(!cs.synced());
    CHECK_EQ(ntpFromNanos(kBase + 7), cs.syncedNtp(7));
    int64_t mono = 10000000000LL;
    const int64_t phone = kBase + 3500000000LL;  // phone clock 3.5 s ahead of our wall estimate
    const int64_t d = 2000000;                   // 2 ms each way
    const int64_t proc = 100000;                 // 0.1 ms in the phone

    CHECK_EQ(static_cast<int>(ClockSync::kPicking), static_cast<int>(exchange(cs, mono, phone, d, proc)));
    CHECK(!cs.synced());
    CHECK_EQ(kBase, cs.offsetNs());
    CHECK(cs.lastRttSec() > 0.0039 && cs.lastRttSec() < 0.0041);
    CHECK(cs.lastOffsetSec() > 3.4999 && cs.lastOffsetSec() < 3.5001);

    CHECK_EQ(static_cast<int>(ClockSync::kStepped), static_cast<int>(exchange(cs, mono, phone, d, proc)));
    CHECK(cs.synced());
    CHECK(absDiff(cs.offsetNs(), phone) <= 2);
    CHECK(!cs.hasPendingRequest());

    // Converged: further exchanges slew by ~0.
    CHECK_EQ(static_cast<int>(ClockSync::kPicking), static_cast<int>(exchange(cs, mono, phone, d, proc)));
    CHECK_EQ(static_cast<int>(ClockSync::kSlewed), static_cast<int>(exchange(cs, mono, phone, d, proc)));
    CHECK(absDiff(cs.offsetNs(), phone) <= 2);

    // Phone drifts +40 ms (< 128 ms): slew by 1/8 per applied pair.
    const int64_t before = cs.offsetNs();
    const int64_t phone2 = phone + 40000000LL;
    exchange(cs, mono, phone2, d, proc);
    CHECK_EQ(static_cast<int>(ClockSync::kSlewed), static_cast<int>(exchange(cs, mono, phone2, d, proc)));
    CHECK(absDiff(cs.offsetNs() - before, 5000000LL) <= 2);
    CHECK(absDiff(cs.lastAppliedNs(), 5000000LL) <= 2);

    // Repeated slewing converges geometrically toward the new offset.
    // The delay window rejects a sample whose RTT exceeds any of the last 8 by even one NTP
    // unit (floor quantization), so the path delay shrinks by 1 us per exchange here to make
    // every pair eligible. 60 applied pairs: 35 ms * (7/8)^60 ~ 0.01 ms.
    for (int i = 0; i < 120; ++i) {
        CHECK(exchange(cs, mono, phone2, d - 1000 * (i + 1), proc) != ClockSync::kWindowRejected);
    }
    CHECK(absDiff(cs.offsetNs(), phone2) < 100000);  // < 0.1 ms
}

TEST_CASE(clockSyncIgnoresMismatchedAndUnsolicitedResponses) {
    ClockSync cs(kBase);
    int64_t mono = 1000;
    uint8_t out[kPacketBytes];
    bool has = false;

    // No pending request.
    uint8_t fake_req[kPacketBytes];
    buildRequest(cs.syncedNtp(mono), fake_req);
    uint8_t resp[kPacketBytes];
    buildResponse(fake_req, sizeof(fake_req), 1, 1, resp);
    CHECK_EQ(static_cast<int>(ClockSync::kIgnored), static_cast<int>(cs.onPacket(resp, sizeof(resp), mono, out, has)));

    // Pending, but originate does not match t1.
    uint8_t req[kPacketBytes];
    cs.makeRequest(mono, req);
    CHECK(cs.hasPendingRequest());
    uint8_t other[kPacketBytes];
    memcpy(other, req, sizeof(other));
    other[31] ^= 0x01;
    buildResponse(other, sizeof(other), 5, 5, resp);
    CHECK_EQ(static_cast<int>(ClockSync::kIgnored), static_cast<int>(cs.onPacket(resp, sizeof(resp), mono, out, has)));
    CHECK(cs.hasPendingRequest());  // still waiting for the real one
    CHECK(!cs.synced());

    // The real response is still accepted afterwards; a replay of it is not.
    const uint64_t t1 = readNtp64(req + kTransmitOffset);
    buildResponse(req, sizeof(req), t1 + 10, t1 + 20, resp);
    CHECK_EQ(static_cast<int>(ClockSync::kPicking),
             static_cast<int>(cs.onPacket(resp, sizeof(resp), mono + 100, out, has)));
    CHECK(!cs.hasPendingRequest());
    CHECK_EQ(static_cast<int>(ClockSync::kIgnored),
             static_cast<int>(cs.onPacket(resp, sizeof(resp), mono + 100, out, has)));
}

TEST_CASE(clockSyncRejectsNegativeRtt) {
    ClockSync cs(kBase);
    int64_t mono = 50000000000LL;
    const int64_t phone = kBase + 3500000000LL;
    // Phone claims 10 ms processing while our round trip is 1 ms -> rtt < 0.
    uint8_t req[kPacketBytes];
    cs.makeRequest(mono, req);
    uint8_t resp[kPacketBytes];
    buildResponse(req, sizeof(req), ntpFromNanos(mono + phone), ntpFromNanos(mono + 10000000LL + phone), resp);
    uint8_t out[kPacketBytes];
    bool has = false;
    CHECK_EQ(static_cast<int>(ClockSync::kRejectedNegativeRtt),
             static_cast<int>(cs.onPacket(resp, sizeof(resp), mono + 1000000LL, out, has)));
    CHECK(cs.lastRttSec() < 0.0);
    CHECK(!cs.synced());
    CHECK_EQ(kBase, cs.offsetNs());
    // The rejected sample did not consume a pick slot: two good samples are still needed.
    mono += 1000000000LL;
    CHECK_EQ(static_cast<int>(ClockSync::kPicking), static_cast<int>(exchange(cs, mono, phone, 1000000, 0)));
    CHECK_EQ(static_cast<int>(ClockSync::kStepped), static_cast<int>(exchange(cs, mono, phone, 1000000, 0)));
    CHECK(absDiff(cs.offsetNs(), phone) <= 2);
}

TEST_CASE(clockSyncPicksLowestRttOfPair) {
    ClockSync cs(kBase);
    int64_t mono = 1000000000LL;
    const int64_t phone = kBase + 1000000000LL;
    // First sample: asymmetric (biased) path with large RTT; second: clean symmetric low RTT.
    uint8_t req[kPacketBytes];
    cs.makeRequest(mono, req);
    uint8_t resp[kPacketBytes];
    buildResponse(req, sizeof(req), ntpFromNanos(mono + 30000000LL + phone), ntpFromNanos(mono + 30000000LL + phone),
                  resp);
    uint8_t out[kPacketBytes];
    bool has = false;
    CHECK_EQ(static_cast<int>(ClockSync::kPicking),
             static_cast<int>(cs.onPacket(resp, sizeof(resp), mono + 32000000LL, out, has)));
    mono += 1000000000LL;
    CHECK_EQ(static_cast<int>(ClockSync::kStepped), static_cast<int>(exchange(cs, mono, phone, 1000000, 0)));
    CHECK(absDiff(cs.offsetNs(), phone) <= 2);  // the biased (+14 ms) sample was not chosen
}

TEST_CASE(clockSyncDelayWindowHoldsBackHighRttSample) {
    ClockSync cs(kBase);
    int64_t mono = 1000000000LL;
    const int64_t phone = kBase + 2000000000LL;
    exchange(cs, mono, phone, 1000000, 0);
    CHECK_EQ(static_cast<int>(ClockSync::kStepped), static_cast<int>(exchange(cs, mono, phone, 1000000, 0)));
    // Window reset by the step; a low-RTT pair (2 ms) is accepted and seeds the window.
    exchange(cs, mono, phone, 1000000, 0);
    CHECK_EQ(static_cast<int>(ClockSync::kSlewed), static_cast<int>(exchange(cs, mono, phone, 1000000, 0)));
    const int64_t held = cs.offsetNs();

    // Phone offset moves +50 ms, but measured over a 40 ms RTT path: not applied.
    const int64_t moved = phone + 50000000LL;
    exchange(cs, mono, moved, 20000000, 0);
    CHECK_EQ(static_cast<int>(ClockSync::kWindowRejected), static_cast<int>(exchange(cs, mono, moved, 20000000, 0)));
    CHECK_EQ(held, cs.offsetNs());

    // Same move measured over the low-RTT path again: applied (slewed 1/8 of 50 ms).
    exchange(cs, mono, moved, 1000000, 0);
    CHECK_EQ(static_cast<int>(ClockSync::kSlewed), static_cast<int>(exchange(cs, mono, moved, 1000000, 0)));
    CHECK(absDiff(cs.offsetNs() - held, 6250000LL) <= 2);
}

TEST_CASE(clockSyncLargeJumpResteps) {
    ClockSync cs(kBase);
    int64_t mono = 1000000000LL;
    const int64_t phone = kBase - 7000000000LL;  // negative offset this time
    exchange(cs, mono, phone, 1500000, 50000);
    CHECK_EQ(static_cast<int>(ClockSync::kStepped), static_cast<int>(exchange(cs, mono, phone, 1500000, 50000)));
    CHECK(absDiff(cs.offsetNs(), phone) <= 2);
    // Jump of +1 s (> 0.128 s) re-steps in full even after sync.
    const int64_t jumped = phone + 1000000000LL;
    exchange(cs, mono, jumped, 1500000, 50000);
    CHECK_EQ(static_cast<int>(ClockSync::kStepped), static_cast<int>(exchange(cs, mono, jumped, 1500000, 50000)));
    CHECK(absDiff(cs.offsetNs(), jumped) <= 2);
    // Just above the threshold (-130 ms) also steps.
    const int64_t small_jump = jumped - 130000000LL;
    exchange(cs, mono, small_jump, 1500000, 50000);
    CHECK_EQ(static_cast<int>(ClockSync::kStepped),
             static_cast<int>(exchange(cs, mono, small_jump, 1500000, 50000)));
    CHECK(absDiff(cs.offsetNs(), small_jump) <= 2);
}

// NtpClockPeerTest.thePhonesResponseStillMovesTheClock: the phone answers with
// receive = transmit = t1 + (3600 << 32); after two responses the clock is > 3000 s ahead.
TEST_CASE(clockSyncFollowsSkewedPeerLikeReferenceTest) {
    const uint64_t kSkew = 3600ULL << 32;
    ClockSync cs(kBase);
    int64_t mono = 123456789LL;
    for (int i = 0; i < 2; ++i) {
        uint8_t req[kPacketBytes];
        cs.makeRequest(mono, req);
        const uint64_t t1 = readNtp64(req + kTransmitOffset);
        uint8_t resp[kPacketBytes];
        memset(resp, 0, sizeof(resp));
        resp[0] = 0x80;
        resp[1] = 211;  // the reference test leaves the u16 at offset 2 as zero
        writeNtp64(resp + kOriginateOffset, t1);
        writeNtp64(resp + kReceiveOffset, t1 + kSkew);
        writeNtp64(resp + kTransmitOffset, t1 + kSkew);
        uint8_t out[kPacketBytes];
        bool has = false;
        const ClockSync::Outcome o = cs.onPacket(resp, sizeof(resp), mono + 300000LL, out, has);
        CHECK_EQ(static_cast<int>(i == 0 ? ClockSync::kPicking : ClockSync::kStepped), static_cast<int>(o));
        mono += 1000000000LL;
    }
    const int64_t drift_sec = (cs.offsetNs() - kBase) / 1000000000LL;
    CHECK(drift_sec > 3000);
    CHECK(absDiff(cs.offsetNs() - kBase, 3600000000000LL - 150000LL) <= 2);  // 3600 s - rtt/2
}

int main() { return test_support::runAll("test_ntp_timing"); }
