#ifndef CARPLAY_NTP_TIMING_HPP
#define CARPLAY_NTP_TIMING_HPP

// CarPlay timing-port clock sync (port of DiPlay NtpClock.kt) without sockets, threads or clocks.
//
// The accessory drives an RTCP-style exchange with the iPhone: PT 210 (request) carries our
// transmit time, PT 211 (response) echoes it as `originate` and adds the peer's receive and
// transmit times. All times are NTP 32.32 (seconds since 1900 | 2^-32 fraction), big-endian.
//
// Time is injected: the caller passes a monotonic nanosecond reading (e.g. CLOCK_MONOTONIC) to
// every call. The synchronized clock is ntpFromNanos(mono_ns + offset_ns).

#include <stddef.h>
#include <stdint.h>

namespace carplay {
namespace ntp {

static const size_t kPacketBytes = 32U;
static const uint8_t kPtRequest = 210U;
static const uint8_t kPtResponse = 211U;
static const size_t kOriginateOffset = 8U;
static const size_t kReceiveOffset = 16U;
static const size_t kTransmitOffset = 24U;
static const uint64_t kNtpUnixEpochOffsetSec = 2208988800ULL;  // 1900 -> 1970
static const int64_t kNanosPerSecond = 1000000000LL;

/// Filter constants (NtpClock.kt companion object).
static const int kPickCount = 2;
static const int kDelayWindow = 8;
static const double kStepThresholdSec = 0.128;
static const double kSlewGain = 1.0 / 8.0;

struct Packet {
    uint8_t payload_type;  // byte 1
    uint64_t originate;    // @8
    uint64_t receive;      // @16
    uint64_t transmit;     // @24

    Packet() : payload_type(0), originate(0), receive(0), transmit(0) {}
};

void writeNtp64(uint8_t* out, uint64_t value);
uint64_t readNtp64(const uint8_t* in);

/// 32-byte request: 0x80, 210, u16 BE 7, zeros, transmit @24 = t1.
void buildRequest(uint64_t t1, uint8_t out[kPacketBytes]);

/// Validates like NtpClock.handleMessage: len >= 32 and byte1 in {210, 211}. Byte 0 and the
/// u16 at offset 2 are not checked (the reference does not check them either).
bool parsePacket(const uint8_t* data, size_t len, Packet& out);

/// 32-byte response: 0x80, 211, u16 BE 7, zeros, originate = request bytes [24..32) verbatim,
/// receive @16, transmit @24. Returns false if `request` is not a valid packet (len < 32).
bool buildResponse(const uint8_t* request,
                   size_t request_len,
                   uint64_t receive,
                   uint64_t transmit,
                   uint8_t out[kPacketBytes]);

/// NtpClock.kt ntpFromNanos: seconds = floorDiv(ns, 1e9), frac = floor(floorMod(ns,1e9) * 2^32 / 1e9),
/// result = (seconds << 32) | frac, truncated to 64 bits (negative ns wraps like the reference's
/// masked BigInteger).
uint64_t ntpFromNanos(int64_t ns);

/// floor(ntp64 * 1e9 / 2^32) — the conversion used by wallClockNtpOffsetNs. Exact, no overflow
/// (max result ~4.29e18 < 2^63).
int64_t nanosFromNtp(uint64_t ntp64);

/// Wall-clock Unix nanoseconds -> NTP64 (adds the 1900->1970 epoch offset).
uint64_t ntpFromUnixNanos(int64_t unix_ns);

/// NtpClock.kt wallClockNtpOffsetNs: nanosFromNtp(wall_ntp64) - mono_ns. Use it to build the
/// ClockSync initial offset from one simultaneous (wall clock, monotonic) reading.
int64_t wallClockNtpOffsetNs(uint64_t wall_ntp64, int64_t mono_ns);

/// a - b as a signed 64-bit value on wrapped NTP64 values (well defined, no UB).
int64_t ntpDiff(uint64_t a, uint64_t b);

/// NTP64 delta -> seconds (double).
double ntpDeltaToSeconds(int64_t delta);

class ClockSync {
public:
    enum Outcome {
        kIgnored = 0,         // too short / unknown payload type / no pending request / t1 mismatch
        kRepliedToRequest,    // PT 210 handled; response_out holds the 211 reply
        kRejectedNegativeRtt, // matching response with rtt < 0
        kPicking,             // sample stored; waiting for the rest of the PICK_COUNT group
        kWindowRejected,      // selected sample's RTT larger than a delay-window entry; not applied
        kStepped,             // offset applied in full (first sync or |offset| > 0.128 s)
        kSlewed               // offset applied * 1/8
    };

    /// initial_offset_ns: wall-clock-NTP nanoseconds minus monotonic nanoseconds, from
    /// wallClockNtpOffsetNs(). The clock starts "not synced".
    explicit ClockSync(int64_t initial_offset_ns);

    /// Now in the synchronized (phone) clock domain.
    uint64_t syncedNtp(int64_t mono_ns) const;

    /// Builds a PT 210 request stamped with syncedNtp(mono_ns) and records it as pending t1.
    void makeRequest(int64_t mono_ns, uint8_t out[kPacketBytes]);

    /// Handles one received timing datagram. PT 210 -> has_response = true and response_out is
    /// the PT 211 reply (receive = transmit = syncedNtp(mono_ns)). PT 211 -> offset/RTT filter.
    ///
    /// NOTE: the reference additionally ignores PT 211 responses whose source address is not
    /// the iPhone's (NtpClockPeerTest.aStrangersResponseCannotMoveTheClock). That check belongs
    /// to the socket layer: only pass PT 211 datagrams from the peer address to this method.
    Outcome onPacket(const uint8_t* data,
                     size_t len,
                     int64_t mono_ns,
                     uint8_t response_out[kPacketBytes],
                     bool& has_response);

    bool synced() const { return synced_; }
    int64_t offsetNs() const { return offset_ns_; }
    bool hasPendingRequest() const { return has_pending_; }

    /// Diagnostics: the most recent matching sample (before pick / window filtering).
    double lastOffsetSec() const { return last_offset_sec_; }
    double lastRttSec() const { return last_rtt_sec_; }
    /// Diagnostics: the most recent adjustment actually added to offsetNs().
    int64_t lastAppliedNs() const { return last_applied_ns_; }

private:
    void applyOffset(double offset_sec, Outcome& outcome);
    void resetWindow();

    int64_t offset_ns_;
    double delays_[kDelayWindow];
    int delay_index_;
    int pick_count_;
    double pick_rtt_;
    double pick_offset_;
    uint64_t pending_t1_;
    bool has_pending_;
    bool synced_;
    double last_offset_sec_;
    double last_rtt_sec_;
    int64_t last_applied_ns_;
};

}  // namespace ntp
}  // namespace carplay

#endif  // CARPLAY_NTP_TIMING_HPP
