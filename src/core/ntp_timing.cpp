// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/airplay/NtpClock.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.

#include "carplay/ntp_timing.hpp"

#include <math.h>
#include <string.h>

#include <limits>

namespace carplay {
namespace ntp {

void writeNtp64(uint8_t* out, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out[i] = static_cast<uint8_t>(value >> (8 * (7 - i)));
    }
}

uint64_t readNtp64(const uint8_t* in) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | in[i];
    }
    return v;
}

namespace {

void writeHeader(uint8_t out[kPacketBytes], uint8_t pt) {
    memset(out, 0, kPacketBytes);
    out[0] = 0x80U;
    out[1] = pt;
    out[2] = 0x00U;  // u16 BE 7
    out[3] = 0x07U;
}

}  // namespace

void buildRequest(uint64_t t1, uint8_t out[kPacketBytes]) {
    writeHeader(out, kPtRequest);
    writeNtp64(out + kTransmitOffset, t1);
}

bool parsePacket(const uint8_t* data, size_t len, Packet& out) {
    if (data == NULL || len < kPacketBytes) {
        return false;
    }
    if (data[1] != kPtRequest && data[1] != kPtResponse) {
        return false;
    }
    out.payload_type = data[1];
    out.originate = readNtp64(data + kOriginateOffset);
    out.receive = readNtp64(data + kReceiveOffset);
    out.transmit = readNtp64(data + kTransmitOffset);
    return true;
}

bool buildResponse(const uint8_t* request,
                   size_t request_len,
                   uint64_t receive,
                   uint64_t transmit,
                   uint8_t out[kPacketBytes]) {
    if (request == NULL || request_len < kPacketBytes) {
        return false;
    }
    uint8_t originate[8];
    memcpy(originate, request + kTransmitOffset, 8);  // request may alias out
    writeHeader(out, kPtResponse);
    memcpy(out + kOriginateOffset, originate, 8);
    writeNtp64(out + kReceiveOffset, receive);
    writeNtp64(out + kTransmitOffset, transmit);
    return true;
}

uint64_t ntpFromNanos(int64_t ns) {
    int64_t sec = ns / kNanosPerSecond;
    int64_t rem = ns % kNanosPerSecond;
    if (rem < 0) {  // floorDiv / floorMod
        rem += kNanosPerSecond;
        --sec;
    }
    const uint64_t frac = (static_cast<uint64_t>(rem) << 32) / static_cast<uint64_t>(kNanosPerSecond);
    return (static_cast<uint64_t>(sec) << 32) | frac;
}

int64_t nanosFromNtp(uint64_t ntp64) {
    const uint64_t sec = ntp64 >> 32;
    const uint64_t frac = ntp64 & 0xffffffffULL;
    const uint64_t ns = sec * static_cast<uint64_t>(kNanosPerSecond) +
                        ((frac * static_cast<uint64_t>(kNanosPerSecond)) >> 32);
    return static_cast<int64_t>(ns);
}

uint64_t ntpFromUnixNanos(int64_t unix_ns) {
    return ntpFromNanos(unix_ns + static_cast<int64_t>(kNtpUnixEpochOffsetSec) * kNanosPerSecond);
}

int64_t wallClockNtpOffsetNs(uint64_t wall_ntp64, int64_t mono_ns) {
    return nanosFromNtp(wall_ntp64) - mono_ns;
}

int64_t ntpDiff(uint64_t a, uint64_t b) {
    const uint64_t d = a - b;
    if (d <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        return static_cast<int64_t>(d);
    }
    return -static_cast<int64_t>(~d) - 1;
}

double ntpDeltaToSeconds(int64_t delta) {
    return static_cast<double>(delta) / 4294967296.0;
}

// ---------------------------------------------------------------------------------------------
// ClockSync
// ---------------------------------------------------------------------------------------------

ClockSync::ClockSync(int64_t initial_offset_ns)
    : offset_ns_(initial_offset_ns),
      delay_index_(0),
      pick_count_(kPickCount),
      pick_rtt_(std::numeric_limits<double>::infinity()),
      pick_offset_(0.0),
      pending_t1_(0),
      has_pending_(false),
      synced_(false),
      last_offset_sec_(0.0),
      last_rtt_sec_(0.0),
      last_applied_ns_(0) {
    resetWindow();
}

void ClockSync::resetWindow() {
    for (int i = 0; i < kDelayWindow; ++i) {
        delays_[i] = std::numeric_limits<double>::infinity();
    }
    delay_index_ = 0;
}

uint64_t ClockSync::syncedNtp(int64_t mono_ns) const {
    return ntpFromNanos(mono_ns + offset_ns_);
}

void ClockSync::makeRequest(int64_t mono_ns, uint8_t out[kPacketBytes]) {
    const uint64_t t1 = syncedNtp(mono_ns);
    pending_t1_ = t1;
    has_pending_ = true;
    buildRequest(t1, out);
}

ClockSync::Outcome ClockSync::onPacket(const uint8_t* data,
                                       size_t len,
                                       int64_t mono_ns,
                                       uint8_t response_out[kPacketBytes],
                                       bool& has_response) {
    has_response = false;
    Packet p;
    if (!parsePacket(data, len, p)) {
        return kIgnored;
    }
    if (p.payload_type == kPtRequest) {
        // NtpClock.respondToRequest: originate = request transmit, receive/transmit = now.
        const uint64_t now = syncedNtp(mono_ns);
        if (response_out == NULL || !buildResponse(data, len, now, now, response_out)) {
            return kIgnored;
        }
        has_response = true;
        return kRepliedToRequest;
    }

    // NtpClock.handleResponse.
    const uint64_t t4 = syncedNtp(mono_ns);
    const uint64_t t1 = p.originate;
    const uint64_t t2 = p.receive;
    const uint64_t t3 = p.transmit;
    if (!has_pending_ || pending_t1_ != t1) {
        return kIgnored;
    }
    has_pending_ = false;

    // offset = ((t2 - t1) + (t3 - t4)) / 2 ; rtt = (t4 - t1) - (t3 - t2), in seconds.
    // The reference sums exact BigIntegers then converts to double; here each signed 64-bit
    // difference is converted first (sub-nanosecond rounding difference only).
    const double offset = (static_cast<double>(ntpDiff(t2, t1)) + static_cast<double>(ntpDiff(t3, t4))) *
                          0.5 / 4294967296.0;
    const double rtt = (static_cast<double>(ntpDiff(t4, t1)) - static_cast<double>(ntpDiff(t3, t2))) /
                       4294967296.0;
    last_offset_sec_ = offset;
    last_rtt_sec_ = rtt;
    if (rtt < 0.0) {
        return kRejectedNegativeRtt;
    }

    if (rtt < pick_rtt_) {
        pick_rtt_ = rtt;
        pick_offset_ = offset;
    }
    if (--pick_count_ > 0) {
        return kPicking;
    }

    const double selected_rtt = pick_rtt_;
    const double selected_offset = pick_offset_;
    pick_count_ = kPickCount;
    pick_rtt_ = std::numeric_limits<double>::infinity();

    bool use_sample = true;
    for (int i = 0; i < kDelayWindow; ++i) {
        if (!(selected_rtt <= delays_[i])) {
            use_sample = false;
            break;
        }
    }
    delays_[delay_index_] = selected_rtt;
    delay_index_ = (delay_index_ + 1) % kDelayWindow;
    if (!use_sample) {
        return kWindowRejected;
    }
    Outcome outcome = kSlewed;
    applyOffset(selected_offset, outcome);
    return outcome;
}

void ClockSync::applyOffset(double offset_sec, Outcome& outcome) {
    const bool stepping = !synced_ || fabs(offset_sec) > kStepThresholdSec;
    const double applied = stepping ? offset_sec : offset_sec * kSlewGain;
    // Math.round(x) == floor(x + 0.5)
    const int64_t delta = static_cast<int64_t>(floor(applied * 1e9 + 0.5));
    offset_ns_ += delta;
    last_applied_ns_ = delta;
    if (stepping) {
        resetWindow();
        has_pending_ = false;
        synced_ = true;
        outcome = kStepped;
    } else {
        outcome = kSlewed;
    }
}

}  // namespace ntp
}  // namespace carplay
