// Derived in part from DiPlay-main:
//   shared/src/main/java/com/shilapi/xcertplay/transport/Ntb16Codec.kt
//   shared/src/main/java/com/shilapi/xcertplay/transport/NcmUsbBridge.kt
// GPL-3.0, Copyright (c) DiPlay contributors.

#include "carplay/cdc_ncm.hpp"

#include <cstring>
#include <sstream>

namespace carplay {
namespace ncm {

namespace {

static const size_t kMaxNdpChainDepth = 64U;

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

void writeU16Le(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v & 0xffU);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xffU);
}

void writeU32Le(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xffU);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xffU);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xffU);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xffU);
}

bool isPowerOfTwoInRange(uint16_t v, uint16_t min_v, uint16_t max_v) {
    return v >= min_v && v <= max_v && (v & (v - 1U)) == 0U;
}

uint32_t alignUp(uint32_t pos, uint32_t alignment) {
    if (alignment <= 1U) {
        return pos;
    }
    const uint32_t mask = alignment - 1U;
    return (pos + mask) & ~mask;
}

uint32_t alignDivRem(uint32_t pos, uint32_t divisor, uint32_t remainder) {
    if (divisor <= 1U) {
        return pos;
    }
    const uint32_t cur = pos % divisor;
    if (cur == remainder) {
        return pos;
    }
    const uint32_t delta = (remainder >= cur) ? (remainder - cur) : (divisor - cur + remainder);
    return pos + delta;
}

struct Range {
    uint32_t start;
    uint32_t end;
};

bool rangesOverlap(uint32_t a_start, uint32_t a_end, uint32_t b_start, uint32_t b_end) {
    return a_start < b_end && b_start < a_end;
}

}  // namespace

bool NtbParameters::validate(std::string* error_out) const {
    if (length != kNtbParametersBytes) {
        setError(error_out, "NTB parameters wLength must be 28");
        return false;
    }
    if ((formats_supported & 0x0001U) == 0U) {
        setError(error_out, "device does not support NTB-16 format");
        return false;
    }
    if (ntb_in_max_size < 2048U) {
        setError(error_out, "dwNtbInMaxSize must be >= 2048");
        return false;
    }
    if (ntb_out_max_size < 2048U) {
        setError(error_out, "dwNtbOutMaxSize must be >= 2048");
        return false;
    }
    if (!isPowerOfTwoInRange(ndp_in_divisor, 1U, 32768U) ||
        ndp_in_payload_remainder >= ndp_in_divisor) {
        setError(error_out, "invalid wNdpInDivisor / wNdpInPayloadRemainder");
        return false;
    }
    if (!isPowerOfTwoInRange(ndp_in_alignment, 4U, 32768U)) {
        setError(error_out, "invalid wNdpInAlignment");
        return false;
    }
    if (!isPowerOfTwoInRange(ndp_out_divisor, 1U, 32768U) ||
        ndp_out_payload_remainder >= ndp_out_divisor) {
        setError(error_out, "invalid wNdpOutDivisor / wNdpOutPayloadRemainder");
        return false;
    }
    if (!isPowerOfTwoInRange(ndp_out_alignment, 4U, 32768U)) {
        setError(error_out, "invalid wNdpOutAlignment");
        return false;
    }
    return true;
}

NtbParseOptions NtbParseOptions::fromParameters(const NtbParameters& p, bool strict_alignment) {
    NtbParseOptions opts;
    opts.max_ntb_size =
        p.ntb_in_max_size > kMaxNtb16BlockSize ? kMaxNtb16BlockSize : p.ntb_in_max_size;
    opts.check_in_alignment = strict_alignment;
    opts.ndp_in_divisor = p.ndp_in_divisor;
    opts.ndp_in_payload_remainder = p.ndp_in_payload_remainder;
    opts.ndp_in_alignment = p.ndp_in_alignment;
    return opts;
}

NtbBuildOptions NtbBuildOptions::fromParameters(const NtbParameters& p) {
    NtbBuildOptions opts;
    opts.max_ntb_size =
        p.ntb_out_max_size > kMaxNtb16BlockSize ? kMaxNtb16BlockSize : p.ntb_out_max_size;
    opts.ndp_alignment = p.ndp_out_alignment;
    opts.ndp_divisor = p.ndp_out_divisor;
    opts.ndp_payload_remainder = p.ndp_out_payload_remainder;
    opts.max_datagrams = p.ntb_out_max_datagrams;
    return opts;
}

bool parseNtbParameters(const uint8_t* data,
                        size_t len,
                        NtbParameters& out,
                        std::string* error_out) {
    out = NtbParameters();
    if (data == NULL || len < kNtbParametersBytes) {
        setError(error_out, "GET_NTB_PARAMETERS response truncated (< 28 bytes)");
        return false;
    }
    out.length = readU16Le(data + 0);
    out.formats_supported = readU16Le(data + 2);
    out.ntb_in_max_size = readU32Le(data + 4);
    out.ndp_in_divisor = readU16Le(data + 8);
    out.ndp_in_payload_remainder = readU16Le(data + 10);
    out.ndp_in_alignment = readU16Le(data + 12);
    // bytes [14..15] reserved
    out.ntb_out_max_size = readU32Le(data + 16);
    out.ndp_out_divisor = readU16Le(data + 20);
    out.ndp_out_payload_remainder = readU16Le(data + 22);
    out.ndp_out_alignment = readU16Le(data + 24);
    out.ntb_out_max_datagrams = readU16Le(data + 26);
    return out.validate(error_out);
}

void encodeNtbParameters(const NtbParameters& params, std::vector<uint8_t>& out) {
    out.assign(kNtbParametersBytes, 0U);
    writeU16Le(&out[0], params.length);
    writeU16Le(&out[2], params.formats_supported);
    writeU32Le(&out[4], params.ntb_in_max_size);
    writeU16Le(&out[8], params.ndp_in_divisor);
    writeU16Le(&out[10], params.ndp_in_payload_remainder);
    writeU16Le(&out[12], params.ndp_in_alignment);
    writeU16Le(&out[14], 0U);
    writeU32Le(&out[16], params.ntb_out_max_size);
    writeU16Le(&out[20], params.ndp_out_divisor);
    writeU16Le(&out[22], params.ndp_out_payload_remainder);
    writeU16Le(&out[24], params.ndp_out_alignment);
    writeU16Le(&out[26], params.ntb_out_max_datagrams);
}

void encodeSetNtbInputSize(uint32_t ntb_in_max_size, std::vector<uint8_t>& out) {
    out.resize(4U);
    writeU32Le(&out[0], ntb_in_max_size);
}

uint32_t crc32Ieee8023(const uint8_t* data, size_t len) {
    uint32_t crc = 0xffffffffU;
    for (size_t i = 0; i < len; ++i) {
        crc ^= static_cast<uint32_t>(data[i]);
        for (int b = 0; b < 8; ++b) {
            const uint32_t mask = (crc & 1U) != 0U ? 0xedb88320U : 0U;
            crc = (crc >> 1) ^ mask;
        }
    }
    return crc ^ 0xffffffffU;
}

bool parseNtb16(const uint8_t* data,
                size_t len,
                const NtbParseOptions& opts,
                Ntb16Frame& out,
                std::string* error_out) {
    out = Ntb16Frame();
    if (data == NULL || len < kNth16Bytes) {
        setError(error_out, "NTB-16 buffer shorter than 12-byte NTH16 header");
        return false;
    }

    const uint32_t sig = readU32Le(data + 0);
    if (sig != kNth16Signature) {
        setError(error_out, "invalid NTH16 signature");
        return false;
    }
    const uint16_t hdr_len = readU16Le(data + 4);
    if (hdr_len != kNth16Bytes) {
        setError(error_out, "invalid NTH16 wHeaderLength");
        return false;
    }
    const uint16_t seq = readU16Le(data + 6);
    const uint16_t block_len = readU16Le(data + 8);
    const uint16_t first_ndp = readU16Le(data + 10);

    if (block_len < kNth16Bytes + kNdp16MinBytes) {
        setError(error_out, "NTB-16 wBlockLength too small");
        return false;
    }
    if (static_cast<size_t>(block_len) > len) {
        setError(error_out, "NTB-16 truncated (wBlockLength > buffer len)");
        return false;
    }
    if (opts.max_ntb_size > 0U && block_len > opts.max_ntb_size) {
        setError(error_out, "NTB-16 wBlockLength exceeds max_ntb_size");
        return false;
    }
    if (first_ndp < kNth16Bytes) {
        setError(error_out, "NTH16 wNdpIndex overlaps header or is zero");
        return false;
    }

    const uint16_t ndp_align =
        (opts.check_in_alignment && opts.ndp_in_alignment >= 4U) ? opts.ndp_in_alignment : 4U;

    std::vector<Range> ndp_ranges;
    struct PendingDatagram {
        uint32_t offset;
        uint32_t length;
        bool has_crc;
    };
    std::vector<PendingDatagram> pending;
    uint32_t total_datagram_bytes = 0U;

    uint16_t ndp_off = first_ndp;
    for (size_t depth = 0; ndp_off != 0U; ++depth) {
        if (depth >= kMaxNdpChainDepth) {
            setError(error_out, "NDP16 chain exceeds maximum depth");
            return false;
        }
        if (ndp_off < kNth16Bytes || (ndp_off % ndp_align) != 0U) {
            setError(error_out, "NDP16 offset misaligned or inside NTH16");
            return false;
        }
        if (static_cast<uint32_t>(ndp_off) + kNdp16MinBytes > block_len) {
            setError(error_out, "NDP16 header out of NTB bounds");
            return false;
        }

        const uint32_t ndp_sig = readU32Le(data + ndp_off + 0);
        if (ndp_sig != kNdp16SignatureNoCrc && ndp_sig != kNdp16SignatureCrc) {
            setError(error_out, "invalid NDP16 signature");
            return false;
        }
        const uint16_t ndp_len = readU16Le(data + ndp_off + 4);
        const uint16_t next_ndp = readU16Le(data + ndp_off + 6);
        if (ndp_len < kNdp16MinBytes || (ndp_len % 4U) != 0U) {
            setError(error_out, "invalid NDP16 wLength");
            return false;
        }
        const uint32_t ndp_end = static_cast<uint32_t>(ndp_off) + ndp_len;
        if (ndp_end > block_len) {
            setError(error_out, "NDP16 extends past wBlockLength");
            return false;
        }
        for (size_t r = 0; r < ndp_ranges.size(); ++r) {
            if (rangesOverlap(ndp_off, ndp_end, ndp_ranges[r].start, ndp_ranges[r].end)) {
                setError(error_out, "NDP16 chain contains cycle or overlapping tables");
                return false;
            }
        }
        Range this_range;
        this_range.start = ndp_off;
        this_range.end = ndp_end;
        ndp_ranges.push_back(this_range);

        const bool has_crc = (ndp_sig == kNdp16SignatureCrc);
        bool saw_terminator = false;
        for (uint32_t entry_off = kNdp16HeaderBytes; entry_off + kNdp16EntryBytes <= ndp_len;
             entry_off += kNdp16EntryBytes) {
            const uint16_t dg_idx = readU16Le(data + ndp_off + entry_off);
            const uint16_t dg_len = readU16Le(data + ndp_off + entry_off + 2U);
            if (dg_idx == 0U && dg_len == 0U) {
                saw_terminator = true;
                break;
            }
            if (dg_idx == 0U || dg_len == 0U) {
                setError(error_out, "malformed half-zero NDP16 datagram pointer");
                return false;
            }
            if (opts.max_datagrams > 0U && pending.size() >= opts.max_datagrams) {
                setError(error_out, "NDP16 datagram count exceeds max_datagrams");
                return false;
            }
            if (dg_idx < kNth16Bytes) {
                setError(error_out, "NDP16 datagram index points inside NTH16");
                return false;
            }
            const uint32_t dg_end = static_cast<uint32_t>(dg_idx) + dg_len;
            if (dg_end > block_len) {
                setError(error_out, "NDP16 datagram extends past wBlockLength");
                return false;
            }
            if (total_datagram_bytes + dg_len > block_len) {
                setError(error_out, "NDP16 datagrams overlap or exceed wBlockLength");
                return false;
            }
            total_datagram_bytes += dg_len;
            if (opts.check_in_alignment && opts.ndp_in_divisor > 1U) {
                if ((dg_idx % opts.ndp_in_divisor) != opts.ndp_in_payload_remainder) {
                    setError(error_out, "NDP16 datagram index violates wNdpInDivisor/Remainder");
                    return false;
                }
            }
            if (has_crc && dg_len <= 4U) {
                setError(error_out, "NCM1 datagram too short for 4-byte CRC-32");
                return false;
            }
            PendingDatagram pd;
            pd.offset = dg_idx;
            pd.length = dg_len;
            pd.has_crc = has_crc;
            pending.push_back(pd);
        }
        if (!saw_terminator) {
            setError(error_out, "NDP16 missing terminating {0, 0} entry");
            return false;
        }
        ndp_off = next_ndp;
    }

    // Verify no datagram overlaps any NDP16 table in the chain, and verify CRC-32 if NCM1.
    out.sequence = seq;
    out.block_length = block_len;
    out.datagrams.reserve(pending.size());
    for (size_t i = 0; i < pending.size(); ++i) {
        const PendingDatagram& pd = pending[i];
        const uint32_t dg_end = pd.offset + pd.length;
        for (size_t j = 0; j < i; ++j) {
            const PendingDatagram& other = pending[j];
            if (rangesOverlap(pd.offset, dg_end, other.offset, other.offset + other.length)) {
                setError(error_out, "NDP16 datagrams overlap each other");
                out = Ntb16Frame();
                return false;
            }
        }
        for (size_t r = 0; r < ndp_ranges.size(); ++r) {
            if (rangesOverlap(pd.offset, dg_end, ndp_ranges[r].start, ndp_ranges[r].end)) {
                setError(error_out, "NDP16 datagram overlaps NDP16 table");
                out = Ntb16Frame();
                return false;
            }
        }
        uint32_t payload_len = pd.length;
        if (pd.has_crc) {
            payload_len -= 4U;
            if (opts.verify_crc32) {
                const uint32_t expected_crc = readU32Le(data + pd.offset + payload_len);
                const uint32_t actual_crc = crc32Ieee8023(data + pd.offset, payload_len);
                if (actual_crc != expected_crc) {
                    setError(error_out, "NCM1 datagram CRC-32 mismatch");
                    out = Ntb16Frame();
                    return false;
                }
            }
        }
        out.datagrams.push_back(
            std::vector<uint8_t>(data + pd.offset, data + pd.offset + payload_len));
    }

    return true;
}

bool packNtb16Batch(const std::vector<std::vector<uint8_t> >& frames,
                    size_t start_index,
                    uint16_t sequence,
                    const NtbBuildOptions& opts,
                    std::vector<uint8_t>& out,
                    size_t& frames_packed_out,
                    std::string* error_out) {
    out.clear();
    frames_packed_out = 0;
    if (start_index >= frames.size()) {
        setError(error_out, "no frames available to pack into NTB-16");
        return false;
    }
    if (!isPowerOfTwoInRange(opts.ndp_alignment, 4U, 32768U)) {
        setError(error_out, "invalid ndp_alignment");
        return false;
    }
    if (!isPowerOfTwoInRange(opts.ndp_divisor, 1U, 32768U) ||
        opts.ndp_payload_remainder >= opts.ndp_divisor) {
        setError(error_out, "invalid ndp_divisor / ndp_payload_remainder");
        return false;
    }
    const uint32_t max_ntb =
        (opts.max_ntb_size == 0U || opts.max_ntb_size > kMaxNtb16BlockSize) ? kMaxNtb16BlockSize
                                                                           : opts.max_ntb_size;
    if (max_ntb < kNth16Bytes + kNdp16MinBytes) {
        setError(error_out, "max_ntb_size too small for NTB-16");
        return false;
    }

    struct PlacedFrame {
        size_t index;
        uint16_t offset;
        uint16_t wire_length;
    };
    std::vector<PlacedFrame> placed;

    // Layout: NTH16 (12B) -> aligned datagrams -> aligned NDP16 at end.
    // Placing NDP16 after the datagrams means adding another datagram never shifts earlier ones.
    uint32_t cursor = static_cast<uint32_t>(kNth16Bytes);
    uint32_t final_ndp_offset = 0;
    uint32_t final_total_size = 0;

    for (size_t i = start_index; i < frames.size(); ++i) {
        if (opts.max_datagrams > 0U && placed.size() >= opts.max_datagrams) {
            break;
        }
        const std::vector<uint8_t>& f = frames[i];
        if (f.empty()) {
            setError(error_out, "cannot pack empty datagram into NTB-16");
            return false;
        }
        const size_t crc_bytes = opts.append_crc32 ? 4U : 0U;
        if (f.size() > static_cast<size_t>(kMaxNtb16BlockSize) - crc_bytes) {
            if (placed.empty()) {
                setError(error_out, "datagram exceeds 16-bit NTB-16 length limit");
                return false;
            }
            break;
        }
        const uint32_t wire_len = static_cast<uint32_t>(f.size() + crc_bytes);
        const uint32_t dg_off =
            alignDivRem(cursor, opts.ndp_divisor, opts.ndp_payload_remainder);
        const uint32_t dg_end = dg_off + wire_len;
        const uint32_t ndp_off = alignUp(dg_end, opts.ndp_alignment);
        const uint32_t next_count = static_cast<uint32_t>(placed.size() + 1U);
        const uint32_t ndp_len = static_cast<uint32_t>(kNdp16HeaderBytes) +
                                 (next_count + 1U) * static_cast<uint32_t>(kNdp16EntryBytes);
        const uint32_t total = ndp_off + ndp_len;
        if (total > max_ntb) {
            if (placed.empty()) {
                std::ostringstream oss;
                oss << "single datagram of " << f.size() << " bytes requires " << total
                    << " bytes NTB, exceeding max_ntb_size=" << max_ntb;
                setError(error_out, oss.str());
                return false;
            }
            break;
        }

        PlacedFrame pf;
        pf.index = i;
        pf.offset = static_cast<uint16_t>(dg_off);
        pf.wire_length = static_cast<uint16_t>(wire_len);
        placed.push_back(pf);
        cursor = dg_end;
        final_ndp_offset = ndp_off;
        final_total_size = total;
    }

    if (placed.empty()) {
        setError(error_out, "no frames packed into NTB-16");
        return false;
    }

    out.assign(final_total_size, 0U);
    // NTH16
    writeU32Le(&out[0], kNth16Signature);
    writeU16Le(&out[4], static_cast<uint16_t>(kNth16Bytes));
    writeU16Le(&out[6], sequence);
    writeU16Le(&out[8], static_cast<uint16_t>(final_total_size));
    writeU16Le(&out[10], static_cast<uint16_t>(final_ndp_offset));

    // Datagrams
    for (size_t i = 0; i < placed.size(); ++i) {
        const PlacedFrame& pf = placed[i];
        const std::vector<uint8_t>& f = frames[pf.index];
        std::memcpy(&out[pf.offset], &f[0], f.size());
        if (opts.append_crc32) {
            const uint32_t crc = crc32Ieee8023(&f[0], f.size());
            writeU32Le(&out[pf.offset + f.size()], crc);
        }
    }

    // NDP16
    const uint32_t ndp_len = static_cast<uint32_t>(kNdp16HeaderBytes) +
                             static_cast<uint32_t>(placed.size() + 1U) *
                                 static_cast<uint32_t>(kNdp16EntryBytes);
    writeU32Le(&out[final_ndp_offset + 0U],
               opts.append_crc32 ? kNdp16SignatureCrc : kNdp16SignatureNoCrc);
    writeU16Le(&out[final_ndp_offset + 4U], static_cast<uint16_t>(ndp_len));
    writeU16Le(&out[final_ndp_offset + 6U], 0U);  // wNextNdpIndex = 0
    for (size_t i = 0; i < placed.size(); ++i) {
        const size_t entry_off = final_ndp_offset + kNdp16HeaderBytes + i * kNdp16EntryBytes;
        writeU16Le(&out[entry_off + 0U], placed[i].offset);
        writeU16Le(&out[entry_off + 2U], placed[i].wire_length);
    }
    // Terminating {0, 0} entry is already zeroed by out.assign().

    frames_packed_out = placed.size();
    return true;
}

bool buildNtb16(const std::vector<std::vector<uint8_t> >& frames,
                uint16_t sequence,
                const NtbBuildOptions& opts,
                std::vector<uint8_t>& out,
                std::string* error_out) {
    size_t packed = 0;
    if (!packNtb16Batch(frames, 0U, sequence, opts, out, packed, error_out)) {
        return false;
    }
    if (packed != frames.size()) {
        out.clear();
        std::ostringstream oss;
        oss << "not all frames fit into one NTB-16 (packed " << packed << " of "
            << frames.size() << ")";
        setError(error_out, oss.str());
        return false;
    }
    return true;
}

Ntb16StreamDecoder::Ntb16StreamDecoder(const NtbParseOptions& opts,
                                       uint16_t usb_packet_size,
                                       size_t max_buffer_bytes)
    : opts_(opts),
      usb_packet_size_(usb_packet_size > 0U ? usb_packet_size : 512U),
      max_buffer_bytes_(max_buffer_bytes >= kNth16Bytes ? max_buffer_bytes : 262144U),
      optional_short_pad_(false),
      in_resync_(false) {}

void Ntb16StreamDecoder::reset() {
    buffer_.clear();
    optional_short_pad_ = false;
    in_resync_ = false;
}

void Ntb16StreamDecoder::setUsbPacketSize(uint16_t usb_packet_size) {
    usb_packet_size_ = (usb_packet_size > 0U) ? usb_packet_size : 512U;
}

bool Ntb16StreamDecoder::plausibleHeaderAt(size_t offset) const {
    if (offset + kNth16Bytes > buffer_.size()) {
        return false;
    }
    const uint32_t sig = readU32Le(&buffer_[offset]);
    if (sig != kNth16Signature) {
        return false;
    }
    const uint16_t hdr_len = readU16Le(&buffer_[offset + 4U]);
    const uint16_t block_len = readU16Le(&buffer_[offset + 8U]);
    const uint16_t ndp_idx = readU16Le(&buffer_[offset + 10U]);
    if (hdr_len != kNth16Bytes || block_len < kNth16Bytes + kNdp16MinBytes) {
        return false;
    }
    if (opts_.max_ntb_size > 0U && block_len > opts_.max_ntb_size) {
        return false;
    }
    return ndp_idx >= kNth16Bytes && (ndp_idx % 4U) == 0U &&
           static_cast<uint32_t>(ndp_idx) + kNdp16HeaderBytes <= block_len;
}

void Ntb16StreamDecoder::recordErrorAndResync(NtbStreamStats* delta) {
    if (!in_resync_) {
        in_resync_ = true;
        ++stats_.parse_errors;
        ++stats_.resyncs;
        if (delta != NULL) {
            ++delta->parse_errors;
            ++delta->resyncs;
        }
    }
}

void Ntb16StreamDecoder::finishResync() { in_resync_ = false; }

bool Ntb16StreamDecoder::resynchronize(NtbStreamStats* delta) {
    if (buffer_.size() <= 1U) {
        if (!buffer_.empty()) {
            stats_.resync_bytes_skipped += buffer_.size();
            if (delta != NULL) {
                delta->resync_bytes_skipped += buffer_.size();
            }
            buffer_.clear();
        }
        return false;
    }
    if (buffer_.size() > kNth16Bytes) {
        const size_t limit = buffer_.size() - kNth16Bytes;
        for (size_t off = 1U; off <= limit; ++off) {
            if (plausibleHeaderAt(off)) {
                buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<ptrdiff_t>(off));
                stats_.resync_bytes_skipped += off;
                if (delta != NULL) {
                    delta->resync_bytes_skipped += off;
                }
                return true;
            }
        }
    }
    const size_t keep = kNth16Bytes - 1U;
    if (buffer_.size() > keep) {
        const size_t drop = buffer_.size() - keep;
        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<ptrdiff_t>(drop));
        stats_.resync_bytes_skipped += drop;
        if (delta != NULL) {
            delta->resync_bytes_skipped += drop;
        }
    }
    return false;
}

void Ntb16StreamDecoder::push(const uint8_t* data,
                              size_t len,
                              std::vector<Ntb16Frame>& out_frames,
                              NtbStreamStats* delta_stats_out) {
    NtbStreamStats delta;
    if (delta_stats_out != NULL) {
        *delta_stats_out = delta;
    }
    if (data == NULL || len == 0U) {
        return;
    }
    if (buffer_.size() + len > max_buffer_bytes_) {
        recordErrorAndResync(&delta);
        stats_.resync_bytes_skipped += buffer_.size();
        delta.resync_bytes_skipped += buffer_.size();
        buffer_.clear();
        optional_short_pad_ = false;
        if (len > max_buffer_bytes_) {
            stats_.resync_bytes_skipped += len;
            delta.resync_bytes_skipped += len;
            if (delta_stats_out != NULL) {
                *delta_stats_out = delta;
            }
            return;
        }
    }

    buffer_.insert(buffer_.end(), data, data + len);

    for (;;) {
        if (optional_short_pad_ && !buffer_.empty()) {
            optional_short_pad_ = false;
            const uint8_t b0 = buffer_[0];
            if (b0 == 0x00U) {
                buffer_.erase(buffer_.begin());
            } else if (b0 != static_cast<uint8_t>(kNth16Signature & 0xffU)) {
                recordErrorAndResync(&delta);
                if (!resynchronize(&delta)) {
                    break;
                }
                continue;
            }
        }

        if (buffer_.size() < kNth16Bytes) {
            break;
        }

        const uint32_t sig = readU32Le(&buffer_[0]);
        const uint16_t hdr_len = readU16Le(&buffer_[4]);
        const uint16_t block_len = readU16Le(&buffer_[8]);
        const bool bad_max = (opts_.max_ntb_size > 0U && block_len > opts_.max_ntb_size);
        if (sig != kNth16Signature || hdr_len != kNth16Bytes ||
            block_len < kNth16Bytes + kNdp16MinBytes || bad_max) {
            recordErrorAndResync(&delta);
            if (!resynchronize(&delta)) {
                break;
            }
            continue;
        }

        if (buffer_.size() < block_len) {
            break;
        }

        Ntb16Frame frame;
        std::string err;
        if (!parseNtb16(&buffer_[0], block_len, opts_, frame, &err)) {
            recordErrorAndResync(&delta);
            if (!resynchronize(&delta)) {
                break;
            }
            continue;
        }

        out_frames.push_back(frame);
        ++stats_.ntbs_parsed;
        ++delta.ntbs_parsed;
        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<ptrdiff_t>(block_len));
        optional_short_pad_ = (usb_packet_size_ > 0U && (block_len % usb_packet_size_) == 0U);
        finishResync();
    }

    if (delta_stats_out != NULL) {
        *delta_stats_out = delta;
    }
}

}  // namespace ncm
}  // namespace carplay
