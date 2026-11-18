#ifndef CARPLAY_CDC_NCM_HPP
#define CARPLAY_CDC_NCM_HPP

// Pure USB CDC-NCM 1.0 (Network Control Model) NTB-16 codec and control parameter structures.
// Reference: USB-IF "Universal Serial Bus Communications Class Subclass Specification for Network
// Control Model Devices", Revision 1.0 (public standard).
// NTB-16 stream reassembly, short-packet pad handling, overlap/datagram caps, and header
// resynchronization derived in part from DiPlay-main:
//   shared/src/main/java/com/shilapi/xcertplay/transport/Ntb16Codec.kt
//   shared/src/main/java/com/shilapi/xcertplay/transport/NcmUsbBridge.kt
// GPL-3.0, Copyright (c) DiPlay contributors.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

namespace carplay {
namespace ncm {

// CDC-NCM 1.0 Class-Specific Control Requests (Section 6.2; verified: USB-IF CDC-NCM 1.0).
static const uint8_t kReqGetNtbParameters = 0x80U;
static const uint8_t kReqGetNetAddress = 0x81U;
static const uint8_t kReqSetNetAddress = 0x82U;
static const uint8_t kReqGetNtbFormat = 0x83U;
static const uint8_t kReqSetNtbFormat = 0x84U;
static const uint8_t kReqGetNtbInputSize = 0x85U;
static const uint8_t kReqSetNtbInputSize = 0x86U;
static const uint8_t kReqGetMaxDatagramSize = 0x87U;
static const uint8_t kReqSetMaxDatagramSize = 0x88U;
static const uint8_t kReqSetEthernetPacketFilter = 0x43U;

// bmRequestType values for CDC class interface control transfers.
static const uint8_t kReqTypeClassIn = 0xa1U;   // Device-to-Host | Class | Interface
static const uint8_t kReqTypeClassOut = 0x21U;  // Host-to-Device | Class | Interface

// CDC-ECM/NCM packet filter bits (SET_ETHERNET_PACKET_FILTER wValue).
static const uint16_t kPacketFilterPromiscuous = 0x0001U;
static const uint16_t kPacketFilterAllMulticast = 0x0002U;
static const uint16_t kPacketFilterDirected = 0x0004U;
static const uint16_t kPacketFilterBroadcast = 0x0008U;
static const uint16_t kPacketFilterMulticast = 0x0010U;

// NTB-16 wire signatures (verified: USB-IF CDC-NCM 1.0 & DiPlay Ntb16Codec.kt).
static const uint32_t kNth16Signature = 0x484d434eU;       // "NCMH"
static const uint32_t kNdp16SignatureNoCrc = 0x304d434eU;  // "NCM0"
static const uint32_t kNdp16SignatureCrc = 0x314d434eU;    // "NCM1"

static const size_t kNth16Bytes = 12U;                      // verified: USB-IF CDC-NCM 1.0 & DiPlay Ntb16Codec.kt
static const size_t kNdp16HeaderBytes = 8U;
static const size_t kNdp16EntryBytes = 4U;
static const size_t kNdp16MinBytes = 16U;                   // verified: 8B header + >=1 entry + {0,0} terminator
static const size_t kNtbParametersBytes = 28U;
static const uint32_t kMaxNtb16BlockSize = 65535U;
static const uint16_t kMaxNtb16Datagrams = 256U;            // verified: DiPlay Ntb16Codec.kt MAX_ENTRIES_PER_BLOCK

struct NtbParameters {
    uint16_t length;
    uint16_t formats_supported;
    uint32_t ntb_in_max_size;
    uint16_t ndp_in_divisor;
    uint16_t ndp_in_payload_remainder;
    uint16_t ndp_in_alignment;
    uint32_t ntb_out_max_size;
    uint16_t ndp_out_divisor;
    uint16_t ndp_out_payload_remainder;
    uint16_t ndp_out_alignment;
    uint16_t ntb_out_max_datagrams;  // 0 = no limit

    NtbParameters()
        : length(28U),
          formats_supported(1U),
          ntb_in_max_size(16384U),
          ndp_in_divisor(4U),
          ndp_in_payload_remainder(0U),
          ndp_in_alignment(4U),
          ntb_out_max_size(16384U),
          ndp_out_divisor(4U),
          ndp_out_payload_remainder(0U),
          ndp_out_alignment(4U),
          ntb_out_max_datagrams(32U) {}

    static NtbParameters defaults() { return NtbParameters(); }
    bool validate(std::string* error_out = NULL) const;
};

struct NtbParseOptions {
    uint32_t max_ntb_size;
    uint16_t max_datagrams;  // 0 = unlimited; default kMaxNtb16Datagrams (256)
    bool check_in_alignment;
    uint16_t ndp_in_divisor;
    uint16_t ndp_in_payload_remainder;
    uint16_t ndp_in_alignment;
    bool verify_crc32;

    NtbParseOptions()
        : max_ntb_size(kMaxNtb16BlockSize),
          max_datagrams(kMaxNtb16Datagrams),
          check_in_alignment(false),
          ndp_in_divisor(1U),
          ndp_in_payload_remainder(0U),
          ndp_in_alignment(4U),
          verify_crc32(true) {}

    static NtbParseOptions fromParameters(const NtbParameters& p, bool strict_alignment = false);
};

struct NtbBuildOptions {
    uint32_t max_ntb_size;
    uint16_t ndp_alignment;
    uint16_t ndp_divisor;
    uint16_t ndp_payload_remainder;
    uint16_t max_datagrams;  // 0 = unlimited
    bool append_crc32;

    NtbBuildOptions()
        : max_ntb_size(16384U),
          ndp_alignment(4U),
          ndp_divisor(4U),
          ndp_payload_remainder(0U),
          max_datagrams(32U),
          append_crc32(false) {}

    static NtbBuildOptions fromParameters(const NtbParameters& p);
};

struct Ntb16Frame {
    uint16_t sequence;
    uint16_t block_length;
    std::vector<std::vector<uint8_t> > datagrams;

    Ntb16Frame() : sequence(0), block_length(0) {}
};

struct NtbStreamStats {
    uint64_t ntbs_parsed;
    uint64_t parse_errors;
    uint64_t resyncs;
    uint64_t resync_bytes_skipped;

    NtbStreamStats()
        : ntbs_parsed(0), parse_errors(0), resyncs(0), resync_bytes_skipped(0) {}
};

/// Reassembles a USB CDC-NCM Bulk IN byte stream into whole NTB-16 blocks, handling:
///   * NTB-16 blocks split across multiple USB reads
///   * Multiple NTB-16 blocks coalesced in a single USB read
///   * Optional 1-byte 0x00 short-packet padding after USB-packet-size-aligned blocks (512 HS / 64 FS)
///   * Bounded NTH16 header resynchronization after stream corruption
class Ntb16StreamDecoder {
public:
    explicit Ntb16StreamDecoder(const NtbParseOptions& opts = NtbParseOptions(),
                                uint16_t usb_packet_size = 512U,
                                size_t max_buffer_bytes = 262144U);

    void reset();
    void setParseOptions(const NtbParseOptions& opts) { opts_ = opts; }
    void setUsbPacketSize(uint16_t usb_packet_size);

    const NtbStreamStats& stats() const { return stats_; }
    size_t bufferedBytes() const { return buffer_.size(); }

    /// Feeds `data[0..len)` into the reassembly buffer and appends any complete decoded
    /// NTB-16 blocks to `out_frames`. `delta_stats_out`, if non-NULL, receives per-call counts.
    void push(const uint8_t* data,
              size_t len,
              std::vector<Ntb16Frame>& out_frames,
              NtbStreamStats* delta_stats_out = NULL);

private:
    bool resynchronize(NtbStreamStats* delta);
    bool plausibleHeaderAt(size_t offset) const;
    void recordErrorAndResync(NtbStreamStats* delta);
    void finishResync();

    NtbParseOptions opts_;
    uint16_t usb_packet_size_;
    size_t max_buffer_bytes_;
    std::vector<uint8_t> buffer_;
    bool optional_short_pad_;
    bool in_resync_;
    NtbStreamStats stats_;
};

/// Parses a 28-byte GET_NTB_PARAMETERS response and validates divisor/remainder/alignment fields.
bool parseNtbParameters(const uint8_t* data,
                        size_t len,
                        NtbParameters& out,
                        std::string* error_out = NULL);

/// Encodes NtbParameters into the 28-byte CDC-NCM wire format.
void encodeNtbParameters(const NtbParameters& params, std::vector<uint8_t>& out);

/// Encodes the 4-byte SET_NTB_INPUT_SIZE payload (little-endian uint32).
void encodeSetNtbInputSize(uint32_t ntb_in_max_size, std::vector<uint8_t>& out);

/// Computes IEEE 802.3 CRC-32 (used by NCM1 frames).
uint32_t crc32Ieee8023(const uint8_t* data, size_t len);

/// Parses a single NTB-16 block, following wNdpIndex and wNextNdpIndex chains.
/// Rejects truncated blocks, bad signatures, out-of-bounds/overflowing offsets, cycles,
/// overlapping NDP/header/datagram regions, datagram counts > max_datagrams, and optional
/// alignment or CRC-32 mismatches.
bool parseNtb16(const uint8_t* data,
                size_t len,
                const NtbParseOptions& opts,
                Ntb16Frame& out,
                std::string* error_out = NULL);

/// Packs as many consecutive frames starting at `start_index` as fit into one OUT NTB-16
/// respecting `opts.max_ntb_size`, `opts.max_datagrams`, and divisor/remainder/alignment rules.
/// Fails if `start_index >= frames.size()`, options are invalid, or a single frame cannot fit.
bool packNtb16Batch(const std::vector<std::vector<uint8_t> >& frames,
                    size_t start_index,
                    uint16_t sequence,
                    const NtbBuildOptions& opts,
                    std::vector<uint8_t>& out,
                    size_t& frames_packed_out,
                    std::string* error_out = NULL);

/// Builds a single OUT NTB-16 containing ALL `frames`. Fails if they do not fit in one NTB.
bool buildNtb16(const std::vector<std::vector<uint8_t> >& frames,
                uint16_t sequence,
                const NtbBuildOptions& opts,
                std::vector<uint8_t>& out,
                std::string* error_out = NULL);

}  // namespace ncm
}  // namespace carplay

#endif  // CARPLAY_CDC_NCM_HPP
