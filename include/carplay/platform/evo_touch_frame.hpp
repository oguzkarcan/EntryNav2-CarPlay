#ifndef CARPLAY_PLATFORM_EVO_TOUCH_FRAME_HPP
#define CARPLAY_PLATFORM_EVO_TOUCH_FRAME_HPP

// BMW NBT Evo / EntryNav2 touchscreen PDU reassembler and stream parser (UDP port 30567).
//
// Wire layout (observed on vehicle, 160.48.199.115:30501 -> 30567):
//   * Header (16 bytes): [0..3] magic B0 04 80 02, [4..7] BE32 (datagram_len - 8), [8..15] reserved.
//   * Records (8 bytes each): [0] 0x00, [1] type (0xC5 start, 0xC1 continuation, 0xC3 end;
//     bit 2 = start, bit 1 = end), [2] flags, [3] wrapping seq, [4..7] 4 payload bytes.
//   * Joined message is typically 12 records (112-byte single datagram, or split across 2..4
//     datagrams). Payload bytes from record 4 onward form the touch stream:
//       [0] flags & rolling counter
//       [1] contact count N
//       N x 6-byte contacts: BE16 x, BE16 y, size, (state << 4) | id
//         state: 1 = down, 2 = move, 3 = up
//         id: 0..kTouchMaxContacts-1
//
// Pure header, no I/O, no dynamic allocation. GCC 4.7.2 -std=gnu++0x compatible.

#include <stddef.h>
#include <stdint.h>

namespace carplay {
namespace platform {

enum {
    kTouchMaxContacts = 5,
    kTouchMaxMsgs = 4
};

struct RawTouchContact {
    int id;
    int state;  // 1 = down, 2 = move, 3 = up
    int x;
    int y;
    int size;

    RawTouchContact() : id(0), state(0), x(0), y(0), size(0) {}
};

struct TouchPointer {
    int id;
    int x;
    int y;

    TouchPointer() : id(0), x(0), y(0) {}
};

struct TouchEventOut {
    enum Action {
        kPress = 0,
        kRelease = 1,
        kMove = 2,
        kPointerDown = 5,
        kPointerUp = 6
    };

    int n;
    TouchPointer p[kTouchMaxContacts];
    int action;
    int index;

    TouchEventOut() : n(0), action(0), index(0) {}
};

struct TouchMsg {
    enum { kMaxRecords = 32 };
    uint8_t d[kMaxRecords * 4];
    int recs;
    uint8_t seq0;
    uint8_t seq1;

    TouchMsg() : recs(0), seq0(0), seq1(0) {
        for (size_t i = 0; i < sizeof(d); ++i) {
            d[i] = 0U;
        }
    }
};

namespace touchpdu {
static const size_t kHeader = 16U;
static const size_t kRecord = 8U;
static const int kStreamRecord = 4;
static const int kContactBytes = 6;
static const int kFrameRecords = 12;
static const size_t kFrameBytes = kHeader + kRecord * kFrameRecords;  // 112

inline bool isIdent(const uint8_t* p) {
    return p != NULL && p[0] == 0xB0U && p[1] == 0x04U && p[2] == 0x80U && p[3] == 0x02U;
}
}  // namespace touchpdu

/// Parses contacts from a joined TouchMsg. Returns parsed contact count, or -1 if too short.
inline int parseTouchStream(const TouchMsg& m, RawTouchContact* out, int max, int* declared) {
    if (declared != NULL) {
        *declared = 0;
    }
    const int start = touchpdu::kStreamRecord * 4;
    const int size = m.recs * 4 - start;
    if (size < 2) {
        return -1;
    }
    const uint8_t* stream = m.d + start;
    const int claimed = static_cast<int>(stream[1]);
    if (declared != NULL) {
        *declared = claimed;
    }
    int found = 0;
    for (int c = 0; c < claimed && c < kTouchMaxContacts && found < max; ++c) {
        const int off = 2 + touchpdu::kContactBytes * c;
        if (off + 5 >= size) {
            break;
        }
        const uint8_t* at = stream + off;
        RawTouchContact contact;
        contact.x = (static_cast<int>(at[0]) << 8) | static_cast<int>(at[1]);
        contact.y = (static_cast<int>(at[2]) << 8) | static_cast<int>(at[3]);
        contact.size = static_cast<int>(at[4]);
        contact.state = (at[5] >> 4) & 0x0F;
        contact.id = at[5] & 0x0F;
        if (contact.state >= 1 && contact.state <= 3 &&
            contact.id >= 0 && contact.id < kTouchMaxContacts) {
            if (out != NULL) {
                out[found] = contact;
            }
            ++found;
        }
    }
    return found;
}

/// Joins 8-byte touch PDU records across one or more datagrams.
class TouchReassembler {
public:
    TouchReassembler() : open_(false), last_seq_(0U), dropped_(0U) { cur_.recs = 0; }

    void reset() {
        open_ = false;
        last_seq_ = 0U;
        dropped_ = 0U;
        cur_.recs = 0;
    }

    /// Feeds one UDP payload. Returns completed message count (>= 0), or -1 if not a touch PDU.
    int feed(const uint8_t* buf, size_t n, TouchMsg* out, int max_msgs) {
        if (buf == NULL || n < touchpdu::kHeader + touchpdu::kRecord || !touchpdu::isIdent(buf)) {
            return -1;
        }
        const uint32_t length = (static_cast<uint32_t>(buf[4]) << 24) |
                                (static_cast<uint32_t>(buf[5]) << 16) |
                                (static_cast<uint32_t>(buf[6]) << 8) |
                                static_cast<uint32_t>(buf[7]);
        if (length + 8U < n && length + 8U >= touchpdu::kHeader + touchpdu::kRecord) {
            n = static_cast<size_t>(length + 8U);
        }
        int done = 0;
        for (const uint8_t* record = buf + touchpdu::kHeader;
             record + touchpdu::kRecord <= buf + n;
             record += touchpdu::kRecord) {
            const uint8_t type = record[1];
            const uint8_t seq = record[3];
            if (record[0] != 0x00U || (type & 0xC0U) != 0xC0U) {
                drop();
                return done > 0 ? done : -1;
            }
            if ((type & 0x04U) != 0U) {
                if (open_) {
                    ++dropped_;
                }
                open_ = true;
                cur_.recs = 0;
                cur_.seq0 = seq;
            } else if (!open_) {
                continue;
            } else if (seq != static_cast<uint8_t>(last_seq_ + 1U)) {
                drop();
                continue;
            }
            last_seq_ = seq;
            if (cur_.recs >= TouchMsg::kMaxRecords) {
                drop();
                continue;
            }
            for (int i = 0; i < 4; ++i) {
                cur_.d[cur_.recs * 4 + i] = record[4 + i];
            }
            ++cur_.recs;
            if ((type & 0x02U) != 0U) {
                cur_.seq1 = seq;
                if (out != NULL && done < max_msgs) {
                    out[done++] = cur_;
                }
                open_ = false;
                cur_.recs = 0;
            }
        }
        return done;
    }

    unsigned dropped() const { return dropped_; }

private:
    void drop() {
        if (open_) {
            ++dropped_;
        }
        open_ = false;
        cur_.recs = 0;
    }

    TouchMsg cur_;
    bool open_;
    uint8_t last_seq_;
    unsigned dropped_;
};

/// Test helper: builds a whole 112-byte (12-record) touch PDU.
inline void buildTouchFrame(uint8_t* f,
                            const RawTouchContact* c,
                            int nc,
                            uint8_t counter,
                            uint8_t seq0 = 0U) {
    for (size_t i = 0; i < touchpdu::kFrameBytes; ++i) {
        f[i] = 0U;
    }
    f[0] = 0xB0U;
    f[1] = 0x04U;
    f[2] = 0x80U;
    f[3] = 0x02U;
    f[7] = static_cast<uint8_t>(touchpdu::kFrameBytes - 8U);
    for (int r = 0; r < touchpdu::kFrameRecords; ++r) {
        uint8_t* record = f + touchpdu::kHeader + touchpdu::kRecord * r;
        record[1] = (r == 0) ? 0xC5U : ((r == touchpdu::kFrameRecords - 1) ? 0xC3U : 0xC1U);
        record[2] = 0x40U;
        record[3] = static_cast<uint8_t>(seq0 + r);
    }
    uint8_t stream[32];
    for (size_t i = 0; i < sizeof(stream); ++i) {
        stream[i] = 0U;
    }
    stream[0] = counter;
    stream[1] = static_cast<uint8_t>(nc);
    for (int k = 0; k < nc && k < kTouchMaxContacts; ++k) {
        uint8_t* at = stream + 2 + touchpdu::kContactBytes * k;
        at[0] = static_cast<uint8_t>((c[k].x >> 8) & 0xFF);
        at[1] = static_cast<uint8_t>(c[k].x & 0xFF);
        at[2] = static_cast<uint8_t>((c[k].y >> 8) & 0xFF);
        at[3] = static_cast<uint8_t>(c[k].y & 0xFF);
        at[4] = static_cast<uint8_t>(c[k].size & 0xFF);
        at[5] = static_cast<uint8_t>(((c[k].state & 0x0F) << 4) | (c[k].id & 0x0F));
    }
    for (int i = 0; i < 32; ++i) {
        f[touchpdu::kHeader + touchpdu::kRecord * (touchpdu::kStreamRecord + i / 4) + 4 + i % 4] =
            stream[i];
    }
}

/// Test helper: splits a 112-byte touch PDU into datagrams of `recs_per[k]` records.
inline int splitTouchFrame(const uint8_t* f,
                           const int* recs_per,
                           int parts,
                           uint8_t* dg,
                           int* sizes) {
    int first = 0;
    int k = 0;
    for (; k < parts && first < touchpdu::kFrameRecords; ++k) {
        const int remaining = touchpdu::kFrameRecords - first;
        const int records = (recs_per[k] > remaining) ? remaining : recs_per[k];
        uint8_t* d = dg + touchpdu::kFrameBytes * k;
        for (size_t i = 0; i < touchpdu::kHeader; ++i) {
            d[i] = f[i];
        }
        const int size = static_cast<int>(touchpdu::kHeader + touchpdu::kRecord * records);
        d[4] = 0U;
        d[5] = 0U;
        d[6] = 0U;
        d[7] = static_cast<uint8_t>(size - 8);
        for (int i = 0; i < static_cast<int>(touchpdu::kRecord) * records; ++i) {
            d[touchpdu::kHeader + i] = f[touchpdu::kHeader + touchpdu::kRecord * first + i];
        }
        sizes[k] = size;
        first += records;
    }
    return k;
}

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_EVO_TOUCH_FRAME_HPP
