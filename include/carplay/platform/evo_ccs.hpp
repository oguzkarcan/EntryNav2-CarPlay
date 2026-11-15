#ifndef CARPLAY_PLATFORM_EVO_CCS_HPP
#define CARPLAY_PLATFORM_EVO_CCS_HPP

// BMW iDrive controller (ZBE3 / CCS) vMOST FBlock 0xE5 decoder and protocol arbiter.
//
// Supports BOTH BMW controller protocols on FBlock 0xE5:
//   1. CCS35up (instance 0x03, newer G-series / some F-series):
//      - 0xC46 RotaryEncoderState (len >= 5):
//          [1..2] BE16 rotary counter, [3] center push (1/0), [4] 12-step clock tilt (0=center,
//          12/1/2=Up, 3/4/5=Right, 6/7/8=Down, 9/10/11=Left).
//      - 0xC47 PushButtonsState (7 bytes) / 0xC4F PushButtonsState2 (8 bytes):
//          One byte per slot: 0=MENU, 1=BACK, 2=OPTION, 3=COM, 4=MEDIA, 5=NAV, 6=MAP.
//          Values: 0=released, 1/2/3=pressed/held, 4=finger resting on capacitive key (NOT pressed),
//          7=no information (keep previous state).
//
//   2. Older CCS (instance 0x01, 2017 BMW F20 LCI target hardware / i3 / F-series ZBE3):
//      - 0xC10 RotaryEncoder:
//          7-byte form: [0] sender, [1] receiver, [2] counter (0xFF=not configured),
//                       [3..4] BE16 detent position, [5] cluster (0x1E), [6] overflow (rebase).
//          4..6-byte compact form: [2] != 0xFF, [3] 8-bit wrapping counter.
//      - 0xC20 PushButton (len >= 7):
//          [2] counter (0xFF=ignore), [3] status (0=released, 1=pressed, 2=held, 3+=no change/invalid),
//          [4] tilt mask (1=Up, 2=Right, 4=Down, 8=Left), [5] cluster (0x00=hard keys, 0x1D=tilt,
//          0x1E=knob push), [6] sensor:
//            * cluster 0x1E, sensor 1: center push
//            * cluster 0x00, sensor bitmask (TARGET_HARDWARE.md §3):
//                0x01=MENU, 0x02=BACK, 0x04=OPTION, 0x08=MEDIA, 0x10=NAV, 0x20=MAP, 0x40=COM.
//
// Pure header, no I/O, GCC 4.7.2 -std=gnu++0x compatible.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "carplay/airplay_hid.hpp"

namespace carplay {
namespace platform {

// Hardware button bitmasks matching carplay::hid::zbe3 + optional 7-button NAV/MAP slots.
static const uint8_t kCcsBtnMenu = hid::zbe3::kBtnMenu;      // 0x01
static const uint8_t kCcsBtnBack = hid::zbe3::kBtnBack;      // 0x02
static const uint8_t kCcsBtnOption = hid::zbe3::kBtnOption;  // 0x04
static const uint8_t kCcsBtnMedia = hid::zbe3::kBtnMedia;    // 0x08
static const uint8_t kCcsBtnNav = 0x10U;
static const uint8_t kCcsBtnMap = 0x20U;
static const uint8_t kCcsBtnCom = hid::zbe3::kBtnCom;        // 0x40

enum CcsKey {
    kCcsKeyNone = 0,
    kCcsKeyCenter = 1,
    kCcsKeyUp = 2,
    kCcsKeyRight = 3,
    kCcsKeyDown = 4,
    kCcsKeyLeft = 5,
    kCcsKeyMenu = 6,
    kCcsKeyBack = 7,
    kCcsKeyOption = 8,
    kCcsKeyMedia = 9,
    kCcsKeyNav = 10,
    kCcsKeyMap = 11,
    kCcsKeyCom = 12,
    kCcsKeyRotary = 13
};

struct CcsEvent {
    enum Kind { kKey = 1, kRotary = 2 };

    int kind;
    CcsKey key;
    uint8_t btn_mask;  // kCcsBtn* for hard keys, 0 otherwise
    uint8_t dir_mask;  // hid::zbe3::kDir* for tilt, 0 otherwise
    bool down;
    int delta;
    const char* name;

    CcsEvent()
        : kind(0),
          key(kCcsKeyNone),
          btn_mask(0),
          dir_mask(0),
          down(false),
          delta(0),
          name("") {}
};

class CcsDecoder {
public:
    enum { kInstance = 0x03, kCcsInstance = 0x01, kSlots = 7 };

    CcsDecoder()
        : position_(-1),
          tilt_key_(kCcsKeyNone),
          dir_mask_(0),
          push_(false),
          button_mask_(0),
          ccs_position_(-1),
          ccs8_position_(-1),
          ccs_tilt_key_(kCcsKeyNone),
          ccs_dir_mask_(0),
          ccs_push_(false),
          ccs_button_mask_(0) {
        for (int i = 0; i < kSlots; ++i) {
            slots_[i] = false;
        }
    }

    static const char* slotName(int slot) {
        static const char* const kNames[kSlots] = {
            "MENU", "BACK", "OPTION", "COM", "MEDIA", "NAV", "MAP"
        };
        return (slot >= 0 && slot < kSlots) ? kNames[slot] : "?";
    }

    static int slotByName(const char* name) {
        if (name == NULL) {
            return -1;
        }
        if (strcmp(name, "OPTIONS") == 0) {
            return 2;
        }
        for (int i = 0; i < kSlots; ++i) {
            if (strcmp(name, slotName(i)) == 0) {
                return i;
            }
        }
        return -1;
    }

    static uint8_t slotBit(int slot) {
        static const uint8_t kBits[kSlots] = {
            kCcsBtnMenu, kCcsBtnBack, kCcsBtnOption, kCcsBtnCom,
            kCcsBtnMedia, kCcsBtnNav, kCcsBtnMap
        };
        return (slot >= 0 && slot < kSlots) ? kBits[slot] : 0U;
    }

    static CcsKey slotKeyId(int slot) {
        static const CcsKey kKeys[kSlots] = {
            kCcsKeyMenu, kCcsKeyBack, kCcsKeyOption, kCcsKeyCom,
            kCcsKeyMedia, kCcsKeyNav, kCcsKeyMap
        };
        return (slot >= 0 && slot < kSlots) ? kKeys[slot] : kCcsKeyNone;
    }

    /// Decodes one FBlock 0xE5 OpStatus (0xC) message into up to `max` CcsEvents.
    int feed(uint8_t fblock,
             uint8_t inst,
             uint16_t fkt,
             uint8_t op,
             const uint8_t* d,
             size_t n,
             CcsEvent* out,
             int max) {
        Events events(out, max);
        if (fblock != 0xE5U || op != 0xCU || d == NULL) {
            return 0;
        }
        if ((fkt == 0xC10U || fkt == 0xC20U) && inst == kCcsInstance) {
            return fkt == 0xC10U ? ccsRotary(d, n, events) : ccsButton(d, n, events);
        }
        if (inst != kInstance) {
            return 0;
        }
        if (fkt == 0xC46U && n >= 5U) {
            const int position = (static_cast<int>(d[1]) << 8) | static_cast<int>(d[2]);
            if (position_ >= 0 && position != position_) {
                rotate(steps16(position, position_), events);
            }
            position_ = position;
            setTilt(clockTiltKey(d[4]), tilt_key_, dir_mask_, events);
            const bool push = (d[3] != 0U);
            if (push != push_) {
                push_ = push;
                events.addKey(kCcsKeyCenter, 0U, 0U, push, "PUSH");
            }
        } else if ((fkt == 0xC47U || fkt == 0xC4FU) && n >= 1U) {
            for (int slot = 0; slot < kSlots && static_cast<size_t>(slot) < n; ++slot) {
                const uint8_t v = d[slot];
                bool down = slots_[slot];
                if (v == 1U || v == 2U || v == 3U) {
                    down = true;
                } else if (v == 0U || v == 4U) {
                    // 4 = finger resting on capacitive key (not pressed).
                    down = false;
                }
                if (down != slots_[slot]) {
                    slots_[slot] = down;
                    const uint8_t bit = slotBit(slot);
                    if (down) {
                        button_mask_ |= bit;
                    } else {
                        button_mask_ &= static_cast<uint8_t>(~bit);
                    }
                    events.addKey(slotKeyId(slot), bit, 0U, down, slotName(slot));
                }
            }
        }
        return events.count;
    }

    uint8_t buttonMask(bool older) const { return older ? ccs_button_mask_ : button_mask_; }
    bool centerPressed(bool older) const { return older ? ccs_push_ : push_; }
    uint8_t dirMask(bool older) const { return older ? ccs_dir_mask_ : dir_mask_; }

    /// Builds a hid::Zbe3Event snapshot for the selected protocol.
    hid::Zbe3Event zbe3State(bool older, int8_t rotary_delta = 0, bool include_dir = false) const {
        hid::Zbe3Event ev;
        ev.center_pressed = older ? ccs_push_ : push_;
        ev.button_mask = older ? ccs_button_mask_ : button_mask_;
        ev.dir_mask = include_dir ? (older ? ccs_dir_mask_ : dir_mask_) : 0U;
        ev.rotary_delta = rotary_delta;
        return ev;
    }

private:
    struct Events {
        CcsEvent* out;
        int max;
        int count;

        Events(CcsEvent* to, int room) : out(to), max(room), count(0) {}

        void addKey(CcsKey key, uint8_t btn_mask, uint8_t dir_mask, bool down, const char* name) {
            if (out != NULL && count < max) {
                CcsEvent ev;
                ev.kind = CcsEvent::kKey;
                ev.key = key;
                ev.btn_mask = btn_mask;
                ev.dir_mask = dir_mask;
                ev.down = down;
                ev.delta = 0;
                ev.name = name;
                out[count++] = ev;
            }
        }

        void addRotary(int delta) {
            if (out != NULL && count < max) {
                CcsEvent ev;
                ev.kind = CcsEvent::kRotary;
                ev.key = kCcsKeyRotary;
                ev.btn_mask = 0U;
                ev.dir_mask = 0U;
                ev.down = false;
                ev.delta = delta;
                ev.name = "ROTARY";
                out[count++] = ev;
            }
        }
    };

    static int steps16(int now, int before) {
        return static_cast<int16_t>(static_cast<uint16_t>(now - before));
    }

    static void rotate(int delta, Events& events) {
        if (delta != 0) {
            events.addRotary(delta);
        }
    }

    static CcsKey clockTiltKey(unsigned hour) {
        if (hour == 0U || hour > 12U) {
            return kCcsKeyNone;
        }
        if (hour == 12U || hour <= 2U) return kCcsKeyUp;
        if (hour <= 5U) return kCcsKeyRight;
        if (hour <= 8U) return kCcsKeyDown;
        return kCcsKeyLeft;
    }

    static CcsKey bitTiltKey(unsigned bits) {
        switch (bits) {
            case 1U: return kCcsKeyUp;
            case 2U: return kCcsKeyRight;
            case 4U: return kCcsKeyDown;
            case 8U: return kCcsKeyLeft;
            default: return kCcsKeyNone;
        }
    }

    static uint8_t tiltDirMask(CcsKey key) {
        switch (key) {
            case kCcsKeyUp: return hid::zbe3::kDirUp;
            case kCcsKeyRight: return hid::zbe3::kDirRight;
            case kCcsKeyDown: return hid::zbe3::kDirDown;
            case kCcsKeyLeft: return hid::zbe3::kDirLeft;
            default: return 0U;
        }
    }

    static const char* tiltName(CcsKey key) {
        switch (key) {
            case kCcsKeyUp: return "TILT_UP";
            case kCcsKeyRight: return "TILT_RIGHT";
            case kCcsKeyDown: return "TILT_DOWN";
            case kCcsKeyLeft: return "TILT_LEFT";
            default: return "TILT_?";
        }
    }

    static void setTilt(CcsKey new_key, CcsKey& held_key, uint8_t& dir_mask, Events& events) {
        if (new_key == held_key) {
            return;
        }
        if (held_key != kCcsKeyNone) {
            events.addKey(held_key, 0U, tiltDirMask(held_key), false, tiltName(held_key));
        }
        if (new_key != kCcsKeyNone) {
            events.addKey(new_key, 0U, tiltDirMask(new_key), true, tiltName(new_key));
        }
        held_key = new_key;
        dir_mask = tiltDirMask(new_key);
    }

    int ccsRotary(const uint8_t* d, size_t n, Events& events) {
        if (n >= 7U) {
            const int position = (static_cast<int>(d[3]) << 8) | static_cast<int>(d[4]);
            if (d[2] == 0xFFU || d[5] != 0x1EU) {
                ccs_position_ = -1;
                return 0;
            }
            if (d[6] != 0U || ccs_position_ < 0) {
                ccs_position_ = position;
                return 0;
            }
            const int delta = steps16(position, ccs_position_);
            ccs_position_ = position;
            rotate(delta, events);
            return events.count;
        }
        if (n >= 4U) {
            if (d[2] == 0xFFU) {
                ccs8_position_ = -1;
                return 0;
            }
            const int pos8 = static_cast<int>(d[3]);
            if (ccs8_position_ < 0) {
                ccs8_position_ = pos8;
                return 0;
            }
            const int delta = static_cast<int8_t>(static_cast<uint8_t>(pos8 - ccs8_position_));
            ccs8_position_ = pos8;
            rotate(delta, events);
            return events.count;
        }
        return 0;
    }

    void setOlderButtonBit(uint8_t bit, CcsKey key, const char* name, bool down, Events& events) {
        const bool was_down = (ccs_button_mask_ & bit) != 0U;
        if (down == was_down) {
            return;
        }
        if (down) {
            ccs_button_mask_ |= bit;
        } else {
            ccs_button_mask_ &= static_cast<uint8_t>(~bit);
        }
        events.addKey(key, bit, 0U, down, name);
    }

    int ccsButton(const uint8_t* d, size_t n, Events& events) {
        if (n < 7U || d[2] == 0xFFU || d[3] > 2U) {
            return 0;
        }
        const bool down = (d[3] != 0U);
        const uint8_t cluster = d[5];
        const uint8_t sensor = d[6];
        if (cluster == 0x1EU) {
            if (sensor == 1U && down != ccs_push_) {
                ccs_push_ = down;
                events.addKey(kCcsKeyCenter, 0U, 0U, down, "PUSH");
            }
        } else if (cluster == 0x1DU) {
            setTilt((down && d[4] != 0U) ? bitTiltKey(d[4]) : kCcsKeyNone,
                    ccs_tilt_key_,
                    ccs_dir_mask_,
                    events);
        } else if (cluster == 0x00U) {
            struct BitEntry {
                uint8_t bit;
                CcsKey key;
                const char* name;
            };
            static const BitEntry kMap[] = {
                {kCcsBtnMenu, kCcsKeyMenu, "MENU"},
                {kCcsBtnBack, kCcsKeyBack, "BACK"},
                {kCcsBtnOption, kCcsKeyOption, "OPTION"},
                {kCcsBtnMedia, kCcsKeyMedia, "MEDIA"},
                {kCcsBtnNav, kCcsKeyNav, "NAV"},
                {kCcsBtnMap, kCcsKeyMap, "MAP"},
                {kCcsBtnCom, kCcsKeyCom, "COM"}
            };
            if (sensor == 0U && !down) {
                for (size_t i = 0; i < sizeof(kMap) / sizeof(kMap[0]); ++i) {
                    if ((ccs_button_mask_ & kMap[i].bit) != 0U) {
                        setOlderButtonBit(kMap[i].bit, kMap[i].key, kMap[i].name, false, events);
                    }
                }
            } else {
                for (size_t i = 0; i < sizeof(kMap) / sizeof(kMap[0]); ++i) {
                    if ((sensor & kMap[i].bit) != 0U) {
                        setOlderButtonBit(kMap[i].bit, kMap[i].key, kMap[i].name, down, events);
                    }
                }
            }
        }
        return events.count;
    }

    int position_;
    CcsKey tilt_key_;
    uint8_t dir_mask_;
    bool push_;
    uint8_t button_mask_;
    bool slots_[kSlots];

    int ccs_position_;
    int ccs8_position_;
    CcsKey ccs_tilt_key_;
    uint8_t ccs_dir_mask_;
    bool ccs_push_;
    uint8_t ccs_button_mask_;
};

/// Tracks which controller protocol (CCS35up E5.03 vs older CCS E5.01) a vehicle speaks,
/// handles filter-opening Get timing, and locks onto the first protocol that responds.
class CcsProtocol {
public:
    enum Kind { kUnknown = 0, kCcs35up = 1, kOlder = 2 };
    enum { kSilenceMs = 2000 };

    explicit CcsProtocol(bool query_older_immediately = false)
        : kind_(kUnknown),
          asked_(false),
          older_asked_(false),
          query_older_immediately_(query_older_immediately),
          asked_ms_(0U) {}

    Kind kind() const { return kind_; }
    bool queryOlderImmediately() const { return query_older_immediately_; }
    void setQueryOlderImmediately(bool v) { query_older_immediately_ = v; }

    static const char* name(Kind kind) {
        if (kind == kCcs35up) return "CCS35up (E5.03)";
        if (kind == kOlder) return "older CCS (E5.01, C10/C20)";
        return "unknown";
    }

    static Kind of(uint8_t inst, uint16_t fkt) {
        if (inst == CcsDecoder::kInstance && (fkt == 0xC46U || fkt == 0xC47U || fkt == 0xC4FU)) {
            return kCcs35up;
        }
        if (inst == CcsDecoder::kCcsInstance && (fkt == 0xC10U || fkt == 0xC20U)) {
            return kOlder;
        }
        return kUnknown;
    }

    void ccs35upAsked(uint32_t now_ms) {
        asked_ = true;
        asked_ms_ = now_ms;
    }

    void markOlderAsked() { older_asked_ = true; }

    bool olderDue(uint32_t now_ms) {
        if (!asked_ || older_asked_ || kind_ != kUnknown) {
            return false;
        }
        if (!query_older_immediately_ &&
            static_cast<uint32_t>(now_ms - asked_ms_) < static_cast<uint32_t>(kSilenceMs)) {
            return false;
        }
        older_asked_ = true;
        return true;
    }

    bool accept(uint8_t inst, uint16_t fkt) {
        const Kind k = of(inst, fkt);
        if (k == kUnknown) {
            return true;
        }
        if (kind_ == kUnknown) {
            kind_ = k;
        }
        return k == kind_;
    }

private:
    Kind kind_;
    bool asked_;
    bool older_asked_;
    bool query_older_immediately_;
    uint32_t asked_ms_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_EVO_CCS_HPP
