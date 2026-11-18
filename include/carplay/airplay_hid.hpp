#ifndef CARPLAY_AIRPLAY_HID_HPP
#define CARPLAY_AIRPLAY_HID_HPP

// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/airplay/AirPlayHid.kt,
//  shared/src/main/java/com/shilapi/xcertplay/airplay/AirPlayTouchSlots.kt,
//  shared/src/main/java/com/shilapi/xcertplay/airplay/CarPlayMediaButton.kt,
//  shared/src/main/java/com/shilapi/xcertplay/airplay/AirPlaySession.kt,
//  common/src/main/java/com/shilapi/xcertplay/CarPlayRemoteKeys.kt,
//  common/src/main/java/com/shilapi/xcertplay/WheelKeyService.kt),
// GPL-3.0, Copyright (c) DiPlay contributors.
//
// CarPlay virtual HID devices: report descriptors, report encoders, touch slot assignment and the
// BMW HU_ENTRYNAV2 ZBE3 controller mapping.
//
// Descriptors and reports are byte-for-byte ports of the field-proven reference
// DiPlay-main/shared/src/main/java/com/shilapi/xcertplay/airplay/AirPlayHid.kt (+ AirPlayTouchSlots.kt,
// CarPlayMediaButton.kt and the senders in AirPlaySession.kt:347-385). Pure data, no I/O.
//
// Reports are delivered by the session layer as event-channel `hidSendReport` commands
// {"type":"hidSendReport", "uuid": uidString(uid), "hidReport": <report bytes>} (AirPlaySession.kt:441).

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace carplay {
namespace hid {

/// Standard AirPlay / CarPlay HID device UIDs advertised in /info and used by hidSendReport.
static const uint32_t kUidTouchscreen = 0x2a2a2a2aU;
static const uint32_t kUidKnob = 0x2a2a2a2bU;
static const uint32_t kUidMedia = 0x2a2a2a2cU;
static const uint32_t kUidTelephony = 0x2a2a2a2dU;

/// Lowercase hex without "0x" and without leading zeros (Kotlin Int.toString(16)): 0x2a2a2a2a ->
/// "2a2a2a2a". Used for /info `uuid` and the hidSendReport `uuid`.
std::string uidString(uint32_t uid);

/// Touchscreen: two finger collections of 6 bytes each.
static const size_t kTouchContacts = 2U;
static const size_t kTouchBytesPerFinger = 6U;
static const size_t kTouchReportBytes = kTouchContacts * kTouchBytesPerFinger;  // 12

/// Knob report: [select | home<<1 | back<<2, x(int8), y(int8), wheel(int8, relative)].
static const size_t kKnobReportBytes = 4U;
static const int32_t kKnobAxisMin = -127;
static const int32_t kKnobAxisMax = 127;

/// Media report: one byte, an index (array selector, logical 0..6) into the descriptor's usage list
/// (CarPlayMediaButton.kt; CarPlayMediaButtonTest.indicesMatchTheAdvertisedMediaHidReport).
enum MediaIndex {
    MEDIA_NONE = 0,         // Consumer 0x0000 (released)
    MEDIA_PLAY = 1,         // Consumer 0x00b0 Play
    MEDIA_PAUSE = 2,        // Consumer 0x00b1 Pause
    MEDIA_PLAY_PAUSE = 3,   // Consumer 0x00cd Play/Pause
    MEDIA_NEXT = 4,         // Consumer 0x00b5 Scan Next Track
    MEDIA_PREVIOUS = 5,     // Consumer 0x00b6 Scan Previous Track
    MEDIA_USAGE_029E = 6    // Consumer 0x029e (listed by the reference; no reference sender uses it)
};
static const int32_t kMediaLogicalMax = 6;

/// Telephony report: one byte, an index (array selector, logical 0..17) into the descriptor's usage
/// list. Reference senders use 1 (answer) and 3 (end call): CarPlayController.kt:3236-3237.
enum TelephonyIndex {
    TELEPHONY_NONE = 0,         // 0x00 (released)
    TELEPHONY_HOOK_SWITCH = 1,  // 0x20 Hook Switch (answer)
    TELEPHONY_FLASH = 2,        // 0x21 Flash
    TELEPHONY_DROP = 3,         // 0x26 Drop (end call)
    TELEPHONY_PHONE_MUTE = 4,   // 0x2f Phone Mute
    TELEPHONY_KEY_0 = 5,        // 0xb0..0xb9 Phone Key 0..9 -> indices 5..14
    TELEPHONY_KEY_9 = 14,
    TELEPHONY_KEY_STAR = 15,    // 0xba Phone Key Star
    TELEPHONY_KEY_POUND = 16,   // 0xbb Phone Key Pound
    TELEPHONY_BACKSPACE = 17    // Keyboard page 0x07 usage 0x2a (Backspace)
};
static const int32_t kTelephonyLogicalMax = 17;

// ---- Descriptors (AirPlayHid.kt:89-133) ----

/// Multitouch digitizer with kTouchContacts finger collections; X/Y logical maximum is the display
/// size in pixels. Like the reference, only the low 16 bits of each extent are encoded.
std::vector<uint8_t> touchscreenDescriptor(int32_t width_pixels, int32_t height_pixels);
std::vector<uint8_t> knobDescriptor();
std::vector<uint8_t> mediaDescriptor();
std::vector<uint8_t> telephonyDescriptor();

// ---- Touch ----

/// One touch contact. `id` is an external pointer id before TouchSlots::assign and the report slot
/// (0..kTouchContacts-1) after it. x/y are display pixels.
struct TouchContact {
    int32_t id;
    bool down;
    int32_t x;
    int32_t y;

    TouchContact() : id(0), down(false), x(0), y(0) {}
    TouchContact(int32_t id_, bool down_, int32_t x_, int32_t y_) : id(id_), down(down_), x(x_), y(y_) {}

    bool operator==(const TouchContact& o) const {
        return id == o.id && down == o.down && x == o.x && y == o.y;
    }
};

/// Java Math.round(max(normalized * extent_pixels, 0)) as in AirPlaySession.sendTouch +
/// AirPlayHid.touchReport: converts a 0..1 coordinate to pixels (saturating at INT32_MAX).
int32_t pixelFromNormalized(double normalized, int32_t extent_pixels);

/// 12-byte touch report: for each slot s, [s, down, x_lo, x_hi, y_lo, y_hi]. Each contact goes in
/// the slot named by its id (first match wins); a slot with no contact is reported up at (0,0);
/// contacts with other ids are ignored. Coordinates are clamped to [0, width_pixels] x
/// [0, height_pixels] (the descriptor's logical range; the reference only clamps at 0).
std::vector<uint8_t> touchReport(const std::vector<TouchContact>& slotted_contacts,
                                 int32_t width_pixels,
                                 int32_t height_pixels);

/// Port of AirPlayTouchSlots.kt: keeps each external pointer id in one report slot from press to
/// release. A finger missing from the next call (or every finger, for an empty list) is released
/// where it last was; a new finger takes the first free slot only when it is down; a finger beyond
/// the free slots is left out. assign() returns the contacts to report, ids replaced by slots,
/// in slot order, empty slots omitted.
class TouchSlots {
public:
    explicit TouchSlots(size_t slots = kTouchContacts);

    std::vector<TouchContact> assign(const std::vector<TouchContact>& contacts);

    /// Forgets every held finger (e.g. on session teardown). Sends nothing.
    void reset();

    size_t slotCount() const { return pointer_used_.size(); }

private:
    std::vector<bool> pointer_used_;
    std::vector<int32_t> pointers_;
    std::vector<bool> held_used_;
    std::vector<TouchContact> held_;
};

// ---- Knob ----

/// Knob state (AirPlayKnobState). x/y are the reference's legacy absolute axes (never driven by any
/// reference sender); wheel is relative focus movement (+1 = next / forward, -1 = previous).
struct KnobState {
    bool select;
    bool home;
    bool back;
    int32_t x;
    int32_t y;
    int32_t wheel;

    KnobState() : select(false), home(false), back(false), x(0), y(0), wheel(0) {}

    bool operator==(const KnobState& o) const {
        return select == o.select && home == o.home && back == o.back && x == o.x && y == o.y &&
               wheel == o.wheel;
    }
};

/// 4-byte knob report; x/y/wheel are clamped to [-127, 127].
std::vector<uint8_t> knobReport(const KnobState& state);

// ---- Media / Telephony ----

/// 1-byte report holding `index` (low 8 bits, like Kotlin Int.toByte()).
std::vector<uint8_t> mediaReport(int32_t index);
std::vector<uint8_t> telephonyReport(int32_t index);

// ---- Reference send sequences (AirPlaySession.kt:369-385). Each element is one hidSendReport. ----

typedef std::vector<std::vector<uint8_t> > ReportSequence;

/// sendKnob(state, momentary=true): knobReport(state), then knobReport(KnobState()).
ReportSequence momentaryKnobReports(const KnobState& state);
/// sendKnob(state, momentary=false) / sendKnobSelect(down): a single knobReport(state).
ReportSequence heldKnobReports(const KnobState& state);
/// sendMedia(index): mediaReport(index), then mediaReport(0).
ReportSequence mediaPressReports(int32_t index);
/// sendTelephony(index): telephonyReport(index), then telephonyReport(0).
ReportSequence telephonyPressReports(int32_t index);

// ---- BMW HU_ENTRYNAV2 ZBE3 iDrive controller ----

/// Hardware bitmask from BMW HU_ENTRYNAV2 ZBE3 iDrive controller (CAN/EvoIlm ZBE3 E5.01).
namespace zbe3 {
static const uint8_t kBtnMenu = 0x01U;
static const uint8_t kBtnBack = 0x02U;
static const uint8_t kBtnOption = 0x04U;
static const uint8_t kBtnMedia = 0x08U;
static const uint8_t kBtnCom = 0x40U;

static const uint8_t kDirUp = 0x01U;
static const uint8_t kDirRight = 0x02U;
static const uint8_t kDirDown = 0x04U;
static const uint8_t kDirLeft = 0x08U;
}  // namespace zbe3

struct Zbe3Event {
    uint8_t dir_mask;     // zbe3::kDir*: bit0=Up, bit1=Right, bit2=Down, bit3=Left
    bool center_pressed;
    uint8_t button_mask;  // zbe3::kBtn*
    int8_t rotary_delta;  // clockwise > 0, counter-clockwise < 0

    Zbe3Event() : dir_mask(0), center_pressed(false), button_mask(0), rotary_delta(0) {}
};

/// Maps one ZBE3 state snapshot (level semantics) onto CarPlay HID state:
///  - knob.select = center push, knob.home = MENU (0x01), knob.back = BACK (0x02);
///  - knob.wheel = rotary_delta + tilt, where tilt Up/Left = -1 and Down/Right = +1 each (reference
///    D-pad convention, CarPlayRemoteKeys.kt:67-76; opposite tilts cancel); knob.x = knob.y = 0
///    (the reference never drives its legacy X/Y axes, AirPlayHid.kt:112);
///  - media_index_out = MEDIA_PLAY_PAUSE while MEDIA (0x08) is held, else MEDIA_NONE;
///  - telephony_index_out = TELEPHONY_HOOK_SWITCH while COM (0x40) is held, else TELEPHONY_NONE;
///  - OPTION (0x04) is not mapped.
/// The session layer sends wheel movement as zbe3KnobReports(), button changes as heldKnobReports(),
/// and media/telephony on the rising edge as mediaPressReports()/telephonyPressReports().
void mapZbe3ToCarPlay(const Zbe3Event& hw,
                      KnobState& knob_out,
                      int32_t& media_index_out,
                      int32_t& telephony_index_out);

/// Knob reports for a mapped ZBE3 state: a non-zero wheel is sent as knobReport(state) followed by
/// the same state with wheel = 0 (held buttons stay held; with no button held this is exactly the
/// reference's momentary sequence); with wheel = 0 a single knobReport(state).
ReportSequence zbe3KnobReports(const KnobState& state);

// ---- Descriptor inspection (tests / /info sanity) ----

/// Lightweight structural validator for HID short-item descriptors.
struct DescriptorSummary {
    bool valid;
    bool has_relative_input;
    bool has_absolute_input;
    size_t input_item_count;

    DescriptorSummary()
        : valid(false),
          has_relative_input(false),
          has_absolute_input(false),
          input_item_count(0) {}
};

DescriptorSummary inspectDescriptor(const std::vector<uint8_t>& desc);

}  // namespace hid
}  // namespace carplay

#endif  // CARPLAY_AIRPLAY_HID_HPP
