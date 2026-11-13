#ifndef CARPLAY_AIRPLAY_HID_HPP
#define CARPLAY_AIRPLAY_HID_HPP

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace carplay {
namespace hid {

/// Standard AirPlay / CarPlay HID device UIDs advertised in /info and /command.
static const uint32_t kUidTouchscreen = 0x2a2a2a2aU;
static const uint32_t kUidKnob = 0x2a2a2a2bU;
static const uint32_t kUidMedia = 0x2a2a2a2cU;
static const uint32_t kUidTelephony = 0x2a2a2a2dU;

static const uint16_t kTouchAxisMax = 32767U;

/// USB HID short-item Main Input flag values verified against AirPlay HID semantics.
static const uint8_t kInputDataVarAbs = 0x02U;
static const uint8_t kInputDataVarRel = 0x06U;
static const uint8_t kInputDataAryAbs = 0x00U;
static const uint8_t kInputConst = 0x01U;

enum MediaButton {
    MEDIA_NONE = 0,
    MEDIA_PLAY = 1,
    MEDIA_PAUSE = 2,
    MEDIA_PLAY_PAUSE = 3,
    MEDIA_NEXT = 4,
    MEDIA_PREVIOUS = 5
};

enum TelephonyAction {
    TELEPHONY_NONE = 0,
    TELEPHONY_HOOK_SWITCH = 1 << 0,
    TELEPHONY_FLASH = 1 << 1,
    TELEPHONY_DROP = 1 << 2,
    TELEPHONY_MUTE = 1 << 3
};

struct KnobState {
    bool up;
    bool down;
    bool left;
    bool right;
    bool select;
    bool home;
    bool back;
    int8_t wheel_delta;

    KnobState()
        : up(false),
          down(false),
          left(false),
          right(false),
          select(false),
          home(false),
          back(false),
          wheel_delta(0) {}
};

/// Hardware bitmask from BMW HU_ENTRYNAV2 ZBE3 iDrive controller (CAN/EvoIlm ZBE3 E5.01).
namespace zbe3 {
static const uint8_t kBtnMenu = 0x01U;
static const uint8_t kBtnBack = 0x02U;
static const uint8_t kBtnOption = 0x04U;
static const uint8_t kBtnMedia = 0x08U;
static const uint8_t kBtnCom = 0x40U;
}  // namespace zbe3

struct Zbe3Event {
    uint8_t dir_mask;     // bit0=Up, bit1=Right, bit2=Down, bit3=Left
    bool center_pressed;
    uint8_t button_mask;  // zbe3::kBtn*
    int8_t rotary_delta;  // clockwise > 0, counter-clockwise < 0

    Zbe3Event() : dir_mask(0), center_pressed(false), button_mask(0), rotary_delta(0) {}
};

/// Returns canonical CarPlay HID descriptors for each virtual HID device.
std::vector<uint8_t> touchscreenDescriptor(uint16_t max_x = kTouchAxisMax,
                                           uint16_t max_y = kTouchAxisMax);
std::vector<uint8_t> knobDescriptor();
std::vector<uint8_t> mediaDescriptor();
std::vector<uint8_t> telephonyDescriptor();

/// Clamps and scales pixel coordinates [0..width) x [0..height) to HID logical [0..max_axis].
void normalizeTouchCoords(int32_t px,
                          int32_t py,
                          uint16_t screen_width,
                          uint16_t screen_height,
                          uint16_t& x_out,
                          uint16_t& y_out);

/// Builds a 5-byte single-touch HID report: [buttons(tip), x_lo, x_hi, y_lo, y_hi].
std::vector<uint8_t> makeTouchReport(bool tip_down, uint16_t x, uint16_t y);

/// Builds a 3-byte CarPlay knob/navigation HID report:
/// [dpad_buttons(bits0..4=U,D,L,R,Select), ac_buttons(bit0=Home,bit1=Back), int8_t wheel_delta].
std::vector<uint8_t> makeKnobReport(const KnobState& state);

/// Builds a 1-byte Consumer Control media HID report bitmask (Play/Pause/PlayPause/Next/Previous).
std::vector<uint8_t> makeMediaReport(MediaButton button);

/// Builds a 1-byte Telephony HID report from TelephonyAction bitmask.
std::vector<uint8_t> makeTelephonyReport(uint8_t telephony_mask);

/// Maps BMW HU_ENTRYNAV2 ZBE3 iDrive hardware state into CarPlay Knob + Media/Telephony side actions.
void mapZbe3ToCarPlay(const Zbe3Event& hw,
                      KnobState& knob_out,
                      MediaButton& media_out,
                      uint8_t& telephony_out);

/// Lightweight structural validator for HID short-item descriptors used by tests & /info setup.
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
