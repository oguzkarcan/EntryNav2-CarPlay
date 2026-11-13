#include "carplay/airplay_hid.hpp"

namespace carplay {
namespace hid {

namespace {

uint8_t lo8(uint16_t v) { return static_cast<uint8_t>(v & 0xffU); }
uint8_t hi8(uint16_t v) { return static_cast<uint8_t>((v >> 8) & 0xffU); }

}  // namespace

std::vector<uint8_t> touchscreenDescriptor(uint16_t max_x, uint16_t max_y) {
    // Digitizer (0x0D) / Touch Screen (0x04):
    // Finger collection with Tip Switch (1 bit), 7-bit pad, and 16-bit Absolute X/Y.
    const uint8_t raw[] = {
        0x05, 0x0d,                    // Usage Page (Digitizer)
        0x09, 0x04,                    // Usage (Touch Screen)
        0xa1, 0x01,                    // Collection (Application)
        0x09, 0x22,                    //   Usage (Finger)
        0xa1, 0x02,                    //   Collection (Logical)
        0x09, 0x42,                    //     Usage (Tip Switch)
        0x15, 0x00,                    //     Logical Minimum (0)
        0x25, 0x01,                    //     Logical Maximum (1)
        0x75, 0x01,                    //     Report Size (1)
        0x95, 0x01,                    //     Report Count (1)
        0x81, kInputDataVarAbs,        //     Input (Data,Var,Abs)
        0x75, 0x07,                    //     Report Size (7) - padding
        0x95, 0x01,                    //     Report Count (1)
        0x81, kInputConst,             //     Input (Const)
        0x05, 0x01,                    //     Usage Page (Generic Desktop)
        0x15, 0x00,                    //     Logical Minimum (0)
        0x26, lo8(max_x), hi8(max_x),  //     Logical Maximum (max_x)
        0x75, 0x10,                    //     Report Size (16)
        0x95, 0x01,                    //     Report Count (1)
        0x09, 0x30,                    //     Usage (X)
        0x81, kInputDataVarAbs,        //     Input (Data,Var,Abs)
        0x26, lo8(max_y), hi8(max_y),  //     Logical Maximum (max_y)
        0x09, 0x31,                    //     Usage (Y)
        0x81, kInputDataVarAbs,        //     Input (Data,Var,Abs)
        0xc0,                          //   End Collection
        0xc0                           // End Collection
    };
    return std::vector<uint8_t>(raw, raw + sizeof(raw));
}

std::vector<uint8_t> knobDescriptor() {
    // Generic Desktop (0x01) / Game Pad or Multi-axis Controller (0x08) for CarPlay rotary knob:
    // Byte 0 bits 0..4: Up, Down, Left, Right, Select (Button 1)
    // Byte 1 bits 0..1: AC Home (0x0223), AC Back (0x0224)
    // Byte 2 int8_t:    Relative Wheel (-127..127)
    const uint8_t raw[] = {
        0x05, 0x01,              // Usage Page (Generic Desktop)
        0x09, 0x08,              // Usage (Multi-axis Controller)
        0xa1, 0x01,              // Collection (Application)
        0x05, 0x01,              //   Usage Page (Generic Desktop)
        0x09, 0x90,              //   Usage (D-Pad Up)
        0x09, 0x91,              //   Usage (D-Pad Down)
        0x09, 0x93,              //   Usage (D-Pad Left)
        0x09, 0x92,              //   Usage (D-Pad Right)
        0x05, 0x09,              //   Usage Page (Button)
        0x09, 0x01,              //   Usage (Button 1 - Select)
        0x15, 0x00,              //   Logical Minimum (0)
        0x25, 0x01,              //   Logical Maximum (1)
        0x75, 0x01,              //   Report Size (1)
        0x95, 0x05,              //   Report Count (5)
        0x81, kInputDataVarAbs,  //   Input (Data,Var,Abs)
        0x75, 0x03,              //   Report Size (3) - pad byte 0
        0x95, 0x01,              //   Report Count (1)
        0x81, kInputConst,       //   Input (Const)
        0x05, 0x0c,              //   Usage Page (Consumer)
        0x0a, 0x23, 0x02,        //   Usage (AC Home)
        0x0a, 0x24, 0x02,        //   Usage (AC Back)
        0x75, 0x01,              //   Report Size (1)
        0x95, 0x02,              //   Report Count (2)
        0x81, kInputDataVarAbs,  //   Input (Data,Var,Abs)
        0x75, 0x06,              //   Report Size (6) - pad byte 1
        0x95, 0x01,              //   Report Count (1)
        0x81, kInputConst,       //   Input (Const)
        0x05, 0x01,              //   Usage Page (Generic Desktop)
        0x09, 0x38,              //   Usage (Wheel)
        0x15, 0x81,              //   Logical Minimum (-127)
        0x25, 0x7f,              //   Logical Maximum (127)
        0x75, 0x08,              //   Report Size (8)
        0x95, 0x01,              //   Report Count (1)
        0x81, kInputDataVarRel,  //   Input (Data,Var,Rel)
        0xc0                     // End Collection
    };
    return std::vector<uint8_t>(raw, raw + sizeof(raw));
}

std::vector<uint8_t> mediaDescriptor() {
    // Consumer (0x0C) / Consumer Control (0x01): bits 0..4 correspond to Play..Previous.
    const uint8_t raw[] = {
        0x05, 0x0c,              // Usage Page (Consumer)
        0x09, 0x01,              // Usage (Consumer Control)
        0xa1, 0x01,              // Collection (Application)
        0x09, 0xb0,              //   Usage (Play)
        0x09, 0xb1,              //   Usage (Pause)
        0x09, 0xcd,              //   Usage (Play/Pause)
        0x09, 0xb5,              //   Usage (Scan Next Track)
        0x09, 0xb6,              //   Usage (Scan Previous Track)
        0x15, 0x00,              //   Logical Minimum (0)
        0x25, 0x01,              //   Logical Maximum (1)
        0x75, 0x01,              //   Report Size (1)
        0x95, 0x05,              //   Report Count (5)
        0x81, kInputDataVarAbs,  //   Input (Data,Var,Abs)
        0x75, 0x03,              //   Report Size (3) - padding
        0x95, 0x01,              //   Report Count (1)
        0x81, kInputConst,       //   Input (Const)
        0xc0                     // End Collection
    };
    return std::vector<uint8_t>(raw, raw + sizeof(raw));
}

std::vector<uint8_t> telephonyDescriptor() {
    // Telephony (0x0B) / Phone (0x01): bits 0..3 = Hook Switch, Flash, Drop, Phone Mute.
    const uint8_t raw[] = {
        0x05, 0x0b,              // Usage Page (Telephony)
        0x09, 0x01,              // Usage (Phone)
        0xa1, 0x01,              // Collection (Application)
        0x09, 0x20,              //   Usage (Hook Switch)
        0x09, 0x21,              //   Usage (Flash)
        0x09, 0x26,              //   Usage (Drop)
        0x09, 0x2f,              //   Usage (Phone Mute)
        0x15, 0x00,              //   Logical Minimum (0)
        0x25, 0x01,              //   Logical Maximum (1)
        0x75, 0x01,              //   Report Size (1)
        0x95, 0x04,              //   Report Count (4)
        0x81, kInputDataVarAbs,  //   Input (Data,Var,Abs)
        0x75, 0x04,              //   Report Size (4) - padding
        0x95, 0x01,              //   Report Count (1)
        0x81, kInputConst,       //   Input (Const)
        0xc0                     // End Collection
    };
    return std::vector<uint8_t>(raw, raw + sizeof(raw));
}

void normalizeTouchCoords(int32_t px,
                          int32_t py,
                          uint16_t screen_width,
                          uint16_t screen_height,
                          uint16_t& x_out,
                          uint16_t& y_out) {
    if (screen_width <= 1U) {
        x_out = 0;
    } else {
        int32_t cx = px;
        if (cx < 0) cx = 0;
        if (cx >= static_cast<int32_t>(screen_width)) {
            cx = static_cast<int32_t>(screen_width) - 1;
        }
        const uint64_t scaled = (static_cast<uint64_t>(cx) * kTouchAxisMax) /
                                static_cast<uint64_t>(screen_width - 1U);
        x_out = static_cast<uint16_t>(scaled);
    }

    if (screen_height <= 1U) {
        y_out = 0;
    } else {
        int32_t cy = py;
        if (cy < 0) cy = 0;
        if (cy >= static_cast<int32_t>(screen_height)) {
            cy = static_cast<int32_t>(screen_height) - 1;
        }
        const uint64_t scaled = (static_cast<uint64_t>(cy) * kTouchAxisMax) /
                                static_cast<uint64_t>(screen_height - 1U);
        y_out = static_cast<uint16_t>(scaled);
    }
}

std::vector<uint8_t> makeTouchReport(bool tip_down, uint16_t x, uint16_t y) {
    std::vector<uint8_t> report(5, 0);
    report[0] = tip_down ? 0x01U : 0x00U;
    report[1] = lo8(x);
    report[2] = hi8(x);
    report[3] = lo8(y);
    report[4] = hi8(y);
    return report;
}

std::vector<uint8_t> makeKnobReport(const KnobState& state) {
    std::vector<uint8_t> report(3, 0);
    uint8_t byte0 = 0;
    if (state.up) byte0 |= (1U << 0);
    if (state.down) byte0 |= (1U << 1);
    if (state.left) byte0 |= (1U << 2);
    if (state.right) byte0 |= (1U << 3);
    if (state.select) byte0 |= (1U << 4);

    uint8_t byte1 = 0;
    if (state.home) byte1 |= (1U << 0);
    if (state.back) byte1 |= (1U << 1);

    report[0] = byte0;
    report[1] = byte1;
    report[2] = static_cast<uint8_t>(state.wheel_delta);
    return report;
}

std::vector<uint8_t> makeMediaReport(MediaButton button) {
    uint8_t bits = 0;
    if (button >= MEDIA_PLAY && button <= MEDIA_PREVIOUS) {
        bits = static_cast<uint8_t>(1U << (static_cast<unsigned int>(button) - 1U));
    }
    return std::vector<uint8_t>(1, bits);
}

std::vector<uint8_t> makeTelephonyReport(uint8_t telephony_mask) {
    return std::vector<uint8_t>(1, static_cast<uint8_t>(telephony_mask & 0x0fU));
}

void mapZbe3ToCarPlay(const Zbe3Event& hw,
                      KnobState& knob_out,
                      MediaButton& media_out,
                      uint8_t& telephony_out) {
    knob_out = KnobState();
    knob_out.up = (hw.dir_mask & 0x01U) != 0;
    knob_out.right = (hw.dir_mask & 0x02U) != 0;
    knob_out.down = (hw.dir_mask & 0x04U) != 0;
    knob_out.left = (hw.dir_mask & 0x08U) != 0;
    knob_out.select = hw.center_pressed;
    knob_out.home = (hw.button_mask & zbe3::kBtnMenu) != 0;
    knob_out.back = (hw.button_mask & zbe3::kBtnBack) != 0;
    knob_out.wheel_delta = hw.rotary_delta;

    media_out = (hw.button_mask & zbe3::kBtnMedia) != 0 ? MEDIA_PLAY_PAUSE : MEDIA_NONE;
    telephony_out = (hw.button_mask & zbe3::kBtnCom) != 0 ? TELEPHONY_HOOK_SWITCH : TELEPHONY_NONE;
}

DescriptorSummary inspectDescriptor(const std::vector<uint8_t>& desc) {
    DescriptorSummary summary;
    if (desc.empty()) {
        return summary;
    }
    int depth = 0;
    size_t i = 0;
    while (i < desc.size()) {
        const uint8_t b = desc[i++];
        if (b == 0xfeU) {
            // Long item: [0xFE, data_size, tag, data...]
            if (i + 2 > desc.size()) return summary;
            const size_t data_size = desc[i];
            i += 2 + data_size;
            if (i > desc.size()) return summary;
            continue;
        }
        const uint8_t bsize_code = static_cast<uint8_t>(b & 0x03U);
        const size_t bsize = (bsize_code == 3U) ? 4U : static_cast<size_t>(bsize_code);
        const uint8_t btype = static_cast<uint8_t>((b >> 2) & 0x03U);
        const uint8_t btag = static_cast<uint8_t>((b >> 4) & 0x0fU);
        if (i + bsize > desc.size()) {
            return summary;
        }
        if (btype == 0U && btag == 0x0aU) {
            ++depth;  // Collection
        } else if (btype == 0U && btag == 0x0cU) {
            --depth;  // End Collection
            if (depth < 0) return summary;
        } else if (btype == 0U && btag == 0x08U && bsize >= 1U) {
            // Main Input item
            const uint8_t flags = desc[i];
            ++summary.input_item_count;
            if ((flags & kInputConst) == 0) {
                if ((flags & 0x04U) != 0) {
                    summary.has_relative_input = true;
                } else {
                    summary.has_absolute_input = true;
                }
            }
        }
        i += bsize;
    }
    summary.valid = (depth == 0);
    return summary;
}

}  // namespace hid
}  // namespace carplay
