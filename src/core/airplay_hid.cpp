#include "carplay/airplay_hid.hpp"

#include <math.h>

namespace carplay {
namespace hid {

namespace {

const uint8_t kInputConst = 0x01U;
const uint8_t kInputRelative = 0x04U;

uint8_t lo8(int32_t v) { return static_cast<uint8_t>(static_cast<uint32_t>(v) & 0xffU); }
uint8_t hi8(int32_t v) { return static_cast<uint8_t>((static_cast<uint32_t>(v) >> 8) & 0xffU); }

int32_t clampI32(int32_t v, int32_t lo, int32_t hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

uint8_t clampAxis(int32_t v) {
    return static_cast<uint8_t>(static_cast<int8_t>(clampI32(v, kKnobAxisMin, kKnobAxisMax)));
}

void appendFinger(std::vector<uint8_t>& out, int32_t x_max, int32_t y_max) {
    // AirPlayHid.fingerCollection (AirPlayHid.kt:97-104).
    const uint8_t raw[] = {
        0x05, 0x0d,              // Usage Page (Digitizer)
        0x09, 0x22,              // Usage (Finger)
        0xa1, 0x02,              // Collection (Logical)
        0x09, 0x38,              //   Usage (Transducer Index) - contact id byte
        0x75, 0x08,              //   Report Size (8)
        0x95, 0x01,              //   Report Count (1)
        0x81, 0x02,              //   Input (Data,Var,Abs)
        0x15, 0x00,              //   Logical Minimum (0)
        0x25, 0x01,              //   Logical Maximum (1)
        0x09, 0x33,              //   Usage (Touch)
        0x75, 0x01,              //   Report Size (1)
        0x95, 0x01,              //   Report Count (1)
        0x81, 0x02,              //   Input (Data,Var,Abs)
        0x95, 0x07,              //   Report Count (7) - padding
        0x81, 0x03,              //   Input (Const,Var,Abs)
        0x05, 0x01,              //   Usage Page (Generic Desktop)
        0x26, lo8(x_max), hi8(x_max),  // Logical Maximum (width pixels)
        0x09, 0x30,              //   Usage (X)
        0x75, 0x10,              //   Report Size (16)
        0x95, 0x01,              //   Report Count (1)
        0x81, 0x02,              //   Input (Data,Var,Abs)
        0x26, lo8(y_max), hi8(y_max),  // Logical Maximum (height pixels)
        0x09, 0x31,              //   Usage (Y)
        0x81, 0x02,              //   Input (Data,Var,Abs)
        0xc0                     // End Collection
    };
    out.insert(out.end(), raw, raw + sizeof(raw));
}

void writeU16Le(std::vector<uint8_t>& out, size_t offset, int32_t v) {
    out[offset] = lo8(v);
    out[offset + 1] = hi8(v);
}

ReportSequence pair(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    ReportSequence seq;
    seq.push_back(a);
    seq.push_back(b);
    return seq;
}

}  // namespace

std::string uidString(uint32_t uid) {
    static const char kDigits[] = "0123456789abcdef";
    if (uid == 0) return "0";
    std::string out;
    while (uid != 0) {
        out.insert(out.begin(), kDigits[uid & 0x0fU]);
        uid >>= 4;
    }
    return out;
}

std::vector<uint8_t> touchscreenDescriptor(int32_t width_pixels, int32_t height_pixels) {
    // AirPlayHid.multitouchDescriptor (AirPlayHid.kt:89-95).
    std::vector<uint8_t> out;
    const uint8_t head[] = {
        0x05, 0x0d,  // Usage Page (Digitizer)
        0x09, 0x04,  // Usage (Touch Screen)
        0xa1, 0x01   // Collection (Application)
    };
    out.insert(out.end(), head, head + sizeof(head));
    for (size_t k = 0; k < kTouchContacts; ++k) {
        appendFinger(out, width_pixels, height_pixels);
    }
    out.push_back(0xc0);  // End Collection
    return out;
}

std::vector<uint8_t> knobDescriptor() {
    // AirPlayHid.knobDescriptor (AirPlayHid.kt:106-115).
    const uint8_t raw[] = {
        0x05, 0x01,        // Usage Page (Generic Desktop)
        0x09, 0x08,        // Usage (Multi-axis Controller)
        0xa1, 0x01,        // Collection (Application)
        0x05, 0x09,        //   Usage Page (Button)
        0x09, 0x01,        //   Usage (Button 1) - select
        0x15, 0x00,        //   Logical Minimum (0)
        0x25, 0x01,        //   Logical Maximum (1)
        0x75, 0x01,        //   Report Size (1)
        0x95, 0x01,        //   Report Count (1)
        0x81, 0x02,        //   Input (Data,Var,Abs)
        0x05, 0x0c,        //   Usage Page (Consumer)
        0x0a, 0x23, 0x02,  //   Usage (AC Home)
        0x0a, 0x24, 0x02,  //   Usage (AC Back)
        0x95, 0x02,        //   Report Count (2)
        0x81, 0x02,        //   Input (Data,Var,Abs)
        0x95, 0x05,        //   Report Count (5) - padding
        0x81, 0x01,        //   Input (Const)
        0x05, 0x01,        //   Usage Page (Generic Desktop)
        0x09, 0x01,        //   Usage (Pointer)
        0xa1, 0x00,        //   Collection (Physical)
        0x09, 0x30,        //     Usage (X)
        0x09, 0x31,        //     Usage (Y)
        0x15, 0x81,        //     Logical Minimum (-127)
        0x25, 0x7f,        //     Logical Maximum (127)
        0x75, 0x08,        //     Report Size (8)
        0x95, 0x02,        //     Report Count (2)
        0x81, 0x02,        //     Input (Data,Var,Abs)
        0xc0,              //   End Collection
        0x09, 0x38,        //   Usage (Wheel)
        0x15, 0x81,        //   Logical Minimum (-127)
        0x25, 0x7f,        //   Logical Maximum (127)
        0x75, 0x08,        //   Report Size (8)
        0x95, 0x01,        //   Report Count (1)
        0x81, 0x06,        //   Input (Data,Var,Rel)
        0xc0               // End Collection
    };
    return std::vector<uint8_t>(raw, raw + sizeof(raw));
}

std::vector<uint8_t> mediaDescriptor() {
    // AirPlayHid.mediaDescriptor (AirPlayHid.kt:117-123).
    const uint8_t raw[] = {
        0x05, 0x0c,        // Usage Page (Consumer)
        0x09, 0x01,        // Usage (Consumer Control)
        0xa1, 0x01,        // Collection (Application)
        0x15, 0x00,        //   Logical Minimum (0)
        0x25, 0x06,        //   Logical Maximum (6)
        0x05, 0x0c,        //   Usage Page (Consumer)
        0x0a, 0x00, 0x00,  //   Usage (0x0000)          index 0
        0x0a, 0xb0, 0x00,  //   Usage (Play)            index 1
        0x0a, 0xb1, 0x00,  //   Usage (Pause)           index 2
        0x0a, 0xcd, 0x00,  //   Usage (Play/Pause)      index 3
        0x0a, 0xb5, 0x00,  //   Usage (Scan Next)       index 4
        0x0a, 0xb6, 0x00,  //   Usage (Scan Previous)   index 5
        0x0a, 0x9e, 0x02,  //   Usage (0x029e)          index 6
        0x75, 0x08,        //   Report Size (8)
        0x95, 0x01,        //   Report Count (1)
        0x81, 0x00,        //   Input (Data,Array,Abs)
        0xc0               // End Collection
    };
    return std::vector<uint8_t>(raw, raw + sizeof(raw));
}

std::vector<uint8_t> telephonyDescriptor() {
    // AirPlayHid.telephonyDescriptor (AirPlayHid.kt:125-133).
    const uint8_t raw[] = {
        0x05, 0x0b,  // Usage Page (Telephony)
        0x09, 0x07,  // Usage (Programmable Button)
        0xa1, 0x01,  // Collection (Application)
        0x15, 0x00,  //   Logical Minimum (0)
        0x25, 0x11,  //   Logical Maximum (17)
        0x05, 0x0b,  //   Usage Page (Telephony)
        0x09, 0x00,  //   Usage (0x00)            index 0
        0x09, 0x20,  //   Usage (Hook Switch)     index 1
        0x09, 0x21,  //   Usage (Flash)           index 2
        0x09, 0x26,  //   Usage (Drop)            index 3
        0x09, 0x2f,  //   Usage (Phone Mute)      index 4
        0x09, 0xb0,  //   Usage (Phone Key 0)     index 5
        0x09, 0xb1,
        0x09, 0xb2,
        0x09, 0xb3,
        0x09, 0xb4,
        0x09, 0xb5,
        0x09, 0xb6,
        0x09, 0xb7,
        0x09, 0xb8,
        0x09, 0xb9,  //   Usage (Phone Key 9)     index 14
        0x09, 0xba,  //   Usage (Phone Key Star)  index 15
        0x09, 0xbb,  //   Usage (Phone Key Pound) index 16
        0x05, 0x07,  //   Usage Page (Keyboard)
        0x09, 0x2a,  //   Usage (Backspace)       index 17
        0x75, 0x08,  //   Report Size (8)
        0x95, 0x01,  //   Report Count (1)
        0x81, 0x00,  //   Input (Data,Array,Abs)
        0xc0         // End Collection
    };
    return std::vector<uint8_t>(raw, raw + sizeof(raw));
}

int32_t pixelFromNormalized(double normalized, int32_t extent_pixels) {
    const double v = normalized * static_cast<double>(extent_pixels);
    if (!(v > 0.0)) return 0;  // also NaN
    const double r = floor(v + 0.5);
    if (r >= 2147483647.0) return 2147483647;
    return static_cast<int32_t>(r);
}

std::vector<uint8_t> touchReport(const std::vector<TouchContact>& slotted_contacts,
                                 int32_t width_pixels,
                                 int32_t height_pixels) {
    // AirPlayHid.touchReport (AirPlayHid.kt:44-55).
    std::vector<uint8_t> report(kTouchReportBytes, 0);
    const int32_t x_max = width_pixels > 0 ? width_pixels : 0;
    const int32_t y_max = height_pixels > 0 ? height_pixels : 0;
    for (size_t slot = 0; slot < kTouchContacts; ++slot) {
        const size_t offset = slot * kTouchBytesPerFinger;
        report[offset] = static_cast<uint8_t>(slot);
        const TouchContact* contact = NULL;
        for (size_t k = 0; k < slotted_contacts.size(); ++k) {
            if (slotted_contacts[k].id == static_cast<int32_t>(slot)) {
                contact = &slotted_contacts[k];
                break;
            }
        }
        if (contact == NULL) continue;
        report[offset + 1] = contact->down ? 0x01U : 0x00U;
        writeU16Le(report, offset + 2, clampI32(contact->x, 0, x_max));
        writeU16Le(report, offset + 4, clampI32(contact->y, 0, y_max));
    }
    return report;
}

TouchSlots::TouchSlots(size_t slots)
    : pointer_used_(slots, false), pointers_(slots, 0), held_used_(slots, false), held_(slots) {}

void TouchSlots::reset() {
    for (size_t s = 0; s < pointer_used_.size(); ++s) {
        pointer_used_[s] = false;
        pointers_[s] = 0;
        held_used_[s] = false;
        held_[s] = TouchContact();
    }
}

std::vector<TouchContact> TouchSlots::assign(const std::vector<TouchContact>& contacts) {
    // AirPlayTouchSlots.assign (AirPlayTouchSlots.kt:14-34).
    const size_t n = pointer_used_.size();
    std::vector<bool> report_used(n, false);
    std::vector<TouchContact> report(n);
    for (size_t k = 0; k < contacts.size(); ++k) {
        const TouchContact& c = contacts[k];
        size_t slot = n;
        for (size_t s = 0; s < n; ++s) {
            if (pointer_used_[s] && pointers_[s] == c.id) {
                slot = s;
                break;
            }
        }
        if (slot == n && c.down) {
            for (size_t s = 0; s < n; ++s) {
                if (!pointer_used_[s]) {
                    slot = s;
                    break;
                }
            }
        }
        if (slot == n) continue;
        pointer_used_[slot] = true;
        pointers_[slot] = c.id;
        report_used[slot] = true;
        report[slot] = TouchContact(static_cast<int32_t>(slot), c.down, c.x, c.y);
    }
    std::vector<TouchContact> out;
    for (size_t s = 0; s < n; ++s) {
        if (!report_used[s] && held_used_[s]) {
            report[s] = held_[s];
            report[s].down = false;
            report_used[s] = true;
        }
        if (report_used[s] && report[s].down) {
            held_used_[s] = true;
            held_[s] = report[s];
        } else {
            held_used_[s] = false;
            held_[s] = TouchContact();
            pointer_used_[s] = false;
            pointers_[s] = 0;
        }
        if (report_used[s]) out.push_back(report[s]);
    }
    return out;
}

std::vector<uint8_t> knobReport(const KnobState& state) {
    // AirPlayHid.knobReport (AirPlayHid.kt:57-68).
    std::vector<uint8_t> report(kKnobReportBytes, 0);
    uint8_t buttons = 0;
    if (state.select) buttons |= 0x01U;
    if (state.home) buttons |= 0x02U;
    if (state.back) buttons |= 0x04U;
    report[0] = buttons;
    report[1] = clampAxis(state.x);
    report[2] = clampAxis(state.y);
    report[3] = clampAxis(state.wheel);
    return report;
}

std::vector<uint8_t> mediaReport(int32_t index) { return std::vector<uint8_t>(1, lo8(index)); }

std::vector<uint8_t> telephonyReport(int32_t index) { return std::vector<uint8_t>(1, lo8(index)); }

ReportSequence momentaryKnobReports(const KnobState& state) {
    return pair(knobReport(state), knobReport(KnobState()));
}

ReportSequence heldKnobReports(const KnobState& state) {
    return ReportSequence(1, knobReport(state));
}

ReportSequence mediaPressReports(int32_t index) {
    return pair(mediaReport(index), mediaReport(MEDIA_NONE));
}

ReportSequence telephonyPressReports(int32_t index) {
    return pair(telephonyReport(index), telephonyReport(TELEPHONY_NONE));
}

void mapZbe3ToCarPlay(const Zbe3Event& hw,
                      KnobState& knob_out,
                      int32_t& media_index_out,
                      int32_t& telephony_index_out) {
    knob_out = KnobState();
    knob_out.select = hw.center_pressed;
    knob_out.home = (hw.button_mask & zbe3::kBtnMenu) != 0;
    knob_out.back = (hw.button_mask & zbe3::kBtnBack) != 0;

    // Reference D-pad convention (CarPlayRemoteKeys.kt:67-76): Up/Left -> wheel -1,
    // Down/Right -> wheel +1. CarPlay's non-touch focus model is rotary-first
    // (CarPlayRemoteKeys.kt:12-13) and "CarPlay moves its focus only when the knob turns; x/y
    // nudges pan a focused map instead" (common/.../WheelKeyService.kt:392). The legacy X/Y axes
    // stay 0 (AirPlayHid.kt:112).
    int32_t tilt = 0;
    if ((hw.dir_mask & zbe3::kDirUp) != 0) --tilt;
    if ((hw.dir_mask & zbe3::kDirLeft) != 0) --tilt;
    if ((hw.dir_mask & zbe3::kDirDown) != 0) ++tilt;
    if ((hw.dir_mask & zbe3::kDirRight) != 0) ++tilt;
    // Rotation: clockwise = forward = +1, like the wheel's NEXT (WheelKeyService.kt:394-395).
    knob_out.wheel = static_cast<int32_t>(hw.rotary_delta) + tilt;

    media_index_out = (hw.button_mask & zbe3::kBtnMedia) != 0 ? MEDIA_PLAY_PAUSE : MEDIA_NONE;
    telephony_index_out =
        (hw.button_mask & zbe3::kBtnCom) != 0 ? TELEPHONY_HOOK_SWITCH : TELEPHONY_NONE;
}

ReportSequence zbe3KnobReports(const KnobState& state) {
    if (state.wheel == 0) return heldKnobReports(state);
    KnobState settled = state;
    settled.wheel = 0;
    return pair(knobReport(state), knobReport(settled));
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
                if ((flags & kInputRelative) != 0) {
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
