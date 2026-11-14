// Exact-byte tests for carplay::hid against the reference
// DiPlay-main/shared/src/main/java/com/shilapi/xcertplay/airplay/AirPlayHid.kt, AirPlayTouchSlots.kt,
// CarPlayMediaButton.kt and their unit tests (AirPlayHidInputSemanticsTest.kt,
// AirPlayTouchSlotsTest.kt, CarPlayMediaButtonTest.kt).

#include "carplay/airplay_hid.hpp"

#include <math.h>

#include "test_support.hpp"

using namespace carplay::hid;
using test_support::hexToBytes;

namespace {

// Finger collection from AirPlayHid.kt:97-104 with the X/Y logical maximum bytes given as hex.
std::string fingerHex(const char* x_max_le, const char* y_max_le) {
    return std::string("050d0922a102") +  // Usage Page (Digitizer), Usage (Finger), Collection (Logical)
           "0938" "7508" "9501" "8102" +   // Usage 0x38, Report Size 8, Count 1, Input (Data,Var,Abs)
           "1500" "2501" "0933" "7501" "9501" "8102" +  // Touch bit
           "9507" "8103" +                 // 7 padding bits
           "0501" "26" + x_max_le + "0930" "7510" "9501" "8102" +
           "26" + y_max_le + "0931" "8102" +
           "c0";
}

std::string touchHex(const char* x_max_le, const char* y_max_le) {
    const std::string f = fingerHex(x_max_le, y_max_le);
    return "050d0904a101" + f + f + "c0";
}

const char* const kKnobHex =
    "0501" "0908" "a101"
    "0509" "0901" "1500" "2501" "7501" "9501" "8102"
    "050c" "0a2302" "0a2402" "9502" "8102"
    "9505" "8101"
    "0501" "0901" "a100"
    "0930" "0931" "1581" "257f" "7508" "9502" "8102" "c0"
    "0938" "1581" "257f" "7508" "9501" "8106" "c0";

const char* const kMediaHex =
    "050c" "0901" "a101" "1500" "2506" "050c"
    "0a0000" "0ab000" "0ab100" "0acd00" "0ab500" "0ab600" "0a9e02"
    "7508" "9501" "8100" "c0";

const char* const kTelephonyHex =
    "050b" "0907" "a101" "1500" "2511" "050b"
    "0900" "0920" "0921" "0926" "092f"
    "09b0" "09b1" "09b2" "09b3" "09b4" "09b5" "09b6" "09b7" "09b8" "09b9" "09ba" "09bb"
    "0507" "092a"
    "7508" "9501" "8100" "c0";

// HID short-item field decoder, port of AirPlayHidInputSemanticsTest.inputFields.
struct InputField {
    uint32_t page;
    std::vector<uint32_t> usages;
    uint32_t size;
    uint32_t count;
    uint32_t flags;
};

std::vector<InputField> inputFields(const std::vector<uint8_t>& d) {
    std::vector<InputField> fields;
    std::vector<uint32_t> usages;
    uint32_t page = 0, report_size = 0, report_count = 0;
    size_t off = 0;
    while (off < d.size()) {
        const uint32_t prefix = d[off++];
        const size_t size = (prefix & 3U) == 3U ? 4U : (prefix & 3U);
        uint32_t value = 0;
        for (size_t b = 0; b < size && off < d.size(); ++b) {
            value |= static_cast<uint32_t>(d[off++]) << (8U * b);
        }
        const uint32_t type = (prefix >> 2) & 3U;
        const uint32_t tag = prefix >> 4;
        if (type == 1U) {
            if (tag == 0U) page = value;
            if (tag == 7U) report_size = value;
            if (tag == 9U) report_count = value;
        } else if (type == 2U) {
            if (tag == 0U) usages.push_back(value);
        } else if (type == 0U) {
            if (tag == 8U) {
                InputField f;
                f.page = page;
                f.usages = usages;
                f.size = report_size;
                f.count = report_count;
                f.flags = value;
                fields.push_back(f);
            }
            usages.clear();
        }
    }
    return fields;
}

std::vector<uint8_t> u8(const uint8_t* p, size_t n) { return std::vector<uint8_t>(p, p + n); }

TouchContact c(int32_t id, int32_t x, int32_t y, bool down = true) {
    return TouchContact(id, down, x, y);
}

std::vector<TouchContact> list() { return std::vector<TouchContact>(); }
std::vector<TouchContact> list(const TouchContact& a) { return std::vector<TouchContact>(1, a); }
std::vector<TouchContact> list(const TouchContact& a, const TouchContact& b) {
    std::vector<TouchContact> v;
    v.push_back(a);
    v.push_back(b);
    return v;
}
std::vector<TouchContact> list(const TouchContact& a, const TouchContact& b, const TouchContact& d) {
    std::vector<TouchContact> v = list(a, b);
    v.push_back(d);
    return v;
}

bool sameContacts(const std::vector<TouchContact>& e, const std::vector<TouchContact>& a) {
    return e == a;
}

}  // namespace

// ---------------- Descriptors ----------------

TEST_CASE(touchDescriptorMatchesReferenceForDisplaySizes) {
    // 800x480: 0x0320 / 0x01e0.
    CHECK_BYTES_EQ(hexToBytes(touchHex("2003", "e001")), touchscreenDescriptor(800, 480));
    // 1280x480: 0x0500 / 0x01e0.
    CHECK_BYTES_EQ(hexToBytes(touchHex("0005", "e001")), touchscreenDescriptor(1280, 480));
    // 1440x540: 0x05a0 / 0x021c.
    CHECK_BYTES_EQ(hexToBytes(touchHex("a005", "1c02")), touchscreenDescriptor(1440, 540));
    // 1920x1080 (AirPlayHidInputSemanticsTest): 0x0780 / 0x0438.
    CHECK_BYTES_EQ(hexToBytes(touchHex("8007", "3804")), touchscreenDescriptor(1920, 1080));
    CHECK_EQ(static_cast<size_t>(109), touchscreenDescriptor(800, 480).size());
    // Like Kotlin `xMax and 0xff, (xMax shr 8) and 0xff`: only the low 16 bits are encoded.
    CHECK_BYTES_EQ(hexToBytes(touchHex("3412", "0000")), touchscreenDescriptor(0x51234, 0x10000));
}

TEST_CASE(knobMediaTelephonyDescriptorsMatchReference) {
    CHECK_BYTES_EQ(hexToBytes(kKnobHex), knobDescriptor());
    CHECK_BYTES_EQ(hexToBytes(kMediaHex), mediaDescriptor());
    CHECK_BYTES_EQ(hexToBytes(kTelephonyHex), telephonyDescriptor());
    CHECK_EQ(static_cast<size_t>(70), knobDescriptor().size());
    CHECK_EQ(static_cast<size_t>(40), mediaDescriptor().size());
    CHECK_EQ(static_cast<size_t>(57), telephonyDescriptor().size());
}

TEST_CASE(touchscreenCoordinatesAreAbsoluteSixteenBitForBothContacts) {
    // AirPlayHidInputSemanticsTest.touchscreenCoordinatesRemainAbsoluteSixteenBitValuesForBothContacts
    const std::vector<InputField> all = inputFields(touchscreenDescriptor(1920, 1080));
    std::vector<uint32_t> axes;
    for (size_t k = 0; k < all.size(); ++k) {
        const InputField& f = all[k];
        bool xy = false;
        for (size_t u = 0; u < f.usages.size(); ++u) xy = xy || f.usages[u] == 0x30U || f.usages[u] == 0x31U;
        if (f.page != 1U || !xy) continue;
        CHECK_EQ(16U, f.size);
        CHECK_EQ(1U, f.count);
        CHECK_EQ(2U, f.flags);
        REQUIRE(f.usages.size() == 1);
        axes.push_back(f.usages[0]);
    }
    REQUIRE(axes.size() == 4);
    CHECK(axes[0] == 0x30U && axes[1] == 0x31U && axes[2] == 0x30U && axes[3] == 0x31U);
    // Fields total 2 x 6 bytes = the 12-byte report.
    uint32_t bits = 0;
    for (size_t k = 0; k < all.size(); ++k) bits += all[k].size * all[k].count;
    CHECK_EQ(static_cast<uint32_t>(kTouchReportBytes * 8U), bits);
}

TEST_CASE(knobCoordinatesAbsoluteWheelRelative) {
    // AirPlayHidInputSemanticsTest.legacyKnobCoordinatesStayAbsoluteWhileWheelMovementRemainsRelative
    const std::vector<InputField> all = inputFields(knobDescriptor());
    int coords = 0, wheels = 0;
    uint32_t bits = 0;
    for (size_t k = 0; k < all.size(); ++k) {
        const InputField& f = all[k];
        bits += f.size * f.count;
        if (f.page == 1U && f.usages.size() == 2 && f.usages[0] == 0x30U && f.usages[1] == 0x31U) {
            ++coords;
            CHECK_EQ(2U, f.flags);
            CHECK_EQ(8U, f.size);
            CHECK_EQ(2U, f.count);
        }
        if (f.page == 1U && f.usages.size() == 1 && f.usages[0] == 0x38U) {
            ++wheels;
            CHECK_EQ(6U, f.flags);
            CHECK_EQ(8U, f.size);
            CHECK_EQ(1U, f.count);
        }
    }
    CHECK_EQ(1, coords);
    CHECK_EQ(1, wheels);
    CHECK_EQ(static_cast<uint32_t>(kKnobReportBytes * 8U), bits);
    const DescriptorSummary s = inspectDescriptor(knobDescriptor());
    CHECK(s.valid && s.has_absolute_input && s.has_relative_input);
}

TEST_CASE(mediaAndTelephonyAreOneByteArraySelectors) {
    const std::vector<InputField> m = inputFields(mediaDescriptor());
    REQUIRE(m.size() == 1);
    CHECK_EQ(8U, m[0].size);
    CHECK_EQ(1U, m[0].count);
    CHECK_EQ(0U, m[0].flags);
    CHECK_EQ(static_cast<size_t>(kMediaLogicalMax + 1), m[0].usages.size());
    const std::vector<InputField> t = inputFields(telephonyDescriptor());
    REQUIRE(t.size() == 1);
    CHECK_EQ(8U, t[0].size);
    CHECK_EQ(1U, t[0].count);
    CHECK_EQ(0U, t[0].flags);
    CHECK_EQ(static_cast<size_t>(kTelephonyLogicalMax + 1), t[0].usages.size());
    CHECK(inspectDescriptor(mediaDescriptor()).valid);
    CHECK(inspectDescriptor(telephonyDescriptor()).valid);
}

TEST_CASE(uidStringIsLowercaseHexWithoutPrefix) {
    CHECK_EQ(std::string("2a2a2a2a"), uidString(kUidTouchscreen));
    CHECK_EQ(std::string("2a2a2a2b"), uidString(kUidKnob));
    CHECK_EQ(std::string("2a2a2a2c"), uidString(kUidMedia));
    CHECK_EQ(std::string("2a2a2a2d"), uidString(kUidTelephony));
    CHECK_EQ(std::string("0"), uidString(0));
    CHECK_EQ(std::string("abc"), uidString(0xabcU));
}

// ---------------- Touch reports ----------------

TEST_CASE(touchContactGoesInTheSlotItsIdNames) {
    // AirPlayTouchSlotsTest.eachContactGoesInTheSlotItsIdNames
    const uint8_t exp[] = {0, 0, 0, 0, 0, 0, 1, 1, 0x2c, 0x01, 0x90, 0x01};
    CHECK_BYTES_EQ(u8(exp, sizeof(exp)), touchReport(list(c(1, 300, 400)), 800, 480));
    // No contacts: both slots up at (0,0), slot bytes still set.
    const uint8_t none[] = {0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0};
    CHECK_BYTES_EQ(u8(none, sizeof(none)), touchReport(list(), 800, 480));
    // Two contacts, released slot keeps its coordinates; ids outside 0..1 are ignored.
    const uint8_t two[] = {0, 1, 0x20, 0x03, 0xe0, 0x01, 1, 0, 0x0a, 0x00, 0x14, 0x00};
    CHECK_BYTES_EQ(u8(two, sizeof(two)),
                   touchReport(list(c(1, 10, 20, false), c(0, 800, 480), c(7, 5, 5)), 800, 480));
    // First match wins for a duplicated id.
    const uint8_t dup[] = {0, 1, 0x01, 0x00, 0x02, 0x00, 1, 0, 0, 0, 0, 0};
    CHECK_BYTES_EQ(u8(dup, sizeof(dup)), touchReport(list(c(0, 1, 2), c(0, 3, 4)), 800, 480));
}

TEST_CASE(touchCoordinatesClampAtDisplayEdges) {
    // Below 0 -> 0 (reference coerceAtLeast(0.0)); above the logical max -> the max.
    const uint8_t lo[] = {0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0};
    CHECK_BYTES_EQ(u8(lo, sizeof(lo)), touchReport(list(c(0, -5, -1)), 800, 480));
    const uint8_t hi[] = {0, 1, 0x20, 0x03, 0xe0, 0x01, 1, 0, 0, 0, 0, 0};
    CHECK_BYTES_EQ(u8(hi, sizeof(hi)), touchReport(list(c(0, 900, 70000)), 800, 480));
    const uint8_t wide[] = {0, 1, 0x00, 0x05, 0xe0, 0x01, 1, 0, 0, 0, 0, 0};
    CHECK_BYTES_EQ(u8(wide, sizeof(wide)), touchReport(list(c(0, 1280, 480)), 1280, 480));
    const uint8_t edge[] = {0, 1, 0xff, 0x04, 0xdf, 0x01, 1, 0, 0, 0, 0, 0};
    CHECK_BYTES_EQ(u8(edge, sizeof(edge)), touchReport(list(c(0, 1279, 479)), 1280, 480));
}

TEST_CASE(normalizedCoordinatesRoundLikeTheReference) {
    // AirPlaySession.sendTouch scales 0..1 by the display pixels; touchReport rounds (Math.round).
    CHECK_EQ(400, pixelFromNormalized(0.5, 800));
    CHECK_EQ(800, pixelFromNormalized(1.0, 800));
    CHECK_EQ(0, pixelFromNormalized(0.0, 800));
    CHECK_EQ(0, pixelFromNormalized(-0.25, 800));
    CHECK_EQ(1, pixelFromNormalized(0.25, 2));         // exactly 0.5 rounds up (Math.round)
    CHECK_EQ(2, pixelFromNormalized(0.75, 2));         // 1.5 -> 2
    CHECK_EQ(0, pixelFromNormalized(0.0005, 800));     // 0.4
    CHECK_EQ(240, pixelFromNormalized(0.5, 480));
    CHECK_EQ(0, pixelFromNormalized(sqrt(-1.0), 800));  // NaN
    CHECK_EQ(2147483647, pixelFromNormalized(1e12, 800));
}

// ---------------- Touch slots (AirPlayTouchSlotsTest.kt) ----------------

TEST_CASE(theFingerThatStaysKeepsItsSlotAndTheOtherIsReleasedWhereItWas) {
    TouchSlots slots(2);
    CHECK(sameContacts(list(c(0, 600, 500)), slots.assign(list(c(0, 600, 500)))));
    CHECK(sameContacts(list(c(0, 600, 500), c(1, 400, 300)),
                       slots.assign(list(c(0, 600, 500), c(1, 400, 300)))));
    // ACTION_POINTER_UP for pointer 0.
    CHECK(sameContacts(list(c(0, 550, 450, false), c(1, 420, 350)),
                       slots.assign(list(c(0, 550, 450, false), c(1, 420, 350)))));
    // Pointer 1 moves on alone and keeps slot 1.
    CHECK(sameContacts(list(c(1, 430, 360)), slots.assign(list(c(1, 430, 360)))));
    CHECK(sameContacts(list(c(1, 430, 360, false)), slots.assign(list(c(1, 430, 360, false)))));
    CHECK(sameContacts(list(), slots.assign(list())));
}

TEST_CASE(anEmptyListReleasesEveryFingerWhereItWas) {
    TouchSlots slots(2);
    slots.assign(list(c(3, 100, 200), c(5, 700, 800)));
    CHECK(sameContacts(list(c(0, 100, 200, false), c(1, 700, 800, false)), slots.assign(list())));
    CHECK(sameContacts(list(), slots.assign(list())));
}

TEST_CASE(aFingerMissingFromTheNextEventIsReleasedWhereItWas) {
    TouchSlots slots(2);
    slots.assign(list(c(0, 100, 200), c(1, 700, 800)));
    CHECK(sameContacts(list(c(0, 150, 250), c(1, 700, 800, false)), slots.assign(list(c(0, 150, 250)))));
}

TEST_CASE(aThirdFingerWaitsForAFreeSlot) {
    TouchSlots slots(2);
    slots.assign(list(c(0, 100, 100), c(1, 200, 200)));
    CHECK(sameContacts(list(c(0, 100, 100), c(1, 200, 200)),
                       slots.assign(list(c(0, 100, 100), c(1, 200, 200), c(2, 300, 300)))));
    CHECK(sameContacts(list(c(0, 100, 100, false), c(1, 200, 200)),
                       slots.assign(list(c(0, 100, 100, false), c(1, 200, 200), c(2, 300, 300)))));
    CHECK(sameContacts(list(c(0, 300, 300), c(1, 200, 200)),
                       slots.assign(list(c(1, 200, 200), c(2, 300, 300)))));
}

TEST_CASE(aReleaseOfAFingerThatWasNeverReportedIsLeftOut) {
    TouchSlots slots(2);
    CHECK(sameContacts(list(), slots.assign(list(c(4, 500, 500, false)))));
}

TEST_CASE(resetForgetsHeldFingers) {
    TouchSlots slots;
    CHECK_EQ(kTouchContacts, slots.slotCount());
    slots.assign(list(c(9, 10, 10)));
    slots.reset();
    CHECK(sameContacts(list(), slots.assign(list())));
    // Slots then feed the report builder directly.
    slots.assign(list(c(42, 10, 20)));
    const uint8_t exp[] = {0, 1, 10, 0, 20, 0, 1, 0, 0, 0, 0, 0};
    CHECK_BYTES_EQ(u8(exp, sizeof(exp)), touchReport(slots.assign(list(c(42, 10, 20))), 800, 480));
}

// ---------------- Knob ----------------

TEST_CASE(knobReportLayout) {
    KnobState s;
    CHECK_BYTES_EQ(hexToBytes("00000000"), knobReport(s));
    s.select = true;
    CHECK_BYTES_EQ(hexToBytes("01000000"), knobReport(s));
    s = KnobState();
    s.home = true;
    CHECK_BYTES_EQ(hexToBytes("02000000"), knobReport(s));
    s = KnobState();
    s.back = true;
    CHECK_BYTES_EQ(hexToBytes("04000000"), knobReport(s));
    s = KnobState();
    s.wheel = 1;
    CHECK_BYTES_EQ(hexToBytes("00000001"), knobReport(s));
    s.wheel = -1;
    CHECK_BYTES_EQ(hexToBytes("000000ff"), knobReport(s));
    s = KnobState();
    s.select = s.home = s.back = true;
    s.x = 5;
    s.y = -5;
    s.wheel = 3;
    CHECK_BYTES_EQ(hexToBytes("0705fb03"), knobReport(s));
}

TEST_CASE(knobAxesClampToInt8Range) {
    KnobState s;
    s.x = 127;
    s.y = -127;
    s.wheel = 0;
    CHECK_BYTES_EQ(hexToBytes("007f8100"), knobReport(s));
    s.x = 128;
    s.y = -128;
    s.wheel = 1000;
    CHECK_BYTES_EQ(hexToBytes("007f817f"), knobReport(s));
    s.x = -100000;
    s.y = 100000;
    s.wheel = -129;
    CHECK_BYTES_EQ(hexToBytes("00817f81"), knobReport(s));
}

// ---------------- Media / Telephony ----------------

TEST_CASE(mediaAndTelephonyIndices) {
    // CarPlayMediaButtonTest.indicesMatchTheAdvertisedMediaHidReport + CarPlayMediaButton.kt.
    CHECK_EQ(1, static_cast<int>(MEDIA_PLAY));
    CHECK_EQ(2, static_cast<int>(MEDIA_PAUSE));
    CHECK_EQ(3, static_cast<int>(MEDIA_PLAY_PAUSE));
    CHECK_EQ(4, static_cast<int>(MEDIA_NEXT));
    CHECK_EQ(5, static_cast<int>(MEDIA_PREVIOUS));
    CHECK_EQ(6, kMediaLogicalMax);
    // CarPlayController.kt:3236-3237.
    CHECK_EQ(1, static_cast<int>(TELEPHONY_HOOK_SWITCH));
    CHECK_EQ(3, static_cast<int>(TELEPHONY_DROP));
    CHECK_EQ(17, kTelephonyLogicalMax);
    CHECK_EQ(17, static_cast<int>(TELEPHONY_BACKSPACE));
    CHECK_BYTES_EQ(hexToBytes("03"), mediaReport(MEDIA_PLAY_PAUSE));
    CHECK_BYTES_EQ(hexToBytes("05"), mediaReport(MEDIA_PREVIOUS));
    CHECK_BYTES_EQ(hexToBytes("00"), mediaReport(MEDIA_NONE));
    CHECK_BYTES_EQ(hexToBytes("01"), telephonyReport(TELEPHONY_HOOK_SWITCH));
    CHECK_BYTES_EQ(hexToBytes("03"), telephonyReport(TELEPHONY_DROP));
    CHECK_BYTES_EQ(hexToBytes("11"), telephonyReport(TELEPHONY_BACKSPACE));
    // Kotlin Int.toByte(): low 8 bits.
    CHECK_BYTES_EQ(hexToBytes("01"), mediaReport(0x101));
}

// ---------------- Send sequences (AirPlaySession.kt:369-385) ----------------

TEST_CASE(referenceSendSequences) {
    KnobState wheel;
    wheel.wheel = 1;
    ReportSequence seq = momentaryKnobReports(wheel);
    REQUIRE(seq.size() == 2);
    CHECK_BYTES_EQ(hexToBytes("00000001"), seq[0]);
    CHECK_BYTES_EQ(hexToBytes("00000000"), seq[1]);

    KnobState sel;
    sel.select = true;
    seq = heldKnobReports(sel);
    REQUIRE(seq.size() == 1);
    CHECK_BYTES_EQ(hexToBytes("01000000"), seq[0]);

    seq = mediaPressReports(MEDIA_NEXT);
    REQUIRE(seq.size() == 2);
    CHECK_BYTES_EQ(hexToBytes("04"), seq[0]);
    CHECK_BYTES_EQ(hexToBytes("00"), seq[1]);

    seq = telephonyPressReports(TELEPHONY_DROP);
    REQUIRE(seq.size() == 2);
    CHECK_BYTES_EQ(hexToBytes("03"), seq[0]);
    CHECK_BYTES_EQ(hexToBytes("00"), seq[1]);
}

// ---------------- BMW ZBE3 ----------------

TEST_CASE(zbe3HardwareBitsUnchanged) {
    CHECK_EQ(0x01, zbe3::kBtnMenu);
    CHECK_EQ(0x02, zbe3::kBtnBack);
    CHECK_EQ(0x04, zbe3::kBtnOption);
    CHECK_EQ(0x08, zbe3::kBtnMedia);
    CHECK_EQ(0x40, zbe3::kBtnCom);
    CHECK_EQ(0x01, zbe3::kDirUp);
    CHECK_EQ(0x02, zbe3::kDirRight);
    CHECK_EQ(0x04, zbe3::kDirDown);
    CHECK_EQ(0x08, zbe3::kDirLeft);
}

TEST_CASE(zbe3MappingTable) {
    struct Row {
        uint8_t dir;
        bool center;
        uint8_t buttons;
        int8_t rotary;
        const char* knob_hex;
        int32_t media;
        int32_t telephony;
    };
    const Row rows[] = {
        {0x00, false, 0x00, 0, "00000000", MEDIA_NONE, TELEPHONY_NONE},           // idle
        {0x00, true, 0x00, 0, "01000000", MEDIA_NONE, TELEPHONY_NONE},            // push -> select
        {0x00, false, zbe3::kBtnMenu, 0, "02000000", MEDIA_NONE, TELEPHONY_NONE},  // MENU -> home
        {0x00, false, zbe3::kBtnBack, 0, "04000000", MEDIA_NONE, TELEPHONY_NONE},  // BACK -> back
        {0x00, false, zbe3::kBtnOption, 0, "00000000", MEDIA_NONE, TELEPHONY_NONE},  // OPTION: none
        {0x00, false, zbe3::kBtnMedia, 0, "00000000", MEDIA_PLAY_PAUSE, TELEPHONY_NONE},
        {0x00, false, zbe3::kBtnCom, 0, "00000000", MEDIA_NONE, TELEPHONY_HOOK_SWITCH},
        {0x00, false, 0x00, 1, "00000001", MEDIA_NONE, TELEPHONY_NONE},    // clockwise -> +1
        {0x00, false, 0x00, -1, "000000ff", MEDIA_NONE, TELEPHONY_NONE},   // counter-clockwise
        {0x00, false, 0x00, 5, "00000005", MEDIA_NONE, TELEPHONY_NONE},
        {0x00, false, 0x00, -128, "00000081", MEDIA_NONE, TELEPHONY_NONE},  // clamped to -127
        {zbe3::kDirUp, false, 0x00, 0, "000000ff", MEDIA_NONE, TELEPHONY_NONE},     // up -> -1
        {zbe3::kDirLeft, false, 0x00, 0, "000000ff", MEDIA_NONE, TELEPHONY_NONE},   // left -> -1
        {zbe3::kDirDown, false, 0x00, 0, "00000001", MEDIA_NONE, TELEPHONY_NONE},   // down -> +1
        {zbe3::kDirRight, false, 0x00, 0, "00000001", MEDIA_NONE, TELEPHONY_NONE},  // right -> +1
        {zbe3::kDirUp | zbe3::kDirLeft, false, 0x00, 0, "000000fe", MEDIA_NONE, TELEPHONY_NONE},
        {zbe3::kDirDown | zbe3::kDirRight, false, 0x00, 0, "00000002", MEDIA_NONE, TELEPHONY_NONE},
        {zbe3::kDirUp | zbe3::kDirDown, false, 0x00, 0, "00000000", MEDIA_NONE, TELEPHONY_NONE},
        {zbe3::kDirDown, false, 0x00, 2, "00000003", MEDIA_NONE, TELEPHONY_NONE},  // tilt + rotary
        {0x00, true, static_cast<uint8_t>(zbe3::kBtnMenu | zbe3::kBtnBack | zbe3::kBtnOption |
                                          zbe3::kBtnMedia | zbe3::kBtnCom),
         -2, "070000fe", MEDIA_PLAY_PAUSE, TELEPHONY_HOOK_SWITCH},
        {0x00, false, 0x30, 0, "00000000", MEDIA_NONE, TELEPHONY_NONE},  // unknown bits ignored
    };
    for (size_t k = 0; k < sizeof(rows) / sizeof(rows[0]); ++k) {
        Zbe3Event hw;
        hw.dir_mask = rows[k].dir;
        hw.center_pressed = rows[k].center;
        hw.button_mask = rows[k].buttons;
        hw.rotary_delta = rows[k].rotary;
        KnobState knob;
        knob.x = 99;  // must be overwritten
        int32_t media = -1;
        int32_t tel = -1;
        mapZbe3ToCarPlay(hw, knob, media, tel);
        CHECK_BYTES_EQ(hexToBytes(rows[k].knob_hex), knobReport(knob));
        CHECK_EQ(0, knob.x);
        CHECK_EQ(0, knob.y);
        CHECK_EQ(rows[k].media, media);
        CHECK_EQ(rows[k].telephony, tel);
    }
}

TEST_CASE(zbe3KnobReportSequences) {
    KnobState s;
    ReportSequence seq = zbe3KnobReports(s);
    REQUIRE(seq.size() == 1);
    CHECK_BYTES_EQ(hexToBytes("00000000"), seq[0]);
    // Pure rotation == the reference's momentary sendKnob(wheel = 1).
    s.wheel = 1;
    seq = zbe3KnobReports(s);
    CHECK(seq == momentaryKnobReports(s));
    // Rotation while select is held keeps select held after the step.
    s.select = true;
    s.wheel = -1;
    seq = zbe3KnobReports(s);
    REQUIRE(seq.size() == 2);
    CHECK_BYTES_EQ(hexToBytes("010000ff"), seq[0]);
    CHECK_BYTES_EQ(hexToBytes("01000000"), seq[1]);
    // Button-only change: a single held report.
    s.wheel = 0;
    seq = zbe3KnobReports(s);
    CHECK(seq == heldKnobReports(s));
}

int main() { return test_support::runAll("test_airplay_hid"); }
