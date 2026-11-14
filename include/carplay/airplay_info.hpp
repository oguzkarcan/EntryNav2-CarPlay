#ifndef CARPLAY_AIRPLAY_INFO_HPP
#define CARPLAY_AIRPLAY_INFO_HPP

// AirPlay / CarPlay receiver `/info` response builder (port of DiPlay AirPlayInfoPlist.kt) plus the
// SETUP `enabledFeatures` negotiation (port of AirPlaySession.setupEnabledFeatures).
//
// Pure data construction: no OS headers, no I/O. The produced bplist::Value is an ordered Dict
// whose key order matches the reference implementation exactly.

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "carplay/bplist_codec.hpp"

namespace carplay {
namespace info {

/// Display UUIDs advertised in /info `displays` and referenced by every HID device.
extern const char* const kMainDisplayUuid;  // "b7e6c5a0-1111-4000-8000-000000000001"
extern const char* const kAltDisplayUuid;   // "b7e6c5a0-2222-4000-8000-000000000002"

/// AirPlay SETUP / /info stream types.
static const int32_t kStreamTypeMainAudio = 100;
static const int32_t kStreamTypeAltAudio = 101;
static const int32_t kStreamTypeMainHighAudio = 102;
static const int32_t kStreamTypeMainBufferedAudio = 103;
static const int32_t kStreamTypeMainScreen = 110;
static const int32_t kStreamTypeAltScreen = 111;
static const int32_t kStreamTypeData = 130;

/// Receiver feature bitmask (/info `features` and Bonjour `features`); exceeds 32 bits.
static const uint64_t kCarPlayFeatures = 0x615653aee2ULL;
/// Audio bits removed from kCarPlayFeatures when audio output is disabled.
static const uint64_t kCarPlayAudioFeatures = 0x10004540a00ULL;

/// Display `features` bits.
static const int32_t kDisplayFeatureKnobs = 0x02;
static const int32_t kDisplayFeatureHighFidelityTouch = 0x08;

/// Display `primaryInputDevice` values as used by the reference (1 = touch, 3 = knob; 0 = none, cluster).
static const int32_t kPrimaryInputNone = 0;
static const int32_t kPrimaryInputTouch = 1;
static const int32_t kPrimaryInputKnob = 3;

/// viewAreaStatusBarEdge values (dock position).
static const int32_t kDockEdgeBottom = 1;
static const int32_t kDockEdgeDriverSide = 2;

/// Display setting ranges (AirPlayDisplaySettings.kt).
static const int32_t kMinFps = 30;
static const int32_t kMaxFps = 60;
static const int32_t kFpsStep = 5;
static const int32_t kDefaultWidthPhysicalMm = 200;
static const int32_t kMinReportedPhysicalMm = 1;
static const int32_t kMaxReportedPhysicalMm = 2000;

/// SETUP enabledFeatures strings.
extern const char* const kFeatureHevc;          // "hevc"
extern const char* const kFeatureIapChannel;    // "iAPChannel"
extern const char* const kFeatureViewAreas;     // "viewAreas"
extern const char* const kFeatureAltScreen;     // "altScreen"
extern const char* const kFeatureMainBuffered;  // "mainBuffered"

/// Display insets in pixels (viewArea / safeArea declarations).
struct Insets {
    int32_t top;
    int32_t bottom;
    int32_t left;
    int32_t right;

    Insets() : top(0), bottom(0), left(0), right(0) {}
    Insets(int32_t t, int32_t b, int32_t l, int32_t r) : top(t), bottom(b), left(l), right(r) {}
};

/// One rectangle of the display stream that CarPlay may draw in.
struct ViewArea {
    int32_t width;
    int32_t height;
    int32_t origin_x;
    int32_t origin_y;
    bool has_dock_edge;
    int32_t dock_edge;  // kDockEdge*; ignored unless has_dock_edge

    ViewArea()
        : width(0), height(0), origin_x(0), origin_y(0), has_dock_edge(false), dock_edge(0) {}
    ViewArea(int32_t w, int32_t h, int32_t x = 0, int32_t y = 0)
        : width(w), height(h), origin_x(x), origin_y(y), has_dock_edge(false), dock_edge(0) {}
};

/// One display advertised to the phone (AirPlayDisplayConfig).
/// `has_xxx` flags stand in for Kotlin nullables. Out of scope (not yet modelled):
/// mainDisplayCornerMasks / useIphoneCornerMask (iPhone corner masks).
struct DisplayConfig {
    int32_t width_pixels;
    int32_t height_pixels;
    bool has_width_physical_mm;
    int32_t width_physical_mm;
    bool has_height_physical_mm;
    int32_t height_physical_mm;
    int32_t fps;                   // default 60, snapped to [30..60] step 5
    int32_t primary_input_device;  // default kPrimaryInputTouch (1)
    bool has_view_area;
    Insets view_area;
    bool has_safe_area;
    Insets safe_area;
    bool has_safe_area_draw_outside;
    bool safe_area_draw_outside;   // reference default when unset: true
    bool has_initial_url;
    std::string initial_url;
    bool has_features;
    int32_t features;              // default when unset: HighFidelityTouch | Knobs (0x0a)
    std::vector<ViewArea> view_areas;  // empty == whole display as one area
    int32_t initial_view_area;     // index into view_areas (clamped)
    bool disable_safe_area;        // mainDisplayDisableSafeArea (honoured for the main display only)

    DisplayConfig();
    DisplayConfig(int32_t width, int32_t height);
};

/// One OEM home-screen icon.
struct OemIcon {
    int32_t width_pixels;
    int32_t height_pixels;
    std::vector<uint8_t> data;

    OemIcon() : width_pixels(0), height_pixels(0) {}
};

/// Accessory configuration consumed by /info and SETUP (AirPlayConfig.kt).
/// Out of scope (not yet modelled): videoInCar / videoPlaybackInfo, port.
struct AirPlayConfig {
    std::string device_name;
    std::string device_id;
    std::string bt_mac;
    std::string source_version;
    DisplayConfig main;
    bool has_cluster;
    DisplayConfig cluster;
    bool right_hand_drive;
    int32_t entertainment_sample_rate;  // 44100 or 48000 (default 48000)
    bool hevc;
    bool disable_audio_output;
    bool microphone;
    bool microphone_opus;               // default true
    std::string manufacturer;
    std::string model;
    std::string oem_label;
    std::vector<OemIcon> icons;
    bool main_buffered_audio;
    bool speech_without_8_and_16khz;
    bool call_at_call_rate;
    /// Prefix of the HID device `name` strings ("<prefix> Touchscreen", ...). Reference: "xcertplay".
    std::string hid_name_prefix;

    AirPlayConfig();

    /// mainBufferedAudio && !disableAudioOutput.
    bool bufferedAudioOutputEnabled() const { return main_buffered_audio && !disable_audio_output; }
};

// ---- Display settings helpers (AirPlayDisplaySettings.kt) ----
int32_t sanitizeFps(int32_t fps);
int32_t sanitizeReportedPhysicalMm(int32_t mm);

// ---- BMW HU_ENTRYNAV2 profiles ----
// Knob-primary (iDrive ZBE3): primaryInputDevice = 3. `touch` adds the high-fidelity-touch display
// feature bit (0x08) for units with a touch panel; the knob bit (0x02) is always set.
// device_id / bt_mac are placeholders ("02:00:00:00:00:02") to be filled at runtime.
AirPlayConfig bmwEntryNav2_800x480(bool touch = false);
AirPlayConfig bmwEntryNav2_1280x480(bool touch = false);
AirPlayConfig bmwEntryNav2_1440x540(bool touch = false);

// ---- /info ----
/// 0x615653aee2, minus 0x10004540a00 when audio output is disabled.
uint64_t features(const AirPlayConfig& config);

/// Builds the ordered /info dictionary. `hidDevices` = [touch, knob, media, telephony], all bound to
/// kMainDisplayUuid, with descriptors from carplay::hid; the touch descriptor's X/Y logical maximum
/// is config.main.width_pixels / height_pixels (AirPlayInfoPlist.kt:58-63).
bplist::Value buildInfo(const AirPlayConfig& config);

/// bplist00-encodes buildInfo(config).
bool encodeInfo(const AirPlayConfig& config, std::vector<uint8_t>& out, std::string* error_out = NULL);

// ---- SETUP ----
/// Ordered enabledFeatures for the SETUP response: [hevc?], iAPChannel, viewAreas, [altScreen?],
/// [mainBuffered? (only if enabled AND proposed by the phone)].
std::vector<std::string> setupEnabledFeatures(const AirPlayConfig& config,
                                              const std::vector<std::string>& proposed_features);

/// Convenience: same, taking the phone's SETUP `features` array (non-strings ignored; NULL = none).
std::vector<std::string> setupEnabledFeatures(const AirPlayConfig& config,
                                              const bplist::Value* proposed_features);

}  // namespace info
}  // namespace carplay

#endif  // CARPLAY_AIRPLAY_INFO_HPP
