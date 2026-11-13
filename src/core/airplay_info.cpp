#include "carplay/airplay_info.hpp"

#include <math.h>

#include "carplay/airplay_hid.hpp"

namespace carplay {
namespace info {

using bplist::Value;

const char* const kMainDisplayUuid = "b7e6c5a0-1111-4000-8000-000000000001";
const char* const kAltDisplayUuid = "b7e6c5a0-2222-4000-8000-000000000002";

const char* const kFeatureHevc = "hevc";
const char* const kFeatureIapChannel = "iAPChannel";
const char* const kFeatureViewAreas = "viewAreas";
const char* const kFeatureAltScreen = "altScreen";
const char* const kFeatureMainBuffered = "mainBuffered";

namespace {

const int32_t kResourceScreen = 1;
const int32_t kResourceAudio = 2;
const int32_t kTransferTake = 1;
const int32_t kPriorityNiceToHave = 100;
const int32_t kConstraintAnytime = 100;

const char* const kDefaultSourceVersion = "950.7.1";
const char* const kPlaceholderMac = "02:00:00:00:00:02";

int32_t clampI32(int32_t v, int32_t lo, int32_t hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

int32_t snapToStep(int32_t value, int32_t minimum, int32_t maximum, int32_t step) {
    const int32_t clamped = clampI32(value, minimum, maximum);
    return (((clamped - minimum) + step / 2) / step) * step + minimum;
}

// Java Math.round(double).toInt(): floor(x + 0.5), saturating to the int32 range.
int32_t javaRoundToInt(double x) {
    if (x != x) return 0;  // NaN
    const double r = floor(x + 0.5);
    if (r >= 2147483647.0) return 2147483647;
    if (r <= -2147483648.0) return static_cast<int32_t>(-2147483647 - 1);
    return static_cast<int32_t>(r);
}

Value i(int64_t v) { return Value::makeInt(v); }
Value b(bool v) { return Value::makeBool(v); }
Value s(const std::string& v) { return Value::makeString(v); }

void put(Value& dict, const char* key, const Value& v) {
    dict.asDict().push_back(std::make_pair(std::string(key), v));
}

Value resource(int32_t resource_id) {
    Value d = Value::makeDict();
    put(d, "resourceID", i(resource_id));
    put(d, "transferType", i(kTransferTake));
    put(d, "transferPriority", i(kPriorityNiceToHave));
    put(d, "takeConstraint", i(kConstraintAnytime));
    put(d, "borrowConstraint", i(kConstraintAnytime));
    put(d, "unborrowConstraint", i(kConstraintAnytime));
    return d;
}

Value appState(int32_t id, const char* key, const Value& v) {
    Value d = Value::makeDict();
    put(d, "appStateID", i(id));
    put(d, key, v);
    return d;
}

Value modes() {
    Value resources = Value::makeArray();
    resources.asArray().push_back(resource(kResourceScreen));
    resources.asArray().push_back(resource(kResourceAudio));

    Value states = Value::makeArray();
    states.asArray().push_back(appState(2, "state", b(false)));
    states.asArray().push_back(appState(1, "speechMode", i(-1)));
    states.asArray().push_back(appState(3, "state", b(false)));

    Value d = Value::makeDict();
    put(d, "resources", resources);
    put(d, "appStates", states);
    return d;
}

Value latency(int32_t type, const char* audio_type) {
    Value d = Value::makeDict();
    put(d, "type", i(type));
    put(d, "inputLatencyMicros", i(0));
    put(d, "outputLatencyMicros", i(0));
    if (audio_type != NULL) put(d, "audioType", s(audio_type));
    return d;
}

Value audioLatencies() {
    Value a = Value::makeArray();
    Value::Array& arr = a.asArray();
    arr.push_back(latency(100, NULL));
    arr.push_back(latency(100, "default"));
    arr.push_back(latency(100, "media"));
    arr.push_back(latency(100, "telephony"));
    arr.push_back(latency(100, "speechRecognition"));
    arr.push_back(latency(100, "alert"));
    arr.push_back(latency(101, NULL));
    arr.push_back(latency(101, "default"));
    arr.push_back(latency(102, "default"));
    return a;
}

// input_formats < 0 means "no audioInputFormats key".
Value format(int32_t type, const char* audio_type, int64_t output_formats, int64_t input_formats) {
    Value d = Value::makeDict();
    put(d, "type", i(type));
    put(d, "audioType", s(audio_type));
    put(d, "audioOutputFormats", i(output_formats));
    if (input_formats >= 0) put(d, "audioInputFormats", i(input_formats));
    return d;
}

Value audioFormats(const AirPlayConfig& c) {
    const bool is48 = c.entertainment_sample_rate == 48000;
    const int64_t pcm_voice = 0x3fc;
    const int64_t pcm = pcm_voice | (is48 ? 0xc000 : 0xc00);
    // PCM 8 kHz and 16 kHz, mono and stereo.
    const int64_t speech = c.speech_without_8_and_16khz ? (pcm & ~static_cast<int64_t>(0x3c)) : pcm;
    const int64_t pcm_mono = 0x154 | (is48 ? 0x4000 : 0x400);
    const int64_t opus = 0x70000000;
    const int64_t aac_lc = is48 ? 0x800000 : 0x400000;
    const int64_t telephony_output = c.call_at_call_rate ? 0x154 : (pcm_mono | opus);
    const int64_t pcm_input = c.microphone ? pcm_mono : -1;
    const int64_t wireless_input =
        c.microphone ? (c.microphone_opus ? (pcm_mono | opus) : pcm_mono) : -1;
    const int64_t telephony_input = (c.call_at_call_rate && c.microphone) ? 0x154 : wireless_input;

    Value a = Value::makeArray();
    Value::Array& arr = a.asArray();
    arr.push_back(format(100, "compatibility", pcm, pcm_input));
    arr.push_back(format(101, "compatibility", pcm, -1));
    arr.push_back(format(100, "default", speech | opus, wireless_input));
    arr.push_back(format(100, "alert", speech | opus, -1));
    arr.push_back(format(100, "media", pcm, -1));
    arr.push_back(format(100, "telephony", telephony_output, telephony_input));
    arr.push_back(format(100, "speechRecognition", pcm_mono | opus, wireless_input));
    arr.push_back(format(101, "default", speech | opus, -1));
    arr.push_back(format(102, "media", aac_lc, -1));
    if (c.main_buffered_audio) {
        arr.push_back(format(kStreamTypeMainBufferedAudio, "media", aac_lc, -1));
    }
    return a;
}

Value insetRect(int32_t width, int32_t height, const Insets& in) {
    Value d = Value::makeDict();
    put(d, "widthPixels", i(static_cast<int64_t>(width) - in.left - in.right));
    put(d, "heightPixels", i(static_cast<int64_t>(height) - in.top - in.bottom));
    put(d, "originXPixels", i(in.left));
    put(d, "originYPixels", i(in.top));
    return d;
}

int32_t maxI32(int32_t a, int32_t b2) { return a > b2 ? a : b2; }

Value areaDict(const DisplayConfig& display, const ViewArea* area, bool disable_safe_area) {
    const int32_t width = display.width_pixels;
    const int32_t height = display.height_pixels;
    Insets view;
    if (area != NULL) {
        view = Insets(area->origin_y,
                      height - area->origin_y - area->height,
                      area->origin_x,
                      width - area->origin_x - area->width);
    } else if (display.has_view_area) {
        view = display.view_area;
    }
    Value result = insetRect(width, height, view);
    if (area != NULL && area->has_dock_edge) {
        put(result, "viewAreaStatusBarEdge", i(area->dock_edge));
    }
    if (!disable_safe_area) {
        const Insets display_safe = display.has_safe_area ? display.safe_area : Insets();
        Insets clipped = display_safe;
        if (area != NULL) {
            clipped = Insets(maxI32(display_safe.top, view.top),
                             maxI32(display_safe.bottom, view.bottom),
                             maxI32(display_safe.left, view.left),
                             maxI32(display_safe.right, view.right));
        }
        // Empty intersection of a saved mapping with a smaller view area: use the area's bounds.
        const bool empty = area != NULL &&
                           (static_cast<int64_t>(clipped.left) + clipped.right >= width ||
                            static_cast<int64_t>(clipped.top) + clipped.bottom >= height);
        const Insets safe = empty ? view : clipped;
        Value safe_dict = insetRect(width, height, safe);
        put(safe_dict, "drawUIOutsideSafeArea",
            b(display.has_safe_area_draw_outside ? display.safe_area_draw_outside : true));
        put(result, "safeArea", safe_dict);
    }
    return result;
}

Value displayEntry(const DisplayConfig& display, int32_t type, const char* uuid, bool is_main) {
    const int32_t width_physical = sanitizeReportedPhysicalMm(
        display.has_width_physical_mm ? display.width_physical_mm : kDefaultWidthPhysicalMm);
    int32_t height_raw;
    if (display.has_height_physical_mm) {
        height_raw = display.height_physical_mm;
    } else {
        // Kotlin: Math.round(widthPhysical * heightPixels.toDouble() / widthPixels).toInt()
        // (double division; a zero width yields +/-Infinity or NaN, which saturates / becomes 0).
        const double num = static_cast<double>(width_physical) * display.height_pixels;
        if (display.width_pixels == 0) {
            height_raw = num > 0 ? 2147483647 : (num < 0 ? static_cast<int32_t>(-2147483647 - 1) : 0);
        } else {
            height_raw = javaRoundToInt(num / display.width_pixels);
        }
    }
    const int32_t height_physical = sanitizeReportedPhysicalMm(height_raw);
    const int32_t fps = sanitizeFps(display.fps);

    Value e = Value::makeDict();
    put(e, "uuid", s(uuid));
    put(e, "type", i(type));
    put(e, "maxFPS", i(fps));
    put(e, "widthPixels", i(display.width_pixels));
    put(e, "heightPixels", i(display.height_pixels));
    put(e, "widthPhysical", i(width_physical));
    put(e, "heightPhysical", i(height_physical));
    put(e, "features", i(display.has_features
                             ? display.features
                             : (kDisplayFeatureHighFidelityTouch | kDisplayFeatureKnobs)));
    put(e, "primaryInputDevice", i(display.primary_input_device));
    put(e, "uiAppearanceMode", i(0));
    put(e, "uiAppearanceSetting", i(0));
    put(e, "mapAppearanceMode", i(0));
    put(e, "mapAppearanceSetting", i(0));

    const bool has_areas = !display.view_areas.empty();
    const bool disable_safe = is_main && display.disable_safe_area;
    Value areas = Value::makeArray();
    if (has_areas) {
        for (size_t k = 0; k < display.view_areas.size(); ++k) {
            areas.asArray().push_back(areaDict(display, &display.view_areas[k], disable_safe));
        }
    } else {
        areas.asArray().push_back(areaDict(display, NULL, disable_safe));
    }
    put(e, "viewAreas", areas);
    int32_t initial = 0;
    if (has_areas) {
        initial = clampI32(display.initial_view_area, 0,
                           static_cast<int32_t>(display.view_areas.size()) - 1);
    }
    put(e, "initialViewArea", i(initial));
    // cornerMasks: out of scope (not modelled).
    if (has_areas && display.view_areas.size() > 1) put(e, "viewAreaTransitionControl", b(true));
    if (display.has_initial_url) put(e, "initialURL", s(display.initial_url));
    return e;
}

std::string hexUid(uint32_t uid) {
    // Kotlin Int.toString(16): lowercase, no leading zeros (UIDs here are all positive).
    static const char kDigits[] = "0123456789abcdef";
    if (uid == 0) return "0";
    std::string out;
    while (uid != 0) {
        out.insert(out.begin(), kDigits[uid & 0x0fU]);
        uid >>= 4;
    }
    return out;
}

Value hidDeviceEntry(uint32_t uid,
                     const std::string& name,
                     const std::vector<uint8_t>& descriptor,
                     const char* display_uuid) {
    Value d = Value::makeDict();
    put(d, "hidProductID", i(1));
    put(d, "hidVendorID", i(2));
    put(d, "hidCountryCode", i(0));
    put(d, "uuid", s(hexUid(uid)));
    put(d, "name", s(name));
    put(d, "displayUUID", s(display_uuid));
    put(d, "hidDescriptor", Value::makeData(descriptor));
    return d;
}

Value stringList(const char* a, const char* b2) {
    Value v = Value::makeArray();
    v.asArray().push_back(s(a));
    if (b2 != NULL) v.asArray().push_back(s(b2));
    return v;
}

AirPlayConfig bmwProfile(int32_t width, int32_t height, int32_t width_mm, bool touch,
                         const char* model) {
    AirPlayConfig c;
    c.device_name = "BMW CarPlay";
    c.device_id = kPlaceholderMac;
    c.bt_mac = kPlaceholderMac;
    c.manufacturer = "BMW";
    c.model = model;
    c.oem_label = "BMW";
    c.hid_name_prefix = "EntryNav2";
    c.main = DisplayConfig(width, height);
    c.main.has_width_physical_mm = true;
    c.main.width_physical_mm = width_mm;
    c.main.has_features = true;
    c.main.features = kDisplayFeatureKnobs | (touch ? kDisplayFeatureHighFidelityTouch : 0);
    c.main.primary_input_device = kPrimaryInputKnob;
    c.microphone = true;
    c.entertainment_sample_rate = 48000;
    c.hevc = false;
    c.has_cluster = false;
    return c;
}

}  // namespace

DisplayConfig::DisplayConfig()
    : width_pixels(0),
      height_pixels(0),
      has_width_physical_mm(false),
      width_physical_mm(0),
      has_height_physical_mm(false),
      height_physical_mm(0),
      fps(60),
      primary_input_device(kPrimaryInputTouch),
      has_view_area(false),
      has_safe_area(false),
      has_safe_area_draw_outside(false),
      safe_area_draw_outside(true),
      has_initial_url(false),
      has_features(false),
      features(0),
      initial_view_area(0),
      disable_safe_area(false) {}

DisplayConfig::DisplayConfig(int32_t width, int32_t height)
    : width_pixels(width),
      height_pixels(height),
      has_width_physical_mm(false),
      width_physical_mm(0),
      has_height_physical_mm(false),
      height_physical_mm(0),
      fps(60),
      primary_input_device(kPrimaryInputTouch),
      has_view_area(false),
      has_safe_area(false),
      has_safe_area_draw_outside(false),
      safe_area_draw_outside(true),
      has_initial_url(false),
      has_features(false),
      features(0),
      initial_view_area(0),
      disable_safe_area(false) {}

AirPlayConfig::AirPlayConfig()
    : source_version(kDefaultSourceVersion),
      has_cluster(false),
      right_hand_drive(false),
      entertainment_sample_rate(48000),
      hevc(false),
      disable_audio_output(false),
      microphone(false),
      microphone_opus(true),
      manufacturer("xcertplay"),
      model("xcertplay"),
      oem_label("xcertplay"),
      main_buffered_audio(false),
      speech_without_8_and_16khz(false),
      call_at_call_rate(false),
      hid_name_prefix("xcertplay") {}

int32_t sanitizeFps(int32_t fps) { return snapToStep(fps, kMinFps, kMaxFps, kFpsStep); }

int32_t sanitizeReportedPhysicalMm(int32_t mm) {
    return clampI32(mm, kMinReportedPhysicalMm, kMaxReportedPhysicalMm);
}

// Physical widths are estimates from the nominal panel diagonals (6.5" 5:3, 8.8" 8:3,
// 10.25" 8:3); heights are derived from the pixel aspect ratio. Not measured on a car.
AirPlayConfig bmwEntryNav2_800x480(bool touch) {
    return bmwProfile(800, 480, 142, touch, "HU_ENTRYNAV2");
}

AirPlayConfig bmwEntryNav2_1280x480(bool touch) {
    return bmwProfile(1280, 480, 209, touch, "HU_ENTRYNAV2");
}

AirPlayConfig bmwEntryNav2_1440x540(bool touch) {
    return bmwProfile(1440, 540, 244, touch, "HU_ENTRYNAV2");
}

uint64_t features(const AirPlayConfig& config) {
    return config.disable_audio_output ? (kCarPlayFeatures & ~kCarPlayAudioFeatures)
                                       : kCarPlayFeatures;
}

Value buildInfo(const AirPlayConfig& config) {
    Value info = Value::makeDict();
    put(info, "sourceVersion", s(config.source_version));
    put(info, "features", Value::makeUInt(features(config)));
    put(info, "statusFlags", i(4));
    put(info, "model", s(config.model));
    put(info, "manufacturer", s(config.manufacturer));
    put(info, "deviceID", s(config.device_id));
    put(info, "bluetoothIDs", stringList(config.bt_mac.c_str(), NULL));
    put(info, "name", s(config.device_name));
    put(info, "rightHandDrive", b(config.right_hand_drive));
    put(info, "keepAliveLowPower", b(false));
    put(info, "keepAliveSendStatsAsBody", b(false));
    put(info, "modes", modes());
    if (!config.disable_audio_output) {
        put(info, "audioLatencies", audioLatencies());
        put(info, "audioFormats", audioFormats(config));
    }
    put(info, "extendedFeatures", stringList("vocoderInfo", "enhancedRequestCarUI"));

    Value displays = Value::makeArray();
    displays.asArray().push_back(
        displayEntry(config.main, kStreamTypeMainScreen, kMainDisplayUuid, true));
    if (config.has_cluster) {
        displays.asArray().push_back(
            displayEntry(config.cluster, kStreamTypeAltScreen, kAltDisplayUuid, false));
    }
    put(info, "displays", displays);

    // HID descriptors come from carplay::hid (see airplay_hid.hpp). The touch descriptor uses the
    // module's 0..kTouchAxisMax logical range, matching hid::normalizeTouchCoords/makeTouchReport,
    // rather than the reference's pixel range.
    const std::string& p = config.hid_name_prefix;
    Value hids = Value::makeArray();
    hids.asArray().push_back(hidDeviceEntry(hid::kUidTouchscreen, p + " Touchscreen",
                                            hid::touchscreenDescriptor(), kMainDisplayUuid));
    hids.asArray().push_back(
        hidDeviceEntry(hid::kUidKnob, p + " Knob", hid::knobDescriptor(), kMainDisplayUuid));
    hids.asArray().push_back(
        hidDeviceEntry(hid::kUidMedia, p + " Media", hid::mediaDescriptor(), kMainDisplayUuid));
    hids.asArray().push_back(hidDeviceEntry(hid::kUidTelephony, p + " Telephony",
                                            hid::telephonyDescriptor(), kMainDisplayUuid));
    put(info, "hidDevices", hids);

    if (!config.icons.empty()) {
        put(info, "oemIconVisible", b(true));
        put(info, "oemIconLabel", s(config.oem_label));
        Value icons = Value::makeArray();
        for (size_t k = 0; k < config.icons.size(); ++k) {
            const OemIcon& icon = config.icons[k];
            Value d = Value::makeDict();
            put(d, "imageData", Value::makeData(icon.data));
            put(d, "widthPixels", i(icon.width_pixels));
            put(d, "heightPixels", i(icon.height_pixels));
            put(d, "prerendered", b(true));
            icons.asArray().push_back(d);
        }
        put(info, "oemIcons", icons);
    }
    if (config.hevc) put(info, "hevcInfo", Value::makeDict());
    if (config.bufferedAudioOutputEnabled()) put(info, "mainBufferedInfo", Value::makeDict());
    // videoPlaybackInfo (videoInCar): out of scope.
    return info;
}

bool encodeInfo(const AirPlayConfig& config, std::vector<uint8_t>& out, std::string* error_out) {
    return bplist::encode(buildInfo(config), out, error_out);
}

std::vector<std::string> setupEnabledFeatures(const AirPlayConfig& config,
                                              const std::vector<std::string>& proposed_features) {
    std::vector<std::string> out;
    if (config.hevc) out.push_back(kFeatureHevc);
    out.push_back(kFeatureIapChannel);
    out.push_back(kFeatureViewAreas);
    if (config.has_cluster) out.push_back(kFeatureAltScreen);
    // cornerMasks / videoPlayback: out of scope.
    if (config.bufferedAudioOutputEnabled()) {
        for (size_t k = 0; k < proposed_features.size(); ++k) {
            if (proposed_features[k] == kFeatureMainBuffered) {
                out.push_back(kFeatureMainBuffered);
                break;
            }
        }
    }
    return out;
}

std::vector<std::string> setupEnabledFeatures(const AirPlayConfig& config,
                                              const Value* proposed_features) {
    std::vector<std::string> proposed;
    if (proposed_features != NULL && proposed_features->isArray()) {
        const Value::Array& arr = proposed_features->asArray();
        for (size_t k = 0; k < arr.size(); ++k) {
            if (arr[k].isString()) proposed.push_back(arr[k].asString());
        }
    }
    return setupEnabledFeatures(config, proposed);
}

}  // namespace info
}  // namespace carplay
