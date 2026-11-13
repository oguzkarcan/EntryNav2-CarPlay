// /info plist builder (port of DiPlay AirPlayInfoPlist.kt) and SETUP enabledFeatures.
// Every check goes through bplist encode -> decode so it covers what the phone actually receives.

#include "carplay/airplay_hid.hpp"
#include "carplay/airplay_info.hpp"
#include "carplay/bplist_codec.hpp"
#include "test_support.hpp"

#include <string>
#include <vector>

using carplay::bplist::Value;
namespace info = carplay::info;
namespace hid = carplay::hid;

namespace {

const int64_t kOpus = 0x70000000;

info::AirPlayConfig baseConfig(int32_t w = 1280, int32_t h = 720) {
    info::AirPlayConfig c;
    c.device_name = "test";
    c.device_id = "02:00:00:00:00:02";
    c.bt_mac = "02:00:00:00:00:02";
    c.source_version = "366.0";
    c.main = info::DisplayConfig(w, h);
    return c;
}

bool roundTrip(const info::AirPlayConfig& c, Value& out) {
    std::vector<uint8_t> bytes;
    std::string err;
    if (!info::encodeInfo(c, bytes, &err)) return false;
    return carplay::bplist::decode(bytes, out, &err);
}

std::vector<std::string> keysOf(const Value& dict) {
    std::vector<std::string> keys;
    for (size_t k = 0; k < dict.asDict().size(); ++k) keys.push_back(dict.asDict()[k].first);
    return keys;
}

int64_t intAt(const Value& dict, const char* key) {
    int64_t v = -999999;
    if (!dict.getInt(key, v)) return -999999;
    return v;
}

bool hasKey(const Value& dict, const char* key) { return dict.find(key) != NULL; }

const Value& mustFind(const Value& dict, const char* key) {
    static const Value kNull;
    const Value* v = dict.find(key);
    return v != NULL ? *v : kNull;
}

const Value& display0(const Value& root) { return mustFind(root, "displays").asArray()[0]; }

// Returns the audioFormats entry with the given type and audioType, or NULL.
const Value* audioFormat(const Value& root, int64_t type, const std::string& audio_type) {
    const Value* fmts = root.find("audioFormats");
    if (fmts == NULL || !fmts->isArray()) return NULL;
    const Value* found = NULL;
    int count = 0;
    for (size_t k = 0; k < fmts->asArray().size(); ++k) {
        const Value& e = fmts->asArray()[k];
        std::string at;
        if (intAt(e, "type") == type && e.getString("audioType", at) && at == audio_type) {
            found = &e;
            ++count;
        }
    }
    return count == 1 ? found : NULL;
}

int64_t outFmt(const Value& root, int64_t type, const char* at) {
    const Value* e = audioFormat(root, type, at);
    return e == NULL ? -1 : intAt(*e, "audioOutputFormats");
}

int64_t inFmt(const Value& root, int64_t type, const char* at) {
    const Value* e = audioFormat(root, type, at);
    if (e == NULL) return -2;
    return hasKey(*e, "audioInputFormats") ? intAt(*e, "audioInputFormats") : -1;
}

std::vector<std::string> strList(const char* a, const char* b = NULL, const char* c = NULL,
                                 const char* d = NULL, const char* e = NULL) {
    std::vector<std::string> v;
    const char* all[] = {a, b, c, d, e};
    for (size_t k = 0; k < 5; ++k) {
        if (all[k] != NULL) v.push_back(all[k]);
    }
    return v;
}

std::string joined(const std::vector<std::string>& v) {
    std::string out;
    for (size_t k = 0; k < v.size(); ++k) {
        if (k) out += ",";
        out += v[k];
    }
    return out;
}

void checkRect(const Value& d, int64_t w, int64_t h, int64_t x, int64_t y) {
    CHECK_EQ(w, intAt(d, "widthPixels"));
    CHECK_EQ(h, intAt(d, "heightPixels"));
    CHECK_EQ(x, intAt(d, "originXPixels"));
    CHECK_EQ(y, intAt(d, "originYPixels"));
}

}  // namespace

TEST_CASE(constantsMatchReference) {
    CHECK_EQ(std::string("b7e6c5a0-1111-4000-8000-000000000001"), std::string(info::kMainDisplayUuid));
    CHECK_EQ(std::string("b7e6c5a0-2222-4000-8000-000000000002"), std::string(info::kAltDisplayUuid));
    CHECK_EQ(110, info::kStreamTypeMainScreen);
    CHECK_EQ(111, info::kStreamTypeAltScreen);
    CHECK_EQ(100, info::kStreamTypeMainAudio);
    CHECK_EQ(101, info::kStreamTypeAltAudio);
    CHECK_EQ(102, info::kStreamTypeMainHighAudio);
    CHECK_EQ(103, info::kStreamTypeMainBufferedAudio);
    CHECK_EQ(130, info::kStreamTypeData);
}

TEST_CASE(topLevelKeyOrderMatchesReference) {
    info::AirPlayConfig c = info::bmwEntryNav2_1280x480();
    Value root;
    REQUIRE(roundTrip(c, root));
    REQUIRE(root.isDict());
    const std::string expected =
        "sourceVersion,features,statusFlags,model,manufacturer,deviceID,bluetoothIDs,name,"
        "rightHandDrive,keepAliveLowPower,keepAliveSendStatsAsBody,modes,audioLatencies,"
        "audioFormats,extendedFeatures,displays,hidDevices";
    CHECK_EQ(expected, joined(keysOf(root)));

    // Everything optional switched on: icons, hevc, mainBuffered.
    c.hevc = true;
    c.main_buffered_audio = true;
    info::OemIcon icon;
    icon.width_pixels = 1;
    icon.height_pixels = 1;
    icon.data.push_back(1);
    c.icons.push_back(icon);
    Value full;
    REQUIRE(roundTrip(c, full));
    CHECK_EQ(expected + ",oemIconVisible,oemIconLabel,oemIcons,hevcInfo,mainBufferedInfo",
             joined(keysOf(full)));
}

TEST_CASE(scalarTopLevelValuesAndTypes) {
    info::AirPlayConfig c = baseConfig();
    c.right_hand_drive = true;
    c.manufacturer = "Example";
    c.model = "HeadUnit";
    Value root;
    REQUIRE(roundTrip(c, root));
    std::string sv;
    CHECK(root.getString("sourceVersion", sv));
    CHECK_EQ(std::string("366.0"), sv);
    uint64_t f = 0;
    CHECK(root.getUInt("features", f));
    CHECK_EQ(static_cast<uint64_t>(0x615653aee2ULL), f);
    CHECK_EQ(4, intAt(root, "statusFlags"));
    std::string str;
    CHECK(root.getString("model", str) && str == "HeadUnit");
    CHECK(root.getString("manufacturer", str) && str == "Example");
    CHECK(root.getString("deviceID", str) && str == "02:00:00:00:00:02");
    CHECK(root.getString("name", str) && str == "test");
    const Value& bt = mustFind(root, "bluetoothIDs");
    REQUIRE(bt.isArray() && bt.asArray().size() == 1);
    CHECK_EQ(std::string("02:00:00:00:00:02"), bt.asArray()[0].asString());
    CHECK(mustFind(root, "rightHandDrive").isBool());
    CHECK(mustFind(root, "rightHandDrive").asBool());
    CHECK(mustFind(root, "keepAliveLowPower").isBool());
    CHECK(!mustFind(root, "keepAliveLowPower").asBool());
    CHECK(mustFind(root, "keepAliveSendStatsAsBody").isBool());
    CHECK(!mustFind(root, "keepAliveSendStatsAsBody").asBool());
    const Value& ext = mustFind(root, "extendedFeatures");
    REQUIRE(ext.isArray() && ext.asArray().size() == 2);
    CHECK_EQ(std::string("vocoderInfo"), ext.asArray()[0].asString());
    CHECK_EQ(std::string("enhancedRequestCarUI"), ext.asArray()[1].asString());
}

TEST_CASE(featuresValueAndNoAudioVariant) {
    info::AirPlayConfig c = baseConfig();
    CHECK_EQ(static_cast<uint64_t>(0x615653aee2ULL), info::features(c));
    c.disable_audio_output = true;
    CHECK_EQ(static_cast<uint64_t>(0x615203a4e2ULL), info::features(c));
    CHECK_EQ(info::kCarPlayFeatures & ~info::kCarPlayAudioFeatures, info::features(c));

    Value root;
    REQUIRE(roundTrip(c, root));
    uint64_t f = 0;
    CHECK(root.getUInt("features", f));
    CHECK_EQ(static_cast<uint64_t>(0x615203a4e2ULL), f);
    CHECK(!hasKey(root, "audioLatencies"));
    CHECK(!hasKey(root, "audioFormats"));
    CHECK_EQ(std::string("sourceVersion,features,statusFlags,model,manufacturer,deviceID,"
                         "bluetoothIDs,name,rightHandDrive,keepAliveLowPower,"
                         "keepAliveSendStatsAsBody,modes,extendedFeatures,displays,hidDevices"),
             joined(keysOf(root)));

    // mainBuffered is suppressed when audio output is disabled.
    c.main_buffered_audio = true;
    Value nb;
    REQUIRE(roundTrip(c, nb));
    CHECK(!hasKey(nb, "mainBufferedInfo"));
}

TEST_CASE(modesStructure) {
    Value root;
    REQUIRE(roundTrip(baseConfig(), root));
    const Value& modes = mustFind(root, "modes");
    REQUIRE(modes.isDict());
    CHECK_EQ(std::string("resources,appStates"), joined(keysOf(modes)));
    const Value::Array& res = mustFind(modes, "resources").asArray();
    REQUIRE(res.size() == 2);
    for (size_t k = 0; k < 2; ++k) {
        CHECK_EQ(std::string("resourceID,transferType,transferPriority,takeConstraint,"
                             "borrowConstraint,unborrowConstraint"),
                 joined(keysOf(res[k])));
        CHECK_EQ(static_cast<int64_t>(k + 1), intAt(res[k], "resourceID"));
        CHECK_EQ(1, intAt(res[k], "transferType"));
        CHECK_EQ(100, intAt(res[k], "transferPriority"));
        CHECK_EQ(100, intAt(res[k], "takeConstraint"));
        CHECK_EQ(100, intAt(res[k], "borrowConstraint"));
        CHECK_EQ(100, intAt(res[k], "unborrowConstraint"));
    }
    const Value::Array& st = mustFind(modes, "appStates").asArray();
    REQUIRE(st.size() == 3);
    CHECK_EQ(2, intAt(st[0], "appStateID"));
    CHECK(mustFind(st[0], "state").isBool() && !mustFind(st[0], "state").asBool());
    CHECK_EQ(1, intAt(st[1], "appStateID"));
    CHECK_EQ(-1, intAt(st[1], "speechMode"));
    CHECK(!hasKey(st[1], "state"));
    CHECK_EQ(3, intAt(st[2], "appStateID"));
    CHECK(mustFind(st[2], "state").isBool() && !mustFind(st[2], "state").asBool());
}

TEST_CASE(audioLatenciesNineEntries) {
    Value root;
    REQUIRE(roundTrip(baseConfig(), root));
    const Value::Array& lat = mustFind(root, "audioLatencies").asArray();
    REQUIRE(lat.size() == 9);
    const int64_t types[] = {100, 100, 100, 100, 100, 100, 101, 101, 102};
    const char* ats[] = {NULL, "default", "media", "telephony", "speechRecognition", "alert",
                         NULL, "default", "default"};
    for (size_t k = 0; k < 9; ++k) {
        CHECK_EQ(types[k], intAt(lat[k], "type"));
        CHECK_EQ(0, intAt(lat[k], "inputLatencyMicros"));
        CHECK_EQ(0, intAt(lat[k], "outputLatencyMicros"));
        std::string at;
        if (ats[k] == NULL) {
            CHECK(!hasKey(lat[k], "audioType"));
            CHECK_EQ(std::string("type,inputLatencyMicros,outputLatencyMicros"), joined(keysOf(lat[k])));
        } else {
            CHECK(lat[k].getString("audioType", at));
            CHECK_EQ(std::string(ats[k]), at);
        }
    }
}

TEST_CASE(audioFormats48kWithMicrophone) {
    info::AirPlayConfig c = baseConfig();
    c.microphone = true;
    Value root;
    REQUIRE(roundTrip(c, root));
    const Value::Array& f = mustFind(root, "audioFormats").asArray();
    REQUIRE(f.size() == 9);
    CHECK_EQ(std::string("type,audioType,audioOutputFormats,audioInputFormats"), joined(keysOf(f[0])));
    CHECK_EQ(0xc3fc, outFmt(root, 100, "compatibility"));
    CHECK_EQ(0x4154, inFmt(root, 100, "compatibility"));
    CHECK_EQ(0xc3fc, outFmt(root, 101, "compatibility"));
    CHECK_EQ(-1, inFmt(root, 101, "compatibility"));
    CHECK_EQ(0xc3fc | kOpus, outFmt(root, 100, "default"));
    CHECK_EQ(0x70004154, inFmt(root, 100, "default"));
    CHECK_EQ(0xc3fc | kOpus, outFmt(root, 100, "alert"));
    CHECK_EQ(-1, inFmt(root, 100, "alert"));
    CHECK_EQ(0xc3fc, outFmt(root, 100, "media"));
    CHECK_EQ(0x70004154, outFmt(root, 100, "telephony"));
    CHECK_EQ(0x70004154, inFmt(root, 100, "telephony"));
    CHECK_EQ(0x70004154, outFmt(root, 100, "speechRecognition"));
    CHECK_EQ(0x70004154, inFmt(root, 100, "speechRecognition"));
    CHECK_EQ(0xc3fc | kOpus, outFmt(root, 101, "default"));
    CHECK_EQ(0x800000, outFmt(root, 102, "media"));
    // Stream types are exactly {100, 101, 102}.
    for (size_t k = 0; k < f.size(); ++k) {
        const int64_t t = intAt(f[k], "type");
        CHECK(t == 100 || t == 101 || t == 102);
    }
}

TEST_CASE(audioFormats44k) {
    info::AirPlayConfig c = baseConfig();
    c.entertainment_sample_rate = 44100;
    c.microphone = true;
    Value root;
    REQUIRE(roundTrip(c, root));
    CHECK_EQ(0xffc, outFmt(root, 100, "compatibility"));
    CHECK_EQ(0x554, inFmt(root, 100, "compatibility"));
    CHECK_EQ(0xffc | kOpus, outFmt(root, 100, "default"));
    CHECK_EQ(0x554 | kOpus, inFmt(root, 100, "default"));
    CHECK_EQ(0x554 | kOpus, outFmt(root, 100, "telephony"));
    CHECK_EQ(0x400000, outFmt(root, 102, "media"));
}

TEST_CASE(microphoneInputsOnlyWhenEnabled) {
    info::AirPlayConfig c = baseConfig();
    Value off;
    REQUIRE(roundTrip(c, off));
    const char* withInput[] = {"compatibility", "default", "telephony", "speechRecognition"};
    for (size_t k = 0; k < 4; ++k) CHECK_EQ(-1, inFmt(off, 100, withInput[k]));

    c.microphone = true;
    c.microphone_opus = false;
    Value no_opus;
    REQUIRE(roundTrip(c, no_opus));
    CHECK_EQ(0x4154, inFmt(no_opus, 100, "telephony"));
    CHECK_EQ(0x4154, inFmt(no_opus, 100, "default"));
    CHECK_EQ(0x4154, inFmt(no_opus, 100, "speechRecognition"));
    CHECK_EQ(0x4154, inFmt(no_opus, 100, "compatibility"));
    // Output untouched by the microphone Opus flag.
    CHECK_EQ(0x70004154, outFmt(no_opus, 100, "telephony"));

    // microphoneOpus=false without a microphone: still no input.
    info::AirPlayConfig c2 = baseConfig();
    c2.microphone_opus = false;
    Value r2;
    REQUIRE(roundTrip(c2, r2));
    CHECK_EQ(-1, inFmt(r2, 100, "telephony"));
}

TEST_CASE(speechWithout8And16KhzOnlyAffectsSpeechStreams) {
    info::AirPlayConfig c = baseConfig();
    Value base;
    REQUIRE(roundTrip(c, base));
    c.speech_without_8_and_16khz = true;
    Value on;
    REQUIRE(roundTrip(c, on));
    const int64_t types[] = {100, 100, 101};
    const char* ats[] = {"default", "alert", "default"};
    for (size_t k = 0; k < 3; ++k) {
        CHECK_EQ(0x3c, outFmt(base, types[k], ats[k]) & 0x3c);
        CHECK_EQ(0, outFmt(on, types[k], ats[k]) & 0x3c);
        CHECK_EQ(outFmt(base, types[k], ats[k]) & ~static_cast<int64_t>(0x3c),
                 outFmt(on, types[k], ats[k]));
    }
    CHECK_EQ(outFmt(base, 100, "telephony"), outFmt(on, 100, "telephony"));
    CHECK_EQ(outFmt(base, 100, "media"), outFmt(on, 100, "media"));
}

TEST_CASE(callAtCallRateRestrictsTelephonyOnly) {
    info::AirPlayConfig c = baseConfig();
    c.microphone = true;
    Value base;
    REQUIRE(roundTrip(c, base));
    c.call_at_call_rate = true;
    Value on;
    REQUIRE(roundTrip(c, on));
    CHECK_EQ(0x70004154, outFmt(base, 100, "telephony"));
    CHECK_EQ(0x154, outFmt(on, 100, "telephony"));
    CHECK_EQ(0x70004154, inFmt(base, 100, "telephony"));
    CHECK_EQ(0x154, inFmt(on, 100, "telephony"));
    const char* others[] = {"default", "alert", "media", "speechRecognition", "compatibility"};
    for (size_t k = 0; k < 5; ++k) {
        const Value* a = audioFormat(base, 100, others[k]);
        const Value* b = audioFormat(on, 100, others[k]);
        REQUIRE(a != NULL && b != NULL);
        CHECK(*a == *b);
    }
    c.microphone = false;
    Value nomic;
    REQUIRE(roundTrip(c, nomic));
    CHECK_EQ(-1, inFmt(nomic, 100, "telephony"));
    CHECK_EQ(0x154, outFmt(nomic, 100, "telephony"));
}

TEST_CASE(mainBufferedEntryOnlyWhenEnabled) {
    info::AirPlayConfig c = baseConfig();
    Value off;
    REQUIRE(roundTrip(c, off));
    CHECK(audioFormat(off, 103, "media") == NULL);
    CHECK(!hasKey(off, "mainBufferedInfo"));
    c.main_buffered_audio = true;
    Value on;
    REQUIRE(roundTrip(c, on));
    REQUIRE(mustFind(on, "audioFormats").asArray().size() == 10);
    const Value& last = mustFind(on, "audioFormats").asArray()[9];
    CHECK_EQ(103, intAt(last, "type"));
    CHECK_EQ(0x800000, intAt(last, "audioOutputFormats"));
    CHECK(!hasKey(last, "audioInputFormats"));
    const Value& mbi = mustFind(on, "mainBufferedInfo");
    CHECK(mbi.isDict() && mbi.asDict().empty());
    c.entertainment_sample_rate = 44100;
    Value on44;
    REQUIRE(roundTrip(c, on44));
    CHECK_EQ(0x400000, outFmt(on44, 103, "media"));
}

TEST_CASE(defaultDisplayFullViewAndSafeArea) {
    Value root;
    REQUIRE(roundTrip(baseConfig(), root));
    REQUIRE(mustFind(root, "displays").asArray().size() == 1);
    const Value& d = display0(root);
    CHECK_EQ(std::string("uuid,type,maxFPS,widthPixels,heightPixels,widthPhysical,heightPhysical,"
                         "features,primaryInputDevice,uiAppearanceMode,uiAppearanceSetting,"
                         "mapAppearanceMode,mapAppearanceSetting,viewAreas,initialViewArea"),
             joined(keysOf(d)));
    CHECK_EQ(0, intAt(d, "initialViewArea"));
    CHECK(!hasKey(d, "cornerMasks"));
    CHECK(!hasKey(d, "viewAreaTransitionControl"));
    CHECK_EQ(1, intAt(d, "primaryInputDevice"));
    CHECK_EQ(0x0a, intAt(d, "features"));
    CHECK_EQ(60, intAt(d, "maxFPS"));
    CHECK_EQ(200, intAt(d, "widthPhysical"));
    CHECK_EQ(113, intAt(d, "heightPhysical"));  // round(200*720/1280 = 112.5) = 113
    const Value::Array& areas = mustFind(d, "viewAreas").asArray();
    REQUIRE(areas.size() == 1);
    CHECK(!hasKey(areas[0], "viewAreaStatusBarEdge"));
    checkRect(areas[0], 1280, 720, 0, 0);
    const Value& safe = mustFind(areas[0], "safeArea");
    REQUIRE(safe.isDict());
    CHECK_EQ(std::string("widthPixels,heightPixels,originXPixels,originYPixels,drawUIOutsideSafeArea"),
             joined(keysOf(safe)));
    checkRect(safe, 1280, 720, 0, 0);
    CHECK(mustFind(safe, "drawUIOutsideSafeArea").isBool());
    CHECK(mustFind(safe, "drawUIOutsideSafeArea").asBool());
    for (size_t k = 0; k < 4; ++k) {
        const char* keys[] = {"uiAppearanceMode", "uiAppearanceSetting", "mapAppearanceMode",
                              "mapAppearanceSetting"};
        CHECK_EQ(0, intAt(d, keys[k]));
    }
}

TEST_CASE(bmwProfilesDisplayGeometry) {
    struct Case {
        info::AirPlayConfig cfg;
        int64_t w, h, wmm, hmm;
    };
    Case cases[3];
    cases[0].cfg = info::bmwEntryNav2_800x480();
    cases[0].w = 800; cases[0].h = 480; cases[0].wmm = 142; cases[0].hmm = 85;
    cases[1].cfg = info::bmwEntryNav2_1280x480();
    cases[1].w = 1280; cases[1].h = 480; cases[1].wmm = 209; cases[1].hmm = 78;
    cases[2].cfg = info::bmwEntryNav2_1440x540();
    cases[2].w = 1440; cases[2].h = 540; cases[2].wmm = 244; cases[2].hmm = 92;
    for (size_t k = 0; k < 3; ++k) {
        const info::AirPlayConfig& c = cases[k].cfg;
        CHECK_EQ(std::string("BMW"), c.manufacturer);
        CHECK(c.microphone);
        CHECK(!c.hevc);
        CHECK(!c.has_cluster);
        CHECK_EQ(48000, c.entertainment_sample_rate);
        Value root;
        REQUIRE(roundTrip(c, root));
        REQUIRE(mustFind(root, "displays").asArray().size() == 1);
        const Value& d = display0(root);
        std::string uuid;
        CHECK(d.getString("uuid", uuid));
        CHECK_EQ(std::string(info::kMainDisplayUuid), uuid);
        CHECK_EQ(110, intAt(d, "type"));
        CHECK_EQ(60, intAt(d, "maxFPS"));
        CHECK_EQ(cases[k].w, intAt(d, "widthPixels"));
        CHECK_EQ(cases[k].h, intAt(d, "heightPixels"));
        CHECK_EQ(cases[k].wmm, intAt(d, "widthPhysical"));
        CHECK_EQ(cases[k].hmm, intAt(d, "heightPhysical"));
        CHECK_EQ(0x02, intAt(d, "features"));
        CHECK_EQ(3, intAt(d, "primaryInputDevice"));
        const Value::Array& areas = mustFind(d, "viewAreas").asArray();
        REQUIRE(areas.size() == 1);
        checkRect(areas[0], cases[k].w, cases[k].h, 0, 0);
        checkRect(mustFind(areas[0], "safeArea"), cases[k].w, cases[k].h, 0, 0);
        CHECK_EQ(0, intAt(d, "initialViewArea"));
        // Microphone on => input formats advertised.
        CHECK_EQ(0x70004154, inFmt(root, 100, "telephony"));
        CHECK(!hasKey(root, "hevcInfo"));
    }
    // Touch-capable variant adds the high-fidelity touch bit.
    Value t;
    REQUIRE(roundTrip(info::bmwEntryNav2_1280x480(true), t));
    CHECK_EQ(0x0a, intAt(display0(t), "features"));
    CHECK_EQ(3, intAt(display0(t), "primaryInputDevice"));
}

TEST_CASE(fpsAndPhysicalSizeSanitising) {
    info::AirPlayConfig c = baseConfig();
    c.main.fps = 37;
    c.main.has_width_physical_mm = true;
    c.main.width_physical_mm = 125;
    Value root;
    REQUIRE(roundTrip(c, root));
    CHECK_EQ(35, intAt(display0(root), "maxFPS"));
    CHECK_EQ(125, intAt(display0(root), "widthPhysical"));
    CHECK_EQ(70, intAt(display0(root), "heightPhysical"));  // round(125*720/1280 = 70.3)

    CHECK_EQ(30, info::sanitizeFps(0));
    CHECK_EQ(30, info::sanitizeFps(32));
    CHECK_EQ(35, info::sanitizeFps(33));
    CHECK_EQ(60, info::sanitizeFps(120));
    CHECK_EQ(55, info::sanitizeFps(57));
    CHECK_EQ(60, info::sanitizeFps(58));
    CHECK_EQ(1, info::sanitizeReportedPhysicalMm(-5));
    CHECK_EQ(2000, info::sanitizeReportedPhysicalMm(5000));

    // Over-range width is clamped before the height is derived from it.
    info::AirPlayConfig big = baseConfig(1000, 3000);
    big.main.has_width_physical_mm = true;
    big.main.width_physical_mm = 9000;
    Value rb;
    REQUIRE(roundTrip(big, rb));
    CHECK_EQ(2000, intAt(display0(rb), "widthPhysical"));
    CHECK_EQ(2000, intAt(display0(rb), "heightPhysical"));  // 6000 clamped

    // Explicit height is used (sanitised) instead of the aspect-ratio derivation.
    info::AirPlayConfig eh = baseConfig();
    eh.main.has_height_physical_mm = true;
    eh.main.height_physical_mm = 0;
    Value re;
    REQUIRE(roundTrip(eh, re));
    CHECK_EQ(1, intAt(display0(re), "heightPhysical"));
}

TEST_CASE(viewAreaInsetsAndSafeAreaInsets) {
    info::AirPlayConfig c = baseConfig(960, 540);
    c.main.has_safe_area = true;
    c.main.safe_area = info::Insets(10, 15, 20, 25);
    c.main.has_safe_area_draw_outside = true;
    c.main.safe_area_draw_outside = false;
    Value root;
    REQUIRE(roundTrip(c, root));
    const Value& area = mustFind(display0(root), "viewAreas").asArray()[0];
    checkRect(area, 960, 540, 0, 0);
    const Value& safe = mustFind(area, "safeArea");
    checkRect(safe, 915, 515, 20, 10);
    CHECK(mustFind(safe, "drawUIOutsideSafeArea").isBool());
    CHECK(!mustFind(safe, "drawUIOutsideSafeArea").asBool());

    // Display-level view insets shrink the view area; the safe area is NOT clipped by them.
    c.main.has_view_area = true;
    c.main.view_area = info::Insets(5, 7, 30, 40);
    Value r2;
    REQUIRE(roundTrip(c, r2));
    const Value& a2 = mustFind(display0(r2), "viewAreas").asArray()[0];
    checkRect(a2, 960 - 30 - 40, 540 - 5 - 7, 30, 5);
    checkRect(mustFind(a2, "safeArea"), 915, 515, 20, 10);

    // Reference: full-HD mapping (0,0)-(1920,975) after even alignment -> bottom inset 104.
    info::AirPlayConfig fhd = baseConfig(1920, 1080);
    fhd.main.has_safe_area = true;
    fhd.main.safe_area = info::Insets(0, 104, 0, 0);
    Value rf;
    REQUIRE(roundTrip(fhd, rf));
    checkRect(mustFind(mustFind(display0(rf), "viewAreas").asArray()[0], "safeArea"), 1920, 976, 0, 0);
}

TEST_CASE(multipleViewAreasDockEdgeAndClippedSafeArea) {
    info::AirPlayConfig c = baseConfig(2560, 1440);
    info::ViewArea full(2560, 1440);
    full.has_dock_edge = true;
    full.dock_edge = info::kDockEdgeDriverSide;
    info::ViewArea split(1270, 1208);
    split.has_dock_edge = true;
    split.dock_edge = info::kDockEdgeBottom;
    c.main.view_areas.push_back(full);
    c.main.view_areas.push_back(split);
    c.main.initial_view_area = 1;
    c.main.has_safe_area = true;
    c.main.safe_area = info::Insets(10, 0, 20, 0);
    Value root;
    REQUIRE(roundTrip(c, root));
    const Value& d = display0(root);
    const Value::Array& areas = mustFind(d, "viewAreas").asArray();
    REQUIRE(areas.size() == 2);
    CHECK_EQ(2, intAt(areas[0], "viewAreaStatusBarEdge"));
    CHECK_EQ(1, intAt(areas[1], "viewAreaStatusBarEdge"));
    CHECK_EQ(std::string("widthPixels,heightPixels,originXPixels,originYPixels,"
                         "viewAreaStatusBarEdge,safeArea"),
             joined(keysOf(areas[1])));
    checkRect(areas[1], 1270, 1208, 0, 0);
    checkRect(mustFind(areas[1], "safeArea"), 1270 - 20, 1208 - 10, 20, 10);
    CHECK_EQ(1, intAt(d, "initialViewArea"));
    CHECK(mustFind(d, "viewAreaTransitionControl").isBool());
    CHECK(mustFind(d, "viewAreaTransitionControl").asBool());

    // initialViewArea is clamped into range.
    c.main.initial_view_area = 9;
    Value r9;
    REQUIRE(roundTrip(c, r9));
    CHECK_EQ(1, intAt(display0(r9), "initialViewArea"));
    c.main.initial_view_area = -3;
    Value rn;
    REQUIRE(roundTrip(c, rn));
    CHECK_EQ(0, intAt(display0(rn), "initialViewArea"));

    // A single explicit area: no transition control, initial 0.
    info::AirPlayConfig one = baseConfig(1280, 480);
    one.main.view_areas.push_back(info::ViewArea(1000, 400, 280, 40));
    Value r1;
    REQUIRE(roundTrip(one, r1));
    CHECK(!hasKey(display0(r1), "viewAreaTransitionControl"));
    const Value& a1 = mustFind(display0(r1), "viewAreas").asArray()[0];
    checkRect(a1, 1000, 400, 280, 40);
    CHECK(!hasKey(a1, "viewAreaStatusBarEdge"));
    checkRect(mustFind(a1, "safeArea"), 1000, 400, 280, 40);  // safe clipped to the area
}

TEST_CASE(savedMappingOutsideSplitAreaUsesAreaBounds) {
    // Mappings (left, top, right, bottom) on 2560x1440: right of, below, and touching the split edge.
    const int32_t maps[3][4] = {{1280, 0, 2560, 1440}, {0, 1300, 2560, 1440}, {1270, 0, 2560, 1440}};
    for (size_t k = 0; k < 3; ++k) {
        info::AirPlayConfig c = baseConfig(2560, 1440);
        c.main.view_areas.push_back(info::ViewArea(2560, 1440));
        c.main.view_areas.push_back(info::ViewArea(1270, 1208));
        c.main.has_safe_area = true;
        c.main.safe_area = info::Insets(maps[k][1], 1440 - maps[k][3], maps[k][0], 2560 - maps[k][2]);
        Value root;
        REQUIRE(roundTrip(c, root));
        const Value::Array& areas = mustFind(display0(root), "viewAreas").asArray();
        REQUIRE(areas.size() == 2);
        checkRect(mustFind(areas[0], "safeArea"), maps[k][2] - maps[k][0], maps[k][3] - maps[k][1],
                  maps[k][0], maps[k][1]);
        checkRect(mustFind(areas[1], "safeArea"), 1270, 1208, 0, 0);
    }
}

TEST_CASE(disableSafeAreaOnlyAffectsMainDisplay) {
    info::AirPlayConfig c = baseConfig();
    c.main.disable_safe_area = true;
    c.has_cluster = true;
    c.cluster = info::DisplayConfig(960, 360);
    c.cluster.disable_safe_area = true;
    Value root;
    REQUIRE(roundTrip(c, root));
    const Value::Array& displays = mustFind(root, "displays").asArray();
    REQUIRE(displays.size() == 2);
    CHECK(!hasKey(mustFind(displays[0], "viewAreas").asArray()[0], "safeArea"));
    CHECK(hasKey(mustFind(displays[1], "viewAreas").asArray()[0], "safeArea"));
}

TEST_CASE(clusterDisplayAddsAltEntryAndAltScreenFeature) {
    info::AirPlayConfig c = info::bmwEntryNav2_1280x480();
    c.has_cluster = true;
    c.cluster = info::DisplayConfig(960, 360);
    c.cluster.has_width_physical_mm = true;
    c.cluster.width_physical_mm = 300;
    c.cluster.has_height_physical_mm = true;
    c.cluster.height_physical_mm = 113;
    c.cluster.fps = 30;
    c.cluster.primary_input_device = info::kPrimaryInputNone;
    c.cluster.has_features = true;
    c.cluster.features = 0;
    c.cluster.has_initial_url = true;
    c.cluster.initial_url = "maps:";
    Value root;
    REQUIRE(roundTrip(c, root));
    const Value::Array& displays = mustFind(root, "displays").asArray();
    REQUIRE(displays.size() == 2);
    const Value& alt = displays[1];
    std::string uuid;
    CHECK(alt.getString("uuid", uuid));
    CHECK_EQ(std::string(info::kAltDisplayUuid), uuid);
    CHECK_EQ(111, intAt(alt, "type"));
    CHECK_EQ(30, intAt(alt, "maxFPS"));
    CHECK_EQ(960, intAt(alt, "widthPixels"));
    CHECK_EQ(360, intAt(alt, "heightPixels"));
    CHECK_EQ(300, intAt(alt, "widthPhysical"));
    CHECK_EQ(113, intAt(alt, "heightPhysical"));
    CHECK_EQ(0, intAt(alt, "features"));
    CHECK_EQ(0, intAt(alt, "primaryInputDevice"));
    std::string url;
    CHECK(alt.getString("initialURL", url));
    CHECK_EQ(std::string("maps:"), url);
    CHECK_EQ(std::string("initialURL"), keysOf(alt).back());
    for (size_t k = 0; k < 2; ++k) {
        CHECK_EQ(0, intAt(displays[k], "uiAppearanceMode"));
        CHECK_EQ(0, intAt(displays[k], "mapAppearanceSetting"));
    }
    // HID devices stay bound to the main display.
    const Value::Array& hids = mustFind(root, "hidDevices").asArray();
    for (size_t k = 0; k < hids.size(); ++k) {
        std::string du;
        CHECK(hids[k].getString("displayUUID", du));
        CHECK_EQ(std::string(info::kMainDisplayUuid), du);
    }
    const std::vector<std::string> f = info::setupEnabledFeatures(c, std::vector<std::string>());
    CHECK_EQ(std::string("iAPChannel,viewAreas,altScreen"), joined(f));
}

TEST_CASE(hidDevicesUseExistingDescriptors) {
    info::AirPlayConfig c = info::bmwEntryNav2_800x480();
    Value root;
    REQUIRE(roundTrip(c, root));
    const Value::Array& hids = mustFind(root, "hidDevices").asArray();
    REQUIRE(hids.size() == 4);
    const char* uuids[] = {"2a2a2a2a", "2a2a2a2b", "2a2a2a2c", "2a2a2a2d"};
    const char* names[] = {"EntryNav2 Touchscreen", "EntryNav2 Knob", "EntryNav2 Media",
                           "EntryNav2 Telephony"};
    std::vector<std::vector<uint8_t> > descs;
    descs.push_back(hid::touchscreenDescriptor());
    descs.push_back(hid::knobDescriptor());
    descs.push_back(hid::mediaDescriptor());
    descs.push_back(hid::telephonyDescriptor());
    for (size_t k = 0; k < 4; ++k) {
        CHECK_EQ(std::string("hidProductID,hidVendorID,hidCountryCode,uuid,name,displayUUID,hidDescriptor"),
                 joined(keysOf(hids[k])));
        CHECK_EQ(1, intAt(hids[k], "hidProductID"));
        CHECK_EQ(2, intAt(hids[k], "hidVendorID"));
        CHECK_EQ(0, intAt(hids[k], "hidCountryCode"));
        std::string s;
        CHECK(hids[k].getString("uuid", s));
        CHECK_EQ(std::string(uuids[k]), s);
        CHECK(hids[k].getString("name", s));
        CHECK_EQ(std::string(names[k]), s);
        CHECK(hids[k].getString("displayUUID", s));
        CHECK_EQ(std::string(info::kMainDisplayUuid), s);
        const Value& d = mustFind(hids[k], "hidDescriptor");
        REQUIRE(d.isData());
        CHECK_BYTES_EQ(descs[k], d.asData());
        CHECK(hid::inspectDescriptor(d.asData()).valid);
    }
    // Generic config keeps the reference's "xcertplay" names.
    Value g;
    REQUIRE(roundTrip(baseConfig(), g));
    std::string n;
    CHECK(mustFind(g, "hidDevices").asArray()[1].getString("name", n));
    CHECK_EQ(std::string("xcertplay Knob"), n);
}

TEST_CASE(oemIconAdvertisedWithOriginalBytes) {
    info::AirPlayConfig c = baseConfig();
    Value none;
    REQUIRE(roundTrip(c, none));
    CHECK(!hasKey(none, "oemIcons"));
    CHECK(!hasKey(none, "oemIconVisible"));
    info::OemIcon icon;
    icon.width_pixels = 1;
    icon.height_pixels = 1;
    icon.data = test_support::hexToBytes("01020304");
    c.icons.push_back(icon);
    c.oem_label = "xcertplay";
    Value root;
    REQUIRE(roundTrip(c, root));
    CHECK(mustFind(root, "oemIconVisible").isBool() && mustFind(root, "oemIconVisible").asBool());
    std::string label;
    CHECK(root.getString("oemIconLabel", label));
    CHECK_EQ(std::string("xcertplay"), label);
    const Value::Array& icons = mustFind(root, "oemIcons").asArray();
    REQUIRE(icons.size() == 1);
    CHECK_EQ(std::string("imageData,widthPixels,heightPixels,prerendered"), joined(keysOf(icons[0])));
    CHECK_EQ(1, intAt(icons[0], "widthPixels"));
    CHECK_EQ(1, intAt(icons[0], "heightPixels"));
    CHECK(mustFind(icons[0], "prerendered").isBool() && mustFind(icons[0], "prerendered").asBool());
    CHECK_BYTES_EQ(test_support::hexToBytes("01020304"), mustFind(icons[0], "imageData").asData());
}

TEST_CASE(hevcAddsInfoAndFeature) {
    info::AirPlayConfig c = baseConfig();
    Value off;
    REQUIRE(roundTrip(c, off));
    CHECK(!hasKey(off, "hevcInfo"));
    CHECK_EQ(std::string("iAPChannel,viewAreas"),
             joined(info::setupEnabledFeatures(c, std::vector<std::string>())));
    c.hevc = true;
    Value on;
    REQUIRE(roundTrip(c, on));
    const Value& h = mustFind(on, "hevcInfo");
    CHECK(h.isDict() && h.asDict().empty());
    CHECK_EQ(std::string("hevc,iAPChannel,viewAreas"),
             joined(info::setupEnabledFeatures(c, std::vector<std::string>())));
}

TEST_CASE(setupEnabledFeaturesCases) {
    info::AirPlayConfig c = baseConfig();
    const std::vector<std::string> proposed = strList("mainBuffered", "cornerMasks", "videoPlayback");
    // Out-of-scope features are never enabled even when proposed.
    CHECK_EQ(std::string("iAPChannel,viewAreas"), joined(info::setupEnabledFeatures(c, proposed)));
    c.main_buffered_audio = true;
    CHECK_EQ(std::string("iAPChannel,viewAreas,mainBuffered"),
             joined(info::setupEnabledFeatures(c, proposed)));
    // Not proposed by the phone -> not enabled.
    CHECK_EQ(std::string("iAPChannel,viewAreas"),
             joined(info::setupEnabledFeatures(c, strList("altScreen"))));
    // Audio output disabled suppresses mainBuffered.
    c.disable_audio_output = true;
    CHECK_EQ(std::string("iAPChannel,viewAreas"), joined(info::setupEnabledFeatures(c, proposed)));
    c.disable_audio_output = false;
    c.hevc = true;
    c.has_cluster = true;
    c.cluster = info::DisplayConfig(800, 240);
    CHECK_EQ(std::string("hevc,iAPChannel,viewAreas,altScreen,mainBuffered"),
             joined(info::setupEnabledFeatures(c, proposed)));

    // bplist-array overload: non-strings ignored, NULL means nothing proposed.
    Value arr = Value::makeArray();
    arr.asArray().push_back(Value::makeInt(7));
    arr.asArray().push_back(Value::makeString("mainBuffered"));
    CHECK_EQ(std::string("hevc,iAPChannel,viewAreas,altScreen,mainBuffered"),
             joined(info::setupEnabledFeatures(c, &arr)));
    CHECK_EQ(std::string("hevc,iAPChannel,viewAreas,altScreen"),
             joined(info::setupEnabledFeatures(c, static_cast<const Value*>(NULL))));
    Value notArray = Value::makeString("mainBuffered");
    CHECK_EQ(std::string("hevc,iAPChannel,viewAreas,altScreen"),
             joined(info::setupEnabledFeatures(c, &notArray)));
}

int main() { return test_support::runAll("test_airplay_info"); }
