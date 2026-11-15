// BMW HU_ENTRYNAV2 HmiMain3D RHMI plugin (`libEntryCarPlay.so`).
//
// Zero link-time dependency on BMW's proprietary `libAppFramework.A.so` / `libCoreFramework.A.so`:
// all framework symbols are resolved at runtime from `HmiMain3D`'s global symbol table via
// `dlsym(RTLD_DEFAULT, ...)` (or injected via `entryCarPlaySetFrameworkApiForTest` in unit tests).

#include "carplay/platform/entry_carplay_plugin.hpp"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <new>
#include <string>

#include "carplay/platform/evo_control.hpp"
#include "carplay/platform/file_util.hpp"
#include "carplay/platform/hold_machine.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/peek_timing.hpp"
#include "carplay/platform/service_contract.hpp"

namespace carplay {
namespace platform {
namespace hmi {

namespace {

static const size_t kPluginAppStorage = 0x200U;
static const int kSlotOnError = 21;
static const int kSlotOnInit = 22;
static const int kSlotOnFinalize = 23;
static const unsigned kStatusPollMs = 1000U;

struct AppRunnable {
    void** vptr;
    void* vtbl[5];
};

BmwFrameworkApi g_fw;
bool g_fw_injected = false;

std::string g_data_dir = contract::kDataDir;
std::string g_control_name = contract::kControlName;
std::string g_state_file = contract::kStateFile;
std::string g_app_key_file = contract::kAppKeyFile;
std::string g_day_night_file = contract::kDayNightFile;
std::string g_media_recall_file = contract::kMediaRecallFile;

void* g_app = NULL;
void* g_run_app = NULL;
void* g_vtbl[36];
long g_init_time = 0;
bool g_stable_marked = false;
bool g_autostart_done = false;
unsigned g_shown_text = rhmi::kTextDefault;
unsigned g_shown_row = rhmi::kTextStart;
int g_stop_shown = -1;
bool g_call_line[2] = {false, false};
int g_last_gear = kGearUnknown;
int g_last_day_night = -1000;
int g_last_drive_mode[2] = {-1000, -1000};
long g_drive_mode_sub_at = -1;

AppRunnable g_status_runnable;
AppRunnable g_sub_runnable;

long monoSeconds() {
    return static_cast<long>(monotonicMillis() / 1000);
}

void appLog(const char* fmt, ...) {
    const std::string log_path = g_data_dir + "/app.log";
    FILE* f = fopen(log_path.c_str(), "a");
    if (!f) {
        return;
    }
    fprintf(f, "[%ld] ", monoSeconds());
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fprintf(f, "\n");
    fclose(f);
}

void runnableNoop(void*) {}

void makeRunnable(AppRunnable& r, void (*run_fn)(void*)) {
    memset(&r, 0, sizeof(r));
    if (g_fw.runnable_vtable != NULL) {
        memcpy(r.vtbl, g_fw.runnable_vtable, 5 * sizeof(void*));
    }
    r.vtbl[2] = reinterpret_cast<void*>(&runnableNoop);
    r.vtbl[3] = reinterpret_cast<void*>(&runnableNoop);
    r.vtbl[4] = reinterpret_cast<void*>(run_fn);
    r.vptr = r.vtbl + 2;
}

void narrowU16(const BmwBasicStringU16& value, char* text, size_t cap) {
    size_t n = 0U;
    const uint16_t* p = value.data;
    while (p != NULL && p[n] != 0U && n + 1U < cap) {
        text[n] = (p[n] < 0x80U) ? static_cast<char>(p[n]) : '?';
        ++n;
    }
    if (cap > 0U) {
        text[n] = '\0';
    }
}

bool parcelBool(const BmwParcelStorage& parcel) {
    bool b = false;
    if (g_fw.parcel_read_bool != NULL) {
        g_fw.parcel_read_bool(&parcel, b);
    }
    return b;
}

void triggerFocusEvent(void* app, unsigned event_id) {
    if (app != NULL && g_fw.trigger_event != NULL) {
        g_fw.trigger_event(app, event_id);
    }
}

void triggerPopupEvent(void* app, unsigned event_id, bool open) {
    if (app != NULL && g_fw.parcel_ctor_bool != NULL &&
        g_fw.trigger_event_parcel != NULL && g_fw.parcel_dtor != NULL) {
        BmwParcelStorage p;
        memset(&p, 0, sizeof(p));
        g_fw.parcel_ctor_bool(&p, open);
        g_fw.trigger_event_parcel(app, event_id, p);
        g_fw.parcel_dtor(&p);
    }
}

void updateTextModel(void* app, unsigned model_id, unsigned text_id) {
    if (app != NULL && g_fw.text_id_ctor != NULL && g_fw.update_model_text != NULL) {
        BmwTextIdStorage t;
        memset(&t, 0, sizeof(t));
        g_fw.text_id_ctor(&t, text_id);
        g_fw.update_model_text(app, model_id, t);
    }
}

void setComponentVisible(void* app, unsigned comp_id, bool visible) {
    if (app != NULL && g_fw.parcel_ctor_bool != NULL &&
        g_fw.set_property != NULL && g_fw.parcel_dtor != NULL) {
        BmwParcelStorage p;
        memset(&p, 0, sizeof(p));
        g_fw.parcel_ctor_bool(&p, visible);
        g_fw.set_property(app, comp_id, rhmi::kPropVisible, p);
        g_fw.parcel_dtor(&p);
    }
}

void addCdsProperty(void* app,
                    const char* prop_name,
                    bool (*stub)(void*, const BmwBasicStringU16&)) {
    if (app != NULL && g_fw.bstr_ctor_cstr != NULL &&
        g_fw.cds_add_handler != NULL && g_fw.bstr_dtor != NULL) {
        BmwBasicStringChar s;
        s.data = NULL;
        g_fw.bstr_ctor_cstr(&s, prop_name);
        BmwCdsDelegate d;
        d.object = app;
        d.stub = stub;
        g_fw.cds_add_handler(app, s, 0U, d);
        g_fw.bstr_dtor(&s);
    }
}

void launchDaemonProcess() {
#ifndef _WIN32
    const char* bin = contract::kSupervisor;
    struct stat st;
    if (stat(bin, &st) != 0) {
        bin = contract::kService;
        if (stat(bin, &st) != 0) {
            appLog("launch: neither %s nor %s exists", contract::kSupervisor, contract::kService);
            return;
        }
    }
    unlink(contract::kServiceStop);

    static const char* const kEnv[] = {
        "PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin",
        "LD_LIBRARY_PATH=/usr/local/lib:/opt/hmi/lib:/usr/lib:/lib",
        "XDG_RUNTIME_DIR=/run/system/0",
        "WAYLAND_DISPLAY=wayland-0",
        "HOME=/tmp",
        NULL
    };
    char* argv[] = {
        const_cast<char*>(bin),
        const_cast<char*>("--service"),
        NULL
    };
    int in_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int out_fd = open(contract::kServiceLog, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (in_fd < 0 || out_fd < 0) {
        if (in_fd >= 0) close(in_fd);
        if (out_fd >= 0) close(out_fd);
        return;
    }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, in_fd, 0);
    posix_spawn_file_actions_adddup2(&fa, out_fd, 1);
    posix_spawn_file_actions_adddup2(&fa, out_fd, 2);

    posix_spawnattr_t at;
    if (initServiceSpawnAttr(&at) == 0) {
        pid_t pid = -1;
        const int rc = posix_spawn(
            &pid, bin, &fa, &at, argv, const_cast<char* const*>(kEnv));
        posix_spawnattr_destroy(&at);
        if (rc == 0) {
            appLog("launch: spawned %s pid %d", bin, static_cast<int>(pid));
        } else {
            appLog("launch: posix_spawn(%s) failed: %s", bin, strerror(rc));
        }
    }
    posix_spawn_file_actions_destroy(&fa);
    close(in_fd);
    close(out_fd);
#endif
}

class AppHoldIo : public HoldIo {
public:
    virtual void triggerEvent(unsigned event) {
        triggerFocusEvent(g_run_app, event);
    }
    virtual void ownPopup(bool open) {
        triggerPopupEvent(g_run_app, rhmi::kEvOwnPopup, open);
    }
    virtual void send(const char* message) {
        sendControl(g_control_name.c_str(), message);
    }
    virtual void log(const char* line) {
        appLog("%s", line ? line : "");
    }
    virtual ServiceState readService() {
        return readServiceStateFile(g_state_file.c_str(), g_control_name.c_str());
    }
    virtual bool appKeyAge(long* seconds) {
#ifndef _WIN32
        struct stat st;
        if (stat(g_app_key_file.c_str(), &st) != 0) {
            return false;
        }
        const time_t now = time(NULL);
        if (seconds != NULL) {
            *seconds = (now >= st.st_mtime) ? static_cast<long>(now - st.st_mtime) : 0L;
        }
        return true;
#else
        (void)seconds;
        return false;
#endif
    }
    virtual void removeAppKey() {
        removeFile(g_app_key_file);
    }
};

AppHoldIo g_hold_io;
HoldMachine g_hold(g_hold_io);

bool callActive() {
    return g_call_line[0] || g_call_line[1];
}

// ---- RHMI Action & State Handlers ----

bool onStartRow(void*, const BmwParcelStorage&) {
    const ServiceState d = readServiceStateFile(g_state_file.c_str(), g_control_name.c_str());
    if (d.is("connected")) {
        g_hold.showAndHold("menu Open row", monoSeconds());
    } else if (d.pid == 0) {
        removeFile(g_data_dir + "/bootguard");
        launchDaemonProcess();
    }
    return true;
}

bool onStopRow(void*, const BmwParcelStorage&) {
    sendControl(g_control_name.c_str(), "quit");
    return true;
}

bool onEntryButton(void*, const BmwParcelStorage&) {
    const ServiceState d = readServiceStateFile(g_state_file.c_str(), g_control_name.c_str());
    if (d.is("connected") && !callActive() && g_last_gear != kReverseGear) {
        g_hold.showAndHold("entry button", monoSeconds());
    } else if (g_run_app != NULL) {
        triggerFocusEvent(g_run_app, rhmi::kEvOpenMenu);
    }
    return true;
}

bool onAutostartToggle(void*, const BmwParcelStorage&) {
    const std::string path = g_data_dir + "/autostart";
    if (pathExists(path)) {
        removeFile(path);
    } else {
        const uint8_t one[2] = {'1', '\n'};
        writeFileAtomic(path, one, sizeof(one));
    }
    if (g_run_app != NULL && g_fw.update_model_bool != NULL) {
        g_fw.update_model_bool(g_run_app, rhmi::kAutostartModel, pathExists(path));
    }
    return true;
}

bool onUsbCableToggle(void*, const BmwParcelStorage&) {
    const std::string path = g_data_dir + "/usb";
    if (pathExists(path)) {
        removeFile(path);
    } else {
        writeFileAtomic(path, NULL, 0U);
    }
    if (g_run_app != NULL && g_fw.update_model_bool != NULL) {
        g_fw.update_model_bool(g_run_app, rhmi::kUsbCableModel, pathExists(path));
    }
    return true;
}

bool onMenuFocus(void*, const BmwParcelStorage& p) {
    g_hold.menuFocus(rhmi::kMenuState, parcelBool(p), monoSeconds(),
                     static_cast<long>(monotonicMillis()));
    return true;
}

bool onHelpFocus(void*, const BmwParcelStorage& p) {
    g_hold.menuFocus(rhmi::kHelpState, parcelBool(p), monoSeconds(),
                     static_cast<long>(monotonicMillis()));
    return true;
}

bool onCarPlayFocus(void*, const BmwParcelStorage& p) {
    g_hold.carPlayFocus(parcelBool(p));
    return true;
}

bool onCarPlayVisible(void*, const BmwParcelStorage& p) {
    g_hold.carPlayVisible(parcelBool(p), monoSeconds());
    return true;
}

// ---- CDS Property Handlers ----

bool onGearChanged(void*, const BmwBasicStringU16& value) {
    char text[160];
    narrowU16(value, text, sizeof(text));
    const int gear = cdsGearValue(text, -1);
    if (gear != g_last_gear) {
        g_last_gear = gear;
        g_hold.gearChanged(gear);
        char msg[32];
        snprintf(msg, sizeof(msg), "gear %d", gear);
        sendControl(g_control_name.c_str(), msg);
    }
    return true;
}

bool onCallStatusLine(int line, const BmwBasicStringU16& value) {
    char text[200];
    narrowU16(value, text, sizeof(text));
    const bool active = cdsCallActive(text);
    const bool was = callActive();
    g_call_line[line] = active;
    g_hold.callChanged(callActive(), monoSeconds());
    if (was != callActive()) {
        sendControl(g_control_name.c_str(), callActive() ? "call 1" : "call 0");
    }
    return true;
}

bool onCallStatus0(void*, const BmwBasicStringU16& v) { return onCallStatusLine(0, v); }
bool onCallStatus1(void*, const BmwBasicStringU16& v) { return onCallStatusLine(1, v); }

bool onDayNightChanged(void*, const BmwBasicStringU16& value) {
    char text[160];
    narrowU16(value, text, sizeof(text));
    const int v = cdsIntField(text, "dayNightChangeOver", -1);
    if (v == g_last_day_night) {
        return true;
    }
    g_last_day_night = v;
    if (v != 1 && v != 2) {
        return true;
    }
    writeDayNightFile(g_day_night_file.c_str(), v);
    char msg[32];
    snprintf(msg, sizeof(msg), "daynight %d", v);
    sendControl(g_control_name.c_str(), msg);
    return true;
}

bool onDriveModeProp(int prop, const BmwBasicStringU16& value) {
    char text[160];
    narrowU16(value, text, sizeof(text));
    const int v = cdsIntField(text, "mode", -1);
    const int was = g_last_drive_mode[prop];
    if (v == was) {
        return true;
    }
    const int invalid = (prop == 1) ? 63 : 15;
    g_last_drive_mode[prop] = v;
    const bool valid = v >= 0 && v != invalid;
    const bool change =
        valid && ((was >= 0 && was != invalid) ||
                  (was < 0 && g_drive_mode_sub_at >= 0 && monoSeconds() - g_drive_mode_sub_at >= 5));
    if (!change) {
        return true;
    }
    char msg[32];
    snprintf(msg, sizeof(msg), "drivemode %d", v);
    sendControl(g_control_name.c_str(), msg);
    g_hold.driveModeChanged(monoSeconds());
    return true;
}

bool onDriveMode0(void*, const BmwBasicStringU16& v) { return onDriveModeProp(0, v); }
bool onDriveMode1(void*, const BmwBasicStringU16& v) { return onDriveModeProp(1, v); }

void subscribeRun(void*) {
    if (g_run_app == NULL) {
        return;
    }
    addCdsProperty(g_run_app, "driving.gear", &onGearChanged);
    addCdsProperty(g_run_app, "communication.callStatus0", &onCallStatus0);
    addCdsProperty(g_run_app, "communication.callStatus1", &onCallStatus1);
    addCdsProperty(g_run_app, "vehicle.dayNightChangeOver", &onDayNightChanged);
    g_drive_mode_sub_at = monoSeconds();
    addCdsProperty(g_run_app, "driving.mode", &onDriveMode0);
    addCdsProperty(g_run_app, "driving.mode35up", &onDriveMode1);
}

void statusRun(void*) {
    if (g_run_app == NULL) {
        return;
    }
    const long now_sec = static_cast<long>(time(NULL));
    resetGuardsWhenStableInDir(g_data_dir.c_str(), g_init_time, now_sec, g_stable_marked);

    if (!g_autostart_done && g_init_time > 0 && now_sec - g_init_time >= 30) {
        g_autostart_done = true;
        if (pathExists(g_data_dir + "/autostart")) {
            const ServiceState d0 = readServiceStateFile(g_state_file.c_str(), g_control_name.c_str());
            if (d0.pid == 0 && bootGuardAllowsInDir(g_data_dir.c_str(), now_sec)) {
                launchDaemonProcess();
            }
        }
    }

    const ServiceState d = readServiceStateFile(g_state_file.c_str(), g_control_name.c_str());
    const bool connecting = d.is("connecting");
    const bool connected = d.is("connected");
    const unsigned want_text = connecting ? rhmi::kTextConnecting : rhmi::kTextDefault;
    if (want_text != g_shown_text) {
        updateTextModel(g_run_app, rhmi::kEntryTextModel, want_text);
        g_shown_text = want_text;
    }

    const int stop_wanted = (d.pid != 0) ? 1 : 0;
    if (stop_wanted != g_stop_shown) {
        setComponentVisible(g_run_app, rhmi::kStopButton, stop_wanted != 0);
        g_stop_shown = stop_wanted;
    }

    g_hold.tellService(d);

    if (takeMediaRecall(g_media_recall_file.c_str(), d.pid, static_cast<uint32_t>(monotonicMillis()))) {
        const ServiceState cur = readServiceStateFile(g_state_file.c_str(), g_control_name.c_str());
        if (cur.pid == d.pid && cur.overlay == 0 && cur.is("connected") &&
            !callActive() && g_last_gear != kReverseGear) {
            g_hold.showAndHold("double MEDIA", monoSeconds());
        }
    }

    const unsigned row = connected ? rhmi::kTextRowOpen
                                   : (connecting ? rhmi::kTextRowConnecting : rhmi::kTextStart);
    if (row != g_shown_row) {
        updateTextModel(g_run_app, rhmi::kStartRowModel, row);
        g_shown_row = row;
    }

    g_hold.poll(d, monoSeconds());
    if (g_fw.post_runnable != NULL) {
        g_fw.post_runnable(g_run_app, &g_status_runnable, kStatusPollMs);
    }
}

// ---- PluginApp vtable hooks (slots 21, 22, 23) ----

bool appOnInit(void* self) {
    if (g_fw.add_action_handler != NULL) {
        BmwActionDelegate d;
        d.object = self;
        d.stub = &onStartRow;
        g_fw.add_action_handler(self, rhmi::kActStart, d);
        d.stub = &onStopRow;
        g_fw.add_action_handler(self, rhmi::kActStop, d);
        d.stub = &onEntryButton;
        g_fw.add_action_handler(self, rhmi::kActEntry, d);
        d.stub = &onAutostartToggle;
        g_fw.add_action_handler(self, rhmi::kActAutostart, d);
        d.stub = &onUsbCableToggle;
        g_fw.add_action_handler(self, rhmi::kActUsbCable, d);
    }
    if (g_fw.add_state_handler != NULL) {
        BmwActionDelegate d;
        d.object = self;
        d.stub = &onMenuFocus;
        g_fw.add_state_handler(self, rhmi::kMenuState, rhmi::kHandlerFocus, d);
        d.stub = &onHelpFocus;
        g_fw.add_state_handler(self, rhmi::kHelpState, rhmi::kHandlerFocus, d);
        d.stub = &onCarPlayFocus;
        g_fw.add_state_handler(self, rhmi::kCarPlayState, rhmi::kHandlerFocus, d);
        d.stub = &onCarPlayVisible;
        g_fw.add_state_handler(self, rhmi::kCarPlayState, rhmi::kHandlerVisible, d);
    }
    g_init_time = static_cast<long>(time(NULL));
    const bool ok = (g_fw.on_init != NULL) ? g_fw.on_init(self) : true;
    g_run_app = self;
    makeRunnable(g_sub_runnable, &subscribeRun);
    if (g_fw.post_runnable != NULL) {
        g_fw.post_runnable(self, &g_sub_runnable, 1500U);
    }
    makeRunnable(g_status_runnable, &statusRun);
    if (g_fw.post_runnable != NULL) {
        g_fw.post_runnable(self, &g_status_runnable, 2000U);
    }
    return ok;
}

void appOnError(void*, unsigned code, const BmwBasicStringChar& text) {
    appLog("onError %u: %s", code, text.data ? text.data : "(null)");
}

void appOnFinalize(void* self) {
    g_run_app = NULL;
    if (g_fw.on_finalize != NULL) {
        g_fw.on_finalize(self);
    }
}

void* createApp(void* dispatcher, const char* name, const void* params, const void* config) {
#ifndef _WIN32
    mkdir(g_data_dir.c_str(), 0755);
#endif
    if (isAppDisabledInDir(g_data_dir.c_str()) ||
        !crashGuardAllowsInDir(g_data_dir.c_str(), static_cast<long>(time(NULL)))) {
        return NULL;
    }
    if (g_app != NULL) {
        return NULL;
    }
    if (!g_fw_injected && !g_fw.resolveFromDefault()) {
        appLog("createApp: BMW framework symbols unavailable in process");
        return NULL;
    }

    void* mem = ::operator new(kPluginAppStorage);
    memset(mem, 0, kPluginAppStorage);

    BmwBasicStringChar app_name;
    app_name.data = NULL;
    g_fw.bstr_ctor_cstr(&app_name, name ? name : "EntryCarPlay");
    g_fw.plugin_app_ctor(mem, dispatcher, &app_name, 1U, 0U, 1, params, config);
    g_fw.bstr_dtor(&app_name);

    void** base = *reinterpret_cast<void***>(mem);
    if (base != NULL) {
        memcpy(g_vtbl, base - 2, sizeof(g_vtbl));
    } else {
        memset(g_vtbl, 0, sizeof(g_vtbl));
    }
    g_vtbl[2 + kSlotOnError] = reinterpret_cast<void*>(&appOnError);
    g_vtbl[2 + kSlotOnInit] = reinterpret_cast<void*>(&appOnInit);
    g_vtbl[2 + kSlotOnFinalize] = reinterpret_cast<void*>(&appOnFinalize);
    *reinterpret_cast<void***>(mem) = g_vtbl + 2;

    g_app = mem;
    return mem;
}

void destroyApp(void* app) {
    if (!app) {
        return;
    }
    void** vt = *reinterpret_cast<void***>(app);
    if (vt != NULL && vt[1] != NULL) {
        void (*deleting_dtor)(void*) = NULL;
        memcpy(&deleting_dtor, &vt[1], sizeof(deleting_dtor));
        deleting_dtor(app);
    } else {
        ::operator delete(app);
    }
    if (app == g_app) {
        g_app = NULL;
        g_run_app = NULL;
    }
}

}  // namespace
}  // namespace hmi
}  // namespace platform
}  // namespace carplay

extern "C" {

__attribute__((visibility("default"))) EntryPluginAppInfo pluginAppInfo = {
    1U,
    0U,
    "Apple CarPlay",
    "EntryCarPlay",
    1U,
    &carplay::platform::hmi::createApp,
    &carplay::platform::hmi::destroyApp
};

__attribute__((visibility("default"))) void entryCarPlaySetFrameworkApiForTest(
    const carplay::platform::BmwFrameworkApi* api,
    const char* data_dir,
    const char* control_name,
    const char* state_file) {
    if (api != NULL) {
        carplay::platform::hmi::g_fw = *api;
        carplay::platform::hmi::g_fw_injected = true;
    } else {
        carplay::platform::hmi::g_fw = carplay::platform::BmwFrameworkApi();
        carplay::platform::hmi::g_fw_injected = false;
    }
    if (data_dir != NULL) {
        carplay::platform::hmi::g_data_dir = data_dir;
    }
    if (control_name != NULL) {
        carplay::platform::hmi::g_control_name = control_name;
    }
    if (state_file != NULL) {
        carplay::platform::hmi::g_state_file = state_file;
    }
}

}  // extern "C"
