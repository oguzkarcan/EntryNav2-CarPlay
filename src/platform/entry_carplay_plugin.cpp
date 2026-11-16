#include "carplay/platform/entry_carplay_plugin.hpp"

#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <string>

#include "carplay/platform/file_util.hpp"

namespace carplay {
namespace platform {

namespace {

static const int kCrashGuardMax = 3;
static const long kStableAfterSec = 120;
static const int kBootGuardMax = 3;
static const long kBootGuardWindowSec = 15 * 60;

#ifndef _WIN32
template <typename FnPtr>
bool resolveDefaultSym(const char* sym_name, FnPtr& out) {
    void* raw = dlsym(RTLD_DEFAULT, sym_name);
    if (!raw) {
        out = NULL;
        return false;
    }
    memcpy(&out, &raw, sizeof(out));
    return true;
}
#endif

}  // namespace

BmwFrameworkApi::BmwFrameworkApi()
    : parcel_ctor_bool(NULL),
      parcel_dtor(NULL),
      parcel_read_bool(NULL),
      bstr_ctor_cstr(NULL),
      bstr_dtor(NULL),
      text_id_ctor(NULL),
      image_id_ctor(NULL),
      plugin_app_ctor(NULL),
      add_action_handler(NULL),
      add_state_handler(NULL),
      trigger_event(NULL),
      trigger_event_parcel(NULL),
      post_runnable(NULL),
      update_model_text(NULL),
      update_model_image(NULL),
      update_model_bool(NULL),
      set_property(NULL),
      cds_add_handler(NULL),
      on_init(NULL),
      on_finalize(NULL),
      runnable_vtable(NULL) {}

bool BmwFrameworkApi::isComplete() const {
    return parcel_ctor_bool != NULL &&
           parcel_dtor != NULL &&
           parcel_read_bool != NULL &&
           bstr_ctor_cstr != NULL &&
           bstr_dtor != NULL &&
           text_id_ctor != NULL &&
           image_id_ctor != NULL &&
           plugin_app_ctor != NULL &&
           add_action_handler != NULL &&
           add_state_handler != NULL &&
           trigger_event != NULL &&
           trigger_event_parcel != NULL &&
           post_runnable != NULL &&
           update_model_text != NULL &&
           update_model_image != NULL &&
           update_model_bool != NULL &&
           set_property != NULL &&
           cds_add_handler != NULL &&
           on_init != NULL &&
           on_finalize != NULL;
}

bool BmwFrameworkApi::resolveFromDefault() {
#ifndef _WIN32
    resolveDefaultSym("_ZN3bmw6ParcelC1Eb", parcel_ctor_bool);
    resolveDefaultSym("_ZN3bmw6ParcelD1Ev", parcel_dtor);
    resolveDefaultSym("_ZNK3bmw6Parcel8readBoolERb", parcel_read_bool);
    resolveDefaultSym("_ZN3bmw11BasicStringIcEC1EPKc", bstr_ctor_cstr);
    resolveDefaultSym("_ZN3bmw11BasicStringIcED1Ev", bstr_dtor);
    resolveDefaultSym("_ZN3bmw6TextIDC1Ej", text_id_ctor);
    resolveDefaultSym("_ZN3bmw7ImageIDC1Ej", image_id_ctor);
    resolveDefaultSym(
        "_ZN3bmw9PluginAppC1ERNS_11IDispatcherENS_11BasicStringIcEEjjNS_20RHMIInterfaceVersionERKNS_6BundleES8_",
        plugin_app_ctor);
    resolveDefaultSym(
        "_ZN3bmw9PluginApp10addHandlerEjRKNS_8DelegateIbRKNS_6ParcelEvvvEE",
        add_action_handler);
    resolveDefaultSym(
        "_ZN3bmw9PluginApp10addHandlerEjjRKNS_8DelegateIbRKNS_6ParcelEvvvEE",
        add_state_handler);
    resolveDefaultSym("_ZN3bmw9PluginApp12triggerEventEj", trigger_event);
    resolveDefaultSym("_ZN3bmw9PluginApp12triggerEventEjRKNS_6ParcelE", trigger_event_parcel);
    resolveDefaultSym("_ZN3bmw9PluginApp4postEPNS_8RunnableEj", post_runnable);
    resolveDefaultSym("_ZN3bmw9PluginApp11updateModelEjRKNS_6TextIDE", update_model_text);
    resolveDefaultSym("_ZN3bmw9PluginApp11updateModelEjRKNS_7ImageIDE", update_model_image);
    resolveDefaultSym("_ZN3bmw9PluginApp11updateModelEjb", update_model_bool);
    resolveDefaultSym("_ZN3bmw9PluginApp11setPropertyEjjRKNS_6ParcelE", set_property);
    resolveDefaultSym(
        "_ZN3bmw9PluginApp33cdsAddPropertyChangedEventHandlerERNS_11BasicStringIcEEjRKNS_8DelegateIbRKNS1_ItEEvvvEE",
        cds_add_handler);
    resolveDefaultSym("_ZN3bmw9PluginApp6onInitEv", on_init);
    resolveDefaultSym("_ZN3bmw9PluginApp10onFinalizeEv", on_finalize);
    runnable_vtable = reinterpret_cast<void**>(dlsym(RTLD_DEFAULT, "_ZTVN3bmw8RunnableE"));
    return isComplete();
#else
    return false;
#endif
}

bool isAppDisabledInDir(const char* data_dir) {
    if (!data_dir || !data_dir[0]) {
        return false;
    }
    const std::string path = std::string(data_dir) + "/app.disable";
    return pathExists(path);
}

bool crashGuardAllowsInDir(const char* data_dir, long now_sec) {
    if (!data_dir || !data_dir[0]) {
        return true;
    }
    const std::string path = std::string(data_dir) + "/app-guard";
    int lines = 0;
    FILE* f = fopen(path.c_str(), "r");
    if (f) {
        char buf[64];
        while (fgets(buf, sizeof(buf), f) != NULL) {
            ++lines;
        }
        fclose(f);
    }
    if (lines >= kCrashGuardMax) {
        return false;
    }
    f = fopen(path.c_str(), "a");
    if (f) {
        fprintf(f, "%ld\n", now_sec);
        fflush(f);
#ifndef _WIN32
        // The attempt must be on stable storage before the risky load proceeds:
        // a watchdog reset would otherwise lose it and the guard never trips.
        fsync(fileno(f));
#endif
        fclose(f);
    }
    return true;
}

void resetGuardsWhenStableInDir(const char* data_dir,
                                long init_sec,
                                long now_sec,
                                bool& stable_marked) {
    if (!data_dir || !data_dir[0] || stable_marked || init_sec <= 0) {
        return;
    }
    if (now_sec - init_sec >= kStableAfterSec) {
        stable_marked = true;
        removeFile(std::string(data_dir) + "/app-guard");
        removeFile(std::string(data_dir) + "/bootguard");
    }
}

bool bootGuardAllowsInDir(const char* data_dir, long now_sec) {
    if (!data_dir || !data_dir[0]) {
        return true;
    }
    const std::string path = std::string(data_dir) + "/bootguard";
    long t[8];
    int n = 0;
    FILE* f = fopen(path.c_str(), "r");
    if (f) {
        long v = 0;
        while (n < 8 && fscanf(f, "%ld", &v) == 1) {
            if (v <= now_sec && now_sec - v < kBootGuardWindowSec) {
                t[n++] = v;
            }
        }
        fclose(f);
    }
    if (n >= kBootGuardMax) {
        return false;
    }
    // Atomic replace (temp + fsync + rename): truncating in place would leave an
    // empty guard, i.e. no boot-loop protection, if power drops mid-write.
    std::string out;
    char line[32];
    for (int i = 0; i < n; ++i) {
        snprintf(line, sizeof(line), "%ld\n", t[i]);
        out += line;
    }
    snprintf(line, sizeof(line), "%ld\n", now_sec);
    out += line;
    writeFileAtomic(path, reinterpret_cast<const uint8_t*>(out.data()), out.size());
    return true;
}

}  // namespace platform
}  // namespace carplay
