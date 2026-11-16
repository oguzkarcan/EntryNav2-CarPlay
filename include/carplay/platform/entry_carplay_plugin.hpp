#ifndef CARPLAY_PLATFORM_ENTRY_CARPLAY_PLUGIN_HPP
#define CARPLAY_PLATFORM_ENTRY_CARPLAY_PLUGIN_HPP

// ABI contract for the BMW HU_ENTRYNAV2 HmiMain3D RHMI plugin (`libEntryCarPlay.so`).
//
// `ManagedPluginApp::init` in `HmiMain3D` loads `{pluginDir}/EntryCarPlay` via `dlopen` and
// looks up `dlsym(handle, "pluginAppInfo")`. On 32-bit ARM (`arm-linux-gnueabihf`), `create`
// sits at byte offset +0x10 and `destroy` sits at byte offset +0x14.

#include <stddef.h>
#include <stdint.h>

namespace carplay {
namespace platform {

struct BmwBasicStringChar {
    char* data;
};

struct BmwBasicStringU16 {
    const uint16_t* data;
};

struct BmwParcelStorage {
    unsigned char storage[32];
};

struct BmwTextIdStorage {
    uint32_t id;
    uint32_t type;
};

struct BmwImageIdStorage {
    uint32_t id;
    uint32_t type;
};

struct BmwActionDelegate {
    void* object;
    bool (*stub)(void* object, const BmwParcelStorage& parcel);
};

struct BmwCdsDelegate {
    void* object;
    bool (*stub)(void* object, const BmwBasicStringU16& value);
};

/// Function table of mangled symbols from `libAppFramework.A.so` and `libCoreFramework.A.so`,
/// resolved at runtime via `dlsym(RTLD_DEFAULT, ...)` inside `HmiMain3D` (or injected in tests).
struct BmwFrameworkApi {
    void (*parcel_ctor_bool)(BmwParcelStorage* self, bool value);
    void (*parcel_dtor)(BmwParcelStorage* self);
    void (*parcel_read_bool)(const BmwParcelStorage* self, bool& out);

    void (*bstr_ctor_cstr)(BmwBasicStringChar* self, const char* s);
    void (*bstr_dtor)(BmwBasicStringChar* self);

    void (*text_id_ctor)(BmwTextIdStorage* self, unsigned id);
    void (*image_id_ctor)(BmwImageIdStorage* self, unsigned id);

    void (*plugin_app_ctor)(void* self,
                            void* dispatcher,
                            BmwBasicStringChar* name,
                            unsigned major,
                            unsigned minor,
                            int rhmi_ver,
                            const void* params,
                            const void* config);
    void (*add_action_handler)(void* self, unsigned action_id, const BmwActionDelegate& d);
    void (*add_state_handler)(void* self, unsigned state_id, unsigned kind, const BmwActionDelegate& d);
    void (*trigger_event)(void* self, unsigned event_id);
    void (*trigger_event_parcel)(void* self, unsigned event_id, const BmwParcelStorage& parcel);
    void (*post_runnable)(void* self, void* runnable, unsigned delay_ms);
    void (*update_model_text)(void* self, unsigned model_id, const BmwTextIdStorage& text);
    void (*update_model_image)(void* self, unsigned model_id, const BmwImageIdStorage& image);
    void (*update_model_bool)(void* self, unsigned model_id, bool value);
    void (*set_property)(void* self, unsigned comp_id, unsigned prop_id, const BmwParcelStorage& parcel);
    void (*cds_add_handler)(void* self,
                            BmwBasicStringChar& prop_name,
                            unsigned id,
                            const BmwCdsDelegate& d);
    bool (*on_init)(void* self);
    void (*on_finalize)(void* self);

    void** runnable_vtable;

    BmwFrameworkApi();
    bool isComplete() const;
    bool resolveFromDefault();
};

/// Crash-guard and boot-guard helpers over a configurable data directory.
bool isAppDisabledInDir(const char* data_dir);
bool crashGuardAllowsInDir(const char* data_dir, long now_sec);
void resetGuardsWhenStableInDir(const char* data_dir, long init_sec, long now_sec, bool& stable_marked);
bool bootGuardAllowsInDir(const char* data_dir, long now_sec);

}  // namespace platform
}  // namespace carplay

extern "C" {

struct EntryPluginAppInfo {
    uint16_t versionMajor;
    uint16_t versionMinor;
    const char* name;
    const char* vendor;
    uint32_t rhmiInterfaceVersion;
    void* (*create)(void* dispatcher, const char* name, const void* params, const void* config);
    void (*destroy)(void* app);
};

}  // extern "C"

// HmiMain3D reads this as a 0x18-byte ILP32 record with create at +0x10 and
// destroy at +0x14; fail the ARM build if the layout ever drifts.
#if defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 4
static_assert(sizeof(EntryPluginAppInfo) == 0x18, "pluginAppInfo must be 0x18 bytes");
static_assert(__builtin_offsetof(EntryPluginAppInfo, create) == 0x10, "create must be at +0x10");
static_assert(__builtin_offsetof(EntryPluginAppInfo, destroy) == 0x14, "destroy must be at +0x14");
#endif

#endif  // CARPLAY_PLATFORM_ENTRY_CARPLAY_PLUGIN_HPP
