// Runtime smoke test for BMW HU_ENTRYNAV2 (EntryNav2 / EVO) shared libraries under QEMU.
//
// Designed to run on ARMv7 hard-float against the car's dynamic linker (/lib/ld-linux-armhf.so.3,
// eglibc 2.15) and real target shared libraries from $SYSROOT (never linked at build time).
//
// Exercises BOTH our own platform dlopen loaders (`AlsaLoader`, `MdnsAdvertiser`, `VmostClient`,
// `loadDbusApi`, `probeBtCapability`, `BmwFrameworkApi::resolveFromDefault`) and direct
// `dlopen()`/`dlsym()` symbol checks for all groups in `scripts/ci/sysroot_symbols.txt`, plus
// sysroot graphics/Wayland libraries (`libEGL.so.1`, `libGLESv2.so.2`, `libilm*.so`).
//
// Safety rule: NEVER call any function that opens hardware devices (`/dev/snd/*`, `/dev/dri/*`,
// `/dev/dce`), connects to live car daemons (`mdnsd`, `vmostd`, `dbus-daemon`, Wayland/ILM),
// or requires `HmiMain3D`'s `IDispatcher`. Every runtime call below is strictly in-process and
// side-effect-free, with its safety rationale documented inline.

#include "test_support.hpp"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include <string>
#include <vector>

#include "carplay/platform/alps_spp.hpp"
#include "carplay/platform/bt_rfcomm.hpp"
#include "carplay/platform/entry_carplay_plugin.hpp"
#include "carplay/platform/evo_audio.hpp"
#include "carplay/platform/mdns_advertiser.hpp"
#include "carplay/platform/omap_dmabuf.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/vmost_client.hpp"
#include "carplay/platform/xsv_api.hpp"

namespace {

namespace plat = carplay::platform;

std::string g_hmi_plugin_path;

#ifndef _WIN32

template <typename Fn>
bool resolveSym(void* lib, const char* name, Fn& out) {
    if (lib == NULL || name == NULL || sizeof(Fn) != sizeof(void*)) {
        out = NULL;
        return false;
    }
    (void)dlerror();
    void* p = dlsym(lib, name);
    const char* err = dlerror();
    if (err != NULL || p == NULL) {
        std::fprintf(stderr, "  dlsym(%s) failed: %s\n", name, err != NULL ? err : "NULL");
        out = NULL;
        return false;
    }
    memcpy(&out, &p, sizeof(out));
    return true;
}

bool hasSym(void* lib, const char* name) {
    void* p = NULL;
    return resolveSym(lib, name, p);
}

#endif  // !_WIN32

}  // namespace

// ------------------------------------------------------------------------------------------------
// 1. libasound.so.2 (ALSA) via AlsaLoader + safe string/version calls
// ------------------------------------------------------------------------------------------------
TEST_CASE(smokeLibAsound) {
#ifdef _WIN32
    CHECK(true);
#else
    plat::AlsaLoader loader;
    std::string err;
    REQUIRE(loader.load(plat::AlsaLoader::kDefaultLibrary, &err));
    CHECK(loader.loaded());
    const plat::AlsaApi& api = loader.api();
    CHECK(api.isComplete());
    CHECK(api.snd_pcm_open != NULL);
    CHECK(api.snd_pcm_set_params != NULL);
    CHECK(api.snd_pcm_writei != NULL);
    CHECK(api.snd_pcm_readi != NULL);
    CHECK(api.snd_pcm_recover != NULL);
    CHECK(api.snd_pcm_prepare != NULL);
    CHECK(api.snd_pcm_drop != NULL);
    CHECK(api.snd_pcm_drain != NULL);
    CHECK(api.snd_pcm_close != NULL);
    CHECK(api.snd_strerror != NULL);

    // Safety rationale: snd_strerror() maps an integer errno to a static string table inside
    // libasound.so.2; it never reads /etc/asound.conf or opens /dev/snd/* PCM devices.
    const char* ok_str = api.snd_strerror(0);
    const char* enoent_str = api.snd_strerror(-ENOENT);
    CHECK(ok_str != NULL && ok_str[0] != '\0');
    CHECK(enoent_str != NULL && enoent_str[0] != '\0');

    // Safety rationale: snd_asoundlib_version() returns a static compile-time version literal.
    void* raw = dlopen("libasound.so.2", RTLD_NOW | RTLD_LOCAL);
    REQUIRE(raw != NULL);
    typedef const char* (*AsoundVerFn)(void);
    AsoundVerFn ver_fn = NULL;
    CHECK(resolveSym(raw, "snd_asoundlib_version", ver_fn));
    const char* ver = ver_fn != NULL ? ver_fn() : NULL;
    CHECK(ver != NULL && ver[0] != '\0');
    std::printf("    libasound: version=%s snd_strerror(0)=%s snd_strerror(-ENOENT)=%s\n",
                ver ? ver : "?", ok_str ? ok_str : "?", enoent_str ? enoent_str : "?");
    dlclose(raw);

    loader.unload();
    CHECK(!loader.loaded());
#endif
}

// ------------------------------------------------------------------------------------------------
// 2. libxsvideo.so.4 (IVA-HD / DCE hardware H.264 decoder)
// ------------------------------------------------------------------------------------------------
TEST_CASE(smokeLibXsvideo) {
#ifdef _WIN32
    CHECK(true);
#else
    (void)dlerror();
    // RTLD_NOW forces ld.so to bind every transitive dependency (libwayland-client, libdce,
    // libmmrpc, libdrm_omap, libdrm, libivi-application, libpng16, libffi, libz) at load time.
    void* lib = dlopen("libxsvideo.so.4", RTLD_NOW | RTLD_LOCAL);
    if (lib == NULL) {
        std::fprintf(stderr, "  dlopen(libxsvideo.so.4) failed: %s\n", dlerror());
    }
    REQUIRE(lib != NULL);

    plat::XsvApi xsv;
    CHECK(resolveSym(lib, "xsv_open", xsv.xsv_open));
    CHECK(resolveSym(lib, "xsv_close", xsv.xsv_close));
    CHECK(resolveSym(lib, "xsv_configure_stream", xsv.xsv_configure_stream));
    CHECK(resolveSym(lib, "xsv_set_output_dimension", xsv.xsv_set_output_dimension));
    CHECK(resolveSym(lib, "xsv_set_input_viewport", xsv.xsv_set_input_viewport));
    CHECK(resolveSym(lib, "xsv_decode_video_frame", xsv.xsv_decode_video_frame));
    CHECK(resolveSym(lib, "xsv_start", xsv.xsv_start));
    CHECK(resolveSym(lib, "xsv_stop", xsv.xsv_stop));
    CHECK(resolveSym(lib, "xsv_pause", xsv.xsv_pause));
    CHECK(resolveSym(lib, "xsv_update", xsv.xsv_update));
    CHECK(resolveSym(lib, "xsv_enable_frame_events", xsv.xsv_enable_frame_events));
    CHECK(resolveSym(lib, "xsv_disable_frame_events", xsv.xsv_disable_frame_events));
    CHECK(resolveSym(lib, "xsv_receive_event", xsv.xsv_receive_event));
    CHECK(resolveSym(lib, "xsv_get_event_queue_fd", xsv.xsv_get_event_queue_fd));
    CHECK(xsv.complete());

    // Safety rationale: no xsv_* function is called because xsv_open() opens Wayland/DCE/IVA-HD
    // resources and all other functions require a valid xsv_handle.
    std::printf("    libxsvideo.so.4: RTLD_NOW + 14/14 XsvApi symbols resolved\n");
    dlclose(lib);
#endif
}

// ------------------------------------------------------------------------------------------------
// 3 & 4. libdrm.so.2 + libdrm_omap.so.1 (OMAP dma-buf)
// ------------------------------------------------------------------------------------------------
TEST_CASE(smokeLibDrmAndOmap) {
#ifdef _WIN32
    CHECK(true);
#else
    (void)dlerror();
    void* drm = dlopen("libdrm.so.2", RTLD_NOW | RTLD_LOCAL);
    if (drm == NULL) {
        std::fprintf(stderr, "  dlopen(libdrm.so.2) failed: %s\n", dlerror());
    }
    REQUIRE(drm != NULL);

    void* omap = dlopen("libdrm_omap.so.1", RTLD_NOW | RTLD_LOCAL);
    if (omap == NULL) {
        std::fprintf(stderr, "  dlopen(libdrm_omap.so.1) failed: %s\n", dlerror());
        dlclose(drm);
    }
    REQUIRE(omap != NULL);

    plat::DrmOmapApi api;
    CHECK(resolveSym(drm, "drmOpen", api.drmOpen));
    CHECK(resolveSym(drm, "drmClose", api.drmClose));
    CHECK(resolveSym(omap, "omap_device_new", api.omap_device_new));
    CHECK(resolveSym(omap, "omap_device_del", api.omap_device_del));
    CHECK(resolveSym(omap, "omap_bo_new", api.omap_bo_new));
    CHECK(resolveSym(omap, "omap_bo_del", api.omap_bo_del));
    CHECK(resolveSym(omap, "omap_bo_dmabuf", api.omap_bo_dmabuf));
    CHECK(resolveSym(omap, "omap_bo_map", api.omap_bo_map));
    CHECK(api.complete());

    // Safety rationale: drmAvailable() probes whether /dev/dri/card0 can be opened read-only and
    // closes it immediately, returning 0 when no DRM device exists under QEMU.
    typedef int (*DrmAvailableFn)(void);
    DrmAvailableFn drm_avail = NULL;
    CHECK(resolveSym(drm, "drmAvailable", drm_avail));
    const int avail = drm_avail != NULL ? drm_avail() : -1;
    CHECK(avail == 0 || avail == 1);

    // Safety rationale: omap_device_new/omap_bo_* require a real omapdrm fd and are not called.
    std::printf("    libdrm.so.2 + libdrm_omap.so.1: 8/8 DrmOmapApi symbols resolved (drmAvailable=%d)\n",
                avail);

    dlclose(omap);
    dlclose(drm);
#endif
}

// ------------------------------------------------------------------------------------------------
// 5. libvmostclient.so.1 via VmostClient loader
// ------------------------------------------------------------------------------------------------
TEST_CASE(smokeLibVmostClient) {
#ifdef _WIN32
    CHECK(true);
#else
    plat::VmostClient client;
    // Without vmostd socket present, loader must report kNoDaemon cleanly.
    plat::setVmostForTest(NULL, NULL);
    CHECK(!plat::isVmostDaemonPresent());
    CHECK_EQ(static_cast<int>(plat::VmostClient::kNoDaemon), static_cast<int>(client.load()));

    // Create a dummy AF_UNIX socket file (never listening, never calling vmostConnect) so we can
    // exercise VmostClient::load()'s real dlopen("libvmostclient.so.1") and dlsym() path.
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/carlib_smoke_vmost_%ld.sock",
             static_cast<long>(getpid()));
    const char* sock_path = addr.sun_path;
    unlink(sock_path);
    const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);
    const int bind_rc = bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (bind_rc != 0) {
        close(fd);
        unlink(sock_path);
    }
    REQUIRE(bind_rc == 0);

    plat::setVmostForTest(sock_path, NULL);
    CHECK(plat::isVmostDaemonPresent());
    const plat::VmostClient::Load load_rc = client.load();
    if (load_rc != plat::VmostClient::kLoaded) {
        std::fprintf(stderr, "  VmostClient::load() failed (%d): %s\n",
                     static_cast<int>(load_rc), client.error().c_str());
    }
    CHECK_EQ(static_cast<int>(plat::VmostClient::kLoaded), static_cast<int>(load_rc));
    CHECK(client.connect != NULL);
    CHECK(client.shadowRegister != NULL);
    CHECK(client.shadowDeregister != NULL);
    CHECK(client.fileDescriptorGet != NULL);
    CHECK(client.processMessages != NULL);
    CHECK(client.disconnect != NULL);
    CHECK(client.send != NULL);

    if (sizeof(void*) == 4U) {
        CHECK_EQ(static_cast<size_t>(24U), sizeof(plat::VmostMsgOut));
    }

    // Safety rationale: vmostConnect/vmostMostMsgSend talk to vmostd IPC and are not called.
    // vmostFileDescriptorGet(-1/ptr) reads the internal client fd without touching any socket.
    if (client.fileDescriptorGet != NULL) {
        int vmost_fd = 12345;
        const int fd_rc = client.fileDescriptorGet(&vmost_fd);
        std::printf("    libvmostclient.so.1: VmostClient::load() OK (7/7 symbols, vmostFileDescriptorGet rc=%d fd=%d)\n",
                    fd_rc, vmost_fd);
    }

    client.unload();
    plat::setVmostForTest(NULL, NULL);
    close(fd);
    unlink(addr.sun_path);
#endif
}

// ------------------------------------------------------------------------------------------------
// 6. libdns_sd.so.0 via MdnsAdvertiser::load() + safe in-memory calls
// ------------------------------------------------------------------------------------------------
TEST_CASE(smokeLibDnsSd) {
#ifdef _WIN32
    CHECK(true);
#else
    plat::Reactor reactor;
    plat::MdnsAdvertiser adv(reactor);
    std::string err;
    const bool ok = adv.load(&err);
    if (!ok) {
        std::fprintf(stderr, "  MdnsAdvertiser::load() failed: %s\n", err.c_str());
    }
    REQUIRE(ok);
    CHECK(adv.available());
    CHECK_EQ(std::string("libdns_sd.so.0"), adv.loadedLibrary());

    // Direct dlsym verification of all 5 sysroot_symbols.txt symbols (4 required + 1 optional)
    // plus side-effect-free formatting & TXT helpers that never contact mdnsd.
    void* lib = dlopen("libdns_sd.so.0", RTLD_NOW | RTLD_LOCAL);
    REQUIRE(lib != NULL);
    CHECK(hasSym(lib, "DNSServiceRegister"));
    CHECK(hasSym(lib, "DNSServiceRefSockFD"));
    CHECK(hasSym(lib, "DNSServiceProcessResult"));
    CHECK(hasSym(lib, "DNSServiceRefDeallocate"));
    const bool has_update = hasSym(lib, "DNSServiceUpdateRecord");
    CHECK(has_update);

    // Safety rationale: DNSServiceConstructFullName() formats a DNS-SD full domain name purely in
    // caller-supplied memory and performs no socket I/O or mdnsd communication.
    typedef int32_t (*ConstructFullNameFn)(char* fullName,
                                           const char* service,
                                           const char* regtype,
                                           const char* domain);
    ConstructFullNameFn construct_fn = NULL;
    CHECK(resolveSym(lib, "DNSServiceConstructFullName", construct_fn));
    char full_name[1009];
    memset(full_name, 0, sizeof(full_name));
    if (construct_fn != NULL) {
        const int32_t rc = construct_fn(full_name, "EntryCarPlay", "_airplay._tcp", "local.");
        CHECK_EQ(static_cast<int32_t>(0), rc);
        CHECK_EQ(std::string("EntryCarPlay._airplay._tcp.local."), std::string(full_name));
    }

    // Safety rationale: TXTRecordCreate / SetValue / GetLength / GetCount / ContainsKey /
    // Deallocate manipulate only the caller's 16-byte TXTRecordRef struct and heap buffer,
    // without touching mdnsd. (Note: MdnsAdvertiser uses dnssd_txt in production; this verifies
    // libdns_sd.so.0's hard-float/struct ABI.)
    struct TxtRecordOpaque {
        unsigned char opaque[16];
    };
    typedef void (*TxtCreateFn)(TxtRecordOpaque*, uint16_t, void*);
    typedef int32_t (*TxtSetFn)(TxtRecordOpaque*, const char*, uint8_t, const void*);
    typedef uint16_t (*TxtLenFn)(const TxtRecordOpaque*);
    typedef uint16_t (*TxtCountFn)(uint16_t, const void*);
    typedef const void* (*TxtBytesFn)(const TxtRecordOpaque*);
    typedef int (*TxtContainsFn)(uint16_t, const void*, const char*);
    typedef void (*TxtDeallocFn)(TxtRecordOpaque*);

    TxtCreateFn txt_create = NULL;
    TxtSetFn txt_set = NULL;
    TxtLenFn txt_len = NULL;
    TxtCountFn txt_count = NULL;
    TxtBytesFn txt_bytes = NULL;
    TxtContainsFn txt_contains = NULL;
    TxtDeallocFn txt_dealloc = NULL;
    CHECK(resolveSym(lib, "TXTRecordCreate", txt_create));
    CHECK(resolveSym(lib, "TXTRecordSetValue", txt_set));
    CHECK(resolveSym(lib, "TXTRecordGetLength", txt_len));
    CHECK(resolveSym(lib, "TXTRecordGetCount", txt_count));
    CHECK(resolveSym(lib, "TXTRecordGetBytesPtr", txt_bytes));
    CHECK(resolveSym(lib, "TXTRecordContainsKey", txt_contains));
    CHECK(resolveSym(lib, "TXTRecordDeallocate", txt_dealloc));

    if (txt_create && txt_set && txt_len && txt_count && txt_bytes && txt_contains && txt_dealloc) {
        TxtRecordOpaque rec;
        uint8_t storage[256];
        txt_create(&rec, sizeof(storage), storage);
        const char val[] = "0x5A7FFFF7,0x1E";
        CHECK_EQ(static_cast<int32_t>(0),
                 txt_set(&rec, "features", static_cast<uint8_t>(sizeof(val) - 1U), val));
        const uint16_t len = txt_len(&rec);
        const void* ptr = txt_bytes(&rec);
        CHECK(len > 0U && ptr != NULL);
        CHECK_EQ(static_cast<uint16_t>(1U), txt_count(len, ptr));
        CHECK(txt_contains(len, ptr, "features") != 0);
        txt_dealloc(&rec);
    }

    std::printf("    libdns_sd.so.0: MdnsAdvertiser::load() OK (fullName=%s, updateRecord=%s)\n",
                full_name, has_update ? "yes" : "no");
    dlclose(lib);
    adv.unload();
#endif
}

// ------------------------------------------------------------------------------------------------
// 7. libdbus-1.so.3 via loadDbusApi() + probeBtCapability() + in-memory message/error ABI
// ------------------------------------------------------------------------------------------------
TEST_CASE(smokeLibDbus) {
#ifdef _WIN32
    CHECK(true);
#else
    plat::DbusApi api;
    void* lib = NULL;
    std::string loaded;
    std::string err;
    const bool ok = plat::loadDbusApi(api, &lib, &loaded, &err);
    if (!ok) {
        std::fprintf(stderr, "  loadDbusApi() failed: %s\n", err.c_str());
    }
    REQUIRE(ok);
    CHECK(lib != NULL);
    CHECK(api.isComplete());
    CHECK_EQ(std::string("libdbus-1.so.3"), loaded);

    // Also exercise BtCapability probe (without AF_BLUETOOTH syscall or bus connections).
    plat::BtProbePaths paths;
    paths.probe_af_bluetooth = false;
    paths.sys_class_bluetooth.clear();
    paths.sdpd_socket.clear();
    paths.bluetoothd_socket.clear();
    paths.dbus_socket.clear();
    const plat::BtCapability cap = plat::probeBtCapability(paths);
    CHECK(cap.libdbus_loadable);
    CHECK_EQ(std::string("libdbus-1.so.3"), cap.libdbus_name);
    CHECK(!cap.libbluetooth_loadable);

    // Safety rationale: dbus_get_version() reads compile-time constants; dbus_threads_init_default()
    // initializes in-process mutex/condvar callbacks; dbus_error_*, dbus_validate_path(), and
    // dbus_message_* operate purely in memory with zero dbus-daemon socket connection.
    typedef void (*DbusVerFn)(int* major, int* minor, int* micro);
    DbusVerFn ver_fn = NULL;
    CHECK(resolveSym(lib, "dbus_get_version", ver_fn));
    int maj = 0, min = 0, mic = 0;
    if (ver_fn != NULL) {
        ver_fn(&maj, &min, &mic);
    }
    CHECK(maj >= 1);

    CHECK(api.threads_init_default() != 0U);

    // Guard pattern around DbusErrorRaw to detect any struct size overflow on ARM32.
    struct GuardedDbusError {
        uint32_t head;
        plat::DbusErrorRaw err;
        uint32_t tail;
    };
    GuardedDbusError gd;
    gd.head = 0xCAFEBABEU;
    gd.tail = 0xDEADBEEFU;
    api.error_init(&gd.err);
    CHECK(api.error_is_set(&gd.err) == 0U);
    CHECK(api.validate_path("/org/alps/evolution/hli", &gd.err) != 0U);
    CHECK(api.error_is_set(&gd.err) == 0U);
    CHECK(api.validate_path("not a valid/path!", &gd.err) == 0U);
    CHECK(api.error_is_set(&gd.err) != 0U);
    api.error_free(&gd.err);
    CHECK_EQ(static_cast<uint32_t>(0xCAFEBABEU), gd.head);
    CHECK_EQ(static_cast<uint32_t>(0xDEADBEEFU), gd.tail);

    plat::DbusMessage* msg = api.message_new_method_call(
        "org.alps.evolution", "/org/alps/evolution/hli", "org.alps.evo.SPP", "BtApplSppDataReq");
    REQUIRE(msg != NULL);
    CHECK_EQ(1, api.message_get_type(msg));  // DBUS_MESSAGE_TYPE_METHOD_CALL
    CHECK_EQ(std::string("BtApplSppDataReq"), std::string(api.message_get_member(msg)));
    CHECK_EQ(std::string("org.alps.evo.SPP"), std::string(api.message_get_interface(msg)));
    CHECK(api.message_has_interface(msg, "org.alps.evo.SPP") != 0U);
    CHECK(api.message_has_path(msg, "/org/alps/evolution/hli") != 0U);
    api.message_set_no_reply(msg, 1U);

    // Round-trip marshal/unmarshal using DbusMessageIterRaw with guard words.
    struct GuardedIter {
        uint32_t head;
        plat::DbusMessageIterRaw iter;
        uint32_t tail;
    };
    GuardedIter gi;
    gi.head = 0x11223344U;
    gi.tail = 0x55667788U;
    api.message_iter_init_append(msg, &gi.iter);
    const uint8_t slot = 5U;
    const char* uuid_str = "00000000-deca-fade-deca-deafdecacaff";
    const uint8_t payload[4] = {0xAAU, 0xBBU, 0xCCU, 0xDDU};
    const uint8_t* payload_ptr = payload;
    CHECK(api.message_iter_append_basic(&gi.iter, 'y', &slot) != 0U);
    CHECK(api.message_iter_append_basic(&gi.iter, 's', &uuid_str) != 0U);
    GuardedIter sub;
    sub.head = 0x99AABBCCU;
    sub.tail = 0xDDEEFF00U;
    CHECK(api.message_iter_open_container(&gi.iter, 'a', "y", &sub.iter) != 0U);
    CHECK(api.message_iter_append_fixed_array(&sub.iter, 'y', &payload_ptr, 4) != 0U);
    CHECK(api.message_iter_close_container(&gi.iter, &sub.iter) != 0U);

    CHECK_EQ(std::string("ysay"), std::string(api.message_get_signature(msg)));
    CHECK(api.message_has_signature(msg, "ysay") != 0U);

    GuardedIter ri;
    ri.head = 0x01020304U;
    ri.tail = 0x05060708U;
    CHECK(api.message_iter_init(msg, &ri.iter) != 0U);
    CHECK_EQ(static_cast<int>('y'), api.message_iter_get_arg_type(&ri.iter));
    uint8_t got_slot = 0U;
    api.message_iter_get_basic(&ri.iter, &got_slot);
    CHECK_EQ(static_cast<uint8_t>(5U), got_slot);
    CHECK(api.message_iter_next(&ri.iter) != 0U);
    CHECK_EQ(static_cast<int>('s'), api.message_iter_get_arg_type(&ri.iter));
    const char* got_uuid = NULL;
    api.message_iter_get_basic(&ri.iter, &got_uuid);
    REQUIRE(got_uuid != NULL);
    CHECK_EQ(std::string(uuid_str), std::string(got_uuid));
    CHECK(api.message_iter_next(&ri.iter) != 0U);
    CHECK_EQ(static_cast<int>('a'), api.message_iter_get_arg_type(&ri.iter));
    CHECK_EQ(static_cast<int>('y'), api.message_iter_get_element_type(&ri.iter));
    GuardedIter rsub;
    rsub.head = 0x13572468U;
    rsub.tail = 0x24681357U;
    api.message_iter_recurse(&ri.iter, &rsub.iter);
    const uint8_t* got_bytes = NULL;
    int got_len = 0;
    api.message_iter_get_fixed_array(&rsub.iter, &got_bytes, &got_len);
    CHECK_EQ(4, got_len);
    REQUIRE(got_bytes != NULL);
    CHECK(memcmp(got_bytes, payload, 4U) == 0);

    CHECK_EQ(static_cast<uint32_t>(0x11223344U), gi.head);
    CHECK_EQ(static_cast<uint32_t>(0x55667788U), gi.tail);
    CHECK_EQ(static_cast<uint32_t>(0x99AABBCCU), sub.head);
    CHECK_EQ(static_cast<uint32_t>(0xDDEEFF00U), sub.tail);
    CHECK_EQ(static_cast<uint32_t>(0x01020304U), ri.head);
    CHECK_EQ(static_cast<uint32_t>(0x05060708U), ri.tail);
    CHECK_EQ(static_cast<uint32_t>(0x13572468U), rsub.head);
    CHECK_EQ(static_cast<uint32_t>(0x24681357U), rsub.tail);

    api.message_unref(msg);
    plat::unloadDbusLibrary(lib);
    std::printf("    libdbus-1.so.3: version=%d.%d.%d, 40/40 symbols, DbusErrorRaw/Iter ABI OK\n",
                maj, min, mic);
#endif
}

// ------------------------------------------------------------------------------------------------
// 8 & 9. Optional libraries: libbluetooth (absent on EVO), libevo_btappl.so (/opt/app)
// ------------------------------------------------------------------------------------------------
TEST_CASE(smokeOptionalLibs) {
#ifdef _WIN32
    CHECK(true);
#else
    // libevo_btappl.so lives under /opt/app/usr/BTMedia/evolution/stack/lib on a live HU and is
    // absent in partial sysroots (dangling /usr/local/lib/alps/evolution symlink). If present,
    // verify its 3 exported tables (`app`, `spp_info`, `spp_connected`); if absent, skip cleanly.
    const char* const kCandidates[2] = {
        "libevo_btappl.so",
        "/usr/local/lib/alps/evolution/libevo_btappl.so"
    };
    void* bt_app_lib = NULL;
    const char* found_at = NULL;
    for (size_t i = 0; i < 2U; ++i) {
        (void)dlerror();
        bt_app_lib = dlopen(kCandidates[i], RTLD_LAZY | RTLD_LOCAL);
        if (bt_app_lib != NULL) {
            found_at = kCandidates[i];
            break;
        }
    }
    if (bt_app_lib != NULL) {
        CHECK(hasSym(bt_app_lib, "app"));
        CHECK(hasSym(bt_app_lib, "spp_info"));
        CHECK(hasSym(bt_app_lib, "spp_connected"));
        std::printf("    libevo_btappl.so: FOUND (%s), 3/3 tables resolved\n", found_at);
        dlclose(bt_app_lib);
    } else {
        std::printf("    libevo_btappl.so: OPTIONAL-ABSENT (partial sysroot without /opt/app)\n");
    }

    // BlueZ libbluetooth probe: expected absent on EntryNav2 ALPS units.
    void* bt_lib = dlopen("libbluetooth.so.3", RTLD_LAZY | RTLD_LOCAL);
    if (bt_lib != NULL) {
        std::printf("    libbluetooth.so.3: FOUND\n");
        dlclose(bt_lib);
    } else {
        std::printf("    libbluetooth.so.3: OPTIONAL-ABSENT (ALPS D-Bus unit)\n");
    }
    CHECK(true);
#endif
}

// ------------------------------------------------------------------------------------------------
// 10. hmi_framework (libCoreFramework.A.so + libAppFramework.A.so + libEntryCarPlay.so)
// ------------------------------------------------------------------------------------------------
TEST_CASE(smokeHmiFrameworkAndPlugin) {
#ifdef _WIN32
    CHECK(true);
#else
    (void)dlerror();
    void* core = dlopen("libCoreFramework.A.so", RTLD_NOW | RTLD_GLOBAL);
    if (core == NULL) {
        std::fprintf(stderr, "  dlopen(libCoreFramework.A.so) failed: %s\n", dlerror());
    }
    REQUIRE(core != NULL);

    void* appfw = dlopen("libAppFramework.A.so", RTLD_NOW | RTLD_GLOBAL);
    if (appfw == NULL) {
        std::fprintf(stderr, "  dlopen(libAppFramework.A.so) failed: %s\n", dlerror());
    }
    REQUIRE(appfw != NULL);

    plat::BmwFrameworkApi fw;
    CHECK(fw.resolveFromDefault());
    CHECK(fw.isComplete());
    CHECK(fw.runnable_vtable != NULL);

    // Verify bmw::PluginApp vtable slots 21 (onError), 22 (onInit), 23 (onFinalize) match the
    // real libAppFramework.A.so vtable (matching src/hmi/entry_carplay_app.cpp).
    void** vt = static_cast<void**>(dlsym(appfw, "_ZTVN3bmw9PluginAppE"));
    void* on_err = dlsym(appfw, "_ZN3bmw9PluginApp7onErrorEjRKNS_11BasicStringIcEE");
    REQUIRE(vt != NULL);
    REQUIRE(on_err != NULL);
    CHECK(vt[2 + 21] == on_err);
    CHECK(vt[2 + 22] == reinterpret_cast<void*>(fw.on_init));
    CHECK(vt[2 + 23] == reinterpret_cast<void*>(fw.on_finalize));

    // Safety rationale: BasicString, TextID, ImageID, and Parcel(bool) are pure in-memory value
    // types inside libCoreFramework/libAppFramework; calling them with guard words checks that
    // our 32-byte BmwParcelStorage and BmwBasicStringChar/TextId/ImageId layouts match ARM32 ABI
    // without touching HmiMain3D's IDispatcher.
    plat::BmwBasicStringChar bstr;
    bstr.data = NULL;
    fw.bstr_ctor_cstr(&bstr, "CarPlaySmoke");
    CHECK(bstr.data != NULL);
    CHECK_EQ(std::string("CarPlaySmoke"), std::string(bstr.data));
    fw.bstr_dtor(&bstr);

    plat::BmwTextIdStorage tid;
    memset(&tid, 0xAA, sizeof(tid));
    fw.text_id_ctor(&tid, 42U);
    CHECK_EQ(static_cast<uint32_t>(42U), tid.id);

    plat::BmwImageIdStorage iid;
    memset(&iid, 0x55, sizeof(iid));
    fw.image_id_ctor(&iid, 99U);
    CHECK_EQ(static_cast<uint32_t>(99U), iid.id);

    struct GuardedParcel {
        uint32_t head;
        plat::BmwParcelStorage parcel;
        uint32_t tail;
    };
    GuardedParcel gp;
    gp.head = 0xCAFE1234U;
    gp.tail = 0x5678BEEFU;
    memset(&gp.parcel, 0, sizeof(gp.parcel));
    fw.parcel_ctor_bool(&gp.parcel, true);
    bool val = false;
    fw.parcel_read_bool(&gp.parcel, val);
    CHECK(val);
    fw.parcel_dtor(&gp.parcel);
    CHECK_EQ(static_cast<uint32_t>(0xCAFE1234U), gp.head);
    CHECK_EQ(static_cast<uint32_t>(0x5678BEEFU), gp.tail);

    // Optional: load libEntryCarPlay.so the exact way HmiMain3D ManagedPluginApp::init does,
    // without calling create() (which needs HmiMain3D's dispatcher).
    if (!g_hmi_plugin_path.empty()) {
        (void)dlerror();
        void* plugin = dlopen(g_hmi_plugin_path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (plugin == NULL) {
            std::fprintf(stderr, "  dlopen(%s) failed: %s\n",
                         g_hmi_plugin_path.c_str(), dlerror());
        }
        REQUIRE(plugin != NULL);
        const EntryPluginAppInfo* info =
            reinterpret_cast<const EntryPluginAppInfo*>(dlsym(plugin, "pluginAppInfo"));
        REQUIRE(info != NULL);
        CHECK_EQ(static_cast<uint16_t>(1U), info->versionMajor);
        CHECK_EQ(static_cast<uint16_t>(0U), info->versionMinor);
        CHECK_EQ(static_cast<uint32_t>(1U), info->rhmiInterfaceVersion);
        REQUIRE(info->name != NULL);
        REQUIRE(info->vendor != NULL);
        CHECK_EQ(std::string("Apple CarPlay"), std::string(info->name));
        CHECK_EQ(std::string("EntryCarPlay"), std::string(info->vendor));
        CHECK(info->create != NULL);
        CHECK(info->destroy != NULL);
        std::printf("    libEntryCarPlay.so: pluginAppInfo valid (name=%s, v%u.%u, rhmi=%u)\n",
                    info->name, info->versionMajor, info->versionMinor,
                    info->rhmiInterfaceVersion);
        dlclose(plugin);
    }

    std::printf("    hmi_framework: 20/20 req + runnable vtable, PluginApp slots 21/22/23, Parcel/BasicString ABI OK\n");
    // Leave RTLD_GLOBAL handles open or close in reverse order.
    dlclose(appfw);
    dlclose(core);
#endif
}

// ------------------------------------------------------------------------------------------------
// 11. Sysroot Graphics & Wayland ILM libraries (EGL / GLESv2 / ILM)
// ------------------------------------------------------------------------------------------------
TEST_CASE(smokeSysrootGraphicsAndIlm) {
#ifdef _WIN32
    CHECK(true);
#else
    (void)dlerror();
    void* egl = dlopen("libEGL.so.1", RTLD_NOW | RTLD_LOCAL);
    if (egl == NULL) {
        std::fprintf(stderr, "  dlopen(libEGL.so.1) failed: %s\n", dlerror());
    }
    REQUIRE(egl != NULL);
    typedef int (*EglGetErrorFn)(void);
    typedef void* (*EglGetCurrentDisplayFn)(void);
    typedef const char* (*EglQueryStringFn)(void* dpy, int name);
    EglGetErrorFn egl_get_error = NULL;
    EglGetCurrentDisplayFn egl_cur_dpy = NULL;
    EglQueryStringFn egl_query = NULL;
    CHECK(resolveSym(egl, "eglGetError", egl_get_error));
    CHECK(resolveSym(egl, "eglGetCurrentDisplay", egl_cur_dpy));
    CHECK(resolveSym(egl, "eglQueryString", egl_query));
    CHECK(hasSym(egl, "eglGetDisplay"));

    // Safety rationale: eglGetError() and eglGetCurrentDisplay() only inspect thread-local EGL
    // state and do not open GPU kernel nodes or Wayland displays.
    const int egl_err = egl_get_error != NULL ? egl_get_error() : -1;
    CHECK_EQ(0x3000, egl_err);  // EGL_SUCCESS
    void* cur_dpy = egl_cur_dpy != NULL ? egl_cur_dpy() : reinterpret_cast<void*>(1);
    CHECK(cur_dpy == NULL);  // EGL_NO_DISPLAY

    void* gles = dlopen("libGLESv2.so.2", RTLD_NOW | RTLD_LOCAL);
    if (gles == NULL) {
        std::fprintf(stderr, "  dlopen(libGLESv2.so.2) failed: %s\n", dlerror());
    }
    REQUIRE(gles != NULL);
    CHECK(hasSym(gles, "glGetError"));
    CHECK(hasSym(gles, "glGetString"));

    // libilmCommon, libilmClient, and libilmControl have mutual symbol references (libilmCommon
    // has undefined references to both ilmClient_destroy and ilmControl_destroy). When
    // LD_BIND_NOW=1 forces RTLD_NOW, neither library can be dlopen()'d standalone without the
    // other already linked via DT_NEEDED (which is why EvoIlm invokes LayerManagerControl
    // instead of dlopen()ing libilm*.so). Only probe dlopen() when lazy binding is permitted.
    const char* bind_now = getenv("LD_BIND_NOW");
    const bool eager_bind = (bind_now != NULL && bind_now[0] != '\0' && strcmp(bind_now, "0") != 0);
    if (!eager_bind) {
        void* ilm_control = dlopen("libilmControl.so", RTLD_LAZY | RTLD_GLOBAL);
        void* ilm_client = dlopen("libilmClient.so", RTLD_LAZY | RTLD_GLOBAL);
        void* ilm_common = dlopen("libilmCommon.so", RTLD_NOW | RTLD_GLOBAL);
        CHECK(ilm_control != NULL);
        CHECK(ilm_client != NULL);
        CHECK(ilm_common != NULL);
        if (ilm_common != NULL) {
            CHECK(hasSym(ilm_common, "ilm_init"));
            CHECK(hasSym(ilm_common, "ilm_destroy"));
        }
        std::printf("    EGL/GLES/ILM: libEGL.so.1 (eglGetError=0x%x), libGLESv2.so.2, libilm{Control,Client,Common}.so OK\n",
                    egl_err);
        if (ilm_common != NULL) dlclose(ilm_common);
        if (ilm_client != NULL) dlclose(ilm_client);
        if (ilm_control != NULL) dlclose(ilm_control);
    } else {
        std::printf("    EGL/GLES: libEGL.so.1 (eglGetError=0x%x), libGLESv2.so.2 OK (libilm*.so skipped under LD_BIND_NOW=1 due to mutual ilmCommon<->ilmClient/ilmControl symbols)\n",
                    egl_err);
    }
    dlclose(gles);
    dlclose(egl);
#endif
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--hmi-plugin") == 0 && i + 1 < argc) {
            g_hmi_plugin_path = argv[++i];
        }
    }
    if (g_hmi_plugin_path.empty()) {
        const char* env_p = getenv("CARPLAY_HMI_PLUGIN");
        if (env_p != NULL && env_p[0] != '\0') {
            g_hmi_plugin_path = env_p;
        }
    }
    return test_support::runAll("carlib_smoke");
}
