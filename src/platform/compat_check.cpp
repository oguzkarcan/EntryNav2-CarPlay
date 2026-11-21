// Dry-run vehicle compatibility self-check (`carplayd --compat` / `--self-check`).
//
// Derived from EntryNav2-Android-Auto 0.13.0-rc.6 tools/aa_supervisor.cpp
// (PolyForm Noncommercial License 1.0.0) for the `@ok|@info|@warn|@block|<check>|detail`
// output contract, ALPS/USB mode downgrading, and `bmw::PluginApp` vtable ABI check.

#include "carplay/platform/compat_check.hpp"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#endif

#include <sstream>

#include "carplay/platform/elf_symbols.hpp"
#include "carplay/platform/evo_ilm.hpp"
#include "carplay/platform/evo_wlan.hpp"
#include "carplay/platform/file_util.hpp"
#include "carplay/platform/safe_mode.hpp"
#include "carplay/platform/usb_host.hpp"
#include "carplay/platform/vmost_client.hpp"

namespace carplay {
namespace platform {

namespace {

static const uint32_t kExpectedPluginAppVtableBytes = 172U;

static const char* const kLibAsoundSonames[] = {"libasound.so.2"};
static const char* const kLibAsoundSyms[] = {
    "snd_pcm_open",
    "snd_pcm_set_params",
    "snd_pcm_writei",
    "snd_pcm_readi",
    "snd_pcm_recover",
    "snd_pcm_prepare",
    "snd_pcm_drop",
    "snd_pcm_drain",
    "snd_pcm_close",
    "snd_strerror"
};

static const char* const kLibXsvideoSonames[] = {"libxsvideo.so.4"};
static const char* const kLibXsvideoSyms[] = {
    "xsv_open",
    "xsv_close",
    "xsv_configure_stream",
    "xsv_set_output_dimension",
    "xsv_set_input_viewport",
    "xsv_decode_video_frame",
    "xsv_start",
    "xsv_stop",
    "xsv_pause",
    "xsv_update",
    "xsv_enable_frame_events",
    "xsv_disable_frame_events",
    "xsv_receive_event",
    "xsv_get_event_queue_fd"
};

static const char* const kLibDrmSonames[] = {"libdrm.so.2"};
static const char* const kLibDrmSyms[] = {
    "drmOpen",
    "drmClose"
};

static const char* const kLibDrmOmapSonames[] = {"libdrm_omap.so.1"};
static const char* const kLibDrmOmapSyms[] = {
    "omap_device_new",
    "omap_device_del",
    "omap_bo_new",
    "omap_bo_del",
    "omap_bo_dmabuf",
    "omap_bo_map"
};

static const char* const kLibVmostSonames[] = {"libvmostclient.so.1"};
static const char* const kLibVmostSyms[] = {
    "vmostConnect",
    "vmostFblockShadowRegister",
    "vmostFblockShadowDeregister",
    "vmostFileDescriptorGet",
    "vmostProcessMessages",
    "vmostDisconnect",
    "vmostMostMsgSend"
};

static const char* const kLibDnsSdSonames[] = {"libdns_sd.so.0", "libdns_sd.so.1", "libdns_sd.so"};
static const char* const kLibDnsSdReqSyms[] = {
    "DNSServiceRegister",
    "DNSServiceRefSockFD",
    "DNSServiceProcessResult",
    "DNSServiceRefDeallocate"
};
static const char* const kLibDnsSdOptSyms[] = {"DNSServiceUpdateRecord"};

static const char* const kLibBluetoothSonames[] = {"libbluetooth.so.3", "libbluetooth.so"};

static const char* const kLibDbusSonames[] = {"libdbus-1.so.3", "libdbus-1.so"};
static const char* const kLibDbusSyms[] = {
    "dbus_threads_init_default",
    "dbus_error_init",
    "dbus_error_is_set",
    "dbus_error_free",
    "dbus_bus_get_private",
    "dbus_bus_add_match",
    "dbus_connection_set_exit_on_disconnect",
    "dbus_connection_close",
    "dbus_connection_unref",
    "dbus_connection_add_filter",
    "dbus_connection_remove_filter",
    "dbus_connection_send",
    "dbus_connection_send_with_reply_and_block",
    "dbus_connection_read_write_dispatch",
    "dbus_message_new_method_call",
    "dbus_message_unref",
    "dbus_message_set_no_reply",
    "dbus_message_get_type",
    "dbus_message_get_member",
    "dbus_message_get_interface",
    "dbus_message_get_signature",
    "dbus_message_has_interface",
    "dbus_message_has_path",
    "dbus_message_has_sender",
    "dbus_message_has_signature",
    "dbus_message_is_signal",
    "dbus_message_iter_init",
    "dbus_message_iter_next",
    "dbus_message_iter_get_arg_type",
    "dbus_message_iter_get_element_type",
    "dbus_message_iter_get_basic",
    "dbus_message_iter_recurse",
    "dbus_message_iter_get_fixed_array",
    "dbus_message_iter_init_append",
    "dbus_message_iter_append_basic",
    "dbus_message_iter_open_container",
    "dbus_message_iter_close_container",
    "dbus_message_iter_abandon_container",
    "dbus_message_iter_append_fixed_array",
    "dbus_validate_path"
};

static const char* const kHmiFrameworkReqSyms[] = {
    "_ZN3bmw6ParcelC1Eb",
    "_ZN3bmw6ParcelD1Ev",
    "_ZNK3bmw6Parcel8readBoolERb",
    "_ZN3bmw11BasicStringIcEC1EPKc",
    "_ZN3bmw11BasicStringIcED1Ev",
    "_ZN3bmw6TextIDC1Ej",
    "_ZN3bmw7ImageIDC1Ej",
    "_ZN3bmw9PluginAppC1ERNS_11IDispatcherENS_11BasicStringIcEEjjNS_20RHMIInterfaceVersionERKNS_6BundleES8_",
    "_ZN3bmw9PluginApp10addHandlerEjRKNS_8DelegateIbRKNS_6ParcelEvvvEE",
    "_ZN3bmw9PluginApp10addHandlerEjjRKNS_8DelegateIbRKNS_6ParcelEvvvEE",
    "_ZN3bmw9PluginApp12triggerEventEj",
    "_ZN3bmw9PluginApp12triggerEventEjRKNS_6ParcelE",
    "_ZN3bmw9PluginApp4postEPNS_8RunnableEj",
    "_ZN3bmw9PluginApp11updateModelEjRKNS_6TextIDE",
    "_ZN3bmw9PluginApp11updateModelEjRKNS_7ImageIDE",
    "_ZN3bmw9PluginApp11updateModelEjb",
    "_ZN3bmw9PluginApp11setPropertyEjjRKNS_6ParcelE",
    "_ZN3bmw9PluginApp33cdsAddPropertyChangedEventHandlerERNS_11BasicStringIcEEjRKNS_8DelegateIbRKNS1_ItEEvvvEE",
    "_ZN3bmw9PluginApp6onInitEv",
    "_ZN3bmw9PluginApp10onFinalizeEv"
};

#define ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

static const CompatLibGroupSpec kRuntimeLibGroups[] = {
    {"libasound", true, kLibAsoundSonames, ARRAY_LEN(kLibAsoundSonames),
     kLibAsoundSyms, ARRAY_LEN(kLibAsoundSyms), NULL, 0U},
    {"libxsvideo", true, kLibXsvideoSonames, ARRAY_LEN(kLibXsvideoSonames),
     kLibXsvideoSyms, ARRAY_LEN(kLibXsvideoSyms), NULL, 0U},
    {"libdrm", true, kLibDrmSonames, ARRAY_LEN(kLibDrmSonames),
     kLibDrmSyms, ARRAY_LEN(kLibDrmSyms), NULL, 0U},
    {"libdrm_omap", true, kLibDrmOmapSonames, ARRAY_LEN(kLibDrmOmapSonames),
     kLibDrmOmapSyms, ARRAY_LEN(kLibDrmOmapSyms), NULL, 0U},
    {"libvmostclient", true, kLibVmostSonames, ARRAY_LEN(kLibVmostSonames),
     kLibVmostSyms, ARRAY_LEN(kLibVmostSyms), NULL, 0U},
    {"libdns_sd", true, kLibDnsSdSonames, ARRAY_LEN(kLibDnsSdSonames),
     kLibDnsSdReqSyms, ARRAY_LEN(kLibDnsSdReqSyms),
     kLibDnsSdOptSyms, ARRAY_LEN(kLibDnsSdOptSyms)},
    {"libdbus", true, kLibDbusSonames, ARRAY_LEN(kLibDbusSonames),
     kLibDbusSyms, ARRAY_LEN(kLibDbusSyms), NULL, 0U},
    {"libbluetooth", false, kLibBluetoothSonames, ARRAY_LEN(kLibBluetoothSonames),
     NULL, 0U, NULL, 0U}
};

CompatLineLevel mapAlpsCompatLevel(CompatStatusLevel lvl) {
    switch (lvl) {
        case kCompatPass: return kCompatLineOk;
        case kCompatInfo: return kCompatLineInfo;
        case kCompatWarn: return kCompatLineWarn;
        case kCompatFail: return kCompatLineBlock;
    }
    return kCompatLineBlock;
}

std::string parentDirOf(const std::string& path) {
    const size_t pos = path.find_last_of('/');
    if (pos == std::string::npos) {
        return ".";
    }
    if (pos == 0U) {
        return "/";
    }
    return path.substr(0, pos);
}

int readUsbFlagFile(const std::string& path, std::string& port_out) {
    port_out.clear();
    std::vector<uint8_t> raw;
    const FileReadResult rr = readFileBounded(path, 256U, raw);
    if (rr == kFileMissing) {
        return 0;
    }
    if (rr != kFileReadOk) {
        return -1;
    }
    std::string val(raw.empty() ? std::string()
                                : std::string(reinterpret_cast<const char*>(&raw[0]), raw.size()));
    while (!val.empty() && (val[val.size() - 1U] == '\n' || val[val.size() - 1U] == '\r' ||
                            val[val.size() - 1U] == ' ' || val[val.size() - 1U] == '\t')) {
        val.erase(val.size() - 1U);
    }
    size_t b = 0U;
    while (b < val.size() && (val[b] == ' ' || val[b] == '\t')) {
        ++b;
    }
    val = val.substr(b);
    if (val.empty()) {
        return 1;
    }
    if (!isValidUsbPortName(val)) {
        return -1;
    }
    port_out = val;
    return 1;
}

#ifndef _WIN32
void sleepMsCompat(int64_t ms) {
    if (ms <= 0) {
        return;
    }
    struct timespec req;
    req.tv_sec = static_cast<time_t>(ms / 1000LL);
    req.tv_nsec = static_cast<long>((ms % 1000LL) * 1000000LL);
    while (::nanosleep(&req, &req) < 0 && errno == EINTR) {
    }
}

bool processNameRunning(const char* name) {
    DIR* proc = ::opendir("/proc");
    if (proc == NULL) {
        return false;
    }
    bool found = false;
    struct dirent* ent = NULL;
    while ((ent = ::readdir(proc)) != NULL) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') {
            continue;
        }
        std::vector<uint8_t> raw;
        const std::string comm_path = std::string("/proc/") + ent->d_name + "/comm";
        if (readFileBounded(comm_path, 128U, raw) == kFileReadOk && !raw.empty()) {
            std::string comm(reinterpret_cast<const char*>(&raw[0]), raw.size());
            while (!comm.empty() && (comm[comm.size() - 1U] == '\n' || comm[comm.size() - 1U] == '\r')) {
                comm.erase(comm.size() - 1U);
            }
            if (comm == name) {
                found = true;
                break;
            }
        }
    }
    ::closedir(proc);
    return found;
}
#endif

}  // namespace

const char* compatLineLevelTag(CompatLineLevel level) {
    switch (level) {
        case kCompatLineOk: return "@ok";
        case kCompatLineInfo: return "@info";
        case kCompatLineWarn: return "@warn";
        case kCompatLineBlock: return "@block";
    }
    return "@block";
}

std::string CompatLine::format() const {
    return std::string(compatLineLevelTag(level)) + "|" + check + "|" + detail;
}

void CompatReport::add(CompatLineLevel level, const std::string& check, const std::string& detail) {
    lines.push_back(CompatLine(level, check, detail));
}

bool CompatReport::hasBlockingFailure() const {
    for (size_t i = 0; i < lines.size(); ++i) {
        if (lines[i].level == kCompatLineBlock) {
            return true;
        }
    }
    return false;
}

int CompatReport::exitCode() const {
    return hasBlockingFailure() ? 1 : 0;
}

std::string CompatReport::format() const {
    std::string out;
    for (size_t i = 0; i < lines.size(); ++i) {
        out += lines[i].format();
        out += "\n";
    }
    return out;
}

const CompatLibGroupSpec* compatRuntimeLibGroups(size_t& count_out) {
    count_out = ARRAY_LEN(kRuntimeLibGroups);
    return kRuntimeLibGroups;
}

// ------------------------------------------------------------------------------------------------
// PosixCompatSystemOps
// ------------------------------------------------------------------------------------------------

bool PosixCompatSystemOps::openLibrary(const char* const* sonames,
                                       size_t soname_count,
                                       const std::vector<std::string>& extra_dirs,
                                       void*& handle_out,
                                       std::string& loaded_name_out,
                                       std::string& error_out) {
    handle_out = NULL;
    loaded_name_out.clear();
    error_out.clear();
#ifdef _WIN32
    (void)sonames;
    (void)soname_count;
    (void)extra_dirs;
    error_out = "dlopen unsupported on Windows";
    return false;
#else
    std::string last_err;
    for (size_t i = 0; i < soname_count; ++i) {
        if (sonames[i] == NULL) {
            continue;
        }
        ::dlerror();
        void* h = ::dlopen(sonames[i], RTLD_NOW | RTLD_LOCAL);
        if (h != NULL) {
            handle_out = h;
            loaded_name_out = sonames[i];
            return true;
        }
        const char* err = ::dlerror();
        if (!last_err.empty()) {
            last_err += "; ";
        }
        last_err += std::string(sonames[i]) + ": " + (err != NULL ? err : "dlopen failed");

        for (size_t d = 0; d < extra_dirs.size(); ++d) {
            if (extra_dirs[d].empty()) {
                continue;
            }
            const std::string full = joinPath(extra_dirs[d], sonames[i]);
            ::dlerror();
            h = ::dlopen(full.c_str(), RTLD_NOW | RTLD_LOCAL);
            if (h != NULL) {
                handle_out = h;
                loaded_name_out = full;
                return true;
            }
        }
    }
    error_out = last_err.empty() ? std::string("no candidate soname") : last_err;
    return false;
#endif
}

bool PosixCompatSystemOps::resolveSymbol(void* handle, const char* symbol_name) {
#ifdef _WIN32
    (void)handle;
    (void)symbol_name;
    return false;
#else
    if (handle == NULL || symbol_name == NULL) {
        return false;
    }
    ::dlerror();
    void* sym = ::dlsym(handle, symbol_name);
    const char* err = ::dlerror();
    return sym != NULL && err == NULL;
#endif
}

void PosixCompatSystemOps::closeLibrary(void* handle) {
#ifndef _WIN32
    if (handle != NULL) {
        ::dlclose(handle);
    }
#else
    (void)handle;
#endif
}

bool PosixCompatSystemOps::readElfSymbolSize(const std::string& elf_path,
                                             const char* symbol_name,
                                             uint32_t& size_out,
                                             std::string& error_out) {
    size_out = 0U;
    ElfSymbols elf;
    if (!elf.loadFromFile(elf_path)) {
        error_out = std::string("cannot load ELF ") + elf_path;
        return false;
    }
    ElfSymbolInfo sym;
    if (!elf.findSymbol(symbol_name, sym)) {
        error_out = std::string("symbol ") + symbol_name + " absent in " + elf_path;
        return false;
    }
    size_out = sym.size;
    return true;
}

bool PosixCompatSystemOps::checkElfSymbols(const std::vector<std::string>& elf_paths,
                                           const char* const* symbols,
                                           size_t symbol_count,
                                           std::string& missing_out,
                                           std::string& error_out) {
    missing_out.clear();
    error_out.clear();
    std::vector<ElfSymbols> loaded(elf_paths.size());
    for (size_t i = 0; i < elf_paths.size(); ++i) {
        if (!loaded[i].loadFromFile(elf_paths[i])) {
            error_out = std::string("cannot load ELF ") + elf_paths[i];
            return false;
        }
    }
    for (size_t s = 0; s < symbol_count; ++s) {
        bool found = false;
        ElfSymbolInfo sym;
        for (size_t i = 0; i < loaded.size(); ++i) {
            if (loaded[i].findSymbol(symbols[s], sym)) {
                found = true;
                break;
            }
        }
        if (!found) {
            if (!missing_out.empty()) {
                missing_out += " ";
            }
            missing_out += symbols[s];
        }
    }
    return true;
}

BtTransportCapability PosixCompatSystemOps::probeBtCapability() {
    return probeBtTransportCapability();
}

AlpsCompatReport PosixCompatSystemOps::probeAlpsCompat(const BtTransportCapability& cap,
                                                       bool usb_mode) {
    return probeAlpsSppCompat(cap, NULL, usb_mode);
}

bool PosixCompatSystemOps::queryApWland(std::string& detail_out,
                                        bool& active_out,
                                        bool& capable_out) {
    detail_out.clear();
    active_out = false;
    capable_out = false;
#ifdef _WIN32
    detail_out = "unsupported on Windows";
    return false;
#else
    const bool vmost = isVmostDaemonPresent();
    const bool wlan0 = pathExists("/sys/class/net/wlan0");
    const bool wlan1 = pathExists("/sys/class/net/wlan1");
    const bool hostapd_sock = pathExists("/var/run/hostapd/wlan0");
    const bool ap_conf = pathExists("/tmp/wland/ap.conf");
    const bool hostapd_bin = pathExists("/usr/sbin/hostapd");
    const bool wpa_lib = pathExists("/usr/local/lib/libwpa_client.so.1");

    active_out = hostapd_sock || ap_conf;
    capable_out = (vmost && wlan0) || active_out || (hostapd_bin && (wlan0 || wlan1));

    std::ostringstream oss;
    oss << "vmostd=" << (vmost ? "yes" : "no")
        << " wlan0=" << (wlan0 ? "yes" : "no")
        << " wlan1=" << (wlan1 ? "yes" : "no")
        << " hostapd_sock=" << (hostapd_sock ? "yes" : "no")
        << " ap_conf=" << (ap_conf ? "yes" : "no")
        << " hostapd_bin=" << (hostapd_bin ? "yes" : "no")
        << " libwpa_client=" << (wpa_lib ? "yes" : "no");
    detail_out = oss.str();
    return capable_out;
#endif
}

bool PosixCompatSystemOps::queryMdnsDaemon(std::string& detail_out) {
    detail_out.clear();
#ifdef _WIN32
    detail_out = "unsupported on Windows";
    return false;
#else
    const bool bin = pathExists("/usr/local/bin/mdnsd") || pathExists("/usr/sbin/mdnsd");
    const bool running = processNameRunning("mdnsd");
    detail_out = std::string("mdnsd_bin=") + (bin ? "yes" : "no") +
                 " running=" + (running ? "yes" : "no");
    return bin || running;
#endif
}

bool PosixCompatSystemOps::queryUsbfs(const std::string& usbfs_dir,
                                      std::string& detail_out,
                                      bool& accessible_out,
                                      bool& writable_out) {
    detail_out.clear();
    accessible_out = false;
    writable_out = false;
#ifdef _WIN32
    (void)usbfs_dir;
    detail_out = "usbfs unsupported on Windows";
    return false;
#else
    struct stat st;
    if (::stat(usbfs_dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        detail_out = usbfs_dir + " missing or not a directory";
        return false;
    }
    if (::access(usbfs_dir.c_str(), R_OK | X_OK) != 0) {
        detail_out = usbfs_dir + " not readable (" + strerror(errno) + ")";
        return false;
    }
    accessible_out = true;

    unsigned bus_count = 0U;
    unsigned dev_count = 0U;
    unsigned rw_count = 0U;
    DIR* top = ::opendir(usbfs_dir.c_str());
    if (top != NULL) {
        struct dirent* b_ent = NULL;
        while ((b_ent = ::readdir(top)) != NULL) {
            if (b_ent->d_name[0] == '.') {
                continue;
            }
            const std::string bus_dir = joinPath(usbfs_dir, b_ent->d_name);
            struct stat bst;
            if (::stat(bus_dir.c_str(), &bst) != 0 || !S_ISDIR(bst.st_mode)) {
                continue;
            }
            ++bus_count;
            DIR* sub = ::opendir(bus_dir.c_str());
            if (sub == NULL) {
                continue;
            }
            struct dirent* d_ent = NULL;
            while ((d_ent = ::readdir(sub)) != NULL) {
                if (d_ent->d_name[0] == '.') {
                    continue;
                }
                const std::string dev_node = joinPath(bus_dir, d_ent->d_name);
                struct stat dst;
                if (::stat(dev_node.c_str(), &dst) == 0 && S_ISCHR(dst.st_mode)) {
                    ++dev_count;
                    if (::access(dev_node.c_str(), R_OK | W_OK) == 0) {
                        ++rw_count;
                    }
                }
            }
            ::closedir(sub);
        }
        ::closedir(top);
    }

    if (dev_count > 0U) {
        writable_out = (rw_count > 0U);
    } else {
        writable_out = (::geteuid() == 0) || (::access(usbfs_dir.c_str(), W_OK) == 0);
    }

    std::ostringstream oss;
    oss << usbfs_dir << " buses=" << bus_count << " nodes=" << dev_count
        << " rw_nodes=" << rw_count;
    detail_out = oss.str();
    return accessible_out && writable_out;
#endif
}

bool PosixCompatSystemOps::queryTap(const std::string& tun_path, std::string& detail_out) {
    detail_out.clear();
#ifdef _WIN32
    (void)tun_path;
    detail_out = "TAP unsupported on Windows";
    return false;
#else
    struct stat st;
    if (::stat(tun_path.c_str(), &st) != 0) {
        detail_out = tun_path + " missing (" + strerror(errno) + ")";
        return false;
    }
    if (!S_ISCHR(st.st_mode)) {
        detail_out = tun_path + " is not a character device";
        return false;
    }
    const int fd = ::open(tun_path.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        detail_out = tun_path + " open(O_RDWR) failed (" + strerror(errno) + ")";
        return false;
    }
    ::close(fd);
    detail_out = tun_path + " present and openable (IFF_TAP ready)";
    return true;
#endif
}

bool PosixCompatSystemOps::queryIlmScreen(const std::string& ilm_ctl_path,
                                          const std::string& compositor_conf_path,
                                          uint32_t& width_out,
                                          uint32_t& height_out,
                                          bool& top_first_out,
                                          std::string& detail_out) {
    width_out = 0U;
    height_out = 0U;
    top_first_out = false;
    detail_out.clear();
    EvoIlm ilm(ilm_ctl_path, compositor_conf_path);
    if (!ilm.screenSize(width_out, height_out) || width_out == 0U || height_out == 0U) {
        detail_out = "LayerManagerControl screen size unavailable";
        return false;
    }
    const bool have_order = ilm.renderOrderTopFirst(top_first_out);
    std::ostringstream oss;
    oss << width_out << "x" << height_out
        << " top_first=" << (have_order ? (top_first_out ? "1" : "0") : "unknown");
    detail_out = oss.str();
    return true;
}

bool PosixCompatSystemOps::checkWritableDir(const std::string& dir_path,
                                            std::string& detail_out) {
    detail_out.clear();
#ifdef _WIN32
    (void)dir_path;
    detail_out = "POSIX writable check skipped on Windows";
    return true;
#else
    if (dir_path.empty()) {
        detail_out = "empty path";
        return false;
    }
    struct stat st;
    if (::stat(dir_path.c_str(), &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            detail_out = dir_path + " exists but is not a directory";
            return false;
        }
        char probe_name[64];
        snprintf(probe_name, sizeof(probe_name), ".compat_probe.%ld",
                 static_cast<long>(::getpid()));
        const std::string probe = joinPath(dir_path, probe_name);
        const int fd = ::open(probe.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) {
            detail_out = dir_path + " not writable (" + strerror(errno) + ")";
            return false;
        }
        ::close(fd);
        ::unlink(probe.c_str());
        detail_out = dir_path + " writable";
        return true;
    }

    const std::string parent = parentDirOf(dir_path);
    if (::stat(parent.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        detail_out = dir_path + " and parent " + parent + " do not exist";
        return false;
    }
    if (::access(parent.c_str(), W_OK | X_OK) != 0) {
        detail_out = parent + " not writable (" + strerror(errno) + ")";
        return false;
    }
    detail_out = dir_path + " not created yet; parent " + parent + " is writable";
    return true;
#endif
}

bool PosixCompatSystemOps::pathExists(const std::string& path) {
    return carplay::platform::pathExists(path);
}

bool PosixCompatSystemOps::queryI2cMfi(const MfiI2cConfig& mfi_cfg,
                                       bool probe_version_reg,
                                       std::string& detail_out,
                                       bool& accessible_out,
                                       bool& funcs_ok_out) {
    detail_out.clear();
    accessible_out = false;
    funcs_ok_out = false;
#ifdef _WIN32
    (void)mfi_cfg;
    (void)probe_version_reg;
    detail_out = "Linux i2c-dev unsupported on Windows";
    return false;
#else
    if (mfi_cfg.device_path.empty()) {
        detail_out = "empty I2C device path";
        return false;
    }
    struct stat st;
    if (::stat(mfi_cfg.device_path.c_str(), &st) != 0) {
        detail_out = mfi_cfg.device_path + " missing (" + strerror(errno) + ")";
        return false;
    }
    if (!S_ISCHR(st.st_mode)) {
        detail_out = mfi_cfg.device_path + " is not a character device";
        return false;
    }

    LinuxI2cBackend backend;
    std::string open_err;
    if (!backend.openDevice(mfi_cfg.device_path, &open_err)) {
        if (open_err.find("ioctl(I2C_FUNCS)") != std::string::npos) {
            accessible_out = true;
            funcs_ok_out = false;
        }
        detail_out = open_err;
        return false;
    }

    accessible_out = true;
    funcs_ok_out = true;

    if (!probe_version_reg) {
        std::ostringstream oss;
        oss << mfi_cfg.device_path << " accessible, I2C_FUNCS ok (I2C_RDWR="
            << (backend.supportsI2cRdwr() ? "yes" : "no")
            << "; bus read skipped, pass --compat-mfi-read to probe 0x00)";
        detail_out = oss.str();
        backend.closeDevice();
        return true;
    }

    std::vector<uint8_t> addrs;
    if (mfi_cfg.address7 != 0U) {
        addrs.push_back(mfi_cfg.address7);
    } else {
        addrs.push_back(mfi_reg::kCandidateAddrPrimary);
        addrs.push_back(mfi_reg::kCandidateAddrSecondary);
    }

    std::string last_fail;
    for (size_t i = 0; i < addrs.size(); ++i) {
        const uint8_t addr = addrs[i];
        for (int attempt = 0; attempt < 2; ++attempt) {
            const uint8_t reg = mfi_reg::kDeviceVersion;
            int sys_err = 0;
            const I2cStatus st_tx = backend.transfer(addr, &reg, 1U, NULL, 0U, &sys_err);
            if (st_tx == kI2cNack && attempt == 0) {
                sleepMsCompat(20);
                continue;
            }
            if (st_tx != kI2cOk) {
                char buf[64];
                snprintf(buf, sizeof(buf), "0x%02x select failed (status=%d errno=%d)",
                         static_cast<unsigned>(addr), static_cast<int>(st_tx), sys_err);
                last_fail = buf;
                break;
            }
            const int64_t gap_ms =
                (mfi_cfg.select_to_read_gap_ms > 0) ? mfi_cfg.select_to_read_gap_ms : 5;
            sleepMsCompat(gap_ms);
            uint8_t dev_ver = 0U;
            const I2cStatus st_rx = backend.transfer(addr, NULL, 0U, &dev_ver, 1U, &sys_err);
            if (st_rx == kI2cNack && attempt == 0) {
                sleepMsCompat(20);
                continue;
            }
            if (st_rx != kI2cOk) {
                char buf[64];
                snprintf(buf, sizeof(buf), "0x%02x read failed (status=%d errno=%d)",
                         static_cast<unsigned>(addr), static_cast<int>(st_rx), sys_err);
                last_fail = buf;
                break;
            }
            if (dev_ver == 0x00U || dev_ver == 0xffU) {
                char buf[64];
                snprintf(buf, sizeof(buf), "0x%02x invalid dev_ver=0x%02x",
                         static_cast<unsigned>(addr), static_cast<unsigned>(dev_ver));
                last_fail = buf;
                break;
            }
            char okbuf[160];
            snprintf(okbuf, sizeof(okbuf), "%s I2C_FUNCS ok, addr=0x%02x dev_ver=0x%02x",
                     mfi_cfg.device_path.c_str(),
                     static_cast<unsigned>(addr),
                     static_cast<unsigned>(dev_ver));
            detail_out = okbuf;
            backend.closeDevice();
            return true;
        }
    }

    backend.closeDevice();
    detail_out = mfi_cfg.device_path + " accessible, I2C_FUNCS ok, CP version read failed: " +
                 (last_fail.empty() ? std::string("no response") : last_fail);
    return false;
#endif
}

// ------------------------------------------------------------------------------------------------
// Main compatibility check orchestration
// ------------------------------------------------------------------------------------------------

CompatReport runCompatChecks(const CompatCheckConfig& config, CompatSystemOps* ops_in) {
    PosixCompatSystemOps default_ops;
    CompatSystemOps& ops = (ops_in != NULL) ? *ops_in : static_cast<CompatSystemOps&>(default_ops);
    CompatReport report;

    // 1. Config file & USB mode detection
    DaemonFileConfig file_cfg;
    std::string cfg_err;
    bool usb_mode = config.usb_mode;
    if (!config.config_file.empty()) {
        if (!loadDaemonConfigFile(config.config_file, file_cfg, cfg_err)) {
            report.add(kCompatLineBlock, "config", cfg_err);
        } else if (file_cfg.loaded_from_file) {
            std::ostringstream oss;
            oss << config.config_file
                << " (enabled=" << (file_cfg.enabled ? "1" : "0")
                << " wireless=" << (file_cfg.wireless ? "1" : "0")
                << " wired=" << (file_cfg.wired ? "1" : "0")
                << " detach_usbfs=" << (file_cfg.detach_usbfs_driver ? "1" : "0")
                << " ddp_handoff=" << (file_cfg.ddp_handoff ? "1" : "0")
                << " mfi_i2c="
                << (file_cfg.mfi_i2c_config.enabled ? file_cfg.mfi_i2c_config.device_path
                                                    : std::string("off"))
                << ")";
            report.add(kCompatLineOk, "config", oss.str());
            if (!usb_mode && file_cfg.wired && !file_cfg.wireless) {
                usb_mode = true;
            }
        } else {
            report.add(kCompatLineInfo, "config",
                       config.config_file + " absent (safe defaults: wireless=0, wired=0)");
        }
    }

    const std::string usb_flag_path = joinPath(config.data_dir, "usb");
    std::string usb_port_filter;
    const int usb_setting = readUsbFlagFile(usb_flag_path, usb_port_filter);
    if (usb_setting < 0) {
        report.add(kCompatLineBlock, "usb_file",
                   usb_flag_path + " contains an invalid USB port name");
    } else if (usb_setting == 1) {
        usb_mode = true;
        report.add(kCompatLineInfo, "usb_file",
                   usb_port_filter.empty() ? std::string("any removable USB port")
                                           : ("pinned port " + usb_port_filter));
    }

    // Kill switch awareness (informational/warn in --compat)
    const std::string ks_path = joinPath(config.data_dir, "killswitch");
    const std::string dis_path = joinPath(config.data_dir, "app.disable");
    if (ops.pathExists(ks_path)) {
        report.add(kCompatLineWarn, "killswitch", ks_path + " present (daemon startup inhibited)");
    } else if (ops.pathExists(dis_path)) {
        report.add(kCompatLineWarn, "killswitch", dis_path + " present (plugin/daemon disabled)");
    } else {
        report.add(kCompatLineOk, "killswitch", "inactive");
    }

    // 2. Runtime shared library loadability (dlopen + dlsym across sysroot_symbols.txt groups)
    size_t group_count = 0U;
    const CompatLibGroupSpec* groups = compatRuntimeLibGroups(group_count);
    for (size_t i = 0; i < group_count; ++i) {
        const CompatLibGroupSpec& g = groups[i];
        void* handle = NULL;
        std::string loaded_name;
        std::string open_err;
        if (!ops.openLibrary(g.sonames, g.soname_count, config.extra_lib_dirs,
                             handle, loaded_name, open_err)) {
            report.add(g.required ? kCompatLineBlock : kCompatLineInfo,
                       g.name,
                       g.required ? open_err : (std::string("optional absent: ") + open_err));
            continue;
        }

        std::string missing_req;
        for (size_t s = 0; s < g.required_symbol_count; ++s) {
            if (!ops.resolveSymbol(handle, g.required_symbols[s])) {
                if (!missing_req.empty()) {
                    missing_req += " ";
                }
                missing_req += g.required_symbols[s];
            }
        }
        std::string missing_opt;
        for (size_t s = 0; s < g.optional_symbol_count; ++s) {
            if (!ops.resolveSymbol(handle, g.optional_symbols[s])) {
                if (!missing_opt.empty()) {
                    missing_opt += " ";
                }
                missing_opt += g.optional_symbols[s];
            }
        }
        ops.closeLibrary(handle);

        if (!missing_req.empty()) {
            report.add(g.required ? kCompatLineBlock : kCompatLineWarn,
                       g.name,
                       loaded_name + " missing symbol(s): " + missing_req);
        } else {
            std::ostringstream oss;
            oss << loaded_name << " (" << g.required_symbol_count << "/"
                << g.required_symbol_count << " symbols)";
            if (!missing_opt.empty()) {
                oss << "; optional missing: " << missing_opt;
                report.add(kCompatLineWarn, g.name, oss.str());
            } else {
                report.add(kCompatLineOk, g.name, oss.str());
            }
        }
    }

    // 3. HMI Framework ELF ABI check (`libAppFramework.A.so` + `libCoreFramework.A.so`)
    {
        const std::string app_fw = config.hmi_lib_dir + "/libAppFramework.A.so";
        const std::string core_fw = config.hmi_lib_dir + "/libCoreFramework.A.so";
        uint32_t vtable_size = 0U;
        std::string abi_err;
        if (!ops.readElfSymbolSize(app_fw, "_ZTVN3bmw9PluginAppE", vtable_size, abi_err)) {
            report.add(kCompatLineBlock, "hmi_abi",
                       abi_err.empty() ? (app_fw + " unreadable") : abi_err);
        } else if (vtable_size != kExpectedPluginAppVtableBytes) {
            std::ostringstream oss;
            oss << "bmw::PluginApp vtable size " << vtable_size
                << " (expected " << kExpectedPluginAppVtableBytes << ")";
            report.add(kCompatLineBlock, "hmi_abi", oss.str());
        } else {
            std::vector<std::string> fw_paths;
            fw_paths.push_back(app_fw);
            fw_paths.push_back(core_fw);
            std::string missing_fw;
            std::string fw_err;
            if (!ops.checkElfSymbols(fw_paths, kHmiFrameworkReqSyms,
                                     ARRAY_LEN(kHmiFrameworkReqSyms),
                                     missing_fw, fw_err)) {
                report.add(kCompatLineBlock, "hmi_abi", fw_err);
            } else if (!missing_fw.empty()) {
                report.add(kCompatLineBlock, "hmi_abi", "missing symbol(s): " + missing_fw);
            } else {
                std::ostringstream oss;
                oss << "bmw::PluginApp vtable=" << vtable_size << " B ("
                    << ARRAY_LEN(kHmiFrameworkReqSyms) << "/"
                    << ARRAY_LEN(kHmiFrameworkReqSyms) << " symbols)";
                report.add(kCompatLineOk, "hmi_abi", oss.str());
            }
        }
    }

    // 4. ALPS Bluetooth & SPP compatibility report
    {
        const BtTransportCapability bt_cap = ops.probeBtCapability();
        report.add(kCompatLineInfo, "bt_backend", formatBtTransportCapability(bt_cap));
        const AlpsCompatReport alps_rep = ops.probeAlpsCompat(bt_cap, usb_mode);
        report.add(mapAlpsCompatLevel(alps_rep.alps.level), "alps", alps_rep.alps.detail);
        report.add(mapAlpsCompatLevel(alps_rep.uuid.level), "uuid", alps_rep.uuid.detail);
        report.add(mapAlpsCompatLevel(alps_rep.spp.level), "spp", alps_rep.spp.detail);
    }

    // 5. AP / wland + mDNS availability
    {
        std::string ap_detail;
        bool ap_active = false;
        bool ap_capable = false;
        ops.queryApWland(ap_detail, ap_active, ap_capable);
        if (ap_active) {
            report.add(kCompatLineOk, "ap", ap_detail);
        } else if (ap_capable) {
            report.add(kCompatLineOk, "ap", ap_detail + " (hotspot idle/off until started)");
        } else {
            report.add(kCompatLineWarn, "ap",
                       ap_detail.empty() ? std::string("no wland/hostapd AP capability")
                                         : ap_detail);
        }

        std::string mdns_detail;
        if (ops.queryMdnsDaemon(mdns_detail)) {
            report.add(kCompatLineOk, "mdnsd", mdns_detail);
        } else {
            report.add(kCompatLineWarn, "mdnsd",
                       mdns_detail.empty() ? std::string("mdnsd not found") : mdns_detail);
        }
    }

    // 6. usbfs access
    {
        std::string usb_detail;
        bool accessible = false;
        bool writable = false;
        if (ops.queryUsbfs(config.usbfs_dir, usb_detail, accessible, writable)) {
            report.add(kCompatLineOk, "usbfs", usb_detail);
        } else if (accessible) {
            report.add(kCompatLineWarn, "usbfs", usb_detail + " (not writable)");
        } else {
            report.add(kCompatLineBlock, "usbfs", usb_detail);
        }
    }

    // 7. TAP (/dev/net/tun) availability
    {
        std::string tap_detail;
        if (ops.queryTap(config.tun_path, tap_detail)) {
            report.add(kCompatLineOk, "tap", tap_detail);
        } else {
            report.add(kCompatLineBlock, "tap", tap_detail);
        }
    }

    // 8. LayerManager display geometry
    if (config.check_ilm) {
        uint32_t w = 0U;
        uint32_t h = 0U;
        bool top_first = false;
        std::string ilm_detail;
        if (ops.queryIlmScreen(config.ilm_ctl_path, config.compositor_conf_path,
                               w, h, top_first, ilm_detail)) {
            if ((w == 800U && h == 480U) || (w == 1280U && h == 480U) ||
                (w == 1440U && h == 540U)) {
                report.add(kCompatLineOk, "video", ilm_detail);
            } else {
                report.add(kCompatLineWarn, "video",
                           ilm_detail + " (untested resolution on car)");
            }
        } else {
            report.add(kCompatLineWarn, "video", ilm_detail);
        }
    }

    // 9. Writable persistent data dir & runtime state dir
    {
        std::string data_detail;
        if (ops.checkWritableDir(config.data_dir, data_detail)) {
            report.add(kCompatLineOk, "data_dir", data_detail);
        } else {
            report.add(kCompatLineBlock, "data_dir", data_detail);
        }

        const std::string state_dir = parentDirOf(config.state_file);
        std::string state_detail;
        if (ops.checkWritableDir(state_dir, state_detail)) {
            report.add(kCompatLineOk, "state_dir", state_detail);
        } else {
            report.add(kCompatLineBlock, "state_dir", state_detail);
        }
    }

    // 10. MFi I2C coprocessor check (never performs bus transactions unless compat_mfi_read=true)
    {
        MfiI2cConfig mfi_cfg = config.mfi_i2c_config;
        if (!config.has_mfi_i2c_override && file_cfg.loaded_from_file) {
            mfi_cfg = file_cfg.mfi_i2c_config;
        }
        if (!mfi_cfg.enabled) {
            report.add(kCompatLineInfo, "mfi",
                       "disabled (default off; set mfi_i2c=... in carplay.conf or --mfi-i2c=DEV[:ADDR])");
        } else {
            std::string mfi_detail;
            bool mfi_accessible = false;
            bool mfi_funcs_ok = false;
            if (ops.queryI2cMfi(mfi_cfg, config.compat_mfi_read,
                                mfi_detail, mfi_accessible, mfi_funcs_ok)) {
                report.add(kCompatLineOk, "mfi", mfi_detail);
            } else if (mfi_accessible && mfi_funcs_ok) {
                report.add(kCompatLineWarn, "mfi", mfi_detail);
            } else {
                report.add(kCompatLineBlock, "mfi", mfi_detail);
            }
        }
    }

    return report;
}

}  // namespace platform
}  // namespace carplay
