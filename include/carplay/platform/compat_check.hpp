#ifndef CARPLAY_PLATFORM_COMPAT_CHECK_HPP
#define CARPLAY_PLATFORM_COMPAT_CHECK_HPP

// Dry-run vehicle compatibility self-check (`carplayd --compat` / `--self-check`).
//
// Derived from EntryNav2-Android-Auto 0.13.0-rc.6 tools/aa_supervisor.cpp
// (PolyForm Noncommercial License 1.0.0) for the `@ok|@info|@warn|@block|<check>|detail`
// output contract, ALPS/USB mode downgrading, and `bmw::PluginApp` vtable ABI check.
//
// Strictly read-only on head-unit state: probes runtime library loadability (`dlopen` +
// `dlsym` across every group in `scripts/ci/sysroot_symbols.txt`), HMI framework ELF ABI,
// ALPS SPP compatibility, AP/wland availability, usbfs access, TAP (/dev/net/tun)
// openability, LayerManager screen geometry, and writable state/data directories.
// Exits non-zero ONLY when one or more `@block` lines are emitted.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/platform/bt_transport.hpp"
#include "carplay/platform/mfi_i2c.hpp"
#include "carplay/platform/service_contract.hpp"

namespace carplay {
namespace platform {

enum CompatLineLevel {
    kCompatLineOk = 0,
    kCompatLineInfo = 1,
    kCompatLineWarn = 2,
    kCompatLineBlock = 3
};

const char* compatLineLevelTag(CompatLineLevel level);

struct CompatLine {
    CompatLineLevel level;
    std::string check;
    std::string detail;

    CompatLine() : level(kCompatLineInfo) {}
    CompatLine(CompatLineLevel lvl, const std::string& chk, const std::string& dtl)
        : level(lvl), check(chk), detail(dtl) {}

    std::string format() const;
};

struct CompatReport {
    std::vector<CompatLine> lines;

    void add(CompatLineLevel level, const std::string& check, const std::string& detail = std::string());
    bool hasBlockingFailure() const;
    int exitCode() const;
    std::string format() const;
};

struct CompatLibGroupSpec {
    const char* name;
    bool required;
    const char* const* sonames;
    size_t soname_count;
    const char* const* required_symbols;
    size_t required_symbol_count;
    const char* const* optional_symbols;
    size_t optional_symbol_count;
};

/// Returns the static table of `dlopen`-loaded runtime library groups matching
/// `scripts/ci/sysroot_symbols.txt`.
const CompatLibGroupSpec* compatRuntimeLibGroups(size_t& count_out);

struct CompatCheckConfig {
    bool usb_mode;
    bool check_ilm;
    bool has_mfi_i2c_override;
    MfiI2cConfig mfi_i2c_config;
    bool compat_mfi_read;
    std::string data_dir;
    std::string state_file;
    std::string config_file;
    std::string tun_path;
    std::string usbfs_dir;
    std::string hmi_lib_dir;
    std::string ilm_ctl_path;
    std::string compositor_conf_path;
    std::vector<std::string> extra_lib_dirs;

    CompatCheckConfig()
        : usb_mode(false),
          check_ilm(true),
          has_mfi_i2c_override(false),
          mfi_i2c_config(),
          compat_mfi_read(false),
          data_dir(contract::kDataDir),
          state_file(contract::kStateFile),
          config_file(contract::kConfigFile),
          tun_path("/dev/net/tun"),
          usbfs_dir("/dev/bus/usb"),
          hmi_lib_dir("/opt/hmi/lib"),
          ilm_ctl_path("LayerManagerControl"),
          compositor_conf_path("/etc/layermanager/compositor.conf") {
        extra_lib_dirs.push_back("/usr/local/lib");
        extra_lib_dirs.push_back("/opt/hmi/lib");
    }
};

/// OS/hardware probe interface isolated for fakeable host unit testing.
class CompatSystemOps {
public:
    virtual ~CompatSystemOps() {}

    virtual bool openLibrary(const char* const* sonames,
                             size_t soname_count,
                             const std::vector<std::string>& extra_dirs,
                             void*& handle_out,
                             std::string& loaded_name_out,
                             std::string& error_out) = 0;
    virtual bool resolveSymbol(void* handle, const char* symbol_name) = 0;
    virtual void closeLibrary(void* handle) = 0;

    virtual bool readElfSymbolSize(const std::string& elf_path,
                                   const char* symbol_name,
                                   uint32_t& size_out,
                                   std::string& error_out) = 0;
    virtual bool checkElfSymbols(const std::vector<std::string>& elf_paths,
                                 const char* const* symbols,
                                 size_t symbol_count,
                                 std::string& missing_out,
                                 std::string& error_out) = 0;

    virtual BtTransportCapability probeBtCapability() = 0;
    virtual AlpsCompatReport probeAlpsCompat(const BtTransportCapability& cap, bool usb_mode) = 0;

    virtual bool queryApWland(std::string& detail_out, bool& active_out, bool& capable_out) = 0;
    virtual bool queryMdnsDaemon(std::string& detail_out) = 0;
    virtual bool queryUsbfs(const std::string& usbfs_dir,
                            std::string& detail_out,
                            bool& accessible_out,
                            bool& writable_out) = 0;
    virtual bool queryTap(const std::string& tun_path, std::string& detail_out) = 0;
    virtual bool queryIlmScreen(const std::string& ilm_ctl_path,
                                const std::string& compositor_conf_path,
                                uint32_t& width_out,
                                uint32_t& height_out,
                                bool& top_first_out,
                                std::string& detail_out) = 0;
    virtual bool checkWritableDir(const std::string& dir_path, std::string& detail_out) = 0;
    virtual bool pathExists(const std::string& path) = 0;
    virtual bool queryI2cMfi(const MfiI2cConfig& mfi_cfg,
                             bool probe_version_reg,
                             std::string& detail_out,
                             bool& accessible_out,
                             bool& funcs_ok_out) = 0;
};

class PosixCompatSystemOps : public CompatSystemOps {
public:
    PosixCompatSystemOps() {}
    virtual ~PosixCompatSystemOps() {}

    virtual bool openLibrary(const char* const* sonames,
                             size_t soname_count,
                             const std::vector<std::string>& extra_dirs,
                             void*& handle_out,
                             std::string& loaded_name_out,
                             std::string& error_out);
    virtual bool resolveSymbol(void* handle, const char* symbol_name);
    virtual void closeLibrary(void* handle);

    virtual bool readElfSymbolSize(const std::string& elf_path,
                                   const char* symbol_name,
                                   uint32_t& size_out,
                                   std::string& error_out);
    virtual bool checkElfSymbols(const std::vector<std::string>& elf_paths,
                                 const char* const* symbols,
                                 size_t symbol_count,
                                 std::string& missing_out,
                                 std::string& error_out);

    virtual BtTransportCapability probeBtCapability();
    virtual AlpsCompatReport probeAlpsCompat(const BtTransportCapability& cap, bool usb_mode);

    virtual bool queryApWland(std::string& detail_out, bool& active_out, bool& capable_out);
    virtual bool queryMdnsDaemon(std::string& detail_out);
    virtual bool queryUsbfs(const std::string& usbfs_dir,
                            std::string& detail_out,
                            bool& accessible_out,
                            bool& writable_out);
    virtual bool queryTap(const std::string& tun_path, std::string& detail_out);
    virtual bool queryIlmScreen(const std::string& ilm_ctl_path,
                                const std::string& compositor_conf_path,
                                uint32_t& width_out,
                                uint32_t& height_out,
                                bool& top_first_out,
                                std::string& detail_out);
    virtual bool checkWritableDir(const std::string& dir_path, std::string& detail_out);
    virtual bool pathExists(const std::string& path);
    virtual bool queryI2cMfi(const MfiI2cConfig& mfi_cfg,
                             bool probe_version_reg,
                             std::string& detail_out,
                             bool& accessible_out,
                             bool& funcs_ok_out);

private:
    PosixCompatSystemOps(const PosixCompatSystemOps&) = delete;
    PosixCompatSystemOps& operator=(const PosixCompatSystemOps&) = delete;
};

/// Runs the full compatibility report using `ops` (NULL -> `PosixCompatSystemOps`).
CompatReport runCompatChecks(const CompatCheckConfig& config, CompatSystemOps* ops = NULL);

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_COMPAT_CHECK_HPP
