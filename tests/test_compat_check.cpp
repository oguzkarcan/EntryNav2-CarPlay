#include "test_support.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include <map>
#include <set>
#include <string>
#include <vector>

#include "carplay/platform/compat_check.hpp"
#include "carplay/platform/evo_process.hpp"
#include "carplay/platform/file_util.hpp"

namespace {

namespace plat = carplay::platform;

std::string g_argv0_exe;

std::string siblingDaemonPath() {
    if (!g_argv0_exe.empty()) {
        const size_t slash = g_argv0_exe.find_last_of('/');
        if (slash != std::string::npos) {
            return g_argv0_exe.substr(0, slash + 1U) + "carplayd";
        }
    }
    return "build/host/carplayd";
}

std::string makeTempDir(const char* prefix) {
#ifndef _WIN32
    char tmpl[128];
    snprintf(tmpl, sizeof(tmpl), "/tmp/%s_XXXXXX", prefix ? prefix : "compat_test");
    char* d = mkdtemp(tmpl);
    return d ? std::string(d) : std::string("/tmp/compat_test_fallback");
#else
    (void)prefix;
    return "build/compat_test_tmp";
#endif
}

void removeTempDir(const std::string& dir) {
    if (dir.empty()) {
        return;
    }
#ifndef _WIN32
    std::vector<std::string> args;
    args.push_back("-rf");
    args.push_back(dir);
    std::string out;
    plat::runCommand("rm", args, out, 5000);
#endif
}

class FakeCompatSystemOps : public plat::CompatSystemOps {
public:
    std::set<std::string> missing_libs;
    std::set<std::string> missing_syms;
    uint32_t plugin_app_vtable_size;
    bool hmi_elf_ok;
    std::string hmi_missing_syms;

    plat::BtTransportCapability bt_cap;
    plat::AlpsCompatReport alps_report_wireless;
    plat::AlpsCompatReport alps_report_usb;

    bool ap_capable;
    bool ap_active;
    bool mdns_ok;
    bool usbfs_accessible;
    bool usbfs_writable;
    bool tap_ok;
    bool ilm_ok;
    uint32_t ilm_w;
    uint32_t ilm_h;
    bool ilm_top_first;
    bool mfi_accessible;
    bool mfi_funcs_ok;
    bool mfi_read_ok;
    bool mfi_query_called;
    bool mfi_read_requested;
    std::set<std::string> unwritable_dirs;
    std::set<std::string> existing_paths;

    FakeCompatSystemOps()
        : plugin_app_vtable_size(172U),
          hmi_elf_ok(true),
          ap_capable(true),
          ap_active(false),
          mdns_ok(true),
          usbfs_accessible(true),
          usbfs_writable(true),
          tap_ok(true),
          ilm_ok(true),
          ilm_w(800U),
          ilm_h(480U),
          ilm_top_first(false),
          mfi_accessible(true),
          mfi_funcs_ok(true),
          mfi_read_ok(true),
          mfi_query_called(false),
          mfi_read_requested(false) {
        bt_cap.alps_library_present = true;
        bt_cap.alps_dbus_ready = true;
        bt_cap.alps_service_owned = true;

        alps_report_wireless.wireless_ready = true;
        alps_report_wireless.usb_mode = false;
        alps_report_wireless.alps = plat::CompatCheckResult("alps", plat::kCompatPass, "pid=123 slot=5");
        alps_report_wireless.uuid = plat::CompatCheckResult("uuid", plat::kCompatPass, "iAP2 UUID ok");
        alps_report_wireless.spp = plat::CompatCheckResult("spp", plat::kCompatPass, "org.alps.evolution ready");

        alps_report_usb = alps_report_wireless;
        alps_report_usb.usb_mode = true;
    }

    virtual bool openLibrary(const char* const* sonames,
                             size_t soname_count,
                             const std::vector<std::string>& /*extra_dirs*/,
                             void*& handle_out,
                             std::string& loaded_name_out,
                             std::string& error_out) {
        for (size_t i = 0; i < soname_count; ++i) {
            if (missing_libs.find(sonames[i]) == missing_libs.end()) {
                handle_out = reinterpret_cast<void*>(static_cast<uintptr_t>(0x1000U + i));
                loaded_name_out = sonames[i];
                return true;
            }
        }
        error_out = std::string(soname_count > 0 ? sonames[0] : "unknown") + ": fake missing";
        return false;
    }

    virtual bool resolveSymbol(void* /*handle*/, const char* symbol_name) {
        return missing_syms.find(symbol_name) == missing_syms.end();
    }

    virtual void closeLibrary(void* /*handle*/) {}

    virtual bool readElfSymbolSize(const std::string& /*elf_path*/,
                                   const char* /*symbol_name*/,
                                   uint32_t& size_out,
                                   std::string& error_out) {
        if (!hmi_elf_ok) {
            error_out = "fake hmi elf missing";
            return false;
        }
        size_out = plugin_app_vtable_size;
        return true;
    }

    virtual bool checkElfSymbols(const std::vector<std::string>& /*elf_paths*/,
                                 const char* const* /*symbols*/,
                                 size_t /*symbol_count*/,
                                 std::string& missing_out,
                                 std::string& error_out) {
        if (!hmi_elf_ok) {
            error_out = "fake hmi elf missing";
            return false;
        }
        missing_out = hmi_missing_syms;
        return true;
    }

    virtual plat::BtTransportCapability probeBtCapability() {
        return bt_cap;
    }

    virtual plat::AlpsCompatReport probeAlpsCompat(const plat::BtTransportCapability& /*cap*/,
                                                   bool usb_mode) {
        return usb_mode ? alps_report_usb : alps_report_wireless;
    }

    virtual bool queryApWland(std::string& detail_out, bool& active_out, bool& capable_out) {
        active_out = ap_active;
        capable_out = ap_capable;
        detail_out = ap_capable ? "vmostd=yes wlan0=yes" : "vmostd=no wlan0=no";
        return ap_capable;
    }

    virtual bool queryMdnsDaemon(std::string& detail_out) {
        detail_out = mdns_ok ? "mdnsd_bin=yes running=yes" : "mdnsd_bin=no running=no";
        return mdns_ok;
    }

    virtual bool queryUsbfs(const std::string& usbfs_dir,
                            std::string& detail_out,
                            bool& accessible_out,
                            bool& writable_out) {
        accessible_out = usbfs_accessible;
        writable_out = usbfs_writable;
        detail_out = usbfs_dir + (accessible_out ? " ok" : " missing");
        return accessible_out && writable_out;
    }

    virtual bool queryTap(const std::string& tun_path, std::string& detail_out) {
        detail_out = tun_path + (tap_ok ? " openable" : " missing");
        return tap_ok;
    }

    virtual bool queryIlmScreen(const std::string& /*ilm_ctl_path*/,
                                const std::string& /*compositor_conf_path*/,
                                uint32_t& width_out,
                                uint32_t& height_out,
                                bool& top_first_out,
                                std::string& detail_out) {
        if (!ilm_ok) {
            detail_out = "LayerManager unavailable";
            return false;
        }
        width_out = ilm_w;
        height_out = ilm_h;
        top_first_out = ilm_top_first;
        detail_out = "800x480 top_first=0";
        return true;
    }

    virtual bool checkWritableDir(const std::string& dir_path, std::string& detail_out) {
        if (unwritable_dirs.find(dir_path) != unwritable_dirs.end()) {
            detail_out = dir_path + " read-only";
            return false;
        }
        detail_out = dir_path + " writable";
        return true;
    }

    virtual bool pathExists(const std::string& path) {
        return existing_paths.find(path) != existing_paths.end();
    }

    virtual bool queryI2cMfi(const plat::MfiI2cConfig& mfi_cfg,
                             bool probe_version_reg,
                             std::string& detail_out,
                             bool& accessible_out,
                             bool& funcs_ok_out) {
        mfi_query_called = true;
        mfi_read_requested = probe_version_reg;
        accessible_out = mfi_accessible;
        funcs_ok_out = mfi_funcs_ok;
        if (!mfi_accessible) {
            detail_out = mfi_cfg.device_path + " missing";
            return false;
        }
        if (!mfi_funcs_ok) {
            detail_out = mfi_cfg.device_path + " I2C_FUNCS failed";
            return false;
        }
        if (!probe_version_reg) {
            detail_out = mfi_cfg.device_path + " accessible, I2C_FUNCS ok (bus read skipped)";
            return true;
        }
        if (!mfi_read_ok) {
            detail_out = mfi_cfg.device_path + " accessible, I2C_FUNCS ok, reg 0x00 NACK";
            return false;
        }
        detail_out = mfi_cfg.device_path + " I2C_FUNCS ok, addr=0x10 dev_ver=0x05";
        return true;
    }
};

const plat::CompatLine* findLine(const plat::CompatReport& r, const std::string& check) {
    for (size_t i = 0; i < r.lines.size(); ++i) {
        if (r.lines[i].check == check) {
            return &r.lines[i];
        }
    }
    return NULL;
}

TEST_CASE(compatAllPassWithFakeOps) {
    FakeCompatSystemOps ops;
    plat::CompatCheckConfig cfg;
    CHECK_EQ(std::string("/etc/wayland/compositor.conf"), cfg.compositor_conf_path);
    cfg.data_dir = "/tmp/nonexistent_carplay_data_compat_test";
    cfg.state_file = "/tmp/entry-carplayd-state";
    cfg.config_file = "/tmp/nonexistent_carplay_conf_compat_test";

    const plat::CompatReport r = plat::runCompatChecks(cfg, &ops);
    CHECK(!r.hasBlockingFailure());
    CHECK_EQ(0, r.exitCode());

    const plat::CompatLine* asound = findLine(r, "libasound");
    REQUIRE(asound != NULL);
    CHECK_EQ(static_cast<int>(plat::kCompatLineOk), static_cast<int>(asound->level));

    const plat::CompatLine* hmi = findLine(r, "hmi_abi");
    REQUIRE(hmi != NULL);
    CHECK_EQ(static_cast<int>(plat::kCompatLineOk), static_cast<int>(hmi->level));

    const plat::CompatLine* bt_opt = findLine(r, "libbluetooth");
    REQUIRE(bt_opt != NULL);
    CHECK_EQ(static_cast<int>(plat::kCompatLineOk), static_cast<int>(bt_opt->level));

    const plat::CompatLine* tap = findLine(r, "tap");
    REQUIRE(tap != NULL);
    CHECK_EQ(static_cast<int>(plat::kCompatLineOk), static_cast<int>(tap->level));

    const plat::CompatLine* usbfs = findLine(r, "usbfs");
    REQUIRE(usbfs != NULL);
    CHECK_EQ(static_cast<int>(plat::kCompatLineOk), static_cast<int>(usbfs->level));

    const std::string formatted = r.format();
    CHECK(formatted.find("@ok|libxsvideo|") != std::string::npos);
    CHECK(formatted.find("@ok|alps|") != std::string::npos);
    CHECK(formatted.find("@ok|data_dir|") != std::string::npos);
    CHECK(formatted.find("@ok|state_dir|") != std::string::npos);
    CHECK(formatted.find("@info|mfi|") != std::string::npos);
    CHECK(!ops.mfi_query_called);
}

TEST_CASE(compatOptionalLibAndSymbolDoNotBlock) {
    FakeCompatSystemOps ops;
    ops.missing_libs.insert("libbluetooth.so.3");
    ops.missing_libs.insert("libbluetooth.so");
    ops.missing_syms.insert("DNSServiceUpdateRecord");
    ops.ap_capable = false;
    ops.ilm_ok = false;

    plat::CompatCheckConfig cfg;
    cfg.config_file.clear();
    const plat::CompatReport r = plat::runCompatChecks(cfg, &ops);

    CHECK(!r.hasBlockingFailure());
    CHECK_EQ(0, r.exitCode());

    const plat::CompatLine* bt_opt = findLine(r, "libbluetooth");
    REQUIRE(bt_opt != NULL);
    CHECK_EQ(static_cast<int>(plat::kCompatLineInfo), static_cast<int>(bt_opt->level));

    const plat::CompatLine* dnssd = findLine(r, "libdns_sd");
    REQUIRE(dnssd != NULL);
    CHECK_EQ(static_cast<int>(plat::kCompatLineWarn), static_cast<int>(dnssd->level));

    const plat::CompatLine* ap = findLine(r, "ap");
    REQUIRE(ap != NULL);
    CHECK_EQ(static_cast<int>(plat::kCompatLineWarn), static_cast<int>(ap->level));
}

TEST_CASE(compatRequiredFailuresBlockAndExitNonZero) {
    FakeCompatSystemOps ops;
    ops.missing_libs.insert("libxsvideo.so.4");
    ops.missing_syms.insert("snd_pcm_open");
    ops.plugin_app_vtable_size = 168U;
    ops.tap_ok = false;
    ops.usbfs_accessible = false;
    ops.usbfs_writable = false;
    ops.unwritable_dirs.insert("/var/local/data/CarPlay");

    plat::CompatCheckConfig cfg;
    cfg.config_file.clear();
    const plat::CompatReport r = plat::runCompatChecks(cfg, &ops);

    CHECK(r.hasBlockingFailure());
    CHECK_EQ(1, r.exitCode());

    CHECK_EQ(static_cast<int>(plat::kCompatLineBlock),
             static_cast<int>(findLine(r, "libxsvideo")->level));
    CHECK_EQ(static_cast<int>(plat::kCompatLineBlock),
             static_cast<int>(findLine(r, "libasound")->level));
    CHECK_EQ(static_cast<int>(plat::kCompatLineBlock),
             static_cast<int>(findLine(r, "hmi_abi")->level));
    CHECK_EQ(static_cast<int>(plat::kCompatLineBlock),
             static_cast<int>(findLine(r, "tap")->level));
    CHECK_EQ(static_cast<int>(plat::kCompatLineBlock),
             static_cast<int>(findLine(r, "usbfs")->level));
    CHECK_EQ(static_cast<int>(plat::kCompatLineBlock),
             static_cast<int>(findLine(r, "data_dir")->level));
}

TEST_CASE(compatAlpsFailBlocksWirelessOnlyNotUsbMode) {
    FakeCompatSystemOps ops;
    ops.alps_report_wireless.wireless_ready = false;
    ops.alps_report_wireless.alps = plat::CompatCheckResult(
        "alps", plat::kCompatFail, "unknown ALPS structure 15024/480/36 (wireless only)");
    ops.alps_report_usb.wireless_ready = false;
    ops.alps_report_usb.usb_mode = true;
    ops.alps_report_usb.alps = plat::CompatCheckResult(
        "alps", plat::kCompatInfo, "unknown ALPS structure 15024/480/36 (wireless only)");

    plat::CompatCheckConfig cfg;
    cfg.config_file.clear();
    cfg.usb_mode = false;
    const plat::CompatReport wireless_rep = plat::runCompatChecks(cfg, &ops);
    CHECK(wireless_rep.hasBlockingFailure());
    CHECK_EQ(1, wireless_rep.exitCode());
    CHECK_EQ(static_cast<int>(plat::kCompatLineBlock),
             static_cast<int>(findLine(wireless_rep, "alps")->level));

    cfg.usb_mode = true;
    const plat::CompatReport usb_rep = plat::runCompatChecks(cfg, &ops);
    CHECK(!usb_rep.hasBlockingFailure());
    CHECK_EQ(0, usb_rep.exitCode());
    CHECK_EQ(static_cast<int>(plat::kCompatLineInfo),
             static_cast<int>(findLine(usb_rep, "alps")->level));
}

TEST_CASE(compatConfigFileAndKillSwitchReporting) {
    const std::string dir = makeTempDir("compat_cfg");
    const std::string conf_path = plat::joinPath(dir, "carplay.conf");
    const std::string ks_path = plat::joinPath(dir, "killswitch");
    const std::string cfg_body = "wireless=0\nwired=1\n";
    REQUIRE(plat::writeFileAtomic(
        conf_path, reinterpret_cast<const uint8_t*>(cfg_body.data()), cfg_body.size()));

    FakeCompatSystemOps ops;
    ops.existing_paths.insert(ks_path);
    ops.alps_report_usb.alps = plat::CompatCheckResult(
        "alps", plat::kCompatInfo, "usb mode info");

    plat::CompatCheckConfig cfg;
    cfg.data_dir = dir;
    cfg.config_file = conf_path;
    cfg.state_file = plat::joinPath(dir, "state");

    const plat::CompatReport r = plat::runCompatChecks(cfg, &ops);
    CHECK(!r.hasBlockingFailure());
    CHECK_EQ(static_cast<int>(plat::kCompatLineOk),
             static_cast<int>(findLine(r, "config")->level));
    CHECK_EQ(static_cast<int>(plat::kCompatLineWarn),
             static_cast<int>(findLine(r, "killswitch")->level));
    // wired=1 with wireless=0 auto-selected usb_mode=true
    CHECK_EQ(static_cast<int>(plat::kCompatLineInfo),
             static_cast<int>(findLine(r, "alps")->level));

    // Invalid config file triggers @block
    const std::string bad_cfg = "wired=maybe\n";
    REQUIRE(plat::writeFileAtomic(
        conf_path, reinterpret_cast<const uint8_t*>(bad_cfg.data()), bad_cfg.size()));
    const plat::CompatReport r_bad = plat::runCompatChecks(cfg, &ops);
    CHECK(r_bad.hasBlockingFailure());
    CHECK_EQ(static_cast<int>(plat::kCompatLineBlock),
             static_cast<int>(findLine(r_bad, "config")->level));

    removeTempDir(dir);
}

TEST_CASE(compatRuntimeLibGroupTableCoversManifest) {
    size_t n = 0U;
    const plat::CompatLibGroupSpec* groups = plat::compatRuntimeLibGroups(n);
    CHECK_EQ(8U, n);
    size_t total_req_syms = 0U;
    for (size_t i = 0; i < n; ++i) {
        CHECK(groups[i].soname_count > 0U);
        total_req_syms += groups[i].required_symbol_count;
    }
    // 10 (asound) + 14 (xsvideo) + 2 (drm) + 6 (drm_omap) + 7 (vmost) + 4 (dns_sd) + 40 (dbus) = 83
    CHECK_EQ(83U, total_req_syms);
}

TEST_CASE(compatDaemonBinaryCliSmoke) {
#ifdef _WIN32
    return;
#else
    const std::string dir = makeTempDir("compat_cli");
    const std::string state_file = plat::joinPath(dir, "state");
    std::vector<std::string> args;
    args.push_back("--self-check");
    args.push_back("--data-dir");
    args.push_back(dir);
    args.push_back("--state-file");
    args.push_back(state_file);
    args.push_back("--no-ilm-size");

    std::string out;
    plat::CommandReport rep;
    plat::runCommand(siblingDaemonPath(), args, out, 5000, &rep);
    CHECK_EQ(0, rep.spawn_error);
    // On a host box without car libs, exit_code is 1 due to @block lines; output must still be formatted.
    CHECK(rep.text.find("@ok|data_dir|") != std::string::npos);
    CHECK(rep.text.find("@ok|state_dir|") != std::string::npos);
    CHECK(rep.text.find("|libxsvideo|") != std::string::npos);
    CHECK(rep.text.find("@info|mfi|") != std::string::npos);

    // Passing --mfi-i2c /dev/null triggers @block|mfi| (not a character I2C device; no bus transaction)
    args.push_back("--mfi-i2c");
    args.push_back("/dev/null");
    std::string out_mfi;
    plat::CommandReport rep_mfi;
    plat::runCommand(siblingDaemonPath(), args, out_mfi, 5000, &rep_mfi);
    CHECK_EQ(0, rep_mfi.spawn_error);
    CHECK(rep_mfi.text.find("@block|mfi|") != std::string::npos);

    removeTempDir(dir);
#endif
}

TEST_CASE(compatMfiConfiguredAndOptInReadStates) {
    const std::string dir = makeTempDir("compat_mfi");
    const std::string conf_path = plat::joinPath(dir, "carplay.conf");
    const std::string cfg_body = "wired=1\nmfi_i2c=/dev/i2c-0:0x10\n";
    REQUIRE(plat::writeFileAtomic(
        conf_path, reinterpret_cast<const uint8_t*>(cfg_body.data()), cfg_body.size()));

    // 1. Configured via carplay.conf without compat_mfi_read -> @ok without bus read
    {
        FakeCompatSystemOps ops;
        plat::CompatCheckConfig cfg;
        cfg.data_dir = dir;
        cfg.config_file = conf_path;
        cfg.state_file = plat::joinPath(dir, "state");
        const plat::CompatReport r = plat::runCompatChecks(cfg, &ops);
        CHECK(!r.hasBlockingFailure());
        CHECK(ops.mfi_query_called);
        CHECK(!ops.mfi_read_requested);
        const plat::CompatLine* mfi = findLine(r, "mfi");
        REQUIRE(mfi != NULL);
        CHECK_EQ(static_cast<int>(plat::kCompatLineOk), static_cast<int>(mfi->level));
    }

    // 2. Explicit CLI --no-mfi-i2c override suppresses carplay.conf mfi_i2c
    {
        FakeCompatSystemOps ops;
        plat::CompatCheckConfig cfg;
        cfg.data_dir = dir;
        cfg.config_file = conf_path;
        cfg.state_file = plat::joinPath(dir, "state");
        cfg.has_mfi_i2c_override = true;
        cfg.mfi_i2c_config.enabled = false;
        const plat::CompatReport r = plat::runCompatChecks(cfg, &ops);
        CHECK(!ops.mfi_query_called);
        const plat::CompatLine* mfi = findLine(r, "mfi");
        REQUIRE(mfi != NULL);
        CHECK_EQ(static_cast<int>(plat::kCompatLineInfo), static_cast<int>(mfi->level));
    }

    // 3. Explicit --compat-mfi-read succeeds -> @ok; fails reg read -> @warn
    {
        FakeCompatSystemOps ops;
        plat::CompatCheckConfig cfg;
        cfg.data_dir = dir;
        cfg.config_file = conf_path;
        cfg.state_file = plat::joinPath(dir, "state");
        cfg.compat_mfi_read = true;
        const plat::CompatReport r_ok = plat::runCompatChecks(cfg, &ops);
        CHECK(ops.mfi_read_requested);
        CHECK(!r_ok.hasBlockingFailure());
        CHECK_EQ(static_cast<int>(plat::kCompatLineOk),
                 static_cast<int>(findLine(r_ok, "mfi")->level));

        ops.mfi_read_ok = false;
        const plat::CompatReport r_warn = plat::runCompatChecks(cfg, &ops);
        CHECK(!r_warn.hasBlockingFailure());
        CHECK_EQ(static_cast<int>(plat::kCompatLineWarn),
                 static_cast<int>(findLine(r_warn, "mfi")->level));
    }

    // 4. Inaccessible device or failed I2C_FUNCS -> @block
    {
        FakeCompatSystemOps ops;
        ops.mfi_accessible = false;
        plat::CompatCheckConfig cfg;
        cfg.data_dir = dir;
        cfg.config_file = conf_path;
        cfg.state_file = plat::joinPath(dir, "state");
        const plat::CompatReport r_missing = plat::runCompatChecks(cfg, &ops);
        CHECK(r_missing.hasBlockingFailure());
        CHECK_EQ(static_cast<int>(plat::kCompatLineBlock),
                 static_cast<int>(findLine(r_missing, "mfi")->level));

        ops.mfi_accessible = true;
        ops.mfi_funcs_ok = false;
        const plat::CompatReport r_nofunc = plat::runCompatChecks(cfg, &ops);
        CHECK(r_nofunc.hasBlockingFailure());
        CHECK_EQ(static_cast<int>(plat::kCompatLineBlock),
                 static_cast<int>(findLine(r_nofunc, "mfi")->level));
    }

    removeTempDir(dir);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 0 && argv != NULL && argv[0] != NULL) {
        g_argv0_exe = argv[0];
    }
    return test_support::runAll("test_compat_check");
}
