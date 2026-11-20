#include "test_support.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "carplay/platform/evo_process.hpp"
#include "carplay/platform/file_util.hpp"
#include "carplay/platform/safe_mode.hpp"

namespace {

namespace plat = carplay::platform;

std::string g_argv0_exe;

std::string makeTempDir(const char* prefix) {
#ifndef _WIN32
    char tmpl[128];
    snprintf(tmpl, sizeof(tmpl), "/tmp/%s_XXXXXX", prefix ? prefix : "safe_mode_test");
    char* d = mkdtemp(tmpl);
    return d ? std::string(d) : std::string("/tmp/safe_mode_fallback");
#else
    (void)prefix;
    return "build/safe_mode_tmp";
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

std::string siblingDaemonPath() {
    if (!g_argv0_exe.empty()) {
        const size_t slash = g_argv0_exe.find_last_of('/');
        if (slash != std::string::npos) {
            return g_argv0_exe.substr(0, slash + 1U) + "carplayd";
        }
    }
    return "build/host/carplayd";
}

TEST_CASE(safeModeConfigMissingUsesDisabledDefaults) {
    const std::string dir = makeTempDir("cfg_missing");
    plat::DaemonFileConfig cfg;
    std::string err;
    CHECK(plat::loadDaemonConfigFile(plat::joinPath(dir, "carplay.conf"), cfg, err));
    CHECK(!cfg.loaded_from_file);
    CHECK(cfg.enabled);
    CHECK(!cfg.wireless);
    CHECK(!cfg.wired);
    CHECK(!cfg.detach_usbfs_driver);

    plat::CarPlayDaemonConfig dcfg;
    dcfg.enable_wireless = true;
    dcfg.enable_wired = true;
    plat::applyDaemonFileConfig(cfg, dcfg);
    CHECK(!dcfg.enable_wireless);
    CHECK(!dcfg.enable_wired);
    CHECK(!dcfg.connectivity_config.enable_wireless);
    CHECK(!dcfg.connectivity_config.enable_wired);
    CHECK(!dcfg.connectivity_config.usb_host_config.detach_usbfs_driver);
    CHECK(!dcfg.mfi_i2c_config.enabled);
    removeTempDir(dir);
}

TEST_CASE(safeModeConfigValidAndInvalidParsing) {
    const std::string dir = makeTempDir("cfg_parse");
    const std::string path = plat::joinPath(dir, "carplay.conf");

    const std::string valid =
        "# comment\n"
        "enabled = true\n"
        "wireless = 0 # disabled\n"
        "wired = 1\n"
        "detach_usbfs_driver = false\n"
        "port = 7001\n"
        "width = 1280\n"
        "height = 480\n"
        "usb_port = 3-1\n"
        "mfi_i2c = /dev/i2c-0:0x10\n"
        "crash_guard_max = 4\n"
        "crash_guard_window_sec = 90\n"
        "crash_guard_stable_sec = 60\n";
    REQUIRE(plat::writeFileAtomic(
        path, reinterpret_cast<const uint8_t*>(valid.data()), valid.size()));

    plat::DaemonFileConfig cfg;
    std::string err;
    CHECK(plat::loadDaemonConfigFile(path, cfg, err));
    CHECK(cfg.loaded_from_file);
    CHECK(cfg.enabled);
    CHECK(!cfg.wireless);
    CHECK(cfg.wired);
    CHECK(!cfg.detach_usbfs_driver);
    CHECK(cfg.has_control_port);
    CHECK_EQ(7001U, static_cast<unsigned>(cfg.control_port));
    CHECK_EQ(1280U, cfg.width);
    CHECK_EQ(480U, cfg.height);
    CHECK_EQ(std::string("3-1"), cfg.usb_port);
    CHECK(cfg.mfi_i2c_config.enabled);
    CHECK_EQ(std::string("/dev/i2c-0"), cfg.mfi_i2c_config.device_path);
    CHECK_EQ(0x10U, static_cast<unsigned>(cfg.mfi_i2c_config.address7));
    CHECK_EQ(4, cfg.crash_guard_max);
    CHECK_EQ(90, static_cast<int>(cfg.crash_guard_window_sec));
    CHECK_EQ(60, static_cast<int>(cfg.crash_guard_stable_sec));

    plat::CarPlayDaemonConfig dcfg;
    plat::applyDaemonFileConfig(cfg, dcfg);
    CHECK(!dcfg.enable_wireless);
    CHECK(dcfg.enable_wired);
    CHECK_EQ(7001U, static_cast<unsigned>(dcfg.control_port));
    CHECK_EQ(std::string("3-1"), dcfg.connectivity_config.usb_host_config.usb_port_filter);
    CHECK(dcfg.mfi_i2c_config.enabled);
    CHECK_EQ(std::string("/dev/i2c-0"), dcfg.mfi_i2c_config.device_path);
    CHECK_EQ(0x10U, static_cast<unsigned>(dcfg.mfi_i2c_config.address7));

    // Empty mfi_i2c= explicitly leaves MFi disabled
    const std::string empty_mfi = "mfi_i2c=\n";
    REQUIRE(plat::writeFileAtomic(
        path, reinterpret_cast<const uint8_t*>(empty_mfi.data()), empty_mfi.size()));
    CHECK(plat::loadDaemonConfigFile(path, cfg, err));
    CHECK(!cfg.mfi_i2c_config.enabled);

    const char* bad_cases[] = {
        "wireless=maybe\n",
        "port=99999\n",
        "usb_port=../evil\n",
        "mfi_i2c=/dev/i2c-0:0x99\n",
        "mfi_i2c=/dev/i2c-0:\n",
        "unknown_key=1\n",
        "no_equals_sign\n"
    };
    for (size_t i = 0; i < sizeof(bad_cases) / sizeof(bad_cases[0]); ++i) {
        const std::string bad(bad_cases[i]);
        REQUIRE(plat::writeFileAtomic(
            path, reinterpret_cast<const uint8_t*>(bad.data()), bad.size()));
        CHECK(!plat::loadDaemonConfigFile(path, cfg, err));
        CHECK(!err.empty());
    }

    removeTempDir(dir);
}

TEST_CASE(safeModeKillSwitchCheck) {
    const std::string dir = makeTempDir("killswitch");
    const std::string ks = plat::joinPath(dir, "killswitch");
    const std::string dis = plat::joinPath(dir, "app.disable");
    std::vector<std::string> paths;
    paths.push_back(ks);
    paths.push_back(dis);

    std::string matched;
    CHECK(!plat::checkKillSwitch(paths, matched));
    CHECK(matched.empty());

    REQUIRE(plat::writeFileAtomic(ks, NULL, 0U));
    CHECK(plat::checkKillSwitch(paths, matched));
    CHECK_EQ(ks, matched);

    plat::removeFile(ks);
    REQUIRE(plat::writeFileAtomic(dis, NULL, 0U));
    CHECK(plat::checkKillSwitch(paths, matched));
    CHECK_EQ(dis, matched);

    removeTempDir(dir);
}

TEST_CASE(safeModeCrashLoopGuardLifecycle) {
    const std::string dir = makeTempDir("crash_guard");
    plat::CrashLoopGuardConfig gcfg;
    gcfg.guard_file = plat::joinPath(dir, "crash-guard");
    gcfg.disabled_file = plat::joinPath(dir, "disabled-until-reboot");
    gcfg.max_rapid_restarts = 3;
    gcfg.window_sec = 120;
    gcfg.stable_sec = 120;

    std::string reason;
    {
        plat::CrashLoopGuard g(gcfg);
        CHECK(g.enterStartup(100, reason));
        CHECK(g.enterStartup(110, reason));
        CHECK(g.enterStartup(120, reason));
        // 4th rapid start within 120s trips guard & creates disabled-until-reboot marker
        CHECK(!g.enterStartup(130, reason));
        CHECK(reason.find("disabled until reboot") != std::string::npos);
        CHECK(plat::pathExists(gcfg.disabled_file));
    }

    // Subsequent start even later in same boot remains disabled
    {
        plat::CrashLoopGuard g(gcfg);
        CHECK(!g.enterStartup(500, reason));
        CHECK(reason.find("disabled until reboot") != std::string::npos);
    }

    // Simulated reboot (monotonic clock resets < recorded timestamp) clears stale guard
    {
        plat::CrashLoopGuard g(gcfg);
        CHECK(g.enterStartup(5, reason));
        CHECK(!plat::pathExists(gcfg.disabled_file));
        CHECK(!g.markStable(50));
        CHECK(g.markStable(130));
        CHECK(!plat::pathExists(gcfg.guard_file));
    }

    // Clean exit clears rapid-restart history so N clean restarts never trip
    {
        plat::CrashLoopGuard g(gcfg);
        for (int i = 0; i < 6; ++i) {
            CHECK(g.enterStartup(200 + i, reason));
            CHECK(g.clearOnCleanExit());
        }
    }

    removeTempDir(dir);
}

TEST_CASE(safeModeDaemonBinaryKillSwitchAndCrashGuard) {
#ifdef _WIN32
    return;
#else
    const std::string daemon_bin = siblingDaemonPath();
    const std::string dir = makeTempDir("daemon_safe");
    const std::string data_dir = plat::joinPath(dir, "data");
    const std::string rt_dir = plat::joinPath(dir, "rt");
    REQUIRE(plat::ensurePrivateDirectory(data_dir));
    REQUIRE(plat::ensurePrivateDirectory(rt_dir));

    // 1. Kill switch file inhibits carplayd immediately with exit code 78
    const std::string ks_file = plat::joinPath(data_dir, "killswitch");
    REQUIRE(plat::writeFileAtomic(ks_file, NULL, 0U));
    {
        std::vector<std::string> args;
        args.push_back("--data-dir");
        args.push_back(data_dir);
        args.push_back("--runtime-dir");
        args.push_back(rt_dir);
        args.push_back("--no-control");
        std::string out;
        plat::CommandReport rep;
        CHECK(!plat::runCommand(daemon_bin, args, out, 5000, &rep));
        CHECK_EQ(78, rep.exit_code);
        CHECK(rep.text.find("kill switch") != std::string::npos);
    }
    plat::removeFile(ks_file);

    // 2. Repeated rapid startup failures (invalid state-file under /dev/null -> bind/start or
    //    unusable data dir) trip crash-loop guard after 3 failures (4th exits 75 immediately).
    const std::string bad_data = "/dev/null/impossible_carplay_data";
    const std::string bad_conf = plat::joinPath(dir, "carplay.conf");
    const std::string conf_txt = "crash_guard_max=2\ncrash_guard_window_sec=120\n";
    REQUIRE(plat::writeFileAtomic(
        bad_conf, reinterpret_cast<const uint8_t*>(conf_txt.data()), conf_txt.size()));

    std::vector<std::string> fail_args;
    fail_args.push_back("--data-dir");
    fail_args.push_back(bad_data);
    fail_args.push_back("--config");
    fail_args.push_back(bad_conf);
    fail_args.push_back("--runtime-dir");
    fail_args.push_back(rt_dir);
    fail_args.push_back("--no-video");
    fail_args.push_back("--no-audio");
    fail_args.push_back("--no-input");
    fail_args.push_back("--no-control");
    fail_args.push_back("--no-ilm-size");

    for (int attempt = 0; attempt < 2; ++attempt) {
        std::string out;
        plat::CommandReport rep;
        CHECK(!plat::runCommand(daemon_bin, fail_args, out, 5000, &rep));
        CHECK_EQ(1, rep.exit_code);
    }
    {
        std::string out;
        plat::CommandReport rep;
        CHECK(!plat::runCommand(daemon_bin, fail_args, out, 5000, &rep));
        CHECK_EQ(75, rep.exit_code);
        CHECK(rep.text.find("crash-loop guard") != std::string::npos);
    }

    removeTempDir(dir);
#endif
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 0 && argv != NULL && argv[0] != NULL) {
        g_argv0_exe = argv[0];
    }
    return test_support::runAll("test_safe_mode");
}
