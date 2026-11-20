// EntryNav2-CarPlay daemon (`carplayd`) entry point.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include <string>
#include <vector>

#include "carplay/platform/carplay_daemon.hpp"
#include "carplay/platform/compat_check.hpp"
#include "carplay/platform/file_util.hpp"
#include "carplay/platform/log.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/safe_mode.hpp"
#include "carplay/platform/service_contract.hpp"

namespace {

// Only async-signal-safe work in the handler: the daemon tick polls this flag.
volatile sig_atomic_t g_stop_requested = 0;

void onSignal(int /*sig*/) { g_stop_requested = 1; }

bool parseUint(const char* s, unsigned long max_val, unsigned long& out) {
    if (!s || !*s || *s == '-') {
        return false;
    }
    char* end = NULL;
    errno = 0;
    const unsigned long v = strtoul(s, &end, 0);
    if (errno != 0 || !end || *end != '\0' || v > max_val) {
        return false;
    }
    out = v;
    return true;
}

class StableGuardTimer : public carplay::platform::TimerHandler {
public:
    explicit StableGuardTimer(carplay::platform::CrashLoopGuard& guard) : guard_(guard) {}
    virtual void onTimer(uint32_t /*timer_id*/) {
        const int64_t now_sec = carplay::platform::monotonicMillis() / 1000;
        if (guard_.markStable(now_sec)) {
            CARPLAY_LOG_INFO("safe_mode", "carplayd stable uptime reached; crash-loop guard cleared");
        }
    }

private:
    carplay::platform::CrashLoopGuard& guard_;
};

void printUsage(const char* argv0) {
    printf(
        "Usage: %s [options]\n"
        "  --port N               AirPlay control TCP port (default: 7000)\n"
        "  --data-dir PATH        Persistent data directory (default: %s)\n"
        "  --config PATH          Config file path (default: <data-dir>/carplay.conf)\n"
        "  --runtime-dir PATH     Runtime guard directory (default: /tmp)\n"
        "  --control-name NAME    Abstract Unix control socket name (default: %s)\n"
        "  --state-file PATH      Runtime state file path (default: %s)\n"
        "  --width W              Fallback display width in pixels (default: 800)\n"
        "  --height H             Fallback display height in pixels (default: 480)\n"
        "  --no-ilm-size          Do not query LayerManager for screen dimensions\n"
        "  --no-video             Disable hardware video sink (EvoVideo)\n"
        "  --no-audio             Disable ALSA audio playback & microphone capture\n"
        "  --no-input             Disable vMOST controller & UDP 30567 touchscreen\n"
        "  --no-control           Disable abstract Unix control channel\n"
        "  --no-touch             Advertise knob-only display profile\n"
        "  --wireless             Enable Wireless CarPlay (BT ALPS/RFCOMM + Wi-Fi AP + mDNS)\n"
        "  --no-wireless          Disable Wireless CarPlay (default)\n"
        "  --wired                Enable Wired USB CarPlay (usbfs + CDC-NCM/TAP)\n"
        "  --no-wired             Disable Wired USB CarPlay (default)\n"
        "  --mfi-i2c DEV[:ADDR]   Enable I2C MFi coprocessor auth (e.g. /dev/i2c-0:0x10; default off)\n"
        "  --no-mfi-i2c           Disable I2C MFi coprocessor auth (default)\n"
        "  --compat               Run dry-run vehicle compatibility self-check and exit\n"
        "  --self-check           Alias for --compat\n"
        "  --service              Supervisor compatibility flag (default mode)\n"
        "  --version              Show version information and exit\n"
        "  --help                 Show this help message and exit\n",
        argv0,
        carplay::platform::contract::kDataDir,
        carplay::platform::contract::kControlName,
        carplay::platform::contract::kStateFile);
}

struct CliOverrides {
    bool compat_mode;
    bool has_port;
    uint16_t port;
    bool has_data_dir;
    std::string data_dir;
    bool has_config_path;
    std::string config_path;
    bool has_runtime_dir;
    std::string runtime_dir;
    bool has_control_name;
    std::string control_name;
    bool has_state_file;
    std::string state_file;
    bool has_width;
    uint32_t width;
    bool has_height;
    uint32_t height;
    bool no_ilm_size;
    bool no_video;
    bool no_audio;
    bool no_input;
    bool no_control;
    bool no_touch;
    bool has_wireless;
    bool wireless;
    bool has_wired;
    bool wired;
    bool has_mfi_i2c;
    carplay::platform::MfiI2cConfig mfi_i2c_config;

    CliOverrides()
        : compat_mode(false),
          has_port(false),
          port(7000U),
          has_data_dir(false),
          data_dir(carplay::platform::contract::kDataDir),
          has_config_path(false),
          config_path(),
          has_runtime_dir(false),
          runtime_dir("/tmp"),
          has_control_name(false),
          control_name(carplay::platform::contract::kControlName),
          has_state_file(false),
          state_file(carplay::platform::contract::kStateFile),
          has_width(false),
          width(800U),
          has_height(false),
          height(480U),
          no_ilm_size(false),
          no_video(false),
          no_audio(false),
          no_input(false),
          no_control(false),
          no_touch(false),
          has_wireless(false),
          wireless(false),
          has_wired(false),
          wired(false),
          has_mfi_i2c(false),
          mfi_i2c_config() {}
};

}  // namespace

int main(int argc, char** argv) {
    CliOverrides cli;

    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        const char* val = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            printUsage(argv[0]);
            return 0;
        } else if (strcmp(arg, "--version") == 0 || strcmp(arg, "-V") == 0) {
            printf("carplayd (EntryNav2-CarPlay) 1.0.0\n");
            return 0;
        } else if (strcmp(arg, "--compat") == 0 || strcmp(arg, "--self-check") == 0) {
            cli.compat_mode = true;
        } else if (strcmp(arg, "--service") == 0) {
            // Accepted for supervisor invocation (`carplayd --service`).
        } else if (strcmp(arg, "--port") == 0 && val != NULL) {
            unsigned long p = 0;
            if (!parseUint(val, 65535UL, p)) {
                printUsage(argv[0]);
                return 2;
            }
            cli.has_port = true;
            cli.port = static_cast<uint16_t>(p);
            ++i;
        } else if (strcmp(arg, "--data-dir") == 0 && val != NULL) {
            cli.has_data_dir = true;
            cli.data_dir = val;
            ++i;
        } else if (strcmp(arg, "--config") == 0 && val != NULL) {
            cli.has_config_path = true;
            cli.config_path = val;
            ++i;
        } else if (strcmp(arg, "--runtime-dir") == 0 && val != NULL) {
            cli.has_runtime_dir = true;
            cli.runtime_dir = val;
            ++i;
        } else if (strcmp(arg, "--control-name") == 0 && val != NULL) {
            cli.has_control_name = true;
            cli.control_name = val;
            ++i;
        } else if (strcmp(arg, "--state-file") == 0 && val != NULL) {
            cli.has_state_file = true;
            cli.state_file = val;
            ++i;
        } else if (strcmp(arg, "--width") == 0 && val != NULL) {
            unsigned long w = 0;
            if (!parseUint(val, 2560UL, w) || w < 320UL) {
                printUsage(argv[0]);
                return 2;
            }
            cli.has_width = true;
            cli.width = static_cast<uint32_t>(w);
            ++i;
        } else if (strcmp(arg, "--height") == 0 && val != NULL) {
            unsigned long h = 0;
            if (!parseUint(val, 1600UL, h) || h < 240UL) {
                printUsage(argv[0]);
                return 2;
            }
            cli.has_height = true;
            cli.height = static_cast<uint32_t>(h);
            ++i;
        } else if (strcmp(arg, "--no-ilm-size") == 0) {
            cli.no_ilm_size = true;
        } else if (strcmp(arg, "--no-video") == 0) {
            cli.no_video = true;
        } else if (strcmp(arg, "--no-audio") == 0) {
            cli.no_audio = true;
        } else if (strcmp(arg, "--no-input") == 0) {
            cli.no_input = true;
        } else if (strcmp(arg, "--no-control") == 0) {
            cli.no_control = true;
        } else if (strcmp(arg, "--no-touch") == 0) {
            cli.no_touch = true;
        } else if (strcmp(arg, "--wireless") == 0) {
            cli.has_wireless = true;
            cli.wireless = true;
        } else if (strcmp(arg, "--no-wireless") == 0) {
            cli.has_wireless = true;
            cli.wireless = false;
        } else if (strcmp(arg, "--wired") == 0) {
            cli.has_wired = true;
            cli.wired = true;
        } else if (strcmp(arg, "--no-wired") == 0) {
            cli.has_wired = true;
            cli.wired = false;
        } else if (strncmp(arg, "--mfi-i2c=", 10) == 0 || (strcmp(arg, "--mfi-i2c") == 0 && val != NULL)) {
            const char* spec = (strncmp(arg, "--mfi-i2c=", 10) == 0) ? (arg + 10) : val;
            std::string mfi_err;
            if (!carplay::platform::parseMfiI2cSpec(spec, cli.mfi_i2c_config, &mfi_err)) {
                fprintf(stderr, "carplayd: invalid --mfi-i2c: %s\n", mfi_err.c_str());
                return 2;
            }
            cli.has_mfi_i2c = true;
            if (strncmp(arg, "--mfi-i2c=", 10) != 0) {
                ++i;
            }
        } else if (strcmp(arg, "--no-mfi-i2c") == 0) {
            cli.has_mfi_i2c = true;
            cli.mfi_i2c_config = carplay::platform::MfiI2cConfig();
            cli.mfi_i2c_config.enabled = false;
        } else {
            fprintf(stderr, "carplayd: unknown option: %s\n", arg);
            printUsage(argv[0]);
            return 2;
        }
    }

#ifndef _WIN32
    setenv("XDG_RUNTIME_DIR", "/run/system/0", 0);
    signal(SIGPIPE, SIG_IGN);
#endif

    const std::string resolved_config =
        cli.has_config_path ? cli.config_path
                            : carplay::platform::joinPath(cli.data_dir, "carplay.conf");

    if (cli.compat_mode) {
        carplay::platform::CompatCheckConfig compat_cfg;
        compat_cfg.data_dir = cli.data_dir;
        compat_cfg.state_file = cli.state_file;
        compat_cfg.config_file = resolved_config;
        compat_cfg.check_ilm = !cli.no_ilm_size;
        if (cli.has_wired && cli.wired && (!cli.has_wireless || !cli.wireless)) {
            compat_cfg.usb_mode = true;
        }
        const carplay::platform::CompatReport report =
            carplay::platform::runCompatChecks(compat_cfg);
        const std::string text = report.format();
        fwrite(text.data(), 1U, text.size(), stdout);
        fflush(stdout);
        return report.exitCode();
    }

    // 1. Load persistent configuration file (defaults: wireless=false, wired=false).
    carplay::platform::DaemonFileConfig file_cfg;
    std::string cfg_err;
    if (!carplay::platform::loadDaemonConfigFile(resolved_config, file_cfg, cfg_err)) {
        CARPLAY_LOG_ERROR("safe_mode", "carplayd: invalid config %s", cfg_err.c_str());
        fprintf(stderr, "carplayd: invalid config: %s\n", cfg_err.c_str());
        return 78;
    }

    // 2. Kill switch check (refuse immediately before touching hardware or crash-loop guard).
    if (!file_cfg.enabled) {
        CARPLAY_LOG_ERROR("safe_mode", "carplayd: disabled via enabled=0 in %s; exiting immediately",
                          resolved_config.c_str());
        fprintf(stderr, "carplayd: disabled via enabled=0 in %s\n", resolved_config.c_str());
        return 78;
    }
    {
        std::vector<std::string> ks_paths;
        ks_paths.push_back(carplay::platform::joinPath(cli.data_dir, "killswitch"));
        ks_paths.push_back(carplay::platform::joinPath(cli.data_dir, "app.disable"));
        if (!cli.has_data_dir) {
            ks_paths.push_back(carplay::platform::contract::kKillSwitch);
            ks_paths.push_back(carplay::platform::contract::kAppDisable);
        }
        std::string matched_ks;
        if (carplay::platform::checkKillSwitch(ks_paths, matched_ks)) {
            CARPLAY_LOG_ERROR("safe_mode",
                              "carplayd: kill switch file present (%s); exiting immediately",
                              matched_ks.c_str());
            fprintf(stderr, "carplayd: kill switch present (%s); exiting immediately\n",
                    matched_ks.c_str());
            return 78;
        }
    }

    // 3. Crash-loop guard (disables until reboot after N rapid starts within window).
    carplay::platform::CrashLoopGuardConfig guard_cfg;
    if (cli.has_runtime_dir) {
        guard_cfg.guard_file = carplay::platform::joinPath(cli.runtime_dir, "entry-carplay-crash-guard");
        guard_cfg.disabled_file =
            carplay::platform::joinPath(cli.runtime_dir, "entry-carplay-disabled-until-reboot");
    }
    guard_cfg.max_rapid_restarts = file_cfg.crash_guard_max;
    guard_cfg.window_sec = file_cfg.crash_guard_window_sec;
    guard_cfg.stable_sec = file_cfg.crash_guard_stable_sec;

    carplay::platform::CrashLoopGuard crash_guard(guard_cfg);
    {
        std::string guard_reason;
        const int64_t now_mono_sec = carplay::platform::monotonicMillis() / 1000;
        if (!crash_guard.enterStartup(now_mono_sec, guard_reason)) {
            CARPLAY_LOG_ERROR("safe_mode", "carplayd: %s", guard_reason.c_str());
            fprintf(stderr, "carplayd: %s\n", guard_reason.c_str());
            return 75;
        }
    }

    // 4. Assemble daemon config: safe defaults -> carplay.conf -> explicit CLI overrides.
    carplay::platform::CarPlayDaemonConfig cfg;
    carplay::platform::applyDaemonFileConfig(file_cfg, cfg);

    if (cli.has_data_dir) {
        cfg.data_dir = cli.data_dir;
    }
    if (cli.has_control_name) {
        cfg.control_name = cli.control_name;
    }
    if (cli.has_state_file) {
        cfg.state_file = cli.state_file;
    }
    if (cli.has_port) {
        cfg.control_port = cli.port;
    }
    if (cli.has_width) {
        cfg.fallback_width = cli.width;
    }
    if (cli.has_height) {
        cfg.fallback_height = cli.height;
    }
    if (cli.no_ilm_size) {
        cfg.query_display_from_ilm = false;
    }
    if (cli.no_video) {
        cfg.enable_video = false;
    }
    if (cli.no_audio) {
        cfg.enable_audio = false;
    }
    if (cli.no_input) {
        cfg.enable_input = false;
    }
    if (cli.no_control) {
        cfg.enable_control = false;
    }
    if (cli.no_touch) {
        cfg.touch_enabled = false;
    }
    if (cli.has_wireless) {
        cfg.enable_wireless = cli.wireless;
        cfg.connectivity_config.enable_wireless = cli.wireless;
    }
    if (cli.has_wired) {
        cfg.enable_wired = cli.wired;
        cfg.connectivity_config.enable_wired = cli.wired;
    }
    if (cli.has_mfi_i2c) {
        cfg.mfi_i2c_config = cli.mfi_i2c_config;
    }

    signal(SIGINT, &onSignal);
    signal(SIGTERM, &onSignal);

    cfg.stop_flag = &g_stop_requested;
    if (cfg.tick_interval_ms <= 0) {
        cfg.tick_interval_ms = 100;  // the tick is what observes stop_flag
    }

    carplay::platform::CarPlayDaemon daemon(cfg);
    if (!daemon.start()) {
        return 1;
    }

    StableGuardTimer stable_timer(crash_guard);
    uint32_t stable_tid = carplay::platform::Reactor::kNoTimer;
    if (guard_cfg.stable_sec > 0 && guard_cfg.max_rapid_restarts > 0) {
        stable_tid = daemon.reactor().startTimer(guard_cfg.stable_sec * 1000, 0, &stable_timer);
    }

    daemon.reactor().run();

    if (stable_tid != carplay::platform::Reactor::kNoTimer) {
        daemon.reactor().cancelTimer(stable_tid);
    }
    daemon.stop();
    crash_guard.clearOnCleanExit();
    return 0;
}
