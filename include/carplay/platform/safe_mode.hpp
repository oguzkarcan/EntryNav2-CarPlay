#ifndef CARPLAY_PLATFORM_SAFE_MODE_HPP
#define CARPLAY_PLATFORM_SAFE_MODE_HPP

// Safe-mode startup guards and persistent configuration for `carplayd`:
//   * `DaemonFileConfig` (`carplay.conf`): key=value settings defaulting wireless & wired
//     transports to DISABLED (`false`) and `detach_usbfs_driver` to `false`.
//   * Kill switch check (`killswitch` / `app.disable`): refuses startup immediately with a
//     clear diagnostic when present.
//   * `CrashLoopGuard`: records rapid startup timestamps in `/tmp` (cleared automatically on
//     reboot) and disables the daemon until reboot after N rapid crashes within a time window.

#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/platform/carplay_daemon.hpp"
#include "carplay/platform/ddp_handoff.hpp"
#include "carplay/platform/service_contract.hpp"

namespace carplay {
namespace platform {

struct DaemonFileConfig {
    bool loaded_from_file;
    bool enabled;
    bool wireless;
    bool wired;
    bool detach_usbfs_driver;

    bool has_control_port;
    uint16_t control_port;

    bool has_width;
    uint32_t width;
    bool has_height;
    uint32_t height;

    bool enable_video;
    bool enable_audio;
    bool enable_input;
    bool enable_control;
    bool touch_enabled;

    std::string usb_port;
    MfiI2cConfig mfi_i2c_config;
    bool ddp_handoff;
    DdpRestoreMode ddp_restore;
    int crash_guard_max;
    int64_t crash_guard_window_sec;
    int64_t crash_guard_stable_sec;

    DaemonFileConfig()
        : loaded_from_file(false),
          enabled(true),
          wireless(false),
          wired(false),
          detach_usbfs_driver(false),
          has_control_port(false),
          control_port(7000U),
          has_width(false),
          width(800U),
          has_height(false),
          height(480U),
          enable_video(true),
          enable_audio(true),
          enable_input(true),
          enable_control(true),
          touch_enabled(true),
          usb_port(),
          mfi_i2c_config(),
          ddp_handoff(false),
          ddp_restore(kDdpRestoreRebootPrompt),
          crash_guard_max(3),
          crash_guard_window_sec(120),
          crash_guard_stable_sec(120) {}
};

/// Parses a `key=value` configuration file (`#` comments, whitespace trimmed).
/// If the file does not exist, returns `true` leaving `out` at safe defaults
/// (`loaded_from_file = false`). Returns `false` on read/syntax/range errors.
bool loadDaemonConfigFile(const std::string& path,
                          DaemonFileConfig& out,
                          std::string& error_out);

/// Applies `DaemonFileConfig` fields onto `CarPlayDaemonConfig` (CLI flags should be
/// re-applied or parsed afterwards so explicit command-line overrides win).
void applyDaemonFileConfig(const DaemonFileConfig& file_cfg, CarPlayDaemonConfig& daemon_cfg);

/// Returns true if any kill-switch path exists on disk (`matched_path_out` receives it).
bool checkKillSwitch(const std::vector<std::string>& paths, std::string& matched_path_out);

struct CrashLoopGuardConfig {
    std::string guard_file;
    std::string disabled_file;
    int max_rapid_restarts;   // <= 0 disables the guard
    int64_t window_sec;       // sliding window for counting rapid restarts
    int64_t stable_sec;       // uptime after which rapid-restart history clears

    CrashLoopGuardConfig()
        : guard_file(contract::kCrashGuardFile),
          disabled_file(contract::kCrashDisabledFile),
          max_rapid_restarts(3),
          window_sec(120),
          stable_sec(120) {}
};

class CrashLoopGuard {
public:
    explicit CrashLoopGuard(const CrashLoopGuardConfig& config = CrashLoopGuardConfig());

    /// Called at daemon startup with monotonic seconds (`monotonicMillis() / 1000`).
    /// Returns false (with explanation in `reason_out`) if already disabled until reboot
    /// or if this start trips `max_rapid_restarts` inside `window_sec`.
    bool enterStartup(int64_t now_mono_sec, std::string& reason_out);

    /// Called once uptime >= `stable_sec`: clears rapid-restart history.
    bool markStable(int64_t now_mono_sec);

    /// Called on clean daemon shutdown (`SIGTERM`/`SIGINT`/`quit`/STOP): clears history.
    bool clearOnCleanExit();

    const CrashLoopGuardConfig& config() const { return config_; }

private:
    CrashLoopGuardConfig config_;
    int64_t start_sec_;
    bool stable_marked_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_SAFE_MODE_HPP
