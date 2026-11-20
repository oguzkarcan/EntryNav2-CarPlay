#include "carplay/platform/safe_mode.hpp"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sstream>

#include "carplay/platform/file_util.hpp"
#include "carplay/platform/usb_host.hpp"

namespace carplay {
namespace platform {

namespace {

static const size_t kMaxConfigFileBytes = 65536U;
static const size_t kMaxGuardFileBytes = 16384U;

std::string trimAscii(const std::string& s) {
    size_t b = 0U;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) {
        ++b;
    }
    size_t e = s.size();
    while (e > b && (s[e - 1U] == ' ' || s[e - 1U] == '\t' || s[e - 1U] == '\r' || s[e - 1U] == '\n')) {
        --e;
    }
    return s.substr(b, e - b);
}

bool parseBoolValue(const std::string& v, bool& out) {
    if (v == "1" || v == "true" || v == "TRUE" || v == "yes" || v == "YES" || v == "on" || v == "ON") {
        out = true;
        return true;
    }
    if (v == "0" || v == "false" || v == "FALSE" || v == "no" || v == "NO" || v == "off" || v == "OFF") {
        out = false;
        return true;
    }
    return false;
}

bool parseUintRange(const std::string& v, unsigned long min_val, unsigned long max_val, unsigned long& out) {
    if (v.empty() || v[0] == '-') {
        return false;
    }
    char* end = NULL;
    errno = 0;
    const unsigned long val = strtoul(v.c_str(), &end, 10);
    if (errno != 0 || end == NULL || *end != '\0' || val < min_val || val > max_val) {
        return false;
    }
    out = val;
    return true;
}

}  // namespace

bool loadDaemonConfigFile(const std::string& path,
                          DaemonFileConfig& out,
                          std::string& error_out) {
    out = DaemonFileConfig();
    error_out.clear();
    if (path.empty()) {
        return true;
    }

    std::vector<uint8_t> bytes;
    const FileReadResult rr = readFileBounded(path, kMaxConfigFileBytes, bytes);
    if (rr == kFileMissing) {
        return true;
    }
    if (rr == kFileTooLarge) {
        error_out = path + " exceeds max config size";
        return false;
    }
    if (rr != kFileReadOk) {
        error_out = path + " unreadable";
        return false;
    }

    out.loaded_from_file = true;
    const std::string content(bytes.empty() ? std::string()
                                            : std::string(reinterpret_cast<const char*>(&bytes[0]), bytes.size()));
    std::istringstream iss(content);
    std::string raw_line;
    unsigned lineno = 0U;
    while (std::getline(iss, raw_line)) {
        ++lineno;
        // Strip inline comments only if preceded by start of line or whitespace.
        std::string line = raw_line;
        const size_t hash = line.find('#');
        if (hash != std::string::npos) {
            line.erase(hash);
        }
        line = trimAscii(line);
        if (line.empty()) {
            continue;
        }
        const size_t eq = line.find('=');
        if (eq == std::string::npos) {
            std::ostringstream err;
            err << path << ":" << lineno << ": expected key=value";
            error_out = err.str();
            return false;
        }
        const std::string key = trimAscii(line.substr(0, eq));
        const std::string val = trimAscii(line.substr(eq + 1U));
        if (key.empty()) {
            std::ostringstream err;
            err << path << ":" << lineno << ": empty key";
            error_out = err.str();
            return false;
        }

        bool b = false;
        unsigned long u = 0UL;
        if (key == "enabled") {
            if (!parseBoolValue(val, b)) {
                error_out = path + ": invalid boolean for enabled";
                return false;
            }
            out.enabled = b;
        } else if (key == "wireless") {
            if (!parseBoolValue(val, b)) {
                error_out = path + ": invalid boolean for wireless";
                return false;
            }
            out.wireless = b;
        } else if (key == "wired") {
            if (!parseBoolValue(val, b)) {
                error_out = path + ": invalid boolean for wired";
                return false;
            }
            out.wired = b;
        } else if (key == "detach_usbfs_driver") {
            if (!parseBoolValue(val, b)) {
                error_out = path + ": invalid boolean for detach_usbfs_driver";
                return false;
            }
            out.detach_usbfs_driver = b;
        } else if (key == "port") {
            if (!parseUintRange(val, 1UL, 65535UL, u)) {
                error_out = path + ": invalid port";
                return false;
            }
            out.has_control_port = true;
            out.control_port = static_cast<uint16_t>(u);
        } else if (key == "width") {
            if (!parseUintRange(val, 320UL, 2560UL, u)) {
                error_out = path + ": invalid width";
                return false;
            }
            out.has_width = true;
            out.width = static_cast<uint32_t>(u);
        } else if (key == "height") {
            if (!parseUintRange(val, 240UL, 1600UL, u)) {
                error_out = path + ": invalid height";
                return false;
            }
            out.has_height = true;
            out.height = static_cast<uint32_t>(u);
        } else if (key == "video") {
            if (!parseBoolValue(val, b)) {
                error_out = path + ": invalid boolean for video";
                return false;
            }
            out.enable_video = b;
        } else if (key == "audio") {
            if (!parseBoolValue(val, b)) {
                error_out = path + ": invalid boolean for audio";
                return false;
            }
            out.enable_audio = b;
        } else if (key == "input") {
            if (!parseBoolValue(val, b)) {
                error_out = path + ": invalid boolean for input";
                return false;
            }
            out.enable_input = b;
        } else if (key == "control") {
            if (!parseBoolValue(val, b)) {
                error_out = path + ": invalid boolean for control";
                return false;
            }
            out.enable_control = b;
        } else if (key == "touch") {
            if (!parseBoolValue(val, b)) {
                error_out = path + ": invalid boolean for touch";
                return false;
            }
            out.touch_enabled = b;
        } else if (key == "usb_port") {
            if (!val.empty() && !isValidUsbPortName(val)) {
                error_out = path + ": invalid usb_port (" + val + ")";
                return false;
            }
            out.usb_port = val;
        } else if (key == "crash_guard_max") {
            if (!parseUintRange(val, 0UL, 20UL, u)) {
                error_out = path + ": invalid crash_guard_max";
                return false;
            }
            out.crash_guard_max = static_cast<int>(u);
        } else if (key == "crash_guard_window_sec") {
            if (!parseUintRange(val, 1UL, 86400UL, u)) {
                error_out = path + ": invalid crash_guard_window_sec";
                return false;
            }
            out.crash_guard_window_sec = static_cast<int64_t>(u);
        } else if (key == "crash_guard_stable_sec") {
            if (!parseUintRange(val, 1UL, 86400UL, u)) {
                error_out = path + ": invalid crash_guard_stable_sec";
                return false;
            }
            out.crash_guard_stable_sec = static_cast<int64_t>(u);
        } else {
            std::ostringstream err;
            err << path << ":" << lineno << ": unknown config key '" << key << "'";
            error_out = err.str();
            return false;
        }
    }

    return true;
}

void applyDaemonFileConfig(const DaemonFileConfig& file_cfg, CarPlayDaemonConfig& daemon_cfg) {
    daemon_cfg.enable_wireless = file_cfg.wireless;
    daemon_cfg.connectivity_config.enable_wireless = file_cfg.wireless;
    daemon_cfg.enable_wired = file_cfg.wired;
    daemon_cfg.connectivity_config.enable_wired = file_cfg.wired;
    daemon_cfg.connectivity_config.usb_host_config.detach_usbfs_driver = file_cfg.detach_usbfs_driver;
    daemon_cfg.connectivity_config.usb_bridge_config.detach_usbfs_driver = file_cfg.detach_usbfs_driver;
    if (file_cfg.has_control_port) {
        daemon_cfg.control_port = file_cfg.control_port;
    }
    if (file_cfg.has_width) {
        daemon_cfg.fallback_width = file_cfg.width;
    }
    if (file_cfg.has_height) {
        daemon_cfg.fallback_height = file_cfg.height;
    }
    daemon_cfg.enable_video = file_cfg.enable_video;
    daemon_cfg.enable_audio = file_cfg.enable_audio;
    daemon_cfg.enable_input = file_cfg.enable_input;
    daemon_cfg.enable_control = file_cfg.enable_control;
    daemon_cfg.touch_enabled = file_cfg.touch_enabled;
    if (!file_cfg.usb_port.empty()) {
        daemon_cfg.connectivity_config.usb_host_config.usb_port_filter = file_cfg.usb_port;
    }
}

bool checkKillSwitch(const std::vector<std::string>& paths, std::string& matched_path_out) {
    matched_path_out.clear();
    for (size_t i = 0; i < paths.size(); ++i) {
        if (!paths[i].empty() && pathExists(paths[i])) {
            matched_path_out = paths[i];
            return true;
        }
    }
    return false;
}

CrashLoopGuard::CrashLoopGuard(const CrashLoopGuardConfig& config)
    : config_(config),
      start_sec_(0),
      stable_marked_(false) {}

bool CrashLoopGuard::enterStartup(int64_t now_mono_sec, std::string& reason_out) {
    reason_out.clear();
    start_sec_ = now_mono_sec;
    stable_marked_ = false;

    if (config_.max_rapid_restarts <= 0 || config_.guard_file.empty()) {
        return true;
    }

    // Check existing disabled-until-reboot marker.
    if (!config_.disabled_file.empty() && pathExists(config_.disabled_file)) {
        std::vector<uint8_t> raw;
        bool stale_reboot = false;
        if (readFileBounded(config_.disabled_file, 1024U, raw) == kFileReadOk && !raw.empty()) {
            const std::string text(reinterpret_cast<const char*>(&raw[0]), raw.size());
            char* end = NULL;
            const long long recorded = strtoll(text.c_str(), &end, 10);
            if (end != text.c_str() && recorded > now_mono_sec) {
                // Monotonic time went backwards -> new boot (when file survived on non-tmpfs).
                stale_reboot = true;
            }
        }
        if (stale_reboot) {
            removeFile(config_.disabled_file);
            removeFile(config_.guard_file);
        } else {
            reason_out = "crash-loop guard active (disabled until reboot): remove " +
                         config_.disabled_file + " or reboot";
            return false;
        }
    }

    std::vector<int64_t> stamps;
    std::vector<uint8_t> raw;
    if (readFileBounded(config_.guard_file, kMaxGuardFileBytes, raw) == kFileReadOk && !raw.empty()) {
        const std::string content(reinterpret_cast<const char*>(&raw[0]), raw.size());
        std::istringstream iss(content);
        std::string line;
        while (std::getline(iss, line)) {
            char* end = NULL;
            const long long v = strtoll(line.c_str(), &end, 10);
            if (end != line.c_str() && v >= 0 && v <= now_mono_sec &&
                (now_mono_sec - v) < config_.window_sec) {
                stamps.push_back(static_cast<int64_t>(v));
            }
        }
    }

    stamps.push_back(now_mono_sec);
    std::ostringstream oss;
    for (size_t i = 0; i < stamps.size(); ++i) {
        oss << static_cast<long long>(stamps[i]) << "\n";
    }
    const std::string out = oss.str();
    writeFileAtomic(config_.guard_file, reinterpret_cast<const uint8_t*>(out.data()), out.size());

    if (static_cast<int>(stamps.size()) > config_.max_rapid_restarts) {
        if (!config_.disabled_file.empty()) {
            std::ostringstream dis;
            dis << static_cast<long long>(now_mono_sec)
                << "\ncrash-loop guard tripped (" << stamps.size()
                << " starts in " << static_cast<long long>(config_.window_sec) << "s)\n";
            const std::string dis_str = dis.str();
            writeFileAtomic(config_.disabled_file,
                            reinterpret_cast<const uint8_t*>(dis_str.data()),
                            dis_str.size());
        }
        std::ostringstream msg;
        msg << "crash-loop guard tripped after " << stamps.size()
            << " rapid starts within " << static_cast<long long>(config_.window_sec)
            << "s; disabled until reboot";
        reason_out = msg.str();
        return false;
    }

    return true;
}

bool CrashLoopGuard::markStable(int64_t now_mono_sec) {
    if (stable_marked_ || config_.guard_file.empty()) {
        return false;
    }
    if (now_mono_sec - start_sec_ < config_.stable_sec) {
        return false;
    }
    stable_marked_ = true;
    removeFile(config_.guard_file);
    return true;
}

bool CrashLoopGuard::clearOnCleanExit() {
    if (config_.guard_file.empty()) {
        return true;
    }
    return removeFile(config_.guard_file);
}

}  // namespace platform
}  // namespace carplay
