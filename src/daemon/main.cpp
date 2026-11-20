// EntryNav2-CarPlay daemon (`carplayd`) entry point.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "carplay/platform/carplay_daemon.hpp"
#include "carplay/platform/log.hpp"
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

void printUsage(const char* argv0) {
    printf(
        "Usage: %s [options]\n"
        "  --port N               AirPlay control TCP port (default: 7000)\n"
        "  --data-dir PATH        Persistent data directory (default: %s)\n"
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
        "  --service              Supervisor compatibility flag (default mode)\n"
        "  --version              Show version information and exit\n"
        "  --help                 Show this help message and exit\n",
        argv0,
        carplay::platform::contract::kDataDir,
        carplay::platform::contract::kControlName,
        carplay::platform::contract::kStateFile);
}

}  // namespace

int main(int argc, char** argv) {
    carplay::platform::CarPlayDaemonConfig cfg;

    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        const char* val = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            printUsage(argv[0]);
            return 0;
        } else if (strcmp(arg, "--version") == 0 || strcmp(arg, "-V") == 0) {
            printf("carplayd (EntryNav2-CarPlay) 1.0.0\n");
            return 0;
        } else if (strcmp(arg, "--service") == 0) {
            // Accepted for supervisor invocation (`carplayd --service`).
        } else if (strcmp(arg, "--port") == 0 && val != NULL) {
            unsigned long p = 0;
            if (!parseUint(val, 65535UL, p)) {
                printUsage(argv[0]);
                return 2;
            }
            cfg.control_port = static_cast<uint16_t>(p);
            ++i;
        } else if (strcmp(arg, "--data-dir") == 0 && val != NULL) {
            cfg.data_dir = val;
            ++i;
        } else if (strcmp(arg, "--control-name") == 0 && val != NULL) {
            cfg.control_name = val;
            ++i;
        } else if (strcmp(arg, "--state-file") == 0 && val != NULL) {
            cfg.state_file = val;
            ++i;
        } else if (strcmp(arg, "--width") == 0 && val != NULL) {
            unsigned long w = 0;
            if (!parseUint(val, 2560UL, w) || w < 320UL) {
                printUsage(argv[0]);
                return 2;
            }
            cfg.fallback_width = static_cast<uint32_t>(w);
            ++i;
        } else if (strcmp(arg, "--height") == 0 && val != NULL) {
            unsigned long h = 0;
            if (!parseUint(val, 1600UL, h) || h < 240UL) {
                printUsage(argv[0]);
                return 2;
            }
            cfg.fallback_height = static_cast<uint32_t>(h);
            ++i;
        } else if (strcmp(arg, "--no-ilm-size") == 0) {
            cfg.query_display_from_ilm = false;
        } else if (strcmp(arg, "--no-video") == 0) {
            cfg.enable_video = false;
        } else if (strcmp(arg, "--no-audio") == 0) {
            cfg.enable_audio = false;
        } else if (strcmp(arg, "--no-input") == 0) {
            cfg.enable_input = false;
        } else if (strcmp(arg, "--no-control") == 0) {
            cfg.enable_control = false;
        } else if (strcmp(arg, "--no-touch") == 0) {
            cfg.touch_enabled = false;
        } else if (strcmp(arg, "--wireless") == 0) {
            cfg.enable_wireless = true;
            cfg.connectivity_config.enable_wireless = true;
        } else if (strcmp(arg, "--no-wireless") == 0) {
            cfg.enable_wireless = false;
            cfg.connectivity_config.enable_wireless = false;
        } else if (strcmp(arg, "--wired") == 0) {
            cfg.enable_wired = true;
            cfg.connectivity_config.enable_wired = true;
        } else if (strcmp(arg, "--no-wired") == 0) {
            cfg.enable_wired = false;
            cfg.connectivity_config.enable_wired = false;
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
    signal(SIGINT, &onSignal);
    signal(SIGTERM, &onSignal);

    cfg.stop_flag = &g_stop_requested;
    if (cfg.tick_interval_ms <= 0) {
        cfg.tick_interval_ms = 100;  // the tick is what observes stop_flag
    }
    carplay::platform::CarPlayDaemon daemon(cfg);
    return daemon.run();
}
