// Phase 3 Wave C (F3-P7) unit and end-to-end tests:
//   * service_contract, parseControlCommand, EvoControl abstract Unix datagram socket & state file
//   * PeekTiming & MediaDoublePress / writeMediaRecall / takeMediaRecall
//   * HoldMachine, PopupPeek, CDS JSON parsers, initServiceSpawnAttr
//   * libEntryCarPlay.so HMI plugin ABI (pluginAppInfo layout, dlopen, vtable hooks, crash/boot guards)
//   * Full CarPlayDaemon end-to-end integration over real loopback sockets + mock HALs

#include "test_support.hpp"

#include "carplay/airplay_crypto.hpp"
#include "carplay/airplay_hid.hpp"
#include "carplay/airplay_info.hpp"
#include "carplay/audio_rtp.hpp"
#include "carplay/bplist_codec.hpp"
#include "carplay/control_cipher.hpp"
#include "carplay/platform/carplay_daemon.hpp"
#include "carplay/platform/entry_carplay_plugin.hpp"
#include "carplay/platform/evo_control.hpp"
#include "carplay/platform/evo_process.hpp"
#include "carplay/platform/file_util.hpp"
#include "carplay/platform/hold_machine.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/peek_timing.hpp"
#include "carplay/platform/service_contract.hpp"
#include "carplay/rtsp_message.hpp"
#include "carplay/screen_stream.hpp"
#include "carplay/tlv8_codec.hpp"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <dlfcn.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

#include <memory>
#include <string>
#include <vector>

namespace {

using namespace carplay;
namespace plat = carplay::platform;
typedef std::vector<uint8_t> Bytes;
typedef std::vector<tlv8::Item> Items;

std::string g_argv0_exe;

void sleepMs(int ms) {
    if (ms <= 0) return;
#ifndef _WIN32
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = static_cast<long>(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

std::string makeTempDir(const char* prefix) {
#ifndef _WIN32
    char tmpl[128];
    snprintf(tmpl, sizeof(tmpl), "/tmp/%s_XXXXXX", prefix ? prefix : "cp_test");
    char* d = mkdtemp(tmpl);
    return d ? std::string(d) : std::string("/tmp/cp_test_fallback");
#else
    (void)prefix;
    return "build/cp_test_tmp";
#endif
}

void removeTempDir(const std::string& dir) {
    if (dir.empty()) {
        return;
    }
#ifndef _WIN32
    std::string cmd = "rm -rf \"" + dir + "\"";
    const int rc = system(cmd.c_str());
    (void)rc;
#endif
}

#ifndef _WIN32
std::string selfExePath() {
    char buf[512] = "";
    const ssize_t rlen = readlink("/proc/self/exe", buf, sizeof(buf) - 1U);
    if (rlen > 0) {
        buf[rlen] = '\0';
        const std::string exe(buf);
        const size_t slash = exe.find_last_of('/');
        const std::string base = (slash != std::string::npos) ? exe.substr(slash + 1U) : exe;
        if (base.compare(0U, 5U, "qemu-") != 0) {
            return exe;
        }
    }
    if (!g_argv0_exe.empty()) {
        char resolved[512] = "";
        if (realpath(g_argv0_exe.c_str(), resolved) != NULL) {
            return std::string(resolved);
        }
        return g_argv0_exe;
    }
    return "build/host/test_carplay_daemon";
}

std::string siblingBinaryPath(const char* name) {
    const std::string self = selfExePath();
    const size_t slash = self.find_last_of('/');
    if (slash != std::string::npos) {
        return self.substr(0, slash + 1U) + name;
    }
    return std::string("build/host/") + name;
}

std::string readTextFile(const std::string& path) {
    std::vector<uint8_t> data;
    if (plat::readFileBounded(path, 262144U, data) != plat::kFileReadOk || data.empty()) {
        return std::string();
    }
    return std::string(reinterpret_cast<const char*>(&data[0]), data.size());
}

size_t countNonEmptyLines(const std::string& text) {
    size_t lines = 0U;
    size_t pos = 0U;
    while (pos < text.size()) {
        const size_t nl = text.find('\n', pos);
        const size_t end = (nl == std::string::npos) ? text.size() : nl;
        if (end > pos) {
            ++lines;
        }
        if (nl == std::string::npos) {
            break;
        }
        pos = nl + 1U;
    }
    return lines;
}

bool testIsZombiePid(pid_t pid) {
    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", static_cast<int>(pid));
    FILE* f = fopen(stat_path, "r");
    if (!f) {
        return false;
    }
    char buf[256];
    const size_t n = fread(buf, 1, sizeof(buf) - 1U, f);
    fclose(f);
    buf[n] = '\0';
    const char* rparen = strrchr(buf, ')');
    return (rparen != NULL && rparen[1] == ' ' && rparen[2] == 'Z');
}

bool testPidAliveNotZombie(pid_t pid) {
    if (pid <= 1) {
        return false;
    }
    if (kill(pid, 0) != 0 && errno != EPERM) {
        return false;
    }
    return !testIsZombiePid(pid);
}

pid_t waitForMockPidInLog(const std::string& log_path, pid_t after_pid, int timeout_ms) {
    const int64_t dl = plat::monotonicMillis() + timeout_ms;
    while (plat::monotonicMillis() < dl) {
        const std::string txt = readTextFile(log_path);
        const char* tag = "MOCK_SERVICE_PID=";
        const size_t pos = txt.rfind(tag);
        if (pos != std::string::npos) {
            const pid_t pid = static_cast<pid_t>(atoi(txt.c_str() + pos + strlen(tag)));
            if (pid > 1 && pid != after_pid && testPidAliveNotZombie(pid)) {
                return pid;
            }
        }
        sleepMs(10);
    }
    return 0;
}

bool waitForLogSubstring(const std::string& log_path, const char* needle, int timeout_ms) {
    const int64_t dl = plat::monotonicMillis() + timeout_ms;
    while (plat::monotonicMillis() < dl) {
        if (readTextFile(log_path).find(needle) != std::string::npos) {
            return true;
        }
        sleepMs(10);
    }
    return false;
}

bool waitForPidReaped(pid_t pid, const std::string& app_log, int timeout_ms) {
    char ended_tag[64];
    snprintf(ended_tag, sizeof(ended_tag), "child pid %d ended", static_cast<int>(pid));
    const int64_t dl = plat::monotonicMillis() + timeout_ms;
    while (plat::monotonicMillis() < dl) {
        if (!testPidAliveNotZombie(pid) &&
            readTextFile(app_log).find(ended_tag) != std::string::npos) {
            // Give the detached reaper thread a brief moment to return out of library code.
            sleepMs(20);
            return true;
        }
        sleepMs(10);
    }
    return false;
}

struct ControlCapture {
    plat::Mutex mu;
    std::vector<std::string> verbs;

    static void onCmd(const plat::ControlCommand& cmd, void* user) {
        ControlCapture* self = static_cast<ControlCapture*>(user);
        if (self != NULL) {
            plat::LockGuard lock(self->mu);
            self->verbs.push_back(cmd.verb);
        }
    }

    bool hasVerb(const char* verb) {
        plat::LockGuard lock(mu);
        for (size_t i = 0; i < verbs.size(); ++i) {
            if (verbs[i] == verb) {
                return true;
            }
        }
        return false;
    }
};
#endif

// =================================================================================================
// 1. Service Contract & Control Command Parser
// =================================================================================================

TEST_CASE(testServiceContractAndControlParser) {
    CHECK(strcmp(plat::contract::kService, "/opt/carplay/carplayd") == 0);
    CHECK(strcmp(plat::contract::kPluginDir, "/opt/hmi/data/ro/Plugins/EntryCarPlay") == 0);
    CHECK(strcmp(plat::contract::kDataDir, "/var/local/data/CarPlay") == 0);
    CHECK(strcmp(plat::contract::kStateFile, "/tmp/entry-carplayd-state") == 0);
    CHECK(strcmp(plat::contract::kControlName, "entry-carplayd-control") == 0);

    plat::ControlCommand cmd;
    CHECK(plat::parseControlCommand("ping", 4, cmd));
    CHECK_EQ(std::string("ping"), cmd.verb);
    CHECK(!cmd.has_arg);

    CHECK(plat::parseControlCommand("show\n", 5, cmd));
    CHECK_EQ(std::string("show"), cmd.verb);
    CHECK(!cmd.has_arg);

    CHECK(plat::parseControlCommand("hide\r\n", 6, cmd));
    CHECK_EQ(std::string("hide"), cmd.verb);

    CHECK(plat::parseControlCommand("await", 5, cmd));
    CHECK_EQ(std::string("await"), cmd.verb);

    CHECK(plat::parseControlCommand("quit", 4, cmd));
    CHECK_EQ(std::string("quit"), cmd.verb);

    CHECK(plat::parseControlCommand("gear 2", 6, cmd));
    CHECK_EQ(std::string("gear"), cmd.verb);
    CHECK(cmd.has_arg);
    CHECK_EQ(2, cmd.arg);

    CHECK(plat::parseControlCommand("daynight 2", 10, cmd));
    CHECK_EQ(std::string("daynight"), cmd.verb);
    CHECK(cmd.has_arg);
    CHECK_EQ(2, cmd.arg);

    CHECK(plat::parseControlCommand("call 1", 6, cmd));
    CHECK_EQ(std::string("call"), cmd.verb);
    CHECK(cmd.has_arg);
    CHECK_EQ(1, cmd.arg);

    CHECK(plat::parseControlCommand("popup 0", 7, cmd));
    CHECK_EQ(std::string("popup"), cmd.verb);
    CHECK(cmd.has_arg);
    CHECK_EQ(0, cmd.arg);

    CHECK(plat::parseControlCommand("drivemode", 9, cmd));
    CHECK_EQ(std::string("drivemode"), cmd.verb);
    CHECK(!cmd.has_arg);

    CHECK(plat::parseControlCommand("drivemode 4", 11, cmd));
    CHECK_EQ(std::string("drivemode"), cmd.verb);
    CHECK(cmd.has_arg);
    CHECK_EQ(4, cmd.arg);

    CHECK(plat::parseControlCommand("pdc 1", 5, cmd));
    CHECK_EQ(std::string("pdc"), cmd.verb);
    CHECK(cmd.has_arg);
    CHECK_EQ(1, cmd.arg);

    // Reject malformed commands
    CHECK(!plat::parseControlCommand("", 0, cmd));
    CHECK(!plat::parseControlCommand("unknown", 7, cmd));
    CHECK(!plat::parseControlCommand("gear", 4, cmd));
    CHECK(!plat::parseControlCommand("show 1", 6, cmd));
    CHECK(!plat::parseControlCommand("gear 1 2", 8, cmd));

    // State line parser
    plat::ServiceState st;
    CHECK(plat::parseServiceStateLine("connected 1234 1\n", st));
    CHECK(st.is("connected"));
    CHECK_EQ(1234, st.pid);
    CHECK_EQ(1, st.overlay);
    CHECK(st.onScreen());
    CHECK(!st.asks());

    CHECK(plat::parseServiceStateLine("connected 1234 2\n", st));
    CHECK(!st.onScreen());
    CHECK(st.asks());

    // AppKey & DayNight file helpers
    const std::string dir = makeTempDir("cp_ctrl_files");
    const std::string dn_file = dir + "/daynight";
    const std::string ak_file = dir + "/appkey";
    CHECK(plat::writeDayNightFile(dn_file.c_str(), 2));
    int dn_val = 0;
    CHECK(plat::readDayNightFile(dn_file.c_str(), dn_val));
    CHECK_EQ(2, dn_val);
    CHECK(!plat::writeDayNightFile(dn_file.c_str(), 99));

    CHECK(plat::writeAppKeyFile(ak_file.c_str(), "MEDIA"));
    CHECK(plat::pathExists(ak_file));
    removeTempDir(dir);
}

// =================================================================================================
// 2. EvoControl Abstract Unix Datagram Socket & State File Lifecycle
// =================================================================================================

struct ControlRecorder {
    plat::Mutex mu;
    std::vector<plat::ControlCommand> cmds;

    static void onCmd(const plat::ControlCommand& c, void* user) {
        ControlRecorder* r = static_cast<ControlRecorder*>(user);
        plat::LockGuard lock(r->mu);
        r->cmds.push_back(c);
    }
};

TEST_CASE(testEvoControlSocketAndStateFile) {
#ifdef _WIN32
    return;
#else
    const std::string dir = makeTempDir("cp_evo_ctrl");
    const std::string state_file = dir + "/state";
    char sock_name[64];
    snprintf(sock_name, sizeof(sock_name), "cp-test-ctrl-%d-%u",
             static_cast<int>(getpid()),
             static_cast<unsigned>(plat::monotonicMillis() & 0xFFFFU));

    CHECK(!plat::controlAnswers(sock_name, 50));

    ControlRecorder rec;
    plat::EvoControl ctrl1;
    REQUIRE(ctrl1.start(sock_name, state_file.c_str(), &ControlRecorder::onCmd, &rec));
    CHECK(ctrl1.running());
    CHECK(plat::controlAnswers(sock_name, 200));

    // Single-instance lock: second EvoControl on the same abstract name must fail.
    plat::EvoControl ctrl2;
    CHECK(!ctrl2.start(sock_name, state_file.c_str(), &ControlRecorder::onCmd, &rec));

    // Write state and read back
    ctrl1.writeState("connecting", 0);
    plat::ServiceState s0 = plat::readServiceStateFile(state_file.c_str(), sock_name);
    CHECK(s0.is("connecting"));
    CHECK_EQ(static_cast<int>(getpid()), s0.pid);
    CHECK_EQ(0, s0.overlay);

    ctrl1.writeState("connected", 1);
    plat::ServiceState s1 = plat::readServiceStateFile(state_file.c_str(), sock_name);
    CHECK(s1.is("connected"));
    CHECK(s1.onScreen());

    // Send commands over abstract Unix datagram socket
    CHECK(plat::sendControl(sock_name, "await"));
    CHECK(plat::sendControl(sock_name, "gear 2"));
    CHECK(plat::sendControl(sock_name, "daynight 2"));
    CHECK(plat::sendControl(sock_name, "call 1"));
    CHECK(plat::sendControl(sock_name, "popup 1"));
    CHECK(plat::sendControl(sock_name, "drivemode 3"));
    CHECK(plat::sendControl(sock_name, "show"));
    CHECK(plat::sendControl(sock_name, "quit"));

    const int64_t deadline = plat::monotonicMillis() + 2000;
    while (plat::monotonicMillis() < deadline) {
        {
            plat::LockGuard lock(rec.mu);
            if (rec.cmds.size() >= 8U) {
                break;
            }
        }
        sleepMs(5);
    }

    {
        plat::LockGuard lock(rec.mu);
        REQUIRE(rec.cmds.size() == 8U);
        CHECK_EQ(std::string("await"), rec.cmds[0].verb);
        CHECK_EQ(std::string("gear"), rec.cmds[1].verb);
        CHECK_EQ(2, rec.cmds[1].arg);
        CHECK_EQ(std::string("daynight"), rec.cmds[2].verb);
        CHECK_EQ(2, rec.cmds[2].arg);
        CHECK_EQ(std::string("call"), rec.cmds[3].verb);
        CHECK_EQ(1, rec.cmds[3].arg);
        CHECK_EQ(std::string("popup"), rec.cmds[4].verb);
        CHECK_EQ(1, rec.cmds[4].arg);
        CHECK_EQ(std::string("drivemode"), rec.cmds[5].verb);
        CHECK_EQ(3, rec.cmds[5].arg);
        CHECK_EQ(std::string("show"), rec.cmds[6].verb);
        CHECK_EQ(std::string("quit"), rec.cmds[7].verb);
    }

    ctrl1.stop();
    CHECK(!plat::pathExists(state_file));
    CHECK(!plat::controlAnswers(sock_name, 50));
    removeTempDir(dir);
#endif
}

// =================================================================================================
// 3. PeekTiming & MediaDoublePress / MediaRecall
// =================================================================================================

TEST_CASE(testPeekTimingAndMediaDoublePress) {
    plat::PeekTiming peek;

    // Initially on screen at full opacity
    plat::PeekTiming::Picture p = peek.turn(1000U, true);
    CHECK(p.shown);
    CHECK_EQ(1.0f, p.opacity);

    // Volume step without pill -> dims to 0.25 for 2500 ms
    CHECK(peek.volumeKey(1000U, false));
    p = peek.turn(1100U, true);
    CHECK(p.shown);
    CHECK_EQ(plat::kVolumeDim, p.opacity);

    p = peek.turn(3501U, true);
    CHECK(p.shown);
    CHECK_EQ(1.0f, p.opacity);

    // Compositor refuses opacity -> volume step hides picture instead
    CHECK(peek.volumeKey(4000U, false));
    p = peek.turn(4000U, true);
    peek.refuseOpacity(4000U, 4000U);
    CHECK(peek.dimRefused());
    p = peek.turn(4100U, true);
    CHECK(!p.shown);
    p = peek.turn(6501U, true);
    CHECK(p.shown);

    // Driving mode change -> hidden after 400 ms delay for 3500 ms
    CHECK(peek.driveMode(10000U));
    p = peek.turn(10200U, true);
    CHECK(p.shown);  // before 400 ms delay
    p = peek.turn(10500U, true);
    CHECK(!p.shown);  // inside 3500 ms window
    p = peek.turn(13901U, true);
    CHECK(p.shown);  // after 400 + 3500 ms

    // iDrive popup -> hidden immediately until popup(false)
    CHECK_EQ(static_cast<int>(plat::PeekTiming::kPopupShown),
             static_cast<int>(peek.popup(20000U, true)));
    p = peek.turn(20100U, true);
    CHECK(!p.shown);
    CHECK_EQ(static_cast<int>(plat::PeekTiming::kPopupGone),
             static_cast<int>(peek.popup(25000U, false)));
    p = peek.turn(25000U, true);
    CHECK(p.shown);

    // Hard key cancels active peek immediately
    CHECK(peek.driveMode(30000U));
    p = peek.turn(30500U, true);
    CHECK(!p.shown);
    CHECK(peek.hardKey());
    p = peek.turn(30500U, true);
    CHECK(p.shown);

    // MediaDoublePress: two short clicks within 500 ms while allowed
    plat::MediaDoublePress mdp;
    const bool allow = plat::mediaRecallAllowed(true, false, false, false, false);
    CHECK(allow);
    CHECK(!plat::mediaRecallAllowed(true, true, false, false, false));   // already on screen
    CHECK(!plat::mediaRecallAllowed(true, false, false, true, false));   // in call
    CHECK(!plat::mediaRecallAllowed(true, false, false, false, true));   // reverse gear

    // First observation establishes baseline state
    CHECK(!mdp.feed(0U, 100U, allow));
    // Click 1: down at 200, up at 350 (150 ms <= 500 ms)
    CHECK(!mdp.feed(1U, 200U, allow));
    CHECK(!mdp.feed(0U, 350U, allow));
    // Capacitive rest (4) counts as released
    CHECK(!mdp.feed(4U, 400U, allow));
    // Click 2: down at 500, up at 650 (300 ms after first up <= 500 ms) -> triggers!
    CHECK(!mdp.feed(1U, 500U, allow));
    CHECK(mdp.feed(0U, 650U, allow));

    // Long press (> 500 ms) does not count as short click
    CHECK(!mdp.feed(1U, 1000U, allow));
    CHECK(!mdp.feed(0U, 1600U, allow));
    CHECK(!mdp.feed(1U, 1700U, allow));
    CHECK(!mdp.feed(0U, 1800U, allow));

    // writeMediaRecall / takeMediaRecall atomic file lifecycle
    const std::string dir = makeTempDir("cp_recall");
    const std::string rfile = dir + "/recall";
    CHECK(plat::writeMediaRecall(rfile.c_str(), 4321, 5000U));
    CHECK(plat::takeMediaRecall(rfile.c_str(), 4321, 6000U));
    CHECK(!plat::takeMediaRecall(rfile.c_str(), 4321, 6000U));  // already consumed

    // Stale (> 2000 ms) or wrong PID rejected and file removed
    CHECK(plat::writeMediaRecall(rfile.c_str(), 4321, 5000U));
    CHECK(!plat::takeMediaRecall(rfile.c_str(), 4321, 7500U));
    CHECK(!plat::pathExists(rfile));
    removeTempDir(dir);
}

// =================================================================================================
// 4. HoldMachine, PopupPeek, CDS Parsers & Spawn Attributes
// =================================================================================================

struct MockHoldIo : public plat::HoldIo {
    std::vector<unsigned> events;
    std::vector<bool> popups;
    std::vector<std::string> sent;
    std::vector<std::string> logs;
    plat::ServiceState service;
    bool has_app_key;
    long app_key_age;

    MockHoldIo() : service(), has_app_key(false), app_key_age(0) {}

    virtual void triggerEvent(unsigned event) { events.push_back(event); }
    virtual void ownPopup(bool open) { popups.push_back(open); }
    virtual void send(const char* message) { sent.push_back(message ? message : ""); }
    virtual void log(const char* line) { logs.push_back(line ? line : ""); }
    virtual plat::ServiceState readService() { return service; }
    virtual bool appKeyAge(long* seconds) {
        if (!has_app_key) return false;
        if (seconds) *seconds = app_key_age;
        return true;
    }
    virtual void removeAppKey() { has_app_key = false; }

    void clearOutputs() {
        events.clear();
        popups.clear();
        sent.clear();
    }
};

TEST_CASE(testHoldMachineAndCdsParsers) {
    CHECK_EQ(2, plat::cdsIntField("{\"gear\":2}", "gear", -1));
    CHECK_EQ(2, plat::cdsGearValue("{\"driving.gear\":2}", -1));
    CHECK(plat::cdsCallActive("{\"state\":1,\"name\":\"Alice\"}"));
    CHECK(!plat::cdsCallActive("{\"state\":0}"));
    CHECK(!plat::cdsCallActive("malformed"));
    CHECK_EQ(2, plat::cdsIntField("{\"dayNightChangeOver\": 2}", "dayNightChangeOver", -1));

#ifndef _WIN32
    posix_spawnattr_t attr;
    CHECK_EQ(0, plat::initServiceSpawnAttr(&attr));
    posix_spawnattr_destroy(&attr);
#endif

    MockHoldIo io;
    plat::HoldMachine hold(io);

    // 1. Service becomes reachable -> sends "await", "call 0"
    io.service = plat::ServiceState("connecting", 1001, 0);
    hold.gearChanged(0);
    hold.tellService(io.service);
    REQUIRE(io.sent.size() == 3U);
    CHECK_EQ(std::string("await"), io.sent[0]);
    CHECK_EQ(std::string("call 0"), io.sent[1]);
    CHECK_EQ(std::string("gear 0"), io.sent[2]);
    io.clearOutputs();

    // 2. Phone connects and waits aside (overlay == 2 -> asks() == true)
    io.service = plat::ServiceState("connected", 1001, 2);
    hold.tellService(io.service);
    hold.poll(io.service, 10L);
    CHECK(hold.waiting());
    REQUIRE(io.events.size() == 1U);
    CHECK_EQ(plat::rhmi::kEvOpenMenu, io.events[0]);
    io.clearOutputs();

    // Menu opens -> sends "show" and fires kEvHoldCarPlay (52) immediately
    hold.menuFocus(plat::rhmi::kMenuState, true, 10L, 10000L);
    REQUIRE(io.sent.size() == 1U);
    CHECK_EQ(std::string("show"), io.sent[0]);
    REQUIRE(io.events.size() == 1U);
    CHECK_EQ(plat::rhmi::kEvHoldCarPlay, io.events[0]);
    io.clearOutputs();

    // Blank state 13 becomes visible and focused; service reports overlay == 1
    hold.carPlayVisible(true, 11L);
    hold.carPlayFocus(true);
    io.service = plat::ServiceState("connected", 1001, 1);
    hold.poll(io.service, 11L);
    CHECK(hold.holding());
    CHECK(hold.blankShown());
    io.clearOutputs();

    // 3. iDrive popup takes focus over our visible blank state -> sends "popup 1", then "popup 0"
    hold.carPlayFocus(false);
    hold.poll(io.service, 12L);
    REQUIRE(io.sent.size() == 1U);
    CHECK_EQ(std::string("popup 1"), io.sent[0]);
    CHECK(hold.popupPeek());
    io.clearOutputs();

    hold.carPlayFocus(true);
    hold.poll(io.service, 13L);
    REQUIRE(io.sent.size() == 1U);
    CHECK_EQ(std::string("popup 0"), io.sent[0]);
    CHECK(!hold.popupPeek());
    io.clearOutputs();

    // 4. App key (e.g. MEDIA/BACK) pressed when iDrive leaves state 13 -> keeps CarPlay on screen
    io.has_app_key = true;
    io.app_key_age = 1L;
    hold.carPlayVisible(false, 14L);
    CHECK(!io.has_app_key);
    REQUIRE(io.events.size() == 1U);
    CHECK_EQ(plat::rhmi::kEvHoldCarPlay, io.events[0]);
    hold.carPlayVisible(true, 14L);
    hold.carPlayFocus(true);
    io.clearOutputs();

    // 5. Hard key (e.g. MAP/NAV on iDrive) leaves blank state without appkey -> after 2 polls sends "hide"
    hold.carPlayFocus(false);
    hold.carPlayVisible(false, 20L);
    hold.poll(io.service, 20L);
    CHECK(io.sent.empty());
    hold.poll(io.service, 21L);
    REQUIRE(io.sent.size() == 1U);
    CHECK_EQ(std::string("hide"), io.sent[0]);
}

// =================================================================================================
// 5. HMI Plugin Shared Library (libEntryCarPlay.so) ABI, Guards & Mock Framework Lifecycle
// =================================================================================================

struct MockBmwEnv {
    void* fake_vtable_alloc[38];
    void* fake_runnable_vtbl[5];
    unsigned last_action_id;
    unsigned action_ids[16];
    plat::BmwActionDelegate actions[16];
    size_t action_count;
    unsigned state_ids[8];
    unsigned state_kinds[8];
    plat::BmwActionDelegate state_handlers[8];
    size_t state_count;
    plat::BmwCdsDelegate cds[8];
    size_t cds_count;
    std::vector<unsigned> triggered_events;
    std::vector<unsigned> updated_text_models;
    std::vector<void*> posted_runnables;
    bool base_on_init_called;
    bool base_on_finalize_called;
    bool dtor_called;

    MockBmwEnv()
        : last_action_id(0U),
          action_count(0U),
          state_count(0U),
          cds_count(0U),
          base_on_init_called(false),
          base_on_finalize_called(false),
          dtor_called(false) {
        memset(fake_vtable_alloc, 0, sizeof(fake_vtable_alloc));
        memset(fake_runnable_vtbl, 0, sizeof(fake_runnable_vtbl));
        memset(action_ids, 0, sizeof(action_ids));
        memset(actions, 0, sizeof(actions));
        memset(state_ids, 0, sizeof(state_ids));
        memset(state_kinds, 0, sizeof(state_kinds));
        memset(state_handlers, 0, sizeof(state_handlers));
        memset(cds, 0, sizeof(cds));
    }

    const plat::BmwActionDelegate* findAction(unsigned action_id) const {
        for (size_t i = 0U; i < action_count; ++i) {
            if (action_ids[i] == action_id) {
                return &actions[i];
            }
        }
        return NULL;
    }

    const plat::BmwActionDelegate* findState(unsigned state_id, unsigned kind) const {
        for (size_t i = 0U; i < state_count; ++i) {
            if (state_ids[i] == state_id && state_kinds[i] == kind) {
                return &state_handlers[i];
            }
        }
        return NULL;
    }

    bool invokeAction(unsigned action_id) const {
        const plat::BmwActionDelegate* d = findAction(action_id);
        if (d == NULL || d->stub == NULL) {
            return false;
        }
        plat::BmwParcelStorage p;
        memset(&p, 0, sizeof(p));
        return d->stub(d->object, p);
    }
};

static MockBmwEnv* g_mock_bmw = NULL;

void mockDeletingDtor(void* self) {
    if (g_mock_bmw != NULL) {
        g_mock_bmw->dtor_called = true;
    }
    ::operator delete(self);
}

void mockParcelCtorBool(plat::BmwParcelStorage* self, bool value) {
    self->storage[0] = value ? 1U : 0U;
}
void mockParcelDtor(plat::BmwParcelStorage*) {}
void mockParcelReadBool(const plat::BmwParcelStorage* self, bool& out) {
    out = (self->storage[0] != 0U);
}
void mockBstrCtor(plat::BmwBasicStringChar* self, const char* s) {
    self->data = const_cast<char*>(s);
}
void mockBstrDtor(plat::BmwBasicStringChar* self) {
    self->data = NULL;
}
void mockTextIdCtor(plat::BmwTextIdStorage* self, unsigned id) {
    self->id = id;
    self->type = 0U;
}
void mockImageIdCtor(plat::BmwImageIdStorage* self, unsigned id) {
    self->id = id;
    self->type = 0U;
}
void mockPluginAppCtor(void* self,
                       void* /*dispatcher*/,
                       plat::BmwBasicStringChar* /*name*/,
                       unsigned /*major*/,
                       unsigned /*minor*/,
                       int /*rhmi_ver*/,
                       const void* /*params*/,
                       const void* /*config*/) {
    if (g_mock_bmw != NULL) {
        g_mock_bmw->fake_vtable_alloc[3] = reinterpret_cast<void*>(&mockDeletingDtor);
        *reinterpret_cast<void***>(self) = g_mock_bmw->fake_vtable_alloc + 2;
    }
}
void mockAddAction(void*, unsigned action_id, const plat::BmwActionDelegate& d) {
    if (g_mock_bmw != NULL && g_mock_bmw->action_count < 16U) {
        g_mock_bmw->last_action_id = action_id;
        g_mock_bmw->action_ids[g_mock_bmw->action_count] = action_id;
        g_mock_bmw->actions[g_mock_bmw->action_count] = d;
        ++g_mock_bmw->action_count;
    }
}
void mockAddState(void*, unsigned state_id, unsigned kind, const plat::BmwActionDelegate& d) {
    if (g_mock_bmw != NULL && g_mock_bmw->state_count < 8U) {
        g_mock_bmw->state_ids[g_mock_bmw->state_count] = state_id;
        g_mock_bmw->state_kinds[g_mock_bmw->state_count] = kind;
        g_mock_bmw->state_handlers[g_mock_bmw->state_count] = d;
        ++g_mock_bmw->state_count;
    }
}
void mockTriggerEvent(void*, unsigned ev) {
    if (g_mock_bmw != NULL) {
        g_mock_bmw->triggered_events.push_back(ev);
    }
}
void mockTriggerEventParcel(void*, unsigned ev, const plat::BmwParcelStorage&) {
    if (g_mock_bmw != NULL) {
        g_mock_bmw->triggered_events.push_back(ev);
    }
}
void mockPostRunnable(void*, void* r, unsigned) {
    if (g_mock_bmw != NULL) {
        g_mock_bmw->posted_runnables.push_back(r);
    }
}
void mockUpdateText(void*, unsigned /*model_id*/, const plat::BmwTextIdStorage& t) {
    if (g_mock_bmw != NULL) {
        g_mock_bmw->updated_text_models.push_back(t.id);
    }
}
void mockUpdateImage(void*, unsigned, const plat::BmwImageIdStorage&) {}
void mockUpdateBool(void*, unsigned, bool) {}
void mockSetProperty(void*, unsigned, unsigned, const plat::BmwParcelStorage&) {}
void mockCdsAdd(void*, plat::BmwBasicStringChar&, unsigned, const plat::BmwCdsDelegate& d) {
    if (g_mock_bmw != NULL && g_mock_bmw->cds_count < 8U) {
        g_mock_bmw->cds[g_mock_bmw->cds_count++] = d;
    }
}
bool mockOnInit(void*) {
    if (g_mock_bmw != NULL) {
        g_mock_bmw->base_on_init_called = true;
    }
    return true;
}
void mockOnFinalize(void*) {
    if (g_mock_bmw != NULL) {
        g_mock_bmw->base_on_finalize_called = true;
    }
}

void initMockFrameworkApi(plat::BmwFrameworkApi& api, MockBmwEnv& env) {
    api.parcel_ctor_bool = &mockParcelCtorBool;
    api.parcel_dtor = &mockParcelDtor;
    api.parcel_read_bool = &mockParcelReadBool;
    api.bstr_ctor_cstr = &mockBstrCtor;
    api.bstr_dtor = &mockBstrDtor;
    api.text_id_ctor = &mockTextIdCtor;
    api.image_id_ctor = &mockImageIdCtor;
    api.plugin_app_ctor = &mockPluginAppCtor;
    api.add_action_handler = &mockAddAction;
    api.add_state_handler = &mockAddState;
    api.trigger_event = &mockTriggerEvent;
    api.trigger_event_parcel = &mockTriggerEventParcel;
    api.post_runnable = &mockPostRunnable;
    api.update_model_text = &mockUpdateText;
    api.update_model_image = &mockUpdateImage;
    api.update_model_bool = &mockUpdateBool;
    api.set_property = &mockSetProperty;
    api.cds_add_handler = &mockCdsAdd;
    api.on_init = &mockOnInit;
    api.on_finalize = &mockOnFinalize;
    api.runnable_vtable = env.fake_runnable_vtbl;
}

typedef void (*SetApiFn)(const plat::BmwFrameworkApi*,
                         const char*,
                         const char*,
                         const char*,
                         const plat::EntryCarPlayTestOptions*);

void invokeRunnableObj(void* runnable) {
    void** vptr = *reinterpret_cast<void***>(runnable);
    void (*run_fn)(void*) = NULL;
    memcpy(&run_fn, &vptr[2], sizeof(run_fn));
    run_fn(runnable);
}

#ifndef _WIN32
struct ChildWaitGuard {
    pid_t pid;
    bool wait_locally;

    ChildWaitGuard() : pid(0), wait_locally(true) {}
    ~ChildWaitGuard() {
        if (pid > 1) {
            kill(pid, SIGKILL);
            if (wait_locally) {
                int st = 0;
                waitpid(pid, &st, 0);
            }
        }
    }
};
#endif

TEST_CASE(testHmiPluginAbiAndMockFramework) {
    // 1. Crash guard & boot guard tests
    const std::string dir = makeTempDir("cp_hmi_guards");
    CHECK(!plat::isAppDisabledInDir(dir.c_str()));

    CHECK(plat::crashGuardAllowsInDir(dir.c_str(), 100L));
    CHECK(plat::crashGuardAllowsInDir(dir.c_str(), 110L));
    CHECK(plat::crashGuardAllowsInDir(dir.c_str(), 120L));
    CHECK(!plat::crashGuardAllowsInDir(dir.c_str(), 130L));  // 4th load blocked!

    bool stable = false;
    plat::resetGuardsWhenStableInDir(dir.c_str(), 100L, 150L, stable);
    CHECK(!stable);
    plat::resetGuardsWhenStableInDir(dir.c_str(), 100L, 225L, stable);
    CHECK(stable);
    CHECK(plat::crashGuardAllowsInDir(dir.c_str(), 230L));  // allowed again after reset!

    CHECK(plat::bootGuardAllowsInDir(dir.c_str(), 1000L));
    CHECK(plat::bootGuardAllowsInDir(dir.c_str(), 1100L));
    CHECK(plat::bootGuardAllowsInDir(dir.c_str(), 1200L));
    CHECK(!plat::bootGuardAllowsInDir(dir.c_str(), 1300L));  // 4th within 15 min blocked!

    // Clean guard files before dlopen test
    plat::removeFile(dir + "/app-guard");
    plat::removeFile(dir + "/bootguard");

#ifndef _WIN32
    // 2. Verify ARM32 struct offsets when compiled on 32-bit target
    if (sizeof(void*) == 4U) {
        CHECK_EQ(static_cast<size_t>(0x10U), offsetof(EntryPluginAppInfo, create));
        CHECK_EQ(static_cast<size_t>(0x14U), offsetof(EntryPluginAppInfo, destroy));
    }

    const std::string so_path = siblingBinaryPath("libEntryCarPlay.so");
    void* handle = dlopen(so_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    REQUIRE(handle != NULL);

    const EntryPluginAppInfo* info =
        reinterpret_cast<const EntryPluginAppInfo*>(dlsym(handle, "pluginAppInfo"));
    REQUIRE(info != NULL);
    CHECK_EQ(static_cast<uint16_t>(1U), info->versionMajor);
    CHECK_EQ(static_cast<uint16_t>(0U), info->versionMinor);
    CHECK(strcmp(info->name, "Apple CarPlay") == 0);
    CHECK(strcmp(info->vendor, "EntryCarPlay") == 0);
    CHECK_EQ(static_cast<uint32_t>(1U), info->rhmiInterfaceVersion);
    REQUIRE(info->create != NULL);
    REQUIRE(info->destroy != NULL);

    SetApiFn set_api = NULL;
    void* set_api_sym = dlsym(handle, "entryCarPlaySetFrameworkApiForTest");
    REQUIRE(set_api_sym != NULL);
    memcpy(&set_api, &set_api_sym, sizeof(set_api));

    MockBmwEnv mock_env;
    g_mock_bmw = &mock_env;

    plat::BmwFrameworkApi api;
    initMockFrameworkApi(api, mock_env);
    CHECK(api.isComplete());

    const std::string state_file = dir + "/state";
    set_api(&api, dir.c_str(), "cp-test-hmi-ctrl", state_file.c_str(), NULL);

    int dummy_disp = 0;
    int dummy_params = 0;
    int dummy_cfg = 0;
    void* app = info->create(&dummy_disp, "EntryCarPlay", &dummy_params, &dummy_cfg);
    REQUIRE(app != NULL);

    // Invoke vtable slot 22 (onInit)
    void** vtbl = *reinterpret_cast<void***>(app);
    REQUIRE(vtbl != NULL);
    bool (*on_init_hook)(void*) = NULL;
    memcpy(&on_init_hook, &vtbl[22], sizeof(on_init_hook));
    REQUIRE(on_init_hook != NULL);
    CHECK(on_init_hook(app));
    CHECK(mock_env.base_on_init_called);
    CHECK_EQ(static_cast<size_t>(5U), mock_env.action_count);
    CHECK_EQ(static_cast<size_t>(4U), mock_env.state_count);
    CHECK(mock_env.findAction(plat::rhmi::kActStart) != NULL);
    CHECK(mock_env.findAction(plat::rhmi::kActStop) != NULL);
    CHECK(mock_env.findState(plat::rhmi::kMenuState, plat::rhmi::kHandlerFocus) != NULL);
    CHECK(mock_env.findState(plat::rhmi::kCarPlayState, plat::rhmi::kHandlerVisible) != NULL);
    REQUIRE(mock_env.posted_runnables.size() == 2U);

    // Invoke posted subscribeRun runnable and statusRun runnable
    invokeRunnableObj(mock_env.posted_runnables[0]);
    CHECK_EQ(static_cast<size_t>(6U), mock_env.cds_count);
    invokeRunnableObj(mock_env.posted_runnables[1]);

    // Invoke vtable slot 23 (onFinalize) and destroy
    void (*on_fin_hook)(void*) = NULL;
    memcpy(&on_fin_hook, &vtbl[23], sizeof(on_fin_hook));
    REQUIRE(on_fin_hook != NULL);
    on_fin_hook(app);
    CHECK(mock_env.base_on_finalize_called);

    info->destroy(app);
    CHECK(mock_env.dtor_called);

    set_api(NULL, NULL, NULL, NULL, NULL);
    g_mock_bmw = NULL;
    dlclose(handle);
#endif
    removeTempDir(dir);
}

TEST_CASE(testHmiPluginErrorGuardsAndEdgeCases) {
#ifdef _WIN32
    return;
#else
    const std::string dir = makeTempDir("cp_hmi_errguards");
    const std::string state_file = dir + "/state";
    const std::string guard_file = dir + "/app-guard";
    const std::string disable_file = dir + "/app.disable";
    const std::string so_path = siblingBinaryPath("libEntryCarPlay.so");

    void* handle = dlopen(so_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    REQUIRE(handle != NULL);

    const EntryPluginAppInfo* info =
        reinterpret_cast<const EntryPluginAppInfo*>(dlsym(handle, "pluginAppInfo"));
    REQUIRE(info != NULL);
    SetApiFn set_api = NULL;
    void* set_api_sym = dlsym(handle, "entryCarPlaySetFrameworkApiForTest");
    REQUIRE(set_api_sym != NULL);
    memcpy(&set_api, &set_api_sym, sizeof(set_api));

    MockBmwEnv mock_env;
    g_mock_bmw = &mock_env;
    plat::BmwFrameworkApi api;
    initMockFrameworkApi(api, mock_env);

    int dummy_disp = 0;
    int dummy_params = 0;
    int dummy_cfg = 0;

    // 1. app.disable prevents createApp and does not create app-guard
    const uint8_t one[2] = {'1', '\n'};
    REQUIRE(plat::writeFileAtomic(disable_file, one, sizeof(one)));
    set_api(&api, dir.c_str(), "cp-test-err-ctrl", state_file.c_str(), NULL);
    CHECK(info->create(&dummy_disp, "EntryCarPlay", &dummy_params, &dummy_cfg) == NULL);
    CHECK(!plat::pathExists(guard_file));
    plat::removeFile(disable_file);

    // 2. app-guard with 3 entries blocks createApp
    static const char kThreeGuards[] = "100\n110\n120\n";
    REQUIRE(plat::writeFileAtomic(
        guard_file, reinterpret_cast<const uint8_t*>(kThreeGuards), sizeof(kThreeGuards) - 1U));
    CHECK(info->create(&dummy_disp, "EntryCarPlay", &dummy_params, &dummy_cfg) == NULL);
    CHECK_EQ(static_cast<size_t>(3U), countNonEmptyLines(readTextFile(guard_file)));
    plat::removeFile(guard_file);

    // 3. Missing framework API returns NULL and does NOT consume an app-guard entry
    static const char kOneGuard[] = "100\n";
    REQUIRE(plat::writeFileAtomic(
        guard_file, reinterpret_cast<const uint8_t*>(kOneGuard), sizeof(kOneGuard) - 1U));
    set_api(NULL, dir.c_str(), "cp-test-err-ctrl", state_file.c_str(), NULL);
    CHECK(info->create(&dummy_disp, "EntryCarPlay", &dummy_params, &dummy_cfg) == NULL);
    CHECK_EQ(static_cast<size_t>(1U), countNonEmptyLines(readTextFile(guard_file)));

    // 4. Successful createApp + duplicate createApp does NOT consume extra guard entry
    set_api(&api, dir.c_str(), "cp-test-err-ctrl", state_file.c_str(), NULL);
    void* app = info->create(&dummy_disp, "EntryCarPlay", &dummy_params, &dummy_cfg);
    REQUIRE(app != NULL);
    CHECK_EQ(static_cast<size_t>(2U), countNonEmptyLines(readTextFile(guard_file)));
    CHECK(info->create(&dummy_disp, "EntryCarPlay", &dummy_params, &dummy_cfg) == NULL);
    CHECK_EQ(static_cast<size_t>(2U), countNonEmptyLines(readTextFile(guard_file)));

    // 5. appOnError (vtable slot 21) handles non-NULL and NULL message cleanly
    void** vtbl = *reinterpret_cast<void***>(app);
    REQUIRE(vtbl != NULL);
    void (*on_error_hook)(void*, unsigned, const plat::BmwBasicStringChar&) = NULL;
    memcpy(&on_error_hook, &vtbl[21], sizeof(on_error_hook));
    REQUIRE(on_error_hook != NULL);

    plat::BmwBasicStringChar msg_ok;
    msg_ok.data = const_cast<char*>("rhmi test warning");
    on_error_hook(app, 42U, msg_ok);
    plat::BmwBasicStringChar msg_null;
    msg_null.data = NULL;
    on_error_hook(app, 43U, msg_null);

    const std::string app_log = readTextFile(dir + "/app.log");
    CHECK(app_log.find("onError 42: rhmi test warning") != std::string::npos);
    CHECK(app_log.find("onError 43: (null)") != std::string::npos);

    // 6. destroyApp(NULL) is a safe no-op, followed by normal destroy
    info->destroy(NULL);
    info->destroy(app);
    CHECK(mock_env.dtor_called);

    set_api(NULL, NULL, NULL, NULL, NULL);
    g_mock_bmw = NULL;
    dlclose(handle);
    removeTempDir(dir);
#endif
}

TEST_CASE(testHmiPluginStopEscalationAndPidGuard) {
#ifdef _WIN32
    return;
#else
    const std::string dir = makeTempDir("cp_hmi_stop");
    const std::string state_file = dir + "/state";
    const std::string stop_file = dir + "/stop/STOP";
    const std::string service_log = dir + "/service.log";
    const std::string app_log = dir + "/app.log";
    const std::string self_exe = selfExePath();
    const std::string carplayd_bin = siblingBinaryPath("carplayd");
    const std::string so_path = siblingBinaryPath("libEntryCarPlay.so");

    char ctrl_name[64];
    snprintf(ctrl_name, sizeof(ctrl_name), "cp-test-stop-%d", static_cast<int>(getpid()));

    void* handle = dlopen(so_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    REQUIRE(handle != NULL);
    const EntryPluginAppInfo* info =
        reinterpret_cast<const EntryPluginAppInfo*>(dlsym(handle, "pluginAppInfo"));
    REQUIRE(info != NULL);
    SetApiFn set_api = NULL;
    void* set_api_sym = dlsym(handle, "entryCarPlaySetFrameworkApiForTest");
    REQUIRE(set_api_sym != NULL);
    memcpy(&set_api, &set_api_sym, sizeof(set_api));

    MockBmwEnv mock_env;
    g_mock_bmw = &mock_env;
    plat::BmwFrameworkApi api;
    initMockFrameworkApi(api, mock_env);

    plat::EntryCarPlayTestOptions opts;
    opts.stop_file = stop_file.c_str();
    opts.service_bin = self_exe.c_str();
    opts.service_log = service_log.c_str();
    opts.stop_term_ms = 40L;
    opts.stop_kill_ms = 120L;
    opts.stop_giveup_ms = 500L;
    opts.launch_debounce_ms = 0L;

    // A0. onStopRow creates STOP file & sends "quit" over a bound EvoControl channel
    {
        ControlCapture cap;
        plat::EvoControl ctrl;
        REQUIRE(ctrl.start(ctrl_name, state_file.c_str(), &ControlCapture::onCmd, &cap));

        set_api(&api, dir.c_str(), ctrl_name, state_file.c_str(), &opts);
        int dummy = 0;
        void* app = info->create(&dummy, "EntryCarPlay", &dummy, &dummy);
        REQUIRE(app != NULL);
        void** vtbl = *reinterpret_cast<void***>(app);
        bool (*on_init_hook)(void*) = NULL;
        memcpy(&on_init_hook, &vtbl[22], sizeof(on_init_hook));
        REQUIRE(on_init_hook(app));

        CHECK(mock_env.invokeAction(plat::rhmi::kActStop));
        CHECK(plat::pathExists(stop_file));
        const int64_t q_dl = plat::monotonicMillis() + 1000;
        while (plat::monotonicMillis() < q_dl && !cap.hasVerb("quit")) {
            sleepMs(10);
        }
        CHECK(cap.hasVerb("quit"));

        info->destroy(app);
        ctrl.stop();
        plat::removeFile(state_file);
        plat::removeFile(stop_file);
    }

    // A. Direct child (`kService` ignoring SIGTERM) spawned via onStartRow escalates SIGTERM -> SIGKILL
    // B. Start after Stop unlinks STOP file and cancels pending escalation
    {
        plat::removeFile(dir + "/app-guard");
        mock_env = MockBmwEnv();
        set_api(&api, dir.c_str(), ctrl_name, state_file.c_str(), &opts);
        int dummy = 0;
        void* app = info->create(&dummy, "EntryCarPlay", &dummy, &dummy);
        REQUIRE(app != NULL);
        void** vtbl = *reinterpret_cast<void***>(app);
        bool (*on_init_hook)(void*) = NULL;
        memcpy(&on_init_hook, &vtbl[22], sizeof(on_init_hook));
        REQUIRE(on_init_hook(app));
        REQUIRE(mock_env.posted_runnables.size() == 2U);
        void* status_runnable = mock_env.posted_runnables[1];

        // Spawn mock hung service (--service ignores SIGTERM)
        CHECK(mock_env.invokeAction(plat::rhmi::kActStart));
        const pid_t svc_pid = waitForMockPidInLog(service_log, 0, 2000);
        REQUIRE(svc_pid > 1);
        CHECK(testPidAliveNotZombie(svc_pid));

        CHECK(mock_env.invokeAction(plat::rhmi::kActStop));
        CHECK(plat::pathExists(stop_file));

        // Past stop_term_ms (40 ms), before stop_kill_ms (120 ms): SIGTERM sent, process ignores it
        sleepMs(55);
        invokeRunnableObj(status_runnable);
        CHECK(waitForLogSubstring(app_log, "-> SIGTERM", 500));
        CHECK(testPidAliveNotZombie(svc_pid));

        // Past stop_kill_ms (120 ms): SIGKILL sent and child reaped
        sleepMs(85);
        invokeRunnableObj(status_runnable);
        CHECK(waitForLogSubstring(app_log, "-> SIGKILL", 500));
        CHECK(waitForPidReaped(svc_pid, app_log, 2000));

        // B. Start after Stop unlinks STOP file and cancels pending escalation
        CHECK(mock_env.invokeAction(plat::rhmi::kActStop));
        CHECK(plat::pathExists(stop_file));
        CHECK(mock_env.invokeAction(plat::rhmi::kActStart));
        CHECK(!plat::pathExists(stop_file));
        const pid_t svc_pid2 = waitForMockPidInLog(service_log, svc_pid, 2000);
        REQUIRE(svc_pid2 > 1);
        sleepMs(150);  // Well past stop_kill_ms: must NOT kill newly started child!
        invokeRunnableObj(status_runnable);
        CHECK(testPidAliveNotZombie(svc_pid2));

        // Clean up svc_pid2 before resetting session
        kill(svc_pid2, SIGKILL);
        CHECK(waitForPidReaped(svc_pid2, app_log, 2000));

        info->destroy(app);
        plat::removeFile(state_file);
        plat::removeFile(stop_file);
    }

    // C. kSupervisor + frozen real carplayd: only verified carplayd receives SIGTERM -> SIGKILL
    {
        plat::removeFile(dir + "/app-guard");
        plat::removeFile(service_log);
        mock_env = MockBmwEnv();
        plat::EntryCarPlayTestOptions sup_opts = opts;
        sup_opts.supervisor_bin = self_exe.c_str();
        sup_opts.service_bin = NULL;  // expected basename stays "carplayd"

        const std::string daemon_data = dir + "/daemon_data";
        mkdir(daemon_data.c_str(), 0700);
        set_api(&api, dir.c_str(), ctrl_name, state_file.c_str(), &sup_opts);

        int dummy = 0;
        void* app = info->create(&dummy, "EntryCarPlay", &dummy, &dummy);
        REQUIRE(app != NULL);
        void** vtbl = *reinterpret_cast<void***>(app);
        bool (*on_init_hook)(void*) = NULL;
        memcpy(&on_init_hook, &vtbl[22], sizeof(on_init_hook));
        REQUIRE(on_init_hook(app));
        REQUIRE(mock_env.posted_runnables.size() == 2U);
        void* status_runnable = mock_env.posted_runnables[1];

        // Spawn mock supervisor through launchDaemonProcess
        CHECK(mock_env.invokeAction(plat::rhmi::kActStart));
        const pid_t sup_pid = waitForMockPidInLog(service_log, 0, 2000);
        REQUIRE(sup_pid > 1);

        // Spawn real carplayd as a direct child of the test so we can waitpid() and SIGSTOP it
        ChildWaitGuard carplayd_guard;
        const pid_t dpid = fork();
        REQUIRE(dpid >= 0);
        if (dpid == 0) {
            const char* dargv[] = {
                carplayd_bin.c_str(),
                "--no-ilm-size",
                "--no-video",
                "--no-audio",
                "--no-input",
                "--port", "0",
                "--data-dir", daemon_data.c_str(),
                "--control-name", ctrl_name,
                "--state-file", state_file.c_str(),
                NULL
            };
            execv(carplayd_bin.c_str(), const_cast<char* const*>(dargv));
            _exit(127);
        }
        carplayd_guard.pid = dpid;

        // Wait until carplayd writes its state file with its own PID
        const int64_t st_dl = plat::monotonicMillis() + 3000;
        bool state_ready = false;
        while (plat::monotonicMillis() < st_dl) {
            const plat::ServiceState st = plat::readServiceStateFile(state_file.c_str(), NULL);
            if (st.pid == static_cast<int>(dpid)) {
                state_ready = true;
                break;
            }
            sleepMs(20);
        }
        REQUIRE(state_ready);

        // Freeze carplayd so it cannot respond to STOP or "quit" or SIGTERM until SIGKILL
        REQUIRE(kill(dpid, SIGSTOP) == 0);

        CHECK(mock_env.invokeAction(plat::rhmi::kActStop));
        CHECK(plat::pathExists(stop_file));

        sleepMs(55);
        invokeRunnableObj(status_runnable);
        CHECK(waitForLogSubstring(app_log, "verified daemon pid", 500));
        CHECK(testPidAliveNotZombie(sup_pid));

        sleepMs(85);
        invokeRunnableObj(status_runnable);

        const int64_t kill_dl = plat::monotonicMillis() + 2000;
        int dstatus = 0;
        pid_t wr = 0;
        while (plat::monotonicMillis() < kill_dl) {
            wr = waitpid(dpid, &dstatus, WNOHANG);
            if (wr == dpid) {
                break;
            }
            sleepMs(10);
        }
        CHECK_EQ(dpid, wr);
        CHECK(WIFSIGNALED(dstatus) && WTERMSIG(dstatus) == SIGKILL);
        carplayd_guard.pid = 0;  // already reaped
        CHECK(testPidAliveNotZombie(sup_pid));  // supervisor was never signalled!

        // Stop mock supervisor cleanly and wait for plugin reaper before next sub-case
        kill(sup_pid, SIGKILL);
        CHECK(waitForPidReaped(sup_pid, app_log, 2000));

        info->destroy(app);
        plat::removeFile(state_file);
        plat::removeFile(stop_file);
    }

    // D. Negative PID-verification test: unrelated process in state_file must NOT be signalled
    {
        plat::removeFile(dir + "/app-guard");
        mock_env = MockBmwEnv();
        plat::EntryCarPlayTestOptions neg_opts = opts;
        neg_opts.service_bin = NULL;  // expects "carplayd", whereas child is "test_carplay_daemon"

        ChildWaitGuard unrelated_guard;
        const pid_t other_pid = fork();
        REQUIRE(other_pid >= 0);
        if (other_pid == 0) {
            const char* uargv[] = {self_exe.c_str(), "--mock-hang", NULL};
            execv(self_exe.c_str(), const_cast<char* const*>(uargv));
            _exit(127);
        }
        unrelated_guard.pid = other_pid;
        sleepMs(40);
        REQUIRE(testPidAliveNotZombie(other_pid));

        char fake_state[64];
        snprintf(fake_state, sizeof(fake_state), "connected %d 0\n", static_cast<int>(other_pid));
        REQUIRE(plat::writeFileAtomic(
            state_file, reinterpret_cast<const uint8_t*>(fake_state), strlen(fake_state)));

        set_api(&api, dir.c_str(), ctrl_name, state_file.c_str(), &neg_opts);
        int dummy = 0;
        void* app = info->create(&dummy, "EntryCarPlay", &dummy, &dummy);
        REQUIRE(app != NULL);
        void** vtbl = *reinterpret_cast<void***>(app);
        bool (*on_init_hook)(void*) = NULL;
        memcpy(&on_init_hook, &vtbl[22], sizeof(on_init_hook));
        REQUIRE(on_init_hook(app));
        REQUIRE(mock_env.posted_runnables.size() == 2U);
        void* status_runnable = mock_env.posted_runnables[1];

        CHECK(mock_env.invokeAction(plat::rhmi::kActStop));
        sleepMs(55);
        invokeRunnableObj(status_runnable);
        sleepMs(85);
        invokeRunnableObj(status_runnable);
        sleepMs(50);

        // Unrelated process must STILL be alive (SIGTERM/SIGKILL refused)
        CHECK(testPidAliveNotZombie(other_pid));

        info->destroy(app);
        // unrelated_guard kills & reaps other_pid cleanly here
    }

    set_api(NULL, NULL, NULL, NULL, NULL);
    g_mock_bmw = NULL;
    dlclose(handle);
    removeTempDir(dir);
#endif
}

// =================================================================================================
// 6. Full CarPlayDaemon End-to-End Integration Test (Simulated iPhone + Mock HALs)
// =================================================================================================

struct DaemonMockHal {
    plat::Mutex mu;
    bool xsv_opened;
    bool xsv_started;
    uint32_t decoded_frames;
    uint32_t alsa_opens;
    uint64_t alsa_frames_written;
    std::vector<std::string> alsa_devices;
    int vmost_fds[2];
    plat::VmostCallback vmost_cb;
    void* vmost_user;

    DaemonMockHal()
        : xsv_opened(false),
          xsv_started(false),
          decoded_frames(0U),
          alsa_opens(0U),
          alsa_frames_written(0ULL),
          vmost_cb(NULL),
          vmost_user(NULL) {
        vmost_fds[0] = -1;
        vmost_fds[1] = -1;
    }

    bool initVmostPipe() {
#ifndef _WIN32
        return pipe(vmost_fds) == 0;
#else
        return false;
#endif
    }

    void closeVmostPipe() {
#ifndef _WIN32
        if (vmost_fds[0] >= 0) close(vmost_fds[0]);
        if (vmost_fds[1] >= 0) close(vmost_fds[1]);
        vmost_fds[0] = -1;
        vmost_fds[1] = -1;
#endif
    }
};

static DaemonMockHal* g_hal = NULL;

struct MockXsvEvent {
    int words[5];
};

struct FakeXsvDecoder {
    std::vector<MockXsvEvent> pending_events;
};

int mockDrmOpen(const char*, const char*) { return 77; }
void mockDrmClose(int) {}
struct omap_device* mockOmapDevNew(int) {
    return reinterpret_cast<struct omap_device*>(0x1001);
}
void mockOmapDevDel(struct omap_device*) {}
struct omap_bo* mockOmapBoNew(struct omap_device*, uint32_t sz, uint32_t) {
    uint8_t* mem = new uint8_t[sz];
    memset(mem, 0, sz);
    return reinterpret_cast<struct omap_bo*>(mem);
}
void mockOmapBoDel(struct omap_bo* bo) { delete[] reinterpret_cast<uint8_t*>(bo); }
int mockOmapBoDmabuf(struct omap_bo*) {
#ifndef _WIN32
    return dup(0);
#else
    return 10;
#endif
}
void* mockOmapBoMap(struct omap_bo* bo) { return reinterpret_cast<void*>(bo); }

plat::xsv_handle mockXsvOpen(int, uint32_t, const char*) {
    FakeXsvDecoder* d = new FakeXsvDecoder();
    if (g_hal) {
        plat::LockGuard lock(g_hal->mu);
        g_hal->xsv_opened = true;
    }
    return reinterpret_cast<plat::xsv_handle>(d);
}
void mockXsvClose(plat::xsv_handle h) {
    delete static_cast<FakeXsvDecoder*>(h);
}
int mockXsvConfigureStream(plat::xsv_handle, uint32_t, uint32_t, float) { return 0; }
int mockXsvSetOutputDimension(plat::xsv_handle, uint32_t, uint32_t) { return 0; }
int mockXsvSetInputViewport(plat::xsv_handle, uint32_t, uint32_t, uint32_t, uint32_t) { return 0; }
int mockXsvDecodeVideoFrame(plat::xsv_handle h, int dmabuf_fd, uint32_t) {
    if (!h) return -1;
    FakeXsvDecoder* d = static_cast<FakeXsvDecoder*>(h);
    if (g_hal) {
        plat::LockGuard lock(g_hal->mu);
        g_hal->decoded_frames += 1U;
        MockXsvEvent ev1;
        memset(&ev1, 0, sizeof(ev1));
        ev1.words[0] = plat::XSV_EVENT_DMABUF_COMPLETE;
        ev1.words[1] = dmabuf_fd;
        d->pending_events.push_back(ev1);
        MockXsvEvent ev2;
        memset(&ev2, 0, sizeof(ev2));
        ev2.words[0] = plat::XSV_EVENT_FRAME;
        d->pending_events.push_back(ev2);
    }
    return 0;
}
int mockXsvStart(plat::xsv_handle h) {
    if (g_hal) {
        plat::LockGuard lock(g_hal->mu);
        g_hal->xsv_started = true;
        if (h) {
            FakeXsvDecoder* d = static_cast<FakeXsvDecoder*>(h);
            MockXsvEvent ev;
            memset(&ev, 0, sizeof(ev));
            ev.words[0] = plat::XSV_EVENT_PLAYING;
            d->pending_events.push_back(ev);
        }
    }
    return 0;
}
int mockXsvStop(plat::xsv_handle) { return 0; }
int mockXsvPause(plat::xsv_handle) { return 0; }
int mockXsvUpdate(plat::xsv_handle) { return 0; }
int mockXsvEnableFrameEvents(plat::xsv_handle) { return 0; }
int mockXsvDisableFrameEvents(plat::xsv_handle) { return 0; }
int mockXsvReceiveEvent(plat::xsv_handle h, int* event_out, int) {
    if (!h || !event_out) return -1;
    FakeXsvDecoder* d = static_cast<FakeXsvDecoder*>(h);
    if (g_hal) {
        plat::LockGuard lock(g_hal->mu);
        if (!d->pending_events.empty()) {
            const MockXsvEvent ev = d->pending_events.front();
            d->pending_events.erase(d->pending_events.begin());
            memcpy(event_out, ev.words, sizeof(ev.words));
            return 0;
        }
    }
    sleepMs(5);
    memset(event_out, 0, 5U * sizeof(int));
    return 0;
}
int mockXsvGetEventQueueFd(plat::xsv_handle) { return -1; }

int mockAlsaOpen(void** pcm, const char* name, int, int) {
    *pcm = reinterpret_cast<void*>(0x2001);
    if (g_hal) {
        plat::LockGuard lock(g_hal->mu);
        g_hal->alsa_opens += 1U;
        g_hal->alsa_devices.push_back(name ? name : "");
    }
    return 0;
}
int mockAlsaSetParams(void*, int, int, unsigned int, unsigned int, int, unsigned int) { return 0; }
long mockAlsaWritei(void*, const void*, unsigned long frames) {
    if (g_hal) {
        plat::LockGuard lock(g_hal->mu);
        g_hal->alsa_frames_written += frames;
    }
    return static_cast<long>(frames);
}
long mockAlsaReadi(void*, void* buf, unsigned long frames) {
    memset(buf, 0, frames * 2U);
    sleepMs(10);
    return static_cast<long>(frames);
}
int mockAlsaRecover(void*, int, int) { return 0; }
int mockAlsaPrepare(void*) { return 0; }
int mockAlsaDrop(void*) { return 0; }
int mockAlsaDrain(void*) { return 0; }
int mockAlsaClose(void*) { return 0; }
const char* mockAlsaStrerror(int) { return "mock-alsa-ok"; }

int mockVmostConnect(plat::VmostCallback cb, void* user, int) {
    if (!g_hal) return -1;
    plat::LockGuard lock(g_hal->mu);
    g_hal->vmost_cb = cb;
    g_hal->vmost_user = user;
    return 0;
}
int mockVmostReg(uint8_t, uint8_t) { return 0; }
int mockVmostDereg(uint8_t, uint8_t) { return 0; }
int mockVmostFd(int* fd) {
    if (!g_hal || !fd) return -1;
    *fd = g_hal->vmost_fds[0];
    return (*fd >= 0) ? 0 : -1;
}
int mockVmostProc() { return 0; }
int mockVmostDisc() { return 0; }
int mockVmostSend(void*) { return 0; }

// ---- Simulated iPhone Helpers ----

Bytes sha512Bytes(const Bytes& data) {
    Bytes out(64);
    crypto::sha512(data.empty() ? NULL : &data[0], data.size(), &out[0]);
    return out;
}

Bytes strToBytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

Bytes hkdf32(const Bytes& ikm, const std::string& salt, const std::string& info_label) {
    Bytes out;
    crypto::hkdfSha512(ikm, salt, info_label, 32, out);
    return out;
}

Bytes makeLabelNonce12(const char* label) {
    Bytes n(12, 0);
    memcpy(&n[4], label, 8);
    return n;
}

Bytes encodeBplist(const bplist::Value& v) {
    Bytes b;
    bplist::encode(v, b);
    return b;
}

struct SimPhone {
    plat::Reactor& reactor;
    std::string id;
    crypto::Ed25519KeyPair ltsk;
    std::string acc_id;
    Bytes acc_ltpk;

    plat::TcpConnection control_conn;
    plat::TcpConnection event_conn;
    plat::TcpConnection screen_conn;
    plat::UdpSocket audio_sock;
    plat::UdpSocket timing_sock;

    rtsp::Parser control_parser;
    rtsp::Parser event_parser;
    std::unique_ptr<ControlCipher> control_cipher;
    std::unique_ptr<ControlCipher> event_cipher;
    int cseq;
    Bytes shared_secret;

    std::vector<bplist::Value> event_commands;

    SimPhone(plat::Reactor& r, const std::string& ctrl_id)
        : reactor(r), id(ctrl_id), cseq(0) {
        const Bytes seed = sha512Bytes(strToBytes("sim-phone-seed-" + ctrl_id));
        crypto::ed25519FromSeed(&seed[0], ltsk);
    }

    ~SimPhone() {
        screen_conn.close();
        event_conn.close();
        control_conn.close();
        audio_sock.close();
        timing_sock.close();
    }

    bool connectTcp(plat::TcpConnection& conn, const plat::Address& dest) {
        if (!conn.connect(dest)) return false;
        const int64_t dl = plat::monotonicMillis() + 3000;
        while (conn.connecting() && plat::monotonicMillis() < dl) {
            reactor.runOnce(5);
            const plat::IoStatus st = conn.finishConnect();
            if (st == plat::kIoOk) break;
            if (st == plat::kIoError) return false;
        }
        for (int i = 0; i < 4; ++i) {
            reactor.runOnce(5);
        }
        return conn.isOpen();
    }

    bool sendRaw(plat::TcpConnection& conn, const Bytes& data) {
        if (data.empty()) return true;
        if (conn.send(&data[0], data.size()) != plat::TcpConnection::kSendOk) return false;
        const int64_t dl = plat::monotonicMillis() + 3000;
        while (conn.wantsWrite() && plat::monotonicMillis() < dl) {
            reactor.runOnce(5);
            conn.flush();
        }
        for (int i = 0; i < 2; ++i) {
            reactor.runOnce(5);
        }
        return !conn.wantsWrite();
    }

    bool request(const std::string& method,
                 const std::string& path,
                 const std::string& content_type,
                 const Bytes& body,
                 int& status_out,
                 rtsp::Request& resp_out) {
        ++cseq;
        rtsp::HeaderList hdrs;
        if (!content_type.empty()) {
            hdrs.push_back(rtsp::Header("Content-Type", content_type));
        }
        hdrs.push_back(rtsp::Header("CSeq", rtsp::toDecimal(cseq)));
        hdrs.push_back(rtsp::Header("User-Agent", "AirPlay/770.8.1"));

        Bytes wire;
        rtsp::buildRequest(method, path, "RTSP/1.0", hdrs, body, wire);
        Bytes to_send = wire;
        const bool encrypted = (control_cipher.get() != NULL);
        if (encrypted) {
            to_send.clear();
            if (!control_cipher->encrypt(wire, to_send)) return false;
        }
        if (!sendRaw(control_conn, to_send)) return false;

        std::vector<rtsp::Request> msgs;
        uint8_t buf[16384];
        const int64_t dl = plat::monotonicMillis() + 3000;
        while (msgs.empty() && plat::monotonicMillis() < dl) {
            reactor.runOnce(5);
            size_t n = 0;
            const plat::IoStatus st = control_conn.read(buf, sizeof(buf), n);
            if (st == plat::kIoOk && n > 0) {
                Bytes plain;
                if (encrypted) {
                    if (!control_cipher->feed(buf, n, plain)) return false;
                } else {
                    plain.assign(buf, buf + n);
                }
                if (!plain.empty()) {
                    if (!control_parser.feed(plain, msgs)) return false;
                }
            }
        }
        if (msgs.size() != 1U || !msgs[0].isResponse()) return false;
        resp_out = msgs[0];
        status_out = atoi(resp_out.path.c_str());
        return true;
    }

    bool pairVerify() {
        const Bytes eph_seed = sha512Bytes(strToBytes("sim-phone-eph-seed"));
        crypto::X25519KeyPair eph;
        crypto::x25519FromSecret(&eph_seed[0], eph);

        Items m1;
        m1.push_back(tlv8::Item::fromByte(tlv8::kTagState, 1));
        m1.push_back(tlv8::Item(tlv8::kTagPublicKey, Bytes(eph.public_key, eph.public_key + 32)));
        int status = 0;
        rtsp::Request m2_resp;
        if (!request("POST", "/pair-verify", rtsp::kContentTypePairingTlv8, tlv8::encode(m1), status, m2_resp) ||
            status != 200) {
            return false;
        }
        Items m2;
        if (!tlv8::decode(m2_resp.body, m2)) return false;
        const tlv8::Item* pk_it = tlv8::findFirst(m2, tlv8::kTagPublicKey);
        if (!pk_it || pk_it->value.size() != 32U) return false;
        const Bytes acc_eph = pk_it->value;

        shared_secret.assign(32, 0);
        if (!crypto::x25519SharedSecret(eph.secret_key, &acc_eph[0], &shared_secret[0])) {
            return false;
        }
        const Bytes session_key =
            hkdf32(shared_secret, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info");

        Bytes info_bytes(eph.public_key, eph.public_key + 32);
        info_bytes.insert(info_bytes.end(), id.begin(), id.end());
        info_bytes.insert(info_bytes.end(), acc_eph.begin(), acc_eph.end());
        uint8_t sig[64];
        crypto::ed25519Sign(ltsk.secret_key, &info_bytes[0], info_bytes.size(), sig);

        Items sub;
        sub.push_back(tlv8::Item(tlv8::kTagIdentifier, strToBytes(id)));
        sub.push_back(tlv8::Item(tlv8::kTagSignature, Bytes(sig, sig + 64)));
        const Bytes sub_plain = tlv8::encode(sub);
        const Bytes nonce3 = makeLabelNonce12("PV-Msg03");
        Bytes sub_ct;
        crypto::chacha20Poly1305Seal(&session_key[0], &nonce3[0], NULL, 0,
                                     &sub_plain[0], sub_plain.size(), sub_ct);

        Items m3;
        m3.push_back(tlv8::Item::fromByte(tlv8::kTagState, 3));
        m3.push_back(tlv8::Item(tlv8::kTagEncryptedData, sub_ct));
        rtsp::Request m4_resp;
        if (!request("POST", "/pair-verify", rtsp::kContentTypePairingTlv8, tlv8::encode(m3), status, m4_resp) ||
            status != 200) {
            return false;
        }

        const Bytes c_read = hkdf32(shared_secret, "Control-Salt", "Control-Read-Encryption-Key");
        const Bytes c_write = hkdf32(shared_secret, "Control-Salt", "Control-Write-Encryption-Key");
        control_cipher.reset(new ControlCipher(&c_read[0], &c_write[0]));

        const Bytes e_read = hkdf32(shared_secret, "Events-Salt", "Events-Write-Encryption-Key");
        const Bytes e_write = hkdf32(shared_secret, "Events-Salt", "Events-Read-Encryption-Key");
        event_cipher.reset(new ControlCipher(&e_read[0], &e_write[0]));
        return true;
    }

    Bytes streamOutputKey(uint64_t id_val) const {
        return hkdf32(shared_secret,
                      "DataStream-Salt" + rtsp::toDecimalUnsigned(id_val),
                      "DataStream-Output-Encryption-Key");
    }

    void pumpEventChannel() {
        if (!event_conn.isOpen() || event_cipher.get() == NULL) return;
        uint8_t buf[16384];
        for (;;) {
            size_t n = 0;
            const plat::IoStatus rr = event_conn.read(buf, sizeof(buf), n);
            if (rr != plat::kIoOk || n == 0) break;
            Bytes plain;
            if (!event_cipher->feed(buf, n, plain)) break;
            std::vector<rtsp::Request> msgs;
            if (!plain.empty() && !event_parser.feed(plain, msgs)) break;
            for (size_t i = 0; i < msgs.size(); ++i) {
                if (!msgs[i].isResponse()) {
                    bplist::Value cmd;
                    if (bplist::decode(msgs[i].body, cmd)) {
                        event_commands.push_back(cmd);
                    }
                    rtsp::Response reply(200);
                    Bytes reply_plain;
                    rtsp::buildResponse(msgs[i], reply, reply_plain);
                    Bytes reply_ct;
                    if (event_cipher->encrypt(reply_plain, reply_ct) && !reply_ct.empty()) {
                        event_conn.send(&reply_ct[0], reply_ct.size());
                        event_conn.flush();
                    }
                }
            }
        }
    }
};

TEST_CASE(testCarPlayDaemonEndToEndIntegration) {
#ifdef _WIN32
    return;
#else
    const std::string dir = makeTempDir("cp_daemon_e2e");
    const std::string data_dir = dir + "/data";
    const std::string state_file = dir + "/state";
    const std::string appkey_file = dir + "/appkey";
    const std::string daynight_file = dir + "/daynight";
    const std::string recall_file = dir + "/recall";
    const std::string stop_file = dir + "/STOP";
    const std::string ilm_script = dir + "/mock_ilm.sh";
    const std::string ilm_order_file = dir + "/ilm_order";
    const std::string comp_conf = dir + "/compositor.conf";

    // Write a mock LayerManagerControl script that reports a 1280x480 screen and tracks layer render order
    {
        FILE* f = fopen(ilm_order_file.c_str(), "w");
        REQUIRE(f != NULL);
        fprintf(f, "0(0x0),");
        fclose(f);
    }
    {
        FILE* f = fopen(ilm_script.c_str(), "w");
        REQUIRE(f != NULL);
        fprintf(f,
                "#!/bin/sh\n"
                "ORDER_FILE=\"%s\"\n"
                "case \"$*\" in\n"
                "  *\"get screen\"*)\n"
                "    echo \"screen 0 (0x0)\"\n"
                "    echo \"- resolution: x=1280, y=480\"\n"
                "    echo \"- layer render order: 2147483648(0x80000000),\"\n"
                "    ;;\n"
                "  *\"get layer\"*)\n"
                "    ORDER=$(cat \"$ORDER_FILE\" 2>/dev/null || echo \"0(0x0),\")\n"
                "    echo \"layer 2147483648 (0x80000000)\"\n"
                "    echo \"- visibility: 1\"\n"
                "    echo \"- opacity: 1\"\n"
                "    echo \"- orientation: 0 (up is top)\"\n"
                "    echo \"- source region: x=0, y=0, w=1280, h=480\"\n"
                "    echo \"- destination region: x=0, y=0, w=1280, h=480\"\n"
                "    echo \"- surface render order: $ORDER\"\n"
                "    echo \"- on screen: 0(0x0)\"\n"
                "    ;;\n"
                "  *\"get surfaces\"*)\n"
                "    echo \"1 Surface(s):\"\n"
                "    echo \"- Surface 0 (0x0)\"\n"
                "    ;;\n"
                "  *\"set layer\"*\"render order\"*)\n"
                "    printf \"%%s\" \"$6\" > \"$ORDER_FILE\"\n"
                "    ;;\n"
                "esac\n"
                "exit 0\n",
                ilm_order_file.c_str());
        fclose(f);
        chmod(ilm_script.c_str(), 0755);
    }
    {
        FILE* f = fopen(comp_conf.c_str(), "w");
        REQUIRE(f != NULL);
        fprintf(f, "genivi-flip-renderorder = 1\n");
        fclose(f);
    }

    // Write initial daynight file (1 = day)
    CHECK(plat::writeDayNightFile(daynight_file.c_str(), 1));

    DaemonMockHal hal;
    REQUIRE(hal.initVmostPipe());
    g_hal = &hal;

    char ctrl_name[64];
    snprintf(ctrl_name, sizeof(ctrl_name), "cp-daemon-e2e-%d-%u",
             static_cast<int>(getpid()),
             static_cast<unsigned>(plat::monotonicMillis() & 0xFFFFU));

    plat::CarPlayDaemonConfig cfg;
    cfg.control_port = 0U;
    cfg.bind_loopback_only = true;
    cfg.data_dir = data_dir;
    cfg.control_name = ctrl_name;
    cfg.state_file = state_file;
    cfg.app_key_file = appkey_file;
    cfg.day_night_file = daynight_file;
    cfg.media_recall_file = recall_file;
    cfg.stop_file = stop_file;
    cfg.enable_video = true;
    cfg.enable_audio = true;
    cfg.enable_input = true;
    cfg.enable_control = true;
    cfg.query_display_from_ilm = true;
    cfg.fallback_width = 800U;
    cfg.fallback_height = 480U;
    cfg.touch_enabled = true;
    cfg.menu_exits_to_idrive = true;
    cfg.use_test_touch_udp = true;
    cfg.test_touch_udp_port = 0U;
    cfg.tick_interval_ms = 50;
    cfg.server_config.ntp_request_interval_ms = 0;

    cfg.video_config.ilm_ctl_path = ilm_script;
    cfg.video_config.compositor_conf_path = comp_conf;

    cfg.knob_config.mode = plat::kInputForward;
    cfg.knob_config.query_older_immediately = true;
    cfg.knob_config.use_api_override = true;
    cfg.knob_config.api_override.connect = &mockVmostConnect;
    cfg.knob_config.api_override.shadowRegister = &mockVmostReg;
    cfg.knob_config.api_override.shadowDeregister = &mockVmostDereg;
    cfg.knob_config.api_override.fileDescriptorGet = &mockVmostFd;
    cfg.knob_config.api_override.processMessages = &mockVmostProc;
    cfg.knob_config.api_override.disconnect = &mockVmostDisc;
    cfg.knob_config.api_override.send = &mockVmostSend;

    plat::CarPlayDaemon daemon(cfg);

    // Inject mock video & audio APIs before start()
    plat::XsvApi xsv_api;
    xsv_api.xsv_open = &mockXsvOpen;
    xsv_api.xsv_close = &mockXsvClose;
    xsv_api.xsv_configure_stream = &mockXsvConfigureStream;
    xsv_api.xsv_set_output_dimension = &mockXsvSetOutputDimension;
    xsv_api.xsv_set_input_viewport = &mockXsvSetInputViewport;
    xsv_api.xsv_decode_video_frame = &mockXsvDecodeVideoFrame;
    xsv_api.xsv_start = &mockXsvStart;
    xsv_api.xsv_stop = &mockXsvStop;
    xsv_api.xsv_pause = &mockXsvPause;
    xsv_api.xsv_update = &mockXsvUpdate;
    xsv_api.xsv_enable_frame_events = &mockXsvEnableFrameEvents;
    xsv_api.xsv_disable_frame_events = &mockXsvDisableFrameEvents;
    xsv_api.xsv_receive_event = &mockXsvReceiveEvent;
    xsv_api.xsv_get_event_queue_fd = &mockXsvGetEventQueueFd;
    daemon.video().setXsvApiForTest(xsv_api);

    plat::DrmOmapApi drm_api;
    drm_api.drmOpen = &mockDrmOpen;
    drm_api.drmClose = &mockDrmClose;
    drm_api.omap_device_new = &mockOmapDevNew;
    drm_api.omap_device_del = &mockOmapDevDel;
    drm_api.omap_bo_new = &mockOmapBoNew;
    drm_api.omap_bo_del = &mockOmapBoDel;
    drm_api.omap_bo_dmabuf = &mockOmapBoDmabuf;
    drm_api.omap_bo_map = &mockOmapBoMap;
    daemon.video().setDrmOmapApiForTest(drm_api);

    plat::AlsaApi alsa_api;
    alsa_api.snd_pcm_open = &mockAlsaOpen;
    alsa_api.snd_pcm_set_params = &mockAlsaSetParams;
    alsa_api.snd_pcm_writei = &mockAlsaWritei;
    alsa_api.snd_pcm_readi = &mockAlsaReadi;
    alsa_api.snd_pcm_recover = &mockAlsaRecover;
    alsa_api.snd_pcm_prepare = &mockAlsaPrepare;
    alsa_api.snd_pcm_drop = &mockAlsaDrop;
    alsa_api.snd_pcm_drain = &mockAlsaDrain;
    alsa_api.snd_pcm_close = &mockAlsaClose;
    alsa_api.snd_strerror = &mockAlsaStrerror;
    daemon.audioSink().setAlsaApi(alsa_api);
    daemon.mic().setAlsaApi(alsa_api);

    REQUIRE(daemon.start());
    CHECK(daemon.isStarted());
    // Verified dynamic display resolution from LayerManagerControl!
    CHECK_EQ(1280U, daemon.displayWidth());
    CHECK_EQ(480U, daemon.displayHeight());
    CHECK_EQ(1280, daemon.airplayConfig().main.width_pixels);
    CHECK_EQ(480, daemon.airplayConfig().main.height_pixels);
    REQUIRE(daemon.controlPort() > 0U);
    CHECK(plat::controlAnswers(ctrl_name, 200));

    // Initial state file is "connecting <pid> 0"
    plat::ServiceState st0 = plat::readServiceStateFile(state_file.c_str(), ctrl_name);
    CHECK(st0.is("connecting"));
    CHECK_EQ(0, st0.overlay);

    // Pre-register simulated iPhone pairing in daemon's FilePairingStore
    SimPhone phone(daemon.reactor(), "AA11BB22-CC33-44DD-88EE-FF0011223344");
    phone.acc_id = daemon.accessoryIdentity().pairing_id;
    phone.acc_ltpk.assign(daemon.accessoryIdentity().keys.public_key,
                          daemon.accessoryIdentity().keys.public_key + 32);
    REQUIRE(daemon.pairingStore() != NULL);
    REQUIRE(daemon.pairingStore()->save(phone.id, phone.ltsk.public_key));

    // Connect control TCP & pair-verify
    REQUIRE(phone.connectTcp(phone.control_conn, plat::Address::ipv4Loopback(daemon.controlPort())));
    REQUIRE(phone.pairVerify());

    // Fetch encrypted GET /info and verify 1280x480 display config
    int status = 0;
    rtsp::Request info_resp;
    REQUIRE(phone.request("GET", "/info", "", Bytes(), status, info_resp));
    CHECK_EQ(200, status);
    bplist::Value info_plist;
    REQUIRE(bplist::decode(info_resp.body, info_plist));
    const bplist::Value* displays = info_plist.find("displays");
    REQUIRE(displays != NULL && displays->isArray() && displays->asArray().size() == 1U);
    int64_t info_w = 0;
    int64_t info_h = 0;
    CHECK(displays->asArray()[0].getInt("widthPixels", info_w));
    CHECK(displays->asArray()[0].getInt("heightPixels", info_h));
    CHECK_EQ(static_cast<int64_t>(1280), info_w);
    CHECK_EQ(static_cast<int64_t>(480), info_h);

    // Session SETUP -> opens timing + event channel
    REQUIRE(phone.timing_sock.open(plat::Address::ipv4Loopback(0)));
    bplist::Value setup_sess = bplist::Value::makeDict();
    setup_sess.set("deviceID", bplist::Value::makeString("AA:BB:CC:DD:EE:FF"));
    setup_sess.set("name", bplist::Value::makeString("Ozzy iPhone"));
    setup_sess.set("model", bplist::Value::makeString("iPhone15,2"));
    setup_sess.set("timingPort", bplist::Value::makeInt(phone.timing_sock.port()));
    rtsp::Request setup_resp;
    REQUIRE(phone.request("SETUP", "rtsp://127.0.0.1/session", rtsp::kContentTypeBinaryPlist,
                          encodeBplist(setup_sess), status, setup_resp));
    CHECK_EQ(200, status);
    bplist::Value setup_reply;
    REQUIRE(bplist::decode(setup_resp.body, setup_reply));
    int64_t ev_port = 0;
    REQUIRE(setup_reply.getInt("eventPort", ev_port) && ev_port > 0);
    REQUIRE(phone.connectTcp(phone.event_conn,
                             plat::Address::ipv4Loopback(static_cast<uint16_t>(ev_port))));

    // Pump reactor so EventChannel accepts and flushes initial night mode
    for (int i = 0; i < 20; ++i) {
        daemon.reactor().runOnce(5);
        phone.pumpEventChannel();
    }
    CHECK(daemon.hasActiveSession());
    CHECK(daemon.isPictureShown());
    plat::ServiceState st_conn = plat::readServiceStateFile(state_file.c_str(), ctrl_name);
    CHECK(st_conn.is("connected"));
    CHECK_EQ(1, st_conn.overlay);

    // SETUP screen stream (110) and main audio stream (100, 44.1kHz stereo LPCM = 0x4000)
    const uint64_t screen_conn_id = 0x1122334455667788ULL;
    const uint64_t audio_conn_id = 0x19AABBCCDDEEFF01ULL;
    bplist::Value s110 = bplist::Value::makeDict();
    s110.set("type", bplist::Value::makeInt(110));
    s110.set("streamConnectionID", bplist::Value::makeUInt(screen_conn_id));

    bplist::Value s100 = bplist::Value::makeDict();
    s100.set("type", bplist::Value::makeInt(100));
    s100.set("audioType", bplist::Value::makeString("media"));
    s100.set("audioFormat", bplist::Value::makeInt(0x4000));
    s100.set("streamConnectionID", bplist::Value::makeUInt(audio_conn_id));

    bplist::Value::Array streams_vec;
    streams_vec.push_back(s110);
    streams_vec.push_back(s100);
    bplist::Value setup_streams = bplist::Value::makeDict();
    setup_streams.set("streams", bplist::Value::makeArray(streams_vec));

    rtsp::Request st_resp;
    REQUIRE(phone.request("SETUP", "rtsp://127.0.0.1/streams", rtsp::kContentTypeBinaryPlist,
                          encodeBplist(setup_streams), status, st_resp));
    CHECK_EQ(200, status);
    bplist::Value st_reply;
    REQUIRE(bplist::decode(st_resp.body, st_reply));
    const bplist::Value* rstreams = st_reply.find("streams");
    REQUIRE(rstreams != NULL && rstreams->isArray() && rstreams->asArray().size() == 2U);
    int64_t screen_port = 0;
    int64_t audio_port = 0;
    REQUIRE(rstreams->asArray()[0].getInt("dataPort", screen_port) && screen_port > 0);
    REQUIRE(rstreams->asArray()[1].getInt("dataPort", audio_port) && audio_port > 0);

    // Connect screen TCP and send avcC config + encrypted IDR video frame
    REQUIRE(phone.connectTcp(phone.screen_conn,
                             plat::Address::ipv4Loopback(static_cast<uint16_t>(screen_port))));

    const uint8_t avcc_raw[] = {
        0x01U, 0x64U, 0x00U, 0x1FU, 0xFFU, 0xE1U, 0x00U, 0x04U,
        0x67U, 0x64U, 0x00U, 0x1FU, 0x01U, 0x00U, 0x04U, 0x68U,
        0xEBU, 0xECU, 0xB2U
    };
    Bytes cfg_pkt(128, 0);
    const uint32_t cfg_len = static_cast<uint32_t>(sizeof(avcc_raw));
    cfg_pkt[0] = static_cast<uint8_t>(cfg_len & 0xFFU);
    cfg_pkt[1] = static_cast<uint8_t>((cfg_len >> 8) & 0xFFU);
    cfg_pkt[2] = static_cast<uint8_t>((cfg_len >> 16) & 0xFFU);
    cfg_pkt[3] = static_cast<uint8_t>((cfg_len >> 24) & 0xFFU);
    cfg_pkt[4] = 1U;  // kOpVideoConfig = 1 (LE16)
    cfg_pkt[5] = 0U;
    const float cfg_w = 1280.0f;
    const float cfg_h = 480.0f;
    memcpy(&cfg_pkt[16], &cfg_w, 4);
    memcpy(&cfg_pkt[20], &cfg_h, 4);
    cfg_pkt.insert(cfg_pkt.end(), avcc_raw, avcc_raw + sizeof(avcc_raw));

    // Build one encrypted H.264 IDR NALU frame (type 5: 0x65), counter=0, AAD = 128-byte header
    const uint8_t idr_nalu[] = {0x00U, 0x00U, 0x00U, 0x04U, 0x65U, 0x88U, 0x84U, 0x21U};
    const Bytes screen_key = phone.streamOutputKey(screen_conn_id);
    Bytes frm_pkt(128, 0);
    const uint32_t frm_len = static_cast<uint32_t>(sizeof(idr_nalu) + 16U);
    frm_pkt[0] = static_cast<uint8_t>(frm_len & 0xFFU);
    frm_pkt[1] = static_cast<uint8_t>((frm_len >> 8) & 0xFFU);
    frm_pkt[2] = static_cast<uint8_t>((frm_len >> 16) & 0xFFU);
    frm_pkt[3] = static_cast<uint8_t>((frm_len >> 24) & 0xFFU);
    frm_pkt[4] = 0U;  // kOpVideoFrame = 0
    frm_pkt[5] = 0U;
    uint8_t frame_nonce[12];
    crypto::makeCounterNonce(0ULL, frame_nonce);
    Bytes sealed_idr;
    crypto::chacha20Poly1305Seal(&screen_key[0], frame_nonce, &frm_pkt[0], frm_pkt.size(),
                                 idr_nalu, sizeof(idr_nalu), sealed_idr);
    frm_pkt.insert(frm_pkt.end(), sealed_idr.begin(), sealed_idr.end());

    REQUIRE(phone.sendRaw(phone.screen_conn, cfg_pkt));
    REQUIRE(phone.sendRaw(phone.screen_conn, frm_pkt));

    // Send one encrypted RTP audio packet to audio_port
    REQUIRE(phone.audio_sock.open(plat::Address::ipv4Loopback(0)));
    const Bytes audio_out_key = phone.streamOutputKey(audio_conn_id);
    uint8_t rtp_hdr[audio::kRtpHeaderBytes];
    audio::buildRtpHeader(96U, true, 1U, 0U, 0x12345678U, rtp_hdr);
    const uint8_t pcm_be[16] = {0, 100, 0, 100, 0, 200, 0, 200, 0, 50, 0, 50, 0, 25, 0, 25};
    Bytes rtp_pkt;
    REQUIRE(audio::sealPacket(&audio_out_key[0], rtp_hdr, pcm_be, sizeof(pcm_be), 1ULL, rtp_pkt));
    CHECK_EQ(static_cast<int>(plat::kIoOk),
             static_cast<int>(phone.audio_sock.sendTo(
                 &rtp_pkt[0], rtp_pkt.size(),
                 plat::Address::ipv4Loopback(static_cast<uint16_t>(audio_port)))));

    // Pump reactor until frame is decoded, picture is ready, and input bridge owns the screen
    const int64_t frame_dl = plat::monotonicMillis() + 2000;
    while (plat::monotonicMillis() < frame_dl) {
        daemon.reactor().runOnce(10);
        phone.pumpEventChannel();
        if (daemon.video().firstFrameSeen() &&
            daemon.inputBridge() != NULL &&
            daemon.inputBridge()->owned()) {
            break;
        }
    }
    CHECK(daemon.video().firstFrameSeen());
    REQUIRE(daemon.inputBridge() != NULL);
    CHECK(daemon.inputBridge()->owned());

    // Wait for ALSA worker thread to write the audio frames
    const int64_t audio_dl = plat::monotonicMillis() + 2000;
    while (plat::monotonicMillis() < audio_dl) {
        {
            plat::LockGuard lock(hal.mu);
            if (hal.alsa_frames_written > 0ULL) break;
        }
        sleepMs(5);
    }
    {
        plat::LockGuard lock(hal.mu);
        CHECK(hal.alsa_frames_written > 0ULL);
    }

    // Send a touch UDP frame to daemon.touch().boundUdpPort() -> phone receives hidSendReport!
    const size_t cmds_before_touch = phone.event_commands.size();
    plat::UdpSocket touch_sender;
    REQUIRE(touch_sender.open(plat::Address::ipv4Loopback(0)));
    uint8_t touch_frame[plat::touchpdu::kFrameBytes];
    plat::RawTouchContact tc;
    tc.id = 0;
    tc.state = 1;
    tc.x = 640;
    tc.y = 240;
    plat::buildTouchFrame(touch_frame, &tc, 1, 1U, 0x10U);
    CHECK_EQ(static_cast<int>(plat::kIoOk),
             static_cast<int>(touch_sender.sendTo(
                 touch_frame, sizeof(touch_frame),
                 plat::Address::ipv4Loopback(daemon.touch().boundUdpPort()))));

    const int64_t touch_dl = plat::monotonicMillis() + 2000;
    while (plat::monotonicMillis() < touch_dl) {
        daemon.reactor().runOnce(10);
        phone.pumpEventChannel();
        if (phone.event_commands.size() > cmds_before_touch) {
            break;
        }
    }
    CHECK(phone.event_commands.size() > cmds_before_touch);
    CHECK(daemon.inputBridge()->touchReportsSent() >= 1ULL);

    // Send "daynight 2" over EvoControl -> phone receives setNightMode(true)
    const size_t cmds_before_dn = phone.event_commands.size();
    CHECK(plat::sendControl(ctrl_name, "daynight 2"));
    const int64_t dn_dl = plat::monotonicMillis() + 2000;
    while (plat::monotonicMillis() < dn_dl) {
        daemon.reactor().runOnce(10);
        phone.pumpEventChannel();
        if (phone.event_commands.size() > cmds_before_dn) {
            break;
        }
    }
    CHECK(daemon.isNightMode());
    CHECK(phone.event_commands.size() > cmds_before_dn);

    // Send "gear 2" (reverse camera) -> surface hides immediately & touch is released
    CHECK(plat::sendControl(ctrl_name, "gear 2"));
    const int64_t gear_dl = plat::monotonicMillis() + 2000;
    while (plat::monotonicMillis() < gear_dl) {
        daemon.reactor().runOnce(10);
        phone.pumpEventChannel();
        if (daemon.isReverseGear()) {
            break;
        }
    }
    CHECK(daemon.isReverseGear());
    CHECK(!daemon.isPictureShown());
    CHECK(!daemon.inputBridge()->owned());
    plat::ServiceState st_rev = plat::readServiceStateFile(state_file.c_str(), ctrl_name);
    CHECK_EQ(0, st_rev.overlay);

    // Send "gear 0" -> surface and input ownership restored
    CHECK(plat::sendControl(ctrl_name, "gear 0"));
    const int64_t gear0_dl = plat::monotonicMillis() + 2000;
    while (plat::monotonicMillis() < gear0_dl) {
        daemon.reactor().runOnce(10);
        phone.pumpEventChannel();
        if (!daemon.isReverseGear()) {
            break;
        }
    }
    CHECK(!daemon.isReverseGear());
    CHECK(daemon.isPictureShown());
    CHECK(daemon.inputBridge()->owned());

    // Press BACK key -> writes appkey file while staying on screen
    daemon.inputBridge()->handleHardKey(plat::kCcsKeyBack, true, "BACK");
    daemon.inputBridge()->handleHardKey(plat::kCcsKeyBack, false, "BACK");
    CHECK(plat::pathExists(appkey_file));
    CHECK(daemon.isPictureShown());

    // Press MENU key -> steps CarPlay aside and removes appkey file
    daemon.inputBridge()->handleHardKey(plat::kCcsKeyMenu, true, "MENU");
    daemon.inputBridge()->handleHardKey(plat::kCcsKeyMenu, false, "MENU");
    CHECK(!daemon.isFocusOwned());
    CHECK(!daemon.isPictureShown());
    CHECK(!plat::pathExists(appkey_file));

    // Double-press MEDIA while CarPlay is hidden -> writes media recall file!
    daemon.inputBridge()->handleHardKey(plat::kCcsKeyMedia, true, "MEDIA");
    daemon.inputBridge()->handleHardKey(plat::kCcsKeyMedia, false, "MEDIA");
    daemon.inputBridge()->handleHardKey(plat::kCcsKeyMedia, true, "MEDIA");
    daemon.inputBridge()->handleHardKey(plat::kCcsKeyMedia, false, "MEDIA");
    CHECK(plat::takeMediaRecall(
        recall_file.c_str(),
        static_cast<int>(getpid()),
        static_cast<uint32_t>(plat::monotonicMillis())));

    // Send "show" over EvoControl -> brings CarPlay back on screen and requests keyframe
    CHECK(plat::sendControl(ctrl_name, "show"));
    const int64_t show_dl = plat::monotonicMillis() + 2000;
    while (plat::monotonicMillis() < show_dl) {
        daemon.reactor().runOnce(10);
        phone.pumpEventChannel();
        if (daemon.isFocusOwned() && daemon.isPictureShown()) {
            break;
        }
    }
    CHECK(daemon.isFocusOwned());
    CHECK(daemon.isPictureShown());

    // Clean stop
    daemon.stop();
    CHECK(!daemon.isStarted());
    CHECK(!plat::pathExists(state_file));

    hal.closeVmostPipe();
    g_hal = NULL;
    removeTempDir(dir);
#endif
}

TEST_CASE(testCarPlayDaemonCliBinary) {
#ifdef _WIN32
    return;
#else
    const std::string daemon_bin = siblingBinaryPath("carplayd");

    std::vector<std::string> help_args;
    help_args.push_back("--help");
    std::string out;
    CHECK(plat::runCommand(daemon_bin.c_str(), help_args, out));
    CHECK(out.find("Usage:") != std::string::npos);
    CHECK(out.find("--data-dir") != std::string::npos);

    std::vector<std::string> ver_args;
    ver_args.push_back("--version");
    out.clear();
    CHECK(plat::runCommand(daemon_bin.c_str(), ver_args, out));
    CHECK(out.find("carplayd") != std::string::npos);

    std::vector<std::string> bad_args;
    bad_args.push_back("--unknown-flag");
    out.clear();
    CHECK(!plat::runCommand(daemon_bin.c_str(), bad_args, out));
#endif
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 0 && argv != NULL && argv[0] != NULL) {
        g_argv0_exe = argv[0];
    }
#ifndef _WIN32
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--service") == 0) {
            // Mock hung service / supervisor spawned by launchDaemonProcess(): ignores SIGTERM.
            signal(SIGTERM, SIG_IGN);
            printf("MOCK_SERVICE_PID=%d\n", static_cast<int>(getpid()));
            fflush(stdout);
            for (int tick = 0; tick < 300; ++tick) {
                sleepMs(100);
            }
            return 0;
        }
        if (strcmp(argv[i], "--mock-hang") == 0) {
            for (int tick = 0; tick < 300; ++tick) {
                sleepMs(100);
            }
            return 0;
        }
    }
#endif
    return test_support::runAll("test_carplay_daemon");
}
