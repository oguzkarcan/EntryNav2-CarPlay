// BMW HU_ENTRYNAV2 HmiMain3D RHMI plugin (`libEntryCarPlay.so`).
//
// Zero link-time dependency on BMW's proprietary `libAppFramework.A.so` / `libCoreFramework.A.so`:
// all framework symbols are resolved at runtime from `HmiMain3D`'s global symbol table via
// `dlsym(RTLD_DEFAULT, ...)` (or injected via `entryCarPlaySetFrameworkApiForTest` in unit tests).
//
// Exception safety: this library is dlopen()'d into `HmiMain3D`. Every host-callable function,
// registered RHMI/CDS delegate, posted runnable, and pthread entry point catches `...` so no C++
// exception can ever unwind into the host or terminate the process. Global path configuration uses
// static constant pointers and fixed buffers so dlopen() static initialization cannot throw.

#include "carplay/platform/entry_carplay_plugin.hpp"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <new>
#include <string>

#include "carplay/platform/evo_control.hpp"
#include "carplay/platform/file_util.hpp"
#include "carplay/platform/hold_machine.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/peek_timing.hpp"
#include "carplay/platform/service_contract.hpp"

namespace carplay {
namespace platform {
namespace hmi {

namespace {

static const size_t kPluginAppStorage = 0x200U;
static const int kSlotOnError = 21;
static const int kSlotOnInit = 22;
static const int kSlotOnFinalize = 23;
static const unsigned kStatusPollMs = 1000U;

static const long kDefaultStopTermMs = 3000L;
static const long kDefaultStopKillMs = 8000L;
static const long kDefaultStopGiveupMs = 15000L;
static const long kDefaultLaunchDebounceMs = 3000L;

struct AppRunnable {
    void** vptr;
    void* vtbl[5];
};

BmwFrameworkApi g_fw;
bool g_fw_injected = false;

// Trivial static initialization only (pointers to literals + zero-filled buffers)
// so dlopen() never executes throwing heap allocations.
const char* g_data_dir = contract::kDataDir;
const char* g_control_name = contract::kControlName;
const char* g_state_file = contract::kStateFile;
const char* g_app_key_file = contract::kAppKeyFile;
const char* g_day_night_file = contract::kDayNightFile;
const char* g_media_recall_file = contract::kMediaRecallFile;
const char* g_stop_file = contract::kServiceStop;
const char* g_service_bin = contract::kService;
const char* g_supervisor_bin = contract::kSupervisor;
const char* g_service_log = contract::kServiceLog;

char g_data_dir_buf[512] = "";
char g_control_name_buf[128] = "";
char g_state_file_buf[576] = "";
char g_app_key_file_buf[576] = "";
char g_day_night_file_buf[576] = "";
char g_media_recall_file_buf[576] = "";
char g_stop_file_buf[576] = "";
char g_service_bin_buf[576] = "";
char g_supervisor_bin_buf[576] = "";
char g_service_log_buf[576] = "";

void* g_app = NULL;
void* g_run_app = NULL;
void* g_vtbl[36];
long g_init_time = 0;
bool g_stable_marked = false;
bool g_autostart_done = false;
unsigned g_shown_text = rhmi::kTextDefault;
unsigned g_shown_row = rhmi::kTextStart;
int g_stop_shown = -1;
bool g_call_line[2] = {false, false};
int g_last_gear = kGearUnknown;
int g_last_day_night = -1000;
int g_last_drive_mode[2] = {-1000, -1000};
long g_drive_mode_sub_at = -1;

AppRunnable g_status_runnable;
AppRunnable g_sub_runnable;

#ifndef _WIN32
pthread_mutex_t g_child_mu = PTHREAD_MUTEX_INITIALIZER;
pid_t g_child_pid = 0;
bool g_child_is_supervisor = false;
uint64_t g_child_gen = 0ULL;
#endif

int64_t g_last_launch_ms = -1;
long g_stop_term_ms = kDefaultStopTermMs;
long g_stop_kill_ms = kDefaultStopKillMs;
long g_stop_giveup_ms = kDefaultStopGiveupMs;
long g_launch_debounce_ms = kDefaultLaunchDebounceMs;

bool g_stop_pending = false;
int64_t g_stop_start_ms = 0;
int g_stop_stage = 0;
#ifndef _WIN32
pid_t g_stop_pid = 0;
#endif
bool g_stop_from_child = false;
uint64_t g_stop_child_gen = 0ULL;

long monoSeconds() {
    return static_cast<long>(monotonicMillis() / 1000);
}

// Stack-only path formatting: safe to call from catch(...) without throwing.
void appLog(const char* fmt, ...) {
    if (g_data_dir == NULL || g_data_dir[0] == '\0') {
        return;
    }
    char log_path[576];
    const int n = snprintf(log_path, sizeof(log_path), "%s/app.log", g_data_dir);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(log_path)) {
        return;
    }
    FILE* f = fopen(log_path, "a");
    if (!f) {
        return;
    }
    fprintf(f, "[%ld] ", monoSeconds());
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fprintf(f, "\n");
    fclose(f);
}

void copyPathOverride(char* buf, size_t cap, const char* src, const char*& target) {
    if (src == NULL) {
        return;
    }
    const int n = snprintf(buf, cap, "%s", src);
    if (n >= 0 && static_cast<size_t>(n) < cap) {
        target = buf;
    }
}

void resetPluginConfigToDefaults() {
    g_data_dir = contract::kDataDir;
    g_control_name = contract::kControlName;
    g_state_file = contract::kStateFile;
    g_app_key_file = contract::kAppKeyFile;
    g_day_night_file = contract::kDayNightFile;
    g_media_recall_file = contract::kMediaRecallFile;
    g_stop_file = contract::kServiceStop;
    g_service_bin = contract::kService;
    g_supervisor_bin = contract::kSupervisor;
    g_service_log = contract::kServiceLog;
    g_stop_term_ms = kDefaultStopTermMs;
    g_stop_kill_ms = kDefaultStopKillMs;
    g_stop_giveup_ms = kDefaultStopGiveupMs;
    g_launch_debounce_ms = kDefaultLaunchDebounceMs;
}

void clearPendingStop() {
    g_stop_pending = false;
    g_stop_start_ms = 0;
    g_stop_stage = 0;
#ifndef _WIN32
    g_stop_pid = 0;
#endif
    g_stop_from_child = false;
    g_stop_child_gen = 0ULL;
}

void resetSessionRuntimeState() {
    clearPendingStop();
    g_last_launch_ms = -1;
    g_init_time = 0;
    g_stable_marked = false;
    g_autostart_done = false;
    g_shown_text = rhmi::kTextDefault;
    g_shown_row = rhmi::kTextStart;
    g_stop_shown = -1;
    g_call_line[0] = false;
    g_call_line[1] = false;
    g_last_gear = kGearUnknown;
    g_last_day_night = -1000;
    g_last_drive_mode[0] = -1000;
    g_last_drive_mode[1] = -1000;
    g_drive_mode_sub_at = -1;
}

void runnableNoop(void*) {
    try {
    } catch (...) {
    }
}

void makeRunnable(AppRunnable& r, void (*run_fn)(void*)) {
    memset(&r, 0, sizeof(r));
    if (g_fw.runnable_vtable != NULL) {
        memcpy(r.vtbl, g_fw.runnable_vtable, 5 * sizeof(void*));
    }
    r.vtbl[2] = reinterpret_cast<void*>(&runnableNoop);
    r.vtbl[3] = reinterpret_cast<void*>(&runnableNoop);
    r.vtbl[4] = reinterpret_cast<void*>(run_fn);
    r.vptr = r.vtbl + 2;
}

void narrowU16(const BmwBasicStringU16& value, char* text, size_t cap) {
    size_t n = 0U;
    const uint16_t* p = value.data;
    while (p != NULL && p[n] != 0U && n + 1U < cap) {
        text[n] = (p[n] < 0x80U) ? static_cast<char>(p[n]) : '?';
        ++n;
    }
    if (cap > 0U) {
        text[n] = '\0';
    }
}

bool parcelBool(const BmwParcelStorage& parcel) {
    bool b = false;
    if (g_fw.parcel_read_bool != NULL) {
        g_fw.parcel_read_bool(&parcel, b);
    }
    return b;
}

void triggerFocusEvent(void* app, unsigned event_id) {
    if (app != NULL && g_fw.trigger_event != NULL) {
        g_fw.trigger_event(app, event_id);
    }
}

void triggerPopupEvent(void* app, unsigned event_id, bool open) {
    if (app != NULL && g_fw.parcel_ctor_bool != NULL &&
        g_fw.trigger_event_parcel != NULL && g_fw.parcel_dtor != NULL) {
        BmwParcelStorage p;
        memset(&p, 0, sizeof(p));
        g_fw.parcel_ctor_bool(&p, open);
        g_fw.trigger_event_parcel(app, event_id, p);
        g_fw.parcel_dtor(&p);
    }
}

void updateTextModel(void* app, unsigned model_id, unsigned text_id) {
    if (app != NULL && g_fw.text_id_ctor != NULL && g_fw.update_model_text != NULL) {
        BmwTextIdStorage t;
        memset(&t, 0, sizeof(t));
        g_fw.text_id_ctor(&t, text_id);
        g_fw.update_model_text(app, model_id, t);
    }
}

void setComponentVisible(void* app, unsigned comp_id, bool visible) {
    if (app != NULL && g_fw.parcel_ctor_bool != NULL &&
        g_fw.set_property != NULL && g_fw.parcel_dtor != NULL) {
        BmwParcelStorage p;
        memset(&p, 0, sizeof(p));
        g_fw.parcel_ctor_bool(&p, visible);
        g_fw.set_property(app, comp_id, rhmi::kPropVisible, p);
        g_fw.parcel_dtor(&p);
    }
}

void addCdsProperty(void* app,
                    const char* prop_name,
                    bool (*stub)(void*, const BmwBasicStringU16&)) {
    if (app != NULL && g_fw.bstr_ctor_cstr != NULL &&
        g_fw.cds_add_handler != NULL && g_fw.bstr_dtor != NULL) {
        BmwBasicStringChar s;
        s.data = NULL;
        g_fw.bstr_ctor_cstr(&s, prop_name);
        BmwCdsDelegate d;
        d.object = app;
        d.stub = stub;
        g_fw.cds_add_handler(app, s, 0U, d);
        g_fw.bstr_dtor(&s);
    }
}

#ifndef _WIN32
const char* pathBasename(const char* p) {
    if (!p) {
        return "";
    }
    const char* slash = strrchr(p, '/');
    return slash ? (slash + 1) : p;
}

bool isZombiePid(pid_t pid) {
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

bool pidAliveNotZombie(pid_t pid) {
    if (pid <= 1) {
        return false;
    }
    if (kill(pid, 0) != 0 && errno != EPERM) {
        return false;
    }
    return !isZombiePid(pid);
}

// Verify a PID obtained from the state file before sending SIGTERM/SIGKILL,
// guarding against PID reuse or a stale/corrupted state file.
bool verifyDaemonPid(pid_t pid) {
    if (pid <= 1 || pid == getpid()) {
        return false;
    }
    if (!pidAliveNotZombie(pid)) {
        return false;
    }
    const char* expected = pathBasename(
        (g_service_bin != NULL && g_service_bin[0] != '\0') ? g_service_bin : contract::kService);
    if (expected[0] == '\0') {
        expected = "carplayd";
    }

    char proc_exe[64];
    snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", static_cast<int>(pid));
    char exe_buf[512];
    const ssize_t rlen = readlink(proc_exe, exe_buf, sizeof(exe_buf) - 1U);
    bool under_qemu = false;
    if (rlen > 0) {
        exe_buf[rlen] = '\0';
        static const char kDeleted[] = " (deleted)";
        const size_t del_len = sizeof(kDeleted) - 1U;
        const size_t elen = static_cast<size_t>(rlen);
        if (elen > del_len && strcmp(exe_buf + elen - del_len, kDeleted) == 0) {
            exe_buf[elen - del_len] = '\0';
        }
        const char* exe_base = pathBasename(exe_buf);
        if (strcmp(exe_base, expected) == 0) {
            return true;
        }
        if (strncmp(exe_base, "qemu-", 5) == 0) {
            under_qemu = true;
        } else {
            return false;
        }
    }

    // Fallback to /proc/<pid>/cmdline only when running under QEMU user emulation
    // (where /proc/<pid>/exe points to qemu-arm*) or when /proc/<pid>/exe was unreadable.
    char proc_cmd[64];
    snprintf(proc_cmd, sizeof(proc_cmd), "/proc/%d/cmdline", static_cast<int>(pid));
    FILE* f = fopen(proc_cmd, "r");
    if (!f) {
        return false;
    }
    char cmd_buf[512];
    const size_t cn = fread(cmd_buf, 1, sizeof(cmd_buf) - 1U, f);
    fclose(f);
    if (cn == 0U) {
        return false;
    }
    cmd_buf[cn] = '\0';
    if (strcmp(pathBasename(cmd_buf), expected) == 0) {
        return true;
    }
    if (under_qemu) {
        const size_t arg0_len = strlen(cmd_buf);
        if (arg0_len + 1U < cn) {
            const char* arg1 = cmd_buf + arg0_len + 1U;
            if (strcmp(pathBasename(arg1), expected) == 0) {
                return true;
            }
        }
    }
    return false;
}

void ensureParentDir(const char* path) {
    if (!path || !path[0]) {
        return;
    }
    const char* slash = strrchr(path, '/');
    if (slash == NULL || slash == path) {
        return;
    }
    const size_t len = static_cast<size_t>(slash - path);
    if (len >= 512U) {
        return;
    }
    char dir[512];
    memcpy(dir, path, len);
    dir[len] = '\0';
    mkdir(dir, 0755);
}

void createStopFile(const char* path) {
    if (!path || !path[0]) {
        return;
    }
    ensureParentDir(path);
    const int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (fd >= 0) {
        close(fd);
    }
}

// The daemon/supervisor is our child: without a waitpid() it stays a zombie after it exits,
// and kill(pid, 0) on a zombie still succeeds, so the menu would keep showing a dead service
// as running until HmiMain3D restarts.
void* reapDaemonChild(void* arg) {
    try {
        const pid_t pid = static_cast<pid_t>(reinterpret_cast<intptr_t>(arg));
        int status = 0;
        pid_t r = -1;
        do {
            r = waitpid(pid, &status, 0);
        } while (r < 0 && errno == EINTR);
        if (r == pid) {
            pthread_mutex_lock(&g_child_mu);
            if (g_child_pid == pid) {
                g_child_pid = 0;
                g_child_is_supervisor = false;
            }
            pthread_mutex_unlock(&g_child_mu);
            appLog("launch: child pid %d ended (%s %d)%s",
                   static_cast<int>(pid),
                   WIFEXITED(status) ? "exit" : "signal",
                   WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status),
                   (WIFEXITED(status) && WEXITSTATUS(status) == 127)
                       ? " : 127 = start refused before/at exec"
                       : "");
        }
    } catch (...) {
    }
    return NULL;
}

void startDaemonReaper(pid_t pid) {
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        return;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t tid;
    const int rc = pthread_create(&tid, &attr, &reapDaemonChild,
                                  reinterpret_cast<void*>(static_cast<intptr_t>(pid)));
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        appLog("launch: reaper thread for pid %d failed: %s", static_cast<int>(pid), strerror(rc));
    }
}
#endif

ServiceState readCurrentServiceState() {
    ServiceState d = readServiceStateFile(g_state_file, g_control_name);
#ifndef _WIN32
    if (d.pid == 0) {
        pthread_mutex_lock(&g_child_mu);
        const pid_t cur_child = g_child_pid;
        const bool cur_is_sup = g_child_is_supervisor;
        pthread_mutex_unlock(&g_child_mu);
        if (cur_child > 1 && pidAliveNotZombie(cur_child)) {
            snprintf(d.state, sizeof(d.state), "%s", "connecting");
            d.pid = cur_is_sup ? -1 : static_cast<int>(cur_child);
            d.overlay = 0;
        }
    }
#endif
    return d;
}

void launchDaemonProcess() {
#ifndef _WIN32
    // The state file appears only once the daemon is up; a second Start press
    // inside the debounce window must not spawn a second instance.
    const int64_t launch_now_ms = monotonicMillis();
    if (g_last_launch_ms >= 0 && launch_now_ms - g_last_launch_ms < g_launch_debounce_ms) {
        return;
    }

    pthread_mutex_lock(&g_child_mu);
    const pid_t existing_child = g_child_pid;
    pthread_mutex_unlock(&g_child_mu);
    if (existing_child > 1 && pidAliveNotZombie(existing_child)) {
        appLog("launch: child pid %d still running", static_cast<int>(existing_child));
        return;
    }

    const char* bin = g_supervisor_bin;
    bool is_supervisor = true;
    struct stat st;
    if (bin == NULL || bin[0] == '\0' || stat(bin, &st) != 0 || !S_ISREG(st.st_mode)) {
        bin = g_service_bin;
        is_supervisor = false;
        if (bin == NULL || bin[0] == '\0' || stat(bin, &st) != 0 || !S_ISREG(st.st_mode)) {
            appLog("launch: neither %s nor %s exists",
                   g_supervisor_bin ? g_supervisor_bin : "(null)",
                   g_service_bin ? g_service_bin : "(null)");
            return;
        }
    }

    // Clear any prior stop request before spawning so a fresh Start is never killed
    // by a leftover STOP file or pending escalation state.
    if (g_stop_file != NULL && g_stop_file[0] != '\0') {
        unlink(g_stop_file);
    }
    clearPendingStop();

    static const char* const kEnv[] = {
        "PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin",
        "LD_LIBRARY_PATH=/usr/local/lib:/opt/hmi/lib:/usr/lib:/lib",
        "XDG_RUNTIME_DIR=/run/system/0",
        "WAYLAND_DISPLAY=wayland-0",
        "HOME=/tmp",
        NULL
    };
    char* argv[] = {
        const_cast<char*>(bin),
        const_cast<char*>("--service"),
        NULL
    };
    int in_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int out_fd = open(g_service_log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (in_fd < 0 || out_fd < 0) {
        if (in_fd >= 0) close(in_fd);
        if (out_fd >= 0) close(out_fd);
        return;
    }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, in_fd, 0);
    posix_spawn_file_actions_adddup2(&fa, out_fd, 1);
    posix_spawn_file_actions_adddup2(&fa, out_fd, 2);

    posix_spawnattr_t at;
    if (initServiceSpawnAttr(&at) == 0) {
        pid_t pid = -1;
        const int rc = posix_spawn(
            &pid, bin, &fa, &at, argv, const_cast<char* const*>(kEnv));
        posix_spawnattr_destroy(&at);
        if (rc == 0) {
            g_last_launch_ms = launch_now_ms;
            pthread_mutex_lock(&g_child_mu);
            g_child_pid = pid;
            g_child_is_supervisor = is_supervisor;
            ++g_child_gen;
            pthread_mutex_unlock(&g_child_mu);
            appLog("launch: spawned %s pid %d (supervisor=%d)",
                   bin, static_cast<int>(pid), is_supervisor ? 1 : 0);
            startDaemonReaper(pid);
        } else {
            appLog("launch: posix_spawn(%s) failed: %s", bin, strerror(rc));
        }
    }
    posix_spawn_file_actions_destroy(&fa);
    close(in_fd);
    close(out_fd);
#endif
}

void driveDaemonStop() {
#ifndef _WIN32
    if (!g_stop_pending) {
        return;
    }

    pthread_mutex_lock(&g_child_mu);
    const pid_t cur_child = g_child_pid;
    const bool cur_is_sup = g_child_is_supervisor;
    const uint64_t cur_gen = g_child_gen;
    pthread_mutex_unlock(&g_child_mu);

    const bool child_alive = (cur_child > 1) && pidAliveNotZombie(cur_child);

    // 1. Direct child mode (`contract::kService` spawned by us).
    if (g_stop_from_child) {
        if (cur_child <= 1 || cur_gen != g_stop_child_gen || !child_alive) {
            appLog("stop: spawned daemon pid %d exited", static_cast<int>(g_stop_pid));
            clearPendingStop();
            return;
        }
        const pid_t target = cur_child;
        const int64_t elapsed = monotonicMillis() - g_stop_start_ms;
        if (g_stop_stage == 0 && elapsed >= g_stop_term_ms) {
            appLog("stop: daemon pid %d still alive after %ld ms -> SIGTERM",
                   static_cast<int>(target), static_cast<long>(elapsed));
            if (target > 1 && target != getpid()) {
                kill(target, SIGTERM);
            }
            g_stop_stage = 1;
        } else if (g_stop_stage == 1 && elapsed >= g_stop_kill_ms) {
            appLog("stop: daemon pid %d still alive after %ld ms -> SIGKILL",
                   static_cast<int>(target), static_cast<long>(elapsed));
            if (target > 1 && target != getpid()) {
                kill(target, SIGKILL);
            }
            g_stop_stage = 2;
        } else if (g_stop_stage == 2 && elapsed >= g_stop_giveup_ms) {
            appLog("stop: daemon pid %d survived SIGKILL; clearing pending stop",
                   static_cast<int>(target));
            clearPendingStop();
        }
        return;
    }

    // 2. Supervisor mode (`contract::kSupervisor` child, `carplayd` PID from state file)
    //    or pre-existing daemon discovered only via state file.
    const ServiceState d = readServiceStateFile(g_state_file, NULL);
    const pid_t state_pid = (d.pid > 1) ? static_cast<pid_t>(d.pid) : g_stop_pid;
    bool state_pid_verified = false;
    if (state_pid > 1) {
        if (cur_child > 1 && !cur_is_sup && cur_child == state_pid && child_alive) {
            state_pid_verified = true;
        } else {
            state_pid_verified = verifyDaemonPid(state_pid);
        }
    }

    const bool daemon_alive = state_pid_verified && pidAliveNotZombie(state_pid);
    const bool sup_alive = (cur_child > 1 && cur_is_sup && child_alive);

    if (!daemon_alive && !sup_alive && !controlAnswers(g_control_name, 50)) {
        appLog("stop: service exited");
        clearPendingStop();
        return;
    }

    const int64_t elapsed = monotonicMillis() - g_stop_start_ms;
    if (!daemon_alive) {
        // Supervisor is still finishing cleanup (never signalled directly), or daemon PID unknown.
        if (elapsed >= g_stop_giveup_ms) {
            appLog("stop: giving up after %ld ms (sup_alive=%d)",
                   static_cast<long>(elapsed), sup_alive ? 1 : 0);
            clearPendingStop();
        }
        return;
    }

    if (g_stop_stage == 0 && elapsed >= g_stop_term_ms) {
        appLog("stop: verified daemon pid %d still alive after %ld ms -> SIGTERM",
               static_cast<int>(state_pid), static_cast<long>(elapsed));
        if (state_pid > 1 && state_pid != getpid() && verifyDaemonPid(state_pid)) {
            kill(state_pid, SIGTERM);
        }
        g_stop_stage = 1;
    } else if (g_stop_stage == 1 && elapsed >= g_stop_kill_ms) {
        appLog("stop: verified daemon pid %d still alive after %ld ms -> SIGKILL",
               static_cast<int>(state_pid), static_cast<long>(elapsed));
        if (state_pid > 1 && state_pid != getpid() && verifyDaemonPid(state_pid)) {
            kill(state_pid, SIGKILL);
        }
        g_stop_stage = 2;
    } else if (g_stop_stage == 2 && elapsed >= g_stop_giveup_ms) {
        appLog("stop: verified daemon pid %d survived SIGKILL; clearing pending stop",
               static_cast<int>(state_pid));
        clearPendingStop();
    }
#endif
}

class AppHoldIo : public HoldIo {
public:
    virtual void triggerEvent(unsigned event) {
        triggerFocusEvent(g_run_app, event);
    }
    virtual void ownPopup(bool open) {
        triggerPopupEvent(g_run_app, rhmi::kEvOwnPopup, open);
    }
    virtual void send(const char* message) {
        sendControl(g_control_name, message);
    }
    virtual void log(const char* line) {
        appLog("%s", line ? line : "");
    }
    virtual ServiceState readService() {
        return readCurrentServiceState();
    }
    virtual bool appKeyAge(long* seconds) {
#ifndef _WIN32
        struct stat st;
        if (stat(g_app_key_file, &st) != 0) {
            return false;
        }
        const time_t now = time(NULL);
        if (seconds != NULL) {
            *seconds = (now >= st.st_mtime) ? static_cast<long>(now - st.st_mtime) : 0L;
        }
        return true;
#else
        (void)seconds;
        return false;
#endif
    }
    virtual void removeAppKey() {
        removeFile(g_app_key_file);
    }
};

AppHoldIo g_hold_io;
HoldMachine g_hold(g_hold_io);

bool callActive() {
    return g_call_line[0] || g_call_line[1];
}

// ---- RHMI Action & State Handlers ----

bool onStartRow(void*, const BmwParcelStorage&) {
    try {
        const ServiceState d = readCurrentServiceState();
        if (d.is("connected")) {
            g_hold.showAndHold("menu Open row", monoSeconds());
        } else if (d.pid == 0) {
            removeFile(std::string(g_data_dir) + "/bootguard");
            launchDaemonProcess();
        }
        return true;
    } catch (...) {
        appLog("onStartRow: caught unexpected exception");
        return true;
    }
}

bool onStopRow(void*, const BmwParcelStorage&) {
    try {
#ifndef _WIN32
        createStopFile(g_stop_file);
#endif
        sendControl(g_control_name, "quit");
#ifndef _WIN32
        if (!g_stop_pending) {
            pthread_mutex_lock(&g_child_mu);
            const pid_t cur_child = g_child_pid;
            const bool cur_is_sup = g_child_is_supervisor;
            const uint64_t cur_gen = g_child_gen;
            pthread_mutex_unlock(&g_child_mu);

            const ServiceState d = readServiceStateFile(g_state_file, NULL);
            if (cur_child > 1 && !cur_is_sup) {
                g_stop_pid = cur_child;
                g_stop_from_child = true;
                g_stop_child_gen = cur_gen;
            } else if (d.pid > 1) {
                g_stop_pid = static_cast<pid_t>(d.pid);
                g_stop_from_child = false;
                g_stop_child_gen = 0ULL;
            } else {
                g_stop_pid = 0;
                g_stop_from_child = false;
                g_stop_child_gen = 0ULL;
            }
            g_stop_pending = true;
            g_stop_start_ms = monotonicMillis();
            g_stop_stage = 0;
            appLog("stop: requested (stop_file=%s, child=%d sup=%d state_pid=%d)",
                   g_stop_file ? g_stop_file : "(null)",
                   static_cast<int>(cur_child),
                   cur_is_sup ? 1 : 0,
                   d.pid);
        }
#endif
        return true;
    } catch (...) {
        appLog("onStopRow: caught unexpected exception");
        return true;
    }
}

bool onEntryButton(void*, const BmwParcelStorage&) {
    try {
        const ServiceState d = readCurrentServiceState();
        if (d.is("connected") && !callActive() && g_last_gear != kReverseGear) {
            g_hold.showAndHold("entry button", monoSeconds());
        } else if (g_run_app != NULL) {
            triggerFocusEvent(g_run_app, rhmi::kEvOpenMenu);
        }
        return true;
    } catch (...) {
        appLog("onEntryButton: caught unexpected exception");
        return true;
    }
}

bool onAutostartToggle(void*, const BmwParcelStorage&) {
    try {
        const std::string path = std::string(g_data_dir) + "/autostart";
        if (pathExists(path)) {
            removeFile(path);
        } else {
            const uint8_t one[2] = {'1', '\n'};
            writeFileAtomic(path, one, sizeof(one));
        }
        if (g_run_app != NULL && g_fw.update_model_bool != NULL) {
            g_fw.update_model_bool(g_run_app, rhmi::kAutostartModel, pathExists(path));
        }
        return true;
    } catch (...) {
        appLog("onAutostartToggle: caught unexpected exception");
        return true;
    }
}

bool onUsbCableToggle(void*, const BmwParcelStorage&) {
    try {
        const std::string path = std::string(g_data_dir) + "/usb";
        if (pathExists(path)) {
            removeFile(path);
        } else {
            writeFileAtomic(path, NULL, 0U);
        }
        if (g_run_app != NULL && g_fw.update_model_bool != NULL) {
            g_fw.update_model_bool(g_run_app, rhmi::kUsbCableModel, pathExists(path));
        }
        return true;
    } catch (...) {
        appLog("onUsbCableToggle: caught unexpected exception");
        return true;
    }
}

bool onMenuFocus(void*, const BmwParcelStorage& p) {
    try {
        g_hold.menuFocus(rhmi::kMenuState, parcelBool(p), monoSeconds(),
                         static_cast<long>(monotonicMillis()));
        return true;
    } catch (...) {
        appLog("onMenuFocus: caught unexpected exception");
        return true;
    }
}

bool onHelpFocus(void*, const BmwParcelStorage& p) {
    try {
        g_hold.menuFocus(rhmi::kHelpState, parcelBool(p), monoSeconds(),
                         static_cast<long>(monotonicMillis()));
        return true;
    } catch (...) {
        appLog("onHelpFocus: caught unexpected exception");
        return true;
    }
}

bool onCarPlayFocus(void*, const BmwParcelStorage& p) {
    try {
        g_hold.carPlayFocus(parcelBool(p));
        return true;
    } catch (...) {
        appLog("onCarPlayFocus: caught unexpected exception");
        return true;
    }
}

bool onCarPlayVisible(void*, const BmwParcelStorage& p) {
    try {
        g_hold.carPlayVisible(parcelBool(p), monoSeconds());
        return true;
    } catch (...) {
        appLog("onCarPlayVisible: caught unexpected exception");
        return true;
    }
}

// ---- CDS Property Handlers ----

bool onGearChanged(void*, const BmwBasicStringU16& value) {
    try {
        char text[160];
        narrowU16(value, text, sizeof(text));
        const int gear = cdsGearValue(text, -1);
        if (gear != g_last_gear) {
            g_last_gear = gear;
            g_hold.gearChanged(gear);
            char msg[32];
            snprintf(msg, sizeof(msg), "gear %d", gear);
            sendControl(g_control_name, msg);
        }
        return true;
    } catch (...) {
        appLog("onGearChanged: caught unexpected exception");
        return true;
    }
}

bool onCallStatusLine(int line, const BmwBasicStringU16& value) {
    char text[200];
    narrowU16(value, text, sizeof(text));
    const bool active = cdsCallActive(text);
    const bool was = callActive();
    g_call_line[line] = active;
    g_hold.callChanged(callActive(), monoSeconds());
    if (was != callActive()) {
        sendControl(g_control_name, callActive() ? "call 1" : "call 0");
    }
    return true;
}

bool onCallStatus0(void*, const BmwBasicStringU16& v) {
    try {
        return onCallStatusLine(0, v);
    } catch (...) {
        appLog("onCallStatus0: caught unexpected exception");
        return true;
    }
}

bool onCallStatus1(void*, const BmwBasicStringU16& v) {
    try {
        return onCallStatusLine(1, v);
    } catch (...) {
        appLog("onCallStatus1: caught unexpected exception");
        return true;
    }
}

bool onDayNightChanged(void*, const BmwBasicStringU16& value) {
    try {
        char text[160];
        narrowU16(value, text, sizeof(text));
        const int v = cdsIntField(text, "dayNightChangeOver", -1);
        if (v == g_last_day_night) {
            return true;
        }
        g_last_day_night = v;
        if (v != 1 && v != 2) {
            return true;
        }
        writeDayNightFile(g_day_night_file, v);
        char msg[32];
        snprintf(msg, sizeof(msg), "daynight %d", v);
        sendControl(g_control_name, msg);
        return true;
    } catch (...) {
        appLog("onDayNightChanged: caught unexpected exception");
        return true;
    }
}

bool onDriveModeProp(int prop, const BmwBasicStringU16& value) {
    char text[160];
    narrowU16(value, text, sizeof(text));
    const int v = cdsIntField(text, "mode", -1);
    const int was = g_last_drive_mode[prop];
    if (v == was) {
        return true;
    }
    const int invalid = (prop == 1) ? 63 : 15;
    g_last_drive_mode[prop] = v;
    const bool valid = v >= 0 && v != invalid;
    const bool change =
        valid && ((was >= 0 && was != invalid) ||
                  (was < 0 && g_drive_mode_sub_at >= 0 && monoSeconds() - g_drive_mode_sub_at >= 5));
    if (!change) {
        return true;
    }
    char msg[32];
    snprintf(msg, sizeof(msg), "drivemode %d", v);
    sendControl(g_control_name, msg);
    g_hold.driveModeChanged(monoSeconds());
    return true;
}

bool onDriveMode0(void*, const BmwBasicStringU16& v) {
    try {
        return onDriveModeProp(0, v);
    } catch (...) {
        appLog("onDriveMode0: caught unexpected exception");
        return true;
    }
}

bool onDriveMode1(void*, const BmwBasicStringU16& v) {
    try {
        return onDriveModeProp(1, v);
    } catch (...) {
        appLog("onDriveMode1: caught unexpected exception");
        return true;
    }
}

void subscribeRun(void*) {
    try {
        if (g_run_app == NULL) {
            return;
        }
        addCdsProperty(g_run_app, "driving.gear", &onGearChanged);
        addCdsProperty(g_run_app, "communication.callStatus0", &onCallStatus0);
        addCdsProperty(g_run_app, "communication.callStatus1", &onCallStatus1);
        addCdsProperty(g_run_app, "vehicle.dayNightChangeOver", &onDayNightChanged);
        g_drive_mode_sub_at = monoSeconds();
        addCdsProperty(g_run_app, "driving.mode", &onDriveMode0);
        addCdsProperty(g_run_app, "driving.mode35up", &onDriveMode1);
    } catch (...) {
        appLog("subscribeRun: caught unexpected exception");
    }
}

void statusRun(void*) {
    try {
        if (g_run_app == NULL) {
            return;
        }
        // Uptime checks run on the monotonic clock: the wall clock jumps when the
        // head unit syncs time, which would clear the guards early or stall autostart.
        // Only the persisted boot-guard timestamps need wall-clock seconds.
        const long now_sec = static_cast<long>(time(NULL));
        const long up_sec = monoSeconds();
        resetGuardsWhenStableInDir(g_data_dir, g_init_time, up_sec, g_stable_marked);

        driveDaemonStop();

        if (!g_autostart_done && g_init_time > 0 && up_sec - g_init_time >= 30) {
            g_autostart_done = true;
            if (pathExists(std::string(g_data_dir) + "/autostart")) {
                const ServiceState d0 = readCurrentServiceState();
                if (d0.pid == 0 && bootGuardAllowsInDir(g_data_dir, now_sec)) {
                    launchDaemonProcess();
                }
            }
        }

        const ServiceState d = readCurrentServiceState();
        const bool connecting = d.is("connecting");
        const bool connected = d.is("connected");
        const unsigned want_text = connecting ? rhmi::kTextConnecting : rhmi::kTextDefault;
        if (want_text != g_shown_text) {
            updateTextModel(g_run_app, rhmi::kEntryTextModel, want_text);
            g_shown_text = want_text;
        }

        const int stop_wanted = (d.pid != 0) ? 1 : 0;
        if (stop_wanted != g_stop_shown) {
            setComponentVisible(g_run_app, rhmi::kStopButton, stop_wanted != 0);
            g_stop_shown = stop_wanted;
        }

        g_hold.tellService(d);

        if (takeMediaRecall(g_media_recall_file, d.pid, static_cast<uint32_t>(monotonicMillis()))) {
            const ServiceState cur = readCurrentServiceState();
            if (cur.pid == d.pid && cur.overlay == 0 && cur.is("connected") &&
                !callActive() && g_last_gear != kReverseGear) {
                g_hold.showAndHold("double MEDIA", monoSeconds());
            }
        }

        const unsigned row = connected ? rhmi::kTextRowOpen
                                       : (connecting ? rhmi::kTextRowConnecting : rhmi::kTextStart);
        if (row != g_shown_row) {
            updateTextModel(g_run_app, rhmi::kStartRowModel, row);
            g_shown_row = row;
        }

        g_hold.poll(d, monoSeconds());
        if (g_fw.post_runnable != NULL) {
            g_fw.post_runnable(g_run_app, &g_status_runnable, kStatusPollMs);
        }
    } catch (...) {
        appLog("statusRun: caught unexpected exception");
    }
}

// ---- PluginApp vtable hooks (slots 21, 22, 23) ----

bool appOnInit(void* self) {
    try {
        if (g_fw.add_action_handler != NULL) {
            BmwActionDelegate d;
            d.object = self;
            d.stub = &onStartRow;
            g_fw.add_action_handler(self, rhmi::kActStart, d);
            d.stub = &onStopRow;
            g_fw.add_action_handler(self, rhmi::kActStop, d);
            d.stub = &onEntryButton;
            g_fw.add_action_handler(self, rhmi::kActEntry, d);
            d.stub = &onAutostartToggle;
            g_fw.add_action_handler(self, rhmi::kActAutostart, d);
            d.stub = &onUsbCableToggle;
            g_fw.add_action_handler(self, rhmi::kActUsbCable, d);
        }
        if (g_fw.add_state_handler != NULL) {
            BmwActionDelegate d;
            d.object = self;
            d.stub = &onMenuFocus;
            g_fw.add_state_handler(self, rhmi::kMenuState, rhmi::kHandlerFocus, d);
            d.stub = &onHelpFocus;
            g_fw.add_state_handler(self, rhmi::kHelpState, rhmi::kHandlerFocus, d);
            d.stub = &onCarPlayFocus;
            g_fw.add_state_handler(self, rhmi::kCarPlayState, rhmi::kHandlerFocus, d);
            d.stub = &onCarPlayVisible;
            g_fw.add_state_handler(self, rhmi::kCarPlayState, rhmi::kHandlerVisible, d);
        }
        g_init_time = monoSeconds();
        if (g_init_time <= 0) {
            g_init_time = 1;  // 0 means "not initialised" to the guard reset
        }
        const bool ok = (g_fw.on_init != NULL) ? g_fw.on_init(self) : true;
        g_run_app = self;
        makeRunnable(g_sub_runnable, &subscribeRun);
        if (g_fw.post_runnable != NULL) {
            g_fw.post_runnable(self, &g_sub_runnable, 1500U);
        }
        makeRunnable(g_status_runnable, &statusRun);
        if (g_fw.post_runnable != NULL) {
            g_fw.post_runnable(self, &g_status_runnable, 2000U);
        }
        return ok;
    } catch (...) {
        appLog("appOnInit: caught unexpected exception");
        return false;
    }
}

void appOnError(void*, unsigned code, const BmwBasicStringChar& text) {
    try {
        appLog("onError %u: %s", code, text.data ? text.data : "(null)");
    } catch (...) {
    }
}

void appOnFinalize(void* self) {
    try {
        g_run_app = NULL;
        if (g_fw.on_finalize != NULL) {
            g_fw.on_finalize(self);
        }
    } catch (...) {
        appLog("appOnFinalize: caught unexpected exception");
    }
}

void* createApp(void* dispatcher, const char* name, const void* params, const void* config) {
    try {
#ifndef _WIN32
        mkdir(g_data_dir, 0755);
#endif
        if (isAppDisabledInDir(g_data_dir)) {
            return NULL;
        }
        // Refusals that cannot crash the host come before the crash guard, so they
        // do not burn guard attempts and disable the plugin for good.
        if (g_app != NULL) {
            return NULL;
        }
        if ((!g_fw_injected && !g_fw.resolveFromDefault()) || !g_fw.isComplete()) {
            appLog("createApp: BMW framework symbols unavailable in process");
            return NULL;
        }
        if (!crashGuardAllowsInDir(g_data_dir, static_cast<long>(time(NULL)))) {
            return NULL;
        }

        // Never let std::bad_alloc unwind into HmiMain3D.
        void* mem = ::operator new(kPluginAppStorage, std::nothrow);
        if (mem == NULL) {
            return NULL;
        }
        memset(mem, 0, kPluginAppStorage);

        BmwBasicStringChar app_name;
        app_name.data = NULL;
        g_fw.bstr_ctor_cstr(&app_name, name ? name : "EntryCarPlay");
        g_fw.plugin_app_ctor(mem, dispatcher, &app_name, 1U, 0U, 1, params, config);
        g_fw.bstr_dtor(&app_name);

        void** base = *reinterpret_cast<void***>(mem);
        if (base != NULL) {
            memcpy(g_vtbl, base - 2, sizeof(g_vtbl));
        } else {
            memset(g_vtbl, 0, sizeof(g_vtbl));
        }
        g_vtbl[2 + kSlotOnError] = reinterpret_cast<void*>(&appOnError);
        g_vtbl[2 + kSlotOnInit] = reinterpret_cast<void*>(&appOnInit);
        g_vtbl[2 + kSlotOnFinalize] = reinterpret_cast<void*>(&appOnFinalize);
        *reinterpret_cast<void***>(mem) = g_vtbl + 2;

        g_app = mem;
        return mem;
    } catch (...) {
        appLog("createApp: caught unexpected exception");
        return NULL;
    }
}

void destroyApp(void* app) {
    try {
        if (!app) {
            return;
        }
        void** vt = *reinterpret_cast<void***>(app);
        if (vt != NULL && vt[1] != NULL) {
            void (*deleting_dtor)(void*) = NULL;
            memcpy(&deleting_dtor, &vt[1], sizeof(deleting_dtor));
            deleting_dtor(app);
        } else {
            ::operator delete(app);
        }
        if (app == g_app) {
            g_app = NULL;
            g_run_app = NULL;
        }
    } catch (...) {
        appLog("destroyApp: caught unexpected exception");
    }
}

}  // namespace
}  // namespace hmi
}  // namespace platform
}  // namespace carplay

extern "C" {

__attribute__((visibility("default"))) EntryPluginAppInfo pluginAppInfo = {
    1U,
    0U,
    "Apple CarPlay",
    "EntryCarPlay",
    1U,
    &carplay::platform::hmi::createApp,
    &carplay::platform::hmi::destroyApp
};

__attribute__((visibility("default"))) void entryCarPlaySetFrameworkApiForTest(
    const carplay::platform::BmwFrameworkApi* api,
    const char* data_dir,
    const char* control_name,
    const char* state_file,
    const carplay::platform::EntryCarPlayTestOptions* test_opts) {
    try {
        using namespace carplay::platform::hmi;
        if (api != NULL) {
            g_fw = *api;
            g_fw_injected = true;
        } else {
            g_fw = carplay::platform::BmwFrameworkApi();
            g_fw_injected = false;
        }

        if (api == NULL && data_dir == NULL && control_name == NULL &&
            state_file == NULL && test_opts == NULL) {
            resetPluginConfigToDefaults();
            resetSessionRuntimeState();
            g_app = NULL;
            g_run_app = NULL;
            return;
        }

        resetSessionRuntimeState();

        if (data_dir != NULL) {
            copyPathOverride(g_data_dir_buf, sizeof(g_data_dir_buf), data_dir, g_data_dir);
            // Keep all secondary runtime/service files out of /opt and /tmp/entry-carplay* in tests.
            snprintf(g_stop_file_buf, sizeof(g_stop_file_buf), "%s/STOP", g_data_dir);
            g_stop_file = g_stop_file_buf;
            snprintf(g_service_log_buf, sizeof(g_service_log_buf), "%s/service.log", g_data_dir);
            g_service_log = g_service_log_buf;
            snprintf(g_app_key_file_buf, sizeof(g_app_key_file_buf), "%s/appkey", g_data_dir);
            g_app_key_file = g_app_key_file_buf;
            snprintf(g_day_night_file_buf, sizeof(g_day_night_file_buf), "%s/daynight", g_data_dir);
            g_day_night_file = g_day_night_file_buf;
            snprintf(g_media_recall_file_buf, sizeof(g_media_recall_file_buf),
                     "%s/media-recall", g_data_dir);
            g_media_recall_file = g_media_recall_file_buf;
            g_supervisor_bin = "";
            g_service_bin = "";
        }
        if (control_name != NULL) {
            copyPathOverride(
                g_control_name_buf, sizeof(g_control_name_buf), control_name, g_control_name);
        }
        if (state_file != NULL) {
            copyPathOverride(g_state_file_buf, sizeof(g_state_file_buf), state_file, g_state_file);
        }

        if (test_opts != NULL) {
            copyPathOverride(g_stop_file_buf, sizeof(g_stop_file_buf),
                             test_opts->stop_file, g_stop_file);
            copyPathOverride(g_service_bin_buf, sizeof(g_service_bin_buf),
                             test_opts->service_bin, g_service_bin);
            copyPathOverride(g_supervisor_bin_buf, sizeof(g_supervisor_bin_buf),
                             test_opts->supervisor_bin, g_supervisor_bin);
            copyPathOverride(g_service_log_buf, sizeof(g_service_log_buf),
                             test_opts->service_log, g_service_log);
            copyPathOverride(g_app_key_file_buf, sizeof(g_app_key_file_buf),
                             test_opts->app_key_file, g_app_key_file);
            copyPathOverride(g_day_night_file_buf, sizeof(g_day_night_file_buf),
                             test_opts->day_night_file, g_day_night_file);
            copyPathOverride(g_media_recall_file_buf, sizeof(g_media_recall_file_buf),
                             test_opts->media_recall_file, g_media_recall_file);
            if (test_opts->stop_term_ms > 0L) {
                g_stop_term_ms = test_opts->stop_term_ms;
            }
            if (test_opts->stop_kill_ms > 0L) {
                g_stop_kill_ms = test_opts->stop_kill_ms;
            }
            if (test_opts->stop_giveup_ms > 0L) {
                g_stop_giveup_ms = test_opts->stop_giveup_ms;
            }
            if (test_opts->launch_debounce_ms >= 0L) {
                g_launch_debounce_ms = test_opts->launch_debounce_ms;
            }
        }
    } catch (...) {
    }
}

}  // extern "C"
