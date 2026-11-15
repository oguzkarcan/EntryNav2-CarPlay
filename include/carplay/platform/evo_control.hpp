#ifndef CARPLAY_PLATFORM_EVO_CONTROL_HPP
#define CARPLAY_PLATFORM_EVO_CONTROL_HPP

// Control channel between the iDrive HMI plugin (libEntryCarPlay.so in HmiMain3D) and carplayd.
//
// Protocol:
//   * Linux abstract Unix datagram socket (\0 + name, e.g. "\0entry-carplayd-control"):
//     no filesystem path to clean up, no ephemeral IPv4 port collision, released by the kernel
//     automatically if the process dies.
//   * Commands (one ASCII command per datagram):
//       - "ping"          -> answered immediately with "pong"
//       - "show"          -> bring CarPlay surface on screen
//       - "hide"          -> step CarPlay surface aside
//       - "await"         -> keep newly connected phone aside until "show"
//       - "quit"          -> clean daemon shutdown
//       - "gear <n>"      -> CDS driving.gear (2 == reverse camera)
//       - "daynight <n>"  -> CDS vehicle.dayNightChangeOver (1 == day, 2 == night)
//       - "call <0|1>"    -> CDS communication.callStatus (1 == active native call)
//       - "popup <0|1>"   -> iDrive popup over blank state 13
//       - "drivemode [<n>]" -> CDS driving.mode / driving.mode35up change
//       - "pdc <n>"       -> accepted for compatibility
//   * State file (e.g. /tmp/entry-carplayd-state):
//       "<connecting|connected> <pid> <overlay>\n"
//       overlay == 1: CarPlay is on screen (knob & touch owned by CarPlay)
//       overlay == 2: phone is connected and waiting aside for "show" ("await" mode)
//       overlay == 0: hidden / idle

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>

#include "carplay/platform/thread.hpp"

namespace carplay {
namespace platform {

struct ControlCommand {
    std::string verb;
    int arg;
    bool has_arg;

    ControlCommand() : arg(0), has_arg(false) {}
};

/// Pure parser for control datagrams. Returns false for unknown or malformed commands.
bool parseControlCommand(const char* data, size_t len, ControlCommand& out);

/// Parsed representation of the daemon state file ("<state> <pid> <overlay>\n").
struct ServiceState {
    char state[24];
    int pid;
    int overlay;

    ServiceState() : pid(0), overlay(0) { strcpy(state, "idle"); }
    ServiceState(const char* name, int process_id, int on_screen)
        : pid(process_id), overlay(on_screen) {
        strncpy(state, name ? name : "idle", sizeof(state) - 1);
        state[sizeof(state) - 1] = '\0';
    }

    bool is(const char* name) const { return name != NULL && strcmp(state, name) == 0; }
    bool onScreen() const { return pid > 0 && overlay == 1; }
    bool asks() const { return pid > 0 && overlay == 2; }
};

/// Pure parser for a state file line ("<state> <pid> [<overlay>]").
bool parseServiceStateLine(const char* line, ServiceState& out);

/// Reads `state_file` and checks if `pid` is alive (or falls back to control socket ping if `control_name` is non-NULL).
ServiceState readServiceStateFile(const char* state_file, const char* control_name = NULL);

/// Sends a one-way datagram to the abstract Unix socket `name`. Non-blocking.
bool sendControl(const char* name, const char* message);

/// Sends "ping" to `name` and waits up to `wait_ms` for "pong".
bool controlAnswers(const char* name, int wait_ms = 200);

/// Writes `appkey <key_name>\n` atomically to `path`.
bool writeAppKeyFile(const char* path, const char* key_name);

/// Writes `daynight <val>\n` atomically to `path`.
bool writeDayNightFile(const char* path, int val);

/// Reads `daynight <val>` from `path`. Returns true if valid (1 = day, 2 = night).
bool readDayNightFile(const char* path, int& val_out);

class EvoControl {
public:
    typedef void (*Callback)(const ControlCommand& cmd, void* user);

    EvoControl();
    ~EvoControl();

    /// Binds abstract Unix datagram socket `name` and starts the listener thread.
    /// Returns false if `name` is already bound by another running instance.
    bool start(const char* name, const char* state_file, Callback cb, void* user);
    void stop();

    bool running() const { return started_; }

    /// Atomically writes "<state> <pid> <overlay>\n" to `state_file` when changed or after 5 s.
    void writeState(const char* state, int overlay);
    void writeStateWithPid(const char* state, int pid, int overlay);

private:
    EvoControl(const EvoControl&) = delete;
    EvoControl& operator=(const EvoControl&) = delete;

    static void threadMain(void* self);
    void run();

    int fd_;
    Thread thread_;
    bool started_;
    volatile bool running_;
    Mutex write_mu_;
    std::string name_;
    std::string state_file_;
    std::string last_line_;
    uint32_t last_write_ms_;
    Callback cb_;
    void* user_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_EVO_CONTROL_HPP
