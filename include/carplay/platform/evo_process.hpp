#ifndef CARPLAY_PLATFORM_EVO_PROCESS_HPP
#define CARPLAY_PLATFORM_EVO_PROCESS_HPP

// Runs a subprocess without a shell, with bounded wall-clock time and captured output.
// Uses posix_spawnp on POSIX so concurrent worker threads remain safe; fails cleanly on Windows.

#include <stddef.h>

#include <string>
#include <vector>

namespace carplay {
namespace platform {

/// Diagnostic copy of a subprocess run. Partial or failed output is kept here for logging,
/// while `runCommand()` clears `output` on any non-zero exit, timeout, truncation, or error.
struct CommandReport {
    std::string text;
    int exit_code;
    int signal;
    int spawn_error;
    bool timed_out;
    bool truncated;

    CommandReport()
        : exit_code(-1),
          signal(0),
          spawn_error(0),
          timed_out(false),
          truncated(false) {}
};

/// Executes `executable` directly via posix_spawnp (no shell), capturing stdout (and stderr when
/// `diagnostic != NULL`) up to 64 KiB within `timeout_ms` monotonic milliseconds.
/// Reaps the child process on every exit path (sending SIGKILL on timeout or truncation).
bool runCommand(const std::string& executable,
                const std::vector<std::string>& args,
                std::string& output,
                int timeout_ms = 2000,
                CommandReport* diagnostic = NULL);

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_EVO_PROCESS_HPP
