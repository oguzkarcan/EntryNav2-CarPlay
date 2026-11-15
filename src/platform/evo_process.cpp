#include "carplay/platform/evo_process.hpp"

#include <cerrno>
#include <cstring>

#include "carplay/platform/net_compat.hpp"

#ifndef _WIN32
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char** environ;
#endif

namespace carplay {
namespace platform {

namespace {
static const size_t kMaxCommandOutputBytes = 65536U;
}  // namespace

bool runCommand(const std::string& executable,
                const std::vector<std::string>& args,
                std::string& output,
                int timeout_ms,
                CommandReport* diagnostic) {
    output.clear();
    if (diagnostic != NULL) {
        *diagnostic = CommandReport();
    }
    if (executable.empty() || timeout_ms <= 0) {
        if (diagnostic != NULL) {
            diagnostic->spawn_error = EINVAL;
        }
        return false;
    }

#ifdef _WIN32
    (void)args;
    if (diagnostic != NULL) {
        diagnostic->spawn_error = ENOSYS;
    }
    return false;
#else
    int fds[2];
    // Mark both ends FD_CLOEXEC so concurrent spawns in other threads never inherit them.
    if (pipe(fds) != 0) {
        if (diagnostic != NULL) {
            diagnostic->spawn_error = errno;
        }
        return false;
    }
    if (fcntl(fds[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(fds[1], F_SETFD, FD_CLOEXEC) != 0) {
        if (diagnostic != NULL) {
            diagnostic->spawn_error = errno;
        }
        close(fds[0]);
        close(fds[1]);
        return false;
    }
    const int read_flags = fcntl(fds[0], F_GETFL, 0);
    if (read_flags < 0 || fcntl(fds[0], F_SETFL, read_flags | O_NONBLOCK) != 0) {
        if (diagnostic != NULL) {
            diagnostic->spawn_error = errno;
        }
        close(fds[0]);
        close(fds[1]);
        return false;
    }

    std::vector<char*> argv;
    argv.reserve(args.size() + 2U);
    argv.push_back(const_cast<char*>(executable.c_str()));
    for (size_t i = 0; i < args.size(); ++i) {
        argv.push_back(const_cast<char*>(args[i].c_str()));
    }
    argv.push_back(NULL);

    posix_spawn_file_actions_t actions;
    const int init_err = posix_spawn_file_actions_init(&actions);
    if (init_err != 0) {
        if (diagnostic != NULL) {
            diagnostic->spawn_error = init_err;
        }
        close(fds[0]);
        close(fds[1]);
        return false;
    }

    const bool actions_ok =
        posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO) == 0 &&
        (diagnostic == NULL ||
         posix_spawn_file_actions_adddup2(&actions, fds[1], STDERR_FILENO) == 0) &&
        posix_spawn_file_actions_addclose(&actions, fds[0]) == 0 &&
        posix_spawn_file_actions_addclose(&actions, fds[1]) == 0;

    pid_t pid = -1;
    const int spawn_rc = actions_ok
                             ? posix_spawnp(&pid, executable.c_str(), &actions, NULL, &argv[0], environ)
                             : EINVAL;
    posix_spawn_file_actions_destroy(&actions);
    close(fds[1]);

    if (spawn_rc != 0) {
        if (diagnostic != NULL) {
            diagnostic->spawn_error = spawn_rc;
        }
        close(fds[0]);
        return false;
    }

    bool ended = false;
    bool eof = false;
    bool ok = true;
    bool truncated = false;
    bool timed_out = false;
    const int64_t begin_ms = monotonicMillis();
    int status = 0;

    while ((!ended || !eof) && ok) {
        const int64_t elapsed_ms = monotonicMillis() - begin_ms;
        if (elapsed_ms >= static_cast<int64_t>(timeout_ms)) {
            timed_out = true;
            break;
        }
        int step_ms = static_cast<int>(static_cast<int64_t>(timeout_ms) - elapsed_ms);
        if (step_ms > 10) {
            step_ms = 10;
        }
        if (step_ms < 1) {
            step_ms = 1;
        }

        if (!eof) {
            struct pollfd reader;
            reader.fd = fds[0];
            reader.events = POLLIN;
            reader.revents = 0;
            poll(&reader, 1, step_ms);

            while (!eof && ok) {
                char buf[1024];
                const ssize_t n = read(fds[0], buf, sizeof(buf));
                if (n > 0) {
                    const size_t avail = static_cast<size_t>(n);
                    if (output.size() + avail > kMaxCommandOutputBytes) {
                        const size_t keep = kMaxCommandOutputBytes - output.size();
                        if (keep > 0) {
                            output.append(buf, keep);
                        }
                        truncated = true;
                        ok = false;
                    } else {
                        output.append(buf, avail);
                    }
                } else if (n == 0) {
                    eof = true;
                } else {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    }
                    if (errno != EINTR) {
                        ok = false;
                    }
                }
            }
        } else {
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = static_cast<long>(step_ms) * 1000000L;
            nanosleep(&ts, NULL);
        }

        if (!ended) {
            const pid_t w = waitpid(pid, &status, WNOHANG);
            if (w == pid) {
                ended = true;
            } else if (w < 0 && errno != EINTR) {
                ended = true;
                ok = false;
            }
        }
    }

    close(fds[0]);

    if (diagnostic != NULL) {
        diagnostic->text = output;
        diagnostic->truncated = truncated;
        diagnostic->timed_out = timed_out ||
                                ((!ended || !eof) && !truncated &&
                                 (monotonicMillis() - begin_ms >= static_cast<int64_t>(timeout_ms)));
        if (ended && WIFEXITED(status)) {
            diagnostic->exit_code = WEXITSTATUS(status);
        }
        if (ended && WIFSIGNALED(status)) {
            diagnostic->signal = WTERMSIG(status);
        }
    }

    if (!ended) {
        kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }
        ok = false;
    }

    ok = ok && !timed_out && eof && ended && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!ok) {
        output.clear();
    }
    return ok;
#endif
}

}  // namespace platform
}  // namespace carplay
