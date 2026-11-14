#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <string.h>

#include "carplay/airplay_crypto.hpp"
#include "carplay/platform/os_random.hpp"

namespace carplay {
namespace platform {

#ifdef _WIN32
OsRandomSource::OsRandomSource() {}

OsRandomSource::~OsRandomSource() {}

bool OsRandomSource::fill(uint8_t* out, size_t len) {
    if (len == 0) {
        return true;
    }
    if (out == NULL) {
        return false;
    }
    size_t done = 0;
    while (done < len) {
        const size_t chunk = (len - done) > 0x10000000U ? 0x10000000U : (len - done);
        if (BCryptGenRandom(NULL, out + done, static_cast<ULONG>(chunk), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            memset(out, 0, len);
            return false;
        }
        done += chunk;
    }
    return true;
}
#else
OsRandomSource::OsRandomSource() : fd_(-1) {}

OsRandomSource::~OsRandomSource() {
    if (fd_ >= 0) {
        close(fd_);
    }
}

bool OsRandomSource::ensureOpen() {
    if (fd_ >= 0) {
        return true;
    }
    int fd;
    do {
        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOCTTY);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return false;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode)) {
        close(fd);  // something other than the kernel device sits at that path: refuse
        return false;
    }
    fd_ = fd;
    return true;
}

bool OsRandomSource::fill(uint8_t* out, size_t len) {
    if (len == 0) {
        return true;
    }
    if (out == NULL) {
        return false;
    }
    if (!ensureOpen()) {
        memset(out, 0, len);
        return false;
    }
    size_t done = 0;
    while (done < len) {
        const ssize_t r = read(fd_, out + done, len - done);
        if (r > 0) {
            done += static_cast<size_t>(r);
            continue;
        }
        if (r < 0 && errno == EINTR) {
            continue;
        }
        // r == 0 (EOF on a char device) or a hard error: fail closed and reopen next time.
        close(fd_);
        fd_ = -1;
        memset(out, 0, len);
        return false;
    }
    return true;
}
#endif

bool randomSelfTest(pairing::RandomSource& rng) {
    uint8_t a[32];
    uint8_t b[32];
    bool ok = rng.fill(a, sizeof(a)) && rng.fill(b, sizeof(b)) && memcmp(a, b, sizeof(a)) != 0;
    if (ok) {
        bool constant_a = true;
        bool constant_b = true;
        for (size_t i = 1; i < sizeof(a); ++i) {
            constant_a = constant_a && a[i] == a[0];
            constant_b = constant_b && b[i] == b[0];
        }
        ok = !constant_a && !constant_b;
    }
    crypto::wipe(a, sizeof(a));
    crypto::wipe(b, sizeof(b));
    return ok;
}

}  // namespace platform
}  // namespace carplay
