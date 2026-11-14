#ifndef CARPLAY_PLATFORM_OS_RANDOM_HPP
#define CARPLAY_PLATFORM_OS_RANDOM_HPP

// OS CSPRNG as a pairing::RandomSource.
//   Linux:   /dev/urandom (the target kernel 3.12 predates getrandom(2), added in 3.17). Opened once
//            with O_CLOEXEC, verified to be a character device, read in a full-read loop that
//            retries EINTR and short reads.
//   Windows: BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG) (link -lbcrypt).
// Fail closed: on ANY failure fill() zeroes the whole output buffer and returns false; after a
// read error the device is closed and reopened on the next call.
// Not thread-safe (one instance per thread, or external locking).

#include <stddef.h>
#include <stdint.h>

#include "carplay/pairing.hpp"

namespace carplay {
namespace platform {

class OsRandomSource : public pairing::RandomSource {
public:
    OsRandomSource();
    virtual ~OsRandomSource();
    /// len == 0 succeeds without touching the OS (out may then be NULL).
    virtual bool fill(uint8_t* out, size_t len);

private:
    OsRandomSource(const OsRandomSource&) = delete;
    OsRandomSource& operator=(const OsRandomSource&) = delete;
#ifndef _WIN32
    bool ensureOpen();
    int fd_;
#endif
};

/// Startup sanity check: two 32-byte draws that must succeed, differ from each other and not be
/// constant. Catches a broken / stubbed RNG; it is NOT a statistical test.
bool randomSelfTest(pairing::RandomSource& rng);

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_OS_RANDOM_HPP
