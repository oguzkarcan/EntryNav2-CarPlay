#ifndef CARPLAY_PLATFORM_LOG_HPP
#define CARPLAY_PLATFORM_LOG_HPP

// Minimal leveled logger.
//
//   CARPLAY_LOG_INFO("net", "listening on %s", addr.toString().c_str());
//
// * Messages are formatted into a bounded stack buffer (kLogMaxMessage bytes; longer messages are
//   truncated and end with "..."), then handed to the sink. Default sink: one fputs to stderr per
//   line ("[I] net: text\n").
// * printf format checking via the GCC format attribute (gnu_printf on MinGW, where the logger is
//   built with the MinGW ANSI stdio so %zu / %lld behave like glibc).
// * Debug logging is compiled out when CARPLAY_LOG_STRIP_DEBUG is defined (arguments are still
//   type-checked but never evaluated).
// * No global constructors: the state is constant-initialised PODs. setLogSink()/setLogLevel() are
//   meant to be called once at startup before other threads log; logWrite() itself is reentrant and
//   may be called from any thread (the sink must be thread-safe if several threads log).
// * Policy: never log key material, seeds or pairing secrets.

#include <stdarg.h>
#include <stddef.h>

namespace carplay {
namespace platform {

enum LogLevel { kLogError = 0, kLogWarn = 1, kLogInfo = 2, kLogDebug = 3 };

static const size_t kLogMaxMessage = 512;

/// Receives one complete message (no trailing newline). `tag` is never NULL.
typedef void (*LogSink)(void* ctx, LogLevel level, const char* tag, const char* message);

/// NULL restores the default stderr sink.
void setLogSink(LogSink sink, void* ctx);
/// Messages above `level` are dropped (default kLogInfo).
void setLogLevel(LogLevel level);
LogLevel logLevel();
bool logEnabled(LogLevel level);
/// One-letter level name: E W I D.
char logLevelChar(LogLevel level);

#if defined(__GNUC__) && defined(__MINGW32__)
#define CARPLAY_PRINTF_ATTR(fmt, first) __attribute__((format(gnu_printf, fmt, first)))
#elif defined(__GNUC__)
#define CARPLAY_PRINTF_ATTR(fmt, first) __attribute__((format(printf, fmt, first)))
#else
#define CARPLAY_PRINTF_ATTR(fmt, first)
#endif

void logWrite(LogLevel level, const char* tag, const char* fmt, ...) CARPLAY_PRINTF_ATTR(3, 4);
void logWriteV(LogLevel level, const char* tag, const char* fmt, va_list ap) CARPLAY_PRINTF_ATTR(3, 0);

}  // namespace platform
}  // namespace carplay

#define CARPLAY_LOG_AT(level, tag, ...)                                       \
    do {                                                                      \
        if (::carplay::platform::logEnabled(level)) {                         \
            ::carplay::platform::logWrite((level), (tag), __VA_ARGS__);       \
        }                                                                     \
    } while (0)

#define CARPLAY_LOG_ERROR(tag, ...) CARPLAY_LOG_AT(::carplay::platform::kLogError, tag, __VA_ARGS__)
#define CARPLAY_LOG_WARN(tag, ...) CARPLAY_LOG_AT(::carplay::platform::kLogWarn, tag, __VA_ARGS__)
#define CARPLAY_LOG_INFO(tag, ...) CARPLAY_LOG_AT(::carplay::platform::kLogInfo, tag, __VA_ARGS__)

#ifdef CARPLAY_LOG_STRIP_DEBUG
#define CARPLAY_LOG_DEBUG(tag, ...)                                           \
    do {                                                                      \
        if (0) {                                                              \
            ::carplay::platform::logWrite(::carplay::platform::kLogDebug, (tag), __VA_ARGS__); \
        }                                                                     \
    } while (0)
#else
#define CARPLAY_LOG_DEBUG(tag, ...) CARPLAY_LOG_AT(::carplay::platform::kLogDebug, tag, __VA_ARGS__)
#endif

#endif  // CARPLAY_PLATFORM_LOG_HPP
