// Use MinGW's C99-conforming printf family so %zu / %lld / %llu work like glibc.
#if defined(_WIN32) && !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1
#endif

#include <stdio.h>
#include <string.h>

#include "carplay/platform/log.hpp"

namespace carplay {
namespace platform {

namespace {

// Constant-initialised (no constructors run). Plain volatile words: written once at startup.
LogSink volatile g_sink = NULL;
void* volatile g_sink_ctx = NULL;
volatile int g_level = kLogInfo;

void stderrSink(void*, LogLevel level, const char* tag, const char* message) {
    char line[kLogMaxMessage + 96];
    snprintf(line, sizeof(line), "[%c] %s: %s\n", logLevelChar(level), tag, message);
    fputs(line, stderr);
    fflush(stderr);
}

}  // namespace

void setLogSink(LogSink sink, void* ctx) {
    g_sink_ctx = ctx;
    g_sink = sink;
}

void setLogLevel(LogLevel level) { g_level = static_cast<int>(level); }

LogLevel logLevel() { return static_cast<LogLevel>(g_level); }

bool logEnabled(LogLevel level) { return static_cast<int>(level) <= g_level; }

char logLevelChar(LogLevel level) {
    switch (level) {
        case kLogError: return 'E';
        case kLogWarn: return 'W';
        case kLogInfo: return 'I';
        case kLogDebug: return 'D';
    }
    return '?';
}

void logWriteV(LogLevel level, const char* tag, const char* fmt, va_list ap) {
    if (!logEnabled(level) || fmt == NULL) {
        return;
    }
    char msg[kLogMaxMessage];
    const int n = vsnprintf(msg, sizeof(msg), fmt, ap);
    if (n < 0) {
        strcpy(msg, "(log format error)");
    } else if (static_cast<size_t>(n) >= sizeof(msg)) {
        memcpy(msg + sizeof(msg) - 4, "...", 4);  // marks truncation, keeps the NUL
    }
    const LogSink sink = g_sink;
    if (sink != NULL) {
        sink(g_sink_ctx, level, tag != NULL ? tag : "", msg);
    } else {
        stderrSink(NULL, level, tag != NULL ? tag : "", msg);
    }
}

void logWrite(LogLevel level, const char* tag, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    logWriteV(level, tag, fmt, ap);
    va_end(ap);
}

}  // namespace platform
}  // namespace carplay
