#include "carplay/platform/peek_timing.hpp"

#include <stdio.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "carplay/platform/file_util.hpp"

namespace carplay {
namespace platform {

PeekTiming::PeekTiming()
    : hide_from_(0U),
      hide_until_(0U),
      dim_until_(0U),
      dim_refused_(false),
      level_seen_(false),
      popup_hide_(false),
      shown_now_(false),
      visible_now_(false) {}

void PeekTiming::hide(uint32_t now, uint32_t from, unsigned ms) {
    const bool hiding =
        hide_from_ != 0U &&
        static_cast<int32_t>(now - hide_from_) >= 0 &&
        static_cast<int32_t>(hide_until_ - now) > 0;
    if (!hiding) {
        hide_from_ = nz(from);
    }
    const uint32_t until = nz(from + ms);
    if (hide_until_ == 0U || static_cast<int32_t>(until - hide_until_) > 0) {
        hide_until_ = until;
    }
}

bool PeekTiming::volumeKey(uint32_t now, bool pill_ready) {
    const bool use_pill = level_seen_ && pill_ready;
    if (!shown_now_ || use_pill) {
        return false;
    }
    if (!dim_refused_) {
        const bool start = (dim_until_ == 0U);
        dim_until_ = nz(now + kVolumePeekMs);
        return start;
    }
    const bool start = (hide_until_ == 0U);
    hide(now, now, kVolumePeekMs);
    return start;
}

bool PeekTiming::volumeLevel(bool pill_ready) {
    level_seen_ = true;
    if (!visible_now_ || !pill_ready) {
        return false;
    }
    dim_until_ = 0U;
    return true;
}

bool PeekTiming::hardKey() {
    if (!shown_now_) {
        return false;
    }
    hide_from_ = 0U;
    hide_until_ = 0U;
    dim_until_ = 0U;
    return true;
}

bool PeekTiming::driveMode(uint32_t now) {
    if (!shown_now_) {
        return false;
    }
    hide(now, now + kDriveModeDelayMs, kDriveModeShowMs);
    return true;
}

PeekTiming::Popup PeekTiming::popup(uint32_t now, bool open) {
    if (open && shown_now_) {
        hide(now, now, kPopupShowMs);
        popup_hide_ = true;
        return kPopupShown;
    }
    if (!open && popup_hide_) {
        popup_hide_ = false;
        hide_from_ = 0U;
        hide_until_ = 0U;
        return kPopupGone;
    }
    return kPopupIgnored;
}

void PeekTiming::refuseOpacity(uint32_t now, uint32_t from) {
    dim_refused_ = true;
    dim_until_ = 0U;
    hide(now, from, kVolumePeekMs);
}

PeekTiming::Picture PeekTiming::turn(uint32_t now, bool on_screen) {
    const bool hiding =
        hide_from_ != 0U &&
        static_cast<int32_t>(now - hide_from_) >= 0 &&
        static_cast<int32_t>(hide_until_ - now) > 0;
    if (hide_until_ != 0U && static_cast<int32_t>(hide_until_ - now) <= 0) {
        hide_from_ = 0U;
        hide_until_ = 0U;
    }
    const bool dimming = dim_until_ != 0U && static_cast<int32_t>(dim_until_ - now) > 0;
    if (dim_until_ != 0U && !dimming) {
        dim_until_ = 0U;
    }
    if (!on_screen) {
        hide_from_ = 0U;
        hide_until_ = 0U;
        dim_until_ = 0U;
    }
    Picture picture;
    picture.shown = on_screen && !hiding;
    picture.opacity = (picture.shown && dimming) ? kVolumeDim : 1.0f;
    shown_now_ = on_screen;
    visible_now_ = picture.shown;
    return picture;
}

bool writeMediaRecall(const char* path, int pid, uint32_t now) {
    if (!path || !path[0]) {
        return false;
    }
    const std::string temporary = std::string(path) + ".tmp";
    FILE* file = fopen(temporary.c_str(), "w");
    if (!file) {
        return false;
    }
    const bool written = fprintf(file, "media-recall %d %u\n", pid, static_cast<unsigned>(now)) > 0;
    const bool closed = fclose(file) == 0;
    if (written && closed && rename(temporary.c_str(), path) == 0) {
        return true;
    }
    removeFile(temporary);
    return false;
}

bool takeMediaRecall(const char* path, int expected_pid, uint32_t now) {
    if (!path || !path[0]) {
        return false;
    }
    const std::string reading = std::string(path) + ".read";
    if (rename(path, reading.c_str()) != 0) {
        return false;
    }
    FILE* file = fopen(reading.c_str(), "r");
    int pid = 0;
    unsigned at = 0U;
    char extra = '\0';
    const int fields = file ? fscanf(file, "media-recall %d %u %c", &pid, &at, &extra) : 0;
    if (file) {
        fclose(file);
    }
    removeFile(reading);
    return fields == 2 && pid > 1 && pid == expected_pid &&
           static_cast<uint32_t>(now - at) <= 2000U;
}

}  // namespace platform
}  // namespace carplay
