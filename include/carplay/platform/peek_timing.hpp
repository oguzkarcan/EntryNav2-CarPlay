#ifndef CARPLAY_PLATFORM_PEEK_TIMING_HPP
#define CARPLAY_PLATFORM_PEEK_TIMING_HPP

// Pure timing state machines for:
//   1. PeekTiming: when the CarPlay surface temporarily dims (0.25 opacity for 2500 ms on volume
//      steps) or steps aside for iDrive's native overlays (driving mode popup after 400 ms delay
//      for 3500 ms, iDrive popup over blank state 13 up to 120000 ms, or volume step-aside when
//      the compositor refuses opacity).
//   2. MediaDoublePress & writeMediaRecall / takeMediaRecall: two short physical MEDIA clicks
//      within 500 ms while CarPlay is connected in the background publish a one-shot recall
//      request consumed by the HMI plugin.

#include <stdint.h>
#include <stdio.h>

#include <string>

namespace carplay {
namespace platform {

static const unsigned kVolumePeekMs = 2500U;
static const float kVolumeDim = 0.25f;
static const unsigned kDriveModeShowMs = 3500U;
static const unsigned kDriveModeDelayMs = 400U;
static const unsigned kPopupShowMs = 120000U;

class PeekTiming {
public:
    enum Popup {
        kPopupIgnored = 0,
        kPopupShown = 1,
        kPopupGone = 2
    };

    struct Picture {
        bool shown;
        float opacity;

        Picture() : shown(false), opacity(1.0f) {}
    };

    PeekTiming();

    /// Volume key (knob or steering wheel). Returns true when a new peek window starts.
    bool volumeKey(uint32_t now, bool pill_ready);
    /// Volume level reported by AudioMaster 20.00.C08.
    bool volumeLevel(bool pill_ready);
    /// Physical hard key acted on by iDrive (ends any active peek).
    bool hardKey();
    /// Driving mode change (steps CarPlay aside for kDriveModeShowMs after kDriveModeDelayMs).
    bool driveMode(uint32_t now);
    /// iDrive popup opened (`open == true`) or closed (`open == false`).
    Popup popup(uint32_t now, bool open);
    /// Compositor refused surface opacity: fall back to stepping the surface aside on volume keys.
    void refuseOpacity(uint32_t now, uint32_t from);
    /// Evaluates one turn of the visibility loop.
    Picture turn(uint32_t now, bool on_screen);

    bool onScreen() const { return shown_now_; }
    bool visible() const { return visible_now_; }
    bool levelSeen() const { return level_seen_; }
    bool dimRefused() const { return dim_refused_; }
    bool popupOpen() const { return popup_hide_; }
    uint32_t hideFrom() const { return hide_from_; }
    uint32_t hideUntil() const { return hide_until_; }
    uint32_t dimUntil() const { return dim_until_; }

private:
    static uint32_t nz(uint32_t t) { return t ? t : 1U; }
    void hide(uint32_t now, uint32_t from, unsigned ms);

    uint32_t hide_from_;
    uint32_t hide_until_;
    uint32_t dim_until_;
    bool dim_refused_;
    bool level_seen_;
    bool popup_hide_;
    bool shown_now_;
    bool visible_now_;
};

/// True when CarPlay is connected in the background and eligible to be recalled by double-MEDIA.
inline bool mediaRecallAllowed(bool connected,
                               bool on_screen,
                               bool stopping,
                               bool in_call,
                               bool reverse_gear) {
    return connected && !on_screen && !stopping && !in_call && !reverse_gear;
}

class MediaDoublePress {
public:
    static const uint32_t kShortMs = 500U;
    static const uint32_t kPairMs = 500U;

    MediaDoublePress()
        : seen_(false),
          down_(false),
          short_(false),
          first_(false),
          down_at_(0U),
          first_at_(0U) {}

    void cancel() {
        short_ = false;
        first_ = false;
    }

    /// Raw button state: 0 released, 1 pressed, 4 capacitive rest.
    /// Returns true on the release of the second short click within kPairMs.
    bool feed(unsigned state, uint32_t now, bool allowed) {
        if (state != 0U && state != 1U && state != 4U) {
            cancel();
            seen_ = false;
            down_ = false;
            return false;
        }
        const bool down = (state == 1U);
        if (!seen_ || !allowed) {
            cancel();
            seen_ = true;
            down_ = down;
            return false;
        }
        if (down == down_) {
            return false;
        }
        down_ = down;
        if (down) {
            short_ = true;
            down_at_ = now;
            return false;
        }
        if (!short_ || static_cast<uint32_t>(now - down_at_) > kShortMs) {
            cancel();
            return false;
        }
        short_ = false;
        if (first_ && static_cast<uint32_t>(now - first_at_) <= kPairMs) {
            first_ = false;
            return true;
        }
        first_ = true;
        first_at_ = now;
        return false;
    }

private:
    bool seen_;
    bool down_;
    bool short_;
    bool first_;
    uint32_t down_at_;
    uint32_t first_at_;
};

/// Atomically publishes a one-shot double-MEDIA recall request bound to `pid` and monotonic `now`.
bool writeMediaRecall(const char* path, int pid, uint32_t now);

/// Atomically consumes a double-MEDIA recall request, returning true if `pid == expected_pid`
/// and `now - at <= 2000`.
bool takeMediaRecall(const char* path, int expected_pid, uint32_t now);

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_PEEK_TIMING_HPP
