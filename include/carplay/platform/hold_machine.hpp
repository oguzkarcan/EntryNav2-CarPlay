#ifndef CARPLAY_PLATFORM_HOLD_MACHINE_HPP
#define CARPLAY_PLATFORM_HOLD_MACHINE_HPP

// Pure, testable iDrive RHMI screen-hold state machine, CDS JSON property parsers,
// and glibc-2.15-safe posix_spawn attribute helper for the EntryCarPlay HMI plugin.
//
// While CarPlay is drawn in its own LayerManager layer above iDrive, the physical knob and
// hard keys still reach whatever iDrive screen sits underneath unless iDrive is held on
// our inert blank state (state 13 in EntryCarPlay.xml).
//
// Pure logic: no BMW framework call, no file I/O, no wall-clock dependency. All side effects
// go through HoldIo so unit tests can drive every transition deterministically.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <signal.h>
#include <spawn.h>
#endif

#include "carplay/platform/evo_control.hpp"

namespace carplay {
namespace platform {

// ---- RHMI IDs matching hmiapp/EntryCarPlay.xml ----
namespace rhmi {

static const unsigned kMenuState = 10U;
static const unsigned kPreviewState = 11U;
static const unsigned kHelpState = 12U;
static const unsigned kCarPlayState = 13U;
static const unsigned kPopupState = 14U;

static const unsigned kHandlerFocus = 1U;
static const unsigned kHandlerVisible = 11U;

static const unsigned kEvGoHome = 50U;       // -> NativeStateID 1 (iDrive main menu)
static const unsigned kEvOpenMenu = 51U;     // -> state 10 (EntryCarPlay menu)
static const unsigned kEvHoldCarPlay = 52U;  // -> state 13 (blank hold state)
static const unsigned kEvOwnPopup = 53U;     // -> popupState 14

static const unsigned kActEntry = 2U;
static const unsigned kActStart = 21U;
static const unsigned kActStop = 22U;
static const unsigned kActAutostart = 24U;
static const unsigned kActUsbCable = 26U;

static const unsigned kEntryTextModel = 3U;
static const unsigned kEntryImageModel = 4U;
static const unsigned kTextDefault = 1U;
static const unsigned kTextConnecting = 2U;
static const unsigned kImgEntryIcon = 55001U;
static const unsigned kImgSpinFirst = 55010U;
static const unsigned kSpinFrames = 8U;

static const unsigned kStartRowModel = 31U;
static const unsigned kTextStart = 10U;
static const unsigned kTextRowConnecting = 13U;
static const unsigned kTextRowOpen = 14U;
static const unsigned kAutostartModel = 34U;
static const unsigned kUsbCableModel = 38U;
static const unsigned kStartButton = 61U;
static const unsigned kStopButton = 62U;

static const unsigned kPropVisible = 3U;
static const unsigned kPropWaiting = 8U;

}  // namespace rhmi

// ---- CDS JSON integer field parser (no heap, safe on malformed input) ----
inline int cdsIntField(const char* text, const char* key, int def) {
    if (!text || !key) {
        return def;
    }
    char pat[48];
    const size_t kl = strlen(key);
    if (kl + 3U > sizeof(pat)) {
        return def;
    }
    pat[0] = '"';
    memcpy(pat + 1, key, kl);
    pat[kl + 1] = '"';
    pat[kl + 2] = '\0';
    const char* p = strstr(text, pat);
    if (!p) {
        return def;
    }
    p += kl + 2U;
    while (*p == ' ' || *p == ':') {
        ++p;
    }
    if (!(*p == '-' || (*p >= '0' && *p <= '9'))) {
        return def;
    }
    return atoi(p);
}

inline bool cdsCallActive(const char* text) {
    return cdsIntField(text, "state", 0) != 0;
}

inline int cdsGearValue(const char* text, int def = -1) {
    if (!text) {
        return def;
    }
    const int by_key = cdsIntField(text, "gear", -9999);
    if (by_key != -9999) {
        return by_key;
    }
    for (size_t i = 0; text[i] != '\0'; ++i) {
        if (text[i] >= '0' && text[i] <= '9') {
            return atoi(text + i);
        }
    }
    return def;
}

// ---- glibc 2.15 safe posix_spawnattr_t setup (excludes SIGKILL/SIGSTOP from sigdefault) ----
#ifndef _WIN32
inline int initServiceSpawnAttr(posix_spawnattr_t* at) {
    if (!at) {
        return -1;
    }
    int rc = posix_spawnattr_init(at);
    if (rc != 0) {
        return rc;
    }
    sigset_t none;
    sigset_t def;
    sigemptyset(&none);
    sigemptyset(&def);
    for (int s = 1; s < 32; ++s) {
        if (s != SIGKILL && s != SIGSTOP) {
            sigaddset(&def, s);
        }
    }
    rc = posix_spawnattr_setsigmask(at, &none);
    if (rc == 0) {
        rc = posix_spawnattr_setsigdefault(at, &def);
    }
    if (rc == 0) {
        rc = posix_spawnattr_setpgroup(at, 0);
    }
    if (rc == 0) {
        rc = posix_spawnattr_setflags(
            at, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    }
    if (rc != 0) {
        posix_spawnattr_destroy(at);
    }
    return rc;
}
#endif

// ---- PopupPeek: detects when an iDrive popup covers our visible blank state ----
class PopupPeek {
public:
    enum Action {
        kNone = 0,
        kStart = 1,
        kEnd = -1
    };
    static const int kDriveModeSeconds = 6;

    PopupPeek() : peek_(false), decided_(false) {}

    Action step(bool covered, long now, long last_drive_mode) {
        if (!covered) {
            decided_ = false;
            if (!peek_) {
                return kNone;
            }
            peek_ = false;
            return kEnd;
        }
        if (decided_) {
            return kNone;
        }
        decided_ = true;
        if (last_drive_mode != 0 && now - last_drive_mode < kDriveModeSeconds) {
            return kNone;
        }
        peek_ = true;
        return kStart;
    }

    bool active() const { return peek_; }

private:
    bool peek_;
    bool decided_;
};

// ---- HoldMachine: keeps iDrive on blank state 13 while CarPlay is on screen ----
static const int kReverseGear = 2;
static const int kGearUnknown = -1000;
static const int kPdcUnknown = -1000;
static const int kParkAssistOn = 1;

class HoldIo {
public:
    virtual void triggerEvent(unsigned event) = 0;
    virtual void ownPopup(bool open) = 0;
    virtual void send(const char* message) = 0;
    virtual void log(const char* line) = 0;
    virtual ServiceState readService() = 0;
    virtual bool appKeyAge(long* seconds) = 0;
    virtual void removeAppKey() = 0;

protected:
    ~HoldIo() {}
};

class HoldMachine {
public:
    static const int kMaxHoldTries = 8;
    static const int kMenuRouteTries = 3;
    static const int kDriveModeQuietS = 15;
    static const int kAppKeyS = 2;
    static const int kCallEndS = 10;
    static const int kCameraWaitS = 15;
    static const long kMenuRefireMs = 300;

    explicit HoldMachine(HoldIo& io);

    // CDS car signals
    void callChanged(bool in_call, long now);
    void gearChanged(int gear);
    /// Returns true if the caller should forward `gear` immediately; false while waiting
    /// for the reverse camera to finish leaving the screen (upstream #114).
    bool gearChanged(int gear, long now);
    void pdcChanged(int status);
    void driveModeChanged(long now);

    // User / menu requests
    void showAndHold(const char* why, long now);
    void requestShow();

    // RHMI state focus / visibility notifications
    void carPlayFocus(bool focused);
    void carPlayVisible(bool visible, long now);
    void menuFocus(unsigned state, bool focused, long now, long now_ms);

    // 1 Hz status poll
    void tellService(const ServiceState& service);
    void poll(const ServiceState& service, long now);

    bool holding() const { return holding_; }
    bool blankShown() const { return cp_visible_ && !menu_focused_; }
    bool popupPeek() const { return popup_.active(); }
    bool waiting() const { return waiting_; }
    bool parkAssistOwns() const { return pdc_ == kParkAssistOn && !park_dismissed_; }
    bool cameraWins() const { return gear_ == kReverseGear || gear_pending_ || parkAssistOwns(); }

private:
    void fireHold(const char* why, long now);
    void holdViaMenu(const char* why, long now);
    bool appKeyRecent();
    bool keepForAppKey(const char* why, long now);
    void flushGear(const char* why);
    void updatePopupPeek(bool covered, long now);
    void beginWait(long now);
    void askWithoutHold(long now);
    void bringIdrive(const ServiceState& service, long now);
    void say(const char* fmt, ...);

    HoldIo& io_;
    PopupPeek popup_;

    bool menu_focused_;
    bool cp_visible_;
    bool cp_focused_;

    bool holding_;
    bool hide_sent_;
    bool cp_seen_;
    bool hold_gave_up_;
    bool prev_overlay_;
    long hold_time_;
    long hold_shown_at_;
    int hold_tries_;
    int menu_route_tries_;
    bool popup_tried_;
    int unfocused_polls_;
    long left_seen_;
    long menu_hold_ms_;

    bool waiting_;
    bool unheld_;
    bool popup_open_;
    bool under_popup_;
    long wait_since_;
    long asked_at_;
    int asks_;

    bool in_call_;
    long call_end_;
    int gear_;
    bool reverse_held_;
    bool gear_pending_;
    long gear_pending_since_;
    int pdc_;
    bool park_dismissed_;
    long drive_mode_at_;

    bool service_reachable_;
    char prev_state_[24];
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_HOLD_MACHINE_HPP
