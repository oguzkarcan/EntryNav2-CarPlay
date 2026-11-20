#include "carplay/platform/hold_machine.hpp"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

namespace carplay {
namespace platform {

HoldMachine::HoldMachine(HoldIo& io)
    : io_(io),
      menu_focused_(false),
      cp_visible_(false),
      cp_focused_(false),
      holding_(false),
      hide_sent_(false),
      cp_seen_(false),
      hold_gave_up_(false),
      prev_overlay_(false),
      hold_time_(0),
      hold_shown_at_(0),
      hold_tries_(0),
      menu_route_tries_(0),
      popup_tried_(false),
      unfocused_polls_(0),
      left_seen_(0),
      menu_hold_ms_(-1000),
      waiting_(false),
      unheld_(false),
      popup_open_(false),
      under_popup_(false),
      wait_since_(0),
      asked_at_(0),
      asks_(0),
      in_call_(false),
      call_end_(0),
      gear_(kGearUnknown),
      reverse_held_(false),
      gear_pending_(false),
      gear_pending_since_(0),
      pdc_(kPdcUnknown),
      park_dismissed_(false),
      drive_mode_at_(0),
      service_reachable_(false) {
    memset(prev_state_, 0, sizeof(prev_state_));
    strcpy(prev_state_, "idle");
}

void HoldMachine::say(const char* fmt, ...) {
    char line[384];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    io_.log(line);
}

void HoldMachine::callChanged(bool in_call, long now) {
    if (in_call_ && !in_call) {
        call_end_ = now;
    }
    in_call_ = in_call;
}

void HoldMachine::gearChanged(int gear) {
    gear_ = gear;
    if (gear == kReverseGear) {
        gear_pending_ = false;
    }
}

bool HoldMachine::gearChanged(int gear, long now) {
    const bool was_reverse = (gear_ == kReverseGear);
    gear_ = gear;
    if (gear == kReverseGear) {
        gear_pending_ = false;
        reverse_held_ = holding_;
        return true;
    }
    if (was_reverse && (reverse_held_ || holding_) && !cp_focused_ && !menu_focused_) {
        gear_pending_ = true;
        gear_pending_since_ = now;
        reverse_held_ = false;
        say("hold: left reverse (gear %d): keeping picture aside until camera lets go", gear);
        return false;
    }
    reverse_held_ = false;
    gear_pending_ = false;
    return true;
}

void HoldMachine::pdcChanged(int status) {
    if (status == pdc_) {
        return;
    }
    const bool owned = parkAssistOwns();
    pdc_ = status;
    park_dismissed_ = false;
    if (parkAssistOwns() != owned) {
        io_.send(owned ? "pdc 0" : "pdc 1");
        say("park assist %s: CarPlay picture %s",
            owned ? "ended" : "on",
            owned ? "back" : "aside");
    }
}

void HoldMachine::flushGear(const char* why) {
    if (!gear_pending_) {
        return;
    }
    gear_pending_ = false;
    char msg[32];
    snprintf(msg, sizeof(msg), "gear %d", gear_);
    io_.send(msg);
    say("hold: reverse wait ended (%s): forwarded gear %d", why, gear_);
}

void HoldMachine::driveModeChanged(long now) {
    drive_mode_at_ = now;
}

void HoldMachine::fireHold(const char* why, long now) {
    if (hold_tries_ >= kMaxHoldTries) {
        say("hold: not entering state %u (%s): already tried %d times",
            rhmi::kCarPlayState, why, hold_tries_);
        return;
    }
    ++hold_tries_;
    cp_seen_ = false;
    hold_time_ = now;
    io_.triggerEvent(rhmi::kEvHoldCarPlay);
    say("hold: event %u -> state %u (%s, try %d)",
        rhmi::kEvHoldCarPlay, rhmi::kCarPlayState, why, hold_tries_);
}

void HoldMachine::holdViaMenu(const char* why, long now) {
    ++menu_route_tries_;
    cp_seen_ = false;
    hold_time_ = now;
    io_.triggerEvent(rhmi::kEvOpenMenu);
    say("hold: event %u -> our menu, then state %u (%s, try %d)",
        rhmi::kEvOpenMenu, rhmi::kCarPlayState, why, menu_route_tries_);
}

void HoldMachine::showAndHold(const char* why, long now) {
    flushGear("driver chose CarPlay");
    if (parkAssistOwns()) {
        park_dismissed_ = true;
        io_.send("pdc 0");
        say("park assist: CarPlay chosen over it, kept until park assist changes");
    }
    waiting_ = false;
    unheld_ = false;
    if (popup_open_) {
        popup_open_ = false;
        io_.ownPopup(false);
    }
    io_.send("show");
    prev_overlay_ = false;
    holding_ = true;
    hide_sent_ = false;
    hold_tries_ = 0;
    hold_shown_at_ = now;
    fireHold(why, now);
}

void HoldMachine::requestShow() {
    waiting_ = false;
    unheld_ = false;
    io_.send("show");
    prev_overlay_ = false;
}

bool HoldMachine::appKeyRecent() {
    long age = 0;
    return io_.appKeyAge(&age) && age <= kAppKeyS;
}

bool HoldMachine::keepForAppKey(const char* why, long now) {
    if (!appKeyRecent() || in_call_ || cameraWins()) {
        return false;
    }
    const ServiceState d = io_.readService();
    if (!d.onScreen()) {
        return false;
    }
    io_.removeAppKey();
    hold_tries_ = 0;
    fireHold(why, now);
    return true;
}

void HoldMachine::carPlayFocus(bool focused) {
    cp_focused_ = focused;
    if (focused) {
        menu_focused_ = false;
        cp_visible_ = true;
        cp_seen_ = true;
        hold_tries_ = 0;
        menu_route_tries_ = 0;
        popup_tried_ = false;
        hold_gave_up_ = false;
        under_popup_ = false;
        flushGear("blank state regained focus");
    }
    say("hold: state %u focus -> %d", rhmi::kCarPlayState, static_cast<int>(focused));
}

void HoldMachine::carPlayVisible(bool visible, long now) {
    cp_visible_ = visible;
    if (visible) {
        cp_seen_ = true;
        hold_tries_ = 0;
        menu_route_tries_ = 0;
        popup_tried_ = false;
    }
    say("hold: state %u visible -> %d", rhmi::kCarPlayState, static_cast<int>(visible));
    if (!visible && keepForAppKey("a key kept CarPlay on screen", now)) {
        return;
    }
    if (visible && !holding_ && !in_call_ && !cameraWins()) {
        const ServiceState d = io_.readService();
        if (d.pid > 0 && !d.onScreen() && d.is("connected")) {
            say("hold: iDrive went back to the CarPlay screen: asking the service to come to the front");
            requestShow();
        }
    }
}

void HoldMachine::menuFocus(unsigned state, bool focused, long now, long now_ms) {
    menu_focused_ = focused;
    if (focused) {
        cp_focused_ = false;
        flushGear("our menu has the focus");
    }
    say("menu state %u focus -> %d", state, static_cast<int>(focused));
    if (focused && unheld_ && !waiting_) {
        say("hold: iDrive opened our menu after %d request(s): taking the hold", asks_);
    }
    if (focused && waiting_ && !in_call_ && !cameraWins()) {
        say("hold: our menu is open after %ld s and %d request(s): CarPlay comes up",
            now - wait_since_, asks_);
        showAndHold("our menu opened for CarPlay", now);
        return;
    }
    if (focused && holding_ && !in_call_) {
        const ServiceState d = io_.readService();
        if (d.onScreen() && now_ms - menu_hold_ms_ >= kMenuRefireMs) {
            menu_hold_ms_ = now_ms;
            fireHold("BACK/tilt popped to our menu (immediate)", now);
        }
    }
}

void HoldMachine::tellService(const ServiceState& service) {
    const bool reachable = service.pid > 0;
    if (reachable && !service_reachable_) {
        io_.send("await");
    }
    if ((reachable && !service_reachable_) ||
        (service.is("connected") && strcmp(prev_state_, "connected") != 0)) {
        io_.send(in_call_ ? "call 1" : "call 0");
        if (gear_ != kGearUnknown) {
            char msg[32];
            snprintf(msg, sizeof(msg), "gear %d", gear_pending_ ? kReverseGear : gear_);
            io_.send(msg);
        }
        if (pdc_ != kPdcUnknown) {
            io_.send(parkAssistOwns() ? "pdc 1" : "pdc 0");
        }
    }
    service_reachable_ = reachable;
    // Bounded copy by hand: GCC 16 rejects the strncpy + explicit NUL idiom
    // under -Werror=stringop-truncation.
    size_t n = 0;
    while (n < sizeof(prev_state_) - 1 && service.state[n] != '\0') {
        prev_state_[n] = service.state[n];
        ++n;
    }
    prev_state_[n] = '\0';
}

void HoldMachine::updatePopupPeek(bool covered, long now) {
    const PopupPeek::Action a = popup_.step(covered, now, drive_mode_at_);
    if (a == PopupPeek::kStart) {
        io_.send("popup 1");
        say("popup: iDrive took the focus over state %u (gear %d): CarPlay picture removed",
            rhmi::kCarPlayState, gear_);
    } else if (a == PopupPeek::kEnd) {
        io_.send("popup 0");
        say("popup: focus given back: CarPlay picture back");
    }
}

void HoldMachine::beginWait(long now) {
    waiting_ = true;
    wait_since_ = now;
    asked_at_ = 0;
    asks_ = 0;
}

void HoldMachine::bringIdrive(const ServiceState& service, long now) {
    if (service.onScreen() || service.pid <= 0 || !service.is("connected") || !service.asks()) {
        waiting_ = false;
        if (popup_open_) {
            popup_open_ = false;
            io_.ownPopup(false);
        }
        return;
    }
    if (in_call_ || cameraWins()) {
        return;
    }
    if (menu_focused_ || cp_focused_) {
        say("hold: one of our pages has the focus: CarPlay comes up");
        showAndHold("CarPlay was waiting aside", now);
        return;
    }
    if (asked_at_ != 0 && now - asked_at_ < 1) {
        return;
    }
    if (asks_ == 1) {
        asked_at_ = now;
        ++asks_;
        popup_open_ = true;
        io_.ownPopup(true);
        say("hold: iDrive refused our menu: our own popup opened (event %u) to ask under it",
            rhmi::kEvOwnPopup);
        return;
    }
    if (asks_ >= 2) {
        io_.triggerEvent(rhmi::kEvHoldCarPlay);
        io_.ownPopup(false);
        popup_open_ = false;
        under_popup_ = true;
        asked_at_ = now;
        waiting_ = false;
        unheld_ = true;
        holding_ = true;
        hide_sent_ = false;
        hold_gave_up_ = false;
        prev_overlay_ = false;
        io_.send("show");
        say("hold: event %u -> state %u asked under our popup, popup closed: CarPlay comes up after %ld s",
            rhmi::kEvHoldCarPlay, rhmi::kCarPlayState, now - wait_since_);
        return;
    }
    asked_at_ = now;
    ++asks_;
    io_.triggerEvent(rhmi::kEvOpenMenu);
    if (asks_ == 1) {
        say("hold: CarPlay waits aside: event %u -> our menu", rhmi::kEvOpenMenu);
    }
}

void HoldMachine::askWithoutHold(long now) {
    if (in_call_ || cameraWins() || (asked_at_ != 0 && now - asked_at_ < 1)) {
        return;
    }
    asked_at_ = now;
    ++asks_;
    if (menu_focused_) {
        hold_tries_ = 0;
        fireHold("our menu opened under CarPlay", now);
        return;
    }
    io_.triggerEvent(rhmi::kEvOpenMenu);
}

void HoldMachine::poll(const ServiceState& service, long now) {
    if (gear_pending_ && now - gear_pending_since_ >= kCameraWaitS) {
        flushGear("camera focus wait timed out");
    }
    const bool overlay = service.onScreen();
    const bool rose = overlay && !prev_overlay_;
    const bool fell = !overlay && prev_overlay_;
    prev_overlay_ = overlay;
    const bool blank = blankShown();
    updatePopupPeek(!rose && !fell && overlay && holding_ && blank &&
                        !cp_focused_ && !in_call_ && !cameraWins() && !under_popup_,
                    now);
    if (rose) {
        waiting_ = false;
        if (unheld_) {
            holding_ = true;
            return;
        }
        hold_tries_ = 0;
        menu_route_tries_ = 0;
        popup_tried_ = false;
        hide_sent_ = false;
        hold_gave_up_ = false;
        holding_ = true;
        if (menu_focused_) {
            fireHold("CarPlay came on screen over our menu", now);
        } else if (!cp_visible_ && in_call_) {
            fireHold("CarPlay came on screen during a call", now);
        } else if (!cp_visible_) {
            holdViaMenu("CarPlay came on screen over an iDrive screen", now);
        }
        return;
    }
    if (fell) {
        if (popup_open_) {
            popup_open_ = false;
            io_.ownPopup(false);
        }
        if (blank && !cp_focused_ && !cameraWins()) {
            io_.triggerEvent(rhmi::kEvOpenMenu);
            say("hold: OPTION: event %u -> CarPlay menu", rhmi::kEvOpenMenu);
        } else if (blank && !hide_sent_ && !cameraWins()) {
            io_.triggerEvent(rhmi::kEvGoHome);
            say("hold: CarPlay stepped aside: event %u -> iDrive main menu", rhmi::kEvGoHome);
        } else {
            say("hold: CarPlay stepped aside (state %u visible %d, hard key %d, gear %d)",
                rhmi::kCarPlayState, static_cast<int>(cp_visible_),
                static_cast<int>(hide_sent_), gear_);
        }
        holding_ = false;
        unheld_ = false;
        under_popup_ = false;
        return;
    }
    if (unheld_) {
        if (service.pid <= 0 || !service.is("connected")) {
            unheld_ = false;
        } else if (blank || cp_focused_) {
            unheld_ = false;
            say("hold: iDrive is on our blank state after %d request(s): CarPlay is held", asks_);
        } else {
            if (overlay) {
                askWithoutHold(now);
            }
            return;
        }
    }
    if (service.asks() && !waiting_) {
        beginWait(now);
    }
    if (waiting_) {
        bringIdrive(service, now);
        return;
    }
    if (blank) {
        call_end_ = 0;
    }
    if (overlay && holding_ && blank && !cp_focused_ && !in_call_) {
        if (under_popup_) {
            return;
        }
        if (popup_.active() || (drive_mode_at_ != 0 && now - drive_mode_at_ < kDriveModeQuietS)) {
            return;
        }
        if (cameraWins()) {
            unfocused_polls_ = 0;
            return;
        }
        if (++unfocused_polls_ >= 2 && now - hold_time_ >= 1) {
            unfocused_polls_ = 0;
            fireHold("state lost focus", now);
        }
        return;
    }
    unfocused_polls_ = 0;
    if (!overlay && holding_ && blank && hold_shown_at_ != 0 && now - hold_shown_at_ >= 3) {
        hold_shown_at_ = 0;
        holding_ = false;
        io_.triggerEvent(rhmi::kEvOpenMenu);
        say("hold: CarPlay did not come up after the blank state: event %u -> menu",
            rhmi::kEvOpenMenu);
        return;
    }
    if (overlay) {
        hold_shown_at_ = 0;
    }
    if (!overlay || !holding_ || blank) {
        return;
    }
    if (now - hold_time_ < 1) {
        return;
    }
    if (menu_focused_) {
        fireHold("BACK returned to our menu", now);
        return;
    }
    if (in_call_) {
        cp_seen_ = true;
        return;
    }
    if (call_end_ != 0 && now - call_end_ < kCallEndS) {
        call_end_ = 0;
        fireHold("call ended", now);
        return;
    }
    if (!cp_seen_) {
        if (popup_open_) {
            io_.triggerEvent(rhmi::kEvHoldCarPlay);
            io_.ownPopup(false);
            popup_open_ = false;
            under_popup_ = true;
            cp_seen_ = false;
            hold_time_ = now;
            say("hold: event %u -> state %u asked under our popup over an iDrive screen, popup closed",
                rhmi::kEvHoldCarPlay, rhmi::kCarPlayState);
        } else if (menu_route_tries_ == 1 && !popup_tried_) {
            popup_tried_ = true;
            popup_open_ = true;
            hold_time_ = now;
            io_.ownPopup(true);
            say("hold: iDrive refused our menu over its screen: our own popup opened (event %u) to ask under it",
                rhmi::kEvOwnPopup);
        } else if (menu_route_tries_ < kMenuRouteTries) {
            holdViaMenu("state not shown over an iDrive screen", now);
        } else if (hold_tries_ == 0) {
            fireHold("our menu did not open: state directly", now);
        } else if (!hold_gave_up_) {
            hold_gave_up_ = true;
            unheld_ = true;
            asked_at_ = now;
            asks_ = 0;
            say("hold: iDrive did not show state %u, even through our menu: CarPlay stays, without the hold",
                rhmi::kCarPlayState);
        }
        return;
    }
    if (cameraWins()) {
        return;
    }
    if (keepForAppKey("a key kept CarPlay on screen (poll)", now)) {
        return;
    }
    if (left_seen_ == 0 || now - left_seen_ > 3) {
        left_seen_ = now;
        return;
    }
    left_seen_ = 0;
    hide_sent_ = true;
    holding_ = false;
    io_.send("hide");
    say("hold: iDrive left state %u (hard key): asked the service to step aside",
        rhmi::kCarPlayState);
}

}  // namespace platform
}  // namespace carplay
