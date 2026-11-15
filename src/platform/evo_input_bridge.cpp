#include "carplay/platform/evo_input_bridge.hpp"

#include "carplay/platform/log.hpp"

namespace carplay {
namespace platform {

EvoInputBridge::EvoInputBridge(Reactor& reactor,
                               SessionServer& server,
                               const EvoInputBridgeConfig& config,
                               EvoInputListener* listener)
    : reactor_(reactor),
      server_(server),
      config_(config),
      listener_(listener),
      knob_(NULL),
      touch_(NULL),
      owned_(false),
      picture_started_(true),
      touch_slots_(hid::kTouchContacts),
      touch_down_(false),
      media_down_(false),
      tel_down_(false),
      mfl_tel_down_(false),
      mfl_ptt_down_(false),
      touch_reports_sent_(0U),
      knob_reports_sent_(0U),
      media_reports_sent_(0U),
      telephony_reports_sent_(0U),
      siri_requests_sent_(0U),
      post_pending_(false) {}

EvoInputBridge::~EvoInputBridge() {
    detach();
    reactor_.cancelPosted(&EvoInputBridge::onPostedDrain, this);
}

void EvoInputBridge::attach(EvoKnob* knob, EvoTouch* touch) {
    detach();
    knob_ = knob;
    touch_ = touch;
    if (knob_ != NULL) {
        knob_->setOwned(owned_);
        knob_->setPhoneToIdrive(config_.phone_to_idrive);
        knob_->setZbe3Callback(&EvoInputBridge::zbe3Thunk, this);
        knob_->setMflTelephoneCallback(&EvoInputBridge::mflTelThunk, this);
        knob_->setMflPttCallback(&EvoInputBridge::mflPttThunk, this);
        knob_->setHardKeyCallback(&EvoInputBridge::hardKeyThunk, this);
        knob_->setVolumeCallback(&EvoInputBridge::volStepThunk, this);
        knob_->setVolumeLevelCallback(&EvoInputBridge::volLevelThunk, this);
    }
    if (touch_ != NULL) {
        if (config_.display_width > 0 && config_.display_height > 0) {
            touch_->setDisplaySize(static_cast<uint32_t>(config_.display_width),
                                   static_cast<uint32_t>(config_.display_height));
        }
        touch_->setOwned(owned_);
        touch_->setPictureStarted(picture_started_);
        touch_->setCallback(&EvoInputBridge::touchThunk, this);
    }
}

void EvoInputBridge::detach() {
    if (knob_ != NULL) {
        knob_->setZbe3Callback(NULL, NULL);
        knob_->setMflTelephoneCallback(NULL, NULL);
        knob_->setMflPttCallback(NULL, NULL);
        knob_->setHardKeyCallback(NULL, NULL);
        knob_->setVolumeCallback(NULL, NULL);
        knob_->setVolumeLevelCallback(NULL, NULL);
        knob_ = NULL;
    }
    if (touch_ != NULL) {
        touch_->setCallback(NULL, NULL);
        touch_ = NULL;
    }
}

void EvoInputBridge::setDisplaySize(int32_t width_pixels, int32_t height_pixels) {
    config_.display_width = width_pixels > 0 ? width_pixels : 0;
    config_.display_height = height_pixels > 0 ? height_pixels : 0;
    if (touch_ != NULL && width_pixels > 0 && height_pixels > 0) {
        touch_->setDisplaySize(static_cast<uint32_t>(width_pixels),
                               static_cast<uint32_t>(height_pixels));
    }
}

void EvoInputBridge::setOwned(bool owned) {
    if (owned_ == owned) {
        return;
    }
    owned_ = owned;
    if (knob_ != NULL) {
        knob_->setOwned(owned);
    }
    if (touch_ != NULL) {
        touch_->setOwned(owned);
    }
    if (!owned) {
        releaseHeldInputs(true);
    }
}

void EvoInputBridge::setPictureStarted(bool started) {
    picture_started_ = started;
    if (touch_ != NULL) {
        touch_->setPictureStarted(started);
    }
}

void EvoInputBridge::setPhoneToIdrive(bool phone_to_idrive) {
    config_.phone_to_idrive = phone_to_idrive;
    if (knob_ != NULL) {
        knob_->setPhoneToIdrive(phone_to_idrive);
    }
}

void EvoInputBridge::onSessionEnded() {
    releaseHeldInputs(false);
}

void EvoInputBridge::releaseHeldInputs(bool send_hid) {
    if (touch_down_) {
        const std::vector<hid::TouchContact> released =
            touch_slots_.assign(std::vector<hid::TouchContact>());
        if (send_hid && !released.empty()) {
            const std::vector<uint8_t> report =
                hid::touchReport(released, config_.display_width, config_.display_height);
            if (server_.sendHidReport(hid::kUidTouchscreen, report)) {
                ++touch_reports_sent_;
            }
        }
        touch_down_ = false;
    }
    touch_slots_.reset();

    if (last_knob_state_.select || last_knob_state_.home || last_knob_state_.back ||
        last_knob_state_.wheel != 0) {
        const hid::KnobState zero;
        if (send_hid && server_.sendHidReport(hid::kUidKnob, hid::knobReport(zero))) {
            ++knob_reports_sent_;
        }
        last_knob_state_ = zero;
    }
    media_down_ = false;
    tel_down_ = false;
    mfl_tel_down_ = false;
    mfl_ptt_down_ = false;
}

bool EvoInputBridge::enqueue(const QueuedItem& item) {
    bool need_post = false;
    {
        LockGuard lock(queue_mutex_);
        if (config_.max_queued_events > 0U && queue_.size() >= config_.max_queued_events) {
            return false;
        }
        queue_.push_back(item);
        if (!post_pending_) {
            post_pending_ = true;
            need_post = true;
        }
    }
    if (need_post && !reactor_.post(&EvoInputBridge::onPostedDrain, this)) {
        LockGuard lock(queue_mutex_);
        post_pending_ = false;
        return false;
    }
    return true;
}

void EvoInputBridge::onPostedDrain(void* ctx) {
    static_cast<EvoInputBridge*>(ctx)->drainQueue();
}

void EvoInputBridge::drainQueue() {
    std::vector<QueuedItem> local;
    {
        LockGuard lock(queue_mutex_);
        local.swap(queue_);
        post_pending_ = false;
    }
    for (size_t i = 0; i < local.size(); ++i) {
        const QueuedItem& it = local[i];
        switch (it.type) {
            case QueuedItem::kTouch:
                handleTouch(it.touch);
                break;
            case QueuedItem::kZbe3:
                handleZbe3(it.zbe3);
                break;
            case QueuedItem::kMflTel:
                handleMflTelephone(it.pressed);
                break;
            case QueuedItem::kMflPtt:
                handleMflPtt(it.pressed);
                break;
            case QueuedItem::kHardKey:
                handleHardKey(it.key, it.pressed, it.name);
                break;
            case QueuedItem::kVolumeStep:
                if (listener_ != NULL) {
                    listener_->onVolumeStep(it.vol_steps, it.vol_dir);
                }
                break;
            case QueuedItem::kVolumeLevel:
                if (listener_ != NULL) {
                    listener_->onVolumeLevel(it.vol_level);
                }
                break;
        }
    }
}

bool EvoInputBridge::submitTouch(const TouchEventOut& ev) {
    QueuedItem it;
    it.type = QueuedItem::kTouch;
    it.touch = ev;
    return enqueue(it);
}

bool EvoInputBridge::submitZbe3(const hid::Zbe3Event& hw) {
    QueuedItem it;
    it.type = QueuedItem::kZbe3;
    it.zbe3 = hw;
    return enqueue(it);
}

bool EvoInputBridge::submitMflTelephone(bool pressed) {
    QueuedItem it;
    it.type = QueuedItem::kMflTel;
    it.pressed = pressed;
    return enqueue(it);
}

bool EvoInputBridge::submitMflPtt(bool pressed) {
    QueuedItem it;
    it.type = QueuedItem::kMflPtt;
    it.pressed = pressed;
    return enqueue(it);
}

bool EvoInputBridge::submitHardKey(CcsKey key, bool pressed, const char* name) {
    QueuedItem it;
    it.type = QueuedItem::kHardKey;
    it.key = key;
    it.pressed = pressed;
    it.name = name;
    return enqueue(it);
}

bool EvoInputBridge::submitVolumeStep(unsigned steps, uint8_t direction) {
    QueuedItem it;
    it.type = QueuedItem::kVolumeStep;
    it.vol_steps = steps;
    it.vol_dir = direction;
    return enqueue(it);
}

bool EvoInputBridge::submitVolumeLevel(const VolumeLevel& level) {
    QueuedItem it;
    it.type = QueuedItem::kVolumeLevel;
    it.vol_level = level;
    return enqueue(it);
}

void EvoInputBridge::handleTouch(const TouchEventOut& ev) {
    if (!owned_) {
        return;
    }
    std::vector<hid::TouchContact> contacts;
    const bool is_up =
        (ev.action == TouchEventOut::kRelease || ev.action == TouchEventOut::kPointerUp);
    for (int i = 0; i < ev.n && i < kTouchMaxContacts; ++i) {
        const bool down = !(is_up && i == ev.index);
        contacts.push_back(hid::TouchContact(ev.p[i].id, down, ev.p[i].x, ev.p[i].y));
    }
    const std::vector<hid::TouchContact> slotted = touch_slots_.assign(contacts);
    if (slotted.empty()) {
        if (touch_down_) {
            touch_down_ = false;
        }
        return;
    }
    bool any_down = false;
    for (size_t i = 0; i < slotted.size(); ++i) {
        if (slotted[i].down) {
            any_down = true;
            break;
        }
    }
    const std::vector<uint8_t> report =
        hid::touchReport(slotted, config_.display_width, config_.display_height);
    if (server_.sendHidReport(hid::kUidTouchscreen, report)) {
        ++touch_reports_sent_;
    }
    touch_down_ = any_down;
}

void EvoInputBridge::handleZbe3(const hid::Zbe3Event& hw) {
    if (!owned_) {
        return;
    }
    hid::Zbe3Event effective = hw;
    if (!config_.menu_to_carplay) {
        effective.button_mask = static_cast<uint8_t>(effective.button_mask & ~hid::zbe3::kBtnMenu);
    }

    hid::KnobState mapped;
    int32_t media_idx = hid::MEDIA_NONE;
    int32_t tel_idx = hid::TELEPHONY_NONE;
    hid::mapZbe3ToCarPlay(effective, mapped, media_idx, tel_idx);

    if (mapped.wheel != 0) {
        const hid::ReportSequence seq = hid::zbe3KnobReports(mapped);
        if (server_.sendHidReports(hid::kUidKnob, seq)) {
            knob_reports_sent_ += seq.size();
        }
        last_knob_state_ = mapped;
        last_knob_state_.wheel = 0;
    } else if (!(mapped == last_knob_state_)) {
        if (server_.sendHidReport(hid::kUidKnob, hid::knobReport(mapped))) {
            ++knob_reports_sent_;
        }
        last_knob_state_ = mapped;
    }

    if (media_idx != hid::MEDIA_NONE) {
        if (!media_down_) {
            media_down_ = true;
            const hid::ReportSequence seq = hid::mediaPressReports(media_idx);
            if (server_.sendHidReports(hid::kUidMedia, seq)) {
                media_reports_sent_ += seq.size();
            }
        }
    } else {
        media_down_ = false;
    }

    if (tel_idx != hid::TELEPHONY_NONE) {
        if (!tel_down_) {
            tel_down_ = true;
            if (!config_.phone_to_idrive) {
                const hid::ReportSequence seq = hid::telephonyPressReports(tel_idx);
                if (server_.sendHidReports(hid::kUidTelephony, seq)) {
                    telephony_reports_sent_ += seq.size();
                }
            }
        }
    } else {
        tel_down_ = false;
    }
}

void EvoInputBridge::handleMflTelephone(bool pressed) {
    if (!owned_) {
        return;
    }
    if (pressed && !mfl_tel_down_) {
        mfl_tel_down_ = true;
        if (!config_.phone_to_idrive) {
            const hid::ReportSequence seq =
                hid::telephonyPressReports(hid::TELEPHONY_HOOK_SWITCH);
            if (server_.sendHidReports(hid::kUidTelephony, seq)) {
                telephony_reports_sent_ += seq.size();
            }
        }
    } else if (!pressed) {
        mfl_tel_down_ = false;
    }
}

void EvoInputBridge::handleMflPtt(bool pressed) {
    if (!owned_) {
        return;
    }
    if (pressed && !mfl_ptt_down_) {
        mfl_ptt_down_ = true;
        if (server_.requestSiri()) {
            ++siri_requests_sent_;
        }
    } else if (!pressed) {
        mfl_ptt_down_ = false;
    }
}

void EvoInputBridge::handleHardKey(CcsKey key, bool pressed, const char* name) {
    if (listener_ != NULL) {
        listener_->onUiKey(key, pressed, name);
    }
}

void EvoInputBridge::touchThunk(const TouchEventOut& ev, void* user) {
    static_cast<EvoInputBridge*>(user)->submitTouch(ev);
}

void EvoInputBridge::zbe3Thunk(const hid::Zbe3Event& hw, void* user) {
    static_cast<EvoInputBridge*>(user)->submitZbe3(hw);
}

void EvoInputBridge::mflTelThunk(bool pressed, void* user) {
    static_cast<EvoInputBridge*>(user)->submitMflTelephone(pressed);
}

void EvoInputBridge::mflPttThunk(bool pressed, void* user) {
    static_cast<EvoInputBridge*>(user)->submitMflPtt(pressed);
}

void EvoInputBridge::hardKeyThunk(CcsKey key, bool pressed, const char* name, void* user) {
    static_cast<EvoInputBridge*>(user)->submitHardKey(key, pressed, name);
}

void EvoInputBridge::volStepThunk(unsigned steps, uint8_t dir, void* user) {
    static_cast<EvoInputBridge*>(user)->submitVolumeStep(steps, dir);
}

void EvoInputBridge::volLevelThunk(const VolumeLevel& level, void* user) {
    static_cast<EvoInputBridge*>(user)->submitVolumeLevel(level);
}

}  // namespace platform
}  // namespace carplay
