#include "carplay/platform/evo_knob.hpp"

#include <string.h>

#ifndef _WIN32
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#endif

#include "carplay/platform/log.hpp"
#include "carplay/platform/net_compat.hpp"

namespace carplay {
namespace platform {

namespace {

const uint8_t kCcsInstances[] = {0x01U, 0x03U, 0x05U};
const uint16_t kCcs35upFunctions[] = {0xC46U, 0xC47U, 0xC4FU};
const uint16_t kOlderCcsFunctions[] = {0xC10U, 0xC20U};

uint32_t monoMs32() {
    return static_cast<uint32_t>(monotonicMillis());
}

bool isCarPlayKnobBit(uint8_t bit) {
    return bit == kCcsBtnMenu || bit == kCcsBtnBack || bit == kCcsBtnMedia || bit == kCcsBtnCom;
}

int decodeMflButton(const VmostMsgView& m, uint16_t fkt) {
    if (m.fblock != kVolumeFblock || m.inst != kVolumeMflInstance || m.fkt != fkt ||
        m.op != kMostOpStatus || m.data == NULL || m.len < 1U) {
        return -1;
    }
    if (m.data[0] == 1U) return 1;
    if (m.data[0] == 0U) return 0;
    return -1;
}

}  // namespace

void normalizePushButtons(const uint8_t* in, size_t n, uint8_t* prev, uint8_t* out) {
    if (in == NULL || prev == NULL || out == NULL) {
        return;
    }
    for (size_t i = 0; i < n && i < 8U; ++i) {
        const uint8_t v = in[i];
        if (v == 1U || v == 2U || v == 3U) {
            prev[i] = 1U;
        } else if (v == 0U || v == 4U) {
            prev[i] = 0U;
        }
        out[i] = prev[i];
    }
}

int decodeTelephoneButton(const VmostMsgView& m) {
    return decodeMflButton(m, kMflTelephoneFkt);
}

int decodePttButton(const VmostMsgView& m) {
    return decodeMflButton(m, kMflPttFkt);
}

int decodeVolumeButton(const VmostMsgView& m, unsigned* steps, uint8_t* raw_dir) {
    if (m.fblock != kVolumeFblock || m.op != kMostOpStatus || m.data == NULL) {
        return 0;
    }
    unsigned raw = 0U;
    unsigned n = 0U;
    if (m.inst == kVolumeCsInstance && m.fkt == kVolumeCsFkt && m.len >= 2U) {
        raw = m.data[0];
        n = m.data[1];
    } else if (m.inst == kVolumeMflInstance && m.fkt == kVolumeMflFkt && m.len >= 4U) {
        raw = m.data[2];
        n = m.data[3];
    } else {
        return 0;
    }
    if (raw != 1U && raw != 2U) {
        return 0;
    }
    if (steps != NULL) {
        *steps = n;
    }
    if (raw_dir != NULL) {
        *raw_dir = static_cast<uint8_t>(raw);
    }
    return 1;
}

bool decodeVolumeLevel(const VmostMsgView& m, VolumeLevel& out) {
    if (m.fblock != kAudioMasterFblock || m.inst != kAudioMasterInstance ||
        m.fkt != kVolumeLevelFkt || m.op != kMostOpStatus || m.data == NULL || m.len < 5U) {
        return false;
    }
    const unsigned value = m.data[2];
    const unsigned min = m.data[3];
    const unsigned max = m.data[4];
    if (max <= min || value < min || value > max) {
        return false;
    }
    out.value = value;
    out.min = min;
    out.max = max;
    return true;
}

EvoKnob::EvoKnob()
    : mode_(kInputOff),
      query_older_immediately_(false),
      event_cb_(NULL),
      event_user_(NULL),
      zbe3_cb_(NULL),
      zbe3_user_(NULL),
      mfl_tel_cb_(NULL),
      mfl_tel_user_(NULL),
      mfl_ptt_cb_(NULL),
      mfl_ptt_user_(NULL),
      hard_key_cb_(NULL),
      hard_key_user_(NULL),
      vol_cb_(NULL),
      vol_user_(NULL),
      level_cb_(NULL),
      level_user_(NULL),
      running_(false),
      owned_(false),
      phone_to_idrive_(false),
      started_(false),
      connected_(false),
      n_registered_(0),
      n_vol_registered_(0),
      level_registered_(false),
      other_protocol_logged_(false),
      tel_down_(false),
      tel_forwarded_(false),
      ptt_down_(false),
      ptt_forwarded_(false),
      sent_push_(false),
      sent_buttons_(0U),
      gets_(0U),
      messages_(0U),
      e5_messages_(0U) {
    memset(registered_, 0, sizeof(registered_));
    memset(vol_registered_, 0, sizeof(vol_registered_));
    memset(push_prev_, 0, sizeof(push_prev_));
}

EvoKnob::~EvoKnob() {
    stop();
}

void EvoKnob::setZbe3Callback(Zbe3Callback cb, void* user) {
    LockGuard lock(state_mutex_);
    zbe3_cb_ = cb;
    zbe3_user_ = user;
}

void EvoKnob::setMflTelephoneCallback(MflButtonCallback cb, void* user) {
    LockGuard lock(state_mutex_);
    mfl_tel_cb_ = cb;
    mfl_tel_user_ = user;
}

void EvoKnob::setMflPttCallback(MflButtonCallback cb, void* user) {
    LockGuard lock(state_mutex_);
    mfl_ptt_cb_ = cb;
    mfl_ptt_user_ = user;
}

void EvoKnob::setHardKeyCallback(HardKeyCallback cb, void* user) {
    LockGuard lock(state_mutex_);
    hard_key_cb_ = cb;
    hard_key_user_ = user;
}

void EvoKnob::setVolumeCallback(VolumeCallback cb, void* user) {
    LockGuard lock(state_mutex_);
    vol_cb_ = cb;
    vol_user_ = user;
}

void EvoKnob::setVolumeLevelCallback(VolumeLevelCallback cb, void* user) {
    LockGuard lock(state_mutex_);
    level_cb_ = cb;
    level_user_ = user;
}

void EvoKnob::setQueryOlderImmediately(bool immediate) {
    query_older_immediately_ = immediate;
    protocol_.setQueryOlderImmediately(immediate);
}

void EvoKnob::setApiOverride(const VmostApi* api) {
    vmost_.setApiOverride(api);
}

void EvoKnob::setOwned(bool owned) {
    LockGuard lock(state_mutex_);
    owned_ = owned;
}

bool EvoKnob::owned() const {
    LockGuard lock(state_mutex_);
    return owned_;
}

void EvoKnob::setPhoneToIdrive(bool phone_to_idrive) {
    LockGuard lock(state_mutex_);
    phone_to_idrive_ = phone_to_idrive;
}

bool EvoKnob::phoneToIdrive() const {
    LockGuard lock(state_mutex_);
    return phone_to_idrive_;
}

CcsProtocol::Kind EvoKnob::protocol() const {
    return protocol_.kind();
}

void EvoKnob::attachForTest(InputMode mode, EventCallback cb, void* user) {
    mode_ = mode;
    event_cb_ = cb;
    event_user_ = user;
}

void EvoKnob::pollTurnForTest() {
    if (!owned()) {
        releaseHeldKeys("picture gone");
    }
}

bool EvoKnob::load() {
    switch (vmost_.load()) {
        case VmostClient::kLoaded:
            return true;
        case VmostClient::kNoDaemon:
            CARPLAY_LOG_WARN("knob", "vmostd socket missing: controller not read");
            return false;
        case VmostClient::kNoLibrary:
            CARPLAY_LOG_WARN("knob", "libvmostclient.so.1: %s", vmost_.error().c_str());
            return false;
        case VmostClient::kNoSymbols:
            CARPLAY_LOG_WARN("knob", "vMOST functions missing: controller not read");
            return false;
    }
    return false;
}

bool EvoKnob::start(InputMode mode, EventCallback cb, void* user) {
    EvoKnobConfig cfg;
    cfg.mode = mode;
    cfg.query_older_immediately = query_older_immediately_;
    return start(cfg, cb, user);
}

bool EvoKnob::start(const EvoKnobConfig& cfg, EventCallback cb, void* user) {
    if (started_ || cfg.mode == kInputOff) {
        return cfg.mode == kInputOff;
    }
    mode_ = cfg.mode;
    query_older_immediately_ = cfg.query_older_immediately;
    protocol_.setQueryOlderImmediately(cfg.query_older_immediately);
    if (cfg.use_api_override) {
        vmost_.setApiOverride(&cfg.api_override);
    }
    event_cb_ = cb;
    event_user_ = user;
    if (!load()) {
        return false;
    }
    {
        LockGuard lock(state_mutex_);
        running_ = true;
    }
    if (!thread_.start(&EvoKnob::threadEntry, this)) {
        LockGuard lock(state_mutex_);
        running_ = false;
        CARPLAY_LOG_ERROR("knob", "cannot start vMOST reader thread");
        return false;
    }
    started_ = true;
    return true;
}

void EvoKnob::stop() {
    if (!started_) {
        return;
    }
    {
        LockGuard lock(state_mutex_);
        running_ = false;
    }
    thread_.join();
    started_ = false;
}

void EvoKnob::threadEntry(void* self) {
    static_cast<EvoKnob*>(self)->run();
}

void EvoKnob::vmostCallback(void* msg, void* user) {
    VmostMsgView v;
    if (user != NULL && parseVmostMsg(msg, v)) {
        static_cast<EvoKnob*>(user)->onMessage(v);
    }
}

void EvoKnob::emitZbe3(const hid::Zbe3Event& hw) {
    Zbe3Callback cb = NULL;
    void* user = NULL;
    {
        LockGuard lock(state_mutex_);
        cb = zbe3_cb_;
        user = zbe3_user_;
    }
    if (cb != NULL) {
        cb(hw, user);
    }
}

void EvoKnob::releaseHeldKeys(const char* why) {
    const bool had_held = sent_push_ || sent_buttons_ != 0U;
    if (sent_push_) {
        sent_push_ = false;
        if (event_cb_ != NULL) {
            CcsEvent ev;
            ev.kind = CcsEvent::kKey;
            ev.key = kCcsKeyCenter;
            ev.down = false;
            ev.name = "RELEASE";
            event_cb_(ev, event_user_);
        }
    }
    if (sent_buttons_ != 0U) {
        struct BitKey {
            uint8_t bit;
            CcsKey key;
        };
        static const BitKey kBits[] = {
            {kCcsBtnMenu, kCcsKeyMenu},
            {kCcsBtnBack, kCcsKeyBack},
            {kCcsBtnOption, kCcsKeyOption},
            {kCcsBtnMedia, kCcsKeyMedia},
            {kCcsBtnNav, kCcsKeyNav},
            {kCcsBtnMap, kCcsKeyMap},
            {kCcsBtnCom, kCcsKeyCom}
        };
        for (size_t i = 0; i < sizeof(kBits) / sizeof(kBits[0]); ++i) {
            if ((sent_buttons_ & kBits[i].bit) != 0U) {
                sent_buttons_ &= static_cast<uint8_t>(~kBits[i].bit);
                if (event_cb_ != NULL) {
                    CcsEvent ev;
                    ev.kind = CcsEvent::kKey;
                    ev.key = kBits[i].key;
                    ev.btn_mask = kBits[i].bit;
                    ev.down = false;
                    ev.name = "RELEASE";
                    event_cb_(ev, event_user_);
                }
            }
        }
    }
    if (had_held) {
        CARPLAY_LOG_DEBUG("knob", "released held ZBE3 keys (%s)", why != NULL ? why : "");
        hid::Zbe3Event zero;
        emitZbe3(zero);
    }
}

void EvoKnob::onMessage(const VmostMsgView& m) {
    ++messages_;

    if (m.fblock == kAudioMasterFblock) {
        VolumeLevel level;
        if (decodeVolumeLevel(m, level)) {
            VolumeLevelCallback cb = NULL;
            void* user = NULL;
            {
                LockGuard lock(state_mutex_);
                cb = level_cb_;
                user = level_user_;
            }
            if (cb != NULL) {
                cb(level, user);
            }
        }
        return;
    }

    if (m.fblock == kVolumeFblock) {
        unsigned steps = 0U;
        uint8_t dir = 0U;
        if (decodeVolumeButton(m, &steps, &dir)) {
            VolumeCallback cb = NULL;
            void* user = NULL;
            {
                LockGuard lock(state_mutex_);
                cb = vol_cb_;
                user = vol_user_;
            }
            if (cb != NULL) {
                cb(steps, dir, user);
            }
        }

        const int tel = decodeTelephoneButton(m);
        if (tel == 1 && !tel_down_) {
            tel_down_ = true;
            MflButtonCallback cb = NULL;
            void* user = NULL;
            bool allow = false;
            {
                LockGuard lock(state_mutex_);
                cb = mfl_tel_cb_;
                user = mfl_tel_user_;
                allow = (mode_ == kInputForward && owned_ && !phone_to_idrive_ && cb != NULL);
            }
            if (allow) {
                tel_forwarded_ = true;
                cb(true, user);
            }
        } else if (tel == 0 && tel_down_) {
            tel_down_ = false;
            if (tel_forwarded_) {
                tel_forwarded_ = false;
                MflButtonCallback cb = NULL;
                void* user = NULL;
                {
                    LockGuard lock(state_mutex_);
                    cb = mfl_tel_cb_;
                    user = mfl_tel_user_;
                }
                if (cb != NULL) {
                    cb(false, user);
                }
            }
        }

        const int ptt = decodePttButton(m);
        if (ptt == 1 && !ptt_down_) {
            ptt_down_ = true;
            MflButtonCallback cb = NULL;
            void* user = NULL;
            bool allow = false;
            {
                LockGuard lock(state_mutex_);
                cb = mfl_ptt_cb_;
                user = mfl_ptt_user_;
                allow = (mode_ == kInputForward && owned_ && cb != NULL);
            }
            if (allow) {
                ptt_forwarded_ = true;
                cb(true, user);
            }
        } else if (ptt == 0 && ptt_down_) {
            ptt_down_ = false;
            if (ptt_forwarded_) {
                ptt_forwarded_ = false;
                MflButtonCallback cb = NULL;
                void* user = NULL;
                {
                    LockGuard lock(state_mutex_);
                    cb = mfl_ptt_cb_;
                    user = mfl_ptt_user_;
                }
                if (cb != NULL) {
                    cb(false, user);
                }
            }
        }
        return;
    }

    if (m.fblock != kControllerFblock) {
        return;
    }
    ++e5_messages_;

    if (m.op == kMostOpStatus) {
        const bool chosen = (protocol_.kind() != CcsProtocol::kUnknown);
        if (!protocol_.accept(m.inst, m.fkt)) {
            if (!other_protocol_logged_) {
                other_protocol_logged_ = true;
                CARPLAY_LOG_INFO("knob",
                                 "E5.%02x fkt 0x%03x ignored: active protocol is %s",
                                 m.inst,
                                 m.fkt,
                                 CcsProtocol::name(protocol_.kind()));
            }
            return;
        }
        if (!chosen && protocol_.kind() != CcsProtocol::kUnknown) {
            CARPLAY_LOG_INFO("knob", "controller protocol locked: %s",
                             CcsProtocol::name(protocol_.kind()));
        }
    }

    const uint8_t* data = m.data;
    uint8_t keys[8];
    if (m.inst == CcsDecoder::kInstance &&
        (m.fkt == 0xC47U || m.fkt == 0xC4FU) &&
        m.op == kMostOpStatus &&
        m.data != NULL &&
        m.len <= sizeof(keys)) {
        normalizePushButtons(m.data, m.len, push_prev_, keys);
        data = keys;
    }

    CcsEvent ev[8];
    const int n = decoder_.feed(m.fblock,
                                m.inst,
                                m.fkt,
                                static_cast<uint8_t>(m.op),
                                data,
                                m.len,
                                ev,
                                8);
    const bool is_owned = owned();
    const bool phone_idrive = phoneToIdrive();
    const bool send = (mode_ == kInputForward && is_owned);

    for (int i = 0; i < n; ++i) {
        if (ev[i].kind == CcsEvent::kRotary) {
            if (send) {
                if (event_cb_ != NULL) {
                    event_cb_(ev[i], event_user_);
                }
                int rem = ev[i].delta;
                while (rem != 0) {
                    int chunk = rem;
                    if (chunk > 127) chunk = 127;
                    if (chunk < -127) chunk = -127;
                    rem -= chunk;
                    hid::Zbe3Event hw;
                    hw.center_pressed = sent_push_;
                    hw.button_mask = sent_buttons_;
                    hw.dir_mask = 0U;
                    hw.rotary_delta = static_cast<int8_t>(chunk);
                    emitZbe3(hw);
                }
            }
            continue;
        }

        if (ev[i].kind != CcsEvent::kKey) {
            continue;
        }

        // Notify hard key observer (e.g. MENU / OPTION / NAV / MAP / BACK).
        if (ev[i].key == kCcsKeyMenu || ev[i].key == kCcsKeyBack ||
            ev[i].key == kCcsKeyOption || ev[i].key == kCcsKeyMedia ||
            ev[i].key == kCcsKeyNav || ev[i].key == kCcsKeyMap ||
            ev[i].key == kCcsKeyCom) {
            HardKeyCallback hcb = NULL;
            void* huser = NULL;
            {
                LockGuard lock(state_mutex_);
                hcb = hard_key_cb_;
                huser = hard_key_user_;
            }
            if (hcb != NULL && (send || !ev[i].down)) {
                hcb(ev[i].key, ev[i].down, ev[i].name, huser);
            }
        }

        if (ev[i].dir_mask != 0U) {
            // Tilt: forward press and matching release (or press only for Zbe3Event wheel step).
            if (ev[i].down) {
                if (send) {
                    if (event_cb_ != NULL) {
                        event_cb_(ev[i], event_user_);
                    }
                    hid::Zbe3Event hw;
                    hw.center_pressed = sent_push_;
                    hw.button_mask = sent_buttons_;
                    hw.dir_mask = ev[i].dir_mask;
                    hw.rotary_delta = 0;
                    emitZbe3(hw);
                }
            } else if (send && event_cb_ != NULL) {
                event_cb_(ev[i], event_user_);
            }
            continue;
        }

        if (ev[i].key == kCcsKeyCenter) {
            bool forward = false;
            if (ev[i].down) {
                if (send) {
                    sent_push_ = true;
                    forward = true;
                }
            } else if (sent_push_) {
                sent_push_ = false;
                forward = true;
            }
            if (forward) {
                if (event_cb_ != NULL) {
                    event_cb_(ev[i], event_user_);
                }
                hid::Zbe3Event hw;
                hw.center_pressed = sent_push_;
                hw.button_mask = sent_buttons_;
                emitZbe3(hw);
            }
            continue;
        }

        const uint8_t bit = ev[i].btn_mask;
        if (bit == 0U || !isCarPlayKnobBit(bit)) {
            continue;
        }
        if (bit == kCcsBtnCom && phone_idrive && ev[i].down) {
            continue;
        }

        bool forward = false;
        if (ev[i].down) {
            if (send) {
                sent_buttons_ |= bit;
                forward = true;
            }
        } else if ((sent_buttons_ & bit) != 0U) {
            sent_buttons_ &= static_cast<uint8_t>(~bit);
            forward = true;
        }

        if (forward) {
            if (event_cb_ != NULL) {
                event_cb_(ev[i], event_user_);
            }
            hid::Zbe3Event hw;
            hw.center_pressed = sent_push_;
            hw.button_mask = sent_buttons_;
            emitZbe3(hw);
        }
    }
}

void EvoKnob::readOlderProtocol() {
    static const uint8_t dummy[4] = {0U, 0U, 0U, 0U};
    for (size_t i = 0; i < sizeof(kOlderCcsFunctions) / sizeof(kOlderCcsFunctions[0]); ++i) {
        VmostMsgOut m;
        buildVmostGet(m, kControllerFblock, CcsDecoder::kCcsInstance, kOlderCcsFunctions[i], dummy);
        if (vmost_.send(&m) == 0) {
            ++gets_;
        }
    }
}

void EvoKnob::run() {
    if (vmost_.connect(&EvoKnob::vmostCallback, this, 0) != 0) {
        CARPLAY_LOG_WARN("knob", "vmostd refused connection");
        return;
    }
    connected_ = true;

    n_registered_ = 0;
    for (size_t i = 0; i < sizeof(kCcsInstances); ++i) {
        if (vmost_.shadowRegister(kControllerFblock, kCcsInstances[i]) == 0) {
            registered_[n_registered_++] = kCcsInstances[i];
        }
    }

    static const uint8_t dummy[4] = {0U, 0U, 0U, 0U};
    if (n_registered_ > 0) {
        for (size_t i = 0; i < sizeof(kCcs35upFunctions) / sizeof(kCcs35upFunctions[0]); ++i) {
            VmostMsgOut m;
            buildVmostGet(m, kControllerFblock, CcsDecoder::kInstance, kCcs35upFunctions[i], dummy);
            if (vmost_.send(&m) == 0) {
                ++gets_;
            }
        }
        protocol_.ccs35upAsked(monoMs32());
        if (query_older_immediately_) {
            protocol_.markOlderAsked();
            readOlderProtocol();
        }
    }

    int fd = -1;
    if (n_registered_ > 0 && vmost_.fileDescriptorGet(&fd) == 0 && fd >= 0) {
        // Volume buttons + MFL telephone + MFL PTT
        static const uint8_t vol_inst[2] = {kVolumeCsInstance, kVolumeMflInstance};
        static const uint16_t vol_fkt[2] = {kVolumeCsFkt, kVolumeMflFkt};
        n_vol_registered_ = 0;
        for (int i = 0; i < 2; ++i) {
            if (vmost_.shadowRegister(kVolumeFblock, vol_inst[i]) == 0) {
                vol_registered_[n_vol_registered_++] = vol_inst[i];
                VmostMsgOut vm;
                buildVmostGet(vm, kVolumeFblock, vol_inst[i], vol_fkt[i], dummy);
                if (vmost_.send(&vm) == 0) {
                    ++gets_;
                }
                if (vol_inst[i] == kVolumeMflInstance) {
                    VmostMsgOut tm;
                    buildVmostGet(tm, kVolumeFblock, kVolumeMflInstance, kMflTelephoneFkt, dummy);
                    if (vmost_.send(&tm) == 0) {
                        ++gets_;
                    }
                    VmostMsgOut pm;
                    buildVmostGet(pm, kVolumeFblock, kVolumeMflInstance, kMflPttFkt, dummy);
                    if (vmost_.send(&pm) == 0) {
                        ++gets_;
                    }
                }
            }
        }

        // AudioMaster volume level (20.00.C08)
        level_registered_ = (vmost_.shadowRegister(kAudioMasterFblock, kAudioMasterInstance) == 0);
        if (level_registered_) {
            static const uint8_t record[2] = {0x01U, 0x00U};
            VmostMsgOut lm;
            buildVmostGet(lm, kAudioMasterFblock, kAudioMasterInstance, kVolumeLevelFkt, record,
                          sizeof(record));
            if (vmost_.send(&lm) == 0) {
                ++gets_;
            }
        }

#ifndef _WIN32
        for (;;) {
            {
                LockGuard lock(state_mutex_);
                if (!running_) {
                    break;
                }
            }
            struct pollfd p;
            p.fd = fd;
            p.events = POLLIN;
            p.revents = 0;
            const int r = poll(&p, 1, 100);
            if (r < 0 && errno != EINTR) {
                break;
            }
            if (r > 0 && (p.revents & (POLLERR | POLLHUP | POLLNVAL))) {
                break;
            }
            if (r > 0 && (p.revents & POLLIN)) {
                if (vmost_.processMessages() != 0) {
                    connected_ = false;
                    break;
                }
            }
            if (!owned()) {
                releaseHeldKeys("picture gone");
            }
            if (protocol_.olderDue(monoMs32())) {
                readOlderProtocol();
            }
        }
#endif
    }

    releaseHeldKeys("controller stopped");
    if (connected_) {
        if (level_registered_) {
            vmost_.shadowDeregister(kAudioMasterFblock, kAudioMasterInstance);
            level_registered_ = false;
        }
        for (int i = 0; i < n_vol_registered_; ++i) {
            vmost_.shadowDeregister(kVolumeFblock, vol_registered_[i]);
        }
        n_vol_registered_ = 0;
        for (int i = 0; i < n_registered_; ++i) {
            vmost_.shadowDeregister(kControllerFblock, registered_[i]);
        }
        n_registered_ = 0;
        vmost_.disconnect();
        connected_ = false;
    }
}

}  // namespace platform
}  // namespace carplay
