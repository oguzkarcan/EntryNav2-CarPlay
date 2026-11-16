#include "carplay/platform/carplay_daemon.hpp"

#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#else
#include <direct.h>
#include <process.h>
#endif

#include "carplay/platform/file_util.hpp"
#include "carplay/platform/log.hpp"
#include "carplay/platform/net_compat.hpp"

namespace carplay {
namespace platform {

namespace {

int daemonPid() {
#ifndef _WIN32
    return static_cast<int>(getpid());
#else
    return static_cast<int>(_getpid());
#endif
}

bool ensureDirExists(const std::string& path) {
    if (path.empty()) {
        return false;
    }
#ifndef _WIN32
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    return mkdir(path.c_str(), 0700) == 0;
#else
    return _mkdir(path.c_str()) == 0;
#endif
}

}  // namespace

CarPlayDaemon::CarPlayDaemon(const CarPlayDaemonConfig& config)
    : config_(config),
      reactor_(),
      rng_(),
      identity_(),
      pairing_store_(NULL),
      display_width_(config.fallback_width),
      display_height_(config.fallback_height),
      airplay_config_(info::bmwEntryNav2_800x480(config.touch_enabled)),
      video_(),
      video_sink_(video_, 110, false),
      audio_sink_(config.audio_config),
      mic_(config.mic_config),
      media_sink_(audio_sink_, mic_, this),
      media_engine_(NULL),
      server_(NULL),
      knob_(),
      touch_(),
      input_bridge_(NULL),
      control_(),
      peek_(),
      media_press_(),
      cmd_mu_(),
      cmd_queue_(),
      cmd_post_pending_(false),
      tick_timer_(Reactor::kNoTimer),
      started_(false),
      stopping_(false),
      video_running_(false),
      session_focus_initialized_(false),
      focus_(true),
      await_show_(false),
      asking_(false),
      reverse_gear_(false),
      in_call_(false),
      night_mode_(false),
      picture_shown_(false),
      picture_opacity_(1.0f) {}

CarPlayDaemon::~CarPlayDaemon() {
    stop();
}

bool CarPlayDaemon::start() {
    if (started_) {
        return true;
    }
    stopping_ = false;
    session_focus_initialized_ = false;
    if (!reactor_.init()) {
        CARPLAY_LOG_ERROR("daemon", "CarPlayDaemon: Reactor::init() failed");
        return false;
    }

    ensureDirExists(config_.data_dir);
    ensurePrivateDirectory(config_.data_dir);

    const StorageStatus id_status =
        loadOrCreateIdentity(config_.data_dir, rng_, identity_, config_.storage_options);
    if (!storageUsable(id_status)) {
        CARPLAY_LOG_ERROR("daemon", "CarPlayDaemon: failed to load or create identity in %s (%s)",
                          config_.data_dir.c_str(), storageStatusName(id_status));
        return false;
    }

    pairing_store_ = new FilePairingStore(config_.storage_options);
    const StorageStatus pair_status = pairing_store_->open(config_.data_dir);
    if (!storageUsable(pair_status)) {
        CARPLAY_LOG_WARN("daemon", "CarPlayDaemon: failed to open pairings in %s (%s)",
                         config_.data_dir.c_str(), storageStatusName(pair_status));
    }

    // Discover display dimensions dynamically from LayerManager when enabled.
    uint32_t w = config_.fallback_width;
    uint32_t h = config_.fallback_height;
    if (config_.query_display_from_ilm) {
        EvoIlm ilm(config_.video_config.ilm_ctl_path,
                   config_.video_config.compositor_conf_path);
        uint32_t ilm_w = 0U;
        uint32_t ilm_h = 0U;
        if (ilm.screenSize(ilm_w, ilm_h) && ilm_w > 0U && ilm_h > 0U) {
            w = ilm_w;
            h = ilm_h;
            CARPLAY_LOG_INFO("daemon", "CarPlayDaemon: LayerManager reported screen %ux%u", w, h);
        }
    }
    if (!info::bmwEntryNav2ForDisplay(
            static_cast<int32_t>(w), static_cast<int32_t>(h),
            config_.touch_enabled, airplay_config_)) {
        w = 800U;
        h = 480U;
        info::bmwEntryNav2ForDisplay(800, 480, config_.touch_enabled, airplay_config_);
    }
    display_width_ = w;
    display_height_ = h;
    config_.video_config.setDisplay(display_width_, display_height_, display_width_, display_height_);

    if (config_.enable_control) {
        if (!control_.start(config_.control_name.c_str(),
                            config_.state_file.c_str(),
                            &CarPlayDaemon::controlThunk,
                            this)) {
            CARPLAY_LOG_ERROR("daemon", "CarPlayDaemon: EvoControl failed to bind \"%s\"",
                              config_.control_name.c_str());
            delete pairing_store_;
            pairing_store_ = NULL;
            return false;
        }
    }

    media_engine_ = new MediaEngine(reactor_, media_sink_, config_.media_config);

    config_.server_config.control_port = config_.control_port;
    server_ = new SessionServer(reactor_,
                                airplay_config_,
                                identity_,
                                *pairing_store_,
                                rng_,
                                *this,
                                *media_engine_,
                                NULL,
                                config_.server_config);

    const bool server_ok = config_.bind_loopback_only
                               ? server_->start(Address::ipv4Loopback(config_.control_port))
                               : server_->start();
    if (!server_ok) {
        CARPLAY_LOG_ERROR("daemon", "CarPlayDaemon: SessionServer failed to listen on port %u",
                          static_cast<unsigned>(config_.control_port));
        stop();
        return false;
    }

    video_running_ = false;
    if (config_.enable_video) {
        if (video_.init(config_.video_config) && video_.start()) {
            video_running_ = true;
        } else {
            CARPLAY_LOG_WARN("daemon", "CarPlayDaemon: EvoVideo unavailable (continuing without hardware surface)");
            video_.stop();
        }
    }

    if (config_.enable_audio) {
        if (!audio_sink_.start()) {
            CARPLAY_LOG_WARN("daemon", "CarPlayDaemon: EvoAudioSink unavailable");
        }
        if (!mic_.start(*media_engine_)) {
            CARPLAY_LOG_WARN("daemon", "CarPlayDaemon: EvoMic unavailable");
        }
    }

    if (config_.enable_input) {
        EvoInputBridgeConfig br_cfg;
        br_cfg.display_width = static_cast<int32_t>(display_width_);
        br_cfg.display_height = static_cast<int32_t>(display_height_);
        br_cfg.menu_to_carplay = !config_.menu_exits_to_idrive;
        br_cfg.phone_to_idrive = in_call_;
        input_bridge_ = new EvoInputBridge(reactor_, *server_, br_cfg, this);
        touch_.setDisplaySize(display_width_, display_height_);
        input_bridge_->attach(&knob_, &touch_);

        if (!knob_.start(config_.knob_config, NULL, NULL)) {
            CARPLAY_LOG_WARN("daemon", "CarPlayDaemon: EvoKnob unavailable");
        }
        const bool touch_ok =
            config_.use_test_touch_udp
                ? touch_.startUdpForTest(config_.test_touch_udp_port, kInputForward, NULL, NULL)
                : touch_.start(kInputForward, NULL, NULL);
        if (!touch_ok) {
            CARPLAY_LOG_WARN("daemon", "CarPlayDaemon: EvoTouch unavailable");
        }
    }

    if (!config_.day_night_file.empty()) {
        int dn = 0;
        if (readDayNightFile(config_.day_night_file.c_str(), dn)) {
            applyDayNight(dn);
        }
    }

    if (config_.tick_interval_ms > 0) {
        tick_timer_ = reactor_.startTimer(config_.tick_interval_ms, config_.tick_interval_ms, this);
    }

    started_ = true;
    stepVisibility();
    return true;
}

void CarPlayDaemon::stop() {
    stopping_ = true;
    media_press_.cancel();
    if (!config_.media_recall_file.empty()) {
        removeFile(config_.media_recall_file);
    }

    if (tick_timer_ != Reactor::kNoTimer) {
        reactor_.cancelTimer(tick_timer_);
        tick_timer_ = Reactor::kNoTimer;
    }
    // Join the control thread first: it posts onPostedCommands(this), and
    // Reactor::cancelPosted requires posting threads to have stopped.
    control_.stop();
    reactor_.cancelPosted(&CarPlayDaemon::onPostedCommands, this);
    {
        LockGuard lock(cmd_mu_);
        cmd_queue_.clear();
        cmd_post_pending_ = false;
    }

    touch_.setOwned(false);
    knob_.setOwned(false);
    touch_.stop();
    knob_.stop();

    if (input_bridge_ != NULL) {
        input_bridge_->setOwned(false);
        input_bridge_->detach();
        delete input_bridge_;
        input_bridge_ = NULL;
    }

    if (server_ != NULL) {
        server_->stop();
        delete server_;
        server_ = NULL;
    }

    // Join the capture thread before the engine goes away: the worker calls
    // MediaEngine::submitMicrophonePcm() outside its own lock.
    mic_.stop();

    if (media_engine_ != NULL) {
        delete media_engine_;
        media_engine_ = NULL;
    }

    audio_sink_.stop();
    video_.stop();
    video_running_ = false;

    if (pairing_store_ != NULL) {
        delete pairing_store_;
        pairing_store_ = NULL;
    }

    started_ = false;
    session_focus_initialized_ = false;
    picture_shown_ = false;
    picture_opacity_ = 1.0f;
}

int CarPlayDaemon::run() {
    if (!started_ && !start()) {
        return 1;
    }
    reactor_.run();
    stop();
    return 0;
}

void CarPlayDaemon::requestStop() {
    stopping_ = true;
    reactor_.stop();
}

uint16_t CarPlayDaemon::controlPort() const {
    return server_ != NULL ? server_->controlPort() : 0U;
}

bool CarPlayDaemon::hasActiveSession() const {
    return server_ != NULL && server_->hasActiveSession();
}

void CarPlayDaemon::stepVisibility() {
    if ((config_.stop_flag != NULL && *config_.stop_flag != 0) ||
        (!config_.stop_file.empty() && pathExists(config_.stop_file))) {
        requestStop();
        return;
    }

    const uint32_t now_ms = static_cast<uint32_t>(monotonicMillis());
    const bool active = hasActiveSession();
    const bool video_ok = !config_.enable_video || video_running_;
    const bool on_screen = active && focus_ && !reverse_gear_ && video_ok;
    const bool asks = active && asking_ && !focus_;

    PeekTiming::Picture pic = peek_.turn(now_ms, on_screen);
    picture_shown_ = pic.shown;
    picture_opacity_ = pic.opacity;

    bool picture_up = pic.shown;
    bool picture_started = active;

    if (config_.enable_video && video_running_) {
        video_.setVisible(pic.shown);
        const bool opacity_refused =
            pic.shown && !video_.setOpacity(pic.opacity) && pic.opacity < 1.0f;
        picture_up = video_.isVisible();
        picture_started = video_.isReady();
        if (opacity_refused) {
            CARPLAY_LOG_WARN("daemon", "CarPlayDaemon: compositor refused opacity %.2f; stepping surface aside",
                             static_cast<double>(pic.opacity));
            peek_.refuseOpacity(now_ms, now_ms);
            pic = peek_.turn(now_ms, on_screen);
            picture_shown_ = pic.shown;
            picture_opacity_ = pic.opacity;
            video_.setVisible(pic.shown);
            picture_up = video_.isVisible();
        }
    }

    if (input_bridge_ != NULL) {
        const bool owned = pic.shown && picture_up;
        input_bridge_->setPictureStarted(picture_started);
        input_bridge_->setOwned(owned);
    }

    if (config_.enable_control && control_.running()) {
        const int overlay = on_screen ? 1 : (asks ? 2 : 0);
        control_.writeState(active ? "connected" : "connecting", overlay);
    }
}

void CarPlayDaemon::controlThunk(const ControlCommand& cmd, void* user) {
    static_cast<CarPlayDaemon*>(user)->submitControlCommand(cmd);
}

void CarPlayDaemon::submitControlCommand(const ControlCommand& cmd) {
    bool need_post = false;
    {
        LockGuard lock(cmd_mu_);
        cmd_queue_.push_back(cmd);
        if (!cmd_post_pending_) {
            cmd_post_pending_ = true;
            need_post = true;
        }
    }
    if (need_post && !reactor_.post(&CarPlayDaemon::onPostedCommands, this)) {
        LockGuard lock(cmd_mu_);
        cmd_post_pending_ = false;
    }
}

void CarPlayDaemon::onPostedCommands(void* ctx) {
    static_cast<CarPlayDaemon*>(ctx)->drainControlQueue();
}

void CarPlayDaemon::drainControlQueue() {
    std::vector<ControlCommand> local;
    {
        LockGuard lock(cmd_mu_);
        local.swap(cmd_queue_);
        cmd_post_pending_ = false;
    }
    for (size_t i = 0; i < local.size(); ++i) {
        handleControlCommand(local[i]);
    }
}

void CarPlayDaemon::handleControlCommand(const ControlCommand& cmd) {
    const uint32_t now_ms = static_cast<uint32_t>(monotonicMillis());
    if (cmd.verb == "show" || cmd.verb == "hide" || cmd.verb == "await" || cmd.verb == "quit" ||
        (cmd.verb == "call" && (cmd.arg != 0) != in_call_) ||
        (cmd.verb == "gear" && (cmd.arg == 2) != reverse_gear_)) {
        media_press_.cancel();
        if (!config_.media_recall_file.empty()) {
            removeFile(config_.media_recall_file);
        }
    }

    if (cmd.verb == "show") {
        focus_ = true;
        asking_ = false;
        stepVisibility();
        if (server_ != NULL && server_->hasActiveSession()) {
            server_->requestKeyFrame(110);
        }
    } else if (cmd.verb == "hide") {
        focus_ = false;
        asking_ = false;
        stepVisibility();
    } else if (cmd.verb == "await") {
        await_show_ = true;
    } else if (cmd.verb == "drivemode") {
        if (peek_.driveMode(now_ms)) {
            stepVisibility();
        }
    } else if (cmd.verb == "popup") {
        const PeekTiming::Popup p = peek_.popup(now_ms, cmd.arg != 0);
        if (p != PeekTiming::kPopupIgnored) {
            stepVisibility();
        }
    } else if (cmd.verb == "gear") {
        const bool rev = (cmd.arg == 2);
        if (rev != reverse_gear_) {
            reverse_gear_ = rev;
            stepVisibility();
        }
    } else if (cmd.verb == "call") {
        in_call_ = (cmd.arg != 0);
        if (input_bridge_ != NULL) {
            input_bridge_->setPhoneToIdrive(in_call_);
        } else {
            knob_.setPhoneToIdrive(in_call_);
        }
    } else if (cmd.verb == "daynight") {
        applyDayNight(cmd.arg);
    } else if (cmd.verb == "quit") {
        requestStop();
    }
}

void CarPlayDaemon::applyDayNight(int val) {
    if (val != 1 && val != 2) {
        return;
    }
    night_mode_ = (val == 2);
    if (server_ != NULL) {
        server_->setNightMode(night_mode_);
    }
}

void CarPlayDaemon::onTimer(uint32_t /*timer_id*/) {
    stepVisibility();
}

void CarPlayDaemon::activateSessionFocus() {
    if (session_focus_initialized_) {
        return;
    }
    session_focus_initialized_ = true;
    media_press_.cancel();
    if (!config_.media_recall_file.empty()) {
        removeFile(config_.media_recall_file);
    }
    focus_ = !await_show_;
    asking_ = await_show_;
    if (server_ != NULL) {
        server_->setNightMode(night_mode_);
    }
    stepVisibility();
}

// ---- session::SessionListener ----

void CarPlayDaemon::onSessionActive(session::Session& /*session*/) {
    activateSessionFocus();
}

void CarPlayDaemon::onDeviceInfo(session::Session& /*session*/, const session::DeviceInfo& info) {
    CARPLAY_LOG_INFO("daemon", "CarPlayDaemon: device connected name=\"%s\" model=\"%s\"",
                     info.name.c_str(), info.model.c_str());
    activateSessionFocus();
}

void CarPlayDaemon::onHostUiRequested(session::Session& /*session*/) {
    focus_ = false;
    asking_ = false;
    stepVisibility();
}

void CarPlayDaemon::onCommand(session::Session& /*session*/,
                              const std::string& type,
                              const bplist::Value& /*params*/) {
    if (type == "requestUI") {
        focus_ = true;
        asking_ = false;
        stepVisibility();
    }
}

void CarPlayDaemon::onSessionEnded(session::Session& /*session*/) {
    session_focus_initialized_ = false;
    mic_.stopCapture();
    audio_sink_.stopAll();
    if (input_bridge_ != NULL) {
        input_bridge_->onSessionEnded();
    }
    focus_ = false;
    asking_ = false;
    media_press_.cancel();
    if (!config_.media_recall_file.empty()) {
        removeFile(config_.media_recall_file);
    }
    stepVisibility();
}

// ---- MediaSink (delegated from EvoAudioMediaSink) ----

void CarPlayDaemon::onScreenStreamActive(int32_t type, bool active) {
    if (active) {
        activateSessionFocus();
    }
    video_sink_.onScreenStreamActive(type, active);
    stepVisibility();
}

void CarPlayDaemon::onVideoConfig(int32_t type,
                                  stream::VideoCodecType codec,
                                  const uint8_t* annexb_data,
                                  size_t annexb_len,
                                  const uint8_t* raw_config,
                                  size_t raw_len,
                                  float width_px,
                                  float height_px) {
    video_sink_.onVideoConfig(type, codec, annexb_data, annexb_len,
                              raw_config, raw_len, width_px, height_px);
}

void CarPlayDaemon::onVideoFrame(int32_t type,
                                 const uint8_t* annexb_data,
                                 size_t len,
                                 uint64_t sender_nanos,
                                 int64_t arrival_mono_nanos) {
    const bool was_ready = video_.isReady();
    video_sink_.onVideoFrame(type, annexb_data, len, sender_nanos, arrival_mono_nanos);
    if (!was_ready && video_.isReady()) {
        stepVisibility();
    }
}

// ---- EvoInputListener ----

void CarPlayDaemon::onUiKey(CcsKey key, bool pressed, const char* name) {
    const uint32_t now_ms = static_cast<uint32_t>(monotonicMillis());
    const bool active = hasActiveSession();
    const bool video_ok = !config_.enable_video || video_running_;
    const bool on_screen = active && focus_ && !reverse_gear_ && video_ok;

    if (key == kCcsKeyMedia) {
        const bool allowed = !asking_ && !stopping_ &&
                             mediaRecallAllowed(active, on_screen, stopping_, in_call_, reverse_gear_);
        if (pressed) {
            media_press_.feed(0U, now_ms, allowed);
        }
        if (media_press_.feed(pressed ? 1U : 0U, now_ms, allowed)) {
            if (!config_.media_recall_file.empty()) {
                writeMediaRecall(config_.media_recall_file.c_str(), daemonPid(), now_ms);
            }
        }
    }

    if (!pressed || !on_screen) {
        return;
    }

    // Keys that leave CarPlay and return the screen to iDrive (MENU, MAP, OPTIONS, or COM during a native call).
    const bool is_leave_key =
        config_.menu_exits_to_idrive &&
        (key == kCcsKeyMenu || key == kCcsKeyMap || key == kCcsKeyOption ||
         (key == kCcsKeyCom && in_call_));
    if (is_leave_key) {
        if (peek_.hardKey()) {
            focus_ = false;
            media_press_.cancel();
            if (!config_.media_recall_file.empty()) {
                removeFile(config_.media_recall_file);
            }
            if (!config_.app_key_file.empty()) {
                removeFile(config_.app_key_file);
            }
            stepVisibility();
        }
        return;
    }

    // Keys that stay in CarPlay and notify the HMI plugin to keep iDrive on blank state 13 underneath.
    const bool is_app_key =
        key == kCcsKeyBack || key == kCcsKeyLeft || key == kCcsKeyMedia ||
        key == kCcsKeyNav || (key == kCcsKeyCom && !in_call_);
    if (is_app_key && !config_.app_key_file.empty()) {
        writeAppKeyFile(config_.app_key_file.c_str(), name ? name : "KEY");
    }
}

void CarPlayDaemon::onVolumeStep(unsigned /*steps*/, uint8_t /*direction*/) {
    const uint32_t now_ms = static_cast<uint32_t>(monotonicMillis());
    if (peek_.volumeKey(now_ms, false)) {
        stepVisibility();
    }
}

void CarPlayDaemon::onVolumeLevel(const VolumeLevel& /*level*/) {
    peek_.volumeLevel(false);
}

}  // namespace platform
}  // namespace carplay
