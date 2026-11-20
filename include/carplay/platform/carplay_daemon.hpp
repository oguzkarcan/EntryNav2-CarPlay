#ifndef CARPLAY_PLATFORM_CARPLAY_DAEMON_HPP
#define CARPLAY_PLATFORM_CARPLAY_DAEMON_HPP

// BMW HU_ENTRYNAV2 CarPlay daemon orchestrator (`carplayd`).
//
// Integrates:
//   * Reactor + SessionServer + MediaEngine (AirPlay control :7000, event, timing, screen, audio, mic, iAP2)
//   * Persistent accessory identity (`identity.bin`) & controller pairings (`controllers.bin`)
//   * Dynamic display resolution discovery via EvoIlm::screenSize() -> info::bmwEntryNav2ForDisplay()
//   * EvoVideo (`libxsvideo.so.4` + OMAP dma-buf + LayerManager)
//   * EvoAudioSink + EvoMic (`libasound.so.2`: `entertainment`, `carplay_alt`, `tel_out1`, `mic1`)
//   * EvoKnob (`libvmostclient.so.1`) + EvoTouch (UDP 30567) + EvoInputBridge (-> EventChannel HID/Siri)
//   * EvoControl abstract Unix datagram socket (`\0entry-carplayd-control`) & atomic state file
//   * PeekTiming (volume dim/peek, driving mode peek, iDrive popup step-aside) & MediaDoublePress recall

#include <signal.h>
#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/airplay_info.hpp"
#include "carplay/airplay_session.hpp"
#include "carplay/pairing.hpp"
#include "carplay/platform/carplay_connectivity.hpp"
#include "carplay/platform/evo_audio.hpp"
#include "carplay/platform/evo_control.hpp"
#include "carplay/platform/evo_ilm.hpp"
#include "carplay/platform/evo_input_bridge.hpp"
#include "carplay/platform/evo_knob.hpp"
#include "carplay/platform/evo_mic.hpp"
#include "carplay/platform/evo_touch.hpp"
#include "carplay/platform/evo_video.hpp"
#include "carplay/platform/media_engine.hpp"
#include "carplay/platform/mfi_i2c.hpp"
#include "carplay/platform/os_random.hpp"
#include "carplay/platform/pairing_storage.hpp"
#include "carplay/platform/peek_timing.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/service_contract.hpp"
#include "carplay/platform/session_server.hpp"
#include "carplay/platform/thread.hpp"

namespace carplay {
namespace platform {

struct CarPlayDaemonConfig {
    uint16_t control_port;
    bool bind_loopback_only;

    std::string data_dir;
    std::string control_name;
    std::string state_file;
    std::string app_key_file;
    std::string day_night_file;
    std::string media_recall_file;
    std::string stop_file;
    /// Optional flag set by a signal handler; polled on every tick (NULL = unused).
    const volatile sig_atomic_t* stop_flag;

    bool enable_video;
    bool enable_audio;
    bool enable_input;
    bool enable_control;
    /// Safe defaults: both wireless and wired transports are disabled by default so `carplayd`
    /// never borrows ALPS SPP slot 5, toggles car-native Wi-Fi AP, or touches Apple USB devices
    /// alongside BMW MediaPlayer/CARPLAY unless explicitly enabled (or passed --wireless / --wired).
    bool enable_wireless;
    bool enable_wired;

    bool query_display_from_ilm;
    uint32_t fallback_width;
    uint32_t fallback_height;
    bool touch_enabled;
    /// When true (default on vehicle), pressing physical MENU / MAP / OPTIONS while CarPlay is on
    /// screen steps the CarPlay surface aside and returns focus to iDrive (while BACK, MEDIA, NAV,
    /// COM stay in CarPlay and write `kAppKeyFile`).
    bool menu_exits_to_idrive;

    /// Test hook: start EvoTouch on a localhost UDP socket instead of AF_PACKET.
    bool use_test_touch_udp;
    uint16_t test_touch_udp_port;

    int64_t tick_interval_ms;

    StorageOptions storage_options;
    EvoVideoConfig video_config;
    EvoAudioConfig audio_config;
    EvoMicConfig mic_config;
    EvoKnobConfig knob_config;
    SessionServerConfig server_config;
    MediaEngineConfig media_config;
    CarPlayConnectivityConfig connectivity_config;
    MfiI2cConfig mfi_i2c_config;

    CarPlayDaemonConfig()
        : control_port(7000U),
          bind_loopback_only(false),
          data_dir(contract::kDataDir),
          control_name(contract::kControlName),
          state_file(contract::kStateFile),
          app_key_file(contract::kAppKeyFile),
          day_night_file(contract::kDayNightFile),
          media_recall_file(contract::kMediaRecallFile),
          stop_file(contract::kServiceStop),
          stop_flag(NULL),
          enable_video(true),
          enable_audio(true),
          enable_input(true),
          enable_control(true),
          enable_wireless(false),
          enable_wired(false),
          query_display_from_ilm(true),
          fallback_width(800U),
          fallback_height(480U),
          touch_enabled(true),
          menu_exits_to_idrive(true),
          use_test_touch_udp(false),
          test_touch_udp_port(0U),
          tick_interval_ms(100),
          storage_options(),
          video_config(),
          audio_config(),
          mic_config(),
          knob_config(),
          server_config(),
          media_config(),
          connectivity_config(),
          mfi_i2c_config() {}
};

class CarPlayDaemon : public session::SessionListener,
                      public MediaSink,
                      public EvoInputListener,
                      public TimerHandler {
public:
    explicit CarPlayDaemon(const CarPlayDaemonConfig& config = CarPlayDaemonConfig());
    virtual ~CarPlayDaemon();

    /// Initializes Reactor, persistent identity/pairings, display resolution, and subcomponents,
    /// and starts listening on the control port and control channel.
    bool start();
    /// Stops all workers, closes active sessions, and removes the runtime state file.
    void stop();

    /// Runs the Reactor loop until `requestStop()`, the `"quit"` control command, `stop_file`
    /// or `stop_flag`.
    int run();
    /// Thread-safe stop request. NOT async-signal-safe (Reactor::stop() takes a mutex):
    /// signal handlers must set `CarPlayDaemonConfig::stop_flag` instead.
    void requestStop();

    bool isStarted() const { return started_; }
    uint16_t controlPort() const;
    uint32_t displayWidth() const { return display_width_; }
    uint32_t displayHeight() const { return display_height_; }
    const info::AirPlayConfig& airplayConfig() const { return airplay_config_; }
    const pairing::Identity& accessoryIdentity() const { return identity_; }

    // Visibility & focus state inspection
    bool hasActiveSession() const;
    bool isFocusOwned() const { return focus_; }
    bool isAskingToShow() const { return asking_; }
    bool isReverseGear() const { return reverse_gear_; }
    bool isInCall() const { return in_call_; }
    bool isNightMode() const { return night_mode_; }
    bool isPictureShown() const { return picture_shown_; }
    float pictureOpacity() const { return picture_opacity_; }

    /// Evaluates one visibility/peek/ownership/state-file turn immediately on the Reactor thread.
    void stepVisibility();

    /// Injects a control command directly on the Reactor thread (or via submitControlCommand).
    void handleControlCommand(const ControlCommand& cmd);
    void submitControlCommand(const ControlCommand& cmd);

    // Component accessors (for pre-start test API injection and post-run assertions)
    Reactor& reactor() { return reactor_; }
    EvoVideo& video() { return video_; }
    EvoAudioSink& audioSink() { return audio_sink_; }
    EvoMic& mic() { return mic_; }
    EvoKnob& knob() { return knob_; }
    EvoTouch& touch() { return touch_; }
    EvoControl& control() { return control_; }
    EvoInputBridge* inputBridge() { return input_bridge_; }
    SessionServer* server() { return server_; }
    MediaEngine* mediaEngine() { return media_engine_; }
    FilePairingStore* pairingStore() { return pairing_store_; }
    CarPlayConnectivity& connectivity() { return connectivity_; }
    const CarPlayConnectivity& connectivity() const { return connectivity_; }
    I2cMfiAuthProvider* mfiAuth() { return mfi_auth_; }
    const I2cMfiAuthProvider* mfiAuth() const { return mfi_auth_; }

    /// Test hook: inject a non-owning fake I2cBackend before start() when mfi_i2c_config.enabled is true.
    void setMfiI2cBackendForTest(I2cBackend* backend) { mfi_backend_override_ = backend; }

    // ---- TimerHandler (Reactor thread) ----
    virtual void onTimer(uint32_t timer_id);

    // ---- session::SessionListener (Reactor thread) ----
    virtual void onSessionActive(session::Session& session);
    virtual void onSessionEnded(session::Session& session);
    virtual void onDeviceInfo(session::Session& session, const session::DeviceInfo& info);
    virtual void onHostUiRequested(session::Session& session);
    virtual void onCommand(session::Session& session,
                           const std::string& type,
                           const bplist::Value& params);

    // ---- MediaSink (Reactor thread, delegated from EvoAudioMediaSink) ----
    virtual void onScreenStreamActive(int32_t type, bool active);
    virtual void onVideoConfig(int32_t type,
                               stream::VideoCodecType codec,
                               const uint8_t* annexb_data,
                               size_t annexb_len,
                               const uint8_t* raw_config,
                               size_t raw_len,
                               float width_px,
                               float height_px);
    virtual void onVideoFrame(int32_t type,
                              const uint8_t* annexb_data,
                              size_t len,
                              uint64_t sender_nanos,
                              int64_t arrival_mono_nanos);
    virtual void onIapMessage(const uint8_t* data, size_t len);

    // ---- EvoInputListener (Reactor thread) ----
    virtual void onUiKey(CcsKey key, bool pressed, const char* name);
    virtual void onVolumeStep(unsigned steps, uint8_t direction);
    virtual void onVolumeLevel(const VolumeLevel& level);

private:
    CarPlayDaemon(const CarPlayDaemon&) = delete;
    CarPlayDaemon& operator=(const CarPlayDaemon&) = delete;

    static void controlThunk(const ControlCommand& cmd, void* user);
    static void onPostedCommands(void* ctx);

    void drainControlQueue();
    void applyDayNight(int val);
    void activateSessionFocus();

    CarPlayDaemonConfig config_;
    Reactor reactor_;
    OsRandomSource rng_;
    pairing::Identity identity_;
    FilePairingStore* pairing_store_;

    uint32_t display_width_;
    uint32_t display_height_;
    info::AirPlayConfig airplay_config_;

    EvoVideo video_;
    EvoVideoSink video_sink_;
    EvoAudioSink audio_sink_;
    EvoMic mic_;
    EvoAudioMediaSink media_sink_;

    MediaEngine* media_engine_;
    I2cBackend* mfi_backend_override_;
    I2cMfiAuthProvider* mfi_auth_;
    SessionServer* server_;
    CarPlayConnectivity connectivity_;

    EvoKnob knob_;
    EvoTouch touch_;
    EvoInputBridge* input_bridge_;

    EvoControl control_;
    PeekTiming peek_;
    MediaDoublePress media_press_;

    Mutex cmd_mu_;
    std::vector<ControlCommand> cmd_queue_;
    bool cmd_post_pending_;

    uint32_t tick_timer_;
    bool started_;
    bool stopping_;
    bool video_running_;
    bool session_focus_initialized_;
    bool focus_;
    bool await_show_;
    bool asking_;
    bool reverse_gear_;
    bool in_call_;
    bool night_mode_;
    bool picture_shown_;
    float picture_opacity_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_CARPLAY_DAEMON_HPP
