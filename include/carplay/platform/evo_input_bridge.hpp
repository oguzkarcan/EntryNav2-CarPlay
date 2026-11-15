#ifndef CARPLAY_PLATFORM_EVO_INPUT_BRIDGE_HPP
#define CARPLAY_PLATFORM_EVO_INPUT_BRIDGE_HPP

// Bridges BMW EvoKnob (vMOST ZBE3/MFL/volume) and EvoTouch (UDP 30567 touchscreen) into
// SessionServer's encrypted CarPlay EventChannel (hidSendReport / requestSiri) on the
// Reactor thread.
//
// Threading:
//   * submit*() methods are thread-safe and may be called from EvoKnob / EvoTouch worker
//     threads; they enqueue under a Mutex and wake the Reactor via Reactor::post().
//   * handle*(), setOwned(), setPictureStarted(), setPhoneToIdrive(), setDisplaySize(),
//     onSessionEnded(), attach(), detach(), and the destructor run on the Reactor thread.

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "carplay/airplay_hid.hpp"
#include "carplay/platform/evo_ccs.hpp"
#include "carplay/platform/evo_knob.hpp"
#include "carplay/platform/evo_touch.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/session_server.hpp"
#include "carplay/platform/thread.hpp"

namespace carplay {
namespace platform {

struct EvoInputBridgeConfig {
    int32_t display_width;
    int32_t display_height;
    bool menu_to_carplay;
    bool phone_to_idrive;
    size_t max_queued_events;

    EvoInputBridgeConfig()
        : display_width(800),
          display_height(480),
          menu_to_carplay(true),
          phone_to_idrive(false),
          max_queued_events(256U) {}
};

class EvoInputListener {
public:
    virtual ~EvoInputListener() {}

    virtual void onUiKey(CcsKey /*key*/, bool /*pressed*/, const char* /*name*/) {}
    virtual void onVolumeStep(unsigned /*steps*/, uint8_t /*direction*/) {}
    virtual void onVolumeLevel(const VolumeLevel& /*level*/) {}
};

class EvoInputBridge {
public:
    EvoInputBridge(Reactor& reactor,
                   SessionServer& server,
                   const EvoInputBridgeConfig& config = EvoInputBridgeConfig(),
                   EvoInputListener* listener = NULL);
    ~EvoInputBridge();

    void attach(EvoKnob* knob, EvoTouch* touch);
    void detach();

    void setDisplaySize(int32_t width_pixels, int32_t height_pixels);
    void setOwned(bool owned);
    void setPictureStarted(bool started);
    void setPhoneToIdrive(bool phone_to_idrive);
    void onSessionEnded();

    // Thread-safe submission (worker threads -> Reactor::post()).
    bool submitTouch(const TouchEventOut& ev);
    bool submitZbe3(const hid::Zbe3Event& hw);
    bool submitMflTelephone(bool pressed);
    bool submitMflPtt(bool pressed);
    bool submitHardKey(CcsKey key, bool pressed, const char* name);
    bool submitVolumeStep(unsigned steps, uint8_t direction);
    bool submitVolumeLevel(const VolumeLevel& level);

    // Reactor-thread direct handlers.
    void handleTouch(const TouchEventOut& ev);
    void handleZbe3(const hid::Zbe3Event& hw);
    void handleMflTelephone(bool pressed);
    void handleMflPtt(bool pressed);
    void handleHardKey(CcsKey key, bool pressed, const char* name);

    bool owned() const { return owned_; }
    bool touchDown() const { return touch_down_; }
    const hid::KnobState& lastKnobState() const { return last_knob_state_; }

    uint64_t touchReportsSent() const { return touch_reports_sent_; }
    uint64_t knobReportsSent() const { return knob_reports_sent_; }
    uint64_t mediaReportsSent() const { return media_reports_sent_; }
    uint64_t telephonyReportsSent() const { return telephony_reports_sent_; }
    uint64_t siriRequestsSent() const { return siri_requests_sent_; }

private:
    EvoInputBridge(const EvoInputBridge&) = delete;
    EvoInputBridge& operator=(const EvoInputBridge&) = delete;

    struct QueuedItem {
        enum Type {
            kTouch = 0,
            kZbe3 = 1,
            kMflTel = 2,
            kMflPtt = 3,
            kHardKey = 4,
            kVolumeStep = 5,
            kVolumeLevel = 6
        };
        Type type;
        TouchEventOut touch;
        hid::Zbe3Event zbe3;
        bool pressed;
        CcsKey key;
        const char* name;
        unsigned vol_steps;
        uint8_t vol_dir;
        VolumeLevel vol_level;

        QueuedItem()
            : type(kTouch),
              pressed(false),
              key(kCcsKeyNone),
              name(NULL),
              vol_steps(0U),
              vol_dir(0U) {}
    };

    static void onPostedDrain(void* ctx);
    static void touchThunk(const TouchEventOut& ev, void* user);
    static void zbe3Thunk(const hid::Zbe3Event& hw, void* user);
    static void mflTelThunk(bool pressed, void* user);
    static void mflPttThunk(bool pressed, void* user);
    static void hardKeyThunk(CcsKey key, bool pressed, const char* name, void* user);
    static void volStepThunk(unsigned steps, uint8_t dir, void* user);
    static void volLevelThunk(const VolumeLevel& level, void* user);

    bool enqueue(const QueuedItem& item);
    void drainQueue();
    void releaseHeldInputs(bool send_hid);

    Reactor& reactor_;
    SessionServer& server_;
    EvoInputBridgeConfig config_;
    EvoInputListener* listener_;

    EvoKnob* knob_;
    EvoTouch* touch_;

    bool owned_;
    bool picture_started_;

    hid::TouchSlots touch_slots_;
    bool touch_down_;
    hid::KnobState last_knob_state_;
    bool media_down_;
    bool tel_down_;
    bool mfl_tel_down_;
    bool mfl_ptt_down_;

    uint64_t touch_reports_sent_;
    uint64_t knob_reports_sent_;
    uint64_t media_reports_sent_;
    uint64_t telephony_reports_sent_;
    uint64_t siri_requests_sent_;

    Mutex queue_mutex_;
    std::vector<QueuedItem> queue_;
    bool post_pending_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_EVO_INPUT_BRIDGE_HPP
