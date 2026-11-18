// Derived from EntryNav2-Android-Auto 0.12.0 platform/evo_wlan.hpp, PolyForm Noncommercial License 1.0.0
//
// Switches the BMW HU_ENTRYNAV2 car-native Wi-Fi AP on/off via vMOST FBlock 0xA0 instance 0x01
// (matching how BMW's own CarPlay service toggles `wland`):
//   * WLANState3.Get (0xC10, op 0x1) -> Status (op 0xC) returns 1 byte (0 = off, 1 = on).
//   * SelectWLANState3.StartResultAck (0xC11, op 0x6) -> 3-byte big-endian payload
//     [sender_handle_hi, sender_handle_lo, state (1 = on, 0 = off)].
//   * CarPlay restoration rule (extends AA): switch off on stop (SelectWLANState3 = 0) ONLY if
//     we were the ones who switched it on (`state_before != 1`). If it was already ON, leave it ON.

#ifndef CARPLAY_PLATFORM_EVO_WLAN_HPP
#define CARPLAY_PLATFORM_EVO_WLAN_HPP

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "carplay/platform/reactor.hpp"
#include "carplay/platform/vmost_client.hpp"

namespace carplay {
namespace platform {

// Verified: EntryNav2-Android-Auto-0.12.0/platform/evo_wlan.hpp & evo_wlan.cpp
static const uint8_t kWlanFblock = 0xA0U;
static const uint8_t kWlanApInstance = 0x01U;
static const uint16_t kWlanState3 = 0xC10U;
static const uint16_t kSelectWlanState3 = 0xC11U;
static const uint16_t kDefaultWlanSenderHandle = 0x5741U;  // 'WA'

/// Encodes SelectWLANState3.StartResultAck payload in MOST big-endian byte order:
/// [sender_handle >> 8, sender_handle & 0xff, on ? 1 : 0]. Always returns 3.
size_t buildSelectWlanState3(uint8_t out[3], uint16_t sender_handle, bool on);

struct WlanRequestResult {
    bool connected;          // vmostd session opened and WLAN.01 shadow registered
    int state_before;        // WLANState3 read before switch-on (-1 = no answer)
    bool sent;               // SelectWLANState3 sent
    int state_after;         // last WLANState3 seen after request (-1 = none)
    int reply_op;            // last SelectWLANState3 reply op (-1 = none; 0xD ResultAck, 0x9/0xF Error)
    unsigned messages;       // WLAN.01 messages received
    bool switched_on_by_us;  // true iff state_before != 1 and SelectWLANState3(1) was sent

    WlanRequestResult();
};

/// Synchronous vMOST helper (ported from AA):
/// Opens a short vMOST session, reads WLANState3, sends SelectWLANState3(1) ONLY if state_before != 1,
/// waits up to `wait_ms` for replies, deregisters and disconnects. Never sends "off".
bool requestWlanAccessPoint(unsigned wait_ms,
                            WlanRequestResult* result = NULL,
                            const VmostApi* api_override = NULL);

/// Synchronous vMOST helper: sends SelectWLANState3(0) to switch the car AP off.
bool releaseWlanAccessPoint(unsigned wait_ms,
                            WlanRequestResult* result = NULL,
                            const VmostApi* api_override = NULL);

/// Restores the car AP on stop: sends SelectWLANState3(0) iff `switched_on_by_us` is true.
/// When `switched_on_by_us` is false (e.g. AP was already on), performs no vMOST I/O and returns true.
bool restoreWlanAccessPoint(bool switched_on_by_us,
                            unsigned wait_ms,
                            WlanRequestResult* result = NULL,
                            const VmostApi* api_override = NULL);

class WlanControllerListener {
public:
    virtual ~WlanControllerListener() {}
    virtual void onWlanEnableResult(bool ok,
                                    const WlanRequestResult& result,
                                    const std::string& error) = 0;
    virtual void onWlanDisableResult(bool ok,
                                     const WlanRequestResult& result,
                                     const std::string& error) = 0;
};

/// Abstract interface for toggling the car-native WLAN AP so WifiAp is unit-testable with fakes.
class IWlanController {
public:
    virtual ~IWlanController() {}

    virtual void setListener(WlanControllerListener* listener) = 0;
    virtual bool isAvailable() const = 0;
    virtual bool isBusy() const = 0;

    /// Begins an asynchronous enable flow (reads WLANState3, sends SelectWLANState3(1) if needed).
    /// Returns false synchronously if vMOST cannot be initialized; otherwise reports completion via
    /// WlanControllerListener::onWlanEnableResult().
    virtual bool beginEnable(unsigned timeout_ms, std::string* error_out = NULL) = 0;

    /// Begins an asynchronous disable flow (sends SelectWLANState3(0)).
    virtual bool beginDisable(unsigned timeout_ms, std::string* error_out = NULL) = 0;

    /// Cancels any active asynchronous vMOST session without firing listener callbacks.
    virtual void cancel() = 0;

    /// Synchronous disable for stopSync() / destructor teardown.
    virtual bool restoreSync(unsigned timeout_ms, std::string* error_out = NULL) = 0;
};

/// Reactor-integrated non-blocking implementation of IWlanController over VmostClient.
/// Ownership: `reactor` and any non-NULL `WlanControllerListener*` must outlive `EvoWlanController`
/// (or be cleared with `setListener(NULL)` before destruction).
class EvoWlanController : public IWlanController, private IoHandler, private TimerHandler {
public:
    explicit EvoWlanController(Reactor& reactor);
    virtual ~EvoWlanController();

    /// Optional test API override (NULL clears). Must be called while idle.
    void setApiOverride(const VmostApi* api);

    virtual void setListener(WlanControllerListener* listener) { listener_ = listener; }
    virtual bool isAvailable() const;
    virtual bool isBusy() const { return mode_ != kModeIdle; }

    virtual bool beginEnable(unsigned timeout_ms, std::string* error_out = NULL);
    virtual bool beginDisable(unsigned timeout_ms, std::string* error_out = NULL);
    virtual void cancel();
    virtual bool restoreSync(unsigned timeout_ms, std::string* error_out = NULL);

private:
    EvoWlanController(const EvoWlanController&) = delete;
    EvoWlanController& operator=(const EvoWlanController&) = delete;

    enum Mode {
        kModeIdle = 0,
        kModeEnableGetState,
        kModeEnableWaitAck,
        kModeEnableWaitStateAfter,
        kModeDisableWaitAck
    };

    virtual void onReadable();
    virtual void onError();
    virtual void onTimer(uint32_t timer_id);

    static void onMessageStatic(void* msg, void* user);
    void onMessage(const VmostMsgView& v);

    bool openSession(std::string* error_out);
    void closeSession();
    bool sendGetState(std::string* error_out);
    bool sendSelectState(bool on, std::string* error_out);
    void stepAfterIo();
    void completeOperation(bool is_enable, bool ok, const std::string& error);
    void armTimer(int delay_ms);
    void cancelTimer();
    int64_t nowMs() const;

    struct AliveState {
        int refs;
        bool alive;
        AliveState() : refs(1), alive(true) {}
    };

    struct AliveGuard {
        AliveState* state;
        explicit AliveGuard(AliveState* s) : state(s) {
            if (state != NULL) {
                ++state->refs;
            }
        }
        ~AliveGuard() {
            if (state != NULL && --state->refs == 0) {
                delete state;
            }
        }
        bool alive() const { return state != NULL && state->alive; }
    };

    Reactor& reactor_;
    WlanControllerListener* listener_;
    VmostClient vmost_;
    const VmostApi* api_override_;
    SocketHandle fd_;
    Mode mode_;
    uint32_t timer_id_;
    int64_t total_deadline_ms_;
    unsigned total_timeout_ms_;
    WlanRequestResult result_;
    bool got_state_before_;
    bool got_final_reply_;
    bool got_state_after_;
    AliveState* alive_state_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_EVO_WLAN_HPP
