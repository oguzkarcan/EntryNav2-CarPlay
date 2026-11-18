#ifndef CARPLAY_PLATFORM_HOSTAPD_CTRL_HPP
#define CARPLAY_PLATFORM_HOSTAPD_CTRL_HPP

// Non-blocking, Reactor-integrated client for hostapd's UNIX datagram control interface.
//
// Protocol (wpa_ctrl):
//   * Client binds an AF_UNIX SOCK_DGRAM socket to its own unique path inside `local_bind_dir`
//     (hostapd replies via sendto() to the client's bound sun_path) and connects() to hostapd's
//     socket (typically `<ctrl_interface>/<iface>`).
//   * Commands: plain ASCII strings ("PING", "ATTACH", "DETACH", "STATUS", "ALL_STA", "ENABLE",
//     "DISABLE", ...). Replies are text ("PONG\n", "OK\n", "FAIL\n", key=value lines, etc.).
//   * Unsolicited events after ATTACH are prefixed with `<N>` (priority digit), e.g.:
//       `<3>AP-STA-CONNECTED aa:bb:cc:dd:ee:ff`
//       `<3>AP-STA-DISCONNECTED aa:bb:cc:dd:ee:ff`
//       `<3>AP-ENABLED`
//       `<3>AP-DISABLED`
//       `<3>CTRL-EVENT-TERMINATING`

#include <stddef.h>
#include <stdint.h>

#include <deque>
#include <string>
#include <utility>
#include <vector>

#include "carplay/platform/reactor.hpp"

namespace carplay {
namespace platform {

enum HostapdCommandKind {
    kCmdPing = 0,
    kCmdAttach,
    kCmdDetach,
    kCmdStatus,
    kCmdAllSta,
    kCmdEnable,
    kCmdDisable,
    kCmdRaw
};

struct HostapdStatus {
    std::string state;
    std::string phy;
    int freq;
    int channel;
    std::string bss;
    std::string bssid;  // normalized lowercase aa:bb:cc:dd:ee:ff
    std::string ssid;
    int num_sta;  // -1 if absent
    std::vector<std::pair<std::string, std::string> > raw;

    HostapdStatus() : freq(0), channel(0), num_sta(-1) {}
};

struct HostapdStationInfo {
    std::string mac;  // normalized lowercase
    std::string flags;
    int aid;
    uint64_t connected_time;
    uint64_t rx_packets;
    uint64_t tx_packets;
    std::vector<std::pair<std::string, std::string> > raw;

    HostapdStationInfo() : aid(-1), connected_time(0ULL), rx_packets(0ULL), tx_packets(0ULL) {}
};

enum HostapdEventType {
    kHostapdEventUnknown = 0,
    kHostapdEventStaConnected,
    kHostapdEventStaDisconnected,
    kHostapdEventApEnabled,
    kHostapdEventApDisabled,
    kHostapdEventInterfaceDisabled,
    kHostapdEventTerminating
};

struct HostapdEvent {
    int level;  // >= 0 from `<N>` prefix; -1 if none
    HostapdEventType type;
    std::string name;
    std::string mac;       // normalized lowercase for STA connect/disconnect
    std::string raw_body;  // payload after `<N>`

    HostapdEvent() : level(-1), type(kHostapdEventUnknown) {}
};

/// Pure helper: validates and normalizes `aa:bb:cc:dd:ee:ff` (or `AA-BB-...`) to lowercase colon hex.
bool normalizeMacAddress(const std::string& input, std::string& out);

/// Pure helper: parses `aa:bb:cc:dd:ee:ff` into 6 raw bytes.
bool parseMacAddressBytes(const std::string& input, uint8_t out[6]);

/// Pure parser for hostapd `STATUS` key=value output.
bool parseHostapdStatus(const std::string& text, HostapdStatus& out);

/// Pure parser for hostapd `ALL_STA` output (empty/whitespace -> 0 stations, returns true).
bool parseHostapdAllSta(const std::string& text, std::vector<HostapdStationInfo>& out);

/// True iff `msg` begins with `<digits>`.
bool isUnsolicitedHostapdMessage(const std::string& msg);

/// Pure parser for unsolicited `<N>...` hostapd events.
bool parseHostapdEvent(const std::string& msg, HostapdEvent& out);

/// Evaluates whether a command reply indicates success for the given command kind.
bool isHostapdReplyOk(HostapdCommandKind kind, const std::string& reply);

class HostapdCtrlListener {
public:
    virtual ~HostapdCtrlListener() {}
    virtual void onHostapdCommandReply(HostapdCommandKind cmd,
                                       bool ok,
                                       const std::string& reply) = 0;
    virtual void onHostapdEvent(const HostapdEvent& event) = 0;
    virtual void onHostapdCtrlError(const std::string& error) = 0;
};

class IHostapdCtrl {
public:
    virtual ~IHostapdCtrl() {}

    virtual void setListener(HostapdCtrlListener* listener) = 0;
    virtual bool open(const std::string& remote_ctrl_path,
                      const std::string& local_bind_dir,
                      std::string* error_out = NULL) = 0;
    virtual void close() = 0;
    virtual bool isOpen() const = 0;

    virtual bool sendPing(int timeout_ms = 1000) = 0;
    virtual bool sendAttach(int timeout_ms = 1000) = 0;
    virtual bool sendDetach(int timeout_ms = 1000) = 0;
    virtual bool sendStatus(int timeout_ms = 1000) = 0;
    virtual bool sendAllSta(int timeout_ms = 1000) = 0;
    virtual bool sendEnable(int timeout_ms = 1000) = 0;
    virtual bool sendDisable(int timeout_ms = 1000) = 0;
    virtual bool sendCommand(HostapdCommandKind kind,
                             const std::string& cmd,
                             int timeout_ms = 1000) = 0;
};

class HostapdCtrl : public IHostapdCtrl, private IoHandler, private TimerHandler {
public:
    static const size_t kMaxPendingCommands = 64U;
    static const size_t kMaxDatagramBytes = 8192U;

    explicit HostapdCtrl(Reactor& reactor);
    virtual ~HostapdCtrl();

    virtual void setListener(HostapdCtrlListener* listener);
    virtual bool open(const std::string& remote_ctrl_path,
                      const std::string& local_bind_dir,
                      std::string* error_out = NULL);
    virtual void close();
    virtual bool isOpen() const;

    virtual bool sendPing(int timeout_ms = 1000);
    virtual bool sendAttach(int timeout_ms = 1000);
    virtual bool sendDetach(int timeout_ms = 1000);
    virtual bool sendStatus(int timeout_ms = 1000);
    virtual bool sendAllSta(int timeout_ms = 1000);
    virtual bool sendEnable(int timeout_ms = 1000);
    virtual bool sendDisable(int timeout_ms = 1000);
    virtual bool sendCommand(HostapdCommandKind kind,
                             const std::string& cmd,
                             int timeout_ms = 1000);

    const std::string& localSocketPath() const { return local_path_; }
    const std::string& remoteSocketPath() const { return remote_path_; }

private:
    HostapdCtrl(const HostapdCtrl&) = delete;
    HostapdCtrl& operator=(const HostapdCtrl&) = delete;

    struct QueuedCommand {
        HostapdCommandKind kind;
        std::string text;
        int timeout_ms;
        bool sent;
    };

    virtual void onReadable();
    virtual void onWritable();
    virtual void onError();
    virtual void onTimer(uint32_t timer_id);

    void pumpNextCommand();
    void armTimeout(int timeout_ms);
    void cancelTimeout();
    void handleDatagram(const std::string& msg);

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
    HostapdCtrlListener* listener_;
    SocketHandle fd_;
    std::string local_path_;
    std::string remote_path_;
    std::deque<QueuedCommand> queue_;
    uint32_t timeout_timer_id_;
    uint32_t generation_;
    AliveState* alive_state_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_HOSTAPD_CTRL_HPP
