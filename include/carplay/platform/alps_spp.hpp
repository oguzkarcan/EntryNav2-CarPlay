#ifndef CARPLAY_PLATFORM_ALPS_SPP_HPP
#define CARPLAY_PLATFORM_ALPS_SPP_HPP

// Derived from EntryNav2-Android-Auto 0.12.0 platform/alps_spp.hpp,
// platform/alps_spp.cpp, platform/spp_advertisement.hpp, and
// tools/aa_supervisor.cpp, PolyForm Noncommercial License 1.0.0
//
// BMW HU_ENTRYNAV2 ALPS "Evolution" Bluetooth SPP stack client over D-Bus
// (`org.alps.evolution`, `/org/alps/evolution/hli`, `org.alps.evo.SPP` / `DM`).
//
// Design constraints:
//   * Zero link-time dependency on libdbus-1 or <dbus/dbus.h> headers.
//     `libdbus-1.so.3` (fallback `libdbus-1.so`) is loaded at runtime via
//     dlopen/dlsym, matching vmost_client.cpp / evo_audio.cpp.
//   * Single-threaded Reactor delivery: D-Bus dispatch & TX pump run on worker
//     threads and marshal connect/data/disconnect/fatal events onto `Reactor` via
//     `Reactor::post()` (cancelled after joining worker threads on stop()).
//   * CarPlay slot policy & restoration invariants (`AlpsSppManager`):
//       - Uses native CarPlay slot 1 untouched when idle with iAP2 UUID.
//       - Otherwise borrows spare slot 5 (`0x6203 = 1` + iAP2 UUID), re-reads
//         snapshot to verify both UUID copies, refreshes advertisement on idle,
//         and ALWAYS restores slot 5 (`generic` UUID + `0x6203 = 0`) on stop,
//         refusing restoration if the ALPS process restarted or a third-party
//         UUID took ownership.
//       - Refuses slot 0 fallback by default to protect BMW Apps / My BMW.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/platform/bt_rfcomm.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/spp_snapshot.hpp"

namespace carplay {
namespace platform {

struct AppsSlot;

// Verified ALPS D-Bus coordinates (EntryNav2-Android-Auto-0.12.0/platform/alps_spp.cpp).
static const char kAlpsDbusService[] = "org.alps.evolution";
static const char kAlpsDbusPath[] = "/org/alps/evolution/hli";
static const char kAlpsDbusSppInterface[] = "org.alps.evo.SPP";
static const char kAlpsDbusDmInterface[] = "org.alps.evo.DM";
static const uint16_t kAlpsConfigDataInterface = 0x6203U;
static const uint64_t kAlpsDmFunctionSpp = 1ULL;
static const size_t kAlpsMaxDataReqBytes = 1024U;

/// Verified (EntryNav2-Android-Auto-0.12.0/platform/alps_spp.hpp):
/// `libevo_btappl.so` `gen_GetConfig` only indexes slot 0 and slot 1; slots 2..5
/// return slot 0's value on read, so slot 5 writes are confirmed by status only.
inline bool alpsSlotConfigurationReadable(unsigned slot) {
    return slot <= 1U;
}

// ------------------------------------------------------------------------------------------------
// Runtime-Resolved libdbus-1 C ABI Table (no <dbus/dbus.h> dependency)
// ------------------------------------------------------------------------------------------------

struct DbusConnection;
struct DbusMessage;

struct DbusErrorRaw {
    const char* name;
    const char* message;
    void* pad[10];
};

struct DbusMessageIterRaw {
    void* pad[24];
};

typedef uint32_t dbus_bool_raw;
typedef int (*DbusHandleMessageFn)(DbusConnection* conn, DbusMessage* msg, void* user_data);
typedef void (*DbusFreeFn)(void* memory);

struct DbusApi {
    dbus_bool_raw (*threads_init_default)();

    void (*error_init)(DbusErrorRaw* error);
    dbus_bool_raw (*error_is_set)(const DbusErrorRaw* error);
    void (*error_free)(DbusErrorRaw* error);

    DbusConnection* (*bus_get_private)(int type, DbusErrorRaw* error);
    void (*bus_add_match)(DbusConnection* conn, const char* rule, DbusErrorRaw* error);

    void (*connection_set_exit_on_disconnect)(DbusConnection* conn, dbus_bool_raw exit_on_disconnect);
    void (*connection_close)(DbusConnection* conn);
    void (*connection_unref)(DbusConnection* conn);
    dbus_bool_raw (*connection_add_filter)(DbusConnection* conn,
                                           DbusHandleMessageFn function,
                                           void* user_data,
                                           DbusFreeFn free_data_function);
    void (*connection_remove_filter)(DbusConnection* conn,
                                     DbusHandleMessageFn function,
                                     void* user_data);
    dbus_bool_raw (*connection_send)(DbusConnection* conn,
                                     DbusMessage* msg,
                                     uint32_t* serial_out);
    DbusMessage* (*connection_send_with_reply_and_block)(DbusConnection* conn,
                                                         DbusMessage* msg,
                                                         int timeout_ms,
                                                         DbusErrorRaw* error);
    dbus_bool_raw (*connection_read_write_dispatch)(DbusConnection* conn, int timeout_ms);

    DbusMessage* (*message_new_method_call)(const char* destination,
                                            const char* path,
                                            const char* iface,
                                            const char* method);
    void (*message_unref)(DbusMessage* msg);
    void (*message_set_no_reply)(DbusMessage* msg, dbus_bool_raw no_reply);
    int (*message_get_type)(DbusMessage* msg);
    const char* (*message_get_member)(DbusMessage* msg);
    const char* (*message_get_interface)(DbusMessage* msg);
    const char* (*message_get_signature)(DbusMessage* msg);
    dbus_bool_raw (*message_has_interface)(DbusMessage* msg, const char* iface);
    dbus_bool_raw (*message_has_path)(DbusMessage* msg, const char* path);
    dbus_bool_raw (*message_has_sender)(DbusMessage* msg, const char* name);
    dbus_bool_raw (*message_has_signature)(DbusMessage* msg, const char* sig);
    dbus_bool_raw (*message_is_signal)(DbusMessage* msg, const char* iface, const char* signal_name);

    dbus_bool_raw (*message_iter_init)(DbusMessage* msg, DbusMessageIterRaw* iter);
    dbus_bool_raw (*message_iter_next)(DbusMessageIterRaw* iter);
    int (*message_iter_get_arg_type)(DbusMessageIterRaw* iter);
    int (*message_iter_get_element_type)(DbusMessageIterRaw* iter);
    void (*message_iter_get_basic)(DbusMessageIterRaw* iter, void* value);
    void (*message_iter_recurse)(DbusMessageIterRaw* iter, DbusMessageIterRaw* sub);
    void (*message_iter_get_fixed_array)(DbusMessageIterRaw* iter, void* value, int* n_elements);

    void (*message_iter_init_append)(DbusMessage* msg, DbusMessageIterRaw* iter);
    dbus_bool_raw (*message_iter_append_basic)(DbusMessageIterRaw* iter,
                                               int type,
                                               const void* value);
    dbus_bool_raw (*message_iter_open_container)(DbusMessageIterRaw* iter,
                                                 int type,
                                                 const char* contained_signature,
                                                 DbusMessageIterRaw* sub);
    dbus_bool_raw (*message_iter_close_container)(DbusMessageIterRaw* iter,
                                                  DbusMessageIterRaw* sub);
    void (*message_iter_abandon_container)(DbusMessageIterRaw* iter,
                                           DbusMessageIterRaw* sub);
    dbus_bool_raw (*message_iter_append_fixed_array)(DbusMessageIterRaw* iter,
                                                     int element_type,
                                                     const void* value,
                                                     int n_elements);

    dbus_bool_raw (*validate_path)(const char* path, DbusErrorRaw* error);

    DbusApi();
    bool isComplete() const;
};

/// Loads `libdbus-1.so.3` (fallback `libdbus-1.so`) and resolves all required D-Bus symbols.
bool loadDbusApi(DbusApi& out,
                 void** lib_handle_out = NULL,
                 std::string* loaded_name_out = NULL,
                 std::string* error_out = NULL);
void unloadDbusLibrary(void* lib_handle);

/// Side-effect-free probe checking whether `org.alps.evolution` currently has a bus owner.
bool probeAlpsDbusService(int timeout_ms = 500,
                          std::string* owner_out = NULL,
                          const DbusApi* api_override = NULL);

// ------------------------------------------------------------------------------------------------
// Idle Advertisement Refresh Schedule
// ------------------------------------------------------------------------------------------------

/// Bounded advertisement schedule: 15s, 45s, 90s, then every `repeat_ms` while idle.
class AdvertisementSchedule {
public:
    explicit AdvertisementSchedule(uint32_t repeat_ms = 60000U)
        : next_(0), repeat_ms_(repeat_ms), last_ms_(0) {}

    void reset() {
        next_ = 0;
        last_ms_ = 0;
    }

    bool due(uint32_t elapsed_ms);

private:
    unsigned next_;
    uint32_t repeat_ms_;
    uint32_t last_ms_;
};

// ------------------------------------------------------------------------------------------------
// AlpsSppLink Abstraction & Runtime D-Bus Implementation
// ------------------------------------------------------------------------------------------------

class AlpsSppLinkListener {
public:
    virtual ~AlpsSppLinkListener() {}
    virtual void onAlpsConnected(const BtAddr& peer) = 0;
    virtual void onAlpsData(const uint8_t* data, size_t len) = 0;
    virtual void onAlpsDisconnected(const std::string& reason) = 0;
    virtual void onAlpsFatalError(const std::string& reason) = 0;
};

class AlpsSppLink {
public:
    virtual ~AlpsSppLink() {}

    virtual bool start(uint8_t instance, bool monitor_only = false) = 0;
    virtual void stop() = 0;
    virtual bool isRunning() const = 0;
    virtual bool isLinkUp() const = 0;
    virtual void setListener(AlpsSppLinkListener* listener) = 0;

    virtual int registerUuidPayload(const std::vector<uint8_t>& payload, int timeout_ms) = 0;
    virtual bool readConfiguration(uint8_t instance,
                                   uint16_t id,
                                   std::vector<uint8_t>& out,
                                   int timeout_ms) = 0;
    virtual bool setDataInterface(uint8_t instance, uint8_t value, int timeout_ms) = 0;
    virtual bool requestSppDisconnect() = 0;
    virtual void disconnectLink(const std::string& reason = "local disconnect") = 0;
    virtual bool sendData(const uint8_t* data, size_t len) = 0;
    virtual const std::string& lastError() const = 0;
};

class DbusAlpsSppLink : public AlpsSppLink {
public:
    DbusAlpsSppLink(Reactor& reactor,
                    AlpsSppLinkListener* listener = NULL,
                    const DbusApi* dbus_api_override = NULL,
                    size_t write_queue_limit = 256U * 1024U,
                    size_t max_rx_bytes = 256U * 1024U);
    virtual ~DbusAlpsSppLink();

    virtual bool start(uint8_t instance, bool monitor_only = false);
    virtual void stop();
    virtual bool isRunning() const;
    virtual bool isLinkUp() const;
    virtual void setListener(AlpsSppLinkListener* listener);

    virtual int registerUuidPayload(const std::vector<uint8_t>& payload, int timeout_ms);
    virtual bool readConfiguration(uint8_t instance,
                                   uint16_t id,
                                   std::vector<uint8_t>& out,
                                   int timeout_ms);
    virtual bool setDataInterface(uint8_t instance, uint8_t value, int timeout_ms);
    virtual bool requestSppDisconnect();
    virtual void disconnectLink(const std::string& reason = "local disconnect");
    virtual bool sendData(const uint8_t* data, size_t len);
    virtual const std::string& lastError() const { return last_error_; }

private:
    DbusAlpsSppLink(const DbusAlpsSppLink&) = delete;
    DbusAlpsSppLink& operator=(const DbusAlpsSppLink&) = delete;

    struct Impl;
    Impl* impl_;
    std::string last_error_;
};

// ------------------------------------------------------------------------------------------------
// AlpsSppManager (Slot Selection + Borrow + Verification + Mandatory Restore)
// ------------------------------------------------------------------------------------------------

struct AlpsSppManagerConfig {
    CarPlaySlotPolicy slot_policy;
    uint32_t double_read_delay_ms;
    int dbus_timeout_ms;
    int uuid_timeout_ms;
    bool verify_native_slot_interface;
    bool enable_advertisement_refresh;
    uint32_t advertisement_repeat_ms;
    int restore_settle_timeout_ms;
    int restore_disconnect_timeout_ms;
    uint32_t restore_poll_interval_ms;

    AlpsSppManagerConfig()
        : double_read_delay_ms(20U),
          dbus_timeout_ms(2000),
          uuid_timeout_ms(3000),
          verify_native_slot_interface(true),
          enable_advertisement_refresh(true),
          advertisement_repeat_ms(60000U),
          restore_settle_timeout_ms(3000),
          restore_disconnect_timeout_ms(5000),
          restore_poll_interval_ms(100U) {}
};

class AlpsSppManagerListener {
public:
    virtual ~AlpsSppManagerListener() {}
    virtual void onAlpsManagerConnected(const BtAddr& peer) = 0;
    virtual void onAlpsManagerData(const uint8_t* data, size_t len) = 0;
    virtual void onAlpsManagerDisconnected(const std::string& reason) = 0;
};

class AlpsSppManager {
public:
    /// `mem_backend` and `link_override` are optional (NULL uses real `/proc` and
    /// `DbusAlpsSppLink`). Caller retains ownership of injected fakes.
    AlpsSppManager(Reactor& reactor,
                   AlpsSppManagerListener& listener,
                   const AlpsSppManagerConfig& config = AlpsSppManagerConfig(),
                   SppMemoryBackend* mem_backend = NULL,
                   AlpsSppLink* link_override = NULL);
    ~AlpsSppManager();

    bool start(std::string* error_out = NULL);
    /// Stops the transport; if a slot was borrowed (e.g. slot 5), verifies ALPS
    /// process identity & UUID state and restores baseline UUID and 0x6203.
    bool stop(std::string* error_out = NULL);

    void disconnect(const std::string& reason = "local disconnect");
    bool sendData(const uint8_t* data, size_t len);
    void setListener(AlpsSppManagerListener* listener) { listener_ = listener; }

    /// Read-only probe of ALPS BMW Apps slot 0 (`kAlpsBmwAppsSlot`) using the open snapshot reader.
    bool readBmwAppsSlot(AppsSlot& out);

    bool isStarted() const { return started_; }
    bool isConnected() const { return connected_; }
    uint8_t activeSlot() const { return active_slot_; }
    CarPlaySlotDecision slotDecision() const { return slot_decision_; }
    bool borrowedSlot() const { return borrowed_; }
    bool restoreAttempted() const { return restore_attempted_; }
    bool restoreSucceeded() const { return restore_succeeded_; }
    const BtAddr& peerAddress() const { return peer_addr_; }
    const std::string& lastError() const { return last_error_; }

private:
    AlpsSppManager(const AlpsSppManager&) = delete;
    AlpsSppManager& operator=(const AlpsSppManager&) = delete;

    class LinkAdapter : public AlpsSppLinkListener {
    public:
        explicit LinkAdapter(AlpsSppManager* owner) : owner_(owner) {}
        virtual void onAlpsConnected(const BtAddr& peer) { owner_->handleLinkConnected(peer); }
        virtual void onAlpsData(const uint8_t* data, size_t len) { owner_->handleLinkData(data, len); }
        virtual void onAlpsDisconnected(const std::string& reason) { owner_->handleLinkDisconnected(reason); }
        virtual void onAlpsFatalError(const std::string& reason) { owner_->handleLinkFatalError(reason); }
    private:
        AlpsSppManager* owner_;
    };

    class AdvertTimerHandler : public TimerHandler {
    public:
        explicit AdvertTimerHandler(AlpsSppManager* owner) : owner_(owner) {}
        virtual void onTimer(uint32_t timer_id) { owner_->handleAdvertTimer(timer_id); }
    private:
        AlpsSppManager* owner_;
    };

    void handleLinkConnected(const BtAddr& peer);
    void handleLinkData(const uint8_t* data, size_t len);
    void handleLinkDisconnected(const std::string& reason);
    void handleLinkFatalError(const std::string& reason);
    void handleAdvertTimer(uint32_t timer_id);

    bool configureBorrowedSlot(std::string* error_out);
    bool restoreBorrowedSlot(std::string* error_out);
    bool waitSettledSnapshot(unsigned instance,
                             SppSlotSnapshot& out,
                             bool allow_split,
                             int timeout_ms);
    void abortStartCleanup();

    Reactor& reactor_;
    AlpsSppManagerListener* listener_;
    AlpsSppManagerConfig config_;

    SppSnapshotReader reader_;
    LinkAdapter link_adapter_;
    DbusAlpsSppLink default_link_;
    AlpsSppLink* link_;
    AdvertTimerHandler advert_handler_;
    uint32_t advert_timer_id_;
    int64_t advert_start_ns_;
    AdvertisementSchedule advert_schedule_;

    bool started_;
    bool connected_;
    BtAddr peer_addr_;
    uint8_t active_slot_;
    CarPlaySlotDecision slot_decision_;
    bool borrowed_;
    int baseline_pid_;
    std::string baseline_identity_;
    uint8_t baseline_interface_;
    std::vector<uint8_t> baseline_uuid_;
    bool restore_attempted_;
    bool restore_succeeded_;
    std::string last_error_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_ALPS_SPP_HPP
