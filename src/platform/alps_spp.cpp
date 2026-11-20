// Derived from EntryNav2-Android-Auto 0.12.0 platform/alps_spp.cpp,
// platform/spp_advertisement.hpp, and tools/aa_supervisor.cpp,
// PolyForm Noncommercial License 1.0.0

#include "carplay/platform/alps_spp.hpp"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <algorithm>
#include <deque>

#ifndef _WIN32
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

#include "carplay/platform/log.hpp"
#include "carplay/platform/thread.hpp"
#include "carplay/platform/wifi_link.hpp"

namespace carplay {
namespace platform {

namespace {

static const int kDbusBusSystem = 1;
static const int kDbusTypeByte = 'y';
static const int kDbusTypeUint16 = 'q';
static const int kDbusTypeUint64 = 't';
static const int kDbusTypeString = 's';
static const int kDbusTypeArray = 'a';
static const int kDbusMessageTypeSignal = 4;
static const int kDbusHandlerResultNotYetHandled = 1;
static const dbus_bool_raw kDbusTrue = 1U;
static const dbus_bool_raw kDbusFalse = 0U;

static const char kDbusService[] = "org.freedesktop.DBus";
static const char kDbusPath[] = "/org/freedesktop/DBus";
static const char kDbusInterface[] = "org.freedesktop.DBus";
static const char kDbusLocalInterface[] = "org.freedesktop.DBus.Local";

void setErr(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

void sleepPlatformMs(uint32_t ms) {
    if (ms == 0U) {
        return;
    }
#ifdef _WIN32
    ::Sleep(ms);
#else
    ::usleep(static_cast<useconds_t>(ms) * 1000U);
#endif
}

#ifndef _WIN32
template <typename Fn>
bool resolveDbusSym(void* lib, const char* name, Fn& fn) {
    if (sizeof(Fn) != sizeof(void*)) {
        return false;
    }
    void* p = ::dlsym(lib, name);
    if (p == NULL) {
        fn = NULL;
        return false;
    }
    memcpy(&fn, &p, sizeof(p));
    return true;
}

struct timespec monotonicDeadline(int ms) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    if (ms > 0) {
        t.tv_sec += ms / 1000;
        t.tv_nsec += static_cast<long>(ms % 1000) * 1000000L;
        if (t.tv_nsec >= 1000000000L) {
            ++t.tv_sec;
            t.tv_nsec -= 1000000000L;
        }
    }
    return t;
}
#endif

bool readSingleStringReply(const DbusApi& api, DbusMessage* msg, std::string& out) {
    out.clear();
    if (msg == NULL) {
        return false;
    }
    DbusMessageIterRaw it;
    memset(&it, 0, sizeof(it));
    if (!api.message_iter_init(msg, &it) ||
        api.message_iter_get_arg_type(&it) != kDbusTypeString) {
        return false;
    }
    const char* s = NULL;
    api.message_iter_get_basic(&it, &s);
    if (s == NULL) {
        return false;
    }
    out = s;
    return true;
}

bool readThreeStringArgs(const DbusApi& api,
                         DbusMessage* msg,
                         std::string& s0,
                         std::string& s1,
                         std::string& s2) {
    DbusMessageIterRaw it;
    memset(&it, 0, sizeof(it));
    if (!api.message_iter_init(msg, &it)) {
        return false;
    }
    std::string* dst[3] = {&s0, &s1, &s2};
    for (int i = 0; i < 3; ++i) {
        if (i > 0 && !api.message_iter_next(&it)) {
            return false;
        }
        if (api.message_iter_get_arg_type(&it) != kDbusTypeString) {
            return false;
        }
        const char* val = NULL;
        api.message_iter_get_basic(&it, &val);
        if (val == NULL) {
            return false;
        }
        *dst[i] = val;
    }
    return true;
}

bool readByteArrayIter(const DbusApi& api,
                       DbusMessageIterRaw& it,
                       const uint8_t*& ptr_out,
                       int& len_out) {
    ptr_out = NULL;
    len_out = 0;
    if (api.message_iter_get_arg_type(&it) != kDbusTypeArray ||
        api.message_iter_get_element_type(&it) != kDbusTypeByte) {
        return false;
    }
    DbusMessageIterRaw arr;
    memset(&arr, 0, sizeof(arr));
    api.message_iter_recurse(&it, &arr);
    api.message_iter_get_fixed_array(&arr, &ptr_out, &len_out);
    return len_out >= 0;
}

bool appendAlpsByteArrayPayload(const DbusApi& api,
                               DbusMessage* msg,
                               uint8_t inst,
                               const uint8_t* data,
                               size_t n,
                               const uint16_t* config_id) {
    if (msg == NULL || n > 65535U || (n > 0 && data == NULL)) {
        return false;
    }
    DbusMessageIterRaw it;
    DbusMessageIterRaw arr;
    memset(&it, 0, sizeof(it));
    memset(&arr, 0, sizeof(arr));
    api.message_iter_init_append(msg, &it);
    const uint16_t len = static_cast<uint16_t>(n);
    if (!api.message_iter_append_basic(&it, kDbusTypeByte, &inst)) {
        return false;
    }
    if (config_id != NULL && !api.message_iter_append_basic(&it, kDbusTypeUint16, config_id)) {
        return false;
    }
    if (!api.message_iter_append_basic(&it, kDbusTypeUint16, &len) ||
        !api.message_iter_open_container(&it, kDbusTypeArray, "y", &arr)) {
        return false;
    }
    if (n > 0 &&
        !api.message_iter_append_fixed_array(&arr, kDbusTypeByte, &data, static_cast<int>(n))) {
        api.message_iter_abandon_container(&it, &arr);
        return false;
    }
    return api.message_iter_close_container(&it, &arr) != 0;
}

}  // namespace

// ------------------------------------------------------------------------------------------------
// DbusApi & Runtime Loader
// ------------------------------------------------------------------------------------------------

DbusApi::DbusApi() {
    memset(this, 0, sizeof(*this));
}

bool DbusApi::isComplete() const {
    return threads_init_default != NULL &&
           error_init != NULL &&
           error_is_set != NULL &&
           error_free != NULL &&
           bus_get_private != NULL &&
           bus_add_match != NULL &&
           connection_set_exit_on_disconnect != NULL &&
           connection_close != NULL &&
           connection_unref != NULL &&
           connection_add_filter != NULL &&
           connection_remove_filter != NULL &&
           connection_send != NULL &&
           connection_send_with_reply_and_block != NULL &&
           connection_read_write_dispatch != NULL &&
           message_new_method_call != NULL &&
           message_unref != NULL &&
           message_set_no_reply != NULL &&
           message_get_type != NULL &&
           message_get_member != NULL &&
           message_get_interface != NULL &&
           message_get_signature != NULL &&
           message_has_interface != NULL &&
           message_has_path != NULL &&
           message_has_sender != NULL &&
           message_has_signature != NULL &&
           message_is_signal != NULL &&
           message_iter_init != NULL &&
           message_iter_next != NULL &&
           message_iter_get_arg_type != NULL &&
           message_iter_get_element_type != NULL &&
           message_iter_get_basic != NULL &&
           message_iter_recurse != NULL &&
           message_iter_get_fixed_array != NULL &&
           message_iter_init_append != NULL &&
           message_iter_append_basic != NULL &&
           message_iter_open_container != NULL &&
           message_iter_close_container != NULL &&
           message_iter_abandon_container != NULL &&
           message_iter_append_fixed_array != NULL &&
           validate_path != NULL;
}

bool loadDbusApi(DbusApi& out,
                 void** lib_handle_out,
                 std::string* loaded_name_out,
                 std::string* error_out) {
    out = DbusApi();
    if (lib_handle_out != NULL) {
        *lib_handle_out = NULL;
    }
    if (loaded_name_out != NULL) {
        loaded_name_out->clear();
    }
#ifdef _WIN32
    setErr(error_out, "libdbus-1 dlopen unsupported on Windows");
    return false;
#else
    static const char* const kCandidates[2] = {"libdbus-1.so.3", "libdbus-1.so"};
    void* lib = NULL;
    std::string chosen;
    for (size_t i = 0; i < 2U; ++i) {
        lib = ::dlopen(kCandidates[i], RTLD_LAZY | RTLD_LOCAL);
        if (lib != NULL) {
            chosen = kCandidates[i];
            break;
        }
    }
    if (lib == NULL) {
        setErr(error_out, "dlopen(libdbus-1.so.3) failed");
        return false;
    }

    bool ok = true;
    ok = ok && resolveDbusSym(lib, "dbus_threads_init_default", out.threads_init_default);
    ok = ok && resolveDbusSym(lib, "dbus_error_init", out.error_init);
    ok = ok && resolveDbusSym(lib, "dbus_error_is_set", out.error_is_set);
    ok = ok && resolveDbusSym(lib, "dbus_error_free", out.error_free);
    ok = ok && resolveDbusSym(lib, "dbus_bus_get_private", out.bus_get_private);
    ok = ok && resolveDbusSym(lib, "dbus_bus_add_match", out.bus_add_match);
    ok = ok && resolveDbusSym(lib, "dbus_connection_set_exit_on_disconnect",
                              out.connection_set_exit_on_disconnect);
    ok = ok && resolveDbusSym(lib, "dbus_connection_close", out.connection_close);
    ok = ok && resolveDbusSym(lib, "dbus_connection_unref", out.connection_unref);
    ok = ok && resolveDbusSym(lib, "dbus_connection_add_filter", out.connection_add_filter);
    ok = ok && resolveDbusSym(lib, "dbus_connection_remove_filter", out.connection_remove_filter);
    ok = ok && resolveDbusSym(lib, "dbus_connection_send", out.connection_send);
    ok = ok && resolveDbusSym(lib, "dbus_connection_send_with_reply_and_block",
                              out.connection_send_with_reply_and_block);
    ok = ok && resolveDbusSym(lib, "dbus_connection_read_write_dispatch",
                              out.connection_read_write_dispatch);
    ok = ok && resolveDbusSym(lib, "dbus_message_new_method_call", out.message_new_method_call);
    ok = ok && resolveDbusSym(lib, "dbus_message_unref", out.message_unref);
    ok = ok && resolveDbusSym(lib, "dbus_message_set_no_reply", out.message_set_no_reply);
    ok = ok && resolveDbusSym(lib, "dbus_message_get_type", out.message_get_type);
    ok = ok && resolveDbusSym(lib, "dbus_message_get_member", out.message_get_member);
    ok = ok && resolveDbusSym(lib, "dbus_message_get_interface", out.message_get_interface);
    ok = ok && resolveDbusSym(lib, "dbus_message_get_signature", out.message_get_signature);
    ok = ok && resolveDbusSym(lib, "dbus_message_has_interface", out.message_has_interface);
    ok = ok && resolveDbusSym(lib, "dbus_message_has_path", out.message_has_path);
    ok = ok && resolveDbusSym(lib, "dbus_message_has_sender", out.message_has_sender);
    ok = ok && resolveDbusSym(lib, "dbus_message_has_signature", out.message_has_signature);
    ok = ok && resolveDbusSym(lib, "dbus_message_is_signal", out.message_is_signal);
    ok = ok && resolveDbusSym(lib, "dbus_message_iter_init", out.message_iter_init);
    ok = ok && resolveDbusSym(lib, "dbus_message_iter_next", out.message_iter_next);
    ok = ok && resolveDbusSym(lib, "dbus_message_iter_get_arg_type", out.message_iter_get_arg_type);
    ok = ok && resolveDbusSym(lib, "dbus_message_iter_get_element_type",
                              out.message_iter_get_element_type);
    ok = ok && resolveDbusSym(lib, "dbus_message_iter_get_basic", out.message_iter_get_basic);
    ok = ok && resolveDbusSym(lib, "dbus_message_iter_recurse", out.message_iter_recurse);
    ok = ok && resolveDbusSym(lib, "dbus_message_iter_get_fixed_array",
                              out.message_iter_get_fixed_array);
    ok = ok && resolveDbusSym(lib, "dbus_message_iter_init_append",
                              out.message_iter_init_append);
    ok = ok && resolveDbusSym(lib, "dbus_message_iter_append_basic", out.message_iter_append_basic);
    ok = ok && resolveDbusSym(lib, "dbus_message_iter_open_container",
                              out.message_iter_open_container);
    ok = ok && resolveDbusSym(lib, "dbus_message_iter_close_container",
                              out.message_iter_close_container);
    ok = ok && resolveDbusSym(lib, "dbus_message_iter_abandon_container",
                              out.message_iter_abandon_container);
    ok = ok && resolveDbusSym(lib, "dbus_message_iter_append_fixed_array",
                              out.message_iter_append_fixed_array);
    ok = ok && resolveDbusSym(lib, "dbus_validate_path", out.validate_path);

    if (!ok || !out.isComplete()) {
        ::dlclose(lib);
        out = DbusApi();
        setErr(error_out, "libdbus-1 missing required D-Bus symbols");
        return false;
    }

    if (loaded_name_out != NULL) {
        *loaded_name_out = chosen;
    }
    if (lib_handle_out != NULL) {
        *lib_handle_out = lib;
    } else {
        ::dlclose(lib);
    }
    return true;
#endif
}

void unloadDbusLibrary(void* lib_handle) {
#ifndef _WIN32
    if (lib_handle != NULL) {
        ::dlclose(lib_handle);
    }
#else
    (void)lib_handle;
#endif
}

bool probeAlpsDbusService(int timeout_ms,
                          std::string* owner_out,
                          const DbusApi* api_override) {
    if (owner_out != NULL) {
        owner_out->clear();
    }
#ifdef _WIN32
    (void)timeout_ms;
    (void)api_override;
    return false;
#else
    DbusApi loaded;
    void* lib_handle = NULL;
    const DbusApi* api = api_override;
    if (api == NULL) {
        if (!loadDbusApi(loaded, &lib_handle, NULL, NULL)) {
            return false;
        }
        api = &loaded;
    } else if (!api->isComplete()) {
        return false;
    }

    if (!api->threads_init_default()) {
        unloadDbusLibrary(lib_handle);
        return false;
    }

    DbusErrorRaw err;
    memset(&err, 0, sizeof(err));
    api->error_init(&err);

    DbusConnection* conn = api->bus_get_private(kDbusBusSystem, &err);
    if (conn == NULL || api->error_is_set(&err)) {
        if (conn != NULL) {
            api->connection_close(conn);
            api->connection_unref(conn);
        }
        api->error_free(&err);
        unloadDbusLibrary(lib_handle);
        return false;
    }
    api->connection_set_exit_on_disconnect(conn, kDbusFalse);

    DbusMessage* q = api->message_new_method_call(
        kDbusService, kDbusPath, kDbusInterface, "GetNameOwner");
    DbusMessage* reply = NULL;
    if (q != NULL) {
        DbusMessageIterRaw it;
        memset(&it, 0, sizeof(it));
        api->message_iter_init_append(q, &it);
        const char* svc = kAlpsDbusService;
        if (api->message_iter_append_basic(&it, kDbusTypeString, &svc)) {
            reply = api->connection_send_with_reply_and_block(
                conn, q, timeout_ms > 0 ? timeout_ms : 500, &err);
        }
        api->message_unref(q);
    }

    std::string owner;
    const bool got_owner =
        !api->error_is_set(&err) && readSingleStringReply(*api, reply, owner) && !owner.empty();
    if (reply != NULL) {
        api->message_unref(reply);
    }
    api->error_free(&err);
    api->connection_close(conn);
    api->connection_unref(conn);
    unloadDbusLibrary(lib_handle);

    if (got_owner && owner_out != NULL) {
        *owner_out = owner;
    }
    return got_owner;
#endif
}

// ------------------------------------------------------------------------------------------------
// AdvertisementSchedule
// ------------------------------------------------------------------------------------------------

bool AdvertisementSchedule::due(uint32_t elapsed_ms) {
    static const uint32_t kInitialTimesMs[3] = {15000U, 45000U, 90000U};
    if (next_ >= 3U) {
        if (repeat_ms_ == 0U || elapsed_ms - last_ms_ < repeat_ms_) {
            return false;
        }
        last_ms_ = elapsed_ms;
        return true;
    }
    if (elapsed_ms < kInitialTimesMs[next_]) {
        return false;
    }
    ++next_;
    last_ms_ = elapsed_ms;
    return true;
}

// ------------------------------------------------------------------------------------------------
// DbusAlpsSppLink
// ------------------------------------------------------------------------------------------------

#ifdef _WIN32

struct DbusAlpsSppLink::Impl {
    Impl(Reactor& r, AlpsSppLinkListener* l, const DbusApi*, size_t, size_t)
        : reactor(r), listener(l) {}
    Reactor& reactor;
    AlpsSppLinkListener* listener;
};

DbusAlpsSppLink::DbusAlpsSppLink(Reactor& reactor,
                                 AlpsSppLinkListener* listener,
                                 const DbusApi* dbus_api_override,
                                 size_t write_queue_limit,
                                 size_t max_rx_bytes)
    : impl_(new Impl(reactor, listener, dbus_api_override, write_queue_limit, max_rx_bytes)) {}

DbusAlpsSppLink::~DbusAlpsSppLink() {
    delete impl_;
}

bool DbusAlpsSppLink::start(uint8_t, bool) {
    last_error_ = "ALPS D-Bus transport is unsupported on Windows";
    return false;
}

void DbusAlpsSppLink::stop() {}
bool DbusAlpsSppLink::isRunning() const { return false; }
bool DbusAlpsSppLink::isLinkUp() const { return false; }
void DbusAlpsSppLink::setListener(AlpsSppLinkListener* listener) { impl_->listener = listener; }
int DbusAlpsSppLink::registerUuidPayload(const std::vector<uint8_t>&, int) { return -1; }
bool DbusAlpsSppLink::readConfiguration(uint8_t, uint16_t, std::vector<uint8_t>& out, int) {
    out.clear();
    return false;
}
bool DbusAlpsSppLink::setDataInterface(uint8_t, uint8_t, int) { return false; }
bool DbusAlpsSppLink::requestSppDisconnect() { return false; }
void DbusAlpsSppLink::disconnectLink(const std::string&) {}
bool DbusAlpsSppLink::sendData(const uint8_t*, size_t) { return false; }

#else

struct DbusAlpsSppLink::Impl {
    enum EventType {
        kEventConnected = 0,
        kEventData = 1,
        kEventDisconnected = 2,
        kEventFatalError = 3
    };

    struct Event {
        EventType type;
        BtAddr peer;
        std::vector<uint8_t> data;
        std::string reason;
    };

    Impl(Reactor& r,
         AlpsSppLinkListener* l,
         const DbusApi* api_override,
         size_t wq_limit,
         size_t rx_limit)
        : reactor(r),
          listener(l),
          api_override(api_override),
          has_api(false),
          lib_handle(NULL),
          write_queue_limit(wq_limit > 0 ? wq_limit : 256U * 1024U),
          max_rx_bytes(rx_limit > 0 ? rx_limit : 256U * 1024U),
          conn(NULL),
          inst(0),
          monitor(false),
          active(false),
          filter_installed(false),
          dispatch_started(false),
          pump_started(false),
          link_up(false),
          require_connect(false),
          remote_closed(false),
          tx_pending(false),
          tx_allowed(true),
          uuid_waiting(false),
          cfg_waiting(false),
          uuid_poisoned(false),
          cfg_poisoned(false),
          cfg_write(false),
          uuid_status(-1),
          cfg_status(-1),
          cfg_inst(0),
          cfg_id(0),
          tx_since_ms(0),
          tx_head(0),
          pending_rx_bytes(0),
          phone_known(false),
          dispatch_gen(0) {
        memset(phone, 0, sizeof(phone));
        pthread_mutex_init(&mu, NULL);
        pthread_mutex_init(&request_mu, NULL);
        pthread_mutex_init(&send_mu, NULL);
        pthread_condattr_t attr;
        pthread_condattr_init(&attr);
        pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
        pthread_cond_init(&cv, &attr);
        pthread_condattr_destroy(&attr);
    }

    ~Impl() {
        pthread_cond_destroy(&cv);
        pthread_mutex_destroy(&send_mu);
        pthread_mutex_destroy(&request_mu);
        pthread_mutex_destroy(&mu);
    }

    Reactor& reactor;
    AlpsSppLinkListener* listener;
    const DbusApi* api_override;
    DbusApi api;
    bool has_api;
    void* lib_handle;
    size_t write_queue_limit;
    size_t max_rx_bytes;

    DbusConnection* conn;
    std::string owner;
    uint8_t inst;
    bool monitor;
    bool active;
    bool filter_installed;
    bool dispatch_started;
    bool pump_started;
    Thread dispatch_thread;
    Thread pump_thread;

    pthread_mutex_t mu;
    pthread_mutex_t request_mu;
    pthread_mutex_t send_mu;
    pthread_cond_t cv;

    bool link_up;
    bool require_connect;
    bool remote_closed;
    bool tx_pending;
    bool tx_allowed;
    bool uuid_waiting;
    bool cfg_waiting;
    bool uuid_poisoned;
    bool cfg_poisoned;
    bool cfg_write;
    int uuid_status;
    int cfg_status;
    uint8_t cfg_inst;
    uint16_t cfg_id;
    int64_t tx_since_ms;

    std::vector<uint8_t> tx_queue;
    size_t tx_head;
    std::vector<uint8_t> cfg_data;
    std::deque<Event> pending_events;
    size_t pending_rx_bytes;
    uint8_t phone[6];
    bool phone_known;
    uint32_t dispatch_gen;

    // mu must be held.
    void enqueueEvent(const Event& ev) {
        pending_events.push_back(ev);
        reactor.post(&Impl::onReactorDispatch, this);
    }

    // mu must be held.
    void closeLinkLocked(bool notify_disconnect, const std::string& reason) {
        const bool was_up = link_up;
        if (was_up) {
            require_connect = true;
        }
        link_up = false;
        tx_pending = false;
        tx_queue.clear();
        tx_head = 0;
        if (was_up && notify_disconnect) {
            Event ev;
            ev.type = kEventDisconnected;
            ev.reason = reason;
            enqueueEvent(ev);
        }
        pthread_cond_broadcast(&cv);
    }

    // mu must be held.
    bool openLinkLocked(const uint8_t* addr6) {
        if (link_up) {
            return true;
        }
        if (monitor || !active || require_connect) {
            return false;
        }
        link_up = true;
        remote_closed = false;
        tx_pending = false;
        tx_allowed = true;
        tx_queue.clear();
        tx_head = 0;

        Event ev;
        ev.type = kEventConnected;
        if (addr6 != NULL) {
            memcpy(ev.peer.b, addr6, 6);
        } else if (phone_known) {
            memcpy(ev.peer.b, phone, 6);
        }
        CARPLAY_LOG_INFO("alps", "SPP link open on instance %u", static_cast<unsigned>(inst));
        enqueueEvent(ev);
        pthread_cond_broadcast(&cv);
        return true;
    }

    // Called without holding `mu` so synchronous D-Bus fakes cannot deadlock.
    bool sendMethodNoReply(DbusMessage* msg, bool valid) {
        bool ok = false;
        if (msg != NULL) {
            api.message_set_no_reply(msg, kDbusTrue);
            if (valid) {
                pthread_mutex_lock(&send_mu);
                ok = (api.connection_send(conn, msg, NULL) != 0);
                pthread_mutex_unlock(&send_mu);
            }
            api.message_unref(msg);
        }
        return ok;
    }

    static int filterCallback(DbusConnection* /*conn*/, DbusMessage* m, void* arg) {
        Impl* self = static_cast<Impl*>(arg);
        self->handleDbusMessage(m);
        return kDbusHandlerResultNotYetHandled;
    }

    void handleDbusMessage(DbusMessage* m) {
        pthread_mutex_lock(&mu);
        if (api.message_is_signal(m, kDbusLocalInterface, "Disconnected")) {
            active = false;
            closeLinkLocked(true, "D-Bus disconnected");
            Event ev;
            ev.type = kEventFatalError;
            ev.reason = "D-Bus disconnected";
            enqueueEvent(ev);
            pthread_mutex_unlock(&mu);
            return;
        }
        if (api.message_is_signal(m, kDbusInterface, "NameOwnerChanged") &&
            api.message_has_sender(m, kDbusService)) {
            std::string name;
            std::string old_owner;
            std::string new_owner;
            if (readThreeStringArgs(api, m, name, old_owner, new_owner) &&
                name == kAlpsDbusService && owner != new_owner) {
                CARPLAY_LOG_WARN("alps", "ALPS service owner changed/lost; restarting required");
                active = false;
                closeLinkLocked(true, "ALPS service lost");
                Event ev;
                ev.type = kEventFatalError;
                ev.reason = "ALPS service lost";
                enqueueEvent(ev);
            }
            pthread_mutex_unlock(&mu);
            return;
        }
        if (!active ||
            !api.message_has_path(m, kAlpsDbusPath) ||
            !api.message_has_sender(m, owner.c_str()) ||
            api.message_get_type(m) != kDbusMessageTypeSignal) {
            pthread_mutex_unlock(&mu);
            return;
        }
        handleAlpsSignalLocked(m);
        pthread_mutex_unlock(&mu);
    }

    void handleAlpsSignalLocked(DbusMessage* m) {
        const char* member = api.message_get_member(m);
        if (member == NULL) {
            return;
        }

        if (api.message_has_interface(m, kAlpsDbusDmInterface)) {
            if (strcmp(member, "BtApplReadConfigurationCfm") == 0 ||
                strcmp(member, "BtApplSetConfigurationCfm") == 0) {
                const bool writing = (strcmp(member, "BtApplSetConfigurationCfm") == 0);
                if (!api.message_has_signature(m, writing ? "yyq" : "yyqqay")) {
                    return;
                }
                DbusMessageIterRaw it;
                memset(&it, 0, sizeof(it));
                if (!api.message_iter_init(m, &it)) {
                    return;
                }
                uint8_t status = 0;
                uint8_t instance = 0;
                uint16_t id = 0;
                api.message_iter_get_basic(&it, &status);
                api.message_iter_next(&it);
                api.message_iter_get_basic(&it, &instance);
                api.message_iter_next(&it);
                api.message_iter_get_basic(&it, &id);
                if (!cfg_waiting || cfg_write != writing || cfg_inst != instance || cfg_id != id) {
                    return;
                }
                cfg_data.clear();
                if (!writing) {
                    uint16_t len = 0;
                    api.message_iter_next(&it);
                    api.message_iter_get_basic(&it, &len);
                    api.message_iter_next(&it);
                    const uint8_t* data = NULL;
                    int n = 0;
                    if (!readByteArrayIter(api, it, data, n) || n != static_cast<int>(len)) {
                        return;
                    }
                    if (n > 0 && data != NULL) {
                        cfg_data.assign(data, data + n);
                    }
                }
                cfg_status = static_cast<int>(status);
                cfg_waiting = false;
                pthread_cond_broadcast(&cv);
                return;
            }

            const bool connecting = (strcmp(member, "BtApplDeviceConnectInd") == 0);
            if (!connecting && strcmp(member, "BtApplDeviceDisconnectInd") != 0) {
                return;
            }
            if (!api.message_has_signature(m, connecting ? "yayty" : "yayyty")) {
                return;
            }
            DbusMessageIterRaw it;
            memset(&it, 0, sizeof(it));
            if (!api.message_iter_init(m, &it)) {
                return;
            }
            uint8_t status = 0;
            api.message_iter_get_basic(&it, &status);
            api.message_iter_next(&it);
            const uint8_t* addr = NULL;
            int n = 0;
            if (!readByteArrayIter(api, it, addr, n) || n != 6 || addr == NULL) {
                return;
            }
            api.message_iter_next(&it);
            uint8_t reason = 0;
            if (!connecting) {
                api.message_iter_get_basic(&it, &reason);
                api.message_iter_next(&it);
            }
            uint64_t function = 0;
            uint8_t instance = 0;
            api.message_iter_get_basic(&it, &function);
            api.message_iter_next(&it);
            api.message_iter_get_basic(&it, &instance);

            const bool ours = !monitor &&
                              instance == inst &&
                              function == kAlpsDmFunctionSpp &&
                              (status & 0x7fU) == 0U;
            if (ours && connecting) {
                memcpy(phone, addr, sizeof(phone));
                phone_known = true;
            }
            if (!ours) {
                return;
            }
            if (connecting) {
                require_connect = false;
                openLinkLocked(addr);
            } else {
                remote_closed = true;
                require_connect = true;
                tx_pending = false;
                tx_allowed = false;
                char reason_buf[64];
                snprintf(reason_buf, sizeof(reason_buf), "peer disconnected (reason=%u)",
                         static_cast<unsigned>(reason));
                closeLinkLocked(true, reason_buf);
            }
            return;
        }

        if (!api.message_has_interface(m, kAlpsDbusSppInterface)) {
            return;
        }
        DbusMessageIterRaw it;
        memset(&it, 0, sizeof(it));
        if (!api.message_iter_init(m, &it) ||
            api.message_iter_get_arg_type(&it) != kDbusTypeByte) {
            return;
        }
        uint8_t instance = 0;
        api.message_iter_get_basic(&it, &instance);
        if (instance != inst) {
            return;
        }

        if (strcmp(member, "BtApplSppSetUuidCfm") == 0 && api.message_has_signature(m, "yy")) {
            api.message_iter_next(&it);
            uint8_t status = 0;
            api.message_iter_get_basic(&it, &status);
            if (uuid_waiting) {
                uuid_status = static_cast<int>(status);
                uuid_waiting = false;
                pthread_cond_broadcast(&cv);
            }
            return;
        }

        if (monitor) {
            return;
        }

        if (strcmp(member, "BtApplSppDataInd") == 0 && api.message_has_signature(m, "yqay")) {
            uint16_t len = 0;
            api.message_iter_next(&it);
            api.message_iter_get_basic(&it, &len);
            api.message_iter_next(&it);
            const uint8_t* data = NULL;
            int n = 0;
            if (!readByteArrayIter(api, it, data, n) || n != static_cast<int>(len) || n <= 0 || data == NULL) {
                return;
            }
            if (remote_closed || !openLinkLocked(NULL)) {
                return;
            }
            if (static_cast<size_t>(n) > max_rx_bytes ||
                pending_rx_bytes > max_rx_bytes - static_cast<size_t>(n)) {
                CARPLAY_LOG_ERROR("alps", "SPP receive buffer exceeded %zu bytes; closing link",
                                  max_rx_bytes);
                closeLinkLocked(true, "rx buffer overflow");
                return;
            }
            Event ev;
            ev.type = kEventData;
            ev.data.assign(data, data + n);
            pending_rx_bytes += ev.data.size();
            enqueueEvent(ev);
        } else if (link_up && strcmp(member, "BtApplSppDataCfm") == 0 &&
                   api.message_has_signature(m, "yy")) {
            uint8_t status = 0;
            api.message_iter_next(&it);
            api.message_iter_get_basic(&it, &status);
            if (!tx_pending) {
                return;
            }
            // BtApplSppDataCfm only reports failure when status != 0; BtApplSppSendInd completes TX.
            if (status != 0U) {
                CARPLAY_LOG_WARN("alps", "BtApplSppDataCfm error status=%u", static_cast<unsigned>(status));
                closeLinkLocked(true, "DataCfm error");
            }
            pthread_cond_broadcast(&cv);
        } else if (link_up && strcmp(member, "BtApplSppSendInd") == 0 &&
                   api.message_has_signature(m, "y")) {
            tx_pending = false;
            pthread_cond_broadcast(&cv);
        } else if (link_up && strcmp(member, "BtApplSppDataSendFcInd") == 0 &&
                   api.message_has_signature(m, "yy")) {
            uint8_t status = 0;
            api.message_iter_next(&it);
            api.message_iter_get_basic(&it, &status);
            tx_allowed = (status == 0U);
            CARPLAY_LOG_DEBUG("alps", "SPP flow control status=%u (%s)",
                              static_cast<unsigned>(status), tx_allowed ? "ready" : "paused");
            pthread_cond_broadcast(&cv);
        }
    }

    static void dispatchThreadFn(void* arg) {
        Impl* self = static_cast<Impl*>(arg);
        for (;;) {
            pthread_mutex_lock(&self->mu);
            const bool running = self->active;
            pthread_mutex_unlock(&self->mu);
            if (!running) {
                break;
            }
            if (!self->api.connection_read_write_dispatch(self->conn, 50)) {
                pthread_mutex_lock(&self->mu);
                const bool was_active = self->active;
                self->active = false;
                self->closeLinkLocked(true, "D-Bus dispatch ended");
                if (was_active) {
                    Event ev;
                    ev.type = kEventFatalError;
                    ev.reason = "D-Bus dispatch ended";
                    self->enqueueEvent(ev);
                }
                pthread_mutex_unlock(&self->mu);
                break;
            }
            sleepPlatformMs(1U);
        }
    }

    static void pumpThreadFn(void* arg) {
        Impl* self = static_cast<Impl*>(arg);
        pthread_mutex_lock(&self->mu);
        while (self->active) {
            if (self->link_up) {
                if (self->tx_pending && monotonicMillis() - self->tx_since_ms >= 5000) {
                    CARPLAY_LOG_ERROR("alps", "no BtApplSppSendInd for 5s; closing SPP link");
                    self->closeLinkLocked(true, "TX SendInd timeout");
                }
                if (self->link_up &&
                    !self->remote_closed &&
                    !self->tx_pending &&
                    self->tx_allowed &&
                    self->tx_head < self->tx_queue.size()) {
                    const size_t avail = self->tx_queue.size() - self->tx_head;
                    const size_t chunk = avail > kAlpsMaxDataReqBytes ? kAlpsMaxDataReqBytes : avail;
                    uint8_t buf[kAlpsMaxDataReqBytes];
                    memcpy(buf, &self->tx_queue[self->tx_head], chunk);
                    self->tx_head += chunk;
                    if (self->tx_head == self->tx_queue.size()) {
                        self->tx_queue.clear();
                        self->tx_head = 0;
                    } else if (self->tx_head > 4096U && self->tx_head * 2U > self->tx_queue.size()) {
                        self->tx_queue.erase(
                            self->tx_queue.begin(),
                            self->tx_queue.begin() + static_cast<std::ptrdiff_t>(self->tx_head));
                        self->tx_head = 0;
                    }
                    self->tx_pending = true;
                    self->tx_since_ms = monotonicMillis();
                    const std::string target_owner = self->owner;
                    const uint8_t target_inst = self->inst;
                    pthread_mutex_unlock(&self->mu);

                    DbusMessage* m = self->api.message_new_method_call(
                        target_owner.c_str(), kAlpsDbusPath, kAlpsDbusSppInterface, "BtApplSppDataReq");
                    const bool valid = appendAlpsByteArrayPayload(
                        self->api, m, target_inst, buf, chunk, NULL);
                    const bool sent = self->sendMethodNoReply(m, valid);

                    pthread_mutex_lock(&self->mu);
                    if (!sent && self->active && self->link_up) {
                        self->closeLinkLocked(true, "BtApplSppDataReq failed");
                    }
                    continue;
                }
            }
            struct timespec t = monotonicDeadline(10);
            pthread_cond_timedwait(&self->cv, &self->mu, &t);
        }
        pthread_mutex_unlock(&self->mu);
    }

    static void onReactorDispatch(void* ctx) {
        Impl* self = static_cast<Impl*>(ctx);
        std::deque<Event> batch;
        AlpsSppLinkListener* cb = NULL;
        uint32_t gen_before = 0;

        pthread_mutex_lock(&self->mu);
        batch.swap(self->pending_events);
        self->pending_rx_bytes = 0;
        cb = self->listener;
        gen_before = self->dispatch_gen;
        pthread_mutex_unlock(&self->mu);

        if (cb == NULL) {
            return;
        }

        for (size_t i = 0; i < batch.size(); ++i) {
            pthread_mutex_lock(&self->mu);
            const bool abort_batch = (!self->active && batch[i].type == kEventData) ||
                                     (self->dispatch_gen != gen_before) ||
                                     (self->listener == NULL);
            cb = self->listener;
            pthread_mutex_unlock(&self->mu);
            if (abort_batch || cb == NULL) {
                break;
            }
            const Event& ev = batch[i];
            switch (ev.type) {
                case kEventConnected:
                    cb->onAlpsConnected(ev.peer);
                    break;
                case kEventData:
                    if (!ev.data.empty()) {
                        cb->onAlpsData(&ev.data[0], ev.data.size());
                    }
                    break;
                case kEventDisconnected:
                    cb->onAlpsDisconnected(ev.reason);
                    break;
                case kEventFatalError:
                    cb->onAlpsFatalError(ev.reason);
                    break;
            }
        }
    }

    bool configurationLockedReq(uint8_t target_inst,
                                uint16_t id,
                                bool writing,
                                std::vector<uint8_t>& out,
                                int ms,
                                uint8_t value) {
        out.clear();
        pthread_mutex_lock(&mu);
        if (!active || cfg_poisoned || ms <= 0 || (writing && monitor)) {
            pthread_mutex_unlock(&mu);
            return false;
        }
        cfg_inst = target_inst;
        cfg_id = id;
        cfg_write = writing;
        cfg_status = -1;
        cfg_waiting = true;
        cfg_data.clear();
        const std::string target_owner = owner;
        pthread_mutex_unlock(&mu);

        bool sent = false;
        if (writing) {
            DbusMessage* m = api.message_new_method_call(
                target_owner.c_str(), kAlpsDbusPath, kAlpsDbusDmInterface, "BtApplSetConfigurationReq");
            const bool valid = appendAlpsByteArrayPayload(api, m, target_inst, &value, 1U, &id);
            sent = sendMethodNoReply(m, valid);
        } else {
            DbusMessage* m = api.message_new_method_call(
                target_owner.c_str(), kAlpsDbusPath, kAlpsDbusDmInterface, "BtApplReadConfigurationReq");
            bool valid = false;
            if (m != NULL) {
                DbusMessageIterRaw it;
                memset(&it, 0, sizeof(it));
                api.message_iter_init_append(m, &it);
                valid = api.message_iter_append_basic(&it, kDbusTypeByte, &target_inst) != 0 &&
                        api.message_iter_append_basic(&it, kDbusTypeUint16, &id) != 0;
            }
            sent = sendMethodNoReply(m, valid);
        }

        pthread_mutex_lock(&mu);
        if (!sent) {
            cfg_waiting = false;
            pthread_mutex_unlock(&mu);
            return false;
        }
        const struct timespec t = monotonicDeadline(ms);
        while (active && cfg_waiting) {
            if (pthread_cond_timedwait(&cv, &mu, &t) == ETIMEDOUT) {
                break;
            }
        }
        if (cfg_waiting) {
            cfg_poisoned = true;
            cfg_waiting = false;
            pthread_mutex_unlock(&mu);
            return false;
        }
        const bool ok = active && (cfg_status == 0);
        if (ok) {
            out = cfg_data;
        }
        pthread_mutex_unlock(&mu);
        return ok;
    }
};

DbusAlpsSppLink::DbusAlpsSppLink(Reactor& reactor,
                                 AlpsSppLinkListener* listener,
                                 const DbusApi* dbus_api_override,
                                 size_t write_queue_limit,
                                 size_t max_rx_bytes)
    : impl_(new Impl(reactor, listener, dbus_api_override, write_queue_limit, max_rx_bytes)) {}

DbusAlpsSppLink::~DbusAlpsSppLink() {
    setListener(NULL);
    stop();
    delete impl_;
}

void DbusAlpsSppLink::setListener(AlpsSppLinkListener* listener) {
    pthread_mutex_lock(&impl_->mu);
    impl_->listener = listener;
    pthread_mutex_unlock(&impl_->mu);
}

bool DbusAlpsSppLink::isRunning() const {
    pthread_mutex_lock(&impl_->mu);
    const bool r = impl_->active;
    pthread_mutex_unlock(&impl_->mu);
    return r;
}

bool DbusAlpsSppLink::isLinkUp() const {
    pthread_mutex_lock(&impl_->mu);
    const bool r = impl_->link_up;
    pthread_mutex_unlock(&impl_->mu);
    return r;
}

bool DbusAlpsSppLink::start(uint8_t instance, bool monitor_only) {
    if (impl_->conn != NULL) {
        last_error_ = "ALPS D-Bus link already started";
        return false;
    }
    if (instance >= kAlpsMaxInstances) {
        last_error_ = "invalid ALPS SPP instance";
        return false;
    }

    if (impl_->api_override != NULL) {
        if (!impl_->api_override->isComplete()) {
            last_error_ = "incomplete DbusApi override";
            return false;
        }
        impl_->api = *impl_->api_override;
        impl_->has_api = true;
    } else {
        std::string load_err;
        if (!loadDbusApi(impl_->api, &impl_->lib_handle, NULL, &load_err)) {
            last_error_ = load_err;
            return false;
        }
        impl_->has_api = true;
    }

    if (!impl_->api.threads_init_default()) {
        last_error_ = "dbus_threads_init_default() failed";
        stop();
        return false;
    }

    DbusErrorRaw err;
    memset(&err, 0, sizeof(err));
    impl_->api.error_init(&err);

    impl_->conn = impl_->api.bus_get_private(kDbusBusSystem, &err);
    if (impl_->conn == NULL || impl_->api.error_is_set(&err)) {
        last_error_ = err.message != NULL ? err.message : "dbus_bus_get_private() failed";
        impl_->api.error_free(&err);
        stop();
        return false;
    }
    impl_->api.connection_set_exit_on_disconnect(impl_->conn, kDbusFalse);

    DbusMessage* q = impl_->api.message_new_method_call(
        kDbusService, kDbusPath, kDbusInterface, "GetNameOwner");
    DbusMessage* reply = NULL;
    if (q != NULL) {
        DbusMessageIterRaw it;
        memset(&it, 0, sizeof(it));
        impl_->api.message_iter_init_append(q, &it);
        const char* svc = kAlpsDbusService;
        if (impl_->api.message_iter_append_basic(&it, kDbusTypeString, &svc)) {
            reply = impl_->api.connection_send_with_reply_and_block(impl_->conn, q, 2000, &err);
        }
        impl_->api.message_unref(q);
    }

    std::string owner;
    const bool got_owner =
        !impl_->api.error_is_set(&err) && readSingleStringReply(impl_->api, reply, owner) && !owner.empty();
    if (reply != NULL) {
        impl_->api.message_unref(reply);
    }
    if (!got_owner) {
        last_error_ = "org.alps.evolution service missing on D-Bus";
        impl_->api.error_free(&err);
        stop();
        return false;
    }
    impl_->owner = owner;

    if (!impl_->api.connection_add_filter(impl_->conn, &Impl::filterCallback, impl_, NULL)) {
        last_error_ = "dbus_connection_add_filter() failed";
        impl_->api.error_free(&err);
        stop();
        return false;
    }
    impl_->filter_installed = true;

    const char* interfaces[2] = {kAlpsDbusSppInterface, kAlpsDbusDmInterface};
    for (size_t i = 0; i < 2U; ++i) {
        const std::string rule = std::string("type='signal',sender='") + kAlpsDbusService +
                                 "',path='" + kAlpsDbusPath + "',interface='" + interfaces[i] + "'";
        impl_->api.bus_add_match(impl_->conn, rule.c_str(), &err);
        if (impl_->api.error_is_set(&err)) {
            last_error_ = err.message != NULL ? err.message : "dbus_bus_add_match() failed";
            impl_->api.error_free(&err);
            stop();
            return false;
        }
    }

    impl_->api.bus_add_match(
        impl_->conn,
        "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',"
        "member='NameOwnerChanged',arg0='org.alps.evolution'",
        &err);
    if (impl_->api.error_is_set(&err)) {
        last_error_ = err.message != NULL ? err.message : "dbus_bus_add_match(NameOwnerChanged) failed";
        impl_->api.error_free(&err);
        stop();
        return false;
    }
    impl_->api.error_free(&err);

    pthread_mutex_lock(&impl_->mu);
    impl_->inst = instance;
    impl_->monitor = monitor_only;
    impl_->active = true;
    impl_->link_up = false;
    impl_->require_connect = false;
    impl_->remote_closed = false;
    impl_->tx_pending = false;
    impl_->tx_allowed = true;
    impl_->uuid_waiting = false;
    impl_->cfg_waiting = false;
    impl_->uuid_poisoned = false;
    impl_->cfg_poisoned = false;
    impl_->tx_queue.clear();
    impl_->tx_head = 0;
    impl_->pending_events.clear();
    impl_->pending_rx_bytes = 0;
    ++impl_->dispatch_gen;
    pthread_mutex_unlock(&impl_->mu);

    if (!impl_->dispatch_thread.start(&Impl::dispatchThreadFn, impl_)) {
        last_error_ = "failed to start ALPS D-Bus dispatch thread";
        stop();
        return false;
    }
    impl_->dispatch_started = true;

    if (!monitor_only) {
        if (!impl_->pump_thread.start(&Impl::pumpThreadFn, impl_)) {
            last_error_ = "failed to start ALPS D-Bus TX pump thread";
            stop();
            return false;
        }
        impl_->pump_started = true;
    }

    last_error_.clear();
    return true;
}

void DbusAlpsSppLink::stop() {
    pthread_mutex_lock(&impl_->mu);
    impl_->active = false;
    impl_->closeLinkLocked(false, "stopped");
    ++impl_->dispatch_gen;
    pthread_mutex_unlock(&impl_->mu);

    if (impl_->dispatch_started) {
        impl_->dispatch_thread.join();
        impl_->dispatch_started = false;
    }
    if (impl_->pump_started) {
        impl_->pump_thread.join();
        impl_->pump_started = false;
    }

    // Worker threads have joined so nothing can post after cancelPosted().
    impl_->reactor.cancelPosted(&Impl::onReactorDispatch, impl_);
    pthread_mutex_lock(&impl_->mu);
    impl_->pending_events.clear();
    impl_->pending_rx_bytes = 0;
    pthread_mutex_unlock(&impl_->mu);

    pthread_mutex_lock(&impl_->request_mu);
    if (impl_->conn != NULL && impl_->has_api) {
        if (impl_->filter_installed) {
            impl_->api.connection_remove_filter(impl_->conn, &Impl::filterCallback, impl_);
            impl_->filter_installed = false;
        }
        impl_->api.connection_close(impl_->conn);
        impl_->api.connection_unref(impl_->conn);
        impl_->conn = NULL;
    }
    impl_->owner.clear();
    pthread_mutex_unlock(&impl_->request_mu);

    if (impl_->lib_handle != NULL) {
        unloadDbusLibrary(impl_->lib_handle);
        impl_->lib_handle = NULL;
    }
    impl_->has_api = false;
}

int DbusAlpsSppLink::registerUuidPayload(const std::vector<uint8_t>& payload, int timeout_ms) {
    if (!validateSppUuidPayload(payload) || timeout_ms <= 0) {
        return -1;
    }

    pthread_mutex_lock(&impl_->request_mu);
    pthread_mutex_lock(&impl_->mu);
    if (!impl_->active || impl_->monitor || impl_->uuid_poisoned || impl_->link_up) {
        pthread_mutex_unlock(&impl_->mu);
        pthread_mutex_unlock(&impl_->request_mu);
        return -1;
    }
    impl_->uuid_waiting = true;
    impl_->uuid_status = -1;
    const std::string target_owner = impl_->owner;
    const uint8_t target_inst = impl_->inst;
    pthread_mutex_unlock(&impl_->mu);

    DbusMessage* m = impl_->api.message_new_method_call(
        target_owner.c_str(), kAlpsDbusPath, kAlpsDbusSppInterface, "BtApplSppSetUuidReq");
    const bool valid = appendAlpsByteArrayPayload(
        impl_->api, m, target_inst, &payload[0], payload.size(), NULL);
    const bool sent = impl_->sendMethodNoReply(m, valid);

    pthread_mutex_lock(&impl_->mu);
    if (!sent) {
        impl_->uuid_waiting = false;
        pthread_mutex_unlock(&impl_->mu);
        pthread_mutex_unlock(&impl_->request_mu);
        return -1;
    }
    const struct timespec t = monotonicDeadline(timeout_ms);
    while (impl_->active && impl_->uuid_waiting) {
        if (pthread_cond_timedwait(&impl_->cv, &impl_->mu, &t) == ETIMEDOUT) {
            break;
        }
    }
    int status = -1;
    if (impl_->uuid_waiting) {
        impl_->uuid_poisoned = true;
        impl_->uuid_waiting = false;
    } else if (impl_->active) {
        status = impl_->uuid_status;
    }
    pthread_mutex_unlock(&impl_->mu);
    pthread_mutex_unlock(&impl_->request_mu);
    return status;
}

bool DbusAlpsSppLink::readConfiguration(uint8_t instance,
                                        uint16_t id,
                                        std::vector<uint8_t>& out,
                                        int timeout_ms) {
    pthread_mutex_lock(&impl_->request_mu);
    const bool ok = impl_->configurationLockedReq(instance, id, false, out, timeout_ms, 0U);
    pthread_mutex_unlock(&impl_->request_mu);
    return ok;
}

bool DbusAlpsSppLink::setDataInterface(uint8_t instance, uint8_t value, int timeout_ms) {
    if (value > 1U) {
        return false;
    }
    pthread_mutex_lock(&impl_->request_mu);
    std::vector<uint8_t> data;
    bool ok = impl_->configurationLockedReq(
        instance, kAlpsConfigDataInterface, true, data, timeout_ms, value);
    if (ok && alpsSlotConfigurationReadable(instance)) {
        ok = impl_->configurationLockedReq(
                 instance, kAlpsConfigDataInterface, false, data, timeout_ms, 0U) &&
             data.size() == 1U &&
             data[0] == value;
    }
    pthread_mutex_unlock(&impl_->request_mu);
    return ok;
}

bool DbusAlpsSppLink::requestSppDisconnect() {
    pthread_mutex_lock(&impl_->request_mu);
    pthread_mutex_lock(&impl_->mu);
    if (!impl_->active || impl_->monitor) {
        pthread_mutex_unlock(&impl_->mu);
        pthread_mutex_unlock(&impl_->request_mu);
        return false;
    }
    const std::string target_owner = impl_->owner;
    const uint8_t target_inst = impl_->inst;
    pthread_mutex_unlock(&impl_->mu);

    DbusMessage* m = impl_->api.message_new_method_call(
        target_owner.c_str(), kAlpsDbusPath, kAlpsDbusDmInterface, "BtApplDeviceDisconnectReq");
    bool valid = false;
    if (m != NULL) {
        DbusMessageIterRaw it;
        memset(&it, 0, sizeof(it));
        impl_->api.message_iter_init_append(m, &it);
        const uint64_t function = kAlpsDmFunctionSpp;
        valid = impl_->api.message_iter_append_basic(&it, kDbusTypeUint64, &function) != 0 &&
                impl_->api.message_iter_append_basic(&it, kDbusTypeByte, &target_inst) != 0;
    }
    const bool ok = impl_->sendMethodNoReply(m, valid);
    pthread_mutex_unlock(&impl_->request_mu);
    return ok;
}

void DbusAlpsSppLink::disconnectLink(const std::string& reason) {
    pthread_mutex_lock(&impl_->mu);
    impl_->closeLinkLocked(true, reason);
    pthread_mutex_unlock(&impl_->mu);
}

bool DbusAlpsSppLink::sendData(const uint8_t* data, size_t len) {
    pthread_mutex_lock(&impl_->mu);
    if (!impl_->active || !impl_->link_up || impl_->remote_closed) {
        pthread_mutex_unlock(&impl_->mu);
        return false;
    }
    if (len == 0U) {
        pthread_mutex_unlock(&impl_->mu);
        return true;
    }
    if (data == NULL) {
        pthread_mutex_unlock(&impl_->mu);
        return false;
    }
    const size_t queued = impl_->tx_queue.size() - impl_->tx_head;
    if (len > impl_->write_queue_limit || queued > impl_->write_queue_limit - len) {
        pthread_mutex_unlock(&impl_->mu);
        return false;
    }
    impl_->tx_queue.insert(impl_->tx_queue.end(), data, data + len);
    pthread_cond_broadcast(&impl_->cv);
    pthread_mutex_unlock(&impl_->mu);
    return true;
}

#endif  // _WIN32

// ------------------------------------------------------------------------------------------------
// AlpsSppManager
// ------------------------------------------------------------------------------------------------

AlpsSppManager::AlpsSppManager(Reactor& reactor,
                               AlpsSppManagerListener& listener,
                               const AlpsSppManagerConfig& config,
                               SppMemoryBackend* mem_backend,
                               AlpsSppLink* link_override)
    : reactor_(reactor),
      listener_(&listener),
      config_(config),
      reader_(mem_backend, config.double_read_delay_ms),
      link_adapter_(this),
      default_link_(reactor, &link_adapter_),
      link_(link_override != NULL ? link_override : &default_link_),
      advert_handler_(this),
      advert_timer_id_(Reactor::kNoTimer),
      advert_start_ns_(0),
      advert_schedule_(config.advertisement_repeat_ms),
      started_(false),
      connected_(false),
      active_slot_(0),
      slot_decision_(kSlotRefuseError),
      borrowed_(false),
      baseline_pid_(0),
      baseline_interface_(0),
      restore_attempted_(false),
      restore_succeeded_(false) {
    link_->setListener(&link_adapter_);
}

AlpsSppManager::~AlpsSppManager() {
    listener_ = NULL;
    stop();
    link_->setListener(NULL);
}

void AlpsSppManager::abortStartCleanup() {
    if (advert_timer_id_ != Reactor::kNoTimer) {
        reactor_.cancelTimer(advert_timer_id_);
        advert_timer_id_ = Reactor::kNoTimer;
    }
    link_->stop();
    reader_.close();
    started_ = false;
    connected_ = false;
    borrowed_ = false;
    peer_addr_ = BtAddr::any();
}

bool AlpsSppManager::start(std::string* error_out) {
    if (started_) {
        setErr(error_out, "AlpsSppManager already started");
        last_error_ = *error_out;
        return false;
    }

    last_error_.clear();
    restore_attempted_ = false;
    restore_succeeded_ = false;
    connected_ = false;
    peer_addr_ = BtAddr::any();
    advert_schedule_.reset();

    reader_.close();
    if (!reader_.open()) {
        last_error_ = reader_.error().empty() ? "failed to open ALPS snapshot reader" : reader_.error();
        setErr(error_out, last_error_);
        return false;
    }

    const CarPlaySlotSelection sel = selectCarPlaySppSlot(reader_, config_.slot_policy);
    slot_decision_ = sel.decision;
    if (!sel.isUsable()) {
        last_error_ = sel.reason;
        setErr(error_out, last_error_);
        reader_.close();
        return false;
    }

    active_slot_ = sel.slot;
    borrowed_ = sel.requires_restore;
    baseline_pid_ = reader_.pid();
    baseline_identity_ = reader_.identity();
    baseline_uuid_ = sel.snapshot.uuid_payload;
    baseline_interface_ = 0U;

    if (!link_->start(active_slot_, false)) {
        last_error_ = link_->lastError().empty() ? "failed to start ALPS D-Bus link" : link_->lastError();
        setErr(error_out, last_error_);
        abortStartCleanup();
        return false;
    }

    if (!sel.requires_configure) {
        // Native CarPlay slot 1: read-only verification only; never mutate UUID or 0x6203.
        if (config_.verify_native_slot_interface) {
            std::vector<uint8_t> cfg;
            if (!link_->readConfiguration(active_slot_, kAlpsConfigDataInterface,
                                          cfg, config_.dbus_timeout_ms) ||
                cfg.size() != 1U || cfg[0] != 1U) {
                last_error_ = "native CarPlay slot 1 0x6203 data interface is not 1";
                setErr(error_out, last_error_);
                abortStartCleanup();
                return false;
            }
        }
        CARPLAY_LOG_INFO("alps", "using native CarPlay SPP slot %u (unmodified)",
                         static_cast<unsigned>(active_slot_));
        started_ = true;
        return true;
    }

    // Borrowed slot (5, or 0 if explicit fallback enabled).
    if (!configureBorrowedSlot(error_out)) {
        if (!restoreBorrowedSlot(NULL)) {
            CARPLAY_LOG_ERROR("alps", "restore failed during aborted start cleanup");
        }
        abortStartCleanup();
        return false;
    }

    started_ = true;
    if (config_.enable_advertisement_refresh) {
        advert_start_ns_ = reactor_.now();
        advert_timer_id_ = reactor_.startTimer(1000, 1000, &advert_handler_);
    }
    CARPLAY_LOG_INFO("alps", "borrowed ALPS SPP slot %u (%s); restoration armed",
                     static_cast<unsigned>(active_slot_), carPlaySlotDecisionName(slot_decision_));
    return true;
}

bool AlpsSppManager::configureBorrowedSlot(std::string* error_out) {
    if (alpsSlotConfigurationReadable(active_slot_)) {
        std::vector<uint8_t> cfg;
        if (!link_->readConfiguration(active_slot_, kAlpsConfigDataInterface,
                                      cfg, config_.dbus_timeout_ms) ||
            cfg.size() != 1U || cfg[0] > 1U) {
            last_error_ = "cannot read baseline 0x6203 on borrowed slot";
            setErr(error_out, last_error_);
            return false;
        }
        baseline_interface_ = cfg[0];
        if (baseline_interface_ != 1U) {
            if (!link_->setDataInterface(active_slot_, 1U, config_.dbus_timeout_ms)) {
                last_error_ = "failed to set 0x6203=1 on borrowed slot";
                setErr(error_out, last_error_);
                return false;
            }
        }
    } else {
        // Slot 5: gen_GetConfig returns slot 0's value; baseline is 0 (generic unused spare)
        // and writing 1 is confirmed by BtApplSetConfigurationCfm status == 0.
        baseline_interface_ = 0U;
        if (!link_->setDataInterface(active_slot_, 1U, config_.dbus_timeout_ms)) {
            last_error_ = "failed to set 0x6203=1 on borrowed slot 5";
            setErr(error_out, last_error_);
            return false;
        }
    }

    const int uuid_rc = link_->registerUuidPayload(
        config_.slot_policy.target_uuid_pair, config_.uuid_timeout_ms);
    if (uuid_rc != 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "BtApplSppSetUuidReq failed (status=%d)", uuid_rc);
        last_error_ = buf;
        setErr(error_out, last_error_);
        return false;
    }

    // Re-read ALPS tables via /proc to confirm both UUID copies match our target pair.
    SppSlotSnapshot verify;
    if (!reader_.read(active_slot_, verify, false) ||
        !verify.hasConsistentUuids() ||
        verify.uuid_payload != config_.slot_policy.target_uuid_pair) {
        last_error_ = "post-configure ALPS snapshot mismatch or unreadable";
        setErr(error_out, last_error_);
        return false;
    }
    return true;
}

bool AlpsSppManager::waitSettledSnapshot(unsigned instance,
                                         SppSlotSnapshot& out,
                                         bool allow_split,
                                         int timeout_ms) {
    const int64_t deadline_ms = monotonicMillis() + (timeout_ms > 0 ? timeout_ms : 1);
    do {
        if (reader_.read(instance, out, allow_split)) {
            return true;
        }
        sleepPlatformMs(config_.restore_poll_interval_ms);
    } while (monotonicMillis() < deadline_ms);
    return false;
}

bool AlpsSppManager::restoreBorrowedSlot(std::string* error_out) {
    restore_attempted_ = true;
    restore_succeeded_ = false;

    if (!reader_.isOpen()) {
        last_error_ = "restore refused: snapshot reader is closed";
        setErr(error_out, last_error_);
        return false;
    }
    if (reader_.pid() != baseline_pid_ ||
        !reader_.checkProcessIdentity() ||
        reader_.identity() != baseline_identity_) {
        last_error_ = "restore refused: ALPS process restarted; not writing old values back";
        setErr(error_out, last_error_);
        CARPLAY_LOG_WARN("alps", "%s", last_error_.c_str());
        return false;
    }

    SppSlotSnapshot now;
    if (!waitSettledSnapshot(active_slot_, now, true, config_.restore_settle_timeout_ms)) {
        last_error_ = "restore failed: ALPS snapshot not settled (" + reader_.error() + ")";
        setErr(error_out, last_error_);
        CARPLAY_LOG_WARN("alps", "%s", last_error_.c_str());
        return false;
    }

    const std::vector<uint8_t>& target = config_.slot_policy.target_uuid_pair;
    if ((now.uuid_payload != target && now.uuid_payload != baseline_uuid_) ||
        (now.transport_uuid_payload != target && now.transport_uuid_payload != baseline_uuid_)) {
        last_error_ = "restore refused: third-party UUID found on borrowed slot";
        setErr(error_out, last_error_);
        CARPLAY_LOG_WARN("alps", "%s", last_error_.c_str());
        return false;
    }

    if (now.uuid_payload == target || now.transport_uuid_payload == target) {
        if (!now.isIdle()) {
            // An unconfirmed partial registration does not establish ownership of an active link.
            if (now.uuid_payload != target) {
                last_error_ = "restore refused: slot busy without confirmed CarPlay registration";
                setErr(error_out, last_error_);
                CARPLAY_LOG_WARN("alps", "%s", last_error_.c_str());
                return false;
            }
            if (!link_->requestSppDisconnect()) {
                last_error_ = "restore failed: BtApplDeviceDisconnectReq rejected";
                setErr(error_out, last_error_);
                return false;
            }
            const int64_t deadline_ms = monotonicMillis() +
                (config_.restore_disconnect_timeout_ms > 0 ? config_.restore_disconnect_timeout_ms : 1);
            bool became_idle = false;
            do {
                sleepPlatformMs(config_.restore_poll_interval_ms);
                if (reader_.read(active_slot_, now, false) && now.isIdle()) {
                    became_idle = true;
                    break;
                }
            } while (monotonicMillis() < deadline_ms);
            if (!became_idle) {
                last_error_ = "restore failed: SPP disconnect not confirmed";
                setErr(error_out, last_error_);
                return false;
            }
            if ((now.uuid_payload != target && now.uuid_payload != baseline_uuid_) ||
                (now.transport_uuid_payload != target && now.transport_uuid_payload != baseline_uuid_)) {
                last_error_ = "restore refused: UUID changed during disconnect";
                setErr(error_out, last_error_);
                return false;
            }
        }

        link_->disconnectLink("restoring borrowed slot");
        const int rc = link_->registerUuidPayload(baseline_uuid_, config_.uuid_timeout_ms);
        if (rc != 0) {
            char buf[64];
            snprintf(buf, sizeof(buf), "restore failed: UUID restore status=%d", rc);
            last_error_ = buf;
            setErr(error_out, last_error_);
            return false;
        }
    }

    const bool readable = alpsSlotConfigurationReadable(active_slot_);
    std::vector<uint8_t> cfg;
    if (readable &&
        (!link_->readConfiguration(active_slot_, kAlpsConfigDataInterface,
                                   cfg, config_.dbus_timeout_ms) ||
         cfg.size() != 1U || cfg[0] > 1U)) {
        last_error_ = "restore failed: 0x6203 unreadable or invalid";
        setErr(error_out, last_error_);
        return false;
    }

    if (!readable || cfg[0] != baseline_interface_) {
        if (!waitSettledSnapshot(active_slot_, now, false, config_.restore_settle_timeout_ms) ||
            !now.isIdle() ||
            now.uuid_payload != baseline_uuid_) {
            last_error_ = "restore refused: slot busy or UUID changed before 0x6203 restore";
            setErr(error_out, last_error_);
            return false;
        }
        if (!link_->setDataInterface(active_slot_, baseline_interface_, config_.dbus_timeout_ms)) {
            last_error_ = "restore failed: 0x6203 write not confirmed";
            setErr(error_out, last_error_);
            return false;
        }
    }

    if (!waitSettledSnapshot(active_slot_, now, false, config_.restore_settle_timeout_ms) ||
        !now.hasConsistentUuids() ||
        now.uuid_payload != baseline_uuid_) {
        last_error_ = "restore failed: baseline UUID not read back after restore";
        setErr(error_out, last_error_);
        return false;
    }
    if (readable &&
        (!link_->readConfiguration(active_slot_, kAlpsConfigDataInterface,
                                   cfg, config_.dbus_timeout_ms) ||
         cfg.size() != 1U || cfg[0] != baseline_interface_)) {
        last_error_ = "restore failed: baseline 0x6203 not read back after restore";
        setErr(error_out, last_error_);
        return false;
    }

    CARPLAY_LOG_INFO("alps", "restored borrowed slot %u to baseline UUID and 0x6203=%u",
                     static_cast<unsigned>(active_slot_),
                     static_cast<unsigned>(baseline_interface_));
    restore_succeeded_ = true;
    return true;
}

bool AlpsSppManager::stop(std::string* error_out) {
    if (advert_timer_id_ != Reactor::kNoTimer) {
        reactor_.cancelTimer(advert_timer_id_);
        advert_timer_id_ = Reactor::kNoTimer;
    }
    if (!started_) {
        link_->stop();
        reader_.close();
        return true;
    }

    const bool was_connected = connected_;
    connected_ = false;
    peer_addr_ = BtAddr::any();
    if (was_connected && listener_ != NULL) {
        listener_->onAlpsManagerDisconnected("stopped");
    }

    bool ok = true;
    if (borrowed_) {
        ok = restoreBorrowedSlot(error_out);
    }

    link_->stop();
    reader_.close();
    started_ = false;
    borrowed_ = false;
    return ok;
}

void AlpsSppManager::disconnect(const std::string& reason) {
    if (!started_) {
        return;
    }
    link_->requestSppDisconnect();
    link_->disconnectLink(reason);
}

bool AlpsSppManager::sendData(const uint8_t* data, size_t len) {
    if (!started_ || !connected_) {
        return false;
    }
    return link_->sendData(data, len);
}

bool AlpsSppManager::readBmwAppsSlot(AppsSlot& out) {
    if (!started_ || !reader_.isOpen()) {
        out = AppsSlot();
        return false;
    }
    return ::carplay::platform::readBmwAppsSlot(reader_, out);
}

void AlpsSppManager::handleLinkConnected(const BtAddr& peer) {
    if (!started_) {
        return;
    }
    connected_ = true;
    peer_addr_ = peer;
    if (listener_ != NULL) {
        listener_->onAlpsManagerConnected(peer);
    }
}

void AlpsSppManager::handleLinkData(const uint8_t* data, size_t len) {
    if (!started_ || !connected_) {
        return;
    }
    if (listener_ != NULL) {
        listener_->onAlpsManagerData(data, len);
    }
}

void AlpsSppManager::handleLinkDisconnected(const std::string& reason) {
    if (!connected_) {
        return;
    }
    connected_ = false;
    peer_addr_ = BtAddr::any();
    if (listener_ != NULL) {
        listener_->onAlpsManagerDisconnected(reason);
    }
}

void AlpsSppManager::handleLinkFatalError(const std::string& reason) {
    last_error_ = reason;
    if (connected_) {
        connected_ = false;
        peer_addr_ = BtAddr::any();
        if (listener_ != NULL) {
            listener_->onAlpsManagerDisconnected(reason);
        }
    }
}

void AlpsSppManager::handleAdvertTimer(uint32_t timer_id) {
    if (timer_id != advert_timer_id_ || !started_ || !borrowed_ || link_->isLinkUp()) {
        return;
    }
    const int64_t now_ns = reactor_.now();
    if (now_ns < advert_start_ns_) {
        return;
    }
    const uint32_t elapsed_ms = static_cast<uint32_t>((now_ns - advert_start_ns_) / 1000000LL);
    if (!advert_schedule_.due(elapsed_ms)) {
        return;
    }

    SppSlotSnapshot current;
    if (!reader_.read(active_slot_, current, false)) {
        CARPLAY_LOG_DEBUG("alps", "advertisement refresh skipped: snapshot unreadable or changing");
        return;
    }
    if (!current.hasConsistentUuids() ||
        current.uuid_payload != config_.slot_policy.target_uuid_pair) {
        CARPLAY_LOG_WARN("alps", "CarPlay UUID pair changed unexpectedly on slot %u; stopping",
                         static_cast<unsigned>(active_slot_));
        last_error_ = "CarPlay UUID pair changed during advertisement";
        stop();
        return;
    }
    if (!current.isIdle() || link_->isLinkUp()) {
        return;
    }
    const int rc = link_->registerUuidPayload(
        config_.slot_policy.target_uuid_pair, config_.uuid_timeout_ms);
    if (rc != 0) {
        if (link_->isLinkUp()) {
            return;
        }
        CARPLAY_LOG_WARN("alps", "advertisement refresh failed (status=%d); stopping and restoring", rc);
        last_error_ = "UUID advertisement refresh failed";
        stop();
        return;
    }
    CARPLAY_LOG_DEBUG("alps", "refreshed CarPlay UUID advertisement on idle slot %u",
                      static_cast<unsigned>(active_slot_));
}

}  // namespace platform
}  // namespace carplay
