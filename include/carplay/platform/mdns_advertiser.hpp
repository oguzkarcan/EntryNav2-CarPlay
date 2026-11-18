#ifndef CARPLAY_PLATFORM_MDNS_ADVERTISER_HPP
#define CARPLAY_PLATFORM_MDNS_ADVERTISER_HPP

// Reactor-integrated mDNS / DNS-SD service advertiser (`_airplay._tcp` for Wireless CarPlay).
//
// Zero link-time dependency on Bonjour / mDNSResponder:
//   * Backend A ("dns_sd"): runtime `dlopen()` of `libdns_sd.so.1` then `libdns_sd.so`,
//     resolving `DNSServiceRegister`, `DNSServiceRefSockFD`, `DNSServiceProcessResult`,
//     `DNSServiceRefDeallocate` (plus optional `DNSServiceUpdateRecord`). The underlying fd is
//     registered on the single-threaded `Reactor` (`kPollIn`).
//   * Backend B ("unavailable"): reported cleanly when neither library (nor test override) is
//     available on the host/target.
//
// `MdnsAdvertiser` never closes the `DNSServiceRefSockFD` descriptor directly; it removes the fd
// from `Reactor` and lets `DNSServiceRefDeallocate` close it.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/dnssd_txt.hpp"
#include "carplay/platform/reactor.hpp"

struct carplay_DNSServiceRef_t;

namespace carplay {
namespace platform {

typedef struct carplay_DNSServiceRef_t* DnsServiceRef;
typedef uint32_t DnsServiceFlags;
typedef int32_t DnsServiceErrorType;

static const DnsServiceErrorType kDnsServiceErrNoError = 0;
static const DnsServiceErrorType kDnsServiceErrUnknown = -65537;
static const DnsServiceErrorType kDnsServiceErrNameConflict = -65548;
static const DnsServiceErrorType kDnsServiceErrServiceNotRunning = -65563;

static const DnsServiceFlags kDnsServiceFlagsAdd = 0x2U;
static const DnsServiceFlags kDnsServiceFlagsNoAutoRename = 0x8U;
static const uint32_t kDnsServiceInterfaceIndexAny = 0U;

typedef void (*DnsServiceRegisterReplyFn)(DnsServiceRef sdRef,
                                          DnsServiceFlags flags,
                                          DnsServiceErrorType errorCode,
                                          const char* name,
                                          const char* regtype,
                                          const char* domain,
                                          void* context);

/// Hand-written ABI table matching Apple mDNSResponder `dns_sd.h` (POSIX C ABI).
/// Note: `port_be` passed to `register_service` is in network byte order (big-endian).
struct DnsSdApi {
    DnsServiceErrorType (*register_service)(DnsServiceRef* sdRef,
                                            DnsServiceFlags flags,
                                            uint32_t interfaceIndex,
                                            const char* name,
                                            const char* regtype,
                                            const char* domain,
                                            const char* host,
                                            uint16_t port_be,
                                            uint16_t txtLen,
                                            const void* txtRecord,
                                            DnsServiceRegisterReplyFn callBack,
                                            void* context);
    int (*ref_sock_fd)(DnsServiceRef sdRef);
    DnsServiceErrorType (*process_result)(DnsServiceRef sdRef);
    void (*ref_deallocate)(DnsServiceRef sdRef);
    /// Optional: NULL falls back to re-registering when updating TXT records.
    DnsServiceErrorType (*update_record)(DnsServiceRef sdRef,
                                         void* recordRef,
                                         DnsServiceFlags flags,
                                         uint16_t rdlen,
                                         const void* rdata,
                                         uint32_t ttl);

    DnsSdApi()
        : register_service(NULL),
          ref_sock_fd(NULL),
          process_result(NULL),
          ref_deallocate(NULL),
          update_record(NULL) {}

    bool complete() const {
        return register_service != NULL && ref_sock_fd != NULL &&
               process_result != NULL && ref_deallocate != NULL;
    }
};

enum MdnsBackend {
    kMdnsBackendUninitialized = 0,
    kMdnsBackendDnsSd = 1,
    kMdnsBackendUnavailable = 2
};

const char* mdnsBackendName(MdnsBackend backend);

struct MdnsServiceConfig {
    std::string service_name;    // empty -> mdnsd default host name
    std::string regtype;         // default "_airplay._tcp"
    std::string domain;          // empty -> mdnsd default ("local.")
    std::string host;            // empty -> mdnsd default host
    std::string interface_name;  // optional; resolved via if_nametoindex when interface_index == 0
    uint32_t interface_index;    // 0 = any interface
    uint16_t port;               // host byte order (default 7000)
    std::vector<uint8_t> txt_record;
    bool allow_auto_rename;
    int max_conflict_retries;

    MdnsServiceConfig()
        : regtype(dnssd::kAirPlayServiceType),
          interface_index(kDnsServiceInterfaceIndexAny),
          port(dnssd::kAirPlayDefaultPort),
          allow_auto_rename(true),
          max_conflict_retries(8) {}
};

class MdnsAdvertiserListener {
public:
    virtual ~MdnsAdvertiserListener() {}
    virtual void onMdnsRegistered(const std::string& assigned_name,
                                  const std::string& regtype,
                                  const std::string& domain) = 0;
    virtual void onMdnsNameConflictRenamed(const std::string& old_name,
                                           const std::string& new_name) = 0;
    virtual void onMdnsError(DnsServiceErrorType code, const std::string& message) = 0;
    virtual void onMdnsStopped() = 0;
};

/// Ownership and lifetime: `reactor` and any non-NULL `MdnsAdvertiserListener*` must outlive
/// `MdnsAdvertiser` (or the listener must be cleared via `setListener(NULL)` before destruction).
/// `~MdnsAdvertiser()` detaches the listener before tearing down active registrations.
class MdnsAdvertiser : private IoHandler {
public:
    explicit MdnsAdvertiser(Reactor& reactor);
    virtual ~MdnsAdvertiser();

    void setListener(MdnsAdvertiserListener* listener) { listener_ = listener; }

    /// Injects an in-memory dns_sd table for tests (NULL clears override). Must be stopped.
    void setApiOverride(const DnsSdApi* api);

    /// Probes and loads `libdns_sd.so.1` / `libdns_sd.so` (or uses the test override).
    /// Returns true if Backend A ("dns_sd") is ready; false with Backend B ("unavailable") otherwise.
    bool load(std::string* error_out = NULL);
    void unload();

    MdnsBackend backend() const { return backend_; }
    const char* backendName() const { return mdnsBackendName(backend_); }
    bool available() const { return backend_ == kMdnsBackendDnsSd; }

    bool start(const MdnsServiceConfig& cfg, std::string* error_out = NULL);
    bool updateTxtRecord(const std::vector<uint8_t>& txt_record, std::string* error_out = NULL);
    void stop();

    bool isActive() const { return sd_ref_ != NULL; }
    bool isRegistered() const { return registered_; }
    const std::string& assignedName() const { return assigned_name_; }
    const std::string& requestedName() const { return requested_base_name_; }
    const std::string& loadedLibrary() const { return loaded_library_; }
    const std::string& lastError() const { return last_error_; }
    int conflictRetryCount() const { return conflict_attempt_; }

private:
    MdnsAdvertiser(const MdnsAdvertiser&) = delete;
    MdnsAdvertiser& operator=(const MdnsAdvertiser&) = delete;

    virtual void onReadable();
    virtual void onError();

    static void onRegisterReplyStatic(DnsServiceRef sdRef,
                                      DnsServiceFlags flags,
                                      DnsServiceErrorType errorCode,
                                      const char* name,
                                      const char* regtype,
                                      const char* domain,
                                      void* context);
    void onRegisterReply(DnsServiceRef sdRef,
                         DnsServiceFlags flags,
                         DnsServiceErrorType errorCode,
                         const char* name,
                         const char* regtype,
                         const char* domain);

    bool registerCandidate(const std::string& candidate_name, std::string* error_out);
    void teardownRegistration();
    bool resolveInterfaceIndex(const MdnsServiceConfig& cfg,
                               uint32_t& index_out,
                               std::string* error_out) const;

    Reactor& reactor_;
    MdnsAdvertiserListener* listener_;

    void* lib_;
    MdnsBackend backend_;
    bool has_override_;
    DnsSdApi override_api_;
    DnsSdApi api_;
    std::string loaded_library_;
    std::string last_error_;

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

    MdnsServiceConfig config_;
    DnsServiceRef sd_ref_;
    SocketHandle fd_;
    bool registered_;
    std::string requested_base_name_;
    std::string current_candidate_name_;
    std::string assigned_name_;
    int conflict_attempt_;
    bool pending_conflict_;
    DnsServiceErrorType pending_reply_error_;
    AliveState* alive_state_;
};

/// Host tests: override the two dlopen() candidate paths (NULL resets to defaults).
void setMdnsLibraryPathsForTest(const char* primary_path, const char* fallback_path);

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_MDNS_ADVERTISER_HPP
