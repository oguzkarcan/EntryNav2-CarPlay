#include "carplay/platform/mdns_advertiser.hpp"

#include <stdio.h>
#include <string.h>

#include <sstream>

#include "carplay/platform/log.hpp"

#ifndef _WIN32
#include <dlfcn.h>
#include <net/if.h>
#endif

namespace carplay {
namespace platform {

namespace {

const char* const kTag = "mdns";
std::string g_test_lib_primary;
std::string g_test_lib_fallback;

void setError(std::string* err, const std::string& msg) {
    if (err != NULL) {
        *err = msg;
    }
}

uint16_t hostToNetworkU16(uint16_t value) {
    uint8_t be[2];
    be[0] = static_cast<uint8_t>((value >> 8) & 0xffU);
    be[1] = static_cast<uint8_t>(value & 0xffU);
    uint16_t net_val = 0U;
    memcpy(&net_val, be, sizeof(net_val));
    return net_val;
}

#ifndef _WIN32
template <typename Fn>
bool resolveOptionalSymbol(void* lib, const char* name, Fn& fn) {
    if (sizeof(Fn) != sizeof(void*)) {
        fn = NULL;
        return false;
    }
    void* p = dlsym(lib, name);
    if (p == NULL) {
        fn = NULL;
        return false;
    }
    memcpy(&fn, &p, sizeof(p));
    return true;
}
#endif

}  // namespace

const char* mdnsBackendName(MdnsBackend backend) {
    switch (backend) {
        case kMdnsBackendUninitialized:
            return "uninitialized";
        case kMdnsBackendDnsSd:
            return "dns_sd";
        case kMdnsBackendUnavailable:
            return "unavailable";
    }
    return "unknown";
}

MdnsAdvertiser::MdnsAdvertiser(Reactor& reactor)
    : reactor_(reactor),
      listener_(NULL),
      lib_(NULL),
      backend_(kMdnsBackendUninitialized),
      has_override_(false),
      sd_ref_(NULL),
      fd_(kInvalidSocket),
      registered_(false),
      conflict_attempt_(0),
      pending_conflict_(false),
      pending_reply_error_(kDnsServiceErrNoError),
      alive_state_(new AliveState()) {}

MdnsAdvertiser::~MdnsAdvertiser() {
    if (alive_state_ != NULL) {
        alive_state_->alive = false;
    }
    listener_ = NULL;
    stop();
    unload();
    if (alive_state_ != NULL) {
        if (--alive_state_->refs == 0) {
            delete alive_state_;
        }
        alive_state_ = NULL;
    }
}

void MdnsAdvertiser::setApiOverride(const DnsSdApi* api) {
    if (isActive()) {
        stop();
    }
    unload();
    if (api == NULL) {
        has_override_ = false;
        override_api_ = DnsSdApi();
    } else {
        has_override_ = true;
        override_api_ = *api;
    }
}

bool MdnsAdvertiser::load(std::string* error_out) {
    last_error_.clear();
    if (backend_ == kMdnsBackendDnsSd && api_.complete()) {
        return true;
    }

    unload();

    if (has_override_) {
        if (!override_api_.complete()) {
            backend_ = kMdnsBackendUnavailable;
            last_error_ = "incomplete dns_sd API override";
            setError(error_out, last_error_);
            return false;
        }
        api_ = override_api_;
        backend_ = kMdnsBackendDnsSd;
        loaded_library_ = "<override>";
        return true;
    }

#ifdef _WIN32
    backend_ = kMdnsBackendUnavailable;
    last_error_ = "Apple dns_sd runtime library is unavailable on Windows";
    setError(error_out, last_error_);
    return false;
#else
    const char* candidates[2];
    candidates[0] = !g_test_lib_primary.empty() ? g_test_lib_primary.c_str() : "libdns_sd.so.1";
    candidates[1] = !g_test_lib_fallback.empty() ? g_test_lib_fallback.c_str() : "libdns_sd.so";
    std::string dl_errors;
    for (size_t i = 0U; i < 2U; ++i) {
        if (candidates[i] == NULL || candidates[i][0] == '\0') {
            continue;
        }
        void* handle = dlopen(candidates[i], RTLD_NOW | RTLD_LOCAL);
        if (handle != NULL) {
            lib_ = handle;
            loaded_library_ = candidates[i];
            break;
        }
        const char* why = dlerror();
        if (!dl_errors.empty()) {
            dl_errors += "; ";
        }
        dl_errors += std::string(candidates[i]) + ": " + (why != NULL ? why : "dlopen failed");
    }

    if (lib_ == NULL) {
        backend_ = kMdnsBackendUnavailable;
        last_error_ = "mDNS dns_sd backend unavailable (" + dl_errors + ")";
        setError(error_out, last_error_);
        return false;
    }

    bool ok = true;
    ok &= resolveOptionalSymbol(lib_, "DNSServiceRegister", api_.register_service);
    ok &= resolveOptionalSymbol(lib_, "DNSServiceRefSockFD", api_.ref_sock_fd);
    ok &= resolveOptionalSymbol(lib_, "DNSServiceProcessResult", api_.process_result);
    ok &= resolveOptionalSymbol(lib_, "DNSServiceRefDeallocate", api_.ref_deallocate);
    resolveOptionalSymbol(lib_, "DNSServiceUpdateRecord", api_.update_record);  // optional

    if (!ok || !api_.complete()) {
        dlclose(lib_);
        lib_ = NULL;
        api_ = DnsSdApi();
        loaded_library_.clear();
        backend_ = kMdnsBackendUnavailable;
        last_error_ = "dns_sd library missing required DNSService* symbols";
        setError(error_out, last_error_);
        return false;
    }

    backend_ = kMdnsBackendDnsSd;
    CARPLAY_LOG_INFO(kTag, "loaded mDNS backend from %s", loaded_library_.c_str());
    return true;
#endif
}

void MdnsAdvertiser::unload() {
    if (isActive()) {
        stop();
    }
    api_ = DnsSdApi();
    loaded_library_.clear();
#ifndef _WIN32
    if (lib_ != NULL) {
        dlclose(lib_);
        lib_ = NULL;
    }
#endif
    backend_ = kMdnsBackendUninitialized;
}

bool MdnsAdvertiser::resolveInterfaceIndex(const MdnsServiceConfig& cfg,
                                           uint32_t& index_out,
                                           std::string* error_out) const {
    if (cfg.interface_index != kDnsServiceInterfaceIndexAny) {
        index_out = cfg.interface_index;
        return true;
    }
    if (cfg.interface_name.empty()) {
        index_out = kDnsServiceInterfaceIndexAny;
        return true;
    }
#ifdef _WIN32
    setError(error_out, "interface_name resolution is not supported on Windows");
    return false;
#else
    const unsigned int idx = if_nametoindex(cfg.interface_name.c_str());
    if (idx == 0U) {
        setError(error_out, "unknown network interface for mDNS: " + cfg.interface_name);
        return false;
    }
    index_out = static_cast<uint32_t>(idx);
    return true;
#endif
}

bool MdnsAdvertiser::start(const MdnsServiceConfig& cfg, std::string* error_out) {
    if (isActive()) {
        stop();
    }
    if (cfg.regtype.empty()) {
        last_error_ = "mDNS service regtype must not be empty";
        setError(error_out, last_error_);
        return false;
    }
    if (cfg.port == 0U) {
        last_error_ = "mDNS service port must be non-zero";
        setError(error_out, last_error_);
        return false;
    }
    if (cfg.txt_record.size() > 65535U) {
        last_error_ = "mDNS TXT record exceeds 65535 bytes";
        setError(error_out, last_error_);
        return false;
    }
    if (!load(error_out)) {
        return false;
    }

    config_ = cfg;
    requested_base_name_ = cfg.service_name;
    assigned_name_.clear();
    conflict_attempt_ = 0;
    pending_conflict_ = false;
    pending_reply_error_ = kDnsServiceErrNoError;
    registered_ = false;

    return registerCandidate(cfg.service_name, error_out);
}

bool MdnsAdvertiser::registerCandidate(const std::string& candidate_name,
                                       std::string* error_out) {
    uint32_t iface_idx = kDnsServiceInterfaceIndexAny;
    if (!resolveInterfaceIndex(config_, iface_idx, error_out)) {
        last_error_ = error_out != NULL ? *error_out : "invalid mDNS interface";
        return false;
    }

    const DnsServiceFlags flags = config_.allow_auto_rename ? 0U : kDnsServiceFlagsNoAutoRename;
    const char* name_cstr = candidate_name.empty() ? NULL : candidate_name.c_str();
    const char* domain_cstr = config_.domain.empty() ? NULL : config_.domain.c_str();
    const char* host_cstr = config_.host.empty() ? NULL : config_.host.c_str();
    const uint16_t txt_len = static_cast<uint16_t>(config_.txt_record.size());
    const void* txt_ptr = config_.txt_record.empty() ? NULL : &config_.txt_record[0];

    DnsServiceRef ref = NULL;
    const DnsServiceErrorType rc = api_.register_service(
        &ref, flags, iface_idx, name_cstr, config_.regtype.c_str(), domain_cstr, host_cstr,
        hostToNetworkU16(config_.port), txt_len, txt_ptr, &MdnsAdvertiser::onRegisterReplyStatic,
        this);
    if (rc != kDnsServiceErrNoError || ref == NULL) {
        std::ostringstream oss;
        oss << "DNSServiceRegister failed (err=" << rc << ")";
        last_error_ = oss.str();
        setError(error_out, last_error_);
        if (ref != NULL) {
            api_.ref_deallocate(ref);
        }
        return false;
    }

    const int raw_fd = api_.ref_sock_fd(ref);
    if (raw_fd < 0) {
        api_.ref_deallocate(ref);
        last_error_ = "DNSServiceRefSockFD returned invalid descriptor";
        setError(error_out, last_error_);
        return false;
    }

    const SocketHandle sock_fd = static_cast<SocketHandle>(raw_fd);
    if (!reactor_.add(sock_fd, this, kPollIn)) {
        api_.ref_deallocate(ref);
        last_error_ = "failed to register mDNS fd in Reactor";
        setError(error_out, last_error_);
        return false;
    }

    sd_ref_ = ref;
    fd_ = sock_fd;
    current_candidate_name_ = candidate_name;
    pending_conflict_ = false;
    pending_reply_error_ = kDnsServiceErrNoError;
    CARPLAY_LOG_INFO(kTag, "registering mDNS %s on port %u (name=\"%s\", iface=%u)",
                     config_.regtype.c_str(), static_cast<unsigned int>(config_.port),
                     candidate_name.empty() ? "<auto>" : candidate_name.c_str(),
                     static_cast<unsigned int>(iface_idx));
    return true;
}

bool MdnsAdvertiser::updateTxtRecord(const std::vector<uint8_t>& txt_record,
                                     std::string* error_out) {
    if (!isActive()) {
        setError(error_out, "mDNS service is not active");
        return false;
    }
    if (txt_record.size() > 65535U) {
        setError(error_out, "mDNS TXT record exceeds 65535 bytes");
        return false;
    }

    const uint16_t txt_len = static_cast<uint16_t>(txt_record.size());
    const void* txt_ptr = txt_record.empty() ? NULL : &txt_record[0];

    if (api_.update_record != NULL) {
        const DnsServiceErrorType rc =
            api_.update_record(sd_ref_, NULL, 0U, txt_len, txt_ptr, 0U);
        if (rc != kDnsServiceErrNoError) {
            std::ostringstream oss;
            oss << "DNSServiceUpdateRecord failed (err=" << rc << ")";
            last_error_ = oss.str();
            setError(error_out, last_error_);
            return false;
        }
        config_.txt_record = txt_record;
        return true;
    }

    // Fallback when DNSServiceUpdateRecord is absent: re-register with updated TXT.
    const std::string keep_name =
        !assigned_name_.empty() ? assigned_name_ : current_candidate_name_;
    config_.txt_record = txt_record;
    teardownRegistration();
    registered_ = false;
    return registerCandidate(keep_name, error_out);
}

void MdnsAdvertiser::teardownRegistration() {
    if (fd_ != kInvalidSocket) {
        reactor_.remove(fd_);
        fd_ = kInvalidSocket;
    }
    if (sd_ref_ != NULL) {
        if (api_.ref_deallocate != NULL) {
            api_.ref_deallocate(sd_ref_);
        }
        sd_ref_ = NULL;
    }
}

void MdnsAdvertiser::stop() {
    const bool was_active = isActive();
    teardownRegistration();
    registered_ = false;
    pending_conflict_ = false;
    pending_reply_error_ = kDnsServiceErrNoError;
    if (was_active && listener_ != NULL) {
        AliveGuard guard(alive_state_);
        listener_->onMdnsStopped();
        if (!guard.alive()) {
            return;
        }
    }
}

void MdnsAdvertiser::onRegisterReplyStatic(DnsServiceRef sdRef,
                                           DnsServiceFlags flags,
                                           DnsServiceErrorType errorCode,
                                           const char* name,
                                           const char* regtype,
                                           const char* domain,
                                           void* context) {
    MdnsAdvertiser* self = static_cast<MdnsAdvertiser*>(context);
    if (self != NULL) {
        self->onRegisterReply(sdRef, flags, errorCode, name, regtype, domain);
    }
}

void MdnsAdvertiser::onRegisterReply(DnsServiceRef sdRef,
                                     DnsServiceFlags flags,
                                     DnsServiceErrorType errorCode,
                                     const char* name,
                                     const char* regtype,
                                     const char* domain) {
    (void)flags;
    if (sdRef != sd_ref_) {
        return;
    }

    if (errorCode == kDnsServiceErrNameConflict) {
        CARPLAY_LOG_WARN(kTag, "mDNS name conflict for \"%s\"",
                         current_candidate_name_.c_str());
        pending_conflict_ = true;
        return;
    }

    if (errorCode != kDnsServiceErrNoError) {
        pending_reply_error_ = errorCode;
        return;
    }

    registered_ = true;
    const std::string prev_name = assigned_name_;
    assigned_name_ = (name != NULL && name[0] != '\0') ? name : current_candidate_name_;
    const std::string regtype_str = (regtype != NULL && regtype[0] != '\0') ? regtype : config_.regtype;
    const std::string domain_str =
        (domain != NULL && domain[0] != '\0') ? domain : dnssd::kAirPlayDefaultDomain;

    CARPLAY_LOG_INFO(kTag, "mDNS registered \"%s.%s%s\"",
                     assigned_name_.c_str(), regtype_str.c_str(), domain_str.c_str());

    if (listener_ != NULL) {
        AliveGuard guard(alive_state_);
        listener_->onMdnsRegistered(assigned_name_, regtype_str, domain_str);
        if (!guard.alive()) {
            return;
        }
        if (!prev_name.empty() && prev_name != assigned_name_) {
            listener_->onMdnsNameConflictRenamed(prev_name, assigned_name_);
        } else if (prev_name.empty() && !requested_base_name_.empty() &&
                   assigned_name_ != requested_base_name_) {
            listener_->onMdnsNameConflictRenamed(requested_base_name_, assigned_name_);
        }
    }
}

void MdnsAdvertiser::onReadable() {
    if (!isActive() || api_.process_result == NULL) {
        return;
    }

    AliveGuard guard(alive_state_);

    pending_conflict_ = false;
    pending_reply_error_ = kDnsServiceErrNoError;
    const DnsServiceErrorType proc_err = api_.process_result(sd_ref_);
    if (!guard.alive()) {
        return;
    }

    if (pending_conflict_) {
        pending_conflict_ = false;
        teardownRegistration();
        registered_ = false;
        ++conflict_attempt_;
        if (conflict_attempt_ <= config_.max_conflict_retries) {
            const std::string base =
                requested_base_name_.empty() ? std::string("CarPlay") : requested_base_name_;
            std::ostringstream oss;
            oss << base << " (" << (conflict_attempt_ + 1) << ")";
            const std::string next_name = oss.str();
            std::string reg_err;
            if (!registerCandidate(next_name, &reg_err)) {
                if (listener_ != NULL) {
                    listener_->onMdnsError(kDnsServiceErrNameConflict, reg_err);
                }
            }
        } else {
            last_error_ = "exceeded maximum mDNS name conflict retries";
            if (listener_ != NULL) {
                listener_->onMdnsError(kDnsServiceErrNameConflict, last_error_);
            }
        }
        return;
    }

    if (pending_reply_error_ != kDnsServiceErrNoError) {
        const DnsServiceErrorType err_code = pending_reply_error_;
        std::ostringstream oss;
        oss << "DNSServiceRegister callback error (" << err_code << ")";
        last_error_ = oss.str();
        teardownRegistration();
        registered_ = false;
        if (listener_ != NULL) {
            listener_->onMdnsError(err_code, last_error_);
        }
        return;
    }

    if (proc_err != kDnsServiceErrNoError) {
        std::ostringstream oss;
        oss << "DNSServiceProcessResult failed (err=" << proc_err << ")";
        last_error_ = oss.str();
        teardownRegistration();
        registered_ = false;
        if (listener_ != NULL) {
            listener_->onMdnsError(proc_err, last_error_);
        }
    }
}

void MdnsAdvertiser::onError() {
    last_error_ = "mDNS control socket error";
    CARPLAY_LOG_WARN(kTag, "%s", last_error_.c_str());
    teardownRegistration();
    registered_ = false;

    AliveGuard guard(alive_state_);
    if (listener_ != NULL) {
        listener_->onMdnsError(kDnsServiceErrServiceNotRunning, last_error_);
    }
    if (!guard.alive()) {
        return;
    }
}

void setMdnsLibraryPathsForTest(const char* primary_path, const char* fallback_path) {
    g_test_lib_primary = primary_path != NULL ? primary_path : "";
    g_test_lib_fallback = fallback_path != NULL ? fallback_path : "";
}

}  // namespace platform
}  // namespace carplay
