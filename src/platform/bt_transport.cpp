#include "carplay/platform/bt_transport.hpp"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <fstream>

#ifndef _WIN32
#include <dirent.h>
#endif

#include "carplay/platform/log.hpp"

namespace carplay {
namespace platform {

namespace {

bool probeAlpsLibraryInProc(const std::string& proc_root, std::string& detail_out) {
#ifdef _WIN32
    (void)proc_root;
    detail_out = "windows";
    return false;
#else
    if (proc_root.empty()) {
        detail_out = "empty_proc";
        return false;
    }
    DIR* proc = ::opendir(proc_root.c_str());
    if (proc == NULL) {
        detail_out = "proc_unreadable";
        return false;
    }

    unsigned matches = 0U;
    std::string rejected;
    struct dirent* item = NULL;
    while ((item = ::readdir(proc)) != NULL) {
        if (item->d_name[0] == '\0') {
            continue;
        }
        char* end = NULL;
        const long pid = strtol(item->d_name, &end, 10);
        if (end == NULL || *end != '\0' || pid <= 0 || pid > INT_MAX) {
            continue;
        }
        const std::string prefix = proc_root + "/" + item->d_name;
        std::ifstream maps((prefix + "/maps").c_str());
        std::string line;
        while (std::getline(maps, line)) {
            unsigned long begin = 0;
            unsigned long finish = 0;
            unsigned long offset = 0;
            unsigned long inode = 0;
            unsigned major = 0;
            unsigned minor = 0;
            char perms[8];
            int used = 0;
            if (sscanf(line.c_str(), "%lx-%lx %4s %lx %x:%x %lu %n",
                       &begin, &finish, perms, &offset, &major, &minor, &inode, &used) != 7 ||
                offset != 0 || used <= 0 || static_cast<size_t>(used) >= line.size()) {
                continue;
            }
            const std::string map_path = line.substr(static_cast<size_t>(used));
            const size_t slash = map_path.rfind('/');
            if (slash == std::string::npos ||
                map_path.substr(slash + 1U) != kAlpsLibraryFilename ||
                begin > 0xffffffffUL) {
                continue;
            }
            SppLayout layout;
            std::string why;
            if (!extractSppLayoutFromFile(prefix + "/root" + map_path, layout, &why)) {
                rejected = why;
                continue;
            }
            ++matches;
        }
    }
    ::closedir(proc);

    if (matches == 1U) {
        detail_out = "found";
        return true;
    }
    if (matches > 1U) {
        detail_out = "multiple_matches";
        return false;
    }
    detail_out = rejected.empty() ? "absent" : rejected;
    return false;
#endif
}

}  // namespace

const char* btBackendKindName(BtBackendKind kind) {
    switch (kind) {
        case kBtBackendNone: return "none";
        case kBtBackendAlpsSpp: return "alps-spp";
        case kBtBackendRfcomm: return "bluez-rfcomm";
    }
    return "unknown";
}

// ------------------------------------------------------------------------------------------------
// AlpsBtTransport
// ------------------------------------------------------------------------------------------------

AlpsBtTransport::AlpsBtTransport(Reactor& reactor,
                                 BtTransportListener& listener,
                                 const AlpsSppManagerConfig& config,
                                 SppMemoryBackend* mem_backend,
                                 AlpsSppLink* link_override)
    : listener_(&listener),
      adapter_(this),
      manager_(reactor, adapter_, config, mem_backend, link_override) {}

AlpsBtTransport::~AlpsBtTransport() {
    listener_ = NULL;
    stop();
}

bool AlpsBtTransport::start(std::string* error_out) {
    return manager_.start(error_out);
}

void AlpsBtTransport::stop() {
    manager_.stop();
}

void AlpsBtTransport::disconnect(const std::string& reason) {
    manager_.disconnect(reason);
}

bool AlpsBtTransport::sendBytes(const uint8_t* data, size_t len) {
    return manager_.sendData(data, len);
}

// ------------------------------------------------------------------------------------------------
// RfcommBtTransport
// ------------------------------------------------------------------------------------------------

RfcommBtTransport::RfcommBtTransport(Reactor& reactor,
                                     BtTransportListener& listener,
                                     const RfcommBtTransportConfig& config,
                                     BtSocketOps* socket_ops,
                                     std::unique_ptr<sdp::SdpRegistrar> sdp_registrar)
    : listener_(&listener),
      config_(config),
      adapter_(this),
      server_(reactor, adapter_, config.rfcomm, socket_ops),
      sdp_registrar_(std::move(sdp_registrar)),
      sdp_registered_(false),
      sdp_handle_(0U) {}

RfcommBtTransport::~RfcommBtTransport() {
    listener_ = NULL;
    stop();
}

bool RfcommBtTransport::start(std::string* error_out) {
    stop();
    if (!server_.start(error_out)) {
        return false;
    }
    if (sdp_registrar_ != NULL && sdp_registrar_->isSupported()) {
        sdp::Iap2SdpConfig sdp_cfg = config_.sdp;
        sdp_cfg.rfcomm_channel = server_.boundChannel();
        sdp::ServiceRecord rec;
        std::vector<uint8_t> encoded;
        std::string sdp_err;
        if (!sdp::buildIap2SdpRecord(sdp_cfg, rec, &sdp_err) ||
            !rec.encode(encoded, &sdp_err) ||
            !sdp_registrar_->registerRecord(encoded, sdp_handle_)) {
            const std::string msg = "SDP registration failed: " +
                (!sdp_err.empty() ? sdp_err : sdp_registrar_->lastError());
            if (config_.require_sdp_registration) {
                if (error_out != NULL) {
                    *error_out = msg;
                }
                CARPLAY_LOG_ERROR("bt", "%s", msg.c_str());
                server_.stop();
                return false;
            }
            CARPLAY_LOG_WARN("bt", "%s", msg.c_str());
        } else {
            sdp_registered_ = true;
        }
    }
    return true;
}

void RfcommBtTransport::stop() {
    if (sdp_registered_ && sdp_registrar_ != NULL) {
        sdp_registrar_->unregisterRecord(sdp_handle_);
    }
    sdp_registered_ = false;
    sdp_handle_ = 0U;
    server_.stop();
}

void RfcommBtTransport::disconnect(const std::string& reason) {
    server_.disconnect(reason);
}

bool RfcommBtTransport::sendBytes(const uint8_t* data, size_t len) {
    return server_.send(data, len) == BtRfcommServer::kSendOk;
}

// ------------------------------------------------------------------------------------------------
// Runtime Capability Probe & Backend Selection
// ------------------------------------------------------------------------------------------------

BtTransportCapability probeBtTransportCapability() {
    return probeBtTransportCapability(BtTransportProbePaths());
}

BtTransportCapability probeBtTransportCapability(const BtTransportProbePaths& paths) {
    BtTransportCapability cap;
    cap.rfcomm = probeBtCapability(paths.rfcomm_paths);
    cap.alps_library_present = probeAlpsLibraryInProc(paths.proc_root, cap.alps_detail);
    cap.alps_dbus_ready = cap.rfcomm.alpsDbusCapable();
    if (cap.alps_library_present && cap.alps_dbus_ready && paths.probe_alps_dbus) {
        std::string owner;
        cap.alps_service_owned = probeAlpsDbusService(500, &owner);
        if (!cap.alps_service_owned) {
            cap.alps_dbus_ready = false;
            cap.alps_detail = "dbus_service_missing";
        }
    }
    return cap;
}

BtBackendKind selectBtBackend(const BtTransportCapability& cap) {
    if (cap.alpsCapable()) {
        return kBtBackendAlpsSpp;
    }
    if (cap.rfcommCapable()) {
        return kBtBackendRfcomm;
    }
    return kBtBackendNone;
}

std::string formatBtTransportCapability(const BtTransportCapability& cap) {
    const BtBackendKind selected = selectBtBackend(cap);
    return std::string("selected=") + btBackendKindName(selected) +
           " alps_lib=" + (cap.alps_library_present ? "yes" : "no") +
           " alps_dbus=" + (cap.alps_dbus_ready ? "yes" : "no") +
           " alps_detail=" + (cap.alps_detail.empty() ? "none" : cap.alps_detail) +
           " " + formatBtCapability(cap.rfcomm);
}

void logBtTransportCapability(const BtTransportCapability& cap) {
    CARPLAY_LOG_INFO("bt", "transport capability: %s", formatBtTransportCapability(cap).c_str());
}

std::unique_ptr<BtTransport> createBtTransport(Reactor& reactor,
                                             BtTransportListener& listener,
                                             const BtTransportCapability& cap,
                                             const AlpsSppManagerConfig& alps_config,
                                             const RfcommBtTransportConfig& rfcomm_config,
                                             const std::string& sdp_socket_path) {
    switch (selectBtBackend(cap)) {
        case kBtBackendAlpsSpp:
            return std::unique_ptr<BtTransport>(
                new AlpsBtTransport(reactor, listener, alps_config));
        case kBtBackendRfcomm:
            return std::unique_ptr<BtTransport>(
                new RfcommBtTransport(
                    reactor,
                    listener,
                    rfcomm_config,
                    NULL,
                    createBtSdpRegistrar(cap.rfcomm, sdp_socket_path)));
        case kBtBackendNone:
            break;
    }
    return std::unique_ptr<BtTransport>();
}

}  // namespace platform
}  // namespace carplay
