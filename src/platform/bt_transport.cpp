// ALPS/UUID/SPP compatibility probe derived from EntryNav2-Android-Auto 0.13.0-rc.6
// tools/aa_supervisor.cpp, PolyForm Noncommercial License 1.0.0.

#include "carplay/platform/bt_transport.hpp"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <fstream>
#include <sstream>

#ifndef _WIN32
#include <dirent.h>
#endif

#include "carplay/platform/log.hpp"
#include "carplay/platform/wifi_link.hpp"

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

bool AlpsBtTransport::readBmwAppsSlot(AppsSlot& out) {
    return manager_.readBmwAppsSlot(out);
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

const char* compatStatusLevelName(CompatStatusLevel level) {
    switch (level) {
        case kCompatPass: return "pass";
        case kCompatWarn: return "warn";
        case kCompatInfo: return "info";
        case kCompatFail: return "fail";
        default: return "unknown";
    }
}

AlpsCompatReport probeAlpsSppCompat(const BtTransportCapability& cap,
                                    SppMemoryBackend* mem_backend,
                                    bool usb_mode,
                                    const CarPlaySlotPolicy& policy) {
    AlpsCompatReport rep;
    rep.usb_mode = usb_mode;
    const CompatStatusLevel bt_fail_level = usb_mode ? kCompatInfo : kCompatFail;

    bool snapshot_ok = false;
    bool slot_usable = false;
    if (!cap.alps_library_present) {
        const std::string why =
            cap.alps_detail.empty() ? std::string("libevo_btappl.so absent") : cap.alps_detail;
        rep.alps = CompatCheckResult("alps", bt_fail_level, why + " (wireless only)");
    } else {
        SppSnapshotReader reader(mem_backend);
        if (!reader.open()) {
            const std::string why =
                reader.error().empty() ? std::string("ALPS snapshot open failed") : reader.error();
            rep.alps = CompatCheckResult("alps", bt_fail_level, why + " (wireless only)");
        } else {
            snapshot_ok = true;
            const CarPlaySlotSelection sel = selectCarPlaySppSlot(reader, policy);
            slot_usable = sel.isUsable();
            std::ostringstream oss;
            oss << "pid=" << reader.pid() << " slot=" << static_cast<unsigned>(sel.slot)
                << " (" << carPlaySlotDecisionName(sel.decision) << ")";
            if (!sel.reason.empty()) {
                oss << ": " << sel.reason;
            }
            if (slot_usable) {
                SppSlotSnapshot slot0;
                CompatStatusLevel lvl = kCompatPass;
                if (reader.read(kAlpsBmwAppsSlot, slot0, true) && !slot0.isIdle()) {
                    oss << "; slot0_apps=" << (slot0.connected ? "connected" : "busy");
                    if (sel.decision == kSlotBorrow5) {
                        lvl = kCompatWarn;
                    }
                }
                rep.alps = CompatCheckResult("alps", lvl, oss.str());
            } else {
                rep.alps = CompatCheckResult("alps", bt_fail_level, oss.str() + " (wireless only)");
            }
        }
    }

    if (!isSupportedSppBaseline(policy.target_uuid_pair)) {
        rep.uuid = CompatCheckResult(
            "uuid",
            bt_fail_level,
            "target UUID payload is not a verified iAP2/generic baseline (wireless only)");
    } else if (!snapshot_ok) {
        rep.uuid = CompatCheckResult(
            "uuid",
            kCompatInfo,
            "skipped (ALPS snapshot unavailable; target iAP2 UUID valid, wireless only)");
    } else if (slot_usable) {
        rep.uuid = CompatCheckResult(
            "uuid", kCompatPass, "iAP2/CarPlay SPP UUID baseline and slot policy compatible");
    } else {
        rep.uuid = CompatCheckResult(
            "uuid", bt_fail_level, "no usable SPP slot for target iAP2 UUID (wireless only)");
    }

    if (cap.alps_dbus_ready) {
        rep.spp = CompatCheckResult(
            "spp", kCompatPass, "org.alps.evolution D-Bus + libdbus-1 ready");
    } else {
        const std::string why =
            cap.alps_detail.empty() ? std::string("ALPS D-Bus unavailable") : cap.alps_detail;
        rep.spp = CompatCheckResult("spp", bt_fail_level, why + " (wireless only)");
    }

    rep.wireless_ready = (rep.alps.level == kCompatPass || rep.alps.level == kCompatWarn) &&
                         (rep.uuid.level == kCompatPass || rep.uuid.level == kCompatWarn) &&
                         (rep.spp.level == kCompatPass || rep.spp.level == kCompatWarn);
    return rep;
}

std::string formatAlpsCompatReport(const AlpsCompatReport& report) {
    std::ostringstream oss;
    oss << "wireless_ready=" << (report.wireless_ready ? "yes" : "no")
        << " usb_mode=" << (report.usb_mode ? "yes" : "no")
        << " [" << report.alps.name << ":" << compatStatusLevelName(report.alps.level)
        << " " << report.alps.detail << "]"
        << " [" << report.uuid.name << ":" << compatStatusLevelName(report.uuid.level)
        << " " << report.uuid.detail << "]"
        << " [" << report.spp.name << ":" << compatStatusLevelName(report.spp.level)
        << " " << report.spp.detail << "]";
    return oss.str();
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
