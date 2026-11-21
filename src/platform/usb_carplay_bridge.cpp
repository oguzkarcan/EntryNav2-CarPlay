// Derived in part from DiPlay-main:
//   shared/src/main/java/com/shilapi/xcertplay/transport/IphoneUsbHost.kt
//   shared/src/main/java/com/shilapi/xcertplay/orchestration/WiredConfigurationAction.kt
//   shared/src/main/java/com/shilapi/xcertplay/transport/NcmUsbBridge.kt
//   shared/src/main/java/com/shilapi/xcertplay/transport/UsbConfigurationSelection.kt
// GPL-3.0, Copyright (c) DiPlay contributors.
// Derived from EntryNav2-Android-Auto 0.12.0 platform/usb_loop.cpp, platform/usb_bridge.cpp,
// PolyForm Noncommercial License 1.0.0.

#include "carplay/platform/usb_carplay_bridge.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sstream>

#include "carplay/platform/log.hpp"

namespace carplay {
namespace platform {

namespace {

int kTagIap2In = 0;
int kTagIap2Out = 0;
int kTagNcmIn = 0;
int kTagNcmOut = 0;

static const size_t kMinEthernetFrameBytes = 14U;
static const size_t kMaxEthernetFrameBytes = 1536U;

bool isUrbCancelledStatus(int status) {
#ifdef ENOENT
    if (status == -ENOENT) {
        return true;
    }
#endif
#ifdef ECONNRESET
    if (status == -ECONNRESET) {
        return true;
    }
#endif
    return false;
}

bool isUrbDisconnectStatus(int status) {
#ifdef ENODEV
    if (status == -ENODEV) {
        return true;
    }
#endif
#ifdef ESHUTDOWN
    if (status == -ESHUTDOWN) {
        return true;
    }
#endif
    return false;
}

std::string formatHexBytes(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) {
        return "none";
    }
    std::string out;
    char tmp[4];
    for (size_t i = 0; i < bytes.size(); ++i) {
        std::snprintf(tmp, sizeof(tmp), "%02x", static_cast<unsigned>(bytes[i]));
        if (i > 0U) {
            out += ':';
        }
        out += tmp;
    }
    return out;
}

}  // namespace

UsbCarPlayBridge::UsbCarPlayBridge(UsbHostInterface& usb,
                                   TapPortInterface& tap,
                                   const UsbCarPlayBridgeConfig& config)
    : usb_(&usb),
      tap_(&tap),
      config_(config),
      reactor_(NULL),
      listener_(NULL),
      state_(kBridgeStopped),
      session_gen_(0),
      switch_sent_for_device_(false),
      awaiting_reenum_from_switch_(false),
      effective_ntb_in_bytes_(16384U),
      effective_ntb_out_bytes_(16384U),
      has_device_ncm_mac_(false),
      iap2_out_inflight_(0),
      ncm_out_inflight_(0),
      ncm_out_ready_(false),
      ncm_out_not_ready_logged_(false),
      ncm_tx_seq_(0),
      consecutive_urb_errors_(0) {
    std::memset(device_ncm_mac_, 0, sizeof(device_ncm_mac_));
}

UsbCarPlayBridge::~UsbCarPlayBridge() { stop(); }

bool UsbCarPlayBridge::start(Reactor& reactor, UsbCarPlayBridgeListener* listener) {
    if (state_ != kBridgeStopped) {
        return false;
    }
    if (!reactor.initialized()) {
        return false;
    }
    reactor_ = &reactor;
    listener_ = listener;
    setState(kBridgeWaiting);
    if (!usb_->start(reactor, this)) {
        reactor_ = NULL;
        listener_ = NULL;
        setState(kBridgeStopped);
        return false;
    }
    return true;
}

void UsbCarPlayBridge::stop() {
    if (state_ == kBridgeStopped) {
        return;
    }
    awaiting_reenum_from_switch_ = false;
    teardownDevice(false, true);
    usb_->stop();
    reactor_ = NULL;
    listener_ = NULL;
    setState(kBridgeStopped);
}

void UsbCarPlayBridge::getDeviceNcmMac(uint8_t mac_out[6]) const {
    if (mac_out != NULL) {
        std::memcpy(mac_out, device_ncm_mac_, 6U);
    }
}

void UsbCarPlayBridge::setState(BridgeState s) {
    if (state_ == s) {
        return;
    }
    state_ = s;
    if (listener_ != NULL) {
        listener_->onBridgeStateChanged(s);
    }
}

void UsbCarPlayBridge::reportError(const std::string& msg) {
    CARPLAY_LOG_ERROR("usb-bridge", "%s", msg.c_str());
    if (listener_ != NULL) {
        listener_->onBridgeError(msg);
    }
}

bool UsbCarPlayBridge::sendCarPlayModeSwitch() {
    if (!usb_->isDeviceOpen()) {
        return false;
    }
    return usb_->requestCarPlayModeSwitch(config_.switch_request);
}

bool UsbCarPlayBridge::claimBridgeInterface(uint8_t interface_number, const char* role) {
    UsbClaimStatus st = kUsbClaimError;
    std::string driver;
    if (usb_->claimInterfaceWithStatus(interface_number, config_.detach_kernel_driver,
                                       config_.detach_usbfs_driver, st, driver)) {
        return true;
    }
    std::ostringstream oss;
    if (st == kUsbClaimBusyUserspace) {
        ++stats_.ownership_conflicts;
        oss << "USB " << role << " interface " << static_cast<unsigned>(interface_number)
            << " is already claimed by userspace driver '"
            << (driver.empty() ? "usbfs" : driver)
            << "' (likely BMW MediaPlayer/CARPLAY); refusing to detach, leaving device alone";
        reportError(oss.str());
        usb_->ignoreCurrentDevice();
    } else if (st == kUsbClaimBusyKernel) {
        ++stats_.ownership_conflicts;
        oss << "USB " << role << " interface " << static_cast<unsigned>(interface_number)
            << " is bound to kernel driver '" << driver
            << "' and kernel detach is disabled; leaving device alone";
        reportError(oss.str());
        usb_->ignoreCurrentDevice();
    } else {
        oss << "failed to claim USB " << role << " interface "
            << static_cast<unsigned>(interface_number);
        reportError(oss.str());
    }
    return false;
}

void UsbCarPlayBridge::onUsbDeviceArrived(
    const UsbDeviceInfo& info,
    const usb::DeviceDescriptor& dev_desc,
    const std::vector<usb::ConfigurationDescriptor>& configs) {
    (void)dev_desc;
    if (state_ == kBridgeStopped) {
        return;
    }

    const bool after_switch_reenum = awaiting_reenum_from_switch_;
    awaiting_reenum_from_switch_ = false;

    ++stats_.device_arrivals;
    ++session_gen_;
    const uint64_t my_gen = session_gen_;
    setState(kBridgeConfiguring);

    selection_ = usb::selectCarPlayInterfaces(configs, config_.iap2_criteria);
    if (!selection_.found_config || (!selection_.iap2.found && !selection_.ncm.found)) {
        if (config_.auto_request_carplay_switch && !switch_sent_for_device_) {
            switch_sent_for_device_ = true;
            CARPLAY_LOG_INFO("usb-bridge",
                             "no iAP2/NCM interface in current descriptors; sending CarPlay mode switch");
            if (sendCarPlayModeSwitch()) {
                awaiting_reenum_from_switch_ = true;
                teardownDevice(false, true);
                return;
            }
            {
                std::vector<uint8_t> mode;
                if (usb_->queryAppleUsbMode(mode)) {
                    CARPLAY_LOG_INFO("usb-bridge", "Apple USB mode query after rejection: %s",
                                     formatHexBytes(mode).c_str());
                }
            }
        }
        reportError("no CarPlay iAP2 or CDC-NCM interfaces found in USB descriptors");
        teardownDevice(false, true);
        return;
    }

    // DiPlay WiredConfigurationAction: iOS 17+/26 offers USBMUX+NCM without Apple Ethernet
    // (0xff/0xfd/0x01) even outside CarPlay mode (#634). When auto_request_carplay_switch is
    // enabled, try 0xc0/0x52 first so the phone can re-enumerate into full CarPlay mode; only
    // fall back to USBMUX+NCM without Apple Ethernet if 0x52 is rejected or already tried.
    if (selection_.ncm.found && !selection_.iap2.found && selection_.has_usbmux &&
        !selection_.is_carplay_mode) {
        if (!after_switch_reenum && config_.auto_request_carplay_switch &&
            !switch_sent_for_device_) {
            switch_sent_for_device_ = true;
            CARPLAY_LOG_INFO(
                "usb-bridge",
                "USBMUX+NCM present without Apple Ethernet (0xff/0xfd/0x01); requesting CarPlay mode");
            if (sendCarPlayModeSwitch()) {
                CARPLAY_LOG_INFO("usb-bridge",
                                 "CarPlay mode request accepted; closing to await re-enumeration");
                awaiting_reenum_from_switch_ = true;
                teardownDevice(false, true);
                return;
            }
            std::vector<uint8_t> mode;
            if (usb_->queryAppleUsbMode(mode)) {
                CARPLAY_LOG_INFO("usb-bridge", "Apple USB mode query after rejection: %s",
                                 formatHexBytes(mode).c_str());
            }
            if (!config_.ncm_allow_control_fallback) {
                reportError("CarPlay mode switch rejected and USBMUX+NCM fallback disabled");
                teardownDevice(false, true);
                return;
            }
            CARPLAY_LOG_WARN(
                "usb-bridge",
                "CarPlay mode switch rejected; falling back to offered USBMUX+NCM configuration");
        } else if (after_switch_reenum && !config_.ncm_allow_control_fallback) {
            reportError("re-enumerated USB device still lacks Apple Ethernet (0xff/0xfd/0x01)");
            teardownDevice(false, true);
            return;
        }
    }

    if (!selection_.ncm.found && config_.auto_request_carplay_switch && !switch_sent_for_device_) {
        switch_sent_for_device_ = true;
        CARPLAY_LOG_INFO("usb-bridge",
                         "CDC-NCM absent; issuing Apple CarPlay switch request (0xc0/0x52)");
        if (!sendCarPlayModeSwitch()) {
            std::vector<uint8_t> mode;
            if (usb_->queryAppleUsbMode(mode)) {
                CARPLAY_LOG_INFO("usb-bridge", "Apple USB mode query after rejection: %s",
                                 formatHexBytes(mode).c_str());
            }
        }
    }

    if (info.configuration_value != selection_.configuration_value) {
        if (!usb_->setConfiguration(selection_.configuration_value)) {
            reportError("USB SET_CONFIGURATION failed");
            teardownDevice(false, true);
            return;
        }
    }

    if (selection_.iap2.found) {
        if (!claimBridgeInterface(selection_.iap2.interface_number, "iAP2")) {
            teardownDevice(false, true);
            return;
        }
        if (selection_.iap2.alternate_setting != 0U) {
            if (!usb_->setInterface(selection_.iap2.interface_number,
                                    selection_.iap2.alternate_setting)) {
                reportError("failed to set alternate setting on USB iAP2 interface");
                teardownDevice(false, true);
                return;
            }
        }
    }

    bool ncm_ready = false;
    if (selection_.ncm.found) {
        if (!setupNcm()) {
            teardownDevice(false, true);
            return;
        }
        ncm_ready = true;
    }

    consecutive_urb_errors_ = 0;
    iap2_out_inflight_ = 0;
    ncm_out_inflight_ = 0;
    ncm_out_ready_ = false;
    ncm_out_not_ready_logged_ = false;
    ncm_tx_seq_ = 0;
    iap2_tx_queue_.clear();
    ncm_tx_frames_.clear();

    if (selection_.iap2.found && !submitIap2InUrbs()) {
        reportError("failed to submit initial iAP2 Bulk IN URBs");
        teardownDevice(false, true);
        return;
    }

    if (ncm_ready && !submitNcmInUrbs()) {
        reportError("failed to submit initial CDC-NCM Bulk IN URBs");
        teardownDevice(false, true);
        return;
    }

    setState(ncm_ready ? kBridgeActive : kBridgeIap2Only);
    if (session_gen_ != my_gen || state_ == kBridgeStopped) {
        return;
    }

    if (selection_.iap2.found && listener_ != NULL) {
        listener_->onIap2Ready(selection_.iap2);
    }
    if (session_gen_ != my_gen || state_ == kBridgeStopped) {
        return;
    }

    if (ncm_ready && listener_ != NULL) {
        uint8_t tap_mac[6];
        tap_->getMacAddress(tap_mac);
        listener_->onNcmReady(tap_->interfaceName(), tap_->ifIndex(), tap_mac);
    }
}

bool UsbCarPlayBridge::setupNcm() {
    const usb::NcmInterfaceSelection& ncm_sel = selection_.ncm;
    if (!claimBridgeInterface(ncm_sel.control_interface, "CDC-NCM control")) {
        return false;
    }
    if (ncm_sel.data_interface != ncm_sel.control_interface) {
        if (!claimBridgeInterface(ncm_sel.data_interface, "CDC-NCM data")) {
            return false;
        }
    }

    if (ncm_sel.has_idle_alt_setting) {
        usb_->setInterface(ncm_sel.data_interface, ncm_sel.idle_alt_setting);
    }
    if (!usb_->setInterface(ncm_sel.data_interface, ncm_sel.data_alt_setting)) {
        reportError("failed to activate CDC-NCM data alternate setting");
        return false;
    }

    // GET_NTB_PARAMETERS
    std::vector<uint8_t> ntb_param_buf(ncm::kNtbParametersBytes, 0U);
    int actual = 0;
    if (!usb_->controlTransfer(ncm::kReqTypeClassIn, ncm::kReqGetNtbParameters, 0U,
                               ncm_sel.control_interface, ntb_param_buf, 1000U, &actual)) {
        reportError("CDC-NCM GET_NTB_PARAMETERS failed");
        return false;
    }
    std::string err;
    if (!ncm::parseNtbParameters(ntb_param_buf.empty() ? NULL : &ntb_param_buf[0],
                                 ntb_param_buf.size(), ntb_params_, &err)) {
        reportError("invalid CDC-NCM NTB parameters: " + err);
        return false;
    }

    uint32_t in_max = ntb_params_.ntb_in_max_size;
    if (config_.ncm_max_ntb_in_bytes > 0U && config_.ncm_max_ntb_in_bytes < in_max) {
        in_max = config_.ncm_max_ntb_in_bytes;
    }
    if (in_max > ncm::kMaxNtb16BlockSize) {
        in_max = ncm::kMaxNtb16BlockSize;
    }
    if (in_max < 2048U) {
        in_max = 2048U;
    }
    effective_ntb_in_bytes_ = in_max;

    uint32_t out_max = ntb_params_.ntb_out_max_size;
    if (config_.ncm_max_ntb_out_bytes > 0U && config_.ncm_max_ntb_out_bytes < out_max) {
        out_max = config_.ncm_max_ntb_out_bytes;
    }
    if (out_max > ncm::kMaxNtb16BlockSize) {
        out_max = ncm::kMaxNtb16BlockSize;
    }
    if (out_max < 2048U) {
        out_max = 2048U;
    }
    effective_ntb_out_bytes_ = out_max;

    ncm::NtbParseOptions parse_opts =
        ncm::NtbParseOptions::fromParameters(ntb_params_, config_.ncm_strict_in_alignment);
    parse_opts.max_ntb_size = effective_ntb_in_bytes_;
    ncm_rx_decoder_.reset();
    ncm_rx_decoder_.setParseOptions(parse_opts);
    const uint16_t pkt_sz =
        config_.ncm_usb_packet_size > 0U
            ? config_.ncm_usb_packet_size
            : (ncm_sel.bulk_in_max_packet > 0U ? ncm_sel.bulk_in_max_packet : 512U);
    ncm_rx_decoder_.setUsbPacketSize(pkt_sz);

    // SET_NTB_FORMAT (NTB-16) when device advertises NTB-32 too (best-effort).
    if ((ntb_params_.formats_supported & 0x0002U) != 0U) {
        std::vector<uint8_t> empty;
        usb_->controlTransfer(ncm::kReqTypeClassOut, ncm::kReqSetNtbFormat, 0x0000U,
                              ncm_sel.control_interface, empty, 1000U, NULL);
    }

    // SET_NTB_INPUT_SIZE
    std::vector<uint8_t> in_size_buf;
    ncm::encodeSetNtbInputSize(effective_ntb_in_bytes_, in_size_buf);
    if (!usb_->controlTransfer(ncm::kReqTypeClassOut, ncm::kReqSetNtbInputSize, 0U,
                               ncm_sel.control_interface, in_size_buf, 1000U, NULL)) {
        reportError("CDC-NCM SET_NTB_INPUT_SIZE failed");
        return false;
    }

    // Best-effort SET_ETHERNET_PACKET_FILTER so multicast/IPv6 NDP passes through.
    if (config_.ncm_set_ethernet_packet_filter) {
        const uint16_t filter = ncm::kPacketFilterDirected | ncm::kPacketFilterBroadcast |
                                ncm::kPacketFilterMulticast | ncm::kPacketFilterAllMulticast;
        std::vector<uint8_t> empty;
        usb_->controlTransfer(ncm::kReqTypeClassOut, ncm::kReqSetEthernetPacketFilter, filter,
                              ncm_sel.control_interface, empty, 1000U, NULL);
    }

    // Best-effort read of the device's iMACAddress string descriptor for diagnostics.
    has_device_ncm_mac_ = false;
    std::memset(device_ncm_mac_, 0, sizeof(device_ncm_mac_));
    if (ncm_sel.has_mac_string_index) {
        std::string mac_str;
        if (usb_->readStringDescriptor(ncm_sel.mac_string_index, mac_str)) {
            if (usb::parseUsbMacString(mac_str, device_ncm_mac_)) {
                has_device_ncm_mac_ = true;
            }
        }
    }

    if (reactor_ == NULL || !tap_->open(*reactor_, this)) {
        reportError("failed to open/bring up TAP interface");
        return false;
    }
    return true;
}

bool UsbCarPlayBridge::submitOneIap2In() {
    if (!selection_.iap2.found) {
        return false;
    }
    const size_t sz = config_.iap2_in_urb_bytes > 0U ? config_.iap2_in_urb_bytes : 4096U;
    return usb_->submitBulkIn(selection_.iap2.bulk_in_ep, sz, &kTagIap2In) != 0U;
}

bool UsbCarPlayBridge::submitOneNcmIn() {
    if (!selection_.ncm.found) {
        return false;
    }
    return usb_->submitBulkIn(selection_.ncm.bulk_in_ep, effective_ntb_in_bytes_, &kTagNcmIn) != 0U;
}

bool UsbCarPlayBridge::submitIap2InUrbs() {
    const size_t count = config_.iap2_in_urb_count > 0U ? config_.iap2_in_urb_count : 1U;
    for (size_t i = 0; i < count; ++i) {
        if (!submitOneIap2In()) {
            return false;
        }
    }
    return true;
}

bool UsbCarPlayBridge::submitNcmInUrbs() {
    const size_t count = config_.ncm_in_urb_count > 0U ? config_.ncm_in_urb_count : 1U;
    for (size_t i = 0; i < count; ++i) {
        if (!submitOneNcmIn()) {
            return false;
        }
    }
    return true;
}

bool UsbCarPlayBridge::writeIap2(const uint8_t* data, size_t len) {
    if ((state_ != kBridgeIap2Only && state_ != kBridgeActive) || !selection_.iap2.found) {
        return false;
    }
    if (data == NULL || len == 0U) {
        return false;
    }
    if (config_.iap2_max_tx_queue_chunks > 0U &&
        iap2_tx_queue_.size() >= config_.iap2_max_tx_queue_chunks) {
        return false;
    }
    iap2_tx_queue_.push_back(std::vector<uint8_t>(data, data + len));
    pumpIap2Out();
    return true;
}

void UsbCarPlayBridge::pumpIap2Out() {
    const size_t max_inflight =
        config_.iap2_max_out_urbs_inflight > 0U ? config_.iap2_max_out_urbs_inflight : 1U;
    const uint64_t my_gen = session_gen_;
    while ((state_ == kBridgeIap2Only || state_ == kBridgeActive) &&
           iap2_out_inflight_ < max_inflight && !iap2_tx_queue_.empty()) {
        const std::vector<uint8_t>& chunk = iap2_tx_queue_.front();
        const uint16_t max_pkt = selection_.iap2.bulk_out_max_packet;
        const bool zlp = (max_pkt > 0U && (chunk.size() % max_pkt) == 0U);
        const uint64_t id = usb_->submitBulkOut(
            selection_.iap2.bulk_out_ep, chunk.empty() ? NULL : &chunk[0], chunk.size(), zlp,
            &kTagIap2Out);
        if (id == 0U) {
            if (session_gen_ != my_gen || state_ == kBridgeStopped || state_ == kBridgeWaiting) {
                return;
            }
            reportError("submitBulkOut failed on iAP2 endpoint");
            teardownDevice(true, true);
            return;
        }
        stats_.iap2_tx_bytes += chunk.size();
        iap2_tx_queue_.pop_front();
        ++iap2_out_inflight_;
    }
}

void UsbCarPlayBridge::pumpNcmOut() {
    const size_t max_inflight =
        config_.ncm_max_out_urbs_inflight > 0U ? config_.ncm_max_out_urbs_inflight : 1U;
    ncm::NtbBuildOptions build_opts = ncm::NtbBuildOptions::fromParameters(ntb_params_);
    build_opts.max_ntb_size = effective_ntb_out_bytes_;
    const uint64_t my_gen = session_gen_;

    while (state_ == kBridgeActive && ncm_out_inflight_ < max_inflight && !ncm_tx_frames_.empty()) {
        std::vector<std::vector<uint8_t> > batch_input;
        const size_t max_take = (build_opts.max_datagrams > 0U &&
                                 build_opts.max_datagrams < ncm_tx_frames_.size())
                                    ? build_opts.max_datagrams
                                    : ncm_tx_frames_.size();
        batch_input.reserve(max_take);
        for (size_t i = 0; i < max_take; ++i) {
            batch_input.push_back(ncm_tx_frames_[i]);
        }

        std::vector<uint8_t> ntb_bytes;
        size_t packed = 0;
        std::string err;
        if (!ncm::packNtb16Batch(batch_input, 0U, ncm_tx_seq_, build_opts, ntb_bytes, packed,
                                 &err)) {
            // Drop the un-packable head frame so the queue cannot stall indefinitely.
            ++stats_.usb_tx_drops;
            ncm_tx_frames_.pop_front();
            continue;
        }

        const uint16_t max_pkt = selection_.ncm.bulk_out_max_packet;
        const bool zlp = (max_pkt > 0U && (ntb_bytes.size() % max_pkt) == 0U &&
                          ntb_bytes.size() < effective_ntb_out_bytes_);

        const uint64_t id = usb_->submitBulkOut(selection_.ncm.bulk_out_ep, &ntb_bytes[0],
                                                ntb_bytes.size(), zlp, &kTagNcmOut);
        if (id == 0U) {
            if (session_gen_ != my_gen || state_ == kBridgeStopped || state_ == kBridgeWaiting) {
                return;
            }
            reportError("submitBulkOut failed on CDC-NCM endpoint");
            teardownDevice(true, true);
            return;
        }

        for (size_t i = 0; i < packed; ++i) {
            ncm_tx_frames_.pop_front();
        }
        ++ncm_tx_seq_;
        ++ncm_out_inflight_;
        ++stats_.ncm_tx_ntbs;
        stats_.ncm_tx_frames += packed;
    }
}

void UsbCarPlayBridge::onUsbDeviceRemoved() {
    if (state_ == kBridgeStopped || state_ == kBridgeWaiting) {
        return;
    }
    teardownDevice(true, false);
}

void UsbCarPlayBridge::onUsbUrbComplete(uint64_t urb_id,
                                        uint8_t endpoint,
                                        bool is_in,
                                        int status,
                                        const uint8_t* data,
                                        size_t len,
                                        void* user_ctx) {
    (void)urb_id;
    (void)endpoint;
    (void)is_in;

    if (state_ != kBridgeIap2Only && state_ != kBridgeActive) {
        return;
    }
    if (isUrbCancelledStatus(status)) {
        return;
    }
    if (isUrbDisconnectStatus(status)) {
        teardownDevice(true, true);
        return;
    }

    const uint64_t my_gen = session_gen_;

    // DiPlay NcmUsbBridge.kt: before StartCarPlaySession completes, the iPhone NAKs CDC-NCM Bulk
    // OUT (timeouts / stall / EPROTO). Do not count pre-ready NCM OUT failures as fatal bridge
    // errors; allow later packets and iAP2 handshake traffic to proceed cleanly.
    if (user_ctx == &kTagNcmOut && status != 0 && !ncm_out_ready_) {
        if (ncm_out_inflight_ > 0U) {
            --ncm_out_inflight_;
        }
        ++stats_.ncm_out_not_ready_drops;
        if (!ncm_out_not_ready_logged_) {
            ncm_out_not_ready_logged_ = true;
            CARPLAY_LOG_INFO("usb-bridge",
                             "CDC-NCM bulk-out not ready yet (status=%d); retaining bridge",
                             status);
        }
        if (session_gen_ == my_gen && state_ == kBridgeActive) {
            pumpNcmOut();
        }
        return;
    }

    if (status != 0) {
        ++consecutive_urb_errors_;
        if (config_.max_consecutive_urb_errors > 0U &&
            consecutive_urb_errors_ >= config_.max_consecutive_urb_errors) {
            reportError("consecutive USB URB errors exceeded threshold");
            teardownDevice(true, true);
            return;
        }
    } else {
        consecutive_urb_errors_ = 0;
    }

    if (user_ctx == &kTagIap2In) {
        if (status == 0 && len > 0U && data != NULL) {
            stats_.iap2_rx_bytes += len;
            if (listener_ != NULL) {
                listener_->onIap2Data(data, len);
            }
        }
        if (session_gen_ == my_gen && (state_ == kBridgeIap2Only || state_ == kBridgeActive)) {
            submitOneIap2In();
        }
        return;
    }

    if (user_ctx == &kTagIap2Out) {
        if (iap2_out_inflight_ > 0U) {
            --iap2_out_inflight_;
        }
        if (session_gen_ == my_gen && (state_ == kBridgeIap2Only || state_ == kBridgeActive)) {
            pumpIap2Out();
        }
        return;
    }

    if (user_ctx == &kTagNcmIn) {
        if (status == 0 && len > 0U && data != NULL) {
            std::vector<ncm::Ntb16Frame> ntbs;
            ncm::NtbStreamStats delta;
            ncm_rx_decoder_.push(data, len, ntbs, &delta);
            stats_.ncm_rx_ntbs += delta.ntbs_parsed;
            stats_.ncm_rx_errors += delta.parse_errors;
            if (delta.parse_errors > 0U) {
                CARPLAY_LOG_WARN("usb-bridge",
                                 "dropped/resynced malformed IN NTB-16 stream (errors=+%llu)",
                                 static_cast<unsigned long long>(delta.parse_errors));
            }
            for (size_t ni = 0; ni < ntbs.size(); ++ni) {
                const ncm::Ntb16Frame& ntb = ntbs[ni];
                for (size_t i = 0; i < ntb.datagrams.size(); ++i) {
                    const std::vector<uint8_t>& frame = ntb.datagrams[i];
                    if (frame.size() < kMinEthernetFrameBytes) {
                        ++stats_.ncm_rx_errors;
                        continue;
                    }
                    ++stats_.ncm_rx_frames;
                    const TapWriteResult wr = tap_->writeFrame(&frame[0], frame.size());
                    if (wr == kTapWriteSent || wr == kTapWriteQueued) {
                        ++stats_.tap_tx_frames;
                    } else {
                        ++stats_.tap_tx_drops;
                    }
                }
            }
        }
        if (session_gen_ == my_gen && state_ == kBridgeActive) {
            submitOneNcmIn();
        }
        return;
    }

    if (user_ctx == &kTagNcmOut) {
        if (status == 0 && !ncm_out_ready_) {
            ncm_out_ready_ = true;
            if (ncm_out_not_ready_logged_) {
                ncm_out_not_ready_logged_ = false;
                CARPLAY_LOG_INFO("usb-bridge", "CDC-NCM bulk-out became ready");
            }
        }
        if (ncm_out_inflight_ > 0U) {
            --ncm_out_inflight_;
        }
        if (session_gen_ == my_gen && state_ == kBridgeActive) {
            pumpNcmOut();
        }
        return;
    }
}

void UsbCarPlayBridge::onTapFrame(const uint8_t* frame, size_t len) {
    if (state_ != kBridgeActive || frame == NULL) {
        return;
    }
    if (len < kMinEthernetFrameBytes || len > kMaxEthernetFrameBytes) {
        ++stats_.usb_tx_drops;
        return;
    }
    ++stats_.tap_rx_frames;
    if (config_.ncm_max_tx_queue_frames > 0U &&
        ncm_tx_frames_.size() >= config_.ncm_max_tx_queue_frames) {
        ++stats_.usb_tx_drops;
        return;
    }
    ncm_tx_frames_.push_back(std::vector<uint8_t>(frame, frame + len));
    pumpNcmOut();
}

void UsbCarPlayBridge::onTapError() {
    if (state_ == kBridgeActive) {
        reportError("TAP device error");
        teardownDevice(true, true);
    }
}

void UsbCarPlayBridge::teardownDevice(bool notify_listener, bool close_usb) {
    const bool was_connected =
        (state_ == kBridgeConfiguring || state_ == kBridgeIap2Only || state_ == kBridgeActive);

    ++session_gen_;
    tap_->close();
    if (close_usb && usb_->isDeviceOpen()) {
        usb_->closeCurrentDevice();
    }

    selection_ = usb::CarPlayUsbSelection();
    ntb_params_ = ncm::NtbParameters();
    ncm_rx_decoder_.reset();
    has_device_ncm_mac_ = false;
    std::memset(device_ncm_mac_, 0, sizeof(device_ncm_mac_));
    iap2_out_inflight_ = 0;
    iap2_tx_queue_.clear();
    ncm_out_inflight_ = 0;
    ncm_out_ready_ = false;
    ncm_out_not_ready_logged_ = false;
    ncm_tx_seq_ = 0;
    ncm_tx_frames_.clear();
    consecutive_urb_errors_ = 0;

    if (was_connected) {
        ++stats_.device_removals;
    }
    if (!awaiting_reenum_from_switch_) {
        switch_sent_for_device_ = false;
    }
    if (state_ != kBridgeStopped) {
        setState(kBridgeWaiting);
    }
    if (notify_listener && was_connected && listener_ != NULL) {
        listener_->onDeviceRemoved();
    }
}

}  // namespace platform
}  // namespace carplay
