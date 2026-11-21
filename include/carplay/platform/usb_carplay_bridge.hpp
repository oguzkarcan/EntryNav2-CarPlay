#ifndef CARPLAY_PLATFORM_USB_CARPLAY_BRIDGE_HPP
#define CARPLAY_PLATFORM_USB_CARPLAY_BRIDGE_HPP

// Reactor-driven glue state machine bridging an Apple USB device (usbfs) to:
//   1. An iAP2 byte stream (Bulk IN callback + writeIap2() Bulk OUT)
//   2. A Linux TAP virtual Ethernet interface via CDC-NCM NTB-16 framing (when NCM is present)
//
// Provenance:
//   * Apple CarPlay mode switch / iOS 17+ configuration fallback / NCM stream resync & pre-ready
//     Bulk OUT NAK handling derived in part from DiPlay-main:
//       shared/src/main/java/com/shilapi/xcertplay/transport/IphoneUsbHost.kt
//       shared/src/main/java/com/shilapi/xcertplay/orchestration/WiredConfigurationAction.kt
//       shared/src/main/java/com/shilapi/xcertplay/transport/NcmUsbBridge.kt
//       shared/src/main/java/com/shilapi/xcertplay/transport/UsbConfigurationSelection.kt
//     GPL-3.0, Copyright (c) DiPlay contributors.
//   * Safe usbfs ownership/EBUSY policy & ignored-device anti-retry logic derived from
//     EntryNav2-Android-Auto 0.12.0 platform/usb_loop.cpp, platform/usb_bridge.cpp,
//     PolyForm Noncommercial License 1.0.0.
//
// Fully testable on the host with fake UsbHostInterface and fake TapPortInterface.

#include <stddef.h>
#include <stdint.h>

#include <deque>
#include <string>
#include <vector>

#include "carplay/cdc_ncm.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/tap_iface.hpp"
#include "carplay/platform/usb_host.hpp"
#include "carplay/usb_descriptors.hpp"

namespace carplay {
namespace platform {

enum BridgeState {
    kBridgeStopped = 0,
    kBridgeWaiting = 1,
    kBridgeConfiguring = 2,
    kBridgeIap2Only = 3,
    kBridgeActive = 4
};

struct UsbBridgeStats {
    uint64_t device_arrivals;
    uint64_t device_removals;
    uint64_t ownership_conflicts;
    uint64_t iap2_rx_bytes;
    uint64_t iap2_tx_bytes;
    uint64_t ncm_rx_ntbs;
    uint64_t ncm_rx_frames;
    uint64_t ncm_rx_errors;
    uint64_t ncm_tx_ntbs;
    uint64_t ncm_tx_frames;
    uint64_t ncm_out_not_ready_drops;
    uint64_t tap_rx_frames;
    uint64_t tap_tx_frames;
    uint64_t tap_tx_drops;
    uint64_t usb_tx_drops;

    UsbBridgeStats()
        : device_arrivals(0),
          device_removals(0),
          ownership_conflicts(0),
          iap2_rx_bytes(0),
          iap2_tx_bytes(0),
          ncm_rx_ntbs(0),
          ncm_rx_frames(0),
          ncm_rx_errors(0),
          ncm_tx_ntbs(0),
          ncm_tx_frames(0),
          ncm_out_not_ready_drops(0),
          tap_rx_frames(0),
          tap_tx_frames(0),
          tap_tx_drops(0),
          usb_tx_drops(0) {}
};

struct UsbCarPlayBridgeConfig {
    usb::Iap2SelectionCriteria iap2_criteria;
    bool detach_kernel_driver;
    bool detach_usbfs_driver;  // MUST stay false by default to coexist with MediaPlayer/CARPLAY
    bool auto_request_carplay_switch;
    bool ncm_allow_control_fallback;  // Fallback to USBMUX+NCM without Apple Ethernet if 0x52 rejected
    AppleCarPlaySwitchRequest switch_request;

    size_t iap2_in_urb_count;
    size_t iap2_in_urb_bytes;
    size_t iap2_max_out_urbs_inflight;
    size_t iap2_max_tx_queue_chunks;

    size_t ncm_in_urb_count;
    uint32_t ncm_max_ntb_in_bytes;
    uint32_t ncm_max_ntb_out_bytes;
    uint16_t ncm_usb_packet_size;  // 0 = auto from CDC-NCM bulk IN wMaxPacketSize (fallback 512)
    size_t ncm_max_out_urbs_inflight;
    size_t ncm_max_tx_queue_frames;
    bool ncm_set_ethernet_packet_filter;
    bool ncm_strict_in_alignment;
    size_t max_consecutive_urb_errors;

    UsbCarPlayBridgeConfig()
        : detach_kernel_driver(false),
          detach_usbfs_driver(false),
          auto_request_carplay_switch(false),
          ncm_allow_control_fallback(true),
          iap2_in_urb_count(2U),
          iap2_in_urb_bytes(4096U),
          iap2_max_out_urbs_inflight(2U),
          iap2_max_tx_queue_chunks(128U),
          ncm_in_urb_count(4U),
          ncm_max_ntb_in_bytes(16384U),
          ncm_max_ntb_out_bytes(16384U),
          ncm_usb_packet_size(0U),
          ncm_max_out_urbs_inflight(2U),
          ncm_max_tx_queue_frames(256U),
          ncm_set_ethernet_packet_filter(true),
          ncm_strict_in_alignment(false),
          max_consecutive_urb_errors(8U) {}
};

class UsbCarPlayBridgeListener {
public:
    virtual ~UsbCarPlayBridgeListener() {}

    virtual void onBridgeStateChanged(BridgeState /*state*/) {}
    virtual void onIap2Ready(const usb::Iap2InterfaceSelection& /*iap2*/) {}
    virtual void onIap2Data(const uint8_t* data, size_t len) = 0;
    virtual void onNcmReady(const std::string& /*tap_ifname*/,
                            uint32_t /*tap_ifindex*/,
                            const uint8_t /*tap_mac*/[6]) {}
    virtual void onDeviceRemoved() {}
    virtual void onBridgeError(const std::string& /*reason*/) {}
};

class UsbCarPlayBridge : public UsbHostListener, public TapListener {
public:
    /// Caller retains ownership of `usb` and `tap` (must outlive the bridge).
    UsbCarPlayBridge(UsbHostInterface& usb,
                     TapPortInterface& tap,
                     const UsbCarPlayBridgeConfig& config = UsbCarPlayBridgeConfig());
    virtual ~UsbCarPlayBridge();

    bool start(Reactor& reactor, UsbCarPlayBridgeListener* listener);
    void stop();

    BridgeState state() const { return state_; }
    const UsbBridgeStats& stats() const { return stats_; }
    const usb::CarPlayUsbSelection& selection() const { return selection_; }
    const ncm::NtbParameters& ntbParameters() const { return ntb_params_; }
    bool hasDeviceNcmMac() const { return has_device_ncm_mac_; }
    void getDeviceNcmMac(uint8_t mac_out[6]) const;

    /// Queues raw iAP2 bytes onto the USB iAP2 Bulk OUT endpoint.
    bool writeIap2(const uint8_t* data, size_t len);

    /// Explicitly issues the Apple vendor control request to switch the device into CarPlay mode.
    bool sendCarPlayModeSwitch();

    // UsbHostListener (Reactor thread)
    virtual void onUsbDeviceArrived(const UsbDeviceInfo& info,
                                    const usb::DeviceDescriptor& dev_desc,
                                    const std::vector<usb::ConfigurationDescriptor>& configs);
    virtual void onUsbDeviceRemoved();
    virtual void onUsbUrbComplete(uint64_t urb_id,
                                  uint8_t endpoint,
                                  bool is_in,
                                  int status,
                                  const uint8_t* data,
                                  size_t len,
                                  void* user_ctx);

    // TapListener (Reactor thread)
    virtual void onTapFrame(const uint8_t* frame, size_t len);
    virtual void onTapError();

private:
    UsbCarPlayBridge(const UsbCarPlayBridge&) = delete;
    UsbCarPlayBridge& operator=(const UsbCarPlayBridge&) = delete;

    bool claimBridgeInterface(uint8_t interface_number, const char* role);
    bool setupNcm();
    bool submitIap2InUrbs();
    bool submitNcmInUrbs();
    bool submitOneIap2In();
    bool submitOneNcmIn();
    void pumpIap2Out();
    void pumpNcmOut();
    void teardownDevice(bool notify_listener, bool close_usb);
    void setState(BridgeState s);
    void reportError(const std::string& msg);

    UsbHostInterface* usb_;
    TapPortInterface* tap_;
    UsbCarPlayBridgeConfig config_;

    Reactor* reactor_;
    UsbCarPlayBridgeListener* listener_;
    BridgeState state_;
    UsbBridgeStats stats_;

    uint64_t session_gen_;
    bool switch_sent_for_device_;
    bool awaiting_reenum_from_switch_;
    usb::CarPlayUsbSelection selection_;
    ncm::NtbParameters ntb_params_;
    ncm::Ntb16StreamDecoder ncm_rx_decoder_;
    uint32_t effective_ntb_in_bytes_;
    uint32_t effective_ntb_out_bytes_;
    bool has_device_ncm_mac_;
    uint8_t device_ncm_mac_[6];

    size_t iap2_out_inflight_;
    std::deque<std::vector<uint8_t> > iap2_tx_queue_;

    size_t ncm_out_inflight_;
    bool ncm_out_ready_;
    bool ncm_out_not_ready_logged_;
    uint16_t ncm_tx_seq_;
    std::deque<std::vector<uint8_t> > ncm_tx_frames_;

    size_t consecutive_urb_errors_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_USB_CARPLAY_BRIDGE_HPP
