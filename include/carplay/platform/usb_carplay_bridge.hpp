#ifndef CARPLAY_PLATFORM_USB_CARPLAY_BRIDGE_HPP
#define CARPLAY_PLATFORM_USB_CARPLAY_BRIDGE_HPP

// Reactor-driven glue state machine bridging an Apple USB device (usbfs) to:
//   1. An iAP2 byte stream (Bulk IN callback + writeIap2() Bulk OUT)
//   2. A Linux TAP virtual Ethernet interface via CDC-NCM NTB-16 framing (when NCM is present)
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
    uint64_t iap2_rx_bytes;
    uint64_t iap2_tx_bytes;
    uint64_t ncm_rx_ntbs;
    uint64_t ncm_rx_frames;
    uint64_t ncm_rx_errors;
    uint64_t ncm_tx_ntbs;
    uint64_t ncm_tx_frames;
    uint64_t tap_rx_frames;
    uint64_t tap_tx_frames;
    uint64_t tap_tx_drops;
    uint64_t usb_tx_drops;

    UsbBridgeStats()
        : device_arrivals(0),
          device_removals(0),
          iap2_rx_bytes(0),
          iap2_tx_bytes(0),
          ncm_rx_ntbs(0),
          ncm_rx_frames(0),
          ncm_rx_errors(0),
          ncm_tx_ntbs(0),
          ncm_tx_frames(0),
          tap_rx_frames(0),
          tap_tx_frames(0),
          tap_tx_drops(0),
          usb_tx_drops(0) {}
};

struct UsbCarPlayBridgeConfig {
    usb::Iap2SelectionCriteria iap2_criteria;
    bool detach_kernel_driver;
    bool auto_request_carplay_switch;
    AppleCarPlaySwitchRequest switch_request;

    size_t iap2_in_urb_count;
    size_t iap2_in_urb_bytes;
    size_t iap2_max_out_urbs_inflight;
    size_t iap2_max_tx_queue_chunks;

    size_t ncm_in_urb_count;
    uint32_t ncm_max_ntb_in_bytes;
    uint32_t ncm_max_ntb_out_bytes;
    size_t ncm_max_out_urbs_inflight;
    size_t ncm_max_tx_queue_frames;
    bool ncm_set_ethernet_packet_filter;
    bool ncm_strict_in_alignment;
    size_t max_consecutive_urb_errors;

    UsbCarPlayBridgeConfig()
        : detach_kernel_driver(true),
          auto_request_carplay_switch(false),
          iap2_in_urb_count(2U),
          iap2_in_urb_bytes(4096U),
          iap2_max_out_urbs_inflight(2U),
          iap2_max_tx_queue_chunks(128U),
          ncm_in_urb_count(4U),
          ncm_max_ntb_in_bytes(16384U),
          ncm_max_ntb_out_bytes(16384U),
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
    usb::CarPlayUsbSelection selection_;
    ncm::NtbParameters ntb_params_;
    uint32_t effective_ntb_in_bytes_;
    uint32_t effective_ntb_out_bytes_;
    bool has_device_ncm_mac_;
    uint8_t device_ncm_mac_[6];

    size_t iap2_out_inflight_;
    std::deque<std::vector<uint8_t> > iap2_tx_queue_;

    size_t ncm_out_inflight_;
    uint16_t ncm_tx_seq_;
    std::deque<std::vector<uint8_t> > ncm_tx_frames_;

    size_t consecutive_urb_errors_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_USB_CARPLAY_BRIDGE_HPP
