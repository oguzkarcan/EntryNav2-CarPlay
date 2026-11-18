#ifndef CARPLAY_PLATFORM_USB_HOST_HPP
#define CARPLAY_PLATFORM_USB_HOST_HPP

// Linux usbfs USB host access and sysfs hotplug polling for Apple CarPlay devices.
//
// Design & Provenance:
//   * Enumerates devices via /sys/bus/usb/devices (no libudev).
//   * Opens /dev/bus/usb/BBB/DDD, reads raw descriptors (Device + Configs), and issues
//     USBDEVFS_* ioctls (SETCONFIGURATION, GETDRIVER, DISCONNECT, CLAIMINTERFACE,
//     RELEASEINTERFACE, SETINTERFACE, RESET, CONTROL, SUBMITURB, REAPURBNDELAY, DISCARDURB).
//   * Registers the usbfs fd in Reactor with kPollOut (Linux devio.c signals POLLOUT when
//     async URBs are ready to be reaped via USBDEVFS_REAPURBNDELAY, and POLLERR/POLLHUP on
//     device removal).
//   * Apple CarPlay mode-switch control transfer (0xc0/0x52/0/4) and USB mode query (0xc0/0x45)
//     derived from DiPlay-main:
//       shared/src/main/java/com/shilapi/xcertplay/transport/IphoneUsbHost.kt
//       shared/src/main/java/com/shilapi/xcertplay/transport/UsbConfigurationSelection.kt
//     GPL-3.0, Copyright (c) DiPlay contributors.
//   * Linux 3.12 usbfs URB, ENODEV tracking, sysfs port/removable filtering, and ignored-device
//     (left-alone) anti-retry logic derived from EntryNav2-Android-Auto 0.12.0:
//       platform/usb_devfs.cpp, platform/usb_accessory.cpp, platform/usb_loop.cpp
//     PolyForm Noncommercial License 1.0.0.
//   * Isolates OS sysfs/ioctl calls behind UsbDevfsInterface so UsbHost itself is fully
//     unit-testable with a fake backend, and exposes UsbHostInterface for UsbCarPlayBridge.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/usb_descriptors.hpp"

namespace carplay {
namespace platform {

// Standard & Apple vendor control request constants
// verified: DiPlay-main/shared/src/main/java/com/shilapi/xcertplay/transport/IphoneUsbHost.kt
static const uint8_t kUsbStandardDeviceIn = 0x80U;
static const uint8_t kUsbReqGetConfiguration = 0x08U;
static const uint8_t kUsbVendorDeviceIn = 0xc0U;
static const uint8_t kAppleReqGetUsbMode = 0x45U;
static const uint8_t kAppleReqCarPlayConfig = 0x52U;
static const uint16_t kAppleCarPlayConfigIndex = 0x0004U;
static const uint16_t kAppleVendorResponseBytes = 1U;
static const uint16_t kAppleUsbModeResponseBytes = 4U;

/// Validates a Linux sysfs USB port/device name ("1-1", "3-1.2"; rejects "usbN" root hubs,
/// interfaces containing ':', and path traversal).
bool isValidUsbPortName(const std::string& port);

struct UsbDeviceInfo {
    uint16_t vendor_id;
    uint16_t product_id;
    uint8_t bus_num;
    uint8_t dev_num;
    uint8_t configuration_value;
    uint8_t device_class;
    uint8_t device_subclass;
    uint8_t device_protocol;
    bool is_fixed;  // sysfs `<dev>/removable` == "fixed" (soldered on-board chip, never an iPhone)
    std::string sysfs_name;
    std::string sysfs_path;
    std::string dev_path;
    std::string manufacturer;
    std::string product;
    std::string serial;
    std::string speed;

    UsbDeviceInfo()
        : vendor_id(0),
          product_id(0),
          bus_num(0),
          dev_num(0),
          configuration_value(0),
          device_class(0),
          device_subclass(0),
          device_protocol(0),
          is_fixed(false) {}

    bool sameBusDev(const UsbDeviceInfo& other) const {
        return bus_num == other.bus_num && dev_num == other.dev_num &&
               vendor_id == other.vendor_id && product_id == other.product_id;
    }
};

/// Apple vendor control request to ask an iPhone to enter CarPlay / CDC-NCM USB mode.
/// verified: DiPlay-main/shared/src/main/java/com/shilapi/xcertplay/transport/IphoneUsbHost.kt
///   bmRequestType = 0xc0 (Device-to-Host | Vendor | Device)
///   bRequest      = 0x52 (CARPLAY_CONFIGURATION_REQUEST)
///   wValue        = 0x0000
///   wIndex        = 0x0004 (CARPLAY_CONFIGURATION_INDEX)
///   wLength       = 1 byte IN response
struct AppleCarPlaySwitchRequest {
    uint8_t request_type;
    uint8_t request;
    uint16_t value;
    uint16_t index;
    uint16_t response_length;
    uint32_t timeout_ms;

    AppleCarPlaySwitchRequest()
        : request_type(kUsbVendorDeviceIn),
          request(kAppleReqCarPlayConfig),
          value(0x0000U),
          index(kAppleCarPlayConfigIndex),
          response_length(kAppleVendorResponseBytes),
          timeout_ms(1000U) {}
};

enum UsbClaimStatus {
    kUsbClaimOk = 0,
    kUsbClaimBusyUserspace = 1,  // Held by another userspace process ("usbfs", e.g. MediaPlayer/CARPLAY) or EBUSY
    kUsbClaimBusyKernel = 2,     // Held by a kernel driver and detach is disabled/failed
    kUsbClaimError = 3
};

struct UsbUrbSubmit {
    uint8_t endpoint;
    bool is_in;
    bool zero_packet;
    std::vector<uint8_t> data;  // OUT payload, or empty with capacity=in_length for IN
    size_t in_length;

    UsbUrbSubmit() : endpoint(0), is_in(false), zero_packet(false), in_length(0) {}
};

struct UsbUrbCompletion {
    uint64_t urb_id;
    uintptr_t os_token;
    uint8_t endpoint;
    bool is_in;
    int status;  // 0 on success, negative errno (-ENOENT, -ENODEV, etc.) on failure
    std::vector<uint8_t> data;

    UsbUrbCompletion() : urb_id(0), os_token(0), endpoint(0), is_in(false), status(0) {}
};

enum UsbReapStatus {
    kUsbReapOk = 0,
    kUsbReapEmpty = 1,         // EAGAIN: no completed URBs waiting
    kUsbReapDisconnected = 2,  // ENODEV / ESHUTDOWN: device unplugged
    kUsbReapError = 3
};

/// Low-level OS abstraction over sysfs enumeration and usbfs ioctls.
class UsbDevfsInterface {
public:
    virtual ~UsbDevfsInterface() {}

    virtual int lastErrno() const = 0;

    virtual bool enumerateDevices(const std::string& sysfs_root,
                                  std::vector<UsbDeviceInfo>& out) = 0;

    virtual bool openDevice(const std::string& dev_path,
                            const std::string& sysfs_path,
                            SocketHandle& fd_out,
                            std::vector<uint8_t>& raw_descriptors_out) = 0;

    virtual void closeDevice(SocketHandle fd) = 0;

    virtual bool controlTransfer(SocketHandle fd,
                                 uint8_t request_type,
                                 uint8_t request,
                                 uint16_t value,
                                 uint16_t index,
                                 uint8_t* data,
                                 uint16_t length,
                                 uint32_t timeout_ms,
                                 int& transferred_out) = 0;

    virtual bool setConfiguration(SocketHandle fd, uint8_t configuration_value) = 0;

    /// Queries the driver currently bound to `interface_number` via USBDEVFS_GETDRIVER.
    /// Returns true with empty `driver_out` when no driver is bound (ENODATA / ENOENT),
    /// true with driver name (e.g. "usbfs", "snd-usb-audio", "usbhid") when bound,
    /// or false if the ioctl itself failed.
    virtual bool getInterfaceDriver(SocketHandle fd,
                                    uint8_t interface_number,
                                    std::string& driver_out) = 0;

    virtual bool claimInterface(SocketHandle fd, uint8_t interface_number, bool detach_driver) = 0;
    virtual bool releaseInterface(SocketHandle fd, uint8_t interface_number) = 0;
    virtual bool setInterface(SocketHandle fd, uint8_t interface_number, uint8_t alt_setting) = 0;
    virtual bool resetDevice(SocketHandle fd) = 0;

    virtual bool submitBulkUrb(SocketHandle fd,
                               const UsbUrbSubmit& req,
                               uint64_t urb_id,
                               uintptr_t& os_token_out) = 0;

    virtual UsbReapStatus reapUrb(SocketHandle fd, UsbUrbCompletion& out) = 0;
    virtual bool discardUrb(SocketHandle fd, uintptr_t os_token) = 0;
};

/// Real Linux sysfs + usbfs implementation. Fails cleanly on non-Linux hosts.
class PosixUsbDevfs : public UsbDevfsInterface {
public:
    PosixUsbDevfs();
    virtual ~PosixUsbDevfs();

    virtual int lastErrno() const;

    virtual bool enumerateDevices(const std::string& sysfs_root,
                                  std::vector<UsbDeviceInfo>& out);

    virtual bool openDevice(const std::string& dev_path,
                            const std::string& sysfs_path,
                            SocketHandle& fd_out,
                            std::vector<uint8_t>& raw_descriptors_out);

    virtual void closeDevice(SocketHandle fd);

    virtual bool controlTransfer(SocketHandle fd,
                                 uint8_t request_type,
                                 uint8_t request,
                                 uint16_t value,
                                 uint16_t index,
                                 uint8_t* data,
                                 uint16_t length,
                                 uint32_t timeout_ms,
                                 int& transferred_out);

    virtual bool setConfiguration(SocketHandle fd, uint8_t configuration_value);
    virtual bool getInterfaceDriver(SocketHandle fd,
                                    uint8_t interface_number,
                                    std::string& driver_out);
    virtual bool claimInterface(SocketHandle fd, uint8_t interface_number, bool detach_driver);
    virtual bool releaseInterface(SocketHandle fd, uint8_t interface_number);
    virtual bool setInterface(SocketHandle fd, uint8_t interface_number, uint8_t alt_setting);
    virtual bool resetDevice(SocketHandle fd);

    virtual bool submitBulkUrb(SocketHandle fd,
                               const UsbUrbSubmit& req,
                               uint64_t urb_id,
                               uintptr_t& os_token_out);

    virtual UsbReapStatus reapUrb(SocketHandle fd, UsbUrbCompletion& out);
    virtual bool discardUrb(SocketHandle fd, uintptr_t os_token);

private:
    PosixUsbDevfs(const PosixUsbDevfs&) = delete;
    PosixUsbDevfs& operator=(const PosixUsbDevfs&) = delete;

    struct Impl;
    Impl* impl_;
};

class UsbHostListener {
public:
    virtual ~UsbHostListener() {}
    virtual void onUsbDeviceArrived(const UsbDeviceInfo& info,
                                    const usb::DeviceDescriptor& dev_desc,
                                    const std::vector<usb::ConfigurationDescriptor>& configs) = 0;
    virtual void onUsbDeviceRemoved() = 0;
    virtual void onUsbUrbComplete(uint64_t urb_id,
                                  uint8_t endpoint,
                                  bool is_in,
                                  int status,
                                  const uint8_t* data,
                                  size_t len,
                                  void* user_ctx) = 0;
};

/// High-level USB host interface implemented by UsbHost (and fakeable for bridge tests).
class UsbHostInterface {
public:
    virtual ~UsbHostInterface() {}

    virtual bool start(Reactor& reactor, UsbHostListener* listener) = 0;
    virtual void stop() = 0;

    virtual bool isDeviceOpen() const = 0;
    virtual const UsbDeviceInfo& currentDevice() const = 0;
    virtual const usb::DeviceDescriptor& deviceDescriptor() const = 0;
    virtual const std::vector<usb::ConfigurationDescriptor>& configurations() const = 0;

    virtual bool setConfiguration(uint8_t config_value) = 0;
    virtual bool claimInterface(uint8_t interface_number, bool detach_kernel_driver) = 0;
    virtual bool claimInterfaceWithStatus(uint8_t interface_number,
                                          bool detach_kernel_driver,
                                          bool detach_usbfs_driver,
                                          UsbClaimStatus& status_out,
                                          std::string& driver_out) = 0;
    virtual bool releaseInterface(uint8_t interface_number) = 0;
    virtual bool setInterface(uint8_t interface_number, uint8_t alt_setting) = 0;
    virtual bool resetDevice() = 0;

    virtual bool controlTransfer(uint8_t request_type,
                                 uint8_t request,
                                 uint16_t value,
                                 uint16_t index,
                                 std::vector<uint8_t>& data_io,
                                 uint32_t timeout_ms,
                                 int* actual_len_out = NULL) = 0;

    virtual bool readStringDescriptor(uint8_t string_index, std::string& out) = 0;
    virtual bool queryActiveConfiguration(uint8_t& config_value_out) = 0;
    virtual bool queryAppleUsbMode(std::vector<uint8_t>& mode_out) = 0;
    virtual bool requestCarPlayModeSwitch(const AppleCarPlaySwitchRequest& req) = 0;

    virtual uint64_t submitBulkIn(uint8_t endpoint, size_t max_bytes, void* user_ctx) = 0;
    virtual uint64_t submitBulkOut(uint8_t endpoint,
                                   const uint8_t* data,
                                   size_t len,
                                   bool zero_packet,
                                   void* user_ctx) = 0;
    virtual bool discardUrb(uint64_t urb_id) = 0;
    virtual void ignoreCurrentDevice() = 0;
    virtual void closeCurrentDevice() = 0;
};

struct UsbHostConfig {
    std::string sysfs_devices_root;
    std::string dev_usb_root;
    std::string usb_port_filter;  // empty = any external port; e.g. "3-1" to pin one port
    uint16_t target_vendor_id;
    int64_t hotplug_poll_ms;  // 0 = manual pollHotplug() only
    bool detach_kernel_driver;
    bool detach_usbfs_driver;   // MUST stay false by default so MediaPlayer/CARPLAY is not disrupted
    bool ignore_fixed_devices;  // skip sysfs removable=="fixed" devices (soldered chips)

    UsbHostConfig()
        : sysfs_devices_root("/sys/bus/usb/devices"),
          dev_usb_root("/dev/bus/usb"),
          target_vendor_id(usb::kAppleVendorId),
          hotplug_poll_ms(500),
          detach_kernel_driver(true),
          detach_usbfs_driver(false),
          ignore_fixed_devices(true) {}
};

class UsbHost : public UsbHostInterface, public IoHandler, public TimerHandler {
public:
    /// `backend` may be NULL to use the default PosixUsbDevfs (owned internally).
    /// If non-NULL, the caller retains ownership of `backend`.
    explicit UsbHost(const UsbHostConfig& config = UsbHostConfig(),
                     UsbDevfsInterface* backend = NULL);
    virtual ~UsbHost();

    virtual bool start(Reactor& reactor, UsbHostListener* listener);
    virtual void stop();

    /// Performs one sysfs scan immediately (detects arrivals and removals).
    void pollHotplug();
    /// Reaps any completed URBs from the open usbfs handle (called automatically on kPollOut).
    void reapCompletedUrbs();

    virtual bool isDeviceOpen() const { return device_open_; }
    virtual const UsbDeviceInfo& currentDevice() const { return current_info_; }
    virtual const usb::DeviceDescriptor& deviceDescriptor() const { return dev_desc_; }
    virtual const std::vector<usb::ConfigurationDescriptor>& configurations() const {
        return configs_;
    }

    virtual bool setConfiguration(uint8_t config_value);
    virtual bool claimInterface(uint8_t interface_number, bool detach_kernel_driver);
    virtual bool claimInterfaceWithStatus(uint8_t interface_number,
                                          bool detach_kernel_driver,
                                          bool detach_usbfs_driver,
                                          UsbClaimStatus& status_out,
                                          std::string& driver_out);
    virtual bool releaseInterface(uint8_t interface_number);
    virtual bool setInterface(uint8_t interface_number, uint8_t alt_setting);
    virtual bool resetDevice();

    UsbClaimStatus lastClaimStatus() const { return last_claim_status_; }
    const std::string& lastClaimDriver() const { return last_claim_driver_; }
    int lastErrno() const { return backend_->lastErrno(); }

    virtual bool controlTransfer(uint8_t request_type,
                                 uint8_t request,
                                 uint16_t value,
                                 uint16_t index,
                                 std::vector<uint8_t>& data_io,
                                 uint32_t timeout_ms,
                                 int* actual_len_out = NULL);

    virtual bool readStringDescriptor(uint8_t string_index, std::string& out);
    virtual bool queryActiveConfiguration(uint8_t& config_value_out);
    virtual bool queryAppleUsbMode(std::vector<uint8_t>& mode_out);
    virtual bool requestCarPlayModeSwitch(const AppleCarPlaySwitchRequest& req);

    virtual uint64_t submitBulkIn(uint8_t endpoint, size_t max_bytes, void* user_ctx);
    virtual uint64_t submitBulkOut(uint8_t endpoint,
                                   const uint8_t* data,
                                   size_t len,
                                   bool zero_packet,
                                   void* user_ctx);
    virtual bool discardUrb(uint64_t urb_id);
    virtual void ignoreCurrentDevice();
    virtual void closeCurrentDevice();

    // IoHandler (usbfs fd registered with kPollOut)
    virtual void onReadable();
    virtual void onWritable();
    virtual void onError();

    // TimerHandler (sysfs hotplug poll)
    virtual void onTimer(uint32_t timer_id);

private:
    UsbHost(const UsbHost&) = delete;
    UsbHost& operator=(const UsbHost&) = delete;

    struct PendingUrb {
        uint64_t urb_id;
        uintptr_t os_token;
        uint8_t endpoint;
        bool is_in;
        void* user_ctx;
    };

    struct IgnoredDevice {
        std::string sysfs_name;
        uint8_t bus_num;
        uint8_t dev_num;
    };

    void handleUnexpectedDisconnect();
    bool tryOpenCandidate(const UsbDeviceInfo& candidate);
    bool isIgnoredDevice(const UsbDeviceInfo& candidate) const;
    void forgetGoneIgnored(const std::vector<UsbDeviceInfo>& present);
    int findPendingUrbById(uint64_t urb_id) const;
    int findPendingUrbByToken(uintptr_t os_token) const;

    UsbHostConfig config_;
    PosixUsbDevfs default_backend_;
    UsbDevfsInterface* backend_;

    Reactor* reactor_;
    UsbHostListener* listener_;
    uint32_t poll_timer_id_;
    bool started_;

    bool device_open_;
    SocketHandle fd_;
    bool fd_registered_;
    UsbDeviceInfo current_info_;
    usb::DeviceDescriptor dev_desc_;
    std::vector<usb::ConfigurationDescriptor> configs_;
    std::vector<uint8_t> claimed_interfaces_;
    std::vector<PendingUrb> pending_urbs_;
    std::vector<IgnoredDevice> ignored_devices_;
    UsbClaimStatus last_claim_status_;
    std::string last_claim_driver_;
    uint64_t next_urb_id_;
    bool in_callback_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_USB_HOST_HPP
