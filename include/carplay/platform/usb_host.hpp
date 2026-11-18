#ifndef CARPLAY_PLATFORM_USB_HOST_HPP
#define CARPLAY_PLATFORM_USB_HOST_HPP

// Linux usbfs USB host access and sysfs hotplug polling for Apple CarPlay devices.
//
// Design:
//   * Enumerates devices via /sys/bus/usb/devices (no libudev).
//   * Opens /dev/bus/usb/BBB/DDD, reads raw descriptors (Device + Configs), and issues
//     USBDEVFS_* ioctls (SETCONFIGURATION, DISCONNECT + CLAIMINTERFACE, RELEASEINTERFACE,
//     SETINTERFACE, CONTROL, SUBMITURB, REAPURBNDELAY, DISCARDURB).
//   * Registers the usbfs fd in Reactor with kPollOut (Linux devio.c signals POLLOUT when
//     async URBs are ready to be reaped via USBDEVFS_REAPURBNDELAY, and POLLERR/POLLHUP on
//     device removal).
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

struct UsbDeviceInfo {
    uint16_t vendor_id;
    uint16_t product_id;
    uint8_t bus_num;
    uint8_t dev_num;
    uint8_t configuration_value;
    uint8_t device_class;
    uint8_t device_subclass;
    uint8_t device_protocol;
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
          device_protocol(0) {}

    bool sameBusDev(const UsbDeviceInfo& other) const {
        return bus_num == other.bus_num && dev_num == other.dev_num &&
               vendor_id == other.vendor_id && product_id == other.product_id;
    }
};

/// Apple vendor control request hook to ask an iPhone to enter CarPlay / CDC-NCM USB mode.
/// All Apple-specific request fields below are unverified against a live iPhone capture.
struct AppleCarPlaySwitchRequest {
    uint8_t request_type;  // Host-to-Device | Vendor | Device (0x40)
    uint8_t request;       // unverified: Apple role/mode switch (0x51; alt 0x52)
    uint16_t value;        // unverified
    uint16_t index;        // unverified
    uint32_t timeout_ms;

    AppleCarPlaySwitchRequest()
        : request_type(0x40U),  // unverified: USB vendor host->device request
          request(0x51U),       // unverified: Apple CarPlay/NCM mode switch request
          value(0x0001U),       // unverified
          index(0x0000U),       // unverified
          timeout_ms(1000U) {}
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
    virtual bool claimInterface(SocketHandle fd, uint8_t interface_number, bool detach_driver) = 0;
    virtual bool releaseInterface(SocketHandle fd, uint8_t interface_number) = 0;
    virtual bool setInterface(SocketHandle fd, uint8_t interface_number, uint8_t alt_setting) = 0;

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
    virtual bool claimInterface(SocketHandle fd, uint8_t interface_number, bool detach_driver);
    virtual bool releaseInterface(SocketHandle fd, uint8_t interface_number);
    virtual bool setInterface(SocketHandle fd, uint8_t interface_number, uint8_t alt_setting);

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
    virtual bool releaseInterface(uint8_t interface_number) = 0;
    virtual bool setInterface(uint8_t interface_number, uint8_t alt_setting) = 0;

    virtual bool controlTransfer(uint8_t request_type,
                                 uint8_t request,
                                 uint16_t value,
                                 uint16_t index,
                                 std::vector<uint8_t>& data_io,
                                 uint32_t timeout_ms,
                                 int* actual_len_out = NULL) = 0;

    virtual bool readStringDescriptor(uint8_t string_index, std::string& out) = 0;
    virtual bool requestCarPlayModeSwitch(const AppleCarPlaySwitchRequest& req) = 0;

    virtual uint64_t submitBulkIn(uint8_t endpoint, size_t max_bytes, void* user_ctx) = 0;
    virtual uint64_t submitBulkOut(uint8_t endpoint,
                                   const uint8_t* data,
                                   size_t len,
                                   bool zero_packet,
                                   void* user_ctx) = 0;
    virtual bool discardUrb(uint64_t urb_id) = 0;
    virtual void closeCurrentDevice() = 0;
};

struct UsbHostConfig {
    std::string sysfs_devices_root;
    std::string dev_usb_root;
    uint16_t target_vendor_id;
    int64_t hotplug_poll_ms;  // 0 = manual pollHotplug() only
    bool detach_kernel_driver;

    UsbHostConfig()
        : sysfs_devices_root("/sys/bus/usb/devices"),
          dev_usb_root("/dev/bus/usb"),
          target_vendor_id(usb::kAppleVendorId),
          hotplug_poll_ms(500),
          detach_kernel_driver(true) {}
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
    virtual bool releaseInterface(uint8_t interface_number);
    virtual bool setInterface(uint8_t interface_number, uint8_t alt_setting);

    virtual bool controlTransfer(uint8_t request_type,
                                 uint8_t request,
                                 uint16_t value,
                                 uint16_t index,
                                 std::vector<uint8_t>& data_io,
                                 uint32_t timeout_ms,
                                 int* actual_len_out = NULL);

    virtual bool readStringDescriptor(uint8_t string_index, std::string& out);
    virtual bool requestCarPlayModeSwitch(const AppleCarPlaySwitchRequest& req);

    virtual uint64_t submitBulkIn(uint8_t endpoint, size_t max_bytes, void* user_ctx);
    virtual uint64_t submitBulkOut(uint8_t endpoint,
                                   const uint8_t* data,
                                   size_t len,
                                   bool zero_packet,
                                   void* user_ctx);
    virtual bool discardUrb(uint64_t urb_id);
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

    void handleUnexpectedDisconnect();
    bool tryOpenCandidate(const UsbDeviceInfo& candidate);
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
    uint64_t next_urb_id_;
    bool in_callback_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_USB_HOST_HPP
