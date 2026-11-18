#include "carplay/cdc_ncm.hpp"
#include "carplay/iap2_wire.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/tap_iface.hpp"
#include "carplay/platform/usb_carplay_bridge.hpp"
#include "carplay/platform/usb_host.hpp"
#include "carplay/usb_descriptors.hpp"
#include "test_support.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifdef __linux__
#include <stdlib.h>
#include <sys/stat.h>
#endif

namespace {

using namespace carplay;
using namespace carplay::platform;

void pushU16Le(std::vector<uint8_t>& v, uint16_t val) {
    v.push_back(static_cast<uint8_t>(val & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 8) & 0xffU));
}

void pushU32Le(std::vector<uint8_t>& v, uint32_t val) {
    v.push_back(static_cast<uint8_t>(val & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 8) & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 16) & 0xffU));
    v.push_back(static_cast<uint8_t>((val >> 24) & 0xffU));
}

std::vector<uint8_t> buildSyntheticCarPlayBlob(bool include_ncm) {
    std::vector<uint8_t> body;
    // Interface 0: Apple iAP2
    body.push_back(9U);
    body.push_back(usb::kDescTypeInterface);
    body.push_back(0U);
    body.push_back(0U);
    body.push_back(2U);
    body.push_back(usb::kAppleIap2Class);
    body.push_back(usb::kAppleIap2SubClass);
    body.push_back(usb::kAppleIap2Protocol);
    body.push_back(0U);
    // Bulk IN 0x81, Bulk OUT 0x01
    body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x81U);
    body.push_back(usb::kEpTypeBulk); pushU16Le(body, 512U); body.push_back(0U);
    body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x01U);
    body.push_back(usb::kEpTypeBulk); pushU16Le(body, 512U); body.push_back(0U);

    uint8_t num_ifaces = 1U;
    if (include_ncm) {
        num_ifaces = 3U;
        // Interface 1: CDC-NCM Control
        body.push_back(9U);
        body.push_back(usb::kDescTypeInterface);
        body.push_back(1U);
        body.push_back(0U);
        body.push_back(1U);
        body.push_back(usb::kClassCommunications);
        body.push_back(usb::kSubClassCdcNcm);
        body.push_back(0U);
        body.push_back(0U);
        // Header + Union(1->2) + Ethernet(iMAC=4) + NCM
        body.push_back(5U); body.push_back(usb::kDescTypeCsInterface); body.push_back(usb::kCdcSubtypeHeader);
        pushU16Le(body, 0x0120U);
        body.push_back(5U); body.push_back(usb::kDescTypeCsInterface); body.push_back(usb::kCdcSubtypeUnion);
        body.push_back(1U); body.push_back(2U);
        body.push_back(13U); body.push_back(usb::kDescTypeCsInterface); body.push_back(usb::kCdcSubtypeEthernet);
        body.push_back(4U); pushU32Le(body, 0U); pushU16Le(body, 1514U); pushU16Le(body, 0U); body.push_back(0U);
        body.push_back(6U); body.push_back(usb::kDescTypeCsInterface); body.push_back(usb::kCdcSubtypeNcm);
        pushU16Le(body, 0x0100U); body.push_back(0x0fU);
        // Interrupt IN 0x82
        body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x82U);
        body.push_back(usb::kEpTypeInterrupt); pushU16Le(body, 16U); body.push_back(9U);
        // Interface 2 alt 0: idle
        body.push_back(9U); body.push_back(usb::kDescTypeInterface); body.push_back(2U); body.push_back(0U);
        body.push_back(0U); body.push_back(usb::kClassCdcData); body.push_back(0U); body.push_back(usb::kProtocolCdcNcmData);
        body.push_back(0U);
        // Interface 2 alt 1: active
        body.push_back(9U); body.push_back(usb::kDescTypeInterface); body.push_back(2U); body.push_back(1U);
        body.push_back(2U); body.push_back(usb::kClassCdcData); body.push_back(0U); body.push_back(usb::kProtocolCdcNcmData);
        body.push_back(0U);
        body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x83U);
        body.push_back(usb::kEpTypeBulk); pushU16Le(body, 512U); body.push_back(0U);
        body.push_back(7U); body.push_back(usb::kDescTypeEndpoint); body.push_back(0x03U);
        body.push_back(usb::kEpTypeBulk); pushU16Le(body, 512U); body.push_back(0U);
    }

    std::vector<uint8_t> blob;
    // Device descriptor (18B)
    blob.push_back(18U); blob.push_back(usb::kDescTypeDevice); pushU16Le(blob, 0x0200U);
    blob.push_back(0U); blob.push_back(0U); blob.push_back(0U); blob.push_back(64U);
    pushU16Le(blob, usb::kAppleVendorId); pushU16Le(blob, 0x12a8U); pushU16Le(blob, 0x0100U);
    blob.push_back(1U); blob.push_back(2U); blob.push_back(3U); blob.push_back(1U);
    // Config descriptor
    blob.push_back(9U); blob.push_back(usb::kDescTypeConfiguration);
    pushU16Le(blob, static_cast<uint16_t>(9U + body.size()));
    blob.push_back(num_ifaces);
    blob.push_back(include_ncm ? 4U : 1U);  // bConfigurationValue
    blob.push_back(0U); blob.push_back(0xc0U); blob.push_back(250U);
    blob.insert(blob.end(), body.begin(), body.end());
    return blob;
}

std::vector<uint8_t> makeEthFrame(uint8_t tag, size_t payload_bytes) {
    std::vector<uint8_t> f(14U + payload_bytes, 0U);
    f[0] = 0x33U; f[1] = 0x33U; f[5] = 0x01U;
    f[6] = 0x02U; f[7] = 0xaaU; f[11] = tag;
    f[12] = 0x86U; f[13] = 0xddU;
    for (size_t i = 0; i < payload_bytes; ++i) {
        f[14U + i] = static_cast<uint8_t>(tag ^ i);
    }
    return f;
}

bool openBidirectionalTestPair(SocketHandle& a, SocketHandle& b) {
#ifdef _WIN32
    return wakePairOpen(a, b);
#else
    a = kInvalidSocket;
    b = kInvalidSocket;
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return false;
    }
    for (int i = 0; i < 2; ++i) {
        const int fl = fcntl(fds[i], F_GETFL, 0);
        if (fl < 0 || fcntl(fds[i], F_SETFL, fl | O_NONBLOCK) != 0) {
            close(fds[0]);
            close(fds[1]);
            return false;
        }
    }
    a = fds[0];
    b = fds[1];
    return true;
#endif
}

// ------------------------------------------------------------------------------------------------
// Fake UsbDevfs for testing UsbHost directly (including Reactor kPollOut completions)
// ------------------------------------------------------------------------------------------------

class FakeUsbDevfs : public UsbDevfsInterface {
public:
    FakeUsbDevfs()
        : device_present(false),
          next_token(100U),
          read_end(kInvalidSocket),
          write_end(kInvalidSocket),
          set_config_calls(0),
          switch_calls(0) {
        std::memset(&last_switch_req, 0, sizeof(last_switch_req));
    }

    ~FakeUsbDevfs() { wakePairClose(read_end, write_end); }

    bool initWakeFd() { return openBidirectionalTestPair(read_end, write_end); }

    struct ControlCall {
        uint8_t req_type;
        uint8_t req;
        uint16_t val;
        uint16_t idx;
    };

    virtual bool enumerateDevices(const std::string&, std::vector<UsbDeviceInfo>& out) {
        out.clear();
        if (device_present) {
            out.push_back(present_info);
        }
        return true;
    }

    virtual bool openDevice(const std::string&,
                            const std::string&,
                            SocketHandle& fd_out,
                            std::vector<uint8_t>& raw_descriptors_out) {
        if (!device_present) {
            return false;
        }
        fd_out = read_end;
        raw_descriptors_out = raw_descriptors;
        return true;
    }

    virtual void closeDevice(SocketHandle) {
        in_flight.clear();
        completions.clear();
    }

    virtual bool controlTransfer(SocketHandle,
                                 uint8_t request_type,
                                 uint8_t request,
                                 uint16_t value,
                                 uint16_t index,
                                 uint8_t* data,
                                 uint16_t length,
                                 uint32_t,
                                 int& transferred_out) {
        ControlCall cc;
        cc.req_type = request_type;
        cc.req = request;
        cc.val = value;
        cc.idx = index;
        control_calls.push_back(cc);

        if (request_type == 0x80U && request == 0x06U && (value >> 8) == usb::kDescTypeString) {
            const char s[] = "021122334455";
            const size_t n = 2U + 12U * 2U;
            if (length >= n && data != NULL) {
                data[0] = static_cast<uint8_t>(n);
                data[1] = usb::kDescTypeString;
                for (size_t i = 0; i < 12U; ++i) {
                    data[2U + 2U * i] = static_cast<uint8_t>(s[i]);
                    data[2U + 2U * i + 1U] = 0U;
                }
                transferred_out = static_cast<int>(n);
                return true;
            }
        }
        if (request_type == 0x40U) {
            ++switch_calls;
            last_switch_req = cc;
        }
        transferred_out = 0;
        return true;
    }

    virtual bool setConfiguration(SocketHandle, uint8_t cfg) {
        ++set_config_calls;
        present_info.configuration_value = cfg;
        return true;
    }
    virtual bool claimInterface(SocketHandle, uint8_t iface, bool) {
        claimed.push_back(iface);
        return true;
    }
    virtual bool releaseInterface(SocketHandle, uint8_t iface) {
        released.push_back(iface);
        return true;
    }
    virtual bool setInterface(SocketHandle, uint8_t, uint8_t) { return true; }

    virtual bool submitBulkUrb(SocketHandle,
                               const UsbUrbSubmit& req,
                               uint64_t urb_id,
                               uintptr_t& os_token_out) {
        const uintptr_t tok = next_token++;
        os_token_out = tok;
        SubmittedUrb su;
        su.urb_id = urb_id;
        su.token = tok;
        su.req = req;
        in_flight.push_back(su);
        return true;
    }

    virtual UsbReapStatus reapUrb(SocketHandle, UsbUrbCompletion& out) {
        if (completions.empty()) {
            return kUsbReapEmpty;
        }
        out = completions.front();
        completions.pop_front();
        return kUsbReapOk;
    }

    virtual bool discardUrb(SocketHandle, uintptr_t os_token) {
        for (size_t i = 0; i < in_flight.size(); ++i) {
            if (in_flight[i].token == os_token) {
                in_flight.erase(in_flight.begin() + static_cast<ptrdiff_t>(i));
                return true;
            }
        }
        return false;
    }

    void completeNextUrb(int status, const std::vector<uint8_t>& rx_data) {
        if (in_flight.empty()) {
            return;
        }
        const SubmittedUrb su = in_flight.front();
        in_flight.erase(in_flight.begin());
        UsbUrbCompletion c;
        c.urb_id = su.urb_id;
        c.os_token = su.token;
        c.endpoint = su.req.endpoint;
        c.is_in = su.req.is_in;
        c.status = status;
        c.data = rx_data;
        completions.push_back(c);
    }

    struct SubmittedUrb {
        uint64_t urb_id;
        uintptr_t token;
        UsbUrbSubmit req;
    };

    bool device_present;
    UsbDeviceInfo present_info;
    std::vector<uint8_t> raw_descriptors;
    uintptr_t next_token;
    SocketHandle read_end;
    SocketHandle write_end;
    int set_config_calls;
    int switch_calls;
    ControlCall last_switch_req;
    std::vector<ControlCall> control_calls;
    std::vector<uint8_t> claimed;
    std::vector<uint8_t> released;
    std::vector<SubmittedUrb> in_flight;
    std::deque<UsbUrbCompletion> completions;
};

// ------------------------------------------------------------------------------------------------
// Fake TapOsInterface for testing TapIface + Reactor without root
// ------------------------------------------------------------------------------------------------

class FakeTapOs : public TapOsInterface {
public:
    FakeTapOs()
        : open_ok(true),
          cfg_ok(true),
          fd(kInvalidSocket),
          peer_fd(kInvalidSocket),
          mtu_configured(0),
          would_block_writes(false),
          close_count(0) {
        std::memset(mac_configured, 0, sizeof(mac_configured));
    }

    ~FakeTapOs() { wakePairClose(fd, peer_fd); }

    bool initSockets() { return openBidirectionalTestPair(fd, peer_fd); }

    virtual bool openTap(const std::string&,
                         const std::string& req_name,
                         SocketHandle& fd_out,
                         std::string& actual_name_out) {
        if (!open_ok) {
            return false;
        }
        fd_out = fd;
        actual_name_out = req_name.empty() ? "tap0" : req_name;
        return true;
    }

    virtual bool configureInterface(const std::string&,
                                    const uint8_t mac[6],
                                    uint16_t mtu,
                                    uint32_t& ifindex_out) {
        if (!cfg_ok) {
            return false;
        }
        std::memcpy(mac_configured, mac, 6U);
        mtu_configured = mtu;
        ifindex_out = 42U;
        return true;
    }

    virtual void closeTap(SocketHandle) { ++close_count; }

    virtual IoStatus readFrame(SocketHandle, uint8_t* buf, size_t cap, size_t& len_out) {
        if (rx_queue.empty()) {
            wakeDrain(fd);
            return kIoWouldBlock;
        }
        const std::vector<uint8_t> f = rx_queue.front();
        rx_queue.pop_front();
        if (rx_queue.empty()) {
            wakeDrain(fd);
        }
        const size_t n = f.size() <= cap ? f.size() : cap;
        std::memcpy(buf, &f[0], n);
        len_out = n;
        return kIoOk;
    }

    virtual IoStatus writeFrame(SocketHandle, const uint8_t* data, size_t len) {
        if (would_block_writes) {
            return kIoWouldBlock;
        }
        tx_frames.push_back(std::vector<uint8_t>(data, data + len));
        return kIoOk;
    }

    void pushInboundFrame(const std::vector<uint8_t>& frame) {
        rx_queue.push_back(frame);
        wakeSignal(peer_fd);
    }

    bool open_ok;
    bool cfg_ok;
    SocketHandle fd;
    SocketHandle peer_fd;
    uint8_t mac_configured[6];
    uint16_t mtu_configured;
    bool would_block_writes;
    int close_count;
    std::deque<std::vector<uint8_t> > rx_queue;
    std::vector<std::vector<uint8_t> > tx_frames;
};

// ------------------------------------------------------------------------------------------------
// Fake UsbHostInterface + FakeTapPort for testing UsbCarPlayBridge cleanly
// ------------------------------------------------------------------------------------------------

class FakeUsbHost : public UsbHostInterface {
public:
    struct SentBulkOut {
        uint8_t ep;
        bool zero_packet;
        std::vector<uint8_t> data;
    };

    struct InflightUrb {
        uint64_t id;
        uint8_t ep;
        bool is_in;
        void* user_ctx;
    };

    FakeUsbHost()
        : listener_(NULL),
          started_(false),
          open_(false),
          next_id_(1U),
          switch_calls_(0),
          set_cfg_calls_(0) {
        ntb_params_ = ncm::NtbParameters::defaults();
    }

    virtual bool start(Reactor&, UsbHostListener* listener) {
        started_ = true;
        listener_ = listener;
        return true;
    }

    virtual void stop() {
        started_ = false;
        closeCurrentDevice();
        listener_ = NULL;
    }

    virtual bool isDeviceOpen() const { return open_; }
    virtual const UsbDeviceInfo& currentDevice() const { return info_; }
    virtual const usb::DeviceDescriptor& deviceDescriptor() const { return dev_desc_; }
    virtual const std::vector<usb::ConfigurationDescriptor>& configurations() const {
        return configs_;
    }

    virtual bool setConfiguration(uint8_t config_value) {
        ++set_cfg_calls_;
        info_.configuration_value = config_value;
        return true;
    }

    virtual bool claimInterface(uint8_t iface, bool) {
        claimed_ifaces_.push_back(iface);
        return true;
    }

    virtual bool releaseInterface(uint8_t) { return true; }
    virtual bool setInterface(uint8_t iface, uint8_t alt) {
        set_ifaces_.push_back(std::make_pair(iface, alt));
        return true;
    }

    virtual bool controlTransfer(uint8_t request_type,
                                 uint8_t request,
                                 uint16_t value,
                                 uint16_t index,
                                 std::vector<uint8_t>& data_io,
                                 uint32_t,
                                 int* actual_len_out) {
        (void)value;
        (void)index;
        if (request_type == ncm::kReqTypeClassIn && request == ncm::kReqGetNtbParameters) {
            ncm::encodeNtbParameters(ntb_params_, data_io);
            if (actual_len_out != NULL) {
                *actual_len_out = static_cast<int>(data_io.size());
            }
            return true;
        }
        if (request_type == ncm::kReqTypeClassOut && request == ncm::kReqSetNtbInputSize) {
            set_ntb_input_sizes_.push_back(data_io);
            return true;
        }
        if (request_type == ncm::kReqTypeClassOut && request == ncm::kReqSetEthernetPacketFilter) {
            packet_filters_.push_back(value);
            return true;
        }
        return true;
    }

    virtual bool readStringDescriptor(uint8_t, std::string& out) {
        out = "02AABBCCDDEE";
        return true;
    }

    virtual bool requestCarPlayModeSwitch(const AppleCarPlaySwitchRequest&) {
        ++switch_calls_;
        return true;
    }

    virtual uint64_t submitBulkIn(uint8_t endpoint, size_t, void* user_ctx) {
        if (!open_) {
            return 0U;
        }
        InflightUrb u;
        u.id = next_id_++;
        u.ep = endpoint;
        u.is_in = true;
        u.user_ctx = user_ctx;
        inflight_.push_back(u);
        return u.id;
    }

    virtual uint64_t submitBulkOut(uint8_t endpoint,
                                   const uint8_t* data,
                                   size_t len,
                                   bool zero_packet,
                                   void* user_ctx) {
        if (!open_) {
            return 0U;
        }
        SentBulkOut s;
        s.ep = endpoint;
        s.zero_packet = zero_packet;
        if (data != NULL && len > 0U) {
            s.data.assign(data, data + len);
        }
        sent_out_.push_back(s);

        InflightUrb u;
        u.id = next_id_++;
        u.ep = endpoint;
        u.is_in = false;
        u.user_ctx = user_ctx;
        inflight_.push_back(u);
        return u.id;
    }

    virtual bool discardUrb(uint64_t urb_id) {
        for (size_t i = 0; i < inflight_.size(); ++i) {
            if (inflight_[i].id == urb_id) {
                inflight_.erase(inflight_.begin() + static_cast<ptrdiff_t>(i));
                return true;
            }
        }
        return false;
    }

    virtual void closeCurrentDevice() {
        open_ = false;
        inflight_.clear();
    }

    // Test drivers
    void simulateArrival(const std::vector<uint8_t>& descriptor_blob, uint8_t initial_cfg = 1U) {
        std::string err;
        usb::parseUsbfsDescriptors(&descriptor_blob[0], descriptor_blob.size(), dev_desc_, configs_,
                                   &err);
        info_ = UsbDeviceInfo();
        info_.vendor_id = dev_desc_.id_vendor;
        info_.product_id = dev_desc_.id_product;
        info_.bus_num = 1U;
        info_.dev_num = 2U;
        info_.configuration_value = initial_cfg;
        open_ = true;
        if (listener_ != NULL) {
            listener_->onUsbDeviceArrived(info_, dev_desc_, configs_);
        }
    }

    void simulateRemoval() {
        open_ = false;
        inflight_.clear();
        if (listener_ != NULL) {
            listener_->onUsbDeviceRemoved();
        }
    }

    bool completeFirstUrbOnEp(uint8_t ep, int status, const std::vector<uint8_t>& rx_data) {
        for (size_t i = 0; i < inflight_.size(); ++i) {
            if (inflight_[i].ep == ep) {
                const InflightUrb u = inflight_[i];
                inflight_.erase(inflight_.begin() + static_cast<ptrdiff_t>(i));
                if (listener_ != NULL) {
                    const uint8_t* ptr = rx_data.empty() ? NULL : &rx_data[0];
                    listener_->onUsbUrbComplete(u.id, u.ep, u.is_in, status, ptr, rx_data.size(),
                                                u.user_ctx);
                }
                return true;
            }
        }
        return false;
    }

    size_t inflightCountOnEp(uint8_t ep) const {
        size_t n = 0;
        for (size_t i = 0; i < inflight_.size(); ++i) {
            if (inflight_[i].ep == ep) {
                ++n;
            }
        }
        return n;
    }

    UsbHostListener* listener_;
    bool started_;
    bool open_;
    uint64_t next_id_;
    UsbDeviceInfo info_;
    usb::DeviceDescriptor dev_desc_;
    std::vector<usb::ConfigurationDescriptor> configs_;
    ncm::NtbParameters ntb_params_;
    int switch_calls_;
    int set_cfg_calls_;
    std::vector<uint8_t> claimed_ifaces_;
    std::vector<std::pair<uint8_t, uint8_t> > set_ifaces_;
    std::vector<std::vector<uint8_t> > set_ntb_input_sizes_;
    std::vector<uint16_t> packet_filters_;
    std::vector<SentBulkOut> sent_out_;
    std::vector<InflightUrb> inflight_;
};

class FakeTapPort : public TapPortInterface {
public:
    FakeTapPort() : listener_(NULL), open_(false), ifindex_(9U), name_("carplay0") {
        deriveLocallyAdministeredMac(12345ULL, mac_);
    }

    virtual bool open(Reactor&, TapListener* listener) {
        open_ = true;
        listener_ = listener;
        return true;
    }
    virtual void close() {
        open_ = false;
        listener_ = NULL;
    }
    virtual bool isOpen() const { return open_; }
    virtual const std::string& interfaceName() const { return name_; }
    virtual uint32_t ifIndex() const { return ifindex_; }
    virtual void getMacAddress(uint8_t mac_out[6]) const { std::memcpy(mac_out, mac_, 6U); }

    virtual TapWriteResult writeFrame(const uint8_t* data, size_t len) {
        if (!open_) {
            return kTapWriteError;
        }
        rx_from_usb.push_back(std::vector<uint8_t>(data, data + len));
        return kTapWriteSent;
    }

    virtual bool queryIpv6LinkLocal(Address& out) const {
        if (!open_) {
            return false;
        }
        out = computeEui64LinkLocal(mac_, ifindex_);
        return true;
    }

    void injectFromKernel(const std::vector<uint8_t>& frame) {
        if (open_ && listener_ != NULL) {
            listener_->onTapFrame(frame.empty() ? NULL : &frame[0], frame.size());
        }
    }

    TapListener* listener_;
    bool open_;
    uint32_t ifindex_;
    std::string name_;
    uint8_t mac_[6];
    std::vector<std::vector<uint8_t> > rx_from_usb;
};

struct RecordingBridgeListener : public UsbCarPlayBridgeListener {
    RecordingBridgeListener()
        : iap2_ready_count(0), ncm_ready_count(0), removed_count(0) {}

    virtual void onBridgeStateChanged(BridgeState s) { states.push_back(s); }
    virtual void onIap2Ready(const usb::Iap2InterfaceSelection&) { ++iap2_ready_count; }
    virtual void onIap2Data(const uint8_t* data, size_t len) {
        iap2_rx.insert(iap2_rx.end(), data, data + len);
    }
    virtual void onNcmReady(const std::string& ifname, uint32_t ifidx, const uint8_t[6]) {
        ++ncm_ready_count;
        last_tap_name = ifname;
        last_tap_ifindex = ifidx;
    }
    virtual void onDeviceRemoved() { ++removed_count; }
    virtual void onBridgeError(const std::string& reason) { errors.push_back(reason); }

    std::vector<BridgeState> states;
    int iap2_ready_count;
    int ncm_ready_count;
    int removed_count;
    std::string last_tap_name;
    uint32_t last_tap_ifindex;
    std::vector<uint8_t> iap2_rx;
    std::vector<std::string> errors;
};

struct RecordingHostListener : public UsbHostListener {
    RecordingHostListener() : arrived(0), removed(0), urbs_completed(0) {}
    virtual void onUsbDeviceArrived(const UsbDeviceInfo&,
                                    const usb::DeviceDescriptor&,
                                    const std::vector<usb::ConfigurationDescriptor>&) {
        ++arrived;
    }
    virtual void onUsbDeviceRemoved() { ++removed; }
    virtual void onUsbUrbComplete(uint64_t urb_id,
                                  uint8_t ep,
                                  bool is_in,
                                  int status,
                                  const uint8_t* data,
                                  size_t len,
                                  void*) {
        (void)urb_id;
        (void)ep;
        (void)is_in;
        (void)status;
        if (data != NULL && len > 0U) {
            last_rx.assign(data, data + len);
        }
        ++urbs_completed;
    }
    int arrived;
    int removed;
    int urbs_completed;
    std::vector<uint8_t> last_rx;
};

struct RecordingTapListener : public TapListener {
    RecordingTapListener() : errors(0) {}
    virtual void onTapFrame(const uint8_t* frame, size_t len) {
        frames.push_back(std::vector<uint8_t>(frame, frame + len));
    }
    virtual void onTapError() { ++errors; }
    std::vector<std::vector<uint8_t> > frames;
    int errors;
};

#ifdef __linux__
bool writeTempTextFile(const std::string& path, const std::string& txt) {
    FILE* f = std::fopen(path.c_str(), "w");
    if (f == NULL) {
        return false;
    }
    std::fwrite(txt.data(), 1, txt.size(), f);
    std::fclose(f);
    return true;
}
#endif

}  // namespace

TEST_CASE(macDerivationAndProcIfInet6Parser) {
    uint8_t mac1[6], mac2[6];
    deriveLocallyAdministeredMac(1ULL, mac1);
    deriveLocallyAdministeredMac(2ULL, mac2);
    CHECK((mac1[0] & 0x03U) == 0x02U);  // locally-administered + unicast
    CHECK((mac2[0] & 0x03U) == 0x02U);
    CHECK(std::memcmp(mac1, mac2, 6U) != 0);

    uint8_t mac_str[6];
    deriveLocallyAdministeredMacFromString("F20-EntryNav2-CarPlay", mac_str);
    CHECK((mac_str[0] & 0x03U) == 0x02U);

    const Address ll = computeEui64LinkLocal(mac1, 7U);
    CHECK(ll.valid());
    CHECK(ll.isLinkLocal());
    CHECK_EQ(7U, ll.scopeId());

    const std::string sample_proc =
        "00000000000000000000000000000001 01 80 10 80       lo\n"
        "fe80000000000000001122fffe334455 07 40 20 80 carplay0\n";
    Address parsed;
    REQUIRE(parseProcNetIfInet6(sample_proc, "carplay0", parsed));
    CHECK(parsed.valid());
    CHECK(parsed.isLinkLocal());
    CHECK_EQ(7U, parsed.scopeId());
    CHECK_EQ(std::string("fe80::11:22ff:fe33:4455%7"), parsed.hostString());
    CHECK(!parseProcNetIfInet6(sample_proc, "eth0", parsed));
}

TEST_CASE(posixSysfsEnumerationOnTempTree) {
#ifdef __linux__
    char tmpl[] = "/tmp/carplay_sysfs_XXXXXX";
    char* root = mkdtemp(tmpl);
    REQUIRE(root != NULL);

    const std::string base(root);
    const std::string dev_dir = base + "/1-1";
    const std::string iface_dir = base + "/1-1:1.0";
    REQUIRE(mkdir(dev_dir.c_str(), 0700) == 0);
    REQUIRE(mkdir(iface_dir.c_str(), 0700) == 0);

    REQUIRE(writeTempTextFile(dev_dir + "/idVendor", "05ac\n"));
    REQUIRE(writeTempTextFile(dev_dir + "/idProduct", "12a8\n"));
    REQUIRE(writeTempTextFile(dev_dir + "/busnum", "1\n"));
    REQUIRE(writeTempTextFile(dev_dir + "/devnum", "4\n"));
    REQUIRE(writeTempTextFile(dev_dir + "/bConfigurationValue", "4\n"));
    REQUIRE(writeTempTextFile(dev_dir + "/product", "iPhone\n"));
    REQUIRE(writeTempTextFile(dev_dir + "/serial", "TESTSERIAL\n"));

    PosixUsbDevfs devfs;
    std::vector<UsbDeviceInfo> list;
    REQUIRE(devfs.enumerateDevices(base, list));
    REQUIRE(list.size() == 1U);
    CHECK_EQ(0x05acU, list[0].vendor_id);
    CHECK_EQ(0x12a8U, list[0].product_id);
    CHECK_EQ(1U, list[0].bus_num);
    CHECK_EQ(4U, list[0].dev_num);
    CHECK_EQ(4U, list[0].configuration_value);
    CHECK_EQ(std::string("iPhone"), list[0].product);
    CHECK_EQ(std::string("TESTSERIAL"), list[0].serial);

    // Cleanup temp tree
    const char* files[] = {"idVendor", "idProduct", "busnum", "devnum",
                           "bConfigurationValue", "product", "serial"};
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        unlink((dev_dir + "/" + files[i]).c_str());
    }
    rmdir(iface_dir.c_str());
    rmdir(dev_dir.c_str());
    rmdir(base.c_str());
#endif
}

TEST_CASE(usbHostHotplugAndAsyncUrbsWithReactor) {
    Reactor reactor;
    REQUIRE(reactor.init());

    FakeUsbDevfs fake_devfs;
    REQUIRE(fake_devfs.initWakeFd());

    UsbHostConfig cfg;
    cfg.hotplug_poll_ms = 20;
    UsbHost host(cfg, &fake_devfs);
    RecordingHostListener hl;
    REQUIRE(host.start(reactor, &hl));

    // Device arrives on next hotplug poll
    fake_devfs.present_info.vendor_id = usb::kAppleVendorId;
    fake_devfs.present_info.product_id = 0x12a8U;
    fake_devfs.present_info.bus_num = 1U;
    fake_devfs.present_info.dev_num = 3U;
    fake_devfs.present_info.configuration_value = 1U;
    fake_devfs.raw_descriptors = buildSyntheticCarPlayBlob(true);
    fake_devfs.device_present = true;

    for (int i = 0; i < 10 && hl.arrived == 0; ++i) {
        reactor.runOnce(30);
    }
    REQUIRE(hl.arrived == 1);
    CHECK(host.isDeviceOpen());

    // String descriptor + Apple CarPlay switch hook
    std::string mac_s;
    REQUIRE(host.readStringDescriptor(4U, mac_s));
    CHECK_EQ(std::string("021122334455"), mac_s);
    REQUIRE(host.requestCarPlayModeSwitch(AppleCarPlaySwitchRequest()));
    CHECK_EQ(1, fake_devfs.switch_calls);

    // Submit Bulk IN URB, complete it; Reactor dispatches kPollOut -> onWritable -> reap
    const uint64_t urb_id = host.submitBulkIn(0x81U, 512U, NULL);
    REQUIRE(urb_id != 0U);
    const std::vector<uint8_t> payload(4, 0xabU);
    fake_devfs.completeNextUrb(0, payload);
    reactor.runOnce(20);
    CHECK_EQ(1, hl.urbs_completed);
    CHECK_BYTES_EQ(payload, hl.last_rx);

    // Simulate unplug from sysfs (wait on wall-clock since fake socketpair is always kPollOut)
    fake_devfs.device_present = false;
    PollSet sleep_ps;
    const int64_t deadline_ms = monotonicMillis() + 500;
    while (hl.removed == 0 && monotonicMillis() < deadline_ms) {
        sleep_ps.wait(NULL, 0, 5);
        reactor.runOnce(20);
    }
    CHECK_EQ(1, hl.removed);
    CHECK(!host.isDeviceOpen());
    host.stop();
}

TEST_CASE(tapIfaceReactorBackpressureAndOptionalRealTun) {
    Reactor reactor;
    REQUIRE(reactor.init());

    FakeTapOs fake_os;
    REQUIRE(fake_os.initSockets());

    TapConfig cfg;
    cfg.interface_name = "carplay0";
    cfg.mac_seed = 987654321ULL;
    cfg.max_tx_queue_frames = 2U;

    TapIface tap(cfg, &fake_os);
    RecordingTapListener tl;
    REQUIRE(tap.open(reactor, &tl));
    CHECK(tap.isOpen());
    CHECK_EQ(std::string("carplay0"), tap.interfaceName());
    CHECK_EQ(42U, tap.ifIndex());
    CHECK((fake_os.mac_configured[0] & 0x03U) == 0x02U);

    // Inbound frame from kernel -> Reactor kPollIn -> onTapFrame
    const std::vector<uint8_t> f1 = makeEthFrame(0x11U, 40U);
    fake_os.pushInboundFrame(f1);
    reactor.runOnce(20);
    REQUIRE(tl.frames.size() == 1U);
    CHECK_BYTES_EQ(f1, tl.frames[0]);

    // Outbound immediate write
    const std::vector<uint8_t> f2 = makeEthFrame(0x22U, 50U);
    CHECK_EQ(kTapWriteSent, tap.writeFrame(&f2[0], f2.size()));
    REQUIRE(fake_os.tx_frames.size() == 1U);

    // Backpressure: EAGAIN queues up to 2, 3rd is dropped, then kPollOut drains
    fake_os.would_block_writes = true;
    CHECK_EQ(kTapWriteQueued, tap.writeFrame(&f2[0], f2.size()));
    CHECK_EQ(kTapWriteQueued, tap.writeFrame(&f2[0], f2.size()));
    CHECK_EQ(kTapWriteDroppedQueueFull, tap.writeFrame(&f2[0], f2.size()));
    CHECK_EQ(2U, tap.queuedTxFrames());

    fake_os.would_block_writes = false;
    reactor.runOnce(20);
    CHECK_EQ(0U, tap.queuedTxFrames());
    CHECK_EQ(3U, fake_os.tx_frames.size());

    tap.close();
    CHECK(!tap.isOpen());

    // Best-effort check against real /dev/net/tun (gracefully skipped without CAP_NET_ADMIN)
#ifdef __linux__
    PosixTapOs real_os;
    SocketHandle real_fd = kInvalidSocket;
    std::string real_name;
    if (real_os.openTap("/dev/net/tun", "cptest0", real_fd, real_name)) {
        real_os.closeTap(real_fd);
    }
#endif
}

TEST_CASE(bridgeArrivalIap2AndNcmBidirectionalRoundTrip) {
    Reactor reactor;
    REQUIRE(reactor.init());

    FakeUsbHost fake_usb;
    FakeTapPort fake_tap;
    UsbCarPlayBridge bridge(fake_usb, fake_tap);
    RecordingBridgeListener listener;

    REQUIRE(bridge.start(reactor, &listener));
    CHECK_EQ(kBridgeWaiting, bridge.state());

    // 1. Device arrival with iAP2 + CDC-NCM (initially on config 1, selector chooses config 4)
    fake_usb.simulateArrival(buildSyntheticCarPlayBlob(true), 1U);
    CHECK_EQ(kBridgeActive, bridge.state());
    CHECK_EQ(1, fake_usb.set_cfg_calls_);
    CHECK_EQ(1, listener.iap2_ready_count);
    CHECK_EQ(1, listener.ncm_ready_count);
    CHECK(fake_tap.isOpen());
    CHECK(bridge.hasDeviceNcmMac());
    uint8_t dev_mac[6];
    bridge.getDeviceNcmMac(dev_mac);
    CHECK_EQ(0xaaU, dev_mac[1]);

    // Verify NCM control setup happened
    CHECK(!fake_usb.set_ntb_input_sizes_.empty());
    CHECK(!fake_usb.packet_filters_.empty());
    CHECK_EQ(2U, fake_usb.inflightCountOnEp(0x81U));  // iAP2 Bulk IN URBs
    CHECK_EQ(4U, fake_usb.inflightCountOnEp(0x83U));  // NCM Bulk IN URBs

    // 2. iAP2 bidirectional CSM frame exchange
    iap2::Frame out_msg;
    out_msg.message_id = iap2::msg::kStartIdentification;
    std::vector<uint8_t> out_wire;
    REQUIRE(out_msg.encode(out_wire));
    REQUIRE(bridge.writeIap2(&out_wire[0], out_wire.size()));
    REQUIRE(fake_usb.sent_out_.size() == 1U);
    CHECK_EQ(0x01U, fake_usb.sent_out_[0].ep);
    CHECK_BYTES_EQ(out_wire, fake_usb.sent_out_[0].data);
    // Complete iAP2 Bulk OUT URB
    CHECK(fake_usb.completeFirstUrbOnEp(0x01U, 0, std::vector<uint8_t>()));

    // Inbound iAP2 CSM frame in 2 chunks -> CsmFramer reassembles
    iap2::Frame in_msg;
    in_msg.message_id = iap2::msg::kIdentificationAccepted;
    std::vector<uint8_t> in_wire;
    REQUIRE(in_msg.encode(in_wire));
    const size_t split = in_wire.size() / 2U;
    CHECK(fake_usb.completeFirstUrbOnEp(
        0x81U, 0, std::vector<uint8_t>(in_wire.begin(), in_wire.begin() + split)));
    CHECK(fake_usb.completeFirstUrbOnEp(
        0x81U, 0, std::vector<uint8_t>(in_wire.begin() + split, in_wire.end())));
    CHECK_EQ(2U, fake_usb.inflightCountOnEp(0x81U));  // re-submitted!

    iap2::CsmFramer framer;
    std::vector<iap2::Frame> parsed_iap2;
    REQUIRE(framer.push(&listener.iap2_rx[0], listener.iap2_rx.size(), parsed_iap2));
    REQUIRE(parsed_iap2.size() == 1U);
    CHECK_EQ(iap2::msg::kIdentificationAccepted, parsed_iap2[0].message_id);

    // 3. NCM Bulk IN (3 Ethernet frames in 1 NTB) -> FakeTapPort
    std::vector<std::vector<uint8_t> > in_eth;
    in_eth.push_back(makeEthFrame(1U, 42U));
    in_eth.push_back(makeEthFrame(2U, 100U));
    in_eth.push_back(makeEthFrame(3U, 300U));
    std::vector<uint8_t> in_ntb;
    REQUIRE(ncm::buildNtb16(in_eth, 1U, ncm::NtbBuildOptions(), in_ntb));
    CHECK(fake_usb.completeFirstUrbOnEp(0x83U, 0, in_ntb));
    CHECK_EQ(4U, fake_usb.inflightCountOnEp(0x83U));  // re-submitted!
    REQUIRE(fake_tap.rx_from_usb.size() == 3U);
    for (size_t i = 0; i < 3U; ++i) {
        CHECK_BYTES_EQ(in_eth[i], fake_tap.rx_from_usb[i]);
    }

    // 4. TAP -> NCM Bulk OUT (verify NTB16 batching when OUT URBs are saturated!)
    fake_usb.sent_out_.clear();
    const std::vector<uint8_t> out_eth1 = makeEthFrame(0x51U, 60U);
    const std::vector<uint8_t> out_eth2 = makeEthFrame(0x52U, 70U);
    const std::vector<uint8_t> out_eth3 = makeEthFrame(0x53U, 80U);
    const std::vector<uint8_t> out_eth4 = makeEthFrame(0x54U, 90U);
    // First two frames go immediately into the 2 allowed in-flight OUT URBs
    fake_tap.injectFromKernel(out_eth1);
    fake_tap.injectFromKernel(out_eth2);
    CHECK_EQ(2U, fake_usb.inflightCountOnEp(0x03U));
    // Next two queue while both OUT URBs are in flight, then get batched into ONE NTB!
    fake_tap.injectFromKernel(out_eth3);
    fake_tap.injectFromKernel(out_eth4);
    CHECK_EQ(2U, fake_usb.sent_out_.size());

    // Complete first OUT URB -> triggers batched pump of out_eth3 + out_eth4 in one NTB!
    CHECK(fake_usb.completeFirstUrbOnEp(0x03U, 0, std::vector<uint8_t>()));
    REQUIRE(fake_usb.sent_out_.size() == 3U);
    ncm::Ntb16Frame decoded_batch;
    REQUIRE(ncm::parseNtb16(&fake_usb.sent_out_[2].data[0], fake_usb.sent_out_[2].data.size(),
                            ncm::NtbParseOptions(), decoded_batch));
    REQUIRE(decoded_batch.datagrams.size() == 2U);
    CHECK_BYTES_EQ(out_eth3, decoded_batch.datagrams[0]);
    CHECK_BYTES_EQ(out_eth4, decoded_batch.datagrams[1]);

    bridge.stop();
    CHECK_EQ(kBridgeStopped, bridge.state());
    CHECK(!fake_tap.isOpen());
}

TEST_CASE(bridgeIap2OnlyVendorSwitchAndReplug) {
    Reactor reactor;
    REQUIRE(reactor.init());

    FakeUsbHost fake_usb;
    FakeTapPort fake_tap;
    UsbCarPlayBridgeConfig cfg;
    cfg.auto_request_carplay_switch = true;
    UsbCarPlayBridge bridge(fake_usb, fake_tap, cfg);
    RecordingBridgeListener listener;

    REQUIRE(bridge.start(reactor, &listener));

    // Arrival with iAP2 only (no NCM): enters kBridgeIap2Only and sends vendor switch request
    fake_usb.simulateArrival(buildSyntheticCarPlayBlob(false), 1U);
    CHECK_EQ(kBridgeIap2Only, bridge.state());
    CHECK_EQ(1, fake_usb.switch_calls_);
    CHECK(!fake_tap.isOpen());
    CHECK_EQ(1, listener.iap2_ready_count);
    CHECK_EQ(0, listener.ncm_ready_count);

    // iAP2 still works in kBridgeIap2Only
    const uint8_t ping[] = {0x40, 0x40, 0x00, 0x06, 0x1d, 0x00};
    CHECK(bridge.writeIap2(ping, sizeof(ping)));
    CHECK_EQ(1U, fake_usb.sent_out_.size());

    // Simulate re-enumeration into CarPlay NCM mode
    fake_usb.simulateRemoval();
    CHECK_EQ(kBridgeWaiting, bridge.state());
    CHECK_EQ(1, listener.removed_count);

    fake_usb.simulateArrival(buildSyntheticCarPlayBlob(true), 1U);
    CHECK_EQ(kBridgeActive, bridge.state());
    CHECK(fake_tap.isOpen());
    CHECK_EQ(1, listener.ncm_ready_count);
    bridge.stop();
}

TEST_CASE(bridgeMidTransferRemovalAndMalformedNtbRecovery) {
    Reactor reactor;
    REQUIRE(reactor.init());

    FakeUsbHost fake_usb;
    FakeTapPort fake_tap;
    UsbCarPlayBridge bridge(fake_usb, fake_tap);
    RecordingBridgeListener listener;
    REQUIRE(bridge.start(reactor, &listener));

    fake_usb.simulateArrival(buildSyntheticCarPlayBlob(true), 4U);
    REQUIRE(bridge.state() == kBridgeActive);

    // 1. Malformed IN NTB is dropped gracefully without breaking bridge or URB loop
    const std::vector<uint8_t> garbage(64U, 0xeeU);
    CHECK(fake_usb.completeFirstUrbOnEp(0x83U, 0, garbage));
    CHECK_EQ(kBridgeActive, bridge.state());
    CHECK_EQ(1U, bridge.stats().ncm_rx_errors);
    CHECK_EQ(4U, fake_usb.inflightCountOnEp(0x83U));

    // 2. Oversized TAP frame is dropped cleanly
    const std::vector<uint8_t> huge_frame(2000U, 0x55U);
    fake_tap.injectFromKernel(huge_frame);
    CHECK_EQ(1U, bridge.stats().usb_tx_drops);

    // 3. Mid-transfer disconnect via -ENODEV URB completion tears down cleanly
    CHECK(fake_usb.completeFirstUrbOnEp(0x81U, -ENODEV, std::vector<uint8_t>()));
    CHECK_EQ(kBridgeWaiting, bridge.state());
    CHECK(!fake_tap.isOpen());
    CHECK(!fake_usb.isDeviceOpen());
    CHECK_EQ(1, listener.removed_count);

    // Re-plug after mid-transfer disconnect still works
    fake_usb.simulateArrival(buildSyntheticCarPlayBlob(true), 4U);
    CHECK_EQ(kBridgeActive, bridge.state());
    CHECK(fake_tap.isOpen());
    bridge.stop();
}

int main() { return test_support::runAll("test_usb_bridge"); }
