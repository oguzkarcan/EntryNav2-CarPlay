// Derived in part from DiPlay-main:
//   shared/src/main/java/com/shilapi/xcertplay/transport/IphoneUsbHost.kt
//   shared/src/main/java/com/shilapi/xcertplay/transport/UsbConfigurationSelection.kt
// GPL-3.0, Copyright (c) DiPlay contributors.
// Derived from EntryNav2-Android-Auto 0.12.0 platform/usb_devfs.cpp, platform/usb_accessory.cpp,
// platform/usb_loop.cpp, PolyForm Noncommercial License 1.0.0.

#include "carplay/platform/usb_host.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "carplay/platform/log.hpp"

#ifdef __linux__
#include <dirent.h>
#include <fcntl.h>
#include <linux/usbdevice_fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace carplay {
namespace platform {

namespace {

#ifdef __linux__
bool readSmallTextFile(const std::string& path, std::string& out) {
    out.clear();
    int fd;
    do {
        fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return false;
    }
    char buf[512];
    ssize_t r;
    do {
        r = read(fd, buf, sizeof(buf) - 1U);
    } while (r < 0 && errno == EINTR);
    close(fd);
    if (r <= 0) {
        return false;
    }
    buf[r] = '\0';
    out.assign(buf, static_cast<size_t>(r));
    while (!out.empty() &&
           (out[out.size() - 1U] == '\n' || out[out.size() - 1U] == '\r' ||
            out[out.size() - 1U] == ' ' || out[out.size() - 1U] == '\t')) {
        out.erase(out.size() - 1U);
    }
    return true;
}

bool readRawBinaryFile(const std::string& path, size_t max_bytes, std::vector<uint8_t>& out) {
    out.clear();
    int fd;
    do {
        fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return false;
    }
    out.resize(max_bytes);
    size_t done = 0;
    while (done < max_bytes) {
        const ssize_t r = read(fd, &out[done], max_bytes - done);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            out.clear();
            return false;
        }
        if (r == 0) {
            break;
        }
        done += static_cast<size_t>(r);
    }
    close(fd);
    out.resize(done);
    return !out.empty();
}

bool parseUnsignedBase(const std::string& s, int base, unsigned long& out) {
    if (s.empty()) {
        return false;
    }
    char* end = NULL;
    errno = 0;
    const unsigned long v = std::strtoul(s.c_str(), &end, base);
    if (errno != 0 || end == s.c_str() || *end != '\0') {
        return false;
    }
    out = v;
    return true;
}

bool parseHexU16(const std::string& s, uint16_t& out) {
    unsigned long v = 0;
    if (!parseUnsignedBase(s, 16, v) || v > 0xffffUL) {
        return false;
    }
    out = static_cast<uint16_t>(v);
    return true;
}

bool parseHexU8(const std::string& s, uint8_t& out) {
    unsigned long v = 0;
    if (!parseUnsignedBase(s, 16, v) || v > 0xffUL) {
        return false;
    }
    out = static_cast<uint8_t>(v);
    return true;
}

bool parseDecU8(const std::string& s, uint8_t& out) {
    unsigned long v = 0;
    if (!parseUnsignedBase(s, 10, v) || v > 0xffUL) {
        return false;
    }
    out = static_cast<uint8_t>(v);
    return true;
}
#endif  // __linux__

std::string formatDevNodePath(const std::string& root, uint8_t bus_num, uint8_t dev_num) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "/%03u/%03u", static_cast<unsigned>(bus_num),
                  static_cast<unsigned>(dev_num));
    if (!root.empty() && root[root.size() - 1U] == '/') {
        return root.substr(0, root.size() - 1U) + buf;
    }
    return root + buf;
}

bool isDisconnectErrno(int err) {
#ifdef ENODEV
    if (err == ENODEV) {
        return true;
    }
#endif
#ifdef ESHUTDOWN
    if (err == ESHUTDOWN) {
        return true;
    }
#endif
    return false;
}

}  // namespace

// Derived from EntryNav2-Android-Auto 0.12.0 platform/usb_accessory.cpp (validUsbPort).
bool isValidUsbPortName(const std::string& port) {
    size_t i = 0;
    const size_t n = port.size();
    if (n == 0U || n > 32U) {
        return false;
    }
    for (unsigned part = 0U;; ++part) {
        const size_t start = i;
        while (i < n && port[i] >= '0' && port[i] <= '9') {
            ++i;
        }
        if (i == start) {
            return false;
        }
        if (i == n) {
            return part >= 1U;
        }
        if (port[i] != (part == 0U ? '-' : '.')) {
            return false;
        }
        ++i;
    }
}

// ------------------------------------------------------------------------------------------------
// PosixUsbDevfs
// ------------------------------------------------------------------------------------------------

struct PosixUsbDevfs::Impl {
    int last_errno;

    Impl() : last_errno(0) {}

#ifdef __linux__
    struct KernelUrb {
        int fd;
        uint64_t urb_id;
        bool is_in;
        struct usbdevfs_urb* urb;
        std::vector<uint8_t> buffer;

        KernelUrb()
            : fd(-1),
              urb_id(0),
              is_in(false),
              urb(static_cast<struct usbdevfs_urb*>(std::calloc(1U, sizeof(struct usbdevfs_urb)))) {}

        ~KernelUrb() { std::free(urb); }

    private:
        KernelUrb(const KernelUrb&) = delete;
        KernelUrb& operator=(const KernelUrb&) = delete;
    };

    std::vector<KernelUrb*> active_urbs;
#endif
};

PosixUsbDevfs::PosixUsbDevfs() : impl_(new Impl()) {}

PosixUsbDevfs::~PosixUsbDevfs() {
#ifdef __linux__
    for (size_t i = 0; i < impl_->active_urbs.size(); ++i) {
        delete impl_->active_urbs[i];
    }
    impl_->active_urbs.clear();
#endif
    delete impl_;
}

int PosixUsbDevfs::lastErrno() const { return impl_->last_errno; }

bool PosixUsbDevfs::enumerateDevices(const std::string& sysfs_root,
                                     std::vector<UsbDeviceInfo>& out) {
    out.clear();
    impl_->last_errno = 0;
#ifndef __linux__
    (void)sysfs_root;
    return false;
#else
    DIR* dir = opendir(sysfs_root.c_str());
    if (dir == NULL) {
        impl_->last_errno = errno;
        return false;
    }
    struct dirent* ent = NULL;
    while ((ent = readdir(dir)) != NULL) {
        const std::string name(ent->d_name);
        if (!isValidUsbPortName(name)) {
            continue;
        }
        const std::string dev_dir =
            (!sysfs_root.empty() && sysfs_root[sysfs_root.size() - 1U] == '/')
                ? (sysfs_root + name)
                : (sysfs_root + "/" + name);

        std::string s_vid, s_pid, s_bus, s_dev;
        if (!readSmallTextFile(dev_dir + "/idVendor", s_vid) ||
            !readSmallTextFile(dev_dir + "/idProduct", s_pid) ||
            !readSmallTextFile(dev_dir + "/busnum", s_bus) ||
            !readSmallTextFile(dev_dir + "/devnum", s_dev)) {
            continue;
        }

        UsbDeviceInfo info;
        if (!parseHexU16(s_vid, info.vendor_id) || !parseHexU16(s_pid, info.product_id) ||
            !parseDecU8(s_bus, info.bus_num) || !parseDecU8(s_dev, info.dev_num)) {
            continue;
        }

        info.sysfs_name = name;
        info.sysfs_path = dev_dir;

        std::string tmp;
        if (readSmallTextFile(dev_dir + "/bConfigurationValue", tmp)) {
            parseDecU8(tmp, info.configuration_value);
        }
        if (readSmallTextFile(dev_dir + "/bDeviceClass", tmp)) {
            parseHexU8(tmp, info.device_class);
        }
        if (readSmallTextFile(dev_dir + "/bDeviceSubClass", tmp)) {
            parseHexU8(tmp, info.device_subclass);
        }
        if (readSmallTextFile(dev_dir + "/bDeviceProtocol", tmp)) {
            parseHexU8(tmp, info.device_protocol);
        }
        if (readSmallTextFile(dev_dir + "/removable", tmp)) {
            info.is_fixed = (tmp == "fixed");
        }
        readSmallTextFile(dev_dir + "/manufacturer", info.manufacturer);
        readSmallTextFile(dev_dir + "/product", info.product);
        readSmallTextFile(dev_dir + "/serial", info.serial);
        readSmallTextFile(dev_dir + "/speed", info.speed);

        out.push_back(info);
    }
    closedir(dir);
    return true;
#endif
}

bool PosixUsbDevfs::openDevice(const std::string& dev_path,
                               const std::string& sysfs_path,
                               SocketHandle& fd_out,
                               std::vector<uint8_t>& raw_descriptors_out) {
    fd_out = kInvalidSocket;
    raw_descriptors_out.clear();
    impl_->last_errno = 0;
#ifndef __linux__
    (void)dev_path;
    (void)sysfs_path;
    return false;
#else
    int fd;
    do {
        fd = open(dev_path.c_str(), O_RDWR | O_CLOEXEC | O_NONBLOCK);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        const int err = errno;
        impl_->last_errno = err;
        CARPLAY_LOG_WARN("usb", "open(%s) failed: %s (%d)", dev_path.c_str(), strerror(err), err);
        return false;
    }

    static const size_t kMaxDescBytes = 65536U;
    std::vector<uint8_t> buf(kMaxDescBytes, 0U);
    size_t done = 0;
    while (done < kMaxDescBytes) {
        const ssize_t r = read(fd, &buf[done], kMaxDescBytes - done);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            impl_->last_errno = errno;
            break;
        }
        if (r == 0) {
            break;
        }
        done += static_cast<size_t>(r);
    }
    buf.resize(done);

    if (buf.size() < 18U && !sysfs_path.empty()) {
        readRawBinaryFile(sysfs_path + "/descriptors", kMaxDescBytes, buf);
    }
    if (buf.size() < 18U) {
        if (impl_->last_errno == 0) {
            impl_->last_errno = EIO;
        }
        CARPLAY_LOG_ERROR("usb", "failed to read USB descriptors from %s", dev_path.c_str());
        close(fd);
        return false;
    }

    impl_->last_errno = 0;
    fd_out = fd;
    raw_descriptors_out.swap(buf);
    return true;
#endif
}

void PosixUsbDevfs::closeDevice(SocketHandle fd) {
#ifndef __linux__
    (void)fd;
#else
    if (fd < 0) {
        return;
    }
    // Closing the usbfs fd detaches all kernel URBs synchronously before we free KernelUrb memory.
    ::close(fd);

    size_t w = 0;
    for (size_t i = 0; i < impl_->active_urbs.size(); ++i) {
        Impl::KernelUrb* ku = impl_->active_urbs[i];
        if (ku->fd == fd) {
            delete ku;
        } else {
            impl_->active_urbs[w++] = ku;
        }
    }
    impl_->active_urbs.resize(w);
#endif
}

bool PosixUsbDevfs::controlTransfer(SocketHandle fd,
                                    uint8_t request_type,
                                    uint8_t request,
                                    uint16_t value,
                                    uint16_t index,
                                    uint8_t* data,
                                    uint16_t length,
                                    uint32_t timeout_ms,
                                    int& transferred_out) {
    transferred_out = 0;
    impl_->last_errno = 0;
#ifndef __linux__
    (void)fd;
    (void)request_type;
    (void)request;
    (void)value;
    (void)index;
    (void)data;
    (void)length;
    (void)timeout_ms;
    return false;
#else
    if (fd < 0) {
        impl_->last_errno = EBADF;
        return false;
    }
    struct usbdevfs_ctrltransfer ctrl;
    std::memset(&ctrl, 0, sizeof(ctrl));
    ctrl.bRequestType = request_type;
    ctrl.bRequest = request;
    ctrl.wValue = value;
    ctrl.wIndex = index;
    ctrl.wLength = length;
    ctrl.timeout = timeout_ms;
    ctrl.data = data;

    int rc;
    do {
        rc = ioctl(fd, USBDEVFS_CONTROL, &ctrl);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        const int err = errno;
        impl_->last_errno = err;
        CARPLAY_LOG_WARN("usb", "USBDEVFS_CONTROL(type=0x%02x req=0x%02x) failed: %s (%d)",
                         static_cast<unsigned>(request_type), static_cast<unsigned>(request),
                         strerror(err), err);
        return false;
    }
    transferred_out = rc;
    return true;
#endif
}

bool PosixUsbDevfs::setConfiguration(SocketHandle fd, uint8_t configuration_value) {
    impl_->last_errno = 0;
#ifndef __linux__
    (void)fd;
    (void)configuration_value;
    return false;
#else
    if (fd < 0) {
        impl_->last_errno = EBADF;
        return false;
    }
    unsigned int cfg = configuration_value;
    int rc;
    do {
        rc = ioctl(fd, USBDEVFS_SETCONFIGURATION, &cfg);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        const int err = errno;
        impl_->last_errno = err;
        CARPLAY_LOG_WARN("usb", "USBDEVFS_SETCONFIGURATION(%u) failed: %s (%d)", cfg, strerror(err),
                         err);
        return false;
    }
    return true;
#endif
}

bool PosixUsbDevfs::getInterfaceDriver(SocketHandle fd,
                                       uint8_t interface_number,
                                       std::string& driver_out) {
    driver_out.clear();
    impl_->last_errno = 0;
#ifndef __linux__
    (void)fd;
    (void)interface_number;
    return false;
#else
    if (fd < 0) {
        impl_->last_errno = EBADF;
        return false;
    }
    struct usbdevfs_getdriver gd;
    std::memset(&gd, 0, sizeof(gd));
    gd.interface = interface_number;
    int rc;
    do {
        rc = ioctl(fd, USBDEVFS_GETDRIVER, &gd);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        const int err = errno;
        if (err == ENODATA || err == ENOENT) {
            return true;
        }
        impl_->last_errno = err;
        CARPLAY_LOG_DEBUG("usb", "USBDEVFS_GETDRIVER(if=%u) failed: %s (%d)",
                          static_cast<unsigned>(interface_number), strerror(err), err);
        return false;
    }
    gd.driver[sizeof(gd.driver) - 1U] = '\0';
    driver_out = gd.driver;
    return true;
#endif
}

bool PosixUsbDevfs::claimInterface(SocketHandle fd, uint8_t interface_number, bool detach_driver) {
    impl_->last_errno = 0;
#ifndef __linux__
    (void)fd;
    (void)interface_number;
    (void)detach_driver;
    return false;
#else
    if (fd < 0) {
        impl_->last_errno = EBADF;
        return false;
    }
    if (detach_driver) {
        // Use USBDEVFS_IOCTL + USBDEVFS_DISCONNECT (supported on kernel 2.6+ / wheezy headers,
        // unlike USBDEVFS_DISCONNECT_CLAIM which requires Linux 3.6+ headers).
        struct usbdevfs_ioctl cmd;
        std::memset(&cmd, 0, sizeof(cmd));
        cmd.ifno = static_cast<int>(interface_number);
        cmd.ioctl_code = USBDEVFS_DISCONNECT;
        cmd.data = NULL;
        int d_rc;
        do {
            d_rc = ioctl(fd, USBDEVFS_IOCTL, &cmd);
        } while (d_rc < 0 && errno == EINTR);
        if (d_rc < 0 && errno != ENODATA && errno != ENOENT) {
            const int d_err = errno;
            CARPLAY_LOG_DEBUG("usb", "USBDEVFS_DISCONNECT(if=%u) returned %s (%d)",
                              static_cast<unsigned>(interface_number), strerror(d_err), d_err);
        }
    }
    unsigned int ifno = interface_number;
    int rc;
    do {
        rc = ioctl(fd, USBDEVFS_CLAIMINTERFACE, &ifno);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        const int err = errno;
        impl_->last_errno = err;
        CARPLAY_LOG_WARN("usb", "USBDEVFS_CLAIMINTERFACE(%u) failed: %s (%d)", ifno, strerror(err),
                         err);
        return false;
    }
    return true;
#endif
}

bool PosixUsbDevfs::releaseInterface(SocketHandle fd, uint8_t interface_number) {
    impl_->last_errno = 0;
#ifndef __linux__
    (void)fd;
    (void)interface_number;
    return false;
#else
    if (fd < 0) {
        impl_->last_errno = EBADF;
        return false;
    }
    unsigned int ifno = interface_number;
    int rc;
    do {
        rc = ioctl(fd, USBDEVFS_RELEASEINTERFACE, &ifno);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        impl_->last_errno = errno;
        return false;
    }
    return true;
#endif
}

bool PosixUsbDevfs::setInterface(SocketHandle fd, uint8_t interface_number, uint8_t alt_setting) {
    impl_->last_errno = 0;
#ifndef __linux__
    (void)fd;
    (void)interface_number;
    (void)alt_setting;
    return false;
#else
    if (fd < 0) {
        impl_->last_errno = EBADF;
        return false;
    }
    struct usbdevfs_setinterface si;
    std::memset(&si, 0, sizeof(si));
    si.interface = interface_number;
    si.altsetting = alt_setting;
    int rc;
    do {
        rc = ioctl(fd, USBDEVFS_SETINTERFACE, &si);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        const int err = errno;
        impl_->last_errno = err;
        CARPLAY_LOG_WARN("usb", "USBDEVFS_SETINTERFACE(%u, alt=%u) failed: %s (%d)",
                         static_cast<unsigned>(interface_number),
                         static_cast<unsigned>(alt_setting), strerror(err), err);
        return false;
    }
    return true;
#endif
}

bool PosixUsbDevfs::resetDevice(SocketHandle fd) {
    impl_->last_errno = 0;
#ifndef __linux__
    (void)fd;
    return false;
#else
    if (fd < 0) {
        impl_->last_errno = EBADF;
        return false;
    }
    int rc;
    do {
        rc = ioctl(fd, USBDEVFS_RESET, 0);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        const int err = errno;
        impl_->last_errno = err;
        CARPLAY_LOG_WARN("usb", "USBDEVFS_RESET failed: %s (%d)", strerror(err), err);
        return false;
    }
    return true;
#endif
}

bool PosixUsbDevfs::submitBulkUrb(SocketHandle fd,
                                  const UsbUrbSubmit& req,
                                  uint64_t urb_id,
                                  uintptr_t& os_token_out) {
    os_token_out = 0;
    impl_->last_errno = 0;
#ifndef __linux__
    (void)fd;
    (void)req;
    (void)urb_id;
    return false;
#else
    if (fd < 0) {
        impl_->last_errno = EBADF;
        return false;
    }
    static const size_t kMaxUsbfsUrbBytes = 16U * 1024U * 1024U;
    const size_t buf_len = req.is_in ? req.in_length : req.data.size();
    if ((req.is_in && buf_len == 0U) || buf_len > kMaxUsbfsUrbBytes) {
        impl_->last_errno = EINVAL;
        return false;
    }

    Impl::KernelUrb* ku = new Impl::KernelUrb();
    if (ku->urb == NULL) {
        impl_->last_errno = ENOMEM;
        delete ku;
        return false;
    }
    ku->fd = fd;
    ku->urb_id = urb_id;
    ku->is_in = req.is_in;
    if (req.is_in) {
        ku->buffer.assign(buf_len, 0U);
    } else {
        ku->buffer = req.data;
    }

    ku->urb->type = USBDEVFS_URB_TYPE_BULK;
    ku->urb->endpoint = req.endpoint;
    ku->urb->flags = req.zero_packet ? USBDEVFS_URB_ZERO_PACKET : 0U;
    ku->urb->buffer = ku->buffer.empty() ? NULL : &ku->buffer[0];
    ku->urb->buffer_length = static_cast<int>(ku->buffer.size());
    ku->urb->usercontext = ku;

    impl_->active_urbs.push_back(ku);

    int rc;
    do {
        rc = ioctl(fd, USBDEVFS_SUBMITURB, ku->urb);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        const int err = errno;
        impl_->last_errno = err;
        CARPLAY_LOG_WARN("usb", "USBDEVFS_SUBMITURB(ep=0x%02x) failed: %s (%d)",
                         static_cast<unsigned>(req.endpoint), strerror(err), err);
        impl_->active_urbs.pop_back();
        delete ku;
        return false;
    }

    os_token_out = reinterpret_cast<uintptr_t>(ku);
    return true;
#endif
}

UsbReapStatus PosixUsbDevfs::reapUrb(SocketHandle fd, UsbUrbCompletion& out) {
    out = UsbUrbCompletion();
    impl_->last_errno = 0;
#ifndef __linux__
    (void)fd;
    return kUsbReapError;
#else
    if (fd < 0) {
        impl_->last_errno = EBADF;
        return kUsbReapError;
    }
    void* raw_urb = NULL;
    int rc;
    do {
        rc = ioctl(fd, USBDEVFS_REAPURBNDELAY, &raw_urb);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        const int err = errno;
        impl_->last_errno = err;
        if (err == EAGAIN) {
            return kUsbReapEmpty;
        }
        if (isDisconnectErrno(err) || err == ENOENT) {
            return kUsbReapDisconnected;
        }
        return kUsbReapError;
    }
    if (raw_urb == NULL) {
        return kUsbReapError;
    }
    struct usbdevfs_urb* k_urb = static_cast<struct usbdevfs_urb*>(raw_urb);
    Impl::KernelUrb* ku = static_cast<Impl::KernelUrb*>(k_urb->usercontext);

    size_t idx = impl_->active_urbs.size();
    for (size_t i = 0; i < impl_->active_urbs.size(); ++i) {
        if (impl_->active_urbs[i] == ku) {
            idx = i;
            break;
        }
    }
    if (idx == impl_->active_urbs.size()) {
        return kUsbReapError;
    }
    impl_->active_urbs.erase(impl_->active_urbs.begin() + static_cast<ptrdiff_t>(idx));

    out.urb_id = ku->urb_id;
    out.os_token = reinterpret_cast<uintptr_t>(ku);
    out.endpoint = k_urb->endpoint;
    out.is_in = ku->is_in;
    out.status = k_urb->status;
    if (ku->is_in && k_urb->actual_length > 0) {
        const size_t n = static_cast<size_t>(k_urb->actual_length) <= ku->buffer.size()
                             ? static_cast<size_t>(k_urb->actual_length)
                             : ku->buffer.size();
        out.data.assign(ku->buffer.begin(), ku->buffer.begin() + static_cast<ptrdiff_t>(n));
    }

    delete ku;
    return kUsbReapOk;
#endif
}

bool PosixUsbDevfs::discardUrb(SocketHandle fd, uintptr_t os_token) {
    impl_->last_errno = 0;
#ifndef __linux__
    (void)fd;
    (void)os_token;
    return false;
#else
    if (fd < 0 || os_token == 0) {
        impl_->last_errno = EINVAL;
        return false;
    }
    Impl::KernelUrb* target = reinterpret_cast<Impl::KernelUrb*>(os_token);
    bool found = false;
    for (size_t i = 0; i < impl_->active_urbs.size(); ++i) {
        if (impl_->active_urbs[i] == target && target->fd == fd) {
            found = true;
            break;
        }
    }
    if (!found || target->urb == NULL) {
        impl_->last_errno = ENOENT;
        return false;
    }
    int rc;
    do {
        rc = ioctl(fd, USBDEVFS_DISCARDURB, target->urb);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        impl_->last_errno = errno;
        return false;
    }
    return true;
#endif
}

// ------------------------------------------------------------------------------------------------
// UsbHost
// ------------------------------------------------------------------------------------------------

UsbHost::UsbHost(const UsbHostConfig& config, UsbDevfsInterface* backend)
    : config_(config),
      backend_(backend != NULL ? backend : &default_backend_),
      reactor_(NULL),
      listener_(NULL),
      poll_timer_id_(Reactor::kNoTimer),
      started_(false),
      device_open_(false),
      fd_(kInvalidSocket),
      fd_registered_(false),
      last_claim_status_(kUsbClaimOk),
      next_urb_id_(1U),
      in_callback_(false) {}

UsbHost::~UsbHost() { stop(); }

bool UsbHost::start(Reactor& reactor, UsbHostListener* listener) {
    if (started_) {
        return false;
    }
    if (!reactor.initialized()) {
        return false;
    }
    reactor_ = &reactor;
    listener_ = listener;
    started_ = true;
    if (config_.hotplug_poll_ms > 0) {
        poll_timer_id_ = reactor_->startTimer(0, config_.hotplug_poll_ms, this);
        if (poll_timer_id_ == Reactor::kNoTimer) {
            started_ = false;
            reactor_ = NULL;
            listener_ = NULL;
            return false;
        }
    }
    return true;
}

void UsbHost::stop() {
    if (poll_timer_id_ != Reactor::kNoTimer && reactor_ != NULL) {
        reactor_->cancelTimer(poll_timer_id_);
        poll_timer_id_ = Reactor::kNoTimer;
    }
    closeCurrentDevice();
    ignored_devices_.clear();
    last_claim_status_ = kUsbClaimOk;
    last_claim_driver_.clear();
    started_ = false;
    reactor_ = NULL;
    listener_ = NULL;
}

bool UsbHost::isIgnoredDevice(const UsbDeviceInfo& candidate) const {
    for (size_t i = 0; i < ignored_devices_.size(); ++i) {
        const IgnoredDevice& ig = ignored_devices_[i];
        if (ig.sysfs_name == candidate.sysfs_name && ig.bus_num == candidate.bus_num &&
            ig.dev_num == candidate.dev_num) {
            return true;
        }
    }
    return false;
}

void UsbHost::forgetGoneIgnored(const std::vector<UsbDeviceInfo>& present) {
    for (size_t i = 0; i < ignored_devices_.size();) {
        const IgnoredDevice& ig = ignored_devices_[i];
        bool still_there = false;
        for (size_t j = 0; j < present.size(); ++j) {
            if (present[j].sysfs_name == ig.sysfs_name && present[j].bus_num == ig.bus_num &&
                present[j].dev_num == ig.dev_num) {
                still_there = true;
                break;
            }
        }
        if (!still_there) {
            ignored_devices_.erase(ignored_devices_.begin() + static_cast<ptrdiff_t>(i));
        } else {
            ++i;
        }
    }
}

void UsbHost::pollHotplug() {
    if (!started_) {
        return;
    }
    std::vector<UsbDeviceInfo> devs;
    if (!backend_->enumerateDevices(config_.sysfs_devices_root, devs)) {
        return;
    }
    forgetGoneIgnored(devs);

    if (device_open_) {
        bool still_present = false;
        for (size_t i = 0; i < devs.size(); ++i) {
            if (current_info_.sameBusDev(devs[i])) {
                still_present = true;
                break;
            }
        }
        if (!still_present) {
            CARPLAY_LOG_INFO("usb", "Apple USB device %04x:%04x (%u/%u) removed from sysfs",
                             static_cast<unsigned>(current_info_.vendor_id),
                             static_cast<unsigned>(current_info_.product_id),
                             static_cast<unsigned>(current_info_.bus_num),
                             static_cast<unsigned>(current_info_.dev_num));
            handleUnexpectedDisconnect();
        }
        return;
    }

    for (size_t i = 0; i < devs.size(); ++i) {
        const UsbDeviceInfo& d = devs[i];
        if (d.vendor_id != config_.target_vendor_id) {
            continue;
        }
        if (!config_.usb_port_filter.empty() && d.sysfs_name != config_.usb_port_filter) {
            continue;
        }
        if (d.device_class == usb::kClassHub) {
            continue;
        }
        if (config_.ignore_fixed_devices && d.is_fixed) {
            continue;
        }
        if (isIgnoredDevice(d)) {
            continue;
        }
        if (tryOpenCandidate(d)) {
            break;
        }
    }
}

bool UsbHost::tryOpenCandidate(const UsbDeviceInfo& candidate) {
    last_claim_status_ = kUsbClaimOk;
    last_claim_driver_.clear();

    UsbDeviceInfo info = candidate;
    if (info.dev_path.empty()) {
        info.dev_path = formatDevNodePath(config_.dev_usb_root, info.bus_num, info.dev_num);
    }

    SocketHandle fd = kInvalidSocket;
    std::vector<uint8_t> raw_desc;
    if (!backend_->openDevice(info.dev_path, info.sysfs_path, fd, raw_desc)) {
        return false;
    }

    usb::DeviceDescriptor dev_desc;
    std::vector<usb::ConfigurationDescriptor> configs;
    std::string parse_err;
    if (!usb::parseUsbfsDescriptors(raw_desc.empty() ? NULL : &raw_desc[0], raw_desc.size(),
                                    dev_desc, configs, &parse_err)) {
        CARPLAY_LOG_WARN("usb", "descriptor parse failed for %s: %s", info.dev_path.c_str(),
                         parse_err.c_str());
        backend_->closeDevice(fd);
        return false;
    }

    if (dev_desc.device_class == usb::kClassHub) {
        CARPLAY_LOG_DEBUG("usb", "skipping USB hub device at %s", info.dev_path.c_str());
        backend_->closeDevice(fd);
        return false;
    }

    // Linux usbfs signals POLLOUT when an async URB completes, POLLERR|POLLHUP on unplug.
    bool registered = false;
    if (fd != kInvalidSocket && reactor_ != NULL) {
        if (!reactor_->add(fd, this, kPollOut)) {
            CARPLAY_LOG_ERROR("usb", "failed to register usbfs fd in Reactor");
            backend_->closeDevice(fd);
            return false;
        }
        registered = true;
    }

    device_open_ = true;
    fd_ = fd;
    fd_registered_ = registered;
    current_info_ = info;
    dev_desc_ = dev_desc;
    configs_ = configs;
    claimed_interfaces_.clear();
    pending_urbs_.clear();

    CARPLAY_LOG_INFO("usb", "opened Apple USB device %04x:%04x at %s (%u configs)",
                     static_cast<unsigned>(dev_desc_.id_vendor),
                     static_cast<unsigned>(dev_desc_.id_product),
                     current_info_.dev_path.c_str(),
                     static_cast<unsigned>(configs_.size()));

    if (listener_ != NULL) {
        in_callback_ = true;
        listener_->onUsbDeviceArrived(current_info_, dev_desc_, configs_);
        in_callback_ = false;
    }
    return true;
}

void UsbHost::ignoreCurrentDevice() {
    if (!device_open_) {
        return;
    }
    if (!isIgnoredDevice(current_info_)) {
        IgnoredDevice ig;
        ig.sysfs_name = current_info_.sysfs_name;
        ig.bus_num = current_info_.bus_num;
        ig.dev_num = current_info_.dev_num;
        ignored_devices_.push_back(ig);
    }
    CARPLAY_LOG_INFO("usb", "leaving Apple USB device %04x:%04x (%s %u/%u) alone until unplug",
                     static_cast<unsigned>(current_info_.vendor_id),
                     static_cast<unsigned>(current_info_.product_id),
                     current_info_.sysfs_name.c_str(),
                     static_cast<unsigned>(current_info_.bus_num),
                     static_cast<unsigned>(current_info_.dev_num));
    closeCurrentDevice();
}

void UsbHost::closeCurrentDevice() {
    if (!device_open_) {
        return;
    }
    for (size_t i = 0; i < pending_urbs_.size(); ++i) {
        backend_->discardUrb(fd_, pending_urbs_[i].os_token);
    }
    pending_urbs_.clear();

    for (size_t i = 0; i < claimed_interfaces_.size(); ++i) {
        backend_->releaseInterface(fd_, claimed_interfaces_[i]);
    }
    claimed_interfaces_.clear();

    if (fd_registered_ && reactor_ != NULL && fd_ != kInvalidSocket) {
        reactor_->remove(fd_);
    }
    fd_registered_ = false;

    backend_->closeDevice(fd_);
    fd_ = kInvalidSocket;
    device_open_ = false;
    current_info_ = UsbDeviceInfo();
    dev_desc_ = usb::DeviceDescriptor();
    configs_.clear();
}

void UsbHost::handleUnexpectedDisconnect() {
    if (!device_open_) {
        return;
    }
    closeCurrentDevice();
    if (listener_ != NULL) {
        in_callback_ = true;
        listener_->onUsbDeviceRemoved();
        in_callback_ = false;
    }
}

bool UsbHost::setConfiguration(uint8_t config_value) {
    if (!device_open_) {
        return false;
    }
    return backend_->setConfiguration(fd_, config_value);
}

bool UsbHost::claimInterface(uint8_t interface_number, bool detach_kernel_driver) {
    UsbClaimStatus st = kUsbClaimError;
    std::string drv;
    return claimInterfaceWithStatus(interface_number, detach_kernel_driver,
                                    config_.detach_usbfs_driver, st, drv);
}

bool UsbHost::claimInterfaceWithStatus(uint8_t interface_number,
                                       bool detach_kernel_driver,
                                       bool detach_usbfs_driver,
                                       UsbClaimStatus& status_out,
                                       std::string& driver_out) {
    status_out = kUsbClaimError;
    driver_out.clear();
    last_claim_status_ = kUsbClaimError;
    last_claim_driver_.clear();

    if (!device_open_) {
        return false;
    }
    for (size_t i = 0; i < claimed_interfaces_.size(); ++i) {
        if (claimed_interfaces_[i] == interface_number) {
            status_out = kUsbClaimOk;
            last_claim_status_ = kUsbClaimOk;
            return true;
        }
    }

    const bool got_driver = backend_->getInterfaceDriver(fd_, interface_number, driver_out);
    bool should_detach = false;
    if (got_driver && !driver_out.empty()) {
        if (driver_out == "usbfs") {
            if (!detach_usbfs_driver) {
                status_out = kUsbClaimBusyUserspace;
                last_claim_status_ = status_out;
                last_claim_driver_ = driver_out;
                CARPLAY_LOG_WARN(
                    "usb",
                    "interface %u is held by userspace driver '%s' (e.g. MediaPlayer/CARPLAY); "
                    "refusing to detach without explicit detach_usbfs_driver",
                    static_cast<unsigned>(interface_number), driver_out.c_str());
                return false;
            }
            CARPLAY_LOG_WARN("usb",
                             "detaching userspace driver '%s' on interface %u (explicitly enabled)",
                             driver_out.c_str(), static_cast<unsigned>(interface_number));
            should_detach = true;
        } else {
            if (!(detach_kernel_driver && config_.detach_kernel_driver)) {
                status_out = kUsbClaimBusyKernel;
                last_claim_status_ = status_out;
                last_claim_driver_ = driver_out;
                CARPLAY_LOG_WARN("usb",
                                 "interface %u bound to kernel driver '%s' and detach disabled",
                                 static_cast<unsigned>(interface_number), driver_out.c_str());
                return false;
            }
            should_detach = true;
        }
    }

    if (!backend_->claimInterface(fd_, interface_number, should_detach)) {
        const int err = backend_->lastErrno();
        if (err == EBUSY) {
            std::string now_drv;
            if (backend_->getInterfaceDriver(fd_, interface_number, now_drv) && !now_drv.empty()) {
                driver_out = now_drv;
            }
            if (driver_out.empty() || driver_out == "usbfs") {
                if (driver_out.empty()) {
                    driver_out = "usbfs";
                }
                status_out = kUsbClaimBusyUserspace;
            } else {
                status_out = kUsbClaimBusyKernel;
            }
        } else {
            status_out = kUsbClaimError;
        }
        last_claim_status_ = status_out;
        last_claim_driver_ = driver_out;
        return false;
    }

    claimed_interfaces_.push_back(interface_number);
    status_out = kUsbClaimOk;
    last_claim_status_ = kUsbClaimOk;
    last_claim_driver_ = driver_out;
    return true;
}

bool UsbHost::releaseInterface(uint8_t interface_number) {
    if (!device_open_) {
        return false;
    }
    const bool ok = backend_->releaseInterface(fd_, interface_number);
    for (size_t i = 0; i < claimed_interfaces_.size(); ++i) {
        if (claimed_interfaces_[i] == interface_number) {
            claimed_interfaces_.erase(claimed_interfaces_.begin() + static_cast<ptrdiff_t>(i));
            break;
        }
    }
    return ok;
}

bool UsbHost::setInterface(uint8_t interface_number, uint8_t alt_setting) {
    if (!device_open_) {
        return false;
    }
    return backend_->setInterface(fd_, interface_number, alt_setting);
}

bool UsbHost::resetDevice() {
    if (!device_open_) {
        return false;
    }
    return backend_->resetDevice(fd_);
}

bool UsbHost::controlTransfer(uint8_t request_type,
                              uint8_t request,
                              uint16_t value,
                              uint16_t index,
                              std::vector<uint8_t>& data_io,
                              uint32_t timeout_ms,
                              int* actual_len_out) {
    if (!device_open_) {
        return false;
    }
    if (data_io.size() > 0xffffU) {
        return false;
    }
    const uint16_t wlen = static_cast<uint16_t>(data_io.size());
    uint8_t* ptr = data_io.empty() ? NULL : &data_io[0];
    int transferred = 0;
    if (!backend_->controlTransfer(fd_, request_type, request, value, index, ptr, wlen,
                                   timeout_ms, transferred)) {
        return false;
    }
    if (actual_len_out != NULL) {
        *actual_len_out = transferred;
    }
    if ((request_type & 0x80U) != 0U && transferred >= 0 &&
        static_cast<size_t>(transferred) <= data_io.size()) {
        data_io.resize(static_cast<size_t>(transferred));
    }
    return true;
}

bool UsbHost::readStringDescriptor(uint8_t string_index, std::string& out) {
    out.clear();
    if (!device_open_ || string_index == 0U) {
        return false;
    }
    std::vector<uint8_t> buf(255U, 0U);
    int actual = 0;
    const uint16_t wval = static_cast<uint16_t>((static_cast<uint16_t>(usb::kDescTypeString) << 8) |
                                                string_index);
    if (!controlTransfer(0x80U, 0x06U, wval, 0x0409U, buf, 1000U, &actual)) {
        buf.assign(255U, 0U);
        if (!controlTransfer(0x80U, 0x06U, wval, 0x0000U, buf, 1000U, &actual)) {
            return false;
        }
    }
    if (buf.empty()) {
        return false;
    }
    return usb::decodeUsbStringDescriptor(&buf[0], buf.size(), out, NULL);
}

bool UsbHost::queryActiveConfiguration(uint8_t& config_value_out) {
    config_value_out = 0;
    if (!device_open_) {
        return false;
    }
    std::vector<uint8_t> buf(1U, 0U);
    int actual = 0;
    if (!controlTransfer(kUsbStandardDeviceIn, kUsbReqGetConfiguration, 0U, 0U, buf, 1000U,
                         &actual)) {
        return false;
    }
    if (actual != 1 || buf.empty()) {
        return false;
    }
    config_value_out = buf[0];
    return true;
}

bool UsbHost::queryAppleUsbMode(std::vector<uint8_t>& mode_out) {
    mode_out.clear();
    if (!device_open_) {
        return false;
    }
    std::vector<uint8_t> buf(kAppleUsbModeResponseBytes, 0U);
    int actual = 0;
    if (!controlTransfer(kUsbVendorDeviceIn, kAppleReqGetUsbMode, 0U, 0U, buf, 1000U, &actual)) {
        return false;
    }
    if (actual <= 0) {
        return false;
    }
    mode_out.swap(buf);
    return true;
}

bool UsbHost::requestCarPlayModeSwitch(const AppleCarPlaySwitchRequest& req) {
    if (!device_open_) {
        return false;
    }
    if ((req.request_type & 0x80U) != 0U && req.response_length > 0U) {
        std::vector<uint8_t> buf(req.response_length, 0U);
        int actual = 0;
        if (!controlTransfer(req.request_type, req.request, req.value, req.index, buf,
                             req.timeout_ms, &actual)) {
            return false;
        }
        return actual == static_cast<int>(req.response_length);
    }
    std::vector<uint8_t> empty;
    return controlTransfer(req.request_type, req.request, req.value, req.index, empty,
                           req.timeout_ms, NULL);
}

uint64_t UsbHost::submitBulkIn(uint8_t endpoint, size_t max_bytes, void* user_ctx) {
    if (!device_open_ || max_bytes == 0U) {
        return 0;
    }
    UsbUrbSubmit req;
    req.endpoint = endpoint;
    req.is_in = true;
    req.zero_packet = false;
    req.in_length = max_bytes;

    const uint64_t id = next_urb_id_++;
    if (next_urb_id_ == 0U) {
        next_urb_id_ = 1U;
    }
    uintptr_t token = 0;
    if (!backend_->submitBulkUrb(fd_, req, id, token)) {
        if (isDisconnectErrno(backend_->lastErrno())) {
            handleUnexpectedDisconnect();
        }
        return 0;
    }

    PendingUrb pu;
    pu.urb_id = id;
    pu.os_token = token;
    pu.endpoint = endpoint;
    pu.is_in = true;
    pu.user_ctx = user_ctx;
    pending_urbs_.push_back(pu);
    return id;
}

uint64_t UsbHost::submitBulkOut(uint8_t endpoint,
                                const uint8_t* data,
                                size_t len,
                                bool zero_packet,
                                void* user_ctx) {
    if (!device_open_) {
        return 0;
    }
    if (len > 0U && data == NULL) {
        return 0;
    }
    UsbUrbSubmit req;
    req.endpoint = endpoint;
    req.is_in = false;
    req.zero_packet = zero_packet;
    if (len > 0U) {
        req.data.assign(data, data + len);
    }

    const uint64_t id = next_urb_id_++;
    if (next_urb_id_ == 0U) {
        next_urb_id_ = 1U;
    }
    uintptr_t token = 0;
    if (!backend_->submitBulkUrb(fd_, req, id, token)) {
        if (isDisconnectErrno(backend_->lastErrno())) {
            handleUnexpectedDisconnect();
        }
        return 0;
    }

    PendingUrb pu;
    pu.urb_id = id;
    pu.os_token = token;
    pu.endpoint = endpoint;
    pu.is_in = false;
    pu.user_ctx = user_ctx;
    pending_urbs_.push_back(pu);
    return id;
}

bool UsbHost::discardUrb(uint64_t urb_id) {
    if (!device_open_ || urb_id == 0U) {
        return false;
    }
    const int idx = findPendingUrbById(urb_id);
    if (idx < 0) {
        return false;
    }
    const uintptr_t token = pending_urbs_[static_cast<size_t>(idx)].os_token;
    return backend_->discardUrb(fd_, token);
}

int UsbHost::findPendingUrbById(uint64_t urb_id) const {
    for (size_t i = 0; i < pending_urbs_.size(); ++i) {
        if (pending_urbs_[i].urb_id == urb_id) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

int UsbHost::findPendingUrbByToken(uintptr_t os_token) const {
    if (os_token == 0) {
        return -1;
    }
    for (size_t i = 0; i < pending_urbs_.size(); ++i) {
        if (pending_urbs_[i].os_token == os_token) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

void UsbHost::reapCompletedUrbs() {
    while (device_open_) {
        UsbUrbCompletion comp;
        const UsbReapStatus st = backend_->reapUrb(fd_, comp);
        if (st == kUsbReapEmpty) {
            break;
        }
        if (st == kUsbReapDisconnected || st == kUsbReapError) {
            handleUnexpectedDisconnect();
            break;
        }

        int idx = findPendingUrbById(comp.urb_id);
        if (idx < 0) {
            idx = findPendingUrbByToken(comp.os_token);
        }
        if (idx < 0) {
            continue;
        }
        const PendingUrb pu = pending_urbs_[static_cast<size_t>(idx)];
        pending_urbs_.erase(pending_urbs_.begin() + static_cast<ptrdiff_t>(idx));

        if (listener_ != NULL) {
            const uint8_t* ptr = comp.data.empty() ? NULL : &comp.data[0];
            in_callback_ = true;
            listener_->onUsbUrbComplete(pu.urb_id, pu.endpoint, pu.is_in, comp.status, ptr,
                                        comp.data.size(), pu.user_ctx);
            in_callback_ = false;
        }
    }
}

void UsbHost::onReadable() {
    // usbfs does not signal POLLIN for URB completions; ignore if spuriously invoked.
}

void UsbHost::onWritable() { reapCompletedUrbs(); }

void UsbHost::onError() {
    reapCompletedUrbs();
    if (device_open_) {
        handleUnexpectedDisconnect();
    }
}

void UsbHost::onTimer(uint32_t timer_id) {
    if (timer_id == poll_timer_id_) {
        pollHotplug();
    }
}

}  // namespace platform
}  // namespace carplay
