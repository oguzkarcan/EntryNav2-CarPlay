// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/mfi/MfiAuthenticationClient.kt,
//  shared/src/main/java/com/shilapi/xcertplay/mfi/MfiDeviceScanner.kt,
//  shared/src/main/java/com/shilapi/xcertplay/transport/LinuxI2cTransport.kt,
//  shared/src/main/jni/linux_i2c_jni.c),
// GPL-3.0, Copyright (c) DiPlay contributors.

#include "carplay/platform/mfi_i2c.hpp"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

#include "carplay/platform/log.hpp"

namespace carplay {
namespace platform {

namespace {

const int64_t kNsPerMs = 1000000LL;

uint16_t readBe16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t readBe32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

I2cStatus mapErrno(int err) {
    switch (err) {
    case ENXIO:
    case EIO:
#ifdef EREMOTEIO
    case EREMOTEIO:
#endif
        return kI2cNack;
    case EBUSY:
    case EAGAIN:
#if defined(EWOULDBLOCK) && (!defined(EAGAIN) || EWOULDBLOCK != EAGAIN)
    case EWOULDBLOCK:
#endif
        return kI2cBusy;
    case EINVAL:
    case EBADF:
    case EFAULT:
        return kI2cInvalidArg;
    default:
        return kI2cIoError;
    }
}

std::string formatHexByte(uint8_t v) {
    char buf[8];
    snprintf(buf, sizeof(buf), "0x%02x", static_cast<unsigned>(v));
    return std::string(buf);
}

}  // namespace

LinuxI2cBackend::LinuxI2cBackend()
    : fd_(-1),
      has_i2c_rdwr_(false) {}

LinuxI2cBackend::~LinuxI2cBackend() {
    closeDevice();
}

bool LinuxI2cBackend::openDevice(const std::string& device_path, std::string* error_out) {
    closeDevice();
#ifndef _WIN32
    if (device_path.empty()) {
        if (error_out != NULL) *error_out = "empty I2C device path";
        return false;
    }
    const int fd = open(device_path.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        if (error_out != NULL) {
            *error_out = "open(" + device_path + "): " + strerror(errno);
        }
        return false;
    }
    unsigned long funcs = 0UL;
    if (ioctl(fd, I2C_FUNCS, &funcs) < 0) {
        const int saved = errno;
        close(fd);
        if (error_out != NULL) {
            *error_out = "ioctl(I2C_FUNCS) on " + device_path + ": " + strerror(saved);
        }
        return false;
    }
    fd_ = fd;
    has_i2c_rdwr_ = (funcs & I2C_FUNC_I2C) != 0UL;
    return true;
#else
    (void)device_path;
    if (error_out != NULL) *error_out = "Linux i2c-dev is unavailable on Windows";
    return false;
#endif
}

void LinuxI2cBackend::closeDevice() {
#ifndef _WIN32
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
#endif
    has_i2c_rdwr_ = false;
}

I2cStatus LinuxI2cBackend::transfer(uint8_t address7,
                                    const uint8_t* tx_data,
                                    size_t tx_len,
                                    uint8_t* rx_data,
                                    size_t rx_len,
                                    int* sys_errno_out) {
    if (sys_errno_out != NULL) *sys_errno_out = 0;
#ifndef _WIN32
    if (fd_ < 0 || address7 > 0x7fU) {
        return kI2cInvalidArg;
    }
    const bool has_tx = (tx_len > 0U);
    const bool has_rx = (rx_len > 0U);
    if (has_tx == has_rx) {
        return kI2cInvalidArg;
    }
    if ((has_tx && (tx_data == NULL || tx_len > 0xffffU)) ||
        (has_rx && (rx_data == NULL || rx_len > 0xffffU))) {
        return kI2cInvalidArg;
    }

    if (has_i2c_rdwr_) {
        struct i2c_msg msg;
        memset(&msg, 0, sizeof(msg));
        msg.addr = static_cast<uint16_t>(address7);
        if (has_tx) {
            msg.flags = 0;
            msg.len = static_cast<uint16_t>(tx_len);
            msg.buf = const_cast<uint8_t*>(tx_data);
        } else {
            msg.flags = I2C_M_RD;
            msg.len = static_cast<uint16_t>(rx_len);
            msg.buf = rx_data;
        }
        struct i2c_rdwr_ioctl_data ioctl_data;
        ioctl_data.msgs = &msg;
        ioctl_data.nmsgs = 1;

        int rc = 0;
        do {
            rc = ioctl(fd_, I2C_RDWR, &ioctl_data);
        } while (rc < 0 && errno == EINTR);
        if (rc < 0) {
            const int err = errno;
            if (sys_errno_out != NULL) *sys_errno_out = err;
            return mapErrno(err);
        }
        return kI2cOk;
    }

    // Fallback when controller lacks I2C_FUNC_I2C: bind 7-bit address with I2C_SLAVE
    // (never I2C_SLAVE_FORCE) and use plain write()/read().
    int rc = 0;
    do {
        rc = ioctl(fd_, I2C_SLAVE, static_cast<unsigned long>(address7));
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        const int err = errno;
        if (sys_errno_out != NULL) *sys_errno_out = err;
        return mapErrno(err);
    }

    if (has_tx) {
        size_t sent = 0U;
        while (sent < tx_len) {
            const ssize_t n = write(fd_, tx_data + sent, tx_len - sent);
            if (n < 0) {
                if (errno == EINTR) continue;
                const int err = errno;
                if (sys_errno_out != NULL) *sys_errno_out = err;
                return mapErrno(err);
            }
            if (n == 0) {
                return kI2cIoError;
            }
            sent += static_cast<size_t>(n);
        }
    } else {
        size_t got = 0U;
        while (got < rx_len) {
            const ssize_t n = read(fd_, rx_data + got, rx_len - got);
            if (n < 0) {
                if (errno == EINTR) continue;
                const int err = errno;
                if (sys_errno_out != NULL) *sys_errno_out = err;
                return mapErrno(err);
            }
            if (n == 0) {
                return kI2cIoError;
            }
            got += static_cast<size_t>(n);
        }
    }
    return kI2cOk;
#else
    (void)address7;
    (void)tx_data;
    (void)tx_len;
    (void)rx_data;
    (void)rx_len;
    return kI2cIoError;
#endif
}

bool parseMfiI2cSpec(const std::string& spec,
                     MfiI2cConfig& config_out,
                     std::string* error_out) {
    if (spec.empty()) {
        if (error_out != NULL) *error_out = "empty --mfi-i2c specification";
        return false;
    }

    const size_t colon = spec.rfind(':');
    std::string path = spec;
    uint8_t addr = 0U;
    if (colon != std::string::npos) {
        path = spec.substr(0, colon);
        const std::string addr_str = spec.substr(colon + 1U);
        if (addr_str.empty()) {
            if (error_out != NULL) *error_out = "missing I2C address after ':' in " + spec;
            return false;
        }
        if (addr_str[0] == '-' || addr_str[0] == '+') {
            if (error_out != NULL) *error_out = "invalid I2C address in " + spec;
            return false;
        }
        char* end = NULL;
        errno = 0;
        const unsigned long val = strtoul(addr_str.c_str(), &end, 0);
        if (errno != 0 || end == NULL || *end != '\0' || val == 0UL || val > 0x7fUL) {
            if (error_out != NULL) {
                *error_out = "I2C address must be 7-bit 0x01..0x7f (typically 0x10 or 0x11): " + spec;
            }
            return false;
        }
        addr = static_cast<uint8_t>(val);
    }

    if (path.empty()) {
        if (error_out != NULL) *error_out = "missing I2C device path in " + spec;
        return false;
    }

    config_out.enabled = true;
    config_out.device_path = path;
    config_out.address7 = addr;
    return true;
}

I2cMfiAuthProvider::I2cMfiAuthProvider(Reactor& reactor,
                                       const MfiI2cConfig& config,
                                       I2cBackend* external_backend)
    : reactor_(reactor),
      config_(config),
      backend_(external_backend != NULL ? external_backend : new LinuxI2cBackend()),
      owns_backend_(external_backend == NULL),
      started_(false),
      chip_info_(),
      cached_cert_(),
      stats_(),
      op_kind_(kOpNone),
      deferred_op_(kOpNone),
      next_op_id_(1ULL),
      active_op_id_(0ULL),
      auth_cb_(NULL),
      probe_cb_(NULL),
      timer_id_(Reactor::kNoTimer),
      probe_candidates_(),
      probe_idx_(0U),
      active_addr_(0U),
      phase_(kPhaseIdle),
      reg_sub_(kSubSelect),
      io_reg_(0U),
      io_tx_(),
      io_rx_len_(0U),
      io_deadline_ns_(0LL),
      auth_deadline_ns_(0LL),
      expected_cert_len_(0U),
      cert_page_reg_(0U),
      work_cert_(),
      work_challenge_(),
      expected_resp_len_(0U) {}

I2cMfiAuthProvider::~I2cMfiAuthProvider() {
    stop();
    if (owns_backend_) {
        delete backend_;
        backend_ = NULL;
    }
}

bool I2cMfiAuthProvider::start(ProbeCallback* probe_cb, std::string* error_out) {
    stop();
    if (!config_.enabled) {
        if (error_out != NULL) *error_out = "MFi I2C provider is disabled";
        return false;
    }
    if (backend_ == NULL) {
        if (error_out != NULL) *error_out = "missing I2C backend";
        return false;
    }
    if (config_.max_certificate_bytes == 0U || config_.max_certificate_bytes > iap2::kMaxCertificateBytes) {
        config_.max_certificate_bytes = iap2::kMaxCertificateBytes;
    }
    std::string err;
    if (!backend_->openDevice(config_.device_path, &err)) {
        stats_.last_error = err;
        if (error_out != NULL) *error_out = err;
        return false;
    }
    started_ = true;
    chip_info_ = MfiChipInfo();
    cached_cert_.clear();
    beginProbe(probe_cb);
    return true;
}

void I2cMfiAuthProvider::stop() {
    cancelTimer();
    op_kind_ = kOpNone;
    deferred_op_ = kOpNone;
    active_op_id_ = 0ULL;
    auth_cb_ = NULL;
    probe_cb_ = NULL;
    phase_ = kPhaseIdle;
    started_ = false;
    if (backend_ != NULL && backend_->isOpen()) {
        backend_->closeDevice();
    }
}

bool I2cMfiAuthProvider::beginProbe(ProbeCallback* probe_cb) {
    if (!started_ || backend_ == NULL || !backend_->isOpen() || op_kind_ != kOpNone) {
        return false;
    }
    probe_cb_ = probe_cb;
    op_kind_ = kOpProbe;
    deferred_op_ = config_.cache_certificate ? kOpCert : kOpNone;
    active_op_id_ = next_op_id_++;
    startProbeCandidate(0U);
    scheduleTimer(0);
    return true;
}

int I2cMfiAuthProvider::protocolMajor() const {
    if (chip_info_.probed && (chip_info_.protocol_major == 2U || chip_info_.protocol_major == 3U)) {
        return static_cast<int>(chip_info_.protocol_major);
    }
    return 3;
}

uint64_t I2cMfiAuthProvider::beginGetCertificate(iap2::AuthCallback& callback) {
    if (config_.cache_certificate && !cached_cert_.empty()) {
        callback.onCertificateComplete(0ULL, true, cached_cert_);
        return 0ULL;
    }
    if (!started_ || backend_ == NULL || !backend_->isOpen() || op_kind_ != kOpNone) {
        stats_.last_error = (op_kind_ != kOpNone) ? "MFi I2C operation already in flight" : "MFi I2C not started";
        std::vector<uint8_t> empty;
        callback.onCertificateComplete(0ULL, false, empty);
        return 0ULL;
    }

    op_kind_ = kOpCert;
    deferred_op_ = kOpNone;
    auth_cb_ = &callback;
    probe_cb_ = NULL;
    active_op_id_ = next_op_id_++;
    if (active_op_id_ == 0ULL) active_op_id_ = next_op_id_++;

    work_cert_.clear();
    expected_cert_len_ = 0U;

    if (!chip_info_.probed) {
        deferred_op_ = kOpCert;
        op_kind_ = kOpProbe;
        startProbeCandidate(0U);
    } else {
        enterPhase(kPhaseCertLen, kSubSelect, mfi_reg::kCertificateLength, NULL, 0U, 2U);
    }
    scheduleTimer(0);
    return active_op_id_;
}

uint64_t I2cMfiAuthProvider::beginSignChallenge(const uint8_t* challenge,
                                                size_t challenge_len,
                                                iap2::AuthCallback& callback) {
    if (challenge == NULL || challenge_len == 0U || challenge_len > iap2::kMaxChallengeBytes) {
        stats_.last_error = "invalid challenge length";
        std::vector<uint8_t> empty;
        callback.onSignatureComplete(0ULL, false, empty);
        return 0ULL;
    }
    if (!started_ || backend_ == NULL || !backend_->isOpen() || op_kind_ != kOpNone) {
        stats_.last_error = (op_kind_ != kOpNone) ? "MFi I2C operation already in flight" : "MFi I2C not started";
        std::vector<uint8_t> empty;
        callback.onSignatureComplete(0ULL, false, empty);
        return 0ULL;
    }

    work_challenge_.assign(challenge, challenge + challenge_len);
    expected_resp_len_ = 0U;
    auth_cb_ = &callback;
    probe_cb_ = NULL;
    active_op_id_ = next_op_id_++;
    if (active_op_id_ == 0ULL) active_op_id_ = next_op_id_++;

    if (!chip_info_.probed) {
        deferred_op_ = kOpSign;
        op_kind_ = kOpProbe;
        startProbeCandidate(0U);
    } else {
        op_kind_ = kOpSign;
        deferred_op_ = kOpNone;
        uint8_t len_be[2];
        len_be[0] = static_cast<uint8_t>((challenge_len >> 8) & 0xffU);
        len_be[1] = static_cast<uint8_t>(challenge_len & 0xffU);
        enterPhase(kPhaseSignChalLen, kSubWrite, mfi_reg::kChallengeLength, len_be, 2U, 0U);
    }
    scheduleTimer(0);
    return active_op_id_;
}

void I2cMfiAuthProvider::cancelAuth(uint64_t op_id) {
    if (op_id == 0ULL || op_id != active_op_id_) {
        return;
    }
    cancelTimer();
    op_kind_ = kOpNone;
    deferred_op_ = kOpNone;
    phase_ = kPhaseIdle;
    active_op_id_ = 0ULL;
    auth_cb_ = NULL;
    probe_cb_ = NULL;
}

void I2cMfiAuthProvider::scheduleTimer(int64_t delay_ms) {
    cancelTimer();
    const int64_t clamped = (delay_ms < 0) ? 0 : delay_ms;
    timer_id_ = reactor_.startTimer(clamped, 0, this);
    if (timer_id_ == Reactor::kNoTimer) {
        handleIoFailure("failed to schedule Reactor timer for MFi I2C operation");
    }
}

void I2cMfiAuthProvider::cancelTimer() {
    if (timer_id_ != Reactor::kNoTimer) {
        reactor_.cancelTimer(timer_id_);
        timer_id_ = Reactor::kNoTimer;
    }
}

void I2cMfiAuthProvider::startProbeCandidate(size_t index) {
    probe_candidates_.clear();
    if (config_.address7 != 0U) {
        probe_candidates_.push_back(config_.address7);
    } else {
        probe_candidates_.push_back(mfi_reg::kCandidateAddrPrimary);
        probe_candidates_.push_back(mfi_reg::kCandidateAddrSecondary);
    }
    probe_idx_ = index;
    active_addr_ = (probe_idx_ < probe_candidates_.size()) ? probe_candidates_[probe_idx_] : 0U;
    enterPhase(kPhaseProbeDevVer, kSubSelect, mfi_reg::kDeviceVersion, NULL, 0U, 1U);
}

void I2cMfiAuthProvider::enterPhase(Phase phase,
                                    RegSub sub,
                                    uint8_t reg,
                                    const uint8_t* tx,
                                    size_t tx_len,
                                    size_t rx_len) {
    phase_ = phase;
    reg_sub_ = sub;
    io_reg_ = reg;
    io_rx_len_ = rx_len;
    io_tx_.clear();
    if (sub == kSubWrite) {
        io_tx_.push_back(reg);
        if (tx != NULL && tx_len > 0U) {
            io_tx_.insert(io_tx_.end(), tx, tx + tx_len);
        }
    }
    const int64_t now_ns = reactor_.now();
    const int64_t budget_ms = (config_.io_retry_timeout_ms > 0) ? config_.io_retry_timeout_ms : 0;
    io_deadline_ns_ = now_ns + budget_ms * kNsPerMs;
}

void I2cMfiAuthProvider::onTimer(uint32_t timer_id) {
    if (timer_id != timer_id_) {
        return;
    }
    timer_id_ = Reactor::kNoTimer;
    if (!started_ || op_kind_ == kOpNone) {
        return;
    }
    stepAsync();
}

I2cStatus I2cMfiAuthProvider::runSingleIo(uint8_t addr,
                                          const uint8_t* tx,
                                          size_t tx_len,
                                          uint8_t* rx,
                                          size_t rx_len) {
    ++stats_.transactions;
    int sys_errno = 0;
    const I2cStatus st = backend_->transfer(addr, tx, tx_len, rx, rx_len, &sys_errno);
    if (st == kI2cNack) {
        ++stats_.nack_retries;
    } else if (st == kI2cBusy) {
        ++stats_.busy_retries;
    }
    return st;
}

void I2cMfiAuthProvider::stepAsync() {
    while (op_kind_ != kOpNone) {
        if (reg_sub_ == kSubWrite) {
            const I2cStatus st = runSingleIo(active_addr_, &io_tx_[0], io_tx_.size(), NULL, 0U);
            if (st == kI2cOk) {
                std::vector<uint8_t> empty;
                handlePhaseCompleted(empty);
                if (timer_id_ != Reactor::kNoTimer || op_kind_ == kOpNone) return;
                continue;
            }
            if ((st == kI2cNack || st == kI2cBusy) && reactor_.now() < io_deadline_ns_) {
                scheduleTimer(config_.nack_retry_delay_ms);
                return;
            }
            handleIoFailure("write failed at register " + formatHexByte(io_reg_));
            return;
        }

        if (reg_sub_ == kSubSelect) {
            const I2cStatus st = runSingleIo(active_addr_, &io_reg_, 1U, NULL, 0U);
            if (st == kI2cOk) {
                reg_sub_ = kSubRead;
                if (config_.select_to_read_gap_ms > 0) {
                    scheduleTimer(config_.select_to_read_gap_ms);
                    return;
                }
                continue;
            }
            if (phase_ == kPhaseSignPollStatus && (st == kI2cNack || st == kI2cBusy)) {
                if (reactor_.now() < auth_deadline_ns_) {
                    scheduleTimer(config_.auth_poll_interval_ms);
                    return;
                }
                enterPhase(kPhaseSignReadError, kSubSelect, mfi_reg::kErrorCode, NULL, 0U, 1U);
                continue;
            }
            if ((st == kI2cNack || st == kI2cBusy) && reactor_.now() < io_deadline_ns_) {
                scheduleTimer(config_.nack_retry_delay_ms);
                return;
            }
            if (phase_ == kPhaseSignReadError) {
                finishOp(false, std::vector<uint8_t>());
                return;
            }
            handleIoFailure("register select failed at " + formatHexByte(io_reg_));
            return;
        }

        // kSubRead
        std::vector<uint8_t> rx(io_rx_len_, 0U);
        const I2cStatus st = runSingleIo(active_addr_, NULL, 0U, &rx[0], io_rx_len_);
        if (st == kI2cOk) {
            handlePhaseCompleted(rx);
            if (timer_id_ != Reactor::kNoTimer || op_kind_ == kOpNone) return;
            continue;
        }
        // On NACK/busy during read, rewind to select+read so waking chip gets a fresh select.
        reg_sub_ = kSubSelect;
        if (phase_ == kPhaseSignPollStatus && (st == kI2cNack || st == kI2cBusy)) {
            if (reactor_.now() < auth_deadline_ns_) {
                scheduleTimer(config_.auth_poll_interval_ms);
                return;
            }
            enterPhase(kPhaseSignReadError, kSubSelect, mfi_reg::kErrorCode, NULL, 0U, 1U);
            continue;
        }
        if ((st == kI2cNack || st == kI2cBusy) && reactor_.now() < io_deadline_ns_) {
            scheduleTimer(config_.nack_retry_delay_ms);
            return;
        }
        if (phase_ == kPhaseSignReadError) {
            finishOp(false, std::vector<uint8_t>());
            return;
        }
        handleIoFailure("read failed at register " + formatHexByte(io_reg_));
        return;
    }
}

void I2cMfiAuthProvider::handleIoFailure(const std::string& reason) {
    if (phase_ == kPhaseProbeDevVer && probe_idx_ + 1U < probe_candidates_.size()) {
        startProbeCandidate(probe_idx_ + 1U);
        scheduleTimer(0);
        return;
    }
    stats_.last_error = reason;
    CARPLAY_LOG_WARN("mfi-i2c", "%s (addr=%s)",
                     reason.c_str(),
                     formatHexByte(active_addr_).c_str());
    finishOp(false, std::vector<uint8_t>());
}

void I2cMfiAuthProvider::handlePhaseCompleted(const std::vector<uint8_t>& rx) {
    switch (phase_) {
    case kPhaseProbeDevVer: {
        const uint8_t dev_ver = rx[0];
        if (dev_ver == 0x00U || dev_ver == 0xffU) {
            handleIoFailure("invalid device version " + formatHexByte(dev_ver));
            return;
        }
        chip_info_.address7 = active_addr_;
        chip_info_.device_version = dev_ver;
        enterPhase(kPhaseProbeFwVer, kSubSelect, mfi_reg::kFirmwareVersion, NULL, 0U, 1U);
        return;
    }
    case kPhaseProbeFwVer:
        chip_info_.firmware_version = rx[0];
        enterPhase(kPhaseProbeProtoMajor, kSubSelect, mfi_reg::kProtocolMajor, NULL, 0U, 1U);
        return;

    case kPhaseProbeProtoMajor: {
        const uint8_t major = rx[0];
        if (config_.require_known_protocol_major && major != 2U && major != 3U) {
            handleIoFailure("unsupported protocol major version " + formatHexByte(major));
            return;
        }
        chip_info_.protocol_major = major;
        enterPhase(kPhaseProbeProtoMinor, kSubSelect, mfi_reg::kProtocolMinor, NULL, 0U, 1U);
        return;
    }
    case kPhaseProbeProtoMinor:
        chip_info_.protocol_minor = rx[0];
        enterPhase(kPhaseProbeDevId, kSubSelect, mfi_reg::kDeviceId, NULL, 0U, 4U);
        return;

    case kPhaseProbeDevId: {
        chip_info_.device_id = readBe32(&rx[0]);
        chip_info_.probed = true;
        CARPLAY_LOG_INFO("mfi-i2c",
                         "detected MFi coprocessor at %s: dev=0x%02x fw=0x%02x proto=%u.%u id=0x%08x",
                         formatHexByte(chip_info_.address7).c_str(),
                         static_cast<unsigned>(chip_info_.device_version),
                         static_cast<unsigned>(chip_info_.firmware_version),
                         static_cast<unsigned>(chip_info_.protocol_major),
                         static_cast<unsigned>(chip_info_.protocol_minor),
                         static_cast<unsigned>(chip_info_.device_id));
        if (probe_cb_ != NULL) {
            ProbeCallback* cb = probe_cb_;
            probe_cb_ = NULL;
            cb->onProbeComplete(true, chip_info_);
            if (!started_ || op_kind_ == kOpNone) {
                return;
            }
        }
        if (deferred_op_ == kOpCert) {
            op_kind_ = kOpCert;
            deferred_op_ = kOpNone;
            work_cert_.clear();
            expected_cert_len_ = 0U;
            enterPhase(kPhaseCertLen, kSubSelect, mfi_reg::kCertificateLength, NULL, 0U, 2U);
            return;
        }
        if (deferred_op_ == kOpSign) {
            op_kind_ = kOpSign;
            deferred_op_ = kOpNone;
            uint8_t len_be[2];
            len_be[0] = static_cast<uint8_t>((work_challenge_.size() >> 8) & 0xffU);
            len_be[1] = static_cast<uint8_t>(work_challenge_.size() & 0xffU);
            enterPhase(kPhaseSignChalLen, kSubWrite, mfi_reg::kChallengeLength, len_be, 2U, 0U);
            return;
        }
        finishOp(true, std::vector<uint8_t>());
        return;
    }

    case kPhaseCertLen: {
        const size_t len = static_cast<size_t>(readBe16(&rx[0]));
        if (len == 0U || len > config_.max_certificate_bytes || len > iap2::kMaxCertificateBytes) {
            handleIoFailure("certificate length out of bounds");
            return;
        }
        const size_t pages = (len + mfi_reg::kCertPageBytes - 1U) / mfi_reg::kCertPageBytes;
        if (static_cast<size_t>(mfi_reg::kCertificateData) + pages > 0x100U) {
            handleIoFailure("certificate page overflow");
            return;
        }
        expected_cert_len_ = len;
        work_cert_.clear();
        work_cert_.reserve(len);
        cert_page_reg_ = mfi_reg::kCertificateData;
        const size_t chunk = (len < mfi_reg::kCertPageBytes) ? len : mfi_reg::kCertPageBytes;
        enterPhase(kPhaseCertPage, kSubSelect, cert_page_reg_, NULL, 0U, chunk);
        return;
    }

    case kPhaseCertPage: {
        work_cert_.insert(work_cert_.end(), rx.begin(), rx.end());
        if (work_cert_.size() < expected_cert_len_) {
            ++cert_page_reg_;
            const size_t rem = expected_cert_len_ - work_cert_.size();
            const size_t chunk = (rem < mfi_reg::kCertPageBytes) ? rem : mfi_reg::kCertPageBytes;
            enterPhase(kPhaseCertPage, kSubSelect, cert_page_reg_, NULL, 0U, chunk);
            return;
        }
        if (config_.validate_der_certificate && !isValidDerCertificate(work_cert_)) {
            handleIoFailure("MFi certificate failed ASN.1 DER framing check");
            return;
        }
        ++stats_.cert_reads;
        if (config_.cache_certificate) {
            cached_cert_ = work_cert_;
        }
        finishOp(true, work_cert_);
        return;
    }

    case kPhaseSignChalLen:
        enterPhase(kPhaseSignChalData,
                   kSubWrite,
                   mfi_reg::kChallengeData,
                   &work_challenge_[0],
                   work_challenge_.size(),
                   0U);
        return;

    case kPhaseSignChalData: {
        const uint8_t cmd = mfi_reg::kAuthStartCommand;
        enterPhase(kPhaseSignStart, kSubWrite, mfi_reg::kAuthControlStatus, &cmd, 1U, 0U);
        return;
    }

    case kPhaseSignStart: {
        const int64_t timeout_ms = (config_.auth_timeout_ms > 0) ? config_.auth_timeout_ms : 1;
        auth_deadline_ns_ = reactor_.now() + timeout_ms * kNsPerMs;
        enterPhase(kPhaseSignPollStatus, kSubSelect, mfi_reg::kAuthControlStatus, NULL, 0U, 1U);
        if (config_.auth_initial_delay_ms > 0) {
            scheduleTimer(config_.auth_initial_delay_ms);
        }
        return;
    }

    case kPhaseSignPollStatus: {
        const uint8_t status = rx[0];
        if (status == mfi_reg::kAuthSuccessStatus) {
            enterPhase(kPhaseSignRespLen, kSubSelect, mfi_reg::kResponseLength, NULL, 0U, 2U);
            return;
        }
        if ((status & mfi_reg::kAuthErrorMask) != 0U) {
            stats_.last_error = "coprocessor reported auth error status " + formatHexByte(status);
            enterPhase(kPhaseSignReadError, kSubSelect, mfi_reg::kErrorCode, NULL, 0U, 1U);
            return;
        }
        if (reactor_.now() < auth_deadline_ns_) {
            enterPhase(kPhaseSignPollStatus, kSubSelect, mfi_reg::kAuthControlStatus, NULL, 0U, 1U);
            scheduleTimer((config_.auth_poll_interval_ms > 0) ? config_.auth_poll_interval_ms : 1);
            return;
        }
        stats_.last_error = "coprocessor signature computation timed out";
        enterPhase(kPhaseSignReadError, kSubSelect, mfi_reg::kErrorCode, NULL, 0U, 1U);
        return;
    }

    case kPhaseSignReadError:
        stats_.last_chip_error = rx[0];
        if (stats_.last_error.empty()) {
            stats_.last_error = "MFi signature failed";
        }
        stats_.last_error += " (chip error " + formatHexByte(stats_.last_chip_error) + ")";
        CARPLAY_LOG_WARN("mfi-i2c", "%s", stats_.last_error.c_str());
        finishOp(false, std::vector<uint8_t>());
        return;

    case kPhaseSignRespLen: {
        const size_t len = static_cast<size_t>(readBe16(&rx[0]));
        if (len == 0U || len > iap2::kMaxCertificateBytes) {
            handleIoFailure("signature response length out of bounds");
            return;
        }
        expected_resp_len_ = len;
        enterPhase(kPhaseSignRespData, kSubSelect, mfi_reg::kResponseData, NULL, 0U, len);
        return;
    }

    case kPhaseSignRespData:
        ++stats_.sign_ops;
        finishOp(true, rx);
        return;

    case kPhaseIdle:
    default:
        finishOp(false, std::vector<uint8_t>());
        return;
    }
}

void I2cMfiAuthProvider::finishOp(bool ok, const std::vector<uint8_t>& payload) {
    cancelTimer();
    const OpKind kind = op_kind_;
    const OpKind pending_deferred = deferred_op_;
    const uint64_t op_id = active_op_id_;
    iap2::AuthCallback* auth_cb = auth_cb_;
    ProbeCallback* probe_cb = probe_cb_;

    op_kind_ = kOpNone;
    deferred_op_ = kOpNone;
    phase_ = kPhaseIdle;
    active_op_id_ = 0ULL;
    auth_cb_ = NULL;
    probe_cb_ = NULL;
    work_challenge_.clear();

    if (kind == kOpProbe) {
        if (probe_cb != NULL) {
            probe_cb->onProbeComplete(ok, chip_info_);
        }
        if (auth_cb != NULL) {
            std::vector<uint8_t> empty;
            if (pending_deferred == kOpSign) {
                auth_cb->onSignatureComplete(op_id, false, empty);
            } else {
                auth_cb->onCertificateComplete(op_id, false, empty);
            }
        }
    } else if (kind == kOpCert) {
        if (auth_cb != NULL) {
            auth_cb->onCertificateComplete(op_id, ok, payload);
        }
    } else if (kind == kOpSign) {
        if (auth_cb != NULL) {
            auth_cb->onSignatureComplete(op_id, ok, payload);
        }
    }
}

bool I2cMfiAuthProvider::getCertificate(std::vector<uint8_t>& certificate_out) {
    certificate_out.clear();
    if (config_.cache_certificate && !cached_cert_.empty()) {
        certificate_out = cached_cert_;
        return true;
    }
    if (!started_ || backend_ == NULL || !backend_->isOpen() || op_kind_ != kOpNone) {
        stats_.last_error = (op_kind_ != kOpNone) ? "MFi I2C busy" : "MFi I2C not started";
        return false;
    }
    return syncReadCertificate(certificate_out);
}

bool I2cMfiAuthProvider::signChallenge(const uint8_t* challenge,
                                       size_t challenge_len,
                                       std::vector<uint8_t>& signature_out) {
    signature_out.clear();
    if (challenge == NULL || challenge_len == 0U || challenge_len > iap2::kMaxChallengeBytes) {
        stats_.last_error = "invalid challenge length";
        return false;
    }
    if (!started_ || backend_ == NULL || !backend_->isOpen() || op_kind_ != kOpNone) {
        stats_.last_error = (op_kind_ != kOpNone) ? "MFi I2C busy" : "MFi I2C not started";
        return false;
    }
    return syncSignChallenge(challenge, challenge_len, signature_out);
}

void I2cMfiAuthProvider::syncSleepMs(int64_t ms) const {
    if (ms <= 0) return;
#ifndef _WIN32
    struct timespec req;
    req.tv_sec = static_cast<time_t>(ms / 1000);
    req.tv_nsec = static_cast<long>((ms % 1000) * 1000000LL);
    while (nanosleep(&req, &req) < 0 && errno == EINTR) {
    }
#else
    Sleep(static_cast<DWORD>(ms));
#endif
}

bool I2cMfiAuthProvider::syncReadReg(uint8_t addr,
                                     uint8_t reg,
                                     size_t rx_len,
                                     std::vector<uint8_t>& out) {
    out.assign(rx_len, 0U);
    const int64_t deadline = reactor_.now() + config_.io_retry_timeout_ms * kNsPerMs;
    while (true) {
        I2cStatus st = runSingleIo(addr, &reg, 1U, NULL, 0U);
        if (st == kI2cOk) {
            if (config_.select_to_read_gap_ms > 0) {
                syncSleepMs(config_.select_to_read_gap_ms);
            }
            st = runSingleIo(addr, NULL, 0U, &out[0], rx_len);
            if (st == kI2cOk) {
                return true;
            }
        }
        if ((st != kI2cNack && st != kI2cBusy) || reactor_.now() >= deadline) {
            stats_.last_error = "sync read failed at register " + formatHexByte(reg);
            out.clear();
            return false;
        }
        syncSleepMs(config_.nack_retry_delay_ms);
    }
}

bool I2cMfiAuthProvider::syncWriteReg(uint8_t addr,
                                      uint8_t reg,
                                      const uint8_t* data,
                                      size_t len) {
    std::vector<uint8_t> frame;
    frame.reserve(1U + len);
    frame.push_back(reg);
    if (data != NULL && len > 0U) {
        frame.insert(frame.end(), data, data + len);
    }
    const int64_t deadline = reactor_.now() + config_.io_retry_timeout_ms * kNsPerMs;
    while (true) {
        const I2cStatus st = runSingleIo(addr, &frame[0], frame.size(), NULL, 0U);
        if (st == kI2cOk) {
            return true;
        }
        if ((st != kI2cNack && st != kI2cBusy) || reactor_.now() >= deadline) {
            stats_.last_error = "sync write failed at register " + formatHexByte(reg);
            return false;
        }
        syncSleepMs(config_.nack_retry_delay_ms);
    }
}

bool I2cMfiAuthProvider::syncProbe() {
    if (chip_info_.probed) return true;
    std::vector<uint8_t> candidates;
    if (config_.address7 != 0U) {
        candidates.push_back(config_.address7);
    } else {
        candidates.push_back(mfi_reg::kCandidateAddrPrimary);
        candidates.push_back(mfi_reg::kCandidateAddrSecondary);
    }
    for (size_t i = 0U; i < candidates.size(); ++i) {
        const uint8_t addr = candidates[i];
        std::vector<uint8_t> b;
        if (!syncReadReg(addr, mfi_reg::kDeviceVersion, 1U, b)) continue;
        if (b[0] == 0x00U || b[0] == 0xffU) continue;
        MfiChipInfo info;
        info.address7 = addr;
        info.device_version = b[0];
        if (!syncReadReg(addr, mfi_reg::kFirmwareVersion, 1U, b)) continue;
        info.firmware_version = b[0];
        if (!syncReadReg(addr, mfi_reg::kProtocolMajor, 1U, b)) continue;
        if (config_.require_known_protocol_major && b[0] != 2U && b[0] != 3U) continue;
        info.protocol_major = b[0];
        if (!syncReadReg(addr, mfi_reg::kProtocolMinor, 1U, b)) continue;
        info.protocol_minor = b[0];
        if (!syncReadReg(addr, mfi_reg::kDeviceId, 4U, b)) continue;
        info.device_id = readBe32(&b[0]);
        info.probed = true;
        chip_info_ = info;
        return true;
    }
    return false;
}

bool I2cMfiAuthProvider::syncReadCertificate(std::vector<uint8_t>& cert_out) {
    if (!syncProbe()) return false;
    std::vector<uint8_t> len_bytes;
    if (!syncReadReg(chip_info_.address7, mfi_reg::kCertificateLength, 2U, len_bytes)) {
        return false;
    }
    const size_t len = static_cast<size_t>(readBe16(&len_bytes[0]));
    if (len == 0U || len > config_.max_certificate_bytes || len > iap2::kMaxCertificateBytes) {
        stats_.last_error = "certificate length out of bounds";
        return false;
    }
    const size_t pages = (len + mfi_reg::kCertPageBytes - 1U) / mfi_reg::kCertPageBytes;
    if (static_cast<size_t>(mfi_reg::kCertificateData) + pages > 0x100U) {
        stats_.last_error = "certificate page overflow";
        return false;
    }
    cert_out.clear();
    cert_out.reserve(len);
    uint8_t reg = mfi_reg::kCertificateData;
    while (cert_out.size() < len) {
        const size_t rem = len - cert_out.size();
        const size_t chunk = (rem < mfi_reg::kCertPageBytes) ? rem : mfi_reg::kCertPageBytes;
        std::vector<uint8_t> page;
        if (!syncReadReg(chip_info_.address7, reg, chunk, page)) {
            cert_out.clear();
            return false;
        }
        cert_out.insert(cert_out.end(), page.begin(), page.end());
        ++reg;
    }
    if (config_.validate_der_certificate && !isValidDerCertificate(cert_out)) {
        stats_.last_error = "MFi certificate failed ASN.1 DER framing check";
        cert_out.clear();
        return false;
    }
    ++stats_.cert_reads;
    if (config_.cache_certificate) {
        cached_cert_ = cert_out;
    }
    return true;
}

bool I2cMfiAuthProvider::syncSignChallenge(const uint8_t* challenge,
                                           size_t len,
                                           std::vector<uint8_t>& sig_out) {
    if (!syncProbe()) return false;
    const uint8_t addr = chip_info_.address7;
    const uint8_t len_be[2] = {
        static_cast<uint8_t>((len >> 8) & 0xffU),
        static_cast<uint8_t>(len & 0xffU)
    };
    if (!syncWriteReg(addr, mfi_reg::kChallengeLength, len_be, 2U)) return false;
    if (!syncWriteReg(addr, mfi_reg::kChallengeData, challenge, len)) return false;
    const uint8_t cmd = mfi_reg::kAuthStartCommand;
    if (!syncWriteReg(addr, mfi_reg::kAuthControlStatus, &cmd, 1U)) return false;

    syncSleepMs(config_.auth_initial_delay_ms);
    const int64_t deadline = reactor_.now() + config_.auth_timeout_ms * kNsPerMs;
    while (true) {
        uint8_t reg = mfi_reg::kAuthControlStatus;
        uint8_t status = 0U;
        I2cStatus st = runSingleIo(addr, &reg, 1U, NULL, 0U);
        if (st == kI2cOk) {
            syncSleepMs(config_.select_to_read_gap_ms);
            st = runSingleIo(addr, NULL, 0U, &status, 1U);
        }
        if (st == kI2cOk) {
            if (status == mfi_reg::kAuthSuccessStatus) {
                break;
            }
            if ((status & mfi_reg::kAuthErrorMask) != 0U) {
                std::vector<uint8_t> err_reg;
                if (syncReadReg(addr, mfi_reg::kErrorCode, 1U, err_reg)) {
                    stats_.last_chip_error = err_reg[0];
                }
                stats_.last_error = "coprocessor reported auth error status";
                return false;
            }
        } else if (st != kI2cNack && st != kI2cBusy) {
            stats_.last_error = "failed polling auth status";
            return false;
        }
        if (reactor_.now() >= deadline) {
            std::vector<uint8_t> err_reg;
            if (syncReadReg(addr, mfi_reg::kErrorCode, 1U, err_reg)) {
                stats_.last_chip_error = err_reg[0];
            }
            stats_.last_error = "coprocessor signature computation timed out";
            return false;
        }
        syncSleepMs(config_.auth_poll_interval_ms);
    }

    std::vector<uint8_t> len_bytes;
    if (!syncReadReg(addr, mfi_reg::kResponseLength, 2U, len_bytes)) return false;
    const size_t resp_len = static_cast<size_t>(readBe16(&len_bytes[0]));
    if (resp_len == 0U || resp_len > iap2::kMaxCertificateBytes) {
        stats_.last_error = "signature response length out of bounds";
        return false;
    }
    if (!syncReadReg(addr, mfi_reg::kResponseData, resp_len, sig_out)) return false;
    ++stats_.sign_ops;
    return true;
}

bool I2cMfiAuthProvider::isValidDerCertificate(const std::vector<uint8_t>& cert) {
    if (cert.size() < 4U || cert[0] != 0x30U) {
        return false;
    }
    const uint8_t len_byte = cert[1];
    size_t header_len = 2U;
    size_t content_len = 0U;
    if ((len_byte & 0x80U) == 0U) {
        content_len = len_byte;
    } else {
        const size_t octets = static_cast<size_t>(len_byte & 0x7fU);
        if (octets == 0U || octets > 4U || cert.size() < 2U + octets) {
            return false;
        }
        header_len += octets;
        for (size_t i = 0U; i < octets; ++i) {
            content_len = (content_len << 8) | cert[2U + i];
        }
    }
    return header_len + content_len == cert.size();
}

}  // namespace platform
}  // namespace carplay
