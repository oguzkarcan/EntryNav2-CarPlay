#ifndef CARPLAY_PLATFORM_MFI_I2C_HPP
#define CARPLAY_PLATFORM_MFI_I2C_HPP

// Derived from DiPlay
// (shared/src/main/java/com/shilapi/xcertplay/mfi/MfiAuthenticationClient.kt,
//  shared/src/main/java/com/shilapi/xcertplay/mfi/MfiDeviceScanner.kt,
//  shared/src/main/java/com/shilapi/xcertplay/transport/LinuxI2cTransport.kt,
//  shared/src/main/jni/linux_i2c_jni.c),
// GPL-3.0, Copyright (c) DiPlay contributors.
//
// Hardware MFi Authentication Coprocessor (CP 2.0C / 3.0) over Linux i2c-dev (/dev/i2c-N).
//
// Features:
//   * Injectable I2cBackend: LinuxI2cBackend (/dev/i2c-N via I2C_RDWR / I2C_SLAVE ioctls,
//     dlopen-free, no I2C_SLAVE_FORCE) or fake register-level backend for host tests.
//   * Reactor-timer-driven asynchronous iap2::AuthProvider state machine: STOP-terminated
//     register-select + read gap, NACK/EBUSY retries, and auth-status polling run via
//     Reactor timers without blocking the single-threaded Reactor loop.
//   * Implements both iap2::AuthProvider (async + sync) and session::AuthProvider (/auth-setup).

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/airplay_session.hpp"
#include "carplay/auth_provider.hpp"
#include "carplay/platform/reactor.hpp"

namespace carplay {
namespace platform {

namespace mfi_reg {

// Verified register addresses (DiPlay MfiAuthenticationClient.kt:227-237 & MfiDeviceScanner.kt:129-145).
static const uint8_t kDeviceVersion = 0x00U;      // 1B: CP silicon/device version (reject 0x00, 0xFF)
static const uint8_t kFirmwareVersion = 0x01U;    // 1B: coprocessor firmware version
static const uint8_t kProtocolMajor = 0x02U;      // 1B: 2 = CP 2.0C, 3 = CP 3.0
static const uint8_t kProtocolMinor = 0x03U;      // 1B: protocol minor version
static const uint8_t kDeviceId = 0x04U;           // 4B BE: device identifier
static const uint8_t kErrorCode = 0x05U;          // 1B: last chip error code
static const uint8_t kAuthControlStatus = 0x10U;  // 1B R/W: write 0x01 start sign; read 0x10 success / bit 0x80 error
static const uint8_t kResponseLength = 0x11U;     // 2B BE: signature length
static const uint8_t kResponseData = 0x12U;       // N B: generated signature bytes
static const uint8_t kChallengeLength = 0x20U;    // 2B BE: challenge length (1..128)
static const uint8_t kChallengeData = 0x21U;      // N B: challenge bytes
static const uint8_t kCertificateLength = 0x30U;  // 2B BE: accessory X.509 cert length
static const uint8_t kCertificateData = 0x31U;    // 128B/page across 0x31..0x3F
static const uint8_t kAppleCertLength = 0x50U;    // 2B BE: Apple CA cert length (optional)

static const uint8_t kCandidateAddrPrimary = 0x10U;    // 7-bit I2C address (8-bit 0x20/0x21)
static const uint8_t kCandidateAddrSecondary = 0x11U;  // 7-bit I2C address (8-bit 0x22/0x23)

static const uint8_t kAuthStartCommand = 0x01U;
static const uint8_t kAuthSuccessStatus = 0x10U;
static const uint8_t kAuthErrorMask = 0x80U;
static const size_t kCertPageBytes = 128U;

}  // namespace mfi_reg

enum I2cStatus {
    kI2cOk = 0,
    kI2cNack = 1,       // ENXIO, EREMOTEIO, EIO (sleep wake NACK / missing addr)
    kI2cBusy = 2,       // EBUSY, EAGAIN, EWOULDBLOCK (concurrent bus/address owner)
    kI2cInvalidArg = 3, // bad fd / address / length
    kI2cIoError = 4     // unexpected kernel / hardware failure
};

/// Abstract single-transaction I2C bus backend.
/// Each transfer is EITHER a pure STOP-terminated write (`tx_len > 0 && rx_len == 0`)
/// OR a pure read (`tx_len == 0 && rx_len > 0`). Combined repeated-START write+read
/// must NOT be used because CP 2.0C requires a STOP condition before reading a register.
class I2cBackend {
public:
    virtual ~I2cBackend() {}

    virtual bool openDevice(const std::string& device_path, std::string* error_out) = 0;
    virtual void closeDevice() = 0;
    virtual bool isOpen() const = 0;

    virtual I2cStatus transfer(uint8_t address7,
                               const uint8_t* tx_data,
                               size_t tx_len,
                               uint8_t* rx_data,
                               size_t rx_len,
                               int* sys_errno_out = NULL) = 0;
};

/// Real Linux `/dev/i2c-N` backend using `<linux/i2c-dev.h>` ioctls (`I2C_RDWR`, fallback `I2C_SLAVE`).
class LinuxI2cBackend : public I2cBackend {
public:
    LinuxI2cBackend();
    virtual ~LinuxI2cBackend();

    virtual bool openDevice(const std::string& device_path, std::string* error_out);
    virtual void closeDevice();
    virtual bool isOpen() const { return fd_ >= 0; }

    virtual I2cStatus transfer(uint8_t address7,
                               const uint8_t* tx_data,
                               size_t tx_len,
                               uint8_t* rx_data,
                               size_t rx_len,
                               int* sys_errno_out = NULL);

    bool supportsI2cRdwr() const { return has_i2c_rdwr_; }

private:
    LinuxI2cBackend(const LinuxI2cBackend&);
    LinuxI2cBackend& operator=(const LinuxI2cBackend&);

    int fd_;
    bool has_i2c_rdwr_;
};

struct MfiI2cConfig {
    bool enabled;
    std::string device_path;          // e.g. "/dev/i2c-0"
    uint8_t address7;                 // 0 = auto-probe 0x10 then 0x11; else explicit 7-bit address
    int64_t select_to_read_gap_ms;    // STOP -> read START gap (CP 2.0C requires >= ~500us-5ms; default 5ms)
    int64_t nack_retry_delay_ms;      // delay between NACK/EBUSY retries (default 20ms)
    int64_t io_retry_timeout_ms;      // max retry budget per register transaction (default 2000ms)
    int64_t auth_initial_delay_ms;    // delay after writing 0x10=0x01 before first poll (default 10ms)
    int64_t auth_poll_interval_ms;    // polling interval on 0x10 (default 10ms)
    int64_t auth_timeout_ms;          // total timeout for signature computation (default 3000ms)
    size_t max_certificate_bytes;     // default 1920 (0x31..0x3F * 128), cap <= 65525
    bool cache_certificate;           // cache certificate after first read / startup warmup
    bool require_known_protocol_major;// accept protocol_major == 2 or 3 during probe
    bool validate_der_certificate;    // optional ASN.1 SEQUENCE framing check

    MfiI2cConfig()
        : enabled(false),
          device_path(),
          address7(0U),
          select_to_read_gap_ms(5),
          nack_retry_delay_ms(20),
          io_retry_timeout_ms(2000),
          auth_initial_delay_ms(10),
          auth_poll_interval_ms(10),
          auth_timeout_ms(3000),
          max_certificate_bytes(1920U),
          cache_certificate(true),
          require_known_protocol_major(true),
          validate_der_certificate(false) {}
};

/// Parses `--mfi-i2c` specification strings of the form:
///   `/dev/i2c-0`       (auto-probe 7-bit 0x10 then 0x11)
///   `/dev/i2c-0:0x10`  (explicit 7-bit hex address)
///   `/dev/i2c-0:16`    (explicit 7-bit decimal address)
/// Rejects empty strings, missing address after `:`, or out-of-range (> 0x7f / == 0) addresses.
bool parseMfiI2cSpec(const std::string& spec,
                     MfiI2cConfig& config_out,
                     std::string* error_out = NULL);

struct MfiChipInfo {
    bool probed;
    uint8_t address7;
    uint8_t device_version;
    uint8_t firmware_version;
    uint8_t protocol_major;
    uint8_t protocol_minor;
    uint32_t device_id;

    MfiChipInfo()
        : probed(false),
          address7(0U),
          device_version(0U),
          firmware_version(0U),
          protocol_major(0U),
          protocol_minor(0U),
          device_id(0U) {}
};

struct I2cMfiStats {
    uint64_t transactions;
    uint64_t nack_retries;
    uint64_t busy_retries;
    uint64_t cert_reads;
    uint64_t sign_ops;
    uint8_t last_chip_error;
    std::string last_error;

    I2cMfiStats()
        : transactions(0ULL),
          nack_retries(0ULL),
          busy_retries(0ULL),
          cert_reads(0ULL),
          sign_ops(0ULL),
          last_chip_error(0U),
          last_error() {}
};

/// Non-blocking Reactor-driven MFi Authentication Coprocessor provider.
///
/// Ownership & lifetime:
///   - Construct on the Reactor thread. If `external_backend` is NULL, owns a `LinuxI2cBackend`.
///   - `start()` opens the I2C device and schedules an asynchronous probe (+ cert warmup if enabled).
///   - `stop()` cancels active Reactor timers, aborts any pending async callback, and closes the device.
///   - `iap2::AuthProvider` async hooks (`beginGetCertificate`, `beginSignChallenge`) execute completely
///     without blocking sleeps using Reactor timers.
class I2cMfiAuthProvider : public iap2::AuthProvider,
                           public session::AuthProvider,
                           public TimerHandler {
public:
    class ProbeCallback {
    public:
        virtual ~ProbeCallback() {}
        virtual void onProbeComplete(bool ok, const MfiChipInfo& info) = 0;
    };

    I2cMfiAuthProvider(Reactor& reactor,
                       const MfiI2cConfig& config,
                       I2cBackend* external_backend = NULL);
    virtual ~I2cMfiAuthProvider();

    bool start(ProbeCallback* probe_cb = NULL, std::string* error_out = NULL);
    void stop();

    bool isStarted() const { return started_; }
    bool isBusy() const { return op_kind_ != kOpNone; }
    const MfiI2cConfig& config() const { return config_; }
    const MfiChipInfo& chipInfo() const { return chip_info_; }
    const I2cMfiStats& stats() const { return stats_; }
    const std::vector<uint8_t>& cachedCertificate() const { return cached_cert_; }

    /// Starts an explicit asynchronous probe (if idle). Returns true if started.
    bool beginProbe(ProbeCallback* probe_cb = NULL);

    // ---- iap2::AuthProvider & session::AuthProvider ----
    virtual bool getCertificate(std::vector<uint8_t>& certificate_out);
    virtual bool signChallenge(const uint8_t* challenge,
                               size_t challenge_len,
                               std::vector<uint8_t>& signature_out);
    virtual int protocolMajor() const;

    virtual bool isAsync() const { return true; }
    virtual uint64_t beginGetCertificate(iap2::AuthCallback& callback);
    virtual uint64_t beginSignChallenge(const uint8_t* challenge,
                                          size_t challenge_len,
                                          iap2::AuthCallback& callback);
    virtual void cancelAuth(uint64_t op_id);

    // ---- TimerHandler ----
    virtual void onTimer(uint32_t timer_id);

private:
    I2cMfiAuthProvider(const I2cMfiAuthProvider&);
    I2cMfiAuthProvider& operator=(const I2cMfiAuthProvider&);

    enum OpKind {
        kOpNone = 0,
        kOpProbe = 1,
        kOpCert = 2,
        kOpSign = 3
    };

    enum Phase {
        kPhaseIdle = 0,
        kPhaseProbeDevVer,
        kPhaseProbeFwVer,
        kPhaseProbeProtoMajor,
        kPhaseProbeProtoMinor,
        kPhaseProbeDevId,
        kPhaseCertLen,
        kPhaseCertPage,
        kPhaseSignChalLen,
        kPhaseSignChalData,
        kPhaseSignStart,
        kPhaseSignPollStatus,
        kPhaseSignReadError,
        kPhaseSignRespLen,
        kPhaseSignRespData
    };

    enum RegSub {
        kSubSelect = 0,
        kSubRead = 1,
        kSubWrite = 2
    };

    void scheduleTimer(int64_t delay_ms);
    void cancelTimer();
    void startProbeCandidate(size_t index);
    void enterPhase(Phase phase, RegSub sub, uint8_t reg, const uint8_t* tx, size_t tx_len, size_t rx_len);
    void stepAsync();
    void handlePhaseCompleted(const std::vector<uint8_t>& rx);
    void handleIoFailure(const std::string& reason);
    void finishOp(bool ok, const std::vector<uint8_t>& payload);
    I2cStatus runSingleIo(uint8_t addr,
                          const uint8_t* tx,
                          size_t tx_len,
                          uint8_t* rx,
                          size_t rx_len);

    // Blocking fallback used only when synchronous getCertificate() (uncached) / signChallenge()
    // is invoked directly outside iap2 async hooks.
    bool syncProbe();
    bool syncReadReg(uint8_t addr, uint8_t reg, size_t rx_len, std::vector<uint8_t>& out);
    bool syncWriteReg(uint8_t addr, uint8_t reg, const uint8_t* data, size_t len);
    bool syncReadCertificate(std::vector<uint8_t>& cert_out);
    bool syncSignChallenge(const uint8_t* challenge, size_t len, std::vector<uint8_t>& sig_out);
    void syncSleepMs(int64_t ms) const;

    static bool isValidDerCertificate(const std::vector<uint8_t>& cert);

    Reactor& reactor_;
    MfiI2cConfig config_;
    I2cBackend* backend_;
    bool owns_backend_;
    bool started_;

    MfiChipInfo chip_info_;
    std::vector<uint8_t> cached_cert_;
    I2cMfiStats stats_;

    // Active async operation state
    OpKind op_kind_;
    OpKind deferred_op_;
    uint64_t next_op_id_;
    uint64_t active_op_id_;
    iap2::AuthCallback* auth_cb_;
    ProbeCallback* probe_cb_;
    uint32_t timer_id_;

    std::vector<uint8_t> probe_candidates_;
    size_t probe_idx_;
    uint8_t active_addr_;

    Phase phase_;
    RegSub reg_sub_;
    uint8_t io_reg_;
    std::vector<uint8_t> io_tx_;
    size_t io_rx_len_;
    int64_t io_deadline_ns_;
    int64_t auth_deadline_ns_;

    size_t expected_cert_len_;
    uint8_t cert_page_reg_;
    std::vector<uint8_t> work_cert_;
    std::vector<uint8_t> work_challenge_;
    size_t expected_resp_len_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_MFI_I2C_HPP
