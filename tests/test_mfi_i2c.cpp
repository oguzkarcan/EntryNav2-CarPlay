#include "test_support.hpp"

#include "carplay/airplay_crypto.hpp"
#include "carplay/auth_provider.hpp"
#include "carplay/iap2_session.hpp"
#include "carplay/mfi_sap.hpp"
#include "carplay/pairing.hpp"
#include "carplay/platform/carplay_daemon.hpp"
#include "carplay/platform/mfi_i2c.hpp"
#include "carplay/platform/reactor.hpp"

#include <cstring>
#include <string>
#include <vector>

#ifndef _WIN32
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

using namespace carplay;
namespace plat = carplay::platform;
typedef std::vector<uint8_t> Bytes;

int64_t g_fake_clock_ns = 1000000000000LL;
int64_t fakeClockNs() {
    return g_fake_clock_ns;
}
void resetFakeClock() {
    g_fake_clock_ns = 1000000000000LL;
}
void advanceFakeClockMs(int64_t ms) {
    g_fake_clock_ns += ms * 1000000LL;
}

class DeterministicRng : public pairing::RandomSource {
public:
    DeterministicRng() : counter_(1U) {}
    virtual bool fill(uint8_t* out, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            out[i] = static_cast<uint8_t>((counter_ * 29U + i * 7U) & 0xffU);
        }
        ++counter_;
        return true;
    }

private:
    uint32_t counter_;
};

// Register-level fake Apple Authentication Coprocessor (CP 2.0C and CP 3.0).
class FakeMfiChipBackend : public plat::I2cBackend {
public:
    bool open_ok;
    bool open_called;
    uint8_t chip_addr;
    uint8_t dev_ver;
    uint8_t fw_ver;
    uint8_t proto_major;
    uint8_t proto_minor;
    uint32_t dev_id;
    uint8_t error_code;

    Bytes certificate;
    bool override_cert_len;
    uint16_t cert_len_override;
    uint16_t resp_len_override;
    bool override_resp_len;

    int initial_nacks;
    int initial_busys;
    int fail_second_half_read_nacks;
    int auth_pending_polls;
    int auth_pending_nacks;
    uint8_t auth_terminal_status;
    bool hard_io_error_on_select;
    bool never_complete_auth;

    bool has_selected_reg;
    uint8_t selected_reg;
    int64_t last_select_ns;
    int64_t min_select_to_read_ns;
    bool saw_combined_write_read;
    bool saw_select_then_read_after_nack;
    bool expect_reselect_on_next_op;

    Bytes written_challenge;
    uint16_t written_challenge_len;
    Bytes last_signature;
    int transfer_calls;

    FakeMfiChipBackend()
        : open_ok(true),
          open_called(false),
          chip_addr(plat::mfi_reg::kCandidateAddrPrimary),
          dev_ver(0x03U),
          fw_ver(0x01U),
          proto_major(3U),
          proto_minor(0U),
          dev_id(0x00000300U),
          error_code(0x00U),
          certificate(),
          override_cert_len(false),
          cert_len_override(0U),
          resp_len_override(0U),
          override_resp_len(false),
          initial_nacks(0),
          initial_busys(0),
          fail_second_half_read_nacks(0),
          auth_pending_polls(2),
          auth_pending_nacks(0),
          auth_terminal_status(plat::mfi_reg::kAuthSuccessStatus),
          hard_io_error_on_select(false),
          never_complete_auth(false),
          has_selected_reg(false),
          selected_reg(0U),
          last_select_ns(0LL),
          min_select_to_read_ns(-1LL),
          saw_combined_write_read(false),
          saw_select_then_read_after_nack(false),
          expect_reselect_on_next_op(false),
          written_challenge(),
          written_challenge_len(0U),
          last_signature(),
          transfer_calls(0),
          open_state_(false),
          poll_counter_(0),
          nack_counter_(0) {
        setDerCertificate(512U);
    }

    void setDerCertificate(size_t total_size) {
        certificate.clear();
        if (total_size < 4U) total_size = 4U;
        certificate.push_back(0x30U);
        const size_t body_len = total_size - 4U;
        certificate.push_back(0x82U);
        certificate.push_back(static_cast<uint8_t>((body_len >> 8) & 0xffU));
        certificate.push_back(static_cast<uint8_t>(body_len & 0xffU));
        for (size_t i = 0U; i < body_len; ++i) {
            certificate.push_back(static_cast<uint8_t>((i * 17U + 3U) & 0xffU));
        }
    }

    virtual bool openDevice(const std::string& /*device_path*/, std::string* error_out) {
        open_called = true;
        if (!open_ok) {
            if (error_out != NULL) *error_out = "injected openDevice failure";
            open_state_ = false;
            return false;
        }
        open_state_ = true;
        return true;
    }

    virtual void closeDevice() {
        open_state_ = false;
    }

    virtual bool isOpen() const {
        return open_state_;
    }

    virtual plat::I2cStatus transfer(uint8_t address7,
                                     const uint8_t* tx_data,
                                     size_t tx_len,
                                     uint8_t* rx_data,
                                     size_t rx_len,
                                     int* sys_errno_out) {
        (void)sys_errno_out;
        ++transfer_calls;
        if (!open_state_) {
            return plat::kI2cInvalidArg;
        }
        if (tx_len > 0U && rx_len > 0U) {
            saw_combined_write_read = true;
            return plat::kI2cInvalidArg;
        }
        if (address7 != chip_addr) {
            return plat::kI2cNack;
        }

        if (initial_busys > 0) {
            --initial_busys;
            return plat::kI2cBusy;
        }
        if (initial_nacks > 0) {
            --initial_nacks;
            return plat::kI2cNack;
        }

        if (tx_len > 0U) {
            if (hard_io_error_on_select) {
                return plat::kI2cIoError;
            }
            const uint8_t reg = tx_data[0];
            if (tx_len == 1U) {
                if (expect_reselect_on_next_op) {
                    saw_select_then_read_after_nack = true;
                    expect_reselect_on_next_op = false;
                }
                selected_reg = reg;
                has_selected_reg = true;
                last_select_ns = g_fake_clock_ns;
                return plat::kI2cOk;
            }
            has_selected_reg = false;
            const uint8_t* payload = tx_data + 1U;
            const size_t plen = tx_len - 1U;
            if (reg == plat::mfi_reg::kChallengeLength && plen == 2U) {
                written_challenge_len = static_cast<uint16_t>((static_cast<uint16_t>(payload[0]) << 8) | payload[1]);
                return plat::kI2cOk;
            }
            if (reg == plat::mfi_reg::kChallengeData) {
                written_challenge.assign(payload, payload + plen);
                return plat::kI2cOk;
            }
            if (reg == plat::mfi_reg::kAuthControlStatus && plen == 1U && payload[0] == plat::mfi_reg::kAuthStartCommand) {
                poll_counter_ = 0;
                nack_counter_ = 0;
                computeSignature();
                return plat::kI2cOk;
            }
            return plat::kI2cOk;
        }

        // Pure read
        if (fail_second_half_read_nacks > 0) {
            --fail_second_half_read_nacks;
            expect_reselect_on_next_op = true;
            return plat::kI2cNack;
        }
        if (expect_reselect_on_next_op) {
            // Failed: caller retried pure read without re-selecting register!
            return plat::kI2cInvalidArg;
        }
        if (!has_selected_reg) {
            return plat::kI2cIoError;
        }

        const int64_t gap_ns = g_fake_clock_ns - last_select_ns;
        if (min_select_to_read_ns < 0 || gap_ns < min_select_to_read_ns) {
            min_select_to_read_ns = gap_ns;
        }

        if (selected_reg == plat::mfi_reg::kDeviceVersion && rx_len == 1U) {
            rx_data[0] = dev_ver;
            return plat::kI2cOk;
        }
        if (selected_reg == plat::mfi_reg::kFirmwareVersion && rx_len == 1U) {
            rx_data[0] = fw_ver;
            return plat::kI2cOk;
        }
        if (selected_reg == plat::mfi_reg::kProtocolMajor && rx_len == 1U) {
            rx_data[0] = proto_major;
            return plat::kI2cOk;
        }
        if (selected_reg == plat::mfi_reg::kProtocolMinor && rx_len == 1U) {
            rx_data[0] = proto_minor;
            return plat::kI2cOk;
        }
        if (selected_reg == plat::mfi_reg::kDeviceId && rx_len == 4U) {
            rx_data[0] = static_cast<uint8_t>((dev_id >> 24) & 0xffU);
            rx_data[1] = static_cast<uint8_t>((dev_id >> 16) & 0xffU);
            rx_data[2] = static_cast<uint8_t>((dev_id >> 8) & 0xffU);
            rx_data[3] = static_cast<uint8_t>(dev_id & 0xffU);
            return plat::kI2cOk;
        }
        if (selected_reg == plat::mfi_reg::kErrorCode && rx_len == 1U) {
            rx_data[0] = error_code;
            return plat::kI2cOk;
        }
        if (selected_reg == plat::mfi_reg::kAuthControlStatus && rx_len == 1U) {
            if (auth_pending_nacks > 0 && nack_counter_ < auth_pending_nacks) {
                ++nack_counter_;
                return plat::kI2cNack;
            }
            if (never_complete_auth || poll_counter_ < auth_pending_polls) {
                ++poll_counter_;
                rx_data[0] = 0x00U;
                return plat::kI2cOk;
            }
            rx_data[0] = auth_terminal_status;
            return plat::kI2cOk;
        }
        if (selected_reg == plat::mfi_reg::kCertificateLength && rx_len == 2U) {
            const uint16_t len = override_cert_len ? cert_len_override : static_cast<uint16_t>(certificate.size());
            rx_data[0] = static_cast<uint8_t>((len >> 8) & 0xffU);
            rx_data[1] = static_cast<uint8_t>(len & 0xffU);
            return plat::kI2cOk;
        }
        if (selected_reg >= plat::mfi_reg::kCertificateData && selected_reg <= 0x3fU) {
            const size_t page = static_cast<size_t>(selected_reg - plat::mfi_reg::kCertificateData);
            const size_t offset = page * plat::mfi_reg::kCertPageBytes;
            if (offset + rx_len > certificate.size()) {
                return plat::kI2cNack;
            }
            std::memcpy(rx_data, &certificate[offset], rx_len);
            return plat::kI2cOk;
        }
        if (selected_reg == plat::mfi_reg::kResponseLength && rx_len == 2U) {
            const uint16_t len = override_resp_len ? resp_len_override : static_cast<uint16_t>(last_signature.size());
            rx_data[0] = static_cast<uint8_t>((len >> 8) & 0xffU);
            rx_data[1] = static_cast<uint8_t>(len & 0xffU);
            return plat::kI2cOk;
        }
        if (selected_reg == plat::mfi_reg::kResponseData) {
            if (rx_len != last_signature.size()) {
                return plat::kI2cInvalidArg;
            }
            std::memcpy(rx_data, &last_signature[0], rx_len);
            return plat::kI2cOk;
        }
        return plat::kI2cNack;
    }

private:
    void computeSignature() {
        const size_t sig_len = (proto_major == 2U) ? 128U : 64U;
        last_signature.assign(sig_len, 0U);
        for (size_t i = 0U; i < sig_len; ++i) {
            const uint8_t ch = written_challenge.empty()
                                   ? 0U
                                   : written_challenge[i % written_challenge.size()];
            last_signature[i] = static_cast<uint8_t>(ch ^ proto_major ^ static_cast<uint8_t>(i));
        }
    }

    bool open_state_;
    int poll_counter_;
    int nack_counter_;
};

class RecordingProbeCallback : public plat::I2cMfiAuthProvider::ProbeCallback {
public:
    int calls;
    bool ok;
    plat::MfiChipInfo info;
    RecordingProbeCallback() : calls(0), ok(false), info() {}
    virtual void onProbeComplete(bool probe_ok, const plat::MfiChipInfo& chip_info) {
        ++calls;
        ok = probe_ok;
        info = chip_info;
    }
};

class RecordingAuthCallback : public iap2::AuthCallback {
public:
    int cert_calls;
    bool cert_ok;
    uint64_t cert_op_id;
    Bytes cert_data;

    int sign_calls;
    bool sign_ok;
    uint64_t sign_op_id;
    Bytes sign_data;

    RecordingAuthCallback()
        : cert_calls(0), cert_ok(false), cert_op_id(0ULL),
          sign_calls(0), sign_ok(false), sign_op_id(0ULL) {}

    virtual void onCertificateComplete(uint64_t op_id, bool ok, const Bytes& certificate) {
        ++cert_calls;
        cert_op_id = op_id;
        cert_ok = ok;
        cert_data = certificate;
    }

    virtual void onSignatureComplete(uint64_t op_id, bool ok, const Bytes& signature) {
        ++sign_calls;
        sign_op_id = op_id;
        sign_ok = ok;
        sign_data = signature;
    }
};

void driveReactor(plat::Reactor& reactor, int steps, int64_t step_ms) {
    for (int i = 0; i < steps; ++i) {
        advanceFakeClockMs(step_ms);
        reactor.runOnce(0);
    }
}

class MemoryByteSink : public iap2::ByteSink {
public:
    std::vector<Bytes> writes;
    Bytes flat;
    virtual bool sendBytes(const uint8_t* data, size_t len) {
        writes.push_back(Bytes(data, data + len));
        flat.insert(flat.end(), data, data + len);
        return true;
    }
    void clear() {
        writes.clear();
        flat.clear();
    }
};

class RecordingIap2Listener : public iap2::SessionListener {
public:
    int auth_succeeded;
    std::vector<std::string> auth_failed;
    int ready_count;
    RecordingIap2Listener() : auth_succeeded(0), ready_count(0) {}
    virtual void onAuthenticationSucceeded() { ++auth_succeeded; }
    virtual void onAuthenticationFailed(const std::string& reason) { auth_failed.push_back(reason); }
    virtual void onReady() { ++ready_count; }
};

class FakeDevice {
public:
    Bytes tx_to_accessory;
    std::vector<iap2::Frame> received_frames;
    bool detect_seen;
    bool syn_seen;
    uint8_t dev_seq;
    uint8_t last_acc_seq;
    uint8_t session_id;
    iap2::SynPayload dev_syn;
    iap2::CsmFramer framer;

    FakeDevice()
        : detect_seen(false),
          syn_seen(false),
          dev_seq(100U),
          last_acc_seq(0U),
          session_id(10U) {
        dev_syn.version = 1;
        dev_syn.max_outstanding = 3;
        dev_syn.max_packet_length = 256;
        dev_syn.retransmission_timeout_ms = 1000;
        dev_syn.cumulative_ack_timeout_ms = 50;
        dev_syn.max_retransmissions = 5;
        dev_syn.max_cumulative_acks = 1;
        dev_syn.sessions.push_back(iap2::SynSession(10U, iap2::kSessionTypeControl, 1U));
    }

    void consumeFromAccessory(MemoryByteSink& acc_sink) {
        Bytes& buf = acc_sink.flat;
        size_t pos = 0U;
        while (pos < buf.size()) {
            if (pos + iap2::kDetectSequenceBytes <= buf.size() &&
                std::memcmp(&buf[pos], iap2::kDetectSequence, iap2::kDetectSequenceBytes) == 0) {
                detect_seen = true;
                pos += iap2::kDetectSequenceBytes;
                continue;
            }
            if (pos + iap2::kLinkHeaderBytes <= buf.size() &&
                buf[pos] == 0xffU && buf[pos + 1U] == 0x5aU) {
                const uint16_t len = static_cast<uint16_t>(
                    (static_cast<uint16_t>(buf[pos + 2U]) << 8) | buf[pos + 3U]);
                iap2::LinkPacket pkt;
                REQUIRE(len >= iap2::kLinkHeaderBytes && pos + len <= buf.size());
                REQUIRE(iap2::LinkPacket::decode(&buf[pos], len, pkt));
                pos += len;
                if ((pkt.control & iap2::kCtrlSyn) != 0U) {
                    syn_seen = true;
                    last_acc_seq = pkt.seq;
                    iap2::SynPayload acc_syn;
                    REQUIRE(iap2::SynPayload::decode(pkt.payload, acc_syn));
                    const iap2::SynSession* ctrl = acc_syn.findSessionByType(iap2::kSessionTypeControl);
                    if (ctrl != NULL) session_id = ctrl->id;
                } else if (!pkt.payload.empty()) {
                    last_acc_seq = pkt.seq;
                    REQUIRE(framer.push(&pkt.payload[0], pkt.payload.size(), received_frames));
                    sendAck();
                }
                continue;
            }
            REQUIRE(false);
        }
        buf.clear();
    }

    void sendDetect() {
        tx_to_accessory.insert(tx_to_accessory.end(),
                               iap2::kDetectSequence,
                               iap2::kDetectSequence + iap2::kDetectSequenceBytes);
    }

    void sendSynAck() {
        iap2::LinkPacket pkt;
        pkt.control = static_cast<uint8_t>(iap2::kCtrlSyn | iap2::kCtrlAck);
        pkt.seq = dev_seq;
        pkt.ack = last_acc_seq;
        pkt.session_id = 0U;
        REQUIRE(dev_syn.encode(pkt.payload));
        Bytes raw;
        REQUIRE(pkt.encode(raw));
        tx_to_accessory.insert(tx_to_accessory.end(), raw.begin(), raw.end());
    }

    void sendAck() {
        iap2::LinkPacket pkt;
        pkt.control = iap2::kCtrlAck;
        pkt.seq = dev_seq;
        pkt.ack = last_acc_seq;
        pkt.session_id = 0U;
        Bytes raw;
        REQUIRE(pkt.encode(raw));
        tx_to_accessory.insert(tx_to_accessory.end(), raw.begin(), raw.end());
    }

    void sendControlFrame(uint16_t msg_id, const iap2::ParameterList& params = iap2::ParameterList()) {
        iap2::Frame f;
        REQUIRE(iap2::Frame::build(msg_id, params, f));
        Bytes csm;
        REQUIRE(f.encode(csm));
        std::vector<Bytes> chunks;
        const size_t max_pl = dev_syn.max_packet_length - iap2::kLinkPacketOverheadBytes;
        REQUIRE(iap2::CsmFramer::splitForLink(csm, max_pl, chunks));
        for (size_t i = 0U; i < chunks.size(); ++i) {
            dev_seq = static_cast<uint8_t>(dev_seq + 1U);
            iap2::LinkPacket pkt;
            pkt.control = iap2::kCtrlAck;
            pkt.seq = dev_seq;
            pkt.ack = last_acc_seq;
            pkt.session_id = session_id;
            pkt.payload = chunks[i];
            Bytes raw;
            REQUIRE(pkt.encode(raw));
            tx_to_accessory.insert(tx_to_accessory.end(), raw.begin(), raw.end());
        }
    }

    void flushToAccessory(iap2::Session& session, MemoryByteSink& acc_sink) {
        int guard = 0;
        while (!tx_to_accessory.empty() || !acc_sink.flat.empty()) {
            REQUIRE(++guard < 64);
            if (!tx_to_accessory.empty()) {
                const Bytes batch = tx_to_accessory;
                tx_to_accessory.clear();
                session.feed(batch);
            }
            if (!acc_sink.flat.empty()) {
                consumeFromAccessory(acc_sink);
            }
        }
    }
};

std::string makeTempDir() {
#ifdef _WIN32
    return "";
#else
    char tmpl[] = "/tmp/entrynav2-mfi-test-XXXXXX";
    char* d = mkdtemp(tmpl);
    return d != NULL ? std::string(d) : std::string();
#endif
}

void removeTempDir(const std::string& dir) {
#ifndef _WIN32
    if (dir.empty()) return;
    unlink((dir + "/identity.bin").c_str());
    unlink((dir + "/controllers.bin").c_str());
    unlink((dir + "/daemon.state").c_str());
    unlink((dir + "/media_recall").c_str());
    rmdir(dir.c_str());
#else
    (void)dir;
#endif
}

TEST_CASE(cryptoPrimitives) {
    // FIPS 180-4 SHA-1 vectors
    {
        uint8_t d[crypto::kSha1Bytes];
        crypto::sha1(NULL, 0U, d);
        CHECK_BYTES_EQ(test_support::hexToBytes("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
                       Bytes(d, d + sizeof(d)));

        const char* abc = "abc";
        crypto::sha1(reinterpret_cast<const uint8_t*>(abc), 3U, d);
        CHECK_BYTES_EQ(test_support::hexToBytes("a9993e364706816aba3e25717850c26c9cd0d89d"),
                       Bytes(d, d + sizeof(d)));

        const char* long_msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        crypto::sha1(reinterpret_cast<const uint8_t*>(long_msg), std::strlen(long_msg), d);
        CHECK_BYTES_EQ(test_support::hexToBytes("84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
                       Bytes(d, d + sizeof(d)));
    }

    // FIPS 180-4 SHA-256 vectors
    {
        uint8_t d[crypto::kSha256Bytes];
        crypto::sha256(NULL, 0U, d);
        CHECK_BYTES_EQ(test_support::hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                       Bytes(d, d + sizeof(d)));

        const char* abc = "abc";
        crypto::sha256(reinterpret_cast<const uint8_t*>(abc), 3U, d);
        CHECK_BYTES_EQ(test_support::hexToBytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                       Bytes(d, d + sizeof(d)));

        const char* long_msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        crypto::sha256(reinterpret_cast<const uint8_t*>(long_msg), std::strlen(long_msg), d);
        CHECK_BYTES_EQ(test_support::hexToBytes("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
                       Bytes(d, d + sizeof(d)));
    }

    // NIST SP 800-38A F.5.1 CTR-AES128 encrypt/decrypt (3 blocks + partial block check)
    {
        const Bytes key = test_support::hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        const Bytes iv = test_support::hexToBytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const Bytes pt = test_support::hexToBytes(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef");
        const Bytes expected_ct = test_support::hexToBytes(
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab");

        Bytes ct(pt.size(), 0U);
        REQUIRE(crypto::aes128Ctr(&key[0], &iv[0], &pt[0], pt.size(), &ct[0]));
        CHECK_BYTES_EQ(expected_ct, ct);

        // Decrypt in-place (aliasing input and output) on a 37-byte partial prefix
        Bytes partial(ct.begin(), ct.begin() + 37);
        REQUIRE(crypto::aes128Ctr(&key[0], &iv[0], &partial[0], partial.size(), &partial[0]));
        CHECK_BYTES_EQ(Bytes(pt.begin(), pt.begin() + 37), partial);
    }
}

TEST_CASE(parseMfiI2cSpecTests) {
    plat::MfiI2cConfig cfg;
    std::string err;

    REQUIRE(plat::parseMfiI2cSpec("/dev/i2c-0", cfg, &err));
    CHECK(cfg.enabled);
    CHECK_EQ(std::string("/dev/i2c-0"), cfg.device_path);
    CHECK_EQ(0U, static_cast<unsigned>(cfg.address7));

    REQUIRE(plat::parseMfiI2cSpec("/dev/i2c-1:0x10", cfg, &err));
    CHECK(cfg.enabled);
    CHECK_EQ(std::string("/dev/i2c-1"), cfg.device_path);
    CHECK_EQ(0x10U, static_cast<unsigned>(cfg.address7));

    REQUIRE(plat::parseMfiI2cSpec("/dev/i2c-2:17", cfg, &err));
    CHECK_EQ(std::string("/dev/i2c-2"), cfg.device_path);
    CHECK_EQ(0x11U, static_cast<unsigned>(cfg.address7));

    CHECK(!plat::parseMfiI2cSpec("", cfg, &err));
    CHECK(!plat::parseMfiI2cSpec("/dev/i2c-0:", cfg, &err));
    CHECK(!plat::parseMfiI2cSpec(":0x10", cfg, &err));
    CHECK(!plat::parseMfiI2cSpec("/dev/i2c-0:0x00", cfg, &err));
    CHECK(!plat::parseMfiI2cSpec("/dev/i2c-0:0x80", cfg, &err));
    CHECK(!plat::parseMfiI2cSpec("/dev/i2c-0:0xaa", cfg, &err));
    CHECK(!plat::parseMfiI2cSpec("/dev/i2c-0:-1", cfg, &err));
    CHECK(!plat::parseMfiI2cSpec("/dev/i2c-0:bad", cfg, &err));
}

TEST_CASE(asyncHappyPathCp20CAndCp30) {
    // 1. CP 2.0C at secondary 7-bit address 0x11 (auto-probed after 0x10 NACKs)
    {
        resetFakeClock();
        plat::Reactor reactor(&fakeClockNs);
        REQUIRE(reactor.init());

        FakeMfiChipBackend chip;
        chip.chip_addr = 0x11U;
        chip.dev_ver = 0x05U;
        chip.fw_ver = 0x01U;
        chip.proto_major = 2U;
        chip.proto_minor = 0U;
        chip.dev_id = 0x00000200U;
        chip.setDerCertificate(420U);

        plat::MfiI2cConfig cfg;
        cfg.enabled = true;
        cfg.device_path = "/dev/fake-i2c-0";
        cfg.address7 = 0U;  // auto-probe 0x10 then 0x11
        cfg.select_to_read_gap_ms = 5;
        cfg.nack_retry_delay_ms = 20;
        cfg.io_retry_timeout_ms = 100;
        cfg.auth_initial_delay_ms = 10;
        cfg.auth_poll_interval_ms = 10;
        cfg.validate_der_certificate = true;

        plat::I2cMfiAuthProvider provider(reactor, cfg, &chip);
        RecordingProbeCallback probe_cb;
        std::string err;
        REQUIRE(provider.start(&probe_cb, &err));
        CHECK(chip.open_called);
        CHECK(!chip.has_selected_reg);

        driveReactor(reactor, 60, 20);
        CHECK_EQ(1, probe_cb.calls);
        CHECK(probe_cb.ok);
        CHECK_EQ(0x11U, static_cast<unsigned>(provider.chipInfo().address7));
        CHECK_EQ(2, provider.protocolMajor());
        CHECK(!chip.saw_combined_write_read);
        CHECK(chip.min_select_to_read_ns >= 5LL * 1000000LL);
        CHECK_BYTES_EQ(chip.certificate, provider.cachedCertificate());

        // Subsequent beginGetCertificate hits cache inline with op_id == 0
        RecordingAuthCallback auth_cb;
        const uint64_t cert_op = provider.beginGetCertificate(auth_cb);
        CHECK_EQ(0ULL, cert_op);
        CHECK_EQ(1, auth_cb.cert_calls);
        CHECK(auth_cb.cert_ok);
        CHECK_BYTES_EQ(chip.certificate, auth_cb.cert_data);

        // Async sign challenge (CP 2.0C -> 128B signature)
        Bytes challenge(32U, 0x33U);
        const uint64_t sign_op = provider.beginSignChallenge(&challenge[0], challenge.size(), auth_cb);
        CHECK(sign_op != 0ULL);
        CHECK_EQ(0, auth_cb.sign_calls);

        driveReactor(reactor, 30, 5);
        CHECK_EQ(1, auth_cb.sign_calls);
        CHECK(auth_cb.sign_ok);
        CHECK_EQ(sign_op, auth_cb.sign_op_id);
        CHECK_EQ(32U, static_cast<unsigned>(chip.written_challenge_len));
        CHECK_BYTES_EQ(challenge, chip.written_challenge);
        CHECK_BYTES_EQ(chip.last_signature, auth_cb.sign_data);
        CHECK_EQ(128U, auth_cb.sign_data.size());

        provider.stop();
        CHECK(!chip.isOpen());
    }

    // 2. CP 3.0 at 0x10 with multi-page 900B cert and uncached cert read
    {
        resetFakeClock();
        plat::Reactor reactor(&fakeClockNs);
        REQUIRE(reactor.init());

        FakeMfiChipBackend chip;
        chip.chip_addr = 0x10U;
        chip.dev_ver = 0x07U;
        chip.fw_ver = 0x02U;
        chip.proto_major = 3U;
        chip.proto_minor = 0U;
        chip.dev_id = 0x00000301U;
        chip.setDerCertificate(900U);

        plat::MfiI2cConfig cfg;
        cfg.enabled = true;
        cfg.device_path = "/dev/fake-i2c-1";
        cfg.address7 = 0x10U;
        cfg.cache_certificate = false;
        cfg.validate_der_certificate = true;

        plat::I2cMfiAuthProvider provider(reactor, cfg, &chip);
        RecordingProbeCallback probe_cb;
        REQUIRE(provider.start(&probe_cb));
        driveReactor(reactor, 30, 5);
        CHECK(probe_cb.ok);
        CHECK_EQ(3, provider.protocolMajor());

        RecordingAuthCallback auth_cb;
        const uint64_t cert_op = provider.beginGetCertificate(auth_cb);
        CHECK(cert_op != 0ULL);
        driveReactor(reactor, 40, 5);
        CHECK_EQ(1, auth_cb.cert_calls);
        CHECK(auth_cb.cert_ok);
        CHECK_BYTES_EQ(chip.certificate, auth_cb.cert_data);

        Bytes challenge(32U, 0x77U);
        const uint64_t sign_op = provider.beginSignChallenge(&challenge[0], challenge.size(), auth_cb);
        CHECK(sign_op != 0ULL);
        driveReactor(reactor, 30, 5);
        CHECK_EQ(1, auth_cb.sign_calls);
        CHECK(auth_cb.sign_ok);
        CHECK_EQ(64U, auth_cb.sign_data.size());
        CHECK_BYTES_EQ(chip.last_signature, auth_cb.sign_data);
    }
}

TEST_CASE(nackBusyReselectAndErrorCases) {
    // NACK on wake, EBUSY contention, second-half read NACK re-select, and transient auth poll NACK
    {
        resetFakeClock();
        plat::Reactor reactor(&fakeClockNs);
        REQUIRE(reactor.init());

        FakeMfiChipBackend chip;
        chip.initial_busys = 2;
        chip.initial_nacks = 2;
        chip.fail_second_half_read_nacks = 1;
        chip.auth_pending_nacks = 2;
        chip.auth_pending_polls = 2;

        plat::MfiI2cConfig cfg;
        cfg.enabled = true;
        cfg.device_path = "/dev/fake-i2c-0";
        cfg.address7 = 0x10U;
        cfg.cache_certificate = false;

        plat::I2cMfiAuthProvider provider(reactor, cfg, &chip);
        RecordingProbeCallback probe_cb;
        REQUIRE(provider.start(&probe_cb));
        driveReactor(reactor, 80, 20);
        CHECK(probe_cb.ok);
        CHECK(chip.saw_select_then_read_after_nack);
        CHECK(provider.stats().nack_retries >= 3ULL);
        CHECK(provider.stats().busy_retries >= 2ULL);

        RecordingAuthCallback auth_cb;
        Bytes challenge(16U, 0x12U);
        REQUIRE(provider.beginSignChallenge(&challenge[0], challenge.size(), auth_cb) != 0ULL);
        driveReactor(reactor, 40, 10);
        CHECK_EQ(1, auth_cb.sign_calls);
        CHECK(auth_cb.sign_ok);
    }

    // Wrong version (0x00 / 0xff / unsupported proto_major)
    {
        resetFakeClock();
        plat::Reactor reactor(&fakeClockNs);
        REQUIRE(reactor.init());

        FakeMfiChipBackend chip;
        chip.dev_ver = 0xffU;
        plat::MfiI2cConfig cfg;
        cfg.enabled = true;
        cfg.device_path = "/dev/fake-i2c-0";
        cfg.address7 = 0x10U;
        cfg.io_retry_timeout_ms = 50;

        plat::I2cMfiAuthProvider provider(reactor, cfg, &chip);
        RecordingProbeCallback probe_cb;
        REQUIRE(provider.start(&probe_cb));
        driveReactor(reactor, 20, 10);
        CHECK_EQ(1, probe_cb.calls);
        CHECK(!probe_cb.ok);

        chip.dev_ver = 0x02U;
        chip.proto_major = 1U;
        RecordingProbeCallback probe_cb2;
        REQUIRE(provider.beginProbe(&probe_cb2));
        driveReactor(reactor, 20, 10);
        CHECK_EQ(1, probe_cb2.calls);
        CHECK(!probe_cb2.ok);
    }

    // Truncated / malformed DER / oversized cert
    {
        resetFakeClock();
        plat::Reactor reactor(&fakeClockNs);
        REQUIRE(reactor.init());

        FakeMfiChipBackend chip;
        chip.override_cert_len = true;
        chip.cert_len_override = 2000U;  // > default max_certificate_bytes (1920)

        plat::MfiI2cConfig cfg;
        cfg.enabled = true;
        cfg.device_path = "/dev/fake-i2c-0";
        cfg.address7 = 0x10U;
        cfg.cache_certificate = false;
        cfg.validate_der_certificate = true;

        plat::I2cMfiAuthProvider provider(reactor, cfg, &chip);
        RecordingProbeCallback probe_cb;
        REQUIRE(provider.start(&probe_cb));
        driveReactor(reactor, 20, 10);
        CHECK(probe_cb.ok);

        RecordingAuthCallback auth_cb;
        REQUIRE(provider.beginGetCertificate(auth_cb) != 0ULL);
        driveReactor(reactor, 20, 10);
        CHECK_EQ(1, auth_cb.cert_calls);
        CHECK(!auth_cb.cert_ok);

        // Valid length, corrupted DER header
        chip.override_cert_len = false;
        chip.certificate[0] = 0x31U;
        REQUIRE(provider.beginGetCertificate(auth_cb) != 0ULL);
        driveReactor(reactor, 40, 10);
        CHECK_EQ(2, auth_cb.cert_calls);
        CHECK(!auth_cb.cert_ok);
    }

    // Auth timeout reads 0x05 error code register, and 0x80 error bit fails fast
    {
        resetFakeClock();
        plat::Reactor reactor(&fakeClockNs);
        REQUIRE(reactor.init());

        FakeMfiChipBackend chip;
        chip.never_complete_auth = true;
        chip.error_code = 0x42U;

        plat::MfiI2cConfig cfg;
        cfg.enabled = true;
        cfg.device_path = "/dev/fake-i2c-0";
        cfg.address7 = 0x10U;
        cfg.cache_certificate = false;
        cfg.auth_timeout_ms = 60;
        cfg.auth_poll_interval_ms = 10;

        plat::I2cMfiAuthProvider provider(reactor, cfg, &chip);
        RecordingProbeCallback probe_cb;
        REQUIRE(provider.start(&probe_cb));
        driveReactor(reactor, 20, 10);
        CHECK(probe_cb.ok);

        RecordingAuthCallback auth_cb;
        Bytes ch(20U, 0xaaU);
        REQUIRE(provider.beginSignChallenge(&ch[0], ch.size(), auth_cb) != 0ULL);
        driveReactor(reactor, 30, 10);
        CHECK_EQ(1, auth_cb.sign_calls);
        CHECK(!auth_cb.sign_ok);
        CHECK_EQ(0x42U, static_cast<unsigned>(provider.stats().last_chip_error));

        chip.never_complete_auth = false;
        chip.auth_pending_polls = 0;
        chip.auth_terminal_status = 0x80U;
        chip.error_code = 0x19U;
        REQUIRE(provider.beginSignChallenge(&ch[0], ch.size(), auth_cb) != 0ULL);
        driveReactor(reactor, 10, 10);
        CHECK_EQ(2, auth_cb.sign_calls);
        CHECK(!auth_cb.sign_ok);
        CHECK_EQ(0x19U, static_cast<unsigned>(provider.stats().last_chip_error));
    }
}

TEST_CASE(iap2AsyncMfiHandshakeAndCancel) {
    resetFakeClock();
    plat::Reactor reactor(&fakeClockNs);
    REQUIRE(reactor.init());

    FakeMfiChipBackend chip;
    chip.proto_major = 3U;
    chip.setDerCertificate(380U);
    chip.auth_pending_polls = 3;

    plat::MfiI2cConfig cfg;
    cfg.enabled = true;
    cfg.device_path = "/dev/fake-i2c-0";
    cfg.address7 = 0x10U;
    cfg.cache_certificate = false;

    plat::I2cMfiAuthProvider provider(reactor, cfg, &chip);
    REQUIRE(provider.start());
    driveReactor(reactor, 25, 10);
    REQUIRE(provider.chipInfo().probed);

    MemoryByteSink acc_sink;
    RecordingIap2Listener listener;
    iap2::SessionConfig sess_cfg;
    sess_cfg.identification.name = "BMW EntryNav2";
    sess_cfg.identification.model = "HU_ENTRYNAV2";
    sess_cfg.identification.manufacturer = "BMW";
    sess_cfg.identification.serial_number = "00000001";
    sess_cfg.identification.firmware_version = "1.0.0";
    sess_cfg.identification.hardware_version = "1.0.0";
    iap2::Session session(acc_sink, provider, listener, sess_cfg);
    FakeDevice dev;

    session.start();
    dev.consumeFromAccessory(acc_sink);
    REQUIRE(dev.detect_seen);
    dev.sendDetect();
    dev.flushToAccessory(session, acc_sink);
    REQUIRE(dev.syn_seen);
    dev.sendSynAck();
    dev.flushToAccessory(session, acc_sink);
    CHECK_EQ(iap2::kSessionConnected, session.state());

    // Device -> Accessory: StartIdentification (0x1D00) + IdentificationAccepted (0x1D02)
    dev.sendControlFrame(iap2::msg::kStartIdentification);
    dev.flushToAccessory(session, acc_sink);
    dev.received_frames.clear();
    dev.sendControlFrame(iap2::msg::kIdentificationAccepted);
    dev.flushToAccessory(session, acc_sink);
    CHECK_EQ(iap2::kSessionIdentified, session.state());

    // Device -> Accessory: RequestAuthenticationCertificate (0xAA00)
    dev.sendControlFrame(iap2::msg::kRequestAuthenticationCertificate);
    session.feed(dev.tx_to_accessory);
    dev.tx_to_accessory.clear();
    // Link ACK may be emitted immediately, but no CSM auth response before Reactor timers advance!
    dev.consumeFromAccessory(acc_sink);
    CHECK(dev.received_frames.empty());
    CHECK(provider.isBusy());

    driveReactor(reactor, 30, 10);
    CHECK(!provider.isBusy());
    REQUIRE(!acc_sink.flat.empty());
    dev.flushToAccessory(session, acc_sink);

    bool saw_cert = false;
    for (size_t i = 0; i < dev.received_frames.size(); ++i) {
        if (dev.received_frames[i].message_id == iap2::msg::kAuthenticationCertificate) {
            saw_cert = true;
            iap2::ParameterList cert_params;
            REQUIRE(iap2::ParameterList::decode(dev.received_frames[i].payload, cert_params));
            Bytes got_cert;
            REQUIRE(cert_params.readBytes(iap2::param::kAuthCertificateData, got_cert));
            CHECK_BYTES_EQ(chip.certificate, got_cert);
        }
    }
    CHECK(saw_cert);
    dev.received_frames.clear();

    // Device -> Accessory: RequestAuthenticationChallengeResponse (0xAA02)
    Bytes challenge(32U, 0x55U);
    iap2::ParameterList ch_params;
    ch_params.addRaw(iap2::param::kAuthChallengeData, challenge);
    dev.sendControlFrame(iap2::msg::kRequestAuthenticationChallengeResponse, ch_params);
    session.feed(dev.tx_to_accessory);
    dev.tx_to_accessory.clear();
    dev.consumeFromAccessory(acc_sink);
    CHECK(dev.received_frames.empty());
    CHECK(provider.isBusy());

    driveReactor(reactor, 30, 10);
    dev.flushToAccessory(session, acc_sink);

    bool saw_sig = false;
    for (size_t i = 0; i < dev.received_frames.size(); ++i) {
        if (dev.received_frames[i].message_id == iap2::msg::kAuthenticationResponse) {
            saw_sig = true;
            iap2::ParameterList sig_params;
            REQUIRE(iap2::ParameterList::decode(dev.received_frames[i].payload, sig_params));
            Bytes got_sig;
            REQUIRE(sig_params.readBytes(iap2::param::kAuthChallengeResponseData, got_sig));
            CHECK_BYTES_EQ(chip.last_signature, got_sig);
        }
    }
    CHECK(saw_sig);
    dev.received_frames.clear();

    // Device -> Accessory: AuthenticationSucceeded (0xAA05)
    dev.sendControlFrame(iap2::msg::kAuthenticationSucceeded);
    dev.flushToAccessory(session, acc_sink);
    CHECK_EQ(1, listener.auth_succeeded);
    CHECK(session.isAuthenticated());
    CHECK(session.isReady());

    // Start a second challenge request and cancel via session.reset() mid-flight
    dev.sendControlFrame(iap2::msg::kRequestAuthenticationChallengeResponse, ch_params);
    session.feed(dev.tx_to_accessory);
    dev.tx_to_accessory.clear();
    dev.consumeFromAccessory(acc_sink);
    dev.received_frames.clear();
    CHECK(provider.isBusy());
    session.reset(false);
    CHECK(!provider.isBusy());
    acc_sink.clear();
    driveReactor(reactor, 20, 10);
    CHECK(acc_sink.flat.empty());
}

TEST_CASE(mfiSapWithI2cProvider) {
    resetFakeClock();
    plat::Reactor reactor(&fakeClockNs);
    REQUIRE(reactor.init());

    FakeMfiChipBackend chip;
    chip.proto_major = 2U;
    chip.setDerCertificate(256U);

    plat::MfiI2cConfig cfg;
    cfg.enabled = true;
    cfg.device_path = "/dev/fake-i2c-0";
    cfg.address7 = 0x10U;
    cfg.select_to_read_gap_ms = 0;
    cfg.auth_initial_delay_ms = 0;
    cfg.auth_poll_interval_ms = 1;
    chip.auth_pending_polls = 0;

    plat::I2cMfiAuthProvider provider(reactor, cfg, &chip);
    REQUIRE(provider.start());
    driveReactor(reactor, 20, 10);
    REQUIRE(provider.chipInfo().probed);
    CHECK(!provider.cachedCertificate().empty());

    DeterministicRng rng;
    crypto::X25519KeyPair client_kp;
    uint8_t secret[crypto::kKeyBytes];
    rng.fill(secret, sizeof(secret));
    crypto::x25519FromSecret(secret, client_kp);

    Bytes req(1U + crypto::kKeyBytes, 0x01U);
    std::memcpy(&req[1], client_kp.public_key, crypto::kKeyBytes);

    Bytes resp;
    REQUIRE(mfi_sap::handleAuthSetup(req, static_cast<session::AuthProvider&>(provider), rng, resp));
    CHECK(resp.size() > 40U);
    CHECK_EQ(crypto::kSha1Bytes, chip.written_challenge.size());  // proto_major == 2 -> SHA-1
}

TEST_CASE(daemonMfiWiringTests) {
#ifdef _WIN32
    return;
#else
    const std::string dir = makeTempDir();
    REQUIRE(!dir.empty());

    // 1. Default config leaves MFi I2C disabled and UnavailableAuthProvider remains active
    {
        plat::CarPlayDaemonConfig cfg;
        cfg.data_dir = dir;
        cfg.state_file = dir + "/daemon.state";
        cfg.media_recall_file = dir + "/media_recall";
        cfg.bind_loopback_only = true;
        cfg.control_port = 0U;
        cfg.enable_video = false;
        cfg.enable_audio = false;
        cfg.enable_input = false;
        cfg.enable_control = false;
        cfg.query_display_from_ilm = false;

        plat::CarPlayDaemon daemon(cfg);
        REQUIRE(daemon.start());
        CHECK(daemon.mfiAuth() == NULL);
        daemon.stop();
    }

    // 2. Enabled with injected fake I2C backend wires daemon.mfiAuth() cleanly
    {
        FakeMfiChipBackend chip;
        plat::CarPlayDaemonConfig cfg;
        cfg.data_dir = dir;
        cfg.state_file = dir + "/daemon.state";
        cfg.media_recall_file = dir + "/media_recall";
        cfg.bind_loopback_only = true;
        cfg.control_port = 0U;
        cfg.enable_video = false;
        cfg.enable_audio = false;
        cfg.enable_input = false;
        cfg.enable_control = false;
        cfg.query_display_from_ilm = false;
        REQUIRE(plat::parseMfiI2cSpec("/dev/fake-i2c-0:0x10", cfg.mfi_i2c_config));

        plat::CarPlayDaemon daemon(cfg);
        daemon.setMfiI2cBackendForTest(&chip);
        REQUIRE(daemon.start());
        REQUIRE(daemon.mfiAuth() != NULL);
        CHECK(chip.open_called);

        for (int i = 0; i < 40 && !daemon.mfiAuth()->chipInfo().probed; ++i) {
            daemon.reactor().runOnce(5);
        }
        CHECK(daemon.mfiAuth()->chipInfo().probed);
        daemon.stop();
        CHECK(daemon.mfiAuth() == NULL);
        CHECK(!chip.isOpen());
    }

    // 3. Enabled with nonexistent Linux device fails start() cleanly
    {
        plat::CarPlayDaemonConfig cfg;
        cfg.data_dir = dir;
        cfg.state_file = dir + "/daemon.state";
        cfg.media_recall_file = dir + "/media_recall";
        cfg.bind_loopback_only = true;
        cfg.control_port = 0U;
        cfg.enable_video = false;
        cfg.enable_audio = false;
        cfg.enable_input = false;
        cfg.enable_control = false;
        cfg.query_display_from_ilm = false;
        REQUIRE(plat::parseMfiI2cSpec("/dev/nonexistent-i2c-99:0x10", cfg.mfi_i2c_config));

        plat::CarPlayDaemon daemon(cfg);
        CHECK(!daemon.start());
        CHECK(daemon.mfiAuth() == NULL);
    }

    removeTempDir(dir);
#endif
}

TEST_CASE(mfiCp30DevVer05At0x10Visit3HardwareSpec) {
    resetFakeClock();
    plat::Reactor reactor(&fakeClockNs);
    REQUIRE(reactor.init());

    FakeMfiChipBackend chip;
    chip.chip_addr = 0x10U;
    chip.dev_ver = 0x05U;  // verified on car visit 3: @ok|mfi|/dev/i2c-0 I2C_FUNCS ok, addr=0x10 dev_ver=0x05
    chip.fw_ver = 0x01U;
    chip.proto_major = 3U;
    chip.proto_minor = 0U;
    chip.setDerCertificate(900U);

    plat::MfiI2cConfig cfg;
    REQUIRE(plat::parseMfiI2cSpec("/dev/i2c-0:0x10", cfg));
    cfg.select_to_read_gap_ms = 5;
    cfg.validate_der_certificate = true;

    plat::I2cMfiAuthProvider auth(reactor, cfg, &chip);
    RecordingProbeCallback probe_cb;
    REQUIRE(auth.start(&probe_cb));
    driveReactor(reactor, 60, 20);
    REQUIRE(probe_cb.calls == 1);
    CHECK(probe_cb.ok);
    CHECK_EQ(0x10U, probe_cb.info.address7);
    CHECK_EQ(0x05U, probe_cb.info.device_version);
    CHECK_EQ(3U, probe_cb.info.protocol_major);
    CHECK_EQ(3, auth.protocolMajor());
    CHECK(!auth.isBusy());

    RecordingAuthCallback auth_cb;
    uint8_t challenge[32];
    for (size_t i = 0U; i < sizeof(challenge); ++i) {
        challenge[i] = static_cast<uint8_t>(i + 0x10U);
    }
    const uint64_t sign_op = auth.beginSignChallenge(challenge, sizeof(challenge), auth_cb);
    CHECK(sign_op != 0ULL);
    driveReactor(reactor, 60, 20);
    REQUIRE(auth_cb.sign_calls == 1);
    CHECK(auth_cb.sign_ok);
    CHECK_EQ(32U, chip.written_challenge.size());
    CHECK_EQ(static_cast<size_t>(64U), auth_cb.sign_data.size());

    auth.stop();
}

}  // namespace

int main() {
    return test_support::runAll("test_mfi_i2c");
}
