// Host tests for WifiApConfig, credential generation, hostapd/udhcpd config generators,
// hostapd STATUS/ALL_STA/event parsers, HostapdCtrl over real AF_UNIX SOCK_DGRAM, SupervisedProcess,
// and the WifiAp state machine with fakes.

#include "carplay/iap2_wire.hpp"
#include "carplay/pairing.hpp"
#include "carplay/platform/evo_supervisor.hpp"
#include "carplay/platform/file_util.hpp"
#include "carplay/platform/hostapd_ctrl.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/os_random.hpp"
#include "carplay/platform/reactor.hpp"
#include "carplay/platform/wifi_ap.hpp"
#include "test_support.hpp"

#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace plat = carplay::platform;
namespace iap2 = carplay::iap2;
namespace pairing = carplay::pairing;

namespace {

int64_t g_fake_clock_ns = 1000000000LL;

int64_t fakeClockNs() {
    return g_fake_clock_ns;
}

void advanceFakeClockMs(int64_t ms) {
    g_fake_clock_ns += ms * 1000000LL;
}

class DeterministicRng : public pairing::RandomSource {
public:
    explicit DeterministicRng(uint8_t seed = 0x11U) : next_(seed), should_fail_(false) {}
    void setFail(bool f) { should_fail_ = f; }

    virtual bool fill(uint8_t* out, size_t len) {
        if (should_fail_) {
            return false;
        }
        for (size_t i = 0U; i < len; ++i) {
            out[i] = next_;
            next_ = static_cast<uint8_t>(next_ + 17U);
        }
        return true;
    }

private:
    uint8_t next_;
    bool should_fail_;
};

class TempDirGuard {
public:
    explicit TempDirGuard(const std::string& tag) {
        char buf[128];
#ifndef _WIN32
        snprintf(buf, sizeof(buf), "/tmp/carplay_test_%s_%ld", tag.c_str(),
                 static_cast<long>(getpid()));
#else
        snprintf(buf, sizeof(buf), "carplay_test_%s", tag.c_str());
#endif
        path_ = buf;
        plat::ensurePrivateDirectory(path_);
    }

    ~TempDirGuard() {
        for (size_t i = files_.size(); i > 0U; --i) {
            plat::removeFile(files_[i - 1U]);
        }
        for (size_t i = dirs_.size(); i > 0U; --i) {
            plat::removeDirectory(dirs_[i - 1U]);
        }
        plat::removeDirectory(path_);
    }

    const std::string& path() const { return path_; }
    void trackFile(const std::string& p) { files_.push_back(p); }
    void trackDir(const std::string& p) { dirs_.push_back(p); }

private:
    std::string path_;
    std::vector<std::string> files_;
    std::vector<std::string> dirs_;
};

class FakeChildProcess : public plat::IChildProcess {
public:
    FakeChildProcess()
        : running_(false),
          next_pid_(1000),
          pid_(-1),
          start_should_fail_(false),
          term_exits_immediately_(true),
          kill_exits_immediately_(true),
          start_count_(0),
          term_count_(0),
          kill_count_(0) {}

    virtual bool start(const std::string& executable,
                       const std::vector<std::string>& args,
                       const std::string& log_path,
                       std::string* error_out) {
        last_executable_ = executable;
        last_args_ = args;
        last_log_path_ = log_path;
        if (start_should_fail_) {
            if (error_out != NULL) {
                *error_out = "fake spawn failure";
            }
            return false;
        }
        ++start_count_;
        pid_ = next_pid_++;
        running_ = true;
        status_ = plat::ProcessExitStatus();
        return true;
    }

    virtual bool pollExited(plat::ProcessExitStatus* status_out) {
        if (status_out != NULL) {
            *status_out = status_;
        }
        return !running_;
    }

    virtual bool isRunning() { return running_; }
    virtual int pid() const { return pid_; }
    virtual plat::ProcessExitStatus exitStatus() const { return status_; }

    virtual bool sendTerm() {
        if (!running_) {
            return false;
        }
        ++term_count_;
        if (term_exits_immediately_) {
            simulateExit(0, 15);
        }
        return true;
    }

    virtual bool sendKill() {
        if (!running_) {
            return false;
        }
        ++kill_count_;
        if (kill_exits_immediately_) {
            simulateExit(-1, 9);
        }
        return true;
    }

    virtual bool stop(int term_timeout_ms, int kill_timeout_ms) {
        (void)term_timeout_ms;
        (void)kill_timeout_ms;
        if (!running_) {
            return true;
        }
        sendTerm();
        if (running_) {
            sendKill();
        }
        return !running_;
    }

    void simulateExit(int code, int sig = 0) {
        running_ = false;
        status_.exited = true;
        status_.exit_code = code;
        status_.signal = sig;
        pid_ = -1;
    }

    bool running_;
    int next_pid_;
    int pid_;
    plat::ProcessExitStatus status_;
    bool start_should_fail_;
    bool term_exits_immediately_;
    bool kill_exits_immediately_;
    int start_count_;
    int term_count_;
    int kill_count_;
    std::string last_executable_;
    std::vector<std::string> last_args_;
    std::string last_log_path_;
};

class FakeHostapdCtrl : public plat::IHostapdCtrl {
public:
    FakeHostapdCtrl()
        : listener_(NULL),
          open_(false),
          socket_ready_(false),
          open_count_(0),
          close_count_(0),
          status_state_("ENABLED"),
          status_bssid_("02:aa:bb:cc:dd:ee"),
          all_sta_reply_("") {}

    virtual void setListener(plat::HostapdCtrlListener* listener) { listener_ = listener; }

    virtual bool open(const std::string& remote_ctrl_path,
                      const std::string& local_bind_dir,
                      std::string* error_out) {
        last_remote_ = remote_ctrl_path;
        last_local_dir_ = local_bind_dir;
        if (!socket_ready_) {
            if (error_out != NULL) {
                *error_out = "control socket not ready yet";
            }
            return false;
        }
        open_ = true;
        ++open_count_;
        return true;
    }

    virtual void close() {
        if (open_) {
            open_ = false;
            ++close_count_;
        }
        pending_.clear();
    }

    virtual bool isOpen() const { return open_; }

    virtual bool sendPing(int timeout_ms) { return sendCommand(plat::kCmdPing, "PING", timeout_ms); }
    virtual bool sendAttach(int timeout_ms) {
        return sendCommand(plat::kCmdAttach, "ATTACH", timeout_ms);
    }
    virtual bool sendDetach(int timeout_ms) {
        return sendCommand(plat::kCmdDetach, "DETACH", timeout_ms);
    }
    virtual bool sendStatus(int timeout_ms) {
        return sendCommand(plat::kCmdStatus, "STATUS", timeout_ms);
    }
    virtual bool sendAllSta(int timeout_ms) {
        return sendCommand(plat::kCmdAllSta, "ALL_STA", timeout_ms);
    }
    virtual bool sendEnable(int timeout_ms) {
        return sendCommand(plat::kCmdEnable, "ENABLE", timeout_ms);
    }
    virtual bool sendDisable(int timeout_ms) {
        return sendCommand(plat::kCmdDisable, "DISABLE", timeout_ms);
    }

    virtual bool sendCommand(plat::HostapdCommandKind kind,
                             const std::string& cmd,
                             int timeout_ms) {
        (void)timeout_ms;
        if (!open_) {
            return false;
        }
        sent_commands_.push_back(cmd);
        pending_.push_back(kind);
        return true;
    }

    void flushReplies() {
        while (!pending_.empty() && open_) {
            const plat::HostapdCommandKind kind = pending_.front();
            pending_.erase(pending_.begin());
            std::string reply;
            if (kind == plat::kCmdPing) {
                reply = "PONG\n";
            } else if (kind == plat::kCmdAttach || kind == plat::kCmdDetach ||
                       kind == plat::kCmdEnable || kind == plat::kCmdDisable) {
                reply = "OK\n";
            } else if (kind == plat::kCmdStatus) {
                reply = "state=" + status_state_ + "\nphy=phy1\nfreq=5180\nchannel=36\n"
                        "bss[0]=wlan1\nbssid[0]=" + status_bssid_ +
                        "\nssid[0]=test\nnum_sta[0]=0\n";
            } else if (kind == plat::kCmdAllSta) {
                reply = all_sta_reply_;
            }
            if (listener_ != NULL) {
                listener_->onHostapdCommandReply(kind, plat::isHostapdReplyOk(kind, reply), reply);
            }
        }
    }

    void emitEvent(const std::string& raw) {
        plat::HostapdEvent ev;
        if (plat::parseHostapdEvent(raw, ev) && listener_ != NULL) {
            listener_->onHostapdEvent(ev);
        }
    }

    plat::HostapdCtrlListener* listener_;
    bool open_;
    bool socket_ready_;
    int open_count_;
    int close_count_;
    std::string last_remote_;
    std::string last_local_dir_;
    std::string status_state_;
    std::string status_bssid_;
    std::string all_sta_reply_;
    std::vector<std::string> sent_commands_;
    std::vector<plat::HostapdCommandKind> pending_;
};

class RecordingApListener : public plat::WifiApListener {
public:
    RecordingApListener()
        : started_count(0), stopped_count(0), restarting_count(0), failed_count(0) {}

    virtual void onWifiApStarted(const plat::WifiCredentials& creds) {
        ++started_count;
        last_creds = creds;
    }
    virtual void onWifiApStopped() { ++stopped_count; }
    virtual void onWifiApRestarting(int attempt, const std::string& reason) {
        ++restarting_count;
        last_restart_attempt = attempt;
        last_reason = reason;
    }
    virtual void onWifiApFailed(const std::string& reason) {
        ++failed_count;
        last_reason = reason;
    }
    virtual void onStationConnected(const std::string& mac) {
        connected_events.push_back(mac);
    }
    virtual void onStationDisconnected(const std::string& mac) {
        disconnected_events.push_back(mac);
    }

    int started_count;
    int stopped_count;
    int restarting_count;
    int failed_count;
    int last_restart_attempt;
    std::string last_reason;
    plat::WifiCredentials last_creds;
    std::vector<std::string> connected_events;
    std::vector<std::string> disconnected_events;
};

class RecordingCtrlListener : public plat::HostapdCtrlListener {
public:
    virtual void onHostapdCommandReply(plat::HostapdCommandKind cmd,
                                       bool ok,
                                       const std::string& reply) {
        Reply r;
        r.cmd = cmd;
        r.ok = ok;
        r.reply = reply;
        replies.push_back(r);
    }
    virtual void onHostapdEvent(const plat::HostapdEvent& event) {
        events.push_back(event);
    }
    virtual void onHostapdCtrlError(const std::string& error) {
        errors.push_back(error);
    }

    struct Reply {
        plat::HostapdCommandKind cmd;
        bool ok;
        std::string reply;
    };
    std::vector<Reply> replies;
    std::vector<plat::HostapdEvent> events;
    std::vector<std::string> errors;
};

}  // namespace

TEST_CASE(configValidationAndBandChannels) {
    plat::WifiApConfig cfg;
    std::string err;
    CHECK(plat::validateWifiApConfig(cfg, &err));
    CHECK_EQ(std::string("wlan1"), cfg.interface_name);
    CHECK_EQ(std::string("/var/run/carplay/hostapd-carplay.conf"), cfg.effectiveHostapdConfPath());
    CHECK_EQ(std::string("/var/run/carplay/hostapd_ctrl/wlan1"),
             cfg.effectiveRemoteCtrlSocketPath());

    // Never allow /etc/hostapd.conf.
    {
        plat::WifiApConfig bad = cfg;
        bad.hostapd_conf_path = "/etc/hostapd.conf";
        CHECK(!plat::validateWifiApConfig(bad, &err));
    }

    // Channel & band validation (2.4 GHz vs 5 GHz).
    char hw_mode = '\0';
    CHECK(plat::resolveWifiBandAndHwMode(plat::kWifiBandAuto, 1, hw_mode, &err));
    CHECK_EQ('g', hw_mode);
    CHECK(plat::resolveWifiBandAndHwMode(plat::kWifiBandAuto, 13, hw_mode, &err));
    CHECK_EQ('g', hw_mode);
    CHECK(plat::resolveWifiBandAndHwMode(plat::kWifiBandAuto, 36, hw_mode, &err));
    CHECK_EQ('a', hw_mode);
    CHECK(plat::resolveWifiBandAndHwMode(plat::kWifiBand5GHz, 149, hw_mode, &err));
    CHECK_EQ('a', hw_mode);
    CHECK(plat::resolveWifiBandAndHwMode(plat::kWifiBand24GHz, 6, hw_mode, &err));
    CHECK_EQ('g', hw_mode);

    CHECK(!plat::resolveWifiBandAndHwMode(plat::kWifiBand24GHz, 36, hw_mode, &err));
    CHECK(!plat::resolveWifiBandAndHwMode(plat::kWifiBand5GHz, 6, hw_mode, &err));
    CHECK(!plat::resolveWifiBandAndHwMode(plat::kWifiBandAuto, 0, hw_mode, &err));
    CHECK(!plat::resolveWifiBandAndHwMode(plat::kWifiBandAuto, 14, hw_mode, &err));
    CHECK(!plat::resolveWifiBandAndHwMode(plat::kWifiBandAuto, 37, hw_mode, &err));

    // Country code, interface name, SSID & passphrase constraints.
    {
        plat::WifiApConfig bad = cfg;
        bad.country_code = "de";
        CHECK(!plat::validateWifiApConfig(bad, &err));
    }
    {
        plat::WifiApConfig bad = cfg;
        bad.interface_name = "wlan0/bad";
        CHECK(!plat::validateWifiApConfig(bad, &err));
    }
    {
        plat::WifiApConfig bad = cfg;
        bad.ssid = std::string(33U, 'A');
        CHECK(!plat::validateWifiApConfig(bad, &err));
    }
    {
        plat::WifiApConfig bad = cfg;
        bad.passphrase = "short";
        CHECK(!plat::validateWifiApConfig(bad, &err));
    }
    {
        plat::WifiApConfig bad = cfg;
        bad.passphrase = "line1\nline2";
        CHECK(!plat::validateWifiApConfig(bad, &err));
    }
    {
        plat::WifiApConfig bad = cfg;
        bad.passphrase = std::string(64U, 'p');
        CHECK(!plat::validateWifiApConfig(bad, &err));
    }
}

TEST_CASE(credentialGenerationAndIap2Frame) {
    plat::WifiApConfig cfg;
    cfg.channel = 44U;
    uint8_t bssid_raw[6] = {0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U};
    cfg.bssid.assign(bssid_raw, bssid_raw + 6U);

    plat::OsRandomSource os_rng;
    plat::WifiCredentials c1;
    plat::WifiCredentials c2;
    std::string err;
    REQUIRE(plat::generateWifiCredentials(cfg, os_rng, c1, &err));
    REQUIRE(plat::generateWifiCredentials(cfg, os_rng, c2, &err));

    CHECK_EQ(static_cast<size_t>(18U), c1.ssid.size());  // "BMW-CarPlay-" (12) + 6 hex
    CHECK_EQ(std::string("BMW-CarPlay-"), c1.ssid.substr(0U, 12U));
    CHECK_EQ(static_cast<size_t>(16U), c1.passphrase.size());
    CHECK(c1.ssid != c2.ssid);
    CHECK(c1.passphrase != c2.passphrase);
    CHECK_EQ(static_cast<uint8_t>(44U), c1.channel);
    CHECK_EQ(plat::kIap2WifiSecurityWpa2, c1.security_type);
    CHECK(c1.has_bssid);

    // Failing RNG fails closed.
    DeterministicRng bad_rng;
    bad_rng.setFail(true);
    plat::WifiCredentials bad_creds;
    CHECK(!plat::generateWifiCredentials(cfg, bad_rng, bad_creds, &err));

    // iAP2 0x5703 AccessoryWiFiConfigurationInformation matches credentials.
    iap2::Frame frame;
    REQUIRE(plat::buildAccessoryWiFiConfigFrame(c1, frame, &err));
    CHECK_EQ(iap2::msg::kAccessoryWiFiConfiguration, frame.message_id);

    iap2::ParameterList params;
    REQUIRE(iap2::ParameterList::decode(frame.payload, params, &err));
    std::vector<uint8_t> bssid_out;
    std::string ssid_out;
    std::string psk_out;
    uint8_t sec_out = 0U;
    uint8_t ch_out = 0U;
    CHECK(params.readBytes(0U, bssid_out));
    CHECK_BYTES_EQ(c1.bssidVector(), bssid_out);
    CHECK(params.readString(1U, ssid_out));
    CHECK_EQ(c1.ssid, ssid_out);
    CHECK(params.readString(2U, psk_out));
    CHECK_EQ(c1.passphrase, psk_out);
    CHECK(params.readU8(3U, sec_out));
    CHECK_EQ(plat::kIap2WifiSecurityWpa2, sec_out);
    CHECK(params.readU8(4U, ch_out));
    CHECK_EQ(static_cast<uint8_t>(44U), ch_out);
}

TEST_CASE(hostapdAndUdhcpdConfigGoldenStrings) {
    plat::WifiApConfig cfg;
    cfg.interface_name = "wlan1";
    cfg.runtime_dir = "/var/run/carplay";
    cfg.country_code = "DE";
    cfg.channel = 36U;
    cfg.ieee80211n = true;
    cfg.max_num_sta = 4;
    cfg.ssid = "BMW-CarPlay-123456";
    cfg.passphrase = "TestPassphrase99";

    DeterministicRng rng;
    plat::WifiCredentials creds;
    std::string err;
    REQUIRE(plat::generateWifiCredentials(cfg, rng, creds, &err));

    std::string conf;
    REQUIRE(plat::generateHostapdConfig(cfg, creds, conf, &err));

    const std::string expected_5g =
        "interface=wlan1\n"
        "driver=nl80211\n"
        "ctrl_interface=/var/run/carplay/hostapd_ctrl\n"
        "country_code=DE\n"
        "ieee80211d=1\n"
        "hw_mode=a\n"
        "channel=36\n"
        "ieee80211n=1\n"
        "wmm_enabled=1\n"
        "max_num_sta=4\n"
        "ssid=BMW-CarPlay-123456\n"
        "utf8_ssid=1\n"
        "ignore_broadcast_ssid=0\n"
        "auth_algs=1\n"
        "wpa=2\n"
        "wpa_key_mgmt=WPA-PSK\n"
        "rsn_pairwise=CCMP\n"
        "wpa_passphrase=TestPassphrase99\n";
    CHECK_EQ(expected_5g, conf);

    // 2.4 GHz variant with optional group and ap_isolate.
    cfg.band = plat::kWifiBand24GHz;
    cfg.channel = 6U;
    cfg.ctrl_interface_group = "0";
    cfg.ap_isolate = true;
    cfg.ieee80211n = false;
    cfg.max_num_sta = 0;
    REQUIRE(plat::generateWifiCredentials(cfg, rng, creds, &err));
    REQUIRE(plat::generateHostapdConfig(cfg, creds, conf, &err));
    const std::string expected_24g =
        "interface=wlan1\n"
        "driver=nl80211\n"
        "ctrl_interface=/var/run/carplay/hostapd_ctrl\n"
        "ctrl_interface_group=0\n"
        "country_code=DE\n"
        "ieee80211d=1\n"
        "hw_mode=g\n"
        "channel=6\n"
        "ap_isolate=1\n"
        "ssid=BMW-CarPlay-123456\n"
        "utf8_ssid=1\n"
        "ignore_broadcast_ssid=0\n"
        "auth_algs=1\n"
        "wpa=2\n"
        "wpa_key_mgmt=WPA-PSK\n"
        "rsn_pairwise=CCMP\n"
        "wpa_passphrase=TestPassphrase99\n";
    CHECK_EQ(expected_24g, conf);

    // udhcpd golden string (no gateway / no DNS).
    std::string uconf;
    REQUIRE(plat::generateUdhcpdConfig(cfg, uconf, &err));
    const std::string expected_udhcpd =
        "start 192.168.50.10\n"
        "end 192.168.50.50\n"
        "interface wlan1\n"
        "lease_file /var/run/carplay/udhcpd-carplay.leases\n"
        "option subnet 255.255.255.0\n"
        "option lease 86400\n";
    CHECK_EQ(expected_udhcpd, uconf);
    CHECK(uconf.find("router") == std::string::npos);
    CHECK(uconf.find("dns") == std::string::npos);
}

TEST_CASE(hostapdStatusAllStaAndEventParsing) {
    plat::HostapdStatus st;
    const std::string status_text =
        "state=ENABLED\n"
        "phy=phy1\n"
        "freq=5180\n"
        "channel=36\n"
        "bss[0]=wlan1\n"
        "bssid[0]=02:AA:BB:CC:DD:EE\n"
        "ssid[0]=BMW-CarPlay-1234\n"
        "num_sta[0]=2\n";
    REQUIRE(plat::parseHostapdStatus(status_text, st));
    CHECK_EQ(std::string("ENABLED"), st.state);
    CHECK_EQ(std::string("phy1"), st.phy);
    CHECK_EQ(5180, st.freq);
    CHECK_EQ(36, st.channel);
    CHECK_EQ(std::string("wlan1"), st.bss);
    CHECK_EQ(std::string("02:aa:bb:cc:dd:ee"), st.bssid);
    CHECK_EQ(std::string("BMW-CarPlay-1234"), st.ssid);
    CHECK_EQ(2, st.num_sta);

    CHECK(!plat::parseHostapdStatus("FAIL\n", st));
    CHECK(!plat::parseHostapdStatus("", st));

    // ALL_STA: empty -> 0 stations (valid).
    std::vector<plat::HostapdStationInfo> stas;
    CHECK(plat::parseHostapdAllSta("", stas));
    CHECK_EQ(static_cast<size_t>(0U), stas.size());
    CHECK(!plat::parseHostapdAllSta("FAIL\n", stas));

    const std::string all_sta_text =
        "AA:BB:CC:DD:EE:01\n"
        "flags=[AUTH][ASSOC][AUTHORIZED]\n"
        "aid=1\n"
        "rx_packets=120\n"
        "tx_packets=240\n"
        "connected_time=15\n"
        "aa:bb:cc:dd:ee:02\n"
        "flags=[AUTH]\n"
        "aid=2\n";
    REQUIRE(plat::parseHostapdAllSta(all_sta_text, stas));
    REQUIRE(stas.size() == 2U);
    CHECK_EQ(std::string("aa:bb:cc:dd:ee:01"), stas[0].mac);
    CHECK_EQ(std::string("[AUTH][ASSOC][AUTHORIZED]"), stas[0].flags);
    CHECK_EQ(1, stas[0].aid);
    CHECK_EQ(static_cast<uint64_t>(120ULL), stas[0].rx_packets);
    CHECK_EQ(static_cast<uint64_t>(240ULL), stas[0].tx_packets);
    CHECK_EQ(static_cast<uint64_t>(15ULL), stas[0].connected_time);
    CHECK_EQ(std::string("aa:bb:cc:dd:ee:02"), stas[1].mac);
    CHECK_EQ(2, stas[1].aid);

    // Events.
    CHECK(plat::isUnsolicitedHostapdMessage("<3>AP-STA-CONNECTED aa:bb:cc:dd:ee:ff"));
    CHECK(!plat::isUnsolicitedHostapdMessage("PONG\n"));

    plat::HostapdEvent ev;
    REQUIRE(plat::parseHostapdEvent("<3>AP-STA-CONNECTED AA:BB:CC:DD:EE:FF", ev));
    CHECK_EQ(3, ev.level);
    CHECK_EQ(plat::kHostapdEventStaConnected, ev.type);
    CHECK_EQ(std::string("aa:bb:cc:dd:ee:ff"), ev.mac);

    REQUIRE(plat::parseHostapdEvent("<2>AP-STA-DISCONNECTED 11:22:33:44:55:66\n", ev));
    CHECK_EQ(2, ev.level);
    CHECK_EQ(plat::kHostapdEventStaDisconnected, ev.type);
    CHECK_EQ(std::string("11:22:33:44:55:66"), ev.mac);

    REQUIRE(plat::parseHostapdEvent("<3>AP-ENABLED", ev));
    CHECK_EQ(plat::kHostapdEventApEnabled, ev.type);

    REQUIRE(plat::parseHostapdEvent("<3>CTRL-EVENT-TERMINATING", ev));
    CHECK_EQ(plat::kHostapdEventTerminating, ev.type);
}

TEST_CASE(hostapdCtrlRealFakeUnixSocket) {
#ifndef _WIN32
    TempDirGuard tmp("ctrl");
    const std::string server_path = plat::joinPath(tmp.path(), "wlan1");
    tmp.trackFile(server_path);

    const int srv_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    REQUIRE(srv_fd >= 0);
    const int flags = fcntl(srv_fd, F_GETFL, 0);
    REQUIRE(flags >= 0 && fcntl(srv_fd, F_SETFL, flags | O_NONBLOCK) == 0);

    struct sockaddr_un srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sun_family = AF_UNIX;
    REQUIRE(server_path.size() < sizeof(srv_addr.sun_path));
    memcpy(srv_addr.sun_path, server_path.c_str(), server_path.size() + 1U);
    unlink(server_path.c_str());
    REQUIRE(bind(srv_fd, reinterpret_cast<struct sockaddr*>(&srv_addr), sizeof(srv_addr)) == 0);

    plat::Reactor reactor;
    REQUIRE(reactor.init());

    plat::HostapdCtrl ctrl(reactor);
    RecordingCtrlListener listener;
    ctrl.setListener(&listener);

    std::string err;
    REQUIRE(ctrl.open(server_path, tmp.path(), &err));
    const std::string local_sock = ctrl.localSocketPath();
    CHECK(plat::pathExists(local_sock));

    REQUIRE(ctrl.sendPing(1000));
    REQUIRE(ctrl.sendAttach(1000));
    REQUIRE(ctrl.sendStatus(1000));
    REQUIRE(ctrl.sendEnable(1000));
    REQUIRE(ctrl.sendDisable(1000));

    // Pump commands one by one via the real UNIX datagram socket + Reactor.
    struct sockaddr_un client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buf[512];

    for (int step = 0; step < 5; ++step) {
        ssize_t n = -1;
        for (int tries = 0; tries < 20; ++tries) {
            client_len = sizeof(client_addr);
            n = recvfrom(srv_fd, buf, sizeof(buf) - 1U, 0,
                         reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
            if (n > 0) {
                break;
            }
            reactor.runOnce(5);
        }
        REQUIRE(n > 0);
        buf[n] = '\0';
        const std::string cmd(buf, static_cast<size_t>(n));

        std::string reply;
        if (cmd == "PING") {
            // Also inject an unsolicited event BEFORE replying to PING to prove event
            // interleaving does not consume the PING reply!
            const char* ev = "<3>AP-STA-CONNECTED 00:11:22:33:44:55";
            sendto(srv_fd, ev, strlen(ev), 0,
                   reinterpret_cast<struct sockaddr*>(&client_addr), client_len);
            reply = "PONG\n";
        } else if (cmd == "ATTACH" || cmd == "ENABLE" || cmd == "DISABLE") {
            reply = "OK\n";
        } else if (cmd == "STATUS") {
            reply = "state=ENABLED\nbssid[0]=02:00:00:00:00:99\n";
        }
        sendto(srv_fd, reply.data(), reply.size(), 0,
               reinterpret_cast<struct sockaddr*>(&client_addr), client_len);

        for (int r = 0; r < 10 && listener.replies.size() <= static_cast<size_t>(step); ++r) {
            reactor.runOnce(10);
        }
    }

    REQUIRE(listener.replies.size() == 5U);
    CHECK_EQ(plat::kCmdPing, listener.replies[0].cmd);
    CHECK(listener.replies[0].ok);
    CHECK_EQ(plat::kCmdAttach, listener.replies[1].cmd);
    CHECK(listener.replies[1].ok);
    CHECK_EQ(plat::kCmdStatus, listener.replies[2].cmd);
    CHECK(listener.replies[2].ok);
    CHECK_EQ(plat::kCmdEnable, listener.replies[3].cmd);
    CHECK(listener.replies[3].ok);
    CHECK_EQ(plat::kCmdDisable, listener.replies[4].cmd);
    CHECK(listener.replies[4].ok);

    REQUIRE(listener.events.size() == 1U);
    CHECK_EQ(plat::kHostapdEventStaConnected, listener.events[0].type);
    CHECK_EQ(std::string("00:11:22:33:44:55"), listener.events[0].mac);

    // Timeout test using a silent server.
    REQUIRE(ctrl.sendPing(30));
    for (int i = 0; i < 10 && listener.replies.size() < 6U; ++i) {
        reactor.runOnce(20);
    }
    REQUIRE(listener.replies.size() == 6U);
    CHECK_EQ(plat::kCmdPing, listener.replies[5].cmd);
    CHECK(!listener.replies[5].ok);

    ctrl.close();
    CHECK(!plat::pathExists(local_sock));
    ::close(srv_fd);
#endif
}

TEST_CASE(wifiApStateMachineStartConnectCrashRestartStop) {
    TempDirGuard tmp("wifiap");
    g_fake_clock_ns = 1000000000LL;
    plat::Reactor reactor(&fakeClockNs);
    REQUIRE(reactor.init());

    DeterministicRng rng(0x25U);
    plat::WifiAp ap(reactor, rng);

    FakeChildProcess fake_hostapd;
    FakeChildProcess fake_udhcpd;
    FakeHostapdCtrl fake_ctrl;
    RecordingApListener listener;

    ap.setHostapdProcessForTest(&fake_hostapd);
    ap.setUdhcpdProcessForTest(&fake_udhcpd);
    ap.setHostapdCtrlForTest(&fake_ctrl);
    ap.setListener(&listener);

    plat::WifiApConfig cfg;
    cfg.runtime_dir = tmp.path();
    cfg.enable_udhcpd = true;
    cfg.ctrl_poll_interval_ms = 10;
    cfg.ctrl_wait_timeout_ms = 500;
    cfg.health_check_interval_ms = 20;
    cfg.restart_backoff_ms = 50;
    cfg.max_restarts = 1;
    cfg.stop_term_timeout_ms = 100;
    cfg.stop_kill_timeout_ms = 100;

    tmp.trackFile(cfg.effectiveHostapdConfPath());
    tmp.trackFile(cfg.effectiveUdhcpdConfPath());
    tmp.trackFile(cfg.effectiveUdhcpdLeaseFile());
    tmp.trackDir(cfg.effectiveCtrlInterfaceDir());

    std::string err;
    REQUIRE(ap.start(cfg, &err));
    CHECK_EQ(plat::kWifiApStartingWaitCtrl, ap.state());
    CHECK_EQ(1, fake_hostapd.start_count_);
    REQUIRE(fake_hostapd.last_args_.size() == 1U);
    CHECK_EQ(cfg.effectiveHostapdConfPath(), fake_hostapd.last_args_[0]);
    CHECK(plat::pathExists(cfg.effectiveHostapdConfPath()));
    CHECK(plat::pathExists(cfg.effectiveUdhcpdConfPath()));

    // Check file permissions (0600 on hostapd config, 0700 on runtime dir).
#ifndef _WIN32
    unsigned mode = 0U;
    CHECK(plat::posixMode(cfg.effectiveHostapdConfPath(), mode));
    CHECK_EQ(0600U, mode);
    CHECK(plat::posixMode(cfg.runtime_dir, mode));
    CHECK_EQ(0700U, mode);
#endif

    // Control socket not ready on first poll, then becomes ready on second poll.
    advanceFakeClockMs(10);
    reactor.runOnce(0);
    CHECK_EQ(plat::kWifiApStartingWaitCtrl, ap.state());

    fake_ctrl.socket_ready_ = true;
    advanceFakeClockMs(10);
    reactor.runOnce(0);
    CHECK(fake_ctrl.isOpen());
    fake_ctrl.flushReplies();

    CHECK_EQ(plat::kWifiApRunning, ap.state());
    CHECK_EQ(1, listener.started_count);
    CHECK_EQ(1, fake_udhcpd.start_count_);
    CHECK(ap.credentials().has_bssid);
    CHECK_EQ(ap.credentials().ssid, listener.last_creds.ssid);
    const std::string initial_ssid = ap.credentials().ssid;
    const std::string initial_psk = ap.credentials().passphrase;

    // Station connect / disconnect tracking.
    fake_ctrl.emitEvent("<3>AP-STA-CONNECTED AA:BB:CC:DD:EE:01");
    CHECK(ap.isStationConnected("aa:bb:cc:dd:ee:01"));
    CHECK_EQ(static_cast<size_t>(1U), ap.connectedStations().size());
    CHECK_EQ(static_cast<size_t>(1U), listener.connected_events.size());

    fake_ctrl.emitEvent("<3>AP-STA-DISCONNECTED aa:bb:cc:dd:ee:01");
    CHECK(!ap.isStationConnected("aa:bb:cc:dd:ee:01"));
    CHECK_EQ(static_cast<size_t>(0U), ap.connectedStations().size());
    CHECK_EQ(static_cast<size_t>(1U), listener.disconnected_events.size());

    // Re-connect a station, then simulate unexpected hostapd crash -> restart.
    fake_ctrl.emitEvent("<3>AP-STA-CONNECTED 11:22:33:44:55:66");
    CHECK(ap.isStationConnected("11:22:33:44:55:66"));

    fake_hostapd.simulateExit(1, 0);
    advanceFakeClockMs(20);
    reactor.runOnce(0);

    CHECK_EQ(plat::kWifiApRestarting, ap.state());
    CHECK_EQ(1, listener.restarting_count);
    CHECK_EQ(1, ap.restartCount());
    CHECK(!ap.isStationConnected("11:22:33:44:55:66"));
    CHECK(!fake_ctrl.isOpen());
    CHECK(!fake_udhcpd.isRunning());

    // Advance past restart backoff -> hostapd respawns with SAME credentials.
    advanceFakeClockMs(50);
    reactor.runOnce(0);
    CHECK_EQ(plat::kWifiApStartingWaitCtrl, ap.state());
    CHECK_EQ(2, fake_hostapd.start_count_);
    CHECK_EQ(initial_ssid, ap.credentials().ssid);
    CHECK_EQ(initial_psk, ap.credentials().passphrase);

    fake_ctrl.flushReplies();
    CHECK_EQ(plat::kWifiApRunning, ap.state());
    CHECK_EQ(2, listener.started_count);

    // Non-immediate SIGTERM -> SIGKILL escalation during stop().
    fake_hostapd.term_exits_immediately_ = false;
    fake_udhcpd.term_exits_immediately_ = true;
    ap.stop();
    CHECK_EQ(plat::kWifiApStopping, ap.state());
    CHECK_EQ(1, fake_hostapd.term_count_);
    CHECK_EQ(0, fake_hostapd.kill_count_);

    advanceFakeClockMs(100);
    reactor.runOnce(0);
    CHECK_EQ(1, fake_hostapd.kill_count_);
    CHECK_EQ(plat::kWifiApStopped, ap.state());
    CHECK_EQ(1, listener.stopped_count);
    CHECK(!plat::pathExists(cfg.effectiveHostapdConfPath()));
    CHECK(!plat::pathExists(cfg.effectiveUdhcpdConfPath()));

    // Exceeding max_restarts transitions to kWifiApFailed.
    fake_hostapd.term_exits_immediately_ = true;
    cfg.max_restarts = 0;
    REQUIRE(ap.start(cfg, &err));
    fake_ctrl.flushReplies();
    REQUIRE(ap.state() == plat::kWifiApRunning);
    fake_hostapd.simulateExit(2, 0);
    advanceFakeClockMs(20);
    reactor.runOnce(0);
    CHECK_EQ(plat::kWifiApFailed, ap.state());
    CHECK_EQ(1, listener.failed_count);
}

TEST_CASE(supervisedProcessRealPosixChild) {
#ifndef _WIN32
    // Normal exit (0).
    {
        plat::SupervisedProcess proc;
        std::string err;
        std::vector<std::string> args;
        REQUIRE(proc.start("true", args, "", &err));
        bool exited = false;
        plat::ProcessExitStatus st;
        for (int i = 0; i < 100; ++i) {
            if (proc.pollExited(&st)) {
                exited = true;
                break;
            }
            struct timespec ts = {0, 10000000L};
            nanosleep(&ts, NULL);
        }
        CHECK(exited);
        CHECK(st.exited);
        CHECK_EQ(0, st.exit_code);
        CHECK_EQ(0, st.signal);
    }

    // Long-running child terminated and reaped cleanly via SIGTERM.
    {
        plat::SupervisedProcess proc;
        std::string err;
        std::vector<std::string> args;
        args.push_back("30");
        REQUIRE(proc.start("sleep", args, "", &err));
        CHECK(proc.isRunning());
        CHECK(proc.pid() > 0);
        CHECK(proc.stop(500, 500));
        CHECK(!proc.isRunning());
        CHECK(proc.exitStatus().exited);
    }
#endif
}

int main() {
    return test_support::runAll("test_wifi_ap");
}
