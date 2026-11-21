#include "carplay/platform/carplay_daemon.hpp"
#include "carplay/platform/ddp_handoff.hpp"
#include "carplay/platform/file_util.hpp"
#include "carplay/platform/mfi_i2c.hpp"
#include "test_support.hpp"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <string>
#include <vector>

namespace {

namespace plat = carplay::platform;

std::string makeTempDir(const char* prefix) {
#ifdef _WIN32
    (void)prefix;
    return std::string(".");
#else
    char tmpl[128];
    snprintf(tmpl, sizeof(tmpl), "/tmp/%s-XXXXXX", prefix);
    char* res = mkdtemp(tmpl);
    if (res == NULL) {
        abort();
    }
    return std::string(res);
#endif
}

void removeTree(const std::string& path) {
#ifdef _WIN32
    (void)path;
#else
    const std::string cmd = "rm -rf '" + path + "'";
    const int rc = system(cmd.c_str());
    (void)rc;
#endif
}

class RecordingHandoffCallback : public plat::DdpHandoff::Callback {
public:
    bool called;
    bool ok;
    bool did_stop_ddp;
    std::string detail;

    RecordingHandoffCallback() : called(false), ok(false), did_stop_ddp(false) {}

    virtual void onDdpHandoffFinished(bool ok_in, bool did_stop_in, const std::string& detail_in) {
        called = true;
        ok = ok_in;
        did_stop_ddp = did_stop_in;
        detail = detail_in;
    }
};

class FakeDdpHandoffOps : public plat::DdpHandoffOps {
public:
    int start_systemctl_calls;
    int poll_systemctl_calls;
    int sigterm_calls;
    std::string last_service_stopped;
    bool start_systemctl_ok;
    int systemctl_exit_code;
    int systemctl_polls_until_exit;

    std::vector<int64_t> ddp_pids;
    std::vector<plat::DdpProcHolder> i2c_holders;
    std::vector<int64_t> sent_sigterm_pids;
    bool clear_ddp_on_sigterm;
    bool keep_i2c_holder_after_sigterm;
    int sigterm_errno;

    FakeDdpHandoffOps()
        : start_systemctl_calls(0),
          poll_systemctl_calls(0),
          sigterm_calls(0),
          start_systemctl_ok(true),
          systemctl_exit_code(0),
          systemctl_polls_until_exit(1),
          clear_ddp_on_sigterm(true),
          keep_i2c_holder_after_sigterm(false),
          sigterm_errno(0) {}

    virtual bool startSystemctlStop(const std::string& /*systemctl_path*/,
                                    const std::string& service_name,
                                    int64_t& child_pid_out,
                                    int& pipe_fd_out,
                                    std::string& error_out) {
        ++start_systemctl_calls;
        last_service_stopped = service_name;
        if (!start_systemctl_ok) {
            error_out = "fake fork failure";
            return false;
        }
        child_pid_out = 9001;
        pipe_fd_out = -1;
        return true;
    }

    virtual bool pollSystemctlStop(int64_t /*child_pid*/,
                                   bool& exited_out,
                                   int& exit_code_out,
                                   std::string& /*error_out*/) {
        ++poll_systemctl_calls;
        if (poll_systemctl_calls >= systemctl_polls_until_exit) {
            exited_out = true;
            exit_code_out = systemctl_exit_code;
        } else {
            exited_out = false;
            exit_code_out = -1;
        }
        return true;
    }

    virtual void cleanupSystemctlStop(int64_t& child_pid_inout, int& pipe_fd_inout) {
        child_pid_inout = -1;
        pipe_fd_inout = -1;
    }

    virtual bool findDdpServerPids(const std::string& /*proc_root*/,
                                   const std::string& /*exe_suffix*/,
                                   std::vector<int64_t>& pids_out,
                                   std::string& /*error_out*/) {
        pids_out = ddp_pids;
        return true;
    }

    virtual bool sendSigTerm(int64_t pid, int& errno_out) {
        ++sigterm_calls;
        sent_sigterm_pids.push_back(pid);
        if (sigterm_errno != 0) {
            errno_out = sigterm_errno;
            return false;
        }
        if (clear_ddp_on_sigterm) {
            for (size_t i = 0U; i < ddp_pids.size(); ++i) {
                if (ddp_pids[i] == pid) {
                    ddp_pids.erase(ddp_pids.begin() + static_cast<long>(i));
                    break;
                }
            }
            if (!keep_i2c_holder_after_sigterm) {
                for (size_t i = 0U; i < i2c_holders.size();) {
                    if (i2c_holders[i].pid == pid) {
                        i2c_holders.erase(i2c_holders.begin() + static_cast<long>(i));
                    } else {
                        ++i;
                    }
                }
            }
        }
        errno_out = 0;
        return true;
    }

    virtual bool findI2cHolders(const std::string& /*proc_root*/,
                                const std::string& /*i2c_device_path*/,
                                std::vector<plat::DdpProcHolder>& holders_out,
                                std::string& /*error_out*/) {
        holders_out = i2c_holders;
        return true;
    }
};

// Minimal I2C backend fake supporting CP 3.0 @ 0x10 dev_ver=0x05 probe + open gate check.
class FakeI2cGateBackend : public plat::I2cBackend {
public:
    bool fail_probe;
    bool open_called;
    bool open_while_ddp_alive;
    const FakeDdpHandoffOps* ops_check;

    FakeI2cGateBackend()
        : fail_probe(false),
          open_called(false),
          open_while_ddp_alive(false),
          ops_check(NULL),
          open_state_(false),
          selected_reg_(0U) {}

    virtual bool openDevice(const std::string& /*device_path*/, std::string* /*error_out*/) {
        open_called = true;
        if (ops_check != NULL &&
            (!ops_check->ddp_pids.empty() || !ops_check->i2c_holders.empty())) {
            open_while_ddp_alive = true;
        }
        open_state_ = true;
        return true;
    }

    virtual void closeDevice() { open_state_ = false; }
    virtual bool isOpen() const { return open_state_; }

    virtual plat::I2cStatus transfer(uint8_t address7,
                                     const uint8_t* tx_data,
                                     size_t tx_len,
                                     uint8_t* rx_data,
                                     size_t rx_len,
                                     int* /*sys_errno_out*/) {
        if (!open_state_ || address7 != 0x10U) {
            return plat::kI2cNack;
        }
        if (fail_probe) {
            return plat::kI2cIoError;
        }
        if (tx_len == 1U && rx_len == 0U) {
            selected_reg_ = tx_data[0];
            return plat::kI2cOk;
        }
        if (tx_len == 0U && rx_len == 1U) {
            if (selected_reg_ == plat::mfi_reg::kDeviceVersion) {
                rx_data[0] = 0x05U;
            } else if (selected_reg_ == plat::mfi_reg::kFirmwareVersion) {
                rx_data[0] = 0x01U;
            } else if (selected_reg_ == plat::mfi_reg::kProtocolMajor) {
                rx_data[0] = 3U;
            } else if (selected_reg_ == plat::mfi_reg::kProtocolMinor) {
                rx_data[0] = 0U;
            } else {
                return plat::kI2cNack;
            }
            return plat::kI2cOk;
        }
        if (tx_len == 0U && rx_len == 4U && selected_reg_ == plat::mfi_reg::kDeviceId) {
            rx_data[0] = 0x00U;
            rx_data[1] = 0x00U;
            rx_data[2] = 0x05U;
            rx_data[3] = 0x01U;
            return plat::kI2cOk;
        }
        return plat::kI2cOk;
    }

private:
    bool open_state_;
    uint8_t selected_reg_;
};

void createProcEntry(const std::string& proc_root,
                     const char* pid_str,
                     const char* exe_target,
                     char state_char,
                     const char* fd_target) {
#ifndef _WIN32
    const std::string pdir = plat::joinPath(proc_root, pid_str);
    const std::string fdir = plat::joinPath(pdir, "fd");
    REQUIRE(mkdir(pdir.c_str(), 0755) == 0);
    REQUIRE(mkdir(fdir.c_str(), 0755) == 0);
    if (exe_target != NULL) {
        REQUIRE(symlink(exe_target, plat::joinPath(pdir, "exe").c_str()) == 0);
    }
    char stat_buf[64];
    snprintf(stat_buf, sizeof(stat_buf), "%s (proc) %c 1 1 1\n", pid_str, state_char);
    REQUIRE(plat::writeFileAtomic(plat::joinPath(pdir, "stat"),
                                  reinterpret_cast<const uint8_t*>(stat_buf),
                                  strlen(stat_buf)));
    if (fd_target != NULL) {
        REQUIRE(symlink(fd_target, plat::joinPath(fdir, "3").c_str()) == 0);
    }
#else
    (void)proc_root;
    (void)pid_str;
    (void)exe_target;
    (void)state_char;
    (void)fd_target;
#endif
}

TEST_CASE(posixProcScanMatchesExactDdpServerAndI2cHolderOnly) {
#ifndef _WIN32
    CHECK(plat::isDdpServerExePath("/opt/app/usr/MediaPlayer/bin/DDPServer",
                                   "/MediaPlayer/bin/DDPServer"));
    CHECK(plat::isDdpServerExePath("/opt/app/usr/MediaPlayer/bin/DDPServer (deleted)",
                                   "/MediaPlayer/bin/DDPServer"));
    CHECK(!plat::isDdpServerExePath("/opt/app/usr/bin/OtherServer",
                                    "/MediaPlayer/bin/DDPServer"));

    const std::string fake_proc = makeTempDir("fake-proc");
    // 101: exact DDPServer holding /dev/i2c-0
    createProcEntry(fake_proc, "101", "/opt/app/usr/MediaPlayer/bin/DDPServer", 'S', "/dev/i2c-0");
    // 102: unrelated binary (must NOT match DDPServer even if holding /dev/i2c-1)
    createProcEntry(fake_proc, "102", "/opt/app/usr/bin/AdvHelper", 'S', "/dev/i2c-1");
    // 103: zombie DDPServer (must be ignored)
    createProcEntry(fake_proc, "103", "/opt/app/usr/MediaPlayer/bin/DDPServer", 'Z', "/dev/i2c-0");
    // 104: unrelated process holding /dev/i2c-0
    createProcEntry(fake_proc, "104", "/opt/app/usr/bin/OtherI2cTool", 'S', "/dev/i2c-0");

    plat::PosixDdpHandoffOps ops;
    std::vector<int64_t> ddp_pids;
    std::string err;
    REQUIRE(ops.findDdpServerPids(fake_proc, "/MediaPlayer/bin/DDPServer", ddp_pids, err));
    REQUIRE(ddp_pids.size() == 1U);
    CHECK_EQ(101, static_cast<int>(ddp_pids[0]));

    std::vector<plat::DdpProcHolder> holders;
    REQUIRE(ops.findI2cHolders(fake_proc, "/dev/i2c-0", holders, err));
    REQUIRE(holders.size() == 2U);
    CHECK((holders[0].pid == 101 && holders[1].pid == 104) ||
          (holders[0].pid == 104 && holders[1].pid == 101));

    removeTree(fake_proc);
#endif
}

TEST_CASE(posixForkExecSystemctlStubWorksNonBlocking) {
#ifndef _WIN32
    const std::string dir = makeTempDir("ddp-exec");
    const std::string fake_proc = plat::joinPath(dir, "proc");
    REQUIRE(mkdir(fake_proc.c_str(), 0755) == 0);
    const std::string log_file = plat::joinPath(dir, "calls.log");
    const std::string script_path = plat::joinPath(dir, "fake_systemctl");
    const std::string script =
        "#!/bin/sh\n"
        "printf '%s %s\\n' \"$1\" \"$2\" >> '" + log_file + "'\n"
        "exit 0\n";
    REQUIRE(plat::writeFileAtomic(script_path,
                                  reinterpret_cast<const uint8_t*>(script.data()),
                                  script.size()));
    REQUIRE(chmod(script_path.c_str(), 0755) == 0);

    plat::Reactor reactor;
    REQUIRE(reactor.init());

    plat::DdpHandoffConfig cfg;
    cfg.enabled = true;
    cfg.systemctl_path = script_path;
    cfg.proc_root = fake_proc;
    cfg.i2c_device_path = "/dev/nonexistent-test-i2c-0";
    cfg.wait_exit_timeout_ms = 2000;
    cfg.poll_interval_ms = 10;

    RecordingHandoffCallback cb;
    plat::DdpHandoff handoff(reactor, cfg);
    REQUIRE(handoff.begin(&cb));
    for (int i = 0; i < 100 && !cb.called; ++i) {
        reactor.runOnce(10);
    }
    CHECK(cb.called);
    CHECK(cb.ok);
    CHECK(!cb.did_stop_ddp);

    std::vector<uint8_t> raw;
    REQUIRE(plat::readFileBounded(log_file, 1024U, raw) == plat::kFileReadOk);
    const std::string calls(raw.begin(), raw.end());
    CHECK(calls.find("stop DistributedDeviceProtocol.service") != std::string::npos);

    removeTree(dir);
#endif
}

TEST_CASE(ddpHandoffStateMachineSuccessAndHolderAbort) {
    plat::Reactor reactor;
    REQUIRE(reactor.init());

    // 1. Disabled -> immediate success, zero ops calls
    {
        FakeDdpHandoffOps ops;
        plat::DdpHandoffConfig cfg;
        cfg.enabled = false;
        plat::DdpHandoff handoff(reactor, cfg, &ops);
        RecordingHandoffCallback cb;
        REQUIRE(handoff.begin(&cb));
        CHECK(cb.called);
        CHECK(cb.ok);
        CHECK(!cb.did_stop_ddp);
        CHECK_EQ(0, ops.start_systemctl_calls);
        CHECK_EQ(0, ops.sigterm_calls);
    }

    // 2. Enabled with DDPServer PID 4242 -> systemctl stop, SIGTERM 4242, wait clear -> OK
    {
        FakeDdpHandoffOps ops;
        ops.ddp_pids.push_back(4242);
        ops.i2c_holders.push_back(plat::DdpProcHolder(4242, "/opt/app/usr/MediaPlayer/bin/DDPServer"));
        plat::DdpHandoffConfig cfg;
        cfg.enabled = true;
        cfg.poll_interval_ms = 10;
        cfg.wait_exit_timeout_ms = 500;
        plat::DdpHandoff handoff(reactor, cfg, &ops);
        RecordingHandoffCallback cb;
        REQUIRE(handoff.begin(&cb));
        for (int i = 0; i < 40 && !cb.called; ++i) {
            reactor.runOnce(10);
        }
        CHECK(cb.called);
        CHECK(cb.ok);
        CHECK(cb.did_stop_ddp);
        CHECK_EQ(1, ops.start_systemctl_calls);
        CHECK_EQ(std::string("DistributedDeviceProtocol.service"), ops.last_service_stopped);
        REQUIRE(ops.sent_sigterm_pids.size() == 1U);
        CHECK_EQ(4242, static_cast<int>(ops.sent_sigterm_pids[0]));
    }

    // 3. Unrelated process still holds /dev/i2c-0 -> aborts without success
    {
        FakeDdpHandoffOps ops;
        ops.i2c_holders.push_back(plat::DdpProcHolder(8888, "OtherHolder"));
        plat::DdpHandoffConfig cfg;
        cfg.enabled = true;
        cfg.poll_interval_ms = 10;
        cfg.wait_exit_timeout_ms = 120;
        plat::DdpHandoff handoff(reactor, cfg, &ops);
        RecordingHandoffCallback cb;
        REQUIRE(handoff.begin(&cb));
        for (int i = 0; i < 40 && !cb.called; ++i) {
            reactor.runOnce(10);
        }
        CHECK(cb.called);
        CHECK(!cb.ok);
        CHECK_EQ(0, ops.sigterm_calls);
    }

    // 4. DDPServer refuses SIGTERM within <= 5s budget -> times out and aborts
    {
        FakeDdpHandoffOps ops;
        ops.ddp_pids.push_back(5150);
        ops.clear_ddp_on_sigterm = false;
        plat::DdpHandoffConfig cfg;
        cfg.enabled = true;
        cfg.poll_interval_ms = 15;
        cfg.wait_exit_timeout_ms = 100;
        plat::DdpHandoff handoff(reactor, cfg, &ops);
        RecordingHandoffCallback cb;
        REQUIRE(handoff.begin(&cb));
        for (int i = 0; i < 40 && !cb.called; ++i) {
            reactor.runOnce(15);
        }
        CHECK(cb.called);
        CHECK(!cb.ok);
        CHECK(cb.did_stop_ddp);
    }
}

TEST_CASE(daemonDdpHandoffGatesI2cAndRecordsRebootWithoutRestart) {
#ifndef _WIN32
    const std::string dir = makeTempDir("daemon-ddp");

    // 1. Happy path: ddp_handoff stops DDPServer BEFORE I2C opens, dev_ver=0x05 probed,
    //    session/daemon stop writes ddp_needs_reboot and never restarts DDPServer.
    {
        FakeDdpHandoffOps ops;
        ops.ddp_pids.push_back(31337);
        ops.i2c_holders.push_back(plat::DdpProcHolder(31337, "/opt/app/usr/MediaPlayer/bin/DDPServer"));
        ops.systemctl_polls_until_exit = 2;

        FakeI2cGateBackend chip;
        chip.ops_check = &ops;

        plat::CarPlayDaemonConfig cfg;
        cfg.data_dir = dir;
        cfg.state_file = dir + "/state";
        cfg.media_recall_file = dir + "/recall";
        cfg.ddp_needs_reboot_file = dir + "/ddp-needs-reboot";
        cfg.bind_loopback_only = true;
        cfg.control_port = 0U;
        cfg.enable_video = false;
        cfg.enable_audio = false;
        cfg.enable_input = false;
        cfg.enable_control = false;
        cfg.query_display_from_ilm = false;
        REQUIRE(plat::parseMfiI2cSpec("/dev/fake-i2c-0:0x10", cfg.mfi_i2c_config));
        cfg.ddp_handoff_config.enabled = true;
        cfg.ddp_handoff_config.poll_interval_ms = 10;
        cfg.ddp_handoff_config.wait_exit_timeout_ms = 500;
        cfg.ddp_handoff_config.restore_mode = plat::kDdpRestoreRebootPrompt;

        plat::CarPlayDaemon daemon(cfg);
        daemon.setDdpHandoffOpsForTest(&ops);
        daemon.setMfiI2cBackendForTest(&chip);
        REQUIRE(daemon.start());
        // Before handoff completes, MFi backend must NOT have been opened yet!
        CHECK(!chip.open_called);
        CHECK(daemon.mfiAuth() == NULL);

        for (int i = 0; i < 60 &&
             (daemon.mfiAuth() == NULL || !daemon.mfiAuth()->chipInfo().probed); ++i) {
            daemon.reactor().runOnce(10);
        }
        REQUIRE(daemon.mfiAuth() != NULL);
        CHECK(daemon.mfiAuth()->chipInfo().probed);
        CHECK_EQ(0x05U, daemon.mfiAuth()->chipInfo().device_version);
        CHECK(!chip.open_while_ddp_alive);
        CHECK(!daemon.hasStartupFailure());

        daemon.stop();
        CHECK(daemon.ddpNeedsReboot());
        CHECK(plat::pathExists(cfg.ddp_needs_reboot_file));

        std::vector<uint8_t> raw;
        REQUIRE(plat::readFileBounded(cfg.ddp_needs_reboot_file, 1024U, raw) == plat::kFileReadOk);
        const std::string marker(raw.begin(), raw.end());
        CHECK(marker.find("ddp_needs_reboot=1") != std::string::npos);
        CHECK_EQ(1, ops.start_systemctl_calls);  // stop once, never restarted
    }

    // 2. ddp_restore=none -> ddp_needs_reboot file is NOT created
    {
        const std::string marker_path = dir + "/ddp-needs-reboot-none";
        FakeDdpHandoffOps ops;
        ops.ddp_pids.push_back(4444);

        FakeI2cGateBackend chip;
        plat::CarPlayDaemonConfig cfg;
        cfg.data_dir = dir;
        cfg.state_file = dir + "/state2";
        cfg.media_recall_file = dir + "/recall2";
        cfg.ddp_needs_reboot_file = marker_path;
        cfg.bind_loopback_only = true;
        cfg.control_port = 0U;
        cfg.enable_video = false;
        cfg.enable_audio = false;
        cfg.enable_input = false;
        cfg.enable_control = false;
        cfg.query_display_from_ilm = false;
        REQUIRE(plat::parseMfiI2cSpec("/dev/fake-i2c-0:0x10", cfg.mfi_i2c_config));
        cfg.ddp_handoff_config.enabled = true;
        cfg.ddp_handoff_config.poll_interval_ms = 10;
        cfg.ddp_handoff_config.restore_mode = plat::kDdpRestoreNone;

        plat::CarPlayDaemon daemon(cfg);
        daemon.setDdpHandoffOpsForTest(&ops);
        daemon.setMfiI2cBackendForTest(&chip);
        REQUIRE(daemon.start());
        for (int i = 0; i < 60 &&
             (daemon.mfiAuth() == NULL || !daemon.mfiAuth()->chipInfo().probed); ++i) {
            daemon.reactor().runOnce(10);
        }
        CHECK(daemon.mfiAuth() != NULL);
        CHECK(daemon.mfiAuth()->chipInfo().probed);
        daemon.stop();
        CHECK(!plat::pathExists(marker_path));
    }

    // 3. Another process still holds /dev/i2c-0 -> aborts BEFORE touching I2C bus (both sync and async)
    {
        FakeDdpHandoffOps ops;
        ops.i2c_holders.push_back(plat::DdpProcHolder(9999, "OtherBusOwner"));
        FakeI2cGateBackend chip;
        plat::CarPlayDaemonConfig cfg;
        cfg.data_dir = dir;
        cfg.state_file = dir + "/state3";
        cfg.media_recall_file = dir + "/recall3";
        cfg.ddp_needs_reboot_file = dir + "/ddp-needs-reboot-3";
        cfg.bind_loopback_only = true;
        cfg.control_port = 0U;
        cfg.enable_video = false;
        cfg.enable_audio = false;
        cfg.enable_input = false;
        cfg.enable_control = false;
        cfg.query_display_from_ilm = false;
        REQUIRE(plat::parseMfiI2cSpec("/dev/fake-i2c-0:0x10", cfg.mfi_i2c_config));
        cfg.ddp_handoff_config.enabled = true;
        cfg.ddp_handoff_config.poll_interval_ms = 10;
        cfg.ddp_handoff_config.wait_exit_timeout_ms = 120;

        // 3a: Synchronous completion during start() returns false and never touches I2C
        plat::CarPlayDaemon daemon_sync(cfg);
        daemon_sync.setDdpHandoffOpsForTest(&ops);
        daemon_sync.setMfiI2cBackendForTest(&chip);
        CHECK(!daemon_sync.start());
        CHECK(daemon_sync.hasStartupFailure());
        CHECK(!chip.open_called);

        // 3b: Async completion on Reactor aborts cleanly during run() and never touches I2C
        FakeDdpHandoffOps ops_async;
        ops_async.i2c_holders.push_back(plat::DdpProcHolder(9999, "OtherBusOwner"));
        ops_async.systemctl_polls_until_exit = 2;
        plat::CarPlayDaemon daemon(cfg);
        daemon.setDdpHandoffOpsForTest(&ops_async);
        daemon.setMfiI2cBackendForTest(&chip);
        REQUIRE(daemon.start());
        daemon.reactor().run();
        CHECK(daemon.hasStartupFailure());
        CHECK(!chip.open_called);
        daemon.stop();
    }

    // 4. MFi probe failure after handoff -> closes I2C fd immediately (never half-used) & aborts
    {
        FakeDdpHandoffOps ops;
        ops.ddp_pids.push_back(7777);
        FakeI2cGateBackend chip;
        chip.fail_probe = true;

        plat::CarPlayDaemonConfig cfg;
        cfg.data_dir = dir;
        cfg.state_file = dir + "/state4";
        cfg.media_recall_file = dir + "/recall4";
        cfg.ddp_needs_reboot_file = dir + "/ddp-needs-reboot-4";
        cfg.bind_loopback_only = true;
        cfg.control_port = 0U;
        cfg.enable_video = false;
        cfg.enable_audio = false;
        cfg.enable_input = false;
        cfg.enable_control = false;
        cfg.query_display_from_ilm = false;
        REQUIRE(plat::parseMfiI2cSpec("/dev/fake-i2c-0:0x10", cfg.mfi_i2c_config));
        cfg.mfi_i2c_config.io_retry_timeout_ms = 20;
        cfg.ddp_handoff_config.enabled = true;
        cfg.ddp_handoff_config.poll_interval_ms = 10;

        plat::CarPlayDaemon daemon(cfg);
        daemon.setDdpHandoffOpsForTest(&ops);
        daemon.setMfiI2cBackendForTest(&chip);
        REQUIRE(daemon.start());
        daemon.reactor().run();
        CHECK(daemon.hasStartupFailure());
        CHECK(chip.open_called);
        CHECK(!chip.isOpen());
        CHECK(plat::pathExists(cfg.ddp_needs_reboot_file));
        daemon.stop();
    }

    removeTree(dir);
#endif
}

}  // namespace

int main() { return test_support::runAll("test_ddp_handoff"); }
