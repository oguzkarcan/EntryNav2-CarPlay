#include "test_support.hpp"

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "carplay/platform/evo_ilm.hpp"
#include "carplay/platform/evo_process.hpp"
#include "carplay/platform/evo_video.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/omap_dmabuf.hpp"
#include "carplay/platform/thread.hpp"
#include "carplay/platform/xsv_api.hpp"

#ifndef _WIN32
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

using carplay::platform::CommandReport;
using carplay::platform::DmaBufPool;
using carplay::platform::DrmOmapApi;
using carplay::platform::EvoIlm;
using carplay::platform::EvoVideo;
using carplay::platform::EvoVideoConfig;
using carplay::platform::EvoVideoSink;
using carplay::platform::LockGuard;
using carplay::platform::Mutex;
using carplay::platform::XsvApi;
using carplay::platform::monotonicMillis;
using carplay::platform::runCommand;

std::string g_self_exe;

std::string readFileText(const char* path) {
    std::ifstream file(path, std::ios::in | std::ios::binary);
    std::ostringstream out;
    out << file.rdbuf();
    return out.str();
}

void writeFileText(const char* path, const std::string& content) {
    std::ofstream file(path, std::ios::out | std::ios::trunc | std::ios::binary);
    file << content;
}

void resetLogAndOrder(const char* log_path) {
    std::ofstream file(log_path, std::ios::out | std::ios::trunc);
#ifndef _WIN32
    unlink((std::string(log_path) + ".order").c_str());
#endif
}

std::string makeTempFile(const char* prefix) {
#ifdef _WIN32
    (void)prefix;
    return std::string();
#else
    std::string tmpl = std::string("/tmp/") + prefix + "-XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    const int fd = mkstemp(&buf[0]);
    if (fd >= 0) {
        close(fd);
        return std::string(&buf[0]);
    }
    return std::string();
#endif
}

// ---- Helper mode when test binary invokes itself as a subprocess / fake LayerManagerControl ----
int runSubprocessHelper(int argc, char** argv) {
    if (std::strcmp(argv[1], "--flood") == 0) {
        for (int i = 0; i < 70000; ++i) {
            std::putchar('x');
        }
        return 0;
    }
    if (std::strcmp(argv[1], "--fail") == 0) {
        std::puts("surface render order: 0x101");
        return 7;
    }
    if (std::strcmp(argv[1], "--diagnostic-fail") == 0) {
        std::puts("partial stdout");
        std::fputs("detail stderr\n", stderr);
        return 9;
    }
    if (std::strcmp(argv[1], "--sleep") == 0) {
#ifndef _WIN32
        sleep(10);
#endif
        return 0;
    }

    const char* log = std::getenv("CARPLAY_TEST_LM_LOG");
    if (log == NULL) {
        return 2;
    }
    {
        std::ofstream file(log, std::ios::app);
        for (int i = 1; i < argc; ++i) {
            file << (i == 1 ? "" : " ") << argv[i];
        }
        file << '\n';
    }

    if (std::strcmp(argv[1], "get") == 0) {
        const char* scene_dir = std::getenv("CARPLAY_TEST_SCENE_DIR");
        if (scene_dir != NULL && argc > 2) {
            std::string path = std::string(scene_dir) + "/";
            if (std::strcmp(argv[2], "screen") == 0) {
                path += "screen.txt";
            } else if (std::strcmp(argv[2], "layer") == 0) {
                path += "layer.txt";
            } else {
                path += "surfaces.txt";
            }
            if (std::strcmp(argv[2], "surfaces") == 0 &&
                std::getenv("CARPLAY_TEST_TRUNCATED_SURFACES") != NULL) {
                std::puts("6 Surface(s):\n- Surface 0 (0x0)");
            } else if (std::strcmp(argv[2], "layer") == 0) {
                std::string text = readFileText(path.c_str());
                const std::string saved = std::string(log) + ".order";
                std::ifstream saved_in(saved.c_str(), std::ios::in | std::ios::binary);
                if (saved_in) {
                    std::ostringstream ss;
                    ss << saved_in.rdbuf();
                    const size_t pos = text.find("surface render order:");
                    if (pos != std::string::npos) {
                        const size_t eol = text.find('\n', pos);
                        text.replace(pos,
                                     eol == std::string::npos ? std::string::npos : eol - pos,
                                     "surface render order: " + ss.str() + "\r");
                    }
                }
                std::fwrite(text.data(), 1U, text.size(), stdout);
            } else {
                const std::string text = readFileText(path.c_str());
                std::fwrite(text.data(), 1U, text.size(), stdout);
            }
        } else {
            const std::string saved = std::string(log) + ".order";
            const char* env_order = std::getenv("CARPLAY_TEST_ORDER");
            std::string order = env_order != NULL ? env_order : "";
            std::ifstream saved_in(saved.c_str(), std::ios::in | std::ios::binary);
            if (saved_in) {
                std::ostringstream ss;
                ss << saved_in.rdbuf();
                order = ss.str();
            }
            std::printf("surface render order: %s\n", order.c_str());
        }
        if (std::getenv("CARPLAY_TEST_ERROR_ZERO") != NULL) {
            std::puts("LayerManagerService returned: failed");
        }
        return std::getenv("CARPLAY_TEST_FAIL_GET") != NULL ? 4 : 0;
    }

    if (argc > 4 && std::getenv("CARPLAY_TEST_FAIL_SET") != NULL &&
        std::strcmp(argv[4], std::getenv("CARPLAY_TEST_FAIL_SET")) == 0) {
        return 5;
    }

    if (argc > 5 && std::strcmp(argv[4], "render") == 0) {
        if (argc > 7 || std::getenv("CARPLAY_TEST_PARSER_ERROR") != NULL) {
            std::fputs("Interpreter error: unexpected token.\n", stderr);
            return 0;
        }
        if (std::getenv("CARPLAY_TEST_NO_EFFECT") == NULL) {
            std::ofstream state((std::string(log) + ".order").c_str(), std::ios::trunc);
            if (argc == 7) {
                state << argv[6];
            }
        }
    }
    if (std::getenv("CARPLAY_TEST_ERROR_ZERO") != NULL) {
        std::puts("LayerManagerService returned: failed");
    }
    return 0;
}

void writeFixtureScene(const std::string& dir, uint32_t w, uint32_t h, const std::string& surfaces_txt) {
    std::ostringstream screen;
    screen << "screen 0 (0x0)\r\n"
           << "---------------------------------------\r\n"
           << "- resolution:           x=" << w << ", y=" << h << "\r\n"
           << "- hardware layer count: 0\r\n"
           << "- layer render order:   2147483648(0x80000000), \r\n";
    writeFileText((dir + "/screen.txt").c_str(), screen.str());

    std::ostringstream layer;
    layer << "layer 2147483648 (0x80000000)\r\n"
          << "---------------------------------------\r\n"
          << "- created by pid:       0\r\n"
          << "- original size:        x=" << w << ", y=" << h << "\r\n"
          << "- destination region:   x=0, y=0, w=" << w << ", h=" << h << "\r\n"
          << "- source region:        x=0, y=0, w=" << w << ", h=" << h << "\r\n"
          << "- orientation:          0 (up is top)\r\n"
          << "- opacity:              1\r\n"
          << "- visibility:           1\r\n"
          << "- type:                 0 (unknown)\r\n"
          << "- chromakey:            disabled (r=0, g=0, b=0)\r\n"
          << "- surface render order: 0(0x0), \r\n"
          << "- on screen:            0(0x0)\r\n";
    writeFileText((dir + "/layer.txt").c_str(), layer.str());
    writeFileText((dir + "/surfaces.txt").c_str(), surfaces_txt);
}

// ============================================================================
// Mock DRM / OMAP and libxsvideo implementations for unit tests
// ============================================================================

struct MockBo {
    std::vector<uint8_t> data;
    uint32_t requested_size;
    int fd;
    bool dmabuf_exported;
    bool freed;
    MockBo() : requested_size(0), fd(-1), dmabuf_exported(false), freed(false) {}
};

struct MockDrmState {
    int drm_open_result;
    bool fail_device_new;
    int fail_bo_at;
    int fail_dmabuf_at;
    int fail_map_at;
    int open_count;
    int close_count;
    int dev_new_count;
    int dev_del_count;
    int bo_new_count;
    int bo_del_count;
    std::vector<MockBo*> bos;

    void reset() {
        for (size_t i = 0; i < bos.size(); ++i) {
            delete bos[i];
        }
        bos.clear();
        drm_open_result = 100;
        fail_device_new = false;
        fail_bo_at = -1;
        fail_dmabuf_at = -1;
        fail_map_at = -1;
        open_count = 0;
        close_count = 0;
        dev_new_count = 0;
        dev_del_count = 0;
        bo_new_count = 0;
        bo_del_count = 0;
    }

    bool allBosFreed() const {
        for (size_t i = 0; i < bos.size(); ++i) {
            if (!bos[i]->freed) {
                return false;
            }
        }
        return true;
    }

    bool allExportedFdsClosed() const {
#ifndef _WIN32
        for (size_t i = 0; i < bos.size(); ++i) {
            if (bos[i]->dmabuf_exported && bos[i]->fd >= 0) {
                if (fcntl(bos[i]->fd, F_GETFD) != -1 || errno != EBADF) {
                    return false;
                }
            }
        }
#endif
        return true;
    }

    MockDrmState() { reset(); }
    ~MockDrmState() { reset(); }
};

MockDrmState g_drm;

int mockDrmOpen(const char* name, const char* busid) {
    (void)busid;
    ++g_drm.open_count;
    if (name == NULL || std::strcmp(name, "omapdrm") != 0) {
        return -1;
    }
    return g_drm.drm_open_result;
}

void mockDrmClose(int fd) {
    (void)fd;
    ++g_drm.close_count;
}

struct omap_device* mockOmapDeviceNew(int fd) {
    (void)fd;
    ++g_drm.dev_new_count;
    if (g_drm.fail_device_new) {
        return NULL;
    }
    return reinterpret_cast<struct omap_device*>(0x1234);
}

void mockOmapDeviceDel(struct omap_device* dev) {
    (void)dev;
    ++g_drm.dev_del_count;
}

struct omap_bo* mockOmapBoNew(struct omap_device* dev, uint32_t size, uint32_t flags) {
    (void)dev;
    (void)flags;
    const int idx = g_drm.bo_new_count++;
    if (g_drm.fail_bo_at == idx) {
        return NULL;
    }
    MockBo* bo = new MockBo();
    bo->requested_size = size;
    bo->data.resize(size, 0);
    g_drm.bos.push_back(bo);
    return reinterpret_cast<struct omap_bo*>(bo);
}

void mockOmapBoDel(struct omap_bo* raw) {
    ++g_drm.bo_del_count;
    MockBo* bo = reinterpret_cast<MockBo*>(raw);
    if (bo != NULL) {
        bo->freed = true;
    }
}

int mockOmapBoDmabuf(struct omap_bo* raw) {
    MockBo* bo = reinterpret_cast<MockBo*>(raw);
    if (bo == NULL) {
        return -1;
    }
    for (size_t i = 0; i < g_drm.bos.size(); ++i) {
        if (g_drm.bos[i] == bo) {
            if (g_drm.fail_dmabuf_at == static_cast<int>(i)) {
                return -1;
            }
            if (bo->fd < 0) {
#ifndef _WIN32
                bo->fd = open("/dev/null", O_RDONLY);
                if (bo->fd < 0) {
                    bo->fd = 200 + static_cast<int>(i);
                }
#else
                bo->fd = 200 + static_cast<int>(i);
#endif
            }
            bo->dmabuf_exported = true;
            return bo->fd;
        }
    }
    return -1;
}

void* mockOmapBoMap(struct omap_bo* raw) {
    MockBo* bo = reinterpret_cast<MockBo*>(raw);
    if (bo == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < g_drm.bos.size(); ++i) {
        if (g_drm.bos[i] == bo) {
            if (g_drm.fail_map_at == static_cast<int>(i)) {
                return NULL;
            }
            return &bo->data[0];
        }
    }
    return NULL;
}

DrmOmapApi makeMockDrmApi() {
    DrmOmapApi api;
    api.drmOpen = &mockDrmOpen;
    api.drmClose = &mockDrmClose;
    api.omap_device_new = &mockOmapDeviceNew;
    api.omap_device_del = &mockOmapDeviceDel;
    api.omap_bo_new = &mockOmapBoNew;
    api.omap_bo_del = &mockOmapBoDel;
    api.omap_bo_dmabuf = &mockOmapBoDmabuf;
    api.omap_bo_map = &mockOmapBoMap;
    return api;
}

struct MockXsvEvent {
    int words[5];
};

struct MockXsvState {
    Mutex mu;
    bool open_fails;
    bool configure_fails;
    bool reconfigure_fails;
    int decode_fail_remaining;
    bool auto_complete_dmabuf;
    bool auto_emit_frame;

    int open_calls;
    int close_calls;
    int configure_calls;
    int output_dim_calls;
    int update_calls;
    int start_calls;
    int stop_calls;
    int decode_calls;

    uint32_t last_surface_id;
    uint32_t last_width;
    uint32_t last_height;
    float last_fps;
    std::string last_title;

    std::vector<std::vector<uint8_t> > submitted_frames;
    std::vector<int> submitted_fds;
    std::vector<MockXsvEvent> pending_events;

    void reset() {
        LockGuard lock(mu);
        open_fails = false;
        configure_fails = false;
        reconfigure_fails = false;
        decode_fail_remaining = 0;
        auto_complete_dmabuf = true;
        auto_emit_frame = true;

        open_calls = 0;
        close_calls = 0;
        configure_calls = 0;
        output_dim_calls = 0;
        update_calls = 0;
        start_calls = 0;
        stop_calls = 0;
        decode_calls = 0;

        last_surface_id = 0;
        last_width = 0;
        last_height = 0;
        last_fps = -1.0f;
        last_title.clear();
        submitted_frames.clear();
        submitted_fds.clear();
        pending_events.clear();
    }

    void pushEvent(int type, int data = 0) {
        LockGuard lock(mu);
        MockXsvEvent e;
        std::memset(&e, 0, sizeof(e));
        e.words[0] = type;
        e.words[1] = data;
        pending_events.push_back(e);
    }

    MockXsvState() { reset(); }
};

MockXsvState g_xsv;

carplay::platform::xsv_handle mockXsvOpen(int type, uint32_t surface_id, const char* title) {
    (void)type;
    LockGuard lock(g_xsv.mu);
    ++g_xsv.open_calls;
    g_xsv.last_surface_id = surface_id;
    g_xsv.last_title = title != NULL ? title : "";
    if (g_xsv.open_fails) {
        return NULL;
    }
    return reinterpret_cast<carplay::platform::xsv_handle>(0x5678);
}

void mockXsvClose(carplay::platform::xsv_handle h) {
    (void)h;
    LockGuard lock(g_xsv.mu);
    ++g_xsv.close_calls;
}

int mockXsvConfigureStream(carplay::platform::xsv_handle h,
                           uint32_t width,
                           uint32_t height,
                           float fps) {
    (void)h;
    LockGuard lock(g_xsv.mu);
    ++g_xsv.configure_calls;
    if (g_xsv.configure_fails) {
        return -1;
    }
    if (g_xsv.configure_calls > 1 && g_xsv.reconfigure_fails) {
        g_xsv.reconfigure_fails = false;
        return -1;
    }
    g_xsv.last_width = width;
    g_xsv.last_height = height;
    g_xsv.last_fps = fps;
    return 0;
}

int mockXsvSetOutputDimension(carplay::platform::xsv_handle h, uint32_t width, uint32_t height) {
    (void)h;
    (void)width;
    (void)height;
    LockGuard lock(g_xsv.mu);
    ++g_xsv.output_dim_calls;
    return 0;
}

int mockXsvSetInputViewport(carplay::platform::xsv_handle h,
                            uint32_t x,
                            uint32_t y,
                            uint32_t w,
                            uint32_t hgt) {
    (void)h;
    (void)x;
    (void)y;
    (void)w;
    (void)hgt;
    return 0;
}

int mockXsvDecodeVideoFrame(carplay::platform::xsv_handle h, int dmabuf_fd, uint32_t length) {
    (void)h;
    LockGuard lock(g_xsv.mu);
    ++g_xsv.decode_calls;
    if (g_xsv.decode_fail_remaining > 0) {
        --g_xsv.decode_fail_remaining;
        return -1;
    }
    g_xsv.submitted_fds.push_back(dmabuf_fd);
    for (size_t i = 0; i < g_drm.bos.size(); ++i) {
        if (!g_drm.bos[i]->freed && g_drm.bos[i]->dmabuf_exported &&
            g_drm.bos[i]->fd == dmabuf_fd && length <= g_drm.bos[i]->data.size()) {
            std::vector<uint8_t> copy(g_drm.bos[i]->data.begin(),
                                      g_drm.bos[i]->data.begin() + length);
            g_xsv.submitted_frames.push_back(copy);
            break;
        }
    }
    if (g_xsv.auto_complete_dmabuf) {
        MockXsvEvent ev;
        std::memset(&ev, 0, sizeof(ev));
        ev.words[0] = carplay::platform::XSV_EVENT_DMABUF_COMPLETE;
        ev.words[1] = dmabuf_fd;
        g_xsv.pending_events.push_back(ev);
    }
    if (g_xsv.auto_emit_frame) {
        MockXsvEvent ev;
        std::memset(&ev, 0, sizeof(ev));
        ev.words[0] = carplay::platform::XSV_EVENT_FRAME;
        g_xsv.pending_events.push_back(ev);
    }
    return 0;
}

int mockXsvStart(carplay::platform::xsv_handle h) {
    (void)h;
    LockGuard lock(g_xsv.mu);
    ++g_xsv.start_calls;
    MockXsvEvent ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.words[0] = carplay::platform::XSV_EVENT_PLAYING;
    g_xsv.pending_events.push_back(ev);
    return 0;
}

int mockXsvStop(carplay::platform::xsv_handle h) {
    (void)h;
    LockGuard lock(g_xsv.mu);
    ++g_xsv.stop_calls;
    return 0;
}

int mockXsvPause(carplay::platform::xsv_handle h) {
    (void)h;
    return 0;
}

int mockXsvUpdate(carplay::platform::xsv_handle h) {
    (void)h;
    LockGuard lock(g_xsv.mu);
    ++g_xsv.update_calls;
    return 0;
}

int mockXsvEnableFrameEvents(carplay::platform::xsv_handle h) {
    (void)h;
    return 0;
}

int mockXsvDisableFrameEvents(carplay::platform::xsv_handle h) {
    (void)h;
    return 0;
}

int mockXsvReceiveEvent(carplay::platform::xsv_handle h, int* event_out, int timeout_ms) {
    (void)h;
    const int64_t deadline = monotonicMillis() + (timeout_ms > 0 ? timeout_ms : 0);
    for (;;) {
        {
            LockGuard lock(g_xsv.mu);
            if (!g_xsv.pending_events.empty()) {
                const MockXsvEvent ev = g_xsv.pending_events.front();
                g_xsv.pending_events.erase(g_xsv.pending_events.begin());
                std::memcpy(event_out, ev.words, sizeof(ev.words));
                return 0;
            }
        }
        if (monotonicMillis() >= deadline) {
            std::memset(event_out, 0, 5U * sizeof(int));
            return 0;
        }
#ifndef _WIN32
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 2000000L;
        nanosleep(&ts, NULL);
#endif
    }
}

int mockXsvGetEventQueueFd(carplay::platform::xsv_handle h) {
    (void)h;
    return -1;
}

XsvApi makeMockXsvApi() {
    XsvApi api;
    api.xsv_open = &mockXsvOpen;
    api.xsv_close = &mockXsvClose;
    api.xsv_configure_stream = &mockXsvConfigureStream;
    api.xsv_set_output_dimension = &mockXsvSetOutputDimension;
    api.xsv_set_input_viewport = &mockXsvSetInputViewport;
    api.xsv_decode_video_frame = &mockXsvDecodeVideoFrame;
    api.xsv_start = &mockXsvStart;
    api.xsv_stop = &mockXsvStop;
    api.xsv_pause = &mockXsvPause;
    api.xsv_update = &mockXsvUpdate;
    api.xsv_enable_frame_events = &mockXsvEnableFrameEvents;
    api.xsv_disable_frame_events = &mockXsvDisableFrameEvents;
    api.xsv_receive_event = &mockXsvReceiveEvent;
    api.xsv_get_event_queue_fd = &mockXsvGetEventQueueFd;
    return api;
}

bool waitUntilFirstFrame(EvoVideo& video, int timeout_ms) {
    const int64_t deadline = monotonicMillis() + timeout_ms;
    while (monotonicMillis() < deadline) {
        if (video.firstFrameSeen()) {
            return true;
        }
#ifndef _WIN32
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 5000000L;
        nanosleep(&ts, NULL);
#endif
    }
    return video.firstFrameSeen();
}

}  // namespace

// ============================================================================
// Tests
// ============================================================================

TEST_CASE(runCommandBasicsTimeoutAndTruncation) {
#ifndef _WIN32
    REQUIRE(!g_self_exe.empty());
    std::string output;
    std::vector<std::string> args(1, "literal $(echo nope); & data");
    CHECK(runCommand("/bin/echo", args, output));
    CHECK_EQ(args[0] + "\n", output);

    args[0] = "--fail";
    CHECK(!runCommand(g_self_exe, args, output));
    CHECK(output.empty());

    CommandReport report;
    args[0] = "--diagnostic-fail";
    CHECK(!runCommand(g_self_exe, args, output, 2000, &report));
    CHECK(output.empty());
    CHECK_EQ(9, report.exit_code);
    CHECK(!report.timed_out);
    CHECK(!report.truncated);
    CHECK(report.text.find("partial stdout") != std::string::npos);
    CHECK(report.text.find("detail stderr") != std::string::npos);

    args[0] = "--flood";
    CHECK(!runCommand(g_self_exe, args, output, 2000, &report));
    CHECK(output.empty());
    CHECK(report.truncated);
    CHECK(!report.timed_out);
    CHECK_EQ(static_cast<size_t>(65536), report.text.size());

    args[0] = "--sleep";
    const int64_t before = monotonicMillis();
    CHECK(!runCommand(g_self_exe, args, output, 80, &report));
    CHECK(monotonicMillis() - before < 1500);
    CHECK(report.timed_out);
    CHECK_EQ(-1, report.exit_code);

    int status = 0;
    CHECK(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD);

    CHECK(!runCommand("/nonexistent-carplay-binary", args, output, 2000, &report));
    CHECK(report.spawn_error == ENOENT || report.exit_code == 127);
#endif
}

TEST_CASE(evoIlmPureParsers) {
    std::vector<uint32_t> ids;

    CHECK(EvoIlm::parseRenderOrder("surface render order: [0x101, 0x102]\n", ids));
    REQUIRE(ids.size() == 2U);
    CHECK_EQ(0x101U, ids[0]);
    CHECK_EQ(0x102U, ids[1]);

    CHECK(EvoIlm::parseRenderOrder("surface render order:\n", ids) && ids.empty());
    CHECK(!EvoIlm::parseRenderOrder("surface render order: 0x101, junk", ids) && ids.empty());
    CHECK(!EvoIlm::parseRenderOrder("surface render order: 0x100000000", ids));
    CHECK(!EvoIlm::parseRenderOrder("surface render order: 0x101,0x101", ids));
    CHECK(!EvoIlm::parseRenderOrder("surface render order: 0x", ids));
    CHECK(!EvoIlm::parseRenderOrder("surface render order: [0x101", ids));
    CHECK(!EvoIlm::parseRenderOrder("surface render order: [0x101,]", ids));

    CHECK(EvoIlm::parseRenderOrder("- surface render order: 0(0x0), \r\n- on screen: 0(0x0)", ids));
    REQUIRE(ids.size() == 1U);
    CHECK_EQ(0U, ids[0]);

    CHECK(EvoIlm::parseRenderOrder(
        "- surface render order: 2125070337(0x7eaa0001), 0(0x0), \n", ids));
    REQUIRE(ids.size() == 2U);
    CHECK_EQ(0x7eaa0001U, ids[0]);
    CHECK_EQ(0U, ids[1]);

    CHECK(EvoIlm::parseRenderOrder(
        "- layer render order: 2147483648(0x80000000), 2164260864(0x81000000), \n", ids));
    REQUIRE(ids.size() == 2U);
    CHECK_EQ(0x80000000U, ids[0]);
    CHECK_EQ(0x81000000U, ids[1]);

    CHECK(EvoIlm::parseRenderOrder("- surface render order: \n- on screen: 0(0x0)", ids) &&
          ids.empty());
    CHECK(!EvoIlm::parseRenderOrder("surface render order: 131072(0x20001),", ids));
    CHECK(!EvoIlm::parseRenderOrder("surface render order: 4294967296(0x0),", ids));
    CHECK(!EvoIlm::parseRenderOrder("surface render order: 0(0x0), 0(0x0),", ids));
    CHECK(!EvoIlm::parseRenderOrder("surface render order: 0(0x0), junk", ids));
    CHECK(!EvoIlm::parseRenderOrder("surface render order: 0(0x0),,", ids));
    CHECK(!EvoIlm::parseRenderOrder("surface render order: 0(0x0)1(0x1)", ids));

    int w = 0;
    int h = 0;
    CHECK(EvoIlm::parseResolution("- resolution: x=800, y=480\r\n", w, h));
    CHECK_EQ(800, w);
    CHECK_EQ(480, h);
    CHECK(EvoIlm::parseResolution("- resolution: x=1280, y=480\n", w, h));
    CHECK_EQ(1280, w);
    CHECK_EQ(480, h);
    CHECK(!EvoIlm::parseResolution("- resolution: x=0, y=480\n", w, h));
    CHECK(!EvoIlm::parseResolution("- resolution: x=abc, y=480\n", w, h));

    CHECK(EvoIlm::parseSurfaceList(
        "2 Surface(s):\n- Surface 0 (0x0)\n- Surface 196610 (0x30002)\n", ids));
    REQUIRE(ids.size() == 2U);
    CHECK_EQ(0x30002U, ids[1]);
    CHECK(EvoIlm::parseSurfaceList("0 Surface(s):\n", ids) && ids.empty());
    CHECK(!EvoIlm::parseSurfaceList("2 Surface(s):\n- Surface 0 (0x0)\n", ids));
    CHECK(!EvoIlm::parseSurfaceList("1 Surface(s):\n- Surface 1 (0x2)\n", ids));
    CHECK(!EvoIlm::parseSurfaceList(
        "2 Surface(s):\n- Surface 0 (0x0)\n- Surface 0 (0x0)\n", ids));
    CHECK(!EvoIlm::parseSurfaceList("LayerManagerService returned: failed\n", ids));

    const std::string geom_800 =
        "- visibility: 1\n- opacity: 1\n- orientation: 0 (up is top)\n"
        "- source region: x=0, y=0, w=800, h=480\n"
        "- destination region: x=0, y=0, w=800, h=480\n";
    CHECK(EvoIlm::validLayerGeometry(geom_800, 800U, 480U));
    CHECK(!EvoIlm::validLayerGeometry(geom_800, 1280U, 480U));
    CHECK(!EvoIlm::validLayerGeometry(geom_800 + "- visibility: 1\n", 800U, 480U));

    std::string hidden = geom_800;
    hidden.replace(hidden.find("visibility: 1"), 13U, "visibility: 0");
    CHECK(!EvoIlm::validLayerGeometry(hidden, 800U, 480U));

    bool top_first = false;
    CHECK(EvoIlm::parseRenderOrderFlip("genivi-flip-renderorder = 1\n", top_first) && top_first);
    CHECK(EvoIlm::parseRenderOrderFlip("genivi-flip-renderorder = 0\n", top_first) && !top_first);
    CHECK(EvoIlm::parseRenderOrderFlip("genivi-flip-renderorder=1 # inline\r\n", top_first) &&
          top_first);
    CHECK(EvoIlm::parseRenderOrderFlip("plugin = ivi, genivi\n", top_first) && !top_first);
    CHECK(EvoIlm::parseRenderOrderFlip("#genivi-flip-renderorder = 1\n", top_first) && !top_first);
    CHECK(!EvoIlm::parseRenderOrderFlip("genivi-flip-renderorder = 2\n", top_first));
    CHECK(!EvoIlm::parseRenderOrderFlip("genivi-flip-renderorder =\n", top_first));
    CHECK(!EvoIlm::parseRenderOrderFlip(
        "genivi-flip-renderorder = 1\ngenivi-flip-renderorder = 1\n", top_first));
}

TEST_CASE(evoIlmCliExecutionAndValidation) {
#ifndef _WIN32
    REQUIRE(!g_self_exe.empty());

    const std::string log_path = makeTempFile("carplay-ilm-log");
    const std::string conf_plain = makeTempFile("carplay-conf-plain");
    const std::string conf_flip = makeTempFile("carplay-conf-flip");
    const std::string scene_dir = "/tmp/carplay-ilm-scene-" +
                                  std::string(log_path.substr(log_path.size() - 6U));
    REQUIRE(!log_path.empty() && !conf_plain.empty() && !conf_flip.empty());
    std::vector<std::string> mkdir_args;
    mkdir_args.push_back("-p");
    mkdir_args.push_back(scene_dir);
    std::string unused;
    REQUIRE(runCommand("/bin/mkdir", mkdir_args, unused));

    writeFileText(conf_plain.c_str(), "genivi-flip-renderorder = 0\n");
    writeFileText(conf_flip.c_str(), "genivi-flip-renderorder = 1\n");
    writeFixtureScene(scene_dir, 800U, 480U,
                      "2 Surface(s):\r\n- Surface 0 (0x0)\r\n- Surface 131072 (0x20000)\r\n");

    setenv("CARPLAY_TEST_LM_LOG", log_path.c_str(), 1);
    setenv("CARPLAY_TEST_SCENE_DIR", scene_dir.c_str(), 1);

    EvoIlm ilm_plain(g_self_exe, conf_plain);
    uint32_t sw = 0;
    uint32_t sh = 0;
    CHECK(ilm_plain.screenSize(sw, sh));
    CHECK_EQ(800U, sw);
    CHECK_EQ(480U, sh);
    CHECK(ilm_plain.validateTarget(0x7ec00001U, 0x80000000U, 800U, 480U, true));
    CHECK(!ilm_plain.validateTarget(0x20000U, 0x80000000U, 800U, 480U, true));
    CHECK(!ilm_plain.validateTarget(0x7ec00001U, 0x80000000U, 1280U, 480U, true));

    setenv("CARPLAY_TEST_TRUNCATED_SURFACES", "1", 1);
    CHECK(!ilm_plain.validateTarget(0x7ec00001U, 0x80000000U, 800U, 480U, true));
    unsetenv("CARPLAY_TEST_TRUNCATED_SURFACES");

    unsetenv("CARPLAY_TEST_SCENE_DIR");
    setenv("CARPLAY_TEST_ORDER", "0x101, 0x102", 1);
    resetLogAndOrder(log_path.c_str());

    // Normal GENIVI order: appended at end.
    CHECK(ilm_plain.attachSurface(0x7ec00001U, 0x80000000U, 800U, 480U));
    std::string log_text = readFileText(log_path.c_str());
    CHECK(log_text.find("set layer 0x80000000 render order 0x101,0x102,0x7ec00001") !=
          std::string::npos);
    CHECK(log_text.find("set screen") == std::string::npos);
    CHECK(ilm_plain.setSurfaceVisibility(0x7ec00001U, true));
    CHECK(ilm_plain.setSurfaceOpacity(0x7ec00001U, 0.75f));
    log_text = readFileText(log_path.c_str());
    CHECK(log_text.find("set surface 0x7ec00001 visibility 1") != std::string::npos);
    CHECK(log_text.find("set surface 0x7ec00001 opacity 0.75") != std::string::npos);
    CHECK(ilm_plain.detachSurface(0x7ec00001U, 0x80000000U));
    log_text = readFileText(log_path.c_str());
    CHECK(log_text.find("set layer 0x80000000 render order 0x101,0x102") != std::string::npos);

    // Flipped EntryNav2 order (genivi-flip-renderorder = 1): inserted at head.
    EvoIlm ilm_flip(g_self_exe, conf_flip);
    setenv("CARPLAY_TEST_ORDER", "0(0x0), ", 1);
    resetLogAndOrder(log_path.c_str());
    CHECK(ilm_flip.attachSurface(0x7ec00001U, 0x80000000U, 800U, 480U));
    log_text = readFileText(log_path.c_str());
    CHECK(log_text.find("set layer 0x80000000 render order 0x7ec00001,0x0") != std::string::npos);
    CHECK(log_text.find("set screen") == std::string::npos);

    // Overlay + raiseSurface
    resetLogAndOrder(log_path.c_str());
    setenv("CARPLAY_TEST_ORDER", "0x7ec00001, 0x0", 1);
    CHECK(ilm_flip.attachOverlay(0x7ec00002U, 0x80000000U, 200U, 380U, 400U, 64U));
    log_text = readFileText(log_path.c_str());
    CHECK(log_text.find("set surface 0x7ec00002 source region 0 0 400 64") != std::string::npos);
    CHECK(log_text.find("set surface 0x7ec00002 destination region 200 380 400 64") !=
          std::string::npos);
    CHECK(log_text.find("set layer 0x80000000 render order 0x7ec00002,0x7ec00001,0x0") !=
          std::string::npos);

    // Already on top: raiseSurface emits no set commands.
    resetLogAndOrder(log_path.c_str());
    setenv("CARPLAY_TEST_ORDER", "0x7ec00002, 0x7ec00001, 0x0", 1);
    CHECK(ilm_flip.raiseSurface(0x7ec00002U, 0x80000000U));
    CHECK(readFileText(log_path.c_str()).find("set ") == std::string::npos);

    // Behind another surface: raiseSurface moves it back to head.
    resetLogAndOrder(log_path.c_str());
    setenv("CARPLAY_TEST_ORDER", "0x7ec00001, 0x7ec00002, 0x0", 1);
    CHECK(ilm_flip.raiseSurface(0x7ec00002U, 0x80000000U));
    CHECK(readFileText(log_path.c_str()).find(
              "set layer 0x80000000 render order 0x7ec00002,0x7ec00001,0x0") != std::string::npos);

    // Refuses Interpreter error: even on exit 0.
    setenv("CARPLAY_TEST_ORDER", "0x0", 1);
    resetLogAndOrder(log_path.c_str());
    setenv("CARPLAY_TEST_PARSER_ERROR", "1", 1);
    CHECK(!ilm_flip.attachSurface(0x7ec00001U, 0x80000000U, 800U, 480U));
    unsetenv("CARPLAY_TEST_PARSER_ERROR");

    // Refuses LayerManagerService returned: failed even on exit 0.
    resetLogAndOrder(log_path.c_str());
    setenv("CARPLAY_TEST_ERROR_ZERO", "1", 1);
    CHECK(!ilm_flip.attachSurface(0x7ec00001U, 0x80000000U, 800U, 480U));
    CHECK(readFileText(log_path.c_str()).find("set ") == std::string::npos);
    unsetenv("CARPLAY_TEST_ERROR_ZERO");

    // Refuses when read-back shows render order did not stick.
    resetLogAndOrder(log_path.c_str());
    setenv("CARPLAY_TEST_NO_EFFECT", "1", 1);
    CHECK(!ilm_flip.attachSurface(0x7ec00001U, 0x80000000U, 800U, 480U));
    unsetenv("CARPLAY_TEST_NO_EFFECT");

    unsetenv("CARPLAY_TEST_LM_LOG");
    unsetenv("CARPLAY_TEST_ORDER");
    unlink((log_path + ".order").c_str());
    unlink(log_path.c_str());
    unlink(conf_plain.c_str());
    unlink(conf_flip.c_str());
    unlink((scene_dir + "/screen.txt").c_str());
    unlink((scene_dir + "/layer.txt").c_str());
    unlink((scene_dir + "/surfaces.txt").c_str());
    rmdir(scene_dir.c_str());
#endif
}

TEST_CASE(dmaBufPoolLifecycleAndFailures) {
    g_drm.reset();
    DmaBufPool pool;

    // Missing dlopen libraries fail cleanly.
    pool.setDrmLibrariesForTest("/nonexistent/libdrm.so.2", "/nonexistent/libdrm_omap.so.1");
    CHECK(!pool.init(4U, 65536U));
    CHECK_EQ(static_cast<size_t>(0), pool.size());

    // Inject mock table: test failure paths.
    pool.setApiForTest(makeMockDrmApi());

    g_drm.drm_open_result = -1;
    CHECK(!pool.init(4U, 65536U));
    g_drm.reset();

    g_drm.fail_device_new = true;
    CHECK(!pool.init(4U, 65536U));
    CHECK_EQ(1, g_drm.close_count);
    g_drm.reset();

    g_drm.fail_bo_at = 2;
    CHECK(!pool.init(4U, 65536U));
    CHECK_EQ(2, g_drm.bo_del_count);
    CHECK_EQ(1, g_drm.dev_del_count);
    CHECK_EQ(1, g_drm.close_count);
    g_drm.reset();

    g_drm.fail_map_at = 1;
    CHECK(!pool.init(4U, 65536U));
    CHECK_EQ(2, g_drm.bo_del_count);
    g_drm.reset();

    // Success path + exhaustion + find.
    REQUIRE(pool.init(3U, 65536U));
    CHECK_EQ(static_cast<size_t>(3), pool.size());

    const int i0 = pool.acquireFree();
    REQUIRE(i0 >= 0);
    pool.at(i0).in_flight = true;
    const int i1 = pool.acquireFree();
    REQUIRE(i1 >= 0 && i1 != i0);
    pool.at(i1).in_flight = true;
    const int i2 = pool.acquireFree();
    REQUIRE(i2 >= 0 && i2 != i0 && i2 != i1);
    pool.at(i2).in_flight = true;
    CHECK_EQ(-1, pool.acquireFree());

    CHECK_EQ(i1, pool.find(pool.at(i1).fd));
    CHECK_EQ(-1, pool.find(999999));

    pool.at(i1).in_flight = false;
    CHECK_EQ(i1, pool.acquireFree());

    pool.destroy();
    CHECK_EQ(static_cast<size_t>(0), pool.size());
    CHECK_EQ(3, g_drm.bo_del_count);
    CHECK_EQ(1, g_drm.dev_del_count);
    CHECK_EQ(1, g_drm.close_count);
    g_drm.reset();
}

TEST_CASE(evoVideoIsIdrAndSpsPpsPrependAndRetry) {
#ifndef _WIN32
    REQUIRE(!g_self_exe.empty());

    // Static isIdr checks (3-byte and 4-byte start codes).
    const uint8_t idr3[] = {0x00, 0x00, 0x01, 0x65, 0x88};
    const uint8_t idr4[] = {0x00, 0x00, 0x00, 0x01, 0x25, 0x88};
    const uint8_t non_idr[] = {0x00, 0x00, 0x00, 0x01, 0x41, 0x9a};
    const uint8_t aud_then_idr[] = {0x00, 0x00, 0x00, 0x01, 0x09, 0xf0,
                                    0x00, 0x00, 0x01, 0x65, 0xaa};
    CHECK(EvoVideo::isIdr(idr3, sizeof(idr3)));
    CHECK(EvoVideo::isIdr(idr4, sizeof(idr4)));
    CHECK(!EvoVideo::isIdr(non_idr, sizeof(non_idr)));
    CHECK(EvoVideo::isIdr(aud_then_idr, sizeof(aud_then_idr)));
    CHECK(!EvoVideo::isIdr(NULL, 0));

    const std::string log_path = makeTempFile("carplay-vid-log");
    const std::string conf_flip = makeTempFile("carplay-vid-conf");
    const std::string scene_dir = "/tmp/carplay-vid-scene-" +
                                  std::string(log_path.substr(log_path.size() - 6U));
    REQUIRE(!log_path.empty() && !conf_flip.empty());
    std::vector<std::string> mkdir_args;
    mkdir_args.push_back("-p");
    mkdir_args.push_back(scene_dir);
    std::string unused;
    REQUIRE(runCommand("/bin/mkdir", mkdir_args, unused));

    writeFileText(conf_flip.c_str(), "genivi-flip-renderorder = 1\n");
    writeFixtureScene(scene_dir, 800U, 480U, "1 Surface(s):\r\n- Surface 0 (0x0)\r\n");
    setenv("CARPLAY_TEST_LM_LOG", log_path.c_str(), 1);
    setenv("CARPLAY_TEST_SCENE_DIR", scene_dir.c_str(), 1);

    g_drm.reset();
    g_xsv.reset();

    EvoVideo video;
    video.setDrmOmapApiForTest(makeMockDrmApi());
    video.setXsvApiForTest(makeMockXsvApi());

    EvoVideoConfig cfg;
    cfg.width = 800U;
    cfg.height = 480U;
    cfg.display_width = 800U;
    cfg.display_height = 480U;
    cfg.pool_count = 2U;
    cfg.pool_buf_size = 65536U;
    cfg.acquire_timeout_ms = 25;
    cfg.ilm_ctl_path = g_self_exe;
    cfg.compositor_conf_path = conf_flip;

    REQUIRE(video.init(cfg));
    REQUIRE(video.start());
    CHECK(video.isStarted());
    CHECK(video.isReady());
    CHECK(!video.isVisible());
    CHECK(!video.firstFrameSeen());
    CHECK_EQ(1, g_xsv.open_calls);
    CHECK_EQ(0x7ec00001U, g_xsv.last_surface_id);
    CHECK_EQ(800U, g_xsv.last_width);
    CHECK_EQ(480U, g_xsv.last_height);
    CHECK_EQ(0.0f, g_xsv.last_fps);

    // Non-IDR frame before SPS/PPS: transmitted as-is; firstFrameSeen flips on XSV_EVENT_FRAME.
    CHECK(video.postVideoFrame(non_idr, sizeof(non_idr), 1000U));
    CHECK(waitUntilFirstFrame(video, 500));
    CHECK_EQ(static_cast<uint64_t>(1), video.framesReceived());
    CHECK_EQ(static_cast<uint64_t>(0), video.idrCount());

    // Cache SPS/PPS; simulate first IDR decode failure -> SPS/PPS must be retried on next IDR!
    const uint8_t sps_pps[] = {0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1e,
                               0x00, 0x00, 0x00, 0x01, 0x68, 0xce, 0x38, 0x80};
    video.postCodecConfig(sps_pps, sizeof(sps_pps));
    {
        LockGuard lock(g_xsv.mu);
        g_xsv.decode_fail_remaining = 1;
    }
    CHECK(!video.postVideoFrame(idr4, sizeof(idr4), 2000U));

    // Next IDR succeeds and receives SPS/PPS prepended.
    CHECK(video.postVideoFrame(idr4, sizeof(idr4), 3000U));
    // Following IDR does NOT receive SPS/PPS again.
    CHECK(video.postVideoFrame(idr4, sizeof(idr4), 4000U));
    // Subsequent non-IDR does NOT receive SPS/PPS.
    CHECK(video.postVideoFrame(non_idr, sizeof(non_idr), 5000U));

    {
        LockGuard lock(g_xsv.mu);
        REQUIRE(g_xsv.submitted_frames.size() == 4U);
        // Frame 0: non_idr only
        CHECK_BYTES_EQ(std::vector<uint8_t>(non_idr, non_idr + sizeof(non_idr)),
                       g_xsv.submitted_frames[0]);
        // Frame 1 (after failed IDR): sps_pps + idr4
        std::vector<uint8_t> expected_idr_with_cfg(sps_pps, sps_pps + sizeof(sps_pps));
        expected_idr_with_cfg.insert(expected_idr_with_cfg.end(), idr4, idr4 + sizeof(idr4));
        CHECK_BYTES_EQ(expected_idr_with_cfg, g_xsv.submitted_frames[1]);
        // Frame 2: idr4 only
        CHECK_BYTES_EQ(std::vector<uint8_t>(idr4, idr4 + sizeof(idr4)),
                       g_xsv.submitted_frames[2]);
        // Frame 3: non_idr only
        CHECK_BYTES_EQ(std::vector<uint8_t>(non_idr, non_idr + sizeof(non_idr)),
                       g_xsv.submitted_frames[3]);
    }

    // Visibility and opacity controls.
    video.setVisible(true);
    CHECK(video.isVisible());
    video.setVisible(false);
    CHECK(!video.isVisible());
    CHECK(video.setOpacity(0.5f));
    CHECK(video.opacity() > 0.49f && video.opacity() < 0.51f);

    // Exhaust 2-buffer pool by disabling auto DMABUF_COMPLETE.
    {
        LockGuard lock(g_xsv.mu);
        g_xsv.auto_complete_dmabuf = false;
    }
    CHECK(video.postVideoFrame(non_idr, sizeof(non_idr), 6000U));
    CHECK(video.postVideoFrame(non_idr, sizeof(non_idr), 7000U));
    // 3rd frame drops after acquire_timeout_ms.
    CHECK(!video.postVideoFrame(non_idr, sizeof(non_idr), 8000U));
    CHECK_EQ(static_cast<uint64_t>(1), video.framesDropped());

    // Release one dma-buf via XSV_EVENT_DMABUF_COMPLETE -> next frame succeeds.
    int release_fd = -1;
    {
        LockGuard lock(g_xsv.mu);
        release_fd = g_xsv.submitted_fds.back();
        g_xsv.auto_complete_dmabuf = true;
    }
    g_xsv.pushEvent(carplay::platform::XSV_EVENT_DMABUF_COMPLETE, release_fd);
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 25000000L;
    nanosleep(&ts, NULL);
    CHECK(video.postVideoFrame(non_idr, sizeof(non_idr), 9000U));

    video.stop();
    CHECK(!video.isStarted());
    CHECK(!video.isVisible());
    CHECK_EQ(1, g_xsv.stop_calls);
    CHECK_EQ(1, g_xsv.close_calls);

    unsetenv("CARPLAY_TEST_LM_LOG");
    unsetenv("CARPLAY_TEST_SCENE_DIR");
    unlink((log_path + ".order").c_str());
    unlink(log_path.c_str());
    unlink(conf_flip.c_str());
    unlink((scene_dir + "/screen.txt").c_str());
    unlink((scene_dir + "/layer.txt").c_str());
    unlink((scene_dir + "/surfaces.txt").c_str());
    rmdir(scene_dir.c_str());
    g_drm.reset();
    g_xsv.reset();
#endif
}

TEST_CASE(evoVideoSinkMediaIntegrationAndDynamicResolution) {
#ifndef _WIN32
    REQUIRE(!g_self_exe.empty());

    const std::string log_path = makeTempFile("carplay-sink-log");
    const std::string conf_flip = makeTempFile("carplay-sink-conf");
    const std::string scene_dir = "/tmp/carplay-sink-scene-" +
                                  std::string(log_path.substr(log_path.size() - 6U));
    REQUIRE(!log_path.empty() && !conf_flip.empty());
    std::vector<std::string> mkdir_args;
    mkdir_args.push_back("-p");
    mkdir_args.push_back(scene_dir);
    std::string unused;
    REQUIRE(runCommand("/bin/mkdir", mkdir_args, unused));

    writeFileText(conf_flip.c_str(), "genivi-flip-renderorder = 1\n");
    writeFixtureScene(scene_dir, 800U, 480U, "1 Surface(s):\r\n- Surface 0 (0x0)\r\n");
    setenv("CARPLAY_TEST_LM_LOG", log_path.c_str(), 1);
    setenv("CARPLAY_TEST_SCENE_DIR", scene_dir.c_str(), 1);

    g_drm.reset();
    g_xsv.reset();

    EvoVideo video;
    video.setDrmOmapApiForTest(makeMockDrmApi());
    video.setXsvApiForTest(makeMockXsvApi());

    EvoVideoConfig cfg;
    cfg.width = 800U;
    cfg.height = 480U;
    cfg.display_width = 800U;
    cfg.display_height = 480U;
    cfg.pool_count = 3U;
    cfg.pool_buf_size = 65536U;
    cfg.ilm_ctl_path = g_self_exe;
    cfg.compositor_conf_path = conf_flip;
    REQUIRE(video.init(cfg));

    EvoVideoSink sink(video, 110, false);

    // Alt stream 111 must be ignored.
    sink.onScreenStreamActive(111, true);
    CHECK(!video.isStarted());

    // Stream 110 activation starts EvoVideo.
    sink.onScreenStreamActive(110, true);
    CHECK(video.isStarted());

    // Dynamic resolution change 800x480 -> 1280x720 + new SPS/PPS.
    const uint8_t sps_pps[] = {0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x1f,
                               0x00, 0x00, 0x00, 0x01, 0x68, 0xee, 0x3c, 0x80};
    sink.onVideoConfig(110, carplay::stream::CODEC_H264_AVCC,
                       sps_pps, sizeof(sps_pps), NULL, 0U, 1280.0f, 720.0f);
    CHECK_EQ(1280U, video.config().width);
    CHECK_EQ(720U, video.config().height);
    {
        LockGuard lock(g_xsv.mu);
        CHECK_EQ(1280U, g_xsv.last_width);
        CHECK_EQ(720U, g_xsv.last_height);
        CHECK_EQ(2, g_xsv.configure_calls);
        CHECK_EQ(2, g_xsv.output_dim_calls);
        CHECK_EQ(2, g_xsv.update_calls);
    }

    const uint8_t idr[] = {0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84};
    sink.onVideoFrame(110, idr, sizeof(idr), 12345ULL, 67890LL);
    CHECK(waitUntilFirstFrame(video, 500));
    CHECK_EQ(static_cast<uint64_t>(1), video.framesReceived());
    CHECK_EQ(static_cast<uint64_t>(1), video.idrCount());

    sink.onScreenStreamActive(110, false);
    CHECK(!video.isStarted());

    unsetenv("CARPLAY_TEST_LM_LOG");
    unsetenv("CARPLAY_TEST_SCENE_DIR");
    unlink((log_path + ".order").c_str());
    unlink(log_path.c_str());
    unlink(conf_flip.c_str());
    unlink((scene_dir + "/screen.txt").c_str());
    unlink((scene_dir + "/layer.txt").c_str());
    unlink((scene_dir + "/surfaces.txt").c_str());
    rmdir(scene_dir.c_str());
    g_drm.reset();
    g_xsv.reset();
#endif
}

TEST_CASE(realDlopenMockSharedLibraryRoundTrip) {
#ifndef _WIN32
    REQUIRE(!g_self_exe.empty());

    // Find an available C compiler at test runtime; skip gracefully if none is installed.
    const char* cc_candidates[] = {"cc", "gcc", "clang", NULL};
    const char* cc = NULL;
    for (int i = 0; cc_candidates[i] != NULL; ++i) {
        std::string out;
        std::vector<std::string> args(1, "--version");
        if (runCommand(cc_candidates[i], args, out)) {
            cc = cc_candidates[i];
            break;
        }
    }
    if (cc == NULL) {
        return;
    }

    const std::string c_path = makeTempFile("carplay-mock-so") + ".c";
    const std::string so_path = makeTempFile("carplay-mock-so") + ".so";
    const std::string log_path = makeTempFile("carplay-dlopen-log");
    const std::string conf_flip = makeTempFile("carplay-dlopen-conf");
    const std::string scene_dir = "/tmp/carplay-dlopen-scene-" +
                                  std::string(log_path.substr(log_path.size() - 6U));
    std::vector<std::string> mkdir_args;
    mkdir_args.push_back("-p");
    mkdir_args.push_back(scene_dir);
    std::string unused;
    REQUIRE(runCommand("/bin/mkdir", mkdir_args, unused));

    const char* mock_c =
        "#include <fcntl.h>\n"
        "#include <stdint.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "#include <unistd.h>\n"
        "struct omap_device { int dummy; };\n"
        "struct omap_bo { uint8_t* buf; uint32_t size; int fd; };\n"
        "int drmOpen(const char* name, const char* busid) {\n"
        "  (void)busid; return (name && strcmp(name, \"omapdrm\") == 0) ? 77 : -1;\n"
        "}\n"
        "void drmClose(int fd) { (void)fd; }\n"
        "struct omap_device* omap_device_new(int fd) {\n"
        "  (void)fd; return (struct omap_device*)calloc(1, sizeof(struct omap_device));\n"
        "}\n"
        "void omap_device_del(struct omap_device* d) { free(d); }\n"
        "struct omap_bo* omap_bo_new(struct omap_device* d, uint32_t sz, uint32_t fl) {\n"
        "  (void)d; (void)fl;\n"
        "  struct omap_bo* b = (struct omap_bo*)calloc(1, sizeof(struct omap_bo));\n"
        "  b->buf = (uint8_t*)calloc(1, sz);\n"
        "  b->size = sz;\n"
        "  b->fd = open(\"/dev/null\", O_RDONLY);\n"
        "  return b;\n"
        "}\n"
        "void omap_bo_del(struct omap_bo* b) { if (b) { free(b->buf); free(b); } }\n"
        "int omap_bo_dmabuf(struct omap_bo* b) { return b ? b->fd : -1; }\n"
        "void* omap_bo_map(struct omap_bo* b) { return b ? b->buf : NULL; }\n"
        "typedef void* xsv_handle;\n"
        "static int g_pending_fd = -1;\n"
        "xsv_handle xsv_open(int t, uint32_t s, const char* title) {\n"
        "  (void)t; (void)s; (void)title; return (xsv_handle)0x1;\n"
        "}\n"
        "void xsv_close(xsv_handle h) { (void)h; }\n"
        "int xsv_configure_stream(xsv_handle h, uint32_t w, uint32_t hh, float fps) {\n"
        "  (void)h; (void)w; (void)hh; (void)fps; return 0;\n"
        "}\n"
        "int xsv_set_output_dimension(xsv_handle h, uint32_t w, uint32_t hh) {\n"
        "  (void)h; (void)w; (void)hh; return 0;\n"
        "}\n"
        "int xsv_set_input_viewport(xsv_handle h, uint32_t x, uint32_t y, uint32_t w, uint32_t hh) {\n"
        "  (void)h; (void)x; (void)y; (void)w; (void)hh; return 0;\n"
        "}\n"
        "int xsv_decode_video_frame(xsv_handle h, int fd, uint32_t len) {\n"
        "  (void)h; (void)len; g_pending_fd = fd; return 0;\n"
        "}\n"
        "int xsv_start(xsv_handle h) { (void)h; return 0; }\n"
        "int xsv_stop(xsv_handle h) { (void)h; return 0; }\n"
        "int xsv_pause(xsv_handle h) { (void)h; return 0; }\n"
        "int xsv_update(xsv_handle h) { (void)h; return 0; }\n"
        "int xsv_enable_frame_events(xsv_handle h) { (void)h; return 0; }\n"
        "int xsv_disable_frame_events(xsv_handle h) { (void)h; return 0; }\n"
        "int xsv_receive_event(xsv_handle h, int* ev, int timeout_ms) {\n"
        "  (void)h; (void)timeout_ms; memset(ev, 0, 5 * sizeof(int));\n"
        "  if (g_pending_fd >= 0) { ev[0] = 9; ev[1] = g_pending_fd; g_pending_fd = -1; return 0; }\n"
        "  usleep(5000); return 0;\n"
        "}\n"
        "int xsv_get_event_queue_fd(xsv_handle h) { (void)h; return -1; }\n";

    writeFileText(c_path.c_str(), mock_c);
    std::vector<std::string> cc_args;
    cc_args.push_back("-shared");
    cc_args.push_back("-fPIC");
    cc_args.push_back("-O2");
    cc_args.push_back(c_path);
    cc_args.push_back("-o");
    cc_args.push_back(so_path);
    std::string cc_out;
    REQUIRE(runCommand(cc, cc_args, cc_out, 5000));

    writeFileText(conf_flip.c_str(), "genivi-flip-renderorder = 1\n");
    writeFixtureScene(scene_dir, 800U, 480U, "1 Surface(s):\r\n- Surface 0 (0x0)\r\n");
    setenv("CARPLAY_TEST_LM_LOG", log_path.c_str(), 1);
    setenv("CARPLAY_TEST_SCENE_DIR", scene_dir.c_str(), 1);

    EvoVideo video;
    EvoVideoConfig cfg;
    cfg.xsv_lib_path = so_path;
    cfg.drm_lib_path = so_path;
    cfg.omap_lib_path = so_path;
    cfg.pool_count = 2U;
    cfg.pool_buf_size = 65536U;
    cfg.ilm_ctl_path = g_self_exe;
    cfg.compositor_conf_path = conf_flip;

    REQUIRE(video.init(cfg));
    REQUIRE(video.start());
    const uint8_t idr[] = {0x00, 0x00, 0x00, 0x01, 0x65, 0x88};
    CHECK(video.postVideoFrame(idr, sizeof(idr), 0U));
    video.stop();

    unsetenv("CARPLAY_TEST_LM_LOG");
    unsetenv("CARPLAY_TEST_SCENE_DIR");
    unlink(c_path.c_str());
    unlink(so_path.c_str());
    unlink((log_path + ".order").c_str());
    unlink(log_path.c_str());
    unlink(conf_flip.c_str());
    unlink((scene_dir + "/screen.txt").c_str());
    unlink((scene_dir + "/layer.txt").c_str());
    unlink((scene_dir + "/surfaces.txt").c_str());
    rmdir(scene_dir.c_str());
#endif
}

#ifndef _WIN32
namespace {

struct ScopedVideoTestEnv {
    std::string log_path;
    std::string conf_flip;
    std::string scene_dir;
    bool ok;

    ScopedVideoTestEnv() : ok(false) {
        log_path = makeTempFile("carplay-vtest-log");
        conf_flip = makeTempFile("carplay-vtest-conf");
        if (log_path.empty() || conf_flip.empty()) {
            return;
        }
        scene_dir = "/tmp/carplay-vtest-scene-" +
                    std::string(log_path.substr(log_path.size() - 6U));
        std::vector<std::string> mkdir_args;
        mkdir_args.push_back("-p");
        mkdir_args.push_back(scene_dir);
        std::string unused;
        if (!runCommand("/bin/mkdir", mkdir_args, unused)) {
            return;
        }
        writeFileText(conf_flip.c_str(), "genivi-flip-renderorder = 1\n");
        writeFixtureScene(scene_dir, 800U, 480U, "1 Surface(s):\r\n- Surface 0 (0x0)\r\n");
        setenv("CARPLAY_TEST_LM_LOG", log_path.c_str(), 1);
        setenv("CARPLAY_TEST_SCENE_DIR", scene_dir.c_str(), 1);
        g_drm.reset();
        g_xsv.reset();
        ok = true;
    }

    ~ScopedVideoTestEnv() {
        unsetenv("CARPLAY_TEST_LM_LOG");
        unsetenv("CARPLAY_TEST_SCENE_DIR");
        if (!log_path.empty()) {
            unlink((log_path + ".order").c_str());
            unlink(log_path.c_str());
        }
        if (!conf_flip.empty()) {
            unlink(conf_flip.c_str());
        }
        if (!scene_dir.empty()) {
            unlink((scene_dir + "/screen.txt").c_str());
            unlink((scene_dir + "/layer.txt").c_str());
            unlink((scene_dir + "/surfaces.txt").c_str());
            rmdir(scene_dir.c_str());
        }
        g_drm.reset();
        g_xsv.reset();
    }
};

}  // namespace
#endif

TEST_CASE(dmaBufPoolFailDmabufAndNoFdLeaks) {
#ifndef _WIN32
    REQUIRE(!g_self_exe.empty());

    // 1. Direct DmaBufPool fail_dmabuf_at at index 2 (after 2 exported BOs) and index 0.
    g_drm.reset();
    DmaBufPool pool;
    pool.setApiForTest(makeMockDrmApi());

    g_drm.fail_dmabuf_at = 2;
    CHECK(!pool.init(4U, 65536U));
    CHECK_EQ(static_cast<size_t>(0), pool.size());
    CHECK_EQ(3, g_drm.bo_new_count);
    CHECK_EQ(3, g_drm.bo_del_count);
    CHECK_EQ(1, g_drm.dev_new_count);
    CHECK_EQ(1, g_drm.dev_del_count);
    CHECK_EQ(1, g_drm.open_count);
    CHECK_EQ(1, g_drm.close_count);
    CHECK(g_drm.allBosFreed());
    CHECK(g_drm.allExportedFdsClosed());
    g_drm.reset();

    g_drm.fail_dmabuf_at = 0;
    CHECK(!pool.init(4U, 65536U));
    CHECK_EQ(static_cast<size_t>(0), pool.size());
    CHECK_EQ(1, g_drm.bo_new_count);
    CHECK_EQ(1, g_drm.bo_del_count);
    CHECK_EQ(1, g_drm.dev_del_count);
    CHECK_EQ(1, g_drm.close_count);
    CHECK(g_drm.allBosFreed());
    CHECK(g_drm.allExportedFdsClosed());
    g_drm.reset();

    // 2. Also verify fail_map_at closes exported fds before deleting BOs.
    g_drm.fail_map_at = 1;
    CHECK(!pool.init(4U, 65536U));
    CHECK_EQ(2, g_drm.bo_del_count);
    CHECK_EQ(1, g_drm.dev_del_count);
    CHECK_EQ(1, g_drm.close_count);
    CHECK(g_drm.allBosFreed());
    CHECK(g_drm.allExportedFdsClosed());
    g_drm.reset();

    // 3. Through EvoVideo::init(), fail_dmabuf_at cleans up and allows recovery.
    ScopedVideoTestEnv env;
    REQUIRE(env.ok);
    EvoVideo video;
    video.setDrmOmapApiForTest(makeMockDrmApi());
    video.setXsvApiForTest(makeMockXsvApi());

    EvoVideoConfig cfg;
    cfg.width = 800U;
    cfg.height = 480U;
    cfg.display_width = 800U;
    cfg.display_height = 480U;
    cfg.pool_count = 3U;
    cfg.pool_buf_size = 65536U;
    cfg.ilm_ctl_path = g_self_exe;
    cfg.compositor_conf_path = env.conf_flip;

    g_drm.fail_dmabuf_at = 1;
    CHECK(!video.init(cfg));
    CHECK_EQ(2, g_drm.bo_new_count);
    CHECK_EQ(2, g_drm.bo_del_count);
    CHECK_EQ(1, g_drm.dev_del_count);
    CHECK_EQ(1, g_drm.close_count);
    CHECK(g_drm.allBosFreed());
    CHECK(g_drm.allExportedFdsClosed());
    CHECK(!video.start());

    g_drm.fail_dmabuf_at = -1;
    REQUIRE(video.init(cfg));
    REQUIRE(video.start());
    const uint8_t idr[] = {0x00, 0x00, 0x00, 0x01, 0x65, 0x88};
    CHECK(video.postVideoFrame(idr, sizeof(idr), 0U));
    CHECK(waitUntilFirstFrame(video, 500));
    video.stop();
    CHECK(g_drm.allBosFreed());
    CHECK(g_drm.allExportedFdsClosed());
    CHECK_EQ(g_drm.bo_new_count, g_drm.bo_del_count);
    CHECK_EQ(g_drm.dev_new_count, g_drm.dev_del_count);
    CHECK_EQ(g_drm.open_count, g_drm.close_count);
#endif
}

TEST_CASE(evoVideoOpenAndConfigureFailuresCleanupAndRestart) {
#ifndef _WIN32
    REQUIRE(!g_self_exe.empty());
    ScopedVideoTestEnv env;
    REQUIRE(env.ok);

    EvoVideo video;
    video.setDrmOmapApiForTest(makeMockDrmApi());
    video.setXsvApiForTest(makeMockXsvApi());

    EvoVideoConfig cfg;
    cfg.width = 800U;
    cfg.height = 480U;
    cfg.display_width = 800U;
    cfg.display_height = 480U;
    cfg.pool_count = 2U;
    cfg.pool_buf_size = 65536U;
    cfg.ilm_ctl_path = g_self_exe;
    cfg.compositor_conf_path = env.conf_flip;

    const uint8_t idr[] = {0x00, 0x00, 0x00, 0x01, 0x65, 0x88};

    // 1. xsv_open failure: start() fails, stop() cleans up pool, retry start() recreates pool.
    REQUIRE(video.init(cfg));
    {
        LockGuard lock(g_xsv.mu);
        g_xsv.open_fails = true;
    }
    CHECK(!video.start());
    CHECK(!video.isStarted());
    CHECK(!video.isReady());
    CHECK(!video.postVideoFrame(idr, sizeof(idr), 1U));
    {
        LockGuard lock(g_xsv.mu);
        CHECK_EQ(1, g_xsv.open_calls);
        CHECK_EQ(0, g_xsv.close_calls);
        CHECK_EQ(0, g_xsv.configure_calls);
        g_xsv.open_fails = false;
    }
    // stop() destroys the pool allocated during init().
    video.stop();
    CHECK_EQ(2, g_drm.bo_del_count);
    CHECK_EQ(1, g_drm.dev_del_count);
    CHECK_EQ(1, g_drm.close_count);
    CHECK(g_drm.allBosFreed());
    CHECK(g_drm.allExportedFdsClosed());

    // Restart after open_fails without re-calling init() succeeds and allocates fresh pool.
    REQUIRE(video.start());
    CHECK(video.isStarted());
    CHECK(video.isReady());
    CHECK(video.postVideoFrame(idr, sizeof(idr), 2U));
    CHECK(waitUntilFirstFrame(video, 500));
    video.stop();
    CHECK_EQ(4, g_drm.bo_new_count);
    CHECK_EQ(4, g_drm.bo_del_count);
    CHECK_EQ(2, g_drm.dev_del_count);
    CHECK_EQ(2, g_drm.close_count);
    CHECK(g_drm.allBosFreed());
    CHECK(g_drm.allExportedFdsClosed());
    {
        LockGuard lock(g_xsv.mu);
        CHECK_EQ(2, g_xsv.open_calls);
        CHECK_EQ(1, g_xsv.close_calls);
        CHECK_EQ(1, g_xsv.stop_calls);
    }

    // 2. xsv_configure_stream failure: open succeeds then fails configure -> xsv_close called immediately.
    REQUIRE(video.init(cfg));
    {
        LockGuard lock(g_xsv.mu);
        g_xsv.configure_fails = true;
    }
    CHECK(!video.start());
    CHECK(!video.isStarted());
    CHECK(!video.isReady());
    CHECK(!video.postVideoFrame(idr, sizeof(idr), 3U));
    {
        LockGuard lock(g_xsv.mu);
        CHECK_EQ(3, g_xsv.open_calls);
        CHECK_EQ(2, g_xsv.close_calls);
        CHECK_EQ(2, g_xsv.configure_calls);
        CHECK_EQ(1, g_xsv.start_calls);
        g_xsv.configure_fails = false;
    }

    // Direct retry of start() reuses pool cleanly, and stop() frees all resources.
    REQUIRE(video.start());
    CHECK(video.isStarted());
    CHECK(video.isReady());
    CHECK(video.postVideoFrame(idr, sizeof(idr), 4U));
    CHECK(waitUntilFirstFrame(video, 500));
    video.stop();
    CHECK_EQ(g_drm.bo_new_count, g_drm.bo_del_count);
    CHECK_EQ(g_drm.dev_new_count, g_drm.dev_del_count);
    CHECK_EQ(g_drm.open_count, g_drm.close_count);
    CHECK(g_drm.allBosFreed());
    CHECK(g_drm.allExportedFdsClosed());
    {
        LockGuard lock(g_xsv.mu);
        CHECK_EQ(4, g_xsv.open_calls);
        CHECK_EQ(3, g_xsv.close_calls);
    }
#endif
}

TEST_CASE(evoVideoReconfigureOver720pAndSpsPpsCache) {
#ifndef _WIN32
    REQUIRE(!g_self_exe.empty());
    ScopedVideoTestEnv env;
    REQUIRE(env.ok);

    EvoVideo video;
    video.setDrmOmapApiForTest(makeMockDrmApi());
    video.setXsvApiForTest(makeMockXsvApi());

    const uint8_t old_sps_pps[] = {0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1e,
                                   0x00, 0x00, 0x00, 0x01, 0x68, 0xce, 0x38, 0x80};
    const uint8_t new_sps_pps[] = {0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x28,
                                   0x00, 0x00, 0x00, 0x01, 0x68, 0xee, 0x3c, 0x80};
    const uint8_t small_idr[] = {0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21};
    std::vector<uint8_t> big_idr(600U * 1024U, 0x55U);
    big_idr[0] = 0x00U;
    big_idr[1] = 0x00U;
    big_idr[2] = 0x00U;
    big_idr[3] = 0x01U;
    big_idr[4] = 0x65U;

    // 1. Not-started reconfig from 512 KiB pool -> >1280x720 clears old SPS/PPS and grows pool to 2 MiB.
    EvoVideoConfig cfg;
    cfg.width = 800U;
    cfg.height = 480U;
    cfg.display_width = 800U;
    cfg.display_height = 480U;
    cfg.pool_count = 2U;
    cfg.pool_buf_size = 512U * 1024U;
    cfg.ilm_ctl_path = g_self_exe;
    cfg.compositor_conf_path = env.conf_flip;

    REQUIRE(video.init(cfg));
    CHECK_EQ(2, g_drm.bo_new_count);
    CHECK_EQ(512U * 1024U, g_drm.bos[0]->requested_size);

    video.postCodecConfig(old_sps_pps, sizeof(old_sps_pps));
    // Resolution change while not started, with no new SPS/PPS yet.
    video.onVideoConfig(110, carplay::stream::CODEC_H264_AVCC,
                        NULL, 0U, NULL, 0U, 1920.0f, 1080.0f);
    CHECK(!video.isStarted());
    CHECK_EQ(1920U, video.config().width);
    CHECK_EQ(1080U, video.config().height);
    CHECK_EQ(2U << 20, video.config().pool_buf_size);
    CHECK_EQ(2, g_drm.bo_del_count);
    CHECK_EQ(1, g_drm.dev_del_count);
    CHECK_EQ(1, g_drm.close_count);
    CHECK(g_drm.allBosFreed());
    CHECK(g_drm.allExportedFdsClosed());

    REQUIRE(video.start());
    REQUIRE(g_drm.bos.size() == 4U);
    CHECK_EQ(2U << 20, g_drm.bos[2]->requested_size);
    CHECK_EQ(2U << 20, g_drm.bos[3]->requested_size);
    CHECK(!g_drm.bos[2]->freed);

    // >512 KiB keyframe accepted, and old_sps_pps was cleared by resolution change.
    CHECK(video.postVideoFrame(&big_idr[0], big_idr.size(), 100U));
    CHECK(waitUntilFirstFrame(video, 500));
    {
        LockGuard lock(g_xsv.mu);
        REQUIRE(g_xsv.submitted_frames.size() == 1U);
        CHECK_BYTES_EQ(big_idr, g_xsv.submitted_frames[0]);
    }
    video.stop();

    // 2. Same-resolution stop()/start() preserves cached SPS/PPS and resets config_sent_.
    g_drm.reset();
    g_xsv.reset();
    REQUIRE(video.init(cfg));
    REQUIRE(video.start());
    video.postCodecConfig(old_sps_pps, sizeof(old_sps_pps));
    CHECK(video.postVideoFrame(small_idr, sizeof(small_idr), 200U));
    CHECK(video.postVideoFrame(small_idr, sizeof(small_idr), 201U));

    video.stop();
    REQUIRE(video.start());
    CHECK(video.postVideoFrame(small_idr, sizeof(small_idr), 202U));
    {
        LockGuard lock(g_xsv.mu);
        REQUIRE(g_xsv.submitted_frames.size() == 3U);
        std::vector<uint8_t> with_old(old_sps_pps, old_sps_pps + sizeof(old_sps_pps));
        with_old.insert(with_old.end(), small_idr, small_idr + sizeof(small_idr));
        CHECK_BYTES_EQ(with_old, g_xsv.submitted_frames[0]);
        CHECK_BYTES_EQ(std::vector<uint8_t>(small_idr, small_idr + sizeof(small_idr)),
                       g_xsv.submitted_frames[1]);
        CHECK_BYTES_EQ(with_old, g_xsv.submitted_frames[2]);
    }

    // 3. In-place <=720p resolution change clears old SPS/PPS even when stop()/start() is NOT taken.
    video.onVideoConfig(110, carplay::stream::CODEC_H264_AVCC,
                        NULL, 0U, NULL, 0U, 1280.0f, 720.0f);
    CHECK_EQ(1280U, video.config().width);
    CHECK_EQ(720U, video.config().height);
    CHECK_EQ(512U * 1024U, video.config().pool_buf_size);
    {
        LockGuard lock(g_xsv.mu);
        CHECK_EQ(1, g_xsv.stop_calls);  // unchanged from explicit stop() above
    }
    CHECK(video.postVideoFrame(small_idr, sizeof(small_idr), 203U));
    {
        LockGuard lock(g_xsv.mu);
        REQUIRE(g_xsv.submitted_frames.size() == 4U);
        CHECK_BYTES_EQ(std::vector<uint8_t>(small_idr, small_idr + sizeof(small_idr)),
                       g_xsv.submitted_frames[3]);
    }

    // 4. Started reconfig from 512 KiB pool -> >1280x720 takes stop/start, preserves visibility,
    //    destroys 512 KiB pool, creates 2 MiB pool, and accepts >512 KiB keyframe with new SPS/PPS.
    video.setVisible(true);
    CHECK(video.isVisible());
    video.onVideoConfig(110, carplay::stream::CODEC_H264_AVCC,
                        new_sps_pps, sizeof(new_sps_pps), NULL, 0U, 1920.0f, 1080.0f);
    CHECK(video.isStarted());
    CHECK(video.isReady());
    CHECK(video.isVisible());
    CHECK_EQ(1920U, video.config().width);
    CHECK_EQ(1080U, video.config().height);
    CHECK_EQ(2U << 20, video.config().pool_buf_size);
    {
        LockGuard lock(g_xsv.mu);
        CHECK_EQ(2, g_xsv.stop_calls);
        CHECK_EQ(2, g_xsv.close_calls);
        CHECK_EQ(3, g_xsv.open_calls);
    }
    // Check old 512 KiB BOs are freed (and any still-open fd number was recycled to active 2 MiB BOs).
    REQUIRE(g_drm.bos.size() >= 6U);
    const int active_fd0 = g_drm.bos[g_drm.bos.size() - 2U]->fd;
    const int active_fd1 = g_drm.bos[g_drm.bos.size() - 1U]->fd;
    for (size_t i = 0; i + 2U < g_drm.bos.size(); ++i) {
        CHECK(g_drm.bos[i]->freed);
#ifndef _WIN32
        if (g_drm.bos[i]->dmabuf_exported &&
            g_drm.bos[i]->fd != active_fd0 &&
            g_drm.bos[i]->fd != active_fd1) {
            CHECK(fcntl(g_drm.bos[i]->fd, F_GETFD) == -1 && errno == EBADF);
        }
#endif
    }
    CHECK_EQ(2U << 20, g_drm.bos[g_drm.bos.size() - 2U]->requested_size);
    CHECK_EQ(2U << 20, g_drm.bos[g_drm.bos.size() - 1U]->requested_size);

    CHECK(video.postVideoFrame(&big_idr[0], big_idr.size(), 300U));
    {
        LockGuard lock(g_xsv.mu);
        REQUIRE(g_xsv.submitted_frames.size() == 5U);
        // Reserve first: GCC 15 reports a false -Warray-bounds on inserting into
        // a vector sized exactly from a 16-byte array.
        std::vector<uint8_t> expected_big;
        expected_big.reserve(sizeof(new_sps_pps) + big_idr.size());
        expected_big.insert(expected_big.end(), new_sps_pps, new_sps_pps + sizeof(new_sps_pps));
        expected_big.insert(expected_big.end(), big_idr.begin(), big_idr.end());
        CHECK_BYTES_EQ(expected_big, g_xsv.submitted_frames[4]);
    }

    video.stop();
    CHECK(g_drm.allBosFreed());
    CHECK(g_drm.allExportedFdsClosed());
    CHECK_EQ(g_drm.bo_new_count, g_drm.bo_del_count);
    CHECK_EQ(g_drm.dev_new_count, g_drm.dev_del_count);
    CHECK_EQ(g_drm.open_count, g_drm.close_count);
#endif
}

TEST_CASE(evoVideoReconfigureFailsFallbackAndAutoShowSink) {
#ifndef _WIN32
    REQUIRE(!g_self_exe.empty());
    ScopedVideoTestEnv env;
    REQUIRE(env.ok);

    EvoVideo video;
    video.setDrmOmapApiForTest(makeMockDrmApi());
    video.setXsvApiForTest(makeMockXsvApi());

    EvoVideoConfig cfg;
    cfg.width = 800U;
    cfg.height = 480U;
    cfg.display_width = 800U;
    cfg.display_height = 480U;
    cfg.pool_count = 2U;
    cfg.pool_buf_size = 512U * 1024U;
    cfg.ilm_ctl_path = g_self_exe;
    cfg.compositor_conf_path = env.conf_flip;
    REQUIRE(video.init(cfg));

    // 1. EvoVideoSink with auto_show = true keeps hidden until after firstFrameSeen().
    EvoVideoSink sink(video, 110, true);
    sink.onScreenStreamActive(110, true);
    CHECK(video.isStarted());
    CHECK(!video.isVisible());

    const uint8_t non_idr[] = {0x00, 0x00, 0x00, 0x01, 0x41, 0x9a};
    const uint8_t idr[] = {0x00, 0x00, 0x00, 0x01, 0x65, 0x88};
    sink.onVideoFrame(110, idr, sizeof(idr), 100U, 100LL);
    CHECK(waitUntilFirstFrame(video, 500));
    if (!video.isVisible()) {
        sink.onVideoFrame(110, non_idr, sizeof(non_idr), 200U, 200LL);
    }
    CHECK(video.isVisible());
    CHECK(readFileText(env.log_path.c_str()).find("set surface 0x7ec00001 visibility 1") !=
          std::string::npos);

    // 2. While visible, trigger in-place reconfigure failure -> stop/start fallback preserves visibility.
    const uint8_t sps_pps[] = {0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x1f,
                               0x00, 0x00, 0x00, 0x01, 0x68, 0xee, 0x3c, 0x80};
    {
        LockGuard lock(g_xsv.mu);
        g_xsv.reconfigure_fails = true;
    }
    sink.onVideoConfig(110, carplay::stream::CODEC_H264_AVCC,
                       sps_pps, sizeof(sps_pps), NULL, 0U, 1280.0f, 720.0f);
    CHECK(video.isStarted());
    CHECK(video.isReady());
    CHECK(video.isVisible());
    CHECK_EQ(1280U, video.config().width);
    CHECK_EQ(720U, video.config().height);
    {
        LockGuard lock(g_xsv.mu);
        CHECK(!g_xsv.reconfigure_fails);
        CHECK_EQ(2, g_xsv.open_calls);
        CHECK_EQ(1, g_xsv.close_calls);
        CHECK_EQ(1, g_xsv.stop_calls);
        CHECK_EQ(3, g_xsv.configure_calls);
        CHECK_EQ(1280U, g_xsv.last_width);
        CHECK_EQ(720U, g_xsv.last_height);
    }

    // Subsequent IDR receives new SPS/PPS and triggers first frame on restarted stream.
    sink.onVideoFrame(110, idr, sizeof(idr), 300U, 300LL);
    CHECK(waitUntilFirstFrame(video, 500));
    {
        LockGuard lock(g_xsv.mu);
        REQUIRE(!g_xsv.submitted_frames.empty());
        std::vector<uint8_t> expected(sps_pps, sps_pps + sizeof(sps_pps));
        expected.insert(expected.end(), idr, idr + sizeof(idr));
        CHECK_BYTES_EQ(expected, g_xsv.submitted_frames.back());
    }

    sink.onScreenStreamActive(110, false);
    CHECK(!video.isStarted());
    CHECK(!video.isVisible());
    CHECK(g_drm.allBosFreed());
    CHECK(g_drm.allExportedFdsClosed());
    CHECK_EQ(g_drm.bo_new_count, g_drm.bo_del_count);
    CHECK_EQ(g_drm.dev_new_count, g_drm.dev_del_count);
    CHECK_EQ(g_drm.open_count, g_drm.close_count);
#endif
}

int main(int argc, char** argv) {
    if (argc > 1) {
        return runSubprocessHelper(argc, argv);
    }
#ifndef _WIN32
    char buf[PATH_MAX];
    if (realpath(argv[0], buf) != NULL) {
        g_self_exe = buf;
    } else {
        g_self_exe = argv[0];
    }
#else
    g_self_exe = argv[0];
#endif
    return test_support::runAll("test_evo_video");
}
