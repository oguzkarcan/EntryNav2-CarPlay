#ifndef CARPLAY_PLATFORM_EVO_VIDEO_HPP
#define CARPLAY_PLATFORM_EVO_VIDEO_HPP

// BMW EntryNav2 hardware H.264 video sink:
//   * libxsvideo.so.4 (dlopen) type-1 decoder onto an IVI Wayland surface
//   * OMAP dma-buf pool (libdrm.so.2 + libdrm_omap.so.1 via dlopen) carrying Annex-B H.264
//   * GENIVI LayerManager (EvoIlm) attaching/showing/hiding our surface without touching screen order

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "carplay/platform/evo_ilm.hpp"
#include "carplay/platform/media_engine.hpp"
#include "carplay/platform/omap_dmabuf.hpp"
#include "carplay/platform/thread.hpp"
#include "carplay/platform/xsv_api.hpp"

#ifndef _WIN32
#include <pthread.h>
#endif

namespace carplay {
namespace platform {

struct EvoVideoConfig {
    uint32_t surface_id;
    uint32_t layer_id;
    uint32_t width;
    uint32_t height;
    uint32_t display_width;
    uint32_t display_height;
    float fps;
    unsigned pool_count;
    uint32_t pool_buf_size;
    int acquire_timeout_ms;
    std::string title;
    std::string xsv_lib_path;
    std::string drm_lib_path;
    std::string omap_lib_path;
    std::string ilm_ctl_path;
    std::string compositor_conf_path;

    EvoVideoConfig()
        : surface_id(kDefaultCarPlaySurfaceId),
          layer_id(kDefaultCarPlayLayerId),
          width(800U),
          height(480U),
          display_width(800U),
          display_height(480U),
          fps(0.0f),
          pool_count(4U),
          pool_buf_size(512U * 1024U),
          acquire_timeout_ms(20),
          title("carplay"),
          xsv_lib_path("libxsvideo.so.4"),
          drm_lib_path("libdrm.so.2"),
          omap_lib_path("libdrm_omap.so.1"),
          ilm_ctl_path("/usr/bin/LayerManagerControl"),
          compositor_conf_path("/etc/wayland/compositor.conf") {}

    void setDisplay(uint32_t canvas_width,
                    uint32_t canvas_height,
                    uint32_t panel_width,
                    uint32_t panel_height) {
        width = canvas_width;
        height = canvas_height;
        display_width = panel_width;
        display_height = panel_height;
        if ((canvas_width > 1280U || canvas_height > 720U) &&
            pool_buf_size < (2U << 20)) {
            pool_buf_size = (2U << 20);
        }
    }
};

class EvoVideo {
public:
    EvoVideo();
    ~EvoVideo();

    /// Test hooks: inject mock function tables (bypassing dlopen for libxsvideo / libdrm).
    void setXsvApiForTest(const XsvApi& api);
    void clearXsvApiForTest();
    void setDrmOmapApiForTest(const DrmOmapApi& api);
    void clearDrmOmapApiForTest();

    /// Validates target layer/surface and allocates the dma-buf pool.
    bool init(const EvoVideoConfig& cfg = EvoVideoConfig());
    /// Opens libxsvideo, starts the decoder + event thread, and attaches the surface hidden.
    bool start();
    void stop();

    void setVisible(bool visible);
    bool isVisible() const;
    bool setOpacity(float opacity);
    float opacity() const;

    bool isReady() const;
    bool isStarted() const;
    bool firstFrameSeen() const;

    /// Caches SPS/PPS Annex-B bytes and marks them to be prepended to the next IDR frame.
    void postCodecConfig(const uint8_t* data, size_t len);
    /// Submits one Annex-B H.264 access unit via a free dma-buf.
    bool postVideoFrame(const uint8_t* data, size_t len, uint64_t pts = 0);

    /// Scans an Annex-B bitstream for an H.264 IDR slice (NAL unit type 5).
    static bool isIdr(const uint8_t* data, size_t len);

    uint64_t framesReceived() const;
    uint64_t framesDropped() const;
    uint64_t idrCount() const;

    const EvoVideoConfig& config() const { return cfg_; }

    // Direct MediaSink-aligned methods for stream type 110 (main CarPlay display).
    void onScreenStreamActive(int32_t type, bool active);
    void onVideoConfig(int32_t type,
                       stream::VideoCodecType codec,
                       const uint8_t* annexb_data,
                       size_t annexb_len,
                       const uint8_t* raw_config,
                       size_t raw_len,
                       float width_px,
                       float height_px);
    void onVideoFrame(int32_t type,
                      const uint8_t* annexb_data,
                      size_t len,
                      uint64_t sender_nanos,
                      int64_t arrival_mono_nanos);

private:
    EvoVideo(const EvoVideo&) = delete;
    EvoVideo& operator=(const EvoVideo&) = delete;

    static void eventStub(void* self);
    void eventLoop();
    bool loadXsvLibrary();
    void unloadXsvLibrary();
    bool isRunning() const;
    bool reconfigureStream(uint32_t new_width, uint32_t new_height);

    EvoVideoConfig cfg_;
    EvoIlm ilm_;
    DmaBufPool pool_;

    void* xsv_handle_;
    XsvApi xsv_;
    bool use_test_xsv_api_;
    xsv_handle h_;

    Thread ev_thread_;

#ifdef _WIN32
    mutable Mutex mu_;
#else
    mutable pthread_mutex_t mu_;
    pthread_cond_t cv_;
#endif

    bool initialized_;
    bool running_;
    bool visible_;
    float opacity_;
    bool ready_;
    bool started_;
    bool config_sent_;
    bool seen_first_frame_;
    std::vector<uint8_t> codec_cfg_;
    uint64_t frames_in_;
    uint64_t frames_dropped_;
    uint64_t idr_seen_;
    uint64_t frames_at_start_;
};

/// MediaSink adapter forwarding CarPlay main screen callbacks (default type 110) to EvoVideo.
class EvoVideoSink : public MediaSink {
public:
    explicit EvoVideoSink(EvoVideo& video, int32_t stream_type = 110, bool auto_show = false);
    virtual ~EvoVideoSink() {}

    virtual void onScreenStreamActive(int32_t type, bool active);
    virtual void onVideoConfig(int32_t type,
                               stream::VideoCodecType codec,
                               const uint8_t* annexb_data,
                               size_t annexb_len,
                               const uint8_t* raw_config,
                               size_t raw_len,
                               float width_px,
                               float height_px);
    virtual void onVideoFrame(int32_t type,
                              const uint8_t* annexb_data,
                              size_t len,
                              uint64_t sender_nanos,
                              int64_t arrival_mono_nanos);

private:
    EvoVideoSink(const EvoVideoSink&) = delete;
    EvoVideoSink& operator=(const EvoVideoSink&) = delete;

    EvoVideo& video_;
    int32_t stream_type_;
    bool auto_show_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_EVO_VIDEO_HPP
