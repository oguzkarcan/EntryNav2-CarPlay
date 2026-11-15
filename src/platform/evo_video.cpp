#if defined(_WIN32) && !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1
#endif

#include "carplay/platform/evo_video.hpp"

#include <cerrno>
#include <cstring>
#include <ctime>

#include "carplay/platform/log.hpp"

#ifndef _WIN32
#include <dlfcn.h>
#endif

namespace carplay {
namespace platform {

namespace {

static const int32_t kMainScreenStreamType = 110;

bool xsvCommand(const char* name, int result) {
    if (result < 0) {
        CARPLAY_LOG_ERROR("video", "%s failed (result=%d)", name, result);
        return false;
    }
    CARPLAY_LOG_DEBUG("video", "%s accepted (result=%d)", name, result);
    return true;
}

#ifndef _WIN32
template <typename Fn>
bool loadXsvSym(void* handle, const char* symbol, Fn& out) {
    dlerror();
    void* sym = dlsym(handle, symbol);
    const char* err = dlerror();
    if (err != NULL || sym == NULL) {
        CARPLAY_LOG_ERROR("video", "dlsym(%s) failed: %s", symbol,
                          err != NULL ? err : "NULL symbol");
        return false;
    }
    std::memcpy(&out, &sym, sizeof(out));
    return true;
}
#endif

}  // namespace

EvoVideo::EvoVideo()
    : xsv_handle_(NULL),
      use_test_xsv_api_(false),
      h_(NULL),
      initialized_(false),
      running_(false),
      visible_(false),
      opacity_(1.0f),
      ready_(false),
      started_(false),
      config_sent_(false),
      seen_first_frame_(false),
      frames_in_(0),
      frames_dropped_(0),
      idr_seen_(0),
      frames_at_start_(0) {
#ifndef _WIN32
    pthread_mutex_init(&mu_, NULL);
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&cv_, &attr);
    pthread_condattr_destroy(&attr);
#endif
}

EvoVideo::~EvoVideo() {
    stop();
    unloadXsvLibrary();
#ifndef _WIN32
    pthread_cond_destroy(&cv_);
    pthread_mutex_destroy(&mu_);
#endif
}

void EvoVideo::setXsvApiForTest(const XsvApi& api) {
    stop();
    unloadXsvLibrary();
    xsv_ = api;
    use_test_xsv_api_ = true;
}

void EvoVideo::clearXsvApiForTest() {
    stop();
    unloadXsvLibrary();
    xsv_ = XsvApi();
    use_test_xsv_api_ = false;
}

void EvoVideo::setDrmOmapApiForTest(const DrmOmapApi& api) {
    pool_.setApiForTest(api);
}

void EvoVideo::clearDrmOmapApiForTest() {
    pool_.clearApiForTest();
}

bool EvoVideo::loadXsvLibrary() {
    if (use_test_xsv_api_) {
        if (!xsv_.complete()) {
            CARPLAY_LOG_ERROR("video", "injected XsvApi is incomplete");
            return false;
        }
        return true;
    }

#ifdef _WIN32
    CARPLAY_LOG_ERROR("video", "dlopen of libxsvideo is not supported on Windows");
    return false;
#else
    if (xsv_handle_ != NULL && xsv_.complete()) {
        return true;
    }
    unloadXsvLibrary();

    const char* path = cfg_.xsv_lib_path.empty() ? "libxsvideo.so.4" : cfg_.xsv_lib_path.c_str();
    xsv_handle_ = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (xsv_handle_ == NULL) {
        CARPLAY_LOG_ERROR("video", "dlopen(%s) failed: %s", path, dlerror());
        return false;
    }

    const bool ok =
        loadXsvSym(xsv_handle_, "xsv_open", xsv_.xsv_open) &&
        loadXsvSym(xsv_handle_, "xsv_close", xsv_.xsv_close) &&
        loadXsvSym(xsv_handle_, "xsv_configure_stream", xsv_.xsv_configure_stream) &&
        loadXsvSym(xsv_handle_, "xsv_set_output_dimension", xsv_.xsv_set_output_dimension) &&
        loadXsvSym(xsv_handle_, "xsv_set_input_viewport", xsv_.xsv_set_input_viewport) &&
        loadXsvSym(xsv_handle_, "xsv_decode_video_frame", xsv_.xsv_decode_video_frame) &&
        loadXsvSym(xsv_handle_, "xsv_start", xsv_.xsv_start) &&
        loadXsvSym(xsv_handle_, "xsv_stop", xsv_.xsv_stop) &&
        loadXsvSym(xsv_handle_, "xsv_pause", xsv_.xsv_pause) &&
        loadXsvSym(xsv_handle_, "xsv_update", xsv_.xsv_update) &&
        loadXsvSym(xsv_handle_, "xsv_enable_frame_events", xsv_.xsv_enable_frame_events) &&
        loadXsvSym(xsv_handle_, "xsv_disable_frame_events", xsv_.xsv_disable_frame_events) &&
        loadXsvSym(xsv_handle_, "xsv_receive_event", xsv_.xsv_receive_event) &&
        loadXsvSym(xsv_handle_, "xsv_get_event_queue_fd", xsv_.xsv_get_event_queue_fd);

    if (!ok || !xsv_.complete()) {
        unloadXsvLibrary();
        return false;
    }
    return true;
#endif
}

void EvoVideo::unloadXsvLibrary() {
    if (!use_test_xsv_api_) {
        xsv_ = XsvApi();
    }
#ifndef _WIN32
    if (xsv_handle_ != NULL) {
        dlclose(xsv_handle_);
        xsv_handle_ = NULL;
    }
#endif
}

bool EvoVideo::init(const EvoVideoConfig& cfg) {
    if (isStarted()) {
        return false;
    }
    if (cfg.width == 0U || cfg.height == 0U || cfg.width > 1920U || cfg.height > 1080U ||
        cfg.display_width == 0U || cfg.display_height == 0U ||
        cfg.display_width > cfg.width || cfg.display_height > cfg.height ||
        cfg.pool_count == 0U || cfg.pool_count > 16U ||
        cfg.pool_buf_size < 65536U || cfg.pool_buf_size > (4U << 20)) {
        CARPLAY_LOG_ERROR("video", "REFUSED: invalid EvoVideoConfig dimensions or pool bounds");
        return false;
    }

    EvoIlm ilm(cfg.ilm_ctl_path, cfg.compositor_conf_path);
    if (!ilm.validateTarget(cfg.surface_id, cfg.layer_id, cfg.display_width, cfg.display_height)) {
        CARPLAY_LOG_ERROR("video",
                          "REFUSED: ILM target invalid (surface=0x%x layer=0x%x %ux%u)",
                          cfg.surface_id, cfg.layer_id, cfg.display_width, cfg.display_height);
        return false;
    }

    pool_.destroy();
    if (!pool_.hasTestApi()) {
        pool_.setDrmLibrariesForTest(cfg.drm_lib_path.c_str(), cfg.omap_lib_path.c_str());
    }
    if (!pool_.init(cfg.pool_count, cfg.pool_buf_size)) {
        return false;
    }

    cfg_ = cfg;
    ilm_ = ilm;
    initialized_ = true;
    CARPLAY_LOG_INFO("video", "init %ux%u (display %ux%u) surface=0x%x layer=0x%x pool=%ux%u",
                     cfg_.width, cfg_.height, cfg_.display_width, cfg_.display_height,
                     cfg_.surface_id, cfg_.layer_id, cfg_.pool_count, cfg_.pool_buf_size);
    return true;
}

bool EvoVideo::start() {
    if (isStarted()) {
        return true;
    }
    if (!initialized_) {
        return false;
    }
    if (!ilm_.validateTarget(cfg_.surface_id, cfg_.layer_id, cfg_.display_width, cfg_.display_height)) {
        CARPLAY_LOG_ERROR("video", "layer unreadable or surface 0x%x already taken", cfg_.surface_id);
        return false;
    }
    if (pool_.size() == 0U && !pool_.init(cfg_.pool_count, cfg_.pool_buf_size)) {
        return false;
    }
    if (!loadXsvLibrary()) {
        return false;
    }

    const char* title = cfg_.title.empty() ? "carplay" : cfg_.title.c_str();
    h_ = xsv_.xsv_open(XSV_TYPE_DIGITAL_CAM, cfg_.surface_id, title);
    if (h_ == NULL) {
        CARPLAY_LOG_ERROR("video", "xsv_open(type=%d, surface=0x%x) failed",
                          XSV_TYPE_DIGITAL_CAM, cfg_.surface_id);
        return false;
    }

    if (!xsvCommand("xsv_configure_stream",
                    xsv_.xsv_configure_stream(h_, cfg_.width, cfg_.height, cfg_.fps)) ||
        !xsvCommand("xsv_set_output_dimension",
                    xsv_.xsv_set_output_dimension(h_, cfg_.width, cfg_.height)) ||
        !xsvCommand("xsv_enable_frame_events", xsv_.xsv_enable_frame_events(h_)) ||
        !xsvCommand("xsv_update", xsv_.xsv_update(h_)) ||
        !xsvCommand("xsv_start", xsv_.xsv_start(h_))) {
        xsv_.xsv_close(h_);
        h_ = NULL;
        return false;
    }

#ifdef _WIN32
    {
        LockGuard lock(mu_);
        running_ = true;
        started_ = true;
        config_sent_ = false;
        seen_first_frame_ = false;
        frames_at_start_ = frames_in_;
        opacity_ = 1.0f;
        visible_ = false;
        ready_ = false;
    }
#else
    pthread_mutex_lock(&mu_);
    running_ = true;
    started_ = true;
    config_sent_ = false;
    seen_first_frame_ = false;
    frames_at_start_ = frames_in_;
    opacity_ = 1.0f;
    visible_ = false;
    ready_ = false;
    pthread_mutex_unlock(&mu_);
#endif

    if (!ev_thread_.start(&EvoVideo::eventStub, this)) {
        CARPLAY_LOG_ERROR("video", "failed to start libxsvideo event thread");
        stop();
        return false;
    }

    if (!ilm_.attachSurface(cfg_.surface_id, cfg_.layer_id, cfg_.display_width, cfg_.display_height) ||
        !ilm_.setSurfaceVisibility(cfg_.surface_id, false)) {
        stop();
        return false;
    }

#ifdef _WIN32
    {
        LockGuard lock(mu_);
        ready_ = true;
    }
#else
    pthread_mutex_lock(&mu_);
    ready_ = true;
    pthread_mutex_unlock(&mu_);
#endif

    CARPLAY_LOG_INFO("video", "started (handle=%p surface=0x%x)", h_, cfg_.surface_id);
    return true;
}

void EvoVideo::stop() {
    if (!isStarted()) {
        pool_.destroy();
        return;
    }

#ifdef _WIN32
    {
        LockGuard lock(mu_);
        running_ = false;
    }
#else
    pthread_mutex_lock(&mu_);
    running_ = false;
    pthread_cond_broadcast(&cv_);
    pthread_mutex_unlock(&mu_);
#endif

    ev_thread_.join();

    ilm_.setSurfaceVisibility(cfg_.surface_id, false);
    ilm_.detachSurface(cfg_.surface_id, cfg_.layer_id);

    if (h_ != NULL && xsv_.xsv_stop != NULL && xsv_.xsv_close != NULL) {
        xsv_.xsv_stop(h_);
        xsv_.xsv_close(h_);
        h_ = NULL;
    }
    pool_.destroy();

    uint64_t rx = 0;
    uint64_t dropped = 0;
    uint64_t idrs = 0;
#ifdef _WIN32
    {
        LockGuard lock(mu_);
        started_ = false;
        visible_ = false;
        ready_ = false;
        seen_first_frame_ = false;
        rx = frames_in_;
        dropped = frames_dropped_;
        idrs = idr_seen_;
    }
#else
    pthread_mutex_lock(&mu_);
    started_ = false;
    visible_ = false;
    ready_ = false;
    seen_first_frame_ = false;
    rx = frames_in_;
    dropped = frames_dropped_;
    idrs = idr_seen_;
    pthread_mutex_unlock(&mu_);
#endif

    CARPLAY_LOG_INFO("video", "stopped (received=%llu dropped=%llu idr=%llu)",
                     static_cast<unsigned long long>(rx),
                     static_cast<unsigned long long>(dropped),
                     static_cast<unsigned long long>(idrs));
}

void EvoVideo::setVisible(bool visible) {
    bool cur_visible = false;
#ifdef _WIN32
    {
        LockGuard lock(mu_);
        if (!started_ || (visible && !ready_)) {
            return;
        }
        cur_visible = visible_;
    }
#else
    pthread_mutex_lock(&mu_);
    if (!started_ || (visible && !ready_)) {
        pthread_mutex_unlock(&mu_);
        return;
    }
    cur_visible = visible_;
    pthread_mutex_unlock(&mu_);
#endif

    if (visible == cur_visible) {
        return;
    }
    if (ilm_.setSurfaceVisibility(cfg_.surface_id, visible)) {
#ifdef _WIN32
        LockGuard lock(mu_);
        visible_ = visible;
#else
        pthread_mutex_lock(&mu_);
        visible_ = visible;
        pthread_mutex_unlock(&mu_);
#endif
    }
}

bool EvoVideo::isVisible() const {
#ifdef _WIN32
    LockGuard lock(mu_);
    return visible_;
#else
    pthread_mutex_lock(&mu_);
    const bool v = visible_;
    pthread_mutex_unlock(&mu_);
    return v;
#endif
}

bool EvoVideo::setOpacity(float opacity) {
    if (opacity < 0.0f) {
        opacity = 0.0f;
    }
    if (opacity > 1.0f) {
        opacity = 1.0f;
    }

    float cur_opacity = 1.0f;
#ifdef _WIN32
    {
        LockGuard lock(mu_);
        if (!started_) {
            return false;
        }
        cur_opacity = opacity_;
    }
#else
    pthread_mutex_lock(&mu_);
    if (!started_) {
        pthread_mutex_unlock(&mu_);
        return false;
    }
    cur_opacity = opacity_;
    pthread_mutex_unlock(&mu_);
#endif

    if (opacity == cur_opacity) {
        return true;
    }
    if (!ilm_.setSurfaceOpacity(cfg_.surface_id, opacity)) {
        return false;
    }
#ifdef _WIN32
    {
        LockGuard lock(mu_);
        opacity_ = opacity;
    }
#else
    pthread_mutex_lock(&mu_);
    opacity_ = opacity;
    pthread_mutex_unlock(&mu_);
#endif
    return true;
}

float EvoVideo::opacity() const {
#ifdef _WIN32
    LockGuard lock(mu_);
    return opacity_;
#else
    pthread_mutex_lock(&mu_);
    const float o = opacity_;
    pthread_mutex_unlock(&mu_);
    return o;
#endif
}

bool EvoVideo::isReady() const {
#ifdef _WIN32
    LockGuard lock(mu_);
    return ready_;
#else
    pthread_mutex_lock(&mu_);
    const bool r = ready_;
    pthread_mutex_unlock(&mu_);
    return r;
#endif
}

bool EvoVideo::isStarted() const {
#ifdef _WIN32
    LockGuard lock(mu_);
    return started_;
#else
    pthread_mutex_lock(&mu_);
    const bool s = started_;
    pthread_mutex_unlock(&mu_);
    return s;
#endif
}

bool EvoVideo::isRunning() const {
#ifdef _WIN32
    LockGuard lock(mu_);
    return running_;
#else
    pthread_mutex_lock(&mu_);
    const bool r = running_;
    pthread_mutex_unlock(&mu_);
    return r;
#endif
}

bool EvoVideo::firstFrameSeen() const {
#ifdef _WIN32
    LockGuard lock(mu_);
    return seen_first_frame_;
#else
    pthread_mutex_lock(&mu_);
    const bool seen = seen_first_frame_;
    pthread_mutex_unlock(&mu_);
    return seen;
#endif
}

uint64_t EvoVideo::framesReceived() const {
#ifdef _WIN32
    LockGuard lock(mu_);
    return frames_in_;
#else
    pthread_mutex_lock(&mu_);
    const uint64_t n = frames_in_;
    pthread_mutex_unlock(&mu_);
    return n;
#endif
}

uint64_t EvoVideo::framesDropped() const {
#ifdef _WIN32
    LockGuard lock(mu_);
    return frames_dropped_;
#else
    pthread_mutex_lock(&mu_);
    const uint64_t n = frames_dropped_;
    pthread_mutex_unlock(&mu_);
    return n;
#endif
}

uint64_t EvoVideo::idrCount() const {
#ifdef _WIN32
    LockGuard lock(mu_);
    return idr_seen_;
#else
    pthread_mutex_lock(&mu_);
    const uint64_t n = idr_seen_;
    pthread_mutex_unlock(&mu_);
    return n;
#endif
}

void EvoVideo::postCodecConfig(const uint8_t* data, size_t len) {
    if (data == NULL || len == 0U) {
        return;
    }
#ifdef _WIN32
    {
        LockGuard lock(mu_);
        codec_cfg_.assign(data, data + len);
        config_sent_ = false;
    }
#else
    pthread_mutex_lock(&mu_);
    codec_cfg_.assign(data, data + len);
    config_sent_ = false;
    pthread_mutex_unlock(&mu_);
#endif
    CARPLAY_LOG_INFO("video", "codec config (SPS/PPS) %zu B cached", len);
}

bool EvoVideo::isIdr(const uint8_t* data, size_t len) {
    if (data == NULL || len < 4U) {
        return false;
    }
    for (size_t i = 0; i + 3U < len; ++i) {
        if (data[i] == 0x00U && data[i + 1U] == 0x00U) {
            size_t j = 0;
            if (data[i + 2U] == 0x01U) {
                j = i + 3U;
            } else if (i + 4U < len && data[i + 2U] == 0x00U && data[i + 3U] == 0x01U) {
                j = i + 4U;
            }
            if (j != 0U && j < len && (data[j] & 0x1FU) == 5U) {
                return true;
            }
        }
    }
    return false;
}

bool EvoVideo::postVideoFrame(const uint8_t* data, size_t len, uint64_t pts) {
    (void)pts;
    if (data == NULL || len == 0U) {
        return false;
    }

#ifdef _WIN32
    (void)data;
    (void)len;
    return false;
#else
    pthread_mutex_lock(&mu_);
    if (!running_ || !started_) {
        pthread_mutex_unlock(&mu_);
        return false;
    }

    const bool idr = isIdr(data, len);
    if (idr) {
        ++idr_seen_;
    }
    const bool prepend_cfg = idr && !config_sent_ && !codec_cfg_.empty();
    const size_t need = len + (prepend_cfg ? codec_cfg_.size() : 0U);

    int bi = pool_.acquireFree();
    if (bi < 0 && cfg_.acquire_timeout_ms > 0) {
        struct timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        const long add_ms = static_cast<long>(cfg_.acquire_timeout_ms);
        deadline.tv_sec += add_ms / 1000L;
        deadline.tv_nsec += (add_ms % 1000L) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec += 1;
            deadline.tv_nsec -= 1000000000L;
        }
        while (bi < 0 && running_) {
            if (pthread_cond_timedwait(&cv_, &mu_, &deadline) == ETIMEDOUT) {
                break;
            }
            bi = pool_.acquireFree();
        }
    }
    if (bi < 0) {
        ++frames_dropped_;
        pthread_mutex_unlock(&mu_);
        return false;
    }

    DmaBufPool::Buf& buf = pool_.at(bi);
    if (need > buf.size) {
        ++frames_dropped_;
        pthread_mutex_unlock(&mu_);
        CARPLAY_LOG_WARN("video", "frame %zu B > dma-buf %u B", need, buf.size);
        return false;
    }

    size_t off = 0;
    if (prepend_cfg) {
        std::memcpy(buf.map, &codec_cfg_[0], codec_cfg_.size());
        off = codec_cfg_.size();
        config_sent_ = true;
    }
    std::memcpy(buf.map + off, data, len);
    buf.in_flight = true;
    const int fd = buf.fd;
    ++frames_in_;
    pthread_mutex_unlock(&mu_);

    const int rc = xsv_.xsv_decode_video_frame(h_, fd, static_cast<uint32_t>(need));
    if (rc < 0) {
        pthread_mutex_lock(&mu_);
        buf.in_flight = false;
        if (prepend_cfg) {
            config_sent_ = false;
        }
        pthread_cond_signal(&cv_);
        pthread_mutex_unlock(&mu_);
        return false;
    }
    return true;
#endif
}

void EvoVideo::eventStub(void* self) {
    static_cast<EvoVideo*>(self)->eventLoop();
}

void EvoVideo::eventLoop() {
    int evt[5];
    while (isRunning()) {
        std::memset(evt, 0, sizeof(evt));
        xsv_.xsv_receive_event(h_, evt, 100);
        switch (evt[0]) {
            case 0:
                break;
            case XSV_EVENT_PLAYING:
                CARPLAY_LOG_INFO("video", "libxsvideo PLAYING; waiting for H.264 frames");
                break;
            case XSV_EVENT_FRAME: {
                bool first = false;
#ifdef _WIN32
                {
                    LockGuard lock(mu_);
                    first = !seen_first_frame_ && frames_in_ > frames_at_start_;
                    if (first) {
                        seen_first_frame_ = true;
                    }
                }
#else
                pthread_mutex_lock(&mu_);
                first = !seen_first_frame_ && frames_in_ > frames_at_start_;
                if (first) {
                    seen_first_frame_ = true;
                }
                pthread_mutex_unlock(&mu_);
#endif
                if (first) {
                    CARPLAY_LOG_INFO("video", "first compositor frame callback after H.264");
                }
                break;
            }
            case XSV_EVENT_DMABUF_COMPLETE: {
#ifndef _WIN32
                pthread_mutex_lock(&mu_);
                const int bi = pool_.find(evt[1]);
                if (bi >= 0) {
                    pool_.at(bi).in_flight = false;
                    pthread_cond_signal(&cv_);
                }
                pthread_mutex_unlock(&mu_);
#endif
                break;
            }
            case XSV_EVENT_STOPPED:
                CARPLAY_LOG_INFO("video", "libxsvideo stream stopped");
                break;
            case XSV_EVENT_ERROR:
                CARPLAY_LOG_ERROR("video", "libxsvideo decode error: %d", evt[1]);
                break;
            case XSV_EVENT_WATCHDOG_ERROR:
                CARPLAY_LOG_ERROR("video", "libxsvideo watchdog error");
                break;
            case XSV_EVENT_ABORTED:
                CARPLAY_LOG_ERROR("video", "libxsvideo stream aborted");
                break;
            default:
                CARPLAY_LOG_DEBUG("video", "libxsvideo event %d (%d)", evt[0], evt[1]);
                break;
        }
    }
}

bool EvoVideo::reconfigureStream(uint32_t new_width, uint32_t new_height) {
    if (new_width == 0U || new_height == 0U || new_width > 1920U || new_height > 1080U ||
        new_width < cfg_.display_width || new_height < cfg_.display_height) {
        return false;
    }
    if (new_width == cfg_.width && new_height == cfg_.height) {
        return true;
    }
    if (!isStarted()) {
        cfg_.width = new_width;
        cfg_.height = new_height;
        if ((new_width > 1280U || new_height > 720U) && cfg_.pool_buf_size < (2U << 20)) {
            cfg_.pool_buf_size = (2U << 20);
        }
        return true;
    }

    CARPLAY_LOG_INFO("video", "reconfiguring stream resolution %ux%u -> %ux%u",
                     cfg_.width, cfg_.height, new_width, new_height);
    if (h_ != NULL &&
        xsvCommand("xsv_configure_stream",
                   xsv_.xsv_configure_stream(h_, new_width, new_height, cfg_.fps)) &&
        xsvCommand("xsv_set_output_dimension",
                   xsv_.xsv_set_output_dimension(h_, new_width, new_height)) &&
        xsvCommand("xsv_update", xsv_.xsv_update(h_))) {
        cfg_.width = new_width;
        cfg_.height = new_height;
        return true;
    }

    const bool was_visible = isVisible();
    stop();
    cfg_.width = new_width;
    cfg_.height = new_height;
    if ((new_width > 1280U || new_height > 720U) && cfg_.pool_buf_size < (2U << 20)) {
        cfg_.pool_buf_size = (2U << 20);
    }
    if (!start()) {
        return false;
    }
    if (was_visible) {
        setVisible(true);
    }
    return true;
}

void EvoVideo::onScreenStreamActive(int32_t type, bool active) {
    if (type != kMainScreenStreamType) {
        return;
    }
    if (active) {
        if (initialized_ && !isStarted()) {
            start();
        }
    } else {
        if (isStarted()) {
            stop();
        }
    }
}

void EvoVideo::onVideoConfig(int32_t type,
                             stream::VideoCodecType codec,
                             const uint8_t* annexb_data,
                             size_t annexb_len,
                             const uint8_t* raw_config,
                             size_t raw_len,
                             float width_px,
                             float height_px) {
    if (type != kMainScreenStreamType) {
        return;
    }
    if (codec != stream::CODEC_H264_AVCC && codec != stream::CODEC_ANNEX_B) {
        CARPLAY_LOG_WARN("video", "unsupported video codec %d", static_cast<int>(codec));
        return;
    }

    if (width_px >= 1.0f && width_px <= 1920.0f &&
        height_px >= 1.0f && height_px <= 1080.0f) {
        const uint32_t new_w = static_cast<uint32_t>(width_px + 0.5f);
        const uint32_t new_h = static_cast<uint32_t>(height_px + 0.5f);
        if (new_w != cfg_.width || new_h != cfg_.height) {
            reconfigureStream(new_w, new_h);
        }
    }

    if (annexb_data != NULL && annexb_len > 0U) {
        postCodecConfig(annexb_data, annexb_len);
    } else if (codec == stream::CODEC_ANNEX_B && raw_config != NULL && raw_len > 0U) {
        postCodecConfig(raw_config, raw_len);
    }
}

void EvoVideo::onVideoFrame(int32_t type,
                            const uint8_t* annexb_data,
                            size_t len,
                            uint64_t sender_nanos,
                            int64_t arrival_mono_nanos) {
    (void)arrival_mono_nanos;
    if (type != kMainScreenStreamType) {
        return;
    }
    postVideoFrame(annexb_data, len, sender_nanos);
}

EvoVideoSink::EvoVideoSink(EvoVideo& video, int32_t stream_type, bool auto_show)
    : video_(video), stream_type_(stream_type), auto_show_(auto_show) {}

void EvoVideoSink::onScreenStreamActive(int32_t type, bool active) {
    if (type != stream_type_) {
        return;
    }
    video_.onScreenStreamActive(kMainScreenStreamType, active);
}

void EvoVideoSink::onVideoConfig(int32_t type,
                                 stream::VideoCodecType codec,
                                 const uint8_t* annexb_data,
                                 size_t annexb_len,
                                 const uint8_t* raw_config,
                                 size_t raw_len,
                                 float width_px,
                                 float height_px) {
    if (type != stream_type_) {
        return;
    }
    video_.onVideoConfig(kMainScreenStreamType, codec, annexb_data, annexb_len,
                         raw_config, raw_len, width_px, height_px);
}

void EvoVideoSink::onVideoFrame(int32_t type,
                                const uint8_t* annexb_data,
                                size_t len,
                                uint64_t sender_nanos,
                                int64_t arrival_mono_nanos) {
    if (type != stream_type_) {
        return;
    }
    video_.onVideoFrame(kMainScreenStreamType, annexb_data, len, sender_nanos, arrival_mono_nanos);
    if (auto_show_ && video_.firstFrameSeen() && !video_.isVisible()) {
        video_.setVisible(true);
    }
}

}  // namespace platform
}  // namespace carplay
