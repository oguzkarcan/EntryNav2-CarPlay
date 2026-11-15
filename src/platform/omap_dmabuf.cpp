#include "carplay/platform/omap_dmabuf.hpp"

#include <cstring>

#include "carplay/platform/log.hpp"

#ifndef _WIN32
#include <dlfcn.h>
#include <unistd.h>
#endif

namespace carplay {
namespace platform {

namespace {

#ifndef _WIN32
template <typename Fn>
bool loadDlsym(void* handle, const char* symbol, Fn& out) {
    dlerror();
    void* sym = dlsym(handle, symbol);
    const char* err = dlerror();
    if (err != NULL || sym == NULL) {
        CARPLAY_LOG_ERROR("dmabuf", "dlsym(%s) failed: %s", symbol,
                          err != NULL ? err : "NULL symbol");
        return false;
    }
    std::memcpy(&out, &sym, sizeof(out));
    return true;
}
#endif

void closeFd(int fd) {
    if (fd < 0) {
        return;
    }
#ifndef _WIN32
    ::close(fd);
#endif
}

}  // namespace

DmaBufPool::DmaBufPool()
    : drm_lib_path_("libdrm.so.2"),
      omap_lib_path_("libdrm_omap.so.1"),
      drm_handle_(NULL),
      omap_handle_(NULL),
      use_test_api_(false),
      drm_fd_(-1),
      dev_(NULL) {}

DmaBufPool::~DmaBufPool() {
    destroy();
}

void DmaBufPool::setDrmLibrariesForTest(const char* drm_lib, const char* omap_lib) {
    destroy();
    use_test_api_ = false;
    api_ = DrmOmapApi();
    drm_lib_path_ = (drm_lib != NULL && *drm_lib != '\0') ? drm_lib : "libdrm.so.2";
    omap_lib_path_ = (omap_lib != NULL && *omap_lib != '\0') ? omap_lib : "libdrm_omap.so.1";
}

void DmaBufPool::setApiForTest(const DrmOmapApi& api) {
    destroy();
    api_ = api;
    use_test_api_ = true;
}

void DmaBufPool::clearApiForTest() {
    destroy();
    api_ = DrmOmapApi();
    use_test_api_ = false;
}

bool DmaBufPool::loadLibraries() {
    if (use_test_api_) {
        if (!api_.complete()) {
            CARPLAY_LOG_ERROR("dmabuf", "injected DrmOmapApi is incomplete");
            return false;
        }
        return true;
    }

#ifdef _WIN32
    CARPLAY_LOG_ERROR("dmabuf", "dlopen of DRM/OMAP libraries is not supported on Windows");
    return false;
#else
    unloadLibraries();
    api_ = DrmOmapApi();

    drm_handle_ = dlopen(drm_lib_path_.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (drm_handle_ == NULL) {
        CARPLAY_LOG_ERROR("dmabuf", "dlopen(%s) failed: %s", drm_lib_path_.c_str(), dlerror());
        return false;
    }
    omap_handle_ = dlopen(omap_lib_path_.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (omap_handle_ == NULL) {
        CARPLAY_LOG_ERROR("dmabuf", "dlopen(%s) failed: %s", omap_lib_path_.c_str(), dlerror());
        unloadLibraries();
        return false;
    }

    const bool ok =
        loadDlsym(drm_handle_, "drmOpen", api_.drmOpen) &&
        loadDlsym(drm_handle_, "drmClose", api_.drmClose) &&
        loadDlsym(omap_handle_, "omap_device_new", api_.omap_device_new) &&
        loadDlsym(omap_handle_, "omap_device_del", api_.omap_device_del) &&
        loadDlsym(omap_handle_, "omap_bo_new", api_.omap_bo_new) &&
        loadDlsym(omap_handle_, "omap_bo_del", api_.omap_bo_del) &&
        loadDlsym(omap_handle_, "omap_bo_dmabuf", api_.omap_bo_dmabuf) &&
        loadDlsym(omap_handle_, "omap_bo_map", api_.omap_bo_map);

    if (!ok || !api_.complete()) {
        unloadLibraries();
        return false;
    }
    return true;
#endif
}

void DmaBufPool::unloadLibraries() {
    if (!use_test_api_) {
        api_ = DrmOmapApi();
    }
#ifndef _WIN32
    if (omap_handle_ != NULL) {
        dlclose(omap_handle_);
        omap_handle_ = NULL;
    }
    if (drm_handle_ != NULL) {
        dlclose(drm_handle_);
        drm_handle_ = NULL;
    }
#endif
}

bool DmaBufPool::init(unsigned count, uint32_t buf_size) {
    destroy();
    if (count == 0U || buf_size == 0U) {
        return false;
    }
    if (!loadLibraries()) {
        return false;
    }

    drm_fd_ = api_.drmOpen("omapdrm", NULL);
    if (drm_fd_ < 0) {
        CARPLAY_LOG_ERROR("dmabuf", "drmOpen(omapdrm) failed");
        unloadLibraries();
        return false;
    }

    dev_ = api_.omap_device_new(drm_fd_);
    if (dev_ == NULL) {
        CARPLAY_LOG_ERROR("dmabuf", "omap_device_new failed");
        api_.drmClose(drm_fd_);
        drm_fd_ = -1;
        unloadLibraries();
        return false;
    }

    bufs_.reserve(count);
    for (unsigned i = 0; i < count; ++i) {
        Buf b;
        b.bo = api_.omap_bo_new(dev_, buf_size, kOmapBoWriteCombine);
        if (b.bo == NULL) {
            CARPLAY_LOG_ERROR("dmabuf", "omap_bo_new(%u) failed at buffer %u", buf_size, i);
            destroy();
            return false;
        }
        b.fd = api_.omap_bo_dmabuf(b.bo);
        b.map = static_cast<uint8_t*>(api_.omap_bo_map(b.bo));
        b.size = buf_size;
        b.in_flight = false;
        if (b.fd < 0 || b.map == NULL) {
            CARPLAY_LOG_ERROR("dmabuf", "dmabuf/map unavailable at buffer %u", i);
            closeFd(b.fd);
            api_.omap_bo_del(b.bo);
            destroy();
            return false;
        }
        bufs_.push_back(b);
    }

    CARPLAY_LOG_INFO("dmabuf", "dma-buf pool: %u buffers of %u B (omapdrm fd %d)",
                     count, buf_size, drm_fd_);
    return true;
}

void DmaBufPool::destroy() {
    for (size_t i = 0; i < bufs_.size(); ++i) {
        closeFd(bufs_[i].fd);
        if (bufs_[i].bo != NULL && api_.omap_bo_del != NULL) {
            api_.omap_bo_del(bufs_[i].bo);
        }
    }
    bufs_.clear();
    if (dev_ != NULL && api_.omap_device_del != NULL) {
        api_.omap_device_del(dev_);
        dev_ = NULL;
    }
    if (drm_fd_ >= 0 && api_.drmClose != NULL) {
        api_.drmClose(drm_fd_);
        drm_fd_ = -1;
    }
    unloadLibraries();
}

int DmaBufPool::acquireFree() {
    for (size_t i = 0; i < bufs_.size(); ++i) {
        if (!bufs_[i].in_flight) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

int DmaBufPool::find(int fd) const {
    for (size_t i = 0; i < bufs_.size(); ++i) {
        if (bufs_[i].fd == fd) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

}  // namespace platform
}  // namespace carplay
