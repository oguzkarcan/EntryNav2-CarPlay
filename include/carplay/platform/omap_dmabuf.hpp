#ifndef CARPLAY_PLATFORM_OMAP_DMABUF_HPP
#define CARPLAY_PLATFORM_OMAP_DMABUF_HPP

// OMAP dma-buf pool that carries Annex-B H.264 frames to libxsvideo.
// Loads libdrm.so.2 and libdrm_omap.so.1 at runtime via dlopen/dlsym so the binary has
// zero link-time DT_NEEDED dependencies on proprietary/vehicle shared libraries.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

struct omap_device;
struct omap_bo;

namespace carplay {
namespace platform {

static const uint32_t kOmapBoWriteCombine = 0x00000002U;

/// Runtime-resolved or test-injected function table for libdrm + libdrm_omap.
struct DrmOmapApi {
    typedef int (*DrmOpenFn)(const char* name, const char* busid);
    typedef void (*DrmCloseFn)(int fd);
    typedef struct omap_device* (*OmapDeviceNewFn)(int fd);
    typedef void (*OmapDeviceDelFn)(struct omap_device* dev);
    typedef struct omap_bo* (*OmapBoNewFn)(struct omap_device* dev, uint32_t size, uint32_t flags);
    typedef void (*OmapBoDelFn)(struct omap_bo* bo);
    typedef int (*OmapBoDmabufFn)(struct omap_bo* bo);
    typedef void* (*OmapBoMapFn)(struct omap_bo* bo);

    DrmOpenFn drmOpen;
    DrmCloseFn drmClose;
    OmapDeviceNewFn omap_device_new;
    OmapDeviceDelFn omap_device_del;
    OmapBoNewFn omap_bo_new;
    OmapBoDelFn omap_bo_del;
    OmapBoDmabufFn omap_bo_dmabuf;
    OmapBoMapFn omap_bo_map;

    DrmOmapApi()
        : drmOpen(NULL),
          drmClose(NULL),
          omap_device_new(NULL),
          omap_device_del(NULL),
          omap_bo_new(NULL),
          omap_bo_del(NULL),
          omap_bo_dmabuf(NULL),
          omap_bo_map(NULL) {}

    bool complete() const {
        return drmOpen != NULL && drmClose != NULL &&
               omap_device_new != NULL && omap_device_del != NULL &&
               omap_bo_new != NULL && omap_bo_del != NULL &&
               omap_bo_dmabuf != NULL && omap_bo_map != NULL;
    }
};

class DmaBufPool {
public:
    struct Buf {
        struct omap_bo* bo;
        int fd;
        uint8_t* map;
        uint32_t size;
        bool in_flight;

        Buf() : bo(NULL), fd(-1), map(NULL), size(0), in_flight(false) {}
    };

    DmaBufPool();
    ~DmaBufPool();

    /// Overrides the shared-library names/paths opened by dlopen (defaults: "libdrm.so.2",
    /// "libdrm_omap.so.1"). Clears any previously injected test function table.
    void setDrmLibrariesForTest(const char* drm_lib, const char* omap_lib);

    /// Injects a mock function table for unit tests (bypasses dlopen).
    void setApiForTest(const DrmOmapApi& api);
    void clearApiForTest();
    bool hasTestApi() const { return use_test_api_; }

    /// Loads libraries (unless a test API is injected), opens "omapdrm", and allocates `count`
    /// write-combine buffers of `buf_size` bytes each.
    bool init(unsigned count, uint32_t buf_size);
    void destroy();

    /// Index of a free buffer, or -1 if all buffers are in flight (or pool is empty).
    int acquireFree();
    Buf& at(int i) { return bufs_[static_cast<size_t>(i)]; }
    const Buf& at(int i) const { return bufs_[static_cast<size_t>(i)]; }
    int find(int fd) const;
    size_t size() const { return bufs_.size(); }

private:
    DmaBufPool(const DmaBufPool&) = delete;
    DmaBufPool& operator=(const DmaBufPool&) = delete;

    bool loadLibraries();
    void unloadLibraries();

    std::string drm_lib_path_;
    std::string omap_lib_path_;
    void* drm_handle_;
    void* omap_handle_;
    DrmOmapApi api_;
    bool use_test_api_;

    int drm_fd_;
    struct omap_device* dev_;
    std::vector<Buf> bufs_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_OMAP_DMABUF_HPP
