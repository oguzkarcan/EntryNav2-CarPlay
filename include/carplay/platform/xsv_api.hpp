#ifndef CARPLAY_PLATFORM_XSV_API_HPP
#define CARPLAY_PLATFORM_XSV_API_HPP

// Runtime interface for the head unit's /usr/lib/libxsvideo.so.4 (no SDK header ships with it).
// All symbols are resolved at runtime via dlopen/dlsym so the binary carries zero link-time
// DT_NEEDED dependencies on proprietary/vehicle shared libraries.
//
// ARM hard-float ABI note: xsv_configure_stream passes handle/width/height in r0/r1/r2 and
// fps as a single-precision float in s0.

#include <stdint.h>

namespace carplay {
namespace platform {

enum XsvDriverType {
    XSV_TYPE_ANALOG_CAM = 0,
    XSV_TYPE_DIGITAL_CAM = 1,  // H.264 hardware decoder (IVA-HD/DCE) onto an IVI surface
    XSV_TYPE_FILE_PLAYER = 2,
    XSV_TYPE_STATIC_PIC = 3
};

enum XsvEventType {
    XSV_EVENT_PLAYING = 1,          // decoder pipeline reached PLAYING (before any H.264)
    XSV_EVENT_STOPPED = 2,
    XSV_EVENT_ERROR = 5,            // event[1] holds error code
    XSV_EVENT_WATCHDOG_ERROR = 6,
    XSV_EVENT_ABORTED = 7,
    XSV_EVENT_DMABUF_COMPLETE = 9,  // event[1] holds the dma-buf fd now free for reuse
    XSV_EVENT_FRAME = 10            // Wayland frame callback; only event[0] is initialized
};

typedef void* xsv_handle;

/// Function pointer table resolved from libxsvideo.so.4 (or injected in tests).
struct XsvApi {
    typedef xsv_handle (*OpenFn)(int type, uint32_t surface_id, const char* title);
    typedef void (*CloseFn)(xsv_handle h);
    typedef int (*ConfigureStreamFn)(xsv_handle h, uint32_t width, uint32_t height, float fps);
    typedef int (*SetOutputDimensionFn)(xsv_handle h, uint32_t width, uint32_t height);
    typedef int (*SetInputViewportFn)(xsv_handle h, uint32_t x, uint32_t y, uint32_t w, uint32_t hgt);
    typedef int (*DecodeVideoFrameFn)(xsv_handle h, int dmabuf_fd, uint32_t length);
    typedef int (*StartFn)(xsv_handle h);
    typedef int (*StopFn)(xsv_handle h);
    typedef int (*PauseFn)(xsv_handle h);
    typedef int (*UpdateFn)(xsv_handle h);
    typedef int (*EnableFrameEventsFn)(xsv_handle h);
    typedef int (*DisableFrameEventsFn)(xsv_handle h);
    typedef int (*ReceiveEventFn)(xsv_handle h, int* event_out, int timeout_ms);
    typedef int (*GetEventQueueFdFn)(xsv_handle h);

    OpenFn xsv_open;
    CloseFn xsv_close;
    ConfigureStreamFn xsv_configure_stream;
    SetOutputDimensionFn xsv_set_output_dimension;
    SetInputViewportFn xsv_set_input_viewport;
    DecodeVideoFrameFn xsv_decode_video_frame;
    StartFn xsv_start;
    StopFn xsv_stop;
    PauseFn xsv_pause;
    UpdateFn xsv_update;
    EnableFrameEventsFn xsv_enable_frame_events;
    DisableFrameEventsFn xsv_disable_frame_events;
    ReceiveEventFn xsv_receive_event;
    GetEventQueueFdFn xsv_get_event_queue_fd;

    XsvApi()
        : xsv_open(NULL),
          xsv_close(NULL),
          xsv_configure_stream(NULL),
          xsv_set_output_dimension(NULL),
          xsv_set_input_viewport(NULL),
          xsv_decode_video_frame(NULL),
          xsv_start(NULL),
          xsv_stop(NULL),
          xsv_pause(NULL),
          xsv_update(NULL),
          xsv_enable_frame_events(NULL),
          xsv_disable_frame_events(NULL),
          xsv_receive_event(NULL),
          xsv_get_event_queue_fd(NULL) {}

    bool complete() const {
        return xsv_open != NULL &&
               xsv_close != NULL &&
               xsv_configure_stream != NULL &&
               xsv_set_output_dimension != NULL &&
               xsv_set_input_viewport != NULL &&
               xsv_decode_video_frame != NULL &&
               xsv_start != NULL &&
               xsv_stop != NULL &&
               xsv_pause != NULL &&
               xsv_update != NULL &&
               xsv_enable_frame_events != NULL &&
               xsv_disable_frame_events != NULL &&
               xsv_receive_event != NULL &&
               xsv_get_event_queue_fd != NULL;
    }
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_XSV_API_HPP
