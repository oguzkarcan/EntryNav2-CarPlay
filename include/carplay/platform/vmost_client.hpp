#ifndef CARPLAY_PLATFORM_VMOST_CLIENT_HPP
#define CARPLAY_PLATFORM_VMOST_CLIENT_HPP

// Runtime loader and wire structs for BMW's libvmostclient.so.1 (vmostd IPC).
//
// Zero link-time dependency: libvmostclient.so.1 is opened at runtime with dlopen() and
// resolved via dlsym() + memcpy() (avoiding ISO C++ pedantic function-pointer cast warnings).
//
// Callback message layout received from libvmostclient.so.1:
//   +0  uint16_t addr
//   +2  uint8_t  fblock
//   +3  uint8_t  inst
//   +4  uint16_t fkt
//   +8  uint32_t op
//   +12 uint16_t len
//   +16 const uint8_t* data (pointer size: 4 bytes on ARMv7, 8 bytes on x86_64)
//
// Outbound message layout (24 bytes on 32-bit ARM, matching vmostctl):
//   VmostMsgOut

#include <stddef.h>
#include <stdint.h>

#include <string>

namespace carplay {
namespace platform {

static const uint32_t kMostOpGet = 0x1U;
static const uint32_t kMostOpStartResultAck = 0x6U;
static const uint32_t kMostOpError = 0x9U;          // verified: EntryNav2-Android-Auto-0.12.0/platform/evo_wlan.cpp
static const uint32_t kMostOpProcessingAck = 0xAU;  // verified: EntryNav2-Android-Auto-0.12.0/platform/evo_wlan.cpp
static const uint32_t kMostOpStatus = 0xCU;
static const uint32_t kMostOpResultAck = 0xDU;      // verified: EntryNav2-Android-Auto-0.12.0/platform/evo_wlan.cpp
static const uint32_t kMostOpErrorAck = 0xFU;       // verified: EntryNav2-Android-Auto-0.12.0/platform/evo_wlan.cpp

struct VmostMsgView {
    uint16_t addr;
    uint8_t fblock;
    uint8_t inst;
    uint16_t fkt;
    uint32_t op;
    uint16_t len;
    const uint8_t* data;

    VmostMsgView() : addr(0), fblock(0), inst(0), fkt(0), op(0), len(0), data(NULL) {}
};

/// Defensive read of a raw vMOST message buffer handed to the callback.
bool parseVmostMsg(const void* msg, VmostMsgView& out);

/// Outbound vMOST message struct passed to vmostMostMsgSend().
struct VmostMsgOut {
    uint16_t addr;  // 0xFFFF: address resolved by vmostd/IMC
    uint8_t fblock;
    uint8_t inst;
    uint16_t fkt;
    uint16_t reserved;
    uint32_t op;  // 1 = Get
    uint16_t len;
    uint16_t reserved2;
    const uint8_t* data;
    uint32_t channel;  // 0, as vmostctl
};

/// Populates a read-only MOST Get (OpType 1, addr 0xFFFF).
void buildVmostGet(VmostMsgOut& m,
                   uint8_t fblock,
                   uint8_t inst,
                   uint16_t fkt,
                   const uint8_t* data,
                   uint16_t len = 0);

/// Populates a MOST StartResultAck (OpType 6, addr 0xFFFF).
void buildVmostStartResultAck(VmostMsgOut& m,
                              uint8_t fblock,
                              uint8_t inst,
                              uint16_t fkt,
                              const uint8_t* data,
                              uint16_t len);

extern const char kVmostLibrary[];
extern const char* const kVmostFunctions[];
static const size_t kVmostFunctionCount = 7U;

typedef void (*VmostCallback)(void* msg, void* user);

/// Optional in-memory API table for unit/integration tests without a .so file.
struct VmostApi {
    int (*connect)(VmostCallback cb, void* user, int flags);
    int (*shadowRegister)(uint8_t fblock, uint8_t inst);
    int (*shadowDeregister)(uint8_t fblock, uint8_t inst);
    int (*fileDescriptorGet)(int* fd);
    int (*processMessages)();
    int (*disconnect)();
    int (*send)(void* msg);

    VmostApi()
        : connect(NULL),
          shadowRegister(NULL),
          shadowDeregister(NULL),
          fileDescriptorGet(NULL),
          processMessages(NULL),
          disconnect(NULL),
          send(NULL) {}

    bool complete() const {
        return connect != NULL && shadowRegister != NULL && shadowDeregister != NULL &&
               fileDescriptorGet != NULL && processMessages != NULL && disconnect != NULL &&
               send != NULL;
    }
};

class VmostClient {
public:
    enum Load { kLoaded = 0, kNoDaemon = 1, kNoLibrary = 2, kNoSymbols = 3 };

    VmostClient();
    ~VmostClient();

    /// Injects an in-memory API table for tests (NULL clears the override).
    void setApiOverride(const VmostApi* api);

    /// Checks for vmostd socket, opens libvmostclient.so.1 via dlopen, and resolves all 7 symbols.
    /// When an API override is set, loads from it directly without touching disk/dlopen.
    Load load();
    const std::string& error() const { return error_; }
    void unload();

    int (*connect)(VmostCallback, void*, int);
    int (*shadowRegister)(uint8_t, uint8_t);
    int (*shadowDeregister)(uint8_t, uint8_t);
    int (*fileDescriptorGet)(int*);
    int (*processMessages)();
    int (*disconnect)();
    int (*send)(void*);

private:
    VmostClient(const VmostClient&) = delete;
    VmostClient& operator=(const VmostClient&) = delete;

    void clearFunctions();

    void* lib_;
    std::string error_;
    bool has_override_;
    VmostApi override_api_;
};

/// Returns true if the vmostd UNIX socket (or test socket override) exists.
bool isVmostDaemonPresent();

/// Host tests: override the vmostd socket path and client .so path (NULL clears).
void setVmostForTest(const char* socket_path, const char* library_path);

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_VMOST_CLIENT_HPP
