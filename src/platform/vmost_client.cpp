#include "carplay/platform/vmost_client.hpp"

#include <string.h>

#ifndef _WIN32
#include <dlfcn.h>
#include <sys/stat.h>
#endif

namespace carplay {
namespace platform {

const char kVmostLibrary[] = "libvmostclient.so.1";

const char* const kVmostFunctions[] = {
    "vmostConnect",
    "vmostFblockShadowRegister",
    "vmostFblockShadowDeregister",
    "vmostFileDescriptorGet",
    "vmostProcessMessages",
    "vmostDisconnect",
    "vmostMostMsgSend"
};

namespace {

std::string g_test_socket;
std::string g_test_library;

#ifndef _WIN32
bool isSocketPath(const char* path) {
    if (path == NULL || *path == '\0') {
        return false;
    }
    struct stat st;
    return stat(path, &st) == 0 && S_ISSOCK(st.st_mode);
}

bool daemonPresent() {
    if (!g_test_socket.empty()) {
        return isSocketPath(g_test_socket.c_str());
    }
    return isSocketPath("/var/run/vmost_sockstream") || isSocketPath("/tmp/vmost_sockstream");
}

template <typename Fn>
bool resolveSymbol(void* lib, const char* name, Fn& fn) {
    if (sizeof(Fn) != sizeof(void*)) {
        return false;
    }
    void* p = dlsym(lib, name);
    if (p == NULL) {
        fn = NULL;
        return false;
    }
    memcpy(&fn, &p, sizeof(p));
    return true;
}
#endif

}  // namespace

void setVmostForTest(const char* socket_path, const char* library_path) {
    g_test_socket = socket_path != NULL ? socket_path : "";
    g_test_library = library_path != NULL ? library_path : "";
}

bool parseVmostMsg(const void* msg, VmostMsgView& out) {
    if (msg == NULL) {
        return false;
    }
    const uint8_t* b = static_cast<const uint8_t*>(msg);
    memcpy(&out.addr, b + 0, sizeof(out.addr));
    out.fblock = b[2];
    out.inst = b[3];
    memcpy(&out.fkt, b + 4, sizeof(out.fkt));
    memcpy(&out.op, b + 8, sizeof(out.op));
    memcpy(&out.len, b + 12, sizeof(out.len));
    memcpy(&out.data, b + 16, sizeof(out.data));
    if (out.len > 4096U || (out.len > 0U && out.data == NULL) || out.op > 0xFU) {
        return false;
    }
    return true;
}

void buildVmostGet(VmostMsgOut& m,
                   uint8_t fblock,
                   uint8_t inst,
                   uint16_t fkt,
                   const uint8_t* data,
                   uint16_t len) {
    memset(&m, 0, sizeof(m));
    m.addr = 0xFFFFU;
    m.fblock = fblock;
    m.inst = inst;
    m.fkt = fkt;
    m.op = kMostOpGet;
    m.len = len;
    m.data = data;
    m.channel = 0U;
}

VmostClient::VmostClient()
    : connect(NULL),
      shadowRegister(NULL),
      shadowDeregister(NULL),
      fileDescriptorGet(NULL),
      processMessages(NULL),
      disconnect(NULL),
      send(NULL),
      lib_(NULL),
      has_override_(false) {}

VmostClient::~VmostClient() {
    // Intentionally does not dlclose() automatically on destruction: libvmostclient.so.1 keeps
    // GLib static state across the process lifetime unless unload() is called explicitly.
}

void VmostClient::clearFunctions() {
    connect = NULL;
    shadowRegister = NULL;
    shadowDeregister = NULL;
    fileDescriptorGet = NULL;
    processMessages = NULL;
    disconnect = NULL;
    send = NULL;
}

void VmostClient::setApiOverride(const VmostApi* api) {
    if (api == NULL) {
        has_override_ = false;
        override_api_ = VmostApi();
    } else {
        has_override_ = true;
        override_api_ = *api;
    }
}

VmostClient::Load VmostClient::load() {
    error_.clear();
    clearFunctions();

    if (has_override_) {
        if (!override_api_.complete()) {
            error_ = "incomplete test VmostApi override";
            return kNoSymbols;
        }
        connect = override_api_.connect;
        shadowRegister = override_api_.shadowRegister;
        shadowDeregister = override_api_.shadowDeregister;
        fileDescriptorGet = override_api_.fileDescriptorGet;
        processMessages = override_api_.processMessages;
        disconnect = override_api_.disconnect;
        send = override_api_.send;
        return kLoaded;
    }

#ifdef _WIN32
    error_ = "vmostd IPC is not available on Windows";
    return kNoDaemon;
#else
    if (!daemonPresent()) {
        return kNoDaemon;
    }
    const char* path = !g_test_library.empty() ? g_test_library.c_str() : kVmostLibrary;
    lib_ = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (lib_ == NULL) {
        const char* why = dlerror();
        error_ = why != NULL ? why : "";
        return kNoLibrary;
    }

    bool complete = resolveSymbol(lib_, kVmostFunctions[0], connect);
    complete &= resolveSymbol(lib_, kVmostFunctions[1], shadowRegister);
    complete &= resolveSymbol(lib_, kVmostFunctions[2], shadowDeregister);
    complete &= resolveSymbol(lib_, kVmostFunctions[3], fileDescriptorGet);
    complete &= resolveSymbol(lib_, kVmostFunctions[4], processMessages);
    complete &= resolveSymbol(lib_, kVmostFunctions[5], disconnect);
    complete &= resolveSymbol(lib_, kVmostFunctions[6], send);
    if (!complete) {
        unload();
        return kNoSymbols;
    }
    return kLoaded;
#endif
}

void VmostClient::unload() {
    clearFunctions();
#ifndef _WIN32
    if (lib_ != NULL) {
        dlclose(lib_);
        lib_ = NULL;
    }
#endif
}

}  // namespace platform
}  // namespace carplay
