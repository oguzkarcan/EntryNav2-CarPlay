#include "carplay/platform/evo_ilm.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

#include "carplay/platform/evo_process.hpp"
#include "carplay/platform/log.hpp"
#include "carplay/platform/thread.hpp"

namespace carplay {
namespace platform {

namespace {

// Serializes read-modify-write sequences on a layer's render order across threads (video + overlay).
Mutex& orderMutex() {
    static Mutex mu;
    return mu;
}

std::string trimmed(const std::string& s) {
    const size_t b = s.find_first_not_of(" \t\r");
    if (b == std::string::npos) {
        return std::string();
    }
    const size_t e = s.find_last_not_of(" \t\r");
    return s.substr(b, e - b + 1U);
}

std::string u32Hex(uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%x", v);
    return std::string(buf);
}

std::string propertyValue(const std::string& text, const char* name) {
    std::istringstream stream(text);
    std::string line;
    std::string value;
    unsigned found = 0;
    const std::string prefix = std::string("- ") + name + ":";
    while (std::getline(stream, line)) {
        size_t p = line.find_first_not_of(" \t");
        if (p == std::string::npos || line.compare(p, prefix.size(), prefix) != 0) {
            continue;
        }
        p = line.find_first_not_of(" \t", p + prefix.size());
        value = (p == std::string::npos) ? std::string() : line.substr(p);
        const size_t end = value.find_last_not_of(" \t\r");
        if (end != std::string::npos) {
            value.resize(end + 1U);
        } else {
            value.clear();
        }
        ++found;
    }
    return found == 1U ? value : std::string();
}

}  // namespace

EvoIlm::EvoIlm()
    : ctl_("/usr/bin/LayerManagerControl"),
      compositor_conf_("/etc/wayland/compositor.conf") {}

EvoIlm::EvoIlm(const std::string& ctl_path, const std::string& compositor_conf_path)
    : ctl_(ctl_path),
      compositor_conf_(compositor_conf_path) {}

bool EvoIlm::parseRenderOrderFlip(const std::string& conf, bool& top_first) {
    std::istringstream input(conf);
    std::string line;
    unsigned found = 0;
    bool value = false;
    while (std::getline(input, line)) {
        const size_t hash = line.find('#');
        if (hash != std::string::npos) {
            line.erase(hash);
        }
        const size_t eq = line.find('=');
        if (eq == std::string::npos || trimmed(line.substr(0, eq)) != "genivi-flip-renderorder") {
            continue;
        }
        const std::string v = trimmed(line.substr(eq + 1U));
        if (v == "1" || v == "true" || v == "yes" || v == "on") {
            value = true;
        } else if (v == "0" || v == "false" || v == "no" || v == "off") {
            value = false;
        } else {
            return false;
        }
        ++found;
    }
    if (found > 1U) {
        return false;
    }
    top_first = value;
    return true;
}

bool EvoIlm::renderOrderTopFirst(bool& top_first) {
    std::string active_conf = compositor_conf_;
    std::ifstream file(active_conf.c_str(), std::ios::in | std::ios::binary);
    if (!file.is_open() && active_conf == "/etc/wayland/compositor.conf") {
        const char* fallback_conf = "/etc/layermanager/compositor.conf";
        std::ifstream alt(fallback_conf, std::ios::in | std::ios::binary);
        if (alt.is_open()) {
            active_conf = fallback_conf;
            file.open(active_conf.c_str(), std::ios::in | std::ios::binary);
        }
    }
    if (!file.is_open()) {
        // Verified EntryNav2 compositor (/etc/wayland/compositor.conf, 2026-11-21 visit 2) uses
        // genivi-flip-renderorder = 1 (top-first); do not fail closed when absent.
        CARPLAY_LOG_WARN("ilm",
                         "compositor configuration absent/unreadable (%s); using verified "
                         "EntryNav2 fallback top_first=1",
                         compositor_conf_.c_str());
        top_first = true;
        return true;
    }
    std::string text;
    char buf[4096];
    while (file && text.size() <= 65536U) {
        file.read(buf, sizeof(buf));
        text.append(buf, static_cast<size_t>(file.gcount()));
    }
    if (!file.eof() || text.size() > 65536U) {
        CARPLAY_LOG_ERROR("ilm", "compositor configuration unreadable (%s)", active_conf.c_str());
        return false;
    }
    if (!parseRenderOrderFlip(text, top_first)) {
        CARPLAY_LOG_ERROR("ilm", "genivi-flip-renderorder invalid or duplicated in %s",
                          active_conf.c_str());
        return false;
    }
    return true;
}

bool EvoIlm::exec(const std::vector<std::string>& args, std::string* out) {
    std::string shown = ctl_;
    for (size_t i = 0; i < args.size(); ++i) {
        shown += ' ';
        shown += args[i];
    }
    CARPLAY_LOG_DEBUG("ilm", "%s", shown.c_str());

    std::string captured;
    CommandReport report;
    bool ok = runCommand(ctl_, args, captured, 2000, &report);

    const std::string status_prefix = "LayerManagerService returned: ";
    const size_t status_pos = captured.find(status_prefix);
    if (captured.find("Interpreter error:") != std::string::npos ||
        (status_pos != std::string::npos &&
         captured.compare(status_pos + status_prefix.size(), 7U, "success") != 0)) {
        CARPLAY_LOG_WARN("ilm", "refused by CLI: %s", captured.c_str());
        ok = false;
    }
    if (!ok) {
        captured.clear();
        CARPLAY_LOG_WARN("ilm", "command failed or timed out: %s", shown.c_str());
    }
    if (out != NULL) {
        *out = captured;
    }
    return ok;
}

std::string EvoIlm::get(const char* what, uint32_t id) {
    if (what == NULL) {
        return std::string();
    }
    std::vector<std::string> args;
    args.push_back("get");
    args.push_back(what);
    args.push_back(u32Hex(id));
    std::string out;
    if (!exec(args, &out)) {
        out.clear();
    }
    return out;
}

bool EvoIlm::parseRenderOrder(const std::string& txt, std::vector<uint32_t>& out) {
    out.clear();
    const size_t p = txt.find("render order:");
    if (p == std::string::npos) {
        return false;
    }
    const size_t eol = txt.find('\n', p);
    const std::string line =
        txt.substr(p + 13U, eol == std::string::npos ? std::string::npos : eol - p - 13U);

    size_t i = 0;
    while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) {
        ++i;
    }
    bool bracket = (i < line.size() && line[i] == '[');
    const bool bracketed = bracket;
    if (bracket) {
        ++i;
    }

    std::vector<uint32_t> parsed;
    bool comma = false;
    bool native_pair = false;

    for (;;) {
        while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) {
            ++i;
        }
        if (bracket && i < line.size() && line[i] == ']') {
            ++i;
            bracket = false;
            while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) {
                ++i;
            }
            if (i != line.size()) {
                return false;
            }
        }
        if (i == line.size()) {
            if (bracket || (comma && !(native_pair && !bracketed))) {
                return false;
            }
            break;
        }

        native_pair = (line.compare(i, 2U, "0x") != 0 && line.compare(i, 2U, "0X") != 0);
        unsigned long decimal = 0;
        if (native_pair) {
            if (!std::isdigit(static_cast<unsigned char>(line[i]))) {
                return false;
            }
            char* end = NULL;
            errno = 0;
            decimal = std::strtoul(line.c_str() + i, &end, 10);
            if (errno != 0 || decimal > 0xffffffffUL || end == NULL || *end != '(') {
                return false;
            }
            i = static_cast<size_t>(end - line.c_str()) + 1U;
        }

        if (line.compare(i, 2U, "0x") != 0 && line.compare(i, 2U, "0X") != 0) {
            return false;
        }
        char* end = NULL;
        errno = 0;
        const char* begin = line.c_str() + i + 2U;
        const unsigned long value = std::strtoul(begin, &end, 16);
        if (errno != 0 || end == begin || value > 0xffffffffUL ||
            !std::isxdigit(static_cast<unsigned char>(*begin))) {
            return false;
        }
        if (native_pair) {
            if (*end != ')' || decimal != value) {
                return false;
            }
            ++end;
        }

        const uint32_t id = static_cast<uint32_t>(value);
        for (size_t n = 0; n < parsed.size(); ++n) {
            if (parsed[n] == id) {
                return false;
            }
        }
        parsed.push_back(id);

        i = static_cast<size_t>(end - line.c_str());
        comma = false;
        const size_t before_space = i;
        while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) {
            ++i;
        }
        if (i < line.size() && line[i] == ',') {
            ++i;
            comma = true;
        } else if (i < line.size() && i == before_space && !(bracket && line[i] == ']')) {
            return false;
        }
    }

    out.swap(parsed);
    return true;
}

bool EvoIlm::parseResolution(const std::string& txt, int& w, int& h) {
    const size_t p = txt.find("x=");
    const size_t q = txt.find("y=");
    if (p == std::string::npos || q == std::string::npos) {
        return false;
    }
    char* end_w = NULL;
    char* end_h = NULL;
    const long pw = std::strtol(txt.c_str() + p + 2U, &end_w, 10);
    const long ph = std::strtol(txt.c_str() + q + 2U, &end_h, 10);
    if (end_w == txt.c_str() + p + 2U || end_h == txt.c_str() + q + 2U ||
        pw <= 0 || ph <= 0 || pw > 16384 || ph > 16384) {
        return false;
    }
    w = static_cast<int>(pw);
    h = static_cast<int>(ph);
    return true;
}

bool EvoIlm::parseSurfaceList(const std::string& txt, std::vector<uint32_t>& out) {
    out.clear();
    std::istringstream input(txt);
    std::string line;
    unsigned count = 0;
    int used = 0;
    if (!std::getline(input, line) ||
        std::sscanf(line.c_str(), "%u Surface(s): %n", &count, &used) != 1 || used <= 0 ||
        static_cast<size_t>(used) != line.size() || count > 4096U) {
        return false;
    }
    std::vector<uint32_t> ids;
    while (std::getline(input, line)) {
        if (line.find_first_not_of(" \t\r") == std::string::npos) {
            continue;
        }
        unsigned long dec = 0;
        unsigned long hex = 0;
        used = 0;
        if (std::sscanf(line.c_str(), "- Surface %lu (0x%lx) %n", &dec, &hex, &used) != 2 ||
            used <= 0 || static_cast<size_t>(used) != line.size() || dec != hex ||
            dec > 0xffffffffUL) {
            return false;
        }
        const uint32_t id = static_cast<uint32_t>(dec);
        if (std::find(ids.begin(), ids.end(), id) != ids.end()) {
            return false;
        }
        ids.push_back(id);
    }
    if (ids.size() != count) {
        return false;
    }
    out.swap(ids);
    return true;
}

bool EvoIlm::validLayerGeometry(const std::string& txt, uint32_t w, uint32_t h) {
    if (propertyValue(txt, "visibility") != "1" ||
        propertyValue(txt, "opacity") != "1" ||
        propertyValue(txt, "orientation") != "0 (up is top)") {
        return false;
    }
    const char* regions[2] = {"source region", "destination region"};
    for (unsigned i = 0; i < 2U; ++i) {
        const std::string region = propertyValue(txt, regions[i]);
        int x = 0;
        int y = 0;
        int rw = 0;
        int rh = 0;
        int used = 0;
        if (std::sscanf(region.c_str(), "x=%d, y=%d, w=%d, h=%d%n", &x, &y, &rw, &rh, &used) != 4 ||
            used <= 0 || static_cast<size_t>(used) != region.size() || x != 0 || y != 0 ||
            rw <= 0 || rh <= 0 || static_cast<uint32_t>(rw) != w ||
            static_cast<uint32_t>(rh) != h) {
            return false;
        }
    }
    return true;
}

bool EvoIlm::validateTarget(uint32_t surface_id,
                            uint32_t layer_id,
                            uint32_t w,
                            uint32_t h,
                            bool require_free) {
    if (surface_id == 0U || w == 0U || h == 0U) {
        return false;
    }
    const std::string screen = get("screen", 0U);
    int sw = 0;
    int sh = 0;
    std::vector<uint32_t> ids;
    if (!parseResolution(screen, sw, sh) ||
        static_cast<uint32_t>(sw) != w || static_cast<uint32_t>(sh) != h ||
        !parseRenderOrder(screen, ids) ||
        std::find(ids.begin(), ids.end(), layer_id) == ids.end()) {
        return false;
    }
    const std::string target = get("layer", layer_id);
    if (!validLayerGeometry(target, w, h) || !parseRenderOrder(target, ids)) {
        return false;
    }
    if (require_free && std::find(ids.begin(), ids.end(), surface_id) != ids.end()) {
        return false;
    }
    std::vector<std::string> args;
    args.push_back("get");
    args.push_back("surfaces");
    std::string inventory;
    if (!exec(args, &inventory) || !parseSurfaceList(inventory, ids)) {
        return false;
    }
    const bool present = std::find(ids.begin(), ids.end(), surface_id) != ids.end();
    return require_free ? !present : present;
}

bool EvoIlm::screenSize(uint32_t& w, uint32_t& h) {
    int sw = 0;
    int sh = 0;
    if (!parseResolution(get("screen", 0U), sw, sh) || sw <= 0 || sh <= 0) {
        return false;
    }
    w = static_cast<uint32_t>(sw);
    h = static_cast<uint32_t>(sh);
    return true;
}

bool EvoIlm::surfaceAbsent(uint32_t surface_id) {
    std::vector<std::string> args;
    args.push_back("get");
    args.push_back("surfaces");
    std::string text;
    std::vector<uint32_t> ids;
    return exec(args, &text) && parseSurfaceList(text, ids) &&
           std::find(ids.begin(), ids.end(), surface_id) == ids.end();
}

bool EvoIlm::surfacesOnLayer(uint32_t layer_id, std::vector<uint32_t>& out) {
    return parseRenderOrder(get("layer", layer_id), out);
}

bool EvoIlm::surfaceExists(uint32_t surface_id) {
    const std::string out = get("surface", surface_id);
    return out.find("resolution") != std::string::npos ||
           out.find("visibility") != std::string::npos;
}

bool EvoIlm::setSurfaceVisibility(uint32_t surface_id, bool visible) {
    std::vector<std::string> args;
    args.push_back("set");
    args.push_back("surface");
    args.push_back(u32Hex(surface_id));
    args.push_back("visibility");
    args.push_back(visible ? "1" : "0");
    return exec(args, NULL);
}

bool EvoIlm::setSurfaceOpacity(uint32_t surface_id, float opacity) {
    if (opacity < 0.0f) {
        opacity = 0.0f;
    }
    if (opacity > 1.0f) {
        opacity = 1.0f;
    }
    char val[16];
    std::snprintf(val, sizeof(val), "%.2f", static_cast<double>(opacity));
    std::vector<std::string> args;
    args.push_back("set");
    args.push_back("surface");
    args.push_back(u32Hex(surface_id));
    args.push_back("opacity");
    args.push_back(val);
    return exec(args, NULL);
}

bool EvoIlm::setRegion(uint32_t surface_id,
                       const char* which,
                       uint32_t x,
                       uint32_t y,
                       uint32_t w,
                       uint32_t h) {
    char v[4][16];
    std::snprintf(v[0], sizeof(v[0]), "%u", x);
    std::snprintf(v[1], sizeof(v[1]), "%u", y);
    std::snprintf(v[2], sizeof(v[2]), "%u", w);
    std::snprintf(v[3], sizeof(v[3]), "%u", h);
    std::vector<std::string> args;
    args.push_back("set");
    args.push_back("surface");
    args.push_back(u32Hex(surface_id));
    args.push_back(which);
    args.push_back("region");
    for (int i = 0; i < 4; ++i) {
        args.push_back(v[i]);
    }
    return exec(args, NULL);
}

bool EvoIlm::attachSurface(uint32_t surface_id, uint32_t layer_id, uint32_t w, uint32_t h) {
    bool top_first = false;
    if (!renderOrderTopFirst(top_first)) {
        return false;
    }
    LockGuard lock(orderMutex());
    std::vector<uint32_t> order;
    if (!surfacesOnLayer(layer_id, order)) {
        return false;
    }
    if (!setSurfaceVisibility(surface_id, false)) {
        return false;
    }
    if (!setRegion(surface_id, "source", 0U, 0U, w, h) ||
        !setRegion(surface_id, "destination", 0U, 0U, w, h)) {
        return false;
    }
    bool present = false;
    for (size_t i = 0; i < order.size(); ++i) {
        if (order[i] == surface_id) {
            present = true;
            break;
        }
    }
    if (!present) {
        if (top_first) {
            order.insert(order.begin(), surface_id);
        } else {
            order.push_back(surface_id);
        }
    }
    CARPLAY_LOG_INFO("ilm",
                     "compositor genivi-flip-renderorder=%d: surface 0x%x placed %s of layer 0x%x",
                     top_first ? 1 : 0, surface_id,
                     top_first ? "at head" : "at end", layer_id);
    return setRenderOrder(layer_id, order) && setSurfaceVisibility(surface_id, false);
}

bool EvoIlm::attachOverlay(uint32_t surface_id,
                           uint32_t layer_id,
                           uint32_t x,
                           uint32_t y,
                           uint32_t w,
                           uint32_t h) {
    bool top_first = false;
    if (surface_id == 0U || w == 0U || h == 0U || w > 1920U || h > 1080U || x > 1920U ||
        y > 1080U || !renderOrderTopFirst(top_first)) {
        return false;
    }
    LockGuard lock(orderMutex());
    std::vector<uint32_t> order;
    if (!surfacesOnLayer(layer_id, order)) {
        return false;
    }
    if (!setSurfaceVisibility(surface_id, false) ||
        !setRegion(surface_id, "source", 0U, 0U, w, h) ||
        !setRegion(surface_id, "destination", x, y, w, h)) {
        return false;
    }
    return raiseLocked(surface_id, layer_id, top_first);
}

bool EvoIlm::raiseSurface(uint32_t surface_id, uint32_t layer_id) {
    bool top_first = false;
    if (!renderOrderTopFirst(top_first)) {
        return false;
    }
    LockGuard lock(orderMutex());
    return raiseLocked(surface_id, layer_id, top_first);
}

bool EvoIlm::raiseLocked(uint32_t surface_id, uint32_t layer_id, bool top_first) {
    std::vector<uint32_t> order;
    if (!surfacesOnLayer(layer_id, order)) {
        return false;
    }
    if (!order.empty() && (top_first ? order.front() : order.back()) == surface_id) {
        return true;
    }
    order.erase(std::remove(order.begin(), order.end(), surface_id), order.end());
    if (top_first) {
        order.insert(order.begin(), surface_id);
    } else {
        order.push_back(surface_id);
    }
    return setRenderOrder(layer_id, order);
}

bool EvoIlm::setRenderOrder(uint32_t layer_id, const std::vector<uint32_t>& order) {
    std::vector<std::string> args;
    args.push_back("set");
    args.push_back("layer");
    args.push_back(u32Hex(layer_id));
    args.push_back("render");
    args.push_back("order");
    std::string list;
    for (size_t i = 0; i < order.size(); ++i) {
        if (i > 0U) {
            list += ',';
        }
        list += u32Hex(order[i]);
    }
    if (!list.empty()) {
        args.push_back(list);
    }
    if (!exec(args, NULL)) {
        return false;
    }
    std::vector<uint32_t> actual;
    if (!surfacesOnLayer(layer_id, actual) || actual != order) {
        CARPLAY_LOG_ERROR("ilm", "surface render order not confirmed after set layer 0x%x",
                          layer_id);
        return false;
    }
    CARPLAY_LOG_INFO("ilm", "surface render order confirmed (%u surfaces)",
                     static_cast<unsigned>(order.size()));
    return true;
}

bool EvoIlm::detachSurface(uint32_t surface_id, uint32_t layer_id) {
    LockGuard lock(orderMutex());
    std::vector<uint32_t> order;
    if (!surfacesOnLayer(layer_id, order)) {
        return false;
    }
    if (std::find(order.begin(), order.end(), surface_id) == order.end()) {
        return true;
    }
    order.erase(std::remove(order.begin(), order.end(), surface_id), order.end());
    return setRenderOrder(layer_id, order);
}

}  // namespace platform
}  // namespace carplay
