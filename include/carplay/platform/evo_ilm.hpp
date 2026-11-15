#ifndef CARPLAY_PLATFORM_EVO_ILM_HPP
#define CARPLAY_PLATFORM_EVO_ILM_HPP

// Drives the GENIVI IVI LayerManager through /usr/bin/LayerManagerControl via posix_spawnp
// (never a shell). Never modifies the screen render order; preserves the relative order of
// existing surfaces on a layer; verifies layer render order via read-back after every update.

#include <stdint.h>

#include <string>
#include <vector>

namespace carplay {
namespace platform {

static const uint32_t kDefaultCarPlayLayerId = 0x80000000U;
static const uint32_t kDefaultCarPlaySurfaceId = 0x7ec00001U;
static const uint32_t kDefaultOverlaySurfaceId = 0x7ec00002U;

class EvoIlm {
public:
    EvoIlm();
    EvoIlm(const std::string& ctl_path, const std::string& compositor_conf_path);

    /// Reads `genivi-flip-renderorder` from the Wayland compositor configuration.
    /// When `top_first == true`, the first entry in a render-order list is on top.
    /// Fails closed (returns false) if the file cannot be read or the key is invalid/duplicated.
    bool renderOrderTopFirst(bool& top_first);

    /// Attaches `surface_id` to `layer_id` hidden, with source and destination regions (0,0,w,h).
    /// Existing surfaces keep their relative order; `surface_id` is placed on top according to
    /// `renderOrderTopFirst()`. Refuses before issuing any `set` command if direction or current
    /// layer render order cannot be established.
    bool attachSurface(uint32_t surface_id, uint32_t layer_id, uint32_t w, uint32_t h);

    /// Attaches an overlay `surface_id` above all surfaces on `layer_id` with source (0,0,w,h)
    /// and destination (x,y,w,h), initially hidden.
    bool attachOverlay(uint32_t surface_id,
                       uint32_t layer_id,
                       uint32_t x,
                       uint32_t y,
                       uint32_t w,
                       uint32_t h);

    /// Moves `surface_id` back to the top of `layer_id` while preserving the relative order of all
    /// other surfaces on the layer. No-op (returns true) if `surface_id` is already on top.
    bool raiseSurface(uint32_t surface_id, uint32_t layer_id);

    bool setSurfaceVisibility(uint32_t surface_id, bool visible);
    bool setSurfaceOpacity(uint32_t surface_id, float opacity);

    /// Removes `surface_id` from `layer_id` while preserving the relative order of remaining surfaces.
    bool detachSurface(uint32_t surface_id, uint32_t layer_id);

    // ---- Read-only queries ----
    bool surfacesOnLayer(uint32_t layer_id, std::vector<uint32_t>& out);
    bool surfaceExists(uint32_t surface_id);
    bool surfaceAbsent(uint32_t surface_id);

    /// Validates that screen 0 matches `(w, h)`, contains `layer_id`, `layer_id` is visible with
    /// full-screen geometry `(0,0,w,h)`, and `surface_id` is free (when `require_free == true`) or
    /// present (when `require_free == false`).
    bool validateTarget(uint32_t surface_id,
                        uint32_t layer_id,
                        uint32_t w,
                        uint32_t h,
                        bool require_free = true);

    bool screenSize(uint32_t& w, uint32_t& h);
    std::string get(const char* what, uint32_t id);

    // ---- Pure parsers (unit-testable without spawning processes) ----
    static bool parseRenderOrder(const std::string& txt, std::vector<uint32_t>& out);
    static bool parseResolution(const std::string& txt, int& w, int& h);
    static bool parseSurfaceList(const std::string& txt, std::vector<uint32_t>& out);
    static bool validLayerGeometry(const std::string& txt, uint32_t w, uint32_t h);
    static bool parseRenderOrderFlip(const std::string& conf, bool& top_first);

private:
    bool exec(const std::vector<std::string>& args, std::string* out);
    bool setRenderOrder(uint32_t layer_id, const std::vector<uint32_t>& order);
    bool setRegion(uint32_t surface_id,
                   const char* which,
                   uint32_t x,
                   uint32_t y,
                   uint32_t w,
                   uint32_t h);
    bool raiseLocked(uint32_t surface_id, uint32_t layer_id, bool top_first);

    std::string ctl_;
    std::string compositor_conf_;
};

}  // namespace platform
}  // namespace carplay

#endif  // CARPLAY_PLATFORM_EVO_ILM_HPP
