# Sysroot Soname & Symbol Verification

EntryNav2-CarPlay builds with zero link-time `DT_NEEDED` dependencies on proprietary BMW or target vehicle libraries (`docs/BUILD.md` §4). Instead, platform modules resolve shared libraries via `dlopen()` and symbols via `dlsym()` at runtime. Because wrong sonames or misspelled/unexported symbol names only fail on the car, `scripts/ci/check_sysroot_symbols.sh` verifies both:

1. **Source-to-manifest sync:** Automatically extracts `dlopen()` / `dlsym()` usage, helper wrappers, string arrays (such as `kVmostFunctions[]`), and `lib*.so*` literals from C++ sources under `src/` and `include/`, failing if any file, soname, or symbol disagrees with `scripts/ci/sysroot_symbols.txt`.
2. **Sysroot ELF verification:** Given an extracted head-unit rootfs (`SYSROOT`), resolves every soname candidate across `lib`, `usr/lib`, `usr/local/lib`, and `opt/hmi/lib` (mapping absolute and relative symlinks strictly inside `SYSROOT` and reporting dangling targets) and checks that every symbol is exported in `.dynsym` (via `readelf -W --dyn-syms`, falling back to `nm -D --defined-only`; versioned symbols such as `snd_pcm_open@@ALSA_0.9` are accepted).

## Usage

```sh
# Default: checks source <-> manifest sync, then checks ../EntryNav2-CarPlay-Assets/sysroot
# (skips with exit 0 if that directory does not exist)
sh scripts/ci/check_sysroot_symbols.sh

# Explicit sysroot path
SYSROOT=/path/to/sysroot sh scripts/ci/check_sysroot_symbols.sh

# Sync check only (no sysroot needed)
sh scripts/ci/check_sysroot_symbols.sh --sync-only

# Built-in self-test (builds tiny .so files with the host C compiler in a temp dir)
sh scripts/ci/check_sysroot_symbols.sh --self-test

# Optional hook inside build_and_test.sh (skipped by default)
CHECK_SYSROOT=1 SYSROOT=/path/to/sysroot sh scripts/ci/build_and_test.sh host
```

Exit status:
- `0`: Source-to-manifest sync passed and either `SYSROOT` is absent (skip message printed) or all required libraries and required symbols are present.
- `1`: Source-to-manifest disagreement, missing required soname (including dangling symlink), or missing required symbol.
- `2`: Invalid CLI arguments, malformed manifest, or missing host tool (`python3`, `readelf`/`nm`).

## Manifest Format (`scripts/ci/sysroot_symbols.txt`)

Each runtime-loaded library group is declared as:

```text
library <name> <required|optional> <any|all> [handle=<expr>]
  source <repo-relative-path>
  soname <filename> [manifest_only]
  symbol <required|optional> <symbol_name> [manifest_only]
```

- `required` vs `optional`: missing a `required` library or `required` symbol fails with exit `1`; missing an `optional` library (e.g. `libbluetooth` capability probe on non-BlueZ EntryNav2) or `optional` symbol (e.g. `DNSServiceUpdateRecord`, `_ZTVN3bmw8RunnableE`) is reported as a warning without failing.
- `any` vs `all`: `any` models fallback `dlopen()` candidate lists (the first resolved soname must export the group's symbols); `all` models `dlsym(RTLD_DEFAULT, ...)` inside a host process (`HmiMain3D`), where every backing DSO must exist and symbols may come from any of them.
- `manifest_only`: marks entries that cannot be parsed from C++ string literals (specifically `libAppFramework.A.so` and `libCoreFramework.A.so` for `RTLD_DEFAULT` in `src/platform/entry_carplay_plugin.cpp`).
- `handle=<expr>`: disambiguates symbols when a single file opens multiple libraries (`drm_handle_` vs `omap_handle_` in `src/platform/omap_dmabuf.cpp`).

## Findings on `main` (`13b531e`) vs EntryNav2 Sysroot (`202402191339`)

Running `SYSROOT=../EntryNav2-CarPlay-Assets/sysroot sh scripts/ci/check_sysroot_symbols.sh` against the extracted head-unit sysroot reports **7/8 library groups satisfied, 1 required error, 1 optional warning** (exit `1`):

| Group | Requirement / Mode | Source(s) | Sysroot Resolution | Symbols | Status |
| --- | --- | --- | --- | --- | --- |
| `libasound` | required / `any` | `src/platform/evo_audio.cpp` | `/usr/lib/libasound.so.2` -> `/usr/lib/libasound.so.2.0.0` | 10/10 exported (`@@ALSA_0.9`) | **OK** |
| `libxsvideo` | required / `any` | `src/platform/evo_video.cpp`, `include/carplay/platform/evo_video.hpp` | `/usr/lib/libxsvideo.so.4` -> `/usr/lib/libxsvideo.so.4.1.3` | 14/14 exported | **OK** |
| `libdrm` | required / `any` | `src/platform/omap_dmabuf.cpp`, `include/carplay/platform/evo_video.hpp` | `/usr/lib/libdrm.so.2` -> `/usr/lib/libdrm.so.2.4.0` | 2/2 exported | **OK** |
| `libdrm_omap` | required / `any` | `src/platform/omap_dmabuf.cpp`, `include/carplay/platform/evo_video.hpp` | `/usr/lib/libdrm_omap.so.1` -> `/usr/lib/libdrm_omap.so.1.0.0` | 6/6 exported | **OK** |
| `libvmostclient` | required / `any` | `src/platform/vmost_client.cpp` | `/usr/local/lib/libvmostclient.so.1` -> `/usr/local/lib/libvmostclient.so.1.6.0` | 7/7 exported | **OK** |
| `libdns_sd` | required / `any` | `src/platform/mdns_advertiser.cpp` | `libdns_sd.so.1` MISSING; `libdns_sd.so` MISSING (nearby: `/usr/local/lib/libdns_sd.so.0`) | 4 req + 1 opt skipped (no DSO) | **FAIL** |
| `libbluetooth` | optional / `any` | `src/platform/bt_rfcomm.cpp` | `libbluetooth.so.3` MISSING; `libbluetooth.so` MISSING | — (probe only) | **OPTIONAL-MISSING** |
| `hmi_framework` | required / `all` | `src/platform/entry_carplay_plugin.cpp` | `/opt/hmi/lib/libAppFramework.A.so`, `/opt/hmi/lib/libCoreFramework.A.so` | 20/20 req + 1/1 opt exported | **OK** |

### Real Bug Identified

- **`libdns_sd` soname mismatch in `src/platform/mdns_advertiser.cpp`:** `MdnsAdvertiser::load()` only tries `"libdns_sd.so.1"` and `"libdns_sd.so"`, neither of which exists in the EntryNav2 `202402191339` sysroot. The head unit ships `/usr/local/lib/libdns_sd.so.0`, which exports all five symbols (`DNSServiceRegister`, `DNSServiceRefSockFD`, `DNSServiceProcessResult`, `DNSServiceRefDeallocate`, and optional `DNSServiceUpdateRecord`). Adding `"libdns_sd.so.0"` to `MdnsAdvertiser::load()` (and updating `scripts/ci/sysroot_symbols.txt`) is required for wireless CarPlay mDNS advertisement to load on the car.
- **`libbluetooth` absence (expected):** `probeBtCapability()` in `src/platform/bt_rfcomm.cpp` probes `libbluetooth.so.3` / `libbluetooth.so` opportunistically; EntryNav2 uses the Alps Bluetooth D-Bus stack rather than BlueZ, so absence in the car sysroot is expected.

## Self-Test Mode

`sh scripts/ci/check_sysroot_symbols.sh --self-test` verifies the checker without needing the real sysroot:

1. Verifies the real repo sources match `scripts/ci/sysroot_symbols.txt`.
2. Compiles tiny shared libraries in a temporary directory with the host C compiler (`$CC` / `cc` / `gcc` / `clang`), covering relative symlinks, absolute symlinks mapped inside the fake sysroot, ELF symbol versioning (`@@ALPHA_1.0`), missing optional symbols, and missing optional libraries.
3. Confirms a missing required symbol fails with non-zero exit status.
4. Confirms an absolute dangling symlink fails and reports the missing mapped sysroot target.
5. Confirms source-vs-manifest drift fails with non-zero exit status.
6. Confirms a missing `SYSROOT` directory skips cleanly with exit `0`.
