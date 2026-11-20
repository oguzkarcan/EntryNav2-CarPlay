# Car-Library Runtime Smoke Test (QEMU + Real Target Sysroot)

`scripts/ci/carlib_smoke.sh` builds ARMv7 hard-float binaries with the head unit's compiler generation (GCC 4.7.2 `-std=gnu++0x`, `debian/eol:wheezy` container) and executes them under `qemu-arm-static -L "$SYSROOT"` against the **real** BMW `HU_ENTRYNAV2` shared libraries (`eglibc 2.15`, `libstdc++.so.6.0.17`, and every vehicle/system `.so` in `SYSROOT`).

Whereas [scripts/ci/check_sysroot_symbols.sh](../../scripts/ci/check_sysroot_symbols.sh) checks ELF `.dynsym` exports statically, `carlib_smoke` proves **runtime** compatibility under the car's dynamic linker (`/lib/ld-linux-armhf.so.3` with `LD_BIND_NOW=1`):

1. All transitive `DT_NEEDED` dependencies of each `dlopen()`ed library resolve inside `$SYSROOT`.
2. Our own platform loader classes (`AlsaLoader`, `MdnsAdvertiser`, `VmostClient`, `loadDbusApi`, `probeBtCapability`, `BmwFrameworkApi::resolveFromDefault`) load and resolve their symbol tables against the real car DSOs.
3. Side-effect-free functions execute cleanly under the ARMv7 hard-float calling convention (`-mfloat-abi=hard`), and our hand-written opaque struct buffers (`DbusErrorRaw`, `DbusMessageIterRaw`, `BmwParcelStorage`, `VmostMsgOut`, `EntryPluginAppInfo`) match the target ABI without buffer overrun.
4. No built ARM binary (`carlib_smoke`, `carplayd`, `libEntryCarPlay.so`, and our unit-test subset) requires any `GLIBC_*`, `GLIBCXX_*`, `CXXABI_*`, or `GCC_*` symbol version absent from `$SYSROOT`.

## Usage

```sh
# Explicit sysroot (recommended)
SYSROOT=/path/to/EntryNav2-CarPlay-Assets/sysroot sh scripts/ci/carlib_smoke.sh

# Default sysroot (../EntryNav2-CarPlay-Assets/sysroot); skips with exit 0 if absent
sh scripts/ci/carlib_smoke.sh

# Optional hook inside build_and_test.sh
RUN_CARLIB_SMOKE=1 SYSROOT=/path/to/sysroot sh scripts/ci/build_and_test.sh host

# Skip the armhf unit-test subset (run carlib_smoke + carplayd + ABI checks only)
SYSROOT=/path/to/sysroot sh scripts/ci/carlib_smoke.sh --no-unit-subset
```

Requirements on the host:
- Extracted `SYSROOT` containing `lib/ld-linux-armhf.so.3` and `lib/libc.so.6` (mounted/read-only, never copied into the repository).
- `docker` with `linux/arm/v7` binfmt emulation (`debian/eol:wheezy`) and `qemu-arm-static` (or `qemu-arm`) in `PATH`.
- `python3` and `readelf` for ELF attribute and `.gnu.version_r` vs `.gnu.version_d` verification.

If `SYSROOT`, `docker`, or `qemu-arm*` is unavailable, `scripts/ci/carlib_smoke.sh` prints a `SKIP:` line and exits `0`.

## Library Verification Matrix (`tests/carlib_smoke.cpp`)

All libraries in [scripts/ci/sysroot_symbols.txt](../../scripts/ci/sysroot_symbols.txt) plus sysroot graphics/Wayland libraries are covered:

| Library Group | Platform Loader Exercised | Symbols Checked | Safe Side-Effect-Free Calls & Rationale |
| --- | --- | --- | --- |
| `libasound.so.2` | `AlsaLoader::load()` / `unload()` | 10/10 required (`snd_pcm_*`, `snd_strerror`) | `snd_strerror(0)`, `snd_strerror(-ENOENT)`, `snd_asoundlib_version()` (`1.0.27.2`). Pure static string/version lookups; never parses `/etc/asound.conf` or opens `/dev/snd/*`. |
| `libxsvideo.so.4` | `dlopen(..., RTLD_NOW)` + `XsvApi` | 14/14 required (`xsv_*`) | No calls made: every function needs a live `xsv_handle` from `xsv_open()` (which connects to Wayland/DCE/IVA-HD). `RTLD_NOW` proves all transitive deps (`libwayland-client`, `libdce`, `libmmrpc`, `libdrm_omap`, `libivi-application`, `libpng16`, `libffi`, `libz`) resolve. |
| `libdrm.so.2` + `libdrm_omap.so.1` | `dlopen(..., RTLD_NOW)` + `DrmOmapApi` | 2/2 `libdrm` + 6/6 `libdrm_omap` | `drmAvailable()` (returns `0` when `/dev/dri` is absent; read-only open/close probe). `omap_device_new` / `omap_bo_*` are not called without a real `omapdrm` fd. |
| `libvmostclient.so.1` | `VmostClient::load()` / `unload()` | 7/7 required (`vmost*`), `sizeof(VmostMsgOut) == 24` | Tested `kNoDaemon` when socket absent, then `kLoaded` with a bound temporary `AF_UNIX` socket path via `setVmostForTest` (no `listen()`, no `vmostConnect()`). `vmostFileDescriptorGet()` reads internal fd state without IPC. |
| `libdns_sd.so.0` | `MdnsAdvertiser::load()` / `unload()` | 4/4 required + 1/1 optional (`DNSServiceUpdateRecord`) | `DNSServiceConstructFullName()` + `TXTRecord{Create,SetValue,GetLength,GetCount,GetBytesPtr,ContainsKey,Deallocate}`. Pure in-memory string/buffer formatting; never connects to `mdnsd`. |
| `libdbus-1.so.3` | `loadDbusApi()` + `probeBtCapability()` | 40/40 required (`dbus_*`) | `dbus_get_version()` (`1.6.10`), `dbus_threads_init_default()`, `dbus_error_{init,is_set,free}` + `dbus_validate_path()` (with guard words around `DbusErrorRaw`), `dbus_message_new_method_call()` + `dbus_message_iter_*` marshal/unmarshal round-trip (with guard words around `DbusMessageIterRaw`). Pure in-memory; never touches `/var/run/dbus/system_bus_socket`. |
| `libbluetooth.so.3` | `probeBtCapability()` | Optional probe | Reported `OPTIONAL-ABSENT` on EntryNav2 ALPS sysroot (expected; passes if present). |
| `libevo_btappl.so` | `dlopen()` probe | Optional (`app`, `spp_info`, `spp_connected`) | Reported `OPTIONAL-ABSENT` in partial sysroot (`/usr/local/lib/alps/evolution -> /opt/app/...` is dangling because `/opt/app` is excluded). Verifies the 3 symbols if present in a full rootfs. |
| `libCoreFramework.A.so` + `libAppFramework.A.so` + `libEntryCarPlay.so` | `BmwFrameworkApi::resolveFromDefault()` | 20/20 required + `_ZTVN3bmw8RunnableE` | `dlopen(..., RTLD_NOW \| RTLD_GLOBAL)` matching `HmiMain3D`; verifies `bmw::PluginApp` vtable slots `21/22/23` (`onError`, `onInit`, `onFinalize`); constructs/destructs `BmwBasicStringChar`, `BmwTextIdStorage`, `BmwImageIdStorage`, and guarded `BmwParcelStorage` (`bool` round-trip) in memory; loads `libEntryCarPlay.so` and validates `pluginAppInfo` (`Apple CarPlay`, `v1.0`, `rhmi=1`) without calling `create()`. |
| `libEGL.so.1` + `libGLESv2.so.2` (+ `libilm*.so`) | Direct `dlopen(..., RTLD_NOW)` probe | `eglGetError`, `eglGetCurrentDisplay`, `eglQueryString`, `eglGetDisplay`, `glGetError`, `glGetString` | `eglGetError()` (`0x3000` `EGL_SUCCESS`) and `eglGetCurrentDisplay()` (`NULL`) inspect thread-local EGL state with no GPU/Wayland access. Note: `libilmCommon.so.1.2.0` has bidirectional undefined symbols (`ilmClient_destroy` / `ilmControl_destroy`) across `libilmClient.so` and `libilmControl.so`, so it is only `dlopen`ed when `LD_BIND_NOW=1` is not set (our `EvoIlm` runs `LayerManagerControl` instead of `dlopen`ing `libilm*`). |

## ARMv7 Unit Test Subset & Symbol-Version Results

Against `/home/ozzy/Projects/EntryNav2-CarPlay-Assets/sysroot` (`GLIBC_2.15`, `GLIBCXX_3.4.17`, `CXXABI_1.3.6`, `GCC_4.7.0`):
- **Max required versions across all built binaries:** `GLIBC_2.9` (`carplayd`; `GLIBC_2.4` elsewhere), `GLIBCXX_3.4.11`, `CXXABI_ARM_1.3.3` / `CXXABI_1.3`. Every required symbol version is present in the sysroot.
- **`carplayd --help` and `carplayd --version`:** load with `LD_BIND_NOW=1` and exit `0`.
- **Self-contained ARMv7 unit tests under QEMU (`LD_BIND_NOW=1`):** `test_phase1` (10/10), `test_evo_audio` (16/16), `test_evo_input` (19/19), `test_mdns_advertiser` (4/4), `test_alps_spp` (11/11), `test_bt_rfcomm` (11/11), `test_airplay_session` (26/26), `test_iap2_session` (4/4). Tests that `fork()`/`exec()` `/bin/sh` helper scripts (`test_evo_video`, `test_carplay_daemon`) are excluded from the library-only sysroot subset because the partial sysroot has no `/bin/sh`.
