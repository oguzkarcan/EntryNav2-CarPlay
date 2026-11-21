# Coexistence with Native BMW `CARPLAY`, `DDPServer`, and `EntryAad`

On the target BMW `HU_ENTRYNAV2` (`/etc/version` `202402191339`), activating native CarPlay via FSC coding fails with an error, so this project continues with its own clean-room `carplayd` stack. Visit 1 (`2026-11-21`) revealed that native BMW Apple/CarPlay services still run on the head unit by default and share hardware resources (`i2c-0`, USB, ALPS BT, `wland`, `mdnsd`, HMI plugin focus).

> **Hard Policy Invariant:** `carplayd`, `install.sh`, and probe scripts **never kill, stop, or detach BMW processes or drivers by default** (`detach_usbfs_driver=0`, `mfi_i2c` off, `wireless=0`, `wired=0`). Any suspension of native BMW services during an active session must be **explicit, opt-in via config/CLI, and strictly reversible** on teardown or exit.

---

## 1. Visit 1 Baseline Observations (verified 2026-11-21 visit 1)

| Component | Observed State on Head Unit | Resource / Contention Impact |
| --- | --- | --- |
| `/usr/local/bin/CARPLAY` (`CARPLAY.service`) | Running as user `carplay`, `00:00:00` CPU while idle; no TCP `:7000` listener; ALPS slot `1` does not carry iAP2 UUID; `wlan0`/`wlan1` `DOWN`. | Unknown until Visit 2: `/proc/<pid>/{maps,fd,environ,net/unix}`, `CARPLAY.service` unit contents, D-Bus names, and mDNS registrations. |
| `/usr/local/bin/DDPServer` (`DistributedDeviceProtocol.service`) | Running as user `auxmms`, group `mplayer`. Holds **`/dev/i2c-0` open (`fd 40`)** and actively logs `NmeIAP2Link` / `NmeIAP2` (`0x4040` iAP2 CSM, `OnNowPlayingUpdate`, `OnPlaybackAttributes`) in `/tmp/Mediaplayer/*_DDPS_*.txt`. | **Direct `/dev/i2c-0` MFi bus owner** and active USB/iAP2 media handler when an iPhone is plugged into USB. |
| `MediaManagementServer`, `vmostAuxInBT`, `vmostAuxInUSB`, `AuxInUCM` | All running under `mplayer` / `aux*` users (`CARLIFE` also active on `/dev/ffs-carlife`). | Attached iPhone (`05ac:12a8`, port `3-1`) enumerates as `cfg=2/4` (`use iap configuration`, Audio + HID) with two USB resets. Visit 1 `usb_probe.sh` timed out (`[rc=143]`) before recording `/proc/*/fd` owners of `/dev/bus/usb/003/002`. |
| ALPS BT (`evo_hli_socket`) | Slot `0` (BMW Apps) connected; slot `5` idle (`borrow_slot5` compatible). | No conflict with native `CARPLAY` on slot `1` while FSC is inactive. |
| Wi-Fi (`wland` / `wl18xx`) & `mdnsd` | `wlan0`/`wlan1` `DOWN`; all 5 GHz channels `(disabled)` in `iw list` under regdomain `XA`; `mdnsd` running as `nobody`. | Must verify whether `wland` activates 5 GHz on AP start and whether `CARPLAY` registers `_carplay._tcp` / `_airplay._tcp` with `mdnsd`. |
| HMI Plugins (`/opt/hmi/data/ro/Plugins/`) | `EntryAad` is installed on the unit. | Both `EntryCarPlay.xml` and `EntryAad.xml` use `entryButtonFocusID="32752"` ([BUILD.md](BUILD.md)). |

---

## 2. Coexistence Options

### Option A — Share the MFi Chip via `DDPServer` IPC (Preferred if Feasible)

- **Mechanism:** `CARPLAY` runs as user `carplay`, whereas `/dev/i2c-0` is `root:mplayer 0660` and held open by `DDPServer` (`auxmms:mplayer`). This separation strongly suggests `CARPLAY` does not open `/dev/i2c-0` directly, and instead requests MFi certificates/signatures (or whole iAP2 sessions) from `DDPServer` over D-Bus, vMOST, or a Unix socket. If `DDPServer` exposes a reachable IPC method for certificate read + challenge signing, `carplayd` could implement an `IpcMfiAuthProvider` without touching `/dev/i2c-0` directly.
- **Pros:** Zero I2C bus contention; preserves native iPod/USB media when CarPlay is not running; no service stopping needed.
- **Risks:** Proprietary, undocumented IPC protocol; `DDPServer` may enforce peer-UID/D-Bus policy (`carplay` or `auxmms` only), single-client registration, or bundle MFi auth inside a full iPod/CarPlay state machine rather than exposing raw sign primitives.
- **Needs Verified (Visit 2):**
  1. `DDPServer` `/proc/<pid>/{fd,maps,net/unix}` and `CARPLAY` `/proc/<pid>/{fd,maps,net/unix}`.
  2. D-Bus `org.freedesktop.DBus.ListNames` and `/etc/dbus-1/system.d/*` policies for `DDPServer` / `CARPLAY`.
  3. Whether `CARPLAY` links `libNmeCarPlay.so` or `libauxin-apple.so` and communicates with `DDPServer`.

### Option B — Time-Share `/dev/i2c-0` Directly from `carplayd`

- **Mechanism:** Run `carplayd` with `--mfi-i2c=/dev/i2c-0` (as `root` or group `mplayer`). Linux `i2c-dev` allows multiple processes to open `/dev/i2c-0` concurrently.
- **Pros:** Uses our existing, tested `I2cMfiAuthProvider` (`mfi_i2c.cpp`) with no proprietary IPC reversing.
- **Risks:** **High I2C race hazard if `DDPServer` is active.** Kernel `i2c-omap` only locks individual `I2C_RDWR` ioctls, not multi-step Apple CP 2.0C/3.0 sequences (`select reg` -> `5 ms` -> `read`, or `0x20`/`0x21`/`0x10` -> poll -> `0x12`). If `DDPServer` polls `/dev/i2c-0` or runs `NmeIAP2Link` simultaneously (e.g., when iPhone is plugged in via USB), register pointers and signatures will be corrupted.
- **Needs Verified (Visit 2):**
  1. With iPhone **unplugged** (wireless CarPlay scenario): does `DDPServer` touch `/dev/i2c-0` at all after boot, or is `/dev/i2c-0` completely quiescent unless USB iAP2 runs?
  2. Does `carplayd --compat --mfi-i2c=/dev/i2c-0 --compat-mfi-read` succeed cleanly at `0x10` or `0x11` when `DDPServer` is idle (or stopped)?

### Option C — Leverage Native Stack Auth / Transport Path

- **Mechanism:** Attempt to let native `CARPLAY` or `DDPServer` handle iAP2 + MFi authentication and hand off only AirPlay/UI, or check if iOS accepts AirPlay HAP without iAP2 MFi.
- **Pros:** Would avoid implementing an `AuthProvider` client in `carplayd` if native iAP2 succeeded.
- **Risks:**
  1. Genuine iOS CarPlay **requires** valid Apple MFi authentication (over iAP2 `0xAA00`–`0xAA05` or RTSP `/auth-setup` MFiSAP); iOS rejects unauthenticated CarPlay sessions.
  2. Because native CarPlay FSC coding fails on this HU, native `CARPLAY` will not advertise CarPlay capabilities (`0x4300`/`0x4301`/`0x5703`) over `DDPServer`'s `NmeIAP2Link`, and `DDPServer` only runs standard iPod/NowPlaying (`0x4040` `OnNowPlayingUpdate`) unless instructed otherwise.
- **Needs Verified (Visit 2):**
  1. Inspect `CARPLAY.service`, `CARPLAY` `/proc` state, and `/etc` / `/opt` config/XML files mentioning `carplay`/`fsc`/`iap`/`mfi` to confirm whether `CARPLAY` is hard-gated by FSC before touching iAP2/mDNS/AP.

### Option D — Explicit, Reversible, Opt-In Suspend of Competing Native Services During Session

- **Mechanism:** Keep `CARPLAY.service` and `DistributedDeviceProtocol.service` (`DDPServer`) untouched by default. Only when the user enables an explicit opt-in config flag (e.g. `suspend_native_carplay=1` or `suspend_ddp_for_wired=1`, default `0` / disabled), `carplayd` (or its wrapper) cleanly stops the competing unit (`CARPLAY.service`, and for wired USB if required `DistributedDeviceProtocol.service` / `vmostAuxInUSB12.service`) **only while our CarPlay session/mode is active**, and **unconditionally restarts** those units on teardown, signal exit, or crash-guard trip.
- **Pros:** Guarantees exclusive ownership of `/dev/i2c-0` and `/dev/bus/usb/*` with deterministic behavior and zero protocol guesswork; completely reversible when CarPlay is not active or uninstalled.
- **Risks:**
  1. Stopping `DDPServer` / `vmostAuxInUSB` temporarily disables native USB iPod/MTP/BT-AVRCP (`AuxIn`) functionality while our session holds them, and must be carefully restarted on every exit path (including `CrashLoopGuard` and `SIGTERM`).
  2. `CARPLAY.service` / `DDPServer` systemd dependencies (`Requires=` / `BindsTo=` / `MediaManagementServer`) could cascade if stopped blindly — unit files must be inspected first!
- **Needs Verified (Visit 2):**
  1. Full contents of `CARPLAY.service`, `DistributedDeviceProtocol.service`, `MediaManagementServer.service`, `vmostAuxInUSB12.service` (dependencies, `Restart=`, `ExecStart=`).
  2. Exact `/proc/<pid>/fd` USB ownership during iPhone plug/unplug (`--watch`).

---

## 3. Recommended Coexistence Strategy

1. **Collect Visit 2 diagnostics first** (`sh car_visit.sh --native --watch 20`) to close the missing facts above (`CARPLAY` + `DDPServer` maps/fds/sockets/systemd units, USB fd owners during plug/unplug, `evo_config.xml` UUIDs, `compositor.conf` path).
2. **Wireless CarPlay first (lowest contention):**
   - Because native `CARPLAY` is idle (slot 1 unconfigured, `wlan0` down, no `:7000` listener) and `DDPServer` only logs iAP2 USB media traffic when an iPhone is plugged in via USB, **Wireless CarPlay** (`ALPS` slot 5 + `wland`/`hostapd` + `mdnsd`) has the highest chance of coexisting **without stopping `DDPServer`** (Option B if `/dev/i2c-0` is idle with USB unplugged, or Option A if Visit 2 reveals a usable `DDPServer` MFi IPC).
   - If `CARPLAY.service` interferes with `mdnsd` or `wland` when wireless starts, prefer stopping only `CARPLAY.service` via an **opt-in, reversible** config flag (Option D) while leaving `DDPServer` running if possible.
3. **Wired USB CarPlay second (explicit opt-in suspend if needed):**
   - Because `DDPServer` / `AuxIn` actively claims the USB iPhone into `cfg=2/4` (`use iap configuration`) and holds `/dev/i2c-0`, wired USB CarPlay will likely require Option A (if feasible) or Option D (explicit, reversible opt-in suspend of the competing USB/iAP handler while wired CarPlay runs, never enabled by default).
4. **HMI Plugin (`EntryAad` vs `EntryCarPlay`):**
   - Before deploying `libEntryCarPlay.so` to `/opt/hmi/data/ro/Plugins/`, either temporarily remove/disable `/opt/hmi/data/ro/Plugins/EntryAad` or verify a non-colliding `entryButtonFocusID` on target (`32752` is currently shared by both).
