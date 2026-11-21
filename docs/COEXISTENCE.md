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
| HMI Plugins (`/opt/hmi/data/ro/Plugins/`) | `EntryAad` is installed on the unit. | `EntryAad.xml` uses `entryButtonFocusID="32752"`; `EntryCarPlay.xml` updated to `32753` ([BUILD.md](BUILD.md)) pending Visit 3 live menu test. |

---

## 2. Visit 2 Observations (verified 2026-11-21 visit 2)

| Component | Verified Visit 2 Evidence | Design Consequence |
| --- | --- | --- |
| `/usr/local/bin/CARPLAY` (`CARPLAY.service`) | Runs as `carplay:carplay` (`Uid 1081`, `00:00:00` CPU, 4 threads), `/var/local/data/CarPlay` empty, links `libNmeSDK`/`libNmeBaseClasses`/`libNme`/Boost/`libSomeIP`/`libpersistence` (note: `/proc/<pid>/maps` cut at line 160 before high addresses). Holds **0** `/dev/i2c-0`, **0** `/dev/bus/usb/*`, **0** `/var/run/mdnsd` fds. Unit `ExecStartPre` writes `1081` to `/sys/module/omapdrm/parameters/authenticated_uid`, and `ExecStartPost` opens CarPlay/AirPlay TCP & UDP ports on `wlan0` via `iptables`. Registers vMOST shadows `0x02/0x00, 0xDD/0x03, 0xF2/0x02, 0xD1/0x06, 0xF1/0x2B`. | **Leave `CARPLAY.service` running:** it consumes zero runtime resources while FSC (`va_CARPLAY_SWT`) fails and its `ExecStartPost` already provisions the `wlan0` firewall ports (`53`, `5353`, `5000:5001`, `7000:7001`, etc.) needed for Wireless CarPlay. Check whether `omapdrm` `authenticated_uid=1081` affects `root` `carplayd` DRM access in Visit 3. |
| `/usr/local/bin/DDPServer` (`DistributedDeviceProtocol.service`) | Unit (`438` B): `After=vmostAuxinDiag.service`, `User=auxmms`, `Group=mplayer`, `CapabilityBoundingSet=`. Maps `libNmeAppleAuth.so`, `libNmeAppleAuthImpl.so`, `libNmeTransport.so`, `libNmeVfs.so`, `libNmeAvrcpEvo.so`. Permanently holds **`/dev/i2c-0` (`fd 38`)** across every idle and USB `--watch` sample. IPC consists only of Cinemo socketpairs to `MediaManagementServer`, `/tmp/BTAS`, and `org.alps.evolution` D-Bus signals (no `/etc/dbus-1/system.d` policy for `DDPServer`, no vMOST FBlocks). Even **before iPhone USB plug**, logs `NmeIAP2Link` + `NmeIAPDBusEntryEvoAudio` (`OnIdentificationAccepted`) over `org.alps.evo.SPP::BtApplSppDataInd([0,28,...])`. | **No usable MFi/iAP2 IPC exists.** Worse, because `DDPServer` drives iAP2 over **BT Slot 0** even with USB unplugged, concurrent `/dev/i2c-0` access while an iPhone connects/identifies on BT risks colliding on the CP chip. |
| ALPS BT Slot `0` vs Slot `5` | `DDPServer` Bluetooth iAP2 (`[0,28,...]`) runs on **ALPS Slot `0`** (`compat.txt`: `slot0_apps=connected`, `borrow_slot5`). `evo_config.xml` had 0 grep matches for `caff|cafe|carplay|iap|supported_services|6203`. | **No direct slot-number collision** with our Slot `5` borrow. Keep `bt_probe`/Visit 3 test to see whether iOS allows simultaneous BT CarPlay iAP2 on Slot `5` while `DDPServer` holds Slot `0`. |
| USB Plug (`05ac:12a8` on `3-1`) | During Visit 2 `--watch` (samples 4–5), `05ac:12a8` attached with `cfg=2/4` (`01/01/00`, `01/02/00`, `03/00/00`, `drv=none`) and `vmostAuxInUSB` opened `/tmp/Mediaplayer/614_USBC_*.txt`; none of the 6 target PIDs held a persistent `/dev/bus/usb/*` fd at the ~6s sample snapshots. | `vmostAuxInUSB` reacts immediately to iPhone plug, while steady-state USB CarPlay ownership/contention during active `0xC0/0x52` switch must be confirmed on Visit 3. |
| Compositor & `mdnsd` | Real config is **`/etc/wayland/compositor.conf`** (`995` B, `genivi-flip-renderorder = 1`, i.e., `top_first = true`). `mdnsd` (`/var/run/mdnsd`, `nobody`) has `RefCount 2` and **0 client sockets** (0 active CarPlay/AirPlay registrations). | `CompatCheckConfig` updated to `/etc/wayland/compositor.conf`; `EvoIlm` now falls back to `top_first = true` if absent. `mdnsd` is clean and uncontended. |

---

## 3. Coexistence Options (Updated After Visit 2)

### Option A — Share the MFi Chip via `DDPServer` IPC (**Ruled Out — verified 2026-11-21 visit 2**)

- **Mechanism & Visit 2 Verdict:** `DDPServer` only maintains Cinemo socketpairs to `MediaManagementServer` (for `Mediaplayer` USB/BT playback), `/tmp/BTAS`, and ALPS D-Bus signals; it exposes no public D-Bus service name, D-Bus policy file, vMOST FBlock, or raw MFi signing socket. **`CARPLAY` itself stays completely idle and unauthenticated when FSC is inactive.** Implementing an `IpcMfiAuthProvider` against `DDPServer` is not viable without brittle binary hooking.

### Option B — Time-Share `/dev/i2c-0` Directly While `DDPServer` Runs (**Unsafe by Default — verified 2026-11-21 visit 2**)

- **Mechanism & Visit 2 Verdict:** Although `i2c-omap` serializes single `I2C_RDWR` ioctls, Visit 2 disproved the hypothesis that `DDPServer` leaves `/dev/i2c-0` idle when USB is unplugged: `DDPServer` keeps `/dev/i2c-0` (`fd 38`) permanently open and actively negotiates `NmeIAP2Link` (`OnIdentificationAccepted`) over **Bluetooth Slot 0**. A new BT iAP2 handshake happening at the same instant as `carplayd` (`--mfi-i2c`) would race on CP registers (`select` + `5 ms` + `read`, `0x20`/`0x21`/`0x10`).
- **Permitted Read-Only Diagnostic Use:** One-shot `carplayd --compat --mfi-i2c=/dev/i2c-0 --compat-mfi-read` (only reading register `0x00`) is reasonable during bench/car checks when iPhone BT & USB are temporarily quiescent, before choosing Option D for session use.

### Option C — Leverage Native Stack Auth / Transport Path (**Ruled Out — verified 2026-11-21 visit 2**)

- **Visit 2 Verdict:** Native `CARPLAY` stays idle (`00:00:00` CPU, empty `/var/local/data/CarPlay`, no AP, no mDNS fd) because FSC coding (`va_CARPLAY_SWT`) fails. `DDPServer` only runs iPod/Audio (`NmeIAPDBusEntryEvoAudio`), never CarPlay.

### Option D — Opt-In Irreversible-Until-Reboot `DDPServer` Handoff (`ddp_handoff`, **Revised & Implemented After Visit 3**)

- **Why the original "stop + restart" assumption changed (verified 2026-11-21 visit 3):**
  - `DistributedDeviceProtocol.service` has **`KillMode=none`**, **no `ExecStop`**, `Restart=no`, `WatchdogSec=75`, `User=auxmms`, `Group=mplayer`, `WantedBy=unfocussed.target`.
  - Calling `systemctl stop DistributedDeviceProtocol.service` alone leaves `DDPServer` running and still holding `/dev/i2c-0`.
  - Sending `SIGTERM` explicitly to the verified `DDPServer` PID (`/proc/<pid>/exe -> .../MediaPlayer/bin/DDPServer`) stops `DDPServer` within ~1 s and frees `/dev/i2c-0` (`0` holders). Never use `SIGKILL` (`-9`).
  - Calling `systemctl start DistributedDeviceProtocol.service` afterward spawns a fresh `DDPServer` PID that **does not reopen `/dev/i2c-0` and does not restore Bluetooth music**; an ignition off/on cycle did **not** recover it either — **only an explicit `systemctl reboot` (~3 min shutdown+boot) restored `DDPServer` and BT music**.
- **Implemented `ddp_handoff` design (`include/carplay/platform/ddp_handoff.hpp`, opt-in default OFF):**
  - Config keys in `/var/local/data/CarPlay/carplay.conf`:
    - `ddp_handoff=0|1` (default `0`; CLI `--ddp-handoff` / `--no-ddp-handoff`).
    - `ddp_restore=reboot_prompt|none` (default `reboot_prompt`; CLI `--ddp-restore=reboot_prompt|none`; **never** auto-restarts `DDPServer`).
  - When `ddp_handoff=1` and `mfi_i2c` is enabled, **before opening `/dev/i2c-0`**:
    1. `DdpHandoff` forks/execs `/bin/systemctl stop DistributedDeviceProtocol.service` non-blockingly on the single-threaded `Reactor` (`fork`/`execv` + `O_CLOEXEC` pipe, zero `system()`/`popen()`).
    2. Scans `/proc` and sends `SIGTERM` (`kill(pid, SIGTERM)`, never `-9`) **only** to live non-zombie PIDs whose resolved `/proc/<pid>/exe` ends in `/MediaPlayer/bin/DDPServer`.
    3. Polls non-blockingly up to **`<= 5 s`** until all `DDPServer` PIDs have exited **and** no process holds an open fd on `/dev/i2c-0` (or the configured I2C device path).
    4. If any process still holds `/dev/i2c-0` (or `systemctl`/`SIGTERM` fails or times out), **aborts the session cleanly without ever opening `/dev/i2c-0`**.
    5. Once `I2cMfiAuthProvider` opens `/dev/i2c-0`, if the coprocessor probe fails, `CarPlayDaemon` immediately calls `mfi_auth_->stop()` (closing `/dev/i2c-0` so the bus is never left half-used) and aborts.
  - **On session end / daemon exit:** `carplayd` does **not** run `systemctl start` on `DDPServer`. Instead, when `ddp_restore=reboot_prompt`, it atomically writes `/tmp/entry-carplayd-ddp-needs-reboot`, logs the reboot requirement, and `libEntryCarPlay.so` surfaces `"Apple CarPlay (Reboot for BT audio)"` / `"Start CarPlay (Reboot for BT audio)"` in the iDrive menu while idle (plus a one-time notice in `app.log`).

---

## 4. Visit 3 Results & Post-Visit-3 Strategy (`verified 2026-11-21 visit 3`)

1. **Confirmed on HU in Visit 3 (verified 2026-11-21 visit 3):**
   - **MFi chip present:** `@ok|mfi|/dev/i2c-0 I2C_FUNCS ok, addr=0x10 dev_ver=0x05` (with `DDPServer` stopped).
   - **`omapdrm` + LayerManager:** `CARPLAY.service` (`authenticated_uid=1081`) does **not** block `root` `carplayd` from allocating `omapdrm` dma-buf (`4x524288 B`) or rendering `800x480` on surface `0x7ec00001` / layer `0x80000000` (`genivi-flip-renderorder=1`).
   - **vMOST & HMI Coexistence:** `EntryCarPlay` (`32753`) coexists stably in `HmiMain3D` alongside `EntryAad` (`32752`); `knob: controller protocol locked: older CCS (E5.01, C10/C20)`; `STOP` file exits cleanly (`0`) and the plugin debounces relaunch (`3 s`).
   - **Reboot vs Ignition & Persistent Uninstall:** Normal ignition off/on does **not** reboot `HU_ENTRYNAV2`; `systemctl reboot` is required to reload HMI plugins and wipes `/tmp/carplay-stage`, so `install.sh` now stores `uninstall.sh` inside `/var/local/data/CarPlay/.install-backup/uninstall.sh`.
2. **Default Installation Remains Non-Invasive:** `carplay.conf` still defaults to `wireless=0`, `wired=0`, `detach_usbfs_driver=0`, `ddp_handoff=0`, and `# mfi_i2c=/dev/i2c-0:0x10` commented out. `CARPLAY.service` stays running (zero runtime contention, provides `wlan0` firewall rules).
3. **Visit 4 Order of Operations:** Test **wired USB + MFi** (`wired=1`, `mfi_i2c=/dev/i2c-0:0x10`, `ddp_handoff=1`, `detach_usbfs_driver=0`) first via `/var/local/data/CarPlay/carplay.conf`, observing `vmostAuxInUSB` coexistence during `0xC0/0x52` CarPlay switch, `0x30..0x3F` cert read, and live session video/audio/input; then test **wireless** (`wireless=1`) once wired is proven. See [docs/CAR_VISIT.md](CAR_VISIT.md).
