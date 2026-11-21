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

### Option D — Explicit, Opt-In, Strictly Reversible Suspend of `DistributedDeviceProtocol.service` (**Recommended Path — verified 2026-11-21 visit 2**)

- **Mechanism:** Keep all BMW units untouched by default (`mfi_i2c` off, `suspend_ddp=0`). When hardware MFi auth is explicitly enabled via opt-in config/CLI, cleanly `systemctl stop DistributedDeviceProtocol.service` (a standalone `438` B unit under `After=vmostAuxinDiag.service`, `User=auxmms`, `Group=mplayer` — keeping `CARPLAY.service` and `MediaManagementServer.service` running unless wired USB testing also proves `vmostAuxInUSB12.service` contends) **only while our active CarPlay auth/session runs**, and **unconditionally `systemctl start` it** on teardown, `SIGTERM`/`SIGINT`, or crash-guard trip.
- **Pros:** Guarantees exclusive ownership of `/dev/i2c-0` with our already-tested `I2cMfiAuthProvider`; prevents `DDPServer` BT Slot-0 `NmeIAP2Link` handshakes from racing with `carplayd` on `/dev/i2c-0` OR fighting iOS with a second simultaneous iAP2 session; preserves `CARPLAY.service` (which is idle and keeps `wlan0` `iptables` CarPlay ports open); 100% reversible on exit or uninstall.
- **Risks & Visit 3 Checks:**
  1. Stopping `DistributedDeviceProtocol.service` temporarily disables native USB iPod / BT AVRCP (`NmeIAPDBusEntryEvoAudio`) while CarPlay is active (acceptable trade-off while CarPlay owns media/audio).
  2. Verify on Visit 3 whether `systemctl stop DistributedDeviceProtocol.service` restarts automatically or cascades to `MediaManagementServer`, whether CP `0x10`/`0x11` responds cleanly to `--compat-mfi-read`, and whether `CARPLAY.service`'s `authenticated_uid=1081` blocks DRM rendering or whether `root` `carplayd` renders cleanly via `omapdrm`/`Wayland`.

---

## 4. Recommended Coexistence Strategy (Post-Visit 2 Decision)

1. **Default Installation Remains Safe & Non-Invasive:** Ship safe defaults (`wireless=0`, `wired=0`, `detach_usbfs_driver=0`, `mfi_i2c` commented out, no service stopped by default). Keep **`CARPLAY.service` running** so its `wlan0` `iptables` allow-rules stay in place unless Visit 3 finds interference (`omapdrm` `authenticated_uid=1081`).
2. **Primary Hardware-MFi & Session Path — Option D:** Adopt **Option D** (explicit, opt-in, strictly reversible suspend/restore of `DistributedDeviceProtocol.service` while `carplayd` runs MFi auth/sessions; adding `vmostAuxInUSB12.service` only if wired USB testing shows `vmostAuxInUSB` reclaims `05ac:12a8`). Never attempt undocumented `DDPServer` socket hijacking (Option A) or blind concurrent `/dev/i2c-0` writes (Option B).
3. **Wireless-First Session Validation (Visit 3):**
   - Run `carplayd --compat` to verify `@ok|ilm|800x480 top_first=1` (using `/etc/wayland/compositor.conf`).
   - Run one-shot `--compat --mfi-i2c=/dev/i2c-0 --compat-mfi-read` (ideally with `DistributedDeviceProtocol.service` stopped under opt-in test) to confirm Apple CP address (`0x10` vs `0x11`), `dev_ver`, `proto_major`, and `cert_len`.
   - Test wireless bring-up (`ALPS` Slot `5` + `vmostd`/`wland` + `mdnsd` + Option D MFi), verifying `iptables`, `wland` 2.4 vs 5 GHz channel, and DRM/Wayland frame output.
4. **Wired USB Second:** Test `--wired` `0xC0/0x52` CarPlay switch and CDC-NCM/`TapIface` on port `3-1` with fast 2s `--watch` to confirm whether `vmostAuxInUSB12.service` also needs opt-in suspend during wired sessions.
5. **HMI Plugin (`EntryCarPlay` vs `EntryAad`):** `hmiapp/EntryCarPlay.xml` now uses `entryButtonFocusID="32753"` (`0x7FF1`) instead of `32752` (`EntryAad`); verify side-by-side `HmiMain3D` menu rendering in Visit 3 before permanent plugin installation.
