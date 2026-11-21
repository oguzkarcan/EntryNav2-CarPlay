# EntryNav2-CarPlay

Open-source C++11 (`-std=gnu++0x`, GCC 4.7 compatible) Apple CarPlay receiver core and platform daemon targeting BMW `HU_ENTRYNAV2` (EntryEVO / OMAP5 / Linux 3.12), supporting **both Wired USB (iAP2 over USB + CDC-NCM TAP IPv6)** and **Wireless (Bluetooth ALPS SPP iAP2 + Wi-Fi AP/mDNS)** transports.

> [!WARNING]
> **Pre-release (`v0.1.0-alpha.1`):** Safe-mode installation and **Start CarPlay** (HMI plugin launch, `800x480` LayerManager/omapdrm surface, `ZBE3` controller lock, clean `STOP` teardown, and MFi I2C coprocessor `0x10` probe) are verified on a real `HU_ENTRYNAV2` head unit (`/etc/version` `202402191339`). **A live iPhone CarPlay session has not been tested on a vehicle yet.** Use safe mode (`wireless=0`, `wired=0`) first and always keep the uninstall/kill-switch commands handy.

## Status

- **Current Release:** [`v0.1.0-alpha.1`](https://github.com/oguzkarcan/EntryNav2-CarPlay/releases/tag/v0.1.0-alpha.1) (pre-release)
- **Verified on real hardware (`2017 BMW F20 HU_ENTRYNAV2`, `/etc/version` `202402191339`):**
  - Read-only vehicle probe (`scripts/probe/car_visit.sh`) and `carplayd --compat` library/ABI checks.
  - Safe-mode installation (`scripts/deploy/install.sh --mode safe`) and byte-for-byte rollback (`uninstall.sh`).
  - `HmiMain3D` loading `EntryCarPlay` (`entryButtonFocusID="32753"`) stably alongside `EntryAad` (`32752`), launching `/opt/carplay/carplayd`, allocating `omapdrm` dma-buf + `800x480` LayerManager surface (`0x7ec00001` / `0x80000000`), locking `older CCS (E5.01, C10/C20)`, and stopping cleanly via `/tmp/entry-carplay-service/STOP`.
  - Apple MFi coprocessor detected on `/dev/i2c-0` at `addr=0x10` (`dev_ver=0x05`) once `DDPServer` is stopped.
- **Not yet tested on real hardware:** End-to-end iPhone CarPlay session (wired USB `0xc0/0x52` switch, MFi cert/signing, H.264 video, ALSA audio/mic, touch/knob input, or wireless BT+Wi-Fi session). See [docs/CAR_VISIT.md](docs/CAR_VISIT.md) and [docs/VEHICLE_FACTS.md](docs/VEHICLE_FACTS.md).

## Requirements

- **Head Unit:** BMW `HU_ENTRYNAV2` (EntryEVO, ARMv7 hard-float, Linux 3.12, eglibc 2.15).
- **Connection:** ENET (OBD-to-Ethernet) cable connected to a laptop; head unit default IP is `169.254.1.0` with `root` SSH/SCP access.
- **For Wired USB Testing:** Certified Lightning or USB-C **data** cable (not charge-only) and iPhone plugged into the center-console/armrest USB port.
- **Vehicle Safety:** Keep the vehicle parked with ignition ON (or engine idling / battery charger attached). **Never turn off ignition while `/` is mounted read-write (`rw`).**

## Installation

Follow this order on the head unit: read-only check -> `--compat` -> `--dry-run` -> safe-mode install -> `systemctl reboot`. See [docs/CAR_VISIT.md](docs/CAR_VISIT.md) for the full vehicle checklist.

1. **Copy the staged build and deploy scripts to `/tmp/carplay-stage` (RAM):**
   ```sh
   scp -r build/arm-entrynav2/install-root scripts/deploy root@169.254.1.0:/tmp/carplay-stage
   ```
   *(If using a release archive, unpack it first so `install-root/opt/carplay/carplayd` and `deploy/install.sh` are under `/tmp/carplay-stage`.)*

2. **(Recommended) Run the dry-run compatibility self-check from `/tmp` first:**
   ```sh
   ssh root@169.254.1.0 '
     LD_LIBRARY_PATH=/usr/local/lib:/opt/hmi/lib:/usr/lib:/lib \
     XDG_RUNTIME_DIR=/run/system/0 WAYLAND_DISPLAY=wayland-0 \
     /tmp/carplay-stage/install-root/opt/carplay/carplayd --compat
   '
   ```
   Do **not** install if any core requirement (`libxsvideo`, `libasound`, `libvmostclient`, `libdrm`, `hmi_abi`, `tap`, `usbfs`, `data_dir`) prints `@block`.

3. **Preview the installation with `--dry-run` (makes zero changes):**
   ```sh
   ssh root@169.254.1.0 '
     sh /tmp/carplay-stage/deploy/install.sh \
       --stage /tmp/carplay-stage/install-root --mode safe --dry-run
   '
   ```

4. **Install in safe mode (`wireless=0`, `wired=0`, `detach_usbfs_driver=0`, `ddp_handoff=0`, `mfi_i2c` off) and reboot:**
   ```sh
   ssh root@169.254.1.0 '
     sh /tmp/carplay-stage/deploy/install.sh \
       --stage /tmp/carplay-stage/install-root --mode safe &&
     systemctl reboot
   '
   ```
   `install.sh` temporarily remounts `/` as `rw`, backs up any overwritten files byte-for-byte into `/var/local/data/CarPlay/.install-backup/`, `sync`s, and remounts `/` back to `ro`.

   > [!IMPORTANT]
   > **`systemctl reboot` is required** (~3 minutes) so `HmiMain3D` loads the new `EntryCarPlay` plugin. A normal ignition off/on cycle does **not** reboot `HU_ENTRYNAV2` or reload HMI plugins.

5. **Verify after reboot:** Open **Media -> Apple CarPlay** in iDrive and confirm the menu entry appears and starts/stops cleanly without affecting iDrive stability.

## Configuration (`/var/local/data/CarPlay/carplay.conf`)

`/var/local` is persistent and mounted `rw,noexec`, so you can edit `/var/local/data/CarPlay/carplay.conf` over SSH without remounting `/`. Safe-mode defaults keep all active transports disabled until you opt in.

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `1` | Master config enable (`0` refuses daemon start with exit code `78`). |
| `wireless` | `0` | `1` enables Wireless CarPlay (ALPS SPP + `wland` AP + mDNS). |
| `wired` | `0` | `1` enables Wired USB CarPlay (`usbfs` + `carplay0` CDC-NCM TAP IPv6). |
| `mfi_i2c` | *(commented out)* | MFi I2C coprocessor path & 7-bit address, e.g. `mfi_i2c=/dev/i2c-0:0x10`. Leave off unless `/dev/i2c-0` ownership is handled via `ddp_handoff=1`. |
| `ddp_handoff` | `0` | `1` stops BMW's `DDPServer` cleanly (`systemctl stop DistributedDeviceProtocol.service` + `SIGTERM` to `DDPServer`) before opening `/dev/i2c-0` (see Known Limitation below). |
| `ddp_restore` | `reboot_prompt` | `reboot_prompt` writes `/tmp/entry-carplayd-ddp-needs-reboot` and shows `"Apple CarPlay (Reboot for BT audio)"` in the idle iDrive menu when `DDPServer` was stopped; `none` skips the prompt. |
| `detach_usbfs_driver` | `0` | `1` allows detaching an active kernel USB driver on unclaimed interfaces (`0` is safest and recommended). |
| `usb_port` | *(empty)* | Optional sysfs USB port filter (e.g. `3-1` for the center-console port). |
| `crash_guard_max` / `window_sec` / `stable_sec` | `3` / `120` / `120` | Disables `carplayd` until reboot after more than `crash_guard_max` rapid restarts within `window_sec` seconds. |

### Kill Switch & Immediate Stop

You can disable or stop `EntryNav2-CarPlay` at any time without remounting `/`:

```sh
# Prevent carplayd from starting (exits immediately with code 78):
touch /var/local/data/CarPlay/killswitch

# Stop a running carplayd session cleanly:
touch /tmp/entry-carplay-service/STOP

# Re-enable startup when ready:
rm -f /var/local/data/CarPlay/killswitch
```

*(If the crash-loop guard trips, remove `/tmp/entry-carplay-crash-guard /tmp/entry-carplay-disabled-until-reboot /var/local/data/CarPlay/app-guard /var/local/data/CarPlay/bootguard` or run `systemctl reboot`.)*

## Known Limitation

- **Bluetooth music stays off until reboot when `ddp_handoff=1`:** On `HU_ENTRYNAV2`, BMW's `DDPServer` (`DistributedDeviceProtocol.service`, `KillMode=none`) permanently holds `/dev/i2c-0` open. When `ddp_handoff=1` stops `DDPServer` so `carplayd` can access the MFi coprocessor, restarting `DistributedDeviceProtocol.service` or cycling ignition does **not** reopen `/dev/i2c-0` or restore Bluetooth audio. A full **`systemctl reboot`** (~3 minutes) is required to restore native `DDPServer` and Bluetooth music after ending a session that used `ddp_handoff=1`. See [docs/COEXISTENCE.md](docs/COEXISTENCE.md).

## Uninstall / Rollback

`install.sh` stores a persistent copy of `uninstall.sh` and `manifest.txt` in `/var/local/data/CarPlay/.install-backup/` (so uninstall keeps working even after `systemctl reboot` wipes `/tmp/carplay-stage`).

```sh
sh /var/local/data/CarPlay/.install-backup/uninstall.sh --dry-run
sh /var/local/data/CarPlay/.install-backup/uninstall.sh
systemctl reboot
```

Pass `--keep-data` to `uninstall.sh` if you want to preserve `/var/local/data/CarPlay/` files after restoring system binaries.

## Collecting Logs for a Bug Report

Connect to the head unit over ENET (`root@169.254.1.0`) and collect the files below from your laptop:

1. **Pull the HMI plugin and daemon logs:**
   ```sh
   scp root@169.254.1.0:/var/local/data/CarPlay/app.log .
   scp root@169.254.1.0:/tmp/entry-carplay-service.log .
   ```

2. **Capture `carplayd --compat` output:**
   ```sh
   ssh root@169.254.1.0 '
     LD_LIBRARY_PATH=/usr/local/lib:/opt/hmi/lib:/usr/lib:/lib \
     XDG_RUNTIME_DIR=/run/system/0 WAYLAND_DISPLAY=wayland-0 \
     /opt/carplay/carplayd --compat
   ' > compat.txt
   ```
   *(If `carplayd` is not installed yet, substitute `/tmp/carplayd` or `/tmp/carplay-stage/install-root/opt/carplay/carplayd`. Add `--wired` or `--mfi-i2c=/dev/i2c-0` if diagnosing wired USB or I2C access.)*

3. **Run the read-only `car_visit.sh` hardware probe and pull the archive:**
   ```sh
   scp scripts/probe/*.sh root@169.254.1.0:/tmp/
   ssh root@169.254.1.0 '
     chmod +x /tmp/car_visit.sh /tmp/bt_probe.sh /tmp/usb_probe.sh /tmp/native_carplay_probe.sh &&
     sh /tmp/car_visit.sh --daemon /opt/carplay/carplayd --out-dir /tmp/visit_out
   '
   scp root@169.254.1.0:/tmp/visit_out/carplay-visit-*.tar.gz .
   ```
   *(Pass `--native` for native `CARPLAY`/`DDPServer` inspection, or `--daemon /tmp/carplayd` if running before installation. Default `car_visit.sh` makes zero writes outside `/tmp/visit_out` and performs zero I2C transactions.)*

4. **(If relevant) Capture recent system journal / kernel logs:**
   ```sh
   ssh root@169.254.1.0 'journalctl -b --no-pager -n 200' > journal_tail.txt
   ssh root@169.254.1.0 'dmesg | tail -n 100' > dmesg_tail.txt
   ```

> [!CAUTION]
> **Privacy — redact before posting logs or archives publicly:**
> Before uploading logs, `compat.txt`, or `carplay-visit-*.tar.gz` to a GitHub issue, inspect and redact:
> - **VIN** (Vehicle Identification Number)
> - **Bluetooth and Wi-Fi MAC addresses**
> - **Phone name / device name**
> - **Serial numbers** (head unit, iPhone, USB serial strings)
> - **UDID / IMEI**
> - **Accessory identity UUID** (and any keys, pairing tokens, or passphrases)
> - **IP addresses other than `169.254.x.x`**

## Architecture Overview

`EntryNav2-CarPlay` combines a portable C++11 protocol core with a BMW `HU_ENTRYNAV2` platform layer:

- **CarPlay & iAP2 Protocol Core** (`src/core/`, `include/carplay/`, informed by [shihabal3amri/DiPlay](https://github.com/shihabal3amri/DiPlay)):
  - `airplay_crypto`: X25519 key exchange, Ed25519 signing/verification, SHA-512, HKDF-SHA512, HAP counter/label nonces, and ChaCha20-Poly1305 (RFC 8439 IETF AEAD) backed by vendored [Monocypher 4.0.3](https://monocypher.org/).
  - `tlv8_codec` & `bplist_codec`: HAP TLV8 fragmentation/reassembly and bounds-hardened Apple `bplist00` encoder/decoder.
  - `iap2_wire`, `iap2_link`, `iap2_session`: Stateful `0x4040` CSM framer, iAP2 link/session state machines, `0x4301` `CarPlayStartSession` for Wired IPv6 and Wireless Wi-Fi, plus `0x4300`/`0x4e0d`/`0x4e0e`/`0x5701`/`0x5703`.
  - `pairing`, `srp6a`, `control_cipher`, `airplay_session`, `event_channel`: HAP Pair-Setup (SRP-6a) & Pair-Verify, encrypted RTSP/HTTP control & event channels, `/info` & `SETUP`/`RECORD`/`TEARDOWN` routing, and `/auth-setup` MFiSAP (`mfi_sap`).
  - `airplay_hid`, `screen_stream`, `audio_rtp`, `mic_uplink`, `ntp_timing`, `usb_descriptors`, `cdc_ncm`: HID descriptors & BMW `ZBE3` mapping, 128-byte AirPlay screen frame decryption + Annex B conversion, LPCM/RTP audio + mic uplink, NTP 32.32 clock sync, and USB/CDC-NCM NTB-16 framing.
- **BMW `HU_ENTRYNAV2` Platform & HMI Layer** (`src/platform/`, `src/hmi/`, `src/daemon/`, `hmiapp/`, aligned with [Jiraiya43/EntryNav2-Android-Auto](https://github.com/Jiraiya43/EntryNav2-Android-Auto)):
  - Runtime `dlopen()`-only HAL (`EvoVideo`/`omap_dmabuf`, `EvoIlm`, `EvoKnob` vMOST `ZBE3`, `EvoTouch`, `EvoAudio`/`EvoMic`), `SessionServer`, `CarPlayDaemon`, `CarPlayConnectivity`.
  - Wired `usbfs` + `carplay0` TAP bridge (`usb_host`, `usb_carplay_bridge`, `tap_iface`), Wireless ALPS SPP + `wland`/`hostapd` + `mdnsd` (`alps_spp`, `evo_ap`, `evo_wlan`, `mdns_advertiser`, `wifi_link`), I2C MFi coprocessor (`mfi_i2c`), opt-in `DdpHandoff`, safe-mode guards (`safe_mode`), and `libEntryCarPlay.so` RHMI plugin.

## Project Layout

```text
EntryNav2-CarPlay/
├── include/carplay/          # Public C++11 protocol & platform headers
├── src/
│   ├── core/                 # OS-agnostic CarPlay / AirPlay / iAP2 protocol core
│   ├── platform/             # Reactor, sockets, USB, BT/Wi-Fi, MFi I2C, EVO HAL
│   ├── hmi/                  # HmiMain3D RHMI plugin (libEntryCarPlay.so)
│   └── daemon/               # carplayd entry point & --compat self-check
├── hmiapp/                   # EntryCarPlay.xml, manifest & resource packer
├── scripts/
│   ├── ci/                   # Host/ARMv7 build, symbol, probe & repo content checks
│   ├── deploy/               # install.sh, uninstall.sh & systemd unit
│   └── probe/                # Read-only car_visit.sh, bt_probe.sh, usb_probe.sh, native_carplay_probe.sh
├── docs/                     # BUILD.md, CAR_VISIT.md, COEXISTENCE.md, VEHICLE_FACTS.md, etc.
├── third_party/monocypher/   # Vendored Monocypher 4.0.3 (BSD-2-Clause OR CC0-1.0)
├── tests/                    # Host & ARMv7 unit, e2e & fuzz test suites
├── Makefile                  # Host tests, daemon/plugin builds & ARMv7 targets
└── PROGRESS.md               # Development status & verification log
```

## Building & Running Tests

Requires `g++`, `gcc`, `ar`, and GNU `make` (see [docs/BUILD.md](docs/BUILD.md) for Windows `w64devkit`, Linux/Clang, and Docker Debian 7 `wheezy` GCC 4.7.2 ARMv7 details):

```sh
make test-host
```

On Windows PowerShell/CMD when `.exe` suffix is needed:

```sh
make test-host BIN_EXT=.exe
```

Cross-compile the ARMv7 binaries (`carplayd`, `libEntryCarPlay.so`) and stage the head-unit rootfs layout:

```sh
make arm-daemon
make arm-hmiapp
make BUILD_DIR=build/arm-entrynav2 hmiapp-res install-layout
```

## Licensing & Third-Party Attributions

- Repository source code is under the GNU General Public License v3.0 ([LICENSE](LICENSE)), with upstream-derived platform modules documented in [docs/THIRD_PARTY.md](docs/THIRD_PARTY.md). Note the `PolyForm-Noncommercial-1.0.0` notice in [docs/THIRD_PARTY.md](docs/THIRD_PARTY.md) for the `EntryNav2-Android-Auto`-derived platform files.
- **Monocypher 4.0.3** (`third_party/monocypher/`): Copyright (c) 2017–2020 Loup Vaillant, dual-licensed under **BSD-2-Clause OR CC0-1.0** ([third_party/monocypher/LICENCE.md](third_party/monocypher/LICENCE.md)).
- Vehicle constants and coexistence findings are tracked in [docs/VEHICLE_FACTS.md](docs/VEHICLE_FACTS.md) and [docs/COEXISTENCE.md](docs/COEXISTENCE.md).
