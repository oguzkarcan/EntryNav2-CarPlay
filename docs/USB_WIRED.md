# Wired USB CarPlay Transport (`usbfs` + Userspace CDC-NCM + TAP)

## 1. Why Userspace CDC-NCM Is Needed on `HU_ENTRYNAV2`

As documented in [TARGET_HARDWARE.md](TARGET_HARDWARE.md) (§4), the target head unit runs Linux `3.12.25-FR21.0` without `cdc_ncm.ko`, `usb_f_ncm.ko`, or `ipheth.ko` in the kernel or module tree (`/lib/modules/3.12.25-FR21.0/kernel/drivers/net/usb/` contains only `asix.ko`, `ax88179_178a.ko`, and `usbnet.ko`). When an iPhone enters CarPlay USB mode, it exposes:

1. An **Apple iAP2 / USBMUX** interface (vendor-specific bulk endpoints) for control/session signaling and authentication (`0x4040` CSM frames when iAP2 bulk is used, or USBMUX when iOS exposes `0xff/0xfe/0x02`).
2. A **USB CDC-NCM 1.0** (`02/0d` control + `0a/00` data alt 1) virtual Ethernet interface (typically paired with Apple Ethernet `0xff/0xfd/0x01` in CarPlay mode), over which AirPlay/CarPlay TCP/UDP streams run using **IPv6 link-local (`fe80::/64`)** addressing.

Because the kernel cannot create a `usb0` network device for CDC-NCM, this module implements the CDC-NCM driver in userspace over `/dev/bus/usb/BBB/DDD` (`usbfs`) and bridges Ethernet frames to a Linux `IFF_TAP | IFF_NO_PI` virtual interface (`/dev/net/tun`). Once the TAP interface is brought `UP`, the kernel's IPv6 stack creates the link-local interface and `SessionServer` / `MediaEngine` continue to use ordinary POSIX sockets.

---

## 2. Data Flow & Architecture

```text
+-------------------------------------------------------------------------+
| Apple iPhone (USB Device, idVendor 0x05ac)                              |
|  - Apple iAP2 (ff/f0/00, unverified) and/or USBMUX (ff/fe/02, verified) |
|  - CDC-NCM Control (02/0d) + Data (0a/00 alt 1) Bulk IN/OUT endpoints   |
|  - Apple Ethernet (ff/fd/01) indicating active CarPlay mode (verified)  |
+-----------------------------------+-------------------------------------+
                                    | USB 2.0 (usbfs ioctls + async URBs)
                                    v
+-------------------------------------------------------------------------+
| UsbHost (/sys/bus/usb/devices hotplug + /dev/bus/usb/BBB/DDD)           |
|  - Polls sysfs on Reactor timer (validates port, skips hubs & fixed)    |
|  - Checks USBDEVFS_GETDRIVER before claim; refuses "usbfs" hijack       |
|  - Registers usbfs fd in Reactor with kPollOut -> USBDEVFS_REAPURBNDELAY |
+-----------------------------------+-------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| UsbCarPlayBridge (Reactor-driven state machine)                         |
|                                                                         |
|  [1] usb_descriptors: tiered config selection (CarPlay vs iOS 17+ NCM)  |
|  [2] Optional 0xc0/0x52 CarPlay mode request + 0xc0/0x45 rejection diag |
|  [3] iAP2 Stream <---> onIap2Data() / writeIap2()                       |
|  [4] CDC-NCM NTB-16 Codec (cdc_ncm):                                    |
|       Bulk IN  -> Ntb16StreamDecoder -> Ethernet frames -> TapIface     |
|       TapIface -> packNtb16Batch() (multi-frame)        -> Bulk OUT     |
|       (tolerates pre-StartCarPlaySession Bulk OUT NAKs cleanly)         |
+-----------------------------------+-------------------------------------+
                                    | read() / write() Ethernet frames
                                    v
+-------------------------------------------------------------------------+
| TapIface (/dev/net/tun, IFF_TAP | IFF_NO_PI, e.g. "carplay0")           |
|  - Locally-administered unicast MAC via SIOCSIFHWADDR                   |
|  - Brought up via SIOCSIFFLAGS (IFF_UP | IFF_RUNNING)                   |
|  - Kernel auto-assigns IPv6 link-local (fe80::/64, scope = ifindex)     |
+-----------------------------------+-------------------------------------+
                                    | Standard POSIX IPv6 Sockets
                                    v
+-------------------------------------------------------------------------+
| SessionServer (:7000) & MediaEngine (AirPlay video/audio/HID/iAP2)      |
+-------------------------------------------------------------------------+
```

---

## 3. Component Summary

| Component | Layer | Responsibility |
| --- | --- | --- |
| `usb_descriptors` (`include/carplay/usb_descriptors.hpp`) | Core (pure) | Parses Device, Configuration, Interface, Endpoint, IAD, and CDC functional descriptors; discovers iAP2, USBMUX (`ff/fe/02`, preferred EPs `0x04`/`0x85`), Apple Ethernet (`ff/fd/01`), and CDC-NCM (`02/0d` + `0a/00` alt `1` preferred); scores CarPlay vs non-CarPlay configs (`is_carplay_mode`). |
| `cdc_ncm` (`include/carplay/cdc_ncm.hpp`) | Core (pure) | Parses `GET_NTB_PARAMETERS` (28B); validates and decodes NTH16/NDP16 frames (`NCM0`/`NCM1` CRC-32, chains, cycles, overlaps, `max_datagrams = 256` cap); `Ntb16StreamDecoder` reassembles split/coalesced NTBs across Bulk IN URBs, handles optional 1B `0x00` short-packet padding, and resynchronizes on corruption; batches OUT NTB-16 blocks. |
| `UsbHost` (`include/carplay/platform/usb_host.hpp`) | Platform | Sysfs hotplug polling (`usb_port_filter`, hub/fixed filtering, ignored-device tracking), `USBDEVFS_GETDRIVER` pre-claim check, `USBDEVFS_RESET`, `0xc0/0x52` & `0xc0/0x45` control helpers, `16 MiB` URB bound, immediate `ENODEV`/`ESHUTDOWN` disconnect detection. |
| `TapIface` (`include/carplay/platform/tap_iface.hpp`) | Platform | Opens `/dev/net/tun` (`IFF_TAP \| IFF_NO_PI`), derives locally-administered MAC, configures MAC/MTU/`IFF_UP`, reports `ifindex`, non-blocking `Reactor` I/O, `/proc/net/if_inet6` IPv6 link-local query. |
| `UsbCarPlayBridge` (`include/carplay/platform/usb_carplay_bridge.hpp`) | Platform | Glue state machine (`Stopped -> Waiting -> Configuring -> Iap2Only / Active`): ownership-safe claiming (`detach_usbfs_driver = false`), iOS 17+ `USBMUX+NCM` transition/fallback (`ncm_allow_control_fallback`), `Ntb16StreamDecoder` IN path, pre-ready NCM OUT NAK tolerance, clean teardown. |

### TAP IPv6 Link-Local Address Assignment

`TapIface` sets a deterministic locally-administered unicast MAC (`(octet0 | 0x02) & 0xfe`) derived from `TapConfig::mac_seed` (distinct from the iPhone's own `iMACAddress` to avoid duplicate-MAC collisions) and raises `IFF_UP | IFF_RUNNING` via `SIOCSIFFLAGS`. Once up, Linux automatically assigns a `fe80::/64` link-local address on that interface unless `net.ipv6.conf.<ifname>.disable_ipv6` is `1`. `TapIface::queryIpv6LinkLocal()` reads `/proc/net/if_inet6` to retrieve the active `fe80::...%<ifindex>` address for iAP2 `CarPlayStartSession (0x4301)`.

---

## 4. Protocol Constants: Verified vs. Unverified

### Verified Constants (USB-IF Specifications & `DiPlay-main`)

| Constant / Tuple | Value | Verification Source |
| --- | --- | --- |
| Apple Vendor ID (`kAppleVendorId`) | `0x05ac` | USB-IF / `DiPlay` `IphoneUsbHost.kt` |
| USB Hub Class (`kClassHub`) | `0x09` | USB 2.0 Spec / `DiPlay` `IphoneUsbHost.kt` |
| CDC-NCM Control (`kClassCommunications` / `kSubClassCdcNcm`) | `0x02 / 0x0d` | USB CDC-NCM 1.0 / `DiPlay` `NcmFunctionDiscovery.kt` |
| CDC-NCM Data (`kClassCdcData` / `kProtocolCdcNcmData`, alt) | `0x0a / 0x00 / 0x01`, alt `1` preferred | USB CDC-NCM 1.0 / `DiPlay` `NcmFunctionDiscovery.kt` |
| Apple USBMUX (`kAppleUsbmux*`) | `0xff / 0xfe / 0x02`, preferred EPs `0x04` OUT / `0x85` IN | `DiPlay` `IphoneCarPlayConfiguration.kt` |
| Apple Ethernet (`kAppleEthernet*`, alias `kAppleEap*`) | `0xff / 0xfd / 0x01` (indicates CarPlay mode) | `DiPlay` `IphoneCarPlayConfiguration.kt` |
| CarPlay Mode Switch (`kAppleReqCarPlayConfig`) | `bmRequestType=0xc0`, `bRequest=0x52`, `wValue=0x0000`, `wIndex=0x0004`, `wLength=1` (IN) | `DiPlay` `IphoneUsbHost.kt` (`CARPLAY_CONFIGURATION_REQUEST`) |
| Apple USB Mode Query (`kAppleReqGetUsbMode`) | `bmRequestType=0xc0`, `bRequest=0x45`, `wValue=0`, `wIndex=0`, `wLength=4` (IN) | `DiPlay` `IphoneUsbHost.kt` (`GET_USB_MODE_REQUEST`) |
| Standard `GET_CONFIGURATION` | `bmRequestType=0x80`, `bRequest=0x08`, `wLength=1` | USB 2.0 / `DiPlay` `IphoneUsbHost.kt` |
| NTB-16 Limits & Signatures | `NCMH`/`NCM0`/`NCM1`, 12B NTH16, 16B min NDP16, `kMaxNtb16Datagrams = 256` | USB CDC-NCM 1.0 / `DiPlay` `Ntb16Codec.kt` |
| NCM Requests | `0x80` (`GET_NTB_PARAMETERS`), `0x84` (`SET_NTB_FORMAT`), `0x86` (`SET_NTB_INPUT_SIZE`), `0x43` (`SET_ETHERNET_PACKET_FILTER`) | USB CDC-NCM 1.0 |

### Unverified Constants (Must Be Validated on Live iPhone / Head Unit)

- `kAppleIap2Class = 0xff`, `kAppleIap2SubClass = 0xf0`, `kAppleIap2Protocol = 0x00` — `unverified`: Apple iAP2 USB bulk interface tuple assumed for raw iAP2 over USB bulk (`DiPlay` uses USBMUX TCP instead of bulk `0xff/0xf0/0x00`; `Iap2SelectionCriteria` supports wildcard/runtime override).

---

## 5. Verification Corrections (`old -> new`)

| Area | Old Behavior | New Verified Behavior (`DiPlay-main` / `AA 0.12.0`) |
| --- | --- | --- |
| **Apple CarPlay switch control transfer** | `bmRequestType = 0x40` (Host-to-Device OUT), `bRequest = 0x51`, `wValue = 0x0001`, `wIndex = 0x0000`, `wLength = 0` | `bmRequestType = 0xc0` (Vendor Device-to-Host IN), `bRequest = 0x52`, `wValue = 0x0000`, `wIndex = 0x0004`, `wLength = 1` (verifies 1 byte returned; `IphoneUsbHost.kt`), plus `0xc0/0x45` mode diagnostic on rejection. |
| **CarPlay vs. iOS 17+ non-CarPlay NCM** | Treated any config with `CDC-NCM` + `USBMUX` as ready (`0xff/0xfd/0x01` only gave a +1 score bonus) | `is_carplay_mode` requires `Apple Ethernet (0xff/0xfd/0x01)` alongside `NCM`; when `auto_request_carplay_switch` is enabled on `USBMUX + NCM` without `Apple Ethernet`, tries `0xc0/0x52` and waits for re-enumeration first, falling back to `USBMUX+NCM` only if rejected or already tried (`WiredConfigurationAction.kt`). |
| **USBMUX discovery & endpoints** | `CarPlayUsbSelection` only tracked `bool has_usbmux` | Extracts full `UsbmuxInterfaceSelection` preferring endpoints `0x04` OUT / `0x85` IN (with unique bulk pair fallback) and rejects bare `PTP + USBMUX` configs (`IphoneCarPlayConfiguration.kt`). |
| **NCM Data alternate setting** | Picked first alt setting with Bulk IN + Bulk OUT | `pickDataAltSetting()` prefers `alternate_setting == 1` (`kNcmDataAltSetting`, `NcmFunctionDiscovery.kt`), falling back to first active alt setting. |
| **NTB-16 IN decoding & safety** | Single-buffer `parseNtb16()` per URB; unbounded datagram count; no byte-sum overlap check | Adds `kMaxNtb16Datagrams = 256` cap and total-datagram-bytes `<= block_len` overlap guard (`Ntb16Codec.kt`), plus stateful `Ntb16StreamDecoder` handling split/coalesced NTBs, optional `0x00` short-packet padding, and bounded resync (`NcmUsbBridge.kt`). |
| **Pre-ready NCM Bulk OUT NAKs** | Counted any non-zero NCM OUT status toward `max_consecutive_urb_errors` | Ignores non-disconnect NCM OUT errors until the first NCM OUT URB completes with `status == 0` (`ncm_out_not_ready_drops`, `NcmUsbBridge.kt`). |
| **Linux 3.12 `usbfs` robustness** | Enumerated any sysfs dir; no driver check before detach/claim; ignored `ENODEV` on submit | Validates port names (`isValidUsbPortName`), skips hubs & `removable == "fixed"`, supports `usb_port_filter`, checks `USBDEVFS_GETDRIVER`, adds `USBDEVFS_RESET`, caps URBs at 16 MiB, disconnects immediately on `ENODEV`/`ESHUTDOWN`, tracks ignored devices until unplug (`AA 0.12.0`). |

---

## 6. Sysroot Ownership Analysis & Coexistence Policy

Inspection of the head unit sysroot (`/home/ozzy/Projects/EntryNav2-CarPlay-Assets/sysroot`) shows:

1. **Userspace Apple/USB stack (`MediaPlayer` / `CARPLAY`):**
   - `/usr/local/lib/libauxin-apple.so.0` symlinks to `../../../opt/app/usr/MediaPlayer/lib/libauxin-apple.so.0` (alongside `libauxin-aoap.so.0` and `libauxin-player.so.0`), and the image contains `/opt/app/usr/MediaPlayer/bin/CARPLAY`. (`/opt/app` is not populated in the partial sysroot extract, so these symlinks dangle offline.)
   - `/lib/libusb-1.0.so.0.1.0` uses Linux `usbfs` directly (`/dev/bus/usb`, `usbfs_scan_busdir`, `usbfs_get_active_config`). When a userspace `libusb`/`usbfs` process such as `MediaPlayer` or `CARPLAY` claims a USB interface, the kernel binds the interface's driver name as `"usbfs"`.
   - `/usr/local/lib/libpiapom.so.0.0.0` (`PiaPortingMasterStateChart`) links only `libstdc++`, `libm`, `libc`, `libgcc_s` and has no `usbfs` or `05ac` strings (it is a state/audio porting module rather than a USB host driver).
2. **`udev` rules and kernel modules:**
   - `/lib/udev/rules.d/80-udisks.rules` only sets presentation icons/tags for `05ac:8403` and `05ac:1209`; no `udev` rule spawns a CarPlay daemon or alters `/dev/bus/usb` permissions on attach.
   - `/lib/modules/3.12.25-FR21.0/kernel/` ships `snd-usb-audio.ko`, `usbhid.ko`, and `hid-generic.ko` (which may bind to iPhone USB audio/HID interfaces — note that `SET_CONFIGURATION` returns `EBUSY` on Linux if a kernel driver holds an active-config interface), and does **not** ship `cdc_ncm.ko` or `ipheth.ko`.

### Safe Coexistence Policy in `UsbHost` & `UsbCarPlayBridge`

- **Never hijack `"usbfs"` by default:** `UsbHostConfig::detach_usbfs_driver` and `UsbCarPlayBridgeConfig::detach_usbfs_driver` both default to `false` (confirmed in-car policy in `EntryNav2-Android-Auto` `docs/USB.md`: never detach a BMW driver/process).
- **Pre-claim check (`USBDEVFS_GETDRIVER`):** Before claiming any iAP2 or CDC-NCM interface, `UsbHost::claimInterfaceWithStatus()` queries `USBDEVFS_GETDRIVER`.
  - If the bound driver is `"usbfs"` and `detach_usbfs_driver == false`, `claimInterfaceWithStatus()` refuses immediately with `kUsbClaimBusyUserspace` (`USBDEVFS_DISCONNECT` is **not** issued).
  - If `USBDEVFS_CLAIMINTERFACE` fails with `EBUSY` (race condition or residual binding), it re-queries `USBDEVFS_GETDRIVER` and classifies `kUsbClaimBusyUserspace` vs `kUsbClaimBusyKernel`.
  - If a kernel driver (e.g. `snd-usb-audio`, `usbhid`, `cdc_ncm`) is bound and `detach_kernel_driver` is disabled, it refuses with `kUsbClaimBusyKernel`.
- **Clear reporting & anti-retry loop:** On `kUsbClaimBusyUserspace` or `kUsbClaimBusyKernel`, `UsbCarPlayBridge` increments `stats_.ownership_conflicts`, emits an explicit `onBridgeError` message naming `"usbfs"` (`MediaPlayer`/`CARPLAY`) or the kernel driver, calls `usb_->ignoreCurrentDevice()` so the device is left untouched until physical unplug or address change (`forgetGoneIgnored()`), and transitions cleanly back to `kBridgeWaiting`.
- **USB-only isolation & `/var/local/data/CarPlay/usb` contract (upstream `docs/USB.md`, `v0.13.0-rc.5`):**
  - When USB mode is configured via `/var/local/data/CarPlay/usb` (`contract::kUsb`), Bluetooth (ALPS SPP / RFCOMM) and Wi-Fi (`wland` / `hostapd`) are **never** touched — including on head units with unknown BT library builds such as the 2017 F20 (`15024/480/36` ALPS layout, where USB mode still works while wireless is skipped as wireless-only).
  - Empty `/var/local/data/CarPlay/usb` accepts any external non-hub, removable USB port; a non-empty file pins one sysfs port name (e.g., `3-1`, validated strictly via `isValidUsbPortName()`); invalid file contents must block USB startup cleanly rather than guessing a port.
  - Phone USB reset (`USBDEVFS_RESET`) is reserved strictly for re-trying/clearing the phone's own residual accessory state without touching BMW drivers (upstream caps retries at 3 per physical plug).
- **Explicit override:** Setting `detach_usbfs_driver = true` is reserved exclusively for deployments where the user intentionally stops or overrides native `MediaPlayer`/`CARPLAY`.

---

## 7. Open Hardware Questions for Target Bring-Up

1. **USB Port Role (`48890000.usb` Host vs. Peripheral):**
   `TARGET_HARDWARE.md` observed UDC `48890000.usb` with `g_ffs` / `libcomposite` / `configfs` loaded. Verify which physical USB port (armrest / center console) acts as USB **host** vs **peripheral/OTG**, and set `UsbHostConfig::usb_port_filter` if needed to pin a single port.
2. **`MediaPlayer` / `CARPLAY` Live Behavior:**
   Run `scripts/probe/usb_probe.sh` on the target unit with an iPhone plugged in to confirm whether `MediaPlayer` or `CARPLAY` actually opens `/dev/bus/usb/BBB/DDD` on that vehicle coding (`CarPlay` enabled vs disabled in FA/coding).
3. **Kernel Drivers & Permissions:**
   Confirm `/dev/bus/usb/BBB/DDD` and `/dev/net/tun` permissions under the daemon user, whether `snd-usb-audio`/`usbhid` binds any iPhone interface (`SET_CONFIGURATION` `EBUSY` interaction), and whether `net.ipv6.conf.default.disable_ipv6` is `0`.
4. **Live iPhone USB Descriptors & iAP2 Interface:**
   Verify on a live iPhone whether CarPlay exposes iAP2 over raw bulk (`0xff/0xf0/0x00`), USBMUX (`0xff/0xfe/0x02`), or HID-iAP2 (`0x03/0x00/0x00`).

---

## 8. Running the Read-Only Hardware Probe

Copy `scripts/probe/usb_probe.sh` to the head unit (or pipe over SSH) and run it with an iPhone plugged in and unplugged. The script **never writes** to any file, sysfs attribute, proc entry, or device node, and now reports sysfs `removable` status, processes holding open `/dev/bus/usb/*` file descriptors, and `MediaPlayer`/`CARPLAY` process status:

```sh
ssh root@<head-unit-ip> 'sh -s' < scripts/probe/usb_probe.sh > usb_probe_output.txt
```
