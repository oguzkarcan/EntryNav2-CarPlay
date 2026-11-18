# Wired USB CarPlay Transport (`usbfs` + Userspace CDC-NCM + TAP)

## 1. Why Userspace CDC-NCM Is Needed on `HU_ENTRYNAV2`

As documented in [TARGET_HARDWARE.md](TARGET_HARDWARE.md) (§4), the target head unit runs Linux `3.12.25-FR21.0` without `cdc_ncm.ko` or `usb_f_ncm.ko` in the kernel or module tree. When an iPhone enters CarPlay USB mode, it exposes:

1. An **Apple iAP2** bulk interface (vendor-specific class) for iAP2 Control Session Messages (`0x4040` CSM frames, authentication, and `CarPlayStartSession 0x4301`).
2. A **USB CDC-NCM 1.0** (`02/0d` control + `0a/00` data) virtual Ethernet interface, over which AirPlay/CarPlay TCP/UDP streams run using **IPv6 link-local (`fe80::/64`)** addressing.

Because the kernel cannot create a `usb0` network device for CDC-NCM, this module implements the CDC-NCM driver in userspace over `/dev/bus/usb/BBB/DDD` (`usbfs`) and bridges Ethernet frames to a Linux `IFF_TAP | IFF_NO_PI` virtual interface (`/dev/net/tun`). Once the TAP interface is brought `UP`, the kernel's IPv6 stack creates the link-local interface and `SessionServer` / `MediaEngine` continue to use ordinary POSIX sockets.

---

## 2. Data Flow & Architecture

```text
+-------------------------------------------------------------------------+
| Apple iPhone (USB Device, idVendor 0x05ac)                              |
|  - iAP2 Bulk IN/OUT endpoints                                           |
|  - CDC-NCM Control (02/0d) + Data (0a/00 alt 1) Bulk IN/OUT endpoints   |
+-----------------------------------+-------------------------------------+
                                    | USB 2.0 (usbfs ioctls + async URBs)
                                    v
+-------------------------------------------------------------------------+
| UsbHost (/sys/bus/usb/devices hotplug + /dev/bus/usb/BBB/DDD)           |
|  - Polls sysfs on Reactor timer (no libudev)                            |
|  - Registers usbfs fd in Reactor with kPollOut -> USBDEVFS_REAPURBNDELAY |
+-----------------------------------+-------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| UsbCarPlayBridge (Reactor-driven state machine)                         |
|                                                                         |
|  [1] usb_descriptors: select config + iAP2 + CDC-NCM control/data       |
|  [2] iAP2 Stream <---> onIap2Data() / writeIap2() (for iAP2 link layer) |
|  [3] CDC-NCM NTB-16 Codec (cdc_ncm):                                    |
|       Bulk IN  -> parseNtb16() -> Ethernet frames -> TapIface           |
|       TapIface -> packNtb16Batch() (multi-frame)  -> Bulk OUT           |
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
| `usb_descriptors` (`include/carplay/usb_descriptors.hpp`) | Core (pure) | Parses Device, Configuration, Interface, Endpoint, IAD, and CDC functional descriptors (Header, Union, Ethernet Networking `iMACAddress`, NCM); scores & selects iAP2 and CDC-NCM interfaces; decodes UTF-16LE USB strings. |
| `cdc_ncm` (`include/carplay/cdc_ncm.hpp`) | Core (pure) | Parses `GET_NTB_PARAMETERS` (28B); validates and decodes NTH16/NDP16 frames (`NCM0` and `NCM1` CRC-32, `wNextNdpIndex` chains, cycle/overlap/bounds checks); batches multiple Ethernet frames into OUT NTB-16 blocks honoring `wNdpOutDivisor`/`Remainder`/`Alignment` and `wNtbOutMaxDatagrams`. |
| `UsbHost` (`include/carplay/platform/usb_host.hpp`) | Platform | Sysfs hotplug polling (`Reactor` timer), `usbfs` open + descriptor read + `USBDEVFS_*` ioctls (`SETCONFIGURATION`, `USBDEVFS_DISCONNECT` + `CLAIMINTERFACE`, `SETINTERFACE`, `CONTROL`, `SUBMITURB`, `REAPURBNDELAY` on `kPollOut`, `DISCARDURB`). OS layer abstracted behind `UsbDevfsInterface`. |
| `TapIface` (`include/carplay/platform/tap_iface.hpp`) | Platform | Opens `/dev/net/tun` (`IFF_TAP \| IFF_NO_PI`), derives locally-administered MAC, configures MAC/MTU/`IFF_UP`, reports `ifindex`, non-blocking `Reactor` `kPollIn`/`kPollOut` frame I/O, `/proc/net/if_inet6` IPv6 link-local query. OS layer abstracted behind `TapOsInterface`. |
| `UsbCarPlayBridge` (`include/carplay/platform/usb_carplay_bridge.hpp`) | Platform | Glue state machine (`Stopped -> Waiting -> Configuring -> Iap2Only / Active`): configuration selection, NCM setup (`SET_NTB_INPUT_SIZE`, `SET_ETHERNET_PACKET_FILTER`), iAP2 Bulk IN/OUT stream, NCM <-> TAP pumping, clean teardown on removal. |

### TAP IPv6 Link-Local Address Assignment

`TapIface` sets a deterministic locally-administered unicast MAC (`(octet0 | 0x02) & 0xfe`) derived from `TapConfig::mac_seed` (distinct from the iPhone's own `iMACAddress` to avoid duplicate-MAC collisions) and raises `IFF_UP | IFF_RUNNING` via `SIOCSIFFLAGS`. Once up, Linux automatically assigns a `fe80::/64` link-local address on that interface unless `net.ipv6.conf.<ifname>.disable_ipv6` is `1`. `TapIface::queryIpv6LinkLocal()` reads `/proc/net/if_inet6` to retrieve the active `fe80::...%<ifindex>` address for iAP2 `CarPlayStartSession (0x4301)`.

---

## 4. Protocol Constants: Verified vs. Unverified

### Verified (Public USB-IF Specifications)

- **USB 2.0 Specification:** standard descriptor types (`0x01..0x05`, `0x0b`), endpoint direction/type bits (`0x80`, `0x02` Bulk, `0x03` Interrupt), Apple Inc. USB-IF Vendor ID (`0x05ac`).
- **USB CDC 1.2 / CDC-NCM 1.0 Specification:**
  - Control interface: Class `0x02`, SubClass `0x0d` (`CDC NCM`), Data interface: Class `0x0a`, Protocol `0x01`.
  - Class-specific descriptors (`0x24`): Header (`0x00`), Union (`0x06`), Ethernet (`0x0f`), NCM (`0x1a`).
  - NTB-16 signatures: `NCMH` (`0x484d434e`), `NCM0` (`0x304d434e`), `NCM1` (`0x314d434e`).
  - Requests: `GET_NTB_PARAMETERS` (`0x80`), `SET_NTB_FORMAT` (`0x84`), `SET_NTB_INPUT_SIZE` (`0x86`), `SET_ETHERNET_PACKET_FILTER` (`0x43`).

### Unverified Constants (Must Be Validated on Live iPhone / Head Unit)

All Apple-specific USB class codes and vendor control requests are marked `unverified` in source headers:

- `kAppleIap2Class = 0xff`, `kAppleIap2SubClass = 0xf0`, `kAppleIap2Protocol = 0x00` — Apple iAP2 USB bulk interface tuple (note: `Iap2SelectionCriteria` allows protocol wildcard or override at runtime).
- `kAppleUsbmuxClass = 0xff`, `kAppleUsbmuxSubClass = 0xfe`, `kAppleUsbmuxProtocol = 0x02` — Apple `usbmux` interface.
- `kAppleEapClass = 0xff`, `kAppleEapSubClass = 0xfd`, `kAppleEapProtocol = 0x01` — Apple Ethernet / EAP interface.
- `AppleCarPlaySwitchRequest` defaults (`bmRequestType = 0x40`, `bRequest = 0x51`, `wValue = 0x0001`, `wIndex = 0x0000`) — Apple vendor control transfer hook to request CarPlay/NCM mode switch (some iOS versions/flows use `bRequest = 0x52` or rely on `SET_CONFIGURATION` directly without a vendor request; `auto_request_carplay_switch` is `false` by default and configurable).

---

## 5. Open Hardware Questions for Target Bring-Up

1. **USB Port Role (`48890000.usb` Host vs. Peripheral):**
   `TARGET_HARDWARE.md` observed UDC `48890000.usb` with `g_ffs` / `libcomposite` / `configfs` loaded. On a dual-role TI DRA7xx (`dwc3`) controller, we need to verify which physical USB port (armrest / center console) acts as USB **host** vs **peripheral/OTG**, and whether `48890000.usb` stays in peripheral mode while another controller (`488d0000.usb` / `xhci` / `ehci`) serves the iPhone port.
2. **Coexistence with `/dev/ffs-carlife/ep0` (`carlife` FunctionFS Gadget):**
   Which BMW/supplier daemon owns `/dev/ffs-carlife`, whether it only uses a secondary UDC or competes for the iPhone port role, and whether CarLife/native MediaPlayer tries to claim the iPhone via `usbfs` or `libpiapom.so.0` when an iPhone is plugged in.
3. **Kernel Drivers & Permissions:**
   Confirm whether `/dev/bus/usb/BBB/DDD` and `/dev/net/tun` are writable by the user/group under which `carplayd` runs, whether `ipheth` or `usbhid` binds to any iPhone interface (handled by `USBDEVFS_DISCONNECT`), and whether `net.ipv6.conf.default.disable_ipv6` is `0`.
4. **Live iPhone Descriptor & Mode-Switch Behavior:**
   Confirm whether modern iOS devices already expose the iAP2 + CDC-NCM configuration in `bNumConfigurations` on initial plug-in (selectable via `USBDEVFS_SETCONFIGURATION`), or require the vendor control request (`0x51`/`0x52`) to re-enumerate with CDC-NCM.

---

## 6. Running the Read-Only Hardware Probe

Copy `scripts/probe/usb_probe.sh` to the head unit (or pipe over SSH) and run it with an iPhone plugged in and unplugged. The script **never writes** to any file, sysfs attribute, proc entry, or device node:

```sh
ssh root@<head-unit-ip> 'sh -s' < scripts/probe/usb_probe.sh > usb_probe_output.txt
```
