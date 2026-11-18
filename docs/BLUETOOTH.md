# Bluetooth RFCOMM & SDP Discovery (`F4-P2`)

This document describes the Bluetooth RFCOMM transport, SDP service-record builder, runtime capability probe, and read-only head-unit inspection script for wireless CarPlay bring-up on `HU_ENTRYNAV2`.

## 1. Context & Stack Uncertainty

Wireless CarPlay begins over Bluetooth: the head unit and iPhone establish an iAP2 link over RFCOMM (or an equivalent vendor SPP/iAP2 transport), perform iAP2 identification and authentication, and exchange Wi-Fi AP credentials (`0x5700`–`0x5703` in [iap2_wire.hpp](../include/carplay/iap2_wire.hpp)) so the iPhone joins the head unit's Wi-Fi AP and starts AirPlay over TCP/UDP.

As of Phase 4 (`F4-P2`), live SSH inspection ([TARGET_HARDWARE.md](TARGET_HARDWARE.md)) has verified only the Bluetooth ALSA PCM routes (`bluetooth_out` / `bluetooth_in` on `hw:0,1` at 16 kHz) and the presence of `/opt/app/usr/MediaPlayer/bin/CARPLAY` + `/usr/local/lib/libpiapom.so.0`. It is **not yet confirmed** on the target unit whether:

- the kernel exposes `AF_BLUETOOTH` / `BTPROTO_RFCOMM` (`bluetooth.ko`, `rfcomm.ko`) and an HCI device under `/sys/class/bluetooth`,
- userland runs BlueZ 4 (`sdpd` on `/var/run/sdp`, `bluetoothd`, `libbluetooth.so.3`), BlueZ 5 (`--compat`), or a vendor stack such as an Alps D-Bus service (`org.alps.evolution` / `org.alps.evo.SPP`, noted in [CLAUDE.md](../CLAUDE.md)).

To support BlueZ-style kernel sockets when available while degrading cleanly on hosts/targets without them, the module separates pure protocol logic, syscall abstractions, and runtime probing.

---

## 2. Components

### 2.1 `BtRfcommServer` ([bt_rfcomm.hpp](../include/carplay/platform/bt_rfcomm.hpp), [bt_rfcomm.cpp](../src/platform/bt_rfcomm.cpp))

- **Zero header/link dependency:** Defines `kAfBluetooth = 31`, `kBtProtoRfcomm = 3`, `BtAddr` (6-byte BlueZ `bdaddr_t` LSB-first order), and `SockAddrRc` (10-byte `struct sockaddr_rc` layout, `static_assert`-checked) locally so CI containers and the daemon build without `<bluetooth/*.h>` or `-lbluetooth`.
- **Syscall abstraction (`BtSocketOps`):** Wraps `socket()`, `bind()`, `getsockname()`, `listen()`, `accept()`, `recv()`, `send()`, and `close()`. Production uses `PosixBtSocketOps`; host unit tests inject `FakeBtSocketOps` backed by real non-blocking `socketpair` (POSIX) / loopback TCP pairs (Windows) to exercise the actual `Reactor` `poll()` loop.
- **Reactor integration:** Owns a listening socket (`kPollIn`) and at most **one active client connection** (`kPollIn`, plus `kPollOut` only while the outbound write queue is non-empty).
- **Single-session & reconnect policy:** By default (`replace_active_connection = false`), incoming connections while a client is active are closed immediately; once the active client disconnects (peer EOF, socket error, or local `disconnect()`), the listener remains open for subsequent reconnects.
- **Back-pressure:** `send()` is all-or-nothing against `write_queue_limit` (default 256 KiB). If `queuedBytes() + len > write_queue_limit`, `send()` returns `kSendOverflow` without tearing any framed message.
- **Raw byte delivery:** `BtRfcommListener::onBtData(const uint8_t*, size_t)` delivers raw RFCOMM stream bytes so the Phase 4 iAP2 link-layer package (`F4-P1`) and `iap2::CsmFramer` can adapt directly to it without duplicating framing logic.

### 2.2 SDP Record & Registration ([sdp_record.hpp](../include/carplay/sdp_record.hpp), [sdp_record.cpp](../src/core/sdp_record.cpp))

Pure C++11 (`src/core/`, zero OS headers):

- **Data Element encoder:** Supports `Nil`, `uint8`, `uint16`, `uint32`, `bool`, `UUID16`, `UUID32`, `UUID128`, `Text` (8/16/32-bit length descriptors), `Data Element Sequence` (`DES`), and `Data Element Alternative` (`DEA`) in big-endian network order per Bluetooth Core Spec Vol 3, Part B, Section 3.
- **iAP2 service record builder (`buildIap2SdpRecord`):** Encodes a `DES` attribute list sorted by ascending attribute ID:
  - `0x0001` `ServiceClassIDList`: `DES { UUID128(service_uuid) [, extra_uuid16s...] }`
  - `0x0004` `ProtocolDescriptorList`: `DES { DES{L2CAP (0x0100)}, DES{RFCOMM (0x0003), uint8(channel)} }` (validates channel in `1..30`)
  - `0x0005` `BrowseGroupList`: `DES { PublicBrowseRoot (0x1002) }`
  - `0x0006` `LanguageBaseAttributeIDList`: `DES { 0x656e ("en"), 0x006a (UTF-8), 0x0100 }` (when `service_name` is non-empty)
  - `0x0100` `ServiceName`: `Text(service_name)`
- **UUID status (UNVERIFIED):**
  - `defaultIap2AccessoryUuid128()` (`00000000-deca-fade-deca-deafdecacafe`) and `defaultAppleIapDeviceUuid128()` (`00000000-deca-fade-deca-deafdecacaff`) are commonly cited in public iAP/iAP2 documentation, **not verified** against Apple MFi documentation (NDA) or a live `HU_ENTRYNAV2`/iPhone capture. Both are marked `UNVERIFIED` in code comments and `Iap2SdpConfig::service_uuid` is configurable.
- **Registration backends:**
  1. `BluezSdpdRegistrar` (platform): Implements the BlueZ 4 legacy `sdpd` binary protocol (`SDP_SVC_REGISTER_REQ` `0x81`, `SDP_SVC_REGISTER_RSP` `0x82`, `SDP_SVC_REMOVE_REQ` `0x85`, `SDP_SVC_REMOVE_RSP` `0x86`, `SDP_ERROR_RSP` `0x01`) over `/var/run/sdp` (`AF_UNIX`, `SOCK_STREAM`) with non-blocking `poll()` timeouts.
  2. `NoopSdpRegistrar` (core): Reports `isSupported() == false` and `lastError() == "unsupported"` when no supported SDP daemon is present.
  3. `createBtSdpRegistrar(cap)` selects `BluezSdpdRegistrar` when `cap.sdpd_socket_present` is true, otherwise `NoopSdpRegistrar`.

### 2.3 Runtime Capability Probe (`probeBtCapability`)

`probeBtCapability()` returns a `BtCapability` struct (and `formatBtCapability()` / `logBtCapability()` formats it for `log.hpp`):

- `af_bluetooth_supported` / `af_bluetooth_errno`: attempts `socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)` and immediately closes it.
- `has_hci_device` / `hci_devices`: scans `/sys/class/bluetooth` for `hci*`.
- `sdpd_socket_present`: checks `/var/run/sdp` (`S_ISSOCK`).
- `bluetoothd_socket_present`: checks `/var/run/bluetoothd` (`S_ISSOCK`).
- `dbus_socket_present`: checks `/var/run/dbus/system_bus_socket` (`S_ISSOCK`).
- `libbluetooth_loadable` / `libbluetooth_name`: probes `dlopen("libbluetooth.so.3")` and `dlopen("libbluetooth.so")` (immediately `dlclose()`s).

---

## 3. Read-Only Head-Unit Probe Script ([scripts/probe/bt_probe.sh](../scripts/probe/bt_probe.sh))

`scripts/probe/bt_probe.sh` is a **strictly read-only**, BusyBox / POSIX `sh` script designed to run on the `HU_ENTRYNAV2` target over SSH without modifying kernel, interface, or filesystem state (no `hciconfig up/down`, no `hcitool scan`, no file writes).

Run on the head unit and capture output on the host:

```sh
ssh root@<head-unit-ip> 'sh -s' < scripts/probe/bt_probe.sh > bt_probe_report.txt
```

It collects:

1. Kernel version (`uname -a`) and `/etc/version`.
2. Kernel Bluetooth config (`/proc/config.gz` or `/boot/config-*` matching `CONFIG_BT*` / `RFCOMM` / `L2CAP`).
3. Loaded and available Bluetooth/RFCOMM/HCI/UART kernel modules (`/proc/modules`, `/lib/modules/$(uname -r)`).
4. `/sys/class/bluetooth/*` attributes (`address`, `name`, `type`, `bus`, `dev_id`) and `/dev/rfcomm*` / `/dev/hci*` nodes.
5. Read-only `hciconfig -a` and `hcitool dev` output if installed.
6. Running processes matching `bt|bluetooth|sdp|alps|btd|carplay|iap`.
7. UNIX sockets under `/var/run`, `/run`, and `/tmp`.
8. Shared libraries matching `*blue*` or `*bt*` in `/lib`, `/usr/lib`, `/usr/local/lib`, `/opt`.
9. D-Bus system service configs and live `org.freedesktop.DBus.ListNames` output.
10. Presence/permissions of `/opt/app/usr/MediaPlayer/bin/CARPLAY` and `/usr/local/lib/libpiapom.so*`.

---

## 4. Open Questions for Target Bring-Up

1. **Actual Bluetooth stack on `HU_ENTRYNAV2`:** Does the unit run BlueZ (`AF_BLUETOOTH` + `/var/run/sdp`) or an Alps/vendor stack over D-Bus (`org.alps.evolution` / `org.alps.evo.SPP`)? If Alps-only, a `BtRfcommServer`-equivalent or `BtSocketOps`-style D-Bus SPP adapter (`F4` integration) will be needed alongside `BluezSdpdRegistrar`.
2. **Authoritative iAP2 Bluetooth Service UUID:** Confirm via `sdptool browse` / iPhone Bluetooth packet capture / native `CARPLAY` inspection whether the head unit must advertise `00000000-deca-fade-deca-deafdecacafe`, `00000000-deca-fade-deca-deafdecacaff`, or another UUID, and which UUID the iPhone initiates RFCOMM against.
3. **BlueZ 4 `sdpd` PDU details on target:** `BluezSdpdRegistrar` implements BlueZ 4's local `SDP_SVC_REGISTER_REQ` (`0x81` with 6-byte `bdaddr_t` + 1-byte `flags` + `DES` record) and `SDP_SVC_REMOVE_REQ` (`0x85`). If the target runs BlueZ 5 without `--compat` or a patched `sdpd`, verify whether `/var/run/sdp` exists or whether D-Bus `org.bluez.ProfileManager1` is used instead.
4. **Bluetooth pairing & native BMW BT coexistence:** Native iDrive already manages Bluetooth HFP/A2DP pairing with the phone. Determine how `EntryCarPlay` / `carplayd` avoids colliding with native BMW pairing, and how `DeviceTransportIdentifier` (`0x4e0e`) / `WirelessCarPlayUpdate` (`0x4e0d`) map to the active paired phone.
5. **Daemon wiring (deferred to integration wave):** `CarPlayDaemon` (`carplay_daemon.cpp`) is intentionally untouched in `F4-P2`; integration will bridge `BtRfcommServer` raw bytes into the iAP2 link layer (`F4-P1`) and Wi-Fi AP/mDNS (`F4-P3`).
