# Bluetooth Transport & Discovery (`F4-P2` / `F4-B2`)

This document describes the Bluetooth byte-stream transport layer for wireless CarPlay iAP2 bring-up on `HU_ENTRYNAV2`: BMW's proprietary **ALPS "Evolution" SPP stack** (`F4-B2`, primary vehicle path), the kernel **`AF_BLUETOOTH` RFCOMM + BlueZ `sdpd` fallback** (`F4-P2`), the unified **`BtTransport`** selector, and the strictly read-only head-unit probe script.

## 1. Target Reality on `HU_ENTRYNAV2`

Inspection of the `HU_ENTRYNAV2` sysroot and the `EntryNav2-Android-Auto-0.12.0` implementation (`docs/COMPATIBILITE.md`, `docs/ARCHITECTURE.md`) confirms:

- **No BlueZ userland:** The sysroot carries kernel `bluetooth.ko` (`/lib/modules/3.12.25-FR21.0/kernel/net/bluetooth/bluetooth.ko`), **no `libbluetooth.so`**, and `/usr/local/lib/alps/evolution -> /opt/app/usr/BTMedia/evolution/stack/lib`.
- **Proprietary ALPS stack over D-Bus:** BMW runs the ALPS Evolution stack (`libevo_btappl.so`) exposing service `org.alps.evolution` on object `/org/alps/evolution/hli` with interfaces `org.alps.evo.SPP` and `org.alps.evo.DM`. There is no virtual serial port (`bvd_tty` / `evo_bvd` is absent from the kernel), so both control and SPP byte-stream data flow over D-Bus via `libdbus-1.so.3` (loaded at runtime with `dlopen`/`dlsym` — never link-time `-ldbus-1`).
- **Six SPP slots (`0..5`):** `libevo_btappl.so` (`spp_instance_init`) initializes six SPP slots with generic 16-bit SPP UUID pair `01 11 01 01 11 01`, and `stack/etc/evo_config.xml` configures:
  - **Slot `0`:** BMW Apps / My BMW (`vmostAuxInBT`) — **protected** (fallback to slot `0` is refused by default so My BMW is never broken).
  - **Slot `1`:** Native BMW CarPlay slot.
  - **Slots `2..5`:** Unconfigured generic slots; slot **`5`** is preferred when borrowing is required.
- **Verified iAP2 UUID pair:**
  - Initiator UUID: `00000000-deca-fade-deca-deafdecacaff` (`defaultAppleIapDeviceUuid128()`)
  - Local SDP record UUID: `00000000-deca-fade-deca-deafdecacafe` (`defaultIap2AccessoryUuid128()`)
  - Encoded 34-byte `BtApplSppSetUuidReq` payload: `03` + initiator UUID + `03` + record UUID (`0300000000decafadedecadeafdecacaff0300000000decafadedecadeafdecacafe`).
  - *Verified against* `EntryNav2-Android-Auto-0.12.0/platform/spp_baseline.hpp`, `tests/fixtures/spp-bmw-uuids.txt`, and `DiPlay-main/shared/src/main/java/com/shilapi/xcertplay/orchestration/CarPlayController.kt:3239`.

---

## 2. ALPS Stack Components (`F4-B2`)

### 2.1 ELF Symbol & GOT Parser ([elf_symbols.hpp](../include/carplay/platform/elf_symbols.hpp), [elf_symbols.cpp](../src/platform/elf_symbols.cpp))

- Portable ELF32 ARM little-endian parser (no `<elf.h>` dependency; all bounds checked).
- Extracts `.dynsym` defined symbols (`app`, `spp_info`, `spp_connected`) and their `R_ARM_GLOB_DAT` (`21`) GOT relocation offsets without loading or executing `libevo_btappl.so`.

### 2.2 Snapshot Reader & Slot Selection Policy ([spp_snapshot.hpp](../include/carplay/platform/spp_snapshot.hpp), [spp_snapshot.cpp](../src/platform/spp_snapshot.cpp))

- **Structure validation:** Requires exact table sizes (`app = 15032`, `spp_info = 480`, `spp_connected = 36`) and verifies GOT relocation pointers (`*(base + sym.got) == base + sym.value`) inside a single running process mapping `libevo_btappl.so`.
- **Read-only double-read (`SppSnapshotReader`):** Uses `O_RDONLY | O_CLOEXEC` on `/proc/<pid>/mem` (`pread64`) without `ptrace` or process writes. Checks `/proc/<pid>/stat` field 22 (monotonic start ticks) identity before reading, performs two reads separated by 20 ms (`double_read_delay_ms`), rejects unstable/changing state, and cross-checks `app` record UUIDs against `spp_info` transport UUIDs.
- **CarPlay slot selection (`selectCarPlaySppSlot` / `evaluateCarPlaySppSlot`):**
  1. **Native CarPlay slot `1` first (`kSlotUseNative1`):** If slot `1` is idle and both UUID copies already carry `carPlayIap2UuidPair()`, use slot `1` directly — **do not** reconfigure UUID or `0x6203`, and **do not** restore on stop. If slot `1` carries iAP2 while busy or split, refuse (`kSlotRefuseBusy`) to avoid double-advertising iAP2.
  2. **Borrow spare slot `5` (`kSlotBorrow5`):** If slot `1` is not native CarPlay and slot `5` is started (`state != 0`), idle, consistent, and holds the generic SPP pair (`011101011101`), borrow slot `5` and mark it for mandatory restoration. If slot `5` is connected, busy, or already carries iAP2, refuse (`kSlotRefuseBusy`).
  3. **Slot `0` protected (`kSlotRefuseProtected`):** When slot `5` is unavailable, slot `0` (BMW Apps / My BMW) fallback is **refused by default** (`CarPlaySlotPolicy::allow_slot0_fallback = false`).

### 2.3 ALPS D-Bus Client & Manager ([alps_spp.hpp](../include/carplay/platform/alps_spp.hpp), [alps_spp.cpp](../src/platform/alps_spp.cpp))

- **`DbusLoader` (`loadDbusApi`):** Resolves all 40 required `libdbus-1` functions from `libdbus-1.so.3` (fallback `libdbus-1.so`) via `dlopen`/`dlsym` (`memcpy` pointer cast, matching `vmost_client.cpp`), using opaque `DbusErrorRaw` / `DbusMessageIterRaw` buffers and non-variadic `dbus_message_iter_*` calls.
- **`DbusAlpsSppLink`:**
  - Subscribes to `org.alps.evo.SPP` (`BtApplSppSetUuidCfm`, `BtApplSppDataInd`, `BtApplSppDataCfm`, `BtApplSppSendInd`, `BtApplSppDataSendFcInd`), `org.alps.evo.DM` (`BtApplReadConfigurationCfm`, `BtApplSetConfigurationCfm`, `BtApplDeviceConnectInd`, `BtApplDeviceDisconnectInd` with `function == 1`), and `NameOwnerChanged`.
  - Runs dedicated D-Bus dispatch and TX pump threads (`Thread` / `pthread_cond_t` timed waits), delivering `onAlpsConnected` / `onAlpsData` / `onAlpsDisconnected` / `onAlpsFatalError` onto the single-threaded `Reactor` via `Reactor::post()` (worker threads are joined before `Reactor::cancelPosted()` on `stop()`).
  - Enforces ALPS flow control (`BtApplSppSendInd` completion, `BtApplSppDataSendFcInd` pause/resume, 5 s `SendInd` timeout, 1024-byte max `BtApplSppDataReq` chunks).
  - Accounts for the `gen_GetConfig` bug in `libevo_btappl.so` (`alpsSlotConfigurationReadable(slot)` is true only for slots `<= 1`; slot `5` `0x6203` writes are confirmed by `BtApplSetConfigurationCfm` status `0`).
- **`AlpsSppManager`:**
  - Executes slot selection, configures borrowed slot (`0x6203 = 1` + `BtApplSppSetUuidReq`), **re-reads the `/proc` snapshot** to verify both UUID copies match `carPlayIap2UuidPair()` (immediately restoring & failing on mismatch), schedules bounded idle advertisement refreshes (`15s, 45s, 90s`, then `60s`), and **always restores** a borrowed slot on `stop()` / destruction (checking process start ticks identity, settling with `allow_split=true`, refusing if a third-party UUID took over, disconnecting only our SPP instance via `function = 1` if active, restoring the saved baseline UUID and `0x6203`, and re-reading to confirm).

---

## 3. Unified `BtTransport` & Kernel RFCOMM Fallback

### 3.1 `BtTransport` ([bt_transport.hpp](../include/carplay/platform/bt_transport.hpp), [bt_transport.cpp](../src/platform/bt_transport.cpp))

- **`BtTransport` + `BtTransportListener`:** Common interface for `start()`, `stop()`, `disconnect()`, `sendBytes()`, connection state, and byte-stream callbacks.
- **`BtTransportByteSink`:** Implements `carplay::iap2::ByteSink` directly on top of `BtTransport::sendBytes()`.
- **Backend implementations:**
  - `AlpsBtTransport`: wraps `AlpsSppManager`.
  - `RfcommBtTransport`: wraps `BtRfcommServer` + `sdp::SdpRegistrar` (`BluezSdpdRegistrar` / `NoopSdpRegistrar`).
- **Runtime capability selection (`probeBtTransportCapability` / `selectBtBackend` / `createBtTransport`):**
  1. **`kBtBackendAlpsSpp`** (preferred on vehicle): selected whenever `libevo_btappl.so` is uniquely mapped with valid table sizes, `/var/run/dbus/system_bus_socket` + `libdbus-1.so.3` exist, and `org.alps.evolution` is owned on the bus.
  2. **`kBtBackendRfcomm`** (fallback): selected when ALPS is absent and `AF_BLUETOOTH` + an `hci*` device are present.
  3. **`kBtBackendNone`:** selected when neither stack is available.

### 3.2 `BtRfcommServer`, `sdp_record`, and `probeBtCapability`

- [`BtRfcommServer`](../include/carplay/platform/bt_rfcomm.hpp): zero link-time `libbluetooth` dependency (`kAfBluetooth = 31`, `kBtProtoRfcomm = 3`, `SockAddrRc`), Reactor-integrated single active peer, all-or-nothing write queue (`256 KiB` limit), `BtSocketOps` fakeable for host tests.
- [`sdp_record`](../include/carplay/sdp_record.hpp): pure C++11 SDP Data Element encoder (`buildIap2SdpRecord`), BlueZ 4 legacy `sdpd` PDU codec (`0x81..0x86`), `NoopSdpRegistrar`. SDP record attribute details follow Bluetooth Core Spec Vol 3 Part B; UUID pair `...caff` / `...cafe` is verified as noted in Section 1.
- [`probeBtCapability`](../include/carplay/platform/bt_rfcomm.hpp): checks `AF_BLUETOOTH`, `/sys/class/bluetooth/hci*`, `/var/run/sdp`, `/var/run/bluetoothd`, `/var/run/dbus/system_bus_socket`, `dlopen("libbluetooth.so.3")`, and `dlopen("libdbus-1.so.3")`.

---

## 4. Read-Only Head-Unit Probe Script ([scripts/probe/bt_probe.sh](../scripts/probe/bt_probe.sh))

`scripts/probe/bt_probe.sh` is **strictly read-only** (POSIX/BusyBox `sh`; zero state changes) and collects kernel config/modules, `/sys/class/bluetooth`, read-only `hciconfig`/`hcitool`, running BT/ALPS processes, UNIX sockets, `*blue*`/`*bt*`/`libdbus-1`/`*alps*`/`libevo_btappl*` libraries, ALPS `/proc/*/maps` mappings and `evo_config.xml` SPP metadata, D-Bus `ListNames` + read-only `Introspect` of `org.alps.evolution`, and `/opt/app/usr/MediaPlayer/bin/CARPLAY`.

```sh
ssh root@<head-unit-ip> 'sh -s' < scripts/probe/bt_probe.sh > bt_probe_report.txt
```

---

## 5. Remaining Integration Work

`CarPlayDaemon` (`carplay_daemon.cpp`) is intentionally untouched in `F4-B2`. Daemon integration will:

1. Call `probeBtTransportCapability()` / `createBtTransport()` at startup and wire `BtTransportByteSink` + `BtTransportListener` into `iap2::Link` (`F4-P1`).
2. Feed authenticated Wi-Fi AP credentials (`0x5700`–`0x5703`) and track `DeviceTransportIdentifier` (`0x4e0e`) / `WirelessCarPlayUpdate` (`0x4e0d`) per active paired phone.
3. Gate `CarPlayDaemon` teardown through `BtTransport::stop()` so any borrowed ALPS slot `5` is always restored cleanly on exit.
