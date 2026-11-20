# Transport-to-Daemon Connectivity Orchestration (`CarPlayConnectivity`)

This document describes how `CarPlayDaemon` orchestrates the Phase 4 wireless and wired CarPlay transports into the existing AirPlay/CarPlay `SessionServer`.

## Overview

`CarPlayConnectivity` ([carplay_connectivity.hpp](../include/carplay/platform/carplay_connectivity.hpp), [carplay_connectivity.cpp](../src/platform/carplay_connectivity.cpp)) is owned by `CarPlayDaemon` and runs exclusively on the single-threaded `Reactor` loop. All vehicle-facing backends sit behind interfaces so the full pipeline runs unmodified under host simulation fakes. Vehicle-specific constants, ABI guards, QoS values, and live-car probe procedures referenced below are tracked in [docs/VEHICLE_FACTS.md](VEHICLE_FACTS.md).

```
                      +---------------------+
                      |    CarPlayDaemon    |
                      | (Reactor + Session) |
                      +----------+----------+
                                 |
                                 v
                      +---------------------+
                      | CarPlayConnectivity |
                      +---+-------------+---+
                          |             |
        Wireless (BT+WiFi)|             | Wired (USB+NCM)
                          v             v
     +-----------------------+       +-------------------------+
     | BtTransport           |       | UsbCarPlayBridge        |
     | (ALPS SPP preferred,  |       | (UsbHost + CDC-NCM      |
     |  kernel RFCOMM fb)    |       |  <-> TapIface)          |
     +-----------+-----------+       +------------+------------+
                 |                                |
                 v                                v
     +-----------------------+       +-------------------------+
     | BtSessionAdapter      |       | UsbBridgeSessionAdapter |
     +-----------+-----------+       +------------+------------+
                 |                                |
                 +---------------+----------------+
                                 |
                                 v
                  +-----------------------------+
                  | iap2::Session + AuthProvider|
                  | (Ident 0x1D01 + Auth 0xAA0x)|
                  +--------------+--------------+
                                 |
               +-----------------+-----------------+
               | Wireless                          | Wired
               v                                   v
    +-----------------------+           +-----------------------+
    | WifiAp (EVO native    |           | 0x4301 StartSession   |
    |  preferred, hostapd   |           | (TAP IPv6 link-local, |
    |  fallback)            |           |  no %ifindex scope)   |
    | -> 0x5703 + 0x4301    |           +-----------+-----------+
    | -> MdnsAdvertiser     |                       |
    |    (_airplay._tcp)    |                       |
    +----------+------------+                       |
               |                                    |
               +-----------------+------------------+
                                 |
                                 v
                   +---------------------------+
                   | SessionServer TCP (:7000) |
                   | HAP/RTSP + CarPlay Video  |
                   +---------------------------+
```

## Safe Configuration Defaults & CLI Switches

Both transports default to **disabled** (`false`) in `CarPlayDaemonConfig` and `CarPlayConnectivityConfig`:

| Setting / CLI Flag | Default | Purpose / Safe-Default Rationale |
| --- | --- | --- |
| `enable_wireless` (`--wireless` / `--no-wireless`) | `false` | Avoids borrowing ALPS SPP slot 5 or bringing up the car-native Wi-Fi AP (`vmostd`/`wland`) until wireless CarPlay and an `AuthProvider` are explicitly enabled. |
| `enable_wired` (`--wired` / `--no-wired`) | `false` | Avoids probing or claiming Apple USB interfaces alongside existing BMW HU infotainment/MediaPlayer processes unless explicitly enabled. |
| `usb_host_config.detach_usbfs_driver` / `usb_bridge_config.detach_usbfs_driver` | `false` | Enforces USB coexistence: never calls `USBDEVFS_DISCONNECT` to detach bound kernel drivers by default. |
| `handoff_timeout_ms` | `30000` | Maximum wait during AP startup / AirPlay TCP handoff (`0` disables). |
| `wired_failure_retry_ms` | `2000` | Delay before restarting `UsbCarPlayBridge` waiting state after a wired failure (`0` disables auto-restart). |
| `iap2_tick_interval_ms` | `50` | `Reactor` timer cadence driving iAP2 link retransmission/ACKs. |
| `start_mdns_on_wireless` | `true` | Starts `MdnsAdvertiser` (`_airplay._tcp`) alongside wireless `WifiAp` startup. |

If no `iap2::AuthProvider` is injected (`setIap2AuthProvider(...)`), `CarPlayConnectivity` uses an internal `UnavailableAuthProvider` that logs an explicit Phase 5 diagnostic error on `0xAA00`/`0xAA02` requests instead of crashing or silently succeeding.

## State Machine (`ConnectivityState`)

Every transition between states is logged via `CARPLAY_LOG_INFO` (`[conn] state <old> -> <new> (mode=<none|wireless|wired>, <reason>)`) and emitted to `CarPlayConnectivityListener::onConnectivityStateChanged(...)`.

| State | `ActiveTransportMode` | Description |
| --- | --- | --- |
| `kConnStopped` | `kActiveNone` | Initial state and post-`stop()` state. All transports torn down. |
| `kConnWaiting` | `kActiveNone` | Enabled listeners active (BT SPP waiting / USB host scanning); idle for a phone. |
| `kConnWirelessIap2` | `kActiveWireless` | BT peer connected; iAP2 link sync, identification (`wirelessBluetooth`), and MFi auth running. |
| `kConnWirelessApStarting` | `kActiveWireless` | iAP2 identified & authenticated; `WifiAp` starting (native EVO AP preferred, `hostapd` fallback). Any `0x5702` request arriving mid-start is deferred and answered with `0x5703` once AP credentials are ready. |
| `kConnWirelessWaitingAirPlay` | `kActiveWireless` | `WifiAp` running, `0x5703`/`0x4301` ready, `MdnsAdvertiser` active; waiting for iPhone TCP connect + `SETUP /session` on `SessionServer`. Normal BT RFCOMM disconnect during handoff keeps AP and mDNS alive. |
| `kConnWiredConfiguring` | `kActiveWired` | Apple USB device detected and CarPlay mode switch / NCM configuration in progress. |
| `kConnWiredIap2` | `kActiveWired` | USB iAP2 bulk interface ready (`kConnWiredIap2` entered via `onIap2Ready`); `iap2::Session` (`wiredUsb`) running alongside NCM/TAP setup (`onNcmReady`). |
| `kConnWiredWaitingAirPlay` | `kActiveWired` | iAP2 identified & authenticated and `0x4300` handled with `0x4301` carrying the TAP IPv6 link-local address (scope `%ifindex` stripped); waiting for `SETUP /session` on `SessionServer`. |
| `kConnActiveSession` | `kActiveWireless` or `kActiveWired` | `SessionServer` reported an active CarPlay `SETUP /session`. |

## Single-Phone Concurrency & Failure Teardown Invariants

- **One active phone at a time:** While `active_mode_ != kActiveNone` (any state outside `kConnStopped`/`kConnWaiting`), incoming connections from the *other* transport are rejected immediately (`rejectedConcurrentAttempts()` incremented) without disturbing the active phone.
- **Wireless failure / disconnect:**
  - If BT disconnects before `kConnWirelessWaitingAirPlay` (or during iAP2/AP startup), `WifiAp` and `MdnsAdvertiser` are stopped, BT is disconnected, and state returns to `kConnWaiting`.
  - If BT disconnects *after* entering `kConnWirelessWaitingAirPlay` or `kConnActiveSession`, Wi-Fi AP, mDNS, and AirPlay remain active until AirPlay ends or `handoff_timeout_ms` expires.
  - On `stop()` or destruction, `AlpsBtTransport` runs `AlpsSppManager::stop()` so borrowed ALPS SPP slot 5 UUID and `0x6203` are restored whenever `AlpsSppManager` borrowed the slot (including after AP startup failure or mid-session daemon stop).
- **Wired failure / removal:**
  - On iAP2 error, bridge error, AirPlay session end, USB removal, or `stop()`, `UsbCarPlayBridge::stop()` closes the `TapIface` and releases/closes USB interfaces.
  - Wired `0x4301` strips `%<ifindex>` from IPv6 link-local addresses before sending `StartSessionConfig` (required by iOS over USB NCM).

## Vehicle Compatibility Gate, QoS & Coexistence Diagnostics ([VEHICLE_FACTS.md](VEHICLE_FACTS.md))

- **ALPS compatibility gate (`probeAlpsSppCompat`):**
  - When wireless CarPlay is enabled, `CarPlayConnectivity::startWirelessSubsystem()` runs `probeBtTransportCapability()` and `probeAlpsSppCompat(..., usb_mode=false)` before instantiating or starting `AlpsBtTransport`, and logs `formatAlpsCompatReport(...)`.
  - On unknown `libevo_btappl.so` builds (such as the `15024/480/36` variant) or failed `alps` / `uuid` / `spp` checks, it **never opens `/proc/<pid>/mem` or reads offsets of an unknown build**, logs the formatted report, and falls back to kernel `RfcommBtTransport` (if `AF_BLUETOOTH` + HCI is capable) or disables wireless cleanly while leaving wired USB / AirPlay running.
  - In wired-only mode (`enable_wired && !enable_wireless`), `probeAlpsSppCompat(..., usb_mode=true)` runs as an informational check (downgrading absent/unknown ALPS to `kCompatInfo` `"wireless only"`).
- **Per-transport socket QoS (`wifi_video_qos`):**
  - `SessionServer::setWifiVideoQos(...)` delegates to `MediaEngine::setWifiVideoQos(...)` and is updated per active transport by `CarPlayConnectivity`: enabled (`true`) when entering `kActiveWireless` (so accepted control TCP, event TCP, screen TCP, and audio data UDP sockets carry `IP_TOS` / `IPV6_TCLASS = 0x80`, WMM `AC_VI`, matching BMW's `libNmeCarPlay.so` `SocketSetQoS`) and disabled (`false`, `0`) for `kActiveWired` USB sessions and idle/waiting states.
- **Read-only BMW Apps BT-coex logging (`WifiLinkLog` + `readBmwAppsSlot`):**
  - `CarPlayConnectivity` owns a `WifiLinkLog` instance wired with a read-only `setAppsProbe` callback (`BtTransport::readBmwAppsSlot()` -> `AlpsSppManager::readBmwAppsSlot()` -> `readBmwAppsSlot()`, active only when ALPS snapshot probing is verified safe).
  - When wireless `WifiAp` starts and an AirPlay session enters `kConnActiveSession`, `WifiLinkLog` is enabled on the active AP interface (`wlan0` or fallback `wlan1`), attached to the accepted control socket, and ticked on the `Reactor` to emit `[wifi-link]` `nl80211`, `TCP_INFO`, and read-only ALPS slot `0` diagnostics without mutating state.

## Verification Status

Host simulation unit and end-to-end tests verify all state transitions, wire exchanges, ALPS compatibility gating, per-transport `wifi_video_qos` (`0x80` wireless vs `0` wired), read-only `WifiLinkLog` BMW Apps slot-0 probing, concurrency rejections, and failure/restore paths against fake BT/ALPS/WLAN/mDNS/USB/TAP/AuthProvider backends:
- [test_carplay_connectivity.cpp](../tests/test_carplay_connectivity.cpp) — safe defaults, disabled-transport no-op, missing `AuthProvider` error path, wireless handoff timeout cleanup, ALPS compatibility gate fallback to RFCOMM / wireless disable on unknown `15024/480/36` & failed `spp`/`alps` checks, wired-only informational compat logging.
- [test_carplay_e2e_sim.cpp](../tests/test_carplay_e2e_sim.cpp) — scripted wireless E2E (ALPS SPP slot 5 borrow -> iAP2 -> EVO AP -> mDNS -> TCP AirPlay `SETUP /session` -> teardown & ALPS slot 5 restore), scripted wired E2E (USB `detach_usbfs=false` -> NCM/TAP -> iAP2 -> `0x4301` IPv6 -> TCP AirPlay `SETUP /session` -> USB removal teardown), dynamic wireless (`0x80`) vs wired (`0`) `getSocketTrafficClass` E2E verification across control/event/screen/audio sockets + read-only `[wifi-link]` BMW Apps slot-0 logging, and failure injection (AP failure with ALPS restore, wireless/wired auth failures, mid-session BT/daemon stop, and concurrent-phone rejection).

Vehicle hardware execution on EntryNav2 / HU_EVO (`ALPS` D-Bus/memory, real `vmostd`/`wland`, real `libdns_sd.so.0`, real iPhone USB CDC-NCM) and Phase 5 MFi coprocessor `AuthProvider` remain untested without car hardware.
