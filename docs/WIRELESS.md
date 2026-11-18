# Wireless CarPlay: Wi-Fi AP (`hostapd`) + mDNS/DNS-SD (`_airplay._tcp`)

This document describes the Wireless CarPlay Wi-Fi Access Point and mDNS/DNS-SD advertisement
subsystems (`F4-P3`) for the BMW `HU_ENTRYNAV2` (`2017 F20 LCI`, TI `wl18xx`, Linux 3.12 ARMv7).

> **Integration status:** `F4-P3` implements the standalone Wi-Fi AP, `hostapd` control client,
> supervised process launcher, DNS-SD TXT builder, and `dns_sd` mDNS advertiser with full host
> unit tests. Wiring into `CarPlayDaemon` and Bluetooth RFCOMM/iAP2 (`F4-P2`) happens in the
> integration wave.

---

## 1. End-to-End Wireless CarPlay Flow

1. **Bluetooth RFCOMM / iAP2 Control Session (`F4-P1` / `F4-P2`):**
   - The iPhone and head unit connect over Bluetooth Classic (`alps_spp` + `iap2::CsmFramer`).
   - iAP2 identification advertises CarPlay capability and wireless availability (`0x4300` /
     `0x4e0d` `WirelessCarPlayUpdate`).
   - When the iPhone requests accessory Wi-Fi configuration (`0x5702`
     `RequestAccessoryWiFiConfigurationInformation`), the head unit replies with `0x5703`
     (`AccessoryWiFiConfigurationInformation`), built by `iap2::buildAccessoryWiFiConfiguration`
     via `platform::buildAccessoryWiFiConfigFrame(wifi_ap.credentials(), frame)`:
     - `BSSID` (6 bytes from `/sys/class/net/<iface>/address` or `hostapd` `STATUS` `bssid[0]`)
     - `SSID` (`BMW-CarPlay-<random_hex>`, max 32 bytes)
     - `Passphrase` (random WPA2-PSK passphrase from `OsRandomSource`, 8–63 printable ASCII bytes)
     - `SecurityType` (`3` = WPA2-PSK; see assumptions below)
     - `Channel` (e.g. `36` for 5 GHz or `6` for 2.4 GHz)

2. **Wi-Fi Access Point (`WifiAp` + `HostapdCtrl` + `SupervisedProcess`):**
   - `WifiAp` generates fresh random SSID suffix + passphrase via `pairing::RandomSource`
     (`OsRandomSource` reading `/dev/urandom`), validates band/channel/country code, and writes
     our **own** isolated config file `/var/run/carplay/hostapd-carplay.conf` (mode `0600` inside
     `/var/run/carplay/`, mode `0700`). **`/etc/hostapd.conf` is never read or modified.**
   - `SupervisedProcess` launches `/usr/sbin/hostapd /var/run/carplay/hostapd-carplay.conf`
     directly via `posix_spawnp` (no shell, no `-B` daemonize flag so `waitpid` tracks the child).
   - `HostapdCtrl` opens a non-blocking `AF_UNIX` `SOCK_DGRAM` socket bound to its own path in
     `/var/run/carplay/` and connected to `/var/run/carplay/hostapd_ctrl/<iface>`, integrated
     with `Reactor`.
   - `WifiAp` probes `PING` -> `ATTACH` -> `STATUS` -> `ALL_STA`, reads `bssid[0]` if not already
     known, optionally starts `/usr/sbin/udhcpd -f /var/run/carplay/udhcpd-carplay.conf`, and
     tracks `<N>AP-STA-CONNECTED <mac>` / `<N>AP-STA-DISCONNECTED <mac>` events.
   - If `hostapd` exits unexpectedly, `WifiAp` tears down the control socket / `udhcpd`, notifies
     `onWifiApRestarting`, and respawns `hostapd` with the same credentials (up to `max_restarts`).
     On `stop()`, `SupervisedProcess` sends `SIGTERM` and escalates to `SIGKILL` before reaping.

3. **mDNS / DNS-SD Advertisement (`dnssd_txt` + `MdnsAdvertiser`):**
   - `dnssd::buildAirPlayTxtRecord(airplay_cfg, identity, txt)` builds the length-prefixed
     RFC 6763 TXT record for `_airplay._tcp` from the receiver's `info::AirPlayConfig` and
     `pairing::Identity`:
     - `deviceid`: `config.device_id`
     - `features`: `info::features(config)` formatted as `0x<lo32>,0x<hi32>`
     - `flags`: `0x4` (matching `statusFlags = 4` in `src/core/airplay_info.cpp`)
     - `model`: `config.model` (e.g. `HU_ENTRYNAV2`)
     - `pi`: `identity.pairing_id` (RFC 4122 UUID)
     - `pk`: 64-char lowercase hex of the 32-byte Ed25519 public key
     - `srcvers`: `config.source_version` (`950.7.1`)
   - `MdnsAdvertiser` dynamically loads `libdns_sd.so.1` or `libdns_sd.so` via `dlopen()` (no
     link-time dependency; reports `"unavailable"` cleanly if absent), registers `_airplay._tcp`
     on port `7000` (network byte order) with `/usr/local/bin/mdnsd`, and registers
     `DNSServiceRefSockFD` on the `Reactor`.
   - Name conflicts (`kDnsServiceErrNameConflict` or `mdnsd` auto-rename callbacks) are handled
     cleanly and surface `onMdnsNameConflictRenamed`.

4. **AirPlay Session Bring-Up:**
   - Once the iPhone associates to the AP, it obtains an IPv6 link-local address (`fe80::/64`)
     and queries `_airplay._tcp.local` over mDNS.
   - **IPv6 vs IPv4 note:** CarPlay primarily communicates over **IPv6 link-local (`fe80::/64`)**
     plus mDNS. An optional `udhcpd` IPv4 subnet (`192.168.50.10..50`, `enable_udhcpd = false` by
     default) is supported for diagnostics or fallback. `generateUdhcpdConfig` intentionally omits
     `option router` and `option dns` so iOS keeps cellular data routing active while connected
     to CarPlay Wi-Fi.
   - The iPhone connects to `SessionServer` on port `7000` and proceeds through `/pair-setup` /
     `/pair-verify`, `/info`, `SETUP`, `RECORD`, and encrypted media/HID/iAP2 streams.

---

## 2. Files & Paths Used

### Repository Modules
| File | Role |
| --- | --- |
| `include/carplay/dnssd_txt.hpp`, `src/core/dnssd_txt.cpp` | Pure RFC 6763 TXT encoder/decoder (255-byte limit, key rules, duplicate rejection) + `_airplay._tcp` TXT builder |
| `include/carplay/platform/evo_supervisor.hpp`, `src/platform/evo_supervisor.cpp` | `IChildProcess` + `SupervisedProcess` (`posix_spawnp`, `waitpid(WNOHANG)`, `SIGTERM`->`SIGKILL`) |
| `include/carplay/platform/hostapd_ctrl.hpp`, `src/platform/hostapd_ctrl.cpp` | Non-blocking Reactor-integrated `AF_UNIX` `SOCK_DGRAM` `hostapd` control client + `STATUS`/`ALL_STA`/event parsers |
| `include/carplay/platform/wifi_ap.hpp`, `src/platform/wifi_ap.cpp` | `WifiApConfig`, credential & config generators (`hostapd` / `udhcpd`), and `WifiAp` state machine |
| `include/carplay/platform/mdns_advertiser.hpp`, `src/platform/mdns_advertiser.cpp` | Runtime `dlopen` `dns_sd` advertiser (`libdns_sd.so.1` / `libdns_sd.so`) + `"unavailable"` fallback + Reactor fd integration |

### Target Head-Unit Paths (`HU_ENTRYNAV2`)
| Path | Purpose | Notes |
| --- | --- | --- |
| `/usr/sbin/hostapd` | System `hostapd` binary | Verified present in `docs/TARGET_HARDWARE.md` §6 |
| `/usr/sbin/udhcpd` | Optional BusyBox DHCPv4 daemon | Verified present in `docs/TARGET_HARDWARE.md` §6 |
| `/usr/local/bin/mdnsd` | Apple-style mDNS responder daemon | Verified present in `docs/TARGET_HARDWARE.md` §6 |
| `libdns_sd.so.1` / `libdns_sd.so` | Client library for `mdnsd` | Loaded via `dlopen` at runtime; not linked at build time |
| `/var/run/carplay/` | Runtime directory (`0700`) | Created/owned by `WifiAp` |
| `/var/run/carplay/hostapd-carplay.conf` | Generated WPA2-PSK CCMP config (`0600`) | Isolated from `/etc/hostapd.conf` |
| `/var/run/carplay/hostapd_ctrl/wlan1` | `hostapd` UNIX datagram control socket | Created by `hostapd` |
| `/var/run/carplay/carplay_wpa_ctrl_<pid>_<seq>.sock` | Our client bind socket (`0600`) | Unlinked on close |
| `/var/run/carplay/udhcpd-carplay.conf` & `.leases` | Optional `udhcpd` runtime files | Only written when `enable_udhcpd = true` |

---

## 3. Assumptions & Unverified Items (Must Verify on Vehicle)

The following items are **assumptions / unverified against a live head unit or iPhone capture**:

1. **Interface assignment (`wlan1` vs `wlan0`):**
   - `docs/TARGET_HARDWARE.md` §6 confirms TI `wl18xx` exposes `wlan0` and `wlan1`. `WifiApConfig`
     defaults to `wlan1` on the assumption `wlan0` is used for client/BMW services or P2P, and
     `wlan1` is free for AP mode. Configurable via `WifiApConfig::interface_name`.
2. **Band / channel / regulatory domain (`DE`, channel `36`):**
   - `WifiApConfig` defaults to 5 GHz channel `36` (`hw_mode=a`) and `country_code="DE"`. Must
     verify on the unit whether `wl18xx` + the installed `hostapd` binary and regdb allow 5 GHz
     AP mode (`iw list`) or require 2.4 GHz (`hw_mode=g`, e.g. channel `6`).
3. **iAP2 `WiFiSecurityType` (`kIap2WifiSecurityWpa2 = 3`):**
   - Matches `tests/test_phase1.cpp` (lines 482, 534). Other security-type enum values are not
     verified against live iPhone iAP2 traces.
4. **`_airplay._tcp` TXT formatting & required keys:**
   - Reuses existing repo values (`deviceid`, `features`, `flags`, `model`, `pi`, `pk`, `srcvers`).
   - `features` formatting (`0x<lo32>,0x<hi32>`, lowercase hex) and `flags` (`0x4`) follow open
     AirPlay conventions and have **not** been captured against `/opt/app/usr/MediaPlayer/bin/CARPLAY`
     or a real iPhone. Whether iOS expects additional keys (such as `vv` or `protovers`) for
     Wireless CarPlay discovery must be checked on-unit.
5. **`libdns_sd` library filename & `mdnsd` IPC compatibility:**
   - `MdnsAdvertiser` tries `libdns_sd.so.1` then `libdns_sd.so` via `dlopen`. Exact SONAME and
     `/var/run/mdnsd` socket permissions on the target firmware must be confirmed on the unit.
6. **Interface link-up / IPv6 link-local readiness:**
   - `WifiAp` spawns `hostapd` and optional `udhcpd`; bringing the interface `UP` (`ip link set wlan1 up`)
     or assigning an IPv4 address when `enable_udhcpd=true` is assumed to be handled either by
     network scripts or the daemon integration wave. Note that `hostapd` with `driver=nl80211`
     typically brings the AP interface up itself once started.

---

## 4. How to Verify on the Head Unit (ENET SSH)

Run these read-only / isolated checks over ENET SSH on `HU_ENTRYNAV2`:

```sh
# 1. Inspect Wi-Fi interfaces, capabilities (AP mode, 5 GHz support), and current state
iw dev
iw phy
ifconfig -a
ps | grep -E 'hostapd|wpa_supplicant|mdnsd|udhcpd'

# 2. Check existing /etc/hostapd.conf (READ-ONLY — do not modify!) and dns_sd libraries
cat /etc/hostapd.conf
ls -la /usr/sbin/hostapd /usr/sbin/udhcpd /usr/local/bin/mdnsd
ls -la /usr/lib/libdns_sd* /usr/local/lib/libdns_sd* /lib/libdns_sd* 2>/dev/null

# 3. Verify IPv6 link-local on the chosen AP interface (after starting hostapd with a test conf)
ip -6 addr show dev wlan1

# 4. Test mdnsd registration/browsing if dns-sd CLI is present on the image
which dns-sd && dns-sd -B _airplay._tcp local.
```

During integration testing:
1. Ensure `/var/run/carplay/` is writable and `/etc/hostapd.conf` remains untouched.
2. Start `WifiAp` on `wlan1` and confirm `HostapdCtrl` receives `PONG`, `OK` (on `ATTACH`), and
   `STATUS` with `state=ENABLED`.
3. Confirm `MdnsAdvertiser` loads `libdns_sd.so*` (`backendName() == "dns_sd"`) and registers
   `_airplay._tcp` on port `7000` without errors.
4. Connect a test phone (with the generated SSID/passphrase or via iAP2 `0x5703`), confirm
   `onStationConnected(<mac>)` fires, and verify `ip -6 neigh show dev wlan1` + TCP `:7000`
   reachability.
