# Wireless CarPlay: Car-Native AP (`vMOST` / `wland`), `hostapd` Fallback, and mDNS/DNS-SD (`_airplay._tcp`)

This document describes the Wireless CarPlay Wi-Fi Access Point and mDNS/DNS-SD advertisement
subsystems (`F4-P3` + `F4-B3`) for the BMW `HU_ENTRYNAV2` (`2017 F20 LCI`, TI `wl18xx`,
Linux 3.12 ARMv7).

> **Integration status:** `F4-B3` adds BMW's car-native Wi-Fi AP controller (`evo_wlan`), native
> credential/AP reader (`evo_ap`), read-only `nl80211`/`TCP_INFO` link logger (`wifi_link`),
> dual-backend `WifiAp` selection (`kWifiApBackendAuto` preferring car-native AP when present, with
> `kWifiApBackendHostapd` fallback — never running both), and fixes `MdnsAdvertiser` `dlopen()` to
> probe `libdns_sd.so.0` first as shipped on `HU_ENTRYNAV2`. Wiring into `CarPlayDaemon` happens in
> the integration wave.

---

## 1. End-to-End Wireless CarPlay Flow

1. **Bluetooth RFCOMM / iAP2 Control Session:**
   - The iPhone and head unit connect over Bluetooth Classic (`alps_spp` + `iap2::CsmFramer`).
   - iAP2 identification advertises CarPlay capability and wireless availability (`0x4300` /
     `0x4e0d` `WirelessCarPlayUpdate`).
   - When the iPhone requests accessory Wi-Fi configuration (`0x5702`
     `RequestAccessoryWiFiConfigurationInformation`), the head unit replies with `0x5703`
     (`AccessoryWiFiConfigurationInformation`), built by `iap2::buildAccessoryWiFiConfiguration`
     via `platform::buildAccessoryWiFiConfigFrame(wifi_ap.credentials(), frame)`:
     - `BSSID` (6 bytes from `/var/run/hostapd/<iface>` `STATUS` `bssid[0]` or `SIOCGIFHWADDR` /
       `/sys/class/net/<iface>/address`)
     - `SSID` (`<= 32` UTF-8 bytes)
     - `Passphrase` (WPA2-PSK ASCII passphrase, `8–63` bytes — never logged)
     - `SecurityType` (`3` = WPA2-PSK)
     - `Channel` (e.g. `36` for 5 GHz or `6` for 2.4 GHz)

2. **Wi-Fi Access Point Backend Selection (`WifiAp`):**
   - `WifiAp::resolveBackend(cfg)` chooses **exactly one** backend; it never runs both:
     - **`kWifiApBackendAuto` (default):** probes `WifiAp::isNativeCapable(cfg)`
       (`EvoWlanController::isAvailable()` or `EvoAccessPointReader::isNativeEnvironmentPresent()`).
       Selects `kWifiApBackendNative` on `HU_ENTRYNAV2`, or `kWifiApBackendHostapd` on non-EVO
       dev/host environments.
     - **`kWifiApBackendNative`:** requires the car-native AP; fails closed without spawning
       `hostapd` if `vmostd` / native WLAN is unavailable.
     - **`kWifiApBackendHostapd`:** forces our own isolated `hostapd` (+ optional `udhcpd`) on
       `interface_name` (`wlan1`) without touching `vmostd`.

3. **Backend A — Car-Native Wi-Fi AP (`evo_wlan` + `evo_ap` + `HostapdCtrl`):**
   - **Conflict analysis on `HU_ENTRYNAV2` (verified in sysroot):**
     - BMW's WLAN daemon (`wland`, `/opt/app/usr/WLAN/app/`, using `/usr/local/lib/libwpa_client.so.1`)
       already manages `hostapd` on `wlan0` with control socket `/var/run/hostapd/wlan0` and
       runtime config `/tmp/wland/ap.conf`, and tracks `APConnectionTimeout`.
     - If an external process reconfigures `wlan0` or spawns a competing `hostapd` on the same
       radio while `wland` owns it, `wland` fights it or disables the AP on idle timeout.
     - Instead, BMW's own CarPlay service toggles `wland` cleanly over vMOST FBlock `0xA0` instance
       `0x01`:
       1. `EvoWlanController` queries `WLANState3.Get` (`0xA0.01.0xC10`, op `0x1`).
       2. If `state_before == 1` (hotspot already ON), **nothing** is sent to `0xC11`
          (`switched_on_by_us = false`).
       3. Otherwise, `EvoWlanController` sends `SelectWLANState3.StartResultAck` (`0xA0.01.0xC11`,
          op `0x6`, big-endian payload `57 41 01`), recording `switched_on_by_us = true`.
   - **Readiness & Credential Readback:**
     - `WifiAp` connects `HostapdCtrl` (Reactor-driven `AF_UNIX` `SOCK_DGRAM`) to
       `/var/run/hostapd/wlan0` and sends `PING`, `ATTACH`, `STATUS`, `GET_CONFIG`, and `ALL_STA`,
       merging with `EvoAccessPointReader` (`hostapd_cli -p /var/run/hostapd -i wlan0 get_config`
       fallback -> `/tmp/wland/ap.conf` fallback + `SIOCGIFHWADDR` + `nl80211` `NL80211_CMD_GET_INTERFACE`).
     - Note: `hostapd` `GET_CONFIG` typically omits `channel`/`freq`, while `STATUS` and `nl80211`
       provide `freq`/`channel` and `bssid[0]`. `WifiAp` merges both before encoding `0x5703`.
     - Station connect/disconnect events come from `HostapdCtrl` `ATTACH` events, with `nl80211`
       `readConnectedStations` diff polling when control socket attach is unavailable.
   - **CarPlay Restoration Rule:**
     - On `stop()`, `stopSync()`, failure, or `~WifiAp()`, `WifiAp` sends `SelectWLANState3(0)`
       (`57 41 00`) **only** when `nativeSwitchedOnByUs() == true && config_.native_restore_on_stop`.
       If the car hotspot was already ON (`state_before == 1`), CarPlay leaves it ON.

4. **Backend B — Isolated `hostapd` Fallback (`WifiAp` + `SupervisedProcess`):**
   - Used on hosts/builds without BMW `wland` or when `backend = kWifiApBackendHostapd`.
   - Generates random SSID suffix + WPA2 passphrase via `OsRandomSource`, writes an isolated
     config at `/var/run/carplay/hostapd-carplay.conf` (`0600` in `0700` dir; **never touches
     `/etc/hostapd.conf`**), spawns `/usr/sbin/hostapd` via `SupervisedProcess` (`posix_spawnp`, no
     shell, `SIGTERM`->`SIGKILL`), attaches `HostapdCtrl` on `/var/run/carplay/hostapd_ctrl/wlan1`,
     and optionally runs `/usr/sbin/udhcpd -f` (omitting `router` and `dns` so iOS keeps cellular data).

5. **mDNS / DNS-SD Advertisement (`dnssd_txt` + `MdnsAdvertiser`):**
   - `dnssd::buildAirPlayTxtRecord(airplay_cfg, identity, txt)` encodes the RFC 6763 TXT record
     for `_airplay._tcp` (`deviceid`, `features`, `flags`, `model`, `pi`, `pk`, `srcvers`).
   - `MdnsAdvertiser` dynamically loads `libdns_sd.so.0` first (then `libdns_sd.so.1`, then
     `libdns_sd.so`) via `dlopen()`, resolving `DNSServiceRegister`, `DNSServiceRefSockFD`,
     `DNSServiceProcessResult`, `DNSServiceRefDeallocate`, and optional `DNSServiceUpdateRecord`.
   - **Sysroot verification (`HU_ENTRYNAV2`):** `/usr/local/lib/libdns_sd.so.0` (SONAME
     `libdns_sd.so.0`) exports all 21 `DNSService*` symbols (including the 5 used by
     `MdnsAdvertiser`) and **no** `TXTRecord*` helpers. `dnssd_txt` builds raw length-prefixed TXT
     records standalone, so no `TXTRecord*` imports are needed.

6. **Wi-Fi/TCP Diagnostics (`WifiLinkLog`):**
   - Once TCP `:7000` is connected, `WifiLinkLog` holds an `F_DUPFD_CLOEXEC` copy of the socket and
     logs periodic `nl80211` station stats (signal dBm, Tx/Rx PHY bitrates, frame retries/losses)
     plus `TCP_INFO` RTT/retransmits without ever logging addresses or passphrases.

---

## 2. Files & Paths Used

### Repository Modules
| File | Role |
| --- | --- |
| `include/carplay/dnssd_txt.hpp`, `src/core/dnssd_txt.cpp` | Pure RFC 6763 TXT encoder/decoder + `_airplay._tcp` TXT builder (standalone; no `libdns_sd` `TXTRecord*` dependency) |
| `include/carplay/platform/vmost_client.hpp`, `src/platform/vmost_client.cpp` | Runtime `dlopen("libvmostclient.so.1")` loader, MOST op constants (`0x1`/`0x6`/`0x9`/`0xA`/`0xC`/`0xD`/`0xF`), `buildVmostStartResultAck`, `isVmostDaemonPresent()` |
| `include/carplay/platform/evo_wlan.hpp`, `src/platform/evo_wlan.cpp` | BMW vMOST `0xA0.01` `WLANState3`/`SelectWLANState3` sync helpers + Reactor `EvoWlanController` + CarPlay restore rule (ported from AA 0.12.0) |
| `include/carplay/platform/evo_ap.hpp`, `src/platform/evo_ap.cpp` | `hostapd` config parser, channel<->MHz math, `EvoAccessPointReader` (`hostapd_cli`, `/tmp/wland/ap.conf`, ioctls, `nl80211`), `EvoApInfo::toWifiCredentials` (ported from AA 0.12.0) |
| `include/carplay/platform/wifi_link.hpp`, `src/platform/wifi_link.cpp` | Read-only `nl80211` station/frequency parsers + queries, `TCP_INFO`, `describeWifiLink`, `WifiLinkLog` (ported from AA 0.12.0) |
| `include/carplay/platform/hostapd_ctrl.hpp`, `src/platform/hostapd_ctrl.cpp` | Non-blocking Reactor `AF_UNIX` `SOCK_DGRAM` `hostapd` control client (`PING`/`ATTACH`/`STATUS`/`GET_CONFIG`/`ALL_STA`/`ENABLE`/`DISABLE`) |
| `include/carplay/platform/evo_supervisor.hpp`, `src/platform/evo_supervisor.cpp` | `IChildProcess` + `SupervisedProcess` (`posix_spawnp`, `waitpid(WNOHANG)`, `SIGTERM`->`SIGKILL`) |
| `include/carplay/platform/wifi_ap.hpp`, `src/platform/wifi_ap.cpp` | `WifiApConfig`, dual-backend `WifiAp` state machine (car-native AP + `hostapd` fallback), iAP2 `0x5703` frame helper |
| `include/carplay/platform/mdns_advertiser.hpp`, `src/platform/mdns_advertiser.cpp` | Runtime `dlopen` `dns_sd` advertiser (`libdns_sd.so.0` -> `.1` -> `.so`) + `"unavailable"` fallback + Reactor fd integration |

### Target Head-Unit Paths (`HU_ENTRYNAV2`)
| Path | Purpose | Notes |
| --- | --- | --- |
| `/var/run/vmost_sockstream` / `/tmp/vmost_sockstream` | `vmostd` IPC UNIX socket | Verified via `isVmostDaemonPresent()` |
| `libvmostclient.so.1` | vMOST shared client library | Loaded via `dlopen()` at runtime |
| `/var/run/hostapd/wlan0` | BMW `wland` `hostapd` ctrl socket | Created by BMW `wland` on car-native AP start |
| `/tmp/wland/ap.conf` | BMW `wland` AP configuration | Verified path; fallback read if `GET_CONFIG`/`hostapd_cli` unavailable |
| `/usr/sbin/hostapd_cli` | `hostapd` CLI query helper | Used by `EvoAccessPointReader` (`get_config`) |
| `/opt/app/usr/WLAN/app/libwpa_client.so.1` | BMW WLAN client library | Symlinked at `/usr/local/lib/libwpa_client.so.1` (verified in sysroot) |
| `/usr/sbin/hostapd` & `/usr/sbin/udhcpd` | Fallback AP / optional DHCPv4 binaries | Used only in `kWifiApBackendHostapd` (`wlan1`) |
| `/usr/local/bin/mdnsd` | Apple-style mDNS responder daemon | Verified in sysroot |
| `/usr/local/lib/libdns_sd.so.0` | `mdnsd` client library (SONAME `.0`) | Verified in sysroot; exports 21 `DNSService*` symbols, 0 `TXTRecord*` symbols |
| `/var/run/carplay/` | Runtime directory (`0700`) | Holds our `AF_UNIX` client bind sockets & fallback configs (`0600`) |

---

## 3. Verified vs. Vehicle-Check Items

### Verified in Sysroot
- **`libdns_sd.so.0` ABI & SONAME:** `/usr/local/lib/libdns_sd.so.0` exports `DNSServiceRegister`,
  `DNSServiceRefSockFD`, `DNSServiceProcessResult`, `DNSServiceRefDeallocate`, and
  `DNSServiceUpdateRecord`; does not export `TXTRecord*`.
- **BMW WLAN ownership:** `/usr/local/lib/libwpa_client.so.1` -> `/opt/app/usr/WLAN/app/libwpa_client.so.1.0.0`,
  `hostapd` socket `/var/run/hostapd/wlan0`, config `/tmp/wland/ap.conf`, vMOST `0xA0.01` `0xC10` /
  `0xC11`.

### Must Verify on Live Vehicle
1. **`libvmostclient.so.1` runtime IPC:** Verify `EvoWlanController` (`0xA0.01.0xC10` + `0xC11`
   `57 41 01` / `57 41 00`) against live `vmostd` and confirm `wland` starts `/var/run/hostapd/wlan0`
   without `APConnectionTimeout` interfering during CarPlay association.
2. **Car-native AP channel & band:** Confirm whether `wland` brings `wlan0` up on 5 GHz (`36`+) or
   2.4 GHz and that `STATUS` / `nl80211` reports the real operating frequency before `0x5703` is sent.
3. **iAP2 `WiFiSecurityType` (`kIap2WifiSecurityWpa2 = 3`) & `_airplay._tcp` TXT keys:** Confirm
   against a real iPhone pairing trace (`0x5702`/`0x5703` + `dns-sd -B _airplay._tcp local.`).
4. **IPv6 link-local on `wlan0`:** CarPlay uses IPv6 `fe80::/64` over the car AP even when no
   IPv4 address is assigned to `wlan0` (`EvoApInfo::ip` empty is explicitly permitted).

---

## 4. How to Verify on the Head Unit (ENET SSH)

Run these read-only checks over ENET SSH on `HU_ENTRYNAV2`:

```sh
# 1. Inspect Wi-Fi interfaces, vMOST daemon, and wland artifacts
iw dev
iw phy
ifconfig -a
ps | grep -E 'hostapd|wpa_supplicant|wland|vmostd|mdnsd'
ls -la /var/run/vmost_sockstream /tmp/vmost_sockstream /var/run/hostapd /tmp/wland 2>/dev/null

# 2. Check installed dns_sd library and test mdnsd browsing
ls -la /usr/local/lib/libdns_sd* /usr/lib/libdns_sd* 2>/dev/null
which dns-sd && dns-sd -B _airplay._tcp local.

# 3. Read-only check of car hotspot state (0 = off, 1 = on)
# After WifiAp starts in native mode, verify:
#   - /var/run/hostapd/wlan0 responds to hostapd_cli -p /var/run/hostapd -i wlan0 status
#   - ip -6 addr show dev wlan0 has link-local fe80::/64
#   - on stop(), car hotspot turns back off only if it was off before CarPlay started
```
