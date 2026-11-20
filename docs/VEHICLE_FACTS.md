# EntryNav2 / EVO Vehicle Facts Ledger (Phase 4 & Platform Audit)

Audit baseline: **`EntryNav2-Android-Auto` `v0.12.0` -> `v0.13.0-rc.6`**, **`DiPlay-main`**, and the **HU_ENTRYNAV2 sysroot** (`/home/ozzy/Projects/EntryNav2-CarPlay-Assets/sysroot`).

This ledger tracks every vehicle-specific constant, ABI assumption, path, D-Bus coordinate, vMOST function ID, and hardware quirk used in `EntryNav2-CarPlay`, its provenance, verification status, dependent code, and live-car probe method. For how `CarPlayDaemon` and `CarPlayConnectivity` gate ALPS compatibility, toggle per-transport Wi-Fi QoS, and drive read-only link logging, see [docs/CONNECTIVITY.md](CONNECTIVITY.md).

Status legend:
- **Confirmed in car (upstream):** Verified working on live HU_ENTRYNAV2 / NBT Evo vehicles in `EntryNav2-Android-Auto` (`v0.12.0`–`v0.13.0-rc.6`) or its referenced system binaries.
- **Confirmed on car system (upstream/sysroot):** Extracted directly from BMW head-unit binaries/configs (`libvmostclient`, `libevo_btappl`, `libAppFramework`, `libNmeCarPlay`, `wland`, sysroot).
- **Verified in DiPlay:** Confirmed against the reference `DiPlay-main` CarPlay stack.
- **Unverified (needs car):** Inferred or unexercised on a real vehicle/iPhone; must be validated during live head-unit testing.

---

## 1. Bluetooth & ALPS Evolution SPP Stack (`docs/BLUETOOTH.md`, `docs/IAP2.md`)

| Constant / Fact | Value | Source | Status | Dependent Code | Live-Car Probe / Failure Mode |
| --- | --- | --- | --- | --- | --- |
| ALPS D-Bus service & object path | `org.alps.evolution`, `/org/alps/evolution/hli` | Upstream `platform/alps_spp.cpp` | Confirmed in car (upstream) | [alps_spp.hpp](../include/carplay/platform/alps_spp.hpp) | `bt_probe.sh` (`dbus-send ListNames` & `Introspect`) |
| ALPS D-Bus interfaces & SPP/DM fkts | `org.alps.evo.SPP`, `org.alps.evo.DM`, DM `fn = 1`, config `0x6203`, max chunk `1024` B | Upstream `platform/alps_spp.cpp` | Confirmed in car (upstream) | `alps_spp.cpp` | `probeAlpsSppCompat()` checks D-Bus owner |
| `libdbus-1` runtime SONAME | `libdbus-1.so.3` (fallback `libdbus-1.so`), `dlopen` only | Upstream `platform/alps_spp.cpp` | Confirmed on car system (upstream) | `alps_spp.cpp`, `scripts/ci/sysroot_symbols.txt` | Checked by `check_sysroot_symbols.sh` & `bt_probe.sh` |
| `libevo_btappl.so` `.dynsym` table sizes | `app` = `15032` B, `spp_info` = `480` B, `spp_connected` = `36` B | Upstream `platform/evo_spp_snapshot.cpp` | Confirmed in car on reference car; **varies by build** (2017 F20 has `15024/480/36`, upstream `#106`) | [spp_snapshot.hpp](../include/carplay/platform/spp_snapshot.hpp), [bt_transport.cpp](../src/platform/bt_transport.cpp), [carplay_connectivity.cpp](../src/platform/carplay_connectivity.cpp) | `extractSppLayout()` refuses mismatched sizes (`unknown ALPS structure`) instead of reading wrong offsets; `CarPlayConnectivity` runs `probeAlpsSppCompat()` before ALPS startup and falls back to RFCOMM / disables wireless (`usb_mode=true` informational in wired-only mode); `bt_probe.sh` prints `readelf -Ws` sizes |
| `libevo_btappl.so` internal offsets | `app+0x514` state[6], `app+0x64c` record (stride `34`), `spp_info` stride `80`, `spp_connected` stride `6` | Upstream `platform/evo_spp_snapshot.cpp` | Confirmed in car when sizes match `15032/480/36` | `spp_snapshot.cpp` | Protected by GOT relocation + size guard |
| ALPS SPP slot assignment | Slot `0` = BMW Apps / My BMW (read-only protected by default); Slot `1` = native CarPlay (`...caff`/`...cafe`); Slot `5` = spare borrowable slot (`0x6203 = 1` on start, restored on stop) | Upstream `platform/alps_spp.cpp`, `DiPlay` | Confirmed in car (upstream) for AA slots 0/1/5; CarPlay iAP2 over ALPS **unverified on live car** | [spp_snapshot.hpp](../include/carplay/platform/spp_snapshot.hpp) | Test live iPhone BT SPP connect on native slot 1 vs borrowed slot 5 |
| `gen_GetConfig` readable slots | `slot <= 1` (`2..5` return slot 0 value on read) | Upstream `platform/alps_spp.hpp` | Confirmed on car system (upstream) | `alpsSlotConfigurationReadable()` | Verified via `SppSnapshotReader` snapshot read-back |
| iAP2 / CarPlay SPP UUID pair | Initiator `00000000-deca-fade-deca-deafdecacaff`, record `00000000-deca-fade-deca-deafdecacafe` | Upstream `tests/fixtures/spp-bmw-uuids.txt` (`evo_config.xml`), `DiPlay` | Confirmed on car system (upstream); live phone handshake **unverified** | [sdp_record.hpp](../include/carplay/sdp_record.hpp), `carPlayIap2UuidPair()` | `bt_probe.sh` greps `evo_config.xml` |
| Standard BlueZ fallback | `AF_BLUETOOTH` / `BTPROTO_RFCOMM`, `/var/run/sdp`, `org.bluez` | Standard Linux/BlueZ | Absent on reference EVO ALPS units (`kBtBackendNone` or `ALPS` selected) | `bt_rfcomm.cpp`, `bt_transport.cpp` | `bt_probe.sh` checks `/sys/class/bluetooth` & sockets |
| BMW Apps BT coex monitoring | `readBmwAppsSlot()` reads slot `0` for `WifiLinkLog` | Upstream `platform/wifi_link.*` (`#71`, `#111`, `v0.13.0-rc.6`) | Confirmed in car (upstream): BT slot 0 shares WL18xx chip with Wi-Fi | [wifi_link.hpp](../include/carplay/platform/wifi_link.hpp), [carplay_connectivity.cpp](../src/platform/carplay_connectivity.cpp) | `CarPlayConnectivity` hooks `WifiLinkLog::setAppsProbe()` on wireless AirPlay sessions; check `[wifi-link]` logs during BT+Wi-Fi bring-up |

---

## 2. Wi-Fi AP, Network QoS, mDNS & Link Diagnostics (`docs/WIRELESS.md`, `docs/CONNECTIVITY.md`)

| Constant / Fact | Value | Source | Status | Dependent Code | Live-Car Probe / Failure Mode |
| --- | --- | --- | --- | --- | --- |
| Wireless socket video QoS (`IP_TOS`) | `IP_TOS` / `IPV6_TCLASS = 0x80` (WMM `AC_VI`); no `SO_PRIORITY`; **wireless only** (USB left `0`) | Upstream `v0.13.0-rc.6` (`2777f12`, from BMW `libNmeCarPlay.so` `SocketSetQoS`) | Confirmed on car system (`libNmeCarPlay.so`, upstream) | [net_compat.hpp](../include/carplay/platform/net_compat.hpp), [session_server.hpp](../include/carplay/platform/session_server.hpp), [media_engine.hpp](../include/carplay/platform/media_engine.hpp), [carplay_connectivity.cpp](../src/platform/carplay_connectivity.cpp) | `CarPlayConnectivity` sets `SessionServer::setWifiVideoQos(true)` for wireless and `false` for wired; inspect Wi-Fi packet WMM UP=4 / DSCP AF41 on live AP capture |
| BMW `wland` AP paths & library | `/tmp/wland/ap.conf`, `/var/run/hostapd/wlan0`, `/usr/local/lib/libwpa_client.so.1` | Sysroot + upstream `platform/evo_ap.*` | Confirmed in car (upstream) & verified in sysroot | `evo_ap.cpp`, `wifi_ap.hpp` | `iw dev` & `hostapd` socket inspection |
| vMOST hotspot control (`wland`) | `FBlock=0xA0`, `Inst=0x01`, `Get/Status/Set` `0xC10`/`0xC11`, payload `57 41 01` (on) / `57 41 00` (off) | Upstream `platform/evo_wlan.*` | Confirmed in car (upstream) | `evo_wlan.hpp` | Confirm `wlan0` starts & `APConnectionTimeout` behavior on car |
| iAP2 `WiFiSecurityType` & `0x5703` | `kWirelessSecurityWpaWpa2 = 2U` (not `3`); BSSID, SSID, WPA2-PSK, channel | `DiPlay-main`, `iap2_messages.hpp` | Verified in `DiPlay`; live iPhone pairing **unverified** | `wifi_ap.hpp`, `iap2_messages.hpp` | Validate `0x5702`/`0x5703` trace with live iPhone |
| mDNS library (`libdns_sd.so.0`) | `/usr/local/lib/libdns_sd.so.0`: exports 21 `DNSService*` symbols, **0 `TXTRecord*` symbols** | Sysroot (`nm`/`objdump` on `libdns_sd.so.0`) | Verified in sysroot; live `mdnsd` registration **unverified** | `mdns_advertiser.cpp` (`dns_wire.hpp` TXT encoder) | Run `dns-sd -B _airplay._tcp local.` on HU |
| WL18xx / `wlcore` `nl80211` quirks | `STA_INFO_SIGNAL = 0` when unmeasured (`< 0` valid); `TX_BITRATE` always lies (`1.0 Mbit/s`) | Upstream `v0.13.0-rc.4` (`#80`, `f0a684b`) | Confirmed in car (upstream on TI WL18xx EVO) | [wifi_link.cpp](../src/platform/wifi_link.cpp) | Check `[wifi-link]` logs for RSSI & RX rate |
| Wireless lockfile path | `/tmp/entry-carplayd-wireless.lock` (`kWirelessLock`) | Adapted from upstream `/tmp/entry-aad-wireless.lock` | Convention | [service_contract.hpp](../include/carplay/platform/service_contract.hpp) | Only one wireless negotiation at a time |

---

## 3. Wired USB, iAP2 & Native `MediaPlayer` Coexistence (`docs/USB_WIRED.md`, `docs/IAP2.md`)

| Constant / Fact | Value | Source | Status | Dependent Code | Live-Car Probe / Failure Mode |
| --- | --- | --- | --- | --- | --- |
| Apple USB VID & Role Switch | VID `0x05AC`; vendor IN `bmRequestType=0xc0, bRequest=0x52, wValue=0, wIndex=4, wLength=1` + mode query `0xc0/0x45` | `DiPlay-main` (`IphoneUsbHost.kt`) | Verified in `DiPlay`; live HU attach **unverified** | `usb_descriptors.hpp`, `usb_host.cpp`, `usb_carplay_bridge.cpp` | Run `usb_probe.sh` with iPhone attached |
| USBMUX & Apple Ethernet tuples | USBMUX `0xff/0xfe/0x02` (`0x04` OUT / `0x85` IN); CDC-NCM `0x02/0x0d/0x00`; Apple Ethernet `0xff/0xfd/0x01`; NTB-16 `kMaxNtb16Datagrams=256`, alt setting `1` | `DiPlay-main` (`IphoneCarPlayConfiguration.kt`, `Ntb16Codec.kt`) | Verified in `DiPlay`; raw bulk `0xff/0xf0/0x00` **unverified** | `usb_descriptors.hpp`, `cdc_ncm.hpp` | Inspect live iPhone `lsusb -v` / sysfs descriptors on HU |
| Kernel & userspace USB ownership | Sysroot lacks `cdc_ncm.ko`/`ipheth.ko`; has `snd-usb-audio`, `usbhid`, `hid-generic`, `/opt/app/usr/MediaPlayer/bin/CARPLAY`; `usbfs` driver holds userspace claims | Sysroot + `docs/SYSROOT_CHECK.md` + upstream `docs/USB.md` | Verified in sysroot & confirmed in car (upstream never detaches BMW `"usbfs"` owner) | `usb_host.cpp`, [usb_carplay_bridge.hpp](../include/carplay/platform/usb_carplay_bridge.hpp) | `usb_probe.sh` inspects `/dev/bus/usb/*` open FDs |
| Persistent USB config file | `/var/local/data/CarPlay/usb` (`kUsb`): empty = any external port, non-empty = pinned sysfs port (e.g. `3-1`), invalid blocks start; max 3 phone resets | Upstream `docs/USB.md`, `tools/aa_supervisor.cpp` | Confirmed in car (upstream for AA); USB port layout on target HU **unverified** | [service_contract.hpp](../include/carplay/platform/service_contract.hpp), [USB_WIRED.md](USB_WIRED.md) | Confirm armrest/console USB port sysfs path (`3-1`, etc.) |
| TUN/TAP NCM bridge interface | `/dev/net/tun` (`IFF_TAP | IFF_NO_PI`), IPv6 link-local (`fe80::/64`) | Sysroot (`CONFIG_TUN`) + `DiPlay-main` | Sysroot kernel config verified; live HU permissions **unverified** | `tap_iface.cpp` | Check `/dev/net/tun` perms & `disable_ipv6` on HU |
| iAP2 link/EA constants | Frame sync `0xFF 0x5A`, Link Control, Accessory Identification, EA protocol `com.apple.carplay`, Control `7000` | `DiPlay-main`, `docs/IAP2.md` | Verified in `DiPlay`; live iPhone iAP2 **unverified** | `iap2_wire.hpp`, `iap2_link.hpp`, `iap2_session.hpp` | Capture live iAP2 negotiation on HU |

---

## 4. Video, Audio, Input, HMI & Vehicle Variant Facts (Phase 3 Foundation)

| Constant / Fact | Value | Source | Status | Dependent Code | Live-Car Probe / Failure Mode |
| --- | --- | --- | --- | --- | --- |
| Screen resolutions & ratios | `800x480` (i3, F20, F48, MINI F57) & `1280x480` (G20, G01, F20, F30, F45, F48, F54); MINI round bezel `40` px (`1280`) / `25` px (`800`) | Upstream `docs/COMPATIBILITE.md` `v0.13.0-rc.4/5` | Confirmed in car (upstream) | `airplay_config.hpp`, `evo_video.hpp` | `evo_display_probe.sh` |
| Touchscreen PDU & F45 drag fix | UDP `160.48.199.115:30501 -> 30567`, magic `B0 04 80 02`, `contact.state = (at[5] >> 4) & 0x03` | Upstream `#60` (`98320f3`), `HmiMain3D` `CTouchDataClient` | Confirmed in car (upstream on G20 & F45) | [evo_touch_frame.hpp](../include/carplay/platform/evo_touch_frame.hpp) | Test multi-touch drag on resistive/capacitive panels |
| vMOST controller, MFL & volume | `0xE5.{01,03,05}` (`0xC46`/`0xC47`/`0xC4F` & `0xC10`/`0xC20`); `0x15.{02,0C}` MFL/volume; `0x20.00` AudioMaster `data[0] <= 1 && data[1] == 0`; F20 5-btn `kCcsBtnMedia=0x08`, `kCcsBtnCom=0x40`; MAP kept for nav | Upstream `platform/evo_knob.cpp`, `TARGET_HARDWARE.md`, upstream `#1`/`add9669` | Confirmed in car (upstream) + HU log (`F20`) | [evo_knob.cpp](../src/platform/evo_knob.cpp), [evo_ccs.hpp](../include/carplay/platform/evo_ccs.hpp) | Test knob, MFL Tel/PTT, volume & hard keys on HU |
| HMI Plugin ABI & `HoldMachine` | `bmw::PluginApp` vtable `172` B (`libAppFramework.A.so`); RHMI states `10..14`; `sensors.PDCStatus` (`pdc 1/0`); reverse camera settle `kCameraWaitS = 15`; `MediaDoublePress::kOtherInput = 8` | Sysroot + upstream `v0.13.0-rc.4/6` (`#65`, `#93`, `#114`) | Confirmed in car (upstream) | [hold_machine.hpp](../include/carplay/platform/hold_machine.hpp), [peek_timing.hpp](../include/carplay/platform/peek_timing.hpp) | Exercise reverse -> neutral -> drive & PDC button in car |
| Kombi cluster Ethernet (`0xB006`) | EntryNav2 **F-series** instrument cluster is NOT on Ethernet (SOME/IP navigation guidance works on G-series / supported Kombi only) | Upstream `docs/COMPATIBILITE.md` | Confirmed in car (upstream) | Future Kombi guidance only | Keep any cluster guidance strictly opt-in / non-blocking |
| Video/Audio HW (`libvdec`/`OmapDrm`/Pulse) | `libvdec.so` + `OmapDrm` (`nv12`/`nv21` DRM overlay); `PulseAudio` (`libpulse.so.0` `dlopen`) | Upstream + sysroot | Confirmed in car (upstream) | `evo_video.*`, `evo_audio.*` | Run video + multi-stream audio test on HU |
