# Third-Party Code & Provenance

This document records the provenance and licensing of every file in `EntryNav2-CarPlay` that contains code derived from upstream third-party projects or vendored third-party libraries.

## Licensing Notice

1. **DiPlay (`GPL-3.0`)**:
   - Copyright (c) DiPlay contributors.
   - Licensed under the GNU General Public License v3.0.
2. **EntryNav2-Android-Auto 0.12.0 & 0.13.0-rc.6 (`PolyForm-Noncommercial-1.0.0`)**:
   - Required Notice: `Copyright (c) 2026 Jiraiya43 - EntryNav2 (EntryEvo) Android Auto`
   - Licensed under the PolyForm Noncommercial License 1.0.0.
   - **Important License Incompatibility Note**: `PolyForm Noncommercial License 1.0.0` restricts use to noncommercial purposes and is **not compatible with GPL-3.0** (which forbids additional noncommercial restrictions on redistributed combined works under Section 7 / Section 10). The EntryNav2-Android-Auto-derived platform modules (and dual-derived USB usbfs/bridge modules) were ported here **with the repository owner's explicit authorisation** for personal/noncommercial head-unit research and integration in this repository; downstream redistributors cannot redistribute combined binaries under GPL-3.0 without separate permission from all relevant copyright holders.
3. **Monocypher (`BSD-2-Clause OR CC0-1.0`)**:
   - Copyright (c) 2017-2023 Loup Vaillant, Michael Savage, Fabio Scotoni (see [`third_party/monocypher/LICENCE.md`](../third_party/monocypher/LICENCE.md)).
   - Dual-licensed under 2-clause BSD or CC0-1.0.

## Summary Counts

| Upstream Source | License | Header Files | Source Files | Test Files | Other Files | Total Files |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| DiPlay (derived only) | `GPL-3.0` | 17 | 16 | 6 | 0 | **39** |
| DiPlay + EntryNav2-Android-Auto 0.12.0 (dual-derived) | `GPL-3.0` + `PolyForm-Noncommercial-1.0.0` | 2 | 2 | 0 | 0 | **4** |
| EntryNav2-Android-Auto 0.12.0 / 0.13.0-rc.6 (derived only) | `PolyForm-Noncommercial-1.0.0` | 8 | 8 | 1 | 0 | **17** |
| Monocypher (vendored) | `BSD-2-Clause OR CC0-1.0` | 2 | 2 | 0 | 1 | **5** |
| **Total** | | **29** | **28** | **7** | **1** | **65** |

*(Note: Total derived files = 60 across `include/`, `src/`, and `tests/`; total third-party/derived files including vendored Monocypher = 65.)*

---

## Derived Files: DiPlay (`GPL-3.0`)

| Repository File | Upstream Source File(s) in `DiPlay-main` | License |
| --- | --- | --- |
| `include/carplay/airplay_hid.hpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{AirPlayHid,AirPlayTouchSlots,CarPlayMediaButton,AirPlaySession}.kt`, `common/src/main/java/com/shilapi/xcertplay/{CarPlayRemoteKeys,WheelKeyService}.kt` | `GPL-3.0` |
| `src/core/airplay_hid.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{AirPlayHid,AirPlayTouchSlots,CarPlayMediaButton,AirPlaySession}.kt`, `common/src/main/java/com/shilapi/xcertplay/{CarPlayRemoteKeys,WheelKeyService}.kt` | `GPL-3.0` |
| `tests/test_airplay_hid.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{AirPlayHid,AirPlayTouchSlots,CarPlayMediaButton,AirPlaySession}.kt`, `shared/src/test/java/com/shilapi/xcertplay/airplay/{AirPlayHidInputSemanticsTest,AirPlayTouchSlotsTest,CarPlayMediaButtonTest}.kt` | `GPL-3.0` |
| `include/carplay/airplay_info.hpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{AirPlayInfoPlist,AirPlayDisplaySettings,AirPlayConfig,AirPlaySession}.kt` | `GPL-3.0` |
| `src/core/airplay_info.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{AirPlayInfoPlist,AirPlayDisplaySettings,AirPlayConfig,AirPlaySession}.kt` | `GPL-3.0` |
| `tests/test_airplay_info.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{AirPlayInfoPlist,AirPlayHid}.kt`, `shared/src/test/java/com/shilapi/xcertplay/airplay/AirPlayInfoPlistTest.kt` | `GPL-3.0` |
| `include/carplay/airplay_session.hpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{AirPlaySession,CarPlayMediaEngine}.kt` | `GPL-3.0` |
| `src/core/airplay_session.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{AirPlaySession,CarPlayMediaEngine}.kt` | `GPL-3.0` |
| `include/carplay/audio_rtp.hpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{AudioStream,MicrophonePacketizer,CarPlayMediaEngine,BufferedAudioStream}.kt` | `GPL-3.0` |
| `src/core/audio_rtp.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{AudioStream,MicrophonePacketizer,CarPlayMediaEngine,BufferedAudioStream}.kt` | `GPL-3.0` |
| `include/carplay/auth_provider.hpp` | `shared/src/main/java/com/shilapi/xcertplay/mfi/Iap2MfiAuthenticationClient.kt` | `GPL-3.0` |
| `include/carplay/cdc_ncm.hpp` | `shared/src/main/java/com/shilapi/xcertplay/transport/{Ntb16Codec,NcmUsbBridge}.kt` | `GPL-3.0` |
| `src/core/cdc_ncm.cpp` | `shared/src/main/java/com/shilapi/xcertplay/transport/{Ntb16Codec,NcmUsbBridge}.kt` | `GPL-3.0` |
| `include/carplay/control_cipher.hpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/ControlCipher.kt` | `GPL-3.0` |
| `src/core/control_cipher.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/ControlCipher.kt` | `GPL-3.0` |
| `include/carplay/event_channel.hpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/AirPlaySession.kt` | `GPL-3.0` |
| `src/core/event_channel.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/AirPlaySession.kt` | `GPL-3.0` |
| `include/carplay/iap2_link.hpp` | `shared/src/main/java/com/shilapi/xcertplay/transport/{Iap2LinkEngine,Iap2LinkChannel}.kt` | `GPL-3.0` |
| `src/core/iap2_link.cpp` | `shared/src/main/java/com/shilapi/xcertplay/transport/{Iap2LinkEngine,Iap2LinkChannel}.kt` | `GPL-3.0` |
| `include/carplay/iap2_session.hpp` | `shared/src/main/java/com/shilapi/xcertplay/iap2/catalog/Iap2Endpoint.kt`, `.../transport/{Iap2IdentificationClient,Iap2WiredControlClient,Iap2WirelessControlClient,Iap2VehicleStatus,Iap2LocationClient}.kt`, `.../mfi/Iap2MfiAuthenticationClient.kt` | `GPL-3.0` |
| `src/core/iap2_session.cpp` | `shared/src/main/java/com/shilapi/xcertplay/iap2/catalog/Iap2Endpoint.kt`, `.../transport/{Iap2IdentificationClient,Iap2WiredControlClient,Iap2WirelessControlClient,Iap2VehicleStatus,Iap2LocationClient}.kt`, `.../mfi/Iap2MfiAuthenticationClient.kt` | `GPL-3.0` |
| `tests/test_iap2_identification.cpp` | `shared/src/test/java/com/shilapi/xcertplay/transport/{Iap2WirelessControlClientTest,Iap2WiredControlClientTest,Iap2IdentificationRetryTest,Iap2WirelessLinkRoleTest}.kt` | `GPL-3.0` |
| `include/carplay/iap2_wire.hpp` | `shared/src/main/java/com/shilapi/xcertplay/iap2/{catalog/Iap2Endpoint,message/Iap2Messages,wire/Iap2CsmFramer,wire/Iap2WireCodec}.kt`, `.../transport/Iap2VehicleStatus.kt` | `GPL-3.0` |
| `src/core/iap2_wire.cpp` | `shared/src/main/java/com/shilapi/xcertplay/iap2/{catalog/Iap2Endpoint,message/Iap2Messages,wire/Iap2CsmFramer,wire/Iap2WireCodec}.kt`, `.../transport/Iap2VehicleStatus.kt` | `GPL-3.0` |
| `include/carplay/mic_uplink.hpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{CarPlayMediaEngine,MicrophonePacketizer}.kt`, `shared/src/main/java/com/shilapi/xcertplay/media/MicrophoneUplink.kt` | `GPL-3.0` |
| `src/core/mic_uplink.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{CarPlayMediaEngine,MicrophonePacketizer}.kt`, `shared/src/main/java/com/shilapi/xcertplay/media/MicrophoneUplink.kt` | `GPL-3.0` |
| `tests/test_mic_uplink.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{MicrophonePacketizer,CarPlayMediaEngine}.kt`, `shared/src/test/java/com/shilapi/xcertplay/airplay/MicrophonePacketizerTest.kt` | `GPL-3.0` |
| `include/carplay/ntp_timing.hpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/NtpClock.kt` | `GPL-3.0` |
| `src/core/ntp_timing.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/NtpClock.kt` | `GPL-3.0` |
| `include/carplay/pairing.hpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{PairSetup,PairVerify,AirPlayIdentity,PairingStore}.kt` | `GPL-3.0` |
| `src/core/pairing.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/{PairSetup,PairVerify,AirPlayIdentity,PairingStore}.kt` | `GPL-3.0` |
| `include/carplay/rtsp_message.hpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/RtspMessage.kt` | `GPL-3.0` |
| `src/core/rtsp_message.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/RtspMessage.kt` | `GPL-3.0` |
| `tests/test_rtsp_message.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/RtspMessage.kt` | `GPL-3.0` |
| `include/carplay/srp6a.hpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/Srp6a.kt` | `GPL-3.0` |
| `src/core/srp6a.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/Srp6a.kt` | `GPL-3.0` |
| `tests/test_srp6a.cpp` | `shared/src/main/java/com/shilapi/xcertplay/airplay/Srp6a.kt` (RFC 5054 `N_HEX` literal & pinned vectors; client test harness is independent) | `GPL-3.0` |
| `include/carplay/usb_descriptors.hpp` | `shared/src/main/java/com/shilapi/xcertplay/transport/{IphoneCarPlayConfiguration,NcmFunctionDiscovery}.kt` | `GPL-3.0` |
| `src/core/usb_descriptors.cpp` | `shared/src/main/java/com/shilapi/xcertplay/transport/{IphoneCarPlayConfiguration,NcmFunctionDiscovery}.kt` | `GPL-3.0` |

---

## Derived Files: Dual-Derived (`DiPlay` `GPL-3.0` + `EntryNav2-Android-Auto 0.12.0` `PolyForm-Noncommercial-1.0.0`)

| Repository File | Upstream Source File(s) | License |
| --- | --- | --- |
| `include/carplay/platform/usb_host.hpp` | DiPlay `.../transport/{IphoneUsbHost,UsbConfigurationSelection}.kt`; AA `platform/{usb_devfs,usb_accessory,usb_loop}.cpp` | `GPL-3.0` + `PolyForm-Noncommercial-1.0.0` |
| `src/platform/usb_host.cpp` | DiPlay `.../transport/{IphoneUsbHost,UsbConfigurationSelection}.kt`; AA `platform/{usb_devfs,usb_accessory,usb_loop}.cpp` | `GPL-3.0` + `PolyForm-Noncommercial-1.0.0` |
| `include/carplay/platform/usb_carplay_bridge.hpp` | DiPlay `.../transport/{IphoneUsbHost,NcmUsbBridge,UsbConfigurationSelection}.kt`, `.../orchestration/WiredConfigurationAction.kt`; AA `platform/{usb_loop,usb_bridge}.cpp` | `GPL-3.0` + `PolyForm-Noncommercial-1.0.0` |
| `src/platform/usb_carplay_bridge.cpp` | DiPlay `.../transport/{IphoneUsbHost,NcmUsbBridge,UsbConfigurationSelection}.kt`, `.../orchestration/WiredConfigurationAction.kt`; AA `platform/{usb_loop,usb_bridge}.cpp` | `GPL-3.0` + `PolyForm-Noncommercial-1.0.0` |

---

## Derived Files: EntryNav2-Android-Auto 0.12.0 & 0.13.0-rc.6 (`PolyForm-Noncommercial-1.0.0`)

Required Notice: `Copyright (c) 2026 Jiraiya43 - EntryNav2 (EntryEvo) Android Auto`

| Repository File | Upstream Source File(s) in `EntryNav2-Android-Auto` (`0.12.0` / `0.13.0-rc.6`) | License |
| --- | --- | --- |
| `include/carplay/platform/alps_spp.hpp` | `platform/alps_spp.hpp`, `platform/alps_spp.cpp`, `platform/spp_advertisement.hpp`, `tools/aa_supervisor.cpp` | `PolyForm-Noncommercial-1.0.0` |
| `src/platform/alps_spp.cpp` | `platform/alps_spp.cpp`, `platform/spp_advertisement.hpp`, `tools/aa_supervisor.cpp` | `PolyForm-Noncommercial-1.0.0` |
| `include/carplay/platform/bt_transport.hpp` | `tools/aa_supervisor.cpp` (`0.13.0-rc.6` `alps`/`uuid`/`spp` compat probe additions) | `PolyForm-Noncommercial-1.0.0` |
| `src/platform/bt_transport.cpp` | `tools/aa_supervisor.cpp` (`0.13.0-rc.6` `alps`/`uuid`/`spp` compat probe additions) | `PolyForm-Noncommercial-1.0.0` |
| `include/carplay/platform/elf_symbols.hpp` | `platform/evo_elf.hpp` | `PolyForm-Noncommercial-1.0.0` |
| `src/platform/elf_symbols.cpp` | `platform/evo_elf.hpp` | `PolyForm-Noncommercial-1.0.0` |
| `include/carplay/platform/evo_ap.hpp` | `platform/evo_ap.hpp`, `platform/evo_ap.cpp`, `platform/evo_ap_config.cpp` | `PolyForm-Noncommercial-1.0.0` |
| `src/platform/evo_ap.cpp` | `platform/evo_ap.cpp`, `platform/evo_ap_config.cpp` | `PolyForm-Noncommercial-1.0.0` |
| `include/carplay/platform/evo_touch_frame.hpp` | `platform/evo_touch_frame.hpp` (`0.13.0-rc.6` `#60` state bitmask `(at[5] >> 4) & 0x03`) | `PolyForm-Noncommercial-1.0.0` |
| `include/carplay/platform/evo_wlan.hpp` | `platform/evo_wlan.hpp` | `PolyForm-Noncommercial-1.0.0` |
| `src/platform/evo_wlan.cpp` | `platform/evo_wlan.cpp` | `PolyForm-Noncommercial-1.0.0` |
| `src/platform/net_compat.cpp` | `core/tcp_server.cpp` (`0.13.0-rc.6` `IP_TOS 0x80` Wi-Fi WMM `AC_VI` helper) | `PolyForm-Noncommercial-1.0.0` |
| `tests/test_evo_wlan.cpp` | `tests/test_wifi_link.cpp` (`0.12.0` / `0.13.0-rc.6`), `platform/evo_wlan` tests | `PolyForm-Noncommercial-1.0.0` |
| `include/carplay/platform/spp_snapshot.hpp` | `platform/evo_spp_snapshot.hpp`, `platform/evo_spp_snapshot.cpp`, `platform/spp_baseline.hpp`, `platform/alps_spp_codec.cpp` | `PolyForm-Noncommercial-1.0.0` |
| `src/platform/spp_snapshot.cpp` | `platform/evo_spp_snapshot.cpp`, `platform/spp_baseline.hpp`, `platform/alps_spp_codec.cpp` | `PolyForm-Noncommercial-1.0.0` |
| `include/carplay/platform/wifi_link.hpp` | `platform/wifi_link.hpp` (`0.12.0` / `0.13.0-rc.6` `AppsSlot` probe) | `PolyForm-Noncommercial-1.0.0` |
| `src/platform/wifi_link.cpp` | `platform/wifi_link.cpp` (`0.12.0` / `0.13.0-rc.6` WL18xx & `AppsSlot` fixes) | `PolyForm-Noncommercial-1.0.0` |

---

## Protocol Constants Cross-Checked Only (Clean-Room Code)

The following files contain original C++ implementations and only reference DiPlay or EntryNav2-Android-Auto 0.12.0 to document cross-verified protocol/opcode/UUID constants:

- `include/carplay/platform/vmost_client.hpp` — `vmostd` IPC opcode constants (`0x9`, `0xA`, `0xD`, `0xF`) cross-checked with `EntryNav2-Android-Auto-0.12.0/platform/evo_wlan.cpp`.
- `include/carplay/platform/wifi_ap.hpp` — `kIap2WifiSecurityWpa2 = iap2::kWirelessSecurityWpaWpa2` (`2U`) cross-checked with `DiPlay-main/.../Iap2WirelessControlClient.kt`.
- `include/carplay/sdp_record.hpp`, `src/core/sdp_record.cpp` — 128-bit iAP2 UUID constants cross-checked with `EntryNav2-Android-Auto-0.12.0/platform/spp_baseline.hpp` and `DiPlay-main/.../CarPlayController.kt`.

---

## Vendored Third-Party Libraries

| Repository Path | Upstream Project & Version | License |
| --- | --- | --- |
| `third_party/monocypher/monocypher.c` | Monocypher (4.0.3 / `__git__` release) | `BSD-2-Clause OR CC0-1.0` |
| `third_party/monocypher/monocypher.h` | Monocypher | `BSD-2-Clause OR CC0-1.0` |
| `third_party/monocypher/monocypher-ed25519.c` | Monocypher Ed25519 | `BSD-2-Clause OR CC0-1.0` |
| `third_party/monocypher/monocypher-ed25519.h` | Monocypher Ed25519 | `BSD-2-Clause OR CC0-1.0` |
| `third_party/monocypher/LICENCE.md` | Monocypher License Text | `BSD-2-Clause OR CC0-1.0` |
