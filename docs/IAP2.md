# iAP2 Protocol Stack & Control Flow

> Provenance: Protocol constants, link presets, identification layouts, and
> wired/wireless control flows in this stack are verified against DiPlay
> (`shared/src/main/java/com/shilapi/xcertplay/iap2/`, `transport/Iap2*.kt`,
> `mfi/Iap2MfiAuthenticationClient.kt`), GPL-3.0, Copyright (c) DiPlay contributors.
> Constants not exercised by DiPlay remain explicitly marked `unverified`.

## 1. Architecture Overview

The transport-agnostic iAP2 stack is layered in three parts:

1. **Link Layer** ([`iap2_link.hpp`](../include/carplay/iap2_link.hpp), [`iap2_link.cpp`](../src/core/iap2_link.cpp))
   - Handles detect (`FF 55 02 00 EE 10`), `FF 5A` packet framing + two's-complement header/payload checksums, stream resynchronisation, `SYN` negotiation, sliding window, EAK, cumulative ACK, `SLP`, and `RST`.
   - Ready-made transport presets:
     - `LinkConfig::wiredUsb()`: `initial_seq = 99`, sends `SYN` immediately with detect (`send_syn_with_detect = true`), `syn_retry_interval_ms = 500`, `max_syn_retries = 10`, zero-acknowledgement data mode (`rto=0, cum_ack=0, max_retx=0, max_cum_acks=0`), sessions `10` (Control v2), `11` (EA v1), `12` (FileTransfer v2).
     - `LinkConfig::wirelessBluetooth()`: waits for peer detect (`send_syn_with_detect = false`), reliable ACK/retransmit timers (`rto=4000, cum_ack=500, max_retx=4, max_cum_acks=3`), same 3 sessions.
     - `LinkConfig::wirelessTunnel()`: AirPlay Type-130 iAP2 DataStream tunnel; uses `wiredUsb()` zero-ack initiator parameters over the encrypted TCP/AirPlay stream.

2. **Wire / CSM Framing & Codecs** ([`iap2_wire.hpp`](../include/carplay/iap2_wire.hpp), [`iap2_wire.cpp`](../src/core/iap2_wire.cpp))
   - `CsmFramer` (`0x4040` frames split/reassembled across link payloads), `ParameterList` (BE16 length + BE16 ID + payload), and typed builders/parsers for `0x4300`/`0x4301`, `0x5700..0x5703`, `0x4E0D`, `0x4E0E`, `0xAE03`, `0xFFFB`, and the 5 DiPlay control subscriptions.

3. **Control Session & Auth** ([`iap2_session.hpp`](../include/carplay/iap2_session.hpp), [`iap2_session.cpp`](../src/core/iap2_session.cpp), [`auth_provider.hpp`](../include/carplay/auth_provider.hpp))
   - Drives link sync -> Identification (`0x1D00..0x1D06`) + Authentication (`0xAA00..0xAA05`) in either order -> post-auth `kSessionReady`.
   - When `config.control_mode` is `kTransportControlWired` or `kTransportControlWireless`, `Session` automatically emits proactive bring-up messages matching DiPlay and tracks `WirelessControlStatus`. (`kTransportControlManual`, the default, leaves all post-auth sends under manual caller control.)

---

## 2. Wired USB CarPlay Message Flow

```text
Accessory (HU)                                          iPhone (USB Device)
==============                                          ===================
   |                                                            |
   |-- FF 55 02 00 EE 10 (Detect) ----------------------------->|
   |-- FF 5A SYN [seq=99, zero-ack, sess 10(v2),11(v1),12(v2)]->|  (immediate)
   |<---------------------------- FF 55 02 00 EE 10 (Detect) ---|
   |<---------------------------- FF 5A SYN|ACK [ack=99] -------|
   |-- FF 5A ACK [seq=99, ack=dev_seq] ------------------------>|  [kLinkConnected]
   |                                                            |
   |<-- 0x1D00 StartIdentification -----------------------------|
   |-- 0x1D01 IdentificationInformation (wiredUsb preset:       |
   |          pwr=2, 20mA, EA(10), USBHost(16,if), RG(30)) ---->|
   |   [optional: if 0x1D03 rejects only params 6/7 msgs,       |
   |    retry 0x1D01 once omitting those unsupported IDs]       |
   |<-- 0x1D02 IdentificationAccepted --------------------------|
   |                                                            |
   |<-- 0xAA00 RequestAuthenticationCertificate ----------------|
   |-- 0xAA01 AuthenticationCertificate (DER <= 65525 B) ------>|
   |<-- 0xAA02 RequestAuthenticationChallengeResponse (<=128 B)-|
   |-- 0xAA03 AuthenticationResponse (MFi / BAA signature) ---->|
   |<-- 0xAA05 AuthenticationSucceeded -------------------------|  [kSessionReady]
   |                                                            |
   |-- 0xAE03 PowerSourceUpdate (e.g. 2400 mA, charging=1) ---->|  (proactive)
   |-- 0x5000 StartNowPlayingUpdates -------------------------->|  (proactive)
   |-- 0x5200 StartRouteGuidanceUpdates (comp=42) ------------->|  (proactive)
   |-- 0xAE00 StartPowerUpdates (params 4,5,6) ---------------->|  (proactive)
   |-- 0x4157 StartCommunicationsUpdates (params 0,4,5) ------->|  (proactive)
   |-- 0x4154 StartCallStateUpdates (params 0..4,11) ---------->|  (proactive)
   |                                                            |
   |<-- 0x4300 CarPlayAvailability (group 0: wired) ------------|
   |-- 0x4301 CarPlayStartSession (group 0: IPv6, port, pubkey)>|
   |                                                            |
   |====== USB NCM Ethernet + AirPlay TCP/RTSP (:7000) ========>|
```

---

## 3. Wireless Bluetooth Bootstrap + Type-130 Tunnel Flow

Wireless CarPlay uses two distinct iAP2 links with different identification responsibilities:

1. **Bluetooth RFCOMM bootstrap (`BLUETOOTH_BOOTSTRAP` / `wirelessBluetooth()`)**:
   authenticates the accessory and passes Wi-Fi credentials + receiver identity.
   **Deliberately omits** Location (`22`), VehicleInfo (`20`), and VehicleStatus (`21`)
   so iOS does not bind those streams to the short-lived RFCOMM connection.
2. **AirPlay Type-130 runtime tunnel (`RUNTIME_TUNNEL` / `wirelessRuntimeTunnel()`)**:
   opened inside the encrypted AirPlay session once Wi-Fi + TCP/7000 are up, carrying
   ongoing Location (`0xFFFA..0xFFFC`) and VehicleStatus (`0xA100..0xA102`) after RFCOMM closes.

```text
Accessory (HU)                                          iPhone (BT RFCOMM)
==============                                          ==================
   |-- FF 55 02 00 EE 10 (Detect) ----------------------------->|
   |<---------------------------- FF 55 02 00 EE 10 (Detect) ---|  (waits for detect)
   |-- FF 5A SYN [seq=99, rto=4000, sess 10(v2),11(v1),12(v2)]->|
   |<---------------------------- FF 5A SYN|ACK [ack=99] -------|
   |-- FF 5A ACK [seq=99, ack=dev_seq] ------------------------>|  [kLinkConnected]
   |                                                            |
   |<-- 0x1D00 StartIdentification -----------------------------|
   |-- 0x1D01 IdentificationInformation (wirelessBluetooth:     |
   |          pwr=0, 20mA, EA(10), BT(17), WCP(24), RG(30);     |
   |          NO USBHost(16), NO Location(22), NO Vehicle(20/21))|
   |   [optional 1-shot 0x1D03 retry omitting unsupported IDs]  |
   |<-- 0x1D02 IdentificationAccepted --------------------------|
   |                                                            |
   |<-- 0xAA00 .. 0xAA05 MFi / BAA Authentication ------------->|  [kSessionReady]
   |                                                            |
   |-- 5 proactive subscriptions (0x5000,0x5200,0xAE00,0x4157,0x4154) -->|
   |                                                            |
   |<-- 0x4E0D WirelessCarPlayUpdate (available=1) -------------|
   |<-- 0x5702 RequestAccessoryWiFiConfiguration ---------------|  (pre-transport cap: 5)
   |-- 0x5703 AccessoryWiFiConfiguration (SSID, pass, sec, ch) >|
   |<-- 0x4300 CarPlayAvailability (group 1: wireless) ---------|
   |-- 0x4301 CarPlayStartSession (group 1: Wi-Fi + AirPlay IP) |
   |<-- 0x4E0E DeviceTransportIdentifier (BT MAC / USB ID) -----|
   |-- 0x5703 AccessoryWiFiConfiguration (proactive resend) --->|  (post-transport cap: 2)
   |                                                            |
   |====== iPhone joins HU SoftAP + AirPlay TCP (:7000) =======>|
   |====== Optional Type-130 iAP2 Tunnel (wirelessTunnel) =====>|
   |       (LinkConfig::wirelessTunnel + wirelessRuntimeTunnel  |
   |        ident; serves 0xFFFA/0xFFFB/0xFFFC & 0xA100..0xA102)|
```

---

## 4. Corrections Applied Against DiPlay (`old -> new`)

| Symbol / Area | Old Value | New Value | DiPlay Reference |
|---|---|---|---|
| `param::kIdentWirelessCarPlayTransportComponent` | `34U` | `24U` | `Iap2Endpoint.kt:124` |
| `param::kWirelessCarPlaySupportsCarPlay` (id `3` void) | `void` (`kWirelessCarPlaySupportsCarPlay`) | `u16` (`kWirelessCarPlayTransportIdentifier = 3U`, value `1`), plus `4U` (`isAvailable` void), `5U` (`isEnabled` void), `1U` (`SSID`) | `Iap2Endpoint.kt:127-134` |
| `param::kVehicleInfoDisplayName` | `3U` | `6U` (plus `8U` MapsDisplayName, `11U` SupportedChargingConnectors) | `Iap2VehicleStatus.kt:60-62` |
| `param::kIdentSupportedLanguage` (`13U`) encoding | Repeated param `13` per string | Single `STRING_LIST` (`ParameterList::addStrings`) | `Iap2Endpoint.kt:94`, `Iap2IdentificationClient.kt:353` |
| `param::kIdentRejectedParamId` (`0U`) & `0x1D03` decode | Synthetic `kIdentRejectedParamId = 0U` | Removed; `0x1D03` uses top-level param IDs directly + BE16 unsupported message IDs in params `6` & `7` | `Iap2IdentificationClient.kt:242-299` |
| `msg::kStartPowerUpdates` (`0xAE00`) / `kStopPowerUpdates` (`0xAE02`) direction | Handled inbound from device | Sent outbound by accessory (`sendStartPowerUpdates()` / `sendStopPowerUpdates()`); device sends `0xAE01 PowerUpdate` | `Iap2Endpoint.kt:415-433` |
| `SynPayload` defaults & Control session version | `max_out=3, max_pkt=2048, rto=1000, cum=50, retx=5, cum_acks=1`, ctrl `v1` | `max_out=4, max_pkt=65535, rto=4000, cum=500, retx=4, cum_acks=3`, ctrl `v2` | `Iap2LinkEngine.kt:581-593,640-642,662-664`, `Iap2LinkChannel.kt:361-369` |
| Open-network `0x4301` passphrase (`security == 0`) | Omitted param `1` when passphrase empty | Emits param `1` empty NUL-terminated string when wireless SSID present and `security == 0` | `Iap2WirelessControlClientTest.kt:164-174` |

---

## 5. Constant Table & Provenance

### 5.1 Link Layer (`include/carplay/iap2_link.hpp`)

| Constant | Value | Status / Provenance |
|---|---|---|
| `kDetectSequence` | `FF 55 02 00 EE 10` | `verified: DiPlay Iap2LinkEngine.kt:644` |
| `kDetectBadSequence` | `FF 55 04 00 02 04 EE 08` | `unverified` (not used in DiPlay) |
| `kLinkStartMarker` | `0xFF5A` | `verified: DiPlay Iap2LinkEngine.kt:646` |
| `kLinkHeaderBytes` / `kLinkPayloadChecksumBytes` | `9` / `1` | `verified: DiPlay Iap2LinkEngine.kt:647-648` |
| `kLinkMaxPacketBytes` | `0xFFFF` (`65535`) | `verified: DiPlay Iap2LinkEngine.kt:649` |
| `kCtrlSyn` / `kCtrlAck` / `kCtrlEak` / `kCtrlRst` | `0x80` / `0x40` / `0x20` / `0x10` | `verified: DiPlay Iap2LinkEngine.kt:655-658` |
| `kCtrlSlp` | `0x08` | `unverified` (not used in DiPlay) |
| `kLinkVersion` | `1` | `verified: DiPlay Iap2LinkEngine.kt:650` |
| `kSessionTypeControl` / `FileTransfer` / `ExternalAccessory` | `0` / `1` / `2` | `verified: DiPlay Iap2LinkEngine.kt:651-652` |
| `kSynFixedPayloadBytes` / `kSynSessionEntryBytes` | `10` / `3` | `verified: DiPlay Iap2LinkEngine.kt:581-593` |
| `kDefaultControlSessionId` / `Version` | `10` / `2` | `verified: DiPlay Iap2LinkEngine.kt:588,640` |
| `kDefaultEaSessionId` / `Version` | `11` / `1` | `verified: DiPlay Iap2LinkEngine.kt:590,641; Iap2LinkChannel.kt:363` |
| `kDefaultFileTransferSessionId` / `Version` | `12` / `2` | `verified: DiPlay Iap2LinkEngine.kt:592,642` |

### 5.2 CSM Frame & Authentication Bounds (`iap2_wire.hpp`, `auth_provider.hpp`)

| Constant | Value | Status / Provenance |
|---|---|---|
| `kCsmStartMarker` | `0x4040` | `verified: DiPlay Iap2CsmFramer.kt` |
| `kCsmHeaderBytes` / `kCsmMaxFrameBytes` | `6` / `0xFFFF` | `verified: DiPlay Iap2CsmFramer.kt:157` |
| `kParamHeaderBytes` | `4` | `verified: DiPlay Iap2Wire.kt` |
| `kMaxChallengeBytes` | `128` | `verified: DiPlay Iap2MfiAuthenticationClient.kt:110` |
| `kMaxCertificateBytes` | `65525` | `verified: DiPlay Iap2MfiAuthenticationClient.kt:111` |

### 5.3 CSM Message IDs (`iap2_wire.hpp` `msg::`)

| Group | Message IDs | Status / Provenance |
|---|---|---|
| Identification | `0x1D00..0x1D03`, `0x1D05`, `0x1D06` | `verified: DiPlay Iap2Endpoint.kt:70-177` |
| Accessory Auth | `0xAA00..0xAA06` | `verified: DiPlay Iap2Endpoint.kt:179-223` |
| CarPlay Connection | `0x4300` (Avail), `0x4301` (StartSession) | `verified: DiPlay Iap2Endpoint.kt:260-337` |
| Wi-Fi Sharing | `0x5700..0x5703` | `verified: DiPlay Iap2Endpoint.kt:351-387` |
| Call State & Comms | `0x4154..0x4159` | `verified: DiPlay Iap2Endpoint.kt:459-482,646-647` |
| Device Notifications | `0x4E09..0x4E0E` | `verified: DiPlay Iap2Endpoint.kt:484-532` |
| Now Playing | `0x5000..0x5002` | `verified: DiPlay Iap2Endpoint.kt:447-458` |
| Route Guidance | `0x5200..0x5204` | `verified: DiPlay Iap2Endpoint.kt:435-446,643-645` |
| Vehicle Status | `0xA100..0xA102` | `verified: DiPlay Iap2VehicleStatus.kt:47-49` |
| Power | `0xAE00..0xAE03`, `0xAE05`, `0xAE06` | `verified: DiPlay Iap2Endpoint.kt:415-433` |
| External Accessory | `0xEA00..0xEA03` | `verified: DiPlay Iap2Endpoint.kt:534-551,688` |
| Location | `0xFFFA..0xFFFC` | `verified: DiPlay Iap2Endpoint.kt:395-413` |

### 5.4 Identification & Authentication Parameters (`iap2_session.hpp` `param::`)

| Constant | ID | Status / Provenance |
|---|---|---|
| `kIdentName` .. `kIdentHardwareVersion` | `0..5` | `verified: DiPlay Iap2Endpoint.kt:82-87` |
| `kIdentMessagesSentByAccessory` / `ReceivedFromDevice` | `6` / `7` | `verified: DiPlay Iap2Endpoint.kt:88-89` |
| `kIdentPowerProvidingCapability` / `MaxCurrentDrawn` | `8` / `9` | `verified: DiPlay Iap2Endpoint.kt:90-91` |
| `kIdentSupportedEaProtocol` (`0,1,2`) | `10` | `verified: DiPlay Iap2Endpoint.kt:92`, `Iap2IdentificationClient.kt:348-350` |
| `kIdentAppMatchTeamId` | `11` | `unverified` |
| `kIdentCurrentLanguage` / `SupportedLanguage` | `12` / `13` | `verified: DiPlay Iap2Endpoint.kt:93-94` |
| `kIdentSerialTransportComponent` | `14` | `unverified` |
| `kIdentUsbDeviceTransportComponent` (`3` sample rate) | `15` | `unverified` |
| `kIdentUsbHostTransportComponent` (`0,1,2,3,4`) | `16` | `verified: DiPlay Iap2Endpoint.kt:96-106` |
| `kIdentBluetoothTransportComponent` (`0,1,2,3,4,5`) | `17` | `verified: DiPlay Iap2Endpoint.kt:108-118` |
| `kIdentHidComponent` | `18` | `unverified` |
| `kIdentVehicleInformationComponent` (`0,1,2,6,8,11`) | `20` | `verified: DiPlay Iap2Endpoint.kt:120`, `Iap2VehicleStatus.kt:56-63` |
| `kIdentVehicleStatusComponent` (`0,1,3,6,11,15,21,30`) | `21` | `verified: DiPlay Iap2Endpoint.kt:121`, `Iap2VehicleStatus.kt:64-73` |
| `kIdentLocationInformationComponent` (`0,1,17,18,20`) | `22` | `verified: DiPlay Iap2Endpoint.kt:122`, `Iap2IdentificationClient.kt:382-388` |
| `kIdentWirelessCarPlayTransportComponent` (`0,1,2,3,4,5`) | `24` | `verified: DiPlay Iap2Endpoint.kt:124-135` |
| `kIdentRouteGuidanceDisplayComponent` (`0,1,2,4,6,7,8`) | `30` | `verified: DiPlay Iap2Endpoint.kt:137-151` |
| `kAuthCertificateData` / `ChallengeData` / `ResponseData` | `0` / `0` / `0` | `verified: DiPlay Iap2Endpoint.kt:190,197,204` |
| `kAuthCertificateSerial` | `0` | `unverified` |
