# EntryNav2-CarPlay

Open-source C++11 (`-std=gnu++0x`, GCC 4.7 compatible) Apple CarPlay receiver core targeting BMW `HU_ENTRYNAV2` (EntryEVO / OMAP5 / QNX-or-Linux service layer), supporting **both Wired USB (iAP2 over USB + NCM IPv6)** and **Wireless (Bluetooth iAP2 + Wi-Fi AP/STA IPv4/IPv6)** transports.

> [!NOTE]
> This repository is currently at **Phase 1 (Host-testable CarPlay & iAP2 protocol core)** while no target vehicle headunit is attached. No proprietary binary blobs, private keys, or MFi/BAA certificates are included.

## Architecture Overview

`EntryNav2-CarPlay` combines protocol engineering from two open-source references:

- **CarPlay & iAP2 Protocol Core** (clean C++11 port informed by [shihabal3amri/DiPlay](https://github.com/shihabal3amri/DiPlay)):
  - `airplay_crypto`: X25519 key exchange, Ed25519 signing/verification, SHA-512, HKDF-SHA512, HAP counter/label nonces, and ChaCha20-Poly1305 (RFC 8439 IETF AEAD) backed by vendored [Monocypher 4.0.3](https://monocypher.org/).
  - `tlv8_codec`: HAP TLV8 encoder/decoder with >255-byte fragmentation/reassembly and automatic `0xff 0x00` separator handling.
  - `bplist_codec`: Apple `bplist00` binary plist encoder & bounds-hardened decoder (cyclic ref, exponential array amplification, byte budget, and wide-scalar DoS protections; ASCII & UTF-16BE Unicode strings; Cocoa epoch Dates).
  - `iap2_wire`: Stateful `0x4040` CSM framer, repeated-ID & nested-group TLV parameter codec, `0x4301` `CarPlayStartSession` builder for **both Wired IPv6 and Wireless Wi-Fi**, plus `0x4300`/`0x4e0d`/`0x4e0e`/`0x5701`/`0x5703` wireless & accessory config messages.
  - `airplay_hid`: CarPlay HID report descriptors & encoders for Touchscreen (`0x2a2a2a2a`), Rotary Knob (`0x2a2a2a2b`), Media (`0x2a2a2a2c`), and Telephony (`0x2a2a2a2d`), plus BMW `HU_ENTRYNAV2` `ZBE3` controller (`MENU`/`BACK`/`MEDIA`/`COM`/rotary, tilt -> knob wheel) mapping.
  - `screen_stream`: 128-byte AirPlay screen packet header parser (NTP 32.32 `senderNanos`), ChaCha20-Poly1305 frame decryption, in-place 4-byte length-prefix -> Annex B `00 00 00 01` NALU conversion, and `avcC`/`hvcC` -> Annex B SPS/PPS extraction for `EvoVideo`.
- **BMW HU_ENTRYNAV2 Platform Integration Layer** (planned Phases 3–5, aligned with [Jiraiya43/EntryNav2-Android-Auto](https://github.com/Jiraiya43/EntryNav2-Android-Auto)):
  - Video surface (`EvoVideo`), iDrive `ZBE3` + Touchscreen (`EvoIlm`, `EvoKnob`, `EvoTouch`), ALSA/microphone (`EvoMic`), instrument cluster turn-by-turn navigation (`KombiNav`), USB `devfs` host & NCM networking (`usb_device`), and Wireless BT/Wi-Fi daemon loop.

## Project Layout

```text
EntryNav2-CarPlay/
├── include/carplay/       # Public C++11 protocol headers
├── src/core/              # Phase 1 pure C++11 implementations
├── third_party/monocypher/# Vendored Monocypher 4.0.3 (BSD-2-Clause OR CC0-1.0)
├── tests/                 # Host-runnable unit & hostile-input tests
├── Makefile               # Host test build & ARMv7 (-std=gnu++0x) cross target
└── PROGRESS.md            # Development status & phase checklist
```

## Building & Running Host Tests

Requires `g++`, `gcc`, `ar`, and `make` (tested on Windows with `w64devkit` and standard Linux toolchains):

```sh
make test-host
```

On Windows PowerShell/CMD if `test_phase1.exe` needs `.exe` suffix:

```sh
make test-host BIN_EXT=.exe
```

To cross-compile the Phase 1 core static library for BMW `HU_ENTRYNAV2` ARMv7 (GCC 4.7+ `-std=gnu++0x`):

```sh
make arm-core
```

## Multi-Phase Roadmap (USB + Wireless)

1. **Phase 1 (Complete):** Zero-car C++11 protocol core (`crypto`, `TLV8`, `bplist00`, `iAP2 wire`, `HID + ZBE3`, `ScreenStream + Annex B`) + unit tests.
2. **Phase 2:** AirPlay HTTP/RTSP server & HAP Pairing (`Pair-Setup`, `Pair-Verify`, `/info`, `/setup`, `/feedback`, `/command`, encrypted HTTP block framing) + Audio PCM/AAC RTP jitter receiver & NTP/PTP timing.
3. **Phase 3:** `EntryNav2` Platform HAL (`EvoVideo`, `EvoIlm`/`ZBE3`, `EvoTouch`, `ALSA`/`EvoMic`, `KombiNav`, `NMEA` GPS bridge).
4. **Phase 4:** Transport bring-up — **Wired** (`iAP2` over USB bulk/NCM + link-local IPv6) and **Wireless** (`Bluetooth` RFCOMM iAP2 + Wi-Fi credential exchange `0x5701`/`0x5703` + Bonjour/mDNS `_airplay._tcp`).
5. **Phase 5:** Authentication provider abstraction (`MFi` coprocessor / `BAA` local-or-proxy sign interface) and live in-vehicle bench testing.

## Third-Party Attributions

- **Monocypher 4.0.3** (`third_party/monocypher/`): Copyright (c) 2017–2020 Loup Vaillant, dual-licensed under **BSD-2-Clause OR CC0-1.0**. See [third_party/monocypher/LICENCE.md](third_party/monocypher/LICENCE.md).
- Reference architectures & protocol documentation studied from [DiPlay](https://github.com/shihabal3amri/DiPlay) and [EntryNav2-Android-Auto](https://github.com/Jiraiya43/EntryNav2-Android-Auto).
