# EntryNav2-CarPlay Progress Log

**Target Hardware:** BMW `HU_ENTRYNAV2` (EntryEVO / ARMv7 `-std=gnu++0x`)  
**Transports Targeted:** Wired USB (`iAP2` over USB + `NCM` IPv6) **and** Wireless (`Bluetooth RFCOMM` + `Wi-Fi` AP/STA + Bonjour)  
**Active Milestone:** **Phase 1 Completed** (Zero-Car Host-Verified C++11 Core)

---

## Completed Work — Phase 1 (2026-11-14)

All Phase 1 protocol primitives are implemented in portable C++11 (`-std=gnu++0x`, zero external runtime dependencies beyond vendored Monocypher 4.0.3) and verified natively on the host with `-Wall -Wextra -Werror`:

- [x] **Cryptographic Foundation (`airplay_crypto`)**
  - Vendored **Monocypher 4.0.3** (`monocypher.c`, `monocypher.h`, `monocypher-ed25519.c`, `monocypher-ed25519.h`) under `third_party/monocypher/`.
  - Implemented `X25519` key generation + low-order all-zero rejection, `Ed25519` seed-preserving keypair/sign/verify, `SHA-512`, `HKDF-SHA512`, `makeCounterNonce`, `makeLabelNonce` (`PV-Msg02`, `PS-Msg05`, etc.), and both detached and combined `ChaCha20-Poly1305` (RFC 8439 IETF AEAD).
- [x] **HAP TLV8 Codec (`tlv8_codec`)**
  - Implemented multi-fragment (>255-byte) encoding & reassembly, automatic `0xff 0x00` separator insertion for adjacent repeated tags, tag lookup helpers, and truncated/malformed guardrails.
- [x] **Apple Binary Plist Codec (`bplist_codec`)**
  - Implemented `bplist00` encoder with string deduplication, ASCII (`0x5n`) & UTF-16BE (`0x6n`) conversion, Apple epoch Dates (`978307200.0s`), ints, float64, UIDs, binary data, arrays, and dicts.
  - Hardened decoder against cyclic graphs, exponential DAG fanout (`max_reads = 100,000`), nesting depth (`max_depth = 32`), total payload amplification (`max_total_decoded_bytes = 16 MB`), non-string dictionary keys, and over-wide integers/UIDs.
- [x] **iAP2 Control Session Wire Codec (`iap2_wire`)**
  - Implemented stateful `0x4040` CSM framer + link MTU packet splitter (`splitForLink`), nested group & repeated-ID parameter list codec, signed/unsigned big-endian & NUL-terminated string helpers.
  - Implemented **both Wired USB IPv6 and Wireless Wi-Fi** `0x4301` (`CarPlayStartSession`), `0x4300` (`CarPlayAvailability`), `0x4e0d` (`WirelessCarPlayUpdate`), `0x4e0e` (`DeviceTransportIdentifierNotification`), `0x5701` (`WiFiInformation`), `0x5703` (`AccessoryWiFiConfigurationInformation`), `0xae03` (`PowerSourceUpdate`), and `0xfffb` (`LocationInformation`).
- [x] **CarPlay HID & BMW ZBE3 Mapping (`airplay_hid`)**
  - Implemented HID report descriptors & builders for Touchscreen (`0x2a2a2a2a`), Rotary Knob (`0x2a2a2a2b`), Consumer Media (`0x2a2a2a2c`), and Telephony (`0x2a2a2a2d`), plus `mapZbe3ToCarPlay` mapping BMW `ZBE3` (`MENU`/`BACK`/`MEDIA`/`COM`/D-Pad/Center/Rotary) events.
- [x] **AirPlay Screen Stream Frame Processing (`screen_stream`)**
  - Implemented 128-byte packet header parser (NTP 32.32 `senderNanos` conversion & video config dimensions), ChaCha20-Poly1305 frame decrypt (`decryptFrame` & `decryptFrameInPlace`), in-place 4-byte length-prefix -> Annex B `00 00 00 01` NALU converter, and `avcC`/`hvcC` detection + SPS/PPS Annex B extraction for `EvoVideo`.
- [x] **Host Test Suite (`tests/test_phase1.cpp`)**
  - Executed via `make test-host BIN_EXT=.exe`: **10/10 test suites passing** (RFC 8439 ChaCha vector, X25519/Ed25519/HKDF, TLV8 fragmentation, Safari `bplist00` Date vector, UTF-16BE + 500KB round-trip, 6 hostile `bplist00` attacks, iAP2 streaming framer + repeated params, Wired + Wireless `0x4301`, HID descriptors + ZBE3 map, Screen 128B header + decrypt + `avcC`/Annex B).
- [x] **Claude Code Handoff & Self-Contained Workspace Migration**
  - Migrated repository, portable build/git toolchain (`w64devkit` + `MinGit`), and upstream reference repos (`DiPlay-main`, `EntryNav2-Android-Auto-0.12.0`) under `Documents\EntryNav2-CarPlay` and `Documents\EntryNav2-CarPlay-Assets`.
  - Added `CLAUDE.md` architectural/GCC-4.7/ZBE3/platform handoff guide and `scripts/dev_env.ps1` session helper; configured local SSH deploy key in `.git/config` for zero-friction `git push`.

---

## Phase 2 — In Progress

- [x] **P0 — Build & test foundation** (2026-11-14)
  - `Makefile` auto-discovers `src/core/*.cpp` and builds every `tests/test_*.cpp` into its own binary; `make test-host` runs all and fails if any fails; header-change rebuilds via `-MMD -MP` (objects) and header prerequisites (tests).
  - Header-only test harness `tests/test_support.hpp` (`TEST_CASE`, `CHECK`/`CHECK_EQ`/`CHECK_BYTES_EQ`/`REQUIRE`, hex helpers, per-file `test_xxx: N/N passed` summary).
  - `bplist_codec` unsigned 64-bit support: `0x14` integers with `hi == 0` decode (values >= 2^63 as `TYPE_UINT64`), encoder emits `0x14` for >= 2^63, `makeUInt`/`isUInt`/`asUInt`/`getUInt`, `toUnsignedDecimal` (for `DataStream-Salt<streamConnectionID>`); covered by `tests/test_bplist_u64.cpp` (11/11).

## Next Phases (Pending)

### Phase 2 — AirPlay HAP Session, HTTP/RTSP Server & Audio Pipeline (Host-Testable)
- [ ] Lightweight non-blocking HTTP/RTSP parser & responder (binary plist + TLV8 bodies, HAP encrypted block framing `[u16 LE len | ciphertext | tag16]` with the length header as AAD and up to `0x4000` bytes of plaintext per frame).
- [ ] HAP `Pair-Setup` & `Pair-Verify` state machine (client-auth MFi/Ed25519 verifier hooks + `Control-Salt` Read/Write key derivation).
- [ ] RTSP `/info`, `SETUP`, `RECORD`, `SET_PARAMETER`, `FLUSH`, `TEARDOWN`, `/feedback`, and `/command` (`hidSendReport`, `requestUI`, `changeModes`) state handlers.
- [ ] AirPlay RTP audio receiver (AAC-LC / Opus / LPCM jitter buffer, NTP/PTP timing response, control/timing UDP sockets).

### Phase 3 — BMW `HU_ENTRYNAV2` Platform Abstraction Layer (`src/platform/`)
- [ ] `EvoVideo` Annex-B surface integration (`800x480` / `1280x480` / `1440x540` display profiles).
- [ ] `EvoIlm` / `ZBE3` rotary/button reader + `EvoTouch` single/multi-touch reader + video focus arbiter.
- [ ] `EvoMic` & ALSA audio output + Navi/Siri ducking stream separation + `KombiNav` cluster HUD turn-by-turn adapter + `NMEA` GPS forwarder.

### Phase 4 — Dual Transport Integration (USB & Wireless)
- [ ] **Wired USB Transport:** `usb_device` / `devfs` host -> USB role/configuration switch (`0x12a8`/`0x12a*` iPhone CarPlay USB config) -> `usbmuxd`-less direct USB bulk iAP2 + `CDC NCM` virtual Ethernet + link-local IPv6 (`fe80::/64`) socket binding.
- [ ] **Wireless Transport:** `Bluetooth` RFCOMM iAP2 channel (SDP CarPlay service discovery) -> `0x5700/0x5701` & `0x5702/0x5703` Wi-Fi AP credential handoff -> hostapd/Wi-Fi AP interface management + lightweight mDNS/DNS-SD responder (`_airplay._tcp.local`).

### Phase 5 — Authentication Bridge & Live Vehicle Bring-Up
- [ ] Pluggable `AuthProvider` interface supporting both hardware Apple MFi CP (`I2C` coprocessor on bench/target) and optional `BAA` local/proxy test signer.
- [ ] Cross-compilation with BMW `arm-linux-gnueabihf` GCC 4.7 toolchain (`make arm-core` -> full `entrynav2_carplay` daemon binary).
- [ ] Live `HU_ENTRYNAV2` vehicle deployment & end-to-end validation (USB plug-in, Wireless BT -> Wi-Fi auto-connect, steering wheel / ZBE3 buttons, Siri mic, audio routing).
