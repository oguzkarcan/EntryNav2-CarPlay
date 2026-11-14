# EntryNav2-CarPlay Progress Log

**Target Hardware:** BMW `HU_ENTRYNAV2` (EntryEVO / ARMv7 `-std=gnu++0x`)  
**Transports Targeted:** Wired USB (`iAP2` over USB + `NCM` IPv6) **and** Wireless (`Bluetooth RFCOMM` + `Wi-Fi` AP/STA + Bonjour)  
**Active Milestone:** **Phase 3 In Progress** (Phase 2 completed, host-verified)

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

## Completed Work — Phase 2 (2026-11-14, host-verified)

- [x] **P0 — Build & test foundation** (2026-11-14)
  - `Makefile` auto-discovers `src/core/*.cpp` and builds every `tests/test_*.cpp` into its own binary; `make test-host` runs all and fails if any fails; header-change rebuilds via `-MMD -MP` (objects) and header prerequisites (tests).
  - Header-only test harness `tests/test_support.hpp` (`TEST_CASE`, `CHECK`/`CHECK_EQ`/`CHECK_BYTES_EQ`/`REQUIRE`, hex helpers, per-file `test_xxx: N/N passed` summary).
  - `bplist_codec` unsigned 64-bit support: `0x14` integers with `hi == 0` decode (values >= 2^63 as `TYPE_UINT64`), encoder emits `0x14` for >= 2^63, `makeUInt`/`isUInt`/`asUInt`/`getUInt`, `toUnsignedDecimal` (for `DataStream-Salt<streamConnectionID>`); covered by `tests/test_bplist_u64.cpp` (11/11).
- [x] **P1 — RTSP/HTTP message framing (`rtsp_message`)** (2026-11-14)
  - Incremental byte-stream `Parser` (port of `RtspMessage.kt`) with `kMaxHeaderBytes = 16 KiB` / `kMaxBodyBytes = 1 MiB` caps, lowercased/trimmed ordered headers (repeated name: last value wins), `isResponse()` for event-channel status lines; request/response builders with `CSeq` echo. `tests/test_rtsp_message.cpp` (16/16).
- [x] **P2 — Encrypted control channel framing (`control_cipher`)** (2026-11-14)
  - Byte-exact `ControlCipher.kt` port: `[u16 LE len | ciphertext | tag16]`, AAD = 2-byte length header, per-direction keys + `makeCounterNonce` counters, `0x4000`-byte write chunks (empty plaintext -> one 18-byte frame), streaming partial-frame decrypt, fatal-on-auth-failure with key/buffer wipe. `tests/test_control_cipher.cpp` (19/19).
- [x] **P3 — SRP-6a pair-setup math (`bigint` + `srp6a`)** (2026-11-14)
  - Fixed-width 3072-bit (96 x `uint32_t` limbs, `uint64_t` products, no `__int128`, no heap) Montgomery/CIOS bignum with 4-bit window `modExp` (not constant-time; public setup code `3939`).
  - SRP-6a server (RFC 5054 3072-bit group, `g = 5`, SHA-512, user `Pair-Setup`) byte-compatible with `Srp6a.kt` (`min`/`pad` encodings, raw `pad(A)`, `A mod N == 0` rejected); vectors cross-checked against .NET `BigInteger`. `tests/test_bigint.cpp` (11/11), `tests/test_srp6a.cpp` (11/11).
- [x] **P4 — Realtime audio RTP & timing (`audio_rtp` + `ntp_timing`)** (2026-11-14)
  - RTP open/seal for stream types 100/101/102 (`[RTP12 | ct | tag16 | nonce tail8]`, AAD = header bytes 4..11, nonce `[0,0,0,0 | tail8]`), `audioFormat` bit -> codec mapping (AAC-LC / Opus / LPCM), `DataStream-Salt<unsigned streamConnectionID>` HKDF output/input keys, big-endian LPCM helpers, sequence-ordered `JitterBuffer`.
  - NTP 32.32 PT 210/211 request/response packets and `ClockSync` filter with injected monotonic time. `tests/test_audio_rtp.cpp` (17/17), `tests/test_ntp_timing.cpp` (10/10).
- [x] **P5 — `/info` plist & SETUP features (`airplay_info`)** (2026-11-14)
  - `AirPlayConfig`/`DisplayConfig`, `/info` bplist builder mirroring `AirPlayInfoPlist.kt` key order, `setupEnabledFeatures`, BMW `bmwEntryNav2_800x480` / `_1280x480` / `_1440x540` profiles. `tests/test_airplay_info.cpp` (25/25 after P5b).
- [x] **P5b — Reference HID layouts (`airplay_hid`)** (2026-11-14)
  - Byte-exact `AirPlayHid.kt` layouts: 2-contact 12-byte touch report (`[slot, down, x16le, y16le] x2`) with the descriptor's X/Y logical maxima = display pixels, 4-byte knob report (`[select|home<<1|back<<2, x, y, wheel]`), index-byte media/telephony reports, `TouchSlots` (port of `AirPlayTouchSlots.kt`), ZBE3 tilt -> wheel mapping (Up/Left `-1`, Down/Right `+1`). `tests/test_airplay_hid.cpp` (22/22).
- [x] **P6 — HAP pairing (`pairing`)** (2026-11-14)
  - `RandomSource`, `Identity`, `PairingStore` (+ in-memory store), Pair-Setup M1–M6 (SRP-6a `3939`), Pair-Verify M1–M4 (X25519 + Ed25519), control keys swapped (`read = Control-Write-Encryption-Key`) / event keys not swapped, single-attempt hardening (any failure discards the exchange). `tests/test_pairing.cpp` (14/14).
- [x] **P7 — AirPlay control session + event channel (`airplay_session`, `event_channel`)** (2026-11-14)
  - Sans-I/O `session::Session` port of `AirPlaySession.kt` runControl/handle: plaintext pairing, M4 written in plaintext then `ControlCipher` switch (chunking-independent: the cipher takes over at the byte after the request that enabled it), RTSP routing in the reference's precedence (SETUP / SET_PARAMETER / RECORD / TEARDOWN / buffered-audio methods, then `/pair-setup`, `/pair-verify`, `/auth-setup`, `/info`, `POST /command`, `POST /feedback`, default 200), handler failure -> 500, session SETUP (`timingPort`/`eventPort`/optional `keepAlivePort`/`enabledFeatures`) and streams SETUP (110/111, 100/101/102, 103, 130) with an ordered active-stream set, `teardownStreamTypes`, idempotent `close()`.
  - Abstract `SessionListener`, `MediaHandler`, `TransportHost` (timing/event/keep-alive ports), `AuthProvider` (Phase 5 seam; `/auth-setup` stays 400). Stream key helpers (`deriveAudioStreamKeys`, `deriveScreenStreamKey`, `deriveDataStreamSeedKey`, `streamOutputKey`/`streamInputKey`).
  - `session::EventChannel`: encrypted `POST /command` sender (exact `sendCommandLocked` bytes, CSeq from 1), `hidSendReport`, report sequences, `requestSiri`, pending night mode flushed on accept, `iAPSendMessage`; inbound requests answered 200, responses consumed.
  - Hardening: `SessionPolicy::require_verified_for_session_requests` (default on: non-pairing requests before pair-verify -> `403 Forbidden`, no side effects), max 32 streams per SETUP, type-checked plist fields, timing port range check. `tests/test_event_channel.cpp` (8/8), `tests/test_airplay_session.cpp` (21/21).
- [x] **P8 — End-to-end simulated-iPhone session (`tests/test_e2e_session.cpp`)** (2026-11-14)
  - An independent simulated iPhone (own SRP-6a client, pair-verify client, phone-side control/event/stream key labels, RTP/NTP/screen-header builders, big-endian LPCM) drives ONE `Session` with a fresh empty pairing store through the whole flow: plaintext `/info` -> pair-setup M1–M6 (accessory LTPK learned from M6, controller LTPK stored) -> pair-verify M1–M4 (M4 plaintext) -> encrypted `/info` (identical plist) -> session `SETUP` (ports, `enabledFeatures`, `onDeviceInfo`) -> event channel (pending night mode flushed on accept) -> `ntp::ClockSync` synchronised against the phone clock through PT 210/211 exchanges -> streams `SETUP` 110 / 100 (LPCM, `streamConnectionID` >= 2^63) / 101 -> `RECORD` -> HID (2-finger `TouchSlots` sequence, knob wheel/select, media, telephony, ZBE3 mapping) with phone-side bplist/CSeq checks and 200 answers, a phone->accessory event request -> screen config + 2 sealed frames to Annex B and 8 RTP audio datagrams (reordered, duplicate, one lost) through `JitterBuffer` to int16, wrong-key packet rejected -> `/feedback` (synced NTP timestamp), `/command` duck/unduck/requestUI, `SET_PARAMETER`, `FLUSH` -> partial and whole `TEARDOWN` -> disconnect (`onSessionEnded` / `closeAll` exactly once).
  - The golden path is re-run with every phone byte delivered one at a time: byte-identical accessory output. Reconnection (stored pairing -> verify + encrypted `/info`; empty store -> error TLV, plaintext, 403). Adversarial: wrong setup code + fresh-M1 retry, replayed frame, event frame on the control channel, truncated frame + silence, SETUP before verify, replaced LTPK, Content-Length 1 MiB + 1. SHA-512 regression pins of the plaintext-phase and encrypted transcripts (self-generated, not external vectors). 11/11.

**Verified host & ARMv7 GCC 4.7.2 test status (2026-11-14, after Wave A):** clean `-Wall -Wextra -Werror` build, **18 test binaries (261 tests)** all passing on Windows host (`w64devkit` GCC 16), Linux host (`clang++` / `g++`), and **Debian 7 wheezy `armhf` `g++-4.7` 4.7.2 under QEMU (`armv7-gcc47` CI job, `ARM checks: 0`)** — `test_airplay_hid` 22/22, `test_airplay_info` 28/28, `test_airplay_session` 26/26, `test_audio_rtp` 17/17, `test_bigint` 11/11, `test_bplist_u64` 11/11, `test_control_cipher` 19/19, `test_e2e_session` 15/15, `test_event_channel` 8/8, `test_mic_uplink` 5/5, `test_ntp_timing` 10/10, `test_pairing` 14/14, `test_phase1` 10/10, `test_platform_net` 14/14, `test_platform_reactor` 13/13, `test_platform_storage` 11/11, `test_rtsp_message` 16/16, `test_srp6a` 11/11.

### Known gaps / not yet verified
- No real iPhone traffic captured; all vectors come from the reference implementation or self-generated data (the P8 simulated iPhone is written from the reference/protocol description, so it cannot catch a shared misreading of the reference).
- Type-103 buffered audio (TCP, `shk` key, `SETRATE`/`GETANCHOR`) not implemented (only routed to `MediaHandler`).
- AAC-LC / Opus decoding not present in the `HU_ENTRYNAV2` sysroot; F20 profile advertises LPCM-only in the 44.1 kHz Dirana domain. `/auth-setup` MFiSAP (SHA-1/SHA-256/AES-CTR) deferred to Phase 5.
- Network session server (`F3-P3`: control TCP `:7000`, event TCP with peer-address check, screen TCP, audio data/control UDP, NTP timing UDP, keep-alive UDP) and vehicle HAL (`F3-P4`..`F3-P7`) remain in Wave B / Wave C.
- HID tilt -> wheel convention and the ZBE3 mapping are unverified against a real iPhone.
- BMW display physical sizes and the 48 kHz entertainment sample rate are estimates.
- `airplay_session` out of scope / deferred: iPhone corner masks (`SET_PARAMETER` / screen SETUP), cluster (alt-screen) content and `showUI`/`stopUI`/map zoom, video-in-car (remote-control `X-Apple-StreamID` messages are acknowledged but not dispatched; `requestUI` with the video URL is a plain `requestUI`), `sendIapMessage` timeout/poll variant, keep-alive / NTP / event socket handling itself (delegated to `TransportHost`; the event socket layer must accept only the control peer's address), reentrant/thread-safe use (callers serialise).
- The default `require_verified_for_session_requests = true` policy is a deviation from the reference (which answers SETUP etc. on an unencrypted connection); it has not been checked against real iPhone traffic.

---

## Phase 3 — In Progress

### Architecture decisions
1. All vehicle libraries (`libxsvideo`, `libasound`, `libvmostclient`, `libilm*`, `libdns_sd`, …) are loaded with `dlopen`/`dlsym` through hand-written prototypes; the daemon links only libc / libstdc++ / libpthread / librt / libdl and builds without the sysroot.
2. Single-threaded `poll()` reactor owning the `Session` and every socket; media sinks sit behind interfaces with a worker hand-off.
3. POSIX sockets with a thin Winsock compatibility layer, so the network layer stays host-testable on Windows.
4. Audio: LPCM-only advertisement on this head unit (the sysroot contains no AAC/Opus decoder); ALSA `entertainment` / `carplay_alt` / `tel_out1` playback and `mic1` capture in the Dirana 44.1 kHz domain.
5. CI: Linux host tests + GCC 4.7.x ARMv7 build-and-run under QEMU; the sysroot never leaves the PC (see `docs/BUILD.md`).

### Wave A
- [x] **F3-P0 — CI & ARM GCC 4.7 verification** (2026-11-14)
  - `.github/workflows/ci.yml`: `host-linux` (`sh scripts/ci/build_and_test.sh host`, g++ blocking + clang++ advisory), `armv7-gcc47` (Debian 7 wheezy armhf `debian/eol:wheezy` under QEMU, `g++-4.7` 4.7.2-5, `-std=gnu++0x -O2 -march=armv7-a -mfpu=neon -mfloat-abi=hard -Wall -Wextra -Werror`, builds with `make -k` and runs every test binary; checks hard-float ELF attributes, `DT_NEEDED`, max `GLIBC_2.15` / `GLIBCXX_3.4.17` / `CXXABI_1.3.6`; logs as artifact), `no-proprietary-files`.
  - `scripts/ci/build_and_test.sh` (POSIX sh, `host` / `armv7-gcc47` profiles, also usable with a cross compiler + `RUNNER="qemu-arm -L …"`), `scripts/ci/wheezy_armhf.sh` (container entry with both `wheezy` and `wheezy/updates` APT archive repos), `scripts/ci/check_repo_content.sh`; `docs/BUILD.md`; `LICENSE` (GNU GPLv3).
- [x] **F3-P1 — Core hardening + F20 profile + microphone packetizer** (2026-11-14)
  - P8 review items in `Session`: `SessionPolicy::max_pre_verify_requests = 16` (closes control channel when pre-verify request budget is exceeded), `reVerifyAllowed()` gate rejecting `/pair-setup` and `/pair-verify` (`403 Forbidden`) once control channel encryption is active (`cipher_.isReady()`), and deterministic `TEARDOWN` ordering (`MediaHandler::onStreamsTorndown` -> `TransportHost` socket cleanup -> `SessionListener::onSessionEnded` when `has_established_streams_` drops to empty).
  - BMW F20 (`HU_ENTRYNAV2`) LPCM-only / 44.1 kHz Dirana audio profile in `airplay_info`: `makeF20EntryNav2Config(EvoDisplayVariant)` (`kF20AudioFormats` 6 entries: main 44.1k stereo, alt 44.1k stereo, telephony 8k/16k/24k in+out, Siri 16k in; `makeBmwEntryNav2Config` stays as backward-compatible alias).
  - Microphone RTP packetizer (`include/carplay/mic_uplink.hpp`, `src/core/mic_uplink.cpp`, `tests/test_mic_uplink.cpp` 5/5): 12-byte RTP header V=2 PT=96, big-endian S16 PCM conversion, ChaCha20-Poly1305 sealing with `inputKey` and `[4B seq || 4B ts || 4B ssrc]` nonce.
- [x] **F3-P2 — Platform base (`src/platform/`)** (2026-11-14)
  - `net_compat`: cross-platform POSIX/Winsock2 non-blocking sockets, IPv4/IPv6 `SockAddr`, `pollSockets` (`poll()` / `WSAPoll()`), self-pipe / loopback `WakePipe`, monotonic clock (`clock_gettime(CLOCK_MONOTONIC)` / `QueryPerformanceCounter`), `sleepMs`.
  - `tcp` & `udp`: `TcpListener`, `TcpConnection` (`RecvResult` / `SendResult` with `WouldBlock` backpressure), `UdpSocket`.
  - `reactor`: single-threaded `Reactor` multiplexing fds, monotonic one-shot/repeating timers, cross-thread `post()` queue woken via `WakePipe`.
  - `os_random`, `file_util`, `pairing_storage`, `thread`, `log`: `OsRandomSource` (`/dev/urandom` / `BCryptGenRandom`), atomic temp+fsync+rename `writeFileAtomic` (`0600`), persistent `FilePairingStore` (`controller_pairings.tsv`) and `loadOrCreateAccessoryIdentity` (`accessory_ltpk.key`), RAII `Thread`/`Mutex`/`ScopedLock`.
  - Tests: `test_platform_net` (14/14), `test_platform_reactor` (13/13), `test_platform_storage` (11/11).

### Wave B
- [x] **F3-P3 — Network session server + media engine** (2026-11-14)
  - `include/carplay/platform/media_engine.hpp` & `src/platform/media_engine.cpp`: `Reactor`-driven `MediaEngine` implementing `session::MediaHandler` (Screen TCP receiver for stream types `110`/`111` with peer-host accept filter, ISO `avcC`/`hvcC` box stripping, `avcCToAnnexB` config extraction, ChaCha20-Poly1305 frame decryption and 4-byte length-prefixed-to-Annex-B conversion; Realtime Audio UDP data/control receivers for stream types `100`/`101`/`102` with 512 KiB `SO_RCVBUF`, sender-host verification, `audio::openPacket`, `audio::JitterBuffer`, and `lpcmToInt16`; Microphone RTP uplink with `MicPacketizer`, downlink/silent-start timer, reactor-thread `pushMicrophonePcm` and cross-thread `submitMicrophonePcm`; iAP2-over-CarPlay DataStream TCP receiver for stream type `130` UUID `E9459FD0-BCAD-4C45-820F-1E72447EF2F2`; `POST /feedback` responder reporting active audio streams' `sampleRate`, `streamConnectionID`, synced NTP `timestamp`, `timestampRawNs`, and `sampleTime`; `duckAudio`/`unduckAudio` state tracking and teardown cleanup).
  - `include/carplay/platform/session_server.hpp` & `src/platform/session_server.cpp`: `Reactor`-driven `SessionServer` implementing `session::TransportHost` (Control TCP listener `:7000` or ephemeral `0`, sliding-window accept rate limiting, single-active-session peer protection, unverified handshake timeout, control/event write-queue backpressure and read-pause watermark, Event TCP listener/connection with control-peer `AcceptFilter`, NTP timing UDP socket + periodic `PT 210` sender + `PT 210/211` handler ignoring non-peer senders, keep-alive UDP socket, and outbound `EventChannel` helpers `sendHidReport`, `sendHidReports`, `requestSiri`, `setNightMode`, `sendIapMessage`, `sendEventCommand`, `requestKeyFrame`).
  - `tests/test_network_session.cpp`: Real-socket loopback end-to-end test suite (`4/4` tests: `goldenRealSocketE2eAndReconnect`, `peerFilteringAndSingleSessionProtection`, `rateLimitingAndUnverifiedTimeout`, `backpressureOverflowAndScreenErrorCleanup`) over real non-blocking TCP/UDP sockets, `OsRandomSource`, and `FilePairingStore` (`19/19` host & ARM test binaries).

### Wave C (vehicle HAL, dlopen)
- [ ] **F3-P4 — Video sink**: `libxsvideo` + OMAP dma-buf + LayerManager.
- [ ] **F3-P5 — Audio sinks + microphone** (ALSA).
- [ ] **F3-P6 — Input**: ZBE3 over vmost `E5.01` / `E5.03`, touch UDP `30567` → HID over the event channel.
- [ ] **F3-P7 — Daemon `carplayd`**, HMI plugin / visibility, install layout.

---

## Next Phases (Pending)

### Phase 2 — AirPlay HAP Session, HTTP/RTSP Server & Audio Pipeline (Host-Testable)
- [x] Lightweight non-blocking HTTP/RTSP parser & responder (binary plist + TLV8 bodies, HAP encrypted block framing `[u16 LE len | ciphertext | tag16]` with the length header as AAD and up to `0x4000` bytes of plaintext per frame).
- [x] HAP `Pair-Setup` & `Pair-Verify` state machine (Ed25519 verifier + `Control-Salt` Read/Write key derivation; MFi hook = `AuthProvider`, MFiSAP itself in Phase 5).
- [x] RTSP `/info`, `SETUP`, `RECORD`, `SET_PARAMETER`, `FLUSH`, `TEARDOWN`, `/feedback`, and `/command` (inbound `requestUI` / `duckAudio` / generic; outbound `hidSendReport`, `requestSiri`, `setNightMode`, generic typed commands such as `changeModes`) state handlers (P7, host-verified; no real iPhone yet).
- [ ] AirPlay RTP audio receiver — **partly done**: RTP open/seal, per-stream keys, `audioFormat` -> codec mapping, LPCM conversion, sequence-ordered jitter buffer and NTP PT 210/211 request/response + `ClockSync` are implemented and host-verified (P4, exercised end to end in P8); AAC-LC / Opus decoding, type-103 buffered audio and the control/timing/keep-alive UDP sockets move to Phase 3.

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
