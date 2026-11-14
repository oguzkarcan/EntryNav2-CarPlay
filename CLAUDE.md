# CLAUDE.md — EntryNav2-CarPlay Handoff & Engineering Guide

This file gives Claude Code (and any contributor) everything needed to pick up **EntryNav2-CarPlay** cleanly from Phase 1 into Phases 2–5.

## 1. Project Goal & Current Situation
- **Goal:** Build an open-source C++11 Apple CarPlay receiver for **BMW `HU_ENTRYNAV2` (EntryEVO)** supporting **both**:
  1. **Wired USB CarPlay** (`iAP2` over USB bulk/mux + `CDC NCM` virtual Ethernet / link-local IPv6)
  2. **Wireless CarPlay** (`Bluetooth` RFCOMM/iAP2 via Alps D-Bus stack + `Wi-Fi` AP/STA credential handoff + Bonjour/mDNS)
- **Physical Access Status:** The user does **not** currently have continuous bench access on this Windows PC, though the target car (`2017 BMW F20 LCI`, `HU_ENTRYNAV2`, `/etc/version` `202402191339`) has been profiled over ENET — see **[docs/TARGET_HARDWARE.md](docs/TARGET_HARDWARE.md)** for verified screen (`800x480`), `ZBE3` (`E5.01`), USB (`no cdc_ncm` / `tun` available), ALSA (`carplay_alt`, `mic1`), Wi-Fi (`wl18xx`), and I2C facts. Keep all Phase 2 protocol, session, crypto, framing, and state-machine work **host-testable on PC** (`make test-host BIN_EXT=.exe`) until vehicle bring-up.
- **Language Preference:** Respond to the user in **Turkish** unless they switch language.
- **Tracking Rule:** Always update [PROGRESS.md](PROGRESS.md) after completing tasks or milestones, and commit/push verified changes cleanly to `origin/main`.

---

## 2. Local Environment, Paths & Git Setup (Windows)

Global `g++`, `make`, and `git` are **not** installed system-wide on this Windows machine. Everything portable and self-contained lives inside `Documents`:

- **Project Repo:** `C:\Users\Acer\Documents\EntryNav2-CarPlay`
- **Portable Toolchain & Reference Repos:** `C:\Users\Acer\Documents\EntryNav2-CarPlay-Assets`
  - Compiler & Make (`w64devkit` GCC 16.2.0 + GNU Make 4.4.1 + BusyBox): `..\EntryNav2-CarPlay-Assets\tools\w64devkit\bin`
  - Git (`MinGit` 2.56.1): `..\EntryNav2-CarPlay-Assets\tools\mingit\cmd`
  - Upstream Reference 1 (CarPlay protocol/AirPlay/iAP2): `..\EntryNav2-CarPlay-Assets\repos\DiPlay-main`
  - Upstream Reference 2 (BMW EntryNav2 HAL/ARMv7 build): `..\EntryNav2-CarPlay-Assets\repos\EntryNav2-Android-Auto-0.12.0`
  - Vendored Crypto Upstream Tarball Source: `..\EntryNav2-CarPlay-Assets\repos\Monocypher-4.0.3`
- **GitHub Remote & SSH Push:**
  - Remote: `git@github.com:oguzkarcan/EntryNav2-CarPlay.git` (Public repo on `main`)
  - Local `.git/config` already has `core.sshCommand` configured to use Windows OpenSSH (`C:/Windows/System32/OpenSSH/ssh.exe`) + write-enabled Deploy Key `C:/Users/Acer/.ssh/id_ed25519_entrynav2_carplay` (`IdentitiesOnly=yes`). Just use `..\EntryNav2-CarPlay-Assets\tools\mingit\cmd\git.exe push origin main`.

### Running Host Build & Tests (Windows CMD / PowerShell)
Note: PowerShell `ExecutionPolicy` on this machine blocks `.ps1` scripts unless run with `-ExecutionPolicy Bypass`. Use either the `.cmd` wrapper or inline `$env:PATH`:

```powershell
# Easiest (works in both PowerShell and CMD without ExecutionPolicy issues):
.\scripts\test_host.cmd

# Or directly in PowerShell:
$tools = "C:\Users\Acer\Documents\EntryNav2-CarPlay-Assets\tools"
$env:PATH = "$tools\w64devkit\bin;$tools\mingit\cmd;" + $env:PATH
make clean; make test-host BIN_EXT=.exe
```

---

## 3. Hard Target Constraints (`HU_ENTRYNAV2` / GCC 4.7.2)

From `EntryNav2-Android-Auto-0.12.0/Makefile`:
- **Target Architecture:** Linux ARMv7 hard-float, `glibc 2.15`, `-march=armv7-a -mfpu=neon -mfloat-abi=hard`
- **Target Compiler:** **`arm-linux-gnueabihf-g++` GCC 4.7.2** with **`-std=gnu++0x`**
- **CRITICAL C++ RULES:**
  1. Stick strictly to **GCC 4.7-compatible C++11 (`-std=gnu++0x`)**.
  2. **DO NOT use C++14/17/20 features**: no `std::optional`, `std::variant`, `std::string_view`, `std::make_unique`, `std::shared_mutex`, structured bindings, `constexpr` multi-line functions, generic `[](auto x)`, digit separators (`1'000`), or `std::filesystem`.
  3. Keep `>>` template closing spacing conservative where needed (`std::vector<std::pair<std::string, Value> >`) and keep warning-clean compilation with `-Wall -Wextra -Werror`.
  4. Avoid heavy third-party dependencies (especially Boost, OpenSSL version mismatches on glibc 2.15, etc.); keep core pure C++11 + vendored **Monocypher 4.0.3** (`BSD-2-Clause OR CC0-1.0`).

---

## 4. What Is Already Built & Verified (Phase 1 + Phase 2)

All Phase 1 modules live under `include/carplay/` and `src/core/`, compiled into `libcarplay_core.a` and verified by `tests/test_phase1.cpp` (**10/10 tests passing**):

> **Test discovery (Phase 2 P0+):** tests are auto-discovered — every `tests/test_*.cpp` builds into its own binary (`build/host/test_<name>.exe`) and `make test-host` runs all of them, failing if any fails. New test files should use the header-only harness `tests/test_support.hpp` (`TEST_CASE`, `CHECK`, `CHECK_EQ`, `CHECK_BYTES_EQ`, `REQUIRE`, `hexToBytes`/`bytesToHex`, `runAll`). Core sources are likewise auto-discovered from `src/core/*.cpp`.

1. **`airplay_crypto`** (`include/carplay/airplay_crypto.hpp`, `src/core/airplay_crypto.cpp`)
   - Wraps vendored `third_party/monocypher/` (`monocypher.c`, `monocypher-ed25519.c`).
   - Provides `X25519` (rejects all-zero low-order shared secrets), `Ed25519` keypair/sign/verify, `SHA-512`, `HKDF-SHA512`, `makeCounterNonce` (`[0,0,0,0 | le64]`), `makeLabelNonce` (e.g., `"PV-Msg02"`, `"PS-Msg05"`), and both detached and combined `ChaCha20-Poly1305` (RFC 8439 IETF 96-bit nonce).
   - **Gotcha:** Monocypher's `crypto_ed25519_key_pair()` mutates & wipes its non-const `seed` parameter; `ed25519FromSeed()` copies the seed to a mutable temp buffer first so caller seeds stay intact.
2. **`tlv8_codec`** (`include/carplay/tlv8_codec.hpp`, `src/core/tlv8_codec.cpp`)
   - HAP TLV8 encode/decode with >255-byte fragment splitting & reassembly, automatic `0xff 0x00` separator insertion between adjacent same-tag items, and truncation/bad-separator checks.
3. **`bplist_codec`** (`include/carplay/bplist_codec.hpp`, `src/core/bplist_codec.cpp`)
   - Apple `bplist00` encoder (string pooling, ASCII `0x5n` & UTF-16BE `0x6n`, Apple epoch `978307200.0` Dates, UID, Data, Array, Dict) & DoS-hardened decoder (`Limits`: `max_depth=32`, `max_reads=100000`, `max_object_bytes=4MB`, `max_total_decoded_bytes=16MB`; rejects cyclic containers, exponential DAG amplification, blob memory bombs, non-string dict keys, and oversized int/UID widths).
4. **`iap2_wire`** (`include/carplay/iap2_wire.hpp`, `src/core/iap2_wire.cpp`)
   - Stateful `0x4040` `CsmFramer` + `splitForLink` MTU packetizer.
   - `ParameterList` preserving parameter order and repeated IDs + nested groups.
   - Codecs for **both Wired IPv6 and Wireless Wi-Fi** `0x4301` (`buildStartCarPlaySession`), `0x4300` (`parseCarPlayAvailability`), `0x4e0d` (`WirelessCarPlayUpdate`), `0x4e0e` (`DeviceTransportIdentifierNotification`), `0x5701` (`WiFiInformation`), `0x5703` (`AccessoryWiFiConfigurationInformation`), `0xae03` (`PowerSourceUpdate`), and `0xfffb` (`LocationInformation`).
5. **`airplay_hid`** (`include/carplay/airplay_hid.hpp`, `src/core/airplay_hid.cpp`)
   - Descriptors & reports are byte-for-byte the reference `DiPlay-main\...\airplay\AirPlayHid.kt` (Phase 2 P5b): Touchscreen (`0x2a2a2a2a`, `touchscreenDescriptor(width_px, height_px)`: 2 finger collections, 8-bit contact id + Touch bit + 16-bit X/Y with logical max = display pixels; 12-byte `touchReport` `[slot, down, x16le, y16le] x2`, coordinates clamped to `[0, width/height]`; `TouchSlots` = port of `AirPlayTouchSlots.kt`), Knob (`0x2a2a2a2b`, 4-byte `knobReport` `[select|home<<1|back<<2, x, y, wheel]`, x/y absolute `0x02` legacy (never driven), wheel relative `0x06`, all clamped to `-127..127`), Media (`0x2a2a2a2c`, 1-byte array index 0..6: `MEDIA_PLAY=1 .. MEDIA_PREVIOUS=5`), Telephony (`0x2a2a2a2d`, 1-byte array index 0..17: `HOOK_SWITCH=1`, `DROP=3`). `uidString()` gives the lowercase-hex `uuid`; `momentaryKnobReports` / `mediaPressReports` / `telephonyPressReports` reproduce the reference send sequences (report, then neutral/0) for `hidSendReport`.
   - Hardware mapper `mapZbe3ToCarPlay(hw, knob, media_index, telephony_index)` using verified BMW `HU_ENTRYNAV2` `ZBE3` button bits:
     - `MENU = 0x01` -> CarPlay `home`
     - `BACK = 0x02` -> CarPlay `back`
     - `OPTION = 0x04` (not mapped)
     - `MEDIA = 0x08` -> `MEDIA_PLAY_PAUSE`
     - `COM = 0x40` -> `TELEPHONY_HOOK_SWITCH`
     - push -> `select`; rotation -> `wheel` (clockwise `+`); tilt Up/Left -> wheel `-1`, Down/Right -> wheel `+1` (reference D-pad convention, `CarPlayRemoteKeys.kt:67-76`); knob X/Y stay 0. `zbe3KnobReports` sends a wheel step then the same state with wheel 0.
6. **`screen_stream`** (`include/carplay/screen_stream.hpp`, `src/core/screen_stream.cpp`)
   - 128-byte AirPlay screen header parser (NTP 32.32 `senderNanos`, opcode `0` frame / `1` config, dimensions).
   - `ChaCha20-Poly1305` frame decryption (`decryptFrame`, `decryptFrameInPlace`).
   - Zero-allocation in-place 4-byte length-prefix -> Annex B (`00 00 00 01`) converter (`lengthPrefixedToAnnexBInPlace`).
   - `detectConfigCodec` (`avcC`/`hvcC`/Annex B) and `avcCToAnnexB` SPS/PPS extractor for `EvoVideo`.

**Phase 2 modules** (host-verified; 14 auto-discovered test binaries incl. the end-to-end simulated-iPhone session `tests/test_e2e_session.cpp`; see PROGRESS.md for per-binary counts):

1. **`rtsp_message`** — incremental RTSP/HTTP parser (16 KiB header / 1 MiB body caps, lowercased headers, last value wins) + request/response builders echoing `CSeq`.
2. **`control_cipher`** — `[u16 LE len | ct | tag16]`, AAD = length header, per-direction `makeCounterNonce` counters, 0x4000-byte write chunks; any auth failure is fatal.
3. **`bigint`** — fixed 3072-bit Montgomery math on `uint32_t` limbs with `uint64_t` products (no `__int128`, no heap; not constant-time).
4. **`srp6a`** — RFC 5054 3072-bit SRP-6a server, SHA-512, user `Pair-Setup`, code `3939`, byte-compatible with `Srp6a.kt`.
5. **`pairing`** — Pair-Setup M1–M6 / Pair-Verify M1–M4; control keys SWAPPED (accessory read = `Control-Write-Encryption-Key`), event keys NOT swapped; one attempt per M1.
6. **`airplay_info`** — `/info` plist in reference key order, `setupEnabledFeatures`, BMW display profiles.
7. **`audio_rtp`** — RTP `[hdr12 | ct | tag | tail8]`, AAD = header[4..12], nonce `[0,0,0,0|tail8]`; `DataStream-Salt<UNSIGNED streamConnectionID>`; wire LPCM is BIG-endian; `JitterBuffer`.
8. **`ntp_timing`** — PT 210/211 packets (NTP 32.32 BE) + `ClockSync` filter with injected monotonic time.
9. **`event_channel`** — encrypted `POST /command` sender (CSeq from 1, never reset), HID/Siri/night mode/iAP, inbound requests answered 200, responses consumed.
10. **`airplay_session`** — sans-I/O `Session` (`onControlBytes`/`onEventBytes`): pair-verify M4 is written in PLAINTEXT, then the cipher takes over at the next input byte (chunking-independent); default policy answers non-pairing requests with 403 before verify; `streamConnectionID` handled as unsigned (`plistUnsignedId`); sockets/clock delegated to `TransportHost` / `MediaHandler`.

---

## 5. Architecture Blueprint for Phases 2–5 (Reference Map)

When continuing development, inspect the two local reference repositories in `..\EntryNav2-CarPlay-Assets\repos\` rather than guessing wire details:

### Phase 2 — AirPlay Session, Pairing, HTTP/RTSP & Audio (DONE, host-verified; Phase 3 is the next task)
- Reference in `DiPlay-main\shared\src\main\java\com\shilapi\xcertplay\airplay\`:
  - `AirPlaySession.kt`: RTSP/HTTP request parser & response builder, `ControlCipher` (see `ControlCipher.kt`: each frame is `[u16 LE len | ciphertext | tag16]` where the 2-byte little-endian length header `[len_lo, len_hi]` is the AAD; writes split plaintext into blocks of up to `MAX_PAYLOAD = 0x4000` (16384) bytes, reads accept any u16 length; 16B ChaCha20-Poly1305 tag, incrementing read/write nonces via `makeCounterNonce`), `PairSetup`, `PairVerify`, `/info` (advertises HID UIDs + descriptors + display geometry), `SETUP`, `RECORD`, `SET_PARAMETER`, `FLUSH`, `TEARDOWN`, `/feedback`, `/command` (`requestUI`, `hidSendReport`, `changeModes`, `duckAudio`/`unduckAudio`), `eventServer` / `eventCipher`, and NTP/keep-alive UDP timing.
  - `AudioStream.kt`: Main audio (`type 103` buffered / realtime) & alt/TTS audio (`AAC-LC` / `Opus` / `LPCM`), RTP jitter buffer & clock sync.
- Keep `Phase 2` completely OS-agnostic (`net`/socket abstraction or pure byte-stream state machines) so host unit tests can drive full `Pair-Verify` + `/info` + `SETUP` + encrypted `POST /command` round-trips natively on Windows.

### Phase 3 — BMW `HU_ENTRYNAV2` Platform HAL (`src/platform/`) (Next Immediate Task)
- Reference in `EntryNav2-Android-Auto-0.12.0\platform\`:
  - **Video:** `evo_video.hpp` — `libxsvideo.so.4` (type 1 IVA-HD/DCE hardware H.264 decoder) -> NV12 onto Wayland IVI surface (`kAaLayerId = 0x80000000`, `LayerManager` via `evo_ilm.hpp`), fed via OMAP `dma-buf` (`omap_dmabuf.hpp`). Prepend cached Annex-B SPS/PPS (`avcCToAnnexB`) before IDR NAL units (`type 5`).
  - **Knob / Buttons / Volume / Steering Wheel:** `evo_knob.hpp` — runtime-loaded `libvmostclient.so.1`, `FBlock 0xE5` (`instance 03`, functions `C46/C47/C4F` for `CCS35up`; `instance 01` `C10/C20` fallback). Issue plain `Get` (`OpType 1`) to open `vmostd`'s `EnableFunctionBasedFiltering`. Remember `normalizePushButtons`: byte value `4` means finger resting (NOT pressed!), `1/2/3` = pressed, `0` = released. Steering wheel telephone button is `0x15.02` `fkt 0x400`.
  - **Touchscreen:** `evo_touch.hpp` — there is **no `/dev/input/event*` touch device**; `HmiMain3D` listens on UDP port `30567`. Passive tap uses `AF_PACKET` BPF on UDP `30567`; active capture connects a `SO_REUSEADDR`/`SO_REUSEPORT` UDP `30567` socket while CarPlay is visible so iDrive stops receiving touches.
  - **Microphone:** `evo_mic.hpp` — `dlopen("libasound.so.2")`, capture PCM `"mic1"` (`dsnoop ipc_key 1025`, `16 kHz mono S16LE`).
  - **Instrument Cluster Arrows:** `kombi_nav.hpp` — cluster link handle `0xC8`, yields automatically while native BMW D-Bus guidance is active.
  - **HMI Entry Point & Service Contract:** `service_contract.hpp` and `Makefile` (`hmiapp` builds `libEntryAad.so` exporting `pluginAppInfo` for `/opt/hmi/data/ro/Plugins/...`).

### Phase 4 — Dual Transport Bring-Up (Wired USB & Wireless)
- **Wired USB:**
  - `DiPlay-main\...\transport\IphoneCarPlayConfiguration.kt`: Discover iPhone USB configuration matching USBMUX (`ff.fe.02`) + CDC NCM (`02.0d`) + Apple Ethernet (`ff.fd.01`).
  - `EntryNav2-Android-Auto-0.12.0\platform\usb_loop.hpp` & `usb_devfs.cpp`: Direct kernel `usbfs` polling/claiming + role/config switch + link-local IPv6 (`fe80::/64`) over `NCM`.
- **Wireless (Bluetooth + Wi-Fi + Bonjour):**
  - `EntryNav2-Android-Auto-0.12.0\platform\alps_spp.hpp` & `wireless_loop.hpp`: No virtual serial tty (`evo_bvd` absent); talk to Alps Bluetooth stack over D-Bus (`org.alps.evolution` `/org/alps/evolution/hli`, `org.alps.evo.SPP` `BtApplSppSetUuidReq` / `BtApplSppDataReq` / `BtApplSppDataInd` / `BtApplSppDataCfm`) bridging into `iap2_wire::CsmFramer`.
  - Use `iap2_wire` Wi-Fi sharing (`0x5700..0x5703`) + `evo_ap` / hostapd + Bonjour/mDNS (`_airplay._tcp`, see `DiPlay-main\...\network\CarPlayBonjour.kt`).

### Phase 5 — MFi / BAA Authentication & Vehicle Testing
- Design a clean `AuthProvider` interface (`getCertificate()`, `signChallenge()`) so hardware MFi coprocessor I2C (if available) or external/test BAA signing providers can plug in without modifying core session code.
- **Security Hygiene:** Never commit private SSH keys, `.pk8`, `.pem`, `.p7b`, `.der`, or `offline-mfi/` assets (`.gitignore` already blocks these patterns).
