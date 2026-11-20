# Apple MFi Authentication Research & Implementation (Phase 5)

This document records the sysroot/asset research, register protocol, AirPlay `/auth-setup` MFiSAP handling, bus-sharing risks, in-car confirmation commands, and PC bench testing setup for Phase 5 MFi authentication in `EntryNav2-CarPlay`.

---

## 1. Local Research Findings & Confidence Levels

All findings below were verified in `/home/ozzy/Projects/EntryNav2-CarPlay-Assets/sysroot` (`etc/version`: `202402191339`, library-only extract without `/opt/app`), `DiPlay-main`, `EntryNav2-Android-Auto-latest`, and the live head-unit SSH profile recorded in [TARGET_HARDWARE.md](TARGET_HARDWARE.md).

| Finding | Evidence (File & Line / Offset) | Confidence |
| --- | --- | --- |
| **Linux kernel & I2C drivers** | Kernel `3.12.25-FR21.0`: `lib/modules/3.12.25-FR21.0/modules.builtin` lines `23`, `41–43`, `54` list `regmap-i2c.ko`, `i2c-core.ko`, `i2c-algo-bit.ko`, `i2c-omap.ko`, `adv7182.ko`; `modules.dep` line `81` lists `kernel/drivers/i2c/i2c-dev.ko`. No `.dtb` or kernel `.config` is present in the sysroot. | **High** |
| **No dedicated kernel MFi/iAP driver node** | `lib/udev/rules.d/` has no MFi/iAP rule (`80-udisks.rules` only sets icon metadata). Live HU profile ([TARGET_HARDWARE.md](TARGET_HARDWARE.md#L44-L49)): no `/dev/iap*`, `/dev/mfi*`, or kernel-bound `0x10`/`0x11` node in `/sys/bus/i2c/devices/` (`0-0021` `adv7182`, `1-0020` `tca6416`, `1-0058..005a` `tps659038`). | **High** |
| **Likely bus: `/dev/i2c-0` owned by `MediaPlayer` (`mplayer`)** | [TARGET_HARDWARE.md](TARGET_HARDWARE.md#L44): `/dev/i2c-0` has permissions `root:mplayer` `0660`, whereas `/dev/i2c-1` is `root:root` `0600` (holding `tca6416` and `tps659038` PMIC). Sysroot `/usr/local/lib/libauxin-apple.so.0` symlinks to `../../../opt/app/usr/MediaPlayer/lib/libauxin-apple.so.0`, and HU `/opt/app/usr/MediaPlayer/bin/CARPLAY` ([TARGET_HARDWARE.md](TARGET_HARDWARE.md#L58), [USB_WIRED.md](USB_WIRED.md#L120)) plus `libNmeCarPlay.so` (`EntryNav2-Android-Auto-latest/core/tcp_server.cpp:24`) implement BMW's native Apple/CarPlay stack. | **Medium-High** |
| **Candidate I2C address & silicon (`0x10` or `0x11`, CP 2.0C or 3.0)** | Apple Authentication Coprocessor 2.0C / 3.0 datasheet & `DiPlay-main` (`MfiDeviceScanner.kt:107`): 7-bit `0x10` (8-bit `0x20`/`0x21`) and `0x11` (8-bit `0x22`/`0x23`). Units with coding disabled or older hardware may lack a populated chip or keep it gated: `opt/hmi/lib/libhmicoding.so` contains `va_API_APPLE_AUTH_CHIP_ON_OFF` (`0x494c2`), `va_ENT_IAP2_SUPPORT` (`0x4a37c`), `va_CARPLAY_SWT` (`0x4a3ab`), and `va_ENT_BTAS_IAP` (`0x48e1b`). | **Medium** *(needs live car probe)* |
| **Concurrency / process owner of `/dev/i2c-0`** | `/dev/i2c-0` mode `0660` group `mplayer` strongly indicates `MediaPlayer` / `CARPLAY` opens `/dev/i2c-0` directly via `i2c-dev` (`root` or `mplayer` group), since `i2c-omap` + `i2c-dev` expose raw bus ioctls (`I2C_RDWR`, `I2C_SLAVE`). Whether `CARPLAY` keeps the fd open idle or opens per-session is unknown until inspected on the car. | **Medium** *(needs live car probe)* |
| **iAP2 vs AirPlay `/auth-setup`** | Over iAP2-authenticated USB/BT links (`0xAA00`–`0xAA05`), iPhones verify MFi before AirPlay and typically use HAP `pair-setup`/`pair-verify` without `/auth-setup`. However `DiPlay-main` (`AirPlaySession.kt:580-584`, `MfiSapAuthSetup.kt:20-183`) still implements `POST /auth-setup` (MFiSAP) using the same `MfiAuthenticator` so standalone AirPlay/older controllers are handled cleanly. | **High** |

---

## 2. Apple CP 2.0C / 3.0 Register Protocol & `I2cMfiAuthProvider`

Implemented in [mfi_i2c.hpp](../include/carplay/platform/mfi_i2c.hpp) and [mfi_i2c.cpp](../src/platform/mfi_i2c.cpp) behind `iap2::AuthProvider` and `session::AuthProvider`:

| Register | Size | Access | Meaning | Provenance / Status |
| --- | ---: | --- | --- | --- |
| `0x00` | 1 B | R | Device version (reject `0x00`, `0xFF`) | `DiPlay` `MfiDeviceScanner.kt:111,152-153` |
| `0x01` | 1 B | R | Firmware version | CP 2.0C / 3.0 register map (unverified in car) |
| `0x02` | 1 B | R | Protocol major version (`2` = CP 2.0C, `3` = CP 3.0) | `DiPlay` `MfiAuthenticationClient.kt:54-57,227` |
| `0x03` | 1 B | R | Protocol minor version | CP 2.0C / 3.0 register map (`unverified`) |
| `0x04` | 4 B | R | Device ID (BE) | CP 2.0C / 3.0 register map (`unverified`) |
| `0x05` | 1 B | R | Error code (best-effort diagnostic read on auth failure) | `DiPlay` `MfiAuthenticationClient.kt:122-128,228` |
| `0x10` | 1 B | R/W | Auth control (`0x01` start signature gen) / status (`0x10` done, bit `0x80` error) | `DiPlay` `MfiAuthenticationClient.kt:99,105,229,237-238` |
| `0x11` | 2 B | R | Challenge response length (BE) | `DiPlay` `MfiAuthenticationClient.kt:115,230` |
| `0x12` | N B | R | Challenge response signature data | `DiPlay` `MfiAuthenticationClient.kt:119,231` |
| `0x20` | 2 B | R/W | Challenge length (BE, `1..128`) | `DiPlay` `MfiAuthenticationClient.kt:97,232,239-240` |
| `0x21` | N B | R/W | Challenge bytes | `DiPlay` `MfiAuthenticationClient.kt:98,233` |
| `0x30` | 2 B | R | Accessory certificate length (BE) | `DiPlay` `MfiAuthenticationClient.kt:66,234` |
| `0x31..0x3F` | `<=128` B/reg | R | Accessory X.509 DER certificate pages (register increments +1 per 128 B page) | `DiPlay` `MfiAuthenticationClient.kt:72-80,235-236` |
| `0x50` | 2 B | R | Apple CA certificate length (optional inspection) | CP 2.0C / 3.0 register map (`unverified`) |

### Non-Blocking Reactor Architecture & I2C Quirk Handling

1. **Separate STOP-terminated select and read (`I2cBackend`):** Register reads issue a 1-byte write (`[reg]`) with STOP, wait `select_to_read_gap_ms` (default `5 ms` for CP 2.0C STOP/START window), then issue a pure read. Combined repeated-START write+read messages are never used.
2. **Re-select after NACK:** If the read half NACKs (e.g., sleeping coprocessor waking on I2C activity), `I2cMfiAuthProvider` rewinds to the select step so the retry never reads a stale register (`DiPlay MfiAuthenticationClient.kt:145-147`).
3. **Zero blocking on the Reactor thread:** `iap2::AuthProvider::beginGetCertificate()` and `beginSignChallenge()` run the entire probe, retry (`20 ms` up to `2000 ms`), STOP/START gap (`5 ms`), and signature poll (`10 ms` initial delay, `10 ms` poll interval, `3000 ms` timeout) state machine on `platform::Reactor` one-shot timers, cancelling timers cleanly on `Session::reset()`, link drop, or `stop()`.
4. **Linux `i2c-dev` ioctls:** `LinuxI2cBackend` uses `open(O_RDWR | O_CLOEXEC)` + `I2C_FUNCS` + `I2C_RDWR` (primary) with `I2C_SLAVE` `write()`/`read()` fallback (matching `linux_i2c_jni.c`), retries `EINTR`, maps `ENXIO`/`EREMOTEIO`/`EIO` to `kI2cNack` and `EBUSY`/`EAGAIN` to `kI2cBusy`, and **never** uses `I2C_SLAVE_FORCE` or `dlopen`.

---

## 3. AirPlay Control Session `/auth-setup` (MFiSAP)

Implemented in [mfi_sap.hpp](../include/carplay/mfi_sap.hpp) and [mfi_sap.cpp](../src/core/mfi_sap.cpp) (using `sha1`, `sha256`, and `aes128Ctr` added to [airplay_crypto.hpp](../include/carplay/airplay_crypto.hpp)), and wired into `kRouteAuthSetup` in [airplay_session.cpp](../src/core/airplay_session.cpp):

- Request body (`application/octet-stream`): `[0x01][32B peer X25519 public key]`.
- Generates ephemeral X25519 keypair, verifies non-zero shared secret, derives:
  - `aes_key = SHA-1("AES-KEY" || shared)[0..16)`
  - `aes_iv  = SHA-1("AES-IV"  || shared)[0..16)`
- Reads certificate and signs `SHA-1(acc_pk || peer_pk)` when `protocolMajor() == 2` (CP 2.0C) or `SHA-256(acc_pk || peer_pk)` when `protocolMajor() == 3` (CP 3.0).
- Returns `[32B acc_pk][u32be cert_len][cert][u32be enc_sig_len][AES-128-CTR(signature)]` with `200 OK` (`400 Bad Request` when `auth_ == NULL` or on malformed input).
- Startup warmup caches `cachedCertificate()` and `protocol_major` on the provider so `/auth-setup` avoids re-reading multi-page certificates mid-session.

---

## 4. Risks, Concurrency & Legal Notes

### I2C Bus Sharing Risk with BMW `CARPLAY` / `MediaPlayer`

Linux `i2c-dev` allows multiple processes to `open("/dev/i2c-0")`. The kernel OMAP I2C adapter lock serializes a **single** `ioctl(I2C_RDWR)` call, **not** a multi-transaction sequence (`register select` -> `5 ms` -> `read`, or `0x20` -> `0x21` -> `0x10` -> poll -> `0x11` -> `0x12`). If both BMW's `CARPLAY`/`MediaPlayer` and `carplayd` talk to the same coprocessor simultaneously:
- The other process can change the active register pointer between select and read.
- Concurrent `0x20`/`0x21`/`0x10` writes will corrupt in-flight challenge signing.
- If `i2cdetect` or another driver already bound the slave, `I2C_SLAVE` returns `EBUSY`.

**Safe defaults in this repo:**
- `--mfi-i2c` is **opt-in and OFF by default** (`CarPlayDaemon` uses `UnavailableAuthProvider` unless `--mfi-i2c` is explicitly configured).
- `LinuxI2cBackend` never uses `I2C_SLAVE_FORCE`.
- In-car deployment must confirm via the read-only commands below whether BMW `CARPLAY` holds `/dev/i2c-0` open; if it actively accesses the chip concurrently, stop/disable the competing native CarPlay handler before enabling `--mfi-i2c`.

### Legal & Licensing Note

Apple MFi Authentication Coprocessors contain factory-programmed Apple X.509 certificates and private keys governed by Apple's MFi licensing program. This repository contains **zero** proprietary Apple or BMW binaries, certificates, or keys (`scripts/ci/check_repo_content.sh`). `--mfi-i2c` provides only the clean-room protocol client to talk to local Linux `/dev/i2c-N` hardware physically present in the owner's head unit or bench setup.

---

## 5. In-Car Confirmation Commands (Read-Only Probe Checklist)

Run these commands during a live car visit (read-only inspection **first**, before attempting any register traffic):

```sh
# 1. Confirm I2C device nodes, permissions, and kernel-bound slaves
ls -l /dev/i2c*
ls -la /sys/bus/i2c/devices/
for d in /sys/bus/i2c/devices/*; do echo "$d: $(cat "$d/name" 2>/dev/null)"; done

# 2. Check which BMW process has /dev/i2c-0 or /dev/i2c-1 open
ls -l /proc/*/fd 2>/dev/null | grep i2c || true
ps | grep -i -E 'carplay|mediaplayer|mfi|iap'

# 3. Check if coding/SWT flags expose MFi chip status on the HU
# (inspect whatever coding/diagnostic dump or logs exist on /var/local or /tmp)
grep -ri "apple\|mfi\|carplay\|auth" /tmp/ 2>/dev/null | head -n 40

# 4. ONLY if no active MediaPlayer/CARPLAY session is touching the MFi chip:
#    Check available tools (i2cdetect / i2cget / i2ctransfer may or may not exist on HU)
which i2cdetect i2cget i2cset i2ctransfer || true

# 5. If i2cdetect exists (read probe at 0x10 and 0x11 only on bus 0, avoid full write scan):
i2cget -y 0 0x10 0x00 b; i2cget -y 0 0x11 0x00 b
# Repeat once after a 50ms sleep if the first read wakes the sleeping chip with ENXIO.

# 6. Once address (0x10 or 0x11) responds with non-0x00/0xFF device version:
#    Read version/ID/cert-length metadata (regs 0x00..0x04, 0x30, 0x50):
for r in 0x00 0x01 0x02 0x03; do printf "reg %s = " "$r"; i2cget -y 0 0x10 "$r" b; done
# Note: i2cget "w" / SMBus read_word swaps byte order vs BE registers; prefer carplayd's
# /dev/i2c-0 probe (STOP-terminated select + 5ms gap + I2C_RDWR read) to confirm 0x30 BE len.
```

---

## 6. External USB–I2C Adapter Testing on PC Bench

To test real iPhone MFi handshakes on a Linux PC before touching the car, attach a breakout Apple Authentication Coprocessor (CP 2.0C / 3.0, pulled up to 3.3V SDA/SCL) via any Linux mainline USB–I2C bridge that exposes a standard `/dev/i2c-N` node:

- **FT232H** (`i2c-tiny-usb` / MPSSE `libmpsse` or kernel `ftdi-sio` / `i2c-ft232h` module)
- **MCP2221 / MCP2221A** (mainline kernel `hid-mcp2221` exposes `/dev/i2c-N`)
- **CH341A** (mainline kernel `i2c-ch341` or `ch341-i2c-spi-gpio` DKMS exposes `/dev/i2c-N` supporting `I2C_RDWR`)

Once `/dev/i2c-N` appears on the PC:

```sh
# Confirm address 0x10 or 0x11 responds
i2cdetect -y N 0x10 0x11

# Launch carplayd with MFi I2C enabled on that adapter
./build/host/carplayd --mfi-i2c=/dev/i2c-N:0x10 --wired
```
