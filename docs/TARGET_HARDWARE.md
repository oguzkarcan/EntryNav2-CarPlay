# Target Hardware Profile (`HU_ENTRYNAV2` / 2017 BMW F20 LCI)

Verified via live SSH inspection over ENET on the target head unit (`/etc/version` `202402191339`). Keep all Phase 2–5 platform decisions aligned with these real hardware and OS constraints rather than assuming a generic Linux or G-series `1280x480` unit.

## 1. System & CPU

- **Kernel:** `Linux xse-j6-apn-entryevo 3.12.25-FR21.0 #1 SMP PREEMPT armv7l GNU/Linux`
- **Firmware / Version:** `/etc/version` `202402191339`
- **CPU:** `ARMv7 Processor rev 2 (v7l)` (dual-core, `neon`, `vfpv3`, `vfpv4`, `lpae`, `idiva`, `idivt`)
- **Sysroot directories for ARMv7 cross-linking:** `/lib`, `/usr/lib`, `/usr/local/lib`, `/opt/hmi/lib` (never commit BMW binaries to git).

## 2. Display & LayerManager (`EvoVideo` / `/info` / HID)

- **Native screen resolution:** `LayerManagerControl get screen 0x0` reports **`x=800, y=480`** (`hardware layer count: 0`, render order starts at `0x80000000`).
- **Implication:** Do **not** hardcode `1280x480` in `/info` (`displays`), `airplay_hid::touchscreenDescriptor(width_px, height_px)`, or `EvoVideo` / `EvoIlm`. Query the screen resolution dynamically at runtime (`800x480` on this F20, `1280x480` on wider displays).

## 3. iDrive Controller (`ZBE3` & Coding)

- **Protocol:** On this F20 LCI, the controller does **not** use `CCS35up` (`E5.03` `0xC46/0xC47/0xC4F`). It speaks the **older CCS protocol (`E5.01`, `0xC10`/`0xC20`)**.
- **HMI Variant Coding (`IHmiVariantServer`):**
  `coding b80=0 5141=1 4e59=1 4f1e=0 5486=0 role=1` (F-style 5-button controller; no `RADIO`/`NAV`/`MAP` buttons).
- **Observed `E5.01 fkt=0xc20 op=0xc` sensor bitmask (`data[6]`):**
  - `0x01`: `MENU`
  - `0x02`: `BACK`
  - `0x04`: `OPTION`
  - `0x08`: `MEDIA`
  - `0x40`: `COM`
- **Implication:** Keep `E5.01` `0xC10/0xC20` support first-class alongside `E5.03` `CCS35up`, and distinguish F-style vs G-style (`0xB80`) coding cleanly (note: `0x5141=1` with `0xB80=0` is present on this F20 `ZBE3`).

## 4. USB Subsystem & Wired CarPlay (`CDC NCM` Constraint)

- **Kernel USB network modules (`/lib/modules/3.12.25-FR21.0/kernel/drivers/net/usb/`):**
  Only `asix.ko`, `ax88179_178a.ko`, and `usbnet.ko` are present. **`cdc_ncm` / `usb_f_ncm` is NOT present** in kernel modules or `modules.builtin`.
- **USB Gadget / UDC:**
  - `/sys/class/udc/48890000.usb`
  - Loaded modules: `g_ffs`, `libcomposite`, `configfs` (with `/dev/ffs-carlife/ep0` active by default).
  - `/dev/bus/usb/` (`usbfs`) and `tun` kernel module **are** present.
- **Implication for Phase 4 Wired USB:**
  - Do **not** expect the Linux kernel to create a `usb0` network interface when an iPhone switches to CarPlay CDC-NCM (`02.0d`).
  - Wired USB CarPlay will need either a userspace CDC-NCM bridge over `/dev/bus/usb/` (`usbfs`) bridged to `/dev/net/tun` (giving the kernel a `tun` IPv6 interface for standard POSIX sockets), or a full userspace IPv6/TCP stack over `usbfs`.

## 5. I2C & Apple MFi / Authentication (Phase 5)

- **I2C buses:** `/dev/i2c-0` (`root:mplayer`, `0660`) and `/dev/i2c-1` (`root:root`, `0600`), `i2c_dev` loaded.
- **Registered `/sys/bus/i2c/devices/`:**
  - `0-0021`: `adv7182`
  - `1-0020`: `tca6416`
  - `1-0058`, `1-0059`, `1-005a`: `tps659038` (PMIC)
- **No `/dev/iap*`, `/dev/mfi*`, or kernel-bound `0x10`/`0x11` Apple Auth Coprocessor** node exists on this unit. Keep the Phase 5 `AuthProvider` interface completely decoupled from kernel device nodes.

## 6. Wireless, mDNS & Native CarPlay Artifacts

- **Wi-Fi hardware:** TI `wl18xx` (`wlcore`, `wlcore_sdio`, `mac80211`, `cfg80211`) exposing `wlan0` and `wlan1`.
- **On-device networking daemons/tools:**
  - `/usr/sbin/hostapd` (with `/etc/hostapd.conf`)
  - `/usr/sbin/udhcpd` and `/usr/sbin/dhcpd`
  - `/usr/local/bin/mdnsd` (no `avahi-daemon`; Apple-style `mdnsd` is installed)
- **Reference note:** `/opt/app/usr/MediaPlayer/bin/CARPLAY` and `/usr/local/lib/libpiapom.so.0` exist on the image.

## 7. ALSA Audio & Microphone (`/etc/asound.conf`)

- **Cards:**
  - Card 0: `dra7-entryevo` (`00-00`: `raw_tdm_dirana-0` 8ch 44.1 kHz `S32_LE`; `00-01`: `raw_tdm_bluetooth-1` 2ch 16 kHz `S32_LE`)
  - Card 9: `Loopback`
- **Named ALSA PCMs available in `/etc/asound.conf`:**
  - **Capture (Mic):** `mic1` (and `mic2`, `barge_in`, `ref_signal` via `dsnooper` `ipc_key 1025`)
  - **Playback (Dirana `dshare` `ipc_key 1024`):**
    - `entertainment` / `mmi` (`01ch`, stereo — main media)
    - `navi` (`2ch`, mono — navigation guidance)
    - `tel_out1` / `tel_out2` (`3ch`, mono — telephony)
    - `voiceprompt` (`4ch`, mono)
    - `tts` (`5ch`, mono)
    - `carplay_alt` (`6ch`, mono — dedicated CarPlay alternate audio channel already configured in `/etc/asound.conf`)
  - **Bluetooth PCM:** `bluetooth_out` / `bluetooth_in` (`hw:0,1`, 16 kHz)
