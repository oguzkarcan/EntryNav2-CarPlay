# EntryNav2-CarPlay Araç Ziyareti Rehberi / First Car Visit Checklist

> **Altın Kural / Golden Rule:**
> Araç park halinde, kontak açık (tercihen akü destekli / motor rölantide), yazma sırasında kontağı **kesinlikle kapatmayın**.
> Önce yalnızca salt-okunur teşhis (`car_visit.sh`) → sonra `--compat` → sonra güvenli mod kurulum (`wireless=0, wired=0`) → sonra yalnızca kablolu (`wired=1`) → en son kablosuz (`wireless=1`).
>
> Car parked, ignition ON, **never turn off ignition** while `/` is mounted `rw`.
> Strict order: read-only probe (`car_visit.sh`) → `--compat` → safe-mode install (`wireless=0, wired=0`) → wired only (`wired=1`) → wireless (`wireless=1`).

---

## Bölüm I — Türkçe Rehber (Adım Adım Kontrol Listesi)

### 1. Yanınıza Alacaklarınız
- **Dizüstü bilgisayar** (SSH + SCP istemcisi kurulu; `build/arm-entrynav2/` çıktıları veya hazırlanan `install-root` paketi + `scripts/probe/` + `scripts/deploy/`).
- **ENET (OBD-to-Ethernet) kablosu** (gerekirse USB-Ethernet dönüştürücü). Varsayılan ünite IP adresi: `169.254.1.0`.
- **Head unit `root` SSH parolası**.
- **iPhone + orijinal/sertifikalı Lightning veya USB-C veri kablosu** (sadece şarj kablosu değil!).
- **İsteğe bağlı USB bellek** (çıktıları kopyalamak için, ancak SCP ile doğrudan dizüstüne çekmek daha kolaydır).

### 2. Sıra 1 — Salt-Okunur Araç Taraması (`car_visit.sh`) *(Disk yazımı YOK)*
Bu adım ünitenin kök dosya sistemine (`/`) hiçbir şey yazmaz; tüm komutlar zaman aşımı (`--timeout 5`) ile çalışır.

1. ENET kablosunu bağlayın, iPhone'u aracın kolçak/konsol USB portuna **takın** (böylece `usb_probe.sh` `0x05ac` tanımlayıcılarını ve `MediaPlayer`/`CARPLAY` sürecinin `/dev/bus/usb/*` sahipliğini görür) ve `carplayd` (ARMv7 derlemesi) ile probe betiklerini `/tmp/` (RAM) altına kopyalayın:
   ```sh
   scp build/arm-entrynav2/carplayd scripts/probe/*.sh root@169.254.1.0:/tmp/
   ssh root@169.254.1.0
   ```
2. Araç içinde `/tmp` altında çalıştırın:
   ```sh
   chmod +x /tmp/carplayd /tmp/car_visit.sh /tmp/bt_probe.sh /tmp/usb_probe.sh
   sh /tmp/car_visit.sh --daemon /tmp/carplayd --out-dir /tmp/visit_out
   cat /tmp/visit_out/carplay-visit-*/SUMMARY.txt
   ```
3. **Neden bu kadar önemli?** `SUMMARY.txt`, [docs/VEHICLE_FACTS.md](VEHICLE_FACTS.md) içindeki her *"needs car"* satırının yanıtını (`libevo_btappl.so` `.dynsym` boyutu `15032` mi `15024` mü, ALPS D-Bus, `wland`, `mdnsd`, `libdns_sd.so.0`, `/dev/net/tun`, `CARPLAY` USB sahipliği, `LayerManagerControl` çözünürlüğü, `/dev/i2c-*` MFi veriyolları) tek bir `.tar.gz` arşivinde toplar.

### 3. Sıra 2 — Kuru Çalıştırma Uyumluluk Kontrolü (`carplayd --compat`)
`carplayd` henüz sisteme kurulmadan önce RAM içinden (`/tmp`) tüm kütüphaneleri `dlopen`/`dlsym` ile test eder:
```sh
LD_LIBRARY_PATH=/usr/local/lib:/opt/hmi/lib:/usr/lib:/lib \
XDG_RUNTIME_DIR=/run/system/0 WAYLAND_DISPLAY=wayland-0 \
/tmp/carplayd --compat
```
Çıktı satırlarının anlamı:
- `@ok|...|...` — Doğrulandı.
- `@info|...|...` — Bilgilendirme (ör. opsiyonel `libbluetooth` yok, beklenen durum).
- `@warn|...|...` — Dikkat gerektirir ama engellemez (ör. `ap` şu an kapalı/idle).
- `@block|...|...` — **Engelleyici hata** (çıkış kodu `1`).
  - Eğer **sadece** `alps`/`uuid`/`spp` satırları `@block` veriyorsa kablosuz çalışmaz ama kablolu USB çalışabilir; `--wired` ile doğrulayın:
    `/tmp/carplayd --compat --wired`
  - `libxsvideo`, `libasound`, `libvmostclient`, `libdrm`, `hmi_abi`, `tap`, `usbfs` veya `data_dir` satırlarında `@block` varsa **kuruluma geçmeyin**, günlükleri geliştiriciye gönderin.

### 4. Sıra 3 — Güvenli Modda Kurulum (`install.sh`)
Varsayılan kurulum **`wireless=0` ve `wired=0`** ile kurulur. iDrive menüsünde *Apple CarPlay* görünür ama siz açana kadar Bluetooth'a, Wi-Fi'ye veya iPhone USB cihazlarına dokunmaz.

1. Bilgisayardan `install-layout` staging klasörünü ve `scripts/deploy/` betiklerini `/tmp/carplay-stage` içine kopyalayın:
   ```sh
   scp -r build/arm-entrynav2/install-root scripts/deploy root@169.254.1.0:/tmp/carplay-stage
   ```
2. Önce **dry-run** çalıştırıp her adımı inceleyin (hiçbir dosya değişmez):
   ```sh
   sh /tmp/carplay-stage/deploy/install.sh \
       --stage /tmp/carplay-stage/install-root --mode safe --dry-run
   ```
3. Gerçek kurulumu yapın (değiştirilen dosyalar `/var/local/data/CarPlay/.install-backup/` altına bayt-bayt yedeklenir, `/` geçici `rw` yapılır, `sync` edilir ve `ro` moda geri alınır):
   ```sh
   sh /tmp/carplay-stage/deploy/install.sh \
       --stage /tmp/carplay-stage/install-root --mode safe
   ```
4. Günlük kaydını açıp üniteyi yeniden başlatın:
   ```sh
   touch /var/local/data/CarPlay/maintenance
   reboot
   ```
5. Açılış sonrası kontrol:
   - iDrive **Media → Apple CarPlay** satırının göründüğünü ve iDrive'ın çökmeden stabil çalıştığını doğrulayın.
   - Güvenlik testi: `touch /var/local/data/CarPlay/killswitch` oluşturup menüden başlatmayı deneyin; `carplayd` anında durup nedenini loglamalıdır. Sonra `rm -f /var/local/data/CarPlay/killswitch` ile kaldırın.

### 5. Sıra 4 — Yalnızca Kablolu USB Modu (`wired=1`)
Kablosuzdan önce mutlaka yalnızca kablolu USB'yi test edin:
1. `/var/local/data/CarPlay/carplay.conf` dosyasında `wired=1` ve `wireless=0` (`detach_usbfs_driver=0`) yapın.
2. iPhone'u **veri kablosu** ile bağlayın ve iDrive'dan *Apple CarPlay*'i başlatın.
3. SSH ile kontrol edin:
   - `ip -6 addr show dev carplay0` (TAP arayüzü ve `fe80::/64` link-local IPv6 oluştu mu?)
   - `/tmp/entry-carplay-service.log` içinde `usbfs` çakışma (`MediaPlayer`/`CARPLAY` sahipliği) veya `0xAA00`/`0xAA02` MFi AuthProvider mesajı var mı?
   - *(Not: Faz 5 donanım MFi coprocessor/BAA imzalayıcı henüz bağlanmadıysa `UnavailableAuthProvider` logu görünmesi beklenir — USB tanımlayıcıları ve NCM/TAP açılışı doğrulanmış olur.)*

### 6. Sıra 5 — Kablosuz Mod (`wireless=1`)
Yalnızca `--compat` çıktısında `alps`, `uuid`, `spp`, `libdns_sd`, `ap`, `mdnsd` geçtiyse deneyin:
1. `/var/local/data/CarPlay/carplay.conf` dosyasında `wired=0` ve `wireless=1` yapın.
2. iDrive menüsünden durdurup tekrar başlatın.
3. Kontrol edin:
   - ALPS SPP slot 5 ödünç alımı ve durdurunca geri yüklenmesi (`Stop` sonrası `car_visit.sh` veya loglarla).
   - `iw dev` / `/var/run/hostapd/wlan0` / `dns-sd -B _airplay._tcp local.` üzerinden `_airplay._tcp` yayını.
   - `[wifi-link]` log satırları.

### 7. Günlük Toplama (Log Collection)
Sorun veya başarı sonrası bilgisayardan çekin:
```sh
scp root@169.254.1.0:/tmp/visit_out/carplay-visit-*.tar.gz .
scp root@169.254.1.0:/var/local/data/CarPlay/app.log .
scp root@169.254.1.0:/tmp/entry-carplay-service.log .
```
Test bittikten sonra flash belleği yormamak için logları kapatabilirsiniz:
`rm -f /var/local/data/CarPlay/maintenance`

### 8. Geri Alma / Acil Durum Kurtarma (Rollback)
- **Anında durdurma (flash remount gerekmez):**
  ```sh
  touch /var/local/data/CarPlay/killswitch
  touch /tmp/entry-carplay-service/STOP
  ```
- **Crash-loop korumasını sıfırlama (3 hızlı çökmeden sonra kilitlendiyse):**
  ```sh
  rm -f /tmp/entry-carplay-crash-guard /tmp/entry-carplay-disabled-until-reboot \
        /var/local/data/CarPlay/app-guard /var/local/data/CarPlay/bootguard
  ```
- **Tam kaldırma (değiştirilen dosyaları bayt-bayt geri yükler):**
  ```sh
  sh /tmp/carplay-stage/deploy/uninstall.sh --dry-run
  sh /tmp/carplay-stage/deploy/uninstall.sh
  reboot
  ```
- **iDrive ekranı donarsa:** iDrive ses/güç düğmesini yaklaşık **30 saniye** basılı tutarak üniteyi yeniden başlatın. `/` `rw` kaldıysa `mount -o remount,ro /` veya `reboot` çalıştırın.

### 9. Geliştiriciye Neler Gönderilmeli?
1. `carplay-visit-*.tar.gz` arşivi (içindeki `SUMMARY.txt` ve tüm `.txt` raporlarıyla).
2. `carplayd --compat` (ve gerekirse `--compat --wired`) tam çıktısı.
3. `/var/local/data/CarPlay/app.log` ve `/tmp/entry-carplay-service.log`.
4. Her adımda iDrive ekranı ve iPhone ekranında görülen davranış özeti (hangi USB portu kullanıldı, BMW `CARPLAY` süreci USB'yi tuttu mu, ses/görüntü/dokunmatik/ZBE3 tepkisi).

---

## Part II — English Guide (Step-by-Step Checklist)

### 1. What to Bring
- **Laptop** with SSH/SCP, built ARMv7 artifacts (`build/arm-entrynav2/carplayd`, `install-root/`), `scripts/probe/`, and `scripts/deploy/`.
- **ENET (OBD-to-Ethernet) cable** (plus Ethernet adapter if needed). Default head-unit IP: `169.254.1.0`.
- **Root SSH password** for the head unit.
- **iPhone + certified Lightning/USB-C data cable** (not charge-only).
- **Optional USB flash drive** (if not pulling logs directly via `scp`).

### 2. Step 1 — Read-Only Vehicle Probe FIRST (`car_visit.sh`)
Zero writes outside one output directory under `/tmp` (RAM); every command has a strict timeout (`--timeout 5`).

1. Plug the iPhone into the center-console/armrest USB port (so `usb_probe.sh` captures `0x05ac` descriptors and `MediaPlayer`/`CARPLAY` FD ownership), then copy `carplayd` + probe scripts to `/tmp/`:
   ```sh
   scp build/arm-entrynav2/carplayd scripts/probe/*.sh root@169.254.1.0:/tmp/
   ssh root@169.254.1.0
   ```
2. Run on the unit:
   ```sh
   chmod +x /tmp/carplayd /tmp/car_visit.sh /tmp/bt_probe.sh /tmp/usb_probe.sh
   sh /tmp/car_visit.sh --daemon /tmp/carplayd --out-dir /tmp/visit_out
   cat /tmp/visit_out/carplay-visit-*/SUMMARY.txt
   ```
3. `SUMMARY.txt` maps every *"Unverified (needs car)"* row in [docs/VEHICLE_FACTS.md](VEHICLE_FACTS.md) plus `/dev/i2c-*` MFi hardware details to exact output files and lines, packed into one timestamped `.tar.gz`.

### 3. Step 2 — Dry-Run Compatibility Self-Check (`carplayd --compat`)
Runs from `/tmp` (RAM) without modifying flash:
```sh
LD_LIBRARY_PATH=/usr/local/lib:/opt/hmi/lib:/usr/lib:/lib \
XDG_RUNTIME_DIR=/run/system/0 WAYLAND_DISPLAY=wayland-0 \
/tmp/carplayd --compat
```
- `@ok` / `@info` / `@warn`: non-blocking.
- `@block`: exit code `1`.
  - If `@block` appears **only** on `alps`/`uuid`/`spp`, wireless is unsupported on this BT build, while wired USB may still work — re-run `/tmp/carplayd --compat --wired`.
  - If `@block` appears on `libxsvideo`, `libasound`, `libvmostclient`, `libdrm`, `hmi_abi`, `tap`, `usbfs`, or `data_dir`, **do not install**; send the output and tarball back.

### 4. Step 3 — Install in Safe Mode (`install.sh`)
Safe mode installs `/var/local/data/CarPlay/carplay.conf` with **`wireless=0`**, **`wired=0`**, and **`detach_usbfs_driver=0`**.
1. Copy staged artifacts and deploy scripts to `/tmp/carplay-stage`:
   ```sh
   scp -r build/arm-entrynav2/install-root scripts/deploy root@169.254.1.0:/tmp/carplay-stage
   ```
2. Preview every action with `--dry-run` first:
   ```sh
   sh /tmp/carplay-stage/deploy/install.sh \
       --stage /tmp/carplay-stage/install-root --mode safe --dry-run
   ```
3. Run the install (backs up any existing files byte-for-byte into `/var/local/data/CarPlay/.install-backup/`):
   ```sh
   sh /tmp/carplay-stage/deploy/install.sh \
       --stage /tmp/carplay-stage/install-root --mode safe
   touch /var/local/data/CarPlay/maintenance
   reboot
   ```
4. Verify after reboot:
   - **Media → Apple CarPlay** appears in iDrive and iDrive remains stable.
   - Verify kill switch: `touch /var/local/data/CarPlay/killswitch` -> starting CarPlay exits immediately (`78`) and logs why; then `rm -f /var/local/data/CarPlay/killswitch`.

### 5. Step 4 — Enable Wired Only (`wired=1`)
1. Edit `/var/local/data/CarPlay/carplay.conf`: set `wired=1` and keep `wireless=0`, `detach_usbfs_driver=0`.
2. Connect iPhone via USB data cable and press *Start Apple CarPlay*.
3. Check `ip -6 addr show dev carplay0` and `/tmp/entry-carplay-service.log` for USB descriptor selection, `MediaPlayer`/`CARPLAY` `usbfs` coexistence, TAP creation, and iAP2/`0xAA00` diagnostics (expected until Phase 5 hardware MFi `AuthProvider` is wired).

### 6. Step 5 — Enable Wireless (`wireless=1`)
Proceed only if `--compat` passed `alps`/`uuid`/`spp`/`libdns_sd`/`ap`/`mdnsd`:
1. Edit `/var/local/data/CarPlay/carplay.conf`: set `wired=0`, `wireless=1`.
2. Restart CarPlay from the iDrive menu.
3. Verify ALPS slot 5 borrow & restore on stop, `wlan0` AP / `wland`, `_airplay._tcp` via `dns-sd -B _airplay._tcp local.`, and `[wifi-link]` logs.

### 7. Collecting Logs & Rollback
- **Pull logs:**
  ```sh
  scp root@169.254.1.0:/tmp/visit_out/carplay-visit-*.tar.gz .
  scp root@169.254.1.0:/var/local/data/CarPlay/app.log .
  scp root@169.254.1.0:/tmp/entry-carplay-service.log .
  ```
- **Immediate kill switch (no flash remount):**
  ```sh
  touch /var/local/data/CarPlay/killswitch
  touch /tmp/entry-carplay-service/STOP
  ```
- **Reset crash-loop guard (after 3 rapid crashes in 120s):**
  ```sh
  rm -f /tmp/entry-carplay-crash-guard /tmp/entry-carplay-disabled-until-reboot \
        /var/local/data/CarPlay/app-guard /var/local/data/CarPlay/bootguard
  ```
- **Full byte-for-byte uninstall:**
  ```sh
  sh /tmp/carplay-stage/deploy/uninstall.sh --dry-run
  sh /tmp/carplay-stage/deploy/uninstall.sh
  reboot
  ```
- **If iDrive freezes:** hold the iDrive volume/power knob for ~30 seconds to reboot.

### 8. What to Send Back to the Developer
1. The `carplay-visit-*.tar.gz` archive (containing `SUMMARY.txt` and all probe reports).
2. Full `carplayd --compat` (and `--compat --wired` if applicable) output.
3. `/var/local/data/CarPlay/app.log` and `/tmp/entry-carplay-service.log`.
4. Notes on which USB port was used and observed behavior at Steps 3, 4, and 5.
