#!/bin/sh
# Host CI test for probe and deployment scripts (`car_visit.sh`, `bt_probe.sh`,
# `usb_probe.sh`, `install.sh`, `uninstall.sh`) using a fake root and stubbed tools.
# Runs completely unprivileged without touching host system files.

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
cd "$REPO_ROOT"

TMP_BASE=$(mktemp -d)
cleanup() {
    rm -rf "$TMP_BASE"
}
trap cleanup EXIT INT TERM

FAKE_ROOT="$TMP_BASE/fake_root"
STUB_BIN="$TMP_BASE/stub_bin"
OUT_DIR="$TMP_BASE/visit_out"
STAGE_DIR="$TMP_BASE/stage"

mkdir -p "$STUB_BIN" "$OUT_DIR"

# ---- 1. Build realistic HU_ENTRYNAV2 fake root ----
mkdir -p \
    "$FAKE_ROOT/etc/dbus-1/system.d" \
    "$FAKE_ROOT/etc/layermanager" \
    "$FAKE_ROOT/etc/systemd/system" \
    "$FAKE_ROOT/lib/modules/3.12.25-FR21.0/kernel/drivers/net/usb" \
    "$FAKE_ROOT/usr/lib" \
    "$FAKE_ROOT/usr/local/lib" \
    "$FAKE_ROOT/usr/local/bin" \
    "$FAKE_ROOT/usr/sbin" \
    "$FAKE_ROOT/opt/app/usr/BTMedia/evolution/stack/lib" \
    "$FAKE_ROOT/opt/app/usr/BTMedia/evolution/stack/etc" \
    "$FAKE_ROOT/opt/app/usr/MediaPlayer/bin" \
    "$FAKE_ROOT/opt/hmi/lib" \
    "$FAKE_ROOT/opt/hmi/data/ro/Plugins/ExistingBmwPlugin" \
    "$FAKE_ROOT/var/run/hostapd" \
    "$FAKE_ROOT/var/local/data" \
    "$FAKE_ROOT/tmp/wland" \
    "$FAKE_ROOT/run/system/0" \
    "$FAKE_ROOT/dev/bus/usb/001" \
    "$FAKE_ROOT/dev/net" \
    "$FAKE_ROOT/proc/101/fd" \
    "$FAKE_ROOT/proc/sys/net/ipv6/conf/all" \
    "$FAKE_ROOT/proc/sys/net/ipv6/conf/default" \
    "$FAKE_ROOT/proc/sys/net/ipv6/conf/wlan0" \
    "$FAKE_ROOT/proc/asound" \
    "$FAKE_ROOT/proc/net" \
    "$FAKE_ROOT/sys/bus/usb/devices/1-1" \
    "$FAKE_ROOT/sys/bus/usb/devices/1-1:1.0" \
    "$FAKE_ROOT/sys/bus/i2c/devices/0-0021" \
    "$FAKE_ROOT/sys/bus/i2c/devices/1-0020" \
    "$FAKE_ROOT/sys/class/net/wlan0" \
    "$FAKE_ROOT/sys/class/udc/48890000.usb"

printf '202402191339\n' > "$FAKE_ROOT/etc/version"
printf 'genivi-flip-renderorder=1\n' > "$FAKE_ROOT/etc/layermanager/compositor.conf"
printf 'pcm.carplay_alt { type dshare }\npcm.mic1 { type dsnoop }\n' > "$FAKE_ROOT/etc/asound.conf"
printf '0 - dra7-entryevo\n' > "$FAKE_ROOT/proc/asound/cards"
printf '00-00: raw_tdm_dirana-0\n' > "$FAKE_ROOT/proc/asound/pcm"
printf 'wl18xx 12345 0 - Live 0xbf000000\nwlcore 54321 1 wl18xx, Live 0xbf010000\n' > "$FAKE_ROOT/proc/modules"
printf '1234.56 2000.00\n' > "$FAKE_ROOT/proc/uptime"
printf 'console=ttyO0,115200n8\n' > "$FAKE_ROOT/proc/cmdline"
printf '/dev/root / ext4 ro,relatime 0 0\nnone /var/local ext4 rw,noexec 0 0\n' > "$FAKE_ROOT/proc/mounts"
printf '0\n' > "$FAKE_ROOT/proc/sys/net/ipv6/conf/all/disable_ipv6"
printf '0\n' > "$FAKE_ROOT/proc/sys/net/ipv6/conf/default/disable_ipv6"
printf '0\n' > "$FAKE_ROOT/proc/sys/net/ipv6/conf/wlan0/disable_ipv6"
printf 'fe80000000000000020000fffe000001 05 40 20 80 wlan0\n' > "$FAKE_ROOT/proc/net/if_inet6"
printf 'wlan0: 0 0 0 0\n' > "$FAKE_ROOT/proc/net/dev"
printf '1234-5678\n' > "$FAKE_ROOT/opt/app/usr/BTMedia/evolution/stack/lib/libevo_btappl.so"
printf '<configuration><name>"supported_services"</name><id>0x01</id><instance>0x01</instance><value>0x00000000decafadedecadeafdecacaff</value></configuration>\n' \
    > "$FAKE_ROOT/opt/app/usr/BTMedia/evolution/stack/etc/evo_config.xml"
printf '76543000-76544000 r-xp 00000000 b3:02 123 /opt/app/usr/BTMedia/evolution/stack/lib/libevo_btappl.so\n' \
    > "$FAKE_ROOT/proc/101/maps"
printf 'BTMedia\n' > "$FAKE_ROOT/proc/101/comm"
printf 'BTMedia\0--daemon\0' > "$FAKE_ROOT/proc/101/cmdline"
printf 'Uid:\t0\t0\t0\t0\n' > "$FAKE_ROOT/proc/101/status"
ln -s /dev/bus/usb/001/002 "$FAKE_ROOT/proc/101/fd/10"

printf '05ac\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1/idVendor"
printf '12a8\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1/idProduct"
printf '1\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1/busnum"
printf '2\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1/devnum"
printf '4\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1/bConfigurationValue"
printf '4\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1/bNumConfigurations"
printf '00\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1/bDeviceClass"
printf '00\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1/bDeviceSubClass"
printf '00\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1/bDeviceProtocol"
printf '480\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1/speed"
printf 'removable\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1/removable"
printf 'Apple Inc.\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1/manufacturer"
printf 'iPhone\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1/product"
printf 'FAKE1234\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1/serial"
printf '01\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1:1.0/bInterfaceNumber"
printf '00\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1:1.0/bAlternateSetting"
printf 'ff\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1:1.0/bInterfaceClass"
printf 'fe\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1:1.0/bInterfaceSubClass"
printf '02\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1:1.0/bInterfaceProtocol"
printf '02\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1:1.0/bNumEndpoints"
printf 'usbmux\n' > "$FAKE_ROOT/sys/bus/usb/devices/1-1:1.0/interface"

printf 'adv7182\n' > "$FAKE_ROOT/sys/bus/i2c/devices/0-0021/name"
printf 'i2c:adv7182\n' > "$FAKE_ROOT/sys/bus/i2c/devices/0-0021/modalias"
printf 'tca6416\n' > "$FAKE_ROOT/sys/bus/i2c/devices/1-0020/name"
printf 'i2c:tca6416\n' > "$FAKE_ROOT/sys/bus/i2c/devices/1-0020/modalias"

printf 'interface=wlan0\nssid=BMW-CarPlay\nchannel=36\nwpa_passphrase=SUPERSECRET\n' > "$FAKE_ROOT/tmp/wland/ap.conf"
: > "$FAKE_ROOT/dev/i2c-0"
: > "$FAKE_ROOT/dev/i2c-1"
: > "$FAKE_ROOT/dev/net/tun"
: > "$FAKE_ROOT/dev/bus/usb/001/002"
: > "$FAKE_ROOT/usr/local/bin/mdnsd"
: > "$FAKE_ROOT/usr/local/lib/libdns_sd.so.0"
: > "$FAKE_ROOT/usr/local/lib/libvmostclient.so.1"
: > "$FAKE_ROOT/opt/hmi/lib/libAppFramework.A.so"
: > "$FAKE_ROOT/opt/app/usr/MediaPlayer/bin/CARPLAY"

# ---- 2. Create stubbed commands in STUB_BIN ----
cat > "$STUB_BIN/uname" <<'EOF'
#!/bin/sh
echo "Linux xse-j6-apn-entryevo 3.12.25-FR21.0 #1 SMP PREEMPT armv7l GNU/Linux"
EOF
cat > "$STUB_BIN/iw" <<'EOF'
#!/bin/sh
echo "phy#0 Interface wlan0 type AP channel 36 (5180 MHz)"
EOF
cat > "$STUB_BIN/vmostctl" <<'EOF'
#!/bin/sh
echo "FBlock 0xA0 Inst 0x01; FBlock 0xE5 Inst 0x01"
EOF
cat > "$STUB_BIN/dns-sd" <<'EOF'
#!/bin/sh
echo "Browsing for _airplay._tcp.local."
EOF
cat > "$STUB_BIN/LayerManagerControl" <<'EOF'
#!/bin/sh
case "$*" in
    *"get screen 0"*) echo "screen 0 (0x0) resolution: x=800, y=480" ;;
    *) echo "layer 0x80000000" ;;
esac
EOF
cat > "$STUB_BIN/dbus-send" <<'EOF'
#!/bin/sh
echo 'string "org.alps.evolution"'
EOF
cat > "$STUB_BIN/readelf" <<'EOF'
#!/bin/sh
echo "  10: 00010000 15032 OBJECT GLOBAL DEFAULT 10 app"
echo "  11: 00020000   480 OBJECT GLOBAL DEFAULT 10 spp_info"
echo "  12: 00030000    36 OBJECT GLOBAL DEFAULT 10 spp_connected"
echo "  99: 00040000   172 OBJECT GLOBAL DEFAULT 10 _ZTVN3bmw9PluginAppE"
echo "  50: 00001000    64 FUNC GLOBAL DEFAULT 10 DNSServiceRegister"
EOF
cat > "$STUB_BIN/fake-carplayd" <<'EOF'
#!/bin/sh
echo "@ok|libasound|libasound.so.2 (10/10 symbols)"
echo "@ok|alps|pid=101 slot=5"
echo "@ok|tap|/dev/net/tun openable"
exit 0
EOF
chmod +x "$STUB_BIN"/*

# Record checksums of fake root before car_visit.sh to prove read-only behavior
BEFORE_HASH=$(find "$FAKE_ROOT" -type f -exec sha256sum {} + | sort | sha256sum)

# ---- 3. Run car_visit.sh against fake root ----
PATH="$STUB_BIN:$PATH" sh scripts/probe/car_visit.sh \
    --probe-root "$FAKE_ROOT" \
    --out-dir "$OUT_DIR" \
    --daemon "$STUB_BIN/fake-carplayd" \
    --timeout 2

AFTER_HASH=$(find "$FAKE_ROOT" -type f -exec sha256sum {} + | sort | sha256sum)
if [ "$BEFORE_HASH" != "$AFTER_HASH" ]; then
    echo "FAIL: car_visit.sh modified files inside PROBE_ROOT!" >&2
    exit 1
fi

TARBALL=$(find "$OUT_DIR" -maxdepth 1 -name 'carplay-visit-*.tar*' | head -n 1)
if [ -z "$TARBALL" ] || [ ! -s "$TARBALL" ]; then
    echo "FAIL: car_visit.sh did not produce a non-empty tarball" >&2
    exit 1
fi

UNPACK="$TMP_BASE/unpack"
mkdir -p "$UNPACK"
tar -xf "$TARBALL" -C "$UNPACK"
VISIT_DIR=$(find "$UNPACK" -mindepth 1 -maxdepth 1 -type d | head -n 1)
for f in MANIFEST.txt SUMMARY.txt bt_probe.txt usb_probe.txt wifi_wland.txt vmost_mdns.txt hmi_display_audio.txt system_mounts_init.txt i2c_mfi.txt compat.txt; do
    if [ ! -f "$VISIT_DIR/$f" ]; then
        echo "FAIL: tarball missing $f" >&2
        exit 1
    fi
done

# Check key summary & redaction invariants
grep -q 'adv7182' "$VISIT_DIR/i2c_mfi.txt"
grep -q '05ac' "$VISIT_DIR/usb_probe.txt"
grep -q '15032' "$VISIT_DIR/bt_probe.txt"
grep -q 'wpa_passphrase=<REDACTED>' "$VISIT_DIR/wifi_wland.txt"
if grep -q 'SUPERSECRET' "$VISIT_DIR/wifi_wland.txt"; then
    echo "FAIL: wpa_passphrase leaked into wifi_wland.txt!" >&2
    exit 1
fi
grep -q '1.1 ALPS' "$VISIT_DIR/SUMMARY.txt"
grep -q '4.4 HMI Plugin ABI' "$VISIT_DIR/SUMMARY.txt"
grep -q '5.1 I2C buses' "$VISIT_DIR/SUMMARY.txt"
grep -q '@ok|libasound|' "$VISIT_DIR/compat.txt"
echo "[PASS] car_visit.sh fake-root probe, tarball, redaction, and VEHICLE_FACTS summary"

# ---- 4. Test install.sh + uninstall.sh (--dry-run, safe defaults, byte-for-byte restore) ----
mkdir -p \
    "$STAGE_DIR/opt/carplay" \
    "$STAGE_DIR/opt/hmi/data/ro/Plugins/EntryCarPlay"
printf 'FAKE_CARPLAYD_ELF_V2' > "$STAGE_DIR/opt/carplay/carplayd"
chmod +x "$STAGE_DIR/opt/carplay/carplayd"
printf 'FAKE_PLUGIN_SO' > "$STAGE_DIR/opt/hmi/data/ro/Plugins/EntryCarPlay/libEntryCarPlay.so"
printf 'FAKE_MANIFEST' > "$STAGE_DIR/opt/hmi/data/ro/Plugins/EntryCarPlay/EntryCarPlay.manifest"
printf 'FAKE_XML' > "$STAGE_DIR/opt/hmi/data/ro/Plugins/EntryCarPlay/EntryCarPlay.xml"

# Pre-existing files in FAKE_ROOT to verify byte-for-byte backup & restore
mkdir -p "$FAKE_ROOT/var/local/data/CarPlay"
printf 'ORIGINAL_CONFIG_BYTES\n# keep me exact\nwireless=1\n' > "$FAKE_ROOT/var/local/data/CarPlay/carplay.conf"
chmod 0640 "$FAKE_ROOT/var/local/data/CarPlay/carplay.conf"
printf 'ORIGINAL_UNIT_BYTES\n' > "$FAKE_ROOT/etc/systemd/system/entry-carplay.service"
printf 'KEEP_ME_EXISTING_PLUGIN\n' > "$FAKE_ROOT/opt/hmi/data/ro/Plugins/ExistingBmwPlugin/plugin.xml"

ORIG_CONF_HASH=$(sha256sum "$FAKE_ROOT/var/local/data/CarPlay/carplay.conf" | awk '{print $1}')
ORIG_UNIT_HASH=$(sha256sum "$FAKE_ROOT/etc/systemd/system/entry-carplay.service" | awk '{print $1}')
ORIG_PLUG_HASH=$(sha256sum "$FAKE_ROOT/opt/hmi/data/ro/Plugins/ExistingBmwPlugin/plugin.xml" | awk '{print $1}')

# 4a. Dry-run must make ZERO changes
DRY_OUT=$(sh scripts/deploy/install.sh --root "$FAKE_ROOT" --stage "$STAGE_DIR" --with-systemd --dry-run)
printf '%s\n' "$DRY_OUT" | grep -q '^\[dry-run\]'
if [ -e "$FAKE_ROOT/opt/carplay/carplayd" ]; then
    echo "FAIL: install.sh --dry-run created carplayd!" >&2
    exit 1
fi
if [ "$(sha256sum "$FAKE_ROOT/var/local/data/CarPlay/carplay.conf" | awk '{print $1}')" != "$ORIG_CONF_HASH" ]; then
    echo "FAIL: install.sh --dry-run modified carplay.conf!" >&2
    exit 1
fi

# 4b. Install in default safe mode
sh scripts/deploy/install.sh --root "$FAKE_ROOT" --stage "$STAGE_DIR" --with-systemd >/dev/null
[ -x "$FAKE_ROOT/opt/carplay/carplayd" ]
[ -f "$FAKE_ROOT/opt/carplay/.installed-by-entrycarplay" ]
[ -f "$FAKE_ROOT/opt/hmi/data/ro/Plugins/EntryCarPlay/EntryCarPlay.manifest" ]
[ -f "$FAKE_ROOT/etc/systemd/system/entry-carplay.service" ]
grep -q '^wireless=0$' "$FAKE_ROOT/var/local/data/CarPlay/carplay.conf"
grep -q '^wired=0$' "$FAKE_ROOT/var/local/data/CarPlay/carplay.conf"
grep -q '^detach_usbfs_driver=0$' "$FAKE_ROOT/var/local/data/CarPlay/carplay.conf"

# 4c. Uninstall dry-run makes ZERO changes
sh scripts/deploy/uninstall.sh --root "$FAKE_ROOT" --dry-run | grep -q '^\[dry-run\]'
[ -x "$FAKE_ROOT/opt/carplay/carplayd" ]

# 4d. Uninstall restores every modified file byte-for-byte & removes newly added files/dirs
sh scripts/deploy/uninstall.sh --root "$FAKE_ROOT" >/dev/null
[ ! -e "$FAKE_ROOT/opt/carplay" ]
[ ! -e "$FAKE_ROOT/opt/hmi/data/ro/Plugins/EntryCarPlay" ]
[ ! -e "$FAKE_ROOT/var/local/data/CarPlay/.install-backup" ]
[ "$(sha256sum "$FAKE_ROOT/var/local/data/CarPlay/carplay.conf" | awk '{print $1}')" = "$ORIG_CONF_HASH" ]
[ "$(sha256sum "$FAKE_ROOT/etc/systemd/system/entry-carplay.service" | awk '{print $1}')" = "$ORIG_UNIT_HASH" ]
[ "$(sha256sum "$FAKE_ROOT/opt/hmi/data/ro/Plugins/ExistingBmwPlugin/plugin.xml" | awk '{print $1}')" = "$ORIG_PLUG_HASH" ]

echo "[PASS] install.sh & uninstall.sh (--dry-run, safe defaults, byte-for-byte restore)"
echo "check_probe_scripts: all checks passed"
