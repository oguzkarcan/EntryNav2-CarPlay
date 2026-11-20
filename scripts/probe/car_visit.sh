#!/bin/sh
# Comprehensive read-only vehicle visit probe for BMW HU_ENTRYNAV2 (BusyBox / POSIX sh).
#
# Collects everything needed in ONE car visit without modifying car state:
#   1. bt_probe.sh (ALPS Evolution SPP stack, D-Bus, BlueZ/BT kernel)
#   2. usb_probe.sh (usbfs, sysfs USB devices, UDC, MediaPlayer/CARPLAY ownership, tun)
#   3. Wi-Fi / wland / IPv6 sysctl inventory (wlan0/wlan1, hostapd, ap.conf redacted)
#   4. vMOST / mDNS inventory (vmostctl, libvmostclient, mdnsd, libdns_sd, dns-sd)
#   5. HMI / Display / Audio / Input inventory (LayerManagerControl, libAppFramework, ALSA)
#   6. Process / systemd / init / mount / kernel / module inventory
#   7. I2C / MFi hardware inventory (/dev/i2c-*, /sys/bus/i2c/devices/*/name, modalias)
#   8. carplayd --compat output (if carplayd binary is available)
#
# Writes ONLY inside one output directory (default /tmp/carplay-visit-<timestamp>),
# creates SUMMARY.txt mapping every "Unverified (needs car)" row in docs/VEHICLE_FACTS.md
# to the captured output file & line, generates MANIFEST.txt, and packs a timestamped
# tarball. Every external command runs under a bounded timeout.

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
R=${PROBE_ROOT:-}
OUT_DIR=${CARPLAY_VISIT_OUT:-}
DAEMON_BIN=${CARPLAYD_BIN:-}
CMD_TIMEOUT=${CARPLAY_VISIT_TIMEOUT:-5}
MAKE_TAR=1

usage() {
    cat <<'EOF'
Usage: car_visit.sh [options]
  --out-dir PATH       Writable output directory (default: /tmp/carplay-visit-YYYYMMDD-HHMMSS)
  --daemon PATH        Path to carplayd binary for --compat check
  --probe-root PATH    Fake root prefix for host CI testing (or PROBE_ROOT env)
  --timeout SEC        Per-command timeout in seconds (default: 5)
  --no-tar             Skip creating the .tar.gz / .tar archive
  -h, --help           Show help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --out-dir)
            OUT_DIR=$2; shift 2 ;;
        --daemon)
            DAEMON_BIN=$2; shift 2 ;;
        --probe-root)
            R=$2; export PROBE_ROOT="$R"; shift 2 ;;
        --timeout)
            CMD_TIMEOUT=$2; shift 2 ;;
        --no-tar)
            MAKE_TAR=0; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "car_visit.sh: unknown option: $1" >&2
            usage >&2
            exit 2 ;;
    esac
done

TS=$(date '+%Y%m%d-%H%M%S' 2>/dev/null || echo 'unknown-time')
if [ -z "$OUT_DIR" ]; then
    OUT_DIR="/tmp/carplay-visit-$TS"
fi

mkdir -p "$OUT_DIR"
WORK_DIR="$OUT_DIR/carplay-visit-$TS"
mkdir -p "$WORK_DIR"

# Detect timeout syntax once (GNU coreutils: `timeout 5 cmd`, BusyBox: `timeout -t 5 cmd`)
TIMEOUT_STYLE="none"
if command -v timeout >/dev/null 2>&1; then
    if timeout 1 true >/dev/null 2>&1; then
        TIMEOUT_STYLE="gnu"
    elif timeout -t 1 true >/dev/null 2>&1; then
        TIMEOUT_STYLE="busybox"
    fi
fi

run_to() {
    secs=$1
    shift
    case "$TIMEOUT_STYLE" in
        gnu)
            timeout "$secs" "$@" 2>&1 || printf '[rc=%s]\n' "$?" ;;
        busybox)
            timeout -t "$secs" "$@" 2>&1 || printf '[rc=%s]\n' "$?" ;;
        *)
            "$@" 2>&1 &
            cmd_pid=$!
            (
                i=0
                while [ "$i" -lt "$secs" ]; do
                    sleep 1 2>/dev/null || break
                    kill -0 "$cmd_pid" 2>/dev/null || exit 0
                    i=$((i + 1))
                done
                kill -TERM "$cmd_pid" 2>/dev/null || true
                sleep 1 2>/dev/null || true
                kill -KILL "$cmd_pid" 2>/dev/null || true
            ) &
            wd_pid=$!
            rc=0
            wait "$cmd_pid" 2>/dev/null || rc=$?
            kill "$wd_pid" 2>/dev/null || true
            wait "$wd_pid" 2>/dev/null || true
            if [ "$rc" -ne 0 ]; then
                printf '[rc=%s]\n' "$rc"
            fi ;;
    esac
}

section_hdr() {
    printf '\n=== %s ===\n' "$1"
}

find_match_line() {
    file=$1
    pat=$2
    if [ -r "$file" ]; then
        m=$(grep -nE "$pat" "$file" 2>/dev/null | head -n 1 || true)
        if [ -n "$m" ]; then
            printf '%s:%s' "${file##*/}" "$m"
            return 0
        fi
    fi
    printf '%s: (no matching line)' "${file##*/}"
}

# ---- 1. Bluetooth probe ----
BT_FILE="$WORK_DIR/bt_probe.txt"
if [ -r "$SCRIPT_DIR/bt_probe.sh" ]; then
    PROBE_ROOT="$R" run_to "$((CMD_TIMEOUT * 4))" sh "$SCRIPT_DIR/bt_probe.sh" > "$BT_FILE"
else
    printf 'bt_probe.sh not found at %s\n' "$SCRIPT_DIR/bt_probe.sh" > "$BT_FILE"
fi

# ---- 2. USB probe ----
USB_FILE="$WORK_DIR/usb_probe.txt"
if [ -r "$SCRIPT_DIR/usb_probe.sh" ]; then
    PROBE_ROOT="$R" run_to "$((CMD_TIMEOUT * 4))" sh "$SCRIPT_DIR/usb_probe.sh" > "$USB_FILE"
else
    printf 'usb_probe.sh not found at %s\n' "$SCRIPT_DIR/usb_probe.sh" > "$USB_FILE"
fi
if command -v lsusb >/dev/null 2>&1; then
    {
        section_hdr "lsusb -v (Apple 05ac if attached)"
        run_to "$CMD_TIMEOUT" lsusb
        run_to "$CMD_TIMEOUT" lsusb -d 05ac: -v
    } >> "$USB_FILE"
fi

# ---- 3. Wi-Fi & wland inventory ----
WIFI_FILE="$WORK_DIR/wifi_wland.txt"
{
    section_hdr "Wi-Fi kernel modules (/proc/modules)"
    if [ -r "$R/proc/modules" ]; then
        grep -iE 'wl18|wlcore|mac80211|cfg80211|wlan' "$R/proc/modules" 2>/dev/null || printf '(no matching wifi modules)\n'
    fi

    section_hdr "Network interfaces (iw dev / iw phy / ifconfig / ip)"
    if command -v iw >/dev/null 2>&1; then
        run_to "$CMD_TIMEOUT" iw dev
        run_to "$CMD_TIMEOUT" iw list
    else
        printf 'iw: not installed\n'
    fi
    if command -v ip >/dev/null 2>&1; then
        run_to "$CMD_TIMEOUT" ip addr show
        run_to "$CMD_TIMEOUT" ip -6 addr show
        run_to "$CMD_TIMEOUT" ip route show
    elif command -v ifconfig >/dev/null 2>&1; then
        run_to "$CMD_TIMEOUT" ifconfig -a
    fi

    section_hdr "IPv6 sysctl settings"
    for p in "$R/proc/sys/net/ipv6/conf/all/disable_ipv6" \
             "$R/proc/sys/net/ipv6/conf/default/disable_ipv6" \
             "$R/proc/sys/net/ipv6/conf/wlan0/disable_ipv6"; do
        if [ -r "$p" ]; then
            printf '%s = %s\n' "${p#"$R"}" "$(cat "$p" 2>/dev/null || true)"
        else
            printf '%s: absent\n' "${p#"$R"}"
        fi
    done

    section_hdr "wland / hostapd / udhcpd state & config (passphrase redacted)"
    ls -la "$R/tmp/wland" "$R/var/run/hostapd" "$R/usr/sbin/hostapd" \
        "$R/usr/sbin/hostapd_cli" "$R/usr/sbin/udhcpd" \
        "$R"/usr/local/lib/libwpa_client.so* 2>/dev/null || printf '(some wland/hostapd paths absent)\n'
    if [ -r "$R/tmp/wland/ap.conf" ]; then
        printf '[%s]\n' "/tmp/wland/ap.conf (redacted)"
        sed 's/^\(wpa_passphrase=\|passphrase=\|wpa_psk=\).*/\1<REDACTED>/' "$R/tmp/wland/ap.conf" 2>/dev/null || true
    fi
    if [ -S "$R/var/run/hostapd/wlan0" ] && command -v hostapd_cli >/dev/null 2>&1; then
        run_to "$CMD_TIMEOUT" hostapd_cli -p "$R/var/run/hostapd" -i wlan0 status
    fi

    section_hdr "Wi-Fi processes"
    (ps -ef 2>/dev/null || ps w 2>/dev/null || ps 2>/dev/null) | \
        grep -iE 'wland|hostapd|wpa_supplicant|udhcpd|dhcpd' | grep -v 'grep' || printf '(no matching wifi processes)\n'
} > "$WIFI_FILE"

# ---- 4. vMOST & mDNS inventory ----
VMOST_MDNS_FILE="$WORK_DIR/vmost_mdns.txt"
{
    section_hdr "vMOST daemon & library"
    ls -la "$R/var/run/vmost_sockstream" "$R/tmp/vmost_sockstream" "$R"/var/run/vmostd* \
        "$R"/usr/local/lib/libvmostclient.so* "$R/usr/local/bin/vmostctl" 2>/dev/null || printf '(some vMOST paths absent)\n'
    if command -v vmostctl >/dev/null 2>&1; then
        run_to "$CMD_TIMEOUT" vmostctl --list-fblock
        run_to "$CMD_TIMEOUT" vmostctl --apps
    elif [ -x "$R/usr/local/bin/vmostctl" ]; then
        run_to "$CMD_TIMEOUT" "$R/usr/local/bin/vmostctl" --list-fblock
        run_to "$CMD_TIMEOUT" "$R/usr/local/bin/vmostctl" --apps
    else
        printf 'vmostctl: not installed\n'
    fi

    section_hdr "mDNS / DNS-SD (mdnsd & libdns_sd)"
    ls -la "$R/usr/local/bin/mdnsd" "$R/usr/sbin/mdnsd" \
        "$R"/usr/local/lib/libdns_sd.so* "$R"/usr/lib/libdns_sd.so* 2>/dev/null || printf '(some mDNS paths absent)\n'
    (ps -ef 2>/dev/null || ps w 2>/dev/null || ps 2>/dev/null) | \
        grep -iE 'vmostd|mdnsd|avahi' | grep -v 'grep' || printf '(no matching vmostd/mdnsd processes)\n'
    for lib in "$R"/usr/local/lib/libdns_sd.so* "$R"/usr/lib/libdns_sd.so*; do
        [ -r "$lib" ] || continue
        printf 'lib=%s\n' "$lib"
        if command -v readelf >/dev/null 2>&1; then
            run_to "$CMD_TIMEOUT" readelf -Ws "$lib" | grep -E 'DNSService|TXTRecord' || true
        elif command -v nm >/dev/null 2>&1; then
            run_to "$CMD_TIMEOUT" nm -D "$lib" | grep -E 'DNSService|TXTRecord' || true
        fi
    done
    if command -v dns-sd >/dev/null 2>&1; then
        printf '[dns-sd -B _airplay._tcp local. (2s browse)]\n'
        run_to 2 dns-sd -B _airplay._tcp local.
    else
        printf 'dns-sd: not installed\n'
    fi
} > "$VMOST_MDNS_FILE"

# ---- 5. HMI, Display, Video, Audio, Input ----
HMI_FILE="$WORK_DIR/hmi_display_audio.txt"
{
    section_hdr "LayerManager / Wayland Display"
    ls -la "$R/run/system/0/wayland-0" "$R/etc/layermanager/compositor.conf" \
        "$R/dev/dri/card0" "$R/dev/cmem" "$R/dev/rpmsg-dce" 2>/dev/null || true
    if [ -r "$R/etc/layermanager/compositor.conf" ]; then
        grep -i 'genivi-flip-renderorder' "$R/etc/layermanager/compositor.conf" 2>/dev/null || true
    fi
    if command -v LayerManagerControl >/dev/null 2>&1; then
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/system/0}" run_to "$CMD_TIMEOUT" LayerManagerControl get screens
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/system/0}" run_to "$CMD_TIMEOUT" LayerManagerControl get screen 0
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/system/0}" run_to "$CMD_TIMEOUT" LayerManagerControl get layers
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/system/0}" run_to "$CMD_TIMEOUT" LayerManagerControl get surfaces
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/system/0}" run_to "$CMD_TIMEOUT" LayerManagerControl get scene
    else
        printf 'LayerManagerControl: not installed\n'
    fi

    section_hdr "HMI Plugins & libAppFramework.A.so ABI"
    ls -la "$R/opt/hmi/data/ro/Plugins" "$R/opt/hmi/lib/libAppFramework.A.so" \
        "$R/opt/hmi/lib/libCoreFramework.A.so" 2>/dev/null || printf '(HMI paths absent)\n'
    if [ -r "$R/opt/hmi/lib/libAppFramework.A.so" ]; then
        if command -v readelf >/dev/null 2>&1; then
            run_to "$CMD_TIMEOUT" readelf -Ws "$R/opt/hmi/lib/libAppFramework.A.so" | grep '_ZTVN3bmw9PluginAppE' || true
        elif command -v nm >/dev/null 2>&1; then
            run_to "$CMD_TIMEOUT" nm -D -S "$R/opt/hmi/lib/libAppFramework.A.so" | grep '_ZTVN3bmw9PluginAppE' || true
        fi
    fi

    section_hdr "Video / DRM / ALSA Libraries"
    ls -la "$R"/usr/lib/libxsvideo.so* "$R"/usr/lib/libdrm.so* "$R"/usr/lib/libdrm_omap.so* \
        "$R"/usr/lib/libasound.so* "$R"/lib/libasound.so* 2>/dev/null || true

    section_hdr "ALSA Cards, PCMs & /etc/asound.conf"
    for p in "$R/proc/asound/cards" "$R/proc/asound/pcm" "$R/etc/asound.conf"; do
        if [ -r "$p" ]; then
            printf '[%s]\n' "${p#"$R"}"
            cat "$p" 2>/dev/null || true
        fi
    done

    section_hdr "Touchscreen UDP 30567 & Open Ports"
    if command -v netstat >/dev/null 2>&1; then
        run_to "$CMD_TIMEOUT" netstat -tuln
    elif command -v ss >/dev/null 2>&1; then
        run_to "$CMD_TIMEOUT" ss -tuln
    fi
} > "$HMI_FILE"

# ---- 6. System, Process, systemd/init, Mounts, Kernel, Modules ----
SYS_FILE="$WORK_DIR/system_mounts_init.txt"
{
    section_hdr "Kernel & Firmware Version"
    run_to "$CMD_TIMEOUT" uname -a
    for p in "$R/etc/version" "$R/proc/cmdline" "$R/proc/uptime"; do
        if [ -r "$p" ]; then
            printf '%s: ' "${p#"$R"}"
            cat "$p" 2>/dev/null || true
        fi
    done

    section_hdr "Mounts & Free Space"
    if [ -r "$R/proc/mounts" ]; then
        cat "$R/proc/mounts" 2>/dev/null || true
    elif command -v mount >/dev/null 2>&1; then
        run_to "$CMD_TIMEOUT" mount
    fi
    if command -v df >/dev/null 2>&1; then
        run_to "$CMD_TIMEOUT" df -k
    fi
    for d in "$R/var/local/data" "$R/tmp" "$R/opt"; do
        ls -ld "$d" 2>/dev/null || true
    done

    section_hdr "All Loaded Kernel Modules (/proc/modules)"
    if [ -r "$R/proc/modules" ]; then
        cat "$R/proc/modules" 2>/dev/null || true
    elif command -v lsmod >/dev/null 2>&1; then
        run_to "$CMD_TIMEOUT" lsmod
    fi

    section_hdr "Init / systemd / Service Inventory"
    if command -v systemctl >/dev/null 2>&1; then
        run_to "$CMD_TIMEOUT" systemctl list-units --all --no-pager
    else
        printf 'systemctl: not installed\n'
    fi
    for d in "$R/etc/systemd/system" "$R/lib/systemd/system" "$R/etc/init.d"; do
        if [ -d "$d" ]; then
            printf '[%s]\n' "${d#"$R"}"
            ls -la "$d" 2>/dev/null || true
        fi
    done
    if [ -r "$R/etc/inittab" ]; then
        printf '[%s]\n' "/etc/inittab"
        cat "$R/etc/inittab" 2>/dev/null || true
    fi

    section_hdr "Running Processes"
    if ps -ef >/dev/null 2>&1; then
        run_to "$CMD_TIMEOUT" ps -ef
    else
        run_to "$CMD_TIMEOUT" ps
    fi

    section_hdr "Recent dmesg (tail 100)"
    if command -v dmesg >/dev/null 2>&1; then
        run_to "$CMD_TIMEOUT" dmesg | tail -n 100 || true
    fi
} > "$SYS_FILE"

# ---- 7. I2C / MFi hardware inventory ----
I2C_FILE="$WORK_DIR/i2c_mfi.txt"
{
    section_hdr "I2C device nodes (/dev/i2c-*)"
    ls -la "$R"/dev/i2c-* "$R"/dev/iap* "$R"/dev/mfi* 2>/dev/null || printf '(no matching /dev/i2c-*, /dev/iap*, or /dev/mfi* nodes)\n'

    section_hdr "I2C sysfs devices (/sys/bus/i2c/devices/*)"
    if [ -d "$R/sys/bus/i2c/devices" ]; then
        for dev in "$R/sys/bus/i2c/devices"/*; do
            [ -e "$dev" ] || [ -L "$dev" ] || continue
            dname=${dev##*/}
            n=""
            m=""
            [ -r "$dev/name" ] && n=$(tr -d '\r\n' < "$dev/name" 2>/dev/null || true)
            [ -r "$dev/modalias" ] && m=$(tr -d '\r\n' < "$dev/modalias" 2>/dev/null || true)
            printf 'I2C %s name=%s modalias=%s\n' "$dname" "${n:-<none>}" "${m:-<none>}"
            if [ -r "$dev/uevent" ]; then
                sed 's/^/  /' "$dev/uevent" 2>/dev/null || true
            fi
        done
    else
        printf '/sys/bus/i2c/devices not present\n'
    fi

    section_hdr "I2C kernel modules"
    if [ -r "$R/proc/modules" ]; then
        grep -iE 'i2c|mfi|iap|apple' "$R/proc/modules" 2>/dev/null || printf '(no matching i2c/mfi modules)\n'
    fi
} > "$I2C_FILE"

# ---- 8. Daemon --compat self-check ----
COMPAT_FILE="$WORK_DIR/compat.txt"
if [ -z "$DAEMON_BIN" ]; then
    for cand in "$R/opt/carplay/carplayd" /opt/carplay/carplayd "$SCRIPT_DIR/../../build/host/carplayd" /tmp/carplayd ./carplayd; do
        if [ -x "$cand" ]; then
            DAEMON_BIN=$cand
            break
        fi
    done
fi
{
    if [ -n "$DAEMON_BIN" ] && [ -x "$DAEMON_BIN" ]; then
        printf '# binary: %s\n' "$DAEMON_BIN"
        rc=0
        if [ -n "$R" ]; then
            LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-/usr/local/lib:/opt/hmi/lib:/usr/lib:/lib}" \
            XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/system/0}" \
            WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-wayland-0}" \
                run_to "$((CMD_TIMEOUT * 2))" "$DAEMON_BIN" --compat --data-dir "$OUT_DIR/.compat_probe_tmp" --state-file "$OUT_DIR/.compat_probe_state" --no-ilm-size || rc=$?
        else
            LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-/usr/local/lib:/opt/hmi/lib:/usr/lib:/lib}" \
            XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/system/0}" \
            WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-wayland-0}" \
                run_to "$((CMD_TIMEOUT * 2))" "$DAEMON_BIN" --compat || rc=$?
        fi
        printf 'compat_exit_code=%s\n' "$rc"
    else
        printf '@info|daemon|carplayd binary not found (pass --daemon PATH or copy carplayd to /tmp/carplayd)\n'
        printf 'compat_exit_code=not_run\n'
    fi
} > "$COMPAT_FILE"
rm -rf "$OUT_DIR/.compat_probe_tmp" "$OUT_DIR/.compat_probe_state" 2>/dev/null || true

# ---- 9. Human-readable SUMMARY.txt mapped to docs/VEHICLE_FACTS.md ----
SUMMARY_FILE="$WORK_DIR/SUMMARY.txt"
{
    printf 'EntryNav2-CarPlay Vehicle Visit Summary (%s)\n' "$TS"
    printf '================================================================\n'
    printf 'Maps every "Unverified (needs car)" row in docs/VEHICLE_FACTS.md\n'
    printf 'plus I2C/MFi hardware inventory to the captured probe output.\n\n'

    printf '[System]\n'
    printf '  Kernel  : %s\n' "$(find_match_line "$SYS_FILE" 'Linux|uname')"
    printf '  Version : %s\n' "$(find_match_line "$SYS_FILE" 'etc/version')"
    printf '  Free /  : %s\n\n' "$(find_match_line "$SYS_FILE" ' /($| )')"

    printf '[docs/VEHICLE_FACTS.md Ledger Mapping]\n'
    printf '  1.1 ALPS .dynsym sizes (15032 vs 15024) -> %s\n' "$(find_match_line "$BT_FILE" 'app|spp_info|spp_connected|ALPS paths')"
    printf '  1.2 ALPS SPP slots (0/1/5) & maps       -> %s\n' "$(find_match_line "$BT_FILE" 'libevo_btappl\.so|evo_config|pid=')"
    printf '  1.3 iAP2 SPP UUID pair (...caff/cafe)   -> %s\n' "$(find_match_line "$BT_FILE" 'caff|cafe|uuid|UUID')"
    printf '  1.4 BlueZ / AF_BLUETOOTH fallback       -> %s\n' "$(find_match_line "$BT_FILE" 'bluetooth|rfcomm|hciconfig')"
    printf '  1.5 ALPS D-Bus (org.alps.evolution)     -> %s\n' "$(find_match_line "$BT_FILE" 'org\.alps\.evolution|dbus-send')"
    printf '  2.1 wland AP paths (/tmp/wland, wlan0)  -> %s\n' "$(find_match_line "$WIFI_FILE" 'wlan0|ap\.conf|hostapd')"
    printf '  2.2 vMOST hotspot control (0xA0.01)     -> %s\n' "$(find_match_line "$VMOST_MDNS_FILE" 'vmost|0xA0|FBlock|libvmostclient')"
    printf '  2.3 Wi-Fi AP security/channel/band      -> %s\n' "$(find_match_line "$WIFI_FILE" 'channel|ssid|hw_mode|wland')"
    printf '  2.4 mDNS (mdnsd & libdns_sd.so.0)       -> %s\n' "$(find_match_line "$VMOST_MDNS_FILE" 'libdns_sd|mdnsd|DNSService')"
    printf '  2.5 WL18xx / wlcore driver & PHY        -> %s\n' "$(find_match_line "$WIFI_FILE" 'wl18|wlcore|phy|iw dev')"
    printf '  3.1 Apple USB VID 0x05AC attach         -> %s\n' "$(find_match_line "$USB_FILE" '05ac|DEV ')"
    printf '  3.2 USBMUX / CDC-NCM / Apple Eth IFs    -> %s\n' "$(find_match_line "$USB_FILE" 'IF |ff/f|02/0d')"
    printf '  3.3 usbfs owners (MediaPlayer/CARPLAY)  -> %s\n' "$(find_match_line "$USB_FILE" '/dev/bus/usb|CARPLAY|MediaPlayer')"
    printf '  3.4 USB port layout & /var/local/data   -> %s\n' "$(find_match_line "$SYS_FILE" 'var/local')"
    printf '  3.5 /dev/net/tun & IPv6 disable_ipv6    -> %s | %s\n' "$(find_match_line "$USB_FILE" '/dev/net/tun')" "$(find_match_line "$WIFI_FILE" 'disable_ipv6')"
    printf '  4.1 Screen resolution & LayerManager    -> %s\n' "$(find_match_line "$HMI_FILE" 'screen|x=|LayerManager')"
    printf '  4.2 Touchscreen UDP 30567 & HmiMain3D   -> %s\n' "$(find_match_line "$HMI_FILE" '30567|netstat|ss|HmiMain3D')"
    printf '  4.3 vMOST controller (E5.01/E5.03)      -> %s\n' "$(find_match_line "$VMOST_MDNS_FILE" 'vmostctl|E5|libvmostclient')"
    printf '  4.4 HMI Plugin ABI (vtable 172 B)       -> %s\n' "$(find_match_line "$HMI_FILE" '_ZTVN3bmw9PluginAppE|libAppFramework')"
    printf '  4.5 Video/Audio HW (xsvideo/drm/alsa)   -> %s\n' "$(find_match_line "$HMI_FILE" 'carplay_alt|mic1|libxsvideo|cards')"
    printf '  5.1 I2C buses & devices (MFi research)  -> %s\n\n' "$(find_match_line "$I2C_FILE" 'I2C |/dev/i2c')"

    printf '[Daemon --compat Summary]\n'
    cat "$COMPAT_FILE" 2>/dev/null || true
} > "$SUMMARY_FILE"

# ---- 10. MANIFEST.txt & Timestamped Tarball ----
MANIFEST_FILE="$WORK_DIR/MANIFEST.txt"
{
    printf 'EntryNav2-CarPlay Car Visit Manifest (%s)\n' "$TS"
    for f in "$WORK_DIR"/*; do
        [ -f "$f" ] || continue
        bname=${f##*/}
        [ "$bname" = "MANIFEST.txt" ] && continue
        sz=$(wc -c < "$f" 2>/dev/null | tr -d ' ')
        sum="-"
        if command -v sha256sum >/dev/null 2>&1; then
            sum=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
        elif command -v md5sum >/dev/null 2>&1; then
            sum=$(md5sum "$f" 2>/dev/null | awk '{print $1}')
        fi
        printf '%-28s  size=%-8s  hash=%s\n' "$bname" "$sz" "$sum"
    done
} > "$MANIFEST_FILE"

TAR_PATH=""
if [ "$MAKE_TAR" -eq 1 ]; then
    if command -v gzip >/dev/null 2>&1; then
        TAR_PATH="$OUT_DIR/carplay-visit-$TS.tar.gz"
        (cd "$OUT_DIR" && tar -cf - "carplay-visit-$TS" | gzip -c > "$TAR_PATH")
    else
        TAR_PATH="$OUT_DIR/carplay-visit-$TS.tar"
        (cd "$OUT_DIR" && tar -cf "$TAR_PATH" "carplay-visit-$TS")
    fi
fi

printf 'car_visit.sh complete.\n'
printf '  Summary : %s\n' "$SUMMARY_FILE"
printf '  Manifest: %s\n' "$MANIFEST_FILE"
if [ -n "$TAR_PATH" ]; then
    printf '  Tarball : %s\n' "$TAR_PATH"
fi
