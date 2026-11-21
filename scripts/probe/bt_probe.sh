#!/bin/sh
# Read-only Bluetooth capability & stack probe for BMW HU_ENTRYNAV2 (BusyBox / POSIX sh).
# Collects kernel, sysfs, daemon, socket, library, and D-Bus facts without modifying state.
# Usage: sh bt_probe.sh > bt_probe_report.txt
# Optional: PROBE_ROOT=/path/to/fake_root (defaults to empty = live root /).

set -u

R=${PROBE_ROOT:-}

section() {
    printf '\n=== %s ===\n' "$1"
}

section "System"
uname -a 2>/dev/null || true
if [ -r "$R/etc/version" ]; then
    printf 'etc_version: '
    cat "$R/etc/version" 2>/dev/null || true
fi
date 2>/dev/null || true

section "Kernel config (BT/BLUETOOTH/RFCOMM/L2CAP)"
if [ -r "$R/proc/config.gz" ] && command -v zcat >/dev/null 2>&1; then
    zcat "$R/proc/config.gz" 2>/dev/null | grep -E 'CONFIG_(BT|BLUETOOTH|RFCOMM|L2CAP)' || true
elif [ -r "$R/boot/config-$(uname -r 2>/dev/null)" ]; then
    grep -E 'CONFIG_(BT|BLUETOOTH|RFCOMM|L2CAP)' "$R/boot/config-$(uname -r)" 2>/dev/null || true
else
    printf 'no readable kernel config (/proc/config.gz or /boot/config-*)\n'
fi

section "Loaded kernel modules (/proc/modules)"
if [ -r "$R/proc/modules" ]; then
    grep -iE 'blue|bt|rfcomm|l2cap|hci|sco|bnep|hidp|uart|tty' "$R/proc/modules" 2>/dev/null || printf '(no matching loaded modules)\n'
elif command -v lsmod >/dev/null 2>&1; then
    lsmod 2>/dev/null | grep -iE 'blue|bt|rfcomm|l2cap|hci|sco' || printf '(no matching loaded modules)\n'
else
    printf 'no /proc/modules or lsmod\n'
fi

section "Available kernel modules (/lib/modules)"
KVER=$(uname -r 2>/dev/null || printf '')
if [ -n "$KVER" ] && [ -d "$R/lib/modules/$KVER" ]; then
    find "$R/lib/modules/$KVER" -type f \( -name '*blue*' -o -name '*rfcomm*' -o -name '*bt*' -o -name '*hci*' \) 2>/dev/null | sort || true
else
    printf '/lib/modules/%s not present\n' "$KVER"
fi

section "/sys/class/bluetooth & /dev nodes"
if [ -d "$R/sys/class/bluetooth" ]; then
    ls -la "$R/sys/class/bluetooth" 2>/dev/null || true
    for dev in "$R/sys/class/bluetooth"/*; do
        [ -e "$dev" ] || continue
        printf '%s:\n' "$dev"
        for attr in address name type bus dev_id; do
            if [ -r "$dev/$attr" ]; then
                printf '  %s=' "$attr"
                cat "$dev/$attr" 2>/dev/null || true
            fi
        done
    done
else
    printf '/sys/class/bluetooth not present\n'
fi
ls -la "$R"/dev/rfcomm* "$R"/dev/hci* "$R"/dev/bluetooth* 2>/dev/null || printf '(no /dev/rfcomm* or /dev/hci* nodes)\n'

section "hciconfig / hcitool (read-only)"
if command -v hciconfig >/dev/null 2>&1; then
    hciconfig -a 2>/dev/null || hciconfig 2>/dev/null || true
else
    printf 'hciconfig: not installed\n'
fi
if command -v hcitool >/dev/null 2>&1; then
    hcitool dev 2>/dev/null || true
else
    printf 'hcitool: not installed\n'
fi

section "Running processes (bt/bluetooth/sdp/alps/carplay/iap)"
(ps -ef 2>/dev/null || ps w 2>/dev/null || ps 2>/dev/null) | \
    grep -iE 'bt|bluetooth|sdp|alps|btd|carplay|iap' | grep -v 'grep' || printf '(no matching processes)\n'

section "Sockets in /var/run, /run, /tmp"
for dir in "$R/var/run" "$R/run" "$R/tmp"; do
    if [ -d "$dir" ]; then
        printf '[%s]\n' "$dir"
        find "$dir" -type s 2>/dev/null | sort || true
    fi
done

section "Libraries matching *blue*, *bt*, *alps*, or libdbus in /lib /usr/lib /usr/local/lib /opt"
for dir in "$R/lib" "$R/usr/lib" "$R/usr/local/lib" "$R/opt"; do
    if [ -d "$dir" ]; then
        find "$dir" -path "$R/opt/hmi/data" -prune -o \
            \( -name '*blue*' -o -name '*bt*' -o -name '*alps*' -o -name 'libdbus-1*' \) -print 2>/dev/null | sort || true
    fi
done

section "ALPS Evolution library, config & /proc/*/maps (read-only)"
ls -la "$R/usr/local/lib/alps" "$R/usr/local/lib/alps/evolution" \
    "$R/opt/app/usr/BTMedia/evolution/stack/lib/libevo_btappl.so" \
    "$R/opt/app/usr/BTMedia/evolution/stack/etc/evo_config.xml" 2>/dev/null || printf '(ALPS paths not found)\n'
if [ -r "$R/opt/app/usr/BTMedia/evolution/stack/lib/libevo_btappl.so" ]; then
    printf 'libevo_btappl.so .dynsym sizes (expected 15032/480/36; F20 2017 variant 15024/480/36):\n'
    if command -v readelf >/dev/null 2>&1; then
        readelf -Ws "$R/opt/app/usr/BTMedia/evolution/stack/lib/libevo_btappl.so" 2>/dev/null | \
            grep -E ' (app|spp_info|spp_connected)$' || true
    elif command -v nm >/dev/null 2>&1; then
        nm -D -S "$R/opt/app/usr/BTMedia/evolution/stack/lib/libevo_btappl.so" 2>/dev/null | \
            grep -E ' (app|spp_info|spp_connected)$' || true
    else
        printf '  (readelf/nm not installed; inspect ELF on host)\n'
    fi
fi
if [ -r "$R/opt/app/usr/BTMedia/evolution/stack/etc/evo_config.xml" ]; then
    grep -iE 'caff|cafe|supported_services|carplay|iap|6203' "$R/opt/app/usr/BTMedia/evolution/stack/etc/evo_config.xml" 2>/dev/null | head -n 60 || true
fi
for map in "$R"/proc/[0-9]*/maps; do
    [ -r "$map" ] || continue
    if grep -q 'libevo_btappl\.so' "$map" 2>/dev/null; then
        pid=${map#"$R/proc/"}
        pid=${pid%/maps}
        comm=$(cat "$R/proc/$pid/comm" 2>/dev/null || printf '?')
        printf 'pid=%s comm=%s:\n' "$pid" "$comm"
        grep 'libevo_btappl\.so' "$map" 2>/dev/null | head -n 5 || true
    fi
done

section "D-Bus services & system bus names"
for dir in "$R/etc/dbus-1/system.d" "$R/usr/share/dbus-1/system-services"; do
    if [ -d "$dir" ]; then
        printf '[%s]\n' "$dir"
        ls -la "$dir" 2>/dev/null || true
        grep -rilE 'blue|bt|alps|sdp|spp|iap|carplay' "$dir" 2>/dev/null || true
    fi
done
if command -v dbus-send >/dev/null 2>&1; then
    dbus-send --system --print-reply --dest=org.freedesktop.DBus \
        /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>/dev/null || printf 'dbus-send ListNames failed\n'
    dbus-send --system --print-reply --dest=org.alps.evolution \
        /org/alps/evolution/hli org.freedesktop.DBus.Introspectable.Introspect 2>/dev/null | head -n 80 || \
        printf 'org.alps.evolution Introspect unavailable\n'
else
    printf 'dbus-send: not installed\n'
fi

section "Native CarPlay / iAP binaries & Wi-Fi AP paths (stat only)"
ls -la "$R/opt/app/usr/MediaPlayer/bin/CARPLAY" "$R"/usr/local/lib/libpiapom.so* \
    "$R"/usr/local/lib/libNmeCarPlay.so* "$R"/usr/lib/libdns_sd.so.0* \
    "$R/tmp/wland" "$R/var/run/hostapd" "$R"/var/run/vmostd* 2>/dev/null || printf '(not found at known paths)\n'
if command -v iw >/dev/null 2>&1; then
    iw dev 2>/dev/null || true
    for iface in wl0 wlan0; do
        if [ -e "$R/sys/class/net/$iface" ]; then
            printf '[iw %s station dump]\n' "$iface"
            iw dev "$iface" station dump 2>/dev/null || true
        fi
    done
fi
