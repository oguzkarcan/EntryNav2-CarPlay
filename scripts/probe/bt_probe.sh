#!/bin/sh
# Read-only Bluetooth capability & stack probe for BMW HU_ENTRYNAV2 (BusyBox / POSIX sh).
# Collects kernel, sysfs, daemon, socket, library, and D-Bus facts without modifying state.
# Usage: sh bt_probe.sh > bt_probe_report.txt

set -u

section() {
    printf '\n=== %s ===\n' "$1"
}

section "System"
uname -a 2>/dev/null || true
if [ -r /etc/version ]; then
    printf 'etc_version: '
    cat /etc/version 2>/dev/null || true
fi
date 2>/dev/null || true

section "Kernel config (BT/BLUETOOTH/RFCOMM/L2CAP)"
if [ -r /proc/config.gz ] && command -v zcat >/dev/null 2>&1; then
    zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_(BT|BLUETOOTH|RFCOMM|L2CAP)' || true
elif [ -r "/boot/config-$(uname -r 2>/dev/null)" ]; then
    grep -E 'CONFIG_(BT|BLUETOOTH|RFCOMM|L2CAP)' "/boot/config-$(uname -r)" 2>/dev/null || true
else
    printf 'no readable kernel config (/proc/config.gz or /boot/config-*)\n'
fi

section "Loaded kernel modules (/proc/modules)"
if [ -r /proc/modules ]; then
    grep -iE 'blue|bt|rfcomm|l2cap|hci|sco|bnep|hidp|uart|tty' /proc/modules 2>/dev/null || printf '(no matching loaded modules)\n'
elif command -v lsmod >/dev/null 2>&1; then
    lsmod 2>/dev/null | grep -iE 'blue|bt|rfcomm|l2cap|hci|sco' || printf '(no matching loaded modules)\n'
else
    printf 'no /proc/modules or lsmod\n'
fi

section "Available kernel modules (/lib/modules)"
KVER=$(uname -r 2>/dev/null || printf '')
if [ -n "$KVER" ] && [ -d "/lib/modules/$KVER" ]; then
    find "/lib/modules/$KVER" -type f \( -name '*blue*' -o -name '*rfcomm*' -o -name '*bt*' -o -name '*hci*' \) 2>/dev/null | sort || true
else
    printf '/lib/modules/%s not present\n' "$KVER"
fi

section "/sys/class/bluetooth & /dev nodes"
if [ -d /sys/class/bluetooth ]; then
    ls -la /sys/class/bluetooth 2>/dev/null || true
    for dev in /sys/class/bluetooth/*; do
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
ls -la /dev/rfcomm* /dev/hci* /dev/bluetooth* 2>/dev/null || printf '(no /dev/rfcomm* or /dev/hci* nodes)\n'

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
for dir in /var/run /run /tmp; do
    if [ -d "$dir" ]; then
        printf '[%s]\n' "$dir"
        find "$dir" -type s 2>/dev/null | sort || true
    fi
done

section "Libraries matching *blue* or *bt* in /lib /usr/lib /usr/local/lib /opt"
for dir in /lib /usr/lib /usr/local/lib /opt; do
    if [ -d "$dir" ]; then
        find "$dir" \( -name '*blue*' -o -name '*bt*' \) 2>/dev/null | sort || true
    fi
done

section "D-Bus services & system bus names"
for dir in /etc/dbus-1/system.d /usr/share/dbus-1/system-services; do
    if [ -d "$dir" ]; then
        printf '[%s]\n' "$dir"
        ls -la "$dir" 2>/dev/null || true
        grep -rilE 'blue|bt|alps|sdp|spp|iap|carplay' "$dir" 2>/dev/null || true
    fi
done
if command -v dbus-send >/dev/null 2>&1; then
    dbus-send --system --print-reply --dest=org.freedesktop.DBus \
        /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>/dev/null || printf 'dbus-send ListNames failed\n'
else
    printf 'dbus-send: not installed\n'
fi

section "Native CarPlay / iAP binaries (stat only)"
ls -la /opt/app/usr/MediaPlayer/bin/CARPLAY /usr/local/lib/libpiapom.so* 2>/dev/null || printf '(not found at known paths)\n'
