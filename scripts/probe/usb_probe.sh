#!/bin/sh
# Read-only USB / UDC / configfs / usbfs / tun probe for BMW HU_ENTRYNAV2 (BusyBox POSIX sh).
# NEVER writes to /sys, /proc, /dev, or disk.
# Optional: PROBE_ROOT=/path/to/fake_root (defaults to empty = live root /).

set -u

R=${PROBE_ROOT:-}

section() {
    echo
    echo "=================================================================="
    echo "== $1"
    echo "=================================================================="
}

read_attr() {
    if [ -r "$1" ]; then
        tr -d '\r\n' < "$1" 2>/dev/null || true
    fi
}

section "System / Kernel"
uname -a 2>/dev/null || true
if [ -r "$R/etc/version" ]; then
    printf "etc_version: "
    read_attr "$R/etc/version"
    echo
fi
if [ -r "$R/proc/uptime" ]; then
    printf "uptime: "
    cat "$R/proc/uptime" 2>/dev/null || true
fi

section "USB Modules & Net USB Drivers"
if command -v lsmod >/dev/null 2>&1; then
    lsmod 2>/dev/null || true
elif [ -r "$R/proc/modules" ]; then
    cat "$R/proc/modules" 2>/dev/null || true
fi
KREL=$(uname -r 2>/dev/null || echo unknown)
if [ -d "$R/lib/modules/$KREL/kernel/drivers/net/usb" ]; then
    echo "--- /lib/modules/$KREL/kernel/drivers/net/usb ---"
    ls -la "$R/lib/modules/$KREL/kernel/drivers/net/usb" 2>/dev/null || true
fi
if [ -r "$R/lib/modules/$KREL/modules.builtin" ]; then
    echo "--- modules.builtin (usb/ncm/tun/ffs) ---"
    grep -E 'ncm|cdc|tun|ffs|dwc3|xhci|ehci|musb|gadget|ipheth' "$R/lib/modules/$KREL/modules.builtin" 2>/dev/null || true
fi

section "/dev/net/tun & Network Interfaces"
ls -la "$R/dev/net/tun" 2>/dev/null || echo "/dev/net/tun: not present"
if [ -r "$R/proc/net/dev" ]; then
    cat "$R/proc/net/dev" 2>/dev/null || true
fi
if [ -r "$R/proc/net/if_inet6" ]; then
    echo "--- /proc/net/if_inet6 ---"
    cat "$R/proc/net/if_inet6" 2>/dev/null || true
fi

section "/dev/bus/usb (usbfs)"
if [ -d "$R/dev/bus/usb" ]; then
    ls -laR "$R/dev/bus/usb" 2>/dev/null || true
else
    echo "/dev/bus/usb: not present"
fi
if [ -r "$R/proc/mounts" ]; then
    echo "--- usb/configfs/ffs mounts ---"
    grep -E 'usbfs|usbdev|configfs|functionfs|debugfs' "$R/proc/mounts" 2>/dev/null || true
fi

section "/sys/bus/usb/devices Tree"
if [ -d "$R/sys/bus/usb/devices" ]; then
    for d in "$R/sys/bus/usb/devices"/*; do
        [ -e "$d" ] || continue
        name=${d##*/}
        if [ -r "$d/idVendor" ]; then
            vid=$(read_attr "$d/idVendor")
            pid=$(read_attr "$d/idProduct")
            bus=$(read_attr "$d/busnum")
            dev=$(read_attr "$d/devnum")
            cfg=$(read_attr "$d/bConfigurationValue")
            ncfg=$(read_attr "$d/bNumConfigurations")
            cls=$(read_attr "$d/bDeviceClass")
            sub=$(read_attr "$d/bDeviceSubClass")
            proto=$(read_attr "$d/bDeviceProtocol")
            spd=$(read_attr "$d/speed")
            rem=$(read_attr "$d/removable")
            mfg=$(read_attr "$d/manufacturer")
            prod=$(read_attr "$d/product")
            ser=$(read_attr "$d/serial")
            drv=""
            if [ -L "$d/driver" ]; then
                drv=$(ls -ld "$d/driver" 2>/dev/null | sed 's/.*-> //' || true)
            fi
            echo "DEV $name vid=$vid pid=$pid bus=$bus dev=$dev cfg=$cfg/$ncfg class=$cls/$sub/$proto speed=${spd}M rem=${rem:-unknown} drv=${drv:-none} mfg='$mfg' prod='$prod' ser='$ser'"
        elif [ -r "$d/bInterfaceNumber" ]; then
            ifno=$(read_attr "$d/bInterfaceNumber")
            alt=$(read_attr "$d/bAlternateSetting")
            cls=$(read_attr "$d/bInterfaceClass")
            sub=$(read_attr "$d/bInterfaceSubClass")
            proto=$(read_attr "$d/bInterfaceProtocol")
            ep=$(read_attr "$d/bNumEndpoints")
            istr=$(read_attr "$d/interface")
            drv=""
            if [ -L "$d/driver" ]; then
                drv=$(ls -ld "$d/driver" 2>/dev/null | sed 's/.*-> //' || true)
            fi
            echo "  IF $name if=$ifno alt=$alt eps=$ep class=$cls/$sub/$proto drv=${drv:-none} name='$istr'"
        fi
    done
else
    echo "/sys/bus/usb/devices: not present"
fi

section "/sys/class/udc & State"
if [ -d "$R/sys/class/udc" ]; then
    for u in "$R/sys/class/udc"/*; do
        [ -e "$u" ] || continue
        uname_u=${u##*/}
        echo "UDC: $uname_u"
        for attr in state current_speed maximum_speed is_otg is_a_peripheral is_selfpowered b_hnp_enable a_hnp_support a_alt_hnp_support function; do
            if [ -r "$u/$attr" ]; then
                echo "  $attr = $(read_attr "$u/$attr")"
            fi
        done
        if [ -r "$u/uevent" ]; then
            echo "  uevent:"
            sed 's/^/    /' "$u/uevent" 2>/dev/null || true
        fi
        if [ -L "$u/device" ]; then
            ls -ld "$u/device" 2>/dev/null || true
        fi
    done
else
    echo "/sys/class/udc: not present"
fi

section "ConfigFS USB Gadget Layout (/sys/kernel/config/usb_gadget)"
if [ -d "$R/sys/kernel/config/usb_gadget" ]; then
    find "$R/sys/kernel/config/usb_gadget" -maxdepth 4 2>/dev/null | while IFS= read -r p; do
        if [ -L "$p" ]; then
            ls -ld "$p" 2>/dev/null || true
        elif [ -f "$p" ] && [ -r "$p" ]; then
            val=$(head -c 128 "$p" 2>/dev/null | tr -d '\0\r\n' || true)
            echo "FILE $p = $val"
        else
            echo "DIR  $p"
        fi
    done
else
    echo "/sys/kernel/config/usb_gadget: not present"
fi

section "Process Owning /dev/bus/usb/* (read-only proc scan)"
usb_fd_found=0
for pdir in "$R"/proc/[0-9]*; do
    [ -d "$pdir/fd" ] || continue
    hits=$(ls -l "$pdir/fd" 2>/dev/null | grep '/dev/bus/usb/' || true)
    [ -n "$hits" ] || continue
    usb_fd_found=1
    pid=${pdir##*/}
    comm=""
    cmdline=""
    uid=""
    exe=""
    if [ -r "$pdir/comm" ]; then
        comm=$(read_attr "$pdir/comm")
    fi
    if [ -r "$pdir/cmdline" ]; then
        cmdline=$(tr '\0' ' ' < "$pdir/cmdline" 2>/dev/null || true)
    fi
    if [ -r "$pdir/status" ]; then
        uid=$(grep '^Uid:' "$pdir/status" 2>/dev/null | head -n 1 || true)
    fi
    if [ -L "$pdir/exe" ]; then
        exe=$(ls -ld "$pdir/exe" 2>/dev/null || true)
    fi
    echo "$hits"
    echo "  pid=$pid comm=${comm:-unknown} $uid cmdline=$cmdline"
    if [ -n "$exe" ]; then
        echo "  $exe"
    fi
done
if [ "$usb_fd_found" -eq 0 ]; then
    echo "no readable /proc/*/fd/* symlinks pointing to /dev/bus/usb/*"
fi

section "MediaPlayer / CARPLAY Process & Binary Status (read-only)"
for p in "$R/opt/app/usr/MediaPlayer/bin/CARPLAY" "$R/opt/app/usr/MediaPlayer/bin/MediaPlayer" "$R/usr/local/lib/libauxin-apple.so.0" "$R/lib/libusb-1.0.so.0"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
        ls -ld "$p" 2>/dev/null || true
    else
        echo "$p: not present"
    fi
done
echo "--- matching processes (/proc scan) ---"
mp_found=0
for pdir in "$R"/proc/[0-9]*; do
    [ -d "$pdir" ] || continue
    pid=${pdir##*/}
    [ "$pid" = "$$" ] && continue
    comm=""
    cmdline=""
    if [ -r "$pdir/comm" ]; then
        comm=$(read_attr "$pdir/comm")
    fi
    case "$comm" in
        sh|bash|ash|dash|busybox|su|sudo|ssh|sshd|timeout|grep|awk|sed)
            continue ;;
    esac
    if [ -r "$pdir/cmdline" ]; then
        cmdline=$(tr '\0' ' ' < "$pdir/cmdline" 2>/dev/null || true)
    fi
    argv0=${cmdline%% *}
    exe_base=${argv0##*/}
    if printf '%s\n%s\n' "$comm" "$exe_base" | grep -qiE '^(mediaplayer|mediamanagement|carplay|carlife|vmostauxin|auxin|apple|ipod|usbmux|ddpserver)'; then
        mp_found=1
        echo "pid=$pid comm=${comm:-unknown} cmdline=$cmdline"
    fi
done
if [ "$mp_found" -eq 0 ]; then
    echo "no matching MediaPlayer/CARPLAY processes readable in /proc"
fi

section "Process Owning /dev/ffs-carlife (read-only proc scan)"
ls -la "$R/dev/ffs-carlife" 2>/dev/null || echo "/dev/ffs-carlife: not present"
for pdir in "$R"/proc/[0-9]*; do
    [ -d "$pdir/fd" ] || continue
    hits=$(ls -l "$pdir/fd" 2>/dev/null | grep -E 'ffs-carlife|carlife' || true)
    [ -n "$hits" ] || continue
    echo "$hits"
    pid=${pdir##*/}
    if [ -r "$pdir/comm" ]; then
        echo "  pid=$pid comm=$(read_attr "$pdir/comm")"
    fi
    if [ -r "$pdir/cmdline" ]; then
        echo "  pid=$pid cmdline=$(tr '\0' ' ' < "$pdir/cmdline" 2>/dev/null || true)"
    fi
done

section "Dual-Role / Host vs Peripheral Hints"
for base in "$R/sys/devices/platform" "$R/sys/bus/platform/devices" "$R/sys/class/extcon" "$R/sys/class/usb_role"; do
    [ -d "$base" ] || continue
    for p in "$base"/*usb* "$base"/*dwc* "$base"/*otg* "$base"/*4889* "$base"/*488d* "$base"/*extcon*; do
        [ -e "$p" ] || continue
        echo "--- $p ---"
        ls -ld "$p" 2>/dev/null || true
        for attr in role mode dr_mode state cable_state vbus id status uevent; do
            if [ -r "$p/$attr" ]; then
                echo "  $attr = $(read_attr "$p/$attr")"
            fi
        done
    done
done
if [ -d "$R/sys/kernel/debug/usb" ]; then
    echo "--- /sys/kernel/debug/usb ---"
    ls -la "$R/sys/kernel/debug/usb" 2>/dev/null || true
fi
for dbg in "$R"/sys/kernel/debug/*4889* "$R"/sys/kernel/debug/dwc3*; do
    [ -e "$dbg" ] || continue
    echo "--- $dbg ---"
    ls -la "$dbg" 2>/dev/null || true
    for attr in mode regdump link_state; do
        if [ -r "$dbg/$attr" ] && [ "$attr" != "regdump" ]; then
            echo "  $attr = $(read_attr "$dbg/$attr")"
        fi
    done
done

section "Recent Kernel USB/Gadget Messages"
if command -v dmesg >/dev/null 2>&1; then
    dmesg 2>/dev/null | grep -iE 'usb|dwc|omap|xhci|ehci|musb|ncm|tun|ffs|gadget|carlife|05ac' | tail -n 40 || true
fi
