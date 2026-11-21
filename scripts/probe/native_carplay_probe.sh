#!/bin/sh
# Read-only native CARPLAY / DDPServer / MediaPlayer probe for BMW HU_ENTRYNAV2 (Visit 2).
# BusyBox / POSIX sh compatible.
#
# Collects:
#   1. /proc/<pid>/{cmdline,environ (redacted),maps,status,fd,net/unix} for CARPLAY,
#      DDPServer, MediaManagementServer/MediaPlayer, vmostAuxInUSB, AuxInUCM
#   2. ls -l of /usr/local/bin/CARPLAY, /opt/app/usr/MediaPlayer, data/systemd units
#   3. Bounded config/xml/json scan under /etc and /opt (incl. compositor.conf & evo_config.xml)
#   4. D-Bus system bus ListNames (if dbus-send/busctl available) & system.d configs
#   5. Bounded journal/dmesg/Mediaplayer log lines mentioning CarPlay/iAP/MFi/FSC
#   6. mDNS registrations & mdnsd state
#   7. Optional --watch SECS loop (every 2s) for live iPhone plug/unplug observation
#
# Strictly read-only outside --out-dir (under /tmp by default). Never kills processes,
# never performs I2C transactions.

set -u

R=${PROBE_ROOT:-}
OUT_DIR=${NATIVE_PROBE_OUT:-}
OUT_FILE=""
CMD_TIMEOUT=${NATIVE_PROBE_TIMEOUT:-5}
WATCH_SECS=0

usage() {
    cat <<'EOF'
Usage: native_carplay_probe.sh [options]
  --out-dir PATH       Writable output directory (default: /tmp/native-carplay-probe-YYYYMMDD-HHMMSS)
  --out-file PATH      Specific output file inside --out-dir (default: <out-dir>/native_carplay.txt)
  --probe-root PATH    Fake root prefix for host CI testing (or PROBE_ROOT env)
  --timeout SEC        Per-command timeout in seconds (default: 5)
  --watch SECS         Sample every 2s for SECS seconds while plugging/unplugging iPhone (max 120s)
  -h, --help           Show help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --out-dir)
            OUT_DIR=$2; shift 2 ;;
        --out-file)
            OUT_FILE=$2; shift 2 ;;
        --probe-root)
            R=$2; export PROBE_ROOT="$R"; shift 2 ;;
        --timeout)
            CMD_TIMEOUT=$2; shift 2 ;;
        --watch)
            WATCH_SECS=$2; shift 2 ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "native_carplay_probe.sh: unknown option: $1" >&2
            usage >&2
            exit 2 ;;
    esac
done

case "$CMD_TIMEOUT" in
    ''|*[!0-9]*) CMD_TIMEOUT=5 ;;
esac
[ "$CMD_TIMEOUT" -lt 1 ] && CMD_TIMEOUT=5

case "$WATCH_SECS" in
    ''|*[!0-9]*) WATCH_SECS=0 ;;
esac
if [ "$WATCH_SECS" -gt 120 ]; then
    WATCH_SECS=120
fi

TS=$(date '+%Y%m%d-%H%M%S' 2>/dev/null || echo 'unknown-time')
if [ -z "$OUT_DIR" ]; then
    OUT_DIR="/tmp/native-carplay-probe-$TS"
fi
mkdir -p "$OUT_DIR"
if [ -z "$OUT_FILE" ]; then
    OUT_FILE="$OUT_DIR/native_carplay.txt"
fi

# Detect GNU coreutils timeout only (BusyBox `timeout -t` leaves orphan timer processes).
USE_GNU_TIMEOUT=0
if command -v timeout >/dev/null 2>&1; then
    if timeout 1 true >/dev/null 2>&1; then
        USE_GNU_TIMEOUT=1
    fi
fi

run_to() {
    secs=$1
    shift
    if [ "$USE_GNU_TIMEOUT" -eq 1 ]; then
        timeout "$secs" "$@" 2>&1 || printf '[rc=%s]\n' "$?"
        return 0
    fi
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
    fi
}

section() {
    printf '\n=== %s ===\n' "$1"
}

read_attr() {
    if [ -r "$1" ]; then
        tr -d '\r\n' < "$1" 2>/dev/null || true
    fi
}

redact_environ() {
    env_file=$1
    if [ ! -r "$env_file" ]; then
        printf '(unreadable)\n'
        return 0
    fi
    tr '\0' '\n' < "$env_file" 2>/dev/null | awk '
    {
        if ($0 == "") next
        eq = index($0, "=")
        if (eq == 0) { print $0; next }
        k = substr($0, 1, eq - 1)
        v = substr($0, eq + 1)
        uk = toupper(k)
        if (uk ~ /(KEY|TOKEN|SECRET|PASS|PWD|PIN|AUTH|CRED|CERT|PRIV|COOKIE|SESSION|VIN|SERIAL|IMEI|UDID|MAC|BTADDR|PSK|SIG)/ || v ~ /^[0-9A-Fa-f]{24,}$/) {
            print k "=<REDACTED>"
        } else {
            print $0
        }
    }'
}

redact_line() {
    sed -e 's/\([Pp]assphrase\|[Pp]assword\|wpa_psk\|[Ss]ecret\|[Tt]oken\|[Aa]uth[Kk]ey\|[Ss]erial\|[Vv][Ii][Nn]\|[Uu][Dd][Ii][Dd]\|[Ii][Mm][Ee][Ii]\)[=:][^ ;,]*/\1=<REDACTED>/g'
}

is_target_proc() {
    pid=$1
    comm=$2
    cmdline=$3
    [ "$pid" = "$$" ] && return 1
    case "$comm" in
        sh|bash|ash|dash|busybox|su|sudo|ssh|sshd|timeout|grep|awk|sed)
            return 1 ;;
    esac
    argv0=${cmdline%% *}
    exe_base=${argv0##*/}
    if printf '%s\n%s\n' "$comm" "$exe_base" | grep -qiE '^(carplay|ddpserver|mediaplayer|mediamanagement|vmostauxinusb|auxinucm)'; then
        return 0
    fi
    return 1
}

dump_proc_target() {
    pdir=$1
    pid=${pdir##*/}
    comm=""
    cmdline=""
    [ -r "$pdir/comm" ] && comm=$(read_attr "$pdir/comm")
    [ -r "$pdir/cmdline" ] && cmdline=$(tr '\0' ' ' < "$pdir/cmdline" 2>/dev/null || true)

    printf '\n--- PID %s (comm=%s) ---\n' "$pid" "${comm:-unknown}"
    printf 'cmdline: %s\n' "${cmdline:-<empty>}"
    if [ -L "$pdir/exe" ]; then
        printf 'exe: %s\n' "$(ls -ld "$pdir/exe" 2>/dev/null || true)"
    fi
    printf '[status]\n'
    if [ -r "$pdir/status" ]; then
        grep -E '^(Name|State|Pid|PPid|Uid|Gid|Groups|Threads|VmRSS|VmSize):' "$pdir/status" 2>/dev/null || cat "$pdir/status" 2>/dev/null || true
    else
        printf '(status unreadable)\n'
    fi

    printf '[environ (redacted)]\n'
    redact_environ "$pdir/environ"

    printf '[fd links]\n'
    if [ -d "$pdir/fd" ]; then
        ls -l "$pdir/fd" 2>/dev/null | head -n 120 || printf '(fd unreadable)\n'
    else
        printf '(no fd dir)\n'
    fi

    printf '[maps]\n'
    if [ -r "$pdir/maps" ]; then
        head -n 300 "$pdir/maps" 2>/dev/null || true
    else
        printf '(maps unreadable)\n'
    fi

    printf '[net/unix]\n'
    if [ -r "$pdir/net/unix" ]; then
        head -n 120 "$pdir/net/unix" 2>/dev/null || true
    else
        printf '(net/unix unreadable)\n'
    fi
}

sample_watch_tick() {
    tick_idx=$1
    tick_max=$2
    now_str=$(date '+%H:%M:%S' 2>/dev/null || echo '?')
    up_str=$(read_attr "$R/proc/uptime")
    printf '\n--- WATCH SAMPLE %s/%s (%s uptime=%s) ---\n' "$tick_idx" "$tick_max" "$now_str" "${up_str:-?}"

    if [ -d "$R/sys/bus/usb/devices" ]; then
        found_apple=0
        for d in "$R/sys/bus/usb/devices"/*; do
            [ -e "$d" ] || continue
            [ -r "$d/idVendor" ] || continue
            vid=$(read_attr "$d/idVendor")
            case "$vid" in
                05ac|05AC)
                    found_apple=1
                    dname=${d##*/}
                    pid_hex=$(read_attr "$d/idProduct")
                    busn=$(read_attr "$d/busnum")
                    devn=$(read_attr "$d/devnum")
                    cfg=$(read_attr "$d/bConfigurationValue")
                    ncfg=$(read_attr "$d/bNumConfigurations")
                    printf 'USB %s vid=%s pid=%s bus=%s dev=%s cfg=%s/%s\n' \
                        "$dname" "$vid" "$pid_hex" "$busn" "$devn" "$cfg" "$ncfg"
                    for iface in "$R/sys/bus/usb/devices/$dname":*; do
                        [ -e "$iface" ] || continue
                        iname=${iface##*/}
                        cls=$(read_attr "$iface/bInterfaceClass")
                        sub=$(read_attr "$iface/bInterfaceSubClass")
                        proto=$(read_attr "$iface/bInterfaceProtocol")
                        drv="none"
                        if [ -L "$iface/driver" ]; then
                            drv=$(ls -ld "$iface/driver" 2>/dev/null | sed 's/.*-> //' || true)
                        fi
                        printf '  IF %s class=%s/%s/%s drv=%s\n' "$iname" "$cls" "$sub" "$proto" "$drv"
                    done
                    ;;
            esac
        done
        [ "$found_apple" -eq 0 ] && printf 'USB: no 05ac device attached\n'
    fi

    if [ -n "$WATCH_PIDS" ]; then
        for pid in $WATCH_PIDS; do
            pdir="$R/proc/$pid"
            [ -d "$pdir" ] || continue
            comm=""
            [ -r "$pdir/comm" ] && comm=$(read_attr "$pdir/comm")
            hits=$(ls -l "$pdir/fd" 2>/dev/null | grep -E '/dev/bus/usb|hid|i2c|mdns|ffs|/tmp/Mediaplayer' || true)
            if [ -n "$hits" ]; then
                printf 'FD pid=%s comm=%s:\n' "$pid" "${comm:-unknown}"
                printf '%s\n' "$hits" | sed 's/^/  /'
            else
                printf 'FD pid=%s comm=%s: (no usb/hid/i2c/mdns/ffs fds)\n' "$pid" "${comm:-unknown}"
            fi
        done
    else
        printf 'FD: (no cached CARPLAY/DDPServer/MediaPlayer target PIDs)\n'
    fi

    for f in "$R"/tmp/Mediaplayer/*DDPS* "$R"/tmp/Mediaplayer/*CARPLAY* "$R"/tmp/Mediaplayer/*USBC*; do
        [ -f "$f" ] || continue
        ls -l "$f" 2>/dev/null || true
        tail -n 5 "$f" 2>/dev/null | redact_line | sed 's/^/  /' || true
    done
}

WATCH_PIDS=""

{
    printf 'EntryNav2-CarPlay Native CarPlay / DDPServer Probe (%s)\n' "$TS"
    printf '================================================================\n'

    section "1. Target Processes (/proc/<pid>/{cmdline,environ,maps,status,fd,net/unix})"
    found_target=0
    for pdir in "$R"/proc/[0-9]*; do
        [ -d "$pdir" ] || continue
        pid=${pdir##*/}
        comm=""
        cmdline=""
        [ -r "$pdir/comm" ] && comm=$(read_attr "$pdir/comm")
        [ -r "$pdir/cmdline" ] && cmdline=$(tr '\0' ' ' < "$pdir/cmdline" 2>/dev/null || true)
        if is_target_proc "$pid" "$comm" "$cmdline"; then
            found_target=1
            WATCH_PIDS="$WATCH_PIDS $pid"
            dump_proc_target "$pdir"
        fi
    done
    if [ "$found_target" -eq 0 ]; then
        printf '(no CARPLAY/DDPServer/MediaPlayer processes found in %s/proc)\n' "$R"
    fi

    section "2. Native Binaries, Dirs & Systemd Unit Files (metadata + unit text only)"
    ls -la "$R/usr/local/bin/CARPLAY" "$R/usr/local/bin/DDPServer" \
        "$R/usr/local/bin/MediaManagementServer" "$R/usr/local/bin/vmostAuxInUSB" \
        "$R/usr/local/bin/AuxInUCM" 2>/dev/null || printf '(some /usr/local/bin binaries absent)\n'

    for d in "$R/opt/app/usr/MediaPlayer" "$R/var/local/data/MediaPlayer" \
             "$R/var/local/data/CarPlay" "$R/tmp/Mediaplayer"; do
        if [ -d "$d" ]; then
            printf '\n[dir %s]\n' "${d#"$R"}"
            find "$d" -maxdepth 3 2>/dev/null | head -n 120 | while IFS= read -r item; do
                ls -ld "$item" 2>/dev/null || true
            done
        else
            printf '\n[dir %s]: absent\n' "${d#"$R"}"
        fi
    done

    for unit in CARPLAY.service DistributedDeviceProtocol.service \
                MediaManagementServer.service vmostAuxInUSB12.service \
                USBConnectionManager.service; do
        upath="$R/etc/systemd/system/$unit"
        if [ -r "$upath" ]; then
            printf '\n[%s]\n' "/etc/systemd/system/$unit"
            ls -la "$upath" 2>/dev/null || true
            cat "$upath" 2>/dev/null || true
        fi
    done

    section "3. Config / XML / JSON / Compositor Files under /etc and /opt (bounded)"
    printf '[compositor / layermanager / weston paths]\n'
    for base in "$R/etc" "$R/opt"; do
        [ -d "$base" ] || continue
        find "$base" -maxdepth 4 \( -name '*compositor*' -o -name '*weston*' -o -name '*layermanager*' \) 2>/dev/null | head -n 40 || true
    done

    evo_xml="$R/opt/app/usr/BTMedia/evolution/stack/etc/evo_config.xml"
    if [ -r "$evo_xml" ]; then
        printf '\n[%s (carplay/iap/uuid/supported_services matches)]\n' "/opt/app/usr/BTMedia/evolution/stack/etc/evo_config.xml"
        grep -niE 'caff|cafe|carplay|iap|supported_services|6203' "$evo_xml" 2>/dev/null | head -n 60 || printf '(no matching lines)\n'
    fi

    printf '\n[config/xml/json scan in /etc and /opt]\n'
    total_cfg_lines=0
    for base in "$R/etc" "$R/opt"; do
        [ -d "$base" ] || continue
        # Prune large HMI image/mesh asset directories; inspect config/xml/json files <= 512 KiB
        find "$base" -path "$R/opt/hmi/data" -prune -o -type f \
            \( -name '*.conf' -o -name '*.cfg' -o -name '*.xml' -o -name '*.json' -o -name '*.ini' -o -name '*.policy' -o -name '*.rules' \) \
            -size -512k -print 2>/dev/null | head -n 200 | while IFS= read -r cfg; do
            [ -r "$cfg" ] || continue
            hits=$(grep -niE 'carplay|iap2|mfi|apple_auth|auth_chip|genivi-flip-renderorder|compositor' "$cfg" 2>/dev/null | head -n 15 || true)
            if [ -n "$hits" ]; then
                printf 'FILE: %s\n' "${cfg#"$R"}"
                printf '%s\n' "$hits" | redact_line | sed 's/^/  /'
            fi
        done | head -n 250
    done

    section "4. D-Bus System Names & Policies"
    if [ -d "$R/etc/dbus-1/system.d" ]; then
        grep -rilE 'carplay|ddp|mediaplayer|mediamanagement|auxin|apple|mfi|iap' "$R/etc/dbus-1/system.d" 2>/dev/null || printf '(no matching D-Bus policy files)\n'
    fi
    if command -v dbus-send >/dev/null 2>&1; then
        run_to "$CMD_TIMEOUT" dbus-send --system --print-reply --dest=org.freedesktop.DBus \
            /org/freedesktop/DBus org.freedesktop.DBus.ListNames
    else
        printf 'dbus-send: not installed\n'
        if command -v busctl >/dev/null 2>&1; then
            run_to "$CMD_TIMEOUT" busctl list --no-pager
        elif command -v gdbus >/dev/null 2>&1; then
            run_to "$CMD_TIMEOUT" gdbus call --system --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus --method org.freedesktop.DBus.ListNames
        fi
    fi

    section "5. Journal / dmesg / MediaPlayer Logs (CarPlay/iAP/MFi/FSC, bounded)"
    if command -v journalctl >/dev/null 2>&1; then
        printf '[journalctl matches (tail 100)]\n'
        run_to "$CMD_TIMEOUT" sh -c "journalctl -b --no-pager -n 1000 2>/dev/null | grep -iE 'carplay|iap|mfi|fsc|ddp|05ac|apple' | tail -n 100" | redact_line || true
    else
        printf 'journalctl: not installed\n'
    fi
    if command -v dmesg >/dev/null 2>&1; then
        printf '[dmesg matches (tail 60)]\n'
        run_to "$CMD_TIMEOUT" dmesg | grep -iE 'carplay|iap|mfi|fsc|05ac|i2c' | tail -n 60 | redact_line || true
    fi
    if [ -d "$R/tmp/Mediaplayer" ]; then
        for lf in "$R"/tmp/Mediaplayer/*.txt; do
            [ -r "$lf" ] || continue
            printf '[%s (tail 30 matching lines)]\n' "${lf#"$R"}"
            grep -iE 'carplay|iap|mfi|fsc|auth|i2c|05ac|usb|ddp' "$lf" 2>/dev/null | tail -n 30 | redact_line || true
        done
    fi

    section "6. mDNS Registrations & mdnsd State"
    for pdir in "$R"/proc/[0-9]*; do
        [ -d "$pdir" ] || continue
        comm=""
        [ -r "$pdir/comm" ] && comm=$(read_attr "$pdir/comm")
        if [ "$comm" = "mdnsd" ]; then
            dump_proc_target "$pdir"
        fi
    done
    ls -la "$R/var/run/mdnsd" "$R/run/mdnsd" "$R"/etc/mdns* 2>/dev/null || true
    if command -v dns-sd >/dev/null 2>&1; then
        printf '[dns-sd -B _carplay._tcp local. (2s)]\n'
        run_to 2 dns-sd -B _carplay._tcp local.
        printf '[dns-sd -B _airplay._tcp local. (2s)]\n'
        run_to 2 dns-sd -B _airplay._tcp local.
    else
        printf 'dns-sd: not installed\n'
    fi

    if [ "$WATCH_SECS" -gt 0 ]; then
        section "7. Live Plug/Unplug Watch (--watch ${WATCH_SECS}s, every 2s)"
        max_ticks=$(( (WATCH_SECS + 1) / 2 ))
        [ "$max_ticks" -lt 1 ] && max_ticks=1
        printf 'native_carplay_probe.sh: WATCH MODE (%ss, %s samples every 2s) -- plug/unplug iPhone now\n' "$WATCH_SECS" "$max_ticks" >&2
        tick=1
        while [ "$tick" -le "$max_ticks" ]; do
            sample_watch_tick "$tick" "$max_ticks"
            if [ "$tick" -lt "$max_ticks" ]; then
                sleep 2 2>/dev/null || break
            fi
            tick=$((tick + 1))
        done
    fi
} > "$OUT_FILE"

printf 'native_carplay_probe.sh complete: %s\n' "$OUT_FILE"
