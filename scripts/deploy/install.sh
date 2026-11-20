#!/bin/sh
# Safe installer for EntryNav2-CarPlay on BMW HU_ENTRYNAV2 (BusyBox / POSIX sh).
#
# Installs:
#   * /opt/carplay/carplayd
#   * /opt/hmi/data/ro/Plugins/EntryCarPlay/ (HMI plugin, manifest, XML, resource zips)
#   * /var/local/data/CarPlay/carplay.conf (safe defaults: wireless=0, wired=0)
#   * Optional systemd unit if --with-systemd is passed or <root>/etc/systemd/system exists
#
# Backs up every modified pre-existing file byte-for-byte (with mode) and records all
# created files/directories in <root>/var/local/data/CarPlay/.install-backup/ so
# uninstall.sh restores the head unit byte-for-byte.

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)

ROOT="${CARPLAY_ROOT:-/}"
STAGE_DIR=""
MODE="safe"
DRY_RUN=0
NO_REMOUNT=0
WITH_SYSTEMD="auto"
KEEP_EXISTING_CONF=0

usage() {
    cat <<'EOF'
Usage: install.sh [options]
  --root PATH          Target root directory (default: /; override for fake-root tests)
  --stage PATH         Staging directory (e.g. build/host/install-root or unpacked tarball)
  --mode MODE          safe (default: wireless=0, wired=0) | wired | wireless | both
  --with-systemd       Always install entry-carplay.service into <root>/etc/systemd/system
  --no-systemd         Never install entry-carplay.service
  --keep-config        Do not overwrite existing carplay.conf (still backs up on first install)
  --no-remount         Skip mount -o remount,rw/ro /
  --dry-run            Print every action without modifying anything
  -h, --help           Show help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            ROOT=$2; shift 2 ;;
        --stage)
            STAGE_DIR=$2; shift 2 ;;
        --mode)
            MODE=$2; shift 2 ;;
        --with-systemd)
            WITH_SYSTEMD=1; shift ;;
        --no-systemd)
            WITH_SYSTEMD=0; shift ;;
        --keep-config)
            KEEP_EXISTING_CONF=1; shift ;;
        --no-remount)
            NO_REMOUNT=1; shift ;;
        --dry-run)
            DRY_RUN=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "install.sh: unknown option: $1" >&2
            usage >&2
            exit 2 ;;
    esac
done

case "$MODE" in
    safe)     CFG_WIRELESS=0; CFG_WIRED=0 ;;
    wired)    CFG_WIRELESS=0; CFG_WIRED=1 ;;
    wireless) CFG_WIRELESS=1; CFG_WIRED=0 ;;
    both)     CFG_WIRELESS=1; CFG_WIRED=1 ;;
    *)
        echo "install.sh: invalid --mode '$MODE' (expected safe|wired|wireless|both)" >&2
        exit 2 ;;
esac

# Normalize ROOT (keep "/" as "", otherwise strip trailing "/")
if [ "$ROOT" = "/" ]; then
    R=""
    IS_LIVE_ROOT=1
else
    R=${ROOT%/}
    IS_LIVE_ROOT=0
    NO_REMOUNT=1
fi

if [ -z "$STAGE_DIR" ]; then
    for cand in "$PWD" "$REPO_ROOT/build/host/install-root" "$REPO_ROOT/build/arm-entrynav2/install-root"; do
        if [ -f "$cand/opt/carplay/carplayd" ]; then
            STAGE_DIR=$cand
            break
        fi
    done
fi

if [ -z "$STAGE_DIR" ] || [ ! -d "$STAGE_DIR" ]; then
    echo "install.sh: staging directory not found (pass --stage PATH)" >&2
    exit 1
fi

if [ ! -f "$STAGE_DIR/opt/carplay/carplayd" ]; then
    echo "install.sh: missing $STAGE_DIR/opt/carplay/carplayd" >&2
    exit 1
fi

BACKUP_REL="var/local/data/CarPlay/.install-backup"
BACKUP_DIR="$R/$BACKUP_REL"
MANIFEST="$BACKUP_DIR/manifest.txt"
DIRS_LOG="$BACKUP_DIR/created_dirs.txt"
FILES_DIR="$BACKUP_DIR/files"

log_act() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] %s\n' "$*"
    else
        printf '[install] %s\n' "$*"
    fi
}

file_mode() {
    if [ -x "$1" ]; then
        echo "0755"
    else
        echo "0644"
    fi
}

ensure_dir_tracked() {
    _edt_rel=${1#/}
    _edt_target="$R/$_edt_rel"
    if [ -d "$_edt_target" ]; then
        return 0
    fi
    # Walk components so parent dirs created by us are recorded in order
    _edt_cur=""
    _edt_ifs=$IFS
    IFS='/'
    set -- $_edt_rel
    IFS=$_edt_ifs
    for _edt_part in "$@"; do
        [ -n "$_edt_part" ] || continue
        _edt_cur="${_edt_cur:+$_edt_cur/}$_edt_part"
        _edt_full="$R/$_edt_cur"
        if [ ! -d "$_edt_full" ]; then
            log_act "mkdir -p $_edt_full"
            if [ "$DRY_RUN" -eq 0 ]; then
                mkdir -p "$_edt_full"
                printf '%s\n' "$_edt_cur" >> "$DIRS_LOG"
            fi
        fi
    done
}

backup_and_install_file() {
    _bif_src=$1
    _bif_rel=${2#/}
    _bif_mode=$3
    _bif_dst="$R/$_bif_rel"
    _bif_rel_dir=${_bif_rel%/*}

    ensure_dir_tracked "$_bif_rel_dir"

    if [ -e "$_bif_dst" ] || [ -L "$_bif_dst" ]; then
        _bif_orig_mode=$(file_mode "$_bif_dst")
        _bif_bfile="$FILES_DIR/$_bif_rel"
        _bif_bdir=${_bif_bfile%/*}
        log_act "backup $_bif_dst -> $_bif_bfile (mode $_bif_orig_mode)"
        if [ "$DRY_RUN" -eq 0 ]; then
            mkdir -p "$_bif_bdir"
            cp -p "$_bif_dst" "$_bif_bfile"
            printf 'RESTORE %s %s\n' "$_bif_orig_mode" "$_bif_rel" >> "$MANIFEST"
        fi
    else
        log_act "record new file $_bif_rel"
        if [ "$DRY_RUN" -eq 0 ]; then
            printf 'REMOVE %s\n' "$_bif_rel" >> "$MANIFEST"
        fi
    fi

    log_act "install $_bif_src -> $_bif_dst (mode $_bif_mode)"
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -f "$_bif_dst"
        cp "$_bif_src" "$_bif_dst"
        chmod "$_bif_mode" "$_bif_dst"
    fi
}

install_generated_conf() {
    _igc_rel="var/local/data/CarPlay/carplay.conf"
    _igc_dst="$R/$_igc_rel"
    ensure_dir_tracked "var/local/data/CarPlay"

    if [ -e "$_igc_dst" ] && [ "$KEEP_EXISTING_CONF" -eq 1 ]; then
        log_act "keep existing $_igc_dst (--keep-config)"
        return 0
    fi

    if [ -e "$_igc_dst" ] || [ -L "$_igc_dst" ]; then
        _igc_orig_mode=$(file_mode "$_igc_dst")
        _igc_bfile="$FILES_DIR/$_igc_rel"
        _igc_bdir=${_igc_bfile%/*}
        log_act "backup $_igc_dst -> $_igc_bfile (mode $_igc_orig_mode)"
        if [ "$DRY_RUN" -eq 0 ]; then
            mkdir -p "$_igc_bdir"
            cp -p "$_igc_dst" "$_igc_bfile"
            printf 'RESTORE %s %s\n' "$_igc_orig_mode" "$_igc_rel" >> "$MANIFEST"
        fi
    else
        log_act "record new config $_igc_rel"
        if [ "$DRY_RUN" -eq 0 ]; then
            printf 'REMOVE %s\n' "$_igc_rel" >> "$MANIFEST"
        fi
    fi

    log_act "write $_igc_dst (wireless=$CFG_WIRELESS wired=$CFG_WIRED detach_usbfs_driver=0)"
    if [ "$DRY_RUN" -eq 0 ]; then
        cat > "$_igc_dst" <<EOF
# EntryNav2-CarPlay configuration (generated by install.sh --mode $MODE)
# Safe defaults keep wireless=0 and wired=0 until explicitly verified and enabled.
enabled=1
wireless=$CFG_WIRELESS
wired=$CFG_WIRED
detach_usbfs_driver=0
crash_guard_max=3
crash_guard_window_sec=120
crash_guard_stable_sec=120
EOF
        chmod 0644 "$_igc_dst"
    fi
}

REMOUNTED_RW=0
cleanup_ro() {
    if [ "$REMOUNTED_RW" -eq 1 ] && [ "$DRY_RUN" -eq 0 ]; then
        sync || true
        mount -o remount,ro / || echo "WARNING: mount -o remount,ro / failed; reboot to restore read-only" >&2
    fi
}
trap cleanup_ro EXIT INT TERM

if [ -d "$BACKUP_DIR" ] && [ -f "$MANIFEST" ]; then
    echo "install.sh: existing backup found at $BACKUP_DIR; run uninstall.sh first to avoid losing original baseline" >&2
    exit 1
fi

if [ "$NO_REMOUNT" -eq 0 ] && [ "$IS_LIVE_ROOT" -eq 1 ]; then
    log_act "mount -o remount,rw /"
    if [ "$DRY_RUN" -eq 0 ]; then
        mount -o remount,rw /
        REMOUNTED_RW=1
    fi
fi

log_act "prepare backup metadata under $BACKUP_DIR"
if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p "$FILES_DIR"
    : > "$MANIFEST"
    : > "$DIRS_LOG"
fi

# 1. Daemon binary
backup_and_install_file "$STAGE_DIR/opt/carplay/carplayd" "opt/carplay/carplayd" "0755"

# 2. HMI Plugin directory (all staged files under opt/hmi/data/ro/Plugins/EntryCarPlay)
PLUGIN_REL="opt/hmi/data/ro/Plugins/EntryCarPlay"
if [ -d "$STAGE_DIR/$PLUGIN_REL" ]; then
    for f in "$STAGE_DIR/$PLUGIN_REL"/*; do
        [ -f "$f" ] || continue
        fname=${f##*/}
        case "$fname" in
            EntryCarPlay|*.so|*.so.*) fmode="0755" ;;
            *) fmode="0644" ;;
        esac
        backup_and_install_file "$f" "$PLUGIN_REL/$fname" "$fmode"
    done
fi

# 3. Marker file matching upstream .installed-by-* convention
MARKER_REL="opt/carplay/.installed-by-entrycarplay"
ensure_dir_tracked "opt/carplay"
log_act "create marker $R/$MARKER_REL"
if [ "$DRY_RUN" -eq 0 ]; then
    printf 'REMOVE %s\n' "$MARKER_REL" >> "$MANIFEST"
    date '+%Y-%m-%dT%H:%M:%S' > "$R/$MARKER_REL" 2>/dev/null || : > "$R/$MARKER_REL"
    chmod 0644 "$R/$MARKER_REL"
fi

# 4. Optional systemd service unit
UNIT_SRC="$SCRIPT_DIR/entry-carplay.service"
if [ "$WITH_SYSTEMD" = "1" ] || { [ "$WITH_SYSTEMD" = "auto" ] && [ -d "$R/etc/systemd/system" ]; }; then
    if [ -f "$UNIT_SRC" ]; then
        backup_and_install_file "$UNIT_SRC" "etc/systemd/system/entry-carplay.service" "0644"
    fi
fi

# 5. Safe-mode config file
install_generated_conf

if [ "$NO_REMOUNT" -eq 0 ] && [ "$IS_LIVE_ROOT" -eq 1 ]; then
    log_act "sync && mount -o remount,ro /"
    if [ "$DRY_RUN" -eq 0 ]; then
        sync
        mount -o remount,ro /
        REMOUNTED_RW=0
    fi
fi

log_act "done (mode=$MODE, root=${ROOT})"
