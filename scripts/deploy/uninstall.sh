#!/bin/sh
# Safe uninstaller / rollback for EntryNav2-CarPlay (BusyBox / POSIX sh).
#
# Reads <root>/var/local/data/CarPlay/.install-backup/manifest.txt and:
#   * Restores every backed-up pre-existing file byte-for-byte with original mode
#   * Removes every file newly added by install.sh
#   * Removes newly created directories in reverse order (only if empty)

set -eu

ROOT="${CARPLAY_ROOT:-/}"
DRY_RUN=0
NO_REMOUNT=0
KEEP_DATA=0

usage() {
    cat <<'EOF'
Usage: uninstall.sh [options]
  --root PATH          Target root directory (default: /; override for fake-root tests)
  --keep-data          Keep user data files in <root>/var/local/data/CarPlay after restoring backups
  --no-remount         Skip mount -o remount,rw/ro /
  --dry-run            Print every action without modifying anything
  -h, --help           Show help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            ROOT=$2; shift 2 ;;
        --keep-data)
            KEEP_DATA=1; shift ;;
        --no-remount)
            NO_REMOUNT=1; shift ;;
        --dry-run)
            DRY_RUN=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "uninstall.sh: unknown option: $1" >&2
            usage >&2
            exit 2 ;;
    esac
done

if [ "$ROOT" = "/" ]; then
    R=""
    IS_LIVE_ROOT=1
else
    R=${ROOT%/}
    IS_LIVE_ROOT=0
    NO_REMOUNT=1
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
        printf '[uninstall] %s\n' "$*"
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

if [ "$NO_REMOUNT" -eq 0 ] && [ "$IS_LIVE_ROOT" -eq 1 ]; then
    log_act "mount -o remount,rw /"
    if [ "$DRY_RUN" -eq 0 ]; then
        mount -o remount,rw /
        REMOUNTED_RW=1
    fi
fi

if [ ! -f "$MANIFEST" ]; then
    log_act "no install manifest at $MANIFEST; performing standard cleanup"
    for p in "$R/opt/carplay" "$R/opt/hmi/data/ro/Plugins/EntryCarPlay"; do
        if [ -e "$p" ]; then
            log_act "rm -rf $p"
            [ "$DRY_RUN" -eq 1 ] || rm -rf "$p"
        fi
    done
    if [ "$KEEP_DATA" -eq 0 ] && [ -e "$R/var/local/data/CarPlay" ]; then
        log_act "rm -rf $R/var/local/data/CarPlay"
        [ "$DRY_RUN" -eq 1 ] || rm -rf "$R/var/local/data/CarPlay"
    fi
else
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        action=${line%% *}
        rest=${line#* }
        case "$action" in
            REMOVE)
                rel=$rest
                target="$R/$rel"
                if [ "$KEEP_DATA" -eq 1 ]; then
                    case "$rel" in
                        var/local/data/CarPlay/*)
                            log_act "keep data file $target (--keep-data)"
                            continue ;;
                    esac
                fi
                if [ -e "$target" ] || [ -L "$target" ]; then
                    log_act "rm -f $target"
                    [ "$DRY_RUN" -eq 1 ] || rm -f "$target"
                fi
                ;;
            RESTORE)
                mode=${rest%% *}
                rel=${rest#* }
                target="$R/$rel"
                src="$FILES_DIR/$rel"
                if [ ! -e "$src" ] && [ ! -L "$src" ]; then
                    echo "uninstall.sh: missing backup file $src" >&2
                    exit 1
                fi
                log_act "restore $src -> $target (mode $mode)"
                if [ "$DRY_RUN" -eq 0 ]; then
                    mkdir -p "${target%/*}"
                    rm -f "$target"
                    cp -p "$src" "$target"
                    chmod "$mode" "$target"
                fi
                ;;
            *)
                echo "uninstall.sh: malformed manifest line: $line" >&2
                exit 1 ;;
        esac
    done < "$MANIFEST"

    if [ -f "$DIRS_LOG" ]; then
        # Reverse order without relying on GNU tac
        rev_list=""
        while IFS= read -r d; do
            [ -n "$d" ] || continue
            rev_list="$d
$rev_list"
        done < "$DIRS_LOG"
        printf '%s' "$rev_list" | while IFS= read -r d; do
            [ -n "$d" ] || continue
            target="$R/$d"
            if [ "$KEEP_DATA" -eq 1 ] && [ "$d" = "var/local/data/CarPlay" ]; then
                continue
            fi
            if [ -d "$target" ]; then
                log_act "rmdir (if empty) $target"
                if [ "$DRY_RUN" -eq 0 ]; then
                    rmdir "$target" 2>/dev/null || true
                fi
            fi
        done
    fi

    log_act "remove backup directory $BACKUP_DIR"
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -rf "$BACKUP_DIR"
        if [ "$KEEP_DATA" -eq 0 ] && [ -d "$R/var/local/data/CarPlay" ]; then
            rmdir "$R/var/local/data/CarPlay" 2>/dev/null || true
        fi
    fi
fi

if [ "$NO_REMOUNT" -eq 0 ] && [ "$IS_LIVE_ROOT" -eq 1 ]; then
    log_act "sync && mount -o remount,ro /"
    if [ "$DRY_RUN" -eq 0 ]; then
        sync
        mount -o remount,ro /
        REMOUNTED_RW=0
    fi
fi

log_act "done (root=$ROOT)"
