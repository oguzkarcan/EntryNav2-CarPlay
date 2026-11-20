#!/bin/sh
# Opt-in car-library runtime smoke test for BMW HU_ENTRYNAV2 (ARMv7 hard-float, eglibc 2.15).
#
# Builds ARMv7 GCC 4.7.2 binaries inside a Debian 7 "wheezy" armhf container (--tmpfs /work,
# mounting the repository read-only), checks every ELF binary's architecture, DT_NEEDED list,
# and symbol versions against the real car sysroot libraries, and runs:
#   1. `carlib_smoke` (our platform loaders + dlopen/dlsym + safe side-effect-free calls)
#   2. `carplayd --help` / `--version`
#   3. A subset of existing armhf unit tests (without fork+exec of /bin/sh)
# under QEMU user-mode against the real car libraries from $SYSROOT (mounted read-only).
#
# Skips cleanly (exit 0) when $SYSROOT, Docker, or QEMU is unavailable.
#
# Usage:
#   SYSROOT=/path/to/sysroot sh scripts/ci/carlib_smoke.sh [options]
#
# Options:
#   --sysroot PATH    Path to extracted target rootfs (default: $SYSROOT or ../EntryNav2-CarPlay-Assets/sysroot)
#   --build-dir PATH  Directory for built ARM binaries (default: temporary dir, removed on exit)
#   --log-dir PATH    Directory for logs and summary (default: build/ci-logs-carlib-smoke)
#   --image IMAGE     Docker armhf toolchain image (default: debian/eol:wheezy)
#   --no-unit-subset  Run only carlib_smoke + carplayd + ELF/symbol checks (skip armhf unit-test subset)
#   -h, --help        Show help

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)

SYSROOT_PATH=${SYSROOT:-}
if [ -z "$SYSROOT_PATH" ]; then
    SYSROOT_PATH="$REPO_ROOT/../EntryNav2-CarPlay-Assets/sysroot"
fi
BUILD_OUT_DIR=""
LOG_DIR=${LOG_DIR:-"$REPO_ROOT/build/ci-logs-carlib-smoke"}
ARMHF_IMAGE=${ARMHF_IMAGE:-debian/eol:wheezy}
RUN_UNIT_SUBSET=1

# Self-contained armhf unit tests (no fork+exec of /bin/sh or host helper scripts, since the
# extracted library sysroot contains libraries only and no /bin/sh).
SUBSET_TESTS=${SUBSET_TESTS:-"test_phase1 test_evo_audio test_evo_input test_mdns_advertiser test_alps_spp test_bt_rfcomm test_airplay_session test_iap2_session"}

usage() {
    sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --sysroot)
            [ $# -ge 2 ] || { echo "error: --sysroot requires an argument" >&2; exit 2; }
            SYSROOT_PATH="$2"
            shift 2
            ;;
        --build-dir)
            [ $# -ge 2 ] || { echo "error: --build-dir requires an argument" >&2; exit 2; }
            BUILD_OUT_DIR="$2"
            shift 2
            ;;
        --log-dir)
            [ $# -ge 2 ] || { echo "error: --log-dir requires an argument" >&2; exit 2; }
            LOG_DIR="$2"
            shift 2
            ;;
        --image)
            [ $# -ge 2 ] || { echo "error: --image requires an argument" >&2; exit 2; }
            ARMHF_IMAGE="$2"
            shift 2
            ;;
        --no-unit-subset)
            RUN_UNIT_SUBSET=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------- prerequisite checks (skip cleanly)
if [ ! -d "$SYSROOT_PATH" ]; then
    echo "SKIP: sysroot directory not found: $SYSROOT_PATH (set SYSROOT=/path/to/sysroot to run carlib_smoke)"
    exit 0
fi
SYSROOT_ABS=$(CDPATH='' cd -- "$SYSROOT_PATH" && pwd)

if [ ! -e "$SYSROOT_ABS/lib/ld-linux-armhf.so.3" ] || [ ! -e "$SYSROOT_ABS/lib/libc.so.6" ]; then
    echo "SKIP: $SYSROOT_ABS does not look like an ARMv7 hard-float sysroot (missing lib/ld-linux-armhf.so.3 or lib/libc.so.6)"
    exit 0
fi

QEMU_BIN=""
if command -v qemu-arm-static >/dev/null 2>&1; then
    QEMU_BIN=$(command -v qemu-arm-static)
elif command -v qemu-arm >/dev/null 2>&1; then
    QEMU_BIN=$(command -v qemu-arm)
fi

if [ -z "$QEMU_BIN" ]; then
    echo "SKIP: neither qemu-arm-static nor qemu-arm found in PATH (needed for -L <sysroot> runtime execution)"
    exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not found in PATH (needed for GCC 4.7.2 wheezy armhf build)"
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "SKIP: docker daemon not reachable"
    exit 0
fi

if ! docker run --rm --platform linux/arm/v7 "$ARMHF_IMAGE" true >/dev/null 2>&1; then
    echo "SKIP: docker --platform linux/arm/v7 ($ARMHF_IMAGE) cannot execute (check binfmt_misc / image availability)"
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1 || ! command -v readelf >/dev/null 2>&1; then
    echo "error: python3 and readelf are required on the host to verify ELF symbol versions" >&2
    exit 2
fi

TMP_CREATED=0
if [ -z "$BUILD_OUT_DIR" ]; then
    BUILD_OUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/carplay_carlib_smoke.XXXXXX")
    TMP_CREATED=1
else
    mkdir -p "$BUILD_OUT_DIR"
fi

cleanup() {
    if [ "$TMP_CREATED" -eq 1 ] && [ "${CARLIB_SMOKE_KEEP:-0}" != "1" ]; then
        rm -rf "$BUILD_OUT_DIR"
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$LOG_DIR"
BUILD_LOG="$LOG_DIR/build.log"
ABI_LOG="$LOG_DIR/abi_check.log"
RUN_LOG="$LOG_DIR/qemu_run.log"
SUMMARY="$LOG_DIR/summary.txt"
: > "$BUILD_LOG"
: > "$ABI_LOG"
: > "$RUN_LOG"
: > "$SUMMARY"

echo "=== Car-Library Runtime Smoke Test ==="
echo "Repo    : $REPO_ROOT"
echo "Sysroot : $SYSROOT_ABS (read-only)"
echo "QEMU    : $QEMU_BIN"
echo "Image   : $ARMHF_IMAGE"
echo "Build   : $BUILD_OUT_DIR"
echo "Logs    : $LOG_DIR"

# ---------------------------------------------------------------- 1. Build ARM binaries (GCC 4.7.2)
TARGETS="carlib-smoke daemon hmiapp"
UNIT_LIST=""
if [ "$RUN_UNIT_SUBSET" -eq 1 ]; then
    for t in $SUBSET_TESTS; do
        if [ -f "$REPO_ROOT/tests/$t.cpp" ]; then
            TARGETS="$TARGETS /work/build/$t"
            UNIT_LIST="$UNIT_LIST $t"
        else
            echo "error: requested subset test tests/$t.cpp not found" >&2
            exit 2
        fi
    done
fi

echo
echo "== [1/3] Building ARMv7 GCC 4.7.2 binaries in $ARMHF_IMAGE (--tmpfs /work) =="
build_rc=0
docker run --rm --platform linux/arm/v7 \
    -v "$REPO_ROOT:/src:ro" \
    -v "$BUILD_OUT_DIR:/out" \
    --tmpfs /work:exec,size=3g \
    -e "CARPLAY_SMOKE_TARGETS=$TARGETS" \
    -e "CARPLAY_SMOKE_UNITS=$UNIT_LIST" \
    "$ARMHF_IMAGE" sh -c '
set -eu
cat > /etc/apt/sources.list <<EOF
deb http://archive.debian.org/debian wheezy main
deb http://archive.debian.org/debian-security wheezy/updates main
EOF
rm -f /etc/apt/sources.list.d/*.list 2>/dev/null || true
cat > /etc/apt/apt.conf.d/99ci-eol <<EOF
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
Acquire::http::Timeout "60";
APT::Get::AllowUnauthenticated "true";
APT::Install-Recommends "false";
EOF
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || { sleep 10; apt-get update -qq; }
apt-get install -y -qq --force-yes g++-4.7 gcc-4.7 make binutils libc6-dev >/dev/null
g++-4.7 --version | head -n 1
ver=$(g++-4.7 -dumpversion)
case "$ver" in
    4.7|4.7.*) : ;;
    *) echo "error: expected g++-4.7 to be 4.7.x, got $ver" >&2; exit 1 ;;
esac

mkdir -p /work/repo
( cd /src && tar --exclude=./.git --exclude=./build -cf - . ) | ( cd /work/repo && tar -xf - )
cd /work/repo
JOBS=$(nproc 2>/dev/null || echo 2)
ARM_FLAGS="-std=gnu++0x -O2 -march=armv7-a -mfpu=neon -mfloat-abi=hard -Wall -Wextra -Werror"
make -j"$JOBS" CXX=g++-4.7 CC=gcc-4.7 AR=ar BUILD_DIR=/work/build CXXFLAGS="$ARM_FLAGS" $CARPLAY_SMOKE_TARGETS

cp /work/build/carlib_smoke /work/build/carplayd /work/build/libEntryCarPlay.so /out/
for t in $CARPLAY_SMOKE_UNITS; do
    cp "/work/build/$t" /out/
done
chmod -R a+rX /out
' > "$BUILD_LOG" 2>&1 || build_rc=$?

if [ "$build_rc" -ne 0 ]; then
    cat "$BUILD_LOG"
    echo "FAIL: ARMv7 GCC 4.7.2 build failed (exit $build_rc)" >&2
    exit 1
fi
echo "Build OK (log: $BUILD_LOG)"

# ---------------------------------------------------------------- 2. ELF & Symbol-Version check vs SYSROOT
echo
echo "== [2/3] Checking ELF attributes, DT_NEEDED, and symbol versions against $SYSROOT_ABS =="
export CARPLAY_SMOKE_SYSROOT="$SYSROOT_ABS"
export CARPLAY_SMOKE_BINDIR="$BUILD_OUT_DIR"
export CARPLAY_SMOKE_UNITS="$UNIT_LIST"

python3 -I - <<'__ABI_CHECK_PY__' > "$ABI_LOG" 2>&1
import os
import re
import subprocess
import sys

sysroot = os.environ["CARPLAY_SMOKE_SYSROOT"]
bindir = os.environ["CARPLAY_SMOKE_BINDIR"]
units = os.environ.get("CARPLAY_SMOKE_UNITS", "").split()

ALLOWED_NEEDED = {
    "libc.so.6",
    "libm.so.6",
    "libstdc++.so.6",
    "libgcc_s.so.1",
    "libpthread.so.0",
    "librt.so.1",
    "libdl.so.2",
    "ld-linux-armhf.so.3",
}

BASE_LIBS = [
    "lib/libc.so.6",
    "lib/libm.so.6",
    "lib/libpthread.so.0",
    "lib/librt.so.1",
    "lib/libdl.so.2",
    "lib/libstdc++.so.6",
    "lib/libgcc_s.so.1",
    "lib/ld-linux-armhf.so.3",
]


def run_readelf(args):
    p = subprocess.run(["readelf"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError("readelf %s failed: %s" % (" ".join(args), p.stderr))
    return p.stdout


def parse_verdef(path):
    out = run_readelf(["-W", "-V", path])
    in_verdef = False
    defs = set()
    for line in out.splitlines():
        if "Version definition section" in line:
            in_verdef = True
            continue
        if "Version needs section" in line or "Version symbols section" in line:
            in_verdef = False
            continue
        if in_verdef:
            m = re.search(r"\bName:\s*(\S+)", line)
            if m:
                defs.add(m.group(1))
    return defs


def parse_verneed(path):
    out = run_readelf(["-W", "-V", path])
    in_verneed = False
    cur_file = None
    needs = {}  # soname -> set(versions)
    for line in out.splitlines():
        if "Version needs section" in line:
            in_verneed = True
            continue
        if "Version symbols section" in line or "Version definition section" in line:
            in_verneed = False
            continue
        if in_verneed:
            fm = re.search(r"File:\s*(\S+)", line)
            if fm:
                cur_file = fm.group(1)
                needs.setdefault(cur_file, set())
                continue
            vm = re.search(r"\bName:\s*(\S+)", line)
            if vm and cur_file is not None:
                needs[cur_file].add(vm.group(1))
    return needs


def ver_tuple(name):
    m = re.search(r"_([0-9]+(?:\.[0-9]+)*)$", name)
    if not m:
        return ()
    return tuple(int(x) for x in m.group(1).split("."))


def max_ver(ver_set, prefix):
    cands = [v for v in ver_set if v.startswith(prefix) and ver_tuple(v)]
    if not cands:
        return "none"
    return max(cands, key=ver_tuple)


sysroot_defs = {}
all_sysroot_vers = set()
for rel in BASE_LIBS:
    full = os.path.join(sysroot, rel)
    if not os.path.exists(full):
        print("FAIL: missing sysroot base library %s" % full)
        sys.exit(1)
    soname = os.path.basename(rel)
    d = parse_verdef(full)
    sysroot_defs[soname] = d
    all_sysroot_vers.update(d)

print("Sysroot provided max versions: %s, %s, %s, %s" % (
    max_ver(all_sysroot_vers, "GLIBC_"),
    max_ver(all_sysroot_vers, "GLIBCXX_"),
    max_ver(all_sysroot_vers, "CXXABI_"),
    max_ver(all_sysroot_vers, "GCC_"),
))

targets = ["carlib_smoke", "carplayd", "libEntryCarPlay.so"] + units
failures = 0

for name in targets:
    path = os.path.join(bindir, name)
    if not os.path.isfile(path):
        print("FAIL: missing built binary %s" % path)
        failures += 1
        continue

    hdr = run_readelf(["-h", path])
    if "ELF32" not in hdr or "ARM" not in hdr:
        print("FAIL: %s is not ELF32 ARM" % name)
        failures += 1

    attrs = run_readelf(["-A", path])
    if "Tag_ABI_VFP_args: VFP registers" not in attrs or not re.search(r"Tag_CPU_arch:\s*v7\b", attrs):
        print("FAIL: %s is not ARMv7 hard-float" % name)
        failures += 1

    if name != "libEntryCarPlay.so":
        prog = run_readelf(["-W", "-l", path])
        if "/lib/ld-linux-armhf.so.3" not in prog:
            print("FAIL: %s missing PT_INTERP /lib/ld-linux-armhf.so.3" % name)
            failures += 1

    dyn = run_readelf(["-d", path])
    needed = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dyn)
    bad_needed = [n for n in needed if n not in ALLOWED_NEEDED]
    if bad_needed:
        print("FAIL: %s links forbidden DT_NEEDED: %s" % (name, ", ".join(bad_needed)))
        failures += 1

    verneeds = parse_verneed(path)
    req_vers = set()
    missing_vers = []
    for lib_name, vers in sorted(verneeds.items()):
        avail = sysroot_defs.get(lib_name, all_sysroot_vers)
        for v in sorted(vers):
            req_vers.add(v)
            if v not in avail:
                missing_vers.append("%s:%s" % (lib_name, v))

    if missing_vers:
        print("FAIL: %s requires symbol version(s) absent from sysroot: %s" % (name, ", ".join(missing_vers)))
        failures += 1
    else:
        print("OK   %-22s needed=[%s] max=(%s, %s, %s)" % (
            name,
            " ".join(needed),
            max_ver(req_vers, "GLIBC_"),
            max_ver(req_vers, "GLIBCXX_"),
            max_ver(req_vers, "CXXABI_"),
        ))

sys.exit(1 if failures > 0 else 0)
__ABI_CHECK_PY__
abi_rc=$?
cat "$ABI_LOG"
if [ "$abi_rc" -ne 0 ]; then
    echo "FAIL: ELF / symbol-version check failed" >&2
    exit 1
fi

# ---------------------------------------------------------------- 3. Execute under QEMU against SYSROOT
echo
echo "== [3/3] Executing ARM binaries under QEMU against $SYSROOT_ABS (LD_BIND_NOW=1) =="

run_qemu_case() {
    case_name="$1"
    shift
    out_file="$LOG_DIR/$case_name.out"
    set +e
    "$QEMU_BIN" -L "$SYSROOT_ABS" \
        -E "LD_LIBRARY_PATH=/opt/hmi/lib:/usr/local/lib:/usr/lib:/lib" \
        -E "LD_BIND_NOW=1" \
        "$@" > "$out_file" 2>&1
    rc=$?
    set -e
    cat "$out_file" >> "$RUN_LOG"
    if [ "$rc" -eq 0 ]; then
        last_line=$(grep -v '^[[:space:]]*$' "$out_file" | tail -n 1 | tr -d '\r' || true)
        printf '%-24s PASS  %s\n' "$case_name" "$last_line" | tee -a "$SUMMARY"
        return 0
    else
        cat "$out_file"
        printf '%-24s FAIL(%d)\n' "$case_name" "$rc" | tee -a "$SUMMARY"
        return 1
    fi
}

overall_rc=0

echo "--- carlib_smoke ---" | tee -a "$RUN_LOG"
if run_qemu_case "carlib_smoke" "$BUILD_OUT_DIR/carlib_smoke" --hmi-plugin "$BUILD_OUT_DIR/libEntryCarPlay.so"; then
    cat "$LOG_DIR/carlib_smoke.out"
else
    overall_rc=1
fi

echo "--- carplayd --help / --version ---" | tee -a "$RUN_LOG"
if ! run_qemu_case "carplayd_help" "$BUILD_OUT_DIR/carplayd" --help; then
    overall_rc=1
fi
if ! run_qemu_case "carplayd_version" "$BUILD_OUT_DIR/carplayd" --version; then
    overall_rc=1
fi

if [ "$RUN_UNIT_SUBSET" -eq 1 ]; then
    echo "--- ARMv7 unit test subset ---" | tee -a "$RUN_LOG"
    for t in $UNIT_LIST; do
        if ! run_qemu_case "$t" "$BUILD_OUT_DIR/$t"; then
            overall_rc=1
        fi
    done
fi

echo
echo "=== Summary ==="
cat "$SUMMARY"

if [ "$overall_rc" -ne 0 ]; then
    echo "carlib_smoke.sh: FAILED (logs in $LOG_DIR)" >&2
    exit 1
fi
echo "carlib_smoke.sh: ALL PASSED (logs in $LOG_DIR)"
