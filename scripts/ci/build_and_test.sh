#!/bin/sh
# Build every test binary and run it, with diagnostics meant for CI logs.
#
# Usage:  scripts/ci/build_and_test.sh [host|armv7-gcc47]
#
#   host         Makefile defaults (CXX=g++ unless overridden). Any Linux box / WSL.
#   armv7-gcc47  GCC 4.7.x, -march=armv7-a -mfpu=neon -mfloat-abi=hard. Fails unless the
#                compiler really is 4.7.x. Works natively inside an armhf GCC 4.7 environment
#                (the CI uses Debian 7 "wheezy" armhf under QEMU, see scripts/ci/wheezy_armhf.sh),
#                or with a cross compiler: CXX=arm-linux-gnueabihf-g++ CC=arm-linux-gnueabihf-gcc
#                AR=arm-linux-gnueabihf-ar RUNNER="qemu-arm -L /usr/arm-linux-gnueabihf".
#
# Environment overrides (all optional):
#   CXX CC AR        compilers / archiver passed to make
#   CXXFLAGS CFLAGS  replace the profile's flags entirely
#   BUILD_DIR        make BUILD_DIR (default build/ci-<profile>)
#   BIN_EXT          test binary suffix passed to make (".exe" on Windows/w64devkit)
#   JOBS             parallel make jobs (default: nproc)
#   LOG_DIR          where build.log / tests.log / summary.txt go (default build/ci-logs-<profile>)
#   RUNNER           command prefix used to execute test binaries (e.g. qemu-arm -L <sysroot>)
#   TEST_TIMEOUT     seconds per test binary when `timeout` exists (default 3600)
#   EXPECT_GCC       required `-dumpversion` prefix (armv7-gcc47 default: 4.7)
#   ALLOWED_NEEDED   space-separated DT_NEEDED sonames allowed in ARM binaries
#
# The build runs with `make -k` so ONE run reports every compile error; the script still
# fails at the end if anything failed to build or any test binary failed.

set -eu

PROFILE=${1:-host}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

case "$PROFILE" in
    host)
        : "${BUILD_DIR:=build/ci-host}"
        ;;
    armv7-gcc47)
        : "${BUILD_DIR:=build/ci-armv7-gcc47}"
        if [ -z "${CXX:-}" ]; then
            if command -v g++-4.7 >/dev/null 2>&1; then CXX=g++-4.7; else CXX=arm-linux-gnueabihf-g++; fi
        fi
        if [ -z "${CC:-}" ]; then
            case "$CXX" in
                *g++-4.7) CC=$(echo "$CXX" | sed 's/g++-4\.7$/gcc-4.7/') ;;
                *g++) CC=$(echo "$CXX" | sed 's/g++$/gcc/') ;;
                *) CC=gcc ;;
            esac
        fi
        if [ -z "${AR:-}" ]; then
            case "$CXX" in
                arm-linux-gnueabihf-*) AR=arm-linux-gnueabihf-ar ;;
                *) AR=ar ;;
            esac
        fi
        ARM_FLAGS="-march=armv7-a -mfpu=neon -mfloat-abi=hard"
        : "${CXXFLAGS:=-std=gnu++0x -O2 $ARM_FLAGS -Wall -Wextra -Werror}"
        : "${CFLAGS:=-std=c99 -O2 $ARM_FLAGS -Wall -Wextra}"
        : "${EXPECT_GCC:=4.7}"
        ;;
    *)
        echo "usage: $0 [host|armv7-gcc47]" >&2
        exit 2
        ;;
esac

: "${CXX:=g++}"
: "${CC:=gcc}"
: "${AR:=ar}"
: "${RUNNER:=}"
: "${BIN_EXT:=}"
: "${TEST_TIMEOUT:=3600}"
: "${LOG_DIR:=build/ci-logs-$PROFILE}"
if [ -z "${JOBS:-}" ]; then
    JOBS=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
fi
: "${ALLOWED_NEEDED:=libc.so.6 libm.so.6 libstdc++.so.6 libgcc_s.so.1 libpthread.so.0 librt.so.1 libdl.so.2 ld-linux-armhf.so.3}"

mkdir -p "$LOG_DIR"
BUILD_LOG="$LOG_DIR/build.log"
TEST_LOG="$LOG_DIR/tests.log"
SUMMARY="$LOG_DIR/summary.txt"
: > "$BUILD_LOG"
: > "$TEST_LOG"
: > "$SUMMARY"

section() {
    echo
    echo "=================================================================="
    echo "== $*"
    echo "=================================================================="
}

# ---------------------------------------------------------------- environment
section "Environment ($PROFILE)"
echo "uname -a     : $(uname -a)"
echo "uname -m     : $(uname -m)"
if [ -r /etc/debian_version ]; then echo "debian       : $(cat /etc/debian_version)"; fi
if [ -r /etc/os-release ]; then echo "os-release   : $(grep '^PRETTY_NAME=' /etc/os-release || true)"; fi
echo "ldd --version: $(ldd --version 2>&1 | head -n 1 || true)"
echo "make         : $(make --version 2>&1 | head -n 1)"
echo "CXX          : $CXX ($(command -v "$CXX" || echo 'NOT FOUND'))"
echo "CC           : $CC ($(command -v "$CC" || echo 'NOT FOUND'))"
echo "AR           : $AR"
echo "BUILD_DIR    : $BUILD_DIR"
echo "BIN_EXT      : ${BIN_EXT:-<none>}"
echo "CXXFLAGS     : ${CXXFLAGS:-<Makefile default>}"
echo "CFLAGS       : ${CFLAGS:-<Makefile default>}"
echo "RUNNER       : ${RUNNER:-<none>}"
echo "JOBS         : $JOBS"
echo
"$CXX" --version
echo "$CXX -dumpversion : $("$CXX" -dumpversion)"
echo "$CXX -dumpmachine : $("$CXX" -dumpmachine)"
"$CC" --version | head -n 1

if [ -n "${EXPECT_GCC:-}" ]; then
    ver=$("$CXX" -dumpversion)
    cver=$("$CC" -dumpversion)
    case "$ver" in
        "$EXPECT_GCC"|"$EXPECT_GCC".*) echo "compiler check: $CXX is $ver (expected $EXPECT_GCC.x) OK" ;;
        *) echo "::error::compiler check FAILED: $CXX -dumpversion = $ver, expected $EXPECT_GCC.x"; exit 1 ;;
    esac
    case "$cver" in
        "$EXPECT_GCC"|"$EXPECT_GCC".*) : ;;
        *) echo "::error::compiler check FAILED: $CC -dumpversion = $cver, expected $EXPECT_GCC.x"; exit 1 ;;
    esac
    machine=$("$CXX" -dumpmachine)
    case "$machine" in
        arm*-linux-gnueabihf) echo "target check  : $machine OK" ;;
        *) echo "::error::target check FAILED: $CXX -dumpmachine = $machine, expected arm*-linux-gnueabihf"; exit 1 ;;
    esac
fi

# ---------------------------------------------------------------- build
section "Build (make -k: every error is reported before failing)"
rm -rf "$BUILD_DIR"

set -- CXX="$CXX" CC="$CC" AR="$AR" BUILD_DIR="$BUILD_DIR" BIN_EXT="$BIN_EXT"
if [ -n "${CXXFLAGS:-}" ]; then set -- "$@" CXXFLAGS="$CXXFLAGS"; fi
if [ -n "${CFLAGS:-}" ]; then set -- "$@" CFLAGS="$CFLAGS"; fi
echo "+ make -k -j$JOBS $* tests"

# No pipefail in POSIX sh: carry make's exit code out of the pipeline through a file.
RC_FILE="$LOG_DIR/.make_rc"
{ make -k -j"$JOBS" "$@" tests; echo $? > "$RC_FILE"; } 2>&1 | tee "$BUILD_LOG"
BUILD_RC=$(cat "$RC_FILE")
rm -f "$RC_FILE"

nerr=$(grep -c 'error:' "$BUILD_LOG" || true)
nwarn=$(grep -c 'warning:' "$BUILD_LOG" || true)
echo
echo "build: make exit code $BUILD_RC, $nerr 'error:' lines, $nwarn 'warning:' lines (full log: $BUILD_LOG)"
if [ "$nerr" -gt 0 ]; then
    section "All compiler errors (deduplicated)"
    grep 'error:' "$BUILD_LOG" | sort | uniq
fi

# Highest dotted version in stdin (numeric per component).
max_version() {
    sort -u -t. -k1,1n -k2,2n -k3,3n | tail -n 1
}

# True if version $1 <= version $2.
version_le() {
    [ "$(printf '%s\n%s\n' "$1" "$2" | max_version)" = "$2" ]
}

# ---------------------------------------------------------------- binary checks (ARM only)
ABI_RC=0
if [ "$PROFILE" = "armv7-gcc47" ]; then
    section "ARM binary checks (ELF attributes, DT_NEEDED, symbol versions)"
    READELF=readelf
    OBJDUMP=objdump
    case "$CXX" in
        arm-linux-gnueabihf-*) READELF=arm-linux-gnueabihf-readelf; OBJDUMP=arm-linux-gnueabihf-objdump ;;
    esac
    for src in tests/test_*.cpp; do
        [ -e "$src" ] || continue
        name=$(basename "$src" .cpp)
        bin="$BUILD_DIR/$name$BIN_EXT"
        [ -f "$bin" ] || continue
        echo "--- $bin"
        "$READELF" -h "$bin" | grep -E 'Class|Machine|Flags' || true
        "$READELF" -A "$bin" | grep -E 'Tag_CPU_name|Tag_CPU_arch:|Tag_FP_arch|Tag_Advanced_SIMD_arch|Tag_ABI_VFP_args' || true
        needed=$("$READELF" -d "$bin" | sed -n 's/.*(NEEDED).*\[\(.*\)\].*/\1/p' | tr '\n' ' ')
        echo "NEEDED: $needed"
        for lib in $needed; do
            case " $ALLOWED_NEEDED " in
                *" $lib "*) : ;;
                *) echo "::error::$bin links against $lib (not allowed: vehicle libraries must be dlopen()ed)"; ABI_RC=1 ;;
            esac
        done
        if ! "$READELF" -A "$bin" | grep -q 'Tag_ABI_VFP_args: VFP registers'; then
            echo "::error::$bin is not hard-float (Tag_ABI_VFP_args: VFP registers missing)"; ABI_RC=1
        fi
        # The head unit has eglibc 2.15 and libstdc++.so.6.0.17 (GLIBCXX_3.4.17, CXXABI_1.3.6).
        dynsyms=$("$OBJDUMP" -T "$bin" || true)
        maxglibc=$(echo "$dynsyms" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | max_version || true)
        maxcxx=$(echo "$dynsyms" | grep -o 'GLIBCXX_[0-9][0-9.]*' | sed 's/GLIBCXX_//' | max_version || true)
        maxabi=$(echo "$dynsyms" | grep -o 'CXXABI_[0-9][0-9.]*' | sed 's/CXXABI_//' | max_version || true)
        echo "max symbol versions: GLIBC_${maxglibc:-none} GLIBCXX_${maxcxx:-none} CXXABI_${maxabi:-none}"
        if [ -n "$maxglibc" ] && ! version_le "$maxglibc" 2.15; then
            echo "::error::$bin needs GLIBC_$maxglibc (> 2.15 on the head unit)"; ABI_RC=1
        fi
        if [ -n "$maxcxx" ] && ! version_le "$maxcxx" 3.4.17; then
            echo "::error::$bin needs GLIBCXX_$maxcxx (> 3.4.17 on the head unit)"; ABI_RC=1
        fi
        if [ -n "$maxabi" ] && ! version_le "$maxabi" 1.3.6; then
            echo "::error::$bin needs CXXABI_$maxabi (> 1.3.6 on the head unit)"; ABI_RC=1
        fi
    done
fi

# ---------------------------------------------------------------- tests
section "Run test binaries"
TIMEOUT_CMD=
if command -v timeout >/dev/null 2>&1; then TIMEOUT_CMD="timeout $TEST_TIMEOUT"; fi

total=0
passed=0
failed=0
missing=0
printf '%-28s %-8s %8s  %s\n' "binary" "result" "seconds" "harness summary" >> "$SUMMARY"
for src in tests/test_*.cpp; do
    [ -e "$src" ] || continue
    name=$(basename "$src" .cpp)
    bin="$BUILD_DIR/$name$BIN_EXT"
    total=$((total + 1))
    if [ ! -f "$bin" ]; then
        echo "==> $bin: MISSING (did not build)"
        printf '%-28s %-8s %8s  %s\n' "$name" "MISSING" "-" "build failed" >> "$SUMMARY"
        missing=$((missing + 1))
        continue
    fi
    echo "==> ${RUNNER:+$RUNNER }$bin" | tee -a "$TEST_LOG"
    out="$LOG_DIR/$name.out"
    start=$(date +%s)
    set +e
    # shellcheck disable=SC2086  # RUNNER / TIMEOUT_CMD are intentionally word-split
    $TIMEOUT_CMD $RUNNER "./$bin" > "$out" 2>&1
    rc=$?
    set -e
    end=$(date +%s)
    cat "$out"
    cat "$out" >> "$TEST_LOG"
    line=$(grep -E '^test_[A-Za-z0-9_]*: [0-9]+/[0-9]+ passed' "$out" | tail -n 1 || true)
    if [ -z "$line" ]; then
        # Binaries that predate tests/test_support.hpp: show their last non-empty output line.
        line=$(grep -v '^[[:space:]]*$' "$out" | tail -n 1 | tr -d '\r' || true)
    fi
    if [ "$rc" -eq 0 ]; then
        result=PASS
        passed=$((passed + 1))
    else
        if [ "$rc" -eq 124 ] && [ -n "$TIMEOUT_CMD" ]; then result=TIMEOUT; else result="FAIL($rc)"; fi
        failed=$((failed + 1))
    fi
    printf '%-28s %-8s %8s  %s\n' "$name" "$result" "$((end - start))" "${line:-<no summary line>}" >> "$SUMMARY"
done

{
    echo
    echo "binaries: $total, passed: $passed, failed: $failed, missing: $missing; make exit: $BUILD_RC; ARM checks: $ABI_RC"
} >> "$SUMMARY"
section "Summary ($PROFILE, $CXX $("$CXX" -dumpversion))"
cat "$SUMMARY"

if [ "$total" -eq 0 ]; then
    echo "::error::no tests/test_*.cpp found"
    exit 1
fi
if [ "$BUILD_RC" -ne 0 ] || [ "$failed" -ne 0 ] || [ "$missing" -ne 0 ] || [ "$ABI_RC" -ne 0 ]; then
    echo "::error::$PROFILE: build or tests FAILED (see summary above and $LOG_DIR)"
    exit 1
fi
echo "$PROFILE: all $total test binaries built and passed"
