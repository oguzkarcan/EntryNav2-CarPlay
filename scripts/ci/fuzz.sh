#!/bin/sh
# Opt-in libFuzzer + ASan + UBSan build and run driver for EntryNav2-CarPlay parsers.
# Not invoked by the default GCC 4.7 build or scripts/ci/build_and_test.sh.
#
# Usage:
#   sh scripts/ci/fuzz.sh
#   FUZZ_BUILD_ONLY=1 sh scripts/ci/fuzz.sh
#   FUZZ_TARGETS="fuzz_iap2_link fuzz_rtsp_message" FUZZ_SECONDS=120 sh scripts/ci/fuzz.sh

set -eu

CC_BIN="${CC:-clang}"
CXX_BIN="${CXX:-clang++}"
BUILD_DIR="${FUZZ_BUILD_DIR:-build/fuzz}"
CORPUS_ROOT="${FUZZ_CORPUS_DIR:-tests/fuzz/corpus}"
ARTIFACT_ROOT="${FUZZ_ARTIFACT_DIR:-build/fuzz/artifacts}"
LOG_ROOT="${FUZZ_LOG_DIR:-build/fuzz/logs}"
FUZZ_SECONDS="${FUZZ_SECONDS:-120}"
FUZZ_MAX_LEN="${FUZZ_MAX_LEN:-65536}"
FUZZ_JOBS="${FUZZ_JOBS:-1}"
FUZZ_BUILD_ONLY="${FUZZ_BUILD_ONLY:-0}"

ALL_TARGETS="fuzz_iap2_link fuzz_iap2_session fuzz_cdc_ncm fuzz_usb_descriptors fuzz_rtsp_message fuzz_bplist_codec fuzz_tlv8_codec fuzz_sdp_record fuzz_dnssd_txt fuzz_event_channel fuzz_audio_rtp fuzz_screen_stream fuzz_pairing_srp"
TARGETS="${FUZZ_TARGETS:-$ALL_TARGETS}"

COMMON_FLAGS="-O1 -g -fno-omit-frame-pointer -Wall -Wextra -Werror -fsanitize=fuzzer-no-link,address,undefined -Iinclude -Ithird_party/monocypher"
CFLAGS_FUZZ="$COMMON_FLAGS -std=gnu99"
CXXFLAGS_FUZZ="$COMMON_FLAGS -std=gnu++0x"
LINK_FUZZ="-O1 -g -fno-omit-frame-pointer -Wall -Wextra -Werror -std=gnu++0x -fsanitize=fuzzer,address,undefined -Iinclude -Ithird_party/monocypher"

mkdir -p "$BUILD_DIR/obj/src/core" "$BUILD_DIR/obj/third_party/monocypher" "$ARTIFACT_ROOT" "$LOG_ROOT"

if [ ! -d "$CORPUS_ROOT/iap2_link" ]; then
    python3 tests/fuzz/gen_seeds.py
fi

echo "==> Compiling core + monocypher with $CXX_BIN / $CC_BIN (fuzzer-no-link,address,undefined)"
CORE_OBJS=""
for src in src/core/*.cpp; do
    obj="$BUILD_DIR/obj/${src%.cpp}.o"
    "$CXX_BIN" $CXXFLAGS_FUZZ -c "$src" -o "$obj"
    CORE_OBJS="$CORE_OBJS $obj"
done

for src in third_party/monocypher/*.c; do
    obj="$BUILD_DIR/obj/${src%.c}.o"
    "$CC_BIN" $CFLAGS_FUZZ -c "$src" -o "$obj"
    CORE_OBJS="$CORE_OBJS $obj"
done

echo "==> Linking libFuzzer harnesses into $BUILD_DIR"
for target in $TARGETS; do
    src="tests/fuzz/${target}.cpp"
    if [ ! -f "$src" ]; then
        echo "ERROR: missing fuzz harness $src" >&2
        exit 1
    fi
    "$CXX_BIN" $LINK_FUZZ "$src" $CORE_OBJS -o "$BUILD_DIR/$target"
done

if [ "$FUZZ_BUILD_ONLY" = "1" ]; then
    echo "==> Built all requested fuzz targets cleanly in $BUILD_DIR"
    exit 0
fi

echo "==> Running libFuzzer targets (FUZZ_SECONDS=$FUZZ_SECONDS, FUZZ_MAX_LEN=$FUZZ_MAX_LEN)"
for target in $TARGETS; do
    corpus_name="${target#fuzz_}"
    seed_dir="$CORPUS_ROOT/$corpus_name"
    work_corpus="$BUILD_DIR/corpus/$corpus_name"
    artifact_dir="$ARTIFACT_ROOT/$target"
    log_file="$LOG_ROOT/${target}.log"
    mkdir -p "$work_corpus" "$artifact_dir"
    if [ -d "$seed_dir" ]; then
        cp -f "$seed_dir"/* "$work_corpus"/ 2>/dev/null || true
    fi

    JOBS_FLAG=""
    if [ "$FUZZ_JOBS" -gt 1 ] 2>/dev/null; then
        JOBS_FLAG="-jobs=$FUZZ_JOBS"
    fi

    echo "=== Running $target (${FUZZ_SECONDS}s) ==="
    if ! ASAN_OPTIONS="detect_leaks=1:abort_on_error=1" \
         UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
         "$BUILD_DIR/$target" \
         "$work_corpus" \
         -artifact_prefix="$artifact_dir/" \
         -max_total_time="$FUZZ_SECONDS" \
         -max_len="$FUZZ_MAX_LEN" \
         $JOBS_FLAG \
         -print_final_stats=1 \
         >"$log_file" 2>&1; then
        echo "FAIL: $target exited non-zero (see $log_file)" >&2
        tail -n 40 "$log_file" >&2
        exit 1
    fi
    tail -n 12 "$log_file"
done

echo "==> All requested libFuzzer targets completed cleanly"
