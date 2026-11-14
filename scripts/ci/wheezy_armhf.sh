#!/bin/sh
# Container entry point for the GCC 4.7.2 / ARMv7 hard-float CI job.
#
# Runs INSIDE a Debian 7 "wheezy" armhf container (debian/eol:wheezy, linux/arm/v7) executed
# through QEMU user emulation. Wheezy's armhf toolchain is the same compiler generation as the
# head unit's: g++-4.7 4.7.2-5, binutils 2.22, eglibc 2.13 (older than the car's 2.15, so any
# binary that runs here only needs symbols the car has), libstdc++.so.6.0.17.
#
#   docker run --rm --platform linux/arm/v7 \
#     -v "$PWD:/src:ro" -v "$PWD/build/ci-out:/out" \
#     --tmpfs /work:exec,size=2g \
#     debian/eol:wheezy sh /src/scripts/ci/wheezy_armhf.sh
#
# /src  read-only repository checkout
# /work build directory on tmpfs (see the readdir note below)
# /out  receives the logs (build.log, tests.log, summary.txt, per-binary *.out)
#
# Why the copy to tmpfs: 32-bit programs that use the non-LFS readdir() fail with EOVERFLOW
# under qemu-user on 64-bit ext4 hosts (directory cookies do not fit in 32 bits). Old make /
# glob code may do exactly that for $(wildcard ...). tmpfs hands out small cookies.
#
# Wheezy is end-of-life: packages come from archive.debian.org over plain HTTP and the archive
# signing keys have expired, so apt is told to accept the (no longer verifiable) archive.

set -eu

SRC=${SRC:-/src}
WORK=${WORK:-/work}
OUT=${OUT:-/out}

echo "== container: $(uname -a)"
echo "== debian_version: $(cat /etc/debian_version 2>/dev/null || echo '?')"

cat > /etc/apt/sources.list <<'EOF'
deb http://archive.debian.org/debian wheezy main
deb http://archive.debian.org/debian-security wheezy/updates main
EOF
rm -f /etc/apt/sources.list.d/*.list 2>/dev/null || true
cat > /etc/apt/apt.conf.d/99ci-eol <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
Acquire::http::Timeout "60";
APT::Get::AllowUnauthenticated "true";
APT::Install-Recommends "false";
EOF

export DEBIAN_FRONTEND=noninteractive
echo "== apt-get update"
apt-get update || { echo "apt-get update failed once, retrying in 20s"; sleep 20; apt-get update; }
echo "== apt-get install g++-4.7 gcc-4.7 make binutils"
apt-get install -y --force-yes g++-4.7 gcc-4.7 make binutils libc6-dev
echo "== installed versions"
dpkg-query -W -f='${Package} ${Version}\n' g++-4.7 gcc-4.7 libstdc++6-4.7-dev libc6 libc6-dev binutils make

echo "== copying $SRC -> $WORK (tmpfs)"
mkdir -p "$WORK/repo"
( cd "$SRC" && tar --exclude=./.git --exclude=./build -cf - . ) | ( cd "$WORK/repo" && tar -xf - )

mkdir -p "$OUT"
rc=0
(
    cd "$WORK/repo"
    CXX=g++-4.7 CC=gcc-4.7 AR=ar LOG_DIR="$OUT" sh scripts/ci/build_and_test.sh armv7-gcc47
) || rc=$?
# Logs are written to /out by the host user's bind mount; make them readable for the upload step.
chmod -R a+rwX "$OUT" 2>/dev/null || true
exit $rc
