# Build & Test Guide

How to build and test EntryNav2-CarPlay on a PC, how CI checks the real target compiler generation, and how to build for the car (`HU_ENTRYNAV2`, Linux 3.12 ARMv7 Cortex-A15 `neon`/`vfpv4` hard-float, eglibc 2.15, `libstdc++.so.6.0.17` = GCC 4.7 ABI).

All code must stay **GCC 4.7.2 `-std=gnu++0x`** compatible and warning-clean with `-Wall -Wextra -Werror` (see `CLAUDE.md` §3).

## 1. Windows host tests (w64devkit)

No system-wide compiler is needed; the portable toolchain lives in `..\EntryNav2-CarPlay-Assets\tools`.

```powershell
.\scripts\test_host.cmd                      # clean, build, run every test binary, clean
# or by hand:
$tools = "C:\Users\Acer\Documents\EntryNav2-CarPlay-Assets\tools"
$env:PATH = "$tools\w64devkit\bin;$tools\mingit\cmd;" + $env:PATH
make clean; make test-host BIN_EXT=.exe
```

## 2. Linux / WSL host tests

Any distribution with `g++`, `gcc`, `ar` and GNU `make`:

```sh
make test-host                               # builds build/host/test_* and runs them all
make test-host CXX=clang++ CC=clang          # optional second compiler
sh scripts/ci/build_and_test.sh host         # same, with make -k, logs and a per-binary summary
```

`scripts/ci/build_and_test.sh` writes `build.log`, `tests.log`, `summary.txt` and one `<test>.out` per binary to `build/ci-logs-<profile>/`. It builds with `make -k`, so a single run lists every compile error before failing.

## 3. How CI verifies GCC 4.7.2 / ARMv7

`.github/workflows/ci.yml` runs on every push / pull request to `main` (and manually):

| Job | What it proves |
| --- | --- |
| `host-linux` | `make test-host` with Ubuntu's current `g++` (blocking) and `clang++` (advisory). |
| `armv7-gcc47` | The whole code base compiles with **GCC 4.7.2 for ARMv7 hard-float** with `-std=gnu++0x -O2 -march=armv7-a -mfpu=neon -mfloat-abi=hard -Wall -Wextra -Werror`, and **every test binary runs and passes** on ARM. |
| `no-proprietary-files` | No `*.so`, `*.so.*`, `*.ko`, `*.tar.gz`, keys/certificates, `sysroot/` directory or file over 2 MB is tracked (`scripts/ci/check_repo_content.sh`). |

The ARM job runs a **Debian 7 "wheezy" armhf** container (`debian/eol:wheezy`, platform `linux/arm/v7`) through QEMU user emulation and compiles natively inside it (`scripts/ci/wheezy_armhf.sh`). Wheezy's armhf toolchain is the car's compiler generation: `g++-4.7` **4.7.2-5**, binutils 2.22, eglibc 2.13, `libstdc++.so.6.0.17`. Note that wheezy's *default* `g++` is 4.6, so the job explicitly uses `g++-4.7` / `gcc-4.7` and the script fails if `-dumpversion` is not `4.7.x` or the target is not `arm*-linux-gnueabihf`. Packages come from `archive.debian.org` (end-of-life archive, expired signing keys, so apt is configured to accept it).

After the build the script also checks every ARM binary: hard-float (`Tag_ABI_VFP_args: VFP registers`), `DT_NEEDED` limited to libc / libm / libstdc++ / libgcc_s / libpthread / librt / libdl, and symbol versions no newer than `GLIBC_2.15`, `GLIBCXX_3.4.17`, `CXXABI_1.3.6` (what the head unit provides). Logs are uploaded as the `armv7-gcc47-logs` artifact and the per-binary summary appears on the run page.

Reproduce the ARM job on any Linux box with Docker:

```sh
docker run --privileged --rm tonistiigi/binfmt --install arm     # once per boot, registers qemu-arm
docker run --rm --platform linux/arm/v7 \
  -v "$PWD:/src:ro" -v "$PWD/build/ci-out:/out" --tmpfs /work:exec,size=3g \
  debian/eol:wheezy sh /src/scripts/ci/wheezy_armhf.sh
```

The build happens on tmpfs because 32-bit programs using the old `readdir()` can fail with `EOVERFLOW` under qemu-user on 64-bit ext4 hosts.

The reference project's Ubuntu 12.10 cross-toolchain image is **not** used: `ubuntu:12.10` exists on Docker Hub only as a manifest schema v1 image, which current Docker refuses to pull. If you do have an `arm-linux-gnueabihf-g++` 4.7 cross compiler, the same script works:

```sh
CXX=arm-linux-gnueabihf-g++ CC=arm-linux-gnueabihf-gcc AR=arm-linux-gnueabihf-ar \
RUNNER="qemu-arm -L /usr/arm-linux-gnueabihf" sh scripts/ci/build_and_test.sh armv7-gcc47
```

## 4. Vehicle libraries: dlopen policy

Every vehicle library (`libxsvideo`, `libasound`, `libvmostclient`, `libilm*`, `libdns_sd`, …) is loaded at run time with `dlopen()` / `dlsym()` through hand-written prototypes. The daemon links **only** against libc, libstdc++, libm, libgcc_s, libpthread, librt and libdl. Consequences:

- The whole project builds without any copy of the car's system, so CI can build and test everything.
- No BMW or supplier header or library is needed in the repository.
- A missing or different vehicle library is a run-time error the daemon can report, not a link failure.

The CI `DT_NEEDED` check enforces this for every ARM binary.

## 5. Building for the car (local, needs Linux)

The car's system libraries (the "sysroot") are proprietary BMW / supplier software. A copy exists only on the development PC:

```text
C:\Users\Acer\Documents\EntryNav2-CarPlay-Assets\sysroot\entrynav2-sysroot-202402191339.tar.gz
```

Thanks to the dlopen policy, the sysroot is **not needed to build**. It is only useful to run binaries against the car's real libc / libstdc++ (and later the vehicle libraries) under QEMU before going to the car.

1. Extract the tarball **on a Linux filesystem** (WSL ext4 home, a Linux box), **never on NTFS** (`/mnt/c/...`): the sysroot is full of symlinks that NTFS / Windows tools break silently. Keep it outside the repository:
   ```sh
   mkdir -p ~/entrynav2/sysroot
   tar -xzf /mnt/c/Users/Acer/Documents/EntryNav2-CarPlay-Assets/sysroot/entrynav2-sysroot-202402191339.tar.gz -C ~/entrynav2/sysroot
   ```
2. Build with GCC 4.7 exactly as CI does, mounting the sysroot **read-only** if a step needs it:
   ```sh
   docker run --rm --platform linux/arm/v7 \
     -v "$PWD:/src:ro" -v "$PWD/build/ci-out:/out" --tmpfs /work:exec,size=3g \
     -v "$HOME/entrynav2/sysroot:/sysroot:ro" \
     debian/eol:wheezy sh /src/scripts/ci/wheezy_armhf.sh
   ```
3. Optional: run a built ARM binary against the car's own libraries with `qemu-arm -L ~/entrynav2/sysroot <binary>` (from an x86 Linux shell with `qemu-user` installed).

4. Deployable targets and vehicle install layout (`F3-P7`):
   ```sh
   make daemon                                 # builds <BUILD_DIR>/carplayd
   make hmiapp                                 # builds <BUILD_DIR>/libEntryCarPlay.so
   make install-layout                         # stages the full head-unit rootfs tree under <BUILD_DIR>/install-root:
   #   /opt/carplay/carplayd
   #   /opt/hmi/data/ro/Plugins/EntryCarPlay/EntryCarPlay
   #   /opt/hmi/data/ro/Plugins/EntryCarPlay/libEntryCarPlay.so
   #   /opt/hmi/data/ro/Plugins/EntryCarPlay/EntryCarPlay.manifest
   #   /opt/hmi/data/ro/Plugins/EntryCarPlay/EntryCarPlay.xml
   #   /var/local/data/CarPlay/
   ```

## 6. Hard rule: the sysroot never leaves the PC

- **Never commit** the sysroot, the tarball, or any file taken from it (`*.so`, `*.so.*`, `*.ko`, headers, firmware) — not even temporarily, not in a branch. `no-proprietary-files` fails the build if one appears; if it ever happens, the file must also be removed from history.
- **Never upload** it anywhere: not to CI (no artifacts, no caches, no secrets, no download URLs), not to issues, releases or any file host.
- **Never extract it on NTFS** or inside the repository directory.
