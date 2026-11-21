## Summary

<!-- Briefly describe what this PR changes and why. Link any related issue. -->

## Verification

- [ ] Host build and unit tests pass (`sh scripts/ci/build_and_test.sh host`)
- [ ] ARMv7 GCC 4.7.2 build and tests pass (`scripts/ci/wheezy_armhf.sh` / CI `armv7-gcc47`)
- [ ] Repository content check passes (`sh scripts/ci/check_repo_content.sh`)
- [ ] Vehicle / head-unit testing (if applicable, state car model, `/etc/version`, and what was tested; otherwise state `Host / CI only`)

## Checklist

- [ ] No proprietary or sysroot files added (`*.so`, `*.so.*`, `*.ko`, archives, keys/certs, `sysroot/`)
- [ ] No personal or machine-specific data added (VIN, MAC addresses, serials, local `/home/...` paths, emails, passwords)
- [ ] Existing documentation and safe-mode defaults (`wireless=0`, `wired=0`, `ddp_handoff=0`, `detach_usbfs_driver=0`) remain accurate and intact
