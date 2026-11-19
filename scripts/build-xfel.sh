#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Build xfel (https://github.com/xboot/xfel, MIT) from source into
# out/tools/xfel, with the USB bulk-transfer timeout raised from 10 s to 60 s:
# bt0's FEL entry 1 (clocks, PMIC, DRAM training) keeps the mask ROM busy for
# about 7 s, longer with DRAM tracing. Needs gcc, make, pkgconf and
# libusb1-devel. No xfel binary is part of this repository.
#
# On the host that runs scripts/fel-boot.sh, either run xfel as root (the
# default SUDO=sudo there) or install xfel's udev rule (out/tools/xfel-src/99-xfel.rules)
# into /etc/udev/rules.d and use SUDO= .
set -euo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
SRC=$TOP/out/tools/xfel-src
XFEL_TAG=v1.4.0
XFEL_COMMIT=445e8aefe6914c85817cc9bd1d201629364b0ec6

if [ ! -d "$SRC/.git" ]; then
    git clone -q --depth 1 --branch "$XFEL_TAG" https://github.com/xboot/xfel.git "$SRC"
fi
[ "$(git -C "$SRC" rev-parse HEAD)" = "$XFEL_COMMIT" ] || {
    echo "build-xfel: $SRC is not xfel $XFEL_TAG ($XFEL_COMMIT)" >&2
    exit 1
}
# Never build in the cache: xfel's Makefile includes untracked *.c files.
BUILD=$(mktemp -d "$TOP/out/tools/.xfel-build.XXXXXXXX")
trap 'rm -rf -- "$BUILD"' EXIT
git clone -q --no-local --no-checkout "$SRC" "$BUILD"
SRC=$BUILD
git -C "$SRC" checkout -q --detach "$XFEL_COMMIT"
git -C "$SRC" apply --unidiff-zero "$TOP/scripts/xfel-port-select.patch"
grep -c '&bytes, 10000);' "$SRC/fel.c" | grep -qx 2 || {
    echo "build-xfel: fel.c does not have the two 10 s bulk transfers this script patches" >&2
    exit 1
}
sed -i 's/&bytes, 10000);/\&bytes, 60000);/' "$SRC/fel.c"
make -C "$SRC" -s "CFLAGS=-g -Wall -O3 -ffile-prefix-map=$SRC=/xfel"
python3 -I "$TOP/scripts/fel-tools.py" record-xfel "$SRC" "$XFEL_COMMIT"
echo "build-xfel: $TOP/out/tools/xfel (xfel $XFEL_TAG, port selector, 60 s USB timeout)"
