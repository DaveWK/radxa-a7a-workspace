#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Fetch the closed vendor input the optional measurement builds read, from
# its public source, into vendor/ (gitignored; never committed, never
# redistributed). The default build reads nothing from a vendor; this is a
# measurement build only.
#
#   vendor/dramlib/libdram   Allwinner's A733 DRAM library object from the
#                            Tina SDK (gitlab.com/tina5.0_aiot/lichee/dramlib,
#                            sun60iw2p1/spl_libdram/libdram at the commit
#                            below), checked by SHA-256.
#
# What reads it (all measurement builds):
#   - VENDOR_DRAM=yes (and the FEL bt0 with FEL_DRAM=dramlib) links it: DRAM
#     init through the vendor library;
#   - VENDOR_DRAM=phyfw extracts the DRAM PHY's training firmware and PIE
#     images from it as data, by symbol name and hash.
set -euo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
DIR=$TOP/vendor/dramlib
DRAMLIB_COMMIT=35e84c835b26f8d933e50299869657365e996363
DRAMLIB_PATH=sun60iw2p1/spl_libdram/libdram
DRAMLIB_SHA256=d05bc328619cb64f4d273f8d83670f59d085d3758a0968eb4a7f6328f6c42c8e
URL=https://gitlab.com/tina5.0_aiot/lichee/dramlib/-/raw/$DRAMLIB_COMMIT/$DRAMLIB_PATH

mkdir -p "$DIR"
out=$DIR/libdram
if [ -f "$out" ] && echo "$DRAMLIB_SHA256  $out" | sha256sum -c --quiet 2>/dev/null; then
    echo "fetch-vendor: $out present (sha256 ok)"
    exit 0
fi
# aria2c downloads into a fresh directory; the SHA-256 check still gates the
# move into place.
fetch=$(mktemp -d "$DIR/.fetch.XXXXXX")
trap 'rm -rf "$fetch"' EXIT
aria2c --dir="$fetch" --out=libdram.part --allow-overwrite=true \
    --auto-file-renaming=false --max-tries=3 --retry-wait=2 \
    --connect-timeout=30 --timeout=60 --summary-interval=0 "$URL"
echo "$DRAMLIB_SHA256  $fetch/libdram.part" | sha256sum -c --quiet || {
    echo "fetch-vendor: $URL does not have the expected sha256" >&2
    exit 1
}
mv -f "$fetch/libdram.part" "$out"
echo "fetch-vendor: $out (commit ${DRAMLIB_COMMIT:0:12}, sha256 ok)"
