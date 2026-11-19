#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Boot the Radxa Cubie A7A over USB FEL, without its SD card slot.
#
#   scripts/fel-boot.sh <image dir>
#
# The image dir is a `make fel-image` output (out/fel): bt0-fel.bin (bt0
# feature fel, linked at 0x90000) and the SD image firmware.bin +
# firmware.seek, whose boot layout table names oreboot main and the EDK2 FD.
# The board must be in FEL (USB 1f3a:efe8 on its USB-C): with no bootable SD
# card the mask ROM falls back to FEL by itself.
#
# Steps: check the FEL device is an A733; clear the mailbox (0xdf000) and
# write bt0-fel.bin to 0x90000; `xfel exec 0x90040` (entry 1: clocks, PMIC,
# DRAM, CPU boost, ~7 s, then back to FEL); check the mailbox; write the
# layout table frame to 0xdf200 and each image to its load address in DRAM,
# every write verified by reading it back (sha256); `xfel exec 0x90044`
# (entry 2: bt0 checks the table and the images' CRCs and warm-resets into
# main, which starts EDK2; FEL does not come back). See bt0/src/fel.rs.
#
# The A733 mask ROM answers `exec` before the code it starts has finished
# (its USB runs on interrupts), so the result of each entry comes from the
# mailbox: a read waits while bt0 runs with interrupts masked, and after the
# hand-over to main nothing answers any more.
#
# Environment:
#   XFEL   xfel binary (default: xfel). Upstream xfel waits 10 s for a FEL
#          call to return; entry 1 takes ~7 s, so use a build with a 60 s USB
#          timeout: scripts/build-xfel.sh (out/tools/xfel, what make fel-boot
#          uses).
#   SUDO   prefix for xfel (default: sudo; empty if the udev rule grants
#          access).
#   EXPECT_MODE / EXPECT_PROFILE   expected build record mode and profile
#          (default: blobfree and ${DRAM_MHZ:-1200}).
#
# The image dir is a `make fel-image` output (out/fel/<mode>-<mhz>/):
# bt0-fel.bin (bt0 feature fel, linked at 0x90000), firmware.bin +
# firmware.seek, whose boot layout table names oreboot main and the EDK2 FD,
# and build-manifest.json. fel-boot copies the bundle into a private staging
# directory under out/ (mode 0700), checks the copies against the local record with
# scripts/fel-check.py before any USB access, and passes only the staged paths
# to xfel. A dramlib or phyfw bundle is a measurement build: it needs
# FEL_MEASUREMENT_AUTH=<file> naming this bt0's digest and a human
# authorization reference.
#
# No board access beyond FEL: nothing here touches an SD card or SPI NOR.
set -euo pipefail

BT0_BASE=0x90000
ENTRY1=0x90040
ENTRY2=0x90044
MAILBOX=0xdf000
TABLE=0xdf200

SCRIPTS=$(cd "$(dirname "$0")" && pwd)
XFEL=${XFEL:-xfel}
SUDO=${SUDO-sudo}
sudo_prefix=()
if [[ -n $SUDO ]]; then
    read -r -a sudo_prefix <<<"$SUDO"
fi

die() {
    printf 'fel-boot: %s\n' "$*" >&2
    exit 1
}
step() { printf '\n==> %s\n' "$*"; }
# Keep stdin closed so xfel/sudo never reads the plan file.
x() { "${sudo_prefix[@]}" "$XFEL" "$@" </dev/null; }

[ $# -eq 1 ] || die "usage: $0 <image dir with bt0-fel.bin, firmware.bin, firmware.seek, build-manifest.json>"
IMAGE=$(cd "$1" && pwd)
for f in bt0-fel.bin firmware.bin firmware.seek build-manifest.json; do
    [ -f "$IMAGE/$f" ] || die "$IMAGE/$f missing (make fel-image)"
done
command -v python3 >/dev/null || die "python3 not found"
command -v "$XFEL" >/dev/null || die "xfel not found (XFEL=$XFEL)"

# Copy the bundle into a private staging directory and validate the copies
# before any USB access. Nothing reads the original bundle after this.
STAGE=$(mktemp -d "$(dirname "$IMAGE")/.fel-stage.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
cp "$IMAGE/bt0-fel.bin" "$IMAGE/firmware.bin" "$IMAGE/firmware.seek" \
    "$IMAGE/build-manifest.json" "$STAGE/"
WORK="$STAGE/work"
mkdir -p "$WORK"

check_args=(--work "$WORK" --expect-mode "${EXPECT_MODE:-blobfree}"
    --expect-profile "${EXPECT_PROFILE:-${DRAM_MHZ:-1200}}")
if [ -n "${FEL_MEASUREMENT_AUTH:-}" ]; then
    check_args+=(--measurement-auth "$FEL_MEASUREMENT_AUTH")
fi
python3 -I "$SCRIPTS/fel-check.py" "$STAGE" "${check_args[@]}"

# put <file> <address> <label>: write, read back, compare.
put() {
    local file=$1 addr=$2 label=$3 size want got
    size=$(stat -c %s "$file")
    printf '  %-24s %8d bytes -> %s\n' "$label" "$size" "$addr"
    x write "$addr" "$file" >/dev/null
    x read "$addr" "$size" "$WORK/readback" >/dev/null
    want=$(sha256sum <"$file" | cut -d' ' -f1)
    got=$(sha256sum <"$WORK/readback" | cut -d' ' -f1)
    [ "$want" = "$got" ] || die "$label: read-back mismatch at $addr (sha256 $got, want $want)"
    printf '  %-24s verified, sha256 %s\n' "" "$want"
}

# mailbox [seconds]: prints "magic state dram_mb dram_mhz rom_sctlr
# rom_cpsr rom_vbar", or "none" if FEL does not answer within the time.
mailbox() {
    if timeout "${1:-30}" "${sudo_prefix[@]}" "$XFEL" read "$MAILBOX" 28 "$WORK/mailbox" </dev/null >/dev/null 2>&1; then
        od -An -v -tx4 -w28 "$WORK/mailbox" | tr -s ' ' | sed 's/^ //'
    else
        echo none
    fi
}

step "FEL device"
lsusb -d 1f3a:efe8 || die "no Allwinner FEL device (1f3a:efe8): is the board in FEL and its USB-C on this host?"
ver=$(x version) || die "xfel version failed"
printf '  %s\n' "$ver"
grep -q 'ID=0x00190300' <<<"$ver" || die "FEL device is not an A733 (ID 0x00190300)"

step "Images from $STAGE"
while read -r kind addr size _ name; do
    printf '  kind %s %-20s %8d bytes -> %s\n' "$kind" "$name" "$size" "$addr"
done <"$WORK/plan"

step "bt0 (FEL build) to $BT0_BASE"
head -c 4096 /dev/zero >"$WORK/zero"
put "$WORK/zero" "$MAILBOX" "mailbox (cleared)"
put "$STAGE/bt0-fel.bin" "$BT0_BASE" "bt0-fel.bin"
# xfel's read32 helper invalidates the I-cache and branch predictor first.
x read32 "$ENTRY1" >/dev/null

step "Entry 1 ($ENTRY1): clocks, PMIC, DRAM (~7 s; bt0 logs on UART0)"
t0=$(date +%s)
x exec "$ENTRY1" || die "xfel exec $ENTRY1 failed (see the serial console)"
# Each read waits while entry 1 runs; poll until it reports DRAM up.
while :; do
    mb=$(mailbox 60)
    [ "$mb" != none ] || die "FEL stopped answering during entry 1 (see the serial console)"
    read -r magic state dram_mb dram_mhz sctlr cpsr vbar <<<"$mb"
    [ "$state" = 00000011 ] && break
    [ "$state" = 00000000 ] || [ "$state" = 00000010 ] ||
        die "mailbox state 0x$state after entry 1 (magic $magic)"
    [ $(($(date +%s) - t0)) -lt 60 ] || die "entry 1 did not finish within 60 s (state 0x$state)"
    sleep 0.5
done
[ "$magic" = 46413741 ] || die "mailbox magic $magic: bt0 entry 1 did not run"
printf '  back in FEL after %d s: DRAM %d MiB at %d MHz; mask ROM SCTLR 0x%s CPSR 0x%s VBAR 0x%s\n' \
    $(($(date +%s) - t0)) $((16#$dram_mb)) $((16#$dram_mhz)) "$sctlr" "$cpsr" "$vbar"

step "Images to DRAM"
put "$WORK/table.bin" "$TABLE" "layout table frame"
while read -r _ addr _ file name; do
    put "$WORK/$file" "$addr" "$name"
done <"$WORK/plan"

step "Entry 2 ($ENTRY2): check the images, warm reset into oreboot main"
rc=0
timeout 15 "${sudo_prefix[@]}" "$XFEL" exec "$ENTRY2" </dev/null || rc=$?
state=none
if [ "$rc" -eq 0 ]; then
    # exec answered; whether entry 2 has started yet is the mailbox's to say.
    for _ in $(seq 20); do
        mb=$(mailbox 5)
        [ "$mb" != none ] || {
            state=none
            break
        }
        read -r _ state _ <<<"$mb"
        [ "$state" = 00000011 ] || break
        sleep 0.5
    done
fi
case $state in
000000e0) die "bt0 refused the hand-over (state 0xe0: entry 1 has not run in this FEL session); still in FEL" ;;
000000e1) die "bt0 refused the hand-over (state 0xe1: layout table or boot layout invalid); still in FEL" ;;
000000e2) die "bt0 refused the hand-over (state 0xe2: an image does not match its CRC); still in FEL" ;;
00000011) die "entry 2 did not start within 10 s (mailbox still 0x11); see the serial console" ;;
none) printf '  FEL no longer answers: bt0 is past the checks (xfel exit %d)\n' "$rc" ;;
*) printf '  mailbox state 0x%s (0x21: handing over)\n' "$state" ;;
esac
printf '\nWatch the serial console: "[bt0] RVBAR ...", then "main>" and oreboot main,\n'
printf 'EDK2, then GRUB/Linux from the USB disk in the blue port. If instead bt0\n'
printf 'prints "no warm reset 1 s after the request", the watchdog resets the\n'
printf 'board back into FEL about 16 s later.\n'
