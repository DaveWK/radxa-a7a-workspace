#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# Capture the register state EDK2 still needs from a Cubie A7A running
# Radxa's vendor image (RadxaOS / Armbian BSP kernel), in one session:
#
#   1. HDMI: the Synopsys PHY PLL settings for HdmiPhyTable.c, plus a golden
#      trace of the CCU / DE / TCON / HDMI state to diff against
#      A733DisplayDxe's log.
#   2. USB2: the EHCI-internal PHY tune (HCI+0x818/+0x81C) and the USB2 PHY
#      state, still Orange Pi 4 Pro values in SunxiUsbDxe.
#   3. USB3: the SERDES wrapper and the combo0 PHY (PMA) registers with a
#      SuperSpeed link up, for a future USB3 PHY init.
#   4. PCIe: the combo1 PHY (PMA) and the PCIe application registers with a
#      link up, for a future PCIe driver.
#   5. The PMIC rail registers, for comparison with bt0's log.
#   6. Ethernet: the GMAC0 clock, pin, glue and MAC registers oreboot's
#      gmac.rs programs, and ethtool output for every interface.
#   7. The SD controller's clock and delay registers at the vendor bus mode.
#   8. PCIe devices (lspci tree, link status, NVMe), e.g. the 2x2.5 GbE HAT.
#
# PHY calibration values come from captures like these.
#
# Setup before running (as root, on the A7A):
#   - HDMI monitor attached, the mode you want set (1920x1080@60 is
#     148500 kHz, 1280x720@60 is 74250 kHz). Run once per mode.
#   - A USB 3 device in the blue Type-A port (for the USB3 section).
#   - Optionally the PCIe FPC HAT with an NVMe drive (for the PCIe section).
#   - Something plugged into a black USB 2.0 port and the USB-C port, so the
#     controllers are not runtime-suspended.
#
# Usage: capture-a7a-vendor.sh [-o DIR] [--no-pma] [--force]
#   -o DIR    output directory (default ./a7a-capture-YYYYmmdd-HHMMSS)
#   --no-pma  skip the bulk 128 KiB combo PHY dumps
#   --force   run on a board whose DT model is not "Cubie A7A"
#
# Safety. Everything is a read except the DW HDMI PHY I2C master, which is
# driven to *read* the Synopsys PHY registers (a read transaction plus
# clearing its own done/error flags); avoid running while the kernel changes
# display modes. Only named registers are read, with two exceptions: the
# combo PHY wrapper (0xA00) and PMA (128 KiB) windows are swept, and only
# while that PHY's link is up.
# DockSeed/a7s-build read the whole combo0 window this way on a linked
# board. The PCIe controller's DBI window is never touched: reading across
# it hung a board hard (vehoelite/edk2-a733 research notes), so PCIe uses
# only the application-register offsets known to be safe. Do not unbind the
# PCIe driver with a drive fitted either; that hangs the board too.

set -eu

OUT=
PMA=1
FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
  -o)
    OUT=$2
    shift 2
    ;;
  --no-pma)
    PMA=0
    shift
    ;;
  --force)
    FORCE=1
    shift
    ;;
  *)
    echo "usage: $0 [-o DIR] [--no-pma] [--force]" >&2
    exit 2
    ;;
  esac
done

if [ "$(id -u)" != 0 ]; then
  echo "run as root" >&2
  exit 1
fi

# Radxa's 5.15 images name the board in the model; the 6.6 (trixie) ones
# only say "sun60iw2" there but list radxa,cubie-a7a in compatible.
MODEL=$(tr -d '\0' </proc/device-tree/model 2>/dev/null || echo unknown)
COMPAT=$(tr '\0' ' ' </proc/device-tree/compatible 2>/dev/null || true)
case "$MODEL $COMPAT" in
*"Cubie A7A"* | *radxa,cubie-a7a*) ;;
*)
  if [ "$FORCE" != 1 ]; then
    echo "not a Cubie A7A (model '$MODEL', compatible '$COMPAT'; use --force)" >&2
    exit 1
  fi
  ;;
esac

if command -v devmem >/dev/null 2>&1; then
  DEVMEM=devmem
elif command -v busybox >/dev/null 2>&1 && busybox devmem 0x02002000 >/dev/null 2>&1; then
  DEVMEM="busybox devmem"
else
  echo "devmem not found (install busybox)" >&2
  exit 1
fi

HAVE_PY=0
command -v python3 >/dev/null 2>&1 && HAVE_PY=1

OUT=${OUT:-./a7a-capture-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
SUMMARY=$OUT/summary.txt
: >"$SUMMARY"

say() { echo "$*" | tee -a "$SUMMARY"; }
section() {
  say
  say "== $*"
}

r8() { $DEVMEM "$(printf 0x%x "$1")" 8; }
w8() { $DEVMEM "$(printf 0x%x "$1")" 8 "$2"; }
r32() { $DEVMEM "$(printf 0x%x "$1")" 32; }

# reg32 BASE NAME OFF...: print BASE+OFF for each offset
reg32() {
  base=$1
  name=$2
  shift 2
  for off in "$@"; do
    say "$(printf '%s+0x%04x = %s' "$name" "$off" "$(r32 $((base + off)))")"
  done
}

# range32 BASE NAME FIRST LAST: every word from FIRST to LAST inclusive
range32() {
  base=$1
  name=$2
  off=$(($3))
  last=$(($4)) # dash's [ ] needs decimal
  while [ "$off" -le "$last" ]; do
    reg32 "$base" "$name" "$off"
    off=$((off + 4))
  done
}

# dump32 BASE SIZE FILE: bulk 32-bit dump through /dev/mem (python3 mmap)
dump32() {
  if [ "$HAVE_PY" != 1 ]; then
    say "  (python3 missing; skipped bulk dump of $(printf 0x%x "$1"))"
    return
  fi
  python3 -I - "$1" "$2" "$3" <<'PY'
import mmap, os, sys
base, size, path = int(sys.argv[1], 0), int(sys.argv[2], 0), sys.argv[3]
fd = os.open("/dev/mem", os.O_RDONLY | os.O_SYNC)
mm = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ, offset=base)
words = memoryview(mm).cast("I")          # aligned 32-bit loads only
with open(path, "w") as f:
    for i in range(size // 4):
        v = words[i]
        if v:
            f.write("0x%08x 0x%08x\n" % (base + 4 * i, v))
words.release()
mm.close()
os.close(fd)
PY
  say "  wrote $(basename "$3") (non-zero words of $(printf 0x%x "$1")+$(printf 0x%x "$2"))"
}

CCU=0x02002000
SYSCFG=0x03000000
SERDES=0x06C00000
COMBO_MUX=0x06C06000
COMBO0_TOP=0x06C01000
COMBO0_PMA=0x06C80000
COMBO1_TOP=0x06C02000
COMBO1_PMA=0x06CA0000
PCIE_APP=0x06400000
XHCI=0x06A00000
U2PHY=0x06B00000

#
# 0. System
#
section "system"
say "model: $MODEL"
say "compatible: $COMPAT"
say "kernel: $(uname -a)"
say "cmdline: $(cat /proc/cmdline)"
{ command -v lsusb >/dev/null && lsusb -t; } >"$OUT/lsusb-t.txt" 2>&1 || true
{ command -v lsusb >/dev/null && lsusb; } >"$OUT/lsusb.txt" 2>&1 || true
{ command -v lspci >/dev/null && lspci -nnvv; } >"$OUT/lspci.txt" 2>&1 || true
for c in /sys/class/drm/card*-*; do
  [ -f "$c/status" ] || continue
  say "drm $(basename "$c"): $(cat "$c/status") $(head -1 "$c/modes" 2>/dev/null || true)"
done
for r in /sys/class/regulator/regulator.*; do
  [ -f "$r/name" ] || continue
  printf '%s %s uV=%s state=%s users=%s\n' "$(basename "$r")" "$(cat "$r/name")" \
    "$(cat "$r/microvolts" 2>/dev/null || echo -)" \
    "$(cat "$r/state" 2>/dev/null || echo -)" \
    "$(cat "$r/num_users" 2>/dev/null || echo -)"
done >"$OUT/regulators.txt"
say "wrote lsusb*.txt, lspci.txt, regulators.txt"

#
# 1. PMIC (AXP318W at 0x36): DCDC/LDO enables and voltages, read only
#
section "PMIC AXP318W"
PMIC_DEV=
for d in /sys/bus/i2c/devices/*-0036; do
  if [ -e "$d" ]; then
    PMIC_DEV=$d
    break
  fi
done
if [ -n "$PMIC_DEV" ] && command -v i2cget >/dev/null 2>&1; then
  BUS=$(basename "$PMIC_DEV" | cut -d- -f1)
  line=
  for reg in $( # 0x10..0x33
    seq 16 51
  ); do
    v=$(i2cget -f -y "$BUS" 0x36 "$reg" 2>/dev/null || echo "??")
    line="$line $(printf '%02x' "$reg")=$v"
  done
  say "i2c-$BUS 0x36:$line"
  say "(0x20 bit6 BLDO1, 0x21 bit4 CLDO2, bit7 CLDO5; voltage regs 0x2a/0x30/0x33: 500 + 100*n mV)"
else
  say "skipped (no i2cget or no *-0036 device)"
fi

#
# 2. HDMI
#
section "HDMI"
HDMI=0x05520000
TOP_PHY=$((HDMI + 0xE0000))
say "$(printf 'DW HDMI design %s rev %s product %s %s' \
  "$(r8 $HDMI)" "$(r8 $((HDMI + 1)))" "$(r8 $((HDMI + 2)))" "$(r8 $((HDMI + 3)))")"
say "PHY_CONF0 $(r8 $((HDMI + 0x3000))) PHY_STAT0 $(r8 $((HDMI + 0x3004)))"
reg32 $CCU CCU 0x0120 0x02E0 0x0A00 0x0A04 0x0A74 0x05C0 0x05E0 \
  0x1604 0x1680 0x1684 0x168C 0x1690 0x16CC 0x16EC
reg32 $TOP_PHY TOP_PHY 0x00 0x04 0x10 0x14 0x20 0x24 0x28 0x2C 0x30 0x34 0x40
reg32 $SYSCFG SYSCFG 0x160 0x164 0x168
reg32 0x05510000 TCON_TOP 0x00 0x1C 0x20
reg32 0x05730000 TCON_TV0 0x000 0x040 0x088 0x08C 0x090 0x098 0x09C 0x0A0 0x0A4 0x0A8 0x340
reg32 0x05008000 DE_TOP 0x000 0x004 0x008 0x010 0x028 0x02C 0x030 0x050 0x100 0x108 0x10C 0x110
reg32 0x05101000 VCH0_OVL 0x00 0x04 0x08 0x0C 0x18 0xD0 0xE8
reg32 0x05281000 BLD0 0x00 0x04 0x08 0x0C 0x80 0x88 0x8C 0x90 0xFC

# DW HDMI PHY I2C master (byte registers)
IH_I2CMPHY_STAT0=$((HDMI + 0x0108))
PHY_I2CM_SLAVE=$((HDMI + 0x3020))
PHY_I2CM_ADDRESS=$((HDMI + 0x3021))
PHY_I2CM_DATAI_1=$((HDMI + 0x3024))
PHY_I2CM_DATAI_0=$((HDMI + 0x3025))
PHY_I2CM_OPERATION=$((HDMI + 0x3026))

phy_read() {
  w8 $IH_I2CMPHY_STAT0 0xff
  w8 $PHY_I2CM_SLAVE 0x69
  w8 $PHY_I2CM_ADDRESS "$1"
  w8 $PHY_I2CM_OPERATION 0x01
  n=0
  while [ $(($(r8 $IH_I2CMPHY_STAT0) & 3)) -eq 0 ]; do
    n=$((n + 1))
    [ $n -gt 100 ] && {
      echo "timeout"
      return 0
    }
  done
  st=$(($(r8 $IH_I2CMPHY_STAT0) & 3))
  w8 $IH_I2CMPHY_STAT0 $st
  [ $((st & 1)) -ne 0 ] && {
    echo "error"
    return 0
  }
  printf "0x%04x" $((($(r8 $PHY_I2CM_DATAI_1) << 8) | $(r8 $PHY_I2CM_DATAI_0)))
}

HDMI_ID=$(r8 $((HDMI + 2)))
if [ "$HDMI_ID" = 0x00 ] || [ "$HDMI_ID" = 0x0 ]; then
  say "HDMI controller reads as zero (powered down or no monitor); PHY skipped"
else
  p06=$(phy_read 0x06)
  p10=$(phy_read 0x10)
  p11=$(phy_read 0x11)
  p19=$(phy_read 0x19)
  p0e=$(phy_read 0x0e)
  p09=$(phy_read 0x09)
  say "Synopsys PHY 0x06=$p06 0x10=$p10 0x11=$p11 0x19=$p19 0x0e=$p0e 0x09=$p09"
  # Pixel clock and sync flags of the active CRTC, from DRM debugfs:
  # mode: "name": vrefresh clock hdisp hss hse htot vdisp vss vse vtot type flags
  MODE_LINE=$(grep -h 'mode:' /sys/kernel/debug/dri/*/state 2>/dev/null | grep -v ': 0 0 ' | head -1 || true)
  say "DRM ${MODE_LINE:-mode: unavailable (mount debugfs)}"
  khz=$(echo "$MODE_LINE" | sed -n 's/.*mode: "[^"]*": [0-9]* \([0-9]*\) .*/\1/p')
  khz=${khz:-unknown}
  # Pixel clock source: HDMI_TV_CLK gate (CCU) or the HDMI PHY's own PLL.
  if [ $(($(r32 $((CCU + 0x1684))) >> 31)) -eq 1 ]; then
    say "pixel clock source: CCU HDMI_TV_CLK"
  else
    say "pixel clock source: HDMI PHY PLL (HDMI_TV_CLK gated; TOP_PHY+0x20 = $(r32 $((TOP_PHY + 0x20))))"
  fi
  HDMI_ROW="  { $khz, $p06, $p10, $p11 },   // gA733HdmiPhyMpll (check $khz kHz against the mode)"
  HDMI_DRIVE="  TXTERM $p19 VLEVCTRL $p0e CKSYMTXCTRL $p09 (should match gA733HdmiPhyDrive; VLEVCTRL bit 15 reads back as 0)"
fi

#
# 3. USB2: clocks, calibration, EHCI-internal PHY registers, USB2 PHY
#
section "USB2"
reg32 $CCU CCU 0x05A4 0x05C0 0x05E0 0x1300 0x1304 0x1308 0x130C 0x1340 \
  0x1348 0x1350 0x1354 0x135C 0x1360 0x1364 0x13C0 0x13C4 0x1A00
reg32 0x04100000 OTG 0x420
for hci in 0x04101000 0x04200000; do
  reg32 $hci "EHCI@$hci" 0x000 0x004 0x008 0x010 0x014 0x054 \
    0x800 0x804 0x808 0x80C 0x810 0x814 0x818 0x81C 0x820 0x824 0x828
done
range32 $U2PHY U2PHY 0x00 0x7C
EHCI_ROW="  EHCI0 +0x818=$(r32 0x04101818) +0x81C=$(r32 0x0410181C)  EHCI1 +0x818=$(r32 0x04200818) +0x81C=$(r32 0x0420081C)"
U2PHY_ROW="  U2PHY +0x10=$(r32 $((U2PHY + 0x10))) +0x18=$(r32 $((U2PHY + 0x18)))"

#
# 4. USB3: dwc3, SERDES wrapper, combo0 (the A7A's USB3 PHY)
#
section "USB3 / SERDES"
reg32 $XHCI XHCI 0x0000 0x0004 0x0008 0x0010 0x0014
reg32 $XHCI DWC3 0xC110 0xC11C 0xC12C 0xC200 0xC2C0 0xD024 0xD050 0xD054 0xD060
range32 $SERDES SERDES 0x000 0x0FC
reg32 $COMBO_MUX COMBO 0xC44
reg32 0x0709016C DCXO_SERDES 0x0
SS_UP=0
# a device (not the root hub, which always reports its top speed)
if grep -v root_hub "$OUT/lsusb-t.txt" 2>/dev/null | grep -q "5000M\|10000M"; then
  SS_UP=1
fi
if [ "$SS_UP" = 1 ]; then
  say "SuperSpeed link up"
  range32 $COMBO0_TOP COMBO0_TOP 0x000 0x9FC
  if [ "$PMA" = 1 ]; then
    dump32 $COMBO0_PMA 0x20000 "$OUT/combo0-pma.txt"
  fi
else
  say "no SuperSpeed device in lsusb -t; combo0 skipped (plug a USB 3 device into the blue port)"
fi

#
# 5. PCIe: safe application offsets only; combo1 only with the link up
#
section "PCIe"
reg32 $CCU CCU 0x0574 0x1380 0x1384 0x138C
reg32 $PCIE_APP PCIE_APP 0x000 0x004 0x200 0x220 0x800 0xC00 0xE04 0xE0C
LINK=$(r32 $((PCIE_APP + 0xE0C)))
if [ $((LINK & 3)) -eq 3 ]; then
  say "link up (SMLH|RDLH)"
  range32 $COMBO1_TOP COMBO1_TOP 0x000 0x9FC
  if [ "$PMA" = 1 ]; then
    dump32 $COMBO1_PMA 0x20000 "$OUT/combo1-pma.txt"
  fi
else
  say "link not up (PCIE_LINK_STAT $LINK); combo1 skipped"
fi

#
# 6. Ethernet GMAC0: what oreboot main/src/gmac.rs programs, as the vendor
#    kernel left it with the link up. Named registers only.
#
section "GMAC0"
reg32 $CCU CCU 0x05E4 0x1400 0x1410 0x141C
reg32 0x02000000 PIO_PH 0x400 0x404 0x408 0x410 0x420 0x424 0x430 0x434
reg32 0x04508000 GMAC_GLUE 0x0
reg32 0x04500000 GMAC 0x0000 0x0004 0x0110 0x0300 0x0304 0x1000 0x1004
for path in /sys/class/net/*; do
  ifc=${path##*/}
  drv=$(basename "$(readlink -f "/sys/class/net/$ifc/device/driver" 2>/dev/null)" 2>/dev/null)
  [ -n "$drv" ] || continue
  say "$ifc: driver $drv, mac $(cat "/sys/class/net/$ifc/address"), speed $(cat "/sys/class/net/$ifc/speed" 2>/dev/null || echo ?)"
  if command -v ethtool >/dev/null; then
    {
      ethtool "$ifc"
      ethtool -i "$ifc"
      ethtool -d "$ifc"
    } >"$OUT/ethtool-$ifc.txt" 2>&1 || true
  fi
done

#
# 7. SD card (SMHC0): clock and delay settings at the vendor's bus mode, to
#    compare with SunxiMmcDxe. Configuration registers only, never the FIFO.
#
section "SMHC0"
reg32 $CCU CCU 0x0D00 0x0D0C
reg32 0x04020000 SMHC0 0x000 0x004 0x008 0x00C 0x05C 0x078 0x140 0x144 0x148 0x14C
if [ -r /sys/kernel/debug/mmc0/ios ]; then
  cat /sys/kernel/debug/mmc0/ios | tee -a "$SUMMARY"
fi

#
# 8. The 2x2.5 GbE HAT (ASM2806 switch, two RTL8125B, NVMe) under the
#    vendor kernel, as a hardware baseline before our own PCIe bring-up.
#
section "PCIe devices"
if command -v lspci >/dev/null; then
  lspci -tv 2>&1 | tee -a "$SUMMARY"
  lspci -vv 2>/dev/null | grep -E '^[0-9a-f]|LnkCap:|LnkSta:' | tee -a "$SUMMARY"
fi
{
  command -v nvme >/dev/null && nvme list
  for b in /sys/block/nvme*; do [ -e "$b" ] && echo "${b##*/}: $(cat "$b/size") sectors"; done
} >>"$SUMMARY" 2>&1 || true

#
# Results to paste
#
section "results"
if [ -n "${HDMI_ROW:-}" ]; then
  say "HdmiPhyTable.c:"
  say "$HDMI_ROW"
  say "$HDMI_DRIVE"
fi
say "SunxiUsbDxe (HCI_PHY_TUNE_VALUE / +0x81C, USB2 PHY):"
say "$EHCI_ROW"
say "$U2PHY_ROW"
say
say "Everything is in $OUT/. Send summary.txt and any *-pma.txt files."
