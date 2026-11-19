# Bring-up status (2026-11-18)

Board: Radxa Cubie A7A, Allwinner A733 (SoC rev B), 4 GB CXMT LPDDR5,
AXP318W PMIC, Maxio MAE0621A-Q3C Ethernet PHY. Tested with Fedora 45, kernel
7.3.3-300.fc45 (stock) and the board RPMs from the `fedora` submodule.

## Boot paths

| Path | State |
|---|---|
| USB FEL (`make fel-boot`) | **Works.** bt0 → main → EDK2 → GRUB → Fedora login, root on a USB disk in the blue port. The current way to boot this board; see [usb-fel-boot.md](usb-fel-boot.md) |
| microSD | Booted bt0 → main → EDK2 → Fedora until 2026-11-11. Since then the slot on our board does not boot any card (below) |
| SPI NOR | Not used. The board's NOR holds no firmware; nothing here writes it |
| Fastboot over FEL | **Works on a development build**, not yet in this workspace: the firmware is sent over USB and booted from RAM. It writes no storage ([usb-fel-boot.md](usb-fel-boot.md#fastboot-over-fel)) |

### SD slot

Since 2026-11-11, bt0 (loaded over FEL) reports `SD init failed: NoCard` with
every card tried, including a freshly written spare. The cards and their
firmware area read back correctly in a card reader. With pull-ups, the
slot's data lines read low (DAT3 also with no card), and a card's lines read
as clamped. That points at the slot's power or contacts on this board, but
nothing has been measured yet, so the cause is open. The leading suspect is
the small series resistor that feeds the slot's 3.3 V supply (R25 in
Radxa's schematic) or the slot's supply pin joint; this is not confirmed.
bt0 drives DAT3 high and uses a 1-bit bus on the SD path as a workaround
attempt; it did not change the result.

## Firmware

| Part | State |
|---|---|
| bt0: clocks, DCXO, UART0, PMIC rails, DVFS | works (CPU_L 1612 / CPU_B 1794 / DSU 1222 MHz after DRAM) |
| bt0: DRAM, no vendor input (the default build) | **boots Fedora at 1200 MHz**, its default clock, and passes `memtester 2600M` once and a 5-minute `stress-ng` run with verify there. At 2400 MHz (`DRAM_MHZ=2400`) the kernel fails to decompress at the hand-over read latency of 6; at 5 Linux starts but the memory tests fail on bit 37: not usable yet (see [DRAM without vendor code](#dram-without-vendor-code)). 4 GB board, USB FEL only so far |
| bt0: DRAM, vendor library (`VENDOR_DRAM=yes`) | works: all four pstates trained, 4096 MiB at 2400 MHz. The comparison build |
| bt0: DRAM, our driver with the PHY's training firmware as data (`VENDOR_DRAM=phyfw`) | builds; controller and PHY set-up are ours. Not booted as a default |
| bt0: USB FEL (`fel`) | works |
| bt0: fastboot over FEL | works on a development build: 25.7 MB/s down, about 42 MB/s up ([usb-fel-boot.md](usb-fel-boot.md#fastboot-over-fel)) |
| main: PSCI 1.0, GICv3, 8 cores, warm reboot | works |
| main: GMAC0 + Maxio PHY | works (Linux: about 108 MiB/s each way, no CRC errors) |
| main: USB (DWC3/xHCI, EHCI) | works; `usb-hs-only` keeps the blue port's SuperSpeed PHY off for the FEL root disk |
| main: SMCCC TRNG (Crypto Engine) | works: self-tests pass, Linux uses it as `/dev/hwrng`, EFI RNG table present |
| main: PCIe | builds; Linux owns the controller in the current images (`BRINGUP` without `pcie`) |
| EDK2: SD, USB, Ethernet, SMBIOS, DTB | works |
| EDK2: HDMI GOP | works at the monitor's native mode in the tested boots |
| EDK2: UEFI variables on the card | built (`-D SD_VARSTORE_ENABLE=TRUE`), not yet confirmed on the board |

## Linux (stock Fedora kernel + board RPMs)

| Part | State |
|---|---|
| pinctrl, PMIC regulators, MMC, UART, RTC (hym8563) | works |
| Ethernet | works |
| HDMI display (`cubie-a7a-display`, sunxidrm) | binds, HDMI-A-1 at the native mode |
| Video decoder (`cubie-a7a-vdec`, cedrus) | `/dev/video0`: MPEG-2, H.264, H.265, VP8 |
| NPU (`cubie-a7a-npu`, vipcore) | `/dev/vipcore`, self-test passes |
| RK1828 coprocessor on PCIe (`cubie-a7a-rk1828`) | packaged; needs the HAT |
| GPU | not working. Since 2026-11-12 the GPU power domains are off at boot and are switched on only when the GPU driver asks for them; GPU_CORE still does not switch on, so the driver stays blocked and there is no rendering |
| Wi-Fi/Bluetooth (AIC8800D80) | works with the board's Wi-Fi package, which needs a local driver tree (`AIC8800_SRC`: the driver source is not redistributable, see `fedora/README.md`): Wi-Fi scans find networks, the Bluetooth controller powers up. Off on the protective test entry (HAT stack off) |
| cpufreq | no driver yet; the CPUs stay at bt0's clocks |
| Stability | three memory-corruption oopses in softirq context on 2026-11-12, two of them after the Wi-Fi driver loaded; on vendor DRAM. The cause is open. Test boots therefore use a read-only root (below) |

## Test boots: protective entries

Test boots on our board keep the root read-only, so a crash or a forced
reset cannot corrupt it. The board's Fedora image script has this as
an option (`BOOT_MODES=protective`, with `FIRST_BOOT=maintenance`). That
version of the script is not yet in this workspace's `fedora` submodule,
so `make fedora-image` does not add these entries yet.

| GRUB entry | Root | HAT stack | Use |
|---|---|---|---|
| default (protective) | read-only, RAM overlay (`systemd.volatile=overlay`); ESP not mounted, no root growth, no fsck, no journal replay, volatile journal | off (`cubie_a7a.hat=0`: no HAT, Wi-Fi or USB 3 stack) | every test boot |
| maintenance | read-write | off | package installs, root growth |
| full | read-write | on | only tests that need the HAT or Wi-Fi |

- The **first boot** is a one-shot maintenance boot: it creates the
  machine ID and SSH host keys and grows the root to the disk. Every boot
  after that is the protective default.
- `cubie-a7a-bootmode next maintenance|full` picks the next boot only;
  `cubie-a7a-bootmode status` shows the state. On the protective boot
  `grub2-reboot` fails on purpose, because the real root is not writable
  there.
- Kernel updates (on a maintenance boot) keep the protective options on the
  new kernel's default entry and add its maintenance and full entries.
- Trade-off: the protective entry mounts ext4 without replaying its journal
  (`rootflags=noload`), so after a crash on a read-write boot it sees the
  root as it was before the journal, until the next read-write boot.

## DRAM without vendor code

On 2026-11-12 Fedora booted on DRAM brought up entirely by our own code:
no Allwinner DRAM library, no Synopsys PHY training firmware, and no PHY
sequencer microcode (PIE). All training runs on the CPU in bt0. This is
now what `make firmware` and `make fel-image` build by default, with the
settings of that boot built in (and those of the 2400 MHz runs below as
`DRAM_MHZ=2400`); the vendor library is the comparison build
(`VENDOR_DRAM=yes`).

**What was shown** (one boot over USB FEL, root on a USB disk, the protective
default entry, 4 GB board):

- bt0 reports 4096 MiB; main, EDK2, GRUB and Fedora 7.3.3 come up, and
  Linux sees the same memory as on vendor DRAM (MemTotal 3970952 kB).
- `memtester 2600M 1`: all tests pass, once.
- `stress-ng --vm 4 --vm-bytes 80% --vm-method all --verify` for 5 minutes:
  passed, no oops, no EDAC error.
- A control boot on vendor DRAM (`VENDOR_DRAM=yes`, a measurement build),
  same entry and same tests, gives the same results.
- Before Linux, bt0's own tests pass: mode-register reads on all four
  ranks, and a hash memory test over 2 GiB (the 32-bit bt0 cannot address
  more) with 0 errors.

**Limits.** This is one boot at 1200 MHz, not a stability result:

- It runs at **1200 MHz**, the default build's clock. The vendor path
  trains 2400 MHz. At 2400 MHz (`DRAM_MHZ=2400`):
  - bring-ups over USB FEL end with clean memory tests on both ranks in
    bt0 (12 runs in a row; a write reference voltage and a centred write
    delay made the difference there), and main, EDK2 and GRUB run;
  - with the settings as built, the kernel then fails to decompress
    (`ZSTD-decompression failed`) at the hand-over read latency (DFIMRL) of
    6, the last value before the edge: cache line-fill probes in bt0 are
    clean at 5 and 6 and fail at 7;
  - with the read latency at 5, Linux starts, but its initramfs is found
    corrupt and `memtester` and `stress-ng --verify` fail within seconds.
    Every failure is the same single bit, bit 37 (bit 5 of the upper 32-bit
    half of the 64-bit word), flipping both ways, spread over the whole
    buffer. bt0's own tests do not catch it;
  - per-lane write centring (below) moves individual lanes by up to 14
    delay steps but does not remove those errors.

  So 2400 MHz is not usable as a boot clock yet. The missing full-speed
  stages (WCK duty-cycle adjustment, two-dimensional read reference
  voltage, command-bus reference voltage) and per-lane read timing are the
  candidates being worked on.
- Every run was on the 4 GB board, loaded over USB FEL. The same build
  selects the 6 GB board's parameters by its strap and has not run there;
  a boot from a card or the eMMC has not run either. The 8 and 12 GB
  parameter sets run another DRAM clock and are refused by our driver.
- Only the 5-minute stress above has run. No long soak, no temperature
  sweep, no load test of the rank-to-rank margins.
- Without the PHY's sequencer microcode, nothing compensates for drift at
  run time. An earlier partly-open build reached a login prompt and then
  hung under stress-ng, so long soaks matter here.
- The vendor library path stays available as `VENDOR_DRAM=yes`, for
  comparison and for the boards our driver does not cover yet; nothing of
  it is removed.

**How it got there.** The approach was to take the vendor-trained state as
a reference: register snapshots of the PHY and controller after vendor
training and after ours, compared field by field, and bisection by running
our stages one at a time on top of the vendor-trained state. Three faults
were found that way. Each was in our own sequence, not in the hardware:

1. **WCK always-on (LPDDR5 MR18).** Reads failed even when every readable
   PHY and controller register matched the vendor state. The difference was
   in the DRAM's own mode registers: the hand-over must leave MR18 with WCK
   always-on set (0x1c, not 0x0c), together with the final MR3 and MR13
   values, a ZQ latch and a self-refresh cycle. With MR18 at 0x0c reads
   return stale data; at 0x1c all four ranks read correctly.
2. **Read pulse restore.** One byte lane read wrong data in normal
   operation, in two of its bytes. Our device initialisation leaves the
   PHY command sequencer's read pulses four steps longer than the vendor
   training does, so our read training placed that lane's receive-enable
   gate too early for normal reads. Restoring the pulses before read
   training puts the gate within a few steps of the vendor-trained value,
   and the lane reads clean.
3. **Read latency for cache line fills (DFIMRL).** bt0's tests passed, but
   oreboot main printed nothing after the warm reset. Probe code run from
   DRAM showed that single reads were correct while cache line fills
   (back-to-back bursts) returned wrong data: with the instruction cache off
   the code ran, with it on it executed the wrong instructions. A sweep of
   the PHY's DFI read latency at 1200 MHz gave: 5 passes every probe, 6
   loses a few words, 8 loses whole lines (a run first recorded as "4"
   had in fact run at 8). Training at 5 moves the gate along with it and
   fails too, so the hand-over keeps the trained value and adds one. At
   2400 MHz that rule gives 6, the edge (see the limits above), so the
   rule is to be replaced by one that centres in the measured window.

The DRAM keeps its contents across bt0's warm reset into main; that was
checked separately and ruled out as a cause.

**Write lanes.** The write stage's lane discovery used to fail every time,
so all eight lanes of a byte shared one write delay. The cause was that
the check also counted the data-mask lane, whose writes affect a whole
byte. With that fixed, discovery works on the board at 2400 MHz on both
ranks, and an optional per-lane centring (a stage bit, off by default)
measures write windows of 38 to 59 delay steps per lane and places each
lane in its own window. It runs cleanly but has not yet been shown to
change any test result.

**Tooling.** A lab build of bt0 runs a DRAM training pass with options set
at run time and returns results and memory dumps over fastboot, so one
image covers many experiments. Open: after a lab DRAM run, the lab's
watchdog reset does not return the board to FEL (it does without a run),
so lab runs need a USB-C replug. A workaround is in the source (the lab
leaves through the mask ROM's FEL entry instead) but has not run on a
board. The experiments above used plain FEL images instead.
