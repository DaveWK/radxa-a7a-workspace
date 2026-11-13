# Bring-up status (2026-11-12)

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
| bt0: DRAM, vendor library (`VENDOR_DRAM=yes`) | works: all four pstates trained, 4096 MiB at 2400 MHz |
| bt0: DRAM, open driver (`VENDOR_DRAM=no`) | builds; controller and PHY set-up are ours, with the PHY's training firmware loaded as data. In development, not booted as the default |
| bt0: DRAM, no vendor input (`BLOBLESS=yes`) | **boots Fedora at 1200 MHz on a development branch** (see [DRAM without vendor code](#dram-without-vendor-code)). This workspace's pin still builds the earlier stage, which trains and then halts |
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
| GPU | not working: the GPU_CORE power domain does not come up |
| Wi-Fi/Bluetooth (AIC8800D80) | chip enumerates on USB; the driver source is not redistributable, see `fedora/README.md` |
| cpufreq | no driver yet; the CPUs stay at bt0's clocks |
| Stability | three memory-corruption oopses in softirq context on 2026-11-12, two of them after the Wi-Fi driver loaded; on vendor DRAM. The cause is open. Test boots therefore use a read-only root (below) |

## Test boots: protective entries

After a USB root disk failed on 2026-11-12, following several crashes and
forced resets with its root mounted read-write, every test boot on our
board uses a read-only root. The board's Fedora image script has this as
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
sequencer microcode (PIE). All training runs on the CPU in bt0. The code
is on a development branch of the oreboot fork and is not yet in this
workspace's pin.

**What was shown** (boot over USB FEL, root on a USB disk, the protective
default entry):

- bt0 reports 4096 MiB; main, EDK2, GRUB and Fedora 7.3.3 come up, and
  Linux sees the same memory as on vendor DRAM (MemTotal 3970952 kB).
- `memtester 512M 1`: all tests pass.
- `stress-ng --vm 2 --vm-bytes 30% --verify --timeout 3m`: passed, no
  oops, no EDAC error.
- A control boot on vendor DRAM, same entry and same tests, gives the same
  results.
- Before Linux, bt0's own tests pass: mode-register reads on all four
  ranks, and a hash memory test over 2 GiB (the 32-bit bt0 cannot address
  more) with 0 errors.

**Limits.** This is a first boot, not a stability result:

- It runs at **1200 MHz**. The vendor path trains 2400 MHz.
- Only the 3-minute stress above has run. No long soak, no temperature
  sweep, no load test of the rank-to-rank margins.
- Without the PHY's sequencer microcode, nothing compensates for drift at
  run time. An earlier partly-open build reached a login prompt and then
  hung under stress-ng, so long soaks matter here.
- The vendor library path stays the default (`VENDOR_DRAM=yes`). The open
  path replaces it only after it runs at 2400 MHz and matches the vendor
  path's stability; nothing is removed before then.

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
   the PHY's DFI read latency gave: the trained 4 fails, 5 passes every
   probe, 6 and 8 fail. Training at 5 moves the gate along with it and fails
   too, so the hand-over keeps the trained value and adds one.

The DRAM keeps its contents across bt0's warm reset into main; that was
checked separately and ruled out as a cause.

**Tooling.** A lab build of bt0 runs a DRAM training pass with options set
at run time and returns results and memory dumps over fastboot, so one
image covers many experiments. Open: after a lab DRAM run, the lab's
watchdog reset does not return the board to FEL (it does without a run),
so lab runs need a USB-C replug. The experiments above used plain FEL
images instead.
