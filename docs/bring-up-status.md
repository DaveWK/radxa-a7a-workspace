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
| Fastboot over FEL | Planned, not implemented ([usb-fel-boot.md](usb-fel-boot.md#planned-fastboot-over-fel)) |

### SD slot

Since 2026-11-11, bt0 (loaded over FEL) reports `SD init failed: NoCard` with
every card tried, including a freshly written spare. The cards and their
firmware area read back correctly in a card reader. With pull-ups, the
slot's data lines read low (DAT3 also with no card), and a card's lines read
as clamped. That points at the slot's power or contacts on this board, but
nothing has been measured yet, so the cause is open. bt0 drives DAT3 high
and uses a 1-bit bus on the SD path as a workaround attempt; it did not
change the result.

## Firmware

| Part | State |
|---|---|
| bt0: clocks, DCXO, UART0, PMIC rails, DVFS | works (CPU_L 1612 / CPU_B 1794 / DSU 1222 MHz after DRAM) |
| bt0: DRAM, vendor library (`VENDOR_DRAM=yes`) | works: all four pstates trained, 4096 MiB at 2400 MHz |
| bt0: DRAM, open driver (`VENDOR_DRAM=no`) | builds; controller and PHY set-up are ours, with the PHY's training firmware loaded as data. In development, not booted as the default |
| bt0: DRAM, no vendor input (`BLOBLESS=yes`) | development stage: our own DevInit, command bus training, WCK2CK leveling and read training run over FEL, then halt |
| bt0: USB FEL (`fel`) | works |
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
