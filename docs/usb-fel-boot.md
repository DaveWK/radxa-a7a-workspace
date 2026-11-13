# USB FEL boot and fastboot

The A733 mask ROM has a USB download mode, **FEL**. The board in FEL shows
up on the host as USB device `1f3a:efe8`. `scripts/fel-boot.sh` uses it to
start the whole boot chain from the host over USB, with no SD card involved:
bt0 initialises DRAM, the host loads oreboot main and EDK2 into DRAM, and bt0
hands over to them. This is the current way to boot the Cubie A7A here (see
[bring-up-status.md](bring-up-status.md) for the SD slot).

## What you need

- The board's **USB-C port** connected to the host. It powers the board and
  carries FEL. Use a port and cable that can supply the board.
- A **USB disk with the Fedora image** (`out/image/a7a-fedora45.img`) in the
  **blue USB-A port**. The FEL main is built with `usb-hs-only`, so combo0
  stays off and a USB 3 disk in the blue port runs at high speed on EHCI1,
  which both EDK2 and Linux's initramfs drive.
- **xfel built with a 60 s USB timeout.** Upstream xfel gives up on a FEL
  call after 10 s, and bt0's entry 1 (clocks, PMIC, DRAM training) keeps the
  ROM busy for about 5-7 s, longer with DRAM tracing. `make xfel` builds
  xfel v1.4.0 from <https://github.com/xboot/xfel> (MIT) with
  `libusb_bulk_transfer` raised from 10000 to 60000 ms in `fel.c`, into
  `out/tools/xfel`. It needs `gcc`, `make`, `pkgconf` and `libusb1-devel`.
  No xfel binary is part of this repository.
- Root for xfel, or xfel's udev rule
  (`out/tools/xfel-src/99-xfel.rules` in `/etc/udev/rules.d`) and `SUDO=`.
- Optional: a 3.3 V USB-UART adapter on UART0 (115200 8N1), with
  `make serial`.

## Enter FEL

- With **no bootable SD card** (none inserted, or one the ROM cannot boot),
  the mask ROM falls back to FEL by itself at power-on.
- Or hold the **UBOOT/FEL key (SW2)** while plugging in USB-C.

Check with `lsusb -d 1f3a:efe8`.

## Boot

    make fel-image            # in the build container: out/fel/
    make xfel                 # once, on the host
    make fel-boot             # on the host, board in FEL

`make fel-boot` runs `scripts/fel-boot.sh out/fel` with `XFEL=out/tools/xfel`.
The steps:

1. **Check** that the FEL device is an A733 (`xfel version`, ID `0x00190300`).
2. **Load bt0**: clear the mailbox at `0xdf000`, write `bt0-fel.bin` (bt0
   built with feature `fel`, linked at `0x90000`) and read it back.
3. **Entry 1** (`xfel exec 0x90040`): bt0 brings up clocks, PMIC and DRAM,
   boosts the CPUs and returns to FEL. The ROM answers `exec` before the code
   finishes, so the script polls the mailbox until it reports DRAM up, then
   prints the DRAM size and clock.
4. **Load the images**: the layout table frame goes to `0xdf200`, oreboot
   main to `0x40000000` and the EDK2 FD to `0x41000000`, all taken from
   `firmware.bin`. Each write is read back and compared (SHA-256).
5. **Entry 2** (`xfel exec 0x90044`): bt0 checks the layout table and the
   images' CRCs in DRAM and turns off the GIC state the ROM left behind (its
   USB runs on interrupts, and a pending interrupt blocks the warm reset).
   It then warm-resets into main at EL3, as the SD boot does. FEL does not
   come back after this. A refusal is reported from the mailbox instead (state
   `0xe0` entry 1 not run, `0xe1` bad layout table, `0xe2` CRC mismatch), and
   the board stays in FEL.

`out/fel/` holds `bt0-fel.bin`, `firmware.bin`, `firmware.seek` and
`SHA256SUMS`. Build options: `FEL_DRAM=dramlib` (default, vendor DRAM
library) or `FEL_DRAM=open` (open DRAM driver), and `FEL_BRINGUP=` (features of
the FEL main, default `gmac usb usb-hs-only trng`).

## Expected serial output

Abridged, from a boot of this flow (values vary by board and build):

    oreboot 🦀 bt0 | Radxa Cubie A7A | Allwinner A733
    [bt0] SoC rev B, DCXO 26000 kHz ...
    [bt0] DRAM: strap ... -> CXMT 4GB
    [bt0] DRAM: init with CXMT 4GB parameters (2400 MHz)
    [bt0] DRAM: 4096 MiB
    [bt0] CPU_L 1612 MHz, CPU_B 1794 MHz, DSU 1222 MHz; ...
    [bt0] FEL: DRAM up, ... ms; back to FEL. Next: images to DRAM, layout table to 0xdf200, entry 2 at 0x90044
    [bt0] FEL: entry 2: checking the images in DRAM
    [bt0] FEL: kind 1 (... KiB) at 0x40000000, CRC ok
    [bt0] FEL: kind 2 (4096 KiB) at 0x41000000, CRC ok
    [bt0] FEL: GIC off for the hand-over (...)
    [bt0] done in ... ms, warm reset into AArch64 at 0x40000000
    [bt0] RVBAR 00000000:40000000, ...
    main>
    [main] DRAM 4096 MiB @ 0x40000000, ...
    [main] GICv3: 288 interrupt lines, ...
    [main] GMAC0: Maxio MAE0621A-Q3C configured, ...
    [main] USB: combo0 off (usb-hs-only): blue port high speed on EHCI1
    [main] PSCI 1.0 ready; entering payload @ 0x41000000 in EL2
    UEFI firmware (version oreboot-edk2 ...)
    ...
     Radxa Cubie A7A UEFI  (Allwinner A733)  oreboot + EDK2
    [Bds]Booting UEFI USB DISK ...
    GRUB ...
    [    0.000000] Linux version 7.3.3-300.fc45.aarch64 ...
    ...
    localhost login:

## Recovery

- Anything stuck: **unplug and replug USB-C** (a power cycle). With no
  bootable SD card the board comes back in FEL.
- If bt0 prints `no warm reset 1 s after the request`, its watchdog resets
  the board back into FEL about 16 s later.
- A refusal at entry 2 leaves the board in FEL: fix the images and run
  `make fel-boot` again (entry 1 has to run again after a power cycle).
- Nothing in this flow writes the SD card, the SPI NOR flash or the eFuses.

## Images

`make fel-image` builds the current preferred FEL image: vendor-library DRAM
init, main with `gmac usb usb-hs-only trng` (the SMCCC TRNG on the Crypto
Engine, which Linux uses as `/dev/hwrng`), and EDK2 DEBUG with USB, Ethernet
and display. Use the root image from the same commit (`make fedora-image`),
since the firmware embeds the device tree that the image's
`cubie-a7a-dtb` expects.

## Fastboot over FEL

**Works on a development build of bt0; not in this workspace yet** (no
build target here produces it). After its FEL entry for DRAM init, this bt0
enumerates on the USB-C port as a fastboot device (`18d1:4ee0`, product
`cubie-a7a`) instead of handing back to FEL, and the stock `fastboot` tool
talks to it:

- `fastboot stage <file>` / `download`: into DRAM, up to 128 MiB per
  transfer (`max-download-size`);
- `fastboot fetch download <file>`: reads the downloaded data back;
  `fetch` also reads (only reads) the USB disk, the SD card and the SPI NOR;
- `fastboot boot` with a firmware bundle (oreboot main + EDK2, the same
  layout table as entry 2): bt0 checks the images' CRCs and hands over as
  in [Boot](#boot) step 5;
- `fastboot reboot-bootloader` or `oem fel`: back to the mask ROM's FEL
  with DRAM still up; `fastboot reboot`: watchdog reset, back in FEL after
  about 1.8 s;
- `oem help`, `oem log`, `oem read32`: diagnostics.

It writes no storage: there is no `flash` for the microSD or a USB disk.
SPI NOR writes exist only in a separate, guarded build, which is not used.

Measured on the board on 2026-11-12 (MB = 10^6 bytes):

| | Earlier build | Current build |
|---|---|---|
| Download (64 and 128 MiB) | 10.3 MB/s | **25.7 MB/s** |
| Upload (`fetch download`) | not available | **40-42.6 MB/s** |
| Bundle check at `boot` (5 MiB bundle) | 1031 ms | 29 ms |
| `reboot-bootloader` to FEL | 0.4-0.7 s | 0.4-0.7 s |

- The gain comes from double-buffered USB endpoints, fewer register
  accesses per packet and running with the MMU and data cache on.
  Transfers are still programmed I/O, without USB DMA. The USB-C port is
  USB 2.0 OTG (the only USB 3 port is a Type-A host port), so USB 2.0 high
  speed is the ceiling.
- All 24 round trips were bit-exact, including odd sizes, single short
  packets and exact multiples of 512 bytes. A host that stalls or cancels
  a transfer in either direction leaves the device usable after a 5 s
  timeout. Every way out (`reboot-bootloader`, `oem fel`, giving up after
  four failed USB sessions, `boot`) leaves memory coherent: the MMU and data
  cache are off and the data is in DRAM.
- `boot` with the current build reaches EDK2. Not yet re-tested with it:
  booting on to Fedora, and a 1 GB read from the USB disk.
- Open: a lab build that runs DRAM training experiments and returns the
  results over fastboot does not come back to FEL through its watchdog
  reset after a DRAM run (it does without one); that needs a USB-C replug.
