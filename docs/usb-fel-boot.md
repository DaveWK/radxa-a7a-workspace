# USB FEL boot and fastboot

The A733 mask ROM has a USB download mode, **FEL**. The board in FEL shows
up on the host as USB device `1f3a:efe8`. `make fel-boot`,
`scripts/fel-boot.sh` and `scripts/fel-wdt-reset.sh` own a complete
[port-bound session](fel-session.md). Use the two-stage cached runner
documented there for cached memtests.

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
  `out/tools/xfel` and its build receipt. It needs `cc`, `make`, `pkgconf` and `libusb1-devel`.
  No xfel binary is part of this repository.
- The runner account must be in `dialout`, and
  `/etc/udev/rules.d/99-a7a-fel.rules` must match `1f3a:efe8` with
  `MODE="0660"` and `GROUP="dialout"`. Installing the host rule is a separate
  approved action. The selector runs directly without elevating privileges.
- Optional: a 3.3 V USB-UART adapter on UART0 (115200 8N1), with
  `make serial`.

## Enter FEL

- With **no bootable SD card** (none inserted, or one the ROM cannot boot),
  the mask ROM falls back to FEL by itself at power-on.
- Or hold the **UBOOT/FEL key (SW2)** while plugging in USB-C.

Check with `lsusb -d 1f3a:efe8`.

## Stateless selector contract

The selector is stateless. The runner first discovers a devnum on the
assigned physical connector, then carries **both** values on each call:

```sh
devnum=$(scripts/xfel-port --discover --port "$FEL_PORT") || exit
scripts/xfel-port --port "$FEL_PORT" --devnum "$devnum" -- version
```

Discovery reads sysfs only; it never stages or starts xfel. Use `3-3.4` for
the 4 GB board and `3-6` for the 6 GB board. Do not exchange cables. Devnums
can change on reset; rediscovery is not authorization to adopt a new devnum.
The runner owns the lease, epoch transitions, reconnect policy and serial
proof. Do not dispatch raw xfel or use retired bench boot/reset helpers.

On little-endian Linux with libusb 1.0.27+ and `USBDEVFS_CONNINFO_EX`, xfel
requires `--port PATH --devnum N` before the command, checks sysfs, verifies
the address, topology and VID:PID on a single open usbfs fd, then wraps
that **same fd** without libusb rediscovery. It supports `version`, `read`,
`write`, `read32`, `write32` and `exec`. It rejects other commands before
USB access. The `version` probe checks the A733 ID, including before each
non-version command. The wrapper executes a verified private copy of
`out/tools/xfel` directly. It refuses `SUDO`, `XFEL` and
`EXPECT_XFEL_SHA256` overrides. A successful prefix or a help-compatible
replacement cannot stand in for a protocol result.

Fixed frames must complete at their exact length, and the entire A733
response must be `AWUS` followed by nine zero bytes, as checked by
[`rfel/src/fel/mod.rs`](https://github.com/rustsbi/allwinner-hal/blob/d90687bdf2012b251062db77a779350f801c3753/rfel/src/fel/mod.rs#L127-L149).
`write` buffers and checks the complete regular-file input before opening
USB; a local file or output error is not an ACK.

| Exit | Meaning |
|---|---|
| 0 | Command completed and every FEL status in it was a validated ACK; discovery only: stdout is the current decimal devnum; help only: usage. An ACK is not proof a submitted boot or reset completed. |
| 2 | Bad arguments, missing/duplicate selectors, or unsupported command. |
| 65 | Malformed FEL status or transport framing. |
| 66 | Selected connector absent from sysfs, or an explicit device-loss error at open, verification or transfer. Not a submission ACK. |
| 74 | Other transport or local I/O failure (including timeout). Do not infer device loss. |
| 76 | A well-formed rejection in the expected 8-byte status frame. |
| 125 | Identity, tool or setup refusal (including permission denied, changed devnum, wrong VID:PID/topology, unavailable verification, or an absent usbfs node whose matching sysfs identity remains). Never interpret as device loss. |
| Other | Wrapper passes the child exit through, mapping a signal to `128 + signal`. An unrecognized status is a failure. |

If an 8-byte rejection arrives instead of longer read data, the selector
classifies the short data completion as `65`. It does not reassemble short
transfers or interpret payload bytes as a status frame.
Diagnostics on stderr are best effort; a failed diagnostic write does not
replace the transfer's exit status.

`make test` includes the compiled selector suite; it requires bubblewrap.
To run that suite alone without hardware:

    python3 -I scripts/test-xfel-binary.py out/tools/xfel

`make fel-image` builds one bundle for the current DRAM mode and profile into
`out/fel/<mode>-<mhz>/` (`blobfree-1200` by default, `blobfree-2400` with
`DRAM_MHZ=2400`, `dramlib-2400` with `VENDOR_DRAM=yes` and `phyfw-2400`
with `VENDOR_DRAM=phyfw`). The bundle holds `bt0-fel.bin`, `firmware.bin`,
`firmware.seek` and `build-manifest.json`.

**Threat model:** the gate protects against accidents on a single-user
bench host: stale, mixed, mislabelled or env-contaminated builds being
booted as blob-free, and measurement builds being booted without a
recorded human authorization. It does not defend against a malicious
local user who can edit the scripts or the local records.

`make fel-image` checks the clean workspace, oreboot, board, EDK2 and
EDK2-platforms source identities before and after compilation. The three
submodule HEADs must match the workspace gitlinks. This build refuses
`OREBOOT` and `BOARD` Make overrides and inherited `EDK2_DIR` and
`EDK2_PLATFORMS_DIR`.

FEL Cargo builds use an offline, job-private home seeded only with read-only
copies of the registry index and crate archives. The gate refuses inherited
and Cargo-configured `A7A_*` and `A733_*` knobs in all modes. Use the separate
lab tooling for knob experiments. In a blob-free build the same `DRAM_MHZ`
(default 1200) selects the slot, Cargo's `A7A_PROFILE` and the reported profile.
Measurement builds require `DRAM_MHZ` to be unset and do not pass
`A7A_PROFILE` to Cargo; the mode fixes the profile at 2400.

Compilation and the packaging snapshot use private directories under the
slot's `build/` directory. EDK2 embeds the private copy of the built DTB
or of the file selected by `FEL_DTB_INPUT`. EDK2 builds serialize access
to the shared checkout with `out/.edk2-build.lock`.
Only the verified build publishes a record at
`out/fel/.records/<bt0_fel_sha256>.json`, separate from the bundle. It
records the mode, profile, features, source paths and commits, effective
build knobs, EDK2 target and arguments, DTB source path and digest, and the
intermediate and packaged digests. Rebuild old bundles: a manifest alone is
not a build record.

### Boot protocol reference for the session runner

This is a separate workspace **maintenance** path for a freshly built
bundle with a local build manifest. It uses the port, verified build record
and the board-sized mailbox, not an operator-cleared Entry 1 identity
range. Keep it out of cached-board briefs: cached sets must always use
the two-stage runner with their per-boot serial identity gate.

Build the receipt-verified selector with `make xfel` and the selected bundle
with `make fel-image` first. Use the same mode and profile for `make fel-boot`,
and set `FEL_PORT` plus `FEL_SERIAL_LOG` (the registered regular capture
file named in [the session guide](fel-session.md#capture-boundaries)).
For example, `FEL_PORT="$port" FEL_SERIAL_LOG="$log" make fel-boot DRAM_MHZ=1200`.

1. **Stage and validate**: copy the bundle into a private directory (mode
   0700). Hash the staged bt0 and use that digest to look up the local build
   record. The record, not the manifest, determines the mode and profile.
    The current `HEAD`s, requested mode and profile, bundle manifest and
    staged file digests must agree with the record. Check the layout table, payload CRCs
   and FEL window before probing USB. Staging is removed on exit; xfel sees
   only the staged bytes.
2. **Check** that the FEL device is an A733 (`xfel version`, ID `0x00190300`).
3. **Load bt0**: clear the mailbox at `0xdf000`, write the staged
   `bt0-fel.bin` (bt0 built with feature `fel`, linked at `0x90000`) and read
   it back.
4. **Entry 1** (`xfel exec 0x90040`): bt0 brings up clocks, PMIC and DRAM,
   boosts the CPUs and returns to FEL. The ROM answers `exec` before the code
   finishes, so the session polls the mailbox until it reports DRAM up and
   records the verified size and clock.
5. **Load the images**: the layout table frame goes to `0xdf200`, oreboot
   main to `0x40000000` and the EDK2 FD to `0x41000000`, all taken from the
   staged `firmware.bin`. Each write is read back and compared (SHA-256).
6. **Entry 2** (`xfel exec 0x90044`): bt0 checks the layout table and the
   images' CRCs in DRAM and turns off the GIC state the ROM left behind (its
   USB runs on interrupts, and a pending interrupt blocks the warm reset).
   It then warm-resets into main at EL3, as the SD boot does. FEL does not
   come back after this. A refusal is reported from the mailbox instead (state
   `0xe0` entry 1 not run, `0xe1` bad layout table, `0xe2` CRC mismatch), and
   the board stays in FEL.

### Measurement builds

A `dramlib` or `phyfw` bundle is a measurement build. Its authorization
file must name the exact `bt0_fel_sha256` from the local build record and a
human authorization reference (a DECISIONS date and a queue key). The file
records authorization; it grants nothing by itself. `scripts/fel-check.py`
validates the digest and reference before producing the write plan.

Build options: `DRAM_MHZ=1200|2400` (the DRAM clock of our own DRAM driver,
which is the default; 1200 unless set), `VENDOR_DRAM=yes` (the vendor DRAM
library instead; see the [README](../README.md#dram)), and `FEL_BRINGUP=`
(features of the FEL main, default `gmac usb usb-hs-only trng`).

## Expected serial output

Abridged, from a boot of this flow with the vendor DRAM library (values
vary by board and build). With the default DRAM driver the init line names
1200 MHz and the driver's `[dram]` stage lines follow it:

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

- If recovery requires a power cycle, ask the bench operator. With no
  bootable SD card the board comes back in FEL.
- If bt0 prints `no warm reset 1 s after the request`, its watchdog resets
  the board back into FEL about 16 s later.
- A refusal at entry 2 leaves the board in FEL: fix the images and run
  the reviewed session runner again (entry 1 has to run again after a power
  cycle). [Session recovery](fel-session.md#recovery) also covers failed
  reconnects and a replaced capture log.
- Nothing in this flow writes the SD card, the SPI NOR flash or the eFuses.

## Images

`make fel-image` builds the current FEL image: DRAM init by our own driver
(`VENDOR_DRAM=yes` for the vendor library, with which the boots described
here were made), main with `gmac usb usb-hs-only trng` (the SMCCC TRNG on the Crypto
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
  in [Boot protocol reference](#boot-protocol-reference-for-the-session-runner) step 6;
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
# Gated source checkouts

`make fel-image` requires full, clean workspace, oreboot, EDK2,
edk2-platforms and Fedora trees before compilation and again before
publication. Sparse checkout, hidden index entries and missing or mistyped
tracked files are refused. Initialized nested submodules must pass the same
checks at their parent's gitlink. Optional uninitialized gitlinks must be
empty; the record distinguishes them from verified checkouts.

At the pinned `439613accf` oreboot has no gitlinks. EDK2's
`BaseTools/Source/C/GNUmakefile` builds BrotliCompress from its `brotli`
submodule; `build-edk2.sh` requires BaseFdtLib's `libfdt`. The board DSC
maps BaseFdtLib and ArmTransferListLib, whose INFs use `libfdt` and `libtl`,
respectively. These three nested EDK2 checkouts must be initialized.

The default DTB is built from the workspace's Fedora gitlink. Use
`FEL_DTB_INPUT` for an external tree; booting such a blobfree bundle requires
`EXPECT_DTB_SHA256` to match the input. Before publication the gate decodes
the LZMA-guided FV from `firmware.bin` itself, checks the embedded FDT's
size and digest, and records both offsets: the section in the package and
the FDT in the decoded stream. The FDF name comes from the current EDK2
build's `BuildOptions`, including when `EDK2_ARGS` overrides the DSC default.

The first EDK2 build without `out/edk2-basetools.stamp.json` forces a C
tool rebuild under the EDK2 lock. Later builds refuse an EDK2 revision
or binary-set/digest mismatch; investigate it before intentionally starting
a new stamp. Each build records the stamp digest and the three effective
`Conf` file digests, checked on both sides of the build under that lock.

Run `make xfel` to produce the tool and its `out/tools/xfel.record.json`.
Before any USB access, the selector verifies the receipt against the
tracked source seals, copies and hashes the tool in one pass, then runs only
the verified private copy. Caller-provided digests are not accepted.
