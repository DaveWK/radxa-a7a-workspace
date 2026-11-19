# radxa-a7a-workspace

U-Boot-free firmware and a Fedora 45 image for the **Radxa Cubie A7A**
(Allwinner A733: 2x Cortex-A76 + 6x Cortex-A55, LPDDR5). The workspace
builds the whole chain from the git submodules in a container, and it
includes the scripts that boot the board over USB.

    BROM (mask ROM)
      -> bt0        oreboot first stage, Rust, AArch32 in SRAM
                    (DaveWK/oreboot, branch radxa-cubie-a7a)
                    clocks, AXP318W PMIC, LPDDR5, loads the next stages
      -> main       oreboot EL3 runtime: PSCI, GICv3, devicetree, GMAC/USB
                    bring-up, SMCCC TRNG
      -> EDK2       UEFI (DaveWK/edk2-platforms, branch radxa-cubie-a7a,
                    on TianoCore EDK2)
      -> GRUB -> stock Fedora 45 kernel + board RPMs
                    (DaveWK/radxa-a7a-fedora, branch radxa-cubie-a7a)

There is no vendor boot0, TF-A or U-Boot in this chain.

**No images are hosted or distributed.** You build your own with
`make fedora-image`. Never commit or upload a built image, firmware binary or
vendor input.

## Board status (2026-11-18)

- **Boots to a Fedora 45 login over USB FEL:** bt0 → main → EDK2 → GRUB →
  Fedora 7.3.3 (stock kernel) on all 8 cores, with the root on a USB disk in
  the blue port. DRAM is 4096 MiB at 2400 MHz; these boots used the vendor
  DRAM library path (`VENDOR_DRAM=yes`, a measurement build; see "DRAM"
  below).
- **DRAM without vendor code is the default build:** no Allwinner DRAM
  library, no Synopsys PHY training firmware. It runs DRAM at 1200 MHz and
  boots Fedora: 4096 MiB, `memtester 2600M` once and a 5-minute `stress-ng`
  run with verify pass, matching the vendor-DRAM control boot. At 2400 MHz
  (`DRAM_MHZ=2400`) the kernel fails to decompress at the hand-over read
  latency of 6; at 5 Linux starts but the memory tests fail on bit 37, so
  2400 MHz is not usable yet. All of it on the 4 GB board over USB FEL: no
  card or eMMC boot, and the 6 GB board, are still to run. See
  [docs/bring-up-status.md](docs/bring-up-status.md#dram-without-vendor-code).
- **Fastboot over FEL (development build):** firmware sent at 25.7 MB/s and
  read back at about 42 MB/s over the USB 2.0 port, then booted from RAM.
  Not in this workspace yet.
- **Test boots use a read-only root** with the HAT, Wi-Fi and USB 3 stack
  off by default, with separate maintenance and full entries
  ([details](docs/bring-up-status.md#test-boots-protective-entries)).
- **SD slot (our board):** it booted the same chain from microSD until
  2026-11-11. Since then every card reports `SD init failed: NoCard` and the
  slot's data lines read low. A fault in the slot's supply is suspected but
  not measured; until it is fixed, this board boots over USB FEL.
- **Works:** Gigabit Ethernet (about 108 MiB/s each way, no errors), SMCCC
  TRNG (Linux `/dev/hwrng`, EFI RNG), PSCI with warm reboot, EHCI/xHCI in
  firmware, HDMI in EDK2 at the monitor's native mode, and in Linux the
  sunxidrm display, the cedrus video decoder (`/dev/video0`), the NPU
  (`/dev/vipcore`, self-test passes), and Wi-Fi scan and Bluetooth with the
  AIC8800 package built from a local driver tree (`AIC8800_SRC`).
- **Not yet:** the GPU (its power domains are now switched on only on
  demand, but GPU_CORE still does not come up, so no rendering), cpufreq, a
  error-free 2400 MHz on our own DRAM driver, and a cause for three
  memory-corruption oopses on 2026-11-12 (two followed the Wi-Fi driver's
  start). Persistent UEFI variables on the card are built
  (`-D SD_VARSTORE_ENABLE=TRUE`) but not yet confirmed on the board.

Details: [docs/bring-up-status.md](docs/bring-up-status.md).

## FEL transaction safety

Use the [port-bound FEL session](docs/fel-session.md) for boot or reset. The
cached runner requires preflight and a separate, board-specific identity
clearance before any host DRAM upload. The serial capture check detects
rotation, shrinkage and a rewrite of the 4 KiB before the attempt cursor.
The capture has no producer generation or firmware attempt token:
copytruncate followed by regrowth that reproduces those bytes, or an
unmarked reset, cannot be detected by the host. Serial attribution is limited
to the defined markers in the ACKed attempt window; the cached runner's
per-boot identity check is an independent second gate.

## Build

    git clone --recurse-submodules https://github.com/DaveWK/radxa-a7a-workspace.git
    cd radxa-a7a-workspace
    podman build -t a7a-build -f Containerfile .
    podman run --rm --userns=keep-id --security-opt label=disable \
      -v "$PWD":/w -w /w a7a-build make firmware fel-image rpms
    podman run --rm --privileged -v "$PWD":/w -w /w a7a-build make fedora-image

`make fedora-image` installs aarch64 Fedora packages and runs their
scriptlets (DKMS, initramfs) under `qemu-aarch64-static`. In the container it
needs `--privileged` to mount the container's own `binfmt_misc` instance and
register the handler there (Linux 6.7 or later; nothing changes on the host).
It also needs network access to Fedora's mirrors. You can also build on a
Fedora 45 host with the packages in `Containerfile`; there
`qemu-user-static-aarch64` registers the handler.

| Target | Output |
|---|---|
| `make dtb` | `out/dtb/sun60i-a733-cubie-a7a.dtb` |
| `make firmware` | `out/firmware/firmware.bin` + `firmware.seek`: bt0, layout table, main, EDK2 (with the DTB), for the SD card or the eMMC at sector 256 |
| `make fel-image` | `out/fel/<mode>-<mhz>/` (`blobfree-1200`, `blobfree-2400`, `dramlib-2400`, `phyfw-2400`): `bt0-fel.bin`, `firmware.bin`, `firmware.seek` and `build-manifest.json`; intermediates and the cargo target under `build/` |
| `make xfel` | `out/tools/xfel`: xfel v1.4.0 built from source with a 60 s USB timeout |
| `make fel-boot` | workspace maintenance boot of the selected bundle; requires `FEL_PORT` and `FEL_SERIAL_LOG` |
| `make rpms` | `out/fedora/rpmbuild/`: the `cubie-a7a-*` SRPMs and RPMs |
| `make fedora-image` | `out/image/a7a-fedora45.img`: GPT, `firmware.bin` at sector 256, ESP, Fedora 45 root (grows to the card on first boot) |
| `make serial` | UART0 logger: picocom in a detached screen session, logs in `serial-logs/` |
| `make test` | host tests of the board crates and script checks |
| `make vendor` | measurement builds only (`VENDOR_DRAM=yes`, `phyfw`, `FEL_DRAM=dramlib`): `vendor/dramlib/libdram`, the vendor DRAM library object, downloaded with `aria2c` from its public source and checked by SHA-256 (see "Vendor inputs") |

Options: `DRAM_MHZ=1200|2400`, `VENDOR_DRAM=yes` (see "DRAM"),
`BRINGUP=`/`FEL_BRINGUP=` (features of oreboot main), `EDK2_TARGET=DEBUG|RELEASE`,
`EDK2_ARGS=`, `AIC8800_SRC=<tree>` (Wi-Fi driver, see
[fedora/README.md](fedora/README.md)), `FWREPO=<tree>` (firmware log reader
package). `make help` lists them.

The SD/eMMC bt0 build ignores the caller's Cargo-home configuration and
rejects unapproved Cargo config in the workspace and source ancestors. For
`make fedora-image`, the raw bt0 must match a reviewed fingerprint for the
expected DRAM profile, and the packaged firmware must begin with that bt0's
exact eGON wrapping. The fingerprints cover the pinned oreboot default at
1200 and 2400 MHz, and 1200 MHz with `OTP=yes`. Both 1200 MHz entries map to
`blobfree-1200`: the check proves the DRAM profile, not which OTP variant was
built. Unknown bytes, including unlisted measurement builds, are not put
into an image. Changes to the oreboot pin or toolchain can invalidate the
fingerprints. Refresh `scripts/sd-bt0-fingerprints.json` from independently
reproduced SD/eMMC bt0 builds when changing either or adding a build variant.

Image policy: root is the only login, the password is `Fedora123`, sshd and
DHCP are on, and there are no SSH keys of anyone in the image (host keys
are generated on first boot). Change the password on first login.

## Boot it

**USB FEL boot:** use the two-stage runner for cached-board briefs. For
workspace maintenance, build with `make xfel` and `make fel-image` before
using `make fel-boot` with `FEL_PORT` and the registered `FEL_SERIAL_LOG`.
The selector and maintenance procedure are in
[docs/usb-fel-boot.md](docs/usb-fel-boot.md).

**SD card**: write `out/image/a7a-fedora45.img` to a microSD card, or write
only `out/firmware/firmware.bin` at sector 256 of an existing card. See
[docs/sd-card.md](docs/sd-card.md).

**Fastboot over FEL works on a development build, not yet in this
workspace.** bt0 enumerates as a fastboot device after DRAM init; the host
sends the firmware into RAM and boots it. It does not write the microSD or
any other storage yet. See
[docs/usb-fel-boot.md](docs/usb-fel-boot.md#fastboot-over-fel).

**Installing** the firmware and an OS (Fedora today; Debian planned; going
back to Radxa's images): [docs/flashing.md](docs/flashing.md).

Serial console: UART0 at 115200 8N1 (`make serial`; `scripts/serial-log.sh
attach` reattaches).

## DRAM

By default `bt0`, and the FEL `bt0`, bring DRAM up with this project's own
LPDDR5 driver (`cubie-a7a-dram` in the oreboot branch) and nothing from a
vendor: no DRAM library, no PHY training firmware, no PHY sequencer image.
All training runs on the CPU in `bt0`, with the settings of the board runs
built in, so `make firmware` and `make fel-image` need no `make vendor`.

- `DRAM_MHZ=1200|2400` picks the DRAM clock of those settings. Unset, it is
  the firmware's default, 1200, the clock Fedora boots at. 2400 is there
  for the work on it: it does not boot Linux yet (see the status above). The
  vendor paths run 2400 MHz. The profile is part of the bundle path
  (`out/fel/<mode>-<mhz>/`) and `scripts/fel-check.py` verifies it.
- `VENDOR_DRAM=yes`: measurement build. DRAM init through Allwinner's DRAM
  library, linked into bt0 from `vendor/` (run `make vendor` first), at
  2400 MHz. It is also what the 8 and 12 GB boards need for now: their
  parameter sets run another DRAM clock, which our driver's stages refuse.
  The build does not authorize a measurement boot.
- `VENDOR_DRAM=phyfw`: measurement build. Our driver with the PHY's own
  training firmware, read from the library object as data (`make vendor` as
  well). The build does not authorize a measurement boot.

One setting of our driver can be changed for a build by its `A7A_*`
variable in the environment; the board README in `firmware/oreboot`
(`src/mainboard/radxa/cubie-a7a/`) lists how. Earlier spellings:
`BLOBLESS=yes` and `FEL_DRAM=open` are the default now, and
`FEL_DRAM=dramlib` still builds only the FEL `bt0` with the library, for
measurements.

When our driver's training does not end clean, `bt0` halts instead of
booting: over USB FEL the board stays in FEL and records the failure in
the mailbox; from a card the next start enters FEL.

## Vendor inputs

The default firmware build reads no closed input. The measurement builds
(`VENDOR_DRAM=yes`, `VENDOR_DRAM=phyfw` and `FEL_DRAM=dramlib`) read one,
Allwinner's A733 DRAM library object from the Tina SDK
(`gitlab.com/tina5.0_aiot/lichee/dramlib`, commit `35e84c83`,
`sun60iw2p1/spl_libdram/libdram`). `make vendor` downloads it to `vendor/`
(gitignored) with `aria2c` and checks its SHA-256. It is never committed here
or in any submodule. Firmware built with it contains vendor code or data:
keep it for your own use.

No other closed binaries are involved: EDK2, oreboot and the board RPMs are
built from source, and the Fedora image takes its firmware files from
Fedora's own packages.

## Layout

| Path | What |
|---|---|
| `firmware/oreboot` | DaveWK/oreboot `radxa-cubie-a7a` (on `sbc-common`): bt0, main, the DRAM driver in `src/mainboard/radxa/cubie-a7a/`, shared crates in `src/lib/` |
| `firmware/edk2` | TianoCore EDK2 at the pinned commit |
| `firmware/edk2-platforms` | DaveWK/edk2-platforms `radxa-cubie-a7a` (on `sbc-common`): `Platform/Radxa/CubieA7APkg`, `Silicon/Allwinner/A733Pkg`, shared packages in `OreEdk2Boot/` |
| `fedora` | DaveWK/radxa-a7a-fedora `radxa-cubie-a7a`: DTS, DKMS kmods, RPM specs, `build-rpms.sh`, `mkdevcard.sh` |
| `scripts/` | image assembly (`mkimage.py`, `lib/`), EDK2 build, USB FEL boot, xfel build, vendor fetch, serial logger, vendor-image register capture |
| `docs/` | bring-up status, USB FEL boot, SD card, flashing, sources |
| `Containerfile`, `Makefile` | build |

Update the submodules to their branch heads with
`git submodule update --remote`.

## Licence

Scripts and Makefile: GPL-2.0-only (`LICENSE`), except
`scripts/capture-a7a-vendor.sh` (BSD-2-Clause-Patent, as its header says).
The submodules carry their own licences. The vendor DRAM library is
Allwinner's and is not covered by any licence here.
