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

## Board status (2026-11-12)

- **Boots to a Fedora 45 login over USB FEL:** bt0 → main → EDK2 → GRUB →
  Fedora 7.3.3 (stock kernel) on all 8 cores, with the root on a USB disk in
  the blue port. DRAM is 4096 MiB at 2400 MHz through the vendor DRAM library
  path (the default, see "DRAM" below).
- **SD slot (our board):** it booted the same chain from microSD until
  2026-11-11. Since then every card reports `SD init failed: NoCard` and the
  slot's data lines read low. The cause is not established yet; until it is,
  this board boots over USB FEL.
- **Works:** Gigabit Ethernet (about 108 MiB/s each way, no errors), SMCCC
  TRNG (Linux `/dev/hwrng`, EFI RNG), PSCI with warm reboot, EHCI/xHCI in
  firmware, HDMI in EDK2 at the monitor's native mode, and in Linux the
  sunxidrm display, the cedrus video decoder (`/dev/video0`) and the NPU
  (`/dev/vipcore`, self-test passes).
- **Not yet:** the GPU (its power domain does not come up), cpufreq, the
  open DRAM driver as the default. Persistent UEFI variables on the card are
  built (`-D SD_VARSTORE_ENABLE=TRUE`) but not yet confirmed on the board.

Details: [docs/bring-up-status.md](docs/bring-up-status.md).

## Build

    git clone --recurse-submodules https://github.com/DaveWK/radxa-a7a-workspace.git
    cd radxa-a7a-workspace
    podman build -t a7a-build -f Containerfile .
    podman run --rm --userns=keep-id --security-opt label=disable \
      -v "$PWD":/w -w /w a7a-build make vendor firmware fel-image rpms
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
| `make vendor` | `vendor/dramlib/libdram`: the vendor DRAM library object, downloaded from its public source and checked by SHA-256 (see "Vendor inputs") |
| `make dtb` | `out/dtb/sun60i-a733-cubie-a7a.dtb` |
| `make firmware` | `out/firmware/firmware.bin` + `firmware.seek`: bt0, layout table, main, EDK2 (with the DTB), for the SD card at sector 256 |
| `make fel-image` | `out/fel/`: `bt0-fel.bin` (bt0 linked at 0x90000) and a `firmware.bin` whose main runs USB in high-speed mode |
| `make xfel` | `out/tools/xfel`: xfel v1.4.0 built from source with a 60 s USB timeout |
| `make fel-boot` | boots the board over USB FEL with `out/fel/` (run on the host, see below) |
| `make rpms` | `out/fedora/rpmbuild/`: the `cubie-a7a-*` SRPMs and RPMs |
| `make fedora-image` | `out/image/a7a-fedora45.img`: GPT, `firmware.bin` at sector 256, ESP, Fedora 45 root (grows to the card on first boot) |
| `make serial` | UART0 logger: picocom in a detached screen session, logs in `serial-logs/` |
| `make test` | host tests of the board crates and script checks |

Options: `VENDOR_DRAM=yes|no`, `BLOBLESS=yes`, `FEL_DRAM=dramlib|open`,
`BRINGUP=`/`FEL_BRINGUP=` (features of oreboot main), `EDK2_TARGET=DEBUG|RELEASE`,
`EDK2_ARGS=`, `AIC8800_SRC=<tree>` (Wi-Fi driver, see
[fedora/README.md](fedora/README.md)), `FWREPO=<tree>` (firmware log reader
package). `make help` lists them.

Image policy: root is the only login, the password is `Fedora123`, sshd and
DHCP are on, and there are no SSH keys of anyone in the image (host keys
are generated on first boot). Change the password on first login.

## Boot it

**USB FEL boot** is the current path, with no SD card needed. Full
instructions are in [docs/usb-fel-boot.md](docs/usb-fel-boot.md):

    dd if=out/image/a7a-fedora45.img of=/dev/sdX bs=4M conv=fsync   # USB disk, blue port
    make xfel                       # once
    make fel-boot                   # board in FEL on this host's USB (its USB-C port)

**SD card**: write `out/image/a7a-fedora45.img` to a microSD card, or write
only `out/firmware/firmware.bin` at sector 256 of an existing card. See
[docs/sd-card.md](docs/sd-card.md).

**Fastboot over FEL is planned, not implemented.** The idea is a bt0 that
enumerates as a fastboot device, so the microSD can be flashed over USB.
See [docs/usb-fel-boot.md](docs/usb-fel-boot.md#planned-fastboot-over-fel).

Serial console: UART0 at 115200 8N1 (`make serial`; `scripts/serial-log.sh
attach` reattaches).

## DRAM

`bt0` has three DRAM paths. The default is the one that boots today, and the
open ones stay available as options:

- `VENDOR_DRAM=yes` (default): DRAM init through Allwinner's DRAM library,
  which is linked into bt0 from `vendor/`.
- `VENDOR_DRAM=no`: the open LPDDR5 driver (`cubie-a7a-dram` in the oreboot
  branch) does the controller and PHY set-up. Only the PHY's own training
  firmware is read from the library object, as data.
- `BLOBLESS=yes`: no vendor input at all. This development stage runs the
  open PHY training stages and then halts.

## Vendor inputs

The firmware build reads one closed input, Allwinner's A733 DRAM library
object from the Tina SDK
(`gitlab.com/tina5.0_aiot/lichee/dramlib`, commit `35e84c83`,
`sun60iw2p1/spl_libdram/libdram`). `make vendor` downloads it to `vendor/`
(gitignored) and checks its SHA-256. It is never committed here or in any
submodule. Firmware built with it contains vendor code or data: keep it for
your own use.

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
| `docs/` | bring-up status, USB FEL boot, SD card, sources |
| `Containerfile`, `Makefile` | build |

Update the submodules to their branch heads with
`git submodule update --remote`.

## Licence

Scripts and Makefile: GPL-2.0-only (`LICENSE`), except
`scripts/capture-a7a-vendor.sh` (BSD-2-Clause-Patent, as its header says).
The submodules carry their own licences. The vendor DRAM library is
Allwinner's and is not covered by any licence here.
