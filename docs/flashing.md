# Installing the firmware and an OS

This page covers putting this workspace's firmware on a Radxa Cubie A7A and
running an operating system on it. It also covers going back to Radxa's own
stack. Vendor facts come from the pages in [Sources](#sources), read on
2026-11-12.

The firmware is oreboot bt0 and oreboot main, followed by EDK2 (UEFI). It
does not use Allwinner's BL31, U-Boot, OP-TEE or ARISC firmware. One closed
part remains: by default bt0 trains DRAM with Allwinner's DRAM library and
the DDR PHY's Synopsys training firmware, both taken from Allwinner's DRAM
library object. The open DRAM driver is in progress and is not the default
yet (see [README](../README.md#dram)).

## Which firmware runs

- The A733 mask ROM loads the first boot stage from a boot medium. Radxa
  documents the boot priority with the **microSD card first**, ahead of the
  eMMC/UFS module. With no bootable medium the ROM enters USB FEL
  ([usb-fel-boot.md](usb-fel-boot.md#enter-fel)).
- Whatever is at the start of that medium decides the chain:
  - a card written from this workspace runs oreboot bt0 from sector 256,
    then oreboot main and EDK2 ([sd-card.md](sd-card.md));
  - a card with Radxa's Debian image runs Allwinner's boot0 and U-Boot.
    Radxa's A733 U-Boot package writes boot0 at sector 256 (128 KiB), the
    same place as this workspace's bt0, and its boot package at 12 MiB;
  - a card or module with Radxa's Android image runs the Allwinner boot
    chain from the Android firmware package.
- Writing one kind of image over another replaces the card's firmware along
  with its partitions.
- The board has an 8 MB SPI NOR flash. This workspace does not use it and
  never writes it.
- Not tested here: an eMMC/UFS module with a system on it, or boot firmware
  in the SPI NOR (Radxa uses the SPI NOR for NVMe boot), may stop the board
  from falling back to FEL by itself when no card is inserted. If that
  happens, remove the module or use the UBOOT key (see
  [Going back to the vendor stack](#going-back-to-the-vendor-stack)).

## Before any write

Writing destroys everything on the target card or disk.

    lsblk -o NAME,SIZE,MODEL,TRAN,MOUNTPOINTS   # before and after inserting the card
    sudo umount /dev/sdX?*                      # every mounted partition (/dev/mmcblk0p* in an SD slot)

Write to the whole device (`/dev/sdX`, `/dev/mmcblk0`), not to a partition
(`/dev/sdX1`). Check the size and model, because a wrong device name
overwrites another disk. Let `dd` finish with `conv=fsync` (or run `sync`)
before you remove the card.

## Installing the firmware

| Medium | State |
|---|---|
| microSD card | **Works.** The full Fedora image carries the firmware (below). To put only the firmware onto an existing card, see [sd-card.md](sd-card.md#firmware-only) |
| USB FEL | **Works, and is the tested path today.** The host loads the firmware into the board over USB-C, so nothing is written to the board. See [usb-fel-boot.md](usb-fel-boot.md) |
| eMMC module | **Planned.** It is the next boot medium. Not documented yet |
| SPI NOR | Not used |

Our board's microSD slot has not booted any card since 2026-11-11, so we
test over USB FEL for now ([bring-up-status.md](bring-up-status.md#sd-slot)).
**Fastboot over FEL** (writing the card over USB without a card reader) is
planned and not in this repository yet
([usb-fel-boot.md](usb-fel-boot.md#planned-fastboot-over-fel)).

## Fedora on this firmware

This is the working, tested path. **No images are hosted.** Build your own
with `make fedora-image` (see [Build](../README.md#build)). The build writes
`out/image/a7a-fedora45.img` and `.img.xz`, which contain:

- `firmware.bin` at sector 256;
- a GPT with an ESP at 16 MiB;
- the Fedora 45 root (stock kernel and board RPMs), which grows to the card
  on first boot.

[sd-card.md](sd-card.md) has the full layout. The raw image is about 5.5 GB
today, so use a card or disk of at least 8 GB.

    sudo dd if=out/image/a7a-fedora45.img of=/dev/sdX bs=4M conv=fsync,sparse status=progress
    # or: xzcat out/image/a7a-fedora45.img.xz | sudo dd of=/dev/sdX bs=4M conv=fsync status=progress

- **microSD card:** the card holds both the firmware and Fedora.
- **USB disk:** write the same image to a USB disk, plug it into the blue
  USB-A port and boot over [USB FEL](usb-fel-boot.md). Radxa lists no USB
  disk among the A7A's boot media. Firmware on a microSD card with the root
  on a USB disk has not been tested.
- **Login:** `root`, password `Fedora123`. sshd and DHCP are on. Change the
  password at first login.

## Debian on this firmware (planned)

**Planned, not in this repository yet.** The plan is to build Debian like the
Fedora image: Debian's stock arm64 kernel, with this board's kernel modules
and device tree packaged for Debian, booted by EDK2 and GRUB.

Radxa's Debian image will not boot on this firmware. Radxa's image boots
through Allwinner's chain:

1. boot0;
2. U-Boot with a secure monitor (BL31) and the SCP/ARISC co-processor
   firmware;
3. U-Boot reads `/boot/extlinux/extlinux.conf` and starts Radxa's Linux 6.6
   vendor kernel (`linux-image-6.6.98-6-aw2511` in release R7).

Radxa's image recipe skips installing a UEFI boot loader. Its vendor kernel
also relies on services from that chain: BL31's SMC calls, the ARISC
firmware and the device-tree changes U-Boot makes at boot. This firmware
does not provide those services, on purpose.

## Ubuntu

No Ubuntu image is provided for the Cubie A7A, either here or by Radxa.

## Android

**Not supported on this firmware.** Radxa's Android 13 image is a Phoenix
firmware package built around Radxa's own boot0 and U-Boot. Running Android
here would need an Android boot path in UEFI. That is a research topic, with
no plan or date.

## Going back to the vendor stack

- **Radxa Debian.** Download from
  <https://github.com/radxa-build/radxa-a733/releases>. Radxa's download
  page links Debian 11 R6, and the releases page also has R7 (Debian 13).
  Use the `output_512.img.xz` image for microSD or eMMC and the
  `output_4096.img.xz` image for UFS. Check it against the release's
  `.sha512sum` file, then write it with balenaEtcher (as Radxa recommends)
  or `dd`:

      sha512sum -c --ignore-missing radxa-a733_bullseye_kde_r6.sha512sum
      xz -dk radxa-a733_bullseye_kde_r6.output_512.img.xz
      sudo dd if=radxa-a733_bullseye_kde_r6.output_512.img of=/dev/sdX bs=4M conv=fsync status=progress

  The login is `radxa` / `radxa`. The image replaces this firmware and
  everything else on the card.
- **Radxa Android 13.** Download from
  <https://github.com/radxa/allwinner-android-manifests/releases>. Radxa
  lists the 20250814 build for the AC101 audio codec and the 20260206 build
  for the AC101B codec. The 20260206 release notes say it cannot be used on
  hardware v1.0. The `.img` inside the zip is an Allwinner firmware package
  (`IMAGEWTY`), not a disk image, so `dd` and Etcher cannot write it. It
  needs Allwinner's proprietary tools, which ship as binaries without
  source:
  - **microSD card:** PhoenixCard (Windows only). Choose the `.img` under
    `Image`, select `Start up`, then click `Burn`.
  - **eMMC or UFS module:** hold the **UBOOT** key while connecting USB-C to
    enter FEL. Radxa documents this key sequence; we have not tested it with
    this workspace. Then write the image with PhoenixSuit (Windows,
    `Full Flash`) or LiveSuit (Linux; Radxa documents it on Ubuntu).
- **Only the firmware was replaced.** You may have saved the card's first
  16 MiB before writing `firmware.bin` onto a vendor card
  ([sd-card.md](sd-card.md#firmware-only)). If so, write that file back:
  `sudo dd if=first16M.bin of=/dev/sdX bs=1M conv=fsync`.
- **Back to Fedora.** Write `a7a-fedora45.img` again.

## Sources

All read on 2026-11-12.

| URL | What it verified |
|---|---|
| <https://docs.radxa.com/en/cubie/a7a/download> | Debian GPT images (R6, `512` for SD/eMMC, `4096` for UFS), Android 13 builds and codec split, PhoenixCard/PhoenixSuit/LiveSuit |
| <https://docs.radxa.com/en/cubie/a7a> | 8 MB SPI NOR; OS support: Debian Linux, Android 13 |
| <https://docs.radxa.com/en/cubie/a7a/getting-started/quickly-start> | boot priority, microSD first; boot media (no USB disk) |
| <https://docs.radxa.com/en/cubie/a7a/getting-started/install-system/sd-system> | balenaEtcher, login `radxa`/`radxa` |
| <https://docs.radxa.com/en/cubie/a7a/faq> | Phoenix images have no partition table and need the Phoenix tools |
| <https://docs.radxa.com/en/cubie/a7a/low-level-dev/install-system/sd-system> | PhoenixCard, Windows only; Image / Start up / Burn |
| <https://docs.radxa.com/en/cubie/a7a/hardware-use/uboot-key> | UBOOT key sequence for FEL |
| <https://docs.radxa.com/en/cubie/a7a/low-level-dev/install-system/fel-install-system/emmc-system> | PhoenixSuit `Full Flash`, LiveSuit on Ubuntu |
| <https://docs.radxa.com/en/cubie/a7a/other-system/android/install-system> | Android only as a Phoenix image |
| <https://github.com/radxa-docs/docs> (commit `862054f`) | Markdown source of the Radxa pages above |
| <https://github.com/radxa-build/radxa-a733/releases> | R6 (Debian 11) and R7 (Debian 13) images and `.sha512sum` files; no Ubuntu image; R7 recipe (`rsdk-r7` `config.yaml`, `build-512-image`, `manifest`): `u-boot-radxa-a733`, `u-boot-menu`, `/boot/extlinux/extlinux.conf`, "Skip systemd-boot installation", `linux-image-6.6.98-6-aw2511` |
| <https://github.com/radxa-pkg/u-boot-aw2501> | Radxa's A733 U-Boot package: `setup/u-boot_setup-allwinner-a733.sh` writes boot0 at sector 256 and the boot package at sector 24576 (12 MiB); `arisc` is a submodule of the package |
| <https://github.com/radxa/allwinner-device/blob/device-a733-v1.4.6/configs/default/boot_package.cfg> | A733 boot package: `u-boot`, `monitor`, `scp` |
| <https://github.com/radxa/allwinner-android-manifests/releases> | Android 13 A7A zips and release notes; the `.img` starts with `IMAGEWTY` and contains `boot0_sdcard.fex`, `u-boot.fex` and `boot_package.fex` (read with HTTP range requests) |
| <https://dl.radxa.com/tools/> (PhoenixCard V4.3.2, PhoenixSuit V2.0.4, LiveSuit V3.0.8 zips) | the tools are binaries (`.exe`/`.dll`, a `.run` installer) with no source |
