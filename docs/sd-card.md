# SD card

The A733 mask ROM loads bt0 (eGON image) from the microSD card at 128 KiB
(sector 256), behind the card's GPT. The firmware region ends below 8 MiB,
and the first partition starts at 16 MiB.

| Offset | What |
|---|---|
| 0 | protective MBR + GPT |
| 0x020000 (sector 256) | bt0 (eGON) = start of `firmware.bin` |
| 0x1ff000 | boot layout table (magic `A7ABOOT1`) |
| 0x200000 | oreboot main → DRAM 0x40000000 |
| 0x300000 | EDK2 FD → DRAM 0x41000000 |
| 8 MiB .. 12 MiB | UEFI variable store window (`-D SD_VARSTORE_ENABLE=TRUE`; never part of `firmware.bin`) |
| 16 MiB | ESP (FAT32, 512 MiB), then the Fedora root (ext4) |

## Whole image

`make fedora-image` writes `firmware.bin` into the image, so one write is
enough:

    sudo dd if=out/image/a7a-fedora45.img of=/dev/sdX bs=4M conv=fsync,sparse status=progress

The root partition grows to the card on first boot.

## Firmware only

To update only the firmware on a card whose partitions start at or after
16 MiB:

    sudo dd if=out/firmware/firmware.bin of=/dev/sdX bs=512 \
      seek=$(cat out/firmware/firmware.seek) conv=fsync,notrunc

That replaces whatever boot0 was at 128 KiB (for example a vendor image's).
Back up the card's first 16 MiB first if you want it back:
`sudo dd if=/dev/sdX of=first16M.bin bs=1M count=16`.

Check the device name with `lsblk` before any write.

## Status

The SD path booted this chain to EDK2 and Fedora until 2026-11-11. On our
board the slot has not booted any card since then (see
[bring-up-status.md](bring-up-status.md)), so we test over
[USB FEL](usb-fel-boot.md). On a board with a working slot, the image above
is the intended boot medium.
