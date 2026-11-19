#!/usr/bin/env python3
"""Assemble the Cubie A7A boot firmware and an SD card image.

SD card layout (byte offsets):

    0x000000  protective MBR + GPT (sectors 0-33; sdcard.img only)
    0x020000  bt0 eGON image (default; or 0x2000 with --egon-offset 8k)
    0x1ff000  boot layout table (cubie_a7a_common::layout)
    0x200000  oreboot main      -> DRAM 0x40000000 (AArch64 EL3)
    0x300000  EDK2 FD (payload) -> DRAM 0x41000000 (EL2)
    ...       optional DTB
    8 MiB     UEFI variable store window, up to 12 MiB (EDK2
              SD_VARSTORE_ENABLE; never part of firmware.bin)
    16 MiB    first partition (FAT32 ESP in sdcard.img)

Earlier versions could also store a vendor SPL (or a second bt0) at
0x780000 as layout kind 4, which bt0 ran after a failed boot. bt0 goes to
the mask ROM's FEL instead now, and this tool no longer writes that entry;
bt0 still accepts it in the table of a card written before and never loads
it.

The A733 mask ROM looks for eGON at 8 KiB and at 128 KiB. 128 KiB is where
Radxa puts boot0 (u-boot-aw2501 setup.sh, sector 256) because RadxaOS
images use GPT, whose entry array covers 8 KiB. The firmware then leaves
the GPT and everything from 12 MiB up (Radxa's boot package, RadxaOS
partitions at 16/32 MiB) alone.

Outputs:
    firmware.bin   everything from the eGON offset up
    firmware.seek  that offset in 512-byte sectors, for `make flash`
    sdcard.img     GPT + firmware + FAT32 ESP (optional, --sdcard)

The A733 parts stay here: the eGON wrapping and the offsets, addresses and
limits above. The layout table is
scripts/lib/bootlayout.py (magic A7ABOOT1, version 1); placing the images
and the card image (GPT, ESP) are scripts/lib/mkcard.py.
"""

import argparse
import importlib.util
import os
import struct
import sys
import zlib
from pathlib import Path

TOOLS = Path(__file__).resolve().parent / "lib"


def _tool(name):
    spec = importlib.util.spec_from_file_location(
        f"ore_edk2_boot_{name}", TOOLS / f"{name}.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bootlayout = _tool("bootlayout")
mkcard = _tool("mkcard")

SECTOR = 512
EGON_PAD = 8192
EGON_OFFSETS = {"8k": 0x2000, "128k": 0x20000}
GPT_END = 34 * SECTOR
EGON_STAMP = 0x5F0A6C39
# Longest image known to boot: the Cubie A7A vendor card's boot0 (SPL-2.0
# preboot, DRAM library V0.6036) has eGON length 0x4a000; Radxa's older A733
# boot0 had 0x3c000. bt0's linker script separately keeps image + bss + stack
# below 0x90000.
EGON_MAX = 0x4A000

TABLE_OFFSET = 0x1FF000
TABLE_MAGIC = b"A7ABOOT1"
TABLE_VERSION = 1

KIND_MAIN = 1
KIND_PAYLOAD = 2
KIND_DTB = 3

MAIN_OFFSET = 0x200000
MAIN_ADDR = 0x40000000
MAIN_MAX = 512 * 1024
PAYLOAD_OFFSET = 0x300000
PAYLOAD_ADDR = 0x41000000
DTB_ADDR = 0x48000000

FIRMWARE_END = 16 * 1024 * 1024
ESP_START = FIRMWARE_END
# EDK2's variable store window (CubieA7A.dsc PcdSdVarStoreLba 16384): every
# image here must end below it, so writing firmware.bin never touches the
# saved UEFI variables.
VARSTORE_START = 8 * 1024 * 1024


def align(n, a):
    return (n + a - 1) // a * a


def egon(bt0: bytes) -> bytes:
    """Fix up length and checksum like SyterKit's mksunxi, padded to 8 KiB.

    Every boot0 the A733 BROM is known to accept (Allwinner's, Armbian's
    Cubie A7Z and Orange Pi 4 Pro ones, dlan17's U-Boot SPL) has an 8 KiB
    multiple as its length, and U-Boot's mkimage pads to 8 KiB too.
    """
    if bt0[4:12] != b"eGON.BT0":
        sys.exit("bt0: no eGON.BT0 header; is this the raw bt0 binary?")
    length = align(len(bt0), EGON_PAD)
    if length > EGON_MAX:
        sys.exit(f"bt0: {length} bytes exceeds {EGON_MAX:#x}, the vendor boot0 length")
    img = bytearray(bt0) + bytes(length - len(bt0))
    struct.pack_into("<II", img, 12, EGON_STAMP, length)
    csum = sum(struct.unpack_from(f"<{length // 4}I", img)) & 0xFFFFFFFF
    struct.pack_into("<I", img, 12, csum)
    return bytes(img)


def layout_table(entries) -> bytes:
    """entries: list of (kind, offset, data, load_addr)."""
    try:
        return bootlayout.layout_table(entries, TABLE_MAGIC, TABLE_VERSION)
    except ValueError as e:
        sys.exit(str(e))


def build_firmware(bt0, main, payload, dtb, egon_offset):
    if len(main) > MAIN_MAX:
        sys.exit(f"main: {len(main)} bytes exceeds {MAIN_MAX}")
    entries = [
        (KIND_MAIN, MAIN_OFFSET, main, MAIN_ADDR),
        (KIND_PAYLOAD, PAYLOAD_OFFSET, payload, PAYLOAD_ADDR),
    ]
    if dtb is not None:
        dtb_offset = align(PAYLOAD_OFFSET + len(payload), 0x100000)
        entries.append((KIND_DTB, dtb_offset, dtb, DTB_ADDR))

    images = [
        ("bt0", egon_offset, egon(bt0), TABLE_OFFSET),
        ("layout table", TABLE_OFFSET, layout_table(entries), MAIN_OFFSET),
    ]
    for kind, off, data, _ in entries:
        images.append((f"kind {kind}", off, data, VARSTORE_START))
    disk = mkcard.build_region(egon_offset, images)
    return disk, entries


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--bt0", help="raw bt0 binary (objcopy -O binary)")
    ap.add_argument("--main", help="raw oreboot main binary")
    ap.add_argument("--payload", help="EDK2 FD")
    ap.add_argument("--dtb", help="optional DTB to load (not consumed yet)")
    ap.add_argument("--out", help="output directory")
    ap.add_argument(
        "--egon",
        metavar="FILE",
        help="only wrap --bt0 into its eGON image and write FILE (the stage for"
        " a slot-staging tool)",
    )
    ap.add_argument(
        "--egon-used",
        metavar="FIRMWARE_BIN",
        help="only print the eGON length of the bt0 at the start of FIRMWARE_BIN"
        " (stage-slot.py --base-used)",
    )
    ap.add_argument(
        "--sdcard", action="store_true", help="also build sdcard.img with a FAT32 ESP"
    )
    ap.add_argument(
        "--esp-size", type=int, default=64, help="ESP size in MiB (default 64)"
    )
    ap.add_argument(
        "--esp-dir", help="directory whose contents are copied into the ESP"
    )
    ap.add_argument(
        "--egon-offset",
        choices=EGON_OFFSETS,
        default="128k",
        help="where bt0 goes on the card (default 128k; 8k only on MBR disks)",
    )
    a = ap.parse_args()
    read = lambda p: open(p, "rb").read()
    if a.egon_used:
        base = read(a.egon_used)
        if base[4:12] != b"eGON.BT0":
            sys.exit(f"{a.egon_used}: does not start with an eGON.BT0 header")
        print(struct.unpack_from("<I", base, 16)[0])
        return
    if a.egon:
        if not a.bt0:
            ap.error("--egon needs --bt0")
        with open(a.egon, "wb") as f:
            f.write(egon(read(a.bt0)))
        return
    missing = [o for o in ("bt0", "main", "payload", "out") if not getattr(a, o)]
    if missing:
        ap.error("required: " + ", ".join("--" + o for o in missing))
    egon_offset = EGON_OFFSETS[a.egon_offset]
    if a.sdcard and egon_offset < GPT_END:
        sys.exit("--egon-offset 8k would sit inside the GPT of sdcard.img")

    disk, entries = build_firmware(
        read(a.bt0),
        read(a.main),
        read(a.payload),
        read(a.dtb) if a.dtb else None,
        egon_offset,
    )
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "firmware.bin"), "wb") as f:
        f.write(disk[egon_offset:])
    with open(os.path.join(a.out, "firmware.seek"), "w") as f:
        f.write(f"{egon_offset // SECTOR}\n")
    print(
        f"firmware.bin: {len(disk) - egon_offset} bytes, write at offset {egon_offset:#x}"
        f" (sector {egon_offset // SECTOR})"
    )
    names = {
        KIND_MAIN: "main",
        KIND_PAYLOAD: "payload",
        KIND_DTB: "dtb",
    }
    for kind, off, data, addr in entries:
        print(
            f"  {names[kind]:8s} sd {off:#09x}  {len(data):8d} bytes -> {addr:#010x}"
            f"  crc32 {zlib.crc32(data):08x}"
        )

    if a.sdcard:
        mkcard.cmd_card(
            argparse.Namespace(
                firmware=Path(a.out),
                out=Path(a.out) / "sdcard.img",
                esp_start=ESP_START,
                esp_size=a.esp_size,
                esp_dir=a.esp_dir,
                esp_label="CUBIEESP",
                reproducible=False,
            )
        )


if __name__ == "__main__":
    main()
