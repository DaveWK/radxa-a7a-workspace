#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Assemble a boot firmware region and an SD card image (GPT + firmware + ESP).

    mkcard.py region --manifest REGION.toml --out DIR
    mkcard.py card --firmware DIR --out sdcard.img [--esp-start BYTES]
                   [--esp-size MIB] [--esp-dir DIR] [--esp-label NAME]
                   [--reproducible]

region: places the board's images (each already in its boot ROM's format,
e.g. an eGON-wrapped bt0, and a layout table from tools/bootlayout.py) at
fixed card offsets, refusing overlaps and images that run past their limit,
and writes DIR/firmware.bin (everything from `start` up, padded to whole
sectors) and DIR/firmware.seek (`start` in 512-byte sectors). The manifest:

    start = 0x20000          # where firmware.bin begins on the card
    [[image]]
    name = "bt0"
    file = "build/oreboot/bt0-egon.bin"   # relative to the manifest
    offset = 0x20000
    limit = 0x1ff000         # optional: the image must end below this
    # optional, top level: end = 0x1000000, the default limit of every image

card: a GPT card image with the firmware region at its sector and one FAT32
EFI system partition at `esp-start` (default 16 MiB): the region is written
first, then the GPT (sfdisk), and the image is refused if partitioning
touched the firmware region. --reproducible makes mkfs.fat and sfdisk use
fixed identifiers (mkfs.fat --invariant, fixed disk and partition GUIDs), so
the same inputs give the same image.

Generalised from scripts/mkimage.py (whose A733 eGON wrapping and boot
layout table stay with the board and lib/bootlayout.py); with the same
images it writes the same firmware.bin, and the same card apart from the
identifiers mkfs.fat and sfdisk pick.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

SECTOR = 512
GPT_END = 34 * SECTOR
ESP_TYPE = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
FIXED_DISK_GUID = "6F8B1A2C-0E5D-4B7A-9C3E-2D1F0A4B5C6D"
FIXED_ESP_GUID = "1B2C3D4E-5F60-4718-8293-A4B5C6D7E8F9"


def align(n, a):
    return (n + a - 1) // a * a


def place(buf: bytearray, offset: int, data: bytes, what: str, limit: int):
    end = offset + len(data)
    if end > limit:
        sys.exit(f"{what}: ends at {end:#x}, beyond {limit:#x}")
    if any(buf[offset:end]):
        sys.exit(f"{what}: overlaps another image at {offset:#x}")
    buf[offset:end] = data


def build_region(start: int, images, end_limit=None):
    """images: (name, offset, data, limit or None). Returns the card bytes
    from 0 up to the last image, sector-aligned (zero below `start`)."""
    if start % SECTOR:
        sys.exit(f"start {start:#x} is not sector-aligned")
    last = max(off + len(d) for _, off, d, _ in images)
    disk = bytearray(align(last, SECTOR))
    for name, off, data, limit in images:
        if off < start:
            sys.exit(f"{name}: at {off:#x}, below the region start {start:#x}")
        lim = limit if limit is not None else (end_limit or len(disk))
        place(disk, off, data, name, lim)
    return disk


def cmd_region(a):
    manifest = tomllib.loads(a.manifest.read_text())
    base = a.manifest.parent
    start = manifest["start"]
    images = []
    for img in manifest.get("image", []):
        path = Path(img["file"])
        if not path.is_absolute():
            path = base / path
        images.append((img["name"], img["offset"], path.read_bytes(), img.get("limit")))
    if not images:
        sys.exit("manifest has no [[image]]")
    disk = build_region(start, images, manifest.get("end"))
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "firmware.bin").write_bytes(disk[start:])
    (a.out / "firmware.seek").write_text(f"{start // SECTOR}\n")
    print(
        f"firmware.bin: {len(disk) - start} bytes, write at offset {start:#x}"
        f" (sector {start // SECTOR})"
    )


def make_esp(path, size_mib, esp_dir, label, reproducible):
    cmd = ["mkfs.fat", "-F", "32", "-n", label, "-C", path, str(size_mib * 1024)]
    if reproducible:
        cmd.insert(1, "--invariant")
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
    if esp_dir:
        if not shutil.which("mcopy"):
            sys.exit("--esp-dir needs mtools (mcopy)")
        for name in sorted(os.listdir(esp_dir)):
            subprocess.run(
                ["mcopy", "-s", "-i", path, os.path.join(esp_dir, name), "::"],
                check=True,
            )


def write_gpt(img_path, esp_start, esp_sectors, reproducible):
    """Protective MBR + GPT with one EFI system partition at esp_start."""
    if not shutil.which("sfdisk"):
        sys.exit("the card image needs sfdisk (util-linux)")
    script = "label: gpt\n"
    part = (
        f"start={esp_start // SECTOR}, size={esp_sectors}, "
        f'type={ESP_TYPE}, name="ESP"'
    )
    if reproducible:
        script += f"label-id: {FIXED_DISK_GUID}\n"
        part += f", uuid={FIXED_ESP_GUID}"
    subprocess.run(
        ["sfdisk", "--quiet", "--no-reread", "--no-tell-kernel", img_path],
        input=(script + part + "\n").encode(),
        check=True,
    )


def cmd_card(a):
    fw = (a.firmware / "firmware.bin").read_bytes()
    seek = int((a.firmware / "firmware.seek").read_text().split()[0])
    start = seek * SECTOR
    if start < GPT_END:
        sys.exit(f"firmware at {start:#x} would sit inside the GPT")
    if start + len(fw) > a.esp_start:
        sys.exit(
            f"firmware ends at {start + len(fw):#x}, beyond the ESP at {a.esp_start:#x}"
        )
    with tempfile.TemporaryDirectory() as tmp:
        esp = os.path.join(tmp, "esp.img")
        make_esp(esp, a.esp_size, a.esp_dir, a.esp_label, a.reproducible)
        esp_data = Path(esp).read_bytes()
    with open(a.out, "wb") as f:
        f.write(bytes(start))
        f.write(fw)
        f.write(bytes(a.esp_start - start - len(fw)))
        f.write(esp_data)
        f.write(bytes(1024 * 1024))  # room for the backup GPT
    write_gpt(str(a.out), a.esp_start, len(esp_data) // SECTOR, a.reproducible)
    with open(a.out, "rb") as f:
        f.seek(start)
        if f.read(len(fw)) != fw:
            sys.exit("card: partitioning overwrote the firmware region")
    print(
        f"{a.out}: {os.path.getsize(a.out) >> 20} MiB, GPT, ESP at {a.esp_start >> 20} MiB"
    )


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("region")
    r.add_argument("--manifest", required=True, type=Path)
    r.add_argument("--out", required=True, type=Path)
    c = sub.add_parser("card")
    c.add_argument(
        "--firmware", required=True, type=Path, help="dir with firmware.bin/.seek"
    )
    c.add_argument("--out", required=True, type=Path)
    c.add_argument("--esp-start", type=lambda x: int(x, 0), default=16 << 20)
    c.add_argument("--esp-size", type=int, default=64, help="MiB (default 64)")
    c.add_argument("--esp-dir")
    c.add_argument("--esp-label", default="ESP")
    c.add_argument("--reproducible", action="store_true")
    a = ap.parse_args()
    {"region": cmd_region, "card": cmd_card}[a.cmd](a)


if __name__ == "__main__":
    main()
