#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Validate a staged FEL bundle before fel-boot touches USB.

The digest of staged bt0 selects a workspace-local build record. Check the
manifest and staged files against it, then extract and validate a write plan.
Only a recorded measurement authorization permits a dramlib or phyfw bundle.
"""

import argparse
import importlib.util
import os
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fel_manifest = load_module("fel_manifest", HERE / "fel-manifest.py")
image = load_module("mkimage", HERE / "mkimage.py")

ROOT = HERE.parent
BT0_FEL_END = 0xDF000
BT0_FEL_BASE = 0x90000
KINDS = {
    image.KIND_MAIN: ("main", image.MAIN_ADDR, image.MAIN_OFFSET, image.MAIN_MAX),
    image.KIND_PAYLOAD: (
        "edk2-fd",
        image.PAYLOAD_ADDR,
        image.PAYLOAD_OFFSET,
        image.VARSTORE_START - image.PAYLOAD_OFFSET,
    ),
    image.KIND_DTB: ("dtb", image.DTB_ADDR, None, image.VARSTORE_START),
}


def prepare_layout(bundle, work):
    size = (bundle / "bt0-fel.bin").stat().st_size
    if not 0x48 <= size <= BT0_FEL_END - BT0_FEL_BASE:
        raise ValueError(f"bt0-fel.bin size {size} is outside the FEL SRAM window")

    base = int((bundle / "firmware.seek").read_text()) * image.SECTOR
    if base not in image.EGON_OFFSETS.values():
        raise ValueError("invalid firmware.seek")
    firmware = bundle / "firmware.bin"
    if firmware.stat().st_size > image.VARSTORE_START - base:
        raise ValueError("firmware.bin extends beyond the firmware window")
    contents = firmware.read_bytes()
    pos = image.TABLE_OFFSET - base
    frame = contents[pos : pos + image.SECTOR]
    if len(frame) != image.SECTOR:
        raise ValueError("missing layout table frame")
    magic, version, count, crc_ok, entries = image.bootlayout.parse_table(frame)
    if (
        magic != image.TABLE_MAGIC
        or version != image.TABLE_VERSION
        or not 2 <= count <= len(KINDS)
        or not crc_ok
    ):
        raise ValueError("invalid layout table header or CRC")

    plan, seen, regions = [], set(), []
    for kind, flags, offset, length, address, crc, reserved in entries:
        if kind not in KINDS or kind in seen or flags or reserved:
            raise ValueError(f"invalid layout entry kind {kind}")
        name, load, fixed_offset, max_size = KINDS[kind]
        end = offset + length
        if (
            address != load
            or (fixed_offset is not None and offset != fixed_offset)
            or offset % image.SECTOR
            or offset < image.MAIN_OFFSET
            or not 0 < length <= max_size
            or end > base + len(contents)
            or any(offset < stop and start < end for start, stop in regions)
        ):
            raise ValueError(f"{name} is outside its FEL layout range or overlaps")
        data = contents[offset - base : end - base]
        if zlib.crc32(data) != crc:
            raise ValueError(f"{name} layout entry CRC mismatch")
        seen.add(kind)
        regions.append((offset, end))
        file = f"kind{kind}.bin"
        (work / file).write_bytes(data)
        plan.append(f"{kind} {address:#x} {length} {file} {name}\n")
    if not {image.KIND_MAIN, image.KIND_PAYLOAD} <= seen:
        raise ValueError("layout does not include oreboot main and EDK2")

    (work / "table.bin").write_bytes(frame)
    (work / "plan").write_text("".join(plan))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("bundle", type=Path, help="staged bundle directory")
    ap.add_argument(
        "--work", type=Path, required=True, help="private write-plan directory"
    )
    ap.add_argument("--expect-profile", type=int, default=1200)
    ap.add_argument("--measurement-auth", type=Path)
    a = ap.parse_args()

    workspace = Path(os.environ.get("EXPECT_WORKSPACE", ROOT))
    oreboot = Path(os.environ.get("EXPECT_OREBOOT", ROOT / "firmware" / "oreboot"))
    expect_source = os.environ.get("EXPECT_SOURCE_SHA") or fel_manifest.git_sha(
        workspace
    )
    expect_oreboot = os.environ.get("EXPECT_OREBOOT_SHA") or fel_manifest.git_sha(
        oreboot
    )
    if not expect_source:
        sys.exit("fel-check: cannot resolve the workspace HEAD (set EXPECT_SOURCE_SHA)")
    if not expect_oreboot:
        sys.exit("fel-check: cannot resolve the oreboot HEAD (set EXPECT_OREBOOT_SHA)")

    try:
        mode, profile, auth = fel_manifest.check_manifest(
            a.bundle,
            expect_source,
            expect_oreboot,
            a.expect_profile,
            a.measurement_auth,
        )
        prepare_layout(a.bundle, a.work)
    except (OSError, ValueError) as e:
        sys.exit(f"fel-check: {e}")
    print(
        f"fel-check: mode {mode}; profile {profile};"
        f" source {expect_source}; oreboot {expect_oreboot}; clean"
    )
    if auth:
        print(f"fel-check: measurement authorization: {auth}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
