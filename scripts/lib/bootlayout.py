#!/usr/bin/env python3
"""Write or inspect a boot-stage layout table (crates/bootlayout format).

    bootlayout.py write --magic A7ABOOT1 --version 1 \\
        --entry KIND:OFFSET:FILE:LOAD [--entry ...] --out table.bin
    bootlayout.py show table.bin [--magic A7ABOOT1]

The table is 24 + 32 * 8 = 280 bytes: magic (8), version, count, CRC-32,
reserved (u32 each, little-endian), then eight 32-byte entries (kind, flags,
medium offset, size, u64 load address, CRC-32 of the image, reserved). The
table CRC-32 is computed with its own field zeroed. Generalised from the
table writer of scripts/mkimage.py (A7A: magic
A7ABOOT1, version 1, written at medium offset 0x1ff000); the loader side is
crates/bootlayout. Numbers accept 0x prefixes.
"""

import argparse
import struct
import sys
import zlib
from pathlib import Path

MAX_ENTRIES = 8
CRC_OFFSET = 16
TABLE_SIZE = 24 + 32 * MAX_ENTRIES


def layout_table(entries, magic: bytes, version: int) -> bytes:
    """entries: list of (kind, offset, data, load_addr)."""
    if len(magic) != 8:
        raise ValueError("the magic is 8 bytes")
    if len(entries) > MAX_ENTRIES:
        raise ValueError("too many layout entries")
    body = b""
    for kind, offset, data, addr in entries:
        body += struct.pack(
            "<IIIIQII", kind, 0, offset, len(data), addr, zlib.crc32(data), 0
        )
    body += bytes(32 * (MAX_ENTRIES - len(entries)))
    table = bytearray(struct.pack("<8sIIII", magic, version, len(entries), 0, 0) + body)
    assert len(table) == TABLE_SIZE
    struct.pack_into("<I", table, CRC_OFFSET, zlib.crc32(table))
    return bytes(table)


def parse_table(table: bytes):
    """(magic, version, count, crc_ok, entries) of a table's bytes."""
    if len(table) < TABLE_SIZE:
        raise ValueError(f"a table is {TABLE_SIZE} bytes, got {len(table)}")
    magic, version, count, crc, reserved = struct.unpack_from("<8sIIII", table, 0)
    check = bytearray(table[:TABLE_SIZE])
    check[CRC_OFFSET : CRC_OFFSET + 4] = bytes(4)
    entries = [
        struct.unpack_from("<IIIIQII", table, 24 + 32 * i)
        for i in range(min(count, MAX_ENTRIES))
    ]
    return magic, version, count, zlib.crc32(check) == crc and reserved == 0, entries


def number(text: str) -> int:
    return int(text, 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("write")
    w.add_argument("--magic", required=True)
    w.add_argument("--version", required=True, type=number)
    w.add_argument(
        "--entry", action="append", default=[], metavar="KIND:OFFSET:FILE:LOAD"
    )
    w.add_argument("--out", required=True, type=Path)
    s = sub.add_parser("show")
    s.add_argument("table", type=Path)
    s.add_argument("--magic")
    a = ap.parse_args()
    if a.cmd == "write":
        entries = []
        for spec in a.entry:
            kind, offset, path, load = spec.split(":")
            entries.append(
                (number(kind), number(offset), Path(path).read_bytes(), number(load))
            )
        a.out.write_bytes(layout_table(entries, a.magic.encode(), a.version))
        return 0
    magic, version, count, ok, entries = parse_table(a.table.read_bytes())
    print(
        f"magic {magic!r} version {version} entries {count} crc {'ok' if ok else 'BAD'}"
    )
    for kind, flags, offset, size, load, crc, _ in entries:
        print(
            f"  kind {kind} offset {offset:#x} size {size} load {load:#x} crc32 {crc:08x}"
            + (f" flags {flags:#x}" if flags else "")
        )
    if a.magic and magic != a.magic.encode():
        print("magic differs", file=sys.stderr)
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
