#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read the packaged board-DTB path with the workspace gitlink's FMMT."""

import ctypes
import hashlib
import json
import lzma
import os
from pathlib import Path
import resource
import struct
import sys
from uuid import UUID

# CubieA7A.fdf:50-52,129-138,255-257; OreEdk2BootPkg.dec:25;
# FdtPlatformDxe.c:259-263 requests this file's RAW instance zero.
BOOT, SIZE = 0x40000, 0x280000
CARRIER = UUID("9e21fd93-9c72-4c15-8c4b-e77f1db2d792")
LZMA = UUID("ee4e5898-3914-4259-9d6e-dc7bd79403cf")
BOARD = UUID("5c3f8a19-2e64-4b0d-8f71-9a2c6e13d458")
FFS3 = UUID("5473c07a-3dcb-4dca-bd6f-1e9689e7349a")
CAP = 64 << 20


def require(test, reason):
    if not test:
        sys.exit("embedded DTB: " + reason)


def one(items, label):
    items = list(items)
    require(len(items) == 1, f"expected exactly one {label}, found {len(items)}")
    return items[0]


def section_rule(node, fs):
    # CoreSectionExtraction.c:1323-1329, edk2 556dcfb.
    if node.Data.Header.Common_Header_Size() == 8:
        require(fs == FFS3.bytes_le, "extended section in FFS2")
        require(
            node.Data.Header.SECTION_SIZE > 0xFFFFFF, "undersized extended section size"
        )


def check_scan_start(data):
    # EFI_FIRMWARE_VOLUME_HEADER.ExtHeaderOffset in PiFirmwareVolume.h.
    require(len(data) >= 56, "truncated FV header")
    require(
        struct.unpack_from("<H", data, 52)[0] == 0,
        "unsupported FV extension header: PrePiLib/FwVol.c:186-202 and "
        "DXE FwVol.c:427-437 start scanning after the aligned extension",
    )


def files(volume, data, boot=False):
    fs = data[16:32]
    require(
        fs in (FFS3.bytes_le, UUID("8c8ce578-8a3d-4f1c-9935-896185c32dd3").bytes_le),
        "unexpected FV filesystem GUID",
    )
    require(len(data) == volume.Data.Size, "FV size disagreement")
    # FMMT's FvNode normalizes its in-memory checksum. Check the input
    # bytes instead (DXE FwVol.c:636, Ffs.c:92-102).
    hdr = data[: volume.Data.HeaderLength]
    require(
        72 <= len(hdr) == volume.Data.HeaderLength
        and len(hdr) % 2 == 0
        and not sum(w[0] for w in struct.iter_unpack("<H", hdr)) & 0xFFFF,
        "invalid FV header checksum",
    )
    # edk2 556dcfb: FwVolBlock.c:507-513 counts the LBAs; :356-358
    # rejects reads beyond them. DXE FwVol.c:190-195,229-235 reads the
    # header via ReadFvbData (:88-109), which can cross block boundaries.
    readable = 0
    for pos in range(56, len(hdr) - 7, 8):
        count, length = struct.unpack_from("<II", hdr, pos)
        if (count, length) == (0, 0):
            break
        require(count and length, "invalid FV block map entry")
        readable += count * length
    else:
        require(False, "unterminated FV block map")
    require(readable >= len(hdr), "FV block map cannot cover the header")
    require(readable == len(data), "FV block map does not cover the volume")
    polarity = 255 if volume.Data.Header.Attributes & 0x800 else 0
    for node in volume.Child:
        if node.type not in ("FFS", "FFS_PAD"):
            continue
        if node.Data.Header.Attributes & 1:
            # PrePiLib/FwVol.c:552-560 uses a 24-byte header. DXE
            # FwVol/FwVol.c:509 requires the large-file size threshold.
            require(not boot, "large FFS header in boot FV")
            require(
                fs == FFS3.bytes_le and node.Data.Size > 0xFFFFFF,
                "invalid large FFS size or filesystem",
            )
        # Preserve the W6 clean-built file integrity check, not a second
        # file walker. PrePiLib/FwVol.c:221; DXE FwVol.c:457-478,500-505.
        h = bytes(node.Data.Header)
        require(
            node.Data.Size == len(h) + len(node.Data.Data)
            and h[23] ^ polarity == 7
            and not (sum(h) - h[23] - h[17]) & 255
            and h[17] == (-sum(node.Data.Data) & 255 if h[19] & 0x40 else 0xAA),
            "invalid FFS length, state or checksum",
        )
        yield node


def validate_fdt(tree, digest):
    # FdtPlatformDxe.c:111-117. Call the host libfdt function itself.
    require(40 <= len(tree) <= 4 << 20, "FDT header truncated or DTB exceeds 4 MiB")
    require(tree[:4] == b"\xd0\x0d\xfe\xed", "invalid FDT header")
    require(
        int.from_bytes(tree[4:8], "big") == len(tree),
        "embedded FDT totalsize differs from RAW section payload size",
    )
    require(
        hashlib.sha256(tree).hexdigest() == digest,
        "embedded FDT digest differs from supplied DTB",
    )
    check = ctypes.CDLL("libfdt.so.1").fdt_check_header
    check.argtypes, check.restype = [ctypes.c_void_p], ctypes.c_int
    require(
        check(ctypes.create_string_buffer(tree)) == 0,
        "libfdt rejected embedded FDT header",
    )


def inspect(package, digest):
    # Same factories as FMMT.py -v/-e. Expand only the selected branch; in
    # particular, check the compressed allocation bound *before* invoking C.
    from core.BinaryFactoryProduct import ParserEntry
    from core.BiosTree import BIOSTREE

    parse = ParserEntry().DataParser
    fd_offset = 0x300000 - 512 * int(package.with_suffix(".seek").read_text())
    with package.open("rb") as source:
        source.seek(fd_offset)
        fd = source.read(0x400000)
    compact = fd[BOOT : BOOT + SIZE]
    check_scan_start(compact)
    root = BIOSTREE("packaged.fd")
    root.type = "ROOT"
    parse(root, fd, 0)
    boot = one(
        (
            n
            for n in root.Child
            if n.type == "FV" and n.Data.HOffset == BOOT and n.Data.Size == SIZE
        ),
        "FVMAIN_COMPACT",
    )
    parse(boot, b"", 0)
    outer = list(files(boot, compact, boot=True))
    require(not any(n.Data.Name == BOARD for n in outer), "board file in outer FV")
    require(
        not any(n.Data.Header.Type == 11 and n.Data.Name != CARRIER for n in outer),
        "unexpected boot FV_IMAGE file",
    )
    carrier = one((n for n in outer if n.Data.Name == CARRIER), "FVMAIN container")
    require(carrier.Data.Header.Type == 11, "FVMAIN container is not FV_IMAGE")
    parse(carrier, b"", 0)
    guided = one(carrier.Child, "guided section")
    section_rule(guided, compact[16:32])
    g = guided.Data
    require(
        g.Type == 2
        and bytes(g.ExtHeader.SectionDefinitionGuid) == LZMA.bytes_le
        and g.ExtHeader.Attributes & 1
        and g.ExtHeader.DataOffset == g.HeaderLength,
        "invalid LZMA guided section",
    )
    packed, section_length = g.Data, g.Size
    declared = int.from_bytes(packed[5:13], "little")
    # LzmaDecompress.c:146-155 uses the declared size, rejects unknown size;
    # keep the bench's tighter 64 MiB bound. FMMT can return short output.
    require(len(packed) >= 13 and 0 < declared <= CAP, "unsupported LZMA declared size")
    parse(guided, b"", 0)
    require(len(g.Data) == declared, "LZMA decoded size disagreement")
    image = one(
        (n for n in guided.Child if n.Data.Type != 0x19), "decoded FV_IMAGE section"
    )
    for n in guided.Child:
        section_rule(n, compact[16:32])
    require(image.Data.Type == 0x17, "expected FV_IMAGE section")
    main = image.Data.Data
    check_scan_start(main)
    parse(image, b"", 0)
    inner = one(image.Child, "nested FV")
    # FwVolRead.c:134-144,299-312: lookup enumerates a readable FV.
    require(inner.Data.Header.Attributes & 4, "inner FV read status clear")
    parse(inner, b"", 0)
    board = one(
        (n for n in files(inner, main) if n.Data.Name == BOARD), "board DTB file"
    )
    require(board.Data.Header.Type == 2, "board DTB file is not FREEFORM")
    parse(board, b"", 0)
    raw = one(board.Child, "board DTB section").Data
    require(raw.Type == 0x19, "board DTB section is not RAW")
    section_rule(board.Child[0], main[16:32])
    tree = raw.Data

    # Independent location: Python's LZMA decoder, the exact FV body and
    # complete named FFS file, then the actual PI header lengths on that path.
    # Never count magic strings or assume the first copy of a GUID is a file.
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=128 << 20)
    stream = dec.decompress(packed, max_length=CAP)
    require(
        dec.eof and not dec.unused_data and len(stream) == declared,
        "incomplete LZMA stream",
    )
    ffs = bytes(board.Data.Header) + board.Data.Data
    require(
        stream.count(main) == main.count(ffs) == 1, "ambiguous FV or named FFS bytes"
    )
    fv_at, file_at = stream.index(main), main.index(ffs)
    file_header = 32 if ffs[19] & 1 else 24
    sec = ffs[file_header:]
    header = 8 if sec[:3] == b"\xff\xff\xff" else 4
    length = int.from_bytes(sec[4:8] if header == 8 else sec[:3], "little") - header
    at = fv_at + file_at + file_header + header
    tool_at, tool_length = raw.DOffset - g.DOffset, raw.Size - raw.HeaderLength
    require(
        (tool_at, tool_length) == (at, length)
        and len(tree) == length
        and sec[header:] == tree,
        "FMMT/path offset or length disagreement",
    )
    validate_fdt(tree, digest)
    return dict(
        boot_fv_fd_offset=BOOT,
        fv_file_guid=str(CARRIER),
        fv_file_offset=carrier.Data.HOffset - BOOT,
        section_offset=fd_offset + g.HOffset,
        section_length=section_length,
        compression="LZMA",
        guided_section_guid=str(LZMA),
        decoded_fv_offset=fv_at,
        dtb_file_guid=str(BOARD),
        dtb_file_offset=file_at,
        decoded_dtb_offset=at,
        dtb_size=length,
        fmmt_decoded_offset=tool_at,
        fmmt_raw_length=tool_length,
        sha256=digest,
    )


if __name__ == "__main__":
    source, package, digest, output = sys.argv[1:]
    python = Path(source) / "Python"
    # -B stops writes; also keep stale ignored caches out of source imports.
    sys.pycache_prefix = str(Path.cwd() / "pycache")
    sys.path[:0] = [str(python / "FMMT"), str(python)]
    os.environ.update(
        PATH=str(Path(source) / "C/bin"), FmmtConfPath=str(python / "FMMT"), tmp="."
    )
    resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
    Path(output).write_text(json.dumps(inspect(Path(package), digest)))
