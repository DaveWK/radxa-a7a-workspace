#!/usr/bin/env python3
"""Check the UEFI variable store a built Cubie A7A FD hands to the DXE phase.

  scripts/check-nvstore.py FD [FVMAIN.Fv]

FD: the 4 MiB CUBIEA7A_EFI.fd. Its NV region (PcdFlashNvStorageVariableBase64
- PcdFdBaseAddress) must hold what VariableRuntimeDxe accepts at its entry
(InitRealNonVolatileVariableStore: "_FVH", gEfiSystemNvDataFvGuid, a
variable store header of the right size, formatted and healthy) and what
SdVarStoreFvbDxe formats (FormatFv, FormatFtwWorking): an FV header whose
checksum and block map are right, an empty store, an FTW working header that
FaultTolerantWriteDxe recognises, and an erased spare. A blank region here
made the variable driver ASSERT on every boot (Volume Corrupt).

FVMAIN.Fv (Build/.../FV/FVMAIN.Fv, the uncompressed DXE FV): if it holds
SdVarStoreFvbDxe, VariableRuntimeDxe and FaultTolerantWriteDxe must wait for
gEdkiiNvVarStoreFormattedGuid and SdVarStoreFvbDxe must not wait for them;
if it does not, nothing may wait for that GUID (it would never come).

Exit status 0 if every check passes; prints what it checked.
"""

import struct
import sys
import uuid
import zlib

FD_BASE = 0x41000000
FD_SIZE = 0x400000
VAR_BASE = 0x412C0000
VAR_SIZE = 0x40000
WORK_BASE = 0x41300000
WORK_SIZE = 0x2000
SPARE_BASE = 0x41302000
SPARE_SIZE = 0x40000
FV_LENGTH = VAR_SIZE + WORK_SIZE + SPARE_SIZE
BLOCK = 0x1000


def guid(s):
    return uuid.UUID(s).bytes_le


SYSTEM_NV_DATA_FV = guid("fff12b8d-7696-4c8b-a985-2747075b4f50")
AUTH_VARIABLE = guid("aaf32c78-947b-439a-a180-2e144ec37792")
VARIABLE = guid("ddcf3616-3275-4164-98b6-fe85707ffe7d")
WORKING_BLOCK_SIG = guid("9e58292b-7c68-497d-a0ce-6500fd9f1b95")
NV_VAR_STORE_FORMATTED = guid("d1a86e3f-0707-4c35-83cd-dc2c29c891a3")
TIMER_ARCH = guid("26baccb3-6f42-11d4-bce7-0080c73c8881")

FILE_SUNXIMMC = guid("4f3a2b1c-6d5e-4c7a-9b8f-2e1d0c3a4b5d")
FILE_SDVARSTORE = guid("2f1c8d8a-52a6-4978-b1fb-d58609d4a970")
FILE_VARIABLE = guid("cbd2e4d5-7068-4ff5-b462-9822b4ad8d60")
FILE_FTW = guid("fe5cea76-4f72-49e8-986f-2cd899dffe5d")

errors = []


def check(cond, what):
    print(("  ok    " if cond else "  FAIL  ") + what)
    if not cond:
        errors.append(what)


def check_fd(path):
    fd = open(path, "rb").read()
    print(f"{path}:")
    check(len(fd) == FD_SIZE, f"FD is {FD_SIZE:#x} bytes")
    nv = fd[VAR_BASE - FD_BASE : VAR_BASE - FD_BASE + FV_LENGTH]
    check(len(nv) == FV_LENGTH, f"NV FV ({FV_LENGTH:#x} bytes at {VAR_BASE:#x}) inside the FD")
    if len(nv) != FV_LENGTH:
        return

    # EFI_FIRMWARE_VOLUME_HEADER
    (fs_guid, fv_length, sig, attrs, hdr_len, _csum, ext_off, _rsvd, rev) = struct.unpack_from(
        "<16sQIIHHHBB", nv, 16
    )
    check(nv[:16] == bytes(16), "FV ZeroVector")
    check(sig == 0x4856465F, "FV signature _FVH")
    check(fs_guid == SYSTEM_NV_DATA_FV, "FV FileSystemGuid gEfiSystemNvDataFvGuid")
    check(fv_length == FV_LENGTH, f"FvLength {fv_length:#x} == store + FTW working + spare")
    check(rev == 2, "FV revision 2")
    check(ext_off == 0, "no FV extended header")
    check(hdr_len == 0x48, f"HeaderLength {hdr_len:#x} == 0x48 (one block map entry + terminator)")
    check(attrs == 0xE36, f"FV attributes {attrs:#x} == 0xe36 (as SdVarStoreFvbDxe's FormatFv)")
    nblocks, blen, t0, t1 = struct.unpack_from("<IIII", nv, 0x38)
    check((nblocks, blen) == (FV_LENGTH // BLOCK, BLOCK), f"block map {nblocks:#x} x {blen:#x}")
    check((t0, t1) == (0, 0), "block map terminator")
    check(sum(struct.unpack_from(f"<{hdr_len // 2}H", nv, 0)) & 0xFFFF == 0, "FV header checksum")

    # VARIABLE_STORE_HEADER (what VariableRuntimeDxe checks, and asserts on)
    vs_sig, vs_size, fmt, state = struct.unpack_from("<16sIBB", nv, hdr_len)
    check(vs_sig in (AUTH_VARIABLE, VARIABLE), "variable store signature (authenticated or plain)")
    check(vs_size == VAR_SIZE - hdr_len, f"variable store Size {vs_size:#x} == {VAR_SIZE - hdr_len:#x}")
    check(fmt == 0x5A, "variable store formatted (0x5a)")
    check(state == 0xFE, "variable store healthy (0xfe)")
    body = nv[hdr_len + 28 : VAR_SIZE]
    check(body == b"\xff" * len(body), "variable store empty (no variables, erased to the end)")

    # FTW working block header (FaultTolerantWriteDxe's InitializeLocalWorkSpaceHeader)
    work = nv[VAR_SIZE : VAR_SIZE + WORK_SIZE]
    expect = bytearray(WORKING_BLOCK_SIG + b"\xff" * 8 + struct.pack("<Q", WORK_SIZE - 32))
    struct.pack_into("<I", expect, 16, zlib.crc32(bytes(expect)))
    expect[20] = 0xFE  # WorkingBlockValid = 0, WorkingBlockInvalid = 1
    check(work[:32] == bytes(expect), "FTW working block header (signature, CRC, valid, queue size)")
    check(work[32:] == b"\xff" * (WORK_SIZE - 32), "FTW write queue empty")
    spare = nv[VAR_SIZE + WORK_SIZE :]
    check(spare == b"\xff" * SPARE_SIZE, "FTW spare erased")


def ffs_files(fv):
    """(name GUID, UI name, depex bytes or None) for each file of an FV."""
    (fv_length, sig, _attrs, hdr_len, _c, ext_off) = struct.unpack_from("<QIIHHH", fv, 32)
    if sig != 0x4856465F:
        sys.exit("FVMAIN.Fv: no FV header")
    off = hdr_len
    if ext_off:
        ext_size = struct.unpack_from("<I", fv, ext_off + 16)[0]
        off = ext_off + ext_size
    off = (off + 7) & ~7
    while off + 24 <= fv_length:
        name = fv[off : off + 16]
        if name == b"\xff" * 16:
            break
        ftype, attrs = fv[off + 18], fv[off + 19]
        size = int.from_bytes(fv[off + 20 : off + 23], "little")
        hdr = 24
        if attrs & 0x01:  # FFS_ATTRIB_LARGE_FILE
            size = struct.unpack_from("<Q", fv, off + 24)[0]
            hdr = 32
        ui, depex = None, None
        if ftype != 0xF0:  # not a pad file
            s = off + hdr
            while s + 4 <= off + size:
                ssize = int.from_bytes(fv[s : s + 3], "little")
                stype = fv[s + 3]
                shdr = 4
                if ssize == 0xFFFFFF:
                    ssize = struct.unpack_from("<I", fv, s + 4)[0]
                    shdr = 8
                if ssize < shdr:
                    break
                data = fv[s + shdr : s + ssize]
                if stype == 0x15:
                    ui = data.decode("utf-16-le").rstrip("\0")
                elif stype == 0x13:
                    depex = data
                s = (s + ssize + 3) & ~3
            yield name, ui, depex
        off = (off + size + 7) & ~7


def depex_guids(depex):
    """GUIDs a DXE depex PUSHes (BEFORE/AFTER count too)."""
    out, i = [], 0
    while depex is not None and i < len(depex):
        op = depex[i]
        if op in (0x00, 0x01, 0x02):  # BEFORE, AFTER, PUSH
            out.append(depex[i + 1 : i + 17])
            i += 17
        elif op == 0x08:  # END
            break
        else:
            i += 1
    return out


def check_fv(path):
    fv = open(path, "rb").read()
    print(f"{path}:")
    files = {name: (ui, depex) for name, ui, depex in ffs_files(fv)}
    order = [name for name, _, _ in ffs_files(fv)]
    check(FILE_VARIABLE in files, "VariableRuntimeDxe in the FV")
    if FILE_VARIABLE not in files:
        return
    var_waits = NV_VAR_STORE_FORMATTED in depex_guids(files[FILE_VARIABLE][1])
    if FILE_SDVARSTORE in files:
        sd = depex_guids(files[FILE_SDVARSTORE][1])
        check(var_waits, "VariableRuntimeDxe waits for gEdkiiNvVarStoreFormattedGuid")
        check(FILE_FTW in files, "FaultTolerantWriteDxe in the FV")
        if FILE_FTW in files:
            check(
                NV_VAR_STORE_FORMATTED in depex_guids(files[FILE_FTW][1]),
                "FaultTolerantWriteDxe waits for gEdkiiNvVarStoreFormattedGuid",
            )
        check(sd == [TIMER_ARCH], "SdVarStoreFvbDxe waits for the timer arch protocol only")
        # Same depex: the dispatcher starts them in FV order, so the card
        # window SunxiMmcDxe publishes is there when SdVarStoreFvbDxe looks.
        check(
            FILE_SUNXIMMC in files and order.index(FILE_SUNXIMMC) < order.index(FILE_SDVARSTORE),
            "SdVarStoreFvbDxe after SunxiMmcDxe in the FV",
        )
    else:
        check(not var_waits, "no SdVarStoreFvbDxe: VariableRuntimeDxe does not wait for a store driver")
        for name, (ui, depex) in files.items():
            if NV_VAR_STORE_FORMATTED in depex_guids(depex):
                check(False, f"{ui or name.hex()} waits for gEdkiiNvVarStoreFormattedGuid, which nothing installs")


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    check_fd(sys.argv[1])
    if len(sys.argv) == 3:
        check_fv(sys.argv[2])
    if errors:
        sys.exit(f"check-nvstore: {len(errors)} check(s) failed")
    print("check-nvstore: all checks passed")


main()
