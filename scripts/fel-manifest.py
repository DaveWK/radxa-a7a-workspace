#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a FEL bundle and bind it to a workspace-local build record.

This gate protects against accidents on a single-user bench host: stale, mixed,
mislabelled or env-contaminated builds being booted as blob-free, and measurement
builds being booted without a recorded human authorization. It does not defend
against a malicious local user who can edit the scripts or the local records.
"""

import argparse
import fcntl
import hashlib
import json
import lzma
import os
import shlex
import stat
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple
from uuid import UUID

MODES = ("blobfree", "dramlib", "phyfw")
PROFILES = (1200, 2400)
MANIFEST = "build-manifest.json"
DTB = "dtb/sun60i-a733-cubie-a7a.dtb"
INTERMEDIATES = (
    ("bt0.bin", "bt0_sha256"),
    ("bt0-fel.bin", "bt0_fel_sha256"),
    ("main-fel.bin", "main_fel_sha256"),
    ("edk2/CUBIEA7A_EFI.fd", "edk2_fd_sha256"),
    (DTB, "dtb_sha256"),
)
PACKAGED = (
    ("bt0-fel.bin", "bt0_fel_sha256"),
    ("firmware.bin", "firmware_sha256"),
    ("firmware.seek", "firmware_seek_sha256"),
)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FEL_ROOT = ROOT / "out" / "fel"
RECORDS = FEL_ROOT / ".records"
OREBOOT = Path("firmware/oreboot")
BOARD = OREBOOT / "src/mainboard/radxa/cubie-a7a"
SUBMODULES = {
    "oreboot": OREBOOT,
    "edk2": Path("firmware/edk2"),
    "edk2_platforms": Path("firmware/edk2-platforms"),
    "fedora": Path("fedora"),
}
REQUIRED_EDK2 = {
    "BaseTools/Source/C/BrotliCompress/brotli",
    "MdePkg/Library/ArmTransferListLib/libtl",
    "MdePkg/Library/BaseFdtLib/libfdt",
}


def die(msg):
    sys.exit(f"fel-manifest: {msg}")


def sha256(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def is_hex(value, length):
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def git_run(cwd, *args):
    return subprocess.run(
        ["git", "-C", str(cwd), *args],
        env={
            "HOME": str(Path.home()),
            "PATH": os.environ.get("PATH", os.defpath),
            "TMPDIR": os.environ.get("TMPDIR", str(ROOT / "out")),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
        },
        capture_output=True,
    )


def git_text(cwd, *args):
    result = git_run(cwd, *args)
    return os.fsdecode(result.stdout).rstrip("\n") if result.returncode == 0 else None


def checked_tree(path, phase):
    def checked(*args):
        result = git_run(path, *args)
        if result.returncode:
            die(f"{phase}: {path}: git {' '.join(args)}: {os.fsdecode(result.stderr)}")
        return result.stdout

    for key in ("core.sparseCheckout", "core.sparseCheckoutCone"):
        setting = git_run(path, "config", "--type=bool", "--get-all", key)
        if setting.returncode not in (0, 1) or b"true" in setting.stdout.splitlines():
            die(f"{phase}: {path}: sparse checkout ({key})")
    sparse = Path(
        os.fsdecode(
            checked(
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "info/sparse-checkout",
            )
        ).rstrip("\n")
    )
    if sparse.exists() and sparse.stat().st_size:
        die(f"{phase}: {path}: non-empty sparse-checkout file")
    types = {
        "100644": stat.S_IFREG,
        "100755": stat.S_IFREG,
        "120000": stat.S_IFLNK,
        "160000": stat.S_IFDIR,
    }
    links = []
    for entry in checked("ls-files", "-v", "--stage", "-z").split(b"\0")[:-1]:
        meta, raw_name = entry.split(b"\t", 1)
        flag, mode, _, stage = meta.decode("ascii").split()
        name = os.fsdecode(raw_name)
        if flag == "S" or flag.islower():
            reason = "skip-worktree" if flag == "S" else "assume-unchanged"
            die(f"{phase}: {path}/{name}: {reason}")
        if stage != "0" or stat.S_IFMT((path / name).lstat().st_mode) != types.get(
            mode
        ):
            die(f"{phase}: {path}/{name}: unexpected index entry or file type")
        if mode == "160000":
            links.append(name)
    if checked("ls-files", "--deleted", "-z"):
        die(f"{phase}: {path}: deleted tracked files")
    if checked("status", "--porcelain", "-uall", "--ignore-submodules=none"):
        die(f"{phase}: {path} is not clean (git status --porcelain)")
    return links


def git_sha(cwd):
    if git_text(cwd, "rev-parse", "--show-toplevel") != str(cwd.absolute()):
        return None
    value = git_text(cwd, "rev-parse", "--verify", "HEAD^{commit}")
    return value if is_hex(value, 40) else None


def source_identity(workspace, phase):
    roots = {}
    for name, relative in {
        "workspace": Path("."),
        **SUBMODULES,
        "board": BOARD,
    }.items():
        path = workspace / relative
        expected_top = workspace / OREBOOT if name == "board" else path
        top = git_text(path, "rev-parse", "--show-toplevel")
        sha = git_text(path, "rev-parse", "--verify", "HEAD^{commit}")
        if path.resolve() != path or top != str(expected_top) or not is_hex(sha, 40):
            die(
                f"{phase}: {path} is not an initialized repository with a 40-hex HEAD at {expected_top}"
            )
        if name in SUBMODULES:
            expected = f"160000 commit {sha}\t{relative}"
            if (
                git_text(
                    workspace,
                    "ls-tree",
                    roots["workspace"]["head"],
                    "--",
                    str(relative),
                )
                != expected
            ):
                die(f"{phase}: {path} HEAD {sha} does not match the workspace gitlink")
        roots[name] = dict(path=str(path), toplevel=top, head=sha, clean=True)

    nested = {}
    required = {workspace / SUBMODULES["edk2"] / rel for rel in REQUIRED_EDK2}

    def inspect(path, head):
        for rel in checked_tree(path, phase):
            child = path / rel
            if child in (workspace / root for root in SUBMODULES.values()):
                continue  # Checked as an independent root below.
            key = str(child.relative_to(workspace))
            if not (child / ".git").exists():
                if child in required or any(child.iterdir()):
                    die(f"{phase}: nested submodule {child} is not initialized")
                nested[key] = dict(path=key, head=None, clean=False)
                continue
            actual = git_sha(child)
            if (
                not actual
                or git_text(path, "ls-tree", head, "--", rel)
                != f"160000 commit {actual}\t{rel}"
            ):
                die(f"{phase}: {child} does not match its parent gitlink")
            nested[key] = dict(path=key, head=actual, clean=True)
            inspect(child, actual)

    for name in (*SUBMODULES, "workspace"):
        root = Path(roots[name]["path"])
        if (
            git_text(
                root, "-c", "submodule.active=.", "submodule", "status", "--recursive"
            )
            is None
        ):
            die(f"{phase}: cannot enumerate nested submodules of {root}")
        # Walk the index as well: inactive local submodule settings must not
        # hide an initialized checkout, nor may a needed gitlink be absent.
        inspect(root, roots[name]["head"])
    for path in required:
        if not nested.get(str(path.relative_to(workspace)), {}).get("head"):
            die(f"{phase}: required nested submodule {path} is not initialized")
    return dict(
        source_sha=roots["workspace"]["head"],
        oreboot_sha=roots["oreboot"]["head"],
        workspace_clean=True,
        oreboot_clean=True,
        source_roots=roots,
        nested_submodules=nested,
    )


def load_json(path):
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        die(f"cannot read JSON from {path}: {e}")
    if not isinstance(data, dict):
        die(f"{path} is not a JSON object")
    return data


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def check_mode_profile_features(mode, profile, features):
    if mode not in MODES:
        die(f"unknown mode {mode!r}")
    if profile not in PROFILES or (mode != "blobfree" and profile != 2400):
        die(f"invalid profile {profile!r} for {mode}")
    expected = ["fel", "dramlib"] if mode == "dramlib" else ["fel"]
    if features != expected:
        die(f"features {features!r} do not match {mode} (expected {expected})")


# Platform/Radxa/CubieA7APkg/CubieA7A.fdf:50-52,131-133,255-257.
# OreEdk2Boot/OreEdk2BootPkg/OreEdk2BootPkg.dec:25 and
# Drivers/FdtPlatformDxe/FdtPlatformDxe.c:259-263: this GUID, RAW instance 0.
BOOT_FV_OFFSET, BOOT_FV_SIZE = 0x40000, 0x280000
FVMAIN_FILE = UUID("9e21fd93-9c72-4c15-8c4b-e77f1db2d792")
LZMA_GUID = UUID("ee4e5898-3914-4259-9d6e-dc7bd79403cf")
DTB_FILE = UUID("5c3f8a19-2e64-4b0d-8f71-9a2c6e13d458")
# edk2 MdePkg/Include/Guid/FirmwareFileSystem{2,3}.h:18-19.
FFS2 = UUID("8c8ce578-8a3d-4f1c-9935-896185c32dd3")
FFS3 = UUID("5473c07a-3dcb-4dca-bd6f-1e9689e7349a")
# MdePkg/Include/Pi/PiFirmwareFile.h:61,71,208,222,224.
FREEFORM, FV_IMAGE_FILE = 0x02, 0x0B
GUID_DEFINED, FV_IMAGE_SECTION, RAW = 0x02, 0x17, 0x19


class Entry(NamedTuple):
    kind: int
    start: int
    body: int
    end: int


def ffs_files(fv):
    """Yield (name, entry) at FV-relative offsets, rejecting malformed volumes."""
    # PiFirmwareVolume.h:101-157: fixed header, checksum and block map.
    if len(fv) < 72:
        die("truncated boot-path FV")
    fs = UUID(bytes_le=fv[16:32])
    size, sig, attrs, header, _, ext, reserved, rev = struct.unpack_from(
        "<Q4sIHHHBB", fv, 32
    )
    if (
        fs not in (FFS2, FFS3)
        or size != len(fv)
        or sig != b"_FVH"
        or rev != 2
        or reserved
        or not 72 <= header <= size
        or header % 2
        or sum(struct.unpack_from(f"<{header // 2}H", fv)) & 0xFFFF
    ):
        die("invalid boot-path FV header")
    blocks = 0
    for pos in range(56, header - 7, 8):
        count, length = struct.unpack_from("<II", fv, pos)
        if not count and not length:
            break
        if not count or not length:
            die("invalid FV block map entry")
        blocks += count * length
    else:
        die("unterminated FV block map")
    if blocks != size:
        die("FV block map does not cover volume")
    first = header
    if ext:
        # MdeModulePkg/Core/Dxe/FwVol/FwVol.c:427-437.
        if not pos + 8 <= ext <= size - 20:
            die("invalid FV extension offset")
        ext_size = struct.unpack_from("<I", fv, ext + 16)[0]
        if not 20 <= ext_size <= size - ext:
            die("invalid FV extension length")
        first = ext + ext_size
    erased = 0xFF if attrs & 0x800 else 0  # PiFirmwareVolume.h:47
    pos = (first + 7) & ~7
    while pos < size:
        h = fv[pos : pos + 24]
        if h == bytes([erased]) * len(h):
            if fv.count(erased, pos) != size - pos:
                die("non-erased bytes after free space in FV")
            break
        if len(h) != 24:
            die("truncated FFS header")
        # PiFirmwareFile.h:23-36,88-102,108-177 (large files use UINT64).
        kind, attr = h[18:20]
        n = int.from_bytes(h[20:23], "little")
        hdr = 24
        if attr & 1:
            if fs != FFS3 or n or pos + 32 > size:
                die("invalid large FFS header")
            hdr = 32
            n = struct.unpack_from("<Q", fv, pos + 24)[0]
        end = pos + n
        body = pos + hdr
        if not body <= end <= size:
            die("invalid FFS length")
        if (h[23] ^ erased) != 7 or (sum(fv[pos:body]) - h[23] - h[17]) & 255:
            die("invalid FFS file state or header checksum")
        checksum = -sum(fv[body:end]) & 255 if attr & 0x40 else 0xAA
        if h[17] != checksum:
            die("invalid FFS data checksum")
        yield UUID(bytes_le=h[:16]), Entry(kind, pos, body, end)
        pos = (end + 7) & ~7


def sections(data, start, end):
    """Walk common (including extended) section headers within one parent."""
    pos = start
    while pos < end:
        if end - pos < 4:
            die("truncated section header")
        size = int.from_bytes(data[pos : pos + 3], "little")
        header = 4
        if size == 0xFFFFFF:
            if end - pos < 8:
                die("truncated extended section header")
            size = struct.unpack_from("<I", data, pos + 4)[0]
            header = 8
        if not header <= size <= end - pos:
            die("invalid section length")
        yield Entry(data[pos + 3], pos, pos + header, pos + size)
        pos += (size + 3) & ~3


def unique(entries, label):
    count = 0
    for count, item in enumerate(entries, 1):
        if count == 1:
            first = item
    if count != 1:
        die(f"expected exactly one {label}, found {count}")
    return first


def embedded_dtb(package, digest):
    """Follow the pinned FDF from the packaged FD, never search for byte patterns."""
    # scripts/mkimage.py:62-65,84,130-133,213-216. fel-check also enforces
    # this fixed medium offset for the payload's layout-table entry at boot.
    fd_offset = 0x300000 - 512 * int(package.with_suffix(".seek").read_text())
    fv_offset = fd_offset + BOOT_FV_OFFSET
    with package.open("rb") as f:
        f.seek(fv_offset)
        compact = f.read(BOOT_FV_SIZE)
    if len(compact) != BOOT_FV_SIZE:
        die("truncated FVMAIN_COMPACT region")
    files = list(ffs_files(compact))
    if any(name == DTB_FILE for name, _ in files):
        die("board DTB file in unexpected outer FV")
    # ArmVirtPkg/PrePi/PrePi.c:94 calls DecompressFirstFv; an earlier,
    # differently named FV_IMAGE is not interchangeable with the FDF carrier.
    if any(e.kind == FV_IMAGE_FILE and name != FVMAIN_FILE for name, e in files):
        die("unexpected FV_IMAGE file in FVMAIN_COMPACT")
    carrier = unique(
        (e for name, e in files if name == FVMAIN_FILE), "FVMAIN container"
    )
    if carrier.kind != FV_IMAGE_FILE:
        die("FVMAIN container is not an FV_IMAGE file")
    guided = unique(sections(compact, carrier.body, carrier.end), "guided section")
    if (
        guided.kind != GUID_DEFINED
        or guided.body + 20 > guided.end
        or compact[guided.body : guided.body + 16] != LZMA_GUID.bytes_le
    ):
        die("expected LZMA guided section")
    offset, flags = struct.unpack_from("<HH", compact, guided.body + 16)
    start = guided.start + offset
    # PiFirmwareFile.h:358,365-378: DataOffset is section-relative.
    if not flags & 1 or not guided.body + 20 <= start < guided.end:
        die("invalid LZMA guided section bounds")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=128 << 20)
    try:
        stream = decoder.decompress(compact[start : guided.end], max_length=64 << 20)
    except lzma.LZMAError as exc:
        die(f"cannot decode packaged LZMA section: {exc}")
    if not decoder.eof or decoder.unused_data:
        die("incomplete or oversized packaged LZMA section")
    # GenFv can insert a RAW alignment section before the nested volume.
    image = unique(
        (s for s in sections(stream, 0, len(stream)) if s.kind != RAW),
        "decoded FV_IMAGE section",
    )
    if image.kind != FV_IMAGE_SECTION:
        die("unexpected section in decoded FVMAIN stream")
    main = stream[image.body : image.end]
    board = unique(
        (e for name, e in ffs_files(main) if name == DTB_FILE), "board DTB file"
    )
    if board.kind != FREEFORM:
        die("board DTB file is not FREEFORM")
    raw = unique(sections(main, board.body, board.end), "board DTB section")
    if raw.kind != RAW:
        die("board DTB section is not RAW")
    tree = main[raw.body : raw.end]
    if len(tree) < 40 or tree[:4] != b"\xd0\x0d\xfe\xed":
        die("invalid embedded FDT header")
    if struct.unpack_from(">I", tree, 4)[0] != len(tree):
        die("embedded FDT totalsize differs from RAW section payload size")
    if hashlib.sha256(tree).hexdigest() != digest:
        die("embedded FDT digest differs from supplied DTB")
    return dict(
        boot_fv_fd_offset=BOOT_FV_OFFSET,
        fv_file_guid=str(FVMAIN_FILE),
        fv_file_offset=carrier.start,
        section_offset=fv_offset + guided.start,
        section_length=guided.end - guided.start,
        compression="LZMA",
        guided_section_guid=str(LZMA_GUID),
        decoded_fv_offset=image.body,
        dtb_file_guid=str(DTB_FILE),
        dtb_file_offset=board.start,
        decoded_dtb_offset=image.body + raw.body,
        dtb_size=len(tree),
        sha256=digest,
    )


def knob(name):
    return name.startswith(("A7A_", "A733_"))


def snapshot(source, dest):
    if not source.is_file():
        die(f"missing intermediate {source}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cp", "--", str(source), str(dest)], check=True)


def seed_cargo_home(home, cache_home):
    # The pinned build uses crates.io, not git dependencies. Only copy the
    # offline inputs; Cargo can extract archives and write locks in this home
    # but never gets the caller's config, credentials or unpacked sources.
    for name in ("index", "cache"):
        source = cache_home / "registry" / name
        if not source.is_dir():
            continue
        dest = home / "registry" / name
        dest.parent.mkdir(exist_ok=True)
        subprocess.run(
            ["cp", "-RL", "--reflink=auto", "--", str(source), str(dest)], check=True
        )
        for path in dest.rglob("*"):
            path.chmod(stat.S_IMODE(path.stat().st_mode) & ~0o222)
        dest.chmod(stat.S_IMODE(dest.stat().st_mode) & ~0o222)


def check_cargo_env(home):
    env = dict(os.environ, CARGO_HOME=str(home), CARGO_NET_OFFLINE="true")
    for name in ("RUSTUP_TOOLCHAIN", "RUSTFLAGS"):
        env.pop(name, None)
    for crate in ("bt0", "main"):
        cwd = ROOT / BOARD / crate
        result = subprocess.run(
            ["cargo", "-Zunstable-options", "config", "get", "--format=json", "env"],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            if (
                result.returncode == 101
                and not result.stdout
                and result.stderr.rstrip().splitlines()[-1:]
                == ["error: config value `env` is not set"]
            ):
                continue
            die(f"cannot inspect Cargo [env] from {cwd} (exit {result.returncode})")
        try:
            config_env = json.loads(result.stdout)["env"]
            if not isinstance(config_env, dict):
                raise ValueError("env is not a table")
        except (KeyError, TypeError, ValueError):
            die(f"cannot read Cargo [env] as JSON from {cwd}")
        # The Make recipe supplies the allowed knobs as process environment,
        # not as Cargo config. Even the same key in config may use force=true.
        knobs = sorted(name for name in config_env if knob(name))
        if knobs:
            die(f"refuses Cargo [env] build knobs from {cwd}: {', '.join(knobs)}")


def build(args):
    if not os.environ.get("MAKELEVEL", "").isdigit() or os.environ["MAKELEVEL"] == "0":
        die("use make fel-image to build and record a bundle")
    mode, profile, features = args.mode, args.profile, args.features.split()
    check_mode_profile_features(mode, profile, features)
    out = FEL_ROOT / f"{mode}-{profile}"
    if args.out_dir != out:
        die(f"expected FEL output directory {out}, got {args.out_dir}")

    inherited = sorted(name for name in os.environ if knob(name))
    if inherited:
        die(f"fel-image refuses inherited build knobs: {', '.join(inherited)}")
    for name in ("EDK2_DIR", "EDK2_PLATFORMS_DIR"):
        if name in os.environ:
            die(f"fel-image refuses {name} override")
    edk2_args = shlex.split(args.edk2_args)
    dtb_input = Path(args.fel_dtb_input).resolve() if args.fel_dtb_input else None
    # No inherited knob gets past the rejection. Also clear the inputs FEL
    # owns at the compiler's parent boundary, before the recipes set them.
    make = [
        "env",
        "-u",
        "A7A_PROFILE",
        "-u",
        "A733_DRAM_LIB",
        "-u",
        "A733_PHY_FW_OBJ",
        args.make,
        "--no-print-directory",
        "-C",
        str(ROOT),
    ]

    def compile_targets(run_dir, targets, *settings):
        subprocess.run(
            [
                *make,
                f"FEL_IMAGE_EXPECT={mode}-{profile}",
                f"FEL_RUN_DIR={run_dir}",
                *settings,
                *targets,
            ],
            check=True,
            close_fds=False,  # preserve GNU Make's pipe jobserver as well as FIFO
        )

    def compile_edk2(run_dir, dtb, dry_run=False):
        edk2_env = dict(os.environ, EDK2_OUT=str(run_dir / "edk2"), BUILD_TAG=out.name)
        # edksetup otherwise reuses settings left by a different EDK2 shell.
        for name in ("WORKSPACE", "CONF_PATH"):
            edk2_env.pop(name, None)
        command = [
            str(HERE / "build-edk2.sh"),
            args.edk2_target,
            *edk2_args,
            "-D",
            f"DTB_FILE={dtb}",
        ]
        if dry_run:
            print(
                shlex.join(
                    [
                        f"EDK2_OUT={edk2_env['EDK2_OUT']}",
                        f"BUILD_TAG={out.name}",
                        *command,
                    ]
                )
            )
            return
        edk2_env["EDK2_EXPECT_HEAD"] = before["source_roots"]["edk2"]["head"]
        subprocess.run(command, cwd=ROOT, env=edk2_env, check=True, close_fds=False)

    def compile_firmware(run_dir):
        targets = ["fel-bt0", "bt0-fel", "main-fel"]
        if dtb_input is None:
            targets.append("fel-dtb")
        # Command-line assignments also replace a caller's Make overrides.
        compile_targets(
            run_dir,
            targets,
            f"CARGO_HOME={run_dir / 'cargo-home'}",
            "CARGO_NET_OFFLINE=true",
        )

    build_root = out / "build"
    if args.dry_run:
        make.append("-n")
        run_dir = build_root / ".compile.DRY-RUN"
        compile_firmware(run_dir)
        compile_edk2(run_dir, build_root / ".snapshot.DRY-RUN" / DTB, dry_run=True)
        return

    build_root.mkdir(parents=True, exist_ok=True)
    with (
        (build_root / ".lock").open("a") as lock,
        tempfile.TemporaryDirectory(prefix=".compile.", dir=build_root) as compiled,
        tempfile.TemporaryDirectory(prefix=".snapshot.", dir=build_root) as private,
    ):
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = source_identity(ROOT, "before compilation")
        compiled, private = Path(compiled), Path(private)
        home = compiled / "cargo-home"
        home.mkdir(mode=0o700)
        cache_home = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo")
        seed_cargo_home(home, cache_home)
        check_cargo_env(home)
        compile_firmware(compiled)
        # EDK2 embeds the DTB. Use the private DTB copy as its source as well.
        dtb_path = dtb_input if dtb_input is not None else compiled / DTB
        snapshot(dtb_path, private / DTB)
        dtb_sha = sha256(private / DTB)
        compile_edk2(compiled, private / DTB)
        if before != source_identity(ROOT, "after compilation"):
            die("workspace or oreboot HEAD changed during compilation")
        for name, _ in INTERMEDIATES:
            if name != DTB:
                snapshot(compiled / name, private / name)
        digests = {key: sha256(private / name) for name, key in INTERMEDIATES}
        if digests["dtb_sha256"] != dtb_sha:
            die("private DTB changed during EDK2 compilation")

        # Hash and package the same files. Nothing reopens the originals.
        subprocess.run(
            [
                sys.executable,
                "-I",
                str(HERE / "mkimage.py"),
                "--bt0",
                str(private / "bt0.bin"),
                "--main",
                str(private / "main-fel.bin"),
                "--payload",
                str(private / "edk2/CUBIEA7A_EFI.fd"),
                "--out",
                str(private),
                "--egon-offset",
                args.egon_offset,
            ],
            check=True,
        )
        manifest = dict(
            mode=mode,
            profile=profile,
            features=features,
            clean=True,
            **before,
            edk2_target=args.edk2_target,
            **load_json(compiled / "edk2/tool-config.json"),
            edk2_args=edk2_args,
            fel_dtb_input=str(dtb_input) if dtb_input is not None else None,
            dtb_path=str(dtb_path),
            dtb_sha256=dtb_sha,
            dts_dir=str(ROOT / "fedora/fedora/dts"),
            dtb_source=(
                "external"
                if dtb_input is not None
                else "fedora@" + before["source_roots"]["fedora"]["head"]
            ),
            embedded_dtb=embedded_dtb(private / "firmware.bin", dtb_sha),
            **{key: sha256(private / name) for name, key in PACKAGED},
        )
        fdfs = [
            line.removeprefix("Flash Image Definition: ").strip()
            for line in (compiled / "edk2/BuildOptions").read_text().splitlines()
            if line.startswith("Flash Image Definition: ")
        ]
        if len(fdfs) != 1 or not fdfs[0]:
            die("missing or ambiguous EDK2 BuildOptions FDF selection")
        manifest["edk2_fdf"] = fdfs[0]
        record = dict(
            **manifest,
            profile_source=(
                "DRAM_MHZ/default" if mode == "blobfree" else "fixed by mode"
            ),
            sd_features=args.sd_features.split(),
            main_features=args.main_features.split(),
            build_environment={
                "bt0_fel": dict(item.split("=", 1) for item in args.fel_env.split()),
                "bt0_sd": dict(item.split("=", 1) for item in args.sd_env.split()),
                "main_fel": {},
            },
            intermediates=digests,
        )
        if before != source_identity(ROOT, "before publication"):
            die("workspace or oreboot HEAD changed before publication")

        RECORDS.mkdir(mode=0o700, exist_ok=True)
        path = RECORDS / f"{digests['bt0_fel_sha256']}.json"
        write_json(private / path.name, record)
        write_json(private / MANIFEST, manifest)
        with (RECORDS / ".lock").open("a") as records_lock:
            fcntl.flock(records_lock, fcntl.LOCK_EX)
            if path.exists():
                previous = load_json(path)
                if (previous.get("mode"), previous.get("profile")) != (mode, profile):
                    die(
                        f"{path} already classifies this bt0 with a different mode/profile"
                    )
            # Atomically replace each file. A reader seeing mixed generations
            # fails the record and digest checks rather than booting them.
            (private / path.name).replace(path)
        for name in (*(name for name, _ in PACKAGED), MANIFEST):
            (private / name).replace(out / name)
        print(f"{out / MANIFEST}: {mode}-{profile}, build record {path}")


def check_auth(path, digest):
    auth = load_json(path)
    if auth.get("bt0_fel_sha256") != digest:
        die(f"{path} does not authorize this bundle's bt0_fel_sha256 {digest}")
    ref = auth.get("authorization")
    if not isinstance(ref, str) or not ref.strip():
        die(f"{path} has no authorization reference")
    return ref


def check_manifest(
    bundle, expect_source, expect_oreboot, expect_mode, expect_profile, auth_path
):
    digest = sha256(bundle / "bt0-fel.bin")
    path = RECORDS / f"{digest}.json"
    if not path.is_file():
        die(f"no local build record for bt0_fel_sha256 {digest} (make fel-image)")
    record = load_json(path)
    mode, profile = record.get("mode"), record.get("profile")
    check_mode_profile_features(mode, profile, record.get("features"))
    if not (
        record.get("clean") is True
        and record.get("workspace_clean") is True
        and record.get("oreboot_clean") is True
    ):
        die("build record does not attest to clean sources")
    for field, expected in (
        ("source_sha", expect_source),
        ("oreboot_sha", expect_oreboot),
    ):
        value = record.get(field)
        if not is_hex(value, 40) or value != expected:
            die(f"record {field} {value!r} does not match expected HEAD {expected}")
    if mode != expect_mode:
        die(f"record mode {mode} does not match requested mode {expect_mode}")
    if mode == "blobfree" and record.get("dtb_source") == "external":
        if (
            not is_hex(record.get("dtb_sha256"), 64)
            or os.environ.get("EXPECT_DTB_SHA256") != record["dtb_sha256"]
        ):
            die("external DTB requires matching EXPECT_DTB_SHA256")
    if profile != expect_profile:
        die(
            f"record profile {profile} does not match requested profile {expect_profile}"
        )

    manifest = load_json(bundle / MANIFEST)
    for key in (
        "mode",
        "profile",
        "features",
        "source_sha",
        "oreboot_sha",
        "clean",
        "workspace_clean",
        "oreboot_clean",
        "source_roots",
        "nested_submodules",
        "edk2_target",
        "basetools_stamp_sha256",
        "conf_sha256",
        "edk2_args",
        "fel_dtb_input",
        "dtb_path",
        "dtb_sha256",
        "dts_dir",
        "dtb_source",
        "embedded_dtb",
        "edk2_fdf",
        *(key for _, key in PACKAGED),
    ):
        if key not in manifest or manifest[key] != record.get(key):
            die(f"bundle manifest {key} disagrees with the build record")
    for name, key in PACKAGED:
        actual = digest if name == "bt0-fel.bin" else sha256(bundle / name)
        if actual != record.get(key):
            die(f"{name} sha256 {actual} does not match the build record")

    ref = None
    if mode != "blobfree":
        if not auth_path:
            die(f"{mode} is a measurement build; set FEL_MEASUREMENT_AUTH")
        ref = check_auth(auth_path, digest)
    return mode, profile, ref


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="compile and package through make fel-image")
    b.add_argument("--make", required=True)
    b.add_argument("--dry-run", action="store_true")
    b.add_argument("--out-dir", required=True, type=Path)
    b.add_argument("--mode", required=True, choices=MODES)
    b.add_argument("--profile", required=True, type=int, choices=PROFILES)
    for arg in ("features", "sd-features", "main-features", "fel-env", "sd-env"):
        b.add_argument(f"--{arg}", required=True)
    b.add_argument("--egon-offset", required=True)
    b.add_argument("--edk2-target", required=True, choices=("DEBUG", "RELEASE"))
    b.add_argument("--edk2-args", required=True)
    b.add_argument("--fel-dtb-input", required=True)
    try:
        build(ap.parse_args())
    except (OSError, ValueError, subprocess.CalledProcessError) as e:
        die(e)


if __name__ == "__main__":
    main()
