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
import os
import subprocess
import sys
import tempfile
from pathlib import Path

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


def git_text(cwd, *args):
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        env.pop(name, None)
    result = subprocess.run(
        ["git", "-C", str(cwd), *args], env=env, capture_output=True, text=True
    )
    return result.stdout.rstrip("\n") if result.returncode == 0 else None


def git_sha(cwd):
    if git_text(cwd, "rev-parse", "--show-toplevel") != str(cwd.absolute()):
        return None
    value = git_text(cwd, "rev-parse", "--verify", "HEAD^{commit}")
    return value if is_hex(value, 40) else None


def source_identity(workspace, phase):
    result = {}
    for name, path in (
        ("workspace", workspace),
        ("oreboot", workspace / "firmware" / "oreboot"),
    ):
        sha = git_sha(path)
        if not sha:
            die(f"{phase}: {path} is not an initialized repository with a 40-hex HEAD")
        if (
            git_text(path, "status", "--porcelain", "-uall", "--ignore-submodules=none")
            != ""
        ):
            die(f"{phase}: {path} is not clean (git status --porcelain)")
        result["source_sha" if name == "workspace" else "oreboot_sha"] = sha
        result[f"{name}_clean"] = True
    return result


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


def knob(name):
    return name.startswith(("A7A_", "A733_"))


def snapshot(build_dir, snapshot_dir, name):
    source, dest = build_dir / name, snapshot_dir / name
    if not source.is_file():
        die(f"missing intermediate {source}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cp", "--", str(source), str(dest)], check=True)


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

    first = ("fel-bt0", "bt0-fel", "main-fel", "fel-dtb")
    build_root = out / "build"
    if args.dry_run:
        make.append("-n")
        run_dir = build_root / ".compile.DRY-RUN"
        compile_targets(run_dir, first)
        compile_targets(
            run_dir,
            ("fel-edk2",),
            f"FEL_DTB_INPUT={build_root / '.snapshot.DRY-RUN' / DTB}",
        )
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
        compile_targets(compiled, first, "FEL_DTB_INPUT=")
        # EDK2 embeds the DTB. Use the private DTB copy as its source as well.
        snapshot(compiled, private, DTB)
        compile_targets(compiled, ("fel-edk2",), f"FEL_DTB_INPUT={private / DTB}")
        if before != source_identity(ROOT, "after compilation"):
            die("workspace or oreboot HEAD changed during compilation")
        for name, _ in INTERMEDIATES:
            if name != DTB:
                snapshot(compiled, private, name)
        digests = {key: sha256(private / name) for name, key in INTERMEDIATES}

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
            **{key: sha256(private / name) for name, key in PACKAGED},
        )
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


def check_manifest(bundle, expect_source, expect_oreboot, expect_profile, auth_path):
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
    try:
        build(ap.parse_args())
    except (OSError, subprocess.CalledProcessError) as e:
        die(e)


if __name__ == "__main__":
    main()
