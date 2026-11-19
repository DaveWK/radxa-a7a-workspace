#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build state and build-mode manifest for a FEL boot bundle.

`make fel-image` builds the intermediates into `out/fel/<mode>-<mhz>/build/`,
records `build-state.json` there, then packages from that directory into
`out/fel/<mode>-<mhz>/` and writes `build-manifest.json` next to the images.
`scripts/fel-check.py` validates a staged bundle against the manifest before
any USB access.

The manifest carries the DRAM mode, the profile (DRAM_MHZ; 1200 unless set,
2400 for the vendor paths), the cargo features, the workspace and oreboot
SHAs, a clean flag and the SHA-256 of each packaged image. A dramlib or
phyfw bundle is a measurement build and needs a separate authorization file.
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

MODES = ("blobfree", "dramlib", "phyfw")
PROFILES = ("1200", "2400")
MANIFEST = "build-manifest.json"
STATE = "build-state.json"
INTERMEDIATES = (
    ("bt0.bin", "bt0_sha256"),
    ("bt0-fel.bin", "bt0_fel_sha256"),
    ("main-fel.bin", "main_fel_sha256"),
    ("edk2/CUBIEA7A_EFI.fd", "edk2_fd_sha256"),
)
PACKAGED = (
    ("bt0-fel.bin", "bt0_fel_sha256"),
    ("firmware.bin", "firmware_sha256"),
    ("firmware.seek", "firmware_seek_sha256"),
)
HERE = Path(__file__).resolve().parent
MKIMAGE = HERE / "mkimage.py"


def die(msg):
    sys.exit(f"fel-manifest: {msg}")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_hex(value, length):
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value.lower())
    )


def features_for_mode(mode):
    return ["fel"] + (["dramlib"] if mode == "dramlib" else [])


def git_text(args, cwd):
    try:
        out = subprocess.run(
            ["git", "-C", str(cwd)] + args, capture_output=True, text=True
        )
    except OSError:
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


def git_sha(cwd):
    value = git_text(["rev-parse", "HEAD"], cwd)
    return value if value and is_hex(value, 40) else None


def git_clean(cwd):
    return git_text(["status", "--porcelain"], cwd) == ""


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except OSError as e:
        die(f"cannot read {path}: {e}")
    except ValueError as e:
        die(f"{path} is not valid JSON: {e}")


def check_mode_profile_features(mode, profile, features):
    if mode not in MODES:
        die(f"mode {mode!r} is not one of {', '.join(MODES)}")
    if profile not in PROFILES:
        die(f"profile {profile!r} is not one of {', '.join(PROFILES)}")
    expected = features_for_mode(mode)
    if list(features) != expected:
        die(f"features {list(features)} do not match mode {mode} (expected {expected})")


def check_auth(path, bt0_fel_sha256):
    auth = load_json(path)
    if not isinstance(auth, dict):
        die(f"{path} is not a JSON object")
    digest = auth.get("bt0_fel_sha256")
    if not is_hex(digest, 64):
        die(f"{path} has no 64-hex bt0_fel_sha256")
    if digest != bt0_fel_sha256:
        die(f"{path} names bt0_fel_sha256 {digest}, not this bundle's {bt0_fel_sha256}")
    ref = auth.get("authorization")
    if not isinstance(ref, str) or not ref.strip():
        die(f"{path} has no authorization reference")
    return ref


def record(build_dir, mode, profile, features, workspace, oreboot):
    build_dir = Path(build_dir)
    check_mode_profile_features(mode, profile, features)
    source_sha = git_sha(workspace)
    if not source_sha:
        die(f"cannot resolve a 40-hex workspace SHA in {workspace}")
    oreboot_sha = git_sha(oreboot)
    if not oreboot_sha:
        die(f"cannot resolve a 40-hex oreboot SHA in {oreboot}")
    if not git_clean(workspace):
        die(f"{workspace} is not clean (git status --porcelain is not empty)")
    if not git_clean(oreboot):
        die(f"{oreboot} is not clean (git status --porcelain is not empty)")
    digests = {}
    for name, key in INTERMEDIATES:
        path = build_dir / name
        if not path.is_file():
            die(f"{path} is missing")
        digests[key] = sha256(path)
    state = {
        "mode": mode,
        "profile": profile,
        "features": list(features),
        "source_sha": source_sha,
        "oreboot_sha": oreboot_sha,
        "clean": True,
        **digests,
    }
    out = build_dir / STATE
    with open(out, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.write("\n")
    print(
        f"{out}: mode {mode}, profile {profile}, source {source_sha}, oreboot {oreboot_sha}"
    )


def package(build_dir, out_dir, egon_offset="128k"):
    build_dir = Path(build_dir)
    out_dir = Path(out_dir)
    state = load_json(build_dir / STATE)
    if not isinstance(state, dict):
        die(f"{build_dir / STATE} is not a JSON object")
    for key in ("mode", "profile", "features", "source_sha", "oreboot_sha", "clean"):
        if key not in state:
            die(f"{build_dir / STATE} has no {key}")
    check_mode_profile_features(state["mode"], state["profile"], state["features"])
    if state["clean"] is not True:
        die(f"{build_dir / STATE} records a dirty tree")
    if not is_hex(state["source_sha"], 40) or not is_hex(state["oreboot_sha"], 40):
        die(f"{build_dir / STATE} has no 40-hex source and oreboot SHA")
    for name, key in INTERMEDIATES:
        path = build_dir / name
        if not path.is_file():
            die(f"{path} is missing")
        got = sha256(path)
        if got != state.get(key):
            die(
                f"{name} sha256 {got} does not match the build state"
                f" ({state.get(key)}); the intermediate was replaced"
            )

    subprocess.run(
        [
            sys.executable,
            "-I",
            str(MKIMAGE),
            "--bt0",
            str(build_dir / "bt0.bin"),
            "--main",
            str(build_dir / "main-fel.bin"),
            "--payload",
            str(build_dir / "edk2" / "CUBIEA7A_EFI.fd"),
            "--out",
            str(out_dir),
            "--egon-offset",
            egon_offset,
        ],
        check=True,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(build_dir / "bt0-fel.bin", "rb") as src, open(
        out_dir / "bt0-fel.bin", "wb"
    ) as dst:
        dst.write(src.read())

    manifest = {
        "mode": state["mode"],
        "profile": state["profile"],
        "features": state["features"],
        "source_sha": state["source_sha"],
        "oreboot_sha": state["oreboot_sha"],
        "clean": True,
    }
    for name, key in PACKAGED:
        manifest[key] = sha256(out_dir / name)
    with open(out_dir / MANIFEST, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    print(
        f"{out_dir / MANIFEST}: mode {manifest['mode']}, profile {manifest['profile']}"
    )


def check_manifest(
    bundle_dir, expect_source, expect_oreboot, expect_profile, auth_path=None
):
    bundle_dir = Path(bundle_dir)
    manifest = load_json(bundle_dir / MANIFEST)
    if not isinstance(manifest, dict):
        die(f"{bundle_dir / MANIFEST} is not a JSON object")
    mode = manifest.get("mode")
    profile = manifest.get("profile")
    features = manifest.get("features")
    check_mode_profile_features(mode, profile, features)
    if manifest.get("clean") is not True:
        die(f"{bundle_dir / MANIFEST} records a dirty tree")
    source_sha = manifest.get("source_sha")
    oreboot_sha = manifest.get("oreboot_sha")
    if not is_hex(source_sha, 40):
        die(f"{bundle_dir / MANIFEST} has no 40-hex source_sha")
    if not is_hex(oreboot_sha, 40):
        die(f"{bundle_dir / MANIFEST} has no 40-hex oreboot_sha")
    if source_sha != expect_source:
        die(
            f"workspace SHA {source_sha} does not match the current HEAD {expect_source}"
        )
    if oreboot_sha != expect_oreboot:
        die(
            f"oreboot SHA {oreboot_sha} does not match the checked-out HEAD {expect_oreboot}"
        )
    if profile != expect_profile:
        die(f"profile {profile} does not match the requested profile {expect_profile}")

    digests = {}
    for name, key in PACKAGED:
        path = bundle_dir / name
        if not path.is_file():
            die(f"{path} is missing")
        digests[name] = sha256(path)
        want = manifest.get(key)
        if not is_hex(want, 64):
            die(f"{bundle_dir / MANIFEST} has no 64-hex {key}")
        if digests[name] != want:
            die(f"{name} sha256 {digests[name]} does not match the manifest ({want})")

    auth_ref = None
    if mode != "blobfree":
        if not auth_path:
            die(
                f"a {mode} bundle is a measurement build;"
                " set FEL_MEASUREMENT_AUTH to a file naming this bt0"
            )
        auth_ref = check_auth(auth_path, digests["bt0-fel.bin"])
    return {
        "mode": mode,
        "profile": profile,
        "source_sha": source_sha,
        "oreboot_sha": oreboot_sha,
        "auth": auth_ref,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record", help="record build-state.json for a build directory")
    r.add_argument("--build-dir", required=True)
    r.add_argument("--mode", required=True)
    r.add_argument("--profile", required=True)
    r.add_argument("--features", required=True)
    r.add_argument("--workspace", required=True)
    r.add_argument("--oreboot", required=True)
    p = sub.add_parser("package", help="verify the build state and write the bundle")
    p.add_argument("--build-dir", required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--egon-offset", default="128k")
    a = ap.parse_args()
    if a.cmd == "record":
        record(
            a.build_dir, a.mode, a.profile, a.features.split(), a.workspace, a.oreboot
        )
    else:
        package(a.build_dir, a.out_dir, a.egon_offset)


if __name__ == "__main__":
    main()
