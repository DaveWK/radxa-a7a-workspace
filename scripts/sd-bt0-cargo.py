#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile SD/eMMC bt0 with a clean environment; identify known raw builds."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
OREBOOT = ROOT / "firmware/oreboot"
CRATE = OREBOOT / "src/mainboard/radxa/cubie-a7a/bt0"
TARGET = "armv7a-none-eabi"
FLAGS = [
    "-C",
    "link-arg=-Tlink-cubie-a7a-bt0.ld",
    "-C",
    "link-arg=--gc-sections",
    "-C",
    "target-cpu=cortex-a55",
]
IDENTITIES = ("blobfree-1200", "blobfree-2400", "dramlib-2400", "phyfw-2400")


def check_config():
    # Cargo starts at ROOT, so it never loads the files under OREBOOT.
    # Refuse every other config in either search chain; checking the whole
    # file also rules out target-specific overrides and config includes.
    for directory in (CRATE, *CRATE.parents):
        for name in ("config", "config.toml"):
            path = directory / ".cargo" / name
            if not path.exists() and not path.is_symlink():
                continue
            if (
                not path.is_symlink()
                and name == "config.toml"
                and directory
                in (
                    CRATE,
                    OREBOOT,
                )
            ):
                try:
                    data = tomllib.loads(path.read_text())
                except (OSError, ValueError):
                    raise SystemExit(
                        f"sd-bt0: unapproved Cargo config: {path}"
                    ) from None
                if directory == OREBOOT and data.keys() == {"alias"}:
                    continue
                if directory == CRATE and data == {
                    "build": {"target": TARGET},
                    "target": {TARGET: {"rustflags": FLAGS}},
                }:
                    continue
            raise SystemExit(
                f"sd-bt0: unapproved Cargo config: {path}; "
                "Cargo [env] must not set A7A_PROFILE and unpinned build settings are not allowed"
            )


def build(args):
    check_config()
    source_home = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo")
    if not source_home.is_absolute():
        source_home = CRATE / source_home
    channel = tomllib.loads((OREBOOT / "rust-toolchain.toml").read_text())["toolchain"][
        "channel"
    ]
    with tempfile.TemporaryDirectory(prefix=".sd-bt0-", dir=args.scratch) as directory:
        scratch = Path(directory).resolve()
        home = scratch / "cargo-home"
        home.mkdir()
        # The pinned bt0 uses crates.io. Seed only the index and archives,
        # never config, credentials, unpacked sources or mutable shared locks.
        for name in ("index", "cache"):
            source = source_home / "registry" / name
            if source.is_dir():
                registry = home / "registry"
                registry.mkdir(exist_ok=True)
                subprocess.run(
                    ["cp", "-RL", "--reflink=auto", "--", source, registry / name],
                    check=True,
                )
        # PATH and HOME locate installed tools; RUSTUP_HOME is required by
        # the container's /opt toolchain. Scratch and target output are ours.
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(Path.home()),
            "CARGO_HOME": str(home),
            "CARGO_TARGET_DIR": str(args.target_dir.resolve()),
            "TMPDIR": str(scratch),
        }
        if os.environ.get("RUSTUP_HOME"):
            env["RUSTUP_HOME"] = os.environ["RUSTUP_HOME"]
        mode, profile = args.identity.rsplit("-", 1)
        features = ["otp"] if args.otp else []
        cargo = [
            "cargo",
            f"+{channel}",
            "build",
            "--manifest-path",
            str(CRATE / "Cargo.toml"),
            "--target",
            TARGET,
            "--config",
            f"target.{TARGET}.rustflags={json.dumps(FLAGS)}",
            "--locked",
            "--release",
        ]
        if os.environ.get("CARGO_NET_OFFLINE") == "true":
            cargo.append("--offline")
        if mode == "blobfree":
            env["A7A_PROFILE"] = profile
            if args.vendor_input:
                raise SystemExit("sd-bt0: blobfree forbids a vendor input")
        else:
            if not args.vendor_input:
                raise SystemExit("sd-bt0: measurement mode requires a vendor input")
            if mode == "dramlib":
                env["A733_DRAM_LIB"] = str(args.vendor_input.resolve())
                features.append("dramlib")
            else:
                env["A733_PHY_FW_OBJ"] = str(args.vendor_input.resolve())
            cargo.append("--no-default-features")
        if features:
            cargo += ["--features", ",".join(features)]
        subprocess.run(
            [
                "/usr/bin/env",
                "-i",
                *(f"{key}={val}" for key, val in env.items()),
                *cargo,
            ],
            cwd=ROOT,
            env={},
            check=True,
        )


def verify(args):
    # The pin's profile constants are compile-time only. Identify the raw
    # objcopy bytes using independently reproduced matrix build fingerprints,
    # not any label or metadata supplied by the build that just ran.
    fingerprints = json.loads(
        Path(__file__).with_name("sd-bt0-fingerprints.json").read_text()
    )
    raw = args.binary.read_bytes()
    digest = sha256(raw).hexdigest()
    actual = fingerprints.get(digest)
    if actual is None:
        raise SystemExit(
            f"sd-bt0: unknown bt0 fingerprint {digest}; expected {args.identity}"
        )
    if actual != args.identity:
        raise SystemExit(
            f"sd-bt0: bt0 fingerprint is {actual}, expected {args.identity}"
        )
    # firmware.bin starts at the eGON offset, so bt0 is its prefix. Wrap
    # the same in-memory bytes we fingerprinted with mkimage's own function.
    egon = runpy.run_path(str(ROOT / "scripts/mkimage.py"))["egon"]
    expected_prefix = egon(raw)
    with args.firmware.open("rb") as package:
        prefix = package.read(len(expected_prefix))
        if prefix != expected_prefix:
            raise SystemExit(
                "sd-bt0: packaged bt0 does not match the fingerprinted raw bt0"
            )
        # Hash the checked prefix plus the remainder from this same open file.
        firmware_digest = sha256(prefix)
        for chunk in iter(lambda: package.read(1024 * 1024), b""):
            firmware_digest.update(chunk)
    print(f"sd-bt0: packaged bt0 matches {actual} ({digest})", file=sys.stderr)
    print(firmware_digest.hexdigest())


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(required=True)
    compile_parser = commands.add_parser("build")
    compile_parser.add_argument("identity", choices=IDENTITIES)
    compile_parser.add_argument("scratch", type=Path)
    compile_parser.add_argument("target_dir", type=Path)
    compile_parser.add_argument("--otp", action="store_true")
    compile_parser.add_argument("--vendor-input", type=Path)
    compile_parser.set_defaults(handler=build)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("identity", choices=IDENTITIES)
    verify_parser.add_argument("binary", type=Path)
    verify_parser.add_argument("firmware", type=Path)
    verify_parser.set_defaults(handler=verify)
    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
