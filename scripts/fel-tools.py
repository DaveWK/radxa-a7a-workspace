#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Local FEL tool receipts. EDK2 operations run under build-edk2.sh's lock."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

OUT = Path(__file__).resolve().parent.parent / "out"
XFEL = OUT / "tools/xfel"
XFEL_RECORD = XFEL.with_suffix(".record.json")
STAMP = OUT / "edk2-basetools.stamp.json"


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def write_receipt(path, value):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as file:
        file.write((json.dumps(value, sort_keys=True, indent=2) + "\n").encode())
    Path(file.name).replace(path)


def copy_tool(source, dest):
    h = hashlib.sha256()
    with source.open("rb") as src, dest.open("xb") as dst:
        while chunk := src.read(1 << 20):
            dst.write(chunk)
            h.update(chunk)
    return h.hexdigest()


def verify_xfel_sources(record):
    pins = json.loads(Path(__file__).with_name("xfel-source.json").read_bytes())
    if any(record[k] != v for k, v in pins.items()) or pins[
        "selector_patch_sha256"
    ] != digest(Path(__file__).with_name("xfel-port-select.patch")):
        raise ValueError(
            "xfel source/selector seal mismatch; rebuild from verified inputs"
        )


def stage_xfel(args):
    if args.override:
        want = os.environ.get("EXPECT_XFEL_SHA256")
        if not want:
            raise ValueError("overridden XFEL requires EXPECT_XFEL_SHA256")
    else:
        record = json.loads(XFEL_RECORD.read_bytes())
        verify_xfel_sources(record)
        want = record["binary_sha256"]
    actual = copy_tool(args.source, args.dest)
    if actual != want:
        raise ValueError(f"xfel sha256 mismatch: {actual}")
    args.dest.chmod(0o700)
    print(f"fel-boot: staged xfel sha256 {actual}")


def tool_stamp(edk2):
    head = subprocess.check_output(
        ["git", "-C", edk2, "rev-parse", "--verify", "HEAD^{commit}"],
        env={
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        | {
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
        text=True,
    ).strip()
    if os.environ.get("EDK2_EXPECT_HEAD", head) != head:
        raise ValueError("EDK2 HEAD changed since gitlink check")
    bindir = edk2 / "BaseTools/Source/C/bin"
    binaries = {}
    for path in bindir.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"unexpected BaseTools binary entry: {path}")
        binaries[path.name] = digest(path)
    if "GenFv" not in binaries:
        raise ValueError("incomplete BaseTools build: no GenFv")
    return dict(edk2_head=head, binaries=binaries)


def verify_tools(edk2):
    raw = STAMP.read_bytes()
    if json.loads(raw) != tool_stamp(edk2):
        raise ValueError("BaseTools stamp mismatch (EDK2 HEAD or binary set/digests)")
    return hashlib.sha256(raw).hexdigest()


def config_receipt(edk2):
    conf = edk2 / "Conf"
    names = {"TOOL_CHAIN_CONF": "tools_def.txt", "BUILD_RULE_CONF": "build_rule.txt"}
    files = {
        name: (conf / name).read_bytes() for name in ("target.txt", *names.values())
    }
    # edk2 556dcfb, BaseTools/Source/Python/Common/ToolDefClassObject.py:
    # 106-117,122-150 strips lines, expands !include macros and recursively
    # searches the workspace, package paths and including directory. A gated
    # build admits only the three direct Conf files; check the bytes we hash.
    for name, data in files.items():
        for line in data.decode().splitlines():
            if line.lstrip().lower().startswith("!include"):
                raise ValueError(f"{name}: !include is not allowed in gated Conf files")
    # Pin the effective files. EDK2 first looks for Conf/Conf/foo and then
    # falls back to Conf/foo for the stock Conf/foo target.txt setting.
    for line in files["target.txt"].decode().splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and (name := names.get(key.strip())):
            value = value.strip().replace("\\", "/")
            if value not in ("", name, f"Conf/{name}") or (
                value.startswith("Conf/") and (conf / value).exists()
            ):
                raise ValueError(
                    f"target.txt redirects {key.strip()} outside the pinned Conf file"
                )
    return {
        "basetools_stamp_sha256": verify_tools(edk2),
        "conf_sha256": {
            name: hashlib.sha256(data).hexdigest() for name, data in files.items()
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    record = sub.add_parser("record-xfel")
    record.add_argument("source", type=Path)
    record.add_argument("commit")
    stage = sub.add_parser("stage-xfel")
    stage.add_argument("--override", action="store_true")
    stage.add_argument("source", type=Path)
    stage.add_argument("dest", type=Path)
    base = sub.add_parser("basetools")
    base.add_argument("edk2", type=Path)
    base.add_argument("jobs")
    for op in ("capture-config", "verify-config"):
        cfg = sub.add_parser(op)
        cfg.add_argument("edk2", type=Path)
        cfg.add_argument("receipt", type=Path)
    args = parser.parse_args()
    if args.cmd == "stage-xfel":
        stage_xfel(args)
    elif args.cmd == "record-xfel":
        sources = dict(
            source_commit=args.commit,
            patched_fel_c_sha256=digest(args.source / "fel.c"),
            patched_main_c_sha256=digest(args.source / "main.c"),
            patched_selector_h_sha256=digest(args.source / "linux-fel-port.h"),
            selector_patch_sha256=digest(
                Path(__file__).with_name("xfel-port-select.patch")
            ),
        )
        verify_xfel_sources(sources)
        with tempfile.TemporaryDirectory(dir=XFEL.parent) as temp:
            fresh = Path(temp) / "xfel"
            binary_digest = copy_tool(args.source / "xfel", fresh)
            fresh.chmod(0o755)
            fresh.replace(XFEL)
        write_receipt(
            XFEL_RECORD,
            dict(
                **sources,
                compiler=subprocess.check_output(
                    ["gcc", "--version"], text=True
                ).splitlines()[0],
                libusb_version=subprocess.check_output(
                    ["pkg-config", "--modversion", "libusb-1.0"], text=True
                ).strip(),
                binary_sha256=binary_digest,
            ),
        )
    elif args.cmd == "basetools":
        if not STAMP.exists():
            # Don't bless old objects or an unstamped installation on upgrade.
            subprocess.run(
                [
                    "make",
                    "-B",
                    "-C",
                    args.edk2 / "BaseTools/Source/C",
                    "-j" + args.jobs,
                ],
                check=True,
            )
            write_receipt(STAMP, tool_stamp(args.edk2))
        verify_tools(args.edk2)
    elif args.cmd == "capture-config":
        write_receipt(args.receipt, config_receipt(args.edk2))
    elif json.loads(args.receipt.read_bytes()) != config_receipt(args.edk2):
        raise ValueError("EDK2 tool/config identity changed during build")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"fel-tools: {exc}") from exc
