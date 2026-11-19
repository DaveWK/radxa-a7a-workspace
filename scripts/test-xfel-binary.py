#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check actual patched xfel discovery against a replacement USB library."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main(binary):
    scratch = Path(__file__).resolve().parent.parent / "out"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch) as tmp:
        lib = Path(tmp) / "libusb-1.0.so.0"
        cflags = subprocess.check_output(
            ["pkg-config", "--cflags", "libusb-1.0"], text=True
        ).split()
        subprocess.run(
            [
                "cc",
                "-shared",
                "-fPIC",
                "-Wall",
                "-Wextra",
                "-Werror",
                *cflags,
                Path(__file__).parent / "tests/xfel-usb-shim.c",
                "-o",
                lib,
            ],
            check=True,
        )
        env = os.environ | dict(LD_LIBRARY_PATH=tmp)
        links = subprocess.check_output(["ldd", binary], text=True, env=env)
        if f"libusb-1.0.so.0 => {lib} (" not in links:
            sys.exit("refusing: binary is not linked to the mock")
        result = subprocess.check_output([binary, "--help"], env=env)
        assert b"--port BUS-PORT" in result
        print("PASS help")
        for fixture, port, expected in (
            ("empty", None, []),
            ("two", None, []),
            ("one", None, ["14"]),
            ("two", "3-3.4", ["14"]),
            ("two", "3-6", ["12"]),
            ("two", "3-3", []),
            ("two", "4-6", []),
            ("wrong", "3-6", []),
            ("duplicate", "3-3.4", []),
            ("unreadable", "3-3.4", []),
        ):
            cmd = [binary, *(["--port", port] if port else []), "version"]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, env=env | dict(USB_CASE=fixture)
            )
            assert proc.returncode == 125, (cmd, proc.stderr)
            opens = [
                line.removeprefix("mock open ")
                for line in proc.stderr.splitlines()
                if line.startswith("mock open ")
            ]
            assert opens == expected, (fixture, cmd, opens)
            print(f"PASS {fixture=} {port=} {opens=}")
        # Mock open succeeds, then claim fails; no bulk API exists in the shim.
        proc = subprocess.run(
            [binary, "--port", "3-6", "version"],
            capture_output=True,
            text=True,
            env=env | dict(USB_CASE="receipt"),
        )
        assert proc.returncode == 255
        assert proc.stderr.splitlines() == [
            "mock open 12",
            "xfel: selected bus=3 port=3-6 devnum=12",
        ]
        print("PASS selected-device receipt")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve(strict=True))
