#!/usr/bin/env python3
"""Test the fel-boot build-mode gate without a USB device.

`make fel-image` writes a build-mode manifest next to the images and
scripts/fel-boot.sh checks it before any USB access. This test seeds fake
image directories, stubs xfel, sunxi-fel and lsusb on PATH, and checks that a
legacy directory or a non-blobfree manifest is refused without calling xfel,
while a correct blobfree manifest reaches the xfel call.
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FEL_BOOT = ROOT / "scripts" / "fel-boot.sh"
FEL_MANIFEST = ROOT / "scripts" / "fel-manifest.py"
IMAGES = ("bt0-fel.bin", "firmware.bin", "firmware.seek")

STUB = """#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$STUB_LOG"
if [ "$1" = version ]; then
    echo "xfel v1.4.0 ID=0x00190300"
fi
"""


def write_stub(dir):
    dir.mkdir(parents=True, exist_ok=True)
    for name in ("xfel", "sunxi-fel", "lsusb"):
        path = dir / name
        path.write_text(STUB)
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return dir


def seed(root, mode, tamper=None):
    """Create a fake out/fel/<mode> image directory; return (dir, manifest)."""
    d = root / "out" / "fel" / mode
    d.mkdir(parents=True, exist_ok=True)
    for name in IMAGES:
        (d / name).write_bytes(f"fake {mode} {name}\n".encode())
    manifest = None
    if mode != "legacy":
        subprocess.run(
            [
                sys.executable,
                "-I",
                str(FEL_MANIFEST),
                "--dir",
                str(d),
                "--mode",
                mode,
                "--features",
                "fel",
                "--source-sha",
                "a" * 40,
                "--oreboot-sha",
                "b" * 40,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        manifest = json.loads((d / "build-manifest.json").read_text())
        if tamper:
            manifest[tamper] = "0" * 64
            (d / "build-manifest.json").write_text(
                json.dumps(manifest, indent=2) + "\n"
            )
    return d, manifest


def run_fel_boot(image, stub_dir, log, measurement=None):
    env = dict(os.environ)
    env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"
    env["XFEL"] = "xfel"
    env["SUDO"] = ""
    env["STUB_LOG"] = str(log)
    if measurement is not None:
        env["FEL_MEASUREMENT_ONLY"] = measurement
    elif "FEL_MEASUREMENT_ONLY" in env:
        del env["FEL_MEASUREMENT_ONLY"]
    log.write_text("")
    proc = subprocess.run(
        ["bash", str(FEL_BOOT), str(image)],
        env=env,
        capture_output=True,
        text=True,
    )
    calls = [line for line in log.read_text().splitlines() if line.strip()]
    return proc, calls


def check(name, condition, detail):
    if condition:
        print(f"ok   {name}")
        return 0
    print(f"FAIL {name}: {detail}")
    return 1


def main():
    failures = 0
    with tempfile.TemporaryDirectory(prefix="fel-manifest-test-") as tmp:
        root = Path(tmp)
        stub_dir = write_stub(root / "stub")

        cases = [
            ("legacy", "legacy", None, None, False),
            ("dramlib refused", "dramlib", None, None, False),
            ("phyfw refused", "phyfw", None, None, False),
            ("tampered digest refused", "blobfree", "bt0_fel_sha256", None, False),
            ("blobfree accepted", "blobfree", None, None, True),
            ("measurement escape hatch", "dramlib", None, "yes", True),
        ]
        for label, mode, tamper, measurement, accepted in cases:
            image, _ = seed(root / label.replace(" ", "-"), mode, tamper)
            proc, calls = run_fel_boot(image, stub_dir, root / "stub.log", measurement)
            reached_xfel = any(line.split()[0] == "version" for line in calls)
            if accepted:
                failures += check(
                    label,
                    reached_xfel,
                    f"xfel was not called (rc={proc.returncode}, calls={calls},"
                    f" stderr={proc.stderr.strip()!r})",
                )
            else:
                failures += check(
                    label,
                    proc.returncode != 0 and not calls,
                    f"rc={proc.returncode}, calls={calls}, stderr={proc.stderr.strip()!r}",
                )
    print(f"{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
