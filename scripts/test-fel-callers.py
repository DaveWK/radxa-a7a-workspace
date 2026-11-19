#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Flag raw FEL tool references in workspace consumers, including new runners."""

from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
RAW = re.compile(r"(?<![\w-])(?:xfel(?:-t60)?|sunxi-fel|FEL_TOOL)(?![\w-])", re.I)
# Non-consumers: building/staging, mock programs, and the sole real dispatcher.
INFRA = {
    "scripts/build-xfel.sh",
    "scripts/fel-tools.py",
    "scripts/xfel-port",
    "scripts/tests/xfel-usb-shim.c",
    "scripts/test-xfel-port.py",
    "scripts/test-xfel-binary.py",
    "scripts/test-fel-callers.py",
    "scripts/test-fel-manifest.py",
    "scripts/test-cached-run.py",
}
ALLOW = {
    "Makefile": (
        "firmware fel-image xfel fel-boot rpms fedora-image serial test clean mrproper FORCE",
        "xfel: $(TOP)/out/tools/xfel $(TOP)/out/tools/xfel.record.json",
        "$(TOP)/out/tools/xfel $(TOP)/out/tools/xfel.record.json &: scripts/build-xfel.sh scripts/xfel-port-select.patch scripts/xfel-source.json scripts/fel-tools.py",
        "test: check-sources xfel",
        "python3 -I scripts/test-xfel-binary.py $(TOP)/out/tools/xfel",
    ),
}


def raw_lines(name, text):
    return [
        f"{name}:{n}"
        for n, line in enumerate(text.splitlines(), 1)
        if not line.lstrip().startswith("#")
        and RAW.search(line)
        and line.strip() not in ALLOW.get(name, ())
    ]


def main():
    for forbidden in (
        "xfel version",
        'timeout 5 "$XFEL" read 1 4 m',
        '"${FEL_TOOL}" version',
        'tool=$(command -v xfel); "$tool" version',
        "sudo sunxi-fel ver",
    ):
        assert raw_lines("scripts/fel-boot.sh", forbidden)
    paths = (
        subprocess.check_output(
            [
                "git",
                "-C",
                ROOT,
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ]
        )
        .decode()
        .split("\0")
    )
    findings = []
    for name in paths:
        path = ROOT / name
        if name in INFRA or path.suffix in (".md", ".patch") or not path.is_file():
            continue
        findings.extend(raw_lines(name, path.read_text()))
    if findings:
        raise SystemExit("raw FEL references: " + ", ".join(findings))
    print("workspace FEL consumer scan passed")


if __name__ == "__main__":
    main()
