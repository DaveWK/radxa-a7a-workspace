#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Flag raw FEL tool references in workspace consumers, including new runners."""

from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
RAW = re.compile(r"(?<![\w-])(?:xfel(?:-t60)?|sunxi-fel)(?![\w-])", re.I)
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
}
ALLOW = {
    "Makefile": (
        "XFEL    ?= $(OUT)/tools/xfel",
        "firmware fel-image xfel fel-boot rpms fedora-image serial test clean mrproper FORCE",
        "xfel: $(XFEL)",
        "ifeq ($(origin XFEL),file)",
        "$(XFEL): scripts/build-xfel.sh scripts/xfel-port-select.patch scripts/xfel-source.json scripts/fel-tools.py",
        "$(XFEL):",
        "fel-boot: $(XFEL)",
        "$(if $(filter-out file,$(origin XFEL)),XFEL=$(call shell-quote,$(XFEL))) EXPECT_MODE=$(FEL_TAG_MODE) EXPECT_PROFILE=$(PROFILE) scripts/fel-boot.sh $(FEL_OUT)",
        "test: check-sources $(OUT)/tools/xfel",
        "python3 -I scripts/test-xfel-binary.py $(OUT)/tools/xfel",
    ),
    "scripts/fel-boot.sh": (
        "if [[ -v XFEL ]]; then",
        "XFEL=$SCRIPTS/../out/tools/xfel",
        'xfel_source=$(command -v -- "$XFEL") || die "xfel not found (XFEL=$XFEL)"',
        'python3 -I "$SCRIPTS/fel-tools.py" stage-xfel "${xfel_flags[@]}" "$xfel_source" "$STAGE/xfel"',
        "export XFEL=$STAGE/xfel",
        """EXPECT_XFEL_SHA256=$(sha256sum <"$XFEL" | cut -d' ' -f1)""",
        'ver=$(x version) || die "xfel version failed"',
        'x exec "$ENTRY1" || die "xfel exec $ENTRY1 failed (see the serial console)"',
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
    print(
        "workspace FEL consumer scan passed; three injected raw dispatch forms detected"
    )


if __name__ == "__main__":
    main()
