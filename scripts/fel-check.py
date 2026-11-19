#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Validate a staged FEL bundle before fel-boot touches USB.

Checks the build-mode manifest against the staged copies: mode, profile,
features, clean flag, workspace and oreboot SHAs, and the SHA-256 of each
image. A dramlib or phyfw bundle is a measurement build and additionally
needs FEL_MEASUREMENT_AUTH, a file naming this bt0's digest and a human
authorization reference.
"""

import argparse
import importlib.util
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("fel_manifest", HERE / "fel-manifest.py")
fel_manifest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fel_manifest)

ROOT = HERE.parent


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("bundle", help="staged bundle directory")
    ap.add_argument("--expect-profile", default="1200")
    ap.add_argument("--measurement-auth")
    a = ap.parse_args()

    workspace = Path(os.environ.get("EXPECT_WORKSPACE", ROOT))
    oreboot = Path(os.environ.get("EXPECT_OREBOOT", ROOT / "firmware" / "oreboot"))
    expect_source = os.environ.get("EXPECT_SOURCE_SHA") or fel_manifest.git_sha(
        workspace
    )
    expect_oreboot = os.environ.get("EXPECT_OREBOOT_SHA") or fel_manifest.git_sha(
        oreboot
    )
    if not expect_source:
        sys.exit("fel-check: cannot resolve the workspace HEAD (set EXPECT_SOURCE_SHA)")
    if not expect_oreboot:
        sys.exit("fel-check: cannot resolve the oreboot HEAD (set EXPECT_OREBOOT_SHA)")

    info = fel_manifest.check_manifest(
        a.bundle, expect_source, expect_oreboot, a.expect_profile, a.measurement_auth
    )
    print(
        f"fel-check: mode {info['mode']}; profile {info['profile']};"
        f" source {info['source_sha']}; oreboot {info['oreboot_sha']}; clean"
    )
    if info["auth"]:
        print(f"fel-check: measurement authorization: {info['auth']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
