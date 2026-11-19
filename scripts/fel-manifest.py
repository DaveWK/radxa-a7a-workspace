#!/usr/bin/env python3
"""Write the build-mode manifest for a `make fel-image` output directory.

The manifest sits next to bt0-fel.bin, firmware.bin and firmware.seek and
records which DRAM path built the FEL bt0, the cargo features, the source
revisions and the sha256 of each image. scripts/fel-boot.sh reads it before
any USB access: only a blobfree manifest is booted, and the recorded digests
must match the files. A dramlib or phyfw image is a measurement build, booted
only when the caller sets FEL_MEASUREMENT_ONLY=yes.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

MODES = ("blobfree", "dramlib", "phyfw")
MANIFEST = "build-manifest.json"
DIGESTS = (
    ("bt0-fel.bin", "bt0_fel_sha256"),
    ("firmware.bin", "firmware_sha256"),
    ("firmware.seek", "firmware_seek_sha256"),
)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", required=True, help="fel-image output directory")
    ap.add_argument("--mode", required=True, choices=MODES, help="DRAM path")
    ap.add_argument("--features", default="", help="space-separated cargo features")
    ap.add_argument("--source-sha", required=True, help="workspace git revision")
    ap.add_argument("--oreboot-sha", required=True, help="oreboot submodule revision")
    a = ap.parse_args()

    d = Path(a.dir)
    missing = [name for name, _ in DIGESTS if not (d / name).is_file()]
    if missing:
        sys.exit(f"fel-manifest: {d}: missing {', '.join(missing)}")

    manifest = {
        "mode": a.mode,
        "features": a.features.split(),
        "source_sha": a.source_sha,
        "oreboot_sha": a.oreboot_sha,
    }
    for name, key in DIGESTS:
        manifest[key] = sha256(d / name)

    out = d / MANIFEST
    with open(out, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"{out}: mode {a.mode}, features {' '.join(manifest['features'])}")


if __name__ == "__main__":
    main()
