#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fence Entry-2 evidence by board, regular log identity and starting byte."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

LOGS = {
    "3-3.4": "2026-11-18-1725-4g-luckfox.log",
    "3-6": "2026-11-18-1725-6g-luckfox.log",
}
HANDOVER = re.compile(
    rb"(?m)^\[bt0\] RVBAR 00000000:40000000[^\r\n]*\r?\n[\s\S]*?^main>"
)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("port")
    p.add_argument("log", type=Path)
    p.add_argument("--since", help="JSON cursor from immediately before Entry 2")
    args = p.parse_args()
    path = Path.home() / "src/radxa-a7a/serial-logs" / LOGS[args.port]
    if args.log.absolute() != path or path.resolve(strict=True) != path:
        raise ValueError("serial log is not the registered path for this port")
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("not a regular serial log")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("not a regular serial log")
        cursor = dict(port=args.port, log=str(path), device=st.st_dev, inode=st.st_ino)
        if args.since is None:
            print(json.dumps(dict(**cursor, start=st.st_size)))
            return
        old = json.loads(args.since)
        start = old.pop("start")
        if old != cursor or not 0 <= st.st_size - start <= 1 << 20 or start < 0:
            raise ValueError("rotated, truncated or oversized serial interval")
        stream.seek(max(start - 1, 0))
        length = st.st_size - stream.tell()
        chunk = stream.read(length)
        if len(chunk) != length or not os.path.samestat(path.lstat(), st):
            raise ValueError("serial log changed while reading the slice")
        slice_digest = hashlib.sha256(chunk[bool(start) :]).hexdigest()
        if start:
            # Do not credit a line that began before the submission fence.
            chunk = chunk[1:] if chunk.startswith(b"\n") else chunk.partition(b"\n")[2]
        if not HANDOVER.search(chunk):
            raise ValueError("no fresh RVBAR then main> on this board")
        print(
            json.dumps(
                dict(
                    **cursor,
                    start=start,
                    end=st.st_size,
                    slice_sha256=slice_digest,
                )
            )
        )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        sys.exit(f"handover unconfirmed: {exc}")
