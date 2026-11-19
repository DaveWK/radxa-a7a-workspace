# SPDX-License-Identifier: GPL-2.0-only
"""Preflight and read-back gates for a private, staged A7A cached set."""

import hashlib
from pathlib import Path
import re
import runpy
import shutil
import struct
import time

prepare_layout = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "fel-check.py")
)["prepare_layout"]
MEMBERS = {
    "bt0-fel.bin",
    "firmware.bin",
    "firmware.seek",
    "LOAD-ORDER.md",
    "extracted/table.bin",
    "extracted/kind1.bin",
    "extracted/kind2.bin",
}
ADDRESSES = {"table": "0xdf200", "kind1": "0x40000000", "kind2": "0x41000000"}
PORT_MB = {"3-3.4": 4096, "3-6": 6144}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stage(source, work, expected):
    """Return hashes and expected MHz; only consume the checked private copies."""
    if source.is_symlink() or not source.is_dir():
        raise ValueError("expected a cached set directory")
    for path in source.rglob("*"):
        name = path.relative_to(source).as_posix()
        if path.is_symlink() or not (
            (name == "extracted" and path.is_dir())
            or (name in MEMBERS | {"SHA256SUMS"} and path.is_file())
        ):
            raise ValueError(f"unlisted or non-regular member: {name}")
    manifest = (source / "SHA256SUMS").read_bytes()
    seal = hashlib.sha256(manifest).hexdigest()
    if seal != expected:
        raise ValueError("SHA256SUMS differs from the expected set digest")
    hashes = {}
    for line in manifest.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or match[2] not in MEMBERS or match[2] in hashes:
            raise ValueError("invalid or duplicate manifest entry")
        hashes[match[2]] = match[1]
    if hashes.keys() != MEMBERS:
        raise ValueError("incomplete cached set")
    (work / "extracted").mkdir()
    for name, checksum in hashes.items():
        dst = work / name
        shutil.copyfile(source / name, dst)
        if digest(dst) != checksum:
            raise ValueError(f"hash mismatch: {name}")

    order = (work / "LOAD-ORDER.md").read_text()
    profile = re.findall(r"^# [^\n]+ — (1200|2400) MHz — cached memtest$", order, re.M)
    if len(profile) != 1:
        raise ValueError("missing or ambiguous cached-memtest profile")
    for pattern, address in (
        (r"upload bt0-fel\.bin into SRAM \((0x[0-9a-fA-F]+)\)", "0x90000"),
        (r"Execute entry 1 \((0x[0-9a-fA-F]+)\)", "0x90040"),
        (r"Execute entry 2 \((0x[0-9a-fA-F]+)\)", "0x90044"),
        (r"table frame to (0x[0-9a-fA-F]+)", ADDRESSES["table"]),
        (r"kind 1 \(main\) to (0x[0-9a-fA-F]+)", ADDRESSES["kind1"]),
        (r"kind 2 \(EDK2 FD\) to (0x[0-9a-fA-F]+)", ADDRESSES["kind2"]),
    ):
        if re.findall(pattern, order) != [address]:
            raise ValueError(f"LOAD-ORDER address mismatch: expected {address}")

    verified = work / "layout"
    verified.mkdir()
    prepare_layout(work, verified)
    if (verified / "kind3.bin").exists():
        raise ValueError("unexpected separate DTB in cached set")
    for label in ADDRESSES:
        name = f"{label}.bin"
        if digest(verified / name) != hashes[f"extracted/{name}"]:
            raise ValueError(f"cached {name} differs from firmware layout")
    return hashes | {"SHA256SUMS": seal}, int(profile[0])


def put(call, work, address, source):
    """Write and compare an exact-length fresh read, both through the same caller."""
    readback = work / "readback"
    readback.unlink(missing_ok=True)
    call("write", address, str(source))
    call("read", address, str(source.stat().st_size), str(readback))
    if digest(readback) != digest(source):
        raise ValueError(f"read-back mismatch at {address}")


def read_mailbox(call, work, *, timeout=65):
    mailbox = work / "mailbox"
    mailbox.unlink(missing_ok=True)
    call("read", "0xdf000", "28", str(mailbox), timeout=timeout)
    data = mailbox.read_bytes()
    if len(data) != 28:
        raise ValueError("short Entry 1 mailbox")
    return struct.unpack("<7I", data)[:4]


def require_ready(mailbox, port, mhz):
    if mailbox != (0x46413741, 0x11, PORT_MB[port], mhz):
        raise ValueError("Entry 1 mailbox magic, state, size or frequency mismatch")


def entry_one(call, work, port, mhz, before_exec=lambda: None):
    zero = work / "zero"
    zero.write_bytes(bytes(4096))
    put(call, work, "0xdf000", zero)
    put(call, work, "0x90000", work / "bt0-fel.bin")
    call("read32", "0x90040")
    deadline = time.monotonic() + 60
    before_exec()
    call("exec", "0x90040", timeout=max(0, deadline - time.monotonic()))
    while time.monotonic() < deadline:
        mailbox = read_mailbox(call, work, timeout=max(0, deadline - time.monotonic()))
        if time.monotonic() >= deadline:
            break
        state = mailbox[1]
        if state == 0x11:
            require_ready(mailbox, port, mhz)
            return mailbox
        if state not in (0, 0x10):
            raise ValueError(f"unexpected Entry 1 mailbox state {state:#x}")
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))
    raise ValueError("Entry 1 mailbox timeout")


def upload_dram(call, work):
    for label, address in ADDRESSES.items():
        put(call, work, address, work / "extracted" / f"{label}.bin")
