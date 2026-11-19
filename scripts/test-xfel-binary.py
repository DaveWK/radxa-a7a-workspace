#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the built selector with mock libusb and *only* synthetic sysfs/usbfs."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile


def main(binary, red=False, round4_base=False):
    scripts = Path(__file__).resolve().parent
    (scripts.parent / "out").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scripts.parent / "out") as tmp:
        root = Path(tmp)
        lib = root / "libusb-1.0.so.0"
        subprocess.run(
            [
                "cc",
                "-shared",
                "-fPIC",
                "-Wall",
                "-Wextra",
                "-Werror",
                *subprocess.check_output(
                    ["pkg-config", "--cflags", "libusb-1.0"], text=True
                ).split(),
                scripts / "tests/xfel-usb-shim.c",
                "-o",
                lib,
            ],
            check=True,
        )
        shutil.copy2(binary, root / "xfel")
        for name in ("write-input", "partial-input"):
            (root / name).write_bytes(b"complete fixture input\n")
        nodes = root / "usb/003"
        nodes.mkdir(parents=True)
        devices = root / "devices"
        devices.mkdir()

        def add(name, number, vid="1f3a", chain=None, fd_pid=0xEFE8):
            path = devices / name
            path.mkdir()
            fields = dict(
                idVendor=vid,
                idProduct="efe8",
                busnum="3",
                devnum=str(number),
                devpath=chain or name[2:],
            )
            for key, val in fields.items():
                (path / key).write_text(val + "\n")
            desc = bytearray(18)
            desc[:2] = b"\x12\x01"
            desc[8:12] = b"\x3a\x1f" + fd_pid.to_bytes(2, "little")
            (nodes / f"{number:03}").write_bytes(desc)

        # No host /sys or /dev/bus anywhere inside the process mount namespace.
        jail = [
            "bwrap",
            "--unshare-all",
            "--die-with-parent",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--ro-bind",
            devices,
            "/sys/bus/usb/devices",
            "--bind",
            nodes.parent,
            "/dev/bus/usb",
            "--ro-bind",
            root,
            "/fixture",
            "--setenv",
            "LD_LIBRARY_PATH",
            "/fixture",
        ]
        links = subprocess.check_output(
            [*jail, "/lib64/ld-linux-x86-64.so.2", "--list", "/fixture/xfel"], text=True
        )
        assert "libusb-1.0.so.0 => /fixture/libusb-1.0.so.0" in links
        selected = ["--port", "3-6", "--devnum", "12", "version"]

        def run(
            name,
            args,
            rc,
            opened=None,
            claim=False,
            shell=None,
            version=False,
            output_error=False,
            closed_pipe=False,
            writes=None,
            partial=False,
        ):
            if output_error:
                shell = shlex.join(["/fixture/xfel", *args]) + " >/dev/full"
            argv = [
                *jail,
                "--setenv",
                "PATH",
                "/fixture:/usr/bin",
                "--setenv",
                "FEL_TOOL",
                "xfel",
                "--setenv",
                "XFEL",
                "xfel",
                *(
                    ["/fixture/xfel", *args]
                    if shell is None
                    else ["/usr/bin/bash", "-c", shell]
                ),
            ]
            reader, writer = os.pipe() if closed_pipe else (None, None)
            if reader is not None:
                os.close(reader)
            try:
                proc = subprocess.run(
                    argv,
                    stdout=writer if closed_pipe else subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=os.environ | dict(USB_CASE=name),
                )
            finally:
                if writer is not None:
                    os.close(writer)
            assert proc.returncode == rc, (
                name,
                proc.returncode,
                proc.stdout,
                proc.stderr,
            )
            lines = proc.stderr.splitlines()
            assert [s for s in lines if s.startswith("mock fd ")] == (
                [] if opened is None else [f"mock fd {opened}"]
            ), (name, lines)
            assert ("mock wrap" in lines) == claim and ("mock claim" in lines) == claim
            assert ("mock init" in lines) == claim
            if writes is not None:
                assert lines.count("mock FEL write request") == writes, (name, lines)
            if partial:
                assert "mock input prefix" in lines and "mock input EIO" in lines
            if version:
                assert (
                    "ID=0x00190300" in proc.stdout and f"devnum={opened}" in proc.stderr
                )
            print(f"PASS {name} exit={rc} fd={opened} claim={claim}")

        prefix = selected[:-1]
        ack_cases = (
            ("version", ["version"]),
            ("entry2", ["exec", "0x90044"]),
            ("wdt", ["write32", "0x0205000c", "0x000014af"]),
        )
        if red:
            add("3-6", 12)
            for name, command in ack_cases:
                for kind in ("malformed", "rejected"):
                    run(f"{name}-{kind}", [*prefix, *command], 0, 12, True)
            run("sole-without-selector", ["version"], 0, 12, True)
            return

        def framing_and_io(base):
            read = [*prefix, "read", "0xdf000", "28", "/dev/null"]
            write = [*prefix, "write", "0xdf000", "/fixture/write-input"]
            for name, old in (
                ("awus-short", 0),
                ("awus-bad-tail", 0),
                ("awus-long", 65),
                ("awus-overflow", 74),
                ("header-short", 0),
            ):
                run(name, selected, old if base else 65, 12, True)
            for command, args in (("read", read), ("write", write)):
                for kind, rc in (("malformed", 65), ("rejected", 76)):
                    run(f"{command}-{kind}", args, rc, 12, True)
            input_fd, claimed = (12, True) if base else (None, False)
            run(
                "missing-input",
                [*write[:-1], "/fixture/missing"],
                255 if base else 74,
                input_fd,
                claimed,
                writes=0,
            )
            run(
                "partial-input",
                [*write[:-1], "/fixture/partial-input"],
                0 if base else 74,
                input_fd,
                claimed,
                writes=int(base),
                partial=True,
            )
            run(
                "version-output-failure",
                selected,
                0 if base else 74,
                12,
                True,
                output_error=True,
            )
            run(
                "read32-output-failure",
                [*prefix, "read32", "0xdf000"],
                0 if base else 74,
                12,
                True,
                output_error=True,
            )
            run(
                "version-broken-pipe",
                selected,
                141 if base else 74,
                12,
                True,
                closed_pipe=True,
            )
            if not base:
                run("read-ack", read, 0, 12, True)
                run("write-ack", write, 0, 12, True, writes=1)

        if round4_base:
            add("3-6", 12)
            framing_and_io(True)
            return
        run("help", ["--help"], 0)
        run("no-args", [], 2)
        run("empty", ["version"], 2)
        add("3-3.4", 14)
        run("sole", ["version"], 2)
        run("misplaced", ["version", "--port", "3-6"], 2)
        add("3-6", 12)
        run("ambiguous", ["version"], 2)
        for name, shell in (
            ("raw-direct", "xfel version"),
            ("raw-fel-tool", '"$FEL_TOOL" version'),
            ("raw-xfel", '"$XFEL" version'),
            ("raw-variable", 'selected=$(command -v xfel); "$selected" version'),
        ):
            run(name, [], 2, shell=shell)
        run("duplicate-option", [*selected, "--port", "3-6"], 2)
        run("missing-devnum", ["--port", "3-6", "version"], 2)
        run("missing-port", ["--devnum", "12", "version"], 2)
        run("unknown-command", [*prefix, "bogus"], 2)
        run("selected-6", selected, 0, 12, True, version=True)
        framing_and_io(False)
        run(
            "selected-4",
            ["--port", "3-3.4", "--devnum", "14", "version"],
            0,
            14,
            True,
            version=True,
        )
        run("missing-connector", ["--port", "3-3", "--devnum", "14", "version"], 66)
        for name in ("fd-port", "fd-bus", "fd-address", "no-conninfo"):
            run(name, selected, 125, 12)
        run("open-gone", selected, 66)
        run("descriptor-gone", selected, 66, 12)
        run(
            "read-gone",
            [*prefix, "read", "0xdf000", "28", "/never-written"],
            66,
            12,
            True,
        )
        run(
            "read-timeout",
            [*prefix, "read", "0xdf000", "28", "/never-written"],
            74,
            12,
            True,
        )
        for name, command in ack_cases:
            for kind, rc in (("malformed", 65), ("rejected", 76)):
                run(f"{name}-{kind}", [*prefix, *command], rc, 12, True)
        run("version-short", selected, 65, 12, True)
        for name, command in ack_cases[1:]:
            run(f"{name}-ack", [*prefix, *command], 0, 12, True)
        (devices / "3-6/devnum").write_text("19")
        run("changed-before-open", selected, 125)
        (devices / "3-6/devnum").write_text("12")
        (devices / "3-6/idVendor").write_text("ffff")
        run("wrong-vid", selected, 125)
        (devices / "3-6/idVendor").write_text("1f3a")
        add("3-7", 19, "ffff", chain="6")
        run("unrelated-port-is-not-input", selected, 0, 12, True, version=True)
        shutil.rmtree(devices / "3-7")
        (nodes / "012").write_bytes(bytes(18))
        run("wrong-fd-descriptor", selected, 125, 12)


if __name__ == "__main__":
    main(
        Path(sys.argv[1]).resolve(strict=True),
        red=sys.argv[2:] == ["--red"],
        round4_base=sys.argv[2:] == ["--round4-base"],
    )
