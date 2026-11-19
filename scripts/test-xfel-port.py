#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the stateless selector with fake sysfs and a fake transport."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent


class SelectorTests(unittest.TestCase):
    def setUp(self):
        out = SCRIPTS.parent / "out"
        out.mkdir(exist_ok=True)
        tmp = tempfile.TemporaryDirectory(dir=out)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.sysfs = self.root / "devices"
        self.sysfs.mkdir()
        self.log = self.root / "commands"
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        for name in (
            "xfel-port",
            "fel-tools.py",
            "xfel-source.json",
            "xfel-port-select.patch",
        ):
            shutil.copy2(SCRIPTS / name, self.scripts)
        self.tool = self.root / "out/tools/xfel"
        self.tool.parent.mkdir(parents=True)
        self.tool.write_text(
            "#!/usr/bin/python3 -I\n"
            "import json, os, signal, sys\n"
            "if sys.argv[1:] == ['--help']:\n"
            "    print('xfel --port PATH --devnum N COMMAND ...')\n"
            "    sys.exit(0)\n"
            "with open(os.environ['COMMANDS'], 'a') as log:\n"
            "    print(json.dumps(sys.argv[1:]), file=log)\n"
            "rc = int(os.environ.get('STATUS', '0'))\n"
            "if rc < 0: os.kill(os.getpid(), -rc)\n"
            "sys.exit(rc)\n"
        )
        self.tool.chmod(0o755)
        pins = json.loads((self.scripts / "xfel-source.json").read_text())
        self.tool.with_suffix(".record.json").write_text(
            json.dumps(
                dict(
                    pins,
                    binary_sha256=hashlib.sha256(self.tool.read_bytes()).hexdigest(),
                )
            )
        )
        self.env = dict(
            {
                k: v
                for k, v in os.environ.items()
                if k not in ("XFEL", "EXPECT_XFEL_SHA256", "SUDO")
            },
            FEL_SYSFS_ROOT=str(self.sysfs),
            COMMANDS=str(self.log),
        )
        self.add("3-3.4", 14)
        self.add("3-6", 12)

    def add(self, port, number):
        path = self.sysfs / port
        path.mkdir()
        for key, value in dict(
            idVendor="1f3a",
            idProduct="efe8",
            busnum=3,
            devpath=port.split("-")[1],
            devnum=number,
        ).items():
            (path / key).write_text(str(value) + "\n")

    def run_selector(
        self, *args, rc=0, stdout=subprocess.PIPE, closed_stdout=False, **overrides
    ):
        command = [self.scripts / "xfel-port", *args]
        if closed_stdout:
            command = ["/bin/sh", "-c", 'exec "$@" 1>&-', "fixture", *command]
        proc = subprocess.run(
            command,
            env=dict(self.env, **overrides),
            text=True,
            stdout=stdout,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        self.assertEqual(proc.returncode, rc, (proc.stdout, proc.stderr))
        return proc

    def dispatch(self, port="3-6", devnum="12", **options):
        return self.run_selector(
            "--port", port, "--devnum", devnum, "--", "version", **options
        )

    def test_discover_without_transport(self):
        for port, expected in (("3-6", "12\n"), ("3-3.4", "14\n")):
            self.assertEqual(
                self.run_selector(
                    "--discover", "--port", port, XFEL="nonexistent"
                ).stdout,
                expected,
            )
        self.assertFalse(self.log.exists())

    def test_discover_output_errors(self):
        args = ("--discover", "--port", "3-6")
        with open("/dev/full", "wb", buffering=0) as sink:
            self.run_selector(*args, rc=74, stdout=sink)
        reader, writer = os.pipe()
        os.close(reader)
        try:
            self.run_selector(*args, rc=74, stdout=writer)
        finally:
            os.close(writer)
        self.run_selector(*args, rc=74, closed_stdout=True)
        self.assertFalse(self.log.exists())

    def test_help_is_only_standalone(self):
        for flag in ("-h", "--help"):
            with self.subTest(flag=flag):
                usage = self.run_selector(flag).stdout
                self.assertIn("usage:", usage)
                self.assertIn("-h/--help must be used on its own.", usage)
                self.run_selector(flag, rc=74, closed_stdout=True)
        for args in (
            ("--port", "3-6", "--devnum", "12", "--help", "--", "version"),
            ("--port", "3-6", "--devnum", "12", "-hh", "--", "version"),
            ("--port", "3-6", "--devnum", "12", "-hfoo", "--", "version"),
            ("--port", "3-6", "--devnum", "12", "--", "write", "0", "--help"),
            ("--discover", "--port", "3-6", "-h"),
        ):
            with self.subTest(args=args):
                self.run_selector(*args, rc=2)
        self.assertFalse(self.log.exists())

    def test_full_command_grammar_precedes_discovery(self):
        for port in ("3-6", "3-7"):
            for cmd in (
                ("read32",),
                ("exec", "not-an-address"),
                ("version", "extra"),
                ("read32", "+1"),
                ("exec", "1 "),
                ("exec", "0x"),
                ("exec", "08"),
                ("exec", "0b02"),
                ("write32", "1", "0x100000000"),
                ("read", "0", "0", "file"),
                ("read", "0xffffffff", "2", "file"),
                ("write", "0", "--devnum=12"),
            ):
                with self.subTest(port=port, cmd=cmd):
                    self.run_selector(
                        "--port", port, "--devnum", "12", "--", *cmd, rc=2
                    )
        self.assertFalse(self.log.exists())

    def test_valid_numeric_forms(self):
        args = ("--port", "3-6", "--devnum", "12", "--")
        for command in (
            ("write32", "0b101", "0X2A"),
            ("exec", "010"),
            ("read", "4294967295", "1", "file"),
            ("write32", "0", "0"),
        ):
            self.run_selector(*args, *command)
        self.assertEqual(len(self.log.read_text().splitlines()), 4)

    def test_pin_each_board(self):
        self.dispatch("3-6", "12")
        self.dispatch("3-3.4", "14")
        self.assertEqual(
            list(map(json.loads, self.log.read_text().splitlines())),
            [
                ["--port", "3-6", "--devnum", "12", "version"],
                ["--port", "3-3.4", "--devnum", "14", "version"],
            ],
        )

    def test_mismatch_is_not_loss(self):
        self.dispatch(devnum="19", rc=125)
        (self.sysfs / "3-6/idVendor").write_text("ffff")
        self.dispatch(rc=125)
        self.assertFalse(self.log.exists())

    def test_missing_connector_not_incomplete_root(self):
        self.dispatch(port="3-7", rc=66)
        self.dispatch(FEL_SYSFS_ROOT=str(self.root / "missing-root"), rc=125)
        (self.sysfs / "3-6/devnum").unlink()
        self.dispatch(rc=125)
        self.assertFalse(self.log.exists())

    def test_peer_churn_is_not_input(self):
        (self.sysfs / "3-3.4/devnum").unlink()
        self.dispatch()

    def test_missing_duplicate_and_retired_options(self):
        for args in (
            ("--port", "3-6", "--", "version"),
            ("--port", "3-6", "--port", "3-6", "--devnum", "12", "--", "version"),
            ("--port", "3-6", "--discover", "--devnum", "12"),
            ("--port", "3-6", "--state", "saved", "--", "version"),
            ("--port", "3-6", "--after-reset", "--", "version"),
        ):
            with self.subTest(args=args):
                self.run_selector(*args, rc=2)
        self.assertFalse(self.log.exists())

    def test_status_propagated(self):
        for status in (65, 66, 74, 76, 125, 31, -signal.SIGTERM):
            with self.subTest(status=status):
                self.dispatch(
                    rc=status if status >= 0 else 128 - status, STATUS=str(status)
                )

    def test_noop_prefix_refused(self):
        self.dispatch(rc=125, SUDO="/usr/bin/true")
        self.assertFalse(self.log.exists())

    def test_help_compatible_unapproved_binary_never_runs(self):
        impostor = self.root / "impostor"
        impostor.write_text(
            "#!/bin/sh\n"
            'echo launched >>"$COMMANDS"\n'
            "echo 'xfel --port PATH --devnum N COMMAND ...'\n"
        )
        impostor.chmod(0o755)
        self.dispatch(
            rc=125,
            XFEL=str(impostor),
            EXPECT_XFEL_SHA256=hashlib.sha256(impostor.read_bytes()).hexdigest(),
        )
        shutil.copy2(impostor, self.tool)
        self.dispatch(rc=125)
        self.assertFalse(self.log.exists())

    def test_unsupported_command_and_bad_port_before_lookup(self):
        self.run_selector("--port", "3-7", "--devnum", "12", "--", "typo", rc=2)
        for port in ("3-256", "256-1", "3-1.1.1.1.1.1.1.1", "3-01"):
            self.run_selector("--discover", "--port", port, rc=2)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
