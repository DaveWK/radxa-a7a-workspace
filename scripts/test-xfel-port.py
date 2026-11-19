#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the stateless selector with fake sysfs and a fake transport."""

import hashlib
import json
import os
from pathlib import Path
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
        self.tool = self.root / "fake-transport"
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
        self.env = dict(
            os.environ,
            XFEL=str(self.tool),
            EXPECT_XFEL_SHA256=hashlib.sha256(self.tool.read_bytes()).hexdigest(),
            FEL_SYSFS_ROOT=str(self.sysfs),
            SUDO="",
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

    def run_selector(self, *args, rc=0, **overrides):
        proc = subprocess.run(
            [SCRIPTS / "xfel-port", *args],
            env=dict(self.env, **overrides),
            text=True,
            capture_output=True,
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

    def test_legacy_binary_refused_after_help_only(self):
        self.tool.write_text("#!/bin/sh\nprintf 'upstream usage\\n'\n")
        new_hash = hashlib.sha256(self.tool.read_bytes()).hexdigest()
        self.dispatch(rc=125, EXPECT_XFEL_SHA256=new_hash)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
