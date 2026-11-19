#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Port admission fixtures. No USB device or production xfel is used."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
STUB = """#!/usr/bin/python3 -I
import json, os, sys
if sys.argv[1:] == ["--help"]:
    print("xfel [--port BUS-PORT[.PORT...]] COMMAND")
else:
    with open(os.environ["LOG"], "a") as log:
        print(json.dumps(sys.argv[1:]), file=log)
    sys.exit(int(os.getenv("STUB_RC", "0")))
"""


class PortTests(unittest.TestCase):
    def setUp(self):
        scratch = SCRIPTS.parent / "out"
        scratch.mkdir(exist_ok=True)
        tmp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.sysfs = self.root / "devices"
        self.sysfs.mkdir()
        self.state = self.root / "state"
        self.log = self.root / "log"
        self.log.touch()
        stub = self.root / "xfel"
        stub.write_text(STUB)
        stub.chmod(0o700)
        self.env = os.environ | dict(
            XFEL=str(stub),
            EXPECT_XFEL_SHA256=hashlib.sha256(stub.read_bytes()).hexdigest(),
            SUDO="",
            LOG=str(self.log),
            FEL_SYSFS_ROOT=str(self.sysfs),
        )
        self.device("3-3.4", 14)
        self.device("3-6", 12)

    def device(self, port, number):
        path = self.sysfs / port
        path.mkdir(exist_ok=True)
        bus, chain = port.split("-")
        for key, val in dict(
            idVendor="1f3a", idProduct="efe8", busnum=bus, devpath=chain, devnum=number
        ).items():
            (path / key).write_text(str(val))

    def call(self, *args, rc):
        before = self.log.read_bytes()
        result = subprocess.run(
            [SCRIPTS / "xfel-port", *args, "--", "version"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertEqual(result.returncode, rc, result.stderr)
        if rc in (125, 2):
            self.assertEqual(self.log.read_bytes(), before)
        return result.stderr

    def test_two_ports(self):
        for port in ("3-3.4", "3-6"):
            self.call("--port", port, rc=0)
        self.assertEqual(
            list(map(json.loads, self.log.read_text().splitlines())),
            [["--port", "3-3.4", "version"], ["--port", "3-6", "version"]],
        )

    def test_no_selector(self):
        self.call(rc=2)

    def test_missing_port_timeout(self):
        self.call("--port", "3-1", "--timeout", ".1", rc=125)

    def test_wrong_ids(self):
        for key in ("idVendor", "idProduct"):
            self.device("3-6", 12)
            (self.sysfs / "3-6" / key).write_text("0000")
            self.call("--port", "3-6", rc=125)

    def test_reenumeration(self):
        args = ["--state", self.state, "--port", "3-6"]
        self.call(*args, rc=0)
        self.call(*args, "--after-reset", rc=125)
        self.device("3-6", 19)
        record = json.loads(self.call(*args, "--after-reset", rc=0))
        self.assertEqual((record["previous_devnum"], record["devnum"]), (12, 19))
        self.assertEqual(json.loads(self.state.read_text())["devnum"], 19)

    def test_move(self):
        args = ["--state", self.state, "--port", "3-6"]
        self.call(*args, rc=0)
        shutil.rmtree(self.sysfs / "3-6")
        self.device("3-7", 19)
        self.call(*args, rc=125)
        self.call("--state", self.state, "--port", "3-7", rc=125)

    def test_peer_change(self):
        args = ["--state", self.state, "--port", "3-6"]
        self.call(*args, rc=0)
        self.device("3-3.4", 15)
        self.call(*args, rc=125)

    def test_legacy_binary(self):
        stub = Path(self.env["XFEL"])
        stub.write_text(STUB.replace("--port BUS-PORT", "old usage"))
        self.env["EXPECT_XFEL_SHA256"] = hashlib.sha256(stub.read_bytes()).hexdigest()
        self.call("--port", "3-6", rc=125)

    def test_command_failure(self):
        self.env["STUB_RC"] = "31"
        self.call("--port", "3-6", rc=31)

    def test_boot_requires_port(self):
        self.env.pop("FEL_PORT", None)
        proc = subprocess.run(
            [SCRIPTS / "fel-boot.sh", self.root], env=self.env, capture_output=True
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"requires FEL_PORT", proc.stderr)
        self.assertEqual(self.log.read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
