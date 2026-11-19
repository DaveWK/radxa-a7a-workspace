#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Cached-set host fixtures. The transport records calls in memory."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
cached = runpy.run_path(str(SCRIPTS / "lib/cached_set.py"))
image = runpy.run_path(str(SCRIPTS / "mkimage.py"))
ORDER = """# Set A — 2400 MHz — cached memtest
1. From FEL, clear SRAM mailbox and upload bt0-fel.bin into SRAM (0x90000).
2. Execute entry 1 (0x90040); wait for the mailbox.
3. After that gate, upload/read back the table frame to 0xdf200, then layout kind 1 (main) to 0x40000000 and kind 2 (EDK2 FD) to 0x41000000.
4. Execute entry 2 (0x90044).
"""
FAKE = """#!/usr/bin/python3 -I
import os, shutil, struct, sys, time
from pathlib import Path

ports = Path(os.environ["FEL_SYSFS_ROOT"])
if sys.argv[1:3] == ["--discover", "--port"]:
    device = ports / sys.argv[3]
    try:
        print((device / "devnum").read_text())
    except FileNotFoundError:
        sys.exit(66)
    sys.exit(0)
flag, port, number_flag, number, separator, cmd, *args = sys.argv[1:]
assert (flag, number_flag, separator) == ("--port", "--devnum", "--")
device = ports / port
try:
    if (device / "devnum").read_text() != number:
        sys.exit(125)
except FileNotFoundError:
    sys.exit(66)
root = Path(os.environ["FIXTURE"]) / port
mb, name = {"3-3.4": (4096, "CXMT 4GB"), "3-6": (6144, "CXMT 6GB")}[port]

if cmd == "version":
    print("AWUC ID=0x00190300(A733)")
elif cmd == "write":
    shutil.copyfile(args[1], root / args[0])
elif cmd == "read":
    data = (root / args[0]).read_bytes()
    Path(args[2]).write_bytes(data[:int(args[1])])
elif (cmd, args) == ("exec", ["0x90040"]):
    (root / "0xdf000").write_bytes(struct.pack("<7I", 0x46413741, 0x11, mb, 2400, 0, 0, 0))
    with Path((root / "serial-path").read_text()).open("a") as log:
        print(f"[bt0] DRAM: strap 640 mV (nearest 640 mV) -> {name}", file=log)
        print(f"[bt0] DRAM: {mb} MiB", file=log)
elif (cmd, args) == ("exec", ["0x90044"]):
    if os.getenv("REJECT_ENTRY_TWO"):
        sys.exit(76)
    # Remove with one atomic rename; never expose partially edited sysfs.
    reset = ports / (port + ".offline")
    if os.getenv("CONCURRENT"):
        # Both runners arrive at Entry 2 before either device disappears.
        (root / "entry-two").touch()
        peer = "3-6" if port == "3-3.4" else "3-3.4"
        deadline = time.monotonic() + 10
        while not (root.parent / peer / "entry-two").exists():
            if time.monotonic() >= deadline:
                sys.exit(32)
            time.sleep(0.02)
        if port == "3-6":
            time.sleep(0.6)
    device.rename(reset)
    (reset / "devnum").write_text(str(int(number) + 10))
    # Return the acknowledgement while the port is absent; fixture controller
    # alone decides when the two devices reappear.
"""


class CachedTests(unittest.TestCase):
    def setUp(self):
        scratch = SCRIPTS.parent / "out"
        scratch.mkdir(exist_ok=True)
        tmp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source = self.root / "set"
        self.work = self.root / "work"
        self.work.mkdir()
        (self.source / "extracted").mkdir(parents=True)
        self.files = {"LOAD-ORDER.md": ORDER.encode(), "firmware.seek": b"256\n"}
        base = 256 * 512
        boot = bytes(4) + b"eGON.BT0" + bytes(500)
        fw, _ = image["build_firmware"](boot, b"mock main", b"mock payload", None, base)
        fw = fw[base:]  # firmware.bin starts at firmware.seek, not byte zero of media.
        pos = image["TABLE_OFFSET"] - base
        self.files.update(
            {
                "bt0-fel.bin": boot,
                "firmware.bin": fw,
                "extracted/table.bin": fw[pos : pos + 512],
                "extracted/kind1.bin": b"mock main",
                "extracted/kind2.bin": b"mock payload",
            }
        )
        self.memory = {}
        self.calls = []
        self.mailbox = struct.pack("<7I", 0x46413741, 0x11, 4096, 2400, 0, 0, 0)

    def manifest(self):
        manifest = []
        for name, data in self.files.items():
            (self.source / name).write_bytes(data)
            manifest.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
        manifest = "".join(manifest).encode()
        (self.source / "SHA256SUMS").write_bytes(manifest)
        return hashlib.sha256(manifest).hexdigest()

    def stage(self):
        return cached["stage"](self.source, self.work, self.manifest())

    def call(self, cmd, *args):
        self.calls.append((cmd, *args))
        if cmd == "version":
            return "AWUC    ID=0x00190300(A733) dflag=0x00"
        if cmd == "write":
            self.memory[args[0]] = Path(args[1]).read_bytes()
        if cmd == "read":
            Path(args[2]).write_bytes(self.memory[args[0]][: int(args[1])])
        if cmd == "exec" and args == ("0x90040",):
            self.memory["0xdf000"] = self.mailbox

    def test_staged_load_and_readbacks(self):
        hashes, mhz = self.stage()
        self.assertEqual(hashes.keys(), self.files.keys() | {"SHA256SUMS"})
        (self.source / "bt0-fel.bin").write_bytes(b"changed after staging")
        cached["entry_one"](self.call, self.work, "3-3.4", mhz)
        cached["upload_dram"](self.call, self.work)
        self.assertEqual(self.memory["0x90000"], self.files["bt0-fel.bin"])
        for label, addr in cached["ADDRESSES"].items():
            self.assertEqual(self.memory[addr], self.files[f"extracted/{label}.bin"])
            self.assertIn(
                (
                    "read",
                    addr,
                    str(len(self.memory[addr])),
                    str(self.work / "readback"),
                ),
                self.calls,
            )

    def test_unlisted(self):
        (self.source / "extra").touch()
        with self.assertRaisesRegex(ValueError, "unlisted"):
            self.stage()

    def test_wrong_order(self):
        self.files["LOAD-ORDER.md"] = ORDER.replace("0xdf200", "0xdf201").encode()
        with self.assertRaisesRegex(ValueError, "address mismatch"):
            self.stage()

    def test_wrong_extraction(self):
        self.files["extracted/kind1.bin"] = b"mismatch"
        with self.assertRaisesRegex(ValueError, "differs from firmware layout"):
            self.stage()

    def test_readback_mismatch(self):
        self.stage()

        def corrupt(cmd, *args):
            result = self.call(cmd, *args)
            if cmd == "read":
                Path(args[-1]).write_bytes(b"incorrect")
            return result

        with self.assertRaisesRegex(ValueError, "read-back mismatch"):
            cached["entry_one"](corrupt, self.work, "3-3.4", 2400)
        self.assertFalse(any(call[0] == "exec" for call in self.calls))

    def test_entry_one_failed(self):
        self.stage()
        self.mailbox = struct.pack("<7I", 0x46413741, 0x12, 6144, 2400, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, "unexpected Entry 1"):
            cached["entry_one"](self.call, self.work, "3-6", 2400)
        self.assertFalse(any(call[:2] == ("write", "0xdf200") for call in self.calls))


class RunnerTests(unittest.TestCase):
    setUp = CachedTests.setUp
    manifest = CachedTests.manifest

    def setup_runner(self):
        self.digest = self.manifest()
        self.sysfs = self.root / "devices"
        self.sysfs.mkdir()
        self.home = self.root / "home"
        logs = self.home / "src/radxa-a7a/serial-logs"
        logs.mkdir(parents=True)
        self.logs = {}
        for port, board, devnum in (("3-3.4", "4g", 12), ("3-6", "6g", 19)):
            self.logs[port] = logs / f"2026-11-18-1725-{board}-luckfox.log"
            self.logs[port].write_bytes(b"stale serial bytes\n")
            path = self.sysfs / port
            path.mkdir()
            for key, value in dict(
                idVendor="1f3a",
                idProduct="efe8",
                busnum="3",
                devpath=port[2:],
                devnum=str(devnum),
            ).items():
                (path / key).write_text(value)
            root = self.root / port
            root.mkdir()
            (root / "serial-path").write_text(str(self.logs[port]))
        scripts = self.root / "fixture-scripts"
        scripts.mkdir()
        for name in (
            "a7a-cached-run",
            "fel_session.py",
            "fel-check.py",
            "fel-manifest.py",
            "mkimage.py",
        ):
            shutil.copy2(SCRIPTS / name, scripts)
        shutil.copytree(SCRIPTS / "lib", scripts / "lib")
        module = scripts / "fel_session.py"
        source = module.read_text()
        host_home = "Path(pwd.getpwuid(os.geteuid()).pw_dir)"
        self.assertEqual(
            source.count(host_home), 1, "fixture must redirect the host lease path"
        )
        module.write_text(source.replace(host_home, "Path.home()"))
        self.runner = scripts / "a7a-cached-run"
        fake = scripts / "xfel-port"
        fake.write_text(FAKE)
        fake.chmod(0o700)
        self.env = os.environ | dict(
            HOME=str(self.home),
            FEL_SYSFS_ROOT=str(self.sysfs),
            FIXTURE=str(self.root),
        )

    def launch(self, stage, *args):
        return subprocess.Popen(
            [self.runner, "--stage", stage, *args],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def finish(self, proc, expected):
        with proc:
            try:
                out, err = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise
            self.assertEqual(proc.returncode, expected, out + err)
        return err

    def paths(self, port):
        return self.root / port / "receipt.json", self.root / port / "state.json"

    def receipt(self, port):
        return json.loads(self.paths(port)[0].read_text())

    def preflight(self, port="3-3.4", rc=0):
        receipt, state = self.paths(port)
        proc = self.launch(
            "preflight",
            "--port",
            port,
            "--state",
            state,
            "--set",
            self.source,
            "--expect-set-sha256",
            self.digest,
            "--receipt",
            receipt,
            "--serial-log",
            self.logs[port],
        )
        err = self.finish(proc, rc)
        self.assert_no_dram(port)
        return err

    def range(self, port, start=None, end=None, digest=None, path=None):
        log = self.logs[port]
        data = log.read_bytes()
        start = self.receipt(port)["identity_window_start"] if start is None else start
        end = len(data) if end is None else end
        digest = digest or hashlib.sha256(data[start:end]).hexdigest()
        return f"{path or log}:{start}-{end}:{digest}"

    def resume(self, port="3-3.4", clearance=None, board=None):
        return self.launch(
            "resume",
            "--receipt",
            self.paths(port)[0],
            "--identity-cleared",
            clearance or self.range(port),
            "--expect-board",
            board or ("4g" if port == "3-3.4" else "6g"),
        )

    def assert_no_dram(self, port):
        for addr in cached["ADDRESSES"].values():
            self.assertFalse((self.root / port / addr).exists(), addr)

    def wait_offline(self, port):
        # Bounded fixture synchronization, not a real USB wait.
        from time import monotonic, sleep

        target = self.sysfs / (port + ".offline")
        deadline = monotonic() + 10
        while not (target / "devnum").exists():
            self.assertLess(monotonic(), deadline, f"fixture never reset {port}")
            sleep(0.02)
        return target

    def test_happy_path_ack_disappears_and_reconnects(self):
        self.setup_runner()
        self.preflight()
        with self.resume() as proc:
            offline = self.wait_offline("3-3.4")
            self.assertFalse((self.sysfs / "3-3.4").exists())
            offline.rename(self.sysfs / "3-3.4")
            self.assertIn("handover unconfirmed pending", self.finish(proc, 3))
        result = self.receipt("3-3.4")
        self.assertEqual(result["status"], "reconnected-handover-unconfirmed")
        self.assertEqual(result["devnums"], [12, 22])
        self.assertEqual(result["calls"][-1]["argv"][-1], "version")
        self.assertEqual(result["handover_cursor"]["start"], result["identity"]["end"])

    def test_unacknowledged_entry_two(self):
        self.setup_runner()
        self.env["REJECT_ENTRY_TWO"] = "yes"
        self.preflight()
        self.assertIn("ACK validation failed", self.finish(self.resume(), 6))
        result = self.receipt("3-3.4")
        self.assertEqual(result["calls"][-1]["argv"][-2:], ["exec", "0x90044"])
        self.assertEqual(result["calls"][-1]["exit"], 76)
        self.assertIsNone(json.loads(self.paths("3-3.4")[1].read_text())["pending"])

    def test_two_staged_runners_and_peer_loss_during_reconnect(self):
        from time import sleep

        self.setup_runner()
        self.env["CONCURRENT"] = "yes"
        for port in self.logs:
            self.preflight(port)
        with self.resume("3-3.4") as first, self.resume("3-6") as second:
            one = self.wait_offline("3-3.4")
            two = self.wait_offline("3-6")
            sleep(
                0.35
            )  # First is selecting on complete snapshots as its peer is absent.
            two.rename(self.sysfs / "3-6")
            sleep(0.35)  # First observes the peer's return before it can reconnect.
            one.rename(self.sysfs / "3-3.4")
            self.finish(first, 3)
            self.finish(second, 3)
        for port, epochs in (("3-3.4", [12, 22]), ("3-6", [19, 29])):
            result = self.receipt(port)
            self.assertEqual(result["status"], "reconnected-handover-unconfirmed")
            self.assertEqual(result["devnums"], epochs)
            self.assertEqual(
                result["identity"]["board"], "4g" if port == "3-3.4" else "6g"
            )
        peer = self.receipt("3-3.4")["peer_history"]
        self.assertEqual(
            peer,
            [
                dict(port="3-6", old_devnum=19, new_devnum=None),
                dict(port="3-6", old_devnum=None, new_devnum=29),
            ],
        )
        print(
            f"Concurrent fixtures: 3-3.4 {[12, 22]}; 3-6 {[19, 29]}; peer transitions {peer}"
        )

    def test_cli_refuses_without_identity(self):
        self.setup_runner()
        self.preflight()
        self.finish(self.launch("resume", "--receipt", self.paths("3-3.4")[0]), 2)
        self.finish(self.resume(board="6g"), 2)
        self.assert_no_dram("3-3.4")

    def test_identity_refusals(self):
        cases = {
            "edited receipt": "receipt digest mismatch",
            "changed epoch": "epoch or devnum changed",
            "changed devnum": "FEL identity refused",
            "bad mailbox": "mailbox magic, state",
            "early range": "outside the fresh",
            "late range": "outside the fresh",
            "wrong digest": "identity clearance digest mismatch",
            "wrong board": "one matching strap and size",
            "two straps": "one matching strap and size",
            "wrong log": "invalid identity clearance path",
        }
        for case, expect in cases.items():
            with self.subTest(case=case):
                self.setUp()
                self.setup_runner()
                port = "3-3.4"
                self.preflight(port)
                receipt, state = self.paths(port)
                log = self.logs[port]
                clearance, board = None, None
                if case == "edited receipt":
                    receipt.write_bytes(receipt.read_bytes() + b" ")
                    clearance = self.range(port)
                elif case == "changed epoch":
                    state.write_bytes(state.read_bytes() + b" ")
                elif case == "changed devnum":
                    (self.sysfs / port / "devnum").write_text("22")
                elif case == "bad mailbox":
                    (self.root / port / "0xdf000").write_bytes(bytes(28))
                elif case == "early range":
                    clearance = self.range(port, start=0)
                elif case == "late range":
                    clearance = self.range(port, end=log.stat().st_size + 1)
                elif case == "wrong digest":
                    clearance = self.range(port, digest="a" * 64)
                elif case == "wrong board":
                    board = "6g"
                elif case == "two straps":
                    with log.open("ab") as stream:
                        stream.write(
                            b"[bt0] DRAM: strap 640 mV (nearest 640 mV) -> CXMT 4GB\n"
                        )
                elif case == "wrong log":
                    clearance = self.range(port, path=self.logs["3-6"])
                self.assertIn(
                    expect,
                    self.finish(
                        self.resume(port, clearance, board),
                        8 if case in ("changed devnum", "changed epoch") else 2,
                    ),
                )
                self.assert_no_dram(port)

    def test_no_unbound_transport(self):
        source = (SCRIPTS / "a7a-cached-run").read_text()
        for invalid in ("FEL_SYSFS_ROOT", "/sys/bus/usb", "subprocess"):
            self.assertNotIn(invalid, source)
        self.assertIn('"fel_session.py"', source)

    def test_active_preflight_blocks_same_port_across_distinct_paths(self):
        self.setup_runner()
        self.preflight()
        same, state = self.paths("3-3.4")
        for receipt, state in (
            (same, state),
            (same.with_name("other-receipt"), state.with_name("other-state")),
        ):
            error = self.finish(
                self.launch(
                    "preflight",
                    "--port",
                    "3-3.4",
                    "--state",
                    state,
                    "--set",
                    self.source,
                    "--expect-set-sha256",
                    self.digest,
                    "--receipt",
                    receipt,
                    "--serial-log",
                    self.logs["3-3.4"],
                ),
                9,
            )
            self.assertIn("already leased", error)
        self.finish(self.resume(board="6g"), 2)

    def test_expired_preflight_refused(self):
        self.setup_runner()
        module = self.runner.with_name("fel_session.py")
        module.write_text(
            module.read_text().replace(
                "IDENTITY_LIFETIME = 120", "IDENTITY_LIFETIME = 0.3"
            )
        )
        self.preflight()
        from time import sleep

        sleep(0.4)
        self.assertIn("expired", self.finish(self.resume(), 2))
        self.assert_no_dram("3-3.4")


if __name__ == "__main__":
    unittest.main()
