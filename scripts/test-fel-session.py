#!/usr/bin/python3 -I
# SPDX-License-Identifier: GPL-2.0-only
"""Test FEL state and capture generations without real devices or logs."""

import os
from pathlib import Path
import runpy
import tempfile
from threading import Thread
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent
M = runpy.run_path(str(SCRIPTS / "fel_session.py"))
EXIT = M["Exit"]
PORT = "3-3.4"
RVBAR = b"[bt0] RVBAR 00000000:40000000, fixture\n"
PROMPT = b"main>"
RESET = b"[bt0] no warm reset 1 s after the request: fixture\n"


class FakeSelector:
    def __init__(self):
        self.devnum = 12
        self.failure = {}
        self.commands = []

    def peers(self, port):
        return {}

    def invoke(self, args, timeout, lease_fd, *, watch=None):
        if args[0] == "--discover":
            key, text = ("discover",), str(self.devnum)
        else:
            key = args[5:]
            if int(args[3]) != self.devnum:
                return 125, "", "new devnum", False
            text = "AWUC ID=0x00190300(A733)" if key == ("version",) else ""
        self.commands.append(key)
        return self.failure.get(key, 0), text, "fixture", False


class Fixture(unittest.TestCase):
    def setUp(self):
        out = SCRIPTS.parent / "out"
        out.mkdir(exist_ok=True)
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(dir=out)))
        devices = self.root / "devices"
        devices.mkdir()
        self.enterContext(
            patch.dict(os.environ, HOME=str(self.root), FEL_SYSFS_ROOT=str(devices))
        )
        self.enterContext(
            patch("pwd.getpwuid", return_value=SimpleNamespace(pw_dir=str(self.root)))
        )


class SessionTests(Fixture):
    def make_session(self):
        fd = self.enterContext(M["lease"](PORT))
        self.selector = FakeSelector()
        self.state = self.root / "state"
        self.record = {}
        return M["Session"](PORT, self.state, self.record, fd, self.selector)

    def assert_exit(self, code, func, *args, **kwargs):
        with self.assertRaises(M["SessionError"]) as caught:
            func(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_ack_failure_on_version(self):
        session = self.make_session()
        self.selector.failure[("version",)] = 65
        self.assert_exit(EXIT.ACK, session.start)
        self.assertFalse(self.state.exists())

    def test_ack_failure_on_wdt_keeps_live_and_does_not_reconnect(self):
        session = self.make_session()
        session.start()
        self.selector.failure[M["WDT"][-1]] = 76
        self.assert_exit(EXIT.ACK, session.watchdog)
        self.assertEqual(self.selector.commands[-3:], list(M["WDT"]))
        self.assertIsNone(session.state["pending"])

    def test_failed_post_reset_probe_keeps_pending(self):
        session = self.make_session()
        session.start()
        session.submit(M["WDT"][-1], returns=True)
        old = self.state.read_bytes()
        self.selector.devnum = 24
        self.selector.failure[("version",)] = 65
        self.assert_exit(EXIT.ACK, session.reconnect, seconds=0.2)
        self.assertEqual(old, self.state.read_bytes())
        self.assertEqual(self.record["devnums"], [12])
        self.selector.failure.clear()
        session.reconnect(seconds=0.2)
        self.assertEqual(self.record["devnums"], [12, 24])
        self.assertIsNone(session.state["pending"])
        self.assertEqual(session.state["epoch"], 2)

    def test_reconnect_passes_remaining_time_and_rejects_late_acked_probe(self):
        session = self.make_session()
        session.start()
        session.submit(M["WDT"][-1], returns=True)
        self.selector.devnum = 24
        old = self.state.read_bytes()
        clock = [100.0]
        observed = []
        original = self.selector.invoke

        def late(args, timeout, lease_fd, *, watch=None):
            observed.append(timeout)
            reply = original(args, timeout, lease_fd, watch=watch)
            clock[0] += 59 if args[0] == "--discover" else 2
            return reply

        with patch("time.monotonic", side_effect=lambda: clock[0]):
            with patch.object(self.selector, "invoke", side_effect=late):
                self.assert_exit(EXIT.LIVE_TIMEOUT, session.reconnect)
        self.assertEqual(observed, [60, 1])
        self.assertEqual(self.state.read_bytes(), old)
        self.assertEqual(self.record["devnums"], [12])

    def test_unchanged_devnum_at_reconnect_deadline(self):
        runner = self.make_session()
        runner.start()
        runner.submit(M["WDT"][-1], returns=True)
        old = self.state.read_bytes()
        for expiry in ("between polls", "before discovery", "late discovery"):
            with self.subTest(expiry=expiry):
                self.selector.devnum = 12
                now = 100.0
                polls = 0
                observations = 0
                invoke = self.selector.invoke

                def sleep(seconds):
                    nonlocal now
                    now += 60 if expiry == "between polls" else seconds

                def observe():
                    nonlocal now, observations
                    observations += 1
                    if observations == 2 and expiry == "before discovery":
                        now = 160

                def discover(args, timeout, *options, **kwargs):
                    nonlocal now, polls
                    polls += 1
                    if polls == 2:
                        now = 161
                        # A fresh devnum is not usable after the deadline.
                        self.selector.devnum = 24
                    return invoke(args, timeout, *options, **kwargs)

                with (
                    patch("time.monotonic", side_effect=lambda: now),
                    patch("time.sleep", side_effect=sleep),
                    patch.object(self.selector, "invoke", side_effect=discover),
                ):
                    self.assert_exit(EXIT.IDENTITY, runner.reconnect, observe=observe)
                self.assertEqual(polls, 2 if expiry == "late discovery" else 1)
                self.assertEqual(self.state.read_bytes(), old)

    def test_first_discovery_hang_has_no_prior_reconnect_observation(self):
        runner = self.make_session()
        runner.start()
        runner.submit(M["WDT"][-1], returns=True)
        with patch.object(
            self.selector, "invoke", return_value=(-9, "", "fixture hung", True)
        ):
            self.assert_exit(EXIT.LIVE_TIMEOUT, runner.reconnect)
        self.assertTrue(self.record["calls"][-1]["timed_out"])

    def test_entry_two_mailbox_budget_does_not_accept_late_ready(self):
        clock, observed = [100], []

        def mailbox(timeout):
            observed.append(timeout)
            clock[0] += 11
            return (0x46413741, 0x21, 4096, 1200)

        with patch("time.monotonic", side_effect=lambda: clock[0]):
            self.assert_exit(
                EXIT.LIVE_TIMEOUT, M["wait_for_handover_target"], mailbox, {}
            )
        self.assertEqual(observed, [10])

    def test_stuck_entry_two_mailbox_keeps_last_completed_state_at_deadline(self):
        for expiry in ("between polls", "late read", "selector timeout"):
            with self.subTest(expiry=expiry):
                clock, observed = [100], []
                record = {}
                stuck = (0x46413741, 0x11, 4096, 1200)

                def mailbox(timeout):
                    observed.append(timeout)
                    if len(observed) == 1:
                        return stuck
                    clock[0] = 111
                    if expiry == "selector timeout":
                        raise M["SessionError"](EXIT.LIVE_TIMEOUT, "fixture timed out")
                    return (0x46413741, 0x21, 4096, 1200)

                def sleep(seconds):
                    clock[0] += 10 if expiry == "between polls" else seconds

                with (
                    patch("time.monotonic", side_effect=lambda: clock[0]),
                    patch("time.sleep", side_effect=sleep),
                ):
                    self.assert_exit(
                        EXIT.SERIAL_UNCONFIRMED,
                        M["wait_for_handover_target"],
                        mailbox,
                        record,
                    )
                self.assertEqual(record["entry_two_mailbox"], stuck)
                self.assertEqual(len(observed), 1 if expiry == "between polls" else 2)

    def test_loss_before_and_after_without_submission_ack(self):
        session = self.make_session()
        session.start()
        cmd, entry = ("read32", "0x90040"), ("exec", "0x90044")
        self.selector.failure.update({cmd: 66, entry: 66})
        self.assert_exit(EXIT.LOST_BEFORE, session, *cmd)
        self.assert_exit(EXIT.LOST_BEFORE, session.submit, entry, returns=True)
        self.assertFalse(
            any(e["event"] == "submission-acked" for e in self.record["events"])
        )
        self.assertIsNone(session.state["pending"])

    def test_loss_after_ack_has_distinct_exit(self):
        session = self.make_session()
        session.start()
        entry, cmd = ("exec", "0x90044"), ("read32", "0x90040")
        session.submit(entry, returns=False)
        self.selector.failure[cmd] = 66
        self.assert_exit(EXIT.LOST_AFTER, session, *cmd)

    def test_selector_exit_table(self):
        session = self.make_session()
        cmd = ("version",)
        self.assertIn("ID=0x00190300", session.at(12, *cmd))
        for selector, expected in (
            (2, EXIT.INPUT),
            (65, EXIT.ACK),
            (66, EXIT.LOST_BEFORE),
            (74, EXIT.TRANSPORT),
            (76, EXIT.ACK),
            (125, EXIT.IDENTITY),
            (143, EXIT.TRANSPORT),
        ):
            with self.subTest(selector=selector):
                self.selector.failure[cmd] = selector
                self.assert_exit(expected, session.at, 12, *cmd)

    def test_identity_deadline_boundary(self):
        M["bounded_identity_time"](100, 220)
        with self.assertRaisesRegex(ValueError, "expired"):
            M["bounded_identity_time"](100, 221)

    def test_byte_drip_does_not_extend_absolute_deadline(self):
        class Drip:
            now = 100
            timeouts = []

            def settimeout(self, seconds):
                self.timeouts.append(seconds)

            def recv(self, _):
                self.now += 1
                return b"x"

        conn = Drip()
        with patch("time.monotonic", side_effect=lambda: conn.now):
            with self.assertRaises(TimeoutError):
                M["receive_request"](conn, 103)
        self.assertEqual(conn.timeouts, [3, 2, 1])

    def test_hung_grandchild_is_terminated_and_reaped_before_release(self):
        child = self.root / "selector"
        alive, done = self.root / "alive", self.root / "done"
        child.write_text(
            "#!/usr/bin/python3 -I\n"
            "import os, signal\n"
            "from pathlib import Path\n"
            "from time import sleep\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            f"    Path({str(alive)!r}).write_text(str(os.getpid()))\n"
            f"    while not Path({str(done)!r}).exists():\n"
            "        sleep(0.02)\n"
            "else:\n"
            "    os.waitpid(pid, 0)\n"
        )
        child.chmod(0o700)
        exit_codes = []

        def run():
            with M["lease"](PORT) as fd:
                session = M["Session"](
                    PORT, self.root / "state", {}, fd, M["Selector"](child)
                )
                try:
                    session.run("unused", timeout=0.8)
                except M["SessionError"] as exc:
                    exit_codes.append(exc.code)

        worker = Thread(target=run)
        worker.start()
        try:
            deadline = time.monotonic() + 5
            while not alive.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(alive.exists())
            self.assertTrue(worker.is_alive())
            with self.assertRaises(M["SessionError"]) as caught:
                with M["lease"](PORT):
                    self.fail("same-port lease escaped from timed-out child")
            self.assertEqual(caught.exception.code, EXIT.LEASE)
            with M["lease"]("3-6"):
                pass
            pid = int(alive.read_text())
            worker.join(timeout=4)
            self.assertFalse(worker.is_alive())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        finally:
            done.touch()
            worker.join(timeout=6)
        self.assertFalse(worker.is_alive())
        self.assertEqual(exit_codes, [EXIT.LIVE_TIMEOUT])
        with M["lease"](PORT):
            pass


class SerialTests(Fixture):
    def setUp(self):
        super().setUp()
        self.log = self.root / "src/radxa-a7a/serial-logs" / M["LOGS"][PORT]
        self.log.parent.mkdir(parents=True)
        self.prefix = b"previous capture\n"
        self.log.write_bytes(self.prefix)
        self.serial = M["Serial"](PORT, self.log)

    def append(self, data):
        with self.log.open("ab") as stream:
            stream.write(data)

    def test_copytruncate_changed_prefix_and_identical_prefix_limit(self):
        # Same-inode regrowth as in the R3 red fixture. Changed prefix
        # refuses; a reproduced anchor is expressly outside detection.
        cursor = self.serial.capture()
        self.log.write_bytes(b"changed" + RVBAR + PROMPT)
        self.assertEqual(self.log.stat().st_ino, cursor["inode"])
        self.assertGreater(self.log.stat().st_size, cursor["start"])
        with self.assertRaisesRegex(ValueError, "generation changed"):
            self.serial.interval(cursor)
        self.log.write_bytes(self.prefix + RVBAR + PROMPT)
        _, data = self.serial.interval(cursor)
        self.assertTrue(M["handover_markers"](data))

    def test_rotation_and_shrink_refuse(self):
        cursor = self.serial.capture()
        self.log.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "generation changed"):
            self.serial.interval(cursor)
        self.log.rename(self.log.with_name("old"))
        self.log.write_bytes(self.prefix + RVBAR + PROMPT)
        with self.assertRaisesRegex(ValueError, "generation changed"):
            self.serial.interval(cursor)

    def test_rolling_eof_detects_rewrite_and_stepped_shrink(self):
        cursor = self.serial.capture()
        self.append(RVBAR)
        first, _, _ = self.serial.observe(cursor)
        self.append(RESET)
        second, _, _ = self.serial.observe(cursor, rolling=first)
        self.log.write_bytes(self.prefix + RVBAR)
        self.assertGreater(self.log.stat().st_size, cursor["start"])
        with self.assertRaisesRegex(ValueError, "generation changed"):
            self.serial.observe(cursor, rolling=second)
        self.append(b"x" * len(RESET))
        with self.assertRaisesRegex(ValueError, "generation changed"):
            self.serial.observe(cursor, rolling=second)

    def test_fstat_after_read_detects_shrink_above_start(self):
        cursor = self.serial.capture()
        self.append(RVBAR + PROMPT)
        original = os.pread

        def shrink(fd, size, offset):
            data = original(fd, size, offset)
            if offset == cursor["start"]:
                self.log.write_bytes(self.prefix + RVBAR)
            return data

        with patch("os.pread", side_effect=shrink):
            with self.assertRaisesRegex(ValueError, "generation changed"):
                self.serial.observe(cursor)

    def test_marked_reset_and_split_attempts(self):
        first = self.serial.capture()
        self.append(RVBAR)
        first_end = self.log.stat().st_size
        second = self.serial.capture()
        self.append(PROMPT)
        _, data = self.serial.interval(first, end=first_end)
        self.assertFalse(M["handover_markers"](data))
        _, data = self.serial.interval(second)
        with self.assertRaisesRegex(ValueError, "main> appeared before"):
            M["handover_markers"](data)
        for data in (
            RVBAR + RESET + PROMPT,
            RVBAR + RVBAR + PROMPT,
            PROMPT + b"\n" + RVBAR + PROMPT,
            RVBAR + PROMPT + b"\n[bt0] RVBAR 00000000:50000000",
            b"[bt0] RVBAR 00000000:50000000\n" + RVBAR + PROMPT,
            RVBAR + PROMPT + b"\n[bt0] RVBAR 00000000:40000000",
            # Reuse the actual marker sequence from 139's red-serial fixture.
            b"[bt0] RVBAR 00000000:40000000\n"
            b"[bt0] FEL: halted; back to FEL (state 0xe2)\nmain>\n",
        ):
            with self.assertRaises(ValueError):
                M["handover_markers"](data)
        announcement = b"[bt0] done in 8 ms, warm reset into AArch64 at 0x40000000\n"
        self.assertTrue(M["handover_markers"](announcement + RVBAR + PROMPT))

    def test_offline_markers_without_ack_are_unconfirmed(self):
        cursor = self.serial.capture()
        self.append(RVBAR + PROMPT)
        end = self.log.stat().st_size
        record = dict(
            port=PORT,
            handover_cursor=cursor,
            handover_end_cursor=self.serial.capture(cursor),
            handover_sha256=M["sha"](RVBAR + PROMPT),
            events=[],
            reconnect=dict(outcome="verified", exit=0),
        )
        with self.assertRaises(M["SessionError"]) as caught:
            M["verify_attempt"](record)
        self.assertEqual(caught.exception.code, EXIT.SERIAL_UNCONFIRMED)
        record["events"] = [dict(event="submission-acked", command=["exec", "0x90044"])]
        self.assertEqual(M["verify_attempt"](record)["end"], end)


if __name__ == "__main__":
    unittest.main()
