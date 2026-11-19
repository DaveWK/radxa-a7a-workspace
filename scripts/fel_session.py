#!/usr/bin/python3 -I
# SPDX-License-Identifier: GPL-2.0-only
"""Own the physical-port lease, FEL epoch and serial attribution for one run."""

import argparse
from contextlib import contextmanager
import ctypes
from enum import IntEnum
import fcntl
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import runpy
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

SCRIPTS = Path(__file__).resolve().parent
LOGS = {
    "3-3.4": "2026-11-19-1033-a7a-4g.log",
    "3-6": "2026-11-19-1041-a7a-6g.log",
}
PORT = re.compile(r"[1-9][0-9]*-[1-9][0-9]*(?:\.[1-9][0-9]*)*")
EXACT_ID = re.compile(r"\bID=(0x[0-9a-fA-F]+)(?=\s|\(|$)")
RVBAR = re.compile(rb"\[bt0\] RVBAR(?:[ \t]|$)")
EXPECTED_RVBAR = re.compile(rb"\[bt0\] RVBAR 00000000:40000000(?:[ \t,].*)?")
MAIN = re.compile(rb"main>.*")
FAILURE = re.compile(
    rb"(?:\[bt0\].*\b(?:reset|failed|failure|refused|halted|panic)\b|panic:)",
    re.I,
)
BOOT_BANNER = re.compile(rb"oreboot .* bt0 \| Radxa Cubie A7A")
NORMAL_RESET = re.compile(
    rb"\[bt0\] done in [0-9]+ ms, warm reset into AArch64 at 0x40000000"
)
ENTRY_TWO = b"[bt0] FEL: entry 2: checking the images in DRAM"
MAX_SERIAL = 1 << 20
IDENTITY_LIFETIME = 120
MIN_POLL_BUDGET = 1.0
BOARDS = {"4g": (b"CXMT 4GB", b"4096"), "6g": (b"CXMT 6GB", b"6144")}
# The pinned oreboot board's bt0/src/dram.rs, bt0/src/main.rs and
# dram/src/sets.rs define the two emitted identity fields.
STRAP = re.compile(rb"\[bt0\] DRAM: strap [0-9]+ mV \(nearest [0-9]+ mV\) -> (.+)")
GPIO_STRAP = re.compile(
    rb"\[bt0\] DRAM: strap GPIOs PH17:PH16 = (?:01|10|11) "
    rb"\(GPIO strap not fitted\); selecting by the ADC"
)
SIZE = re.compile(rb"\[bt0\] DRAM: ([0-9]+) MiB")
SHA256 = re.compile(r"[0-9a-f]{64}")
WDT = (
    ("write32", "0x02050010", "0x16aa0001"),
    ("write32", "0x02050014", "0x16aa0001"),
    ("write32", "0x0205000c", "0x000014af"),
)


class Exit(IntEnum):
    SUCCESS = 0
    INPUT = 2
    SERIAL_UNCONFIRMED = 3
    LOST_BEFORE = 4
    LOST_AFTER = 5
    ACK = 6
    LIVE_TIMEOUT = 7
    IDENTITY = 8
    LEASE = 9
    TRANSPORT = 10
    CLIENT_GONE = 11


class SelectorExit(IntEnum):
    ACKED = 0
    USAGE = 2
    ACK_MALFORMED = 65
    LOST = 66
    IO = 74
    ACK_REJECTED = 76
    IDENTITY = 125


class SessionError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class PollingWindowExpired(SessionError):
    """A check could not start in budget, or completed late without a hang."""

    def __init__(self, message):
        super().__init__(Exit.LIVE_TIMEOUT, message)


class UnchangedEnumeration(SessionError):
    """The reconnect window ended with the original FEL devnum still present."""

    def __init__(self):
        super().__init__(Exit.IDENTITY, "no fresh enumeration after submission")


class ClientWatch:
    def __init__(self, endpoint, stage):
        self.stage = stage
        self.poller = select.poll()
        self.poller.register(
            endpoint, select.POLLERR | select.POLLHUP | select.POLLRDHUP
        )

    def __call__(self):
        if self.poller.poll(0):
            raise SessionError(Exit.CLIENT_GONE, f"{self.stage} client disconnected")


def command_budget(deadline, purpose, *, minimum=0):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise PollingWindowExpired(f"{purpose} deadline expired")
    if seconds < minimum:
        raise PollingWindowExpired(f"{purpose}: less than {minimum:g} s remaining")
    return seconds


def atomic(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temp = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)


@contextmanager
def lease(port):
    if not PORT.fullmatch(port):
        raise SessionError(Exit.IDENTITY, "invalid physical port")
    root = Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".cache/a7a-fel-locks"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (root / f"{port}.lock").open("a") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SessionError(
                Exit.LEASE, f"FEL port {port} is already leased"
            ) from exc
        yield stream.fileno()


class Serial:
    def __init__(self, port, path):
        self.port = port
        self.path = Path(path)
        if self.path != Path.home() / "src/radxa-a7a/serial-logs" / LOGS[port]:
            raise SessionError(
                Exit.IDENTITY, "serial log is not registered on this port"
            )

    @contextmanager
    def read_file(self):
        if self.path.resolve(strict=True) != self.path:
            raise ValueError("serial log path is not canonical")
        fd = os.open(self.path, os.O_PATH | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("serial source is not a regular file")
            with open(f"/proc/self/fd/{fd}", "rb", buffering=0) as stream:
                yield stream.fileno(), st
            if not os.path.samestat(st, self.path.lstat()):
                raise ValueError("serial log was replaced")
        finally:
            os.close(fd)

    @staticmethod
    def prefix(fd, offset):
        length = min(offset, 4096)
        data = os.pread(fd, length, offset - length)
        if len(data) != length:
            raise ValueError("serial log truncated while reading capture anchor")
        return data

    def validate(self, fd, st, cursor):
        offset = cursor["start"]
        if (
            cursor["port"] != self.port
            or cursor["log"] != str(self.path)
            or (st.st_dev, st.st_ino) != (cursor["device"], cursor["inode"])
            or st.st_size < offset
            or sha(self.prefix(fd, offset)) != cursor["prefix_sha256"]
        ):
            raise ValueError("serial capture generation changed")

    def anchor(self, fd, st):
        prefix = self.prefix(fd, st.st_size)
        return dict(
            port=self.port,
            log=str(self.path),
            device=st.st_dev,
            inode=st.st_ino,
            start=st.st_size,
            prefix_sha256=sha(prefix),
            starts_line=not prefix or prefix.endswith(b"\n"),
        )

    def capture(self, prior=None, *, rolling=None):
        with self.read_file() as (fd, st):
            anchors = [anchor for anchor in (prior, rolling) if anchor is not None]
            for anchor in anchors:
                self.validate(fd, st, anchor)
            eof = self.anchor(fd, st)
            current = os.fstat(fd)
            for anchor in (*anchors, eof):
                self.validate(fd, current, anchor)
            return eof

    def observe(self, cursor, *, rolling=None, start=None, end=None, closed=None):
        with self.read_file() as (fd, st):
            anchors = [
                anchor for anchor in (cursor, rolling, closed) if anchor is not None
            ]
            for anchor in anchors:
                self.validate(fd, st, anchor)
            if closed is not None:
                end = closed["start"]
            start = cursor["start"] if start is None else start
            end = st.st_size if end is None else end
            if not cursor["start"] <= start <= end <= st.st_size:
                raise ValueError("serial range outside the fresh capture window")
            if end - start > MAX_SERIAL:
                raise ValueError("oversized serial range")
            eof = self.anchor(fd, st)
            data = os.pread(fd, end - start, start)
            if len(data) != end - start:
                raise ValueError("short serial read")
            current = os.fstat(fd)
            for anchor in (*anchors, eof):
                self.validate(fd, current, anchor)
        return eof, end, data

    def interval(self, cursor, start=None, end=None, *, closed=None):
        _, end, data = self.observe(cursor, start=start, end=end, closed=closed)
        return end, data


def handover_markers(data):
    """Require one RVBAR then main>, with no intervening attempt boundary."""
    lines = [line.removesuffix(b"\r") for line in data.split(b"\n")]
    rvbars = [i for i, line in enumerate(lines) if RVBAR.match(line)]
    if len(rvbars) > 1:
        raise ValueError("multiple RVBAR markers in one serial attempt")
    start = rvbars[0] if rvbars else len(lines)
    if rvbars and not EXPECTED_RVBAR.fullmatch(lines[start]):
        raise ValueError("unexpected RVBAR address or syntax in handover window")
    end = next((i for i, line in enumerate(lines) if MAIN.fullmatch(line)), len(lines))
    if end < len(lines) and end <= start:
        raise ValueError("main> appeared before the RVBAR marker")
    earlier = lines[:end]
    planned = [i for i, line in enumerate(earlier) if NORMAL_RESET.fullmatch(line)]
    submits = [i for i, line in enumerate(earlier) if line == ENTRY_TWO]
    if (
        len(planned) > 1
        or len(submits) > 1
        or any(i >= start for i in planned + submits)
        or any(
            (FAILURE.search(line) and i not in planned)
            or BOOT_BANNER.match(line)
            or STRAP.fullmatch(line)
            or SIZE.fullmatch(line)
            for i, line in enumerate(earlier)
        )
    ):
        raise ValueError("serial reset or failure marker in the handover window")
    return bool(rvbars and end < len(lines))


def attempt_lines(cursor, data):
    return data if cursor["starts_line"] else data.partition(b"\n")[2]


class Selector:
    def __init__(self, path=None):
        self.path = path or SCRIPTS / "xfel-port"

    def invoke(self, args, timeout, lease_fd, *, watch=None, poll_deadline=None):
        # Orphaned descendants in the selector's process group are reparented
        # here so cancellation can reap them as well as the direct child.
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0):  # PR_SET_CHILD_SUBREAPER
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        if watch is not None:
            watch()
        deadline = time.monotonic() + timeout
        if poll_deadline is not None:
            command_budget(poll_deadline, "selector", minimum=MIN_POLL_BUDGET)
            deadline = min(deadline, poll_deadline)
        child = subprocess.Popen(
            [self.path, *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            env=os.environ | {"FEL_SESSION_LEASE_FD": str(lease_fd)},
            pass_fds=(lease_fd,),
            start_new_session=True,
        )
        last_slice = None
        try:
            while True:
                seconds = deadline - time.monotonic()
                if seconds <= 0:
                    raise subprocess.TimeoutExpired(args, timeout)
                if watch is not None:
                    watch()
                try:
                    out, err = child.communicate(
                        timeout=min(seconds, 0.05) if watch else seconds
                    )
                except subprocess.TimeoutExpired as exc:
                    last_slice = exc
                    continue
                if watch is not None:
                    watch()
                # Return a completed, drained result as such. Session.run
                # still rejects late replies; they are not evidence of a hang.
                break
        except subprocess.TimeoutExpired:
            # A watcher slice may expire before a clean exit, then the guardian
            # may not run again until the outer deadline. Prove both the direct
            # exit and group disappearance before treating this as a late reply.
            try:
                returncode = child.poll()
            except OSError:
                returncode = None
            if returncode is not None and returncode >= 0:
                try:
                    os.killpg(child.pid, 0)
                except ProcessLookupError:
                    # Do not wait on pipes after the deadline. The caller
                    # discards late replies; retain already captured diagnostics.
                    def captured(data):
                        if isinstance(data, bytes):
                            return data.decode(child.encoding, errors=child.errors)
                        return data or ""

                    return (
                        returncode,
                        captured(last_slice.output if last_slice else None),
                        captured(last_slice.stderr if last_slice else None),
                        False,
                    )
                except OSError:
                    pass  # Not proof of group disappearance.
            try:
                out, err = self.cancel(child)
            except OSError as exc:
                raise SessionError(
                    Exit.LIVE_TIMEOUT,
                    f"selector timeout cleanup could not be verified: {exc}",
                ) from exc
            return child.returncode, out, err, True
        except BaseException as problem:
            try:
                self.cancel(child)
            except SessionError as cancellation:
                raise problem from cancellation
            raise
        else:
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                pass
            else:
                out, err = self.cancel(child)
                return child.returncode, out, err, True
        finally:
            for stream in (child.stdout, child.stderr):
                stream.close()
        return child.returncode, out, err, False

    @staticmethod
    def cancel(child):
        out = err = ""
        for sig, grace in ((signal.SIGTERM, 0.25), (signal.SIGKILL, 2.0)):
            try:
                os.killpg(child.pid, sig)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + grace
            try:
                out, err = child.communicate(timeout=grace)
            except subprocess.TimeoutExpired:
                continue
            while True:
                try:
                    while os.waitpid(-child.pid, os.WNOHANG)[0]:
                        pass
                except ChildProcessError:
                    pass
                try:
                    os.killpg(child.pid, 0)
                except ProcessLookupError:
                    return out, err
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.01, remaining))
        # An uninterruptible kernel task may survive SIGKILL. The transfer
        # inherits our lease and therefore still fences the port in this case.
        raise SessionError(
            Exit.LIVE_TIMEOUT,
            "selector group did not drain after SIGKILL; any surviving transfer retains the port lease",
        )

    def peers(self, target):
        # Purely telemetry. Nothing from this scan can authorize (or refuse)
        # a command; own identity is revalidated by the stateless selector.
        root = Path(os.getenv("FEL_SYSFS_ROOT", "/sys/bus/usb/devices"))
        try:
            paths = list(root.iterdir())
        except OSError:
            return None
        result = {}
        for path in paths:
            if path.name == target or not PORT.fullmatch(path.name):
                continue
            try:
                if (
                    (path / "idVendor").read_text().strip(),
                    (path / "idProduct").read_text().strip(),
                ) == ("1f3a", "efe8"):
                    number = int((path / "devnum").read_text())
                    if 1 <= number <= 127:
                        result[path.name] = number
            except (OSError, UnicodeError, ValueError):
                # Partial enumeration is not an observation of loss.
                return None
        return result


class Session:
    def __init__(self, port, path, record, lease_fd, selector=None):
        self.port = port
        self.path = Path(path)
        self.record = record
        self.selector = selector or Selector()
        self.lease_fd = lease_fd
        self.state = None
        self.submission_attempted = False
        self.submitted = False
        self.watch = None
        self.record.setdefault("calls", [])
        self.record.setdefault("events", [])
        self.record.setdefault("devnums", [])
        self.record.setdefault("peer_history", [])
        self.peers = None

    def event(self, kind, **values):
        self.record["events"].append(dict(event=kind, time_ns=time.time_ns(), **values))

    def observe(self):
        new = self.selector.peers(self.port)
        if new is None:
            return
        if self.peers is not None:
            for port in sorted(self.peers.keys() | new.keys()):
                old, now = self.peers.get(port), new.get(port)
                if old != now:
                    change = dict(port=port, old_devnum=old, new_devnum=now)
                    self.event("peer-change", **change)
                    self.record["peer_history"] = (
                        self.record["peer_history"] + [change]
                    )[-16:]
        self.peers = new

    def run(self, *args, timeout=65, poll_deadline=None):
        if self.watch is not None:
            self.watch()
        if poll_deadline is None:
            deadline = time.monotonic() + timeout
            options = {}
        else:
            deadline = poll_deadline
            options = {"poll_deadline": poll_deadline}
        self.observe()
        event = dict(argv=args, started_ns=time.time_ns())
        self.record["calls"].append(event)
        try:
            rc, out, err, timed_out = self.selector.invoke(
                args,
                command_budget(
                    deadline, "selector", minimum=MIN_POLL_BUDGET if options else 0
                ),
                self.lease_fd,
                watch=self.watch,
                **options,
            )
        except SessionError as exc:
            prelaunch_expired = isinstance(exc, PollingWindowExpired)
            event.update(
                exit=None,
                error=str(exc),
                ended_ns=time.time_ns(),
                timed_out=exc.code == Exit.LIVE_TIMEOUT and not prelaunch_expired,
                client_disconnected=exc.code == Exit.CLIENT_GONE,
            )
            if prelaunch_expired:
                event["prelaunch_expired"] = True
            raise
        except OSError as exc:
            event.update(exit=None, error=str(exc), ended_ns=time.time_ns())
            raise SessionError(Exit.TRANSPORT, f"cannot run selector: {exc}") from exc
        event.update(exit=rc, stderr=err, ended_ns=time.time_ns(), timed_out=timed_out)
        if timed_out:
            raise SessionError(
                Exit.LIVE_TIMEOUT,
                "selector timed out; its process group was terminated and reaped",
            )
        command_budget(deadline, "selector")
        if rc == SelectorExit.LOST:
            raise SessionError(
                Exit.LOST_AFTER if self.submitted else Exit.LOST_BEFORE,
                (
                    "FEL device lost after submission"
                    if self.submitted
                    else "FEL device lost before submission"
                ),
            )
        if rc in (SelectorExit.ACK_MALFORMED, SelectorExit.ACK_REJECTED):
            raise SessionError(
                Exit.ACK, f"FEL ACK validation failed (selector exit {rc})"
            )
        if rc == SelectorExit.IDENTITY:
            raise SessionError(Exit.IDENTITY, f"FEL identity refused: {err.strip()}")
        if rc == SelectorExit.USAGE:
            raise SessionError(
                Exit.INPUT, f"invalid selector invocation (caller bug): {err.strip()}"
            )
        if rc == SelectorExit.IO:
            raise SessionError(
                Exit.TRANSPORT, f"selector transfer or local I/O: {err.strip()}"
            )
        if rc == SelectorExit.ACKED:
            return out
        raise SessionError(
            Exit.TRANSPORT, f"unexpected selector exit {rc}: {err.strip()}"
        )

    def discover(self, *, poll_deadline=None):
        number = self.run(
            "--discover", "--port", self.port, poll_deadline=poll_deadline
        ).strip()
        if (
            not number.isascii()
            or not number.isdecimal()
            or not 1 <= int(number) <= 127
        ):
            raise SessionError(Exit.IDENTITY, "invalid selector discovery output")
        return int(number)

    def at(self, number, *command, timeout=65, poll_deadline=None):
        return self.run(
            "--port",
            self.port,
            "--devnum",
            str(number),
            "--",
            *command,
            timeout=timeout,
            poll_deadline=poll_deadline,
        )

    def probe(self, number, *, deadline=None):
        if deadline is not None:
            command_budget(deadline, "reconnect probe", minimum=MIN_POLL_BUDGET)
        self.event("probe-attempt", devnum=number)
        version = self.at(number, "version", poll_deadline=deadline)
        if deadline is not None:
            command_budget(deadline, "reconnect")
        if EXACT_ID.findall(version) != ["0x00190300"]:
            raise SessionError(Exit.IDENTITY, "expected exact A733 ID=0x00190300")
        self.event("probe-verified", devnum=number)
        self.record["devnums"].append(number)
        return version

    def commit(self, **fields):
        self.state = dict(port=self.port, **fields)
        atomic(self.path, (json.dumps(self.state, sort_keys=True) + "\n").encode())
        self.event("epoch-state", **self.state)

    def start(self):
        if os.path.lexists(self.path):
            raise SessionError(Exit.IDENTITY, "expected fresh FEL state")
        number = self.discover()
        version = self.probe(number)
        self.commit(devnum=number, epoch=1, pending=None)
        return version

    def __call__(self, *command, timeout=65, poll_deadline=None):
        if self.state is None or self.state["pending"] is not None:
            raise SessionError(
                Exit.IDENTITY, "FEL command requires a live verified epoch"
            )
        if command in (WDT[-1], ("exec", "0x90044")):
            raise SessionError(
                Exit.INPUT, "reset or Entry 2 requires the submission gate"
            )
        return self.at(
            self.state["devnum"], *command, timeout=timeout, poll_deadline=poll_deadline
        )

    def submit(self, command, *, returns, timeout=65):
        if self.state is None or self.state["pending"] is not None:
            raise SessionError(
                Exit.IDENTITY, "FEL submission requires a live verified epoch"
            )
        if self.submission_attempted or command not in (WDT[-1], ("exec", "0x90044")):
            raise SessionError(Exit.INPUT, "invalid or repeated FEL reset submission")
        self.submission_attempted = True
        self.event("submission-attempt", command=command, devnum=self.state["devnum"])
        self.at(self.state["devnum"], *command, timeout=timeout)
        self.submitted = True
        self.event("submission-acked", command=command, devnum=self.state["devnum"])
        if returns:
            self.commit(
                devnum=self.state["devnum"], epoch=self.state["epoch"], pending=command
            )

    def reconnect(self, seconds=60, *, observe=None):
        if self.state is None or not self.state["pending"]:
            raise SessionError(Exit.IDENTITY, "no acknowledged reset is pending")
        deadline = time.monotonic() + seconds
        self.event("reconnect-attempt", devnum=self.state["devnum"])
        last_observation = None
        while True:
            if last_observation is not None and time.monotonic() >= deadline:
                raise last_observation
            if observe is not None:
                observe()
            try:
                command_budget(deadline, "reconnect", minimum=MIN_POLL_BUDGET)
                number = self.discover(poll_deadline=deadline)
                command_budget(deadline, "reconnect")
            except PollingWindowExpired as exc:
                if last_observation is None:
                    raise
                if self.watch is not None:
                    self.watch()
                raise last_observation from exc
            except SessionError as exc:
                if exc.code != Exit.LOST_AFTER:
                    raise
                last_observation = exc
            else:
                if number != self.state["devnum"]:
                    self.probe(number, deadline=deadline)
                    self.commit(
                        devnum=number, epoch=self.state["epoch"] + 1, pending=None
                    )
                    self.event("reconnect-verified", devnum=number)
                    return
                last_observation = UnchangedEnumeration()
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))

    def watchdog(self):
        for command in WDT[:-1]:
            self(*command)
        self.submit(WDT[-1], returns=True)
        self.reconnect()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def clear_identity(serial, cursor, clearance, board, expected_mb):
    try:
        path, offsets, want = clearance.rsplit(":", 2)
    except ValueError as exc:
        raise ValueError("invalid identity clearance format") from exc
    match = re.fullmatch(r"([0-9]+)-([0-9]+)", offsets)
    if path != str(serial.path) or not match or not SHA256.fullmatch(want):
        raise ValueError("invalid identity clearance path, offsets or digest")
    start, end = map(int, match.groups())
    eof, _, window = serial.observe(cursor)
    base = cursor["start"]
    if not base <= start < end <= eof["start"]:
        raise ValueError("identity range outside the fresh capture window")
    lo, hi = start - base, end - base
    if (
        (lo and window[lo - 1] != 10)
        or (not lo and not cursor["starts_line"])
        or window[hi - 1] != 10
    ):
        raise ValueError("identity clearance requires complete serial line boundaries")
    if sha(window[lo:hi]) != want:
        raise ValueError("identity clearance digest mismatch")
    markers = []
    banners = 0
    offset = 0
    for part in window.split(b"\n"):
        line = part.removesuffix(b"\r")
        line_end = offset + len(part) + 1
        if (
            FAILURE.search(line)
            or RVBAR.match(line)
            or MAIN.fullmatch(line)
            or line == ENTRY_TWO
        ):
            raise ValueError("reset or failure in Entry 1 capture window")
        if BOOT_BANNER.match(line):
            banners += 1
            if banners > 1 or markers:
                raise ValueError("another boot in Entry 1 capture window")
        if line.startswith(b"[bt0] DRAM: strap") and not GPIO_STRAP.fullmatch(line):
            match = STRAP.fullmatch(line)
            markers.append(("strap", match[1] if match else None, offset, line_end))
        if re.match(rb"\[bt0\] DRAM: [0-9]+ .*MiB", line):
            match = SIZE.fullmatch(line)
            markers.append(("size", match[1] if match else None, offset, line_end))
        offset = line_end
    name, size = BOARDS[board]
    if (
        [(kind, value) for kind, value, _, _ in markers]
        != [("strap", name), ("size", size)]
        or any(not lo <= first < last <= hi for _, _, first, last in markers)
        or int(size) != expected_mb
    ):
        raise ValueError(
            "serial does not contain one matching strap and size identity in order"
        )
    return dict(board=board, start=start, end=end, sha256=want)


def absolute(value):
    return Path(os.path.abspath(value))


class Receipt:
    def __init__(self, path, record):
        self.path = path
        self.sidecar = Path(f"{path}.sha256")
        self.record = record
        self.digest = None

    def save(self):
        data = (json.dumps(self.record, indent=2, sort_keys=True) + "\n").encode()
        self.digest = sha(data)
        atomic(self.path, data)
        atomic(self.sidecar, (self.digest + "\n").encode())

    def verify(self):
        if (
            self.sidecar.read_text() != self.digest + "\n"
            or sha(self.path.read_bytes()) != self.digest
        ):
            raise ValueError("preflight receipt digest mismatch")

    def ready(self):
        self.record["status"] = "preflight-ready"
        self.save()

    @classmethod
    def read_sealed(cls, path):
        content = path.read_bytes()
        receipt = cls(path, json.loads(content))
        if receipt.sidecar.read_text() != sha(content) + "\n":
            raise ValueError("receipt digest mismatch")
        return receipt.record


def socket_address(path):
    # Abstract names avoid path-length limits for deeply nested run directories.
    # Only the same effective UID can send a resume request (SO_PEERCRED).
    return "\0a7a-fel-" + sha(f"{os.geteuid()}:{path}".encode())


def send(stream, code, text):
    stream.write((json.dumps([int(code), text]) + "\n").encode())
    stream.flush()


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("preflight receipt expired (120 seconds)")
    return seconds


def receive_request(conn, deadline):
    data = bytearray()
    while len(data) < 16384:
        conn.settimeout(remaining(deadline))
        chunk = conn.recv(16384 - len(data))
        if not chunk:
            raise ValueError("incomplete resume request")
        data.extend(chunk)
        if b"\n" in data:
            request, _, extra = data.partition(b"\n")
            if extra:
                raise ValueError("expected one resume request")
            remaining(deadline)
            return json.loads(request)
    raise ValueError("oversized resume request")


def state_hash(session):
    try:
        data = session.path.read_bytes()
        if json.loads(data) != session.state:
            raise ValueError("state contents differ from the transaction")
    except (OSError, ValueError) as exc:
        raise SessionError(Exit.IDENTITY, "FEL epoch or devnum changed") from exc
    return sha(data)


def bounded_identity_time(completed, now):
    if not 0 <= now - completed <= IDENTITY_LIFETIME:
        raise ValueError("preflight receipt expired (120 seconds)")


def cached_resume(request, receipt, session, serial, cached, work):
    record = receipt.record
    receipt.verify()
    bounded_identity_time(record["entry_one_monotonic"], time.monotonic())
    record["status"] = "resume-started"
    record["resume_started_ns"] = time.time_ns()
    receipt.save()
    identity = clear_identity(
        serial,
        record["identity_cursor"],
        request["clearance"],
        request["board"],
        cached["PORT_MB"][session.port],
    )
    record["identity"] = identity
    if state_hash(session) != record["epoch_sha256"]:
        raise SessionError(Exit.IDENTITY, "FEL epoch or devnum changed")
    mailbox = cached["read_mailbox"](session, work)
    cached["require_ready"](mailbox, session.port, record["mhz"])
    record["resume_mailbox"] = mailbox
    cached["upload_dram"](session, work)
    record["handover"] = "Entry 2 not acknowledged; handover unconfirmed"
    cursor = serial.capture(record["identity_cursor"])
    session.submit(("exec", "0x90044"), returns=True, timeout=15)
    record["handover"] = (
        "handover unconfirmed pending fresh board-specific serial evidence"
    )
    try:
        record["handover_cursor"] = serial.capture(cursor)
    except (OSError, ValueError) as exc:
        raise SessionError(Exit.SERIAL_UNCONFIRMED, str(exc)) from exc
    rolling = record["handover_cursor"]

    def observe():
        nonlocal rolling
        try:
            rolling = serial.capture(record["handover_cursor"], rolling=rolling)
        except (OSError, ValueError) as exc:
            raise SessionError(Exit.SERIAL_UNCONFIRMED, str(exc)) from exc

    try:
        session.reconnect(observe=observe)
    except SessionError as problem:
        record["reconnect"] = dict(
            outcome="lost" if problem.code == Exit.LOST_AFTER else "refused",
            exit=int(problem.code),
        )
        unchanged = isinstance(problem, UnchangedEnumeration)
        if problem.code == Exit.LOST_AFTER or unchanged:
            try:
                data = close_handover(serial, record, rolling)
            except (OSError, ValueError) as exc:
                record["handover_capture_error"] = str(exc)
            else:
                if unchanged:
                    try:
                        if not handover_markers(
                            attempt_lines(record["handover_cursor"], data)
                        ):
                            raise ValueError(
                                "no fresh RVBAR then main> in this attempt"
                            )
                    except ValueError as exc:
                        raise SessionError(problem.code, f"{problem}: {exc}") from exc
                    record["reconnect"] = dict(
                        outcome="stale", exit=int(Exit.LOST_AFTER)
                    )
                    raise SessionError(
                        Exit.LOST_AFTER, "unchanged FEL devnum after serial handover"
                    ) from problem
        raise
    record["reconnect"] = dict(outcome="verified", exit=int(Exit.SUCCESS))
    try:
        close_handover(serial, record, rolling)
    except (OSError, ValueError) as exc:
        raise SessionError(Exit.SERIAL_UNCONFIRMED, str(exc)) from exc
    if session.watch is not None:
        session.watch()
    record["reconnect_epoch"] = session.state
    record["status"] = "reconnected-handover-unconfirmed"
    return Exit.SERIAL_UNCONFIRMED, record["handover"]


def close_handover(serial, record, rolling):
    eof, end, data = serial.observe(record["handover_cursor"], rolling=rolling)
    record["handover_end"] = end
    record["handover_end_cursor"] = eof
    record["handover_sha256"] = sha(data)
    return data


def guardian(args, reply):
    receipt = Receipt(
        args.receipt,
        dict(
            port=args.port,
            state=str(args.state),
            serial_log=str(args.serial_log),
            set=str(args.set),
            preflight_started_ns=time.time_ns(),
            status="preflight-started",
        ),
    )
    if args.state in (receipt.path, receipt.sidecar):
        raise ValueError("receipt, digest sidecar and FEL state must be separate")
    with lease(args.port) as fd, socket.socket(socket.AF_UNIX) as listener:
        listener.bind(socket_address(receipt.path))
        listener.listen(1)
        if os.path.lexists(receipt.path) or os.path.lexists(receipt.sidecar):
            raise ValueError("preflight requires a new receipt and digest sidecar")
        if os.path.lexists(args.state):
            raise SessionError(Exit.IDENTITY, "preflight requires fresh FEL state")
        session = Session(args.port, args.state, receipt.record, fd)
        session.watch = ClientWatch(reply, "preflight")
        serial = Serial(args.port, args.serial_log)
        cached = runpy.run_path(str(SCRIPTS / "lib/cached_set.py"))
        with tempfile.TemporaryDirectory(dir=receipt.path.parent) as scratch:
            work = Path(scratch)
            receipt.save()
            try:
                serial.capture()
                record = receipt.record
                record["hashes"], record["mhz"] = cached["stage"](
                    args.set, work, args.expect_set_sha256
                )
                session.start()

                def before_exec():
                    cursor = serial.capture()
                    record["identity_cursor"] = cursor
                    record["identity_window_start"] = cursor["start"]

                record["mailbox"] = cached["entry_one"](
                    session,
                    work,
                    args.port,
                    record["mhz"],
                    before_exec,
                )
                record["entry_one_completed_ns"] = time.time_ns()
                record["entry_one_monotonic"] = time.monotonic()
                record["epoch"] = session.state
                record["epoch_sha256"] = state_hash(session)
                session.watch()
                receipt.ready()
                session.watch()
            except Exception as exc:
                receipt.record.update(status="preflight-refused", error=str(exc))
                receipt.save()
                raise
            try:
                send(reply, Exit.SUCCESS, "")
            except BrokenPipeError as exc:
                record.update(
                    status="preflight-refused", error="preflight client disconnected"
                )
                receipt.save()
                raise SessionError(Exit.CLIENT_GONE, record["error"]) from exc
            reply.close()
            session.watch = None
            deadline = record["entry_one_monotonic"] + IDENTITY_LIFETIME
            while True:
                try:
                    listener.settimeout(remaining(deadline))
                    conn, _ = listener.accept()
                except TimeoutError:
                    record.update(
                        status="resume-expired",
                        error="preflight receipt expired (120 seconds)",
                    )
                    receipt.save()
                    return
                with conn:
                    _, uid, _ = struct.unpack(
                        "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                    )
                    if uid != os.geteuid():
                        continue
                    request_received = False
                    try:
                        request = receive_request(conn, deadline)
                        request_received = True
                        session.watch = ClientWatch(conn, "resume")
                        session.watch()
                        code, message = cached_resume(
                            request, receipt, session, serial, cached, work
                        )
                    except TimeoutError:
                        code, message = (
                            Exit.INPUT,
                            "preflight receipt expired (120 seconds)",
                        )
                        record.update(status="resume-expired", error=message)
                    except (OSError, ValueError, KeyError, TypeError) as exc:
                        code, message = getattr(exc, "code", Exit.INPUT), str(exc)
                        if (
                            record["status"] == "resume-started"
                            or not request_received
                            or code == Exit.CLIENT_GONE
                        ):
                            record.update(status="resume-refused", error=message)
                    if record["status"] != "preflight-ready":
                        record["resume_ended_ns"] = time.time_ns()
                        receipt.save()
                    try:
                        conn.settimeout(0.25)
                        conn.sendall((json.dumps([int(code), message]) + "\n").encode())
                    except OSError:
                        pass
                    return


def start_guardian(args):
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_end)
        code = 0
        try:
            os.setsid()
            with open(os.devnull, "r+b") as null:
                for fd in (0, 1, 2):
                    os.dup2(null.fileno(), fd)
            with os.fdopen(write_end, "wb") as reply:
                try:
                    guardian(args, reply)
                except Exception as exc:
                    if not reply.closed:
                        send(reply, getattr(exc, "code", Exit.INPUT), str(exc))
        except BaseException:
            code = 1
        finally:
            os._exit(code)
    os.close(write_end)
    with os.fdopen(read_end, "rb") as reply:
        line = reply.readline()
    if not line:
        os.waitpid(pid, 0)
        raise ValueError("FEL transaction guardian did not return preflight")
    code, message = json.loads(line)
    if code:
        os.waitpid(pid, 0)
    return code, message


def cached_main():
    parser = argparse.ArgumentParser(
        description="Run a cached memtest in two stages", allow_abbrev=False
    )
    parser.add_argument("--stage", required=True, choices=("preflight", "resume"))
    parser.add_argument("--receipt", required=True, type=absolute)
    parser.add_argument("--port", choices=sorted(LOGS))
    parser.add_argument("--state", type=absolute)
    parser.add_argument("--set", type=absolute)
    parser.add_argument("--expect-set-sha256")
    parser.add_argument("--serial-log", type=absolute)
    parser.add_argument("--identity-cleared")
    parser.add_argument("--expect-board", choices=BOARDS)
    args = parser.parse_args()
    preflight_only = (
        args.port,
        args.state,
        args.set,
        args.expect_set_sha256,
        args.serial_log,
    )
    resume_only = (args.identity_cleared, args.expect_board)
    if args.stage == "preflight":
        if (
            not all(preflight_only)
            or not SHA256.fullmatch(args.expect_set_sha256)
            or any(resume_only)
        ):
            parser.error(
                "preflight requires port, state, set, expected set SHA256 and serial log"
            )
        code, message = start_guardian(args)
    else:
        if not all(resume_only) or any(preflight_only):
            parser.error(
                "resume requires a receipt, identity clearance and expected board"
            )
        with socket.socket(socket.AF_UNIX) as sock:
            try:
                sock.connect(socket_address(args.receipt))
            except ConnectionRefusedError as exc:
                raise ValueError(
                    "no live preflight guardian (expired, refused or already consumed)"
                ) from exc
            with sock.makefile("rwb") as stream:
                stream.write(
                    (
                        json.dumps(
                            dict(
                                clearance=args.identity_cleared, board=args.expect_board
                            )
                        )
                        + "\n"
                    ).encode()
                )
                stream.flush()
                code, message = json.loads(stream.readline())
    if message:
        print(f"a7a-cached-run: {message}", file=sys.stderr)
    return code


def verify_attempt(record):
    submission = ("exec", "0x90044")
    ack = [e for e in record["events"] if e["event"] == "submission-acked"]
    if len(ack) != 1 or tuple(ack[0]["command"]) != submission:
        raise SessionError(
            Exit.SERIAL_UNCONFIRMED, "no matching Entry 2 submission ACK"
        )
    if record.get("reconnect") not in (
        dict(outcome="verified", exit=int(Exit.SUCCESS)),
        dict(outcome="lost", exit=int(Exit.LOST_AFTER)),
        dict(outcome="stale", exit=int(Exit.LOST_AFTER)),
    ):
        raise SessionError(
            Exit.SERIAL_UNCONFIRMED,
            "reconnect outcome does not permit serial confirmation",
        )
    try:
        cursor = record["handover_cursor"]
        serial = Serial(record["port"], cursor["log"])
        end, data = serial.interval(cursor, closed=record["handover_end_cursor"])
        if sha(data) != record["handover_sha256"]:
            raise ValueError("closed handover slice digest mismatch")
        if not handover_markers(attempt_lines(cursor, data)):
            raise ValueError("no fresh RVBAR then main> in this attempt")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SessionError(Exit.SERIAL_UNCONFIRMED, str(exc)) from exc
    return dict(**cursor, end=end, slice_sha256=sha(data))


def cli(entrypoint):
    try:
        sys.exit(entrypoint())
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"fel-session: {exc}", file=sys.stderr)
        sys.exit(getattr(exc, "code", Exit.INPUT))


def wait_for_handover(serial, cursor, record, seconds=10):
    deadline = time.monotonic() + seconds
    rolling = None
    while True:
        rolling, end, data = serial.observe(cursor, rolling=rolling)
        record["handover_end"] = end
        if handover_markers(attempt_lines(cursor, data)):
            record["handover_sha256"] = sha(data)
            return
        if time.monotonic() >= deadline:
            raise SessionError(
                Exit.SERIAL_UNCONFIRMED, "no fresh RVBAR then main> on this board"
            )
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))


def wait_for_handover_target(mailbox, record, seconds=10):
    deadline = time.monotonic() + seconds
    stuck = False
    try:
        while True:
            # Only a classified disconnect can proceed without an ACKed mailbox
            # read; a generic failure is never treated as offline handover.
            try:
                command_budget(deadline, "Entry 2 mailbox", minimum=MIN_POLL_BUDGET)
                current = mailbox(deadline)
            except SessionError as exc:
                if exc.code != Exit.LOST_AFTER:
                    raise
                command_budget(deadline, "Entry 2 mailbox")
                record["device_loss"] = int(exc.code)
                return
            command_budget(deadline, "Entry 2 mailbox")
            record["entry_two_mailbox"] = current
            magic, state, *_ = current
            if magic != 0x46413741 or state not in (0x11, 0x21):
                raise SessionError(
                    Exit.SERIAL_UNCONFIRMED,
                    f"Entry 2 mailbox did not allow handover (state {state:#x})",
                )
            if state == 0x21:
                return
            stuck = True
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    except PollingWindowExpired as exc:
        if stuck:
            raise SessionError(
                Exit.SERIAL_UNCONFIRMED, "Entry 2 mailbox remained at 0x11"
            ) from exc
        raise


def workspace_boot(args, fd, record):
    source = args.bundle
    expected = os.environ.get("EXPECT_PROFILE") or os.environ.get("DRAM_MHZ", "1200")
    serial_path = os.environ.get("FEL_SERIAL_LOG")
    if not serial_path:
        raise ValueError("FEL_SERIAL_LOG is required for workspace boot")
    serial = Serial(args.port, absolute(serial_path))
    serial.capture()
    with tempfile.TemporaryDirectory(dir=source.parent) as scratch:
        bundle = Path(scratch)
        work = bundle / "work"
        work.mkdir()
        for name in (
            "bt0-fel.bin",
            "firmware.bin",
            "firmware.seek",
            "build-manifest.json",
        ):
            shutil.copyfile(source / name, bundle / name)
        check = [
            sys.executable,
            "-I",
            SCRIPTS / "fel-check.py",
            bundle,
            "--work",
            work,
            "--expect-mode",
            os.environ.get("EXPECT_MODE", "blobfree"),
            "--expect-profile",
            expected,
        ]
        if auth := os.environ.get("FEL_MEASUREMENT_AUTH"):
            check.extend(("--measurement-auth", auth))
        if subprocess.run(check, stdin=subprocess.DEVNULL).returncode:
            raise ValueError("workspace bundle failed preflight verification")
        state = args.state or bundle / "fel-state"
        session = Session(args.port, state, record, fd)
        cached = runpy.run_path(str(SCRIPTS / "lib/cached_set.py"))
        session.start()
        record["mailbox"] = cached["entry_one"](
            session, bundle, args.port, int(expected)
        )
        cached["put"](session, work, "0xdf200", work / "table.bin")
        for line in (work / "plan").read_text().splitlines():
            _, address, _, name, _ = line.split(maxsplit=4)
            cached["put"](session, work, address, work / name)
        entry = ("exec", "0x90044")
        generation = serial.capture()
        session.submit(entry, returns=False, timeout=15)
        try:
            record["handover_cursor"] = cursor = serial.capture(generation)
            wait_for_handover_target(
                lambda deadline: cached["read_mailbox"](
                    partial(session, poll_deadline=deadline), work
                ),
                record,
            )
            wait_for_handover(serial, cursor, record)
        except (OSError, ValueError) as exc:
            if isinstance(exc, SessionError):
                raise
            raise SessionError(Exit.SERIAL_UNCONFIRMED, str(exc)) from exc
        print(
            f"Handover to oreboot main confirmed by fresh serial on FEL port {args.port}"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subs = parser.add_subparsers(dest="mode", required=True)
    reset = subs.add_parser("reset")
    reset.add_argument("--port", required=True)
    reset.add_argument("--state", required=True, type=absolute)
    boot = subs.add_parser("boot")
    boot.add_argument("--port", required=True, choices=LOGS)
    boot.add_argument("--state", type=absolute)
    boot.add_argument("bundle", type=absolute)
    verify = subs.add_parser("verify-handover")
    verify.add_argument("--receipt", required=True, type=absolute)
    args = parser.parse_args()
    if args.mode == "verify-handover":
        print(json.dumps(verify_attempt(Receipt.read_sealed(args.receipt))))
        return Exit.SUCCESS
    with lease(args.port) as fd:
        record = {}
        try:
            if args.mode == "boot":
                workspace_boot(args, fd, record)
            else:
                session = Session(args.port, args.state, record, fd)
                session.start()
                session.watchdog()
        finally:
            print(json.dumps(record), file=sys.stderr)
    return Exit.SUCCESS


if __name__ == "__main__":
    cli(main)
