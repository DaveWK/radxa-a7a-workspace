#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host verification for the Radxa Cubie A7A oreboot bt0/main matrix.

This is the maintained board-integration matrix for this workspace. It builds
the bt0 and main feature sets of ``src/mainboard/radxa/cubie-a7a`` at an exact
source checkout, compares them with a retained baseline, runs the five required
host test suites, runs the external publication gate, and checks the four
retained default-image digests.

The harness is fail-closed: the source HEAD must equal ``--source-sha`` and the
gate base must be an ancestor of it, every stage's real exit status is checked,
every produced image is validated by content (size class, extension, eGON
header), a missing path, baseline image, suite or gate is a failure, and no
pipeline (``grep``, ``tail``) can hide a stage's exit. The external gate and the
private build inputs are inputs, not vendored here; pass their paths on the
command line.

Usage:
    python3 -I scripts/verify-a7a/verify.py \
        --source <oreboot-checkout> --source-sha <full-head-sha> \
        --base <gate-base> --baseline <matrix-baseline-dir> \
        --baseline-sums-sha256 <sha256-of-baseline-SHA256SUMS> \
        --dram-lib <libdram-a733.a> --phyfw-obj <libdram-object> \
        --gate <gate.py> --out <job-output-dir> \
        --expect-digest default=<sha256> \
        --expect-digest default-fel=<sha256> \
        --expect-digest default@2400=<sha256> \
        --expect-digest default-fel@2400=<sha256>

Exit status is 0 only when every stage passes. The job output directory must be
fresh (it is never reused); it holds the build logs, the produced images, the
suite logs, the gate log and a SHA256SUMS file. The source checkout is never
written to; cargo targets and TMPDIR stay under the job output directory.
"""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

BT0_DIR = "src/mainboard/radxa/cubie-a7a/bt0"
MAIN_DIR = "src/mainboard/radxa/cubie-a7a/main"
COMMON_LIB = "src/mainboard/radxa/cubie-a7a/common/src/lib.rs"

# The five host suites required by the retained verification record. The board
# fastboot and bootlog suites live at these paths at the verified SHA; there is
# no bootlayout directory at this SHA and no substitute suite is accepted.
SUITE_DIRS = (
    "src/mainboard/radxa/cubie-a7a/dram",
    "src/mainboard/radxa/cubie-a7a/fastboot",
    "src/mainboard/radxa/cubie-a7a/common",
    "src/lib/bootlog",
    "src/lib/dram-train",
)

# OLD: every feature set of the matrix before the default changed, built with
# --no-default-features, compared with the image the same set gave at the base.
OLD_SETS = (
    "",
    "fel",
    "blobless",
    "bl-mission",
    "fel hybrid",
    "spinor",
    "dramlib",
    "dramlib fel",
    "dramlib spinor",
    "dramlib fel fastboot",
    "fel fastboot",
    "dramlib fel fastboot fastboot-nor-write",
    "dramlib fel fastboot fastboot-emmc-write",
    "emmc",
    "dramlib emmc",
    "fel bl-mission dram-lab",
    "otp",
    "fel bl-mission",
    "hybrid",
    "blobless otp",
    "blobless wck-alias-probe",
    "blobless probe-ps3",
    "blobless rd-measure",
    "blobless rd-train-only",
    "blobless handover",
    "blobless handover otp",
    "dramlib otp",
    "dramlib dram-trace",
    "dramlib fel dram-trace",
    "av3-dump",
    "av3c",
    "av3g",
    "av3g-gate",
    "av3h",
    "bl-mission wr-r1",
    "fel bl-mission wr-r1",
    "fel hybrid wr-r1",
    "fel bl-mission dram-lab wr-r1",
)

# NEW: the default feature set (the blob-free boot), per medium and profile.
# (tag, A7A_PROFILE or None, features, baseline required). The full-speed and
# 800/400 profile rows are new at this source: they have no historical baseline
# and are labelled as such.
NEW_ENTRIES = (
    ("default", None, (), True),
    ("default-fel", None, ("fel",), True),
    ("default@2400", "2400", (), True),
    ("default-fel@2400", "2400", ("fel",), True),
    ("default-emmc", None, ("emmc",), True),
    ("default-spinor", None, ("spinor",), True),
    ("default-otp", None, ("otp",), True),
    ("default-fel+fastboot", None, ("fel", "fastboot"), True),
    (
        "default-fel+fastboot+fastboot-nor-write",
        None,
        ("fel", "fastboot", "fastboot-nor-write"),
        True,
    ),
    (
        "default-fel+fastboot+fastboot-emmc-write",
        None,
        ("fel", "fastboot", "fastboot-emmc-write"),
        True,
    ),
    ("default-wr-r1", None, ("wr-r1",), True),
    ("default-fel+wr-r1", None, ("fel", "wr-r1"), True),
    ("default+full-speed", None, ("full-speed",), False),
    ("default@800", "800", (), False),
    ("default-fel@800", "800", ("fel",), False),
    ("default@400", "400", (), False),
    ("default-fel@400", "400", ("fel",), False),
)

# LAB: lab entries with no historical baseline image, labelled as new. The lab
# backend needs bl-mission: with --no-default-features and no lab backend
# selected the build is not equivalent.
LAB_ENTRIES = (
    ("lab-drift", ("fel", "bl-mission", "dram-lab", "drift-log")),
    ("lab-full-speed", ("fel", "bl-mission", "dram-lab", "full-speed")),
)

MAIN_SETS = (
    "gmac pcie usb",
    "",
    "gmac",
    "pcie",
    "usb",
    "gmac pcie usb memtest",
    "gmac pcie usb trng",
    "gmac pcie usb trng trng-byte-addr",
    "gmac pcie usb-hs-only",
    "gmac pcie usb-hs-only trng",
    "gmac usb trng trng-byte-addr",
)

# The four retained default images, checked by full SHA256.
DIGEST_NAMES = ("default", "default-fel", "default@2400", "default-fel@2400")

# scripts/mkimage.py: EGON_MAX (the vendor boot0 length) and EGON_PAD.
EGON_MAX = 0x4A000
EGON_PAD = 0x2000
# bt0/build.rs MEMORY_FEL: the FEL link window length.
FEL_MAX = 0x4F000
# The raw eGON.BT0 header (bt0/src/main.rs global_asm, fastboot/src/egon.rs,
# scripts/mkimage.py): magic at 4, checksum at 12, length at 16, header size at
# 20, run address at 32. The image tool fills length and checksum; the raw
# binary carries the length 0 and the stamp.
EGON_MAGIC = b"eGON.BT0"
EGON_STAMP = 0x5F0A6C39
EGON_HEADER_SIZE = 48
MEDIA_RUN_ADDR = 0x47000

# The exact compile_error texts at this source. A negative row must fail with
# its own diagnostic, not for an arbitrary reason.
CONFLICT_DIAGNOSTIC = (
    "another DRAM backend or a lab feature together with the default feature "
    "`blobfree` (the blob-free boot): build it with --no-default-features"
)
FEL_SPINOR_CONFLICT = "features `fel` and `spinor` exclude each other"

# (tag, features, --no-default-features, exact expected diagnostic)
NEGATIVE_ENTRIES = (
    (
        "default+fel+dram-lab+drift-log",
        ("fel", "dram-lab", "drift-log"),
        False,
        CONFLICT_DIAGNOSTIC,
    ),
    ("default+dram-lab", ("dram-lab",), False, CONFLICT_DIAGNOSTIC),
    ("default+dramlib", ("dramlib",), False, CONFLICT_DIAGNOSTIC),
    ("default+blobless", ("blobless",), False, CONFLICT_DIAGNOSTIC),
    ("fel+spinor", ("fel", "spinor"), True, FEL_SPINOR_CONFLICT),
)

BASELINE_SAME = "= base"
BASELINE_NEW = "no baseline (new)"

TEST_RESULT_RE = re.compile(
    r"^test result: (?:ok|FAILED)\.\s+(\d+) passed; (\d+) failed; " r"(\d+) ignored;",
    re.M,
)
RUNNING_RE = re.compile(r"^\s*Running\s+.*?\((\S+)\)\s*$", re.M)
MAIN_MAX_RE = re.compile(
    r"MAIN_MAX_SIZE\s*:\s*usize\s*=\s*(0x[0-9A-Fa-f_]+|\d[\d_]*)\s*;"
)
WARNING_RE = re.compile(r"^warning: (.*)$")
WARNING_SUMMARY_RE = re.compile(r"^`[^`]+`\s+\(.*\)\s+generated\s+\d+\s+warnings?")
WARNING_LOCATION_RE = re.compile(r"^\s*-->\s*(\S+?):(\d+):(\d+)\s*$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def le32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def paths_overlap(first: Path, second: Path) -> bool:
    """True when one absolute path is the other or lies inside it."""
    return (
        first == second or first.is_relative_to(second) or second.is_relative_to(first)
    )


@dataclass
class CommandResult:
    argv: tuple[str, ...]
    cwd: str
    returncode: int
    output: str


@dataclass
class BuildResult:
    tag: str
    section: str
    ok: bool
    baseline: str
    size: int | None = None
    warnings: int = 0
    detail: str = ""


@dataclass
class MatrixResult:
    ok: bool
    old_total: int
    old_ok: int
    old_identical: int
    old_differ: int
    new_total: int
    new_ok: int
    new_identical: int
    new_differ: int
    new_nobaseline: int
    lab_total: int
    lab_ok: int
    main_total: int
    main_ok: int
    main_identical: int
    failures: list[str]
    builds: list[BuildResult] = field(default_factory=list)


@dataclass
class NegativeResult:
    tag: str
    ok: bool
    returncode: int
    expected: str
    diagnostic_found: bool
    detail: str


@dataclass
class NegativesResult:
    ok: bool
    results: list[NegativeResult]


@dataclass
class SuiteResult:
    directory: str
    ok: bool
    passed: int
    failed: int
    ignored: int
    binaries_expected: int
    binaries_run: int
    detail: str


@dataclass
class SuitesResult:
    ok: bool
    results: list[SuiteResult]


@dataclass
class GateResult:
    ok: bool
    returncode: int
    output: str


@dataclass
class DigestResult:
    name: str
    expected: str | None
    actual: str | None
    ok: bool


@dataclass
class DigestsResult:
    ok: bool
    results: list[DigestResult]


@dataclass
class Config:
    source: Path
    source_sha: str
    base: str
    baseline: Path
    baseline_sums_sha256: str
    dram_lib: Path
    phyfw_obj: Path
    gate: Path
    out: Path
    expected_digests: dict[str, str]


class SubprocessRunner:
    """Run a command, capture its real exit status and optionally log it."""

    def run(
        self,
        argv: list[str],
        cwd: Path,
        env: dict[str, str],
        log: Path | None = None,
    ) -> CommandResult:
        try:
            proc = subprocess.run(
                argv,
                cwd=str(cwd),
                env=env,
                capture_output=True,
                text=True,
                errors="replace",
            )
            output = proc.stdout + proc.stderr
            returncode = proc.returncode
        except FileNotFoundError as exc:
            output = f"{argv[0]}: {exc}\n"
            returncode = 127
        except OSError as exc:
            output = f"{argv[0]}: {exc}\n"
            returncode = 126
        if log is not None:
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(output, encoding="utf-8")
        return CommandResult(tuple(argv), str(cwd), returncode, output)


def build_env(args: Config, out: Path) -> dict[str, str]:
    env = dict(os.environ)
    for key in list(env):
        if key.startswith("A7A_") or key in ("RUSTFLAGS", "RUSTUP_TOOLCHAIN"):
            del env[key]
    env["CARGO_NET_OFFLINE"] = "true"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["RUSTUP_AUTO_INSTALL"] = "0"
    env["A733_DRAM_LIB"] = str(args.dram_lib)
    env["A733_PHY_FW_OBJ"] = str(args.phyfw_obj)
    env["TMPDIR"] = str(out / "tmp")
    return env


def required_baseline_names() -> list[str]:
    names = []
    for set_name in OLD_SETS:
        tag = "old-" + (set_name.replace(" ", "+") or "default")
        names.append(f"bt0-{tag}.bin")
    for tag, _profile, _features, baseline_required in NEW_ENTRIES:
        if baseline_required:
            names.append(f"bt0-{tag}.bin")
    for set_name in MAIN_SETS:
        tag = set_name.replace(" ", "+") or "none"
        names.append(f"main-{tag}.bin")
    return names


def matrix_ok(
    failures: list[str], main_total: int, main_ok: int, main_identical: int
) -> bool:
    """Every build succeeded and every main image is byte-identical to the base."""
    return not failures and main_ok == main_total and main_identical == main_total


def negative_contract_ok(
    returncode: int, output: str, expected: str = CONFLICT_DIAGNOSTIC
) -> tuple[bool, str]:
    """A negative row must fail with its own exact diagnostic."""
    if returncode == 0:
        return False, "expected the build to fail, got exit 0"
    if expected not in output:
        return False, "build failed without the expected diagnostic"
    return True, "expected diagnostic found"


def has_section(readelf_output: str, name: str) -> bool:
    """True when readelf lists a section (its lines are indented)."""
    return (
        re.search(rf"^\s*\[\s*\d+\]\s+{re.escape(name)}\b", readelf_output, re.M)
        is not None
    )


def parse_test_results(output: str) -> tuple[int, int, int, bool]:
    passed = failed = ignored = 0
    found = False
    for match in TEST_RESULT_RE.finditer(output):
        found = True
        passed += int(match.group(1))
        failed += int(match.group(2))
        ignored += int(match.group(3))
    return passed, failed, ignored, found


def parse_running_paths(output: str) -> list[str]:
    """The executable paths from cargo's `Running ... (<path>)` lines."""
    return RUNNING_RE.findall(output)


def read_main_max(source: Path) -> int | None:
    """MAIN_MAX_SIZE from the source, not a hard-coded copy."""
    path = source / COMMON_LIB
    if not path.is_file():
        return None
    match = MAIN_MAX_RE.search(path.read_text(encoding="utf-8"))
    if match is None:
        return None
    return int(match.group(1), 0)


def check_egon_header(data: bytes) -> str | None:
    """Validate the raw media bt0 eGON header, or return the defect.

    mkimage.py writes the length and checksum; the raw binary carries the
    length 0 and the stamp, so those placeholders are checked here, together
    with the magic, the header size and the media run address the mask ROM
    requires (fastboot/src/egon.rs).
    """
    if len(data) < EGON_HEADER_SIZE:
        return (
            f"bt0 image is {len(data)} bytes, shorter than the "
            f"{EGON_HEADER_SIZE}-byte eGON header"
        )
    if data[4:12] != EGON_MAGIC:
        return "bt0 image has no eGON.BT0 magic at offset 4"
    header_size = le32(data, 0x14)
    if header_size != EGON_HEADER_SIZE:
        return f"eGON header size is {header_size}, expected {EGON_HEADER_SIZE}"
    run_addr = le32(data, 0x20)
    if run_addr != MEDIA_RUN_ADDR:
        return f"eGON run address is {run_addr:#x}, expected {MEDIA_RUN_ADDR:#x}"
    length = le32(data, 0x10)
    if length != 0:
        return (
            f"eGON length field is {length:#x}, expected the raw 0 the image tool fills"
        )
    checksum = le32(data, 0x0C)
    if checksum != EGON_STAMP:
        return (
            f"eGON checksum field is {checksum:#x}, expected the stamp {EGON_STAMP:#x}"
        )
    return None


class Harness:
    def __init__(self, args: Config, runner: SubprocessRunner | None = None):
        self.args = args
        self.runner = runner or SubprocessRunner()
        self.env = build_env(args, args.out)
        self.source_head: str | None = None
        self.gate_base: str | None = None
        self.gate_head: str | None = None
        self.main_max: int | None = None
        self.warnings: dict[str, int] = {}
        self._host_checked = False
        self._host: str | None = None

    # -- fail-closed path checks ------------------------------------------

    def check_paths(self) -> list[str]:
        a = self.args
        errors: list[str] = []
        # Overlap first: nothing is created when the job would write into a
        # protected input.
        for label, path in (
            ("source", a.source),
            ("baseline", a.baseline),
            ("dram-lib", a.dram_lib),
            ("phyfw-obj", a.phyfw_obj),
            ("gate", a.gate),
        ):
            if paths_overlap(a.out, path):
                errors.append(f"output directory overlaps the {label}: {path}")
        if errors:
            return errors
        if a.out.exists():
            if not a.out.is_dir():
                errors.append(f"output path is not a directory: {a.out}")
                return errors
            if any(a.out.iterdir()):
                errors.append(f"output directory exists and is not empty: {a.out}")
                return errors
        else:
            a.out.mkdir(parents=True)
        for sub in (
            "matrix/out",
            "matrix/logs",
            "target/bt0",
            "target/main",
            "target/test",
            "target/negative",
            "tests",
            "tmp",
        ):
            (a.out / sub).mkdir(parents=True, exist_ok=True)
        if not a.source.is_dir():
            errors.append(f"source directory not found: {a.source}")
        else:
            self._check_source(errors)
            for rel in (BT0_DIR, MAIN_DIR, *SUITE_DIRS):
                if not (a.source / rel).is_dir():
                    errors.append(f"required source directory missing: {rel}")
            self.main_max = read_main_max(a.source)
            if self.main_max is None:
                errors.append(f"MAIN_MAX_SIZE not found in the source: {COMMON_LIB}")
        if not a.baseline.is_dir():
            errors.append(f"baseline directory not found: {a.baseline}")
        else:
            for name in required_baseline_names():
                if not (a.baseline / name).is_file():
                    errors.append(f"required baseline image missing: {name}")
            errors.extend(self._check_baseline_sums())
        for label, path in (
            ("dram-lib", a.dram_lib),
            ("phyfw-obj", a.phyfw_obj),
            ("gate", a.gate),
        ):
            if not path.is_file():
                errors.append(f"{label} not found: {path}")
        errors.extend(self.check_tooling())
        return errors

    def _check_source(self, errors: list[str]) -> None:
        a = self.args
        git_dir = self.runner.run(
            ["git", "-C", str(a.source), "rev-parse", "--git-dir"], a.source, self.env
        )
        if git_dir.returncode != 0:
            errors.append(f"source is not a git repository: {a.source}")
            return
        head = self.runner.run(
            ["git", "-C", str(a.source), "rev-parse", "HEAD"], a.source, self.env
        )
        if head.returncode != 0:
            errors.append("could not read the source HEAD")
            return
        actual_head = head.output.strip()
        expected = self.runner.run(
            [
                "git",
                "-C",
                str(a.source),
                "rev-parse",
                "--verify",
                "--quiet",
                f"{a.source_sha}^{{commit}}",
            ],
            a.source,
            self.env,
        )
        if expected.returncode != 0:
            errors.append(f"--source-sha is not a commit in the source: {a.source_sha}")
        elif actual_head != expected.output.strip():
            errors.append(
                f"source HEAD {actual_head} does not match --source-sha "
                f"{expected.output.strip()}"
            )
        else:
            self.source_head = actual_head
        base = self.runner.run(
            [
                "git",
                "-C",
                str(a.source),
                "rev-parse",
                "--verify",
                "--quiet",
                f"{a.base}^{{commit}}",
            ],
            a.source,
            self.env,
        )
        if base.returncode != 0:
            errors.append(f"base revision not found in source: {a.base}")
            return
        base_sha = base.output.strip()
        if self.source_head is None:
            return
        ancestor = self.runner.run(
            [
                "git",
                "-C",
                str(a.source),
                "merge-base",
                "--is-ancestor",
                base_sha,
                self.source_head,
            ],
            a.source,
            self.env,
        )
        if ancestor.returncode != 0:
            errors.append(
                f"base {base_sha} is not an ancestor of HEAD {self.source_head}"
            )
        else:
            self.gate_base = base_sha
            self.gate_head = self.source_head
        status = self.runner.run(
            ["git", "-C", str(a.source), "status", "--porcelain"], a.source, self.env
        )
        if status.returncode != 0:
            errors.append("could not read the source worktree status")
        elif status.output.strip():
            errors.append("source worktree is dirty; check out a clean commit")

    def _check_baseline_sums(self) -> list[str]:
        a = self.args
        sums = a.baseline / "SHA256SUMS"
        if not sums.is_file():
            return [f"baseline SHA256SUMS not found: {sums}"]
        errors: list[str] = []
        actual = sha256_file(sums)
        if actual != a.baseline_sums_sha256:
            errors.append(
                f"baseline SHA256SUMS hash {actual} does not match the expected "
                f"{a.baseline_sums_sha256}"
            )
            return errors
        for line in sums.read_text(encoding="utf-8").splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            want, name = parts[0], parts[1].strip().lstrip("*")
            path = a.baseline / name
            if not path.is_file():
                errors.append(f"baseline SHA256SUMS names a missing file: {name}")
            elif sha256_file(path) != want:
                errors.append(f"baseline file does not match SHA256SUMS: {name}")
        return errors

    def check_tooling(self) -> list[str]:
        """Fail clearly when the pinned toolchain or a target is missing."""
        errors: list[str] = []
        for tool in ("cargo", "rustc", "llvm-readelf", "llvm-objcopy"):
            if shutil.which(tool) is None:
                errors.append(f"required tool not found: {tool}")
        toolchain = self.args.source / "rust-toolchain.toml"
        if not toolchain.is_file():
            return errors
        try:
            data = tomllib.loads(toolchain.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError) as exc:
            return errors + [f"could not read rust-toolchain.toml: {exc}"]
        spec = data.get("toolchain", {})
        channel = spec.get("channel")
        if not channel:
            return errors + ["rust-toolchain.toml has no channel"]
        probe = self.runner.run(
            ["rustup", "run", channel, "rustc", "-vV"], self.args.source, self.env
        )
        if probe.returncode != 0:
            errors.append(f"pinned toolchain {channel} is not installed")
            return errors
        targets = spec.get("targets") or []
        if not targets:
            return errors
        installed = self.runner.run(
            ["rustup", "target", "list", "--installed", "--toolchain", channel],
            self.args.source,
            self.env,
        )
        if installed.returncode != 0:
            errors.append(f"could not list the targets of toolchain {channel}")
            return errors
        have = set(installed.output.split())
        for target in targets:
            if target not in have:
                errors.append(f"target {target} is not installed for {channel}")
        return errors

    # -- matrix ------------------------------------------------------------

    def run_matrix(self) -> MatrixResult:
        old = [
            self.build_bt0(
                "old-" + (set_name.replace(" ", "+") or "default"),
                None,
                set_name.split(),
                no_default=True,
                section="old",
                baseline_required=True,
            )
            for set_name in OLD_SETS
        ]
        new = [
            self.build_bt0(
                tag,
                profile,
                list(features),
                no_default=False,
                section="new",
                baseline_required=baseline_required,
            )
            for tag, profile, features, baseline_required in NEW_ENTRIES
        ]
        lab = [
            self.build_bt0(
                tag,
                None,
                list(features),
                no_default=True,
                section="lab",
                baseline_required=False,
            )
            for tag, features in LAB_ENTRIES
        ]
        main = [
            self.build_main(set_name.replace(" ", "+") or "none", set_name.split())
            for set_name in MAIN_SETS
        ]
        builds = [*old, *new, *lab, *main]
        failures = [build.tag for build in builds if not build.ok]
        main_ok = sum(build.ok for build in main)
        main_identical = sum(
            build.ok and build.baseline == BASELINE_SAME for build in main
        )
        self._write_sha256sums()
        return MatrixResult(
            ok=matrix_ok(failures, len(main), main_ok, main_identical),
            old_total=len(old),
            old_ok=sum(build.ok for build in old),
            old_identical=sum(
                build.ok and build.baseline == BASELINE_SAME for build in old
            ),
            old_differ=sum(
                build.ok and build.baseline.startswith("DIFFERS") for build in old
            ),
            new_total=len(new),
            new_ok=sum(build.ok for build in new),
            new_identical=sum(
                build.ok and build.baseline == BASELINE_SAME for build in new
            ),
            new_differ=sum(
                build.ok and build.baseline.startswith("DIFFERS") for build in new
            ),
            new_nobaseline=sum(
                1 for tag, _profile, _features, required in NEW_ENTRIES if not required
            ),
            lab_total=len(lab),
            lab_ok=sum(build.ok for build in lab),
            main_total=len(main),
            main_ok=main_ok,
            main_identical=main_identical,
            failures=failures,
            builds=builds,
        )

    def _write_sha256sums(self) -> None:
        out_dir = self.args.out / "matrix" / "out"
        lines = [
            f"{sha256_file(path)}  {path.name}\n"
            for path in sorted(out_dir.glob("*.bin"))
        ]
        (out_dir / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")

    def _cargo_bt0(self, features: list[str], no_default: bool) -> list[str]:
        argv = ["cargo", "build", "--offline", "--locked", "--release"]
        if no_default:
            argv.append("--no-default-features")
        if features:
            argv += ["--features", " ".join(features)]
        return argv

    def build_bt0(
        self,
        tag: str,
        profile: str | None,
        features: list[str],
        no_default: bool,
        section: str,
        baseline_required: bool,
    ) -> BuildResult:
        env = dict(self.env)
        if profile:
            env["A7A_PROFILE"] = profile
        env["CARGO_TARGET_DIR"] = str(self.args.out / "target" / "bt0")
        log = self.args.out / "matrix" / "logs" / f"bt0-{tag}.log"
        res = self.runner.run(
            self._cargo_bt0(features, no_default), self.args.source / BT0_DIR, env, log
        )
        if res.returncode != 0:
            return BuildResult(
                tag,
                section,
                False,
                "build failed",
                detail=f"cargo exit {res.returncode}",
            )
        elf = (
            self.args.out
            / "target"
            / "bt0"
            / "armv7a-none-eabi"
            / "release"
            / "oreboot-cubie-a7a-bt0"
        )
        if not elf.is_file():
            return BuildResult(
                tag, section, False, "build failed", detail=f"missing ELF {elf}"
            )
        warnings = self._count_warnings(log)
        readelf_log = self.args.out / "matrix" / "logs" / f"bt0-{tag}-readelf.log"
        readelf = self.runner.run(
            ["llvm-readelf", "-S", "-W", str(elf)],
            self.args.source / BT0_DIR,
            env,
            readelf_log,
        )
        if readelf.returncode != 0:
            return BuildResult(
                tag, section, False, "build failed", detail="llvm-readelf failed"
            )
        has_dram = has_section(readelf.output, ".dram")
        has_phyfw = has_section(readelf.output, ".phyfw")
        bin_path = self.args.out / "matrix" / "out" / f"bt0-{tag}.bin"
        strip_argv = ["llvm-objcopy", "-O", "binary"]
        if has_dram:
            strip_argv.append("--remove-section=.dram")
        if has_phyfw:
            strip_argv.append("--remove-section=.phyfw")
        strip_argv += [str(elf), str(bin_path)]
        strip_log = self.args.out / "matrix" / "logs" / f"bt0-{tag}-objcopy.log"
        strip = self.runner.run(strip_argv, self.args.source / BT0_DIR, env, strip_log)
        if strip.returncode != 0 or not bin_path.is_file():
            return BuildResult(
                tag, section, False, "build failed", detail="llvm-objcopy failed"
            )
        ext_path: Path | None = None
        if has_dram or has_phyfw:
            ext_path = self.args.out / "matrix" / "out" / f"bt0-{tag}-ext.bin"
            ext_section = ".dram" if has_dram else ".phyfw"
            ext_log = self.args.out / "matrix" / "logs" / f"bt0-{tag}-ext-objcopy.log"
            ext = self.runner.run(
                [
                    "llvm-objcopy",
                    "-O",
                    "binary",
                    f"--only-section={ext_section}",
                    str(elf),
                    str(ext_path),
                ],
                self.args.source / BT0_DIR,
                env,
                ext_log,
            )
            if (
                ext.returncode != 0
                or not ext_path.is_file()
                or ext_path.stat().st_size == 0
            ):
                return BuildResult(
                    tag,
                    section,
                    False,
                    "build failed",
                    detail=f"extension {ext_section} missing or empty",
                    warnings=warnings,
                )
        image_error = self._validate_bt0_image(features, bin_path)
        if image_error is not None:
            return BuildResult(
                tag,
                section,
                False,
                "invalid image",
                detail=image_error,
                warnings=warnings,
            )
        baseline, detail = self._compare_baseline(
            f"bt0-{tag}", bin_path, ext_path, baseline_required
        )
        if baseline == "missing baseline":
            return BuildResult(
                tag, section, False, baseline, detail=detail, warnings=warnings
            )
        return BuildResult(
            tag,
            section,
            True,
            baseline,
            size=bin_path.stat().st_size,
            warnings=warnings,
            detail=detail,
        )

    def _validate_bt0_image(self, features: list[str], bin_path: Path) -> str | None:
        size = bin_path.stat().st_size
        if size == 0:
            return "primary image is empty"
        limit = FEL_MAX if "fel" in features else EGON_MAX
        if size > limit:
            return f"primary image is {size:#x} bytes, over the {limit:#x} limit"
        if "fel" not in features:
            return check_egon_header(bin_path.read_bytes())
        return None

    def build_main(self, tag: str, features: list[str]) -> BuildResult:
        argv = [
            "cargo",
            "build",
            "--offline",
            "--locked",
            "--release",
            "--no-default-features",
        ]
        if features:
            argv += ["--features", " ".join(features)]
        env = dict(self.env)
        env["CARGO_TARGET_DIR"] = str(self.args.out / "target" / "main")
        log = self.args.out / "matrix" / "logs" / f"main-{tag}.log"
        res = self.runner.run(argv, self.args.source / MAIN_DIR, env, log)
        if res.returncode != 0:
            return BuildResult(
                "main-" + tag,
                "main",
                False,
                "build failed",
                detail=f"cargo exit {res.returncode}",
            )
        elf = (
            self.args.out
            / "target"
            / "main"
            / "aarch64-unknown-none-softfloat"
            / "release"
            / "oreboot-cubie-a7a-main"
        )
        if not elf.is_file():
            return BuildResult(
                "main-" + tag,
                "main",
                False,
                "build failed",
                detail=f"missing ELF {elf}",
            )
        bin_path = self.args.out / "matrix" / "out" / f"main-{tag}.bin"
        copy_log = self.args.out / "matrix" / "logs" / f"main-{tag}-objcopy.log"
        copy = self.runner.run(
            ["llvm-objcopy", "-O", "binary", str(elf), str(bin_path)],
            self.args.source / MAIN_DIR,
            env,
            copy_log,
        )
        if copy.returncode != 0 or not bin_path.is_file():
            return BuildResult(
                "main-" + tag,
                "main",
                False,
                "build failed",
                detail="llvm-objcopy failed",
            )
        warnings = self._count_warnings(log)
        image_error = self._validate_main_image(bin_path)
        if image_error is not None:
            return BuildResult(
                "main-" + tag,
                "main",
                False,
                "invalid image",
                detail=image_error,
                warnings=warnings,
            )
        baseline, detail = self._compare_baseline(f"main-{tag}", bin_path, None, True)
        if baseline == "missing baseline":
            return BuildResult(
                "main-" + tag,
                "main",
                False,
                baseline,
                detail=detail,
                warnings=warnings,
            )
        return BuildResult(
            "main-" + tag,
            "main",
            True,
            baseline,
            size=bin_path.stat().st_size,
            warnings=warnings,
            detail=detail,
        )

    def _validate_main_image(self, bin_path: Path) -> str | None:
        size = bin_path.stat().st_size
        if size == 0:
            return "main image is empty"
        if self.main_max is None:
            return "MAIN_MAX_SIZE is not known"
        if size > self.main_max:
            return f"main image is {size:#x} bytes, over MAIN_MAX {self.main_max:#x}"
        return None

    def _compare_baseline(
        self,
        stem: str,
        bin_path: Path,
        ext_path: Path | None,
        required: bool,
    ) -> tuple[str, str]:
        base_bin = self.args.baseline / f"{stem}.bin"
        if not base_bin.is_file():
            if required:
                return (
                    "missing baseline",
                    f"required baseline image missing: {base_bin}",
                )
            return BASELINE_NEW, "no historical baseline"
        same = filecmp.cmp(base_bin, bin_path, shallow=False)
        detail = ""
        if ext_path is not None:
            base_ext = self.args.baseline / f"{stem}-ext.bin"
            if not base_ext.is_file():
                return (
                    "missing baseline",
                    f"required baseline ext image missing: {base_ext}",
                )
            if not filecmp.cmp(base_ext, ext_path, shallow=False):
                same = False
                detail = " (ext differs)"
        if same:
            return BASELINE_SAME, ""
        return "DIFFERS from base", f"size {bin_path.stat().st_size}{detail}"

    def _count_warnings(self, log: Path) -> int:
        if not log.is_file():
            return 0
        entries: list[tuple[str, str | None]] = []
        message: str | None = None
        location: str | None = None
        for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
            match = WARNING_RE.match(line)
            if match:
                if message is not None:
                    entries.append((message, location))
                text = match.group(1).strip()
                if WARNING_SUMMARY_RE.match(text) or re.match(
                    r"^generated\s+\d+\s+warnings?$", text
                ):
                    message = None
                    location = None
                    continue
                message = text
                location = None
                continue
            found = WARNING_LOCATION_RE.match(line)
            if found and message is not None:
                location = f"{found.group(1)}:{found.group(2)}:{found.group(3)}"
        if message is not None:
            entries.append((message, location))
        for text, where in entries:
            key = text if where is None else f"{text} --> {where}"
            self.warnings[key] = self.warnings.get(key, 0) + 1
        return len(entries)

    # -- negative contract -------------------------------------------------

    def run_negative(self) -> NegativesResult:
        results: list[NegativeResult] = []
        for tag, features, no_default, expected in NEGATIVE_ENTRIES:
            env = dict(self.env)
            env["CARGO_TARGET_DIR"] = str(self.args.out / "target" / "negative")
            argv = ["cargo", "build", "--offline", "--locked", "--release"]
            if no_default:
                argv.append("--no-default-features")
            argv += ["--features", " ".join(features)]
            log = self.args.out / "matrix" / "logs" / f"negative-{tag}.log"
            res = self.runner.run(argv, self.args.source / BT0_DIR, env, log)
            ok, detail = negative_contract_ok(res.returncode, res.output, expected)
            results.append(
                NegativeResult(
                    tag, ok, res.returncode, expected, expected in res.output, detail
                )
            )
        return NegativesResult(all(result.ok for result in results), results)

    # -- host suites -------------------------------------------------------

    def host_triple(self) -> str | None:
        if not self._host_checked:
            self._host_checked = True
            res = self.runner.run(["rustc", "-vV"], self.args.source, self.env)
            match = re.search(r"^host: (\S+)", res.output, re.M)
            self._host = match.group(1) if match and res.returncode == 0 else None
        return self._host

    def _expected_test_binaries(
        self, host: str, cwd: Path, env: dict[str, str]
    ) -> tuple[list[str], str]:
        log = self.args.out / "tests" / (cwd.name + "-no-run.log")
        res = self.runner.run(
            [
                "cargo",
                "test",
                "--offline",
                "--locked",
                "--no-run",
                "--message-format=json",
                "--target",
                host,
            ],
            cwd,
            env,
            log,
        )
        if res.returncode != 0:
            return [], f"cargo test --no-run exited {res.returncode}"
        executables: list[str] = []
        for line in res.output.splitlines():
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if message.get("reason") != "compiler-artifact":
                continue
            executable = message.get("executable")
            if executable and message.get("target", {}).get("test"):
                executables.append(str(executable))
        return executables, ""

    def run_suites(self) -> SuitesResult:
        host = self.host_triple()
        if host is None:
            return SuitesResult(
                False,
                [
                    SuiteResult(
                        "<host>",
                        False,
                        0,
                        0,
                        0,
                        0,
                        0,
                        "could not determine the rustc host triple",
                    )
                ],
            )
        results = []
        for rel in SUITE_DIRS:
            cwd = self.args.source / rel
            if not cwd.is_dir():
                results.append(
                    SuiteResult(rel, False, 0, 0, 0, 0, 0, "suite directory missing")
                )
                continue
            env = dict(self.env)
            env["CARGO_TARGET_DIR"] = str(self.args.out / "target" / "test")
            expected, inventory_error = self._expected_test_binaries(host, cwd, env)
            log = self.args.out / "tests" / (rel.replace("/", "-") + ".log")
            res = self.runner.run(
                ["cargo", "test", "--offline", "--locked", "--target", host],
                cwd,
                env,
                log,
            )
            passed, failed, ignored, parsed = parse_test_results(res.output)
            run_paths = parse_running_paths(res.output)
            expected_set, run_set = set(expected), set(run_paths)
            inventory_ok = expected_set == run_set
            ok = (
                res.returncode == 0
                and parsed
                and failed == 0
                and passed > 0
                and inventory_ok
                and not inventory_error
            )
            detail = (
                f"exit {res.returncode}; passed {passed}, failed {failed}, "
                f"ignored {ignored}; binaries expected {len(expected_set)}, "
                f"run {len(run_set)}"
            )
            if inventory_error:
                detail += f"; inventory error: {inventory_error}"
            if not parsed:
                detail += "; no 'test result:' line found"
            if parsed and passed == 0:
                detail += "; no executed test"
            if not inventory_ok:
                missing = sorted(expected_set - run_set)
                extra = sorted(run_set - expected_set)
                if missing:
                    detail += "; missing binaries: " + ", ".join(missing)
                if extra:
                    detail += "; unexpected binaries: " + ", ".join(extra)
            results.append(
                SuiteResult(
                    rel,
                    ok,
                    passed,
                    failed,
                    ignored,
                    len(expected_set),
                    len(run_set),
                    detail,
                )
            )
        return SuitesResult(all(result.ok for result in results), results)

    # -- external gate -----------------------------------------------------

    def run_gate(self) -> GateResult:
        argv = [
            sys.executable,
            "-I",
            str(self.args.gate),
            str(self.args.source),
            self.gate_base or "",
            self.gate_head or "",
        ]
        log = self.args.out / "gate.log"
        res = self.runner.run(argv, self.args.source, self.env, log)
        return GateResult(res.returncode == 0, res.returncode, res.output)

    # -- retained default digests -----------------------------------------

    def check_digests(self) -> DigestsResult:
        results = []
        for name in DIGEST_NAMES:
            expected = self.args.expected_digests.get(name)
            path = self.args.out / "matrix" / "out" / f"bt0-{name}.bin"
            if expected is None or not path.is_file():
                results.append(DigestResult(name, expected, None, False))
                continue
            actual = sha256_file(path)
            results.append(DigestResult(name, expected, actual, actual == expected))
        return DigestsResult(all(result.ok for result in results), results)

    # -- source unchanged after the build ---------------------------------

    def verify_source_unchanged(self) -> list[str]:
        errors: list[str] = []
        head = self.runner.run(
            ["git", "-C", str(self.args.source), "rev-parse", "HEAD"],
            self.args.source,
            self.env,
        )
        if head.returncode != 0:
            errors.append("could not read the source HEAD after the build")
        elif self.source_head is not None and head.output.strip() != self.source_head:
            errors.append(
                f"source HEAD changed during the run: {head.output.strip()} "
                f"(was {self.source_head})"
            )
        status = self.runner.run(
            ["git", "-C", str(self.args.source), "status", "--porcelain"],
            self.args.source,
            self.env,
        )
        if status.returncode != 0:
            errors.append("could not read the source worktree status after the build")
        elif status.output.strip():
            errors.append("source worktree is dirty after the build")
        return errors

    # -- report and entry --------------------------------------------------

    def print_report(
        self,
        matrix: MatrixResult,
        negative: NegativesResult,
        suites: SuitesResult,
        gate: GateResult,
        digests: DigestsResult,
    ) -> None:
        a = self.args
        print("=== A7A bt0/main host verification ===")
        print(f"source: {a.source}")
        print(f"source HEAD: {self.source_head} (expected {a.source_sha})")
        print(f"gate base: {self.gate_base}  head: {self.gate_head}")
        print()
        print("=== matrix ===")
        print(
            f"OLD: {matrix.old_ok}/{matrix.old_total} built; "
            f"identical to base {matrix.old_identical}, differ {matrix.old_differ}"
        )
        print(
            f"NEW: {matrix.new_ok}/{matrix.new_total} built; "
            f"identical to base {matrix.new_identical}, differ {matrix.new_differ}, "
            f"no baseline {matrix.new_nobaseline}"
        )
        print(f"LAB: {matrix.lab_ok}/{matrix.lab_total} built; no historical baseline")
        positive = matrix.old_ok + matrix.new_ok + matrix.lab_ok
        positive_total = matrix.old_total + matrix.new_total + matrix.lab_total
        print(f"positive bt0: {positive}/{positive_total}")
        print(
            f"main: {matrix.main_ok}/{matrix.main_total} built; "
            f"identical to base {matrix.main_identical}"
        )
        if matrix.failures:
            print("failed builds: " + ", ".join(matrix.failures))
        print()
        print("=== warnings (reported, not suppressed) ===")
        if self.warnings:
            print(f"total warning lines: {sum(self.warnings.values())}")
            for line, count in sorted(
                self.warnings.items(), key=lambda item: (-item[1], item[0])
            ):
                print(f"  {count:4d}  {line}")
        else:
            print("none")
        print()
        print("=== negative feature-contract checks ===")
        for result in negative.results:
            print(
                f"{result.tag}: exit {result.returncode} (expected nonzero); "
                f"diagnostic "
                f"{'found' if result.diagnostic_found else 'NOT FOUND'}; "
                f"{result.detail}"
            )
        print()
        print("=== host suites ===")
        for result in suites.results:
            print(
                f"{result.directory}: ok={result.ok}; passed {result.passed}, "
                f"failed {result.failed}, ignored {result.ignored} "
                f"({result.detail})"
            )
        print()
        print("=== external gate ===")
        print(f"exit: {gate.returncode}")
        print(gate.output.rstrip())
        print()
        print("=== default digests ===")
        for result in digests.results:
            state = "match" if result.ok else "MISMATCH"
            print(
                f"{result.name}: {state} expected {result.expected} "
                f"actual {result.actual}"
            )

    def run(self) -> int:
        errors = self.check_paths()
        if errors:
            print("path checks failed:")
            for error in errors:
                print(f"  - {error}")
            print("VERDICT: FAIL")
            return 1
        matrix = self.run_matrix()
        negative = self.run_negative()
        suites = self.run_suites()
        gate = self.run_gate()
        digests = self.check_digests()
        post = self.verify_source_unchanged()
        self.print_report(matrix, negative, suites, gate, digests)
        if post:
            print("source changed during the run:")
            for error in post:
                print(f"  - {error}")
        ok = (
            matrix.ok
            and negative.ok
            and suites.ok
            and gate.ok
            and digests.ok
            and not post
        )
        print(f"VERDICT: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1


def _digest_arg(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError(
            f"--expect-digest wants NAME=SHA256: {value!r}"
        )
    name, sha = value.split("=", 1)
    if name not in DIGEST_NAMES:
        raise argparse.ArgumentTypeError(
            f"unknown digest name {name!r}; expected one of {', '.join(DIGEST_NAMES)}"
        )
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
        raise argparse.ArgumentTypeError(
            f"digest for {name} is not a 64-digit SHA256: {sha!r}"
        )
    return name, sha.lower()


def _sha256_arg(value: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise argparse.ArgumentTypeError(f"expected a 64-digit SHA256: {value!r}")
    return value.lower()


def parse_args(argv: list[str] | None = None) -> Config:
    parser = argparse.ArgumentParser(
        description="A7A bt0/main host verification matrix, suites, gate and digests."
    )
    parser.add_argument("--source", required=True, help="oreboot checkout")
    parser.add_argument(
        "--source-sha",
        required=True,
        help="expected source HEAD (the exact revision under test)",
    )
    parser.add_argument("--base", required=True, help="gate base revision")
    parser.add_argument(
        "--baseline", required=True, help="retained matrix baseline directory"
    )
    parser.add_argument(
        "--baseline-sums-sha256",
        required=True,
        type=_sha256_arg,
        help="SHA256 of the retained baseline SHA256SUMS manifest",
    )
    parser.add_argument("--dram-lib", required=True, help="libdram-a733.a build input")
    parser.add_argument(
        "--phyfw-obj", required=True, help="PHY firmware object build input"
    )
    parser.add_argument(
        "--gate", required=True, help="external publication gate script"
    )
    parser.add_argument("--out", required=True, help="fresh job output directory")
    parser.add_argument(
        "--expect-digest",
        action="append",
        default=[],
        type=_digest_arg,
        metavar="NAME=SHA256",
        help="retained default-image SHA256 (repeat for the four names)",
    )
    ns = parser.parse_args(argv)
    return Config(
        source=Path(ns.source).resolve(),
        source_sha=ns.source_sha,
        base=ns.base,
        baseline=Path(ns.baseline).resolve(),
        baseline_sums_sha256=ns.baseline_sums_sha256,
        dram_lib=Path(ns.dram_lib).resolve(),
        phyfw_obj=Path(ns.phyfw_obj).resolve(),
        gate=Path(ns.gate).resolve(),
        out=Path(ns.out).resolve(),
        expected_digests=dict(ns.expect_digest),
    )


def validate_args(args: Config) -> list[str]:
    missing = [name for name in DIGEST_NAMES if name not in args.expected_digests]
    if missing:
        return ["missing required --expect-digest for: " + ", ".join(missing)]
    return []


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    errors = validate_args(args)
    if errors:
        for error in errors:
            print(f"argument error: {error}", file=sys.stderr)
        return 2
    return Harness(args).run()


if __name__ == "__main__":
    sys.exit(main())
