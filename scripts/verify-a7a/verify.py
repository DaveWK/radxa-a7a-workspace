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
        --dram-lib <libdram-a733.a> --dram-lib-sha256 <sha256> \
        --phyfw-obj <libdram-object> --phyfw-obj-sha256 <sha256> \
        --gate <gate.py> --gate-sha256 <sha256> --out <job-output-dir> \
        --expect-digest default=<sha256> \
        --expect-digest default-fel=<sha256> \
        --expect-digest default@2400=<sha256> \
        --expect-digest default-fel@2400=<sha256>

Exit status is 0 only when every stage passes. The job output directory must be
fresh (it is never reused); it holds the build logs, the produced images, the
suite logs, the gate log and a SHA256SUMS file. The source checkout is never
written to; cargo targets and TMPDIR stay under the job output directory.

Threat model: prevent false greens from accidents on a single-user bench host:
stale, mixed, truncated or empty inputs and outputs; ambient Git, Cargo or
toolchain configuration; a parent repository mistaken for the source; and a
missing section, binary or test result counted as success. This does not defend
against a malicious local user who can edit the harness.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

BT0_DIR = "src/mainboard/radxa/cubie-a7a/bt0"
MAIN_DIR = "src/mainboard/radxa/cubie-a7a/main"
COMMON_LIB = "src/mainboard/radxa/cubie-a7a/common/src/lib.rs"
BT0_BUILD = f"{BT0_DIR}/build.rs"
MKIMAGE = Path(__file__).resolve().parents[1] / "mkimage.py"
TRACKED_PATH_TYPES = {
    "100644": stat.S_IFREG,
    "100755": stat.S_IFREG,
    "120000": stat.S_IFLNK,
    "160000": stat.S_IFDIR,
}

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
DOC_TESTS = dict(
    zip(
        SUITE_DIRS,
        (
            "cubie_a7a_dram",
            "cubie_a7a_fastboot",
            "cubie_a7a_common",
            "bootlog",
            "dram_train",
        ),
        strict=True,
    )
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

# LAB: entries with no historical baseline. Without bl-mission the lab uses
# the open backend and the runtime-staged PHY firmware.
LAB_ENTRIES = (
    ("lab-dram", ("dram-lab",)),
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
    (
        "dram-lab+phyfw",
        ("dram-lab", "phyfw"),
        True,
        "the package 'oreboot-cubie-a7a-bt0' does not contain this feature: phyfw",
    ),
)

BASELINE_SAME = "= base"
BASELINE_NEW = "no baseline (new)"

TEST_RESULT_RE = re.compile(
    r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"0 measured; 0 filtered out; finished in [0-9.]+s"
)
SECTION_RE = re.compile(
    r"^\s*\[\s*\d+\]\s+(\.dram|\.phyfw)\s+(\S+)\s+([0-9a-fA-F]+)\s+"
    r"[0-9a-fA-F]+\s+([0-9a-fA-F]+)[^\S\n]+([^\n]*)$",
    re.M,
)
SECTION_COUNT_RE = re.compile(r"^There are (\d+) section headers,", re.M)
SECTION_ROW_RE = re.compile(r"^\s*\[\s*\d+\]", re.M)
MAIN_MAX_RE = re.compile(
    r"^\s*pub const MAIN_MAX_SIZE:\s*usize\s*=\s*(0x[0-9A-Fa-f_]+|\d[\d_]*)\s*;",
    re.M,
)
FEL_MAX_RE = re.compile(
    r'^const MEMORY_FEL: &str = "SRAM\s*:\s*ORIGIN\s*=\s*0x[0-9A-Fa-f_]+,'
    r'\s*LENGTH\s*=\s*(0x[0-9A-Fa-f_]+|\d[\d_]*)";$',
    re.M,
)
SUM_LINE_RE = re.compile(r"([0-9A-Fa-f]{64}) [ *]([A-Za-z0-9@+._-]+\.bin)")
WARNING_RE = re.compile(r"^warning: (.*)$")
WARNING_SUMMARY_RE = re.compile(r"^`[^`]+`\s+\(.*\)\s+generated\s+\d+\s+warnings?")
WARNING_LOCATION_RE = re.compile(r"^\s*-->\s*(\S+?):(\d+):(\d+)\s*$")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
    stdout: str
    stderr: str = ""

    @property
    def output(self) -> str:
        """Human-readable aggregate only; never parse it as a protocol."""
        return self.stdout + self.stderr


@dataclass
class BuildResult:
    tag: str
    section: str
    ok: bool
    baseline: str
    size: int | None = None
    warnings: int = 0
    detail: str = ""
    extensions: dict[str, int] = field(default_factory=dict)


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
    dram_lib_sha256: str
    phyfw_obj: Path
    phyfw_obj_sha256: str
    gate: Path
    gate_sha256: str
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
        # NUL-delimited Git output carries arbitrary filesystem names, not text
        # lines. Preserve their bytes and line endings for lstat().
        git_paths = argv[0] == "git" and "-z" in argv
        try:
            proc = subprocess.run(
                argv,
                cwd=str(cwd),
                env=env,
                capture_output=True,
                text=not git_paths,
                errors=None if git_paths else "replace",
            )
            if git_paths:
                stdout, stderr = os.fsdecode(proc.stdout), os.fsdecode(proc.stderr)
            else:
                stdout, stderr = proc.stdout, proc.stderr
            returncode = proc.returncode
        except FileNotFoundError as exc:
            stdout, stderr = "", f"{argv[0]}: {exc}\n"
            returncode = 127
        except OSError as exc:
            stdout, stderr = "", f"{argv[0]}: {exc}\n"
            returncode = 126
        if log is not None:
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(
                f"=== stdout ===\n{stdout}\n=== stderr ===\n{stderr}", encoding="utf-8"
            )
        return CommandResult(tuple(argv), str(cwd), returncode, stdout, stderr)


def git_env() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(Path.home()),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def expected_sections(features: list[str], no_default: bool) -> tuple[str, ...]:
    """Payload section contract from bt0's Cargo.toml, build.rs and dram.rs."""
    selected = set(features)
    dram_lab = "dram-lab" in selected
    # dram-lab and the write variants enable fastboot; fastboot adds DRAM_EXT.
    sections = []
    if selected & {"fastboot", "fastboot-emmc-write", "fastboot-nor-write", "dram-lab"}:
        sections.append(".dram")
    # The linker reserves .phyfw for dram-lab, but only dram/open.rs supplies
    # its statics. bl-mission implies blobless and excludes that backend.
    blobfree = not no_default or bool(selected & {"blobfree", "blobless", "bl-mission"})
    if dram_lab and not blobfree and "dramlib" not in selected:
        sections.append(".phyfw")
    return tuple(sections)


def image_names(stem: str, sections: tuple[str, ...]) -> list[str]:
    # Keep the historical filename when a row has a single extension.
    suffixes = ["-ext"] if len(sections) == 1 else ["-" + s[1:] for s in sections]
    return [f"{stem}{suffix}.bin" for suffix in ("", *suffixes)]


def phyfw_reservation(address: int, size: int, columns: str, build: Path) -> None:
    """Check the FELSRAM NOLOAD reservation against this row's generated index."""
    # llvm-readelf -SW: ES, flags, link, info, alignment.
    fields = columns.split()
    if (
        len(fields) != 5
        or not {"W", "A"}.issubset(fields[1])
        or not fields[-1].isdecimal()
        or int(fields[-1]) < 4
        or address != 0x47000
        or not 0 < size <= 0x5B000 - address
    ):
        raise ValueError("invalid .phyfw FELSRAM reservation")
    # bt0/build.rs::lab_firmware emits LEN from the six extracted images.
    # This intermediate directory is private to this one feature row.
    indices = list(build.rglob("out/phy-fw-lab.rs"))
    if len(indices) != 1:
        raise ValueError("expected one generated PHY firmware index")
    lens = re.search(
        r"^pub const LEN: \[usize; 6\] = \[([0-9]+(?:, [0-9]+){5})\];$",
        indices[0].read_text(encoding="utf-8"),
        re.M,
    )
    lengths = [] if not lens else list(map(int, lens[1].split(", ")))
    if not lengths or min(lengths) <= 0 or size != sum(lengths):
        raise ValueError(".phyfw size differs from the generated PHY firmware index")


ARM_EXCLUSIVE = re.compile(r"(?:ldrex|strex|ldaex|stlex)\w*(?:\.w)?")
A64_ATOMIC = re.compile(
    r"(?:lda?x[rp]|stl?x[rp])[bh]?"
    r"|(?:cas[p]?|swp|(?:ld|st)(?:add|clr|eor|set|smax|smin|umax|umin))[al]*[bh]?"
    r"|(?:ld64b|st64b|st64bv|st64bv0|rcw(?:cas|swp|clr|set)\w*)"
)


def audit_disassembly(text: str, main: bool) -> list[str]:
    """Read llvm-objdump -d -C --no-show-raw-insn, not operands or comments."""
    arch = "elf64-littleaarch64" if main else "elf32-littlearm"
    if not re.search(r"file format " + arch + r"$", text, re.M):
        raise ValueError(f"expected objdump format {arch}")
    symbol = None
    instructions = 0
    hits = []
    for line in text.splitlines():
        if label := re.fullmatch(r"\s*[0-9a-f]+ <(.+)>:", line):
            symbol = label[1]
        elif ins := re.match(r"^\s*([0-9a-f]+):\s+([a-z][\w.]*)\b", line):
            instructions += 1
            if (A64_ATOMIC if main else ARM_EXCLUSIVE).fullmatch(ins[2]):
                hits.append(f"{symbol or '<unnamed>'} 0x{ins[1]} {ins[2]}")
    if not instructions:
        raise ValueError("objdump decoded no instructions")
    return hits


def required_baseline_names() -> list[str]:
    names = []
    for set_name in OLD_SETS:
        tag = "old-" + (set_name.replace(" ", "+") or "default")
        names.extend(
            image_names(f"bt0-{tag}", expected_sections(set_name.split(), True))
        )
    for tag, _profile, features, baseline_required in NEW_ENTRIES:
        if baseline_required:
            names.extend(
                image_names(f"bt0-{tag}", expected_sections(list(features), False))
            )
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
    if not diagnostic_found(output, expected):
        return False, "build failed without the expected diagnostic"
    return True, "expected diagnostic found"


def diagnostic_found(stderr: str, expected: str) -> bool:
    return f"error: {expected}" in stderr.splitlines()


def completed_test_result(stdout: str) -> tuple[bool, int, int, int] | None:
    lines = [line for line in stdout.splitlines() if line.startswith("test result:")]
    match = TEST_RESULT_RE.fullmatch(lines[0]) if len(lines) == 1 else None
    if match is None:
        return None
    status, passed, failed, ignored = match.groups()
    return status == "ok", int(passed), int(failed), int(ignored)


def read_cap(path: Path, pattern: re.Pattern[str]) -> int:
    matches = pattern.findall(path.read_text(encoding="utf-8"))
    if len(matches) != 1 or (value := int(matches[0], 0)) <= 0:
        raise ValueError(f"expected one positive limit in {path}")
    return value


def raise_walk_error(error: OSError) -> None:
    raise error


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
        self.git_env = git_env()
        self.env = {
            **self.git_env,
            "CARGO_HOME": str(args.out / "cargo-home"),
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TERM_COLOR": "never",
            "RUSTUP_AUTO_INSTALL": "0",
            "TMPDIR": str(args.out / "tmp"),
        }
        self.input_paths = {
            label: args.out / "inputs" / filename
            for label, filename in (
                ("dram-lib", "libdram-a733.a"),
                ("phyfw-obj", "phyfw.o"),
                ("gate", "gate.py"),
            )
        }
        self.input_digests: dict[str, str] = {}
        self.input_formats: dict[str, str] = {}
        self.env.update(
            A733_DRAM_LIB=str(self.input_paths["dram-lib"]),
            A733_PHY_FW_OBJ=str(self.input_paths["phyfw-obj"]),
        )
        self.workspace = MKIMAGE.parents[1]
        self.protected = self.protected_inputs()
        self.source_head: str | None = None
        self.workspace_head: str | None = None
        self.gate_base: str | None = None
        self.gate_head: str | None = None
        self.baseline_digests: dict[str, str] = {}
        self.image_digests: dict[str, str] = {}
        self.media_max: int | None = None
        self.media_pad: int | None = None
        self.fel_max: int | None = None
        self.main_max: int | None = None
        self.warnings: dict[str, int] = {}
        self._host: str | None = None
        self.toolchain: dict[str, str] = {}
        self.cargo = "cargo"

    # -- fail-closed path checks ------------------------------------------

    def protected_inputs(self) -> tuple[tuple[str, Path], ...]:
        a = self.args
        return (
            ("workspace", self.workspace),
            ("source", a.source),
            ("baseline", a.baseline),
            ("dram-lib", a.dram_lib),
            ("phyfw-obj", a.phyfw_obj),
            ("gate", a.gate),
            ("host Cargo cache", (Path.home() / ".cargo").resolve()),
        )

    def check_paths(self) -> list[str]:
        a = self.args
        errors: list[str] = []
        # Overlap first: nothing is created when the job would write into a
        # protected input.
        out = a.out.resolve()
        for label, path in self.protected:
            if paths_overlap(out, path):
                errors.append(f"output directory overlaps the {label}: {path}")
        if errors:
            return errors
        if a.out.exists() or a.out.is_symlink():
            return [f"output path already exists: {a.out}"]
        if not a.out.parent.is_dir():
            return [f"output parent directory not found: {a.out.parent}"]
        if not a.source.is_dir():
            errors.append(f"source directory not found: {a.source}")
        else:
            self._check_source(errors)
            for rel in (BT0_DIR, MAIN_DIR, *SUITE_DIRS):
                path = a.source / rel
                if not path.is_dir() or not path.resolve().is_relative_to(a.source):
                    errors.append(f"required source directory missing: {rel}")
            try:
                self.read_limits()
            except (OSError, ValueError, SyntaxError) as exc:
                errors.append(f"could not read image caps: {exc}")
            errors.extend(self.check_cargo_config())
        errors.extend(self.check_workspace())
        if not a.baseline.is_dir():
            errors.append(f"baseline directory not found: {a.baseline}")
        else:
            errors.extend(self._check_baseline_sums())
        return errors

    def snapshot_inputs(self, destination: Path) -> None:
        a = self.args
        destination.mkdir(mode=0o700)
        for label, original, expected in (
            ("dram-lib", a.dram_lib, a.dram_lib_sha256),
            ("phyfw-obj", a.phyfw_obj, a.phyfw_obj_sha256),
            ("gate", a.gate, a.gate_sha256),
        ):
            snapshot = destination / self.input_paths[label].name
            digest = hashlib.sha256()
            # Don't hang on a FIFO accidentally passed as an input. Check the
            # descriptor that supplies the bytes, not a prior stat of the path.
            fd = os.open(original, os.O_RDONLY | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as src:
                if not stat.S_ISREG(os.fstat(src.fileno()).st_mode):
                    raise ValueError(f"{label} is not a regular file: {original}")
                with snapshot.open("xb") as dst:
                    while chunk := src.read(1024 * 1024):
                        digest.update(chunk)
                        dst.write(chunk)
            actual = digest.hexdigest()
            if actual != expected:
                raise ValueError(f"{label} SHA256 {actual} does not match {expected}")
            with snapshot.open("rb") as src:
                magic = src.read(8)
                src.seek(0)
                if hashlib.file_digest(src, "sha256").hexdigest() != actual:
                    raise ValueError(f"{label} snapshot SHA256 changed: {snapshot}")
            if label in ("dram-lib", "phyfw-obj"):
                if magic == b"!<arch>\n":
                    self.input_formats[label] = "normal ar archive"
                elif magic == b"!<thin>\n":
                    raise ValueError(
                        f"{label} snapshot is a thin ar archive; external members "
                        "are not pinned"
                    )
                elif label == "phyfw-obj" and magic.startswith(b"\x7fELF"):
                    self.input_formats[label] = "ELF object"
                else:
                    formats = "a normal ar archive"
                    if label == "phyfw-obj":
                        formats += " or an ELF object"
                    raise ValueError(f"{label} snapshot must be {formats}")
            self.input_digests[label] = actual

    def read_limits(self) -> None:
        # Read integer constants as syntax, not by importing the image builder.
        tree = ast.parse(MKIMAGE.read_bytes(), filename=str(MKIMAGE))
        values = {}
        for name in ("EGON_MAX", "EGON_PAD"):
            matches = [
                node.value.value
                for node in tree.body
                if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
                and isinstance(node.value, ast.Constant)
                and type(node.value.value) is int
            ]
            if len(matches) != 1 or matches[0] <= 0:
                raise ValueError(f"expected one positive {name} in {MKIMAGE}")
            values[name] = matches[0]
        self.media_max, self.media_pad = values["EGON_MAX"], values["EGON_PAD"]
        self.fel_max = read_cap(self.args.source / BT0_BUILD, FEL_MAX_RE)
        self.main_max = read_cap(self.args.source / COMMON_LIB, MAIN_MAX_RE)

    def check_cargo_config(self) -> list[str]:
        a = self.args
        dirs = set(a.source.parents)
        for rel in (BT0_DIR, MAIN_DIR, *SUITE_DIRS):
            dirs.update((a.source / rel, *(a.source / rel).parents))
        errors = []
        for directory in sorted(dirs):
            for name in ("config", "config.toml"):
                path = directory / ".cargo" / name
                if not (path.exists() or path.is_symlink()):
                    continue
                if (
                    not path.is_relative_to(a.source)
                    or not path.is_file()
                    or path.resolve() != path
                    or self.git(
                        "ls-files", "--error-unmatch", "--", str(path)
                    ).returncode
                ):
                    errors.append(
                        f"ambient Cargo configuration would affect the build: {path}"
                    )
        return errors

    def prepare_output(self, staged: Path) -> None:
        out = self.args.out
        out.mkdir(mode=0o700)
        for path in list(staged.iterdir()):
            path.rename(out / path.name)

    def stage_cargo_cache(self, destination: Path) -> None:
        # Cargo's offline cache can still be written to while building. Use
        # copies of the archives, indexes and Git databases, not the host cache
        # or its config, credentials, extracted sources or checked-out trees.
        cache = Path.home() / ".cargo"
        destination.mkdir()
        for rel in ("registry/cache", "registry/index", "git/db"):
            source = cache / rel
            for path in (cache, source.parent, source):
                if path.is_symlink():
                    raise ValueError(f"offline Cargo cache contains a symlink: {path}")
            if source.exists():
                if not source.is_dir():
                    raise ValueError(
                        f"offline Cargo cache is not a directory: {source}"
                    )
                # Copy links as links, never follow them. Reject any link
                # found in the copy before making a job directory visible.
                shutil.copytree(source, destination / rel, symlinks=True)
        for directory, dirs, files in os.walk(destination, onerror=raise_walk_error):
            for name in dirs + files:
                path = Path(directory) / name
                if path.is_symlink():
                    original = cache / path.relative_to(destination)
                    raise ValueError(
                        f"offline Cargo cache contains a symlink: {original}"
                    )

    def cargo_env(self, group: str) -> dict[str, str]:
        # These fixed subpaths are private by construction: check_paths
        # validates output overlap, then prepare_output creates it exclusively.
        return {
            **self.env,
            "CARGO_TARGET_DIR": str(self.args.out / "target" / group),
            "CARGO_BUILD_BUILD_DIR": str(self.args.out / "build" / group),
        }

    def git(self, *argv: str) -> CommandResult:
        return self.tree_git(self.args.source, *argv)

    def tree_git(self, tree: Path, *argv: str) -> CommandResult:
        return self.runner.run(["git", "-C", str(tree), *argv], tree, self.git_env)

    def is_worktree_root(self, tree: Path) -> bool:
        root = self.tree_git(tree, "rev-parse", "--show-toplevel")
        return root.returncode == 0 and root.stdout.rstrip("\n") == str(tree)

    def worktree_error(
        self, tree: Path, label: str, *, allow_gitlinks: bool = False
    ) -> str | None:
        for key in ("core.sparseCheckout", "core.sparseCheckoutCone"):
            setting = self.tree_git(tree, "config", "--type=bool", "--get-all", key)
            if setting.returncode not in (0, 1):
                return f"could not read {label} Git setting {key}"
            if "true" in setting.stdout.splitlines():
                return f"{label} uses sparse checkout ({key})"
        sparse = self.tree_git(
            tree,
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "info/sparse-checkout",
        )
        if sparse.returncode != 0:
            return f"could not locate {label} sparse-checkout configuration"
        try:
            if Path(sparse.stdout.rstrip("\n")).stat().st_size:
                return f"{label} has a non-empty Git info/sparse-checkout"
        except FileNotFoundError:
            pass

        # The combined listing gives us both the index flags and the expected
        # type of each NUL-delimited pathname, without following symlinks.
        tracked = self.tree_git(tree, "ls-files", "-v", "--stage", "-z")
        if tracked.returncode != 0:
            return f"could not list {label} tracked paths"
        for entry in tracked.stdout.split("\0")[:-1]:
            metadata, _, name = entry.partition("\t")
            tag, mode, _oid, stage = metadata.split()
            if tag == "S":
                return f"{label} has a skip-worktree entry: {name!r}"
            if tag.islower():
                return f"{label} has an assume-unchanged entry: {name!r}"
            if stage != "0" or mode not in TRACKED_PATH_TYPES:
                return f"{label} has an unexpected index entry: {name!r}"
            if mode == "160000" and not allow_gitlinks:
                return f"{label} contains a Git submodule (gitlink): {name!r}"
            try:
                actual_type = stat.S_IFMT((tree / name).lstat().st_mode)
            except FileNotFoundError:
                return f"{label} tracked path is missing: {name!r}"
            if actual_type != TRACKED_PATH_TYPES[mode]:
                return f"{label} tracked path has the wrong type: {name!r}"
        deleted = self.tree_git(tree, "ls-files", "--deleted", "-z")
        if deleted.returncode != 0:
            return f"could not list {label} deleted paths"
        if deleted.stdout:
            return f"{label} has deleted tracked paths"
        status = self.tree_git(tree, "status", "--porcelain", "--untracked-files=all")
        if status.returncode != 0:
            return f"could not read the {label} worktree status"
        if status.stdout.strip():
            return f"{label} worktree is dirty"
        return None

    def check_workspace(self) -> list[str]:
        if not self.is_worktree_root(self.workspace):
            return [
                f"workspace is not the root of its own Git worktree: {self.workspace}"
            ]
        head = self.tree_git(self.workspace, "rev-parse", "HEAD")
        if head.returncode != 0:
            return ["could not read the workspace HEAD"]
        actual = head.stdout.strip()
        if self.workspace_head is not None and actual != self.workspace_head:
            return [
                f"workspace HEAD changed during the run: {actual} (was {self.workspace_head})"
            ]
        self.workspace_head = actual
        error = self.worktree_error(self.workspace, "workspace", allow_gitlinks=True)
        return [error] if error else []

    def _check_source(self, errors: list[str]) -> None:
        a = self.args
        if not self.is_worktree_root(a.source):
            errors.append(f"source is not the root of its own git worktree: {a.source}")
            return
        head = self.git("rev-parse", "HEAD")
        if head.returncode != 0:
            errors.append("could not read the source HEAD")
            return
        actual_head = head.stdout.strip()
        if actual_head != a.source_sha.lower():
            errors.append(
                f"source HEAD {actual_head} does not match --source-sha "
                f"{a.source_sha}"
            )
        else:
            self.source_head = actual_head
        base = self.git(
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            f"{a.base}^{{commit}}",
        )
        if base.returncode != 0:
            errors.append(f"base revision not found in source: {a.base}")
            return
        base_sha = base.stdout.strip()
        if self.source_head is None:
            return
        ancestor = self.git("merge-base", "--is-ancestor", base_sha, self.source_head)
        if ancestor.returncode != 0:
            errors.append(
                f"base {base_sha} is not an ancestor of HEAD {self.source_head}"
            )
        else:
            self.gate_base = base_sha
            self.gate_head = self.source_head
        if error := self.worktree_error(a.source, "source"):
            errors.append(error)

    def _check_baseline_sums(self) -> list[str]:
        a = self.args
        sums = a.baseline / "SHA256SUMS"
        if not sums.is_file():
            return [f"baseline SHA256SUMS not found: {sums}"]
        errors: list[str] = []
        data = sums.read_bytes()
        actual = sha256(data)
        if actual != a.baseline_sums_sha256:
            errors.append(
                f"baseline SHA256SUMS hash {actual} does not match the expected "
                f"{a.baseline_sums_sha256}"
            )
            return errors
        manifest: dict[str, str] = {}
        for line in data.decode("ascii").splitlines():
            match = SUM_LINE_RE.fullmatch(line)
            if not match:
                return ["baseline SHA256SUMS contains a malformed line"]
            want, name = match.groups()
            if name in manifest:
                return [f"baseline SHA256SUMS contains a duplicate entry: {name}"]
            manifest[name] = want.lower()
        for name in sorted(set(required_baseline_names()) - manifest.keys()):
            errors.append(f"baseline SHA256SUMS is missing a compared image: {name}")
        for name, want in manifest.items():
            path = a.baseline / name
            if not path.resolve().is_relative_to(a.baseline):
                errors.append(f"baseline image is outside its directory: {name}")
                continue
            if not path.is_file():
                errors.append(f"baseline SHA256SUMS names a missing file: {name}")
                continue
            data = path.read_bytes()
            if not data or sha256(data) != want:
                errors.append(
                    f"baseline file empty or does not match SHA256SUMS: {name}"
                )
        if not errors:
            self.baseline_digests = manifest
        return errors

    def check_tooling(self, tmp: Path) -> list[str]:
        """Fail clearly when the pinned toolchain or a target is missing."""
        errors: list[str] = []
        for tool in ("rustup", "llvm-readelf", "llvm-objcopy"):
            if shutil.which(tool, path=self.env["PATH"]) is None:
                errors.append(f"required tool not found: {tool}")
        toolchain = self.args.source / "rust-toolchain.toml"
        if not toolchain.is_file():
            return errors + ["rust-toolchain.toml is missing"]
        try:
            data = tomllib.loads(toolchain.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError) as exc:
            return errors + [f"could not read rust-toolchain.toml: {exc}"]
        spec = data.get("toolchain", {})
        channel = spec.get("channel")
        if not isinstance(channel, str) or not re.fullmatch(
            r"(?:\d+\.\d+\.\d+|nightly-\d{4}-\d{2}-\d{2})", channel
        ):
            return errors + ["rust-toolchain.toml has no exact channel pin"]
        if errors:
            return errors
        # Resolve in the source, not in the caller's directory. An accidental
        # rustup directory override must not change what will be invoked.
        probe_env = {
            **self.git_env,
            "RUSTUP_AUTO_INSTALL": "0",
            "TMPDIR": str(tmp),
        }
        for tool in ("rustc", "cargo", "rustdoc"):
            resolved = self.runner.run(
                ["rustup", "which", tool], self.args.source, probe_env
            )
            pinned = self.runner.run(
                ["rustup", "which", "--toolchain", channel, tool],
                self.args.source,
                probe_env,
            )
            path = Path(resolved.stdout.strip())
            if (
                resolved.returncode
                or pinned.returncode
                or resolved.stdout != pinned.stdout
                or not path.is_absolute()
                or not path.is_file()
                or not (
                    path.parent.parent.name == channel
                    or path.parent.parent.name.startswith(channel + "-")
                )
            ):
                return [f"source resolves {tool} outside the installed pin {channel}"]
            self.toolchain[tool] = str(path)
        rustc = self.runner.run(
            [self.toolchain["rustc"], "-vV"], self.args.source, probe_env
        )
        cargo = self.runner.run(
            [self.toolchain["cargo"], "-V"], self.args.source, probe_env
        )
        release = re.search(r"^release: (\S+)$", rustc.stdout, re.M)
        cargo_version = re.match(r"^cargo (\S+)", cargo.stdout)
        host = re.search(r"^host: (\S+)$", rustc.stdout, re.M)

        def matches_channel(version: re.Match[str] | None) -> bool:
            return bool(
                version
                and (
                    re.fullmatch(r"\d+\.\d+\.\d+-nightly", version[1])
                    if channel.startswith("nightly-")
                    else version[1] == channel
                )
            )

        if (
            rustc.returncode
            or cargo.returncode
            or not host
            or not all(matches_channel(version) for version in (release, cargo_version))
        ):
            return [f"resolved rustc and cargo versions do not match {channel}"]
        self._host = host[1]
        objdump = (
            Path(self.toolchain["rustc"]).parent.parent
            / "lib"
            / "rustlib"
            / self._host
            / "bin"
            / "llvm-objdump"
        )
        if not objdump.is_file():
            return [f"missing pinned llvm-tools component: {objdump}"]
        self.toolchain["objdump"] = str(objdump)
        self.cargo = self.toolchain["cargo"]
        self.env.update(
            RUSTC=self.toolchain["rustc"], RUSTDOC=self.toolchain["rustdoc"]
        )
        self.toolchain.update(
            channel=channel, rustc_version=rustc.stdout, cargo_version=cargo.stdout
        )
        targets = spec.get("targets") or []
        if not targets:
            return errors
        installed = self.runner.run(
            ["rustup", "target", "list", "--installed", "--toolchain", channel],
            self.args.source,
            probe_env,
        )
        if installed.returncode != 0:
            errors.append(f"could not list the targets of toolchain {channel}")
            return errors
        have = set(installed.stdout.split())
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
            f"{digest}  {name}\n" for name, digest in sorted(self.image_digests.items())
        ]
        (out_dir / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")

    def _cargo_bt0(self, features: list[str], no_default: bool) -> list[str]:
        argv = [self.cargo, "build", "--offline", "--locked", "--release"]
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
        env = self.cargo_env("bt0")
        expected = expected_sections(features, no_default)
        if ".phyfw" in expected:
            env["CARGO_BUILD_BUILD_DIR"] = str(self.args.out / "build" / f"bt0-{tag}")
        if profile:
            env["A7A_PROFILE"] = profile
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
        medium = not {
            "fel",
            "fastboot",
            "fastboot-emmc-write",
            "fastboot-nor-write",
            "dram-lab",
        }.intersection(features)
        return self.export_images(
            f"bt0-{tag}",
            tag,
            section,
            elf,
            self.args.source / BT0_DIR,
            env,
            expected,
            self.media_max if medium else self.fel_max,
            baseline_required,
            self._count_warnings(log),
            media=medium,
        )

    def build_main(self, tag: str, features: list[str]) -> BuildResult:
        argv = [
            self.cargo,
            "build",
            "--offline",
            "--locked",
            "--release",
            "--no-default-features",
        ]
        if features:
            argv += ["--features", " ".join(features)]
        env = self.cargo_env("main")
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
        return self.export_images(
            f"main-{tag}",
            f"main-{tag}",
            "main",
            elf,
            self.args.source / MAIN_DIR,
            env,
            (),
            self.main_max,
            True,
            self._count_warnings(log),
        )

    def export_images(
        self,
        stem: str,
        tag: str,
        row: str,
        elf: Path,
        cwd: Path,
        env: dict[str, str],
        expected: tuple[str, ...],
        limit: int | None,
        required: bool,
        warnings: int,
        *,
        media: bool = False,
    ) -> BuildResult:
        logs = self.args.out / "matrix" / "logs"
        main = row == "main"
        disasm = self.runner.run(
            [
                self.toolchain["objdump"],
                "-d",
                "-C",
                "--no-show-raw-insn",
                "--mattr=+lse" if main else "--mattr=+v8",
                str(elf),
            ],
            cwd,
            env,
        )
        try:
            if disasm.returncode or disasm.stderr.strip():
                raise ValueError(f"objdump exit {disasm.returncode}: {disasm.stderr}")
            hits = audit_disassembly(disasm.stdout, main)
        except ValueError as exc:
            return BuildResult(tag, row, False, "invalid disassembly", detail=str(exc))
        # main/src/memtest_cached.rs enables the MMU only during the test;
        # AArch64 hits are informational, not proof that the path is MMU-on.
        for hit in hits:
            print(f"{stem}: {'AArch64 atomic' if main else 'ARM exclusive'}: {hit}")
        readelf = self.runner.run(
            ["llvm-readelf", "-S", "-W", str(elf)],
            cwd,
            env,
            logs / f"{stem}-readelf.log",
        )
        count = SECTION_COUNT_RE.search(readelf.stdout)
        found = SECTION_RE.findall(readelf.stdout)
        if (
            readelf.returncode
            or not count
            or int(count[1]) != len(SECTION_ROW_RE.findall(readelf.stdout))
        ):
            return BuildResult(
                tag,
                row,
                False,
                "invalid ELF",
                warnings=warnings,
                detail="incomplete llvm-readelf section table",
            )
        found_names = tuple(record[0] for record in found)
        if sorted(found_names) != sorted(expected):
            return BuildResult(
                tag,
                row,
                False,
                "invalid ELF",
                warnings=warnings,
                detail=f"expected payload sections {expected}, found {found_names}",
            )
        sections = {}
        exported = []
        for name, kind, address, size_hex, columns in found:
            size = sections[name] = int(size_hex, 16)
            if name == ".phyfw" and kind == "NOBITS":
                try:
                    phyfw_reservation(
                        int(address, 16),
                        size,
                        columns,
                        Path(env["CARGO_BUILD_BUILD_DIR"]),
                    )
                except ValueError as exc:
                    return BuildResult(tag, row, False, "invalid ELF", detail=str(exc))
            elif kind == "PROGBITS":
                exported.append(name)
            else:
                return BuildResult(
                    tag, row, False, "invalid ELF", detail=f"{name}: unexpected {kind}"
                )
        names = image_names(stem, tuple(exported))
        images = {}
        for name, section in zip(names, (None, *exported), strict=True):
            staged = self.args.out / "tmp" / "images" / name
            options = (
                [f"--only-section={section}"]
                if section
                else [f"--remove-section={item}" for item in expected]
            )
            copy = self.runner.run(
                ["llvm-objcopy", "-O", "binary", *options, str(elf), str(staged)],
                cwd,
                env,
                logs / f"{Path(name).stem}-objcopy.log",
            )
            error = None
            cap = sections[section] if section else limit
            if copy.returncode or not staged.is_file():
                error = (
                    f"extension {section} missing" if section else "llvm-objcopy failed"
                )
            elif cap is None:
                error = "image size limit not known"
            else:
                with staged.open("rb") as stream:
                    data = stream.read(cap + 1)
                if section and (not data or len(data) != cap):
                    error = f"extension {section} empty or size differs from ELF ({cap} bytes)"
                elif not data:
                    error = "primary image is empty"
                elif len(data) > cap:
                    error = f"primary is over the {cap:#x} limit"
                elif not section and media:
                    error = check_egon_header(data)
                    pad = self.media_pad
                    if not pad or (len(data) + pad - 1) // pad * pad > cap:
                        error = f"padded media image exceeds the {cap:#x} limit"
            if error:
                return BuildResult(
                    tag, row, False, "invalid image", warnings=warnings, detail=error
                )
            images[name] = data
        # File-backed sections must still pass the individual export checks.
        # For this runtime-staged payload file backing is itself a defect.
        if ".phyfw" in exported:
            return BuildResult(
                tag, row, False, "invalid ELF", detail=".phyfw must be NOBITS"
            )
        if hits and not main:
            return BuildResult(
                tag, row, False, "ARM exclusive instructions", detail="; ".join(hits)
            )
        for name, data in images.items():
            self.image_digests[name] = sha256(data)
            # Publish the exact in-memory snapshot, not the staging file.
            (self.args.out / "matrix" / "out" / name).write_bytes(data)
        baseline, detail, ok = self.compare_baseline(names, required)
        return BuildResult(
            tag, row, ok, baseline, len(images[names[0]]), warnings, detail, sections
        )

    def compare_baseline(
        self, names: list[str], required: bool
    ) -> tuple[str, str, bool]:
        if not required:
            return BASELINE_NEW, "no historical baseline", True
        if any(name not in self.baseline_digests for name in names):
            return (
                "missing baseline",
                "missing compared image in sealed manifest",
                False,
            )
        differs = [
            name
            for name in names
            if self.image_digests[name] != self.baseline_digests[name]
        ]
        if not differs:
            return BASELINE_SAME, "", True
        # Historical primary changes are expected, but an unchanged primary
        # with a mismatched extension is a mixed row, not a passing comparison.
        return "DIFFERS from base", ", ".join(differs), names[0] in differs

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
            env = self.cargo_env("negative")
            log = self.args.out / "matrix" / "logs" / f"negative-{tag}.log"
            res = self.runner.run(
                self._cargo_bt0(list(features), no_default),
                self.args.source / BT0_DIR,
                env,
                log,
            )
            ok, detail = negative_contract_ok(res.returncode, res.stderr, expected)
            results.append(
                NegativeResult(
                    tag,
                    ok,
                    res.returncode,
                    expected,
                    diagnostic_found(res.stderr, expected),
                    detail,
                )
            )
        return NegativesResult(all(result.ok for result in results), results)

    # -- host suites -------------------------------------------------------

    def _expected_test_binaries(
        self, host: str, cwd: Path, env: dict[str, str]
    ) -> tuple[list[Path], str]:
        log = self.args.out / "tests" / (cwd.name + "-no-run.log")
        res = self.runner.run(
            [
                self.cargo,
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
        executables: list[Path] = []
        finished = False
        cargo_roots = (
            Path(env["CARGO_TARGET_DIR"]),
            Path(env["CARGO_BUILD_BUILD_DIR"]),
        )
        for line in res.stdout.splitlines():
            try:
                message = json.loads(line)
            except ValueError:
                return [], "malformed Cargo inventory JSON"
            if finished or not isinstance(message, dict):
                return [], "unexpected record in Cargo inventory"
            if message.get("reason") == "build-finished":
                if message.get("success") is not True:
                    return [], "Cargo inventory reported a failed build"
                finished = True
                continue
            if message.get("reason") == "compiler-artifact" and message.get(
                "profile", {}
            ).get("test"):
                executable = message.get("executable")
                if not isinstance(executable, str):
                    return [], "Cargo test artifact has no executable"
                path = Path(executable)
                resolved = Path(os.path.realpath(path))
                if (
                    not path.is_absolute()
                    or resolved != path
                    or not any(resolved.is_relative_to(root) for root in cargo_roots)
                    or resolved in executables
                ):
                    return [], f"unexpected or duplicate executable: {path}"
                executables.append(resolved)
        if not finished or not executables:
            return [], "Cargo inventory is incomplete or has no executables"
        return executables, ""

    def run_suites(self) -> SuitesResult:
        host = self._host
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
            env = self.cargo_env("test")
            expected, inventory_error = self._expected_test_binaries(host, cwd, env)
            passed = failed = ignored = completed = 0
            details = []
            logs = self.args.out / "tests" / rel.replace("/", "-")
            logs.mkdir()
            errors = []
            if inventory_error:
                errors.append(f"inventory error: {inventory_error}")
            for index, binary in enumerate(expected, start=1):
                if not binary.is_file():
                    errors.append(f"missing test binary: {binary}")
                    continue
                log = logs / f"{index:02d}-{binary.name}.log"
                res = self.runner.run([str(binary)], cwd, env, log)
                summary = completed_test_result(res.stdout)
                if summary is None:
                    errors.append(
                        f"{binary.name}: exit {res.returncode}; missing or invalid test result"
                    )
                    continue
                completed += 1
                success, p, f, i = summary
                passed += p
                failed += f
                ignored += i
                details.append(f"{binary.name}: exit {res.returncode}, {p}/{f}/{i}")
                if res.returncode or not success or f or not p:
                    errors.append(f"{binary.name}: failed or no executed test")
            if not inventory_error:
                doc_name = DOC_TESTS[rel]
                doc = self.runner.run(
                    [
                        self.cargo,
                        "test",
                        "--offline",
                        "--locked",
                        "--doc",
                        "--target",
                        host,
                    ],
                    cwd,
                    env,
                    logs / "doctest.log",
                )
                units = re.findall(r"^\s*Doc-tests (\S+)$", doc.stderr, re.M)
                if (
                    doc.returncode
                    or units != [doc_name]
                    or completed_test_result(doc.stdout) != (True, 0, 0, 0)
                ):
                    errors.append(
                        f"{doc_name} doctest: expected one successful zero-test result"
                    )
                else:
                    details.append(f"{doc_name} doctest: 0/0/0 (named exception)")
            detail = f"binaries expected {len(expected)}, completed {completed}"
            if errors:
                detail += "; " + "; ".join(errors)
            if details:
                detail += "\n    " + "\n    ".join(details)
            results.append(
                SuiteResult(
                    rel,
                    not errors and completed == len(expected) and passed > 0,
                    passed,
                    failed,
                    ignored,
                    len(expected),
                    completed,
                    detail,
                )
            )
        return SuitesResult(
            bool(results) and all(result.ok for result in results), results
        )

    # -- external gate -----------------------------------------------------

    def run_gate(self) -> GateResult:
        argv = [
            sys.executable,
            "-I",
            str(self.input_paths["gate"]),
            str(self.args.source),
            self.gate_base or "",
            self.gate_head or "",
        ]
        log = self.args.out / "gate.log"
        env = {**self.git_env, "TMPDIR": self.env["TMPDIR"]}
        res = self.runner.run(argv, self.args.source, env, log)
        return GateResult(res.returncode == 0, res.returncode, res.output)

    # -- retained default digests -----------------------------------------

    def check_digests(self) -> DigestsResult:
        results = []
        for name in DIGEST_NAMES:
            expected = self.args.expected_digests.get(name)
            actual = self.image_digests.get(f"bt0-{name}.bin")
            if expected is None or actual is None:
                results.append(DigestResult(name, expected, None, False))
                continue
            results.append(DigestResult(name, expected, actual, actual == expected))
        return DigestsResult(all(result.ok for result in results), results)

    # -- source unchanged after the build ---------------------------------

    def verify_source_unchanged(self) -> list[str]:
        errors: list[str] = []
        if not self.is_worktree_root(self.args.source):
            return ["source is no longer the root of its own Git worktree"]
        head = self.git("rev-parse", "HEAD")
        if head.returncode != 0:
            errors.append("could not read the source HEAD after the build")
        elif self.source_head is not None and head.stdout.strip() != self.source_head:
            errors.append(
                f"source HEAD changed during the run: {head.stdout.strip()} "
                f"(was {self.source_head})"
            )
        if error := self.worktree_error(self.args.source, "source"):
            errors.append(error)
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
        print(f"workspace HEAD: {self.workspace_head}")
        print(f"gate base: {self.gate_base}  head: {self.gate_head}")
        for label, path in self.input_paths.items():
            print(f"{label}: SHA256 {self.input_digests[label]} ({path})")
            if label in self.input_formats:
                print(f"{label} snapshot format: {self.input_formats[label]}")
        print(f"toolchain: {self.toolchain.get('channel')}")
        for key in ("rustc_version", "cargo_version"):
            print(self.toolchain.get(key, "").rstrip())
        for name, source, value in (
            ("eGON media", MKIMAGE, self.media_max),
            ("FEL", a.source / BT0_BUILD, self.fel_max),
            ("main", a.source / COMMON_LIB, self.main_max),
        ):
            if value is not None:
                print(f"{name} cap: {value:#x} ({source})")
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
        for build in matrix.builds:
            if build.extensions:
                sizes = ", ".join(
                    f"{name}: {size} bytes" for name, size in build.extensions.items()
                )
                print(f"{build.section}/{build.tag} payload sections: {sizes}")
            if not build.ok:
                print(f"{build.section}/{build.tag}: {build.baseline}: {build.detail}")
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
        try:
            return self._run()
        except (OSError, ValueError) as exc:
            print(f"verification error: {exc}")
            print("VERDICT: FAIL")
            return 1

    def _run(self) -> int:
        errors = self.check_paths()
        if errors:
            print("path checks failed:")
            for error in errors:
                print(f"  - {error}")
            print("VERDICT: FAIL")
            return 1
        # Check the bytes in private sibling staging first, then move those
        # same files into the exclusively created job tree without recopying.
        with tempfile.TemporaryDirectory(
            prefix=".verify-a7a-", dir=self.args.out.parent
        ) as temp:
            staged = Path(temp)
            self.snapshot_inputs(staged / "inputs")
            for sub in ("matrix/out", "matrix/logs", "tests", "tmp/images"):
                (staged / sub).mkdir(parents=True)
            if errors := self.check_tooling(staged / "tmp"):
                raise ValueError("\n".join(errors))
            self.stage_cargo_cache(staged / "cargo-home")
            self.prepare_output(staged)
        matrix = self.run_matrix()
        negative = self.run_negative()
        suites = self.run_suites()
        gate = self.run_gate()
        digests = self.check_digests()
        post = self.verify_source_unchanged() + self.check_workspace()
        self.print_report(matrix, negative, suites, gate, digests)
        if post:
            print("checkout checks failed after the build:")
            for error in post:
                print(f"  - {error}")
        else:
            print(
                "source and workspace: complete, clean Git worktrees before and after"
            )
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
    parser.add_argument("--dram-lib-sha256", required=True, type=_sha256_arg)
    parser.add_argument(
        "--phyfw-obj", required=True, help="PHY firmware object build input"
    )
    parser.add_argument("--phyfw-obj-sha256", required=True, type=_sha256_arg)
    parser.add_argument(
        "--gate", required=True, help="external publication gate script"
    )
    parser.add_argument("--gate-sha256", required=True, type=_sha256_arg)
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
        dram_lib_sha256=ns.dram_lib_sha256,
        phyfw_obj=Path(ns.phyfw_obj).resolve(),
        phyfw_obj_sha256=ns.phyfw_obj_sha256,
        gate=Path(ns.gate).resolve(),
        gate_sha256=ns.gate_sha256,
        out=Path(ns.out).parent.resolve() / Path(ns.out).name,
        expected_digests=dict(ns.expect_digest),
    )


def validate_args(args: Config) -> list[str]:
    errors = []
    if not re.fullmatch(r"[0-9a-fA-F]{40}", args.source_sha):
        errors.append("--source-sha must be a full 40-digit commit SHA")
    missing = [name for name in DIGEST_NAMES if name not in args.expected_digests]
    if missing:
        errors.append("missing required --expect-digest for: " + ", ".join(missing))
    return errors


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
