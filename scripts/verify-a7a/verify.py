#!/usr/bin/env python3
"""Host verification for the Radxa Cubie A7A oreboot bt0/main matrix.

This is the maintained board-integration matrix for this workspace. It builds
the bt0 and main feature sets of ``src/mainboard/radxa/cubie-a7a`` at an exact
source checkout, compares them with a retained baseline, runs the five required
host test suites, runs the external publication gate, and checks the four
retained default-image digests.

The harness is fail-closed: every stage's real exit status is checked, a
missing path, baseline image, suite or gate is a failure, and no pipeline
(``grep``, ``tail``) can hide a stage's exit. The external gate and the private
build inputs are inputs, not vendored here; pass their paths on the command line.

Usage:
    python3 -I scripts/verify-a7a/verify.py \
        --source <oreboot-checkout> --base <gate-base> \
        --baseline <matrix-baseline-dir> \
        --dram-lib <libdram-a733.a> --phyfw-obj <libdram-object> \
        --gate <gate.py> --out <job-output-dir> \
        --expect-digest default=<sha256> \
        --expect-digest default-fel=<sha256> \
        --expect-digest default@2400=<sha256> \
        --expect-digest default-fel@2400=<sha256>

Exit status is 0 only when every stage passes. The job output directory holds
the build logs, the produced images, the suite logs, the gate log and a
SHA256SUMS file. The source checkout is never written to; cargo targets and
TMPDIR stay under the job output directory.
"""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

BT0_DIR = "src/mainboard/radxa/cubie-a7a/bt0"
MAIN_DIR = "src/mainboard/radxa/cubie-a7a/main"

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
# (tag, A7A_PROFILE or None, features)
NEW_ENTRIES = (
    ("default", None, ()),
    ("default-fel", None, ("fel",)),
    ("default@2400", "2400", ()),
    ("default-fel@2400", "2400", ("fel",)),
    ("default-emmc", None, ("emmc",)),
    ("default-spinor", None, ("spinor",)),
    ("default-otp", None, ("otp",)),
    ("default-fel+fastboot", None, ("fel", "fastboot")),
    (
        "default-fel+fastboot+fastboot-nor-write",
        None,
        ("fel", "fastboot", "fastboot-nor-write"),
    ),
    (
        "default-fel+fastboot+fastboot-emmc-write",
        None,
        ("fel", "fastboot", "fastboot-emmc-write"),
    ),
    ("default-wr-r1", None, ("wr-r1",)),
    ("default-fel+wr-r1", None, ("fel", "wr-r1")),
)

# LAB: the lab entry that replaces the invalid positive. It has no historical
# baseline image and is labelled as new. The lab backend needs bl-mission: with
# --no-default-features and no lab backend selected the build is not equivalent.
LAB_ENTRIES = (("lab-drift", ("fel", "bl-mission", "dram-lab", "drift-log")),)

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

# The negative contract: the default feature build with a lab feature must fail
# with this compile_error, not for an arbitrary reason.
CONFLICT_DIAGNOSTIC = (
    "another DRAM backend or a lab feature together with the default feature "
    "`blobfree`"
)

BASELINE_SAME = "= base"
BASELINE_NEW = "no baseline (new)"

TEST_RESULT_RE = re.compile(
    r"^test result: (?:ok|FAILED)\.\s+(\d+) passed; (\d+) failed; " r"(\d+) ignored;",
    re.M,
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    lab_total: int
    lab_ok: int
    main_total: int
    main_ok: int
    main_identical: int
    failures: list[str]
    builds: list[BuildResult] = field(default_factory=list)


@dataclass
class NegativeResult:
    ok: bool
    returncode: int
    diagnostic_found: bool
    detail: str


@dataclass
class SuiteResult:
    directory: str
    ok: bool
    passed: int
    failed: int
    ignored: int
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
    base: str
    head: str
    baseline: Path
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
    env["A733_DRAM_LIB"] = str(args.dram_lib)
    env["A733_PHY_FW_OBJ"] = str(args.phyfw_obj)
    env["TMPDIR"] = str(out / "tmp")
    return env


def required_baseline_names() -> list[str]:
    names = []
    for set_name in OLD_SETS:
        tag = "old-" + (set_name.replace(" ", "+") or "default")
        names.append(f"bt0-{tag}.bin")
    for tag, _profile, _features in NEW_ENTRIES:
        names.append(f"bt0-{tag}.bin")
    for set_name in MAIN_SETS:
        tag = set_name.replace(" ", "+") or "none"
        names.append(f"main-{tag}.bin")
    return names


def negative_contract_ok(returncode: int, output: str) -> tuple[bool, str]:
    """The invalid positive must fail for the expected feature conflict."""
    if returncode == 0:
        return False, "expected the default-feature lab build to fail, got exit 0"
    if CONFLICT_DIAGNOSTIC not in output:
        return False, "build failed without the expected feature-conflict diagnostic"
    return True, "expected feature-conflict diagnostic found"


def has_dram_section(readelf_output: str) -> bool:
    """True when readelf lists a .dram section (its lines are indented)."""
    return re.search(r"^\s*\[\s*\d+\]\s+\.dram\b", readelf_output, re.M) is not None


def parse_test_results(output: str) -> tuple[int, int, int, bool]:
    passed = failed = ignored = 0
    found = False
    for match in TEST_RESULT_RE.finditer(output):
        found = True
        passed += int(match.group(1))
        failed += int(match.group(2))
        ignored += int(match.group(3))
    return passed, failed, ignored, found


class Harness:
    def __init__(self, args: Config, runner: SubprocessRunner | None = None):
        self.args = args
        self.runner = runner or SubprocessRunner()
        self.env = build_env(args, args.out)
        self.source_head: str | None = None
        self.warnings: dict[str, int] = {}
        self._host_checked = False
        self._host: str | None = None

    # -- fail-closed path checks ------------------------------------------

    def check_paths(self) -> list[str]:
        a = self.args
        errors: list[str] = []
        a.out.mkdir(parents=True, exist_ok=True)
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
            git_dir = self.runner.run(
                ["git", "-C", str(a.source), "rev-parse", "--git-dir"],
                a.source,
                self.env,
            )
            if git_dir.returncode != 0:
                errors.append(f"source is not a git repository: {a.source}")
            else:
                base = self.runner.run(
                    [
                        "git",
                        "-C",
                        str(a.source),
                        "cat-file",
                        "-e",
                        f"{a.base}^{{commit}}",
                    ],
                    a.source,
                    self.env,
                )
                if base.returncode != 0:
                    errors.append(f"base revision not found in source: {a.base}")
                head = self.runner.run(
                    [
                        "git",
                        "-C",
                        str(a.source),
                        "rev-parse",
                        "--verify",
                        "--quiet",
                        f"{a.head}^{{commit}}",
                    ],
                    a.source,
                    self.env,
                )
                if head.returncode != 0:
                    errors.append(f"head revision not found in source: {a.head}")
                status = self.runner.run(
                    ["git", "-C", str(a.source), "status", "--porcelain"],
                    a.source,
                    self.env,
                )
                if status.returncode != 0:
                    errors.append("could not read the source worktree status")
                elif status.output.strip():
                    errors.append("source worktree is dirty; check out a clean commit")
                head_sha = self.runner.run(
                    ["git", "-C", str(a.source), "rev-parse", "HEAD"],
                    a.source,
                    self.env,
                )
                self.source_head = head_sha.output.strip() or None
            for rel in (BT0_DIR, MAIN_DIR, *SUITE_DIRS):
                if not (a.source / rel).is_dir():
                    errors.append(f"required source directory missing: {rel}")
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
        return errors

    def _check_baseline_sums(self) -> list[str]:
        sums = self.args.baseline / "SHA256SUMS"
        if not sums.is_file():
            return []
        errors = []
        for line in sums.read_text(encoding="utf-8").splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            want, name = parts[0], parts[1].strip().lstrip("*")
            path = self.args.baseline / name
            if not path.is_file():
                errors.append(f"baseline SHA256SUMS names a missing file: {name}")
            elif sha256_file(path) != want:
                errors.append(f"baseline file does not match SHA256SUMS: {name}")
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
                baseline_required=True,
            )
            for tag, profile, features in NEW_ENTRIES
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
        self._write_sha256sums()
        return MatrixResult(
            ok=not failures,
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
            lab_total=len(lab),
            lab_ok=sum(build.ok for build in lab),
            main_total=len(main),
            main_ok=sum(build.ok for build in main),
            main_identical=sum(
                build.ok and build.baseline == BASELINE_SAME for build in main
            ),
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
        argv = ["cargo", "build", "--offline", "--release"]
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
        readelf = self.runner.run(
            ["llvm-readelf", "-S", "-W", str(elf)], self.args.source / BT0_DIR, env
        )
        if readelf.returncode != 0:
            return BuildResult(
                tag, section, False, "build failed", detail="llvm-readelf failed"
            )
        has_dram = has_dram_section(readelf.output)
        bin_path = self.args.out / "matrix" / "out" / f"bt0-{tag}.bin"
        ext_path = self.args.out / "matrix" / "out" / f"bt0-{tag}-ext.bin"
        if has_dram:
            strip = self.runner.run(
                [
                    "llvm-objcopy",
                    "-O",
                    "binary",
                    "--remove-section=.dram",
                    "--remove-section=.phyfw",
                    str(elf),
                    str(bin_path),
                ],
                self.args.source / BT0_DIR,
                env,
            )
            if strip.returncode != 0:
                return BuildResult(
                    tag, section, False, "build failed", detail="llvm-objcopy failed"
                )
            ext = self.runner.run(
                [
                    "llvm-objcopy",
                    "-O",
                    "binary",
                    "--only-section=.dram",
                    str(elf),
                    str(ext_path),
                ],
                self.args.source / BT0_DIR,
                env,
            )
            if ext.returncode != 0:
                return BuildResult(
                    tag,
                    section,
                    False,
                    "build failed",
                    detail="llvm-objcopy ext failed",
                )
        else:
            strip = self.runner.run(
                [
                    "llvm-objcopy",
                    "-O",
                    "binary",
                    "--remove-section=.phyfw",
                    str(elf),
                    str(bin_path),
                ],
                self.args.source / BT0_DIR,
                env,
            )
            if strip.returncode != 0:
                return BuildResult(
                    tag, section, False, "build failed", detail="llvm-objcopy failed"
                )
        baseline, detail = self._compare_baseline(
            f"bt0-{tag}", bin_path, ext_path if has_dram else None, baseline_required
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

    def build_main(self, tag: str, features: list[str]) -> BuildResult:
        argv = ["cargo", "build", "--offline", "--release", "--no-default-features"]
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
        copy = self.runner.run(
            ["llvm-objcopy", "-O", "binary", str(elf), str(bin_path)],
            self.args.source / MAIN_DIR,
            env,
        )
        if copy.returncode != 0:
            return BuildResult(
                "main-" + tag,
                "main",
                False,
                "build failed",
                detail="llvm-objcopy failed",
            )
        warnings = self._count_warnings(log)
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
        lines = [
            line
            for line in log.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.startswith("warning")
        ]
        for line in lines:
            self.warnings[line] = self.warnings.get(line, 0) + 1
        return len(lines)

    # -- negative contract -------------------------------------------------

    def run_negative(self) -> NegativeResult:
        env = dict(self.env)
        env["CARGO_TARGET_DIR"] = str(self.args.out / "target" / "negative")
        log = (
            self.args.out
            / "matrix"
            / "logs"
            / "negative-default-fel+dram-lab+drift-log.log"
        )
        res = self.runner.run(
            [
                "cargo",
                "build",
                "--offline",
                "--release",
                "--features",
                "fel dram-lab drift-log",
            ],
            self.args.source / BT0_DIR,
            env,
            log,
        )
        ok, detail = negative_contract_ok(res.returncode, res.output)
        return NegativeResult(
            ok, res.returncode, CONFLICT_DIAGNOSTIC in res.output, detail
        )

    # -- host suites -------------------------------------------------------

    def host_triple(self) -> str | None:
        if not self._host_checked:
            self._host_checked = True
            res = self.runner.run(["rustc", "-vV"], self.args.source, self.env)
            match = re.search(r"^host: (\S+)", res.output, re.M)
            self._host = match.group(1) if match and res.returncode == 0 else None
        return self._host

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
                        "could not determine the rustc host triple",
                    )
                ],
            )
        results = []
        for rel in SUITE_DIRS:
            cwd = self.args.source / rel
            env = dict(self.env)
            env["CARGO_TARGET_DIR"] = str(self.args.out / "target" / "test")
            log = self.args.out / "tests" / (rel.replace("/", "-") + ".log")
            res = self.runner.run(
                ["cargo", "test", "--offline", "--target", host], cwd, env, log
            )
            passed, failed, ignored, parsed = parse_test_results(res.output)
            ok = res.returncode == 0 and parsed and failed == 0
            detail = (
                f"exit {res.returncode}; passed {passed}, failed {failed}, "
                f"ignored {ignored}"
            )
            if not parsed:
                detail += "; no 'test result:' line found"
            results.append(SuiteResult(rel, ok, passed, failed, ignored, detail))
        return SuitesResult(all(result.ok for result in results), results)

    # -- external gate -----------------------------------------------------

    def run_gate(self) -> GateResult:
        argv = [
            sys.executable,
            "-I",
            str(self.args.gate),
            str(self.args.source),
            self.args.base,
            self.args.head,
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

    # -- report and entry --------------------------------------------------

    def print_report(
        self,
        matrix: MatrixResult,
        negative: NegativeResult,
        suites: SuitesResult,
        gate: GateResult,
        digests: DigestsResult,
    ) -> None:
        a = self.args
        print("=== A7A bt0/main host verification ===")
        print(f"source: {a.source}")
        print(f"source HEAD: {self.source_head}")
        print(f"gate base: {a.base}  head: {a.head}")
        print()
        print("=== matrix ===")
        print(
            f"OLD: {matrix.old_ok}/{matrix.old_total} built; "
            f"identical to base {matrix.old_identical}, differ {matrix.old_differ}"
        )
        print(
            f"NEW: {matrix.new_ok}/{matrix.new_total} built; "
            f"identical to base {matrix.new_identical}, differ {matrix.new_differ}"
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
        print("=== negative feature-contract check ===")
        print(f"exit: {negative.returncode} (expected nonzero)")
        print("diagnostic: " + ("found" if negative.diagnostic_found else "NOT FOUND"))
        print(negative.detail)
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
        self.print_report(matrix, negative, suites, gate, digests)
        ok = matrix.ok and negative.ok and suites.ok and gate.ok and digests.ok
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


def parse_args(argv: list[str] | None = None) -> Config:
    parser = argparse.ArgumentParser(
        description="A7A bt0/main host verification matrix, suites, gate and digests."
    )
    parser.add_argument("--source", required=True, help="oreboot checkout")
    parser.add_argument("--base", required=True, help="gate base revision")
    parser.add_argument(
        "--head", default="HEAD", help="gate head revision (default HEAD)"
    )
    parser.add_argument(
        "--baseline", required=True, help="retained matrix baseline directory"
    )
    parser.add_argument("--dram-lib", required=True, help="libdram-a733.a build input")
    parser.add_argument(
        "--phyfw-obj", required=True, help="PHY firmware object build input"
    )
    parser.add_argument(
        "--gate", required=True, help="external publication gate script"
    )
    parser.add_argument("--out", required=True, help="job output directory")
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
        source=Path(ns.source),
        base=ns.base,
        head=ns.head,
        baseline=Path(ns.baseline),
        dram_lib=Path(ns.dram_lib),
        phyfw_obj=Path(ns.phyfw_obj),
        gate=Path(ns.gate),
        out=Path(ns.out),
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
