#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Quick regression suite for the A7A verification harness.

The tests exercise the fail-closed orchestration with controlled stage results
and real path checks; they do not run cargo or the external gate. Run with:

    python3 -I -B scripts/verify-a7a/tests/test_verify.py
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import os
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

VERIFY_PATH = Path(__file__).resolve().parents[1] / "verify.py"
_spec = importlib.util.spec_from_file_location("verify_a7a_under_test", VERIFY_PATH)
assert _spec is not None and _spec.loader is not None
verify = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify)

ZERO = "0" * 64
IDENT = ("DaveWK", "13626476+DaveWK@users.noreply.github.com")
HOST = "x86_64-unknown-linux-gnu"


def home_tmp() -> Path:
    """A HOME-scoped TMPDIR; the project never writes to /tmp."""
    override = os.environ.get("TMPDIR")
    base = (
        Path(override)
        if override
        else Path.home() / ".cache" / "A7A" / "verify-a7a-tests"
    )
    base.mkdir(parents=True, exist_ok=True)
    return base


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


def git_head(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def make_source(root: Path, suites=verify.SUITE_DIRS) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    run(["git", "init", "-q"], root)
    for rel in (verify.BT0_DIR, verify.MAIN_DIR, *suites):
        (root / rel).mkdir(parents=True, exist_ok=True)
    (root / verify.BT0_BUILD).write_text(
        'const MEMORY_FEL: &str = "SRAM : ORIGIN = 0x90000, LENGTH = 0x4f000";\n',
        encoding="utf-8",
    )
    (root / verify.COMMON_LIB).parent.mkdir(parents=True, exist_ok=True)
    (root / verify.COMMON_LIB).write_text(
        "pub const MAIN_MAX_SIZE: usize = 0x0008_0000;\n", encoding="utf-8"
    )
    (root / "README").write_text("fixture\n", encoding="utf-8")
    run(["git", "add", "-A"], root)
    run(
        [
            "git",
            "-c",
            f"user.name={IDENT[0]}",
            "-c",
            f"user.email={IDENT[1]}",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
        root,
    )
    return root


def make_unrelated_commit(root: Path) -> str:
    """A second root: a commit that is not an ancestor of HEAD."""
    tree = subprocess.run(
        ["git", "-C", str(root), "write-tree"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            f"user.name={IDENT[0]}",
            "-c",
            f"user.email={IDENT[1]}",
            "commit-tree",
            tree,
            "-m",
            "unrelated",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def make_baseline(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    lines = []
    for name in verify.required_baseline_names():
        data = b"fixture"
        (root / name).write_bytes(data)
        lines.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return root


def make_args(
    tmp,
    source,
    baseline,
    gate,
    out,
    source_sha=None,
    base=None,
    baseline_sums_sha256=None,
):
    return verify.Config(
        source=source,
        source_sha=source_sha or git_head(source),
        base=base if base is not None else git_head(source),
        baseline=baseline,
        baseline_sums_sha256=baseline_sums_sha256 or sha256_of(baseline / "SHA256SUMS"),
        dram_lib=tmp / "libdram-a733.a",
        dram_lib_sha256=sha256_of(tmp / "libdram-a733.a"),
        phyfw_obj=tmp / "libdram",
        phyfw_obj_sha256=sha256_of(tmp / "libdram"),
        gate=gate,
        gate_sha256=sha256_of(gate) if gate.is_file() else ZERO,
        out=out,
        expected_digests={name: ZERO for name in verify.DIGEST_NAMES},
    )


def green_matrix() -> verify.MatrixResult:
    return verify.MatrixResult(
        ok=True,
        old_total=len(verify.OLD_SETS),
        old_ok=len(verify.OLD_SETS),
        old_identical=14,
        old_differ=24,
        new_total=len(verify.NEW_ENTRIES),
        new_ok=len(verify.NEW_ENTRIES),
        new_identical=0,
        new_differ=12,
        new_nobaseline=sum(
            1
            for _tag, _profile, _features, required in verify.NEW_ENTRIES
            if not required
        ),
        lab_total=len(verify.LAB_ENTRIES),
        lab_ok=len(verify.LAB_ENTRIES),
        main_total=len(verify.MAIN_SETS),
        main_ok=len(verify.MAIN_SETS),
        main_identical=len(verify.MAIN_SETS),
        failures=[],
    )


def green_negative() -> verify.NegativesResult:
    return verify.NegativesResult(
        ok=True,
        results=[
            verify.NegativeResult(tag, True, 1, expected, True, "expected diagnostic")
            for tag, _features, _no_default, expected in verify.NEGATIVE_ENTRIES
        ],
    )


def green_suites() -> verify.SuitesResult:
    return verify.SuitesResult(
        ok=True,
        results=[
            verify.SuiteResult(directory, True, 1, 0, 0, 1, 1, "exit 0")
            for directory in verify.SUITE_DIRS
        ],
    )


def green_gate() -> verify.GateResult:
    return verify.GateResult(ok=True, returncode=0, output="gate: 0 finding(s)")


def green_digests() -> verify.DigestsResult:
    return verify.DigestsResult(
        ok=True,
        results=[
            verify.DigestResult(name, ZERO, ZERO, True) for name in verify.DIGEST_NAMES
        ],
    )


class FakeHarness(verify.Harness):
    def __init__(
        self,
        args,
        matrix=None,
        negative=None,
        suites=None,
        gate=None,
        digests=None,
        real_gate=False,
    ):
        super().__init__(args)
        self._matrix = green_matrix() if matrix is None else matrix
        self._negative = green_negative() if negative is None else negative
        self._suites = green_suites() if suites is None else suites
        self._gate = green_gate() if gate is None else gate
        self._digests = green_digests() if digests is None else digests
        self._real_gate = real_gate

    def run_matrix(self):
        return self._matrix

    def run_negative(self):
        return self._negative

    def run_suites(self):
        return self._suites

    def run_gate(self):
        if self._real_gate:
            return verify.Harness.run_gate(self)
        return self._gate

    def check_digests(self):
        return self._digests

    def check_tooling(self, tmp):
        # Neither the fake build stages nor the external Python gate need Cargo.
        return []

    def stage_cargo_cache(self, destination):
        destination.mkdir()


class DirtyHarness(FakeHarness):
    """Dirties the source during a stage, after the entry path checks."""

    def run_matrix(self):
        (self.args.source / "dirty-after-build.txt").write_text("x", encoding="utf-8")
        return green_matrix()


class HarnessRegressionTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(
            prefix="verify-a7a-test-", dir=home_tmp()
        )
        self.tmp = Path(self._tmp.name)
        self.source = make_source(self.tmp / "oreboot")
        workspace = self.tmp / "workspace"
        mkimage = workspace / "scripts" / "mkimage.py"
        mkimage.parent.mkdir(parents=True)
        mkimage.write_bytes(verify.MKIMAGE.read_bytes())
        make_source(workspace)
        self.enterContext(patch.object(verify, "MKIMAGE", mkimage))
        self.baseline = make_baseline(self.tmp / "baseline")
        self.gate = self.tmp / "gate.py"
        self.gate.write_text("pass\n", encoding="utf-8")
        (self.tmp / "libdram-a733.a").write_bytes(b"!<arch>\n")
        (self.tmp / "libdram").write_bytes(b"\x7fELFfixture")
        self.out = self.tmp / "out"

    def tearDown(self):
        self._tmp.cleanup()

    def args(self, **overrides):
        values = dict(
            source=self.source,
            baseline=self.baseline,
            gate=self.gate,
            out=self.out,
        )
        values.update(overrides)
        return make_args(self.tmp, **values)

    def test_all_green_returns_zero(self):
        self.assertEqual(FakeHarness(self.args()).run(), 0)

    def test_matrix_failure_returns_nonzero(self):
        bad = replace(green_matrix(), ok=False, failures=["bt0-old-fel"])
        self.assertNotEqual(FakeHarness(self.args(), matrix=bad).run(), 0)

    def test_failing_suite_returns_nonzero(self):
        bad = verify.SuitesResult(
            ok=False,
            results=[
                verify.SuiteResult(
                    verify.SUITE_DIRS[0], False, 0, 1, 0, 1, 1, "exit 1; failed 1"
                )
            ],
        )
        self.assertNotEqual(FakeHarness(self.args(), suites=bad).run(), 0)

    def test_missing_suite_returns_nonzero(self):
        source = make_source(
            self.tmp / "oreboot-missing", suites=verify.SUITE_DIRS[:-1]
        )
        self.assertNotEqual(FakeHarness(self.args(source=source)).run(), 0)

    def test_failing_gate_returns_nonzero(self):
        bad = verify.GateResult(ok=False, returncode=1, output="gate: 1 finding(s)")
        self.assertNotEqual(FakeHarness(self.args(), gate=bad).run(), 0)

    def test_missing_gate_returns_nonzero(self):
        self.assertNotEqual(
            FakeHarness(self.args(gate=self.tmp / "missing-gate.py")).run(), 0
        )

    def test_missing_baseline_returns_nonzero(self):
        baseline = make_baseline(self.tmp / "baseline-missing")
        (baseline / verify.required_baseline_names()[0]).unlink()
        self.assertNotEqual(FakeHarness(self.args(baseline=baseline)).run(), 0)

    def test_missing_base_revision_returns_nonzero(self):
        args = self.args()
        args.base = "0" * 40
        self.assertNotEqual(FakeHarness(args).run(), 0)

    def test_base_not_ancestor_returns_nonzero(self):
        args = self.args(base=make_unrelated_commit(self.source))
        self.assertNotEqual(FakeHarness(args).run(), 0)

    def test_wrong_source_sha_returns_nonzero(self):
        self.assertNotEqual(FakeHarness(self.args(source_sha="0" * 40)).run(), 0)

    def test_dirty_tree_after_build_returns_nonzero(self):
        self.assertNotEqual(DirtyHarness(self.args()).run(), 0)

    def test_digest_mismatch_returns_nonzero(self):
        bad = verify.DigestsResult(
            ok=False,
            results=[
                verify.DigestResult(name, ZERO, "1" * 64, False)
                for name in verify.DIGEST_NAMES
            ],
        )
        self.assertNotEqual(FakeHarness(self.args(), digests=bad).run(), 0)

    def test_baseline_sums_hash_mismatch_returns_nonzero(self):
        self.assertNotEqual(
            FakeHarness(self.args(baseline_sums_sha256="0" * 64)).run(), 0
        )

    def test_stale_output_directory_returns_nonzero_and_writes_nothing(self):
        self.out.mkdir()
        (self.out / "stale.bin").write_bytes(b"stale")
        self.assertNotEqual(FakeHarness(self.args()).run(), 0)
        self.assertFalse((self.out / "matrix").exists())

    def test_output_inside_source_returns_nonzero_and_writes_nothing(self):
        out = self.source / "out"
        self.assertNotEqual(FakeHarness(self.args(out=out)).run(), 0)
        self.assertFalse(out.exists())

    def test_output_equal_baseline_returns_nonzero_and_writes_nothing(self):
        self.assertNotEqual(FakeHarness(self.args(out=self.baseline)).run(), 0)
        self.assertFalse((self.baseline / "matrix").exists())

    def test_relative_paths_are_resolved(self):
        argv = [
            "--source",
            "rel-source",
            "--source-sha",
            "0" * 40,
            "--base",
            "0" * 40,
            "--baseline",
            "rel-baseline",
            "--baseline-sums-sha256",
            ZERO,
            "--dram-lib",
            "rel-lib",
            "--dram-lib-sha256",
            ZERO,
            "--phyfw-obj",
            "rel-phy",
            "--phyfw-obj-sha256",
            ZERO,
            "--gate",
            "rel-gate",
            "--gate-sha256",
            ZERO,
            "--out",
            "rel-out",
            "--expect-digest",
            f"default={ZERO}",
        ]
        args = verify.parse_args(argv)
        for path in (
            args.source,
            args.baseline,
            args.dram_lib,
            args.phyfw_obj,
            args.gate,
            args.out,
        ):
            self.assertTrue(path.is_absolute())

    def test_real_gate_failure_is_failure(self):
        gate = self.tmp / "failing-gate.py"
        gate.write_text(
            "#!/usr/bin/env python3\nimport sys\nsys.exit(1)\n", encoding="utf-8"
        )
        harness = FakeHarness(self.args(gate=gate), real_gate=True)
        self.assertEqual(harness.run(), 1)

    def test_gate_receives_the_resolved_source_head(self):
        gate = self.tmp / "recording-gate.py"
        gate.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "open(sys.argv[0] + '.argv', 'w').write(repr(sys.argv))\n"
            "sys.exit(0)\n",
            encoding="utf-8",
        )
        self.assertEqual(FakeHarness(self.args(gate=gate), real_gate=True).run(), 0)
        recorded = ast.literal_eval((self.out / "inputs" / "gate.py.argv").read_text())
        self.assertEqual(recorded[1], str(self.source))
        self.assertEqual(recorded[2], git_head(self.source))
        self.assertEqual(recorded[3], git_head(self.source))

    def test_gate_given_a_wrong_sha_fails(self):
        gate = self.tmp / "wrong-sha-gate.py"
        gate.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"sys.exit(0 if sys.argv[3] == '{'0' * 40}' else 1)\n",
            encoding="utf-8",
        )
        self.assertNotEqual(FakeHarness(self.args(gate=gate), real_gate=True).run(), 0)

    def test_runner_missing_executable_is_failure(self):
        result = verify.SubprocessRunner().run(
            ["verify-a7a-definitely-missing-command"], self.tmp, {}
        )
        self.assertNotEqual(result.returncode, 0)


def valid_media_image(
    size=0x1000,
    magic=verify.EGON_MAGIC,
    run=verify.MEDIA_RUN_ADDR,
    length=0,
    checksum=verify.EGON_STAMP,
) -> bytes:
    data = bytearray(size)
    data[0:4] = b"\x0e\x00\x00\xea"
    data[4:12] = magic
    data[12:16] = checksum.to_bytes(4, "little")
    data[16:20] = length.to_bytes(4, "little")
    data[20:24] = verify.EGON_HEADER_SIZE.to_bytes(4, "little")
    data[24:28] = (0).to_bytes(4, "little")
    data[28:32] = (0).to_bytes(4, "little")
    data[32:36] = run.to_bytes(4, "little")
    return bytes(data)


class ImageRunner(verify.SubprocessRunner):
    def __init__(self, readelf="", primary=b"", ext=b"", cargo_rc=0, asm="mov r0, r0"):
        self.readelf = readelf
        self.primary = primary
        self.ext = ext
        self.cargo_rc = cargo_rc
        self.asm = asm

    def run(self, argv, cwd, env, log=None):
        command = argv[0]
        if command == "cargo":
            return verify.CommandResult(tuple(argv), str(cwd), self.cargo_rc, "")
        if command == "llvm-objdump":
            return verify.CommandResult(
                tuple(argv),
                str(cwd),
                0,
                "test: file format elf32-littlearm\n00000004 <lab_fw::load>:\n  4: "
                + self.asm,
            )
        if command == "llvm-readelf":
            table = f"There are {len(self.readelf.splitlines())} section headers, starting at offset 0x0:\n"
            return verify.CommandResult(tuple(argv), str(cwd), 0, table + self.readelf)
        if command == "llvm-objcopy":
            output = Path(argv[-1])
            output.parent.mkdir(parents=True, exist_ok=True)
            if "--only-section=.dram" in argv or "--only-section=.phyfw" in argv:
                output.write_bytes(self.ext)
            else:
                output.write_bytes(self.primary)
            return verify.CommandResult(tuple(argv), str(cwd), 0, "")
        return verify.CommandResult(tuple(argv), str(cwd), 0, "")


class ImageValidationTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(
            prefix="verify-a7a-image-", dir=home_tmp()
        )
        self.tmp = Path(self._tmp.name)
        self.source = make_source(self.tmp / "oreboot")
        self.baseline = make_baseline(self.tmp / "baseline")
        self.gate = self.tmp / "gate.py"
        self.gate.write_text("", encoding="utf-8")
        (self.tmp / "libdram-a733.a").write_bytes(b"")
        (self.tmp / "libdram").write_bytes(b"")
        self.out = self.tmp / "out"
        for sub in ("matrix/out", "matrix/logs", "tmp/images"):
            (self.out / sub).mkdir(parents=True, exist_ok=True)
        self.args = make_args(
            self.tmp,
            source=self.source,
            baseline=self.baseline,
            gate=self.gate,
            out=self.out,
        )

    def tearDown(self):
        self._tmp.cleanup()

    def build(
        self, runner, features, baseline_required=False, no_default=False, tag="t"
    ):
        elf = (
            self.out
            / "target"
            / "bt0"
            / "armv7a-none-eabi"
            / "release"
            / "oreboot-cubie-a7a-bt0"
        )
        elf.parent.mkdir(parents=True, exist_ok=True)
        elf.write_bytes(b"")
        harness = verify.Harness(self.args, runner=runner)
        harness.toolchain["objdump"] = "llvm-objdump"
        harness.read_limits()
        return harness.build_bt0(
            tag, None, list(features), no_default, "new", baseline_required
        )

    def test_exclusive_audit(self):
        for ins in ("ldrexd", "strexbne", "ldaexh", "stlex"):
            with self.subTest(ins=ins):
                res = self.build(
                    ImageRunner(
                        " [ 1] .text PROGBITS\n", primary=b"ok", asm=ins + " r0, [r1]"
                    ),
                    ["fel"],
                )
                self.assertFalse(res.ok)
                self.assertIn(f"lab_fw::load 0x4 {ins}", res.detail)
        self.assertTrue(
            self.build(ImageRunner(" [ 1] .text PROGBITS\n", primary=b"ok"), ["fel"]).ok
        )

    def test_reserved_payload_contract(self):
        index = self.out / "build/bt0-t/build/a/out/phy-fw-lab.rs"
        index.parent.mkdir(parents=True)
        index.write_text("pub const LEN: [usize; 6] = [1, 1, 1, 1, 1, 1];\n")
        for kind, addr, size, align, dram_kind, ext, features, ok in [
            ("NOBITS", "47000", "6", 4, "PROGBITS", b"A7AX", ["dram-lab"], True),
            ("NOBITS", "47000", "7", 4, "PROGBITS", b"A7AX", ["dram-lab"], False),
            ("NOBITS", "47004", "6", 4, "PROGBITS", b"A7AX", ["dram-lab"], False),
            ("NOBITS", "47000", "6", 2, "PROGBITS", b"A7AX", ["dram-lab"], False),
            (
                "NOBITS",
                "47000",
                "6",
                4,
                "PROGBITS",
                b"A7AX",
                ["dram-lab", "bl-mission"],
                False,
            ),
            ("PROGBITS", "47000", "4", 4, "PROGBITS", b"A7AX", ["dram-lab"], False),
            ("NOBITS", "47000", "6", 4, "NOBITS", b"A7AX", ["dram-lab"], False),
            ("NOBITS", "47000", "6", 4, "PROGBITS", b"", ["dram-lab"], False),
        ]:
            with self.subTest(
                kind=kind,
                addr=addr,
                size=size,
                align=align,
                dram=dram_kind,
                ext=ext,
                features=features,
            ):
                table = f" [ 1] .dram {dram_kind} 59000000 10000 4 00 AR 0 0 64\n [ 2] .phyfw {kind} {addr} 20000 {size} 00 WA 0 0 {align}\n"
                res = self.build(
                    ImageRunner(table, primary=b"code", ext=ext),
                    features,
                    no_default=True,
                )
                self.assertEqual(res.ok, ok, res.detail)

    def test_aarch64_atomic_report_excludes_plain_load_and_store(self):
        mnemonics = (
            "ldxr",
            "stxp",
            "ldaxrb",
            "stlxrh",
            "caspal",
            "swplb",
            "ldaddal",
            "steorlh",
        )
        text = "test: file format elf64-littleaarch64\n0 <cached_test>:\n"
        for i, op in enumerate((*mnemonics, "ldar", "stlr", "ldr", "str")):
            text += f"  {i * 4:x}: {op} x0, [x1]\n"
        self.assertEqual(
            verify.audit_disassembly(text, True),
            [f"cached_test 0x{i * 4:x} {op}" for i, op in enumerate(mnemonics)],
        )

    def test_empty_primary_fails(self):
        result = self.build(
            ImageRunner(readelf="  [ 1] .text             PROGBITS\n", primary=b""),
            [],
        )
        self.assertFalse(result.ok)
        self.assertIn("primary image is empty", result.detail)

    def test_oversized_media_primary_fails(self):
        result = self.build(
            ImageRunner(
                readelf="  [ 1] .text             PROGBITS\n",
                primary=b"\x00" * 0x4A001,
            ),
            [],
        )
        self.assertFalse(result.ok)
        self.assertIn("over the", result.detail)

    def test_oversized_fel_primary_fails(self):
        result = self.build(
            ImageRunner(
                readelf="  [ 1] .text             PROGBITS\n",
                primary=b"\x00" * 0x4F001,
            ),
            ["fel"],
        )
        self.assertFalse(result.ok)
        self.assertIn("over the", result.detail)

    def test_fel_row_at_0x4a7ac_passes(self):
        result = self.build(
            ImageRunner(
                readelf="  [ 1] .text             PROGBITS\n",
                primary=b"\x00" * 0x4A7AC,
            ),
            ["fel"],
            baseline_required=False,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.size, 0x4A7AC)

    def test_fel_row_at_0x4a32c_passes(self):
        result = self.build(
            ImageRunner(
                readelf="  [ 1] .text             PROGBITS\n",
                primary=b"\x00" * 0x4A32C,
            ),
            ["fel"],
            baseline_required=False,
        )
        self.assertTrue(result.ok)

    def test_missing_dram_extension_fails(self):
        result = self.build(
            ImageRunner(
                readelf="  [ 1] .dram PROGBITS 59000000 010000 000004 00\n",
                primary=valid_media_image(),
                ext=b"",
            ),
            ["fel", "fastboot"],
            baseline_required=False,
        )
        self.assertFalse(result.ok)
        self.assertIn("extension .dram empty", result.detail)

    def test_lab_does_not_accept_phyfw_in_place_of_dram(self):
        result = self.build(
            ImageRunner(
                readelf="  [ 2] .phyfw NOBITS 00047000 000000 000004 00\n",
                primary=valid_media_image(),
                ext=b"",
            ),
            ["fel", "bl-mission", "dram-lab", "drift-log"],
            baseline_required=False,
            no_default=True,
        )
        self.assertFalse(result.ok)
        self.assertIn(
            "expected payload sections ('.dram',), found ('.phyfw',)", result.detail
        )

    def test_lab_dram_marker_is_validated(self):
        result = self.build(
            ImageRunner(
                readelf="  [ 1] .dram PROGBITS 59000000 010000 000004 00\n",
                primary=valid_media_image(),
                ext=b"A7AX",
            ),
            ["fel", "bl-mission", "dram-lab", "drift-log"],
            baseline_required=False,
            no_default=True,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.baseline, verify.BASELINE_NEW)

    def test_media_header_is_checked(self):
        result = self.build(
            ImageRunner(
                readelf="  [ 1] .text             PROGBITS\n",
                primary=valid_media_image(magic=b"BADMAGIC!"),
            ),
            [],
            baseline_required=False,
        )
        self.assertFalse(result.ok)
        self.assertIn("no eGON.BT0 magic", result.detail)

    def test_media_header_rejects_a_fel_run_address(self):
        result = self.build(
            ImageRunner(
                readelf="  [ 1] .text             PROGBITS\n",
                primary=valid_media_image(run=0x90000),
            ),
            [],
            baseline_required=False,
        )
        self.assertFalse(result.ok)
        self.assertIn("run address", result.detail)

    def test_valid_media_header_passes(self):
        result = self.build(
            ImageRunner(
                readelf="  [ 1] .text             PROGBITS\n",
                primary=valid_media_image(),
            ),
            [],
            baseline_required=False,
        )
        self.assertTrue(result.ok)


class PureLogicTest(unittest.TestCase):
    def test_negative_contract_requires_the_exact_diagnostic(self):
        ok, _ = verify.negative_contract_ok(
            1, "error: " + verify.CONFLICT_DIAGNOSTIC, verify.CONFLICT_DIAGNOSTIC
        )
        self.assertTrue(ok)

    def test_negative_contract_rejects_a_partial_diagnostic(self):
        partial = (
            "another DRAM backend or a lab feature together with the default "
            "feature `blobfree`"
        )
        ok, _ = verify.negative_contract_ok(
            1, "error: " + partial, verify.CONFLICT_DIAGNOSTIC
        )
        self.assertFalse(ok)

    def test_negative_contract_rejects_success(self):
        ok, _ = verify.negative_contract_ok(0, "", verify.CONFLICT_DIAGNOSTIC)
        self.assertFalse(ok)

    def test_negative_contract_rejects_an_arbitrary_failure(self):
        ok, _ = verify.negative_contract_ok(
            1, "error: unused manifest key", verify.CONFLICT_DIAGNOSTIC
        )
        self.assertFalse(ok)

    def test_matrix_ok_requires_main_equality(self):
        self.assertTrue(verify.matrix_ok([], 11, 11, 11))
        self.assertFalse(verify.matrix_ok([], 11, 11, 10))
        self.assertFalse(verify.matrix_ok(["main-gmac"], 11, 10, 10))

    def test_payload_section_expectations(self):
        self.assertEqual(verify.expected_sections([], False), ())
        self.assertEqual(
            verify.expected_sections(["fastboot-emmc-write"], False), (".dram",)
        )
        self.assertEqual(
            verify.expected_sections(["bl-mission", "dram-lab"], True), (".dram",)
        )
        self.assertEqual(
            verify.expected_sections(["dram-lab"], True), (".dram", ".phyfw")
        )

    def test_test_result_requires_one_complete_line(self):
        line = "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        self.assertEqual(verify.completed_test_result(line), (True, 2, 0, 0))
        self.assertIsNone(verify.completed_test_result(line + line))
        self.assertIsNone(verify.completed_test_result(line[:48]))

    def test_required_baseline_count(self):
        names = verify.required_baseline_names()
        self.assertEqual(len(names), 70)
        self.assertEqual(sum(name.endswith("-ext.bin") for name in names), 9)

    def test_read_main_max(self):
        with tempfile.TemporaryDirectory(
            prefix="verify-a7a-pure-", dir=home_tmp()
        ) as tmp:
            source = make_source(Path(tmp) / "oreboot")
            self.assertEqual(
                verify.read_cap(source / verify.COMMON_LIB, verify.MAIN_MAX_RE),
                0x0008_0000,
            )

    def test_egon_header_accepts_the_raw_media_image(self):
        self.assertIsNone(verify.check_egon_header(valid_media_image()))

    def test_egon_header_rejects_a_short_image(self):
        self.assertIsNotNone(verify.check_egon_header(b"eGON.BT0"))

    def test_digest_argument_rejects_a_bad_sha(self):
        with self.assertRaises(SystemExit):
            verify.parse_args(
                [
                    "--source",
                    "x",
                    "--source-sha",
                    "0" * 40,
                    "--base",
                    "HEAD",
                    "--baseline",
                    "b",
                    "--baseline-sums-sha256",
                    ZERO,
                    "--dram-lib",
                    "d",
                    "--phyfw-obj",
                    "p",
                    "--gate",
                    "g",
                    "--out",
                    "o",
                    "--expect-digest",
                    "default=zzz",
                ]
            )


if __name__ == "__main__":
    unittest.main()
