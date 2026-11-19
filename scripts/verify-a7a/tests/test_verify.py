#!/usr/bin/env python3
"""Quick regression suite for the A7A verification harness.

The tests exercise the fail-closed orchestration with controlled stage results
and real path checks; they do not run cargo or the external gate. Run with:

    python3 -I scripts/verify-a7a/tests/test_verify.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import verify  # noqa: E402

ZERO = "0" * 64


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
        new_differ=len(verify.NEW_ENTRIES),
        lab_total=len(verify.LAB_ENTRIES),
        lab_ok=len(verify.LAB_ENTRIES),
        main_total=len(verify.MAIN_SETS),
        main_ok=len(verify.MAIN_SETS),
        main_identical=len(verify.MAIN_SETS),
        failures=[],
    )


def green_negative() -> verify.NegativeResult:
    return verify.NegativeResult(
        ok=True, returncode=1, diagnostic_found=True, detail="expected diagnostic"
    )


def green_suites() -> verify.SuitesResult:
    return verify.SuitesResult(
        ok=True,
        results=[
            verify.SuiteResult(directory, True, 1, 0, 0, "exit 0")
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
    ):
        super().__init__(args)
        self._matrix = green_matrix() if matrix is None else matrix
        self._negative = green_negative() if negative is None else negative
        self._suites = green_suites() if suites is None else suites
        self._gate = green_gate() if gate is None else gate
        self._digests = green_digests() if digests is None else digests

    def run_matrix(self):
        return self._matrix

    def run_negative(self):
        return self._negative

    def run_suites(self):
        return self._suites

    def run_gate(self):
        return self._gate

    def check_digests(self):
        return self._digests


def run(cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


def make_source(root: Path, suites=verify.SUITE_DIRS) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    run(["git", "init", "-q"], root)
    for rel in (verify.BT0_DIR, verify.MAIN_DIR, *suites):
        (root / rel).mkdir(parents=True, exist_ok=True)
    (root / "README").write_text("fixture\n", encoding="utf-8")
    run(["git", "add", "-A"], root)
    run(
        [
            "git",
            "-c",
            "user.name=DaveWK",
            "-c",
            "user.email=13626476+DaveWK@users.noreply.github.com",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
        root,
    )
    return root


def make_baseline(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name in verify.required_baseline_names():
        (root / name).write_bytes(b"")
    return root


def make_args(tmp: Path, source: Path, baseline: Path, gate: Path, out: Path):
    return verify.Config(
        source=source,
        base="HEAD",
        head="HEAD",
        baseline=baseline,
        dram_lib=tmp / "libdram-a733.a",
        phyfw_obj=tmp / "libdram",
        gate=gate,
        out=out,
        expected_digests={name: ZERO for name in verify.DIGEST_NAMES},
    )


class HarnessRegressionTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.source = make_source(self.tmp / "oreboot")
        self.baseline = make_baseline(self.tmp / "baseline")
        self.gate = self.tmp / "gate.py"
        self.gate.write_text("", encoding="utf-8")
        (self.tmp / "libdram-a733.a").write_bytes(b"")
        (self.tmp / "libdram").write_bytes(b"")
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
                    verify.SUITE_DIRS[0], False, 0, 1, 0, "exit 1; failed 1"
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

    def test_digest_mismatch_returns_nonzero(self):
        bad = verify.DigestsResult(
            ok=False,
            results=[
                verify.DigestResult(name, ZERO, "1" * 64, False)
                for name in verify.DIGEST_NAMES
            ],
        )
        self.assertNotEqual(FakeHarness(self.args(), digests=bad).run(), 0)

    def test_real_gate_failure_is_failure(self):
        gate = self.tmp / "failing-gate.py"
        gate.write_text(
            "#!/usr/bin/env python3\nimport sys\nsys.exit(1)\n", encoding="utf-8"
        )
        harness = verify.Harness(self.args(gate=gate))
        self.assertEqual(harness.check_paths(), [])
        result = harness.run_gate()
        self.assertFalse(result.ok)
        self.assertEqual(result.returncode, 1)

    def test_runner_missing_executable_is_failure(self):
        result = verify.SubprocessRunner().run(
            ["verify-a7a-definitely-missing-command"], self.tmp, {}
        )
        self.assertNotEqual(result.returncode, 0)


class PureLogicTest(unittest.TestCase):
    def test_negative_contract_requires_the_expected_diagnostic(self):
        ok, _ = verify.negative_contract_ok(1, "error: " + verify.CONFLICT_DIAGNOSTIC)
        self.assertTrue(ok)

    def test_negative_contract_rejects_success(self):
        ok, _ = verify.negative_contract_ok(0, "")
        self.assertFalse(ok)

    def test_negative_contract_rejects_arbitrary_failure(self):
        ok, _ = verify.negative_contract_ok(1, "error: unused manifest key")
        self.assertFalse(ok)

    def test_dram_section_detection_allows_readelf_indent(self):
        self.assertTrue(
            verify.has_dram_section(
                "  [Nr] Name              Type\n"
                "  [ 1] .dram             PROGBITS        59000000 010000 000004\n"
            )
        )
        self.assertFalse(
            verify.has_dram_section(
                "  [Nr] Name              Type\n"
                "  [ 1] .text             PROGBITS        00090000 020000 000050\n"
            )
        )

    def test_test_results_aggregate_every_binary(self):
        output = (
            "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered\n"
            "test result: ok. 3 passed; 1 failed; 0 ignored; 0 measured; 0 filtered\n"
        )
        self.assertEqual(verify.parse_test_results(output), (5, 1, 0, True))

    def test_test_results_require_a_result_line(self):
        self.assertEqual(
            verify.parse_test_results("error[E0432]: no result"), (0, 0, 0, False)
        )

    def test_required_baseline_count(self):
        self.assertEqual(
            len(verify.required_baseline_names()),
            len(verify.OLD_SETS) + len(verify.NEW_ENTRIES) + len(verify.MAIN_SETS),
        )

    def test_digest_argument_rejects_a_bad_sha(self):
        with self.assertRaises(SystemExit):
            verify.parse_args(
                [
                    "--source",
                    "x",
                    "--base",
                    "HEAD",
                    "--baseline",
                    "b",
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
