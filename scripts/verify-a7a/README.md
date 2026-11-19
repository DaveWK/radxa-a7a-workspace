# verify-a7a

Host-only verification harness for the Radxa Cubie A7A oreboot `bt0`/`main`
build matrix. It is the maintained board-integration matrix for this workspace:
the previous harness lived in a private scratch tree and masked a failing build.

    python3 -I scripts/verify-a7a/verify.py \
        --source <oreboot-checkout> \
        --base <gate-base-revision> \
        --baseline <matrix-baseline-dir> \
        --dram-lib <libdram-a733.a> \
        --phyfw-obj <libdram-object> \
        --gate <gate.py> \
        --out <job-output-dir> \
        --expect-digest default=<sha256> \
        --expect-digest default-fel=<sha256> \
        --expect-digest default@2400=<sha256> \
        --expect-digest default-fel@2400=<sha256>

All inputs are explicit. The source checkout is an oreboot clone at the exact
revision under test; the baseline directory is the retained matrix output at the
gate base; the gate and the two build inputs are external private artifacts and
are never vendored here.

## What it checks

- **Matrix**: the 38 OLD feature sets built with `--no-default-features`, the 12
  valid NEW default-feature sets, and the one `lab-drift` lab entry built with
  `--no-default-features --features 'fel bl-mission dram-lab drift-log'`
  (51 positive `bt0` builds), plus the 11 `main` sets. OLD and NEW are compared
  with the baseline; `lab-drift` is labelled new with no historical baseline.
  The historical OLD/NEW differences stay visible in the report.
- **Negative contract**: `cargo build --offline --release --features
  'fel dram-lab drift-log'` (default features plus a lab feature) must fail
  with the `blobfree` feature-conflict `compile_error`, not for an arbitrary
  reason.
- **Host suites**: `dram`, `fastboot`, `common`, `src/lib/bootlog` and
  `src/lib/dram-train`. Every `test result:` line is aggregated; a missing
  suite directory, a missing result line or a nonzero exit is a failure.
- **External gate**: the gate script is run with the source, base and head; its
  real exit status and full output are reported.
- **Default digests**: the four produced default images are compared with the
  four full SHA256 values given on the command line.

## Fail-closed behaviour

Every stage's real exit status is checked. A missing source, baseline directory,
required baseline image, suite directory, build input or gate is a failure. The
source must be a clean git worktree at a revision that contains the base. No
`grep`/`tail` pipeline or last-successful-stage summary can hide a failure.
Warnings are reported, not suppressed.

Exit status is `0` only when every stage passes; `1` for a verification failure;
`2` for bad arguments.

## Job output

`<job-output-dir>` receives `matrix/logs/`, `matrix/out/` (with `SHA256SUMS`),
`target/`, `tests/` and `gate.log`. Cargo targets and `TMPDIR` stay under this
directory; the source checkout is never written to.

## Regression tests

    python3 -I scripts/verify-a7a/tests/test_verify.py

The suite is quick and needs no cargo: it drives the fail-closed orchestration
with controlled stage results and real path checks (matrix failure, failing or
missing suite, failing or missing gate, missing baseline, digest mismatch,
all-green). The pure diagnostic and test-result parsers are unit-tested too.
