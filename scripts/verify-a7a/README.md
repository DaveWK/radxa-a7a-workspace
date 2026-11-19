# verify-a7a

Host-only verification harness for the Radxa Cubie A7A oreboot `bt0`/`main`
build matrix. It is the maintained board-integration matrix for this workspace:
the previous harness lived in a private scratch tree and masked a failing build.

    python3 -I scripts/verify-a7a/verify.py \
        --source <oreboot-checkout> \
        --source-sha <full-head-sha> \
        --base <gate-base-revision> \
        --baseline <matrix-baseline-dir> \
        --baseline-sums-sha256 <sha256-of-baseline-SHA256SUMS> \
        --dram-lib <libdram-a733.a> \
        --phyfw-obj <libdram-object> \
        --gate <gate.py> \
        --out <job-output-dir> \
        --expect-digest default=<sha256> \
        --expect-digest default-fel=<sha256> \
        --expect-digest default@2400=<sha256> \
        --expect-digest default-fel@2400=<sha256>

All inputs are explicit. The source checkout is an oreboot clone whose HEAD
must equal `--source-sha`; the gate base must be an ancestor of that HEAD. The
baseline directory is the retained matrix output at the gate base, and its
`SHA256SUMS` manifest must hash to `--baseline-sums-sha256`. The gate and the
two build inputs are external private artifacts and are never vendored here.

## What it checks

- **Matrix**: the 38 OLD feature sets built with `--no-default-features`, the
  17 NEW default-feature sets (12 with a retained baseline, plus the new
  `default+full-speed` and the `default`/`fel` 800 and 400 MHz profile rows,
  which have no historical baseline and are labelled as such), and the two `lab`
  entries (`lab-drift`, `lab-full-speed`) built with `--no-default-features`
  (57 positive `bt0` builds), plus the 11 `main` sets. OLD and NEW are compared
  with the baseline; the lab and new no-baseline rows are labelled new. The
  historical OLD/NEW differences stay visible in the report. Every `main` image
  must be byte-identical to the baseline.
- **Negative contract**: each negative row must fail with its own exact
  `compile_error` diagnostic, not for an arbitrary reason. The rows are the
  default feature plus `dram-lab`, `dramlib` or `blobless` (the `blobfree`
  conflict), the original `fel dram-lab drift-log` invalid positive, and
  `fel` plus `spinor`.
- **Images by content**: every produced image is checked, not trusted from
  `objcopy`'s exit status. The primary must be nonempty and within its class
  limit (eGON media `bt0` 0x4A000 per `scripts/mkimage.py`; FEL `bt0` 0x4F000
  per `bt0/build.rs`; `main` `MAIN_MAX_SIZE` read from the source). Media rows
  must carry the raw eGON.BT0 header (magic, header size, media run address and
  the unfilled length/checksum placeholders). Every `.dram`/`.phyfw` extension
  is extracted, validated nonempty (including lab rows with no baseline) and
  compared with the baseline when one exists.
- **Host suites**: `dram`, `fastboot`, `common`, `src/lib/bootlog` and
  `src/lib/dram-train`. The expected test binaries are taken from
  `cargo test --no-run --message-format=json` and reconciled with the binaries
  `cargo test` actually runs; every `test result:` line is aggregated, at least
  one test must execute, and a missing suite directory, a missing result line or
  a nonzero exit is a failure. Individual zero-test doctests are allowed.
- **External gate**: the gate script is run with the source path and the
  resolved full base and head SHAs; its real exit status and full output are
  reported.
- **Default digests**: the four produced default images are compared with the
  four full SHA256 values given on the command line.

## Fail-closed behaviour

Every stage's real exit status is checked. A missing source, baseline directory,
required baseline image, suite directory, build input or gate is a failure. The
source must be a clean git worktree at `--source-sha` with the base as an
ancestor; the HEAD and the worktree cleanliness are rechecked after the build,
before PASS. The output directory must be fresh: an existing non-empty
directory is refused, so no stale `.bin` can reach `SHA256SUMS`. The output,
`TMPDIR` and the cargo target directories must not overlap the source, the
baseline or any input. Every path is resolved to an absolute path at entry.

Cargo runs with `--locked`, `GIT_OPTIONAL_LOCKS=0` and `RUSTUP_AUTO_INSTALL=0`;
the pinned toolchain and its targets from `rust-toolchain.toml` are checked
before the build. No `grep`/`tail` pipeline or last-successful-stage summary can
hide a failure. Warnings are reported with their file and line, not suppressed.

Exit status is `0` only when every stage passes; `1` for a verification failure;
`2` for bad arguments.

## Job output

`<job-output-dir>` receives `matrix/logs/`, `matrix/out/` (with `SHA256SUMS`),
`target/`, `tests/` and `gate.log`. Cargo targets and `TMPDIR` stay under this
directory; the source checkout is never written to.

The job output is private: it contains vendor-library variants and PHY
extraction, so it is never published or committed. Keep it under the job
directory (or another private scratch area), not in Git.

## Regression tests

    python3 -I -B scripts/verify-a7a/tests/test_verify.py

The suite is quick and needs no cargo: it drives the fail-closed orchestration
with controlled stage results and real path checks (matrix failure, failing,
empty or missing suite, inventory reconciliation, failing or missing gate, a
gate given the wrong SHA, missing baseline, digest mismatch, stale output,
output overlap, wrong source SHA, a non-ancestor base, a dirty tree after the
build, image size/extension/header validation, all-green). The tests use a
HOME-scoped `TMPDIR`, never `/tmp`.
