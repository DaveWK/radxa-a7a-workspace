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
        --dram-lib-sha256 <sha256> \
        --phyfw-obj <libdram-object> \
        --phyfw-obj-sha256 <sha256> \
        --gate <gate.py> \
        --gate-sha256 <sha256> \
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
Each requires a full 64-hex SHA256. Before creating the job directory, the
harness opens each input once, hashing while copying to private staging, then
rehashes the copy. The DRAM library snapshot must have normal ar magic
(`!<arch>\n`); the PHY input must have normal ar or ELF magic. Thin archives
are refused because they can reference unpinned external members. Only the
verified files move into the job; the linker, PHY extractor and gate use the
copies, not the original paths. The report lists their SHA256 values, snapshot
paths and detected binary input formats.

## Threat model

The harness guards against false greens from accidents on a single-user bench
host: stale, mixed, truncated or empty inputs and outputs; ambient Git, Cargo
or toolchain configuration; a parent repository mistaken for the source; and
a missing section, binary or test result counted as success. It does not
defend against a malicious local user who can edit the harness. It uses no
signing or daemon.

## What it checks

- **Matrix**: the 38 OLD feature sets built with `--no-default-features`, the
  17 NEW default-feature sets (12 with a retained baseline, plus the new
  `default+full-speed` and the `default`/`fel` 800 and 400 MHz profile rows,
  which have no historical baseline and are labelled as such), and three `lab`
  entries (`lab-dram`, `lab-drift`, `lab-full-speed`) built with `--no-default-features`
  (58 positive `bt0` builds), plus the 11 `main` sets. OLD and NEW are compared
  with the baseline; the lab and new no-baseline rows are labelled new. The
  historical OLD/NEW differences stay visible in the report. Every `main` image
  must be byte-identical to the baseline. The manifest is read once: the parsed
  bytes are the hashed bytes, and every compared primary and extension is
  required. An unchanged primary with a different extension fails as a mixed
  row. Both the baseline comparison and emitted `SHA256SUMS` use the digests of
  the validated bytes, not reopened paths.
- **Negative contract**: each negative row must fail with its own exact
  diagnostic, not for an arbitrary reason. The rows are the
  default feature plus `dram-lab`, `dramlib` or `blobless` (the `blobfree`
  conflict), the original `fel dram-lab drift-log` invalid positive, and
  `fel` plus `spinor`, and `dram-lab phyfw` (`phyfw` is a command, not a feature).
- **Instructions**: the pinned toolchain's `llvm-objdump` disassembles each ELF
  before the next build replaces it. ARM exclusives fail the `bt0` row. For
  `main`, AArch64 exclusives and LSE atomics are reported but do not fail the
  row; this is not a claim that the MMU is enabled along every path.
- **Images by content**: every produced image is checked, not trusted from
  `objcopy`'s exit status. The primary must be nonempty and within its class
  limit (padded eGON media `bt0` from `EGON_MAX` and `EGON_PAD` in
  `scripts/mkimage.py`; FEL `bt0` from `MEMORY_FEL` in the source's `bt0/build.rs`;
  `main` from `MAIN_MAX_SIZE` in `common/src/lib.rs`). Media rows
  must carry the raw eGON.BT0 header (magic, header size, media run address and
  the unfilled length/checksum placeholders). The row's features declare which
  `.dram` and `.phyfw` payload sections must be present or absent. Each expected
  section is stripped from the primary. File-backed extensions are exported
  separately, with nonzero size checked against the ELF. In `lab-dram`,
  `.phyfw` must instead reserve writable, allocated NOBITS space at the start
  of FELSRAM, aligned to at least 4, fitting the SRAM window and matching
  the six lengths in this build's generated `phy-fw-lab.rs`. It has no
  corresponding exported file. At the verified source, `lab-drift`
  and `lab-full-speed` each carry a **4-byte `.dram` marker** (`A7AX`), not a
  `.phyfw` extension: `dram-lab` enables fastboot and `bl-mission` selects the
  blobless backend.
- **Host suites**: `dram`, `fastboot`, `common`, `src/lib/bootlog` and
  `src/lib/dram-train`. The expected test binaries are taken from
  `cargo test --no-run --message-format=json`. Each executable is run directly
  and must exit zero with exactly one completed, successful `test result:` line
  on stdout and at least one passing test. Each binary has a separate log with
  stdout and stderr in stream order. The five named library doctest targets
  run separately and are expected to report zero tests.
- **External gate**: the gate script is run with the source path and the
  resolved full base and head SHAs; its real exit status and full output are
  reported.
- **Default digests**: the four produced default images are compared with the
  four full SHA256 values given on the command line.

## Fail-closed behaviour

Every stage's real exit status is checked. A missing source, baseline directory,
required baseline image, suite directory, build input or gate is a failure.
`--source` must be the absolute root of its own clean Git worktree at
`--source-sha`, with the base as an ancestor. Both that tree and the workspace
that runs the harness must be clean, full Git worktrees. Sparse checkout,
skip-worktree and assume-unchanged entries, and missing or wrong-type tracked
paths are refused. The source checkout must not contain any Git submodule
entries (gitlinks); the harness does not recurse into submodules. Both
checkouts are rechecked before PASS. Input checks
finish before creating the output directory exclusively (0700); even an
existing empty output is refused. Before creating staging or running Cargo,
the harness rejects `--out` if it resolves to a path overlapping the workspace,
source, baseline or any other protected input. `TMPDIR` and both Cargo output
locations are inside the job directory.

Git runs with only `PATH`, `HOME` and the harness's isolation settings: no
inherited Git variables, no system or global config, and optional locks
disabled. Cargo runs offline and locked in a clean environment with both
`CARGO_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR` set explicitly. It seeds a
private Cargo home from the local offline caches under `~/.cargo` without
sharing configuration, credentials or write locations. The cache is prepared
in private staging before the job exists; a symlink in a cache tree or its
root path is refused, leaving no job directory. The executable paths
resolved by `rustup which` in the source must match the exact channel in
`rust-toolchain.toml`; the installed targets are checked and the actual
`rustc -vV` and `cargo -V` recorded. Toolchain auto-install is disabled.
Warnings are reported, not suppressed.

Exit status is `0` only when every stage passes; `1` for a verification failure;
`2` for bad arguments.

## Job output

`<job-output-dir>` receives `matrix/logs/`, `matrix/out/` (with `SHA256SUMS`),
`target/`, `build/`, `cargo-home/`, `inputs/`, `tests/`, `tmp/` and `gate.log`.
The source checkout is never written to.

The job output is private: it contains vendor-library variants and PHY
extraction, so it is never published or committed. Keep it under the job
directory (or another private scratch area), not in Git.

## Regression tests

    python3 -I -B scripts/verify-a7a/tests/test_verify.py
    python3 -I -B scripts/verify-a7a/tests/test_h2.py

The suites are quick and need no Cargo: they drive the fail-closed orchestration
with controlled stage results and real path checks (matrix failure, failing,
empty or missing suite, inventory reconciliation, failing or missing gate, a
gate given the wrong SHA, missing baseline, digest mismatch, stale output,
output overlap, wrong source SHA, a non-ancestor base, a dirty tree after the
build, image size/extension/header validation, all-green). The H2 tests drive
the real CLI entry point with controlled build and inventory outputs and
exercise hash-time replacements, ambient configuration, section inventory and
per-binary completion. H3 adds checkout and cache refusals and exercises the
verified archive with a real host `cc` and `ar`. Set `VERIFY_A7A_OREBOOT` to a
clean oreboot clone to run the source cases on copies of that clone; otherwise
they use a miniature Git fixture. The tests use a HOME-scoped `TMPDIR`, never
`/tmp`.
