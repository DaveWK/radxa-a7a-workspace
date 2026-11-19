#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Drive the real CLI entry point with small, controlled tool outputs."""

from contextlib import ExitStack, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

VERIFY_PATH = Path(
    os.environ.get("VERIFY_A7A_UNDER_TEST")
    or Path(__file__).resolve().parents[1] / "verify.py"
)
SPEC = importlib.util.spec_from_file_location("verify_a7a", VERIFY_PATH)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)

HOST = "x86_64-unknown-linux-gnu"
SUITE = verify.SUITE_DIRS[-1]
FEL_DEF = f"{verify.BT0_DIR}/build.rs"
FASTBOOT = ("default-fel+fastboot", None, ("fel", "fastboot"), True)
LAB = ("lab-drift", ("fel", "bl-mission", "dram-lab", "drift-log"))
NEGATIVE = verify.NEGATIVE_ENTRIES[0]
EXT = b"A7AX"
MAIN = b"main fixture"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def summary(passed=1, failed=0):
    status = "ok" if failed == 0 else "FAILED"
    return (
        f"test result: {status}. {passed} passed; {failed} failed; 0 ignored; "
        "0 measured; 0 filtered out; finished in 0.00s\n"
    )


def media():
    data = bytearray(48)
    data[4:12] = b"eGON.BT0"
    for offset, value in (
        (0x0C, verify.EGON_STAMP),
        (0x14, verify.EGON_HEADER_SIZE),
        (0x20, verify.MEDIA_RUN_ADDR),
    ):
        data[offset : offset + 4] = value.to_bytes(4, "little")
    return bytes(data)


class BenchTools(verify.SubprocessRunner):
    """Fake compilers only; Git, the gate and individual test binaries are real."""

    def __init__(self, bench):
        self.bench = bench
        self.cargo_envs = []
        self.git_envs = []
        self.row = ""
        self.objcopies = []
        self.paths = []

    @staticmethod
    def response(argv, cwd, rc=0, stdout="", stderr=""):
        if hasattr(verify.CommandResult, "stderr"):
            return verify.CommandResult(tuple(argv), str(cwd), rc, stdout, stderr)
        return verify.CommandResult(tuple(argv), str(cwd), rc, stdout + stderr)

    def run(self, argv, cwd, env, log=None):
        b = self.bench
        cmd = Path(argv[0]).name
        if cmd == "git":
            self.git_envs.append(dict(env))
        if cmd == "git" or cmd.startswith("python") or cmd.startswith("suite-"):
            return super().run(argv, cwd, env, log)
        kwargs = {}
        if cmd == "rustup":
            if argv[1] == "which":
                pinned = len(argv) > 3 or not b.wrong_toolchain
                directory = (
                    b.pinned_bin
                    if pinned
                    else b.pinned_bin.parents[1] / "other" / "bin"
                )
                kwargs["stdout"] = f"{directory / argv[-1]}\n"
            elif argv[1] == "run":
                kwargs["stdout"] = f"host: {HOST}\n"
        elif cmd == "rustc":
            kwargs["stdout"] = f"host: {HOST}\nrelease: 1.97.0\n"
        elif cmd == "cargo" and argv[1:] == ["-V"]:
            kwargs["stdout"] = "cargo 1.97.0 (fixture)\n"
        elif cmd == "cargo":
            self.cargo_envs.append(dict(env))
            target = Path(env["CARGO_TARGET_DIR"])
            if "CARGO_BUILD_BUILD_DIR" in env:
                build = Path(env["CARGO_BUILD_BUILD_DIR"])
                build.mkdir(parents=True, exist_ok=True)
                (build / "intermediate").write_bytes(b"cargo intermediate")
            if argv[1] == "build":
                self.row = log.stem
                if self.row.startswith("negative-"):
                    kwargs.update(
                        rc=101, stderr=f"error: {NEGATIVE[-1]}{b.diagnostic_suffix}\n"
                    )
                else:
                    elf = (
                        "aarch64-unknown-none-softfloat/release/oreboot-cubie-a7a-main"
                        if self.row.startswith("main-")
                        else "armv7a-none-eabi/release/oreboot-cubie-a7a-bt0"
                    )
                    path = target / elf
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"synthetic ELF")
            elif "--no-run" in argv:
                self.paths = [target / "suite-one", target / "suite-two"]
                target.mkdir(parents=True, exist_ok=True)
                for index, path in enumerate(self.paths):
                    if index == 1 and b.missing_binary:
                        continue
                    if index == 1 and b.crash:
                        script = "exit 7\n"
                    else:
                        passed = 0 if index == 1 and b.empty_binary else 1
                        script = f"printf '%s\\n' '{summary(passed).rstrip()}'\n"
                        if b.stderr_noise:
                            script = (
                                "printf '%s\\n' 'first stderr line' >&2\n"
                                + script
                                + f"printf '%s\\n' '{summary(0, 1).rstrip()}' >&2\n"
                                + "printf '%s\\n' 'last stderr line' >&2\n"
                            )
                    path.write_text("#!/bin/sh\n" + script, encoding="utf-8")
                    path.chmod(0o700)
                records = [
                    dict(
                        reason="compiler-artifact",
                        target={"test": True},
                        profile={"test": True},
                        executable=str(path),
                    )
                    for path in self.paths
                ]
                records.append(dict(reason="build-finished", success=True))
                kwargs["stdout"] = "".join(json.dumps(item) + "\n" for item in records)
            elif "--doc" in argv:
                kwargs.update(stdout=summary(0), stderr="   Doc-tests dram_train\n")
            else:
                # Baseline CLI trusts these launch announcements despite one
                # executable not having a completed result.
                kwargs["stdout"] = (
                    "".join(f"     Running unittests ({path})\n" for path in self.paths)
                    + summary()
                    + summary(0)
                )
                if b.stderr_noise:
                    kwargs["stderr"] = summary(0, 1)
        elif cmd == "llvm-readelf":
            sections = []
            if (
                self.row == f"bt0-{FASTBOOT[0]}"
                or self.row == "bt0-lab-both"
                or (self.row == f"bt0-{LAB[0]}" and not b.missing_dram)
            ):
                sections.append(".dram")
            if self.row == "bt0-lab-both":
                sections.append(".phyfw")
            lines = [
                f"There are {len(sections) + 1} section headers, starting at offset 0x0:"
            ]
            lines.append("  [ 0] .text PROGBITS 00000000 000001 000001 00")
            lines.extend(
                f"  [ {i}] {name} PROGBITS 59000000 010000 000004 00"
                for i, name in enumerate(sections, 1)
            )
            kwargs["stdout"] = "\n".join(lines) + "\n"
        elif cmd == "llvm-objcopy":
            self.objcopies.append(tuple(argv))
            path = Path(argv[-1])
            if "--only-section=.phyfw" not in argv:
                data = (
                    b.extension
                    if "--only-section=.dram" in argv
                    else b.images.get(self.row + ".bin", EXT)
                )
                path.write_bytes(data)
        else:
            raise AssertionError(f"unexpected command: {argv!r}")
        if log is not None:
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(kwargs.get("stderr", ""), encoding="utf-8")
        return self.response(argv, cwd, **kwargs)


class CliTest(unittest.TestCase):
    def setUp(self):
        temp = (
            os.environ.get("TMPDIR")
            or Path.home() / ".cache" / "A7A" / "verify-a7a-tests"
        )
        Path(temp).mkdir(parents=True, exist_ok=True)
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(dir=temp)))
        self.home = self.root / "home"
        self.home.mkdir()
        self.source = self.root / "source"
        self.baseline = self.root / "baseline"
        self.baseline.mkdir()
        self.manifest = self.baseline / "SHA256SUMS"
        self.out = self.root / "out"
        self.pinned_bin = (
            self.home / ".rustup" / "toolchains" / f"1.97.0-{HOST}" / "bin"
        )
        self.pinned_bin.mkdir(parents=True)
        for tool in ("cargo", "rustc", "rustdoc"):
            (self.pinned_bin / tool).write_bytes(b"mock tool")
        for rel in (verify.BT0_DIR, verify.MAIN_DIR, SUITE):
            directory = self.source / rel
            directory.mkdir(parents=True)
            (directory / "README").write_text("fixture\n", encoding="utf-8")
        for name, content in (
            (verify.COMMON_LIB, "pub const MAIN_MAX_SIZE: usize = 0x80000;\n"),
            (
                FEL_DEF,
                'const MEMORY_FEL: &str = "SRAM : ORIGIN = 0x90000, LENGTH = 0x4f000";\n',
            ),
            ("rust-toolchain.toml", '[toolchain]\nchannel = "1.97.0"\n'),
        ):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        self.commit(self.source)
        self.dram_lib = self.root / "libdram-a733.a"
        self.phyfw = self.root / "libdram"
        self.gate = self.root / "gate.py"
        for path, content in (
            (self.dram_lib, b"dummy archive"),
            (self.phyfw, b"dummy object"),
            (self.gate, b"print('fixture gate')\n"),
        ):
            path.write_bytes(content)
        self.images = {
            f"bt0-{name}.bin": (
                media() + name.encode() if "-fel" not in name else name.encode()
            )
            for name in verify.DIGEST_NAMES
        }
        self.images.update(
            {"main-none.bin": MAIN, f"bt0-{FASTBOOT[0]}.bin": b"fastboot primary"}
        )
        self.write_manifest({**self.images, f"bt0-{FASTBOOT[0]}-ext.bin": EXT})
        self.lab = LAB
        self.extension = EXT
        self.missing_dram = False
        self.missing_binary = False
        self.crash = False
        self.stderr_noise = False
        self.empty_binary = False
        self.wrong_toolchain = False
        self.diagnostic_suffix = ""

    def git(self, cwd, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        return subprocess.run(
            ["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True
        ).stdout.strip()

    def commit(self, root):
        self.git(root, "init", "-q")
        self.git(root, "add", ".")
        self.git(
            root,
            "-c",
            "user.name=DaveWK",
            "-c",
            "user.email=13626476+DaveWK@users.noreply.github.com",
            "commit",
            "-qm",
            "fixture",
        )

    def write_manifest(self, files):
        lines = []
        for name, content in files.items():
            (self.baseline / name).write_bytes(content)
            lines.append(f"{digest(content)}  {name}\n")
        self.manifest.write_text("".join(lines), encoding="ascii")

    def invoke(self, env=None):
        sha = self.git(self.source, "rev-parse", "HEAD")
        argv = [
            "--source",
            str(self.source),
            "--source-sha",
            sha,
            "--base",
            sha,
            "--baseline",
            str(self.baseline),
            "--baseline-sums-sha256",
            digest(self.manifest.read_bytes()),
            "--dram-lib",
            str(self.dram_lib),
            "--phyfw-obj",
            str(self.phyfw),
            "--gate",
            str(self.gate),
            "--out",
            str(self.out),
        ]
        for name in verify.DIGEST_NAMES:
            argv.extend(
                ["--expect-digest", f"{name}={digest(self.images[f'bt0-{name}.bin'])}"]
            )
        self.tools = BenchTools(self)
        with ExitStack() as stack:
            stack.enter_context(
                patch.dict(os.environ, {"HOME": str(self.home), **(env or {})})
            )
            stack.enter_context(
                patch.multiple(
                    verify,
                    SubprocessRunner=lambda: self.tools,
                    OLD_SETS=(),
                    NEW_ENTRIES=tuple(
                        row
                        for row in verify.NEW_ENTRIES
                        if row[0] in verify.DIGEST_NAMES
                    )
                    + (FASTBOOT,),
                    LAB_ENTRIES=(self.lab,),
                    MAIN_SETS=("",),
                    SUITE_DIRS=(SUITE,),
                    NEGATIVE_ENTRIES=(NEGATIVE,),
                )
            )
            stack.enter_context(
                patch.object(verify.shutil, "which", return_value="/fixture/tool")
            )
            captured = stack.enter_context(redirect_stdout(io.StringIO()))
            status = verify.main(argv)
        return status, captured.getvalue()

    def check(self, expected, message, *, env=None):
        code, output = self.invoke(env)
        self.assertEqual(code, expected, output)
        self.assertIn(message, output)

    def test_good_fixture_passes_and_output_is_private(self):
        self.check(0, "VERDICT: PASS")
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o700)

    def test_empty_manifest_refused_with_its_correct_hash(self):
        self.manifest.write_bytes(b"")
        self.check(1, "SHA256SUMS is missing a compared image")
        self.assertFalse(self.out.exists())

    def test_manifest_missing_a_compared_image_refused(self):
        self.manifest.write_bytes(self.manifest.read_bytes().split(b"\n", 1)[1])
        self.check(1, "missing a compared image: bt0-default.bin")

    def test_manifest_missing_a_compared_extension_refused(self):
        lines = self.manifest.read_text().splitlines(keepends=True)
        self.manifest.write_text(
            "".join(line for line in lines if not line.rstrip().endswith("-ext.bin"))
        )
        self.check(1, f"missing a compared image: bt0-{FASTBOOT[0]}-ext.bin")

    def swap_after_hash(self, old_path, new_path, data, replacement):
        """Swap after the digest function returns the original object's hash."""
        live = getattr(verify, "sha256", None)
        old = getattr(verify, "sha256_file", None)
        fired = []

        if live:

            def swap(actual):
                value = live(actual)
                if not fired and actual == data and new_path.is_file():
                    new_path.write_bytes(replacement)
                    fired.append(True)
                return value

            self.enterContext(patch.object(verify, "sha256", swap))
        else:

            def swap(path):
                value = old(path)
                if not fired and path == old_path:
                    old_path.write_bytes(replacement)
                    fired.append(True)
                return value

            self.enterContext(patch.object(verify, "sha256_file", swap))
        return fired

    def test_manifest_swap_after_digest_does_not_change_parsed_bytes(self):
        data = self.manifest.read_bytes()
        fired = self.swap_after_hash(
            self.manifest, self.manifest, data, b"0" * 64 + b"  other.bin\n"
        )
        self.check(0, "VERDICT: PASS")
        self.assertEqual(fired, [True])

    def test_baseline_image_swap_after_digest_does_not_change_comparison(self):
        path = self.baseline / "main-none.bin"
        fired = self.swap_after_hash(path, path, MAIN, b"swapped baseline")
        self.check(0, "identical to base 1")
        self.assertEqual(fired, [True])

    def test_produced_image_swap_after_digest_does_not_change_snapshot(self):
        name = "bt0-default.bin"
        produced = self.out / "matrix" / "out" / name
        staged = self.out / "tmp" / "images" / name
        fired = self.swap_after_hash(
            produced, staged, self.images[name], b"swapped output"
        )
        self.check(0, "VERDICT: PASS")
        self.assertEqual(fired, [True])
        self.assertEqual(produced.read_bytes(), self.images[name])

    def test_git_dir_override_is_neutralized(self):
        self.check(
            0, "VERDICT: PASS", env={"GIT_DIR": str(self.root / "not-a-git-dir")}
        )

    def test_git_config_override_is_neutralized(self):
        self.check(
            0,
            "VERDICT: PASS",
            env={
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.bare",
                "GIT_CONFIG_VALUE_0": "true",
            },
        )
        self.assertTrue(self.tools.git_envs)
        for env in self.tools.git_envs:
            self.assertEqual(
                {key: value for key, value in env.items() if key.startswith("GIT_")},
                {
                    "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_OPTIONAL_LOCKS": "0",
                },
            )

    def test_parent_git_worktree_refused_before_output(self):
        parent = self.root / "parent"
        parent.mkdir()
        shutil.copytree(
            self.source, parent / "source", ignore=shutil.ignore_patterns(".git")
        )
        self.source = parent / "source"
        self.commit(parent)
        self.check(1, "not the root of its own git worktree")
        self.assertFalse(self.out.exists())

    def test_inherited_build_dir_cannot_put_intermediates_in_source(self):
        spill = self.source / "intermediates"
        self.check(0, "VERDICT: PASS", env={"CARGO_BUILD_BUILD_DIR": str(spill)})
        self.assertFalse(spill.exists())
        for env in self.tools.cargo_envs:
            self.assertTrue(Path(env["CARGO_TARGET_DIR"]).is_relative_to(self.out))
            self.assertTrue(Path(env["CARGO_BUILD_BUILD_DIR"]).is_relative_to(self.out))

    def test_inherited_rust_flags_and_cargo_aliases_never_reach_build(self):
        ambient = {
            "RUSTFLAGS": "--cfg=unexpected",
            "CARGO_ENCODED_RUSTFLAGS": "--cfg=unexpected",
            "RUSTC_WRAPPER": "/not/a/wrapper",
        }
        self.check(0, "VERDICT: PASS", env=ambient)
        for env in self.tools.cargo_envs:
            self.assertTrue(ambient.keys().isdisjoint(env))

    def test_rustup_source_override_refused_before_output(self):
        self.wrong_toolchain = True
        self.check(1, "source resolves rustc outside the installed pin")
        self.assertFalse(self.out.exists())

    def test_missing_required_dram_section_refused(self):
        self.missing_dram = True
        self.check(1, "expected payload sections ('.dram',), found ()")

    def test_both_sections_must_be_exported_individually(self):
        self.lab = ("lab-both", ("fel", "dram-lab", "hybrid"))
        self.check(1, "extension .phyfw missing")
        self.assertTrue(
            any("--only-section=.phyfw" in args for args in self.tools.objcopies)
        )

    def test_identical_primary_with_different_extension_is_a_mixed_row(self):
        self.extension = b"oops"
        self.check(1, f"DIFFERS from base: bt0-{FASTBOOT[0]}-ext.bin")

    def test_binary_crash_without_result_is_not_a_completion(self):
        self.crash = True
        self.check(1, "suite-two: exit 7; missing or invalid test result")

    def test_launch_line_does_not_make_missing_binary_a_completion(self):
        self.missing_binary = True
        self.check(1, "missing test binary:")

    def test_stderr_is_not_a_test_result_and_preserves_its_order(self):
        self.stderr_noise = True
        self.check(0, "binaries expected 2, completed 2")
        log = next((self.out / "tests").glob("*/01-suite-one.log")).read_text()
        self.assertLess(log.index("first stderr line"), log.index("last stderr line"))
        self.assertIn(summary(1), log.split("=== stderr ===", 1)[0])

    def test_zero_executed_binary_cannot_be_rescued_by_a_doctest(self):
        self.empty_binary = True
        self.check(1, "suite-two: failed or no executed test")

    def test_negative_diagnostic_must_be_a_complete_error_line(self):
        self.diagnostic_suffix = " (not the expected diagnostic)"
        self.check(1, "failed without the expected diagnostic")

    def test_fel_limit_is_read_from_source_not_hard_coded(self):
        path = self.source / FEL_DEF
        path.write_text(path.read_text().replace("0x4f000", "0x7"))
        self.git(self.source, "add", FEL_DEF)
        self.git(
            self.source,
            "-c",
            "user.name=DaveWK",
            "-c",
            "user.email=13626476+DaveWK@users.noreply.github.com",
            "commit",
            "-qm",
            "fixture limit",
        )
        self.check(1, "primary is over the 0x7 limit")

    def test_existing_empty_output_is_not_claimed(self):
        self.out.mkdir(mode=0o700)
        self.check(1, "output path already exists")
        self.assertEqual(list(self.out.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
