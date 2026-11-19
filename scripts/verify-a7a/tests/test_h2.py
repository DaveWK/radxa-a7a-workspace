#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Drive the real CLI entry point with small, controlled tool outputs."""

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
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
STAGE_TEST = f"{SUITE}/tests/stage_check.rs"
MKIMAGE = Path(__file__).resolve().parents[2] / "mkimage.py"


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
        self.cargo_invocations = []
        self.cargo_envs = []
        self.git_envs = []
        self.row = ""
        self.objcopies = []
        self.paths = []
        self.test_launches = []
        self.gate_launches = []
        self.build_inputs = []
        self.linked_marker = None

    @staticmethod
    def response(argv, cwd, rc=0, stdout="", stderr=""):
        if hasattr(verify.CommandResult, "stderr"):
            return verify.CommandResult(tuple(argv), str(cwd), rc, stdout, stderr)
        return verify.CommandResult(tuple(argv), str(cwd), rc, stdout + stderr)

    def run(self, argv, cwd, env, log=None):
        b = self.bench
        cmd = Path(argv[0]).name
        if cmd == "cargo":
            self.cargo_invocations.append(tuple(argv))
        if cmd == "git":
            self.git_envs.append(dict(env))
        if cmd.startswith("suite-"):
            self.test_launches.append(Path(argv[0]))
        if cmd.startswith("python"):
            self.gate_launches.append(Path(argv[2]))
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
            elif argv[1:3] == ["target", "list"]:
                kwargs["stdout"] = "\n".join(b.toolchain_targets)
        elif cmd == "rustc":
            kwargs["stdout"] = f"host: {HOST}\nrelease: {b.toolchain_version}\n"
        elif cmd == "cargo" and argv[1:] == ["-V"]:
            kwargs["stdout"] = f"cargo {b.toolchain_version} (fixture)\n"
        elif cmd == "cargo":
            if b.before_first_build is not None and not self.cargo_envs:
                b.before_first_build()
            self.cargo_envs.append(dict(env))
            target = Path(env["CARGO_TARGET_DIR"])
            if "CARGO_BUILD_BUILD_DIR" in env:
                build = Path(env["CARGO_BUILD_BUILD_DIR"])
                build.mkdir(parents=True, exist_ok=True)
                (build / "intermediate").write_bytes(b"cargo intermediate")
            if argv[1] == "build":
                if b.capture_build_inputs:
                    archive = Path(env["A733_DRAM_LIB"])
                    phy = Path(env["A733_PHY_FW_OBJ"])
                    self.build_inputs.append(
                        (archive, archive.read_bytes(), phy, phy.read_bytes())
                    )
                    if self.linked_marker is None:
                        linked = b.root / "linked-fixture"
                        b.host_command("cc", b.root / "link.c", archive, "-o", linked)
                        self.linked_marker = b.host_command(linked).strip()
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
                second_dir = b.test_binary_dir or target
                self.paths = [target / "suite-one", second_dir / "suite-two"]
                for index, path in enumerate(self.paths):
                    if index == 1 and b.missing_binary:
                        continue
                    path.parent.mkdir(parents=True, exist_ok=True)
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
                if b.test_binary_link:
                    b.test_binary_link.symlink_to(self.paths[1])
                    self.paths[1] = b.test_binary_link
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
        self.workspace = self.root / "workspace"
        self.mkimage = self.workspace / "scripts" / "mkimage.py"
        self.mkimage.parent.mkdir(parents=True)
        shutil.copyfile(MKIMAGE, self.mkimage)
        self.commit(self.workspace)
        self.baseline = self.root / "baseline"
        self.baseline.mkdir()
        self.manifest = self.baseline / "SHA256SUMS"
        self.out = self.root / "out"
        for rel in (verify.BT0_DIR, verify.MAIN_DIR, SUITE):
            directory = self.source / rel
            directory.mkdir(parents=True)
            (directory / "README").write_text("fixture\n", encoding="utf-8")
        for name, content in (
            (verify.COMMON_LIB, "pub const MAIN_MAX_SIZE: usize = 0x80000;\n"),
            (STAGE_TEST, "// fixture test\n"),
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
        self.pin_fixture_tools()
        self.dram_lib = self.root / "libdram-a733.a"
        self.phyfw = self.root / "libdram"
        self.gate = self.root / "gate.py"
        for path, content in (
            (self.dram_lib, b"!<arch>\n"),
            (self.phyfw, b"\x7fELFfixture"),
            (self.gate, b"print('fixture gate')\n"),
        ):
            path.write_bytes(content)
        self.input_digests = {
            name: digest(path.read_bytes())
            for name, path in (
                ("dram-lib", self.dram_lib),
                ("phyfw-obj", self.phyfw),
                ("gate", self.gate),
            )
        }
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
        self.test_binary_dir = None
        self.test_binary_link = None
        self.crash = False
        self.stderr_noise = False
        self.empty_binary = False
        self.wrong_toolchain = False
        self.diagnostic_suffix = ""
        self.before_first_build = None
        self.capture_build_inputs = False

    def pin_fixture_tools(self):
        spec = tomllib.loads((self.source / "rust-toolchain.toml").read_text())[
            "toolchain"
        ]
        channel = spec["channel"]
        self.toolchain_version = (
            "1.97.0-nightly" if channel.startswith("nightly-") else channel
        )
        self.toolchain_targets = spec.get("targets", [])
        self.pinned_bin = (
            self.home / ".rustup" / "toolchains" / f"{channel}-{HOST}" / "bin"
        )
        self.pinned_bin.mkdir(parents=True, exist_ok=True)
        for tool in ("cargo", "rustc", "rustdoc"):
            (self.pinned_bin / tool).write_bytes(b"mock tool")

    def copy_oreboot(self):
        # Evidence runs use the pinned full clone; standalone quick runs can
        # exercise the same accidents in copies of the miniature Git fixture.
        oreboot = Path(os.environ.get("VERIFY_A7A_OREBOOT", self.source))
        self.source = Path(
            shutil.copytree(oreboot, self.root / "oreboot-copy", symlinks=True)
        )
        self.pin_fixture_tools()
        self.assertEqual(self.git(self.source, "status", "--porcelain"), "")
        # Refresh the copied index's inode/ctime metadata, not the original.
        self.git(self.source, "update-index", "--refresh")
        return self.source / STAGE_TEST

    def git(self, cwd, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(
            GIT_CONFIG_GLOBAL="/dev/null",
            GIT_CONFIG_NOSYSTEM="1",
            GIT_OPTIONAL_LOCKS="0",
        )
        return subprocess.run(
            ["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True
        ).stdout.strip()

    def host_command(self, *argv, source=None):
        return subprocess.run(
            argv,
            cwd=self.root,
            env={**os.environ, "TMPDIR": str(self.root)},
            input=source,
            check=True,
            capture_output=True,
            text=True,
        ).stdout

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

    def invoke(self, env=None, *, omit_digest=None):
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
        # The same fixture drives the old real entry point, whose parser did
        # not accept these options, when collecting red-at-base evidence.
        if "gate_sha256" in verify.Config.__annotations__:
            for name, value in self.input_digests.items():
                if name != omit_digest:
                    argv.extend([f"--{name}-sha256", value])
        self.tools = BenchTools(self)
        with ExitStack() as stack:
            stack.enter_context(
                patch.dict(os.environ, {"HOME": str(self.home), **(env or {})})
            )
            stack.enter_context(
                patch.multiple(
                    verify,
                    SubprocessRunner=lambda: self.tools,
                    MKIMAGE=self.mkimage,
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

    def assert_clean_git_refused_without_build(self, message):
        self.assertEqual(self.git(self.source, "status", "--porcelain"), "")
        self.check(1, message)
        self.assertEqual(self.tools.cargo_invocations, [])
        self.assertFalse(self.out.exists())

    def test_sparse_checkout_omitting_real_suite_test_refused(self):
        path = self.copy_oreboot()
        self.assertTrue(path.is_file())
        self.git(
            self.source,
            "sparse-checkout",
            "set",
            "--cone",
            verify.BT0_DIR,
            verify.MAIN_DIR,
            str(Path(verify.COMMON_LIB).parent),
            f"{SUITE}/src",
        )
        self.assertFalse(path.exists())
        self.assert_clean_git_refused_without_build("source uses sparse checkout")

    def test_skip_worktree_hiding_modified_test_refused(self):
        path = self.copy_oreboot()
        self.git(self.source, "update-index", "--skip-worktree", "--", STAGE_TEST)
        path.write_bytes(b"// replaced while marked skip-worktree\n")
        self.assert_clean_git_refused_without_build("source has a skip-worktree entry")

    def test_assume_unchanged_hiding_modified_test_refused(self):
        path = self.copy_oreboot()
        self.git(self.source, "update-index", "--assume-unchanged", "--", STAGE_TEST)
        path.write_bytes(b"// replaced while marked assume-unchanged\n")
        self.assert_clean_git_refused_without_build(
            "source has an assume-unchanged entry"
        )

    def test_assume_unchanged_hiding_deleted_test_refused(self):
        path = self.copy_oreboot()
        self.git(self.source, "update-index", "--assume-unchanged", "--", STAGE_TEST)
        path.unlink()
        self.assert_clean_git_refused_without_build(
            "source has an assume-unchanged entry"
        )

    def test_workspace_sparse_pattern_file_refused(self):
        info = self.workspace / ".git" / "info"
        (info / "sparse-checkout").write_text("/*\n")
        self.check(1, "workspace has a non-empty Git info/sparse-checkout")
        self.assertEqual(self.tools.cargo_invocations, [])
        self.assertFalse(self.out.exists())

    def test_workspace_index_flag_set_during_build_refused_before_pass(self):
        self.before_first_build = lambda: self.git(
            self.workspace,
            "update-index",
            "--assume-unchanged",
            "--",
            "scripts/mkimage.py",
        )
        self.check(1, "workspace has an assume-unchanged entry")
        self.assertTrue(self.tools.cargo_envs)

    def test_wrong_type_hidden_by_git_symlink_config_refused(self):
        path = self.source / "link"
        path.symlink_to("rust-toolchain.toml")
        self.git(self.source, "add", "--", "link")
        self.git(
            self.source,
            "-c",
            "user.name=DaveWK",
            "-c",
            "user.email=13626476+DaveWK@users.noreply.github.com",
            "commit",
            "-qm",
            "tracked symlink",
        )
        self.git(self.source, "config", "core.symlinks", "false")
        path.unlink()
        path.write_text("rust-toolchain.toml")
        self.assert_clean_git_refused_without_build(
            "source tracked path has the wrong type"
        )

    def assert_identity_refused_without_build(self, name):
        self.check(1, f"{name} SHA256")
        self.assertEqual(self.tools.cargo_invocations, [])
        self.assertEqual(self.tools.gate_launches, [])
        self.assertFalse(self.out.exists())

    def test_gate_with_different_sha256_refused(self):
        self.gate.write_bytes(b"print('stale gate still exits zero')\n")
        self.assert_identity_refused_without_build("gate")

    def make_archive(self, name, marker, *, thin=False):
        obj = self.root / f"{name}.o"
        archive = self.root / f"{name}.a"
        self.host_command(
            "cc",
            "-x",
            "c",
            "-c",
            "-o",
            obj,
            "-",
            source=f'const char *marker(void) {{ return "{marker}"; }}\n',
        )
        self.host_command("ar", "rcsT" if thin else "rcs", archive, obj.name)
        return archive.read_bytes()

    def assert_format_refused_without_build(self, name, path, data, diagnostic):
        path.write_bytes(data)
        self.input_digests[name] = digest(data)
        self.check(1, f"{name} snapshot {diagnostic}")
        self.assertEqual(self.tools.cargo_invocations, [])
        self.assertFalse(self.out.exists())
        self.assertEqual(list(self.root.glob(".verify-a7a-*")), [])

    def test_pinned_thin_dram_archive_refused_before_cargo(self):
        data = self.make_archive("thin", "fixture member", thin=True)
        self.assertTrue(data.startswith(b"!<thin>\n"))
        self.assert_format_refused_without_build(
            "dram-lib", self.dram_lib, data, "is a thin ar archive"
        )

    def test_pinned_non_archive_dram_input_refused_before_cargo(self):
        self.assert_format_refused_without_build(
            "dram-lib", self.dram_lib, b"\x7fELFfixture", "must be a normal ar archive"
        )

    def test_pinned_thin_phy_archive_refused_before_cargo(self):
        data = self.make_archive("thin-phy", "fixture member", thin=True)
        self.assertTrue(data.startswith(b"!<thin>\n"))
        self.assert_format_refused_without_build(
            "phyfw-obj", self.phyfw, data, "is a thin ar archive"
        )

    def test_pinned_unknown_phy_format_refused_before_cargo(self):
        self.assert_format_refused_without_build(
            "phyfw-obj",
            self.phyfw,
            b"not an archive or an ELF object",
            "must be a normal ar archive or an ELF object",
        )

    def test_pinned_normal_phy_archive_is_identified(self):
        data = self.make_archive("normal-phy", "fixture member")
        self.phyfw.write_bytes(data)
        self.input_digests["phyfw-obj"] = digest(data)
        self.check(0, "phyfw-obj snapshot format: normal ar archive")

    def test_byte_flipped_dram_archive_refused(self):
        data = bytearray(self.make_archive("original", "verified archive"))
        self.input_digests["dram-lib"] = digest(data)
        data[-1] ^= 1
        self.dram_lib.write_bytes(data)
        self.assert_identity_refused_without_build("dram-lib")

    def test_phy_object_with_different_sha256_refused(self):
        self.phyfw.write_bytes(b"stale PHY object")
        self.assert_identity_refused_without_build("phyfw-obj")

    def test_snapshot_changed_before_readback_refused(self):
        file_digest = hashlib.file_digest

        def corrupt_snapshot(stream, algorithm):
            Path(stream.name).write_bytes(b"corrupt snapshot")
            return file_digest(stream, algorithm)

        with patch.object(hashlib, "file_digest", corrupt_snapshot):
            self.check(1, "dram-lib snapshot SHA256 changed")
        self.assertEqual(self.tools.cargo_envs, [])
        self.assertFalse(self.out.exists())

    def test_input_replacements_do_not_reach_build_or_gate(self):
        self.dram_lib.write_bytes(self.make_archive("original", "verified archive"))
        self.input_digests["dram-lib"] = digest(self.dram_lib.read_bytes())
        (self.root / "link.c").write_text(
            "#include <stdio.h>\nconst char *marker(void);\n"
            "int main(void) { puts(marker()); return 0; }\n"
        )
        archive, phy, gate = (
            path.read_bytes() for path in (self.dram_lib, self.phyfw, self.gate)
        )
        originals = (
            (self.dram_lib, self.make_archive("replacement", "stale archive")),
            (self.phyfw, b"replacement PHY"),
            (self.gate, b"print('replacement gate')\n"),
        )

        def replace_inputs():
            for original, replacement in originals:
                tmp = original.with_suffix(".new")
                tmp.write_bytes(replacement)
                tmp.replace(original)

        self.capture_build_inputs = True
        self.before_first_build = replace_inputs
        self.check(0, "VERDICT: PASS")
        archive_path = self.out / "inputs" / "libdram-a733.a"
        phy_path = self.out / "inputs" / "phyfw.o"
        gate_path = self.out / "inputs" / "gate.py"
        with self.subTest(consumer="Cargo linker and PHY extractor"):
            self.assertEqual(self.tools.linked_marker, "verified archive")
            self.assertTrue(self.tools.build_inputs)
            self.assertEqual(
                set(self.tools.build_inputs), {(archive_path, archive, phy_path, phy)}
            )
        with self.subTest(consumer="Python gate"):
            gate_log = (self.out / "gate.log").read_text()
            self.assertIn("fixture gate", gate_log)
            self.assertNotIn("replacement gate", gate_log)
            self.assertEqual(self.tools.gate_launches, [gate_path])
            self.assertEqual(gate_path.read_bytes(), gate)
        for original, replacement in originals:
            self.assertEqual(original.read_bytes(), replacement)

    def test_missing_external_input_sha256_arguments_refused(self):
        for name in self.input_digests:
            with self.subTest(option=name):
                self.out = self.root / f"out-missing-{name}"
                errors = io.StringIO()
                with redirect_stderr(errors), self.assertRaises(SystemExit) as stopped:
                    self.invoke(omit_digest=name)
                self.assertEqual(stopped.exception.code, 2)
                self.assertIn(f"--{name}-sha256", errors.getvalue())
                self.assertEqual(self.tools.cargo_invocations, [])
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

    def test_executables_from_both_pinned_cargo_roots_are_run(self):
        self.test_binary_dir = self.out / "build" / "test"
        self.check(0, "binaries expected 2, completed 2")
        self.assertEqual(
            self.tools.test_launches,
            [
                self.out / "target" / "test" / "suite-one",
                self.test_binary_dir / "suite-two",
            ],
        )

    def test_executable_in_job_but_outside_both_pinned_roots_is_not_run(self):
        self.test_binary_dir = self.out / "build" / "test-spill"
        self.check(1, f"unexpected or duplicate executable: {self.test_binary_dir}")
        self.assertEqual(self.tools.test_launches, [])

    def test_symlink_escaping_both_pinned_roots_is_not_run(self):
        self.test_binary_dir = self.root
        self.test_binary_link = self.out / "build" / "test" / "suite-two"
        self.check(1, f"unexpected or duplicate executable: {self.test_binary_link}")
        self.assertEqual(self.tools.test_launches, [])

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

    def test_output_inside_workspace_refused_before_creation(self):
        self.out = self.workspace / "job"
        code, output = self.invoke()
        self.assertEqual(code, 1, output)
        self.assertFalse(self.out.exists(), output)
        self.assertEqual(self.git(self.workspace, "status", "--porcelain"), "")
        self.assertEqual(self.tools.cargo_invocations, [])
        self.assertIn("output directory overlaps the workspace", output)

    def test_output_resolving_inside_workspace_refused_before_staging(self):
        alias = self.root / "workspace-alias"
        alias.symlink_to(self.workspace, target_is_directory=True)
        self.out = alias / "job"
        with patch.object(
            verify.tempfile, "TemporaryDirectory", wraps=tempfile.TemporaryDirectory
        ) as stage:
            code, output = self.invoke()
            stage.assert_not_called()
        self.assertEqual(code, 1, output)
        self.assertIn("output directory overlaps the workspace", output)
        self.assertFalse(self.out.exists())
        self.assertEqual(self.git(self.workspace, "status", "--porcelain"), "")
        self.assertEqual(self.tools.cargo_invocations, [])

    def test_output_overlapping_other_inputs_refused_before_staging(self):
        for label, path in (
            ("source", self.source),
            ("baseline", self.baseline),
            ("dram-lib", self.dram_lib),
            ("phyfw-obj", self.phyfw),
            ("gate", self.gate),
        ):
            with self.subTest(label=label):
                self.out = path / "job"
                with patch.object(
                    verify.tempfile, "TemporaryDirectory", autospec=True
                ) as stage:
                    self.check(1, f"output directory overlaps the {label}")
                    stage.assert_not_called()
                self.assertFalse(self.out.exists())
                self.assertEqual(self.tools.cargo_invocations, [])

    def test_cache_symlink_refusal_leaves_no_job_directory(self):
        target = self.root / "archive.crate"
        target.write_bytes(b"fixture cache content")
        cache = self.home / ".cargo" / "registry" / "cache"
        cache.mkdir(parents=True)
        link = cache / target.name
        link.symlink_to(target)
        self.check(1, f"offline Cargo cache contains a symlink: {link}")
        self.assertEqual(self.tools.cargo_envs, [])
        self.assertFalse(self.out.exists())
        self.assertEqual(list(self.root.glob(".verify-a7a-*")), [])

    def test_symlinked_cache_root_refusal_leaves_no_job_directory(self):
        target = self.root / "archive-cache"
        target.mkdir()
        cache = self.home / ".cargo" / "registry"
        cache.mkdir(parents=True)
        link = cache / "cache"
        link.symlink_to(target, target_is_directory=True)
        self.check(1, f"offline Cargo cache contains a symlink: {link}")
        self.assertEqual(self.tools.cargo_envs, [])
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
