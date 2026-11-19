#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the workspace devcard recipes on stubs, without building an image."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent

# Dispatch through the invoked filename so all four Fedora calls can be checked
# against one synthetic build's inputs and outputs.
STUB = """\
#!/usr/bin/env python3
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
out = Path(os.environ["TEST_OUT"])
rpmbuild = out / "fedora/rpmbuild"
run = rpmbuild / "runs/stub"
image = out / "image/a7a-fedora45.img"
compressed = os.environ.get("XZ") != "no"
seal = "a" * 64
assert "FW" not in os.environ, tool
if tool == "build-rpms.sh":
    assert args == [str(rpmbuild)], args
    assert os.environ["FWREPO"] == "stub-fwrepo"
    run.mkdir(parents=True)
    print(run)
elif tool == "build-aarch64-rpms.sh":
    assert args == [str(run)], args
    assert os.environ["FEDORA_RELEASE"] == "45"
    assert not (out / "fedora/run").exists()
    (run / "rpm-snapshot.json").touch()
elif tool == "mkdevcard.sh":
    assert len(args) == 2 and args[1] == str(run), args
    assert Path(args[0]).name == "firmware.bin" and Path(args[0]).is_file(), args
    if os.environ.get("TEST_PRIVATE_FIRMWARE"):
        assert Path(args[0]).read_text() == "invocation firmware", args
    assert (run / "rpm-snapshot.json").is_file()
    assert os.environ["DRAM_FIRMWARE_IDENTITY"] == "blobfree-1200"
    assert os.environ["FIRMWARE_DTB_VERSION"] == "42"
    staged = Path(os.environ["OUT"])
    work = Path(os.environ["WORK"])
    build = Path(sys.argv[0]).resolve().parents[1] / "build"
    assert staged.is_relative_to(build) and work.is_relative_to(build)
    assert not staged.exists() and not work.exists()
    staged.parent.mkdir(parents=True)
    payloads = {
        "": "image",
        ".devcard-manifest.json": "manifest",
        ".build-receipt.json": json.dumps({"manifest_sha256": seal}),
    }
    if compressed:
        payloads[".xz"] = "compressed"
    sums = []
    for suffix, payload in payloads.items():
        artifact = staged.with_name(staged.name + suffix)
        artifact.write_text(payload)
        sums.append(f"{sha256(artifact.read_bytes()).hexdigest()}  {artifact.name}\\n")
    staged.with_suffix(".img.sha256").write_text("".join(sums))
elif tool == "verify-devcard.sh":
    assert args == [
        str(image), str(image) + ".devcard-manifest.json", "--expect-manifest-sha256", seal
    ], args
    scratch = Path(os.environ["TMPDIR"])
    assert scratch.is_relative_to(out) and scratch.is_dir()
    checksums = image.with_suffix(".img.sha256")
    assert (image.with_suffix(".img.xz").exists()) == compressed
    assert (image.name + ".xz" in checksums.read_text()) == compressed
    subprocess.run(["sha256sum", "-c", image.name + ".sha256"], cwd=image.parent, check=True)
    (out / "verified").touch()
else:
    raise AssertionError(tool)
"""

# Deterministically simulate the other invocation publishing its own run after
# this invocation updates the shared pointer but before it invokes mkdevcard.
COMPETING_MOVE = """\
#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import sys

subprocess.run([os.environ["TEST_REAL_MV"], *sys.argv[1:]], check=True)
pointer = Path(os.environ["TEST_OUT"]) / "fedora/run"
if Path(sys.argv[-1]) == pointer:
    other_run = pointer.parent / "rpmbuild/runs/competing"
    other_run.mkdir(parents=True)
    (other_run / "rpm-snapshot.json").touch()
    replacement = pointer.with_name("run.competing")
    replacement.write_text(f"{other_run}\\n")
    replacement.replace(pointer)
"""

STUB_CARGO = """\
#!/usr/bin/env python3
import os
from pathlib import Path
import sys
import tomllib

home = Path(os.environ["CARGO_HOME"])
if sys.argv[1:3] == ["-Zunstable-options", "config"]:
    print("error: config value `env` is not set", file=sys.stderr)
    sys.exit(101)
profile = os.environ["A7A_PROFILE"]
config = home / "config.toml"
if config.exists():
    forced = tomllib.loads(config.read_text())["env"]["A7A_PROFILE"]
    if forced["force"]:
        profile = forced["value"]
assert (home / "registry/cache/fixture").is_file(), "registry cache not seeded"
output = (Path(os.environ["CARGO_TARGET_DIR"]) / "armv7a-none-eabi/release"
          / "oreboot-cubie-a7a-bt0")
output.parent.mkdir(parents=True)
output.write_text(profile)
"""

STUB_FIRMWARE_MAKE = """\
#!/usr/bin/env python3
import os
from pathlib import Path
import sys

out, target = sys.argv[1:]
assert out.startswith("OUT=") and target == "firmware", sys.argv
private = Path(out.removeprefix("OUT="))
shared = Path(os.environ["TEST_OUT"])
assert private.is_relative_to(shared) and private != shared, private
(private / "firmware").mkdir()
(private / "firmware/firmware.bin").write_text("invocation firmware")
(shared / "firmware/firmware.bin").write_text("competing firmware")
"""


def executable(path, payload):
    path.write_text(payload)
    path.chmod(0o700)


def run_case(case):
    with tempfile.TemporaryDirectory(
        prefix="workspace-devcard-", dir=os.environ.get("TMPDIR") or ROOT
    ) as directory:
        root = Path(directory)
        shutil.copyfile(ROOT / "Makefile", root / "Makefile")
        (root / "scripts").mkdir()
        binfmt = root / "scripts/binfmt-aarch64.sh"
        executable(binfmt, "#!/bin/sh\nexit 0\n")
        fedora = root / "stub-fedora"
        (fedora / "fedora/dts").mkdir(parents=True)
        (fedora / "fedora/dts/DTB_VERSION").write_text("42\n")
        for name in (
            "build-rpms.sh",
            "build-aarch64-rpms.sh",
            "mkdevcard.sh",
            "verify-devcard.sh",
        ):
            stub = fedora / "fedora" / name
            executable(stub, STUB)
        for prerequisite in (
            "firmware/oreboot/src/mainboard/radxa/cubie-a7a/bt0/Cargo.toml",
            "firmware/edk2/edksetup.sh",
            "firmware/edk2-platforms/Platform/Radxa/CubieA7APkg/CubieA7A.dsc",
            "out/firmware/firmware.bin",
        ):
            path = root / prerequisite
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        env = {"PATH": os.environ["PATH"], "TEST_OUT": str(root / "out")}
        command = [
            "make",
            "--no-print-directory",
            "-o",
            "firmware",
            "-o",
            "fel-image",
            f"FEDORA={fedora}",
            "FEDORA_RELEASE=45",
            "FWREPO=stub-fwrepo",
            "FEL_DRAM=dramlib",
        ]
        firmware_make = binfmt.with_name("make-firmware")
        executable(firmware_make, STUB_FIRMWARE_MAKE)
        command.append(f"MAKE={firmware_make}")
        if case == "forced-cargo-profile":
            helper = ROOT / "scripts/sd-bt0-cargo.py"
            if helper.exists():
                shutil.copyfile(helper, root / "scripts" / helper.name)
            executable(binfmt.with_name("cargo"), STUB_CARGO)
            objcopy = binfmt.with_name("objcopy")
            executable(objcopy, '#!/bin/sh\nshift 2\ncp -- "$1" "$2"\n')
            home = root / "caller-cargo"
            cache = home / "registry/cache"
            cache.mkdir(parents=True)
            (cache / "fixture").touch()
            (home / "config.toml").write_text(
                '[env]\nA7A_PROFILE = { value = "2400", force = true }\n'
            )
            env.update(
                PATH=f"{binfmt.parent}{os.pathsep}{env['PATH']}",
                CARGO_HOME=str(home),
            )
            subprocess.run(
                [*command, f"OBJCOPY={objcopy}", "bt0"], cwd=root, env=env, check=True
            )
            built = (root / "out/oreboot/bt0.bin").read_text()
            assert built == "1200", f"compiled profile was {built!r}, expected '1200'"
            return
        if case in ("label-env", "label-cli"):
            assignment = "DRAM_FIRMWARE_IDENTITY=blobfree-2400"
            if case == "label-env":
                env.update([assignment.split("=", 1)])
            else:
                command.append(assignment)
            result = subprocess.run(
                [*command, "fedora-image"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
            )
            assert result.returncode == 2, result
            assert (
                "DRAM_FIRMWARE_IDENTITY is derived from" in result.stderr
            ), result.stderr
            assert not (root / "out/fedora/rpmbuild").exists()
            return
        if case == "competing-run":
            mv = binfmt.with_name("mv")
            mv.write_text(COMPETING_MOVE)
            mv.chmod(0o700)
            env["TEST_REAL_MV"] = shutil.which("mv")
            env["PATH"] = f"{mv.parent}{os.pathsep}{env['PATH']}"
        if case == "no-xz":
            old = root / "out/image/a7a-fedora45.img.xz"
            old.parent.mkdir()
            old.write_text("old compressed image")
            command.append("XZ=no")
        if case == "private-firmware":
            env["TEST_PRIVATE_FIRMWARE"] = "1"
        goals = (
            ["fedora-image"] if case == "competing-run" else ["rpms", "fedora-image"]
        )
        subprocess.run([*command, *goals], cwd=root, env=env, check=True)
        assert (root / "out/verified").is_file()
        expected = "competing" if case == "competing-run" else "stub"
        assert Path((root / "out/fedora/run").read_text().strip()).name == expected


def main():
    cases = (
        "default",
        "label-env",
        "label-cli",
        "competing-run",
        "no-xz",
        "forced-cargo-profile",
        "private-firmware",
    )
    for case in sys.argv[1:] or cases:
        assert case in cases, case
        run_case(case)
        print(f"workspace Fedora devcard recipe case {case}: passed", flush=True)


if __name__ == "__main__":
    main()
