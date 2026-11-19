#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the workspace devcard recipes on stubs, without building an image."""

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def stub_bt0(profile):
    return bytes(4) + b"eGON.BT0" + bytes(8) + profile.encode()


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
    if os.environ.get("TEST_REPLACE_FIRMWARE"):
        (firmware,) = out.glob(".devcard-firmware-*/firmware/firmware.bin")
        # Preserve the eGON prefix: this regression requires a whole-file
        # digest pinned before the RPM step, not a second prefix check.
        replacement = firmware.with_suffix(".replacement")
        replacement.write_bytes(firmware.read_bytes() + b"replacement tail")
        replacement.replace(firmware)
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
        assert Path(args[0]).read_bytes().endswith(b"invocation firmware"), args
    assert (run / "rpm-snapshot.json").is_file()
    assert os.environ["DRAM_FIRMWARE_IDENTITY"] == "blobfree-1200"
    assert os.environ["FIRMWARE_DTB_VERSION"] == "42"
    staged = Path(os.environ["OUT"])
    work = Path(os.environ["WORK"])
    build = Path(sys.argv[0]).resolve().parents[1] / "build"
    assert staged.is_relative_to(build) and work.is_relative_to(build)
    assert not staged.exists() and not work.exists()
    staged.parent.mkdir(parents=True)
    firmware = Path(args[0]).read_bytes()
    if os.environ.get("TEST_REPLACE_FIRMWARE"):
        assert firmware.endswith(b"replacement tail")
        (out / "mkdevcard-read-replacement").touch()
    payloads = {
        "": "image",
        ".devcard-manifest.json": "manifest",
        ".build-receipt.json": json.dumps({
            "manifest_sha256": seal,
            "firmware": {"sha256": sha256(firmware).hexdigest()},
        }),
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
import json
import os
from pathlib import Path
import sys
import tomllib

home = Path(os.environ["CARGO_HOME"])
(Path(os.environ["HOME"]) / "cargo-invoked").touch()
cwd = Path.cwd()
config = {}
for directory in reversed((cwd, *cwd.parents)):
    path = directory / ".cargo/config.toml"
    if path.is_file():
        config.update(tomllib.loads(path.read_text()))
if sys.argv[1:3] == ["-Zunstable-options", "config"]:
    if "env" in config:
        print(json.dumps({"env": config["env"]}))
        sys.exit(0)
    print("error: config value `env` is not set", file=sys.stderr)
    sys.exit(101)
profile = os.environ["A7A_PROFILE"]
home_config = home / "config.toml"
if home_config.exists():
    forced = tomllib.loads(home_config.read_text())["env"]["A7A_PROFILE"]
    if forced["force"]:
        profile = forced["value"]
if ({"RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
     "CARGO_ENCODED_RUSTFLAGS"} & os.environ.keys()
    or any(key.startswith("CARGO_BUILD_") for key in os.environ)
    or "rustc-wrapper" in config.get("build", {}) or "RUSTC_WRAPPER" in config.get("env", {})):
    profile = "2400"
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
import subprocess
import sys

out, target = sys.argv[1:]
assert out.startswith("OUT=") and target == "firmware", sys.argv
private = Path(out.removeprefix("OUT="))
shared = Path(os.environ["TEST_OUT"])
assert private.is_relative_to(shared) and private != shared, private
(private / "firmware").mkdir()
(private / "oreboot").mkdir()
raw = private / "oreboot/bt0.bin"
profile = os.environ.get("TEST_BT0", "stub-1200")
raw.write_bytes(bytes(4) + b"eGON.BT0" + bytes(8) + profile.encode())
firmware = private / "firmware/firmware.bin"
subprocess.run(
    [sys.executable, "-I", "scripts/mkimage.py", "--bt0", str(raw), "--egon", str(firmware)],
    check=True,
)
wrapped = bytearray(firmware.read_bytes())
if os.environ.get("TEST_WRONG_PREFIX"):
    wrapped[32] ^= 1
firmware.write_bytes(wrapped + b"invocation firmware")
(shared / "firmware/firmware.bin").write_text("competing firmware")
"""


def executable(path, payload):
    path.write_text(payload)
    path.chmod(0o700)


BT0_CASES = {
    "forced-cargo-profile",
    "sd-env-cli",
    "sd-env-inherited",
    "rustc-wrapper",
    "encoded-rustflags",
    "ancestor-build",
    "ancestor-env-profile",
    "ancestor-env-wrapper",
}


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
        (root / "firmware/oreboot/rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "nightly-2026-05-06"\n'
        )
        helper = ROOT / "scripts/sd-bt0-cargo.py"
        shutil.copyfile(helper, root / "scripts" / helper.name)
        (root / "scripts/lib").mkdir()
        for tool in ("mkimage.py", "lib/bootlayout.py", "lib/mkcard.py"):
            shutil.copyfile(ROOT / "scripts" / tool, root / "scripts" / tool)
        (root / "scripts/sd-bt0-fingerprints.json").write_text(
            json.dumps(
                {
                    sha256(stub_bt0(f"stub-{mhz}")).hexdigest(): f"blobfree-{mhz}"
                    for mhz in (1200, 2400)
                }
            )
        )
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(root),
            "TEST_OUT": str(root / "out"),
        }
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
        if case in BT0_CASES:
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
            config = {
                "ancestor-build": '[build]\nrustc-wrapper = "/stub/wrapper"\n',
                "ancestor-env-profile": (
                    '[env]\nA7A_PROFILE = { value = "2400", force = true }\n'
                ),
                "ancestor-env-wrapper": '[env]\nRUSTC_WRAPPER = "/stub/wrapper"\n',
            }.get(case)
            if config:
                (root / ".cargo").mkdir()
                (root / ".cargo/config.toml").write_text(config)
            if case == "sd-env-cli":
                command.append("sd-bt0-env=A7A_PROFILE=2400")
            if case == "sd-env-inherited":
                env["sd-bt0-env"] = "A7A_PROFILE=2400"
            if case == "rustc-wrapper":
                env["RUSTC_WRAPPER"] = "/stub/wrapper"
            if case == "encoded-rustflags":
                env["CARGO_ENCODED_RUSTFLAGS"] = "--cfg\x1fforced"
            reject = "does not accept sd-bt0-env" if case.startswith("sd-env-") else ""
            if config:
                # R3 asked Cargo about [env] before rejecting a reported
                # A7A_PROFILE. R4 rejects the file before it starts Cargo.
                reject = (
                    "Cargo [env] must not set A7A_PROFILE"
                    if case == "ancestor-env-profile"
                    else "unapproved Cargo config"
                )
            result = subprocess.run(
                [*command, f"OBJCOPY={objcopy}", "bt0"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
            )
            if reject:
                assert result.returncode == 2 and reject in result.stderr, result
                assert not (
                    root / "cargo-invoked"
                ).exists(), "started Cargo with a rejected config"
                assert not (root / "out/oreboot/bt0.bin").exists()
                return
            assert result.returncode == 0, result
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
        if case == "firmware-replaced-during-rpms":
            env["TEST_REPLACE_FIRMWARE"] = "1"
            image_dir = root / "out/image"
            image_dir.mkdir()
            old_artifacts = {
                image_dir / f"a7a-fedora45.img{suffix}": f"previous{suffix}\n"
                for suffix in (
                    "",
                    ".xz",
                    ".devcard-manifest.json",
                    ".build-receipt.json",
                    ".sha256",
                )
            }
            for path, contents in old_artifacts.items():
                path.write_text(contents)
            result = subprocess.run(
                [*command, "fedora-image"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
            )
            assert result.returncode == 2, result
            assert (
                "receipt firmware.sha256 does not match verified firmware"
                in result.stderr
            )
            assert (root / "out/mkdevcard-read-replacement").exists()
            assert not (root / "out/verified").exists()
            assert not list(fedora.glob("build/image-*/package/*"))
            for path, contents in old_artifacts.items():
                assert path.read_text() == contents, path
            return
        if case == "wrong-packaged-prefix":
            env["TEST_WRONG_PREFIX"] = "1"
            result = subprocess.run(
                [*command, "fedora-image"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
            )
            assert result.returncode == 2, result
            assert "packaged bt0 does not match the fingerprinted raw bt0" in (
                result.stderr
            ), result
            assert not (root / "out/fedora/rpmbuild").exists()
            return
        if case in ("wrong-binary-profile", "unknown-binary"):
            wrong_profile = case == "wrong-binary-profile"
            env["TEST_BT0"] = "stub-2400" if wrong_profile else "unknown bt0 bytes"
            result = subprocess.run(
                [*command, "fedora-image"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
            )
            assert result.returncode == 2, result
            reason = (
                "bt0 fingerprint is blobfree-2400, expected blobfree-1200"
                if wrong_profile
                else "unknown bt0 fingerprint"
            )
            assert reason in result.stderr, result
            assert not (root / "out/fedora/rpmbuild").exists()
            return
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
        "private-firmware",
        *sorted(BT0_CASES),
        "wrong-binary-profile",
        "unknown-binary",
        "wrong-packaged-prefix",
        "firmware-replaced-during-rpms",
    )
    for case in sys.argv[1:] or cases:
        assert case in cases, case
        run_case(case)
        print(f"workspace Fedora devcard recipe case {case}: passed", flush=True)


if __name__ == "__main__":
    main()
