#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fake-USB regressions for the FEL build isolation, staging and provenance gate.

Builds fake bundles with scripts/fel-manifest.py, stubs xfel, sunxi-fel and
lsusb on PATH, and checks that fel-boot refuses every bad bundle before any
stub call, passes only the staged bytes to xfel for a good one, and that the
packaging step refuses a swapped intermediate.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FEL_BOOT = ROOT / "scripts" / "fel-boot.sh"
FEL_MANIFEST = ROOT / "scripts" / "fel-manifest.py"

STUB_XFEL = """#!/usr/bin/env bash
set -u
printf '%s\\n' "$*" >>"$STUB_LOG"
cmd=${1:-}
shift || true
case $cmd in
  version)
    echo "xfel v1.4.0 ID=0x00190300"
    ;;
  write)
    cp "$2" "$STUB_MEM/$1.bin"
    ;;
  read)
    addr=$1; size=$2; out=$3
    if [ "$addr" = "0xdf000" ] && [ "$size" = "28" ]; then
      python3 - "$out" <<'PY'
import struct, sys
vals = [0x46413741, 0x11, 0x1000, 0x4B0, 0, 0, 0]
open(sys.argv[1], "wb").write(b"".join(struct.pack("<I", v) for v in vals))
PY
    elif [ -f "$STUB_MEM/$addr.bin" ]; then
      head -c "$size" "$STUB_MEM/$addr.bin" >"$out"
    else
      head -c "$size" /dev/zero >"$out"
    fi
    ;;
  read32)
    echo 0
    ;;
  exec)
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
"""

STUB_LSUSB = """#!/usr/bin/env bash
set -u
printf '%s\\n' "$*" >>"$STUB_LOG"
if [ -n "${STUB_REPLACE:-}" ]; then
    cp "${STUB_REPLACE}" "${STUB_REPLACE_TARGET:?}"
fi
exit 0
"""

BT0 = b"\0\0\0\0eGON.BT0" + b"\0" * 8
MAIN_FEL = b"fake main-fel\n"
EDK2_FD = b"fake edk2 fd\n"


def check(name, condition, detail):
    if condition:
        print(f"ok   {name}")
        return 0
    print(f"FAIL {name}: {detail}")
    return 1


def make_build(root, name, bt0_fel):
    d = root / name / "build"
    (d / "edk2").mkdir(parents=True, exist_ok=True)
    (d / "bt0.bin").write_bytes(BT0)
    (d / "bt0-fel.bin").write_bytes(bt0_fel)
    (d / "main-fel.bin").write_bytes(MAIN_FEL)
    (d / "edk2" / "CUBIEA7A_EFI.fd").write_bytes(EDK2_FD)
    return d


def make_repo(root, name):
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(d)], check=True)
    subprocess.run(["git", "-C", str(d), "config", "user.name", "test"], check=True)
    subprocess.run(
        ["git", "-C", str(d), "config", "user.email", "test@example.com"], check=True
    )
    (d / "file").write_text("x\n")
    subprocess.run(["git", "-C", str(d), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(d), "commit", "-q", "-m", "test"],
        check=True,
        capture_output=True,
    )
    sha = subprocess.run(
        ["git", "-C", str(d), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return d, sha


def record(build, mode, profile, features, repo):
    return subprocess.run(
        [
            sys.executable,
            "-I",
            str(FEL_MANIFEST),
            "record",
            "--build-dir",
            str(build),
            "--mode",
            mode,
            "--profile",
            profile,
            "--features",
            features,
            "--workspace",
            str(repo),
            "--oreboot",
            str(repo),
        ],
        capture_output=True,
        text=True,
    )


def package(build, out):
    return subprocess.run(
        [
            sys.executable,
            "-I",
            str(FEL_MANIFEST),
            "package",
            "--build-dir",
            str(build),
            "--out-dir",
            str(out),
        ],
        capture_output=True,
        text=True,
    )


def make_bundle(root, name, mode, profile, features, bt0_fel, repo):
    build = make_build(root, name, bt0_fel)
    proc = record(build, mode, profile, features, repo)
    if proc.returncode != 0:
        raise AssertionError(f"record {name} failed: {proc.stderr}")
    out = root / name / "bundle"
    proc = package(build, out)
    if proc.returncode != 0:
        raise AssertionError(f"package {name} failed: {proc.stderr}")
    return out


def copy_bundle(src, dst):
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    return dst


def edit_manifest(bundle, **changes):
    path = bundle / "build-manifest.json"
    manifest = json.loads(path.read_text())
    manifest.update(changes)
    path.write_text(json.dumps(manifest, indent=2) + "\n")


def write_stubs(root):
    d = root / "stub"
    d.mkdir(parents=True, exist_ok=True)
    for name in ("xfel", "sunxi-fel"):
        path = d / name
        path.write_text(STUB_XFEL)
        path.chmod(0o755)
    path = d / "lsusb"
    path.write_text(STUB_LSUSB)
    path.chmod(0o755)
    return d


def run_fel_boot(
    bundle,
    stub_dir,
    log,
    mem,
    expect_profile="1200",
    auth=None,
    replace=None,
    expect_source=None,
    expect_oreboot=None,
):
    env = dict(os.environ)
    env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"
    env["XFEL"] = "xfel"
    env["SUDO"] = ""
    env["STUB_LOG"] = str(log)
    env["STUB_MEM"] = str(mem)
    env["EXPECT_PROFILE"] = expect_profile
    if expect_source:
        env["EXPECT_SOURCE_SHA"] = expect_source
    if expect_oreboot:
        env["EXPECT_OREBOOT_SHA"] = expect_oreboot
    if auth is not None:
        env["FEL_MEASUREMENT_AUTH"] = str(auth)
    elif "FEL_MEASUREMENT_AUTH" in env:
        del env["FEL_MEASUREMENT_AUTH"]
    if replace is not None:
        env["STUB_REPLACE"] = str(replace[0])
        env["STUB_REPLACE_TARGET"] = str(replace[1])
    else:
        env.pop("STUB_REPLACE", None)
        env.pop("STUB_REPLACE_TARGET", None)
    for f in mem.iterdir():
        f.unlink()
    log.write_text("")
    proc = subprocess.run(
        ["bash", str(FEL_BOOT), str(bundle)], env=env, capture_output=True, text=True
    )
    calls = [line for line in log.read_text().splitlines() if line.strip()]
    return proc, calls


def write_auth(path, digest, ref="DECISIONS 2026-11-18; queue key task-000077"):
    path.write_text(
        json.dumps({"bt0_fel_sha256": digest, "authorization": ref}, indent=2) + "\n"
    )


def make_dry(args):
    proc = subprocess.run(
        ["make", "-n"] + args, cwd=ROOT, capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise AssertionError(f"make -n {' '.join(args)} failed: {proc.stderr}")
    return proc.stdout


def fel_out_dir(dry):
    for line in dry.splitlines():
        if "fel-manifest.py package" in line:
            match = re.search(r"--out-dir (\S+)", line)
            if match:
                return match.group(1)
    raise AssertionError("no fel-manifest.py package line in make -n output")


def check_paths(repo):
    failures = 0
    expected = {"blobfree-1200", "blobfree-2400", "dramlib-2400"}
    slots = []
    for args in ([], ["DRAM_MHZ=2400"], ["VENDOR_DRAM=yes", "DRAM_MHZ=2400"]):
        out = fel_out_dir(make_dry(["fel-image"] + args))
        slots.append(Path(out).name)
        failures += check(
            f"fel-image {' '.join(args) or 'default'} under out/fel",
            out.startswith(str(ROOT / "out" / "fel") + "/"),
            out,
        )
    failures += check(
        "fel-image slots distinct and named", set(slots) == expected, slots
    )

    boot_slots = []
    for args in ([], ["DRAM_MHZ=2400"], ["VENDOR_DRAM=yes", "DRAM_MHZ=2400"]):
        dry = make_dry(["fel-boot"] + args)
        match = re.search(r"scripts/fel-boot\.sh (\S+)", dry)
        boot_slots.append(Path(match.group(1)).name if match else None)
    failures += check(
        "fel-boot slots distinct and matching", set(boot_slots) == expected, boot_slots
    )

    # A swapped intermediate must be refused by the packaging step.
    build = make_build(
        Path(tempfile.mkdtemp(prefix="fel-swap-")), "swap", b"original\n"
    )
    proc = record(build, "blobfree", "1200", "fel", repo)
    if proc.returncode != 0:
        raise AssertionError(f"record swap failed: {proc.stderr}")
    (build / "bt0-fel.bin").write_bytes(b"swapped vendor bt0-fel\n")
    out = build.parent / "bundle"
    proc = package(build, out)
    failures += check(
        "swapped intermediate refused",
        proc.returncode != 0 and not out.exists(),
        f"rc={proc.returncode}, out exists={out.exists()}, stderr={proc.stderr.strip()!r}",
    )
    shutil.rmtree(build.parent)
    return failures


def main():
    failures = 0
    with tempfile.TemporaryDirectory(prefix="fel-w2-test-") as tmp:
        root = Path(tmp)
        stub_dir = write_stubs(root)
        log = root / "stub.log"
        mem = root / "mem"
        mem.mkdir()
        repo, repo_sha = make_repo(root, "repo")
        os.environ["EXPECT_SOURCE_SHA"] = repo_sha
        os.environ["EXPECT_OREBOOT_SHA"] = repo_sha

        failures += check_paths(repo)

        good = make_bundle(
            root,
            "good",
            "blobfree",
            "1200",
            "fel",
            b"fake bt0-fel blobfree\n",
            repo,
        )
        proc, calls = run_fel_boot(good, stub_dir, log, mem)
        loaded = [c for c in calls if c.startswith("write 0x90000")]
        staged = mem / "0x90000.bin"
        got = staged.read_bytes() if staged.exists() else None
        failures += check(
            "valid blobfree reaches xfel with the staged bytes",
            bool(loaded) and got == (good / "bt0-fel.bin").read_bytes(),
            f"calls={calls}, got={got!r}, stderr={proc.stderr.strip()!r}",
        )

        def refused(label, bundle, **kw):
            proc, calls = run_fel_boot(bundle, stub_dir, log, mem, **kw)
            return check(
                label,
                proc.returncode != 0 and not calls,
                f"rc={proc.returncode}, calls={calls}, stderr={proc.stderr.strip()!r}",
            )

        unknown = copy_bundle(good, root / "unknown")
        edit_manifest(unknown, source_sha="unknown")
        failures += refused("unknown provenance refused", unknown)

        bad_source = copy_bundle(good, root / "bad-source")
        edit_manifest(bad_source, source_sha="0" * 40)
        failures += refused("mismatched workspace SHA refused", bad_source)

        bad_oreboot = copy_bundle(good, root / "bad-oreboot")
        edit_manifest(bad_oreboot, oreboot_sha="0" * 40)
        failures += refused("mismatched oreboot SHA refused", bad_oreboot)

        dirty = copy_bundle(good, root / "dirty")
        edit_manifest(dirty, clean=False)
        failures += refused("dirty build refused", dirty)

        wrong_profile = copy_bundle(good, root / "wrong-profile")
        edit_manifest(wrong_profile, profile="2400")
        failures += refused("wrong profile refused", wrong_profile)

        mixed = copy_bundle(good, root / "mixed")
        edit_manifest(mixed, features=["fel", "dramlib"])
        failures += refused("mixed-mode manifest refused", mixed)

        replaced = copy_bundle(good, root / "replaced")
        (replaced / "bt0-fel.bin").write_bytes(b"replaced after packaging\n")
        failures += refused("file replaced after packaging refused", replaced)

        dramlib = make_bundle(
            root,
            "dramlib",
            "dramlib",
            "2400",
            "fel dramlib",
            b"fake bt0-fel dramlib\n",
            repo,
        )
        failures += refused(
            "measurement bundle without authorization refused",
            dramlib,
            expect_profile="2400",
        )

        digest = json.loads((dramlib / "build-manifest.json").read_text())[
            "bt0_fel_sha256"
        ]
        wrong_auth = root / "wrong-auth.json"
        write_auth(wrong_auth, "0" * 64)
        failures += refused(
            "wrong measurement authorization refused",
            dramlib,
            expect_profile="2400",
            auth=wrong_auth,
        )

        auth = root / "auth.json"
        write_auth(auth, digest)
        proc, calls = run_fel_boot(
            dramlib, stub_dir, log, mem, expect_profile="2400", auth=auth
        )
        loaded = [c for c in calls if c.startswith("write 0x90000")]
        got = (
            (mem / "0x90000.bin").read_bytes()
            if (mem / "0x90000.bin").exists()
            else None
        )
        failures += check(
            "authorized measurement bundle reaches xfel",
            bool(loaded) and got == (dramlib / "bt0-fel.bin").read_bytes(),
            f"calls={calls}, got={got!r}, stderr={proc.stderr.strip()!r}",
        )

        original = (good / "bt0-fel.bin").read_bytes()
        replacement = root / "replacement.bin"
        replacement.write_bytes(b"replacement after validation\n")
        proc, calls = run_fel_boot(
            good,
            stub_dir,
            log,
            mem,
            replace=(replacement, good / "bt0-fel.bin"),
        )
        got = (
            (mem / "0x90000.bin").read_bytes()
            if (mem / "0x90000.bin").exists()
            else None
        )
        failures += check(
            "replacement after validation not passed to xfel",
            got == original
            and (good / "bt0-fel.bin").read_bytes()
            == b"replacement after validation\n",
            f"got={got!r}, original={original!r}, stderr={proc.stderr.strip()!r}",
        )

    print(f"{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
