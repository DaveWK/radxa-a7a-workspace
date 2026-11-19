#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise make fel-image/fel-boot with fixture compilers and fake USB."""

import argparse
import fcntl
import hashlib
import json
import os
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT
BOARD = Path("firmware/oreboot/src/mainboard/radxa/cubie-a7a")
FD = "CUBIEA7A_EFI.fd"
MAIN = b"main-fel from the fake compiler\n"
DTB = b"test device tree\n"
BT0 = b"\0\0\0\0eGON.BT0" + bytes(256)
PACKAGED = {
    "bt0-fel.bin": "bt0_fel_sha256",
    "firmware.bin": "firmware_sha256",
    "firmware.seek": "firmware_seek_sha256",
}

FAKE_TOOLS = r"""
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
env = os.environ

def event(event_name):
    if "FAKE_SYNC" in env:
        with open(env["FAKE_SYNC"], "w") as pipe:
            pipe.write(event_name + "\n")

if tool == "cargo":
    target = Path(env["CARGO_TARGET_DIR"])
    knobs = {k: v for k, v in env.items() if k.startswith(("A7A_", "A733_"))}
    with open(env["FAKE_CARGO_LOG"], "a") as log:
        log.write(json.dumps([target.name, args, knobs]) + "\n")
    if target.name == "main-fel":
        arch, binary = "aarch64-unknown-none-softfloat", "oreboot-cubie-a7a-main"
        data = b"main-fel from the fake compiler\n"
    else:
        arch, binary = "armv7a-none-eabi", "oreboot-cubie-a7a-bt0"
        data = b"\0\0\0\0eGON.BT0" + bytes(256)
        if target.name == "bt0-fel":
            data += json.dumps([args, sorted(knobs)], sort_keys=True).encode()
            data += knobs.get("A7A_PROFILE", "").encode()
            if "FAKE_DIRTY_DURING" in env:
                Path(env["FAKE_DIRTY_DURING"]).write_text("modified during compilation\n")
            if "FAKE_HEAD_CHANGE" in env:
                subprocess.run(["git", "-C", env["FAKE_HEAD_CHANGE"], "commit",
                                "-qm", "concurrent commit", "--allow-empty"], check=True)
    path = target / arch / "release" / binary
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
elif tool == "llvm-objcopy":
    shutil.copyfile(args[-2], args[-1])
elif tool == "flock":
    event("lock")
    os.execv(env["REAL_FLOCK"], [env["REAL_FLOCK"], *args])
elif tool == "build":
    event("edk2")
    defines = [arg for arg in args if "=" in arg]
    tag = next(arg.split("=", 1)[1] for arg in defines if arg.startswith("BUILD_TAG="))
    dtb = next(arg.split("=", 1)[1] for arg in defines if arg.startswith("DTB_FILE="))
    target = args[args.index("-b") + 1]
    dest = Path(f"Build/CubieA7A{tag}/{target}_GCC/FV")
    dest.mkdir(parents=True, exist_ok=True)
    data = bytearray(4 * 1024 * 1024)
    struct.pack_into("<I", data, 4, 0x14000000 + ((0x40000 - 4) // 4))
    data[0x38:0x3c] = b"ARMd"
    struct.pack_into("<I", data, 0x40000, 0x14000001)
    data[0x50000:] = Path(dtb).read_bytes().ljust(len(data) - 0x50000, b"\0")
    (dest / "CUBIEA7A_EFI.fd").write_bytes(data)
elif tool == "cp":
    subprocess.run([env["REAL_CP"], *args], check=True)
    if "FAKE_SWAP" in env and ".snapshot." in args[-1] and args[-1].endswith("main-fel.bin"):
        src, dst = map(Path, args[-2:])
        assert dst.parent.stat().st_mode & 0o777 == 0o700
        src.write_bytes(b"replacement after copy\n")
        Path(env["FAKE_SWAP"]).write_text("swapped after snapshot copy")
elif tool == "aarch64-linux-gnu-gcc":
    sys.exit("the fixture must not run the cross compiler")
elif tool in ("xfel", "lsusb"):
    with open(env["FAKE_USB_LOG"], "a") as log:
        log.write(json.dumps([tool, *args]) + "\n")
    if tool == "lsusb":
        if "FAKE_BOOT_SWAP" in env:
            Path(env["FAKE_BOOT_SWAP"]).write_bytes(b"replacement after validation\n")
    else:
        cmd, *params = args
        mem = Path(env["FAKE_MEM"])
        if cmd == "version":
            print("xfel fixture ID=0x00190300")
        elif cmd == "write":
            addr, contents = params
            shutil.copyfile(contents, mem / addr)
        elif cmd == "read":
            addr, size, out = params
            if addr == "0xdf000" and size == "28":
                state = 0x21 if (mem / "entry2").exists() else 0x11
                data = struct.pack("<7I", 0x46413741, state, 4096, 1200, 0, 0, 0)
            else:
                data = (mem / addr).read_bytes()
            Path(out).write_bytes(data[:int(size)])
        elif cmd == "exec" and params == ["0x90044"]:
            (mem / "entry2").touch()
else:
    sys.exit(f"unknown fixture tool {tool}")
"""

# At the old hash-to-open race, change the main binary just as mkimage opens
# it. On W3 the cp fixture above has already replaced the original instead.
MKIMAGE_HOOK = r"""
    import os
    if "FAKE_SWAP" in os.environ and ".snapshot." not in a.main:
        Path(a.main).write_bytes(b"replacement after copy\n")
        Path(os.environ["FAKE_SWAP"]).write_text("swapped before packaging open")
"""


def sha(path):
    with path.open("rb") as image:
        return hashlib.file_digest(image, "sha256").hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def write_json(path, data):
    path.write_text(json.dumps(data))


def git(cwd, *args):
    return subprocess.check_output(
        ["git", "-C", str(cwd), *args], text=True, stderr=subprocess.PIPE
    ).strip()


class GateTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / "out"
        scratch.mkdir(exist_ok=True)
        tmp = tempfile.TemporaryDirectory(prefix="fel-test-", dir=scratch)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.workspace = self.root / "workspace"
        self.oreboot = self.workspace / "firmware" / "oreboot"
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.mem = self.root / "mem"
        self.mem.mkdir()
        self.cargo_log = self.root / "cargo.log"
        self.usb_log = self.root / "usb.log"
        self.cargo_log.touch()
        self.usb_log.touch()
        self.env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("A7A_", "A733_", "EXPECT_", "FEL_", "GIT_"))
            and k
            not in (
                "MAKEFLAGS",
                "MFLAGS",
                "DRAM_MHZ",
                "VENDOR_DRAM",
                "EDK2_DIR",
                "EDK2_PLATFORMS_DIR",
                "MAKELEVEL",
                "MAKEOVERRIDES",
            )
        }
        self.env.update(
            PATH=f"{self.tools}:{os.environ['PATH']}",
            SUDO="",
            FAKE_CARGO_LOG=str(self.cargo_log),
            FAKE_USB_LOG=str(self.usb_log),
            FAKE_MEM=str(self.mem),
            REAL_CP=shutil.which("cp"),
            REAL_FLOCK=shutil.which("flock"),
        )
        for name in (
            "cargo",
            "llvm-objcopy",
            "flock",
            "build",
            "cp",
            "aarch64-linux-gnu-gcc",
            "xfel",
            "lsusb",
        ):
            path = self.tools / name
            path.write_text(f"#!{sys.executable}\n{FAKE_TOOLS}")
            path.chmod(0o755)

        self.workspace.mkdir()
        shutil.copy2(SOURCE / "Makefile", self.workspace)
        scripts = self.workspace / "scripts"
        scripts.mkdir()
        for name in (
            "mkimage.py",
            "fel-manifest.py",
            "fel-check.py",
            "fel-boot.sh",
            "build-edk2.sh",
        ):
            shutil.copy2(SOURCE / "scripts" / name, scripts)
        shutil.copytree(
            SOURCE / "scripts" / "lib",
            scripts / "lib",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        mkimage = scripts / "mkimage.py"
        text = mkimage.read_text()
        marker = "    disk, entries = build_firmware("
        self.assertIn(marker, text)
        mkimage.write_text(text.replace(marker, MKIMAGE_HOOK + "\n" + marker, 1))
        self.file("scripts/check-nvstore.py", "# Fake firmware has no NV store.\n")
        self.file(
            ".gitignore", "/out/\n/vendor/\n__pycache__/\n/firmware/edk2/Build/\n"
        )
        self.file("fedora/fedora/mkdevcard.sh", "")
        self.file(
            "fedora/fedora/dts/Makefile",
            'all:\n\tmkdir -p "$(dir $(OUT))"\n\tprintf "test device tree\\n" >"$(OUT)"\n',
        )
        self.file("firmware/edk2/edksetup.sh", "# build is on the fixture PATH\n")
        self.file("firmware/edk2/MdePkg/Library/BaseFdtLib/libfdt/libfdt/fdt.h", "")
        self.file("firmware/edk2/BaseTools/Source/C/bin/GenFv", "").chmod(0o755)
        self.file("firmware/edk2-platforms/Platform/Radxa/CubieA7APkg/CubieA7A.dsc", "")
        self.file(
            "firmware/edk2-platforms/OreEdk2Boot/OreEdk2BootPkg/OreEdk2BootPkg.dec", ""
        )
        (self.workspace / BOARD / "main").mkdir(parents=True)
        self.file(BOARD / "main" / "Cargo.toml", "# main source\n")
        self.file(BOARD / "bt0" / "Cargo.toml", "# bt0 source\n")
        self.init_repo(self.oreboot)
        self.init_repo(self.workspace, exclude="firmware/oreboot")
        pin = git(self.oreboot, "rev-parse", "HEAD")
        git(
            self.workspace,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{pin},firmware/oreboot",
        )
        git(self.workspace, "commit", "-qm", "Pin fixture oreboot")
        self.file("vendor/dramlib/libdram", "fixture vendor input only\n")
        self.file("out/oreboot/libdram-a733.a", "fixture archive only\n")
        self.assertEqual(git(self.workspace, "status", "--porcelain"), "")

    def file(self, name, contents):
        path = self.workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    @staticmethod
    def init_repo(repo, exclude=None):
        git(repo, "init", "--template=")
        git(repo, "config", "user.name", "Fixture")
        git(repo, "config", "user.email", "fixture@example.invalid")
        args = [".", f":(exclude){exclude}"] if exclude else ["."]
        git(repo, "add", "--", *args)
        git(repo, "commit", "-qm", "Fixture sources")

    def make(self, *args, **env):
        return subprocess.run(
            ["make", "--no-print-directory", *args],
            cwd=self.workspace,
            env=dict(self.env, **env),
            text=True,
            capture_output=True,
            timeout=30,
        )

    def process_result(self, proc):
        return f"exit {proc.returncode}\n{proc.stdout}\n{proc.stderr}"

    def build(self, slot="blobfree-1200", *args, **env):
        proc = self.make("fel-image", *args, **env)
        self.assertEqual(proc.returncode, 0, self.process_result(proc))
        return self.workspace / "out" / "fel" / slot

    def boots(self, *args, auth=None, **env):
        if auth:
            env["FEL_MEASUREMENT_AUTH"] = str(auth)
        self.usb_log.write_text("")
        for f in self.mem.iterdir():
            f.unlink()
        return self.make("fel-boot", *args, f"XFEL={self.tools / 'xfel'}", **env)

    def refusal(self, proc, reason=None):
        self.assertNotEqual(proc.returncode, 0, self.process_result(proc))
        self.assertEqual(self.usb_log.read_text(), "", self.process_result(proc))
        if reason:
            self.assertIn(reason, proc.stderr)

    def record(self, bt0_digest):
        return self.workspace / "out" / "fel" / ".records" / f"{bt0_digest}.json"

    def assert_writes(self, proc, bt0, firmware, base):
        self.assertEqual(proc.returncode, 0, self.process_result(proc))
        table = firmware[0x1FF000 - base : 0x1FF000 - base + 512]
        outputs = {"0xdf000": bytes(4096), "0x90000": bt0, "0xdf200": table}
        count = struct.unpack_from("<I", table, 12)[0]
        for i in range(count):
            _, _, offset, size, addr, _, _ = struct.unpack_from(
                "<IIIIQII", table, 24 + 32 * i
            )
            outputs[hex(addr)] = firmware[offset - base : offset - base + size]
        self.assertEqual(
            [
                args[2]
                for args in map(json.loads, self.usb_log.read_text().splitlines())
                if args[:2] == ["xfel", "write"]
            ],
            list(outputs),
        )
        for addr, expected in outputs.items():
            self.assertEqual((self.mem / addr).read_bytes(), expected, addr)

    def assert_bundle_writes(self, proc, slot):
        self.assert_writes(
            proc,
            (slot / "bt0-fel.bin").read_bytes(),
            (slot / "firmware.bin").read_bytes(),
            int((slot / "firmware.seek").read_text()) * 512,
        )

    def test_snapshot_replacement_after_copy(self):
        swapped = self.root / "swap-receipt"
        bundle = self.build(FAKE_SWAP=str(swapped))
        self.assertTrue(swapped.is_file())
        contents = (bundle / "firmware.bin").read_bytes()
        base = int((bundle / "firmware.seek").read_text()) * 512
        self.assertEqual(contents[0x200000 - base : 0x200000 - base + len(MAIN)], MAIN)
        digest = sha(bundle / "bt0-fel.bin")
        record = read_json(self.record(digest))
        self.assertEqual(
            record["intermediates"]["main_fel_sha256"], hashlib.sha256(MAIN).hexdigest()
        )
        self.assertEqual(
            record["intermediates"]["dtb_sha256"], hashlib.sha256(DTB).hexdigest()
        )
        self.assertEqual(record["firmware_sha256"], sha(bundle / "firmware.bin"))
        self.assertEqual(swapped.read_text(), "swapped after snapshot copy")

    def test_unrecorded_blobfree_refused(self):
        bundle = self.build()
        self.record(sha(bundle / "bt0-fel.bin")).unlink(missing_ok=True)
        self.refusal(self.boots(), "no local build record")

    def test_measurement_record_cannot_be_relabeled(self):
        bundle = self.build("dramlib-2400", "VENDOR_DRAM=yes")
        manifest = bundle / "build-manifest.json"
        write_json(
            manifest, dict(read_json(manifest), mode="blobfree", features=["fel"])
        )
        self.refusal(self.boots("VENDOR_DRAM=yes"), "manifest mode disagrees")

    def test_record_disagrees_with_requested_and_manifest_profile(self):
        bundle = self.build()
        other = bundle.with_name("blobfree-2400")
        shutil.copytree(bundle, other)
        manifest = other / "build-manifest.json"
        data = read_json(manifest)
        data["profile"] = type(data["profile"])(2400)
        write_json(manifest, data)
        with self.subTest("requested profile"):
            self.refusal(self.boots("DRAM_MHZ=2400"), "record profile 1200")
        with self.subTest("manifest profile"):
            write_json(bundle / "build-manifest.json", data)
            self.refusal(self.boots(), "manifest profile disagrees")

    def test_rehashed_manifest_cannot_replace_record_digests(self):
        bundle = self.build()
        image = bundle / "firmware.bin"
        firmware = bytearray(image.read_bytes())
        firmware[0] ^= 1  # SD bt0 changes, while the FEL write plan still parses.
        image.write_bytes(firmware)
        manifest = bundle / "build-manifest.json"
        write_json(manifest, dict(read_json(manifest), firmware_sha256=sha(image)))
        self.refusal(self.boots(), "manifest firmware_sha256 disagrees")

    def test_manifest_cannot_claim_different_provenance(self):
        bundle = self.build()
        manifest = bundle / "build-manifest.json"
        data = read_json(manifest)
        for change in (
            {"source_sha": "unknown"},
            {"source_sha": "0" * 40},
            {"oreboot_sha": "0" * 40},
            {"clean": False},
            {"features": ["fel", "dramlib"]},
        ):
            with self.subTest(change=change):
                write_json(manifest, dict(data, **change))
                self.refusal(self.boots())

    def test_default_and_2400_compile_at_the_recorded_profile(self):
        low = self.build()
        high = self.build("blobfree-2400", "DRAM_MHZ=2400")
        entries = [json.loads(line) for line in self.cargo_log.read_text().splitlines()]
        self.assertEqual(
            [(target, knobs) for target, _, knobs in entries],
            [
                (
                    (f"bt0-{flavor}", {"A7A_PROFILE": str(profile)})
                    if flavor != "main"
                    else ("main-fel", {})
                )
                for profile in (1200, 2400)
                for flavor in ("sd", "fel", "main")
            ],
        )
        for profile, bundle in ((1200, low), (2400, high)):
            digest = sha(bundle / "bt0-fel.bin")
            record = read_json(self.record(digest))
            self.assertEqual(record["profile"], profile)
            self.assertEqual(
                record["build_environment"]["bt0_fel"], {"A7A_PROFILE": str(profile)}
            )
            self.assertEqual(
                record["source_sha"], git(self.workspace, "rev-parse", "HEAD")
            )
            self.assertEqual(
                record["oreboot_sha"], git(self.oreboot, "rev-parse", "HEAD")
            )
            self.assertTrue(record["workspace_clean"])
            self.assertTrue(record["oreboot_clean"])

    def test_inherited_knobs_refused_before_compile(self):
        for args, knob in (
            ([], "A7A_PROFILE"),
            (["VENDOR_DRAM=yes"], "A7A_FOO"),
            (["VENDOR_DRAM=phyfw"], "A733_PHY_FW_OBJ"),
        ):
            with self.subTest(mode=args, knob=knob):
                proc = self.make("fel-image", *args, **{knob: "2400"})
                self.assertNotEqual(proc.returncode, 0, self.process_result(proc))
                self.assertIn(f"refuses inherited build knobs: {knob}", proc.stderr)
                self.assertEqual(self.cargo_log.read_text(), "")

    def test_disjoint_dry_run_slots_and_fixed_measurement_profiles(self):
        for mode, profile, args in (
            ("blobfree", "1200", []),
            ("blobfree", "2400", ["DRAM_MHZ=2400"]),
            ("dramlib", "2400", ["VENDOR_DRAM=yes"]),
            ("phyfw", "2400", ["VENDOR_DRAM=phyfw"]),
        ):
            with self.subTest(mode=mode, profile=profile):
                proc = self.make("-n", "fel-image", *args)
                self.assertEqual(proc.returncode, 0, self.process_result(proc))
                slot = self.workspace / "out" / "fel" / f"{mode}-{profile}"
                self.assertIn(f"--out-dir {slot}", proc.stdout.replace('"', ""))
                self.assertIn(f"{slot}/build/", proc.stdout)
                self.assertFalse(slot.exists())
                boot = self.make("-n", "fel-boot", *args, f"XFEL={self.tools / 'xfel'}")
                self.assertEqual(boot.returncode, 0, self.process_result(boot))
                self.assertIn(
                    f"EXPECT_PROFILE={profile} scripts/fel-boot.sh {slot}", boot.stdout
                )
                if mode == "blobfree":
                    self.assertIn(
                        f"env A7A_PROFILE={profile} CARGO_TARGET_DIR=", proc.stdout
                    )
                else:
                    self.assertNotIn("A7A_PROFILE=", proc.stdout)
        for mode in ("yes", "phyfw"):
            for rate in ("1200", "2400", ""):
                with self.subTest(mode=mode, rate=rate):
                    proc = self.make(
                        "-n", "fel-image", f"VENDOR_DRAM={mode}", f"DRAM_MHZ={rate}"
                    )
                    self.assertNotEqual(proc.returncode, 0, self.process_result(proc))
                    self.assertIn("DRAM_MHZ must be unset", proc.stderr)

    def test_uninitialized_oreboot_does_not_use_parent(self):
        (self.oreboot / ".git").rename(self.root / "removed-git")
        self.assertEqual(
            git(self.oreboot, "rev-parse", "HEAD"),
            git(self.workspace, "rev-parse", "HEAD"),
        )
        proc = self.make("fel-image")
        self.assertNotEqual(proc.returncode, 0, self.process_result(proc))
        self.assertIn("before compilation:", proc.stderr)
        self.assertIn("not an initialized repository", proc.stderr)
        self.assertEqual(self.cargo_log.read_text(), "")

    def test_dirty_oreboot_refused_before_compile(self):
        self.file(BOARD / "bt0" / "Cargo.toml", "# dirty\n")
        proc = self.make("fel-image")
        self.assertNotEqual(proc.returncode, 0, self.process_result(proc))
        self.assertEqual(self.cargo_log.read_text(), "")
        self.assertIn("before compilation:", proc.stderr)
        self.assertIn("not clean", proc.stderr)

    def test_source_edit_during_compile_refused_without_publication(self):
        proc = self.make(
            "fel-image",
            FAKE_DIRTY_DURING=str(self.workspace / BOARD / "bt0" / "Cargo.toml"),
        )
        self.assertNotEqual(proc.returncode, 0, self.process_result(proc))
        self.assertIn("after compilation:", proc.stderr)
        self.assertIn("not clean", proc.stderr)
        self.assertTrue(self.cargo_log.read_text())
        self.assertFalse((self.workspace / "out" / "fel" / ".records").exists())

    def test_clean_head_change_during_compile_refused(self):
        proc = self.make("fel-image", FAKE_HEAD_CHANGE=str(self.workspace))
        self.assertNotEqual(proc.returncode, 0, self.process_result(proc))
        self.assertIn("HEAD changed during compilation", proc.stderr)
        self.assertEqual(git(self.workspace, "status", "--porcelain"), "")
        self.assertFalse((self.workspace / "out" / "fel" / ".records").exists())

    def test_measurement_authorization_and_exact_writes(self):
        for opt, mode in (("yes", "dramlib"), ("phyfw", "phyfw")):
            with self.subTest(mode=mode):
                flags = (f"VENDOR_DRAM={opt}",)
                bundle = self.build(f"{mode}-2400", *flags)
                bt0 = sha(bundle / "bt0-fel.bin")
                self.refusal(self.boots(*flags), "FEL_MEASUREMENT_AUTH")
                auth = self.root / "auth.json"
                write_json(
                    auth, {"bt0_fel_sha256": "0" * 64, "authorization": "fixture"}
                )
                self.refusal(self.boots(*flags, auth=auth))
                write_json(auth, {"bt0_fel_sha256": bt0, "authorization": "fixture"})
                self.assert_bundle_writes(self.boots(*flags, auth=auth), bundle)
                self.assertTrue(
                    self.record(bt0).is_file(), "missing measurement record"
                )
                record = read_json(self.record(bt0))
                self.assertEqual(
                    (record["mode"], record["profile"], record["profile_source"]),
                    (mode, 2400, "fixed by mode"),
                )
                self.assertEqual(
                    set(record["build_environment"]["bt0_fel"]),
                    {"A733_DRAM_LIB"} if mode == "dramlib" else {"A733_PHY_FW_OBJ"},
                )

    def test_success_writes_staged_bt0_table_and_payload(self):
        bundle = self.build()
        bt0, firmware = (
            (bundle / name).read_bytes() for name in ("bt0-fel.bin", "firmware.bin")
        )
        proc = self.boots(FAKE_BOOT_SWAP=str(bundle / "bt0-fel.bin"))
        self.assert_writes(proc, bt0, firmware, 0x20000)
        self.assertEqual(
            (bundle / "bt0-fel.bin").read_bytes(), b"replacement after validation\n"
        )

    def refresh_fixture_digests(self, bundle):
        # Make a consistent but malformed fixture so it reaches layout/SRAM
        # validation rather than testing the digest gate a second time.
        manifest = bundle / "build-manifest.json"
        data = read_json(manifest)
        original = self.record(data["bt0_fel_sha256"])
        new = {key: sha(bundle / name) for name, key in PACKAGED.items()}
        write_json(manifest, dict(data, **new))
        if original.exists():
            record = read_json(original)
            record["intermediates"]["bt0_fel_sha256"] = new["bt0_fel_sha256"]
            write_json(self.record(new["bt0_fel_sha256"]), dict(record, **new))

    def test_malformed_bundles_make_no_usb_calls(self):
        bundle = self.build()
        files = {name: (bundle / name).read_bytes() for name in PACKAGED}
        (bundle / "firmware.seek").unlink()
        self.refusal(self.boots(), "firmware.seek missing")
        (bundle / "firmware.seek").write_bytes(files["firmware.seek"])
        image = bundle / "firmware.bin"
        bytes_ = bytearray(files["firmware.bin"])
        bytes_[0x1FF000 - 0x20000 + 16] ^= 1
        image.write_bytes(bytes_)
        self.refresh_fixture_digests(bundle)
        with self.subTest("layout corruption"):
            self.refusal(self.boots(), "layout table header or CRC")
        image.write_bytes(files["firmware.bin"])
        with (bundle / "bt0-fel.bin").open("ab") as f:
            f.truncate(0x4F001)
        self.refresh_fixture_digests(bundle)
        with self.subTest("FEL SRAM overflow"):
            self.refusal(self.boots(), "outside the FEL SRAM window")

    def test_edk2_modes_wait_at_the_same_lock(self):
        fifo = self.root / "edk2-events"
        os.mkfifo(fifo)
        pipe = os.open(fifo, os.O_RDWR)
        self.addCleanup(os.close, pipe)
        lock = self.workspace / "out" / ".edk2-build.lock"
        with lock.open("a") as locker:
            fcntl.flock(locker, fcntl.LOCK_EX)
            procs = [
                subprocess.Popen(
                    ["make", "--no-print-directory", "fel-image", *args],
                    cwd=self.workspace,
                    env=dict(self.env, FAKE_SYNC=str(fifo)),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                for args in ([], ["VENDOR_DRAM=yes"])
            ]
            flags = b""
            try:
                while len(flags.splitlines()) < 2:
                    if not select.select([pipe], [], [], 10)[0]:
                        self.fail(f"both builds did not reach EDK2: {flags!r}")
                    flags += os.read(pipe, 64)
            finally:
                fcntl.flock(locker, fcntl.LOCK_UN)
                completed = [proc.communicate(timeout=30)[0] for proc in procs]
        self.assertEqual(flags.splitlines(), [b"lock", b"lock"], completed)
        for proc, output in zip(procs, completed):
            self.assertEqual(proc.returncode, 0, output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-tree", type=Path, default=ROOT)
    args, tests = parser.parse_known_args()
    SOURCE = args.source_tree.resolve()
    unittest.main(argv=[sys.argv[0], "-v", *tests])
