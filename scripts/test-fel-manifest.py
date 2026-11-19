#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the FEL gates with fixture compilers, real Cargo config and fake USB."""

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
PROFILE = Path("src/mainboard/radxa/cubie-a7a/dram/src/knobs/profile.rs")
LIBTL = "MdePkg/Library/ArmTransferListLib/libtl"
MAIN = b"main-fel from the fake compiler\n"
# Empty root, terminating reserve-map entry and one spare padding word.
DTB = (
    struct.pack(">10I", 0xD00DFEED, 76, 56, 72, 40, 17, 16, 0, 0, 16)
    + bytes(16)
    + struct.pack(">5I", 1, 0, 2, 9, 0)
)
BT0 = b"\0\0\0\0eGON.BT0" + bytes(256)
PACKAGED = {
    "bt0-fel.bin": "bt0_fel_sha256",
    "firmware.bin": "firmware_sha256",
    "firmware.seek": "firmware_seek_sha256",
}

FAKE_TOOLS = r"""
import json
import lzma
import os
import shutil
import struct
import subprocess
import sys
from uuid import UUID
from pathlib import Path

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
env = os.environ

def event(event_name):
    if "FAKE_SYNC" in env:
        with open(env["FAKE_SYNC"], "w") as pipe:
            pipe.write(event_name + "\n")

if tool == "cargo":
    if "config" in args:
        os.execv(env["REAL_CARGO"], [env["REAL_CARGO"], *args])
    target = Path(env["CARGO_TARGET_DIR"])
    knobs = {k: v for k, v in env.items() if k.startswith(("A7A_", "A733_"))}
    if "REAL_CARGO_BUILD" in env:
        receipt = target / "fixture-knobs"
        subprocess.run([env["REAL_CARGO"], "build", "--offline", "--locked",
                        "--release"], env=dict(env, FIXTURE_KNOB_RECEIPT=str(receipt)),
                       check=True)
        knobs = dict(line.split("=", 1) for line in receipt.read_text().splitlines())
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
    with open(env["FAKE_EDK2_LOG"], "a") as log:
        log.write(json.dumps(args) + "\n")
    defines = [arg for arg in args if "=" in arg]
    tag = next(arg.split("=", 1)[1] for arg in defines if arg.startswith("BUILD_TAG="))
    dtb = next(arg.split("=", 1)[1] for arg in defines if arg.startswith("DTB_FILE="))
    target = args[args.index("-b") + 1]
    dest = Path(f"Build/CubieA7A{tag}/{target}_GCC/FV")
    dest.mkdir(parents=True, exist_ok=True)
    data = bytearray(4 * 1024 * 1024)
    struct.pack_into("<I", data, 4, 0x14000000 + ((0x40000 - 4) // 4))
    data[0x38:0x3c] = b"ARMd"
    fdf = args[args.index("-f") + 1] if "-f" in args else "Platform/Radxa/CubieA7APkg/CubieA7A.fdf"
    (dest.parent / "BuildOptions").write_text("Flash Image Definition: " + fdf + "\n")
    tree = Path(dtb).read_bytes()
    case = env.get("FAKE_EMBED", "one")
    if case == "mismatch":
        tree = tree[:-1] + bytes([tree[-1] ^ 1])
    elif case == "two":
        tree += tree
    elif case == "zero":
        tree = bytes(40)
    elif case == "oversize":
        tree = tree[:4] + b"\xff" * 4 + tree[8:]
    # Model CubieA7A.fdf:50-52,131-133,256-257 and PI file/section headers
    # (MdePkg/Include/Pi/PiFirmwareFile.h:61,71,108-133,208,220-224).
    def sec(kind, payload):
        if kind == 0x19 and case in ("short-extended", "ffs2-extended"):
            return b"\xff\xff\xff" + bytes([kind]) + struct.pack("<I",8+len(payload)) + payload
        return (4+len(payload)).to_bytes(3, "little") + bytes([kind]) + payload

    def file(name, kind, payload):
        hdr = bytearray(UUID(name).bytes_le + bytes([0, 0xaa, kind, 0])
                        + (24+len(payload)).to_bytes(3, "little") + b"\xf8")
        if (kind == 0x0b and case == "large-boot") or (kind == 2 and case == "short-large"):
            hdr[19:23] = b"\x01\0\0\0"
            hdr += struct.pack("<Q",32+len(payload))
        hdr[16] = -(sum(hdr)-hdr[17]-hdr[23]) & 255
        return hdr + payload

    def fv(files, size=None, boot=False):
        ext = 0
        if case == ("boot-ext-header" if boot else "inner-ext-header"):
            # An FV name and a 20-byte extension header in a leading PAD file.
            ext = 72 + 24
            pad = file(str(UUID(int=0)), 0xf0, UUID(int=1).bytes_le + struct.pack("<I",20))
            files = [pad, *files]
        content = bytearray()
        for item in files:
            content += item
            content += b"\xff" * (-len(content) % 8)
        size = size or (72+len(content))
        hdr = bytearray(72)
        if boot:
            struct.pack_into("<I", hdr, 0, 0x14000001)
        # MdePkg/Include/Guid/FirmwareFileSystem2.h:18-19.
        hdr[16:32] = UUID("8c8ce578-8a3d-4f1c-9935-896185c32dd3").bytes_le
        if (boot and case == "large-boot") or (not boot and case in ("short-extended","short-large")):
            hdr[16:32] = UUID("5473c07a-3dcb-4dca-bd6f-1e9689e7349a").bytes_le
        attrs = 0x800 if not boot and case == "no-read-status" else 0x804
        struct.pack_into("<Q4sIHHHBBIIII", hdr, 32, size, b"_FVH", attrs,
                         72, 0, ext, 0, 2, size, 1, 0, 0)
        if not boot and case == "one-short-block":
            struct.pack_into("<II", hdr, 56, 1, 32)
        elif boot and case == "short-map":
            struct.pack_into("<II", hdr, 56, 1, size-1)
        elif not boot and case == "no-map-terminator":
            struct.pack_into("<II", hdr, 64, 1, 1)
        elif not boot and case == "zero-block-size":
            struct.pack_into("<II", hdr, 56, 1, 0)
        struct.pack_into("<H", hdr, 50, -sum(struct.unpack("<36H",hdr)) & 0xffff)
        return (hdr + content).ljust(size, b"\xff")

    board = "5c3f8a19-2e64-4b0d-8f71-9a2c6e13d458"
    container = "9e21fd93-9c72-4c15-8c4b-e77f1db2d792"
    files = [file(container if case == "wrong-guid" else board, 2,
                  sec(0x15 if case == "wrong-type" else 0x19, tree))]
    if case == "two-files":
        # Only the second file has the magic/digest: counting FDTs is not
        # counting files, and the driver requests instance zero.
        files.insert(0, file(board, 2, sec(0x19, bytes(40))))
    if case == "unrelated-magic":
        # A magic constant in an unrelated file cannot make the board file
        # ambiguous. This is not a second board file or a second tree.
        files.insert(0, file(container, 2, sec(0x19, tree[:4])))
    stream = sec(0x17, fv(files))
    packed = lzma.compress(stream, format=lzma.FORMAT_ALONE)
    if case != "unknown-size":
        packed = packed[:5] + struct.pack("<Q",len(stream)) + packed[13:]
    if case == "corrupt":
        packed = packed[:-5]
    section = sec(2, UUID("ee4e5898-3914-4259-9d6e-dc7bd79403cf").bytes_le
                  + struct.pack("<HH",24,1) + packed)
    if case == "two-sections":
        section += bytes(-len(section) % 4)
        section += section
    carrier = file(container, 0x0b, section)
    outside = case == "outside-boot"
    data[0x40000:0x2c0000] = fv([] if outside else [carrier], 0x280000, True)
    if outside:
        decoy = fv([carrier])
        data[0x300000:0x300000+len(decoy)] = decoy
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
        if "FAKE_XFEL_SWAP" in env:
            Path(env["FAKE_XFEL_SWAP"]).write_text("#!/bin/sh\nexit 97\n")
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

CARGO_BUILD_RS = """
fn main() {
    let knobs: String = std::env::vars()
        .filter(|(name, _)| name.starts_with("A7A_") || name.starts_with("A733_"))
        .map(|(name, value)| format!("{name}={value}\\n"))
        .collect();
    std::fs::write(std::env::var_os("FIXTURE_KNOB_RECEIPT").unwrap(), knobs).unwrap();
}
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
    @classmethod
    def setUpClass(cls):
        # make test must work before the real EDK2 build. Build the one C
        # decoder in scratch, without modifying the production tool stamp/bin.
        scratch = ROOT / "out"
        scratch.mkdir(exist_ok=True)
        tmp = tempfile.TemporaryDirectory(prefix="fel-test-basetools-", dir=scratch)
        cls.addClassCleanup(tmp.cleanup)
        edk2 = ROOT / "firmware/edk2"
        source = edk2 / "BaseTools/Source/C"
        dest = Path(tmp.name)
        for name in ("Makefiles", "Common", "LzmaCompress", "Include"):
            shutil.copytree(
                source / name, dest / name, ignore=shutil.ignore_patterns("*.o", "*.d")
            )
        shutil.copy2(source / "GNUmakefile", dest)
        subprocess.run(
            ["make", "-s", "-C", dest, f"EDK2_PATH={edk2}", "LzmaCompress"], check=True
        )
        cls.decoder = dest / "bin/LzmaCompress"

    def setUp(self):
        scratch = ROOT / "out"
        scratch.mkdir(exist_ok=True)
        tmp = tempfile.TemporaryDirectory(prefix="fel-test-", dir=scratch)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.workspace = self.root / "workspace"
        self.oreboot = self.workspace / "firmware" / "oreboot"
        self.edk2 = self.workspace / "firmware" / "edk2"
        self.platforms = self.workspace / "firmware" / "edk2-platforms"
        self.fedora = self.workspace / "fedora"
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.mem = self.root / "mem"
        self.mem.mkdir()
        self.cargo_log = self.root / "cargo.log"
        self.edk2_log = self.root / "edk2.log"
        self.usb_log = self.root / "usb.log"
        self.cargo_log.touch()
        self.edk2_log.touch()
        self.usb_log.touch()
        (self.root / "caller-cargo").mkdir()
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
            CARGO_HOME=str(self.root / "caller-cargo"),
            CARGO_NET_OFFLINE="true",
            SUDO="",
            FAKE_CARGO_LOG=str(self.cargo_log),
            FAKE_EDK2_LOG=str(self.edk2_log),
            FAKE_USB_LOG=str(self.usb_log),
            FAKE_MEM=str(self.mem),
            REAL_CP=shutil.which("cp"),
            REAL_CARGO=shutil.which("cargo"),
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
        self.env["EXPECT_XFEL_SHA256"] = sha(self.tools / "xfel")

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
        if (SOURCE / "scripts/fel-tools.py").exists():
            shutil.copy2(SOURCE / "scripts/fel-tools.py", scripts)
        if (SOURCE / "scripts/fel-fmmt.py").exists():
            shutil.copy2(SOURCE / "scripts/fel-fmmt.py", scripts)
        mkimage = scripts / "mkimage.py"
        text = mkimage.read_text()
        marker = "    disk, entries = build_firmware("
        self.assertIn(marker, text)
        mkimage.write_text(text.replace(marker, MKIMAGE_HOOK + "\n" + marker, 1))
        self.file("scripts/check-nvstore.py", "# Fake firmware has no NV store.\n")
        self.file(".gitignore", "/out/\n/vendor/\n__pycache__/\n")
        self.file("fedora/fedora/mkdevcard.sh", "")
        self.file(
            "fedora/fedora/dts/Makefile",
            'all:\n\tmkdir -p "$(dir $(OUT))"\n\tcp fixture.dtb "$(OUT)"\n',
        )
        (self.fedora / "fedora/dts/fixture.dtb").write_bytes(DTB)
        self.file("firmware/edk2/edksetup.sh", "# build is on the fixture PATH\n")
        self.file(
            "firmware/edk2/.gitignore", "/Build/\n/BaseTools/Source/C/bin/\n/Conf/\n"
        )
        for name in ("target.txt", "tools_def.txt", "build_rule.txt"):
            self.file("firmware/edk2/Conf/" + name, f"# fixture {name}\n")
        self.file(
            "firmware/edk2/BaseTools/Source/C/Makefile",
            'all:\n\tmkdir -p bin\n\tprintf "fixture binary" >bin/GenFv\n\tchmod 755 bin/GenFv\n',
        )
        self.file("firmware/edk2/MdePkg/Library/BaseFdtLib/libfdt/libfdt/fdt.h", "")
        self.file("firmware/edk2/BaseTools/Source/C/bin/GenFv", "").chmod(0o755)
        source = ROOT / "firmware/edk2/BaseTools/Source"
        dest = self.edk2 / "BaseTools/Source"
        for name in ("FirmwareStorageFormat", "FMMT"):
            shutil.copytree(
                source / "Python" / name,
                dest / "Python" / name,
                ignore=shutil.ignore_patterns("__pycache__", "*.log", "Img"),
            )
        shutil.copy2(self.decoder, dest / "C/bin")
        self.file("firmware/edk2-platforms/Platform/Radxa/CubieA7APkg/CubieA7A.dsc", "")
        self.file(
            "firmware/edk2-platforms/OreEdk2Boot/OreEdk2BootPkg/OreEdk2BootPkg.dec", ""
        )
        (self.workspace / BOARD / "main").mkdir(parents=True)
        self.file(
            "firmware/oreboot/rust-toolchain.toml",
            '[toolchain]\nchannel = "nightly-2026-05-06"\n',
        )
        for crate in ("bt0", "main"):
            path = BOARD / crate
            self.file(
                path / "Cargo.toml",
                '[package]\nname = "knob-fixture"\nversion = "0.0.0"\nedition = "2021"\n',
            )
            self.file(
                path / "Cargo.lock",
                'version = 4\n[[package]]\nname = "knob-fixture"\nversion = "0.0.0"\n',
            )
            self.file(path / "build.rs", CARGO_BUILD_RS)
            self.file(path / "src/lib.rs", "")
        self.file(Path("firmware/oreboot") / PROFILE, "// pinned fixture\n")
        children = (
            LIBTL,
            "MdePkg/Library/BaseFdtLib/libfdt",
            "BaseTools/Source/C/BrotliCompress/brotli",
        )
        for rel in children:
            self.file(Path("firmware/edk2") / rel / "tracked", "nested source\n")
            self.init_repo(self.edk2 / rel)
        self.init_with_links(self.edk2, children)
        deps = (self.oreboot, self.platforms, self.fedora)
        for dep in deps:
            self.init_repo(dep)
        paths = [str(dep.relative_to(self.workspace)) for dep in (*deps, self.edk2)]
        self.init_with_links(self.workspace, paths)
        self.file("vendor/dramlib/libdram", "fixture vendor input only\n")
        self.file("out/oreboot/libdram-a733.a", "fixture archive only\n")
        self.assertEqual(git(self.workspace, "status", "--porcelain"), "")

    def file(self, name, contents):
        path = self.workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    @staticmethod
    def init_with_links(repo, paths):
        (repo / ".gitmodules").write_text(
            "".join(
                f'[submodule "{rel}"]\n\tpath = {rel}\n\turl = ./{rel}\n'
                for rel in paths
            )
        )
        GateTests.init_repo(repo, *paths)
        for rel in paths:
            pin = git(repo / rel, "rev-parse", "HEAD")
            git(repo, "update-index", "--add", "--cacheinfo", f"160000,{pin},{rel}")
            git(repo, "config", f"submodule.{rel}.active", "true")
        git(repo, "commit", "-qm", "Pin fixture submodules")

    @staticmethod
    def init_repo(repo, *excluded):
        git(repo, "init", "--template=")
        git(repo, "config", "user.name", "Fixture")
        git(repo, "config", "user.email", "fixture@example.invalid")
        args = [".", *(f":(exclude){path}" for path in excluded)]
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
        return self.run_boot("make", *args, auth=auth, **env)

    def run_boot(self, entry, *args, auth=None, **env):
        if auth:
            env["FEL_MEASUREMENT_AUTH"] = str(auth)
        self.usb_log.write_text("")
        for f in self.mem.iterdir():
            f.unlink()
        if entry == "make":
            return self.make("fel-boot", *args, f"XFEL={self.tools / 'xfel'}", **env)
        env["XFEL"] = str(self.tools / "xfel")
        return subprocess.run(
            [str(self.workspace / "scripts/fel-boot.sh"), *args],
            cwd=self.workspace,
            env=dict(self.env, **env),
            text=True,
            capture_output=True,
            timeout=30,
        )

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

    def test_ancestor_cargo_config_cannot_force_profile(self):
        bundle = self.build(REAL_CARGO_BUILD="1")
        want = sha(bundle / "bt0-fel.bin")
        cfg = self.root / ".cargo" / "config.toml"
        cfg.parent.mkdir()
        cfg.write_text('[env]\nA7A_PROFILE = { value = "2400", force = true }\n')
        self.cargo_log.write_text("")
        proc = self.make("fel-image", REAL_CARGO_BUILD="1")
        if proc.returncode:
            self.assertIn("refuses Cargo [env] build knobs", proc.stderr)
            self.assertIn("A7A_PROFILE", proc.stderr)
            self.assertEqual(self.cargo_log.read_text(), "")
        else:
            self.assertEqual(
                sha(bundle / "bt0-fel.bin"), want, self.process_result(proc)
            )

    def test_caller_cargo_home_config_cannot_inject_knob(self):
        bundle = self.build(REAL_CARGO_BUILD="1")
        want = sha(bundle / "bt0-fel.bin")
        cfg = Path(self.env["CARGO_HOME"]) / "config.toml"
        cfg.write_text('[env]\nA7A_WR_STAGE = "0"\n')
        self.cargo_log.write_text("")
        proc = self.make("fel-image", REAL_CARGO_BUILD="1")
        self.assertEqual(proc.returncode, 0, self.process_result(proc))
        self.assertEqual(sha(bundle / "bt0-fel.bin"), want, self.process_result(proc))
        self.assertNotIn("A7A_WR_STAGE", self.cargo_log.read_text())

    def test_refuse_overridden_compiler_source_roots(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        roots = {
            "OREBOOT": self.oreboot,
            "BOARD": self.workspace / BOARD,
            "EDK2_DIR": self.edk2,
            "EDK2_PLATFORMS_DIR": self.platforms,
        }
        for key, original in roots.items():
            with self.subTest(root=key):
                override = elsewhere / key
                shutil.copytree(original, override)
                self.cargo_log.write_text("")
                self.edk2_log.write_text("")
                if key in ("OREBOOT", "BOARD"):
                    proc = self.make("fel-image", f"{key}={override}")
                else:
                    proc = self.make("fel-image", **{key: str(override)})
                self.refusal(proc, f"refuses {key} override")
                self.assertEqual(self.cargo_log.read_text(), "")
                self.assertEqual(self.edk2_log.read_text(), "")

    def test_edk2_roots_must_match_gitlinks(self):
        for root in (self.edk2, self.platforms):
            with self.subTest(root=root.name):
                rel = str(root.relative_to(self.workspace))
                before = git(root, "rev-parse", "HEAD")
                git(self.workspace, "update-index", "--assume-unchanged", "--", rel)
                git(root, "commit", "-qm", "unpinned EDK2 checkout", "--allow-empty")
                try:
                    self.refusal(
                        self.make("fel-image"), "does not match the workspace gitlink"
                    )
                    self.assertEqual(self.cargo_log.read_text(), "")
                    self.assertEqual(self.edk2_log.read_text(), "")
                finally:
                    git(root, "reset", "--hard", before)
                    git(
                        self.workspace,
                        "update-index",
                        "--no-assume-unchanged",
                        "--",
                        rel,
                    )

    def test_records_checked_roots_and_effective_edk2_inputs(self):
        dtb = self.root / "alternative device tree.dtb"
        dtb.write_bytes(DTB[:-1] + b"\x01")
        for args, expected in (
            ((), DTB),
            ((f"FEL_DTB_INPUT={dtb}",), dtb.read_bytes()),
        ):
            with self.subTest(passed_dtb=bool(args)):
                slot = self.build(
                    "blobfree-1200",
                    "EDK2_TARGET=RELEASE",
                    "EDK2_ARGS=-D USB_ENABLE=FALSE -D 'OTHER=with spaces'",
                    *args,
                )
                bt0 = sha(slot / "bt0-fel.bin")
                record = read_json(self.record(bt0))
                manifest = read_json(slot / "build-manifest.json")
                actual = json.loads(self.edk2_log.read_text().splitlines()[-1])
                self.assertEqual(actual.pop(), f"--conf={self.edk2}/Conf")
                start = actual.index("-D", actual.index("-n")) + 4
                effective = ["-D", "USB_ENABLE=FALSE", "-D", "OTHER=with spaces"]
                self.assertEqual(record.get("edk2_args"), effective)
                self.assertEqual(actual[start:-2], effective)
                for data in (record, manifest):
                    self.assertEqual(data["edk2_args"], effective)
                    self.assertEqual(data["edk2_target"], "RELEASE")
                    self.assertEqual(data["fel_dtb_input"], str(dtb) if args else None)
                    if args:
                        self.assertEqual(data["dtb_path"], str(dtb))
                    else:
                        self.assertIn(".compile.", data["dtb_path"])
                    self.assertEqual(
                        data["dtb_sha256"], hashlib.sha256(expected).hexdigest()
                    )
                self.assertEqual(actual[actual.index("-b") + 1], "RELEASE")
                self.assertIn(".snapshot.", actual[-1])
                self.assertEqual(
                    record["intermediates"]["dtb_sha256"], record["dtb_sha256"]
                )
                self.assertEqual(record["embedded_dtb"]["sha256"], record["dtb_sha256"])
                for name, path, top in (
                    ("oreboot", self.oreboot, self.oreboot),
                    ("board", self.workspace / BOARD, self.oreboot),
                    ("edk2", self.edk2, self.edk2),
                    ("edk2_platforms", self.platforms, self.platforms),
                ):
                    self.assertEqual(
                        record["source_roots"][name],
                        dict(
                            path=str(path),
                            toplevel=str(top),
                            head=git(top, "rev-parse", "HEAD"),
                            clean=True,
                        ),
                    )

    def test_expected_mode_is_required_before_measurement_authorization(self):
        blobfree = self.build()
        dramlib = self.build("dramlib-2400", "VENDOR_DRAM=yes")
        bt0 = sha(dramlib / "bt0-fel.bin")
        auth = self.root / "auth.json"
        write_json(auth, {"bt0_fel_sha256": bt0, "authorization": "fixture"})
        for bundle, profile, mode in (
            (blobfree, 1200, "dramlib"),
            (dramlib, 2400, "blobfree"),
        ):
            with self.subTest(mode=mode):
                self.refusal(
                    self.run_boot(
                        "script",
                        str(bundle),
                        auth=auth,
                        EXPECT_MODE=mode,
                        EXPECT_PROFILE=str(profile),
                    ),
                    f"does not match requested mode {mode}",
                )
        self.refusal(
            self.run_boot(
                "script", str(dramlib), EXPECT_MODE="dramlib", EXPECT_PROFILE="2400"
            ),
            "FEL_MEASUREMENT_AUTH",
        )
        self.assert_bundle_writes(
            self.run_boot(
                "script",
                str(dramlib),
                auth=auth,
                EXPECT_MODE="dramlib",
                EXPECT_PROFILE="2400",
            ),
            dramlib,
        )
        wrong_slot = blobfree.with_name("blobfree-2400")
        shutil.copytree(dramlib, wrong_slot)
        self.refusal(self.boots("DRAM_MHZ=2400", auth=auth), "requested mode blobfree")

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
                    f"EXPECT_MODE={mode} EXPECT_PROFILE={profile} scripts/fel-boot.sh {slot}",
                    boot.stdout,
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

    def refused_before_compile(self, reason):
        self.refusal(self.make("fel-image"), reason)
        self.assertEqual(self.cargo_log.read_text(), "")
        self.assertEqual(self.edk2_log.read_text(), "")

    def test_sparse_oreboot(self):
        git(
            self.oreboot,
            "sparse-checkout",
            "set",
            str(PROFILE.parents[3] / "bt0"),
            str(PROFILE.parents[3] / "main"),
        )
        self.assertFalse((self.oreboot / PROFILE).exists())
        self.refused_before_compile("sparse checkout")

    def changed_profile(self, flag, delete=False):
        git(self.oreboot, "update-index", "--" + flag, str(PROFILE))
        if delete:
            (self.oreboot / PROFILE).unlink()
        else:
            (self.oreboot / PROFILE).write_text("// changed\n")
        self.refused_before_compile(flag)

    def test_skip_worktree_oreboot(self):
        self.changed_profile("skip-worktree")

    def test_assume_unchanged_oreboot(self):
        self.changed_profile("assume-unchanged")

    def test_missing_oreboot_profile(self):
        self.changed_profile("assume-unchanged", delete=True)

    def test_nested_hidden_edit(self):
        child = self.edk2 / LIBTL
        git(child, "update-index", "--skip-worktree", "tracked")
        (child / "tracked").write_text("changed\n")
        self.refused_before_compile("skip-worktree")

    def test_nested_other_commit(self):
        # W4's status-only check overlooks this nested HEAD.
        git(self.edk2, "update-index", "--assume-unchanged", LIBTL)
        git(self.edk2 / LIBTL, "commit", "-qm", "other HEAD", "--allow-empty")
        self.refused_before_compile("before compilation")

    def test_nested_required_uninitialized(self):
        child = self.edk2 / LIBTL
        child.rename(self.root / "detached-child")
        child.mkdir()
        self.refused_before_compile("not initialized")

    def test_overridden_dtb_roots(self):
        for key, src in (("FEDORA", self.fedora), ("DTS", self.fedora / "fedora/dts")):
            with self.subTest(key=key):
                other = self.root / key
                shutil.copytree(src, other)
                self.refusal(
                    self.make("fel-image", f"{key}={other}"), f"refuses {key} override"
                )
                self.assertEqual(self.cargo_log.read_text(), "")

    def test_fedora_gitlink(self):
        git(self.workspace, "update-index", "--assume-unchanged", "fedora")
        git(self.fedora, "commit", "-qm", "other Fedora HEAD", "--allow-empty")
        self.refused_before_compile("workspace gitlink")

    def test_external_dtb_digest_before_usb(self):
        dtb = self.root / "external.dtb"
        dtb.write_bytes(DTB)
        bundle = self.build("blobfree-1200", f"FEL_DTB_INPUT={dtb}")
        self.refusal(self.boots(), "EXPECT_DTB_SHA256")
        self.refusal(self.boots(EXPECT_DTB_SHA256="a" * 64), "EXPECT_DTB_SHA256")
        self.assert_bundle_writes(self.boots(EXPECT_DTB_SHA256=sha(dtb)), bundle)

    def test_packaged_dtb_refusals(self):
        for case, msg in (
            ("zero", "FDT header"),
            ("two", "totalsize"),
            ("mismatch", "digest differs"),
            ("two-sections", "found 2"),
            ("oversize", "totalsize"),
            ("corrupt", "LZMA"),
        ):
            with self.subTest(case=case):
                self.refusal(self.make("fel-image", FAKE_EMBED=case), msg)
                root = self.workspace / "out/fel"
                self.assertFalse((root / ".records").exists())
                self.assertFalse((root / "blobfree-1200/firmware.bin").exists())

    def test_packaged_dtb_identity(self):
        slot = self.build(
            "blobfree-1200", "EDK2_ARGS=-f Local.fdf", FAKE_EMBED="unrelated-magic"
        )
        record = read_json(self.record(sha(slot / "bt0-fel.bin")))
        self.assertEqual(record.get("edk2_fdf"), "Local.fdf")
        head = git(self.fedora, "rev-parse", "HEAD")
        self.assertEqual(record["dtb_source"], "fedora@" + head)
        self.assertEqual(record["dts_dir"], str(self.fedora / "fedora/dts"))
        evidence = record["embedded_dtb"]
        invocation = evidence["fmmt_invocation"]
        exe, flags, helper, source, package, digest, receipt = invocation["argv"]
        source = Path(source)
        self.assertEqual((flags, digest), ("-IB", record["dtb_sha256"]))
        self.assertEqual(Path(helper), self.workspace / "scripts/fel-fmmt.py")
        self.assertEqual(source, self.edk2 / "BaseTools/Source")
        self.assertEqual(invocation["tool_root"], str(source))
        self.assertEqual(Path(package).name, "firmware.bin")
        self.assertEqual(Path(receipt), Path(invocation["cwd"]) / "verified.json")
        self.assertIsNone(invocation["PYTHONPATH"])
        self.assertEqual(
            invocation["import_roots"],
            [str(source / "Python/FMMT"), str(source / "Python")],
        )
        for tool, value in evidence["fmmt_tools_sha256"].items():
            self.assertEqual(value, sha(source / tool))
        self.assertIn(exe, evidence["fmmt_tools_sha256"])
        self.assertIn(helper, evidence["fmmt_tools_sha256"])
        section = (slot / "firmware.bin").read_bytes()[evidence["section_offset"] :][
            : evidence["section_length"]
        ]
        import lzma

        stream = lzma.decompress(section[24:], format=lzma.FORMAT_ALONE)
        self.assertEqual(
            stream[evidence["decoded_dtb_offset"] :][: evidence["dtb_size"]], DTB
        )
        self.assertEqual(evidence["sha256"], record["dtb_sha256"])
        self.assertEqual(evidence["boot_fv_fd_offset"], 0x40000)
        self.assertEqual(
            evidence["dtb_file_guid"], "5c3f8a19-2e64-4b0d-8f71-9a2c6e13d458"
        )

    def test_boot_fv_dtb_path_refusals(self):
        for case, reason in (
            ("wrong-guid", "board DTB file, found 0"),
            ("wrong-type", "board DTB section is not RAW"),
            ("outside-boot", "FVMAIN container, found 0"),
            ("two-files", "board DTB file, found 2"),
        ):
            with self.subTest(case=case):
                self.refusal(self.make("fel-image", FAKE_EMBED=case), reason)
                self.assertFalse((self.workspace / "out/fel/.records").exists())

    def test_fv_block_map(self):
        for case, reason in (
            ("one-short-block", "cannot cover the header"),
            ("short-map", "does not cover the volume"),
            ("no-map-terminator", "unterminated FV block map"),
            ("zero-block-size", "invalid FV block map entry"),
        ):
            with self.subTest(case=case):
                self.refusal(self.make("fel-image", FAKE_EMBED=case), reason)
                self.assertFalse((self.workspace / "out/fel/.records").exists())

    def test_fv_extension_headers(self):
        for case in ("boot-ext-header", "inner-ext-header"):
            with self.subTest(case=case):
                self.refusal(
                    self.make("fel-image", FAKE_EMBED=case),
                    "unsupported FV extension header",
                )
                self.assertFalse((self.workspace / "out/fel/.records").exists())

    def test_loader_refusals(self):
        for case, reason in (
            ("unknown-size", "LZMA"),
            ("short-extended", "extended section size"),
            ("ffs2-extended", "extended section in FFS2"),
            ("large-boot", "large FFS header in boot FV"),
            ("short-large", "large FFS size"),
            ("no-read-status", "read status"),
        ):
            with self.subTest(case=case):
                self.refusal(self.make("fel-image", FAKE_EMBED=case), reason)
                self.assertFalse((self.workspace / "out/fel/.records").exists())

    def test_loader_fdt_limits(self):
        for reason, tree in (
            ("libfdt", DTB[:20] + bytes(4) + DTB[24:]),
            (
                "4 MiB",
                DTB[:4]
                + struct.pack(">I", (4 << 20) + 1)
                + DTB[8:]
                + bytes((4 << 20) + 1 - len(DTB)),
            ),
        ):
            with self.subTest(reason=reason):
                dtb = self.root / "input.dtb"
                dtb.write_bytes(tree)
                self.refusal(self.make("fel-image", f"FEL_DTB_INPUT={dtb}"), reason)
                self.assertFalse((self.workspace / "out/fel/.records").exists())

    def test_tool_offset_agreement(self):
        # Shift only FMMT's reported RAW data offset, not the bytes or GUID path.
        path = self.edk2 / "BaseTools/Source/Python/FMMT/core/BinaryFactoryProduct.py"
        text = path.read_text()
        marker = "Section_Info.DOffset = Section_Offset + Section_Info.HeaderLength + Rel_Whole_Offset"
        self.assertIn(marker, text)
        path.write_text(text.replace(marker, marker + " + (Section_Info.Type == 0x19)"))
        git(self.edk2, "commit", "-qam", "offset disagreement fixture")
        git(self.workspace, "commit", "-qam", "pin offset disagreement fixture")
        self.refusal(self.make("fel-image"), "disagreement")
        self.assertFalse((self.workspace / "out/fel/.records").exists())

    def test_xfel_override_needs_digest(self):
        self.build()
        with (self.tools / "xfel").open("a") as f:
            f.write("\n# different xfel\n")
        for expectation in ("", self.env["EXPECT_XFEL_SHA256"]):
            with self.subTest(expectation=expectation):
                self.refusal(self.boots(EXPECT_XFEL_SHA256=expectation))

    def test_xfel_runs_only_staged_copy(self):
        bundle = self.build()
        self.assert_bundle_writes(
            self.boots(FAKE_XFEL_SWAP=str(self.tools / "xfel")), bundle
        )

    def test_default_xfel_needs_build_record(self):
        bundle = self.build()
        default = self.workspace / "out/tools/xfel"
        default.parent.mkdir()
        shutil.copy2(self.tools / "xfel", default)
        self.refusal(self.make("fel-boot"))
        commit = "445e8aefe6914c85817cc9bd1d201629364b0ec6"
        patched = self.tools / "fel.c"
        patched.write_text("// patched fixture source\n")
        subprocess.run(
            [
                sys.executable,
                "-I",
                self.workspace / "scripts/fel-tools.py",
                "record-xfel",
                self.tools,
                commit,
            ],
            check=True,
        )
        self.assertEqual(
            read_json(default.with_suffix(".record.json")),
            {
                "binary_sha256": sha(default),
                "source_commit": commit,
                "patched_fel_c_sha256": sha(patched),
            },
        )
        self.assert_bundle_writes(self.make("fel-boot"), bundle)
        with default.open("a") as f:
            f.write("\n# other binary\n")
        self.usb_log.write_text("")
        self.refusal(self.make("fel-boot"))

    def test_basetools_changed_binary(self):
        self.build()
        binary = self.edk2 / "BaseTools/Source/C/bin/GenFv"
        binary.write_bytes(b"changed since stamp")
        self.edk2_log.write_text("")
        self.refusal(self.make("fel-image"), "BaseTools stamp mismatch")
        self.assertEqual(self.edk2_log.read_text(), "")

    def test_basetools_wrong_head(self):
        self.build()
        stamp = self.workspace / "out/edk2-basetools.stamp.json"
        data = read_json(stamp) if stamp.exists() else {}
        write_json(stamp, dict(data, edk2_head="0" * 40))
        self.edk2_log.write_text("")
        self.refusal(self.make("fel-image"), "BaseTools stamp mismatch")
        self.assertEqual(self.edk2_log.read_text(), "")

    def test_edk2_conf_include_refused(self):
        conf = self.edk2 / "Conf"
        (conf / "local.txt").write_text("# local tool overrides\n")
        for name in ("tools_def.txt", "target.txt", "build_rule.txt"):
            with self.subTest(name=name):
                path = conf / name
                original = path.read_bytes()
                path.write_bytes(original + b"  \t!include local.txt\n")
                try:
                    self.refusal(self.make("fel-image"), f"{name}: !include")
                    self.assertEqual(self.edk2_log.read_text(), "")
                    self.assertFalse((self.workspace / "out/fel/.records").exists())
                finally:
                    path.write_bytes(original)

    def test_edk2_tool_and_conf_receipt(self):
        bundle = self.build()
        record = read_json(self.record(sha(bundle / "bt0-fel.bin")))
        stamp = self.workspace / "out/edk2-basetools.stamp.json"
        self.assertIn("basetools_stamp_sha256", record)
        self.assertEqual(record["basetools_stamp_sha256"], sha(stamp))
        self.assertEqual(
            read_json(stamp),
            {
                "edk2_head": git(self.edk2, "rev-parse", "HEAD"),
                "binaries": {
                    name: sha(self.edk2 / "BaseTools/Source/C/bin" / name)
                    for name in ("GenFv", "LzmaCompress")
                },
            },
        )
        self.assertEqual(
            record["conf_sha256"],
            {
                name: sha(self.edk2 / "Conf" / name)
                for name in ("target.txt", "tools_def.txt", "build_rule.txt")
            },
        )

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
