#!/usr/bin/env bash
# Build the EDK2 payload for the Radxa Cubie A7A.
#
# Usage: scripts/build-edk2.sh [DEBUG|RELEASE] [extra build args...]
#   e.g. scripts/build-edk2.sh RELEASE -D USB_ENABLE=TRUE
#
# BUILD_TAG=<name> builds into Build/CubieA7A-<name> and out/edk2-<name>
# instead, so two builds can run side by side.
#
# Output: out/edk2/CUBIEA7A_EFI.fd -- a raw 4 MiB FD that oreboot loads at
# 0x41000000 and enters at its first byte (AArch64 EL2, x0 = DTB).
#
# Sources: the submodules firmware/edk2 (TianoCore EDK2, with its own
# submodules) and firmware/edk2-platforms (Platform/Radxa/CubieA7APkg,
# Silicon/Allwinner/A733Pkg, and the shared packages in OreEdk2Boot/).
# EDK2_DIR and EDK2_PLATFORMS_DIR override them.
set -euo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
EDK2=$(cd "${EDK2_DIR:-$TOP/firmware/edk2}" && pwd)
PLAT=$(cd "${EDK2_PLATFORMS_DIR:-$TOP/firmware/edk2-platforms}" && pwd)
TAG=${BUILD_TAG:+-$BUILD_TAG}
JOBS=${BUILD_JOBS:-2}
[[ $JOBS =~ ^[1-9][0-9]*$ ]] || { echo "invalid BUILD_JOBS" >&2; exit 2; }
OUT=${EDK2_OUT:-$TOP/out/edk2$TAG}
TARGET=${1:-DEBUG}
[[ $# -gt 0 ]] && shift
case $TARGET in
DEBUG | RELEASE) ;;
*)
  echo "usage: $0 [DEBUG|RELEASE] [extra build args...]" >&2
  exit 2
  ;;
esac

FD_BASE=0x41000000
FV_OFFSET=0x40000
FV_SIZE=0x280000
FD_SIZE=$((4 * 1024 * 1024))

die() {
  echo "build-edk2: $*" >&2
  exit 1
}

[[ -f $EDK2/edksetup.sh ]] || die "no EDK2 tree at $EDK2 (git submodule update --init --recursive)"
[[ -f $EDK2/MdePkg/Library/BaseFdtLib/libfdt/libfdt/fdt.h ]] ||
  die "EDK2 submodules missing: git -C $EDK2 submodule update --init --recursive --depth 1"
command -v aarch64-linux-gnu-gcc >/dev/null || die "aarch64-linux-gnu-gcc not found"

[[ -f $PLAT/Platform/Radxa/CubieA7APkg/CubieA7A.dsc ]] || die "no CubieA7APkg in $PLAT"
# The shared EDK2 packages (OreEdk2BootPkg, DesignWarePkg).
COMMON=$PLAT/OreEdk2Boot
[[ -f $COMMON/OreEdk2BootPkg/OreEdk2BootPkg.dec ]] || die "no OreEdk2Boot in $PLAT"
# EDK2 matches module paths against the workspace and PACKAGES_PATH by
# string prefix, so firmware/edk2-platforms (which starts with the
# workspace's firmware/edk2) and OreEdk2Boot (inside it) would land in the
# wrong build directories. The build sees both through links under out/.
PKGS=$TOP/out/edk2-packages
mkdir -p "$PKGS/board/Platform" "$PKGS/board/Silicon" "$PKGS/common"
ln -sfn "$PLAT/Platform/Radxa" "$PKGS/board/Platform/Radxa"
ln -sfn "$PLAT/Silicon/Allwinner" "$PKGS/board/Silicon/Allwinner"
ln -sfn "$COMMON/OreEdk2BootPkg" "$PKGS/common/OreEdk2BootPkg"
ln -sfn "$COMMON/DesignWarePkg" "$PKGS/common/DesignWarePkg"

# edksetup.sh only exports variables; the C tools have to be compiled once.
if [[ ! -x $EDK2/BaseTools/Source/C/bin/GenFv ]]; then
  make -C "$EDK2/BaseTools" -j"$JOBS"
fi

FW_VERSION=$(git -C "$PLAT" describe --always --dirty 2>/dev/null || true)
FW_VERSION="oreboot-edk2 ${FW_VERSION:-dev} $TARGET"

FD=$EDK2/Build/CubieA7A$TAG/${TARGET}_GCC/FV/CUBIEA7A_EFI.fd
rm -f "$FD"

# edksetup.sh trips over 'set -u', and sourcing it in this shell would let a
# failing 'build' slip past 'set -e'. Run it in a subshell and check the
# status explicitly.
(
  set +u
  cd "$EDK2"
  export GCC_AARCH64_PREFIX=aarch64-linux-gnu-
  # Conf/BuildEnv.sh caches absolute paths of the host that last ran
  # edksetup.sh (another checkout path or the build container).
  rm -f Conf/BuildEnv.sh
  export EDK_TOOLS_PATH=$EDK2/BaseTools
  export PACKAGES_PATH="$EDK2:$PKGS/common:$PKGS/board"
  # shellcheck disable=SC1091
  . ./edksetup.sh BaseTools >/dev/null
  build -p Platform/Radxa/CubieA7APkg/CubieA7A.dsc -a AARCH64 -t GCC -b "$TARGET" \
    -n "$JOBS" -D "FW_VERSION=$FW_VERSION" -D "BUILD_TAG=$TAG" "$@"
) || die "EDK2 build failed"

[[ -f $FD ]] || die "build reported success but $FD was not produced"

# Sanity-check the entry chain: FD+4 must branch to the FV, and GenFv must
# have pointed the FV's reset vector at the PrePi entry point.
python3 -I - "$FD" "$FD_BASE" "$FV_OFFSET" "$FV_SIZE" "$FD_SIZE" <<'EOF' || die "FD entry chain check failed"
import struct, sys

path, fd_base, fv_off, fv_size, fd_size = sys.argv[1], *(int(a, 0) for a in sys.argv[2:])
fd = open(path, "rb").read()

def branch_target(off):
    insn = struct.unpack_from("<I", fd, off)[0]
    if insn & 0xFC000000 != 0x14000000:
        sys.exit(f"no 'b' instruction at FD+{off:#x} (found {insn:#010x})")
    imm = insn & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 1 << 26
    return off + imm * 4

if len(fd) != fd_size:
    sys.exit(f"FD is {len(fd):#x} bytes, expected {fd_size:#x}")
if fd[0x38:0x3C] != b"ARMd":
    sys.exit("arm64 image magic missing at FD+0x38")
if branch_target(4) != fv_off:
    sys.exit(f"FD+4 does not branch to the FV at {fv_off:#x}")
entry = branch_target(fv_off)
if not fv_off < entry < fv_off + fv_size:
    sys.exit(f"FV reset vector points outside the FV ({entry:#x})")
print(f"entry chain: {fd_base:#x} -> {fd_base + fv_off:#x} (FV) -> {fd_base + entry:#x} (_ModuleEntryPoint, FD+{entry:#x})")
EOF

# The NV region the variable driver reads at its entry must be a formatted,
# empty store, and with SD_VARSTORE_ENABLE the variable and FTW drivers must
# wait for SdVarStoreFvbDxe (a blank region was an ASSERT on every boot).
python3 -I "$TOP/scripts/check-nvstore.py" "$FD" "$(dirname "$FD")/FVMAIN.Fv" >/dev/null ||
  die "NV variable store check failed (python3 scripts/check-nvstore.py $FD $(dirname "$FD")/FVMAIN.Fv)"

mkdir -p "$OUT"
cp "$FD" "$OUT/CUBIEA7A_EFI.fd"
echo "build-edk2: $OUT/CUBIEA7A_EFI.fd ($FW_VERSION)"
