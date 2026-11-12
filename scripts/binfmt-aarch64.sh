#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Make sure aarch64 binaries run under qemu-aarch64-static (binfmt_misc, F
# flag) for mkdevcard.sh's package scriptlets. On a host with
# qemu-user-static installed the handler is already there. In the build
# container (podman run --privileged, Linux 6.7 or later) this mounts the
# container's own binfmt_misc instance and registers the handler from
# /usr/lib/binfmt.d/qemu-aarch64-static.conf; nothing changes on the host.
set -euo pipefail
B=/proc/sys/fs/binfmt_misc
[ "$(uname -m)" != aarch64 ] || exit 0
if [ -e $B/qemu-aarch64 ]; then
    grep -q '^flags: .*F' $B/qemu-aarch64 || { echo "binfmt: qemu-aarch64 has no F flag" >&2; exit 1; }
    exit 0
fi
[ "$(id -u)" = 0 ] || { echo "binfmt: no qemu-aarch64 handler; install qemu-user-static-aarch64 on the host" >&2; exit 1; }
[ -e $B/register ] || mount -t binfmt_misc binfmt_misc $B
sed -n 's/^\(:qemu-aarch64:.*\)$/\1/p' /usr/lib/binfmt.d/qemu-aarch64-static.conf >$B/register
grep -q '^flags: .*F' $B/qemu-aarch64
echo "binfmt: registered qemu-aarch64 (F) in this namespace"
