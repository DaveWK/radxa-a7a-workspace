#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Authorized A733 WDT0 reset. Verify the session before arming the watchdog.
set -euo pipefail
scripts=$(cd "$(dirname "$0")" && pwd)
port=("$scripts/xfel-port" --port "${FEL_PORT:?}" --state "${FEL_STATE_FILE:?}")
"${port[@]}" -- version
"${port[@]}" -- write32 0x02050010 0x16aa0001
"${port[@]}" -- write32 0x02050014 0x16aa0001
"${port[@]}" --expect-reset -- write32 0x0205000c 0x000014af
"${port[@]}" --after-reset --timeout 60 -- version
