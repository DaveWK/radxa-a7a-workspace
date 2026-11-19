#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
scripts=$(cd "$(dirname "$0")" && pwd)
exec python3 -I "$scripts/fel_session.py" reset \
    --port "${FEL_PORT:?}" --state "${FEL_STATE_FILE:?}"
