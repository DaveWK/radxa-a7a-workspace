#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
: "${FEL_PORT:?fel-boot requires FEL_PORT (for example 3-3.4)}"
scripts=$(cd "$(dirname "$0")" && pwd)
args=(boot --port "$FEL_PORT")
if [[ -n ${FEL_STATE_FILE:-} ]]; then
    args+=(--state "$FEL_STATE_FILE")
fi
exec python3 -I "$scripts/fel_session.py" "${args[@]}" -- "$@"
