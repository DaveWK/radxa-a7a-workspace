#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build SD/eMMC bt0 without inheriting the caller's Cargo-home config."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def check_profile_config(env):
    # CARGO_HOME is isolated, but Cargo still reads config from cwd/ancestors.
    config = subprocess.run(
        ["cargo", "-Zunstable-options", "config", "get", "--format=json", "env"],
        env=env,
        capture_output=True,
        text=True,
    )
    if (
        config.returncode == 101
        and not config.stdout
        and config.stderr.rstrip().splitlines()[-1:]
        == ["error: config value `env` is not set"]
    ):
        return
    if config.returncode:
        raise SystemExit(
            f"sd-bt0: cannot inspect Cargo [env] (exit {config.returncode})"
        )
    try:
        settings = json.loads(config.stdout)["env"]
        if not isinstance(settings, dict):
            raise ValueError("env is not a table")
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit(f"sd-bt0: cannot read Cargo [env]: {error}") from error
    if "A7A_PROFILE" in settings:
        raise SystemExit("sd-bt0: Cargo [env] must not set A7A_PROFILE")


def main():
    scratch, *cargo_args = sys.argv[1:]
    source_home = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo")
    with tempfile.TemporaryDirectory(prefix=".sd-bt0-cargo-", dir=scratch) as home:
        home = Path(home)
        # The pinned bt0 uses crates.io. Seed only the index and archives,
        # never config, credentials, unpacked sources or mutable shared locks.
        for name in ("index", "cache"):
            source = source_home / "registry" / name
            if source.is_dir():
                registry = home / "registry"
                registry.mkdir(exist_ok=True)
                subprocess.run(
                    ["cp", "-RL", "--reflink=auto", "--", source, registry / name],
                    check=True,
                )
        env = dict(os.environ, CARGO_HOME=str(home))
        check_profile_config(env)
        subprocess.run(["cargo", *cargo_args], env=env, check=True)


if __name__ == "__main__":
    main()
