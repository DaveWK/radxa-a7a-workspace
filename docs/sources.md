# Sources

## Submodules

| Path | Repository | Branch | What |
|---|---|---|---|
| `firmware/oreboot` | <https://github.com/DaveWK/oreboot> (fork of oreboot/oreboot) | `radxa-cubie-a7a` | on `sbc-common` (upstream oreboot + xtask changes + the shared firmware crates in `src/lib/`); the board in `src/mainboard/radxa/cubie-a7a/` |
| `firmware/edk2` | <https://github.com/tianocore/edk2> | pinned commit `0d61209231` | upstream, unmodified |
| `firmware/edk2-platforms` | <https://github.com/DaveWK/edk2-platforms> (fork of tianocore/edk2-platforms) | `radxa-cubie-a7a` | on `sbc-common` (`OreEdk2Boot/`: OreEdk2BootPkg, DesignWarePkg); `Platform/Radxa/CubieA7APkg`, `Silicon/Allwinner/A733Pkg` |
| `fedora` | <https://github.com/DaveWK/radxa-a7a-fedora> | `radxa-cubie-a7a` | DTS, DKMS kmods, RPM specs, image scripts |

The `sbc-common` branches carry what other single-board-computer ports
share. The board branches sit on top of them.

## Fetched at build time (never committed)

| What | From | Used by |
|---|---|---|
| Allwinner A733 DRAM library object (`libdram`) | <https://gitlab.com/tina5.0_aiot/lichee/dramlib>, commit `35e84c835b26f8d933e50299869657365e996363`, `sun60iw2p1/spl_libdram/libdram`, sha256 `d05bc328…f6c42c8e` | bt0: linked (`VENDOR_DRAM=yes`, `FEL_DRAM=dramlib`) or read for the PHY training firmware (`VENDOR_DRAM=no`) |
| xfel v1.4.0 source | <https://github.com/xboot/xfel>, commit `445e8aefe6` | `make xfel` (built with a 60 s USB timeout) |
| Fedora 45 packages | Fedora's `fedora` and `updates` repositories (signature-checked by dnf) | `make fedora-image` |
| Rust nightly-2026-05-06 | rustup | the build container |

## Not included

- The AIC8800 Wi-Fi/Bluetooth driver source (most upstream files carry no
  licence grant). Point `AIC8800_SRC` at a local tree to build its package.
- Any firmware binary, image, vendor image or vendor document.
