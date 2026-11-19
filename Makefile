# Radxa Cubie A7A (Allwinner A733): oreboot bt0 -> oreboot main (EL3) -> EDK2
# -> Fedora 45 on the stock Fedora kernel. Sources are the git submodules
# under firmware/ and fedora/; outputs go to out/. Images are never committed
# or uploaded: build your own.
#
#   make dtb           the Cubie A7A device tree (out/dtb/)
#   make firmware      bt0 + main + EDK2 -> out/firmware/firmware.bin (SD card or eMMC, LBA 256)
#   make fel-image     the FEL bundle for one mode and profile ->
#                      out/fel/<mode>-<mhz>/ (blobfree-1200, blobfree-2400,
#                      dramlib-2400, phyfw-2400). Private build and packaging
#                      directories, and a build record under out/fel/.records/
#   make xfel          xfel with a 60 s USB timeout -> out/tools/xfel
#   make fel-boot      workspace maintenance boot; requires FEL_PORT, FEL_SERIAL_LOG
#   make rpms          the cubie-a7a-* SRPMs and RPMs -> fresh run in out/fedora/rpmbuild/
#                      sealed run path noted in out/fedora/run (for operators)
#   make fedora-image  Fedora 45 image with firmware at LBA 256 and verification
#                      sidecars -> out/image/; uses a private firmware build
#                      with a known bt0 fingerprint; self-checks against the
#                      build receipt
#   make serial        UART0 logger (picocom in screen, logs in serial-logs/)
#   make test          host tests (oreboot board crates, scripts)
#   make vendor        fetch the vendor DRAM library object (measurement builds
#                      only: VENDOR_DRAM=yes|phyfw, FEL_DRAM=dramlib)
#   make clean         remove out/
#   make mrproper      clean + vendor/ + the host cargo test targets (never the
#                      submodule sources)
#
# DRAM: by default bt0 (and the FEL bt0) brings DRAM up with this project's
#   own driver and nothing from a vendor: no DRAM library, no PHY training
#   firmware, so the build needs no `make vendor`.
#   DRAM_MHZ=1200|2400   the DRAM clock of that driver's built-in settings.
#                        Unset: the firmware's default, 1200, which boots
#                        Linux; 2400 passes bt0's tests but does not boot
#                        Linux yet. The vendor paths run 2400.
#   VENDOR_DRAM=yes      measurement build: DRAM through Allwinner's DRAM
#                        library instead (run `make vendor` first), at
#                        2400 MHz; measurement booting requires authorization.
#   VENDOR_DRAM=phyfw    measurement build: our driver with the PHY's own
#                        training firmware read from that library's object as
#                        data (`make vendor` too). Booting requires authorization.
#   Earlier spellings: BLOBLESS=yes and FEL_DRAM=open are the default now;
#   FEL_DRAM=dramlib builds only the FEL bt0 with the library (measurement only).
#   fel-image refuses inherited or Cargo-configured A7A_* and A733_* knobs.
#   Use the separate lab tooling for individual driver settings.

TOP      := $(abspath .)
OUT      := $(TOP)/out
OREBOOT  := $(TOP)/firmware/oreboot
BOARD    := $(OREBOOT)/src/mainboard/radxa/cubie-a7a
FEDORA   := $(TOP)/fedora
DTS      := $(FEDORA)/fedora/dts

VENDOR_DRAM ?= no
FEL_DRAM    ?=
OTP         ?= no
DRAM_LIB    ?= $(TOP)/vendor/dramlib/libdram
# Peripheral bring-up in oreboot main (cargo features of main).
BRINGUP     ?= gmac usb trng
# The FEL boot's main: combo0 off, so a USB 3 root disk in the blue port
# runs at high speed on EHCI1, which EDK2 and the initramfs both drive.
FEL_BRINGUP ?= gmac usb usb-hs-only trng
EDK2_TARGET ?= DEBUG
EDK2_ARGS   ?= -D USB_ENABLE=TRUE -D ETH_ENABLE=TRUE -D DISPLAY_ENABLE=TRUE
EGON_OFFSET ?= 128k
FEDORA_RELEASE ?= 45
# A local tree of the AIC8800 Wi-Fi driver (not redistributable, see
# fedora/README.md); empty: the Wi-Fi package is skipped.
AIC8800_SRC ?=
# A boot-chain tree with tools/a7a-fwlog for cubie-a7a-fwlog; none skips it.
FWREPO      ?= none

CARGO   := env -u RUSTUP_TOOLCHAIN -u RUSTFLAGS cargo
OBJCOPY ?= llvm-objcopy
# The longest bt0 the image tool wraps: 0x4a000 bytes, the length of the
# vendor boot0 the mask ROM loads from this board's cards (scripts/mkimage.py
# EGON_MAX). An earlier limit of 0x40000 belonged to bt0's hand-over to a
# vendor SPL after a failed boot (larger images had not come back through
# it); bt0 has no such hand-over any more, and with the vendor DRAM library
# (VENDOR_DRAM=yes) it is larger than 0x40000. Image, bss and stack are
# bounded separately by bt0's linker script.
BT0_MAX_BYTES := 303104
DRAM_LIB_OVERRIDES := dwc_ddrphy_phyinit_G_execFW mctl_com_set_controller_after_phy \
	lp5_sw_mr_wr lp5_sw_mr_rd \
	lpddr4_phyinit_D_loadIMEM lpddr4_phyinit_F_loadDMEM lpddr4_phyinit_I_loadPIEImage

FW_OUT  := $(OUT)/firmware
TGT     := $(OUT)/target
DTB     := $(OUT)/dtb/sun60i-a733-cubie-a7a.dtb
DTB_VERSION = $(shell cat $(DTS)/DTB_VERSION)
LIBDRAM_A := $(OUT)/oreboot/libdram-a733.a
BT0_BIN := $(OUT)/oreboot/bt0.bin
MAIN_BIN := $(OUT)/oreboot/main.bin
EDK2_FD := $(OUT)/edk2/CUBIEA7A_EFI.fd
IMAGE   := $(OUT)/image/a7a-fedora$(FEDORA_RELEASE).img
RPM_RUN_FILE := $(OUT)/fedora/run
DEVCARD_SCRATCH := $(abspath $(OUT)/fedora/verify-scratch)

# The DRAM path of bt0 and of the FEL bt0: no (ours, nothing from a vendor),
# yes (the vendor library) or phyfw (ours with the PHY's firmware as data).
ifneq ($(words $(filter no yes phyfw,$(VENDOR_DRAM))):$(words $(VENDOR_DRAM)),1:1)
$(error VENDOR_DRAM=$(VENDOR_DRAM): no (default), yes or phyfw)
endif
ifneq ($(words $(filter 1200 2400,$(or $(DRAM_MHZ),1200))):$(words $(or $(DRAM_MHZ),1200)),1:1)
$(error DRAM_MHZ=$(DRAM_MHZ): 1200 or 2400)
endif
override BT0_DRAM := $(VENDOR_DRAM)
override FEL_BT0_DRAM := $(if $(filter dramlib,$(FEL_DRAM)),yes,$(VENDOR_DRAM))
# dram-cargo <no|yes|phyfw>: the cargo arguments that select the path. bt0's
# default features are the blob-free boot; the other two are built without
# them.
dram-cargo = $(if $(filter no,$(1)),,--no-default-features)
dram-feature = $(if $(filter yes,$(1)),dramlib)
# dram-env <no|yes|phyfw>: what the build reads from outside the tree, and
# the clock of the built-in settings (only our driver alone has them). The
# vendor paths run 2400 MHz, so DRAM_MHZ=2400 is accepted there and any other
# value is refused.
dram-env = $(if $(filter yes,$(1)),A733_DRAM_LIB=$(LIBDRAM_A)) $(if $(filter phyfw,$(1)),A733_PHY_FW_OBJ=$(DRAM_LIB)) \
	$(if $(filter no,$(1)),$(if $(DRAM_MHZ),A7A_PROFILE=$(DRAM_MHZ)),$(if $(DRAM_MHZ),$(if $(filter 2400,$(DRAM_MHZ)),,$(error DRAM_MHZ=$(DRAM_MHZ): the vendor DRAM path runs 2400 MHz))))
# dram-dep <no|yes|phyfw>: the vendor file the build needs, if any.
dram-dep = $(if $(filter yes,$(1)),$(LIBDRAM_A)) $(if $(filter phyfw,$(1)),$(DRAM_LIB))
dram-tag = $(if $(filter no,$(1)),blobfree,$(if $(filter yes,$(1)),dramlib,phyfw))
# firmware.bin uses bt0 (BT0_DRAM), not the separate FEL build's profile.
override BT0_PROFILE := $(if $(filter no,$(BT0_DRAM)),$(or $(DRAM_MHZ),1200),2400)
ifneq ($(origin DRAM_FIRMWARE_IDENTITY),undefined)
$(error DRAM_FIRMWARE_IDENTITY is derived from VENDOR_DRAM and DRAM_MHZ; do not set it directly)
endif
override DRAM_FIRMWARE_IDENTITY := $(call dram-tag,$(BT0_DRAM))-$(BT0_PROFILE)
ifneq ($(origin sd-bt0-env),undefined)
$(error SD/eMMC bt0 does not accept sd-bt0-env; use the validated VENDOR_DRAM and DRAM_MHZ inputs)
endif
# Each DRAM mode and profile gets its own FEL build and output directory, so
# two builds never share or overwrite the same intermediate or bundle.
override FEL_TAG_MODE := $(call dram-tag,$(FEL_BT0_DRAM))
override PROFILE := $(if $(filter blobfree,$(FEL_TAG_MODE)),$(or $(DRAM_MHZ),1200),2400)
override FEL_SLOT := $(FEL_TAG_MODE)-$(PROFILE)
ifneq ($(or $(FEL_IMAGE_EXPECT),$(FEL_SLOT)),$(FEL_SLOT))
$(error FEL compile slot $(FEL_SLOT) does not match the requested $(FEL_IMAGE_EXPECT))
endif
override FEL_OUT := $(OUT)/fel/$(FEL_SLOT)
override FEL_BUILD := $(or $(FEL_RUN_DIR),$(FEL_OUT)/build)
override FEL_TGT := $(FEL_BUILD)/target
override FEL_DTB := $(FEL_BUILD)/dtb/sun60i-a733-cubie-a7a.dtb
override FEL_EDK2_DIR := $(FEL_BUILD)/edk2
override FEL_BT0 := $(FEL_BUILD)/bt0.bin
override FEL_BT0_FEL := $(FEL_BUILD)/bt0-fel.bin
override FEL_MAIN := $(FEL_BUILD)/main-fel.bin
BT0_FEATURES = $(strip $(call dram-feature,$(BT0_DRAM)) $(if $(filter yes,$(OTP)),otp))
override FEL_FEATURES = $(strip fel $(call dram-feature,$(FEL_BT0_DRAM)))
# The old FEL_DRAM=dramlib alias uses the vendor library only in the FEL bt0.
# Its SD bt0 is blob-free at the pinned default, with no profile override.
override FEL_SD_ENV = $(if $(filter blobfree,$(FEL_TAG_MODE)),A7A_PROFILE=$(PROFILE),$(call dram-env,$(BT0_DRAM)))
override FEL_BT0_ENV = $(if $(filter blobfree,$(FEL_TAG_MODE)),A7A_PROFILE=$(PROFILE),$(call dram-env,$(FEL_BT0_DRAM)))
fel-profile-check = $(if $(filter-out blobfree,$(FEL_TAG_MODE)),$(if $(filter-out undefined,$(origin DRAM_MHZ)),$(error DRAM_MHZ must be unset for FEL measurement mode $(FEL_TAG_MODE), which runs at 2400 MHz)))
empty :=
space := $(empty) $(empty)
shell-quote = '$(subst ','"'"',$(1))'

define check-bt0-size
	@s=$$(stat -c %s $(1)); if [ $$s -gt $(BT0_MAX_BYTES) ]; then \
		echo "$(1): $$s bytes, above the $(BT0_MAX_BYTES) byte limit"; exit 1; fi; \
	echo "$(1): $$s bytes (limit $(BT0_MAX_BYTES))"
endef

# bt0_build <features> <target dir> <output .bin> <DRAM path> <env assignments>
define bt0_build
	cd $(BOARD)/bt0 && env $(5) CARGO_TARGET_DIR=$(2) \
		$(CARGO) build --release --locked $(call dram-cargo,$(4)) $(if $(1),--features "$(1)")
	$(OBJCOPY) -O binary $(2)/armv7a-none-eabi/release/oreboot-cubie-a7a-bt0 $(3)
	$(call check-bt0-size,$(3))
endef

# main_build <features> <target dir> <output .bin>
define main_build
	cd $(BOARD)/main && CARGO_TARGET_DIR=$(2) $(CARGO) build --release --locked --no-default-features --features "$(1)"
	$(OBJCOPY) -O binary $(2)/aarch64-unknown-none-softfloat/release/oreboot-cubie-a7a-main $(3)
endef

.PHONY: help check-sources vendor dtb bt0 bt0-fel main main-fel edk2 fel-dtb fel-edk2 fel-bt0 \
	firmware fel-image xfel fel-boot rpms fedora-image serial test clean mrproper FORCE

help:
	@sed -n '/^$$/q;s/^# \{0,1\}//p' Makefile

check-sources:
	@test -f $(BOARD)/bt0/Cargo.toml && test -f $(TOP)/firmware/edk2/edksetup.sh && \
		test -f $(TOP)/firmware/edk2-platforms/Platform/Radxa/CubieA7APkg/CubieA7A.dsc && \
		test -f $(FEDORA)/fedora/mkdevcard.sh || \
		{ echo "submodules missing: git submodule update --init --recursive" >&2; exit 1; }

vendor:
	scripts/fetch-vendor.sh

$(DRAM_LIB):
	scripts/fetch-vendor.sh

$(OUT)/oreboot:
	mkdir -p $@

# The vendor library as a link archive with the functions bt0 provides
# itself weakened (copied only on change so cargo relinks when it changes).
$(LIBDRAM_A): $(DRAM_LIB) | $(OUT)/oreboot
	@rm -f $@.new
	@if [ "$$(head -c 7 $(DRAM_LIB))" = '!<arch>' ]; then cp $(DRAM_LIB) $@.new; \
		else ar rcsD $@.new $(DRAM_LIB); fi
	$(OBJCOPY) $(addprefix --weaken-symbol=,$(DRAM_LIB_OVERRIDES)) $@.new
	@cmp -s $@.new $@ && rm -f $@.new || mv -f $@.new $@

dtb: check-sources
	mkdir -p $(dir $(DTB))
	$(MAKE) -C $(DTS) OUT=$(DTB) DTB_ORIGIN=firmware

bt0: check-sources $(call dram-dep,$(BT0_DRAM)) | $(OUT)/oreboot
	$(if $(filter-out no,$(BT0_DRAM)),$(if $(filter-out 2400,$(DRAM_MHZ)),$(error the vendor DRAM path runs at 2400 MHz)))
	python3 -I scripts/sd-bt0-cargo.py build "$(DRAM_FIRMWARE_IDENTITY)" "$(OUT)/oreboot" \
		"$(TGT)/bt0-$(DRAM_FIRMWARE_IDENTITY)$(if $(filter yes,$(OTP)),-otp)" \
		$(if $(filter yes,$(OTP)),--otp) \
		$(if $(filter yes,$(BT0_DRAM)),--vendor-input "$(LIBDRAM_A)",$(if $(filter phyfw,$(BT0_DRAM)),--vendor-input "$(DRAM_LIB)"))
	$(OBJCOPY) -O binary "$(TGT)/bt0-$(DRAM_FIRMWARE_IDENTITY)$(if $(filter yes,$(OTP)),-otp)/armv7a-none-eabi/release/oreboot-cubie-a7a-bt0" "$(BT0_BIN)"
	$(call check-bt0-size,$(BT0_BIN))

$(FEL_BUILD):
	mkdir -p $@

fel-dtb: check-sources
	mkdir -p $(dir $(FEL_DTB))
	$(MAKE) -C $(DTS) OUT=$(FEL_DTB) DTB_ORIGIN=firmware

fel-edk2: check-sources $(if $(FEL_DTB_INPUT),,fel-dtb)
	EDK2_OUT=$(FEL_EDK2_DIR) BUILD_TAG=$(FEL_SLOT) scripts/build-edk2.sh $(EDK2_TARGET) $(EDK2_ARGS) -D DTB_FILE=$(or $(FEL_DTB_INPUT),$(FEL_DTB))

fel-bt0: check-sources $(call dram-dep,$(BT0_DRAM)) | $(FEL_BUILD)
	$(fel-profile-check)
	$(call bt0_build,$(BT0_FEATURES),$(FEL_TGT)/bt0-sd,$(FEL_BT0),$(BT0_DRAM),$(strip $(FEL_SD_ENV)))

bt0-fel: check-sources $(call dram-dep,$(FEL_BT0_DRAM)) | $(FEL_BUILD)
	$(fel-profile-check)
	$(call bt0_build,$(FEL_FEATURES),$(FEL_TGT)/bt0-fel,$(FEL_BT0_FEL),$(FEL_BT0_DRAM),$(strip $(FEL_BT0_ENV)))
	@echo "$(FEL_BT0_FEL): linked at 0x90000"

main: check-sources | $(OUT)/oreboot
	$(call main_build,$(BRINGUP),$(TGT)/main,$(MAIN_BIN))

main-fel: check-sources | $(FEL_BUILD)
	$(call main_build,$(FEL_BRINGUP),$(FEL_TGT)/main-fel,$(FEL_MAIN))

edk2: check-sources dtb
	EDK2_OUT=$(OUT)/edk2 scripts/build-edk2.sh $(EDK2_TARGET) $(EDK2_ARGS) -D DTB_FILE=$(DTB)

# SD card and eMMC firmware: firmware.bin goes at firmware.seek (sector 256,
# 128 KiB); bt0 boots from whichever of the two the mask ROM loaded it from.
firmware: bt0 main edk2
	python3 scripts/mkimage.py --bt0 $(BT0_BIN) --main $(MAIN_BIN) --payload $(EDK2_FD) \
		--out $(FW_OUT) --egon-offset $(EGON_OFFSET)
	cd $(FW_OUT) && sha256sum firmware.bin firmware.seek | tee SHA256SUMS

# The recursive Make invocation inherits the jobserver. The orchestrator
# handles -n without acquiring locks, creating directories or compiling.
fel-image:
	$(fel-profile-check)
	$(foreach var,TOP OREBOOT BOARD CARGO FEDORA DTS,$(if $(filter file,$(origin $(var))),,$(error fel-image refuses $(var) override (origin: $(origin $(var))))))
	$(if $(findstring t,$(filter-out -%,$(firstword $(MAKEFLAGS)))),:,python3 -I scripts/fel-manifest.py build \
		--make "$(MAKE)" $(if $(findstring n,$(filter-out -%,$(firstword $(MAKEFLAGS)))),--dry-run) \
		--out-dir "$(FEL_OUT)" --mode $(FEL_TAG_MODE) --profile $(PROFILE) \
		--features "$(FEL_FEATURES)" --sd-features "$(BT0_FEATURES)" \
		--main-features "$(FEL_BRINGUP)" --fel-env "$(strip $(FEL_BT0_ENV))" \
		--sd-env "$(strip $(FEL_SD_ENV))" --egon-offset $(EGON_OFFSET) \
		--edk2-target=$(call shell-quote,$(or $(EDK2_TARGET),DEBUG)) \
		--edk2-args=$(call shell-quote,$(EDK2_ARGS)) \
		--fel-dtb-input=$(call shell-quote,$(FEL_DTB_INPUT)))

xfel: $(TOP)/out/tools/xfel $(TOP)/out/tools/xfel.record.json
$(TOP)/out/tools/xfel $(TOP)/out/tools/xfel.record.json &: scripts/build-xfel.sh scripts/xfel-port-select.patch scripts/xfel-source.json scripts/fel-tools.py
	scripts/build-xfel.sh

fel-boot:
	$(fel-profile-check)
	EXPECT_MODE=$(FEL_TAG_MODE) EXPECT_PROFILE=$(PROFILE) scripts/fel-boot.sh "$(FEL_OUT)"

# Keep the sealed run in the caller's shell. The shared file is only a note
# for operators; another Make invocation is free to replace it at any time.
define build-rpm-run
		run=$$(FWREPO="$(FWREPO)" FEDORA_RELEASE="$(FEDORA_RELEASE)" \
			$(if $(AIC8800_SRC),AIC8800_SRC="$(abspath $(AIC8800_SRC))") \
			"$(FEDORA)/fedora/build-rpms.sh" "$(OUT)/fedora/rpmbuild"); \
		test -d "$$run"; \
		if [ "$(FWREPO)" != none ]; then \
			FEDORA_RELEASE="$(FEDORA_RELEASE)" "$(FEDORA)/fedora/build-aarch64-rpms.sh" "$$run"; \
		fi; \
		tmp=$$(mktemp "$(RPM_RUN_FILE).XXXXXXXX"); \
		trap 'rm -f -- "$$tmp"' EXIT; \
		printf '%s\n' "$$run" > "$$tmp"; \
		mv -fT -- "$$tmp" "$(RPM_RUN_FILE)"; \
		trap - EXIT
endef

# When both are requested, the image's own run also satisfies the RPM goal.
ifneq ($(filter fedora-image,$(MAKECMDGOALS)),)
rpms: fedora-image
else
rpms: check-sources
	set -eu; $(build-rpm-run)
endif

# The Fedora image with this build's firmware at LBA 256 (it boots from the
# SD card, and the same image on a USB disk is the root for the FEL boot).
# mkdevcard.sh only writes to fresh paths under fedora/build/ (gitignored
# there); keep the final basename there so the checksum rows survive the move.
override STAMP := $(shell date +%Y%m%d-%H%M%S-%N)
IMG_BUILD = $(FEDORA)/build/image-$(STAMP)
STAGED_IMAGE = $(IMG_BUILD)/package/$(notdir $(IMAGE))
# Claim a fresh output directory before building any firmware intermediates.
# The standalone 'firmware' target can never replace the bytes used here.
override DEVCARD_FW_BUILD := $(abspath $(OUT))/.devcard-firmware-$(STAMP)
override DEVCARD_FW_BIN := $(DEVCARD_FW_BUILD)/firmware/firmware.bin
fedora-image: fel-image
	$(foreach var,FW_OUT TGT DTB LIBDRAM_A BT0_BIN MAIN_BIN EDK2_FD,$(if $(filter file,$(origin $(var))),,$(error fedora-image refuses $(var) override (origin: $(origin $(var))))))
	mkdir -p "$(dir $(IMAGE))" "$(FEDORA)/build" "$(DEVCARD_SCRATCH)"
	mkdir -- "$(DEVCARD_FW_BUILD)"
	$(MAKE) OUT="$(DEVCARD_FW_BUILD)" firmware
	set -eu; \
		firmware_sha=$$(python3 -I scripts/sd-bt0-cargo.py verify "$(DRAM_FIRMWARE_IDENTITY)" \
			"$(DEVCARD_FW_BUILD)/oreboot/bt0.bin" "$(DEVCARD_FW_BIN)"); \
		scripts/binfmt-aarch64.sh; \
		$(build-rpm-run); \
		WORK="$(IMG_BUILD)" OUT="$(STAGED_IMAGE)" FEDORA_RELEASE="$(FEDORA_RELEASE)" \
			FIRMWARE_DTB_VERSION="$(DTB_VERSION)" DRAM_FIRMWARE_IDENTITY="$(DRAM_FIRMWARE_IDENTITY)" \
			"$(FEDORA)/fedora/mkdevcard.sh" "$(DEVCARD_FW_BIN)" "$$run"; \
		if ! python3 -I -c 'import json, sys; sys.exit(json.load(sys.stdin)["firmware"]["sha256"] != sys.argv[1])' \
				"$$firmware_sha" < "$(STAGED_IMAGE).build-receipt.json"; then \
			echo "devcard: receipt firmware.sha256 does not match verified firmware" >&2; \
			rm -f -- "$(STAGED_IMAGE)" "$(STAGED_IMAGE).xz" "$(STAGED_IMAGE).devcard-manifest.json" \
				"$(STAGED_IMAGE).build-receipt.json" "$(STAGED_IMAGE).sha256"; \
			exit 1; \
		fi; \
		for suffix in '' .devcard-manifest.json .build-receipt.json .sha256; do \
			mv -fT -- "$(STAGED_IMAGE)$$suffix" "$(IMAGE)$$suffix"; \
		done; \
		if [ -f "$(STAGED_IMAGE).xz" ]; then \
			mv -fT -- "$(STAGED_IMAGE).xz" "$(IMAGE).xz"; \
		else \
			rm -f -- "$(IMAGE).xz"; \
		fi; \
		manifest_sha=$$(python3 -I -c 'import json, sys; print(json.load(sys.stdin)["manifest_sha256"])' \
			< "$(IMAGE).build-receipt.json"); \
		echo "devcard self-check against this build's receipt (not independent verification)"; \
		TMPDIR="$(DEVCARD_SCRATCH)" "$(FEDORA)/fedora/verify-devcard.sh" \
			"$(IMAGE)" "$(IMAGE).devcard-manifest.json" --expect-manifest-sha256 "$$manifest_sha"
	@echo "image: $(IMAGE) (never commit or upload it)"

# UART0 at 115200 8N1 (LABEL=<name> DEV=/dev/ttyUSB0); scripts/serial-log.sh
# attach / reconcile for a running session.
serial:
	scripts/serial-log.sh $(or $(LABEL),run) $(or $(DEV),/dev/ttyUSB0)

test: check-sources xfel
	python3 -I scripts/test-xfel-binary.py $(TOP)/out/tools/xfel
	python3 -I scripts/test-fel-callers.py
	python3 -I scripts/test-devcard-recipes.py
	cd $(BOARD)/dram && CARGO_TARGET_DIR=$(TGT)/host $(CARGO) test --offline -q --target x86_64-unknown-linux-gnu
	cd $(BOARD)/common && CARGO_TARGET_DIR=$(TGT)/host $(CARGO) test --offline -q --target x86_64-unknown-linux-gnu
	python3 -I -m py_compile scripts/mkimage.py scripts/check-nvstore.py scripts/lib/bootlayout.py scripts/lib/mkcard.py scripts/fel-manifest.py scripts/fel-fmmt.py scripts/fel-check.py scripts/fel-tools.py scripts/test-fel-manifest.py
	python3 -I scripts/test-fel-manifest.py
	python3 -I scripts/test-xfel-port.py
	python3 -I scripts/test-cached-run.py
	python3 -I scripts/test-fel-session.py
	bash -n scripts/fel-boot.sh scripts/build-edk2.sh scripts/serial-log.sh scripts/fetch-vendor.sh scripts/build-xfel.sh scripts/binfmt-aarch64.sh
	shellcheck scripts/*.sh
	shfmt -d scripts/*.sh
	black --check scripts/*.py scripts/xfel-port scripts/a7a-cached-run scripts/lib/cached_set.py scripts/tests/fel-session-python

clean:
	rm -rf $(OUT)

# Everything clean removes, plus the fetched vendor input and the host cargo
# test targets. Never the submodule sources.
mrproper: clean
	rm -rf $(TOP)/vendor
	rm -rf $(TGT)/host
