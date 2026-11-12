# Radxa Cubie A7A (Allwinner A733): oreboot bt0 -> oreboot main (EL3) -> EDK2
# -> Fedora 45 on the stock Fedora kernel. Sources are the git submodules
# under firmware/ and fedora/; outputs go to out/. Images are never committed
# or uploaded: build your own.
#
#   make vendor        fetch the vendor DRAM library object (build input, see README)
#   make dtb           the Cubie A7A device tree (out/dtb/)
#   make firmware      bt0 + main + EDK2 -> out/firmware/firmware.bin (SD card, LBA 256)
#   make fel-image     firmware + bt0 for USB FEL boot -> out/fel/
#   make xfel          xfel with a 60 s USB timeout -> out/tools/xfel
#   make fel-boot      boot the board over USB FEL (board in FEL on the host's USB)
#   make rpms          the cubie-a7a-* SRPMs and RPMs -> out/fedora/rpmbuild/
#   make fedora-image  Fedora 45 image with the firmware at LBA 256 -> out/image/
#   make serial        UART0 logger (picocom in screen, logs in serial-logs/)
#   make test          host tests (oreboot board crates, scripts)
#   make clean
#
# VENDOR_DRAM=yes (default) bt0 initialises DRAM through Allwinner's DRAM
#   library (the path that boots today); VENDOR_DRAM=no uses the open driver
#   (cubie-a7a-dram) with only the PHY's training firmware read from the
#   library as data; BLOBLESS=yes builds the open driver's firmware-free
#   development stage (probes and halts). FEL_DRAM=dramlib|open likewise for
#   the FEL bt0.

TOP      := $(abspath .)
OUT      := $(TOP)/out
OREBOOT  := $(TOP)/firmware/oreboot
BOARD    := $(OREBOOT)/src/mainboard/radxa/cubie-a7a
FEDORA   := $(TOP)/fedora
DTS      := $(FEDORA)/fedora/dts

VENDOR_DRAM ?= yes
BLOBLESS    ?= no
FEL_DRAM    ?= dramlib
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
BT0_MAX_BYTES := 262144
DRAM_LIB_OVERRIDES := dwc_ddrphy_phyinit_G_execFW mctl_com_set_controller_after_phy \
	lp5_sw_mr_wr lp5_sw_mr_rd \
	lpddr4_phyinit_D_loadIMEM lpddr4_phyinit_F_loadDMEM lpddr4_phyinit_I_loadPIEImage

FW_OUT  := $(OUT)/firmware
FEL_OUT := $(OUT)/fel
TGT     := $(OUT)/target
DTB     := $(OUT)/dtb/sun60i-a733-cubie-a7a.dtb
DTB_VERSION = $(shell cat $(DTS)/DTB_VERSION)
LIBDRAM_A := $(OUT)/oreboot/libdram-a733.a
BT0_BIN := $(OUT)/oreboot/bt0.bin
BT0_FEL_BIN := $(OUT)/oreboot/bt0-fel.bin
MAIN_BIN := $(OUT)/oreboot/main.bin
FEL_MAIN_BIN := $(OUT)/oreboot/main-fel.bin
EDK2_FD := $(OUT)/edk2/CUBIEA7A_EFI.fd
XFEL    ?= $(OUT)/tools/xfel
IMAGE   := $(OUT)/image/a7a-fedora$(FEDORA_RELEASE).img

BT0_FEATURES = $(strip $(if $(filter yes,$(BLOBLESS)),blobless,$(if $(filter yes,$(VENDOR_DRAM)),dramlib)) \
	$(if $(filter yes,$(OTP)),otp))
FEL_FEATURES = $(strip fel $(if $(filter dramlib,$(FEL_DRAM)),dramlib))
empty :=
space := $(empty) $(empty)
# The vendor library archive, unless the build reads nothing from it.
LIBDRAM_DEP = $(if $(filter yes,$(BLOBLESS)),,$(LIBDRAM_A))

define check-bt0-size
	@s=$$(stat -c %s $(1)); if [ $$s -gt $(BT0_MAX_BYTES) ]; then \
		echo "$(1): $$s bytes, above the 0x40000 limit"; exit 1; fi; \
	echo "$(1): $$s bytes (limit $(BT0_MAX_BYTES))"
endef

# bt0_build <features> <target dir> <output .bin>
define bt0_build
	cd $(BOARD)/bt0 && A733_PHY_FW_OBJ=$(DRAM_LIB) A733_DRAM_LIB=$(LIBDRAM_A) CARGO_TARGET_DIR=$(2) \
		$(CARGO) build --release --locked $(if $(1),--features "$(1)")
	$(OBJCOPY) -O binary $(2)/armv7a-none-eabi/release/oreboot-cubie-a7a-bt0 $(3)
	$(call check-bt0-size,$(3))
endef

# main_build <features> <target dir> <output .bin>
define main_build
	cd $(BOARD)/main && CARGO_TARGET_DIR=$(2) $(CARGO) build --release --locked --no-default-features --features "$(1)"
	$(OBJCOPY) -O binary $(2)/aarch64-unknown-none-softfloat/release/oreboot-cubie-a7a-main $(3)
endef

.PHONY: help check-sources vendor dtb bt0 bt0-fel main main-fel edk2 firmware fel-image xfel fel-boot \
	rpms fedora-image serial test clean FORCE

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

bt0: check-sources $(LIBDRAM_DEP) | $(OUT)/oreboot
	$(call bt0_build,$(BT0_FEATURES),$(TGT)/bt0-$(subst $(space),-,$(or $(BT0_FEATURES),open)),$(BT0_BIN))

bt0-fel: check-sources $(LIBDRAM_A) | $(OUT)/oreboot
	$(call bt0_build,$(FEL_FEATURES),$(TGT)/bt0-$(subst $(space),-,$(FEL_FEATURES)),$(BT0_FEL_BIN))
	@echo "$(BT0_FEL_BIN): linked at 0x90000"

main: check-sources | $(OUT)/oreboot
	$(call main_build,$(BRINGUP),$(TGT)/main,$(MAIN_BIN))

main-fel: check-sources | $(OUT)/oreboot
	$(call main_build,$(FEL_BRINGUP),$(TGT)/main-fel,$(FEL_MAIN_BIN))

edk2: check-sources dtb
	EDK2_OUT=$(OUT)/edk2 scripts/build-edk2.sh $(EDK2_TARGET) $(EDK2_ARGS) -D DTB_FILE=$(DTB)

# SD card firmware: firmware.bin goes at firmware.seek (sector 256, 128 KiB).
firmware: bt0 main edk2
	python3 scripts/mkimage.py --bt0 $(BT0_BIN) --main $(MAIN_BIN) --payload $(EDK2_FD) \
		--out $(FW_OUT) --egon-offset $(EGON_OFFSET)
	cd $(FW_OUT) && sha256sum firmware.bin firmware.seek | tee SHA256SUMS

# USB FEL boot set for scripts/fel-boot.sh: bt0-fel.bin plus a firmware.bin
# whose layout table names main (FEL_BRINGUP) and EDK2.
fel-image: bt0 bt0-fel main-fel edk2
	python3 scripts/mkimage.py --bt0 $(BT0_BIN) --main $(FEL_MAIN_BIN) --payload $(EDK2_FD) \
		--out $(FEL_OUT) --egon-offset $(EGON_OFFSET)
	cp $(BT0_FEL_BIN) $(FEL_OUT)/bt0-fel.bin
	cd $(FEL_OUT) && sha256sum bt0-fel.bin firmware.bin firmware.seek | tee SHA256SUMS

xfel: $(XFEL)
$(XFEL):
	scripts/build-xfel.sh

# Needs the board in FEL (USB 1f3a:efe8) on this host and root for xfel
# (SUDO=, with xfel's udev rule installed, runs it as you). Run it on the
# host, not in the build container.
fel-boot: $(XFEL)
	@test -f $(FEL_OUT)/bt0-fel.bin || { echo "run make fel-image first (in the container)" >&2; exit 1; }
	XFEL=$(XFEL) scripts/fel-boot.sh $(FEL_OUT)

rpms: check-sources
	FWREPO=$(FWREPO) FEDORA_RELEASE=$(FEDORA_RELEASE) $(if $(AIC8800_SRC),AIC8800_SRC=$(abspath $(AIC8800_SRC))) \
		$(FEDORA)/fedora/build-rpms.sh $(OUT)/fedora/rpmbuild
	$(if $(filter none,$(FWREPO)),,$(FEDORA)/fedora/build-aarch64-rpms.sh $(OUT)/fedora/rpmbuild)

# The Fedora image with this build's firmware at LBA 256 (it boots from the
# SD card, and the same image on a USB disk is the root for the FEL boot).
# mkdevcard.sh only writes to fresh paths under fedora/build/ (gitignored
# there); the image is moved to out/image/ afterwards.
STAMP := $(shell date +%Y%m%d-%H%M%S)
IMG_BUILD = $(FEDORA)/build/image-$(STAMP)
fedora-image: firmware fel-image rpms
	mkdir -p $(dir $(IMAGE)) $(FEDORA)/build
	scripts/binfmt-aarch64.sh
	WORK=$(IMG_BUILD) OUT=$(IMG_BUILD).img FEDORA_RELEASE=$(FEDORA_RELEASE) \
		FIRMWARE_DTB_VERSION=$(DTB_VERSION) \
		$(FEDORA)/fedora/mkdevcard.sh $(FW_OUT)/firmware.bin $(OUT)/fedora/rpmbuild/RPMS
	mv -f $(IMG_BUILD).img $(IMAGE)
	[ ! -f $(IMG_BUILD).img.xz ] || mv -f $(IMG_BUILD).img.xz $(IMAGE).xz
	@echo "image: $(IMAGE) (never commit or upload it)"

# UART0 at 115200 8N1 (LABEL=<name> DEV=/dev/ttyUSB0); scripts/serial-log.sh
# attach / reconcile for a running session.
serial:
	scripts/serial-log.sh $(or $(LABEL),run) $(or $(DEV),/dev/ttyUSB0)

test: check-sources
	cd $(BOARD)/dram && CARGO_TARGET_DIR=$(TGT)/host $(CARGO) test --offline -q --target x86_64-unknown-linux-gnu
	cd $(BOARD)/common && CARGO_TARGET_DIR=$(TGT)/host $(CARGO) test --offline -q --target x86_64-unknown-linux-gnu
	python3 -I -m py_compile scripts/mkimage.py scripts/check-nvstore.py scripts/lib/bootlayout.py scripts/lib/mkcard.py
	bash -n scripts/fel-boot.sh scripts/build-edk2.sh scripts/serial-log.sh scripts/fetch-vendor.sh scripts/build-xfel.sh scripts/binfmt-aarch64.sh

clean:
	rm -rf $(OUT)
