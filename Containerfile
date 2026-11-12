# Build environment for the Radxa Cubie A7A firmware, RPMs and Fedora image.
#   podman build -t a7a-build -f Containerfile .
#   podman run --rm --userns=keep-id --security-opt label=disable \
#     -v "$PWD":/w -w /w a7a-build make firmware fel-image rpms
# make fedora-image runs aarch64 package scriptlets under qemu-aarch64-static:
#   podman run --rm --privileged -v "$PWD":/w -w /w a7a-build make fedora-image
# (--privileged lets scripts/binfmt-aarch64.sh register the handler in the
# container's own binfmt_misc instance, Linux 6.7 or later.)
FROM registry.fedoraproject.org/fedora:45

RUN dnf -y install --setopt=install_weak_deps=False \
        make git patch gcc gcc-c++ libuuid-devel python3 \
        gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu binutils llvm \
        acpica-tools dtc cpp curl xz zstd tar cpio openssl file which \
        findutils diffutils util-linux e2fsprogs dosfstools mtools \
        rpm-build redhat-rpm-config systemd-rpm-macros dnf5 \
        python3-libselinux qemu-user-static-aarch64 systemd \
        libusb1-devel pkgconf-pkg-config \
    && dnf clean all

# Rust: the toolchain firmware/oreboot/rust-toolchain.toml pins.
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH HOME=/tmp
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal \
        --default-toolchain nightly-2026-05-06 \
        --component rust-src,llvm-tools,rustfmt,clippy \
        --target armv7a-none-eabi,aarch64-unknown-none-softfloat,riscv32imac-unknown-none-elf,riscv64imac-unknown-none-elf \
    && chmod -R a+rwX /opt/rustup /opt/cargo
