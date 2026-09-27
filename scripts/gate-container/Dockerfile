# Gate container for scripts/local-gate.sh — a reproducible equivalent of the
# hand-provisioned `pqc-rust` container the gate has always run in.
#
# Why this file exists (2026-09-27): `pqc-rust` is the stock rust:1 image with
# its toolchain installed by hand, so there was no recipe to build a second,
# equivalent container on another host (scripts/remote-gate.sh, the M4 Pro).
# A snapshot (`docker commit`) of the running container was rejected: it
# would carry whatever that container's filesystem holds, unreviewed. This
# recipe inherits nothing from it — every version below was read from the
# live pqc-rust container on 2026-09-27 and is pinned here.
#
# Equivalence is not asserted by this file; it is MEASURED by running the
# same commit through the gate in both containers (see remote-gate.sh).
#
# Build:  docker build -t pqc-gate:2026-09-27 scripts/gate-container
# Run:    docker run -d --name pqc-rust \
#           -v "$HOME/ag-gate:/ag" \
#           -v pqc-cargo-target:/cargo-target \
#           -v pqc-cargo-registry:/usr/local/cargo/registry \
#           -v pqc-cargo-git:/usr/local/cargo/git \
#           pqc-gate:2026-09-27 sleep infinity

# rust:1 as pulled for pqc-rust (rustc 1.96.0, Debian 13 trixie, arm64).
FROM rust@sha256:c6811167278337db5f3b0234964ced5f538f154a2a20f09ec03721d7411c933d

# The manually installed apt set of pqc-rust (`apt-mark showmanual`). Most of
# it is already in the rust:1 base; apt skips what is present.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      autoconf automake binaryen bzip2 ca-certificates clang cmake curl \
      dpkg-dev file g++ gcc gdb git gnupg libbz2-dev libc6-dev libclang-dev \
      libcppunit-dev libcurl4-openssl-dev libffi-dev libgmp-dev libsodium-dev \
      libsqlite3-dev libssl-dev libtool libxml2-dev libyaml-dev make netbase \
      nodejs npm openssh-client patch pkg-config procps python3 python3-pytest \
      unzip wget xz-utils zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

# OpenSSL 3.6.3 at /usr/local/ssl — the gate's C++ build requires >= 3.6 to
# compile (see local-gate.sh, step "C++ ctest"). SHA-256 is the one OpenSSL
# publishes alongside the release tarball, re-checked on 2026-09-27.
ARG OPENSSL_VERSION=3.6.3
ARG OPENSSL_SHA256=243a86649cf6f23eeb6a2ff2456e09e5d77dd9018a54d3d96b0c6bdd6ba6c7f1
RUN cd /tmp \
 && curl -fsSLO "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
 && echo "${OPENSSL_SHA256}  openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c - \
 && tar xzf "openssl-${OPENSSL_VERSION}.tar.gz" \
 && cd "openssl-${OPENSSL_VERSION}" \
 && ./Configure --prefix=/usr/local/ssl --openssldir=/usr/local/ssl --libdir=lib zlib shared \
 && make -j"$(nproc)" >/dev/null \
 && make install_sw install_ssldirs >/dev/null \
 && cd / && rm -rf /tmp/openssl-*

RUN rustup target add wasm32-unknown-unknown wasm32-unknown-emscripten x86_64-unknown-linux-gnu

# Cargo tools, at the versions pqc-rust carries. The gate invokes wasm-pack by
# the full path /cargo-target/release/wasm-pack (it is not on pqc-rust's PATH
# there), so a copy is placed at that path too. A named volume mounted at
# /cargo-target starts out holding the image's contents, so a fresh
# pqc-cargo-target volume gets it.
RUN cargo install --locked cargo-nextest@0.9.143 wasm-pack@0.15.0 \
      wasm-bindgen-cli@0.2.117 \
 && mkdir -p /cargo-target/release \
 && cp /usr/local/cargo/bin/wasm-pack /cargo-target/release/wasm-pack \
 && rm -rf /usr/local/cargo/registry /usr/local/cargo/git

ENV CARGO_TARGET_DIR=/cargo-target
WORKDIR /ag
