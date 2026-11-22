#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
version=3.6.3
sha256=243a86649cf6f23eeb6a2ff2456e09e5d77dd9018a54d3d96b0c6bdd6ba6c7f1
mode=${1:?install or verify}
prefix=${2:?installation prefix}
profile=${3:?ci or gate}
case "$profile" in
  ci) flags=(shared) ;;
  gate) flags=(shared --libdir=lib zlib enable-lms) ;;
  *) exit 2 ;;
esac

case "$mode" in
  install)
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    cd "$tmp"
    archive="openssl-$version.tar.gz"
    curl -fsSLO "https://github.com/openssl/openssl/releases/download/openssl-$version/$archive"
    echo "$sha256  $archive" | sha256sum -c -
    tar xzf "$archive"
    cd "openssl-$version"
    ./Configure --prefix="$prefix" --openssldir="$prefix/ssl" "${flags[@]}"
    make -j"$(nproc)"
    make install_sw
    if [[ "$profile" == gate ]]; then make install_ssldirs; fi
    ;;
  verify) ;;
  *) exit 2 ;;
esac

export LD_LIBRARY_PATH="$prefix/lib64:$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
actual="$("$prefix/bin/openssl" version)"
echo "$actual"
[[ "$actual" == "OpenSSL $version "* ]]
algorithms="$("$prefix/bin/openssl" list -kem-algorithms)"
grep -iq 'ML-KEM-768' <<< "$algorithms"
if [[ "$profile" == gate ]]; then
  signatures="$("$prefix/bin/openssl" list -signature-algorithms)"
  grep -iq 'LMS' <<< "$signatures"
fi
