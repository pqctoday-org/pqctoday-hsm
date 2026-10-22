#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# V5 runner (PKCS#11 v3.3 composite work, 2026-10-21). Runs INSIDE a throwaway
# `docker run --rm python:3.12-slim-trixie` container on the build host.
# /up   = read-only bind of the two pinned upstream clones (kem/, sigs/)
# /v5   = this scripts directory (read-only)
# /in   = the engine-generated fixture (read-only)
# /out  = results directory (read-write)
# Each repo's requirements.txt goes into its own venv, constrained to the
# versions V4 ran with (constraints.txt); versions are recorded.
set -eu
cd /tmp
export PIP_DISABLE_PIP_VERSION_CHECK=1
{ echo "openssl: $(openssl version)"; echo "python: $(python -V 2>&1)"; uname -m; } > /out/env.txt
for repo in kem sigs; do
  python -m venv /tmp/venv-$repo
  /tmp/venv-$repo/bin/pip install -q -c /v5/constraints.txt -r /up/$repo/src/requirements.txt > /out/pip-$repo.log 2>&1
  echo "== $repo pip freeze" >> /out/env.txt
  /tmp/venv-$repo/bin/pip freeze >> /out/env.txt
done
FX=/in/v5-fixture.json
/tmp/venv-kem/bin/python /v5/v5_kem_check.py /up/kem/src $FX /out/v5_kem_results.json > /out/v5_kem.log 2>&1 || echo "v5_kem exit $?" >> /out/v5_kem.log
/tmp/venv-sigs/bin/python /v5/v5_sig_check.py /up/sigs/src $FX /out/v5_sig_results.json > /out/v5_sig.log 2>&1 || echo "v5_sig exit $?" >> /out/v5_sig.log
python -I /v5/v5_combine.py /out "$(sha256sum $FX | cut -d' ' -f1)" > /out/summary.log 2>&1 || echo "combine exit $?" >> /out/summary.log
echo done
