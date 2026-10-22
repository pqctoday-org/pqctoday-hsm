#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# V4 runner (PKCS#11 v3.3 composite work, 2026-10-21). Runs INSIDE a throwaway
# `docker run --rm python:3.12-slim-trixie` container on the build host.
# /up   = read-only bind of the two pinned upstream clones (kem/, sigs/)
# /v4   = this scripts directory (read-only)
# /out  = results directory (read-write)
# Installs each repo's unpinned requirements.txt into its own venv, records
# versions, then runs the three checks. Nothing here runs outside that container.
set -eu
cd /tmp
export PIP_DISABLE_PIP_VERSION_CHECK=1
{ echo "openssl: $(openssl version)"; echo "python: $(python -V 2>&1)"; uname -m; } > /out/env.txt
for repo in kem sigs; do
  python -m venv /tmp/venv-$repo
  /tmp/venv-$repo/bin/pip install -q -r /up/$repo/src/requirements.txt > /out/pip-$repo.log 2>&1
  echo "== $repo pip freeze" >> /out/env.txt
  /tmp/venv-$repo/bin/pip freeze >> /out/env.txt
done
/tmp/venv-kem/bin/python /v4/ref_kem_check.py /up/kem/src /up/kem/src/testvectors.json /out/ref_kem_results.json > /out/ref_kem.log 2>&1 || echo "ref_kem exit $?" >> /out/ref_kem.log
/tmp/venv-sigs/bin/python /v4/ref_sig_check.py /up/sigs/src /up/sigs/src/testvectors.json /out/ref_sig_results.json > /out/ref_sig.log 2>&1 || echo "ref_sig exit $?" >> /out/ref_sig.log
python -I /v4/indep_check.py /up/kem/src/testvectors.json /up/sigs/src/testvectors.json /out/indep_results.json > /out/indep.log 2>&1 || echo "indep exit $?" >> /out/indep.log
python -I /v4/combine_results.py /out > /out/summary.log 2>&1 || echo "combine exit $?" >> /out/summary.log
echo done
