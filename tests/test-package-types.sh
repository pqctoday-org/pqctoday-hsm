#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
archive="$(npm pack --ignore-scripts --silent --pack-destination "$tmp")"
package="$tmp/node_modules/@pqctoday/softhsm-wasm"
mkdir -p "$package"
tar -xzf "$tmp/$archive" -C "$package" --strip-components=1
cat > "$tmp/consumer.cts" <<'TS'
import { CK, createSoftHSMModule } from '@pqctoday/softhsm-wasm'
import constants, { CKA_ENCAPSULATE_TEMPLATE } from '@pqctoday/softhsm-wasm/constants'

const template: typeof CKA_ENCAPSULATE_TEMPLATE = CK.CKA_ENCAPSULATE_TEMPLATE
const sameTemplate: typeof template = constants.CKA_ENCAPSULATE_TEMPLATE
createSoftHSMModule().then(module => module._C_Initialize(0))
TS
tsc --strict --noEmit --module node16 "$tmp/consumer.cts"
