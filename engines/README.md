# Engine releases

The Hub ships WebAssembly engines that are built from this repository. An
**engine release** is a GitHub release in its own tag series, `engines-1`,
`engines-2`, ... (not the product version), that attaches:

- one tarball per bundle, `<bundle>-<commit8>.tar.gz`, holding the files exactly
  as the consumer lays them out (the explicit file paths in `bundles.json`; folder
  entries are rejected because a folder can hold consumer-authored code);
- `engines-manifest.json`: for every bundle the build commit, the tarball
  SHA-256, the SHA-256 and size of every file, and the bundle's notice files;
- `SHA256SUMS`.

## Third-party notices

Every tarball also holds `public/licenses/engines/<bundle>/THIRD-PARTY-NOTICES.txt`
and a `LICENSES/` folder next to it with the full licence texts of everything
compiled into that bundle: the components named in the bundle's `notices`
list (`notices/components.json`, texts in `notices/texts/` or elsewhere in this
repository) and, for the Rust bundles, every crate compiled for the bundle's
wasm32 target (`cargoTarget` in `bundles.json`, default
`wasm32-unknown-unknown`; `openssl-pkcs11` links the Rust engine as a
`wasm32-unknown-emscripten` staticlib) (`notices/crates/<bundle>.json`,
generated from `Cargo.lock`). Changed
third-party code is marked as changed and points to its record (`PATCHES.md`,
`NOTICE`). The strongSwan bundle also carries the GPL-2.0 source pointer: the
strongSwan 6.0.5 tarball plus this repository at the build commit, and the
OpenSSL Studio bundle carries the GPL-3.0 source pointer for its shims. The
manifest lists every notice file with its SHA-256, and `verify` checks them in
the tarballs and in the consumer tree.

The notices are generated from this checkout. Packaging refuses a bundle whose
notices are incomplete, and CI runs the same check:

```bash
python3 scripts/engine_notices.py check     # no cargo needed
# after a dependency change, in the Rust container (cargo + crate sources):
python3 scripts/engine_notices.py crates
```

When a build starts linking new third-party code, add it to
`notices/components.json` and to the bundle's `notices` list.

A consumer pins **one exact release and checksum per bundle** and verifies it
without any sibling checkout.

## What a release attests, and what it does not

It attests *which files were published*. It does not claim the files rebuild
bit-for-bit from source: the engines are built on a maintainer's Mac with the
pinned toolchain. Independent reproducibility is a separate improvement.

## How to make one

1. Build the engines with their scripts (`bundles.json` names each script).
2. Put the built files in a folder laid out like the consumer (today: the Hub
   checkout; the aim is a staging folder the build scripts fill).
3. Package. This never uploads:

   ```bash
   python3 scripts/publish_engines.py package --from <consumer-layout-dir> \
       --out /tmp/engines-1 --tag engines-1 --provenance <consumer wasm-provenance.json>
   # or per bundle:  --commit cacp-kmip=<40-hex>   or  --commit-head
   ```

4. Check what you built: `python3 scripts/publish_engines.py verify --manifest /tmp/engines-1/engines-manifest.json --tarballs /tmp/engines-1 --tree <consumer-layout-dir>`.
5. Publishing is a public act and a separate decision: the package step prints
   the exact `gh release create` command; run it yourself.

The output is deterministic: the same input gives the same bytes.

## The OpenSSL Studio bundle

`openssl-pkcs11` (`public/wasm/openssl.js` + `openssl.wasm`) is linked by
`scripts/build-openssl-studio-wasm.sh` from OpenSSL 3.6.3, this repository's
pkcs11-provider and Rust engine, and the C shims in `wasm/openssl-studio/`.
It writes to a staging folder, `build-wasm/engines-staging/`, laid out like
the consumer, so it can be packaged on its own:

```bash
python3 scripts/publish_engines.py package --from build-wasm/engines-staging \
    --only openssl-pkcs11 --out /tmp/engines-2 --tag engines-2 --commit-head
```
