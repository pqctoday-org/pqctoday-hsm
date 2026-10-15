# Engine releases

The Hub ships WebAssembly engines that are built from this repository. An
**engine release** is a GitHub release in its own tag series, `engines-1`,
`engines-2`, ... (not the product version), that attaches:

- one tarball per bundle, `<bundle>-<commit8>.tar.gz`, holding the files exactly
  as the consumer lays them out (the explicit file paths in `bundles.json`; folder
  entries are rejected because a folder can hold consumer-authored code);
- `engines-manifest.json`: for every bundle the build commit, the tarball
  SHA-256 and the SHA-256 and size of every file;
- `SHA256SUMS`.

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
