#!/usr/bin/env python3
"""Re-add the `__indirect_function_table` export that wasm-bindgen-cli's
own postprocessing pass strips from every wasm-pack build.

Why this exists: C_GetFunctionList (PKCS#11 v3.2 §5.4.4) returns a
CK_FUNCTION_LIST whose fields are real WASM indirect-function-table
indices — a JS caller retrieves one with `table.get(idx)` and invokes it
directly, the standard way to call a funcref pulled out of linear memory.
`rustc`/`wasm-ld` already export the table correctly when built with
`-C link-arg=--export-table` (verified 2026-08-28: `cargo build --target
wasm32-unknown-unknown` alone produces a `__indirect_function_table`
export) — but `wasm-bindgen-cli`'s own transform pass drops it, keeping
only its own internal `__wbindgen_externrefs` table. The underlying table
itself (with every function whose address was ever taken, C_Initialize
included) survives inside the binary; only its *export* is gone, so this
script's job is narrow: disassemble, add one export line, reassemble.

Same class of problem as `__wbg_get_memory` a few lines below in
build-wasm-bundle.sh (wasm-bindgen stopped auto-exporting it too) — same
kind of fix: patch the build's own output rather than the toolchain.

Requires `wasm-dis` and `wasm-as` (Binaryen) on PATH — install via
`brew install binaryen`, or point WASM_DIS/WASM_AS at an existing
Emscripten SDK's `upstream/bin/` (this project's C++ engine already
depends on emsdk for its own, unrelated Emscripten build).

Usage: patch_export_table.py <in.wasm> <out.wasm>
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile


def find_tool(name: str, env_var: str) -> str:
    override = os.environ.get(env_var)
    if override and os.path.isfile(override):
        return override
    found = shutil.which(name)
    if found:
        return found
    raise SystemExit(
        f"{name} not found on PATH and ${env_var} is not set to a valid path.\n"
        f"Install Binaryen (`brew install binaryen`) or set {env_var} to an "
        f"emsdk checkout's upstream/bin/{name}."
    )


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <in.wasm> <out.wasm>", file=sys.stderr)
        return 2
    in_wasm, out_wasm = sys.argv[1], sys.argv[2]

    wasm_dis = find_tool("wasm-dis", "WASM_DIS")
    wasm_as = find_tool("wasm-as", "WASM_AS")

    wat = subprocess.run(
        [wasm_dis, in_wasm], capture_output=True, text=True, check=True
    ).stdout

    m = re.search(r"^ \(table \$0 \d+ \d+ funcref\)$", wat, re.MULTILINE)
    if not m:
        print(
            "patch_export_table.py: could not find the expected "
            "'(table $0 N N funcref)' declaration — wasm-bindgen-cli's "
            "output shape may have changed; re-inspect with wasm-dis "
            "before adjusting this script's regex.",
            file=sys.stderr,
        )
        return 1
    old = m.group(0)
    if wat.count(old) != 1:
        print(
            f"patch_export_table.py: expected exactly 1 occurrence of "
            f"the table declaration, found {wat.count(old)}",
            file=sys.stderr,
        )
        return 1
    new = old + '\n (export "__indirect_function_table" (table $0))'
    wat = wat.replace(old, new, 1)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".wat", delete=False) as f:
        f.write(wat)
        wat_path = f.name

    try:
        result = subprocess.run(
            [
                wasm_as, wat_path, "-o", out_wasm,
                # The feature set this specific build actually uses —
                # verified 2026-08-28 by round-tripping the real bindgen
                # output; --all-features pulls in GC/exception-handling
                # encodings the original binary doesn't use and produces
                # a binary V8 fails to parse ("Unknown heap type").
                "--enable-sign-ext",
                "--enable-mutable-globals",
                "--enable-nontrapping-float-to-int",
                "--enable-bulk-memory",
                "--enable-reference-types",
                "--enable-multivalue",
            ]
        )
    finally:
        os.unlink(wat_path)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
