// Same steps as worker.js, but the bundle comes from ?pkg=<dir> so the
// runner can serve a copy whose WASM memory has a maximum (low-memory cap).
const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
const pkg = new URL(self.location.href).searchParams.get('pkg') || 'pkg';
let m, wasm;
const mem = () => wasm.memory.buffer.byteLength;

self.onmessage = async ({ data }) => {
  try {
    if (data === 'init') {
      const t = performance.now();
      m = await import(`./${pkg}/softhsmrustv3.js`);
      wasm = await m.default();
      self.postMessage({ step: 'init', ms: performance.now() - t, memBytes: mem() });
    } else if (data === 'kat') {
      const t = performance.now();
      const ck = m.fheClientKeyKat(seed);
      self.postMessage({ step: 'kat', ms: performance.now() - t, clientKey: ck, memBytes: mem() });
    } else if (data === 'pk' || data === 'sk') {
      const t = performance.now();
      const blob = m.fhePublicExport(seed, data === 'sk' ? 0 : 1);
      self.postMessage({ step: data, ms: performance.now() - t, bytes: blob.length, memBytes: mem() });
    }
  } catch (e) {
    self.postMessage({ step: data, error: `${(e && e.name) || 'Error'}: ${(e && e.message) || e}` });
  }
};
