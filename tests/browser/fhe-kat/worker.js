// FHE browser matrix — runs the token bundle inside a dedicated module worker
// (FHE plan §6.6: browser calls run in a disposable worker that can be
// terminated). Reports WASM linear-memory size, which only grows, so its
// value after a step is the peak up to that step.
import init, * as m from './pkg/softhsmrustv3.js';

const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
let wasm;
const mem = () => wasm.memory.buffer.byteLength;

self.onmessage = async ({ data }) => {
  try {
    if (data === 'init') {
      const t = performance.now();
      wasm = await init();
      self.postMessage({ step: 'init', ms: performance.now() - t, memBytes: mem() });
    } else if (data === 'kat') {
      const t = performance.now();
      const ck = m.fheClientKeyKat(seed);
      self.postMessage({ step: 'kat', ms: performance.now() - t, clientKey: ck, memBytes: mem() });
    } else if (data === 'pk' || data === 'sk') {
      const t = performance.now();
      const blob = m.fhePublicExport(seed, data === 'sk' ? 0 : 1);
      self.postMessage({ step: data, ms: performance.now() - t, bytes: blob.length, memBytes: mem() });
    } else if (data === 'add') {
      const t = performance.now();
      const sum = m.fheAddU8(seed, 200, 55);
      self.postMessage({ step: 'add', ms: performance.now() - t, sum, memBytes: mem() });
    }
  } catch (e) {
    self.postMessage({ step: data, error: String((e && e.message) || e) });
  }
};
