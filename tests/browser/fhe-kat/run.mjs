#!/usr/bin/env node
// FHE browser matrix runner (FHE plan §7). Serves rust/pkg-fhe-web plus
// index.html on 127.0.0.1, drives each requested browser headless with
// Playwright, checks the §5.5 KAT and prints one JSON line per browser.
//
//   node tests/browser/fhe-kat/run.mjs [--browsers chromium,webkit,firefox] [--add | --memory | --cap-mb 64,96,128]
//
// --memory loads memory.html instead (FHE plan §6.6): peak WASM memory across
// the public export in a module worker, then worker kill + recovery.
// --cap-mb loads cap.html once per cap with the WASM memory maximum patched to
// that many MiB (exploratory: prints every row, never fails on a capped step;
// it fails only if recovery on the uncapped bundle does not reproduce the KAT).
//
// Playwright is pinned in package.json (`npm ci`, then
// `npx playwright install chromium webkit firefox`). PLAYWRIGHT_MODULE can
// still point at another installed copy.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG = path.resolve(HERE, '../../../rust/pkg-fhe-web');
const EXPECT = {
  derivedSeed: 'f6eb1c9a88a4442c8a7449536c3d12dc',
  clientKey: '24087:9f5d847e4d1121eef9d75fcc473e89ee5306523f9cb140384eba5aa85a55b77b',
  addU8: 255,
};
const args = process.argv.slice(2);
const browsers = (args[args.indexOf('--browsers') + 1] && args.includes('--browsers')
  ? args[args.indexOf('--browsers') + 1] : 'chromium,webkit').split(',');
const withAdd = args.includes('--add');
const memoryMode = args.includes('--memory');
const caps = args.includes('--cap-mb') ? args[args.indexOf('--cap-mb') + 1].split(',').map(Number) : [];

const pwSpec = process.env.PLAYWRIGHT_MODULE;
const pw = await import(pwSpec ? pathToFileURL(path.join(pwSpec, 'index.mjs')).href : 'playwright');

// Rewrites the module's memory section to declare a maximum of `mib` MiB.
function capWasm(buf, mib) {
  let o = 8;
  const leb = () => { let r = 0, sh = 0, x; do { x = buf[o++]; r |= (x & 127) << sh; sh += 7; } while (x & 128); return r >>> 0; };
  const enc = (v) => { const a = []; do { let x = v & 127; v >>>= 7; if (v) x |= 128; a.push(x); } while (v); return a; };
  while (o < buf.length) {
    const idPos = o; const id = buf[o++]; const len = leb(); const start = o;
    if (id === 5) {
      const n = leb(); const flag = buf[o++]; const min = leb();
      if (n !== 1 || flag !== 0) throw new Error(`unexpected memory section (n=${n} flag=${flag})`);
      const body = [1, 1, ...enc(min), ...enc(mib * 16)];   // 1 memory, has-max, min, max (64 KiB pages)
      return Buffer.concat([buf.subarray(0, idPos), Buffer.from([5, ...enc(body.length), ...body]), buf.subarray(start + len)]);
    }
    o = start + len;
  }
  throw new Error('no memory section');
}
const capped = new Map();

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm' };
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  const own = { '/': 'index.html', '/memory.html': 'memory.html', '/worker.js': 'worker.js',
    '/cap.html': 'cap.html', '/worker-cap.js': 'worker-cap.js' };
  const cm = url.pathname.match(/^\/pkgcap(\d+)\/(.+)$/);
  if (cm) {
    const f = path.join(PKG, cm[2]);
    if (!f.startsWith(PKG) || !fs.existsSync(f)) { res.writeHead(404).end(); return; }
    let body = fs.readFileSync(f);
    if (f.endsWith('.wasm')) {
      if (!capped.has(cm[1])) capped.set(cm[1], capWasm(body, Number(cm[1])));
      body = capped.get(cm[1]);
    }
    res.writeHead(200, { 'content-type': TYPES[path.extname(f)] || 'application/octet-stream' }).end(body);
    return;
  }
  const file = own[url.pathname] ? path.join(HERE, own[url.pathname])
    : url.pathname.startsWith('/pkg/') ? path.join(PKG, url.pathname.slice(5)) : null;
  if (!file || !file.startsWith(HERE) && !file.startsWith(PKG) || !fs.existsSync(file)) {
    res.writeHead(404).end(); return;
  }
  res.writeHead(200, { 'content-type': TYPES[path.extname(file)] || 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;
const base = caps.length ? null : memoryMode ? `${origin}/memory.html` : `${origin}/${withAdd ? '?add' : ''}`;

let failed = 0;
for (const name of browsers) {
 for (const cap of (caps.length ? caps : [null])) {
  const row = { browser: name };
  if (cap !== null) row.capMiB = cap;
  let browser;
  try {
    browser = await pw[name].launch();
    row.version = browser.version();
    const page = await browser.newPage();
    const t = Date.now();
    await page.goto(cap !== null ? `${origin}/cap.html?pkg=pkgcap${cap}` : base);
    await page.waitForFunction(() => window.__result, null, { timeout: 15 * 60 * 1000 });
    Object.assign(row, await page.evaluate(() => window.__result), { wallMs: Date.now() - t });
    if (cap !== null) {
      row.kat = !row.error && row.recovery && !row.recovery.error && row.recovery.clientKey === EXPECT.clientKey ? 'PASS' : 'FAIL';
    } else if (memoryMode) {
      const kat = (row.steps || []).find((x) => x.step === 'kat');
      row.kat = !row.error && kat && kat.clientKey === EXPECT.clientKey
        && row.recovery && row.recovery.clientKey === EXPECT.clientKey ? 'PASS' : 'FAIL';
    } else {
      row.kat = row.derivedSeed === EXPECT.derivedSeed && row.clientKey === EXPECT.clientKey
        && (!withAdd || row.addU8 === EXPECT.addU8) ? 'PASS' : 'FAIL';
    }
  } catch (e) {
    row.kat = 'ERROR';
    row.error = String(e.message || e).split('\n')[0];
  } finally {
    if (browser) await browser.close();
  }
  if (row.kat !== 'PASS') failed++;
  console.log(JSON.stringify(row));
 }
}
server.close();
process.exit(failed ? 1 : 0);
