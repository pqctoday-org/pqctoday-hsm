#!/usr/bin/env node
// FHE browser matrix runner (FHE plan §7). Serves rust/pkg-fhe-web plus
// index.html on 127.0.0.1, drives each requested browser headless with
// Playwright, checks the §5.5 KAT and prints one JSON line per browser.
//
//   node tests/browser/fhe-kat/run.mjs [--browsers chromium,webkit,firefox] [--add | --memory]
//
// --memory loads memory.html instead (FHE plan §6.6): peak WASM memory across
// the public export in a module worker, then worker kill + recovery.
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

const pwSpec = process.env.PLAYWRIGHT_MODULE;
const pw = await import(pwSpec ? pathToFileURL(path.join(pwSpec, 'index.mjs')).href : 'playwright');

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm' };
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  const own = { '/': 'index.html', '/memory.html': 'memory.html', '/worker.js': 'worker.js' };
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
const base = memoryMode ? `${origin}/memory.html` : `${origin}/${withAdd ? '?add' : ''}`;

let failed = 0;
for (const name of browsers) {
  const row = { browser: name };
  let browser;
  try {
    browser = await pw[name].launch();
    row.version = browser.version();
    const page = await browser.newPage();
    const t = Date.now();
    await page.goto(base);
    await page.waitForFunction(() => window.__result, null, { timeout: 15 * 60 * 1000 });
    Object.assign(row, await page.evaluate(() => window.__result), { wallMs: Date.now() - t });
    if (memoryMode) {
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
server.close();
process.exit(failed ? 1 : 0);
