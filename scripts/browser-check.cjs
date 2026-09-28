'use strict';
// Optional browser smoke test. Uses installed Chrome and native Node.js WebSocket.
// Run the preview server first. Screenshots stay in ignored artifacts/.
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const artifacts = path.resolve(__dirname, '../artifacts');
fs.mkdirSync(artifacts, { recursive: true });
const profile = fs.mkdtempSync(path.join(artifacts, 'browser-profile-'));
const downloads = fs.mkdtempSync(path.join(artifacts, 'downloads-'));
const executable = process.env.CHROME_PATH || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const browser = spawn(executable, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], { windowsHide: true, stdio: 'ignore' });
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
let socket;
let sequence = 0;
const pending = new Map();
const events = [];
async function send(method, params = {}) {
  const id = ++sequence;
  const promise = new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10000);
    pending.set(id, { resolve, reject, timer });
  });
  socket.send(JSON.stringify({ id, method, params }));
  return promise;
}
async function evaluate(expression) {
  const value = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (value.exceptionDetails) throw new Error(JSON.stringify(value.exceptionDetails));
  return value.result.value;
}
async function screenshot(name, width, height) {
  await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: width < 720 });
  await pause(120);
  assert.equal(await evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, `horizontal overflow at ${width}`);
  const capture = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
  fs.writeFileSync(path.join(artifacts, name), Buffer.from(capture.data, 'base64'));
}
(async () => {
  let port;
  for (let attempt = 0; attempt < 100; attempt++) {
    const portFile = path.join(profile, 'DevToolsActivePort');
    if (fs.existsSync(portFile)) { port = fs.readFileSync(portFile, 'utf8').split('\n')[0]; break; }
    await pause(100);
  }
  if (!port) throw new Error('Chrome did not expose a debugging port.');
  const tabs = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
  socket = new WebSocket(tabs.find(t => t.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', reject, { once: true }); });
  socket.addEventListener('message', e => {
    const message = JSON.parse(e.data);
    if (message.id && pending.has(message.id)) {
      const p = pending.get(message.id); pending.delete(message.id); clearTimeout(p.timer);
      if (message.error) p.reject(new Error(message.error.message)); else p.resolve(message.result);
    } else events.push(message);
  });
  await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
  await send('Page.setDownloadBehavior', { behavior: 'allow', downloadPath: downloads });
  await send('Page.navigate', { url: 'http://127.0.0.1:4173/' });
  for (let i = 0; i < 100; i++) {
    if (await evaluate('document.readyState === "complete" && typeof NetScalerCheck !== "undefined"')) break;
    await pause(100);
  }
  assert.equal(await evaluate('document.getElementById("report").hidden'), true);
  await screenshot('desktop-empty.png', 1440, 1100);
  await evaluate('document.getElementById("demo").click()');
  assert.equal(await evaluate('document.querySelectorAll(".result-row").length'), 8);
  assert.equal(await evaluate('document.querySelectorAll(".badge.affected").length'), 8);
  assert.equal(await evaluate('document.getElementById("download").disabled'), false);
  await screenshot('desktop-results.png', 1440, 1100);
  const configBeforeSwitch = await evaluate('document.getElementById("config").value');
  await evaluate('document.querySelector(".result-row").open=true; document.querySelector("[data-language=en]").click()');
  assert.equal(await evaluate('document.documentElement.lang'), 'en');
  assert.equal(await evaluate('document.getElementById("config").value'), configBeforeSwitch);
  assert.equal(await evaluate('document.querySelector(".result-row").open'), true);
  assert.equal(await evaluate('document.querySelector(".summary h3").textContent'), 'Priority action is required.');
  assert.equal(await evaluate('document.querySelector("[data-language=en]").getAttribute("aria-pressed")'), 'true');
  assert.equal(await evaluate('location.search'), '?lang=en');
  const untranslated = await evaluate(`(() => { const w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);const found=[];while(w.nextNode()){const n=w.currentNode;if(!n.parentElement.closest('textarea,script') && /[çğıöşüÇĞİÖŞÜ]/.test(n.textContent))found.push(n.textContent.trim());}return found;})()`);
  assert.deepEqual(untranslated, [], 'English view contains untranslated Turkish text');
  await screenshot('desktop-en.png', 1440, 1100);
  await screenshot('mobile-en.png', 320, 1000);
  await evaluate('document.getElementById("filter").value="review"; document.getElementById("filter").dispatchEvent(new Event("change"))');
  assert.equal(await evaluate('document.querySelectorAll(".result-row").length'), 0);
  await evaluate('document.querySelector("[data-language=tr]").click()');
  assert.equal(await evaluate('document.getElementById("filter").value'), 'review');
  assert.equal(await evaluate('document.querySelector(".no-results").textContent'), 'Bu filtrede sonuç bulunmuyor.');
  await evaluate('document.querySelector("[data-language=en]").click()');
  await evaluate('document.getElementById("filter").value="all"; document.getElementById("filter").dispatchEvent(new Event("change")); document.getElementById("download").click()');
  const reportName = `netscaler-check-${new Date().toISOString().slice(0, 10)}.json`;
  for (let i = 0; i < 50 && !fs.existsSync(path.join(downloads, reportName)); i++) await pause(100);
  const downloaded = JSON.parse(fs.readFileSync(path.join(downloads, reportName), 'utf8'));
  assert.equal(downloaded.language, 'en');
  assert.equal(downloaded.results[0].label, 'Action required');
  assert.equal(/[çğıöşüÇĞİÖŞÜ]/.test(JSON.stringify(downloaded)), false);
  assert.equal(downloaded.results.length, 8); assert.equal(JSON.stringify(downloaded).includes('192.0.2.10'), false);
  await screenshot('mobile-results.png', 375, 1000);
  await screenshot('mobile-small.png', 320, 1000);
  await evaluate('document.getElementById("version").value="14.1-73.37"; document.getElementById("version").dispatchEvent(new Event("input"))');
  assert.equal(await evaluate('document.getElementById("report").hidden'), true);
  assert.equal(await evaluate('document.getElementById("download").disabled'), true);
  await evaluate('document.getElementById("check-form").requestSubmit()');
  assert.equal(await evaluate('document.querySelectorAll(".badge.patched").length'), 7);
  assert.equal(await evaluate('document.querySelectorAll(".badge.affected").length'), 1);
  await evaluate('document.getElementById("clear").click()');
  assert.equal(await evaluate('document.getElementById("config").value'), '');
  assert.equal(await evaluate('document.getElementById("report").hidden'), true);
  // File selection exercises the same browser event path as the user picker.
  const documentNode = await send('DOM.getDocument');
  const picker = await send('DOM.querySelector', { nodeId: documentNode.root.nodeId, selector: '#config-file' });
  await send('DOM.setFileInputFiles', { nodeId: picker.nodeId, files: [path.resolve(__dirname, '../examples/demo.conf')] });
  for (let i = 0; i < 50; i++) {
    if (await evaluate('document.getElementById("config").value.includes("demo_oracle")')) break;
    await pause(50);
  }
  assert.equal(await evaluate('document.getElementById("config").value.includes("demo_oracle")'), true);
  assert.equal(await evaluate('document.getElementById("complete").checked'), false);
  await send('Page.navigate', { url: 'http://127.0.0.1:4173/?lang=en' });
  for (let i = 0; i < 100; i++) {
    if (await evaluate('document.readyState === "complete" && document.documentElement.lang === "en" && document.getElementById("report").hidden')) break;
    await pause(100);
  }
  assert.equal(await evaluate('document.title'), 'NetScaler Check — Security Bulletin Assessment');
  assert.equal(await evaluate('document.getElementById("config").value'), '');
  const exceptions = events.filter(e => e.method === 'Runtime.exceptionThrown');
  assert.equal(exceptions.length, 0, JSON.stringify(exceptions));
  const requests = events.filter(e => e.method === 'Network.requestWillBeSent').map(e => e.params.request.url);
  assert.deepEqual(requests.filter(url => !url.startsWith('http://127.0.0.1:4173/') && !url.startsWith('blob:')), []);
  fs.writeFileSync(path.join(artifacts, 'browser-results.json'), JSON.stringify({ passed: true, checks: ['demo', 'TR/EN switching preserves inputs, filters and expanded findings', 'English translation completeness', 'English JSON download', 'English URL reload', 'filter', 'input invalidation', 'patched build + disabled ISN', 'reset', 'local file import', 'no external requests', 'no runtime errors', '1440 / 375 / 320 px layout'], requests }, null, 2));
  console.log('Browser checks passed. Screenshots and results: artifacts/');
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => { if (socket) socket.close(); browser.kill(); });
browser.on('error', error => { console.error(error.message); process.exitCode = 1; });
