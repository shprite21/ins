/* Browser regression against an isolated local server. Requires Playwright and Chrome. */
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const net = require("node:net");
const { spawn } = require("node:child_process");
const { chromium } = require(process.env.IOT_PLAYWRIGHT_PATH || "playwright");
const root = path.resolve(__dirname, "..");
const results = path.join(root, "test-results");

async function freePort() {
  const listener = net.createServer();
  await new Promise((resolve, reject) => listener.once("error", reject).listen(0, "127.0.0.1", resolve));
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  return port;
}

async function checkTLSImports(page) {
  const external = {
    schema: "INS-IOT-TLS-CHECK-v1", server: "https://127.0.0.1:8443",
    recorded_at: new Date().toISOString(), trusted_authentication: true,
    untrusted_certificate_rejected: true, errors: [],
  };
  const upload = value => page.setInputFiles("#tls-evidence", {
    name: "tls.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(value)),
  });
  await upload(external);
  await page.waitForFunction(() => document.querySelector("#status-st7").textContent === "External PASS");
  await upload({});
  await page.waitForFunction(() => document.querySelector("#tls-import-note").textContent.startsWith("Import rejected"));
  assert.equal(await page.locator("#status-st7").innerText(), "Manual check", "Invalid imports must remove the previous PASS");
  await upload({ ...external, server: "https://different-host.invalid:8443" });
  await page.waitForFunction(() => document.querySelector("#tls-import-note").textContent.includes("hostname differs"));
  assert.equal(await page.locator("#status-st7").innerText(), "Manual check");
  await upload({ ...external, trusted_authentication: false });
  await page.waitForFunction(() => document.querySelector("#status-st7").textContent === "FAIL");
  await upload(external);
  await page.waitForFunction(() => document.querySelector("#status-st7").textContent === "External PASS");
}

(async () => {
  await fs.mkdir(results, { recursive: true });
  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
  const server = spawn(process.env.IOT_TEST_PYTHON || "python", ["-u", "server.py", "--port", String(port)], {
    cwd: root, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
  });
  let browser;
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Server startup timed out")), 10000);
      server.once("error", reject);
      server.stdout.on("data", data => {
        if (data.toString().includes("listening on")) { clearTimeout(timer); resolve(); }
      });
      server.once("exit", code => { clearTimeout(timer); reject(new Error(`Server exited: ${code}`)); });
    });
    browser = await chromium.launch({ headless: true, channel: "chrome" });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(origin);
    await page.locator("#run:enabled").waitFor();
    assert.equal(await page.locator("#test-count").innerText(), "0 / 6");
    assert.equal(await page.locator("#status-st7").innerText(), "Manual check");
    if (process.argv.includes("--tls-import-only")) {
      await checkTLSImports(page);
      assert.deepEqual(errors, []);
      console.log("PASS: external TLS success/failure, malformed import reset, and hostname mismatch rejection.");
      return;
    }
    await page.screenshot({ path: path.join(results, "desktop.png"), fullPage: true });
    await page.screenshot({ path: path.join(results, "desktop-overview.png") });
    await page.selectOption("#device", "sensor-002");
    await page.click("#run");
    await page.waitForFunction(() => document.querySelector("#result").textContent.includes("Authenticated sensor-002"));
    await page.click("#walkthrough");
    await page.waitForFunction(() => document.querySelector("#result").textContent.startsWith("Quick walkthrough passed"));
    for (const id of [1, 2, 3, 4, 6]) assert.equal(await page.locator(`#status-st${id}`).innerText(), "PASS");
    assert.equal(await page.locator("#status-st5").innerText(), "Not run");
    assert.equal(await page.locator("#test-count").innerText(), "5 / 6");
    assert.equal(await page.locator(".event.fail").count(), 0);
    assert.ok((await page.locator("#trace").innerText()).includes("Retry original valid proof"));
    // An interrupted real-time test must not be marked passed.
    await page.click("#expiry");
    await page.waitForFunction(() => document.querySelector("#countdown").textContent.includes("seconds remaining"));
    await page.click("#cancel");
    await page.waitForFunction(() => document.querySelector("#status-st5").textContent === "Incomplete");
    await page.click("#expiry");
    console.log("Quick suite and cancellation passed. Waiting for real ST-5 expiry...");
    await page.waitForFunction(() => document.querySelector("#status-st5").textContent === "PASS", null, { timeout: 75000 });
    assert.equal(await page.locator("#test-count").innerText(), "6 / 6");
    const [download] = await Promise.all([page.waitForEvent("download"), page.click("#export")]);
    const evidencePath = path.join(results, "dashboard-evidence.json");
    await download.saveAs(evidencePath);
    const evidence = JSON.parse(await fs.readFile(evidencePath, "utf8"));
    assert.equal(evidence.tests.st5.status, "pass");
    assert.ok(evidence.records.find(r => r.title.includes("Expired proof")).waited_seconds > 60);
    assert.equal(evidence.tests.st7.status, "manual");
    assert.ok(evidence.records.filter(r => r.request && typeof r.request.body === "object").every(r => !("key" in (r.request.body || {}))));
    await page.locator("#tests").screenshot({ path: path.join(results, "desktop-tests.png") });
    // User-supplied TLS results remain explicitly external, with target and timestamp.
    await checkTLSImports(page);
    const report = await page.request.get(origin + "/report");
    assert.equal(report.status(), 200);
    assert.equal(report.headers()["content-type"], "application/pdf");
    const brokenAnchors = await page.evaluate(() => [...document.querySelectorAll('a[href^="#"]')].map(a => a.getAttribute("href").slice(1)).filter(id => !document.getElementById(id)));
    assert.deepEqual(brokenAnchors, []);
    await page.click("#clear");
    assert.equal(await page.locator("#test-count").innerText(), "0 / 6");
    assert.equal(await page.locator("#status-st7").innerText(), "Manual check");
    assert.equal(await page.locator("#trace .event").count(), 0);
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(origin);
    await page.locator("#run:enabled").waitFor();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "Mobile layout overflows horizontally");
    await page.screenshot({ path: path.join(results, "mobile.png"), fullPage: true });
    await page.screenshot({ path: path.join(results, "mobile-overview.png") });
    await page.locator("#lab").screenshot({ path: path.join(results, "mobile-lab.png") });
    await page.click("#run");
    await page.waitForFunction(() => document.querySelector("#result").textContent.includes("Authenticated sensor-001"));
    // A disconnected/stale service disables controls rather than displaying success.
    await page.route("**/demo/info", route => route.fulfill({ status: 503, contentType: "application/json", body: "{}" }));
    await page.reload();
    await page.waitForFunction(() => document.querySelector("#connection").textContent === "Unavailable");
    assert.equal(await page.locator("#run").isDisabled(), true);
    assert.deepEqual(errors, []);
    console.log("PASS: desktop/mobile authentication, ST-1-6, cancellation, external TLS import, export/reset, PDF, anchors, offline state, and no script errors.");
  } finally {
    if (browser) await browser.close();
    server.kill();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
