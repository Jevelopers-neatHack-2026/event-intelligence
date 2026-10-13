// Fixed synthetic HTML/XHTML fixture probe. API interposition only, not an OS firewall.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { request as namedRequestBeforeGuard } from "node:http";
import { createRequire, syncBuiltinESMExports } from "node:module";

const require = createRequire(import.meta.url);
const MODE = process.argv[2];
const MODES = ["healthy", "caught-network", "caught-browser"];
const PREFIX = "PARSER_SIDE_REQUEST_PROBE_JSON=";
const ERROR = "EI_PARSER_TEST_SIDE_EFFECT_DENIED";
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const attempts = [];
let attemptCount = 0;
const registrations = [];
const controls = [];
const fixtures = [];
const dnsMethods = ["lookup", "lookupService", "resolve", "resolve4", "resolve6",
  "resolveAny", "resolveCaa", "resolveCname", "resolveMx", "resolveNaptr",
  "resolveNs", "resolvePtr", "resolveSoa", "resolveSrv", "resolveTxt", "reverse"];
let phase = "arguments";
let activeFixture = null;
let baseline = 0;

function install(target, keys, label, category) {
  for (const key of keys) {
    assert.equal(typeof target[key], "function", "required API missing: " + label + "." + key);
    const api = label + "." + key;
    target[key] = function denyBeforeNative() {
      attemptCount += 1;
      if (attempts.length < 256) attempts.push({ api, category, phase, fixture: activeFixture });
      const error = new Error(ERROR);
      error.code = ERROR;
      throw error;
    };
    registrations.push({ api, category, target, key });
  }
}

function assertNoSideEffects() {
  if (attemptCount !== baseline || globalThis.__eiParserScriptExecuted !== false) {
    const error = new Error("PARSER_SIDE_EFFECT_RECORDED");
    error.code = "PARSER_SIDE_EFFECT_RECORDED";
    throw error;
  }
}

function exactRanges(result, bytes) {
  const values = [...result.canonicalSuggestions, ...result.pageMetadata, ...result.visibleText,
    ...result.statusMentions, ...result.accessSignals,
    ...result.assetSources.map((row) => row.candidate),
    ...result.events.flatMap((row) => row.candidates),
    ...result.organizations.flatMap((row) => row.candidates)];
  for (const value of values) {
    const { startByte, endByte } = value.source.locator;
    assert.ok(startByte >= 0 && endByte >= startByte && endByte <= bytes.length);
    assert.equal(bytes.subarray(startByte, endByte).toString("utf8"), value.rawValue);
  }
  return values.length;
}

function receipt(kind, extra = {}) {
  return {
    schemaVersion: "ei-parser-side-request-probe/1", kind, mode: MODE,
    measurement: "fixed Node API interposition before product import; not kernel or hostile-native containment",
    node: process.versions.node, phase, activeFixture,
    registrations: registrations.map(({ api, category }) => ({ api, category })),
    positiveControls: controls, fixtures,
    parserAttemptCount: Math.max(0, attemptCount - baseline),
    parserAttempts: attempts.slice(baseline),
    scriptExecuted: globalThis.__eiParserScriptExecuted === true,
    ...extra,
  };
}

try {
  assert.equal(process.argv.length, 3);
  assert.ok(MODES.includes(MODE), "unknown probe mode");

  phase = "install";
  install(require("node:http"), ["request", "get", "ClientRequest"], "http", "network");
  install(require("node:https"), ["request", "get"], "https", "network");
  install(require("node:http2"), ["connect"], "http2", "network");
  install(require("node:net"), ["connect", "createConnection"], "net", "network");
  install(require("node:net").Socket.prototype, ["connect"], "net.Socket", "network");
  install(require("node:net").Server.prototype, ["listen"], "net.Server", "network");
  install(require("node:tls"), ["connect"], "tls", "network");
  install(require("node:dgram"), ["createSocket"], "dgram", "network");
  install(require("node:dgram").Socket.prototype, ["connect", "send", "bind"], "dgram.Socket", "network");
  install(require("node:dns"), dnsMethods, "dns", "network");
  install(require("node:dns/promises"), dnsMethods, "dns.promises", "network");
  install(require("node:dns").Resolver.prototype, dnsMethods.slice(2), "dns.Resolver", "network");
  install(require("node:dns/promises").Resolver.prototype, dnsMethods.slice(2), "dns.promises.Resolver", "network");
  install(globalThis, ["fetch", "WebSocket"], "global", "network");
  install(require("node:child_process"),
    ["exec", "execFile", "execSync", "execFileSync", "fork", "spawn", "spawnSync"],
    "child_process", "launch");
  install(require("node:worker_threads"), ["Worker"], "worker_threads", "launch");
  install(process, ["dlopen"], "process", "launch");
  syncBuiltinESMExports();

  // Every fixed API must deny synchronously with its own observed record before native validation.
  phase = "positive-controls";
  for (const row of registrations) {
    const before = attemptCount;
    assert.throws(() => row.target[row.key]({}), { code: ERROR });
    assert.equal(attemptCount, before + 1);
    assert.deepEqual(attempts.at(-1), { api: row.api, category: row.category, phase, fixture: null });
    controls.push(row.api);
  }
  const beforeNamed = attemptCount;
  assert.throws(() => namedRequestBeforeGuard("not a URL"), { code: ERROR });
  assert.equal(attemptCount, beforeNamed + 1);
  assert.equal(attempts.at(-1).api, "http.request");
  controls.push("http.request.esm-binding");
  assert.equal(registrations.length, 86);
  assert.equal(controls.length, 87);
  baseline = attemptCount;
  globalThis.__eiParserScriptExecuted = false;

  // Product and its dependencies load only after the guard and its controls are established.
  phase = "product-import";
  const { extractDeterministically } = await import("../../../src/extraction/index.mjs");
  assertNoSideEffects();
  const sourceUrl = "https://events.example.test/calendar";
  const fetchedAt = "2026-10-10T12:00:00.000Z";
  const fixtureRoot = new URL("../fixtures/", import.meta.url);
  const multi = await readFile(new URL("multi-event.html", fixtureRoot));
  const shell = await readFile(new URL("sparse-js-shell.html", fixtureRoot));
  const restricted = await readFile(new URL("access-restricted.html", fixtureRoot));
  const remote = "https://must-not-resolve.invalid/";
  const sharedHead = '<link rel="canonical" href="' + remote + 'canonical"/><link rel="stylesheet" href="' + remote
    + 'style.css"/><style>@import url("' + remote + 'other.css");</style>'
    + '<script src="' + remote + 'script.js"></script>'
    + '<script>globalThis.__eiParserScriptExecuted = true; fetch("' + remote + 'script-fetch");</script>'
    + '<script type="application/ld+json">{"@context":"' + remote
    + 'context","@id":"' + remote + 'event","@type":"Event","name":"Recorder Night"}</script>';
  const sharedBody = '<h1>Recorder Night</h1><img src="' + remote + 'image.png"/>'
    + '<iframe src="' + remote + 'frame"></iframe>';
  const html = Buffer.from("<!doctype html><html><head>" + sharedHead + "</head><body>" + sharedBody + "</body></html>");
  const xhtml = Buffer.from('<html xmlns="http://www.w3.org/1999/xhtml"><head>' + sharedHead
    + "</head><body>" + sharedBody + "</body></html>");
  const externalDtd = Buffer.from('<!DOCTYPE html SYSTEM "' + remote + 'external.dtd">'
    + '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>Local visible copy.</p></body></html>');
  const xmlShell = Buffer.from('<html xmlns="http://www.w3.org/1999/xhtml"><body><main id="root"></main>'
    + '<script src="' + remote + 'app.js"></script></body></html>');
  const xmlRestricted = Buffer.from('<html xmlns="http://www.w3.org/1999/xhtml"><body>'
    + '<h1>Access denied</h1><p>Complete the security challenge to continue.</p></body></html>');
  const matrix = [
    ["multi-event-html", multi, "text/html", "PARTIAL", "multi"],
    ["remote-html", html, "text/html", "PARTIAL", "remote"],
    ["remote-xhtml", xhtml, "application/xhtml+xml", "PARTIAL", "remote"],
    ["external-dtd-xhtml", externalDtd, "application/xhtml+xml", "PARTIAL", "visible"],
    ["js-shell-html", shell, "text/html", "JS_REQUIRED", "js"],
    ["js-shell-xhtml", xmlShell, "application/xhtml+xml", "JS_REQUIRED", "js"],
    ["access-html", restricted, "text/html", "ACCESS_RESTRICTED", "access"],
    ["access-xhtml", xmlRestricted, "application/xhtml+xml", "ACCESS_RESTRICTED", "access"],
    ["cancelled-html", multi, "text/html", "CANCELED", "cancel"],
    ["cancelled-xhtml", xhtml, "application/xhtml+xml", "CANCELED", "cancel"],
    ["recovery-html", multi, "text/html", "PARTIAL", "multi"],
  ];
  for (const [id, bytes, contentType, expectedStatus, assertion] of matrix) {
    phase = "fixture"; activeFixture = id;
    assertNoSideEffects();
    if (id === "remote-html" && MODE === "caught-browser") {
      // A usable parse cannot hide even a deliberately swallowed browser-launch denial.
      try { require("node:child_process").spawn({}); }
      catch (error) { assert.equal(error.code, ERROR); }
    }
    const controller = new AbortController();
    if (assertion === "cancel") controller.abort();
    const result = await extractDeterministically({ url: sourceUrl, fetchedAt, contentType, bytes },
      { signal: controller.signal });
    assert.equal(result.status, expectedStatus, id);
    assert.equal(result.sourceHash, "sha256:" + hash(bytes));
    const rangeCount = exactRanges(result, bytes);
    if (assertion === "multi") {
      assert.equal(result.events.length, 2);
      assert.equal(result.events[0].candidates.find((value) => value.field === "name").normalizedValue, "Café Night 🎵");
      assert.ok(rangeCount > 0);
    } else if (assertion === "remote") {
      assert.equal(result.events.length, 1);
      assert.equal(result.events[0].candidates.find((value) => value.field === "name").normalizedValue, "Recorder Night");
      assert.ok(result.canonicalSuggestions.some((value) => value.urlSuggestion === remote + "canonical"));
      assert.ok(result.assetSources.length > 0);
      assert.ok(rangeCount > 0);
    } else if (assertion === "visible") {
      assert.ok(result.visibleText.some((value) => value.normalizedValue === "Local visible copy."));
      assert.ok(rangeCount > 0);
    } else if (assertion === "js") {
      assert.equal(result.events.length, 0);
      assert.equal(result.visibleText.length, 0, "the fixed sparse shell has no usable visible answer");
    } else if (assertion === "access") {
      assert.ok(result.accessSignals.length > 0);
      assert.ok(rangeCount > 0);
    } else {
      assert.equal(result.termination, "CANCELED");
      assert.equal(result.events.length, 0);
    }
    // Drain immediate continuations, then verify all records since pre-import controls.
    await new Promise((resolve) => setImmediate(resolve));
    assertNoSideEffects();
    fixtures.push({ id, inputSha256: hash(bytes), status: result.status, exactRanges: rangeCount,
      events: result.events.length, networkAttempts: 0, launchAttempts: 0, scriptExecuted: false });
  }
  assert.equal(fixtures.length, 11);
  activeFixture = null; phase = "complete";
  assertNoSideEffects();
  if (MODE === "caught-network") {
    // The matrix has already settled. A late caught denial must still invalidate the final receipt.
    setTimeout(() => {
      phase = "late-control";
      try { require("node:http").request("not a URL"); }
      catch (error) { assert.equal(error.code, ERROR); }
    }, 0);
  }
  // Wait for this fixed child's outstanding work, not merely the parser's returned Promise.
  process.once("beforeExit", () => {
    try {
      assertNoSideEffects();
      process.stdout.write(PREFIX + JSON.stringify(receipt("success")) + "\n");
    } catch (error) { emitFailure(error); }
  });
} catch (error) { emitFailure(error); }

function emitFailure(error) {
  process.exitCode = 1;
  process.stdout.write(PREFIX + JSON.stringify(receipt("failure", {
    errorCode: error?.code === "PARSER_SIDE_EFFECT_RECORDED" ? error.code : "PROBE_ASSERTION_OR_SETUP_FAILED",
  })) + "\n");
  process.stderr.write(String(error?.stack ?? error) + "\n");
}
