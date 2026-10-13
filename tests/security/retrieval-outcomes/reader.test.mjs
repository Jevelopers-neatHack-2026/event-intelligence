import assert from "node:assert/strict";
import test from "node:test";
import { gzipSync } from "node:zlib";
import { performance } from "node:perf_hooks";
import { SafeFetcher } from "../../../src/security/controlled-fetch.mjs";
import { RetrievalError } from "../../../src/security/errors.mjs";
import { safeFetchProvenance } from "../../../src/security/internal/fetch-lifecycle.mjs";
import { createLocalRetrievalOutcomes } from "../../../src/security/retrieval-outcomes/index.mjs";
import { wrapSafeFetcher } from "../../../src/security/retrieval-outcomes/internal.mjs";
import { startFixture, localTestSeam, fixtureUrl, respond, png } from "../support.mjs";

const schema = "ei-private-retrieval-outcome/1";
const secret = "synthetic-private-value-never-returned";
const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>';

async function fixture(t, handler, options = {}) {
  const server = await startFixture(handler);
  t.after(() => server.close());
  const dials = [];
  const fetcher = new SafeFetcher(localTestSeam({
    port: server.port, onDial: (value) => dials.push(value), ...options,
  }));
  return { server, dials, fetcher, reader: wrapSafeFetcher(fetcher), url: (p = "/") => fixtureUrl(server.port, p) };
}
function refusal(value, code, reason) {
  assert.deepEqual(value, { schema, kind: "refused", transportComplete: false, code, reason });
  assert.ok(Object.isFrozen(value));
  assert.equal(JSON.stringify(value).includes(secret), false);
  assert.equal(Object.hasOwn(value, "document"), false);
  return value;
}
function retrieved(value, type = "text/plain") {
  assert.equal(value.schema, schema); assert.equal(value.kind, "retrieved");
  assert.equal(value.transportComplete, true); assert.ok(Object.isFrozen(value));
  assert.equal(value.document.contentType, type); assert.ok(Object.isFrozen(value.document));
  assert.ok(safeFetchProvenance(value.document));
  return value.document;
}
async function waitFor(predicate, milliseconds = 3000) {
  const end = performance.now() + milliseconds;
  while (!predicate()) {
    if (performance.now() >= end) throw new Error("controlled fixture phase was not entered");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
const ok = (_request, response) => respond(response, 200, { "content-type": "text/plain" }, "fixture");

test("actual controlled retrieval keeps source identity and provenance", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, ok);
  const doc = retrieved(await f.reader.fetch(f.url()));
  assert.equal(Buffer.from(doc.bytes).toString(), "fixture");
  assert.equal(doc.url, f.url()); assert.equal(doc.redirects, 0);
  assert.equal(f.dials.length, 1);
  assert.equal(safeFetchProvenance(doc).hops[0].bodyComplete, true);
});

test("captured native fetch ignores receiver-owned callback overrides", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, ok); let called = false;
  f.fetcher.fetch = () => { called = true; throw new Error(secret); };
  retrieved(await f.reader.fetch(f.url())); assert.equal(called, false); assert.equal(f.dials.length, 1);
});

test("production factory does not admit caller configuration or callbacks", { timeout: 45000 }, async (t) => {
  let called = false;
  const reader = createLocalRetrievalOutcomes({ fetch() { called = true; } });
  refusal(await reader.fetch("http://127.0.0.1/"), "INVALID_INPUT", "INVALID_INPUT");
  assert.equal(called, false);
});

test("production factory blocks forbidden URL classes before any network path", { timeout: 45000 }, async (t) => {
  const reader = createLocalRetrievalOutcomes();
  for (const url of ["file:///etc/passwd", "ftp://example.org/", "http://u:p@example.org/",
    "http://127.0.0.1/", "http://2130706433/", "http://0x7f000001/", "http://[::ffff:127.0.0.1]/",
    "http://169.254.169.254/", "http://10.0.0.1/", "http://[::1]/"]) {
    refusal(await reader.fetch(url), "DESTINATION_BLOCKED", "POLICY_DENIED");
  }
});

test("malformed method inputs are fixed refusals without coercion or DNS", { timeout: 45000 }, async (t) => {
  let touched = 0; const f = await fixture(t, ok, { resolveOverride() { touched += 1; throw new Error(secret); } });
  for (const input of [null, undefined, 7, {}, [], { toString() { touched += 1; return secret; } }, "", "x".repeat(8193)]) {
    refusal(await f.reader.fetch(input), "INVALID_INPUT", "INVALID_INPUT");
  }
  assert.equal(touched, 0); assert.equal(f.dials.length, 0);
});

test("unknown option fields and extra method arguments are refused before transport", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, ok);
  for (const options of [{ headers: { authorization: secret } }, { maxBytes: 1 }, { fetch: ok }, [],
    null, new Date(), { [Symbol("unknown")]: true }]) {
    refusal(await f.reader.fetch(f.url(), options), "INVALID_INPUT", "INVALID_INPUT");
  }
  refusal(await f.reader.fetch(f.url(), {}, secret), "INVALID_INPUT", "INVALID_INPUT");
  refusal(await f.reader.fetchSvgAsset(f.url(), {}, secret), "INVALID_INPUT", "INVALID_INPUT");
  assert.equal(f.dials.length, 0);
});

test("getters and proxy options never execute", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, ok); let traps = 0;
  const options = Object.defineProperty({}, "signal", { enumerable: true, get() { traps += 1; throw new Error(secret); } });
  const proxy = new Proxy({}, { ownKeys() { traps += 1; throw new Error(secret); }, getPrototypeOf() { traps += 1; throw new Error(secret); } });
  refusal(await f.reader.fetch(f.url(), options), "INVALID_INPUT", "INVALID_INPUT");
  refusal(await f.reader.fetch(f.url(), proxy), "INVALID_INPUT", "INVALID_INPUT");
  assert.equal(traps, 0); assert.equal(f.dials.length, 0);
});

test("fake signals and proxied native signals cannot supply abort authority", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, ok); let traps = 0;
  for (const signal of [{ aborted: false }, new Proxy(new AbortController().signal, { get() { traps += 1; throw new Error(secret); } }), null]) {
    refusal(await f.reader.fetch(f.url(), { signal }), "INVALID_INPUT", "INVALID_INPUT");
  }
  assert.equal(traps, 0); assert.equal(f.dials.length, 0);
});

test("trusted AbortSignal intrinsics ignore an own aborted getter", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, ok); const controller = new AbortController(); let touched = 0;
  Object.defineProperty(controller.signal, "aborted", { get() { touched += 1; throw new Error(secret); } });
  retrieved(await f.reader.fetch(f.url(), { signal: controller.signal }));
  assert.equal(touched, 0); assert.equal(f.dials.length, 1);
});

test("null-prototype options and explicit undefined signal remain supported", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, ok);
  retrieved(await f.reader.fetch(f.url(), Object.assign(Object.create(null), { signal: undefined })));
  retrieved(await f.reader.fetch(f.url(), undefined));
  assert.equal(f.dials.length, 2);
});

test("unsupported receiver and proxy bridge never invokes supplied callbacks", { timeout: 45000 }, async (t) => {
  let touched = 0;
  for (const candidate of [null, {}, { fetch() { touched += 1; } }, new Proxy({}, { getPrototypeOf() { touched += 1; throw new Error(secret); } })]) {
    refusal(await wrapSafeFetcher(candidate).fetch("http://127.0.0.1/"), "INVALID_INPUT", "INVALID_INPUT");
  }
  assert.equal(touched, 0);
});

test("mixed allowed and private DNS answers produce zero dials", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, ok, { addresses: ["127.0.0.1", "10.0.0.7"] });
  refusal(await f.reader.fetch(f.url()), "DESTINATION_BLOCKED", "POLICY_DENIED");
  assert.equal(f.dials.length, 0);
});

test("private redirect destination is denied before its socket", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, (_req, res) => respond(res, 302, { location: "http://169.254.169.254/" + secret }));
  refusal(await f.reader.fetch(f.url()), "DESTINATION_BLOCKED", "POLICY_DENIED");
  assert.equal(f.dials.length, 1);
});

test("redirected image uses the same controlled transport and provenance", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, (req, res) => req.url === "/start"
    ? respond(res, 302, { location: "/image" })
    : respond(res, 200, { "content-type": "image/png" }, png(1, 1)));
  const doc = retrieved(await f.reader.fetch(f.url("/start")), "image/png");
  assert.equal(doc.redirects, 1); assert.equal(f.dials.length, 2);
  assert.deepEqual(doc.image, { width: 1, height: 1 });
  assert.equal(safeFetchProvenance(doc).hops.length, 2);
});

test("redirect loop retains its exact resource refusal reason", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, (_req, res) => respond(res, 302, { location: "/" }));
  refusal(await f.reader.fetch(f.url()), "RESOURCE_LIMIT", "REDIRECT_LIMIT");
  assert.equal(f.dials.length, 6);
});

test("DNS failure is distinct and contains no resolver error text", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, ok, { resolveOverride() { throw new RetrievalError("DNS_FAILURE"); } });
  refusal(await f.reader.fetch(f.url("/" + secret)), "DNS_FAILURE", "DNS_FAILURE");
  assert.equal(f.dials.length, 0);
});

test("transport failure is distinct and contains no socket or URL text", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, (req) => req.socket.destroy());
  refusal(await f.reader.fetch(f.url("/" + secret)), "TRANSPORT_FAILURE", "TRANSPORT_FAILURE");
  assert.equal(f.dials.length, 1);
});

test("unsupported native error codes are sanitized and fail closed", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, ok, { resolveOverride() { throw new RetrievalError(secret); } });
  refusal(await f.reader.fetch(f.url()), "INTERNAL_FAILURE", "UNRECOGNIZED_FAILURE");
  assert.equal(f.dials.length, 0);
});

test("native error code getters are not invoked by outcome mapping", { timeout: 45000 }, async (t) => {
  let touched = 0;
  const f = await fixture(t, ok, { resolveOverride() {
    const error = new RetrievalError("DNS_FAILURE");
    Object.defineProperty(error, "code", { get() { touched += 1; throw new Error(secret); } });
    throw error;
  } });
  refusal(await f.reader.fetch(f.url()), "INTERNAL_FAILURE", "UNRECOGNIZED_FAILURE");
  assert.equal(touched, 0); assert.equal(f.dials.length, 0);
});

test("partial HTTP responses never return a complete document and recover", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, (req, res) => req.url === "/partial"
    ? respond(res, 206, { "content-type": "text/plain" }, secret) : ok(req, res));
  refusal(await f.reader.fetch(f.url("/partial")), "TRANSPORT_FAILURE", "TRANSPORT_FAILURE");
  retrieved(await f.reader.fetch(f.url("/recovery"))); assert.equal(f.dials.length, 2);
});

test("MIME and file magic mismatch maps to a resource refusal", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, (_req, res) => respond(res, 200, { "content-type": "image/png" }, secret));
  refusal(await f.reader.fetch(f.url()), "RESOURCE_LIMIT", "UNSUPPORTED_MEDIA");
});

test("unsupported MIME maps to a resource refusal", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, (_req, res) => respond(res, 200, { "content-type": "application/octet-stream" }, secret));
  refusal(await f.reader.fetch(f.url()), "RESOURCE_LIMIT", "UNSUPPORTED_MEDIA");
});

test("giant raster header is bounded without claiming a native decode", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, (_req, res) => respond(res, 200, { "content-type": "image/png" }, png(10001, 2)));
  refusal(await f.reader.fetch(f.url()), "RESOURCE_LIMIT", "RESOURCE_LIMIT");
});

test("declared wire overflow refuses without exposing response bytes", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, (_req, res) => {
    res.writeHead(200, { "content-type": "text/plain", "content-length": 10485761 }); res.flushHeaders();
  });
  refusal(await f.reader.fetch(f.url()), "RESOURCE_LIMIT", "RESOURCE_LIMIT");
});

test("chunked wire overflow refuses the actual streamed response", { timeout: 45000 }, async (t) => {
  const body = Buffer.alloc(10485761, 65);
  const f = await fixture(t, (_req, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.write(body.subarray(0, 1024)); res.end(body.subarray(1024)); });
  refusal(await f.reader.fetch(f.url()), "RESOURCE_LIMIT", "RESOURCE_LIMIT");
});

test("gzip expansion overflow refuses decompressed partial content", { timeout: 45000 }, async (t) => {
  const body = gzipSync(Buffer.alloc(20971521, 65));
  const f = await fixture(t, (_req, res) => respond(res, 200, { "content-type": "text/plain", "content-encoding": "gzip" }, body));
  refusal(await f.reader.fetch(f.url()), "RESOURCE_LIMIT", "RESOURCE_LIMIT");
});

test("one wrapper retains the existing shared thirty-request run quota", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, ok);
  for (let i = 0; i < 30; i++) retrieved(await f.reader.fetch(f.url()));
  refusal(await f.reader.fetch(f.url()), "RESOURCE_LIMIT", "REQUEST_LIMIT");
  refusal(await f.reader.fetchSvgAsset(f.url()), "RESOURCE_LIMIT", "REQUEST_LIMIT");
  assert.equal(f.dials.length, 30);
});

test("pre-canceled request remains cancellation with zero dials", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, ok); const controller = new AbortController(); controller.abort(secret);
  refusal(await f.reader.fetch(f.url(), { signal: controller.signal }), "CANCELED", "CANCELED");
  assert.equal(f.dials.length, 0); retrieved(await f.reader.fetch(f.url()));
});

test("active cancellation closes the actual response and permits recovery", { timeout: 45000 }, async (t) => {
  let opened = false; let closed = false;
  const f = await fixture(t, (req, res) => {
    if (req.url === "/recovery") return ok(req, res);
    res.writeHead(200, { "content-type": "text/plain" }); res.write("partial");
    opened = true; res.once("close", () => { closed = true; });
  });
  const controller = new AbortController();
  const pending = f.reader.fetch(f.url(), { signal: controller.signal });
  await waitFor(() => opened); controller.abort(secret);
  refusal(await pending, "CANCELED", "CANCELED"); await waitFor(() => closed);
  retrieved(await f.reader.fetch(f.url("/recovery"))); assert.equal(f.dials.length, 2);
});

test("queued cancellation shares the original four-slot semaphore and creates no fifth dial", { timeout: 45000 }, async (t) => {
  let opened = 0;
  const f = await fixture(t, (req, res) => {
    if (req.url === "/recovery") return ok(req, res);
    res.writeHead(200, { "content-type": "text/plain" }); res.write("partial"); opened += 1;
  });
  const controllers = Array.from({ length: 4 }, () => new AbortController());
  t.after(() => { for (const c of controllers) c.abort(); });
  const active = controllers.map((c) => f.reader.fetch(f.url(), { signal: c.signal }));
  await waitFor(() => opened === 4);
  const queued = new AbortController();
  const pending = f.reader.fetch(f.url(), { signal: queued.signal }); queued.abort(secret);
  refusal(await pending, "CANCELED", "CANCELED"); assert.equal(f.dials.length, 4);
  for (const c of controllers) c.abort();
  for (const result of await Promise.all(active)) refusal(result, "CANCELED", "CANCELED");
  retrieved(await f.reader.fetch(f.url("/recovery"))); assert.equal(f.dials.length, 5);
});

test("actual default slow-stream deadline closes transport without partial success or renewal", { timeout: 45000 }, async (t) => {
  let opened = false; let closed = false;
  const f = await fixture(t, (req, res) => {
    if (req.url === "/recovery") return ok(req, res);
    res.writeHead(200, { "content-type": "text/plain" }); res.write("partial");
    opened = true;
    const interval = setInterval(() => res.write("."), 100);
    res.once("close", () => { clearInterval(interval); closed = true; });
  });
  const start = performance.now();
  const pending = f.reader.fetch(f.url());
  await waitFor(() => opened);
  refusal(await pending, "RESOURCE_LIMIT", "DEADLINE_EXCEEDED");
  assert.ok(performance.now() - start >= 29000); await waitFor(() => closed);
  retrieved(await f.reader.fetch(f.url("/recovery"))); assert.equal(f.dials.length, 2);
  t.diagnostic("actual native 30000ms slow-stream deadline; no retry; response closed; recovery passed");
});

test("SVG success is the actual single-hop document with its provenance", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, (_req, res) => respond(res, 200, { "content-type": "image/svg+xml" }, svg));
  const doc = retrieved(await f.reader.fetchSvgAsset(f.url()), "image/svg+xml");
  assert.equal(doc.redirects, 0); assert.equal(safeFetchProvenance(doc).mode, "svg-asset"); assert.equal(f.dials.length, 1);
});

test("SVG redirect refuses before any redirected DNS or socket", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, (_req, res) => respond(res, 302, { location: "http://169.254.169.254/" + secret }));
  refusal(await f.reader.fetchSvgAsset(f.url()), "RESOURCE_LIMIT", "REDIRECT_LIMIT");
  assert.equal(f.dials.length, 1);
});

test("SVG deceptive MIME and oversized source are bounded and recover", { timeout: 45000 }, async (t) => {
  const f = await fixture(t, (req, res) => req.url === "/mime"
    ? respond(res, 200, { "content-type": "text/html" }, svg)
    : req.url === "/large" ? respond(res, 200, { "content-type": "image/svg+xml" }, " ".repeat(131073))
    : respond(res, 200, { "content-type": "image/svg+xml" }, svg));
  refusal(await f.reader.fetchSvgAsset(f.url("/mime")), "RESOURCE_LIMIT", "UNSUPPORTED_MEDIA");
  refusal(await f.reader.fetchSvgAsset(f.url("/large")), "RESOURCE_LIMIT", "RESOURCE_LIMIT");
  retrieved(await f.reader.fetchSvgAsset(f.url("/recovery")), "image/svg+xml");
});

test("legacy direct consumer still receives POLICY_DENIED exceptions", { timeout: 45000 }, async (t) => {
  await assert.rejects(new SafeFetcher().fetch("http://127.0.0.1/"), (error) =>
    error instanceof RetrievalError && error.code === "POLICY_DENIED");
  refusal(await createLocalRetrievalOutcomes().fetch("http://127.0.0.1/"), "DESTINATION_BLOCKED", "POLICY_DENIED");
});
