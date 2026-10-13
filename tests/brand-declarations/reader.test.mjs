import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { createBrandDeclarationReader, BrandDeclarationError, DECLARATION_LIMITS } from '../../src/brand-research/declarations/index.mjs';
import { parseDeclarations } from '../../src/brand-research/declarations/parse.mjs';

// Synthetic source, keys and host decisions. Actual HTML parser + native SQLite.
const EPOCH = Date.parse('2026-10-13T03:00:00Z');
const SOURCE = '<!doctype html><html><head><meta name="theme-color" content="#aBc"></head>'
  + '<body><p>你好🌍</p><div style=" color: #FFcc00; background-color:#012; font-family: \'Demo Sans\', sans-serif ">Event</div></body></html>';
const sha = (v) => createHash('sha256').update(v).digest('hex');
const inputText = (style) => `<!doctype html><div style="${style}"></div>`;
function refuses(code) { return (e) => e instanceof BrandDeclarationError && e.code === code && !e.message.includes('CANARY'); }
const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };

async function fixture(t, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ei-brand-declaration-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const auth = { tenant: 'synthetic-a', allowed: true };
  const state = { now: EPOCH, tenantCalls: 0, onTenant: null, onAuthorize: null, onCurrent: null, onClock: null, key: null };
  const permits = new WeakMap();
  const storeOptions = {
    directory,
    resolveTenant(request) { state.tenantCalls++; state.onTenant?.(request, state.tenantCalls); return request.tenant; },
    resolveKey(input) { if (state.key) return state.key(input); return { keyId: 'synthetic-key-v1', key: createHash('sha256').update(input.tenantId + input.purpose).digest() }; },
    resolveRetention({ tenantId, retentionHandle }) {
      const p = permits.get(retentionHandle); if (!p || p.tenant !== tenantId) throw new Error('CANARY');
      return { expiresAtMs: p.until, policyId: 'synthetic-declaration-test', policyVersion: '1', accessPolicy: 'tenant_private' };
    },
    authorizePrivateAccess(input) { return state.onAuthorize ? state.onAuthorize(input) : input.request.allowed === true && input.request.tenant === input.tenantId; },
    authorizePrivateAccessCurrent(input) { return state.onCurrent ? state.onCurrent(input) : input.request.allowed === true && input.request.tenant === input.tenantId; },
    now: () => { state.onClock?.(); return state.now; },
    maxSourceBytes: 1024 * 1024, maxPositionBytes: 1024 * 1024, maxStoredPayloadBytes: 2 * 1024 * 1024,
    maxPositionCount: 128, maxRetentionMs: 60_000,
  };
  const readerOptions = { evidenceStoreOptions: storeOptions, ...(options.deadlineMs ? { deadlineMs: options.deadlineMs } : {}) };
  const reader = createBrandDeclarationReader(readerOptions);
  async function ingest(raw = SOURCE, extra = {}) {
    const scope = await reader.evidenceStore.scopeForAuthenticatedRequest(auth);
    const retentionHandle = Object.freeze({}); permits.set(retentionHandle, { tenant: auth.tenant, until: EPOCH + 30_000 });
    const bytes = Buffer.from(raw);
    const positions = [];
    for (let startByte = 0; startByte < bytes.length; startByte += 16 * 1024) {
      const endByte = Math.min(bytes.length, startByte + 16 * 1024);
      positions.push({ locator: { kind: 'text-range', startByte, endByte }, content: bytes.subarray(startByte, endByte) });
    }
    const stored = await reader.evidenceStore.ingestEvidence(scope, {
      sourceUrl: 'https://public.example.org/synthetic', content: raw,
      contentType: options.contentType ?? 'text/html; charset=utf-8', retrievedAt: new Date(EPOCH - 1000).toISOString(),
      sourceKind: options.sourceKind ?? 'external', retentionHandle,
      positions, ...extra,
    });
    return stored;
  }
  const stored = await ingest(options.raw ?? SOURCE, options.extra);
  state.tenantCalls = 0;
  return { auth, state, reader, readerOptions, stored, ingest,
    input: () => ({ evidence: stored.evidence, request: auth }) };
}

async function parse(text) {
  return parseDeclarations(Buffer.from(text), 'text/html', { signal: new AbortController().signal,
    check() {}, remainingMs: () => 2500, fail(code) { throw new BrandDeclarationError(code); } });
}

test('actual retained source produces four incomplete declarations with exact multibyte ranges and hashes', async (t) => {
  const f = await fixture(t); const result = await f.reader.read(f.input());
  assert.equal(result.declarations.length, 4);
  assert.deepEqual(result.declarations.map((d) => d.property), ['theme-color', 'color', 'background-color', 'font-family']);
  assert.equal(result.declarations[0].value, '#aabbcc');
  assert.equal(result.declarations[1].value, '#ffcc00');
  assert.deepEqual(result.declarations[3].value, [{ kind: 'declared-name', name: 'Demo Sans' }, { kind: 'generic-family', name: 'sans-serif' }]);
  for (const d of result.declarations) {
    const slice = Buffer.from(SOURCE).subarray(d.locator.startByte, d.locator.endByte);
    assert.equal(slice.toString(), d.rawDeclaration); assert.equal(sha(slice), d.excerptHash);
    assert.ok(d.elementLocator.startByte <= d.locator.startByte && d.elementLocator.endByte >= d.locator.endByte);
    assert.ok(Buffer.from(SOURCE).subarray(d.elementLocator.startByte, d.elementLocator.endByte).toString().startsWith(`<${d.tagName}`));
    assert.ok(Object.isFrozen(d));
  }
  assert.equal(result.source.contentHash, sha(SOURCE)); assert.equal(result.source.evidenceId, f.stored.metadata.evidenceId);
  assert.equal(result.visibility, 'tenant_private'); assert.equal(result.permission, 'unknown');
  assert.equal(result.officialBrand, 'unknown'); assert.equal(result.renderedAppearance, 'not_evaluated');
  assert.equal(result.completeness, 'incomplete-supported-subset'); assert.equal(result.canonicalAdoption, false);
  assert.equal(result.dispatchStatus, 'not_dispatched'); assert.ok(Object.isFrozen(result.declarations));
  assert.equal(JSON.stringify(result).includes('tenantId'), false);
});

test('same retained source read is deterministic and later caller input mutation cannot replace it', async (t) => {
  const f = await fixture(t); const bytes = Buffer.from(SOURCE); const stored = await f.ingest(bytes);
  bytes.fill(65);
  const a = await f.reader.read({ ...f.input(), evidence: stored.evidence });
  const b = await f.reader.read({ ...f.input(), evidence: stored.evidence });
  assert.deepEqual(a, b); assert.equal(a.source.contentHash, sha(SOURCE));
});

test('new adapter reopens durable source with current host scope; copied handles refuse', async (t) => {
  const f = await fixture(t); const other = createBrandDeclarationReader(f.readerOptions);
  // EvidenceStore brands are shared across genuine instances. A genuine handle
  // is a reference, not authorization; the second store still reopens/rechecks.
  assert.equal((await other.read(f.input())).declarations.length, 4);
  await assert.rejects(other.read({ ...f.input(), evidence: { ...f.stored.evidence } }), refuses('EVIDENCE_DENIED'));
  const scope = await other.evidenceStore.scopeForAuthenticatedRequest(f.auth);
  const evidence = await other.evidenceStore.lookupEvidence(scope, f.stored.metadata.evidenceId);
  assert.equal((await other.read({ evidence, request: f.auth })).declarations.length, 4);
});

test('other tenant, forged handle and denied current ACL refuse; source can recover under valid authority', async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.reader.read({ ...f.input(), request: { tenant: 'synthetic-b', allowed: true } }), refuses('EVIDENCE_DENIED'));
  await assert.rejects(f.reader.read({ ...f.input(), evidence: {} }), refuses('EVIDENCE_DENIED'));
  f.auth.allowed = false; await assert.rejects(f.reader.read(f.input()), refuses('EVIDENCE_DENIED'));
  f.auth.allowed = true; assert.equal((await f.reader.read(f.input())).declarations.length, 4);
});

test('ordinary private-payload calls cannot reach the owned consumer', async (t) => {
  const f = await fixture(t); const scope = await f.reader.evidenceStore.scopeForAuthenticatedRequest(f.auth);
  await assert.rejects(f.reader.evidenceStore.withPrivatePayload(scope, f.stored.evidence, f.auth));
  assert.equal((await f.reader.read(f.input())).declarations.length, 4);
});

test('customer source origin is preserved without gaining official status', async (t) => {
  const f = await fixture(t, { sourceKind: 'customer_supplied' }); const r = await f.reader.read(f.input());
  assert.equal(r.source.sourceKind, 'customer_supplied'); assert.equal(r.officialBrand, 'unknown');
});

for (const type of ['text/plain', 'application/xhtml+xml', 'image/svg+xml', 'text/html; charset=iso-8859-1']) {
  test(`unsupported retained MIME/encoding refuses: ${type}`, async (t) => {
    const f = await fixture(t, { contentType: type }); await assert.rejects(f.reader.read(f.input()), refuses('UNSUPPORTED_SOURCE'));
  });
}
test('an excerpt is not accepted as a complete original document', async (t) => {
  const f = await fixture(t, { extra: { positions: [{ locator: { kind: 'text-range', startByte: 1, endByte: 11 }, content: SOURCE.slice(1, 11) }] } });
  await assert.rejects(f.reader.read(f.input()), refuses('SOURCE_INCOMPLETE'));
});
test('expired retained source refuses', async (t) => {
  const f = await fixture(t); f.state.now += 30_001;
  await assert.rejects(f.reader.read(f.input()), refuses('EVIDENCE_EXPIRED'));
});
for (const mode of ['expiry', 'revocation', 'tenant-change']) {
  test(`final reopen prevents release after ${mode}`, async (t) => {
    const f = await fixture(t); f.state.onTenant = (_, calls) => { if (calls === 2) {
      if (mode === 'expiry') f.state.now += 30_001;
      else if (mode === 'revocation') f.auth.allowed = false;
      else f.auth.tenant = 'synthetic-b';
    } };
    await assert.rejects(f.reader.read(f.input()), refuses(mode === 'expiry' ? 'EVIDENCE_EXPIRED' : 'EVIDENCE_DENIED'));
  });
}
test('preabort refuses before source work and following operation recovers', async (t) => {
  const f = await fixture(t); const c = new AbortController(); c.abort();
  await assert.rejects(f.reader.read({ ...f.input(), signal: c.signal }), refuses('CANCELED'));
  assert.equal(f.state.tenantCalls, 0); assert.equal((await f.reader.read(f.input())).declarations.length, 4);
});
test('pending source authorization can cancel; late callback is inert and a new read recovers', async (t) => {
  const f = await fixture(t); const gate = deferred(); const entered = deferred();
  f.state.onAuthorize = () => { entered.resolve(); return gate.promise; };
  const c = new AbortController(); const pending = f.reader.read({ ...f.input(), signal: c.signal });
  await entered.promise; await assert.rejects(f.reader.read(f.input()), refuses('BUSY'));
  c.abort(); await assert.rejects(pending, refuses('CANCELED'));
  await assert.rejects(f.reader.read(f.input()), refuses('BUSY'));
  gate.resolve(true);
  f.state.onAuthorize = null;
  // Await observed underlying completion via the subsequent read, not a claim
  // that cancellation itself settled a trusted host's unresolved promise.
  for (let i = 0; i < 100; i++) {
    try { const r = await f.reader.read(f.input()); assert.equal(r.declarations.length, 4); return; }
    catch (e) { if (e.code !== 'BUSY') throw e; await new Promise((r) => setImmediate(r)); }
  }
  assert.fail('held operation did not settle');
});
test('real elapsed source wait exhausts original budget and subsequent read recovers', async (t) => {
  const f = await fixture(t, { deadlineMs: 80 }); const gate = deferred();
  f.state.onAuthorize = () => gate.promise;
  const start = performance.now(); await assert.rejects(f.reader.read(f.input()), refuses('DEADLINE_EXCEEDED'));
  assert.ok(performance.now() - start < 1000);
  await assert.rejects(f.reader.read(f.input()), refuses('BUSY'));
  gate.resolve(true); f.state.onAuthorize = null;
  for (let i = 0; i < 100; i++) {
    try { assert.equal((await f.reader.read(f.input())).declarations.length, 4); return; }
    catch (e) { if (e.code !== 'BUSY') throw e; await new Promise((r) => setImmediate(r)); }
  }
  assert.fail('held operation did not settle');
});
test('slow synchronous final host callback cannot return declarations after the original deadline', async (t) => {
  const f = await fixture(t, { deadlineMs: 100 });
  f.state.onTenant = (_, calls) => { if (calls === 2) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 130); };
  await assert.rejects(f.reader.read(f.input()), refuses('DEADLINE_EXCEEDED'));
});

const unsupportedStyles = [
  ['color: red', 'UNSUPPORTED_VALUE'], ['color: rgb(1,2,3)', 'COMPLEX_STYLE_UNSUPPORTED'],
  ['color:var(--x)', 'COMPLEX_STYLE_UNSUPPORTED'], ['color:#fff!important', 'COMPLEX_STYLE_UNSUPPORTED'],
  ['color:#fff;COLOR:#000', 'DUPLICATE_DECLARATION'], ['font-family:Demo Sans', 'UNSUPPORTED_VALUE'],
  ["font-family:'Demo; color:#fff; Family'", 'COMPLEX_STYLE_UNSUPPORTED'],
  ["unrelated:'x; color:#fff; end'", 'COMPLEX_STYLE_UNSUPPORTED'],
  ['font-family: url(https://canary.example.org/font)', 'COMPLEX_STYLE_UNSUPPORTED'],
  ['color:#fff;broken', 'MALFORMED_STYLE'], ['color:#fffg00', 'UNSUPPORTED_VALUE'],
  ['color:#ffffffff', 'UNSUPPORTED_VALUE'], ["font-family:'Demo\\20Sans'", 'COMPLEX_STYLE_UNSUPPORTED'],
  ['color:#fff/*comment*/', 'COMPLEX_STYLE_UNSUPPORTED'], ["font-family:'unterminated", 'COMPLEX_STYLE_UNSUPPORTED'],
];
for (const [style, code] of unsupportedStyles) test(`unsupported grammar has no declaration: ${style}`, async () => {
  const r = await parse(inputText(style)); assert.equal(r.declarations.length, 0); assert.equal(r.unsupported[0].code, code);
});
test('entity-decoded attribute never receives an invented exact raw range', async () => {
  const r = await parse('<div style="color: &#35;abc"></div>');
  assert.equal(r.declarations.length, 0); assert.equal(r.unsupported[0].code, 'RAW_ATTRIBUTE_UNSUPPORTED');
});
test('duplicate attributes refuse instead of accepting parse5 first value', async () => {
  await assert.rejects(parse('<div style="color:#abc" STYLE="color:#000"></div>'), refuses('MALFORMED_HTML'));
});
test('foreign SVG, scripts and template content do not become HTML declarations', async () => {
  const r = await parse('<svg style="color:#fff"></svg><script>style="color:#fff"</script><template><div style="color:#fff"></div></template>');
  assert.equal(r.declarations.length, 0);
});
test('stylesheet and font requests are not followed; no global fetch is invoked', async (t) => {
  const f = await fixture(t, { raw: '<link rel="stylesheet" href="https://canary.example.org/a.css"><style>@font-face{src:url(https://canary.example.org/f)}</style><div style="color:#abc"></div>' });
  const original = globalThis.fetch; let calls = 0;
  globalThis.fetch = () => { calls++; throw new Error('CANARY'); };
  try { const r = await f.reader.read(f.input()); assert.equal(r.declarations.length, 1); assert.equal(r.unsupported.length, 2); assert.equal(calls, 0); }
  finally { globalThis.fetch = original; }
});
test('repeated separate declarations retain both sources without selecting an official brand', async () => {
  const r = await parse('<div style="color:#abc"></div><div style="color:#def"></div>');
  assert.equal(r.declarations.length, 2); assert.notDeepEqual(r.declarations[0].locator, r.declarations[1].locator);
});
test('no relevant declaration returns explicit empty supported subset', async (t) => {
  const f = await fixture(t, { raw: '<p>No style data</p>' }); const r = await f.reader.read(f.input());
  assert.equal(r.status, 'no_supported_declarations'); assert.equal(r.completeness, 'incomplete-supported-subset');
});
test('observation overflow rejects whole operation without a successful prefix', async () => {
  await assert.rejects(parse('<div style="color:#abc"></div>'.repeat(65)), refuses('RESOURCE_LIMIT'));
});
test('attribute overflow rejects even when a valid declaration appears before the over-limit suffix', async () => {
  await assert.rejects(parse(inputText('color:#abc;' + ' '.repeat(4096))), refuses('RESOURCE_LIMIT'));
});
test('node overflow rejects whole parse result', async () => {
  await assert.rejects(parse('<span></span>'.repeat(20_001)), refuses('RESOURCE_LIMIT'));
});
test('source bound retains prior store refusal honestly', async (t) => {
  const f = await fixture(t, { raw: 'x'.repeat(DECLARATION_LIMITS.sourceBytes + 1) });
  const scope = await f.reader.evidenceStore.scopeForAuthenticatedRequest(f.auth);
  await assert.rejects(f.reader.evidenceStore.withPrivatePayload(scope, f.stored.evidence, f.auth), (e) => e.code === 'EVIDENCE_INVALID');
  await assert.rejects(f.reader.read(f.input()), refuses('EVIDENCE_UNAVAILABLE'));
});
test('invalid/accessor/proxy configuration is refused without getters or traps', () => {
  let calls = 0;
  assert.throws(() => createBrandDeclarationReader({ get evidenceStoreOptions() { calls++; return {}; } }), refuses('INVALID_INPUT'));
  assert.throws(() => createBrandDeclarationReader(new Proxy({}, { getPrototypeOf() { calls++; return null; } })), refuses('INVALID_INPUT'));
  assert.equal(calls, 0);
});
test('invalid read descriptors refuse without getters and permit recovery', async (t) => {
  const f = await fixture(t); let calls = 0;
  await assert.rejects(f.reader.read({ get evidence() { calls++; return f.stored.evidence; }, request: f.auth }), refuses('INVALID_INPUT'));
  assert.equal(calls, 0); assert.equal((await f.reader.read(f.input())).declarations.length, 4);
});

test('non-ASCII whitespace is not silently normalized into a supported CSS generic', async () => {
  const r = await parse(inputText('font-family:\u00a0serif'));
  assert.equal(r.declarations.length, 0); assert.equal(r.unsupported[0].code, 'UNSUPPORTED_VALUE');
});
test('CR-normalized attribute and entity-encoded meta name produce explicit unsupported observations', async () => {
  const r = await parse('<meta name="th&#101;me-color" content="#abc"><div style="color:\r\n#abc"></div>');
  assert.equal(r.declarations.length, 0); assert.equal(r.unsupported.length, 2);
  assert.ok(r.unsupported.every((v) => v.code === 'RAW_ATTRIBUTE_UNSUPPORTED'));
});
test('unsupported HTML charset declaration cannot relabel retained bytes', async () => {
  await assert.rejects(parse('<meta charset="windows-1252"><div style="color:#abc"></div>'), refuses('UNSUPPORTED_SOURCE'));
});
test('maximum64 declarations are retained with no prefix loss at the inclusive bound', async () => {
  const r = await parse('<div style="color:#abc"></div>'.repeat(64)); assert.equal(r.declarations.length, 64);
});
test('serialized output cap refuses all large but individually supported declarations', async (t) => {
  const font = Array.from({ length: 8 }, (_, i) => `'Synthetic Family ${i}'`).join(',');
  const f = await fixture(t, { raw: inputText(`font-family:${font}`).repeat(64) });
  await assert.rejects(f.reader.read(f.input()), refuses('RESOURCE_LIMIT'));
});
test('changed key during final reopen refuses without returning a prefix', async (t) => {
  const f = await fixture(t); f.state.onTenant = (_, calls) => { if (calls === 2) f.state.key = () => { throw new Error('CANARY'); }; };
  await assert.rejects(f.reader.read(f.input()), refuses('EVIDENCE_UNAVAILABLE'));
});
test('cancellation delivered during actual chunked parsing refuses and recovers after settlement', async (t) => {
  const raw = '<div style="color:#abc"></div>' + '<span>x</span>'.repeat(5000);
  const f = await fixture(t, { raw }); const c = new AbortController();
  // Explicit synthetic phase instrumentation: retain native scheduling, observe
  // the actual HTML parser's first yield and deliver cancellation at that phase.
  const original = globalThis.setImmediate; let parserEntered = false;
  globalThis.setImmediate = (callback, ...args) => {
    if (new Error().stack.includes('/src/extraction/html.mjs:')) { parserEntered = true; c.abort(); }
    return original(callback, ...args);
  };
  try { await assert.rejects(f.reader.read({ ...f.input(), signal: c.signal }), refuses('CANCELED')); }
  finally { globalThis.setImmediate = original; }
  assert.equal(parserEntered, true);
  for (let i = 0; i < 100; i++) {
    try { const r = await f.reader.read(f.input()); assert.equal(r.declarations.length, 1); return; }
    catch (e) { if (e.code !== 'BUSY') throw e; await new Promise((r) => setImmediate(r)); }
  }
  assert.fail('canceled parser did not settle');
});
test('ordinary rejected synchronous authority result stays observed and denies', async (t) => {
  const f = await fixture(t); f.state.onCurrent = () => Promise.reject(new Error('CANARY'));
  await assert.rejects(f.reader.read(f.input()), refuses('EVIDENCE_DENIED'));
  await new Promise((r) => setImmediate(r)); f.state.onCurrent = null;
  assert.equal((await f.reader.read(f.input())).declarations.length, 4);
});
