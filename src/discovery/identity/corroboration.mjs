import { createHash } from 'node:crypto';
import { types } from 'node:util';

export const CORROBORATION_SCHEMA = 'ei-source-corroboration-internal/v1';
export const CORROBORATION_POLICY = 'explicit-source-declaration/v1';
const MAX_BYTES = 65_536;
const MAX_NODES = 23;
const MAX_CLAIMS = 128;
const HASH = /^[a-f0-9]{64}$/;
const REF = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/;
const JSON_POINTER = /^(?:\/(?:[^~/]|~[01])*)*$/;

export class CorroborationError extends Error {
  constructor(code = 'INVALID') { super('Invalid or over-limit private corroboration data'); this.code = code; }
}
function fail(code) { throw new CorroborationError(code); }

export function stableCorroborationJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableCorroborationJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableCorroborationJson(value[key])}`).join(',')}}`;
}
export function corroborationDigest(domain, value) {
  return createHash('sha256').update(`event-intelligence:${domain}:v1\0`).update(stableCorroborationJson(value)).digest('hex');
}

// This is URL matching within the retained input set, never permission to fetch.
// Entity fragments, credentials and query-dependent references need a different
// explicit policy. Do not silently strip them or resolve relative references.
export function normalizedAttributionUrl(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 2048
    || /[\s\u0000-\u001f\u007f]/u.test(value) || !value.isWellFormed()) return null;
  try {
    const url = new URL(value);
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) return null;
    return url.href;
  } catch { return null; }
}

function snapshot(value, budget, depth = 0) {
  if (++budget.nodes > 12_000 || depth > 16) fail('LIMIT');
  if (typeof value === 'string') {
    budget.bytes += Buffer.byteLength(value, 'utf8');
    if (budget.bytes > MAX_BYTES || value.length > 4096 || !value.isWellFormed()) fail('LIMIT');
    return value;
  }
  if (value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return value;
  if (typeof value !== 'object' || types.isProxy(value)) fail();
  const array = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) fail();
  const keys = Reflect.ownKeys(value);
  if (keys.length > 257) fail('LIMIT');
  const out = array ? [] : Object.create(null);
  if (array) {
    const length = Object.getOwnPropertyDescriptor(value, 'length')?.value;
    if (!Number.isSafeInteger(length) || length > 256 || keys.length !== length + 1) fail('LIMIT');
    for (let index = 0; index < length; index += 1) {
      const d = Object.getOwnPropertyDescriptor(value, String(index));
      if (!d?.enumerable || !Object.hasOwn(d, 'value')) fail();
      out.push(snapshot(d.value, budget, depth + 1));
    }
  } else {
    for (const key of keys) {
      if (typeof key !== 'string' || key.length > 80) fail();
      const d = Object.getOwnPropertyDescriptor(value, key);
      if (!d?.enumerable || !Object.hasOwn(d, 'value')) fail();
      out[key] = snapshot(d.value, budget, depth + 1);
    }
  }
  return out;
}

function exact(value, fields) {
  if (!value || Array.isArray(value) || typeof value !== 'object'
    || Object.keys(value).length !== fields.length || fields.some((key) => !Object.hasOwn(value, key))) fail();
}
function orderedUnique(values, maximum, predicate) {
  if (!Array.isArray(values) || values.length > maximum || values.some((v) => !predicate(v))) fail();
  if (new Set(values).size !== values.length) fail();
  return [...values].sort();
}
function freeze(value) {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}

/** Pure EI-private policy; a declaration only reduces presumed independence. */
export function buildSourceCorroboration(rawNodes, rawClaims) {
  const { nodes, claims } = snapshot({ nodes: rawNodes, claims: rawClaims }, { nodes: 0, bytes: 0 });
  if (!Array.isArray(nodes) || nodes.length > MAX_NODES || !Array.isArray(claims) || claims.length > MAX_CLAIMS) fail('LIMIT');
  const byId = new Map();
  for (const node of nodes) {
    exact(node, ['candidateId', 'kind', 'entityKey', 'entityPointer', 'sourceEntityCount', 'evidenceId', 'contentHash', 'sourceUrls', 'identityKeys']);
    const match = /^(event|organization):script-(0|[1-9]\d*):(0|[1-9]\d*)$/.exec(node.entityKey);
    if (!match || match[1] !== node.kind || typeof node.evidenceId !== 'string' || !REF.test(node.evidenceId)
      || !HASH.test(node.contentHash) || typeof node.entityPointer !== 'string'
      || !JSON_POINTER.test(node.entityPointer)
      || !Number.isInteger(node.sourceEntityCount) || node.sourceEntityCount < 1 || node.sourceEntityCount > 24) fail();
    const prefix = node.kind === 'event' ? 'event' : 'org';
    if (node.candidateId !== `${prefix}-${node.evidenceId.replaceAll('-', '')}-${match[2]}-${match[3]}` || byId.has(node.candidateId)) fail();
    node.sourceUrls = orderedUnique(node.sourceUrls, 2, (url) => normalizedAttributionUrl(url) === url);
    node.identityKeys = orderedUnique(node.identityKeys, 128, (key) => typeof key === 'string' && HASH.test(key));
    if (node.identityKeys.length === 0) fail();
    byId.set(node.candidateId, node);
  }
  nodes.sort((a, b) => a.candidateId < b.candidateId ? -1 : a.candidateId > b.candidateId ? 1 : 0);
  const seenClaims = new Set();
  for (const claim of claims) {
    exact(claim, ['candidateId', 'form', 'status', 'targetUrl', 'sourceRef', 'factKey']);
    const node = byId.get(claim.candidateId);
    if (!node || !['direct_string', 'unsupported_shape', 'unsupported_value'].includes(claim.form)
      || !['retained', 'legacy_position_unavailable', 'unsupported'].includes(claim.status)) fail();
    exact(claim.sourceRef, ['evidenceId', 'contentHash', 'locator', 'positionHash', 'jsonPointer']);
    const ref = claim.sourceRef;
    exact(ref.locator, ['kind', 'startByte', 'endByte']);
    if (ref.evidenceId !== node.evidenceId || ref.contentHash !== node.contentHash || !HASH.test(ref.positionHash)
      || ref.locator.kind !== 'text-range' || !Number.isSafeInteger(ref.locator.startByte) || ref.locator.startByte < 0
      || !Number.isSafeInteger(ref.locator.endByte) || ref.locator.endByte <= ref.locator.startByte || ref.locator.endByte > 524288
      || typeof ref.jsonPointer !== 'string' || !JSON_POINTER.test(ref.jsonPointer)
      || !(ref.jsonPointer === `${node.entityPointer}/isBasedOn` || ref.jsonPointer.startsWith(`${node.entityPointer}/isBasedOn/`))) fail();
    if (claim.form === 'direct_string' && (ref.jsonPointer !== `${node.entityPointer}/isBasedOn`
      || normalizedAttributionUrl(claim.targetUrl) !== claim.targetUrl || claim.targetUrl === null)) fail();
    if (claim.form !== 'direct_string' && (claim.targetUrl !== null || claim.status !== 'unsupported' || claim.factKey !== null)) fail();
    if (claim.form === 'direct_string' && claim.status === 'unsupported') fail();
    if (claim.status === 'retained') {
      if (claim.form !== 'direct_string' || claim.factKey !== corroborationDigest('source-attribution-fact', {
        sourceRef: claim.sourceRef, targetUrl: claim.targetUrl,
      })) fail();
    } else if (claim.factKey !== null) fail();
    const key = `${claim.candidateId}:${ref.jsonPointer}:${ref.locator.startByte}:${ref.locator.endByte}`;
    if (seenClaims.has(key)) fail();
    seenClaims.add(key);
    claim.claimId = corroborationDigest('source-declaration', claim);
  }
  claims.sort((a, b) => a.claimId < b.claimId ? -1 : a.claimId > b.claimId ? 1 : 0);
  const parent = new Map(nodes.map((node) => [node.candidateId, node.candidateId]));
  const root = (id) => { while (parent.get(id) !== id) id = parent.get(id); return id; };
  const join = (left, right) => { const a = root(left), b = root(right); if (a !== b) parent.set(a < b ? b : a, a < b ? a : b); };
  const edges = [];
  for (let i = 0; i < nodes.length; i += 1) for (let j = i + 1; j < nodes.length; j += 1) {
    const a = nodes[i], b = nodes[j];
    if (a.contentHash === b.contentHash && a.kind === b.kind && a.entityKey === b.entityKey && a.entityPointer === b.entityPointer) {
      join(a.candidateId, b.candidateId);
      edges.push({ basis: 'exact_content', from: a.candidateId, to: b.candidateId, claimId: null });
    }
  }
  const unresolved = [];
  for (const claim of claims) {
    if (claim.status !== 'retained') { unresolved.push({ claimId: claim.claimId, reason: claim.status }); continue; }
    const source = byId.get(claim.candidateId);
    const matches = nodes.filter((node) => node.kind === source.kind && node.sourceUrls.includes(claim.targetUrl));
    let reason = null;
    if (matches.length === 0) reason = 'target_not_retained';
    else if (matches.length !== 1 || matches[0].sourceEntityCount !== 1) reason = 'target_ambiguous';
    else if (matches[0].candidateId === source.candidateId) reason = 'self_reference';
    if (reason) { unresolved.push({ claimId: claim.claimId, reason }); continue; }
    join(source.candidateId, matches[0].candidateId);
    edges.push({ basis: 'source_declared_derivation', from: source.candidateId, to: matches[0].candidateId, claimId: claim.claimId });
  }
  if (edges.length > 256) fail('LIMIT');
  edges.sort((a, b) => stableCorroborationJson(a) < stableCorroborationJson(b) ? -1 : 1);
  const groups = new Map();
  for (const node of nodes) { const id = root(node.candidateId); const members = groups.get(id) ?? []; members.push(node.candidateId); groups.set(id, members); }
  const clusters = [...groups.values()].map((members) => ({
    clusterId: corroborationDigest('source-dependence-cluster', members), members,
    independence: 'unknown', origin: 'not_established',
  })).sort((a, b) => a.clusterId < b.clusterId ? -1 : 1);
  const core = {
    schema: CORROBORATION_SCHEMA, policy: CORROBORATION_POLICY,
    method: { name: 'retained-source-declaration', version: '1' },
    sourceAuthority: 'not_evaluated', independence: 'unknown', nodes, claims, edges, clusters, unresolved,
    limits: { maxNodes: MAX_NODES, maxClaims: MAX_CLAIMS, maxEdges: 256, maxUtf8Bytes: MAX_BYTES },
  };
  const result = { ...core, digest: corroborationDigest('source-corroboration', core) };
  if (Buffer.byteLength(stableCorroborationJson(result), 'utf8') > MAX_BYTES) fail('LIMIT');
  return freeze(result);
}

/** Validate the whole policy result, including a rehashed but invented edge. */
export function validateSourceCorroboration(value) {
  const graph = snapshot(value, { nodes: 0, bytes: 0 });
  exact(graph, ['schema', 'policy', 'method', 'sourceAuthority', 'independence', 'nodes', 'claims', 'edges', 'clusters', 'unresolved', 'limits', 'digest']);
  if (!Array.isArray(graph.claims)) fail();
  const claims = graph.claims.map((claim) => { const { claimId: ignored, ...core } = claim; if (!HASH.test(ignored)) fail(); return core; });
  const recomputed = buildSourceCorroboration(graph.nodes, claims);
  if (stableCorroborationJson(graph) !== stableCorroborationJson(recomputed)) fail();
  return recomputed;
}
