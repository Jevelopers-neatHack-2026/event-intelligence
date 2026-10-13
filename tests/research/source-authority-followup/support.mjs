import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createEvidenceStore } from '../../../src/evidence/store.mjs';
import { createDiscoveryFrontierStore } from '../../../src/discovery/planner/frontier.mjs';
import { createPrivateAssetReleaseAuthority, runPrivateRetrieval } from '../../../src/research/private-retrieval.mjs';
import { SafeFetcher } from '../../../src/security/controlled-fetch.mjs';
import { fixtureUrl, localTestSeam, respond, startFixture } from '../../security/support.mjs';

export const TENANT = 'synthetic-authority-review-tenant';
const HOST = 'followup.example.org';
export const sourceUrl = (pathname = '/') => fixtureUrl(80, pathname, HOST);

export function eventHtml({ name = 'Synthetic Follow-up Event', date = '2027-06-20', city = 'Boston', asset = false } = {}) {
  return Buffer.from(`<!doctype html>${asset ? '<meta property="og:image" content="/poster.svg">' : ''}`
    + `<script type="application/ld+json">${JSON.stringify({
      '@type': 'Event', name, startDate: date,
      location: { name: 'Synthetic Hall', address: { addressLocality: city } },
    })}</script>`);
}

export function wrapStore(store, overrides) {
  const copy = Object.create(null);
  for (const [name, method] of Object.entries(store)) {
    if (typeof method === 'function') copy[name] = method.bind(store);
  }
  return Object.assign(copy, overrides);
}

export async function harness(t, options = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ei-source-authority-'));
  const permitted = new WeakMap();
  let acl = true;
  let hostAuthority = true;
  let keyAvailable = true;
  const request = { principal: { tenantId: TENANT }, allowPrivate: true };
  const retention = (expiresAtMs = Date.now() + 120_000) => {
    const handle = Object.freeze(Object.create(null));
    permitted.set(handle, { tenantId: TENANT, expiresAtMs });
    return handle;
  };
  const config = {
    directory: path.join(root, 'evidence'),
    resolveTenant: (authenticated) => authenticated?.principal?.tenantId,
    resolveKey({ tenantId, purpose, keyId }) {
      if (!keyAvailable) throw new Error('synthetic key unavailable');
      const selected = `${purpose}-synthetic-v1`;
      if (keyId && keyId !== selected) throw new Error('synthetic key denied');
      return { keyId: selected, key: createHash('sha256').update(`${tenantId}:${purpose}:followup-fixture`).digest() };
    },
    resolveRetention({ tenantId, kind, nowMs, sourceExpiresAtMs, retentionHandle }) {
      if (kind === 'evidence') {
        const stored = permitted.get(retentionHandle);
        if (!stored || stored.tenantId !== tenantId) throw new Error('synthetic retention denied');
        return { expiresAtMs: stored.expiresAtMs, policyId: 'synthetic-followup', policyVersion: '1', accessPolicy: 'tenant_private' };
      }
      return {
        expiresAtMs: sourceExpiresAtMs ?? nowMs + 60_000,
        policyId: 'synthetic-followup', policyVersion: '1', accessPolicy: 'tenant_private',
      };
    },
    authorizePrivateAccess: ({ tenantId, request: authenticated }) => acl
      && authenticated?.principal?.tenantId === tenantId && authenticated.allowPrivate === true,
    authorizePrivateAccessCurrent: ({ tenantId, request: authenticated }) => acl
      && authenticated?.principal?.tenantId === tenantId && authenticated.allowPrivate === true,
    maxSourceBytes: 2 * 1024 * 1024,
    maxPositionBytes: 64 * 1024,
    maxPositionCount: 128,
    maxStoredPayloadBytes: 512 * 1024,
    maxRetentionMs: 180_000,
    ...options.evidenceOptions,
  };
  const evidenceStore = createEvidenceStore(config);
  const frontierStores = [];
  const openFrontier = () => {
    const store = createDiscoveryFrontierStore({
      directory: path.join(root, 'frontier'),
      resolveTenant: (authenticated) => authenticated?.principal?.tenantId,
      lockTimeoutMs: 2_000,
    });
    frontierStores.push(store);
    return store;
  };
  const frontier = openFrontier();
  const scope = await frontier.scopeForAuthenticatedRequest(request);
  const paths = [];
  const controllers = [];
  const server = await startFixture((incoming, response) => {
    paths.push(incoming.url);
    if (options.respond) return options.respond(incoming, response);
    return respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, eventHtml());
  });
  t.after(async () => {
    await server.close();
    for (const store of frontierStores) store.close();
    await rm(root, { recursive: true, force: true });
  });
  const input = (runId, overrides = {}) => {
    const { controlled = false, ...rest } = overrides;
    const policy = { schemaVersion: 1, policyVersion: 'ei-private-svg-acquisition/1', policyId: 'synthetic-followup-v1',
      allowedOrigins: [new URL(sourceUrl()).origin] };
    return {
      frontier, evidenceStore, request, runId,
      safeFetcher: new SafeFetcher(localTestSeam({ port: 80, dialPort: server.port, hostnames: [HOST] })),
      seeds: [{ url: sourceUrl('/event') }],
      limits: { maxDepth: 0, maxTransportAttemptAdmissions: 8, durationMs: 10_000 },
      retentionHandleFor: () => retention(),
      authorizeCurrent: () => hostAuthority,
      ...(controlled ? {
        assetAcquisitionPolicyFor: () => policy,
        assetAcquisitionReleaseAuthorityFor: (_request, context) => {
          const controller = createPrivateAssetReleaseAuthority({
            tenantId: TENANT, runId: context.runId, policy: context.policy,
            expiresAtMonotonic: context.deadlineAtMonotonic,
          });
          controllers.push(controller);
          return controller;
        },
      } : {}),
      ...rest,
    };
  };
  return {
    root, config, request, frontier, scope, evidenceStore, paths, controllers, input,
    run: (runId, overrides) => runPrivateRetrieval(input(runId, overrides)),
    openFrontier, reopenEvidence: () => createEvidenceStore(config), retention,
    setAcl: (value) => { acl = value; },
    setHostAuthority: (value) => { hostAuthority = value; },
    setKeyAvailable: (value) => { keyAvailable = value; },
    evidenceDatabase: path.join(config.directory,
      createHash('sha256').update(`event-intelligence:tenant:v1:${TENANT}`).digest('hex'), 'evidence.sqlite'),
  };
}

export { respond };
