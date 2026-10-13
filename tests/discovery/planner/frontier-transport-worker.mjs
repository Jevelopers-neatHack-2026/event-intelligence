import { access, writeFile } from 'node:fs/promises';
import { createDiscoveryFrontierStore } from '../../../src/discovery/planner/frontier.mjs';

const [directory, runId, leaseToken, attemptKey, url, clockValue, barrierDirectory, tenantLimitsJson] = process.argv.slice(2);
const store = createDiscoveryFrontierStore({
  directory,
  resolveTenant: (request) => request?.principal?.tenantId,
  now: () => Number(clockValue),
  lockTimeoutMs: 10_000,
  ...(tenantLimitsJson ? { tenantLimits: JSON.parse(tenantLimitsJson) } : {}),
});
try {
  await writeFile(`${barrierDirectory}/${attemptKey}.ready`, 'ready', { flag: 'wx' });
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try {
      await access(`${barrierDirectory}/release`);
      break;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }
  if (Date.now() >= deadline) throw new Error('barrier timeout');
  const scope = await store.scopeForAuthenticatedRequest({ principal: { tenantId: 'tenant-a' } });
  const result = await store.admitTransportHop(scope, runId, {
    leaseToken,
    attemptKey,
    kind: 'initial',
    url,
  });
  process.stdout.write(JSON.stringify(result));
} finally {
  store.close();
}
