import { types } from 'node:util';
import { SafeFetcher } from '../../security/controlled-fetch.mjs';
import { withConditionalFetch } from '../../security/internal/conditional-fetch.mjs';
import { runWithSafeFetchLifecycle } from '../../security/internal/fetch-lifecycle.mjs';
import { getPrivateRevalidationPort } from './store.mjs';
import { CacheRevalidationError, createRevalidationContext, dataRecord, revalidationFail } from './revalidation-context.mjs';

export { CacheRevalidationError };

/**
 * Private server composition. `readRetainedSource` is an explicit trusted host
 * evidence/authorization seam, not a canonical adapter or an issuer grant.
 */
export function createPrivateCacheRevalidation(options) {
  const config = dataRecord(options, ['store', 'safeFetcher', 'readRetainedSource', 'timeoutMs']);
  if (!config || types.isProxy(config.safeFetcher) || !(config.safeFetcher instanceof SafeFetcher)
    || typeof config.readRetainedSource !== 'function') revalidationFail('REVALIDATION_INVALID');
  const timeoutMs = config.timeoutMs ?? 10_000;

  async function run(kind, scope, request, input, optionsValue) {
    const options = optionsValue === undefined ? {} : dataRecord(optionsValue, ['signal']);
    if (!options) revalidationFail('REVALIDATION_INVALID');
    const context = createRevalidationContext({
      signal: options.signal, timeoutMs, request, readRetainedSource: config.readRetainedSource,
    });
    let port;
    let prepared;
    let response;
    let dispatchFailure;
    try {
      port = getPrivateRevalidationPort(config.store, context);
      if (kind === 'bind') return await port.bindSource(scope, request, input, context);
      prepared = await port.prepare(scope, request, input, context);
      if (prepared.status !== 'dispatch') return prepared;
      context.check();
      response = await context.wait(runWithSafeFetchLifecycle(config.safeFetcher, {
        onDispatchIntent: async () => {
          try { await port.beforeDispatch(scope, request, prepared.token, context); }
          catch (error) { dispatchFailure = error; throw error; }
        },
      }, { totalMilliseconds: timeoutMs, deadlineAtMonotonic: context.deadlineAtMonotonic }, () => withConditionalFetch(
        config.safeFetcher, prepared.sourceUrl, prepared.validator,
        () => SafeFetcher.prototype.fetch.call(config.safeFetcher, prepared.sourceUrl, { signal: context.signal }),
        prepared.token,
      )));
      context.check();
      return await port.complete(scope, request, prepared.token, response, context);
    } catch (error) {
      context.check();
      if (dispatchFailure) throw dispatchFailure;
      throw error;
    } finally {
      if (prepared?.token) port.dispose(prepared.token);
      // The old representation remains in the host evidence store. This path
      // neither retains new source bodies nor manufactures replacement facts.
      response?.bytes?.fill(0);
      context.close();
    }
  }

  return Object.freeze({
    bindSource: (scope, request, input, options) => run('bind', scope, request, input, options),
    refresh: (scope, request, input, options) => run('refresh', scope, request, input, options),
  });
}
