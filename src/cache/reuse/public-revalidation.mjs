import { types } from 'node:util';
import { SafeFetcher } from '../../security/controlled-fetch.mjs';
import { withConditionalFetch } from '../../security/internal/conditional-fetch.mjs';
import { runWithSafeFetchLifecycle } from '../../security/internal/fetch-lifecycle.mjs';
import { getReviewedPublicRevalidationPort } from './store.mjs';
import { CacheRevalidationError, createRevalidationContext, dataRecord, revalidationFail } from './revalidation-context.mjs';

export { CacheRevalidationError };

const MAPPING_FIELDS = Object.freeze([
  'schema', 'publicationLinkId', 'sourceRecordId', 'profileRef', 'profileVersion',
  'profileContentHash', 'profileHashDomain', 'sourceRef', 'evidenceId', 'evidenceVersion',
  'originalBodyHash', 'bodyHashDomain',
]);

/** Private host composition for one reviewed publication and one original
 * source. Publication/read permission is never freshness mutation authority. */
export function createReviewedPublicCacheRevalidation(options) {
  const config = dataRecord(options, ['store', 'safeFetcher', 'readRetainedPublicSource', 'timeoutMs']);
  if (!config || types.isProxy(config.safeFetcher) || !(config.safeFetcher instanceof SafeFetcher)
    || typeof config.readRetainedPublicSource !== 'function' || types.isProxy(config.readRetainedPublicSource)) {
    revalidationFail('REVALIDATION_INVALID');
  }
  const timeoutMs = config.timeoutMs ?? 10_000;
  const readRetainedSource = async (input, onRevoked) => {
    const retained = dataRecord(await config.readRetainedPublicSource(input),
      ['binding', 'mapping', 'representation', 'bytes', 'validUntilMs', 'status']);
    const mapping = retained && dataRecord(retained.mapping, MAPPING_FIELDS);
    if (!mapping || mapping.schema !== 'ei-reviewed-public-source-mapping/v1'
      || MAPPING_FIELDS.some((field) => field !== 'schema' && mapping[field] !== input.binding[field])) {
      revalidationFail('REVALIDATION_PROVENANCE');
    }
    if (retained.status === 'source_access_revoked' && retained.binding === input.binding
      && !Object.hasOwn(retained, 'bytes') && !Object.hasOwn(retained, 'representation') && !Object.hasOwn(retained, 'validUntilMs')) {
      await onRevoked();
      revalidationFail('REVALIDATION_DENIED');
    }
    if (retained.status !== undefined) revalidationFail('REVALIDATION_PROVENANCE');
    return { binding: retained.binding, representation: retained.representation,
      bytes: retained.bytes, validUntilMs: retained.validUntilMs };
  };

  async function run(kind, scope, request, input, optionsValue) {
    const options = optionsValue === undefined ? {} : dataRecord(optionsValue, ['signal']);
    if (!options) revalidationFail('REVALIDATION_INVALID');
    let port;
    const context = createRevalidationContext({ signal: options.signal, timeoutMs, request,
      readRetainedSource: (input) => readRetainedSource(input, () => port.sourceAccessRevoked(scope, request, input.binding, context)),
    });
    let prepared;
    let response;
    let dispatchFailure;
    try {
      port = getReviewedPublicRevalidationPort(config.store, context);
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
      response?.bytes?.fill(0);
      context.close();
    }
  }

  return Object.freeze({
    bindSource: (scope, request, input, options) => run('bind', scope, request, input, options),
    refresh: (scope, request, input, options) => run('refresh', scope, request, input, options),
  });
}
