import { types } from "node:util";
import { performance } from "node:perf_hooks";
import { SafeFetcher, DEFAULT_RUN_LIMITS } from "../controlled-fetch.mjs";
import { RetrievalError } from "../errors.mjs";

const fetchDocument = SafeFetcher.prototype.fetch;
const fetchSvg = SafeFetcher.prototype.fetchSvgAsset;
const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted").get;
const RESOURCE_REASONS = new Set([
  "RESOURCE_LIMIT", "REDIRECT_LIMIT", "REQUEST_LIMIT", "UNSUPPORTED_MEDIA", "DEADLINE_EXCEEDED",
]);
export const OUTCOME_SCHEMA = "ei-private-retrieval-outcome/1";

function refused(code, reason) {
  return Object.freeze({ schema: OUTCOME_SCHEMA, kind: "refused", transportComplete: false, code, reason });
}

function optionsFrom(value) {
  if (value === undefined) return { options: Object.freeze({}), signal: undefined };
  if (value === null || typeof value !== "object" || types.isProxy(value) || Array.isArray(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => key !== "signal")) return null;
  const descriptor = Object.getOwnPropertyDescriptor(value, "signal");
  if (!descriptor) return { options: Object.freeze({}), signal: undefined };
  if (!Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true) return null;
  const signal = descriptor.value;
  if (signal !== undefined) {
    if (signal === null || typeof signal !== "object" || types.isProxy(signal)) return null;
    Reflect.apply(aborted, signal, []);
  }
  return { options: Object.freeze({ signal }), signal };
}

function failure(error) {
  // Never read message, stack, cause, arbitrary properties, accessors, or proxy traps.
  try {
    if (error === null || typeof error !== "object" || types.isProxy(error)
      || Object.getPrototypeOf(error) !== RetrievalError.prototype) {
      return refused("INTERNAL_FAILURE", "UNRECOGNIZED_FAILURE");
    }
    const descriptor = Object.getOwnPropertyDescriptor(error, "code");
    if (!descriptor || !Object.hasOwn(descriptor, "value")) return refused("INTERNAL_FAILURE", "UNRECOGNIZED_FAILURE");
    const reason = descriptor.value;
    if (reason === "POLICY_DENIED") return refused("DESTINATION_BLOCKED", reason);
    if (RESOURCE_REASONS.has(reason)) return refused("RESOURCE_LIMIT", reason);
    if (reason === "DNS_FAILURE" || reason === "TRANSPORT_FAILURE" || reason === "CANCELED") {
      return refused(reason, reason);
    }
  } catch { /* All unsupported error shapes have the same fixed refusal. */ }
  return refused("INTERNAL_FAILURE", "UNRECOGNIZED_FAILURE");
}

/**
 * Trusted private test/composition bridge; never part of the package export map.
 * Calls the captured real implementation, not receiver-owned fetch callbacks.
 * A forged prototype has no SafeFetcher private fields and cannot perform I/O.
 */
export function wrapSafeFetcher(fetcher) {
  let supported = false;
  try {
    supported = fetcher !== null && typeof fetcher === "object" && !types.isProxy(fetcher)
      && Object.getPrototypeOf(fetcher) === SafeFetcher.prototype;
  } catch { /* Unsupported receiver: both methods return fixed INVALID_INPUT. */ }

  async function retrieve(input, options, method, argumentCount) {
    const deadline = performance.now() + DEFAULT_RUN_LIMITS.totalMilliseconds;
    let validated;
    try {
      if (!supported || argumentCount > 2 || typeof input !== "string" || input.length === 0
        || input.length > 8_192 || !(validated = optionsFrom(options))) {
        return refused("INVALID_INPUT", "INVALID_INPUT");
      }
    } catch {
      return refused("INVALID_INPUT", "INVALID_INPUT");
    }
    try {
      const document = await Reflect.apply(method, fetcher, [input, validated.options]);
      // The original native fetch deadline is unchanged. This additional entry
      // ceiling and final signal check cannot renew it or retry a request.
      if (performance.now() >= deadline) return refused("RESOURCE_LIMIT", "DEADLINE_EXCEEDED");
      if (validated.signal && Reflect.apply(aborted, validated.signal, [])) return refused("CANCELED", "CANCELED");
      if (!document || types.isProxy(document) || !Object.isFrozen(document)
        || !(document.bytes instanceof Uint8Array) || typeof document.url !== "string"
        || typeof document.contentType !== "string" || typeof document.fetchedAt !== "string"
        || !Number.isSafeInteger(document.redirects) || document.redirects < 0
        || (method === fetchSvg && (document.contentType !== "image/svg+xml" || document.redirects !== 0))) {
        return refused("INTERNAL_FAILURE", "UNRECOGNIZED_RESULT");
      }
      // Retain identity: the fetcher's private provenance WeakMap binds this
      // exact document. Its byte ownership remains the existing fetch contract.
      return Object.freeze({ schema: OUTCOME_SCHEMA, kind: "retrieved", transportComplete: true, document });
    } catch (error) {
      return failure(error);
    }
  }

  return Object.freeze({
    fetch(input, options) { return retrieve(input, options, fetchDocument, arguments.length); },
    fetchSvgAsset(input, options) { return retrieve(input, options, fetchSvg, arguments.length); },
  });
}
