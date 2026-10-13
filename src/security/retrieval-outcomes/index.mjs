import { SafeFetcher } from "../controlled-fetch.mjs";
import { wrapSafeFetcher } from "./internal.mjs";

/** EI-private opt-in transport outcomes; no accepted Research API or package export. */
export function createLocalRetrievalOutcomes() {
  // Caller configuration, callbacks, headers, policies and limits are unsupported.
  return wrapSafeFetcher(arguments.length === 0 ? new SafeFetcher() : null);
}
