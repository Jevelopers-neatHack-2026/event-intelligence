import { createHash } from "node:crypto";
import { EvidenceStoreError } from "../../evidence/store.mjs";
import { extractDeterministically, EXTRACTION_LIMITS } from "../../extraction/index.mjs";
import { decodedJsonLdScalarValue } from "../../extraction/jsonld.mjs";
import { normalizeCandidateValue } from "../../extraction/source.mjs";
import { compareEntityIdentity } from "../entities/identity.mjs";
import { compareOccurrenceIdentity } from "../occurrences/identity.mjs";
import { buildSourceCorroboration, corroborationDigest, normalizedAttributionUrl, CorroborationError } from "./corroboration.mjs";

const RESULT_SCHEMA = "ei-source-identity-composition-internal/v2";
const MAX_SOURCES = 8;
const MAX_BYTES_PER_SOURCE = 512 * 1024;
const MAX_TOTAL_BYTES = 2 * 1024 * 1024;
const MAX_IDENTITY_CANDIDATES = 23;
const MAX_FACTS = 128;
const MAX_POSITIONS = 128;
const MAX_LINK_CANDIDATES = 16;
const MAX_COMPARISONS = 256;
const DEADLINE_MS = 12_000;
const HEX_SHA256 = /^[a-f0-9]{64}$/;
const SOURCE_HASH = /^sha256:([a-f0-9]{64})$/;
const SAFE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TYPED_ARRAY_PROTO = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_TAG = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, Symbol.toStringTag).get;
const TYPED_ARRAY_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, "length").get;
const SIGNAL_ABORTED = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted").get;
const ENTITY_SCHEMA = "ei-entity-observation-internal/v1";
const OCCURRENCE_SCHEMA = "ei-occurrence-observation-internal/v1";
const EVENT_STATUSES = new Map([
  ["https://schema.org/EventScheduled", "scheduled"],
  ["http://schema.org/EventScheduled", "scheduled"],
  ["https://schema.org/EventCancelled", "canceled"],
  ["http://schema.org/EventCancelled", "canceled"],
  ["https://schema.org/EventPostponed", "postponed"],
  ["http://schema.org/EventPostponed", "postponed"],
  ["https://schema.org/EventRescheduled", "rescheduled"],
  ["http://schema.org/EventRescheduled", "rescheduled"],
]);

const IDENTITY_LIMITS = Object.freeze({
  ...EXTRACTION_LIMITS,
  maxDocumentBytes: MAX_BYTES_PER_SOURCE,
  maxHtmlNodes: 30_000,
  maxHtmlParseErrors: 16,
  htmlChunkCodeUnits: 8 * 1024,
  parseTimeoutMs: 1_500,
  traversalYieldEvery: 128,
  maxVisibleTextSegments: 512,
  maxVisibleTextBytes: 128 * 1024,
  maxStatusSignalCandidates: 32,
  maxPageMetadataCandidates: 64,
  maxCanonicalSuggestions: 16,
  maxNoscriptNodes: 256,
  maxNoscriptSignals: 16,
  maxJsonLdBlocks: 8,
  maxJsonLdBytes: 256 * 1024,
  maxJsonDepth: 48,
  maxJsonNodes: 12_000,
  maxEntities: 24,
  maxCandidatesPerEntity: 64,
  maxDiagnostics: 64,
});

const FACT_METHODS = new Map([
  ["name", { pointer: "/name", target: "title" }],
  ["series", { pointer: "/series", target: "series" }],
  ["seriesName", { pointer: "/seriesName", target: "series" }],
  ["edition", { pointer: "/edition", target: "edition" }],
  ["eventEdition", { pointer: "/eventEdition", target: "edition" }],
  ["location.address.addressLocality", { pointer: "/location/address/addressLocality", target: "city" }],
  ["location.name", { pointer: "/location/name", target: "venue" }],
  ["startDate", { pointer: "/startDate", target: "start", temporal: true }],
  ["endDate", { pointer: "/endDate", target: "end", temporal: true }],
  ["eventStatus", { pointer: "/eventStatus", target: "status", status: true }],
]);

const ERROR_MESSAGES = Object.freeze({
  INVALID_INPUT: "Source identity composition input is invalid",
  CANCELED: "Source identity composition was canceled",
  DEADLINE_EXCEEDED: "Source identity composition exceeded its deadline",
  RESOURCE_LIMIT: "Source identity composition exceeded a configured bound",
  JS_REQUIRED: "The source requires JavaScript rendering, which is not supported",
  ACCESS_RESTRICTED: "The source reports an access restriction",
  UNSUPPORTED_MEDIA: "The source media type is not supported for deterministic extraction",
  UNSUPPORTED_ENCODING: "The source character encoding is not supported",
  MALFORMED_ENCODING: "The source character encoding is malformed",
  EXTRACTION_UNUSABLE: "Deterministic extraction did not produce a usable source result",
  SOURCE_BINDING_FAILED: "A source candidate could not be bound to its exact bytes",
  NO_IDENTITY_CANDIDATES: "No eligible source-backed identity candidates were found",
  EVIDENCE_POSITION_MISSING: "An exact evidence position is unavailable",
  EVIDENCE_POSITION_AMBIGUOUS: "An exact evidence position is ambiguous",
  STORED_SOURCE_MISMATCH: "Stored source provenance does not match the completed retrieval",
  EVIDENCE_EXPIRED: "Evidence is expired or no longer available",
  EVIDENCE_DENIED: "Evidence access was denied",
  EVIDENCE_UNAVAILABLE: "Evidence could not be read or stored",
  COMPOSITION_FAILED: "Source identity composition failed",
});

export class SourceIdentityCompositionError extends Error {
  constructor(code = "COMPOSITION_FAILED") {
    const safeCode = Object.hasOwn(ERROR_MESSAGES, code) ? code : "COMPOSITION_FAILED";
    super(ERROR_MESSAGES[safeCode]);
    this.name = "SourceIdentityCompositionError";
    this.code = safeCode;
  }
}

function fail(code) {
  throw new SourceIdentityCompositionError(code);
}

function ownRecord(value, allowed) {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string" || !allowed.has(key))) return null;
    const copy = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true) return null;
      copy[key] = descriptor.value;
    }
    return copy;
  } catch {
    return null;
  }
}

function ownArray(value, maximum) {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return null;
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (!lengthDescriptor || !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value > maximum) return null;
    const length = lengthDescriptor.value;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== length + 1 || !keys.includes("length")) return null;
    const copy = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true) return null;
      copy.push(descriptor.value);
    }
    return copy;
  } catch {
    return null;
  }
}

function copyBytes(value, maximum) {
  try {
    if (!ArrayBuffer.isView(value) || TYPED_ARRAY_TAG.call(value) !== "Uint8Array") return null;
    const length = TYPED_ARRAY_LENGTH.call(value);
    if (!Number.isSafeInteger(length) || length < 1 || length > maximum) return null;
    return Buffer.from(Uint8Array.prototype.subarray.call(value, 0, length));
  } catch {
    return null;
  }
}

function snapshotDocument(value) {
  const input = ownRecord(value, new Set([
    "url", "requestedUrl", "redirectChain", "contentType", "bytes", "fetchedAt", "redirects", "image",
  ]));
  if (!input || typeof input.url !== "string" || input.url.length < 1 || input.url.length > 2_048
    || typeof input.contentType !== "string" || input.contentType.length < 1 || input.contentType.length > 160
    || typeof input.fetchedAt !== "string" || input.fetchedAt.length < 1 || input.fetchedAt.length > 64) fail("INVALID_INPUT");
  const bytes = copyBytes(input.bytes, MAX_BYTES_PER_SOURCE);
  if (!bytes) fail("RESOURCE_LIMIT");
  if (!Number.isSafeInteger(input.redirects) || input.redirects < 0 || input.redirects > 20) {
    bytes.fill(0);
    fail("INVALID_INPUT");
  }
  const redirects = input.redirects;
  const redirectChain = input.redirectChain === undefined ? [] : ownArray(input.redirectChain, 20);
  const requestedUrl = input.requestedUrl === undefined ? input.url : input.requestedUrl;
  if (typeof requestedUrl !== "string" || requestedUrl.length < 1 || requestedUrl.length > 2_048
    || !redirectChain || redirectChain.length !== redirects
    || redirectChain.some((url) => typeof url !== "string" || url.length < 1 || url.length > 2_048)
    || (redirects > 0 && redirectChain.at(-1) !== input.url)) {
    bytes.fill(0);
    fail("STORED_SOURCE_MISMATCH");
  }
  return Object.freeze({
    url: input.url,
    requestedUrl,
    redirectChain: Object.freeze([...redirectChain]),
    contentType: input.contentType,
    fetchedAt: input.fetchedAt,
    redirects,
    bytes,
  });
}

function snapshotSources(value) {
  const records = ownArray(value, MAX_SOURCES);
  if (!records || records.length < 1) fail("INVALID_INPUT");
  let totalBytes = 0;
  const sources = [];
  try {
    for (const record of records) {
      const input = ownRecord(record, new Set(["document", "retentionHandle"]));
      if (!input || !input.retentionHandle || typeof input.retentionHandle !== "object") fail("INVALID_INPUT");
      const document = snapshotDocument(input.document);
      totalBytes += document.bytes.byteLength;
      if (totalBytes > MAX_TOTAL_BYTES) {
        document.bytes.fill(0);
        fail("RESOURCE_LIMIT");
      }
      sources.push({ document, retentionHandle: input.retentionHandle });
    }
    return sources;
  } catch (error) {
    for (const source of sources) source.document.bytes.fill(0);
    throw error;
  }
}

function snapshotInput(value) {
  const input = ownRecord(value, new Set(["sources", "request", "evidenceStore", "signal"]));
  if (!input || !Object.hasOwn(input, "request") || input.request === null
    || (typeof input.request !== "object" && typeof input.request !== "function")) fail("INVALID_INPUT");
  const methods = readStoreMethods(input.evidenceStore);
  let signal = input.signal;
  if (signal !== undefined) {
    try {
      SIGNAL_ABORTED.call(signal);
    } catch {
      fail("INVALID_INPUT");
    }
  }
  return { sources: snapshotSources(input.sources), request: input.request, methods, signal };
}

function readStoreMethods(value) {
  const names = [
    "scopeForAuthenticatedRequest", "ingestEvidence", "appendFact", "materializeSelected",
  ];
  try {
    if (value === null || typeof value !== "object") fail("INVALID_INPUT");
    const methods = Object.create(null);
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (!descriptor || !Object.hasOwn(descriptor, "value") || typeof descriptor.value !== "function") fail("INVALID_INPUT");
      methods[name] = descriptor.value.bind(value);
    }
    return methods;
  } catch (error) {
    if (error instanceof SourceIdentityCompositionError) throw error;
    fail("INVALID_INPUT");
  }
}

function abortState(signal) {
  if (signal === undefined) return false;
  try {
    return SIGNAL_ABORTED.call(signal);
  } catch {
    fail("INVALID_INPUT");
  }
}

function createGuard(signal) {
  const deadline = Date.now() + DEADLINE_MS;
  const controller = new AbortController();
  let canceled = false;
  let timedOut = false;
  let rejectAbort;
  const abortPromise = new Promise((resolve, reject) => { rejectAbort = reject; });
  void abortPromise.catch(() => {});
  const rejectOnce = (code) => {
    if (!controller.signal.aborted) controller.abort();
    rejectAbort(new SourceIdentityCompositionError(code));
  };
  const onExternalAbort = () => {
    canceled = true;
    rejectOnce("CANCELED");
  };
  if (signal !== undefined) {
    try {
      EventTarget.prototype.addEventListener.call(signal, "abort", onExternalAbort, { once: true });
      if (abortState(signal)) onExternalAbort();
    } catch {
      fail("INVALID_INPUT");
    }
  }
  const timeout = setTimeout(() => {
    timedOut = true;
    rejectOnce("DEADLINE_EXCEEDED");
  }, DEADLINE_MS);

  const check = () => {
    if (canceled || abortState(signal)) fail("CANCELED");
    if (timedOut || Date.now() >= deadline) fail("DEADLINE_EXCEEDED");
  };
  const awaitCall = async (operation) => {
    check();
    let pending;
    try {
      pending = Promise.resolve().then(operation);
      const result = await Promise.race([pending, abortPromise]);
      check();
      return result;
    } catch (error) {
      if (error instanceof SourceIdentityCompositionError) throw error;
      if (error instanceof EvidenceStoreError) throw mapEvidenceError(error);
      throw error;
    }
  };
  const dispose = () => {
    clearTimeout(timeout);
    if (signal !== undefined) {
      try { EventTarget.prototype.removeEventListener.call(signal, "abort", onExternalAbort); } catch { /* Native signal was checked above. */ }
    }
  };
  return { controller, check, awaitCall, dispose };
}

function mapEvidenceError(error) {
  if (error.code === "EVIDENCE_EXPIRED") return new SourceIdentityCompositionError("EVIDENCE_EXPIRED");
  if (error.code === "EVIDENCE_CANCELLED") return new SourceIdentityCompositionError("CANCELED");
  if (["EVIDENCE_DENIED", "EVIDENCE_KEY_UNAVAILABLE", "EVIDENCE_INVALID"].includes(error.code)) {
    return new SourceIdentityCompositionError("EVIDENCE_DENIED");
  }
  if (error.code === "EVIDENCE_NOT_FOUND") return new SourceIdentityCompositionError("EVIDENCE_UNAVAILABLE");
  return new SourceIdentityCompositionError("EVIDENCE_UNAVAILABLE");
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function sourceHashMatches(extraction, document) {
  const expected = sha256(document.bytes);
  return extraction.sourceHash === `sha256:${expected}`
    && extraction.source?.contentHash === extraction.sourceHash
    && extraction.source?.url === document.url
    && extraction.source?.contentType === document.contentType
    && extraction.source?.fetchedAt === document.fetchedAt;
}

function ownTextRange(value) {
  const locator = ownRecord(value, new Set(["kind", "startByte", "endByte"]));
  if (!locator || locator.kind !== "text-range" || !Number.isSafeInteger(locator.startByte)
    || !Number.isSafeInteger(locator.endByte) || locator.startByte < 0 || locator.endByte <= locator.startByte) return null;
  return Object.freeze({ kind: "text-range", startByte: locator.startByte, endByte: locator.endByte });
}

function bindCandidateToSource(candidate, bytes) {
  const input = ownRecord(candidate, new Set(["field", "rawValue", "normalizedValue", "source", "suggestionOnly", "urlSuggestion", "property"]));
  if (!input || typeof input.rawValue !== "string" || input.rawValue.length === 0 || input.rawValue.length > 4_096) {
    fail("SOURCE_BINDING_FAILED");
  }
  const source = ownRecord(input.source, new Set(["kind", "locator", "jsonPointer", "property"]));
  const locator = source?.kind === "jsonld" ? ownTextRange(source.locator) : null;
  if (!locator || locator.endByte > bytes.byteLength) fail("SOURCE_BINDING_FAILED");
  const rawBytes = Buffer.from(input.rawValue, "utf8");
  const selectedBytes = bytes.subarray(locator.startByte, locator.endByte);
  if (!selectedBytes.equals(rawBytes)) fail("SOURCE_BINDING_FAILED");
  return { input, locator, rawBytes };
}

function mapCandidateField(field, normalizedValue) {
  const mapped = FACT_METHODS.get(field);
  if (!mapped) return null;
  if (typeof normalizedValue !== "string" || normalizedValue.length === 0 || normalizedValue.length > 512
    || normalizedValue.trim().length === 0 || normalizedValue.includes("\0")
    || (mapped.temporal && normalizedValue.length > 100)) return null;
  if (mapped.status) {
    const status = EVENT_STATUSES.get(normalizedValue);
    return status ? { ...mapped, value: status } : null;
  }
  return { ...mapped, value: normalizedValue };
}

function derivePrecision(value) {
  const date = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  const local = /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?$/.exec(value);
  const instant = /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (date && validDateParts(date[1], date[2], date[3])) return "date";
  if (local && validDateParts(...local[1].split("-")) && validClock(local[2], local[3], local[4])) return "local_datetime";
  if (instant && validDateParts(...instant[1].split("-")) && validClock(instant[2], instant[3], instant[4])
    && validZone(instant[6])) return "instant";
  return "unknown";
}

function validDateParts(yearText, monthText, dayText) {
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  if (month < 1 || month > 12) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day >= 1 && day <= days[month - 1];
}

function validClock(hourText, minuteText, secondText) {
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = secondText === undefined ? 0 : Number(secondText);
  return hour <= 23 && minute <= 59 && second <= 59;
}

function validZone(zone) {
  if (zone === "Z") return true;
  const hours = Number(zone.slice(1, 3));
  const minutes = Number(zone.slice(4, 6));
  return hours <= 14 && minutes <= 59 && !(hours === 14 && minutes !== 0);
}

function sourceEntityKey(entity, observationKind, seenKeys, seenEntityIds) {
  const { blockIndex, ordinal, entityId, jsonPointer } = entity;
  if (entity.kind !== observationKind
    || !Number.isSafeInteger(blockIndex) || blockIndex < 0 || blockIndex >= IDENTITY_LIMITS.maxJsonLdBlocks
    || !Number.isSafeInteger(ordinal) || ordinal < 0 || ordinal >= IDENTITY_LIMITS.maxEntities
    || typeof jsonPointer !== "string" || jsonPointer.length > MAX_BYTES_PER_SOURCE
    || entityId !== `${observationKind}:script-${blockIndex}:${jsonPointer}`) fail("SOURCE_BINDING_FAILED");
  const key = `${observationKind}:script-${blockIndex}:${ordinal}`;
  if (seenKeys.has(key) || seenEntityIds.has(entityId)) fail("SOURCE_BINDING_FAILED");
  seenKeys.add(key);
  seenEntityIds.add(entityId);
  return key;
}

function draftSourceCandidates(extraction, document) {
  if (!sourceHashMatches(extraction, document)) fail("SOURCE_BINDING_FAILED");
  const drafts = [];
  const seenEntityKeys = new Set();
  const seenEntityIds = new Set();
  const entities = [
    ...extraction.events.map((entity) => ({ entity, observationKind: "event" })),
    ...extraction.organizations.map((entity) => ({ entity, observationKind: "organization" })),
  ].map(({ entity, observationKind }) => ({
    entity,
    observationKind,
    entityKey: sourceEntityKey(entity, observationKind, seenEntityKeys, seenEntityIds),
  }));
  try {
    for (const { entity, observationKind, entityKey } of entities) {
      for (const candidate of entity.candidates) {
        if (candidate.suggestionOnly === true) continue;
        const field = FACT_METHODS.get(candidate.field);
        if (observationKind === "organization" && candidate.field !== "name") continue;
        // Display fields flatten object keys with dots; only the exact pointer
        // relative to this entity establishes a supported structured property.
        if (!field || candidate.source?.jsonPointer !== entity.jsonPointer + field.pointer) continue;
        const bound = bindCandidateToSource(candidate, document.bytes);
        if (typeof bound.input.normalizedValue !== "string") {
          bound.rawBytes.fill(0);
          continue;
        }
        // XML references and CDATA boundaries belong to the original source
        // slice, not the logical JSON token. Use the parser-owned scalar for
        // this exact candidate while retaining the byte binding above.
        const parsed = decodedJsonLdScalarValue(candidate);
        if (typeof parsed !== "string" || normalizeCandidateValue(parsed) !== bound.input.normalizedValue) {
          bound.rawBytes.fill(0);
          fail("SOURCE_BINDING_FAILED");
        }
        const normalizedValue = bound.input.normalizedValue;
        const mapped = mapCandidateField(bound.input.field, normalizedValue);
        if (!mapped) {
          bound.rawBytes.fill(0);
          continue;
        }
        if (drafts.length >= MAX_FACTS) {
          bound.rawBytes.fill(0);
          fail("RESOURCE_LIMIT");
        }
        const identityField = observationKind === "organization" ? "name" : mapped.target;
        const precision = mapped.temporal ? derivePrecision(normalizedValue) : undefined;
        drafts.push({
          observationKind,
          entityKey,
          identityField,
          identityValue: observationKind === "organization" ? normalizedValue : mapped.value,
          sourceField: bound.input.field,
          rawValue: bound.input.rawValue,
          normalizedValue,
          precision,
          locator: bound.locator,
          positionDigest: sha256(bound.rawBytes),
          positionBytes: bound.rawBytes,
        });
      }
    }
  } catch (error) {
    for (const draft of drafts) draft.positionBytes.fill(0);
    throw error;
  }
  return { entities, drafts };
}

function repeatedlyDecodeUrlComponent(value) {
  let current = value;
  for (let depth = 0; depth < 8; depth += 1) {
    let decoded;
    try { decoded = decodeURIComponent(current.replaceAll('+', '%20')); }
    catch { return null; }
    if (decoded === current) return current;
    current = decoded;
  }
  try {
    return decodeURIComponent(current.replaceAll('+', '%20')) === current ? current : null;
  } catch {
    return null;
  }
}

function isSafeLinkUrl(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 2_048) return false;
  let parsed;
  try { parsed = new URL(value); } catch { return false; }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return false;
  const sensitive = /(?:token|key|auth|code|signature|sig|secret|session|password|credential|invite|ticket|admission)/i;
  for (const key of parsed.searchParams.keys()) {
    const decoded = repeatedlyDecodeUrlComponent(key);
    if (decoded === null || sensitive.test(decoded)) return false;
  }
  const fragment = repeatedlyDecodeUrlComponent(parsed.hash.slice(1));
  if (fragment === null || sensitive.test(fragment)) return false;
  for (const component of fragment.split(/[&;]/)) {
    const key = repeatedlyDecodeUrlComponent(component.split('=', 1)[0]);
    if (key === null || sensitive.test(key)) return false;
  }
  return true;
}

function draftLinkCandidates(extraction, document) {
  const candidates = [
    ...extraction.canonicalSuggestions,
    ...extraction.pageMetadata.filter((candidate) => candidate.field === "openGraph.url"),
  ];
  const drafts = [];
  const seenLocators = new Map();
  let omittedCount = 0;
  try {
    for (const candidate of candidates) {
      const input = ownRecord(candidate, new Set([
        "field", "rawValue", "normalizedValue", "source", "suggestionOnly", "urlSuggestion", "property",
      ]));
      const source = ownRecord(input?.source, new Set(["kind", "locator", "jsonPointer", "property"]));
      const locator = ownTextRange(source?.locator);
      if (!input || !source || !locator || !["canonical", "open-graph"].includes(source.kind)
        || !["canonical.url", "openGraph.url"].includes(input.field)
        || typeof input.rawValue !== "string" || input.rawValue.length < 1 || input.rawValue.length > 4_096
        || !isSafeLinkUrl(input.urlSuggestion) || locator.endByte > document.bytes.byteLength) {
        omittedCount += 1;
        continue;
      }
      const positionBytes = Buffer.from(input.rawValue, "utf8");
      const selected = document.bytes.subarray(locator.startByte, locator.endByte);
      if (!selected.equals(positionBytes)) {
        positionBytes.fill(0);
        fail("SOURCE_BINDING_FAILED");
      }
      const key = locatorKey(locator);
      const previous = seenLocators.get(key);
      if (previous) {
        if (previous.url !== input.urlSuggestion || !previous.positionBytes.equals(positionBytes)) {
          positionBytes.fill(0);
          fail("SOURCE_BINDING_FAILED");
        }
        positionBytes.fill(0);
        continue;
      }
      if (drafts.length >= MAX_LINK_CANDIDATES) {
        omittedCount += 1;
        positionBytes.fill(0);
        continue;
      }
      const draft = {
        url: input.urlSuggestion,
        field: input.field,
        locator,
        positionDigest: sha256(positionBytes),
        positionBytes,
      };
      drafts.push(draft);
      seenLocators.set(key, { url: draft.url, positionBytes });
    }
    return { drafts, omittedCount };
  } catch (error) {
    for (const draft of drafts) draft.positionBytes.fill(0);
    throw error;
  }
}

function draftAttributionCandidates(entities, identityDrafts, document) {
  const eligible = new Set(identityDrafts.map((draft) => draft.entityKey));
  const drafts = [];
  try {
    for (const { entity, observationKind, entityKey } of entities) {
      if (!eligible.has(entityKey)) continue;
      const rootPointer = `${entity.jsonPointer}/isBasedOn`;
      for (const candidate of entity.candidates) {
        const pointer = candidate.source?.jsonPointer;
        if (typeof pointer !== 'string' || !(pointer === rootPointer || pointer.startsWith(`${rootPointer}/`))) continue;
        const bound = bindCandidateToSource(candidate, document.bytes);
        const decoded = decodedJsonLdScalarValue(candidate);
        if (typeof bound.input.normalizedValue === 'string'
          && (typeof decoded !== 'string' || normalizeCandidateValue(decoded) !== bound.input.normalizedValue)) {
          bound.rawBytes.fill(0);
          fail('SOURCE_BINDING_FAILED');
        }
        const targetUrl = pointer === rootPointer ? normalizedAttributionUrl(decoded) : null;
        drafts.push({
          entityKey, observationKind, sourceField: 'isBasedOn', rawValue: bound.input.rawValue,
          normalizedValue: bound.input.normalizedValue, identityValue: bound.input.normalizedValue,
          locator: bound.locator, jsonPointer: pointer, positionDigest: sha256(bound.rawBytes), positionBytes: bound.rawBytes,
          targetUrl, form: pointer !== rootPointer ? 'unsupported_shape' : targetUrl ? 'direct_string' : 'unsupported_value',
          retained: false,
        });
        if (drafts.length > MAX_POSITIONS) fail('RESOURCE_LIMIT');
      }
    }
    return drafts;
  } catch (error) { for (const draft of drafts) draft.positionBytes.fill(0); throw error; }
}

function allSourcePositions(drafts, linkDrafts, attributionDrafts) {
  const positions = new Map();
  for (const draft of [...drafts, ...linkDrafts, ...attributionDrafts]) {
    const key = locatorKey(draft.locator);
    const previous = positions.get(key);
    if (previous && (previous.positionDigest !== draft.positionDigest || !previous.content.equals(draft.positionBytes))) {
      fail("SOURCE_BINDING_FAILED");
    }
    if (!previous) positions.set(key, {
      locator: draft.locator,
      content: draft.positionBytes,
      positionDigest: draft.positionDigest,
    });
  }
  if (positions.size > MAX_POSITIONS) fail("RESOURCE_LIMIT");
  return [...positions.values()];
}

function isValidPdfTextBoxLocator(value) {
  const locator = ownRecord(value, new Set([
    "kind", "pageIndex", "textIndex", "x", "y", "width", "height", "pageWidth", "pageHeight",
    "rotation", "coordinateSystem", "geometry",
  ]));
  return Boolean(locator && locator.kind === "pdf-text-box"
    && Number.isSafeInteger(locator.pageIndex) && locator.pageIndex >= 0
    && Number.isSafeInteger(locator.textIndex) && locator.textIndex >= 0
    && [locator.x, locator.y, locator.width, locator.height, locator.pageWidth, locator.pageHeight].every(Number.isFinite)
    && locator.x >= 0 && locator.y >= 0 && locator.width >= 0 && locator.height >= 0
    && locator.pageWidth > 0 && locator.pageHeight > 0
    && [0, 90, 180, 270].includes(locator.rotation)
    && locator.coordinateSystem === "viewport-points-top-left"
    && locator.geometry === "approximate-text-item");
}

function reconcileStoredSourcePositions(positionValues, source) {
  const actual = ownArray(positionValues, MAX_POSITIONS);
  if (!actual || actual.length === 0) fail("EVIDENCE_POSITION_MISSING");
  const requestedByLocator = new Map(source.expectedPositions.map((position) => [locatorKey(position.locator), position]));
  const factsByLocator = new Set(source.drafts.map((draft) => locatorKey(draft.locator)));
  const linksByLocator = new Map(source.linkDrafts.map((draft) => [locatorKey(draft.locator), draft]));
  const actualByLocator = new Map();
  const reconciled = [];
  for (const value of actual) {
    const position = ownRecord(value, new Set(["handle", "locator", "contentHash"]));
    // Stored derived-PDF positions have their own locator representation and
    // cannot bind the raw fetched bytes consumed by this composer. Preserve the
    // established source-binding error for that representation boundary while
    // keeping malformed raw-position errors on the stored-mismatch path.
    if (position?.handle && isValidPdfTextBoxLocator(position.locator)) fail("SOURCE_BINDING_FAILED");
    const locator = ownTextRange(position?.locator);
    if (!position || !position.handle || !locator || locator.endByte > source.document.bytes.byteLength
      || !HEX_SHA256.test(position.contentHash)) fail("STORED_SOURCE_MISMATCH");
    const key = locatorKey(locator);
    if (actualByLocator.has(key)) fail("EVIDENCE_POSITION_AMBIGUOUS");
    const bytes = source.document.bytes.subarray(locator.startByte, locator.endByte);
    const positionDigest = sha256(bytes);
    if (positionDigest !== position.contentHash) fail("STORED_SOURCE_MISMATCH");
    const requested = requestedByLocator.get(key);
    if (requested && requested.positionDigest !== positionDigest) fail("STORED_SOURCE_MISMATCH");
    const checked = { locator, content: bytes, positionDigest };
    actualByLocator.set(key, checked);
    reconciled.push(checked);
  }
  for (const key of factsByLocator) {
    if (!actualByLocator.has(key)) fail("EVIDENCE_POSITION_MISSING");
  }
  let omittedCount = 0;
  const linkDrafts = source.linkDrafts.filter((draft) => {
    const actualPosition = actualByLocator.get(locatorKey(draft.locator));
    if (actualPosition?.positionDigest === draft.positionDigest) return true;
    omittedCount += 1;
    return false;
  });
  for (const draft of source.linkDrafts) {
    const actualPosition = actualByLocator.get(locatorKey(draft.locator));
    if (actualPosition && actualPosition.positionDigest !== draft.positionDigest) fail("STORED_SOURCE_MISMATCH");
  }
  if (linksByLocator.size !== source.linkDrafts.length) fail("SOURCE_BINDING_FAILED");
  for (const draft of source.attributionDrafts) {
    const actualPosition = actualByLocator.get(locatorKey(draft.locator));
    if (actualPosition && actualPosition.positionDigest !== draft.positionDigest) fail('STORED_SOURCE_MISMATCH');
    // Older immutable same-byte records may lack this newly selected position.
    // Preserve the record and expose unresolved attribution instead of claiming
    // the new input slice is retrievable from the historical evidence.
    draft.retained = Boolean(actualPosition);
  }
  return { expectedPositions: reconciled, linkDrafts, omittedCount };
}

function metadataSnapshot(value, expectedFullHash) {
  const meta = ownRecord(value, new Set([
    "evidenceId", "version", "previousEvidenceId", "contentHash", "duplicateGroupId", "retrievedAt", "createdAt",
    "expiresAt", "policyId", "policyVersion", "accessPolicy", "state", "positionCount",
  ]));
  if (!meta || meta.state !== "available" || typeof meta.evidenceId !== "string" || !SAFE_UUID.test(meta.evidenceId)
    || meta.contentHash !== expectedFullHash || !HEX_SHA256.test(meta.duplicateGroupId)
    || typeof meta.retrievedAt !== "string" || !Number.isFinite(Date.parse(meta.retrievedAt))
    || typeof meta.expiresAt !== "string" || !Number.isFinite(Date.parse(meta.expiresAt))
    || meta.accessPolicy !== "tenant_private"
    || !Number.isSafeInteger(meta.positionCount) || meta.positionCount < 1 || meta.positionCount > MAX_POSITIONS) {
    fail(meta?.state === "expired" ? "EVIDENCE_EXPIRED" : "SOURCE_BINDING_FAILED");
  }
  return Object.freeze({
    evidenceId: meta.evidenceId,
    contentHash: meta.contentHash,
    duplicateGroupId: meta.duplicateGroupId,
    retrievedAt: meta.retrievedAt,
    expiresAt: meta.expiresAt,
    positionCount: meta.positionCount,
  });
}

function snapshotLocator(value) {
  const range = ownTextRange(value);
  if (range) return range;
  const pointer = ownRecord(value, new Set(["kind", "pointer"]));
  if (pointer?.kind === "json-pointer" && typeof pointer.pointer === "string"
    && pointer.pointer.length <= 4_096 && !pointer.pointer.includes("\0")) {
    return Object.freeze({ kind: "json-pointer", pointer: pointer.pointer });
  }
  return null;
}

function locatorKey(locator) {
  return locator.kind === "text-range"
    ? JSON.stringify([locator.kind, locator.startByte, locator.endByte])
    : JSON.stringify([locator.kind, locator.pointer]);
}

function canonicalSourceUrl(value) {
  try {
    const parsed = new URL(value);
    parsed.hash = "";
    return parsed.href;
  } catch {
    fail("STORED_SOURCE_MISMATCH");
  }
}

function matchPositionHandles(positionValues, expectedPositions, expectedCount) {
  const actual = ownArray(positionValues, MAX_POSITIONS);
  if (!actual || actual.length !== expectedCount) fail("SOURCE_BINDING_FAILED");
  const copied = [];
  for (const value of actual) {
    const position = ownRecord(value, new Set(["handle", "locator", "contentHash"]));
    const locator = snapshotLocator(position?.locator);
    if (!position || !position.handle || typeof position.handle !== "object" || !locator || !HEX_SHA256.test(position.contentHash)) {
      fail("SOURCE_BINDING_FAILED");
    }
    copied.push({ handle: position.handle, locator, contentHash: position.contentHash });
  }
  if (copied.length > MAX_POSITIONS) fail("RESOURCE_LIMIT");
  const byKey = new Map();
  for (const position of copied) {
    const key = locatorKey(position.locator);
    const matches = byKey.get(key) ?? [];
    matches.push(position);
    byKey.set(key, matches);
  }
  const mapped = new Map();
  for (const expected of expectedPositions) {
    const key = locatorKey(expected.locator);
    const byLocator = byKey.get(key) ?? [];
    if (byLocator.length > 1) fail("EVIDENCE_POSITION_AMBIGUOUS");
    const matches = byLocator.filter((position) => position.contentHash === expected.positionDigest);
    if (matches.length === 0) fail(byLocator.length === 0 ? "EVIDENCE_POSITION_MISSING" : "SOURCE_BINDING_FAILED");
    if (matches.length !== 1) fail("EVIDENCE_POSITION_AMBIGUOUS");
    mapped.set(key, matches[0].handle);
  }
  return mapped;
}

function selectedMaterialization(value, expectedEvidenceCount, expectedFactCount) {
  const batch = ownRecord(value, new Set(["evidence", "facts"]));
  const evidence = ownArray(batch?.evidence, MAX_SOURCES);
  const facts = ownArray(batch?.facts, MAX_FACTS);
  if (!batch || !evidence || !facts || evidence.length !== expectedEvidenceCount || facts.length !== expectedFactCount) {
    fail("SOURCE_BINDING_FAILED");
  }
  return { evidence, facts };
}

function selectedEvidenceId(value) {
  const metadata = ownRecord(value, new Set([
    "evidenceId", "version", "previousEvidenceId", "contentHash", "duplicateGroupId", "retrievedAt", "createdAt",
    "expiresAt", "policyId", "policyVersion", "accessPolicy", "state", "positionCount",
  ]));
  if (!metadata || typeof metadata.evidenceId !== "string" || !SAFE_UUID.test(metadata.evidenceId)) {
    fail("SOURCE_BINDING_FAILED");
  }
  return metadata.evidenceId;
}

function snapshotSelectedSource(value, expected) {
  const selected = ownRecord(value, new Set(["handle", "metadata", "source", "positions"]));
  const metadata = metadataSnapshot(selected?.metadata, expected.fullHash);
  const source = ownRecord(selected?.source, new Set([
    "sourceUrl", "canonicalUrl", "redirectChain", "contentType", "sourceKind", "retrievedAt", "retrievedAtMs", "contentHash",
  ]));
  const redirects = ownArray(source?.redirectChain, 20);
  if (!selected || !selected.handle || typeof selected.handle !== "object"
    || metadata.evidenceId !== expected.evidenceId
    || !source || !redirects || redirects.some((url) => typeof url !== "string")
    || source.sourceUrl !== expected.document.requestedUrl
    || source.canonicalUrl !== canonicalSourceUrl(expected.document.url)
    || source.contentType !== expected.document.contentType || source.sourceKind !== "external"
    || source.retrievedAt !== metadata.retrievedAt
    || !Number.isSafeInteger(source.retrievedAtMs) || source.retrievedAtMs !== Date.parse(source.retrievedAt)
    || source.contentHash !== expected.fullHash
    || redirects.length !== expected.document.redirectChain.length
    || redirects.some((url, index) => url !== expected.document.redirectChain[index])) {
    fail("STORED_SOURCE_MISMATCH");
  }
  const positions = matchPositionHandles(selected.positions, expected.positions, metadata.positionCount);
  return {
    handle: selected.handle,
    metadata,
    source: Object.freeze({
      sourceUrl: source.sourceUrl,
      canonicalUrl: source.canonicalUrl,
      redirectChain: Object.freeze([...redirects]),
      contentType: source.contentType,
      sourceKind: source.sourceKind,
      retrievedAt: source.retrievedAt,
      retrievedAtMs: source.retrievedAtMs,
      contentHash: source.contentHash,
    }),
    positionHandles: positions,
  };
}

function candidateId(kind, evidenceId, entityKey) {
  const match = /^(event|organization):script-(0|[1-9]\d*):(0|[1-9]\d*)$/.exec(entityKey);
  if (!match || (match[1] === "event" ? kind !== "event" : kind !== "org")) fail("SOURCE_BINDING_FAILED");
  return `${kind}-${evidenceId.replaceAll("-", "")}-${match[2]}-${match[3]}`;
}

function mapStoreFact(record, draft, fullHash, metadata) {
  const fact = ownRecord(record, new Set(["factId", "field", "status", "rawValue", "normalizedValue", "precision", "method", "supports"]));
  const supports = ownArray(fact?.supports, 1);
  if (!fact || !SAFE_UUID.test(fact.factId) || fact.field !== draft.sourceField || fact.status !== "sourced"
    || fact.rawValue !== draft.rawValue || fact.normalizedValue !== draft.normalizedValue
    || fact.precision !== draft.precision
    || !supports || supports.length !== 1) fail("SOURCE_BINDING_FAILED");
  const support = ownRecord(supports[0], new Set(["evidence", "position", "contentHash", "duplicateGroupId", "independence"]));
  if (!support || !support.evidence || !support.position || support.contentHash !== fullHash
    || support.duplicateGroupId !== metadata.duplicateGroupId || support.independence !== "unknown") fail("SOURCE_BINDING_FAILED");
  const locator = draft.locator;
  const reference = Object.freeze({
    evidenceId: metadata.evidenceId,
    contentHash: fullHash,
    locator,
    field: draft.sourceField,
    value: draft.identityValue,
  });
  const identityClaim = Object.freeze({
    value: draft.identityValue,
    origin: "sourced",
    supports: Object.freeze([reference]),
    ...(draft.precision ? { precision: draft.precision } : {}),
  });
  return { fact, claim: identityClaim };
}

function projectObservations(sourceRuns) {
  const entities = [];
  const occurrences = [];
  const facts = [];
  const transitionDiagnostics = [];
  for (const source of sourceRuns) {
    if (!source.evidence) continue;
    const byEntity = new Map();
    for (const item of source.identityFacts) {
      const { draft, fact, claim } = item;
      facts.push(fact);
      const candidateKey = draft.entityKey;
      const candidate = byEntity.get(candidateKey) ?? {
        kind: draft.observationKind,
        entityKey: draft.entityKey,
        facts: Object.create(null),
      };
      const field = draft.observationKind === "organization" ? "names" : draft.identityField;
      if (!candidate.facts[field]) candidate.facts[field] = [];
      const maximum = candidate.kind === "organization" ? 24 : 16;
      if (candidate.facts[field].length >= maximum) fail("RESOURCE_LIMIT");
      candidate.facts[field].push(claim);
      byEntity.set(candidateKey, candidate);
    }
    for (const candidate of byEntity.values()) {
      if (candidate.kind === "organization") {
        entities.push(Object.freeze({
          schema: ENTITY_SCHEMA,
          candidateId: candidateId("org", source.evidence.evidenceId, candidate.entityKey),
          kind: "organization",
          names: Object.freeze(candidate.facts.names ?? []),
        }));
      } else {
        const candidateIdValue = candidateId("event", source.evidence.evidenceId, candidate.entityKey);
        const occurrenceFacts = Object.create(null);
        for (const field of ["title", "series", "edition", "city", "venue", "start", "end", "status"]) {
          if (candidate.facts[field]) occurrenceFacts[field] = Object.freeze(candidate.facts[field]);
        }
        occurrences.push(Object.freeze({ schema: OCCURRENCE_SCHEMA, candidateId: candidateIdValue, facts: Object.freeze(occurrenceFacts) }));
        for (const status of candidate.facts.status ?? []) {
          if (status.value === "canceled" || status.value === "rescheduled") {
            transitionDiagnostics.push(Object.freeze({
              candidateId: candidateIdValue,
              transition: status.value,
              reason: "source_predecessor_successor_relation_not_extracted",
            }));
          }
        }
      }
    }
    for (const item of source.attributionFacts) facts.push(item.fact);
  }
  if (entities.length + occurrences.length > MAX_IDENTITY_CANDIDATES) fail("RESOURCE_LIMIT");
  return {
    entities: entities.sort((left, right) => left.candidateId.localeCompare(right.candidateId, "en")),
    occurrences: occurrences.sort((left, right) => left.candidateId.localeCompare(right.candidateId, "en")),
    facts,
    transitionDiagnostics,
  };
}

function projectCorroboration(sourceRuns) {
  const nodes = [];
  const claims = [];
  const factBindings = [];
  for (const source of sourceRuns) {
    if (!source.evidence) continue;
    const eligible = new Set(source.identityFacts.map((item) => item.draft.entityKey));
    const nodeByEntity = new Map();
    for (const { entity, observationKind, entityKey } of source.entities) {
      if (!eligible.has(entityKey)) continue;
      const node = {
        candidateId: candidateId(observationKind === 'event' ? 'event' : 'org', source.evidence.evidenceId, entityKey),
        kind: observationKind, entityKey, entityPointer: entity.jsonPointer,
        sourceEntityCount: source.entities.filter((item) => item.observationKind === observationKind).length,
        evidenceId: source.evidence.evidenceId, contentHash: source.fullHash,
        sourceUrls: [...new Set([source.storedSource.sourceUrl, source.storedSource.canonicalUrl].map(normalizedAttributionUrl).filter(Boolean))],
        identityKeys: source.identityFacts.filter((item) => item.draft.entityKey === entityKey)
          .map((item) => corroborationDigest('source-identity-support', item.claim.supports[0])),
      };
      nodes.push(node); nodeByEntity.set(entityKey, node);
    }
    for (const draft of source.attributionDrafts) {
      const node = nodeByEntity.get(draft.entityKey);
      if (!node) fail('SOURCE_BINDING_FAILED');
      const fact = source.attributionFacts.find((item) => item.draft === draft)?.fact;
      const sourceRef = { evidenceId: node.evidenceId, contentHash: source.fullHash, locator: draft.locator,
        positionHash: draft.positionDigest, jsonPointer: draft.jsonPointer };
      const claim = {
        candidateId: node.candidateId, form: draft.form,
        status: draft.form !== 'direct_string' ? 'unsupported' : draft.retained ? 'retained' : 'legacy_position_unavailable',
        targetUrl: draft.targetUrl,
        sourceRef,
        factKey: fact ? corroborationDigest('source-attribution-fact', { sourceRef, targetUrl: draft.targetUrl }) : null,
      };
      claims.push(claim);
      if (fact) factBindings.push({ claimId: corroborationDigest('source-declaration', claim), factId: fact.factId });
    }
  }
  return { graph: buildSourceCorroboration(nodes, claims), factBindings: factBindings.sort((a, b) => a.claimId < b.claimId ? -1 : 1) };
}

function comparePairs(values, compare) {
  const count = values.length * (values.length - 1) / 2;
  if (!Number.isSafeInteger(count) || count > MAX_COMPARISONS) fail("RESOURCE_LIMIT");
  const results = [];
  for (let left = 0; left < values.length; left += 1) {
    for (let right = left + 1; right < values.length; right += 1) results.push(compare(values[left], values[right]));
  }
  return results;
}

function freezeDeep(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}

function projectMetadata(metadata) {
  return Object.freeze({
    evidenceId: metadata.evidenceId,
    contentHash: metadata.contentHash,
    duplicateGroupId: metadata.duplicateGroupId,
    retrievedAt: metadata.retrievedAt,
    expiresAt: metadata.expiresAt,
    positionCount: metadata.positionCount,
  });
}

function projectStoredSource(source) {
  return Object.freeze({
    sourceUrl: source.sourceUrl,
    canonicalUrl: source.canonicalUrl,
    redirectChain: Object.freeze([...source.redirectChain]),
    contentType: source.contentType,
    sourceKind: source.sourceKind,
    retrievedAt: source.retrievedAt,
    retrievedAtMs: source.retrievedAtMs,
    contentHash: source.contentHash,
  });
}

function validateExtractorResult(extraction) {
  if (extraction.status === "CANCELED" || extraction.termination === "CANCELED") fail("CANCELED");
  if (extraction.termination !== null || extraction.status === "RESOURCE_LIMIT") fail("RESOURCE_LIMIT");
  if (["JS_REQUIRED", "ACCESS_RESTRICTED", "UNSUPPORTED_MEDIA", "UNSUPPORTED_ENCODING", "MALFORMED_ENCODING"]
    .includes(extraction.status)) fail(extraction.status);
  if (!['PARTIAL', 'NO_ANSWER'].includes(extraction.status) || !extraction.source || !extraction.sourceHash) {
    fail("EXTRACTION_UNUSABLE");
  }
}

/**
 * Compose completed retrieval bytes into private evidence-backed identity observations.
 * Extraction is performed from a private byte snapshot inside this function; caller-supplied
 * extraction objects are not accepted. This function performs no network access.
 */
export async function composeSourceIdentity(inputValue) {
  const input = snapshotInput(inputValue);
  let guard;
  const sourceRuns = [];
  let totalEvidenceFacts = 0;
  let totalLinkCandidatesOmitted = 0;
  try {
    guard = createGuard(input.signal);
    guard.check();
    for (const source of input.sources) {
      const extraction = await guard.awaitCall(() => extractDeterministically(source.document, {
        signal: guard.controller.signal,
        limits: IDENTITY_LIMITS,
      }));
      guard.check();
      validateExtractorResult(extraction);
      let candidateResult;
      let links;
      let attributionDrafts;
      try {
        candidateResult = draftSourceCandidates(extraction, source.document);
        links = draftLinkCandidates(extraction, source.document);
        attributionDrafts = draftAttributionCandidates(candidateResult.entities, candidateResult.drafts, source.document);
      } catch (error) {
        for (const draft of candidateResult?.drafts ?? []) draft.positionBytes.fill(0);
        for (const draft of links?.drafts ?? []) draft.positionBytes.fill(0);
        throw error;
      }
      const { entities, drafts } = candidateResult;
      sourceRuns.push({
        ...source,
        extraction,
        entities,
        drafts,
        linkDrafts: links.drafts,
        linkCandidatesOmitted: links.omittedCount,
        evidence: null,
        identityFacts: [],
        attributionDrafts,
        attributionFacts: [],
      });
      totalEvidenceFacts += drafts.length + attributionDrafts.filter((draft) => draft.form === 'direct_string').length;
      totalLinkCandidatesOmitted += links.omittedCount;
      if (totalEvidenceFacts > MAX_FACTS) fail("RESOURCE_LIMIT");
    }
    if (!sourceRuns.some((source) => source.drafts.length > 0 || source.linkDrafts.length > 0)) {
      fail("NO_IDENTITY_CANDIDATES");
    }

    const identityCandidateCount = sourceRuns.reduce((count, source) => {
      const knownEntityKeys = new Set(source.entities.map((entry) => entry.entityKey));
      const eligibleEntityKeys = new Set();
      for (const draft of source.drafts) {
        if (!knownEntityKeys.has(draft.entityKey)) fail("SOURCE_BINDING_FAILED");
        eligibleEntityKeys.add(draft.entityKey);
      }
      return count + eligibleEntityKeys.size;
    }, 0);
    if (identityCandidateCount > MAX_IDENTITY_CANDIDATES) fail("RESOURCE_LIMIT");
    const totalComparisons = identityCandidateCount * (identityCandidateCount - 1) / 2;
    if (totalComparisons > MAX_COMPARISONS) fail("RESOURCE_LIMIT");

    let totalPositions = 0;
    const evidenceSources = [];
    for (const source of sourceRuns) {
      if (source.drafts.length === 0 && source.linkDrafts.length === 0) continue;
      guard.check();
      const positions = allSourcePositions(source.drafts, source.linkDrafts, source.attributionDrafts);
      totalPositions += positions.length;
      if (totalPositions > MAX_POSITIONS) fail("RESOURCE_LIMIT");
      const fullHashMatch = SOURCE_HASH.exec(source.extraction.sourceHash);
      if (!fullHashMatch) fail("SOURCE_BINDING_FAILED");
      const fullHash = fullHashMatch[1];
      let scope = await guard.awaitCall(() => input.methods.scopeForAuthenticatedRequest(input.request));
      guard.check();
      const ingest = await guard.awaitCall(() => input.methods.ingestEvidence(scope, {
        sourceUrl: source.document.requestedUrl,
        canonicalUrl: source.document.url,
        redirectChain: source.document.redirectChain,
        content: source.document.bytes,
        contentType: source.document.contentType,
        retrievedAt: source.document.fetchedAt,
        sourceKind: "external",
        positions: positions.map(({ locator, content }) => ({ locator, content })),
        retentionHandle: source.retentionHandle,
      }, guard.controller.signal));
      guard.check();
      const ingestResult = ownRecord(ingest, new Set(["evidence", "positions", "created", "metadata"]));
      const ingestMetadata = metadataSnapshot(ingestResult?.metadata, fullHash);
      if (!ingestResult || !ingestResult.evidence || typeof ingestResult.evidence !== "object") fail("SOURCE_BINDING_FAILED");
      source.evidenceHandle = ingestResult.evidence;
      source.fullHash = fullHash;
      source.expectedEvidenceId = ingestMetadata.evidenceId;
      source.expectedPositions = positions;
      source.identityFacts = [];
      evidenceSources.push(source);
    }

    // This all-or-error batch verifies stored descriptors and every actual stored
    // position before any fact write can claim the caller's completed retrieval.
    guard.check();
    let scope = await guard.awaitCall(() => input.methods.scopeForAuthenticatedRequest(input.request));
    guard.check();
    const preappendValue = await guard.awaitCall(() => input.methods.materializeSelected(
      scope,
      { evidence: evidenceSources.map((source) => source.evidenceHandle), facts: [] },
      input.request,
      guard.controller.signal,
    ));
    guard.check();
    const preappendBatch = selectedMaterialization(preappendValue, evidenceSources.length, 0);
    const expectedById = new Map(evidenceSources.map((source) => [source.expectedEvidenceId, source]));
    if (expectedById.size !== evidenceSources.length) fail("SOURCE_BINDING_FAILED");
    for (const selected of preappendBatch.evidence) {
      const selectedRecord = ownRecord(selected, new Set(["handle", "metadata", "source", "positions"]));
      const evidenceId = selectedEvidenceId(selectedRecord?.metadata);
      const source = expectedById.get(evidenceId);
      if (!source) fail("STORED_SOURCE_MISMATCH");
      const compatiblePositions = reconcileStoredSourcePositions(selectedRecord.positions, source);
      const compatibleLinkDrafts = new Set(compatiblePositions.linkDrafts);
      for (const draft of source.linkDrafts) {
        if (!compatibleLinkDrafts.has(draft)) draft.positionBytes.fill(0);
      }
      source.expectedPositions = compatiblePositions.expectedPositions;
      source.linkDrafts = compatiblePositions.linkDrafts;
      source.linkCandidatesOmitted += compatiblePositions.omittedCount;
      totalLinkCandidatesOmitted += compatiblePositions.omittedCount;
      const verified = snapshotSelectedSource(selected, {
        evidenceId: source.expectedEvidenceId,
        document: source.document,
        fullHash: source.fullHash,
        positions: source.expectedPositions,
      });
      source.metadata = verified.metadata;
      source.storedSource = verified.source;
      source.positionHandles = verified.positionHandles;
      source.evidence = verified.metadata;
    }
    if (evidenceSources.some((source) => !source.metadata || !source.storedSource || !source.positionHandles)) {
      fail("SOURCE_BINDING_FAILED");
    }
    totalEvidenceFacts = evidenceSources.reduce((count, source) => count + source.drafts.length
      + source.attributionDrafts.filter((draft) => draft.retained && draft.form === 'direct_string').length, 0);

    // Writes may commit individually. Only the final aggregate read below can
    // authorize releasing the composed identity result.
    for (const source of evidenceSources) {
      const positionByLocator = new Map(source.expectedPositions.map((position) => [locatorKey(position.locator), position]));
      const retainedAttributions = source.attributionDrafts.filter((draft) => draft.retained && draft.form === 'direct_string');
      for (const draft of [...source.drafts, ...retainedAttributions]) {
        guard.check();
        const key = locatorKey(draft.locator);
        const position = positionByLocator.get(key);
        const positionHandle = source.positionHandles.get(key);
        if (!position || !positionHandle || position.positionDigest !== draft.positionDigest) fail("SOURCE_BINDING_FAILED");
        const factInput = {
          field: draft.sourceField,
          status: "sourced",
          rawValue: draft.rawValue,
          normalizedValue: draft.normalizedValue,
          supports: [{ evidence: source.evidenceHandle, position: positionHandle, contentHash: source.fullHash }],
          ...(draft.precision ? { precision: draft.precision } : {}),
        };
        scope = await guard.awaitCall(() => input.methods.scopeForAuthenticatedRequest(input.request));
        guard.check();
        const factHandle = await guard.awaitCall(() => input.methods.appendFact(scope, factInput, input.request, guard.controller.signal));
        guard.check();
        if (!factHandle || typeof factHandle !== "object") fail("SOURCE_BINDING_FAILED");
        (retainedAttributions.includes(draft) ? source.attributionFacts : source.identityFacts).push({ draft, factHandle });
      }
    }

    // The selected-store read is deliberately the last async disclosure check.
    // It rechecks every evidence/fact expiry and current host authorization after
    // all key/decrypt work; only synchronous mapping follows its release.
    guard.check();
    scope = await guard.awaitCall(() => input.methods.scopeForAuthenticatedRequest(input.request));
    guard.check();
    const finalValue = await guard.awaitCall(() => input.methods.materializeSelected(
      scope,
      {
        evidence: evidenceSources.map((source) => source.evidenceHandle),
        facts: evidenceSources.flatMap((source) => [...source.identityFacts, ...source.attributionFacts].map((item) => item.factHandle)),
      },
      input.request,
      guard.controller.signal,
    ));
    guard.check();
    const finalBatch = selectedMaterialization(
      finalValue,
      evidenceSources.length,
      totalEvidenceFacts,
    );
    const finalById = new Map();
    for (const selected of finalBatch.evidence) {
      const selectedRecord = ownRecord(selected, new Set(["handle", "metadata", "source", "positions"]));
      const evidenceId = selectedEvidenceId(selectedRecord?.metadata);
      const source = expectedById.get(evidenceId);
      if (!source) fail("STORED_SOURCE_MISMATCH");
      const verified = snapshotSelectedSource(selected, {
        evidenceId: source.expectedEvidenceId,
        document: source.document,
        fullHash: source.fullHash,
        positions: source.expectedPositions,
      });
      if (verified.metadata.retrievedAt !== source.metadata.retrievedAt
        || verified.metadata.expiresAt !== source.metadata.expiresAt
        || verified.metadata.duplicateGroupId !== source.metadata.duplicateGroupId
        || verified.source.retrievedAtMs !== source.storedSource.retrievedAtMs) fail("STORED_SOURCE_MISMATCH");
      finalById.set(source.expectedEvidenceId, verified);
    }
    if (finalById.size !== evidenceSources.length) fail("SOURCE_BINDING_FAILED");

    const expectedFacts = evidenceSources.flatMap((source) => [...source.identityFacts, ...source.attributionFacts].map((item) => ({ source, item })));
    for (let index = 0; index < finalBatch.facts.length; index += 1) {
      const expected = expectedFacts[index];
      if (!expected) fail("SOURCE_BINDING_FAILED");
      const finalSource = finalById.get(expected.source.expectedEvidenceId);
      if (!finalSource) fail("SOURCE_BINDING_FAILED");
      const verified = mapStoreFact(finalBatch.facts[index], expected.item.draft, expected.source.fullHash, finalSource.metadata);
      expected.item.fact = verified.fact;
      expected.item.claim = verified.claim;
    }

    guard.check();
    const projected = projectObservations(sourceRuns);
    const { graph: corroboration, factBindings: corroborationFactBindings } = projectCorroboration(sourceRuns);
    const entityDecisions = comparePairs(projected.entities, compareEntityIdentity);
    const occurrenceDecisions = comparePairs(projected.occurrences, compareOccurrenceIdentity);
    const sources = sourceRuns.map((source) => Object.freeze({
      evidence: source.metadata ? projectMetadata(source.metadata) : null,
      storedSource: source.storedSource ? projectStoredSource(source.storedSource) : null,
      observedRetrievedAt: source.document.fetchedAt,
      extraction: source.extraction,
    }));
    const transitions = Object.freeze([]);
    const linkCandidates = evidenceSources.flatMap((source) => source.linkDrafts.map((draft) => Object.freeze({
      url: draft.url,
      sourceRef: Object.freeze({
        evidenceId: source.metadata.evidenceId,
        contentHash: source.fullHash,
        locator: draft.locator,
        field: draft.field,
        value: draft.url,
      }),
    })));
    const result = freezeDeep({
      schema: RESULT_SCHEMA,
      sources,
      facts: projected.facts,
      entityCandidates: projected.entities,
      occurrenceCandidates: projected.occurrences,
      entityDecisions,
      occurrenceDecisions,
      transitionLinks: transitions,
      unresolvedTransitions: projected.transitionDiagnostics,
      linkCandidates,
      linkCandidatesOmitted: totalLinkCandidatesOmitted,
      sourceAuthority: "not_evaluated",
      corroboration,
      corroborationFactBindings,
      limits: Object.freeze({
        maxSources: MAX_SOURCES,
        maxBytesPerSource: MAX_BYTES_PER_SOURCE,
        maxTotalBytes: MAX_TOTAL_BYTES,
        maxIdentityCandidates: MAX_IDENTITY_CANDIDATES,
        maxFacts: MAX_FACTS,
        maxPositions: MAX_POSITIONS,
        maxComparisons: MAX_COMPARISONS,
        deadlineMs: DEADLINE_MS,
      }),
    });
    guard.check();
    return result;
  } catch (error) {
    if (error instanceof CorroborationError) fail(error.code === 'LIMIT' ? 'RESOURCE_LIMIT' : 'SOURCE_BINDING_FAILED');
    if (error instanceof SourceIdentityCompositionError) throw error;
    if (error instanceof EvidenceStoreError) throw mapEvidenceError(error);
    fail("COMPOSITION_FAILED");
  } finally {
    guard?.dispose();
    for (const source of sourceRuns) {
      for (const draft of source.drafts) draft.positionBytes.fill(0);
      for (const draft of source.linkDrafts ?? []) draft.positionBytes.fill(0);
      for (const draft of source.attributionDrafts ?? []) draft.positionBytes.fill(0);
    }
    for (const source of input.sources) {
      source.document.bytes.fill(0);
    }
  }
}
