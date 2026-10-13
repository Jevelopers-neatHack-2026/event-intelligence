# Internal privacy boundary scaffold

Status: local EI-09 preparation work on an isolated branch, implemented as dependency-free Node ESM for the Node 22 target. The modules and declarations are internal scaffolding. They are not the accepted EI API, `ResearchRequest`, shared-contract schema, identity authority, durable privacy store, or evidence that an application path is integrated. The canonical contracts and consuming routes remain prerequisites; EI-09 stays open.

## Evidence and release boundary

External source content is private by default. There is no substring-based or regular-expression-based public admission path. Candidate fields are copied through a strict key/type boundary and are only hints to a configured `reviewPublicFacts` adapter. That adapter must positively approve a small allowlisted fact set (`event_name`, `event_date`, `venue`) for the same tenant and exact source digest. If no reviewer is configured, it rejects, fails, returns malformed data, or approves a different tenant/digest, the session is quarantined and cannot publish. A reviewer that blindly approves candidates is a trust-boundary defect in that adapter; no verifier is installed by default here.

The tenant scope is an opaque runtime capability created only by `scopeForAuthenticatedRequest`. A trusted app adapter must supply `resolveTenant` and derive its result from the authenticated server-side request contract. Browser values, external source IDs, and candidate fields are not accepted as tenant authority. The callback and fixture tests do not authenticate requests, and no canonical identity/authorization contract is present.

`html`, `ocr_text`, `pdf_text`, `pdf_metadata`, and `plain_text` are kept as private source content for a trusted reviewer. This module does not parse HTML visibility, perform OCR, extract PDF text or metadata, or redact text, images, QR codes, or binary files. Binary/image/PDF input, attendee CSV, and unsupported modalities are always quarantined. A future contract-backed producer must supply a suitable verifier/extractor and test the actual end-to-end path.

## Retention, handles, and cancellation

Originals live in one in-memory retention map with a fixed TTL measured by a monotonic process clock. Sessions retain only opaque source tokens, not raw content. Restart uses the original expiry and never extends it. Every read and processing commit rechecks the tenant and expiry. Access expires at the deadline; the expired map entry is physically released on access or `purgeExpired()`, so a production adapter must schedule a purge sweep. Cancellation aborts any in-flight reviewer read capability, deletes the original, and makes late review results inert. Publication is a synchronous commit: if cancellation happens first, publication fails; if publication commits first, cancellation returns false. Publication also deletes the raw original. Quarantined originals remain available only until the original TTL or an earlier cancellation.

Explicit private review requires both an injected actor-level authorizer and an injected consumer callback. The callback is trusted app code and must enforce the accepted review contract. This scaffold does not provide encryption at rest, durable/distributed retention, revocation across processes, or guaranteed memory zeroization. JavaScript cannot erase an immutable string already retained by the caller or by an in-flight trusted callback that read it before cancellation; the boundary invalidates future reads and drops its own stored reference.

Issued source handles, sessions, results, derivatives, telemetry records, decision states, and creative payload handles are opaque objects authenticated by issuer-owned `WeakMap` registries. Copies, prototype wrappers, JSON round-trips, altered tenant labels, and forged contents do not carry issuance authority. Diagnostics contain only generated record IDs and fixed state, modality, trust, reason, and category codes; they do not contain source text, candidate values, tenant IDs, or external identifiers.

## Local flow adapters and action fence

`src/privacy/flows.mjs` is a local test adapter for tenant-partitioned cache, telemetry, decision, and creative outputs. It accepts only genuine same-tenant derivatives and wraps each output in an issuer-owned opaque handle. Serialization validates scope first, snapshots only dense ordinary arrays through own data descriptors, verifies every issuer handle, and builds fresh output containers without caller map/species/JSON hooks. Invalid caller inputs produce a fixed boundary error. It is not the application's cache, trace system, decision store, prompt builder, or creative consumer. The tests verify the local serialization path only; they do not prove prompt non-contamination or integration with a live application route.

`src/security/content-boundary/policy.mjs` keeps trusted capability, billable-unit, and approval-set checks independent from optional injection-classifier annotations. Only trusted composition-root code should wrap a callback with `createTrustedInjectionClassifier`; the returned brand records that choice but does not inspect or prove the callback safe. `optionalInjectionSignal` rejects raw callbacks and never invokes them. Boolean annotations are synchronous. An ordinary native Promise is rejection-observed with the captured intrinsic `Promise.prototype.then`; its eventual value is discarded because the API is synchronous. A promise with an own `constructor`, a Promise subclass with custom species, a Promise proxy, or a plain thenable is outside the supported result contract. The trusted adapter must handle rejection before returning those values and must not alter runtime Promise intrinsics. The adapter and callback execute in-process and are not sandboxed. Classifier misses, failures, malformed results, or positive signals cannot change the deterministic authorization result. This is not an accepted approval contract, tenant/project/asset/version binding, cumulative financial ledger, or production action authority.

## Private association to retained source context

Publication now also keeps a private, revocable association between the genuine
derivative and the reviewed source digest, bounded by the original source expiry.
It contains no raw source and does not change the public derivative or flow
serialization. The adjacent [reviewed source-context adapter](reviewed-source-context.md)
can reopen matching complete evidence through the actual EvidenceStore and require
an explicit trusted context review plus current host authority. Its output stays
tenant-private; three published facts and a matching digest alone never authorize
complete source context or downstream model use.

## Local verification

Run the dependency-free fixture suites with Node 22:

```sh
node --test tests/privacy/*.test.mjs tests/security/injection/*.test.mjs
```

Check the public ESM declarations with the pinned TypeScript 7.0.2 development compiler:

```sh
node node_modules/typescript/bin/tsc --noEmit --strict --module NodeNext --moduleResolution NodeNext --target ES2022 tests/privacy/types-consumer.mts
```

The consumer includes valid API use plus compile-time rejection checks for an incorrect authenticated request and a forged derivative handle. `.mts` is a type-check fixture only; runtime modules remain `.mjs` and do not use a TypeScript loader.

The tests cover default-private admission, a positively reviewed synthetic public fixture, copied-handle rejection, tenant isolation, cache/telemetry/decision/creative serialization, binary and text modality handling, private-review access, retries, cancellation scheduling, and retention expiry. They are local unit fixtures, not release evidence. The canonical EI API, authenticated application scope, actor authorization, trusted public-fact verification contract, production storage, actual OCR/PDF/image processing, and downstream route/prompt integrations remain absent. AGT-04, JEV-EI-06, CON-02/03, and full EVAL-04 acceptance are still pending; no provider or paid calls are made here.
