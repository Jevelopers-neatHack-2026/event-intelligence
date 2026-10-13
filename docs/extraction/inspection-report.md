# Local inspection report composition and validation

The private `src/extraction/inspection-report/index.mjs` module composes deterministic report bytes from existing extraction results, retained original source bytes, execution-output bytes and explicitly selected artifact pins. It implements the report-integrity part of the [EI12 aggregate refinement](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/12). It does not register or pass the proposed full `inspection-adapters` route.

The output has `overall: "incomplete"`, `acceptance.evaluated: false` and empty satisfied IDs and owner acknowledgements. Integrity validation checks bytes and joins. It does not authenticate a host, prove a claimed source revision was executed, establish accepted schema mappings, or supply a provider, rights, Finance or consumer grant.

## Supported inputs

Two existing private result types are supported:

| Component | Consumed result | Retained limitations |
| --- | --- | --- |
| Deterministic HTML, XHTML, plain text and JSON-LD | `ExtractionResult` from `extractDeterministically` | Original UTF-8 source slices, separate entities/conflicts/ambiguities, explicit limitations, candidate data requiring review |
| Text PDF | `PdfTextReadResult` from `readTextPdf` | Original PDF hash, exact decoder/config, ordered pages, approximate viewport geometry; `incomplete-text-only`, `requiresInspection: true`, or typed rejection |

The composer performs no retrieval, parsing subprocess, OCR, provider call, filesystem read or permission change. The caller supplies completed component results and corresponding bytes. The maintained tests execute the real deterministic extractor and Linux-isolated text-PDF reader over synthetic repository fixtures.

PNG, JPEG/WebP and scanned-PDF rendering are separate component-owner work. Their formats can be listed in the selected support matrix; missing observations remain missing. This version does not accept those readers' result types, silently substitute text-PDF output for scanned-page rendering, or convert pixels into facts. A later reviewed local adapter can extend the internal format once its actual source and result contract are available. Metered inspection and canonical composition additionally require their accepted host/provider/Finance mappings.

## Selection and byte binding

`composeInspectionReport(input)` requires:

- `expectedPins`: an exact selected repository SHA, package version and original package-file hash, evidence schema ID/version/pointer and original schema-file hash, and support-matrix version/original file hash.
- `artifacts`: the actual package, evidence schema and support-matrix JSON bytes. Every original byte hash is recomputed. The package's `version`, schema's `$id` and explicitly selected JSON Pointer value, and matrix's version must match. The pointer is an exact existing field selection; it does not infer a wire adapter or foreign alias.
- `requiredMode` and `mappingState`. Mapping is only `missing`, `held` or `selected-unaccepted`; there is no accepted/granted value.
- `executions`: unique component execution descriptors with the same pins, expected case count, exit/signal outcome, mode/origin and actual stdout bytes.
- `observations`: unique IDs, component/format, corresponding execution ID, same pins, original source bytes and expected original hash, plus the actual result. Deterministic observations also bind exact URL/fetched-at/content-type metadata and full declared lower-only extraction limits.

These are caller-selected pins, not authority. A caller can provide fabricated source metadata or execution output; matching hashes cannot authenticate its origin. Consumers still need trusted acquisition and accountable acceptance. The module does not fetch schema `$ref` URLs, and the test's existing copied candidate EIP schema remains an unaccepted byte-selected candidate.

The support matrix is a deliberately local format:

```json
{
  "schemaVersion": "ei-local-inspection-support-matrix/1",
  "version": "your-explicit-local-selection/1",
  "requiredFormats": ["html", "plain-text", "text-pdf", "png", "jpeg", "webp", "scanned-pdf"]
}
```

The supported vocabulary additionally includes `xhtml` and `json-ld`. Required formats must be unique and nonempty. Selecting a smaller inventory changes only the explicitly displayed `declaredCoverage`; it cannot waive full EI12 scope. Missing, held, failed or skipped prerequisite evidence never becomes full acceptance.

## Preserved hash domains

| Field | Exact hashed bytes / meaning |
| --- | --- |
| `pins.*.sha256` | Original caller-supplied package/schema/matrix file bytes, including their formatting |
| `prerequisiteDeterministicReport.sha256` | Complete original deterministic execution stdout, not merely its last summary object |
| `observations[].source` | Retained original source bytes, unprefixed SHA-256 |
| Deterministic `view.nativeSourceHash` | Existing extractor's `sha256:`-prefixed original source hash; must equal the recomputed source hash with its prefix |
| PDF `view.nativeSourceHash` | Existing reader's unprefixed original PDF hash; not the derived text or result JSON hash |
| `observations[].result` | Complete component result as this version's canonical JSON; the module validates its relevant source/geometry/limit invariants before hashing |
| Deterministic `locators[].rawSha256` | Exact retained original UTF-8 byte slice, matched byte-for-byte to `rawValue` |
| PDF `pages[].boxes[].textSha256` | UTF-8 of the derived text item, explicitly labeled `derived-text-utf8`; not an original PDF offset or raw-source hash |
| Returned artifact `sha256` | Exact emitted canonical report bytes, outside the hashed report to avoid a self-reference |

The report contains hashes, counts, statuses, limits and locators, not source URLs, raw extracted text or original source bytes. It is still private local evidence: hashes and geometry are not an authorization or anonymization guarantee. Retention/disclosure of original bytes, results and reports remains the host's responsibility.

The component views project only declared fields. Extra deterministic locator and native PDF limit metadata is omitted from the report; the complete original component result, including that metadata, remains bound by its separate result digest. Unknown fields in selected pins, including nested package/schema/matrix records, are rejected at expected-selection, execution and observation boundaries. Allowed inventory IDs and selected pin identifiers/version strings remain explicit caller-selected data; the projection does not classify or scrub their content.

The extractor currently does not echo its effective limits. Its `declaredLimits` are validated against the checked-in ceilings and labeled caller-declared; the composer does not claim to reconstruct an execution's settings. The native PDF output does echo checked limits and these must match the current fixed ceilings and permitted lower text/output caps. Its zero network counter is reader API evidence, not production native-host containment.

## Execution outcomes

The `verify-summary` adapter accepts exactly one `VERIFY_SUMMARY_JSON=` line for `deterministic-extraction`. It validates case/mode/exit, case counts and the success relationship. Duplicate lines or JSON keys, inconsistent totals, false pass flags and mismatched pins refuse.

The `node-tap` adapter accepts the existing flat text-PDF TAP output: exactly one top-level plan and each terminal count, sequential top-level verdicts, and matching pass count. Nested suites or another component's reporter need a reviewed adapter. A pass footer cannot erase a preceding failure. The entire stdout byte hash is retained in both formats.

Failed, skipped, canceled, TODO, interrupted or missing required cases keep coverage incomplete. Expected and actual counts are distinct. The only locally complete execution mode is `mock` with `origin: "local-synthetic"`; a synthetic execution cannot be labeled live. Recorded output remains recorded and cannot supply current execution completeness. Requiring sandbox/live evidence produces an incomplete result; this module does not execute or authorize it.

There can be at most one execution descriptor per implemented component in one report. Competing summaries, duplicate IDs or the same component/source/format observation under a second ID refuse. A retry produces a new report from its new inputs. The caller retains prior report bytes and digests; the module has no mutation, implicit retry, network dispatch or replacement operation.

## Validation and copies

```js
import {
  composeInspectionReport,
  validateInspectionReport,
} from "../../src/extraction/inspection-report/index.mjs";

// input includes actual retained bytes/results and explicitly selected pins.
const artifact = composeInspectionReport(input);
const reportBytes = artifact.copyBytes();
const checked = validateInspectionReport(reportBytes, artifact.sha256, input);
// checked.report.overall is always "incomplete".
// Persist bytes/digest in the host's authorized evidence store if appropriate.
```

`validateInspectionReport` recomputes every source/result/artifact/summary join and the complete derived report, then requires exact canonical byte equality. Changing the report and recomputing its outer hash is insufficient. Duplicate JSON keys, unsupported report/matrix/component versions and alternate JSON whitespace/order are rejected instead of normalized during validation. Sorting uses code-unit ordering and does not depend on locale. Returned views are deeply frozen; each `copyBytes()` returns a new owned copy.

Malformed or oversized inputs throw `InspectionReportError` with a stable code such as `PIN_MISMATCH`, `SOURCE_HASH_MISMATCH`, `SOURCE_SLICE_MISMATCH`, `INVALID_LOCATOR`, `FALSE_PASS`, `DUPLICATE_SUMMARY`, `RESOURCE_LIMIT` or `REPORT_BYTES_MISMATCH`. Messages contain no input data. Source that a component could not bind to an original hash cannot be promoted into a source-bound report; retain that original unsupported result separately.

## Bounds

| Bound | Maximum |
| --- | --- |
| Observations / execution descriptors | 32 / 16 |
| One original source / aggregate source bytes | 20 MiB / 64 MiB |
| Each package/schema/matrix artifact | 1 MiB |
| Each execution stdout | 512 KiB |
| Each canonical component result | 4 MiB |
| Emitted report | 2 MiB |
| JSON depth / nodes per copied or parsed value | 64 / 100,000 |
| Execution counts | 100,000 |

Existing component bounds remain in force: deterministic source is at most 2 MiB, and PDF pages/text/geometry retain the [reader limits](text-pdf.md). This synchronous, byte-bounded composer adds no scheduling service, host RSS guarantee or global monetary budget. Byte inputs must be ordinary `Uint8Array` or Node `Buffer` views without shared backing memory or overridden native metadata/conversion properties. Native view slots determine the copy and byte bound; input getters are not consulted. Strings are not file paths and are refused. Proxies are refused before reflection. Execution and observation inventories must be dense ordinary arrays containing own enumerable data elements; methods, extra properties, accessors and subclasses cannot replace per-record validation. Accessors in JSON records, class instances, cycles, sparse arrays, nonfinite/lossy JSON values and duplicate JSON keys are refused.

## Actual verification route

```sh
node tools/verify-inspection-report.mjs --mode mock
node node_modules/typescript/bin/tsc --noEmit --strict --target ES2022 \
  --module NodeNext --moduleResolution NodeNext --lib ES2022,DOM \
  --types node --skipLibCheck false --noErrorTruncation \
  tests/inspection-report/types-consumer.mts \
  tests/extraction/types-consumer.mts tests/extraction/pdf/types-consumer.mts
npm run typecheck
```

The dedicated `local inspection report integrity` workflow requires Linux/Node22.23.3, **65 cases in two explicit test files**, no skipped/canceled/TODO/failed cases, the three strict consumers and project types. Fixtures obtain real output from the existing deterministic runner **50/50** and existing text-PDF suite **14/14**, and consume actual deterministic HTML/text and native PDF results. These nested counts overlap other component gates; do not add them as independent global acceptance cases. The selected `dc97...` fixture pin and candidate schema selection are labeled synthetic host inputs, not a claim that the report function attested a Git checkout.

The machine line is `INSPECTION_REPORT_VERIFY_JSON=` with case `inspection-report-integrity` and `fullInspectionAdaptersAcceptance:false`. Missing/extra cases, duplicate root summaries, unavailable Linux/Node runtime and test failures exit nonzero. `--mode live` is blocked without starting a child. No existing generic runner case, package export, dependency, media reader or owner's source is changed.

Full EI12 still needs supported media/inspection composition, accepted derived evidence and canonical bindings, authentic provider/attempt/usage/hold and host authority, accountable paired consumer/release evidence, and owner acceptance on the exact release. The report preserves those gaps rather than closing the issue, gate or epic.
