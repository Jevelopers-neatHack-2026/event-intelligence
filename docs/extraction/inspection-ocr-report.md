# Private local OCR inspection report

Refs [EI #12](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/12).
This separate consumer composes the existing media report with caller-supplied
static-image and scanned-PDF OCR observations. It does not change media report
schema/2, expose a public research API, or register the reserved
`inspection-adapters` gate as passing.

## Interface and byte domains

`composeInspectionOcrReport(input)` and
`validateInspectionOcrReport(reportBytes, expectedSha256, input)` are private
source imports from `src/extraction/inspection-report/ocr.mjs`. Both are pure:
they invoke no reader, callback, filesystem access, URL, provider or installer.
They return an immutable report, SHA256, byte length and defensive `copyBytes()`.
The local schema is `ei-local-inspection-ocr-report/1`.

The input includes the complete media/2 prerequisite input and exact report bytes
and digest. Its existing validator rechecks original sources, copied derivatives,
selected package/evidence-schema/support-matrix bytes, source snapshots, runtime
receipts and component execution summaries. A host-selected pin is a checked
selection, not canonical acceptance or authority.

Each OCR observation names its media observation and execution IDs and supplies
the exact declared native result plus its canonical JSON SHA256. Canonical JSON
sorts object keys, uses compact UTF-8 JSON and ends with one LF. Early native
refusals may own `sourceSha256: undefined`; only declared absent refusal metadata
is omitted. The report never fills a missing native source hash from the host's
source correlation. Unknown result properties, accessors, proxies, cycles,
sparse arrays and typed-array overrides are rejected before their hooks run.

| Evidence | Checked relationship | Authority retained |
| --- | --- | --- |
| Original encoded image/PDF | OCR source digest equals independently hashed prerequisite original bytes | Source authority remains unverified |
| Static-image RGBA | Copied raw bytes, length, dimensions, digest and opaque alpha match the declared OCR input | Encoded normalized PNG is a separate domain; no independent cross-decode equivalence is invented |
| Scanned page RGBA | Exact source, one-based page, raw digest, dimensions, pixels and page-point geometry match | OCR boxes use top-left pixels; no original PDF text-byte offsets are claimed |
| Word observations | Every word/page provenance, box, ordinal, confidence and total is bounded and consistent | Literal text is data; scores remain uncalibrated and review is required |
| Caller record | Exact observation/media/execution IDs, result digest and provided-source digest match a separately supplied bounded record | Supplied provenance, not a signature, issuer certification or proof that a suite generated that result |
| Component suite capture | Complete current 137-case image or 143-case PDF composition summary/TAP, source snapshot, child stderr and selected runtime-marker identities match | Suite coverage stays separate from the actual caller record |

`callerRecordBytes` uses `ei-local-ocr-caller-observations/1` with exactly
`schemaVersion`, `executionId`, `component`, `source`, and `records`. Its source
object is the selected media report's observed source identity. Each record has
exactly `id`, `mediaObservationId`, `resultSha256`, and
`providedSourceSha256` (nullable). The input also supplies its expected SHA256.
The actual consumer test records these fields from native results and retains the
full source/result capture. Structural callers can forge their own record, so
the report deliberately does not call it certified native output.

The inner OCR `sourceBinding: "caller-supplied-unverified"` survives a successful
byte join. The outer native composition's local byte-chain label also survives;
neither becomes an authenticated source or verified text. No-text-observed means
the bounded OCR returned no words. It does not prove that a document contains no
text. Refused and cancelled attempts remain distinct from later successful calls.
The report creates no expense, retry entitlement, permission or Finance ACK.

## Limits and incomplete outcomes

The prerequisite keeps all of its original limits. The additional wrapper allows
at most 32 OCR observations, two component executions, 1 MiB per result, 4 MiB of
result bytes in aggregate, 1 MiB per suite stream, 256 KiB per stderr stream,
512 KiB of selected OCR runtime-manifest bytes and an 8 MiB final report. Each
native result is additionally checked against its exact profile and effective
lower-only word, UTF-8 text and output limits; PDF totals span all pages.

The result is always `overall: "incomplete"`, with no evaluated acceptance IDs,
owner acknowledgements, fact inference or financial authority. A missing raw
copy yields `unbound-missing-raw-bytes`; a missing caller record leaves the result
separately supplied. Required missing formats, component refusals, absent runtime
receipts, mismatched modes, source drift and missing/failed/skipped/cancelled/TODO
execution cases cannot become passes. Invalid byte/hash/domain/version/geometry
joins throw a typed `InspectionReportError`; they do not repair the evidence.

Runtime marker bytes are selected evidence. Matching them to the verifier's
record does not reinstall/re-attest the runtime or certify an individual OCR
call. OCR and PDF result objects contain fixed engine/model/profile fields, not
their installed runtime manifest hashes. The image result's Pillow manifest
digest is separately checked against the prior media result/receipt.

## Verification

On the declared Linux x86_64, Node 22.23.3 and CPython 3.12.14 profile, first install
the exact locked local OCR and PDFium dependencies in their fresh checkout-local
runtime paths. Install or select the exact declared static-raster runtime and set
`EI_JPEG_WEBP_TEST_RUNTIME`, `EI_STATIC_IMAGE_OCR_RASTER_RUNTIME` (same canonical
directory), and `EI_JPEG_WEBP_TEST_WHEEL`. Installers fail on replacement or
mismatched pins; no alternate library/model is substituted.

```sh
node tools/verify-inspection-ocr-report.mjs --mode mock
node node_modules/typescript/bin/tsc --noEmit --strict --target ES2022 \
  --module NodeNext --moduleResolution NodeNext --lib ES2022,DOM --types node \
  --skipLibCheck false --noErrorTruncation \
  tests/inspection-report/ocr/types-consumer.mts \
  tests/inspection-report/media/types-consumer.mts \
  tests/inspection-report/types-consumer.mts \
  tests/extraction/static-image-ocr/types-consumer.mts \
  tests/extraction/scanned-pdf-ocr/types-consumer.mts
npm run typecheck
git diff --check
```

The dedicated route executes actual existing deterministic/text-PDF/media
consumers, actual image/PDF-to-OCR calls and both complete native composition
suites over synthetic local fixtures. Boundary mutation cases are synthetic and
are labeled separately. Required runtime unavailability is a failure/NOT_RUN,
never a skip credit. Optional capture directories must be outside the source
checkout; captured files use exclusive creation so an earlier attempt cannot be
overwritten. Native provider calls, OCR accuracy benchmarks, canonical mapping,
Creative acceptance and production-host authorization remain separate outcomes.

## Hosted evidence capture

The dedicated workflow retains its original uploads and additionally mirrors a
fixed synthetic evidence inventory into bounded log records. The two report
directories contribute fourteen media and twenty-four OCR capture files; two
runtime manifests and the six fixed files from the single fresh startup attempt
complete the successful forty-six-file capture. The startup manifest does not
select an attempt: the workflow admits exactly one ordinary attempt directory,
checks its timestamp/UUID name against both receipts, and refuses ambiguity.

Every selected file must be ordinary, stable and at most 4 MiB; the total is
limited to 16 MiB. All files are validated before any payload is emitted as
16 KiB base64 records with lengths and SHA256 values. Missing, unexpected,
oversized or ambiguous evidence fails the mirror step; original failed steps and
the always-run upload remain visible. This bounded fixture capture does not
change the production report's 8 MiB output limit. A future larger fixture needs
an explicit reviewed evidence transport decision.

The capture contains sanitized startup projections, not arbitrary initializer
stdout, environment values, credentials or native library binaries. Captured
source maps and manifests support independent byte and provenance checks; they
do not prove physical host rehash, complete source/pixel replay, hostile-host
containment, canonical adoption or accountable acceptance.
