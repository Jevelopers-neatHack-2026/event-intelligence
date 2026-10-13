# Private supported-reader outcomes

This additive EI-private boundary invokes the existing PNG, JPEG/WebP, scanned-PDF
and text-PDF readers. It gives their bounded resource refusals a common
RESOURCE_LIMIT category while retaining each original detailed code and the exact
original reader result object. It is a local issue8 AC3 contribution, not an
accepted ResearchAPI error enum, fact, permission, canonical interface, inspection
acceptance or provider result. No package export changes are made.

## Entry points

Import from src/extraction/inspection-outcomes/index.mjs:

- readPngOutcome(bytes, options)
- createJpegWebpOutcomeReader({ runtimeDirectory }).read(bytes, options)
- readScannedPdfOutcome(bytes, options)
- readTextPdfOutcome(bytes, options)

The JPEG/WebP factory uses the existing trusted, explicit offline-install
directory. The native reader still verifies its pinned runtime. No executable,
decoder, worker, arbitrary result or callback can be substituted through this
interface. The internal helper module is implementation/test machinery, not an
alternative consumer endpoint.

Inputs are genuine non-proxy Uint8Array/Buffer views on ordinary ArrayBuffer
storage. The boundary creates an intrinsic canonical view without caller getters,
iterators or coercion. The actual reader then copies it synchronously. Shared,
subclassed and proxy storage is refused. Options must be plain own data properties.
Unknown keys, accessors, proxies and nonnumeric limit values fail closed; numeric
range validation remains in the actual reader. Boundary failures are explicitly
distinguished from native reader refusals and contain no invented source hash.

All readers accept signal, timeoutMs and maxOutputBytes. The raster readers also
accept their existing lower-only deadlineAtMs; text PDF instead accepts
maxTextCodeUnits and retains its relative timeout only. The new text-PDF subset
excludes onPageComplete. A genuine AbortSignal is required. The text path forwards
abort state/listener operations through captured native intrinsics, so overridden
caller signal methods cannot execute. There is no additional timer, listener,
retry, deadline renewal, queue, admission policy or stronger cross-reader deadline
claim. Existing child termination and reap behavior remains in the actual readers.

## Result semantics

Every result has schemaVersion ei-private-inspection-outcome/1 and a reader
discriminator. A reader-result retains result by reference:

- category OBSERVATION and reason null preserve decoded, observation or no-text.
  The original incomplete-pixels-only/incomplete-text-only, requiresInspection,
  hashes, pages, geometry, boxes and fresh-copy accessors remain unchanged.
- Resource refusals use category RESOURCE_LIMIT and reason equal to the original
  detailed code. The original rejected object and code remain in result.
- Other reader refusals use their original code as category and reason, preserving
  cancellation, timeout, queue, malformed input, profile, native isolation,
  unavailable runtime and decoder distinctions.
- A boundary-failure has a fixed sanitized reason and no native result. Unexpected
  failures never emit arbitrary exception messages, input bytes or paths.

| Reader | Original resource-family codes |
|---|---|
| PNG | INPUT_TOO_LARGE, DIMENSION_LIMIT, RESOURCE_LIMIT, OUTPUT_LIMIT |
| JPEG/WebP | INPUT_TOO_LARGE, DIMENSION_LIMIT, RESOURCE_LIMIT, OUTPUT_LIMIT |
| Scanned PDF | INPUT_TOO_LARGE, PAGE_LIMIT, DIMENSION_LIMIT, PIXEL_LIMIT, STRUCTURE_LIMIT, OUTPUT_LIMIT |
| Text PDF | INPUT_TOO_LARGE, PAGE_LIMIT, DIMENSION_LIMIT, TEXT_LIMIT, RESOURCE_LIMIT, OUTPUT_LIMIT |

DIMENSION_LIMIT is a geometry-policy refusal: it can mean invalid geometry or a
ceiling refusal. In particular, scanned-PDF zero/fractional geometry already uses
this code. The common category does not assert that every such input was a valid
oversized image. The original code is retained, and the boundary neither reparses
the source to guess a cause nor changes malformed/profile classifications.

No rejected result gains pages, pixels or partial-success status. No-text is still
an incomplete text observation; it is not a resource failure or proof of visual
inspection. Existing callers of the original readers remain unchanged.

## Required validation

The dedicated initialized route is:

    node tools/verify-inspection-outcomes.mjs --mode mock
    node --test tests/extraction/inspection-outcomes/verifier.test.mjs

The first requires exactly73 cases, with zero failures, skips, cancellations or
TODOs. Its synthetic byte fixtures pass through actual supported native readers:
PNG/zlib, pinned Pillow JPEG/WebP, pinned PDFium and pdfjs-dist text PDF. Native
positive/provenance/fresh-copy checks accompany25 actual resource-input variants,
malformed/profile/remote refusals, invalid geometry, active close/cancel/recovery,
queued cancellation and hostile input/options. Parent preflight refusals remain
distinguished from child decode; a resource test does not imply native decoding
began. Text-PDF outline-depth input is a literal synthetic PDF reaching the existing
structural bound, not an injected error result. Four identity controls use genuine
direct-reader results to verify exact reference retention by the private wrapper.

Five separate verifier-only inventories cover complete, missing, reduced, skipped
and failed cases. Their expected failing child summaries are preserved. They are
synthetic runner controls, not native product passes. The production verifier never
discovers these controls recursively.

The dedicated workflow installs the existing hash-pinned Pillow12.3.0 and
pypdfium2 5.14.0 wheels through their unchanged offline installers, plus the locked
Node22.23.3/pdfjs/TypeScript dependencies. No OCR runtime or new dependency is
introduced. It runs the five strict type consumers (this boundary and four original
readers), project typecheck, dependency154 with the current actual graph, and
merge-relative whitespace checking. Required setup/test failure cannot become a
skipped pass. Raw native and control stdout/stderr are printed and retained.

Existing shared verification selects tests/extraction nonrecursively plus the
explicit PDF folder; existing native verifiers have fixed file inventories. These
new native-required tests therefore run only in their initialized dedicated route,
not inadvertently in the mock extraction/security jobs. No shared selector or
existing required inventory is changed.

Evidence must identify the actual commit, runtime, commands and result counts.
This document describes required behavior and checks, not an execution receipt.
Hosted/local/source reviews must retain their own provenance. This slice does not
close issue8, gate22 or epic1 and supplies no supported-source journey, foreign
wire election, accepted facts, rights, Finance custody or consumer ACK.
