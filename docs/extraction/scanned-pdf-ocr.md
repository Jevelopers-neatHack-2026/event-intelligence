# Private scanned PDF to OCR composition

Refs [EI #12](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/12),
[EI #8](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/8), and
[gate #22](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/22).
This local slice connects the bounded image-only PDF reader to the bounded English OCR reader. It produces literal, review-required observations with a verified local source-to-pixel chain. It establishes no accepted facts, permission, canonical contract, Finance event, provider result or global acceptance, and adds no package export.

## Supported byte journey

The private `src/extraction/scanned-pdf-ocr/index.mjs` module exposes `readScannedPdfOcr(Uint8Array, options?)`. It snapshots the exact supplied PDF bytes, hashes that snapshot, and passes those bytes to the actual PDF reader. The PDF reader admits only its existing `classic-full-page-rgb-flate-v1` profile: a strict classic PDF structure containing one full-page embedded opaque RGB8 Flate image per page. Its complete source parser and independent PDFium image/raster checks remain in force. See [the PDF profile](scanned-pdf.md) for the exact supported container, page, image and resource restrictions.

The composition validates the complete PDF result and every page descriptor before invoking a captured `copyRgbaBytes()` method. It copies the returned pixels, independently hashes the copy, requires exact length and geometry, and verifies that every alpha byte is 255. OCR receives that copied raster, the exact original PDF hash, its one-based page number and the verified raw-RGBA derivative hash. Encoded PNG bytes are not substituted for the raw pixel hash.

Pages enter the actual local OCR reader sequentially. The composition verifies the fixed English model and engine identities, both distinct native enforcement profiles, the source/page/derivative relationship, requested resource limits, literal token metadata, exact UTF-8 totals and every pixel box. It constructs new frozen page/word/provenance objects; neither a source-selected function nor mutable pixel bytes escape in the final observation.

```js
import { readScannedPdfOcr } from "../../src/extraction/scanned-pdf-ocr/index.mjs";

const result = await readScannedPdfOcr(suppliedPdfBytes, {
  signal,
  timeoutMs: 20000,
  maxWords: 2048,
  maxTextBytes: 32768,
  maxOutputBytes: 1048576,
});

if (result.kind === "observed") {
  for (const page of result.pages) {
    for (const word of page.words) {
      reviewLiteralObservation(word.text, word.box, word.confidence, word.provenance);
    }
  }
}
```

`kind: "observed"` always remains `completeness: "incomplete-unverified-ocr"`, `requiresReview: true` and `sourceAuthority: "unverified"`. The outer `sourceBinding: "local-pdf-reader-byte-chain"` records this caller's verified byte relationship. Each OCR word retains the OCR reader's narrower `caller-supplied-unverified` origin classification; the composition does not relabel OCR itself as an origin authority. Original PDF dimensions are in points; token boxes use top-left derivative pixels. The exact source hash, one-based page, derivative hash and raster geometry accompany every word.

The fixed printed-English LSTM model and single-block segmentation can misread unfamiliar layouts, scripts, rotations, handwriting and poor scans. Confidence remains an **uncalibrated engine score**, including zero confidence, and low-confidence words are retained. No inferred fields, reconstructed whitespace, facts or rights are attached. `no-text-observed` means that this engine/profile returned no words; it does not establish that the page contains no text. Recognized instructions, URLs and prices remain untrusted literal observations.

## One overall budget and lifecycle

| Boundary | Maximum |
| --- | ---: |
| Exact copied PDF bytes | 16 MiB |
| Pages | 4 |
| Raster dimension | 4,096 pixels |
| Pixels across the entire PDF | 4,194,304 |
| Raw pixel bytes across the entire PDF | 16 MiB |
| Words across all pages | 2,048 |
| Combined UTF-8 token bytes across all pages | 32,768 |
| Complete serialized observation | 1 MiB |
| Active composition / queued compositions per module instance | 1 / 4 |
| Default / maximum overall allowance | 20 / 30 seconds |

Callers may lower the overall timeout, aggregate word count, aggregate token bytes and complete report byte limit. Individual words and required pages are never silently truncated. After any stage refusal, budget exhaustion, cancellation or timeout, the result contains no partial successful page collection. If an aggregate word/text allowance is exhausted while pages remain, the next OCR call is not started; the caller cannot assume an unexamined page would have contained no text.

The original monotonic deadline starts before option validation and PDF snapshot/hash. Source copying, queue wait, native runtime verification and initialization, PDF decoding, each pixel copy/hash, every OCR call, parent protocol validation, freezing, serialization and final promise delivery spend that same allowance. The composition passes the exact absolute deadline to both readers along with a lower relative stage allowance. The four-file predecessor overlay only adds `deadlineAtMs?: number` to those private reader options; its value is in **the same Node process's `performance.now()` timebase**. Each reader applies `min(ownStart + timeoutMs, deadlineAtMs)` and checks it before snapshotting input. A delayed handoff cannot renew the original allowance. A distant absolute value cannot raise the existing relative cap. Standalone callers that omit it retain their existing behavior. The returned `limits.timeoutMs` remains the elected relative cap; it is not a serialized absolute timestamp.

An active cancellation/expiry aborts the owned stage signal once. The composition awaits the actual stage promise, which settles only after the reader's owned child has closed. It does not race away an active child or assign a new cleanup allowance. The next composition cannot consume the active slot until the stage settles. Queued cancellation/expiry starts no stage and does not cancel an unrelated active request. A new independent operation can recover after refusal. The private test factory supplies controlled stage functions only for deterministic boundary tests; the supported index always imports the actual fixed PDF and OCR readers.

Fixed sanitized refusal codes distinguish invalid admission, `PDF_REJECTED`, `OCR_REJECTED`, protocol failure, aggregate output limits, queue limits, cancellation and timeout. A recognized component refusal may retain its existing private code and page/stage identity. Raw exceptions, child stderr, private abort reasons or transcripts are not exposed. These codes do not redefine the foreign Research API enum.

## Native runtime and reproduction

This composition adds no dependency, native executable, model, syscall policy or provider. It uses both existing trusted offline installations under their separately measured native restrictions: [PDFium rasterization](scanned-pdf.md#native-restrictions-and-their-measured-scope) and [Tesseract recognition](local-ocr.md#native-and-process-boundary). Each child independently initializes its exact trusted library/model closure before media, installs its mandatory `no_new_privs`/seccomp profile and executes its eight denial controls. Their policies and dependency receipts stay distinct. Eight controls are deliberate enforcement checks, not a count of access attempts made by an input. No JavaScript guard, namespace grant or complete host-containment claim is added here.

Use Linux x86_64, Node 22.23.3 and CPython 3.12.14 with the declared compatible native host. From this exact checkout:

```sh
python tools/scanned-pdf/install.py --wheel /approved/path/to/pypdfium2-5.14.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
python tools/local-ocr/install.py --archives /approved/path/to/exact-ocr-archives
npm ci
node tools/install-typescript-host.mjs
node tools/verify-scanned-pdf-ocr.mjs
node tools/verify-scanned-pdf.mjs
node tools/verify-local-ocr.mjs
./node_modules/.bin/tsc --noEmit --strict --target ES2022 --module NodeNext --moduleResolution NodeNext --lib ES2022,DOM --types node --skipLibCheck false --noErrorTruncation tests/extraction/scanned-pdf-ocr/types-consumer.mts tests/extraction/scanned-pdf/types-consumer.mts tests/extraction/local-ocr/types-consumer.mts
npm run typecheck
```

The predecessor installers can also acquire only their exactly pinned development archives when invoked without the offline path option. Installation is explicit; runtime calls never download or provision. Preserve the existing lock, source provenance, bundled license/notice inventories and each host-specific loaded-file receipt. The composition does not replace or repin either dependency. A changed or unavailable runtime fails its required route rather than producing a skipped pass.

## Evidence and still-open scope

`tools/verify-scanned-pdf-ocr.mjs` requires all **143** maintained cases with zero failures, cancellations, skips or TODOs: 27 admission, 69 separately simulated result-protocol, 13 lifecycle (including an actual delayed native-reader handoff), 16 actual predecessor deadline-option cases, and 18 actual composed native caller cases. The native caller cases include real PDFium-to-Tesseract execution on owned synthetic PDF/raster fixtures, original and derivative hash checks, malformed/active/remote-resource refusals, aggregate limits, cancellation between pages and during OCR, actual child close/recovery, and the final synchronous deadline/abort boundary. These are synthetic source fixtures with real native execution, not public-media OCR accuracy or provider evidence. The separate 99-case PDF and current 188-case OCR routes cover their broader parser, native enforcement and lifecycle boundaries affected by the deadline overlay. Earlier 122-case OCR evidence remains historical and bound to its recorded revision.

The verifier records the actual Git revision/tree and source byte/mode map, exact command, runtime manifest digests, TAP counts and raw output hashes. Each attempt gets its own directory, including failures; the latest pointer does not replace them. The dedicated workflow installs both exact dependencies, runs the composed cases and three strict consumers, and preserves the complete attempt directories and runtime/provenance receipts. The two predecessor workflows also trigger on their changed reader/type files. Whole-candidate review and current hosted checks remain required before merge.

This slice does not broaden the strict PDF profile or establish the separate PNG/JPEG/WebP pixel bridge. Application inspection-report composition, durable source/derivative permissions, correction propagation, candidate-fact interpretation, canonical contracts, metering and accountable consumer/master acceptance remain their owners' scopes. OCR observations do not automatically enter a creative handoff or close EI12 or gate22.
