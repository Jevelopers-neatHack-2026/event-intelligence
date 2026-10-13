# EI-private retrieval outcomes, version 1

This opt-in relative-import interface maps the existing SafeFetcher transport into
fixed local outcomes. It is not a package export, accepted Research API, shared
contract, inspected fact, permission decision, deployed admission boundary, or
proof of a successful public-source journey. Refs #8 and #22 remain partial.

## Supported entry point

Import createLocalRetrievalOutcomes from
src/security/retrieval-outcomes/index.mjs. Call the zero-argument factory once per
local run, then use fetch(url, { signal }) or fetchSvgAsset(url, { signal }).
Both methods use one retained, real SafeFetcher, its native transport, direct
address pinning, request and aggregate-byte counters, and four-slot semaphore.
The factory accepts no callbacks, resolver options, credentials, caller headers,
policy or limit overrides. Method options allow only a data-property AbortSignal.

Each result has schema ei-private-retrieval-outcome/1 and one of two shapes:

- retrieved: transportComplete is true and document is the original completed
  SafeFetcher document. Its object identity and private provenance are retained.
  Its bytes have the existing mutable Uint8Array ownership contract. Callers must
  copy bytes if they need a separate buffer. No new permission or fact is inferred.
- refused: transportComplete is false, with fixed code and reason fields only.
  There is no document, partial byte buffer, URL, source excerpt, message, stack,
  cause, supplied abort reason, or arbitrary error property.

## Local mapping

| Original internal reason | Local outcome code | Meaning |
| --- | --- | --- |
| POLICY_DENIED | DESTINATION_BLOCKED | Existing URL, address or redirect policy refused the request |
| RESOURCE_LIMIT | RESOURCE_LIMIT | Existing byte, image-header or aggregate resource bound |
| REDIRECT_LIMIT | RESOURCE_LIMIT | Existing redirect limit, including SVG single-hop refusal |
| REQUEST_LIMIT | RESOURCE_LIMIT | Existing shared per-fetcher request quota |
| UNSUPPORTED_MEDIA | RESOURCE_LIMIT | MIME or supported transport signature refused |
| DEADLINE_EXCEEDED | RESOURCE_LIMIT | Original monotonic fetch deadline expired |
| DNS_FAILURE | DNS_FAILURE | Name resolution failed; not evidence of destination denial |
| TRANSPORT_FAILURE | TRANSPORT_FAILURE | HTTP/socket/TLS failure, including unsupported status |
| CANCELED | CANCELED | Genuine caller AbortSignal canceled the request |
| Unsupported wrapper input | INVALID_INPUT / INVALID_INPUT | No transport is attempted |
| Unknown error shape/code | INTERNAL_FAILURE / UNRECOGNIZED_FAILURE | Fixed fail-closed refusal |
| Unexpected internal result | INTERNAL_FAILURE / UNRECOGNIZED_RESULT | No unproven result returned |

The original reason remains explicit: a timeout, unsupported MIME, redirect
limit and byte ceiling are not interchangeable observations. Existing callers
still receive the unchanged RetrievalError codes. In particular,
private-retrieval.mjs still uses POLICY_DENIED for its durable access-restriction
branch; this wrapper does not intercept or modify that consumer.

The wrapper performs no retry. It retains the fetcher's original 30-second
queue-inclusive budget and additionally checks a ceiling measured once at wrapper
entry and the native AbortSignal immediately before returning a document.
Validation does not invoke URL coercion, option getters or proxy traps. Unsupported
factory arguments produce an invalid reader whose calls return INVALID_INPUT.
The internal bridge is trusted repository code for fixtures/composition only; it
captures the real SafeFetcher prototype methods and cannot replace them with
receiver-owned callbacks. A forged receiver cannot pass the fetcher's private
field access and cannot perform transport.

## Resource and decoder boundary

This is transport outcome mapping. Header dimensions are not a native raster
decode. PNG, JPEG/WebP, scanned-PDF, text-PDF and OCR readers retain their separate
private supported profiles, process boundaries, detailed errors and bounded
normalization results; their codes are not adapted here. GIF, arbitrary PDF
content, animations and every other unsupported decoder case remain outside those
declared subsets. This file does not widen any decoder profile or claim that a
native reader's refusal already maps into this interface. The completed transport
document still requires the existing independently bounded content inspection.

No browser fallback, active-script execution, access bypass, provider invocation,
credential provisioning, financial settlement, canonical adoption or downstream
consumer acknowledgment is added.

## Validation and evidence

The dedicated verifier requires exactly 35 maintained cases. They use synthetic
source bodies, real local loopback HTTP, the existing factory-minted resolver
seam, actual sockets and streams, decompression, cancellation and the unmodified
30,000ms slow-stream deadline. These are mock-mode controlled fixtures, not live
public-provider results. The PNG header fixture only checks transport dimensions.

Coverage includes zero forbidden dials, public-to-private redirect refusal,
original document provenance, SVG single-hop handling, DNS/transport distinction,
HTTP 206 rejection, MIME/magic mismatch, wire and gzip limits, shared request and
concurrency limits, active/queued cancellation, actual response closure and
recovery. Four separate verifier controls prove missing, reduced and skipped
required inventory cannot pass. Strict fixtures cover this private API and the
unchanged package API. The existing security verifier and its 110-case inventory
are not edited.

Commands:

- node tools/verify-retrieval-outcomes.mjs
- node --test tests/security/retrieval-outcomes/verifier.test.mjs
- ./node_modules/.bin/tsc --noEmit --strict --target ES2022 --module NodeNext --moduleResolution NodeNext --lib ES2022,DOM --types node --skipLibCheck false tests/security/retrieval-outcomes/types-consumer.mts types/consumer-fixture.mts
- npm run typecheck
- make verify-dependencies
- git diff --check <actual comparison base> HEAD

The dedicated workflow uses the existing pinned Node 22.23.3, npm lockfile and
action revisions. It does not install new dependencies or alter shared runners.
Actual results belong to the exact hosted candidate and must be recorded in its
PR. A missing or skipped required case remains a failure. The source-only baseline
at 6087f359c8f5f12f1db2540f2071d8a3b80b547b lacked this local adapter; that
observation is not an executed failing test. Local executor and graph execution
were unavailable during authoring, so no local test result is claimed.
