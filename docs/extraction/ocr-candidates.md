# Private OCR candidates and question preparation

Refs [EI12](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/12).
This additive private consumer interprets a bounded subset of the OCR inspection
report. It produces **tentative candidates that require review**, retaining the
original source, pixel and report hashes, page, word ordinals and boxes. It never
creates evidence-store facts, merges entities, establishes source officialness,
infers rights, or dispatches a provider request. Canonical package exports and
contracts are unchanged. Full EI12 acceptance remains separate.

## Supported interpretation

`deriveOcrCandidateFacts({ reportBytes, expectedSha256, input })` revalidates the
complete `ei-local-inspection-ocr-report/1` input and bytes before interpretation.
A row must be an observed result with supplied original/raw byte-domain binding
and a matching supplied caller record. Refused results, missing raw bytes and
missing caller records produce explicit unknown outcomes. The structural caller
record is not issuer authentication or proof that caller-supplied words describe
the pixels accurately. Confidence remains an uncalibrated engine score.

Words are grouped only within one observation, page, block, paragraph and line.
The private profile `explicit-label-ordinal-line-unknown-dates/1` recognizes a
leading `Event:`, `Title:`, `Date:`, `Start:`, `End:`, `Venue:` or `City:` label
(case insensitive, with a separate colon token also allowed). The remainder
becomes a tentative field. Existing candidate whitespace normalization is reused;
the raw tokens and literal joined value remain available. Dates and times always
have unknown precision: `03/04/2026` and `7 PM` are not interpreted, localized or
converted to timestamps. Multiple labels on a line, empty values, unlabeled text,
logos and other layouts remain unknown. Repeated fields remain distinct; adjacent
lines and pages are not assumed to describe the same event. In particular, a
first line and “doors open” text are never inferred to be a title or start time.

The output is always incomplete and review-required, with no accepted facts or
owner acknowledgements. It retains predecessor incomplete reasons. This profile
is a usable local subset, not complete arbitrary screenshot/PDF interpretation
or an accuracy/evaluation result.

## Consumer and provenance

`prepareOcrCandidateQuestions({reportBytes, expectedSha256, input}, {lineId})`
requires an explicit single retained line. It rederives the candidate report
from the original inspection input, prepares relevance and injection questions
using the existing pure question preparer, and never executes them. The line is
an untrusted `passage_text`; it is not synthetic HTML or JSON-LD. Language remains
`und`: an English OCR model does not establish the source's language. The wrapper
requires review even if the generic planner's own review flag is false.

The sidecar binds the exact candidate/prerequisite report, selected line,
original/derivative hashes, page geometry, every word and candidate, and the
plan/state hashes. Its digest is a correlation checksum, not authentication.
All generic authority flags remain false, promotion remains unpromoted, readiness
blocked and execution not dispatched. A credential-like or oversized passage refused
by the existing preparer returns a typed preparation refusal; no silent redaction
or truncation is substituted. Callers must keep the original candidate report
and sidecar together for review. This is an EI-private API, absent from exports.

## Bounds and errors

The interpreter caps 256 lines, 128 candidates, 256 words per line, 4,096 UTF-8
bytes per reconstructed line, 32,768 total reconstructed text bytes and 2 MiB of
report bytes. The complete prerequisite has its own bounded validation. Any
exceeded bound refuses the operation, preserving the caller's inputs; subsequent
valid input can be retried. Token reconstruction inserts one space between OCR
words and expressly does not claim original source whitespace. Output objects
are frozen and encoded bytes are copied.

Errors expose fixed codes, not input data: `INVALID_INPUT`,
`PREREQUISITE_INVALID`, `RESOURCE_LIMIT`, `REPORT_BYTES_MISMATCH`,
`UNSUPPORTED_VERSION`, `UNKNOWN_LINE`, `QUESTION_PREPARATION_REFUSED`.

## Verification

The dedicated route is:

```sh
node tools/verify-ocr-candidates.mjs --mode mock
node --test tests/extraction/ocr-candidates/runner.test.mjs
```

The first route requires exactly **41** cases and refuses missing, extra,
failed, skipped, cancelled or TODO results. The second route has **10** checker
controls, reported separately. Unsupported/live modes fail or block before
native work. Existing deterministic extraction selectors are unchanged.

The checked-in labeled PNG is generated synthetic content, with exact font and
byte provenance in its adjacent JSON; it depicts no actual event. Current native
PNG/OCR calls produce title/date/venue candidates; a two-page scanned PDF built
from those pixels checks page linkage. The unchanged native doors-text fixture
stays unknown. A native pre-abort and subsequent blank-image recovery are asserted.
Negative and boundary cases deliberately mutate caller-supplied OCR words or
records and remain labeled synthetic; those mutations are not native recognition
results. The test fixture composes real source/pixel/caller bindings with **empty
predecessor suite streams**: missing-summary/incomplete reasons remain missing,
and no predecessor-suite pass is fabricated or inferred. The candidate requires
per-observation bindings, not an overall report-complete claim.

The workflow installs the existing locked local runtimes and dependencies, runs
the fresh native controls, checks strict declarations and project types, and
retains raw streams, source identities and runtime manifests. Native prerequisites
are mandatory, never skipped. No provider grant, live commerce, accepted canonical
mapping, deployed network, release readiness or foreign consumer ACK is implied.
