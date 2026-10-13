# Capturing bounded handoff reports

This workflow captures the four existing local handoff checker reports. A green
capture job means that it preserved four structurally consistent **BLOCKED**
reports. It does **not** mean release readiness, accepted contracts, authenticated
owner approval, provider access, consumer ACKs, or satisfied issue criteria.

The checker remains unchanged. Its current exit 1 means BLOCKED and exit 2 means
INVALID; it has no trusted evidence verifier and never grants readiness.
The capture helper accepts only the current BLOCKED/1/ready:false combination.
It fails on INVALID, malformed or duplicate-key JSON, inconsistent scope, selected summary counts (checks, missing_deliverables and
failed_or_invalid), or exit values, timeout, output overflow, source changes, or missing capture output/source identity.
A future checker readiness implementation requires a separate reviewed update;
this wrapper will not silently accept a new exit/status combination.

## Fixed inputs and retained evidence

The helper invokes the pinned interpreter with isolation and bytecode disabled:
`python -I -B tools/verify_handoff.py --kind KIND --manifest tests/contracts/handoff-manifest.json`.
KIND is selected from exactly handoff-contracts, handoff-metering,
provider-readiness and handoff-consumer. It accepts no command, URL, manifest or
scope supplied by an artifact. It reads no credentials and performs no provider,
network, install or publication operation.

Run `python3 -I -B tools/capture_handoff_reports.py --output "$RUNNER_TEMP/ei-handoff-unique"`.
The output must be a new direct child of RUNNER_TEMP outside the checkout.
An existing destination is refused, so earlier failures cannot be overwritten.
The checkout must be clean. Exact HEAD/tree, Git status, interpreter, argv, UTC
times, process exits and raw stdout/stderr hashes are retained in receipt.json
and stream files. The same retained report/stdout/stderr and receipt bytes are
mirrored in bounded HANDOFF_CAPTURE_BYTES log records as base64 chunks with
file/offset/total fields. This makes API log inspection possible without
executing archives, and prevents raw output from becoming workflow commands.
It does not log the environment. Source identity is checked before and after all four scopes.

Each scope has a 30-second deadline and a 1 MiB retained limit for each stream.
The process group is killed on timeout or overflow; retained bytes remain
verbatim, but incomplete streams are explicitly failed, never described as
complete. All four scopes are attempted after a report failure. Setup/source
identity failure can prevent them from running; the receipt then remains failed
with an empty or partial group inventory. No missing command becomes a pass.

The workflow triggers on push and pull request changes to its own files, the
index/component/catalog and designated evidence inputs. It checks committed
whitespace with git diff --check HEAD^ HEAD using a two-commit checkout. It always attempts
artifact upload, including on failure. A skipped/untriggered job or absent upload
is unavailable evidence. The source revision in the receipt is the actual
checkout, which may be a PR merge candidate rather than its head.

## Verification boundaries

The dedicated 13 helper controls test capture behavior, including real local
process timeout/output handling and fixed-command continuation. The timeout
control preserves any bytes emitted before termination; empty output is possible
when the deadline expires before the child emits. They are separate
from the unchanged 31 handoff checker tests in the existing verify workflow.
Neither inventory is a provider or consumer evaluation. Do not add nested control
counts to the four report count or treat expected BLOCKED as readiness passing.

This helper does not validate release/evidence-index.json, retrieve immutable
links, authenticate evidence provenance or rewrite any manifest. Those existing
review tasks remain separate. Its initial authoring environment could not execute
commands; initial helper and product checks remain NOT_RUN until the exact
published candidate's natural CI supplies actual results.
