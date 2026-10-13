# Private official-source follow-up

The private retrieval result can now contain an optional `sourceAuthorityReview` with schema `ei-private-source-authority-review/v1`. This is a bounded manual input request for issue #14 AC4. Its authority is `unknown`, status is `review_required`, and execution is `not_dispatched`. It neither determines that a source is official nor establishes that an official source exists. Existing source authority remains `not_evaluated`.

## Final authorized selection

The shared private draft projection constructs the review after the existing selected evidence and fact checks. In controlled-asset mode it remains inside the synchronous one-shot final release barrier, including the zero-asset path. The projection checks the original monotonic deadline and cancellation signal before reading the selection and again before returning; time spent in a trusted final authorization callback does not create a new budget.

Current host authorization still requires the literal boolean `true`. A native Promise, including one resolving to `true`, is refused. Both outcomes of a supported ordinary native Promise are discarded through the existing verified observer, so rejection remains observed and a fulfilled value is never forwarded or adopted. Arbitrary thenable accessors are not invoked. The original independent no-evidence rejected-Promise failure remains recorded separately from the repaired native strict-rejection and fresh-recovery controls.

Each question uses fixed trusted wording. An occurrence asks for an attributable official event or organizer page including its date and venue; an entity asks for an attributable official page identifying that entity and its event relationship. A source-only selection asks for an accessible official event or organizer source containing the event details. Names, URLs, fact values, excerpts, and arbitrary source instructions are never interpolated into these prompts.

Questions carry only a candidate kind/ID and evidence ID/version/full content hash from the current selected metadata. Candidate supports must match that selection. These references remain private provenance, not authenticity signatures or permissions. The adjacent helper is internal source code and is not exported through a public package subpath; callers cannot use it as an authentication or authority issuer.

The existing bound is eight selected sources and 23 candidates per identity kind. The review emits at most eight questions. Occurrences precede entities; within each kind, opaque IDs use code-point ordering. Evidence references are deduplicated and ordered by the serialized ID/version/hash tuple. Identical candidate bindings are deduplicated, inconsistent duplicate bindings are refused, and `omittedQuestionCount` reports the exact number omitted after this bounded deduplication. Question hashes use an explicit v1 domain and include the kind, candidate ID, and ordered current evidence references. Reopening an unchanged authorized selection reproduces the same questions without a request, timestamp refresh, new reservation, or counter reset.

## Settled results without evidence

There is one additional hook at the settled no-evidence return. It follows verification of the durable observation/receipt stream and the checks for unresolved work, active leases, and reserved transport bytes. It rechecks current host release authorization, the original elapsed deadline and cancellation signal, and any opted-in release controller. Only an explicitly eligible source refusal produces one fixed source-input question. That question has a null candidate reference and an empty evidence-reference list.

Eligible refusals include no supported identity/link candidate, a JavaScript-dependent public page, a public-source access gate, unsupported media, or unsupported encoding. The access-gate question asks for another accessible source; it does not request a login, challenge bypass, or retry of the gate. An ambiguous historical refusal is not relabeled into a more specific outcome. Existing `draft: null`, limitations and progress remain intact. Empty seed input remains invalid.

Generic incomplete and cleanup helpers generate no follow-up. Host or financial authorization denial, revoked/expired/key-unavailable evidence, cancellation, deadline, unresolved transport/leases, and unverified or missing receipts cannot produce a question or old source references. Unrecognized limitation or stop codes suppress the review. In particular, `budget_denied` and `decoded_response_budget_exhausted` do not become an instruction to continue spending.

A normal fully settled attempt, depth, or fan-out cap may retain a passive question alongside its original stop/omission metadata. It authorizes no further execution. The generic `frontier_stopped` marker present in an existing sealed attempt-cap replay is eligible only when an explicit ordinary stop is also present; the generic marker alone is insufficient.

## Compatibility and verification

Both `PrivateRetrievalDraft` and `PrivateRetrievalIncomplete` gain only an optional readonly field. Their outer `ei-private-retrieval-draft/v1` schema and the existing `'draft' in result` discrimination remain unchanged. Candidates, conflicts, source/fact values, identity decisions, links, limits, progress, receipt formats and database schemas are preserved. No shared-contracts schema, identity-question composer, corroboration decision, provider adapter, or source-classification policy is changed.

Run with pinned Node 22.23.3:

```sh
node tools/verify-source-authority-followup.mjs
./node_modules/.bin/tsc --noEmit --strict --target ES2022 --module NodeNext --moduleResolution NodeNext --lib ES2022,DOM --types node --skipLibCheck false --noErrorTruncation tests/research/source-authority-followup/types-consumer.mts
npm run typecheck
```

The dedicated verifier requires all 75 maintained cases, no required skips, and unchanged source bytes/modes. Seven isolated native strict-rejection controls cover invalid authorization, late rejection, fulfilled values and getter avoidance, including the existing entry and candidate callers of the same guard. It records the actual revision, tree, dirty flag, complete source manifest, runtime, counts, synthetic fixture mode, and report digest in a unique `.tmp/source-authority-followup/` attempt directory. Existing bounded-frontier CI continues to execute the maintained private retrieval and controlled-release suites; its inventory is unchanged.

The dedicated tests use actual local HTTP, encrypted evidence, native SQLite, current release guards and same-database replay. Source documents, encryption keys, host authorities and deliberate clock-consumption callbacks are synthetic. They cover reference binding, hostile text, deterministic ordering/truncation, no-answer requests, ordinary settled caps versus budget denial, absent receipts, denied access, revocation, cancellation, and elapsed deadlines. They do not supply provider results, official-source classification, cross-repository acceptance, a financial grant, or evidence for closing all of issue #14, gate #22, or epic #1. Asking for an input requires no provider credential; dispatching or accepting an eventual response remains a separate authorized operation.
