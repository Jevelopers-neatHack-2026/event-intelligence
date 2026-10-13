# EI-X01 installed 0.9.7 consumer diagnostic

This maintained diagnostic exercises EI's actual private correction-history store
and source-composition → identity-question preparation callers against the exact
private-development shared-contracts 0.9.7 archive requested on
[issue #3](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/3#issuecomment-6122028176).
The actual-caller request also includes
[DecisionPort](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/3#issuecomment-6116331061).
Its expected disposition is **INCOMPATIBLE_HOLD**. A passing diagnostic establishes
that the observed local behavior and explicit incompatibilities match the checks.
It is not a consumer ACK, accepted migration, public API, release pin, or completion
of CON-01/02/03, #3, #22, or #1.

The earlier [b47 candidate fixture evidence](research-contract-candidate-v1.md)
remains separate and unchanged. This lane does not replace its preserved results.

The launcher still selects this exact 0.9.7 pin by default. An explicit
`--candidate 0.10.2` selects the separately recorded
[0.10.2 proposal diagnostic](installed-research-consumer-0.10.2.md). A newer
archive never changes the default selection or transfers an earlier result.

## Exact candidate and reproduction

The diagnostic pin is in
[`tests/contracts/installed-research-consumer/pin.json`](../../tests/contracts/installed-research-consumer/pin.json).
It records private version 0.9.7, producer source
`d432ad5c895a67155affeaa05cd8423c758d95c3`, tree
`c9a0f7707e603f76628bdd5f256808c2af3ba80b`, archive SHA256
`771a9f565ea9df87a4c08e6e6d5ede422d2a5926182a95be082dc8ed7b8c4c43`,
the exact SRI, and content/schema/fixture manifest identities. This pin is only
an input to this opt-in diagnostic; the runtime has no new dependency.

At that producer revision, using Node 22.23.3 and the producer lockfile:

```sh
npm ci
npm run build
npm pack --json
```

The initial Linux reconstruction matched the requested archive SHA256 exactly and
left the producer tracked files unchanged. Rebuild in an isolated producer checkout;
do not change another owner's branch. Install EI's locked development dependencies
with `npm ci` in the consumer checkout. Then run from a clean EI checkout:

```sh
node tools/contracts/installed-research-consumer.mjs \
  --archive /absolute/path/jevelopers-shared-contracts-0.9.7.tgz \
  --output /absolute/path/to/a-new-evidence-directory
node --test tests/contracts/installed-research-consumer/launcher.test.mjs
node --test tests/decisions/questions/from-source-identity.test.mjs
npm run typecheck
```

The launcher requires Node 22.23.3 and checks both archive SHA256 and SRI before
running an install or importing package code. It copies those verified bytes into
a new temporary consumer, installs with `--offline --ignore-scripts --no-audit
--no-fund`, and verifies every installed package file against the pinned content
manifest. Its wrapper imports the actual root, `research-creative`, and `operations`
public entrypoints. No vendored candidate helper or producer fixture runner is used.

The installed type check defaults to the consumer's locked TypeScript compiler.
`--tsc /absolute/path/to/typescript/bin/tsc` permits an explicitly recorded compiler
location for an isolated worktree; it does not change any dependency. The receipt
records the actual compiler version and command. Negative type assertions preserve
the distinction between the real local DTOs and canonical package, correction,
invalidation and DecisionPort DTOs. In particular, an actual `QuestionPlan` and its
factory result are not assignable to `DecisionPortRequest`; the public operation
result discriminants narrow without an `any` cast. The DecisionPort result checker
receives compile-only signature coverage. Runtime result consumption remains
unsupported because EI has no active consumer for that result.

Every output directory must be new. The launcher retains stdout, stderr, exit codes,
consumer commit/tree, dirty status, source file hashes, runtime, schema versions and
hashes, scenario results, and the exact synthetic observations. It refuses to overwrite
an existing directory. Failed prerequisites leave later required checks explicitly
unexecuted. Development runs with a dirty worktree are labeled; an acceptance request
must use the receipt from the clean reviewed source revision. Receipts are generated
after the tested commit so they do not falsely self-reference a commit containing
their own bytes.

## Exercised behavior and limits

| Evidence origin | Checks | What this establishes |
| --- | --- | --- |
| Actual local SQLite caller | 12 scenarios | Create history with missing and conflicting facts; bind a local handoff reference; apply an immutable customer correction; preserve source claims/revisions; invalidate the exact old version/hash; reopen and read both versions; replay without duplication; reject stale and forged hashes/references, copied requests, forged scope, and a locked field. |
| Actual local DTOs passed to installed package | 10 scenarios | The exact snapshot, correction command/result and invalidation fail canonical wire checks; all three candidate alias profiles refuse the local snapshot; naming a canonical contract/version alone still leaves required fields absent; local and canonical hash domains remain distinct. |
| Independently authored synthetic canonical controls | 16 scenarios | Installed ResearchRequest and EventIntelligencePackage helpers, serialization, unknown/conflicting states, exact reference binding, fact/package tampering, scope, version/additive-field behavior, malformed JSON, and hash domains behave as recorded. These controls are not a transformation of local history into canonical records. |
| Actual source composition and question preparation | 3 scenarios | Persist two explicitly synthetic HTML sources through the real evidence store and composer; prepare an immutable blocked, unpromoted, undispatched identity plan; refuse a tampered source hash; preserve the exact bytes, stored source/evidence identities, sidecar and internal source/state/target/instance/plan hashes across all probes. |
| Actual plan passed unchanged to installed DecisionPort | 3 scenarios | The public root validator, request checker and bound port reject the real plan with `INVALID_PAYLOAD` at `/schema_version`. The bound handler is never invoked; trusted context and Finance policy are not reached. |
| Explicitly rejected DecisionPort projection probes | 3 scenarios | Adding only wire markers still leaves canonical envelope/reference fields absent and the local question array incompatible; reusing the exact local question ID in a separately authored syntax control violates canonical key grammar; the bare local state hash is not a canonical versioned-reference digest. These are rejected mechanical probes, not adapters. |
| Independently authored DecisionPort syntax controls | 2 scenarios | A wholly synthetic canonical request passes structural validation; the bound port still refuses missing trusted context with `INVALID_TRUST_CONTEXT` and zero handler calls. This does not establish Finance authority, result consumption or a successful dispatch. |

The original 38 scenarios remain unchanged. The 11 DecisionPort scenarios extend the
diagnostic to 49 scenarios, including 34 expected rejections and zero skipped cases
when all prerequisites and checks pass. The test harness does not reinterpret
a rejection as interoperability. `diagnostic_status=passed_expected_incompatibility`
and `consumer_acceptance=INCOMPATIBLE_HOLD` intentionally coexist. The launcher
regression test additionally verifies that a wrong archive runs no install/import
commands and that its failed receipt cannot be overwritten.

Canonical controls use fabricated URLs under `synthetic.example.test`, identifiers,
source metadata, references and trust contexts. The synthetic unknown fact has its
own invented control provenance; the actual missing local fact has no such evidence.
Canonical control values are not written into the local correction store or
presented as a lossless adapter. The DecisionPort caller separately persists its
own labeled synthetic HTML bytes in a fresh private evidence store, using synthetic
in-process request/retention capabilities. Those capabilities supply no canonical
issuer trust. There are no approved assets. No network retrieval, provider call, paid
effect, live identity, actual approval, Finance authority, external invalidation
delivery, or Creative acknowledgement is exercised.

## Concrete incompatibilities and required owner input

| Actual local representation | Canonical 0.9.7 requirement or unresolved decision | Accountable role and next action |
| --- | --- | --- |
| `CorrectionHistorySnapshot.schemaVersion: 1`; no wire envelope | `EventIntelligencePackage`, `schema_version: 1.0.0`, authenticated tenant/project and delivery identities, request/receipt/policy references | Product/getticketstub.com and shared-contracts: define the authenticated assembly boundary and supply accepted reference bindings; EI can implement the reviewed assembly afterward. |
| Evidence references contain only `evidenceId` and bare `contentHash`; source claims carry `sourceRevision` | Canonical source URL, retrieval time, content hash, retention/access references and fact provenance are mandatory | EI and shared-contracts: agree the evidence-store join and preserve all real source identities; Product supplies trusted access and retention bindings. Never invent metadata for missing evidence. |
| `sourced`, `inferred`, `missing`, `conflicting`, `customer_supplied`; per-source claim history and customer actor fingerprint | Canonical `known`, `unknown`, `conflicting`, `review`, fact IDs/revisions/hashes, confidence and provenance; even unknown canonical facts require provenance | Shared-contracts plus EI/Creative owners: approve a lossless representation or a typed refusal for every local state, including customer overrides, unknown facts without provenance, and competing source claims. No status equivalence is inferred here. |
| Local UUID `versionId`, `parentVersionId`, whole-snapshot bare SHA256; separate `materialHash` | Stable canonical `package_id`, `package_version`, parent reference, per-fact hash and canonical `researchContentHash` domains | Shared-contracts and EI: settle package/fact identity ownership and retain both local and canonical digests/lineage; prefixing or renaming a local digest cannot establish equivalence. |
| Local correction uses an opaque retention handle and actor authorization callbacks; local invalidation binds old local version/hash | Canonical correction authority, request/receipt identity, affected package/asset references and delivery/acknowledgement | Product owns real issuer/authentication; EI and Creative own reviewed correction and invalidation consumption. A local invalidated row is not an external receipt. |
| Proposed EI compatibility expects `UNSUPPORTED_SCHEMA` and old-minor/additive preservation | Candidate returns exact-semver `UNSUPPORTED_VERSION` and rejects unknown additive fields | Shared-contracts/EI/consumers must record the normative version/error policy; no error renaming or schema weakening occurs in this diagnostic. |
| The actual factory returns a blocked internal `QuestionPlan` and source binding sidecar, with `schema: ei-jev-question-plan-internal/v2` and a question array | `DecisionPortRequest/1.0.0` requires its own envelope, authenticated scope, request/batch/attempt identity, deadline, cancellation/model/policy/budget/state references and a question object | Shared-contracts #14, EI and agent-harness owners: approve the lossless question/target representation and the app-owned issuer/reference bindings before EI can implement a wire adapter. The first unchanged-plan refusal is a schema-version error, before any context or Finance check. |
| `Q-EI-IDENTITY:v1` and bare internal state/source/target/plan hashes | Canonical question keys exclude the local colon syntax; a canonical `VersionedReference` needs its own contract, schema version, ID, revision and prefixed digest with a defined hash domain | Shared-contracts and EI: decide stable question/target/reference ownership and digest semantics while retaining the original local IDs and hashes. This diagnostic does not rename a question or prefix a local digest into accepted authority. |
| EI has question preparation but no active DecisionPort result consumer | Successful dispatch, accepted answers, evidence references, usage/receipt consumption and recovery require the accepted port/result binding | Agent-harness #15 and EI, with Product assembly and Finance owners: supply the accepted caller/result interface and trusted runtime capabilities. No result, completed stage, provider response or consumer ACK is fabricated here. |

The later [0.9.8 private handoff](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/3#issuecomment-6123207522)
names an intentionally unpushed source and exact owner-held archive. Its bytes were
unavailable to this lane at the recorded checkpoint. This 0.9.7 run preserves the
separately authorized immutable baseline; it does not substitute for, repair, or ACK
0.9.8. The producer must supply that exact artifact through the authorized handoff
before its specific migration checks can run. The 0.9.7 DecisionPort request-side
refusal diagnostics above are implemented; successful DecisionPort interoperability,
rights/asset and full catalog acceptance remain separate work.

## Retained development failures

The first launcher run failed before reaching scenarios because the new test caller
used an incorrect relative import depth (`ERR_MODULE_NOT_FOUND` for the local history
store). The first launcher regression run had the same incorrect depth in its launcher
path and failed with a missing receipt. Both failures remain part of the development
history; they are not reconstructed as passing runs. The import paths were corrected.
The next retained run executed all 38 scenarios and installed type checks successfully,
and the launcher regression passed 1/1 with zero skips. Final reviewed evidence must
record the later exact clean consumer revision separately.

The DecisionPort extension retains the clean pre-extension 38-case baseline and its
separate development receipts. Its first extended run passed all 49 cases and the
installed strict type check. That run used a dirty worktree and is development
evidence only; reviewed evidence must identify the later clean committed source.
The required graph lookup was attempted but the `entire` executable was unavailable
(exit 127), so source discovery used focused `rg` and source reads. This tooling
limitation is not a passing graph check or a product test failure.
