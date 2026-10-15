# Research-a.2: explicit offline diagnostic

Related: EI #3; contributions to #6, #10, #16, #17, #19 and #22.

The launcher accepts `--candidate 0.10.0-research-a.2` as a separate exact
private-development diagnostic. The default remains 0.9.7; 0.10.2 remains a
separate selection. No runtime dependency, accepted consumer pin, wire adapter,
B9 election, approval authority or release acceptance is installed.

## Acquired input

The previously announced producer-machine delivery path is accessible in this
workspace. All seven indexed files matched their recorded byte lengths and
SHA256 on October 15, 2026. This resolves the prior environment-specific
acquisition gap; it does not authenticate the producer's review or owner authority.

- Source: `a6b3bee948aaf659617a2cec22ce6f3a1600976f`
- Tree: `a18aa1db05e264ea93a610c9a631e4f7a513c87a`
- Archive SHA256: `5913d86580164400f6f869ff017fe4e3dea554e683f78bd918d0382f7ad60beb`
- Archive: 4,777,577 bytes, 396 ordinary package entries
- Source snapshot SHA256: `2e315fa26a5212f820d50d657e0e53faeef3331e6b51822b5e797b76de3f05d4`
- Nine-pair map SHA256: `977d5046d5e16dd3aabefc0abaaf6089d260863d764768d455257cfe78ab8e59`

The committed pin includes exact archive SRI and content/schema/fixture manifest
identities. No private archive, source snapshot, review packet or provider data is
copied into this repository. Source signature verification is not claimed.

## Run

Use Node 22.23.3, locked repository dependencies, and the installed TypeScript
7.0.2 host compiler. Each output directory must be new:

```sh
node tools/contracts/installed-research-consumer.mjs \
  --candidate 0.10.0-research-a.2 \
  --archive /absolute/path/jevelopers-shared-contracts-0.10.0-research-a.2.tgz \
  --output /absolute/path/new-research-a2-receipt
node --test tests/contracts/installed-research-consumer/launcher.test.mjs
npm run typecheck
```

The existing 49 cases exercise actual local history/correction/recovery and
source-composition/question-plan callers plus explicitly synthetic canonical
controls against retained v1 exports. Their results are not nine-pair acceptance.
The separate `research_a2` observation applies the installed EIP2 structural
validator and issuance helper to the actual initial and corrected SQLite snapshots.
It preserves their bytes and reports the structural and missing-host refusals.
Installed types also assert that a local snapshot is not assignable to EIP2.
The receipt includes EIP2's exact schema pin as well as the six legacy pins.

Expected disposition remains `passed_expected_incompatibility` with
`INCOMPATIBLE_HOLD`: no accepted migration or consumer ACK. The two EIP2 probes
are reported separately from the original 49 cases. Descriptor/Support joins,
nine-pair fixture execution, actual issuance, successful DecisionPort dispatch and
result consumption remain unexecuted. Content/fixture hash verification is not
fixture execution. No provider call is made.

## Exact owner routing

All issue references below are in `Jevelopers-neatHack-2026`. These are scoped
inputs for actual EI implementation, not requirements to finish entire epics.

| Owner / eligible issue | Required decision or artifact | EI affected issues |
| --- | --- | --- |
| shared-contracts #14/#16/#17 | Elect v1 versus Research-a.2. The latter proposes ResearchRequest2, ResearchRequestReceipt2, ResearchResultContent1, ResearchAnswerReceipt2, ResearchBatchReceipt2, EventIntelligencePackage2, ResearchIssuanceReference1, ResearchEvidenceDescriptor1 and ResearchEvidenceSupport1. Return exact elected versions, schemas/fixture hashes, producer/consumer revisions and acceptance decision. | #3, #7, #10, #16, #17 |
| shared-contracts #16/#17 with EI/Creative | Set lossless `sourced/inferred/missing/conflicting/customer_supplied` mappings; unknown facts without provenance; competing source claims; local UUID version/parent versus package/fact IDs and revisions; snapshot/material/fact/package hash domains; retention/access/source-use joins; old-minor/additive policy and `UNSUPPORTED_SCHEMA` versus `UNSUPPORTED_VERSION`. | #3, #6, #10, #19, #20 |
| shared-contracts #16/#17 with Harness/Creative | Elect B9 Descriptor/Support roles, counts and acquisition policy. Original/excerpt/derived Source2 bindings must retain exact byte artifacts and positions; a selected excerpt artifact is not automatically a permitted Support artifact. Decide source-only/no-answer and 36-field ResultContent/package equality bindings. | #3, #7, #10, #12, #14 |
| agent-harness #5/#15 with shared-contracts #14 | Bind colon-versioned EI question IDs, target/state/instance/hash domains, staged predecessor/result state, request/batch/attempt identities and result/receipt/usage references to the sole injected DecisionPort v1. Return exact fixtures/ACK for timeout, malformed, abstain, cancellation and separate identity/support stages. | #3, #5, #13, #16, #17, #21 |
| cost-intelligence #3/#13; held settlement PR59 | Elect UsageEvent fields/version (v1 at shared0.3.0 remains proposal-only) and reservation/pre-dispatch protocol. Separate logical operation, billable attempt, transport attempt, provider request and observation IDs. Supply unknown/late/finality/hold/reconciliation fixtures, direct/trace dedupe, original-expense reuse lineage and exact Finance/Harness ACKs. Shared0.10.2 diagnostics are not accepted migration. | #4, #12, #13, #14, #16, #17, #20 |
| creative-engine #3/#10/#19 and #12 | Accept package/version/hash/provenance mapping and permission states allowed/unknown/denied/expired/revoked bound to tenant/project/package/asset/hash/action/expiry. Return actual corrected-package and rights/freshness invalidation ACKs, retained history, selected-artifact or explicit original-artwork fallback, stale approval refusal and retry idempotency. | #6, #18, #19, #20, #22 |
| getticketstub.com #19 with Harness/Creative | Supply trusted tenant/actor/job/version, current scope/review/retention/source-use/approval ports, issuer/key registry and actual atomic publication/correction/admission bindings. Research-a.2 `resolve`, `observe`, `readBytes`, derivation/discovery witness/verifier and generation/currentness checks need elected real host implementations. | #7, #9, #10, #12, #18, #19, #20 |
| Harness/provider #4; EI #5 | Supply exact account/project/endpoint/API/model/config/retry/rate-card pins, safe nonbillable readiness procedure or explicit limitation, and applicable Finance authorization. Offline-only campaign does not authorize provider smoke runs. | #5, #12, #22 |
| integration-evals and Research/Finance; EI #15/#21 | Supply permission-audited adjudicated corpus/splits and ratified numeric quality/coverage/latency/full-workflow-cost targets. Synthetic policy/projector results do not establish promotion. | #15, #21 |
| integration-evals master acceptance; EI #22 then #1 | Accept the pinned actual public-source → research → correction/rights fallback → Creative chain, including authentic trace/usage and producer/consumer ACKs. Offline diagnostics cannot qualify it. | #22, #1 |

All 19 frozen entries remain open: #1, #3–7, #9–10, #12–22. This diagnostic
addresses an acquisition/executable compatibility subtask of #3 only. Existing
local components and historical scoped acceptance remain credited; no whole-issue
closure candidate is established. Further integration requires the named elected
bindings and actual EI wiring and verification afterward, not an ACK alone.
