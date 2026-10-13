# EI-X01 installed 0.10.2 proposal diagnostic

The installed consumer launcher can separately inspect the private Shared Contracts
0.10.2 proposal from [PR31](https://github.com/Jevelopers-neatHack-2026/shared-contracts/pull/31).
This is an explicit diagnostic choice under [EI-X01](https://github.com/Jevelopers-neatHack-2026/event-intelligence/issues/3#issuecomment-6131963659).
It keeps the [0.9.7 default, callers and historical observations](installed-research-consumer-0.9.7.md).
It does not adopt a contract, elect an adapter mapping, add a runtime dependency,
update the release manifest, or record owner, consumer, Product or release acceptance.

## Exact proposal

[`pin-0.10.2.json`](../../tests/contracts/installed-research-consumer/pin-0.10.2.json)
records these independently checked artifact identities:

| Identity | Value |
| --- | --- |
| Source | `463357726e9825f7e55fbbed54cdcde8129559bf` |
| Tree | `94f72132b98cc18a17f28903bcc82f5fb1646a5d` |
| Package | `@jevelopers/shared-contracts@0.10.2`, private |
| Archive SHA256 | `f317a95bc54a9827cb8d93bf2b6a9bf439752a4d3a18ffef2aa73806c03c8840` |
| Archive bytes | `4590982` |
| Content digest | `sha256:61cf21ae7c883680ddc46341657715b1bdafe9459aac9f61b83fe559047edd71` |
| Fixture digest | `sha256:8f9684718b06dfb7b52c196530c521a7865358c450f1f17ab8bc110558887eb9` |

The archive was reproduced from the complete tracked distribution at that literal
source using Node 22.23.3 / npm 11.9.0 and `npm pack --offline --ignore-scripts
--audit=false --fund=false --json`. No producer build or install was needed. All
496 source files and modes remained unchanged. Its 378 archive entries are regular
tracked files; 377 content entries, 93 fixture entries and 88 schemas across 77
contract names were checked as bytes. These counts describe integrity checks,
not executed upstream fixtures. The pin also records the archive SRI and exact
schema/fixture manifest hashes. Producer source identity comes from the external
Git pin; the package schema manifest's null source revision supplies no acceptance.

## Reproduction in EI

Use Node 22.23.3 and the consumer's locked development dependencies. From a clean
EI checkout, with the exact local archive and a new output directory:

```sh
node tools/contracts/installed-research-consumer.mjs \
  --candidate 0.10.2 \
  --archive /absolute/path/jevelopers-shared-contracts-0.10.2.tgz \
  --output /absolute/path/to/a-new-0102-evidence-directory
node --test tests/contracts/installed-research-consumer/launcher.test.mjs
node --test tests/decisions/questions/from-source-identity.test.mjs
npm run typecheck
```

The optional `--tsc` argument still selects an explicitly recorded compiler path.
The candidate option accepts only the two committed diagnostic pins. It cannot
load a caller-supplied pin file, infer a version from an archive, or fall back to
another candidate after an identity mismatch. Omitting it always selects 0.9.7.
Unknown choices are rejected before an output directory or subprocess is created.

SHA256 and SRI must match before offline installation with lifecycle scripts
disabled. The installed package must then match its complete content inventory and
manifest identities before import. A fresh receipt records the selected pin path
and hash, actual consumer revision/tree and dirty status, exact commands, source
hashes, runtime, required checks and observations. Existing receipts cannot be
overwritten; prerequisite failures retain later required checks as unexecuted.

The unchanged diagnostic executes 49 local history, correction, recovery,
source-composition, DecisionPort refusal and independently authored synthetic
canonical controls, plus installed strict type checks. Its expected successful
diagnostic disposition remains `passed_expected_incompatibility` alongside
`consumer_acceptance: INCOMPATIBLE_HOLD`. Expected refusals are observations, not
interoperability. Changed candidate behavior fails the corresponding existing
assertion; it is not automatically relabeled as accepted. The hosted workflow
always exercises the selection/archive-refusal controls; the external package
diagnostic requires the exact archive and a separately recorded execution.

## Remaining decisions and evidence boundaries

The real EI callers still produce local correction-history and question-plan DTOs.
No lossless canonical adapter, authenticated Product issuer, B9/status/hash mapping,
Finance capability, successful DecisionPort handler dispatch, active result
consumer, external invalidation delivery or Creative ACK is supplied here. All
canonical positive controls use synthetic metadata and trust context. Provider
transport and upstream fixture execution remain outside this diagnostic.

Shared Contracts' current consumer inventory remains discovery-only, with accepted
EI bindings and acknowledgements missing. The all-consumer acceptance runner needs
the real reviewed rows and owner acknowledgements. A proposal diagnostic cannot
populate those fields. Issue #3, gate #22 and epic #1 remain open.

The separately requested 0.9.8 and Research-a.2 exact archives were unavailable at
the prior acquisition checkpoint. This new source-accessible 0.10.2 proposal does
not acquire those older bytes or transfer their selection, review or acceptance.
The earlier default-launcher attempt with 0.10.2 correctly failed its 0.9.7 archive
pin before any install, and retained three unexecuted required checks. That
observation remains separate from any later explicitly selected 0.10.2 run.
