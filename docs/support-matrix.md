# Blocked event links: application handoff

Updated 2026-10-21 for [getticketstub.com #144](https://github.com/Jevelopers-neatHack-2026/getticketstub.com/issues/144). This records the application consumer's behavior and evidence. It does not establish implementation or acceptance of the event-intelligence research contract, provider readiness, or hosted deployment.

The reviewed application change is [getticketstub.com PR #216](https://github.com/Jevelopers-neatHack-2026/getticketstub.com/pull/216), source revision [`83fe39f`](https://github.com/Jevelopers-neatHack-2026/getticketstub.com/tree/83fe39f85eba854d5b2a1f7c7147f6e1f2e98d8a). Its [detailed support/access matrix](https://github.com/Jevelopers-neatHack-2026/getticketstub.com/blob/83fe39f85eba854d5b2a1f7c7147f6e1f2e98d8a/docs/support-matrix.md) owns the provider-by-provider assessment, source links and application limits. Check the PR's merge/check state before treating that revision as shipped.

| Source | Application treatment in that revision | Remaining boundary |
| --- | --- | --- |
| Resident Advisor event links on verified main/legacy hosts | Numeric event paths return a manual-details fallback before any RA fetch; non-event paths are refused. | Normal user browser access is unverified; official/private API access is not enabled. Unverified country subdomains are not recognised as RA. |
| AXS, SeatGeek, StubHub, EVENTIM/See Tickets, Shotgun, Etix, Tixr, Skiddle | Exact provider roots and bounded subdomain matching supply provider-specific copy when a challenge is detected. | Recognition is not proof of an API entitlement or successful event extraction. Dedicated provider issues remain authoritative for adapter expansion. |
| An unrecognised host with a detected challenge | Generic blocked-site message and the same manual-details form. | An unrecognised or unmarked challenge is not claimed as detectable. |

Known Cloudflare/DataDome/Akamai/AWS WAF/Vercel challenge markers map to the application error `access_restricted`, corresponding to this service's `ACCESS_RESTRICTED` concept. Challenge responses never proceed to event parsing or another automated retry. No CAPTCHA solving, browser bypass, user-agent rotation, private API/GraphQL access or Herald lookup is introduced.

The application form requires an event name and valid date, optionally venue/city. The app-local `customer` provenance is shown as **Entered by you**. It is not a new version of an event-intelligence public schema. Weather is a separate source and follows existing configured lookup limits. Only fixed provider/error categories enter application telemetry, not event URLs, customer input or challenge content.

## Evidence and limits

- The application PR records a pinned Node 22.23.3 full Linux test result of 1,303 passed with one existing separately gated Finance test skipped, plus offline phone/desktop browser checks, typecheck, lint and a production build. These are consumer-local results, not event-intelligence acceptance.
- Challenge fixtures are labelled synthetic. The [RA contributor report](https://github.com/Jevelopers-neatHack-2026/getticketstub.com/issues/155#issuecomment-6308518867) reports HTTP blocks and automated-browser homepage tests on 2026-10-20; it is not proof of a normal browser's success or a fresh probe by this change.
- API/partner routes remain conditional on owner-verified entitlement and terms. The consumer decision is fallback-only; no provider agreement, credentials or paid calls were activated.

The [controlled retrieval boundary](security/controlled-retrieval.md), [consumer handoff](contracts/consumer-handoff.md) and [provider readiness](providers/readiness-handoff.md) retain their existing authority and unresolved gates.
