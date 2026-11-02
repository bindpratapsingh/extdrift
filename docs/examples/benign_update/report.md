# Security report: Controlled Update Pair

**Verdict: No significant suspicious behaviour observed**

Nothing concerning happened during this test. This is not proof that the extension is safe, because some behaviour only appears under conditions this test did not create.

**Risk score: 2/100** (Low observed risk). This reflects observed behaviour and is not a probability that the extension is malicious.

## A. Analysis summary

| Item | Value |
|---|---|
| Extension | Controlled Update Pair |
| Extension ID | unsigned-8e839599431bebf2c8a8e5df |
| Version | 1.0.0 (baseline) to 1.0.1 (candidate) |
| Browser | chromium 153.0.8010.12 |
| Analysis ID | 20261102-221958-c22675 |
| Date | 2026-11-02T16:49:58+00:00 |
| Sandbox status | COMPLETED |
| Scenarios completed | 9 of 9 |
| Total time | 192.5 s |

## B. Manifest and permissions

| Item | Value |
|---|---|
| Manifest version | 3 |
| Permissions | storage |
| Host permissions | none |
| Background | service_worker |
| Service worker | background.js |
| Content scripts | 1 |
| Web-accessible resources | 0 |

**Permission changes in the update**

- No declared-capability change between the two versions.

## C. Runtime behaviour

| Measure | Baseline | Candidate |
|---|---|---|
| Network requests, all | 72 | 73 |
| Attributed to the extension | 1 | 2 |
| Attributed to the page | 43 | 43 |
| Browser background traffic | 28 | 28 |
| Unique extension destinations | 1 | 2 |
| DOM access events | 3 | 20 |
| Storage operations | 1 | 2 |
| Cookie operations | 0 | 0 |
| Extension API calls | 1 | 1 |
| Script injections | 0 | 0 |
| Suspicious findings | 0 | 0 |

## D. Suspicious activity

No risk indicator fired. This describes this run and is not a statement of safety.

## E. Version comparison

**Newly introduced and suspicious: 0**


**All newly introduced behaviours: 2**

- Added a aside element (baseline 0, candidate 17)
- GET to fonts.readercdn.test/inter-var.woff2 (baseline 0, candidate 1)

**More frequent: 0**


**Changed parameters: 0**


**Removed: 0**


**Less frequent: 0**


**Unstable across baseline runs, so excluded: 0**


Unchanged behaviours: 4

- New destinations: fonts.readercdn.test
- Destinations no longer contacted: none

**Feature differences (candidate minus baseline)**

| Feature | Change | Meaning |
|---|---|---|
| net_outbound_requests | +1 | Requests attributed to the extension |
| net_unique_domains | +1 | Distinct registrable domains the extension contacted |
| dom_modifications | +17 | Other changes to page structure |
| storage_writes | +1 | Web and extension storage writes |

## F. Risk assessment

| Item | Value |
|---|---|
| Overall risk score | 2/100 |
| Classification | Low observed risk |
| Weighted baseline score | 2 |
| Machine learning | BENIGN (probability 0.01, highest in webmail-login) |
| ML confidence | uncalibrated: useful for ranking only |
| How they combined | both_quiet |

Neither the rules nor the classifier (probability 0.01) flag this update.

**Why this score**

- No risk indicator fired during this analysis.

**Lower-risk observations**

- 17 routine page changes

## Monitoring coverage

| Dimension | Status |
|---|---|
| network | ok |
| dom | ok |
| storage | ok |
| api | ok |


Isolation checks (browser): passed, 15 of 15.
Isolation checks (gateway): passed, 13 of 13.

## G. Final verdict

**No significant suspicious behaviour observed**

Nothing concerning happened during this test. This is not proof that the extension is safe, because some behaviour only appears under conditions this test did not create.

### Limitations

- This is dynamic analysis. It can only report behaviour that happened during this run, so malicious code that stayed dormant, was tied to a date, a specific website, a specific user, or a server response that the sealed sandbox could not provide, would not appear here.
- No suspicious behaviour being captured does not show that an extension is safe.
- The score reflects observed behavioural risk. It is not the probability that the extension is malicious, and its bands are configurable starting points rather than established boundaries.
- An extension could detect the analysis environment and behave differently. Instrumentation is inside the extension's own JavaScript, so sufficiently careful code could evade or tamper with it. The network record, kept in a separate container, is harder to evade than the other channels.
- Browser scheduling, service-worker lifetimes and asynchronous code mean two runs are not perfectly identical, even though both versions receive the same pages and scripted actions.
