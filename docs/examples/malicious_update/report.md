# Security report: Controlled Update Pair

**Verdict: Critical behaviour detected**

The extension did something that very commonly indicates theft of sensitive data. It should not be trusted until reviewed.

**Risk score: 99/100** (Critical observed risk). This reflects observed behaviour and is not a probability that the extension is malicious.

## A. Analysis summary

| Item | Value |
|---|---|
| Extension | Controlled Update Pair |
| Extension ID | unsigned-8e839599431bebf2c8a8e5df |
| Version | 1.0.0 (baseline) to 1.1.0 (candidate) |
| Browser | chromium 153.0.8010.12 |
| Analysis ID | 20261102-221510-289b0b |
| Date | 2026-11-02T16:45:10+00:00 |
| Sandbox status | COMPLETED |
| Scenarios completed | 9 of 9 |
| Total time | 287.8 s |

## B. Manifest and permissions

| Item | Value |
|---|---|
| Manifest version | 3 |
| Permissions | cookies, storage |
| Host permissions | <all_urls> |
| Background | service_worker |
| Service worker | background.js |
| Content scripts | 1 |
| Web-accessible resources | 0 |

**Permission changes in the update**

- Host access escalated to every site the user visits.
- New permission 'cookies' (risk: high).
- New host permission '<all_urls>'.

## C. Runtime behaviour

| Measure | Baseline | Candidate |
|---|---|---|
| Network requests, all | 72 | 89 |
| Attributed to the extension | 1 | 18 |
| Attributed to the page | 43 | 43 |
| Browser background traffic | 28 | 28 |
| Unique extension destinations | 1 | 2 |
| DOM access events | 3 | 139 |
| Storage operations | 1 | 1 |
| Cookie operations | 0 | 34 |
| Extension API calls | 1 | 19 |
| Script injections | 0 | 0 |
| Suspicious findings | 0 | 9 |

## D. Suspicious activity

### Synthetic credential values (password) were sent to telemetry-sync9.test

- **Category:** network
- **First seen:** 2026-11-02T16:48:32.086+00:00
- **Why it matters:** A synthetic password or one-time code left the browser for a destination that does not own it. The value itself was found in the request, so this is not inferred from timing.
- **Risk contribution:** weight 0.97, adding 22.1 points on top of the other findings
- **Attribution:** confirmed
- **Change from baseline:** new
- **Evidence:** POST to telemetry-sync9.test/v1/up x17; scenarios: checkout-form, financial-portal-login, honeypage-harvest, manifest-targeted, webmail-login; from: service_worker; markers: password (plain, body), username (plain, body), session (plain, body), auth_token (plain, body)

### Read the entire cookie jar 17 times in 5 test scenarios

- **Category:** storage
- **First seen:** 2026-11-02T16:48:32.074+00:00
- **Why it matters:** The extension read the whole cookie jar. Session hijacking commonly starts this way, while legitimate features usually read a single named cookie.
- **Risk contribution:** weight 0.50, adding 0.7 points on top of the other findings
- **Attribution:** confirmed
- **Change from baseline:** new
- **Evidence:** Cookie read_all through cookies.getAll x17; scenarios: checkout-form, financial-portal-login, honeypage-harvest, manifest-targeted, webmail-login; from: service_worker

### Read credential or payment field values 36 times in 6 test scenarios (input#late-password, input#password, input[name=cvv])

- **Category:** dom
- **First seen:** 2026-11-02T16:48:32.072+00:00
- **Why it matters:** The extension read the value of a password, payment or one-time-code field. Password managers do this legitimately, so on its own this is not proof of misuse.
- **Risk contribution:** weight 0.35, adding 0.4 points on top of the other findings
- **Attribution:** confirmed
- **Change from baseline:** new
- **Evidence:** Read the value of a password field x30; scenarios: financial-portal-login, honeypage-harvest, interactive-dom, manifest-targeted, webmail-login; from: content_script
- **Evidence:** Read the value of a payment field x6; scenarios: checkout-form; from: content_script

### New high-risk permissions: cookies

- **Category:** permissions
- **First seen:** declared in the manifest
- **Why it matters:** The update requests a high-risk permission the previous version did not have.
- **Risk contribution:** weight 0.30, adding 0.3 points on top of the other findings
- **Attribution:** confirmed
- **Change from baseline:** new

### Synthetic session values (auth_token, session) were sent to telemetry-sync9.test

- **Category:** network
- **First seen:** 2026-11-02T16:48:32.086+00:00
- **Why it matters:** A synthetic session cookie or authentication token left the browser. Stolen session tokens allow account takeover without the password.
- **Risk contribution:** weight 0.95, adding 0.0 points on top of the other findings (not added to the score: same behaviour group as a stronger finding)
- **Attribution:** confirmed
- **Change from baseline:** new
- **Evidence:** POST to telemetry-sync9.test/v1/up x17; scenarios: checkout-form, financial-portal-login, honeypage-harvest, manifest-targeted, webmail-login; from: service_worker; markers: password (plain, body), username (plain, body), session (plain, body), auth_token (plain, body)

### Synthetic personal data (username) was sent to telemetry-sync9.test

- **Category:** network
- **First seen:** 2026-11-02T16:48:32.086+00:00
- **Why it matters:** Synthetic personal data left the browser for a destination that does not own it.
- **Risk contribution:** weight 0.75, adding 0.0 points on top of the other findings (not added to the score: same behaviour group as a stronger finding)
- **Attribution:** confirmed
- **Change from baseline:** new
- **Evidence:** POST to telemetry-sync9.test/v1/up x17; scenarios: checkout-form, financial-portal-login, honeypage-harvest, manifest-targeted, webmail-login; from: service_worker; markers: password (plain, body), username (plain, body), session (plain, body), auth_token (plain, body)

### Read cookies 17 times in 5 test scenarios

- **Category:** dom
- **First seen:** 2026-11-02T16:48:32.073+00:00
- **Why it matters:** The extension read cookies, which can include session identifiers.
- **Risk contribution:** weight 0.30, adding 0.0 points on top of the other findings (not added to the score: same behaviour group as a stronger finding)
- **Attribution:** confirmed
- **Change from baseline:** new
- **Evidence:** Read document.cookie x17; scenarios: checkout-form, financial-portal-login, honeypage-harvest, manifest-targeted, webmail-login; from: content_script

### Host access widened to every site

- **Category:** permissions
- **First seen:** declared in the manifest
- **Why it matters:** The update extends access to every site, so it would also run on banking and email pages.
- **Risk contribution:** weight 0.25, adding 0.0 points on top of the other findings (not added to the score: same behaviour group as a stronger finding)
- **Attribution:** confirmed
- **Change from baseline:** new

### Looked up password or login elements 27 times in 9 test scenarios

- **Category:** dom
- **First seen:** 2026-11-02T16:48:30.464+00:00
- **Why it matters:** The extension looked up a password or login element. Finding a field is not the same as reading its value.
- **Risk contribution:** weight 0.10, adding 0.0 points on top of the other findings (not added to the score: same behaviour group as a stronger finding)
- **Attribution:** confirmed
- **Change from baseline:** new
- **Evidence:** Looked up password elements x24; scenarios: checkout-form, financial-portal-login, general-browsing, honeypage-harvest, idle-background, interactive-dom, manifest-targeted, sensitive-profile, webmail-login; from: content_script
- **Evidence:** Looked up payment elements x3; scenarios: checkout-form; from: content_script

## E. Version comparison

**Newly introduced and suspicious: 7**

- Cookie read_all through cookies.getAll (baseline 0, candidate 17)
- Read document.cookie (baseline 0, candidate 17)
- Read the value of a password field (baseline 0, candidate 30)
- Read the value of a payment field (baseline 0, candidate 6)
- Looked up password elements (baseline 0, candidate 24)
- Looked up payment elements (baseline 0, candidate 3)
- POST to telemetry-sync9.test/v1/up (baseline 0, candidate 17)

**All newly introduced behaviours: 13**

- Extension API runtime.sendMessage (baseline 0, candidate 17)
- Extension API runtime.onMessage.addListener (baseline 0, candidate 1)
- Cookie read_all through cookies.getAll (baseline 0, candidate 17)
- Read document.cookie (baseline 0, candidate 17)
- Read the value of a password field (baseline 0, candidate 30)
- Read the value of a payment field (baseline 0, candidate 6)
- Read the value of a username field (baseline 0, candidate 12)
- Listens for submit on root (baseline 0, candidate 17)
- Looked up other elements (baseline 0, candidate 15)
- Looked up password elements (baseline 0, candidate 24)
- Looked up payment elements (baseline 0, candidate 3)
- Looked up username elements (baseline 0, candidate 12)
- POST to telemetry-sync9.test/v1/up (baseline 0, candidate 17)

**More frequent: 0**


**Changed parameters: 0**


**Removed: 0**


**Less frequent: 0**


**Unstable across baseline runs, so excluded: 0**


Unchanged behaviours: 4

- New destinations: telemetry-sync9.test
- Destinations no longer contacted: none

**Feature differences (candidate minus baseline)**

| Feature | Change | Meaning |
|---|---|---|
| net_outbound_requests | +17 | Requests attributed to the extension |
| net_unique_domains | +1 | Distinct registrable domains the extension contacted |
| net_uploads | +17 | Extension requests carrying data outwards |
| net_upload_bytes | +3573 | Bytes in extension request bodies |
| net_undeclared_domains | +1 | Contacted domains absent from the manifest and the fixed web |
| net_suspicious_destinations | +1 | Upload destinations with a low-reputation shape or an IP literal |
| net_marker_requests | +17 | Requests containing a synthetic secret value |
| dom_password_field_reads | +30 | Value reads of password fields |
| dom_password_field_lookups | +24 | Lookups of password fields without a value read |
| dom_login_form_interactions | +79 | DOM operations touching a form that has a password field |
| dom_sensitive_reads | +36 | Value or text reads of any sensitive field class |
| cookie_reads | +34 | Cookie reads through document.cookie or the cookies API |
| cookie_bulk_reads | +17 | Whole-jar reads through cookies.getAll |
| api_calls | +18 | Extension API calls and listener registrations |
| api_distinct | +2 | Distinct extension APIs used |
| api_privileged_calls | +17 | Calls into privileged extension APIs |
| exfil_events | +17 | Requests where a synthetic secret left for a non-owning destination |
| exfil_credential_events | +14 | Of those, passwords and one-time codes |
| exfil_session_events | +17 | Of those, session cookies and tokens |
| worker_uploads | +17 | Uploads from a service worker or background page |
| sensitive_scenarios | +6 | Scenarios in which sensitive data was read |
| perm_high_risk | +1 | Declared high-risk API permissions |
| perm_broad_host | +1 | 1 when host access covers every site |

## F. Risk assessment

| Item | Value |
|---|---|
| Overall risk score | 99/100 |
| Classification | Critical observed risk |
| Weighted baseline score | 99 |
| Machine learning | MALICIOUS (probability 0.99, highest in honeypage-harvest) |
| ML confidence | uncalibrated: useful for ranking only |
| How they combined | direct_evidence_overrides_ml |

A synthetic secret was observed leaving the browser. The classifier agrees.

**Why this score**

- Synthetic credential values (password) were sent to telemetry-sync9.test. [credential_exfiltration, weight 0.97]
- Read the entire cookie jar 17 times in 5 test scenarios. [cookie_bulk_read, weight 0.50]
- Read credential or payment field values 36 times in 6 test scenarios (input#late-password, input#password, input[name=cvv]). [credential_field_read, weight 0.35]
- New high-risk permissions: cookies. [permission_escalation, weight 0.30]

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

**Critical behaviour detected**

The extension did something that very commonly indicates theft of sensitive data. It should not be trusted until reviewed.

### Limitations

- This is dynamic analysis. It can only report behaviour that happened during this run, so malicious code that stayed dormant, was tied to a date, a specific website, a specific user, or a server response that the sealed sandbox could not provide, would not appear here.
- No suspicious behaviour being captured does not show that an extension is safe.
- The score reflects observed behavioural risk. It is not the probability that the extension is malicious, and its bands are configurable starting points rather than established boundaries.
- An extension could detect the analysis environment and behave differently. Instrumentation is inside the extension's own JavaScript, so sufficiently careful code could evade or tamper with it. The network record, kept in a separate container, is harder to evade than the other channels.
- Browser scheduling, service-worker lifetimes and asynchronous code mean two runs are not perfectly identical, even though both versions receive the same pages and scripted actions.
