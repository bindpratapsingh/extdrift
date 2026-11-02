# Controlled test extensions

Written for the Docker pipeline's tests. All of them are synthetic. The "malicious" ones send only
synthetic values, only to `.test` hosts, and only ever run inside the sandbox, whose network has no
route out. They must never be published to an extension store.

| Directory | Purpose | Required test |
|---|---|---|
| `benign` | Reading-time badge; touches nothing sensitive | 1 |
| `credential_access` | Reads a password field, sends nothing | 2 |
| `cookie_access` | Reads cookies through `document.cookie` and `cookies.getAll` | 3 |
| `network_marker` | Posts a hardcoded synthetic token | 4 |
| `combined` | Reads a password and posts it, base64-encoded | 5 |
| `pair_v1` -> `pair_v2` | Normal version, then a credential and cookie stealing update | 6 |
| `pair_v1` -> `pair_v1_1_benign` | Normal version, then a harmless update | 6, false-positive control |
| `invalid_*`, `rejected_by_browser`, `incompatible_runtime` | Structural failures | 7 |
| `beacon` | Periodic background POST | Beaconing |
| `form_hijack` | Page itself submits credentials to a foreign host | Attribution |
| `full_surface` | Touches every monitored API | Monitoring coverage |
