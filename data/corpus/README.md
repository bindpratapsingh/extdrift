# Corpus — synthetic weaponisation samples

These are **small extensions we wrote ourselves** to exercise the pipeline against real,
running behaviour. They are the miniature of the project's data strategy: a real benign
baseline, a real benign update (must **not** be flagged), and a synthetically weaponised
update (must be flagged).

> ⚠️ **Safety.** The "malicious" behaviour here is synthetic and self-contained. The
> collector host `collect-analytics.test` resolves **only to the local sandbox**
> (`engine/sandbox/testsite.py`) via Chromium's `--host-resolver-rules`; nothing ever
> reaches the real internet. Only dummy credentials are ever used. These samples exist to
> be caught by our own tool and must never be published to any extension store.

## Reader Lite

A genuinely benign reading-mode extension, plus two updates:

| Version | Role | What changed | Expected verdict |
|---|---|---|---|
| `1.0.0` | trusted baseline | — | — (reference) |
| `1.0.1` | benign feature update | adds a reading-time badge (more DOM, nothing leaves the page, no new permission) | **BENIGN** |
| `1.1.0` | weaponised update | injects a Cyberhaven-style payload: harvest login form, dump the cookie jar from the **service worker**, POST to a collector; also declares the `cookies` permission | **MALICIOUS** |

The weaponisation follows the data plan from `Reference Docs/CHANGES.txt` §4b: take a clean
extension as `v1`, inject a known bad behaviour to make `v2`, and always label it as
synthetic. The payload is deliberately **event-gated** (fires on form submit / after a
delay) so that *static* analysis would miss it and only *runtime* capture catches it — the
exact VEX-vs-dynamic point from the literature review.

## Run it

```bash
# malicious update → MALICIOUS, and the collector really receives the stolen data:
python -m engine.cli run-pair data/corpus/readerlite/1.0.0 data/corpus/readerlite/1.1.0

# benign update → BENIGN, collector receives nothing:
python -m engine.cli run-pair data/corpus/readerlite/1.0.0 data/corpus/readerlite/1.0.1
```
