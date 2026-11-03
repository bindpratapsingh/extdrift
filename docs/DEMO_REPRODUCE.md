# Reproducing the demo (Mac)

**For:** Suhani, to get the live demo running on the MacBook.
**Time:** ~15 min the first time; after that, one command.

The demo is a local web page that runs two versions of an extension in a sealed, offline
sandbox and shows the behavioural diff and a verdict. It works out of the box on built-in
sample extensions; the **real** and **real+injected-attack** extensions are optional extra
corpora you generate locally (they are git-ignored, so they are never in the repo).

---

## 1. Get the code

```bash
git clone https://github.com/bindpratapsingh/extdrift.git   # or: cd extdrift && git pull
cd extdrift
```

## 2. One-time setup

Needs Python 3.11+ (`python3 --version`). From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium      # downloads the sandbox browser (~150 MB)
```

Quick check that the analysis half is healthy (pure standard library, no browser):

```bash
python -m pytest tests/ -q
```

## 3. Run the demo

```bash
python demo/server.py          # opens http://127.0.0.1:8765 in your browser
```

That is the whole demo. The **Guided demos** row (malicious / benign / no-change) works
immediately on a built-in sample extension — one click loads a pair, then press
**Analyse this update**. Each run takes ~35 seconds and ends with a verdict, a
version-vs-version chart, the sandbox collector's log, and a one-page report (View /
Print to PDF).

Stop it with `Ctrl+C`. Useful flags: `--port 8799`, `--no-browser`.

## 4. (Optional) Add real published extensions

Download real update pairs from the Firefox add-on store. This writes
`data/real/amo/pairs.json` and the unpacked extensions under `data/real/amo/`
(git-ignored — third-party code, never pushed).

```bash
python -m engine.collector.amo top -n 25 --pairs 1     # ~25 extensions, newest pair each
# or a specific one:
python -m engine.collector.amo pull old-reddit-redirect
```

Restart `python demo/server.py` and a **Real published extensions** row appears, one chip
per pair. These are genuine, benign, and the tool should clear them.

## 5. (Optional) Add the "real extension + injected attack" pairs

These are the honest malicious examples: a real extension as version N, the same
extension with one documented attack behaviour injected as N+1. Needs step 4 first
(it builds from the AMO corpus). Also git-ignored.

```bash
python demo/build_weaponised_pairs.py            # builds ~9 pairs
```

Restart the server; a **Real extension + injected attack** row appears. **Use an MV3
extension for the live malicious run — Old Reddit Redirect or FoxyProxy** — they come out
MALICIOUS with the exfiltration proven by the collector. (Some larger MV2 extensions land
on SUSPICIOUS because their background page does not fully initialise in the sandbox.)

Add `--validate` to run each pair and record its measured verdict, but note: validation
must run in a normal **foreground** terminal — a detached/background run can stall on the
first browser launch.

## 6. Presenting it

The run-of-show, expected verdicts and talking points are in **`docs/DEMO_BRIEF.pdf`**
(source: `docs/DEMO_BRIEF.html`). The longer script is `docs/DEMO_MANUAL.md`.

---

## Mac troubleshooting

| Symptom | Fix |
|---|---|
| "Address already in use" / stale page | `lsof -ti:8765 \| xargs kill -9` then restart |
| A run hangs; stray browsers left over | `pkill -f ms-playwright` (kills leftover Chromium) |
| `playwright` not found | activate the venv: `source .venv/bin/activate` |
| Real/weaponised rows missing | you have not run step 4 / step 5 on this machine yet |
| Chip shows a garbled name | harmless — a store name with a special character |
| Fonts look plain / not Inter | the page pulls fonts from Google; with no internet it falls back to the system font. Harmless — everything still works. |

Nothing in steps 4–5 is committed: `data/real/` is git-ignored on purpose (we do not
redistribute third-party extension code). Each machine regenerates it locally. A fresh
clone always runs on the bundled guided samples alone.
