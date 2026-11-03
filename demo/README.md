# demo/ — the local front end

```bash
python demo/server.py            # opens http://127.0.0.1:8765/
python demo/server.py --port 8799 --no-browser
```

One page that takes two versions of an extension, runs both through the real pipeline, and
shows the whole thing happening: the declared manifest difference, the six pipeline stages
with timings, a live log, the behaviour each version produced side by side with the new
rows marked, the fake collector's record of what the update tried to send, and the verdict
with the rules behind it.

| File | What it is |
|---|---|
| `server.py` | Standard-library HTTP server. No web framework, nothing to install. Serves the page, accepts uploads, runs one analysis per request on a worker thread, and streams the narration back by polling. |
| `analysis.py` | A thin shell over the engine. It adds narration and the flat behaviour table; it adds nothing to the analysis. The only judgement made here is the **NO CHANGE** verdict, which the engine would otherwise report as a very low BENIGN. |
| `ui/` | `index.html`, `app.css`, `app.js`. No dependencies, no build step. |
| `extensions/` | The packaged sample versions, built by `package_samples.py` from `data/corpus/readerlite/`: a signed `.crx` and a plain `.zip` per version. |
| `package_samples.py` | Rebuilds them. Re-run after editing anything in the corpus. |

## Packages

Accepted: `.crx` (CRX2 and CRX3), `.zip`, `.xpi`, and an already-unpacked directory from
the command line. The bundled samples are **signed CRX3**, which is what Chrome ships.

All versions are signed with one key and therefore share one extension id. That is not
decoration: a browser treats an update as an update to the extension you already trust
because the id matches, and the id is the first 16 bytes of SHA-256 over the signing
public key. `analysis.py` checks the two ids agree before it compares anything, and says
so in the log when there is no signature to check.

The signing key is `extensions/demo-signing-key.pem` and is **not committed**. If it is
absent, `package_samples.py` makes a new one and prints the new extension id; the
committed `.crx` files will no longer match, so re-commit them if you regenerate.

## What is measured and what is not

Lines prefixed `config` in the run log are settings. Everything else is read back off the
trace the run produced: the port the test site bound, the scripts instrumented, every host
contacted and whether any was outside the sandbox, per-channel event counts, the rules
that fired, the model output, and the collector's log. The only presentational liberty is
that the behaviour tables are revealed over about two seconds rather than all at once; the
rows were all recorded during the run.

## Safety

Uploaded packages are untrusted input: they are written under `out/demo-ui/<run-id>/` and
unpacked by `engine.unpack.crx.unpack_extension`, which refuses path traversal and symlinks
and caps size and file count. No uploaded code is executed on the host — it runs inside the
sandboxed browser.

Each run leaves `out/demo-ui/<run-id>/` holding both traces and `report.json`.

For presenting this to someone, see [../docs/DEMO_MANUAL.md](../docs/DEMO_MANUAL.md).
