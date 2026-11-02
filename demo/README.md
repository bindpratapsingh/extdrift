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
| `extensions/` | The packaged sample versions, built by `package_samples.py` from `data/corpus/readerlite/`. |
| `package_samples.py` | Rebuilds those `.zip` files. Re-run it after editing anything in the corpus. |

Uploaded packages are untrusted input: they are written under `out/demo-ui/<run-id>/` and
unpacked by `engine.unpack.crx.unpack_extension`, which refuses path traversal and symlinks
and caps size and file count. No uploaded code is executed on the host — it runs inside the
sandboxed browser.

Each run leaves `out/demo-ui/<run-id>/` holding both traces and `report.json`.

For presenting this to someone, see [../docs/DEMO_MANUAL.md](../docs/DEMO_MANUAL.md).
