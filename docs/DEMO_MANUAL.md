# extdrift — demonstration manual

**For:** Bind and Suhani, running the live demonstration.
**Length:** 12 minutes of demo, plus questions. A 6-minute cut is marked at the end.
**What you need:** this laptop, Chrome or Edge, and nothing else. No internet, no Docker.

---

## 0. The one sentence to open with

> "A browser extension you already trust can turn malicious in a silent auto-update — that
> is exactly what happened to Cyberhaven in December 2024. The stores review an extension
> once; they do not review the *change*. We run version N and version N+1 in a sealed
> sandbox, record what each one actually does, and score the difference."

Everything after this is that sentence being demonstrated.

---

## 1. Before the meeting — 10 minutes, once

Run these in order. Each line says what you should see.

```bash
cd C:\Users\Bindp\Documents\GitHub\extdrift

python -m pytest tests/ -q
#  -> 222 passed, 38 skipped      (takes ~90 s)

python demo/package_samples.py
#  -> writes signed .crx and plain .zip for each version, and prints one extension id
#     shared by all three (if it prints "made a new signing key", that is fine)

python demo/server.py
#  -> prints "sandbox : host-sealed Chromium", "model : trained model loaded"
#  -> opens http://127.0.0.1:8765/ in your browser
```

With the page open, **do one full practice run** of the malicious case (section 4). It
must end on a red **MALICIOUS** band with `DATA ACTUALLY LEFT: YES`. The first run of the
day is the slowest because Chromium is cold; after that each run takes about 35 seconds.

Leave the server running. Leave the browser tab open. Have a second window with
`docs/PROJECT_REPORT.md` ready in case a question goes deep.

**If the page will not load:** the port is taken by an older run. Close the terminal,
open a new one, and start it on another port: `python demo/server.py --port 8799`.

---

## 2. The two versions you are demonstrating

They are in `demo/extensions/`, and their source is in `data/corpus/readerlite/`.

| Package | Role | What it is |
|---|---|---|
| `reader-lite-1.0.0.crx` | **version N** | A real-shaped reader extension. Tidies an article, adds a toolbar, asks its own background service worker for a config. Permissions: `storage`. |
| `reader-lite-1.0.1.crx` | a benign update | Same extension, plus a reading-time badge. More behaviour, no new permission, nothing leaves the page. |
| `reader-lite-1.1.0.crx` | **version N+1, weaponised** | Same extension, plus a payload that reads the login form, asks the service worker for the whole cookie jar, and POSTs both to an outside host. Permissions: `storage` **+ `cookies`**. |

These are **signed CRX3 packages**, the format Chrome itself ships, not loose zips. All
three are signed with one key, so all three carry the **same extension id** — which is
precisely how a browser decides that an update is an update to the extension you already
trust rather than a different extension. The page shows that id on both slots, and the log
checks it matches before it compares anything. A `.zip` of each is in the same folder for
anyone who wants one, and `.xpi` is accepted too.

All three are written by us. The payload is synthetic and its destination host resolves
only inside the sandbox — it cannot reach anything real. Say this out loud when you first
mention the malicious version; it is the first thing an examiner will want to know.

If you are asked to show the difference in the code, open these two files side by side:

```
data/corpus/readerlite/1.0.0/content.js      vs    data/corpus/readerlite/1.1.0/content.js
data/corpus/readerlite/1.0.0/sw.js           vs    data/corpus/readerlite/1.1.0/sw.js
```

The injected payload is the block marked `--- injected payload ---`. Showing it takes
20 seconds and makes the rest concrete.

---

## 3. What is on screen, and what each part is for

The page is one scroll, in four numbered steps. Do not scroll ahead of your narration.

| Step | What it shows | Why it is there |
|---|---|---|
| 1. Choose the two versions | Two slots; each shows name, version, manifest version, permissions, file count once read | The *declared* capability — what a store reviewer sees |
| 2. What the tool is doing | Six pipeline stages lighting up, with timings, and a live log | Makes the process visible instead of a black box |
| 3. What each version actually did | Two tables of observed behaviour, with new rows marked | The behavioural evidence, side by side |
| 4. The verdict on the change | Verdict band, both scores, the rules that fired with their source | The answer, and why |

The dark log pane in step 2 is the thing to point at while the two runs happen. It is the
only part of the demo where you will be waiting, about 15 seconds per version.

**If you are asked whether the log is real:** the answer is on the screen. Lines prefixed
`config` are settings — they say how the run was set up. Every other line is read back off
the run that just happened: the port the test site actually bound, the scripts actually
instrumented, every host actually contacted and whether any of them was outside the
sandbox, the per-channel event counts, the rules that actually fired, the model's actual
output, and the collector's actual log. Nothing on the page is a canned string standing in
for a measurement. The one presentational choice is that table rows are revealed over
about two seconds instead of all at once; the rows themselves were all recorded during
the run.

**Read the counts off the screen, do not quote them from memory.** The *verdict* is driven
by the set of distinct behaviours, which is stable run to run — the no-change case proves
it. The raw row count for the weaponised version can move by a few, because its payload is
on a timer and can fire more than once in a session. Same behaviours, sometimes repeated.

---

## 4. Run of show

### Act 1 — the attack (4 minutes)

**Set up:** slot N = `reader-lite-1.0.0.zip`, slot N+1 = `reader-lite-1.1.0.zip`.
(This is the default when the page loads, so normally you change nothing.)

**Before clicking, point at the two permission rows.** Say:

> "This is everything a store reviewer gets to see. The update asks for one extra
> permission, `cookies`. Thousands of honest extensions ask for `cookies`. That by itself
> decides nothing — which is the whole problem."

**Click `Analyse this update`.** While it runs, read the log aloud, roughly:

> "It unpacks both packages. It seals the sandbox — every network name in here resolves
> to a local test site, so no DNS query is made and nothing leaves this machine. It arms
> a fake collector, which records anything the extension tries to send. Then it runs both
> versions through the *same* scripted session — same login page, same typing, same
> clicks, byte-identical pages — because if the two runs saw different web pages, the
> difference we measure would be the web's, not the extension's."

**When the tables appear (step 3):** scroll to them, tick **"only what is new"** on the
right-hand table. Say:

> "The left column is what version N did. The right is version N+1. Everything shown now
> is behaviour that the new version produced and the old one never did: it reads the
> password field, it reads `document.cookie`, the service worker calls
> `chrome.cookies.getAll`, and there is a POST to a host the old version never contacted."

**Then scroll to the red collector box.** This is the moment of the demo. Say:

> "And this is not inference. This is the fake collector's own log — the actual bytes the
> extension tried to send, with the username, the password and the session cookie in
> them. We caught it because we sealed the network, not because we guessed."

**Then the verdict band.** Say:

> "Verdict: malicious. Rules 0.99, model 0.99, and the leak confirmed independently. And
> underneath it, the reason: six heuristics fired, each one traced to the paper or the
> incident it comes from. It is not a number with no explanation attached."

### Act 2 — "so does it just flag every update?" (3 minutes)

This is the question the panel will ask. Ask it yourself, first.

**Set slot N+1 to `reader-lite-1.0.1.zip`. Click Analyse.**

> "Same baseline. This update is a genuine new feature — a reading-time badge. It changes
> behaviour: a handful of new DOM behaviours appear. The tool sees the change, says so, and
> returns **BENIGN**. One weak heuristic fires — new page injection, weight 0.25 — and
> the model puts it at 0.001. A false alarm here would be the thing that makes a tool
> like this useless in practice, because nearly every update is this one."

### Act 3 — the control (2 minutes)

**Set slot N+1 to `reader-lite-1.0.0.zip` — the same file as slot N. Click Analyse.**

> "Last one. The same extension against itself. Two completely separate browser runs, two
> separate traces. If our capture were noisy, this is where it would show: we would
> invent a difference that does not exist. It returns **NO CHANGE** — zero new
> behaviours, all 26 features unchanged. That determinism is what makes the other two
> results mean anything."

### Act 4 — where this sits (3 minutes)

No clicking. Say:

> "What you have just seen runs the browser on this laptop. For the real system, the
> extension runs inside a hardened Docker container with no route to the internet, behind
> a recording gateway — that is built and documented in `docs/SANDBOX.md`, with the
> isolation checked from inside the container on every run.
>
> And the evaluation behind the verdicts is not these three samples. We have 1,152
> analysed update pairs. Trained on synthetic data only and tested on 51 real extensions
> it had never seen, it reaches PR-AUC 0.99 with no false positives at 90% recall. Against
> the closest prior work, which compares code statically, an obfuscated payload is caught
> 0 times out of 21 — and we still catch it, because we watch what the code *does*."

Have these three numbers memorised: **1,152 pairs**, **PR-AUC 0.99**, **0 / 21**.

---

## 5. If something breaks

| What happens | Do this |
|---|---|
| The page will not open | Another server is on the port. New terminal, `python demo/server.py --port 8799` |
| A stage goes red | The log says why. An analysis that fails says *inconclusive*, never *benign* — say that out loud; it is a design decision, not an excuse |
| A run hangs past ~60 s | Reload the page and click Analyse again. The first run after a reboot is the slow one |
| Chromium will not start | `python -m playwright install chromium`, then restart the server |
| Everything is broken | `python scripts/demo_offline.py` — same three verdicts from committed traces, no browser needed. Then show `docs/examples/malicious_update/report.md` |

Every run writes `out/demo-ui/<run-id>/report.json` plus both raw traces, so you can
always show the artefacts from a run that already worked.

---

## 6. Questions you will get, with the short answer

**"Why not just read the code?"** Because obfuscation defeats it. We reproduced the
closest prior static method: it catches a clean payload 21 times out of 21 and an
obfuscated one 0 times out of 21. Behaviour does not obfuscate.

**"Isn't the malicious sample one you wrote yourself?"** Yes, and that is stated
everywhere. Real malicious *update pairs* are not obtainable: about 60% of known-malicious
extensions are delisted and 0 of 15 we probed have an archived predecessor. So we take 51
real extensions and inject real payload behaviour into them, which is the standard
substitute. The baselines are real extensions, unmodified.

**"How do you know the difference is the extension and not the web?"** Both versions get
the same scripted run against the same local pages, and the demo's third case proves the
floor: the same extension against itself produces zero difference.

**"What if the payload only triggers on a real bank site?"** We drive a synthetic login
page and fuzz event handlers to provoke dormant code — the technique from Hulk
(USENIX '14). We cannot promise full coverage; a run that never reached a declared script
is reported as *inconclusive*, not clean.

**"Is the score a probability?"** No, and the page says so under every verdict. The rule
weights are expert priors from the literature. The model's number is calibrated; the
rules' number is a ranking.

**"What is still missing?"** Three things, honestly: the container path is built but not
yet the default runner on this machine; 12 of our 51 real benign captures recorded no
events at all, which makes our false-positive rate look better than it is and which we
are fixing; and the graph-based model the advisor asked for is not built yet.

---

## 7. The 6-minute cut

Act 1 (malicious) and Act 2 (benign), then the last paragraph of Act 4. Skip Act 3 unless
someone asks whether the comparison is stable — then run it, it takes 35 seconds.

---

## 8. Command sheet (keep this visible)

```bash
# start the demo
python demo/server.py                       # http://127.0.0.1:8765/

# fallbacks
python scripts/demo_offline.py              # three verdicts, no browser
python -m experiments.real_behavioural_eval # the real-extension result
python -m engine.ml.bakeoff data/dataset/deltas.csv   # why the model, six-way bake-off

# analyse any pair from the command line
python -m engine.cli run-pair data/corpus/readerlite/1.0.0 data/corpus/readerlite/1.1.0
```
