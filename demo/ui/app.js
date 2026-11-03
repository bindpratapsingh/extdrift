/* extdrift demo UI.
 *
 * All this file does is render what the server narrates. It makes no judgement of its own
 * except one presentational choice: a row in version N+1 is marked "new" when its
 * behaviour key did not occur in version N, which is the same comparison the server uses
 * for the delta. Rows are revealed a few at a time so the table can be read as it fills;
 * the rows themselves were all recorded during the run, not generated here.
 */

"use strict";

const $ = (sel, root) => (root || document).querySelector(sel);

const state = {
  boot: null,
  run: null,
  cursor: 0,
  runId: null,          // carries uploads from /api/upload through to /api/analyse
  picked: { v1: null, v2: null },
  keys: { v1: null, v2: null },
  stageStart: {},
  timer: null,
};

/* ------------------------------------------------------------------ boot */

async function boot() {
  state.boot = await (await fetch("/api/boot")).json();
  renderEnv(state.boot.environment);
  renderStages(state.boot.stages);
  for (const slot of ["v1", "v2"]) setupSlot(slot);
  // The pairing that tells the story best, pre-selected so a demo can start in one click.
  pick("v1", "sample:reader-lite-1.0.0.crx");
  pick("v2", "sample:reader-lite-1.1.0.crx");
  $("#run").addEventListener("click", analyse);
  $("#only-new").addEventListener("change", ev =>
    $("#pane-v2").classList.toggle("filtered", ev.target.checked));
}

function renderEnv(env) {
  const rows = [
    ["sandbox", env.sandbox, env.playwright],
    ["model", env.model ? "trained" : "rules only", env.model],
    ["docker path", env.docker ? "available" : "not on this host", env.docker],
  ];
  $("#env").innerHTML = rows.map(([k, v, on]) =>
    `<div><dt>${esc(k)}</dt><dd class="${on ? "" : "off"}">${esc(v)}</dd></div>`).join("");
}

function renderStages(stages) {
  $("#stages").innerHTML = stages.map(s =>
    `<li id="stage-${s.id}"><span class="dot"></span><span class="label">${esc(s.label)}</span>` +
    `<span class="elapsed"></span></li>`).join("");
}

/* ------------------------------------------------- choosing the packages */

function setupSlot(slot) {
  const root = $(`#slot-${slot}`);
  const select = $(".slot-select", root);
  const input = $("input[type=file]", root);

  select.innerHTML = `<option value="">Choose a package...</option>` +
    state.boot.samples.map(s =>
      `<option value="${esc(s.ref)}">${esc(s.file)} : ${esc(s.label)}</option>`).join("");
  select.addEventListener("change", () => pick(slot, select.value));

  input.addEventListener("change", () => {
    if (input.files.length) upload(slot, input.files[0]);
  });
  const drop = $(".slot-drop", root);
  ["dragenter", "dragover"].forEach(e => root.addEventListener(e, ev => {
    ev.preventDefault(); root.classList.add("dragover");
  }));
  ["dragleave", "drop"].forEach(e => root.addEventListener(e, () => root.classList.remove("dragover")));
  root.addEventListener("drop", ev => {
    ev.preventDefault();
    if (ev.dataTransfer.files.length) upload(slot, ev.dataTransfer.files[0]);
  });
  drop.addEventListener("click", ev => { if (ev.target === drop) input.click(); });
}

function pick(slot, ref) {
  const root = $(`#slot-${slot}`);
  $(".slot-select", root).value = state.boot.samples.some(s => s.ref === ref) ? ref : "";
  if (!ref) {
    state.picked[slot] = null;
    root.classList.remove("filled");
    $(".slot-facts", root).innerHTML = "";
    return;
  }
  state.picked[slot] = ref;
  const sample = state.boot.samples.find(s => s.ref === ref);
  $(".slot-facts", root).innerHTML = sample
    ? `<p class="slot-blurb">${esc(sample.blurb)}</p>` + factsTable([
        ["package", esc(sample.file)],
        ["size", sample.bytes.toLocaleString() + " bytes"],
      ])
    : factsTable([
        ["package", esc(ref.replace(/^upload:/, ""))],
        ["source", "uploaded"],
      ]);
  $("#run").disabled = !(state.picked.v1 && state.picked.v2);
}

async function upload(slot, file) {
  state.runId = state.runId || "";
  const url = `/api/upload?slot=${slot}&name=${encodeURIComponent(file.name)}` +
              (state.runId ? `&run=${state.runId}` : "");
  const res = await fetch(url, { method: "POST", body: file });
  const data = await res.json();
  if (data.error) { alert(data.error); return; }
  state.runId = data.run;
  pick(slot, data.ref);
}

/* ------------------------------------------------------------- the run */

async function analyse() {
  $("#run").disabled = true;
  $("#run").textContent = "Analysing…";
  ["#pipeline-step", "#observed-step", "#verdict-step"].forEach(s => $(s).hidden = false);
  $("#collector").hidden = true;
  $("#only-new").checked = false;
  $("#pane-v2").classList.remove("filtered");
  $("#verdict-step").hidden = true;
  $("#declared").hidden = true;
  $("#log").textContent = "";
  for (const slot of ["v1", "v2"]) {
    $(`#pane-${slot} tbody`).innerHTML = "";
    $(`#pane-${slot} .pane-count`).textContent = "";
    state.keys[slot] = null;
  }
  $("#stages").querySelectorAll("li").forEach(li => {
    li.className = ""; $(".elapsed", li).textContent = "";
  });

  const res = await fetch("/api/analyse", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ v1: state.picked.v1, v2: state.picked.v2, run: state.runId }),
  });
  const data = await res.json();
  if (data.error) { log(data.error, true); resetButton(); return; }
  state.run = data.run;
  state.cursor = 0;
  state.timer = setInterval(poll, 350);
}

async function poll() {
  const res = await fetch(`/api/events?run=${state.run}&cursor=${state.cursor}`);
  const data = await res.json();
  if (data.error) return;
  state.cursor = data.cursor;
  data.events.forEach(handle);
  if (data.done) { clearInterval(state.timer); resetButton(); }
}

function resetButton() {
  $("#run").disabled = false;
  $("#run").textContent = "Analyse this update";
}

/* ------------------------------------------------- rendering each event */

function handle(ev) {
  switch (ev.kind) {
    case "log":      log(ev.text, false, ev.at); break;
    case "error":    log(ev.text, true, ev.at); failActiveStage(); break;
    case "stage":    stage(ev); break;
    case "package":  packageFacts(ev); break;
    case "manifest_diff": declared(ev); break;
    case "observed": observed(ev); break;
    case "verdict":  verdict(ev); break;
    default: break;
  }
}

function log(text, isError, at) {
  const pane = $("#log");
  const stamp = at ? `<span class="t">${esc(at)}</span>  ` : "";
  pane.insertAdjacentHTML("beforeend",
    `${stamp}<span class="${isError ? "err" : ""}">${esc(text)}</span>\n`);
  pane.scrollTop = pane.scrollHeight;
}

function stage(ev) {
  const li = $(`#stage-${ev.id}`);
  if (!li) return;
  li.className = ev.state;
  if (ev.state === "active") state.stageStart[ev.id] = Date.now();
  if (ev.state === "done" && state.stageStart[ev.id]) {
    const secs = (Date.now() - state.stageStart[ev.id]) / 1000;
    $(".elapsed", li).textContent = secs.toFixed(1) + "s";
  }
}

function failActiveStage() {
  const active = $("#stages li.active");
  if (active) active.className = "fail";
}

function factsTable(rows) {
  return "<table>" + rows.map(([k, v]) =>
    `<tr><th>${esc(k)}</th><td>${v}</td></tr>`).join("") + "</table>";
}

function packageFacts(ev) {
  const root = $(`#slot-${ev.slot}`);
  const chips = list => (list.length ? list : ["none"])
    .map(p => `<span class="chip">${esc(p)}</span>`).join("");
  const blurb = $(".slot-blurb", root);
  const rows = [
    ["name", esc(ev.name)],
    ["version", esc(ev.version)],
    ["package", esc(ev.file) + " (" + esc(ev.format) + ")"],
  ];
  // The id comes out of the CRX signature. Two versions are versions of one extension
  // only if it matches, which is exactly how a browser decides to apply an update.
  if (ev.extension_id) rows.push(["extension id", esc(ev.extension_id)]);
  rows.push(["manifest", "MV" + esc(ev.manifest_version) + ", " + esc(ev.background)]);
  rows.push(["permissions", chips(ev.permissions)]);
  rows.push(["host access", chips(ev.host_permissions)]);
  rows.push(["files", esc(ev.files)]);
  $(".slot-facts", root).innerHTML = (blurb ? blurb.outerHTML : "") + factsTable(rows);
}

function declared(ev) {
  const box = $("#declared");
  box.hidden = false;
  box.innerHTML = "<b>Declared by the update, before anything runs:</b> " +
    ev.lines.map(esc).join(" ") +
    (ev.added_permissions.length
      ? " This is what a store reviewer sees. It says what the new code may do, not what it does."
      : " A static permission check has nothing to flag here.");
}

function observed(ev) {
  const rows = ev.rows;
  state.keys[ev.slot] = new Set(rows.map(r => r.key));
  const baseline = ev.slot === "v2" ? state.keys.v1 : null;
  const tbody = $(`#pane-${ev.slot} tbody`);
  tbody.innerHTML = "";
  // Two different counts, and conflating them on screen is confusing: how many recorded
  // rows are new, and how many *distinct* behaviours those rows represent. The verdict is
  // driven by the distinct count, so both are shown.
  const newRows = baseline ? rows.filter(r => !baseline.has(r.key)) : [];
  const newDistinct = new Set(newRows.map(r => r.key)).size;
  $(`#pane-${ev.slot} .pane-count`).textContent =
    `${rows.length} rows · ${ev.duration}s · ${ev.pages.length} pages` +
    (baseline ? ` · ${newRows.length} new (${newDistinct} distinct)` : "");

  // Reveal in small batches so the table can be followed while it fills, and never take
  // longer than about two seconds however many rows there are.
  const batch = Math.max(1, Math.ceil(rows.length / 30));
  let i = 0;
  (function step() {
    const slice = rows.slice(i, i + batch);
    tbody.insertAdjacentHTML("beforeend", slice.map(r => rowHtml(r, baseline)).join(""));
    i += batch;
    if (i < rows.length) setTimeout(step, 55);
  })();

  if (ev.slot === "v2" && ev.collector && ev.collector.length) {
    $("#collector").hidden = false;
    $("#collector-body").textContent = ev.collector.map(hit =>
      `${hit.method} http://${hit.host}${hit.path}\n` +
      (hit.body_preview ? `\n${hit.body_preview}\n` : "")).join("\n");
  }
}

function rowHtml(r, baseline) {
  const isNew = baseline && !baseline.has(r.key);
  const cls = [isNew ? "is-new" : "", r.sensitive ? "sensitive" : ""].join(" ").trim();
  const note = r.note ? ` <span class="note">${esc(r.note)}</span>` : "";
  const tag = isNew ? ` <span class="chip chip-new">new</span>` : "";
  return `<tr class="${cls}">` +
    `<td class="t">${r.t.toFixed(2)}</td>` +
    `<td class="ch">${esc(r.channel)}</td>` +
    `<td class="act">${esc(r.action)}${tag}</td>` +
    `<td class="det">${esc(r.detail)}${note}</td></tr>`;
}

function verdict(ev) {
  const { outcome, record } = ev;
  $("#verdict-step").hidden = false;
  $("#verdict").className = "verdict " + outcome.class;
  $("#verdict-label").textContent = outcome.label;
  $("#verdict-headline").textContent = outcome.headline;
  $("#verdict-detail").textContent = outcome.detail;

  const scores = [];
  for (const [name, value] of Object.entries(record.scores || {})) {
    scores.push([name.replace("weighted-rules", "rules").replace("ml-", "model: "),
                 value.toFixed(3), false]);
  }
  const leaked = record.ground_truth && record.ground_truth.collector_received_data;
  scores.push(["data actually left", leaked ? "YES" : "no", leaked]);
  $("#verdict-scores").innerHTML = scores.map(([k, v, hot]) =>
    `<div><dt>${esc(k)}</dt><dd class="${hot ? "yes" : ""}">${esc(v)}</dd></div>`).join("");

  const fired = record.fired_rules || [];
  $("#why-rules").innerHTML = fired.map(r =>
    `<li><div class="rule-head"><span class="rule-id">${esc(r.id)}</span>` +
    `<span class="rule-name">${esc(r.name)}</span>` +
    `<span class="rule-weight">weight ${r.weight.toFixed(2)}</span></div>` +
    `<p class="rule-evidence">${esc(r.evidence)}</p>` +
    `<p class="rule-src">from the literature: ${esc(r.provenance)}</p></li>`).join("");
  $("#no-rules").hidden = fired.length > 0;

  const docs = state.boot.feature_docs || {};
  const moved = Object.entries(record.delta || {})
    .filter(([, v]) => Math.abs(v) > 1e-9)
    .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));
  $("#features-table tbody").innerHTML = moved.map(([name, value]) =>
    `<tr><td class="name">${esc(name)}</td>` +
    `<td class="val ${value > 0 ? "up" : "down"}">${value > 0 ? "+" : ""}${value}</td>` +
    `<td class="meaning">${esc(docs[name] || "")}</td></tr>`).join("");
  $("#features-box").hidden = moved.length === 0;

  $("#caveats").textContent = (record.caveats || []).join(" ");
}

function esc(value) {
  return String(value).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

boot();
