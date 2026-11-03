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
  renderLoadouts();
  // The pairing that tells the story best, pre-selected so a demo can start in one click.
  pick("v1", "sample:reader-lite-1.0.0.crx");
  pick("v2", "sample:reader-lite-1.1.0.crx");
  const first = $(".chipbtn[data-v2='sample:reader-lite-1.1.0.crx']");
  if (first) first.classList.add("on");
  state.pickLabel = "Malicious update";
  $("#run").addEventListener("click", analyse);
  $("#back").addEventListener("click", newAnalysis);
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

// The three canonical demos, built from the bundled sample extension.
const GUIDED = [
  { label: "Malicious update", cls: "malicious",
    desc: "The update hides a payload that steals data. Expected verdict: MALICIOUS.",
    v1: "sample:reader-lite-1.0.0.crx", v2: "sample:reader-lite-1.1.0.crx" },
  { label: "Benign update", cls: "benign",
    desc: "A normal feature update, nothing dangerous. Expected verdict: BENIGN.",
    v1: "sample:reader-lite-1.0.0.crx", v2: "sample:reader-lite-1.0.1.crx" },
  { label: "No change at all", cls: "nochange",
    desc: "The same version twice — behaviour is identical. Expected: NO CHANGE.",
    v1: "sample:reader-lite-1.0.0.crx", v2: "sample:reader-lite-1.0.0.crx" },
];

function chipButton(v1ref, v2ref, inner) {
  return `<button type="button" class="chipbtn" data-v1="${esc(v1ref)}" ` +
         `data-v2="${esc(v2ref)}">${inner}</button>`;
}

function renderLoadouts() {
  $("#lo-guided").innerHTML = GUIDED.map(d =>
    `<button type="button" class="chipbtn guided-card" data-v1="${esc(d.v1)}" data-v2="${esc(d.v2)}">` +
    `<span class="dot ${d.cls}"></span>` +
    `<span class="gc-text"><span class="gc-title">${esc(d.label)}</span>` +
    `<span class="gc-sub">${esc(d.desc)}</span></span></button>`).join("");

  const real = state.boot.real_pairs || [];
  if (real.length) {
    $("#grp-real").hidden = false;
    $("#count-real").textContent = real.length;
    $("#lo-real").innerHTML = real.map(p => chipButton(p.v1.ref, p.v2.ref,
      `${esc(p.name)} <span class="cv">${esc(p.v1.version)}&#8594;${esc(p.v2.version)}</span>`)).join("");
  }
  const weap = state.boot.weaponised_pairs || [];
  if (weap.length) {
    $("#grp-weap").hidden = false;
    $("#count-weap").textContent = weap.length;
    $("#lo-weap").innerHTML = weap.map(p => chipButton(p.v1.ref, p.v2.ref,
      `${esc(p.name)} <span class="fam">${esc((p.family || "").replace(/_/g, " "))}</span>`)).join("");
  }

  document.querySelectorAll(".chipbtn").forEach(b => b.addEventListener("click", () => {
    document.querySelectorAll(".chipbtn.on").forEach(x => x.classList.remove("on"));
    b.classList.add("on");
    state.pickLabel = (b.querySelector(".gc-title") || b).textContent.trim();
    pick("v1", b.dataset.v1);
    pick("v2", b.dataset.v2);
  }));
}

// Find the pair (real or weaponised) a version ref belongs to, and which slot it is.
function pairForRef(ref) {
  const all = (state.boot.real_pairs || []).concat(state.boot.weaponised_pairs || []);
  for (const p of all) {
    if (p.v1.ref === ref) return { pair: p, slot: "v1" };
    if (p.v2.ref === ref) return { pair: p, slot: "v2" };
  }
  return null;
}

function pick(slot, ref) {
  const root = $(`#slot-${slot}`);
  const found = pairForRef(ref);
  const known = state.boot.samples.some(s => s.ref === ref) || !!found;
  $(".slot-select", root).value = known ? ref : "";
  if (!ref) {
    state.picked[slot] = null;
    root.classList.remove("filled");
    $(".slot-facts", root).innerHTML = "";
    $("#run").disabled = !(state.picked.v1 && state.picked.v2);
    return;
  }
  state.picked[slot] = ref;
  root.classList.add("filled");
  const sample = state.boot.samples.find(s => s.ref === ref);
  if (sample) {
    $(".slot-facts", root).innerHTML = `<p class="slot-blurb">${esc(sample.blurb)}</p>` +
      factsTable([["package", esc(sample.file)],
                  ["size", sample.bytes.toLocaleString() + " bytes"]]);
  } else if (found) {
    const p = found.pair, v = p[found.slot];
    const injected = (found.slot === "v2" && p.family);
    const blurb = injected
      ? `A real published extension with one documented attack behaviour injected to ` +
        `make this candidate version: <b>${esc((p.family || "").replace(/_/g, " "))}</b> &mdash; ${esc(p.family_desc || "")}`
      : `A real published extension from the Firefox add-on store, unpacked on this ` +
        `machine. Nothing synthetic about it.`;
    const rows = [["extension", esc(p.name)], ["version", esc(v.version)],
                  ["manifest", "MV" + esc(String(p.mv || "?"))]];
    if (injected) {
      if (p.added_permission) rows.push(["added permission", esc(p.added_permission)]);
      if (p.injected_files) rows.push(["injected into", esc((p.injected_files || []).join(", "))]);
    } else {
      rows.push(["source", "AMO (local, not redistributed)"]);
    }
    $(".slot-facts", root).innerHTML = `<p class="slot-blurb">${blurb}</p>` + factsTable(rows);
  } else {
    $(".slot-facts", root).innerHTML = factsTable([
      ["package", esc(ref.replace(/^upload:/, ""))], ["source", "uploaded"]]);
  }
  $("#run").disabled = !(state.picked.v1 && state.picked.v2);
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

  const opts = list => list.map(([ref, label]) =>
    `<option value="${esc(ref)}">${esc(label)}</option>`).join("");
  const bundled = state.boot.samples.map(s => [s.ref, `${s.file} : ${s.label}`]);
  const real = (state.boot.real_pairs || []).map(p => [p[slot].ref, `${p[slot].label} (real, AMO)`]);
  const weap = (state.boot.weaponised_pairs || []).map(p =>
    [p[slot].ref, `${p[slot].label}${slot === "v2" ? " + " + p.family : ""}`]);
  select.innerHTML = `<option value="">Choose a package...</option>` +
    `<optgroup label="Bundled samples">${opts(bundled)}</optgroup>` +
    (real.length ? `<optgroup label="Real extensions (this machine)">${opts(real)}</optgroup>` : "") +
    (weap.length ? `<optgroup label="Real + injected attack (this machine)">${opts(weap)}</optgroup>` : "");
  select.addEventListener("change", () => {
    document.querySelectorAll(".chipbtn.on").forEach(x => x.classList.remove("on"));
    const opt = select.options[select.selectedIndex];
    if (opt && select.value) state.pickLabel = opt.textContent.split(" : ")[0].trim();
    pick(slot, select.value);
  });

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

function realVersion(slot, ref) {
  for (const p of state.boot.real_pairs || []) if (p[slot].ref === ref) return p;
  return null;
}

function pick(slot, ref) {
  const root = $(`#slot-${slot}`);
  const known = state.boot.samples.some(s => s.ref === ref) || !!realVersion(slot, ref);
  $(".slot-select", root).value = known ? ref : "";
  if (!ref) {
    state.picked[slot] = null;
    root.classList.remove("filled");
    $(".slot-facts", root).innerHTML = "";
    $("#run").disabled = !(state.picked.v1 && state.picked.v2);
    return;
  }
  state.picked[slot] = ref;
  root.classList.add("filled");
  const sample = state.boot.samples.find(s => s.ref === ref);
  const pair = realVersion(slot, ref);
  if (sample) {
    $(".slot-facts", root).innerHTML = `<p class="slot-blurb">${esc(sample.blurb)}</p>` +
      factsTable([["package", esc(sample.file)],
                  ["size", sample.bytes.toLocaleString() + " bytes"]]);
  } else if (pair) {
    $(".slot-facts", root).innerHTML =
      `<p class="slot-blurb">A real published extension from the Firefox add-on store, ` +
      `unpacked on this machine. Nothing synthetic about it.</p>` +
      factsTable([["extension", esc(pair.name)],
                  ["version", esc(pair[slot].version)],
                  ["manifest", "MV" + esc(String(pair.mv || "?"))],
                  ["source", "AMO (local, not redistributed)"]]);
  } else {
    $(".slot-facts", root).innerHTML = factsTable([
      ["package", esc(ref.replace(/^upload:/, ""))], ["source", "uploaded"]]);
  }
  $("#run").disabled = !(state.picked.v1 && state.picked.v2);
}

function loadRealPair(slug) {
  const p = (state.boot.real_pairs || []).find(x => x.slug === slug);
  if (!p) return;
  pick("v1", p.v1.ref);
  pick("v2", p.v2.ref);
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

function reveal(sel) {
  const el = $(sel);
  el.hidden = false;
  el.classList.remove("revealed");
  void el.offsetWidth;            // restart the animation
  el.classList.add("revealed");
}

function setRunTitle() {
  $("#run-title").innerHTML = "Analysing <b>" + esc(state.pickLabel || "this update") + "</b>";
}

async function analyse() {
  // Move to the dedicated results view; the steps reveal themselves one by one as the
  // run progresses, rather than all sitting empty on the setup page.
  $("#view-setup").hidden = true;
  $("#view-run").hidden = false;
  window.scrollTo({ top: 0, behavior: "instant" in window ? "instant" : "auto" });
  setRunTitle();
  $("#run").disabled = true;
  $("#run").textContent = "Analysing…";

  ["#observed-step", "#verdict-step", "#collector", "#chart-panel",
   "#briefing", "#report-actions", "#declared"].forEach(s => { $(s).hidden = true; });
  reveal("#pipeline-step");
  $("#only-new").checked = false;
  $("#pane-v2").classList.remove("filtered");
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

function newAnalysis() {
  if (state.timer) clearInterval(state.timer);
  $("#view-run").hidden = true;
  $("#view-setup").hidden = false;
  resetButton();
  window.scrollTo({ top: 0, behavior: "instant" in window ? "instant" : "auto" });
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
  $("#run").textContent = "Analyse this update →";
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
  if ($("#observed-step").hidden) reveal("#observed-step");
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

function renderChart(series) {
  const panel = $("#chart-panel");
  if (!series || !series.length) { panel.hidden = true; return; }
  panel.hidden = false;
  const hi = Math.max(1, ...series.map(s => Math.max(s.v1, s.v2)));
  const barFill = (value, cls, grew) =>
    `<div class="chart-bar ${cls}${grew ? " grew" : ""}">` +
    `<span class="fill" style="width:${(value / hi) * 100}%"></span>` +
    `<span class="num">${value}</span></div>`;
  $("#chart").innerHTML = series.map(s =>
    `<div class="chart-row"><div class="chart-cat">${esc(s.label)}</div>` +
    `<div class="chart-bars">${barFill(s.v1, "n", false)}` +
    `${barFill(s.v2, "n1", s.v2 > s.v1)}</div></div>`).join("");
}

function renderBriefing(briefing) {
  const box = $("#briefing");
  const doing = (briefing && briefing.doing) || [];
  if (!doing.length) { box.hidden = true; return; }
  box.hidden = false;
  const hot = briefing.class === "malicious" || briefing.class === "suspicious";
  $("#briefing-doing").innerHTML = doing.map((x, i) =>
    `<li class="${hot && i === 0 ? "hot" : ""}">${esc(x)}</li>`).join("");
}

function renderReportLinks() {
  const box = $("#report-actions");
  if (!state.run) { box.hidden = true; return; }
  box.hidden = false;
  const url = `/api/report?run=${encodeURIComponent(state.run)}`;
  $("#report-view").href = url;
  $("#report-json").href = url + "&format=json";
  const print = $("#report-print");
  print.onclick = () => {
    const w = window.open(url, "_blank");
    if (w) w.addEventListener("load", () => w.print());
  };
}

function verdict(ev) {
  const { outcome, record } = ev;
  reveal("#verdict-step");
  $("#verdict").className = "verdict " + outcome.class;
  $("#verdict-label").textContent = outcome.label;
  $("#verdict-headline").textContent = outcome.headline;
  $("#verdict-detail").textContent = outcome.detail;

  renderChart(ev.briefing && ev.briefing.chart);
  renderBriefing(ev.briefing);
  renderReportLinks();

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
