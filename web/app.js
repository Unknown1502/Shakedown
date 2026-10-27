"use strict";
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const S = { health: null, recorded: [], scenarios: [], record: null, shown: 0, sel: 0, mode: null, tab: "rule", timer: null, poll: null, error: null, running: false };

/* ---------- helpers ---------- */
const benignTotal = (ev) => Object.values(ev.benign || {}).reduce((n, b) => n + b.hits, 0);
const modelName = (id) => String(id || "").replace(/^nvidia\//i, "").replace(/nemotron-3-super-120b-a12b/i, "Nemotron 3 Super 120B").replace(/Nemotron-3_5-Lightning/i, "Nemotron 3.5 Lightning");
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
/* What the model was allowed to see from the web, taken from the run record (never assumed). */
function sourceModeText(rec) {
  let sm = rec.source_mode;
  const screening = rec.research && rec.research.screening;
  if (!sm && screening) {  // recorded before the summary field existed, or still running: derive it from the decisions
    const count = (status) => screening.sources.filter((s) => s.status === status).length;
    sm = { mode: screening.policy === "exclude" ? "leakage-controlled" : "research", excluded: count("excluded"), flagged_shown: count("flagged") };
  }
  if (!sm) {
    return rec.research ? "Source handling: not screened. This was recorded before answer screening existed, so web results may have included the rule being written."
      : "Source handling: not recorded for this run.";
  }
  if (sm.verdict === "no_web_research") return "Source handling: no web research in this run. The model saw only the scenario's description.";
  if (sm.mode === "leakage-controlled") return `Source handling: leakage-controlled. ${sm.excluded ? plural(sm.excluded, "web result") + " looked like the rule being written and " + (sm.excluded === 1 ? "was" : "were") + " left out." : "No web result looked like the rule being written."}`;
  return `Source handling: research mode (nothing is removed). ${sm.flagged_shown ? plural(sm.flagged_shown, "source") + " looked like the rule being written and " + (sm.flagged_shown === 1 ? "was" : "were") + " shown to the model, so this run is not a clean test." : "No source was flagged."}`;
}
const evaluatorWhere = (ev) => {
  const kind = ev && ev.kind;
  if (kind === "token-factory-sandbox") return "inside a Nebius Token Factory Sandbox (a microVM with no network)";
  if (kind === "local-docker") return "in a local isolated Docker container (not a Token Factory Sandbox)";
  return "in an isolated container";
};
const utc = (iso) => (iso ? String(iso).slice(0, 16).replace("T", " ") + " UTC" : "");

function classify(it) {
  if (!it.validation.ok) return "invalid";
  if (!it.evaluation) return "invalid";
  const ev = it.evaluation, det = ev.attack_detected > 0, hits = benignTotal(ev);
  if (det && hits === 0) return "pass";
  return hits > 0 ? "fp" : "miss";
}

function outcome(it) {
  if (!it.validation.ok) return `Not a usable rule: ${(it.validation.errors[0] || "failed validation").replace(/^rule could not be built: /, "")}`;
  if (it.evaluator_error) return "The test runner could not load this rule";
  const ev = it.evaluation, det = ev.attack_detected > 0, hits = benignTotal(ev);
  if (det && hits === 0) return "Detected the attack file with 0 benign events";
  if (det) return `Detected the attack but matched ${plural(hits, "benign event")}`;
  return hits ? `Missed the attack and matched ${plural(hits, "benign event")}` : "Missed the attack file";
}

function diffLines(a, b) {
  const x = a.split("\n"), y = b.split("\n");
  const dp = Array.from({ length: x.length + 1 }, () => new Array(y.length + 1).fill(0));
  for (let i = x.length - 1; i >= 0; i--) for (let j = y.length - 1; j >= 0; j--) dp[i][j] = x[i] === y[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out = []; let i = 0, j = 0;
  while (i < x.length && j < y.length) {
    if (x[i] === y[j]) { out.push({ t: "same", s: x[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) out.push({ t: "del", s: x[i++] });
    else out.push({ t: "add", s: y[j++] });
  }
  while (i < x.length) out.push({ t: "del", s: x[i++] });
  while (j < y.length) out.push({ t: "add", s: y[j++] });
  return out;
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail || `Request failed (${r.status})`);
  return body;
}

/* ---------- rail ---------- */
function renderRail() {
  $("#recorded-list").innerHTML = S.recorded.map((r) => `
    <li><button data-slug="${esc(r.slug)}" ${S.record && S.record._slug === r.slug ? 'aria-current="true"' : ""}>
      <span class="dot ${r.success ? "" : "fail"}" aria-hidden="true"></span>
      <span><span class="t">${esc(r.title)}</span>
      <span class="m">${r.success ? "Passed" : "Did not pass"} in ${plural(r.iterations, "attempt")}${r.used_research ? ", report read with Tavily" : ""}</span></span>
    </button></li>`).join("") || '<li class="hint">No recorded runs on this server.</li>';
  document.querySelectorAll("#recorded-list button").forEach((b) => b.addEventListener("click", () => openRecorded(b.dataset.slug)));
  $("#scenario").innerHTML = S.scenarios.map((s) => `<option value="${esc(s.id)}">${esc(s.title)}</option>`).join("");
  const live = S.health && S.health.live_enabled;
  const rail = $("#live-section").parentElement;
  if (live && rail.firstElementChild !== $("#live-section")) rail.prepend($("#live-section"));  // live first when it is on
  $("#empty-title").textContent = live ? "Run a detection live, or play back a recorded run." : "Pick a recorded run to see how a rule gets built and tested.";
  $("#live-start").disabled = !live || S.running;
  const custom = !!(S.health && S.health.allow_custom_url);
  $("#source-url").hidden = $("#source-url-label").hidden = !custom;
  const b = (S.health && S.health.budget) || {};
  $("#live-note").textContent = live
    ? `A live run reads the scenario's reference page with Tavily, asks Nemotron for a rule and tests it in a Token Factory Sandbox. It takes 2 to 5 minutes. ${b.daily_cap ? `${b.used_today} of ${b.daily_cap} runs used today. ` : ""}${custom ? "" : "Custom report addresses are turned off on this server."}`
    : "Live runs are switched off on this server. The recorded runs above are real runs saved with their evidence.";
}

/* ---------- run view ---------- */
async function openRecorded(slug) {
  stopTimers();
  try {
    const rec = await api(`/api/recorded/${encodeURIComponent(slug)}`);
    rec._slug = slug;
    S.record = rec; S.mode = "replay"; S.sel = 0; S.tab = "rule"; S.error = null; S.running = false;
    S.shown = 0;
    renderRail(); render();
    S.timer = setInterval(() => {
      if (S.shown >= S.record.iterations.length) return stopTimers(render);
      S.shown++; S.sel = S.shown - 1; render();
    }, 1500);
  } catch (e) { S.error = e.message; render(); }
}

function stopTimers(then) {
  clearInterval(S.timer); S.timer = null;
  if (then) then();
}

function complete() {
  return S.mode === "replay" ? S.shown >= S.record.iterations.length : !!(S.record && S.record.totals);
}

function render() {
  const rec = S.record;
  $("#empty").hidden = !!rec; $("#run").hidden = !rec;
  const badge = $("#mode-badge");
  badge.className = "mode " + (S.mode || "");
  badge.textContent = !rec ? "" : S.mode === "replay"
    ? `Replay of a run recorded ${utc(rec.created_at)}. No model is running now.` : "Live run";
  if (!rec) return;

  $("#run-title").textContent = rec.scenario.title;
  const r = rec.research;
  if (r && r.primary) {
    const u = esc(r.primary.url);
    $("#run-source").innerHTML = `Report read with Tavily from ${/^https?:/.test(r.primary.url) ? `<a href="${u}" target="_blank" rel="noopener noreferrer">${u}</a>` : u} on ${esc(utc(r.primary.retrieved_at))}.`;
  } else if (r && r.error) {
    $("#run-source").textContent = `Tavily could not read the report (${r.error}). The run used the scenario's description instead.`;
  } else {
    $("#run-source").textContent = "Input: the scenario's SigmaHQ description and references. This run did no web research.";
  }
  $("#source-mode").textContent = sourceModeText(rec);
  const usedTavily = !!(r && r.primary);
  const shown = (r && r.screening && r.screening.sources) || [];
  const left = shown.filter((s) => s.status === "excluded").length, flagged = shown.filter((s) => s.status === "flagged").length;
  const old = (rec.answer_screen_legacy || []).length;
  const screenNote = left ? ` ${plural(left, "web result")} that looked like a published detection rule for this scenario ${left === 1 ? "was" : "were"} left out.`
    : flagged ? ` ${plural(flagged, "web result")} looked like a published detection rule for this scenario and ${flagged === 1 ? "was" : "were"} shown to the model.`
    : old ? ` Recorded before answer screening existed: ${plural(old, "corroborating source")} ${old === 1 ? "is" : "are"} a published rule page for this scenario, so this run had help a new report would not give.` : "";
  $("#roles").innerHTML = `
    <li><b>${esc(modelName(rec.model || "model"))}</b> wrote and repaired the rule.</li>
    <li><b>sigma check</b> validated every rule file.</li>
    <li><b>SigmaHQ's checker</b> ran each rule against the attack file and benign Windows logs ${evaluatorWhere(rec.evaluator)}.</li>
    <li class="${usedTavily ? "" : "off"}"><b>Tavily</b> ${usedTavily ? `read the threat report and searched for corroborating sources.${esc(screenNote)}` : "was not used in this run."}</li>`;

  const its = (S.mode === "replay" ? rec.iterations.slice(0, S.shown) : rec.iterations) || [];
  const pendingCell = (S.mode === "replay" && S.shown < rec.iterations.length) || (S.mode === "live" && S.running);
  $("#strip").innerHTML = its.map((it, i) => `<button class="cell ${classify(it)}" role="listitem" data-i="${i}" ${i === S.sel ? 'aria-current="true"' : ""} aria-label="Attempt ${i + 1}: ${esc(outcome(it))}">${i + 1}</button>`).join("")
    + (pendingCell ? '<span class="cell pending" role="listitem" aria-label="Next attempt in progress">…</span>' : "");
  document.querySelectorAll("#strip .cell[data-i]").forEach((c) => c.addEventListener("click", () => { S.sel = +c.dataset.i; render(); }));

  renderVerdict(rec, its, pendingCell);
  $("#ledger").innerHTML = its.map((it, i) => `
    <li class="${classify(it)}"><button data-i="${i}" ${i === S.sel ? 'aria-current="true"' : ""}>
      <span class="head">Attempt ${i + 1}, ${it.action === "generate" ? "first rule" : "repair"}</span>
      <span class="sub">${esc(outcome(it))}${it.resamples ? `. The model returned an empty answer ${plural(it.resamples, "time")} and was asked again.` : ""}</span>
    </button></li>`).join("");
  document.querySelectorAll("#ledger button").forEach((b) => b.addEventListener("click", () => { S.sel = +b.dataset.i; render(); }));

  renderTabs(rec, its);
  const done = complete() && !S.error;
  $("#results-section").hidden = !done || !its.length; $("#export-section").hidden = !done || !its.length;
  if (done && its.length) { renderResults(rec); wireExport(rec); }
}

function renderVerdict(rec, its, pending) {
  const v = $("#verdict");
  v.className = "verdict";
  if (S.error) { v.classList.add("error"); v.textContent = S.error; return; }
  if (pending || !its.length) {
    v.textContent = S.mode === "live" ? "Working: the model is writing and testing rules." : "Playing back the recorded run…";
    if (S.mode === "replay") { v.innerHTML = 'Playing back the recorded run. <button id="skip" class="link">Show the whole run</button>'; $("#skip").addEventListener("click", () => { stopTimers(); S.shown = rec.iterations.length; S.sel = S.shown - 1; render(); }); }
    return;
  }
  if (rec.success) { v.classList.add("pass"); v.textContent = `Passed after ${plural(rec.iterations.length, "attempt")}: the final rule detects the attack file and matches 0 benign events in the development set.`; }
  else { v.classList.add("fail"); v.textContent = `Did not pass in ${plural(rec.iterations.length, "attempt")}. Best rule: attempt ${rec.best_index + 1}. ${rec.stop_reason}.`; }
}

function renderTabs(rec, its) {
  const it = its[S.sel];
  ["rule", "evidence", "spec"].forEach((t) => {
    $(`#tab-${t}`).setAttribute("aria-selected", S.tab === t); $(`#tab-${t}`).tabIndex = S.tab === t ? 0 : -1;
    $(`#panel-${t}`).hidden = S.tab !== t;
  });
  if (!it) { $("#panel-rule").innerHTML = '<p class="note">The first rule will appear here.</p>'; $("#panel-evidence").innerHTML = ""; }
  else {
    const prev = S.sel > 0 ? its[S.sel - 1] : null;
    const lines = prev ? diffLines(prev.rule_text, it.rule_text) : it.rule_text.split("\n").map((s) => ({ t: "same", s }));
    $("#panel-rule").innerHTML = `<p class="note">${prev ? `Attempt ${S.sel + 1} compared with attempt ${S.sel}. Added lines are shaded, removed lines are struck through.` : "The first rule the model wrote. There is no earlier attempt to compare with."}</p>
      <pre class="code" tabindex="0" aria-label="Rule text">${lines.map((l) => `<span class="ln ${l.t}"><span class="mark">${l.t === "add" ? "+" : l.t === "del" ? "-" : " "}</span>${esc(l.s)}</span>`).join("")}</pre>`;
    $("#panel-evidence").innerHTML = evidenceHtml(it);
  }
  const s = rec.spec;
  $("#panel-spec").innerHTML = !s ? "" : `
    <p class="note">The model extracted these requirements from the report. An item is kept only if the model quoted text that appears word for word in the report and contains the value.</p>
    <dl class="kv"><dt>Behavior</dt><dd>${esc(s.behavior)}</dd><dt>Log source</dt><dd>${esc(s.logsource_category)}</dd></dl>
    ${(s.observables || []).map((o) => `<div class="ev"><h4>${esc(o.field)} ${esc(o.match)} <code>${esc(o.value)}</code></h4><pre>${esc(o.quote)}</pre></div>`).join("") || '<p class="note">No observables were grounded in the report text.</p>'}
    ${(s.techniques || []).length ? `<div class="ev"><h4>ATT&amp;CK techniques quoted in the report</h4><pre>${esc(s.techniques.map((t) => `${t.id}: ${t.quote}`).join("\n"))}</pre></div>` : ""}
    ${(rec.spec_dropped || []).length ? `<div class="ev"><h4 class="warn">Dropped as not supported by the report: ${rec.spec_dropped.length}</h4><pre>${esc(rec.spec_dropped.map((d) => `${d.kind}: ${JSON.stringify(d.item.value ?? d.item.id)} (${d.reason})`).join("\n"))}</pre></div>` : ""}`;
}

function evidenceHtml(it) {
  const parts = [];
  parts.push(it.validation.ok ? '<div class="ev"><h4 class="ok">Passed sigma check</h4></div>'
    : `<div class="ev"><h4 class="bad">Failed validation</h4><pre>${esc([...it.validation.errors, it.validation.sigma_output].filter(Boolean).join("\n"))}</pre></div>`);
  if (it.evaluator_error) parts.push(`<div class="ev"><h4 class="bad">The test runner could not load this rule</h4><pre>${esc(it.evaluator_error)}</pre></div>`);
  const ev = it.evaluation;
  if (ev) {
    parts.push(`<div class="ev"><h4 class="${ev.attack_detected ? "ok" : "warn"}">Attack file: detected ${ev.attack_detected} of ${ev.attack_total}</h4>
      ${ev.attack_missed.length ? `<p class="note">Missed: ${esc(ev.attack_missed.join(", "))}. These are the events from the missed file that the repair step showed the model:</p><pre>${esc(JSON.stringify(ev.attack_events.slice(0, 2), null, 1))}</pre>` : ""}</div>`);
    for (const [label, b] of Object.entries(ev.benign || {})) {
      const name = label.includes("dev") ? "Development benign set (seen by the repair step)" : "Held-out benign set";
      parts.push(`<div class="ev"><h4 class="${b.hits ? "bad" : "ok"}">${esc(name)}: ${plural(b.hits, "matching event")} in ${b.files_with_hits} of ${b.files_total} files</h4>
        ${b.examples.length ? `<p class="note">First matches:</p><pre>${esc(b.examples.slice(0, 2).map((e) => `${e.file}\n${e.event}`).join("\n\n"))}</pre>` : ""}</div>`);
    }
    parts.push(`<p class="note">Test time: ${esc(ev.seconds)} seconds.</p>`);
  }
  return parts.join("");
}

function renderResults(rec) {
  const its = rec.iterations, first = its[0], best = its[rec.best_index];
  const att = (it) => { if (!it || !it.evaluation) return { v: "Not tested", c: "na", s: "the rule was not valid" }; const e = it.evaluation; return { v: `${e.attack_detected} of ${e.attack_total}`, c: e.attack_detected ? "pass" : "miss" }; };
  const dev = (it) => { if (!it || !it.evaluation) return { v: "Not tested", c: "na" }; const e = it.evaluation, h = benignTotal(e), b = Object.values(e.benign)[0]; return { v: String(h), c: h ? "fp" : "pass", s: b ? `in ${b.files_with_hits} of ${b.files_total} files` : "" }; };
  const held = (h) => { if (!h) return { v: "Not measured", c: "na" }; const b = Object.values(h)[0]; return { v: String(b.hits), c: b.hits ? "fp" : "pass", s: `in ${b.files_with_hits} of ${b.files_total} files` }; };
  const ex = rec.expert;
  const exAtt = ex ? att({ evaluation: ex.dev }) : { v: "Not run", c: "na" };
  const exDev = ex ? dev({ evaluation: ex.dev }) : { v: "Not run", c: "na" };
  const rows = [
    ["Valid Sigma rule", [{ v: first.validation.ok ? "Yes" : "No", c: first.validation.ok ? "" : "miss" }, { v: best.validation.ok ? "Yes" : "No", c: best.validation.ok ? "" : "miss" }, { v: "Yes", c: "" }]],
    ["Attack file detected", [att(first), att(best), exAtt]],
    ["Benign events, development set", [dev(first), dev(best), exDev]],
    ["Benign events, held-out set (never shown to the model)", [{ v: "Not measured", c: "na" }, held(rec.heldout), ex ? held(ex.heldout) : { v: "Not run", c: "na" }]],
    ["Attempts used", [{ v: "1" }, { v: String(its.length) }, { v: "Not applicable", c: "na" }]],
    ["Tokens used by the model", [{ v: "" }, { v: String(rec.totals.tokens) + " in total", c: "" }, { v: "Not applicable", c: "na" }]],
  ];
  $("#results").innerHTML = `<thead><tr><th scope="col"></th><th scope="col">First attempt</th><th scope="col">${rec.success ? "Final rule" : "Best rule"} (attempt ${rec.best_index + 1})</th><th scope="col">SigmaHQ expert rule</th></tr></thead>
    <tbody>${rows.map(([label, cs]) => `<tr><th scope="row">${esc(label)}</th>${cs.map((c) => `<td class="${c.c || ""}">${esc(c.v)}${c.s ? `<span class="sub">${esc(c.s)}</span>` : ""}</td>`).join("")}</tr>`).join("")}</tbody>`;
  $("#results-note").textContent = "Counts are for this one attack file and these benign sets. After a repair, the detection result is not a held-out result. The expert rule was run through the same tests.";
}

/* ---------- export ---------- */
function download(name, text, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
function wireExport(rec) {
  const best = rec.iterations[rec.best_index], slug = (rec.scenario.title || "rule").toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 50);
  const ruleBtn = $("#dl-rule");
  ruleBtn.disabled = !best.validation.ok;
  ruleBtn.onclick = () => download(`${slug}.yml`, best.rule_text, "text/yaml");
  $("#dl-json").onclick = () => download(`${slug}-evidence.json`, JSON.stringify(rec, null, 2), "application/json");
  $("#dl-md").onclick = () => download(`${slug}-summary.md`, summaryMd(rec), "text/markdown");
}
function summaryMd(rec) {
  const best = rec.iterations[rec.best_index];
  const lines = [`# ${rec.scenario.title}`, "",
    `Result: ${rec.success ? "passed" : "did not pass"} after ${plural(rec.iterations.length, "attempt")}. ${rec.stop_reason}.`,
    `Model: ${modelName(rec.model)}. Recorded: ${utc(rec.created_at)}.`, "", "## Attempts", ""];
  rec.iterations.forEach((it, i) => lines.push(`${i + 1}. ${it.action}: ${outcome(it)}`));
  lines.push("", `## Rule (attempt ${rec.best_index + 1})`, "", "```yaml", best.rule_text.trimEnd(), "```", "",
    "## Limits", "", "- One recorded attack file per scenario; after a repair, detection is not a held-out result.",
    "- Benign logs come from a few lab machines and do not represent a production network.");
  return lines.join("\n") + "\n";
}

/* ---------- live ---------- */
$("#live-form").addEventListener("submit", async (e) => {
  e.preventDefault(); stopTimers();
  const body = { scenario_id: $("#scenario").value };
  const url = $("#source-url").value.trim(); if (url) body.source_url = url;
  try {
    const { run_id } = await api("/api/runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const sc = S.scenarios.find((s) => s.id === body.scenario_id);
    S.mode = "live"; S.running = true; S.error = null; S.sel = 0; S.tab = "rule";
    S.record = { scenario: { title: sc.title }, iterations: [], model: "", research: null, spec: null, created_at: new Date().toISOString() };
    renderRail(); render();
    S.poll = setInterval(() => pollRun(run_id), 1500);
  } catch (err) { $("#live-note").textContent = err.message; }
});
async function pollRun(id) {
  try {
    const st = await api(`/api/runs/${id}`);
    const rec = S.record;
    for (const ev of st.events) {
      if (ev.type === "research") rec.research = ev.data;
      if (ev.type === "spec") rec.spec = ev.data;
      if (ev.type === "start") rec.model = ev.data.model;
    }
    rec.iterations = st.events.filter((e) => e.type === "iteration").map((e) => e.data);
    S.sel = Math.max(0, rec.iterations.length - 1);
    if (st.status !== "running") {
      clearInterval(S.poll); S.running = false;
      if (st.status === "done") { S.record = st.record; S.sel = st.record.best_index; } else S.error = `The live run stopped: ${st.error}`;
      renderRail();
    }
    render();
  } catch (e) { clearInterval(S.poll); S.running = false; S.error = e.message; renderRail(); render(); }
}

/* ---------- tabs ---------- */
document.querySelectorAll(".tabs [role=tab]").forEach((b) => {
  b.addEventListener("click", () => { S.tab = b.id.replace("tab-", ""); render(); });
  b.addEventListener("keydown", (e) => {
    const order = ["rule", "evidence", "spec"], i = order.indexOf(S.tab);
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") { S.tab = order[(i + (e.key === "ArrowRight" ? 1 : 2)) % 3]; render(); $(`#tab-${S.tab}`).focus(); }
  });
});

/* ---------- start ---------- */
(async function init() {
  try {
    [S.health, S.recorded, S.scenarios] = await Promise.all([api("/api/health"), api("/api/recorded"), api("/api/scenarios")]);
    renderRail();
    const wanted = new URLSearchParams(location.search).get("run");
    if (wanted) openRecorded(wanted);
  } catch (e) { $("#empty").innerHTML = `<h2>The server did not respond.</h2><p class="err">${esc(e.message)}</p>`; }
})();
