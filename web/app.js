"use strict";
/* Shakedown workbench. Every number and state on screen comes from the server's run records (/api/*) or from the
   frozen results table copied below. Nothing here simulates progress, success or an integration. */

/* Frozen benchmark, copied from docs/RESULTS_TABLE.md (confirmatory set, Runs 8 and 9). tests/test_web_benchmark.py fails if it drifts. */
const BENCH = {
  "Run 8": {"note": "Headline run", "tasks": "19/20", "one_shot": "7/19", "after_repair": "14/19", "after_repair_errored_as_miss": "14/20", "repair_fixed_first_failure": "7/12", "heldout_fp": "1/19 rules, 1 events", "expert": "19/19"},
  "Run 9": {"note": "Comparison run", "tasks": "20/20", "one_shot": "6/20", "after_repair": "14/20", "after_repair_errored_as_miss": "14/20", "repair_fixed_first_failure": "8/14", "heldout_fp": "1/20 rules, 2 events", "expert": "20/20"}
};

const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
const cap = (t) => { const x = String(t ?? ""); return x.charAt(0).toUpperCase() + x.slice(1); };
const ofText = (frac) => String(frac).replace("/", " of ");
const utc = (iso) => (iso ? String(iso).slice(0, 16).replace("T", " ") + " UTC" : "");
const safeUrl = (u) => (/^https?:\/\/[^\s]+$/i.test(String(u || "")) ? String(u) : "");
const link = (u, text) => (safeUrl(u) ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(text ?? u)}</a>` : esc(text ?? u));
const tag = (cls, text) => `<span class="tag ${cls}">${esc(text)}</span>`;
const modelName = (id) => String(id || "").replace(/^nvidia\//i, "").replace(/nemotron-3-super-120b-a12b/i, "Nemotron 3 Super 120B").replace(/Nemotron-3_5-Lightning/i, "Nemotron 3.5 Lightning");
const benignTotal = (ev) => Object.values((ev && ev.benign) || {}).reduce((n, b) => n + b.hits, 0);
const store = {
  get(k, d) { try { const v = sessionStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k, v) { try { sessionStorage.setItem(k, JSON.stringify(v)); } catch { /* storage can be blocked; the page works without it */ } },
};

const S = {
  health: null, recorded: [], details: {}, scenarios: [], live: store.get("shk.live", []).map((x) => ({ ...x, status: "running", rec: blankRec(x.title, x.started), error: null })),
  route: { name: "overview", arg: "" }, replay: null, sel: 0, tab: "rule", compare: true, timer: null, poll: null, loadError: null,
  form: store.get("shk.form", { scenario: "", url: "" }), formError: "", starting: false, open: new Set(), fullDiff: false, focusChange: false, booted: false, pinned: false,
};
function blankRec(title, started) { return { scenario: { title }, iterations: [], model: "", research: null, spec: null, spec_dropped: [], heldout: null, expert: null, created_at: started }; }

/* ---------- record helpers ---------- */
function classify(it) {
  if (!it.validation.ok || !it.evaluation) return "invalid";
  const det = it.evaluation.attack_detected > 0, hits = benignTotal(it.evaluation);
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
const CLS_TAG = { pass: ["ok", "Passed"], miss: ["warn", "Missed the attack"], fp: ["bad", "False positives"], invalid: ["bad", "Not a usable rule"] };
function evaluatorWhere(ev) {
  const kind = ev && ev.kind;
  if (kind === "token-factory-sandbox") return "inside a Nebius Token Factory Sandbox (a microVM with no network)";
  if (kind === "local-docker") return "in a local isolated Docker container (not a Token Factory Sandbox)";
  return "in an isolated container";
}
/* What the model was allowed to see from the web, taken from the run record (never assumed). */
function sourceMode(rec) {
  let sm = rec.source_mode;
  const screening = rec.research && rec.research.screening;
  if (!sm && screening) {
    const count = (status) => screening.sources.filter((s) => s.status === status).length;
    sm = { mode: screening.policy === "exclude" ? "leakage-controlled" : "research", excluded: count("excluded"), flagged_shown: count("flagged") };
  }
  if (!sm) {
    return rec.research ? { cls: "warn", short: "Not screened", line: "Source handling: not screened. Recorded before answer screening existed, so this is not a clean test.", text: "Source handling: not screened. This was recorded before answer screening existed, so web results may have included the rule being written. It is not a clean test." }
      : { cls: "", short: "No web research", line: "Source handling: not recorded for this run.", text: "Source handling: not recorded for this run." };
  }
  if (sm.verdict === "no_web_research") return { cls: "", short: "No web research", line: "Source handling: no web research in this run.", text: "Source handling: no web research in this run. The model saw only the scenario's description." };
  if (sm.mode === "leakage-controlled") {
    const n = sm.excluded;
    return { cls: "", short: n ? `Screened, ${n} left out` : "Screened, none flagged",
      line: `Source handling: leakage-controlled. ${n ? plural(n, "web result") + " left out." : "No web result looked like the rule being written."}`,
      text: `Source handling: leakage-controlled. ${n ? plural(n, "web result") + " looked like the rule being written and " + (n === 1 ? "was" : "were") + " left out." : "No web result looked like the rule being written."} Other pages were still shown, so this is screening, not proof the run is free of leakage.` };
  }
  return { cls: "warn", short: "Research mode", line: "Source handling: research mode. Rule-like web results may have been shown to the model, so this is not a clean test.", text: `Source handling: research mode (nothing is removed). ${sm.flagged_shown ? plural(sm.flagged_shown, "source") + " looked like the rule being written and " + (sm.flagged_shown === 1 ? "was" : "were") + " shown to the model, so this run is not a clean test." : "No source was flagged."}` };
}
function legacyNote(rec) {
  const old = rec.answer_screen_legacy || [];
  return old.length ? `Recorded before answer screening existed: ${plural(old.length, "corroborating source")} ${old.length === 1 ? "is" : "are"} a published rule page for this scenario, so this run had help a new report would not give.` : "";
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
function splitRows(lines) {
  const rows = []; let dels = [], adds = [], l = 0, r = 0;
  const flush = () => {
    for (let k = 0; k < Math.max(dels.length, adds.length); k++) {
      rows.push({ l: dels[k] !== undefined ? { t: "del", s: dels[k], n: ++l } : { t: "blank", s: "" }, r: adds[k] !== undefined ? { t: "add", s: adds[k], n: ++r } : { t: "blank", s: "" } });
    }
    dels = []; adds = [];
  };
  for (const ln of lines) {
    if (ln.t === "del") dels.push(ln.s); else if (ln.t === "add") adds.push(ln.s);
    else { flush(); rows.push({ l: { t: "same", s: ln.s, n: ++l }, r: { t: "same", s: ln.s, n: ++r } }); }
  }
  flush();
  return rows;
}

/* ---------- YAML view ---------- */
function hlValue(v) {
  let out = "", last = 0;
  for (const m of v.matchAll(/('(?:[^']|'')*'|"[^"]*")|(\b\d+\b)/g)) {
    out += esc(v.slice(last, m.index));
    out += m[1] ? `<span class="tk-str">${esc(m[1])}</span>` : `<span class="tk-num">${esc(m[2])}</span>`;
    last = m.index + m[0].length;
  }
  return out + esc(v.slice(last));
}
function hlYaml(line) {
  if (/^\s*#/.test(line)) return `<span class="tk-com">${esc(line)}</span>`;
  const k = line.match(/^(\s*)((?:- )*)([^\s:#'"-][^:]*?|-[^\s:][^:]*?)(:)(?=\s|$)(.*)$/);
  if (k) return `${esc(k[1])}<span class="tk-dash">${esc(k[2])}</span><span class="tk-key">${esc(k[3])}</span>:${hlValue(k[5])}`;
  const d = line.match(/^(\s*)(- )(.*)$/);
  if (d) return `${esc(d[1])}<span class="tk-dash">- </span>${hlValue(d[3])}`;
  return hlValue(line);
}
function editorLines(rows) {
  return `<div class="lines">${rows.map((r) => `<div class="ln ${r.t}"><span class="no" aria-hidden="true">${r.n ?? ""}</span><span class="gut" aria-hidden="true">${r.t === "add" ? "+" : r.t === "del" ? "−" : ""}</span><span class="tx">${hlYaml(r.s)}</span></div>`).join("")}</div>`;
}
function plainRows(text) { return text.replace(/\n$/, "").split("\n").map((s, i) => ({ t: "same", s, n: i + 1 })); }
function unifiedRows(prev, cur) { let n = 0; return diffLines(prev, cur).map((l) => ({ t: l.t, s: l.s, n: l.t === "del" ? "" : ++n })); }
function hunks(rows, ctx = 3) {
  if (S.fullDiff) return rows;
  const keep = new Array(rows.length).fill(false);
  rows.forEach((r, i) => { if (r.l.t !== "same" || r.r.t !== "same") for (let k = Math.max(0, i - ctx); k <= Math.min(rows.length - 1, i + ctx); k++) keep[k] = true; });
  if (!keep.some(Boolean)) return rows;
  const out = []; let gap = 0;
  rows.forEach((r, i) => { if (keep[i]) { if (gap) { out.push({ gap }); gap = 0; } out.push(r); } else gap++; });
  if (gap) out.push({ gap });
  return out;
}
function splitView(a, b, titleA, titleB) {
  const rows = hunks(splitRows(diffLines(a, b)));
  const side = (key) => `<div class="editor-body" tabindex="0" aria-label="${esc(key === "l" ? titleA : titleB)} (rule text)"><div class="lines">${rows.map((r) => { if (r.gap) return `<div class="ln gap"><span class="no" aria-hidden="true"></span><span class="gut" aria-hidden="true"></span><span class="tx">… ${plural(r.gap, "unchanged line")}</span></div>`; const c = r[key]; return `<div class="ln ${c.t === "blank" ? "blank" : c.t}"><span class="no" aria-hidden="true">${c.n ?? ""}</span><span class="gut" aria-hidden="true">${c.t === "add" ? "+" : c.t === "del" ? "−" : ""}</span><span class="tx">${c.t === "blank" ? " " : hlYaml(c.s)}</span></div>`; }).join("")}</div></div>`;
  return `<div class="split editor"><div><h3>${esc(titleA)}</h3>${side("l")}</div><div><h3>${esc(titleB)}</h3>${side("r")}</div></div>`;
}

/* ---------- api and data ---------- */
async function api(path, opts) {
  const r = await fetch(path, opts);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail || `Request failed (${r.status})`);
  return body;
}
async function loadDetail(slug) {
  if (!S.details[slug]) { const rec = await api(`/api/recorded/${encodeURIComponent(slug)}`); S.details[slug] = rec; }
  return S.details[slug];
}
function applyEvents(run, events) {
  const rec = run.rec;
  for (const ev of events) {
    if (ev.type === "start") rec.model = ev.data.model;
    else if (ev.type === "research") rec.research = ev.data;
    else if (ev.type === "spec") { rec.spec = ev.data; rec.spec_dropped = ev.data.dropped || []; }
    else if (ev.type === "heldout") rec.heldout = ev.data;
    else if (ev.type === "expert") rec.expertPartial = ev.data;
  }
  rec.iterations = events.filter((e) => e.type === "iteration").map((e) => e.data);
}
const liveSig = (run) => `${run.status}|${run.rec.iterations.length}|${run.rec.research ? 1 : 0}${run.rec.spec ? 1 : 0}${run.rec.heldout ? 1 : 0}${run.rec.expertPartial ? 1 : 0}|${run.error || ""}`;
function persistLive() { store.set("shk.live", S.live.map((x) => ({ id: x.id, title: x.title, started: x.started }))); }
async function pollLive(run) {
  const before = liveSig(run), prevIts = run.rec.iterations.length;
  try {
    const st = await api(`/api/runs/${run.id}`);
    applyEvents(run, st.events);
    if (st.status === "done") { run.rec = st.record; run.status = "done"; }
    else if (st.status === "error") { run.status = "error"; run.error = st.error; }
  } catch (e) {
    if (/Unknown run/.test(e.message)) { S.live = S.live.filter((x) => x !== run); persistLive(); if (S.route.name === "live" && S.route.arg === run.id) { location.hash = "#/runs"; } return true; }
    /* A dropped connection is not a failed run: the server may still be working. Keep asking, and say so. */
    run.stale = (run.stale || 0) + 1;
    return run.stale === 3;
  }
  const wasStale = run.stale >= 3; run.stale = 0;
  const changed = before !== liveSig(run) || wasStale;
  if (changed) {
    if (run.rec.iterations.length > prevIts) { const it = run.rec.iterations[run.rec.iterations.length - 1]; announce(`Attempt ${run.rec.iterations.length}: ${outcome(it)}`); if (S.route.name === "live" && S.route.arg === run.id) S.sel = run.rec.iterations.length - 1; }
    if (run.status === "done") { announce(run.rec.success ? "Live run finished: passed." : "Live run finished: did not pass."); if (S.route.name === "live" && S.route.arg === run.id) S.sel = run.rec.best_index; }
    if (run.status === "error") announce(`Live run stopped: ${run.error}`);
  }
  return changed;
}
function ensurePolling() {
  const active = S.live.some((x) => x.status === "running");
  if (active && !S.poll) {
    S.poll = setInterval(async () => {
      const runs = S.live.filter((x) => x.status === "running");
      const results = await Promise.all(runs.map(pollLive));
      if (results.some(Boolean)) { persistLive(); renderIfData(); announce(runs.some((r) => r.stale >= 3) ? "Lost contact with the server. Trying again." : ""); }
      if (!S.live.some((x) => x.status === "running")) { clearInterval(S.poll); S.poll = null; }
    }, 1500);
  }
}
function announce(msg) { const a = $("#announce"); if (a) { a.textContent = ""; setTimeout(() => { a.textContent = msg; }, 30); } }

/* ---------- rows for tables ---------- */
function allRuns() {
  const rows = [];
  for (const x of [...S.live].reverse()) {
    const rec = x.rec, its = rec.iterations;
    const oc = x.status === "running" ? ["info", "Running"] : x.status === "error" ? ["bad", "Stopped"] : rec.success ? ["ok", "Passed"] : ["bad", "Did not pass"];
    rows.push({ key: `live-${x.id}`, href: `#/live/${x.id}`, title: x.title, mode: "Live (this session)", oc, detail: x.status === "done" ? `in ${plural(its.length, "attempt")}` : x.status === "running" ? `${plural(its.length, "attempt")} so far` : "", tokens: rec.totals ? rec.totals.tokens : null, source: rec.research || rec.source_mode ? sourceMode(rec) : { cls: "", short: x.status === "running" ? "Reading the report" : "" }, when: x.started });
  }
  const rec = [...S.recorded];
  rec.sort((a, b) => String((S.details[b.slug] || {}).created_at || "").localeCompare(String((S.details[a.slug] || {}).created_at || "")));
  for (const r of rec) {
    const d = S.details[r.slug];
    rows.push({ key: `rec-${r.slug}`, href: `#/run/${r.slug}`, title: r.title, mode: "Replay", oc: r.success ? ["ok", "Passed"] : ["bad", "Did not pass"], detail: `in ${plural(r.iterations, "attempt")}`, tokens: r.tokens, source: d ? sourceMode(d) : { cls: "", short: r.used_research ? "Report read with Tavily" : "No web research" }, when: d ? d.created_at : "" });
  }
  return rows;
}
function runsTable(rows, caption) {
  if (!rows.length) return `<div class="empty"><h2>No assessments yet</h2><p class="muted">Start one from <a href="#/new">New assessment</a>, or open a recorded run once the server lists some.</p></div>`;
  return `<div class="tbl-wrap" tabindex="0" role="region" aria-label="${esc(caption)}"><table><caption class="sr">${esc(caption)}</caption>
    <thead><tr><th scope="col">Assessment</th><th scope="col">Mode</th><th scope="col">Outcome</th><th scope="col">Source handling</th><th scope="col" class="num">Tokens</th><th scope="col">Date (UTC)</th></tr></thead>
    <tbody>${rows.map((r) => `<tr class="link-row"><th scope="row"><a class="title-link" href="${esc(r.href)}">${esc(r.title)}</a></th>
      <td>${esc(r.mode)}</td><td>${tag(...r.oc)}${r.detail ? `<span class="sub">${esc(r.detail)}</span>` : ""}</td>
      <td>${r.source.cls ? tag(r.source.cls, r.source.short) : esc(r.source.short)}</td>
      <td class="num">${r.tokens == null ? "" : esc(r.tokens.toLocaleString("en-US"))}</td><td style="white-space:nowrap">${esc(r.when ? String(r.when).slice(0, 16).replace("T", " ") : "")}</td></tr>`).join("")}</tbody></table></div>`;
}

/* ---------- views ---------- */
function viewOverview() {
  const h = S.health || {}, live = h.live || {}, b = h.budget || {};
  const rows = allRuns();
  const sys = h.live_enabled ? `
    <dl class="kv">
      <dt>Live execution</dt><dd>${tag("ok", "On")}</dd>
      <dt>Model</dt><dd>${esc(modelName(live.model))}, served by Nebius Token Factory</dd>
      <dt>Tests run in</dt><dd>${esc(evaluatorShort(live.evaluator))}</dd>
      <dt>Web sources</dt><dd>${live.answer_policy === "exclude" ? "Rule-like results are left out and listed" : live.answer_policy === "flag" ? "Rule-like results are shown and flagged (research mode)" : "Not recorded"}</dd>
      ${b.daily_cap ? `<dt>Runs today</dt><dd>${esc(b.used_today)} of ${esc(b.daily_cap)}</dd>` : ""}
    </dl>` : `<dl class="kv"><dt>Live execution</dt><dd>${tag("info", "Off")}</dd><dt>Recorded runs</dt><dd>${esc(h.recorded ?? S.recorded.length)}, real runs saved with their evidence</dd></dl>`;
  return `
  <div class="page-head"><div><h1 id="page-title" tabindex="-1">Overview</h1>
    <p class="lede">Turn a threat report into a Sigma rule candidate, then see what happened when it was tested against attack and benign Windows logs.</p></div>
    </div>
  <div class="cols-2">
    <div>
      <section class="panel panel-pad" aria-labelledby="start-h" style="margin-bottom:28px"><h2 class="sec" id="start-h">Start here</h2>
        <p class="small measure">Pick a detection scenario. A live run reads its threat report, writes a Sigma rule with Nemotron and tests it in an isolated Sandbox, then repairs it from the evidence if it fails. ${h.live_enabled ? "" : "Live runs are off on this server; recorded runs are real runs you can open and inspect."}</p>
        <div class="actions" style="margin-top:12px"><a class="btn primary" href="#/new">New assessment</a>${S.recorded.length ? `<a class="btn" href="#/run/${esc(S.recorded[0].slug)}">Open a recorded run</a>` : ""}</div></section>
      <section aria-labelledby="recent-h"><div style="display:flex;justify-content:space-between;align-items:baseline;gap:12px"><h2 class="sec" id="recent-h">Recent assessments</h2><a href="#/runs" class="small">All assessments</a></div>
        ${runsTable(rows.slice(0, 6), "Table of recent assessments")}
        <p class="help">Replays are real runs saved with their evidence; playing one back calls no model.</p></section>
    </div>
    <aside class="stack" aria-label="About this server">
      <section class="panel"><div class="panel-head"><h2>Three separate questions</h2></div><div class="panel-pad small stack">
        <p><b>Rule validity.</b> Did <code>sigma check</code> accept the rule as well-formed?</p>
        <p><b>Attack validation.</b> Did it detect the labelled attack evidence, and did it match benign logs?</p>
        <p><b>Environment preflight.</b> What did a read-only SIEM search find in your environment? <a href="#/integrations">Connect a SIEM</a> to run one.</p>
        <p class="muted">Each result keeps these apart. A valid rule is not a rule that detects.</p></div></section>
      <section class="panel"><div class="panel-head"><h2>This server</h2></div><div class="panel-pad">${sys}</div></section>
    </aside>
  </div>`;
}
const evaluatorShort = (ev) => (ev && ev.kind === "token-factory-sandbox" ? "Nebius Token Factory Sandbox (microVM, network disabled)" : ev && ev.kind === "local-docker" ? "Local Docker container" : (ev && ev.kind) || "an isolated container");

function viewNew() {
  const h = S.health || {}, liveOn = !!h.live_enabled, custom = !!h.allow_custom_url;
  const cats = {};
  for (const sc of S.scenarios) (cats[sc.category] ||= []).push(sc);
  if (!S.form.scenario || !S.scenarios.some((s) => s.id === S.form.scenario)) S.form.scenario = (S.scenarios[0] || {}).id || "";
  const sc = S.scenarios.find((s) => s.id === S.form.scenario) || {};
  const opts = Object.entries(cats).map(([c, list]) => `<optgroup label="${esc(c)}">${list.map((s) => `<option value="${esc(s.id)}" ${s.id === S.form.scenario ? "selected" : ""}>${esc(s.title)}</option>`).join("")}</optgroup>`).join("");
  const lv = h.live || {};
  return `
  <div class="page-head"><div><h1 id="page-title" tabindex="-1">New assessment</h1>
    <p class="lede">Pick a detection scenario. Shakedown reads its threat report, writes a Sigma rule and tests it. It never deploys anything.</p></div></div>
  <div class="cols-2">
    <form id="assess-form" class="panel panel-pad" novalidate>
      <div class="field"><label for="scenario">Scenario</label>
        <select id="scenario" name="scenario" ${S.scenarios.length ? "" : "disabled"}>${opts || "<option>No scenarios on this server</option>"}</select>
        <p class="help">${esc(sc.category || "")}${sc.recorded_slug ? " · a recorded run of this scenario is available" : ""}</p></div>
      ${custom ? `<div class="field"><label for="source-url">Threat report address <span class="muted">(optional)</span></label>
        <input id="source-url" name="url" type="url" inputmode="url" autocomplete="off" placeholder="https://" value="${esc(S.form.url)}">
        <p class="help">Leave empty to read the scenario's own reference page. A report address is read as a web page; this server does not take pasted report text.</p></div>`
        : `<p class="help">Custom report addresses are turned off on this server. The scenario's own reference page is read.</p>`}
      ${(sc.reference_urls || []).length ? `<div class="field"><div class="label">Reference pages for this scenario</div><ul class="list-plain small">${sc.reference_urls.map((u) => `<li class="mono" style="overflow-wrap:anywhere">${link(u)}</li>`).join("")}</ul></div>` : ""}
      <div class="actions" style="margin-top:20px">
        <button class="btn primary" id="start-btn" type="submit" ${liveOn && !S.starting && S.scenarios.length ? "" : "disabled"}>${S.starting ? "Starting" : "Start assessment"}</button>
        ${sc.recorded_slug ? `<a class="btn" href="#/run/${esc(sc.recorded_slug)}">Play the recorded run</a>` : ""}
      </div>
      ${liveOn ? `<p class="help">A live run takes about 2 to 5 minutes${h.budget && h.budget.daily_cap ? ` and counts against the daily limit (${esc(h.budget.used_today)} of ${esc(h.budget.daily_cap)} used today)` : ""}. You can leave this page; the run keeps going.</p>`
        : `<div class="notice" style="margin-top:14px">Live runs are switched off on this server. Recorded runs are real runs saved with their evidence.</div>`}
      <div id="form-error" role="alert">${S.formError ? `<p class="form-error">${esc(S.formError)}</p>` : ""}</div>
    </form>
    <aside class="panel"><div class="panel-head"><h2>What a run does</h2></div>
      <ol class="panel-pad small stack list-plain">
        <li><b>Research.</b> Tavily reads the report${liveOn ? "" : " (live runs only)"} and searches for corroborating pages. Pages that look like the rule being written are ${lv.answer_policy === "flag" ? "flagged but shown" : "left out and listed"}.</li>
        <li><b>Extraction.</b> ${esc(modelName(lv.model) || "The model")} proposes observables. Each needs a word-for-word quote from the report or it is dropped.</li>
        <li><b>Generation.</b> The model writes a Sigma rule. <code>sigma check</code> validates it.</li>
        <li><b>Evaluation.</b> SigmaHQ's checker runs it ${esc(evaluatorWhere(lv.evaluator))} against one attack file and benign logs.</li>
        <li><b>Repair.</b> If it fails, the model sees what it missed and retries, up to three repairs.</li></ol></aside>
  </div>`;
}

function viewRuns() {
  return `<div class="page-head"><div><h1 id="page-title" tabindex="-1">Run history</h1>
    <p class="lede">Live runs started in this browser session and the recorded runs saved on this server.</p></div></div>
    ${runsTable(allRuns(), "Table of all assessments")}
    <p class="help">Live runs started here are kept by the server only while it runs; the recorded runs are files. A replay marked "Not screened" was recorded before answer screening existed: its web results may have included the rule being written, so it is not a clean test.</p>`;
}

/* ----- run view ----- */
function currentRun() {
  const r = S.route;
  if (r.name === "run") {
    if (!S.replay || S.replay.slug !== r.arg) return null;
    const rec = S.replay.rec, n = rec.iterations.length;
    return { kind: "replay", rec, its: rec.iterations.slice(0, S.replay.shown), complete: S.replay.shown >= n, running: S.replay.shown < n, error: null };
  }
  const lr = S.live.find((x) => x.id === r.arg);
  return lr ? { kind: "live", id: lr.id, rec: lr.rec, its: lr.rec.iterations, complete: lr.status === "done", running: lr.status === "running", error: lr.error, started: lr.started, stale: lr.stale || 0 } : null;
}
const bestIndex = (run) => (run.complete && typeof run.rec.best_index === "number" ? run.rec.best_index : Math.max(0, run.its.length - 1));

function stagesFor(run) {
  const { rec, its, complete, running, error } = run, first = its[0], r = rec.research, sp = rec.spec;
  const sm = sourceMode(rec), st = [];
  const add = (o) => { st.push({ have: true, state: "done", label: "", body: "", meta: "", more: "", ...o }); };
  /* 1 research */
  if (r || complete) {
    if (r && r.primary) {
      const cs = (r.screening && r.screening.sources) || [];
      add({ key: "research", title: "Research", state: "done", label: "Report read", body: `Tavily read ${link(r.primary.url)}. ${cs.length ? `It also found ${plural(cs.filter((s) => s.role !== "primary").length, "corroborating page")}.` : ""}`, meta: `Retrieved ${utc(r.primary.retrieved_at)}. ${sm.short}.`, metaCls: sm.cls });
    } else if (r && r.error) add({ key: "research", title: "Research", state: "warn", label: "Report not read", body: `Tavily could not read the report (${esc(r.error)}). The run used the scenario's description instead.` });
    else add({ key: "research", title: "Research", state: "skip", label: "Not used", body: "This run did no web research. The model saw only the scenario's description and references." });
  } else add({ key: "research", title: "Research", have: false, pending: "Tavily is reading the report." });
  /* 2 extraction */
  if (sp || complete) {
    const n = sp ? (sp.observables || []).length : 0, dr = (rec.spec_dropped || []).length;
    if (!sp) add({ key: "extraction", title: "Observable extraction", state: "skip", label: "Not recorded", body: "No extraction result is recorded for this run." });
    else if (n) add({ key: "extraction", title: "Observable extraction", state: "done", label: `${n} kept`, body: `${plural(n, "observable")} kept, each with a quote that appears word for word in the report.${dr ? ` ${dr} dropped as not supported by the report.` : ""}` });
    else add({ key: "extraction", title: "Observable extraction", state: "warn", label: "None kept", body: `No observables were grounded in the report text.${dr ? ` ${dr} dropped.` : ""} Nothing in the rule is traced to a quote from the report.` });
  } else add({ key: "extraction", title: "Observable extraction", have: false, pending: `${esc(modelName(rec.model) || "The model")} is extracting observables.` });
  /* 3 to 6 first attempt */
  if (first) {
    add({ key: "generation", title: "Rule generation", label: "Rule written", body: `${esc(modelName(rec.model) || "The model")} wrote the first rule.${first.resamples ? ` It returned an empty answer ${plural(first.resamples, "time")} and was asked again.` : ""}`, meta: [first.latency_s != null ? `${first.latency_s} s` : "", first.tokens ? `${first.tokens.toLocaleString("en-US")} tokens` : ""].filter(Boolean).join(", ") });
    const v = first.validation;
    add({ key: "validation", title: "Sigma validation", state: v.ok ? "done" : "bad", label: v.ok ? "Valid" : "Rejected", body: v.ok ? `sigma check accepted attempt 1.${its.length > 1 ? ` ${its.filter((i) => i.validation.ok).length} of ${its.length} attempts were valid rules.` : ""}` : `sigma check rejected attempt 1: ${esc((v.errors[0] || "").replace(/^rule could not be built: /, ""))}`,
      more: !v.ok ? [...v.errors, v.sigma_output].filter(Boolean).join("\n") : "" });
    const cls = classify(first);
    if (!v.ok) add({ key: "evaluation", title: "Sandbox evaluation", state: "skip", label: "Not run", body: "Attempt 1 did not validate, so it was not tested." });
    else if (first.evaluator_error) add({ key: "evaluation", title: "Sandbox evaluation", state: "bad", label: "Runner error", body: "The test runner could not load this rule.", more: first.evaluator_error });
    else {
      const ev = first.evaluation, b = Object.values(ev.benign || {})[0];
      add({ key: "evaluation", title: "Sandbox evaluation", state: cls === "pass" ? "done" : cls === "miss" ? "warn" : "bad", label: cls === "pass" ? "Detected" : cls === "miss" ? "Missed" : "False positives",
        body: `${esc(outcome(first))}. Run ${evaluatorWhere(rec.evaluator)}.`, meta: `Attack file ${ev.attack_detected} of ${ev.attack_total}${b ? `; benign ${b.hits} events in ${b.files_with_hits} of ${b.files_total} files` : ""}. Test time ${ev.seconds} s.` });
    }
    if (cls === "pass") {
      add({ key: "diagnosis", title: "Failure diagnosis", state: "skip", label: "Not needed", body: "Attempt 1 passed, so there was nothing to diagnose." });
      add({ key: "repair", title: "Repair and retest", state: "skip", label: "None", body: "No repair was attempted. This run was not repaired." });
    } else {
      const ev = first.evaluation, shown = ev && ev.attack_missed && ev.attack_missed.length;
      add({ key: "diagnosis", title: "Failure diagnosis", state: "done", label: "Diagnosed", body: `${esc(outcome(first))}.${shown ? " The repair step was shown events from the file it missed." : ""}` });
      const reps = its.slice(1), lastPass = reps.length && classify(reps[reps.length - 1]) === "pass";
      /* The held-out and expert events are emitted only after the repair loop has ended, so their arrival also ends this stage. */
      if (lastPass || ((complete || rec.heldout || rec.expertPartial) && !error)) {
        add({ key: "repair", title: "Repair and retest", state: lastPass ? "done" : "bad", label: lastPass ? "Repaired" : "Not repaired",
          body: reps.length ? `${reps.map((it, i) => `Attempt ${i + 2}: ${esc(outcome(it))}.`).join(" ")} ${lastPass ? "" : `Did not pass in ${plural(its.length, "attempt")}.${rec.stop_reason ? ` ${esc(cap(rec.stop_reason))}.` : ""}`}` : `No repair completed. ${esc(cap(rec.stop_reason))}`,
          meta: lastPass ? "A repair sees the events it missed, so this detection is not a held-out result." : "" });
      } else add({ key: "repair", title: "Repair and retest", have: false, pending: reps.length ? `Attempt ${its.length}: ${esc(outcome(its[its.length - 1]))}. Repairing again.` : "Repairing the rule from the missed events." });
    }
  } else {
    for (const [key, title, pending] of [["generation", "Rule generation", `${esc(modelName(rec.model) || "The model")} is writing the first rule.`], ["validation", "Sigma validation", ""], ["evaluation", "Sandbox evaluation", ""], ["diagnosis", "Failure diagnosis", ""], ["repair", "Repair and retest", ""]]) add({ key, title, have: false, pending });
  }
  /* 8 held-out and expert */
  const held = rec.heldout, ex = rec.expert || null, exp = ex ? ex.dev : null;
  const exTxt = exp ? `SigmaHQ's expert rule: attack detected ${exp.attack_detected} of ${exp.attack_total}.` : rec.expertPartial ? `SigmaHQ's expert rule: attack detected ${rec.expertPartial.detected} of ${rec.expertPartial.total}.` : "";
  const hb = held ? Object.values(held)[0] : null;
  if ((run.kind === "live" && (rec.heldout || complete)) || (run.kind === "replay" && complete)) {
    if (!hb && !exTxt) add({ key: "baseline", title: "Held-out check and expert comparison", state: "skip", label: "Not measured", body: "No held-out result or expert comparison is recorded for this run." });
    else add({ key: "baseline", title: "Held-out check and expert comparison", state: hb && hb.hits ? "warn" : "done", label: hb ? (hb.hits ? "Held-out matches" : "Held-out clean") : "Expert only", body: `${hb ? `Held-out benign logs (never shown to the model): ${plural(hb.hits, "matching event")} in ${hb.files_with_hits} of ${hb.files_total} files. ` : ""}${exTxt}` });
  } else add({ key: "baseline", title: "Held-out check and expert comparison", have: false, pending: "Running the held-out logs and the expert rule." });
  /* assign running / waiting / failed to the stages that have no data yet */
  let marked = false;
  for (const s of st) {
    if (s.have) continue;
    if (!marked) { marked = true; if (error) { s.state = "bad"; s.label = "Stopped"; s.body = `The live run stopped here: ${esc(error)}`; } else if (running) { s.state = "running"; s.label = "Running"; s.body = s.pending; } else { s.state = "wait"; s.label = "Waiting"; } }
    else { s.state = "wait"; s.label = error ? "Not reached" : "Waiting"; s.body = ""; }
  }
  return st;
}
const GLYPH = { done: "✓", warn: "!", bad: "×", running: "…", wait: "", skip: "–" };
const STATE_TAG = { done: "ok", warn: "warn", bad: "bad", running: "info", wait: "", skip: "na" };
function traceHtml(run) {
  const items = stagesFor(run).map((s) => `<li class="stage ${s.state}"><span class="mark" aria-hidden="true">${GLYPH[s.state]}</span>
    <div class="stage-title"><span>${esc(s.title)}</span>${s.label ? tag(STATE_TAG[s.state], s.label) : ""}</div>
    ${s.body ? `<div class="stage-body">${s.body}</div>` : ""}${s.meta ? `<div class="stage-meta">${s.metaCls === "warn" ? `<b class="cell-warn">${esc(s.meta)}</b>` : esc(s.meta)}</div>` : ""}
    ${s.more ? `<details data-k="more-${esc(s.key)}"><summary>Technical detail</summary><pre>${esc(s.more)}</pre></details>` : ""}</li>`);
  return `<ol class="trace" aria-label="Execution trace">${items.join("")}</ol>`;
}
function rolesHtml(run) {
  const rec = run.rec, used = !!(rec.research && rec.research.primary), r = rec.research, cs = (r && r.screening && r.screening.sources) || [];
  const left = cs.filter((s) => s.status === "excluded").length;
  return `<dl class="roles"><dt>${esc(modelName(rec.model) || "Model")}</dt><dd>Extracts observables, writes the rule and proposes repairs.</dd>
    <dt>Nebius Token Factory</dt><dd>Serves the model. ${rec.evaluator && rec.evaluator.kind === "token-factory-sandbox" ? "Its Sandbox (a microVM with no network) runs the tests." : ""}</dd>
    <dt>SigmaHQ's checker</dt><dd>Runs each rule against the attack file and benign Windows logs ${esc(evaluatorWhere(rec.evaluator))}. Code, not the model, counts the matches.</dd>
    <dt>sigma check</dt><dd>Validates every rule file.</dd>
    <dt class="${used ? "" : "off"}">Tavily</dt><dd class="${used ? "" : "off"}">${used ? `Read the threat report and searched for corroborating pages.${left ? ` ${plural(left, "page")} that looked like the rule being written ${left === 1 ? "was" : "were"} left out.` : ""}` : "Not used in this run."}</dd></dl>`;
}

function verdictsHtml(run) {
  const { rec, its, complete } = run;
  const bi = bestIndex(run), best = its[bi], first = its[0];
  const heldout = complete ? rec.heldout : null, hb = heldout ? Object.values(heldout)[0] : null;
  const validCount = its.filter((i) => i.validation.ok).length;
  /* 1 rule validity */
  let v1;
  if (!best) v1 = { cls: "", state: "Waiting", lines: ["No rule has been written yet."] };
  else if (best.validation.ok) v1 = { cls: "ok", state: "Valid", lines: [`Attempt ${bi + 1} was accepted by sigma check.`, its.length > 1 ? `${validCount} of ${its.length} attempts were valid rules.` : "", complete && its.length - 1 !== bi && !its[its.length - 1].validation.ok ? `The last attempt (${its.length}) was rejected by sigma check.` : ""] };
  else v1 = { cls: "bad", state: "Invalid", lines: [`Attempt ${bi + 1} was rejected by sigma check.`, (best.validation.errors[0] || "").replace(/^rule could not be built: /, "")] };
  /* 2 attack validation */
  let v2;
  if (!best) v2 = { cls: "", state: "Waiting", lines: ["Nothing to test yet."] };
  else if (!best.evaluation) v2 = { cls: best.evaluator_error ? "bad" : "", state: best.evaluator_error ? "Runner error" : "Not tested", lines: [best.evaluator_error ? "The test runner could not load the rule." : "The rule was not valid, so it was not run."] };
  else {
    const ev = best.evaluation, cls = classify(best), b = Object.values(ev.benign || {})[0];
    const repaired = first && first.evaluation && bi > 0 ? `First attempt ${first.evaluation.attack_detected} of ${first.evaluation.attack_total}; after repair ${ev.attack_detected} of ${ev.attack_total}. Not a held-out result.` : "";
    v2 = { cls: cls === "pass" ? "ok" : cls === "miss" ? "warn" : "bad", state: cls === "pass" ? (bi > 0 && first && first.evaluation && classify(first) !== "pass" ? "Detected after repair" : "Detected") : cls === "miss" ? "Missed" : "False positives",
      lines: [`Attack file: ${ev.attack_detected} of ${ev.attack_total} detected`, b ? `Benign, development: ${plural(b.hits, "event")} in ${b.files_with_hits} of ${b.files_total} files` : "",
        hb ? `Benign, held-out: ${plural(hb.hits, "event")} in ${hb.files_with_hits} of ${hb.files_total} files` : complete ? "Benign, held-out: not measured" : "", repaired] };
  }
  const cell = (q, v, note) => `<section class="verdict ${v.cls}" aria-labelledby="vq-${esc(q.id)}"><h2 class="q" id="vq-${esc(q.id)}" style="font-size:.8125rem">${esc(q.text)}</h2><p class="state">${esc(v.state)}</p>
    <ul>${v.lines.filter(Boolean).map((l) => `<li>${typeof l === "string" ? esc(l) : l.h}</li>`).join("")}</ul><p class="note">${esc(note)}</p></section>`;
  const v3 = { cls: "", state: "Not run", lines: ["No SIEM was searched in this assessment.", { h: `A read-only search of your own logs in Splunk, Elastic or Sentinel. <a href="#/integrations">How</a>` }] };
  return `<div class="verdicts" role="group" aria-label="Three separate verdicts">
    ${cell({ id: "1", text: "Rule validity" }, v1, "Valid means well-formed. It does not show the rule detects anything.")}
    ${cell({ id: "2", text: "Attack validation" }, v2, "One attack file and lab benign logs. Not production accuracy.")}
    ${cell({ id: "3", text: "Environment preflight" }, v3, "Says nothing about your environment until you run it there.")}</div>`;
}

function attemptsHtml(run) {
  const cells = run.its.map((it, i) => { const cls = classify(it); return `<button type="button" class="attempt ${cls}" data-action="sel" data-i="${i}" data-fk="attempt-${i}" ${i === S.sel ? 'aria-current="true"' : ""} aria-label="Attempt ${i + 1}: ${esc(outcome(it))}"><b>Attempt ${i + 1}</b><span>${esc(CLS_TAG[cls][1])}${i === 0 ? ", first rule" : ", repair"}</span></button>`; });
  if (run.running) cells.push(`<span class="attempt pending" role="img" aria-label="Next attempt in progress"><b>Attempt ${run.its.length + 1}</b><span>In progress</span></span>`);
  return cells.join("");
}
function verdictLine(run) {
  const { rec, its } = run;
  if (run.error) return `<div class="notice bad" role="alert">The live run stopped: ${esc(run.error)}. Nothing on this page is a result.</div>`;
  if (run.stale >= 3) return `<div class="notice warn" role="status">Lost contact with the server. The run may still be going; trying again.</div>`;
  if (!its.length) return run.running ? `<p class="reading" role="status">${run.kind === "live" ? "Working: the model is writing and testing rules." : "Playing back the recorded run."}${run.kind === "replay" ? ` <button class="btn quiet small" type="button" data-action="skip">Show the whole run</button>` : ""}</p>` : "";
  if (run.running) return `<p class="reading" role="status">${run.kind === "live" ? "Working: the model is writing and testing rules." : "Playing back the recorded run."}${run.kind === "replay" ? ` <button class="btn quiet small" type="button" data-action="skip">Show the whole run</button>` : ""}</p>`;
  return rec.success ? `<p class="reading"><b class="cell-ok">Passed after ${plural(its.length, "attempt")}.</b> The final rule detects the attack file and matches 0 benign events in the development set. ${its.length > 1 ? "It was repaired, so this detection is not independent." : "It was not repaired."}</p>`
    : `<p class="reading"><b class="cell-bad">Did not pass in ${plural(its.length, "attempt")}.</b> Best rule: attempt ${rec.best_index + 1}. ${esc(cap(rec.stop_reason))}.</p>`;
}

function ruleTab(run) {
  const it = run.its[S.sel];
  if (!it) return `<p class="muted">The first rule will appear here.</p>`;
  const prev = S.sel > 0 ? run.its[S.sel - 1] : null, showDiff = prev && S.compare;
  const rows = showDiff ? unifiedRows(prev.rule_text, it.rule_text) : plainRows(it.rule_text);
  const v = it.validation;
  return `<div class="editor"><div class="editor-bar"><span class="file">attempt-${S.sel + 1}.yml</span>
      ${v.ok ? tag("ok", "sigma check: valid") : tag("bad", "sigma check: rejected")}
      ${prev ? `<button class="btn small" type="button" data-action="compare" aria-pressed="${S.compare}">${S.compare ? "Hide changes" : `Show changes from attempt ${S.sel}`}</button>` : ""}
      <button class="btn small" type="button" data-action="copy-rule" data-fk="copy-rule">Copy</button>
      <button class="btn small" type="button" data-action="dl-attempt">Download</button></div>
    <div class="editor-body" tabindex="0" role="region" aria-label="Rule text, attempt ${S.sel + 1}">${editorLines(rows)}</div></div>
    ${showDiff ? `<p class="help">Attempt ${S.sel + 1} compared with attempt ${S.sel}. Added lines are shaded green with +, removed lines red with −.</p>` : S.sel === 0 ? `<p class="help">The first rule the model wrote. There is no earlier attempt to compare with.</p>` : ""}
    <div class="diag">${v.ok ? `<p class="ok-line">sigma check accepted this rule.</p>` : `<p class="bad-line">sigma check rejected this rule.</p><pre>${esc([...v.errors, v.sigma_output].filter(Boolean).join("\n"))}</pre>`}</div>
    <p class="caveat">Accepted by sigma check means the YAML is a well-formed rule. It does not show the rule detects the attack; see the test evidence.</p>`;
}
function specTab(run) {
  const rec = run.rec, s = rec.spec;
  if (!s) return `<p class="muted">${run.running ? "The extraction result will appear here." : "No extraction result is recorded for this run."}</p>`;
  const obs = s.observables || [], dropped = rec.spec_dropped || [];
  return `<p class="note small muted measure">The model proposes what to look for. An item is kept only if the model quoted text that appears word for word in the report and contains the value.</p>
    <dl class="kv" style="margin:10px 0 14px"><dt>Log source</dt><dd class="mono">${esc(s.logsource_category || "not stated")}</dd>${s.behavior ? `<dt>Behavior</dt><dd>${esc(s.behavior)}</dd>` : ""}</dl>
    ${obs.length ? `<div class="tbl-wrap" tabindex="0" role="region" aria-label="Observables kept, with the supporting quote from the report"><table><caption class="sr">Observables kept, with the supporting quote from the report</caption><thead><tr><th scope="col">Field</th><th scope="col">Match</th><th scope="col">Value</th><th scope="col">Quote from the report</th></tr></thead>
      <tbody>${obs.map((o) => `<tr><td class="mono">${esc(o.field)}</td><td>${esc(o.match)}</td><td class="mono">${esc(o.value)}</td><td><div class="quote" style="margin:0">${esc(o.quote)}</div></td></tr>`).join("")}</tbody></table></div>`
      : `<div class="notice warn"><b>No observables were grounded in the report text.</b> Nothing in this rule is traced to a quote from the report, so it should not be read as source-backed.</div>`}
    ${(s.techniques || []).length ? `<h3 class="sub" style="margin-top:16px">ATT&amp;CK techniques quoted in the report</h3><ul class="list-plain small">${s.techniques.map((t) => `<li><b>${esc(t.id)}</b><div class="quote">${esc(t.quote)}</div></li>`).join("")}</ul>` : ""}
    ${dropped.length ? `<h3 class="sub cell-warn" style="margin-top:16px">Dropped as not supported by the report (${dropped.length})</h3><ul class="list-plain small mono">${dropped.map((d) => `<li>${esc(d.kind)}: ${esc(JSON.stringify(d.item.value ?? d.item.id))} (${esc(d.reason)})</li>`).join("")}</ul>` : ""}`;
}
function excerpt(s) { const t = String(s || "").replace(/\s+/g, " ").trim(); return t.length > 120 ? t.slice(0, 120) + "…" : t; }
function matchRows(it, rec, isFinal) {
  const ev = it.evaluation, rows = [];
  if (!ev) return rows;
  if (ev.attack_missed.length) ev.attack_missed.forEach((f) => rows.push({ set: "Attack file", sample: f, expected: "Detect", out: ["warn", "Missed"], detail: JSON.stringify(ev.attack_events.slice(0, 2), null, 1), sub: "events from this file that the repair step was shown" }));
  else rows.push({ set: "Attack file", sample: plural(ev.attack_total, "file"), expected: "Detect", out: ["ok", `Detected ${ev.attack_detected} of ${ev.attack_total}`] });
  const benign = (label, sub, map) => Object.values(map || {}).forEach((b) => {
    rows.push({ set: label, sub, sample: `${b.files_with_hits} of ${b.files_total} files have matches`, expected: "No match", out: [b.hits ? "bad" : "ok", b.hits ? `${plural(b.hits, "event")} matched` : "No matches"] });
    (b.examples || []).forEach((e) => rows.push({ set: label, sample: e.file, expected: "No match", out: ["bad", "Matched (false positive)"], detail: e.event }));
  });
  benign("Benign, development", "seen by the repair step", ev.benign);
  if (isFinal && rec.heldout) benign("Benign, held-out", "never shown to the model", rec.heldout);
  return rows;
}
function evidenceTab(run) {
  const it = run.its[S.sel];
  if (!it) return `<p class="muted">Test evidence appears when the first rule has been tested.</p>`;
  const rec = run.rec, isFinal = run.complete && S.sel === bestIndex(run), ev = it.evaluation, rows = matchRows(it, rec, isFinal), cls = classify(it);
  return `<p class="attempt-line" style="padding:0 0 10px">Attempt ${S.sel + 1}: ${tag(...CLS_TAG[cls])} <span class="muted" style="font-weight:400">${esc(outcome(it))}</span></p>
    ${it.evaluator_error ? `<div class="notice bad">The test runner could not load this rule.<pre style="white-space:pre-wrap;font-weight:400">${esc(it.evaluator_error)}</pre></div>` : ""}
    ${!it.validation.ok ? `<div class="notice warn">This attempt was not a usable rule, so it was not tested.</div>` : ""}
    ${rows.length ? `<div class="tbl-wrap scroll" tabindex="0" role="region" aria-label="Match evidence for attempt ${S.sel + 1}"><table><caption class="sr">Match evidence for attempt ${S.sel + 1}</caption><thead><tr><th scope="col">Set</th><th scope="col">Sample</th><th scope="col">Expected</th><th scope="col">Outcome</th><th scope="col">Event</th></tr></thead>
      <tbody>${rows.map((r) => `<tr><th scope="row">${esc(r.set)}${r.sub ? `<span class="sub">${esc(r.sub)}</span>` : ""}</th><td class="${r.detail ? "mono" : ""}" style="overflow-wrap:anywhere">${esc(r.sample)}</td><td>${esc(r.expected)}</td><td>${tag(...r.out)}</td>
        <td>${r.detail ? `<div class="ellip" title="${esc(excerpt(r.detail))}">${esc(excerpt(r.detail))}</div><details data-k="ev-${S.sel}-${esc(r.sample)}"><summary>Show event${r.sub ? "s" : ""}</summary><pre>${esc(r.detail)}</pre></details>` : ""}</td></tr>`).join("")}</tbody></table></div>` : ""}
    ${ev ? `<p class="help">Test time ${esc(ev.seconds)} seconds. ${isFinal ? "" : "Held-out results are measured only for the best attempt."}</p>` : ""}`;
}
function sourcesTab(run) {
  const r = run.rec.research;
  if (!r) return `<p class="muted">${run.running ? "Research results will appear here." : "This run did no web research."}</p>`;
  const cs = (r.screening && r.screening.sources) || [];
  const STAT = { included: ["", "Shown to the model"], excluded: ["ok", "Left out"], flagged: ["warn", "Flagged, shown"], not_used: ["na", "Not used"] };
  if (cs.length) return `<p class="note small muted measure">${esc(sourceMode(run.rec).text)}</p>
    <div class="tbl-wrap scroll" tabindex="0" role="region" aria-label="Web sources and how each was handled"><table><caption class="sr">Web sources and how each was handled</caption><thead><tr><th scope="col">Source</th><th scope="col">Role</th><th scope="col">Handling</th><th scope="col">Why</th></tr></thead>
    <tbody>${cs.map((s) => { const t = STAT[s.status] || ["", s.status]; return `<tr><td style="overflow-wrap:anywhere" class="mono">${link(s.url)}<span class="sub">${esc(utc(s.retrieved_at))}</span></td><td>${esc(s.role)}</td><td>${tag(t[0], t[1])}</td><td class="small">${esc((s.reasons || []).join(", ").replace(/_/g, " ") || "")}</td></tr>`; }).join("")}</tbody></table></div>
    <p class="help">Excluded pages looked like the published rule for this scenario. Their text is in the evidence download, not shown here.</p>`;
  const legacy = legacyNote(run.rec);
  return `${legacy ? `<div class="notice warn">${esc(legacy)}</div>` : ""}<ul class="list-plain small mono" style="margin-top:10px">${r.primary ? `<li>${link(r.primary.url)} <span class="muted">(primary)</span></li>` : ""}${(r.corroboration || []).map((c) => `<li>${link(c.url, c.title || c.url)}</li>`).join("")}</ul>`;
}

function compareHtml(run) {
  if (run.its.length < 2) return "";
  const bi = bestIndex(run), to = bi > 0 ? bi : run.its.length - 1, from = run.its[0], dest = run.its[to];
  const missed = from.evaluation && from.evaluation.attack_missed.length ? from.evaluation.attack_missed.join(", ") : "";
  return `<section class="section" aria-labelledby="cmp-h"><h2 class="sec" id="cmp-h">Initial and repaired rule</h2>
    <div class="panel"><div class="panel-head"><h3>Attempt 1 to attempt ${to + 1}</h3><span style="display:inline-flex;gap:8px;align-items:center">${tag(...CLS_TAG[classify(from)])} to ${tag(...CLS_TAG[classify(dest)])} <button class="btn small" type="button" data-action="fulldiff" aria-pressed="${S.fullDiff}">${S.fullDiff ? "Show changed lines only" : "Show full rules"}</button></span></div>
      <div class="panel-pad small stack"><p><b>What failed.</b> ${esc(outcome(from))}.${missed ? ` Missed file: <span class="mono">${esc(missed)}</span>.` : ""}</p>
        <p><b>What the repair step saw.</b> ${from.evaluation && from.evaluation.attack_events && from.evaluation.attack_events.length ? "Events from the file the rule missed." : "The failure report for the first attempt."} A repair sees what it missed, so a pass after repair is not an independent result.</p></div>
      ${splitView(from.rule_text, dest.rule_text, "Attempt 1 (initial rule)", `Attempt ${to + 1} (${bi > 0 ? "best rule" : "last repair"})`)}</div></section>`;
}
function resultsHtml(run) {
  if (!run.complete || !run.its.length) return "";
  const rec = run.rec, its = run.its, first = its[0], best = its[rec.best_index];
  const att = (it) => { if (!it || !it.evaluation) return { v: "Not tested", c: "" }; const e = it.evaluation; return { v: `${e.attack_detected} of ${e.attack_total}`, c: e.attack_detected ? "cell-ok" : "cell-warn" }; };
  const dev = (it) => { if (!it || !it.evaluation) return { v: "Not tested", c: "" }; const h = benignTotal(it.evaluation), b = Object.values(it.evaluation.benign)[0]; return { v: String(h), c: h ? "cell-bad" : "cell-ok", s: b ? `in ${b.files_with_hits} of ${b.files_total} files` : "" }; };
  const held = (h) => { if (!h) return { v: "Not measured", c: "" }; const b = Object.values(h)[0]; return { v: String(b.hits), c: b.hits ? "cell-bad" : "cell-ok", s: `in ${b.files_with_hits} of ${b.files_total} files` }; };
  const ex = rec.expert, exA = ex ? att({ evaluation: ex.dev }) : { v: "Not run", c: "" }, exD = ex ? dev({ evaluation: ex.dev }) : { v: "Not run", c: "" };
  const rowsDef = [["Valid Sigma rule", [{ v: first.validation.ok ? "Yes" : "No", c: first.validation.ok ? "" : "cell-warn" }, { v: best.validation.ok ? "Yes" : "No", c: best.validation.ok ? "" : "cell-warn" }, { v: "Yes" }]],
    ["Attack file detected", [att(first), att(best), exA]], ["Benign events, development set", [dev(first), dev(best), exD]],
    ["Benign events, held-out set", [{ v: "Not measured" }, held(rec.heldout), ex ? held(ex.heldout) : { v: "Not run" }], "never shown to the model"],
    ["Attempts used", [{ v: "1" }, { v: String(its.length) }, { v: "Not applicable" }]], ["Tokens used by the model", [{ v: "" }, { v: `${rec.totals.tokens.toLocaleString("en-US")} in total` }, { v: "Not applicable" }]]];
  return `<section class="section" aria-labelledby="res-h"><h2 class="sec" id="res-h">Results</h2><div class="tbl-wrap" tabindex="0" role="region" aria-label="First attempt, final rule and SigmaHQ expert rule compared"><table><caption class="sr">First attempt, final rule and SigmaHQ expert rule compared</caption>
    <thead><tr><th scope="col"><span class="sr">Measure</span></th><th scope="col">First attempt</th><th scope="col">${rec.success ? "Final rule" : "Best rule"} (attempt ${rec.best_index + 1})</th><th scope="col">SigmaHQ expert rule</th></tr></thead>
    <tbody>${rowsDef.map(([label, cs, sub]) => `<tr><th scope="row">${esc(label)}${sub ? `<span class="sub">${esc(sub)}</span>` : ""}</th>${cs.map((c) => `<td class="${c.c || ""}">${esc(c.v)}${c.s ? `<span class="sub">${esc(c.s)}</span>` : ""}</td>`).join("")}</tr>`).join("")}</tbody></table></div>
    <p class="help measure">Counts are for this one attack file and these benign sets. After a repair, the detection result is not a held-out result. The expert rule was run through the same tests.</p></section>`;
}
const LIMITS = ["The test uses one recorded attack file per scenario. After a repair, \"detected\" means the rule now matches a file whose missed events the model was shown. It does not show the rule catches other variants of the attack.",
  "The benign logs come from a few lab machines. Zero benign matches here does not mean zero false positives on a production network.",
  "The expert rule is the published SigmaHQ rule for the same behaviour, run through the same tests. SigmaHQ rules are used under the Detection Rule License 1.1; the rule's authors are named in the rule text inside the evidence download.",
  "Web search for a scenario can return copies of the very rule being written. Newer runs leave those results out and list them; recordings that say they predate this check had that help.",
  "Recorded runs were chosen after seeing earlier results. Aggregate numbers across two sets of twenty tasks are on the Benchmark and limits page."];
function limitsHtml() { return `<details class="limits" data-k="limits"><summary>What this run does and does not show</summary><ul>${LIMITS.map((l) => `<li>${esc(l)}</li>`).join("")}</ul></details>`; }

function viewRun() {
  const run = currentRun();
  if (!run) return S.loadError ? `<div class="notice bad" role="alert">${esc(S.loadError)}</div><p><a href="#/runs">Back to run history</a></p>` : `<p class="muted" role="status">Loading the run</p>`;
  const rec = run.rec, its = run.its, bi = bestIndex(run);
  if (S.sel >= its.length) S.sel = Math.max(0, its.length - 1);
  const sm = sourceMode(rec), leg = legacyNote(rec), r = rec.research;
  const modeLine = run.kind === "replay" ? `Replay of a run recorded ${utc(rec.created_at)}. No model is running now.` : `Started ${utc(run.started || rec.created_at)}. ${run.running ? "The model and the Sandbox are working now." : run.error ? "" : "It has finished."}`;
  const canExport = run.complete && its.length;
  const tabs = [["rule", "Rule"], ["spec", "Observables"], ["evidence", "Test evidence"], ["sources", "Sources"]];
  const panel = S.tab === "spec" ? specTab(run) : S.tab === "evidence" ? evidenceTab(run) : S.tab === "sources" ? sourcesTab(run) : ruleTab(run);
  return `
  <p class="crumbs"><a href="#/runs">Run history</a> / ${esc(rec.scenario.title)}</p>
  <div class="run-head"><div><h1 id="page-title" tabindex="-1">${esc(rec.scenario.title)}</h1>
    <div class="run-meta">${run.kind === "live" ? tag("info", "Live run") : tag("", "Replay")}<span class="mode-line">${esc(modeLine)}</span></div>
    <p class="provenance">${r && r.primary ? `Report read with Tavily from ${link(r.primary.url)} on ${esc(utc(r.primary.retrieved_at))}.` : r && r.error ? `Tavily could not read the report (${esc(r.error)}). The run used the scenario's description instead.` : run.running && !r ? "Reading the report." : "Input: the scenario's SigmaHQ description and references. This run did no web research."}</p>
    ${run.running && !r ? `<p class="provenance">Source handling will appear once the report has been read.</p>` : `<p class="provenance ${sm.cls}">${esc(sm.line)} <button class="btn quiet small" type="button" data-action="tab" data-t="sources">Source details</button></p>`}${leg ? `<p class="provenance warn">${esc(leg)}</p>` : ""}</div>
    <div class="actions">${canExport ? `<button class="btn" type="button" data-action="dl-rule" ${rec.iterations[rec.best_index].validation.ok ? "" : "disabled"}>${rec.success ? "Download final rule" : "Download best rule"}</button><button class="btn" type="button" data-action="dl-json">Evidence (JSON)</button><button class="btn" type="button" data-action="dl-md">Summary (Markdown)</button>` : ""}</div></div>
  ${verdictsHtml(run)}${verdictLine(run)}
  <div class="section work">
    <section aria-labelledby="trace-h"><h2 class="sec" id="trace-h">Execution trace</h2><div class="panel">${traceHtml(run)}</div></section>
    <section aria-labelledby="inspect-h"><h2 class="sec" id="inspect-h">Inspect</h2><div class="panel">
      <div class="attempts" role="group" aria-label="Attempts">${attemptsHtml(run) || '<span class="muted small">No attempt yet</span>'}</div>
      <div class="tabs" role="tablist" aria-label="Attempt details">${tabs.map(([k, l]) => `<button role="tab" type="button" id="tab-${k}" data-action="tab" data-t="${k}" data-fk="tab-${k}" aria-selected="${S.tab === k}" aria-controls="panel" tabindex="${S.tab === k ? 0 : -1}">${l}</button>`).join("")}</div>
      <div id="panel" class="tabpanel" role="tabpanel" aria-labelledby="tab-${S.tab}" tabindex="0">${panel}</div></div>
      <h2 class="sec" style="margin-top:24px">Who did what</h2><div class="panel">${rolesHtml(run)}</div></section>
  </div>
  ${compareHtml(run)}${resultsHtml(run)}${limitsHtml()}`;
}

/* ----- evidence and real-world pages ----- */
function viewEvidence() {
  const runs = Object.keys(BENCH), row = (label, key, fmt = ofText, sub) => `<tr><th scope="row">${esc(label)}${sub ? `<span class="sub">${esc(sub)}</span>` : ""}</th>${runs.map((r) => `<td>${esc(fmt(BENCH[r][key]))}</td>`).join("")}</tr>`;
  return `<div class="page-head"><div><h1 id="page-title" tabindex="-1">Benchmark and limits</h1>
    <p class="lede">What was measured across many tasks, and what none of it shows.</p></div></div>
  <section aria-labelledby="bench-h"><h2 class="sec" id="bench-h">Frozen benchmark: 20 tasks, run twice</h2>
    <div class="tbl-wrap" tabindex="0" role="region" aria-label="Confirmatory benchmark results for Run 8 and Run 9"><table><caption class="sr">Confirmatory benchmark results for Run 8 and Run 9</caption><thead><tr><th scope="col"><span class="sr">Measure</span></th>${runs.map((r) => `<th scope="col">${esc(r)}<span class="sub">${esc(BENCH[r].note)}</span></th>`).join("")}</tr></thead>
      <tbody>${row("Tasks with results", "tasks")}${row("First rule catches the attack", "one_shot", ofText, "no repair")}${row("After up to three repairs", "after_repair", ofText, "of the tasks that completed")}
        ${row("After repair, errored task counted as a miss", "after_repair_errored_as_miss")}${row("Repair fixed the first failure", "repair_fixed_first_failure")}${row("Held-out false positives, repaired rules", "heldout_fp", (x) => x.replace("/", " of ").replace(/1 events/, "1 event"))}${row("SigmaHQ expert rules catch the attack", "expert")}</tbody></table></div>
    <p class="help measure">Source: docs/RESULTS_TABLE.md, confirmatory set. The 20 tasks were frozen before any model call on them. These figures are copied, not recomputed here, and do not change with the runs on this page.</p>
    <div class="notice" style="margin-top:12px;max-width:80ch">After a repair the model has seen the events it missed, so that detection is not independent. These are counts on a 20-task benchmark. They are not real-world detection accuracy, and runs are not comparable to one another unless they use the same configuration.</div></section>
  <section class="section" aria-labelledby="lim-h"><h2 class="sec" id="lim-h">Limits</h2><ul class="list-plain measure" style="list-style:disc;padding-left:20px">
    <li>Public lab data. Results apply to the tested samples only.</li><li>Compatibility with a customer's production environment is not established.</li>
    <li>There is no continuous live monitoring, and rules are never deployed automatically. The tool recommends; it deploys nothing.</li>
    <li>Rule validity, attack validation and environment preflight answer different questions and are never merged into one pass.</li>
    <li>Recordings made before answer screening existed are marked "Not screened". Their web results may have included the rule being written, so they are not clean tests.</li></ul></section>`;
}
function copyBlock(id, text) { return `<div><pre class="codeblock" id="${id}" tabindex="0">${esc(text)}</pre><button class="btn small" type="button" data-action="copy-text" data-target="${id}" style="margin-top:6px">Copy command</button></div>`; }
/* ---------- routing and rendering ---------- */
const EXT = { views: {}, enter: {}, title: {} };  // filled by integrations.js: the SIEM Integrations workspace
const ROUTES = { "": "overview", new: "new", runs: "runs", run: "run", live: "live", evidence: "evidence", integrations: "integrations", assessments: "assessments", assessment: "assessment" };
function parseRoute() {
  const m = location.hash.replace(/^#\/?/, "").split("/");
  const name = m[0] === "real-world" ? "integrations" : ROUTES[m[0]] || "overview";
  return { name, arg: decodeURIComponent(m.slice(1).join("/")) };
}
const TITLES = { overview: "Overview", new: "New assessment", runs: "Run history", evidence: "Benchmark and limits", integrations: "Integrations", assessments: "Assessments", assessment: "Assessment" };
function stopReplay() { clearInterval(S.timer); S.timer = null; }

async function onRoute() {
  const route = parseRoute();
  S.route = route; S.sel = 0; S.pinned = false; S.tab = "rule"; S.compare = true; S.loadError = null; stopReplay(); S.open = new Set();
  if (route.name === "run") {
    S.replay = null;
    render(true);
    try {
      const rec = await loadDetail(route.arg);
      if (S.route.name !== "run" || S.route.arg !== route.arg) return;
      S.replay = { slug: route.arg, rec, shown: 0 };
      S.sel = 0;
      S.timer = setInterval(() => {
        if (!S.replay || S.replay.shown >= S.replay.rec.iterations.length) return stopReplay();
        S.replay.shown++; if (!S.pinned) S.sel = S.replay.shown - 1; render();
        if (S.replay.shown >= S.replay.rec.iterations.length) { stopReplay(); if (!S.pinned) S.sel = bestIndex(currentRun()); render(); }
      }, 1500);
    } catch (e) { S.loadError = e.message; }
  }
  if (route.name === "live" && !S.live.some((x) => x.id === route.arg)) S.loadError = "That live run is not known to this browser session or the server has restarted.";
  render(true);
  if (EXT.enter[route.name]) {
    try { await EXT.enter[route.name](route); } catch (e) { S.loadError = e.message; }
    if (S.route === route) render(true);
  }
}

function render(newPage) {
  const route = S.route, view = $("#view");
  const fk = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.fk : null;
  view.querySelectorAll("details[data-k]").forEach((d) => { if (d.open) S.open.add(d.dataset.k); else S.open.delete(d.dataset.k); });
  const scroll = view.querySelectorAll(".editor-body").length ? [...view.querySelectorAll(".editor-body")].map((e) => [e.scrollTop, e.scrollLeft]) : [];
  const html = ({ overview: viewOverview, new: viewNew, runs: viewRuns, run: viewRun, live: viewRun, evidence: viewEvidence, ...EXT.views })[route.name]();
  view.innerHTML = html;
  view.querySelectorAll("details[data-k]").forEach((d) => { if (S.open.has(d.dataset.k)) d.open = true; });
  if (!newPage) view.querySelectorAll(".editor-body").forEach((e, i) => { if (scroll[i]) { e.scrollTop = scroll[i][0]; e.scrollLeft = scroll[i][1]; } });
  if (fk && !newPage) { const el = view.querySelector(`[data-fk="${fk}"]`); if (el) el.focus({ preventScroll: true }); }
  /* chrome */
  const run = route.name === "run" || route.name === "live" ? currentRun() : null;
  const title = run ? run.rec.scenario.title : (EXT.title[route.name] ? EXT.title[route.name]() : TITLES[route.name]) || "Overview";
  $("#crumb").textContent = run ? "" : title;
  document.title = `${title} · Shakedown`;
  document.querySelectorAll("#nav a").forEach((a) => { const on = a.dataset.route === route.name || (a.dataset.route === "runs" && (route.name === "run" || route.name === "live")); if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
  const cap = $("#capability"), on = !!(S.health && S.health.live_enabled);
  const capText = S.health ? (on ? "Live rule runs on" : "Rule runs: replay only") : "";
  cap.className = "capability" + (on ? " on" : ""); cap.querySelector(".cap-text").textContent = capText;
  const nc = $("#nav-cap"); nc.className = "capability" + (on ? " on" : ""); nc.textContent = capText;
  if (S.focusChange || newPage) {
    S.focusChange = false;
    const body = view.querySelector("#panel .editor-body"), ch = body && body.querySelector(".ln.add, .ln.del");
    if (ch) body.scrollTop = Math.max(0, ch.offsetTop - 90);
  }
  if (newPage) {
    /* The first load keeps focus at the top so the skip link is the first Tab stop; later page changes move focus to the new heading. */
    if (S.booted) { const h = $("#page-title"); if (h) h.focus({ preventScroll: true }); announce(title); }
    window.scrollTo(0, 0); $("#nav").removeAttribute("data-open"); $("#nav-toggle").setAttribute("aria-expanded", "false");
  }
}
function renderIfData() { if (["overview", "runs", "live", "new"].includes(S.route.name)) render(); }
function rerender() { render(); }  // for extension modules

/* ---------- actions ---------- */
function download(name, text, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
const slugOf = (rec) => (rec.scenario.title || "rule").toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 50);
function summaryMd(rec) {
  const best = rec.iterations[rec.best_index];
  const lines = [`# ${rec.scenario.title}`, "", `Result: ${rec.success ? "passed" : "did not pass"} after ${plural(rec.iterations.length, "attempt")}. ${rec.stop_reason}.`,
    `Model: ${modelName(rec.model)}. Recorded: ${utc(rec.created_at)}.`, "", "## Attempts", ""];
  rec.iterations.forEach((it, i) => lines.push(`${i + 1}. ${it.action}: ${outcome(it)}`));
  lines.push("", `## Rule (attempt ${rec.best_index + 1})`, "", "```yaml", best.rule_text.trimEnd(), "```", "",
    "## Limits", "", "- One recorded attack file per scenario; after a repair, detection is not a held-out result.", "- Benign logs come from a few lab machines and do not represent a production network.");
  return lines.join("\n") + "\n";
}
async function copyText(text, btn) {
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch {
    const t = document.createElement("textarea"); t.value = text; t.style.position = "fixed"; t.style.opacity = "0"; document.body.appendChild(t); t.select();
    try { ok = document.execCommand("copy"); } catch { ok = false; } t.remove();
  }
  const old = btn.textContent; btn.textContent = ok ? "Copied" : "Copy failed: select the text and copy it"; announce(ok ? "Copied to the clipboard." : "Copy failed.");
  setTimeout(() => { btn.textContent = old; }, 1800);
}
document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-action]");
  if (!el) return;
  const run = currentRun(), a = el.dataset.action;
  if (a === "sel") { S.sel = +el.dataset.i; S.pinned = true; S.focusChange = true; render(); }
  else if (a === "tab") { S.tab = el.dataset.t; S.focusChange = true; render(); if (el.closest(".provenance")) { const h = $("#inspect-h"); if (h) h.scrollIntoView({ block: "start" }); } }
  else if (a === "fulldiff") { S.fullDiff = !S.fullDiff; render(); }
  else if (a === "compare") { S.compare = !S.compare; S.focusChange = true; render(); }
  else if (a === "skip" && S.replay) { stopReplay(); S.replay.shown = S.replay.rec.iterations.length; S.sel = bestIndex(currentRun()); render(); }
  else if (a === "copy-rule" && run) copyText(run.its[S.sel].rule_text, el);
  else if (a === "copy-text") copyText($("#" + el.dataset.target).textContent, el);
  else if (a === "dl-attempt" && run) download(`${slugOf(run.rec)}-attempt-${S.sel + 1}.yml`, run.its[S.sel].rule_text, "text/yaml");
  else if (a === "dl-rule" && run) download(`${slugOf(run.rec)}.yml`, run.rec.iterations[run.rec.best_index].rule_text, "text/yaml");
  else if (a === "dl-json" && run) download(`${slugOf(run.rec)}-evidence.json`, JSON.stringify(run.rec, null, 2), "application/json");
  else if (a === "dl-md" && run) download(`${slugOf(run.rec)}-summary.md`, summaryMd(run.rec), "text/markdown");
});
document.addEventListener("keydown", (e) => {
  const t = e.target.closest && e.target.closest('[role="tab"]');
  if (!t || !["ArrowRight", "ArrowLeft", "Home", "End"].includes(e.key)) return;
  const tabs = [...t.parentElement.querySelectorAll('[role="tab"]')], i = tabs.indexOf(t);
  const j = e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : (i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length;
  e.preventDefault(); S.tab = tabs[j].dataset.t; render(); const n = document.querySelector(`[data-fk="tab-${S.tab}"]`); if (n) n.focus();
});
document.addEventListener("change", (e) => { if (e.target.id === "scenario") { S.form.scenario = e.target.value; store.set("shk.form", S.form); render(); const s = $("#scenario"); if (s) s.focus(); } });
document.addEventListener("input", (e) => { if (e.target.id === "source-url") { S.form.url = e.target.value; store.set("shk.form", S.form); } });
document.addEventListener("submit", async (e) => {
  if (e.target.id !== "assess-form") return;
  e.preventDefault();
  if (S.starting) return;
  const url = (S.form.url || "").trim(), body = { scenario_id: S.form.scenario };
  if (S.health && S.health.allow_custom_url && url) {
    if (!/^https?:\/\/\S{3,}$/.test(url)) { S.formError = "The report address must start with http:// or https://."; render(); $("#source-url").focus(); return; }
    body.source_url = url;
  }
  S.starting = true; S.formError = ""; render();
  try {
    const { run_id } = await api("/api/runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const sc = S.scenarios.find((s) => s.id === body.scenario_id), started = new Date().toISOString();
    S.live.push({ id: run_id, title: sc ? sc.title : "Live run", started, status: "running", rec: blankRec(sc ? sc.title : "Live run", started), error: null });
    persistLive(); S.starting = false; ensurePolling();
    api("/api/health").then((h) => { S.health = h; }).catch(() => {});
    location.hash = `#/live/${run_id}`;
  } catch (err) { S.starting = false; S.formError = err.message; render(); }
});
$("#nav-toggle").addEventListener("click", (e) => { const nav = $("#nav"), open = !nav.hasAttribute("data-open"); if (open) nav.setAttribute("data-open", ""); else nav.removeAttribute("data-open"); e.currentTarget.setAttribute("aria-expanded", String(open)); });
window.addEventListener("hashchange", onRoute);

/* ---------- start ---------- */
(async function init() {
  const legacy = new URLSearchParams(location.search).get("run");
  if (legacy && /^[a-z0-9-]{1,80}$/.test(legacy)) history.replaceState(null, "", `/#/run/${legacy}`);
  try {
    [S.health, S.recorded, S.scenarios] = await Promise.all([api("/api/health"), api("/api/recorded"), api("/api/scenarios")]);
  } catch (e) {
    $("#view").innerHTML = `<div class="notice bad" role="alert">The server did not respond: ${esc(e.message)}</div>`; return;
  }
  /* re-attach live runs started earlier in this browser session */
  for (const run of [...S.live]) await pollLive(run);
  persistLive(); ensurePolling();
  await onRoute();
  S.booted = true;
  Promise.all(S.recorded.map((r) => loadDetail(r.slug).catch(() => null))).then(renderIfData);
})();
