"use strict";
/* The Integrations workspace: connect a SIEM, test access, choose a scope, preview the native query, run a bounded read-only preflight,
   inspect real results and export them. Every state on screen comes from /api/integrations/*; nothing here simulates a connection or a result.
   Credentials are read from the form fields at submit time, sent once, and the fields are cleared. They are never kept in script state,
   browser storage, a URL or the DOM after submit. */

const I = { status: null, token: null, header: "x-shakedown-csrf", connections: [], rules: [], assessments: [], wiz: null, pf: null, conn: null, assess: null, poll: null, flowTimer: null,
            confirm: false, edit: false, notice: "", error: "", busy: false };

/* ---------- api ---------- */
async function isession() {
  const r = await fetch("/api/integrations/session", { cache: "no-store" });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail || `Could not start a session (${r.status})`);
  I.token = j.csrf; I.header = j.header;
}
async function iapi(method, path, body) {
  if (!I.token) await isession();
  const call = () => fetch("/api/integrations" + path, { method, cache: "no-store", headers: { "Content-Type": "application/json", [I.header]: I.token }, body: body === undefined ? undefined : JSON.stringify(body) });
  let r = await call();
  if (r.status === 403) { await isession(); r = await call(); }  // the token changes when the server restarts
  const data = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(data.detail || `Request failed (${r.status})`); e.kind = data.kind; e.status = r.status; throw e; }
  return data;
}
const enabled = () => !!(I.status && I.status.enabled);
const spec = (id) => ((I.status && I.status.providers) || []).find((p) => p.id === id);
async function loadStatus() { I.status = await (await fetch("/api/integrations/status", { cache: "no-store" })).json(); }
async function loadConnections() { I.connections = enabled() ? (await iapi("GET", "/connections")).connections : []; }
async function loadAssessments(connId) { I.assessments = enabled() ? (await iapi("GET", "/assessments" + (connId ? `?connection_id=${encodeURIComponent(connId)}` : ""))).assessments : []; }
const route = () => { const a = S.route.arg.split("/"); return { sub: a[0] || "", rest: a.slice(1) }; };

/* ---------- labels ---------- */
const provTag = (x) => { const k = x.status || x.provider_status, label = x.status_label || x.provider_status_label; const t = PROVIDER_TAG[k] || PROVIDER_TAG.planned; return tag(t[0], label || t[1]); };
const PROVIDER_TAG = { live_verified_test_instance: ["ok", "Live-verified on a test instance"], not_live_verified: ["warn", "Implemented, not live-verified"], planned: ["na", "Planned"] };
const CONN_TAG = { connected: ["ok", "Connected"], stale: ["warn", "Not re-checked recently"], needs_credentials: ["warn", "Credentials needed"], check_failed: ["bad", "Last check failed"], unverified: ["info", "Not checked"] };
const ENV_TAG = { potential_matches_found: ["info", "Potential matches found"], no_matches_in_window: ["na", "No matches in the window"], telemetry_missing_or_unsupported: ["warn", "Telemetry missing or unsupported"],
                  query_failed: ["bad", "Search failed"], not_run: ["na", "Not run"], running: ["info", "Running"], interrupted: ["warn", "Interrupted"] };
const CHECK_STATE = { pass: ["done", "Passed", "ok"], fail: ["bad", "Failed", "bad"], warn: ["warn", "Warning", "warn"], skipped: ["skip", "Not run", "na"] };
const KIND_HELP = { auth: "The credential was rejected. Update it on the connection page.", permission: "The account lacks a permission this step needs. Use a search-only role that can read the scope.",
                    tls: "The certificate could not be verified. Add the signing CA as a CA bundle, or fix the certificate name.", unreachable: "Shakedown could not reach the endpoint from this machine.",
                    destination: "That destination is not allowed from this server.", query: "The SIEM rejected the search. The query is shown below.", timeout: "The search ran past its time limit and was cancelled.",
                    cancelled: "You cancelled the search; the search job was stopped.", scope: "The scope or window was refused before any query was sent.", unsafe_query: "The query contained a command that is not read-only, so nothing was sent.",
                    conversion: "The rule could not be converted to this SIEM's query language.", unsupported_logsource: "This rule's log source has no supported scope for this SIEM, so it was not mis-queried.",
                    privileged_account: "The account holds admin-class capabilities. Use a dedicated search-only role.", unavailable: "The SIEM answered with an error." };
const when = (iso) => (iso ? utc(iso) : "never");
const pl = (noun) => (/(x|s)$/.test(noun) ? noun + "es" : noun + "s");
const epoch = (v) => { const n = Number(v); return Number.isFinite(n) && n > 1e9 ? new Date(n * 1000).toISOString().slice(0, 19).replace("T", " ") + " UTC" : String(v ?? ""); };

/* ---------- small pieces ---------- */
function checksHtml(report) {
  return `<ol class="trace" aria-label="Connection checks">${report.checks.map((c) => { const m = CHECK_STATE[c.status] || CHECK_STATE.skipped;
    return `<li class="stage ${m[0]}"><span class="mark" aria-hidden="true">${{ done: "✓", bad: "×", warn: "!", skip: "–" }[m[0]]}</span><div class="stage-title"><span>${esc(c.label)}</span>${tag(m[2], m[1])}</div><div class="stage-body">${esc(c.detail)}</div></li>`; }).join("")}</ol>`;
}
function identityHtml(report) {
  const id = report.identity || {}, ep = report.endpoint || {};
  const rows = [["Account", id.username], ["Roles", (id.roles || []).join(", ")], ["Capabilities", id.capabilities ? (id.capabilities.length > 6 ? `${id.capabilities.length} (${id.capabilities.slice(0, 6).join(", ")}, ...)` : id.capabilities.join(", ")) : ""],
                ["Endpoint", [ep.product, ep.version].filter(Boolean).join(" ")], ["Certificate checking", ep.tls_verified === true ? "On" : ep.tls_verified === false ? "Off (test instance)" : ep.scheme === "http" ? "Not applicable: plain http on loopback" : ""]].filter((r) => r[1]);
  return rows.length ? `<dl class="kv" style="margin-top:12px">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>` : "";
}
const warningsHtml = (list) => (list && list.length ? `<ul class="list-plain small" style="margin-top:10px">${list.map((w) => `<li class="notice warn">${esc(w)}</li>`).join("")}</ul>` : "");
function disabledNotice() {
  const st = I.status || {};
  return `<div class="notice warn" role="status"><b>Connecting a SIEM is not available on this server.</b> ${esc(st.disabled_reason || "")}
    <div class="small" style="margin-top:6px">To use it, run Shakedown on your own machine: <code>uv run python -m shakedown.serve --integrations</code>. Saved credentials never leave that machine, and the server refuses this option on any non-loopback address.</div></div>`;
}
function cliSection() {
  return `<details class="limits" data-k="cli"><summary>Command line and automation</summary>
    <div class="stack" style="margin-top:10px"><p class="small measure">Everything here also runs from the command line, for automation or reproducibility. The command line reads credentials from environment variables and does not use the saved connections.</p>
    ${copyBlock("cmd-splunk", "uv run python -m shakedown.assess --rule rule.yml --manifest case/manifest.yml --splunk --splunk-index win_sysmon --last-hours 24 --out packet/")}
    ${copyBlock("cmd-smoke", "python tools/splunk_smoke.py --index win_sysmon")}
    <p class="small muted">Bring your own logs (EVTX files you supply) is command line only: <code>uv run python -m shakedown.assess --rule rule.yml --manifest case/manifest.yml --out packet/</code>. The hosted demo never accepts uploads.</p></div></details>`;
}
function provenanceFacts() {
  const ss = (I.status && I.status.secret_store) || {};
  return `<section class="panel"><div class="panel-head"><h2>Where things are kept</h2></div><div class="panel-pad small stack">
    <p><b>Credentials.</b> ${esc(ss.note || "")}${ss.kind === "memory" ? " You can instead name an environment variable, which keeps the credential out of Shakedown entirely." : ""}</p>
    <p><b>Results.</b> Assessments, including any event excerpts from your SIEM, are saved in <code>data/integrations/</code> on this machine. Disconnecting offers to delete them.</p>
    <p><b>Nothing leaves this machine.</b> SIEM events and credentials are never sent to the model, Tavily, Nebius or any other service.</p>
    <p><b>Read-only.</b> Shakedown creates and deletes its own search jobs. It never creates an alert, saved search or rule, and never deploys anything.</p></div></section>`;
}

/* ---------- overview ---------- */
function viewIntegrations() {
  const r = route();
  if (!I.status) return `<p class="muted" role="status">Loading</p>`;
  if (r.sub === "connect") return r.rest[0] ? viewWizard(r.rest[0]) : viewConnect();
  if (r.sub) return viewConnection(r.sub);
  const rows = I.connections.map((c) => `<tr><th scope="row"><a class="title-link" href="#/integrations/${esc(c.id)}">${esc(c.label)}</a><span class="sub">${esc(c.provider_name)}</span></th>
      <td class="mono">${esc(c.endpoint)}</td><td>${tag(...(CONN_TAG[c.state] || CONN_TAG.unverified))}<span class="sub">${c.last_check ? "checked " + esc(when(c.last_check.at)) : "never checked"}</span></td>
      <td>${esc(c.scope.indexes.join(", "))}</td><td>${c.last_preflight ? `${tag(...(ENV_TAG[c.last_preflight.status] || ENV_TAG.not_run))}<span class="sub"><a href="#/assessment/${esc(c.last_preflight.assessment_id)}">${esc(when(c.last_preflight.at))}</a></span>` : '<span class="muted">none yet</span>'}</td>
      <td><div class="actions"><button class="btn small" type="button" data-iaction="retest" data-id="${esc(c.id)}">Test connection</button><a class="btn small" href="#/integrations/${esc(c.id)}">Open</a></div></td></tr>`).join("");
  return `<div class="page-head"><div><h1 id="page-title" tabindex="-1">Integrations</h1>
    <p class="lede">Connect a SIEM you already use, check access, and run a read-only preflight of a Sigma rule against a bounded window of your own logs. The preflight reports what the search found; it never deploys the rule.</p></div>
    <div class="actions">${enabled() ? '<a class="btn primary" href="#/integrations/connect">Connect a SIEM</a>' : '<button class="btn primary" type="button" disabled aria-describedby="why-off">Connect a SIEM</button>'}</div></div>
  ${enabled() ? "" : `<div id="why-off">${disabledNotice()}</div>`}
  ${I.notice ? `<div class="notice" role="status" style="margin-bottom:16px">${esc(I.notice)}</div>` : ""}${I.error ? `<div class="notice bad" role="alert" style="margin-bottom:16px">${esc(I.error)}</div>` : ""}
  <div class="cols-2"><div>
    <section><h2 class="sec" id="conn-h">Saved connections</h2>
    ${I.connections.length ? `<div class="tbl-wrap" tabindex="0" role="region" aria-label="Saved connections"><table><caption class="sr">Saved SIEM connections</caption><thead><tr><th scope="col">Connection</th><th scope="col">Endpoint</th><th scope="col">State</th><th scope="col">Scope</th><th scope="col">Last preflight</th><th scope="col"><span class="sr">Actions</span></th></tr></thead><tbody>${rows}</tbody></table></div>`
      : `<div class="empty"><h2>No SIEM is connected</h2><p class="muted measure">Connect a SIEM, verify that Shakedown can reach it with a read-only account, then assess a detection rule against a bounded window of your own history. ${enabled() ? "You will see the exact query before anything runs." : ""}</p>
        ${enabled() ? '<p style="margin-top:12px"><a class="btn primary" href="#/integrations/connect">Connect a SIEM</a></p>' : ""}</div>`}
    </section>
    <section class="section" aria-labelledby="prov-h"><h2 class="sec" id="prov-h">Supported providers</h2>${providerTable()}</section>
    ${cliSection()}</div>
    <aside class="stack">${provenanceFacts()}</aside></div>`;
}
function providerTable() {
  return `<div class="tbl-wrap" tabindex="0" role="region" aria-label="Providers and their verification status"><table><caption class="sr">Providers and what has been verified</caption><thead><tr><th scope="col">Provider</th><th scope="col">Status</th><th scope="col">What that means</th></tr></thead><tbody>
    ${I.status.providers.map((p) => `<tr><th scope="row">${esc(p.name)}<span class="sub">${esc(p.query_language || "")}</span></th><td>${provTag(p)}</td><td class="small">${esc(p.verification_note)}</td></tr>`).join("")}</tbody></table></div>`;
}
function viewConnect() {
  return `<p class="crumbs"><a href="#/integrations">Integrations</a> / Connect a SIEM</p>
    <div class="page-head"><div><h1 id="page-title" tabindex="-1">Connect a SIEM</h1><p class="lede">Choose a provider. Only providers with a working adapter can be connected; a provider marked planned has no wizard.</p></div></div>
    ${enabled() ? "" : disabledNotice()}
    <div class="tbl-wrap" tabindex="0" role="region" aria-label="Choose a provider"><table><caption class="sr">Providers</caption><thead><tr><th scope="col">Provider</th><th scope="col">Verification</th><th scope="col">Signs in with</th><th scope="col"><span class="sr">Connect</span></th></tr></thead><tbody>
    ${I.status.providers.map((p) => `<tr><th scope="row">${esc(p.name)}<span class="sub">${esc(p.summary)}</span></th><td>${provTag(p)}<span class="sub">${esc(p.verification_note)}</span></td>
      <td class="small">${p.implemented ? esc(p.auth_methods.map((a) => a[1]).join("; ")) : "Not implemented"}</td>
      <td>${p.implemented && enabled() ? `<a class="btn small primary" href="#/integrations/connect/${esc(p.id)}">Connect</a>` : `<span class="muted small">${p.implemented ? "Unavailable here" : "Planned"}</span>`}</td></tr>`).join("")}</tbody></table></div>
    <p class="help measure">Compatibility is not claimed for any SIEM beyond what the verification column states.</p>`;
}

/* ---------- wizard ---------- */
function newWizard(id) {
  const p = spec(id);
  return { provider: id, step: 1, auth: p && p.auth_methods[0] ? p.auth_methods[0][0] : "", values: Object.fromEntries(((p && p.fields) || []).map((f) => [f.name, f.default ?? (f.kind === "bool" ? false : "")])),
           credMode: "paste", env: {}, test: null, selected: [], manual: "", hours: 24, label: "", error: "", busy: false, replace: null };
}
const STEPS = ["Details", "Test", "Scope", "Save"];
function stepper(step) {
  return `<ol class="steps" aria-label="Progress">${STEPS.map((s, i) => `<li ${i + 1 === step ? 'aria-current="step"' : ""} class="${i + 1 < step ? "past" : ""}"><span>${i + 1}</span> ${s}</li>`).join("")}</ol>`;
}
function fieldHtml(f, val) {
  const id = `f-${f.name}`, help = f.help ? `<p class="help" id="${id}-h">${esc(f.help)}</p>` : "", d = f.help ? `aria-describedby="${id}-h"` : "";
  if (f.kind === "bool") return `<div class="field"><label class="check-row"><input type="checkbox" id="${id}" name="${esc(f.name)}" ${val ? "checked" : ""} ${d}> ${esc(f.label)}</label>${help}</div>`;
  const type = f.kind === "url" ? "url" : f.kind === "number" ? "number" : "text";
  return `<div class="field"><label for="${id}">${esc(f.label)}${f.required ? "" : ' <span class="muted">(optional)</span>'}</label><input id="${id}" name="${esc(f.name)}" type="${type}" value="${esc(val ?? "")}" placeholder="${esc(f.placeholder || "")}"
    autocomplete="off" spellcheck="false" ${f.kind === "url" ? 'inputmode="url"' : ""} ${f.required ? "required" : ""} ${d}>${help}</div>`;
}
function viewWizard(pid) {
  const p = spec(pid);
  if (!p || !p.implemented) return `<div class="notice bad" role="alert">That provider has no connection wizard. <a href="#/integrations/connect">Choose another provider</a>.</div>`;
  if (!enabled()) return `<p class="crumbs"><a href="#/integrations">Integrations</a> / ${esc(p.name)}</p><h1 id="page-title" tabindex="-1">${esc(p.name)}</h1>${disabledNotice()}`;
  if (!I.wiz || I.wiz.provider !== pid) I.wiz = newWizard(pid);
  const w = I.wiz;
  const head = `<p class="crumbs"><a href="#/integrations">Integrations</a> / <a href="#/integrations/connect">Connect a SIEM</a> / ${esc(p.name)}</p>
    <div class="page-head"><div><h1 id="page-title" tabindex="-1">${w.replace ? "Update" : "Connect"} ${esc(p.name)}</h1><p class="lede">${esc(p.summary)}</p></div><div>${provTag(p)}</div></div>${stepper(w.step)}`;
  const err = `<div role="alert">${w.error ? `<p class="form-error">${esc(w.error)}</p>` : ""}</div>`;
  if (w.step === 1) return head + wizardDetails(p, w) + err;
  if (w.step === 2) return head + wizardTest(p, w) + err;
  if (w.step === 3) return head + wizardScope(p, w) + err;
  return head + wizardSave(p, w) + err;
}
/* A browser sign-in (OAuth): the provider can do it and this method has no pasted credential. */
const isInteractive = (p, auth) => !!(p && p.capabilities && p.capabilities.oauth && !p.secret_fields.some((s) => s.auth === auth));
const redirectUri = () => `${location.origin}/api/integrations/oauth/callback`;
function oauthBox(p, hidden) {
  const ss = I.status.secret_store || {};
  return `<div class="field" data-oauthbox ${hidden ? "hidden" : ""}><p class="label">Sign in at the provider</p>
    <p class="small measure">A new window opens at the provider's own sign-in page. Shakedown never sees your password. It keeps only a refresh token, in ${esc(ss.kind || "memory")}${ss.persistent ? "" : " (lost when the server stops)"}, and can read logs only as the signed-in account can.</p>
    <p class="small measure">The sign-in returns to this redirect URI, so register it on your app registration (Authentication, Mobile and desktop applications, with public client flows allowed) and grant the delegated permission <b>Log Analytics API: Data.Read</b>:</p>
    ${copyBlock("oauth-redirect", redirectUri())}
    <p class="help">If you opened this page as 127.0.0.1, Microsoft may not match a registered localhost address: open Shakedown as <code>http://localhost</code> to match what you registered.</p></div>`;
}
function waitingPanel(w, replace) {
  const f = w.flow;
  return `<section class="panel panel-pad" role="status" aria-live="polite"><h2 class="sec">${replace ? "Sign in again" : "Waiting for sign-in"}</h2>
    <p class="small measure">A sign-in window was opened at the provider. Finish signing in there; this page continues by itself, and nothing is saved until the connection passes its test. The sign-in expires in ${esc(f.minutes)} minutes.</p>
    <p class="small measure">If no window opened, <a href="${esc(f.url)}" target="_blank" rel="noopener noreferrer">open the sign-in page</a>.</p>
    <div class="actions" style="margin-top:12px"><button class="btn" type="button" data-iaction="cancel-signin">Cancel sign-in</button></div></section>`;
}
function detailsFields(p, w, keepEndpoint) {
  const std = p.fields.filter((f) => !f.advanced).map((f) => (keepEndpoint && f.name === "endpoint" ? { ...f, required: false, placeholder: "Leave empty to keep the current endpoint" } : f)), adv = p.fields.filter((f) => f.advanced);
  const secrets = p.secret_fields, interactive = isInteractive(p, w.auth);
  const authSel = p.auth_methods.length > 1 ? `<div class="field"><label for="f-auth">Sign in with</label><select id="f-auth" name="auth">${p.auth_methods.map(([id, label]) => `<option value="${esc(id)}" ${id === w.auth ? "selected" : ""}>${esc(label)}</option>`).join("")}</select></div>` : "";
  const groups = p.auth_methods.map(([a]) => {
    const fs = secrets.filter((s) => s.auth === a);
    return `<div data-auth="${esc(a)}" ${a === w.auth ? "" : "hidden"}>
      <div data-cred="paste" ${w.credMode === "paste" ? "" : "hidden"}>${fs.map((f) => `<div class="field"><label for="sec-${esc(a)}-${esc(f.name)}">${esc(f.label)}</label><input id="sec-${esc(a)}-${esc(f.name)}" name="sec_${esc(a)}_${esc(f.name)}" type="${f.kind === "secret" ? "password" : "text"}" autocomplete="${f.kind === "secret" ? "new-password" : "off"}" spellcheck="false" autocapitalize="off" ${a === w.auth ? "" : "disabled"}></div>`).join("")}</div>
      <div data-cred="env" ${w.credMode === "env" ? "" : "hidden"}>${fs.map((f) => `<div class="field"><label for="env-${esc(a)}-${esc(f.name)}">Environment variable for the ${esc(f.label.toLowerCase())}</label><input id="env-${esc(a)}-${esc(f.name)}" name="env_${esc(a)}_${esc(f.name)}" type="text" value="${esc((w.env[a + "_" + f.name]) || "")}" placeholder="${esc((p.id.split("_")[0] + "_" + f.name).toUpperCase())}" autocomplete="off" spellcheck="false" ${a === w.auth ? "" : "disabled"}></div>`).join("")}
        <p class="help">The variable must be set in the environment of the Shakedown server (a <code>.env</code> file in the project folder works). Only its name is saved.</p></div></div>`;
  }).join("");
  return `${std.map((f) => fieldHtml(f, w.values[f.name])).join("")}${authSel}
    ${p.capabilities && p.capabilities.oauth ? oauthBox(p, !interactive) : ""}
    <fieldset class="field" data-credbox ${interactive ? "hidden" : ""}><legend class="label">Credential</legend>
      <label class="check-row"><input type="radio" name="credmode" value="paste" ${w.credMode === "paste" ? "checked" : ""}> Enter it here, once. It is checked now and saved in ${esc(((I.status.secret_store || {}).kind) || "memory")}${(I.status.secret_store || {}).persistent ? "" : " only (lost when the server stops)"}.</label>
      <label class="check-row"><input type="radio" name="credmode" value="env" ${w.credMode === "env" ? "checked" : ""}> Read it from an environment variable on this machine.</label>
      ${groups}<p class="help">Use a dedicated search-only account or token with the narrowest scope. The credential is never shown again, never put in a URL, and never sent to a model.</p></fieldset>
    ${adv.length ? `<details data-k="wiz-adv"><summary class="small" style="cursor:pointer;font-weight:650">Advanced options</summary><div style="margin-top:10px">${adv.map((f) => fieldHtml(f, w.values[f.name])).join("")}</div></details>` : ""}`;
}
function submitLabel(p, w) { return isInteractive(p, w.auth) ? "Sign in" : "Test connection"; }
function wizardDetails(p, w) {
  if (w.flow) return waitingPanel(w, false);
  return `<form id="wiz-form" class="panel panel-pad" novalidate><h2 class="sec">1. Connection details</h2>${detailsFields(p, w, false)}
    <div class="actions" style="margin-top:18px"><button class="btn primary" type="submit" data-submit ${w.busy ? "disabled" : ""}>${w.busy ? "Working" : submitLabel(p, w)}</button><a class="btn" href="#/integrations/connect">Cancel</a></div>
    <p class="help">Testing makes real calls to the provider from this machine: network and TLS, authentication, then permissions.</p></form>`;
}
function wizardTest(p, w) {
  const t = w.test, rep = t.report;
  return `<section class="panel panel-pad"><h2 class="sec">2. Connection test</h2>
    <p class="small muted measure">${rep.ok ? "Shakedown reached the endpoint and signed in. These are the results of each check; a connection is only as capable as the permissions below." : "The connection did not pass. Fix the failed check and test again; nothing has been saved."}</p>
    ${checksHtml(rep)}${identityHtml(rep)}${warningsHtml(rep.warnings)}
    <div class="actions" style="margin-top:18px">${rep.ok ? '<button class="btn primary" type="button" data-iaction="wiz-next">Continue to data scope</button>' : ""}<button class="btn" type="button" data-iaction="wiz-back">${rep.ok ? "Change details" : "Edit details and test again"}</button></div>
    ${rep.ok ? '<p class="help">You will re-enter the credential if you change the details. It is not kept in this page.</p>' : ""}</section>`;
}
function wizardScope(p, w) {
  const sc = w.test.scopes || { discovery: "manual", items: [], note: "" };
  const noun = p.scope_noun;
  const list = sc.items.length ? `<div class="tbl-wrap scroll" tabindex="0" role="region" aria-label="Available ${esc(pl(noun))}"><table><caption class="sr">Available ${esc(pl(noun))}</caption><thead><tr><th scope="col">Search</th><th scope="col">${esc(cap(noun))}</th><th scope="col" class="num">Events</th></tr></thead><tbody>
    ${sc.items.map((i) => `<tr><td><input type="checkbox" name="scope" value="${esc(i.name)}" id="sc-${esc(i.name)}" ${w.selected.includes(i.name) ? "checked" : ""} aria-label="Search ${esc(i.name)}"></td><th scope="row"><label for="sc-${esc(i.name)}" style="margin:0;font-weight:500">${esc(i.name)}</label></th><td class="num">${Number.isFinite(Number(i.events)) ? Number(i.events).toLocaleString("en-US") : ""}</td></tr>`).join("")}</tbody></table></div>` : "";
  return `<form id="scope-form" class="panel panel-pad" novalidate><h2 class="sec">3. Data scope and window</h2>
    <p class="small muted measure">${esc(sc.note || "")} Choose only the ${esc(pl(noun))} a rule should be assessed against. Names must be specific: wildcards are refused.</p>
    ${list}
    <div class="field"><label for="manual">${sc.items.length ? "Other " + esc(pl(noun)) + ", by name (optional)" : esc(cap(pl(noun))) + ", by name"}</label><input id="manual" name="manual" type="text" value="${esc(w.manual)}" placeholder="${esc(p.scope_example || "")}" autocomplete="off" spellcheck="false">
      <p class="help">Separate names with commas. The account must already be allowed to search them.${p.capabilities.verify_scope ? " Saving checks read access to each one with a single read-only query." : ""}</p></div>
    <div class="field"><label for="hours">Default search window (hours)</label><input id="hours" name="hours" type="number" min="1" max="720" value="${esc(w.hours)}" required>
      <p class="help">Every search is bounded: it covers this many hours back from the moment you preview it, and never more than the longest window this connection allows. There is no open-ended search.</p></div>
    <p class="notice small">An empty result can mean no matching events, missing telemetry, a field that is not parsed the way the rule expects, or a role that cannot see the data. The preflight tells these apart where it can; it never reports an empty search as "nothing detected".</p>
    <div class="actions" style="margin-top:16px"><button class="btn primary" type="submit">Continue to review</button><button class="btn" type="button" data-iaction="wiz-prev">Back</button></div></form>`;
}
function wizardSave(p, w) {
  const t = w.test, rep = t.report, host = (rep.endpoint || {}).host || "";
  const label = w.label || `${p.name}${host ? " (" + host.replace(/^https?:\/\//, "") + ")" : ""}`;
  const cred = t.credential.mode === "env" ? `environment variable ${Object.values(t.credential.env || {}).join(", ")}` : `saved in ${esc(((I.status.secret_store || {}).kind) || "memory")}, fingerprint ${esc(t.credential.fingerprint)}`;
  return `<form id="save-form" class="panel panel-pad" novalidate><h2 class="sec">4. Review and save</h2>
    <div class="field"><label for="label">Connection name</label><input id="label" name="label" type="text" value="${esc(label)}" maxlength="80" required></div>
    <dl class="kv"><dt>Provider</dt><dd>${esc(p.name)} ${provTag(p)}</dd><dt>Endpoint</dt><dd class="mono">${esc(host)}</dd>
    <dt>Account</dt><dd>${esc((rep.identity || {}).username || "")}</dd><dt>Permissions</dt><dd>${esc((rep.checks.find((c) => c.id === "permissions") || {}).detail || "")}</dd>
    <dt>Credential</dt><dd>${cred}. The value is never shown again.</dd><dt>${esc(cap(pl(p.scope_noun)))}</dt><dd>${esc(w.selected.join(", "))}</dd><dt>Default window</dt><dd>${esc(w.hours)} hours</dd></dl>
    ${p.status === "live_verified_test_instance" ? "" : `<div class="notice warn" style="margin-top:12px">${esc(p.verification_note)}</div>`}
    ${warningsHtml(rep.warnings)}
    <div class="actions" style="margin-top:16px"><button class="btn primary" type="submit" ${w.busy ? "disabled" : ""}>${w.busy ? "Saving" : "Save connection"}</button><button class="btn" type="button" data-iaction="wiz-prev">Back</button></div></form>`;
}
function readWizardForm(form, p) {
  const w = I.wiz;
  w.auth = form.elements.auth ? form.elements.auth.value : w.auth;
  w.credMode = form.elements.credmode.value;
  const config = {};
  for (const f of p.fields) {
    const el = form.elements[f.name];
    if (!el) continue;
    const v = f.kind === "bool" ? el.checked : f.kind === "number" ? (el.value === "" ? undefined : Number(el.value)) : el.value.trim();
    w.values[f.name] = f.kind === "bool" ? el.checked : el.value;
    if (v !== "" && v !== undefined) config[f.name] = v;
  }
  const names = p.secret_fields.filter((s) => s.auth === w.auth).map((s) => s.name);
  let secret;
  if (w.credMode === "env") {
    const env = {};
    for (const n of names) { env[n] = form.elements[`env_${w.auth}_${n}`].value.trim(); w.env[w.auth + "_" + n] = env[n]; }
    secret = { mode: "env", env };
  } else {
    const values = {};
    for (const n of names) values[n] = form.elements[`sec_${w.auth}_${n}`].value;
    secret = { mode: "paste", values };
  }
  return { config, secret };
}

/* ---------- connection page ---------- */
async function enterConnection(id) {
  I.confirm = false; I.edit = false; I.notice = ""; I.error = "";  // reset before the awaits: a click made while the page loads must not be undone when loading ends
  I.conn = await iapi("GET", `/connections/${encodeURIComponent(id)}`);
  I.rules = (await iapi("GET", "/rules")).rules.sort((a, b) => (b.rule_valid - a.rule_valid) || (b.success - a.success) || String(b.recorded_at || "").localeCompare(String(a.recorded_at || "")));
  await loadAssessments(id);
  const def = (I.conn.scope && I.conn.scope.default_window_hours) || 24;
  if (!I.pf || I.pf.connId !== id) I.pf = { connId: id, mode: "ref", ref: (I.rules[0] || {}).ref || "", text: "", indexes: [...I.conn.scope.indexes], hours: def, plan: null, busy: false, error: "" };
}
function viewConnection(id) {
  const c = I.conn;
  if (!c || c.id !== id) return S.loadError ? `<div class="notice bad" role="alert">${esc(S.loadError)}</div><p><a href="#/integrations">Back to integrations</a></p>` : `<p class="muted" role="status">Loading</p>`;
  const st = CONN_TAG[c.state] || CONN_TAG.unverified, p = spec(c.provider) || { fields: [], secret_fields: [], auth_methods: [], name: c.provider_name };
  const checks = c.last_check ? checksHtml({ checks: c.last_check.checks }) + identityHtml(c.last_check) + warningsHtml(c.last_check.warnings) : '<p class="muted small">This connection has not been checked.</p>';
  return `<p class="crumbs"><a href="#/integrations">Integrations</a> / ${esc(c.label)}</p>
    <div class="run-head"><div><h1 id="page-title" tabindex="-1">${esc(c.label)}</h1>
      <div class="run-meta">${tag(...st)}${provTag(c)}<span class="mode-line">${esc(c.provider_name)} at <span class="mono">${esc(c.endpoint)}</span></span></div>
      <p class="provenance">Last checked ${esc(when(c.last_check && c.last_check.at))}. Credential: ${c.credential.mode === "env" ? "environment variable " + esc(Object.values(c.credential.env || {}).join(", ")) : `saved in ${esc(c.credential.store)} (fingerprint ${esc(c.credential.fingerprint)})`}.</p></div>
      <div class="actions"><button class="btn" type="button" data-iaction="retest" data-id="${esc(c.id)}" ${I.busy ? "disabled" : ""}>${I.busy ? "Testing" : "Test connection"}</button><button class="btn" type="button" data-iaction="edit">Update connection</button>
      <button class="btn" type="button" data-iaction="ask-disconnect">Disconnect</button></div></div>
    ${I.notice ? `<div class="notice" role="status" style="margin-bottom:16px">${esc(I.notice)}</div>` : ""}${I.error ? `<div class="notice bad" role="alert" style="margin-bottom:16px">${esc(I.error)}</div>` : ""}
    ${c.state === "needs_credentials" ? `<div class="notice warn" role="status" style="margin-bottom:16px"><b>Credentials needed.</b> ${c.credential.mode === "env" ? "The environment variable is not set for the Shakedown server." : "The saved credential is not available (the server restarted, or it was removed)."} Use <b>Update connection</b> to enter it again; nothing will run until you do.</div>` : ""}
    ${I.confirm ? disconnectPanel(c) : ""}${I.edit ? editPanel(c, p) : ""}
    <div class="work"><section aria-labelledby="chk-h"><h2 class="sec" id="chk-h">Last connection check</h2><div class="panel panel-pad">${checks}</div>
      <h2 class="sec" style="margin-top:24px">Scope</h2><div class="panel panel-pad small"><dl class="kv"><dt>${esc(cap(pl(c.scope_noun)))}</dt><dd>${esc(c.scope.indexes.join(", "))}</dd><dt>Default window</dt><dd>${esc(c.scope.default_window_hours || "not set")} hours</dd></dl>
        <p class="help">The scope is the list of ${esc(pl(c.scope_noun))} a preflight may use. Change it with <b>Update connection</b>.</p></div></section>
      <section aria-labelledby="pf-h"><h2 class="sec" id="pf-h">Run a read-only preflight</h2>${preflightForm(c)}
      <h2 class="sec" style="margin-top:24px">Recent assessments</h2>${assessmentsTable(I.assessments.slice(0, 5), false)}</section></div>`;
}
function disconnectPanel(c) {
  return `<div class="panel panel-pad" role="alertdialog" aria-labelledby="dc-h" style="margin-bottom:16px;border-color:var(--bad)"><h2 class="sec" id="dc-h">Disconnect ${esc(c.label)}?</h2>
    <p class="small measure">Shakedown deletes its saved credential and this connection. It cannot revoke the credential inside ${esc(c.provider_name)}: revoke the token there if you no longer need it. Any running search is stopped.</p>
    <label class="check-row"><input type="checkbox" id="del-assess"> Also delete this connection's saved assessments, including any event excerpts</label>
    <div class="actions" style="margin-top:12px"><button class="btn primary" type="button" style="background:var(--bad);border-color:var(--bad)" data-iaction="disconnect" data-id="${esc(c.id)}">Disconnect and delete the credential</button><button class="btn" type="button" data-iaction="cancel-disconnect">Keep it</button></div></div>`;
}
function editPanel(c, p) {
  I.wiz = I.wiz && I.wiz.replace === c.id ? I.wiz : { ...newWizard(c.provider), replace: c.id, values: { ...newWizard(c.provider).values, endpoint: "" } };
  if (I.wiz.flow) return `<div style="margin-bottom:16px">${waitingPanel(I.wiz, true)}</div>`;
  return `<div class="panel panel-pad" style="margin-bottom:16px"><h2 class="sec">Update connection</h2><p class="small muted measure">Enter the credential again, or sign in again; change the endpoint only if it moved. Nothing changes unless the new settings pass a test.</p>
    <form id="edit-form" novalidate><div class="stack">${detailsFields(p, I.wiz, true)}</div>
    <div class="actions" style="margin-top:12px"><button class="btn primary" type="submit" data-submit>${isInteractive(p, I.wiz.auth) ? "Sign in and apply" : "Test and apply"}</button><button class="btn" type="button" data-iaction="cancel-edit">Cancel</button></div></form></div>`;
}
function preflightForm(c) {
  const f = I.pf;
  if (!f) return "";
  const rules = I.rules.map((r) => `<option value="${esc(r.ref)}" ${r.ref === f.ref ? "selected" : ""}>${esc(r.rule_title || r.scenario)}: ${esc(r.scenario)} (${esc(r.source)}${r.rule_valid ? "" : ", rule not valid"})</option>`).join("");
  return `<form id="plan-form" class="panel panel-pad" novalidate>
    <fieldset class="field"><legend class="label">Rule</legend>
      <label class="check-row"><input type="radio" name="rulemode" value="ref" ${f.mode === "ref" ? "checked" : ""} ${I.rules.length ? "" : "disabled"}> A rule from an earlier assessment</label>
      <select name="ref" aria-label="Rule from an earlier assessment" ${f.mode === "ref" ? "" : "disabled"}>${rules || "<option value=''>No assessments yet</option>"}</select>
      <label class="check-row" style="margin-top:8px"><input type="radio" name="rulemode" value="paste" ${f.mode === "paste" ? "checked" : ""}> Paste a Sigma rule</label>
      <textarea name="text" rows="6" aria-label="Sigma rule YAML" spellcheck="false" class="mono-area" ${f.mode === "paste" ? "" : "disabled"} placeholder="title: ...">${esc(f.text)}</textarea></fieldset>
    <fieldset class="field"><legend class="label">${esc(cap(pl(c.scope_noun)))} to search</legend>
      ${c.scope.indexes.map((i) => `<label class="check-row"><input type="checkbox" name="idx" value="${esc(i)}" ${f.indexes.includes(i) ? "checked" : ""}> ${esc(i)}</label>`).join("")}</fieldset>
    <div class="field"><label for="pf-hours">Search the last (hours)</label><input id="pf-hours" name="hours" type="number" min="1" max="720" value="${esc(f.hours)}" required style="max-width:140px">
      <div class="actions" style="margin-top:6px">${[1, 6, 24, 72].map((h) => `<button class="btn small" type="button" data-iaction="hours" data-h="${h}">${h} h</button>`).join("")}</div>
      <p class="help">The window is fixed when you preview, so the preview and the run cover exactly the same time.</p></div>
    <div class="actions"><button class="btn primary" type="submit" ${f.busy ? "disabled" : ""}>${f.busy ? "Preparing" : "Preview the query"}</button></div>
    <div role="alert">${f.error ? `<p class="form-error">${esc(f.error)}</p>` : ""}</div>
    ${f.plan ? planHtml(c, f.plan) : ""}</form>`;
}
function planHtml(c, plan) {
  const v = plan.rule_validity;
  const head = `<div class="section" style="margin-top:18px"><h3 class="sub">Query preview: nothing has been sent to ${esc(c.provider_name)}</h3>
    <dl class="kv small"><dt>Rule</dt><dd>${esc(plan.rule.title)} <span class="muted">(${esc(plan.rule.source)})</span></dd><dt>Rule validity</dt><dd>${v.ok ? tag("ok", "Accepted by the Sigma validator") : tag("bad", "Rejected by the Sigma validator")}</dd>
    <dt>Scope</dt><dd>${esc(plan.scope.indexes.join(", "))}</dd><dt>Window</dt><dd>${esc(utc(plan.window.earliest))} to ${esc(utc(plan.window.latest))} (${esc(plan.window.hours)} hours)</dd></dl>`;
  if (!plan.runnable) return `${head}<div class="notice ${v.ok ? "warn" : "bad"}" style="margin-top:10px" role="status">${esc(plan.reason || "This rule cannot be run.")}${!v.ok && v.errors.length ? `<pre class="codeblock" style="margin-top:8px">${esc(v.errors.join("\n"))}</pre>` : ""}</div></div>`;
  const order = ["coverage", "fields", "detection", "sample"];
  const label = { coverage: "1. Coverage: how many events of this log source exist", fields: "2. Fields: which fields those events actually have", detection: "3. Detection: how many events match the rule", sample: "4. Sample: up to a few matching events" };
  return `${head}<p class="small muted measure">These are the ${esc(plan.language)} searches that will run, in this order. Each is checked against a read-only command list before anything is sent. The log-source scope is an assumption about how your events are indexed; check it.</p>
    ${order.filter((k) => plan.queries[k]).map((k) => `<h4 class="small" style="margin:12px 0 2px">${esc(label[k] || k)}</h4><pre class="codeblock" id="q-${esc(k)}" tabindex="0">${esc(plan.queries[k])}</pre><button class="btn small" type="button" data-action="copy-text" data-target="q-${esc(k)}">Copy query</button>`).join("")}
    ${(plan.notes || []).map((n) => `<p class="help">${esc(n)}</p>`).join("")}
    <div class="actions" style="margin-top:16px"><button class="btn primary" type="button" data-iaction="run-plan" data-plan="${esc(plan.plan_id)}">Run this read-only preflight</button></div>
    <p class="help">It creates and deletes only its own search job. It never creates an alert or saved search and never deploys the rule. The preview expires in ${esc(plan.expires_minutes)} minutes.</p></div>`;
}

/* ---------- assessments ---------- */
function assessmentsTable(list, showConn) {
  if (!list.length) return `<div class="empty"><h2>No assessments yet</h2><p class="muted small measure">A preflight you run against a connected SIEM appears here with its query, scope, window and result.</p></div>`;
  return `<div class="tbl-wrap" tabindex="0" role="region" aria-label="Assessments"><table><caption class="sr">Assessments run against connected SIEMs</caption><thead><tr><th scope="col">Rule</th>${showConn ? '<th scope="col">Connection</th>' : ""}<th scope="col">Window</th><th scope="col">Result</th><th scope="col" class="num">Matches</th><th scope="col">Started</th></tr></thead><tbody>
    ${list.map((a) => `<tr><th scope="row"><a class="title-link" href="#/assessment/${esc(a.id)}">${esc((a.rule || {}).title || "Rule")}</a><span class="sub">${esc(a.rule_source || "")}</span></th>${showConn ? `<td>${esc(a.connection_label || "")}<span class="sub">${esc(a.provider_name || "")}</span></td>` : ""}
      <td class="small">${a.window ? esc(utc(a.window.earliest)) + "<span class='sub'>to " + esc(utc(a.window.latest)) + "</span>" : ""}</td><td>${tag(...(ENV_TAG[a.status] || ENV_TAG.not_run))}<span class="sub">New execution</span></td>
      <td class="num">${a.matches == null ? "" : esc(a.matches)}</td><td class="small">${esc(when(a.started_at))}</td></tr>`).join("")}</tbody></table></div>`;
}
function viewAssessments() {
  return `<div class="page-head"><div><h1 id="page-title" tabindex="-1">Assessments</h1><p class="lede">Read-only preflights you ran against your own SIEMs. Each one is a new execution against that SIEM, not a replay; replays of recorded Shakedown runs are in Run history.</p></div></div>
    ${enabled() ? assessmentsTable(I.assessments, true) : disabledNotice()}`;
}
const KIND_LABEL = { auth: "Authentication", permission: "Permission", tls: "TLS", unreachable: "Network", destination: "Destination", query: "Query", timeout: "Timeout", cancelled: "Cancelled" };
async function enterAssessment(route) {
  await loadStatus();
  if (!enabled()) return;
  I.assess = await iapi("GET", `/assessments/${encodeURIComponent(route.arg)}`);
  startAssessmentPoll(route.arg);
}
function startAssessmentPoll(id) {
  clearInterval(I.poll);
  I.poll = null;
  if (!I.assess || I.assess.status !== "running") return;
  I.poll = setInterval(async () => {
    if (S.route.name !== "assessment" || S.route.arg !== id) { clearInterval(I.poll); return; }
    try {
      const fresh = await iapi("GET", `/assessments/${encodeURIComponent(id)}`);
      const changed = fresh.status !== I.assess.status;
      I.assess = fresh;
      if (fresh.status !== "running") { clearInterval(I.poll); announce("The preflight finished: " + (ENV_TAG[fresh.status] || ["", fresh.status])[1]); }
      if (changed) rerender();
    } catch (e) { clearInterval(I.poll); I.error = e.message; rerender(); }
  }, 1500);
}
const canCancel = (a) => !a.capabilities || !!a.capabilities.cancel;  // records from before capabilities were stored are Splunk, which can cancel
function viewAssessment() {
  const a = I.assess;
  if (!enabled()) return disabledNotice();
  if (!a || a.id !== S.route.arg) return S.loadError ? `<div class="notice bad" role="alert">${esc(S.loadError)}</div><p><a href="#/assessments">Back to assessments</a></p>` : `<p class="muted" role="status">Loading</p>`;
  const A = a.assessment, st = A ? A.statuses : null, env = st ? st.environment_preflight : null, title = (a.rule || {}).title || "Assessment";
  const head = `<p class="crumbs"><a href="#/assessments">Assessments</a> / ${esc(title)}</p>
    <div class="run-head"><div><h1 id="page-title" tabindex="-1">${esc(title)}</h1>
      <div class="run-meta">${tag("info", "New execution")}${tag(...(ENV_TAG[a.status] || ENV_TAG.not_run))}<span class="mode-line">${esc(a.provider_name)}: ${esc(a.connection_label)}</span></div>
      <p class="provenance">Started ${esc(when(a.started_at))}${a.finished_at ? ", finished " + esc(when(a.finished_at)) + " (" + esc(a.elapsed_s) + " s)" : ""}. Searched ${esc(((a.scope || {}).indexes || []).join(", "))} from ${esc(utc((a.window || {}).earliest))} to ${esc(utc((a.window || {}).latest))}. Rule source: ${esc(a.rule_source)}. Credential fingerprint ${esc(a.credential_fingerprint || "n/a (environment variable)")}.</p></div>
      <div class="actions">${a.status === "running" ? (canCancel(a) ? '<button class="btn" type="button" data-iaction="cancel-run">Cancel search</button>' : "") : A ? '<button class="btn" type="button" data-iaction="export" data-fmt="md">Review packet (Markdown)</button><button class="btn" type="button" data-iaction="export" data-fmt="json">Assessment (JSON)</button><button class="btn" type="button" data-iaction="export" data-fmt="query">Query</button>' : ""}</div></div>
    ${I.error ? `<div class="notice bad" role="alert" style="margin-bottom:16px">${esc(I.error)}</div>` : ""}`;
  if (a.status === "running") return head + `<div class="notice" role="status"><b>Running read-only searches in ${esc(a.provider_name)}.</b> Shakedown is waiting for the SIEM. There is no progress percentage because the SIEM does not report one; you can leave this page and come back${canCancel(a) ? ", or cancel the search" : ". " + esc(a.provider_name) + " searches cannot be cancelled from Shakedown; this one stops at its server-side time limit"}.</div>${queriesBlock(a)}`;
  if (a.status === "interrupted") return head + `<div class="notice warn" role="status"><b>This preflight was interrupted.</b> The server stopped while it ran, so there is no result. Run it again from the connection page.</div>${queriesBlock(a)}`;
  const verdict = (q, s, extra) => `<section class="verdict ${extra}" aria-labelledby="av-${q[0]}"><h2 class="q" id="av-${q[0]}" style="font-size:.8125rem">${esc(q[1])}</h2><p class="state">${esc(s.label)}</p><ul><li>${esc(s.detail || "")}</li></ul></section>`;
  const cls = (s) => (["valid", "validated_on_supplied_attack_evidence"].includes(s.state) ? "ok" : ["invalid", "attack_not_detected", "query_failed"].includes(s.state) ? "bad" : s.state === "telemetry_missing_or_unsupported" ? "warn" : "");
  return head + `<div class="verdicts" role="group" aria-label="Three separate verdicts">${verdict(["1", "Rule validity"], st.rule_validity, cls(st.rule_validity))}${verdict(["2", "Attack validation"], st.attack_validation, cls(st.attack_validation))}${verdict(["3", "Environment preflight"], env, cls(env))}</div>
    <p class="reading">${esc(A.recommendation.text)}</p>
    <div class="section">${environmentDetail(a, env)}</div>${queriesBlock(a)}
    <section class="section"><h2 class="sec">Limits of this result</h2><ul class="list-plain small measure" style="list-style:disc;padding-left:20px">${A.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul></section>`;
}
function environmentDetail(a, env) {
  const parts = [];
  if (env.state === "query_failed") {
    const e = env.error || {};
    parts.push(`<div class="notice bad" role="alert"><b>${esc(KIND_LABEL[e.kind] || "Search")} problem.</b> ${esc(e.message || "")}<div class="small" style="margin-top:6px;font-weight:400">${esc(KIND_HELP[e.kind] || "")}</div></div>`);
    return parts.join("");
  }
  const cov = env.coverage, f = env.fields, m = env.matches || {};
  parts.push(`<h2 class="sec">What the search found</h2><dl class="kv" style="margin-bottom:14px"><dt>Events of this log source in scope</dt><dd>${cov ? esc(Number(cov.events_in_scope).toLocaleString("en-US")) : "not measured"}${cov && cov.first_event ? `<span class="muted small"> (first ${esc(epoch(cov.first_event))}, last ${esc(epoch(cov.last_event))})</span>` : ""}</dd>
    ${f ? `<dt>Fields the rule needs</dt><dd>${esc(f.rule_fields.join(", "))}</dd><dt>Seen in a sample of ${esc(f.sampled_events)} events</dt><dd>${f.missing.length ? `<b class="cell-warn">missing: ${esc(f.missing.join(", "))}</b>` : "all present"}</dd>` : ""}
    <dt>Events matching the rule</dt><dd>${m.count == null ? "not run" : `<b>${esc(Number(m.count).toLocaleString("en-US"))}</b>`}</dd></dl>`);
  if (env.state === "telemetry_missing_or_unsupported") parts.push(`<div class="notice warn" role="status"><b>This is not a clean result.</b> ${esc(env.detail)}</div>`);
  else if (env.state === "no_matches_in_window") parts.push(`<div class="notice" role="status">${esc(env.detail)} A quiet window does not show that the rule can detect an attack that did not happen in it.</div>`);
  else if (env.state === "potential_matches_found") parts.push(`<div class="notice" role="status">${esc(env.detail)}</div>`);
  const ex = m.examples || [];
  if (ex.length) {
    const cols = [...new Set(ex.flatMap((e) => Object.keys(e)))];
    parts.push(`<h3 class="sub" style="margin-top:16px">Example matching events (${esc(m.examples_shown)} of ${esc(m.count)}, values shortened)</h3><div class="tbl-wrap scroll" tabindex="0" role="region" aria-label="Example matching events"><table><caption class="sr">Example matching events</caption><thead><tr>${cols.map((c) => `<th scope="col">${esc(c)}</th>`).join("")}</tr></thead><tbody>${ex.map((e) => `<tr>${cols.map((c) => `<td class="mono" style="overflow-wrap:anywhere">${esc(c === "_time" ? epoch(e[c]) : e[c] ?? "")}</td>`).join("")}</tr>`).join("")}</tbody></table></div>
      <p class="help">These come from your SIEM and may contain sensitive data. They are shown here and in the export only; they are not sent to any model or service.</p>`);
  }
  return parts.join("");
}
function queriesBlock(a) {
  const q = a.queries || {};
  return Object.keys(q).length ? `<details class="limits" data-k="queries"><summary>The ${esc(a.language)} searches that ${a.status === "running" ? "are running" : "were run"} (hash ${esc((a.query_sha256 || "").slice(0, 12))})</summary>
    ${Object.entries(q).map(([k, v]) => `<h4 class="small" style="margin:10px 0 2px">${esc(k)}</h4><pre class="codeblock" id="aq-${esc(k)}" tabindex="0">${esc(v)}</pre>`).join("")}</details>` : "";
}

/* ---------- browser sign-in ---------- */
function afterTest(w) {
  const items = (w.test.scopes && w.test.scopes.items) || [], ws = (w.test.config || {}).workspace_id;
  w.step = 2; w.selected = items.length === 1 ? [items[0].name] : [];
  if (ws && items.some((i) => i.name === ws)) w.selected = [...new Set([...w.selected, ws])];
  else if (ws) w.manual = ws;
}
function flowFailed(w, message) { w.flow = null; if (w.replace) I.error = message; else w.error = message; }
async function startSignIn(p, config) {
  const w = I.wiz, connId = w.replace || null;
  w.busy = true; w.error = ""; I.error = ""; rerender();
  try {
    const f = await iapi("POST", "/oauth/start", { provider: p.id, auth: w.auth, config, connection_id: connId });
    w.flow = { id: f.flow_id, url: f.authorize_url, minutes: f.expires_minutes, connId };
    window.open(f.authorize_url, "_blank", "noopener,noreferrer");
    pollSignIn(f.flow_id);
  } catch (err) { flowFailed(w, err.message); }
  w.busy = false; rerender();
}
function pollSignIn(flowId) {
  clearInterval(I.flowTimer);
  I.flowTimer = setInterval(async () => {
    const w = I.wiz;
    if (!w || !w.flow || w.flow.id !== flowId) { clearInterval(I.flowTimer); return; }
    try {
      const out = await iapi("GET", `/oauth/flows/${encodeURIComponent(flowId)}`);
      if (out.status === "waiting" || out.status === "exchanging") return;
      clearInterval(I.flowTimer);
      const connId = w.flow.connId;
      w.flow = null;
      if (out.status === "failed") flowFailed(w, out.error.message);
      else if (connId) {
        const r = out.result;
        if (r.applied) { I.conn = r.connection; I.edit = false; I.wiz = null; I.notice = "Signed in again. The connection was updated."; I.error = ""; await loadConnections(); }
        else I.error = "The new sign-in did not pass the connection test, so nothing was changed: " + r.report.checks.filter((c) => c.status === "fail").map((c) => c.label + ": " + c.detail).join("; ");
      } else { w.test = out.result; afterTest(w); }
      rerender();
    } catch (err) { clearInterval(I.flowTimer); flowFailed(w, err.message); rerender(); }
  }, 1500);
}

/* ---------- actions ---------- */
document.addEventListener("click", async (e) => {
  const el = e.target.closest("[data-iaction]");
  if (!el) return;
  const act = el.dataset.iaction, id = el.dataset.id, w = I.wiz;
  if (act === "cancel-signin") { clearInterval(I.flowTimer); if (w) w.flow = null; rerender(); }
  else if (act === "wiz-next") { w.step = 3; w.error = ""; rerender(); }
  else if (act === "wiz-back") { w.step = 1; w.test = null; w.error = ""; rerender(); }
  else if (act === "wiz-prev") { w.step = Math.max(1, w.step - 1); w.error = ""; if (w.step === 1) w.test = null; rerender(); }
  else if (act === "retest") {
    I.busy = true; I.error = ""; rerender();
    try { const out = await iapi("POST", `/connections/${encodeURIComponent(id)}/test`); I.notice = out.report.ok ? "The connection check passed." : "The connection check failed. See the result below."; I.error = ""; }
    catch (err) { I.error = err.message; }
    I.busy = false; await loadConnections(); if (S.route.arg === id) I.conn = await iapi("GET", `/connections/${encodeURIComponent(id)}`); rerender();
  }
  else if (act === "edit") { I.edit = true; I.confirm = false; I.wiz = null; rerender(); }
  else if (act === "cancel-edit") { I.edit = false; I.wiz = null; rerender(); }
  else if (act === "ask-disconnect") { I.confirm = true; I.edit = false; rerender(); const b = document.querySelector('[data-iaction="disconnect"]'); if (b) b.focus(); }
  else if (act === "cancel-disconnect") { I.confirm = false; rerender(); }
  else if (act === "disconnect") {
    const del = !!document.getElementById("del-assess")?.checked;
    try { const out = await iapi("DELETE", `/connections/${encodeURIComponent(id)}?delete_assessments=${del}`); I.notice = out.note + (out.assessments_deleted ? ` ${out.assessments_deleted} saved assessment(s) were deleted.` : ""); I.conn = null; I.pf = null; location.hash = "#/integrations"; }
    catch (err) { I.error = err.message; I.confirm = false; rerender(); }
  }
  else if (act === "hours") { if (I.pf) { I.pf.hours = Number(el.dataset.h); const inp = document.getElementById("pf-hours"); if (inp) inp.value = I.pf.hours; } }
  else if (act === "run-plan") {
    el.disabled = true;
    try { const out = await iapi("POST", `/connections/${encodeURIComponent(I.conn.id)}/preflight`, { plan_id: el.dataset.plan, confirm: true }); I.assess = null; location.hash = `#/assessment/${out.assessment_id}`; }
    catch (err) { I.pf.error = err.message; el.disabled = false; rerender(); }
  }
  else if (act === "cancel-run") { try { await iapi("POST", `/assessments/${encodeURIComponent(I.assess.id)}/cancel`); announce("Cancelling the search."); } catch (err) { I.error = err.message; rerender(); } }
  else if (act === "export") {
    try {
      const out = await iapi("GET", `/assessments/${encodeURIComponent(I.assess.id)}/export`);
      const names = { md: "review_packet.md", json: "assessment.json", query: Object.keys(out.files).find((k) => k.startsWith("query.")) };
      const type = { md: "text/markdown", json: "application/json", query: "text/plain" }[el.dataset.fmt];
      download(`${I.assess.id}-${names[el.dataset.fmt]}`, out.files[names[el.dataset.fmt]], type);
      announce(out.contains_event_excerpts ? "Downloaded. This file contains excerpts of events from your SIEM." : "Downloaded.");
    } catch (err) { I.error = err.message; rerender(); }
  }
});
document.addEventListener("change", (e) => {
  const t = e.target;
  if (t.name === "credmode" && I.wiz) {
    I.wiz.credMode = t.value;
    document.querySelectorAll("[data-cred]").forEach((d) => { d.hidden = d.dataset.cred !== t.value; });
  } else if (t.id === "f-auth" && I.wiz) {
    I.wiz.auth = t.value;
    document.querySelectorAll("[data-auth]").forEach((g) => { const on = g.dataset.auth === t.value; g.hidden = !on; g.querySelectorAll("input").forEach((i) => { i.disabled = !on; }); });
    const p = spec(I.wiz.provider), inter = isInteractive(p, t.value);
    document.querySelectorAll("[data-oauthbox]").forEach((b) => { b.hidden = !inter; });
    document.querySelectorAll("[data-credbox]").forEach((b) => { b.hidden = inter; });
    document.querySelectorAll("[data-submit]").forEach((b) => { b.textContent = I.wiz.replace ? (inter ? "Sign in and apply" : "Test and apply") : submitLabel(p, I.wiz); });
  } else if (t.name === "rulemode" && I.pf) {
    I.pf.mode = t.value;
    const f = t.form; f.elements.ref.disabled = t.value !== "ref"; f.elements.text.disabled = t.value !== "paste";
  }
});
document.addEventListener("input", (e) => { if (I.pf && e.target.id === "pf-hours") I.pf.hours = Number(e.target.value); });
document.addEventListener("submit", async (e) => {
  const form = e.target;
  if (!["wiz-form", "scope-form", "save-form", "plan-form", "edit-form"].includes(form.id)) return;
  e.preventDefault();
  const w = I.wiz;
  if (form.id === "wiz-form") {
    const p = spec(w.provider);
    const { config, secret } = readWizardForm(form, p);
    form.querySelectorAll('input[type="password"]').forEach((i) => { i.value = ""; });
    if (isInteractive(p, w.auth)) { await startSignIn(p, config); return; }
    w.busy = true; w.error = ""; rerender();
    try { w.test = await iapi("POST", "/connections/test", { provider: w.provider, auth: w.auth, config, secret }); afterTest(w); }
    catch (err) { w.error = err.message; }
    w.busy = false; rerender();
  } else if (form.id === "edit-form") {
    const p = spec(I.conn.provider);
    const { config, secret } = readWizardForm(form, p);
    form.querySelectorAll('input[type="password"]').forEach((i) => { i.value = ""; });
    if (isInteractive(p, w.auth)) { await startSignIn(p, config); return; }
    I.busy = true; I.error = ""; rerender();
    try { const out = await iapi("POST", `/connections/${encodeURIComponent(I.conn.id)}/reconfigure`, { auth: w.auth, config, secret }); I.conn = out.connection; I.edit = !out.applied; I.wiz = out.applied ? null : I.wiz;
      I.notice = out.applied ? "The connection was updated." : ""; I.error = out.applied ? "" : "The new settings did not pass the connection test, so nothing was changed: " + out.report.checks.filter((c) => c.status === "fail").map((c) => c.label + ": " + c.detail).join("; "); }
    catch (err) { I.error = err.message; }
    I.busy = false; rerender();
  } else if (form.id === "scope-form") {
    const chosen = [...form.querySelectorAll('input[name="scope"]:checked')].map((i) => i.value);
    const extra = form.elements.manual.value.split(",").map((s) => s.trim()).filter(Boolean);
    w.manual = form.elements.manual.value; w.hours = Number(form.elements.hours.value);
    w.selected = [...new Set([...chosen, ...extra])];
    if (!w.selected.length) { w.error = `Choose at least one ${spec(w.provider).scope_noun}.`; rerender(); return; }
    if (w.selected.some((s) => s.includes("*"))) { w.error = "Wildcards are not allowed; name each one."; rerender(); return; }
    w.step = 4; w.error = ""; rerender();
  } else if (form.id === "save-form") {
    w.label = form.elements.label.value.trim(); w.busy = true; w.error = ""; rerender();
    try { const conn = await iapi("POST", "/connections", { test_id: w.test.test_id, label: w.label, scope: { indexes: w.selected, default_window_hours: w.hours } });
      I.wiz = null; I.notice = `Saved “${conn.label}”.`; location.hash = `#/integrations/${conn.id}`; return; }
    catch (err) { w.error = err.message; if (err.kind === "not_found") { w.step = 1; w.test = null; w.error += " Test the connection again."; } }
    w.busy = false; rerender();
  } else if (form.id === "plan-form") {
    const f = I.pf;
    f.mode = form.elements.rulemode.value; f.ref = form.elements.ref.value; f.text = form.elements.text.value; f.hours = Number(form.elements.hours.value);
    f.indexes = [...form.querySelectorAll('input[name="idx"]:checked')].map((i) => i.value);
    if (!f.indexes.length) { f.error = "Choose at least one " + I.conn.scope_noun + "."; rerender(); return; }
    f.busy = true; f.error = ""; f.plan = null; rerender();
    try { f.plan = await iapi("POST", `/connections/${encodeURIComponent(I.conn.id)}/plan`, { rule: f.mode === "ref" ? { ref: f.ref } : { text: f.text }, indexes: f.indexes, window: { last_hours: f.hours } }); }
    catch (err) { f.error = err.message; }
    f.busy = false; rerender();
  }
});

/* ---------- registration ---------- */
EXT.views.integrations = viewIntegrations;
EXT.views.assessments = viewAssessments;
EXT.views.assessment = viewAssessment;
EXT.title.integrations = () => { const r = route(); return r.sub === "connect" ? "Connect a SIEM" : r.sub && I.conn && I.conn.id === r.sub ? I.conn.label : "Integrations"; };
EXT.enter.integrations = async () => {
  await loadStatus();
  const r = route();
  I.error = r.sub ? "" : I.error;
  if (!r.sub || r.sub === "connect") { await loadConnections(); if (r.sub === "connect" && r.rest[0] && enabled() && (!I.wiz || I.wiz.provider !== r.rest[0])) I.wiz = null; }
  else if (enabled()) { I.conn = null; try { await enterConnection(r.sub); } catch (e) { S.loadError = e.message; } }
};
EXT.enter.assessments = async () => { await loadStatus(); await loadAssessments(); };
EXT.enter.assessment = enterAssessment;
