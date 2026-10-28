# SIEM Integrations

The **Integrations** workspace lets an analyst connect a SIEM they already use, prove Shakedown can reach it with a read-only account, choose a scope and a bounded time window, see the exact native query **before** anything runs, run a read-only preflight of a Sigma rule, inspect the result, and export an evidence-backed review packet.

It recommends. It never deploys a rule, creates an alert or saved search, or changes anything in the SIEM. The three verdicts stay separate: **rule validity**, **attack validation** (lab or supplied evidence) and **environment preflight** (what a bounded historical search found in your logs).

## Turn it on (local only)

```bash
uv run python -m shakedown.serve --integrations
```

`--integrations` is refused on any non-loopback `--host`. A hosted server (the default) shows the workspace but keeps connecting disabled, with the reason: it has no user accounts, no tenant isolation and no secret vault, so it must not accept SIEM credentials. Open the app as `http://localhost:8000` (use that same name for the Microsoft redirect URI).

The command line keeps working and does not use saved connections: `python -m shakedown.assess ... --splunk` (credentials from environment variables).

## Providers and what is actually verified

| Provider | Status | What was run |
|---|---|---|
| Splunk Enterprise | **Live-verified on a throwaway local test instance** | Real Splunk Enterprise 10.6.1.1 container on loopback, simulated Sysmon events, self-signed certificate (verification explicitly accepted for that test). Not verified: production, clustered, a real Sysmon add-on, a connection whose certificate verifies. |
| Splunk Cloud | **Implemented, not live-verified** | Same adapter code path with a hostname restricted to `*.splunkcloud.com` / `*.splunkcloudgc.com`, verification forced on, token only. Never run against Splunk Cloud. |
| Elastic (Elasticsearch) | **Live-verified on a throwaway local test instance** | Real Elasticsearch 9.1.0 container on loopback with a CA-verified TLS connection, API-key authentication, simulated Sysmon events in a Winlogbeat-style index. The version is recorded as operator-supplied. Not verified: Elastic Cloud, production, a real Winlogbeat/Elastic Agent mapping. |
| Microsoft Sentinel (Azure Monitor Logs) | **Mock-tested, not live-verified** | Tested only against a mock Microsoft Entra ID, Log Analytics and Resource Manager (`tests/fake_microsoft.py`) and in a real browser against that mock. **No real Azure tenant, Entra sign-in or workspace has been used.** Consent, permissions and query behaviour there are unverified. |
| IBM QRadar | **Planned** | No adapter and no wizard. |

Mocked tests are labelled as mocks in their module docstrings and are never counted as live verification. Live tests live in `tests/live/` and are opt-in (`SPLUNK_LIVE_TEST=1`, `ELASTIC_LIVE_TEST=1`, `-m live`).

## The flow

1. **Details.** Provider-specific fields. Credentials are pasted once (checked now, stored per the secret-store rules below) or named as an environment variable on the server.
2. **Test.** A real server-side check: network and TLS, authentication, permissions, endpoint identity/version. Each check shows passed, failed, warning or *not run*. A connection is "Connected" only when its last real check passed and is recent; otherwise it reads *Not re-checked recently*, *Credentials needed* or *Last check failed*.
3. **Scope.** Indexes (Splunk, Elastic) or Log Analytics workspaces (Sentinel), discovered where the account may list them or entered by name. Wildcards are refused. Providers that can prove access (Sentinel) run one read-only query per scope before saving.
4. **Save.** Only from a test that passed, and only the credential that passed.
5. **Preview.** Choose a rule (an earlier assessment or a pasted Sigma rule), an explicit window (last N hours or earliest/latest, capped per connection) and the scope. The native queries are shown, plus the Sigma→field mapping. **Nothing has been sent yet.**
6. **Run.** An explicit confirmation executes the *stored* plan: the query that ran is byte-for-byte the query that was previewed (checked by hash).
7. **Inspect.** Coverage (events of the required log source in scope), field presence, matches and bounded example events, the exact queries, limits, and a *distinct* state for missing telemetry, missing permissions and query failures. An empty result is never reported as "nothing detected".
8. **Export.** `review_packet.md`, `assessment.json`, `rule.yml`, `query.<ext>` and `integration.json`. No credential is ever in an export; event excerpts, if any, come from your SIEM.
9. **Manage.** Re-test, update (blank fields keep saved values; nothing changes unless the new settings pass a test), re-authorize, disconnect. Disconnect deletes Shakedown's saved credential and says plainly that it cannot revoke the credential at the provider.

## Authentication per provider

* **Splunk:** authentication token (recommended) or user name and password for a search-only role. Accounts holding admin-class capabilities are refused.
* **Elastic:** API key (the `encoded` value) or basic auth. A superuser/privileged account is refused; the account needs `read`/`view_index_metadata` on the chosen indices (the check uses `_has_privileges`, so a read-only key without `monitor` still works, with a warning that the version could not be read).
* **Microsoft Sentinel:**
  * *Sign in with Microsoft (recommended)*: OAuth 2.0 authorization code flow with **PKCE** as a public client. No client secret exists anywhere. The browser goes to Microsoft; the code returns by `form_post` (never in a URL or history). Only a refresh token is kept (in the secret store) and is rotated and re-saved when Microsoft issues a new one. Register the redirect URI shown in the wizard (`http://localhost:<port>/api/integrations/oauth/callback`) under *Mobile and desktop applications* with public client flows allowed, and grant delegated **Log Analytics API → Data.Read** (plus Azure Service Management `user_impersonation` only if you want workspace listing).
  * *App registration with a client secret*: client-credentials flow for unattended use; the secret is a stored credential like any other.
  * The Microsoft hosts (`login.microsoftonline.com`, `api.loganalytics.azure.com`, `management.azure.com`) are fixed; there is no endpoint field.

## Query generation

* **Splunk:** pySigma Splunk backend; log-source scope is an assumption about your indexing (Sysmon source and EventCode). Windows Security 4688 data is reported unsupported.
* **Elastic:** pySigma Elasticsearch (Lucene) backend with the `ecs_windows` pipeline. Image and similar fields map to `.caseless` sub-fields (`process.executable.caseless`); if your mapping lacks them the field check reports them missing instead of matching nothing silently. Scope: Sysmon process creation (`winlog.channel` + `event.code`).
* **Sentinel:** pySigma Kusto backend with the Azure Monitor pipeline for the `SecurityEvent` table (EventID 4688). A rule using a field that table lacks (for example `OriginalFileName`) is refused with the pipeline's own reason; Shakedown never guesses a mapping. Sysmon in the `Event` table and Defender tables are not scoped.

Every query set is: coverage (events in scope), fields (are the rule's fields populated?), detection (count) and sample (bounded examples). All carry an explicit time bound and a server-side timeout.

## Security model

* **Credentials:** never in browser storage, URLs, HTML, JS, analytics, logs, exports or any API response; never sent to a model, Nebius, Tavily or any LLM. The pasted field is cleared on submit. Stored credentials are identified by a short non-reversible fingerprint (`sha256:<10 hex>`).
* **Secret store:** by default **memory only** (lost on restart; the connection then reads *Credentials needed*). If the optional `keyring` package is installed (`--secret-store auto|keyring`), the OS credential store is used. An environment-variable reference stores only the variable name. There is no plaintext file vault.
* **Owner isolation:** every call is scoped to the single local operator and another owner's record is "not found". This is not multi-user auth; hosted multi-user use is intentionally not offered.
* **Endpoint safety (SSRF):** https by default, certificate verification on by default, URL credentials and unexpected schemes rejected, DNS resolved and **every** resolved address classified (global / private / CGNAT / loopback / link-local / cloud-metadata / unspecified / multicast / reserved), the connection pinned to the vetted IP with the original Host/SNI, redirects refused, response size capped, and the check repeated on every call. Hosted mode allows global addresses only. Turning certificate verification off is possible only for loopback/private addresses in local mode, with an explicit acknowledgement and a visible warning. There is no generic proxy.
* **Read-only queries:** Splunk SPL command allowlist and search-endpoint allowlist; Elasticsearch endpoint allowlist and body key allowlist; KQL operator allowlist that refuses control commands, cross-workspace references, `union`/`join`/`let`/`evaluate`/`externaldata` and similar. Results, time spans and durations are capped. Nothing is deployed or created.
* **Local API guard:** `Host` allowlist (DNS-rebinding defence), `Sec-Fetch-Site` same-origin/none, `Origin` required on writes, a per-session `X-Shakedown-CSRF` token read from `/session`, `Cache-Control: no-store`, no CORS, a strict CSP. The OAuth callback is the single deliberate exception: it is a cross-site `form_post` from Microsoft, so it checks only the `Host` and trusts the request through an unguessable, single-use, short-lived `state` bound to one waiting sign-in; its page echoes nothing.
* **OAuth sign-in (Sentinel), reviewed:** the PKCE `code_verifier` and the `state` live only in server memory for one waiting sign-in; the `state` is 256 random bits, compared in constant time, single-use (spent the moment a callback claims it), erased on every exit, and expires after 10 minutes. The authorization code can only be exchanged with the verifier that matches the challenge in the original request, so a code issued to someone else's request (callback substitution, login CSRF) fails at the identity provider. The callback must arrive at exactly the address the sign-in started from. Known limits: the `state` is bound to the server-side sign-in and its PKCE verifier, not to a browser cookie (a SameSite cookie is not sent on a cross-site `form_post` to plain-http localhost), the per-session CSRF token is per server process (single operator), and the identity claims read from the `id_token` are used only to display the account name.
* **Errors:** provider errors are redacted (tokens, keys, authorization headers, JWTs, key=value secrets) and truncated before display.
* **Rate and concurrency limits:** 40 connection attempts per minute, 3 concurrent preflights, one per connection, 20 pending tests/sign-ins.

## Exact limitations

* Splunk Enterprise and Elastic were verified only on loopback test instances with **simulated** events. Splunk Cloud and Sentinel were not verified at all against the real service.
* Field names and case sensitivity depend on your mappings and add-ons; the field-presence check reports missing fields but cannot prove your parsing is right. Elastic depends on `.caseless` sub-fields from the ECS pipeline.
* Elasticsearch searches and Sentinel queries **cannot be cancelled** from Shakedown (the Cancel button is not shown); they stop at a server-side timeout. Splunk searches can be cancelled.
* A historical window shows what the rule would have matched, not that it can detect an attack that did not occur in the window, and not that you collect the needed telemetry.
* Sentinel covers Windows Security process creation (EventID 4688) in `SecurityEvent` only; public Azure cloud only. Sentinel workspace listing needs extra Azure permissions and falls back to manual entry.
* Shakedown cannot revoke a token at the provider on disconnect; revoke it there.
* The memory secret store means saved credentials do not survive a restart. Install `keyring` for OS-backed storage; its behaviour on your OS is outside this project's tests.
* One local operator, no accounts, no hosted multi-tenant operation.
* The pySigma Kusto backend is LGPL-3.0 (see `NOTICE`).
