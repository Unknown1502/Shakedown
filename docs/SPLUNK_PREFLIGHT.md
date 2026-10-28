# Splunk read-only preflight

> The same connector is now also available through the Integrations workspace (`--integrations`), with Elastic and Microsoft Sentinel adapters: see [INTEGRATIONS.md](INTEGRATIONS.md). This page documents the Splunk connector and the command line.

Run a Sigma rule as a bounded historical search in your Splunk and see what it would have matched.

## Status: **live-verified on a throwaway local test instance. Not verified against a production Splunk.**

On 2026-10-27 the project's own smoke test and an 11-test live suite passed against a real **Splunk Enterprise 10.6.1.1** container (single node, trial licence, loopback only). A real Splunk executed the connector's actual Sigma-converted query against 8 labelled events, and every count matched the expectation, including a hand-written SPL cross-check. The full result, the exact queries, the negative tests and the limits are in [`evidence/splunk_live_verification/REPORT.md`](../evidence/splunk_live_verification/REPORT.md).

What that does **not** cover: a production, clustered or Splunk Cloud deployment; a real Splunk Add-on for Windows or Sysmon (the test events are `key="value"` text with an assigned `source`, which only *simulates* Sysmon field extraction, and real field names and parsing may differ); a connection where TLS verification succeeds (Splunk's default certificate does not name `127.0.0.1`, so the main run used `SPLUNK_VERIFY_TLS=false`, which is recorded; the failure path was tested live); scale and concurrency.

Two kinds of tests, kept separate: `tests/test_splunk*.py` run against a **mock** server (`tests/fake_splunk.py`) and are not proof of a live integration; `tests/live/test_splunk_live.py` runs against a real Splunk, only when `SPLUNK_LIVE_TEST=1`. The product reads `evidence/splunk_live_verification.json`; if that file is absent every packet says "implemented but not live-verified", and once present it says "live-verified on a loopback test instance". Run `tools/splunk_smoke.py` against your own instance to establish your own result.

## What you need

1. A Splunk management endpoint (normally `https://host:8089`) and credentials for a **search-only role**. Create an authentication token for it (Settings, Tokens) and use `SPLUNK_TOKEN`. Basic authentication is supported but a token is better.
2. A role limited to the indexes you will allow and with a short time window. As a starting point (check the attribute names against your Splunk version's `authorize.conf` documentation):

   ```
   [role_shakedown_preflight]
   importRoles =
   srchIndexesAllowed = win_sysmon
   srchIndexesDefault = win_sysmon
   srchTimeWin = 604800
   srchJobsQuota = 2
   srchDiskQuota = 100
   ```
   with only the `search` capability. **Check what the account really holds.** Splunk Enterprise 10.6.1.1 adds `edit_own_objects`, `list_all_objects`, `run_collect`, `run_mcollect` and `schedule_rtsearch` to every new role, even one meant to hold only `search`. Updating the role with `capabilities=search` replaces the list. `tools/splunk_smoke.py` prints what the account holds, and the connector warns when write-capable extras are present.
3. The variables in [`.env.example`](../.env.example). `SPLUNK_ALLOWED_INDEXES` is a second, client-side allowlist: the tool refuses an index that is not on it, and refuses `*`.
4. Windows events indexed from Sysmon with Sysmon-style field names (`Image`, `CommandLine`, ...). Windows Security 4688 uses different field names and is reported as unsupported, not mis-queried.

```bash
python tools/splunk_smoke.py --index win_sysmon           # one bounded coverage search; records proof only on success
uv run python -m shakedown.assess --rule rule.yml --splunk --splunk-index win_sysmon --last-hours 24 --out packet/
```

A window is always explicit (`--last-hours N`, or `--earliest` and `--latest`), at most `SPLUNK_MAX_TIME_RANGE_HOURS` (168 by default). There is no default scope and no unbounded search.

## What it does

1. Checks the index and window locally, before any request.
2. Reads `authentication/current-context`. An account with admin-class capabilities (`admin_all_objects`, `edit_user`, `delete_by_keyword`, and similar) is **refused** unless `SPLUNK_ALLOW_PRIVILEGED=true`; unknown capabilities are recorded as a warning.
3. Converts the rule with the Sigma CLI (`sigma convert -t splunk -p splunk_windows`). **That conversion adds no log-source scope** (it does not say `EventCode=1` or a source), so the tool adds an explicit, printed scope: for process creation, `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1`. That scope is an assumption about your indexing; check it.
4. Runs up to four searches, each with a timeout, each cancelled and deleted if it does not finish: a coverage count of events of that log source; a 1,000-event sample of which fields exist (`fieldsummary`); the match count; and up to five matching events (values truncated to 300 characters).
5. Classifies the outcome, **keeping these apart**:

| State | Meaning |
|---|---|
| Potential environment matches found | The search matched events. They are potential matches to review, not confirmed detections or false positives |
| No matches in the selected window | Telemetry exists, the rule's fields were observed, and nothing matched. It does not show the rule can detect an attack that did not occur in the window |
| Required telemetry missing or unsupported | No events of the log source in scope, **or** a field the rule uses never appears. A search over missing telemetry is not a clean result |
| Search failed | Credentials rejected, missing permission, query error, timeout, cancellation or an unreachable server, each named |

## What it will not do

It uses only `authentication/current-context` and the search-job endpoints (create, poll, read results, cancel, delete). Any other path is refused in code before the network, which includes saved searches, alerts, indexes and roles. Every SPL string is checked against a command allowlist (search, where, regex, rex, eval, fields, table, head, dedup, stats, fieldsummary, rename, sort); `outputlookup`, `collect`, `delete`, `sendemail`, `rest`, `script`, `map`, subsearches and macros are refused. It never creates or modifies a saved search, alert or rule. The only thing it creates is its own search job, which it deletes. A search job counts against the account's job quota while it runs.

Results are shown to the analyst in the packet. They are never sent to the model, Tavily or any other service, and importing the preflight does not load the model client (tested). Credentials are read from the environment only and are not in any result, packet or error message (tested). TLS is verified by default; turning it off is recorded.

## Verify it yourself against a local Splunk (your decision)

You can check the connector without touching production by running a throwaway Splunk Enterprise container. Starting it means **you** accept Splunk's licence terms. This is the procedure that produced the report above:

```bash
# the password file is yours; never commit it. Bind to loopback only.
docker run -d --name shakedown-splunk-test --env-file <file with SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com, SPLUNK_START_ARGS=--accept-license, SPLUNK_PASSWORD=...> \
  -p 127.0.0.1:18000:8000 -p 127.0.0.1:18089:8089 splunk/splunk:latest
python tools/splunk_live_setup.py --admin-password-file <password file> --bulk 300000   # indexes, search-only role and user, a token, labelled events
set -a; . data/splunk_live/splunk.env; . data/splunk_live/accounts.env; set +a
python tools/splunk_smoke.py --index shakedown_test --minutes 360 --server-version <version>   # records proof only on success
SPLUNK_LIVE_TEST=1 uv run pytest tests/live -m live -q
```

`tools/splunk_live_setup.py` uses the admin account only to create things; the connector never uses it. An empty index is enough for the smoke test alone; the labelled events are what let the end-to-end tests compare expected and observed counts. A pass on a loopback instance is recorded as such (`target_is_loopback`), and is evidence about the connector, not about your production environment.
