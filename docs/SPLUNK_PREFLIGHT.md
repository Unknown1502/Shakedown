# Splunk read-only preflight

Run a Sigma rule as a bounded historical search in your Splunk and see what it would have matched.

## Status: **implemented but not live-verified**

The connector is covered by 47 tests, **all against a mock server** (`tests/fake_splunk.py`) that speaks the REST shapes over real HTTP. That tests request building, authentication headers, JSON handling, polling, cancellation, error classes and the read-only guarantees. It is not proof that the connector works against a real Splunk. No Splunk instance or credentials were available when this was built.

It becomes "live-verified" only when `tools/splunk_smoke.py` succeeds against an instance you are authorised to search. That run writes `evidence/splunk_live_verification.json`; until it exists every packet says "implemented but not live-verified".

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
   with only the `search` capability.
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

You can check the connector without touching production by running a throwaway Splunk Enterprise container. Starting it means **you** accept Splunk's licence terms, which is why I did not do it for you:

```bash
docker run -d --name splunk-test -p 8000:8000 -p 8089:8089 -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_START_ARGS=--accept-license -e SPLUNK_PASSWORD='<choose a password>' splunk/splunk:latest
# create an index named win_sysmon and a token, put SPLUNK_BASE_URL=http://127.0.0.1:8089 SPLUNK_TOKEN=... in .env
python tools/splunk_smoke.py --index win_sysmon
```

An empty index is enough for the smoke test: it proves authentication, the capability read, the job lifecycle and cleanup. To exercise matching you would also ingest some Sysmon-style events with the right `source` and `EventCode`. A pass on a loopback test instance is recorded as such (`target_is_loopback`), and is real evidence about the connector, not about your production environment.
