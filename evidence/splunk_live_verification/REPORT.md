# Splunk live verification report

Date: 2026-10-27. Subject: the read-only Splunk preflight connector (`shakedown/splunk.py`) and `python -m shakedown.assess --splunk`.

## Verdict

**Live-verified on a throwaway local test instance, not on a production Splunk.** A real Splunk Enterprise **10.6.1.1** (build `b2ae2962645c`, trial licence) executed the connector's actual Sigma-converted query against controlled, labelled events, and every observed count matched the expectation. The label the product now shows is "live-verified on a loopback test instance". This is evidence about the connector. It says nothing about any production Splunk, any real Sysmon add-on, or detection accuracy.

## The instance

| Item | Observed |
|---|---|
| Image | `splunk/splunk:latest`, digest `sha256:2a7cf9d2e8a2226773a9fac95b5e0e2cc8752496abfb134a21bdf8f67c9ee44d`, created 2026-10-19 |
| Version | Splunk Enterprise 10.6.1.1, build `b2ae2962645c`, Linux x86_64, `product_type enterprise`, licence state OK, group Trial (read by the admin account, which was used only to provision and to read ground truth) |
| Terms | The owner confirmed on 2026-10-27 that they had reviewed and accepted Splunk's General Terms and licence; the container was started with the acceptance flags only after that |
| Started / ready | Container started 15:24:46 UTC; Docker health `healthy` at about 15:25:45 UTC; the management API answered; provisioning log recap `ok=89 changed=10 failed=0`, "Ansible playbook complete" |
| Network exposure | `8000` and `8089` bound to `127.0.0.1:18000` and `127.0.0.1:18089` only; connecting to the machine's LAN address on both ports was refused |
| Other containers | 11 unrelated containers were listed and left alone; Splunk uses different host ports from the exited containers that map 8000 |
| Secrets | A random 26 character admin password and random account passwords and token live in `data/splunk_live/` (gitignored), were never printed, and are not in any evidence file (checked by comparing every evidence file with every secret value) |

## Accounts and permissions

| Account | Role capabilities (read back from Splunk) | Purpose |
|---|---|---|
| `shakedown_svc` | exactly `search`; indexes `shakedown_test` and `shakedown_bulk` only; 2 concurrent jobs; 7 day time window | the account the connector uses (token and basic auth both tested) |
| `shakedown_noperm` | none | negative test: no search permission |
| `shakedown_overpriv` | `search`, `admin_all_objects` | negative test: admin-class account |
| `admin` | all | provisioning and ground truth only; never given to the connector |

**Finding from this run.** Splunk 10.6.1.1 silently adds `edit_own_objects`, `list_all_objects`, `run_collect`, `run_mcollect` and `schedule_rtsearch` to every new role, including one meant to hold only `search`. Updating the role with `capabilities=search` replaces the list. The connector now warns about write-capable extras, and `docs/SPLUNK_PREFLIGHT.md` tells operators to trim the role and read back what the account holds.

## The controlled test data

Eight labelled events in `shakedown_test` plus one in `shakedown_other` (`seed_manifest.json`), indexed as `<timestamp> key="value" ...` raw text so that Splunk's default key=value extraction produces the fields; `source` was set explicitly. **This simulates Sysmon field extraction. It is not the Splunk Add-on for Sysmon or for Windows.** Ground truth, read from Splunk itself as admin: `shakedown_test` holds 5 Sysmon `EventCode=1` events (one of them 3 days old), 1 Sysmon `EventCode=3` and 1 `XmlWinEventLog:Security` event; `shakedown_other` holds 1.

| Label | Purpose | Expected |
|---|---|---|
| `match_1`, `match_2` | AdFind executions on `LAB-W10-01` and `LAB-W10-02` | match the AdFind rule |
| `unrelated_1` (notepad), `unrelated_2` (cmd) | in scope, unrelated | no match for the AdFind rule |
| `decoy_wrong_eventcode` | right content, `EventCode=3` | excluded by the EventCode scope |
| `decoy_wrong_source` | right content and EventCode, source `Security` | excluded by the source scope |
| `decoy_outside_window` | right content, 3 days old | excluded by a 6 hour window |
| `decoy_other_index` | right content, in `shakedown_other` | never visible to the account |

Plus 300,000 filler events in `shakedown_bulk`, used only to make a real search run long enough to time out.

## Smoke test (the project's own `tools/splunk_smoke.py`)

```
authenticated as shakedown_svc (roles ['shakedown_preflight']); capabilities known: True
coverage search ran in 1.11 s: 4 Sysmon process-creation events in shakedown_test in the last 360 minutes
OK. Verification recorded in evidence/splunk_live_verification.json
```

It was first run with `--no-record` (same result, 4 events), and recorded only after the end-to-end tests below had passed. The proof file holds the check list, `target_is_loopback: true`, `tls_verified: false`, and the operator-supplied version; it holds no credential.

## End-to-end: the actual Shakedown query on real Splunk

Rule: the generated AdFind rule from `demo/replay/pua-adfind-exe-execution.json`, converted by the Sigma CLI (`sigma convert -t splunk -p splunk_windows`). Window: last 6 hours. Index scope: `shakedown_test`. Queries run (no credentials appear in them):

```
coverage : search (index="shakedown_test") source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 | stats count min(_time) as first max(_time) as last
fields   : search (index="shakedown_test") source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 | head 1000 | fieldsummary maxvals=1 | fields field
detection: search (index="shakedown_test") source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (OriginalFileName="AdFind.exe" CommandLine IN ("*parentrdn*", "*objrdn*", "*-dechextosid*", "*-encguidtoiid*", "*-showdel*", "*-sdna*", "*-nosacl*", "*-f*")) | stats count
sample   : ... | head 5 | table _time, host, source, EventCode, User, ParentImage, CommandLine, OriginalFileName
```

| Check | Expected | Observed | Result |
|---|---|---|---|
| Events in scope (source + EventCode 1, 6 h) | 4 | 4 | PASS |
| AdFind rule matches | 2 (`LAB-W10-01`, `LAB-W10-02`) | 2 (`LAB-W10-01`, `LAB-W10-02`) | PASS |
| Same detection written by hand in SPL (not from Sigma), run by Splunk as admin | 2, one per host | 2, one per host | PASS (independent agreement) |
| Notepad rule matches | 1 (`LAB-W10-01`) | 1 (`LAB-W10-01`) | PASS |
| A rule for a tool that is not present | 0 matches, 4 events in scope | 0, 4 | PASS |
| Rule fields observed in Splunk | none missing | none missing | PASS |
| Without the scope, the same detection over 6 h | (4: includes the two decoys) | 4 | shows the scope removes 2 |
| With the source and EventCode scope, 6 h | 2 | 2 | PASS |
| Without the scope, over 7 days | (5: adds the old event) | 5 | shows the window matters |
| With the scope, over 7 days | 3 | 3 | PASS |
| `shakedown_other`: event exists (admin) vs visible to the account | 1 vs 0 | 1 vs 0 | PASS |
| Client-side allowlist refuses an index not on the list | refused before any request | `scope` error | PASS |
| `assess --splunk` command, valid rule | status potential matches, 2 | `potential_matches_found`, 2; rule validity valid; attack validation not run; recommendation "needs more evidence" | PASS |
| Basic authentication reaches the same answer | 2 matches, 4 in scope | 2, 4 | PASS |
| Search jobs left on the server after normal runs | 0 | 0 | PASS |

Packet from the real run: `evidence/splunk_live_verification/packet_adfind_matches/`. Every number above is recorded by `tests/live/test_splunk_live.py` in `live_results.json`.

## Negative tests (real Splunk, real errors)

| Case | Observed | Named correctly |
|---|---|---|
| Wrong token | HTTP 401 | `auth` |
| Wrong password | HTTP 401 | `auth` |
| Account without search capability | HTTP 403 on creating the search | `permission` |
| Admin-class account | refused before any search | `privileged_account` |
| Malformed SPL | Splunk's own "The expression is malformed. Expected )." | `query` |
| Write command (`outputlookup`) | refused locally; no job created (0 jobs on the server) | `unsafe_query` |
| Index the account may not read | zero events, no error from Splunk | `telemetry_missing_or_unsupported` (see limitation) |
| Registry rule, no registry events | 0 events in scope | `no_events_in_scope`, not "no matches" |
| Rule field that never occurs | `NoSuchField` missing; 4 events in scope | `fields_not_observed`, a different state |
| Splunk's default certificate, verification on | "IP address mismatch, certificate is not valid for '127.0.0.1'" | `tls`, with the remedy |
| Search that outlives a 1 s timeout (a 3.0 s `regex` over 300,000 events) | returned after 1.1 s | `timeout`; 0 jobs left on the server |
| Cancel requested at 1 s | returned after 1.1 s | `cancelled`; 0 jobs left on the server |

An earlier attempt to test the timeout with a trivially fast search did **not** time out (Splunk finished first); that attempt proved nothing and was replaced by the 300,000 event search. Splunk also caps `makeresults` at 50,000 rows, so a generating command could not be used.

## Defects the live run found (all fixed, each with a mock-level regression test)

1. New Splunk roles carry write-capable default capabilities; the connector now warns and the guide says to trim them.
2. A TLS certificate failure was reported as "cannot reach Splunk"; it is now a named `tls` error with the remedy.
3. A missing Sigma CLI escaped as a raw `RuntimeError`; it is now a named `conversion` error.
4. My provisioning script assumed a missing user returns 404; Splunk returns 400 "does not exist".

## Limitations that remain

- **One throwaway instance, one version** (Splunk Enterprise 10.6.1.1, trial licence, single node, Docker, loopback). Not Splunk Cloud, not a cluster, not LDAP or SAML, not a production deployment.
- **Simulated Sysmon.** Events are key=value text with an assigned `source`. A real Splunk Add-on for Windows or Sysmon may name or parse fields differently, which is the main reason a rule can match nothing in a real environment. The connector's field check exists for that, but it was not exercised against a real add-on.
- **TLS verification was exercised only on its failure path.** The main run used `SPLUNK_VERIFY_TLS=false` (recorded as `tls_verified: false`). A successful verified connection needs a certificate that names the host; not tested.
- **An unreadable index looks the same as an empty one.** Splunk returns zero events either way, so "telemetry missing" can also mean "this account may not read that index". The connector's wording allows for it; it cannot tell the cases apart.
- **Scale and concurrency untested**: 8 labelled events and 300,000 filler events, one search at a time. The role's job quota (2) and disk quota were set but not exercised.
- **Capabilities are read from `current-context`**, which is what Splunk reports; the connector cannot prove the account is truly read-only beyond that and its own endpoint and command allowlists. Not tested: that the account is *unable* to create a saved search.
- Real-time searches, `tstats`, data models and CIM mappings are not used or tested.
- The trial licence expires in 60 days; the container is a test fixture.

## Live tests are separate from mocked tests

`tests/live/test_splunk_live.py` (11 tests, marker `live`, needs `SPLUNK_LIVE_TEST=1`, deselected by default). The mocked connector tests are `tests/test_splunk*.py` and use `tests/fake_splunk.py`. Reproduce:

```bash
python tools/splunk_live_setup.py --admin-password-file data/splunk_live/admin.pw --bulk 300000   # once, on a fresh container
set -a; . data/splunk_live/splunk.env; . data/splunk_live/accounts.env; set +a
python tools/splunk_smoke.py --index shakedown_test --minutes 360 --server-version <version>
SPLUNK_LIVE_TEST=1 uv run pytest tests/live -m live -q
```

## Stop and cleanup (run these yourself when you are done; nothing was deleted)

```bash
docker stop shakedown-splunk-test            # stop it; data stays inside the container
docker start shakedown-splunk-test           # resume it later
docker rm -f shakedown-splunk-test           # delete the container and everything indexed in it
docker rmi splunk/splunk:latest              # optional: remove the image
# local secrets (admin password, account passwords, token, CA copy); delete when finished:
rm -rf data/splunk_live
```
Removing `evidence/splunk_live_verification.json` returns the product to "implemented but not live-verified".
