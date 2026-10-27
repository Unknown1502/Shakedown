# Release checklist (feature freeze, updated after the live Splunk verification, 2026-10-27)

Every line is **PASS**, **FAIL** or **NOT VERIFIED**, with the file or command behind it. PASS means I ran the check on the final tree and saw the result. FAIL means a required item is missing or broken. NOT VERIFIED means it cannot be checked from here or was not run. Nothing was pushed, published, deployed, sent or submitted; the repository has no remote.

Local commits so far: `a918a26` (release checkpoint), `9f10553` (first checklist, tagged `release-candidate-1`), then the Splunk live-verification commits (see `git log`). The tag was not moved. Deadline: Friday 2026-10-30, 10:00 am PT = 22:30 IST.

## Precise status of the Splunk connector

> **Live-verified on a loopback Splunk Enterprise 10.6.1.1 test instance using simulated Sysmon events.**

Not verified: a production, clustered or Splunk Cloud deployment; a real Splunk Add-on for Windows or Sysmon; a connection where TLS verification succeeds; scale and concurrency. Evidence: `evidence/splunk_live_verification/REPORT.md`, `evidence/splunk_live_verification.json`. The 47 mocked connector tests are not proof of a live integration and are described that way everywhere.

## 1. Scope freeze

| Item | Status | Evidence |
|---|---|---|
| No new integrations or features after the preflight slice | PASS | Since the first checkpoint the code changes are the four fixes the live run found in `shakedown/splunk.py` (capability warnings, `tls` error, `conversion` error, loopback label), `tools/splunk_smoke.py` (`--server-version`), `tools/splunk_live_setup.py` and the opt-in live tests. No new connector or feature |
| Frozen benchmark untouched | PASS | `sha256sum evaluation/tasks.json evaluation/tasks_confirmatory.json` begins `ec9443c87f48e62f` and `84e00aa8c4fffb52`; `python tools/results_table.py` regenerates `docs/RESULTS_TABLE.md` **byte-identical**; `git diff -- evaluation evidence/runs evidence/audit docs/RESULTS_TABLE.md docs/EVALUATION_METHODOLOGY.md` is empty |

## 2. Checks on the final tree

| Item | Status | Evidence |
|---|---|---|
| `git status --short` reviewed | PASS | 15 modified and 6 new paths, all intended; no stray file |
| `git diff --check` | PASS | Unstaged: exit 0. Staged: exit 0 after 7 generated evidence files (written by Python on Windows) were normalised from CRLF to LF; their JSON was re-validated |
| Secret scan, working tree | PASS | `python tools/secret_scan.py`: 179 files against 3 credential values, clean |
| Secret scan, the exact staged tree | PASS | `git checkout-index` export, `python tools/secret_scan.py --root <export>`: 178 files, clean |
| Splunk secrets in the new evidence | PASS | The token, 3 account passwords, the admin password and the 3 `.env` values were compared with all 8 files in `evidence/splunk_live_verification*` plus token-shaped patterns (JWT, Bearer, `Splunk <token>`, private keys, `password=`): no findings |
| Default test suite | PASS | `uv run pytest -q`: **251 passed**, 11 live tests deselected |
| Clean tree from the staged index, lockfile install | PASS | `uv sync --frozen` then `uv run pytest -q`: **245 passed, 6 skipped** (the 6 need datasets or Docker) = 251; the 11 live tests are inert without the opt-in |
| Live suite against the real Splunk | PASS | `SPLUNK_LIVE_TEST=1 uv run pytest tests/live -m live -q`: **11 passed**, endpoint `https://127.0.0.1:18089`, no reference to the mock in `tests/live`. Splunk's own access log grew by 301 request lines during the run: `shakedown_svc` created 41 search jobs and deleted 41, polled 104 times, read 38 result sets, made 2 cancel calls (the timeout and cancel tests), and read `authentication/current-context` 13 times; no other endpoint was called by the connector |
| Excluded from Git | PASS | `.env`, `data/` (including `data/splunk_live/` and the nested SigmaHQ checkout) and `.vscode/` are ignored (`git check-ignore -v`); 0 staged paths under them; 0 nested-repo links; 0 EVTX, archive, key or executable files staged; `.env.example` is the only `.env*` file tracked |
| Repository hygiene | PASS | 180 tracked files after this checkpoint; two PNG screenshots are the only binaries |
| Relative links in committed docs | PASS | 50 relative links across 26 markdown files, 0 broken |
| Frozen artefacts byte-for-byte in git | PASS | `.gitattributes` stores `evaluation/*.json`, `evidence/**`, `demo/**` and `docs/RESULTS_TABLE.md` without line-ending conversion (`git ls-files --eol` shows `attr/-text`) |
| Existing release tag preserved | PASS | `release-candidate-1` still points at `9f10553` |
| Container image reflects the final code | NOT VERIFIED | `shakedown:audit` was built before the preflight slice and was not rebuilt. Rebuild and rerun `tools/smoke_hosted.py --run` before deploying |
| External cross-model audit of the preflight and Splunk slice | NOT VERIFIED | The AQG policy rates credentials, SPL execution and customer-log handling as high-sensitivity. I ran adversarial tests, an import-isolation check and the live suite, but **did not run the external `/audit`** |

## 3. Documentation and submission copy

| Item | Status | Evidence |
|---|---|---|
| Bring-your-own logs described as implemented and exercised with public lab data | PASS | `docs/BRING_YOUR_OWN_LOGS.md` ("What was run"), `README.md`, `docs/DEVPOST_SUBMISSION.md`; run record in `evidence/preflight_demo/public_lab_data/` |
| Splunk status stated accurately wherever it appears | PASS | README, SPLUNK_PREFLIGHT, LIMITATIONS, STATUS, ARCHITECTURE, DEVPOST, RISK_REGISTER and DECISIONS (D24, D26, D27) say live-verified on a throwaway local instance with simulated events and name what is not verified; `shakedown.splunk.live_verification()` reports "live-verified on a loopback test instance" |
| Mock tests never described as proof of a real Splunk integration | PASS | `docs/SPLUNK_PREFLIGHT.md`, `tests/fake_splunk.py` and `tests/test_splunk*.py` headers, `docs/LIMITATIONS.md`; the live tests are separate (`tests/live/`) |
| Lab and simulated evaluation not represented as customer-environment validation | PASS | Three-status design (`shakedown/assess.py`, `tests/test_assess.py`); BYO guide, Devpost draft and the live report say the data is public or simulated |
| Frozen benchmark metrics, methodology and limitations preserved | PASS | `docs/RESULTS_TABLE.md`, `docs/EVALUATION_METHODOLOGY.md`, `docs/LIMITATIONS.md`; Run 8 stated as 7 of 19 first attempt and 14 of 20 after repair counting the errored task as a miss |
| Contradictions found and fixed | PASS | `docs/DATASET_AUDIT.md` (the paired attack sample is shown during repair; four regression files are missing from this checkout, not upstream); stale test counts; platform-dependent "byte for byte" claims; run-time claim; hosting caps in the Devpost text |
| Devpost draft cross-checked against the evidence | PASS | Numbers match `docs/RESULTS_TABLE.md` and `docs/DEMO_DECISION.md`; model id, Sandboxes, Tavily roles, the Splunk status and limits stated; one-bonus rule stated |
| Tavily bonus eligibility | PASS | A functional runtime call is in every live run record (`research` block with URL and retrieval time, e.g. `demo/replay/pua-adfind-exe-execution.json`); the rules text is quoted in `docs/SUBMISSION_CHECKLIST.md`. Whether it improves rules is **not shown** and not claimed |
| Feedback requirement | PASS | `docs/FEEDBACK.md` (9 items, each measured); it is also a required form field |
| Official requirements re-read | PASS (2026-10-27) | Rules, judging update and FAQ read through Tavily. Re-read the rules on the day you submit |

## 4. Licences, attribution, labels, warnings

| Item | Status | Evidence |
|---|---|---|
| Project licence | PASS | `LICENSE` (Apache-2.0), `pyproject.toml` |
| Third-party licences listed | PASS | `NOTICE`: SigmaHQ rules (DRL 1.1, with the licence link), regression data and baselines (fetched, not redistributed), sigma-cli, pySigma and pysigma-backend-splunk (LGPL, unmodified), the other dependencies, and Splunk Enterprise as a local test fixture only |
| Evaluator binary licence | PASS, residual risk documented | Unclear and unresolvable from here (`docs/DATASET_AUDIT.md`); used as is, fetched at run time with a pinned hash, never redistributed |
| Dataset sample labels | PASS | `docs/DATASET_AUDIT.md` "Label provenance"; supplied-evidence labels recorded by `shakedown/byo.py` |
| Historical recording warnings | PASS | `demo/README.md`, the `answer_screen_legacy` label in the UI (`tests/test_server_legacy_screen.py`), README, `evidence/leakage_audit/REPORT.md` |

## 5. Demo and recording

| Item | Status | Evidence |
|---|---|---|
| Demo script built on the screened AdFind scenario and labelled repair evidence | PASS | `docs/DEMO_SCRIPT.md`: 310 words, 104 to 136 words a minute in every segment, spoken numbers checked against the replay records. Included in the release checkpoint at the owner's instruction |
| Recording plan | PASS | The runbook and capture list in the same file |
| Video recorded and uploaded | FAIL | Not recorded. Needs you and your approval |

## 6. Hosting

| Item | Status | Evidence |
|---|---|---|
| Spending cap reassessed against "free of charge and without any restriction" | PASS | `docs/HOSTING_ALTERNATIVES.md`: six options with compliance risk and worst-case cost; recommendation and wording to use |
| Cost figures | PASS for model and Tavily; NOT VERIFIED for Sandboxes after the beta | Two metered runs ($0.0088, $0.0113); Tavily docs quote; Sandboxes pricing not confirmed for December |
| Hosted demo exists and passes the smoke test | FAIL | Nothing is deployed (not authorised). `tools/smoke_hosted.py` is ready |

## 7. Submission items that do not exist yet or are not verified

| Item | Status |
|---|---|
| Public repository | FAIL (not created; local commits only, no remote) |
| Splunk connector on a loopback test instance with simulated Sysmon events | PASS (11 live tests and the project's smoke test, Splunk Enterprise 10.6.1.1) |
| Splunk connector on a production Splunk, a real Sysmon add-on, or with TLS verification succeeding | NOT VERIFIED |
| First-time judge has used the UI unaided | NOT VERIFIED |
| Sandbox pricing in December | NOT VERIFIED |
| "What was built during the hackathon" confirmed by you | NOT VERIFIED (placeholder in the Devpost draft) |
| Explicit authorisation to publish, deploy or submit | NOT GIVEN |

## Reproduce the checks

```bash
git status --short && git diff --check && git diff --cached --check
python tools/secret_scan.py
uv run pytest -q                                   # 251 passed, 11 deselected
# live (needs the throwaway container from docs/SPLUNK_PREFLIGHT.md):
set -a; . data/splunk_live/splunk.env; . data/splunk_live/accounts.env; set +a
SPLUNK_LIVE_TEST=1 uv run pytest tests/live -m live -q   # 11 passed
git checkout-index -a -f --prefix=/tmp/staged/ && (cd /tmp/staged && uv sync --frozen && uv run pytest -q) && python tools/secret_scan.py --root /tmp/staged
sha256sum evaluation/tasks.json evaluation/tasks_confirmatory.json
python tools/results_table.py && git diff --stat docs/RESULTS_TABLE.md
```
