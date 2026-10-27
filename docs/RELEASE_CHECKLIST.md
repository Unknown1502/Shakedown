# Release checklist (feature freeze, 2026-10-27)

Every line is **PASS**, **FAIL** or **NOT VERIFIED**, with the file or command behind it. PASS means I ran the check on the final tree and saw the result. FAIL means a required item is missing or broken. NOT VERIFIED means it cannot be checked from here or was not run. Nothing was pushed, published, deployed, sent or submitted; the repository has no remote.

Release checkpoint: local commit `a918a26` on `main` (167 files). Deadline: Friday 2026-10-30, 10:00 am PT = 22:30 IST.

## 1. Scope freeze

| Item | Status | Evidence |
|---|---|---|
| No new integrations or features after the preflight slice | PASS | The only code change in this pass is `tools/secret_scan.py` (`--root`). Everything else is documentation and `.gitattributes` |
| Frozen benchmark untouched | PASS | `sha256sum evaluation/tasks.json evaluation/tasks_confirmatory.json` begins `ec9443c87f48e62f` and `84e00aa8c4fffb52` in the working tree and in a fresh clone; `python tools/results_table.py` regenerates `docs/RESULTS_TABLE.md` with identical content |

## 2. Checks on the final tree

| Item | Status | Evidence |
|---|---|---|
| Regression suite | PASS | `uv run pytest -q`: **244 passed** |
| Clean clone, install from lockfile, tests | PASS | `git clone` of `a918a26`, `uv sync --frozen`, `uv run pytest -q`: **238 passed, 6 skipped** (the 6 need datasets or Docker) = 244 |
| Secret scan, working tree | PASS | `python tools/secret_scan.py`: 166 files against 3 credential values, clean |
| Secret scan, the published tree | PASS | `python tools/secret_scan.py --root <clone>`: 165 files, clean |
| Repository hygiene | PASS | 167 tracked files, 5 MB; no `.env`, `data/`, `.aqg/`, `.venv/`, EVTX, archive or executable tracked; the only binaries are two screenshots; `.env.example` and `LICENSE` tracked |
| Frozen artefacts byte-for-byte in git | PASS | `.gitattributes` stores `evaluation/*.json`, `evidence/**`, `demo/**` and `docs/RESULTS_TABLE.md` without line-ending conversion; `git ls-files --eol` shows `attr/-text`; hashes match in the clone |
| Relative links in committed docs | PASS | 45 relative links checked in the clone, 0 broken |
| Container image reflects the final code | NOT VERIFIED | The image `shakedown:audit` was built and passed 23 of 23 smoke checks **before** the preflight slice and was not rebuilt. Rebuild and rerun `tools/smoke_hosted.py --run` before deploying |
| External cross-model audit of the preflight slice | NOT VERIFIED | The AQG policy rates credentials, SPL execution and customer-log handling as high-sensitivity. I ran adversarial tests and an import-isolation check but **did not run the external `/audit`**. Say so if asked, or run it |

## 3. Documentation and submission copy

| Item | Status | Evidence |
|---|---|---|
| Bring-your-own logs described as implemented and exercised with public lab data | PASS | `docs/BRING_YOUR_OWN_LOGS.md` ("What was run"), `README.md`, `docs/DEVPOST_SUBMISSION.md`; run record in `evidence/preflight_demo/public_lab_data/` |
| Splunk labelled implemented but not live-verified, wherever it appears | PASS | grep of README, Devpost draft, status, limitations, risks, guides: no unlabelled claim; `shakedown.splunk.live_verification()` returns "implemented but not live-verified" because `evidence/splunk_live_verification.json` does not exist |
| Mock tests never described as proof of a real Splunk integration | PASS | `docs/SPLUNK_PREFLIGHT.md` ("all against a mock server"), `tests/fake_splunk.py` and `tests/test_splunk.py` headers, `docs/LIMITATIONS.md` |
| Lab evaluation not represented as customer-environment validation | PASS | Three-status design (`shakedown/assess.py`, `tests/test_assess.py`); BYO guide and Devpost draft say the public data stands in and is not customer validation |
| Frozen benchmark metrics, methodology and limitations preserved | PASS | `docs/RESULTS_TABLE.md`, `docs/EVALUATION_METHODOLOGY.md`, `docs/LIMITATIONS.md`; Run 8 stated as 7 of 19 first attempt and 14 of 20 after repair counting the errored task as a miss |
| Contradictions found and fixed in this pass | PASS | `docs/DATASET_AUDIT.md` said the paired attack sample is never shown during repair (it is, when the first rule missed it); stale test counts; "byte for byte" claims true only on one platform; "interactive" run time claim; hosting caps in the Devpost text |
| Devpost draft cross-checked against the evidence | PASS | Numbers match `docs/RESULTS_TABLE.md` and `docs/DEMO_DECISION.md`; model id, Sandboxes, Tavily roles and limits stated; bonus rule (one bonus only) stated |
| Tavily bonus eligibility | PASS | A functional runtime call is in every live run record (`research` block with URL and retrieval time, e.g. `demo/replay/pua-adfind-exe-execution.json`); the rules text is quoted in `docs/SUBMISSION_CHECKLIST.md`. Whether it improves rules is **not shown** and not claimed |
| Feedback requirement | PASS | `docs/FEEDBACK.md` (9 items, each measured); it is also a required form field |
| Official requirements re-read | PASS (2026-10-27) | Rules, judging update and FAQ read through Tavily. Re-read the rules on the day you submit; I cannot see later changes |

## 4. Licences, attribution, labels, warnings

| Item | Status | Evidence |
|---|---|---|
| Project licence | PASS | `LICENSE` (Apache-2.0), `pyproject.toml` |
| Third-party licences listed | PASS | `NOTICE`: SigmaHQ rules (DRL 1.1, with the licence link), regression data and baselines (fetched, not redistributed), sigma-cli, pySigma and pysigma-backend-splunk (LGPL, unmodified, not redistributed), the other dependencies |
| Evaluator binary licence | PASS, residual risk documented | Unclear and unresolvable from here (`docs/DATASET_AUDIT.md`); used as is, fetched at run time with a pinned hash, never redistributed |
| Dataset sample labels | PASS | `docs/DATASET_AUDIT.md` "Label provenance"; supplied-evidence labels recorded by `shakedown/byo.py` |
| Historical recording warnings | PASS | `demo/README.md`, the `answer_screen_legacy` label in the UI (`tests/test_server_legacy_screen.py`), README, `evidence/leakage_audit/REPORT.md` |

## 5. Demo and recording

| Item | Status | Evidence |
|---|---|---|
| Demo script built on the screened AdFind scenario and labelled repair evidence | PASS | `docs/DEMO_SCRIPT.md`: 310 words, 104 to 136 words a minute in every segment, spoken numbers checked against the replay records. **The file exists locally and is not in the commit** (at your instruction) |
| Recording plan | PASS | The runbook and capture list in the same file |
| Video recorded and uploaded | FAIL | Not recorded. Needs you and your approval |

## 6. Hosting

| Item | Status | Evidence |
|---|---|---|
| Spending cap reassessed against "free of charge and without any restriction" | PASS | `docs/HOSTING_ALTERNATIVES.md`: six options with compliance risk and worst-case cost; recommendation and wording to use |
| Cost figures | PASS for model and Tavily; NOT VERIFIED for Sandboxes after the beta | Two metered runs ($0.0088, $0.0113); Tavily docs quote; Sandboxes pricing not confirmed for December |
| Hosted demo exists and passes the smoke test | FAIL | Nothing is deployed (not authorised). `tools/smoke_hosted.py` is ready |

## 7. Submission items that do not exist yet

| Item | Status |
|---|---|
| Public repository | FAIL (not created; local commit only) |
| Splunk connector verified against a real instance | NOT VERIFIED (no instance or credentials; `tools/splunk_smoke.py` is ready) |
| First-time judge has used the UI unaided | NOT VERIFIED |
| Sandbox pricing in December | NOT VERIFIED |
| "What was built during the hackathon" confirmed by you | NOT VERIFIED (placeholder in the Devpost draft) |
| Explicit authorisation to publish, deploy or submit | NOT GIVEN |

## Reproduce the checks

```bash
uv run pytest -q
python tools/secret_scan.py
git clone . /tmp/clone && (cd /tmp/clone && uv sync --frozen && uv run pytest -q) && python tools/secret_scan.py --root /tmp/clone
sha256sum evaluation/tasks.json evaluation/tasks_confirmatory.json
python tools/results_table.py && git diff --stat docs/RESULTS_TABLE.md
```
