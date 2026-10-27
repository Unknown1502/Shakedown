# Shakedown status

**Latest (2026-10-27, late evening IST): TECHNICALLY READY, SUBMISSION INCOMPLETE.** Gate-by-gate status: [SUBMISSION_CHECKLIST.md](SUBMISSION_CHECKLIST.md). Risks: [RISK_REGISTER.md](RISK_REGISTER.md). Scorecard: [RUBRIC_SCORECARD.md](RUBRIC_SCORECARD.md). Deadline Fri 2026-10-30 10:00 am PT = 22:30 IST.

## Update 2026-10-27, real-world preflight slice

- **Built:** `shakedown.byo` (bring your own EVTX logs on the existing evaluator), `shakedown.splunk` (read-only Splunk preflight), `shakedown.assess` (three independent verdicts, review packet, `python -m shakedown.assess`). Guides: [BRING_YOUR_OWN_LOGS.md](BRING_YOUR_OWN_LOGS.md), [SPLUNK_PREFLIGHT.md](SPLUNK_PREFLIGHT.md). **244 tests pass** (145 before).
- **Verified for real:** the CLI on real EVTX files through the real local Docker checker (public lab data standing in for supplied evidence): valid rule, attack evidence detected 1 of 1, 0 matching events in 352 benign files, 54 s (`evidence/preflight_demo/public_lab_data/`). The sigma CLI converting two real generated rules to SPL.
- **Splunk: live-verified on a throwaway local Splunk Enterprise 10.6.1.1 instance (controlled, simulated Sysmon events); not verified against a production Splunk or a real Sysmon add-on.** The first version of this note said no instance was available; on 2026-10-27 a real Splunk Enterprise 10.6.1.1 container ran the connector's actual query and every count matched. Report: [evidence/splunk_live_verification/REPORT.md](../evidence/splunk_live_verification/REPORT.md). The live run also found and fixed four defects.
- The frozen benchmark is untouched (the results table regenerates with identical content (line endings aside); task-list hashes unchanged). No model call or customer-data path exists in this slice (a clean import loads no model-side module).
- No UI for this slice, deliberately: the hosted demo must not accept customer logs or SIEM credentials.

## Update 2026-10-27, after the leakage audit

- **Audit done** ([evidence/leakage_audit/REPORT.md](../evidence/leakage_audit/REPORT.md)). The frozen benchmark never used web research and is unchanged (the results table regenerates with identical content (line endings aside)). The PowerShell Child Processes recording was contaminated and is no longer a default or evidence.
- **Demo decided** ([DEMO_DECISION.md](DEMO_DECISION.md)): live "PUA - AdFind.EXE Execution" (6 of 6 leakage-controlled runs passed, zero held-out benign events), a recorded repair trace, and a recorded failure. 10 leakage-controlled demo-candidate runs are all kept.
- **Code:** answer-source screening, `LeakGuard`, neutral attack-file labels in feedback and checker errors, default research from the scenario's own reference, token metering, spec-extraction retry, persistent caps and a total cap, proxy-header and custom-URL controls, `tools/fetch_data.py`, `tools/smoke_hosted.py`, `Dockerfile`. **145 tests pass** (103 before the audit).
- **Hosting prepared, not deployed** ([HOSTING_PLAN.md](HOSTING_PLAN.md)): a container built from the repository passed 23 of 23 acceptance checks including a live run; cost per run about $0.01 measured on two metered runs, planning figure $0.05.
- **Docs rebuilt:** README, DEMO_SCRIPT (2:40, with capture checklist), DEVPOST_SUBMISSION draft, FEEDBACK (one item added), LIMITATIONS, METHODOLOGY, DECISIONS (D14 to D20).

## Needs you

Create the public repository (after `tools/secret_scan.py`), approve and choose hosting, record and upload the video, approve the Devpost submission. Nothing external was done.

---

Last updated: 2026-10-26, about 21:15 IST. Deadline: 2026-10-30, 10:00 PDT (22:30 IST).

## Phase 0: repository and research audit (done)

- **Workspace.** The folder held no code, no git repository and no secrets. `hackathon-strategy-report.md` (written earlier in this session) and the two PDFs are no longer in the folder. The PDFs are on the Desktop; the report was not found in OneDrive, Downloads or Documents. Its content is known from the session, and every claim this phase relies on was re-verified from primary sources below rather than taken from the report.
- **Official rules.** Checked 2026-10-26 on the Devpost rules, FAQ and judging-update pages:
  - a runtime call to Token Factory plus an NVIDIA open model;
  - Coding track text: "agents that write, run, and test code in Token Factory";
  - four equally weighted criteria after a pass/fail fit check;
  - the demo must stay available until Dec 15.
- **Dataset claims re-verified.** See [DATASET_AUDIT.md](DATASET_AUDIT.md).
  - "472 pairs" is the `info.yml` count. **470 are usable**; 2 have problems.
  - The report said "269 process_creation" by folder. By rule logsource it is **283**.
  - Benign baselines exist (Apache-2.0) and are exactly what SigmaHQ's own goodlog CI uses.
  - **41** usable rules are dated 2026.

## Phase 1: feasibility gate

| Check | Result | Evidence |
|---|---|---|
| 1A `NEBIUS_API_KEY` in this environment | **absent. Blocked** | `env` presence check (value never read) |
| 1A model listing, selection and one structured call | **not run.** Tool ready | `tools/smoke_nebius.py` exits 2 without a key |
| 1B Sandboxes tooling | `contree-cli` 0.9.4 and `contree-sdk` 0.3.6 exist on PyPI (Apache-2.0). `contree auth` reads `NEBIUS_API_KEY` and `NEBIUS_AI_PROJECT`; `contree auth ls` lists profiles. **Correct per docs and `--help`** | `uvx --from contree-cli==0.9.4 contree auth --help` |
| 1B Sandboxes auth, activation and harmless run | **not run. Blocked** on `NEBIUS_API_KEY` and `NEBIUS_PROJECT_ID` | `tools/smoke_nebius.py` |
| Sandboxes limits (docs) | Beta; 50 simultaneous operations; VM per operation; `networking.enabled=false` supported; stdout 1 MiB by default, 10 MiB max; images kept 180 days; **pricing not documented** | docs.tokenfactory.nebius.com/sandboxes |
| 1C evaluator (local, isolated Docker; **not** a Token Factory Sandbox) | **PASS.** 470/470 reference rules reproduce SigmaHQ ground truth. The reference rule makes 0 hits on the Win10 benign baseline | `tests/test_checker.py`, `tools/reference_parity.py` |
| 1C validator | **PASS.** `sigma check`: a valid rule exits 0; an undefined condition reference exits 1; a bogus modifier exits 1. Malformed YAML **crashes** sigma-cli, so we must parse it first | manual spike, recorded in DECISIONS D8 |
| 1C model-generated rule | **not run.** Blocked on the key | — |
| Tavily | `TAVILY_API_KEY` absent; `tavily-python` 0.8.5 exists on PyPI | — |

**Tests:** `uv run pytest`: 7 passed (3 harness, including 2 Docker integration; 4 model selection). `compileall` clean.

**Gate decision: CONDITIONAL GO.**
- **Unblocked:** data, evaluator and validator, which are the highest-risk technical parts.
- **Blocked, needing you:** model inference and the Token Factory Sandbox route.
- **If Sandboxes come back `inactive`:** activation goes through contree@nebius.com, which I will not contact without your authorisation. Development continues on the isolated local runner, and the docs will say so plainly.

## Update 2026-10-26 evening: smoke test with real credentials

- Token Factory: key and project ID work. 30 models listed, 5 NVIDIA. `nvidia/nemotron-3-super-120b-a12b` returned schema-valid JSON through the OpenAI-style `json_schema` format in 4.9 s (144 of 159 output tokens were reasoning). Evidence: `data/audit/smoke.json`.
- Sandboxes: **inactive**. Every permission in `/whoami` is false and a run raises `ForbiddenError`. The Sandboxes product page says access is by "request beta access". It also says runs are **free during the beta** (they do not consume credits) and warns against uploading personal or sensitive data. Waiting on the user to request access.
- Tavily key loads from `.env`; live call not yet tested.

## What I needed from you (original)

1. **Create keys:**
   - a Token Factory API key (https://tokenfactory.nebius.com/project/api-keys);
   - the **project ID** (Project settings);
   - optionally a Tavily key.
2. **Run the smoke test in your own PowerShell window**, so the key never enters chat or shell history:

```powershell
cd "C:\Users\prajw\OneDrive\Desktop\Nebius x NVIDIA Global AI Hackathon"
$s = Read-Host "Nebius API key" -AsSecureString
$env:NEBIUS_API_KEY = [System.Net.NetworkCredential]::new("", $s).Password
$env:NEBIUS_PROJECT_ID = Read-Host "Nebius project ID"
uv run python tools/smoke_nebius.py
```

   It writes `data/audit/smoke.json` (no credentials inside). Tell me when it's done and I'll read it.

3. **To let me run live calls myself:** set them as user environment variables (`[Environment]::SetEnvironmentVariable("NEBIUS_API_KEY", <value>, "User")`, same for `NEBIUS_PROJECT_ID`) and restart VS Code. My tools only see variables present when VS Code starts.

## Credit and cost so far

$0. No paid API calls have been made.

## Next concrete actions

1. After the smoke test: confirm the model ID, the JSON format and Sandboxes status. Then build the Sandboxes evaluator image:
   - a setup operation, with the network on, downloads the pinned checker, `thor.yml` and fixtures and verifies their sha256;
   - the result is saved and tagged;
   - each evaluation runs from it with `networking.enabled=false`.
2. Phase 2 vertical slice: one threat report → typed spec → Nemotron rule → `sigma check` → evaluator on 1 positive and the benign split → JSON report.

## Update 2026-10-27 afternoon (IST)

**Built and tested (86 tests pass):** isolated evaluator, validator, spec extraction with grounding, structured rule renderer, bounded repair loop (with resampling of empty model answers and recovery from rules the evaluator cannot load), Tavily client (live-verified: extract and search), pipeline, scenario loader, budget guard, FastAPI server, web UI (replay of recorded runs works; live mode needs `--live`, credentials, Docker and the datasets).

**Evaluation:** five batch runs on the 20 frozen tasks; table in `docs/RESULTS_TABLE.md` (generated by `tools/results_table.py`), method and every deviation in `docs/EVALUATION_METHODOLOGY.md`. Summary: one-shot detects 3 to 7 of about 20; after repair 7 to 13; SigmaHQ expert rules detect all. No configuration clearly beats the others given run-to-run noise.

**Recorded demo runs:** `demo/recorded/*.json` are unedited live runs (Nemotron + Tavily + isolated evaluator). Chosen after seeing earlier results; the UI says so.

**Still blocked:** Token Factory Sandboxes. `tools/smoke_nebius.py` still reports all permissions false (last checked 2026-10-27 12:30 IST). Everything runs on the local isolated Docker runner, which is not a Token Factory Sandbox.

**Still to do:** README, ARCHITECTURE, LIMITATIONS, DEMO_SCRIPT, SUBMISSION_CHECKLIST, feedback text; hosted demo and its credit guard; demo video; public repo and licence; Sandboxes switch if access arrives.

## Update 2026-10-27 evening (IST): Sandboxes unblocked, evaluation finished

**Sandboxes: working.** Access arrived between 12:30 and about 14:20 IST. The evaluator now runs in a Token Factory Sandbox (`shakedown/harness/sandbox.py`, decisions D9 to D13): one immutable image (`shakedown-eval:v1`, UUID in `evidence/audit/sandbox_image.json`) holds the checker, `thor.yml` and both benign baselines; each evaluation is a disposable microVM with `networking.enabled=false` (verified from inside the VM). Parity with the local runner: 30 of 30 random reference rules agree (`evidence/audit/sandbox_parity.json`).

**Evaluation (Runs 6 to 9, all Sandbox).** Confirmatory set of 20 new tasks (10 dated 2026), frozen before any run: first attempt 6 to 7 of 20, after repair 14 of 20 in both runs, expert 20 of 20, held-out false positives in 1 rule (1 to 2 events). The last-resort thinking-off fallback made no measurable difference. Everything, including the one errored task and the post-hoc fix, is in `docs/EVALUATION_METHODOLOGY.md` and `docs/RESULTS_TABLE.md`.

**Demo recordings** were redone on the Sandbox: PowerShell Child Processes passed (2 attempts), AdFind passed (2), Copy From VolumeShadowCopy did not pass (4). The earlier local-runner recordings are in `demo/recorded_local/`.

**Docs written:** README, ARCHITECTURE, LIMITATIONS, DEMO_SCRIPT, SUBMISSION_CHECKLIST, FEEDBACK, NOTICE, LICENSE (Apache-2.0). **Tests:** 103 pass.

**Left for you** (nothing below was done, by design): create the public repository and push; record and upload the video; decide hosting (replay mode recommended); submit on Devpost with the feedback text. See `docs/SUBMISSION_CHECKLIST.md`.
