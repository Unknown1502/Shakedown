# Submission checklist and readiness gates

Updated 2026-10-27 (evening). **Deadline: Friday 2026-10-30, 10:00 am Pacific Time = 22:30 IST.** After it, no changes (rules, section 5). Judging 2026-12-01 to 2026-12-15 12:00 pm PT; the project must stay available free of charge and without restriction until then.

## Readiness status: **TECHNICALLY READY, SUBMISSION INCOMPLETE**

The product works end to end on the final code and every engineering and evidence gate below passes. The required public artefacts do not exist yet (repository, hosted demo, video), and each needs your approval. A passing test suite is not what makes this status; the unticked boxes in Gate F are.

Checked = verified on 2026-10-27 with the evidence named. Unchecked = not done.

## Official requirements, verified against the rules (read 2026-10-27 through Tavily; the pages block ordinary fetches)

| Requirement (rules text) | Status |
|---|---|
| "a working software application that runs on either Nebius Token Factory or Nebius AI Cloud and uses at least one NVIDIA open source model"; "runs on" means a runtime call to the Token Factory inference API | Met: `nvidia/nemotron-3-super-120b-a12b` is called through Token Factory on every run |
| Track "Coding and Agentic Engineering: agents that write, run, and test code in Token Factory"; Stage One is a pass/fail check that the project is "a genuine attempt at the track's stated goal" | Met in substance: the agent writes a Sigma rule, runs it in a Token Factory Sandbox against real logs, and repairs it from the results. Judges decide |
| URL to a working demo, hosted application or test build | **Not met yet** (Gate F) |
| Public repository on GitHub, GitLab or Bitbucket with all source, assets and instructions; open-source licence file visible in the About section; README with setup and run guidance | Licence and README are ready locally (Apache-2.0); **repository not created** |
| README highlights how Nemotron was used, where Token Factory accelerated the workflow, other Nebius tools | Done in README ("Where each piece runs") |
| Video under 3 minutes, public on YouTube, no third-party trademarks or copyrighted music | **Not recorded**; script and checklist ready |
| Identify the track; provide feedback on Nebius and NVIDIA tools; explain what was updated if the project predates the period | Track chosen; feedback drafted (`FEEDBACK.md`); the project did not predate the period |
| Free of charge and without restriction for judges until the Judging Period ends | Replay uncapped; live capped (risk R7 in `RISK_REGISTER.md`) |
| One Overall **or** Track award, plus **one** Bonus award | Tavily and Most Valuable Feedback are both bonus awards, so only one can be won. The Tavily integration qualifies on its face: a functional runtime call on every run |
| Deadline | 2026-10-30 10:00 am PT |

## Gates

**Gate A: track eligibility**
- [x] Fits Coding and Agentic Engineering (write, run, test, repair code; see above).
- [x] NVIDIA open-model use is runtime and verified (`nvidia/nemotron-3-super-120b-a12b`; every live run record saved today names it).
- [x] Token Factory integration is real at runtime (`shakedown/llm.py`; token usage metered per run).
- [x] The Sandbox workflow is operational (`evaluator.kind = token-factory-sandbox`, network disabled, image UUID in every record; 23 of 23 smoke checks, including a live run, inside a container built from the repository).

**Gate B: evidence integrity**
- [x] The contaminated PowerShell success is not used as a clean success: not in the default replay folder, labelled in the app, prohibited in `DEMO_DECISION.md`.
- [x] Source exclusion happens before inference (`tests/test_pipeline_leakage.py`: a spy on every model message) with a backstop guard (`LeakGuard`).
- [x] Reference rule ids do not leak through attack file names or repair diagnostics in new runs (tests assert on the serialised messages). Runs 1 to 9 had the file-name channel; disclosed, not re-run.
- [x] Historical benchmark artefacts are unchanged: `tools/results_table.py` regenerates `RESULTS_TABLE.md` with identical content (line endings aside) from `evidence/runs/`. Task lists: `evaluation/tasks.json` sha256 `ec9443c8...d1d0`, `evaluation/tasks_confirmatory.json` sha256 `84e00aa8...1f30`. (There is no git history to prove this; the hashes let you.)
- [x] The AdFind demo has explicit provenance and execution evidence (`docs/DEMO_DECISION.md`, `evidence/demo_decision/`).

**Gate C: engineering quality**
- [x] Rule generation and validation work (`sigma check`).
- [x] Sandbox evaluation works and agrees with the local runner (30 of 30 rules).
- [x] Attack and benign results are calculated by SigmaHQ's checker and code; nothing is model-judged.
- [x] Failure handling is tested (invalid rules, evaluator errors, empty or JSON-less model answers, budget exhaustion, a failed run is never shown as a pass).
- [x] Repair is shown only from genuine traces (`demo/replay/pua-adfind-exe-execution.json`: miss, then repair, then pass).
- [x] Tests: **251 passed** in the project (11 opt-in live Splunk tests deselected); **245 passed, 6 skipped** (dataset or Docker) in a clean export of the staged tree without datasets (103 at the start of the leakage audit, 145 before the real-world preflight slice, 244 before the live Splunk run). See `RELEASE_CHECKLIST.md`.

**Gate D: product experience**
- [x] The workflow is understandable from the first screen (checked by me through screenshots; no outside person has tried it).
- [x] Live and replay are distinct (badge, "No model is running now", source-handling line).
- [x] Results show counts and denominators.
- [x] Failure states are accurate (red cell, hatched invalid attempt, "Did not pass"; server and tests cover errors).
- [ ] A first-time judge has used it unaided. I cannot do this one.
- [x] The primary demo is short and reproducible (146 to 311 s per live run in the logs).

**Gate E: credibility**
- [x] README claims match the result files (numbers regenerated from `evidence/`).
- [x] Dataset provenance and licences documented (`DATASET_AUDIT.md`, `NOTICE`).
- [x] Limitations explicit (`LIMITATIONS.md`, UI limits panel).
- [x] No fabricated results or superiority claims; expert rules win and the docs say so.
- [x] Every video claim maps to an inspectable record (`DEMO_SCRIPT.md` final checks).

**Gate F: submission (needs you)**
- [ ] Public repository created, licence visible in About, README renders.
- [ ] Hosted demo deployed and `tools/smoke_hosted.py` passes against it.
- [ ] Video recorded from the final build, under 3:00, uploaded publicly on YouTube.
- [x] Track and bonus eligibility verified against the rules (one bonus only).
- [x] Feedback drafted (`FEEDBACK.md`).
- [x] Devpost draft complete (`DEVPOST_SUBMISSION.md`).
- [ ] Your final authorisation before anything external.

## Before you publish the repository

1. Run `python tools/secret_scan.py` on the exact tree (last run 2026-10-27: 143 files, clean). It reads your `.env` values and never prints them. Also run gitleaks if you have it. Use separate demo keys for hosting and rotate after Dec 15.
2. `data/` is git-ignored and must stay out: it holds third-party datasets and the checker binary (licence status in `DATASET_AUDIT.md`). `tools/fetch_data.py` recreates it.
3. Committed on purpose: `demo/replay`, `demo/fresh_attempts`, `demo/recorded_screened`, `demo/recorded`, `demo/recorded_local` (the last two are labelled not-evidence and exist because the audit refers to them), `evaluation/`, `evidence/`, `docs/`, `shakedown/`, `tools/`, `tests/`, `web/`, `Dockerfile`. `evidence/` and `demo/` contain short excerpts of public web pages and SigmaHQ rule text, attributed in `NOTICE`.
4. The workspace is not a git repository. Creating one is a local step you have not authorised; the first commit should be made from the tree after step 1.

## Devpost form

See [DEVPOST_SUBMISSION.md](DEVPOST_SUBMISSION.md) for the text, the track, the bonus choice and the final checks.
