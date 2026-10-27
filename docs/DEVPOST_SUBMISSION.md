# Devpost submission draft

Nothing has been submitted. Paste the sections below into the Devpost form when you approve. Items in `[[double brackets]]` do not exist yet and must not be invented.

## Form fields

| Field | Value |
|---|---|
| Project name | Shakedown |
| Tagline | Detection rules that come with test results |
| Track | **Coding and Agentic Engineering** ("agents that write, run, and test code in Token Factory"; the agent writes a Sigma rule, runs it in a Token Factory Sandbox and repairs it from the results) |
| Bonus award | The rules give each project "one (1) Overall Award OR one (1) Track Award **and one (1) Bonus Award**". Best Use of Tavily ($3,000) and Most Valuable Feedback ($100 and swag) are both bonus awards, so only one can be won. The feedback section is also a required submission item, so complete it regardless. Shakedown qualifies for the Tavily bonus on its face (a functional runtime call to the Tavily API, below). Do not describe it as eligible for both |
| Repository URL | [[public repository URL, after you create it]] |
| Working demo URL | [[hosted demo URL, after you approve hosting]] (see HOSTING_PLAN.md) |
| Video URL | [[public YouTube URL, under 3 minutes]] |
| Written explanation of what was updated | see "What was built during the hackathon" below |

## Text description

**The problem.** When a new attack is reported, a defender has to turn the report into a detection rule. AI can write a Sigma rule in seconds, but a rule that looks valid can still miss the attack or alert on normal activity, and a generated rule normally arrives with no evidence either way.

**What Shakedown does.** Shakedown turns a threat report into a Sigma rule and then tests it, instead of handing it over unchecked. It reads the report with Tavily, has an NVIDIA Nemotron model extract what to look for (every item must come with a quote that appears word for word in the report, or it is dropped), writes the rule, validates it with `sigma check`, and runs it inside a Nebius Token Factory Sandbox against a labelled attack log and against 481 benign Windows log files. If the rule missed the attack or matched benign events, the evidence goes back to the model for a bounded repair (at most three), and the page shows every attempt, the diff, and the results with their denominators next to SigmaHQ's expert rule for the same behaviour. A rule that never passes is shown as not passing.

**What each piece does.**
- **Nemotron 3 Super 120B (`nvidia/nemotron-3-super-120b-a12b`) on Nebius Token Factory** extracts the spec, writes the rule and repairs it, through structured JSON output. This is a runtime call to the Token Factory inference API on every run. Token Factory returns a structured answer in about 5 to 11 seconds, which is what makes a write, test, repair cycle practical; a whole run including the Sandbox evaluations takes about 2.5 to 5 minutes.
- **Token Factory Sandboxes (beta)** run SigmaHQ's own evaluator on each candidate in a disposable microVM with `networking.enabled=false`, from one immutable image holding the checker and the benign logs. Thirty reference rules gave identical match counts in the Sandbox and in a local container.
- **Tavily** reads the report page and searches for corroborating sources at run time (one search and one extraction per run: a functional runtime call to the Tavily API, shown in the `research` block of every live run record, for example `demo/replay/pua-adfind-exe-execution.json`, with URLs and retrieval times). Results that look like the rule being written are excluded before the model sees them, and each source, its time and the decision are stored in the run record. Tavily's contribution to rule quality is **not shown** (an 18-run ablation could not separate the arms).
- **sigma check** validates every candidate. Everything else (rule rendering, rule ids, scoring, the budget guard) is deterministic code.

**Result we can stand behind.** On 20 SigmaHQ tasks frozen before any run on them (10 dated 2026), the first attempt detected the attack in 6 to 7 of 20 (Run 8: 7 of 19 completed tasks; Run 9: 6 of 20), and after up to three repairs in 14 of 20 in both runs. SigmaHQ's expert rules detected 20 of 20 (Run 9). **Expert rules remain the performance reference; Shakedown does not beat them.** What it adds is a tested rule with evidence, produced from a description. One repaired rule matched held-out benign logs in each run (1 to 2 events).

**What the evidence does not show.** After a repair, detection is judged on the same attack file whose missed events the model was shown, so it is not a held-out result; only the first attempt and the held-out benign counts are clean. There is one attack sample per rule, the data is lab data, and 20 tasks is a small sample with large run-to-run noise. Everything is in `docs/LIMITATIONS.md`.

**Beyond the lab (local, not part of the benchmark or the hosted demo).** `python -m shakedown.assess` evaluates a rule against evidence an organisation supplies (EVTX only, every file labelled and hashed, logs never assumed benign, evaluated locally unless the user explicitly allows an upload) and can run a bounded, read-only Splunk search. It reports three separate statuses (rule validity, attack validation, environment preflight), never a single pass, and writes a review packet for an analyst; it deploys nothing and sends no customer data to any model. The bring-your-own-logs path is implemented and was exercised end to end on real EVTX files, using public lab data in place of an organisation's own (it is not customer-environment validation). **The Splunk connector was verified live only against a throwaway local Splunk Enterprise 10.6.1.1 test instance** with controlled, simulated Sysmon events: the real instance ran the connector's actual query and every count matched the labelled expectations (`evidence/splunk_live_verification/REPORT.md`). It has not been tested against a production Splunk, a real Sysmon add-on or a certificate-verified connection, and the 47 mocked tests that also cover it are not proof of a live integration.

**An audit we ran on ourselves.** Web search for a SigmaHQ-derived scenario can return copies of the very rule being written. We found this on 2026-10-27, showed that one early recording (PowerShell Child Processes) had copied its reference rule, and added source screening, a guard that refuses model requests carrying the target rule id, and neutral attack-file labels in repair feedback. The frozen benchmark never used web research and is unchanged. The affected recordings are kept, labelled and not used as evidence (`evidence/leakage_audit/REPORT.md`).

**Live runs we checked after the audit.** For "PUA - AdFind.EXE Execution" with answer-bearing pages excluded, 6 of 6 runs passed (two on the first attempt) with zero held-out benign events; the sibling "AdFind Enumeration" scenario passed in 3 of 4 runs, and the failure is shown. Six passes on one scenario is a demonstration, not a success rate (`docs/DEMO_DECISION.md`).

## How to try it

Replay mode needs no accounts and no credentials: `uv sync && uv run python -m shakedown.serve --port 8000`. Replays are unlimited and need no account. Live runs on the hosted demo are limited by caps that bound spend ([[daily and total caps, set when you deploy; see HOSTING_ALTERNATIVES.md]]); when a cap is reached the app says so and the replays still work. Live mode locally needs a Token Factory key, a Sandboxes-enabled project, a Tavily key and `python tools/fetch_data.py` (see the README).

## What was built during the hackathon

Everything: the repository was created for this hackathon starting 2026-10-26 (the Submission Period opened on 2026-08-26; no code existed before). [[Confirm this is accurate for your history before submitting.]]

## Dataset and source attribution

SigmaHQ rules (Detection Rule License 1.1), SigmaHQ regression data, and the NextronSystems evtx-baseline benign logs and `evtx-sigma-checker` v0.8.5 are third-party, fetched at run time at pinned versions with pinned hashes, and not redistributed in the repository. The evaluator binary has no public source and an unclear licence; it is used as is and never redistributed. Expert rules shown in the app and recordings keep their authors, and short event excerpts appear in recorded evidence. See `NOTICE` and `docs/DATASET_AUDIT.md`.

## Feedback section

Paste `docs/FEEDBACK.md` into the feedback field of the form (it is a required submission item, separate from the bonus prize).

## Final checklist before you press submit (all need you)

- [ ] Public repository created, licence visible in About, README reads correctly on the repository page.
- [ ] Hosted demo URL works from a private window; `tools/smoke_hosted.py` passes against it.
- [ ] Video public on YouTube, under 3:00, repository link in its description.
- [ ] Track selected; bonus choice made knowing only one bonus prize can be won.
- [ ] Submitted before **Friday 2026-10-30, 10:00 am Pacific Time (22:30 IST)**. After that no changes are allowed.
