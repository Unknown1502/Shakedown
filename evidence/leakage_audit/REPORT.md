# Benchmark leakage audit: decision report

Date: 2026-10-27. Scope: the live AdFind / T1087.002 run (`original/live_63b72e6e0664.json`), then everything that run exposed. Nothing was published, deployed or sent. All results below are exploratory and are not merged into the frozen confirmatory score.

## Short answers

| # | Question | Answer |
|---|---|---|
| 1 | Was answer leakage present? | **In the AdFind run: present as metadata, not as detection logic** (plausible, not shown to be material). **In the recorded PowerShell demo: substantiated.** Details below. |
| 2 | Could it have materially helped the AdFind result? | Not shown. The two mirror snippets gave the rule id, title and one-line description; the detection block was cut off in both. Removing them did not produce a detectable change (n = 3 per cell). |
| 3 | Did the rule still pass without the suspected source? | Yes: 4 of 6 runs passed with the mirrors excluded, against 5 of 6 with them; 2 of 6 with no search at all. Two excluded runs passed on the first attempt. |
| 4 | Were attack and benign results unchanged? | Not run for run (the model is non-deterministic), and the differences are not distinguishable from noise: exact p = 1.00 for with-mirrors vs excluded. Held-out benign hits: 0 of 6, 1 of 6, 2 of 6 runs (with mirrors, excluded, no search). |
| 5 | What changed in code? | Source screening, a `flag`/`exclude` policy, a full record of every source decision, neutral attack-file labels in repair feedback, a UI notice and a legacy label for old recordings. 18 new tests, one assertion changed on purpose; suite 121 passed. |
| 6 | Costs or regressions? | Small. See "Costs". |
| 7 | Which claims stay safe? | See the last section. The recorded PowerShell demo is not one of them. |

## 1. Evidence path for the AdFind run

**What the model saw.** `research.primary` is the Red Canary Atomic Red Team page for T1087.002 (11,819 characters extracted; the model sees the first 6,000). `research.corroboration` has three search snippets of 1,447, 1,241 and 498 characters, from `sigmaquery.com`, `detection.fyi/sigmahq/...proc_creation_win_pua_adfind_execution` and `research.splunk.com`.

**Limitation of the evidence.** The run record stores each source's URL and length, not its text. I re-ran the identical search (`PUA - AdFind.EXE Execution Windows detection`, 3 results). It returned the same three URLs with the same three lengths, so it is accepted as a reconstruction of what the model saw (`original/reconstructed_corroboration_search.json`). The primary page cannot be reconstructed exactly: Tavily now extracts 16,167 characters of the same pinned URL, not 11,819, and the order differs.

**What each source contains** (`trace.json`, produced by `tools/leakage_trace.py`):

| Source | Rule id | Title | Description | Detection field names | Detection values |
|---|---|---|---|---|---|
| sigmaquery.com | yes (exact) | yes | yes (exact) | none (cut at `selection: - [...]`) | none, apart from the word "Adfind.exe" in the description |
| detection.fyi | yes (exact) | yes | yes (exact) | none (cut before `references`) | none |
| research.splunk.com | no | no | its own analytic text | none | the tool name only |
| Red Canary page (visible 6,000 chars in the original) | no | no | n/a | none | n/a |

The reference rule's detection block is `Image|endswith: \AdFind.exe`, `OriginalFileName: AdFind.exe` and eight `IMPHASH=` values. None of the field names `Image`, `OriginalFileName`, `Hashes`, and none of the hashes, appears in any snippet.

**What the generated rule contains.** Six detection items: four command lines (`net user /domain`, `net group /domain`, `dscacheutil -q group`, `ldapsearch`) and two image names (`AdFind.exe`, `ADRecon.ps1`). Every item was quoted from the Red Canary page (the spec step requires a verbatim quote), except that "AdFind.exe" is also in the snippets and, in the original extraction, in the page. It shares exactly one value with the reference rule, `AdFind.exe`, which is the tool the scenario is about. It does not use `OriginalFileName` or any hash. The rule's id and title are its own.

**Classification: partial metadata disclosure, no copy.** The two mirror pages disclosed which rule this is and a one-line description of it, not how to detect it. Title similarity alone was not treated as leakage.

**Caveat that matters:** Tavily's snippet extraction depends on the query. The mirror pages themselves contain the whole rule; this run happened to get only their headers. The recorded demos below were not so lucky.

## 2. Does the result depend on those pages?

`tools/leakage_ablation.py`: same scenario, model (`nvidia/nemotron-3-super-120b-a12b`, thinking on, temperature 0), repair budget (3), Sandbox evaluator and datasets in every run. Research is replayed from fixed snapshots so that Tavily's own variation is not a second variable. Every message sent to the model was captured. 18 runs, 3 at a time, in random order (seed 20261027). Raw file: `ablation_20261027_113437.json`; table: `ablation_20261027_113437.summary.md`.

Arms (corroboration): **recorded** (the three snippets, unscreened), **excluded** (same three, after the screen: sigmaquery and detection.fyi dropped, Splunk kept), **no-search** (search disabled, report page retained). Two report-page conditions because the extraction changed: **clean** (navigation and table of contents stripped, so "AdFind.exe" is inside the 6,000 characters the model sees, as in the original) and **raw** (the page as extracted today; "AdFind.exe" is outside the window).

| | clean / recorded | clean / excluded | clean / no-search | raw / recorded | raw / excluded | raw / no-search |
|---|---|---|---|---|---|---|
| passed (attack caught, 0 benign dev events) | 2 / 3 | 1 / 3 | 0 / 3 (1 errored) | 3 / 3 | 3 / 3 | 2 / 3 |
| first attempt caught the attack | 1 | 0 | 0 | 1 | 2 | 1 |
| attempts, median | 2 | 4 | 4 | 2 | 1 | 3 |
| runs with held-out benign hits | 0 | 0 | 2 | 0 | 1 | 0 |
| tokens, mean | 22,010 | 25,182 | 35,375 | 10,822 | 15,397 | 27,051 |
| seconds, mean | 178 | 167 | 217 | 119 | 145 | 216 |
| model saw the mirror hostnames | 3 | 0 | 0 | 3 | 0 | 0 |
| model saw the target rule id | 3 | 2* | 2* | 3 | 0 | 2* |

\* Not research: see "Second leak path". The mirror-hostname row is the clean proof that the exclusion changed the model-visible text: the hostnames appear in all six runs of the recorded arm and in none of the twelve other runs, and each arm has its own input hash (`input_sha256`).

Pooled over both page conditions, passed: recorded 5/6, excluded 4/6, no-search 2/6. Exact two-sided p: recorded vs excluded 1.00; recorded vs no-search 0.24; excluded vs no-search 0.57. **None of this separates the arms.** The one run that errored (`NoJSONError` during spec extraction) is counted as not passed.

Reading the rules: `OriginalFileName` is a field of the reference rule that the snippets do not show. It appeared in 4 of 6 recorded runs, but also in 2 of 3 `raw/excluded` runs, on the first attempt, with the mirrors gone. So the model reaches for it on its own, and it is not evidence of copying.

## 3. The recorded demos (the more serious finding)

`tools/leakage_demo_audit.py` re-ran each demo's corroboration search and kept the text only where URLs and lengths matched the recording.

| Demo | Result when recorded | Sources (3) | Text recoverable | Finding |
|---|---|---|---|---|
| Potentially Suspicious PowerShell Child Processes | passed, 2 attempts | the target rule's GitHub YAML; a ManageEngine page titled like the rule; a detection.fyi page | **yes** | The GitHub snippet shows the target's `title`, `id`, and detection block: `ParentImage`, `Image|endswith` and the full child-process list. The best rule contains 14 of the reference's 15 child processes (bash, bitsadmin, certutil, cscript, forfiles, hh, mshta, regsvr32, rundll32, schtasks, scriptrunner, sh, wmic, wscript; `scrcons` is missing), with PowerShell as the parent, in the same two roles as the reference. The recording's report was a tweet. **Leakage substantiated.** |
| PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | passed, 2 attempts | the target's GitHub file; a Fortinet rule page; `sigma.nasbench.dev/rules/<target id>` | no | URLs alone show answer-bearing sources, content unknown. **Plausible.** |
| Copy From VolumeShadowCopy Via Cmd.EXE | did not pass | a ManageEngine page titled like the rule; serverfault; Splunk | no | One rule-titled vendor page. It did not pass anyway. |

**Screened re-recordings** (`demo/recorded_screened/`, shipped path, real Tavily, Sandbox, exclusion on, n = 1 each, `tools/leakage_compare_demos.py`):

| Demo | Before (unscreened) | After (screened) |
|---|---|---|
| PowerShell Child Processes | passed, 2 attempts, 0 held-out hits, 15 rule values, all 15 in the reference | **did not pass**, 4 attempts, **72 held-out benign events**, 9 rule values, 7 in the reference |
| AdFind enumeration | passed, 2 attempts | passed, 2 attempts (all 8 search results were screened out, so the report was the Joeware page alone) |
| AdFind execution (new) | n/a | passed, 2 attempts |
| VolumeShadowCopy | did not pass | did not pass |

One run each cannot show that the PowerShell demo fails without the leak. Together with the verbatim overlap above, though, its earlier pass cannot be used as evidence of what Shakedown does from a report.

## 4. Second leak path (found by the ablation)

In the rule-free arms the model still "saw" the target rule id in runs that reached a repair step, and only those. Cause: SigmaHQ names each attack sample `<rule id>.evtx`, and `shakedown/loop.py` printed the names of missed attack files in the repair prompt. This also applies to every repair step of Runs 1 to 9. The id is an opaque UUID and carries no detection logic; the rule title, already in every task, is a far stronger lookup key. First attempts are unaffected. Fixed going forward (feedback says "attack sample N"); Runs 1 to 9 are not re-run, per the pre-registration.

## 5. Does the pipeline filter answer-bearing sources?

Before this audit: **no.** It searched `<scenario title> Windows detection` and passed the top three results to the model. After: yes, as below.

## 6. What changed

| File | Change |
|---|---|
| `shakedown/research.py` | `answer_reasons`, `screen_sources`, `AnswerSourceError`, constants. Reasons: `target_rule_id`, `sigma_mirror`, `target_rule_title`, `sigma_rule_text` |
| `shakedown/pipeline.py` | `answer_policy` (`flag` default, `exclude`); in `exclude` mode asks for 8 results and keeps the first 3 clean ones; refuses an answer-bearing report URL (falls back to the scenario text and records why); records `research.screening` and `input.sha256` |
| `shakedown/live.py`, `shakedown/serve.py`, `tools/record_demo.py` | `--answer-policy`, default `exclude` for live runs and recordings |
| `shakedown/loop.py` | repair feedback uses "attack sample N" |
| `shakedown/server.py`, `web/app.js` | old recordings get an `answer_screen_legacy` label when served (the file is not touched); the UI says how many results were left out or flagged |
| `tools/leakage_*.py` | trace, ablation, summary, demo audit, demo comparison |
| tests | `test_leakage_screening.py` (10), `test_pipeline_leakage.py` (5), `test_server_legacy_screen.py` (2), `test_loop.py` (+1, and one existing assertion changed on purpose). Suite: 121 passed (103 before) |

Immutable originals (sha256): `live_63b72e6e0664.json` b43533285a620cc6ffe5443f47d0e3a8f7b4cd94aafe21e5077fa3906510bf6d, `live_a5f72e938eee.json` 57cbc410cdfc2ee07725905b18ca7beeb52f921beb5a604210d08460e219a31d. `demo/recorded/` and `demo/recorded_local/` were not modified.

## 7. Costs and regressions

- **No extra calls**: still one extract and one search. Exclusion asks the search for 8 results instead of 3; I did not verify how Tavily bills by result count.
- **Over-exclusion is real.** Pages that merely share the rule's title are dropped (vendor rule pages, `rulezet.org`). For AdFind enumeration, all 8 results were screened out, so there was no corroboration at all. Corroboration is optional, and every drop is listed with its reason in the record.
- **Under-exclusion is real too**: paraphrases, other rule formats on unknown hosts, and memorised rules are not caught.
- The demo results got worse (PowerShell no longer passes). That is the point of the change, not a regression.
- Known, not fixed: spec extraction does not handle `NoJSONError` the way the repair loop now does (1 of 18 ablation runs errored there).

## 8. Claims that remain safe

Safe:
- The frozen development and confirmatory results (Runs 1 to 9) did not use web research. First-attempt detection and held-out false positives are clean of the file-name channel; post-repair detection was already stated as not held-out.
- A real pipeline: Tavily reads a threat report at run time, Nemotron 3 Super on Token Factory writes the rule, a Token Factory Sandbox runs SigmaHQ's checker with the network off, and the record states each source and decision.
- The live run on the Red Canary page passed with nothing more than rule metadata exposed, and the passing is not explained by the mirrors (ablation, with the limits above).
- The screened re-recordings AdFind enumeration and AdFind execution: real runs, answer-bearing sources excluded.

Not safe:
- Presenting `demo/recorded/potentially-suspicious-powershell-child-processes.json` (or the other pre-screen recordings) as Shakedown turning a report into a passing rule.
- Saying Tavily corroboration improves rule quality, or that the exclusion does not matter. The ablation cannot say either.
- Saying leakage is eliminated. The screen is a heuristic.

Decision for you (nothing was swapped): the replay app still serves `demo/recorded/`, now with a visible warning on the affected ones. `demo/recorded_screened/` holds the replacements. The video script (`docs/DEMO_SCRIPT.md`) opens with the PowerShell demo and should be rebuilt around the screened set.
