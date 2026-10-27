# Limitations

What these results do and do not show. The numbers are in [RESULTS_TABLE.md](RESULTS_TABLE.md); the method and every change made after seeing results are in [EVALUATION_METHODOLOGY.md](EVALUATION_METHODOLOGY.md).

## About the measurements

- **Small samples.** Two sets of 20 SigmaHQ tasks: a development set (14 process creation, 3 PowerShell script, 3 registry set) used while the method changed, and a confirmatory set of 20 different tasks (10 dated 2026) frozen before any run on it. Rates carry wide uncertainty and no significance claim is made. The headline numbers come from the confirmatory set.
- **Run-to-run noise is large.** Nemotron's output differs between runs even at temperature 0. On the development set, one-shot detection ranged from 3 to 7 of about 20 across seven runs and detection after repair from 7 to 13. The runs cannot rank the configurations we tried; the last-resort thinking-off call we added made no measurable difference (14 of 20 with and without it on the confirmatory set).
- **Post-repair detection is not a held-out result.** The repair loop is shown events from an attack file it missed, then judged on that same file. Only the first attempt's detection and the benign false-positive rates on the held-out logs are clean measurements. We did not test whether a repaired rule detects other variants of the same attack.
- **One attack sample per rule.** "Detected" means at least one event in that one EVTX file matched.
- **The tasks are easier than real reports.** Task text is the SigmaHQ rule's title, description, references and tags. It often states the observable directly. A real threat report is longer, noisier and indirect. The demo runs read live reports through Tavily, but the 20-task measurement did not.
- **Possible training-data contamination.** SigmaHQ rules are public and the model may have seen them. The development set contains no 2026-dated rule. The confirmatory set has 10, and they were detected about as often as the older ones (7 to 8 of 10 after repair against 6 to 7 of 10), which is weak evidence at this size and not a proof.
- **Lab data.** The attack files are SigmaHQ's regression samples and the benign files are Windows lab baselines (Windows 7 x86 for development, Windows 10 client for held-out). Zero false positives on them does not predict false positives in a production environment.
- **Expert rules win.** SigmaHQ's expert rules detect every sample (they were written with these samples in mind). Shakedown is not shown to match expert quality; it is shown to produce a tested rule, with evidence, from a description.
- **Recorded demos were picked after seeing results.** They are real, unedited runs, but we chose which scenarios to record. They include a run that did not pass, on purpose.
- **Web research can leak the answer, and the screen against it is a heuristic.** Searching for a SigmaHQ-derived scenario by its title returns mirrors of that rule (sigmaquery.com, detection.fyi, the SigmaHQ GitHub file, vendor rule pages). The pipeline now flags or excludes sources that contain the target rule id, are hosted on known Sigma mirrors, are titled like the target rule, or contain Sigma rule text. It cannot catch a paraphrase, a rule in another format on an unknown site, or content the model already memorised. It can also drop a harmless page that shares the rule's title. Every decision is recorded. See `evidence/leakage_audit/REPORT.md`.
- **Pages for a sibling rule can remain in the model's context.** The screen targets the rule being written. A vendor page for a related rule (for example the "Suspicious ActiveDirectory Enumeration" page shown in the AdFind Execution runs) is kept. No run copied from it, but a stricter evaluation would exclude it.
- **A repaired rule's pass is not independent.** The repair prompt carries the events of the attack file the first rule missed, so detecting that file afterwards is expected. The held-out benign counts are the clean measurement. This applies to every demo.
- **Recorded demos made before that screen are contaminated.** The "Potentially Suspicious PowerShell Child Processes" recording had the target rule's own YAML among its sources and copied its child-process list; the SigmaHQ-derived AdFind recording also listed the target's GitHub file and a rule page keyed by its id (text not recoverable). They are kept, labelled in the UI, and should not be used to claim what Shakedown does from a report alone. Screened re-recordings are in `demo/recorded_screened/`, one run each.
- **Benchmark repair feedback used to name the attack file, which for SigmaHQ is the rule id.** Runs 1 to 9 had this in their repair prompts (first attempts are unaffected). It is fixed going forward; those runs were not re-run.
- **Parity of the two evaluators was checked on 30 rules**, not all 470 (30 of 30 agreed). Runs 1 to 5 used the local Docker evaluator; Runs 6 to 9 used the Sandbox.
- **One task in Run 8 errored** (the model returned no JSON three times and the loop did not catch it). It is counted as a miss in the conservative figure (14 of 20) and the loop was fixed afterwards without re-running.

## About the product

- **Windows event logs only.** Sigma has many log sources; this supports process creation, PowerShell script blocks, registry set, file event, network connection and image load, and is evaluated on the first three.
- **Not a replacement for an analyst.** A rule that passes these checks still needs review before production: scope, performance, field coverage in your own SIEM and exceptions for your environment.
- **The model sometimes fails to produce a usable rule.** With thinking on, Nemotron 3 Super often returns an empty rule skeleton under strict structured output; the loop resamples up to three times and counts that cost. Some tasks still end without a usable rule, and the UI shows those as not passing.
- **A rule that matches too many events** produces more output than the Sandbox captures (10 MiB). That is reported as an evaluator error ("matched too many events"), not as a partial count.
- **Live runs need the datasets and a built Sandbox image.** The benign baselines and SigmaHQ regression data are not redistributed in this repository (licence status unclear for the samples and the checker binary; see [DATASET_AUDIT.md](DATASET_AUDIT.md)). Replay mode needs none of them.
- **Sandboxes is a beta product.** The offline flag is sent through a small subclass of the SDK's request type because `contree-sdk` 0.3.6 does not expose it. The SDK is pinned, and a test checks the request. A later SDK may change this.
- **No authentication on the demo.** The hosted app is protected by a daily cap, a per-client cooldown and a single concurrent run, not by user accounts.

## About the real-world preflight (assess, bring your own logs, Splunk)

- **The Splunk connector is implemented but not live-verified.** Its 47 tests use a mock server. Treat it as unproven against a real Splunk until `tools/splunk_smoke.py` has succeeded and recorded proof.
- **EVTX only.** The evaluator is SigmaHQ's `evtx-sigma-checker`; NDJSON, JSONL and other formats are not supported.
- **Labels are the supplier's word.** They are recorded, hashed and shown, not verified. Assumed-clean logs support no false-positive claim.
- **A clean historical Splunk window does not show the rule can detect an attack that did not occur in it,** and a lab or supplied-attack match does not show the organisation collects the telemetry. The three statuses are kept apart for that reason.
- **The Splunk log-source scope is an assumption about your indexing** (Sysmon source and EventCode, Sysmon-style field names). The Sigma conversion adds no scope of its own. Windows Security 4688 data needs a different field mapping and is reported unsupported.
- **The read-only guarantee is enforced by this client** (an endpoint allowlist and an SPL command allowlist) **and by the account's role, which the client cannot prove.** Use a search-only role. A search job uses a job quota while it runs.
- **No repair on customer data**, by design: repair sends missed events to the model.
- The packet can contain customer log excerpts and is marked when it does.

