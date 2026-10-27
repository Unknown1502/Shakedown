# Bring your own logs

Test a Sigma rule against attack and benign evidence that **you** supply, using the same evaluator Shakedown uses everywhere else (SigmaHQ's `evtx-sigma-checker`, run in an isolated container with no network). This is a local command-line workflow. The hosted demo does not accept uploads and never should.

**Status:** implemented and run end to end on real EVTX files (public lab data standing in for yours; see "What was run"). **Formats: EVTX only.** NDJSON or JSONL are not supported, because the evaluator reads EVTX, and nothing here pretends otherwise.

## Run it

```bash
uv run python tools/fetch_data.py                          # once: fetches the checker, thor.yml and the public datasets (about 150 MB); the local runner needs the first two
uv run python -m shakedown.assess --rule rule.yml --manifest case/manifest.yml --out packet/
```

`--run-record` can replace `--rule` to assess a rule Shakedown generated (its report sources and lab evidence are then included, labelled as lab evidence). A manifest example is in [examples/byo/manifest.example.yml](examples/byo/manifest.example.yml).

## What you must tell it

| In the manifest | Why |
|---|---|
| `logsource.category` | Which telemetry the rule needs (process_creation, ps_script, registry_set, file_event, network_connection, image_load) |
| `provenance.collected_by`, `provenance.method` | Who collected the evidence and how. Recorded verbatim; not verified |
| each `attack` file: `expect` (`detect` or `no_detect`) and `label_basis` (at least 12 characters) | The explicit mapping from sample to expected outcome. A `no_detect` sample is a negative control |
| each `benign` folder: `label_basis` (`known_clean`, `production_sample` or `assumed_clean`), a description, who attests | **Logs are never assumed benign.** A folder without a basis is refused |

## What it checks before it runs

Only `.evtx` files with a valid EVTX header; at most 1 GiB per file, 8 GiB and 5,000 files per benign set; unique attack file names; every path inside the manifest's folder (no `..`, no symlinks); no entry it cannot read (a skipped file would silently vanish from the inventory, so it is an error); and the same content cannot be labelled both attack and benign. All problems are reported together. It also samples the first 300 events of each attack file and checks that the EventIDs SigmaHQ's mapping associates with the rule's log source appear: an attack sample without the required telemetry cannot validate the rule, and says so.

## What it reports

- **Attack validation** (separate from everything else): `validated_on_supplied_attack_evidence`, `attack_not_detected` (a sample you expected to be detected was missed, or a negative control matched), or `insufficient_evidence` (no sample labelled `detect`, or the sample lacks the required telemetry). A single attack sample adds a caveat that one match does not show the rule generalises.
- **Benign baseline:** `no_benign_matches`, `benign_matches_found` (with counts and up to three event excerpts), `benign_evidence_weak` (zero matches, but the logs are only `assumed_clean`, which supports no claim) or `no_benign_baseline`. Zero matches never says anything about logs you did not supply.
- **The record** (`supplied_evidence_record.json`): every input filename, size and sha256; your provenance and labels; the detected schema; the normalisation applied (none: EVTX is not converted); the evaluation time; the rule id and sha256; per-sample outcomes; the evaluator; and the limitations.

## Your logs stay on your machine

The default runner is **local Docker with `--network none`**. The Nebius Sandbox runner is an external service, so for supplied logs it is refused unless you pass `--i-understand-logs-leave-this-machine`. Nothing in this workflow imports or calls the model, and a test checks that importing it does not even load the model client. **There is no repair step on customer data**: repairing a rule means showing the model the events it missed, which would send your events to it. If you want that, it is a separate decision with its own documentation, and it is not built.

## What was run

On 2026-10-27, with SigmaHQ's AdFind attack sample (labelled `detect`) and the 352-file Windows 10 clean baseline (labelled `known_clean`) standing in for an organisation's evidence, against a rule Shakedown generated: valid rule, attack evidence detected (1 of 1), 0 matching events in 352 benign files, evaluator local Docker, 54 seconds. The packet is in `evidence/preflight_demo/public_lab_data/`. The same run first found that the 800 MB Sysmon log in that baseline exceeded my initial 256 MB limit (raised to 1 GiB), and that a file whose path exceeded the Windows length limit was being silently dropped from the inventory (now an error). Both fixes have tests.

## Limits

The labels are your statement and are recorded, not checked. A match shows the rule fires on those events, not that your fleet collects them. A tool cannot tell you your sample is representative of the attack; one detonation is one variant.
