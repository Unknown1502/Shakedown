# Dataset audit

Audited 2026-10-26. Every number below comes from running `tools/dataset_audit.py` and `tools/reference_parity.py` on the pinned sources. Raw outputs are in `data/audit/regression_pairs.json` and `data/audit/reference_parity.json`. The datasets are not committed. Copies of the parity outputs are in `evidence/audit/`; the dataset paths are recreated by `tools/fetch_data.py`.

## Sources

| Source | Version pinned | Licence | Redistribution in this repo | Role |
|---|---|---|---|---|
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) rules | commit `05d1031f537e830b76da53bae2400c5814c89165` (2026-10-21) | Detection Rule License 1.1 (the repo LICENSE file) | No. Fetched at runtime; attribution required if rules are shown | Expert baseline rules; task descriptions |
| SigmaHQ `regression_data/` (EVTX/JSON samples, `info.yml`) | same commit | **Not stated.** The repo LICENSE covers only the rules and the spec | **No.** Fetched at runtime | Positive (attack) fixtures |
| SigmaHQ `tests/thor.yml` | same commit | Not stated separately | No. Fetched at runtime | Log-source → EventID / field mapping used by the evaluator |
| [NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline) release **v0.8.5** (2026-09-14) | `win7-x86.tgz` sha256 `e755f3cd…62b9f`; `win10-client.tgz` sha256 `d48f1b32…6808e` | Apache-2.0 (repo) | No. Fetched at runtime | Benign background fixtures |
| `evtx-sigma-checker` from the same release | sha256 `d672e07a516f3f72eaae8244f99fa2c5b133885a4401eb05a272903857d767e2`; static Go ELF x86-64 | **Unclear.** The binary sits in an Apache-2.0 repo's release, but its source is not public (`NextronSystems/evtx-sigma-checker` returns 404) | No. Fetched at runtime and run only inside an isolated container | Evaluator. This is the exact tool SigmaHQ CI uses (`.github/workflows/regression-tests.yml`, `goodlog-tests.yml`) |

## Paired rule/sample inventory (SigmaHQ regression_data)

- `info.yml` files: **472**.
- Pairs with problems: **2**.
  - `rules/cisco/aaa/cisco_cli_dot1x_disabled`: the rule lies outside this sparse checkout (Windows only).
  - `CVE-2025-55182 …nodejs_server_child_process`: the EVTX file named in `info.yml` is missing upstream.
- **Usable Windows rule ↔ EVTX pairs: 470.**
  - With an explicit `match_count`: **441**. The rest default to "at least 1", the same rule SigmaHQ's runner applies.
  - Also with a JSON sample: 3.
- Pairing check per pair:
  - `info.yml` `rule_metadata[0].id` resolves to exactly one rule file.
  - The rule's `regression_tests_path`, when present, points back at that `info.yml`.
  - The sample file exists and its filename stem equals the rule ID.
  - Its sha256 is recorded.

**Usable pairs by log source:**

| Log source | Pairs |
|---|---|
| process_creation | 283 |
| ps_script | 68 |
| registry_set | 45 |
| file_event | 31 |
| windefend | 7 |
| image_load | 5 |
| registry_delete | 5 |
| network_connection | 4 |
| Other (each ≤ 2) | 22 |

**Usable pairs by rule `date` year:**

| Year | Pairs |
|---|---|
| 2017 | 7 |
| 2018 | 8 |
| 2019 | 45 |
| 2020 | 22 |
| 2021 | 70 |
| 2022 | 171 |
| 2023 | 63 |
| 2024 | 12 |
| 2025 | 31 |
| **2026** | **41** |

**Process-creation samples:**
- All 283 are 69,632 bytes, i.e. one small EVTX chunk.
- `match_count`: 1 for 256 pairs, 2 for one, 4 for one, unspecified for 25.
- So a positive fixture is effectively **one sample containing the attack event(s)**, not a long trace.

## Harness parity (does Shakedown's evaluator agree with SigmaHQ's ground truth?)

`tools/reference_parity.py` runs all 470 reference rules through `shakedown.harness.checker`, using the same image, isolation flags, `thor.yml` and `--rule-level informational` that SigmaHQ's runner uses.
- **470 / 470** rules reproduce at least their declared `match_count` on their own sample.
- The checker takes 12.1 s for the batch.
- It ignored 0 non-JSON output lines.

Benign baselines, with the same 470 expert rules at level ≥ informational:

| Baseline | EVTX files | Expert rules that fired | Total hits | Of those rules, in SigmaHQ `known-FPs.csv` |
|---|---|---|---|---|
| win7-x86 | 129 | 3 | 23 | 3 of 3 |
| win10-client (`Logs_Client`) | 352 | 4 | 7 | 2 of 4 |

The two Win10 rules not on the known-FP list (`proc_creation_win_cmd_rmdir_execution`, `proc_creation_win_susp_local_system_owner_account_discovery`) are `level: low`. The cause was not investigated. Expert rules are not FP-free on these baselines, so any comparison must report expert FPs with the same method.

## Label provenance

- **Positive.** A sample is positive *for its own paired rule*. Contributors recorded it, and SigmaHQ CI and our parity run confirm the paired rule fires on it. It is **not** verified to be positive for any other rule. A sample with no hit for some other rule is "unlabelled for that rule", not "benign".
- **Benign.** evtx-baseline logs are described by Nextron as "goodware" activity: software installation and basic user interaction on test VMs with Sysmon (`sysmonconfig-trace.xml`), expanded audit policy and PowerShell logging. SigmaHQ CI treats any match as a false positive, with a documented exception list. Some known-FP entries reference test artefacts such as `target.exe`, so "benign" means "not attack activity", not "pristine".
- **Unknown.** Everything else, including attack samples evaluated against rules other than their own.

## Splits and leakage controls (as run)

**Grouping and splits:**
- **Grouping unit = the rule.** Each rule owns its sample. Rules sharing a `regression_data` directory or an emerging-threat family stay together.
- **Benign development split:** `win7-x86`.
- **Benign held-out split:** `win10-client` (and later the Win11/2022 sets). These are different hosts and OS builds.
- **Temporal subset:** the 41 rules dated 2026 can be reported separately as "rules created in 2026". This is **not** evidence that a model never saw them; the model's training data is not known.

**Information the model may and may not see:**
- **Visible to the model:** a rule's title, description, ATT&CK tags and references. These are descriptive text.
- **Never shown to the model:** the rule's detection logic. In the benchmark, web research is not used; in live runs, web sources that look like the target rule are excluded (`evidence/leakage_audit/REPORT.md`).
- **The repair loop sees:** hit and miss evidence from the development fixtures, **including the events of the paired attack sample when the first rule missed it** (file names are replaced by "attack sample N"). So detection after a repair is **not** a held-out result; only first-attempt detection and the held-out benign counts are clean.

## Known limitations

- **Single-host lab data:** each positive is one short lab-generated sample, so detection rates are per-sample, not per-campaign.
- **Small benign baselines:** they come from a few lab VMs and say nothing about any production network.
- **Windows only:** about 60% of usable pairs are process-creation events from Sysmon EID 1.
- **Unclear binary licence:** the evaluator binary has no public source and an unclear licence. It is used as-is and never redistributed.
