# Recorded runs: which folder is which

Every file is an unedited run record written by the pipeline. What differs is what the model was allowed to see from the web, and whether a recording may be presented as evidence. The reasoning is in [docs/DEMO_DECISION.md](../docs/DEMO_DECISION.md) and [evidence/leakage_audit/REPORT.md](../evidence/leakage_audit/REPORT.md).

| Folder | Status | Contents |
|---|---|---|
| `replay/` | **Approved. The replay app serves this folder by default.** | Copies of leakage-controlled runs: AdFind Execution (passed after one repair), AdFind Enumeration (one run that did not pass, one that passed on attempt 3), PowerShell Child Processes and Copy From VolumeShadowCopy (neither passed). |
| `fresh_attempts/` | Approved evidence | The six fresh leakage-controlled attempts (three per AdFind scenario) behind the demo decision, every one kept, including failures. |
| `recorded_screened/` | Approved evidence | The first leakage-controlled re-recordings (one run each). |
| `recorded/` | **Not approved as evidence.** Kept unchanged. | Made before answer screening. The PowerShell Child Processes recording's search results included the target rule's own YAML and its rule copies the reference. The app labels these when served. |
| `recorded_local/` | **Not approved as evidence.** Kept unchanged. | Earlier runs on the local Docker evaluator, also before answer screening. |

Do not edit any file here: a recording's value is that it is exactly what the run produced.
