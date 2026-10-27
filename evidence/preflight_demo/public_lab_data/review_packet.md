# Review packet: Potential AdFind Usage

Rule id `856f2711-3c41-4fb0-8236-1487b30a905e`, sha256 `5c114954f3a30d9c...`, assessed 2026-10-27T14:52:00.361650+00:00.

## 1. Summary

Three separate questions, three separate answers. They are not combined.

| Question | Status | Evidence source |
|---|---|---|
| Rule validity | Valid Sigma rule | Sigma validator |
| Attack validation | Validated on the attack evidence | organisation-supplied evidence |
| Environment preflight | Not run | none (implemented but not live-verified) |

**Recommendation: needs more evidence.** More evidence is needed before this rule can be recommended: at least one of the three questions is unanswered or could not be answered reliably. Nothing was deployed or changed.

## 2. Source report and references

No report was supplied with this assessment.

## 3. Sigma rule

```yaml
title: Potential AdFind Usage
id: 856f2711-3c41-4fb0-8236-1487b30a905e
status: experimental
description: Detects potential usage of AdFind.exe based on command-line arguments associated with Active Directory enumeration.
author: Shakedown
date: '2026-10-27'
tags:
- attack.discovery
- attack.t1087.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    OriginalFileName: AdFind.exe
  selection_cmd:
    CommandLine|contains:
    - parentrdn
    - objrdn
    - -dechextosid
    - -encguidtoiid
    - -showdel
    - -sdna
    - -nosacl
    - -f
  condition: selection_image and selection_cmd
falsepositives:
- Legitimate administrative use of AdFind for authorized Active Directory queries.
level: high
```

## 4. Splunk query (not deployed)

```spl
search index="<your index>" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (OriginalFileName="AdFind.exe" CommandLine IN ("*parentrdn*", "*objrdn*", "*-dechextosid*", "*-encguidtoiid*", "*-showdel*", "*-sdna*", "*-nosacl*", "*-f*"))
```

The log-source scope in the query is an assumption about how your events are indexed; check it.

## 5. Validation

**Rule validity: Valid Sigma rule.** the Sigma validator accepted the rule

```

=== Summary ===
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
Parsing Sigma rules
Checking Sigma rules
```

## 6. Attack-test evidence

**Attack validation: Validated on the attack evidence** (organisation-supplied evidence). the rule matched every sample labelled expect: detect and no negative control

Samples labelled expect: detect that were detected: 1 of 1.
- `adfind_run.evtx` expect detect: detected=True, outcome as_expected, sha256 `5175ff0f3f0c`; basis: SigmaHQ regression sample for the AdFind.EXE execution rule; AdFind was run on purpose
- Caveat: Only one attack sample: a match on one sample does not show the rule generalises to other variants.

Benign baseline (no benign matches): 0 matching event(s).
- limited to the logs supplied; says nothing about other hosts, users or periods
- `benign` basis known_clean: 0 of 352 files with hits, 0 events

## 7. Environment preflight

**Environment preflight: Not run** (none; connector implemented but not live-verified). no SIEM search was requested


## 8. Field mapping and telemetry coverage

No field check was run.

## 9. Possible false positives

- Rule author's note: Legitimate administrative use of AdFind for authorized Active Directory queries.

## 10. Limitations

- The three statuses answer different questions and are not added together. There is no overall pass.
- A lab or supplied-attack match does not show the organisation collects the telemetry the rule needs.
- Nothing was deployed, scheduled or changed in any SIEM. Deployment is a decision for an analyst.
- Only one attack sample: a match on one sample does not show the rule generalises to other variants.
- limited to the logs supplied; says nothing about other hosts, users or periods

## 11. Handoff

Files in this folder: `rule.yml` (the rule), `query.spl` (the Splunk search), `assessment.json` (all of the above as data).
Nothing was deployed. Nothing was created or modified in Splunk. Converting, loading and tuning the rule is a manual step for an analyst.
