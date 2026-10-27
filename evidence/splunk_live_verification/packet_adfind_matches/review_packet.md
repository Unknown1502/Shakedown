# Review packet: Potential AdFind Usage

Rule id `856f2711-3c41-4fb0-8236-1487b30a905e`, sha256 `5c114954f3a30d9c...`, assessed 2026-10-27T16:58:55.122032+00:00.

> **This packet contains excerpts of customer log events.** Handle it under your data policy and do not share it outside it.

## 1. Summary

Three separate questions, three separate answers. They are not combined.

| Question | Status | Evidence source |
|---|---|---|
| Rule validity | Valid Sigma rule | Sigma validator |
| Attack validation | Not run | none |
| Environment preflight | Potential environment matches found | Splunk read-only search (live-verified on a loopback test instance) |

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
search (index="shakedown_test") source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (OriginalFileName="AdFind.exe" CommandLine IN ("*parentrdn*", "*objrdn*", "*-dechextosid*", "*-encguidtoiid*", "*-showdel*", "*-sdna*", "*-nosacl*", "*-f*"))
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

**Attack validation: Not run** (none). no attack evidence was supplied and no lab record was given


## 7. Environment preflight

**Environment preflight: Potential environment matches found** (Splunk read-only search; connector live-verified on a loopback test instance). These are potential matches: review each event to decide whether it is the behaviour the rule is meant to find.

Indexes: shakedown_test. Window: 2026-10-27T10:58:47.253259+00:00 to 2026-10-27T16:58:47.253259+00:00. Log-source scope: `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1`.
Events in scope: 4. Matching events: 2.

- match 1: _time=2026-10-27T15:15:31.000+00:00, host=LAB-W10-02, source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational, EventCode=1, User=LAB\svc, CommandLine=adfind.exe -sc trustdmp -nosacl, OriginalFileName=AdFind.exe
- match 2: _time=2026-10-27T15:07:31.000+00:00, host=LAB-W10-01, source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational, EventCode=1, User=LAB\analyst, CommandLine=AdFind.exe -f (objectcategory=person) -dechextosid, OriginalFileName=AdFind.exe

Searches that were run:
- coverage: `search (index="shakedown_test") source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 | stats count min(_time) as first max(_time) as last`
- fields: `search (index="shakedown_test") source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 | head 1000 | fieldsummary maxvals=1 | fields field`
- detection: `search (index="shakedown_test") source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (OriginalFileName="AdFind.exe" CommandLine IN ("*parentrdn*", "*objrdn*", "*-dechextosid*", "*-encguidtoiid*", "*-showdel*", "*-sdna*", "*-nosacl*", "*-f*")) | stats count`
- sample: `search (index="shakedown_test") source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (OriginalFileName="AdFind.exe" CommandLine IN ("*parentrdn*", "*objrdn*", "*-dechextosid*", "*-encguidtoiid*", "*-showdel*", "*-sdna*", "*-nosacl*", "*-f*")) | head 5 | table _time, host, source, EventCode, User, ParentImage, CommandLine, OriginalFileName`

## 8. Field mapping and telemetry coverage

Rule fields: ['CommandLine', 'OriginalFileName']. Observed in a sample of 4 events: ['CommandLine', 'EventCode', 'Image', 'OriginalFileName', 'User', 'date_hour', 'date_mday', 'date_minute', 'date_month', 'date_second', 'date_wday', 'date_year', 'date_zone', 'eventtype', 'host', 'index', 'linecount', 'objectcategory', 'punct', 'source', 'sourcetype', 'splunk_server', 'splunk_server_group', 'timeendpos', 'timestartpos']. Missing: none.
Log source: Sysmon process creation. Windows Security 4688 uses different field names (NewProcessName, CommandLine) and is not supported: a rule written with Sigma's Sysmon-style fields would not match it.

## 9. Possible false positives

- Rule author's note: Legitimate administrative use of AdFind for authorized Active Directory queries.
- 2 event(s) matched in the environment search; some may be legitimate activity.

## 10. Limitations

- The three statuses answer different questions and are not added together. There is no overall pass.
- A lab or supplied-attack match does not show the organisation collects the telemetry the rule needs.
- Nothing was deployed, scheduled or changed in any SIEM. Deployment is a decision for an analyst.
- A historical search shows what the rule would have matched in this window. It does not show that the rule can detect an attack that did not occur in the window.
- Field names depend on the add-ons that parse your events; the log-source scope above is an assumption you should check.

## 11. Handoff

Files in this folder: `rule.yml` (the rule), `query.spl` (the Splunk search), `assessment.json` (all of the above as data).
Nothing was deployed. Nothing was created or modified in Splunk. Converting, loading and tuning the rule is a manual step for an analyst.
