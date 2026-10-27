"""Detection preflight: three independent verdicts about one Sigma rule, and the review packet an analyst reads.

    python -m shakedown.assess --rule rule.yml --manifest case/manifest.yml --splunk --splunk-index win --last-hours 24 --out packet/

A. Rule validity            Does the Sigma validator accept the rule?
B. Attack validation         Does the rule detect the attack evidence supplied (or the controlled lab fixture)?
C. Environment preflight     What did a bounded, read-only SIEM search find in the selected environment and window?

They are reported separately and never combined into one pass. A lab match does not show the organisation collects the
telemetry; a clean historical window does not show the rule can detect an attack that did not occur in it. The output is a
recommendation for an analyst. Nothing is deployed or changed, and nothing here talks to the model: customer events and SIEM
results are never sent to it.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from shakedown import byo, splunk
from shakedown.config import load_dotenv
from shakedown.validate import Validation, validate_rule

ROOT = Path(__file__).resolve().parents[1]
THOR = ROOT / "data/raw/sigma/tests/thor.yml"

RULE_LABELS = {"valid": "Valid Sigma rule", "invalid": "Validation failed", "not_checked": "Not checked"}
ATTACK_LABELS = {"validated_on_supplied_attack_evidence": "Validated on the attack evidence", "attack_not_detected": "Attack evidence not detected",
                 "insufficient_evidence": "Insufficient evidence to validate", "not_run": "Not run"}
ENV_LABELS = {"potential_matches_found": "Potential environment matches found", "no_matches_in_window": "No matches in the selected window",
              "telemetry_missing_or_unsupported": "Required telemetry missing or unsupported", "query_failed": "Search failed", "not_run": "Not run"}
ORIGIN_LABELS = {"organisation_supplied": "organisation-supplied evidence", "controlled_lab_fixture": "controlled lab fixture",
                 "splunk_read_only_search": "Splunk read-only search"}
STANDARD_LIMITATIONS = [
    "The three statuses answer different questions and are not added together. There is no overall pass.",
    "A lab or supplied-attack match does not show the organisation collects the telemetry the rule needs.",
    "Nothing was deployed, scheduled or changed in any SIEM. Deployment is a decision for an analyst.",
]
RECOMMENDATIONS = {
    "do_not_deploy": "Do not deploy this rule as it is: it failed validation or did not detect the attack evidence it was tested on.",
    "needs_more_evidence": "More evidence is needed before this rule can be recommended: at least one of the three questions is unanswered or could not be answered reliably.",
    "review_matches_first": "Review the matching events before any deployment decision. They are potential matches, not confirmed detections or confirmed false positives.",
    "review_for_staged_deployment": "The evidence available supports an analyst reviewing this rule for a staged, alert-only trial. It does not support claims about production detection accuracy.",
}


def _status(state: str, labels: dict, origin: str | None = None, detail: str = "", **extra) -> dict:
    return {"state": state, "label": labels[state], "origin": origin, "detail": detail, **extra}


def lab_attack_from_record(record: dict) -> dict:
    """Controlled lab evidence from a Shakedown run record, labelled as such. It is not the organisation's evidence."""
    best = record["iterations"][record["best_index"]]
    ev = best.get("evaluation")
    out = {"origin": "controlled_lab_fixture", "record": None}
    caveats = ["Controlled lab fixture: one attack sample from SigmaHQ's regression data. It says nothing about your environment or telemetry.",
               "One attack sample: a match on one sample does not show the rule generalises to other variants."]
    if best.get("action") == "repair":
        caveats.append("The repair step was shown the events of this sample, so detection after a repair is not independent and not a held-out result.")
    if not ev or not ev.get("attack_total"):
        out["result"] = {"verdict": "insufficient_evidence", "reasons": ["the run record has no attack evaluation for the final rule"],
                         "caveats": caveats, "samples": []}
        out["benign"] = None
        return out
    hit = ev["attack_detected"] == ev["attack_total"]
    out["result"] = {"verdict": "validated_on_supplied_attack_evidence" if hit else "attack_not_detected",
                     "reasons": [] if hit else [f"missed: {ev.get('attack_missed')}"], "caveats": caveats, "samples": [],
                     "expected_detections": ev["attack_total"], "expected_detections_met": ev["attack_detected"]}
    sets = [{"label": k, "basis": "lab_baseline", "files_total": v["files_total"], "files_with_hits": v["files_with_hits"], "matching_events": v["hits"]}
            for k, v in {**(ev.get("benign") or {}), **(record.get("heldout") or {})}.items()]
    matching = sum(s["matching_events"] for s in sets)
    out["benign"] = {"sets": sets, "matching_events": matching, "verdict": "benign_matches_found" if matching else "no_benign_matches",
                     "supports_false_positive_claim": True,
                     "reasons": ["lab baselines (Windows 7 and Windows 10 clean installs): they say nothing about your environment"]}
    return out


def report_from_record(record: dict) -> dict:
    research = record.get("research") or {}
    primary = research.get("primary") or {}
    return {"url": primary.get("url"), "retrieved_at": primary.get("retrieved_at"), "scenario": (record.get("scenario") or {}).get("title"),
            "source_mode": record.get("source_mode"), "sources": (research.get("screening") or {}).get("sources", [])}


def _recommend(rule, att, env, benign) -> dict:
    if rule["state"] == "invalid" or att["state"] == "attack_not_detected":
        level = "do_not_deploy"
    elif (att["state"] != "validated_on_supplied_attack_evidence" or env["state"] in ("telemetry_missing_or_unsupported", "query_failed", "not_run")
          or (benign and benign.get("verdict") in ("benign_evidence_weak", "no_benign_baseline"))):
        level = "needs_more_evidence"
    elif env["state"] == "potential_matches_found":
        level = "review_matches_first"
    else:
        level = "review_for_staged_deployment"
    return {"level": level, "text": RECOMMENDATIONS[level] + " Nothing was deployed or changed.", "automatic_deployment": False}


def build_assessment(rule_text: str, *, validation: Validation | None, attack: dict | None, environment: dict | None,
                     report: dict | None = None, target_query: dict | None = None, lab: dict | None = None) -> dict:
    doc = yaml.safe_load(rule_text) or {}
    # A. rule validity
    if validation is None:
        rule = _status("not_checked", RULE_LABELS, "sigma_validator", "the rule was not validated")
    elif validation.ok:
        rule = _status("valid", RULE_LABELS, "sigma_validator", "the Sigma validator accepted the rule", output=validation.sigma_output[-1500:])
    else:
        rule = _status("invalid", RULE_LABELS, "sigma_validator", "; ".join(validation.errors) or "the Sigma validator rejected the rule",
                       output=validation.sigma_output[-1500:])
    invalid = rule["state"] == "invalid"

    # B. attack validation
    if invalid:
        att = _status("not_run", ATTACK_LABELS, None, "the rule failed validation, so it was not tested")
    elif attack is None:
        att = _status("not_run", ATTACK_LABELS, None, "no attack evidence was supplied and no lab record was given")
    else:
        result = attack["result"]
        att = _status(result["verdict"], ATTACK_LABELS, attack["origin"], "; ".join(result.get("reasons") or []) or
                      ("the rule matched every sample labelled expect: detect and no negative control" if result["verdict"] == "validated_on_supplied_attack_evidence" else ""),
                      caveats=result.get("caveats", []), expected_detections=result.get("expected_detections"),
                      expected_detections_met=result.get("expected_detections_met"), samples=result.get("samples", []))
    benign = attack.get("benign") if attack and not invalid else None

    # C. environment preflight
    connector_label = ((environment or {}).get("connector", {}).get("verification") or {}).get("label", "implemented but not live-verified")
    if invalid:
        env = _status("not_run", ENV_LABELS, None, "the rule failed validation, so no search was run")
    elif environment is None:
        env = _status("not_run", ENV_LABELS, None, "no SIEM search was requested")
    elif environment["status"] == "not_run":
        env = _status("not_run", ENV_LABELS, None, environment.get("reason", ""))
    elif environment["status"] == "query_failed":
        err = environment["error"]
        env = _status("query_failed", ENV_LABELS, "splunk_read_only_search", f"{err['kind']}: {err['message']}", error=err, connector_label=connector_label)
    else:
        env = _status(environment["status"], ENV_LABELS, "splunk_read_only_search", environment.get("explanation", ""),
                      completed=environment["status"] in ("potential_matches_found", "no_matches_in_window"),
                      scope=environment.get("scope"), coverage=environment.get("coverage"), fields=environment.get("fields"),
                      matches=environment.get("matches"), queries=environment.get("queries"), identity=environment.get("identity"),
                      connector_label=connector_label, elapsed_s=environment.get("elapsed_s"), searched_at=environment.get("searched_at"))
    env.setdefault("connector_label", connector_label)

    limitations = list(STANDARD_LIMITATIONS)
    limitations += [n for n in (environment or {}).get("notes", []) if n not in limitations]
    limitations += [c for c in att.get("caveats", []) if c not in limitations]
    if benign:
        limitations += [r for r in benign.get("reasons", []) if r not in limitations]
    query = target_query or ({"language": "SPL", "detection": environment["queries"]["detection"], "scope": environment.get("scope")}
                             if environment and environment.get("queries") else None)
    return {
        "schema": "shakedown-assessment/1", "created_at": datetime.now(timezone.utc).isoformat(),
        "rule": {"id": str(doc.get("id", "")), "title": str(doc.get("title", "")), "sha256": byo.hashlib.sha256(rule_text.encode("utf-8")).hexdigest(),
                 "falsepositives": doc.get("falsepositives") or [], "logsource": doc.get("logsource")},
        "statuses": {"rule_validity": rule, "attack_validation": att, "environment_preflight": env},
        "benign_baseline": benign, "lab_evidence": lab, "report": report, "target_query": query,
        "recommendation": _recommend(rule, att, env, benign), "limitations": limitations}


# --- the review packet ---------------------------------------------------------------------------------------------
def _fence(text: str, lang: str = "") -> str:
    return f"```{lang}\n{text.rstrip()}\n```"


def render_packet(rule_text: str, a: dict) -> str:
    s = a["statuses"]
    rv, av, ev = s["rule_validity"], s["attack_validation"], s["environment_preflight"]
    origin = lambda st: ORIGIN_LABELS.get(st.get("origin"), "none")
    lines = [f"# Review packet: {a['rule']['title']}", "", f"Rule id `{a['rule']['id']}`, sha256 `{a['rule']['sha256'][:16]}...`, assessed {a['created_at']}.", ""]
    excerpts = bool(((ev.get("matches") or {}).get("examples"))) or any(
        ex.get("examples") for st in ((a.get("benign_baseline") or {}).get("sets") or []) for ex in [st])
    if excerpts:
        lines += ["> **This packet contains excerpts of customer log events.** Handle it under your data policy and do not share it outside it.", ""]
    lines += ["## 1. Summary", "", "Three separate questions, three separate answers. They are not combined.", "",
              "| Question | Status | Evidence source |", "|---|---|---|",
              f"| Rule validity | {rv['label']} | Sigma validator |",
              f"| Attack validation | {av['label']} | {origin(av)} |",
              f"| Environment preflight | {ev['label']} | {origin(ev)} ({ev['connector_label']}) |", "",
              f"**Recommendation: {a['recommendation']['level'].replace('_', ' ')}.** {a['recommendation']['text']}", ""]
    r = a.get("report") or {}
    lines += ["## 2. Source report and references", ""]
    if r.get("url"):
        lines += [f"Report: {r['url']} (retrieved {r.get('retrieved_at')}). Source handling: {(r.get('source_mode') or {}).get('mode', 'not recorded')}."]
        for src in r.get("sources", []):
            lines.append(f"- {src.get('role', '')} {src['url']}: {src['status']} {src.get('reasons') or ''}")
    else:
        lines.append("No report was supplied with this assessment.")
    lines += ["", "## 3. Sigma rule", "", _fence(rule_text, "yaml"), ""]
    q = a.get("target_query")
    lines += ["## 4. Splunk query (not deployed)", ""]
    if q:
        lines += [_fence(q["detection"], "spl"), "", "The log-source scope in the query is an assumption about how your events are indexed; check it.", ""]
    else:
        lines += ["No query was produced.", ""]
    lines += ["## 5. Validation", "", f"**Rule validity: {rv['label']}.** {rv['detail']}", ""]
    if rv.get("output"):
        lines += [_fence(rv["output"]), ""]
    lines += ["## 6. Attack-test evidence", "", f"**Attack validation: {av['label']}** ({origin(av)}). {av['detail']}", ""]
    if av.get("expected_detections") is not None:
        lines.append(f"Samples labelled expect: detect that were detected: {av['expected_detections_met']} of {av['expected_detections']}.")
    for smp in av.get("samples") or []:
        lines.append(f"- `{smp['file']}` expect {smp['expect']}: detected={smp['detected']}, outcome {smp['outcome']}, sha256 `{smp['sha256'][:12]}`; basis: {smp.get('label_basis', '')}")
    for c in av.get("caveats") or []:
        lines.append(f"- Caveat: {c}")
    b = a.get("benign_baseline")
    if b:
        lines += ["", f"Benign baseline ({b['verdict'].replace('_', ' ')}): {b['matching_events']} matching event(s).", *(f"- {x}" for x in b.get("reasons", []))]
        for st in b["sets"]:
            lines.append(f"- `{st['label']}` basis {st['basis']}: {st['files_with_hits']} of {st['files_total']} files with hits, {st['matching_events']} events")
    lines += ["", "## 7. Environment preflight", "", f"**Environment preflight: {ev['label']}** ({origin(ev)}; connector {ev['connector_label']}). {ev['detail']}", ""]
    if ev.get("scope"):
        sc = ev["scope"]
        lines += [f"Indexes: {', '.join(sc['indexes'])}. Window: {sc['earliest']} to {sc['latest']}. Log-source scope: `{sc['logsource_scope']}`.",
                  f"Events in scope: {(ev.get('coverage') or {}).get('events_in_scope')}. Matching events: {(ev.get('matches') or {}).get('count')}.", ""]
        for i, e in enumerate((ev.get("matches") or {}).get("examples") or [], 1):
            lines.append(f"- match {i}: " + ", ".join(f"{k}={v}" for k, v in e.items()))
        if ev.get("queries"):
            lines += ["", "Searches that were run:", *(f"- {k}: `{v}`" for k, v in ev["queries"].items())]
    lines += ["", "## 8. Field mapping and telemetry coverage", ""]
    f = ev.get("fields")
    if f:
        lines.append(f"Rule fields: {f['rule_fields']}. Observed in a sample of {f.get('sampled_events')} events: {f['observed']}. Missing: {f['missing'] or 'none'}.")
    else:
        lines.append("No field check was run." if ev["state"] in ("not_run", "query_failed") else "The field check was not reached (see the status above).")
    if (ev.get("scope") or {}).get("logsource_note"):
        lines.append(f"Log source: {ev['scope']['logsource_note']}")
    lines += ["", "## 9. Possible false positives", ""]
    fps = a["rule"].get("falsepositives") or []
    lines += [f"- Rule author's note: {x}" for x in fps] or ["- The rule lists none."]
    if b and b["matching_events"]:
        lines.append(f"- {b['matching_events']} benign baseline event(s) matched.")
    if (ev.get("matches") or {}).get("count"):
        lines.append(f"- {ev['matches']['count']} event(s) matched in the environment search; some may be legitimate activity.")
    lines += ["", "## 10. Limitations", "", *(f"- {x}" for x in a["limitations"]), "",
              "## 11. Handoff", "",
              "Files in this folder: `rule.yml` (the rule), `query.spl` (the Splunk search), `assessment.json` (all of the above as data).",
              "Nothing was deployed. Nothing was created or modified in Splunk. Converting, loading and tuning the rule is a manual step for an analyst.", ""]
    return "\n".join(lines)


def write_packet(out_dir: Path, rule_text: str, assessment: dict, extra: dict | None = None) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "assessment.json").write_text(json.dumps(assessment, indent=1, default=str), encoding="utf-8")
    (out / "rule.yml").write_text(rule_text, encoding="utf-8")
    q = assessment.get("target_query")
    (out / "query.spl").write_text((q["detection"] if q else "") + "\n", encoding="utf-8")
    (out / "review_packet.md").write_text(render_packet(rule_text, assessment), encoding="utf-8")
    for name, doc in (extra or {}).items():
        (out / name).write_text(json.dumps(doc, indent=1, default=str), encoding="utf-8")


# --- command line ----------------------------------------------------------------------------------------------------
def _window(args) -> tuple[datetime, datetime] | None:
    if args.last_hours:
        now = datetime.now(timezone.utc)
        return now - timedelta(hours=args.last_hours), now
    if args.earliest and args.latest:
        parse = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
        return parse(args.earliest), parse(args.latest)
    return None


def _splunk(rule_text: str, args, env: dict, window) -> dict:
    try:
        connector = splunk.SplunkConnector(splunk.SplunkConfig.from_env(env))
    except splunk.SplunkError as exc:
        return {"status": "not_run", "reason": str(exc)}
    try:
        return connector.preflight(rule_text, indexes=args.splunk_index, earliest=window[0], latest=window[1])
    except KeyboardInterrupt:
        connector.cancel()
        return {"status": "query_failed", "error": {"kind": "cancelled", "message": "interrupted by the user; the search job was stopped"}}
    except splunk.SplunkError as exc:
        return {"status": "query_failed", "error": {"kind": exc.kind, "message": str(exc)}}


def main(argv: list[str] | None = None, *, env: dict | None = None, runner_factory=None, validator=None, schema_ids=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--rule", type=Path, help="a Sigma rule file")
    src.add_argument("--run-record", type=Path, help="a Shakedown run record: uses its best rule, report sources and lab evidence")
    p.add_argument("--manifest", type=Path, help="organisation-supplied evidence (see docs/BRING_YOUR_OWN_LOGS.md)")
    p.add_argument("--runner", choices=["local", "sandbox"], default=None, help="where supplied logs are evaluated (default: local)")
    p.add_argument("--i-understand-logs-leave-this-machine", action="store_true", dest="ack",
                   help="allow the Sandbox runner, which uploads the supplied logs to Nebius")
    p.add_argument("--splunk", action="store_true", help="run a read-only Splunk preflight (needs SPLUNK_* environment variables)")
    p.add_argument("--splunk-index", action="append", default=[], help="an index from the operator's allowed list (repeatable)")
    p.add_argument("--last-hours", type=int, help="search the last N hours")
    p.add_argument("--earliest", help="ISO time, with --latest")
    p.add_argument("--latest")
    p.add_argument("--out", type=Path, required=True, help="folder for the review packet")
    args = p.parse_args(argv)

    if env is None:
        load_dotenv()
        env = dict(os.environ)
    validator = validator or validate_rule
    record = json.loads(args.run_record.read_text(encoding="utf-8")) if args.run_record else None
    rule_text = args.rule.read_text(encoding="utf-8") if args.rule else record["iterations"][record["best_index"]]["rule_text"]
    window = _window(args)
    if args.splunk and (window is None or not args.splunk_index):
        print("error: --splunk needs at least one --splunk-index and an explicit time window (--last-hours N, or --earliest and --latest)", file=sys.stderr)
        return 2

    manifest = None
    if args.manifest:
        try:
            kind = byo.choose_runner_kind(args.runner, args.ack)
            manifest = byo.load_manifest(args.manifest)
        except (byo.ExternalUploadRefused, byo.ManifestError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    validation = validator(rule_text)
    attack = lab = None
    extra: dict = {}
    if record:
        lab = lab_attack_from_record(record)
    if validation.ok and manifest:
        category = manifest.logsource["category"]
        schema = byo.check_schema(manifest, (schema_ids or (lambda c: byo.required_event_ids(c, THOR)))(category))
        if runner_factory is None:
            from shakedown.runners import build_runner
            runner_factory = lambda k: build_runner(ROOT, k)
        runner = runner_factory(kind)
        result = byo.evaluate_supplied(rule_text, manifest, runner, schema)
        brecord = byo.build_record(rule_text, manifest, result, runner.describe() if hasattr(runner, "describe") else {"kind": kind}, schema)
        extra["supplied_evidence_record.json"] = brecord
        attack = {"origin": "organisation_supplied", "result": result["attack"], "benign": result["benign"], "record": brecord}
    elif lab:
        attack = lab
    if lab and attack is not lab:
        extra["lab_evidence.json"] = lab

    environment = None
    if args.splunk and validation.ok:
        environment = _splunk(rule_text, args, env, window)

    target = None
    if validation.ok:
        try:
            category = (yaml.safe_load(rule_text).get("logsource") or {}).get("category", "")
            scope = splunk.logsource_scope(category)
            index = "(" + " OR ".join(f'index="{i}"' for i in args.splunk_index) + ")" if args.splunk_index else 'index="<your index>"'
            target = {"language": "SPL", "detection": f"search {index} {scope['clause']} {splunk._wrap(splunk.convert_to_spl(rule_text))}",
                      "scope": {"logsource_scope": scope["clause"], "logsource_note": scope["note"]}}
        except splunk.SplunkError:
            target = None
    assessment = build_assessment(rule_text, validation=validation, attack=attack, environment=environment,
                                  report=report_from_record(record) if record else None, target_query=target,
                                  lab=lab if (lab and attack is not lab) else None)
    write_packet(args.out, rule_text, assessment, extra)
    st = assessment["statuses"]
    print(f"Rule validity:         {st['rule_validity']['label']}\nAttack validation:     {st['attack_validation']['label']}"
          f" ({ORIGIN_LABELS.get(st['attack_validation']['origin'], 'no evidence')})\nEnvironment preflight: {st['environment_preflight']['label']}\n"
          f"Recommendation:        {assessment['recommendation']['level'].replace('_', ' ')} (nothing was deployed)\nPacket:                {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
