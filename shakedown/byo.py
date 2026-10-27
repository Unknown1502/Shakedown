"""Bring Your Own Logs: evaluate a Sigma rule against organisation-supplied EVTX evidence.

This reuses the existing evaluator (`evaluate_rule` and its `(rules, evtx_dirs) -> CheckerRun` runner); it adds the
parts that make supplied evidence trustworthy: a manifest in which the user labels every file and says why, input checks,
hashes, a telemetry-compatibility check, an explicit expected outcome per attack sample, and verdicts that refuse to
claim more than the evidence supports.

Only EVTX is supported, because the evaluator is SigmaHQ's `evtx-sigma-checker`. Nothing here talks to the model:
customer events must never reach it. Supplied logs are evaluated locally unless the user acknowledges an upload.
"""
import hashlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml

from shakedown.evaluate import evaluate_rule
from shakedown.evtx_events import summarize_events

EVTX_MAGIC = b"ElfFile\x00"
MAX_FILE_BYTES = 1024 ** 3  # real Sysmon logs reach several hundred MB (the public Windows 10 baseline has an 800 MB one)
MAX_SET_BYTES = 8 * 1024 ** 3
MAX_FILES_PER_SET = 5000
SUPPORTED_CATEGORIES = ("process_creation", "ps_script", "registry_set", "file_event", "network_connection", "image_load")
BENIGN_BASES = {
    "known_clean": "reviewed or freshly built, believed to contain no attack activity",
    "production_sample": "real activity from production, not reviewed for attacks",
    "assumed_clean": "no one has checked; assumed to be normal",
}
STRONG_BENIGN_BASES = {"known_clean", "production_sample"}
EXPECTATIONS = ("detect", "no_detect")
MIN_LABEL_CHARS = 12
SCHEMA_SAMPLE_EVENTS = 300
SCHEMA_SAMPLE_BENIGN_FILES = 5

NORMALISATION = ("None. The EVTX files are not converted or filtered. SigmaHQ's evtx-sigma-checker reads them and maps the rule's "
                 "log source to EventID and channel conditions with tests/thor.yml.")
LIMITATIONS = [
    "The labels are the supplier's statement; they are recorded, not verified.",
    "A match on attack samples shows the rule fires on those events. It does not show the organisation collects that telemetry.",
    "Zero matches on a benign baseline shows nothing about logs that were not supplied.",
    "Only EVTX is evaluated. Event fields are as the checker parses them, not as a SIEM would index them.",
]


class ManifestError(ValueError):
    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("manifest rejected:\n- " + "\n- ".join(problems))


class ExternalUploadRefused(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class AttackSample:
    def __init__(self, path: Path, expect: str, label_basis: str):
        self.path, self.name, self.expect, self.label_basis = path, path.name, expect, label_basis
        self.size, self.sha256 = path.stat().st_size, sha256_file(path)


class BenignSet:
    def __init__(self, label: str, path: Path, basis: str, description: str, attested_by: str, files: list[dict]):
        self.label, self.path, self.basis, self.description, self.attested_by, self.files = label, path, basis, description, attested_by, files


class Manifest:
    def __init__(self, base: Path, doc: dict, attack: list[AttackSample], benign: list[BenignSet]):
        self.base, self.doc, self.attack, self.benign = base, doc, attack, benign
        self.name = str(doc.get("name") or base.name)
        self.logsource = doc["logsource"]
        self.schema_info = doc.get("schema") or {}
        self.provenance = doc["provenance"]


def _inside(base: Path, rel: str) -> Path | None:
    candidate = base / rel
    if candidate.is_symlink():
        return None
    resolved = candidate.resolve()
    return resolved if resolved == base or base in resolved.parents else None


def _check_evtx(path: Path, what: str, problems: list[str]) -> bool:
    if path.suffix.lower() != ".evtx":
        problems.append(f"{what}: only .evtx files are supported, got {path.suffix or 'no extension'}")
        return False
    if path.stat().st_size > MAX_FILE_BYTES:
        problems.append(f"{what}: file too large ({path.stat().st_size} bytes, limit {MAX_FILE_BYTES})")
        return False
    with path.open("rb") as handle:
        if handle.read(len(EVTX_MAGIC)) != EVTX_MAGIC:
            problems.append(f"{what}: not an EVTX file (bad header)")
            return False
    return True


def load_manifest(manifest_path: Path) -> Manifest:
    manifest_path = Path(manifest_path)
    base = manifest_path.resolve().parent
    problems: list[str] = []
    try:
        doc = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ManifestError([f"cannot read the manifest: {exc}"]) from exc
    if not isinstance(doc, dict):
        raise ManifestError(["the manifest must be a mapping"])

    logsource = doc.get("logsource") or {}
    if logsource.get("category") not in SUPPORTED_CATEGORIES:
        problems.append(f"logsource.category must be one of {', '.join(SUPPORTED_CATEGORIES)}, got {logsource.get('category')!r}")
    provenance = doc.get("provenance") or {}
    for key in ("collected_by", "method"):
        if not str(provenance.get(key, "")).strip():
            problems.append(f"provenance.{key} is required: who collected the evidence and how")

    attack: list[AttackSample] = []
    for i, entry in enumerate(doc.get("attack") or []):
        what = f"attack[{i}]"
        if entry.get("expect") not in EXPECTATIONS:
            problems.append(f"{what}: expect must be one of {EXPECTATIONS}, got {entry.get('expect')!r}")
        if len(str(entry.get("label_basis", "")).strip()) < MIN_LABEL_CHARS:
            problems.append(f"{what}: label_basis is required (at least {MIN_LABEL_CHARS} characters): why is this file an attack or a negative control")
        path = _inside(base, str(entry.get("file", "")))
        if path is None or not path.is_file():
            problems.append(f"{what}: {entry.get('file')!r} is missing, a symlink, or outside the manifest folder")
            continue
        if _check_evtx(path, what, problems) and entry.get("expect") in EXPECTATIONS:
            attack.append(AttackSample(path, entry["expect"], str(entry.get("label_basis", "")).strip()))
    names = [a.name for a in attack]
    if len(set(names)) != len(names):
        problems.append("attack sample file names must be unique")

    benign: list[BenignSet] = []
    labels: set[str] = set()
    for i, entry in enumerate(doc.get("benign") or []):
        what = f"benign[{i}]"
        basis = entry.get("label_basis")
        if basis not in BENIGN_BASES:
            problems.append(f"{what}: label_basis is required and must be one of {', '.join(BENIGN_BASES)}; logs are never assumed benign")
        directory = _inside(base, str(entry.get("path", "")))
        if directory is None or not directory.is_dir():
            problems.append(f"{what}: {entry.get('path')!r} must be a folder inside the manifest folder (not a symlink)")
            continue
        files, total, set_ok = [], 0, True
        for p in sorted(directory.rglob("*")):
            if p.is_symlink():
                problems.append(f"{what}: symlink {p.name} is not allowed")
                set_ok = False
            elif not p.is_file() and not p.is_dir():
                # Seen for real: a path over the Windows length limit stats as neither. Skipping it would drop the file from the inventory.
                problems.append(f"{what}: {p.name} cannot be read (path too long, or not accessible)")
                set_ok = False
            elif p.is_file():
                if not _check_evtx(p, f"{what} {p.name}", problems):
                    set_ok = False
                    continue
                total += p.stat().st_size
                files.append({"name": p.name, "path": str(p.relative_to(base)).replace("\\", "/"),
                              "size": p.stat().st_size, "sha256": sha256_file(p)})
        if not files:
            problems.append(f"{what}: no .evtx files found")
        if len(files) > MAX_FILES_PER_SET or total > MAX_SET_BYTES:
            problems.append(f"{what}: too large ({len(files)} files, {total} bytes)")
        label = directory.name
        while label in labels:
            label += "_"
        labels.add(label)
        if set_ok and basis in BENIGN_BASES and files:
            benign.append(BenignSet(label, directory, basis, str(entry.get("description", "")),
                                    str(entry.get("attested_by", "")), files))

    attack_hashes = {a.sha256 for a in attack}
    for b in benign:
        if attack_hashes & {f["sha256"] for f in b.files}:
            problems.append(f"benign set {b.label!r} contains a file that is also labelled attack: the same content cannot be both attack and benign")

    if problems:
        raise ManifestError(problems)
    return Manifest(base, doc, attack, benign)


def choose_runner_kind(requested: str | None, acknowledged: bool) -> str:
    """Supplied logs are evaluated locally by default. The Sandbox is an external service: using it uploads the logs."""
    kind = requested or "local"
    if kind == "sandbox" and not acknowledged:
        raise ExternalUploadRefused("The Sandbox runner would upload the supplied logs to Nebius, so they would leave this machine. "
                                    "Use the local runner, or pass the acknowledgement flag if you have decided that is acceptable.")
    return kind


def required_event_ids(category: str, thor_path: Path) -> set[int] | None:
    """EventIDs that SigmaHQ's own mapping associates with a Windows log-source category, or None if it cannot be read."""
    try:
        doc = yaml.safe_load(Path(thor_path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    ids: set[int] = set()
    for entry in (doc.get("logsources") or {}).values():
        if entry.get("category") == category and entry.get("product") == "windows":
            event_id = (entry.get("conditions") or {}).get("EventID")
            for value in event_id if isinstance(event_id, list) else [event_id]:
                if isinstance(value, int):
                    ids.add(value)
    return ids or None


def _sample(path: Path, required: set[int] | None) -> dict:
    try:
        events = summarize_events(path, max_events=SCHEMA_SAMPLE_EVENTS)
    except Exception as exc:  # aqg: top-level boundary - an unreadable file is reported as incompatible, never fatal
        return {"events_sampled": 0, "event_ids": {}, "compatible": False, "reason": f"could not read the file: {type(exc).__name__}"}
    counts = Counter(str(e["EventID"]) for e in events if "EventID" in e)
    out = {"events_sampled": len(events), "event_ids": dict(counts), "channels": sorted({e["Channel"] for e in events if "Channel" in e})}
    if required is None:
        return {**out, "compatible": None, "reason": "the required EventIDs for this log source are unknown"}
    seen = {int(k) for k in counts}
    compatible = bool(seen & required)
    return {**out, "compatible": compatible,
            "reason": "" if compatible else f"none of the required EventIDs {sorted(required)} appear in the first {len(events)} events"}


def check_schema(manifest: Manifest, required_event_ids: set[int] | None) -> dict:
    """Does the supplied evidence contain the telemetry this rule's log source needs? Sampled, not exhaustive."""
    required = set(required_event_ids) if required_event_ids else None
    return {"required_event_ids": sorted(required) if required else None, "sampled_events_per_file": SCHEMA_SAMPLE_EVENTS,
            "attack": {a.name: _sample(a.path, required) for a in manifest.attack},
            "benign": {b.label: {"files_sampled": min(len(b.files), SCHEMA_SAMPLE_BENIGN_FILES),
                                 "files": {f["name"]: _sample(manifest.base / f["path"], required) for f in b.files[:SCHEMA_SAMPLE_BENIGN_FILES]}}
                       for b in manifest.benign}}


def evaluate_supplied(rule_text: str, manifest: Manifest, runner, schema: dict | None) -> dict:
    evaluation = evaluate_rule(rule_text, [a.path for a in manifest.attack],
                               {b.label: b.path for b in manifest.benign}, runner)
    detected = {a.name for a in manifest.attack} - set(evaluation.attack_missed)

    samples = []
    for a in manifest.attack:
        hit = a.name in detected
        outcome = ("as_expected" if hit else "missed") if a.expect == "detect" else ("unexpected_match" if hit else "as_expected")
        samples.append({"file": a.name, "expect": a.expect, "detected": hit, "outcome": outcome,
                        "sha256": a.sha256, "label_basis": a.label_basis})
    attack = _attack_verdict(samples, schema)

    sets, matching = [], 0
    for b in manifest.benign:
        r = evaluation.benign[b.label]
        matching += r.hits
        sets.append({"label": b.label, "basis": b.basis, "files_total": r.files_total, "files_with_hits": r.files_with_hits,
                     "matching_events": r.hits, "examples": r.examples})
    benign = _benign_verdict(sets, matching)
    return {"attack": attack, "benign": benign, "seconds": evaluation.seconds}


def _attack_verdict(samples: list[dict], schema: dict | None) -> dict:
    detect = [s for s in samples if s["expect"] == "detect"]
    controls = [s for s in samples if s["expect"] == "no_detect"]
    out = {"samples": samples, "expected_detections": len(detect), "expected_detections_met": sum(1 for s in detect if s["detected"]),
           "negative_controls": len(controls), "negative_controls_clean": sum(1 for s in controls if not s["detected"]),
           "reasons": [], "caveats": []}
    if not detect:
        out.update(verdict="insufficient_evidence", reasons=["no attack sample is labelled expect: detect, so nothing can show the rule detects an attack"])
        return out
    incompatible = [s["file"] for s in detect if not s["detected"] and schema
                    and schema["attack"].get(s["file"], {}).get("compatible") is False]
    if incompatible:
        out.update(verdict="insufficient_evidence",
                   reasons=[f"required telemetry is missing from the attack sample(s) {incompatible}: the rule cannot match events that are not there, "
                            "so the miss says nothing about the rule"])
        return out
    missed = [s["file"] for s in detect if not s["detected"]]
    unexpected = [s["file"] for s in controls if s["detected"]]
    if missed or unexpected:
        reasons = ([f"missed attack sample(s): {missed}"] if missed else []) + ([f"matched negative control(s): {unexpected}"] if unexpected else [])
        out.update(verdict="attack_not_detected", reasons=reasons)
        return out
    out["verdict"] = "validated_on_supplied_attack_evidence"
    if len(detect) == 1:
        out["caveats"].append("Only one attack sample: a match on one sample does not show the rule generalises to other variants.")
    return out


def _benign_verdict(sets: list[dict], matching: int) -> dict:
    strong = any(s["basis"] in STRONG_BENIGN_BASES for s in sets)
    out = {"sets": sets, "matching_events": matching, "reasons": []}
    if not sets:
        out.update(verdict="no_benign_baseline", supports_false_positive_claim=False,
                   reasons=["no benign baseline was supplied, so nothing is known about false positives"])
    elif matching:
        out.update(verdict="benign_matches_found", supports_false_positive_claim=True)
    elif strong:
        out.update(verdict="no_benign_matches", supports_false_positive_claim=True,
                   reasons=["limited to the logs supplied; says nothing about other hosts, users or periods"])
    else:
        out.update(verdict="benign_evidence_weak", supports_false_positive_claim=False,
                   reasons=["the benign logs are only assumed to be clean, so zero matches is weak evidence"])
    return out


def build_record(rule_text: str, manifest: Manifest, result: dict, runner_description: dict, schema: dict | None = None) -> dict:
    doc = yaml.safe_load(rule_text)
    return {
        "evidence_origin": "organisation_supplied",
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "evaluator": runner_description,
        "rule": {"id": str(doc.get("id", "")), "title": str(doc.get("title", "")), "sha256": hashlib.sha256(rule_text.encode("utf-8")).hexdigest()},
        "manifest": {"name": manifest.name, "logsource": manifest.logsource, "schema": manifest.schema_info},
        "provenance": manifest.provenance,
        "inputs": {
            "attack": [{"file": a.name, "sha256": a.sha256, "size": a.size, "expect": a.expect, "label_basis": a.label_basis} for a in manifest.attack],
            "benign": [{"label": b.label, "label_basis": b.basis, "basis_meaning": BENIGN_BASES[b.basis], "description": b.description,
                        "attested_by": b.attested_by, "files": b.files} for b in manifest.benign]},
        "schema_check": schema,
        "normalisation": NORMALISATION,
        "result": result,
        "contains_event_excerpts": any(s["examples"] for s in result["benign"]["sets"]),
        "limitations": LIMITATIONS,
    }
