"""Validate a candidate Sigma rule with a real validator.

Order matters: YAML is parsed and required fields are checked in-process first, because
sigma-cli crashes with a raw traceback on malformed YAML. Only then is `sigma check` run.
"""
import re
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REQUIRED = ("title", "id", "logsource", "detection")
# sigma-cli flags unconventional filenames, so stage under a conventional one.
STAGED_NAME = "proc_creation_win_shakedown_candidate.yml"


@dataclass(frozen=True)
class Validation:
    ok: bool
    errors: list[str] = field(default_factory=list)
    sigma_output: str = ""


def _sigma_exe() -> str:
    scripts = Path(sys.executable).parent
    for name in ("sigma.exe", "sigma"):
        if (scripts / name).exists():
            return str(scripts / name)
    raise RuntimeError("sigma-cli is not installed in this environment")


def _structural_errors(text: str) -> tuple[dict | None, list[str]]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return None, [f"YAML parse error: {str(exc).splitlines()[0] if str(exc) else 'invalid YAML'}"]
    if not isinstance(doc, dict):
        return None, ["YAML document must be a mapping"]
    errors = [f"missing required field: {name}" for name in REQUIRED if not doc.get(name)]
    if doc.get("id"):
        try:
            uuid.UUID(str(doc["id"]))
        except ValueError:
            errors.append("id is not a valid UUID")
    return doc, errors


def validate_rule(text: str, timeout_s: int = 60) -> Validation:
    doc, errors = _structural_errors(text)
    if errors:
        return Validation(ok=False, errors=errors)

    with tempfile.TemporaryDirectory(prefix="shakedown-validate-") as tmp:
        path = Path(tmp) / STAGED_NAME
        path.write_text(text, encoding="utf-8")
        proc = subprocess.run([_sigma_exe(), "check", str(path)], capture_output=True, text=True,
                              encoding="utf-8", timeout=timeout_s)
    output = re.sub(re.escape(tmp), "<tmp>", proc.stdout + proc.stderr)
    if proc.returncode != 0:
        return Validation(ok=False, errors=["sigma check failed"], sigma_output=output[-3000:])
    return Validation(ok=True, sigma_output=output[-3000:])
