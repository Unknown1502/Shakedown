"""Phase 1 feasibility gate: Token Factory model access, structured output, and Sandboxes.

Needs NEBIUS_API_KEY; the Sandboxes checks also need NEBIUS_PROJECT_ID. Credentials are read from
the environment and never printed or written. Evidence goes to --out.
Exit code: 0 all checks passed, 1 a check failed, 2 credentials missing.
"""
import argparse
import asyncio
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from shakedown.config import load_dotenv
from shakedown.llm import ModelSelectionError, TokenFactory, TokenFactoryError, select_model

SANDBOX_API = "https://api.tokenfactory.nebius.com/sandboxes/v1"
PREFERENCES = ("nemotron-3-super", "nemotron-3_5-lightning", "lightning", "nemotron")
SMOKE_SCHEMA = {
    "type": "object",
    "properties": {"ok": {"type": "boolean"}, "detection_format": {"type": "string"}},
    "required": ["ok", "detection_format"],
    "additionalProperties": False,
}


def check_models(tf: TokenFactory, override: str | None) -> dict:
    models = tf.list_models()
    nvidia = [{"id": m.get("id"), "context_length": m.get("context_length"), "pricing": m.get("pricing"),
               "modality": (m.get("architecture") or {}).get("modality"), "limits": m.get("per_request_limits")}
              for m in models if str(m.get("id", "")).lower().startswith("nvidia/")]
    chosen = select_model([m.get("id", "") for m in models], PREFERENCES, override)
    return {"total_models": len(models), "nvidia_models": nvidia, "chosen": chosen}


def check_inference(tf: TokenFactory, model: str) -> dict:
    completion = tf.chat_json(model, [
        {"role": "system", "content": "Reply only with JSON matching the schema."},
        {"role": "user", "content": "Set ok to true and detection_format to the name of the open, YAML-based "
                                    "SIEM detection rule format maintained by SigmaHQ."},
    ], SMOKE_SCHEMA, name="smoke", max_tokens=1024)
    return {"model": completion.model, "response_format": completion.response_format, "data": completion.data,
            "usage": completion.usage, "latency_s": round(completion.latency_s, 2),
            "had_reasoning": completion.reasoning is not None, "schema_ok": completion.data.get("ok") is True}


def check_sandbox_whoami(key: str, project: str) -> dict:
    req = urllib.request.Request(f"{SANDBOX_API}/whoami",
                                 headers={"Authorization": f"Bearer {key}", "Project": project})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
            return {"http": resp.status, "permissions": data.get("permissions"), "limits": data.get("limits")}
    except urllib.error.HTTPError as exc:
        return {"http": exc.code, "error": exc.read().decode("utf-8", "replace")[:300]}


async def check_sandbox_run() -> dict:
    from contree_sdk import Contree

    client = Contree()  # reads NEBIUS_API_KEY and NEBIUS_PROJECT_ID
    started = time.monotonic()
    base = await client.images.use("alpine:3.19", strict=True)
    result = await base.run(shell="echo shakedown-sandbox-ok; uname -m", disposable=True)
    return {"exit_code": result.exit_code, "stdout": result.stdout, "stderr": result.stderr[-500:],
            "seconds": round(time.monotonic() - started, 1)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", help="exact listed model ID to use instead of the preference order")
    parser.add_argument("--skip-sandbox", action="store_true")
    parser.add_argument("--out", type=Path, default=Path("data/audit/smoke.json"))
    args = parser.parse_args()

    from_file = load_dotenv()
    if from_file:
        print(f"loaded from .env: {', '.join(from_file)}")
    key, project = os.environ.get("NEBIUS_API_KEY"), os.environ.get("NEBIUS_PROJECT_ID")
    if not key:
        print("NEBIUS_API_KEY is not set (checked environment and .env). See docs/STATUS.md.")
        return 2

    report = {"at": datetime.now(timezone.utc).isoformat(), "checks": {}}
    failed = False
    tf = TokenFactory(key)
    try:
        report["checks"]["models"] = check_models(tf, args.model)
        report["checks"]["inference"] = check_inference(tf, report["checks"]["models"]["chosen"])
        failed |= not report["checks"]["inference"]["schema_ok"]
    except (TokenFactoryError, ModelSelectionError) as exc:
        report["checks"]["model_error"] = str(exc)
        failed = True

    if not args.skip_sandbox:
        if not project:
            report["checks"]["sandbox"] = "skipped: NEBIUS_PROJECT_ID not set"
            failed = True
        else:
            report["checks"]["sandbox_whoami"] = check_sandbox_whoami(key, project)
            try:
                report["checks"]["sandbox_run"] = asyncio.run(check_sandbox_run())
                failed |= report["checks"]["sandbox_run"]["exit_code"] != 0
            except Exception as exc:  # aqg: top-level boundary - record any SDK failure as evidence
                report["checks"]["sandbox_run"] = {"error": f"{type(exc).__name__}: {str(exc)[:300]}"}
                failed = True

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(json.dumps(report, indent=1))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
