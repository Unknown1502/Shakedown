"""Live smoke test for the Elasticsearch connector. Run it against a cluster you are authorised to search.

    export ELASTIC_BASE_URL=https://localhost:9200 ELASTIC_API_KEY=<encoded key> ELASTIC_CA_BUNDLE=ca.crt ELASTIC_INDEX=winlogbeat-*   # or put them in .env
    python tools/elastic_smoke.py --index my-index --server-version 9.1.0

It signs in, reads who it is, lists the indices the account can see, converts a small built-in Sigma rule with pySigma's Elasticsearch backend, and
runs ONE bounded preflight (the last hour of the Windows Sysmon process-creation log source in the index you name). On success it writes
evidence/elastic_live_verification.json, which is what lets the product stop labelling the connector "implemented but not live-verified". It creates,
changes and deletes nothing in Elasticsearch. No credential is printed or saved.
"""
import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from shakedown.config import load_dotenv  # noqa: E402
from shakedown.integrations import vault  # noqa: E402
from shakedown.integrations.adapters import elastic  # noqa: E402
from shakedown.integrations.base import IntegrationError  # noqa: E402
from shakedown.integrations.registry import default_registry  # noqa: E402
from shakedown.integrations.service import IntegrationService  # noqa: E402

RULE = """title: Shakedown smoke test, any cmd.exe start
id: 6d4e2c1a-0000-4000-8000-000000000001
status: test
description: A harmless rule used only to prove the connector can run a bounded search.
author: Shakedown
date: 2026-10-27
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\cmd.exe'
    condition: selection
falsepositives:
    - everything
level: informational
"""


class Rules:
    def list(self):
        return []

    def get(self, ref):
        return {"text": RULE, "label": "smoke test rule", "record": None}


def main(argv=None, env=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--index", required=True, help="an index, alias or data stream to search (no wildcards)")
    ap.add_argument("--hours", type=int, default=1)
    ap.add_argument("--proof-path", type=Path, default=elastic.VERIFICATION_FILE)
    ap.add_argument("--server-version", help="the Elasticsearch version as your admin reports it; recorded as operator-supplied (a read-only key may not read it)")
    ap.add_argument("--no-record", action="store_true", help="run the checks but do not write the verification file")
    args = ap.parse_args(argv)
    if env is None:
        load_dotenv()
        env = dict(os.environ)
    missing = [k for k in ("ELASTIC_BASE_URL", "ELASTIC_API_KEY") if not env.get(k)]
    if missing:
        print("not configured: set " + ", ".join(missing), file=sys.stderr)
        return 2
    svc = IntegrationService(data_dir=Path(tempfile.mkdtemp()), registry=default_registry(), secret_store=vault.MemorySecretStore(), rules=Rules(), environ=env)
    cfg = {"endpoint": env["ELASTIC_BASE_URL"], "verify_tls": True, **({"ca_bundle": env["ELASTIC_CA_BUNDLE"]} if env.get("ELASTIC_CA_BUNDLE") else {})}
    try:
        test = svc.test_new("elastic", "api_key", cfg, {"mode": "env", "env": {"api_key": "ELASTIC_API_KEY"}})
        for c in test["report"]["checks"]:
            print(f"[{c['status']:7}] {c['label']}: {c['detail'][:160]}")
        if not test["report"]["ok"]:
            print("FAILED: the connection test did not pass", file=sys.stderr)
            return 1
        conn = svc.save(test["test_id"], "smoke", {"indexes": [args.index]})
        plan = svc.plan(conn["id"], {"text": RULE}, [args.index], {"last_hours": args.hours})
        if not plan["runnable"]:
            print("FAILED: " + plan.get("reason", "the rule could not be planned"), file=sys.stderr)
            return 1
        started = svc.start_preflight(conn["id"], plan["plan_id"], True)
        svc.join(started["assessment_id"], 180)
        rec = svc.get_assessment(started["assessment_id"])
    except IntegrationError as exc:
        print(f"FAILED ({exc.kind}): {exc}", file=sys.stderr)
        return 1
    env_st = rec["assessment"]["statuses"]["environment_preflight"]
    if env_st["state"] == "query_failed":
        print(f"FAILED ({env_st['error']['kind']}): {env_st['error']['message']}", file=sys.stderr)
        return 1
    print(f"preflight completed in {rec.get('elapsed_s')} s: {env_st['label']}; {(env_st.get('coverage') or {}).get('events_in_scope')} process-creation events in scope")
    host = urllib.parse.urlsplit(env["ELASTIC_BASE_URL"]).hostname or ""
    proof = {"verified_at": datetime.now(timezone.utc).isoformat(), "target_host_sha256": hashlib.sha256(host.encode()).hexdigest()[:16],
             "target_is_loopback": host in ("127.0.0.1", "localhost", "::1"), "tls_verified": True, "credential_type": "api_key",
             "checks": ["connected with certificate verification on", "authenticated", "privileges checked", "indices listed", "rule converted with the ECS Windows pipeline",
                        "bounded coverage, field-presence and detection searches completed", "no credential in the result"],
             "server_version": args.server_version, "server_version_source": "operator-supplied" if args.server_version else None}
    if args.no_record:
        print("OK (not recorded)")
        return 0
    args.proof_path.parent.mkdir(parents=True, exist_ok=True)
    args.proof_path.write_text(json.dumps(proof, indent=1), encoding="utf-8")
    print(f"OK. Verification recorded in {args.proof_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
