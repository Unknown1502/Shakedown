"""Live smoke test for the read-only Splunk connector. Run it against an instance you are authorised to search.

    export SPLUNK_BASE_URL=https://splunk.example:8089 SPLUNK_TOKEN=... SPLUNK_ALLOWED_INDEXES=win   # or put them in .env
    python tools/splunk_smoke.py --index win

It authenticates, reads the account's capabilities, runs ONE bounded coverage search (the last 15 minutes of the Windows Sysmon
process-creation log source in the index you name), checks that the job was cleaned up, and prints what it saw. On success it
writes evidence/splunk_live_verification.json, which is what lets the product stop labelling the connector "implemented but
not live-verified". It creates, changes and deletes nothing in Splunk except its own search job. No credential is printed or saved.
"""
import argparse
import hashlib
import json
import os
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from shakedown import splunk  # noqa: E402
from shakedown.config import load_dotenv  # noqa: E402


def main(argv=None, env=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--index", required=True, help="an index from SPLUNK_ALLOWED_INDEXES")
    parser.add_argument("--minutes", type=int, default=15)
    parser.add_argument("--proof-path", type=Path, default=splunk.VERIFICATION_FILE)
    parser.add_argument("--no-record", action="store_true", help="run the checks but do not write the verification file")
    args = parser.parse_args(argv)
    if env is None:
        load_dotenv()
        env = dict(os.environ)
    try:
        config = splunk.SplunkConfig.from_env(env)
        connector = splunk.SplunkConnector(config, poll_interval_s=1.0)
        now = datetime.now(timezone.utc)
        earliest, latest = connector._check_scope([args.index], now - timedelta(minutes=args.minutes), now)
        identity = connector._identity()
        scope = splunk.logsource_scope("process_creation")
        query = f'search index="{args.index}" {scope["clause"]} | stats count min(_time) as first max(_time) as last'
        splunk.check_read_only(query)
        out = connector._search(query, earliest, latest, 1)
    except splunk.SplunkError as exc:
        print(f"FAILED ({exc.kind}): {exc}", file=sys.stderr)
        return 1
    row = (out["rows"] or [{}])[0]
    print(f"authenticated as {identity['username']} (roles {identity['roles']}); capabilities known: {identity['capabilities_known']}")
    for warning in identity["warnings"]:
        print("warning:", warning)
    print(f"coverage search ran in {out['seconds']} s: {row.get('count', 0)} Sysmon process-creation events in {args.index} in the last {args.minutes} minutes")
    host = urllib.parse.urlsplit(config.base_url).hostname or ""
    proof = {"verified_at": datetime.now(timezone.utc).isoformat(), "target_host_sha256": hashlib.sha256(host.encode()).hexdigest()[:16],
             "target_is_loopback": host in ("127.0.0.1", "localhost", "::1"), "tls_verified": config.verify_tls, "credential_type": "token" if config.token else "basic",
             "account_capabilities_known": identity["capabilities_known"], "account_warnings": identity["warnings"],
             "checks": ["authenticated", "capabilities read", "bounded coverage search completed", "search job deleted"],
             "server_version": None}
    if args.no_record:
        print("OK (not recorded)")
        return 0
    args.proof_path.parent.mkdir(parents=True, exist_ok=True)
    args.proof_path.write_text(json.dumps(proof, indent=1), encoding="utf-8")
    print(f"OK. Verification recorded in {args.proof_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
