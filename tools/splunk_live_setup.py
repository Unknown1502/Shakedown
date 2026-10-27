"""Provision a THROWAWAY local Splunk test instance for the live integration test of the Shakedown Splunk connector.

Run it once against a fresh container (see docs/SPLUNK_PREFLIGHT.md). It uses the admin account ONLY to create things; the
connector never uses admin. It creates:
  - three indexes: shakedown_test (the labelled events), shakedown_bulk (optional filler so a search can genuinely run for seconds, for
    the timeout and cancel tests) and shakedown_other (which the test account must not reach);
  - role shakedown_preflight (capability `search` only, limited to shakedown_test) and user shakedown_svc, plus a token for it;
  - two negative-test accounts: one whose role has no search capability, one whose role has an admin-class capability;
  - a small set of LABELLED events (see EVENTS) with known expected results.
Secrets go to a gitignored folder (default data/splunk_live/) and are never printed. Standard library only.

    python tools/splunk_live_setup.py --base-url https://127.0.0.1:18089 --admin-password-file data/splunk_live/admin.pw
"""
import argparse
import base64
import json
import secrets
import ssl
import string
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

SYSMON = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
SECURITY = "XmlWinEventLog:Security"
SOURCETYPE = "shakedown:sysmon_kv"


def _event(minutes_ago: float, **fields) -> dict:
    return {"minutes_ago": minutes_ago, "fields": fields}


# label -> (index, source, event, expectation). The raw text is "<timestamp> key=value ...": Splunk's default key=value extraction
# turns it into searchable fields. This SIMULATES Sysmon field extraction; it is not the Splunk Add-on for Sysmon.
EVENTS = {
    "match_1": ("shakedown_test", SYSMON, _event(20, EventCode=1, host_label="LAB-W10-01", Image=r"C:\Tools\AdFind.exe", OriginalFileName="AdFind.exe",
                CommandLine="AdFind.exe -f (objectcategory=person) -dechextosid", User=r"LAB\analyst"), "MUST match the AdFind rule"),
    "match_2": ("shakedown_test", SYSMON, _event(12, EventCode=1, host_label="LAB-W10-02", Image=r"D:\x\adfind.exe", OriginalFileName="AdFind.exe",
                CommandLine="adfind.exe -sc trustdmp -nosacl", User=r"LAB\svc"), "MUST match the AdFind rule"),
    "unrelated_1": ("shakedown_test", SYSMON, _event(30, EventCode=1, host_label="LAB-W10-01", Image=r"C:\Windows\System32\notepad.exe",
                    OriginalFileName="NOTEPAD.EXE", CommandLine=r"notepad.exe C:\notes.txt", User=r"LAB\analyst"), "in scope, must NOT match"),
    "unrelated_2": ("shakedown_test", SYSMON, _event(25, EventCode=1, host_label="LAB-W10-03", Image=r"C:\Windows\System32\cmd.exe",
                    OriginalFileName="Cmd.Exe", CommandLine="cmd.exe /c dir", User=r"LAB\svc"), "in scope, must NOT match"),
    "decoy_wrong_eventcode": ("shakedown_test", SYSMON, _event(15, EventCode=3, host_label="LAB-W10-01", Image=r"C:\Tools\AdFind.exe",
                    OriginalFileName="AdFind.exe", CommandLine="AdFind.exe -f (objectcategory=person)"), "right content, EventCode 3: excluded by the EventCode scope"),
    "decoy_wrong_source": ("shakedown_test", SECURITY, _event(14, EventCode=1, host_label="LAB-W10-01", Image=r"C:\Tools\AdFind.exe",
                    OriginalFileName="AdFind.exe", CommandLine="AdFind.exe -f (objectcategory=person)"), "right content and EventCode, other source: excluded by the source scope"),
    "decoy_outside_window": ("shakedown_test", SYSMON, _event(60 * 24 * 3, EventCode=1, host_label="LAB-W10-01", Image=r"C:\Tools\AdFind.exe",
                    OriginalFileName="AdFind.exe", CommandLine="AdFind.exe -f (objectcategory=person)"), "right content, 3 days old: excluded by a 1 hour window"),
    "decoy_other_index": ("shakedown_other", SYSMON, _event(10, EventCode=1, host_label="LAB-W10-09", Image=r"C:\Tools\AdFind.exe",
                    OriginalFileName="AdFind.exe", CommandLine="AdFind.exe -f (objectcategory=person)"), "right content, an index the account must not reach"),
}


class Admin:
    def __init__(self, base_url: str, password: str, verify: bool):
        self.base, self._auth = base_url.rstrip("/"), "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()
        self._ctx = None if verify else ssl._create_unverified_context()  # a loopback throwaway instance with Splunk's default certificate

    def call(self, method: str, path: str, form: list | None = None, raw: bytes | None = None, params: dict | None = None, ok404: bool = False) -> dict:
        url = self.base + path + "?" + urllib.parse.urlencode({"output_mode": "json", **(params or {})})
        data = raw if raw is not None else (urllib.parse.urlencode(form).encode() if form is not None else None)
        req = urllib.request.Request(url, data=data, method=method, headers={"Authorization": self._auth})
        try:
            with urllib.request.urlopen(req, timeout=60, context=self._ctx) as resp:
                body = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            if ok404 and (exc.code == 404 or "does not exist" in detail):  # a real Splunk answers 400 "does not exist" for a missing user
                return {}
            raise SystemExit(f"Splunk answered HTTP {exc.code} for {method} {path}: {detail}") from None
        return json.loads(body) if body else {}


def pw(n: int = 24) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="https://127.0.0.1:18089")
    parser.add_argument("--admin-password-file", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, default=Path("data/splunk_live"))
    parser.add_argument("--bulk", type=int, default=0, help="also index N filler events into shakedown_bulk (for the timeout and cancel tests)")
    parser.add_argument("--skip-seed", action="store_true", help="do not index the labelled events again (use when re-provisioning accounts)")
    parser.add_argument("--ca-bundle", help="verify the server certificate with this CA instead of skipping verification")
    args = parser.parse_args()
    admin = Admin(args.base_url, args.admin_password_file.read_text(encoding="utf-8").strip(), verify=bool(args.ca_bundle))
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)

    for index in ("shakedown_test", "shakedown_bulk", "shakedown_other"):
        if admin.call("GET", f"/services/data/indexes/{index}", ok404=True):
            print(f"index {index}: exists")
        else:
            admin.call("POST", "/services/data/indexes", form=[("name", index)])
            print(f"index {index}: created")

    roles = {
        "shakedown_preflight": [("capabilities", "search"), ("srchIndexesAllowed", "shakedown_test"), ("srchIndexesAllowed", "shakedown_bulk"),
                                ("srchIndexesDefault", "shakedown_test"),
                                ("srchJobsQuota", "2"), ("srchDiskQuota", "100"), ("srchTimeWin", "604800")],
        "shakedown_nosearch": [("srchIndexesAllowed", "shakedown_test")],
        "shakedown_overpriv": [("capabilities", "search"), ("capabilities", "admin_all_objects"), ("srchIndexesAllowed", "shakedown_test")],
    }
    exact = {"shakedown_preflight": ["search"], "shakedown_nosearch": [], "shakedown_overpriv": ["search", "admin_all_objects"]}
    for name, attrs in roles.items():
        admin.call("DELETE", f"/services/authorization/roles/{name}", ok404=True)
        admin.call("POST", "/services/authorization/roles", form=[("name", name), ("imported_roles", "")] + attrs)
        # Splunk Enterprise 10.6 adds edit_own_objects, list_all_objects, run_collect, run_mcollect and schedule_rtsearch to every new role.
        # Updating `capabilities` REPLACES the list, so set exactly what the role is meant to hold.
        admin.call("POST", f"/services/authorization/roles/{name}", form=[("capabilities", c) for c in exact[name]] or [("capabilities", "")])
        print(f"role {name}: created with capabilities exactly {exact[name] or 'none'}")

    secrets_out: dict[str, str] = {}
    for user, role in (("shakedown_svc", "shakedown_preflight"), ("shakedown_noperm", "shakedown_nosearch"), ("shakedown_overpriv", "shakedown_overpriv")):
        admin.call("DELETE", f"/services/authentication/users/{user}", ok404=True)
        password = pw()
        admin.call("POST", "/services/authentication/users", form=[("name", user), ("password", password), ("roles", role), ("force-change-pass", "0")])
        secrets_out[user] = password
        print(f"user {user}: created with role {role}")

    token_resp = admin.call("POST", "/services/authorization/tokens", form=[("name", "shakedown_svc"), ("audience", "shakedown-preflight-test"), ("expires_on", "+7d")])
    token = token_resp["entry"][0]["content"]["token"]
    print("token for shakedown_svc: created (expires in 7 days)")

    now = datetime.now(timezone.utc)
    seeded = {}
    for label, (index, source, ev, expectation) in ([] if args.skip_seed else EVENTS.items()):
        stamp = (now - timedelta(minutes=ev["minutes_ago"])).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        fields = dict(ev["fields"])
        host = fields.pop("host_label")
        raw = stamp + " " + " ".join(f'{k}="{v}"' for k, v in fields.items())
        admin.call("POST", "/services/receivers/simple", raw=raw.encode("utf-8"),
                   params={"index": index, "source": source, "sourcetype": SOURCETYPE, "host": host})
        seeded[label] = {"index": index, "source": source, "host": host, "timestamp": stamp, "expectation": expectation, "fields": fields}
    print(f"seeded {len(seeded)} labelled events" if not args.skip_seed else "skipped seeding (events already indexed)")

    if args.bulk:
        chunk, written = 25000, 0
        while written < args.bulk:
            n = min(chunk, args.bulk - written)
            lines = []
            for i in range(written, written + n):
                stamp = (now - timedelta(seconds=(i * 7200) // args.bulk)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
                lines.append(stamp + ' EventCode="1" Image="C:/Windows/System32/svchost.exe" CommandLine="svchost.exe -k netsvcs -p -s Schedule '
                             f'seq={i} token={secrets.token_hex(8)}" User="NT AUTHORITY/SYSTEM"')
            admin.call("POST", "/services/receivers/simple", raw=chr(10).join(lines).encode("utf-8"),
                       params={"index": "shakedown_bulk", "source": SYSMON, "sourcetype": SOURCETYPE, "host": "LAB-BULK-01"})
            written += n
            print(f"  bulk: {written}/{args.bulk}")
        print(f"seeded {args.bulk} filler events into shakedown_bulk")
    base_url = args.base_url
    env_lines = [f"SPLUNK_BASE_URL={base_url}", f"SPLUNK_TOKEN={token}", "SPLUNK_ALLOWED_INDEXES=shakedown_test,shakedown_bulk",
                 f"SPLUNK_VERIFY_TLS={'true' if args.ca_bundle else 'false'}"]
    if args.ca_bundle:
        env_lines.append(f"SPLUNK_CA_BUNDLE={args.ca_bundle}")
    (out / "splunk.env").write_text("\n".join(env_lines) + "\n", encoding="utf-8")
    (out / "accounts.env").write_text("\n".join(f"{u.upper()}_PASSWORD={p}" for u, p in secrets_out.items()) + "\n", encoding="utf-8")
    if not args.skip_seed:
        (out / "seed_manifest.json").write_text(json.dumps({"seeded_at": now.isoformat(), "events": seeded}, indent=1), encoding="utf-8")
    print(f"wrote {out}/splunk.env, accounts.env (secrets, not printed) and seed_manifest.json (no secrets)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
