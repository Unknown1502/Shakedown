"""Prepare a THROWAWAY local Elasticsearch for the Elastic connector's live checks. Loopback only; never point it at a real cluster.

It uses the `elastic` superuser only to create things: a read-only role on one index, three test accounts (search-only, no-permission,
over-privileged), an index with an ECS-style mapping and a few labelled simulated Sysmon events, and an API key restricted to read on that
index. The connector never uses the superuser. Secrets are written only to gitignored files under data/elastic_live/ and are never printed.

    docker run -d --name shakedown-elastic-test --env-file <env with ELASTIC_PASSWORD=...> -p 127.0.0.1:19200:9200 -m 2g \\
        docker.elastic.co/elasticsearch/elasticsearch:9.1.0        # you accept Elastic's licence terms by running this
    python tools/elastic_live_setup.py --admin-password-file data/elastic_live/admin.pw
"""
import argparse
import base64
import json
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX, OTHER_INDEX = "shakedown-sysmon-test", "shakedown-other-test"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def event(ts, host, exe, original, cmd, channel=SYSMON, code="1", parent="C:\\Windows\\System32\\cmd.exe"):
    return {"@timestamp": ts.isoformat(), "winlog": {"channel": channel}, "event": {"code": code}, "host": {"name": host}, "user": {"name": "LAB\\analyst"},
            "process": {"executable": exe, "pe": {"original_file_name": original}, "command_line": cmd, "parent": {"executable": parent}}}


def seed(now):
    m = lambda minutes: now - timedelta(minutes=minutes)
    return [
        event(m(40), "LAB-W10-01", "C:\\Tools\\AdFind.exe", "AdFind.exe", "adfind.exe -f (objectcategory=person) -nosacl"),            # match 1
        event(m(35), "LAB-W10-02", "C:\\Users\\Public\\af.exe", "AdFind.exe", "af.exe -sdna -f objectclass=computer"),               # match 2 (renamed binary: OriginalFileName still AdFind.exe)
        event(m(30), "LAB-W10-03", "C:\\Tools\\AdFind.exe", "AdFind.exe", "adfind.exe -help"),                                       # decoy: right binary, benign arguments
        event(m(25), "LAB-W10-04", "C:\\Windows\\notepad.exe", "NOTEPAD.EXE", "notepad.exe -f notes.txt"),                           # decoy: arguments match, binary does not
        event(m(20), "LAB-W10-05", "C:\\Tools\\AdFind.exe", "AdFind.exe", "adfind.exe -f objectcategory=person", channel="Microsoft-Windows-PowerShell/Operational", code="4104"),  # other log source
        event(m(15), "LAB-W10-06", "C:\\Tools\\AdFind.exe", "AdFind.exe", "adfind.exe -f objectcategory=person", code="3"),           # same channel, not process creation
        event(now - timedelta(days=10), "LAB-W10-07", "C:\\Tools\\AdFind.exe", "AdFind.exe", "adfind.exe -f objectcategory=person"),   # outside any short window
    ]


MAPPING = {"settings": {"number_of_shards": 1, "number_of_replicas": 0, "analysis": {"normalizer": {"lowercase_norm": {"type": "custom", "filter": ["lowercase"]}}}},
           "mappings": {"dynamic": "false", "properties": {
               "@timestamp": {"type": "date"}, "winlog": {"properties": {"channel": {"type": "keyword"}}}, "event": {"properties": {"code": {"type": "keyword"}}},
               "host": {"properties": {"name": {"type": "keyword"}}}, "user": {"properties": {"name": {"type": "keyword"}}},
               "process": {"properties": {
                   "executable": {"type": "keyword", "fields": {"caseless": {"type": "keyword", "normalizer": "lowercase_norm"}}},
                   "command_line": {"type": "wildcard"}, "pe": {"properties": {"original_file_name": {"type": "keyword"}}},
                   "parent": {"properties": {"executable": {"type": "keyword"}}}}}}}}


class Es:
    def __init__(self, url, ca, auth):
        self.url, self.auth = url.rstrip("/"), auth
        self.ctx = ssl.create_default_context(cafile=str(ca))

    def call(self, method, path, body=None, auth=None, raw=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={"Authorization": auth or self.auth, "Content-Type": "application/x-ndjson" if raw is not None else "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60, context=self.ctx) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            raise SystemExit(f"{method} {path.split('?')[0]} failed: HTTP {exc.code} {exc.read().decode('utf-8', 'replace')[:200]}") from None


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--admin-password-file", type=Path, required=True)
    ap.add_argument("--url", default="https://localhost:19200")
    ap.add_argument("--container", default="shakedown-elastic-test")
    ap.add_argument("--out", type=Path, default=ROOT / "data/elastic_live")
    args = ap.parse_args(argv)
    if "localhost" not in args.url and "127.0.0.1" not in args.url:
        print("refusing: this tool is for a loopback test instance only", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    ca = args.out / "http_ca.crt"
    for _ in range(60):  # the certificate is generated while the node starts
        if subprocess.run(["docker", "cp", f"{args.container}:/usr/share/elasticsearch/config/certs/http_ca.crt", str(ca)], capture_output=True).returncode == 0:
            break
        time.sleep(2)
    else:
        print("the container never produced its CA certificate", file=sys.stderr)
        return 1
    admin = basic("elastic", args.admin_password_file.read_text().strip())
    es = Es(args.url, ca, admin)
    for _ in range(60):
        try:
            es.call("GET", "/")
            break
        except (SystemExit, OSError):
            time.sleep(2)
    else:
        print("Elasticsearch did not become ready", file=sys.stderr)
        return 1
    pw = {n: secrets.token_urlsafe(18) for n in ("svc", "noperm", "overpriv")}
    es.call("PUT", "/_security/role/shakedown_search", {"cluster": ["manage_own_api_key"], "indices": [{"names": [INDEX], "privileges": ["read", "view_index_metadata"]}]})
    es.call("PUT", "/_security/role/shakedown_none", {"cluster": ["monitor"], "indices": []})
    for user, role, key in (("shakedown_svc_es", "shakedown_search", "svc"), ("shakedown_noperm_es", "shakedown_none", "noperm"), ("shakedown_overpriv_es", "superuser", "overpriv")):
        es.call("PUT", f"/_security/user/{user}", {"password": pw[key], "roles": [role], "full_name": "Shakedown live test account"})
    for name in (INDEX, OTHER_INDEX):
        try:
            es.call("DELETE", f"/{name}")
        except SystemExit:
            pass
        es.call("PUT", f"/{name}", MAPPING)
    now = datetime.now(timezone.utc)
    docs = seed(now)
    lines = []
    for d in docs:
        lines += [json.dumps({"index": {"_index": INDEX}}), json.dumps(d)]
    lines += [json.dumps({"index": {"_index": OTHER_INDEX}}), json.dumps(docs[0])]
    es.call("POST", "/_bulk?refresh=true", raw=("\n".join(lines) + "\n").encode())
    key = Es(args.url, ca, basic("shakedown_svc_es", pw["svc"])).call("POST", "/_security/api_key", {
        "name": "shakedown-preflight-test", "expiration": "7d",
        "role_descriptors": {"read_only": {"cluster": [], "indices": [{"names": [INDEX], "privileges": ["read", "view_index_metadata"]}]}}})
    (args.out / "elastic.env").write_text("\n".join([f"ELASTIC_BASE_URL={args.url}", f"ELASTIC_API_KEY={key['encoded']}", f"ELASTIC_CA_BUNDLE='{ca.resolve()}'", f"ELASTIC_INDEX={INDEX}",
                                                     f"ELASTIC_OTHER_INDEX={OTHER_INDEX}"]) + "\n", encoding="utf-8")
    (args.out / "accounts.env").write_text("\n".join([f"ELASTIC_SVC_PASSWORD={pw['svc']}", f"ELASTIC_NOPERM_PASSWORD={pw['noperm']}", f"ELASTIC_OVERPRIV_PASSWORD={pw['overpriv']}"]) + "\n", encoding="utf-8")
    info = es.call("GET", "/")
    print(f"ready: Elasticsearch {info['version']['number']}; index {INDEX} has {len(docs)} events ({len(docs) - 3} in the process-creation scope within an hour: 4, of which 2 match the AdFind rule); "
          f"credentials written to {args.out} (not shown)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
