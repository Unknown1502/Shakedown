"""A fake Elasticsearch endpoint for tests. THIS IS A MOCK: it speaks the REST shapes the adapter uses, over real HTTP. It is NOT evidence that the
adapter works against a real Elasticsearch; that needs the opt-in live test against a real instance.
"""
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_KEY = "VnVhQ2ZHY0JDZGJrU2xxWTRHSDA6dGVzdC1rZXktbm90LXJlYWw"


class FakeElastic:
    def __init__(self, *, key=API_KEY, username="svc_es", roles=("shakedown_reader",), indices=("winlogbeat-test", "logs-other"), events=100, present=None, matches=3,
                 admin=False, can_read=True, root_status=200, auth_status=200, privileges_status=200, resolve_status=200, search_error=None, timed_out=False, shard_failed=0):
        self.key, self.username, self.roles, self.indices = key, username, list(roles), list(indices)
        self.events, self.matches, self.admin, self.can_read = events, matches, admin, can_read
        self.present = set(present) if present is not None else None   # field names present in the events; None = all
        self.root_status, self.auth_status, self.privileges_status, self.resolve_status = root_status, auth_status, privileges_status, resolve_status
        self.search_error, self.timed_out, self.shard_failed = search_error, timed_out, shard_failed
        self.requests, self.bodies = [], []
        owner = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _auth(self):
                if self.headers.get("Authorization", "") != f"ApiKey {owner.key}":
                    self._send(401, {"error": {"type": "security_exception", "reason": "unable to authenticate"}, "status": 401})
                    return False
                return True

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n) or b"{}")

            def do_GET(self):
                path = urllib.parse.urlsplit(self.path).path
                owner.requests.append(("GET", path))
                if not self._auth():
                    return
                if path == "/":
                    if owner.root_status != 200:
                        return self._send(owner.root_status, {"error": {"type": "security_exception", "reason": "action [cluster:monitor/main] is unauthorized"}})
                    return self._send(200, {"name": "fake", "cluster_name": "fake-cluster", "version": {"number": "8.15.0-mock", "build_flavor": "default"}, "tagline": "You Know, for Search"})
                if path == "/_security/_authenticate":
                    if owner.auth_status != 200:
                        return self._send(owner.auth_status, {"error": {"reason": "no"}})
                    return self._send(200, {"username": owner.username, "roles": owner.roles, "authentication_type": "api_key"})
                if path == "/_resolve/index/*":
                    if owner.resolve_status != 200:
                        return self._send(owner.resolve_status, {"error": {"reason": "forbidden"}})
                    return self._send(200, {"indices": [{"name": n} for n in owner.indices] + [{"name": ".kibana"}], "aliases": [], "data_streams": []})
                self._send(404, {"error": {"reason": "not found"}})

            def do_POST(self):
                path = urllib.parse.urlsplit(self.path).path
                owner.requests.append(("POST", path))
                if not self._auth():
                    return
                body = self._body()
                if path == "/_security/user/_has_privileges":
                    if owner.privileges_status != 200:
                        return self._send(owner.privileges_status, {"error": {"reason": "forbidden"}})
                    if "cluster" in body:
                        return self._send(200, {"has_all_requested": False, "cluster": {c: owner.admin for c in body["cluster"]},
                                                "index": {"*": {p: owner.admin for p in body["index"][0]["privileges"]}}})
                    names = body["index"][0]["names"]
                    return self._send(200, {"has_all_requested": owner.can_read, "cluster": {}, "index": {n: {p: owner.can_read for p in body["index"][0]["privileges"]} for n in names}})
                if path.endswith("/_search"):
                    owner.bodies.append(body)
                    if owner.search_error:
                        return self._send(400, {"error": {"type": "parsing_exception", "reason": owner.search_error}})
                    return self._send(200, owner.search(body))
                self._send(404, {"error": {"reason": "not found"}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def search(self, body):
        aggs = body.get("aggs") or {}
        base = {"took": 1, "timed_out": self.timed_out, "_shards": {"total": 1, "successful": 1 - bool(self.shard_failed), "failed": self.shard_failed,
                                                                      "failures": [{"reason": {"reason": "shard went away"}}] if self.shard_failed else []}}
        if "first" in aggs:
            return {**base, "hits": {"total": {"value": self.events, "relation": "eq"}, "hits": []}, "aggregations": {"first": {"value": 1.7931e12}, "last": {"value": 1.7932e12}}}
        if aggs:
            fields = [aggs[k]["filter"]["exists"]["field"] for k in aggs]
            return {**base, "hits": {"total": {"value": self.events, "relation": "eq"}, "hits": []},
                    "aggregations": {k: {"doc_count": self.events if (self.present is None or aggs[k]["filter"]["exists"]["field"] in self.present) else 0} for k in aggs}}
        if body.get("size") == 0:
            return {**base, "hits": {"total": {"value": self.matches, "relation": "eq"}, "hits": []}}
        hits = [{"_source": {"@timestamp": "2026-10-27T10:00:00Z", "host": {"name": f"WS-{i}"}, "event": {"code": "1"}, "process": {"executable": "C:\\Tools\\AdFind.exe", "command_line": "adfind.exe -f objectcategory=person " + "A" * 400}}} for i in range(min(self.matches, body.get("size", 5)))]
        return {**base, "hits": {"total": {"value": self.matches, "relation": "eq"}, "hits": hits}}

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
