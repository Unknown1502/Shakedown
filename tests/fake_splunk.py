"""A fake Splunk management endpoint for tests. THIS IS A MOCK: it speaks the REST shapes the connector uses, over real HTTP,
so request building, auth headers, JSON parsing, polling, cancel and delete are exercised. It is NOT evidence that the
connector works against a real Splunk; that needs tools/splunk_smoke.py against an authorised instance.
"""
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "test-token-not-a-real-credential"


class FakeSplunk:
    def __init__(self, handler=None, token: str = TOKEN, capabilities=("search",), username: str = "svc_preflight",
                 poll_delay_s: float = 0.0, context_status: int = 200):
        self.handler = handler or (lambda spl, earliest, latest: {"count": 0, "results": []})
        self.token, self.capabilities, self.username = token, list(capabilities), username
        self.poll_delay_s, self.context_status = poll_delay_s, context_status
        self.requests: list[tuple[str, str]] = []   # (method, path)
        self.searches: list[dict] = []              # the form fields of every job created
        self.jobs: dict[str, dict] = {}
        self.lock = threading.Lock()
        self._n = 0
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

            def _auth(self) -> bool:
                if self.headers.get("Authorization", "") != f"Bearer {owner.token}":
                    self._send(401, {"messages": [{"type": "WARN", "text": "Unauthorized"}]})
                    return False
                return True

            def _body(self) -> dict:
                length = int(self.headers.get("Content-Length") or 0)
                return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(length).decode()).items()}

            def do_GET(self):
                path = urllib.parse.urlsplit(self.path).path
                with owner.lock:
                    owner.requests.append(("GET", path))
                if not self._auth():
                    return
                if path == "/services/authentication/current-context":
                    if owner.context_status != 200:
                        return self._send(owner.context_status, {"messages": [{"type": "ERROR", "text": "forbidden"}]})
                    return self._send(200, {"entry": [{"content": {"username": owner.username, "roles": ["preflight"],
                                                                   "capabilities": owner.capabilities}}]})
                parts = path.strip("/").split("/")
                if parts[:3] == ["services", "search", "jobs"] and len(parts) in (4, 5):
                    job = owner.jobs.get(parts[3])
                    if job is None:
                        return self._send(404, {"messages": [{"type": "FATAL", "text": "Unknown sid."}]})
                    if len(parts) == 4:
                        done = (time.monotonic() - job["created"]) >= owner.poll_delay_s and not job.get("never")
                        state = "FAILED" if job.get("failed") else ("DONE" if done else "RUNNING")
                        return self._send(200, {"entry": [{"content": {
                            "dispatchState": state, "isDone": state in ("DONE", "FAILED"), "isFailed": state == "FAILED",
                            "resultCount": job["count"] if state == "DONE" else 0, "eventCount": job["count"],
                            "messages": job.get("messages", [])}}]})
                    if parts[4] == "results":
                        return self._send(200, {"results": job["results"]})
                self._send(404, {"messages": [{"type": "FATAL", "text": "not found"}]})

            def do_POST(self):
                path = urllib.parse.urlsplit(self.path).path
                with owner.lock:
                    owner.requests.append(("POST", path))
                form = self._body()
                if not self._auth():
                    return
                if path == "/services/search/jobs":
                    with owner.lock:
                        owner.searches.append(form)
                        owner._n += 1
                        sid = f"sid{owner._n}"
                    out = owner.handler(form["search"], form.get("earliest_time"), form.get("latest_time"))
                    if out.get("error"):
                        return self._send(out.get("status", 400), {"messages": [{"type": "FATAL", "text": out["error"]}]})
                    owner.jobs[sid] = {"created": time.monotonic(), "count": out.get("count", 0), "results": out.get("results", []),
                                       "never": out.get("never", False), "failed": out.get("failed", False),
                                       "messages": out.get("messages", [])}
                    return self._send(201, {"sid": sid})
                parts = path.strip("/").split("/")
                if parts[:3] == ["services", "search", "jobs"] and len(parts) == 5 and parts[4] == "control":
                    return self._send(200, {"messages": [{"type": "INFO", "text": f"Search job {form.get('action')}"}]})
                self._send(404, {"messages": [{"type": "FATAL", "text": "not found"}]})

            def do_DELETE(self):
                path = urllib.parse.urlsplit(self.path).path
                with owner.lock:
                    owner.requests.append(("DELETE", path))
                if not self._auth():
                    return
                sid = path.strip("/").split("/")[-1]
                owner.jobs.pop(sid, None)
                self._send(200, {"messages": []})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def paths(self, method: str | None = None) -> list[str]:
        return [p for m, p in self.requests if method in (None, m)]
