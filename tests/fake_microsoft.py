"""A fake Microsoft Entra ID + Azure Monitor Logs + Azure Resource Manager endpoint for tests. THIS IS A MOCK: it speaks the REST shapes the adapter uses, over
real HTTP on loopback. It is NOT evidence that the adapter works against a real Azure tenant; that needs a live run, which has not happened.
"""
import base64
import hashlib
import json
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLIENT_ID = "11111111-2222-4333-8444-555555555555"
TENANT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
WORKSPACE = "99999999-8888-4777-8666-555555555555"
OTHER_WORKSPACE = "12345678-1234-4234-8234-123456789012"
CLIENT_SECRET = "mock-client-secret-value-not-real"
GOOD_CODE = "mock-auth-code-not-real"


def _jwt(claims: dict) -> str:
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'none'})}.{seg(claims)}.sig"


class FakeMicrosoft:
    def __init__(self, *, events=100, present=None, matches=3, forbidden=(OTHER_WORKSPACE,), token_error=None, query_status=None, subscriptions_status=200):
        self.events, self.matches, self.forbidden = events, matches, set(forbidden)
        self.present = set(present) if present is not None else None
        self.token_error, self.query_status, self.subscriptions_status = token_error, query_status, subscriptions_status
        self.challenge = None                       # the S256 challenge the (simulated) authorize step recorded
        self.refresh_tokens, self.access_tokens = set(), set()
        self.rotation = 0
        self.token_requests, self.queries, self.arm_requests, self.authorize_requests = [], [], [], []
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

            def _raw(self):
                return self.rfile.read(int(self.headers.get("Content-Length") or 0))

            def _bearer(self):
                tok = self.headers.get("Authorization", "").removeprefix("Bearer ")
                return tok if tok in owner.access_tokens else None

            def do_POST(self):
                path = urllib.parse.urlsplit(self.path).path
                raw = self._raw()
                if path.endswith("/oauth2/v2.0/token"):
                    form = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode()).items()}
                    owner.token_requests.append(form)
                    return self._send(*owner.token(form))
                m = re.fullmatch(r"/v1/workspaces/([^/]+)/query", path)
                if m:
                    body = json.loads(raw)
                    owner.queries.append({"workspace": m.group(1), "query": body["query"], "timespan": body.get("timespan"), "auth": self.headers.get("Authorization", "")})
                    if not self._bearer():
                        return self._send(401, {"error": {"code": "InvalidAuthenticationToken", "message": "the token is invalid"}})
                    if owner.query_status:
                        return self._send(owner.query_status, {"error": {"code": "x", "message": "mock failure"}})
                    if m.group(1) in owner.forbidden:
                        return self._send(403, {"error": {"code": "InsufficientAccessError", "message": "The provided credentials have insufficient access"}})
                    return self._send(200, owner.table(body["query"]))
                self._send(404, {"error": {"message": "not found"}})

            def do_GET(self):
                parts = urllib.parse.urlsplit(self.path)
                if parts.path.endswith("/oauth2/v2.0/authorize"):
                    # What the browser sees at Microsoft: the sign-in is simulated as already done, and (response_mode=form_post) the code is POSTed to the app's redirect URI.
                    q = {k: v[0] for k, v in urllib.parse.parse_qs(parts.query).items()}
                    owner.authorize_requests.append(q)
                    owner.challenge = q.get("code_challenge")
                    esc = lambda s: s.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")
                    page = (f'<!doctype html><title>Mock Microsoft sign-in</title><p>Mock Microsoft sign-in (a test double). Returning to the app.</p>'
                            f'<form method="post" action="{esc(q["redirect_uri"])}"><input type="hidden" name="state" value="{esc(q["state"])}">'
                            f'<input type="hidden" name="code" value="{GOOD_CODE}"><button>Continue</button></form><script>document.forms[0].submit()</script>').encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(page)))
                    self.end_headers()
                    return self.wfile.write(page)
                owner.arm_requests.append(parts.path)
                if not self._bearer():
                    return self._send(401, {"error": {"code": "AuthenticationFailed"}})
                if parts.path == "/subscriptions":
                    if owner.subscriptions_status != 200:
                        return self._send(owner.subscriptions_status, {"error": {"code": "AuthorizationFailed"}})
                    return self._send(200, {"value": [{"subscriptionId": "sub-1"}]})
                if parts.path == "/subscriptions/sub-1/providers/Microsoft.OperationalInsights/workspaces":
                    return self._send(200, {"value": [{"name": "soc-law", "location": "westeurope", "id": "/subscriptions/sub-1/resourceGroups/rg-soc/providers/Microsoft.OperationalInsights/workspaces/soc-law",
                                                       "properties": {"customerId": WORKSPACE}}]})
                self._send(404, {"error": {"code": "NotFound"}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    # ---- the identity platform ---------------------------------------------------------------------------------------
    def token(self, form: dict) -> tuple:
        if self.token_error:
            return 400, {"error": self.token_error, "error_description": f"AADSTS0000: mock {self.token_error}. Trace ID: abc Correlation ID: def Timestamp: 2026-10-27"}
        if form.get("client_id") != CLIENT_ID:
            return 401, {"error": "invalid_client", "error_description": "AADSTS700016: application not found. Trace ID: abc"}
        grant = form.get("grant_type")
        access = f"AT-{len(self.access_tokens) + 1}-mock-access-token"
        if grant == "client_credentials":
            if form.get("client_secret") != CLIENT_SECRET:
                return 401, {"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided. Trace ID: abc"}
            self.access_tokens.add(access)
            return 200, {"access_token": access, "token_type": "Bearer", "expires_in": 3599}
        if grant == "authorization_code":
            verifier = form.get("code_verifier", "")
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            if form.get("code") != GOOD_CODE or (self.challenge and challenge != self.challenge):
                return 400, {"error": "invalid_grant", "error_description": "AADSTS70008: the code is invalid or PKCE failed. Trace ID: abc"}
            self.access_tokens.add(access)
            self.rotation += 1
            self.refresh_tokens.add(f"RT-{self.rotation}")  # every sign-in mints a new refresh token
            return 200, {"access_token": access, "refresh_token": f"RT-{self.rotation}", "token_type": "Bearer", "expires_in": 3599,
                         "id_token": _jwt({"preferred_username": "analyst@contoso.example", "name": "Ana Lyst", "tid": TENANT, "oid": "oid-1"})}
        if grant == "refresh_token":
            if form.get("refresh_token") not in self.refresh_tokens:
                return 400, {"error": "invalid_grant", "error_description": "AADSTS700082: the refresh token has expired or was already used. Trace ID: abc"}
            self.refresh_tokens.discard(form["refresh_token"])  # Entra rotates refresh tokens: each is good once
            self.rotation += 1
            self.refresh_tokens.add(f"RT-{self.rotation}")
            self.access_tokens.add(access)
            return 200, {"access_token": access, "refresh_token": f"RT-{self.rotation}", "token_type": "Bearer", "expires_in": 3599}
        return 400, {"error": "unsupported_grant_type"}

    # ---- the Logs API ------------------------------------------------------------------------------------------------
    @staticmethod
    def _table(cols, rows):
        return {"tables": [{"name": "PrimaryResult", "columns": [{"name": c, "type": "string"} for c in cols], "rows": rows}]}

    def table(self, kql: str) -> dict:
        if kql.startswith("print"):
            return self._table(["ok"], [[1]])
        if "countif" in kql:
            names = re.findall(r"\['(\w+)'\]=countif", kql)
            return self._table(names, [[self.events if (self.present is None or n in self.present) else 0 for n in names]])
        if "matches=count()" in kql:
            return self._table(["matches"], [[self.matches]])
        if "| project TimeGenerated" in kql:
            rows = [["2026-10-27T10:00:00Z", f"WS-{i}.corp", "CORP\\admin", "C:\\Tools\\AdFind.exe", "C:\\Windows\\cmd.exe", "adfind.exe -f objectcategory=person " + "A" * 400] for i in range(self.matches)]
            return self._table(["TimeGenerated", "Computer", "Account", "NewProcessName", "ParentProcessName", "CommandLine"], rows)
        if "events=count()" in kql:
            return self._table(["events", "first", "last"], [[self.events, "2026-10-26T08:00:00Z", "2026-10-27T09:00:00Z"]])
        return self._table([], [])

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
