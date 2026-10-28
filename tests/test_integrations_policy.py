"""Destination policy for user-entered SIEM endpoints: what may be connected to, and that the check cannot be raced.
These tests use a fake resolver and small loopback HTTP servers. They are unit tests of the policy, not of any SIEM."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from shakedown.integrations import policy
from shakedown.integrations.base import IntegrationError

DNS = {"good.example": ["93.184.216.34"], "meta.example": ["169.254.169.254"], "mixed.example": ["93.184.216.34", "10.0.0.5"],
       "lan.example": ["10.1.2.3"], "loop.example": ["127.0.0.1"], "v6meta.example": ["fd00:ec2::254"], "mapped.example": ["::ffff:169.254.169.254"],
       "cgnat.example": ["100.64.1.1"], "zero.example": ["0.0.0.0"], "mcast.example": ["224.0.0.1"], "ll6.example": ["fe80::1"]}


def resolver(host, port):
    if host not in DNS:
        raise OSError("no such host")
    return DNS[host]


def check(url, mode="local", **kw):
    return policy.validate_endpoint(url, mode=mode, resolver=resolver, **kw)


# --- the URL itself ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("url", ["", "   ", "splunk.example:8089", "ftp://good.example/", "file:///etc/passwd", "gopher://good.example/", "javascript:alert(1)",
                                 "https://user:pw@good.example:8089", "https://good.example:8089/#frag", "https://good.example:0", "https://good.example:70000",
                                 "https://", "https://good.example:8089/\x00", "https://good.example:8089/a b", "http://good.example:8089"])
def test_malformed_or_unsafe_urls_are_refused_before_any_lookup(url):
    with pytest.raises(IntegrationError) as exc:
        check(url)
    assert exc.value.kind in ("config", "destination")


def test_a_url_with_credentials_is_refused_and_the_error_does_not_echo_them():
    with pytest.raises(IntegrationError) as exc:
        check("https://admin:hunter2@good.example:8089")
    assert "hunter2" not in str(exc.value)


def test_plain_http_is_for_loopback_only_and_only_when_asked():
    with pytest.raises(IntegrationError):
        check("http://loop.example:8089")
    with pytest.raises(IntegrationError):
        check("http://127.0.0.1:8089")
    ep = check("http://127.0.0.1:8089", allow_http_loopback=True)
    assert ep.scheme == "http" and ep.is_loopback
    with pytest.raises(IntegrationError):
        check("http://good.example:8089", allow_http_loopback=True)


def test_a_normal_https_endpoint_is_normalised():
    ep = check("https://good.example:8089/")
    assert (ep.scheme, ep.host, ep.port, ep.base_url) == ("https", "good.example", 8089, "https://good.example:8089")
    assert ep.addresses == ("93.184.216.34",) and not ep.is_loopback and not ep.is_private


# --- where it points -----------------------------------------------------------------------------------------------
@pytest.mark.parametrize("host", ["meta.example", "v6meta.example", "mapped.example", "zero.example", "mcast.example", "ll6.example"])
@pytest.mark.parametrize("mode", ["local", "hosted"])
def test_metadata_link_local_unspecified_and_multicast_are_never_allowed(host, mode):
    with pytest.raises(IntegrationError) as exc:
        check(f"https://{host}:8089", mode=mode)
    assert exc.value.kind == "destination"


@pytest.mark.parametrize("literal", ["https://169.254.169.254/", "https://[fd00:ec2::254]/", "https://[::ffff:169.254.169.254]/", "https://2852039166/",
                                     "https://0xa9fea9fe/", "https://0251.0376.0251.0376/", "https://169.254.169.254.nip.io/"])
def test_metadata_address_spellings_do_not_get_through_the_real_resolver(literal):
    with pytest.raises(IntegrationError):
        policy.validate_endpoint(literal, mode="local")  # real getaddrinfo: odd spellings resolve to the address and are refused, or do not resolve


def test_private_and_loopback_are_allowed_locally_and_refused_when_hosted():
    assert check("https://lan.example:8089").is_private
    assert check("https://loop.example:8089").is_loopback
    for host in ("lan.example", "loop.example", "cgnat.example"):
        with pytest.raises(IntegrationError) as exc:
            check(f"https://{host}:8089", mode="hosted")
        assert exc.value.kind == "destination"
    assert check("https://good.example:8089", mode="hosted").addresses == ("93.184.216.34",)


def test_one_bad_address_among_several_refuses_the_whole_name():
    with pytest.raises(IntegrationError):
        check("https://mixed.example:8089", mode="hosted")
    assert check("https://mixed.example:8089", mode="local").addresses == ("93.184.216.34", "10.0.0.5")


def test_an_unresolvable_name_is_a_named_error():
    with pytest.raises(IntegrationError) as exc:
        check("https://nowhere.example:8089")
    assert exc.value.kind == "unreachable"


# --- insecure TLS ---------------------------------------------------------------------------------------------------
def test_certificate_checking_cannot_be_switched_off_for_a_public_address():
    with pytest.raises(IntegrationError) as exc:
        check("https://good.example:8089", verify_tls=False)
    assert exc.value.kind == "destination" and "verification" in str(exc.value).lower()


def test_certificate_checking_can_be_switched_off_for_a_private_or_loopback_test_instance():
    assert check("https://loop.example:8089", verify_tls=False).addresses == ("127.0.0.1",)
    assert check("https://lan.example:8089", verify_tls=False).is_private


# --- the transport -------------------------------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    hits: list = []
    redirect_to = None

    def log_message(self, *a):
        pass

    def do_GET(self):
        type(self).hits.append((self.path, self.headers.get("Host")))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", type(self).redirect_to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b'{"ok": true}' if self.path != "/big" else b"x" * 2_000_000
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    Handler.hits = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


def transport(**kw):
    return policy.PolicyTransport(mode=kw.pop("mode", "local"), resolver=kw.pop("resolver", resolver), allow_http_loopback=True, **kw)


def test_the_request_goes_to_the_address_that_was_checked_not_to_a_second_lookup(server):
    port = server.server_address[1]
    DNS["pinned.example"] = ["127.0.0.1"]
    calls = []

    def flipping(host, p):  # a rebinding resolver: the first answer is allowed, every later answer is the metadata address
        calls.append(host)
        return ["127.0.0.1"] if len(calls) == 1 else ["169.254.169.254"]

    status, body = transport(resolver=flipping).send("GET", f"http://pinned.example:{port}/x", {}, None)
    assert status == 200 and body == b'{"ok": true}'
    assert len(calls) == 1 and Handler.hits == [("/x", f"pinned.example:{port}")]  # real server reached with the original Host header


def test_a_redirect_is_refused_and_never_followed(server):
    other = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=other.serve_forever, daemon=True).start()
    try:
        Handler.redirect_to = f"http://127.0.0.1:{other.server_address[1]}/secret"
        with pytest.raises(IntegrationError) as exc:
            transport().send("GET", f"http://127.0.0.1:{server.server_address[1]}/redirect", {}, None)
        assert exc.value.kind == "redirect"
        assert all(path != "/secret" for path, _ in Handler.hits)
    finally:
        other.shutdown()


def test_an_oversized_response_is_cut_off(server):
    with pytest.raises(IntegrationError) as exc:
        transport(max_bytes=100_000).send("GET", f"http://127.0.0.1:{server.server_address[1]}/big", {}, None)
    assert exc.value.kind == "too_large"


def test_every_call_is_checked_again_so_a_name_that_turns_bad_is_refused(server):
    port = server.server_address[1]
    answers = iter([["127.0.0.1"], ["169.254.169.254"]])
    t = transport(resolver=lambda h, p: next(answers))
    assert t.send("GET", f"http://a.example:{port}/", {}, None)[0] == 200
    with pytest.raises(IntegrationError) as exc:
        t.send("GET", f"http://a.example:{port}/", {}, None)
    assert exc.value.kind == "destination"


def test_hosted_mode_refuses_loopback_even_for_a_name_that_looked_public(server):
    with pytest.raises(IntegrationError) as exc:
        transport(mode="hosted").send("GET", f"http://127.0.0.1:{server.server_address[1]}/", {}, None)
    assert exc.value.kind == "destination"
