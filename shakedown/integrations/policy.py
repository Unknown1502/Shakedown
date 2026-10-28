"""Where Shakedown may connect on a user's behalf, and the one HTTP transport integrations use to do it.

A user-entered SIEM URL is a server-side request forgery vector. The rules, in order:

1. The URL must be https (plain http only for an explicitly allowed loopback test instance) with no credentials, query or fragment.
2. The host is resolved HERE and EVERY address it resolves to must be allowed. Cloud-metadata, link-local, unspecified, multicast and
   other non-routable addresses are never allowed. In `hosted` mode loopback, private and carrier-grade-NAT ranges are refused too;
   in `local` mode (the operator's own machine) private and loopback targets are the point of the tool and are allowed.
3. The connection is made to the address that was checked ("pinned"), with the original host name used for the Host header and for
   TLS name checking, so a second DNS answer cannot redirect the request.
4. Redirects are never followed: a 3xx is an error. Nothing is re-checked "across redirects" because there are none.
5. Certificate checking is on. It can be turned off only for a loopback or private address and only in `local` mode.
6. Responses are size-capped.
"""
import http.client
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from shakedown.integrations.base import IntegrationError

MODES = ("local", "hosted")
_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_METADATA = [ipaddress.ip_address(a) for a in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200", "192.0.0.192")]
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
USER_AGENT = "Shakedown-integration/1"


class DestinationError(IntegrationError):
    def __init__(self, message: str, kind: str = "destination"):
        super().__init__(kind, message)


def classify(addr: str) -> str:
    """One of: global, private, cgnat, loopback, link_local, metadata, unspecified, multicast, reserved."""
    ip = ipaddress.ip_address(addr)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    elif ip.version == 6 and ip in _NAT64:
        ip = ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
    if ip in _METADATA:
        return "metadata"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_multicast:
        return "multicast"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if any(ip in n for n in _PRIVATE):
        return "private"
    if ip.version == 4 and ip in _CGNAT:
        return "cgnat"
    return "global" if ip.is_global else "reserved"


def _check_addresses(addresses: tuple, mode: str, host: str) -> None:
    allowed = {"global", "private", "cgnat", "loopback"} if mode == "local" else {"global"}
    for a in addresses:
        cls = classify(a)
        if cls not in allowed:
            where = "hosted mode only connects to public addresses" if cls in ("private", "cgnat", "loopback") else "that class of address is never allowed"
            raise DestinationError(f"{host} resolves to a {cls.replace('_', '-')} address, and {where}")


def default_resolver(host: str, port: int) -> list:
    try:
        return [ipaddress.ip_address(host).compressed]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        raise IntegrationError("unreachable", f"the host name {host!r} could not be resolved") from None
    return [i[4][0] for i in infos]


@dataclass(frozen=True)
class Endpoint:
    scheme: str
    host: str
    port: int
    path: str
    addresses: tuple
    is_loopback: bool
    is_private: bool

    @property
    def base_url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}{self.path}".rstrip("/")

    @property
    def display(self) -> str:
        return f"{self.scheme}://{_mask_host(self.host)}:{self.port}"


def _mask_host(host: str) -> str:
    """A name shown in lists: the first label is shortened. IP addresses are shown as they are."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        parts = host.split(".")
        return host if len(parts) < 3 else parts[0][:2] + "***." + ".".join(parts[1:])


def mask_endpoint(url: str) -> str:
    """The display form of a saved endpoint, without resolving it."""
    try:
        parts, host, port = _split(url, allow_query=True)
    except IntegrationError:
        return "(invalid)"
    return f"{parts.scheme}://{_mask_host(host)}:{port}"


def _split(url: str, allow_query: bool):
    if not isinstance(url, str) or not url.strip():
        raise IntegrationError("config", "an endpoint URL is required")
    url = url.strip()
    if len(url) > 2048 or re.search(r"[\x00-\x20\x7f]", url):
        raise IntegrationError("config", "the endpoint URL contains spaces or control characters, or is too long")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise IntegrationError("config", "the endpoint URL is not valid") from None
    if parts.scheme not in ("https", "http"):
        raise IntegrationError("config", "the endpoint must be an https:// URL")
    if not parts.hostname:
        raise IntegrationError("config", "the endpoint has no host name")
    if "@" in parts.netloc:
        raise IntegrationError("config", "the endpoint URL must not contain a user name or password; enter credentials in the credential fields")
    if parts.fragment or (parts.query and not allow_query):
        raise IntegrationError("config", "the endpoint URL must not contain a query string or fragment")
    host = parts.hostname.lower()
    if not host.isascii():
        raise IntegrationError("config", "use the ASCII (punycode) form of the host name")
    if port == 0 or (port is not None and not 1 <= port <= 65535):
        raise IntegrationError("config", "the port must be between 1 and 65535")
    return parts, host, port or (443 if parts.scheme == "https" else 80)


def validate_endpoint(url: str, *, mode: str = "local", resolver=None, allow_http_loopback: bool = False, verify_tls: bool = True) -> Endpoint:
    if mode not in MODES:
        raise IntegrationError("config", f"unknown mode {mode!r}")
    parts, host, port = _split(url, allow_query=False)
    return _check_origin(parts.scheme, host, port, parts.path or "", mode, resolver or default_resolver, allow_http_loopback, verify_tls)


def _check_origin(scheme, host, port, path, mode, resolver, allow_http_loopback, verify_tls) -> Endpoint:
    try:
        addresses = (ipaddress.ip_address(host).compressed,)  # an IP literal is checked as it is; nothing is looked up
    except ValueError:
        try:
            addresses = tuple(dict.fromkeys(resolver(host, port)))
        except IntegrationError:
            raise
        except (OSError, UnicodeError):
            raise IntegrationError("unreachable", f"the host name {host!r} could not be resolved") from None
    if not addresses:
        raise IntegrationError("unreachable", f"the host name {host!r} did not resolve to any address")
    _check_addresses(addresses, mode, host)
    classes = {classify(a) for a in addresses}
    loopback, private = classes == {"loopback"}, bool(classes & {"private", "cgnat"})
    if scheme == "http" and not (allow_http_loopback and loopback):
        raise IntegrationError("config", "plain http is accepted only for an explicitly allowed loopback test instance; use https")
    if not verify_tls and not classes <= {"loopback", "private"}:
        raise DestinationError("certificate verification can be turned off only for a loopback or private test instance, never for a public address")
    return Endpoint(scheme, host, port, path.rstrip("/"), addresses, loopback, private)


def ssl_context(verify: bool, ca_bundle: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_bundle or None)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _Pinned:
    """Connect to an address that has already been checked; keep the original host for Host and TLS name checking."""

    _ip = ""  # set by the caller after construction

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTP(_Pinned, http.client.HTTPConnection):
    pass


class _PinnedHTTPS(_Pinned, http.client.HTTPSConnection):
    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class PolicyTransport:
    """The only way an integration talks to a SIEM. `send` returns (status, body); a 3xx is an error."""

    def __init__(self, *, mode: str = "local", verify_tls: bool = True, ca_bundle: str | None = None, timeout: float = 30.0,
                 max_bytes: int = 5_000_000, resolver=None, allow_http_loopback: bool = False):
        self.mode, self.verify_tls, self.ca_bundle, self.timeout, self.max_bytes = mode, verify_tls, ca_bundle, timeout, max_bytes
        self.resolver, self.allow_http_loopback = resolver or default_resolver, allow_http_loopback
        self._ctx = ssl_context(verify_tls, ca_bundle)

    def send(self, method: str, url: str, headers: dict, body: bytes | None) -> tuple:
        parts, host, port = _split(url, allow_query=True)
        ep = _check_origin(parts.scheme, host, port, "", self.mode, self.resolver, self.allow_http_loopback, self.verify_tls)  # checked on EVERY call
        target = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
        last: Exception | None = None
        for ip in ep.addresses:
            conn = (_PinnedHTTPS(host, port, context=self._ctx, timeout=self.timeout) if ep.scheme == "https" else _PinnedHTTP(host, port, timeout=self.timeout))
            conn._ip = ip
            try:
                conn.request(method, target, body=body, headers={"User-Agent": USER_AGENT, "Accept": "application/json", "Connection": "close", **headers})
                resp = conn.getresponse()
                data = resp.read(self.max_bytes + 1)
                status = resp.status
            except ssl.SSLCertVerificationError as exc:
                raise IntegrationError("tls", f"TLS certificate verification failed ({getattr(exc, 'verify_message', None) or 'certificate not trusted'}). "
                                              "The certificate must be signed by a CA you trust (add it as a CA bundle) and must name the host you connect to.") from None
            except ssl.SSLError as exc:
                raise IntegrationError("tls", f"the TLS handshake failed ({type(exc).__name__})") from None
            except (OSError, http.client.HTTPException) as exc:
                last = exc
                continue
            finally:
                conn.close()
            if 300 <= status < 400:
                raise IntegrationError("redirect", f"the server answered HTTP {status} (a redirect); Shakedown does not follow redirects")
            if len(data) > self.max_bytes:
                raise IntegrationError("too_large", f"the response exceeded {self.max_bytes} bytes and was discarded")
            return status, data
        reason = "timed out" if isinstance(last, (TimeoutError, socket.timeout)) else type(last).__name__
        raise IntegrationError("unreachable", f"cannot reach {host}:{port} ({reason})")
