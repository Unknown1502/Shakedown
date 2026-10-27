"""Regression tests for defects the LIVE Splunk run exposed (Splunk Enterprise 10.6.1.1). They use mocks, so they only pin the
fixes; the evidence that the connector works against a real Splunk is in evidence/splunk_live_verification/REPORT.md."""
import ssl
import urllib.error

import pytest
from fake_splunk import TOKEN, FakeSplunk
from test_splunk import HOUR, RULE, make_handler

from shakedown import splunk
from shakedown.splunk import SplunkConfig, SplunkConnector, SplunkError


def conn(fake, **kw):
    cfg = SplunkConfig(base_url=fake.url, token=TOKEN, allowed_indexes=("win",), search_timeout_s=3, **kw)
    return SplunkConnector(cfg, poll_interval_s=0.02)


def test_default_write_capable_capabilities_are_warned_about_not_silently_accepted():
    """Splunk adds edit_own_objects, run_collect, run_mcollect and schedule_rtsearch to every new role. The connector never uses them,
    but an account described as search-only that holds them should be flagged."""
    extras = ("search", "edit_own_objects", "list_all_objects", "run_collect", "run_mcollect", "schedule_rtsearch")
    with FakeSplunk(make_handler(), capabilities=extras) as fake:
        identity = conn(fake)._identity()
    text = " ".join(identity["warnings"])
    assert "run_collect" in text and "run_mcollect" in text and "edit_own_objects" in text
    assert "list_all_objects" not in text  # a read capability is not a write risk


def test_an_exactly_search_only_account_has_no_warnings():
    with FakeSplunk(make_handler(), capabilities=("search",)) as fake:
        assert conn(fake)._identity()["warnings"] == []


def test_a_missing_sigma_cli_is_a_named_conversion_error_not_a_traceback(monkeypatch):
    def missing():
        raise RuntimeError("sigma-cli is not installed in this environment")
    monkeypatch.setattr(splunk, "_sigma_exe", missing)
    with pytest.raises(SplunkError) as exc:
        splunk.convert_to_spl(RULE)
    assert exc.value.kind == "conversion" and "sigma" in str(exc.value).lower()


def test_a_tls_certificate_failure_is_reported_as_tls_with_the_remedy(monkeypatch):
    err = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: IP address mismatch")
    err.verify_message = "IP address mismatch, certificate is not valid for '127.0.0.1'."

    def boom(*args, **kwargs):
        raise urllib.error.URLError(err)
    cfg = SplunkConfig(base_url="https://splunk.example:8089", token="t", allowed_indexes=("win",))
    monkeypatch.setattr(splunk.urllib.request, "urlopen", boom)
    with pytest.raises(SplunkError) as exc:
        SplunkConnector(cfg)._request("GET", "/services/authentication/current-context")
    assert exc.value.kind == "tls" and "SPLUNK_CA_BUNDLE" in str(exc.value) and "IP address mismatch" in str(exc.value)


def test_an_ordinary_connection_failure_is_still_unavailable(monkeypatch):
    def boom(*args, **kwargs):
        raise urllib.error.URLError(ConnectionRefusedError())
    cfg = SplunkConfig(base_url="https://splunk.example:8089", token="t", allowed_indexes=("win",))
    monkeypatch.setattr(splunk.urllib.request, "urlopen", boom)
    with pytest.raises(SplunkError) as exc:
        SplunkConnector(cfg)._request("GET", "/services/authentication/current-context")
    assert exc.value.kind == "unavailable"


def test_a_proof_from_a_loopback_instance_says_so_in_its_label(tmp_path):
    import json
    proof = tmp_path / "proof.json"
    proof.write_text(json.dumps({"verified_at": "2026-10-27T00:00:00+00:00", "target_is_loopback": True, "server_version": "10.6.1.1"}), encoding="utf-8")
    status = splunk.live_verification(proof)
    assert status["live_verified"] is True and status["target_is_loopback"] is True
    assert "loopback test instance" in status["label"]
    proof.write_text(json.dumps({"verified_at": "2026-10-27T00:00:00+00:00", "target_is_loopback": False}), encoding="utf-8")
    assert splunk.live_verification(proof)["label"] == "live-verified"
