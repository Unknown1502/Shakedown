"""The read-only Splunk preflight connector. ALL TESTS HERE USE A MOCK SERVER (tests/fake_splunk.py): they exercise real HTTP
and JSON handling but are not evidence of a working live integration. Live verification is tools/splunk_smoke.py."""
import json
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fake_splunk import TOKEN, FakeSplunk

from shakedown import splunk
from shakedown.splunk import SplunkConfig, SplunkConnector, SplunkError

RULE = """title: T
id: 11111111-2222-4333-8444-555555555555
status: test
description: d
author: a
date: 2026-10-27
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\x.exe'
        CommandLine|contains: 'evil'
    condition: selection
falsepositives:
    - admin tools
level: low
"""
DETECT = 'Image="*\\\\x.exe" CommandLine="*evil*"'
NOW = datetime.now(timezone.utc)
HOUR = (NOW - timedelta(hours=1), NOW)


@pytest.fixture(autouse=True)
def fixed_conversion(monkeypatch):
    monkeypatch.setattr(splunk, "convert_to_spl", lambda rule_text: DETECT)


def make_handler(coverage=1000, fields=("Image", "CommandLine", "EventCode"), matches=3, examples=None, **extra):
    def handle(spl, earliest, latest):
        if "fieldsummary" in spl:
            return {"count": len(fields), "results": [{"field": f} for f in fields]}
        if "min(_time)" in spl:
            return {"count": 1, "results": [{"count": str(coverage), "first": "1", "last": "2"}]}
        if "| table" in spl:
            ex = examples if examples is not None else [{"_time": "t", "Image": "C:\\x.exe", "CommandLine": "evil " + "A" * 600}] * min(matches, 50)
            return {"count": len(ex), "results": ex}
        if "stats count" in spl:
            return {"count": 1, "results": [{"count": str(matches)}]}
        return {"count": 0, "results": []}
    return handle


def config(fake, **kw):
    base = dict(base_url=fake.url, token=TOKEN, allowed_indexes=("win", "other"), search_timeout_s=3, max_results=5)
    base.update(kw)
    return SplunkConfig(**base)


def connector(fake, **kw):
    return SplunkConnector(config(fake, **kw), poll_interval_s=0.02)


def run(fake, indexes=("win",), window=HOUR, **kw):
    return connector(fake, **kw).preflight(RULE, indexes=list(indexes), earliest=window[0], latest=window[1])


# --- configuration and secrets -------------------------------------------------------------------------------------
def test_missing_configuration_names_the_variables_without_values():
    with pytest.raises(SplunkError) as exc:
        SplunkConfig.from_env({})
    assert exc.value.kind == "config" and "SPLUNK_BASE_URL" in str(exc.value) and "SPLUNK_ALLOWED_INDEXES" in str(exc.value)


def test_config_reads_the_environment_and_hides_secrets_in_repr():
    cfg = SplunkConfig.from_env({"SPLUNK_BASE_URL": "https://splunk.example:8089", "SPLUNK_TOKEN": "s3cret-token-value",
                                 "SPLUNK_ALLOWED_INDEXES": "win, sysmon", "SPLUNK_MAX_RESULTS": "7"})
    assert cfg.allowed_indexes == ("win", "sysmon") and cfg.max_results == 7 and cfg.verify_tls is True
    assert "s3cret-token-value" not in repr(cfg) and "s3cret-token-value" not in str(cfg)


def test_plain_http_is_allowed_only_for_loopback():
    with pytest.raises(SplunkError, match="https"):
        SplunkConfig(base_url="http://splunk.example:8089", token="t", allowed_indexes=("a",))
    SplunkConfig(base_url="http://127.0.0.1:8089", token="t", allowed_indexes=("a",))


def test_credentials_never_appear_in_the_result():
    with FakeSplunk(make_handler()) as fake:
        out = run(fake)
    assert TOKEN not in json.dumps(out)


# --- read-only guard ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("spl", [
    "search index=a | outputlookup x.csv", "search index=a | collect index=b", "search index=a | delete",
    "search index=a | sendemail to=x@y", "search index=a | rest /services/server/info", "search index=a | script foo",
    "search index=a | map search=\"search index=b\"", "search index=a [search index=b | head 1]", "search index=a `my_macro`",
    "search index=a | mcollect index=m", "search index=a | outputcsv f", "search index=a | tscollect namespace=n",
])
def test_write_capable_or_unknown_spl_is_refused_locally(spl):
    with pytest.raises(SplunkError) as exc:
        splunk.check_read_only(spl)
    assert exc.value.kind == "unsafe_query"


def test_the_commands_the_preflight_uses_are_allowed_and_quoted_pipes_are_not_commands():
    splunk.check_read_only('search index="a" Image="*a|b*" | stats count min(_time) as first')
    splunk.check_read_only('search index="a" | head 5 | table _time, Image')
    splunk.check_read_only('search index="a" | head 1000 | fieldsummary maxvals=1 | fields field')


def test_a_refused_query_sends_nothing(monkeypatch):
    monkeypatch.setattr(splunk, "convert_to_spl", lambda rule_text: 'Image="x" | outputlookup evil.csv')
    with FakeSplunk(make_handler()) as fake:
        with pytest.raises(SplunkError) as exc:
            run(fake)
        assert exc.value.kind == "unsafe_query" and fake.searches == []


def test_only_search_job_endpoints_can_be_called(monkeypatch):
    with FakeSplunk(make_handler()) as fake:
        conn = connector(fake)
        for method, path in [("POST", "/services/saved/searches"), ("GET", "/services/alerts"), ("POST", "/services/data/indexes"),
                             ("DELETE", "/services/saved/searches/x"), ("POST", "/services/authorization/roles")]:
            with pytest.raises(SplunkError) as exc:
                conn._request(method, path)
            assert exc.value.kind == "forbidden_endpoint"
        assert fake.requests == []


def test_a_whole_run_touches_only_read_endpoints_and_cleans_up():
    with FakeSplunk(make_handler()) as fake:
        run(fake)
        allowed = re.compile(r"^/services/(authentication/current-context|search/jobs(/[A-Za-z0-9_.\-]+(/(results|control))?)?)$")
        assert fake.requests and all(allowed.match(p) for p in fake.paths())
        assert not any("saved" in p or "alert" in p for p in fake.paths())
        assert fake.jobs == {}  # every job it created was deleted


# --- scope -----------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("indexes", [[], ["*"], ["secret_hr"], ["win", "secret_hr"], [""]])
def test_only_allowed_named_indexes_can_be_searched(indexes):
    with FakeSplunk(make_handler()) as fake:
        with pytest.raises(SplunkError) as exc:
            run(fake, indexes=indexes)
        assert exc.value.kind == "scope" and fake.searches == []


def test_the_time_range_is_required_bounded_and_sane():
    with FakeSplunk(make_handler()) as fake:
        too_wide = (NOW - timedelta(days=30), NOW)
        for window in [too_wide, (NOW, NOW - timedelta(hours=1)), (NOW - timedelta(hours=1), NOW + timedelta(days=2))]:
            with pytest.raises(SplunkError) as exc:
                run(fake, window=window)
            assert exc.value.kind == "scope"
        assert fake.searches == []


def test_every_search_carries_the_index_scope_the_log_source_scope_and_the_window():
    with FakeSplunk(make_handler()) as fake:
        out = run(fake, indexes=["win", "other"])
    assert fake.searches
    for form in fake.searches:
        assert form["search"].startswith("search ") and 'index="win"' in form["search"] and 'index="other"' in form["search"]
        assert 'source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"' in form["search"] and "EventCode=1" in form["search"]
        assert form["earliest_time"] == str(int(HOUR[0].timestamp())) and form["latest_time"] == str(int(HOUR[1].timestamp()))
    assert out["scope"]["indexes"] == ["win", "other"] and out["scope"]["logsource_scope"].startswith("source=")


# --- outcomes --------------------------------------------------------------------------------------------------------
def test_matches_are_reported_as_potential_matches_with_a_bounded_sample():
    with FakeSplunk(make_handler(matches=42)) as fake:
        out = run(fake)
    assert out["status"] == "potential_matches_found" and out["matches"]["count"] == 42
    assert len(out["matches"]["examples"]) <= 5 and all(len(str(v)) <= 303 for e in out["matches"]["examples"] for v in e.values())
    assert out["queries"]["detection"].count(DETECT) == 1 and out["coverage"]["events_in_scope"] == 1000


def test_zero_matches_with_telemetry_present_is_no_matches_in_the_window():
    with FakeSplunk(make_handler(matches=0)) as fake:
        out = run(fake)
    assert out["status"] == "no_matches_in_window" and out["matches"]["count"] == 0
    assert any("does not show" in n for n in out["notes"])


def test_no_events_of_the_required_log_source_is_missing_telemetry_not_zero_matches():
    with FakeSplunk(make_handler(coverage=0, matches=0)) as fake:
        out = run(fake)
    assert out["status"] == "telemetry_missing_or_unsupported" and out["status_detail"] == "no_events_in_scope"
    assert not [s for s in fake.searches if "stats count" in s["search"] and "min(_time)" not in s["search"]]  # did not claim a zero


def test_a_rule_field_that_never_appears_is_an_unsupported_field_not_a_clean_result():
    with FakeSplunk(make_handler(fields=("Image", "EventCode"), matches=0)) as fake:  # CommandLine is not extracted
        out = run(fake)
    assert out["status"] == "telemetry_missing_or_unsupported" and out["status_detail"] == "fields_not_observed"
    assert out["fields"]["missing"] == ["CommandLine"] and out["fields"]["observed"] == ["EventCode", "Image"] or "Image" in out["fields"]["observed"]


def test_a_query_error_is_reported_as_a_query_error():
    def handler(spl, e, l):
        if "min(_time)" in spl:
            return {"count": 1, "results": [{"count": "10", "first": "1", "last": "2"}]}
        if "fieldsummary" in spl:
            return {"count": 3, "results": [{"field": "Image"}, {"field": "CommandLine"}, {"field": "EventCode"}]}
        return {"error": "Error in 'search' command: Unable to parse the search", "status": 400}
    with FakeSplunk(handler) as fake:
        with pytest.raises(SplunkError) as exc:
            run(fake)
    assert exc.value.kind == "query" and "Unable to parse" in str(exc.value)


def test_bad_credentials_and_missing_permission_are_distinct():
    with FakeSplunk(make_handler()) as fake:
        with pytest.raises(SplunkError) as exc:
            connector(fake, token="wrong").preflight(RULE, indexes=["win"], earliest=HOUR[0], latest=HOUR[1])
        assert exc.value.kind == "auth"
    with FakeSplunk(make_handler(), context_status=403) as fake:
        with pytest.raises(SplunkError) as exc:
            run(fake)
        assert exc.value.kind == "permission"


def test_an_unreachable_server_is_unavailable():
    cfg = SplunkConfig(base_url="http://127.0.0.1:9", token="t", allowed_indexes=("win",), search_timeout_s=1)
    with pytest.raises(SplunkError) as exc:
        SplunkConnector(cfg, poll_interval_s=0.01).preflight(RULE, indexes=["win"], earliest=HOUR[0], latest=HOUR[1])
    assert exc.value.kind == "unavailable"


# --- identity and privilege -----------------------------------------------------------------------------------------
def test_an_admin_class_account_is_refused_by_default():
    with FakeSplunk(make_handler(), capabilities=("search", "admin_all_objects", "edit_user")) as fake:
        with pytest.raises(SplunkError) as exc:
            run(fake)
        assert exc.value.kind == "privileged_account" and fake.searches == []
    with FakeSplunk(make_handler(), capabilities=("search", "admin_all_objects")) as fake:
        out = run(fake, allow_privileged=True)
        assert out["identity"]["warnings"]


def test_a_search_only_account_is_accepted_and_recorded():
    with FakeSplunk(make_handler(), username="svc_preflight", capabilities=("search",)) as fake:
        out = run(fake)
    assert out["identity"]["username"] == "svc_preflight" and out["identity"]["capabilities"] == ["search"]


# --- timeouts, cancellation, limits --------------------------------------------------------------------------------
def test_a_search_that_does_not_finish_is_cancelled_and_deleted():
    def handler(spl, e, l):
        return {"never": True, "count": 0, "results": []}
    with FakeSplunk(handler) as fake:
        started = time.monotonic()
        with pytest.raises(SplunkError) as exc:
            run(fake, search_timeout_s=0.3)
        assert exc.value.kind == "timeout" and time.monotonic() - started < 5
        assert ("POST", "/services/search/jobs/sid1/control") in fake.requests and ("DELETE", "/services/search/jobs/sid1") in fake.requests
        assert fake.jobs == {}


def test_a_running_preflight_can_be_cancelled():
    def handler(spl, e, l):
        return {"never": True, "count": 0, "results": []}
    with FakeSplunk(handler) as fake:
        conn = connector(fake, search_timeout_s=30)
        threading.Timer(0.3, conn.cancel).start()
        with pytest.raises(SplunkError) as exc:
            conn.preflight(RULE, indexes=["win"], earliest=HOUR[0], latest=HOUR[1])
        assert exc.value.kind == "cancelled" and fake.jobs == {}


def test_the_number_of_events_shown_is_capped():
    many = [{"_time": str(i), "Image": "x"} for i in range(500)]
    with FakeSplunk(make_handler(matches=500, examples=many)) as fake:
        out = run(fake, max_results=3)
    assert len(out["matches"]["examples"]) == 3 and out["matches"]["count"] == 500


# --- live-verification label, isolation from the model, real conversion ----------------------------------------------
def test_the_connector_is_not_live_verified_until_a_smoke_test_recorded_success(tmp_path):
    assert splunk.live_verification(tmp_path / "missing.json")["live_verified"] is False
    proof = tmp_path / "proof.json"
    proof.write_text(json.dumps({"verified_at": "2026-10-28T00:00:00+00:00", "server_version": "9.4.1"}), encoding="utf-8")
    status = splunk.live_verification(proof)
    assert status["live_verified"] is True and status["server_version"] == "9.4.1"
    with FakeSplunk(make_handler()) as fake:
        assert run(fake)["connector"]["live_verified"] is False  # a mock never counts


def test_the_connector_has_no_path_to_the_model():
    source = Path(splunk.__file__).read_text(encoding="utf-8")
    assert "shakedown.llm" not in source and "chat_json" not in source and "shakedown.pipeline" not in source


def test_the_real_sigma_cli_converts_a_rule_to_spl(monkeypatch):
    monkeypatch.undo()  # use the real converter in this one test
    query = splunk.convert_to_spl(RULE)
    assert "Image" in query and "x.exe" in query and "CommandLine" in query and "evil" in query
    splunk.check_read_only("search index=a " + query)


def test_unsupported_log_sources_are_reported_not_guessed():
    assert splunk.logsource_scope("process_creation")["EventCode"] == 1
    assert "4688" in splunk.logsource_scope("process_creation")["note"]
    with pytest.raises(SplunkError) as exc:
        splunk.logsource_scope("firewall")
    assert exc.value.kind == "unsupported_logsource"
