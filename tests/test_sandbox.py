import json
from pathlib import Path

import pytest

from shakedown.harness.checker import CheckerError
from shakedown.harness.sandbox import (
    SandboxConfig, interpret_result, plan_run, redact, OfflineSpawn,
)


def config(tmp_path, datasets=None):
    return SandboxConfig(datasets=datasets or {})


def test_plan_run_places_rules_and_uses_baked_in_datasets(tmp_path):
    dev = tmp_path / "win7-x86"
    dev.mkdir()
    plan = plan_run(config(tmp_path, {dev.resolve(): "/data/win7-x86"}), {"a": "title: a", "b": "title: b"}, [dev])
    assert plan.files == {"/work/rules/r0000.yml": b"title: a", "/work/rules/r0001.yml": b"title: b"}
    assert plan.args[-2:] == ["--evtx-path", "/data/win7-x86"]
    assert "--rule-path" in plan.args and plan.args[plan.args.index("--rule-path") + 1] == "/work/rules"


def test_plan_run_uploads_adhoc_directories_with_relative_names(tmp_path):
    attack = tmp_path / "attack"
    (attack / "sub").mkdir(parents=True)
    (attack / "one.evtx").write_bytes(b"AAA")
    (attack / "sub" / "two.evtx").write_bytes(b"BBB")
    (attack / "notes.txt").write_bytes(b"ignored")
    plan = plan_run(config(tmp_path), {"c": "x"}, [attack])
    assert plan.files["/work/evtx/0/one.evtx"] == b"AAA"
    assert plan.files["/work/evtx/0/sub/two.evtx"] == b"BBB"
    assert not any(p.endswith("notes.txt") for p in plan.files)
    assert plan.args[-2:] == ["--evtx-path", "/work/evtx/0"]


def test_plan_run_never_uses_model_labels_in_guest_paths(tmp_path):
    plan = plan_run(config(tmp_path), {"../../etc/passwd": "x"}, [])
    assert list(plan.files) == ["/work/rules/r0000.yml"]


def test_plan_run_rejects_empty_rules(tmp_path):
    with pytest.raises(ValueError):
        plan_run(config(tmp_path), {}, [])


def line(rule_id, file="x.evtx"):
    return json.dumps({"RuleId": rule_id, "File": f"C:\\logs\\{file}", "Event": "e"})


def test_interpret_result_parses_matches():
    run = interpret_result(0, line("r1") + "\nnot json\n", "", False, False, 1.5)
    assert [m.rule_id for m in run.matches] == ["r1"]
    assert run.matches[0].evtx_file == "x.evtx"
    assert run.ignored_lines == ["not json"]
    assert run.duration_s == 1.5


@pytest.mark.parametrize("exit_code,truncated,timed_out,needle", [
    (2, False, False, "exited 2"),
    (0, True, False, "too many"),
    (0, False, True, "timed out"),
])
def test_interpret_result_refuses_untrustworthy_output(exit_code, truncated, timed_out, needle):
    with pytest.raises(CheckerError, match=needle):
        interpret_result(exit_code, line("r1"), "boom", truncated, timed_out, 1.0)


def test_redact_removes_tokens_and_request_dumps(monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "secret-key-123")
    text = "failed Authorization: Bearer abc.def.ghi key=secret-key-123 RequestInfo(url=x, headers={'a': 1})"
    out = redact(text)
    assert "abc.def.ghi" not in out and "secret-key-123" not in out and "headers" not in out


def test_offline_spawn_serialises_networking_off():
    import cattrs
    from contree_sdk.utils.codecs import io_encode
    req = OfflineSpawn(command="/opt/checker", image="i", hostname="h", cwd="", stdin=io_encode(""),
                       truncate_output_at=1, files={})
    body = cattrs.unstructure(req)
    assert body["networking"] == {"enabled": False}
    assert body["uid"] == 65534 and body["gid"] == 65534
    assert body["disposable"] is True
