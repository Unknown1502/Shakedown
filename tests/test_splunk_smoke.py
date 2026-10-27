"""The smoke tool records a verification only after a successful run. These tests use the mock server, so they must never write
the real evidence file: every call passes --proof-path (or --no-record)."""
import json
import sys
from pathlib import Path

from fake_splunk import TOKEN, FakeSplunk
from test_splunk import make_handler

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import splunk_smoke  # noqa: E402

from shakedown import splunk  # noqa: E402


def env(fake, token=TOKEN):
    return {"SPLUNK_BASE_URL": fake.url, "SPLUNK_TOKEN": token, "SPLUNK_ALLOWED_INDEXES": "win"}


def test_a_successful_run_records_proof_without_any_secret(tmp_path):
    proof = tmp_path / "proof.json"
    with FakeSplunk(make_handler(coverage=25)) as fake:
        code = splunk_smoke.main(["--index", "win", "--proof-path", str(proof)], env=env(fake))
        assert fake.jobs == {}  # its search job was deleted
    saved = json.loads(proof.read_text(encoding="utf-8"))
    assert code == 0 and "bounded coverage search completed" in saved["checks"] and saved["target_is_loopback"] is True
    assert TOKEN not in proof.read_text(encoding="utf-8") and "127.0.0.1" not in proof.read_text(encoding="utf-8")
    assert splunk.live_verification(proof)["live_verified"] is True


def test_a_failed_run_records_nothing(tmp_path):
    proof = tmp_path / "proof.json"
    with FakeSplunk(make_handler()) as fake:
        code = splunk_smoke.main(["--index", "win", "--proof-path", str(proof)], env=env(fake, token="wrong"))
    assert code == 1 and not proof.exists()


def test_an_index_outside_the_allowed_list_is_refused_before_any_request(tmp_path):
    proof = tmp_path / "proof.json"
    with FakeSplunk(make_handler()) as fake:
        code = splunk_smoke.main(["--index", "hr_secrets", "--proof-path", str(proof)], env=env(fake))
        assert code == 1 and fake.requests == [] and not proof.exists()


def test_no_record_runs_the_checks_but_writes_nothing(tmp_path):
    proof = tmp_path / "proof.json"
    with FakeSplunk(make_handler()) as fake:
        assert splunk_smoke.main(["--index", "win", "--proof-path", str(proof), "--no-record"], env=env(fake)) == 0
    assert not proof.exists()
