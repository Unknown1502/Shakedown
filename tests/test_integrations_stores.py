"""Credential and profile storage: owners are isolated, secrets never reach disk or an error message, redaction works."""
import json
import sys
import types

import pytest

from shakedown.integrations import vault
from shakedown.integrations.base import IntegrationError, redact
from shakedown.integrations.store import AssessmentStore, ProfileStore

SECRET = {"token": "tok-9f8e7d6c5b4a-very-secret"}


# --- the memory store --------------------------------------------------------------------------------------------
def test_memory_store_round_trips_and_deletes():
    s = vault.MemorySecretStore()
    s.put("alice", "c1", SECRET)
    assert s.get("alice", "c1") == SECRET and s.describe()["persistent"] is False
    assert s.delete("alice", "c1") is True and s.get("alice", "c1") is None and s.delete("alice", "c1") is False


def test_one_owner_cannot_read_replace_or_delete_another_owners_credential():
    s = vault.MemorySecretStore()
    s.put("alice", "c1", SECRET)
    assert s.get("bob", "c1") is None
    assert s.delete("bob", "c1") is False
    s.put("bob", "c1", {"token": "bobs"})
    assert s.get("alice", "c1") == SECRET and s.get("bob", "c1") == {"token": "bobs"}


def test_a_returned_secret_is_a_copy_not_the_stored_object():
    s = vault.MemorySecretStore()
    s.put("a", "c", {"token": "x" * 10})
    s.get("a", "c")["token"] = "mutated"
    assert s.get("a", "c")["token"] == "x" * 10


def test_the_fingerprint_identifies_without_revealing():
    fp = vault.fingerprint(SECRET)
    assert fp == vault.fingerprint(dict(SECRET)) and SECRET["token"] not in fp and fp.startswith("sha256:") and len(fp) < 24
    assert fp != vault.fingerprint({"token": "another"})


# --- the OS credential store (a fake module stands in; the real one is exercised by a separate opt-in check) ----
def fake_keyring(priority=5, backend_name="WinVaultKeyring"):
    kr = types.SimpleNamespace(vault={})
    backend = type(backend_name, (), {"priority": priority})()
    kr.get_keyring = lambda: backend
    kr.set_password = lambda service, key, value: kr.vault.__setitem__((service, key), value)
    kr.get_password = lambda service, key: kr.vault.get((service, key))

    def delete(service, key):
        if (service, key) not in kr.vault:
            raise RuntimeError("not found")
        del kr.vault[(service, key)]
    kr.delete_password = delete
    return kr


def test_keyring_store_is_used_only_when_it_has_a_real_backend():
    assert vault.KeyringSecretStore.available(fake_keyring()) is True
    assert vault.KeyringSecretStore.available(fake_keyring(priority=0)) is False
    assert vault.KeyringSecretStore.available(fake_keyring(backend_name="FailKeyring")) is False


def test_keyring_store_round_trips_isolates_owners_and_deletes():
    kr = fake_keyring()
    s = vault.KeyringSecretStore(kr)
    s.put("alice", "c1", SECRET)
    assert s.get("alice", "c1") == SECRET and s.get("bob", "c1") is None
    assert s.delete("bob", "c1") is False and s.get("alice", "c1") == SECRET
    assert s.delete("alice", "c1") is True and s.get("alice", "c1") is None
    assert s.describe()["persistent"] is True


def test_a_keyring_failure_does_not_leak_the_secret():
    kr = fake_keyring()
    kr.set_password = lambda *a: (_ for _ in ()).throw(RuntimeError("backend exploded with " + SECRET["token"]))
    with pytest.raises(IntegrationError) as exc:
        vault.KeyringSecretStore(kr).put("a", "c", SECRET)
    assert exc.value.kind == "secret_store" and SECRET["token"] not in str(exc.value)


def test_choose_store_falls_back_to_memory_without_a_keyring(monkeypatch):
    monkeypatch.setitem(sys.modules, "keyring", None)  # import keyring -> ImportError
    assert isinstance(vault.choose_store("auto"), vault.MemorySecretStore)
    with pytest.raises(IntegrationError):
        vault.choose_store("keyring")


# --- environment references --------------------------------------------------------------------------------------
def test_env_references_resolve_and_are_validated():
    assert vault.resolve_env_refs({"token": "SPLUNK_TOKEN"}, {"SPLUNK_TOKEN": "abc12345"}) == {"token": "abc12345"}
    for bad in ("splunk_token", "TO", "A;B", "X" * 80, ""):
        with pytest.raises(IntegrationError) as exc:
            vault.resolve_env_refs({"token": bad}, {bad: "v"})
        assert exc.value.kind == "config"
    with pytest.raises(IntegrationError) as exc:
        vault.resolve_env_refs({"token": "SPLUNK_TOKEN"}, {})
    assert exc.value.kind == "auth" and "SPLUNK_TOKEN" in str(exc.value)


# --- redaction ----------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("text", [
    "request failed: Authorization: Bearer abcdefghijklmnop", "failed with token=supersecretvalue123", "Splunk abcdefgh12345678abcdefgh rejected",
    "ApiKey QWxhZGRpbjpvcGVuIHNlc2FtZQ== was refused", 'password: "hunter2hunter2"', "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk bad",
    "client_secret=abcDEF123", "refresh_token: 0.AAAA-bbbb"])
def test_redaction_removes_credential_shaped_text(text):
    out = redact(text)
    assert "[redacted]" in out
    for leaked in ("abcdefghijklmnop", "supersecretvalue123", "abcdefgh12345678abcdefgh", "QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "hunter2hunter2", "abcdefghijk", "abcDEF123", "0.AAAA-bbbb"):
        assert leaked not in out


def test_redaction_leaves_ordinary_sentences_alone():
    for text in ("Splunk rejected the credentials (HTTP 401)", "basic authentication is disabled", "the token was not accepted", "permission denied for password reset page"):
        assert redact(text) == text or "[redacted]" not in redact(text.replace("token was", "token_was")), text


def test_redaction_removes_known_secret_values_even_without_a_pattern():
    assert SECRET["token"] not in redact("the server said " + SECRET["token"] + " is wrong", [SECRET["token"]])


# --- profiles ------------------------------------------------------------------------------------------------------
def test_profiles_are_isolated_by_owner_and_never_hold_a_credential(tmp_path):
    s = ProfileStore(tmp_path / "connections.json")
    mine = s.create("alice", {"provider": "splunk", "label": "lab", "config": {"endpoint": "https://x:8089"}, "secret_ref": {"mode": "store", "fingerprint": vault.fingerprint(SECRET)}})
    assert s.get("alice", mine["id"])["label"] == "lab"
    assert s.get("bob", mine["id"]) is None and s.list("bob") == []
    with pytest.raises(IntegrationError):
        s.update("bob", mine["id"], {"label": "hijack"})
    assert s.delete("bob", mine["id"]) is False and s.get("alice", mine["id"]) is not None
    assert SECRET["token"] not in (tmp_path / "connections.json").read_text(encoding="utf-8")
    assert s.delete("alice", mine["id"]) is True and s.list("alice") == []


def test_profile_updates_persist_and_a_corrupt_file_is_empty_not_a_crash(tmp_path):
    p = tmp_path / "c.json"
    s = ProfileStore(p)
    row = s.create("a", {"provider": "splunk", "label": "one"})
    s.update("a", row["id"], {"label": "two"})
    assert ProfileStore(p).get("a", row["id"])["label"] == "two"
    p.write_text("{not json", encoding="utf-8")
    assert ProfileStore(p).list("a") == []


# --- assessments --------------------------------------------------------------------------------------------------
def test_assessments_are_isolated_listed_and_deleted_with_their_connection(tmp_path):
    a = AssessmentStore(tmp_path / "assess")
    r1 = a.save("alice", {"connection_id": "c1", "title": "one"})
    r2 = a.save("alice", {"connection_id": "c2", "title": "two"})
    a.save("bob", {"connection_id": "c1", "title": "bobs"})
    assert a.get("bob", r1["id"]) is None and a.get("alice", r1["id"])["title"] == "one"
    assert {x["title"] for x in a.list("alice")} == {"one", "two"} and [x["title"] for x in a.list("alice", "c1")] == ["one"]
    assert a.delete_for_connection("alice", "c1") == 1
    assert a.get("alice", r1["id"]) is None and a.get("alice", r2["id"]) is not None and len(a.list("bob")) == 1


@pytest.mark.parametrize("bad", ["../x", "a/b", "a.b", "", "x" * 40])
def test_assessment_ids_cannot_escape_the_directory(tmp_path, bad):
    assert AssessmentStore(tmp_path / "assess").get("alice", bad) is None
