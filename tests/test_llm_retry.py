"""Transient Token Factory errors (429/5xx, e.g. the 529 'System is overloaded') are retried; client errors are not."""
import pytest

from shakedown.llm import TokenFactory, TokenFactoryError


class Flaky(TokenFactory):
    def __init__(self, outcomes):
        super().__init__("k")
        self.outcomes, self.calls, self.slept = list(outcomes), 0, []

    def _send(self, method, path, body):
        self.calls += 1
        item = self.outcomes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item, 0.1

    def _sleep(self, seconds):
        self.slept.append(seconds)


def test_retries_overload_then_succeeds():
    tf = Flaky([TokenFactoryError("HTTP 529 on POST /x: overloaded", status=529), {"ok": 1}])
    data, _ = tf._request("POST", "/x", {})
    assert data == {"ok": 1} and tf.calls == 2 and len(tf.slept) == 1


def test_does_not_retry_client_errors():
    tf = Flaky([TokenFactoryError("HTTP 400 on POST /x: bad", status=400), {"ok": 1}])
    with pytest.raises(TokenFactoryError):
        tf._request("POST", "/x", {})
    assert tf.calls == 1 and tf.slept == []


def test_gives_up_after_max_attempts():
    tf = Flaky([TokenFactoryError("HTTP 529", status=529)] * 4)
    with pytest.raises(TokenFactoryError):
        tf._request("POST", "/x", {})
    assert tf.calls == tf.max_attempts == 4
    assert tf.slept == sorted(tf.slept) and len(tf.slept) == 3   # exponential backoff, no sleep after the last try


class Replies(TokenFactory):
    def __init__(self, contents):
        super().__init__("k")
        self.contents, self.calls = list(contents), 0

    def _send(self, method, path, body):
        self.calls += 1
        content = self.contents.pop(0)
        return {"choices": [{"message": {"content": content}}], "model": "m", "usage": {}}, 0.1

    def _sleep(self, seconds):
        pass


SCHEMA = {"type": "object", "properties": {"a": {"type": "integer"}}, "required": ["a"]}


def test_non_json_content_is_retried_then_succeeds():
    tf = Replies(['{"behavior": "complete", "logsource', '{"a": 1}'])
    out = tf.chat_json("m", [{"role": "user", "content": "x"}], SCHEMA, name="t")
    assert out.data == {"a": 1} and tf.calls == 2


def test_non_json_content_gives_up_after_three_tries():
    tf = Replies(["not json"] * 3)
    with pytest.raises(TokenFactoryError, match="non-JSON"):
        tf.chat_json("m", [{"role": "user", "content": "x"}], SCHEMA, name="t")
    assert tf.calls == 3
