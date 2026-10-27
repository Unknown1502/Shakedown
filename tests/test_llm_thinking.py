"""The thinking switch reaches the request body only when turned off."""
from shakedown.llm import TokenFactory

REPLY = {"choices": [{"message": {"content": "{\"a\": 1}"}}], "model": "m", "usage": {}}


class Capture(TokenFactory):
    def __init__(self):
        super().__init__("k")
        self.bodies = []

    def _send(self, method, path, body):
        self.bodies.append(body)
        return REPLY, 0.1


SCHEMA = {"type": "object", "properties": {"a": {"type": "integer"}}, "required": ["a"]}


def test_thinking_on_by_default_sends_no_template_override():
    tf = Capture()
    tf.chat_json("m", [{"role": "user", "content": "x"}], SCHEMA, name="t")
    assert "chat_template_kwargs" not in tf.bodies[0]


def test_thinking_off_sends_enable_thinking_false():
    tf = Capture()
    tf.chat_json("m", [{"role": "user", "content": "x"}], SCHEMA, name="t", thinking=False)
    assert tf.bodies[0]["chat_template_kwargs"] == {"enable_thinking": False}
