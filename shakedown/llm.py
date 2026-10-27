"""Nebius Token Factory client (OpenAI-compatible) and NVIDIA model selection.

Model IDs are always chosen from the live /v1/models listing; nothing here assumes an ID exists.
"""
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

API_BASE = "https://api.tokenfactory.nebius.com/v1"
# The hackathon requires an NVIDIA open model; on Token Factory those are published under this owner prefix.
ELIGIBLE_PREFIX = "nvidia/"


class ModelSelectionError(ValueError):
    pass


class TokenFactoryError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, transient: bool = False):
        super().__init__(message)
        self.status = status
        self.transient = transient


class NoJSONError(TokenFactoryError):
    """The model answered three times without parseable JSON (for example an empty string)."""


# Overload (529), rate limit (429) and gateway/server errors are worth retrying; other 4xx are our mistakes.
RETRY_STATUS = {429, 500, 502, 503, 504, 529}


def select_model(listed_ids: list[str], preferences: tuple[str, ...], override: str | None = None) -> str:
    """Pick an NVIDIA model from the listing: the override if given, else the first preference that matches."""
    eligible = [m for m in listed_ids if m.lower().startswith(ELIGIBLE_PREFIX)]
    if override is not None:
        if override not in eligible:
            raise ModelSelectionError(f"{override!r} is not a listed NVIDIA model")
        return override
    for pref in preferences:
        for model_id in eligible:
            if pref.lower() in model_id.lower():
                return model_id
    raise ModelSelectionError(f"no listed NVIDIA model matches {preferences!r}")


@dataclass(frozen=True)
class Completion:
    model: str
    data: dict
    reasoning: str | None
    usage: dict
    latency_s: float
    response_format: str


class TokenFactory:
    def __init__(self, api_key: str, base_url: str = API_BASE, timeout_s: int = 120):
        self._key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s

    @classmethod
    def from_env(cls) -> "TokenFactory":
        key = os.environ.get("NEBIUS_API_KEY")
        if not key:
            raise TokenFactoryError("NEBIUS_API_KEY is not set")
        return cls(key)

    max_attempts = 4

    def _sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def _request(self, method: str, path: str, body: dict | None = None) -> tuple[dict, float]:
        for attempt in range(self.max_attempts):
            try:
                return self._send(method, path, body)
            except TokenFactoryError as exc:
                retryable = exc.transient or exc.status in RETRY_STATUS
                if not retryable or attempt == self.max_attempts - 1:
                    raise
                self._sleep(2.0 * 2 ** attempt)
        raise AssertionError("unreachable")

    def _send(self, method: str, path: str, body: dict | None = None) -> tuple[dict, float]:
        req = urllib.request.Request(
            f"{self.base_url}{path}", method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self._key}", "Content-Type": "application/json"},
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                return json.loads(resp.read()), time.monotonic() - started
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise TokenFactoryError(f"HTTP {exc.code} on {method} {path}: {detail}", status=exc.code) from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            raise TokenFactoryError(f"network error on {method} {path}: {exc}", transient=True) from exc

    def list_models(self) -> list[dict]:
        data, _ = self._request("GET", "/models?verbose=true")
        return data.get("data", [])

    def chat_json(self, model: str, messages: list[dict], schema: dict, name: str,
                  max_tokens: int = 2048, temperature: float = 0.0, thinking: bool = True) -> Completion:
        """Chat completion constrained to `schema`. Tries the OpenAI-standard response_format first and
        falls back to the bare-schema form shown in the Token Factory docs; records which one worked."""
        formats = {
            "openai_json_schema": {"type": "json_schema", "json_schema": {"name": name, "schema": schema, "strict": True}},
            "bare_json_schema": {"type": "json_schema", "json_schema": schema},
        }
        rejected = []
        for label, response_format in formats.items():
            body = {"model": model, "messages": messages, "max_tokens": max_tokens,
                    "temperature": temperature, "response_format": response_format}
            if not thinking:
                # Measured: with thinking on, Nemotron Super often returns an empty JSON skeleton under a strict
                # schema (3-5 of 8 trials); with it off, 0 of 8. See docs/EVALUATION_METHODOLOGY.md, Run 4.
                body["chat_template_kwargs"] = {"enable_thinking": False}
            try:
                # The model occasionally returns truncated or non-JSON text under a schema; resample up to 3 times.
                for attempt in range(3):
                    data, latency = self._request("POST", "/chat/completions", body)
                    message = data["choices"][0]["message"]
                    content = message.get("content") or ""
                    try:
                        parsed = json.loads(content)
                        break
                    except json.JSONDecodeError as exc:
                        if attempt == 2:
                            raise NoJSONError(f"model returned non-JSON content: {content[:300]!r}") from exc
            except TokenFactoryError as exc:
                if "HTTP 400" not in str(exc):
                    raise
                rejected.append(f"{label}: {exc}")
                continue
            return Completion(model=data.get("model", model), data=parsed,
                              reasoning=message.get("reasoning_content") or message.get("reasoning"),
                              usage=data.get("usage") or {}, latency_s=latency, response_format=label)
        raise TokenFactoryError("both response_format variants rejected: " + " | ".join(rejected))
