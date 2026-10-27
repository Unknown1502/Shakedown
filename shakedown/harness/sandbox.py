"""Evaluate Sigma rules inside a Nebius Token Factory Sandbox (Contree microVM, no network interface).

Same contract as `harness.checker.run_checker`: rules (label -> YAML) and EVTX directories in, a
`CheckerRun` out. The checker binary, `thor.yml` and the benign baseline logs are baked into one
immutable image (see `build_eval_image`), so each evaluation only uploads the candidate rules and, for
attack fixtures, the few EVTX files. Every run is disposable and starts the VM with
`networking.enabled=false`.

contree-sdk 0.3.6 has no `networking` option on its run call, but the REST API accepts it; `OfflineSpawn`
adds the field to the SDK's own request type (verified: only `lo` exists inside the VM, DNS fails).
The SDK is pinned, and `tests/test_sandbox.py` checks the serialised request.
"""
import asyncio
import hashlib
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from shakedown.harness.checker import CheckerError, CheckerRun, parse_output

IMAGE_TAG = "shakedown-eval:v1"
BASE_TAG = "shakedown-base-debian:bookworm-slim"
# The Sandbox importer answers 404 for the digest-pinned reference the local runner uses, so the base is
# imported by tag; the build record stores the image UUID it resolved to. The checker is a static Go binary.
BASE_REF = "docker://docker.io/library/debian:bookworm-slim"
NOBODY = 65534
MAX_OUTPUT = 10 * 1024 * 1024  # the API's ceiling for captured stdout/stderr


@dataclass(frozen=True)
class SandboxConfig:
    datasets: dict[Path, str] = field(default_factory=dict)  # local resolved dir -> directory baked into the image
    image: str = IMAGE_TAG
    rule_level: str = "informational"
    timeout_s: int = 600
    max_concurrent: int = 6


@dataclass(frozen=True)
class RunPlan:
    files: dict[str, bytes]  # absolute guest path -> content
    args: list[str]


def _spawn_type():
    # Imported lazily so the harness package stays importable without the SDK.
    from contree_sdk._internals.models.instance import InstanceSpawnRequest

    @dataclass(kw_only=True)
    class _OfflineSpawn(InstanceSpawnRequest):
        networking: dict = field(default_factory=lambda: {"enabled": False})
        uid: int = NOBODY
        gid: int = NOBODY
        disposable: bool = True

    return _OfflineSpawn


try:
    OfflineSpawn = _spawn_type()
except ImportError:  # pragma: no cover - SDK missing
    OfflineSpawn = None


def redact(text: str) -> str:
    """SDK errors can echo request headers; keep tokens and request dumps out of logs and records."""
    key = os.environ.get("NEBIUS_API_KEY")
    if key:
        text = text.replace(key, "[redacted]")
    text = re.sub(r"Bearer\s+\S+", "Bearer [redacted]", text)
    return text.split("RequestInfo(")[0].strip()


def plan_run(config: SandboxConfig, rules: dict[str, str], evtx_dirs: list[Path]) -> RunPlan:
    if not rules:
        raise ValueError("no rules to evaluate")
    files: dict[str, bytes] = {}
    # Labels may come from model output, so never use them in guest paths.
    for i, text in enumerate(rules.values()):
        files[f"/work/rules/r{i:04d}.yml"] = text.encode("utf-8")
    args = ["--log-source", "/work/thor.yml", "--rule-level", config.rule_level, "--rule-path", "/work/rules"]
    for i, directory in enumerate(evtx_dirs):
        directory = Path(directory)
        baked = config.datasets.get(directory.resolve())
        if baked is not None:
            args += ["--evtx-path", baked]
            continue
        if not directory.is_dir():
            raise CheckerError(f"evtx directory not found: {directory}")
        guest = f"/work/evtx/{i}"
        for path in sorted(directory.rglob("*.evtx")):
            files[f"{guest}/{path.relative_to(directory).as_posix()}"] = path.read_bytes()
        args += ["--evtx-path", guest]
    return RunPlan(files=files, args=args)


def interpret_result(exit_code: int, stdout: str, stderr: str, truncated: bool, timed_out: bool,
                     duration_s: float) -> CheckerRun:
    if timed_out:
        raise CheckerError("checker timed out inside the sandbox")
    if truncated:
        raise CheckerError("checker output exceeded the sandbox capture limit (10 MiB): the rule matched too many events")
    if exit_code != 0:
        raise CheckerError(f"checker exited {exit_code}: {stderr.strip()[-2000:]}")
    matches, ignored = parse_output(stdout)
    return CheckerRun(matches=matches, ignored_lines=ignored, stderr=stderr, duration_s=duration_s)


class SandboxRunner:
    """Callable `(rules, evtx_dirs) -> CheckerRun`; safe to call from several threads."""

    def __init__(self, config: SandboxConfig):
        self.config = config
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._client = None
        self._image_uuid: str | None = None
        self._slots: asyncio.Semaphore | None = None
        self._ready: asyncio.Lock | None = None

    def describe(self) -> dict:
        return {"kind": "token-factory-sandbox", "image_tag": self.config.image, "image_uuid": self._image_uuid,
                "network": "disabled (networking.enabled=false)", "isolation": "Contree microVM, disposable"}

    def __call__(self, rules: dict[str, str], evtx_dirs: list[Path]) -> CheckerRun:
        plan = plan_run(self.config, rules, evtx_dirs)  # local validation before touching the network
        future = asyncio.run_coroutine_threadsafe(self._run(plan), self._ensure_loop())
        try:
            return future.result(timeout=self.config.timeout_s + 120)
        except CheckerError:
            raise
        except TimeoutError as exc:
            future.cancel()
            raise CheckerError("sandbox evaluation timed out") from exc
        except Exception as exc:  # aqg: top-level boundary - SDK/transport failures become one trusted error type
            raise CheckerError(f"sandbox error: {type(exc).__name__}: {redact(str(exc))[:300]}") from exc

    def check(self) -> None:
        """Resolve the evaluation image now; raises CheckerError if access or the image is missing."""
        try:
            asyncio.run_coroutine_threadsafe(self._prepare(), self._ensure_loop()).result(timeout=120)
        except CheckerError:
            raise
        except Exception as exc:  # aqg: top-level boundary - same error type as evaluation failures
            raise CheckerError(f"sandbox unavailable: {type(exc).__name__}: {redact(str(exc))[:300]}") from exc

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._loop is None:
                loop = asyncio.new_event_loop()
                threading.Thread(target=loop.run_forever, daemon=True, name="sandbox-loop").start()
                self._loop = loop
            return self._loop

    async def _prepare(self):
        if self._ready is None:
            self._ready = asyncio.Lock()
            self._slots = asyncio.Semaphore(self.config.max_concurrent)
        async with self._ready:
            if self._client is None:
                from contree_sdk import Contree
                from contree_sdk._internals.models.instance import InstanceSpawnRequest
                client = Contree()
                client._operations[OfflineSpawn] = client._operations[InstanceSpawnRequest]
                try:
                    image = await client.images.use(self.config.image, strict=True)
                except Exception as exc:  # aqg: top-level boundary - turn any lookup failure into an actionable message
                    raise CheckerError(f"evaluation image '{self.config.image}' not found; run "
                                       f"`python -m tools.build_sandbox_image` ({type(exc).__name__})") from exc
                self._image_uuid = str(image.uuid)
                self._client = client
        return self._client

    async def _run(self, plan: RunPlan) -> CheckerRun:
        from contree_sdk._internals.models.instance import InstanceFileSpec, InstanceOperationMetadata
        from contree_sdk.utils.codecs import io_decode, io_encode

        client = await self._prepare()
        async with self._slots:
            uploaded = await asyncio.gather(*(client.files._upload_bytes_file(data) for data in plan.files.values()))
            files = {path: InstanceFileSpec(uuid=str(up.uuid), mode="0644", uid=0, gid=0)
                     for path, up in zip(plan.files, uploaded)}
            request = OfflineSpawn(command="/opt/checker", args=plan.args, image=self._image_uuid, hostname="shakedown",
                                   cwd="/work", stdin=io_encode(""), timeout=self.config.timeout_s,
                                   truncate_output_at=MAX_OUTPUT, files=files)
            started = time.monotonic()
            operation = await client._start_operation(request)
            meta, _ = await client._wait_operation(operation, InstanceOperationMetadata,
                                                   timeout=self.config.timeout_s + 60)
            duration = time.monotonic() - started
        result = meta.result
        if result is None:
            raise CheckerError("sandbox returned no process result")
        return interpret_result(
            exit_code=result.state.exit_code, stdout=io_decode(result.stdout).decode("utf-8", "replace"),
            stderr=io_decode(result.stderr).decode("utf-8", "replace"),
            truncated=bool(result.stdout.truncated or result.stderr.truncated),
            timed_out=bool(result.state.timed_out), duration_s=duration)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
