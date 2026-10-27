# Architecture

Shakedown turns a threat report into a Sigma detection rule and shows evidence that the rule works: it detects the described attack in a labelled Windows event log and stays quiet on benign Windows logs. When a candidate fails, the evidence goes back to the model for a bounded number of repairs.

## The loop

```
threat report URL or text
      │  Tavily extract (+ search for corroboration)            ← runtime web research
      ▼
 spec extraction ── Nemotron 3 Super (Token Factory) ── observables must be quoted verbatim from the report
      ▼
 rule generation ── Nemotron 3 Super ── JSON fields; code renders the Sigma YAML and pins the rule id
      ▼
 sigma check ─────── invalid? ──► error text back to the model (a repair attempt)
      ▼
 Token Factory Sandbox (microVM, no network) ── SigmaHQ evtx-sigma-checker
      │      attack EVTX  → detected?
      │      benign EVTX  → how many events match? (development logs)
      ▼
 passed? ── yes ──► held-out benign logs (never shown to the model), evidence export
      │ no
      └─► diagnosis (missed events / false-positive events) ──► repair, at most 3 times
```

Acceptance is deterministic code, not a model opinion: the attack file is detected **and** the development benign logs produce zero matches.

## Where each piece runs

| Piece | What it does | Where |
|---|---|---|
| Nemotron 3 Super 120B (`nvidia/nemotron-3-super-120b-a12b`) | Extracts the spec, writes and repairs the rule | Nebius Token Factory, OpenAI-compatible API, structured JSON output |
| Tavily | Reads the report URL and searches for corroborating sources | Called at run time ([shakedown/research.py](../shakedown/research.py)) |
| `sigma check` (sigma-cli 3.1) | Validates every candidate file | Local, after parsing the YAML ourselves (sigma-cli crashes on malformed YAML) |
| `evtx-sigma-checker` v0.8.5 | SigmaHQ's own regression tool, with `tests/thor.yml` | Inside a Token Factory Sandbox |
| Sandbox image `shakedown-eval:v1` | Debian base, the checker, `thor.yml`, both benign baselines | Built once by [tools/build_sandbox_image.py](../tools/build_sandbox_image.py) |
| FastAPI + vanilla JS | Replay of recorded runs, optional live runs | [shakedown/server.py](../shakedown/server.py), [web/](../web/) |

The same evaluator interface has a local Docker implementation ([shakedown/harness/checker.py](../shakedown/harness/checker.py)) for offline development. Every run record contains an `evaluator` block that says which one ran, and the UI repeats it.

## Trust boundaries

0. **The model must not receive the answer.** In leakage-controlled mode (`answer_policy=exclude`, the default for live runs) sources that contain the target rule id, sit on known Sigma mirrors, are titled like the target rule or contain Sigma rule text are removed before any model call, attack-file names are replaced by "attack sample N" in repair feedback and in checker error text, and `LeakGuard` in [shakedown/pipeline.py](../shakedown/pipeline.py) refuses any model request that still carries the target rule id or the attack file name. The run record states the mode (`source_mode`) and every source decision. The screen is a heuristic; the guard is the backstop.
1. **Web content is untrusted.** Tavily text reaches the model inside blocks labelled `UNTRUSTED WEB CONTENT`. The model's output is never executed or followed as instructions; it is parsed as data.
2. **Spec grounding.** Every observable the model proposes must come with a quote that appears verbatim in the report and contains the value. Others are dropped and listed in the run (`spec_dropped`).
3. **Model output is untrusted.** Rule text is rendered by our code from JSON (`rule_render.py`); rule ids are assigned by code (`loop._pin_id`), never taken from the model; labels are never used as file paths (`harness/sandbox.py::plan_run`, `harness/checker.py`).
4. **Evaluation is isolated.** Each evaluation is a disposable microVM started with `networking.enabled=false` and run as uid 65534. Only candidate rules and attack EVTX files are uploaded. The image contains no credentials; the API key never enters the VM.
5. **Credentials** come from environment variables or `.env` (git-ignored). Nothing prints them; SDK errors are redacted before they reach logs or records (`sandbox.redact`).
6. **The hosted app protects the credit.** Live runs are off unless started with `--live`; a daily cap, a cooldown per client and one concurrent run bound spend ([shakedown/budget.py](../shakedown/budget.py)). Replay mode needs no credentials and calls nothing.

## Evidence, not claims

- Every record keeps each attempt's rule text, its sha256, validation output, the per-file attack result, benign hit examples, token counts, latency and the evaluator's raw error if it could not load the rule.
- The best attempt is chosen by `(attack detected, fewer benign events)`, so a run that never passes is shown as not passing, with its best attempt.
- Benign false positives are measured on logs the model never saw (held-out `win10-client`), separately from the development logs the loop sees.
- The SigmaHQ expert rule for each task is evaluated by the same code as a baseline. It is never shown to the model.

## Module map

| Module | Responsibility |
|---|---|
| `shakedown/llm.py` | Token Factory client: model listing and selection (NVIDIA models only), structured JSON, retries |
| `shakedown/spec.py` | Typed detection spec with grounded observables |
| `shakedown/rule_render.py` | JSON → Sigma YAML |
| `shakedown/validate.py` | YAML parse + required fields + `sigma check` |
| `shakedown/loop.py` | Generate, resample empty answers, repair, choose the best attempt |
| `shakedown/evaluate.py` | Attack and benign evaluation with explicit denominators |
| `shakedown/harness/sandbox.py` | Token Factory Sandbox evaluator |
| `shakedown/harness/checker.py` | Local Docker evaluator (development) |
| `shakedown/research.py` | Tavily client, untrusted-content labelling and answer-source screening |
| `shakedown/byo.py` | Bring your own logs: manifest validation, hashing, schema check and attack/benign verdicts over the existing evaluator (EVTX only, local by default) |
| `shakedown/splunk.py` | Read-only Splunk preflight connector (search-job endpoints only; live-verified on a throwaway local test instance, see evidence/splunk_live_verification/REPORT.md) |
| `shakedown/assess.py` | Three independent verdicts, the review packet and the `python -m shakedown.assess` command. Has no path to the model |
| `shakedown/live.py` | Live wiring; picks the scenario's first readable reference as the report when none is typed |
| `shakedown/budget.py` | Daily, total, cooldown and concurrency caps; counts persist across restarts |
| `shakedown/pipeline.py` | Research → spec → loop → held-out → expert baseline → record |
| `shakedown/scenarios.py`, `budget.py`, `server.py`, `live.py`, `serve.py` | Scenarios, spend guard, API, wiring |
| `tools/` | Dataset audit, parity checks, batch evaluation, demo recording, Sandbox image build |
