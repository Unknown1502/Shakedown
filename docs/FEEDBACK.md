# Feedback on Nebius Token Factory, Sandboxes and Nemotron

Written from building Shakedown (a Sigma detection-rule agent) between 2026-10-26 and 2026-10-30. Every item below is something we measured or hit, with the workaround we used.

## What worked well

- **Model listing.** `/v1/models?verbose=true` made it easy to select an NVIDIA model at run time instead of hard-coding an ID, and the per-model prices let us put a real cost on every run (about $0.18 of generation for a 20-task batch).
- **Nemotron 3 Super 120B** follows a strict JSON schema well when it answers, and its latency (5 to 11 seconds per structured call) is fine for an interactive repair loop.
- **Sandboxes are fast enough to sit in a loop.** A rule evaluation (upload rule and attack log, boot a microVM, run SigmaHQ's checker against the attack file and 129 benign logs) took about 13 to 15 seconds for two operations, against about 8 seconds on a local Docker container. Running 30 reference rules through both gave identical match counts on all 30.
- **Disposable runs and a baked image.** Building one image with the checker and 976 MB of benign logs, then running every evaluation from it as a disposable VM, is a clean fit for "run untrusted code and throw the machine away".
- **Free during the beta** removed a cost worry for an evaluation that makes hundreds of sandbox runs.

## Problems and suggestions

1. **Sandboxes activation had no status or ETA.** The project showed "inactive" with every permission false and a `ForbiddenError` for roughly a day after the request form, with no way to see whether the request had been received. A status line ("requested", "approved", "active") in the console and an expected turnaround would save hackathon teams a lot of guessing. Access did arrive on 2026-10-27.
2. **The SDK does not expose `networking`.** The security page says `networking.enabled=false` starts the VM with no network interface and "must be supplied on every relevant spawn", but `contree-sdk` 0.3.6 has no such option on `run()`. We sent it by subclassing the SDK's `InstanceSpawnRequest` and registering the subclass in the client's operation table, then confirmed from inside the VM that only `lo` exists and DNS fails (a default run has `eth0` and resolves). A first-class `networking=` argument would make the safe setting the easy setting.
3. **Digest-pinned image import returns 404.** `docker://docker.io/library/debian@sha256:...` (and the `name:tag@sha256:` form) failed with `HTTP 404 Not Found` during import, while `docker://docker.io/library/debian:bookworm-slim` worked. Security-minded users want to pin by digest. Either support it or document that it is unsupported.
4. **The Python docs mix the SDK and REST views.** The quickstart is clear, but finding how to attach files, read the process result stream and set limits meant moving between the SDK source and the OpenAPI page. A short "run a command with files, offline, and read stdout" recipe would cover most agent use cases.
5. **Output cap.** stdout and stderr are capped at 10 MiB per stream. That is reasonable, but a truncated result is easy to miss; we treat `truncated` as an error. A more prominent note in the run-result docs would help.
6. **Structured output with reasoning (Nemotron 3 Super).** With thinking on and a strict `json_schema`, about 3 to 5 of every 8 calls returned valid JSON with an empty body (empty lists and blank strings), and a larger `max_tokens` made it worse (5 of 8). With `chat_template_kwargs: {"enable_thinking": false}` we got 0 of 8 empty answers, at some cost in rule quality (detection after repair fell from 11 of 20 to 7 of 20 in one run). We handle it by resampling and, as a last resort, one call with thinking off. Guidance on combining reasoning with strict schemas, or a schema mode that rejects an all-empty object, would help.
7. **Structured-output request shape.** The docs example and the OpenAI-style `response_format` wrapper differ. We try the OpenAI form first and fall back to the bare-schema form, and record which one worked. One documented form would remove the guesswork.
8. **Errors from the SDK embed request and response dumps.** We redact them before logging as a precaution. Shorter, structured exceptions (status, operation UUID, message) would be safer to log.
9. **Empty completions with HTTP 200.** Now and then Nemotron 3 Super returned a completely empty message (no JSON at all) even after the client's own retries: three times in a row on one task of a 20-task run, and once in 18 spec-extraction calls in a later experiment. We treat "no JSON" like an empty skeleton (resample, then fail visibly). A finish reason or a documented retry hint for this case would help clients tell it from a truncation.

## About NVIDIA's open models

Nemotron 3 Super 120B was good at the extraction step (turning a report into typed observables with verbatim quotes) and mixed at writing Sigma rules: it often picks reasonable fields but misses details such as exact process names or the log-source field set. A tested repair loop helped (on 20 tasks we had not tuned against, the first attempt detected the attack in 6 to 7 and after repair 14), but SigmaHQ's expert rules still win (20 of 20). Results and limits are in [RESULTS_TABLE.md](RESULTS_TABLE.md) and [LIMITATIONS.md](LIMITATIONS.md).
