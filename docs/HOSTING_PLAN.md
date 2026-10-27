# Hosting plan (prepared, not deployed)

Nothing here has been deployed. Deploying needs your approval, a provider choice and the three secrets. Everything below was tested locally against a container built from the repository.

> **Read [HOSTING_ALTERNATIVES.md](HOSTING_ALTERNATIVES.md) before choosing the caps.** It sets the spending cap against the rules' "free of charge and without any restriction" clause and compares the options. The caps in the `Dockerfile` are conservative defaults, not a recommendation.

## What was verified (2026-10-27)

| Check | Result |
|---|---|
| `docker build` from a clean tree (`Dockerfile`, `.dockerignore`) | Built, 1.71 GB; the datasets are fetched inside the build by `tools/fetch_data.py` from pinned, hash-verified sources |
| Image contents | No `.env`; no credential value found anywhere in the image filesystem (scanned against the three local values); runs as uid 10001 |
| Container started with the secrets mounted read-only | Server up; one defect found and fixed (the scenario cache write crashed a non-root start; `tests/test_serve_index.py`) |
| `python tools/smoke_hosted.py <url> --run` against the container | 23 of 23 checks passed, including one live run (passed on attempt 1, 22,773 tokens, 234 s) |
| Budget state persisted | `/state/budget.json` in the container held `{"day","used","total_used"}` after the run; no client addresses are stored |
| Reaches the Sandbox API from a container network | Yes: the live run above executed in a Token Factory Sandbox from inside Docker. Reachability from your chosen provider is **not tested** |

## Architecture

One container, one process (`python -m shakedown.serve --live`). It serves the UI and API, calls Token Factory (model), Tavily (research) and the Sandboxes API (evaluation) over HTTPS, and keeps its run counts in `/state/budget.json`.

```
judge browser --HTTPS--> [reverse proxy / platform ingress] --> shakedown container :8000
                                                                  |-- Token Factory API (Nemotron 3 Super)
                                                                  |-- Tavily API (extract + search)
                                                                  |-- Sandboxes API (image shakedown-eval:v1)
                                                                  `-- /state volume (budget.json)
```

Prerequisite in your Nebius project: the evaluation image. `uv run python tools/build_sandbox_image.py` built `shakedown-eval:v1` (UUID in `evidence/audit/sandbox_image.json`); it is tied to the project of the API key you deploy with.

## Configuration

| Item | Where | Notes |
|---|---|---|
| `NEBIUS_API_KEY`, `NEBIUS_PROJECT_ID`, `TAVILY_API_KEY` | environment variables of the container, from the platform's secret store | never in the image or the repository. Use keys created for the demo, not your day-to-day ones, and rotate them after Dec 15 |
| `/state` | a persistent volume | without a volume the caps reset when the container restarts |
| Command line | `Dockerfile` CMD | daily cap 30, total cap 400, cooldown 90 s, 3 concurrent runs, custom report addresses off, answer screening on |
| `--trust-proxy` | add only behind a proxy you control | otherwise every visitor behind the proxy shares one cooldown (safe, slow). With the flag and no proxy, the cooldown can be spoofed |
| Replay-only fallback | run without `--live` | needs no keys, serves `demo/replay`, and the UI says live runs are off. It must be described as replay, never as live |

Sizing: disk about 2 GB for the image plus the volume. RAM and CPU were **not measured**; start with 1 vCPU and 2 GB and watch it.

## Cost model

Prices are the ones the Token Factory API itself reports for `nvidia/nemotron-3-super-120b-a12b`: **$0.30 per million prompt tokens, $0.90 per million completion tokens**. Tavily: 1 credit per basic search and 1 credit per 5 successful basic extractions (docs.tavily.com, quoted 2026-10-27), so a run costs 1.2 credits; pay-as-you-go is $0.008 per credit and the free plan includes 1,000 credits a month. Sandboxes were free during the beta when last checked and are **UNVERIFIED for December**.

| Per live run | Value | Basis |
|---|---|---|
| Model | $0.0088 and $0.0113 | the two runs metered end to end (18,724 and 22,773 tokens: 13,378 + 5,346 and 15,390 + 7,383) |
| Model, upper estimate | about $0.04 | the largest logged generation total (34,339 tokens) plus the spec call, all priced at the completion rate. An estimate, not a measurement |
| Tavily | 1.2 credits, about $0.0096 at pay-as-you-go | a failed extraction is not billed. `max_results` is not part of the documented price; eight results instead of three is not documented to cost more |
| Sandboxes | $0 (beta), UNVERIFIED later | |
| **Per run, planning figure** | **$0.05** | rounded up from the above |

| Cap | Worst case |
|---|---|
| Total cap 400 runs | 400 x $0.05 = **$20** |
| If you lift the total cap, daily 30 for the 47 days from Oct 30 to Dec 15 | 1,410 x $0.05 = about $70 |

Throughput: a run takes 146 to 311 s in the logs. Three concurrent runs is about 35 to 70 runs an hour. Token Factory limits for this model are 200,000 tokens a minute and 300 requests a minute, far above that.

## The "free and without restriction" requirement

The rules (section "Testing") require the project to be available "free of charge and without any restriction" to judges until the Judging Period ends (Dec 15, 12:00 pm PT). A cap on live runs is a restriction on one part of the product. How this plan handles it:

- Replay is uncapped, free, needs no account and is the fallback for everything.
- Live runs are capped to bound your spend. Say so in the testing instructions (draft in `DEVPOST_SUBMISSION.md`), and set the caps so a judge is very unlikely to meet them: 30 a day, 400 total is a deliberate choice, not a guess at the number of judges. You can raise `--total-cap`; the worst-case table above says what that costs.
- The rules also say judges "may choose to judge based solely on the text description, images, and video".

## Quotas and abuse controls (all in the code, all tested)

Per-client cooldown (client = socket address unless `--trust-proxy`), a daily cap, a total cap, a concurrency limit, a restart-proof counter, custom report addresses off (a visitor can only run the scenarios' own references), no free-text model input (the service is not an inference proxy), source text capped at 6,000 characters per source, answer-bearing sources excluded, a guard that refuses model requests carrying the target rule id.

Not covered: DDoS or bandwidth abuse (use the provider's protection), and an overall wall-clock limit per run (a run is bounded by 3 repairs and the model client's 120 s timeout with bounded retries, not by a timer).

## Smoke tests after any deployment

1. `python tools/smoke_hosted.py https://<host>` (free: no model call). Must print PASS.
2. `python tools/smoke_hosted.py https://<host> --run` once (about $0.01 to $0.05). A failed run is a valid result; the checks assert the record is correct, not that the rule passed.
3. Open the page, press Run live on "PUA - AdFind.EXE Execution", confirm the header says "Source handling: leakage-controlled" and the badge says live. Play one replay and confirm the badge says it is a replay.

## Rollback

Redeploy the previous image tag. To stop spending immediately: restart without `--live` (replay only) or delete the three secrets. The budget file survives restarts, so a restart does not reset the caps.

## Readiness

**Technically ready to deploy; blocked on you** for: the provider choice and an account, the three secrets, approval to publish a URL, and a credit balance you are comfortable with through Dec 15. Provider choice is open: a Nebius AI Cloud VM or serverless job keeps everything on one platform and removes the reachability question; any container host with a persistent volume works. If no low-cost live deployment is possible, the alternative is replay-only plus "run it yourself" instructions, and the submission must then say the hosted demo is a replay.
