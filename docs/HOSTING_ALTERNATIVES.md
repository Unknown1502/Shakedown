# Hosting: the spending cap against the "unrestricted access" rule

Nothing here is deployed. This reassesses [HOSTING_PLAN.md](HOSTING_PLAN.md) against the official requirement, lays out compliant options with their risks, and leaves the choice, and the money, to you.

## The requirement

Rules, "Testing" (read 2026-10-27): "The Entrant must make the Project available free of charge and without any restriction, for testing, evaluation and use by the Sponsor, Administrator and Judges until the Judging Period ends" (2026-12-15, 12:00 pm Pacific). The same section says "Judges are not required to test the Project and may choose to judge based solely on the text description, images, and video". Submission Requirements ask for "a URL to a working demo, hosted application, or test build".

**Honest reading:** any cap on live runs is, literally, a restriction. I cannot tell how strictly Nebius or Devpost will read it. The risk is real but its size is unknown; what you control is how likely a judge is to meet a limit, and how clearly the limits are disclosed.

## Cost basis (measured or sourced, nothing guessed)

| Item | Value | Source |
|---|---|---|
| Model, per live run | $0.0088 and $0.0113 | two fully metered runs (18,724 and 22,773 tokens) at the API-listed $0.30 and $0.90 per million prompt and completion tokens |
| Tavily, per run | 1.2 credits (1 search + 0.2 of a 5-URL extract), about $0.0096 at $0.008 a credit | docs.tavily.com, read 2026-10-27; the free plan includes 1,000 credits a month |
| Sandboxes | free during the beta | Nebius page when last read; **UNVERIFIED for December** |
| Planning figure | **$0.05 per run** (rounded up) | the sum above plus margin |
| Run time | 146 to 311 s | run records |

The Nebius credit balance is not visible to me. The FAQ mentions promotional Token Factory credits (a direct-credits form); I did not use it.

## Options

| # | Option | Judge experience | Compliance risk | Worst-case cost to Dec 15 | Other risks |
|---|---|---|---|---|---|
| 1 | **Current defaults:** replay uncapped; live 30 a day, 400 in total, 90 s cooldown, 3 at once | Live works until a cap is hit, then a clear message and the replays still work | Medium: a cap exists, and 400 runs is enough for any realistic judging but is a number someone could hit | 400 x $0.05 = **$20** | Low |
| 2 | **Generous caps:** live 100 a day, 2,000 in total, 30 s cooldown, 4 at once | Almost certainly never meets a limit | Low to medium: a cap still exists, but it is far above plausible demand | 2,000 x $0.05 = **$100** (expected well under $30 at the measured $0.01 a run) | Bill shock if the URL leaks and is scripted. Mitigate with the provider-side limits below |
| 3 | **No cap on live runs** | Never limited | Lowest on this clause | **Unbounded** | Anyone can spend your credit. Not recommended |
| 4 | **Replay only on the hosted URL, plus a test build** (the repository, the Dockerfile and `python tools/smoke_hosted.py`) | Replays of real runs; live needs the judge's own keys | Medium: "working demo" is a replay and says so; live needs credentials the judge does not have, which is itself a restriction | **$0** | The hosted page demonstrates recorded runs only; the live path is shown by the video |
| 5 | **Live gated by an access code or judge-supplied keys** | Judges must ask or sign up | **High**: a gate is the clearest restriction | Low | Judges may simply not bother |
| 6 | **Option 1 or 2 with an automatic fall back** (already built): when a cap or the cooldown applies, the UI says so and offers the replays | Never a dead end | Same as the option it is combined with | Same | None added |

## Recommendation

**Option 2, with option 6's fallback, sized to what you are willing to spend, and option 4 as the stated fallback if you decide you cannot fund it.** Reasoning: the number of judges is small (likely tens), each might try one to three runs, so 2,000 live runs is more than 10 times plausible demand; the measured cost is about a cent a run; the cost of the generous setting is bounded at roughly $100 and expected to be well under $30. The default container command (option 1) is deliberately left conservative because spending authority is yours; raise it with `--daily-cap`, `--total-cap`, `--cooldown` and `--max-concurrent`.

Provider-side limits to set whichever option you choose (I cannot set or verify them): a hard spend limit or alert on the Nebius project and on the Tavily key; use keys created for this demo only; rotate them after December 15. Tavily's free plan stops at its credit limit unless pay-as-you-go is on, which is a natural second cap.

## Wording to use (honest, and it answers the clause)

In the Devpost testing instructions: "The recorded runs are unlimited and need no account. Live runs use the project's own Nebius and Tavily credit, so they are limited to [N] a day and [M] in total to keep the demo free for everyone through December 15; if a limit is reached the page says so and the recorded runs keep working. The code and a container to run it yourself are in the repository."

Do not describe the replay as live, do not say "unlimited" about live runs, and do not delete the caps to make the sentence simpler.

## Decisions for you

1. Which option, and the numbers `[N]` and `[M]`.
2. Whether you will set provider-side spend limits and use demo-only keys.
3. The provider, and approval to deploy (HOSTING_PLAN.md).
