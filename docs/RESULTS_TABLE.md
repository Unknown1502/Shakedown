## Development set (20 tasks, `evaluation/tasks.json`)

Used while the method changed. Run-to-run differences are mostly model noise.

| Run | Configuration | Tasks with results | First rule valid | One-shot detects (clean) | After repair detects | After repair, errored tasks counted as misses | Repair fixed first failure | Held-out FP, repaired rules | Gen. tokens | SigmaHQ expert detects |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | free-form YAML, thinking on, loop bug (5 tasks aborted); local Docker | 15/20 | 13/15 | 4/15 | 13/15 | 13/20 | 8/11 | 1/15 rules, 6 events | 79,335 | 15/15 |
| 2 | free-form YAML, thinking on, loop bug fixed, no API retry; local Docker | 19/20 | 14/19 | 3/19 | 12/19 | 12/20 | 8/16 | 1/17 rules, 6 events | 105,578 | 19/19 |
| 3 | structured JSON + field hints + API retry, thinking on; local Docker | 20/20 | 10/20 | 4/20 | 11/20 | 11/20 | 6/16 | 1/20 rules, 2293 events | 114,581 | 20/20 |
| 4 | as 3, thinking OFF; local Docker | 20/20 | 16/20 | 3/20 | 7/20 | 7/20 | 4/17 | 0/18 rules, 0 events | 69,215 | 20/20 |
| 5 | as 3, thinking on + resample empty skeletons; local Docker | 19/20 | 17/19 | 7/19 | 10/19 | 10/20 | 3/12 | 0/18 rules, 0 events | 221,971 | 19/19 |
| 6 | as 5, evaluated in a Token Factory Sandbox | 20/20 | 16/20 | 5/20 | 11/20 | 11/20 | 6/15 | 0/20 rules, 0 events | 200,770 | 20/20 |
| 7 | as 6 + last-resort thinking-off call when the answer is still empty; Sandbox | 20/20 | 14/20 | 6/20 | 12/20 | 12/20 | 7/15 | 1/20 rules, 2 events | 250,945 | 20/20 |

## Confirmatory set (20 new tasks, `evaluation/tasks_confirmatory.json`)

Frozen before any model call on them; 10 dated 2026 and 10 older. Plan in `docs/EVALUATION_METHODOLOGY.md`.

| Run | Configuration | Tasks with results | First rule valid | One-shot detects (clean) | After repair detects | After repair, errored tasks counted as misses | Repair fixed first failure | Held-out FP, repaired rules | Gen. tokens | SigmaHQ expert detects |
|---|---|---|---|---|---|---|---|---|---|---|
| 8 | Run 7 configuration (with the fallback); Sandbox. Headline run | 19/20 | 18/19 | 7/19 | 14/19 | 14/20 | 7/12 | 1/19 rules, 1 events | 198,113 | 19/19 |
| 9 | Run 6 configuration (no fallback); Sandbox. Comparison | 20/20 | 15/20 | 6/20 | 14/20 | 14/20 | 8/14 | 1/20 rules, 2 events | 190,287 | 20/20 |

### Confirmatory set by rule date

**Rules dated 2026 (10 tasks)**

| Run | Configuration | Tasks with results | First rule valid | One-shot detects (clean) | After repair detects | After repair, errored tasks counted as misses | Repair fixed first failure | Held-out FP, repaired rules | Gen. tokens | SigmaHQ expert detects |
|---|---|---|---|---|---|---|---|---|---|---|
| 8 | Run 7 configuration (with the fallback); Sandbox. Headline run | 9/10 | 8/9 | 3/9 | 7/9 | 7/10 | 4/6 | 0/9 rules, 0 events | 78,475 | 9/9 |
| 9 | Run 6 configuration (no fallback); Sandbox. Comparison | 10/10 | 8/10 | 3/10 | 8/10 | 8/10 | 5/7 | 0/10 rules, 0 events | 95,860 | 10/10 |

**Older rules (10 tasks)**

| Run | Configuration | Tasks with results | First rule valid | One-shot detects (clean) | After repair detects | After repair, errored tasks counted as misses | Repair fixed first failure | Held-out FP, repaired rules | Gen. tokens | SigmaHQ expert detects |
|---|---|---|---|---|---|---|---|---|---|---|
| 8 | Run 7 configuration (with the fallback); Sandbox. Headline run | 10/10 | 10/10 | 4/10 | 7/10 | 7/10 | 3/6 | 1/10 rules, 1 events | 119,638 | 10/10 |
| 9 | Run 6 configuration (no fallback); Sandbox. Comparison | 10/10 | 7/10 | 3/10 | 6/10 | 6/10 | 3/7 | 1/10 rules, 2 events | 94,427 | 10/10 |
