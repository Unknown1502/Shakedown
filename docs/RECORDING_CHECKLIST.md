# Recording checklist

Derived from [DEMO_SCRIPT.md](DEMO_SCRIPT.md) (the narration text lives there; this file is the run-sheet). Target length 2:40, hard limit 3:00. **Recording is local only. Nothing here uploads or publishes anything: the YouTube upload needs your explicit approval and is outside this checklist.**

Tick each box as you go. If a gate fails, stop and fix it before recording.

## A. Gate: record from the verified artefact

- [ ] `git log -1 --format=%h` shows `267615d` (or a later docs-only commit) and `git tag` shows `release-candidate-2`. Do not edit code between rehearsal and recording.
- [ ] Start the verified image (credentials mounted read-only, never baked in), loopback only:
  `docker run -d --name shk-record -p 127.0.0.1:8013:8000 -v "<project folder>/.env:/app/.env:ro" shakedown:release-candidate-2`
  (Alternative that matches the script: `uv run python -m shakedown.serve --live --port 8013 --budget-file data/runs/budget_state.json --total-cap 40`.)
- [ ] `python tools/smoke_hosted.py http://127.0.0.1:8013` prints PASS (free; no model call).
- [ ] `http://127.0.0.1:8013/api/health` shows: `live_enabled` true, `answer_policy` exclude, evaluator `token-factory-sandbox` with the network disabled, `allow_custom_url` false, 5 recorded runs.
- [ ] Know the limits: **90 seconds between live runs from the same client**, 30 a day, 400 in total. A rehearsal run counts. Each live run costs about $0.01 to $0.02 and takes about 2.5 to 5 minutes.
- [ ] Afterwards: `docker rm -f -v shk-record`.

## B. Screen and privacy

- [ ] 1280x720 or larger, browser zoom 110 to 125 percent, a clean browser profile (no bookmarks, extensions or other tabs), notifications off.
- [ ] Not visible at any point: `.env`, any terminal showing keys, the Nebius or Token Factory console (it shows the project id), the Splunk container, file explorers with local paths.
- [ ] Do **not** show or mention the Splunk connector or bring-your-own-logs (no room in 2:40, and the honest wording does not fit).
- [ ] Rehearse once end to end with a real live run, to learn how long it takes and where you will cut.

## C. Run-sheet (times from the script)

| Time | Do and show | Check on screen before moving on |
|---|---|---|
| 0:00 to 0:15 | Landing page, live panel first, scenario "PUA - AdFind.EXE Execution" | Live panel is above the recorded runs; button enabled |
| 0:15 to 0:40 | Press **Run live** | Header shows "Report read with Tavily", **"Source handling: leakage-controlled"** and a count of web results left out (do not say a number unless the page shows it) |
| 0:40 to 0:55 | "What was extracted" tab | Observables with quotes |
| 0:55 to 1:15 | First attempt appears in the strip, then "Test evidence" | Counts 129 (development) and 352 (held-out) files; if you speed up the wait, caption it "sped up, the run took N s" |
| 1:15 to 1:45 | **Switch to the recorded run** `pua-adfind-exe-execution`; caption "Recorded run (replay), not the live run" for the whole clip; click attempt 1, attempt 2, then the diff | Badge reads "Replay of a run recorded ... No model is running now"; attempt 1 missed the attack; attempt 2 detected it with 0 benign events |
| 1:45 to 2:00 | Results table | "Attack file detected" 0 of 1 then 1 of 1; benign 0 in 129 files; held-out 0 in 352 files; expert rule column also 1 of 1 |
| 2:00 to 2:25 | Open the recorded failure `pua-suspicious-activedirectory-enumeration-via-adfind-exe` (the 4-attempt run); caption it as a recording | Attempt 3 is red with **350 benign events**; attempt 4 hatched (unusable rule); verdict "Did not pass in 4 attempts. Best rule: attempt 3" |
| 2:25 to 2:40 | Limits panel, then the repository name | "What this run does and does not show" is open |

Say aloud at least once: **Nemotron**, **Nebius Token Factory**, **Sandbox**, **Tavily**.

## D. If something goes differently

- [ ] **The live run does not pass:** use it. Say "this one did not pass" and show the verdict, then continue with the two recorded clips. Do not retake until it passes.
- [ ] **The live run passes on the first attempt:** say so ("this one passed first time, so here is a recorded run that needed a repair"). Never call it a repair.
- [ ] **A live run errors, a limit is reached, or the Sandbox is unavailable:** show the message the page gives, say live was not available, and use only the replays, captioned as recordings. Do not present a replay as live.
- [ ] **Cooldown message:** wait 90 seconds; do not work around it.

## E. What you may say (every number is in a file you can open)

- First attempt caught the attack 6 or 7 times in 20 tasks (Run 8: 7 of 19 completed; Run 9: 6 of 20); after up to three repairs 14 of 20 in both runs; SigmaHQ's expert rules caught 20 of 20 (Run 9). Source: `docs/RESULTS_TABLE.md`.
- The recorded failure matched 350 benign events (`demo/replay/pua-suspicious-activedirectory-enumeration-via-adfind-exe.json`, attempt 3).
- A repair is shown the missed events, so a pass after a repair is **not** independent; the held-out benign result is the clean measurement.

**Do not say:** that a replay is live; that the rule was "found from a tweet" or is "independent of SigmaHQ"; that any run is "typical" or a success rate; that Shakedown beats expert rules; anything about the Splunk connector or customer environments.

## F. After recording (local checks only)

- [ ] Total length **under 3:00** (target 2:40): `ffprobe -v error -show_entries format=duration -of csv=p=0 <file>` if installed, otherwise the player.
- [ ] Every speed-up or cut has an on-screen caption; no cut hides a failure or joins two different runs without a caption.
- [ ] Scrub the whole video once for secrets or the project id: terminals, tabs, notifications, file paths.
- [ ] No third-party logos, music or footage; English audio, clearly audible; the four sponsor words are said.
- [ ] Every number spoken matches section E.
- [ ] Save the file locally. **Stop here.** Uploading to YouTube (public, repository link in the description, title "Shakedown: detection rules that come with test results") is a separate step that needs your approval.
