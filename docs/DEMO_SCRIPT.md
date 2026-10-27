# Demo video script (target 2:40, hard limit 3:00)

Final version, 2026-10-27. It uses only material approved in [DEMO_DECISION.md](DEMO_DECISION.md): the leakage-controlled AdFind scenario, run live, with a separately labelled recorded repair run and a recorded failure. The earlier recordings in `demo/recorded` are prohibited (see [demo/README.md](../demo/README.md)).

**Principle:** every claim on screen must be inspectable in a run record. The live run is whatever it is. If it does not pass, say so and use the failure clip as the result; do not retake until it passes.

**Scope of the video:** the report-to-rule-to-evidence workflow. It does not show or mention the Splunk connector. If it were mentioned it would have to say it was verified live only on a throwaway local test instance (not on a production Splunk), and 2:40 has no room for that sentence plus the evidence that matters.

## Narration and timing (measured, 310 words, 104 to 136 words a minute in every segment)

| Time | On screen | Narration |
|---|---|---|
| 0:00 to 0:15 | The page, "Run it live" panel, scenario "PUA - AdFind.EXE Execution" selected | "A threat report can become valid-looking Sigma YAML without anyone proving that it catches the attack. Shakedown writes the rule with Nemotron on Nebius Token Factory, then tests it inside a Token Factory Sandbox." |
| 0:15 to 0:40 | Press Run live. The header fills in: report read with Tavily, "Source handling: leakage-controlled", the count of web results left out | "Tavily reads the AdFind report at run time and looks for corroborating sources. Results that look like the very rule being written are kept away from the model. The page shows how many were left out, and the record lists each one with the reason." |
| 0:40 to 0:55 | "What was extracted" tab | "Nemotron first extracts what to look for. Every item has to come with a quote that appears word for word in the report, or it is dropped." |
| 0:55 to 1:15 | The first attempt appears in the strip, then "Test evidence". Caption if sped up | "It writes the rule, sigma check validates it, and SigmaHQ's own checker runs it in a Sandbox microVM with no network: against the attack log, and against 129 development and 352 held-out benign log files." |
| 1:15 to 1:45 | **Switch to the recorded run** "PUA - AdFind.EXE Execution" (replay). Caption: "Recorded run, not the live run". Click attempt 1, then attempt 2, then the diff | "Here is a recorded run showing repair. The first rule was valid but missed the attack. The missed events went back to the model, and the second rule detected it with zero benign matches. A repair sees the events it missed, so that detection is not independent; the clean number is the benign result on logs the model never saw." |
| 1:45 to 2:00 | The results table: attack detected, benign counts with denominators, expert rule column | "The counts are shown with their denominators, per attack file, next to SigmaHQ's expert rule, which also passes. One sample per scenario is all we have." |
| 2:00 to 2:25 | Open the recorded failure "PUA - Suspicious ActiveDirectory Enumeration" (replay, caption). Show the red attempt and the verdict "Did not pass" | "Not every run passes. This rule caught the attack but matched 350 benign events, so it is shown as failing. Across twenty tasks we froze before running them, first attempts caught the attack six or seven times, repairs brought it to fourteen, and expert rules caught all twenty. Experts still win." |
| 2:25 to 2:40 | The limits panel, then the repository name | "Shakedown treats an AI-written rule as a candidate that needs evidence: the rule, what it caught, what it matched, and what we could not show. Limits and code are in the repository." |

## Recording day runbook

1. **Freeze.** Use the committed release tree (`git log -1` shows the checkpoint). Do not edit code between rehearsal and recording.
2. **Start the final build:** `uv run python -m shakedown.serve --live --port 8013 --budget-file data/runs/budget_state.json --total-cap 40`. Open `http://127.0.0.1:8013` at 1280x720 or larger, browser zoom 110 to 125 percent, a clean browser profile with no bookmarks or extensions showing.
3. **Preflight:** `python tools/smoke_hosted.py http://127.0.0.1:8013` prints PASS; `uv run pytest -q` passes (251, with the 11 opt-in live Splunk tests deselected). A live run costs about $0.01 and a rehearsal is worth it.
4. **Hide:** `.env`, terminals showing keys, the Token Factory and Nebius consoles (they show the project id), and any other window or notification.
5. **Rehearse once** end to end, with the real live run, to learn how long it takes (146 to 311 s in the logs) and where to cut.
6. **Record the live run once, whole**, and the two replays as separate takes. Record narration separately or live; either is fine.
7. **Edit rules:** you may cut the waiting or speed it up, with an on-screen caption ("sped up, the run took N s") while you do. You may not cut between different runs without a caption, or make a failed run look like a pass. Replay clips carry the caption "Recorded run (replay), not the live run above" for their whole length.
8. **If the live run does not pass:** use it. Say "this one did not pass" and show it, then use the recorded repair and failure clips as they are. The honest run is the demo.
9. **If the live run passes on the first attempt:** say "this one passed first time, so here is a recorded run that needed a repair". Do not call the live run a repair.

## Shot-by-shot capture list

- [ ] A. Landing page with the live panel first (live enabled).
- [ ] B. Run live pressed; header with the source-handling line.
- [ ] C. "What was extracted" tab with quotes.
- [ ] D. First attempt in the strip; "Test evidence" tab with the 129 and 352 file counts.
- [ ] E. Final live verdict (pass or not), exactly as it came out.
- [ ] F. Replay of `pua-adfind-exe-execution` with the replay badge visible ("No model is running now"): attempt 1, attempt 2, diff.
- [ ] G. Results table with denominators.
- [ ] H. Replay of the Enumeration failure, red cell and "Did not pass".
- [ ] I. Limits panel.
- [ ] J. Narration says "Nemotron", "Nebius Token Factory", "Sandbox" and "Tavily" aloud.

## Checks on the exported file

- [ ] Duration under 3:00 (`ffprobe -v error -show_entries format=duration -of csv=p=0 video.mp4` if installed, otherwise the player). Target 2:40.
- [ ] Any speed-up or cut has an on-screen caption.
- [ ] No third-party logos, music or footage. English audio.
- [ ] Every number spoken appears in `docs/RESULTS_TABLE.md` or `docs/DEMO_DECISION.md`: first attempt 7 of 19 (Run 8) and 6 of 20 (Run 9), after repair 14 of 20 in both (14 of 19 completed in Run 8), expert 20 of 20 in Run 9; 350 benign events and 129 and 352 file counts from the replay records.
- [ ] Upload as public on YouTube only after you approve it. Title: "Shakedown: detection rules that come with test results". Put the repository link in the description once it exists.
