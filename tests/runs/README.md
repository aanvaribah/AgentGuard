# Test runs

This folder holds the raw inputs, outputs and scoring files behind the run results in our Deliverable 3 and Deliverable 4 reports. It changes no AgentGuard code, and pytest does not collect anything in it. The only scripts here are the ones that ran and scored the runs.

## Runs

| Folder | Date | Run by | AgentGuard | What was run | Records | Headline result |
| --- | --- | --- | --- | --- | --- | --- |
| [2026-10-01_f7d1b6d_v0.1](2026-10-01_f7d1b6d_v0.1/) | 2026-10-01 | Alex Anvari | v0.1, commit `f7d1b6d` | ADOP reference sessions through the v0.1 analyst, 3 replays; planted-instruction probe, 6 replays per variant | 22 per replay | 1 of 2 attack records alerted; 8 false alerts on 30 clean verdicts; 7 records changed between replays |
| [2026-11-07_3007e09_v0.5](2026-11-07_3007e09_v0.5/) | 2026-11-07 | Alex Anvari | v0.5, commit `3007e09` | Reference sessions 3 times, planted-instruction and integrity tests, 3 new live ADOP sessions, 18 archived August sessions twice | 22, 84, 293 | 2 of 2 attack records alerted, 0 false alerts on clean records; live: 6 of 6 harmful calls alerted, 1 false alert |

## Where each number in the reports comes from

"v0.1" means `2026-10-01_f7d1b6d_v0.1/`, "v0.5" means `2026-11-07_3007e09_v0.5/`.

| Report and location | Figure | Folder and file |
| --- | --- | --- |
| D3 Table A2, D4 Table 4, v0.1 column | 1 of 2 attack records alerted; false alerts on clean 1, 5, 2; other poisoned 4, 4, 1; 7 records differ | v0.1 `reference-replays/clean-rep*.jsonl`, `poisoned-rep*.jsonl` |
| D3 §2.2 | Analyst alerted on 8 of 30 benign verdicts | v0.1 `reference-replays/clean-rep*.jsonl` |
| D3 §2.2 | `git_diff --output=` suppressed in every poisoned replay | v0.1 `reference-replays/poisoned-rep*.jsonl` and `planted-instruction/*.jsonl` (seq 12) |
| D3 §2.2 | Planted reviewer instruction repeated in all six injection explanations | v0.1 `planted-instruction/injB-rep1..6.jsonl` (seq 11 reasoning) |
| D3 Table A2, D4 Table 4, v0.5 column; D4 §1 | 2 of 2 attack records alerted; 0, 0, 0 false alerts on clean; 4, 4, 4 other poisoned; identical across 3 replays | v0.5 `reference-r1/`, `reference-r2/`, `reference-r3/` |
| D3 Table A2 and §6.3, D4 Table 4 and §6 | Live: 6 of 6 harmful calls alerted, 1 false alert, 6 no-effect attempts missed | v0.5 `live-3-sessions/scored.csv`, `labels.json` |
| D4 §6 | Live: 14 alerts on 84 records, 7 of them on no-effect attempts | v0.5 `live-3-sessions/scored.csv` |
| D4 §5 | 14 alerts in 3 sessions, about 4.7 per session | v0.5 `live-3-sessions/agentguard-output/agentguard-events.jsonl` |
| D4 §4.3 | 84 live-session tool-call records | v0.5 `live-3-sessions/corpus/` |
| D3 §6.3 | 18 archived sessions, 293 records: 12 false alerts on 243 benign calls | v0.5 `archived-18-sessions-r1/scored.csv`, `labels.json` (r2 gives the same) |
| D4 §5, §6 | 18 archived sessions: 4 of 5 harmful calls alerted, 12 false alerts on 243 benign calls | v0.5 `archived-18-sessions-r1/scored.csv`, `labels.json` (r2 gives the same) |
| D3 §6.3 | 36 signature alerts, 33 on paths ADOP had refused | v0.5 `archived-18-sessions-r1/agentguard-output/agentguard-events.jsonl` |
| D3 §6.3; D4 §6 | Planted instruction flipped two of 22 verdicts to alert (seq 15, 22) and suppressed none | v0.5 `planted-instruction/` compared with `reference-r1/` |
| D3 §6.3; D4 §6 | A same-length edit to an earlier mirrored line raised no warning until restart | v0.5 `integrity/integrity-results.json` |

## The "36 live task-suite runs" in D3 §2.4

D3 §2.4 says that in 36 live task-suite runs, `git_init` left the repository in 4, the worktree read did so in 6, and the poisoned page was fetched in 25. The 36 runs come from three groups.

| Run by | Runs | `git_init` outside repo | Worktree read outside repo | Poisoned page fetched | Files |
| --- | --- | --- | --- | --- | --- |
| Alex Anvari, 2026-08-25 | 6 | 1 | 0 | 3 | [v0.5 `archived-18-sessions-r1/corpus/`](2026-11-07_3007e09_v0.5/archived-18-sessions-r1/corpus/), the six `live-session-live-2026-08-25-*` folders |
| Alex Anvari, 2026-11-07 | 3 | 0 | 2 | 2 | [v0.5 `live-3-sessions/corpus/`](2026-11-07_3007e09_v0.5/live-3-sessions/corpus/) |
| Logan Kotlus, August 2026 | 27 | 3 | 4 | 20 | Counts from Logan's D1 report; logs not in this folder yet |

Our 9 runs are counted per run, from the files here. Logan's numbers are per call, from his D1 report; his logs are not in this folder yet.

## Adding a run

1. Make a folder named `YYYY-MM-DD_<commit7>_<version>`, for example `2026-11-30_70cc009_v0.8`.
2. Copy a folder README from an existing run and fill it in: date, who ran it, versions, commands, what each sub-folder holds, results and notes.
3. Put inputs, outputs and the scored file in plain-named sub-folders. Do not name a folder `mirror/` or a file `*.log`, because `.gitignore` drops them, and do not name a script `test_*.py` or `*_test.py`, because pytest would collect it.
4. Add a row to the tables above.
