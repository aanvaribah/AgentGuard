"""Live mode: AgentGuard watches the ADOP corpus/ while ADOP live_mode runs N sessions against
gpu-host's Ollama. Usage: run_live.py <run_dir> <n_sessions>"""
import json, os, signal, subprocess, sys, time
from pathlib import Path

AG = Path("/tmp/poc-run-20261107/AgentGuard"); ADOP = Path("/tmp/poc-run-20261107/adop-cyse")
run = Path(sys.argv[1]).resolve(); n = int(sys.argv[2])
run.mkdir(parents=True)
env = dict(os.environ, OLLAMA_HOST="http://<model-host>:11434")
ag_cmd = ["/tmp/poc-run-20261107/venv/bin/python", "main.py", "-p", str(ADOP / "corpus"),
          "-a", str(ADOP / "testbed-repo"), "-m", str(run / "mirror"), "--plain"]
adop_cmd = ["/tmp/poc-run-20261107/adop-venv/bin/python", "-m", "adop_testbed.scripts.live_mode"]
(run / "command.txt").write_text(
    f"AgentGuard: cd {AG} && OLLAMA_HOST={env['OLLAMA_HOST']} {' '.join(ag_cmd)}\n"
    f"ADOP (x{n}): cd {ADOP} && OLLAMA_HOST={env['OLLAMA_HOST']} {' '.join(adop_cmd)}\n")
t0 = time.time()
ag_out = open(run / "agentguard-stdout.txt", "w")
ag = subprocess.Popen(ag_cmd, cwd=AG, env=env, stdout=ag_out, stderr=subprocess.STDOUT)
time.sleep(3)
for i in range(n):
    with open(run / f"adop-live-{i + 1}-stdout.txt", "w") as fh:
        r = subprocess.run(adop_cmd, cwd=ADOP, env=env, stdout=fh, stderr=subprocess.STDOUT, timeout=3600)
    print("adop session", i + 1, "rc", r.returncode, round(time.time() - t0), "s", flush=True)
# wait for analyst backlog
ev = run / "mirror" / "agentguard-events.jsonl"
n_records = lambda: sum(1 for f in (ADOP / "corpus").rglob("*.jsonl") for l in open(f) if l.strip())
last, idle = -1, time.time()
while time.time() - t0 < 7200:
    time.sleep(3)
    events = [json.loads(l) for l in open(ev)] if ev.exists() else []
    calls = [e for e in events if e["kind"] == "call"]
    first = {(e["session_id"], e["seq"]) for e in calls if e["decision"] in ("reviewing", "suppressed") or e["source"] == "signature"}
    done = {(e["session_id"], e["seq"]) for e in calls if e["decision"] in ("cleared", "error") or (e["decision"] == "alert" and e["source"] == "analyst")}
    pending = {(e["session_id"], e["seq"]) for e in calls if e["decision"] == "reviewing"} - done
    if len(events) != last:
        last, idle = len(events), time.time()
    if len(first) >= n_records() and not pending and time.time() - idle > 10:
        break
ag.send_signal(signal.SIGINT)
try:
    ag.wait(30)
except subprocess.TimeoutExpired:
    ag.kill()
(run / "meta.json").write_text(json.dumps({"records": n_records(), "wall_s": round(time.time() - t0, 1)}, indent=1))
print("done", n_records(), "records", round(time.time() - t0), "s")
