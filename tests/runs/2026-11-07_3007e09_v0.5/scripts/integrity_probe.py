"""Assumption 3 (M1): edit/truncate corpus lines while AgentGuard runs, then once while it is stopped.
Usage: integrity_test.py <run_dir>"""
import json, os, shutil, signal, subprocess, sys, time
from pathlib import Path

AG = Path("/tmp/poc-run-20261107/AgentGuard"); PY = "/tmp/poc-run-20261107/venv/bin/python"
REF = Path("/tmp/poc-run-20261107/ref-backup"); ROOT = "/tmp/poc-run-20261107/adop-cyse/testbed-repo"
run = Path(sys.argv[1]).resolve(); run.mkdir(parents=True)
corpus = run / "corpus"; shutil.copytree(REF, corpus); mirror = run / "mirror"
clean = corpus / "clean/session-01.jsonl"; pois = corpus / "poisoned/session-01.jsonl"
env = dict(os.environ, OLLAMA_HOST="http://<model-host>:11434")
cmd = [PY, "main.py", "-p", str(corpus), "-a", ROOT, "-m", str(mirror), "--plain"]
ev = mirror / "agentguard-events.jsonl"
log = []

def integrity():
    return [e for e in map(json.loads, open(ev)) if e["kind"] == "integrity"] if ev.exists() else []

def edit_line(path, seq, mutate):
    lines = path.read_text().splitlines(keepends=True)
    for i, l in enumerate(lines):
        if json.loads(l)["seq"] == seq:
            lines[i] = mutate(l)
    path.write_text("".join(lines))

def step(name, action, wait=8):
    before = len(integrity()); action(); time.sleep(wait)
    new = integrity()[before:]
    log.append({"step": name, "integrity_events": len(new), "messages": [e["message"] for e in new]})

def start(tag):
    out = open(run / f"stdout-{tag}.txt", "w")
    return subprocess.Popen(cmd, cwd=AG, env=env, stdout=out, stderr=subprocess.STDOUT)

def stop(p):
    p.send_signal(signal.SIGINT); p.wait(30)

# same-length edit so only content, not size, changes
swap = lambda l: l.replace('"success"', '"blocked"', 1) if '"success"' in l else l
p = start("1"); time.sleep(60)  # initial pass incl. analyst reviews
step("online: edit a middle line of clean (seq 3), same length", lambda: edit_line(clean, 3, swap))
step("online: append a valid line to clean so the watcher re-reads it", lambda: open(clean, "a").write(clean.read_text().splitlines()[-1].replace('"seq": 10', '"seq": 99') + "\n"), 30)
step("online: edit the last-read line of poisoned (seq 22), same length", lambda: (edit_line(pois, 22, swap), os.utime(pois)))
step("online: truncate poisoned by its last line", lambda: pois.write_text("".join(pois.read_text().splitlines(keepends=True)[:-1])))
stop(p)
edit_line(clean, 5, swap)
p = start("2")
time.sleep(15)
log.append({"step": "offline: edit clean seq 5 while stopped, then restart", "integrity_events": None,
            "messages": [e["message"] for e in integrity()][-3:]})
stop(p)
(run / "integrity-results.json").write_text(json.dumps(log, indent=1))
print(json.dumps(log, indent=1))
