"""External harness: runs Logan's AgentGuard code UNMODIFIED.
Per record: signature via handler.validate_path + models.Confidences (Logan's),
route via dispatch threshold (overall>0.8 -> auto-alert else analyst),
analyst via agent.AgentSession.evaluate (Logan's, fresh or reused session).
Captures verdict/reasoning/latency/failure as JSONL. No edits to agent_guard/*."""
import sys, json, time, asyncio
AG, CORPUS, MODE, OUTJSONL = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
# MODE: "reuse" (one analyst session across all records) or "fresh" (new session per record)
sys.path.insert(0, AG)
from agent_guard.event_handler import AGEventHandler
from agent_guard.models import LogLine, AgentView, Confidences
from agent_guard.agent import AgentSession
from dataclasses import asdict

ROOT = "/Users/<user>/projects/adop-cyse/testbed-repo"
handler = AGEventHandler(ROOT)

records = []
with open(CORPUS) as f:
    for line in f:
        line=line.strip()
        if not line: continue
        records.append(LogLine(**json.loads(line)))

async def run():
    out = open(OUTJSONL, "w")
    session = None
    for ll in records:
        conf = Confidences(path_traversal=handler.validate_path(ll))
        overall = conf.overall
        route = "auto-alert" if overall > 0.8 else "analyst"
        key_arg = {k: ll.arguments.get(k) for k in ("target_path","path","url","pathspec","key") if k in ll.arguments}
        rec = {"seq": ll.seq, "tool_name": ll.tool_name, "key_arg": key_arg,
               "sig_conf": overall, "route": route}
        if route == "analyst":
            av = AgentView.from_log_line(ll)
            if session is None or MODE=="fresh":
                session = AgentSession(session_id=ll.session_id)
            t0=time.perf_counter()
            try:
                v = await session.evaluate(av, conf)
                dt=(time.perf_counter()-t0)*1000
                rec.update(verdict=("alert" if v.alert else "suppress"), reasoning=v.reasoning, latency_ms=round(dt,1))
            except Exception as e:
                dt=(time.perf_counter()-t0)*1000
                # mirrors registry._handle_result: failure -> printed, record DROPPED (no alert)
                rec.update(verdict="failed", reasoning=f"{type(e).__name__}: {e}", latency_ms=round(dt,1))
        else:
            rec.update(verdict="(auto-alert, analyst not consulted)", reasoning=None, latency_ms=None)
        out.write(json.dumps(rec)+"\n"); out.flush()
        print(f"seq {rec['seq']:>2} {rec['tool_name']:<18} sig={overall} {route:<10} -> {rec['verdict']}")
    out.close()

asyncio.run(run())
