#!/usr/bin/env python3
import subprocess, sys, tempfile, os, datetime, json, re
from continuityos import Memory
from continuityos.orchestrator import Orchestrator, Step

CODE = '''
import psycopg2, json, urllib.request
c=psycopg2.connect("postgresql://admin:admin@localhost:5432/sovereign").cursor()
out={}
c.execute("SELECT round(coalesce(sum(pnl_usd),0)::numeric), count(*), round(100.0*avg((pnl_usd>0)::int),1) FROM arena_all_trades WHERE status=%s AND closed_at>%s",("closed","2026-06-24 06:05+00"))
out["epoch"]=[str(x) for x in c.fetchone()]
c.execute("SELECT verdict,count(*) FROM arena_memento_reco GROUP BY verdict"); out["memento"]=dict((a,int(b)) for a,b in c.fetchall())
c.execute("SELECT count(*) FROM arena_bybit_liq"); out["bybit_liq"]=int(c.fetchone()[0])
try: out["risk"]=json.load(urllib.request.urlopen("http://localhost:8094/status",timeout=8)).get("risk_level")
except Exception: out["risk"]="?"
print(json.dumps(out,ensure_ascii=False))
'''

def researcher(prompt):
    r = subprocess.run(["ssh","-i",os.path.expanduser("~/.ssh/arena_ed25519"),"-o","StrictHostKeyChecking=no",
                        "mirokonkr@34.70.171.152","python3","-"],
                       input=CODE, capture_output=True, text=True, timeout=45)
    if r.returncode: raise RuntimeError(r.stderr[-150:])
    return r.stdout.strip().splitlines()[-1]

def writer(prompt):
    line = next(l for l in prompt.splitlines() if l.startswith("[s1]"))
    d, _ = json.JSONDecoder().raw_decode(line[line.find("{"):])
    pnl, n, wr = d["epoch"]
    return (f"# ☀️ Утренний дайджест арены — {datetime.date.today()}\n\n"
            f"**Эпоха (с 24.06):** PnL ${pnl} · {n} сделок · WR {wr}%\n"
            f"**Risk level:** {d['risk']}  ·  **Memento:** {d['memento']}\n"
            f"**Real Bybit liq в базе:** {d['bybit_liq']} событий\n\n"
            f"_Собрано оркестратором ContinuityOS 0.8.1 (Ф1 пилот): researcher→writer, gate активен._\n")

cps = []
m = Memory(os.path.join(tempfile.mkdtemp(), "pilot.db"))
orc = Orchestrator(m, agents={"researcher": researcher, "writer": writer},
    gate=lambda s: "деплой" not in s.goal and "deploy" not in s.goal.lower(),
    on_checkpoint=lambda s: cps.append(f"{s.id}:{s.status}"))
r = orc.run([
    Step("s1", "collect arena stats", assignee="researcher"),
    Step("s2", "write morning digest from upstream JSON", depends_on=["s1"], assignee="writer"),
    Step("s3", "деплой дайджеста в прод без ревью", depends_on=["s2"], assignee="writer"),
])
ok = r["steps"]["s2"]["status"] == "done" and r["steps"]["s3"]["status"] == "blocked"
print("PILOT:", "OK" if ok else "FAIL", "| checkpoints:", cps)
open("/tmp/digest_out.md", "w").write(r["steps"]["s2"]["result"])
print(r["steps"]["s2"]["result"])
print("s3 (gate):", r["steps"]["s3"]["result"])
