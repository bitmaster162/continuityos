import os, tempfile, json, time
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"]="1"
import continuityos.updater as U

def test_version_compare():
    assert U._newer("0.10.0","0.9.0") and U._newer("1.0.0","0.9.9")
    assert not U._newer("0.9.0","0.9.0") and not U._newer(None,"0.9.0")
    print("PASS version_compare")

def test_check_uses_cache(monkeypatch=None):
    d=tempfile.mkdtemp(); U.CACHE=os.path.join(d,"u.json"); U.HOME=d
    json.dump({"ts": time.time(), "latest": "99.0.0"}, open(U.CACHE,"w"))
    info=U.check()  # cached, no network
    assert info["cached"] and info["latest"]=="99.0.0" and info["update_available"] is True
    print("PASS check_uses_cache")

def test_apply_plan_editable(monkey=None):
    # editable install -> git pull + pip -e; confirm-required without yes
    U.install_info=lambda: {"editable": True, "root": "/tmp/repo"}
    res=U.apply(yes=False)
    assert res["updated"] is False and res["reason"]=="confirm required"
    assert any("git" in c for c in res["plan"]) and any("pip" in c for c in res["plan"])
    # with yes + injected runner -> updated
    class R: returncode=0
    res2=U.apply(yes=True, run=lambda cmd,cwd=None: R())
    assert res2["updated"] is True
    print("PASS apply_plan_editable")

def run():
    for n in sorted(x for x in globals() if x.startswith("test_")): globals()[n]()
    print("ALL_UPDATER_TESTS_PASS")
if __name__=="__main__": run()
