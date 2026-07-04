import os, tempfile
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"]="1"
from continuityos.memory import Memory, MECW, MODEL_REGISTRY

def test_mecw_known_and_fallback():
    m=Memory(os.path.join(tempfile.mkdtemp(),"m.db"))
    # Opus effective < advertised; threshold = 65% of MECW
    assert m.compaction_threshold("claude-opus-4-8")==int(185_000*0.65)
    # unknown model -> 0.92*context fallback
    unk=m.compaction_threshold("no-such-model")
    assert unk>0
    # deepseek MECW much smaller than others
    assert m.compaction_threshold("deepseek-v4-pro") < m.compaction_threshold("gpt-5.5")
    print("PASS mecw_known_and_fallback")

def test_scan_dispatch():
    # exercise the CLI scan branch end-to-end
    from continuityos import cli
    db=os.path.join(tempfile.mkdtemp(),"m.db")
    cli.main(["--db",db,"canon","LLM never controls capital directly."])
    import io,contextlib
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli.main(["--db",db,"scan"])
    out=buf.getvalue()
    assert "SCAN" in out and "EASIEST to violate" in out and "never controls capital" in out
    print("PASS scan_dispatch")

def run():
    for n in sorted(x for x in globals() if x.startswith("test_")): globals()[n]()
    print("ALL_MECW_SCAN_TESTS_PASS")
if __name__=="__main__": run()
