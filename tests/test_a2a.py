import tempfile, os, threading, json, urllib.request, urllib.error
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"]="1"
from continuityos.memory import Memory
from continuityos import a2a as A2A

def _call(port, method, params, token):
    req=urllib.request.Request("http://127.0.0.1:%d/"%port,
        data=json.dumps({"method":method,"params":params,"token":token}).encode(),
        headers={"Content-Type":"application/json"})
    try:
        r=urllib.request.urlopen(req,timeout=5); return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read())

def test_token_scopes_enforced():
    assert A2A.verify_token("s", A2A.mint_token("s","x","read"), "memory.recall")[0]
    assert not A2A.verify_token("s", A2A.mint_token("s","x","read"), "memory.upsert")[0]
    assert A2A.verify_token("s", A2A.mint_token("s","x","write"), "memory.upsert")[0]
    assert not A2A.verify_token("s", "bad.tok.en.sig", "ping")[0]

def test_server_read_write():
    m=Memory(os.path.join(tempfile.mkdtemp(),"t.db")); m.remember("hello world fact", namespace="facts")
    httpd=A2A.serve(m, secret="sec", port=8793); th=threading.Thread(target=httpd.serve_forever,daemon=True); th.start()
    try:
        rt=A2A.mint_token("sec","a","read"); wt=A2A.mint_token("sec","b","write")
        assert _call(8793,"memory.recall",{"query":"hello","k":1},rt)[0]==200
        assert _call(8793,"memory.upsert",{"text":"x","namespace":"facts","key":"z"},rt)[0]==401
        assert _call(8793,"memory.upsert",{"text":"x","namespace":"facts","key":"z"},wt)[0]==200
    finally:
        httpd.shutdown()
