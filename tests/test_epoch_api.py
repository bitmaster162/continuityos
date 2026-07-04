import tempfile, os, threading, json, urllib.request, urllib.error
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"] = "1"
from http.server import ThreadingHTTPServer
from continuityos.memory import Memory
from continuityos.api import make_handler

def _srv(port):
    m = Memory(os.path.join(tempfile.mkdtemp(), "a.db"))
    h = ThreadingHTTPServer(("127.0.0.1", port), make_handler(m))
    threading.Thread(target=h.serve_forever, daemon=True).start()
    return h

def _post(port, path, obj):
    r = urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%d%s" % (port, path),
        data=json.dumps(obj).encode(), headers={"Content-Type": "application/json"}), timeout=5)
    return json.loads(r.read())

def _get(port, path):
    r = urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=5)
    return r, json.loads(r.read())

def test_epoch_endpoints_and_cors():
    h = _srv(8479)
    try:
        _post(8479, "/epoch/commit", {"branch": "main", "label": "g1", "metrics": {"wr": 0.3}})
        _post(8479, "/epoch/commit", {"branch": "main", "label": "g2", "metrics": {"wr": 0.4, "gate_pass": 1}})
        r, g = _get(8479, "/epoch/graph")
        assert len(g["nodes"]) == 2 and len(g["edges"]) == 1
        assert r.headers.get("Access-Control-Allow-Origin") == "*"   # CORS for file:// viewer
    finally:
        h.shutdown()

def test_named_graph_store_and_serve():
    h = _srv(8481)
    try:
        _post(8481, "/graph/eco", {"nodes": [{"id": "a", "type": "skill", "name": "A"}], "edges": [], "types": ["skill"]})
        r, g = _get(8481, "/graph/eco")
        assert g["nodes"][0]["id"] == "a" and g["types"] == ["skill"]
        try:
            _get(8481, "/graph/missing"); assert False, "should 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        h.shutdown()
