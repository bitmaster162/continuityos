"""Default deny legacy MCP forget. Only synthetic OWNER capability fixtures."""
import hashlib
import json
import pytest
from continuityos.mcp_server import OWNER_FORGET_TOOL, Server, TOOLS


class FakeMemory:
    def __init__(self):
        self.deleted = []
    def forget(self, memory_id):
        self.deleted.append(memory_id)


def make_server(enabled=False, digest=""):
    server = object.__new__(Server)
    server.m = FakeMemory()
    server.turns = 0
    server._owner_forget_enabled = enabled
    server._owner_forget_sha256 = digest
    return server


def test_default_catalog_does_not_publish_forget():
    assert "forget" not in {tool["name"] for tool in TOOLS}
    assert OWNER_FORGET_TOOL["inputSchema"]["required"] == ["id", "owner_capability"]


@pytest.mark.parametrize("arguments", [
    {"id": 42}, {"id": 42, "owner_capability": "x" * 32},
    {"id": 42, "owner_capability": "x" * 32, "extra": True},
])
def test_default_server_rejects_forget_before_any_effect(arguments):
    server = make_server()
    with pytest.raises(PermissionError, match="OWNER_FORGET_DISABLED"):
        server.call("forget", arguments)
    assert server.m.deleted == []


@pytest.mark.parametrize("arguments", [
    {"id": 7},
    {"id": 7, "owner_capability": "invalid"},
    {"id": 7, "owner_capability": "b" * 32},
    {"id": 7, "owner_capability": "a" * 32, "other": "value"},
    {"id": True, "owner_capability": "a" * 32},
    {"id": 0, "owner_capability": "a" * 32},
])
def test_explicit_owner_mode_denies_invalid_capabilities(arguments):
    digest = hashlib.sha256(("a" * 32).encode()).hexdigest()
    server = make_server(True, digest)
    with pytest.raises(PermissionError, match="CAPABILITY"):
        server.call("forget", arguments)
    assert server.m.deleted == []


def test_owner_mode_requires_explicit_capability():
    token = "synthetic-owner-capability-only-" + ("z" * 40)
    digest = hashlib.sha256(token.encode()).hexdigest()
    server = make_server(True, digest)
    assert server.call("forget", {"id": 42, "owner_capability": token}) == "forgot #42"
    assert server.m.deleted == [42]


def test_default_constructor_never_enables_forget():
    # Source contract independent of legacy tests that monkeypatch Server.__init__.
    import ast
    from pathlib import Path
    import continuityos.mcp_server as mcp_module
    tree = ast.parse(Path(mcp_module.__file__).read_text(encoding="utf-8"))
    klass = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Server")
    initializer = next(n for n in klass.body if isinstance(n, ast.FunctionDef) and n.name == "__init__")
    defaults = dict(zip(
        [arg.arg for arg in initializer.args.kwonlyargs], initializer.args.kw_defaults
    ))
    assert isinstance(defaults["allow_owner_forget"], ast.Constant)
    assert defaults["allow_owner_forget"].value is False


def test_error_does_not_echo_capability():
    server = make_server(True, hashlib.sha256(b"x" * 32).hexdigest())
    secret = "y" * 40
    with pytest.raises(PermissionError) as err:
        server.call("forget", {"id": 7, "owner_capability": secret})
    assert secret not in str(err.value)


def test_catalog_tool_schema_has_no_extra_args():
    schema = OWNER_FORGET_TOOL["inputSchema"]
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"id", "owner_capability"}

def test_stdio_default_tool_list_and_forget_dispatch(monkeypatch):
    """Validate JSON-RPC surface, not only the exported TOOLS constant."""
    import io
    import sys
    import continuityos.mcp_server as module

    class SyntheticServer:
        def __init__(self, *args, **kwargs):
            self._owner_forget_enabled = False
            self.m = FakeMemory()
            self.turns = 0

        def call(self, name, args):
            return Server.call(self, name, args)

    monkeypatch.setattr(module, "Server", SyntheticServer)
    monkeypatch.setattr(sys, "argv", ["mcp_server", "--db", ":memory:"])
    inputs = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "forget", "arguments": {"id": 7}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "forget",
                    "arguments": {"id": 7, "owner_capability": "x" * 40}}},
    ]
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO(
        "".join(json.dumps(req) + "\n" for req in inputs)))
    monkeypatch.setattr(sys, "stdout", output)
    module.main()
    replies = [json.loads(line) for line in output.getvalue().splitlines()]
    assert "forget" not in {t["name"] for t in replies[0]["result"]["tools"]}
    assert replies[1]["result"]["isError"]
    assert replies[2]["result"]["isError"]
    assert "OWNER_FORGET_DISABLED" in replies[1]["result"]["content"][0]["text"]
    assert "OWNER_FORGET_DISABLED" in replies[2]["result"]["content"][0]["text"]

@pytest.mark.parametrize("invalid", ["", "x", "A" * 64, None, 7])
def test_invalid_owner_config_rejected_before_database_resolution(monkeypatch, invalid):
    import continuityos.mcp_server as module
    calls = []
    def forbidden_resolver(*args, **kwargs):
        calls.append("db")
        raise AssertionError("owner config touched database resolution")
    def forbidden_memory(*args, **kwargs):
        calls.append("memory")
        raise AssertionError("owner config opened SQLite")
    monkeypatch.setattr(module, "resolve_memory_db", forbidden_resolver)
    monkeypatch.setattr(module, "Memory", forbidden_memory)
    monkeypatch.setenv("CONTINUITYOS_EMBEDDER", "hash")
    with pytest.raises(ValueError, match="OWNER_FORGET_CAPABILITY_CONFIGURATION_INVALID"):
        module.Server(":memory:", allow_owner_forget=True, owner_capability_sha256=invalid)
    assert calls == []


def test_valid_owner_config_reaches_resolver_without_database_open(monkeypatch):
    import continuityos.mcp_server as module
    called = []
    def stop_at_resolver(*args, **kwargs):
        called.append("resolver")
        raise RuntimeError("SYNTHETIC_RESOLVER_STOP")
    monkeypatch.setattr(module, "resolve_memory_db", stop_at_resolver)
    monkeypatch.setenv("CONTINUITYOS_EMBEDDER", "hash")
    with pytest.raises(RuntimeError, match="SYNTHETIC_RESOLVER_STOP"):
        module.Server(":memory:", allow_owner_forget=True,
                      owner_capability_sha256="a" * 64)
    assert called == ["resolver"]


def test_stdio_bounded_oversized_line_discards_all_chunks(monkeypatch):
    import io
    import sys
    import continuityos.mcp_server as module

    class BoundedStdin(io.StringIO):
        def readline(self, size=-1):
            assert 0 < size <= module.MAX_STDIN_LINE_CHARS + 1
            return super().readline(size)

    class SyntheticServer:
        def __init__(self, *args, **kwargs):
            self._owner_forget_enabled = False
        def call(self, name, args):
            raise AssertionError("unexpected tools/call after oversized frame")

    huge = '{"jsonrpc":"2.0","id":91,"method":"tools/call","pad":"' + (
        "X" * (2 * module.MAX_STDIN_LINE_CHARS)) + '"}\n'
    valid = json.dumps({"jsonrpc": "2.0", "id": 92, "method": "tools/list"}) + "\n"
    output = io.StringIO()
    monkeypatch.setattr(module, "Server", SyntheticServer)
    monkeypatch.setattr(sys, "stdin", BoundedStdin(huge + valid))
    monkeypatch.setattr(sys, "stdout", output)
    monkeypatch.setattr(sys, "argv", ["mcp_server", "--db", ":memory:"])
    module.main()
    replies = [json.loads(line) for line in output.getvalue().splitlines()]
    assert [item["id"] for item in replies] == [92]
    assert "forget" not in {item["name"] for item in replies[0]["result"]["tools"]}
