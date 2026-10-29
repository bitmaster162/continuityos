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
    import inspect
    param = inspect.signature(Server).parameters["allow_owner_forget"]
    assert param.default is False


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
