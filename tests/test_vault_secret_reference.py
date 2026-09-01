from __future__ import annotations

import ast
import builtins
from collections import Counter
from collections.abc import Mapping
import ctypes
import http.client
import importlib
import inspect
import io
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import urllib.request
import uuid

import pytest

import continuityos.vault_secret_reference as vsr


def _payload(**overrides):
    payload = {
        "provider": "unbound",
        "secret_kind": "credential",
        "purpose_id": "connector_auth",
        "required": True,
    }
    payload.update(overrides)
    return payload


def test_bounded_metadata_domains_are_literal_and_closed():
    assert vsr.SUPPORTED_PROVIDERS == ("unbound", "environment", "os-keyring", "external")
    assert vsr.SUPPORTED_SECRET_KINDS == (
        "api_key",
        "token",
        "password",
        "private_key",
        "credential",
        "other",
    )
    assert vsr.SUPPORTED_PURPOSES == ("connector_auth", "cross_ai_demo")


def test_unbound_reference_is_bounded_opaque_and_preserves_none_false_authority():
    receipt = vsr.build_secret_reference(
        provider="unbound",
        purpose_id="cross_ai_demo",
        secret_kind="api_key",
    )

    assert receipt["schema"] == "continuityos.vault_secret_reference/v1"
    assert receipt["mode"] == "METADATA_ONLY"
    assert re.fullmatch(r"vsr_[0-9a-f]{64}", receipt["reference_id"])
    assert receipt["reference_id_policy"] == "OPAQUE_STABLE_BOUNDED_METADATA_SHA256"
    assert receipt["purpose_id"] == "cross_ai_demo"
    assert receipt["purpose_id_policy"] == "BOUNDED_ALLOWLIST"
    assert receipt["provider"] == "unbound"
    assert "locator" not in receipt
    assert receipt["binding_present"] is False
    assert receipt["binding_authorized"] is False
    assert receipt["readiness"] == "PROVIDER_UNBOUND"
    assert receipt["dedicated_secret_value_present"] is False
    assert receipt["live_secret_access_available"] is False
    assert receipt["execution_authority"] == "NONE"
    assert receipt["can_execute"] is False
    assert receipt["can_trade"] is False
    assert receipt["capital_permission"] == "DENY"
    assert all(value is False for value in receipt["effects"].values())


def test_same_bounded_metadata_has_stable_id_and_canonical_json_across_key_order():
    payload = {
        "schema": vsr.SCHEMA,
        "mode": vsr.MODE,
        "provider": "external",
        "secret_kind": "token",
        "purpose_id": "connector_auth",
        "required": True,
    }
    reordered = dict(reversed(list(payload.items())))

    first_receipt = vsr.validate_secret_reference(payload)
    second_receipt = vsr.validate_secret_reference(reordered)
    first_json = vsr.canonical_secret_reference_json(payload)
    second_json = vsr.canonical_secret_reference_json(reordered)

    assert first_receipt == second_receipt
    assert first_json == second_json
    assert json.loads(first_json) == first_receipt
    assert first_receipt["reference_id"] == (
        "vsr_61e0ca323a3e8b845a326c32b7a08cd7"
        "61c8e12a9e6d0f784522224215b94e40"
    )


def test_each_bounded_identity_field_changes_the_opaque_reference_id():
    receipts = [
        vsr.validate_secret_reference(_payload()),
        vsr.validate_secret_reference(_payload(provider="external")),
        vsr.validate_secret_reference(_payload(secret_kind="token")),
        vsr.validate_secret_reference(_payload(purpose_id="cross_ai_demo")),
        vsr.validate_secret_reference(_payload(required=False)),
    ]

    assert len({receipt["reference_id"] for receipt in receipts}) == len(receipts)


@pytest.mark.parametrize(
    "reference_id",
    [
        "sk" + "-proj-" + "abcdefghijklmnopqrstuvwxyz",
        "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789",
        "vsr_" + "a" * 64,
        "friendly-public-alias",
    ],
)
def test_caller_reference_id_is_rejected_without_echo(reference_id):
    with pytest.raises(vsr.SecretReferenceError) as captured:
        vsr.validate_secret_reference({**_payload(), "reference_id": reference_id})

    assert str(captured.value) == "CALLER_REFERENCE_ID_FORBIDDEN"
    assert reference_id not in str(captured.value)


@pytest.mark.parametrize("purpose_id", vsr.SUPPORTED_PURPOSES)
def test_only_bounded_purpose_ids_are_returned(purpose_id):
    receipt = vsr.build_secret_reference(purpose_id=purpose_id)
    assert receipt["purpose_id"] == purpose_id


@pytest.mark.parametrize(
    "purpose_id",
    [
        "sk" + "-proj-" + "abcdefghijklmnopqrstuvwxyz",
        "github_connector",
        "CONNECTOR_AUTH",
        "connector_auth\u200b",
        "",
        None,
        1,
    ],
)
def test_unbounded_purpose_is_rejected_without_echo(purpose_id):
    with pytest.raises(vsr.SecretReferenceError) as captured:
        vsr.build_secret_reference(purpose_id=purpose_id)

    assert str(captured.value) == "PURPOSE_UNSUPPORTED"
    if isinstance(purpose_id, str) and purpose_id:
        assert purpose_id not in str(captured.value)


def test_declared_environment_provider_class_never_reads_or_binds_environment(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "super-secret-value-that-must-never-be-read")

    receipt = vsr.build_secret_reference(
        provider="environment",
        purpose_id="cross_ai_demo",
        secret_kind="api_key",
    )

    encoded = json.dumps(receipt, sort_keys=True)
    assert receipt["readiness"] == "PROVIDER_CLASS_DECLARED_BINDING_NOT_AUTHORIZED"
    assert receipt["binding_present"] is False
    assert receipt["binding_authorized"] is False
    assert receipt["effects"]["secret_binding_accepted"] is False
    assert receipt["effects"]["environment_read"] is False
    assert "locator" not in receipt
    assert "OPENAI_API_KEY" not in encoded
    assert "super-secret-value-that-must-never-be-read" not in encoded


@pytest.mark.parametrize(
    "field",
    [
        "secret",
        "secret_value",
        "value",
        "token_value",
        "password_value",
        "private_key_value",
        "api_key_value",
        "credential_value",
        "plaintext",
        "ciphertext",
    ],
)
def test_secret_bearing_fields_are_rejected(field):
    value = "definitely-not-metadata"
    with pytest.raises(vsr.SecretReferenceError) as captured:
        vsr.validate_secret_reference({**_payload(), field: value})

    assert str(captured.value) == "SECRET_VALUE_FIELD_FORBIDDEN"
    assert value not in str(captured.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("locator", "OPENAI_API_KEY"),
        ("locator", "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789"),
        ("binding", "provider-owned-reference"),
        ("binding_id", "credential-123"),
        ("secret_id", "secret-123"),
        ("environment_variable", "OPENAI_API_KEY"),
        ("env_name", "OPENAI_API_KEY"),
        ("variable_name", "OPENAI_API_KEY"),
        ("keyring_entry", "continuityos/openai"),
        ("external_secret_id", "vault/path/item"),
    ],
)
def test_concrete_binding_fields_are_rejected_before_any_value_can_be_echoed(field, value):
    with pytest.raises(vsr.SecretReferenceError) as captured:
        vsr.validate_secret_reference({**_payload(provider="environment"), field: value})

    assert str(captured.value) == "SECRET_BINDING_FIELD_FORBIDDEN"
    assert value not in str(captured.value)


def test_build_api_has_no_caller_reference_or_binding_parameter():
    parameters = inspect.signature(vsr.build_secret_reference).parameters
    assert "reference_id" not in parameters
    assert "locator" not in parameters
    assert "binding" not in parameters
    assert "binding_id" not in parameters
    assert "secret_id" not in parameters


def test_provider_classes_never_imply_a_binding():
    for provider in vsr.SUPPORTED_PROVIDERS:
        receipt = vsr.build_secret_reference(
            provider=provider,
            purpose_id="connector_auth",
        )
        assert receipt["provider"] == provider
        assert receipt["binding_present"] is False
        assert receipt["binding_authorized"] is False
        assert "locator" not in receipt
        assert receipt["redaction"]["binding_locators"] == "NOT_ACCEPTED_IN_METADATA_ONLY_V1"


class _HostileMapping(Mapping):
    touched = False

    def __getitem__(self, key):
        self.touched = True
        raise AssertionError("hostile mapping hook executed")

    def __iter__(self):
        self.touched = True
        raise AssertionError("hostile mapping hook executed")

    def __len__(self):
        self.touched = True
        raise AssertionError("hostile mapping hook executed")


class _HostileDict(dict):
    touched = False

    def __iter__(self):
        self.touched = True
        raise AssertionError("hostile dict hook executed")

    def get(self, key, default=None):
        self.touched = True
        raise AssertionError("hostile dict hook executed")


def test_non_exact_dict_inputs_are_rejected_before_caller_hooks():
    for api in (vsr.validate_secret_reference, vsr.canonical_secret_reference_json):
        for payload in (_HostileMapping(), _HostileDict()):
            with pytest.raises(vsr.SecretReferenceError) as captured:
                api(payload)
            assert str(captured.value) == "PAYLOAD_INVALID"
            assert payload.touched is False


class _HostileString(str):
    touched = False

    def __eq__(self, other):
        self.touched = True
        raise AssertionError("hostile string comparison executed")

    def __hash__(self):
        self.touched = True
        raise AssertionError("hostile string hashing executed")

    def __format__(self, format_spec):
        self.touched = True
        raise AssertionError("hostile string formatting executed")

    def __bool__(self):
        self.touched = True
        raise AssertionError("hostile string truthiness executed")

    def __iter__(self):
        self.touched = True
        raise AssertionError("hostile string iteration executed")


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("provider", "PROVIDER_UNSUPPORTED"),
        ("secret_kind", "SECRET_KIND_UNSUPPORTED"),
        ("purpose_id", "PURPOSE_UNSUPPORTED"),
    ],
)
def test_build_rejects_string_subclasses_before_implicit_protocols(field, reason):
    values = {
        "provider": "unbound",
        "secret_kind": "credential",
        "purpose_id": "connector_auth",
    }
    hostile = _HostileString(values[field])
    values[field] = hostile

    with pytest.raises(vsr.SecretReferenceError) as captured:
        vsr.build_secret_reference(**values)
    assert str(captured.value) == reason
    assert hostile.touched is False


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("provider", "unbound", "PROVIDER_UNSUPPORTED"),
        ("secret_kind", "credential", "SECRET_KIND_UNSUPPORTED"),
        ("purpose_id", "connector_auth", "PURPOSE_UNSUPPORTED"),
        ("schema", vsr.SCHEMA, "SCHEMA_UNSUPPORTED"),
        ("mode", vsr.MODE, "MODE_UNSUPPORTED"),
    ],
)
def test_validate_and_canonical_reject_string_subclasses_before_implicit_protocols(
    field,
    value,
    reason,
):
    for api in (vsr.validate_secret_reference, vsr.canonical_secret_reference_json):
        hostile = _HostileString(value)
        payload = _payload(**{field: hostile})

        with pytest.raises(vsr.SecretReferenceError) as captured:
            api(payload)
        assert str(captured.value) == reason
        assert hostile.touched is False


class _HostileRequired:
    touched = False

    def _touch(self, *args, **kwargs):
        self.touched = True
        raise AssertionError("hostile required-value protocol executed")

    __bool__ = _touch
    __eq__ = _touch
    __hash__ = _touch
    __format__ = _touch
    __iter__ = _touch


def test_required_rejects_hostile_objects_before_implicit_protocols():
    for api in (
        lambda value: vsr.build_secret_reference(
            purpose_id="connector_auth",
            required=value,
        ),
        lambda value: vsr.validate_secret_reference(_payload(required=value)),
        lambda value: vsr.canonical_secret_reference_json(_payload(required=value)),
    ):
        hostile = _HostileRequired()
        with pytest.raises(vsr.SecretReferenceError) as captured:
            api(hostile)
        assert str(captured.value) == "REQUIRED_INVALID"
        assert hostile.touched is False


def test_validation_is_strict_and_never_accepts_non_string_keys():
    with pytest.raises(vsr.SecretReferenceError, match="UNEXPECTED_FIELD"):
        vsr.validate_secret_reference({**_payload(), "notes": "not part of v1"})
    with pytest.raises(vsr.SecretReferenceError, match="UNEXPECTED_FIELD"):
        vsr.validate_secret_reference({**_payload(), 1: "not a field"})
    with pytest.raises(vsr.SecretReferenceError, match="REQUIRED_INVALID"):
        vsr.validate_secret_reference(_payload(required=1))


_EXPECTED_IMPORTS = frozenset(
    {
        ("from", "__future__", 0, (("annotations", None),)),
        ("from", "dataclasses", 0, (("dataclass", None),)),
        ("import", None, 0, (("hashlib", None),)),
        ("import", None, 0, (("json", None),)),
        ("from", "typing", 0, (("Any", None),)),
    }
)
_ALLOWED_CALLS = frozenset(
    {
        "SecretReferenceError",
        "_bounded_string",
        "_effects",
        "_governance",
        "_opaque_reference_id",
        "_purpose",
        "build_secret_reference",
        "dataclass",
        "frozenset",
        "hashlib.sha256",
        "hashlib.sha256(...).hexdigest",
        "json.dumps",
        "payload.get",
        "seed.encode",
        "set",
        "type",
        "validate_secret_reference",
    }
)
_ALLOWED_ATTRIBUTES = frozenset(
    {
        "hashlib.sha256",
        "hashlib.sha256(...).hexdigest",
        "json.dumps",
        "payload.get",
        "seed.encode",
        "self.reason",
    }
)
_EXPECTED_CALL_COUNTS = Counter(
    {
        "SecretReferenceError": 11,
        "_bounded_string": 2,
        "_effects": 1,
        "_governance": 1,
        "_opaque_reference_id": 1,
        "_purpose": 1,
        "build_secret_reference": 1,
        "dataclass": 1,
        "frozenset": 3,
        "hashlib.sha256": 1,
        "hashlib.sha256(...).hexdigest": 1,
        "json.dumps": 2,
        "payload.get": 6,
        "seed.encode": 1,
        "set": 1,
        "type": 7,
        "validate_secret_reference": 1,
    }
)
_EXPECTED_ATTRIBUTE_COUNTS = Counter(
    {
        "hashlib.sha256": 1,
        "hashlib.sha256(...).hexdigest": 1,
        "json.dumps": 2,
        "payload.get": 6,
        "seed.encode": 1,
        "self.reason": 1,
    }
)
_EXPECTED_SUBSCRIPT_COUNTS = Counter({"dict[str, Any]": 6, "tuple[str, ...]": 1})
_EXPECTED_COMPARE_COUNTS = Counter(
    {
        "type(required) is not bool": 1,
        "provider_code == 'unbound'": 1,
        "type(payload) is not dict": 1,
        "'reference_id' in keys": 1,
        "type(value) is not str": 2,
        "value not in supported": 1,
        "value not in SUPPORTED_PURPOSES": 1,
        "type(key) is not str": 1,
        "type(schema) is not str": 1,
        "schema != SCHEMA": 1,
        "type(mode) is not str": 1,
        "mode != MODE": 1,
    }
)
_EXPECTED_BOOL_OP_COUNTS = Counter(
    {
        "type(value) is not str or value not in supported": 1,
        "type(value) is not str or value not in SUPPORTED_PURPOSES": 1,
        "type(schema) is not str or schema != SCHEMA": 1,
        "type(mode) is not str or mode != MODE": 1,
    }
)
_EXPECTED_BIN_OP_COUNTS = Counter(
    {
        "_REFERENCE_ID_DOMAIN + seed.encode('ascii')": 1,
        "keys & _FORBIDDEN_SECRET_FIELDS": 1,
        "keys & _FORBIDDEN_BINDING_FIELDS": 1,
        "keys - _ALLOWED_INPUT_FIELDS": 1,
    }
)
_EXPECTED_IF_TEST_COUNTS = Counter(
    {
        "type(value) is not str or value not in supported": 1,
        "type(value) is not str or value not in SUPPORTED_PURPOSES": 1,
        "type(required) is not bool": 1,
        "provider_code == 'unbound'": 1,
        "type(payload) is not dict": 1,
        "type(key) is not str": 1,
        "forbidden_secret": 1,
        "forbidden_binding": 1,
        "'reference_id' in keys": 1,
        "unexpected": 1,
        "type(schema) is not str or schema != SCHEMA": 1,
        "type(mode) is not str or mode != MODE": 1,
    }
)
_EXPECTED_AST_NODE_TYPE_COUNTS = Counter(
    {
        "Add": 1,
        "AnnAssign": 1,
        "Assign": 25,
        "Attribute": 12,
        "BinOp": 4,
        "BitAnd": 2,
        "BoolOp": 4,
        "Call": 42,
        "ClassDef": 1,
        "Compare": 13,
        "Constant": 166,
        "Dict": 5,
        "Eq": 1,
        "Expr": 4,
        "For": 1,
        "FormattedValue": 1,
        "FunctionDef": 9,
        "If": 12,
        "Import": 2,
        "ImportFrom": 3,
        "In": 1,
        "IsNot": 7,
        "JoinedStr": 1,
        "Load": 179,
        "Module": 1,
        "Name": 175,
        "NotEq": 2,
        "NotIn": 2,
        "Or": 4,
        "Raise": 11,
        "Return": 9,
        "Set": 3,
        "Store": 27,
        "Sub": 1,
        "Subscript": 7,
        "Tuple": 12,
        "alias": 5,
        "arg": 15,
        "arguments": 9,
        "keyword": 15,
    }
)
_EXPECTED_FUNCTIONS = frozenset(
    {
        "__str__",
        "_bounded_string",
        "_effects",
        "_governance",
        "_opaque_reference_id",
        "_purpose",
        "build_secret_reference",
        "canonical_secret_reference_json",
        "validate_secret_reference",
    }
)
_EXPECTED_CLASSES = frozenset({"SecretReferenceError"})
_FORBIDDEN_NAME_LOADS = frozenset(
    {
        "__builtins__",
        "__import__",
        "breakpoint",
        "compile",
        "delattr",
        "dir",
        "eval",
        "exec",
        "getattr",
        "globals",
        "hasattr",
        "help",
        "input",
        "locals",
        "open",
        "setattr",
        "vars",
    }
)
_PROTECTED_BINDINGS = frozenset(
    {
        "SecretReferenceError",
        "_bounded_string",
        "_effects",
        "_governance",
        "_opaque_reference_id",
        "_purpose",
        "build_secret_reference",
        "canonical_secret_reference_json",
        "dataclass",
        "frozenset",
        "hashlib",
        "json",
        "payload",
        "set",
        "type",
        "validate_secret_reference",
    }
)


def _import_key(node):
    if isinstance(node, ast.Import):
        return (
            "import",
            None,
            0,
            tuple((item.name, item.asname) for item in node.names),
        )
    return (
        "from",
        node.module,
        node.level,
        tuple((item.name, item.asname) for item in node.names),
    )


def _qname(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _qname(node.value)
        if base is not None:
            return f"{base}.{node.attr}"
    return None


def _attribute_key(node):
    if (
        node.attr == "hexdigest"
        and isinstance(node.value, ast.Call)
        and _qname(node.value.func) == "hashlib.sha256"
    ):
        return "hashlib.sha256(...).hexdigest"
    return _qname(node)


def _call_key(node):
    if isinstance(node.func, ast.Attribute):
        return _attribute_key(node.func)
    return _qname(node.func)


def _assert_metadata_only_ast(source: str) -> None:
    tree = ast.parse(source)

    node_type_counts = Counter(type(node).__name__ for node in ast.walk(tree))
    assert node_type_counts == _EXPECTED_AST_NODE_TYPE_COUNTS

    imports = [
        _import_key(node)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    assert len(imports) == len(_EXPECTED_IMPORTS)
    assert frozenset(imports) == _EXPECTED_IMPORTS

    functions = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    assert len(functions) == len(_EXPECTED_FUNCTIONS)
    assert frozenset(functions) == _EXPECTED_FUNCTIONS
    assert len(classes) == len(_EXPECTED_CLASSES)
    assert frozenset(classes) == _EXPECTED_CLASSES

    call_counts = Counter(
        _call_key(node) for node in ast.walk(tree) if isinstance(node, ast.Call)
    )
    attribute_counts = Counter(
        _attribute_key(node)
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
    )
    assert set(call_counts) <= _ALLOWED_CALLS
    assert set(attribute_counts) <= _ALLOWED_ATTRIBUTES
    assert call_counts == _EXPECTED_CALL_COUNTS
    assert attribute_counts == _EXPECTED_ATTRIBUTE_COUNTS

    subscript_counts = Counter(
        ast.unparse(node) for node in ast.walk(tree) if isinstance(node, ast.Subscript)
    )
    compare_counts = Counter(
        ast.unparse(node) for node in ast.walk(tree) if isinstance(node, ast.Compare)
    )
    bool_op_counts = Counter(
        ast.unparse(node) for node in ast.walk(tree) if isinstance(node, ast.BoolOp)
    )
    bin_op_counts = Counter(
        ast.unparse(node) for node in ast.walk(tree) if isinstance(node, ast.BinOp)
    )
    if_test_counts = Counter(
        ast.unparse(node.test) for node in ast.walk(tree) if isinstance(node, ast.If)
    )
    assert subscript_counts == _EXPECTED_SUBSCRIPT_COUNTS
    assert compare_counts == _EXPECTED_COMPARE_COUNTS
    assert bool_op_counts == _EXPECTED_BOOL_OP_COUNTS
    assert bin_op_counts == _EXPECTED_BIN_OP_COUNTS
    assert if_test_counts == _EXPECTED_IF_TEST_COUNTS

    loops = [node for node in ast.walk(tree) if isinstance(node, ast.For)]
    assert len(loops) == 1
    assert isinstance(loops[0].target, ast.Name)
    assert loops[0].target.id == "key"
    assert isinstance(loops[0].iter, ast.Name)
    assert loops[0].iter.id == "payload"
    assert loops[0].orelse == []
    assert not any(isinstance(node, ast.UnaryOp) for node in ast.walk(tree))

    annotated_assignments = [
        node for node in ast.walk(tree) if isinstance(node, ast.AnnAssign)
    ]
    assert len(annotated_assignments) == 1
    assert isinstance(annotated_assignments[0].target, ast.Name)
    assert annotated_assignments[0].target.id == "reason"
    assert isinstance(annotated_assignments[0].annotation, ast.Name)
    assert annotated_assignments[0].annotation.id == "str"
    assert annotated_assignments[0].value is None
    assert annotated_assignments[0].simple == 1

    joined_strings = [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]
    formatted_values = [
        node for node in ast.walk(tree) if isinstance(node, ast.FormattedValue)
    ]
    assert len(joined_strings) == 1
    assert len(formatted_values) == 1
    assert len(joined_strings[0].values) == 2
    assert isinstance(joined_strings[0].values[0], ast.Constant)
    assert joined_strings[0].values[0].value == "vsr_"
    assert isinstance(formatted_values[0].value, ast.Name)
    assert formatted_values[0].value.id == "digest"
    assert formatted_values[0].conversion == -1
    assert formatted_values[0].format_spec is None

    sets = [node for node in ast.walk(tree) if isinstance(node, ast.Set)]
    dictionaries = [node for node in ast.walk(tree) if isinstance(node, ast.Dict)]
    assert len(sets) == 3
    assert all(
        isinstance(element, ast.Constant) and type(element.value) is str
        for node in sets
        for element in node.elts
    )
    assert len(dictionaries) == 5
    assert sum(key is None for node in dictionaries for key in node.keys) == 1
    assert all(
        key is None or (isinstance(key, ast.Constant) and type(key.value) is str)
        for node in dictionaries
        for key in node.keys
    )

    forbidden_syntax = (
        ast.AsyncFunctionDef,
        ast.AsyncWith,
        ast.Assert,
        ast.Await,
        ast.AugAssign,
        ast.Delete,
        ast.DictComp,
        ast.GeneratorExp,
        ast.Global,
        ast.Lambda,
        ast.ListComp,
        ast.Match,
        ast.NamedExpr,
        ast.Nonlocal,
        ast.Starred,
        ast.SetComp,
        ast.Try,
        ast.While,
        ast.With,
        ast.Yield,
        ast.YieldFrom,
    )
    bad_syntax = [
        (node.lineno, type(node).__name__)
        for node in ast.walk(tree)
        if isinstance(node, forbidden_syntax)
    ]
    assert bad_syntax == []

    bad_mutations = [
        (node.lineno, ast.unparse(node))
        for node in ast.walk(tree)
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.List, ast.Tuple))
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    assert bad_mutations == []

    bad_names = [
        (node.lineno, node.id)
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id in _FORBIDDEN_NAME_LOADS
    ]
    assert bad_names == []

    rebound = [
        (node.lineno, node.id)
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Store)
        and node.id in _PROTECTED_BINDINGS
    ]
    assert rebound == []

    shadowed_arguments = [
        (node.lineno, node.arg)
        for node in ast.walk(tree)
        if isinstance(node, ast.arg)
        and node.arg in (_PROTECTED_BINDINGS - {"payload"})
    ]
    assert shadowed_arguments == []


def test_module_obeys_exact_positive_ast_capability_allowlist():
    source = Path(vsr.__file__).read_text(encoding="utf-8")
    _assert_metadata_only_ast(source)


@pytest.mark.parametrize(
    "snippet",
    [
        "from os import getenv\ngetenv('TOKEN')",
        "import pathlib\npathlib.Path('x').read_text()",
        "import httpx\nhttpx.get('https://example.invalid')",
        "import socket\nsocket.socket()",
        "import subprocess\nsubprocess.run(['true'])",
        "import asyncio\nasyncio.create_subprocess_exec('true')",
        "import importlib\nimportlib.import_module('os')",
        "__import__('os')",
        "open('secret.txt')",
        "getattr(__builtins__, '__import__')('os')",
    ],
)
def test_ast_gate_rejects_import_and_dynamic_capability_bypasses(snippet):
    source = Path(vsr.__file__).read_text(encoding="utf-8")
    with pytest.raises(AssertionError):
        _assert_metadata_only_ast(f"{source}\n{snippet}\n")


@pytest.mark.parametrize(
    "mutation",
    [
        'probe = f"{payload[\'purpose_id\']}"',
        'probe = payload["purpose_id"] == payload["purpose_id"]',
        'probe = payload["purpose_id"]["nested"]',
        'for probe in payload.get("purpose_id"):\n        pass',
        'if payload.get("purpose_id"):\n        pass',
        'probe = {payload.get("purpose_id")}',
        "probe = 1 if required else 0",
    ],
)
def test_ast_gate_rejects_new_implicit_protocols_on_caller_values(mutation):
    source = Path(vsr.__file__).read_text(encoding="utf-8")
    marker = "    receipt = validate_secret_reference(payload)"
    assert source.count(marker) == 1
    mutated = source.replace(marker, f"    {mutation}\n{marker}", 1)

    with pytest.raises(AssertionError):
        _assert_metadata_only_ast(mutated)


class _DeniedEnvironment:
    def __init__(self, events):
        self.events = events

    def _deny(self, *args, **kwargs):
        self.events.append("os.environ")
        raise AssertionError("environment capability touched")

    __getitem__ = _deny
    __setitem__ = _deny
    __delitem__ = _deny
    __iter__ = _deny
    __len__ = _deny
    get = _deny
    copy = _deny


def test_build_validate_and_canonical_json_do_not_touch_runtime_capabilities(monkeypatch):
    events = []

    def deny(label):
        def blocked(*args, **kwargs):
            events.append(label)
            raise AssertionError(f"forbidden runtime capability: {label}")

        return blocked

    def patch_many(mp, obj, names, prefix):
        for name in names:
            if hasattr(obj, name):
                mp.setattr(obj, name, deny(f"{prefix}.{name}"))

    receipts = []
    with monkeypatch.context() as mp:
        mp.setattr(os, "environ", _DeniedEnvironment(events))
        if hasattr(os, "environb"):
            mp.setattr(os, "environb", _DeniedEnvironment(events))

        patch_many(mp, builtins, ("open", "eval", "exec", "compile"), "builtins")
        patch_many(mp, io, ("open",), "io")
        patch_many(
            mp,
            os,
            (
                "getenv",
                "urandom",
                "open",
                "fdopen",
                "popen",
                "system",
                "listdir",
                "scandir",
                "walk",
                "stat",
                "lstat",
                "readlink",
                "mkdir",
                "makedirs",
                "remove",
                "unlink",
                "rename",
                "replace",
                "rmdir",
                "getcwd",
                "putenv",
                "unsetenv",
                "execl",
                "execle",
                "execlp",
                "execlpe",
                "execv",
                "execve",
                "execvp",
                "execvpe",
                "posix_spawn",
                "posix_spawnp",
            ),
            "os",
        )
        patch_many(
            mp,
            Path,
            (
                "open",
                "read_text",
                "read_bytes",
                "write_text",
                "write_bytes",
                "touch",
                "unlink",
                "rename",
                "replace",
                "mkdir",
                "rmdir",
                "iterdir",
                "glob",
                "rglob",
                "stat",
                "exists",
                "is_file",
                "resolve",
                "cwd",
                "home",
            ),
            "Path",
        )
        patch_many(mp, socket, ("socket", "create_connection", "getaddrinfo"), "socket")
        patch_many(mp, urllib.request, ("urlopen",), "urllib.request")
        patch_many(mp, http.client, ("HTTPConnection", "HTTPSConnection"), "http.client")
        patch_many(
            mp,
            subprocess,
            ("Popen", "run", "call", "check_call", "check_output", "getoutput", "getstatusoutput"),
            "subprocess",
        )
        patch_many(mp, ctypes, ("CDLL", "PyDLL", "WinDLL", "OleDLL"), "ctypes")
        patch_many(mp, secrets, ("token_bytes", "token_hex", "token_urlsafe"), "secrets")
        patch_many(mp, uuid, ("uuid1", "uuid4"), "uuid")
        mp.setattr(importlib, "import_module", deny("importlib.import_module"))
        # pytest's monkeypatch implementation may import ``inspect`` internally.
        # Patch __import__ only after every other patch has been installed.
        mp.setattr(builtins, "__import__", deny("builtins.__import__"))

        for provider in vsr.SUPPORTED_PROVIDERS:
            for secret_kind in vsr.SUPPORTED_SECRET_KINDS:
                for purpose_id in vsr.SUPPORTED_PURPOSES:
                    for required in (False, True):
                        payload = {
                            "provider": provider,
                            "secret_kind": secret_kind,
                            "purpose_id": purpose_id,
                            "required": required,
                        }
                        built = vsr.build_secret_reference(**payload)
                        validated = vsr.validate_secret_reference(dict(payload))
                        encoded = vsr.canonical_secret_reference_json(dict(payload))
                        assert built == validated
                        receipts.append((built, encoded))

    assert events == []
    assert len(receipts) == 96
    assert len({receipt["reference_id"] for receipt, _ in receipts}) == 96
    for receipt, encoded in receipts:
        assert json.loads(encoded) == receipt
