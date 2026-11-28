"""ContinuityOS MCP server (stdio transport, dependency-free).

Exposes durable memory to any MCP client (Claude Desktop, Claude Code, etc.):
  - remember(text, namespace?, tags?)   -> store a memory
  - recall(query, k?, namespace?)        -> hybrid (structural+semantic) recall
  - upsert(text, namespace?, key)        -> create-or-update by semantic key (idempotent)
  - find(namespace?, key)                -> exact key lookup (deterministic point-read)
  - forget(id, owner_capability)          -> disabled unless OWNER explicitly opts in
  - list_namespaces()                    -> folder-like overview
  - context(query, k?)                   -> ready-to-inject context block

Run:  python -m continuityos.mcp_server --db ~/.continuityos/memory.db [--policy path/to/policy.json]
Newline-delimited JSON-RPC over stdin/stdout (MCP stdio transport).
"""
from __future__ import annotations
import sys, json, os, argparse, hashlib, hmac, re
from .memory import Memory
from .continuity import Continuity
from .twin import Twin
from .control import ControlPlane
from .db import resolve_memory_db
from .gate import ActionSpec as _AS, preflight as _preflight, Ledger as _Ledger
from .gate.broker import GateBroker as _GateBroker
from .gate.policy import discover_policy as _discover_policy, load_policy as _load_policy
from . import __version__

PROTOCOL = "2024-11-05"
_PRODUCT_LEDGER = _Ledger

_CONTEXT_SCOPE_PROPERTIES = {
    "project": {"type": "string", "minLength": 1,
                "description": "Exact context project. Selects records, not access authority."},
    "subject": {"type": "string", "minLength": 1,
                "description": "Exact context subject. Selects records, not authenticated identity."},
}
_CONTEXT_SNAPSHOT_PROPERTIES = {
    **_CONTEXT_SCOPE_PROPERTIES,
    "max_items": {"type": "integer", "minimum": 0,
                  "description": "Optional complete snapshot budget. Overflow returns HOLD without partial context."},
    "max_bytes": {"type": "integer", "minimum": 0,
                  "description": "Optional canonical UTF-8 snapshot payload budget. Overflow returns HOLD."},
}


def _build_windows_r15_monotonic_anchor(**kwargs):
    # Lazy import keeps ordinary R14/non-Windows product startup unchanged.
    from .gate.windows_tpm_product_runtime import (
        build_windows_r15_monotonic_anchor,
    )
    return build_windows_r15_monotonic_anchor(**kwargs)


TOOLS = [
 {"name":"remember","description":"Store a durable memory. Use for facts about the user, projects, rules, decisions you should recall later.",
  "inputSchema":{"type":"object","properties":{
     "text":{"type":"string","description":"The memory content."},
     "namespace":{"type":"string","description":"Folder-like bucket: identity|projects|rules|facts|events|notes (or your own).","default":"notes"},
     "tags":{"type":"array","items":{"type":"string"},"description":"Optional tags."}},
   "required":["text"]}},
 {"name":"recall","description":"Hybrid recall (structural keyword + semantic vector) of the most relevant memories for a query.",
  "inputSchema":{"type":"object","properties":{
     "query":{"type":"string"},
     "k":{"type":"integer","default":5},
     "namespace":{"type":"string","description":"Optional: restrict to one namespace."}},
   "required":["query"]}},
 {"name":"upsert","description":"Create-or-update a memory by semantic KEY (idempotent). If (namespace,key) exists it is superseded (history kept) and replaced; else created. Use for stable values an agent overwrites over time: a config value, a current decision, a user preference.",
  "inputSchema":{"type":"object","properties":{
     "text":{"type":"string","description":"The new value."},
     "namespace":{"type":"string","default":"facts"},
     "key":{"type":"string","description":"Stable semantic key, e.g. default_model or user.timezone."},
     "tags":{"type":"array","items":{"type":"string"}}},
   "required":["text","key"]}},
 {"name":"find","description":"Exact key lookup: the CURRENT value stored under (namespace,key), or null. Deterministic point-read (not fuzzy recall) - reads back what upsert wrote.",
  "inputSchema":{"type":"object","properties":{
     "namespace":{"type":"string","default":"facts"},
     "key":{"type":"string"}},
   "required":["key"]}},
 {"name":"context","description":"Return a ready-to-inject context block of the most relevant memories for a query.",
  "inputSchema":{"type":"object","properties":{"query":{"type":"string"},"k":{"type":"integer","default":6}},"required":["query"]}},
 {"name":"list_namespaces","description":"List folder-like namespaces and how many memories each holds.",
  "inputSchema":{"type":"object","properties":{}}} ,
 {"name":"checkpoint","description":"Record a scoped session delta, next action, lifecycle and proof reference. A reference does not prove an external result.",
  "inputSchema":{"type":"object","additionalProperties":False,"properties":{**_CONTEXT_SCOPE_PROPERTIES,"summary":{"type":"string"},"next_action":{"type":"string"},"proof":{"type":"string"},"lifecycle":{"type":"string","enum":["ACTIVE","PAUSED","DONE"],"default":"ACTIVE"}},"required":["summary","next_action"]}},
 {"name":"handoff","description":"Return complete current scoped continuity and recorded closures. Global canon remains applicable. Budgets HOLD instead of silently truncating; scope and snapshot hashes grant no authority.",
  "inputSchema":{"type":"object","additionalProperties":False,"properties":{**_CONTEXT_SNAPSHOT_PROPERTIES,"format":{"type":"string","enum":["text","json"],"default":"text"}}}},
 {"name":"doctor","description":"Inspect scoped continuity health and lifecycle. Proof references are not verified proof; healthy is not permission to act.",
  "inputSchema":{"type":"object","additionalProperties":False,"properties":{**_CONTEXT_SCOPE_PROPERTIES}}},
 {"name":"set_frontier","description":"Set the trunk/cash/lab/parked focus (1 trunk + 1 cash + 1 lab discipline).",
  "inputSchema":{"type":"object","additionalProperties":False,"properties":{**_CONTEXT_SCOPE_PROPERTIES,"kind":{"type":"string","enum":["trunk","cash","lab","parked"]},"item":{"type":"string"}},"required":["kind","item"]}},
 {"name":"predict","description":"Retrieve current scoped rules and precedent with source references. The legacy name does not imply a calibrated behavioral prediction.",
  "inputSchema":{"type":"object","additionalProperties":False,"properties":{**_CONTEXT_SCOPE_PROPERTIES,"situation":{"type":"string"}},"required":["situation"]}},
 {"name":"alignment","description":"Review current scoped canon/rules for prohibitive wording. A missing keyword flag is not semantic compatibility or permission to act.",
  "inputSchema":{"type":"object","additionalProperties":False,"properties":{**_CONTEXT_SCOPE_PROPERTIES,"proposed_action":{"type":"string"}},"required":["proposed_action"]}},
 {"name":"preflight_action","description":"ADVISORY PREFLIGHT: returns a safety decision for a typed action. The MCP tool does not intercept other tools; the caller must enforce the result.",
  "inputSchema":{"type":"object","properties":{"tool":{"type":"string","default":"shell"},"command":{"type":"string"},"args":{"type":"array","items":{"type":"string"},"description":"Exact argument vector assessed by tool_schemas.max_args."},"paths":{"type":"array","items":{"type":"string"}},"cwd":{"type":"string","description":"Authoritative execution working directory; required for reliable relative-path decisions."}},"required":["command","args"]}},
 {"name":"preflight_exec","description":"Durably preflight one exact argv/cwd action through the ContinuityOS GateBroker.",
  "inputSchema":{"type":"object","additionalProperties":False,"properties":{
     "request_id":{"type":"string","minLength":1,"maxLength":256},
     "argv":{"type":"array","minItems":1,"maxItems":256,"items":{"type":"string","maxLength":32768}},
     "cwd":{"type":"string","minLength":1,"maxLength":32768},
     "paths":{"type":"array","maxItems":256,"items":{"type":"string","maxLength":32768}}},
   "required":["request_id","argv","cwd"]}},
 {"name":"execute_preflight","description":"Execute or return the cached terminal receipt for a previously brokered request ID.",
  "inputSchema":{"type":"object","additionalProperties":False,"properties":{
     "request_id":{"type":"string","minLength":1,"maxLength":256}},
   "required":["request_id"]}},
 {"name":"srd_status","description":"Local reminder cadence plus a fresh current scoped canon snapshot. The legacy interval is an uncalibrated reminder policy, not a measured safe context depth. On budget HOLD no partial reminder is emitted.",
  "inputSchema":{"type":"object","additionalProperties":False,"properties":{**_CONTEXT_SNAPSHOT_PROPERTIES}}},
 {"name":"memory_pointer","description":"Pass-by-reference: get a lightweight {namespace,key,version} pointer to a memory value instead of its content (A2A courier-tax fix). Dereference with recall/find.",
  "inputSchema":{"type":"object","properties":{"namespace":{"type":"string","default":"facts"},"key":{"type":"string"}},"required":["key"]}},
 {"name":"memory_write_checked","description":"Optimistic-concurrency write by key: succeeds only if current version equals expected_version, else returns a conflict. Prevents lost updates when multiple agents write the same key.",
  "inputSchema":{"type":"object","properties":{"text":{"type":"string"},"namespace":{"type":"string","default":"facts"},"key":{"type":"string"},"expected_version":{"type":"integer"}},"required":["text","key","expected_version"]}},
 {"name":"devils_advocate","description":"Challenge a claim or proposed action against your own memory + canon BEFORE acting: flags contradictions, superseded facts, missing evidence, canon conflicts, overconfidence, dishonest omissions, irreversible actions. Returns a verdict (STOP/RECONSIDER/PROCEED WITH CAUTION/PROCEED). Call before consequential moves.",
  "inputSchema":{"type":"object","properties":{"claim":{"type":"string"},"action":{"type":"boolean","default":False},"namespace":{"type":"string"}},"required":["claim"]}},
 {"name":"system_audit","description":"Full-system audit: memory inventory + invariants (append-only integrity, bi-temporal ordering, canon presence, dangling supersede pointers). devil=true runs the devil's advocate over every failing finding. EU-AI-Act Article-12 style record.",
  "inputSchema":{"type":"object","properties":{"devil":{"type":"boolean","default":False}}}}
]

OWNER_FORGET_TOOL = {"name":"forget","description":"OWNER-only deletion; disabled by default.",
    "inputSchema":{"type":"object","additionalProperties":False,"properties":{
        "id":{"type":"integer","minimum":1},
        "owner_capability":{"type":"string","minLength":32,"maxLength":256}},
        "required":["id","owner_capability"]}}

MAX_STDIN_LINE_CHARS = 131_072  # Local MCP stdio input cap; no unbounded readline.


class Server:
    def __init__(
        self, db=None, policy_path: str = "", db_source: str = "",
        *, governance_witness_path: str = "",
        r15_controller_profile_path: str = "",
        r15_controller_profile_sha256: str = "",
        r15_custody_path: str = "",
        allow_owner_forget: bool = False,
        owner_capability_sha256: str = "",
    ):
        # Match core cos: optional model construction requires explicit opt-in.
        # The existing CURRENT wrapper denies before this constructor is entered.
        embedder_mode = os.environ.get("CONTINUITYOS_EMBEDDER", "").strip().lower()
        if embedder_mode not in {
            "", "hash", "hashing", "offline", "local", "fast", "fastembed",
        }:
            raise ValueError("UNSUPPORTED_EMBEDDER_MODE")
        # Fail before resolve_memory_db or Memory(db) can touch SQLite.
        self._owner_forget_enabled = bool(allow_owner_forget)
        self._owner_forget_sha256 = owner_capability_sha256 if self._owner_forget_enabled else ""
        if (self._owner_forget_enabled and (
                not isinstance(self._owner_forget_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", self._owner_forget_sha256))):
            raise ValueError("OWNER_FORGET_CAPABILITY_CONFIGURATION_INVALID")
        resolved = resolve_memory_db(db)
        db = resolved["path"]
        self.db_path = db
        configured_missing = (
            resolved["configured"]
            and db != ":memory:"
            and not os.path.isfile(db)
        )
        embedder = None
        if embedder_mode in {"fast", "fastembed"}:
            try:
                from .embedders import FastEmbedEmbedder
                embedder = FastEmbedEmbedder()
            except Exception as exc:
                raise RuntimeError(
                    "FAST_EMBEDDER_UNAVAILABLE: explicit fast mode cannot fall back to hash"
                ) from exc
        # Memory errors must propagate, not reopen the same DB with another model.
        self.m = Memory(db, embedder=embedder)
        try:
            # Synthetic probe only: never send a stored record to the embedder here.
            try:
                probe = self.m.embed("continuityos:mcp-embedding-dimension-probe:v1")
            except Exception as exc:
                raise ValueError("EMBEDDER_PROBE_FAILED") from exc
            if not isinstance(probe, (list, tuple)) or not probe:
                raise ValueError("EMBEDDER_PROBE_INVALID")
            selected_dimension = len(probe)
            # All non-NULL vectors, across namespaces; no text or BLOB payload reads.
            cursor = self.m.store.con.execute(
                "SELECT MIN(length(vec)), MAX(length(vec)), "
                "COALESCE(SUM(CASE WHEN typeof(vec) <> 'blob' "
                "OR length(vec) = 0 OR length(vec) % 4 <> 0 "
                "THEN 1 ELSE 0 END), 0) FROM items WHERE vec IS NOT NULL"
            )
            try:
                minimum_bytes, maximum_bytes, malformed = cursor.fetchone()
            finally:
                cursor.close()
            if malformed:
                raise ValueError("EMBEDDER_VECTOR_DATA_INVALID: non-empty float32 BLOB required")
            if minimum_bytes is not None and (
                minimum_bytes != maximum_bytes or minimum_bytes != selected_dimension * 4
            ):
                stored = str(minimum_bytes // 4)
                if minimum_bytes != maximum_bytes:
                    stored += ".." + str(maximum_bytes // 4) + " (mixed)"
                raise ValueError(
                    f"EMBEDDER_DIMENSION_MISMATCH store={stored} selected={selected_dimension}; "
                    "set CONTINUITYOS_EMBEDDER to the original compatible backend; "
                    "restore or re-embed separately, never mix vector spaces"
                )
        except BaseException:
            # A failed startup must not leave its opened Memory connection alive.
            self.m.store.con.close()
            raise
        self.c = Continuity(memory=self.m)
        self.c._context_source = db_source or resolved["source"]
        self._governance_context_error = (
            f"configured memory database was missing at server startup: {db}; "
            "initialize it intentionally and restart before governance preflight"
            if configured_missing
            else ""
        )
        self.t = Twin(memory=self.m)
        self.ctl = ControlPlane(memory=self.m)
        runtime_policy = policy_path or _discover_policy(os.path.expanduser("~/.continuityos"))
        self.policy = _load_policy(runtime_policy)
        governance_root = os.path.expanduser("~/.continuityos")
        witness_path = (
            os.path.abspath(os.path.expanduser(governance_witness_path))
            if governance_witness_path
            else os.path.join(governance_root, "governance.witness.json")
        )
        self._governance_paths = {
            "registry_path": os.path.join(governance_root, "gate_broker.db"),
            "ledger_path": os.path.join(governance_root, "ledger.db"),
            "witness_path": witness_path,
        }
        self._monotonic_anchor = None
        self._r15_runtime_error = ""
        r15_values = {
            "controller_profile_path": r15_controller_profile_path,
            "controller_profile_sha256": r15_controller_profile_sha256,
            "custody_path": r15_custody_path,
        }
        supplied = {key for key, value in r15_values.items() if value}
        if supplied:
            missing = sorted(set(r15_values) - supplied)
            if missing:
                self._r15_runtime_error = (
                    "explicit R15 runtime configuration is incomplete; missing "
                    + ", ".join(missing)
                )
            elif not governance_witness_path:
                self._r15_runtime_error = (
                    "explicit R15 runtime requires an explicit external governance witness path"
                )
            else:
                try:
                    self._monotonic_anchor = _build_windows_r15_monotonic_anchor(
                        controller_profile_path=r15_controller_profile_path,
                        controller_profile_sha256=r15_controller_profile_sha256,
                        custody_path=r15_custody_path,
                    )
                except Exception as exc:
                    self._r15_runtime_error = (
                        "R15 runtime binding failed: "
                        f"{type(exc).__name__}: {exc}"
                    )
        self._broker = None
        self.turns = 0
        self.std = 10  # Legacy local reminder interval; not a calibrated safety threshold.

    def call(self, name, args):
        self.turns += 1
        if name == "remember":
            rid = self.m.remember(args["text"], namespace=args.get("namespace","notes"), tags=args.get("tags"))
            return f"stored #{rid} in [{args.get('namespace','notes')}]"
        if name == "recall":
            hits = self.m.recall(args["query"], k=int(args.get("k",5)), namespace=args.get("namespace"))
            return json.dumps([h.to_dict() for h in hits], ensure_ascii=False, indent=2)
        if name == "context":
            return self.m.context(args["query"], k=int(args.get("k",6))) or "(no relevant memory)"
        if name == "upsert":
            rid = self.m.upsert(args["text"], namespace=args.get("namespace","facts"), key=args["key"], tags=args.get("tags"))
            return f"upserted #{rid} in [{args.get('namespace','facts')}] key={args['key']}"
        if name == "find":
            hit = self.m.find(args.get("namespace","facts"), args["key"])
            return json.dumps(hit.to_dict(), ensure_ascii=False, indent=2) if hit else "null"
        if name == "forget":
            # Deny before any access to memory, including direct Server.call.
            if not getattr(self, "_owner_forget_enabled", False):
                raise PermissionError("OWNER_FORGET_DISABLED")
            if not isinstance(args, dict) or set(args) != {"id", "owner_capability"}:
                raise PermissionError("OWNER_FORGET_CAPABILITY_REQUIRED")
            cap = args.get("owner_capability")
            memory_id = args.get("id")
            if (not isinstance(cap, str) or not (32 <= len(cap) <= 256)
                    or type(memory_id) is not int or memory_id < 1):
                raise PermissionError("OWNER_FORGET_CAPABILITY_REQUIRED")
            actual = hashlib.sha256(cap.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(actual, getattr(self, "_owner_forget_sha256", "")):
                raise PermissionError("OWNER_FORGET_CAPABILITY_INVALID")
            self.m.forget(memory_id)
            return f"forgot #{memory_id}"
        if name == "list_namespaces":
            return json.dumps(self.m.namespaces(), ensure_ascii=False, indent=2)
        if name == "checkpoint":
            scope = self._continuity_options(args, other={"summary", "next_action", "proof", "lifecycle"})
            return f"checkpoint #{self.c.checkpoint(summary=args['summary'], next_action=args['next_action'], proof=args.get('proof',''), lifecycle=args.get('lifecycle', 'ACTIVE'), **scope)}"
        if name == "handoff":
            options = self._continuity_options(args, budgets=True, other={"format"})
            output_format = args.get("format", "text")
            if output_format not in ("text", "json"):
                raise ValueError("handoff format must be text or json")
            if output_format == "json":
                return json.dumps(self.c.handoff_snapshot(**options), ensure_ascii=False, indent=2)
            return self.c.handoff(**options)
        if name == "doctor":
            return json.dumps(self.c.doctor(**self._continuity_options(args)), ensure_ascii=False, indent=2)
        if name == "set_frontier":
            scope = self._continuity_options(args, other={"kind", "item"})
            return f"set {args['kind']} -> {args['item']} (#{self.c.set_frontier(args['kind'], args['item'], **scope)})"
        if name == "predict":
            scope = self._continuity_options(args, other={"situation"})
            return json.dumps(self.t.predict(args["situation"], **scope), ensure_ascii=False, indent=2)
        if name == "alignment":
            scope = self._continuity_options(args, other={"proposed_action"})
            return json.dumps(self.t.alignment(args["proposed_action"], **scope), ensure_ascii=False, indent=2)
        if name == "preflight_action":
            spec=_AS(tool=args.get("tool","shell"), command=args["command"], args=args.get("args"), paths=args.get("paths",[]), cwd=args.get("cwd",""), agent="mcp")
            governance_context_error = getattr(
                self, "_governance_context_error", None
            )
            if governance_context_error is None:
                spec.meta["context_error"] = (
                    "governance context initialization state unavailable"
                )
            elif governance_context_error:
                spec.meta["context_error"] = governance_context_error
            # Compatibility for bounded unit adapters that replace the legacy
            # ledger factory. A normally constructed product server always uses
            # its product-owned witness authority here.
            if _Ledger is not _PRODUCT_LEDGER:
                ledger_context = _Ledger(
                    os.path.expanduser("~/.continuityos/ledger.db")
                )
            else:
                ledger_context = self._gate_broker()._ledger()
            with ledger_context as ledger:
                decision = _preflight(spec, policy=self.policy, ledger=ledger, context=self.c)
            return json.dumps(decision, ensure_ascii=False, indent=2)
        if name == "preflight_exec":
            self._validate_broker_args(
                args, required={"request_id", "argv", "cwd"},
                optional={"paths"},
            )
            try:
                broker = self._gate_broker()
            except Exception as exc:
                result = self._broker_initialization_hold(args["request_id"], exc)
            else:
                result = broker.preflight_exec(
                    args["request_id"], args["argv"], args["cwd"],
                    args.get("paths"),
                )
            return json.dumps(result, ensure_ascii=False, indent=2)
        if name == "execute_preflight":
            # Independent runtime boundary: execution accepts no replacement
            # action, policy, authority paths, or approval material.
            self._validate_broker_args(
                args, required={"request_id"}, optional=set(),
            )
            try:
                broker = self._gate_broker()
            except Exception as exc:
                result = self._broker_initialization_hold(args["request_id"], exc)
            else:
                result = broker.execute_preflight(args["request_id"])
            return json.dumps(result, ensure_ascii=False, indent=2)
        if name == "srd_status":
            options = self._continuity_options(args, budgets=True)
            snapshot = self.c.handoff_snapshot(**options)
            due = self.turns >= self.std
            emitted = due and snapshot["complete"]
            canon = snapshot["payload"]["canon"] if emitted else []
            if emitted:
                self.turns = 0
            return json.dumps({"turns": self.turns, "safe_turn_depth": self.std, "reinject_due": due,
                               "reminder_interval_calls": self.std,
                               "interval_basis": "LEGACY_LOCAL_POLICY_NOT_CALIBRATED",
                               "reminder_emitted": emitted,
                               "canon_reminder": [row["text"] for row in canon],
                               "canon_refs": [row["memory_ref"] for row in canon],
                               "canon_returned_count": len(canon),
                               "canon_omitted_count": snapshot["counts"]["canon"] - len(canon),
                               "context_status": snapshot["status"], "context_complete": snapshot["complete"],
                               "scope": snapshot["scope"], "counts": snapshot["counts"],
                               "snapshot_sha256": snapshot["snapshot_sha256"], "observed_at": snapshot["observed_at"],
                               "excluded_candidate_counts": snapshot["excluded_candidate_counts"],
                               "coverage_kind": snapshot["coverage_kind"], "overflow": snapshot["overflow"],
                               "origin_verified": False, "authority_granted": False,
                               "note": "A complete snapshot is current local context, not permission. Re-inject only an emitted complete reminder; HOLD preserves the pending cadence."},
                              ensure_ascii=False, indent=2)
        if name == "memory_pointer":
            ptr = self.m.pointer(args.get("namespace", "facts"), args["key"])
            return json.dumps(ptr, ensure_ascii=False) if ptr else "null"
        if name == "memory_write_checked":
            from .memory import Conflict
            try:
                rid = self.m.write_checked(args["text"], namespace=args.get("namespace", "facts"),
                                           key=args["key"], expected_version=int(args["expected_version"]))
                return "wrote #%d to %s/%s" % (rid, args.get("namespace", "facts"), args["key"])
            except Conflict as e:
                return json.dumps({"error": "conflict", "detail": str(e)}, ensure_ascii=False)
        if name == "devils_advocate":
            from .advocate import DevilsAdvocate
            da = DevilsAdvocate(self.m, self.t)
            r = da.challenge(args["claim"], action=bool(args.get("action", False)), namespace=args.get("namespace"))
            da.record(r)
            return json.dumps({"verdict": r["verdict"], "flags": r["flags"], "open_questions": r["open_questions"]}, ensure_ascii=False, indent=2)
        if name == "system_audit":
            from .audit import SystemAudit
            return json.dumps(SystemAudit(self.m, self.c, self.t).run(devil=bool(args.get("devil", False))), ensure_ascii=False, indent=2)
        raise ValueError(f"unknown tool {name}")

    @staticmethod
    def _continuity_options(args, *, budgets=False, other=frozenset()):
        """Validate context selectors independently of advisory MCP JSON schemas.

        These selectors neither authenticate a subject nor constrain other tools.
        Broker and execution routes deliberately do not accept them as authority.
        """
        if not isinstance(args, dict):
            raise ValueError("continuity tool arguments must be an object")
        names = {"project", "subject"} | ({"max_items", "max_bytes"} if budgets else set())
        if set(args) - names - set(other):
            raise ValueError("unexpected continuity tool argument")
        options = {}
        for name in names & set(args):
            value = args[name]
            if name in ("project", "subject"):
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"{name} must be a non-empty string")
            elif type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
            options[name] = value
        return options

    @staticmethod
    def _broker_initialization_hold(request_id, exc):
        request_key = (
            _GateBroker._key(request_id) if isinstance(request_id, str) else None
        )
        return _GateBroker._held(
            request_id, request_key,
            [f"witness validation error: {type(exc).__name__}: {exc}"],
        )

    @staticmethod
    def _validate_broker_args(args, *, required, optional):
        if not isinstance(args, dict):
            raise ValueError("broker tool arguments must be an object")
        keys = set(args)
        missing = required - keys
        unexpected = keys - required - optional
        if missing:
            raise ValueError("missing arguments: " + ", ".join(sorted(missing)))
        if unexpected:
            raise ValueError("unexpected arguments: " + ", ".join(sorted(unexpected)))
        request_id = args.get("request_id")
        if not isinstance(request_id, str) or not (1 <= len(request_id) <= 256):
            raise ValueError("request_id must be a string of 1..256 characters")
        if "argv" in args:
            argv = args["argv"]
            if (
                not isinstance(argv, list) or not (1 <= len(argv) <= 256)
                or any(not isinstance(value, str) or len(value) > 32768 for value in argv)
            ):
                raise ValueError("argv must be a non-empty bounded array of strings")
        if "cwd" in args and (
            not isinstance(args["cwd"], str)
            or not (1 <= len(args["cwd"]) <= 32768)
        ):
            raise ValueError("cwd must be a bounded string")
        if "paths" in args:
            paths = args["paths"]
            if (
                not isinstance(paths, list) or len(paths) > 256
                or any(not isinstance(value, str) or len(value) > 32768 for value in paths)
            ):
                raise ValueError("paths must be a bounded array of strings")

    def _gate_broker(self):
        if getattr(self, "_broker", None) is None:
            paths = getattr(self, "_governance_paths", None)
            if paths is None:
                raise RuntimeError("product witness configuration unavailable")
            runtime_error = getattr(self, "_r15_runtime_error", "")
            if runtime_error:
                raise RuntimeError(runtime_error)
            self._broker = _GateBroker(
                **paths,
                db=self.db_path,
                policy_snapshot=self.policy,
                context_error=self._governance_context_error,
                monotonic_anchor=getattr(self, "_monotonic_anchor", None),
            )
        return self._broker

def _send(obj):
    sys.stdout.write(json.dumps(obj) + "\n"); sys.stdout.flush()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=None)
    ap.add_argument("--policy", default="", help="Path to one JSON policy, or YAML when PyYAML is installed")
    ap.add_argument(
        "--governance-witness", default="",
        help="Explicit external R14 witness path for product governance",
    )
    ap.add_argument(
        "--r15-controller-profile", default="",
        help="Explicit external R15 controller binding profile path",
    )
    ap.add_argument(
        "--r15-controller-profile-sha256", default="",
        help="Pinned lowercase SHA-256 of the R15 controller profile",
    )
    ap.add_argument(
        "--r15-custody", default="",
        help="Explicit DPAPI custody envelope path for the provisioned R15 NV index",
    )
    ap.add_argument("--enable-owner-forget", action="store_true", default=False,
                    help="Explicit OWNER opt-in; requires capability SHA-256 supplied in environment")
    a = ap.parse_args()
    owner_hash = os.environ.get("CONTINUITYOS_OWNER_FORGET_SHA256", "") if a.enable_owner_forget else ""
    srv = Server(
        a.db, a.policy,
        governance_witness_path=a.governance_witness,
        r15_controller_profile_path=a.r15_controller_profile,
        r15_controller_profile_sha256=a.r15_controller_profile_sha256,
        r15_custody_path=a.r15_custody,
        allow_owner_forget=a.enable_owner_forget,
        owner_capability_sha256=owner_hash,
    )
    # Read at most one bounded JSON-RPC frame and drain oversized lines.
    while True:
        line = sys.stdin.readline(MAX_STDIN_LINE_CHARS + 1)
        if not line:
            break
        if len(line) > MAX_STDIN_LINE_CHARS:
            if not line.endswith("\n"):
                while True:
                    remainder = sys.stdin.readline(MAX_STDIN_LINE_CHARS + 1)
                    if not remainder or remainder.endswith("\n"):
                        break
            continue
        line = line.strip()
        if not line: continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        mid = req.get("id"); method = req.get("method")
        if method == "initialize":
            _send({"jsonrpc":"2.0","id":mid,"result":{
                "protocolVersion":PROTOCOL,
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"continuityos","version":__version__}}})
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            _send({"jsonrpc":"2.0","id":mid,"result":{"tools":TOOLS + ([OWNER_FORGET_TOOL] if srv._owner_forget_enabled else [])}})
        elif method == "tools/call":
            p = req.get("params",{}) or {}
            try:
                out = srv.call(p.get("name"), p.get("arguments",{}) or {})
                _send({"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":str(out)}]}})
            except Exception as e:
                _send({"jsonrpc":"2.0","id":mid,"result":{"isError":True,"content":[{"type":"text","text":f"error: {e}"}]}})
        elif method == "ping":
            _send({"jsonrpc":"2.0","id":mid,"result":{}})
        else:
            if mid is not None:
                _send({"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":f"method not found: {method}"}})

if __name__ == "__main__":
    main()
