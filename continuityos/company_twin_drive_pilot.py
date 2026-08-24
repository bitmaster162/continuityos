from __future__ import annotations

import copy, hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .company_twin import replay, validate_dataset
from .company_twin_console import build_snapshot, synthetic_demo_bundle, validate_bundle
from .company_twin_ingest import ENVELOPE_SCHEMA_VERSION, InMemoryIngestStore, to_company_twin_evidence

PILOT_SCHEMA_VERSION = "company-twin-p2e-r2-selected-drive/1"
SOURCE_BOUNDARY = "SELECTED_DRIVE_ONE_FOLDER_ONE_FILE_REDACTED"
SOURCE_TYPE = "google_drive_selected_file"
TENANT_ID = "tenant_continuityos_lab"
CONNECTOR_ID = "drive-selected-p2e-r2"
SOURCE_SYSTEM = "google_drive_selected_redacted"
SOURCE_AUTHORITY_ID = "auth_drive_selected_p2e_r2"
SOURCE_SCOPE = "team:engineering"
SELECTED_SOURCE_LOCATOR_HASH = "844fac7468cebce89c71d1749bcf762676f2f14754a63acf4ae0605321825333"
SELECTED_FOLDER_TITLE = "why-continuityos-may-fail-an-adversarial-analysis"
SELECTED_FILE_NAME = "index.html"
SELECTED_MIME_TYPE = "text/html"
MAX_SELECTED_FILE_BYTES = 1_000_000

_ALLOWED = frozenset({"source_type","source_locator_hash","folder_title","file_name","mime_type","size_bytes","source_created_at","source_modified_at","published_date","title","language","description","claims","content_digest"})
_FORBIDDEN_KEYS = frozenset({"id","file_id","folder_id","drive_id","url","web_url","web_view_link","parents","parent_ids","owner","owners","owner_email","email","permissions","permission_ids","shared","sharing_user","oauth","authorization","credential","credentials","access_token","refresh_token","client_secret","cookie"})
_FORBIDDEN_FRAGMENTS = ("token","secret","password","authorization","cookie","private_key","access_key","credential","permission","owner_email")
_FORBIDDEN_HOSTS = ("drive.google.com", "docs.google.com")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_EMAIL = re.compile(r"(?i)(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Z]{2,}(?![\w.-])")
_TOKEN_PATTERNS = (re.compile(r"(?i)\bbearer\s+\S+"), re.compile(r"(?i)\bya29\.[A-Za-z0-9._-]+"), re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"))

class SelectedDrivePilotError(ValueError): pass

def _canon(v: Any) -> str: return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
def _digest(v: Any) -> str: return hashlib.sha256(_canon(v).encode()).hexdigest()
def _norm_key(v: object) -> str: return str(v).strip().lower().replace("-", "_").replace(" ", "_")
def _time(v: str) -> datetime:
    if not isinstance(v, str) or not v: raise SelectedDrivePilotError("timestamp required")
    try: dt = datetime.fromisoformat(v[:-1] + "+00:00" if v.endswith("Z") else v)
    except ValueError as exc: raise SelectedDrivePilotError("invalid timestamp") from exc
    if dt.tzinfo is None: raise SelectedDrivePilotError("timestamp requires timezone")
    return dt.astimezone(timezone.utc)

def _bad_key(v: Any) -> bool:
    if isinstance(v, Mapping):
        for k, x in v.items():
            n = _norm_key(k)
            if n in _FORBIDDEN_KEYS or any(f in n for f in _FORBIDDEN_FRAGMENTS) or _bad_key(x): return True
    elif isinstance(v, (list, tuple)): return any(_bad_key(x) for x in v)
    return False

def _bad_value(v: Any) -> bool:
    if isinstance(v, str):
        low = v.lower()
        return any(h in low for h in _FORBIDDEN_HOSTS) or bool(_EMAIL.search(v)) or any(p.search(v) for p in _TOKEN_PATTERNS)
    if isinstance(v, Mapping): return any(_bad_value(x) for x in v.values())
    if isinstance(v, (list, tuple)): return any(_bad_value(x) for x in v)
    return False

def _basis(a: Mapping[str, Any]) -> dict[str, Any]:
    keys = ("folder_title","file_name","mime_type","size_bytes","source_created_at","source_modified_at","published_date","title","language","description","claims")
    return {k: copy.deepcopy(a[k]) for k in keys}

def sanitize_selected_drive_artifact(a: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(a, Mapping): raise SelectedDrivePilotError("artifact must be object")
    if _bad_key(a) or _bad_value(a): raise SelectedDrivePilotError("private Drive/PII/credential material rejected")
    if a.get("source_type") != SOURCE_TYPE: raise SelectedDrivePilotError("unsupported source_type")
    h = a.get("source_locator_hash")
    if not isinstance(h, str) or not _HEX64.fullmatch(h) or h != SELECTED_SOURCE_LOCATOR_HASH: raise SelectedDrivePilotError("source outside one-file allowlist")
    if a.get("folder_title") != SELECTED_FOLDER_TITLE or a.get("file_name") != SELECTED_FILE_NAME or a.get("mime_type") != SELECTED_MIME_TYPE: raise SelectedDrivePilotError("selected source identity mismatch")
    size = a.get("size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_SELECTED_FILE_BYTES: raise SelectedDrivePilotError("invalid bounded size")
    created, modified = _time(str(a.get("source_created_at", ""))), _time(str(a.get("source_modified_at", "")))
    if modified > created: raise SelectedDrivePilotError("modified after observed snapshot")
    pd = a.get("published_date")
    if not isinstance(pd, str) or not _DATE.fullmatch(pd): raise SelectedDrivePilotError("published_date must be YYYY-MM-DD")
    try: datetime.strptime(pd, "%Y-%m-%d")
    except ValueError as exc: raise SelectedDrivePilotError("invalid published_date") from exc
    for k in ("title","language","description"):
        if not isinstance(a.get(k), str) or not a[k].strip(): raise SelectedDrivePilotError(f"{k} required")
    claims = a.get("claims")
    if not isinstance(claims, list) or not claims or len(claims) > 8 or any(not isinstance(x, str) or not x.strip() or len(x) > 400 for x in claims): raise SelectedDrivePilotError("invalid claims")
    safe = {k: copy.deepcopy(a[k]) for k in _ALLOWED if k in a and k != "content_digest"}
    expected = _digest(_basis(safe)); supplied = a.get("content_digest")
    if supplied is not None and (not isinstance(supplied, str) or not _HEX64.fullmatch(supplied) or supplied != expected): raise SelectedDrivePilotError("content_digest mismatch")
    safe["content_digest"] = expected
    return safe

def artifact_to_envelope(a: Mapping[str, Any]) -> dict[str, Any]:
    x = sanitize_selected_drive_artifact(a); h, d = x["source_locator_hash"], x["content_digest"]
    payload = {k: copy.deepcopy(x[k]) for k in ("title","folder_title","file_name","mime_type","size_bytes","source_created_at","source_modified_at","published_date","language","description","claims")}
    payload.update({"sanitized_content_digest": d, "source_locator_hash": h, "source_boundary": SOURCE_BOUNDARY})
    return {"schema_version":ENVELOPE_SCHEMA_VERSION,"tenant_id":TENANT_ID,"connector_id":CONNECTOR_ID,"source_system":SOURCE_SYSTEM,"source_object_type":"selected_drive_file","source_object_id":"drivefile_"+h[:32],"revision_id":"content_"+d,"observed_at":x["source_created_at"],"effective_at":x["source_modified_at"],"acl":{"visibility":"TEAM","scope":SOURCE_SCOPE},"payload":payload,"raw_ref":"drive-sha256:"+h,"cursor":"drive-selected:"+d[:32],"actor":{"actor_id":"service:drive-selected-p2e-r2","actor_kind":"SERVICE","role":"SOURCE_SERVICE","authority_class":"READ_ONLY"},"deleted":False}

def ingest_selected_drive_artifact(a: Mapping[str, Any], *, store: InMemoryIngestStore | None = None):
    env = artifact_to_envelope(a); target = store or InMemoryIngestStore()
    result = target.apply_batch([env], tenant_id=TENANT_ID, connector_id=CONNECTOR_ID, cursor_after=env["cursor"])
    return target, result

def _published(d: str) -> str: return d + "T00:00:00Z"
def project_selected_drive_to_company_twin(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    active = [r for r in records if not r.get("deleted")]
    if len(active) != 1: raise SelectedDrivePilotError("exactly one active selected Drive record required")
    r = active[0]
    if r.get("source_system") != SOURCE_SYSTEM or r.get("source_object_type") != "selected_drive_file": raise SelectedDrivePilotError("record outside P2E-R2 boundary")
    ev = to_company_twin_evidence(r, source_authority_id=SOURCE_AUTHORITY_ID); p = r["payload"]; eff, obs, pub = str(r["effective_at"]), str(r["observed_at"]), _published(str(p["published_date"]))
    entities=[{"id":"ent_continuityos_lab","type":"organization","name":"ContinuityOS Lab","created_at":pub,"scope":SOURCE_SCOPE,"truth_class":"FACT"},{"id":"ent_drive_adversarial_analysis","type":"document","name":str(p["title"]),"created_at":eff,"scope":SOURCE_SCOPE,"truth_class":"FACT"}]
    rel=[{"id":"rel_drive_analysis_part_of_lab","from_entity_id":"ent_drive_adversarial_analysis","to_entity_id":"ent_continuityos_lab","relation":"PART_OF","effective_from":eff,"scope":SOURCE_SCOPE,"truth_class":"FACT"}]
    events=[{"id":"evt_drive_analysis_publication_date","title":"Selected source states publication date for ContinuityOS adversarial analysis","occurred_at":pub,"scope":SOURCE_SCOPE,"truth_class":"FACT","entity_ids":["ent_drive_adversarial_analysis"],"evidence_ids":[ev["id"]]},{"id":"evt_drive_analysis_selected_snapshot","title":"Selected Drive artifact recorded in bounded P2E-R2 snapshot","occurred_at":eff,"scope":SOURCE_SCOPE,"truth_class":"FACT","entity_ids":["ent_drive_adversarial_analysis"],"evidence_ids":[ev["id"]]}]
    observations=[{"id":"proc_drive_analysis_content_scope","title":"Selected document evaluates ContinuityOS market viability, competitive overlap, adoption friction and failure modes","observed_at":eff,"scope":SOURCE_SCOPE,"truth_class":"FACT","evidence_ids":[ev["id"]]}]
    principals=[{"id":"principal_director","name":"ContinuityOS Director","role":"DIRECTOR","scopes":["company","team:engineering","team:operations","restricted:finance"]},{"id":"principal_eng_worker","name":"Engineering Worker","role":"WORKER","scopes":["company","team:engineering"]},{"id":"principal_ops_worker","name":"Operations Worker","role":"WORKER","scopes":["company","team:operations"]},{"id":"principal_research_robot","name":"Research Robot","role":"AGENT","scopes":["company","team:engineering"]}]
    data={"schema_version":"company-twin-p2a/1","organization":{"id":"org_continuityos_lab","name":"ContinuityOS Lab","industry":"AI infrastructure","synthetic":False,"source_boundary":SOURCE_BOUNDARY},"period":{"start":pub,"end":obs},"source_authorities":[{"id":SOURCE_AUTHORITY_ID,"name":"Selected redacted Google Drive evidence","authority":"SOURCE","source_locator_hash":str(p["source_locator_hash"]),"source_boundary":SOURCE_BOUNDARY}],"principals":principals,"entities":sorted(entities,key=lambda x:x["id"]),"relationships":rel,"evidence":[ev],"events":sorted(events,key=lambda x:x["id"]),"decisions":[],"outcomes":[],"process_observations":observations,"inferences":[]}
    validate_dataset(data); return data

def replay_selected_drive(records: Sequence[Mapping[str, Any]], *, principal_id: str, as_of: str) -> dict[str, Any]: return replay(project_selected_drive_to_company_twin(records), principal_id=principal_id, as_of=as_of)
def build_pilot_console_bundle(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    base=synthetic_demo_bundle(); bundle={"schema_version":base["schema_version"],"memory":project_selected_drive_to_company_twin(records),"policy":copy.deepcopy(base["policy"]),"runtime":copy.deepcopy(base["runtime"]),"proposals":[]}; validate_bundle(bundle); return bundle
def build_pilot_console_snapshot(records: Sequence[Mapping[str, Any]], *, principal_id: str, as_of: str) -> dict[str, Any]: return build_snapshot(build_pilot_console_bundle(records), principal_id=principal_id, as_of=as_of)

def _real() -> dict[str, Any]:
    a={"source_type":SOURCE_TYPE,"source_locator_hash":SELECTED_SOURCE_LOCATOR_HASH,"folder_title":SELECTED_FOLDER_TITLE,"file_name":SELECTED_FILE_NAME,"mime_type":SELECTED_MIME_TYPE,"size_bytes":32773,"source_created_at":"2026-08-22T00:31:03.858Z","source_modified_at":"2026-07-06T17:43:50.717Z","published_date":"2026-07-04","title":"Why ContinuityOS May Fail: An Adversarial Analysis","language":"ru","description":"An adversarial strategic analysis of ContinuityOS evaluating market viability, competitive overlap, adoption friction, integration barriers, and failure modes.","claims":["An adversarial strategic analysis of ContinuityOS.","Evaluates market viability and competitive overlap with enterprise agent governance tools.","Outlines adoption friction, developer integration barriers, and failure modes."]}; a["content_digest"]=_digest(_basis(a)); return a
REAL_SELECTED_DRIVE_ARTIFACT = _real()
def source_fixture_document() -> dict[str, Any]: return {"schema_version":PILOT_SCHEMA_VERSION,"source_boundary":SOURCE_BOUNDARY,"artifact_count":1,"artifact":copy.deepcopy(REAL_SELECTED_DRIVE_ARTIFACT)}
def load_source_fixture(path: str | Path) -> dict[str, Any]:
    data=json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping) or data.get("schema_version")!=PILOT_SCHEMA_VERSION or data.get("source_boundary")!=SOURCE_BOUNDARY or data.get("artifact_count")!=1: raise SelectedDrivePilotError("source fixture boundary mismatch")
    out={"schema_version":PILOT_SCHEMA_VERSION,"source_boundary":SOURCE_BOUNDARY,"artifact_count":1,"artifact":sanitize_selected_drive_artifact(data.get("artifact",{}))}
    if out != source_fixture_document(): raise SelectedDrivePilotError("source fixture differs from pinned sanitized artifact")
    return out
