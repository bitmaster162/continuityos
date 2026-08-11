"""Risk classifier: turn a raw shell command into risk signals.
Pattern-based (transparent, auditable). Not a model — every match is explainable."""
from __future__ import annotations
import fnmatch
import os
import re
import shlex
from typing import List, Dict

# (id, severity, regex, human reason)
RULES = [
    ("rm_rf",        "critical", r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-rf|-fr)\b", "recursive force delete"),
    ("rm_root",      "critical", r"\brm\b[^\n]*\s(/|/\*|~|\$HOME)(\s|$)", "delete of root/home"),
    ("ps_recursive_delete", "critical", r"\bremove-item\b[^\n]*((-recurse\b[^\n]*-force\b)|(-force\b[^\n]*-recurse\b))", "PowerShell recursive force delete"),
    ("cmd_recursive_delete", "critical", r"(^|[;&|]\s*)\b(del|erase|rmdir)\b[^\n]*(/s\b[^\n]*/q\b|/q\b[^\n]*/s\b)", "Windows recursive quiet delete"),
    ("generic_delete", "high", r"(^|[\s;&|/\"'\\(){}\x60])\b(rm|unlink|rmdir|rd|ri|del|erase|remove-item)\b", "filesystem delete"),
    ("windows_format", "critical", r"(^|[;&|]\s*)\bformat\s+[a-z]:", "format Windows volume"),
    ("dd_disk",      "critical", r"\bdd\b[^\n]*of=/dev/", "raw write to block device"),
    ("mkfs",         "critical", r"\bmkfs\b|\bmkswap\b", "format filesystem"),
    ("fork_bomb",    "critical", r":\(\)\s*\{\s*:\|:&\s*\}\s*;", "fork bomb"),
    ("git_force",    "high",     r"\bgit\b[^\n]*push[^\n]*(--force|-f)\b", "force push (history rewrite)"),
    ("git_reset_hard","high",    r"\bgit\b[^\n]*reset[^\n]*--hard\b", "hard reset (discards work)"),
    ("git_clean",    "high",     r"\bgit\b[^\n]*clean[^\n]*-[a-z]*f", "git clean -f (deletes untracked)"),
    ("curl_pipe_sh", "high",     r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh)", "pipe remote script to shell"),
    ("chmod_777",    "medium",   r"\bchmod\s+(-[a-zR]*\s+)?(0?777)\b", "world-writable permissions"),
    ("sudo",         "medium",   r"\bsudo\b", "privilege escalation"),
    ("secret_read",  "high",     r"(cat|less|head|tail|cp|scp)\b[^\n]*(\.env|id_rsa|\.pem|credentials|\.aws|secrets)", "reads secret/credential file"),
    # --- interpreter / indirect destructive (bypass-resistant) ---
    ("interp_delete", "critical", r"\b(python[0-9.]*|node|perl|ruby|deno|bun)\b[^\n]*(-c|-e|--eval|-)\b[^\n]*(rmtree|shutil\.rm|os\.remove|os\.unlink|rmdir|rmSync|unlinkSync|fs\.rm|FileUtils\.rm|unlink|removedirs)", "destructive delete via interpreter"),
    ("find_delete",   "critical", r"\bfind\b[^\n]*\s-delete\b", "find -delete (mass delete)"),
    ("find_exec_rm",  "critical", r"\bfind\b[^\n]*-exec\s+rm\b", "find -exec rm (mass delete)"),
    ("truncate_cmd",  "high",     r"\btruncate\b[^\n]*-s\s*0", "truncate file to zero"),
    ("shred",         "high",     r"\bshred\b", "secure-erase file"),
    ("redirect_wipe", "high",     r"(^|[\s;&|])\d*>(?!>)\s*[^\s>]*\.(db|sqlite3?|sql|env|key|pem|json|ya?ml|conf)\b", "redirect-truncate of sensitive/data file"),
    ("wipe_cmds",     "high",     r"\b(srm|wipe|sdelete(?:64)?)\b", "secure delete tool"),
    ("history_clear","medium",   r"\bhistory\s+-c\b|>\s*~/\.bash_history", "clears shell history (audit evasion)"),
    ("network_exfil","medium",   r"(curl|wget|nc)\b[^\n]*\s(-T|--upload-file|--data)\b", "uploads data to network"),
    # --- insecure-code signals (CWE classes, from agent-framework security research) ---
    # These catch an AGENT writing vulnerable code, not just dangerous shell. The framework
    # itself becomes the attack surface (Wagtail CWE-79, OpenStack Aodh CWE-306 case studies).
    ("cwe79_xss",      "high",     r"(innerHTML\s*=|dangerouslySetInnerHTML|document\.write\(|mark_safe\(|\bv-html\b)", "CWE-79: unescaped output → XSS"),
    ("cwe89_sqli",     "high",     r"(execute|cursor\.execute|query)\s*\(\s*[fF]?[\"'][^\"']*(SELECT|INSERT|UPDATE|DELETE)[^\"']*(\+|%|\{|f[\"'])", "CWE-89: string-built SQL → injection"),
    ("cwe78_oscmd",    "critical", r"(os\.system|subprocess\.(call|run|Popen)|exec\(|eval\()\s*\([^\n]*(\+|%|\bformat\b|f[\"'])", "CWE-78: OS command built from input → injection"),
    ("cwe798_secret",  "high",     r"(api[_-]?key|secret|password|token|aws_secret)\s*[:=]\s*[\"'][A-Za-z0-9/\+_\-]{12,}[\"']", "CWE-798: hardcoded credential in code"),
    ("cwe502_deser",   "high",     r"\b(pickle\.loads|marshal\.loads)\b", "CWE-502: unsafe deserialization"),
    ("shell_chain", "medium", r"&&|\|\||;", "shell chaining operator (&&, ||, ;)"),
    ("shell_pipe", "medium", r"\|(?!\|)", "shell pipe"),
    ("shell_redirect", "high", r">>|>|<", "shell redirect"),
    ("shell_substitution", "high", r"\$\(|`", "shell command substitution"),
]

def classify(command: str) -> List[Dict]:
    cmd = command or ""
    hits = []
    for rid, sev, pat, reason in RULES:
        if re.search(pat, cmd, re.IGNORECASE):
            hits.append({"id": rid, "severity": sev, "reason": reason})
    return hits

def normalize_path(path: str, cwd: str = "") -> str:
    """Resolve a target against the action cwd, including existing symlinks."""
    base = os.path.realpath(os.path.abspath(os.path.expanduser(cwd or os.getcwd())))
    value = os.path.expandvars(os.path.expanduser(path))
    if not os.path.isabs(value):
        value = os.path.join(base, value)
    return os.path.normcase(os.path.realpath(os.path.abspath(value)))


def path_within(path: str, root: str, cwd: str = "") -> bool:
    """True only when path is root itself or a descendant (never a prefix sibling)."""
    candidate = normalize_path(path, cwd)
    boundary = normalize_path(root, cwd)
    try:
        return os.path.commonpath((candidate, boundary)) == boundary
    except ValueError:  # different Windows drives, or otherwise incomparable paths
        return False


def extract_candidate_paths(command: str) -> List[str]:
    """Best-effort path extraction so callers cannot bypass policy by omitting paths.

    This is still a heuristic, not a shell parser. Typed adapters should supply paths;
    these candidates are a conservative second line for shell commands.
    """
    try:
        tokens = shlex.split(command or "", posix=os.name != "nt")
    except ValueError:
        tokens = re.split(r"\s+", command or "")
    out: List[str] = []
    for raw in tokens:
        token = raw.strip("\"'$(){}[],;" + chr(96))
        token = token.lstrip("<>")
        if not token or token.startswith("-") or "://" in token:
            continue
        looks_like_path = (
            token in ("/", "~")
            or token.startswith(("./", "../", "~/", ".\\", "..\\", "~\\"))
            or "/" in token
            or "\\" in token
            or bool(re.search(r"(^\.[\w.-]+$|\.[A-Za-z0-9]{1,12}$)", token))
        )
        if looks_like_path and token not in out:
            out.append(token)
    return out


def _slash(value: str) -> str:
    return os.path.normcase(value).replace("\\", "/")


def _glob_forms(pattern: str, cwd: str) -> List[str]:
    expanded = os.path.expandvars(os.path.expanduser(pattern))
    forms = [_slash(expanded)]
    if os.path.isabs(expanded):
        forms.append(_slash(os.path.abspath(os.path.normpath(expanded))))
    else:
        forms.append(_slash(os.path.abspath(os.path.join(cwd or os.getcwd(), expanded))))
    return list(dict.fromkeys(forms))


def match_protected(paths: List[str], protected_globs: List[str], cwd: str = "") -> List[str]:
    """Return targets matching protected globs after cwd/realpath normalization."""
    out = []
    for p in paths or []:
        absolute = normalize_path(p, cwd)
        candidates = {_slash(p), _slash(absolute), _slash(os.path.basename(absolute))}
        try:
            candidates.add(_slash(os.path.relpath(absolute, normalize_path(".", cwd))))
        except ValueError:
            pass
        for g in protected_globs or []:
            if any(fnmatch.fnmatch(candidate.rstrip("/"), form.rstrip("/"))
                   for candidate in candidates for form in _glob_forms(g, cwd)):
                out.append(p)
                break
    return out

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
