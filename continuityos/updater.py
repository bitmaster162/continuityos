"""Self-update for ContinuityOS clients: check PyPI (and git for editable installs) for a
newer version and upgrade in place. Stdlib-only, offline-safe, daily-cached. Never runs
pip/git on its own — only when the user runs `cos update --yes`.

    cos update            # report + how to upgrade
    cos update --check    # report only
    cos update --yes      # upgrade in place (pip -U, or git pull + pip -e for dev installs)
`cos boot` also prints a one-line notice when a newer version is available (cached daily).
"""
from __future__ import annotations
import json, os, re, subprocess, sys, time, urllib.request
from . import __version__

HOME = os.path.expanduser("~/.continuityos")
CACHE = os.path.join(HOME, "update_check.json")
PYPI_JSON = "https://pypi.org/pypi/continuityos/json"


def _ver(v):
    nums = re.findall(r"\d+", v or "")[:3]
    return tuple(int(x) for x in nums) if nums else (0,)


def _newer(candidate, current) -> bool:
    return bool(candidate) and _ver(candidate) > _ver(current)


def latest_pypi(timeout: float = 4.0):
    try:
        req = urllib.request.Request(PYPI_JSON, headers={"User-Agent": "continuityos-updater"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r).get("info", {}).get("version")
    except Exception:
        return None  # offline / PyPI down -> silent, never blocks


def install_info() -> dict:
    import continuityos
    root = os.path.dirname(os.path.dirname(os.path.abspath(continuityos.__file__)))
    return {"editable": os.path.isdir(os.path.join(root, ".git")), "root": root}


def check(force: bool = False, ttl: float = 86400.0) -> dict:
    """Return {current, latest, update_available, cached}. Uses a daily cache so `cos boot`
    can call it every run without hitting the network."""
    cur = __version__
    if not force:
        try:
            c = json.load(open(CACHE, encoding="utf-8"))
            if time.time() - c.get("ts", 0) < ttl:
                return {"current": cur, "latest": c.get("latest"),
                        "update_available": _newer(c.get("latest"), cur), "cached": True}
        except Exception:
            pass
    latest = latest_pypi()
    if latest:
        try:
            os.makedirs(HOME, exist_ok=True)
            json.dump({"ts": time.time(), "latest": latest}, open(CACHE, "w", encoding="utf-8"))
        except Exception:
            pass
    return {"current": cur, "latest": latest,
            "update_available": _newer(latest, cur), "cached": False}


def plan(info: dict, inf: dict):
    """The command(s) that would upgrade this install."""
    if inf["editable"]:
        return [["git", "-C", inf["root"], "pull", "--ff-only"],
                [sys.executable, "-m", "pip", "install", "-e", inf["root"]]]
    return [[sys.executable, "-m", "pip", "install", "-U", "continuityos"]]


def apply(yes: bool = False, run=None) -> dict:
    """Upgrade in place. `run` is an injectable subprocess runner (for tests)."""
    run = run or (lambda cmd, cwd=None: subprocess.run(cmd, cwd=cwd, capture_output=True, text=True))
    inf = install_info()
    info = check(force=True)
    if not inf["editable"] and not info["update_available"]:
        return {"updated": False, "reason": "already latest", **info}
    cmds = plan(info, inf)
    if not yes:
        return {"updated": False, "reason": "confirm required", "plan": [" ".join(c) for c in cmds], **info}
    steps = []
    for c in cmds:
        r = run(c, cwd=inf["root"])
        code = getattr(r, "returncode", 0)
        steps.append({"cmd": " ".join(c), "code": code})
        if code != 0:
            return {"updated": False, "reason": "command failed", "steps": steps, **info}
    return {"updated": True, "steps": steps, **info}
