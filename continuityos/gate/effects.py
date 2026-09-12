"""Deterministic effect classification for governance preflight.

This layer classifies the exact typed action before execution policy is applied.
It is deliberately separate from shell-risk regexes: an ordinary remote mutation
such as ``git push`` or ``terraform apply`` is an effect even when it contains no
obviously dangerous shell syntax.
"""
from __future__ import annotations

from typing import Any
import os
import re
import shlex

from .spec import ActionSpec

EFFECT_SCHEMA = "continuityos.gate.effect-classification/v1"
EFFECT_CLASSES = (
    "LOCAL_READ",
    "TYPED_LOCAL_MUTATION",
    "LOCAL_MUTATION",
    "DYNAMIC_CODE",
    "NETWORK_READ",
    "NETWORK_WRITE",
    "PACKAGE_MUTATION",
    "GIT_REMOTE_MUTATION",
    "CLOUD_CLI",
    "CLOUD_MUTATION",
    "INFRA_MUTATION",
    "REMOTE_SHELL",
    "REMOTE_ARTIFACT_MUTATION",
    "UNKNOWN_EXEC",
)

_REMOTE_OR_IRREVERSIBLE = {
    "NETWORK_WRITE",
    "PACKAGE_MUTATION",
    "GIT_REMOTE_MUTATION",
    "CLOUD_CLI",
    "CLOUD_MUTATION",
    "INFRA_MUTATION",
    "REMOTE_SHELL",
    "REMOTE_ARTIFACT_MUTATION",
}


def _basename(value: str) -> str:
    return str(value or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def _lower_args(spec: ActionSpec) -> list[str]:
    values = list(spec.args or [])
    if not values and spec.tool == "shell" and spec.command.strip():
        try:
            values = shlex.split(spec.command, posix=os.name != "nt")
        except ValueError:
            values = []
    return [str(value).lower() for value in values]


def _first_subcommand(args: list[str]) -> str:
    return args[1] if len(args) > 1 else ""


def _add(classes: set[str], basis: list[str], effect: str, why: str) -> None:
    classes.add(effect)
    if why not in basis:
        basis.append(why)


def _classify_dynamic_carrier(exe: str, args: list[str], classes: set[str], basis: list[str]) -> None:
    tail = args[1:]
    if exe.startswith("python") or exe in {"py", "py.exe"}:
        if any(token in tail for token in {"--version", "-v"}) and len(tail) == 1:
            _add(classes, basis, "LOCAL_READ", "Python version query is read-only")
        elif "-c" in tail:
            _add(classes, basis, "DYNAMIC_CODE", "python -c executes caller-supplied code")
        elif "-m" in tail or not tail or any(not token.startswith("-") for token in tail):
            _add(classes, basis, "DYNAMIC_CODE", "Python module/script execution can perform arbitrary effects")
    elif exe in {"node", "node.exe", "deno", "deno.exe", "bun", "bun.exe", "perl", "perl.exe", "ruby", "ruby.exe"}:
        if tail == ["--version"] or tail == ["-v"]:
            _add(classes, basis, "LOCAL_READ", f"{exe} version query is read-only")
        elif any(flag in tail for flag in {"-e", "--eval"}):
            _add(classes, basis, "DYNAMIC_CODE", f"{exe} eval flag executes caller-supplied code")
        elif tail:
            _add(classes, basis, "DYNAMIC_CODE", f"{exe} script/module execution can perform arbitrary effects")
    elif exe in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        if any(flag in tail for flag in {"-command", "-c", "-encodedcommand", "-enc"}):
            _add(classes, basis, "DYNAMIC_CODE", "PowerShell command/eval carrier")
    elif exe in {"cmd", "cmd.exe"} and "/c" in tail:
        _add(classes, basis, "DYNAMIC_CODE", "cmd /c executes caller-supplied command text")
    elif exe in {"sh", "bash", "zsh", "dash", "sh.exe", "bash.exe", "zsh.exe"} and "-c" in tail:
        _add(classes, basis, "DYNAMIC_CODE", f"{exe} -c executes caller-supplied command text")


def _classify_git(exe: str, args: list[str], classes: set[str], basis: list[str]) -> None:
    if exe not in {"git", "git.exe"}:
        return
    sub = _first_subcommand(args)
    if sub == "push":
        _add(classes, basis, "GIT_REMOTE_MUTATION", "git push mutates a remote repository")
    elif sub in {"status", "diff", "log", "show", "rev-parse", "ls-files", "ls-tree", "cat-file"}:
        _add(classes, basis, "LOCAL_READ", f"git {sub} reads local repository state")
    elif sub == "branch" and (len(args) == 2 or any(token in args[2:] for token in {"--list", "--show-current"})):
        _add(classes, basis, "LOCAL_READ", "git branch query reads local repository state")
    elif sub == "fetch":
        _add(classes, basis, "NETWORK_READ", "git fetch contacts a remote repository")
        _add(classes, basis, "LOCAL_MUTATION", "git fetch mutates local remote-tracking refs")
    elif sub == "ls-remote":
        _add(classes, basis, "NETWORK_READ", "git ls-remote reads a remote repository")
    elif sub == "remote":
        nested = args[2] if len(args) > 2 else ""
        if nested in {"add", "remove", "rm", "rename", "set-url", "set-head", "set-branches", "prune", "update"}:
            _add(classes, basis, "LOCAL_MUTATION", f"git remote {nested} mutates repository configuration/state")
        else:
            _add(classes, basis, "LOCAL_READ", "git remote query reads repository configuration")
    elif sub in {"pull", "clone"}:
        _add(classes, basis, "NETWORK_READ", f"git {sub} contacts a remote repository")
        _add(classes, basis, "LOCAL_MUTATION", f"git {sub} mutates local repository state")


def _classify_gh(exe: str, args: list[str], classes: set[str], basis: list[str]) -> None:
    if exe not in {"gh", "gh.exe"}:
        return
    sub = _first_subcommand(args)
    if sub == "api":
        method = "post" if any(token in args[2:] for token in {"-f", "--raw-field", "--field", "--input"}) else "get"
        for index, token in enumerate(args[2:]):
            if token in {"-x", "--method"} and index + 3 < len(args):
                method = args[index + 3]
        if method in {"get", "head"}:
            _add(classes, basis, "NETWORK_READ", f"gh api {method.upper()} contacts GitHub")
        else:
            _add(classes, basis, "GIT_REMOTE_MUTATION", f"gh api {method.upper()} mutates GitHub state")
        return
    read_only = {
        "status", "browse", "search", "codespace", "help", "version",
    }
    if sub in read_only:
        _add(classes, basis, "NETWORK_READ", f"gh {sub} may read GitHub state")
        return
    nested_read = {
        "pr": {"view", "list", "status", "checks", "diff"},
        "issue": {"view", "list", "status"},
        "run": {"view", "list", "watch"},
        "workflow": {"view", "list"},
        "repo": {"view", "list"},
        "release": {"view", "list", "download"},
    }
    nested = args[2] if len(args) > 2 else ""
    if sub in nested_read and nested in nested_read[sub]:
        _add(classes, basis, "NETWORK_READ", f"gh {sub} {nested} reads GitHub state")
        if sub == "release" and nested == "download":
            _add(classes, basis, "LOCAL_MUTATION", "gh release download writes local files")
    else:
        _add(classes, basis, "GIT_REMOTE_MUTATION", f"gh {sub or '<command>'} is not a proven read-only GitHub action")


def _classify_packages(exe: str, args: list[str], classes: set[str], basis: list[str]) -> None:
    package_verbs = {"install", "uninstall", "remove", "add", "update", "upgrade", "publish"}
    if exe.startswith("python") or exe in {"py", "py.exe"}:
        if len(args) >= 4 and args[1:3] == ["-m", "pip"] and args[3] in package_verbs:
            _add(classes, basis, "PACKAGE_MUTATION", f"pip {args[3]} mutates package/environment state")
    elif exe in {"pip", "pip.exe", "pip3", "pip3.exe"}:
        if _first_subcommand(args) in package_verbs:
            _add(classes, basis, "PACKAGE_MUTATION", f"pip {_first_subcommand(args)} mutates package/environment state")
    elif exe in {"npm", "npm.cmd", "pnpm", "pnpm.cmd", "yarn", "yarn.cmd", "bun", "bun.exe"}:
        sub = _first_subcommand(args)
        if sub in package_verbs or any(token in package_verbs for token in args[1:3]):
            _add(classes, basis, "PACKAGE_MUTATION", f"{exe} package operation mutates dependency state")
        elif sub in {"test", "run", "exec", "dlx"}:
            _add(classes, basis, "DYNAMIC_CODE", f"{exe} {sub} executes project/package code")
    elif exe in {"apt", "apt-get", "dnf", "yum", "brew", "choco", "choco.exe", "winget", "winget.exe"}:
        if _first_subcommand(args) in package_verbs:
            _add(classes, basis, "PACKAGE_MUTATION", f"{exe} {_first_subcommand(args)} mutates installed software")


def _classify_network(exe: str, args: list[str], classes: set[str], basis: list[str], raw_args: list[str]) -> None:
    if exe in {"curl", "curl.exe"}:
        write_flags = {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--form", "-t", "--upload-file"}
        method = "get"
        for index, token in enumerate(args[1:]):
            if token in {"-x", "--request"} and index + 2 < len(args):
                method = args[index + 2]
        if (
            method in {"post", "put", "patch", "delete"}
            or any(token in write_flags for token in args[1:])
            or "-F" in raw_args[1:]
        ):
            _add(classes, basis, "NETWORK_WRITE", "curl request can mutate remote state")
        else:
            _add(classes, basis, "NETWORK_READ", "curl contacts a network endpoint")
        if any(token in {"-o", "--output", "--remote-name"} for token in args[1:]):
            _add(classes, basis, "LOCAL_MUTATION", "curl output option writes local filesystem state")
    elif exe in {"wget", "wget.exe"}:
        write_flags = {"--post-data", "--post-file", "--body-data", "--body-file"}
        method = "get"
        for index, token in enumerate(args[1:]):
            if token == "--method" and index + 2 < len(args):
                method = args[index + 2]
        if method not in {"get", "head"} or any(token in write_flags for token in args[1:]):
            _add(classes, basis, "NETWORK_WRITE", "wget request can mutate remote state")
        else:
            _add(classes, basis, "NETWORK_READ", "wget contacts a network endpoint")
        if "-o" not in args[1:] or ("-o" in args[1:] and args[args.index("-o") + 1] != "-"):
            _add(classes, basis, "LOCAL_MUTATION", "wget writes downloaded content locally")


def _classify_cloud(exe: str, args: list[str], classes: set[str], basis: list[str]) -> None:
    if exe not in {"aws", "aws.exe", "az", "az.exe", "gcloud", "gcloud.exe"}:
        return
    _add(classes, basis, "CLOUD_CLI", f"{exe} crosses a cloud-provider authority boundary")
    mutation_tokens = {
        "apply", "create", "delete", "destroy", "deploy", "import", "modify",
        "patch", "put", "remove", "restart", "run-instances", "set", "start",
        "stop", "terminate", "undeploy", "update", "upload", "write",
    }
    if any(token in mutation_tokens for token in args[1:]):
        _add(classes, basis, "CLOUD_MUTATION", f"{exe} command contains a cloud mutation verb")
    if exe in {"aws", "aws.exe"} and len(args) >= 4 and args[1:3] == ["s3", "cp"]:
        if any(token.startswith("s3://") for token in args[3:]):
            destination = args[-1]
            if destination.startswith("s3://"):
                _add(classes, basis, "CLOUD_MUTATION", "aws s3 cp writes to remote object storage")


def _classify_infra(exe: str, args: list[str], classes: set[str], basis: list[str]) -> None:
    if exe in {"terraform", "terraform.exe", "tofu", "tofu.exe"}:
        sub = _first_subcommand(args)
        if sub in {"apply", "destroy", "import", "taint", "untaint"}:
            _add(classes, basis, "INFRA_MUTATION", f"{exe} {sub} can change managed infrastructure")
        elif sub in {"init", "fmt"}:
            _add(classes, basis, "LOCAL_MUTATION", f"{exe} {sub} mutates local infrastructure workspace state")
            if sub == "init":
                _add(classes, basis, "NETWORK_READ", f"{exe} init may download providers/modules")
        elif sub == "workspace" and len(args) > 2 and args[2] not in {"list", "show"}:
            _add(classes, basis, "INFRA_MUTATION", f"{exe} workspace {args[2]} changes infrastructure workspace state")
        elif sub == "state" and len(args) > 2 and args[2] in {"mv", "rm", "push"}:
            _add(classes, basis, "INFRA_MUTATION", f"{exe} state {args[2]} mutates infrastructure state")
        else:
            _add(classes, basis, "NETWORK_READ", f"{exe} may read provider/infrastructure state")
    elif exe in {"kubectl", "kubectl.exe"}:
        sub = _first_subcommand(args)
        if sub in {"get", "describe", "logs", "version", "explain", "diff", "api-resources", "api-versions"}:
            _add(classes, basis, "NETWORK_READ", f"kubectl {sub} reads cluster state")
        else:
            _add(classes, basis, "INFRA_MUTATION", f"kubectl {sub or '<command>'} is not a proven read-only cluster action")
    elif exe in {"helm", "helm.exe"}:
        sub = _first_subcommand(args)
        if sub in {"list", "status", "get", "history", "show", "template", "lint", "version"}:
            _add(classes, basis, "NETWORK_READ", f"helm {sub} is read-only or render-only")
        else:
            _add(classes, basis, "INFRA_MUTATION", f"helm {sub or '<command>'} is not a proven read-only release action")


def _classify_remote_tools(exe: str, args: list[str], classes: set[str], basis: list[str]) -> None:
    if exe in {"ssh", "ssh.exe", "mosh", "mosh.exe"}:
        _add(classes, basis, "REMOTE_SHELL", f"{exe} can execute against a remote host")
    elif exe in {"scp", "scp.exe", "sftp", "sftp.exe", "rsync", "rsync.exe"}:
        _add(classes, basis, "REMOTE_ARTIFACT_MUTATION", f"{exe} transfers data across a remote boundary")
    elif exe in {"docker", "docker.exe", "podman", "podman.exe"}:
        sub = _first_subcommand(args)
        if sub == "push":
            _add(classes, basis, "REMOTE_ARTIFACT_MUTATION", f"{exe} push mutates a remote image registry")
        elif sub in {"pull", "build", "run", "compose"}:
            _add(classes, basis, "LOCAL_MUTATION", f"{exe} {sub} mutates local container/runtime state")
            if sub == "pull":
                _add(classes, basis, "NETWORK_READ", f"{exe} pull reads a remote registry")
            else:
                _add(classes, basis, "DYNAMIC_CODE", f"{exe} {sub} can execute workload/build instructions")


def classify_effects(spec: ActionSpec) -> dict[str, Any]:
    """Return a server-derived effect classification for one exact action."""
    classes: set[str] = set()
    basis: list[str] = []
    args = _lower_args(spec)
    exe = _basename(args[0]) if args else ""
    if spec.tool == "shell" and spec.command.strip():
        if re.search(r"(?:&&|\|\||;|`|\$\(|>|<)", spec.command):
            _add(classes, basis, "DYNAMIC_CODE", "compound shell syntax requires explicit review")
        if not args:
            _add(classes, basis, "DYNAMIC_CODE", "shell command could not be parsed into a stable argv")

    if spec.tool == "file.read":
        _add(classes, basis, "LOCAL_READ", "typed file.read action")
    elif spec.tool in {"file.write", "file.delete"}:
        _add(classes, basis, "TYPED_LOCAL_MUTATION", f"typed {spec.tool} action")
    elif spec.tool == "http":
        method = str((spec.meta or {}).get("method", "GET")).upper()
        if method in {"GET", "HEAD", "OPTIONS"}:
            _add(classes, basis, "NETWORK_READ", f"typed HTTP {method}")
        else:
            _add(classes, basis, "NETWORK_WRITE", f"typed HTTP {method}")

    _classify_dynamic_carrier(exe, args, classes, basis)
    _classify_git(exe, args, classes, basis)
    _classify_gh(exe, args, classes, basis)
    _classify_packages(exe, args, classes, basis)
    _classify_network(exe, args, classes, basis, [str(value) for value in (spec.args or [])])
    _classify_cloud(exe, args, classes, basis)
    _classify_infra(exe, args, classes, basis)
    _classify_remote_tools(exe, args, classes, basis)

    safe_local_reads = {
        "ls", "dir", "pwd", "whoami", "hostname", "echo", "printf",
        "cat", "type", "head", "tail", "wc", "where", "which", "stat",
    }
    if not classes and exe in safe_local_reads:
        _add(classes, basis, "LOCAL_READ", f"{exe} is an explicit local read/query command")
    if not classes and exe in {"pytest", "pytest.exe"}:
        _add(classes, basis, "DYNAMIC_CODE", "pytest executes project test code and plugins")
    if not classes and spec.tool in {"exec", "shell"} and exe:
        _add(classes, basis, "UNKNOWN_EXEC", f"unclassified executable {exe!r} requires explicit confirmation")
    if not classes:
        _add(classes, basis, "LOCAL_READ", "no typed executable effect was supplied")
    ordered = [effect for effect in EFFECT_CLASSES if effect in classes]
    return {
        "schema": EFFECT_SCHEMA,
        "classes": ordered,
        "remote_or_irreversible": bool(set(ordered) & _REMOTE_OR_IRREVERSIBLE),
        "basis": basis,
    }
