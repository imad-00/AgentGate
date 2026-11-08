# policy.py
import os
import re
import shlex
import time
import yaml
from pathlib import Path
from urllib.parse import urlparse

from tools import resolve_in_sandbox, SANDBOX
from normalize import normalize_for_policy

POLICY = yaml.safe_load(Path("policy.yaml").read_text())
_call_timestamps = []
# paths written by a curl/wget command in this run — see _taint_fetched_output
# and _tainted_execution. A single download call (e.g. "curl -o x.sh url",
# with no bash/sh keyword in that same call) is legitimate — downloading to
# inspect before running is the recommended safe practice. But nothing else
# then stopped a LATER, separate call like "bash x.sh" from executing it,
# since that call has no curl/wget and so never tripped _is_fetch_and_execute.
# This tracks such outputs across calls so that later execution is still caught.
_tainted_paths = set()
_OUTPUT_TARGET_PATTERN = re.compile(r'(?:-o|-O|--output(?:-document)?)[\s=]+(\S+)')
_REDIRECT_TARGET_PATTERN = re.compile(r'>{1,2}\s*(\S+)')

ENFORCE = True  # flip to False later for the gate-off demo comparison
NORMALIZE_UNICODE = True  # flip False to reproduce the pre-fix vulnerability
URL_FULL_PATTERN = re.compile(r'https?://[^\s\'"]+')


def _is_fetch_and_execute(text: str) -> bool:
    """True if text contains both a remote-fetch command and a shell/interpreter
    execution, regardless of how they're joined (piped, saved-then-run, separate
    lines, ...). Catches rephrasings of `curl ... | bash` that dodge the literal
    forbidden_shell_patterns, e.g. `curl ... > f` followed by `bash f`."""
    has_fetch = any(re.search(p, text) for p in POLICY.get("fetch_patterns", []))
    has_exec = any(re.search(p, text) for p in POLICY.get("exec_patterns", []))
    return has_fetch and has_exec


def _hostname_allowed(hostname: str | None, allowed_domains: list[str]) -> bool:
    """Exact or subdomain match on the real hostname — never substring
    containment on the raw URL, which `evilexample.com.attacker.io`
    or `https://evil.com/?x=example.com` would trivially pass."""
    if not hostname:
        return False
    hostname = hostname.lower()
    return any(
        hostname == allowed.lower() or hostname.endswith("." + allowed.lower())
        for allowed in allowed_domains
    )


def _tokenize_shell(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return re.findall(r'\S+', command)


def _looks_like_fs_path(token: str) -> bool:
    if not token or token.startswith(("http://", "https://")):
        return False
    return (
        "/" in token
        or token.startswith("~")
        or token.startswith("$")
        or token == ".."
        or token.startswith("../")
    )


def _resolve_fs_token(token: str):
    """Resolve a token the same way the shell will: relative to SANDBOX,
    since run_shell's subprocess now runs with cwd=SANDBOX (tools.py)."""
    expanded = os.path.expandvars(os.path.expanduser(token))
    try:
        p = Path(expanded)
        if not p.is_absolute():
            p = SANDBOX / p
        return p.resolve()
    except (OSError, ValueError):
        return None


def _shell_path_escape(command: str) -> str | None:
    """Generalizes the sandbox-boundary check used for read_file/write_file
    to run_shell too: ANY filesystem path argument (absolute, ~, $HOME, or
    ../ traversal) that resolves outside the sandbox is flagged — matching
    policy.yaml's allowed_paths (sandbox/ is the only authorized location),
    not a denylist of specific sensitive paths like .ssh or /etc/shadow."""
    for token in _tokenize_shell(command):
        candidates = [token]
        if token.startswith("-") and "=" in token:
            candidates = [token.split("=", 1)[1]]
        elif token.startswith("-"):
            continue
        for candidate in candidates:
            if not _looks_like_fs_path(candidate):
                continue
            resolved = _resolve_fs_token(candidate)
            if resolved is None:
                continue
            if resolved == SANDBOX or SANDBOX in resolved.parents:
                continue
            return candidate
    return None


def _taint_fetched_output(command: str) -> None:
    """If this command fetches (curl/wget) and names an output file (-o/-O/
    --output or a redirect target), remember that resolved path so a LATER,
    separate call can't execute it unvetted."""
    has_fetch = any(re.search(p, command) for p in POLICY.get("fetch_patterns", []))
    if not has_fetch:
        return
    for pattern in (_OUTPUT_TARGET_PATTERN, _REDIRECT_TARGET_PATTERN):
        for match in pattern.finditer(command):
            resolved = _resolve_fs_token(match.group(1))
            if resolved is not None:
                _tainted_paths.add(resolved)


def _tainted_execution(command: str) -> str | None:
    """Block a command that both references a previously-fetched, unvetted
    file AND contains a real exec keyword — regardless of whether THIS
    command also contains curl/wget (the two-step version of the
    fetch-and-execute bypass: download in one call, run in the next)."""
    has_exec = any(re.search(p, command) for p in POLICY.get("exec_patterns", []))
    if not has_exec:
        return None
    for token in _tokenize_shell(command):
        if token.startswith("-"):
            continue
        resolved = _resolve_fs_token(token)
        if resolved is not None and resolved in _tainted_paths:
            return token
    return None


def check_policy(tool_name: str, tool_input: dict) -> tuple[bool, str]:
    if not ENFORCE:
        return True, "enforcement disabled"

    # rate limit — applies to every tool
    now = time.time()
    _call_timestamps[:] = [t for t in _call_timestamps if now - t < 60]
    if len(_call_timestamps) >= POLICY["rate_limit"]["max_calls_per_minute"]:
        return False, "rate limit exceeded"
    _call_timestamps.append(now)

    if tool_name in ("read_file", "write_file"):
        path = tool_input.get("path", "")
        try:
            resolved = resolve_in_sandbox(path)
        except (ValueError, OSError) as e:
            # fail closed: a malformed path (e.g. embedded null byte) must
            # not crash the gate and skip enforcement — it must be blocked.
            return False, f"path '{path}' could not be resolved: {e}"
        if SANDBOX != resolved and SANDBOX not in resolved.parents:
            return False, f"path '{path}' escapes the sandbox"

    if tool_name == "write_file":
        content = tool_input.get("content", "")
        # normalization is for detection only — never mutates what actually
        # gets written to disk (that still uses the original `content`).
        check_text = normalize_for_policy(content) if NORMALIZE_UNICODE else content
        for pattern in POLICY["forbidden_shell_patterns"]:
            if re.search(pattern, check_text):
                return False, f"file content matches forbidden pattern: {pattern} (after unicode normalization)"
        if _is_fetch_and_execute(check_text):
            return False, "file content combines a remote fetch (curl/wget) with a shell execution (bash/sh/sudo/python) — fetch-and-execute pattern blocked regardless of exact syntax"

    if tool_name == "run_shell":
        command = tool_input.get("command", "")
        # normalization is for detection only — never mutates what actually
        # executes (that still uses the original `command`).
        check_text = normalize_for_policy(command) if NORMALIZE_UNICODE else command
        for pattern in POLICY["forbidden_shell_patterns"]:
            if re.search(pattern, check_text):
                return False, f"shell command matches forbidden pattern: {pattern} (after unicode normalization)"
        if _is_fetch_and_execute(check_text):
            return False, "shell command combines a remote fetch (curl/wget) with a shell execution (bash/sh/sudo/python) — fetch-and-execute pattern blocked regardless of exact syntax"
        tainted = _tainted_execution(check_text)
        if tainted is not None:
            return False, f"'{tainted}' was fetched from the network in an earlier call and has not been reviewed — execution blocked"
        _taint_fetched_output(check_text)
        escaped = _shell_path_escape(command)
        if escaped is not None:
            return False, f"shell command references path '{escaped}' outside the sandbox"
        for url_match in URL_FULL_PATTERN.finditer(command):
            hostname = urlparse(url_match.group(0)).hostname
            if not _hostname_allowed(hostname, POLICY["allowed_domains"]):
                return False, f"shell command references non-allowlisted domain: {hostname}"

    if tool_name == "http_request":
        url = tool_input.get("url", "")
        hostname = urlparse(url).hostname
        if not _hostname_allowed(hostname, POLICY["allowed_domains"]):
            return False, f"domain not in allowlist: {hostname}"

    return True, "ok"
