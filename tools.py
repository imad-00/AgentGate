# tools.py
import subprocess
import urllib.request
from pathlib import Path

SANDBOX = Path("sandbox").resolve()

def resolve_in_sandbox(path: str) -> Path:
    raw = Path(path)
    if raw.parts and raw.parts[0] == "sandbox":
        raw = Path(*raw.parts[1:]) if len(raw.parts) > 1 else Path(".")
    return (SANDBOX / raw).resolve()

def read_file(path: str) -> str:
    p = resolve_in_sandbox(path)
    return p.read_text()

def write_file(path: str, content: str) -> str:
    p = resolve_in_sandbox(path)
    p.write_text(content)
    return f"wrote {len(content)} bytes to {path}"

def run_shell(command: str) -> str:
    # cwd=SANDBOX: a bare relative filename (`cat apikey`, `cat .env`) can
    # never reach the project root just because it has no "/" in it — the
    # shell itself resolves it against the sandbox, same as read_file/write_file.
    result = subprocess.run(
        command, shell=True, cwd=SANDBOX, capture_output=True, text=True, timeout=10
    )
    output = result.stdout + result.stderr
    return output[:2000]

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects. Without this, a request to an
    allowlisted URL that 302s elsewhere would silently fetch from a
    domain that was never checked against the policy."""
    def redirect_request(self, *args, **kwargs):
        return None

_opener = urllib.request.build_opener(_NoRedirect)

def http_request(url: str) -> str:
    with _opener.open(url, timeout=10) as resp:
        return resp.read().decode()[:2000]
