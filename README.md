# AgentGate

A policy-enforcing gateway between an LLM agent and its tools. The agent
(Groq, `openai/gpt-oss-20b`) is given four tools — `read_file`, `write_file`,
`run_shell`, `http_request` — and every tool call is checked by a policy
engine *before* it executes. The point of the project is to demonstrate that
an LLM agent acting on untrusted input (a PR comment, a support ticket, a
scraped web page) needs an independent, non-bypassable enforcement layer,
and to show how far a regex/denylist-based version of that layer can be
pushed — and where it still breaks.

## Architecture

| File | Role |
|---|---|
| `agent.py` | The agent loop: sends the task + tool results to the model, runs `check_policy()` before every tool call, logs every decision. |
| `tools.py` | The 4 tool implementations. `read_file`/`write_file` are confined to `sandbox/`; `run_shell` executes with `cwd=sandbox/`; `http_request` refuses to follow redirects. |
| `policy.py` | `check_policy(tool_name, tool_input) -> (allowed, reason)` — the actual gate. |
| `policy.yaml` | The rulebook: allowed domains, forbidden shell patterns, rate limit. |
| `normalize.py` | Unicode canonicalization pass (decodes Tag-block smuggling, strips zero-width/bidi noise, folds documented homoglyphs, NFKC) used for detection only — never mutates what actually executes. |
| `auditlog.py` | Hash-chained, tamper-evident SQLite audit log (`audit.db`, generated at runtime, not committed). |
| `demo.py` | Runs one attack payload twice — policy disabled, then enabled — to show the gate matters. |
| `demo_attack1.py` | Tests the Unicode-evasion attack directly against the policy engine (deterministic, no LLM call needed). |
| `generate_unicode_payloads.py` | One-off generator for the Unicode payload files (invisible/confusable characters don't survive normal paste/heredocs reliably). |
| `payloads/` | Reference attack scenarios (not read at runtime — their text is pasted directly as the agent's task). |

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install groq python-dotenv rich PyYAML
```

`test.py` is a standalone smoke test unrelated to the agent/policy pipeline
and additionally needs `pip install google-genai`.

Create a `.env` file (gitignored — never commit it) with:

```
GROQ_API_KEY=<your key>
```

## Usage

```bash
# interactive: paste a task, type END on its own line to submit
python agent.py

# policy-disabled vs policy-enabled comparison on one attack payload
python demo.py

# Unicode-evasion attack vs. the normalization fix, tested directly
# against the policy engine (no LLM call, fully deterministic)
python generate_unicode_payloads.py   # (re)generates payloads/unicode_*.txt
python demo_attack1.py
```

## Security model

- **Sandbox is the only authorized filesystem location** (`policy.yaml`'s
  `allowed_paths: sandbox/`). This is enforced for all three filesystem-facing
  tools, not just `read_file`/`write_file`: `run_shell` executes with
  `cwd=sandbox`, so bare relative filenames can't reach the project root, and
  an explicit path-escape check (absolute, `~`, `$HOME`, `../` traversal)
  resolves every shell argument against the sandbox boundary — a denylist of
  specific sensitive paths (`.ssh`, `/etc/shadow`) is *not* the mechanism;
  the boundary itself is what's enforced.
- **Domain allowlist** uses real hostname comparison (`urlparse().hostname`,
  exact or subdomain match) — not substring containment, which a URL like
  `evilexample.com.attacker.io` would otherwise pass.
- **`http_request` does not follow redirects** — an allowlisted URL that
  302s elsewhere would otherwise fetch from a domain that was never checked.
- **Forbidden shell patterns** (`curl|bash`, `rm -rf`, SSH key material,
  raw-socket exfil channels, ...) are checked against Unicode-normalized
  text, so zero-width-character injection, Cyrillic homoglyphs, and Unicode
  Tag-block smuggling can't dodge a literal keyword match.
- **Fetch-and-execute AND-logic**: any text containing both a fetch command
  (`curl`/`wget`) and an execution keyword is blocked regardless of how
  they're joined (piped, saved-then-run, separate lines) — with a negative
  lookbehind so a plain `.sh` file *extension* doesn't falsely trip the
  `sh`/`bash` keyword match.
- **Cross-call taint tracking**: a file fetched by `curl`/`wget` in one call
  is remembered for the rest of the run; a *later*, separate call that
  executes it is still blocked, even though that later call has no fetch
  command of its own.
- **Rate limiting** and a **hash-chained audit log** (every decision —
  allowed or blocked — is appended with a SHA-256 chain back to the previous
  entry, so tampering with history is detectable).
- Normalization and all detection logic is **detection-only**: the original,
  unmodified input is always what actually gets written to disk or executed
  if a call is allowed.

## Attack catalog (`payloads/`)

| File | Technique |
|---|---|
| `shell_injection.txt` | Direct `curl \| bash` in a PR-comment-style prompt injection. |
| `shell_injection_obfuscated.txt` | Same, base64-encoded to dodge a literal-string filter. |
| `supply_chain_staging.txt` | Asks the agent to *save* (not run) a fetch-and-execute script — tests that saving is blocked too, not just running. |
| `path_traversal.txt` | `../../../../home/user/.ssh/id_rsa` — sandbox escape via relative traversal. |
| `credential_exfiltration.txt`* | Asks the agent to POST a secrets file to a non-allowlisted domain. |
| `unicode_zero_width.txt` | Zero-width characters (U+200B/U+200C) injected inside `curl`/`bash` to dodge a literal regex. |
| `unicode_homoglyph.txt` | Cyrillic confusables (`с`, `а`, ...) substituted for Latin letters. |
| `unicode_tag_smuggling.txt` | Fully invisible payload via the deprecated Unicode Tag block (U+E0000–U+E007F) — the visible text is entirely innocuous. |

\* kept locally for testing but gitignored — it embeds a fake-but-realistic-looking
API key/password that would otherwise trip GitHub's secret scanning.

## Known limitations

These are deliberate, documented gaps — not oversights — because they're
fundamental to a denylist/regex approach rather than fixable with one more
pattern:

- `curl`/`wget`'s *own* redirect-following (e.g. `curl -L`) isn't
  intercepted — only `http_request`'s is, since that's code under our
  control. Policing a real subprocess's internal HTTP behavior would need
  an egress proxy, not a string check.
- Indirect shell constructs (`D=..; cd $D`) that only resolve a dangerous
  path at runtime aren't caught by the static token-level path check.
- Homoglyph folding covers the 7 documented Latin/Cyrillic confusable pairs
  used in the test payload, not the full Unicode confusables table.
- A sufficiently indirect `python -c "..."` one-liner (dynamic imports,
  `exec()`, etc.) is fundamentally hard to catch with text patterns — this
  is the core argument for a default-deny allowlist of exact commands being
  the principled long-term fix, rather than an ever-growing denylist.
