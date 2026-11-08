# demo_attack1.py
"""Attack 1: Unicode/homoglyph evasion of the regex policy engine.
Tests the POLICY ENGINE directly (not the LLM agent loop) — whether
gpt-oss-20b itself decodes/acts on these bytes is a separate,
non-deterministic question from whether the FILTER can see them."""

import policy
from normalize import normalize_for_policy

PAYLOADS = {
    "zero_width":   ("run_shell",  "command", "payloads/unicode_zero_width.txt"),
    "homoglyph":    ("run_shell",  "command", "payloads/unicode_homoglyph.txt"),
    "tag_smuggling": ("write_file", "content", "payloads/unicode_tag_smuggling.txt"),
}

for name, (tool, field, path) in PAYLOADS.items():
    raw = open(path, encoding="utf-8").read()
    print(f"\n=== {name} ===")
    print("raw bytes (len):", len(raw))
    print("normalized preview:", normalize_for_policy(raw)[:120])

    tool_input = {field: raw}
    if tool == "write_file":
        tool_input["path"] = "sandbox/note.txt"

    policy._call_timestamps.clear()
    policy.NORMALIZE_UNICODE = False
    allowed, reason = policy.check_policy(tool, tool_input)
    print(f"BEFORE fix (normalization off): allowed={allowed} reason={reason}")

    policy._call_timestamps.clear()
    policy.NORMALIZE_UNICODE = True
    allowed, reason = policy.check_policy(tool, tool_input)
    print(f"AFTER  fix (normalization on):  allowed={allowed} reason={reason}")

policy.NORMALIZE_UNICODE = True  # leave the module in its secure default state

# --- Step 5: false-positive regression test ---------------------------------
print("\n" + "=" * 60)
print("FALSE-POSITIVE REGRESSION (benign non-ASCII must still be allowed)")
print("=" * 60)

FALSE_POSITIVE_CASES = [
    ("french_accents", "write_file", {"path": "sandbox/note.txt", "content": "Vérifie le fichier café.txt avant de continuer."}),
    ("arabic_darija", "write_file", {"path": "sandbox/note.txt", "content": "تحقق من هذا الملف من فضلك"}),
    ("accented_filename_in_shell", "run_shell", {"command": "cat café-notes.txt"}),
]

for name, tool, tool_input in FALSE_POSITIVE_CASES:
    policy._call_timestamps.clear()
    allowed, reason = policy.check_policy(tool, tool_input)
    status = "PASS" if allowed else "FAIL"
    print(f"{status}: {name} -> allowed={allowed} reason={reason}")
