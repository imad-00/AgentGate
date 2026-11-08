# normalize.py
"""Defends against Unicode evasion of regex-based agent guardrails (OWASP ASI01 / MITRE ATLAS AML.T0068 "LLM Prompt Obfuscation")."""

import unicodedata

# Deprecated Unicode Tag block (U+E0000-U+E007F): an invisible shadow copy of
# ASCII. tag codepoint = ascii codepoint + 0xE0000. U+E007F is a "cancel"
# marker with no ASCII equivalent. Renders as nothing in any editor/terminal
# but survives copy-paste intact (Johann Rehberger's "ASCII Smuggling"
# research; also documented crossing from AI prompt-injection into live
# phishing campaigns to evade keyword/signature filters).
_TAG_BASE = 0xE0000
_TAG_CANCEL = 0xE007F

# Zero-width / bidi-control noise: carries no payload of its own, only
# breaks up literal keyword matches when inserted mid-word. Safe to delete
# outright (unlike the Tag block, which must be decoded, not deleted).
_ZERO_WIDTH_NOISE = (
    "​‌‍"  # ZWSP, ZWNJ, ZWJ
    "‎‏"  # LTR/RTL marks
    "‪‫‬‭‮"  # bidi embedding/override controls
    "⁠﻿­"  # word joiner, BOM, soft hyphen
)
_ZERO_WIDTH_TABLE = {ord(c): None for c in _ZERO_WIDTH_NOISE}

# 7 documented Cyrillic confusable pairs (Unicode confusables table, used in
# a known LLaMA-filter-bypass payload): visually identical to their Latin
# counterparts but distinct codepoints, so they don't match a Latin-letter regex.
_CONFUSABLES = {
    "а": "a",
    "с": "c",
    "е": "e",
    "і": "i",
    "о": "o",
    "р": "p",
    "х": "x",
}


def _decode_tag_block(text: str) -> str:
    out = []
    for ch in text:
        cp = ord(ch)
        if cp == _TAG_CANCEL:
            continue
        if _TAG_BASE < cp <= _TAG_BASE + 0x7E:
            out.append(chr(cp - _TAG_BASE))
        else:
            out.append(ch)
    return "".join(out)


def normalize_for_policy(text: str) -> str:
    # 1. Decode Tag-block smuggling FIRST/separately — this must reveal the
    # hidden content, not delete it, or the attack text would vanish from
    # the regex entirely instead of being exposed to it.
    text = _decode_tag_block(text)

    # 2. Delete zero-width/bidi-control noise outright.
    text = text.translate(_ZERO_WIDTH_TABLE)

    # 3. Fold the documented Cyrillic confusables back to Latin.
    for cyrillic, latin in _CONFUSABLES.items():
        text = text.replace(cyrillic, latin)

    # 4. NFKC as a final catch-all for other Unicode-equivalence tricks.
    return unicodedata.normalize("NFKC", text)
