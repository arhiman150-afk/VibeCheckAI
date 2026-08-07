"""
parser.py — PostScript Stream Inspection & Anti-Steganography Unmasking

Reads a PDF at the character-object layer (via pdfplumber, which exposes
each glyph's font size, fill color, and position from the raw content
stream) rather than relying on rendered/rasterized output. This lets us
catch text a human reviewer would never see:

  - Sub-pixel micro-fonts (size <= 1.5pt)
  - White-on-white or near-background-color text
  - Zero-width Unicode characters spliced into otherwise visible text
  - Known credential / command-injection directive patterns

Nothing here executes any extracted content. It only extracts, classifies,
and returns structured findings for the vector engine to score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

try:
    import pdfplumber
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "pdfplumber is required. Install with: pip install pdfplumber"
    ) from e

ZERO_WIDTH_CHARS = ["\u200B", "\u200C", "\u200D", "\uFEFF"]
ZERO_WIDTH_RE = re.compile("[" + "".join(ZERO_WIDTH_CHARS) + "]")

MICRO_FONT_THRESHOLD_PT = 1.5

# Patterns that indicate an attempted instruction override / command
# injection / credential harvest, independent of the vector score. These
# act as a fast, explainable first pass; the vector engine handles
# paraphrased/novel variants that don't match a literal pattern.
SUSPICIOUS_PATTERNS = {
    "instruction_override": re.compile(
        r"(system\s+instruction\s+override|ignore\s+(all\s+)?prior\s+instructions|"
        r"disregard\s+(the\s+)?(above|previous)\s+instructions)",
        re.IGNORECASE,
    ),
    "command_execution": re.compile(
        r"\b(curl|wget|bash\s+-c|/bin/sh|rm\s+-rf|nc\s+-e|eval\()\b",
        re.IGNORECASE,
    ),
    "credential_exfil": re.compile(
        r"(/etc/passwd|\.ssh/id_rsa|api[_-]?key\s*[:=]|password\s*[:=]|"
        r"bearer\s+[a-z0-9\-_.]{10,})",
        re.IGNORECASE,
    ),
    "forced_score": re.compile(
        r"(set\s+(the\s+)?(candidate\s+)?(evaluation\s+)?score\s+to\s+10|"
        r"score\s*[:=]\s*10\s*/\s*10|automatically\s+approve)",
        re.IGNORECASE,
    ),
}


@dataclass
class ExtractedChar:
    text: str
    size: float
    color: Optional[tuple]
    x0: float
    y0: float
    page: int


@dataclass
class ParseResult:
    visible_text: str = ""
    hidden_text: str = ""
    full_raw_text: str = ""
    zero_width_count: int = 0
    zero_width_positions: list = field(default_factory=list)
    hidden_char_count: int = 0
    matched_patterns: dict = field(default_factory=dict)
    sanitized_text: str = ""
    page_count: int = 0

    @property
    def has_hidden_payload(self) -> bool:
        return self.hidden_char_count > 0 or self.zero_width_count > 0

    @property
    def matched_pattern_names(self) -> list:
        return [name for name, hit in self.matched_patterns.items() if hit]


def _is_near_white(color) -> bool:
    """pdfplumber gives non_stroking_color as a tuple (grayscale, RGB, or CMYK),
    a float/int for grayscale, or occasionally None."""
    if color is None:
        return False
    if isinstance(color, (int, float)):
        return float(color) >= 0.92
    try:
        vals = list(color)
    except TypeError:
        return False
    if not vals:
        return False
    # Grayscale: [g] near 1.0. RGB: [r,g,b] all near 1.0.
    return all(v >= 0.92 for v in vals)


def _classify_char(size: float, color) -> bool:
    """Returns True if this glyph is effectively invisible to a human reader."""
    if size is not None and size <= MICRO_FONT_THRESHOLD_PT:
        return True
    if _is_near_white(color):
        return True
    return False


def parse_pdf(file_path: str) -> ParseResult:
    result = ParseResult()
    visible_parts = []
    hidden_parts = []
    raw_parts = []

    with pdfplumber.open(file_path) as pdf:
        result.page_count = len(pdf.pages)
        for page_idx, page in enumerate(pdf.pages):
            chars = page.chars
            for ch in chars:
                text = ch.get("text", "")
                if text == "":
                    continue
                size = ch.get("size")
                color = ch.get("non_stroking_color")
                raw_parts.append(text)

                if ZERO_WIDTH_RE.match(text):
                    result.zero_width_count += 1
                    result.zero_width_positions.append(
                        {"page": page_idx, "x": ch.get("x0"), "y": ch.get("y0")}
                    )
                    # Zero-width chars are invisible but not "hidden payload text"
                    # themselves — they're stripped from both streams.
                    continue

                if _classify_char(size, color):
                    hidden_parts.append(text)
                    result.hidden_char_count += 1
                else:
                    visible_parts.append(text)

    result.visible_text = "".join(visible_parts)
    result.hidden_text = "".join(hidden_parts)
    result.full_raw_text = "".join(raw_parts)

    # Pattern scan runs over hidden text primarily (that's the attack surface),
    # but also over full raw text in case an attacker skips size/color tricks
    # entirely and just relies on the LLM ignoring formatting.
    scan_target = result.hidden_text + "\n" + result.full_raw_text
    for name, pattern in SUSPICIOUS_PATTERNS.items():
        result.matched_patterns[name] = bool(pattern.search(scan_target))

    result.sanitized_text = result.visible_text

    return result


if __name__ == "__main__":
    import sys
    import json

    target = sys.argv[1] if len(sys.argv) > 1 else "adversarial_resume.pdf"
    res = parse_pdf(target)
    print(json.dumps(
        {
            "page_count": res.page_count,
            "visible_text_preview": res.visible_text[:200],
            "hidden_text": res.hidden_text,
            "hidden_char_count": res.hidden_char_count,
            "zero_width_count": res.zero_width_count,
            "matched_patterns": res.matched_patterns,
        },
        indent=2,
    ))
