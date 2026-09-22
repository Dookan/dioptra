"""Real function copied verbatim from app/workflow/diagrams.py (2026-09-22).

Hand-counted in tests/test_brief.py; do not edit — the numbers there depend on these lines.
"""


def mermaid_escape(text: str) -> str:
    """Safe inside a double-quoted Mermaid label: entities for what could break out."""
    out = []
    for char in text:
        code = ord(char)
        if char == '"':
            out.append("#quot;")
        elif char == "#":
            out.append("#35;")
        elif char in "<>{}[]()|`\\":
            out.append(f"#{code};")
        elif code < 32 or code == 127:
            out.append(" ")
        else:
            out.append(char)
    return "".join(out)
