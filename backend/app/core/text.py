"""Text normalisation shared by every module that stores free text.

Moved out of ``app.workflow.triage`` (phase 6): the justification floor is
enforced on the AUTH surface too, and ``app.auth`` must not import
``app.workflow``. ``app.workflow.triage`` re-exports every name, so existing
imports keep working unchanged.
"""

from __future__ import annotations

import re

from app.core.errors import JustificationRequired

#: Shortest justification accepted after stripping whitespace. "ok" is not a
#: reason; ten characters is the floor at which a sentence can exist.
MIN_JUSTIFICATION_CHARS = 10
MAX_JUSTIFICATION_CHARS = 4000

#: C0/C1 control characters other than tab, newline and carriage return. JSON
#: carries them happily; python-docx refuses them ("All strings must be XML
#: compatible"), and a signed version is immutable — so one such character
#: would make a version un-exportable as DOCX forever. Stripped at the boundary.
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def strip_control_chars(raw: str) -> str:
    return CONTROL_CHARS.sub("", raw)


def clean_justification(raw: str) -> str:
    """Normalize a justification or raise :class:`JustificationRequired`."""
    text = " ".join(strip_control_chars(raw).split())
    if len(text) < MIN_JUSTIFICATION_CHARS:
        raise JustificationRequired(f"justification shorter than {MIN_JUSTIFICATION_CHARS}")
    if len(text) > MAX_JUSTIFICATION_CHARS:
        raise JustificationRequired(f"justification longer than {MAX_JUSTIFICATION_CHARS}")
    return text
