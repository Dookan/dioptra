"""CWE → OWASP Top 10:2021 mapping (docs/analysis-pipeline.md).

Our own table: the CWE lists OWASP publishes per category, plus a short curated
set for CWEs the 2021 lists omit. Cross-checked against the institution's
earlier report generator; where the two disagreed, the official 2021 mapping
won and the difference is noted next to the entry. A CWE absent here maps to
``None``: the "unclassified" bucket is a valid state of a finding, not an
error (CLAUDE.md → Glossary → Finding).
"""

from __future__ import annotations

OWASP_TITLES: dict[str, str] = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

_CWE_BY_CATEGORY: dict[str, tuple[int, ...]] = {
    "A01:2021": (
        22,
        23,
        35,
        59,
        200,
        201,
        219,
        264,
        275,
        276,
        284,
        285,
        352,
        359,
        377,
        402,
        425,
        441,
        497,
        538,
        540,
        548,
        552,
        566,
        601,
        639,
        651,
        668,
        706,
        862,
        863,
        913,
        922,
        1275,
    ),
    "A02:2021": (
        261,
        296,
        310,
        319,
        321,
        322,
        323,
        324,
        325,
        326,
        327,
        328,
        329,
        330,
        331,
        335,
        336,
        337,
        338,
        340,
        347,
        523,
        720,
        757,
        759,
        760,
        780,
        818,
        916,
    ),
    "A03:2021": (
        20,
        74,
        75,
        77,
        78,
        79,
        80,
        83,
        87,
        88,
        89,
        90,
        91,
        93,
        94,
        95,
        96,
        97,
        98,
        99,
        100,
        113,
        116,
        138,
        184,
        470,
        471,
        564,
        610,
        643,
        644,
        652,
        917,
        1336,
    ),
    "A04:2021": (
        73,
        183,
        209,
        213,
        235,
        256,
        257,
        266,
        269,
        280,
        311,
        312,
        313,
        316,
        419,
        430,
        434,
        444,
        451,
        472,
        501,
        522,
        525,
        539,
        579,
        598,
        602,
        642,
        646,
        650,
        653,
        656,
        657,
        799,
        807,
        840,
        841,
        927,
        1021,
        1173,
    ),
    "A05:2021": (
        2,
        11,
        13,
        15,
        16,
        260,
        315,
        400,
        520,
        526,
        537,
        541,
        547,
        611,
        614,
        756,
        776,
        942,
        1004,
        1032,
        1174,
        1333,
    ),
    "A06:2021": (937, 1035, 1104, 1395),
    "A07:2021": (
        255,
        259,
        287,
        288,
        290,
        294,
        295,
        297,
        300,
        302,
        304,
        306,
        307,
        346,
        384,
        521,
        613,
        620,
        640,
        798,
        940,
        1216,
    ),
    "A08:2021": (345, 353, 426, 494, 502, 565, 784, 829, 830, 915, 1321),
    "A09:2021": (117, 223, 532, 778),
    "A10:2021": (918,),
}

# CWEs the official 2021 lists omit, placed where the earlier generator (and
# the anchor reports it produced) put them, so the reports keep agreeing.
_CURATED: dict[int, str] = {
    400: "A05:2021",  # uncontrolled resource consumption: anchor report prints A05
    770: "A05:2021",  # allocation without limits, same class as 400
    250: "A05:2021",  # execution with unnecessary privileges (e.g. root container)
    732: "A05:2021",  # incorrect permission assignment
    1333: "A05:2021",  # ReDoS
    1321: "A08:2021",  # prototype pollution, sibling of 915
    1395: "A06:2021",  # dependency with a known vulnerability (CWE added in 2023)
    943: "A03:2021",  # NoSQL / data-query injection
}
# Differences with the earlier generator, resolved in favour of the official
# lists: 295 (it said A02; official A07), 311 (A02; official A04), 347 (A08;
# official A02).

_OWASP_BY_CWE: dict[int, str] = {
    cwe: category for category, cwes in _CWE_BY_CATEGORY.items() for cwe in cwes
}
_OWASP_BY_CWE.update(_CURATED)


def owasp_for(cwe: int | None) -> str | None:
    """OWASP Top 10:2021 code for a CWE, or ``None`` when unclassified."""
    if cwe is None:
        return None
    return _OWASP_BY_CWE.get(cwe)
