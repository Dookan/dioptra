"""Software inventory (P5 day 18): SBOM / CBOM / VEX per analysis, the local
vulnerability mirror (OSV + NVD), BOM ↔ CVE correlation and the statistics
panel. Design: ``tasks/phase5-survey.md``; behaviour: ``docs/software-inventory.md``.

Nothing in this package queries a third party at request time (CLAUDE.md →
Hard Rules → No CDNs, level 3). The only outbound connection the platform ever
opens is the scheduled sync job in ``sync.py``, and it runs in the worker.
"""
