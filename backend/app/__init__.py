"""Dioptra backend package."""

#: One number for the whole platform, in step with `pyproject.toml` and
#: `frontend/package.json` (`tests/test_version.py`). The scheme is
#: `mmarin`'s (CLAUDE.md → Release rules): a small fix bumps the third
#: number, a completed phase the second, a broken contract the first.
__version__ = "1.5.0"
