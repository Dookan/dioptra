"""Stage E7's sandbox: where the DEVELOPER'S tests run against AUDITED code.

The analysis containers parse hostile code; this one executes it. One
ephemeral container per verification attempt, no network, read-only root, all
capabilities dropped, a non-root user, hard CPU/RAM/pids limits, a short
timeout that kills the named container, and exactly one writable mount — the
per-attempt directory, which is discarded afterwards. Nothing of the audited
project is installed (docs/threat-model.md → Test sandbox).
"""
