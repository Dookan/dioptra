"""nginx and the API must agree on the upload caps (phase 10, survey §2.3).

nginx refused the vulnerability dump at 200 MiB while the API allowed 512 MiB,
and nobody noticed because each number lived in its own file. The defaults
are now declared once per side and pinned against each other here.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.core.config import Settings

REPO = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024


def _dockerfile_env(name: str) -> int:
    text = (REPO / "docker" / "frontend.Dockerfile").read_text(encoding="utf-8")
    match = re.search(rf"\b{name}=(\d+)\b", text)
    assert match is not None, f"{name} has no default in frontend.Dockerfile"
    return int(match.group(1))


def _compose_default(path: str, name: str) -> int:
    text = (REPO / "docker" / path).read_text(encoding="utf-8")
    match = re.search(rf"\${{{name}:-(\d+)}}", text)
    assert match is not None, f"{name} has no default in {path}"
    return int(match.group(1))


def test_the_zip_cap_is_the_same_number_on_both_sides() -> None:
    api = Settings.model_fields["max_zip_bytes"].default
    assert _dockerfile_env("DIOPTRA_MAX_ZIP_MIB") * MIB == api
    for compose in ("docker-compose.yml", "docker-compose.frontend.yml"):
        assert _compose_default(compose, "DIOPTRA_MAX_ZIP_MIB") * MIB == api


def test_the_dump_cap_leaves_one_mib_for_the_multipart_envelope() -> None:
    api = Settings.model_fields["vulndb_max_dump_bytes"].default
    assert _dockerfile_env("DIOPTRA_VULNDB_MAX_DUMP_MIB") == api // MIB + 1
    for compose in ("docker-compose.yml", "docker-compose.frontend.yml"):
        assert _compose_default(compose, "DIOPTRA_VULNDB_MAX_DUMP_MIB") == api // MIB + 1


def test_nginx_reads_both_caps_from_the_environment_and_streams_the_zip() -> None:
    conf = (REPO / "docker" / "nginx.conf").read_text(encoding="utf-8")
    ingest = conf[conf.index("location ~ ^/api/v1/projects/[^/]+/ingest$") :]
    ingest = ingest[: ingest.index("\n    }")]
    assert "client_max_body_size ${DIOPTRA_MAX_ZIP_MIB}m;" in ingest
    assert "proxy_request_buffering off;" in ingest
    dump = conf[conf.index("location = /api/v1/inventory/vulndb/import") :]
    dump = dump[: dump.index("\n    }")]
    assert "client_max_body_size ${DIOPTRA_VULNDB_MAX_DUMP_MIB}m;" in dump
    # Addendum A: the API parses the dump to disk as it arrives; buffering it
    # in nginx first would put the whole GiB on the proxy's disk and delay it.
    assert "proxy_request_buffering off;" in dump
    # The regex location must match the route exactly and nothing beside it.
    pattern = re.compile(r"^/api/v1/projects/[^/]+/ingest$")
    assert pattern.match("/api/v1/projects/3f1c0000-0000-0000-0000-000000000000/ingest")
    assert not pattern.match("/api/v1/projects/x/ingest/git")
    assert not pattern.match("/api/v1/projects/x/y/ingest")
