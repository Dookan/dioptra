"""git URL guard: SSRF row of the threat model."""

from __future__ import annotations

import pytest

from app.ingest.errors import ForbiddenHost, InvalidRepositoryUrl
from app.ingest.git_source import validate_repository_url


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/org/repo.git",
        "ssh://git@github.com/org/repo.git",
        "git://github.com/org/repo.git",
        "file:///etc/passwd",
        "https://user:pass@github.com/org/repo.git",
        "https://",
        "https://github.com/org/repo with space",
        "javascript:alert(1)",
    ],
)
def test_scheme_and_shape_are_enforced(url: str) -> None:
    with pytest.raises(InvalidRepositoryUrl):
        validate_repository_url(url, resolve=False)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/repo.git",
        "https://10.0.0.5/repo.git",
        "https://192.168.1.10/repo.git",
        "https://172.16.0.1/repo.git",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/repo.git",
        "https://localhost/repo.git",
        "https://valkey.internal/repo.git",
        "https://github.com:8443/org/repo.git",
        "https://0.0.0.0/repo.git",
        "https://100.64.0.1/repo.git",
    ],
)
def test_private_and_local_targets_are_forbidden(url: str) -> None:
    with pytest.raises(ForbiddenHost):
        validate_repository_url(url, resolve=False)


def test_public_https_url_passes_without_dns() -> None:
    assert validate_repository_url("https://github.com/org/repo.git", resolve=False) == (
        "https://github.com/org/repo.git"
    )


def test_hostname_resolving_to_private_is_forbidden(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        return [(None, None, None, "", ("10.1.2.3", 443))]

    monkeypatch.setattr("app.ingest.git_source.socket.getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ForbiddenHost):
        validate_repository_url("https://evil.example/repo.git")
