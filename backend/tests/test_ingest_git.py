"""git URL guard: SSRF row of the threat model."""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest

from app.ingest.errors import ForbiddenHost, InvalidRepositoryUrl, RepoUnreachable
from app.ingest.git_source import MAX_URL_LENGTH, shallow_clone, validate_repository_url


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


# P1 close (2026-09-24): the mutation pass showed that nothing proved a PUBLIC
# address is accepted, and that `shallow_clone` — whose argv carries the
# redirect, protocol and credential controls of the threat model — had no test.


@pytest.mark.parametrize(
    "url", ["https://140.82.112.3/org/repo.git", "https://[2606:4700::1111]/r"]
)
def test_a_public_literal_address_passes(url: str) -> None:
    assert validate_repository_url(url, resolve=False) == url


def test_a_hostname_resolving_only_to_public_addresses_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Any, ...]] = []

    def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        calls.append((args, kwargs))
        return [(None, None, None, "", ("140.82.112.3", 443))]

    monkeypatch.setattr("app.ingest.git_source.socket.getaddrinfo", fake_getaddrinfo)
    assert validate_repository_url("https://github.com/org/repo.git") == (
        "https://github.com/org/repo.git"
    )
    assert calls == [(("github.com", 443), {"proto": socket.IPPROTO_TCP})]


def test_one_private_address_among_public_ones_is_enough_to_refuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_getaddrinfo(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        return [
            (None, None, None, "", ("140.82.112.3", 443)),
            (None, None, None, "", ("192.168.0.9", 443)),
        ]

    monkeypatch.setattr("app.ingest.git_source.socket.getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ForbiddenHost):
        validate_repository_url("https://rebind.example/repo.git")


def test_an_unresolvable_host_is_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        raise socket.gaierror("no such host")

    monkeypatch.setattr("app.ingest.git_source.socket.getaddrinfo", fake_getaddrinfo)
    with pytest.raises(RepoUnreachable):
        validate_repository_url("https://nowhere.example/repo.git")


@pytest.mark.parametrize(
    "url",
    [
        "https://token@github.com/org/repo.git",  # a username alone is a credential
        "https://github.com/org/re\x00po.git",
        "https://github.com/" + "a" * (MAX_URL_LENGTH - len("https://github.com/") + 1),
    ],
)
def test_credentials_nul_and_length_are_refused(url: str) -> None:
    with pytest.raises(InvalidRepositoryUrl):
        validate_repository_url(url, resolve=False)


def test_the_length_cap_admits_its_own_value() -> None:
    url = "https://github.com/" + "a" * (MAX_URL_LENGTH - len("https://github.com/"))
    assert len(url) == MAX_URL_LENGTH
    assert validate_repository_url(url, resolve=False) == url


def test_the_default_https_port_is_admitted() -> None:
    url = "https://github.com:443/org/repo.git"
    assert validate_repository_url(url, resolve=False) == url


@pytest.mark.parametrize(
    "url",
    ["https://printer.local/r.git", "https://Printer.LOCAL/r.git", "https://app.localhost/r.git"],
)
def test_local_names_are_forbidden_without_dns(url: str) -> None:
    with pytest.raises(ForbiddenHost):
        validate_repository_url(url, resolve=False)


class _Completed:
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode


def _fake_clone(
    monkeypatch: pytest.MonkeyPatch, *, returncode: int = 0, timeout: bool = False
) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> _Completed:
        calls.append({"argv": argv, **kwargs})
        destination = Path(argv[-1])
        destination.mkdir(parents=True)
        (destination / "partial").write_text("half a clone")
        if timeout:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        return _Completed(returncode)

    monkeypatch.setattr(
        "app.ingest.git_source.shutil.which",
        lambda name: "/usr/bin/git" if name == "git" else None,
    )
    monkeypatch.setattr("app.ingest.git_source.subprocess.run", fake_run)
    monkeypatch.setattr(
        "app.ingest.git_source.socket.getaddrinfo",
        lambda *_a, **_k: [(None, None, None, "", ("140.82.112.3", 443))],
    )
    return calls


def test_the_clone_carries_every_control_of_the_threat_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _fake_clone(monkeypatch)
    destination = tmp_path / "jobs" / "a1" / "clone"  # the parents are created
    shallow_clone("https://github.com/org/repo.git", destination, timeout_seconds=42)
    (call,) = calls
    assert call["argv"] == [
        "/usr/bin/git",
        "-c",
        "http.followRedirects=false",
        "-c",
        "credential.helper=",
        "-c",
        "core.symlinks=false",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "clone",
        "--depth",
        "1",
        "--no-tags",
        "--single-branch",
        "--",
        "https://github.com/org/repo.git",
        str(destination),
    ]
    assert call["timeout"] == 42
    assert call["check"] is False
    assert call["capture_output"] is True
    # No inherited environment: no proxy, no askpass, no credential in HOME.
    assert call["env"] == {
        "GIT_TERMINAL_PROMPT": "0",
        "PATH": "/usr/bin:/bin",
        "HOME": str(destination.parent),
    }
    assert destination.parent.stat().st_mode & 0o777 == 0o700
    assert (destination / "partial").exists()  # a success keeps the clone


@pytest.mark.parametrize("kwargs", [{"returncode": 128}, {"timeout": True}])
def test_a_failed_clone_leaves_nothing_behind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, Any]
) -> None:
    _fake_clone(monkeypatch, **kwargs)
    destination = tmp_path / "clone"
    with pytest.raises(RepoUnreachable):
        shallow_clone("https://github.com/org/repo.git", destination, timeout_seconds=5)
    assert not destination.exists()


def test_the_clone_revalidates_the_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The worker never trusts that the request handler validated it.
    calls = _fake_clone(monkeypatch)
    with pytest.raises(ForbiddenHost):
        shallow_clone("https://10.0.0.5/repo.git", tmp_path / "clone", timeout_seconds=5)
    assert calls == []


def test_no_git_on_the_worker_is_unreachable_not_a_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _fake_clone(monkeypatch)
    monkeypatch.setattr("app.ingest.git_source.shutil.which", lambda _name: None)
    with pytest.raises(RepoUnreachable):
        shallow_clone("https://github.com/org/repo.git", tmp_path / "clone", timeout_seconds=5)
    assert calls == []
