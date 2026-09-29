"""git URL validation and shallow clone (threat model → git URL ingest).

The request handler only VALIDATES the URL; the clone runs in the worker so a
slow or hostile remote never holds an HTTP connection open. Validation resolves
the host and refuses every private, loopback, link-local or multicast address
— the platform must never be turned into a proxy against the factory LAN.
"""

from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from app.core.process import Ending, StopCheck, Stopped, run_stoppable
from app.ingest.errors import ForbiddenHost, InvalidRepositoryUrl, RepoUnreachable

ALLOWED_SCHEMES = frozenset({"https"})
MAX_URL_LENGTH = 512


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    # ``is_global`` also refuses the shared address space 100.64.0.0/10 (CGNAT),
    # which ``is_private`` does not consider private.
    return ip.is_global and not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_repository_url(url: str, *, resolve: bool = True) -> str:
    """Return the normalized URL or raise a typed error. Never follows anything."""
    if len(url) > MAX_URL_LENGTH or "\x00" in url or any(c.isspace() for c in url):
        raise InvalidRepositoryUrl("malformed url")
    parts = urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise InvalidRepositoryUrl(f"scheme {parts.scheme!r} not allowed")
    if parts.username or parts.password:
        raise InvalidRepositoryUrl("credentials in url")
    host = parts.hostname
    if not host:
        raise InvalidRepositoryUrl("missing host")
    if parts.port not in (None, 443):
        raise ForbiddenHost(f"port {parts.port}")
    if host in ("localhost",) or host.endswith((".local", ".internal", ".localhost")):
        raise ForbiddenHost(host)
    try:
        # A literal IP is checked without DNS.
        if not _is_public(host):
            raise ForbiddenHost(host)
        return url
    except ValueError:
        pass  # a hostname, resolve it below
    if resolve:
        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise RepoUnreachable(f"cannot resolve {host}") from exc
        for info in infos:
            if not _is_public(str(info[4][0])):
                raise ForbiddenHost(f"{host} resolves to a private address")
    return url


def shallow_clone(
    url: str,
    destination: Path,
    *,
    timeout_seconds: int,
    should_stop: StopCheck | None = None,
) -> None:
    """Clone with depth 1, redirects disabled, no credential helpers, bounded time.

    With ``should_stop`` a cancel kills the clone's whole process group
    (``git-remote-https`` included) within seconds and raises ``Stopped``
    (phase 12).
    """
    validate_repository_url(url)
    git = shutil.which("git")
    if git is None:
        raise RepoUnreachable("git is not installed on the worker")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    argv = [
        git,
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
        url,
        str(destination),
    ]
    env = {
        "GIT_TERMINAL_PROMPT": "0",
        "PATH": "/usr/bin:/bin",
        "HOME": str(destination.parent),
    }
    if should_stop is not None:
        _clone_stoppable(argv, destination, env, timeout_seconds, should_stop)
        return
    try:
        completed = subprocess.run(  # noqa: S603 — argv is a fixed list, url validated above
            argv,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(destination, ignore_errors=True)
        raise RepoUnreachable("clone timed out") from exc
    if completed.returncode != 0:
        shutil.rmtree(destination, ignore_errors=True)
        raise RepoUnreachable(f"git exit {completed.returncode}")


def _clone_stoppable(
    argv: list[str],
    destination: Path,
    env: dict[str, str],
    timeout_seconds: int,
    should_stop: StopCheck,
) -> None:
    done = run_stoppable(argv, timeout_seconds=timeout_seconds, should_stop=should_stop, env=env)
    if done.ending is not Ending.EXITED or done.returncode != 0:
        shutil.rmtree(destination, ignore_errors=True)
    if done.ending is Ending.STOPPED:
        raise Stopped("clone")
    if done.ending is Ending.TIMED_OUT:
        raise RepoUnreachable("clone timed out")
    if done.returncode != 0:
        raise RepoUnreachable(f"git exit {done.returncode}")
