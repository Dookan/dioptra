# Backend image.
#
# Build context: the repository root. Every dependency is resolved from the
# committed uv.lock, so the image is reproducible and nothing is pulled at
# runtime (CLAUDE.md -> Hard Rules -> No CDNs).

FROM python:3.13-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"

# WeasyPrint (report PDF) needs Pango/Cairo at runtime; git is used by the
# worker for the shallow clone of a git URL ingest. Nothing else from apt.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libffi8 libjpeg62-turbo \
        libopenjp2-7 fonts-dejavu-core fonts-liberation git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv is pinned: an unpinned installer would make the build non-reproducible.
RUN pip install --no-cache-dir uv==0.11.1

# Docker CLI for the worker (same image as the API; the API never gets the
# socket, so the binary is inert there). Static build, pinned and verified.
ARG DOCKER_CLI_VERSION=28.3.3
ARG DOCKER_CLI_SHA256=40c16bcf324f354b382d07e845e6a79e3493fc0c09b252dff9e1a46125589bff
RUN set -eux; \
    curl -fsSLo /tmp/docker.tgz "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLI_VERSION}.tgz"; \
    echo "${DOCKER_CLI_SHA256}  /tmp/docker.tgz" | sha256sum -c -; \
    tar -xzf /tmp/docker.tgz -C /tmp docker/docker; \
    install -m 0755 /tmp/docker/docker /usr/local/bin/docker; \
    rm -rf /tmp/docker /tmp/docker.tgz

WORKDIR /srv/app

# Dependency layer first: application edits must not re-resolve the world.
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY backend/app ./app
COPY backend/alembic ./alembic
COPY backend/alembic.ini ./alembic.ini
COPY backend/templates ./templates
# Our own Semgrep rules travel with the worker image (mounted read-only into
# every semgrep container).
COPY rules ./rules

# The service never runs as root; the sandbox work in P4 depends on that too.
RUN useradd --system --uid 10001 --home /srv/app dioptra \
    && chown -R dioptra:dioptra /srv/app
USER dioptra

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=2).status == 200 else 1)"

CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
