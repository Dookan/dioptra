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

# uv is pinned: an unpinned installer would make the build non-reproducible.
RUN pip install --no-cache-dir uv==0.11.1

WORKDIR /srv/app

# Dependency layer first: application edits must not re-resolve the world.
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY backend/app ./app
COPY backend/alembic ./alembic
COPY backend/alembic.ini ./alembic.ini

# The service never runs as root; the sandbox work in P4 depends on that too.
RUN useradd --system --uid 10001 --home /srv/app dioptra \
    && chown -R dioptra:dioptra /srv/app
USER dioptra

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=2).status == 200 else 1)"

CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
