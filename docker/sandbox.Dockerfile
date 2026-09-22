# Sandbox image: where the DEVELOPER'S tests run against the AUDITED code.
#
# The analysis containers parse hostile code; this one EXECUTES it. The worker
# starts one ephemeral container per verification attempt with --network none,
# a read-only root, dropped capabilities, hard CPU / RAM / pids limits and a
# single writable mount (the per-attempt run directory, itself on a sized
# tmpfs) — backend/app/sandbox/executor.py, tasks/phase4-survey.md §2.
#
# NOTHING of the audited project is installed: a test that needs the project's
# own dependencies cannot run here, and that is a recorded non-goal of v1.0.0
# (`npm install` on a hostile tree executes lifecycle scripts, which is remote
# code execution by design). Every runner below is preinstalled at BUILD time,
# pinned, so the image ships to an air-gapped factory as one artefact.
#
# Licences: pytest MIT, coverage Apache-2.0, mutmut BSD-3, vitest MIT,
# @vitest/coverage-v8 MIT, Stryker Apache-2.0. The mutation tools are the
# plan's (CLAUDE.md → Analysis Tool Source Authority); the test runners and
# the coverage tools are not in that table, which names capabilities of the
# ANALYSIS pipeline — their licences are stated here and verified by
# `scripts/ci.sh`, which runs the licence gate inside this image.

# Same base as docker/analysis.Dockerfile, so the two images share layers.
FROM python:3.13-slim

ARG PYTEST_VERSION=8.4.2
ARG COVERAGE_VERSION=7.10.7
ARG MUTMUT_VERSION=3.8.0
# Exactly pinned, like every tool in docker/analysis.Dockerfile: resolving
# "the latest 22.x" at build time means two builds of the same commit ship
# different artefacts (CLAUDE.md → Hard Rules: every dependency version-pinned).
ARG NODE_VERSION=v22.23.2

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NODE_ENV=production \
    npm_config_update_notifier=false \
    npm_config_fund=false \
    npm_config_audit=false

# procps: Stryker shells out to `ps` to reap its own worker processes, and the
# slim base has no ps at all (`spawn ps ENOENT`).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils procps \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    "pytest==${PYTEST_VERSION}" \
    "coverage[toml]==${COVERAGE_VERSION}" \
    "mutmut==${MUTMUT_VERSION}"

# Node from the official tarball, verified against the release SHASUMS.
RUN set -eux; \
    cd /tmp; \
    curl -fsSLO "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.xz"; \
    curl -fsSLO "https://nodejs.org/dist/${NODE_VERSION}/SHASUMS256.txt"; \
    grep " node-${NODE_VERSION}-linux-x64.tar.xz\$" SHASUMS256.txt | sha256sum -c -; \
    tar -xJf "node-${NODE_VERSION}-linux-x64.tar.xz" -C /usr/local --strip-components=1 \
        --exclude CHANGELOG.md --exclude LICENSE --exclude README.md; \
    rm -rf /tmp/*; \
    node --version; npm --version

# The JS runners live in one fixed place, never in the run directory: the
# audited tree must not be able to shadow them with its own node_modules.
# `npm ci` against the committed lockfile, so the transitive tree is pinned
# too and two builds of this commit produce the same image.
COPY docker/sandbox/package.json docker/sandbox/package-lock.json /opt/dioptra-js/
RUN cd /opt/dioptra-js && npm ci --omit=dev && npm cache clean --force

COPY docker/sandbox/run-python.sh /usr/local/bin/dioptra-run-python
COPY docker/sandbox/run-js.sh /usr/local/bin/dioptra-run-js
RUN chmod 0755 /usr/local/bin/dioptra-run-python /usr/local/bin/dioptra-run-js

# Never root, and no writable home: the executor mounts /run for the attempt
# and gives the process a tmpfs at /tmp.
RUN useradd --system --uid 10001 --no-create-home --home /tmp dioptra \
    && mkdir -p /run/attempt && chown dioptra:dioptra /run/attempt
USER dioptra
WORKDIR /run/attempt

# Sanity check at build time: every runner is installed and answers offline.
# mutmut is asked by metadata, not by `--version`: from 3.8 it loads its
# configuration at import time and refuses to start outside a configured
# project, which is exactly what an empty image is.
RUN pytest --version && coverage --version \
    && python3 -c "import importlib.metadata as m; print('mutmut', m.version('mutmut'))" \
    && node /opt/dioptra-js/node_modules/vitest/vitest.mjs --version \
    && node /opt/dioptra-js/node_modules/@stryker-mutator/core/bin/stryker.js --version
