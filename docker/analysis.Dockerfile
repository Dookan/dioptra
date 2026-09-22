# Analysis image: every tool the pipeline runs, in ONE image.
#
# The worker starts one ephemeral container from this image per tool run, with
# --network none, a read-only root, dropped capabilities and hard CPU / RAM /
# pids limits (backend/app/analysis/runners/executor.py). Nothing here reaches
# the network at runtime: Semgrep runs with --metrics=off against our own rules,
# OSV-Scanner in offline mode against a mounted local database, Syft only
# reads lockfiles. Downloads happen at BUILD time only, pinned and verified
# against the vendors' published checksums — one image to ship to an
# air-gapped factory (tasks/phase1-survey.md §3).
#
# Licences: semgrep LGPL-2.1, lizard MIT, cloc GPL-2.0, gitleaks MIT,
# osv-scanner Apache-2.0, syft Apache-2.0 (CLAUDE.md → Analysis Tool Source Authority).

FROM python:3.13-slim

ARG SEMGREP_VERSION=1.177.0
ARG LIZARD_VERSION=1.17.31
ARG GITLEAKS_VERSION=8.28.0
ARG OSV_SCANNER_VERSION=2.2.4
ARG SYFT_VERSION=1.36.0

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git cloc \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" "lizard==${LIZARD_VERSION}"

# Release binaries, verified against each vendor's checksum file.
RUN set -eux; \
    cd /tmp; \
    curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt"; \
    grep " gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz\$" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" gitleaks; \
    install -m 0755 gitleaks /usr/local/bin/gitleaks; \
    \
    curl -fsSLo osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64"; \
    curl -fsSLo osv-sums "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_SHA256SUMS"; \
    grep " osv-scanner_linux_amd64\$" osv-sums | sed 's/osv-scanner_linux_amd64/osv-scanner/' | sha256sum -c -; \
    install -m 0755 osv-scanner /usr/local/bin/osv-scanner; \
    \
    curl -fsSLO "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz"; \
    curl -fsSLO "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_checksums.txt"; \
    grep " syft_${SYFT_VERSION}_linux_amd64.tar.gz\$" "syft_${SYFT_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "syft_${SYFT_VERSION}_linux_amd64.tar.gz" syft; \
    install -m 0755 syft /usr/local/bin/syft; \
    rm -rf /tmp/*

# Never root inside the analysis container, and no writable home: the executor
# mounts /out for reports and gives the process a tmpfs at /tmp.
RUN useradd --system --uid 10001 --no-create-home --home /tmp dioptra \
    && mkdir -p /work /out && chown dioptra:dioptra /out
USER dioptra
WORKDIR /work

# Sanity check at build time: every tool answers, none needs the network to start.
RUN semgrep --version && lizard --version && cloc --version \
    && gitleaks version && osv-scanner --version && syft version
