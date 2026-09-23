# PHP sandbox image (wave 2, phase 7a): where the DEVELOPER'S PHPUnit tests
# run against the AUDITED code.
#
# ONE IMAGE PER LANGUAGE — `tasks/phase7-survey.md` §7.1, decided by `mmarin`
# 2026-09-23. A PHP runtime and a JDK folded into the single wave-1 image
# would roughly double it for every deployment, including the ones that audit
# no PHP at all; a per-language image also means a broken PHP toolchain cannot
# break a Python verification. `app/sandbox/executor.py::image_for` picks it
# from the scaffold's runner.
#
# Every rule of docker/sandbox.Dockerfile applies here unchanged: the worker
# starts one ephemeral container per attempt with --network none, a read-only
# root, dropped capabilities, hard CPU / RAM / pids limits and a single
# writable mount. NOTHING of the audited project is installed — no
# `composer install`, ever: a hostile composer.json runs `scripts` hooks,
# which is remote code execution by design. A test that needs the project's
# own classes cannot run here, and that is the same recorded non-goal wave 1
# carries (tasks/phase4-survey.md §5).
#
# Licences, all free. Each artefact below is pinned by exact version and
# verified by sha256; the LICENCES are checked by the gate, not by this
# comment: the image writes `/opt/dioptra-php/licenses.json` at build time
# (see the generator step further down) and `scripts/ci.sh` reads it with
# `license_gate.py --php-manifest`. PHP-3.01 and Xdebug-1.03 were added to
# `license_gate.py::ALLOWED_LICENSES` by `mmarin` on 2026-09-23 as a widening
# of the enumeration (CLAUDE.md → Hard Rules), not an exception to it.

FROM php:8.3-cli

# Exactly pinned, like NODE_VERSION in the wave-1 image: resolving "the latest
# 12.x" at build time means two builds of the same commit ship different
# artefacts (CLAUDE.md → Hard Rules: every dependency version-pinned). The
# checksums were taken from the downloaded artefact on 2026-09-23 and are
# verified at build time, so a substituted phar fails the build.
ARG PHPUNIT_VERSION=12.5.35
ARG PHPUNIT_SHA256=2c076d3d30f3bca762b13d996ad665d23220bc29afdb98a40387f7896b324195
ARG INFECTION_VERSION=0.35.4
ARG INFECTION_SHA256=24e9d2ab5fc5613be6b9fea99cfd2c689234d6e6053f339b8f5e05136246070a
ARG XDEBUG_VERSION=3.4.6

ENV PHP_INI_DIR=/usr/local/etc/php \
    COMPOSER_ALLOW_SUPERUSER=0

# Xdebug is the coverage driver, and it has to be: pcov is smaller and much
# faster but measures LINES ONLY. The E4 coverage criterion defaults to 100 %
# DECISIONS and every brief branch item is checked side by side ("a half-taken
# branch covers neither side"), which needs path coverage — and in PHP only
# Xdebug produces it. Measured, not assumed: a pcov build of this image
# produced `total_branches: 0` on a five-case suite (2026-09-23).
#
# Xdebug's debugger is the reason not to want it here, so it is never enabled:
# `xdebug.mode=coverage` alone, with the step debugger, the profiler and the
# remote listener all off, in a container that has no network anyway.
# The build toolchain is removed in the same layer it was installed in.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends $PHPIZE_DEPS ca-certificates curl; \
    pecl install "xdebug-${XDEBUG_VERSION}"; \
    docker-php-ext-enable xdebug; \
    apt-get purge -y --auto-remove $PHPIZE_DEPS; \
    rm -rf /var/lib/apt/lists/* /tmp/pear; \
    php -m | grep -qx xdebug

# The runners live in one fixed place, never in the run directory: the audited
# tree must not be able to shadow them with a vendor/ of its own.
RUN set -eux; \
    mkdir -p /opt/dioptra-php; \
    curl -fsSL -o /opt/dioptra-php/phpunit.phar \
        "https://phar.phpunit.de/phpunit-${PHPUNIT_VERSION}.phar"; \
    echo "${PHPUNIT_SHA256}  /opt/dioptra-php/phpunit.phar" | sha256sum -c -; \
    curl -fsSL -o /opt/dioptra-php/infection.phar \
        "https://github.com/infection/infection/releases/download/${INFECTION_VERSION}/infection.phar"; \
    echo "${INFECTION_SHA256}  /opt/dioptra-php/infection.phar" | sha256sum -c -; \
    chmod 0555 /opt/dioptra-php/*.phar

# Infection resolves the test framework by looking for a `phpunit` executable.
# A shim on PATH is how it finds ours, and it can never be the audited tree's:
# the run directory is not on PATH.
RUN set -eux; \
    printf '#!/bin/sh\nexec php /opt/dioptra-php/phpunit.phar "$@"\n' > /usr/local/bin/phpunit; \
    chmod 0555 /usr/local/bin/phpunit

# Coverage AND NOTHING ELSE. `xdebug.mode=coverage` excludes develop, debug,
# profile, trace and gcstats; `start_with_request=no` means nothing starts a
# session; the client host/port are pinned at loopback so a mode flipped by
# some other means still has nowhere to connect — and the container has no
# network. `xdebug.log` is off: it would write into the shared mount.
RUN printf '%s\n' \
    'xdebug.mode=coverage' \
    'xdebug.start_with_request=no' \
    'xdebug.client_host=127.0.0.1' \
    'xdebug.discover_client_host=0' \
    'xdebug.remote_handler=' \
    'xdebug.max_nesting_level=512' \
    'memory_limit=512M' \
    > "${PHP_INI_DIR}/conf.d/dioptra.ini"

# The things this image installs are phars and a pecl extension: they appear in
# no lockfile of the repository, which is exactly why the wave-1 image is gated
# from the INSIDE. This manifest is what makes that possible here —
# `scripts/license_gate.py --php-manifest` reads it.
#
# It is GENERATED from the artefacts, not written by hand. The first version
# named four top-level entries, while `phpunit.phar` and `infection.phar` each
# embed dozens of components the gate never saw, and a version bump changed no
# licence claim (precommit security auditor, 2026-09-23). Neither phar carries
# a phar.io `manifest.xml` or a composer `installed.json`, so the generator
# walks the per-component LICENSE files they DO carry and classifies each from
# its own text; a text it cannot classify FAILS THE BUILD rather than being
# assumed free. 64 packages at the pinned versions, against 4 before.
COPY docker/sandbox/php-licenses.php /opt/dioptra-php/php-licenses.php
RUN set -eux; \
    php /opt/dioptra-php/php-licenses.php; \
    php -r 'exit(is_array(json_decode(file_get_contents("/opt/dioptra-php/licenses.json"), true)) ? 0 : 1);'; \
    rm /opt/dioptra-php/php-licenses.php

COPY docker/sandbox/php-harness.php /opt/dioptra-php/harness.php
COPY docker/sandbox/run-php.sh /usr/local/bin/dioptra-run-php
RUN chmod 0755 /usr/local/bin/dioptra-run-php && chmod 0444 /opt/dioptra-php/harness.php

# Never root, and no writable home: the executor mounts the attempt directory
# and gives the process a tmpfs at /tmp.
RUN useradd --system --uid 10001 --no-create-home --home /tmp dioptra \
    && mkdir -p /run/attempt && chown dioptra:dioptra /run/attempt
USER dioptra
WORKDIR /run/attempt

# Sanity check at build time: every runner is installed and answers offline.
RUN php --version \
    && php -r 'exit(extension_loaded("xdebug") ? 0 : 1);' \
    && php -r 'exit(ini_get("xdebug.mode") === "coverage" ? 0 : 1);' \
    && php /opt/dioptra-php/phpunit.phar --version \
    && php /opt/dioptra-php/infection.phar --version
