"""The per-attempt run directory: the ONE writable thing the sandbox sees.

The jail stays read-only and untouched — it is the evidence of what was
audited. Everything the sandbox needs is COPIED here: the module under test
(read through the same jailed loader the AST layer uses), the developer's test
file, and OUR runner configuration. The audited project's own configuration is
never copied: `vitest.config.js`, `conftest.py`, `pytest.ini` and
`package.json` can run code at collection time and point a runner anywhere
(tasks/phase4-survey.md §2).

Nothing of the audited project is installed. A test that needs the project's
own dependencies cannot run here, and that is a recorded non-goal of v1.0.0.
"""

from __future__ import annotations

import json
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from app.analysis.models import Analysis
from app.core.config import Settings
from app.workflow.ast.source import load_source
from app.workflow.scaffold import ScaffoldFile
from app.workflow.scaffold.text import js_string

#: Where the attempt directory is mounted inside the container.
RUN_DIR = "/run/attempt"

VITEST_CONFIG = "dioptra.vitest.config.mjs"
PYTEST_CONFIG = "dioptra.pytest.ini"
STRYKER_CONFIG = "dioptra.stryker.json"
MUTMUT_CONFIG = "pyproject.toml"
#: Infection refuses any name but PHPUnit's own ("Could not locate the files
#: phpunit.xml, phpunit.xml.dist, …"), so OURS carries that name. It cannot
#: be confused with the audited tree's: nothing of that tree is ever copied
#: into the attempt directory except the one module under test.
PHPUNIT_CONFIG = "phpunit.xml"
#: A real bootstrap file, and the reason it has to exist: Infection runs
#: every mutant through an include-interceptor bootstrap that requires the
#: project's composer autoloader. Nothing of the audited project is ever
#: installed here (that is the v1.0.0 non-goal), so `vendor/autoload.php`
#: does not exist — and without this file EVERY mutant run died in the
#: bootstrap, PHPUnit errored, and Infection counted all 26 of them as
#: "killed by Test Framework". A suite asserting nothing scored 100 % MSI.
#: That is a fail-OPEN of the same family as the P4 one
#: (`docs/development-phases.md`, 2026-09-22), found before shipping:
#: with this file the same suite scores 1 killed and 25 escaped.
PHPUNIT_BOOTSTRAP = "dioptra.bootstrap.php"
INFECTION_CONFIG = "dioptra.infection.json"

#: Where the runners produce their artefacts INSIDE the container: its own
#: tmpfs, not the shared mount. The wrappers copy the three declared files
#: over as their last action, once every runner process has exited.
CONTAINER_WORK_DIR = "/tmp/dioptra"  # noqa: S108 — the container's own tmpfs

#: The only files read back, each capped and parsed as data.
COVERAGE_FILE = "coverage.json"
JUNIT_FILE = "junit.xml"
MUTATION_FILE = "mutation.json"


@dataclass(frozen=True)
class Attempt:
    """One prepared run directory, with the paths as the container will see them."""

    run_dir: Path
    #: Test file name at the run directory's root.
    test_file: str
    #: Module under test, relative to the run directory (its tree is preserved).
    module_file: str
    language: str
    runner: str


def _module_name(path: str) -> str:
    """The module under test is copied FLAT, at the attempt directory's root.

    Two reasons, and they agree: the scaffold imports it by basename (one
    attempt holds exactly one planned function, so nothing can collide), and
    mutmut refuses outright to mutate a module whose dotted path starts with
    ``src.`` — which is most audited trees.
    """
    return path.rsplit("/", 1)[-1] or "module"


def build_attempt(
    settings: Settings,
    *,
    analysis: Analysis,
    scaffold: ScaffoldFile,
    source_path: str,
    test_content: str,
) -> Attempt:
    """Materialise the run directory. The caller MUST ``discard`` it afterwards."""
    root = settings.sandbox_runs_root / str(analysis.id) / uuid.uuid4().hex[:12]
    root.mkdir(parents=True, exist_ok=False)
    root.chmod(0o770)

    module_file = _module_name(source_path)
    (root / module_file).write_bytes(load_source(analysis, source_path))

    (root / scaffold.filename).write_text(test_content, encoding="utf-8")
    _write_config(root, scaffold, module_file)
    return Attempt(
        run_dir=root,
        test_file=scaffold.filename,
        module_file=module_file,
        language=scaffold.language,
        runner=scaffold.runner,
    )


def _xml_text(value: str) -> str:
    """Escape a value that becomes XML TEXT in the config we write."""
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _write_config(root: Path, scaffold: ScaffoldFile, module_file: str) -> None:
    """OUR configuration, never the audited tree's."""
    if scaffold.runner == "pytest":
        (root / PYTEST_CONFIG).write_text(
            f"[pytest]\naddopts = -p no:cacheprovider\ntestpaths = {scaffold.filename}\n",
            encoding="utf-8",
        )
        # mutmut reads `[tool.mutmut]` from pyproject.toml; it mutates only the
        # module under test and runs only the developer's file.
        (root / MUTMUT_CONFIG).write_text(
            "[tool.mutmut]\n"
            f"source_paths = [{json.dumps(module_file)}]\n"
            f"only_mutate = [{json.dumps(module_file)}]\n"
            f"pytest_add_cli_args_test_selection = [{json.dumps(scaffold.filename)}]\n"
            f"also_copy = [{json.dumps(scaffold.filename)}, {json.dumps(PYTEST_CONFIG)}]\n",
            encoding="utf-8",
        )
        return

    if scaffold.runner == "phpunit":
        # The two file names below are XML TEXT NODES, escaped by `_xml_text`
        # (`&`, `<`, `>` — which is the whole escape surface for a text node).
        # One is the generator's own ASCII class name; the other is the audited
        # path's basename, and that is the only value here the audited tree
        # chooses. An audited basename holding an XML-illegal control character
        # yields a config PHPUnit refuses, i.e. ERRORED — fail-closed.
        (root / PHPUNIT_BOOTSTRAP).write_text(
            "<?php\n"
            "// Dioptra E7. Deliberately empty: nothing of the audited project is\n"
            "// installed, so there is no composer autoloader to load. It exists\n"
            "// so Infection's include interceptor has a real file to attach to;\n"
            "// the developer's test file requires the module under test itself.\n",
            encoding="utf-8",
        )
        (root / PHPUNIT_CONFIG).write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<phpunit "
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            # A REAL bootstrap file, never an empty attribute: an empty one
            # makes PHP try to include the directory and warn on every run,
            # and Infection's include interceptor needs a real file to attach
            # to (see PHPUNIT_BOOTSTRAP above for what that costs if missing).
            f'bootstrap="{PHPUNIT_BOOTSTRAP}" '
            'cacheDirectory="/tmp/dioptra/phpunit-cache" '
            'colors="false" '
            # NO `pathCoverage` here: it is not a valid attribute of <phpunit>
            # (PHPUnit refuses the whole configuration and runs NO tests, which
            # Infection then reports as "tests must be in a passing state" —
            # measured 2026-09-23). It is not needed either: the branch sides
            # the brief is measured by come from Xdebug directly, through
            # docker/sandbox/php-harness.php, not from a PHPUnit report.
            'failOnWarning="false" '
            'failOnRisky="false">\n'
            "  <testsuites>\n"
            '    <testsuite name="dioptra">\n'
            f"      <file>{_xml_text(scaffold.filename)}</file>\n"
            "    </testsuite>\n"
            "  </testsuites>\n"
            "  <source>\n"
            "    <include>\n"
            f"      <file>{_xml_text(module_file)}</file>\n"
            "    </include>\n"
            "  </source>\n"
            "</phpunit>\n",
            encoding="utf-8",
        )
        # Infection mutates ONLY the module under test and never the
        # developer's file; its JSON log lands on the container's own tmpfs,
        # like every other artefact, and the wrapper reshapes it there.
        (root / INFECTION_CONFIG).write_text(
            json.dumps(
                {
                    "source": {
                        "directories": ["."],
                        "excludes": [
                            scaffold.filename,
                            PHPUNIT_CONFIG,
                            INFECTION_CONFIG,
                            PHPUNIT_BOOTSTRAP,
                        ],
                    },
                    "timeout": 20,
                    "testFramework": "phpunit",
                    # Infection builds its own PHPUnit invocation from this
                    # directory and passes `--configuration` itself; passing it
                    # again through `testFrameworkOptions` makes PHPUnit refuse
                    # the run ("Option --configuration cannot be used more than
                    # once"), which Infection then reports as "tests must be in
                    # a passing state". Measured 2026-09-23.
                    "phpUnit": {"configDir": "."},
                    "logs": {"json": f"{CONTAINER_WORK_DIR}/infection.json"},
                    "mutators": {"@default": True},
                    "minMsi": 0,
                    "minCoveredMsi": 0,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return

    (root / VITEST_CONFIG).write_text(
        "export default {\n"
        "  test: {\n"
        f"    include: [{js_string(scaffold.filename)}],\n"
        '    environment: "node",\n'
        "    watch: false,\n"
        "  },\n"
        "};\n",
        encoding="utf-8",
    )
    (root / STRYKER_CONFIG).write_text(
        json.dumps(
            {
                "packageManager": "npm",
                "testRunner": "vitest",
                "vitest": {"configFile": VITEST_CONFIG},
                "mutate": [module_file],
                "reporters": ["json"],
                "jsonReporter": {"fileName": f"{CONTAINER_WORK_DIR}/reports/mutation.json"},
                "coverageAnalysis": "perTest",
                "checkers": [],
                "disableTypeChecks": True,
                "cleanTempDir": True,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def discard(attempt: Attempt) -> None:
    """Remove the run directory. Whatever the tests wrote goes with it."""
    shutil.rmtree(attempt.run_dir, ignore_errors=True)
