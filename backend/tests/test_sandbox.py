"""The E7 sandbox: the flags, the attempt directory, and reading results back.

The analysis containers PARSE hostile code; this one EXECUTES it, so the flags
are the control and they are asserted one by one. The result documents are
written by a process running the audited code — they are parsed as data and
every malformed shape has to come back as "nothing measured", never as an
exception.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from pydantic import SecretStr

from app.analysis.models import Analysis
from app.core.config import Settings
from app.sandbox import executor, results, workspace
from app.workflow.ast.errors import FunctionNotFound, SourceTooLarge
from app.workflow.ast.source import MAX_SOURCE_BYTES
from app.workflow.scaffold import ScaffoldCase, ScaffoldFile

SETTINGS = Settings(
    jwt_secret=SecretStr("x" * 32),
    sandbox_image="dioptra-sandbox:latest",
    sandbox_memory="1g",
    sandbox_cpus="1",
    sandbox_pids_limit=256,
    runner_user="10001:10001",
)


def _scaffold(runner: str = "vitest", language: str = "javascript") -> ScaffoldFile:
    suffix = "js" if runner == "vitest" else "py"
    return ScaffoldFile(
        filename=f"edad.obteneredad.abc123.dioptra.test.{suffix}"
        if runner == "vitest"
        else "test_edad_obtener_edad_abc123_dioptra.py",
        language=language,
        runner=runner,
        import_specifier="./edad.js",
        content="// scaffold\n",
        cases=[ScaffoldCase(id="C1", name="C1 · x", title="x", covers=["R1"])],
    )


def test_every_isolation_flag_is_on_the_command_line() -> None:
    attempt = workspace.Attempt(
        run_dir=Path(tempfile.gettempdir()) / "attempt",
        test_file="t.js",
        module_file="edad.js",
        language="javascript",
        runner="vitest",
    )
    argv = executor.command(SETTINGS, attempt, container_name="dioptra-sandbox-test")
    joined = " ".join(argv)
    for flag in (
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--user 10001:10001",
        "--pids-limit 256",
        "--ulimit fsize=268435456",
        "--tmpfs /tmp:rw,size=256m",
        "--memory 1g",
        "--memory-swap 1g",
        "--name dioptra-sandbox-test",
        "--rm",
    ):
        assert flag in joined, flag
    # The attempt directory is the ONLY mount, and it is the only writable thing.
    mounts = [argv[index + 1] for index, value in enumerate(argv) if value == "-v"]
    assert mounts == [f"{attempt.run_dir}:{workspace.RUN_DIR}:rw"]
    assert "/var/run/docker.sock" not in joined
    # No swap at all: --memory-swap equals --memory.
    assert argv[argv.index("--memory") + 1] == argv[argv.index("--memory-swap") + 1]
    assert argv[-3:] == ["dioptra-run-js", "t.js", "edad.js"]


def test_the_attempt_holds_only_what_we_put_there(tmp_path: Path) -> None:
    """The audited project's own config is never copied: it runs code at collection."""
    jail = tmp_path / "jail"
    (jail / "src").mkdir(parents=True)
    (jail / "src" / "edad.js").write_text("export function obtenerEdad() { return 1; }\n")
    # A hostile tree ships these; they must not reach the run directory.
    (jail / "vitest.config.js").write_text("throw new Error('pwned');\n")
    (jail / "conftest.py").write_text("import os; os.system('id')\n")
    (jail / "package.json").write_text('{"scripts": {"test": "id"}}\n')

    analysis = Analysis(workspace_path=str(jail))
    settings = SETTINGS.model_copy(update={"sandbox_runs_root": tmp_path / "runs"})
    attempt = workspace.build_attempt(
        settings,
        analysis=analysis,
        scaffold=_scaffold(),
        source_path="src/edad.js",
        test_content="it('C1 · x', () => {});\n",
    )
    try:
        names = sorted(path.name for path in attempt.run_dir.iterdir())
        assert names == [
            "dioptra.stryker.json",
            "dioptra.vitest.config.mjs",
            "edad.js",
            attempt.test_file,
        ]
        # Flat: the module sits at the root, which is what the scaffold imports
        # and the only layout mutmut will mutate.
        assert attempt.module_file == "edad.js"
        stryker = json.loads((attempt.run_dir / "dioptra.stryker.json").read_text())
        assert stryker["mutate"] == ["edad.js"]
        assert stryker["vitest"]["configFile"] == "dioptra.vitest.config.mjs"
        # The mutation report is produced on the container's own tmpfs, not in
        # the mount the audited code shares.
        assert stryker["jsonReporter"]["fileName"].startswith(workspace.CONTAINER_WORK_DIR)
    finally:
        workspace.discard(attempt)
    assert not attempt.run_dir.exists()


def test_the_python_attempt_writes_our_own_runner_config(tmp_path: Path) -> None:
    jail = tmp_path / "jail"
    jail.mkdir()
    (jail / "edad.py").write_text("def obtener_edad():\n    return 1\n")
    analysis = Analysis(workspace_path=str(jail))
    settings = SETTINGS.model_copy(update={"sandbox_runs_root": tmp_path / "runs"})
    attempt = workspace.build_attempt(
        settings,
        analysis=analysis,
        scaffold=_scaffold(runner="pytest", language="python"),
        source_path="edad.py",
        test_content="def test_c1_x():\n    assert True\n",
    )
    try:
        ini = (attempt.run_dir / workspace.PYTEST_CONFIG).read_text()
        assert "-p no:cacheprovider" in ini
        toml = (attempt.run_dir / workspace.MUTMUT_CONFIG).read_text()
        assert 'only_mutate = ["edad.py"]' in toml
    finally:
        workspace.discard(attempt)


PY_COVERAGE = json.dumps(
    {
        "files": {
            "edad.py": {
                "executed_lines": [1, 2, 4, 5, 6, 7],
                "missing_lines": [3],
                "executed_branches": [[2, 4], [5, 6], [5, 7]],
                "missing_branches": [[2, 3]],
            }
        }
    }
).encode()

JS_COVERAGE = json.dumps(
    {
        "/run/attempt/edad.js": {
            "statementMap": {
                "0": {"start": {"line": 2}},
                "1": {"start": {"line": 3}},
                "2": {"start": {"line": 5}},
            },
            "s": {"0": 2, "1": 0, "2": 2},
            "branchMap": {"0": {"line": 2}, "1": {"line": 6}},
            "b": {"0": [0, 2], "1": [1, 1]},
        }
    }
).encode()


def test_python_coverage_is_normalised_with_its_branches() -> None:
    coverage = results.parse_coverage(PY_COVERAGE, language="python", module_file="edad.py")
    assert coverage.executed_lines == frozenset({1, 2, 4, 5, 6, 7})
    assert coverage.missing_lines == frozenset({3})
    assert coverage.total_branches == 4 and coverage.covered_branches == 3
    # Line 2's branch has an arm nobody took, so line 2 does NOT cover an item.
    assert coverage.partial_branch_lines == frozenset({2})
    assert coverage.covers_line(2) is False
    assert coverage.covers_line(5) is True
    assert coverage.covers_line(3) is False
    assert coverage.covers_line(None) is False


def test_istanbul_coverage_is_normalised_the_same_way() -> None:
    coverage = results.parse_coverage(JS_COVERAGE, language="javascript", module_file="edad.js")
    assert coverage.executed_lines == frozenset({2, 5})
    assert coverage.missing_lines == frozenset({3})
    assert coverage.partial_branch_lines == frozenset({2})
    assert coverage.total_branches == 4 and coverage.covered_branches == 3
    assert coverage.branch_percent == 75.0


@pytest.mark.parametrize(
    "raw",
    [
        None,
        b"",
        b"not json at all",
        b"[]",
        b'{"files": "not a dict"}',
        b'{"files": {"edad.py": {"executed_lines": "nope", "missing_branches": [[1]]}}}',
        json.dumps({"files": {"edad.py": {}}}).encode(),
        # No file at all: there is nothing to fall back to either.
        json.dumps({"files": {}}).encode(),
        json.dumps({}).encode(),
    ],
)
def test_a_malformed_coverage_document_measures_nothing_and_never_raises(raw: bytes | None) -> None:
    coverage = results.parse_coverage(raw, language="python", module_file="edad.py")
    assert coverage.executed_lines == frozenset()
    assert coverage.covers_line(1) is False


def test_the_mutation_document_is_bounded_and_stringified() -> None:
    raw = json.dumps(
        {
            "tool": "stryker",
            "killed": 3,
            "total": 300,
            "survived": [{"id": i, "line": i, "mutant": "x" * 900} for i in range(400)],
        }
    ).encode()
    mutation = results.parse_mutation(raw)
    assert mutation.tool == "stryker" and mutation.killed == 3 and mutation.total == 300
    assert len(mutation.survived) == results.MAX_SURVIVORS
    assert len(mutation.survived[0]["mutant"]) == 400
    assert mutation.survived[0]["id"] == "0"

    empty = results.parse_mutation(b'{"tool": 7, "killed": "lots", "survived": "nope"}')
    assert empty.survived == [] and empty.killed is None


def test_failed_cases_are_read_from_junit_without_an_xml_parser() -> None:
    junit = b"""<?xml version="1.0"?>
    <testsuites>
      <testsuite name="s">
        <testcase name="C1 &#183; ok" time="0.1"/>
        <testcase name="C2 malo" time="0.1"><failure message="boom">x</failure></testcase>
        <testcase name="C3 error" time="0.1"><error message="boom">x</error></testcase>
      </testsuite>
    </testsuites>"""
    assert results.parse_failed_cases(junit) == ["C2 malo", "C3 error"]
    assert results.parse_failed_cases(None) == []
    assert results.parse_failed_cases(b"<testsuites>") == []


def test_a_coverage_document_keyed_by_another_path_still_measures() -> None:
    """The runner may key the file by an absolute path, or by a different one.

    We ask for the module we copied in; when it is not there by that exact
    name the single file in the document is the one we ran, so measuring it is
    right — and measuring nothing would silently pass the gate.
    """
    renamed = json.dumps(
        {
            "files": {
                "/run/attempt/otro-nombre.py": {
                    "executed_lines": [1, 2],
                    "missing_lines": [],
                    "executed_branches": [],
                    "missing_branches": [],
                }
            }
        }
    ).encode()
    coverage = results.parse_coverage(renamed, language="python", module_file="edad.py")
    assert coverage.executed_lines == frozenset({1, 2})

    istanbul = json.dumps(
        {
            "/some/other/place.js": {
                "statementMap": {"0": {"start": {"line": 9}}},
                "s": {"0": 1},
                "branchMap": {},
                "b": {},
            }
        }
    ).encode()
    assert results.parse_coverage(
        istanbul, language="javascript", module_file="edad.js"
    ).executed_lines == frozenset({9})


def test_the_serialised_shape_is_the_contract_the_screen_reads() -> None:
    """The keys are an API: `frontend/src/api/projects.ts` reads them by name."""
    coverage = results.parse_coverage(PY_COVERAGE, language="python", module_file="edad.py")
    assert set(coverage.as_dict()) == {
        "executed_lines",
        "missing_lines",
        "partial_branch_lines",
        "total_branches",
        "covered_branches",
        "statement_percent",
        "branch_percent",
    }
    assert coverage.as_dict()["statement_percent"] == coverage.statement_percent

    mutation = results.parse_mutation(
        b'{"tool": "mutmut", "killed": 1, "total": 2, "survived": []}'
    )
    assert mutation.as_dict() == {"tool": "mutmut", "killed": 1, "total": 2, "survived": []}


def test_an_empty_module_is_fully_covered_rather_than_zero() -> None:
    """A module with no measurable line must not read as 0 % and fail forever."""
    assert results.EMPTY_COVERAGE.statement_percent == 100.0
    assert results.EMPTY_COVERAGE.branch_percent == 100.0


def test_a_survivor_entry_with_missing_keys_becomes_empty_strings() -> None:
    """The wrapper's document is ours, but the tool's fields may be absent."""
    raw = json.dumps(
        {"tool": "mutmut", "survived": ["not a dict", {}, {"mutant": "x" * 500}]}
    ).encode()
    mutation = results.parse_mutation(raw)
    # The non-dict entry is skipped, not a reason to stop reading the rest.
    assert len(mutation.survived) == 2
    assert mutation.survived[0] == {"id": "", "line": "", "mutant": ""}
    assert len(mutation.survived[1]["mutant"]) == 400


def test_every_survivor_field_is_capped_at_its_own_length() -> None:
    raw = json.dumps(
        {"survived": [{"id": "i" * 300, "line": "l" * 30, "mutant": "m" * 500}]}
    ).encode()
    survivor = results.parse_mutation(raw).survived[0]
    assert (len(survivor["id"]), len(survivor["line"]), len(survivor["mutant"])) == (200, 12, 400)


def test_a_self_closing_testcase_is_not_read_as_a_failure() -> None:
    """`<testcase … />` has no children; the next element's failure is not its own."""
    junit = (
        b'<testsuites><testsuite name="s">'
        b'<testcase name="C1 pasa" time="0.1" />'
        b'<testcase name="C2 falla"><failure message="boom">x</failure></testcase>'
        b"</testsuite></testsuites>"
    )
    assert results.parse_failed_cases(junit) == ["C2 falla"]


def test_junit_that_is_not_utf8_is_read_anyway() -> None:
    """The document comes out of the audited code's own test run."""
    junit = (
        b'<testsuites><testcase name="C1 \xff\xfe roto">'
        b'<failure message="boom">x</failure></testcase></testsuites>'
    )
    assert len(results.parse_failed_cases(junit)) == 1


def test_a_half_shaped_istanbul_document_measures_only_what_it_has() -> None:
    """One of `statementMap`/`s` present without the other measures nothing."""
    statements_only = json.dumps(
        {"edad.js": {"statementMap": {"0": {"start": {"line": 2}}}, "s": "not a dict"}}
    ).encode()
    coverage = results.parse_coverage(statements_only, language="javascript", module_file="edad.js")
    assert coverage.executed_lines == frozenset() and coverage.missing_lines == frozenset()

    branches_only = json.dumps(
        {
            "edad.js": {
                "statementMap": {"0": {"start": {"line": 2}}},
                "s": {"0": 1},
                "branchMap": {"0": {"line": 4}, "1": "not a dict"},
                "b": {"0": [0, 1]},
            }
        }
    ).encode()
    partial = results.parse_coverage(branches_only, language="javascript", module_file="edad.js")
    # The malformed branch is skipped; the well-formed one is still counted.
    assert partial.total_branches == 2 and partial.covered_branches == 1
    assert partial.partial_branch_lines == frozenset({4})


@pytest.mark.parametrize("raw", [b"{}", b'{"files": {}}'])
def test_an_istanbul_document_with_no_file_measures_nothing(raw: bytes) -> None:
    coverage = results.parse_coverage(raw, language="javascript", module_file="edad.js")
    assert coverage.executed_lines == frozenset() and coverage.total_branches == 0


def test_a_branch_without_a_line_of_its_own_falls_back_to_its_location() -> None:
    document = json.dumps(
        {
            "edad.js": {
                "statementMap": {},
                "s": {},
                "branchMap": {"0": {"loc": {"start": {"line": 7}}}},
                "b": {"0": [0, 1]},
            }
        }
    ).encode()
    coverage = results.parse_coverage(document, language="javascript", module_file="edad.js")
    assert coverage.partial_branch_lines == frozenset({7})


def test_the_document_reader_refuses_anything_that_is_not_an_object() -> None:
    for raw in (b"[1, 2]", b'"a string"', b"7", b"null", b"\xff\xfe"):
        assert results.parse_mutation(raw).survived == []


def test_the_module_is_read_through_the_jail_and_never_around_it(tmp_path: Path) -> None:
    """`source_path` comes from tool output: it is hostile-influenced.

    `load_source` is the containment — resolve, `is_relative_to(jail)`, size
    cap. Reading the path directly would work for the happy case and let a
    traversal out, so this is what keeps that call honest.
    """
    jail = tmp_path / "jail"
    jail.mkdir()
    (jail / "edad.py").write_text("def obtener_edad():\n    return 1\n")
    outside = tmp_path / "secreto.py"
    outside.write_text("SECRET = 'no debería salir del jail'\n")

    analysis = Analysis(workspace_path=str(jail))
    settings = SETTINGS.model_copy(update={"sandbox_runs_root": tmp_path / "runs"})
    scaffold = _scaffold(runner="pytest", language="python")

    for escape in ("../secreto.py", "../../etc/passwd", "/etc/passwd"):
        with pytest.raises(FunctionNotFound):
            workspace.build_attempt(
                settings,
                analysis=analysis,
                scaffold=scaffold,
                source_path=escape,
                test_content="def test_c1_x():\n    assert True\n",
            )
    # And nothing was left behind by the attempts that failed.
    runs = settings.sandbox_runs_root
    assert not runs.exists() or not any(path.is_file() for path in runs.rglob("*"))


def test_a_module_over_the_size_cap_is_refused(tmp_path: Path) -> None:
    jail = tmp_path / "jail"
    jail.mkdir()
    (jail / "enorme.py").write_bytes(b"# x\n" * (MAX_SOURCE_BYTES // 2))
    analysis = Analysis(workspace_path=str(jail))
    settings = SETTINGS.model_copy(update={"sandbox_runs_root": tmp_path / "runs"})
    with pytest.raises(SourceTooLarge):
        workspace.build_attempt(
            settings,
            analysis=analysis,
            scaffold=_scaffold(runner="pytest", language="python"),
            source_path="enorme.py",
            test_content="def test_c1_x():\n    assert True\n",
        )


def test_php_coverage_is_read_from_our_own_neutral_shape() -> None:
    """The PHP wrapper emits Dioptra's shape, not a tool's — measured by E7.

    PHPUnit's Clover and Cobertura reports carry no branch data (measured
    2026-09-23), so `docker/sandbox/php-harness.php` reads Xdebug directly and
    writes these fields. The mutation pass at the phase close found this parser
    had NO test at all.
    """
    document = {
        "executed_lines": [5, 6, 9],
        "missing_lines": [11, 13],
        "partial_branch_lines": [5, 9],
        "total_branches": 6,
        "covered_branches": 3,
    }
    coverage = results.parse_coverage(
        json.dumps(document).encode(), language="php", module_file="Documento.php"
    )
    assert coverage.executed_lines == frozenset({5, 6, 9})
    assert coverage.missing_lines == frozenset({11, 13})
    assert coverage.partial_branch_lines == frozenset({5, 9})
    assert (coverage.total_branches, coverage.covered_branches) == (6, 3)
    assert coverage.branch_percent == 50.0
    # A half-taken branch covers NEITHER side, so its line is not covered.
    assert coverage.covers_line(6) is True
    assert coverage.covers_line(5) is False


def test_php_coverage_refuses_to_flatter_a_forged_document() -> None:
    """The wrapper runs in the container the audited code executes in."""
    forged = {
        "executed_lines": [1, 2],
        # A line cannot be both run and missed: the executed set wins, so a
        # planted "missing" cannot deflate the statement percentage.
        "missing_lines": [2, 3],
        "partial_branch_lines": ["nope", 2],
        # More covered than total would read as over 100 %.
        "total_branches": 4,
        "covered_branches": 99,
    }
    coverage = results.parse_coverage(
        json.dumps(forged).encode(), language="php", module_file="x.php"
    )
    assert coverage.missing_lines == frozenset({3})
    assert coverage.covered_branches == 4 and coverage.branch_percent == 100.0
    assert coverage.partial_branch_lines == frozenset({2})


def test_php_coverage_of_a_half_shaped_document_measures_nothing() -> None:
    """Wrong types measure nothing rather than raising; absence is ERRORED upstream."""
    for raw in (b"", b"not json", b"[]", b'{"total_branches": "many"}'):
        coverage = results.parse_coverage(raw, language="php", module_file="x.php")
        assert coverage.total_branches == 0
        assert coverage.executed_lines == frozenset()
