"""PHPUnit scaffolds (wave 2, phase 7a): deterministic, assertion-free, safe.

Same two promises the wave-1 scaffolds carry (CLAUDE.md → Hard Rules): the
same approved design always yields the byte-identical file, and the platform
contributes no assertion of any kind. The PHP-specific risk is the string
literal: a case title is the developer's prose and a PHP double-quoted string
INTERPOLATES, so a title holding ``$var`` or ``{$x}`` would become code. The
generator quotes single, which interpolates nothing.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Any

from app.core.clock import utc_now
from app.workflow.models import CaseDesign
from app.workflow.scaffold import build_scaffold, php_class_name
from app.workflow.scaffold.inspect import assertion_free_cases, inspect_cases
from app.workflow.scaffold.text import php_string

ITEMS: list[dict[str, Any]] = [
    {
        "id": "R1",
        "kind": "branch",
        "line": 9,
        "text": "if $cedula === null",
        "detail": "true",
        "values": [],
    },
    {
        "id": "F1",
        "kind": "boundary",
        "line": 14,
        "text": "strlen($limpia) < 6",
        "detail": "<",
        "values": ["5", "6", "7"],
    },
    {
        "id": "M1",
        "kind": "malicious",
        "line": 13,
        "text": "Hallazgo */ <script> $var",
        "detail": "dioptra.sql-injection",
        "values": ["CWE-89"],
    },
]

#: Quotes, a backslash, a block-comment close, and the two things that make a
#: PHP double-quoted string dangerous: a bare variable and a complex expression.
HOSTILE_TITLE = 'Caso "raro" con \\ barra, */ cierre, $inyeccion y {$objeto->metodo()}'


def _design(
    path: str = "app/Support/Documento.php",
    function: str = "validarCedula",
    cases: list[dict[str, Any]] | None = None,
    *,
    approved: bool = True,
) -> CaseDesign:
    design = CaseDesign(
        path=path,
        function=function,
        line=7,
        cases=cases if cases is not None else [{"title": "Cedula vacia", "covers": ["R1", "F1"]}],
        brief={"function": function, "path": path, "items": ITEMS},
        created_by_username="cperez",
    )
    if approved:
        design.approved_at = utc_now()
        design.approved_by_username = "cperez"
    return design


def test_the_scaffold_is_phpunit_and_names_itself_after_its_class() -> None:
    scaffold = build_scaffold(_design())
    assert scaffold.language == "php" and scaffold.runner == "phpunit"
    # PHPUnit resolves a test class by FILE NAME, so the two must agree exactly.
    class_name = scaffold.filename[: -len(".php")]
    # A LITERAL, not `php_class_name(...)` again: comparing the generator
    # against itself passes under any mutation of `studly`/`slug`, which is
    # exactly what the phase-close mutation run showed (x_studly__mutmut_2).
    assert class_name == "DocumentoValidarcedula036203DioptraTest"
    assert class_name == php_class_name("app/Support/Documento.php", "validarCedula", "036203")
    assert class_name.endswith("DioptraTest") and class_name.isidentifier()
    assert f"final class {class_name} extends TestCase" in scaffold.content
    assert scaffold.content.startswith("<?php\n")
    assert "declare(strict_types=1);" in scaffold.content


def test_the_module_under_test_is_required_by_basename() -> None:
    """The sandbox copies it flat beside the test; never the audited layout."""
    scaffold = build_scaffold(_design(path="src/deep/nested/Documento.php"))
    assert scaffold.import_specifier == "Documento.php"
    assert "require_once __DIR__ . '/' . 'Documento.php';" in scaffold.content
    assert "src/deep/nested" not in scaffold.content.replace(
        "// Dioptra · E6 scaffold — validarCedula (src/deep/nested/Documento.php:7)", ""
    )


def test_the_case_id_opens_every_method_name() -> None:
    scaffold = build_scaffold(
        _design(
            cases=[
                {"title": "primero", "covers": ["R1"]},
                {"title": "segundo", "covers": ["F1"]},
            ]
        )
    )
    assert [case.id for case in scaffold.cases] == ["C1", "C2"]
    assert "public function testC1_primero(): void" in scaffold.content
    assert "public function testC2_segundo(): void" in scaffold.content


def test_no_assertion_and_no_data_of_ours_appears() -> None:
    scaffold = build_scaffold(
        _design(cases=[{"title": HOSTILE_TITLE, "covers": ["R1", "F1", "M1"]}])
    )
    code = "\n".join(
        line for line in scaffold.content.splitlines() if not line.lstrip().startswith("//")
    )
    for forbidden in ("assert", "expect", "$this->", "self::", "=="):
        assert forbidden not in code, forbidden
    assert code.count("TODO(developer)") == 0  # the TODO is a comment, not code
    assert "// TODO(developer): write this case." in scaffold.content


def test_a_hostile_title_cannot_become_php_code() -> None:
    scaffold = build_scaffold(_design(cases=[{"title": HOSTILE_TITLE, "covers": ["M1"]}]))
    # The title reaches the file only as a comment and as an identifier slug.
    assert "*/" not in scaffold.content  # block-comment close neutralised
    assert "{$objeto->metodo()}" not in scaffold.content.split("// C1 · ")[0]
    method = next(line for line in scaffold.content.splitlines() if "public function test" in line)
    name = method.strip()
    assert name.startswith("public function testC1_caso_raro_con_barra_cierre") and name.endswith(
        "(): void"
    )
    # Nothing but ASCII identifier characters survived the slug.
    identifier = name[len("public function ") : -len("(): void")]
    assert identifier.replace("_", "").isalnum() and identifier.isascii()
    assert "\n" not in method


def test_a_comment_cannot_leave_php_mode() -> None:
    """``?>`` ends a `//` comment AND php mode; `*/` only closes a block.

    The brief items in the generated comments are lifted from the AUDITED
    source, and `$x === '?> <?php …'` is a legal PHP condition. Found by the
    precommit security panel (2026-09-23), which proved the unescaped form
    passes `php -l` and executes inside the sandbox image.
    """
    from app.workflow.scaffold.text import comment

    payload = '$x === ?> <?php echo "INJECTED"; //'
    assert "?>" not in comment(payload)
    assert "*/" not in comment("tail */ head")
    assert "\n" not in comment("dos\nlineas")


def test_a_hostile_brief_item_reaches_the_file_as_comment_text_only() -> None:
    """The whole path: an audited brief item into a generated `// covers` line."""
    hostile_items: list[dict[str, Any]] = [
        {
            "id": "R1",
            "kind": "branch",
            "line": 3,
            "text": '$x === ?> <?php echo "INJECTED"; //',
            "detail": "true",
            "values": ["?> <?php exit(); //"],
        }
    ]
    design = _design(cases=[{"title": "uno", "covers": ["R1"]}])
    design.brief = {"function": "validarCedula", "items": hostile_items}
    content = build_scaffold(design).content
    # `?>` is the ONLY sequence that leaves PHP mode, so neutralising it is the
    # whole invariant: a `<?php` that survives inside a `//` line is inert text
    # precisely because the comment can no longer be ended.
    assert "?>" not in content
    lines = content.splitlines()
    assert lines[0] == "<?php"
    assert all(line.lstrip().startswith("//") for line in lines[1:] if "<?php" in line), (
        "an audited payload reached a line that is not a comment"
    )


def test_php_string_never_interpolates() -> None:
    """A single-quoted literal is the whole escape surface: backslash and quote."""
    assert php_string("$var {$x} \\n") == "'$var {$x} \\\\n'"
    assert php_string("it's") == "'it\\'s'"
    assert php_string("a\nb") == "'a b'"  # collapsed to one line first


def test_the_scaffold_parses_as_php_and_the_gate_reads_every_case_as_unwritten() -> None:
    """The file we hand the developer is valid PHP, and no case counts as written."""
    scaffold = build_scaffold(
        _design(cases=[{"title": "uno", "covers": ["R1"]}, {"title": "dos", "covers": ["F1"]}])
    )
    bodies = inspect_cases(scaffold.content, "app/Support/Documento.php", scaffold.cases)
    assert [body.id for body in bodies] == ["C1", "C2"]
    assert all(body.present and not body.written for body in bodies)


def test_a_written_case_counts_and_an_empty_one_does_not() -> None:
    scaffold = build_scaffold(
        _design(cases=[{"title": "uno", "covers": ["R1"]}, {"title": "dos", "covers": ["F1"]}])
    )
    written = scaffold.content.replace(
        "        // TODO(developer): write this case.\n    }\n\n    // C2",
        "        $this->assertTrue(validarCedula('12345678', 'V'));\n    }\n\n    // C2",
        1,
    )
    bodies = {b.id: b.written for b in inspect_cases(written, "x.php", scaffold.cases)}
    assert bodies == {"C1": True, "C2": False}


def test_a_case_that_skips_itself_is_not_written() -> None:
    scaffold = build_scaffold(_design(cases=[{"title": "uno", "covers": ["R1"]}]))
    skipped = scaffold.content.replace(
        "        // TODO(developer): write this case.",
        "        $this->markTestSkipped('luego');",
        1,
    )
    body = inspect_cases(skipped, "x.php", scaffold.cases)[0]
    assert not body.present and not body.written


def test_assertion_free_cases_names_the_case_that_checks_nothing() -> None:
    scaffold = build_scaffold(
        _design(cases=[{"title": "uno", "covers": ["R1"]}, {"title": "dos", "covers": ["F1"]}])
    )
    content = scaffold.content.replace(
        "        // TODO(developer): write this case.\n    }\n\n    // C2",
        "        $this->assertSame(1, 1);\n    }\n\n    // C2",
        1,
    ).replace(
        "        // TODO(developer): write this case.\n    }\n}",
        "        $resultado = validarCedula('1', 'V');\n    }\n}",
        1,
    )
    assert assertion_free_cases(content, "x.php", scaffold.cases) == ["C2"]


def test_self_and_static_assertions_count_too() -> None:
    scaffold = build_scaffold(_design(cases=[{"title": "uno", "covers": ["R1"]}]))
    for call in (
        "self::assertTrue(true);",
        "static::assertSame(1, 1);",
        "$this->expectException(\\RuntimeException::class);",
    ):
        content = scaffold.content.replace(
            "        // TODO(developer): write this case.", f"        {call}", 1
        )
        assert assertion_free_cases(content, "x.php", scaffold.cases) == [], call


def test_the_scaffold_is_byte_identical_across_processes() -> None:
    """Determinism must survive a fresh interpreter, not just a second call."""
    script = (
        "import sys, json;"
        "sys.path.insert(0, '.');"
        "from app.core.clock import utc_now;"
        "from app.workflow.models import CaseDesign;"
        "from app.workflow.scaffold import build_scaffold;"
        "items = json.loads(sys.argv[1]);"
        "d = CaseDesign(path='app/Support/Documento.php', function='validarCedula', line=7,"
        " cases=[{'title': sys.argv[2], 'covers': ['R1','F1','M1']}],"
        " brief={'items': items}, created_by_username='cperez');"
        "d.approved_at = utc_now();"
        "s = build_scaffold(d);"
        "print(s.filename); print(s.content)"
    )
    outputs = set()
    for seed in ("1", "4242", "random"):
        result = subprocess.run(  # noqa: S603 — our own interpreter, our own script
            [sys.executable, "-c", script, __import__("json").dumps(ITEMS), HOSTILE_TITLE],
            capture_output=True,
            timeout=60,
            check=False,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        assert result.returncode == 0, result.stderr[-400:]
        outputs.add(result.stdout)
    assert len(outputs) == 1
