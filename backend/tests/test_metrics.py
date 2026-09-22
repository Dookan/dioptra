"""Lizard / cloc parsers and the commented-code scan."""

from __future__ import annotations

from pathlib import Path

from app.analysis.metrics import parse_cloc_json, parse_lizard_csv, scan_commented_code

FIXTURES = Path(__file__).parent / "fixtures"


def test_lizard_rows_are_sorted_by_complexity_and_malformed_rows_are_skipped() -> None:
    rows = parse_lizard_csv((FIXTURES / "lizard.csv").read_text())
    assert [row["function"] for row in rows] == ["handler", "validar", "ping"]
    assert rows[0] == {
        "path": "index.js",
        "function": "handler",
        "line": 30,
        "end_line": 81,
        "nloc": 40,
        "ccn": 12,
        "params": 3,
    }


def test_lizard_tolerates_a_header_row_and_caps_rows() -> None:
    header = "nloc,ccn,token,param,length,location,file,function,long_name,start,end\n"
    row = '1,1,1,0,1,"f@1-1@a.py","a.py","f","f()",1,1\n'
    rows = parse_lizard_csv(header + row * 6000)
    assert len(rows) == 5000
    assert parse_lizard_csv("") == []


def test_cloc_json_drops_the_header_and_keeps_sum() -> None:
    lines = parse_cloc_json((FIXTURES / "cloc.json").read_text())
    assert "header" not in lines
    assert lines["JavaScript"] == {"files": 3, "blank": 40, "comment": 80, "code": 380}
    assert lines["SUM"]["code"] == 400


def test_cloc_garbage_yields_empty() -> None:
    assert parse_cloc_json("not json") == {}
    assert parse_cloc_json("[1, 2]") == {}
    assert parse_cloc_json('{"Go": {"code": true, "nFiles": "3"}}') == {
        "Go": {"files": 0, "blank": 0, "comment": 0, "code": 0}
    }


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_commented_code_scan_lists_offending_files_only(tmp_path: Path) -> None:
    _write(
        tmp_path / "index.js",
        "// const old = require('x');\n// if (a) {\n//   doIt();\n// }\nconst live = 1;\n",
    )
    _write(
        tmp_path / "modulos" / "validacionFormulario.js",
        "// this is prose about the validator\n// another sentence\n// return early;\n",
    )
    _write(tmp_path / "script.py", "# print(x)\n# def old():\n#     return 1;\nx = 1\n")
    _write(tmp_path / "node_modules" / "dep" / "index.js", "// a;\n// b;\n// c;\n")
    _write(tmp_path / "README.md", "// a;\n// b;\n// c;\n")

    assert scan_commented_code(tmp_path) == ["index.js", "script.py"]


def test_commented_code_scan_never_follows_symlinks(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    _write(outside / "leak.js", "// a;\n// b;\n// c;\n")
    root = tmp_path / "src"
    root.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)
    (root / "leak.js").symlink_to(outside / "leak.js")
    _write(root / "real.js", "// a;\n// b;\n// c;\n")

    assert scan_commented_code(root) == ["real.js"]


def test_commented_code_scan_respects_caps(tmp_path: Path) -> None:
    for index in range(5):
        _write(tmp_path / f"{index}.js", "// a;\n// b;\n// c;\n")
    assert len(scan_commented_code(tmp_path, max_files=2)) == 2
    # Only the first bytes are read: the offending lines sit past the cap.
    _write(tmp_path / "big.js", "x = 1;\n" * 100 + "// a;\n// b;\n// c;\n")
    assert "big.js" not in scan_commented_code(tmp_path, max_bytes_per_file=50)


def test_lizard_paths_lose_only_the_tree_root() -> None:
    # In the container Lizard reports /work/…; the audited tree's own `src/`
    # (the MINCYT frontend has one) must survive so E4/E5 can find the file.
    header = "NLOC,CCN,token,PARAM,length,location,file,function,long_name,start,end\n"
    row = (
        '4,2,20,1,6,"edad@3-17@/work/src/helpers/edad.js","/work/src/helpers/edad.js",'
        '"obtenerEdad","obtenerEdad( n )",3,17\n'
    )
    jail = "/var/lib/dioptra/workspaces/p/a/src"
    local = row.replace("/work/", f"{jail}/")
    assert parse_lizard_csv(header + row)[0]["path"] == "src/helpers/edad.js"
    assert parse_lizard_csv(header + local, ("/work", jail))[0]["path"] == "src/helpers/edad.js"
    assert parse_lizard_csv(header + local)[0]["path"] == f"{jail.lstrip('/')}/src/helpers/edad.js"
