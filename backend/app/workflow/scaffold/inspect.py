"""Reading the developer's stored test file to see which cases actually have a body.

The E6 gate must answer one question — "did the developer write something for
every approved case?" — WITHOUT executing the file (that is E7's sandbox, and
the file is the developer's, not ours). So the text is parsed with the same
tree-sitter layer the briefs use, and each case is located by its id, which
the scaffold puts at the start of every case name.

What counts as a body: any statement that is not a comment, not the title
string, not ``pass`` / ``...``. A skipped case (``it.skip``) does not count —
a skipped test is not a written test.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from tree_sitter import Node

from app.workflow.ast.extract import parse
from app.workflow.ast.source import language_for
from app.workflow.errors import UnparsableTests
from app.workflow.scaffold import ScaffoldCase

#: ``it("C3 · …")`` / ``def test_c3_…`` — the id opens the case name. The digit
#: run is BOUNDED: an unbounded one reaches ``int()``, and past CPython's
#: 4300-digit limit that raises — inside a gate that promises never to raise.
#: A longer run simply does not match, so the case reads as unwritten.
_JS_CASE_ID = re.compile(r"^\s*C(\d{1,6})\b")
_PY_CASE_ID = re.compile(r"^test_c(\d{1,6})(?:_|$)")

_JS_CASE_CALLEES = frozenset({"it", "test"})
#: Callees that can wrap cases in a suite, and can themselves be skipped.
_JS_SUITE_CALLEES = frozenset({"describe", "suite"})
#: Properties that mean "not run": a skipped case has no body for our purpose.
_JS_SKIPPED = frozenset({"skip", "todo", "skipIf", "runIf", "fails"})
#: A Python decorator naming a skip marks the case as not run. ``skipif`` counts
#: too: a gate decides on what is GUARANTEED to run, so a maybe is a no.
_PY_SKIP_MARKER = "skip"

_PY_EMPTY = frozenset({"pass_statement"})

#: Roots of a call that asserts something. OUR rule, deterministic and
#: deliberately generous: E7 rejects a case with NO assertion at all, it does
#: not judge whether the assertion is a good one — that is what the mutation
#: run measures. Anything narrower would start guessing at intent.
_JS_ASSERT_ROOTS = frozenset({"expect", "expectTypeOf", "assert", "assertType", "chai"})
_PY_ASSERT_CALLS = ("assert", "raises", "warns", "approx", "fail")


@dataclass(frozen=True)
class CaseBody:
    id: str
    present: bool
    statements: int

    @property
    def written(self) -> bool:
        return self.present and self.statements > 0


def _walk(node: Node) -> list[Node]:
    out: list[Node] = []
    stack = [node]
    while stack:
        current = stack.pop()
        out.append(current)
        stack.extend(reversed(current.named_children))
    return out


def _text(node: Node | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", "replace")


def _string_value(node: Node) -> str:
    """The literal's content, quotes stripped — enough to read the leading case id."""
    raw = _text(node)
    if len(raw) >= 2 and raw[0] in "\"'`" and raw[-1] == raw[0]:
        return raw[1:-1]
    return raw


def _is_string_only(statement: Node) -> bool:
    if statement.type != "expression_statement":
        return False
    children = statement.named_children
    return len(children) == 1 and children[0].type in ("string", "template_string")


def _meaningful(block: Node | None) -> int:
    """Statements that are not comments, not the title string, not ``pass``/``...``."""
    if block is None:
        return 0
    count = 0
    for statement in block.named_children:
        if statement.type == "comment":
            continue
        if statement.type in _PY_EMPTY:
            continue
        if _is_string_only(statement):
            # The scaffold's own title line, and any bare string after it.
            continue
        if statement.type == "expression_statement":
            inner = statement.named_children
            if len(inner) == 1 and inner[0].type == "ellipsis":
                continue
        count += 1
    return count


def _py_skipped(node: Node) -> bool:
    """``@pytest.mark.skip`` (or ``skipif``) above the case: it is not written."""
    parent = node.parent
    if parent is None or parent.type != "decorated_definition":
        return False
    return any(
        child.type == "decorator" and _PY_SKIP_MARKER in _text(child)
        for child in parent.named_children
    )


def _python_bodies(root: Node) -> dict[str, int]:
    found: dict[str, int] = {}
    for node in _walk(root):
        if node.type != "function_definition":
            continue
        match = _PY_CASE_ID.match(_text(node.child_by_field_name("name")))
        if match is None or _py_skipped(node):
            continue
        case_id = f"C{int(match.group(1))}"
        found[case_id] = _meaningful(node.child_by_field_name("body"))
    return found


def _js_member(callee: Node | None) -> tuple[str, str] | None:
    """``(object, property)`` of ``it.skip`` / ``describe.only`` and friends."""
    if callee is None or callee.type != "member_expression":
        return None
    obj = callee.child_by_field_name("object")
    if obj is None or obj.type != "identifier":
        return None
    return _text(obj), _text(callee.child_by_field_name("property"))


def _js_skipped_callee(callee: Node | None) -> bool:
    """``it.skip`` on the case, or ``describe.skip`` on the suite around it."""
    member = _js_member(callee)
    if member is None:
        return False
    obj, prop = member
    return obj in (_JS_CASE_CALLEES | _JS_SUITE_CALLEES) and prop in _JS_SKIPPED


def _js_callee_ok(callee: Node | None) -> bool:
    if callee is None:
        return False
    if callee.type == "identifier":
        return _text(callee) in _JS_CASE_CALLEES
    member = _js_member(callee)
    if member is None:
        return False
    obj, prop = member
    return obj in _JS_CASE_CALLEES and prop not in _JS_SKIPPED


def _js_bodies(root: Node) -> dict[str, int]:
    """Walk carrying "am I inside a skipped suite", so ``describe.skip`` counts too."""
    found: dict[str, int] = {}
    stack: list[tuple[Node, bool]] = [(root, False)]
    while stack:
        node, skipped = stack.pop()
        inherited = skipped
        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if _js_skipped_callee(callee):
                inherited = True
            elif not skipped and _js_callee_ok(callee):
                _record_js_case(node, found)
        for child in reversed(node.named_children):
            stack.append((child, inherited))
    return found


def _record_js_case(node: Node, found: dict[str, int]) -> None:
    """``it("C3 · …", () => {…})``: read the id from the title and count the body."""
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return
    args = [child for child in arguments.named_children if child.type != "comment"]
    if len(args) < 2 or args[0].type not in ("string", "template_string"):
        return
    match = _JS_CASE_ID.match(_string_value(args[0]))
    if match is None:
        return
    case_id = f"C{int(match.group(1))}"
    body = args[1].child_by_field_name("body")
    if body is not None and body.type != "statement_block":
        # A concise arrow body (`() => expect(x)`) is one statement.
        found[case_id] = 1
        return
    found[case_id] = _meaningful(body)


def _js_asserts(node: Node) -> bool:
    for descendant in _walk(node):
        if descendant.type != "call_expression":
            continue
        callee = descendant.child_by_field_name("function")
        root = callee
        while root is not None and root.type == "member_expression":
            root = root.child_by_field_name("object")
        if root is not None and root.type == "identifier" and _text(root) in _JS_ASSERT_ROOTS:
            return True
    return False


def _py_asserts(node: Node) -> bool:
    for descendant in _walk(node):
        if descendant.type == "assert_statement":
            return True
        if descendant.type == "call":
            callee = _text(descendant.child_by_field_name("function")).lower()
            if any(name in callee for name in _PY_ASSERT_CALLS):
                return True
    return False


def assertion_free_cases(content: str, path: str, cases: Sequence[ScaffoldCase]) -> list[str]:
    """Ids of the cases whose body asserts nothing at all.

    E7's own rule (docs/workflow-gates.md → E7 re-audit rules, 2): a test that
    runs the code and checks nothing passes for free. Whether the assertion
    PROVES anything is the mutation run's answer, not this one's.
    """
    language = language_for(path)
    root = parse(content.encode("utf-8"), language)
    if root.has_error:
        raise UnparsableTests(path[:200])
    bodies = _python_case_nodes(root) if language == "python" else _js_case_nodes(root)
    asserts = _py_asserts if language == "python" else _js_asserts
    free: list[str] = []
    for case in cases:
        node = bodies.get(case.id)
        if node is not None and not asserts(node):
            free.append(case.id)
    return free


def _python_case_nodes(root: Node) -> dict[str, Node]:
    found: dict[str, Node] = {}
    for node in _walk(root):
        if node.type != "function_definition":
            continue
        match = _PY_CASE_ID.match(_text(node.child_by_field_name("name")))
        if match is None or _py_skipped(node):
            continue
        body = node.child_by_field_name("body")
        if body is not None:
            found[f"C{int(match.group(1))}"] = body
    return found


def _js_case_nodes(root: Node) -> dict[str, Node]:
    found: dict[str, Node] = {}
    stack: list[tuple[Node, bool]] = [(root, False)]
    while stack:
        node, skipped = stack.pop()
        inherited = skipped
        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if _js_skipped_callee(callee):
                inherited = True
            elif not skipped and _js_callee_ok(callee):
                case_id, body = _js_case_node(node)
                if case_id is not None and body is not None:
                    found[case_id] = body
        for child in reversed(node.named_children):
            stack.append((child, inherited))
    return found


def _js_case_node(node: Node) -> tuple[str | None, Node | None]:
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return None, None
    args = [child for child in arguments.named_children if child.type != "comment"]
    if len(args) < 2 or args[0].type not in ("string", "template_string"):
        return None, None
    match = _JS_CASE_ID.match(_string_value(args[0]))
    if match is None:
        return None, None
    return f"C{int(match.group(1))}", args[1]


def inspect_cases(content: str, path: str, cases: Sequence[ScaffoldCase]) -> list[CaseBody]:
    """Per approved case: is it in the file, and does it have a body of its own?"""
    language = language_for(path)
    root = parse(content.encode("utf-8"), language)
    if root.has_error:
        raise UnparsableTests(path[:200])
    found = _python_bodies(root) if language == "python" else _js_bodies(root)
    return [
        CaseBody(id=case.id, present=case.id in found, statements=found.get(case.id, 0))
        for case in cases
    ]
