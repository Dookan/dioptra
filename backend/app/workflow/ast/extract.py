"""tree-sitter → FlowGraph, for JavaScript / TypeScript / Python (wave 1)
and PHP (wave 2, phase 7a).

One builder, one profile per language: the profile names the node types
that matter (functions, blocks, decisions, loops, exits) and the builder
walks the function body statement by statement. Everything else in the body
is a plain statement and collapses into a process box with its neighbours.

Limits (the source is hostile): nesting depth, and syntax errors inside the
function are a refusal rather than a guessed graph.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from tree_sitter import Language, Node, Parser

from app.workflow.ast.errors import AstError, FunctionNotFound, ParseFailed, TooDeep
from app.workflow.ast.graph import Comparison, FlowEdge, FlowGraph, FlowNode, clip

MAX_DEPTH = 40
MAX_NODES = 400


@dataclass(frozen=True)
class Profile:
    function_types: frozenset[str]
    #: Declarations whose body holds methods. Used to tell a METHOD from a free
    #: function, which E7 needs: Infection mutates only code inside a class
    #: (tasks/phase7a-php.md), so a free PHP function can never be measured.
    class_types: frozenset[str]
    #: Declarators whose value is an anonymous function (``const f = () => …``).
    declarator_types: frozenset[str]
    anonymous_function_types: frozenset[str]
    block_types: frozenset[str]
    if_types: frozenset[str]
    #: Chained alternatives that are a named child of the ``if`` and carry
    #: their own condition (Python ``elif_clause``, PHP ``else_if_clause``).
    #: JavaScript has none — it nests an ``if`` inside its ``else_clause``.
    elif_types: frozenset[str]
    else_types: frozenset[str]
    loop_types: frozenset[str]
    switch_types: frozenset[str]
    case_types: frozenset[str]
    default_case_types: frozenset[str]
    try_types: frozenset[str]
    handler_types: frozenset[str]
    finally_types: frozenset[str]
    #: Compound statements whose body simply continues the flow (with, labeled…).
    transparent_types: frozenset[str]
    #: Thin statement wrappers around a single expression. PHP 8 made ``throw``
    #: an EXPRESSION, so a bare ``throw`` reaches the walker wrapped in an
    #: ``expression_statement``; unwrapping is what keeps it a throw node
    #: instead of a process box. Empty where the language has no such wrapper.
    unwrap_types: frozenset[str]
    return_types: frozenset[str]
    throw_types: frozenset[str]
    #: Counted for cyclomatic complexity beyond the structural ones above.
    expression_decision_types: frozenset[str]
    boolean_operator_tokens: frozenset[str]
    #: Node types that hold the boolean operators (JS: binary_expression).
    boolean_expression_types: frozenset[str]
    #: Node types that hold a comparison (JS: binary_expression; Python: comparison_operator).
    comparison_types: frozenset[str]
    #: Literal node types whose text is a number.
    number_types: frozenset[str]
    string_types: frozenset[str]


PYTHON = Profile(
    function_types=frozenset({"function_definition"}),
    class_types=frozenset({"class_definition"}),
    declarator_types=frozenset(),
    anonymous_function_types=frozenset({"lambda"}),
    block_types=frozenset({"block"}),
    if_types=frozenset({"if_statement", "elif_clause"}),
    elif_types=frozenset({"elif_clause"}),
    else_types=frozenset({"else_clause"}),
    loop_types=frozenset({"for_statement", "while_statement"}),
    switch_types=frozenset({"match_statement"}),
    case_types=frozenset({"case_clause"}),
    default_case_types=frozenset(),
    try_types=frozenset({"try_statement"}),
    handler_types=frozenset({"except_clause", "except_group_clause"}),
    finally_types=frozenset({"finally_clause"}),
    transparent_types=frozenset({"with_statement"}),
    unwrap_types=frozenset(),
    return_types=frozenset({"return_statement"}),
    throw_types=frozenset({"raise_statement"}),
    expression_decision_types=frozenset({"conditional_expression"}),
    boolean_operator_tokens=frozenset({"and", "or"}),
    boolean_expression_types=frozenset({"boolean_operator"}),
    comparison_types=frozenset({"comparison_operator"}),
    number_types=frozenset({"integer", "float"}),
    string_types=frozenset({"string"}),
)

JAVASCRIPT = Profile(
    function_types=frozenset(
        {"function_declaration", "generator_function_declaration", "method_definition"}
    ),
    class_types=frozenset({"class_declaration", "class"}),
    declarator_types=frozenset({"variable_declarator", "public_field_definition", "pair"}),
    anonymous_function_types=frozenset(
        {"arrow_function", "function_expression", "function", "generator_function"}
    ),
    block_types=frozenset({"statement_block"}),
    if_types=frozenset({"if_statement"}),
    elif_types=frozenset(),
    else_types=frozenset({"else_clause"}),
    loop_types=frozenset({"for_statement", "for_in_statement", "while_statement", "do_statement"}),
    switch_types=frozenset({"switch_statement"}),
    case_types=frozenset({"switch_case"}),
    default_case_types=frozenset({"switch_default"}),
    try_types=frozenset({"try_statement"}),
    handler_types=frozenset({"catch_clause"}),
    finally_types=frozenset({"finally_clause"}),
    transparent_types=frozenset({"labeled_statement", "with_statement"}),
    unwrap_types=frozenset(),
    return_types=frozenset({"return_statement"}),
    throw_types=frozenset({"throw_statement"}),
    expression_decision_types=frozenset({"ternary_expression"}),
    boolean_operator_tokens=frozenset({"&&", "||", "??"}),
    boolean_expression_types=frozenset({"binary_expression"}),
    comparison_types=frozenset({"binary_expression"}),
    number_types=frozenset({"number"}),
    string_types=frozenset({"string", "template_string"}),
)

# PHP (wave 2, phase 7a). Node types confirmed against the INSTALLED grammar
# (tree-sitter-php 0.24.1), not from memory — tasks/phase7-survey.md §3.1.
# Three shapes have no wave-1 analogue and are handled by the generalisations
# below rather than by special cases in the walker:
#   - `throw` is an EXPRESSION since PHP 8 → `unwrap_types`;
#   - `elseif` is a chained clause with its own condition → `elif_types`;
#   - the if/while/foreach body field is `body`, not `consequence`.
# `match` is deliberately NOT a switch here: it is an expression, so it never
# reaches the statement walker. Its arms still COUNT (they are in `case_types`,
# so each one adds a basis path and raises `min_cases`) but they are not drawn
# as branches and the brief does not name them — the same treatment a `try`'s
# success edge already gets (docs/workflow-gates.md → Test brief).
PHP = Profile(
    function_types=frozenset({"function_definition", "method_declaration"}),
    class_types=frozenset(
        {"class_declaration", "trait_declaration", "interface_declaration", "enum_declaration"}
    ),
    # `$f = function () {…}` is an assignment_expression with left/right
    # fields, not name/value, so a closure bound to a variable is not a NAMED
    # function here. E4 plans functions Lizard measured by name, so this costs
    # nothing today; revisit if a factory project plans closures.
    declarator_types=frozenset(),
    anonymous_function_types=frozenset({"anonymous_function", "arrow_function"}),
    block_types=frozenset({"compound_statement"}),
    if_types=frozenset({"if_statement", "else_if_clause"}),
    elif_types=frozenset({"else_if_clause"}),
    else_types=frozenset({"else_clause"}),
    loop_types=frozenset({"for_statement", "foreach_statement", "while_statement", "do_statement"}),
    switch_types=frozenset({"switch_statement"}),
    case_types=frozenset({"case_statement", "match_conditional_expression"}),
    default_case_types=frozenset({"default_statement"}),
    try_types=frozenset({"try_statement"}),
    handler_types=frozenset({"catch_clause"}),
    finally_types=frozenset({"finally_clause"}),
    transparent_types=frozenset(),
    unwrap_types=frozenset({"expression_statement"}),
    return_types=frozenset({"return_statement"}),
    throw_types=frozenset({"throw_expression"}),
    expression_decision_types=frozenset({"conditional_expression"}),
    # `and` / `or` / `xor` are the low-precedence spellings of && / || .
    boolean_operator_tokens=frozenset({"&&", "||", "??", "and", "or", "xor"}),
    boolean_expression_types=frozenset({"binary_expression"}),
    comparison_types=frozenset({"binary_expression"}),
    number_types=frozenset({"integer", "float"}),
    string_types=frozenset({"string", "encapsed_string"}),
)


PROFILES: dict[str, Profile] = {
    "python": PYTHON,
    "javascript": JAVASCRIPT,
    "typescript": JAVASCRIPT,
    "tsx": JAVASCRIPT,
    "php": PHP,
}


@lru_cache(maxsize=8)
def _language(name: str) -> Language:
    # Imported lazily: the grammars are compiled extensions, loaded once.
    if name == "python":
        import tree_sitter_python as grammar  # noqa: PLC0415

        return Language(grammar.language())
    if name == "javascript":
        import tree_sitter_javascript as grammar_js  # noqa: PLC0415

        return Language(grammar_js.language())
    if name == "php":
        import tree_sitter_php as grammar_php  # noqa: PLC0415

        # `language_php` parses a full file (with the `<?php` tag); the
        # `_only` variant assumes the tag was already consumed, which an
        # audited file never is.
        return Language(grammar_php.language_php())
    import tree_sitter_typescript as grammar_ts  # noqa: PLC0415

    if name == "tsx":
        return Language(grammar_ts.language_tsx())
    return Language(grammar_ts.language_typescript())


def parse(source: bytes, language: str) -> Node:
    parser = Parser(_language(language))
    return parser.parse(source).root_node


def _text(node: Node | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", errors="replace")


def _bare_name(name: str) -> str:
    """Lizard reports methods as ``Class::method`` / ``Class.method``; keep the last segment."""
    for separator in ("::", "."):
        if separator in name:
            name = name.rsplit(separator, 1)[1]
    return name.strip()


def _named_function(node: Node, profile: Profile) -> tuple[str, Node] | None:
    """(name, function node) when ``node`` defines a function with a name."""
    if node.type in profile.function_types:
        return _text(node.child_by_field_name("name")), node
    if node.type in profile.declarator_types:
        value = node.child_by_field_name("value")
        if value is not None and value.type in profile.anonymous_function_types:
            name_node = node.child_by_field_name("name") or node.child_by_field_name("key")
            return _text(name_node), value
    return None


def find_function(root: Node, name: str, line: int | None, profile: Profile) -> Node:
    """The function called ``name`` closest to ``line`` (1-based), or FunctionNotFound."""
    wanted = _bare_name(name)
    candidates: list[tuple[int, Node]] = []
    stack = [root]
    while stack:
        node = stack.pop()
        found = _named_function(node, profile)
        if found is not None and _bare_name(found[0]) == wanted:
            start = node.start_point.row + 1
            distance = 0 if line is None else abs(start - line)
            candidates.append((distance, found[1]))
        stack.extend(reversed(node.children))
    if not candidates:
        raise FunctionNotFound(wanted[:200])
    candidates.sort(key=lambda item: (item[0], item[1].start_byte))
    return candidates[0][1]


def declared_in_class(source: bytes, language: str, name: str, line: int | None) -> bool:
    """Is the named function declared INSIDE a class (a method), or free?

    Answered from the source, never from an empty result: E7 has to know
    BEFORE it scores a run whether the mutation tool could have produced
    anything at all, so that "no mutants" is read as "not measurable here"
    rather than as "nothing survived" (tasks/phase7a-php.md → the `mmarin`
    decision of 2026-09-23).

    **Which side is conservative, and why it is True.** The caller excuses the
    mutation question when this answers False, so False is the PERMISSIVE
    side: a run with no mutants may then pass. Anything we could not resolve —
    the function is not in the source under that name, the language has no
    profile — therefore answers **True**, and the run is scored on mutation
    like any other (zero mutants from a measurable function is `ERRORED`).
    The earlier version of this function returned False here and said in this
    same docstring that False was the conservative side; both the precommit
    security auditor and the invariant checker caught it, 2026-09-23.
    """
    profile = PROFILES.get(language)
    if profile is None:
        return True
    try:
        function = find_function(parse(source, language), name, line, profile)
    except FunctionNotFound:
        return True
    parent = function.parent
    while parent is not None:
        if parent.type in profile.class_types:
            return True
        parent = parent.parent
    return False


def function_span(
    source: bytes, language: str, name: str, line: int | None
) -> tuple[int, int] | None:
    """The 1-indexed first and last line of the named function, or ``None``.

    E7 applies the E4 coverage criterion to these lines rather than to the
    whole file. Measured on the phase-7a walk: a module with three functions
    where E4 planned ONE could never satisfy "no missing line", because the
    other two are never executed by a test written for the first — the gate
    was unreachable by construction on any multi-function file.

    ``None`` means "could not resolve", and the caller then keeps the whole
    module, which is the STRICTER side: an unresolvable function must not
    silently widen what counts as covered.
    """
    profile = PROFILES.get(language)
    if profile is None:
        return None
    try:
        root = parse(source, language)
        function = find_function(root, name, line, profile)
    except (FunctionNotFound, AstError):
        return None
    # An AMBIGUOUS resolution must land on the strict side too, not just an
    # impossible one. `find_function` ranks by distance to ``line`` and, with no
    # line, every same-named declaration ties at 0 and the FIRST one by position
    # wins. An audited file that declares a trivial `obtener()` above the real
    # one would then shrink the criterion to that stub's single line — which
    # `statements` satisfies unconditionally. Found by the precommit security
    # auditor on this very change, 2026-09-23: before it, the criterion was the
    # one E7 question whose answer did not depend on picking the right node.
    if line is None and _same_named_count(root, name, profile) > 1:
        return None
    return function.start_point.row + 1, function.end_point.row + 1


def _same_named_count(root: Node, name: str, profile: Profile) -> int:
    wanted = _bare_name(name)
    count = 0
    stack = [root]
    while stack:
        node = stack.pop()
        found = _named_function(node, profile)
        if found is not None and _bare_name(found[0]) == wanted:
            count += 1
        stack.extend(node.children)
    return count


def _has_error(node: Node) -> bool:
    return node.has_error


def _params(function: Node) -> list[str]:
    params = function.child_by_field_name("parameters") or function.child_by_field_name("parameter")
    if params is None:
        return []
    if params.is_named and not params.children:
        return [clip(_text(params))]
    return [clip(_text(child)) for child in params.named_children if child.type != "comment"]


#: The keyword each grammar spells the chained alternative with. Read from
#: the node instead of mapped per language, so the diagram says what the
#: source says (`elseif` in PHP, `elif` in Python).
_IF_KEYWORDS = frozenset({"if", "elif", "elseif"})


def _if_keyword(node: Node) -> str:
    for child in node.children:
        if not child.is_named and child.type in _IF_KEYWORDS:
            return child.type
    return "if"


def _statements(node: Node | None, profile: Profile) -> list[Node]:
    """The statements of a body: a block's named children, or the single statement itself."""
    if node is None:
        return []
    if node.type in profile.block_types:
        return [child for child in node.named_children if child.type != "comment"]
    return [node]


class _Builder:
    def __init__(self, profile: Profile, language: str) -> None:
        self.profile = profile
        self.language = language
        self.nodes: list[FlowNode] = []
        self.edges: list[FlowEdge] = []
        self.terminals: list[str] = []
        self.depth = 0

    def _add(self, kind: str, label: str, line: int | None) -> str:
        if len(self.nodes) >= MAX_NODES:
            raise TooDeep(f"more than {MAX_NODES} nodes")
        node_id = f"n{len(self.nodes)}"
        self.nodes.append(FlowNode(id=node_id, kind=kind, label=label, line=line))
        return node_id

    def _connect(self, pending: list[tuple[str, str]], target: str) -> None:
        for source, label in pending:
            self.edges.append(FlowEdge(source=source, target=target, label=label))

    def block(
        self, statements: list[Node], pending: list[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise TooDeep(f"nesting deeper than {MAX_DEPTH}")
        try:
            buffer: list[Node] = []
            for statement in statements:
                statement = self._unwrap(statement)
                if self._is_compound(statement):
                    pending = self._flush(buffer, pending)
                    buffer = []
                    pending = self.compound(statement, pending)
                else:
                    buffer.append(statement)
            return self._flush(buffer, pending)
        finally:
            self.depth -= 1

    def _unwrap(self, node: Node) -> Node:
        """A thin statement wrapper around a compound expression, or ``node``.

        PHP 8 turned ``throw`` into an expression, so ``throw new X();`` is an
        ``expression_statement`` holding a ``throw_expression``. Unwrapping
        only when the single child IS compound keeps every ordinary
        expression statement (an assignment, a call) a plain process box.
        """
        if node.type not in self.profile.unwrap_types:
            return node
        children = [child for child in node.named_children if child.type != "comment"]
        if len(children) == 1 and self._is_compound(children[0]):
            return children[0]
        return node

    def _is_compound(self, node: Node) -> bool:
        profile = self.profile
        return node.type in (
            profile.if_types
            | profile.loop_types
            | profile.switch_types
            | profile.try_types
            | profile.transparent_types
            | profile.return_types
            | profile.throw_types
        )

    def _flush(self, buffer: list[Node], pending: list[tuple[str, str]]) -> list[tuple[str, str]]:
        if not buffer:
            return pending
        first = buffer[0]
        label = clip(_text(first).splitlines()[0] if _text(first) else first.type)
        if len(buffer) > 1:
            label = clip(f"{label} …")
        node_id = self._add("process", label, first.start_point.row + 1)
        self._connect(pending, node_id)
        return [(node_id, "")]

    def compound(self, node: Node, pending: list[tuple[str, str]]) -> list[tuple[str, str]]:
        profile = self.profile
        line = node.start_point.row + 1
        if node.type in profile.return_types:
            node_id = self._add("return", clip(_text(node)), line)
            self._connect(pending, node_id)
            self.terminals.append(node_id)
            return []
        if node.type in profile.throw_types:
            node_id = self._add("throw", clip(_text(node)), line)
            self._connect(pending, node_id)
            self.terminals.append(node_id)
            return []
        if node.type in profile.if_types:
            return self._if(node, pending)
        if node.type in profile.loop_types:
            return self._loop(node, pending)
        if node.type in profile.switch_types:
            return self._switch(node, pending)
        if node.type in profile.try_types:
            return self._try(node, pending)
        # transparent: with / labeled — the body continues the flow
        body = node.child_by_field_name("body")
        return self.block(_statements(body, profile), pending)

    def _condition_label(self, node: Node, keyword: str) -> str:
        condition = node.child_by_field_name("condition")
        text = _text(condition).strip("()") if condition is not None else ""
        return clip(f"{keyword} {text}".strip())

    def _if(self, node: Node, pending: list[tuple[str, str]]) -> list[tuple[str, str]]:
        profile = self.profile
        decision = self._add(
            "decision",
            self._condition_label(node, _if_keyword(node)),
            node.start_point.row + 1,
        )
        self._connect(pending, decision)
        # Python and JS name the taken branch `consequence`; PHP names it
        # `body`, like every other compound statement in that grammar.
        consequence = node.child_by_field_name("consequence") or node.child_by_field_name("body")
        exits = self.block(_statements(consequence, profile), [(decision, "true")])
        false_pending: list[tuple[str, str]] = [(decision, "false")]
        # Python / PHP: elif_clause / else_if_clause and else_clause are named
        # children of the if. JS: one else_clause whose child is a block or
        # another if_statement.
        for child in node.named_children:
            if child.type in profile.elif_types:
                false_pending = self._if(child, false_pending)
            elif child.type in profile.else_types:
                body = child.child_by_field_name("body")
                if body is None and child.named_children:
                    body = child.named_children[-1]
                if body is not None and body.type in profile.if_types:
                    false_pending = self._if(body, false_pending)
                else:
                    false_pending = self.block(_statements(body, profile), false_pending)
        return exits + false_pending

    def _loop(self, node: Node, pending: list[tuple[str, str]]) -> list[tuple[str, str]]:
        profile = self.profile
        keyword = node.type.split("_", 1)[0]
        header = _text(node).splitlines()[0] if _text(node) else keyword
        if "{" in header:
            header = header.split("{", 1)[0]
        if header.rstrip().endswith(":"):
            header = header.rstrip()[:-1]
        loop = self._add("loop", clip(header), node.start_point.row + 1)
        self._connect(pending, loop)
        body = node.child_by_field_name("body")
        exits = self.block(_statements(body, profile), [(loop, "true")])
        # A branch that ends the body keeps its own label (the brief lists
        # that decision's false side); a plain statement's edge is "loop".
        for source, label in exits:
            self.edges.append(FlowEdge(source=source, target=loop, label=label or "loop"))
        return [(loop, "false")]

    def _switch(self, node: Node, pending: list[tuple[str, str]]) -> list[tuple[str, str]]:
        profile = self.profile
        subject = (
            node.child_by_field_name("value")
            or node.child_by_field_name("subject")
            or node.child_by_field_name("condition")
        )
        keyword = "match" if node.type == "match_statement" else "switch"
        decision = self._add(
            "decision", clip(f"{keyword} {_text(subject)}"), node.start_point.row + 1
        )
        self._connect(pending, decision)
        body = node.child_by_field_name("body")
        exits: list[tuple[str, str]] = []
        has_default = False
        for case in body.named_children if body is not None else []:
            if case.type in profile.case_types or case.type in profile.default_case_types:
                is_default = case.type in profile.default_case_types
                has_default = has_default or is_default
                if case.type == "case_clause" and case.named_children:
                    # Python: `case _:` is the wildcard, i.e. the default branch.
                    is_default = _text(case.named_children[0]).strip() in {"_", "case _"}
                    has_default = has_default or is_default
                if is_default and case.type != "case_clause":
                    label = "default"
                    statements = list(case.named_children)
                else:
                    label = clip(
                        "case " + _text(case.named_children[0]) if case.named_children else "case"
                    )
                    statements = list(case.named_children[1:])
                if case.type == "case_clause":  # python: consequence is a block
                    statements = _statements(case.child_by_field_name("consequence"), profile)
                exits += self.block(statements, [(decision, label)])
        if not has_default:
            exits.append((decision, "default"))
        return exits

    def _try(self, node: Node, pending: list[tuple[str, str]]) -> list[tuple[str, str]]:
        profile = self.profile
        marker = self._add("decision", "try", node.start_point.row + 1)
        self._connect(pending, marker)
        body = node.child_by_field_name("body")
        exits = self.block(_statements(body, profile), [(marker, "")])
        for child in node.named_children:
            if child.type in profile.handler_types:
                header = _text(child).splitlines()[0]
                if "{" in header:
                    header = header.split("{", 1)[0]
                if header.rstrip().endswith(":"):
                    header = header.rstrip()[:-1]
                handler_body = child.child_by_field_name("body")
                if handler_body is None:
                    blocks = [c for c in child.named_children if c.type in profile.block_types]
                    handler_body = blocks[-1] if blocks else None
                handler = self._add("process", clip(header), child.start_point.row + 1)
                self.edges.append(FlowEdge(source=marker, target=handler, label="except"))
                exits += self.block(_statements(handler_body, profile), [(handler, "")])
        for child in node.named_children:
            if child.type in profile.finally_types:
                finally_body = child.child_by_field_name("body")
                if finally_body is None:
                    blocks = [c for c in child.named_children if c.type in profile.block_types]
                    finally_body = blocks[-1] if blocks else None
                exits = self.block(_statements(finally_body, profile), exits)
        return exits


def complexity(function: Node, profile: Profile) -> int:
    """Cyclomatic complexity: 1 + decisions, nested functions excluded.

    Decisions: if / elif / else-if, loops, switch or match cases, except or
    catch handlers, ternaries, boolean operators. This is OUR count, the one
    the E5 brief derives the minimum case count from; Lizard's ``ccn`` in the
    E4 ranking differs on a few constructs (it adds ``finally`` and
    comprehension clauses, ignores ``match``, splits ``??``). Do not expect
    the two numbers to agree — the plan ranks, the brief counts paths.
    """
    count = 1
    stack = list(function.named_children)
    while stack:
        node = stack.pop()
        if node.type in profile.function_types | profile.anonymous_function_types:
            continue
        if node.type in (
            profile.if_types
            | profile.loop_types
            | profile.case_types
            | profile.handler_types
            | profile.expression_decision_types
        ):
            count += 1
        elif node.type in profile.boolean_expression_types:
            count += sum(
                1
                for child in node.children
                if not child.is_named and child.type in profile.boolean_operator_tokens
            ) or (1 if node.type == "boolean_operator" else 0)
        stack.extend(node.named_children)
    return count


#: `<>` is PHP's spelling of `!=`; no wave-1 grammar produces it.
COMPARISON_OPERATORS = frozenset({"<", "<=", ">", ">=", "==", "!=", "===", "!==", "<>"})


def _literal(node: Node, profile: Profile) -> int | float | str | None:
    """The literal value of ``node`` when it is a number or a string; None otherwise."""
    if node.type in ("parenthesized_expression",) and node.named_children:
        return _literal(node.named_children[0], profile)
    if node.type in profile.number_types:
        return _number(_text(node))
    # PHP spells it `unary_op_expression`; JS/Python `unary_expression`.
    if node.type in ("unary_expression", "unary_op_expression") and node.named_children:
        # `-1` parses as unary minus over the literal.
        operator = next((c for c in node.children if not c.is_named), None)
        inner = _number(_text(node.named_children[0]))
        if operator is not None and operator.type == "-" and inner is not None:
            return -inner
        return None
    if node.type in profile.string_types:
        # A string with anything but literal content is not a boundary value.
        # PHP's `encapsed_string` holds the interpolated variable directly as a
        # child; JS/Python wrap it in a substitution node.
        if any(
            child.type in ("interpolation", "template_substitution", "variable_name")
            for child in node.children
        ):
            return None
        return _string_body(_text(node))
    return None


#: Longer literals carry no boundary worth testing, and `int(text, 16)` is exempt
#: from Python's 4300-digit conversion limit while `str(value)` is not.
MAX_NUMBER_CHARS = 40


def _number(text: str) -> int | float | None:
    flat = text.replace("_", "").strip().lower()
    if len(flat) > MAX_NUMBER_CHARS:
        return None
    for prefix, base in (("0x", 16), ("0o", 8), ("0b", 2)):
        if flat.startswith(prefix):
            try:
                return int(flat[2:], base)
            except ValueError:
                return None
    if flat.endswith("n"):  # JS BigInt
        flat = flat[:-1]
    if flat.endswith("j"):  # Python complex: no boundary makes sense
        return None
    try:
        if "." in flat or "e" in flat:
            value = float(flat)
            return value if value == value and abs(value) != float("inf") else None
        return int(flat)
    except ValueError:
        return None


def _string_body(text: str) -> str:
    stripped = text.strip()
    for prefix in ("f", "r", "b", "u", "rb", "br", "fr", "rf"):
        if stripped.lower().startswith(prefix) and len(stripped) > len(prefix):
            candidate = stripped[len(prefix) :]
            if candidate[:1] in "\"'`":
                stripped = candidate
                break
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in "\"'`":
        return stripped[1:-1]
    return stripped


def _comparisons_of(node: Node, profile: Profile) -> list[Comparison]:
    """Comparisons inside one comparison node (Python chains: ``0 < x < 10`` gives two)."""
    found: list[Comparison] = []
    children = list(node.children)
    for index, child in enumerate(children):
        if child.is_named or child.type not in COMPARISON_OPERATORS:
            continue
        if index == 0 or index == len(children) - 1:
            continue
        left, right = children[index - 1], children[index + 1]
        for operand in (right, left):
            literal = _literal(operand, profile)
            if literal is not None:
                found.append(
                    Comparison(
                        line=node.start_point.row + 1,
                        text=clip(f"{_text(left)} {child.type} {_text(right)}"),
                        operator=child.type,
                        literal=literal,
                    )
                )
                break
    return found


def comparisons(function: Node, profile: Profile) -> list[Comparison]:
    """Every comparison against a literal in the function body, in source order.

    Nested functions are skipped like in ``complexity``: their branches are not
    this function's paths. Compound expressions are entered operand by operand,
    so ``a > 0 && b <= 10`` yields two comparisons.
    """
    found: list[Comparison] = []
    stack = list(reversed(function.named_children))
    while stack:
        node = stack.pop()
        if node.type in profile.function_types | profile.anonymous_function_types:
            continue
        if node.type in profile.comparison_types:
            found.extend(_comparisons_of(node, profile))
        stack.extend(reversed(node.named_children))
    return found


def build_graph(source: bytes, language: str, name: str, line: int | None) -> FlowGraph:
    """Parse ``source`` and build the flow graph of the function ``name`` near ``line``."""
    profile = PROFILES[language]
    root = parse(source, language)
    function = find_function(root, name, line, profile)
    if _has_error(function):
        raise ParseFailed(name[:200])
    builder = _Builder(profile, language)
    start = builder._add("start", _bare_name(name), function.start_point.row + 1)  # noqa: SLF001
    body = function.child_by_field_name("body")
    statements = _statements(body, profile)
    exits = builder.block(statements, [(start, "")])
    end = builder._add("end", "", function.end_point.row + 1)  # noqa: SLF001
    builder._connect(exits, end)  # noqa: SLF001
    for terminal in builder.terminals:
        builder.edges.append(FlowEdge(source=terminal, target=end, label=""))
    return FlowGraph(
        name=_bare_name(name),
        language=language,
        line=function.start_point.row + 1,
        params=_params(function),
        complexity=complexity(function, profile),
        nodes=builder.nodes,
        edges=builder.edges,
        comparisons=comparisons(function, profile),
        end_line=statements[-1].start_point.row + 1 if statements else function.start_point.row + 1,
    )


def graph_as_dict(graph: FlowGraph) -> dict[str, Any]:
    return {
        "name": graph.name,
        "language": graph.language,
        "line": graph.line,
        "params": list(graph.params),
        "complexity": graph.complexity,
        "nodes": [
            {"id": n.id, "kind": n.kind, "label": n.label, "line": n.line} for n in graph.nodes
        ],
        "edges": [{"source": e.source, "target": e.target, "label": e.label} for e in graph.edges],
        "comparisons": [
            {"line": c.line, "text": c.text, "operator": c.operator, "literal": c.literal}
            for c in graph.comparisons
        ],
        "end_line": graph.end_line,
    }
