from __future__ import annotations

import itertools
import keyword
import inspect
import ast

from typing import TYPE_CHECKING, Generator, NamedTuple
from xdis import Code3

from pylingual.editable_bytecode import PYCFile
from pylingual.editable_bytecode.EditableBytecode import EditableBytecode
from pylingual.utils.use_escape_sequences import use_escape_sequences
from pylingual.utils.version import PythonVersion

if TYPE_CHECKING:
    from .cft import ControlFlowTemplate


def indent_lines(lines: list[SourceLine], i: int = 1) -> list[SourceLine]:
    return [SourceLine(x.line, x.indent + i, x.blame, x.child, x.meta) for x in lines]


class SourceLine(NamedTuple):
    line: str
    indent: int
    blame: Code3
    child: Code3 | None = None
    meta: bool = False

    def with_line(self, line: str):
        return SourceLine(line, self.indent, self.blame, self.child, self.meta)


def sanitize_lines(lines: list[str]) -> list[str]:
    return ["" if x in ("break", "continue", "except:", "while True:", "try:") else x for x in (x[2:] if x.startswith("elif ") else x for x in (x.strip() for x in lines))]


def fake_header(co: Code3):
    name = co.co_name if co.co_name.isidentifier() and not keyword.iskeyword(co.co_name) else "_"
    if co.co_flags & inspect.CO_ASYNC_GENERATOR:
        return f"async def {name}():"
    if co.co_flags & inspect.CO_NEWLOCALS:
        return f"def {name}():"
    return f"class {name}:"


def valid_header(line: SourceLine, version: PythonVersion):
    try:
        ast.parse(line.line + "pass", feature_version=version.as_tuple())
        return True
    except Exception:
        return False


class SourceContext:
    def __init__(self, pyc: PYCFile, lines: list[str], cfts: dict[Code3, ControlFlowTemplate]):
        self.pyc = pyc
        self.lines = sanitize_lines(lines)
        self.cfts = cfts
        self.cache: dict[ControlFlowTemplate, list[SourceLine]] = {}
        self.header_lines: list[SourceLine] = []
        self.purged_cfts: list[ControlFlowTemplate] = []
        self.init_header()

    def init_header(self):
        for bc in self.pyc.iter_bytecodes():
            cft = self.cfts[bc.codeobj]
            if bc.codeobj.co_flags & inspect.CO_NEWLOCALS:
                if bc.codeobj.co_consts and isinstance(bc.codeobj.co_consts[0], str):
                    doc = use_escape_sequences(bc.codeobj.co_consts[0])
                    cft.add_header(f'"""{doc}"""')
            if bc.codeobj.co_flags & (inspect.CO_GENERATOR | inspect.CO_ASYNC_GENERATOR):
                if not any(self.lines[i.starts_line - 1].strip().startswith("yield ") or self.lines[i.starts_line - 1].strip() == "yield" for i in cft.get_instructions() if i.starts_line is not None):
                    cft.add_header("if False: yield")
            for global_var in bc.globals:
                cft.add_header(f"global {global_var}")
            parent_nonlocal = set()
            parent = bc.parent
            while parent:
                parent_nonlocal |= parent.nonlocals
                parent = parent.parent
            for nonlocal_var in bc.nonlocals:
                if nonlocal_var in parent_nonlocal:
                    cft.add_header(f"nonlocal {nonlocal_var}")

    def __getitem__(self, template: ControlFlowTemplate | tuple[ControlFlowTemplate, int]):
        if isinstance(template, tuple):
            template, indent = template
        else:
            indent = 0
        if template not in self.cache:
            self.cache[template] = template.to_indented_source(self)
        if indent:
            return indent_lines(template.header_lines + self.cache[template], indent)
        return template.header_lines + self.cache[template]

    def source_lines_of(self, co: Code3, i=0) -> Generator[SourceLine]:
        lines = self[self.cfts[co], i]
        purged = self.cfts[co] in self.purged_cfts
        prev = None
        for line in lines:
            if line.child:
                if purged:
                    if prev and valid_header(prev, self.pyc.version):
                        yield prev
                    else:
                        yield SourceLine(fake_header(line.child), line.indent - 1, line.child)
                yield from self.source_lines_of(line.child, line.indent)
            elif not purged:
                # filter out returns in top level codeobjs and classes
                if not co.co_flags & (inspect.CO_NEWLOCALS | inspect.CO_GENERATOR | inspect.CO_ASYNC_GENERATOR):
                    if line.line == "return":
                        yield line.with_line("pass")
                    elif line.line.startswith("return "):
                        yield SourceLine("# " + line.line, line.indent, line.blame, meta=True)
                    else:
                        yield line
                else:
                    yield line
            prev = line

    def purge(self, co: Code3):
        self.purged_cfts.append(self.cfts[co])

    def source_lines(self):
        def is_prefix(x: SourceLine):
            return x.line.startswith(("from __future__ import ", "__doc__ = ", "global ", "nonlocal ", '"""'))

        def priority(x: SourceLine):
            if x.line.startswith(("__doc__ = ", '"""')):
                return 0
            if x.line.startswith("from __future__ import "):
                return 1
            return 2

        lines = self.header_lines + list(self.source_lines_of(self.pyc.codeobj))
        prefix = [x.with_line(x.line[10:]) if x.line.startswith("__doc__ = ") else x for x in sorted(itertools.takewhile(is_prefix, lines), key=priority)]
        lines[: len(prefix)] = prefix

        # insert pass in empty blocks
        colon_line = None
        new_lines = []
        for x in lines:
            if colon_line is not None:
                if x.indent <= colon_line.indent:
                    new_lines.append(SourceLine("pass", colon_line.indent + 1, colon_line.blame))
                if not x.meta:
                    colon_line = None
            if x.line.endswith(":"):
                colon_line = x
            new_lines.append(x)
        if colon_line is not None:
            new_lines.append(SourceLine("pass", colon_line.indent + 1, colon_line.blame))

        return new_lines

    def __str__(self):
        return "\n".join("    " * x.indent + x.line for x in self.source_lines())

    def update_cft(self, bc: EditableBytecode, template: ControlFlowTemplate):
        x = bc
        while x.parent is not None:
            del self.cache[self.cfts[x.codeobj]]
            x = x.parent
        self.cfts[bc.codeobj] = template

    def update_lines(self, lines: list[str]):
        self.lines = sanitize_lines(lines)
        self.cache.clear()
