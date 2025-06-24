from typing import Hashable


def postprocess(source_lines: list[str]):
    i = 0
    tab = " " * 4
    decs = []
    while i < len(source_lines):
        line = source_lines[i]
        if line.startswith("global ") or line.startswith("nonlocal "):
            decs.append(i)
        elif line.startswith("__doc__ = "):
            source_lines[i] = line[10:]
        # should check for 'from __future__ import ', but lines are still masked now
        # checking only for 'from ' doesn't make a difference though
        elif not line.startswith('"""') and not line.startswith("from "):
            break
        i += 1
    for dec in reversed(decs):
        source_lines.insert(i - 1, source_lines.pop(dec))
    block_level = None
    can_have_return = [False]

    while i < len(source_lines):
        line = source_lines[i]
        tabs = len(line) - len(line.lstrip("\t"))
        inserted = line.endswith("# inserted")
        if inserted:
            line = line[:-10]
        line = line.strip()
        while len(can_have_return) - 1 > tabs:
            can_have_return.pop()
        if line.startswith("def ") or line.startswith("class ") or line.startswith("async def "):
            while len(can_have_return) - 1 < tabs + 1:
                can_have_return.append(can_have_return[-1])
            can_have_return[tabs + 1] = not line.startswith("class")
            # add newline between function and class defs
        if line.startswith("@") or line.startswith("def ") or line.startswith("class ") or line.startswith("async def "):
            if i and not source_lines[i - 1].strip().startswith("@") and block_level is None:
                source_lines.insert(i, "")
                i += 1
        if (line.startswith("return ") or line == "return") and not can_have_return[min(tabs, len(can_have_return) - 1)]:
            source_lines.pop(i)
            continue
        # insert pass in empty blocks
        if block_level is not None:
            if tabs <= block_level or not line.strip():
                if source_lines[i - 1].strip().startswith("while True:"):
                    prev_line = source_lines[i - 1]
                    source_lines[i - 1] = " " * (len(prev_line) - len(prev_line.lstrip(" "))) + "pass"
                else:
                    source_lines.insert(i, tab * (block_level + 1) + "pass  # postinserted")
                    i += 1
            block_level = None
        if line.endswith(":"):
            block_level = tabs

        # convert tabs to spaces
        source_lines[i] = tab * tabs + line + ("  # inserted" if inserted else "")
        i += 1
    if block_level is not None:
        source_lines.insert(i, tab * (block_level + 1) + "pass  # postinserted")
        i += 1
    return "\n".join(source_lines)


def reconstruct_source(pyc, sources):
    merged_source, blame = merge_indented_sources(pyc, sources)
    return postprocess(merged_source), blame


def split_newlines(li):
    return "\n".join(li).split("\n")


def indent_newlines(li, n=1):
    li = [line for line in split_newlines(li)]
    return ["\t" * n + line for line in li]


def merge_indented_sources(pyc, sources):
    blame_dict = {}
    for bytecode in pyc.child_bytecodes:
        sources[bytecode.codeobj], blame_dict[bytecode.codeobj] = merge_indented_sources(bytecode, sources)
    line = 0
    indented_source = split_newlines(sources[pyc.codeobj])
    blame = [pyc.codeobj] * len(indented_source)
    lines_set = set()
    for i, instruction in enumerate(pyc.ordered_instructions):
        if instruction.starts_line and instruction.starts_line not in lines_set:
            lines_set.add(instruction.starts_line)
            # count implicit else/finally/while True
            while line < len(indented_source) and indented_source[line].endswith("# inserted"):
                line += 1
            line += 1
        if instruction.opname == "LOAD_CONST" and isinstance(instruction.argval, Hashable):
            if instruction.argval in sources:
                if instruction.argval.co_name not in ("<listcomp>", "<genexpr>", "<setcomp>", "<dictcomp>", "<lambda>"):
                    new_tabs = 1

                    # add indentation of previous line
                    prev_line = ""
                    if line > 0:
                        if line < len(indented_source):
                            prev_line = indented_source[line - 1]
                        else:
                            prev_line = indented_source[-1]
                    new_tabs += len(prev_line) - len(prev_line.lstrip("\t"))

                    code_to_insert = indent_newlines(sources[instruction.argval], new_tabs)
                    indented_source[line:line] = code_to_insert
                    blame[line:line] = blame_dict[instruction.argval]
                    line += len(code_to_insert)
    return indented_source, blame
