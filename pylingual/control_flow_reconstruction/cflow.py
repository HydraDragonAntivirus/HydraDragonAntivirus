import os

from pylingual.editable_bytecode import EditableBytecode
from pylingual.editable_bytecode.control_flow_graph import bytecode_to_control_flow_graph
from pylingual.utils.use_escape_sequences import use_escape_sequences

from .structure_control_flow import structure_control_flow


def pyc_to_indented_sources(pyc: EditableBytecode, source_lines: list[str]) -> dict[object, str]:
    sources = {}
    for bytecode in pyc.iter_bytecodes():
        sources[bytecode.codeobj] = bytecode_to_indented_source(bytecode, source_lines)
    return sources


def split_newlines(li):
    return "\n".join(li).split("\n")


def bytecode_to_indented_source(bytecode: EditableBytecode, source_lines: list[str]) -> list[str]:
    cfg = bytecode_to_control_flow_graph(bytecode)

    # breakpoint to debug control flow templates if DEBUG_CFLOW is set
    if os.environ.get("DEBUG_CFLOW", None) == "1":
        breakpoint()

    structured = structure_control_flow(cfg, bytecode)
    indented_source = structured.to_indented_source(source_lines).split("\n")

    bytecode.ordered_instructions = structured.get_instructions()
    # force generator if necessary
    if bytecode.codeobj.co_flags & (0x20 | 0x200):
        if not any(x.strip().startswith("yield ") or x.strip() == "yield" for x in split_newlines(indented_source)):
            indented_source.insert(0, "if False: yield  # inserted")

    # insert globals
    for global_var in bytecode.globals:
        indented_source.insert(0, f"global {global_var}  # inserted")

    # insert nonlocals
    parent_nonlocal = set()
    parent = bytecode.parent
    while parent:
        parent_nonlocal |= parent.nonlocals
        parent = parent.parent
    for nonlocal_var in bytecode.nonlocals:
        if nonlocal_var in parent_nonlocal:
            indented_source.insert(0, f"nonlocal {nonlocal_var}  # inserted")

    # add function docstring
    if bytecode.codeobj.co_flags & 0x2:
        if bytecode.codeobj.co_consts and isinstance(bytecode.codeobj.co_consts[0], str):
            doc = use_escape_sequences(bytecode.codeobj.co_consts[0])
            indented_source.insert(0, f'"""{doc}""" # inserted')

    return [line for line in indented_source if line]  # filter out empty strings
