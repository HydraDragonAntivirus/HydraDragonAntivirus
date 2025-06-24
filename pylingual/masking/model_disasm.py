from __future__ import annotations

import ast
import pathlib
import re
from copy import deepcopy
from typing import TYPE_CHECKING

from pylingual.utils.use_escape_sequences import use_escape_sequences
from pylingual.utils.version import PythonVersion

if TYPE_CHECKING:
    from pylingual.editable_bytecode import EditableBytecode

from pylingual.masking.ast_masker import RewriteMasks, custom_unparse
from pylingual.masking.global_masker import Masker

mask_regex = re.compile(r"(?<=<mask_)\d+(?=>)")


def create_global_masker(bytecode: EditableBytecode) -> Masker:
    """Creates four flat global tables of names, locals, consts, and freevars in given Bytecode for use with improved model view
    Global Tables map local code obj tables: name, varname, const, and freevar to the global table
    - For additional model context, values that match across the name and const tab will have their matching
        partner in the other table appended to their token. ex: <const_x>=<name_y>
    Access table in global dict via keywork of table optype"""

    global_masker = Masker()
    global_tab = global_masker.global_tab
    global_idx = 0

    future_flag = 0x1000000 if bytecode.version > (3, 7) else 0x100000
    global_masker.future_annotations = bool(bytecode.codeobj.co_flags & future_flag)
    global_masker.version = bytecode.version

    for bc in bytecode.iter_bytecodes():
        bc_co = bc.to_code(no_lnotab=True)

        # create consts
        consts = list(deepcopy(bc_co.co_consts))
        while consts:
            const = consts.pop(0)
            # Don't mask None
            if const is None:
                continue
            if type(const) in (list, tuple, frozenset, set):
                consts.extend(const)
            else:
                global_tab.update({bc.resolve_namespace(const): f"<mask_{global_idx}>"})
                global_idx += 1

        # create names
        for name in bc_co.co_names:
            if name in global_tab:
                continue
            global_tab.update({bc.resolve_namespace(name): f"<mask_{global_idx}>"})
            global_idx += 1

        for free in bc_co.co_freevars:
            if free in global_tab:
                continue
            global_tab.update({free: f"<mask_{global_idx}>"})
            global_idx += 1

        for local in bc_co.co_varnames:
            if local in global_tab:
                continue
            global_tab.update({bc.resolve_namespace(local): f"<mask_{global_idx}>"})
            global_idx += 1

        global_tab.update({bc_co.co_name: f"<mask_{global_idx}>"})
        global_idx += 1

    return global_masker


def mask_source(file_path: pathlib.Path, masker: Masker, python_version: PythonVersion) -> str:
    """Replace source strings with tokens from keys in global_tab,
    masks source and provides offsets incured by multiline string replacements"""
    text = file_path.read_text()
    tree = ast.parse(text, feature_version=python_version.as_tuple())

    line_offsets = dict()
    tree = RewriteMasks(masker, line_offsets, python_version).generic_visit(tree)

    source_text = custom_unparse(tree, masker)
    source_lines = source_text.splitlines()

    re_added_lines = 0
    for line_offset, lines_to_add in line_offsets.items():
        insertion_target = line_offset + re_added_lines
        source_lines[insertion_target:insertion_target] = [""] * lines_to_add

    return "\n".join(source_lines)


def restore_masked_source(file_path: pathlib.Path, masker: Masker, python_version: PythonVersion) -> str:
    """Creates a large regex of all the tokens and their respective values
    Replaces everything in file text in one pass."""
    return restore_masked_source_text(file_path.read_text(), masker, python_version)


def format_source_replacement(mask_value: str) -> str:
    if mask_value is ...:
        return "..."
    if type(mask_value) in (int, float) and mask_value < 0:
        return f"({mask_value})"
    if type(mask_value) != str:
        return str(mask_value)

    formatted_mask_value = use_escape_sequences(mask_value)

    return formatted_mask_value


def fix_jump_targets(disasm: str) -> str:
    jump_target_re = r"to (\d+) ([\^v]~>)"
    jump_target_map = {target: f"TARGET_{ind}" for ind, target in enumerate(sorted(set(match.group(1) for match in re.finditer(jump_target_re, disasm))))}

    # remove external jump entry points
    incoming_jump_re = r"([\^v]~>) (\d+) "
    result = re.sub(incoming_jump_re, lambda match: f"{match.group(1)} {jump_target_map[match.group(2)]} " if match.group(2) in jump_target_map else f"{match.group(1)} ", disasm)

    # only enforce order on external jumps
    result = re.sub(jump_target_re, lambda match: f"to {jump_target_map[match.group(1)]} {match.group(2)}", result)
    return result


def restore_masked_source_text(text: str, masker: Masker, python_version: PythonVersion) -> str:
    """Creates a large regex of all the tokens and their respective values
    Replaces everything in file text in one pass."""
    replacements = {re.escape(v): format_source_replacement(k) for k, v in masker.global_tab.items()}  # we use encode + decode so multiline strings get replaced correctly
    re_pattern = re.compile("|".join(replacements.keys()))
    result = re_pattern.sub(lambda match: replacements[match.group()], text)

    # replace imports with a module starting with a number, with that number amount of dots for relative imports
    re_rel_pattern = r"^(\s*)(import|from)\s*(\d+)(.*)"
    result_rel_imports = re.sub(re_rel_pattern, lambda match: f"{match.group(1)}{match.group(2)} {'.' * int(match.group(3))}{match.group(4)}", result, 0, re.MULTILINE)

    # normalize with parse+unparse to catch replacement errors and simplify whitespace
    try:
        return ast.unparse(ast.parse(result_rel_imports, feature_version=python_version.as_tuple()))
    except (SyntaxError, IndentationError):
        return result_rel_imports


# replace mask values to start at 0 and count up
def normalize_masks(statement: str) -> tuple[str, list[str]]:
    masks = mask_regex.findall(statement)
    mask_order = [x for i, x in enumerate(masks) if masks.index(x) == i]
    return mask_regex.sub(lambda x: str(mask_order.index(x.group(0))), statement), mask_order


# reverts masks to their original value
def restore_masks(translation: str, mask_order: list[str]):
    def restore_mask(match):
        i = int(match.group(0))
        # sometimes model adds random masks that did not appear in bytecode,
        # so we have to check if mask is in bounds
        return mask_order[i] if i < len(mask_order) else match.group(0)

    return mask_regex.sub(restore_mask, translation)
