#!/usr/bin/env python3

from .Instruction import Inst

import networkx as nx
from enum import Enum


class ControlFlowEdgeType(Enum):
    NATURAL = "natural"  # edge goes to the next instruction in sequence; this is the default
    JUMP = "jump"  # edge represents an unconditional jump
    TRUE_JUMP = "true_jump"  # edge represents a conditional jump that is taken when the condition is true
    FALSE_JUMP = "false_jump"  # edge represents a conditional jump that is taken when the condition is false
    EXCEPTION = "exception"  # edge goes to an exception handler
    META = "meta"  # used exclusively for the START and END meta-nodes that are added to the cfg


from typing import Any


def inst_to_node_attributes(inst: "Inst") -> dict:
    return {"label": inst.get_dis_view()}


def inst_to_successors(inst: "Inst") -> list[tuple["Inst", ControlFlowEdgeType]]:
    # premature exits
    if inst.opname in ("RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE"):
        return []

    successors = []
    # jump target
    if inst.is_jump and inst.opname not in ("SETUP_WITH", "SETUP_ASYNC_WITH", "SETUP_FINALLY", "SETUP_CLEANUP", "SETUP_EXCEPT"):
        edge_type = ControlFlowEdgeType.JUMP
        if inst.is_cond_jump and any(s in inst.opname for s in ("IF_FALSE", "IF_NONE", "FOR_ITER", "IF_NOT_EXC_MATCH")):
            edge_type = ControlFlowEdgeType.FALSE_JUMP
        elif inst.is_cond_jump and ("IF_TRUE" in inst.opname or "IF_NOT_NONE" in inst.opname):
            edge_type = ControlFlowEdgeType.TRUE_JUMP
        elif inst.opname == "SEND":
            edge_type = ControlFlowEdgeType.TRUE_JUMP
        successors.append((inst.target, edge_type))

    # regular follow-up instruction
    if not inst.is_uncond_jump:
        next_instruction = inst.bytecode._get_instruction_after(inst)
        if next_instruction:
            successors.append((next_instruction, ControlFlowEdgeType.NATURAL))

    return successors


# returns a list of tuples of the form
# (source, destination, edge_properties, next_state)
def inst_to_edges_37(inst: "Inst", state: Any) -> list[tuple["Inst", "Inst", dict[str, ControlFlowEdgeType], Any]]:
    if state is None:
        block_stack = tuple()
    else:
        block_stack = state

    # update exception handler (pre-3.11 style)
    if inst.opname in ("SETUP_FINALLY", "SETUP_WITH", "SETUP_ASYNC_WITH", "SETUP_CLEANUP", "SETUP_EXCEPT"):
        # add new exception handler to the stack
        next_block_stack = (*block_stack, (inst.target, "exception"))
    elif inst.opname in ("POP_BLOCK",):
        # remove an exception handler from the stack
        next_block_stack = block_stack[:-1]
    elif inst.opname in ("SETUP_LOOP",):
        next_block_stack = (*block_stack, (inst.target, "loop"))
    else:
        # no change to the exception handler
        next_block_stack = block_stack

    if inst.opname in ("BREAK_LOOP", "CONTINUE_LOOP"):
        # get the highest loop block from the block stack; default to None
        def is_loop_block(block: tuple["Inst", str]) -> bool:
            return block[1] == "loop"

        break_target = next(filter(is_loop_block, reversed(block_stack)), None)
        loop_block_index = block_stack.index(break_target)
        block_stack = block_stack[:loop_block_index]
        # after breaking out of the loop or continuing, pop off any exeption blocks leading up to the loop block
        if inst.opname == "BREAK_LOOP":
            edges = [((inst, break_target[0], ControlFlowEdgeType.JUMP), block_stack)]
        elif inst.opname == "CONTINUE_LOOP":
            # CONTINUE_LOOP has the offset of the loop instruction as the argval; go there to continue
            edges = [((inst, inst.bytecode.get_by_offset(inst.argval), ControlFlowEdgeType.JUMP), block_stack)]
    else:
        # list of tuples [(successor, edge_type) ...]
        successors = inst_to_successors(inst)
        edges = [((inst, successor, edge_type), next_block_stack) for successor, edge_type in successors]

    # get the highest exception block from the block stack; default to None
    def is_exception_block(block: tuple["Inst", str]) -> bool:
        return block[1] == "exception"

    exception_target = next(filter(is_exception_block, reversed(block_stack)), None)
    if exception_target:
        exception_block_index = block_stack.index(exception_target)
        edges.append(((inst, exception_target[0], ControlFlowEdgeType.EXCEPTION), block_stack[:exception_block_index]))

    return edges


def inst_to_edges_39(inst: "Inst", state: Any) -> list[tuple[tuple["Inst", "Inst", dict[str, ControlFlowEdgeType]], Any]]:
    if state is None:
        block_stack = tuple()
    else:
        block_stack = state

    exception_target = block_stack[-1] if block_stack else None

    # update exception handler (pre-3.11 style)
    if inst.opname in ("SETUP_FINALLY", "SETUP_WITH", "SETUP_ASYNC_WITH", "SETUP_CLEANUP"):
        # add new exception handler to the stack
        next_block_stack = (*block_stack, inst.target)
    elif inst.opname in ("POP_BLOCK"):
        # remove an exception handler from the stack
        next_block_stack = block_stack[:-1]
    else:
        # no change to the exception handler
        next_block_stack = block_stack

    # list of tuples [(successor, edge_type) ...]
    successors = inst_to_successors(inst)
    edges = [((inst, successor, edge_type), next_block_stack) for successor, edge_type in successors]

    if exception_target:
        edges.append(((inst, exception_target, ControlFlowEdgeType.EXCEPTION), block_stack[:-1]))

    return edges


def inst_to_edges_311(inst: "Inst", state: Any) -> list[tuple[tuple["Inst", "Inst", dict[str, ControlFlowEdgeType]], Any]]:
    exception_table = inst.bytecode.named_exception_table
    # search the exception table for any entry that applies to the current instruction
    exception_target = None
    for exception_range in exception_table:
        if inst.offset >= exception_range.start and inst.offset < exception_range.end:
            exception_target = inst.bytecode.get_by_offset(exception_range.target)
            break

    # list of tuples [(successor, edge_type) ...]
    successors = inst_to_successors(inst)
    edges = [((inst, successor, edge_type), None) for successor, edge_type in successors]

    if exception_target:
        edges.append(((inst, exception_target, ControlFlowEdgeType.EXCEPTION), None))

    return edges


def bytecode_to_control_flow_graph(bytecode: "EditableBytecode") -> nx.DiGraph:
    cfg = nx.DiGraph()

    # add one node for each instruction
    cfg.add_nodes_from((inst, inst_to_node_attributes(inst)) for inst in bytecode)

    # depth first traversal of the bytecode
    visited_instructions = set()
    # dfs stack contains (instruction, inst_to_edges_state)
    dfs_stack = [(bytecode.first_instruction, None)]

    inst_to_edges = inst_to_edges_311
    if bytecode.version < (3, 11):
        inst_to_edges = inst_to_edges_39
    if bytecode.version < (3, 8):
        inst_to_edges = inst_to_edges_37

    while dfs_stack:
        # boilerplate depth-first traversal
        current_inst, current_state = dfs_stack.pop()
        if current_inst in visited_instructions:
            continue
        visited_instructions.add(current_inst)

        edges = inst_to_edges(current_inst, current_state)
        for (src, dst, edge_type), next_state in edges:
            cfg.add_edge(src, dst, type=edge_type.value)
            dfs_stack.append((dst, next_state))

    # remove unreachable instructions
    cfg.remove_nodes_from(set(bytecode) - visited_instructions)

    return cfg
