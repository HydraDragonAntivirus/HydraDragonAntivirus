import networkx as nx

import itertools
import collections

from ..cfg_utils import ControlFlowEdgeType, get_dominator_function
from .natural.InstructionTemplate import InstructionTemplate

from .abstract.AbstractTemplate import ControlFlowTemplate
from .natural.LinearSequenceTemplate import LinearSequenceTemplate

from typing import Callable, Any

# common node/edge/mapping verification functions and factories


def assert_edge_type(*edge_types: ControlFlowEdgeType) -> Callable[[Any, Any, dict], bool]:
    def initialized_assert_edge_type(graph_source, graph_dest, graph_edge_properties: dict) -> bool:
        if graph_edge_properties is None:
            return False
        return graph_edge_properties.get("type", None) in [edge_type.value for edge_type in edge_types]

    return initialized_assert_edge_type


def assert_node_type(*node_types: type) -> Callable[[nx.DiGraph, Any], bool]:
    def initialized_assert_node_type(cfg: nx.DiGraph, node) -> bool:
        return any(isinstance(node, node_type) for node_type in node_types)

    return initialized_assert_node_type


def assert_in_degree(in_degree: int) -> Callable[[nx.DiGraph, Any], bool]:
    def initialized_assert_in_degree(cfg: nx.DiGraph, node) -> bool:
        if node is None:
            return False
        return cfg.in_degree(node) == in_degree

    return initialized_assert_in_degree


def assert_instruction_opname(*opnames: str) -> Callable[[nx.DiGraph, Any], bool]:
    def initialized_assert_instruction_opname(cfg: nx.DiGraph, node) -> bool:
        if node is None:
            return False

        if isinstance(node, LinearSequenceTemplate):
            candidate = node.members[-1]
        else:
            candidate = node

        if not isinstance(candidate, InstructionTemplate):
            return False
        return candidate.instruction.opname in opnames

    return initialized_assert_instruction_opname


def assert_first_instruction_opname(*opnames: str) -> Callable[[nx.DiGraph, Any], bool]:
    def initialized_assert_first_instruction_opname(cfg: nx.DiGraph, node) -> bool:
        """
        if node is None:
            return False

        if isinstance(node, LinearSequenceTemplate):
            candidate = node.members[0]
        else:
            candidate = node

        if not isinstance(candidate, InstructionTemplate):
            return False
        return candidate.instruction.opname in opnames
        """
        i = node.get_instructions()
        return i and i[0].opname in opnames

    return initialized_assert_first_instruction_opname


def assert_unconditional_jump(cfg: nx.DiGraph, node) -> bool:
    if not isinstance(node, InstructionTemplate):
        return False
    return node.instruction.is_uncond_jump


def optional_node(cfg, node) -> bool:
    # returns true even when node is None!
    # overrides default behavior of checking if the node exists
    return True


def optional_edge(graph_source, graph_dest, graph_edge_properties: dict) -> bool:
    # returns true even when the edge is None!
    # overrides default behavior of checking if the edge exists
    return True


def edge_is_none_or_matches(verification_func: Callable[[nx.DiGraph, Any], bool]) -> Callable[[Any, Any, dict], bool]:
    def initialized_edge_is_none_or_matches(graph_source, graph_dest, graph_edge_properties: dict) -> bool:
        return graph_dest is None or verification_func(graph_source, graph_dest, graph_edge_properties)

    return initialized_edge_is_none_or_matches


def node_is_none_or_matches(verification_func: Callable[[nx.DiGraph, Any], bool]) -> Callable[[nx.DiGraph, Any], bool]:
    def initialized_node_is_none_or_matches(cfg: nx.DiGraph, node) -> bool:
        return node is None or verification_func(cfg, node)

    return initialized_node_is_none_or_matches


def node_match_all(*verification_funcs: Callable[[nx.DiGraph, Any], bool]) -> Callable[[nx.DiGraph, Any], bool]:
    def initialized_match_all(cfg: nx.DiGraph, node) -> bool:
        return all(f(cfg, node) for f in verification_funcs)

    return initialized_match_all


def node_match_none(*verification_funcs: Callable[[nx.DiGraph, Any], bool]) -> Callable[[nx.DiGraph, Any], bool]:
    def initialized_match_all(cfg: nx.DiGraph, node) -> bool:
        return not any(f(cfg, node) for f in verification_funcs)

    return initialized_match_all


def node_match_any(*verification_funcs: Callable[[nx.DiGraph, Any], bool]) -> Callable[[nx.DiGraph, Any], bool]:
    def initialized_match_any(cfg: nx.DiGraph, node) -> bool:
        return any(f(cfg, node) for f in verification_funcs)

    return initialized_match_any


def assert_no_linestarts(cfg: nx.DiGraph, node: ControlFlowTemplate) -> bool:
    return not any(inst.starts_line for inst in node.get_instructions())


def contains_opname_sequence(*opnames: str) -> Callable[[nx.DiGraph, Any], bool]:
    def initialized_contains_opname_sequence(cfg: nx.DiGraph, node: ControlFlowTemplate) -> bool:
        for window in sliding_window(node.get_instructions(), n=len(opnames)):
            if tuple(inst.opname for inst in window) == opnames:
                return True
        return False

    return initialized_contains_opname_sequence


def starts_with_opname_sequence(*opnames: str) -> Callable[[nx.DiGraph, Any], bool]:
    def initialized_starts_with_opname_sequence(cfg: nx.DiGraph, node: ControlFlowTemplate) -> bool:
        i = node.get_instructions()
        return len(i) >= len(opnames) and tuple(x.opname for x in i[: len(opnames)]) == opnames

    return initialized_starts_with_opname_sequence


def ends_with_opname_sequence(*opnames: str) -> Callable[[nx.DiGraph, Any], bool]:
    def initialized_ends_with_opname_sequence(cfg: nx.DiGraph, node: ControlFlowTemplate) -> bool:
        i = node.get_instructions()
        return len(i) >= len(opnames) and tuple(x.opname for x in i[-len(opnames) :]) == opnames

    return initialized_ends_with_opname_sequence


def is_exactly_opname(*opnames: str) -> Callable[[nx.DiGraph, Any], bool]:
    def initialized_is_exactly_opname(cfg: nx.DiGraph, node: ControlFlowTemplate) -> bool:
        return isinstance(node, ControlFlowTemplate) and tuple(x.opname for x in node.get_instructions()) == opnames

    return initialized_is_exactly_opname


def assert_node_has_no_backwards_edges(cfg, node) -> bool:
    dominates = get_dominator_function(cfg)
    return not any(dominates(successor, node) for successor in cfg.successors(node))


def assert_except_as(cfg: nx.DiGraph, node: ControlFlowTemplate) -> bool:
    # specialized node verification function for the header
    # the header must be a LinearSequence where the last instruction is JUMP_IF_NOT_EXC_MATCH
    # this instruction is used *exclusively* for except-as constructions in pre-3.11 bytecode
    # this rule only applies to versions 3.9 and 3.10
    if not isinstance(node, LinearSequenceTemplate):
        return False

    # version 3.9-3.10
    exc_match_member = node.members[-1]
    if not isinstance(exc_match_member, InstructionTemplate):
        return False
    if exc_match_member.instruction.opname == "JUMP_IF_NOT_EXC_MATCH":
        return True

    # so we dont throw errors

    if len(node.members) < 2:
        return False

    # pre-3.9
    exc_match_member = node.members[-2]
    if not isinstance(exc_match_member, InstructionTemplate):
        return False
    if exc_match_member.instruction.opname == "COMPARE_OP" and exc_match_member.instruction.argval == "exception-match":
        return True

    # 3.11
    if exc_match_member.instruction.opname == "CHECK_EXC_MATCH":
        return True
    return False


def assert_with(cfg: nx.DiGraph, node: ControlFlowTemplate) -> bool:
    # these statements begin in a linear sequence template
    # so if the node is not in a linear sequence template then this is not
    # a with statement

    if not isinstance(node, LinearSequenceTemplate):
        return False

    # designed for version 3.8 might be different for other versions
    with_match_member = node.members[-1]  # get the last element that should be a SETUP_WITH
    if not isinstance(with_match_member, InstructionTemplate):
        return False
    if with_match_member.instruction.opname in ("SETUP_WITH", "SETUP_ASYNC_WITH", "BEFORE_WITH", "END_SEND"):
        return True


# iteration helper
def sliding_window(iterable, n):
    "Collect data into overlapping fixed-length chunks or blocks."
    # sliding_window('ABCDEFG', 4) → ABCD BCDE CDEF DEFG
    it = iter(iterable)
    window = collections.deque(itertools.islice(it, n - 1), maxlen=n)
    for x in it:
        window.append(x)
        yield tuple(window)
