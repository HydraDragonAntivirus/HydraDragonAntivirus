import networkx as nx

from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..try_except.ExceptAsTemplate import ExceptAsTemplate

from ...cfg_utils import get_out_edge_dict, ControlFlowEdgeType


class LoopExitTemplate(ControlFlowTemplate):
    """
    A wrapper for identified break and continue statements.
    """

    def __init__(self, exit_statement: str, tail: ControlFlowTemplate = None):
        self.tail = tail
        self.exit_statement = exit_statement
        assert self.exit_statement in ["break", "continue"]

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        raise NotImplementedError("Loop Exits do not have localized matching logic. These are assigned in refine_loops.")

    @staticmethod
    def structure_edge_inplace(cfg: nx.DiGraph, edge: tuple, exit_statment: str) -> None:
        src, dst = edge
        edge_properties = cfg.get_edge_data(src, dst)

        cfg.remove_edge(src, dst)
        # for an unconditional jump, integrate the tail into the exit template
        if edge_properties.get("type", None) == ControlFlowEdgeType.JUMP.value:
            template = LoopExitTemplate(exit_statement=exit_statment, tail=src)
            nx.relabel_nodes(cfg, {src: template}, copy=False)
        else:
            template = LoopExitTemplate(exit_statement=exit_statment)
            cfg.add_edge(src, template, **edge_properties)
            src_exception_handler = get_out_edge_dict(cfg, src).get("exception")
            if src_exception_handler != (None, None):
                cfg.add_edge(template, src_exception_handler[0], type=ControlFlowEdgeType.EXCEPTION.value)
        return template

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        tail_source = self.tail.to_indented_source(source_lines) + "\n" if self.tail else ""

        exit_statement = self.exit_statement
        if isinstance(self.tail, ExceptAsTemplate):
            exit_statement = ControlFlowTemplate._indent_multiline_string(self.exit_statement)

        return tail_source + exit_statement

    def __repr__(self) -> str:
        return super().__repr__()
