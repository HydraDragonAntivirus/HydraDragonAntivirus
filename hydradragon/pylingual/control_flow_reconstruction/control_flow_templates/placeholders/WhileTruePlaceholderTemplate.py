import networkx as nx

from ..abstract.AbstractTemplate import ControlFlowTemplate

from ...cfg_utils import ControlFlowEdgeType


class WhileTruePlaceholderTemplate(ControlFlowTemplate):
    """
    Placeholder for While True; used in PreRefinedLoopTemplate
    """

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        raise NotImplementedError("WhileTruePlaceholderTemplate does not have local matching logic. These are created in PreRefinedLoopTemplate")

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        return "while True: # inserted"

    @staticmethod
    def structure_node_inplace(cfg: nx.DiGraph, loop_header, loop_successor):
        # insert a WhileTruePlaceholderTemplate before the loop_header, and add a conditional edge to the loop successor
        # this "looks like" a normal while loop, which allows structuring to continue
        placeholder = WhileTruePlaceholderTemplate()

        # replace the incoming edges
        in_edges = [(src, placeholder, data) for src, _, data in cfg.in_edges(loop_header, data=True)]
        cfg.add_edges_from(in_edges)
        cfg.remove_edges_from(list(cfg.in_edges(loop_header)))

        # add outgoing edges to the placeholder
        cfg.add_edge(placeholder, loop_header, type=ControlFlowEdgeType.NATURAL.value)
        if loop_successor:
            cfg.add_edge(placeholder, loop_successor, type=ControlFlowEdgeType.FALSE_JUMP.value)

        return placeholder

    def __repr__(self) -> str:
        return type(self).__name__
