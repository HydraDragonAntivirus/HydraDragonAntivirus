import networkx as nx

from ..abstract.AbstractTemplate import ControlFlowTemplate

from ...cfg_utils import get_out_edge_dict

from ..placeholders.WhileTruePlaceholderTemplate import WhileTruePlaceholderTemplate


class PreRefinedLoopTemplate(ControlFlowTemplate):
    """
    Matches a loop header for an unrefined loop containing breaks and continues.
    Results in a RefinedLoopTemplate header and replaces all breaks and continues with LoopExitTemplates
    """

    def __init__(self, loop_header: ControlFlowTemplate, loop_else: ControlFlowTemplate):
        self.loop_header = loop_header
        self.loop_else = loop_else

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        raise NotImplementedError("PreRefinedLoopTemplate does not have local matching logic. These are created in refine_loop")

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        return self.loop_header.to_indented_source(source_lines)

    @staticmethod
    def structure_nodes_inplace(cfg: nx.DiGraph, loop_header, canonical_loop_exit, loop_successor):
        if not canonical_loop_exit:
            # while true; use a placeholder that makes the while true "look like" a normal loop
            loop_header = WhileTruePlaceholderTemplate.structure_node_inplace(cfg, loop_header, loop_successor)
            loop_template = PreRefinedLoopTemplate(loop_header=loop_header, loop_else=None)
        if canonical_loop_exit != loop_successor:
            loop_template = PreRefinedLoopTemplate(loop_header=loop_header, loop_else=canonical_loop_exit)
        else:
            loop_template = PreRefinedLoopTemplate(loop_header=loop_header, loop_else=None)

        in_edges = ((src, loop_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=loop_header, data=True))
        out_edges = [(loop_template, loop_successor if dst == canonical_loop_exit else dst, edge_properties) for src, dst, edge_properties in cfg.out_edges(nbunch=loop_header, data=True)]

        loop_header_out_dict = get_out_edge_dict(cfg, loop_header)
        exception_target, edge_type = loop_header_out_dict["exception"]
        if exception_target:
            out_edges.append((loop_template, exception_target, edge_type))

        cfg.remove_node(loop_template.loop_header)
        if loop_template.loop_else:
            cfg.remove_node(loop_template.loop_else)
        cfg.add_node(loop_template)
        cfg.add_edges_from(in_edges)
        cfg.add_edges_from(out_edges)

    def __repr__(self) -> str:
        return super().__repr__()
