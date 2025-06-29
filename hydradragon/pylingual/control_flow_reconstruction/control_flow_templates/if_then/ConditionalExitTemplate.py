import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge


class ConditionalExitTemplate(ControlFlowTemplate):
    """
    A conditional exit within a line. Typically due to an assert statement.
      (0)
      j|  --> (01)
      (1)

    optionally, all nodes in the pattern can have a shared exception handler.
    """

    _subgraph = {
        "exit_header": TemplateNode(
            conditional_edge=TemplateEdge(
                source="exit_header",
                dest="tail",
            ),
            exception_edge=TemplateEdge(
                source="if_header",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "tail": TemplateNode(
            natural_edge=TemplateEdge(
                source="tail",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="tail",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="tail",
                dest=None,
                edge_verification_func=optional_edge,
            ),
        ),
        "exception_handler": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(
                source="exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
        ),
    }

    def __init__(self, exit_header: ControlFlowTemplate, tail: ControlFlowTemplate):
        self.exit_header = exit_header
        self.tail = tail

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=ConditionalExitTemplate._subgraph, root_key="exit_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        conditional_exit_template = ConditionalExitTemplate(
            exit_header=mapping["exit_header"],
            tail=mapping["tail"],
        )

        in_edges = ((src, conditional_exit_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = ((conditional_exit_template, dst, edge_properties) for src, dst, edge_properties in cfg.out_edges(nbunch=mapping["tail"], data=True))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([conditional_exit_template.exit_header, conditional_exit_template.tail])
        reduced_cfg.add_node(conditional_exit_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        header = self.exit_header.to_indented_source(source_lines)
        tail = self.tail.to_indented_source(source_lines)
        return "\n".join([header, tail])

    def __repr__(self) -> str:
        return super().__repr__()
