import networkx as nx

import itertools


from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable
from ..try_except.TryExceptTemplate import TryExceptTemplate


from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree, assert_with, node_match_all, assert_node_type


class WithTemplate39(ControlFlowTemplate, AbstractNonSequentiable):
    _subgraph = {
        "setup_with": TemplateNode(
            node_verification_func=assert_with,
            natural_edge=TemplateEdge(
                source="setup_with",
                dest="body",
            ),
            exception_edge=TemplateEdge(
                source="setup_with",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "body": TemplateNode(
            node_verification_func=node_match_all(assert_in_degree(1), assert_node_type(TryExceptTemplate)),
            natural_edge=TemplateEdge(
                source="body",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="body",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="body",
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

    def __init__(self, setup_with: ControlFlowTemplate, body: ControlFlowTemplate):
        self.setup_with = setup_with
        self.body = body

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        node = next(cfg.predecessors(node))
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(
            template_node_dict=WithTemplate39._subgraph,
            root_key="setup_with",
            mapping_verification_func=None,
        )

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        with_template = WithTemplate39(
            setup_with=mapping["setup_with"],
            body=mapping["body"],
        )

        in_edges = ((src, with_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = ((with_template, dst, edge_properties) for src, dst, edge_properties in cfg.out_edges(nbunch=mapping["body"], data=True))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([with_template.setup_with, with_template.body])
        reduced_cfg.add_node(with_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        header = self.setup_with.to_indented_source(source_lines)
        body = self._indent_multiline_string(self.body.try_body.to_indented_source(source_lines))
        return f"{header}\n{body}"

    def __repr__(self) -> str:
        return super().__repr__()
