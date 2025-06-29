import networkx as nx

import itertools


from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher
from .WithCleanup312 import WithCleanup312
from .AsyncWithCleanup312 import AsyncWithCleanup312

from ..match_utils import optional_node, optional_edge, assert_in_degree, assert_with, node_match_all, assert_node_type


class WithTemplate312(ControlFlowTemplate, AbstractNonSequentiable):
    _subgraph = {
        "setup_with": TemplateNode(
            node_verification_func=assert_with,
            natural_edge=TemplateEdge(
                source="setup_with",
                dest="body",
            ),
            exception_edge=TemplateEdge(
                source="setup_with",
                dest=None,
                edge_verification_func=optional_edge,
            ),
        ),
        "body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(source="body", dest="with_cleanup2", edge_verification_func=optional_edge, commit_none_to_mapping=False),
            exception_edge=TemplateEdge(
                source="body",
                dest="with_cleanup",
            ),
        ),
        "with_cleanup": TemplateNode(
            node_verification_func=node_match_all(assert_in_degree(1), assert_node_type(WithCleanup312, AsyncWithCleanup312)),
        ),
        "with_cleanup2": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(
                source="with_cleanup2",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="with_cleanup2",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="with_cleanup2",
                dest=None,
                edge_verification_func=optional_edge,
            ),
        ),
    }

    def __init__(self, setup_with: ControlFlowTemplate, body: ControlFlowTemplate, with_cleanup: ControlFlowTemplate, with_cleanup2: ControlFlowTemplate):
        self.setup_with = setup_with
        self.body = body
        self.with_cleanup = with_cleanup
        self.with_cleanup2 = with_cleanup2

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
            template_node_dict=WithTemplate312._subgraph,
            root_key="setup_with",
            mapping_verification_func=None,
        )

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        with_template = WithTemplate312(
            setup_with=mapping["setup_with"],
            body=mapping["body"],
            with_cleanup=mapping["with_cleanup"],
            with_cleanup2=mapping.get("with_cleanup2"),
        )

        in_edges = ((src, with_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        if "with_cleanup2" in mapping:
            out_edges = (
                (with_template, dst, {"type": ControlFlowEdgeType.NATURAL.value} if edge_properties["type"] == ControlFlowEdgeType.JUMP.value else edge_properties)
                for src, dst, edge_properties in cfg.out_edges(nbunch=mapping["with_cleanup2"], data=True)
            )
        else:
            out_edges = ()
        out_edges2 = ((with_template, dst, edge_properties) for src, dst, edge_properties in cfg.out_edges(nbunch=mapping["setup_with"], data=True) if edge_properties["type"] == ControlFlowEdgeType.EXCEPTION.value)

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([with_template.setup_with, with_template.body, with_template.with_cleanup, with_template.with_cleanup2])
        reduced_cfg.add_node(with_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges, out_edges2))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        header = self.setup_with.to_indented_source(source_lines)
        body = self._indent_multiline_string(self.body.to_indented_source(source_lines))
        if self.with_cleanup2 is not None:
            clean = self.with_cleanup2.to_indented_source(source_lines)
        else:
            clean = ""
        return f"{header}\n{body}\n{clean}"

    def __repr__(self) -> str:
        return super().__repr__()
