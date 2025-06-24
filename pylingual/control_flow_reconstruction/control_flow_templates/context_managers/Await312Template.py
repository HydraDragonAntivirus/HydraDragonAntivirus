import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_edge, assert_in_degree, assert_node_has_no_backwards_edges, node_match_all, is_exactly_opname, node_match_any
from ...cfg_utils import ControlFlowEdgeType


class Await312Template(ControlFlowTemplate):
    _subgraph = {
        "awaited": TemplateNode(
            natural_edge=TemplateEdge(
                source="awaited",
                dest="send",
            ),
            exception_edge=TemplateEdge(
                source="awaited",
                dest="exception_handler",
            ),
        ),
        "send": TemplateNode(
            node_verification_func=node_match_all(assert_in_degree(2), assert_node_has_no_backwards_edges, is_exactly_opname("SEND")),
            natural_edge=TemplateEdge(
                source="send",
                dest="yield",
            ),
            conditional_edge=TemplateEdge(
                source="send",
                dest="jump_back",
            ),
            exception_edge=TemplateEdge(
                source="send",
                dest="exception_handler",
            ),
        ),
        "yield": TemplateNode(
            node_verification_func=node_match_all(assert_in_degree(1), assert_node_has_no_backwards_edges, is_exactly_opname("YIELD_VALUE")),
            natural_edge=TemplateEdge(
                source="yield",
                dest="jump_back",
            ),
            exception_edge=TemplateEdge(
                source="yield",
                dest="cleanup_throw",
            ),
        ),
        "jump_back": TemplateNode(
            node_verification_func=node_match_all(assert_in_degree(2), is_exactly_opname("JUMP_BACKWARD_NO_INTERRUPT")),
            natural_edge=TemplateEdge(
                source="jump_back",
                dest="send",
            ),
            exception_edge=TemplateEdge(
                source="jump_back",
                dest="exception_handler",
            ),
        ),
        "cleanup_throw": TemplateNode(
            node_verification_func=node_match_all(assert_in_degree(1), is_exactly_opname("CLEANUP_THROW")),
            natural_edge=TemplateEdge(
                source="cleanup_throw",
                dest="jump_back2",
            ),
            exception_edge=TemplateEdge(
                source="cleanup_throw",
                dest="exception_handler",
            ),
        ),
        "jump_back2": TemplateNode(
            node_verification_func=node_match_all(assert_in_degree(1), node_match_any(is_exactly_opname("JUMP_BACKWARD"), is_exactly_opname("JUMP_BACKWARD_NO_INTERRUPT"))),
            natural_edge=TemplateEdge(
                source="jump_back2",
                dest=None,
            ),
        ),
        "exception_handler": TemplateNode(
            natural_edge=TemplateEdge(
                source="exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
        ),
    }

    def __init__(self, awaited):
        self.awaited = awaited

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=Await312Template._subgraph, root_key="awaited", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        template = Await312Template(
            awaited=mapping["awaited"],
        )

        in_edges = ((src, template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = [(template, next(cfg.successors(mapping["jump_back2"])), {"type": ControlFlowEdgeType.NATURAL.value}), (template, mapping["exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value})]

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([template.awaited, mapping["send"], mapping["yield"], mapping["jump_back"], mapping["cleanup_throw"], mapping["jump_back2"]])
        reduced_cfg.add_node(template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        return self.awaited.to_indented_source(source_lines)

    def __repr__(self) -> str:
        return super().__repr__()
