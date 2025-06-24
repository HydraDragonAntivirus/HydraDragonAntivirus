import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable
from ..abstract.AbstractExceptionBlockTemplate import AbstractExceptionBlockTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import assert_edge_type, optional_node, optional_edge, assert_in_degree, node_match_all, node_match_any, contains_opname_sequence, edge_is_none_or_matches


class ExceptAsCleanupTemplate(ControlFlowTemplate, AbstractNonSequentiable, AbstractExceptionBlockTemplate):
    """
    The boilerplate cleanup at the end of an `except as` block.
    The "happy cleanup" (1) is when there is no exception, and it jumps out to the next code segment.
    The "angry cleanup" (2) is when there is an exception, and it reraises.
       (0)
       / \\e    -->   (012)
     (1)  (2)           |j
      |j               (3)
     (3)
    """

    _subgraph = {
        "except_body": TemplateNode(
            natural_edge=TemplateEdge(
                source="except_body",
                dest="happy_cleanup",
            ),
            exception_edge=TemplateEdge(
                source="except_body",
                dest="angry_cleanup",
            ),
        ),
        "happy_cleanup": TemplateNode(
            node_verification_func=node_match_all(
                assert_in_degree(1),
                node_match_any(
                    contains_opname_sequence(
                        "LOAD_CONST",
                        "STORE_NAME",
                        "DELETE_NAME",
                    ),
                    contains_opname_sequence(
                        "LOAD_CONST",
                        "STORE_FAST",
                        "DELETE_FAST",
                    ),
                ),
            ),
            natural_edge=TemplateEdge(source="happy_cleanup", dest=None, edge_verification_func=edge_is_none_or_matches(assert_edge_type(ControlFlowEdgeType.JUMP))),
            exception_edge=TemplateEdge(
                source="happy_cleanup",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "angry_cleanup": TemplateNode(
            node_verification_func=node_match_all(
                assert_in_degree(1),
                node_match_any(
                    contains_opname_sequence("LOAD_CONST", "STORE_NAME", "DELETE_NAME", "RERAISE"),
                    contains_opname_sequence("LOAD_CONST", "STORE_FAST", "DELETE_FAST", "RERAISE"),
                ),
            ),
            exception_edge=TemplateEdge(
                source="angry_cleanup",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "outer_exception_handler": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(
                source="outer_exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="outer_exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="outer_exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
        ),
    }

    def __init__(self, except_body: ControlFlowTemplate, happy_cleanup: ControlFlowTemplate, angry_cleanup: ControlFlowTemplate):
        self.except_body = except_body
        self.happy_cleanup = happy_cleanup
        self.angry_cleanup = angry_cleanup

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=ExceptAsCleanupTemplate._subgraph, root_key="except_body", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        except_as_cleanup_template = ExceptAsCleanupTemplate(except_body=mapping["except_body"], happy_cleanup=mapping.get("happy_cleanup", None), angry_cleanup=mapping.get("angry_cleanup", None))

        in_edges = ((src, except_as_cleanup_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(node, data=True))
        out_edges = [(except_as_cleanup_template, dst, data) for _, dst, data in cfg.out_edges([except_as_cleanup_template.happy_cleanup, except_as_cleanup_template.angry_cleanup], data=True)]
        if mapping["outer_exception_handler"]:
            out_edges.append((except_as_cleanup_template, mapping["outer_exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([except_as_cleanup_template.except_body, except_as_cleanup_template.happy_cleanup, except_as_cleanup_template.angry_cleanup])
        reduced_cfg.add_node(except_as_cleanup_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        # cleanup code is implicit! only report the body code
        return self.except_body.to_indented_source(source_lines)

    def __repr__(self) -> str:
        return super().__repr__()
