import networkx as nx

import itertools

from ...abstract.AbstractTemplate import ControlFlowTemplate
from ...abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable
from ...abstract.AbstractExceptionBlockTemplate import AbstractExceptionBlockTemplate

from ....cfg_utils import ControlFlowEdgeType

from ...Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ...match_utils import optional_node, optional_edge, assert_in_degree, node_match_all, node_match_any, contains_opname_sequence


class ExceptAsCleanupSubTemplate311(ControlFlowTemplate, AbstractNonSequentiable, AbstractExceptionBlockTemplate):
    """
    The boilerplate cleanup at the end of an `except as` block after 3.11.
    The "happy cleanup" (3) is when there is no exception, and it jumps out to the next code segment (except footer in 3.11).
    The "angry cleanup" (2) is when there is an exception, and it reraises.
       (0)
        | \\e
       (1)  |
      / |e  |      --> (012)
    (3)(2)  |            | \\e
        |e /           (3) (4)
        (4)
    """

    _subgraph = {
        "except_header": TemplateNode(
            natural_edge=TemplateEdge(
                source="except_header",
                dest="except_body",
            ),
            exception_edge=TemplateEdge(
                source="except_body",
                dest="panic_except",
            ),
        ),
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
            natural_edge=TemplateEdge(source="happy_cleanup", dest=None, edge_verification_func=optional_edge),
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
                dest="panic_except",
            ),
        ),
        "panic_except": TemplateNode(
            exception_edge=TemplateEdge(
                source="except_body",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            )
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

    def __init__(self, except_header: ControlFlowTemplate, except_body: ControlFlowTemplate, angry_cleanup: ControlFlowTemplate):
        self.except_header = except_header
        self.except_body = except_body
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

        matcher = GraphTemplateMatcher(template_node_dict=ExceptAsCleanupSubTemplate311._subgraph, root_key="except_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return cfg  # if we didn't match the subtemplate, keep trying with the main template

        except_as_cleanup_template = ExceptAsCleanupSubTemplate311(except_header=mapping["except_header"], except_body=mapping["except_body"], angry_cleanup=mapping["angry_cleanup"])

        in_edges = ((src, except_as_cleanup_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(node, data=True))
        out_edges = []
        if mapping["happy_cleanup"]:
            out_edges.append((except_as_cleanup_template, mapping["happy_cleanup"], {"type": ControlFlowEdgeType.NATURAL.value}))
        if mapping["panic_except"]:
            out_edges.append((except_as_cleanup_template, mapping["panic_except"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([except_as_cleanup_template.except_header, except_as_cleanup_template.except_body, except_as_cleanup_template.angry_cleanup])
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
