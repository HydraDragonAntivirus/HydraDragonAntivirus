import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..loop.LoopExitTemplate import LoopExitTemplate


from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree, assert_node_has_no_backwards_edges, node_match_all, assert_no_linestarts, assert_node_type, node_match_none

from ..loop.PreRefinedLoopTemplate import PreRefinedLoopTemplate


class ShortCircuitAndTemplate(ControlFlowTemplate):
    """
    A short-circuit evaluated boolean AND. Typically these are all part of one line.
       (0)
       / \\            (01)
     (1)  |j   -->     / \\j
      |\\j|           (2) (3)
     (2) (3)

    optionally, all nodes in the pattern can have a shared exception handler.
    This condenses the short-circuit down to be matched against an if-like template later
    """

    _subgraph = {
        "first_condition": TemplateNode(
            node_verification_func=assert_node_has_no_backwards_edges,
            natural_edge=TemplateEdge(
                source="first_condition",
                dest="second_condition",
            ),
            conditional_edge=TemplateEdge(
                source="first_condition",
                dest="tail",
            ),
            exception_edge=TemplateEdge(
                source="first_condition",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "second_condition": TemplateNode(
            node_verification_func=node_match_all(
                assert_in_degree(1),
                assert_node_has_no_backwards_edges,
                assert_no_linestarts,
                node_match_none(assert_node_type(PreRefinedLoopTemplate)),
            ),
            natural_edge=TemplateEdge(
                source="second_condition",
                dest="if_body",
            ),
            conditional_edge=TemplateEdge(
                source="second_condition",
                dest="tail",
            ),
            exception_edge=TemplateEdge(
                source="second_condition",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "if_body": TemplateNode(
            natural_edge=TemplateEdge(
                source="if_body",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="if_body",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="if_body",
                dest=None,
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

    _subgraph_for_loop_exits = {
        "first_condition": TemplateNode(
            node_verification_func=assert_node_has_no_backwards_edges,
            natural_edge=TemplateEdge(
                source="first_condition",
                dest="second_condition",
            ),
            conditional_edge=TemplateEdge(
                source="first_condition",
                dest="first_loop_exit_tail",
            ),
            exception_edge=TemplateEdge(
                source="if_header",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "second_condition": TemplateNode(
            node_verification_func=node_match_all(
                assert_in_degree(1),
                assert_node_has_no_backwards_edges,
                assert_no_linestarts,
            ),
            natural_edge=TemplateEdge(
                source="second_condition",
                dest="if_body",
            ),
            conditional_edge=TemplateEdge(
                source="second_condition",
                dest="second_loop_exit_tail",
            ),
            exception_edge=TemplateEdge(
                source="second_condition",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "if_body": TemplateNode(
            natural_edge=TemplateEdge(
                source="if_body",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="if_body",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="if_body",
                dest=None,
                edge_verification_func=optional_edge,
            ),
        ),
        "first_loop_exit_tail": TemplateNode(
            node_verification_func=assert_node_type(LoopExitTemplate),
            exception_edge=TemplateEdge(
                source="first_loop_exit_tail",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "second_loop_exit_tail": TemplateNode(
            node_verification_func=assert_node_type(LoopExitTemplate),
            exception_edge=TemplateEdge(
                source="second_loop_exit_tail",
                dest="exception_handler",
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

    def _verify_loop_exit_match(cfg: nx.DiGraph, mapping: dict) -> bool:
        first_tail = mapping["first_loop_exit_tail"]
        second_tail = mapping["second_loop_exit_tail"]
        if not isinstance(first_tail, LoopExitTemplate) or not isinstance(second_tail, LoopExitTemplate):
            return False

        # the loop exits should have no code associated with them
        # this part of the pattern is just to deal with implicit continues that got split into separate nodes
        if first_tail.tail or second_tail.tail:
            return False

        return first_tail.exit_statement == second_tail.exit_statement

    def __init__(self, first_condition: ControlFlowTemplate, second_condition: ControlFlowTemplate):
        self.first_condition = first_condition
        self.second_condition = second_condition

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=ShortCircuitAndTemplate._subgraph, root_key="first_condition", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            matcher = GraphTemplateMatcher(template_node_dict=ShortCircuitAndTemplate._subgraph_for_loop_exits, root_key="first_condition", mapping_verification_func=ShortCircuitAndTemplate._verify_loop_exit_match)
            mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        short_circuit_template = ShortCircuitAndTemplate(
            first_condition=mapping["first_condition"],
            second_condition=mapping["second_condition"],
        )

        in_edges = ((src, short_circuit_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = [(short_circuit_template, dst, edge_properties) for src, dst, edge_properties in cfg.out_edges(short_circuit_template.second_condition, data=True)]

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([short_circuit_template.first_condition, short_circuit_template.second_condition])
        if first_loop_exit_tail := mapping.get("first_loop_exit_tail", None):
            reduced_cfg.remove_node(first_loop_exit_tail)
        reduced_cfg.add_node(short_circuit_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        first_condition = self.first_condition.to_indented_source(source_lines)
        second_condition = self.second_condition.to_indented_source(source_lines)
        return "\n".join([first_condition, second_condition])

    def __repr__(self) -> str:
        return super().__repr__()
