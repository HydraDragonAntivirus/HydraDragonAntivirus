import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree, assert_node_has_no_backwards_edges, node_match_all, assert_no_linestarts



class ChainedComparisonTemplate(ControlFlowTemplate):
    """
    A chained comparison such as a == b == c.
       (0)
      / \\j
    (1)  (2)           (0123)
    / \\j/j             / \\j
   (3) (5)      -->   (4)  (5)
    |j
   (4)

   not (a == b == c)

       (0)
     j/ \\
    (2)  (1)     -->  (0123)
    /   /  \\j         / \\j
    |  (3) (5)       (4)  (5)
    | /j
   (4)

    optionally, all nodes in the pattern can have a shared exception handler.
    This condenses the chained comparison down to be matched against an if-like template later
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
                dest="cleanup",
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
            ),
            natural_edge=TemplateEdge(
                source="second_condition",
                dest="j2if_body",
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
        "cleanup": TemplateNode(
            node_verification_func=node_match_all(
                assert_in_degree(1),
                assert_node_has_no_backwards_edges,
                assert_no_linestarts,
            ),
            natural_edge=TemplateEdge(
                source="cleanup",
                dest="tail",
            ),
            exception_edge=TemplateEdge(
                source="cleanup",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "j2if_body": TemplateNode(
            natural_edge=TemplateEdge(
                source="j2if_body",
                dest="if_body",
            ),
            exception_edge=TemplateEdge(
                source="j2if_body",
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
    _subgraph2 = {
        "first_condition": TemplateNode(
            node_verification_func=assert_node_has_no_backwards_edges,
            natural_edge=TemplateEdge(
                source="first_condition",
                dest="second_condition",
            ),
            conditional_edge=TemplateEdge(
                source="first_condition",
                dest="cleanup",
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
            ),
            natural_edge=TemplateEdge(
                source="second_condition",
                dest="j2if_body",
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
        "cleanup": TemplateNode(
            node_verification_func=node_match_all(
                assert_in_degree(1),
                assert_node_has_no_backwards_edges,
                assert_no_linestarts,
            ),
            natural_edge=TemplateEdge(
                source="cleanup",
                dest="if_body",
            ),
            exception_edge=TemplateEdge(
                source="j2if_body",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "j2if_body": TemplateNode(
            natural_edge=TemplateEdge(
                source="j2if_body",
                dest="if_body",
            ),
            exception_edge=TemplateEdge(
                source="j2if_body",
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

    def __init__(self, first_condition: ControlFlowTemplate, second_condition: ControlFlowTemplate, cleanup: ControlFlowTemplate, j2if_body: ControlFlowTemplate):
        self.first_condition = first_condition
        self.second_condition = second_condition
        self.cleanup = cleanup
        self.j2if_body = j2if_body

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=ChainedComparisonTemplate._subgraph, root_key="first_condition", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            matcher = GraphTemplateMatcher(template_node_dict=ChainedComparisonTemplate._subgraph2, root_key="first_condition", mapping_verification_func=None)
            mapping = matcher.match_at_graph_node(cfg, node)
            if not mapping:
                return None

        chained_comparison_template = ChainedComparisonTemplate(first_condition=mapping["first_condition"], second_condition=mapping["second_condition"], cleanup=mapping["cleanup"], j2if_body=mapping["j2if_body"])

        in_edges = ((src, chained_comparison_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = [(chained_comparison_template, mapping["if_body"], {"type": ControlFlowEdgeType.NATURAL.value}), (chained_comparison_template, mapping["tail"], {"type": ControlFlowEdgeType.TRUE_JUMP.value})]

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([chained_comparison_template.first_condition, chained_comparison_template.second_condition, chained_comparison_template.cleanup, chained_comparison_template.j2if_body])
        reduced_cfg.add_node(chained_comparison_template)
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
