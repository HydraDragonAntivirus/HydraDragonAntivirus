import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate

from ...cfg_utils import get_dominator_function

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree, assert_unconditional_jump



class ShortCircuitOrContinueTemplate(ControlFlowTemplate):
    """
    A short-circuit evaluated boolean OR. Typically these are all part of one line.
    This variant occurs only when the content of the if statement is just a continue.

       (-1)
        |  \\
       (0)   \\
       / \\j  |           (-10)
     (1)  (2) |j  -->     / \\j
      \\j    /           (1) (2)  
       (3) -/             \\j
                           (3)

    optionally, all nodes in the pattern can have a shared exception handler.
    This condenses the short-circuit down to be matched against an if-like template later
    """

    _subgraph = {
        "first_condition": TemplateNode(
            natural_edge=TemplateEdge(
                source="first_condition",
                dest="second_condition",
            ),
            conditional_edge=TemplateEdge(
                source="first_condition",
                dest="loop_header",
            ),
            exception_edge=TemplateEdge(
                source="first_condition",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "second_condition": TemplateNode(
            node_verification_func=assert_in_degree(1),
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
            node_verification_func=assert_unconditional_jump,  # this is the continue statement
            natural_edge=TemplateEdge(
                source="if_body",
                dest="loop_header",
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="if_body",
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
            conditional_edge=TemplateEdge(
                source="tail",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="tail",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "loop_header": TemplateNode(
            natural_edge=TemplateEdge(
                source="loop_header",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="loop_header",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="loop_header",
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

        if cfg.in_degree(node) != 1:
            return None

        # to avoid being treated as an if-else, we actually need to greedily search up one layer
        pred = next(cfg.predecessors(node))

        def verify_loop_header(cfg: nx.DiGraph, mapping: dict[str, ControlFlowTemplate]) -> bool:
            # check to make sure that all non-stack/control instructions match between the two finally blocks
            # this list was made for 3.9, so it may need to be expanded for other versions
            dominates = get_dominator_function(cfg)
            return dominates(mapping["loop_header"], mapping["first_condition"])

        matcher = GraphTemplateMatcher(template_node_dict=ShortCircuitOrContinueTemplate._subgraph, root_key="first_condition", mapping_verification_func=verify_loop_header)

        mapping = matcher.match_at_graph_node(cfg, pred)

        if not mapping:
            return None

        short_circuit_template = ShortCircuitOrContinueTemplate(
            first_condition=mapping["first_condition"],
            second_condition=mapping["second_condition"],
        )

        in_edges = ((src, short_circuit_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=short_circuit_template.first_condition, data=True))
        out_edges = [(short_circuit_template, dst, edge_properties) for src, dst, edge_properties in cfg.out_edges(short_circuit_template.second_condition, data=True)]

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([short_circuit_template.first_condition, short_circuit_template.second_condition])
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
