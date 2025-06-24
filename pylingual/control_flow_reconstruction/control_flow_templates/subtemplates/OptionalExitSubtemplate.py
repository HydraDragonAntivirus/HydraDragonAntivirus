import networkx as nx

import itertools


from ..abstract.AbstractTemplate import ControlFlowTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import assert_edge_type, optional_node, optional_edge, assert_in_degree, node_is_none_or_matches, edge_is_none_or_matches


class ExitSubTemplate(ControlFlowTemplate):
    """ 
    
    A basic with template as a catch all for exits
    first case

    (1)  or simply (1)
  e/    \
        (2)
    

    """

    _subgraph = {
        "exit_header": TemplateNode(
            natural_edge=TemplateEdge(source="exit_header", dest="exit_flow", edge_verification_func=edge_is_none_or_matches(assert_edge_type(ControlFlowEdgeType.NATURAL))),
            exception_edge=TemplateEdge(
                source="exit_header",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "exit_flow": TemplateNode(node_verification_func=node_is_none_or_matches(assert_in_degree(1)), exception_edge=TemplateEdge(source="exit_flow", dest="outer_exception_handler", edge_verification_func=optional_edge)),
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

    def __init__(self, exit_header: ControlFlowTemplate, exit_flow: ControlFlowTemplate):
        self.exit_header = exit_header
        self.exit_flow = exit_flow

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template or we are happy and return the base cfg.
        Otherwise, returns None.
        """

        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(
            template_node_dict=ExitSubTemplate._subgraph,
            root_key="exit_header",
            mapping_verification_func=None,
        )

        mapping = matcher.match_at_graph_node(cfg, node)

        # not standard; if we didn't match the exit, then continue matching the rest of the parent template
        if not mapping:
            return cfg

        # this is an appropriate match, but there is nothing to do
        if not mapping["exit_flow"]:
            return cfg

        exit_template = ExitSubTemplate(
            exit_header=mapping["exit_header"],
            exit_flow=mapping["exit_flow"],
        )

        in_edges = ((src, exit_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = []

        if mapping["exception_handler"]:
            out_edges.append((exit_template, mapping["exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([exit_template.exit_flow, exit_template.exit_header])
        reduced_cfg.add_node(exit_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        header = self.exit_header.to_indented_source(source_lines)
        exit_flow = self.exit_flow.to_indented_source(source_lines)
        return "\n".join([header, exit_flow])

    def __repr__(self) -> str:
        return super().__repr__()
