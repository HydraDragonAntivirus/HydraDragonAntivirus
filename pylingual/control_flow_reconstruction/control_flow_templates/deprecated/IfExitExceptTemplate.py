import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate

from ...cfg_utils import get_out_edge_dict, ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree


class IfExitExceptTemplate(ControlFlowTemplate):
    """
    An if block where the if has no further control flow (structured breaks/continues and returns).
    When the exit leaves an exception block, the final exit statement does not have the same exception handler.

       (0)
      j/ \\     -->   (023)
     (1)  (2)          |
      |    |          (1)
     ...  (3)

    In this configuration, (0,1,2) share an exception handler, but 3 does not
    """

    _subgraph = {
        "if_header": TemplateNode(
            natural_edge=TemplateEdge(
                source="if_header",
                dest="if_body",
            ),
            conditional_edge=TemplateEdge(
                source="if_header",
                dest="tail",
            ),
            exception_edge=TemplateEdge(
                source="if_header",
                dest="exception_handler",
            ),
        ),
        "if_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="if_body",
                dest="exit_node",
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="if_body",
                dest="exception_handler",
            ),
        ),
        "exit_node": TemplateNode(
            node_verification_func=assert_in_degree(1),
            exception_edge=TemplateEdge(
                source="exit_node",
                dest="outer_exception_handler",
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
            ),
        ),
        "exception_handler": TemplateNode(
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

    def __init__(self, if_header: ControlFlowTemplate, if_body: ControlFlowTemplate, exit_node: ControlFlowTemplate):
        self.if_header = if_header
        self.if_body = if_body
        self.exit_node = exit_node

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        # try to match happy non-exception version
        matcher = GraphTemplateMatcher(template_node_dict=IfExitExceptTemplate._subgraph, root_key="if_header", mapping_verification_func=None)
        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        if_exit_template = IfExitExceptTemplate(if_header=mapping["if_header"], if_body=mapping["if_body"], exit_node=mapping["exit_node"])

        in_edges = ((src, if_exit_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        node_edge_dict = get_out_edge_dict(cfg, node)
        out_edges = [(if_exit_template, node_edge_dict["conditional"][0], {"type": ControlFlowEdgeType.NATURAL.value})]
        if node_edge_dict["exception"]:
            out_edges.append((if_exit_template, *(node_edge_dict["exception"])))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([if_exit_template.if_header, if_exit_template.if_body, if_exit_template.exit_node])
        reduced_cfg.add_node(if_exit_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        header = self.if_header.to_indented_source(source_lines)
        if_body = ControlFlowTemplate._indent_multiline_string(self.if_body.to_indented_source(source_lines))
        exit_node = ControlFlowTemplate._indent_multiline_string(self.exit_node.to_indented_source(source_lines))
        return "\n".join([header, if_body, exit_node])

    def __repr__(self) -> str:
        return super().__repr__()
