import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import assert_edge_type, optional_node, optional_edge, assert_in_degree, node_is_none_or_matches, edge_is_none_or_matches


class IfElseExitTemplate(ControlFlowTemplate):
    """
    An if-else block where both options have no further control flow (structured breaks/continues and returns).
       (0)
      j/ \\     -->   (012)
     (1)  (2)

    optionally, all nodes in the pattern can have a shared exception handler.
    nodes 1 and 2 can optionally have a "tail" that is an exit statement that breaks out of the current exception handler.
    """

    _subgraph = {
        "if_header": TemplateNode(
            natural_edge=TemplateEdge(
                source="if_header",
                dest="if_body",
            ),
            conditional_edge=TemplateEdge(
                source="if_header",
                dest="else_body",
            ),
            exception_edge=TemplateEdge(
                source="if_header",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "if_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="if_body",
                dest="if_tail",
                edge_verification_func=edge_is_none_or_matches(assert_edge_type(ControlFlowEdgeType.NATURAL)),
            ),
            exception_edge=TemplateEdge(
                source="if_body",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "if_tail": TemplateNode(
            node_verification_func=node_is_none_or_matches(assert_in_degree(1)),
            exception_edge=TemplateEdge(
                source="if_tail",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "else_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="else_body",
                dest="else_tail",
                edge_verification_func=edge_is_none_or_matches(assert_edge_type(ControlFlowEdgeType.NATURAL)),
            ),
            exception_edge=TemplateEdge(
                source="else_body",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "else_tail": TemplateNode(
            node_verification_func=node_is_none_or_matches(assert_in_degree(1)),
            exception_edge=TemplateEdge(
                source="else_tail",
                dest="outer_exception_handler",
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

    def __init__(
        self,
        if_header: ControlFlowTemplate,
        if_body: ControlFlowTemplate,
        if_tail: ControlFlowTemplate,
        else_body: ControlFlowTemplate,
        else_tail: ControlFlowTemplate,
    ):
        self.if_header = if_header
        self.if_body = if_body
        self.if_tail = if_tail  # may be none
        self.else_body = else_body
        self.else_tail = else_tail  # may be none

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=IfElseExitTemplate._subgraph, root_key="if_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        if_else_template = IfElseExitTemplate(
            if_header=mapping["if_header"],
            if_body=mapping["if_body"],
            if_tail=mapping["if_tail"],
            else_body=mapping["else_body"],
            else_tail=mapping["else_tail"],
        )

        in_edges = ((src, if_else_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        # only preserve meta edges
        out_edges = [(if_else_template, "END", data) for _, _, data in cfg.out_edges([if_else_template.if_body, if_else_template.else_body], data=True) if data["type"] == ControlFlowEdgeType.META.value]
        if mapping["exception_handler"]:
            out_edges.append((if_else_template, mapping["exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([if_else_template.if_header, if_else_template.if_body, if_else_template.if_tail, if_else_template.else_body, if_else_template.else_tail])
        reduced_cfg.add_node(if_else_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        header = self.if_header.to_indented_source(source_lines)
        if_body = self.if_body.to_indented_source(source_lines)
        if header.strip():
            if_body = ControlFlowTemplate._indent_multiline_string(if_body)
        else_body = self.else_body.to_indented_source(source_lines)

        return "\n".join([header, if_body, else_body])

    def __repr__(self) -> str:
        return super().__repr__()
