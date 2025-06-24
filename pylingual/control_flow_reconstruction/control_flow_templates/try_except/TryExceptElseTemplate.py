import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable
from .TryExceptTemplate import TryExceptTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import assert_edge_type, optional_node, optional_edge, assert_in_degree, edge_is_none_or_matches



class TryExceptElseTemplate(ControlFlowTemplate, AbstractNonSequentiable):
    """
    A `try-except` with an else and a structured except.
       (0)
       / \\e    -->   (0123)
     (1)  (2)           |
      |j  |j           (4)
     (3)  |
      \\ /
       (4)
    """

    _subgraph = {
        "try_body": TemplateNode(
            natural_edge=TemplateEdge(
                source="try_body",
                dest="try_footer",
            ),
            exception_edge=TemplateEdge(
                source="try_body",
                dest="except_body",
            ),
        ),
        "try_footer": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(source="try_footer", dest="else_body", edge_verification_func=assert_edge_type(ControlFlowEdgeType.JUMP)),
            exception_edge=TemplateEdge(
                source="try_footer",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "else_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="else_body",
                dest="after_try_except",
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
            exception_edge=TemplateEdge(
                source="else_body",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "except_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="except_body",
                dest="after_try_except",
                edge_verification_func=edge_is_none_or_matches(assert_edge_type(ControlFlowEdgeType.JUMP)),
                commit_none_to_mapping=False,
            ),
            exception_edge=TemplateEdge(
                source="except_body",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "after_try_except": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(
                source="after_try_except",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="after_try_except",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="except_body",
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

    def __init__(self, try_body: ControlFlowTemplate, try_footer: ControlFlowTemplate, else_body: ControlFlowTemplate, except_body: ControlFlowTemplate):
        self.try_body = try_body
        self.try_footer = try_footer
        self.else_body = else_body
        self.except_body = except_body

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=TryExceptElseTemplate._subgraph, root_key="try_body", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        try_except_template = TryExceptElseTemplate(try_body=mapping["try_body"], try_footer=mapping["try_footer"], else_body=mapping["else_body"], except_body=mapping["except_body"])

        in_edges = ((src, try_except_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(node, data=True))
        # only preserve exception handling edges
        # insert a continuation edge to after the try except
        out_edges = []
        if mapping.get("after_try_except", None):
            out_edges.append((try_except_template, mapping["after_try_except"], {"type": ControlFlowEdgeType.NATURAL.value}))
        if mapping["outer_exception_handler"]:
            out_edges.append((try_except_template, mapping["outer_exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([try_except_template.try_body, try_except_template.try_footer, try_except_template.else_body, try_except_template.except_body])
        reduced_cfg.add_node(try_except_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        try_except_template = TryExceptTemplate(try_body=self.try_body, try_footer=self.try_footer, except_body=self.except_body)
        try_except_lines = [try_except_template.to_indented_source(source_lines)]
        else_body = ControlFlowTemplate._indent_multiline_string(self.else_body.to_indented_source(source_lines))
        try_except_lines.extend(["else: # inserted", else_body])

        return "\n".join(try_except_lines)

    def __repr__(self) -> str:
        return super().__repr__()
