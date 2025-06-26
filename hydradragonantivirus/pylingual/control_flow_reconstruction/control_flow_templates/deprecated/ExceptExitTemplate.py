import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import assert_edge_type, optional_node, optional_edge, assert_in_degree

from ..try_except.ExceptAsTemplate import ExceptAsTemplate
from ..try_except.ExceptAsExceptTemplate import ExceptAsExceptTemplate


class ExceptExitTemplate(ControlFlowTemplate, AbstractNonSequentiable):
    """
    A `try-except` block where the except has no further control flow.
       (0)
       / \\e    -->   (012)
     (1)  (2)           |
      |                (3)
     (3)
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
            natural_edge=TemplateEdge(source="try_footer", dest="after_try_except", edge_verification_func=assert_edge_type(ControlFlowEdgeType.JUMP)),
            exception_edge=TemplateEdge(
                source="try_footer",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "except_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            exception_edge=TemplateEdge(
                source="except_body",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "after_try_except": TemplateNode(
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
                source="after_try_except",
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

    def __init__(self, try_body: ControlFlowTemplate, try_footer: ControlFlowTemplate, except_body: ControlFlowTemplate):
        self.try_body = try_body
        self.try_footer = try_footer
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

        matcher = GraphTemplateMatcher(template_node_dict=ExceptExitTemplate._subgraph, root_key="try_body", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        try_except_template = ExceptExitTemplate(try_body=mapping["try_body"], try_footer=mapping["try_footer"], except_body=mapping["except_body"])

        in_edges = ((src, try_except_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(node, data=True))
        # only preserve exception handling edges
        # insert a continuation edge to after the try except
        out_edges = [(try_except_template, mapping["after_try_except"], {"type": ControlFlowEdgeType.NATURAL.value})]
        if mapping["outer_exception_handler"]:
            out_edges.append((try_except_template, mapping["outer_exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([try_except_template.try_body, try_except_template.try_footer, try_except_template.except_body])
        reduced_cfg.add_node(try_except_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        try_body = ControlFlowTemplate._indent_multiline_string(self.try_body.to_indented_source(source_lines))

        try_except_lines = ["try:", try_body]
        # if we matched against an "Except ... as" chain, then omit the inserted except: block
        if isinstance(self.except_body, ExceptAsTemplate) or isinstance(self.except_body, ExceptAsExceptTemplate):
            except_body = self.except_body.to_indented_source(source_lines)
        else:
            except_body = ControlFlowTemplate._indent_multiline_string(self.except_body.to_indented_source(source_lines))
            try_except_lines.append("except:")
        try_except_lines.append(except_body)

        return "\n".join(try_except_lines)

    def __repr__(self) -> str:
        return super().__repr__()
