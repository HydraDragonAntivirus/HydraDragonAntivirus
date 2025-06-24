import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable
from ..abstract.AbstractExceptionBlockTemplate import AbstractExceptionBlockTemplate
from ..loop.LoopExitTemplate import LoopExitTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree, node_match_all, assert_node_has_no_backwards_edges, node_is_none_or_matches

from .ExceptAsTemplate import ExceptAsTemplate
from .ExceptAsExceptTemplate import ExceptAsExceptTemplate
from ..subtemplates.OptionalExitSubtemplate import ExitSubTemplate


class TryExceptTemplate(ControlFlowTemplate, AbstractNonSequentiable):
    """
    A `try-except` block with just a naked except.
       (0)
       / \\e    -->   (012)
     (1)  (2)           |
      \\j /j           (3)
       (3)
    One or more of the try/except may have no further control flow.
    However, if both have successors, they must go to the same place.
    """

    _subgraph = {
        "try_body": TemplateNode(
            natural_edge=TemplateEdge(
                source="try_body",
                dest="try_footer",
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
            exception_edge=TemplateEdge(
                source="try_body",
                dest="except_body",
            ),
        ),
        "try_footer": TemplateNode(
            subtemplate=ExitSubTemplate,
            node_verification_func=node_is_none_or_matches(
                node_match_all(
                    assert_in_degree(1),
                    assert_node_has_no_backwards_edges,
                )
            ),
            natural_edge=TemplateEdge(source="try_footer", dest="after_try_except", edge_verification_func=optional_edge, commit_none_to_mapping=False),
            exception_edge=TemplateEdge(
                source="try_footer",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "except_body": TemplateNode(
            subtemplate=ExitSubTemplate,
            node_verification_func=node_match_all(
                assert_in_degree(1),
                assert_node_has_no_backwards_edges,
            ),
            natural_edge=TemplateEdge(source="except_body", dest="after_try_except", edge_verification_func=optional_edge, commit_none_to_mapping=False),
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

        matcher = GraphTemplateMatcher(template_node_dict=TryExceptTemplate._subgraph, root_key="try_body", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        # have to make sure there is a try_footer before trying to map it as it is an optional node (this is mostly here for 3.7
        # since there are cases where there is not a try footer at all)

        try_except_template = TryExceptTemplate(try_body=mapping["try_body"], try_footer=mapping.get("try_footer", None), except_body=mapping["except_body"])

        in_edges = ((src, try_except_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(node, data=True))
        # only preserve exception handling edges
        # insert a continuation edge to after the try except
        out_edges = []
        if mapping["outer_exception_handler"]:
            out_edges.append((try_except_template, mapping["outer_exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        if "after_try_except" in mapping.keys():
            after_try_except = mapping["after_try_except"]
            out_edges.append((try_except_template, after_try_except, {"type": ControlFlowEdgeType.NATURAL.value}))

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

        # check if there is a try footer as in 3.7 there may not be a try footer at all
        if self.try_footer:
            try_footer = ControlFlowTemplate._indent_multiline_string(self.try_footer.to_indented_source(source_lines))
        else:
            try_footer = ""

        try_except_lines = ["try:", try_body, try_footer]

        # if we matched against an "Except ... as" chain, then omit the inserted except: block
        omit_except = False
        if isinstance(self.except_body, AbstractExceptionBlockTemplate):
            omit_except = True
        elif isinstance(self.except_body, LoopExitTemplate):
            if isinstance(self.except_body.tail, ExceptAsTemplate) or isinstance(self.except_body.tail, ExceptAsExceptTemplate):
                omit_except = True

        except_body = self.except_body.to_indented_source(source_lines)
        if not omit_except:
            try_except_lines.append("except:")
            except_body = ControlFlowTemplate._indent_multiline_string(except_body)

        try_except_lines.append(except_body)

        return "\n".join(try_except_lines)

    def __repr__(self) -> str:
        return super().__repr__()
