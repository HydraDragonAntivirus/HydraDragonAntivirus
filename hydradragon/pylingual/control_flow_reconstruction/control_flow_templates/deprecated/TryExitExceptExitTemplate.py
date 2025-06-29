import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable
from ..try_except.ExceptAsExceptTemplate import ExceptAsExceptTemplate
from ..try_except.ExceptAsTemplate import ExceptAsTemplate
from ..try_except.ExceptAsExitTemplate import ExceptAsExitTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree, assert_instruction_opname, assert_except_as


class TryExitExceptExitTemplate(ControlFlowTemplate, AbstractNonSequentiable):
    """
    An try block where neither the try body nor the except body has no further control flow (structured breaks/continues and returns).
       (0)
        |      -->   (012)
       (1)
        |e
       (2)
    """

    _subgraph = {
        "setup_finally": TemplateNode(
            node_verification_func=assert_instruction_opname("SETUP_FINALLY"),
            natural_edge=TemplateEdge(
                source="setup_finally",
                dest="try_body",
            ),
            exception_edge=TemplateEdge(
                source="setup_finally",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "try_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            exception_edge=TemplateEdge(
                source="try_body",
                dest="except_body",
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

    def __init__(self, setup_finally: ControlFlowTemplate, try_body: ControlFlowTemplate, except_body: ControlFlowTemplate):
        self.setup_finally = setup_finally
        self.try_body = try_body
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

        # an except as exit looks exactly like this, so we need to check that we are not part of the larger pattern
        def assert_not_in_except_as(cfg: nx.DiGraph, mapping: dict) -> bool:
            setup_finally = mapping["setup_finally"]
            if cfg.in_degree(setup_finally) != 1:
                return True

            pred = next(cfg.predecessors(setup_finally))
            return not assert_except_as(cfg, pred)

        matcher = GraphTemplateMatcher(template_node_dict=TryExitExceptExitTemplate._subgraph, root_key="setup_finally", mapping_verification_func=assert_not_in_except_as)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        try_exit_template = TryExitExceptExitTemplate(setup_finally=mapping["setup_finally"], try_body=mapping["try_body"], except_body=mapping["except_body"])

        in_edges = ((src, try_exit_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = []
        if mapping["outer_exception_handler"]:
            out_edges.append((try_exit_template, mapping["outer_exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([try_exit_template.setup_finally, try_exit_template.try_body, try_exit_template.except_body])
        reduced_cfg.add_node(try_exit_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        setup_finally = self.setup_finally.to_indented_source(source_lines)
        try_body = ControlFlowTemplate._indent_multiline_string(self.try_body.to_indented_source(source_lines))

        try_except_lines = [setup_finally, "try:", try_body]
        # if we matched against an "Except ... as" chain, then omit the inserted except: block
        if isinstance(self.except_body, ExceptAsTemplate) or isinstance(self.except_body, ExceptAsExceptTemplate) or isinstance(self.except_body, ExceptAsExitTemplate):
            except_body = self.except_body.to_indented_source(source_lines)
        else:
            except_body = ControlFlowTemplate._indent_multiline_string(self.except_body.to_indented_source(source_lines))
            try_except_lines.append("except:")
        try_except_lines.append(except_body)

        return "\n".join(try_except_lines)

    def __repr__(self) -> str:
        return super().__repr__()
