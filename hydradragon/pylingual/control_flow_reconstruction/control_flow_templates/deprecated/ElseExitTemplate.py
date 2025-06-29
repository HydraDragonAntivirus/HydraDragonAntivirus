import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree


class ElseExitTemplate(ControlFlowTemplate):
    """
    An if-else block where only the else has no further control flow (structured breaks/continues and returns).
       (0)
      j/ \\     -->   (012)
     (1)  (2)           |
           |j          (3)
          (3)

    optionally, all nodes in the pattern can have a shared exception handler.
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
                dest="tail",
            ),
            exception_edge=TemplateEdge(
                source="if_body",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "else_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            exception_edge=TemplateEdge(
                source="else_body",
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

    def __init__(self, if_header: ControlFlowTemplate, if_body: ControlFlowTemplate, else_body: ControlFlowTemplate):
        self.if_header = if_header
        self.if_body = if_body
        self.else_body = else_body

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=ElseExitTemplate._subgraph, root_key="if_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        if_else_template = ElseExitTemplate(if_header=mapping["if_header"], if_body=mapping["if_body"], else_body=mapping["else_body"])

        in_edges = ((src, if_else_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = [(if_else_template, mapping["tail"], {"type": ControlFlowEdgeType.NATURAL.value})]
        if mapping["exception_handler"]:
            out_edges.append((if_else_template, mapping["exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([if_else_template.if_header, if_else_template.if_body, if_else_template.else_body])
        reduced_cfg.add_node(if_else_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        header = self.if_header.to_indented_source(source_lines)
        if_body = ControlFlowTemplate._indent_multiline_string(self.if_body.to_indented_source(source_lines))
        else_body = ControlFlowTemplate._indent_multiline_string(self.else_body.to_indented_source(source_lines))
        return "\n".join([header, if_body, "else: # inserted", else_body])

    def __repr__(self) -> str:
        return super().__repr__()
