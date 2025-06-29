import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..if_then.IfElseTemplate import IfElseTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree


class WhileTrueIfElseTemplate(ControlFlowTemplate):
    """
    A while true that contains in if-else statement at the top level.
      (0)
     j| \\            
     (2)  (1)    -->  (012)  

    nodes 1 and 2 have a backwards unconditional jump to 0
    optionally, all nodes in the pattern can have a shared exception handler.
    """

    _subgraph = {
        "loop_header": TemplateNode(
            natural_edge=TemplateEdge(
                source="loop_header",
                dest="if_body",
            ),
            conditional_edge=TemplateEdge(
                source="loop_header",
                dest="else_body",
            ),
            exception_edge=TemplateEdge(
                source="loop_header",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "if_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="if_body",
                dest="loop_header",
            ),
            exception_edge=TemplateEdge(
                source="if_body",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "else_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="else_body",
                dest="loop_header",
            ),
            exception_edge=TemplateEdge(
                source="else_body",
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

    def __init__(self, loop_header: ControlFlowTemplate, if_body: ControlFlowTemplate, else_body: ControlFlowTemplate):
        self.loop_header = loop_header
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

        matcher = GraphTemplateMatcher(template_node_dict=WhileTrueIfElseTemplate._subgraph, root_key="loop_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        loop_template = WhileTrueIfElseTemplate(
            loop_header=mapping["loop_header"],
            if_body=mapping["if_body"],
            else_body=mapping["else_body"],
        )

        in_edges = ((src, loop_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True) if src != mapping["if_body"] and src != mapping["else_body"])
        out_edges = []
        if mapping["exception_handler"]:
            out_edges.append((loop_template, mapping["exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([loop_template.loop_header, loop_template.if_body, loop_template.else_body])
        reduced_cfg.add_node(loop_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """

        if_else_template = IfElseTemplate(if_header=self.loop_header, if_body=self.if_body, else_body=self.else_body)
        body = ControlFlowTemplate._indent_multiline_string(if_else_template.to_indented_source(source_lines))
        return "\n".join(["while True: # inserted", body])

    def __repr__(self) -> str:
        return super().__repr__()
