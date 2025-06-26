import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..natural.InstructionTemplate import InstructionTemplate
from ..natural.LinearSequenceTemplate import LinearSequenceTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree, assert_unconditional_jump


class IfThenJumpTemplate(ControlFlowTemplate):
    """
    A standard if-block with no extra control flow.
    This variant has an absolute jump from the end of the if body to the outside.
    This occurs when there are nested if-else blocks and the inner if statements jump out directly to the top level.
      (0)
      | \\            (01)
     j|  (1)    -->    |
      |   |           (2)
      |  (2)           |j
      | /j            (3)
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
                dest="tail",
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
                dest="jump",
            ),
            exception_edge=TemplateEdge(
                source="if_body",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "jump": TemplateNode(
            node_verification_func=assert_unconditional_jump,
            natural_edge=TemplateEdge(
                source="jump",
                dest="tail",
            ),
            exception_edge=TemplateEdge(
                source="jump",
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
            exception_edge=TemplateEdge(
                source="tail",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="tail",
                dest=None,
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

    def __init__(self, if_header: ControlFlowTemplate, if_body: ControlFlowTemplate):
        self.if_header = if_header
        self.if_body = if_body

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=IfThenJumpTemplate._subgraph, root_key="if_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        if_then_template = IfThenJumpTemplate(if_header=mapping["if_header"], if_body=mapping["if_body"])

        in_edges = ((src, if_then_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = [(if_then_template, mapping["jump"], {"type": ControlFlowEdgeType.NATURAL.value})]
        if mapping["exception_handler"]:
            out_edges.append((if_then_template, mapping["exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([if_then_template.if_header, if_then_template.if_body])
        reduced_cfg.add_node(if_then_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        header = self.if_header.to_indented_source(source_lines).strip()
        body = ControlFlowTemplate._indent_multiline_string(self.if_body.to_indented_source(source_lines))

        if_lines = [header, body]

        # edge case hack to deal with for loops that have guaranteed breaks (they look exactly like if statements)
        # while loops should be translated as if statements in this case, so we don't have to worry there
        if isinstance(self.if_header, LinearSequenceTemplate):
            last_member = self.if_header.members[-1]
            if isinstance(last_member, InstructionTemplate) and last_member.instruction.opname == "FOR_ITER":
                if_lines.insert(2, "\tbreak # inserted")

        return "\n".join(if_lines)

    def __repr__(self) -> str:
        return super().__repr__()
