import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..natural.InstructionTemplate import InstructionTemplate

from ..subtemplates.OptionalExitSubtemplate import ExitSubTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree, node_match_all, assert_node_has_no_backwards_edges, node_match_none, assert_except_as, is_exactly_opname

from ..natural.LinearSequenceTemplate import LinearSequenceTemplate


class IfElseTemplate(ControlFlowTemplate):
    """
    A standard if-else-block with no extra control flow.
       (0)
      j/ \\           (012)
     (1)  (2)    -->    |
      \\  /j           (3)
       (3)

    optionally, all nodes in the pattern can have a shared exception handler.

    Interestingly, this template also covers loops with guaranteed breaks and an else block.
    """

    _subgraph = {
        "if_header": TemplateNode(
            node_verification_func=node_match_none(assert_except_as, is_exactly_opname("CLEANUP_THROW", "END_SEND", "POP_JUMP_IF_TRUE")),
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
            subtemplate=ExitSubTemplate,
            node_verification_func=node_match_all(
                assert_in_degree(1),
                assert_node_has_no_backwards_edges,
            ),
            natural_edge=TemplateEdge(
                source="if_body",
                dest="tail",
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
            exception_edge=TemplateEdge(
                source="if_body",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "else_body": TemplateNode(
            subtemplate=ExitSubTemplate,
            node_verification_func=node_match_all(
                assert_in_degree(1),
                assert_node_has_no_backwards_edges,
            ),
            natural_edge=TemplateEdge(
                source="else_body",
                dest="tail",
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
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
                commit_none_to_mapping=False,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="tail",
                dest="exception_handler",
                commit_none_to_mapping=False,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="tail",
                dest=None,
                commit_none_to_mapping=False,
                edge_verification_func=optional_edge,
            ),
        ),
        "exception_handler": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(
                source="exception_handler",
                dest=None,
                commit_none_to_mapping=False,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="exception_handler",
                commit_none_to_mapping=False,
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="exception_handler",
                commit_none_to_mapping=False,
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

        matcher = GraphTemplateMatcher(template_node_dict=IfElseTemplate._subgraph, root_key="if_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        if_else_template = IfElseTemplate(if_header=mapping["if_header"], if_body=mapping["if_body"], else_body=mapping["else_body"])

        in_edges = ((src, if_else_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        if "tail" in mapping:
            out_edges = [(if_else_template, mapping["tail"], {"type": ControlFlowEdgeType.NATURAL.value})]
        else:
            out_edges = []
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
        if_lines = []
        header = self.if_header.to_indented_source(source_lines).rstrip()
        if header and header.split("\n")[-1].strip().startswith("assert "):
            return "\n".join([header, self.if_body.to_indented_source(source_lines), self.else_body.to_indented_source(source_lines)])
        if header:
            if_lines.append(header)
        if_body = ControlFlowTemplate._indent_multiline_string(self.if_body.to_indented_source(source_lines))
        if if_body:
            if_lines.append(if_body)
        else_body = ControlFlowTemplate._indent_multiline_string(self.else_body.to_indented_source(source_lines))
        if else_body:
            if_lines.extend(["else: # inserted", else_body])

        # edge case hack to deal with for loops that have guaranteed breaks (they look exactly like if statements)
        # while loops should be translated as if statements in this case, so we don't have to worry there
        if isinstance(self.if_header, LinearSequenceTemplate):
            last_member = self.if_header.members[-1]
            if isinstance(last_member, InstructionTemplate) and last_member.instruction.opname == "FOR_ITER":
                if_lines.insert(2, "\tbreak # inserted")

        return "\n".join(if_lines)

    def __repr__(self) -> str:
        return super().__repr__()
