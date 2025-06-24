import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..natural.InstructionTemplate import InstructionTemplate
from ..natural.LinearSequenceTemplate import LinearSequenceTemplate

from ..subtemplates.OptionalExitSubtemplate import ExitSubTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree, assert_node_has_no_backwards_edges, node_match_all, assert_except_as, node_match_none


class IfThenTemplate(ControlFlowTemplate):
    """
    A standard if-block with no extra control flow.
      (0)
      | \\            (01)
     j|  (1)    -->    |
      | /             (2)
      (2)

    optionally, all nodes in the pattern can have a shared exception handler.

    Interestingly, this template also covers loops with guaranteed breaks.
    """

    _subgraph = {
        "if_header": TemplateNode(
            node_verification_func=node_match_none(assert_except_as),
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
                commit_none_to_mapping=False,
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
                dest=None,
                commit_none_to_mapping=False,
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

        matcher = GraphTemplateMatcher(template_node_dict=IfThenTemplate._subgraph, root_key="if_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        if_then_template = IfThenTemplate(if_header=mapping["if_header"], if_body=mapping["if_body"])

        in_edges = ((src, if_then_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = [(if_then_template, mapping["tail"], {"type": ControlFlowEdgeType.NATURAL.value})]
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
        """
        if header.startswith('while ') and isinstance(self.if_body, RefinedLoopTemplate) and isinstance(self.if_body.loop_header, WhileTruePlaceholderTemplate):
            if isinstance(self.if_body.loop_body, LinearSequenceTemplate):
                last = self.if_body.loop_body.members[-1]
            else:
                last = self.if_body.loop_body
            assert isinstance(last, IfElseTemplate)
            last.to_indented_source = last.if_header.to_indented_source
            self.if_body.loop_header.to_indented_source = lambda x: ''
        if isinstance(self.if_body, LoopExitTemplate) and not header.startswith('if '):
            body = ''
        else:
            body = ControlFlowTemplate._indent_multiline_string(self.if_body.to_indented_source(source_lines))
            """
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
