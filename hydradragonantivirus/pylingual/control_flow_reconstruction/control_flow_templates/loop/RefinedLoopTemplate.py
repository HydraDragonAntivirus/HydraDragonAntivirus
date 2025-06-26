import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate
from .PreRefinedLoopTemplate import PreRefinedLoopTemplate
from ..placeholders.WhileTruePlaceholderTemplate import WhileTruePlaceholderTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree


class RefinedLoopTemplate(ControlFlowTemplate):
    """
    The second stage of matching loops with breaks an continues; matches fully-structured PreRefinedLoopTemplates.
       (0) = PreRefinedLoopTemplate
      // \\j    -->   (01)
     (1)  (2)          |
                      (2)

    optionally, all nodes in the pattern can have a shared exception handler.
    """

    _subgraph = {
        "pre_refined_loop": TemplateNode(
            natural_edge=TemplateEdge(
                source="pre_refined_loop",
                dest="loop_body",
            ),
            conditional_edge=TemplateEdge(source="pre_refined_loop", dest="loop_successor", edge_verification_func=optional_edge),
            exception_edge=TemplateEdge(
                source="pre_refined_loop",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "loop_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            exception_edge=TemplateEdge(
                source="loop_body",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "loop_successor": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(
                source="loop_successor",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="loop_successor",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="loop_successor",
                dest="exception_handler",
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
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

    def __init__(self, loop_header: ControlFlowTemplate, loop_body: ControlFlowTemplate, loop_else: ControlFlowTemplate, has_successor: bool = True):
        self.loop_header = loop_header
        self.loop_body = loop_body
        self.loop_else = loop_else
        self.has_successor = has_successor

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        # this pattern is only for matching on PreRefinedLoops
        if not isinstance(node, PreRefinedLoopTemplate):
            return None

        matcher = GraphTemplateMatcher(template_node_dict=RefinedLoopTemplate._subgraph, root_key="pre_refined_loop", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        loop_template = RefinedLoopTemplate(loop_header=mapping["pre_refined_loop"].loop_header, loop_body=mapping["loop_body"], loop_else=mapping["pre_refined_loop"].loop_else, has_successor=bool(mapping["loop_successor"]))

        in_edges = ((src, loop_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = []
        if mapping["loop_successor"]:
            out_edges.append((loop_template, mapping["loop_successor"], {"type": ControlFlowEdgeType.NATURAL.value}))
        if mapping["exception_handler"]:
            out_edges.append((loop_template, mapping["exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([mapping["pre_refined_loop"], loop_template.loop_body])
        reduced_cfg.add_node(loop_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        loop_lines = []
        header = self.loop_header.to_indented_source(source_lines)
        if not self.has_successor and not isinstance(self.loop_header, WhileTruePlaceholderTemplate):
            header = ControlFlowTemplate._indent_multiline_string(header)
            loop_lines.append("while True: # inserted")
        loop_body = ControlFlowTemplate._indent_multiline_string(self.loop_body.to_indented_source(source_lines))
        loop_lines.extend([header, loop_body])
        if self.loop_else:
            loop_else = ControlFlowTemplate._indent_multiline_string(self.loop_else.to_indented_source(source_lines))
            loop_lines.extend(["else: # inserted", loop_else])

        return "\n".join(loop_lines)

    def __repr__(self) -> str:
        return super().__repr__()
