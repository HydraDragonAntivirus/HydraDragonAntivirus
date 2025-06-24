import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree, assert_instruction_opname, node_match_all, assert_first_instruction_opname


class AsyncForTemplate(ControlFlowTemplate):
    """
    An async for loop.
      (-1)
       |  ^
      (0) |j
      | \\|           (-101)
     e|  (1)    -->    |
      |               (2)
      (2)

    optionally, all nodes in the pattern can have a shared exception handler.
    """

    _subgraph = {
        "loop_header": TemplateNode(
            node_verification_func=assert_instruction_opname("SETUP_FINALLY"),
            natural_edge=TemplateEdge(
                source="loop_header",
                dest="loop_iter",
            ),
            exception_edge=TemplateEdge(
                source="loop_header",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "loop_iter": TemplateNode(
            node_verification_func=node_match_all(assert_in_degree(1), assert_first_instruction_opname("GET_ANEXT")),
            natural_edge=TemplateEdge(
                source="loop_iter",
                dest="loop_body",
            ),
            exception_edge=TemplateEdge(
                source="loop_iter",
                dest="tail",
            ),
        ),
        "loop_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="loop_body",
                dest="loop_header",
            ),
            exception_edge=TemplateEdge(
                source="loop_body",
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

    def __init__(self, loop_header: ControlFlowTemplate, loop_iter: ControlFlowTemplate, loop_body: ControlFlowTemplate):
        self.loop_header = loop_header
        self.loop_iter = loop_iter
        self.loop_body = loop_body

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        if cfg.in_degree(node) != 1:
            return None

        # to avoid being treated as a try-except, we actually need to greedily search up one layer
        pred = next(cfg.predecessors(node))

        matcher = GraphTemplateMatcher(template_node_dict=AsyncForTemplate._subgraph, root_key="loop_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, pred)

        if not mapping:
            return None

        loop_template = AsyncForTemplate(loop_header=mapping["loop_header"], loop_iter=mapping["loop_iter"], loop_body=mapping["loop_body"])

        in_edges = ((src, loop_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=pred, data=True) if src != mapping["loop_body"])
        out_edges = [(loop_template, mapping["tail"], {"type": ControlFlowEdgeType.NATURAL.value})]
        if mapping["exception_handler"]:
            out_edges.append((loop_template, mapping["exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([loop_template.loop_header, loop_template.loop_iter, loop_template.loop_body])
        reduced_cfg.add_node(loop_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        header = self.loop_header.to_indented_source(source_lines)
        loop_iter = self.loop_iter.to_indented_source(source_lines)
        body = ControlFlowTemplate._indent_multiline_string(self.loop_body.to_indented_source(source_lines))
        return "\n".join([header, loop_iter, body])

    def __repr__(self) -> str:
        return super().__repr__()
