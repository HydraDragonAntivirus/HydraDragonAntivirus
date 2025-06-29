import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate

from ...cfg_utils import ControlFlowEdgeType, get_dominator_function

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree


class LoopTemplate(ControlFlowTemplate):
    """
    A natural non-infinite loop with no extra control flow.
      (0)
      | \\            (01)
     j|  (1)    -->    |
      |               (2)
      (2)

    optionally, all nodes in the pattern can have a shared exception handler.
    """

    _subgraph = {
        "loop_header": TemplateNode(
            natural_edge=TemplateEdge(
                source="loop_header",
                dest="loop_body",
            ),
            conditional_edge=TemplateEdge(
                source="loop_header",
                dest="tail",
            ),
            exception_edge=TemplateEdge(
                source="loop_header",
                dest="exception_handler",
                edge_verification_func=optional_edge,
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

    def __init__(self, loop_header: ControlFlowTemplate, loop_body: ControlFlowTemplate):
        self.loop_header = loop_header
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

        def verify_tail_not_in_loop(cfg: nx.DiGraph, mapping: dict) -> bool:
            dominates = get_dominator_function(cfg)
            # subgraph containing all nodes dominated by the loop header
            dominated_subgraph: nx.DiGraph = cfg.subgraph(n for n in cfg.nodes if dominates(mapping["loop_header"], n))
            reverse_reachability_map = nx.single_source_shortest_path_length(dominated_subgraph.reverse(), source=mapping["loop_header"])
            # a node is in the loop if there is a backwards path to the header that doesn't leave the loop
            loop_nodes = [loop_node for loop_node, distance in reverse_reachability_map.items() if distance >= 0]
            return mapping["tail"] not in loop_nodes

        matcher = GraphTemplateMatcher(template_node_dict=LoopTemplate._subgraph, root_key="loop_header", mapping_verification_func=verify_tail_not_in_loop)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        loop_template = LoopTemplate(loop_header=mapping["loop_header"], loop_body=mapping["loop_body"])

        in_edges = ((src, loop_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True) if src != mapping["loop_body"])
        out_edges = [(loop_template, mapping["tail"], {"type": ControlFlowEdgeType.NATURAL.value})]
        if mapping["exception_handler"]:
            out_edges.append((loop_template, mapping["exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([loop_template.loop_header, loop_template.loop_body])
        reduced_cfg.add_node(loop_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        header = self.loop_header.to_indented_source(source_lines)
        body = ControlFlowTemplate._indent_multiline_string(self.loop_body.to_indented_source(source_lines))
        return "\n".join([header, body])

    def __repr__(self) -> str:
        return super().__repr__()
