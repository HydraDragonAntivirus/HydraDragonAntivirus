import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate


from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import assert_in_degree, node_match_all


def is_cleanup(cfg: nx.DiGraph, node) -> bool:
    i = node.get_instructions()
    return len(i) == 2 and i[0].opname == "CALL_INTRINSIC_1" and i[1].opname == "RERAISE"


class GeneratorCleanupTemplate(ControlFlowTemplate):
    _subgraph = {
        "generator": TemplateNode(
            exception_edge=TemplateEdge(
                source="generator",
                dest="cleanup",
            )
        ),
        "cleanup": TemplateNode(
            node_verification_func=node_match_all(assert_in_degree(1), is_cleanup),
        ),
    }

    def __init__(self, generator: ControlFlowTemplate, cleanup: ControlFlowTemplate):
        self.generator = generator
        self.cleanup = cleanup

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=GeneratorCleanupTemplate._subgraph, root_key="generator", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        template = GeneratorCleanupTemplate(generator=mapping["generator"], cleanup=mapping["cleanup"])

        in_edges = ((src, template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = ((template, dst, edge_properties) for src, dst, edge_properties in cfg.out_edges(nbunch=node, data=True) if dst != mapping["cleanup"])

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([template.cleanup, template.generator])
        reduced_cfg.add_node(template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        return self.generator.to_indented_source(source_lines)

    def __repr__(self) -> str:
        return super().__repr__()
