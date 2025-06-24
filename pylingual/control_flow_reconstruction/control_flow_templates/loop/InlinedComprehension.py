import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree, node_match_all


def is_cleanup(cfg: nx.DiGraph, node: ControlFlowTemplate) -> bool:
    insts = node.get_instructions()
    if not insts or insts[-1].opname != "RERAISE":
        return False
    if [i.opname for i in insts[:3]] != ["SWAP", "POP_TOP", "SWAP"]:
        return False
    return all(i.opname == "STORE_FAST" for i in insts[3:-1])


class InlinedComprehensionTemplate(ControlFlowTemplate):
    _subgraph = {
        "comp": TemplateNode(
            natural_edge=TemplateEdge(
                source="comp",
                dest="tail",
            ),
            exception_edge=TemplateEdge(
                source="comp",
                dest="cleanup",
            ),
        ),
        "cleanup": TemplateNode(
            node_verification_func=node_match_all(assert_in_degree(1), is_cleanup),
            exception_edge=TemplateEdge(
                source="cleanup",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "tail": TemplateNode(
            natural_edge=TemplateEdge(source="tail", dest=None, edge_verification_func=optional_edge),
            conditional_edge=TemplateEdge(source="tail", dest=None, edge_verification_func=optional_edge),
            exception_edge=TemplateEdge(source="tail", dest="exception_handler", edge_verification_func=optional_edge),
        ),
        "exception_handler": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(source="exception_handler", dest=None, edge_verification_func=optional_edge),
            conditional_edge=TemplateEdge(source="exception_handler", dest=None, edge_verification_func=optional_edge),
            exception_edge=TemplateEdge(source="exception_handler", dest=None, edge_verification_func=optional_edge),
        ),
    }

    def __init__(self, comp: ControlFlowTemplate, cleanup: ControlFlowTemplate):
        self.comp = comp
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

        matcher = GraphTemplateMatcher(template_node_dict=InlinedComprehensionTemplate._subgraph, root_key="comp", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        template = InlinedComprehensionTemplate(comp=mapping["comp"], cleanup=mapping["cleanup"])

        in_edges = ((src, template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = [(template, mapping["tail"], {"type": ControlFlowEdgeType.NATURAL.value})]
        if mapping["exception_handler"]:
            out_edges.append((template, mapping["exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([template.comp, template.cleanup])
        reduced_cfg.add_node(template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        return ""

    def __repr__(self) -> str:
        return super().__repr__()
