import networkx as nx

import itertools


from ..abstract.AbstractTemplate import ControlFlowTemplate


from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_edge, assert_in_degree, node_match_all, is_exactly_opname, contains_opname_sequence


class AsyncWithCleanup312(ControlFlowTemplate):
    _subgraph = {
        "start": TemplateNode(
            node_verification_func=is_exactly_opname("PUSH_EXC_INFO", "WITH_EXCEPT_START", "GET_AWAITABLE", "LOAD_CONST"),
            natural_edge=TemplateEdge(
                source="start",
                dest="send",
            ),
            exception_edge=TemplateEdge(source="start", dest="exc"),
        ),
        "send": TemplateNode(
            node_verification_func=node_match_all(is_exactly_opname("SEND"), assert_in_degree(2)),
            natural_edge=TemplateEdge(
                source="send",
                dest="yield",
            ),
            conditional_edge=TemplateEdge(
                source="send",
                dest="ifthen",
            ),
            exception_edge=TemplateEdge(
                source="send",
                dest="exc",
            ),
        ),
        "yield": TemplateNode(
            node_verification_func=node_match_all(is_exactly_opname("YIELD_VALUE"), assert_in_degree(1)), natural_edge=TemplateEdge(source="yield", dest="jump_back"), exception_edge=TemplateEdge(source="yield", dest="ifthen")
        ),
        "jump_back": TemplateNode(
            node_verification_func=node_match_all(is_exactly_opname("JUMP_BACKWARD_NO_INTERRUPT"), assert_in_degree(1)), natural_edge=TemplateEdge(source="jump_back", dest="send"), exception_edge=TemplateEdge(source="jump_back", dest="exc")
        ),
        "ifthen": TemplateNode(
            node_verification_func=node_match_all(is_exactly_opname("CLEANUP_THROW", "END_SEND", "POP_JUMP_IF_TRUE", "RERAISE", "POP_TOP"), assert_in_degree(2)),
            natural_edge=TemplateEdge(source="ifthen", dest="tail"),
            exception_edge=TemplateEdge(
                source="ifthen",
                dest="exc",
            ),
        ),
        "exc": TemplateNode(
            node_verification_func=node_match_all(is_exactly_opname("COPY", "POP_EXCEPT", "RERAISE"), assert_in_degree(4)),
            natural_edge=TemplateEdge(
                source="exc",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="exc",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="exc",
                dest=None,
                edge_verification_func=optional_edge,
            ),
        ),
        "tail": TemplateNode(
            node_verification_func=node_match_all(contains_opname_sequence("POP_EXCEPT", "POP_TOP", "POP_TOP"), assert_in_degree(1)),
            natural_edge=TemplateEdge(
                source="tail",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="tail",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="tail",
                dest=None,
                edge_verification_func=optional_edge,
            ),
        ),
    }

    def __init__(self):
        pass

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(
            template_node_dict=AsyncWithCleanup312._subgraph,
            root_key="start",
            mapping_verification_func=None,
        )

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        with_template = AsyncWithCleanup312()

        in_edges = ((src, with_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        # out_edges = ((with_template, dst, edge_properties) for src, dst, edge_properties in cfg.out_edges(nbunch=mapping['exc'], data=True))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from(mapping.values())
        reduced_cfg.add_node(with_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        return ""

    def __repr__(self) -> str:
        return super().__repr__()
