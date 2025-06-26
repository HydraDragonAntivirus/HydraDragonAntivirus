import networkx as nx



from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable


from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_edge, assert_in_degree, node_match_all, is_exactly_opname, contains_opname_sequence, node_match_any


class WithCleanup312(ControlFlowTemplate, AbstractNonSequentiable):
    _subgraph = {
        "start": TemplateNode(
            node_verification_func=node_match_any(
                is_exactly_opname("PUSH_EXC_INFO", "WITH_EXCEPT_START", "POP_JUMP_IF_TRUE"),
                is_exactly_opname("PUSH_EXC_INFO", "WITH_EXCEPT_START", "TO_BOOL", "POP_JUMP_IF_TRUE"),
            ),
            natural_edge=TemplateEdge(
                source="start",
                dest="reraise",
            ),
            conditional_edge=TemplateEdge(
                source="start",
                dest="poptop",
            ),
            exception_edge=TemplateEdge(source="start", dest="exc"),
        ),
        "reraise": TemplateNode(
            node_verification_func=node_match_all(is_exactly_opname("RERAISE"), assert_in_degree(1)),
            exception_edge=TemplateEdge(
                source="reraise",
                dest="exc",
            ),
        ),
        "poptop": TemplateNode(
            node_verification_func=node_match_all(is_exactly_opname("POP_TOP"), assert_in_degree(1)),
            natural_edge=TemplateEdge(
                source="poptop",
                dest="tail",
            ),
            exception_edge=TemplateEdge(
                source="poptop",
                dest="exc",
            ),
        ),
        "exc": TemplateNode(
            node_verification_func=node_match_all(is_exactly_opname("COPY", "POP_EXCEPT", "RERAISE"), assert_in_degree(3)),
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
        # to avoid being treated as an try-except, we actually need to greedily search up one layer
        node = next(cfg.predecessors(node))

        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(
            template_node_dict=WithCleanup312._subgraph,
            root_key="start",
            mapping_verification_func=None,
        )

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        with_template = WithCleanup312()

        in_edges = ((src, with_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from(mapping.values())
        reduced_cfg.add_node(with_template)
        reduced_cfg.add_edges_from(in_edges)
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        return ""

    def __repr__(self) -> str:
        return super().__repr__()
