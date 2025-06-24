import networkx as nx

import itertools


from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree, assert_with, node_match_all
from ..subtemplates.OptionalExitSubtemplate import ExitSubTemplate


class WithTemplate(ControlFlowTemplate, AbstractNonSequentiable):
    r"""

    A basic with template as a catch for normal withs

             (0)               node 2 may point to an outer exception handler
              |
             (1)
          e/  |
         /   (2)
         \    |
           (3)
    """

    _subgraph = {
        "setup_with": TemplateNode(
            node_verification_func=assert_with,
            natural_edge=TemplateEdge(
                source="setup_with",
                dest="body",
            ),
            exception_edge=TemplateEdge(
                source="setup_with",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="body",
                dest="begin_finally",
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,  # since it is possible to not have a begin finally block we need to commit it to mapping
            ),
            exception_edge=TemplateEdge(source="body", dest="with_cleanup"),
        ),
        "begin_finally": TemplateNode(
            subtemplate=ExitSubTemplate,
            node_verification_func=node_match_all(
                optional_node,
                assert_in_degree(1),
            ),
            natural_edge=TemplateEdge(
                source="begin_finally",
                dest="with_cleanup",
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,  # if the destination node is None, don't commit to the mapping
            ),
            exception_edge=TemplateEdge(source="begin_finally", dest="exception_handler", edge_verification_func=optional_edge),
        ),
        "with_cleanup": TemplateNode(
            natural_edge=TemplateEdge(
                source="with_cleanup",
                dest="tail",
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="with_cleanup",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "tail": TemplateNode(
            node_verification_func=optional_node,
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

    def __init__(self, setup_with: ControlFlowTemplate, body: ControlFlowTemplate, begin_finally: ControlFlowTemplate, with_cleanup: ControlFlowTemplate):
        self.setup_with = setup_with
        self.body = body
        self.begin_finally = begin_finally
        self.with_cleanup = with_cleanup

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
            template_node_dict=WithTemplate._subgraph,
            root_key="setup_with",
            mapping_verification_func=None,
        )

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        with_template = WithTemplate(
            setup_with=mapping["setup_with"],
            body=mapping["body"],
            begin_finally=mapping.get("begin_finally", None),
            with_cleanup=mapping["with_cleanup"],
        )

        in_edges = ((src, with_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = []
        if mapping["tail"]:
            out_edges.append((with_template, mapping["tail"], {"type": ControlFlowEdgeType.NATURAL.value}))
        else:
            out_edges.extend([(with_template, dst, edge_properties) for src, dst, edge_properties in cfg.out_edges(nbunch=mapping["with_cleanup"], data=True)])
        if mapping["exception_handler"]:
            out_edges.append((with_template, mapping["exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([with_template.setup_with, with_template.body, with_template.begin_finally, with_template.with_cleanup])
        reduced_cfg.add_node(with_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        header = self.setup_with.to_indented_source(source_lines)
        body = self.body._indent_multiline_string(self.body.to_indented_source(source_lines))
        # cleanup = self.with_cleanup.to_indented_source(source_lines)
        return f"{header}\n{body}"

    def __repr__(self) -> str:
        return super().__repr__()
