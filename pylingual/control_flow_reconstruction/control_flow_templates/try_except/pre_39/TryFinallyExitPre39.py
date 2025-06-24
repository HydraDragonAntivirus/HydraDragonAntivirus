import networkx as nx

import itertools

from ...abstract.AbstractTemplate import ControlFlowTemplate
from ...abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable

from ....cfg_utils import ControlFlowEdgeType

from ...Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ...match_utils import optional_node, optional_edge, assert_in_degree, assert_instruction_opname, node_match_none, node_match_all, contains_opname_sequence

from ...subtemplates.OptionalExitSubtemplate import ExitSubTemplate


class Pre39TryFinallyExitTemplate(ControlFlowTemplate, AbstractNonSequentiable):
    r"""
    A `try` block with only a `finally` following it. But 3.8 and below. This has a similar structure to the with template.
       (0)                              only here because could not figure out a way to condense an exit without killing off the tail
        |
       (1)
       / e\     -->   (0123)
     (2)   \            |
       \   /           (4)
        (3)
    does not cover additional finally blocks that will be inserted in the bytecode as a result of returns / breaking out of loops
    """

    _subgraph = {
        "setup_finally": TemplateNode(
            node_verification_func=node_match_all(
                assert_instruction_opname("SETUP_FINALLY"),
                node_match_none(
                    contains_opname_sequence(
                        "POP_TOP",
                        "STORE_FAST",
                        "POP_TOP",
                    ),
                ),
            ),
            natural_edge=TemplateEdge(
                source="setup_finally",
                dest="try_body",
            ),
            exception_edge=TemplateEdge(source="setup_finally", dest="outer_exception_handler", edge_verification_func=optional_edge),
        ),
        "try_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="try_body",
                dest="begin_finally",
            ),
            exception_edge=TemplateEdge(
                source="try_body",
                dest="finally",
            ),
        ),
        "begin_finally": TemplateNode(
            subtemplate=ExitSubTemplate,
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="begin_finally",
                dest="finally",
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
            exception_edge=TemplateEdge(
                source="begin_finally",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "finally": TemplateNode(
            subtemplate=ExitSubTemplate,
            natural_edge=TemplateEdge(
                source="finally",
                dest="tail",
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
            exception_edge=TemplateEdge(
                source="finally",
                dest="outer_exception_handler",
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
        "outer_exception_handler": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(
                source="outer_exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="outer_exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="outer_exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
        ),
    }

    def __init__(
        self,
        setup_finally: ControlFlowTemplate,
        try_body: ControlFlowTemplate,
        begin_finally: ControlFlowTemplate,
        _finally: ControlFlowTemplate,
    ):
        self.setup_finally = setup_finally
        self.try_body = try_body
        self.begin_finally = begin_finally
        self._finally = _finally

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
        node = next(cfg.predecessors(node))

        matcher = GraphTemplateMatcher(
            template_node_dict=Pre39TryFinallyExitTemplate._subgraph,
            root_key="setup_finally",
            mapping_verification_func=None,
        )

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        finally_template = Pre39TryFinallyExitTemplate(
            setup_finally=mapping["setup_finally"],
            try_body=mapping["try_body"],
            begin_finally=mapping["begin_finally"],
            _finally=mapping["finally"],
        )

        in_edges = [(src, finally_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(finally_template.setup_finally, data=True)]
        # only preserve exception handling edges
        out_edges = []
        if mapping["outer_exception_handler"]:
            out_edges.append((finally_template, mapping["outer_exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        # if there is a tail add a natural out edge
        if mapping.get("tail", None):
            out_edges.append((finally_template, mapping["tail"], {"type": ControlFlowEdgeType.NATURAL.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from(
            [
                finally_template.setup_finally,
                finally_template.try_body,
                finally_template.begin_finally,
                finally_template._finally,
            ]
        )
        reduced_cfg.add_node(finally_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        # sometimes the setup finally is included in a linear sequence, so we need to include that source
        setup_finally = self.setup_finally.to_indented_source(source_lines)
        try_block = ControlFlowTemplate._indent_multiline_string(self.try_body.to_indented_source(source_lines))
        # pick one of the finally bodies to get the source code from
        finally_body = ControlFlowTemplate._indent_multiline_string(self._finally.to_indented_source(source_lines))

        if not finally_body:
            finally_body = ControlFlowTemplate._indent_multiline_string(self._finally.to_indented_source(source_lines))
        finally_lines = [setup_finally, "try:", try_block, "finally:", finally_body]
        return "\n".join(finally_lines)

    def __repr__(self) -> str:
        return super().__repr__()
