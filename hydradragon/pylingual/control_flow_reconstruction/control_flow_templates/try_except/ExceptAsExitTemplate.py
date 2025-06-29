import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable
from ..abstract.AbstractExceptionBlockTemplate import AbstractExceptionBlockTemplate


from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge, assert_in_degree, assert_except_as, node_match_all, node_match_any, contains_opname_sequence



class ExceptAsExitTemplate(ControlFlowTemplate, AbstractNonSequentiable, AbstractExceptionBlockTemplate):
    """
    An `except as` block, but with an exit statement.
    If there are multiple, this will match the last block in the series and set up the next one to be matched
       (0)
       / \\j    -->   (01234)
     (1)  (2)
      |
     (3)
      |e
     (4)
    """

    _subgraph = {
        "except_as_header": TemplateNode(
            node_verification_func=assert_except_as,
            natural_edge=TemplateEdge(
                source="except_as_header",
                dest="except_body_setup",
            ),
            conditional_edge=TemplateEdge(source="except_as_header", dest="non_match_path"),
            exception_edge=TemplateEdge(source="except_as_header", dest="outer_exception_handler", edge_verification_func=optional_edge),
        ),
        "except_body_setup": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(source="except_body_setup", dest="except_body", edge_verification_func=optional_edge),
            exception_edge=TemplateEdge(
                source="except_body_setup",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "except_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            exception_edge=TemplateEdge(
                source="except_body",
                dest="except_as_cleanup",
                edge_verification_func=optional_edge,
            ),
        ),
        "except_as_cleanup": TemplateNode(
            node_verification_func=node_match_all(
                assert_in_degree(1),
                node_match_any(
                    contains_opname_sequence("LOAD_CONST", "STORE_NAME", "DELETE_NAME", "RERAISE"),
                    contains_opname_sequence("LOAD_CONST", "STORE_FAST", "DELETE_FAST", "RERAISE"),
                    contains_opname_sequence("LOAD_CONST", "STORE_NAME", "DELETE_NAME", "END_FINALLY"),
                    contains_opname_sequence("LOAD_CONST", "STORE_FAST", "DELETE_FAST", "END_FINALLY"),
                ),
            ),
            exception_edge=TemplateEdge(
                source="except_as_cleanup",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "non_match_path": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="non_match_path",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="non_match_path",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="non_match_path",
                dest="outer_exception_handler",
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

    def __init__(self, except_as_header: ControlFlowTemplate, except_body_setup: ControlFlowTemplate, except_body: ControlFlowTemplate, except_as_cleanup: ControlFlowTemplate, non_match_path: ControlFlowTemplate):
        self.except_as_header = except_as_header
        self.except_body_setup = except_body_setup
        self.except_body = except_body
        self.except_as_cleanup = except_as_cleanup
        self.non_match_path = non_match_path

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=ExceptAsExitTemplate._subgraph, root_key="except_as_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        except_as_exit_template = ExceptAsExitTemplate(
            except_as_header=mapping["except_as_header"], except_body_setup=mapping["except_body_setup"], except_body=mapping["except_body"], except_as_cleanup=mapping["except_as_cleanup"], non_match_path=mapping["non_match_path"]
        )

        in_edges = ((src, except_as_exit_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(node, data=True))
        out_edges = ((except_as_exit_template, dst, edge_properties) for src, dst, edge_properties in cfg.out_edges(except_as_exit_template.non_match_path, data=True))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from(
            [except_as_exit_template.except_as_header, except_as_exit_template.except_body_setup, except_as_exit_template.except_body, except_as_exit_template.except_as_cleanup, except_as_exit_template.non_match_path]
        )
        reduced_cfg.add_node(except_as_exit_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        header = self.except_as_header.to_indented_source(source_lines) + self.except_body_setup.to_indented_source(source_lines)
        body = ControlFlowTemplate._indent_multiline_string(self.except_body.to_indented_source(source_lines))
        non_match = self.non_match_path.to_indented_source(source_lines)
        return f"{header}\n{body}\n{non_match}"

    def __repr__(self) -> str:
        return super().__repr__()
