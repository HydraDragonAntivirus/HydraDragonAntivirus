import networkx as nx

import itertools

from ...abstract.AbstractTemplate import ControlFlowTemplate
from ...abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable
from ...abstract.AbstractExceptionBlockTemplate import AbstractExceptionBlockTemplate
from ...natural.LinearSequenceTemplate import LinearSequenceTemplate
from ...try_except.pre_39.TryFinallyPre39 import Pre39TryFinallyTemplate

from ....cfg_utils import ControlFlowEdgeType

from ...Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ...match_utils import optional_node, optional_edge, assert_in_degree, assert_except_as



class Pre39ExceptAsTemplate(ControlFlowTemplate, AbstractNonSequentiable, AbstractExceptionBlockTemplate):
    """
    An `except as` block, after its cleanup has been structured.
    If there are multiple, this will match the last block in the series and set up the next one to be matched
       (0)
       / \\j    -->   (012)
     (1)  (2)           |j
      |j               (3)
     (3)
    """

    _subgraph = {
        "except_as_header": TemplateNode(
            node_verification_func=assert_except_as,
            natural_edge=TemplateEdge(
                source="except_as_header",
                dest="except_setup",
            ),
            conditional_edge=TemplateEdge(source="except_as_header", dest="non_match_path"),
            exception_edge=TemplateEdge(source="except_as_header", dest="outer_exception_handler", edge_verification_func=optional_edge),
        ),
        "except_setup": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="except_setup",
                dest="except_body",
            ),
            exception_edge=TemplateEdge(source="except_setup", dest="outer_exception_handler", edge_verification_func=optional_edge),
        ),
        "except_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(source="except_body", dest="begin_finally", edge_verification_func=optional_edge),
            exception_edge=TemplateEdge(
                source="except_body",
                dest="cleanup",
            ),
        ),
        "begin_finally": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="begin_finally",
                dest="cleanup",
            ),
            exception_edge=TemplateEdge(source="begin_finally", dest="outer_exception_handler", edge_verification_func=optional_edge),
        ),
        "cleanup": TemplateNode(
            exception_edge=TemplateEdge(
                source="cleanup",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "non_match_path": TemplateNode(
            node_verification_func=assert_in_degree(1),
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

    def __init__(self, except_as_header: ControlFlowTemplate, except_setup: ControlFlowTemplate, except_body: ControlFlowTemplate, begin_finally: ControlFlowTemplate, cleanup: ControlFlowTemplate, non_match_path: ControlFlowTemplate):
        self.except_as_header = except_as_header
        self.except_setup = except_setup
        self.except_body = except_body
        self.begin_finally = begin_finally
        self.cleanup = cleanup
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

        matcher = GraphTemplateMatcher(template_node_dict=Pre39ExceptAsTemplate._subgraph, root_key="except_as_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        except_as_cleanup_template = Pre39ExceptAsTemplate(
            except_as_header=mapping["except_as_header"], except_setup=mapping["except_setup"], except_body=mapping["except_body"], begin_finally=mapping["begin_finally"], cleanup=mapping["cleanup"], non_match_path=mapping["non_match_path"]
        )

        in_edges = ((src, except_as_cleanup_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(node, data=True))
        # only preserve exception handling edges
        out_edges = []
        if mapping["outer_exception_handler"]:
            out_edges.append((except_as_cleanup_template, mapping["outer_exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from(
            [
                except_as_cleanup_template.except_as_header,
                except_as_cleanup_template.except_setup,
                except_as_cleanup_template.except_body,
                except_as_cleanup_template.begin_finally,
                except_as_cleanup_template.cleanup,
                except_as_cleanup_template.non_match_path,
            ]
        )
        reduced_cfg.add_node(except_as_cleanup_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        header = self.except_as_header.to_indented_source(source_lines)
        if isinstance(self.except_body, LinearSequenceTemplate):
            assert isinstance(self.except_body[0], Pre39TryFinallyTemplate)
            _body = self.except_body[0].try_body.to_indented_source(source_lines)
        else:
            assert isinstance(self.except_body, Pre39TryFinallyTemplate)
            _body = self.except_body.try_body.to_indented_source(source_lines)
        body = ControlFlowTemplate._indent_multiline_string(_body)
        non_match = self.non_match_path.to_indented_source(source_lines)
        return f"{header}\n{body}\n{non_match}"

    def __repr__(self) -> str:
        return super().__repr__()
