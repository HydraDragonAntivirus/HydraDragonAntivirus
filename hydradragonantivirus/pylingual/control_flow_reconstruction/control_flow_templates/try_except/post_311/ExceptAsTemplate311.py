import networkx as nx

import itertools

from ...abstract.AbstractTemplate import ControlFlowTemplate
from ...abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable
from ...abstract.AbstractExceptionBlockTemplate import AbstractExceptionBlockTemplate


from ...subtemplates.OptionalExitSubtemplate import ExitSubTemplate
from .ExceptAsNonMatchSubtemplate311 import ExceptAsNonMatchSubTemplate311
from .ExceptAsCleanupSubTemplate311 import ExceptAsCleanupSubTemplate311

from ....cfg_utils import ControlFlowEdgeType

from ...Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ...match_utils import optional_node, optional_edge, assert_in_degree, assert_except_as



class ExceptAsTemplate311(ControlFlowTemplate, AbstractNonSequentiable, AbstractExceptionBlockTemplate):
    """
    An `except as` block, after its cleanup has been structured.
    If there are multiple, this will match the last block in the series and set up the next one to be matched
       (0)
       / \\j    -->   (0123)
     (1)  (2)           |j
      |                (4)
     (3)
      |j
     (4)

    0,1,2 all have an exception edge to the panic cleanup from the current try block
    """

    _subgraph = {
        "except_as_header": TemplateNode(
            node_verification_func=assert_except_as,
            natural_edge=TemplateEdge(
                source="except_as_header",
                dest="except_body",
            ),
            conditional_edge=TemplateEdge(source="except_as_header", dest="non_match_path"),
            exception_edge=TemplateEdge(
                source="except_as_header",
                dest="panic_except",
            ),
        ),
        "except_body": TemplateNode(
            subtemplate=ExceptAsCleanupSubTemplate311,
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="except_body",
                dest="except_footer",
            ),
            exception_edge=TemplateEdge(
                source="except_body",
                dest="panic_except",
            ),
        ),
        "non_match_path": TemplateNode(
            subtemplate=ExceptAsNonMatchSubTemplate311,
            node_verification_func=assert_in_degree(1),
            exception_edge=TemplateEdge(
                source="non_match_path",
                dest="panic_except",
            ),
            natural_edge=TemplateEdge(
                edge_verification_func=optional_edge,
                source="non_match_path",
                dest="after_except",
                commit_none_to_mapping=False,
            ),
        ),
        "except_footer": TemplateNode(
            subtemplate=ExitSubTemplate,
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="except_footer",
                dest="after_except",
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
            exception_edge=TemplateEdge(
                source="except_footer",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "panic_except": TemplateNode(
            exception_edge=TemplateEdge(
                source="except_body",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            )
        ),
        "after_except": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(
                source="after_except",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="after_except",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="after_except",
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

    def __init__(self, except_as_header: ControlFlowTemplate, except_body: ControlFlowTemplate, except_footer: ControlFlowTemplate, non_match_path: ControlFlowTemplate):
        self.except_as_header = except_as_header
        self.except_body = except_body
        self.except_footer = except_footer
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

        matcher = GraphTemplateMatcher(template_node_dict=ExceptAsTemplate311._subgraph, root_key="except_as_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        except_as_template = ExceptAsTemplate311(except_as_header=mapping["except_as_header"], except_body=mapping["except_body"], except_footer=mapping["except_footer"], non_match_path=mapping["non_match_path"])

        in_edges = ((src, except_as_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(node, data=True))
        # only preserve exception handling edges
        out_edges = []
        if mapping["panic_except"]:
            out_edges.append((except_as_template, mapping["panic_except"], {"type": ControlFlowEdgeType.EXCEPTION.value}))
        if mapping.get("after_except", None):
            out_edges.append((except_as_template, mapping["after_except"], {"type": ControlFlowEdgeType.JUMP.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([except_as_template.except_as_header, except_as_template.except_body, except_as_template.except_footer, except_as_template.non_match_path])
        reduced_cfg.add_node(except_as_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        except_lines = []

        header = self.except_as_header.to_indented_source(source_lines)
        except_lines.append(header)

        body = ControlFlowTemplate._indent_multiline_string(self.except_body.to_indented_source(source_lines))
        except_lines.append(body)

        footer = ControlFlowTemplate._indent_multiline_string(self.except_footer.to_indented_source(source_lines))
        except_lines.append(footer)

        non_match = self.non_match_path.to_indented_source(source_lines)
        except_lines.append(non_match)

        return "\n".join(except_lines)

    def __repr__(self) -> str:
        return super().__repr__()
