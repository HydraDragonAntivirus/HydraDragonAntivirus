import networkx as nx

import itertools

from ...abstract.AbstractTemplate import ControlFlowTemplate
from ...abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable
from ...abstract.AbstractExceptionBlockTemplate import AbstractExceptionBlockTemplate

from ...subtemplates.OptionalExitSubtemplate import ExitSubTemplate

from ....cfg_utils import ControlFlowEdgeType

from ...Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ...match_utils import optional_node, optional_edge, assert_in_degree, node_is_none_or_matches, assert_instruction_opname, assert_node_type



class ExceptAsNonMatchSubTemplate311(ControlFlowTemplate, AbstractNonSequentiable, AbstractExceptionBlockTemplate):
    """
    The non-match path of an except-as, which can be:
    1. a standalone reraise (end of an except as chain)
    2. an except block, which may exit
    3. a structured except-as
    """

    _reraise_subgraph = {
        "reraise": TemplateNode(node_verification_func=assert_instruction_opname("RERAISE"), exception_edge=TemplateEdge(source="reraise", dest="panic_except")),
        "panic_except": TemplateNode(
            exception_edge=TemplateEdge(
                source="except_body",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            )
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

    _except_subgraph = {
        "except_body": TemplateNode(
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
        "except_footer": TemplateNode(
            subtemplate=ExitSubTemplate,
            node_verification_func=node_is_none_or_matches(assert_in_degree(1)),
            natural_edge=TemplateEdge(
                source="except_footer",
                dest="after_except",
                edge_verification_func=optional_edge,
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

    _structered_except_as_subgraph = {
        "except_as": TemplateNode(node_verification_func=assert_node_type(AbstractNonSequentiable), natural_edge=TemplateEdge(source="except_as", dest=None), exception_edge=TemplateEdge(source="except_as", dest="panic_except")),
        "panic_except": TemplateNode(
            exception_edge=TemplateEdge(
                source="except_body",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            )
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

    def __init__(self, except_body: ControlFlowTemplate, except_footer: ControlFlowTemplate):
        self.except_body = except_body
        self.except_footer = except_footer

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        # start by trying to match reraise
        matcher = GraphTemplateMatcher(template_node_dict=ExceptAsNonMatchSubTemplate311._reraise_subgraph, root_key="reraise", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if mapping:
            # single-node subgraph does not need to by updated
            return cfg

        # didn't match reraise; try to match structured except as
        matcher = GraphTemplateMatcher(template_node_dict=ExceptAsNonMatchSubTemplate311._structered_except_as_subgraph, root_key="except_as", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if mapping:
            # single-node subgraph does not need to by updated
            return cfg

        # didn't match structured except as; try to match except block
        matcher = GraphTemplateMatcher(template_node_dict=ExceptAsNonMatchSubTemplate311._except_subgraph, root_key="except_body", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        except_template = ExceptAsNonMatchSubTemplate311(except_body=mapping["except_body"], except_footer=mapping["except_footer"])

        in_edges = ((src, except_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(node, data=True))
        # only preserve exception handling edges
        out_edges = []
        if mapping["panic_except"]:
            out_edges.append((except_template, mapping["panic_except"], {"type": ControlFlowEdgeType.EXCEPTION.value}))
        if mapping["after_except"]:
            out_edges.append((except_template, mapping["after_except"], {"type": ControlFlowEdgeType.JUMP.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_node(except_template.except_body)
        if except_template.except_footer:
            reduced_cfg.remove_node(except_template.except_footer)
        reduced_cfg.add_node(except_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """

        except_lines = ["except:"]
        body = ControlFlowTemplate._indent_multiline_string(self.except_body.to_indented_source(source_lines))
        except_lines.append(body)
        footer = ControlFlowTemplate._indent_multiline_string(self.except_footer.to_indented_source(source_lines))
        except_lines.append(footer)

        return "\n".join(except_lines)

    def __repr__(self) -> str:
        return super().__repr__()
