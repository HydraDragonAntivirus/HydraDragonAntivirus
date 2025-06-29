import networkx as nx

import itertools

from ...abstract.AbstractTemplate import ControlFlowTemplate
from ...abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable
from ...abstract.AbstractExceptionBlockTemplate import AbstractExceptionBlockTemplate

from ...natural.InstructionTemplate import InstructionTemplate


from ....cfg_utils import ControlFlowEdgeType

from ...Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ...match_utils import (
    optional_node,
    optional_edge,
    assert_in_degree,
    node_match_all,
    assert_first_instruction_opname,
    ends_with_opname_sequence,
    is_exactly_opname,
    node_match_any,
)



class ExceptTemplate311(ControlFlowTemplate):
    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        if isinstance(node, InstructionTemplate) and node.instruction.opname == "RERAISE":
            return cfg
        if isinstance(node, ExceptETemplate311):
            return cfg
        new_cfg = ExceptETemplate311.try_to_match_node(cfg, node)
        if new_cfg is not None:
            return new_cfg
        new_cfg = BareExcept311.try_to_match_node(cfg, node)
        if new_cfg is not None:
            return new_cfg


class Footer(ControlFlowTemplate):
    _subgraph = {
        "swap": TemplateNode(node_verification_func=node_match_all(is_exactly_opname("SWAP"), assert_in_degree(1)), natural_edge=TemplateEdge(source="swap", dest="footer"), exception_edge=TemplateEdge(source="swap", dest="panic")),
        "footer": TemplateNode(
            natural_edge=TemplateEdge(source="footer", dest=None, edge_verification_func=optional_edge),
            conditional_edge=TemplateEdge(source="footer", dest=None, edge_verification_func=optional_edge),
            exception_edge=TemplateEdge(source="footer", dest=None, edge_verification_func=optional_edge),
        ),
        "panic": TemplateNode(node_verification_func=is_exactly_opname("COPY", "POP_EXCEPT", "RERAISE"), exception_edge=TemplateEdge(source="panic", dest=None, edge_verification_func=optional_edge)),
    }

    def __init__(self, footer):
        self.footer = footer

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=Footer._subgraph, root_key="swap", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return cfg

        template = Footer(mapping["footer"])

        edges = [(next(cfg.predecessors(node)), template, {"type": ControlFlowEdgeType.NATURAL.value})]
        edges.extend((template, dst, prop) for src, dst, prop in cfg.out_edges(mapping["footer"], data=True))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from((node, mapping["footer"]))
        reduced_cfg.add_node(template)
        reduced_cfg.add_edges_from(edges)
        return reduced_cfg

    def to_indented_source(self, source_lines):
        return self.footer.to_indented_source(source_lines)


class ExceptBody(ControlFlowTemplate):
    _subgraph = {
        "store": TemplateNode(
            node_verification_func=node_match_any(is_exactly_opname("STORE_FAST"), is_exactly_opname("STORE_NAME")),
            natural_edge=TemplateEdge(
                source="store",
                dest="body",
            ),
            exception_edge=TemplateEdge(
                source="store",
                dest="panic",
            ),
        ),
        "body": TemplateNode(
            natural_edge=TemplateEdge(
                source="body",
                dest="footer",
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
            exception_edge=TemplateEdge(
                source="body",
                dest="cleanup",
            ),
        ),
        "cleanup": TemplateNode(
            node_verification_func=node_match_any(
                is_exactly_opname("LOAD_CONST", "STORE_FAST", "DELETE_FAST", "RERAISE"),
                is_exactly_opname("LOAD_CONST", "STORE_NAME", "DELETE_NAME", "RERAISE"),
            ),
            exception_edge=TemplateEdge(source="cleanup", dest="panic"),
        ),
        "panic": TemplateNode(exception_edge=TemplateEdge(source="panic", dest=None, edge_verification_func=optional_edge)),
        "footer": TemplateNode(
            subtemplate=Footer,
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(source="footer", dest=None, edge_verification_func=optional_edge),
            conditional_edge=TemplateEdge(source="footer", dest=None, edge_verification_func=optional_edge),
            exception_edge=TemplateEdge(source="footer", dest=None, edge_verification_func=optional_edge),
        ),
    }

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=ExceptBody._subgraph, root_key="store", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return cfg

        header = next(cfg.predecessors(node))
        footer = mapping.get("footer")

        template = ExceptBody(mapping["body"])
        edges = [(header, template, {"type": ControlFlowEdgeType.NATURAL.value}), (template, mapping["panic"], {"type": ControlFlowEdgeType.EXCEPTION.value})]
        if footer:
            edges.append((template, footer, {"type": ControlFlowEdgeType.NATURAL.value}))
        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([mapping["store"], template.body, mapping["cleanup"]])
        reduced_cfg.add_node(template)
        reduced_cfg.add_edges_from(edges)
        return reduced_cfg

    def __init__(self, body):
        self.body = body

    def to_indented_source(self, source_lines):
        return self.body.to_indented_source(source_lines)


class BareExcept311(ControlFlowTemplate):
    _subgraph = {
        "body": TemplateNode(
            natural_edge=TemplateEdge(source="body", dest="footer"),
            exception_edge=TemplateEdge(
                source="body",
                dest="panic",
            ),
        ),
        "footer": TemplateNode(
            node_verification_func=node_match_all(assert_first_instruction_opname("POP_EXCEPT"), assert_in_degree(1)),
            natural_edge=TemplateEdge(
                source="footer",
                dest="after_except",
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
            exception_edge=TemplateEdge(
                source="except_footer",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
        ),
        "panic": TemplateNode(node_verification_func=is_exactly_opname("COPY", "POP_EXCEPT", "RERAISE"), exception_edge=TemplateEdge(source="panic", dest="outer_exception_handler", edge_verification_func=optional_edge)),
        "after_except": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(
                source="after_except",
                dest=None,
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
            conditional_edge=TemplateEdge(
                source="after_except",
                dest=None,
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
            exception_edge=TemplateEdge(
                source="after_except",
                dest=None,
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
        ),
        "outer_exception_handler": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(
                source="after_except",
                dest=None,
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
            conditional_edge=TemplateEdge(
                source="after_except",
                dest=None,
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
            exception_edge=TemplateEdge(
                source="after_except",
                dest=None,
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
        ),
    }

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=BareExcept311._subgraph, root_key="body", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        template = BareExcept311(
            body=mapping["body"],
            footer=mapping["footer"],
        )

        in_edges = ((src, template, edge_properties) for src, dst, edge_properties in cfg.in_edges(node, data=True))
        # only preserve exception handling edges
        out_edges = []
        if mapping["panic"]:
            out_edges.append((template, mapping["panic"], {"type": ControlFlowEdgeType.EXCEPTION.value}))
        if mapping.get("after_except", None):
            out_edges.append((template, mapping["after_except"], {"type": ControlFlowEdgeType.JUMP.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([template.body, template.footer])
        reduced_cfg.add_node(template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def __init__(self, body, footer):
        self.body = body
        self.footer = footer

    def to_indented_source(self, source_lines):
        return "\n".join(["except:", self._indent_multiline_string(self.body.to_indented_source(source_lines)), self._indent_multiline_string(self.footer.to_indented_source(source_lines))])


class ExceptETemplate311(ControlFlowTemplate, AbstractNonSequentiable, AbstractExceptionBlockTemplate):
    _subgraph = {
        "except_header": TemplateNode(
            node_verification_func=node_match_any(
                ends_with_opname_sequence("CHECK_EXC_MATCH", "POP_JUMP_FORWARD_IF_FALSE"),
                ends_with_opname_sequence("CHECK_EXC_MATCH", "POP_JUMP_IF_FALSE"),
            ),
            natural_edge=TemplateEdge(
                source="except_header",
                dest="except_body",
            ),
            conditional_edge=TemplateEdge(source="except_header", dest="non_match_path"),
            exception_edge=TemplateEdge(
                source="except_header",
                dest="panic_except",
            ),
        ),
        "except_body": TemplateNode(
            subtemplate=ExceptBody,
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(source="except_body", dest="except_footer", edge_verification_func=optional_edge, commit_none_to_mapping=False),
            exception_edge=TemplateEdge(
                source="except_body",
                dest="panic_except",
            ),
        ),
        "non_match_path": TemplateNode(
            subtemplate=ExceptTemplate311,
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
            node_verification_func=node_match_all(assert_first_instruction_opname("POP_EXCEPT"), assert_in_degree(1)),
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
            node_verification_func=is_exactly_opname("COPY", "POP_EXCEPT", "RERAISE"),
            exception_edge=TemplateEdge(
                source="panic_except",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
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

    def __init__(self, except_header: ControlFlowTemplate, except_body: ControlFlowTemplate, except_footer: ControlFlowTemplate, non_match_path: ControlFlowTemplate):
        self.except_header = except_header
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

        matcher = GraphTemplateMatcher(template_node_dict=ExceptETemplate311._subgraph, root_key="except_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        template = ExceptETemplate311(except_header=mapping["except_header"], except_body=mapping["except_body"], except_footer=mapping.get("except_footer"), non_match_path=mapping["non_match_path"])

        in_edges = ((src, template, edge_properties) for src, dst, edge_properties in cfg.in_edges(node, data=True))
        # only preserve exception handling edges
        out_edges = []
        if mapping["panic_except"]:
            out_edges.append((template, mapping["panic_except"], {"type": ControlFlowEdgeType.EXCEPTION.value}))
        if mapping.get("after_except", None):
            out_edges.append((template, mapping["after_except"], {"type": ControlFlowEdgeType.JUMP.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([template.except_header, template.except_body, template.non_match_path])
        if template.except_footer:
            reduced_cfg.remove_node(template.except_footer)
        reduced_cfg.add_node(template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        except_lines = []

        header = self.except_header.to_indented_source(source_lines)
        except_lines.append(header)

        body = ControlFlowTemplate._indent_multiline_string(self.except_body.to_indented_source(source_lines))
        except_lines.append(body)

        if self.except_footer:
            footer = ControlFlowTemplate._indent_multiline_string(self.except_footer.to_indented_source(source_lines))
            except_lines.append(footer)

        non_match = self.non_match_path.to_indented_source(source_lines)
        except_lines.append(non_match)

        return "\n".join(except_lines)

    def __repr__(self) -> str:
        return super().__repr__()
