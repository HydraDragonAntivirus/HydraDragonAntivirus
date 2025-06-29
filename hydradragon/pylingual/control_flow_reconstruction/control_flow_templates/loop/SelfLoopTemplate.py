import networkx as nx


from ..abstract.AbstractTemplate import ControlFlowTemplate


from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import optional_node, optional_edge


class SelfLoopTemplate(ControlFlowTemplate):
    """
    An infinite loop with no extra control flow.
    (0)-<      -->   (0)
    optionally, all nodes in the pattern can have a shared exception handler.
    """

    _subgraph = {
        "loop_body": TemplateNode(
            natural_edge=TemplateEdge(
                source="loop_body",
                dest="loop_body",
            ),
            exception_edge=TemplateEdge(
                source="loop_body",
                dest="exception_handler",
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

    def __init__(self, loop_body: ControlFlowTemplate):
        self.loop_body = loop_body

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=SelfLoopTemplate._subgraph, root_key="loop_body", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        loop_template = SelfLoopTemplate(loop_body=mapping["loop_body"])

        reduced_cfg: nx.DiGraph = nx.relabel_nodes(cfg, {mapping["loop_body"]: loop_template})
        reduced_cfg.remove_edge(loop_template, loop_template)
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        body = ControlFlowTemplate._indent_multiline_string(self.loop_body.to_indented_source(source_lines))
        return f"while True: # inserted\n{body}"

    def __repr__(self) -> str:
        return super().__repr__()
