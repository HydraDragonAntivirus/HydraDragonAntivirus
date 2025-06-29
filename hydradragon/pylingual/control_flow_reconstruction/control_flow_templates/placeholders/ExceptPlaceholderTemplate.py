import networkx as nx


from ..abstract.AbstractTemplate import ControlFlowTemplate





class ExceptPlaceholderTemplate(ControlFlowTemplate):
    """
    Placeholder for except; used in ExceptAs.py
    """

    def __init__(self, body: ControlFlowTemplate):
        self.body = body

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        raise NotImplementedError("ExceptPlaceholderTemplate does not have local matching logic. These are created in ExceptAs")

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        body = ControlFlowTemplate._indent_multiline_string(self.body.to_indented_source(source_lines))
        return f"except:\n{body}"

    def __repr__(self) -> str:
        return super().__repr__() if self.body else type(self).__name__
