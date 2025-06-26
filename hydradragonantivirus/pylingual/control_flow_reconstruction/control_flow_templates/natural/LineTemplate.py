import networkx as nx

from pylingual.editable_bytecode import Inst

from ..abstract.AbstractTemplate import ControlFlowTemplate


class LineTemplate(ControlFlowTemplate):
    """
    A natural progression of control flow templates with the same exception handler.
    No conditional jumps are allowed.
    """

    def __init__(self, *members: ControlFlowTemplate):
        self.members = members

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        raise NotImplementedError("LineTemplates do not have local matching logic.")

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        return "\n".join(member.to_indented_source(source_lines) for member in self.members)

    def get_instructions(self) -> list[Inst]:
        insts: list[Inst] = []
        for member in self.members:
            insts.extend(member.get_instructions())
        return insts
        return sorted(insts, key=lambda i: i.offset)

    def __repr__(self) -> str:
        name = f"{type(self).__name__}"
        components = ControlFlowTemplate._indent_multiline_string("\n".join(repr(member) for member in self.members))
        return f"{name}[\n{components}]"
