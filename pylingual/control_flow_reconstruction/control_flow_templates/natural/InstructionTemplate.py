import networkx as nx

from pylingual.editable_bytecode import Inst

from ..abstract.AbstractTemplate import ControlFlowTemplate


class InstructionTemplate(ControlFlowTemplate):
    """
    A thin wrapper around the Inst class to support formatting source code
    """

    def __init__(self, instruction: Inst):
        self.instruction = instruction

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if not isinstance(node, Inst):
            return None

        if node not in cfg.nodes:
            return None

        inst_template = InstructionTemplate(node)
        return nx.relabel_nodes(cfg, mapping={node: inst_template}, copy=True)

    @staticmethod
    def match_graph(cfg: nx.DiGraph) -> nx.DiGraph:
        """
        Attempts to match this template on the whole graph
        Returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        """
        node_mapping = dict()
        for node in cfg.nodes:
            if not isinstance(node, Inst):
                continue

            inst_template = InstructionTemplate(node)
            node_mapping[node] = inst_template

        return nx.relabel_nodes(cfg, mapping=node_mapping, copy=True)

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        if not self.instruction.starts_line:
            return ""

        line = source_lines[self.instruction.starts_line - 1].strip()
        if line.startswith("elif "):
            line = line[2:]
        elif line in ("break", "continue", "except:", "try:"):
            line = ""

        return line

    def get_instructions(self) -> list[Inst]:
        return [self.instruction]

    def __repr__(self) -> str:
        if self.instruction.starts_line:
            return f"({self.instruction.starts_line}) <{self.instruction.get_dis_view()}>"
        return f"<{self.instruction.get_dis_view()}>"
