from abc import ABC, abstractmethod

import networkx as nx

from pylingual.editable_bytecode import Inst


class ControlFlowTemplate(ABC):
    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        ...

    @abstractmethod
    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        ...

    @staticmethod
    def _indent_multiline_string(multiline_string: str, indentation_level: int = 1) -> str:
        return "\n".join("\t" * indentation_level + line.rstrip() for line in multiline_string.split("\n") if line)

    def __repr__(self) -> str:
        name = f"{type(self).__name__}"
        components = ControlFlowTemplate._indent_multiline_string(",\n".join(f"{key}={repr(value)}" for key, value in vars(self).items()))
        return f"{name}[\n{components}]"

    def get_instructions(self) -> list[Inst]:
        insts: list[Inst] = []
        for key, value in vars(self).items():
            if hasattr(value, "get_instructions"):
                insts.extend(value.get_instructions())
            elif isinstance(value, Inst):
                insts.append(value)
        return insts
        return sorted(insts, key=lambda i: i.offset)
