from ..EditableBytecode import EditableBytecode

import itertools


def remove_docstrings(bytecode: EditableBytecode):
    to_remove = [(load_const, store_doc) for load_const, store_doc in itertools.pairwise(bytecode.instructions) if load_const.opname == "LOAD_CONST" and store_doc.opname == "STORE_NAME" and store_doc.argval == "__doc__"]
    to_remove = list(itertools.chain.from_iterable(to_remove))
    bytecode.remove_instructions(to_remove)
