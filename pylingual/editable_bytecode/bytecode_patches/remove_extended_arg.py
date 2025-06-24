from ..EditableBytecode import EditableBytecode


def remove_extended_arg(bytecode: EditableBytecode):
    for i in bytecode:
        i.has_extended_arg = False
    to_remove = [x for x in bytecode.instructions if x.opname == "EXTENDED_ARG"]
    bytecode.remove_instructions(to_remove)
