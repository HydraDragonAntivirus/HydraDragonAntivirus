from ..EditableBytecode import EditableBytecode


def fix_indirect_jump(bytecode: EditableBytecode):
    for i in bytecode:
        if i.is_jump:
            # avoid infinite loop
            limit = 99
            while i.target.is_uncond_jump and limit:
                i.argval = i.target.argval
                i.target = i.target.target
                limit -= 1
