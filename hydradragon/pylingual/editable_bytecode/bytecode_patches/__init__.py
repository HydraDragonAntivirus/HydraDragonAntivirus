from .fix_unreachable import fix_unreachable as fix_unreachable
from .remove_extended_arg import remove_extended_arg as remove_extended_arg
from .remove_docstrings import remove_docstrings as remove_docstrings
from .remove_nop import remove_nop as remove_nop
from .fix_indirect_jump import fix_indirect_jump as fix_indirect_jump
from .replace_firstlno import replace_firstlno as replace_firstlno

__all__ = [
    "fix_unreachable",
    "remove_extended_arg",
    "remove_docstrings",
    "remove_nop",
    "fix_indirect_jump",
    "replace_firstlno",
]
