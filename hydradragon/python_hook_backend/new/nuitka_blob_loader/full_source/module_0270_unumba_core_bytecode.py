# Reconstructed from integrated Nuitka blob
# Module: unumba.core.bytecode

T aoffset
anext
opcode
opname
arg
lineno
a__slots__
uByteCodeInst.__init__
property
is_jump
uByteCodeInst.is_jump
is_terminator
uByteCodeInst.is_terminator
get_jump_target
uByteCodeInst.get_jump_target
a__repr__
uByteCodeInst.__repr__
block_effect
uByteCodeInst.block_effect
a__orig_bases__
T aNOP
uByteCodeIter.__init__
a__iter__
uByteCodeIter.__iter__
uByteCodeIter._fetch_opcode
uByteCodeIter.next
a__next__
read_arg
uByteCodeIter.read_arg
a_ByteCode
T	afunc_id
co_names
co_varnames
co_consts
co_cellvars
co_freevars
exception_entries
table
labels
u_ByteCode.__init__
classmethod
u_ByteCode._compute_lineno
u_ByteCode.__iter__
u_ByteCode.__getitem__
a__contains__
u_ByteCode.__contains__
dump
u_ByteCode.dump
u_ByteCode._compute_used_globals
get_used_globals
u_ByteCode.get_used_globals
aByteCodePy311
uByteCodePy311.__init__
staticmethod
uByteCodePy311.fixup_eh
find_exception_entry
uByteCodePy311.find_exception_entry
aByteCodePy312
uByteCodePy312.__init__
uByteCodePy312.ordered_offsets
uByteCodePy312.remove_build_list_swap_pattern
T l l aByteCode
aReduceMixin
aFunctionIdentity
count
T l uFunctionIdentity.from_function
derive
uFunctionIdentity.derive
a_reduce_states
uFunctionIdentity._reduce_states
a_rebuild
uFunctionIdentity._rebuild
unumba\core\bytecode.py
T a.0
wkT a.0
wxT a.0
wialabel_marker
u<module numba.core.bytecode>
T a__class__
T aself
offset
T aself
offset
opcode
arg
nextoffset
T aself
code
T aself
func_id
entries
a__class__
T aself
func_id
entries
max_exception_target
a__class__
T aself
func_id
code
labels
table
T aself
T aseq
lst
wswcT acls
table
code
offset
lineno
adj_offset
known
inst
Tacls
func
table
co_consts
co_names
wdaglobs
builtins
inst
name
value
co
subtable
T aarg
T abc_stream
offset
opcode
arg
nextoffset
T acls
pyfunc
T acode
buf
wiastart_offset
op
arg
next_offset
T acode
extended_arg
wnaoffset
wiaop
arg
wjT aself
label_marker
T aself
offset
candidates
ent
T aent
out
T acls
pyfunc
func
code
pysig
func_qualname
self
uid
T aobj
T aobj
attr
T wiaself
T aentries
entry_to_remove
lower_entry_idx
upper_entry_idx
lower_entry
upper_entry
T aself
size
buf
wia_offset
byte
T aself
entries
pop_and_merge_exceptions
change_to_nop
work_remaining
current_nop_fixes
entry
index
curr_inst
next_inst
inst

.numba.core.byteflow
VQ
a_value
aBlockKind
ucannot compare to {!r}
uBlockKind({})
a_logger
debug
ubytecode dump:
%s
a_lazy_pformat
u<lambda>
uFlow.__init__.<locals>.<lambda>
T alazy_func
a_bytecode
aUniqueDict
block_infos
dump
aState
l
T abytecode
pc
nstack
blockstack
aTraceRunner
func_id
filename
T adebug_filename
pending
append
runner
upending: %s
popleft
finished
ustack: %s
a_stack
ustate.pc_initial: %s
first_encounter
pc_initial
dispatch
state
has_terminated
self
a_run_handle_exception
a_is_implicit_new_block
a_guard_with_as
split_new_block
uend state. edges=%s
outgoing_edges
add
get_outgoing_states
extend
a_build_cfg
a_prune_phis
sorted
uFlow.run.<locals>.<lambda>
T akey
adapt_state_infos
ublock_infos %s:
%s
in_with
has_active_try
get_inst
opname
a_NO_RAISE_OPS
fork
anext
T apc
a_adjust_except_stack
advance_pc
is_in_exception
u3.11 exception %s PC=%s
get_exception
a_pc
get_top_block
T aTRY
end
target
make_block
T aend
end_offset
depth
stack_depth
lasti
push_lasti
T apc
extra_block
pop_block_and_above
entry_stack
npop
handler
T aEXCEPT
a_EXCEPT_STACK_OFFSET
T aFINALLY
a_FINALLY_POP
kind
npush
extra_block
pc
aCFGraph
graph
add_node
add_edge
set_entry_point
T l
process
cfgraph
T u-------------------------Prune PHIs-------------------------
get_used_phis_per_state
uFlow._prune_phis.<locals>.get_used_phis_per_state
find_use_defs
uFlow._prune_phis.<locals>.find_use_defs
propagate_phi_map
uFlow._prune_phis.<locals>.propagate_phi_map
apply_changes
uFlow._prune_phis.<locals>.apply_changes
utoo many values to unpack (expected 2)
uUsed_phis: %s
T u----------------------DONE Prune PHIs-----------------------
defaultdict
T Oset
a_used_regs
a_phis
used_phis
phi_set
a_outgoing_phis
items
defmap
udefmap: %s
uphismap: %s
phismap
defsites
uchanging phismap: %s
changing
keep
ukeep phismap: %s
T Odict
phi
unew_out: %s
clear
update
offset
labels
aNEW_BLOCKERS
P aSETUP_WITH
aBEFORE_WITH
aPOP_TOP
aUnsupportedBytecodeError
T uThe 'with (context manager) as (variable):' construct is not supported.
startswith
T u$null$
debug_filename
deque
aLoc
aPYVERSION
T T l l T l l T l la_blockstack
q apop
T T l l
aCACHE
udispatch pc=%s, inst=%s
ustack %s
uop_{}
uUse of unsupported opcode (%s) found
get_debug_loc
lineno
T aloc
l apush
make_null
make_temp
T avalue
res
strvar
arg
T uformat spec in f-strings not supported yet
T astrings
tmps
T aval
res
T aidx
res
T ares
T aconst
w.u
T T l lT T l l T T l l
T l l ainst
res
T aitem
res
get_varname
co_varnames
co_freevars
co_cellvars
T ares
as_load_deref
l l aget_varname_by_arg
T ares1
res2
T astore_value
load_res
T avalue1
value2
T atarget
T atarget
value
T avalue
T abase
start
res
slicevar
indexvar
nonevar
T abase
stop
res
slicevar
indexvar
nonevar
T abase
start
stop
res
slicevar
indexvar
T abase
value
slicevar
indexvar
nonevar
T abase
start
slicevar
value
indexvar
nonevar
T abase
stop
value
slicevar
indexvar
nonevar
T abase
start
stop
value
slicevar
indexvar
T abase
slicevar
indexvar
nonevar
T abase
start
slicevar
indexvar
nonevar
T abase
stop
slicevar
indexvar
nonevar
T abase
start
stop
slicevar
indexvar
l l aunreachable
T astart
stop
step
res
slicevar
T astart
end
container
res
slicevar
temp_res
T astart
end
container
value
res
slicevar
T apred
get_jump_target
get_tos
T apc
npop
a_op_POP_JUMP_IF
T aLOOP
pop_block
T aretval
castval
terminate
T avalue
res
T uThe re-raising of an exception is not yet supported.
uMultiple argument raise is not supported.
T aexc
temps
T atemps
reset_stack
T uUnsupported use of a bytecode related to try..finally or a with-context
push_block
aLOOP
T akind
end
T asetup_with_exitfn
T aprefix
find_exception_entry
exception_entries
ehhead
ehrelated
max
T acontextmanager
exitfn
end
aWITH
u<genexpr>
uTraceRunner.op_BEFORE_WITH.<locals>.<genexpr>
T acontextmanager
exitfn
T akind
end
reset_stack
aTRY
T akind
end
reset_stack
handler
T aexception
a_setup_try
aFINALLY
T anext
end
uPOP_EXCEPT got an unexpected block:
D akind
try
T aWITH
D akind
with
T aindex
target
res
T atarget
index
value
T atarget
index
T l la_is_null_temp_reg
pop_kw_names
callable
kw_names
T afunc
args
kw_names
res
set_kw_names
T afunc
args
res
T afunc
args
names
res
T afunc
vararg
varkwarg
res
T T l l T l l apeek
T l areverse
T aorig
duped
aCALL_INTRINSIC_1_Operand
uop_CALL_INTRINSIC_1(
w)aci1op
aINTRINSIC_STOPITERATION_ERROR
T aoperand
aUNARY_POSITIVE
T aoperand
value
res
aINTRINSIC_LIST_TO_TUPLE
T aoperand
const_list
res
a_dup_topx
D acount
l D acount
l aswap
T aiterable
stores
tupleobj
T aitems
res
T atuples
temps
is_assign
a_build_tuple_unpack
T aconst_list
res
T akeys
keytmps
values
res
T atarget
value
appendvar
res
T atarget
value
extendvar
res
:nnq T aitems
size
res
T atarget
key
value
setitemvar
res
T atarget
value
updatevar
res
T aiterator
pair
indval
pred
T T l l T l ladis
a_nb_ops
aALL_BINOPS_TO_OPERATORS
a__name__
binop_
T aop
lhs
rhs
res
T alhs
rhs
res
l T aname
code
closure
annotations
kwdefaults
defaults
res
set_function_attribute
T adefaults
T akwdefaults
T aannotations
T aclosure
make_func_stack
op_MAKE_FUNCTION
D aMAKE_CLOSURE
tT aassertion_error
T apredicate
T apred
tos
tos1
op_LOAD_ATTR
op_CALL_FUNCTION
a_pc_initial
a_nstack_initial
a_blockstack_initial
a_temp_registers
a_insts
a_outedges
a_terminated
T unull$
T aphi
uState(pc_initial={} nstack_initial={})
get_identity
u${prefix}{offset}{opname}.{tempct}
lower
T aprefix
offset
opname
tempct
u${prefix}{offset}.{tempct}
T aprefix
offset
tempct
a_flatten_inst_regs
values
wdaindex
stack
blockstack
get
T aend_offset
aEdge
T apc
stack
npush
blockstack
T abytecode
pc
nstack
blockstack
nullvals
ret
edge
a__class__
a__init__
a_kw_names
a_make_func_attrs
a_flow
process_function_attributes
uadapt_state_infos.<locals>.process_function_attributes
instructions
T T l l
T l l T l l aAdaptBlockInfo
outgoing_phis
blockstack_initial
find_initial_try_block
get_outgoing_edgepushed
T ainsts
outgoing_phis
blockstack
active_try_block
outgoing_edgepushed
aMAKE_FUNCTION
get_function_attributes
iterable
T Otuple
Olist
a_blocks
aAdaptCFBlock
backbone
blocks
keys
in_loops
inloopblocks
a_backbone
iterliveblocks
uAdaptCFA.iterliveblocks
insts
body
uAdaptCFBlock.__init__.<locals>.<genexpr>
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
logging
collections
T anamedtuple
defaultdict
deque
namedtuple
total_ordering
unumba.core.utils
T aUniqueDict
aPYVERSION
aALL_BINOPS_TO_OPERATORS
a_lazy_pformat
unumba.core.controlflow
T aNEW_BLOCKERS
aCFGraph
unumba.core.ir
T aLoc
unumba.core.errors
T aUnsupportedBytecodeError
getLogger
T unumba.core.byteflow
l P aPRECALL
aLOAD_CONST
aLOAD_DEREF
aNOP
enum
T aEnum
aEnum
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
