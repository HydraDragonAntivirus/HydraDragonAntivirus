# Reconstructed from integrated Nuitka blob
# Module: unumba.core.controlflow

a__qualname__
a__init__
uCFBlock.__init__
a__repr__
uCFBlock.__repr__
a__iter__
uCFBlock.__iter__
a__orig_bases__
namedtuple
T aLoop
T aentries
exits
header
body
a__slots__
uLoop.__eq__
a__hash__
uLoop.__hash__
defaultdict
u_DictOfContainers.__eq__
a__ne__
u_DictOfContainers.__ne__
u_DictOfContainers._non_empty_items
uCFGraph.__init__
uCFGraph.add_node
uCFGraph.add_edge
uCFGraph.set_entry_point
uCFGraph.process
dominators
uCFGraph.dominators
post_dominators
uCFGraph.post_dominators
immediate_dominators
uCFGraph.immediate_dominators
dominance_frontier
uCFGraph.dominance_frontier
dominator_tree
uCFGraph.dominator_tree
cached_property
uCFGraph._exit_points
uCFGraph._doms
uCFGraph._back_edges
uCFGraph._topo_order
uCFGraph._descs
uCFGraph._loops
uCFGraph._in_loops
uCFGraph._post_doms
uCFGraph._idom
uCFGraph._df
uCFGraph._domtree
descendents
uCFGraph.descendents
uCFGraph.entry_point
uCFGraph.exit_points
uCFGraph.backbone
uCFGraph.loops
uCFGraph.in_loops
dead_nodes
uCFGraph.dead_nodes
uCFGraph.nodes
topo_order
uCFGraph.topo_order
uCFGraph.dump
T unumba_cfg.dot
render_dot
uCFGraph.render_dot
uCFGraph._add_edge
uCFGraph._remove_node_edges
uCFGraph._eliminate_dead_blocks
uCFGraph._find_exit_points
uCFGraph._find_postorder
uCFGraph._find_immediate_dominators
uCFGraph._find_dominator_tree
uCFGraph._find_dominance_frontier
uCFGraph._find_dominators_internal
uCFGraph._find_dominators
uCFGraph._find_post_dominators
uCFGraph._find_back_edges
uCFGraph._find_topo_order
uCFGraph._find_descendents
uCFGraph._find_loops
uCFGraph._find_in_loops
uCFGraph._dump_adj_lists
uCFGraph.__eq__
uCFGraph.__ne__
aControlFlowAnalysis
uControlFlowAnalysis.__init__
uControlFlowAnalysis.dump
run
uControlFlowAnalysis.run
T l
uControlFlowAnalysis.jump
uControlFlowAnalysis._use_new_block
uControlFlowAnalysis._start_new_block
uControlFlowAnalysis._guard_with_as
op_SETUP_LOOP
uControlFlowAnalysis.op_SETUP_LOOP
op_SETUP_WITH
uControlFlowAnalysis.op_SETUP_WITH
op_POP_BLOCK
uControlFlowAnalysis.op_POP_BLOCK
op_FOR_ITER
uControlFlowAnalysis.op_FOR_ITER
a_op_ABSOLUTE_JUMP_IF
uControlFlowAnalysis._op_ABSOLUTE_JUMP_IF
op_POP_JUMP_IF_FALSE
op_POP_JUMP_IF_TRUE
op_JUMP_IF_FALSE
op_JUMP_IF_TRUE
op_POP_JUMP_FORWARD_IF_FALSE
op_POP_JUMP_BACKWARD_IF_FALSE
op_POP_JUMP_FORWARD_IF_TRUE
op_POP_JUMP_BACKWARD_IF_TRUE
a_op_ABSOLUTE_JUMP_OR_POP
uControlFlowAnalysis._op_ABSOLUTE_JUMP_OR_POP
op_JUMP_IF_FALSE_OR_POP
op_JUMP_IF_TRUE_OR_POP
op_JUMP_ABSOLUTE
uControlFlowAnalysis.op_JUMP_ABSOLUTE
op_JUMP_FORWARD
uControlFlowAnalysis.op_JUMP_FORWARD
op_JUMP_BACKWARD
op_RETURN_VALUE
uControlFlowAnalysis.op_RETURN_VALUE
T T l l T l laop_RETURN_CONST
uControlFlowAnalysis.op_RETURN_CONST
T T l l
T l l aNotImplementedError
op_RAISE_VARARGS
uControlFlowAnalysis.op_RAISE_VARARGS
op_BREAK_LOOP
uControlFlowAnalysis.op_BREAK_LOOP
unumba\core\controlflow.py
T a.0
src
dests
T a.0
wvaidom
T a.0
wnT a.0
wiaself
T aloop
u<module numba.core.controlflow>
T a__class__
T aself
other
wxathis
that
T aself
other
T aself
other
mine
theirs
T aself
T aself
offset
T aself
bytecode
T aself
other
ret
T aself
args
T aself
from_
to
data
T aself
entries
seen
stack
node
succ
T anode
dest
seen
succs
back_edges
a_dfs_rec
post_order
T a_dfs_rec
back_edges
post_order
seen
succs
T aself
file
adj_lists
pprint
T aself
live
node
dead
T aself
stats
back_edges
stack
succs_state
entry_point
checked
push_state
iter_ct
tos
tos_succs
cur_node
T aself
descs
node
node_descs
succ
T aself
idom
preds_table
df
wuwvT aself
idom
domtree
wuwvT aself
post
entries
preds_table
succs_table
doms
weatodo
wnanew_doms
preds
T aself
exit_points
wnT
self
intersect
entry
preds_table
order
idx
idom
changed
wuanew_idom
T aself
loops
in_loops
loop
wnT aself
bodies
src
dest
header
body
queue
wnaloops
entries
exits
loop
T aself
dummy_exit
loop
wbapdoms
doms
T	aself
succs
back_edges
post_order
seen
dfs_rec
stack
cb
data
T aself
succs
back_edges
post_order
seen
a_dfs_rec
T aself
current_inst
next_op
msg
T aself
inst
T aself
node
succ
pred
T aself
inst
res
T aself
src
dest
data
T aself
node
T anode
dest
seen
stack
post_order
succs
back_edges
dfs_rec
T aback_edges
dfs_rec
post_order
seen
stack
succs
T aself
file
pprint
T aself
file
T aself
block
wiapops
T wuwvaidx
idom
T aidom
idx
T aself
wiT aself
target
pops
T aself
inst
end
T aself
dest
src
T anode
stack
self
succs_state
T aself
stack
succs_state
T aself
filename
gv
wgwnaedge
T aself
inst
fname
fn
wlamsg
cur
nxt
blk
graph
wbaout
pops
lastblk
backbone
inloopblocks
T aself
src
dest
T aself
nodes
reverse
it
wn.numba.core.cpu
D a__class__
a__init__
a_internal_codegen
a_create_empty_module
utils
aMACHINE_BITS
l ais32bit
codegen
aJITCPUCodegen
T unumba.exec
platform
machine
armv7l
all
load_library_permanently
T ulibgcc_s.so.1
externals
c_math_functions
install
rtsys
initialize
unumba.cpython
Tabuiltins
charseq
enumimpl
hashing
heapq
iterators
listobj
numbers
rangeobj
setobj
slicing
tupleobj
unicode
l
builtins
charseq
enumimpl
hashing
heapq
iterators
listobj
numbers
rangeobj
setobj
slicing
tupleobj
unicode
unumba.core
T aoptional
inline_closurecall
optional
inline_closurecall
unumba.misc
T agdb_hook
literal
gdb_hook
literal
unumba.np
T alinalg
arraymath
arrayobj
linalg
arraymath
arrayobj
unumba.np.random
T agenerator_core
generator_methods
generator_core
generator_methods
unumba.np.polynomial
T apolynomial_core
polynomial_functions
polynomial_core
polynomial_functions
unumba.typed
T atypeddict
dictimpl
typeddict
dictimpl
T atypedlist
listobject
typedlist
listobject
unumba.experimental
T ajitclass
function_type
jitclass
function_type
T anpdatetime
npdatetime
T anpyimpl
npyimpl
T acmathimpl
mathimpl
printimpl
randomimpl
cmathimpl
mathimpl
printimpl
randomimpl
T acffiimpl
cffiimpl
unumba.experimental.jitclass.base
T aClassBuilder
aClassBuilder
install_registry
registry
class_impl_registry
numba
core
entrypoints
init_all
unumba.np.unsafe
T andarray
ndarray
target_data
aAOTCPUCodegen
subtarget
T a_internal_codegen
aot_mode
callconv
aCPUCallConv
cgutils
pointer_add
a_dynfunc
a_impl_info
offsetof_env_body
aEnvBody
T aref
cast_ref
declare_env_global
module
get_env_name
fndesc
load
get_python_api
emit_environment_sentry
env_name
T areturn_pyobject
debug_msg
get_env_body
get_env_manager
environment
offsetof_generator_state
T areturn_type
T alistobj
build_list
T asetobj
build_set
T adictobject
dictobject
build_map
fastmath
fastmathpass
rewrite_module
intrinsics
fix_divmod
add_linking_library
library
create_module
T awrapper
call_conv
get_function_type
restype
argtypes
ir
aFunction
llvm_func_name
aPyCallWrapper
T acall_helper
release_gil
build
add_ir_module
T acfunc_wrapper
self
get_value_type
aFunctionType
llvm_cfunc_wrapper_name
aIRBuilder
append_basic_block
T aentry
call_function
args
D aattrs
T anoinline
utoo many values to unpack (expected 2)
if_then
is_error
D alikely
Fa__enter__
a__exit__
gil_ensure
raise_error
insert_const_string
string_from_string
err_write_unraisable
decref
gil_release
T nnnaret
get_pointer_to_function
llvm_cpython_wrapper_name
ucompiled wrapper for %r
qualname
make_function
lookup_module
split
T w.q aset_env
types
aArray
int32
wAaget_abi_sizeof
ufunc_db
get_ufunc_info
is_set
T aenable_pyobject
enable_pyobject
T aenable_looplift
enable_looplift
inherit_if_not_set
T anrt
tT adefault
T adebuginfo
config
aDEBUGINFO_DEFAULT
debuginfo
T adbg_extend_lifetimes
dbg_extend_lifetimes
aEXTEND_VARIABLE_LIFETIMES
T aboundscheck
boundscheck
enable_pyobject_looplift
T afastmath
T aerror_model
python
T aforceinline
forceinline
dbg_optnone
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
ullvmlite.binding
binding
llvmlite
T air
T a_dynfunc
unumba.core.callwrapper
T aPyCallWrapper
unumba.core.base
T aBaseContext
aBaseContext
T	autils
types
config
cgutils
callconv
codegen
externals
fastmathpass
intrinsics
unumba.core.options
T aTargetOptions
include_default_options
aTargetOptions
include_default_options
unumba.core.runtime
T artsys
unumba.core.compiler_lock
T aglobal_compiler_lock
global_compiler_lock
unumba.core.entrypoints
unumba.core.cpu_options
T aParallelOptions
aFastMathOptions
aInlineOptions
aParallelOptions
aFastMathOptions
aInlineOptions
T aufunc_db
aStructure
a__prepare__
aClosureBody
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
