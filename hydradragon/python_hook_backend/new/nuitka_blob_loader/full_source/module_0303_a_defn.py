# Reconstructed from integrated Nuitka blob
# Module: a_defn

T unumpy.
builtin_function_or_method
builtin
module
definition_finder
obj
build_list
build_set
unumba.core
T atyped_passes
typed_passes
code
a__code__
ufunction type not recognized {}
get_ir_of_code
remove_dels
new_var_dict
type_inference_stage
utoo many values to unpack (expected 4)
T uarg.
f_typemap
co_name
T w<w_T w>w_udef closure():

def
w(u):
return (
u)
return
u<string>
exec
closure
co_freevars
w
u	c_%d = None
w,uc_%d
co_argcount
ux_%d
a_create_function_from_code_obj
T acompiler
compiler
run_frontend
T Oobject
a__prepare__
aDummyPipeline
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
unumba.core.ir_utils
uget_ir_of_code.<locals>.DummyPipeline
a__qualname__
a__init__
uget_ir_of_code.<locals>.DummyPipeline.__init__
a__orig_bases__
state
rewrites
rewrite_registry
apply
ubefore-inference
unumba.core.inline_closurecall
core
inline_closurecall
aInlineClosureCallPass
cpu
aParallelOptions
T Funumba.core.untyped_passes
T aReconstructSSA
aReconstructSSA
unumba.core.typed_passes
T aPreLowerStripPhis
aPreLowerStripPhis
run_pass
T taStateDict
targetctx
return_type
T u$np_attr_attr
w:u
dump_block
T aunary
binop
inplace_binop
getitem
static_getitem
is_getitem
is_setitem
ugetitem or setitem node expected but received {}
a__bases__
a_make
a_fields
uis_namedtuple_class.<locals>.<genexpr>
T avalue
loc
make_temp
T aloc
T atarget
value
loc
get_exact
T afunc
args
kws
loc
callres
T avalue
index
index_var
loc
newblock
T atarget
loc
T aname
index
loc
T ascope
name
loc
T aname
T aitems
loc
find_outer_value
count
l  uTuple '{}' length must be smaller than 1000.
Large tuples lead to the generation of a prohibitively large LLVM IR which causes excessive memory pressure and large compile times.
As an alternative, the use of a 'list' is recommended in place of a 'tuple' as lists do not suffer from this problem.
aUnsupportedError
find_insts
make_function
u<creating a function from a closure>
u(%s)
u<could not ascertain use case>
uNumba encountered the use of a language feature it does not support in this context: %s (op code: make_function not supported). If the feature is explicitly supported it is likely that the result of the expression %sis being used in an unsupported manner.
use
aFunctionType
gdb
gdb_init
gdb_internal
gdb_calls
view
issubdtype
integer
floating
u'{}'
u'view' can only be called on NumPy dtypes, try wrapping the variable {}with 'np.<dtype>()'
uThe use of a %s type, assigned to variable '%s' in globals, is not supported as globals are considered compile-time constants and there is no known way to compile a %s type as a constant.
reflected
aDictType
aListType
is_generator
T uThe use of generator expressions is unsupported.
strformat
uCalling either numba.gdb() or numba.gdb_init() more than once in a function is unsupported (strange things happen!), use numba.gdb_breakpoint() to create additional breakpoints instead.
Relevant documentation is available here:
https://numba.readthedocs.io/en/stable/user/troubleshoot.html#using-numba-s-direct-gdb-bindings-in-nopython-mode
Conflicting calls found at:
%s
split
T w.aList
list
set
uhttps://numba.readthedocs.io/en/stable/reference/deprecation.html#deprecation-of-reflection-for-list-and-set-types

Encountered the use of a type that is scheduled for deprecation: type 'reflected %s' found for argument '%s' of function '%s'.
For more information visit %s
warnings
warn
aNumbaPendingDeprecationWarning
resolve_mod
uresolve_func_from_module.<locals>.resolve_mod
defn
getattr_chain
insert
aModuleType
uIllegal IR, del found at: %s
aCompilerError
find_exprs
T aphi
T aop
uIllegal IR, phi found at: %s
enforce_no_phis
enforce_no_dels
dbg_extend_lifetimes
T aextend_lifetimes
caller_ir
uCannot capture a constant value for variable '%s' as there are multiple definitions present.
freevars
uCannot capture the non-constant value associated with variable '%s' in a function that may escape.
u	c_%d = %s
co_varnames
defaults
u%s
u%s = %s
nargs
kwarg_defaults_tup
u,
a__globals__
used_var
localvars
define
a_con
aEnterWith
aTerminator
aPopBlock
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
pytypes
unumba.core.extending
T a_Intrinsic
T atypes
typing
ir
analysis
postproc
rewrites
config
unumba.core.typing.templates
T asignature
unumba.core.analysis
T acompute_live_map
compute_use_defs
compute_cfg_from_blocks
unumba.core.errors
T aTypingError
aUnsupportedError
aNumbaPendingDeprecationWarning
aCompilerError
a_MaxLabel
T l
u_MaxLabel.__init__
u_MaxLabel.next
u_MaxLabel.update
get_unused_var_name
next_label
mk_alloc
mk_range_block
mk_loop_header
legalize_names
replace_vars
flatten_labels
remove_args
T nnnadead_code_elimination
remove_dead_random_call
is_pure
is_const_call
get_canonical_alias
T nnT nT nntaget_tuple_table
get_stmt_writes
L amin
max
sum
prod
mean
var
std
cumsum
cumprod
argmax
argmin
argsort
nonzero
ravel
canonicalize_array_math
get_array_accesses
simplify
T EException
find_build_sequence
find_const
T nnnnnacompile_to_numba_ir
replace_arg_nodes
replace_returns
gen_np_call
dump_blocks
is_operator_or_getitem
is_get_setitem
index_var_of_get_setitem
set_index_var_of_get_setitem
is_namedtuple_class
fill_block_with_call
fill_callee_prologue
fill_callee_epilogue
raise_on_unsupported_feature
warn_deprecated
resolve_func_from_module
legalize_single_scope
check_and_legalize_ir
convert_code_obj_to_function
fixup_var_define_in_scope
transfer_scope
is_setup_with
is_terminator
is_raise
is_return
is_pop_block
unumba\core\ir_utils.py
T a.0
waatypemap
T a.0
wfu<module numba.core.ir_utils>
T a__class__
T aself
value
T aself
f_ir
compiler
T alhs
rhs
alias_map
arg_aliases
T	afcode
func_env
func_arg
func_clo
glbls
sanitized_co_name
func_text
loc
wfTatypemap
start
stop
step
scope
loc
nodes
g_stop_var
stop_assign
g_start_var
start_assign
g_step_var
step_assign
T
blocks
offset
new_blocks
wlwbaterm
inst
wTwfaf_max
T ablocks
in_copies
name_var_table
typemap
calltypes
save_copies
label
block
var_dict
stmt
wfwTagen_set
kill_set
lhs
rhs
wlwralhs_kill
wkwvT ablocks
definitions
block
inst
name
definition
wfT afunc_ir
typemap
calltypes
typingctx
blocks
saved_arr_arg
topo_order
label
block
new_body
stmt
lhs
rhs
arr
scope
loc
g_np_var
g_np
g_np_assign
func
func_typ
old_sig
argtyps
kwtyps
T afunc_ir
flags
post_proc
T amk_func
glbls
typingctx
targetctx
arg_typs
typemap
calltypes
typed_passes
code
f_ir
max_label
var_table
new_var_dict
name
var
f_typemap
f_return_type
f_calltypes
w_aarg_names
waT acode_obj
caller_ir
fcode
nfree
freevars
wxafreevar_def
msg
func_env
func_clo
co_varnames
n_kwargs
n_allargs
kwarg_defaults
wdakwarg_defaults_tup
nargs
func_arg
kw_const
glbls
T asize_var
typemap
scope
loc
nodes
new_size
size_assign
T ablocks
typemap
cfg
entry
c_data
gen_copies
all_copies
kill_copies
in_copies
out_copies
old_point
new_point
label
predecs
wpT afunc_ir
typemap
alias_map
arg_aliases
do_post_proc
post_proc
T afunc_ir
title
blocks
ir_blocks
name
T alabel
block
stmt
T ablocks
label
block
T afunc_ir
blk
dels
msg
T afunc_ir
blk
phis
msg
T anewblock
callee
label_next
inputs
outputs
scope
loc
fn
fnvar
args
callexpr
callres
wiaout
target
getitem
T ablock
outputs
scope
loc
vals
tupexpr
tup
T	ablock
inputs
label_next
scope
loc
args
aname
aval
tmp
T afunc_ir
var
var_def
build_ops
T afunc_ir
expr
typemap
definition_finder
callee
callee_def
attrs
obj
keys
value
key
def_val
mod_name
mod_not_none
numpy_toplevel
class_name
typ
T afunc_ir
var
var_def
T	ablocks
max_label
wlwbaterm
inst
wTwfaf_max
T afunc_ir
var
dfn
prev_val
val
T ablocks
args
typemap
func_ir
alias_map
arg_aliases
np_alias_funcs
bl
instr
wfaexpr
lhs
fdef
fname
fmod
alias_func
old_alias_map
wvwwT alabel
block
blocks
T ablocks
T
blocks
cfg
post_order
seen
visited
stack
node
succs
last_inst
dest
T astmt
typemap
calltypes
t_typ
s_typ
new_s_typ
T ablocks
used_var
blk
scope
inst
var
T	ablocks
new_blocks
topo_order
l_map
idx
wxat_node
wbaterm
T afunc_as_str
func
lhs
args
typingctx
typemap
calltypes
scope
loc
g_np_var
g_np
g_np_assign
np_attr_call
attr_var
func_var_typ
attr_assign
np_call
arg_types
func_typ
np_assign
T	ablocks
accesses
block
inst
lhs
rhs
index
wTwfT ablocks
typemap
block_copies
extra_kill
label
block
assign_dict
stmt
wTwfagen_set
kill_set
lhs
rhs
new_assign_dict
wlwrain1_var
in1_typ
block_cps
T ablocks
call_table
reverse_call_table
topological_ordering
order
label
inst
lhs
rhs
call_var
wTwfT wvaalias_map
v_aliases
T afunc_ir
name
kwargs
T afunc
wkwvT aglbls
fcode
nfree
func_env
func_clo
func_arg
wfacompiler
ir
aDummyPipeline
state
swapped
numba
inline_pass
aReconstructSSA
aPreLowerStripPhis
reconstruct_ssa
phistrip
post_proc
T ablocks
get_name_var_visit
namevar
T avar
namevar
T afunc
typingctx
T astmt
writes
T ablocks
tuple_table
block
inst
lhs
rhs
wTwfT aprefix
var_table
cur
var
T afunc
args
kwargs
T arhs
lives
call_table
array_analysis
parfor
prange
func_name
call_list
aCPUDispatcher
dot_3_mv_check_args
py_func
wfT astmt
T ablocks
entry
typemap
gen_copies
extra_kill
all_copies
wlwsakill_copies
label
gen_set
lhs
rhs
assigned
in_copies
out_copies
T amodule_name
func_name
T avar
typemap
typ
T wcabases
fields
T aexpr
T arhs
lives
call_table
func_name
call_list
wfT aindex
wiT avarnames
var_map
var
new_name
T	ablocks
cfg
removed
label
block
succs
next_label
preds
next_block
T&atypingctx
typemap
calltypes
lhs
size_var
dtype
scope
loc
lhs_typ
out
ndims
size_typ
tuple_var
new_sizes
tuple_call
tuple_assign
g_np_var
g_np
g_np_assign
empty_attr_call
attr_var
attr_assign
dtype_str
typ_var
typename_const
typ_var_assign
np_typ_getattr
alloc_call
cac
empty_c_typ
empty_c_var
empty_c_assign
asfortranarray_attr_call
afa_attr_var
afa_attr_assign
asfortranarray_call
asfortranarray_assign
alloc_assign
T atypemap
phi_var
calltypes
scope
loc
iternext_var
iternext_call
range_iter_type
iternext_assign
pair_first_var
pair_first_call
pair_first_assign
pair_second_var
pair_second_call
pair_second_assign
phi_b_var
phi_b_assign
branch
header_block
T atypemap
start
stop
step
calltypes
scope
loc
g_range_var
g_range
g_range_assign
arg_nodes
args
range_call
range_call_var
range_call_assign
iter_call
calltype_sig
iter_var
iter_call_assign
phi_var
phi_assign
jump_header
range_block
T aprefix
var
T aself
T afunc_ir
typemap
gdb_calls
arg_name
msg
blk
stmt
val
code
use
expr
found
var
df
cn
ty
vardescr
buf
T ablocks
block
new_body
stmt
T ablocks
args
func_ir
typemap
alias_map
arg_aliases
cfg
usedefs
live_map
call_table
w_aalias_set
removed
label
block
lives
out_blk
a_data
T ablock
lives
call_table
arg_aliases
alias_map
alias_set
func_ir
typemap
removed
new_body
stmt
alias_lives
init_alias_lives
wvalives_n_aliases
wfalhs
rhs
name
def_func
uses
defs
rhs_vars
T arhs
lives
call_list
T ablocks
topo_order
return_label
wlwbalabel_map
all_labels
label
term
new_blocks
wkanew_label
T ablock
args
stmt
idx
T avar
namedict
T ablocks
target
return_label
block
stmt
cast_stmt
T avar
vardict
new_var
T ablocks
namedict
new_namedict
wlwrareplace_name
T ablocks
vardict
new_vardict
wlwrT anode
vardict
T astmt
vardict
T acond
T afunc_ir
node
getattr_chain
resolve_mod
mod
defn
wxT amod
getattr_chain
func_ir
resolve_mod
T afunc_ir
getattr_chain
resolve_mod
T	ablocks
save_copies
typemap
rename_dict
var_rename_map
wawbanew_name
typ
T astmt
new_index
T	afunc_ir
typemap
calltypes
metadata
in_cps
w_aname_var_table
save_copies
var_rename_map
T ablocks
cfg
find_single_branch
single_branch_blocks
marked_for_del
label
inst
predecessors
delete_block
wpwqablock
T ablock
scope
old_scope
var
T aself
newval
T ablocks
callback
cbdata
block
stmt
T anode
callback
cbdata
arg
T astmt
callback
cbdata
wtwfavar
T
func_ir
typemap
name
ty
loc
arg
fname
tyname
url
msg
.numba.core.itanium_mangler
{
repl
u_escape_string.<locals>.repl
re
sub
a_re_invalid_char
encode
T aascii

group
T l
T autf8
u_%02x
u<genexpr>
u_escape_string.<locals>.repl.<locals>.<genexpr>
l
isdigit
w_a_fix_lead_digit
u%u%s
wBa_len_encoded
a_escape_string
wvasplit
T w.amangle_abi_tag
uN%s%sE
u%s%s
types
aType
aN2CODE
mangle_templated_ident
mangling_args
uLi%dE
mangle_identifier
uI%sE
mangle_type_or_value
aPREFIX
T aabi_tags
uid
mangle_args
startswith
uinput is not a mangled name
wN:l nn:l nna_split_mangled_ident
utoo many values to unpack (expected 2)
wEa__doc__
a__file__
a__spec__
origin
has_location
a__cached__
unumba.core
T atypes
config
config
compile
u[^a-z0-9_]
wIa_Z
aUSE_LEGACY_TYPE_SYSTEM
void
boolean
wbauint8
whaint8
waauint16
wtaint16
wsauint32
wjaint32
wiauint64
wyaint64
wxafloat16
aDh
float32
wfafloat64
wdapy_bool
py_int
py_float
np_bool_
np_uint8
np_int8
np_uint16
np_int16
np_uint32
np_int32
np_uint64
np_int64
np_float16
np_float32
np_float64
T u
D aabi_tags
uid
T
namangle_type
mangle_value
mangle
prepend_namespace
unumba\core\itanium_mangler.py
T a.0
ch
u<module numba.core.itanium_mangler>
T atext
repl
ret
T atext
T astring
T amangled
ct
ctlen
at
T aident
argtys
abi_tags
uid
T aabi_tag
T aargtys
T aident
template_params
abi_tags
uid
parts
enc_abi_tags
extras
T aidentifier
parameters
template_params
T atyp
enc
T amangled
ns
remaining
ret
head
tail
T wm.numba.core.llvm_bindings
l l  l lKl l  allvm
create_pipeline_tuning_options
speed_level
slp_vectorization
loop_vectorization
create_pass_builder
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
llvmlite
T abinding
l
binding
T l
a_inlining_threshold
T l Fpunumba\core\llvm_bindings.py
u<module numba.core.llvm_bindings>
T aoptlevel
sizelevel
T atm
opt
loop_vectorize
slp_vectorize
pto

.numba.core.lowering
4
library
fndesc
utils
aSortedMap
blocks
items
func_ir
generator_info
metadata
targetconfig
aConfigStack
top_or_none
flags
create_ir_module
unique_name
module
aEnvironment
from_fndesc
env
blkmap
pending_phis
varmap
min
keys
firstblk
q aloc
subtarget
T aenvironment
fndesc
context
enable_debuginfo
aDIBuilder
debuginfo
aDummyDIBuilder
a_compute_def_location
defn_loc
dbg_directives_only
filename
T amodule
filepath
cgctx
directives_only
get_registered_loc_notify
a_loc_notify_registry
init
call_conv
pyapi
get_python_api
builder
get_env_manager
env_manager
env_body
env_ptr
envarg
with_lineno
line
l afunc_id
func
get_func_body_first_lineno
uCould not find source for function:

u. Debug line information may be inaccurate.
warnings
warn
aNumbaDebugInfoWarning
mark_subprogram
function
qualname
args
argtypes
T afunction
qualname
argnames
argtypes
line
attributes
alwaysinline
add
T anoinline
finalize
close
return_dynamic_user_exc
func_name
T aloc
func_name
return_user_exc
set_static_user_exc
get_env_name
declare_env_global
emit_environment_object
genlower
lower_normal_function
aGeneratorLower
gentype
lower_init_func
lower_next_func
has_finalizer
lower_finalize_func
config
aDUMP_LLVM
dump_llvm
enable_nrt
removerefctpass
remove_unnecessary_nrt_usage
T acontext
fndesc
post_lowering
add_ir_module
decode_arguments
fnargs
setup_function
extract_function_arguments
lower_function_body
suspend_emission
a__enter__
a__exit__
position_at_end
branch
T nnnuB%s
self
append_basic_block
pre_lower
basic_block
debug_print
u# function begin: {0}
sorted
utoo many values to unpack (expected 2)
u# lower block:
lower_block
post_lower
pre_block
body
partial
aLoweringError
T aloc
new_error_context
T ulowering "{inst}" at {loc}
T ainst
loc
errcls_
lower_inst
post_block
create_cpython_wrapper
gendesc
call_helper
T arelease_gil
aUnsupportedError
T ugenerator as a first-class function type
create_cfunc_wrapper
declare_function
dbg_optnone
T aoptnone
T aentry
entry_block
aIRBuilder
init_call_helper
typemap
notify
aDEBUG_JIT
uDEBUGJIT [
u]:
types
literal
get_dummy_value
loadvar
typing
signature
none
get_function
print
a__class__
a_find_singly_assigned_variable
is_generator
compute_use_defs
must_use_alloca
defaultdict
T Oset
defmap
blk
usemap
utoo many values to unpack (expected 1)
find_insts
ir
aAssign
target
name
sav
a_singly_assigned_vars
a_blk_local_varmap
unumba.core.unsafe
T aeh
l
eh
aLower
a_cur_ir_block
values
aDel
value
all_names
typeof
a_alloca_var
block
find_exprs
T acall
T aop
ir_utils
guard
get_definition
aGlobal
exception_check
terminator
aBranch
truebr
a_in_try_block
mark_location
notify_loc
lower_assign
aArg
index
storevar
T aargidx
cond
falsebr
cast
boolean
cbranch
aJump
aReturn
return_from_generator
restype
aOptional
return_optional_value
get_return_value
return_value
aPopBlock
aStaticSetItem
calltypes
static_setitem
lower_setitem
index_var
l aPrint
lower_print
aSetItem
aStoreMap
dct
key
aDelItem
operator
delitem
typing_context
resolve_value_type
get_call_type
delvar
aSetAttr
get_setattr
attr
aDynamicRaise
lower_dynamic_raise
aDynamicTryRaise
lower_try_dynamic_raise
aStaticRaise
lower_static_raise
aStaticTryRaise
lower_static_try_raise
setitem
type
unliteral
exc_args
aVar
incref
nb_types
typ
val
return_dynamic_exception
exc_class
return_exception
T naset_exception
aConst
aFreeVar
get_constant_generic
aExpr
lower_expr
uarg.
aOmitted
resolve_value_type_prefer_literal
ty
aYield
lower_yield
yield_points
generators
aLowerYield
live_vars
lower_yield_suspend
yield_type
lower_yield_resume
lhs
rhs
static_lhs
static_rhs
cast_result
uLower.lower_binop.<locals>.cast_result
try_static_impl
uLower.lower_binop.<locals>.try_static_impl
a_lit_or_omitted
return_type
resty
op
aFunction
aTypingError
aUNDEFINED
u<genexpr>
uLower.lower_binop.<locals>.try_static_impl.<locals>.<genexpr>
getitem
utoo many values to unpack (expected 3)
a_VarArgItem
vararg
extract_value
pysig
uunsupported keyword arguments when calling %s
a_cast_var
normal_handler
uLower.fold_call_args.<locals>.normal_handler
default_handler
uLower.fold_call_args.<locals>.default_handler
stararg_handler
uLower.fold_call_args.<locals>.stararg_handler
fold_arguments
cgutils
make_anonymous_struct
T Oprint
inst
consts
pos_tys
replace
T apysig
fold_call_args
u# lower_call: expr = {0}
aPhantom
aObjModeDispatcher
a_lower_call_ObjModeDispatcher
aExternalFunction
a_lower_call_ExternalFunction
aExternalFunctionPointer
a_lower_call_ExternalFunctionPointer
aRecursiveCall
a_lower_call_RecursiveCall
aFunctionType
a_lower_call_FunctionType
a_lower_call_normal
void
unon-void function returns None from implementation
T amsg
loc
unumba.core.pythonapi
T aObjModeUtils
aObjModeUtils
init_pyapi
gil_ensure
from_native_value
load_dispatcher
call_function_objargs
is_null
if_else
decref
gil_release
return_exc
to_native_value
dispatcher
output_types
callable
cleanup
if_then
is_error
T u# external function
kws
funcdesc
aExternalFunctionDescriptor
symbol
sig
declare_external_function
call_external_function
T u# calling external function pointer
requires_gil
ffi_forced_object
newargvals
pyvals
call_function_pointer
cconv
get_overloads
mangler
default_mangler
abi_tags
uid
T aabi_tags
uid
startswith
call_internal
call_unresolved
T u# calling first-class function type
check_signature
umismatch of function types: expected
u but got
a_Lower__call_first_class_function_pointer
ftype
create_struct_proxy
T avalue
jit_addr
jit_addr_of_
alloca_once
get_value_type
D alikely
Fa_Lower__get_first_class_function_pointer
call
store
get_function_type
as_pointer
bitcast
call_function
if_unlikely
return_status_propagate
load
unumba.experimental.function_type
T alower_get_wrapper_address
lower_get_wrapper_address
uaddr_of_%s
T aname
ufptr_of_%s
upyaddr_of_%s
D afailure_mode
ignore
u function address is null
T ERuntimeError
T aexc_args
loc
long_as_voidptr
u# calling normal function: {0}
u# signature: {0}
expr
unumba.core.target_extension
T aresolve_dispatcher_from_str
resolve_dispatcher_from_str
targetdescr
target_context
recvr
binop
lower_binop
fn
inplace_binop
mutable
immutable_fn
unary
lower_call
pair_first
pair_second
T agetiter
iternext
exhaust_iter
aBaseTuple
iterator_type
get_constant_undef
aPair
getiter
iternext
count
iternext_impl
iterobj
pairty
not_
T EValueError
insert_value
tup
getattr
aBoundFunction
this
get_bound_function
get_getattr
resolve_getattr
static_getitem
lower_getitem
typed_getitem
build_tuple
make_tuple
build_list
aLiteralList
aTuple
dtype
build_set
:nnq abuild_map
T L
paappend
key_types
value_types
phi
T uPHI not stripped
null
get_constant_null
undef
special_ops
a_disable_sroa_like_opt
alloca
getvar
arg_names
pointee
uStoring {value.type} to ptr of {ptr.type.pointee} ('{name}'). FE type {fetype}
T avalue
ptr
fetype
name
get_abi_sizeof
data_model_manager
mark_variable
T aname
lltype
size
line
datamodel
argidx
discard
aConstant
alloca_lltype
T adatamodel
T w$T aname
zfill
T aname
lltype
size
line
datamodel
nrt
aLiteralTypingError
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
collections
T anamedtuple
defaultdict
namedtuple
ullvmlite.ir
llvmlite
T aConstant
aIRBuilder
unumba.core
T atyping
utils
types
ir
debuginfo
funcdesc
generators
config
ir_utils
cgutils
removerefctpass
targetconfig
unumba.core.errors
T aLoweringError
new_error_context
aTypingError
aLiteralTypingError
aUnsupportedError
aNumbaDebugInfoWarning
unumba.core.funcdesc
T adefault_mangler
unumba.core.environment
T aEnvironment
unumba.core.analysis
T acompute_use_defs
must_use_alloca
unumba.misc.firstlinefinder
T aget_func_body_first_lineno
unumba.misc.coverage_support
T aget_registered_loc_notify
T a_VarArgItem
T avararg
index
T Oobject
a__prepare__
aBaseLower
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
