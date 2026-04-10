# Reconstructed from integrated Nuitka blob
# Module: unumba.core.imputils

a__qualname__
T aunspecified
a__init__
uRegistry.__init__
lower
uRegistry.lower
uRegistry._decorate_attr
uRegistry.lower_getattr
lower_getattr_generic
uRegistry.lower_getattr_generic
uRegistry.lower_setattr
lower_setattr_generic
uRegistry.lower_setattr_generic
lower_cast
uRegistry.lower_cast
lower_constant
uRegistry.lower_constant
a__repr__
uRegistry.__repr__
a__orig_bases__
aRegistryLoader
T afunctions
getattrs
setattrs
casts
constants
registry_items
T abuiltin_registry
builtin_registry
user_function
user_generator
iterator_impl
T a_context
a_builder
a_pairobj
a__slots__
u_IternextResult.__init__
set_exhausted
u_IternextResult.set_exhausted
T taset_valid
u_IternextResult.set_valid
yield_
u_IternextResult.yield_
u_IternextResult.is_valid
u_IternextResult.yielded_value
l l l T nacall_len
namedtuple
T a_ForIterLoop
T avalue
do_break
contextmanager
T anumpy
numba_typeref_ctor
unumba\core\imputils.py
u<module numba.core.imputils>
T a__class__
T aself
name
T aself
context
builder
pairobj
T aself
T aself
impl
ty
attr
impl_list
decorator
real_impl
T aimpl
ty
attr
real_impl
res
T acontext
builder
iterable_type
val
getiter_sig
getiter_impl
T	acontext
builder
iterator_type
val
itemty
pair_type
iternext_sig
iternext_impl
pairobj
T acontext
builder
ty
val
len_impl
T aimpl
self
func
argtys
T aargtys
func
self
T aimpl
self
fromty
toty
T afromty
self
toty
T aimpl
self
ty
T aself
ty
T aimpl
self
ty
attr
T aattr
self
ty
T abuilder
bb_end
T abb_end
builder
T	acontext
builder
sig
status
retval
value_type
optional_none
retvalptr
optional_value
T
context
builder
iterable_type
val
iterator_type
iterval
bb_body
bb_end
do_break
res
T acontext
model_name
callconv
old_error_model
T	acontext
builder
sig
args
func
status
retval
msg
fndesc
T afndesc
T acontext
builder
sig
args
func
status
retval
gendesc
T agendesc
T actx
builder
retty
ret
T aiterable_type
iterator_type
wrapper
T aref_type
outer
T	acontext
builder
sig
args
result
value
iterobj
cls
iternext
T acls
iternext
T aself
func
argtys
decorate
T aself
fromty
toty
decorate
T aself
ty
decorate
T aself
ty
attr
decorate
T aargs
kwargs
T afunc
wrapper
T aref_type
T acontext
builder
typ
value
attr
real_impl
T areal_impl
T acontext
builder
sig
args
attr
real_impl
T aself
is_valid
T afndesc
libs
imp
T agendesc
libs
imp
T acls
iternext
iternext_wrapper
iterator_type
T aiterator_type
T	acontext
builder
sig
args
pair_type
pairobj
impl_ret
func
ref_type
T afunc
ref_type
T aself
value
.numba.core.inline_closurecall
:
s ablocks
values
find_insts
ir
aAssign
value
aYield
errors
aUnsupportedError
loc
T uThe use of yield in a closure is unsupported.
T aloc

w.w<w_w>w$a_v
func_ir
parallel_options
swapped
a_processed_stencils
typed
postproc
aPostProcessor
run
T taitems
a_make_debug_print
T aInlineClosureCallPass
uSTART
func_id
func_qualname
work_list
utoo many values to unpack (expected 2)
body
aExpr
op
call
guard
find_callname
self
get_definition
func
a_inline_reduction
block
a_inline_closure
a_inline_stencil
enable_inline_arraycall
modified
merge_adjacent_blocks
compute_cfg_from_blocks
T ustart inline arraycall
a_debug_dump
loops
keys
sorted
u<lambda>
uInlineClosureCallPass.run.<locals>.<lambda>
T akey
reverse
visited
a_inline_arraycall
cfg
comprehension
a_fix_nested_array
dead_nodes
dead_code_elimination
rename_labels
remove_dels
T aEND
l arequire
reduction
T areduce
builtins
T areduce
a_functools
args
T l l uinvalid reduce call, two arguments are required (optional initial value can also be specified)
check_reduce_func
l
T nareduce_func
uInlineClosureCallPass._inline_reduction.<locals>.reduce_func
inline_closure_call
a__globals__
callee_ir_validator
T awork_list
callee_validator
wfwsunumba.stencils.stencil
T aStencilFunc
aStencilFunc
target
aGlobal
name
stencil
kws
T astencil
unumba.stencils.stencil
T astencil
numba
append
uAs a minimum Stencil requires a kernel as an argument
make_function
get_ir_of_code
code
neighborhood
a_fix_stencil_neighborhood
ustencil neighborhood option should be a tuple with constant structure such as ((-w, w),)
index_offsets
a_fix_stencil_index_offsets
ustencil index_offsets option should be a tuple with constant structure such as (offset, )
constant
a_definitions
res
uReduce function cannot be found for njit                             analysis
aFreeVar
numba
core
registry
aCPUDispatcher
uInvalid reduction function
py_func
a__code__
co_argcount
l uReduction function should take 2 arguments
check
uInlineWorker.__init__.<locals>.check
unumba.core.compiler
T aDefaultPassBuilder
aDefaultPassBuilder
targetctx
locals
pipeline
flags
typingctx
define_untyped_pipeline
a_compiler_pipeline
validator
T aInlineWorker
debug_print
utypemap and calltypes must both be either None or have a value, got: %s, %s
a_permit_update_type_and_call_maps
typemap
calltypes
u{} must not be None
copy_ir
uInlineWorker.inline_ir.<locals>.copy_ir
scope
max
ir_utils
a_the_max_label
anext
add_offset_to_labels
simplify_CFG
min
update
T uAfter relabel
a_get_all_scopes
ucallee_scopes =
localvars
a_con
a_created_inlined_var_name
callee_ir
unique_name
redefine
callee_scope
var_dict
uvar_dict =
replace_vars
T uAfter local var rename
a_get_callee_args
uarg_typs should have a value not None
update_type_and_call_maps
T uAfter arguments rename:
a_replace_args_with
callee_blocks
aBlock
next_label
aJump
find_topo_order
a_replace_returns
remove
a_add_definitions
caller_ir
new_blocks
T uAfter merge in
copy
deepcopy
the_ir
kernel_copy
run_untyped_passes
co_freevars
inline_ir
T aarg_typs
T aStateDict
a_CompileStatus
aStateDict
a_CompileStatus
unumba.core.untyped_passes
T aExtractByteCode
aExtractByteCode
unumba.core
T abytecode
bytecode
unumba.parfors.parfor
T aParforDiagnostics
aParforDiagnostics
enable_ssa
aFunctionIdentity
from_function
type_annotation
T Fastatus
return_type
parfor_diagnostics
metadata
run_pass
abc
pysig
parameters
types
pyobject
finalize
unumba.core.ssa
T areconstruct_ssa
reconstruct_ssa
unumba.core.typed_passes
T aPreLowerStripPhis
aPreLowerStripPhis
uInlineWorker instance not configured correctly, typemap or calltypes missing in initialization.
T atyped_passes
typed_passes
build_definitions
analysis
dead_branch_prune
type_inference_stage
utoo many values to unpack (expected 4)
a_strip_phi_nodes
canonicalize_array_math
startswith
T uarg.
f_typemap
pop
T ainline_closure_call
uFound closure call:
u with callee =
closure
a__closure__
aFunctionType
T acompiler
compiler
run_frontend
D ainline_closures
tacallee_code
ucallee's closure =
pythonapi
aPyCell_Get
py_object
restype
argtypes
a_replace_freevars
T uAfter closure rename
cellget
u<genexpr>
uinline_closure_call.<locals>.<genexpr>
vararg
uCalling a closure with *args is unsupported.
getattr
is_operator_or_getitem
list_vars
uUnsupported ir.Expr.{}
T uinline_closure_call default handling
utils
pysignature
u_get_callee_args.<locals>.<lambda>
stararg_handler
u_get_callee_args.<locals>.stararg_handler
typing
fold_arguments
defaults
a__defaults__
udefaults =
aVar
defaults_list
aConst
T avalue
loc
uUnsupported defaults to make_function: {}
uStararg not supported in inliner for arg {} {}
u_make_debug_print.<locals>.debug_print
config
aDEBUG_INLINE_CLOSURE
print
prefix
u:
u_make_debug_print.<locals>.debug_print.<locals>.<genexpr>
dump
all_scopes
aArg
index
aReturn
return_label
casts
stmt
cast
wiaDel
list_var
array_var
T aarray
numpy
aSetItem
a_find_unsafe_empty_inferred
T afind_array_call
array_stmt_index
array_kws
T afind_iter_range
urange_iter_var =
u def =
getiter
urange_var =
u range_def =
ufunc_var =
u func_def =
misc
special
prange
T u"array comprehension"
uclosure of
D alhs_only
taGuardException
aRangeIteratorType
yield_type
codegen
ulength_of_iterator.<locals>.codegen
signature
aListIter
intp
aArrayIterator
aUniTupleIter
aListTypeIteratorType
aTypingError
T uUnsupported iterator found in array comprehension, try preallocating the array and filling manually.
utoo many values to unpack (expected 1)
range_impl_map
val_type
cgutils
create_struct_proxy
count
type
impl_ret_untracked
load
get_value_type
aListIterInstance
size
make_helper
T avalue
array_type
make_array
array
unpack_tuple
shape
container
unumba.typed.listobject
T aListIterInstance
T ainline_arraycall
exits
a_find_arraycall
utoo many values to unpack (expected 3)
dtype
ulist_var =
list_var_def
build_list
in_loops
header
ucheck loop body block
attr
ulist_def =
list_append_stmts
label
predecessors
upreds =
entries
iternext
uiter_def =
iter_vars
pair_first
iter_first_vars
terminator
is_removed
u_inline_arraycall.<locals>.is_removed
loop_entry
list_def
removed
stmts
uremoved variables:
a_find_iter_range
a_new_definition
q abinop
operator
sub
T afn
lhs
rhs
loc
internal_prange
len_func
length_of_iterator
size_tuple
build_tuple
T aitems
loc
empty_func
dtype_def
dtype_mod
empty
np
unsafe_empty_inferred
truebr
insert
index_var
:l
q nanext_index
one
add
append_block
append_stmt
T uReplace append with SetItem
T atarget
index
value
loc
u_inline_arraycall.<locals>.<genexpr>
val
T a_find_unsafe_empty_inferred
compute_use_defs
compute_live_variables
defmap
find_array_def
u_fix_nested_array.<locals>.find_array_def
fix_dependencies
u_fix_nested_array.<locals>.fix_dependencies
fix_array_assign
u_fix_nested_array.<locals>.fix_array_assign
T afind_array_def
getitem
T afix_dependencies
defined
livemap
usedefs
u already defined
new_varlist
u not yet defined
new_var
T afix_array_assign
ufound SetItem:
ufound lhs_def:
ufound rhs_def:
rhs_def
udim_def =
uextra_dims =
usize_tuple_def =
fn
a_kws
T avalue
target
loc
aRewriteArrayOfConsts
a__init__
crnt_block
a_inline_const_arraycall
new_body
T ainline_const_arraycall
inline_array
u_inline_const_arraycall.<locals>.inline_array
T Oobject
a__prepare__
aState
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
