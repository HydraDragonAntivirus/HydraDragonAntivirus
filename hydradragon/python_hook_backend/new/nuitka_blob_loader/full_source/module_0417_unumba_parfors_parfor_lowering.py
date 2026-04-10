# Reconstructed from integrated Nuitka blob
# Module: unumba.parfors.parfor_lowering

u_create_gufunc_for_parfor_body.<locals>.ParforGufuncCompiler
a__qualname__
define_pipelines
u_create_gufunc_for_parfor_body.<locals>.ParforGufuncCompiler.define_pipelines
a__orig_bases__
compile_ir
T apipeline_class
ufinished create_gufunc_for_parfor_body. kernel_sig =
unumba.core.compiler_machinery
T aPassManager
aPassManager
aDefaultPassBuilder
T afull_parfor_gufunc
define_parfor_gufunc_pipeline
state
passes
extend
define_parfor_gufunc_nopython_lowering_pipeline
finalize
vars
u$const_ind_0
u$val
replace_var_with_array_internal
replace_var_with_array_in_block
pop
T abuild_gufunc_wrapper
a_launch_threads
build_gufunc_wrapper
a_launch_threads
T amake_parallel_loop
uouter_sig =
return_type
recvr
pysig
expr_args
expr_arg_types
gu_signature
sigutils
normalize_signature
library
get_function
llvm_func_name
D acache
is_parfors
Fta_ensure_finalized
uparallel function =
load_range
ucall_parallel_gufunc.<locals>.load_range
loop_ranges
utoo many values to unpack (expected 3)
ucall_parallel_gufunc loop_ranges[{}] =
printf
uloop range[{}]: %d %d (%d)
llvmlite
aIntType
T l aPointerType
get_constant
type
get_abi_sizeof
T l
uParfor has potentially negative start
signed
dim_starts
T asize
name
dim_stops
one_type
sext
one
gep
get_or_insert_function
module
aFunctionType
D aname
get_parallel_chunksize
aVoidType
D aname
set_parallel_chunksize
bitwidth
get_num_threads
if_unlikely
icmp_signed
u<=
unum_threads: %d
call_conv
return_user_exc
T uInvalid number of threads. This likely indicates a bug in Numba.
D aname
get_sched_size
l D aname
allocate_sched
D aname
do_scheduling_signed
D aname
do_scheduling_unsigned
load
load_potential_tuple_var
ucall_parallel_gufunc.<locals>.load_potential_tuple_var
pargs
bitcast
make_array
unpack_tuple
strides
array_strides
data
byte_ptr_t
boolean
get_data_type
T l arv_to_arg_dict
aOptional
cast
unpacked_aty
aBoolean
ptr
utoo many values to unpack (expected 4)
uvar =
ugu_sig =
utype =
ui =
uvar =
u type =
aty
sig_dim_dict
arg
wiaoccurrences
udim_sym =
u, i =
u = %d
pshape
shapes
psteps
zero
steps
get_null_value
active_code_library
add_linking_library
ubefore calling kernel %p
uafter calling kernel %p
D aname
deallocate_sched
getvar
exp_name_to_tuple_var
extract_value
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
pytypes
dataclasses
T amake_dataclass
make_dataclass
ullvmlite.ir
unumba.parfors
unumba.core
T atypes
ir
config
compiler
sigutils
cgutils
unumba.core.ir_utils
T aadd_offset_to_labels
replace_var_names
remove_dels
legalize_names
rename_labels
get_name_var_table
visit_vars_inner
get_definition
guard
get_call_table
is_pure
get_np_ufunc_typ
get_unused_var_name
is_const_call
fixup_var_define_in_scope
transfer_scope
find_max_label
get_global_func_typ
find_topo_order
unumba.core.typing
T asignature
T alowering
lowering
unumba.parfors.parfor
T aensure_parallel_support
unumba.core.errors
T aNumbaParallelSafetyWarning
aNotDefinedError
aCompilerError
aInternalError
aInternalError
unumba.parfors.parfor_lowering_utils
T aParforLoweringBuilder
aLower
aParforLower
uParforLower.lower_inst
property
a_disable_sroa_like_opt
uParforLower._disable_sroa_like_opt
T a_ReductionInfo
L aredvar_info
redvar_name
redvar_typ
redarr_var
redarr_typ
init_val
tT afrozen
uParforsUnexpectedReduceNodeError.__init__
redtyp_is_scalar
unumba\parfors\parfor_lowering.py
T a.0
wcabump_alpha
class_map
T a.0
var
init_name
u<module numba.parfors.parfor_lowering>
T a__class__
T aself
inst
a__class__
Tgalowerer
parfor
typemap
typingctx
targetctx
flags
locals
has_aliases
index_var_typ
races
loc
loop_body
parfor_dim
loop_indices
parfor_params
parfor_outputs
parfor_redvars
parfor_reddict
parfor_inputs
tuple_expanded_parfor_inputs
tuple_var_to_expanded_names
expanded_name_to_tuple_var
next_expanded_tuple_var
parfor_tuple_params
pi
pi_type
tuple_count
tuple_dtype
this_var_expansion
wiaexpanded_name
tuple_types
race
msg
parfor_redarrs
parfor_red_arg_types
var
arr
redarraytype
redarrsig
param_dict
ind_dict
legal_loop_indices
pd
param_types
func_arg_types
parfor_args
parfor_params_orig
ascontig
pindex
loop_body_var_table
sentinel_name
gufunc_name
gufunc_txt
globls
tup_var
exp_names
tup_type
named_tup
func_def
named_tuple_def
gval
named_tuple_name
name
field_name
gufunc_thread_id_var
eachdim
indent
sched_dim
locls
gufunc_func
gufunc_ir
var_table
new_var_dict
reserved_names
gufunc_param_types
gufunc_stub_last_label
new_label
label
block
new_block
scope
inst
strval
strconsttyp
lhs
assign_lhs
print_node
sig
wrapped_blocks
hoisted
not_hoisted
start_block
diagnostics
prev_block
body_first_label
wlwbabody_last_label
old_alias
aParforGufuncCompiler
kernel_func
kernel_sig
T aget_shape_classes
num_inputs
num_reductions
args
func_sig
races
typemap
wianum_inouts
classes
class_set
a_class
max_class
thread_num_class
class_map
alphabet
wnathreadcount_ordinal
alpha_dict
bump_alpha
gu_sin
gu_sout
count
syms_sin
cls
arg
dim_syms
T aself
T abinop
lowerer
thread_count_var
reduce_info
reduction_add
reduction_mul
kernel
ctx
builder
redarr_typ
arg_arr
init_var
res_print
typemap
arg_thread_count
args
sig
redvar_result
T aidx
lowerer
reduce_info
reducer_getitem
builder
ctx
redarr_typ
arg_arr
args
sig
elem
T
parfor
lowerer
inst
redvar_name
scope
reduction_var
is_same_source_var
redvar_unver_name
target_unver_name
val
T ainst
dep_on_param
call_table
hoisted
not_hoisted
typemap
stored_arrays
target_type
uses
unhoistable
use_unhoist
diff
T ainst
redvar_name
op
rhs
T aparfor
lowerer
thread_count_var
reduce_info
init_name
num_thread_llval
loop
tid
inst
elem
varname
T alowerer
parfor
TFalowerer
parfor
get_thread_count
typingctx
targetctx
builder
orig_typemap
typemap
varmap
loc
scope
instr
racevar
rvtyp
rv
alias_map
arg_aliases
parfor_output_arrays
parfor_redvars
parfor_reddict
nredvars
redarrs
to_cleanup
pfbdr
get_num_threads
num_threads_var
wiared_name
redvar_typ
redvar
redarrvar_typ
reddtype
redarrdim
glbl_np_empty
size_var_list
redshape_var
wjaonedimvar
size_var
cval
dt
empty_call
redarr_var
init_val
full_func_node
init_val_var
full_call
redtoset
res_print_str
strconsttyp
lhs
res_print
num_thread_type
ntllvm_type
alloc_loop_var
numba_ir_loop_index_var
loop
flags
index_var_typ
wlafunc
func_args
func_sig
func_arg_types
exp_name_to_tuple_var
num_reductions
num_inputs
gu_signature
loop_ranges
wvT aparfor
lowerer
thread_count_var
reduce_info
inst
fn
redvar_result
varname
T alowerer
inst
loaded
T aparfor
redarrs
lowerer
parfor_reddict
thread_count_var
redvar_name
redarr_var
redvar_typ
redarr_typ
init_val
reduce_info
handler
T ablock
wiainst
T abody_dict
topo_order
label
block
T aa_def
def_once
def_more
T aitem
typemap
itemsset
T aitemsset
typemap
T wcaclass_map
alpha_dict
T aalpha_dict
Thalowerer
cres
gu_signature
outer_sig
expr_args
expr_arg_types
loop_ranges
redvars
reddict
redarrdict
init_block
index_var_typ
races
exp_name_to_tuple_var
context
builder
build_gufunc_wrapper
a_launch_threads
args
return_type
llvm_func
sin
sout
info
wrapper_name
load_range
num_dim
wiastart
stop
step
byte_t
byte_ptr_t
byte_ptr_ptr_t
intp_t
uintp_t
intp_ptr_t
intp_ptr_ptr_t
uintp_ptr_t
uintp_ptr_ptr_t
zero
one
one_type
sizeof_intp
sched_sig
sched_type
sched_ptr_type
sched_ptr_ptr_type
dim_starts
dim_stops
get_chunksize
set_chunksize
get_num_threads
num_threads
current_chunksize
get_sched_size_fnty
get_sched_size
num_divisions
multiplier
sched_size
alloc_sched_fnty
alloc_sched_func
alloc_space
sched
debug_flag
scheduling_fnty
do_scheduling
redarrs
nredvars
ninouts
load_potential_tuple_var
all_args
num_args
num_inps
array_strides
rv_to_arg_dict
arg
var
aty
dst
ary
strides
wjatyp
rv_arg
unpacked_aty
ptr
sig_dim_dict
occurrences
gu_sig
dim_sym
shapes
nshapes
num_steps
steps
stepsize
data
fnty
fn
dealloc_sched_fnty
dealloc_sched_func
wkwvaonly_elem_ptr
T aloop_body
typemap
def_once
def_more
getattr_taken
module_assigns
T ablock
def_once
def_more
getattr_taken
typemap
module_assigns
assignments
one_assign
a_def
rhs
base_obj
base_attr
base_mod_name
argvar
avtype
T
loop_body
def_once
def_more
getattr_taken
typemap
module_assigns
topo_order
label
block
inst
T aself
aPassManager
dpb
pm
parfor_gufunc_passes
lowering_passes
T ainst
dep_on_param
call_table
hoisted
not_hoisted
typemap
stored_arrays
call_list
T	asetitems
itemsset
block
typemap
inst
rhs
add_to_itemset
item
pair
T asetitems
itemsset
loop_body
typemap
label
block
T avar
varset
T aparfor_params
loop_body
typemap
wrapped_blocks
dep_on_param
hoisted
not_hoisted
def_once
def_more
call_table
reverse_call_table
setitems
itemsset
si
label
block
new_block
inst
new_init_block
ib_inst
T anames
typemap
outdict
wxwyT wxaorig_tup
offset
tup_var
res
exp_name_to_tuple_var
lowerer
builder
T abuilder
exp_name_to_tuple_var
lowerer
T wvalowerer
context
T acontext
lowerer
T aredarraytyp
T aredtype
T aredtyp
redarrdim
T aredarr
index
T athread_count
redarr
init
wcwiT avars
loop_body
typemap
calltypes
wvael_typ
Tavars
block
typemap
calltypes
new_block
inst
loc
scope
const_node
const_var
const_assign
val_var
setitem_node
T avars
loop_body
typemap
calltypes
label
block
T wxT aloop_body
last_label
T aloop_body
blocks
topo_order
T aloop_body
blocks
first_label
last_label
loc
.numba.parfors.parfor_lowering_utils
a
def a_lowerer
a_scope
a_loc
context
a_context
typing_context
fndesc
typemap
calltypes
a__name__

a_func
a_typingctx
resolve_function_type
assign
ir
aGlobal
T aloc
T arhs
typ
name
a_CallableNode
T afunc
sig
aConst
self
a_typemap
name
types
aTuple
from_types
aExpr
build_tuple
redefine
aAssign
lower_inst
aVar
setdefault
call
func
sig
a_calltypes
aSetItem
signature
none
getitem
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
collections
T anamedtuple
l
namedtuple
unumba.core
T atypes
ir
unumba.core.typing
T asignature
aBoundFunc
