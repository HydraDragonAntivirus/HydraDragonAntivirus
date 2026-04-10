# Reconstructed from integrated Nuitka blob
# Module: unumba.parfors.parfor

uparfor_insert_dels.<locals>.DummyFuncIR
a__qualname__
uparfor_insert_dels.<locals>.DummyFuncIR.__init__
a__orig_bases__
postproc
aPostProcessor
a_patch_var_dels
find_potential_aliases
arg_names
order_changed
maximize_fusion_inner
alias_map
arg_aliases
up_direction
a_can_reorder_stmts
next_stmt
stmt
ret
has_no_side_effect
is_assert_equiv
expand_aliases
get_parfor_writes
get_stmt_writes
assert_equiv
writes
dprint
utry_fuse: trying to fuse
T utry_fuse: parfors different lowerers
aFusionReport
u- fusion failed: lowerer mismatch
T utry_fuse: parfors number of dimensions mismatch
uparallel loop #%s has a nest of %s loops
u- fusion failed: number of loops mismatched, %s, %s.
is_equiv
utry_fuse.<locals>.is_equiv
get_user_varname
utry_fuse.<locals>.get_user_varname
parfor1
parfor2
utry_fuse: parfor dimension correlation mismatch
u- fusion failed: loop dimension mismatched in axis %s.
uslice(%s, %s, %s) !=
uslice(%s, %s, %s)
has_cross_iter_dep
T utry_fuse: parfor cross iteration dependency found
u- fusion failed: cross iteration dependency found between loops #%s and #%s
p1_body_defs
p2_uses
get_array_indexed_with_parfor_index
get_loop_nest_vars
T utry_fuse: parfor2 depends on parfor1 body
u- fusion failed: parallel loop %s has a dependency on the body of parallel loop %s.
fuse_parfors_inner
var_rename_map
aArrayCompatible
p2arraynotindexed
utry_fuse.<locals>.<genexpr>
index_dict
T aentry_label
remove_duplicate_definitions
uParallel for-loop #{} is fused into for-loop #{}.
u- fusion succeeded: parallel for-loop #{} is fused into for-loop #{}.
ufuse_parfors_inner.<locals>.<genexpr>
defined
add_check_position
uhas_cross_iter_dep.<locals>.add_check_position
check_index
uhas_cross_iter_dep.<locals>.check_index
index_positions
indexed_arrays
non_indexed_arrays
derived_from_indices
isdisjoint
T taout
a_update_parfor_get_setitems
first_block_saved_values
lives_n_aliases
a_add_liveness_return_block
aLoc
T aparfors_dummy
q aterminator
cfg
successors
in_lives
alias_set
remove_dead_parfor_recursive
is_empty
uremove_dead_parfor.<locals>.<genexpr>
saved_values
T u$branchcond
boolean
remove_dead
T u$tuple_var
aReturn
n_parfors
T u$const
is_terminator
entry_label
copy_propagate
kill_set
ucopy propagate parfor gens:
var_dict
assign_list
T adummy
q aapply_copy_propagate
process_assign
upush_call_vars.<locals>.process_assign
saved_globals
saved_getattrs
D anested
ta_get_saved_call_nodes
block_defs
rename_dict
replace_var_names
fname
rename_global_or_getattr
u_get_saved_call_nodes.<locals>.rename_global_or_getattr
u$push_global_to_block
a_PA_DONE
u$push_getattr_to_block
w_u({}({}))
u({})
join
T w$u'%s' (temporary variable)
state_vars
new_state_types
state_types
get_tuple_table
get_array_accesses
add_offset_to_labels
T aloc
use_literal_type
build_constraint
aNumbaAssertionError
T ulen(args) != 3
aIS_32BITS
T uThe 'parallel' target is not currently supported on 32 bit hardware.
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
pytypes
sys
os
textwrap
collections
T adefaultdict
aOrderedDict
namedtuple
aOrderedDict
namedtuple
contextlib
T acontextmanager
contextmanager
dataclasses
T amake_dataclass
make_dataclass
llvmlite
T air
lir
unumba.core.imputils
T aimpl_ret_untracked
impl_ret_untracked
unumba.core.ir
T atypes
typing
utils
errors
ir
analysis
postproc
rewrites
typeinfer
config
ir_utils
rewrites
typeinfer
T aprange
pndindex
unumba.np.npdatetime_helpers
T adatetime_minimum
datetime_maximum
unumba.np.numpy_support
T aas_dtype
numpy_version
numpy_version
unumba.core.typing.templates
T ainfer_global
aAbstractTemplate
infer_global
aAbstractTemplate
unumba.stencils.stencilparfor
T aStencilPass
unumba.core.extending
T aregister_jitable
lower_builtin
register_jitable
lower_builtin
unumba.core.ir_utils
T+amk_unique_var
next_label
mk_alloc
get_np_ufunc_typ
mk_range_block
mk_loop_header
get_name_var_table
replace_vars
replace_vars_inner
visit_vars
visit_vars_inner
remove_dead
copy_propagate
get_block_copies
apply_copy_propagate
dprint_func_ir
find_topo_order
get_stmt_writes
rename_labels
get_call_table
simplify
simplify_CFG
has_no_side_effect
canonicalize_array_math
add_offset_to_labels
find_callname
find_build_sequence
guard
require
aGuardException
compile_to_numba_ir
get_definition
build_definitions
replace_arg_nodes
replace_returns
is_getitem
is_setitem
is_get_setitem
index_var_of_get_setitem
set_index_var_of_get_setitem
find_potential_aliases
replace_var_names
transfer_scope
get_name_var_table
is_getitem
is_setitem
unumba.core.analysis
T acompute_use_defs
compute_live_map
compute_dead_maps
compute_cfg_from_blocks
unumba.core.controlflow
T aCFGraph
aCFGraph
unumba.core.typing
T anpydecl
signature
unumba.core.types.functions
T aFunction
unumba.parfors.array_analysis
T arandom_int_args
random_1arg_size
random_2arg_sizelast
random_3arg_sizelast
random_calls
assert_equiv
T aoverload
overload
unumba.parfors
T aarray_analysis
unumba.cpython.builtins
unumba.stencils
T astencilparfor
stencilparfor
lPaTextWrapper
T awidth
drop_whitespace
init_prange_overload
a__new__
uinternal_prange.__new__
min_parallel_impl
max_parallel_impl
dotvm_parallel_impl
dot_parallel_impl
sum_parallel_impl
prod_parallel_impl
mean_parallel_impl
var_parallel_impl
std_parallel_impl
D adtype
naarange_parallel_impl
linspace_parallel_impl
T aargmin
numpy
T aargmax
numpy
T amin
numpy
T amax
numpy
T aamin
numpy
T aamax
numpy
T asum
numpy
T aprod
numpy
T amean
numpy
T avar
numpy
T astd
numpy
T adot
numpy
T aarange
numpy
T alinspace
numpy
fill_parallel_impl
fill
checker_impl
uLoopNest.__init__
a__repr__
uLoopNest.__repr__
uLoopNest.list_vars
aStmt
D ano_sequential_lowering
races
FnuParfor.__init__
uParfor.__repr__
uParfor.get_loop_nest_vars
uParfor.list_vars
T nuParfor.get_shape_classes
uParfor.dump
uParfor.validate_params
a_analyze_parfor
array_analysis_extensions
aParforDiagnostics
uParforDiagnostics.__init__
uParforDiagnostics.setup
property
uParforDiagnostics.has_setup
setter
uParforDiagnostics.count_parfors
uParforDiagnostics._get_nested_parfors
uParforDiagnostics._get_parfors
uParforDiagnostics.get_parfors
hoisted_allocations
uParforDiagnostics.hoisted_allocations
uParforDiagnostics.compute_graph_info
get_stats
uParforDiagnostics.get_stats
uParforDiagnostics.reachable_nodes
uParforDiagnostics.sort_pf_by_line
uParforDiagnostics.get_parfors_simple
uParforDiagnostics.get_all_lines
uParforDiagnostics.source_listing
uParforDiagnostics.print_unoptimised
uParforDiagnostics.print_optimised
uParforDiagnostics.allocation_hoist
uParforDiagnostics.instruction_hoist
uParforDiagnostics.dump
a__str__
uParforDiagnostics.__str__
uParforDiagnostics.__repr__
aPreParforPass
uPreParforPass.__init__
uPreParforPass.run
uPreParforPass._replace_parallel_functions
aParforPassStates
uParforPassStates.__init__
uConvertInplaceBinop.__init__
uConvertInplaceBinop.run
uConvertInplaceBinop._inplace_binop_to_parfor
uConvertInplaceBinop._type_getitem
uConvertSetItemPass.__init__
uConvertSetItemPass.run
uConvertSetItemPass._setitem_to_parfor
uConvertSetItemPass._type_getitem
uConvertNumpyPass.__init__
uConvertNumpyPass.run
a_is_C_order
uConvertNumpyPass._is_C_order
uConvertNumpyPass._is_C_or_F_order
uConvertNumpyPass._arrayexpr_to_parfor
uConvertNumpyPass._is_supported_npycall
uConvertNumpyPass._numpy_to_parfor
uConvertNumpyPass._numpy_map_to_parfor
uConvertReducePass.__init__
uConvertReducePass.run
uConvertReducePass._reduce_to_parfor
uConvertReducePass._mk_reduction_body
uConvertLoopPass.__init__
uConvertLoopPass.run
uConvertLoopPass._is_parallel_loop
uConvertLoopPass._get_loop_kind
uConvertLoopPass._get_prange_init_block
uConvertLoopPass._is_prange_init
uConvertLoopPass._replace_loop_access_indices
uConvertLoopPass._replace_multi_dim_ind
aParforPass
uParforPass._pre_run
uParforPass.run
uParforPass._find_mask
uParforPass._mk_parfor_loops
aParforFusionPass
uParforFusionPass.run
uParforFusionPass.fuse_parfors
uParforFusionPass.fuse_recursive_parfor
aParforPreLoweringPass
uParforPreLoweringPass.run
get_parfor_outputs
T a_RedVarInfo
L ainit_val
reduce_nodes
redop
tT afrozen
T nnnnnavisit_vars_parfor
visit_vars_extensions
parfor_defs
ir_extension_usedefs
a_parfor_use_alloca
ir_extension_use_alloca
parfor_insert_dels
ir_extension_insert_dels
first
second
message
remove_dead_parfor
remove_dead_extensions
find_potential_aliases_parfor
alias_analysis_extensions
get_copies_parfor
copy_propagate_extensions
apply_copies_parfor
apply_copy_propagate_extensions
get_parfor_call_table
call_table_extensions
get_parfor_tuple_table
tuple_table_extensions
get_parfor_array_accesses
array_accesses_extensions
parfor_add_offset_to_labels
add_offset_to_labels_extensions
parfor_find_max_label
find_max_label_extensions
parfor_typeinfer
typeinfer_extensions
build_parfor_definitions
build_defs_extensions
aReduceInfer
generic
uReduceInfer.generic
ensure_parallel_support
unumba\parfors\parfor.py
T a.0
wtwvaloop_index
T a.0
wxaindex_vars
T a.0
wxT aloop_body
loop_index_vars
T a.0
wxaself
T ablock
expr
wiainline_closure_call
lhs_typ
self
swapped
work_list
T a.0
waatypemap
T a.0
pv
unversion
rv
T a.0
waT a.0
wvanoncyclic_lookup
T a.0
wvT a.0
wxatypemap
p2arraynotindexed
T wrwaT atup
T wxu<module numba.parfors.parfor>
T a__class__
T aself
pass_states
T aself
index_variable
start
stop
step
Taself
loop_nests
init_block
loop_body
loc
index_var
equiv_set
pattern
flags
no_sequential_lowering
races
fmt
a__class__
T aself
T aself
func_ir
typemap
calltypes
return_type
typingctx
targetctx
options
flags
metadata
diagnostics
T	aself
func_ir
typemap
calltypes
typingctx
targetctx
options
swapped
replace_functions_map
T aself
blocks
T acls
args
T aself
wrT
blocks
lives
typemap
last_label
return_label
loc
scope
tuple_var
live_vars
tuple_call
T aparfor
equiv_set
typemap
array_analysis
func_ir
parfor_blocks
backup_equivset
T aself
equiv_set
lhs
arrayexpr
avail_vars
pass_states
scope
loc
expr
arr_typ
el_typ
size_vars
index_vars
loopnests
init_block
body_label
body_block
expr_out_var
index_var
index_var_typ
pat
parfor
setitem_node
T!afunc_ir
typingctx
typemap
calltypes
equiv_set
init_block
expr_out_var
expr
parfor_index_tuple_var
all_parfor_indices
avail_vars
el_typ
scope
loc
out_ir
op
arr_expr_args
arg_vars
arg
arg_out_var
el_typ1
el_typ2
func_typ
ir_expr
wTafunc_var_name
func_var
func_var_def
g_math_var
g_math
g_math_assign
call_typ
var_typ
T
stmt
next_stmt
func_ir
call_table
alias_map
arg_aliases
stmt_accesses
stmt_writes
next_accesses
next_writes
T ascope
params
races
unversion
races1
unver_params
rv
T abody
wiainst
T atypemap
func
avail_vars
loc
wvwtT aself
arr_def
T atypemap
func_ir
arr_def
value
index
value_typ
index_typ
ndim
seq
op
count_consts
mask_indices
mask_var
ind
mask_typ
T aequiv_set
var
parfor_index_tuple_var
all_parfor_indices
el_typ
calltypes
typingctx
typemap
init_block
out_ir
loc
index_var
var_typ
ndims
num_indices
size_vars
size_consts
ravel_var
ravel_typ
stmts
const_node
const_var
const_assign
ind_offset
tuple_var
index_vars
wiasize_var
size_const
tuple_call
tuple_assign
ir_expr
T aarg1
arg2
out_ir
typemap
typingctx
scope
loc
g_np_var
g_np
g_np_assign
div_attr_call
attr_var
func_var_typ
attr_assign
div_call
func_typ
T aexpr
typemap
new_arg_typs
arg
new_kw_types
name
T aself
func_var
call_table
pass_states
call
kind
T aself
parfor
parfors_list
blocks
T aself
blocks
parfors_list
label
blk
stmt
T aself
entry_block
call_table
prange_args
init_call_ind
prange_call_ind
init_body
wiainst
arg_related_vars
saved_nodes
inst_vars
T afname
saved_globals
saved_getattrs
block_defs
rename_dict
nodes
rename_global_or_getattr
T aself
equiv_set
loc
op
target
value
pass_states
scope
arr_typ
el_typ
init_block
value_typ
size_vars
index_vars
loopnests
body_label
body_block
index_var
index_var_typ
value_var
getitem_call
target_var
expr_out_var
binop_expr
unified_type
setitem_node
parfor
T aself
arr_name
typ
T afunc_ir
index
nest_indices
index_def
T aself
func_var
call_table
call
T aself
expr
call_name
mod_name
T ablock_label
block
new_blocks
typemap
calltypes
parfor_found
scope
wiainst
loc
prev_block
init_label
ndims
loopnest
range_label
header_label
range_block
phi_var
header_block
prev_header_label
body_last_label
body_first_label
wlwbT
typemap
scope
index_vars
body_block
force_tuple
ndims
loc
tuple_var
tuple_call
tuple_assign
T aself
size_vars
scope
loc
T atypemap
size_vars
scope
loc
loopnests
index_vars
size_var
index_var
T aself
call_name
scope
loc
index_vars
in_arr
acc_var
check_reduce_func
pass_states
reduce_func
fcode
arr_typ
in_typ
body_block
index_var
index_var_type
tmp_var
getitem_call
reduce_f_ir
loop_body
end_label
end_block
first_reduce_label
first_reduce_block
T aself
equiv_set
call_name
lhs
args
kws
expr
pass_states
scope
loc
arr_typ
el_typ
size_vars
index_vars
loopnests
init_block
body_label
body_block
expr_out_var
index_var
index_var_typ
value
new_arg_typs
new_kw_types
value_assign
setitem_node
parfor
T aself
equiv_set
lhs
expr
call_name
mod_name
args
kws
T aparfor
alloca_set
blocks
T aself
equiv_set
lhs
args
loc
pass_states
scope
call_name
in_arr
arr_def
mask_var
mask_indices
mask_query_result
mask_typ
init_val
size_vars
index_vars
loopnests
mask_index
acc_var
init_block
body_label
index_var
loop_body
true_label
false_label
body_block
mask
mask_val
parfor
T acall_name
expr
kws
dt_arg
T aself
loop_body
index_set
new_index
labels
first_label
added_indices
wlablock
stmt
scope
unver
index
ind_def
T aself
ind_var
index_set
new_index
pass_states
ind_def_node
T aself
blocks
swapped
inline_closure_call
work_list
label
block
wiainstr
lhs
lhs_typ
expr
replace_func
typ
dtype
scope
loc
g_np_var
g_np
g_np_assign
dtype_str
typ_var
typ_var_assign
dtype_attr_var
temp
tfunc
dtype_attr_getattr
dtype_attr_assign
dtype_var
dtype_getattr
dtype_assign
T#aself
equiv_set
loc
target
index
value
shape
pass_states
scope
arr_typ
el_typ
index_typ
init_block
size_vars
subarr_var
getitem_call
subarr_typ
bool_typ
loopnests
index_vars
size_var
index_var
body_label
body_block
index_var_typ
parfor
true_block
end_label
true_label
end_block
mask_var
mask_val
value_typ
value_var
setitem_node
T aself
args
fnty
T	ablock_body
index_var
alias_map
saved_values
lives
stmt
wwarhs
wvT anew_position
array_accessed
index_positions
indexed_arrays
non_indexed_arrays
npsize
T aself
found
pf_id
data
stmt
inst
attr
msg
loc
path
lines
T aparfor
var_dict
name_var_table
typemap
calltypes
save_copies
wiapattern
wlablocks
assign_list
lhs_name
rhs
in_copies_parfor
out_copies_parfor
T astop
inferred_dtype
T ainferred_dtype
T astop
dtype
T astart
stop
inferred_dtype
T astart
stop
dtype
T astart
stop
step
inferred_dtype
T astart
stop
step
dtype
T
start
stop
step
dtype
nitems_c
nitems_r
nitems_i
nitems
arr
wiT	astart
stop
step
dtype
nitems_r
nitems
arr
val
wiT areturn_type
dtype
args
inferred_dtype
arange_1
arange_1_dtype
arange_2
arange_2_dtype
arange_3
arange_3_dtype
arange_4
T aarr_size
T ain_arr
wAainit_val
ival
wiacurr_ival
T aparfor
definitions
T aparam
nodes
first_red_func
node
msg
T astmt_index
array_accessed
index_positions
indexed_arrays
non_indexed_arrays
derived_from_indices
fbs_res
ind_seq
w_anew_index_positions
typemap
func_ir
indices
add_check_position
T aadd_check_position
func_ir
indices
typemap
T aself
a_a
waavtx
wvwxapotential_roots
roots
not_roots
val
wlT	afadj
nadj
root
nfused
nserial
wkanf
ns
count_root
T acount_root
T avar
varonly
start
lookedup_var
defs
cyclic_lookup
T acyclic_lookup
defs
T areturn_type
atyp
btyp
T	wawbwmwnwlwcwiwswjT wawbwlwmwnwcwiT wawbwlwmwswiT wsT aloop_body
last_label
scope
const
T aself
file
loopnest
offset
block
T!aself
level
name
line
purpose_str
purpose
print_loop_search
print_source_listing
print_fusion_search
print_fusion_summary
print_loopnest_rewrite
print_pre_optimised
print_post_optimised
print_allocation_hoist
print_instruction_hoist
print_internal
parfors_simple
count
filename
path
sword
parfors
parfor_ids
n_parfors
msg
dump_graph_indented
report
l1
l2
after_fusion
root_msg
node_msg
all_lines
T	waaroot_msg
node_msg
fac
print_graph
wlaroots
sword
self
T aself
sword
T amsg
T athe_set
alias_map
arg_aliases
ret
wiT ain_arr
val
wiT areturn_type
arr
val
fill_1
T	aindices
block
inst
arrs
exprs
lv
expr
loop_index_vars
loop_body
Tasize_var
size_def
arr_var
live_vars
index_arrs
index_exprs
arr_def
result
expr
pass_states
loop
live_map
find_indexed_arrays
T afind_indexed_arrays
live_map
loop
pass_states
T aparfor
args
typemap
func_ir
alias_map
arg_aliases
blocks
T aop
ft
T agenerator_info
return_type
typemap
new_state_types
wvT aself
array_analysis
blocks
func_ir
typemap
label
block
equiv_set
fusion_happened
new_body
wiastmt
next_stmt
fused_node
fuse_report
Taparfor1
parfor2
parfor2_first_label
parfor2_first_block
parfor1_first_label
parfor1_last_label
ndims
index_dict
wiablocks
nameset
msg
report
T aself
parfor
equiv_set
func_ir
typemap
blocks
arr_analysis
T aself
args
kws
T aself
parfors_simple
fadj
froots
nadj
a_nroots
lim
tmp
wxanroots
wraall_roots
froots_lines
line
nroots_lines
all_lines
T aloop_body
index
nest_indices
func_ir
ret_indexed
ret_not_indexed
T aloop_body
index
ret_indexed
ret_not_indexed
nest_indices
func_ir
blk
stmt
setarray_index
getarray_index
getarray_name
T aparfor
typemap
blocks
in_copies_parfor
out_copies_parfor
in_gen_copies
in_extra_kill
kill_set
label
last_label
gens
T aexpr
T aparfor
accesses
blocks
T aparfor
call_table
reverse_call_table
blocks
T aparfor
parfor_params
last_label
outputs
blk
stmt
T ablocks
options_fusion
fusion_info
parfor_ids
parfors
pre_defs
w_aall_defs
topo_order
label
block
wiaparfor
dummy_block
before_defs
params
T aparfor
pre_defs
options_fusion
fusion_info
blocks
cfg
usedefs
live_map
parfor_ids
w_an_parfors
after_fusion
keylist
init_block
first_non_init_block
before_defs
params
T aparfor
out
pattern
left_lengths
right_lengths
wvT afunc_ir
parfor
parfor_params
calltypes
reductions
reduce_varnames
param_uses
param_nodes
var_to_param
blocks
topo_order
label
stmt
lhs
rhs
cur_param
used_vars
wvastmt_cp
param
param_name
reduce_nodes
gri_out
init_val
redop
T aparfor
tuple_table
blocks
T aparfor
writes
blocks
block
stmt
T aself
parfors_list
T	aself
print_loop_search
parfors_simple
pf
r_pattern
pattern
loc
replfn
fmt
T areduction_node
nodes
func_ir
reduce_nodes
defs
cyclic_lookup
noncyclic_lookup
name
unversioned_name
wiastmt
lhs
rhs
in_vars
foundj
wjajstmt
args
non_red_args
replace_dict
T anodes
acc_expr
acc_expr_fn
T aself
var
typemap
save_typemap
res
T aself
fadj
nadj
root
count_root
nfused
nserial
T wvauser_varname
metadata
T ametadata
T aparfor
func_ir
typemap
index_positions
indexed_arrays
non_indexed_arrays
indices
derived_from_indices
add_check_position
check_index
wbastmt
op
rhs_vars
T aself
state
T aself
allocs
pf_id
data
stmt
inst
call
T ano_op
T aself
hoist_info_printed
pf_id
data
hoisted
not_hoisted
T afunc_ir
expr
func_name
mod_name
T wxwyaequiv_set
T aequiv_set
T astart
stop
T astart
stop
num
arr
div
delta
wiadtype
T adtype
T areturn_type
args
dtype
linspace_2
linspace_3
T aself
all_uses
T aself
all_uses
wlwbastmt
loop
T
typingctx
func_ir
typemap
calltypes
metadata
parfor_found
new_blocks
scope
block_label
block
T ain_arr
T areturn_type
arg
max_1
T
func_ir
blocks
typemap
up_direction
call_table
w_aalias_map
arg_aliases
block
order_changed
T afunc_ir
block
call_table
alias_map
arg_aliases
up_direction
order_changed
wiastmt
next_stmt
can_reorder
T ain_arr
val
wiazero
T azero
T areturn_type
arg
zero
mean_1
T areturn_type
arg
min_1
T aargs
kwargs
res
cyclic_lookup
T acyclic_lookup
T aparfor
offset
blocks
Taparfor
use_set
def_set
blocks
uses
defs
cfg
last_label
topo_order
definitely_executed
loop
label
loop_vars
T aparfor
blocks
max_label
T aparfor
curr_dead_set
blocks
cfg
usedefs
live_map
dead_map
loop_vars
dead_set
label
aDummyFuncIR
post_proc
T	aparfor
typeinferer
save_blocks
blocks
index_vars
first_block
loc
index_assigns
save_first_block_body
T aty
pf_id
adj
depth
region_id
msg
fused
fac
sword
self
summary
T afac
self
summary
sword
T aty
pf_id
adj
depth
region_id
msg
fused
wkafac
sword
self
T afac
self
sword
T aadj
root
depth
wkafac
sword
node_msg
print_g
T afac
node_msg
print_g
sword
T afadj_
nadj_
nroot
depth
wkamsg
fused
fac
sword
reported
self
summary
region_id
print_g
T afac
print_g
region_id
reported
self
summary
sword
Tafadj_
nadj_
nroot
depth
wkamsg
fused
wiafac
sword
reported
self
print_g
T afac
print_g
reported
self
sword
T aadj
roots
print_g
wrasword
root_msg
wlT afac
wlanode_msg
root_msg
sword
T afadj_
nadj_
theroot
reported
region_id
print_g
sword
summary
T afadj_
nadj_
theroot
reported
region_id
print_g
T aself
lines
sword
fac
fadj
froots
nadj
a_nroots
lim
tmp
wxasummary
print_nest
print_fuse
region_id
reported
line
info
opt_ty
pf_id
adj
wkwvamsg
root
fused
serialized
T aself
lines
sword
fac
fadj
froots
nadj
a_nroots
lim
tmp
wxaprint_nest
print_fuse
region_id
reported
line
info
opt_ty
pf_id
adj
T wxwlT astmt
rhs
lhs
saved_globals
block_defs
saved_getattrs
T ablock_defs
saved_getattrs
saved_globals
T ain_arr
val
wiaone
T aone
T areturn_type
arg
one
prod_1
T ablocks
saved_globals
saved_getattrs
typemap
nested
block
new_body
block_defs
rename_dict
stmt
process_assign
wsapblocks
wvwkatemp_blocks
T aself
adj
root
fusers
wkT#aparfor
lives
lives_n_aliases
arg_aliases
alias_map
func_ir
typemap
labels
first_label
first_block_saved_values
saved_arrs
wlastmt
varnames
rm_arrs
waablock
saved_values
blocks
last_label
return_label
tuple_var
jump
cfg
usedefs
live_map
alias_set
label
new_body
in_lives
out_blk
a_data
alias_lives
wvais_empty
T aparfor
lives
arg_aliases
alias_map
func_ir
typemap
blocks
first_body_block
last_label
return_label
tuple_var
scope
branchcond
branch
T	ablocks
nameset
label
block
body
new_body
defined
inst
name
T aobj
var_base
nodes
block_defs
rename_dict
renamed_var
renamed_assign
T afunc_def
callname
repl_func
typs
kws_typs
new_func
wgacheck
new_blocks
w_acall_table
call
wkwvaself
expr
lhs_typ
inline_closure_call
block
wiawork_list
swapped
T aarrayexpr
opr
args
name
T aself
blocks
pass_states
topo_order
label
block
new_body
equiv_set
instr
lhs
expr
loc
target
value
target_typ
value_typ
new_instr
TEaself
blocks
pass_states
call_table
w_acfg
usedefs
live_map
loops
sized_loops
moved_blocks
loop
wsaentry
inst
msg
body_labels
args
loop_kind
loop_replacing
header_body
loop_index
hbi
stmt
li_index
cps
loop_index_vars
scope
loc
equiv_set
init_block
loop_body
end_label
bodydefs
bl
exit_lives
races
wlalast_inst
find_indexed_arrays
mask_var
mask_indices
find_mask_from_size
unsigned_index
result
in_arr
mask_typ
in_arr_typ
index_var
index_vars
size_vars
orig_index
first_body_block
body_block
index_var_typ
body
orig_index_var
body_label
labels
true_label
false_label
mask
mask_val
start
step
size_var
first_body_label
index_var_map
parfor
T aself
blocks
pass_states
topo_order
avail_vars
label
block
new_body
equiv_set
instr
expr
lhs
lhs_typ
new_instr
T aself
blocks
pass_states
topo_order
label
block
new_body
equiv_set
instr
parfor
loc
lhs
expr
callname
T aself
blocks
pass_states
topo_order
label
block
new_body
equiv_set
instr
loc
target
index
value
target_typ
index_typ
value_typ
new_instr
val_def
shape
sliced_dims
T aself
n_parfors
w_aparfors
wpT aself
stencil_pass
T aself
block_label
block
new_block
scope
stmt
loc
lhs
rhs
lhs_typ
str_var
lhs_const
str_assign
str_print
ir_print
parfor_ids
parfors
wpaname
n_parfors
after_fusion
T aself
func_ir
fusion_enabled
T	ablocks
n_parfors
block
stmt
parfor
last_block
scope
loc
const
T aself
pf_id
parfors_simple
pf
pattern
line
filename
nadj
nroots
fadj
froots
graphs
reported_loc
tmp
adj
wkablk
stmt
idx
wiT aself
parfors_simple
purpose_str
filename
count
func_name
lines
src_width
map_line_to_pf
wkwvamatch_line
max_pf_per_line
width
newlines
fmt
lstart
no
line
pf_ids
pfstr
stripped
srclen
wlT areturn_type
arg
std_1
T areturn_type
arg
zero
sum_1
T wxafunc_ir
supps
callname
T aequiv_set
parfor1
parfor2
metadata
func_ir
typemap
report
msg
fmt
l1
l2
ndims
is_equiv
get_user_varname
wianest1
nest2
p1_cross_dep
p1_ip
p1_ia
p1_non_ia
p2_cross_dep
p1_body_usedefs
p1_body_defs
defs
p2_usedefs
p2_uses
uses
overlap
w_ap2arraynotindexed
unsafe_var
T aname
errors
scope
T wkascope
T aparfor
blocks
init_block_label
first_body_label
block
T aself
typemap
msg
wpaty
T ain_arr
wmassd
wiaval
T areturn_type
arg
var_1
T aparfor
callback
cbdata
pattern
left_lengths
wiaright_lengths
T aparfor
callback
cbdata
wlT aparfor
entry_label
blocks
block
.numba.parfors.parfor_lowering
B
parfor
aParfor
a_lower_parfor_parallel
a__class__
lower_inst
lowerer
a_lower_parfor_parallel_std
unumba.np.ufunc.parallel
T aget_thread_count
l
get_thread_count
ensure_parallel_support
context
typing_context
builder
fndesc
typemap
copy
config
aDEBUG_ARRAY_OPT
print
ulowerer.fndesc
varmap
T a_lower_parfor_parallel
dump
init_block
loc
scope
uinit_block =
w abody
ulower init_block instr =
races
ir
aVar
a_alloca_var
name
numba
parfors
find_potential_aliases_parfor
params
func_ir
alias_map
arg_aliases
get_parfor_outputs
redvars
reddict
utoo many values to unpack (expected 2)
uparfor_redvars:
uparfor_reddict:
aParforLoweringBuilder
T alowerer
scope
loc
bind_global_function
np
ufunc
parallel
a_iget_num_threads
get_global_func_typ
T afobj
ftype
args
assign
call
D aargs
L
types
intp
num_threads_var
T arhs
typ
name
redtyp_to_redarraytype
dtype
reduction_info
aDType
npytypes
aArray
ndim
l apfbdr
empty
get_np_ufunc_typ
a_typingctx
aUniTuple
T afobj
ftype
args
kws
aExpr
getattr
shape
redarr_shape
static_getitem
redshape_var
redshapeonedim
size_var_list
make_tuple_variable
D aname
tuple_size_var
resolve_value_type
make_const_variable
T acval
typ
T aargs
redarr
redarrs
to_cleanup
init_val
full
T acval
typ
name
redtoset
append
aDEBUG_ARRAY_OPT_RUNTIME
ures_print1 for redvar
w:aStringLiteral
str_const
aPrint
T aargs
vararg
loc
signature
none
calltypes
res_print_redvar
targetctx
get_value_type
cgutils
alloca_once
redefine
u$loop_index
for_range
loadvar
T aintp
a__enter__
a__exit__
store
index
setitem
T aobj
index
val
T nnnaflags
numpy
error_model
loop_nests
index_variable
:l nnasequential_parfor_lowering
a_create_gufunc_for_parfor_body
utoo many values to unpack (expected 5)
sched
ufunc_args =
unum_inputs =
uparfor_outputs =
uparfor_redvars =
unum_reductions =
a_create_shape_signature
get_shape_classes
ugu_signature =
start
stop
step
uloop_nests =
uloop_ranges =
call_parallel_gufunc
a_parfor_lowering_finalize_reduction
aDel
T aloc
T u_lower_parfor_parallel done
items
a_ReductionInfo
T aredvar_info
redvar_name
redvar_typ
redarr_var
redarr_typ
init_val
redvar_info
redop
a_lower_trivial_inplace_binops
a_lower_non_trivial_reduce
thread_count_var
a__init__
uUnknown reduce instruction node:

reduce_nodes
a_lower_var_to_var_assign
a_is_right_op_and_rhs_is_init
reduce_info
redvar_name
inplace_binop
value
fn
a_emit_binop_reduce_call
storevar
target
T aname
binop
aParforsUnexpectedReduceNodeError
a_fix_redvar_name_ssa_mismatch
print_variable
u: parfor
a__name__
u reduction
u =
u#init
setdefault
redvar_typ
aAssign
list_vars
a_emit_getitem_call
tid
init_name
u: parfor non-trivial reduction
u<genexpr>
u_lower_non_trivial_reduce.<locals>.<genexpr>
reducer_getitem
u_emit_getitem_call.<locals>.reducer_getitem
redarr_typ
redarr_var
compile_internal
reduction_add
u_emit_binop_reduce_call.<locals>.reduction_add
reduction_mul
u_emit_binop_reduce_call.<locals>.reduction_mul
operator
iadd
isub
add
sub
imul
ifloordiv
itruediv
mul
floordiv
truediv
get
uintp
wcaop
rhs
get_exact
aNotDefinedError
reduction_var
unversioned_name
is_same_source_var
argument
T atypemap
T q aclass_set
max
insert
laaalphabet
class_map
latest_alpha
bump_alpha
u_create_shape_signature.<locals>.bump_alpha
args
classes
threadcount_ordinal
count
gu_sin
syms_sin
alpha_dict
u_create_shape_signature.<locals>.<genexpr>

wrap_find_topo
ulabel:
a_print_block
min
keys
aJump
:nq naremove
find_insts
add_to_def_once_sets
def_once
def_more
aGlobal
aModuleType
module_assigns
attr
getattr_taken
func
is_const_call
mutable
wrap_loop_body
find_topo_order
unwrap_loop_body
compute_def_once_block
compute_def_once_internal
loop_body
ustored array
aInstruction
ucould not be hoisted because the created array is stored.
visit_vars_inner
find_vars
difference
u_hoist_internal:
uuses:
udiff:
is_pure
uWill hoist instruction
dependency
ucould not be hoisted because of a dependency.
unot pure
ucould not be hoisted because it isn't pure.
aStaticSetItem
aSetItem
setitems
itemsset
find_setitems_block
find_setitems_body
add_to_itemset
ufind_setitems_block.<locals>.add_to_itemset
T abuild_tuple
build_list
build_set
build_map
kws
a_hoist_internal
compute_def_once
get_call_table
uhoist - def_once:
usetitems:
uitemsset:
udep_on_param:
uparfor_params:
empty_container_allocator_hoist
dep_on_param
call_table
hoisted
not_hoisted
T aparfor
new_init_block
new_block
wCalayout
legalize_names
aArrayCompatible
T ustarting _create_gufunc_for_parfor_body
remove_dels
get_parfor_reductions
sorted
uparfor_params =
uparfor_inputs =
aNamedUniTuple
expanded_tuple_var_
next_expanded_tuple_var
tuple_expanded_parfor_inputs
this_var_expansion
expanded_name_to_tuple_var
tuple_dtype
tuple_var_to_expanded_names
parfor_tuple_params
aTuple
aNamedTuple
uparfor_inputs post tuple handling =
uVariable %s used in parallel loop may be written to simultaneously by multiple workers and may result in non-deterministic or unintended results.
warnings
warn
aNumbaParallelSafetyWarning
replace_var_with_array
a_arr
parfor_redarrs
parfor_red_arg_types
redarraytype_to_sig
uloop_indices =
uloop_body =
a_print_body
legalize_names_with_typemap
uparam_dict =
uind_dict =
ulegal_loop_indices =
upd =
upd type =
to_scalar_from_0d
unew param_types:
unew func_arg_types:
replace_var_names
parfor_params
get_name_var_table
get_unused_var_name
a__sentinel__
ulegal parfor_params =
list
u__numba_parfor_gufunc_%s
w-w_ugufunc_name
str
udef
u(sched,
u,
u):
gufunc_txt
guard
get_definition
ufunc_def:
unamed_tuple_def:
aArg
named_tuple_def
aFreeVar
ugval:
globls
containers
aBaseNamedTuple
split
T w(uname:
instance_class
T uDidn't find definition of namedtuple for globls.
aCompilerError
uCould not find definition of
u =
w(afields
w=w,u = (
u)
aParallelAcceleratorGufuncThreadId
unumba.np.ufunc.parallel._iget_thread_id()
w[agufunc_thread_id_var
u]
u    print("thread id =", ParallelAcceleratorGufuncThreadId)
u    print("initial reduction value",ParallelAcceleratorGufuncThreadId,
u.shape)
u    print("reduction array",ParallelAcceleratorGufuncThreadId,
ufor
u in range(sched[
u], sched[
parfor_dim
u] + np.uint8(1)):
uprint(
w"u",
u = 0
u    print("final reduction value",ParallelAcceleratorGufuncThreadId,
u    print("final reduction array",ParallelAcceleratorGufuncThreadId,
u] =
w
u    return None
ugufunc_txt =
uglobls:
dict
u<string>
exec
ugufunc_func =
compiler
run_frontend
ugufunc_ir dump
uloop_body dump
blocks
values
new_var_dict
T ugufunc_ir dump after renaming
ugufunc_param_types =
find_max_label
add_offset_to_labels
clear
number_domain
u{} =
aConst
T avalue
loc
T avalue
target
loc
core
typing
T uparfor loop body
hoist
q ametadata
parfor_diagnostics
hoist_info
id
T uAfter hoisting
aBlock
transfer_scope
gufunc_ir
new_label
T ugufunc_ir last dump before renaming
rename_labels
T ugufunc_ir last dump
noalias
T uNo aliases found so adding noalias flag.
fixup_var_define_in_scope
aCompilerBase
a__prepare__
aParforGufuncCompiler
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
