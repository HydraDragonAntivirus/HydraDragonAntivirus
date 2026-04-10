# Reconstructed from integrated Nuitka blob
# Module: unumba.parfors.parfor_lowering_utils

aParforLoweringBuilder
a__qualname__
a__init__
uParforLoweringBuilder.__init__
uParforLoweringBuilder._context
uParforLoweringBuilder._typingctx
uParforLoweringBuilder._typemap
uParforLoweringBuilder._calltypes
T nabind_global_function
uParforLoweringBuilder.bind_global_function
T apf_const
make_const_variable
uParforLoweringBuilder.make_const_variable
T apf_tuple
make_tuple_variable
uParforLoweringBuilder.make_tuple_variable
T apf_assign
uParforLoweringBuilder.assign
assign_inplace
uParforLoweringBuilder.assign_inplace
uParforLoweringBuilder.call
setitem
uParforLoweringBuilder.setitem
uParforLoweringBuilder.getitem
unumba\parfors\parfor_lowering_utils.py
u<module numba.parfors.parfor_lowering_utils>
T a__class__
T aself
lowerer
scope
loc
T aself
T aself
rhs
typ
name
loc
var
assign
T
self
fobj
ftype
args
kws
loc
varname
gvname
func_sig
func_var
T aself
callable_node
args
kws
call
T aself
obj
index
typ
tm
getitem
T aself
cval
typ
name
T aself
varlist
name
loc
vartys
tupty
T aself
obj
index
val
loc
tm
setitem
.numba.stencils
#
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_numba
u\not_existing
stencils
T aNUITKA_PACKAGE_numba_stencils
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
unumba\stencils\__init__.py
u<module numba.stencils>

.numba.stencils.stencil
Y
h astencilFunc
compile_for_argtys
args
return_type
call_internal
fndesc
add_linking_libs
library
shape
literal_unroll
waandim
uSecondary stencil array does not have same number  of dimensions as the first stencil input.
ashape
uSecondary stencil array has some dimension smaller the same dimension in the first stencil input.
start
stop
id_counter
id
l akernel_ir
mode
options
kws
registry
cpu_target
typing_context
a_typingctx
target_context
a_targetctx
a_install_type
get
T aneighborhood
neighborhood
a_type_cache
aStencilFuncLowerer
a_lower_me
items
utoo many values to unpack (expected 2)
scope
loc
body
ir
aReturn
ret_blocks
label
index_vars
aVar
out_name
l
new_body
aSetItem
value
var_index_vars
redefine
stencil_index
aExpr
build_tuple
aAssign
append
config
aDEBUG_ARRAY_OPT
print
add_indices_to_kernel
ir_utils
dump_blocks
blocks
aNumbaValueError
u%d dimensional neighborhood specified for %d dimensional input array
get_tuple_table
values
aConst
uremembering in const_dict
target
name
const_dict
op
T asetitem
static_setitem
kernel
arg_names
T uAssignments to arrays passed to stencil kernels is not allowed.
T agetitem
static_getitem
getitem
index
index_var
relatively_indexed
add
kernel_consts
T ustencil kernel index is not constant, 'neighborhood' option required
typemap
types
misc
aSliceType
slice_addition
numba
njit
functions
aDispatcher
aGlobal
call
get_call_type
self
intp
calltypes
binop
operator
const_index
const_index_vars
ind_stencil_index
ind_stencils
stmt_index_var
aConstSized
:nnnT uStencil kernel with no accesses to relatively indexed arrays.
te
min
max
T ustencil kernel index is not constant,'neighborhood' option required
T uNon-tuple or non-integer used as stencil index.
T uStencil index does not match array dimensionality.
get_return_type
npytypes
aArray
T uThe first argument to a stencil kernel must be the primary input array.
unumba.core
T atyped_passes
typed_passes
type_inference_stage
utoo many values to unpack (expected 4)
T uStencil kernel must return a scalar and not a numpy array.
layout
aStencilFuncTyping_
aAbstractTemplate
key
generic
a_type_me
unumba.stencils.stencil
insert_user_function
a_stencil_wrapper

out
u, out=None
u, neighborhood=None
utoo many values to unpack (expected 3)
signature
udef __numba_dummy_stencil({}{}):
pass
w,u<string>
exec
a__numba_dummy_stencil
replace
utils
pysignature
T apysig
insert_func_defn
copy
deepcopy
new_block
copy_calltypes
kernel_copy
copy_ir_with_calltypes
remove_args
copy_propagate
get_name_var_table
apply_copy_propagate
T uCannot use the reserved word 'out' in stencil kernels.
get_unused_var_name
a__sentinel__
name_var_table
dtype
u__numba_stencil_%s_%s
w-w_u, {}=None
standard_indexing
T uThe first argument to a stencil kernel must use relative indexing, not standard indexing.
T uStandard indexing requested for an array name not present in the stencil kernel definition.
T uAfter add_indices_to_kernel
replace_return_with_setitem
uAfter replace_return_with_setitem
udef {}({}{}):
u{}[{}][0]
u{}[{}][1]
ranges
u    raise_if_incompatible_array_sizes(
func_text
u)
full_shape
u    {} = {}.shape
cval_as_str
uStencilFunc._stencil_wrapper.<locals>.cval_as_str
numpy_support
as_dtype
type
a__name__
u{} = np.empty({}, dtype=np.{})
cval
typing
typeof
can_convert
T ucval type does not match stencil return type.

w:athe_array
u:-{}
u-{}:
u{}[{}] = {}
u{}[:] = {}
offset
ufor {} in range(-min(0,{}),{}[{}]-max(0,{})):
u{} = 0
u    return {}
T unew stencil func text
result
sigret
first_arg
in_cps
out_cps
sentinel_name
stencil_func_name
wiaindex_var_name
neighborhood_name
sig_extra
standard_indexed
kernel_size
lo
hi
other_array
shape_name
return_type_name
out_init
cval_ty
dim
start_items
end_items
wjadct
pysig
T acompiler
compiler
run_frontend
remove_dels
new_var_dict
replace_var_names
keys
add_offset_to_labels
stencil_stub_last_label
uret_blocks w/ offsets
T ubefore replace sentinel stencil_ir
T ubefore replace sentinel kernel_copy
aBlock
aJump
stencil_ir
new_label
rename_labels
new_stencil_param_types
fixup_var_define_in_scope
compile_ir
aDEFAULT_FLAGS
np
isfinite
isnan
unp.nan
isinf
u-np.inf
unp.inf
refresh
u{} dimensional neighborhood specified for {} dimensional input array
from_dtype
map_layout
a__call__
array_types
entry_point
constant
T acval
standard_indexing
neighborhood
uUnknown stencil option
a_stencil
uUnsupported mode style
decorated
u_stencil.<locals>.decorated
aStencilFunc
lir
aConstant
aIntType
bitwidth
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
llvmlite
T air
T atypes
typing
utils
ir
config
ir_utils
registry
unumba.core.typing.templates
T aCallableTemplate
signature
infer_global
aAbstractTemplate
aCallableTemplate
infer_global
unumba.core.imputils
T alower_builtin
lower_builtin
unumba.core.extending
T aregister_jitable
register_jitable
unumba.core.errors
T aNumbaValueError
unumba.misc.special
T aliteral_unroll
unumba.np
T anumpy_support
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
