# Reconstructed from integrated Nuitka blob
# Module: unumba.core.typeconv.typeconv

a__qualname__
ord
T wslsT wuluT wplpa__init__
uTypeManager.__init__
uTypeManager.select_overload
uTypeManager.check_compatible
uTypeManager.set_compatible
uTypeManager.set_promote
uTypeManager.set_unsafe_convert
uTypeManager.set_safe_convert
uTypeManager.get_pointer
a__orig_bases__
aTypeCastingRules
uTypeCastingRules.__init__
uTypeCastingRules.promote
uTypeCastingRules.unsafe
uTypeCastingRules.safe
promote_unsafe
uTypeCastingRules.promote_unsafe
safe_unsafe
uTypeCastingRules.safe_unsafe
unsafe_unsafe
uTypeCastingRules.unsafe_unsafe
uTypeCastingRules._cb_update
unumba\core\typeconv\typeconv.py
u<module numba.core.typeconv.typeconv>
T a__class__
T aself
tm
T aself
T aself
wawbarel
T aself
fromty
toty
name
conv
T aself
wawbT aself
sig
overloads
allow_unsafe
exact_match_required
T aself
fromty
toty
by
code
T aself
fromty
toty
.numba.core.typed_passes
*
state
status
can_fallback
with_traceback
T naflags
enable_looplift

aOUT

Compilation is falling back to object mode WITH%s looplifting enabled because %s
msg
warnings
warn_explicit
u%s due to: %s
errors
aNumbaWarning
func_id
filename
firstlineno
fallback_context
arg_count
uMismatch number of argument types
aWarningsFixer
typeinfer
aTypeInferer
callstack
register
target
a__enter__
a__exit__
arg_names
utoo many values to unpack (expected 2)
infer
seed_argument
seed_return
items
seed_type
build_constraint
propagate
T araise_errors
unify
utoo many values to unpack (expected 3)
T nnna_TypingResults
typemap
restype
calltypes
errs
aFunctionPass
a__init__
uFunction "%s" failed type inference
func_name
type_inference_stage
typingctx
targetctx
func_ir
args
return_type
locals
a_raise_errors
utoo many values to unpack (expected 4)
typing_errors
legalize_return_type
uBaseTypeInference.run_pass.<locals>.legalize_return_type
uFunction "%s" has invalid return type
enable_nrt
types
aArray
blocks
body
ir
aReturn
retstmts
value
name
aAssign
aExpr
op
cast
caststmts
aArg
argvars
add
self
aNumbaTypeError
T uOnly accept returning of array passed into the function as argument
aFunction
aPhantom
uCan't return function object ({}) in nopython mode
aAnalysisPass
add_required
aIRLegalization
copy
type_annotations
aTypeAnnotation
lifted
lifted_from
config
aHTML
T afunc_ir
typemap
calltypes
lifted
lifted_from
args
return_type
html_output
type_annotation
aANNOTATE
print
T u-----------------------------------ANNOTATION-----------------------------------
T u================================================================================
wwahtml_annotate
uInternal error in post-inference rewriting pass encountered during compilation of function "%s"
postproc
aPostProcessor
run
T tarewrites
rewrite_registry
apply
uafter-inference
remove_dels
a_parfor_PreParforPass
auto_parallel
parfor_diagnostics
replaced_fns
unumba.np.ufunc.parallel
T a_launch_threads
l
a_launch_threads
a_parfor_ParforPass
metadata
values
aParfor
has_parfor
aDISABLE_PERFORMANCE_WARNINGS
loc
u<string>
warn
aNumbaPerformanceWarning

The keyword argument 'parallel=True' was specified but no transformation for parallel execution was possible.
To find out why, try turning on parallel diagnostics, see https://numba.readthedocs.io/en/stable/user/parallel.html#diagnostics for help.
reload_init
append
a_reload_parfors
a_parfor_ParforFusionPass
a_parfor_ParforPreLoweringPass
enabled
aPARALLEL_DIAGNOSTICS
dump
uDiagnostics failed.
aLoweringPass
library
codegen
create_library
func_qualname
enable_object_caching
llvm
newpassmanagers
dump_refprune_stats
uFunction %s failed at nopython mode lowering
funcdesc
aPythonFunctionDescriptor
from_specialized_function
mangler
forceinline
noalias
get_mangle_string
T amangler
inline
noalias
abi_tags
push_code_library
lowering_class
T ametadata
lower
no_cpython_wrapper
create_cpython_wrapper
release_gil
no_cfunc_wrapper
aOmitted
aGenerator
aOptional
create_cfunc_wrapper
env
call_helper
unumba.core.compiler
T a_LowerResult
a_LowerResult
no_compile
T acfunc
env
cr
get_executable
insert_user_function
prune_stats
recorded_timings
llvm_pass_timings
lowering
aLower
aParforLower
raise_on_unsupported_feature
warn_deprecated
check_and_legalize_ir
T aflags
typing
signature
T acompile_result
compile_result
cfunc
fail_reason
fndesc
T atyping_context
target_context
entry_point
typing_error
type_annotation
library
call_helper
signature
objectmode
lifted
fndesc
environment
metadata
reload_init
a_DEBUG
T u-----------------------------before overload inline-----------------------------
unique_name
T u--------------------------------------------------------------------------------
unumba.core.inline_closurecall
T aInlineWorker
callee_ir_validator
aInlineWorker
callee_ir_validator
pipeline
work_list
pop
a_do_work_expr
guard
block
inline_worker
T u-----------------------------after overload inline------------------------------
modified
compute_cfg_from_blocks
dead_nodes
dead_code_elimination
T atypemap
simplify_CFG
T u---------------------------after overload inline DCE----------------------------
unliteral
find_matching_getattr_template
attr
template
is_method
get_func_type
uInlineOverloads._get_callable_info.<locals>.get_func_type
call
get_definition
func
make_function
T nnFathis
templates
sig
get_call_type
is_operator_or_getitem
resolve_value_type
fn
select_template
uInlineOverloads._do_work_expr.<locals>.select_template
getattr
a_get_attr_info
a_get_callable_info
a_run_inliner
a_inline
a_inline_overloads
is_never_inline
a_overload_func
inline_type
impl
is_always_inline
unumba.core.typing.templates
T a_inline_info
a_inline_info
iinfo
has_cost_model
a_add_method_self_arg
folded_args
a__code__
co_freevars
inline_ir
T aarg_typs
insert
a_strip_phi_nodes
build_definitions
a_definitions
a_simplify_conditionally_defined_variable
T FT aemit_dels
generator_info
state_vars
gen_func
yield_type
arg_types
has_finalizer
T agen_func
yield_type
arg_types
state_types
has_finalizer
defaultdict
T Olist
find_insts
phi
phis
incoming_blocks
incoming_values
assign
newblocks
aUNDEFINED
null
T aloc
T atarget
value
loc
newblk
q ainsert_after
prepend
scope
unver_or_undef
uPreLowerStripPhis._simplify_conditionally_defined_variable.<locals>.unver_or_undef
legalize_all_versioned_names
uPreLowerStripPhis._simplify_conditionally_defined_variable.<locals>.legalize_all_versioned_names
get_exact
aNotDefinedError
unversioned_name
suspects
versioned_names
delete_set
replace_map
blk
remove
replace_vars
aVar
defs
get
partial
wka__doc__
a__file__
a__spec__
origin
has_location
a__cached__
abc
contextlib
T acontextmanager
contextmanager
collections
T adefaultdict
namedtuple
namedtuple
T acopy
unumba.core
T	aerrors
types
typing
ir
funcdesc
rewrites
typeinfer
config
lowering
unumba.parfors.parfor
T aPreParforPass
aPreParforPass
T aParforPass
aParforPass
T aParforFusionPass
aParforFusionPass
T aParforPreLoweringPass
aParforPreLoweringPass
T aParfor
unumba.parfors.parfor_lowering
T aParforLower
unumba.core.compiler_machinery
T aFunctionPass
aLoweringPass
aAnalysisPass
register_pass
register_pass
unumba.core.annotations
T atype_annotations
unumba.core.ir_utils
T araise_on_unsupported_feature
warn_deprecated
check_and_legalize_ir
guard
dead_code_elimination
simplify_CFG
get_definition
build_definitions
compute_cfg_from_blocks
is_operator_or_getitem
replace_vars
T apostproc
llvmlite
T abinding
binding
L atypemap
return_type
calltypes
typing_errors
T nta__prepare__
aBaseTypeInference
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
