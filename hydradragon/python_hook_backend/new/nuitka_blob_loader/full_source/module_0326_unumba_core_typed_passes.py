# Reconstructed from integrated Nuitka blob
# Module: unumba.core.typed_passes

a__qualname__
uBaseTypeInference.__init__
run_pass
uBaseTypeInference.run_pass
a__orig_bases__
aNopythonTypeInference
T tFT amutates_CFG
analysis_only
nopython_type_inference
a_name
aPartialTypeInference
partial_type_inference
aAnnotateTypes
T Fpaannotate_types
uAnnotateTypes.__init__
get_analysis_usage
uAnnotateTypes.get_analysis_usage
uAnnotateTypes.run_pass
aNopythonRewrites
nopython_rewrites
uNopythonRewrites.__init__
uNopythonRewrites.run_pass
pre_parfor_pass
uPreParforPass.__init__
uPreParforPass.run_pass
parfor_pass
uParforPass.__init__
uParforPass.run_pass
parfor_fusion_pass
uParforFusionPass.__init__
uParforFusionPass.run_pass
parfor_prelowering_pass
uParforPreLoweringPass.__init__
uParforPreLoweringPass.run_pass
aDumpParforDiagnostics
T Ftadump_parfor_diagnostics
uDumpParforDiagnostics.__init__
uDumpParforDiagnostics.run_pass
aABC
aBaseNativeLowering
uBaseNativeLowering.__init__
property
abstractmethod
uBaseNativeLowering.lowering_class
uBaseNativeLowering.run_pass
aNativeLowering
native_lowering
uNativeLowering.lowering_class
aNativeParforLowering
native_parfor_lowering
uNativeParforLowering.lowering_class
aNoPythonSupportedFeatureValidation
nopython_supported_feature_validation
uNoPythonSupportedFeatureValidation.__init__
uNoPythonSupportedFeatureValidation.run_pass
ir_legalization
uIRLegalization.__init__
uIRLegalization.run_pass
aNoPythonBackend
nopython_backend
uNoPythonBackend.__init__
uNoPythonBackend.run_pass
aInlineOverloads
inline_overloads
uInlineOverloads.__init__
uInlineOverloads.run_pass
uInlineOverloads._get_attr_info
uInlineOverloads._get_callable_info
uInlineOverloads._do_work_expr
uInlineOverloads._run_inliner
uInlineOverloads._add_method_self_arg
aDeadCodeElimination
uDeadCodeElimination.__init__
uDeadCodeElimination.run_pass
aPreLowerStripPhis
strip_phis
uPreLowerStripPhis.__init__
uPreLowerStripPhis.run_pass
uPreLowerStripPhis._strip_phi_nodes
uPreLowerStripPhis._simplify_conditionally_defined_variable
unumba\core\typed_passes.py
u<module numba.core.typed_passes>
T a__class__
T aself
T aself
state
expr
func_def
T aself
state
work_list
block
wiaexpr
inline_worker
select_template
inlinee_info
templates
sig
arg_typs
is_method
inlinee
template
inlinee_type
impl
T
self
state
expr
recv_type
matched
template
templates
sig
arg_typs
is_method
T
self
state
expr
get_func_type
to_inline
func_ty
sig
templates
arg_typs
is_method
T aself
state
inline_type
sig
template
arg_typs
expr
wiaimpl
block
work_list
is_method
inline_worker
do_inline
a_inline_info
caller_inline_info
iinfo
freevars
w_anew_blocks
blk
T aself
func_ir
any_block
scope
defs
unver_or_undef
legalize_all_versioned_names
suspects
wkavar
delete_set
replace_map
versioned
ver_var
a_label
blk
assign
T aself
func_ir
exporters
phis
label
block
assign
phi
ib
iv
newblocks
newblk
target
rhs
assignments
last_assignment
T astate
msg
wealoop_lift
msg_rewrite
T aself
aAU
T astate
expr
func_ty
T avar
versioned
vs
defs
unver_or_undef
wkT adefs
wkaunver_or_undef
Tareturn_type
interp
targetctx
retstmts
caststmts
argvars
bid
blk
inst
var
cast
msg
self
T aself
state
func_ir
fout
T aself
state
codegen
library
targetctx
interp
typemap
restype
calltypes
flags
metadata
pre_stats
msg
fndesc
lower
wtaenv
call_helper
a_LowerResult
cfunc
post_stats
T aself
state
typemap
return_type
calltypes
errs
legalize_return_type
T aself
state
T aself
state
aInlineWorker
callee_ir_validator
inline_worker
modified
work_list
label
block
wiainstr
expr
workfn
cfg
dead
T aself
state
lowered
signature
compile_result
T aself
state
msg
pp
T aself
state
parfor_pass
T aself
state
parfor_pass
has_parfor
blk
stmnt
url
msg
T aself
state
post_proc
gentype
state_vars
state_types
T aself
state
preparfor_pass
T atemplates
args
impl
template
inline_type
T atypingctx
targetctx
interp
args
return_type
locals
raise_errors
warnings
infer
callstack_ctx
index
name
ty
wkwvaerrs
typemap
restype
calltypes
T aunver
defn
.numba.core.typeinfer
F
context
var
type
locked
define_loc
aNOTSET
literal_value
types
a_undef_var
can_convert
aTypingError
uNo conversion from %s to %s for '%s', defined at %s
T aloc
unify_pairs
uCannot unify %s and %s for '%s', defined at %s
uInvalid reassignment of a type-variable detected, type variables are locked according to the user provided function signature or from an ir.Const node. This is a bug! Type={}. {}
aCompilerError
uNo conversion from %s to %s for '%s'
add_type
u%s := %s
u<undecided>
uUndecided type {}
l l
constraints
append
loc
typeinfer
warnings
catch_warnings
filename
line
T afilename
lineno
a__enter__
a__exit__
aForceLiteralArg
errors
a_logger
debug
T ucaptured error
T aexc_info
T aloc
highlighting
utils
chain_exception
T nnnadst
src
new_error_context
T utyping of assignment at {loc}
copy_type
refine_map
T aunless_locked
loc
T utyping of argument at {loc}
typevars
defined
getone
aOmitted
resolve_value_type_prefer_literal
value
is_precise
unon-precise type {}
target
items
T utyping of tuple at {loc}
name
get
itertools
product
aUniTuple
T adtype
count
aTuple
self
vals
u<genexpr>
uBuildTupleConstraint.__call__.<locals>.<genexpr>
container_type
T utyping of {container_type} at {loc}
T acontainer_type
loc
undefined
unify_types
aList
aLiteral
T ainitial_value
aLiteralList
special_value
value_indexes
T utyping of dict at {loc}
utoo many values to unpack (expected 2)
aDictType
aStringLiteral
unliteral
check
uBuildMapConstraint.__call__.<locals>.check
aLiteralStrKeyDict
vt0
aConversion
unsafe
count
iterator
T utyping of exhaust iter at {loc}
aOptional
aBaseTuple
uwrong tuple length for

u:
uexpected
u, got
aNumbaValueError
aIterableType
iterator_type
yield_type
ufailed to unpack {}
pair
T utyping of pair-first at {loc}
aPair
first_type
T utyping of pair-second at {loc}
second_type
index
aIntrinsicCallConstraint
operator
getitem
fallback
T utyping of static-get-item at {loc}
resolve_static_getitem
T avalue
index
return_type
get_call_signature
dtype
T utyping of typed-get-item at {loc}
aSignature
signature
q u*args in function call should be a tuple, got %s
:nq nufold_arg_vars.<locals>.<genexpr>
aArray
func
args
kws
vararg
T utyping of call at {loc}
T uresolving caller type: {func}
T afunc
fnty
T uresolving callee type: {fnty}
T afnty
resolve
fold_arg_vars
chain
values
aTypeRef
instance_type
resolve_call
aBoundFunction
this
fold_arguments
requested_args
func_ir
get_definition
ir
aArg
requested
add
unsatisfied
T uCannot request literal type.
sig
sorted
u%s=%s
uInvalid use of {0} with parameters ({1})
u,
explain_function_type
w
recvr
uCannot refine type {} to {}
copy
T athis
propagate_refined_type
replace
T areturn_type
a_add_refine_map
aUndefined
a_is_array_not_precise
T adtype
uno type refinement implemented for function {} updating to {}
T utyping of intrinsic-call at {loc}
aOPERATORS_TO_BUILTINS
resolve_value_type
attr
inst
T utyping of get attribute at {loc}
resolve_getattr
aUntypedAttributeError
refine
uresolving type of attribute "{attr}" of "{value}"
T avalue
attr
T utyping of setitem at {loc}
resolve_setitem
uCannot resolve setitem: %s[%s] = %s
a_refine_target_type
uSetItemConstraint.__call__.<locals>.<genexpr>
index_var
T utyping of staticsetitem at {loc}
resolve_static_setitem
uCannot resolve setitem: %s[%r] = %s
uStaticSetItemConstraint.__call__.<locals>.<genexpr>
T utyping of delitem at {loc}
resolve_delitem
uCannot resolve delitem: %s[%s]
uDelItemConstraint.__call__.<locals>.<genexpr>
T utyping of set attribute {attr!r} at {loc}
T aattr
loc
resolve_setattr
uCannot resolve setattr: (%s).%s = %s
uSetAttrConstraint.__call__.<locals>.<genexpr>
T Oprint
aTypeVar
aTypeVarMap
a__getitem__
uCannot redefine typevar %s
a__setitem__
disp
py_func
a__name__
a_temporary_dispatcher_map
a_temporary_dispatcher_map_ref_count
register_dispatcher
aOrderedDict
blocks
keys
generator_info
func_id
set_context
aConstraintNetwork
arg_names
assumed_immutables
calls
aUniqueDict
calltypes
config
aDEBUG
aDEBUG_TYPEINFER
aTypeInferDebug
aNullDebug
a_skip_recursion
aTypeInferer
clone
uarg.%s
terminator
aReturn
rets
a_mangle_arg_name
seed_type
lock_type
D aloc
na_get_return_vars
typ
body
constrain_statement
T tT askip_recursion
build_constraint
propagate
T FT araise_errors
cloned
rettypes
a_unify_return_types
get_state_token
newtoken
oldtoken
propagate_started
propagate_finished
reduce
or_
union
lock
T aloc
literal_value
find_offender
uTypeInferer.unify.<locals>.find_offender
diagnose_imprecision
uTypeInferer.unify.<locals>.diagnose_imprecision
check_var
uTypeInferer.unify.<locals>.check_var
get_return_type
get_function_types
typdict
get_generator_type
check_undef_var_in_calls
uTypeInferer.unify.<locals>.check_undef_var_in_calls
unify_finished
find_variable_assignment
T EAttributeError
EKeyError
startswith
T w$T aexhaustive
offender
op
build_list

For Numba to be able to compile a list, the list must have a known and
precise type that can be inferred from the other variables. Whilst sometimes
the type of empty lists can be inferred, this is not always the case, see this
documentation for help:
https://numba.readthedocs.io/en/stable/user/troubleshoot.html#my-code-has-an-untyped-list-problem
call
aGlobal
list
raise_errors
uunknown operation
unknown_loc
uType of variable '%s' cannot be determined, operation: %s, location: %s
unknown
aUndefinedFunctionType
get_precise
D aexhaustive
tu (temporary variable)
uCannot infer the type of variable '%s'%s, have imprecise type: %s. %s
isalpha
uTypeInferer.unify.<locals>.<genexpr>
D astart
l uundefined variable used in call argument #
arg_types
state_vars
uCannot type generator: state variable types cannot be found
get_yield_points
uCannot type generator: yield type cannot be found
uCannot type generator: it does not yield any value
aGenerator
D ahas_finalizer
tuCannot type generator: cannot unify yielded types %s
a_termcolor
errmsg
T uYield of: IR '%s', type '%s', location: %s
yp_highlights
strformat
explain_ty
aNoneType
T anone
uCan't unify yield type from the following types: %s

aFunctionType
check_type
uTypeInferer._unify_return_types.<locals>.check_type
problem_str
uCan't unify return type from the following types: %s
none
lst
find_insts
aVar
returns
uReturn of: IR name '%s', type '%s', location: %s
interped
T ureturn value is undefined
aAssign
typeof_assign
aSetItem
typeof_setitem
aStaticSetItem
typeof_static_setitem
aDelItem
typeof_delitem
aSetAttr
typeof_setattr
aPrint
typeof_print
aStoreMap
typeof_storemap
aJump
aBranch
aDel
aDynamicRaise
aDynamicTryRaise
aStaticRaise
aStaticTryRaise
aPopBlock
typeinfer_extensions
uUnsupported constraint encountered: %s
aUnsupportedError
aSetItemConstraint
T atarget
index
value
loc
dct
key
aStaticSetItemConstraint
T atarget
index
index_var
value
loc
aDelItemConstraint
T atarget
index
loc
aSetAttrConstraint
T atarget
attr
value
loc
aPrintConstraint
T aargs
vararg
loc
aConst
typeof_const
aPropagate
T adst
src
loc
aFreeVar
typeof_global
typeof_arg
aExpr
typeof_expr
aYield
typeof_yield
uUnsupported assignment encountered: %s %s
aArgConstraint
use_literal_type
maybe_literal
T avalue
range
slice
len
uModified builtin '%s'
get_call_type
aRecursiveCall
dispatcher_type
dispatcher
fold_argument_types
callstack
match
resolve_function_type
overloads
fndesc
qualifying_prefix
modname
qualname
add_overloads
uid
func_qualname
unique_id
return_types_from_partial
T ucannot type infer runaway recursion
typing
T apysig
add_return_type
func_name
aDispatcher
unumba.misc
T aspecial
special
a__globals__
a__all__
a__builtins__
code
co_freevars
uNameError: name '%s' is not defined
patch_message
uUntyped global name '%s':
u %s

'%s' looks like a Numba internal function, has it been imported (i.e. 'from numba import %s')?
is_compiling
findfirst
ucall to %s: unsupported recursion
T areadonly
aBaseAnonymousTuple
mark_array_ro
uTypeInferer.typeof_global.<locals>.mark_array_ro
sentry_modified_builtin
newtup
from_types
typeof_call
T agetiter
iternext
typeof_intrinsic_call
exhaust_iter
aExhaustIterConstraint
T acount
iterator
loc
pair_first
aPairFirstConstraint
T apair
loc
pair_second
aPairSecondConstraint
binop
fn
lhs
rhs
inplace_binop
unary
static_getitem
aStaticGetItemConstraint
T avalue
index
index_var
loc
typed_getitem
aTypedGetItemConstraint
T avalue
dtype
index
loc
getattr
aGetAttrConstraint
T aattr
value
loc
inst
build_tuple
aBuildTupleConstraint
T aitems
loc
aBuildListConstraint
build_set
aBuildSetConstraint
build_map
aBuildMapConstraint
T aitems
special_value
value_indexes
loc
cast
phi
incoming_values
aUNDEFINED
make_function
aMakeFunctionLiteral
undef
uUnsupported op-code encountered: %s
aCallConstraint
T akws
vararg
loc
print
T u---- type variables ----
pprint
T u-----------------------------------propagate------------------------------------
a_dump_state
T u---------------------------------Variable types---------------------------------
T u----------------------------------Return type-----------------------------------
T u-----------------------------------Call types-----------------------------------
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
logging
contextlib
T apprint
collections
T aOrderedDict
defaultdict
defaultdict
unumba.core
T atypes
utils
typing
ir
config
unumba.core.typing.templates
T aSignature
unumba.core.errors
T aTypingError
aUntypedAttributeError
new_error_context
termcolor
aUnsupportedError
aForceLiteralArg
aCompilerError
aNumbaValueError
termcolor
unumba.core.funcdesc
T aqualifying_prefix
unumba.core.typeconv
T aConversion
getLogger
T unumba.core.typeinfer
