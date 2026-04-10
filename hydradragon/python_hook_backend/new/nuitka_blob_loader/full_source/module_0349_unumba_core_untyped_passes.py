# Reconstructed from integrated Nuitka blob
# Module: unumba.core.untyped_passes

a__qualname__
extract_bytecode
a_name
uExtractByteCode.__init__
run_pass
uExtractByteCode.run_pass
a__orig_bases__
aTranslateByteCode
translate_bytecode
uTranslateByteCode.__init__
uTranslateByteCode.run_pass
aFixupArgs
fixup_args
uFixupArgs.__init__
uFixupArgs.run_pass
aIRProcessing
ir_processing
uIRProcessing.__init__
uIRProcessing.run_pass
uRewriteSemanticConstants.__init__
uRewriteSemanticConstants.run_pass
uDeadBranchPrune.__init__
uDeadBranchPrune.run_pass
get_analysis_usage
uDeadBranchPrune.get_analysis_usage
aInlineClosureLikes
inline_closure_likes
uInlineClosureLikes.__init__
uInlineClosureLikes.run_pass
generic_rewrites
uGenericRewrites.__init__
uGenericRewrites.run_pass
aWithLifting
uWithLifting.__init__
uWithLifting.run_pass
aInlineInlinables
inline_inlinables
uInlineInlinables.__init__
uInlineInlinables.run_pass
uInlineInlinables._do_work
aPreserveIR
T Fpapreserve_ir
uPreserveIR.__init__
uPreserveIR.run_pass
aFindLiterallyCalls
T Ftafind_literally
uFindLiterallyCalls.__init__
uFindLiterallyCalls.run_pass
aCanonicalizeLoopExit
canonicalize_loop_exit
uCanonicalizeLoopExit.__init__
uCanonicalizeLoopExit.run_pass
uCanonicalizeLoopExit._split_exit_block
aCanonicalizeLoopEntry
canonicalize_loop_entry
range
enumerate
zip
uCanonicalizeLoopEntry.__init__
uCanonicalizeLoopEntry.run_pass
uCanonicalizeLoopEntry._split_entry_block
aPrintIRCFG
print_ir_cfg
uPrintIRCFG.__init__
uPrintIRCFG.run_pass
aMakeFunctionToJitFunction
make_function_op_code_to_jit_function
uMakeFunctionToJitFunction.__init__
uMakeFunctionToJitFunction.run_pass
transform_literal_unroll_const_list_to_tuple
aBaseTuple
aLiteralList
uTransformLiteralUnrollConstListToTuple.__init__
uTransformLiteralUnrollConstListToTuple.run_pass
mixed_container_unroller
uMixedContainerUnroller.__init__
uMixedContainerUnroller.analyse_tuple
uMixedContainerUnroller.add_offset_to_labels_w_ignore
uMixedContainerUnroller.inject_loop_body
uMixedContainerUnroller.gen_switch
uMixedContainerUnroller.apply_transform
uMixedContainerUnroller.unroll_loop
uMixedContainerUnroller.run_pass
iter_loop_canonicalisation
uIterLoopCanonicalization.__init__
uIterLoopCanonicalization.assess_loop
uIterLoopCanonicalization.transform
uIterLoopCanonicalization.run_pass
uPropagateLiterals.__init__
uPropagateLiterals.get_analysis_usage
uPropagateLiterals.run_pass
aLiteralPropagationSubPipelinePass
aLiteralPropagation
uLiteralPropagationSubPipelinePass.__init__
uLiteralPropagationSubPipelinePass.run_pass
uLiteralPropagationSubPipelinePass.get_analysis_usage
aLiteralUnroll
uLiteralUnroll.__init__
uLiteralUnroll.run_pass
aSimplifyCFG
simplify_cfg
uSimplifyCFG.__init__
uSimplifyCFG.run_pass
uReconstructSSA.__init__
uReconstructSSA.run_pass
uReconstructSSA._patch_locals
aRewriteDynamicRaises
uRewrite dynamic raises
uRewriteDynamicRaises.__init__
uRewriteDynamicRaises.run_pass
unumba\core\untyped_passes.py
u<module numba.core.untyped_passes>
T a__class__
T aself
T aself
state
work_list
block
wiaexpr
inline_worker
run_frontend
aInlineOptions
to_inline
val
topt
inline_type
inline_opt
do_inline
pyfunc
py_func_ir
w_anew_blocks
blk
T
self
state
locals_dict
first_blk
w_ascope
parent
redefs
typ
derived
T aself
fir
cfg
loop
entry_label
header_block
deps
expr
entry_block
startpt
list_of_insts
assign
rhs
defn
splitpt
new_block
new_label
T aself
fir
cfg
exit_label
curblock
newlabel
newblock
T
self
blocks
offset
ignore
new_blocks
wlwbaterm
new_true
new_false
T aself
tup
wdwiaty
T aself
state
func_ir
cfg
loops
unroll_info
get_call_args
find_unroll_loops
ensure_no_nested_unroll
collect_literal_unroll_info
literal_unroll_loops
literal_unroll_info
info
post_proc
T aself
loop
func_ir
partial_typemap
iternexts
iternext
phi
phi_val_defn
call
func_var
func
ty
T aliteral_unroll_loops
literal_unroll_info
loop
literal_unroll_call
arg
typemap
resolved_arg
ty
tuple_getitem
lbli
blk
stmt
dfn
args
target_ty
ui
state
func_ir
self
unroll_info
T afunc_ir
self
state
unroll_info
T aunroll_loops
test_loop
ref_loop
msg
loc
func_ir
T afunc_ir
T astate
msg
wealoop_lift
msg_rewrite
T aloops
unroll_loops
header_lbl
loop
iternexts
iternext
phi
range_call
range_arg
len_call
len_arg
literal_unroll_call
literal_func
call_func
call_func_value
func_ir
get_call_args
T afunc_ir
get_call_args
T aself
data
index
elif_tplt
wbakeys
elifs
wiasrc
wstr
wlabfunc
branches
lbl
blk
stmt
T aself
aAU
T ainit_arg
want
some_call
the_global
func_ir
T waT#aself
switch_ir
loop_ir
caller_max_label
dont_replace
switch_data
sentinel_exits
sentinel_blocks
lbl
blk
wiastmt
ignore_set
local_lbl
branch_ty
loop_blocks
max_label
loop_start_lbl
new_body
scope
new_const_name
new_const_var
new_const_val
const_assign
new_assign
orig
new_typed_getitem
var_table
drop_keys
wkwvanew_var_dict
name
var
remaining_keys
T aself
state
fir
cfg
status
loop
entry_label
vlt
T aself
state
fir
cfg
status
loop
exit_label
vlt
T aself
state
semantic_const_analysis
msg
T aself
state
func_id
abc
T aself
state
T aself
state
msg
T aself
state
func_ir
post_proc
name
T aself
state
typed_pass
aInlineClosureCallPass
inline_pass
post_proc
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
cfg
dead
post_proc
T	aself
state
func_ir
cfg
loops
mutated
header
loop
stat
T
self
state
found
func_ir
blk
asgn
value
aPassManager
aPartialTypeInference
pm
T	aself
state
found
func_ir
blk
asgn
aPassManager
aPartialTypeInference
pm
T aself
state
njit
func_ir
mutated
idx
blk
stmt
node
getdef
kw_default
ok
pyfunc
func
new_node
post_proc
T aself
state
mutated
func_ir
stat
T aself
state
fir
T aself
state
func_ir
typemap
flags
accepted_functions
changed
block
assign
value
target
fn
arg
iv
msg
wvalit
rhs
new_assign
T aself
state
post_proc
name
T aself
state
func_ir
changed
block
raise_
call_inst
exc_type
exc_args
exc_arg
const
loc
cls
dyn_raise
T aself
state
blks
new_blks
mutated
T aself
state
mutated
func_ir
label
blk
calls
call
glbl
msg
unroll_var
to_unroll
wiaitem
val
to_unroll_lhs
wbaasgn
tup
ty
extra
loc
T aself
state
func_id
abc
interp
func_ir
T aself
state
main
withs
compile_ir
a_EarlyPipelineCompletion
cres
T!aself
loop
func_ir
cfg
get_range
iternext
aLOC
scope
get_range_var
get_range_global
assgn
loop_entry
entry_block
iterarg
idx
stmt
call_get_range_var
make_call
assgn_call
glbls
inline_closure_call
kill
induction_vars
header_block
ind
wxatmp
induction_var_names
succ
lbl
check_blocks
lookup
post_proc
T&aself
state
loop_info
func_ir
getitem_target
target_ty
tuple_getitem
lbl
blk
stmt
dfn
args
msg
aLOC
switch_data
index
branches
item
old
new
this_loop
this_loop_body
loop_blocks
new_ir
usedefs
idx
keep
dont_replace
unrolled_body
blks
the_scope
orig_lbl
replace
delete
unroll
header_block
unroll_lbl
wk.numba.core.utils
.
a__traceback__
traceback
clear_frames
with_traceback
T nu<lambda>
usafe_relpath.<locals>.<lambda>
relpath
T astart
splitdrive
l
a_shutting_down
get
T a_shutting_down
a__class__
a__init_subclass__
stack_name
a_registered
a_tls
stack_

a_stack
append
pop
q aself
push
state
enter
uThreadLocalStack.enter
aOPTIONS
copy
a_values
uInvalid flag: %s
set
a_check_attr
startswith
T w_aConfigOptions
a__setattr__
uFlags(%s)
u,
items
utoo many values to unpack (expected 2)
u%s=%s
u<genexpr>
uConfigOptions.__repr__.<locals>.<genexpr>
sorted
unumba.core.target_extension
T atarget_registry
target_registry
generic
metadata
target
aDEFAULT_TARGET
inherits_from
usable
key
uorder_by_target_specificity.<locals>.key
T akey
uFunction resolution cannot find any matches for function '
u' for the current target: '
u'.
unumba.core.errors
T aUnsupportedError
aUnsupportedError
a__mro__
index
l a_data
uMutableSortedSet.__iter__.<locals>.<genexpr>
a__contains__
add
discard
update
a_index
uSortedMap.__iter__.<locals>.<genexpr>
a_dct
uMutableSortedMap.__iter__.<locals>.<genexpr>
ukey already in dictionary: %r
aUniqueDict
a__setitem__
wraps
inner
urunonce.<locals>.inner
a_ran
fn
a_result
sublist_iterator
ustream_list.<locals>.sublist_iterator
lst
start
stream_list
func
loop
np
array
records
min
best
a__name__
size
format_time
u%20s: %10d loops, best of %d: %s per loop
L wsams
us
ns
ps
:nq nabase
l  u%.1f%s
unit
timeit
aTimer
repeat
result
number
l
timer
l aBenchmarkResult
max
math
ceil
log10
aDEVELOPER_MODE
a__cause__
pysignature
parameters
values
max_nargs
default
inspect
a_empty
min_nargs
unified_function_type
T aNumbaExperimentalFeatureWarning
aNumbaExperimentalFeatureWarning
aSequence
types
aDispatcher
aFunctionType
warnings
warn
T uFirst-class function type feature is experimental
T acategory
T nnaget_nargs_range
dispatcher
py_func
mnargs
mxargs
dispatchers
get_function_type
nargs
wtaUndefinedFunctionType
undefined_function
function
a__init__
a_RedirectSubpackage__old_module_states
a_RedirectSubpackage__new_module
import_module
aModuleType
modules
w.T a__
endswith
a__builtins__
a_RedirectSubpackage
threading
aRLock
a_lock
a__enter__
a__exit__
a__get__
T nnnaprint
uLLVM DUMP %s
center
T lPw-aconfig
aHIGHLIGHT_DUMPS
pygments
T ahighlight
highlight
upygments.lexers
T aLlvmLexer
aLlvmLexer
upygments.formatters
T aTerminal256Formatter
aTerminal256Formatter
unumba.misc.dump_style
T aby_colorscheme
by_colorscheme
a__repr__
T astyle
uPlease install pygments to see highlighted dumps
T u================================================================================
pformat
args
kwargs
lazy_func
a_lazy_pformat
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
atexit
builtins
functools
os
operator
sys
weakref
contextlib
json
a_tp
pprint
T apformat
numpy
T asignature
signature
T aSignature
aSignature
pySignature
T aParameter
aParameter
pyParameter
unumba.core.config
T aPYVERSION
aMACHINE_BITS
aDEVELOPER_MODE
aPYVERSION
aMACHINE_BITS
unumba.core
T aconfig
T atypes
ucollections.abc
T aMapping
aSequence
aMutableSet
aMutableMapping
aMapping
aMutableSet
aMutableMapping
erase_traceback
T w.asafe_relpath
w+w-asub
w*amul
u//
floordiv
w/atruediv
w%amod
u**
pow
w&aand_
w|aor_
w^axor
u<<
lshift
u>>
rshift
u==
eq
u!=
ne
w<alt
u<=
le
w>agt
u>=
ge
is
is_
uis not
is_not
in
contains
w@amatmul
aBINOPS_TO_OPERATORS
u+=
iadd
u-=
isub
u*=
imul
u//=
ifloordiv
u/=
itruediv
u%=
imod
u**=
ipow
u&=
iand
u|=
ior
u^=
ixor
u<<=
ilshift
u>>=
irshift
u@=
imatmul
aINPLACE_BINOPS_TO_OPERATORS
aALL_BINOPS_TO_OPERATORS
pos
neg
w~ainvert
not
not_
is_true
truth
aUNARY_BUITINS_TO_OPERATORS
aOPERATORS_TO_BUILTINS
a_at_shutdown
globals
shutting_down
finalize
register
