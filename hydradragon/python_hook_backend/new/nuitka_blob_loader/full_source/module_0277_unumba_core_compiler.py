# Reconstructed from integrated Nuitka blob
# Module: unumba.core.compiler

a__qualname__
bool
uEnable loop-lifting
T atype
default
doc
enable_looplift
uEnable pyobject mode (in general)
uEnable pyobject mode inside lifted loops
enable_pyobject_looplift
uEnable SSA
uForce pyobject mode inside the whole function
uRelease GIL inside the native function
release_gil
aTODO
no_compile
uForce inlining of the function. Overrides _dbg_optnone.
forceinline
no_cpython_wrapper
no_cfunc_wrapper
uEnable automatic parallel optimization, can be fine-tuned by
taking a dictionary of sub-options instead of a boolean, see parfor.py for
detail
str
python
aFastMathOptions
noalias
aInlineOptions
T anever
inline
uExtend variable lifetime for debugging. This automatically turns on with debug=True.
dbg_extend_lifetimes
uDisable optimization for debug. Equivalent to adding optnone attribute in the LLVM Function.
dbg_optnone
uMake debug emissions directives-only. Used when generating lineinfo.
dbg_directives_only
a__orig_bases__
aDEFAULT_FLAGS
L atyping_context
target_context
entry_point
typing_error
type_annotation
signature
objectmode
lifted
fndesc
library
call_helper
environment
metadata
reload_init
referenced_envs
a_CompileResult
a_reduce
uCompileResult._reduce
uCompileResult._find_referenced_environments
classmethod
a_rebuild
uCompileResult._rebuild
property
uCompileResult.codegen
T u
uCompileResult.dump
a_LowerResult
L afndesc
call_helper
cfunc
env
compile_result
T Fparun_frontend
T Oobject
a__init__
u_CompileStatus.__init__
a__repr__
u_CompileStatus.__repr__
T EException
u_EarlyPipelineCompletion.__init__
T Odict
a__getattr__
uStateDict.__getattr__
a__setattr__
uStateDict.__setattr__
aCompilerBase
uCompilerBase.__init__
uCompilerBase.compile_extra
T T
nuCompilerBase.compile_ir
uCompilerBase.define_pipelines
uCompilerBase._compile_core
uCompilerBase._compile_bytecode
uCompilerBase._compile_ir
uCompiler.define_pipelines
staticmethod
T anopython
uDefaultPassBuilder.define_nopython_pipeline
T anopython_lowering
uDefaultPassBuilder.define_nopython_lowering_pipeline
T aparfor_gufunc_nopython_lowering
define_parfor_gufunc_nopython_lowering_pipeline
uDefaultPassBuilder.define_parfor_gufunc_nopython_lowering_pipeline
T atyped
uDefaultPassBuilder.define_typed_pipeline
T aparfor_gufunc_typed
define_parfor_gufunc_pipeline
uDefaultPassBuilder.define_parfor_gufunc_pipeline
T auntyped
uDefaultPassBuilder.define_untyped_pipeline
T aobject
uDefaultPassBuilder.define_objectmode_pipeline
compile_internal
unumba\core\compiler.py
u<module numba.core.compiler>
T a__class__
T aself
attr
T aself
typingctx
targetctx
library
args
return_type
flags
locals
T aself
can_fallback
T aself
result
T aself
vals
wkT aself
attr
value
T aself
T aself
pms
pm
pipeline_name
func_name
is_final_pipeline
res
weT aself
mod
referenced_envs
gv
gvn
env
T atargetctx
flags
subtargetoptions
error_model
T acls
target_context
libdata
fndesc
env
signature
objectmode
lifted
typeann
reload_init
referenced_envs
fn
library
cfunc
cr
T aself
libdata
typeann
fndesc
referenced_envs
T aself
func
T
typingctx
targetctx
func
args
return_type
flags
locals
library
pipeline_class
pipeline
T	atypingctx
targetctx
library
func
args
return_type
flags
locals
pipeline
T aself
func_ir
lifted
lifted_from
T atypingctx
targetctx
func_ir
args
return_type
flags
locals
lifted
lifted_from
is_lifted_loop
library
pipeline_class
norw_flags
compile_local
norw_cres
rw_cres
cres
pipeline
T athe_ir
the_flags
pipeline
pipeline_class
typingctx
targetctx
library
args
return_type
locals
lifted
lifted_from
T	aargs
library
lifted
lifted_from
locals
pipeline_class
return_type
targetctx
typingctx
T aentries
T astate
name
pm
T astate
name
dpb
pm
untyped_passes
typed_passes
lowering_passes
T aself
tab
T
func
inline_closures
emit_dels
func_id
interp
abc
func_ir
aInlineClosureCallPass
inline_pass
post_proc
T aentries
keys
fieldset
badnames
missing
wkaerr
.numba.core.compiler_lock
A
threading
aRLock
a_lock
ev
start_event
T unumba:compiler_lock
acquire
release
end_event
a_is_owned
callable
wraps
a_acquire_compile_lock
u_CompilerLock.__call__.<locals>._acquire_compile_lock
self
a__enter__
a__exit__
func
T nnnT l
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
l
functools
unumba.core.event
core
event
T Oobject
a__prepare__
a_CompilerLock
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
