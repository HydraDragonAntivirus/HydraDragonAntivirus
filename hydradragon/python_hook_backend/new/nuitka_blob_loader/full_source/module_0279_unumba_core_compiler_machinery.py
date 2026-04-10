# Reconstructed from integrated Nuitka blob
# Module: unumba.core.compiler_machinery

a__qualname__
uSimpleTimer.__enter__
uSimpleTimer.__exit__
a__orig_bases__
metaclass
T aCompilerPass
T
a__init__
uCompilerPass.__init__
classmethod
uCompilerPass.name
property
uCompilerPass.pass_id
setter
uCompilerPass.analysis
uCompilerPass.run_initialization
uCompilerPass.run_pass
uCompilerPass.run_finalizer
uCompilerPass.get_analysis_usage
get_analysis
uCompilerPass.get_analysis
aSSACompliantMixin
aAnalysisPass
aLoweringPass
uAnalysisUsage.__init__
uAnalysisUsage.get_required_set
get_preserved_set
uAnalysisUsage.get_preserved_set
add_required
uAnalysisUsage.add_required
add_preserved
uAnalysisUsage.add_preserved
a__str__
uAnalysisUsage.__str__
T apass_timings
uinit run finalize
aPassManager
uPassManager.__init__
uPassManager._validate_pass
T u
add_pass
uPassManager.add_pass
add_pass_after
uPassManager.add_pass_after
uPassManager._debug_init
finalize
uPassManager.finalize
uPassManager.finalized
uPassManager._patch_error
uPassManager._runPass
uPassManager.run
uPassManager.dependency_analysis
T apass_info
upass_inst mutates_CFG analysis_only
aPassRegistry
dict
register
uPassRegistry.register
uPassRegistry.is_registered
uPassRegistry.get
a_does_pass_name_alias
uPassRegistry._does_pass_name_alias
uPassRegistry.find_by_name
uPassRegistry.dump
register_pass
unumba\core\compiler_machinery.py
u<module numba.core.compiler_machinery>
T a__class__
T aself
T aself
exc
T aself
args
kwargs
T aself
pipeline_name
T aself
parse
ret
T aself
check
wkwvT aself
desc
exc
newmsg
T aself
index
pss
internal_state
mutated
check
debug_print
qualname
ev_details
errctx
init_time
pass_time
finalize_time
pt
T aself
pass_cls
msg
T aself
pss
description
func_desc_tuple
T aself
pass_cls
location
idx
wxw_T aself
pss
T aself
val
T afunc
compiler_state
mangled
msg
pss
T apss
T apass_name
print_condition
printable_condition
fid
args
internal_state
self
T ainternal_state
self
T aargs
kwargs
T aself
deps
pss
w_wxaau
requires_map
wkwvaresolve_requires
dep_chain
T aself
wkwvT aself
class_name
wkwvT aself
clazz
T aself
pass_name
T aself
aAU
T apass_class
self
mutates_CFG
analysis_only
T aanalysis_only
mutates_CFG
self
T acls
T aconf_item
print_passes
splitted
self
T aself
mutates_CFG
analysis_only
make_festive
T akey
rmap
walk
ret
wkT
self
state
a_EarlyPipelineCompletion
idx
pss
pass_desc
pass_inst
weamsg
patched_exception
T alkey
rmap
dep_set
wxawalk
T awalk
.numba.core.config
#
] are
match
u(\d+)\.(\d+)
uCompute capability must be specified as a string of "major.minor" where major and minor are decimals
groups
l
l utoo many values to unpack (expected 1)
max
l a__class__
a__new__
a_raw_value
w'u
u_OptLevel(
w)T w0w1w2w3amax
uEnvironment variable `NUMBA_OPT` is set to an unsupported value '
u', supported values are 0, 1, 2, 3, and 'max'
a_OptLevel
reset
old_environ
update
T tT aforce
a_config_fname
a_HAVE_YAML
warnings
warn
T uA Numba config file is found but YAML parsing capabilities appear to be missing. To use this feature please install `pyyaml`. e.g. `conda install pyyaml`.
rt
a__enter__
a__exit__
yaml
safe_load
T nnnay_conf
items
utoo many values to unpack (expected 2)
new_environ
aNUMBA_
upper
environ
startswith
T aNUMBA_
process_environ
validate
aCUDA_USE_NVIDIA_BINDING
cuda
uCUDA Python bindings requested (the environment variable NUMBA_CUDA_USE_NVIDIA_BINDING is set), but they are not importable:
msg
w.aCUDA_PER_THREAD_DEFAULT_STREAM
T uPTDS support is handled by CUDA Python when using the NVIDIA binding. Please set the environment variable CUDA_PYTHON_CUDA_PER_THREAD_DEFAULT_STREAM to 1 instead.
a_readenv
u_EnvReloader.process_environ.<locals>._readenv
optional_str
u_EnvReloader.process_environ.<locals>.optional_str
T aNUMBA_USE_LEGACY_TYPE_SYSTEM
Oint
l T aNUMBA_DEVELOPER_MODE
Oint
l
T aNUMBA_DISABLE_PERFORMANCE_WARNINGS
Oint
l
aNUMBA_FULL_TRACEBACKS
T aNUMBA_SHOW_HELP
Oint
l
T aNUMBA_COLOR_SCHEME
Ostr
no_color
T aNUMBA_BOUNDSCHECK
Oint
nT aNUMBA_ALWAYS_WARN_UNINIT_VAR
Oint
l
T aNUMBA_CUDA_LOW_OCCUPANCY_WARNINGS
Oint
l T aNUMBA_CUDA_USE_NVIDIA_BINDING
Oint
l
T aNUMBA_DEBUG
Oint
l
T aNUMBA_DEBUG_PRINT_AFTER
Ostr
none
T aNUMBA_DEBUG_PRINT_BEFORE
Ostr
none
T aNUMBA_DEBUG_PRINT_WRAP
Ostr
none
T aNUMBA_HIGHLIGHT_DUMPS
Oint
l
T aNUMBA_DEBUG_JIT
Oint
l
T aNUMBA_DEBUG_FRONTEND
Oint
l
T aNUMBA_DEBUG_NRT
Oint
l
T aNUMBA_NRT_STATS
Oint
l
T aNUMBA_FUNCTION_CACHE_SIZE
Oint
l  T aNUMBA_PARFOR_MAX_TUPLE_SIZE
Oint
ldaNUMBA_DEBUG_CACHE
T aNUMBA_CACHE_DIR
Ostr

T aNUMBA_CACHE_LOCATOR_CLASSES
Ostr

T aNUMBA_TRACE
Oint
l
T aNUMBA_CHROME_TRACE
Ostr

T aNUMBA_DEBUG_TYPEINFER
Oint
l
T aNUMBA_DISABLE_TYPEINFER_FAIL_CACHE
Oint
l
aNUMBA_CPU_NAME
aNUMBA_CPU_FEATURES
lower
generic
aNUMBA_OPT
a_process_opt_level
T l aNUMBA_DUMP_BYTECODE
aNUMBA_DUMP_CFG
aNUMBA_DUMP_IR
aNUMBA_DUMP_SSA
T aNUMBA_DEBUG_ARRAY_OPT
Oint
l
T aNUMBA_DEBUG_ARRAY_OPT_RUNTIME
Oint
l
T aNUMBA_DEBUG_ARRAY_OPT_STATS
Oint
l
T aNUMBA_PARALLEL_DIAGNOSTICS
Oint
l
T aNUMBA_DEBUG_INLINE_CLOSURE
Oint
l
aNUMBA_DUMP_LLVM
aNUMBA_DUMP_FUNC_OPT
aNUMBA_DUMP_OPTIMIZED
T aNUMBA_LOOP_VECTORIZE
Oint
l T aNUMBA_SLP_VECTORIZE
Oint
l
aNUMBA_DUMP_ASSEMBLY
T aNUMBA_DUMP_ANNOTATION
Oint
l
T aNUMBA_DIFF_IR
Oint
l
fmt_html_path
u_EnvReloader.process_environ.<locals>.fmt_html_path
aNUMBA_DUMP_HTML
avx_default
u_EnvReloader.process_environ.<locals>.avx_default
aNUMBA_ENABLE_AVX
aNUMBA_DISABLE_INTEL_SVML
aIS_32BITS
T aNUMBA_DISABLE_JIT
Oint
l
aNUMBA_THREADING_LAYER_PRIORITY
u<lambda>
u_EnvReloader.process_environ.<locals>.<lambda>
tbb
omp
workqueue
T aNUMBA_THREADING_LAYER
Ostr
default
T aNUMBA_CUDA_WARN_ON_IMPLICIT_COPY
Oint
l aNUMBA_FORCE_CUDA_CC
a_parse_cc
aNUMBA_CUDA_DEFAULT_PTX_CC
T l l
aNUMBA_DISABLE_CUDA
aMACHINE_BITS
l T aNUMBA_ENABLE_CUDASIM
Oint
l
T aNUMBA_CUDA_LOG_LEVEL
Ostr

T aNUMBA_CUDA_LOG_API_ARGS
Oint
l
T aNUMBA_CUDA_MAX_PENDING_DEALLOCS_COUNT
Oint
l
T aNUMBA_CUDA_MAX_PENDING_DEALLOCS_RATIO
Ofloat
f       ?T aNUMBA_CUDA_ARRAY_INTERFACE_SYNC
Oint
l T aNUMBA_CUDA_DRIVER
Ostr

T aNUMBA_CUDA_LOG_SIZE
Oint
l  T aNUMBA_CUDA_VERBOSE_JIT_LOG
Oint
l T aNUMBA_CUDA_PER_THREAD_DEFAULT_STREAM
Oint
l
T aNUMBA_CUDA_ENABLE_MINOR_VERSION_COMPATIBILITY
Oint
l
aIS_WIN32
get
T aCUDA_PATH
join
include
cuda_include_not_found
T w\ausr
local
cuda
include
aNUMBA_CUDA_INCLUDE_PATH
num_threads_default
u_EnvReloader.process_environ.<locals>.num_threads_default
aNUMBA_NUM_THREADS
unumba.np.ufunc
T aparallel
parallel
a_is_initialized
uCannot set NUMBA_NUM_THREADS to a different value once the threads have been launched (currently have %s, trying to set %s)
T aNUMBA_ENABLE_SYS_MONITORING
Oint
l
aVS_PROFILER
aNUMBA_ENABLE_PROFILING
aNUMBA_DEBUGINFO
T aNUMBA_CUDA_DEBUGINFO
Oint
l
T aNUMBA_EXTEND_VARIABLE_LIFETIMES
Oint
l
which_gdb
u_EnvReloader.process_environ.<locals>.which_gdb
aNUMBA_GDB_BINARY
gdb
T aNUMBA_CUDA_MEMORY_MANAGER
Ostr
default
T aNUMBA_LLVM_REFPRUNE_PASS
Oint
l aNUMBA_LLVM_REFPRUNE_FLAGS
all
T aNUMBA_USE_LLVMLITE_MEMORY_MANAGER
Oint
nT aNUMBA_LLVM_PASS_TIMINGS
Oint
l
T aNUMBA_JIT_COVERAGE
Oint
l
self
aUSE_LEGACY_TYPE_SYSTEM
aDEVELOPER_MODE
aDISABLE_PERFORMANCE_WARNINGS
aFULL_TRACEBACKS
aSHOW_HELP
aCOLOR_SCHEME
aBOUNDSCHECK
aALWAYS_WARN_UNINIT_VAR
aCUDA_LOW_OCCUPANCY_WARNINGS
aDEBUG
aDEBUG_PRINT_AFTER
aDEBUG_PRINT_BEFORE
aDEBUG_PRINT_WRAP
aHIGHLIGHT_DUMPS
aDEBUG_JIT
aDEBUG_FRONTEND
aDEBUG_NRT
aNRT_STATS
aFUNCTION_CACHE_SIZE
aPARFOR_MAX_TUPLE_SIZE
aDEBUG_CACHE
aCACHE_DIR
aCACHE_LOCATOR_CLASSES
aTRACE
aCHROME_TRACE
aDEBUG_TYPEINFER
aDISABLE_TYPEINFER_FAIL_CACHE
aCPU_NAME
aCPU_FEATURES
aOPT
aDUMP_BYTECODE
aDUMP_CFG
aDUMP_IR
aDUMP_SSA
aDEBUG_ARRAY_OPT
aDEBUG_ARRAY_OPT_RUNTIME
aDEBUG_ARRAY_OPT_STATS
aPARALLEL_DIAGNOSTICS
aDEBUG_INLINE_CLOSURE
aDUMP_LLVM
aDUMP_FUNC_OPT
aDUMP_OPTIMIZED
aLOOP_VECTORIZE
aSLP_VECTORIZE
aDUMP_ASSEMBLY
aANNOTATE
aDIFF_IR
aHTML
aENABLE_AVX
aDISABLE_INTEL_SVML
aDISABLE_JIT
aTHREADING_LAYER_PRIORITY
aTHREADING_LAYER
aCUDA_WARN_ON_IMPLICIT_COPY
aFORCE_CUDA_CC
aCUDA_DEFAULT_PTX_CC
aDISABLE_CUDA
aENABLE_CUDASIM
aCUDA_LOG_LEVEL
aCUDA_LOG_API_ARGS
aCUDA_DEALLOCS_COUNT
aCUDA_DEALLOCS_RATIO
aCUDA_ARRAY_INTERFACE_SYNC
aCUDA_DRIVER
aCUDA_LOG_SIZE
aCUDA_VERBOSE_JIT_LOG
aCUDA_ENABLE_MINOR_VERSION_COMPATIBILITY
cuda_path
default_cuda_include_path
aCUDA_INCLUDE_PATH
aNUMBA_DEFAULT_NUM_THREADS
a_NUMBA_NUM_THREADS
aENABLE_SYS_MONITORING
aRUNNING_UNDER_PROFILER
aENABLE_PROFILING
aDEBUGINFO_DEFAULT
aCUDA_DEBUGINFO_DEFAULT
aEXTEND_VARIABLE_LIFETIMES
aGDB_BINARY
aCUDA_MEMORY_MANAGER
aLLVM_REFPRUNE_PASS
aLLVM_REFPRUNE_FLAGS
aUSE_LLVMLITE_MEMORY_MANAGER
aLLVM_PASS_TIMINGS
aJIT_COVERAGE
copy
isupper
callable
uEnvironment variable '
u' is defined but its associated value '
u' could not be parsed.
The parse failed with exception:
traceback
format_exc
aRuntimeWarning
a_os_supports_avx
all
get_host_cpu_name
S ucorei7-avx
ivybridge
sandybridge
ucore-avx-i
S anocona
split
sched_getaffinity
T l
cpu_count
shutil
which
a_env_reloader
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
platform
sys
os
ullvmlite.binding
binding
aIS_OSX
l@T l l aPYVERSION
u.numba_config.yaml
T Oint
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
