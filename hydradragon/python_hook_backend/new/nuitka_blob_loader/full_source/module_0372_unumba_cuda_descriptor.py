# Reconstructed from integrated Nuitka blob
# Module: unumba.cuda.descriptor

a__qualname__
a__orig_bases__
aCUDATarget
uCUDATarget.__init__
property
typing_context
uCUDATarget.typing_context
target_context
uCUDATarget.target_context
T acuda
cuda_target
unumba\cuda\descriptor.py
u<module numba.cuda.descriptor>
T a__class__
T aself
name
a__class__
T aself

.numba.cuda.device_init
Y
z
driver
is_available
aCudaSupportError
nvvm
runtime
is_supported_version
initialization_error
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
sys
unumba.cuda
T acg
l
cg
stubs
T athreadIdx
blockIdx
blockDim
gridDim
laneid
warpsize
syncwarp
shared
local
const
atomic
shfl_sync_intrinsic
vote_sync_intrinsic
match_any_sync
match_all_sync
threadfence_block
threadfence_system
threadfence
selp
popc
brev
clz
ffs
fma
cbrt
activemask
lanemask_lt
nanosleep
fp16
a_vector_type_stubs
l athreadIdx
blockIdx
blockDim
gridDim
laneid
warpsize
syncwarp
shared
local
const
atomic
shfl_sync_intrinsic
vote_sync_intrinsic
match_any_sync
match_all_sync
threadfence_block
threadfence_system
threadfence
selp
popc
brev
clz
ffs
fma
cbrt
activemask
lanemask_lt
nanosleep
fp16
a_vector_type_stubs
intrinsics
T agrid
gridsize
syncthreads
syncthreads_and
syncthreads_count
syncthreads_or
grid
gridsize
syncthreads
syncthreads_and
syncthreads_count
syncthreads_or
ucudadrv.error
T aCudaSupportError
unumba.cuda.cudadrv.driver
T	aBaseCUDAMemoryManager
aHostOnlyCUDAMemoryManager
aGetIpcHandleMixin
aMemoryPointer
aMappedMemory
aPinnedMemory
aMemoryInfo
aIpcHandle
set_memory_manager
aBaseCUDAMemoryManager
aHostOnlyCUDAMemoryManager
aGetIpcHandleMixin
aMemoryPointer
aMappedMemory
aPinnedMemory
aMemoryInfo
aIpcHandle
set_memory_manager
unumba.cuda.cudadrv.runtime
T aruntime
cudadrv
T anvvm
T ainitialize
initialize
errors
T aKernelRuntimeError
aKernelRuntimeError
decorators
T ajit
declare_device
jit
declare_device
api
T w*T a_auto_device
a_auto_device
args
T aIn
aOut
aInOut
aIn
aOut
aInOut
intrinsic_wrapper
T aall_sync
any_sync
eq_sync
ballot_sync
shfl_sync
shfl_up_sync
shfl_down_sync
shfl_xor_sync
all_sync
any_sync
eq_sync
ballot_sync
shfl_sync
shfl_up_sync
shfl_down_sync
shfl_xor_sync
kernels
T areduction
reduction
aReduce
reduce
vector_type_stub
setattr
modules
unumba.cuda.device_init
a__name__
aliases
alias
cuda_error
initialize_all
unumba\cuda\device_init.py
u<module numba.cuda.device_init>
T adriver_is_available

.numba.cuda.deviceufunc
#
l ufailed to broadcast {0} and {1}
utoo many values to unpack (expected 2)
shape1
T l ashape2
a_broadcast_axis
u<genexpr>
u_pairwise_broadcast.<locals>.<genexpr>
l
:l nnD astart
l a_pairwise_broadcast
result
ufailed to broadcast argument #{0}
wiatypemap
args
argtypes
scalarpos
signature
arrays
self
is_device_array
as_device_array
np
number
append
asarray
dtype
match_map
matches
uNo matching version.  GPU ufunc requires array arguments to have the exact types.  This behaves like regular ufunc with casting='no'.
uFailed to resolve ufunc due to ambiguous signature. Too many untyped scalars. Use numpy dtype object to type tag.
uUFuncMechanism._resolve_signature.<locals>.<genexpr>
array
T adtype
shape
a_multi_broadcast
broadcast_device
arys
ary
ndim
strides
lib
stride_tricks
as_strided
T ashape
strides
force_array_layout
a_fill_arrays
a_fill_argtypes
a_resolve_signature
a_get_actual_args
a_broadcast
ubroadcasting on device is not supported
pop
stream
aDEFAULT_STREAM
T aout
nawarnings
warn
uunrecognized keywords: %s
u,
get_arguments
get_function
attempt_ravel
uUFuncMechanism.call.<locals>.attempt_ravel
cr
devarys
to_device
T astream
out
allocate_device_array
launch
any_device
reshape
copy_to_host
aSUPPORT_DEVICE_SLICING
ravel
to_host
types
aEnumMember
ucaching is not supported
nopython
unopython kwarg for cuda target is redundant
aRuntimeWarning
uUnrecognized options. cuda vectorize target does not support option: '%s'
py_func
parse_identity
identity
aOrderedDict
kernelmap
sigutils
normalize_signature
pyfunc
a__name__
a_get_kernel_source
a_kernel_template
a_compile_core
a_get_globals
void
:nnnasig
return_type
devfnsig
funcname
kernelsource
corefn
glbl
u<string>
exec
u__vectorized_%s
a_compile_kernel
to_dtype
uDeviceVectorize.add.<locals>.<genexpr>
ua%d
name
argitems
format
u%s[__tid__]
uDeviceVectorize._get_kernel_source.<locals>.<genexpr>
uwritable_args are not supported
T anopython
tunopython flag must be True
keys
uThe following target options are not supported: {0}
parse_signature
inputsig
outputsig
none
uguvectorized functions cannot return values: signature

u specifies
u return type
expand_gufunc_template
indims
outdims
valid_return_type
src
glbls
u__gufunc_{name}
T aname
a_determine_gufunc_outer_types
T asig
argtys
dims
aArray
copy
T andim
ugufunc signature mismatch: ndim>0 for scalar
wAT adtype
ndim
layout
uarg{0}
umin({0})
u{0}.shape[0]
utoo many values to unpack (expected 3)
a_gen_src_for_indexing
T aname
args
checkedarg
argitems
u{aref}[{sliced}]
a_gen_src_index
T aaref
sliced
w,a__tid__
w:u__tid__:(__tid__ + 1)
sin
sout
nin
nout
uinvalid number of input argument
uarg #%d: insufficient inner dimension
symbolmap
uarg #%d: shape[%d] mismatch argument
outer_shapes
inner_shapes
oshape
oshapes
reduce
operator
mul
argmax
pinned
uarg #%d: outer dimension mismatch
aGUFuncSchedule
parent
ishapes
loopdims
loopn
output_shapes
pprint
T aishapes
oshapes
loopdims
loopn
pinned
pformat
engine
l     amax_blocksize
a_call_steps
a_schedule
inputs
outputs
utoo many values to unpack (expected 4)
adjust_input_types
prepare_outputs
prepare_inputs
launch_kernel
post_process_outputs
schedule
a_search_matching_signature
uoutput shape mismatch
uGeneralizedUFunc._schedule.<locals>.<genexpr>
idtypes
uno matching signature
can_cast
uGeneralizedUFunc._search_matching_signature.<locals>.<genexpr>
size
a_broadcast_scalar_input
odim
newparams
a_broadcast_array
newretvals
a_broadcast_add_axis
ucannot add new axis
get
T aout
pos_argn
uGUFuncCallSteps.__init__.<locals>.pos_argn
uThis gufunc accepts
u (when providing input only) or
u (when providing input and output). Got
w.ucannot specify argument 'out' as both positional and keyword
all_user_outputs_are_host
a_copy_result_to_host
normalize_arg
uGUFuncCallSteps.__init__.<locals>.normalize_arg
u positional argument
wsaastype
ucompatible signature is possible by casting but {0} does not support .astype()
ensure_device
uGUFuncCallSteps.prepare_inputs.<locals>.ensure_device
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
abc
T aABCMeta
abstractmethod
aABCMeta
abstractmethod
collections
T aOrderedDict
numpy
unumba.np.ufunc.ufuncbuilder
T a_BaseUFuncBuilder
parse_identity
a_BaseUFuncBuilder
unumba.core
T atypes
sigutils
unumba.core.typing
T asignature
unumba.np.ufunc.sigparse
T aparse_signature
T Oobject
a__prepare__
aUFuncMechanism
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
