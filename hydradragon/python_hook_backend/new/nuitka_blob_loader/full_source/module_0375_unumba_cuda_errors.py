# Reconstructed from integrated Nuitka blob
# Module: unumba.cuda.errors

a__qualname__
T nnuKernelRuntimeError.__init__
a__orig_bases__
aCudaLoweringError
uhttps://numba.readthedocs.io/en/stable/cuda/kernels.html#kernel-invocation
a_launch_help_url

Kernel launch configuration was not specified. Use the syntax:
kernel_function[blockspergrid, threadsperblock](arg0, arg1, ..., argn)
See {} for help.
normalize_kernel_dimensions
unumba\cuda\errors.py
u<module numba.cuda.errors>
T a__class__
T aself
msg
tid
ctaid
wta__class__
T adim
name
wvT agriddim
blockdim
check_dim

.numba.cuda.extending
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
unumba.core.extending
T aintrinsic
l
intrinsic
a_intrinsic
T acuda
T atarget
unumba\cuda\extending.py
u<module numba.cuda.extending>

.numba.cuda.initialize
unumba.cuda.models
l
unumba.cuda.decorators
T ajit
jit
unumba.cuda.dispatcher
T aCUDADispatcher
aCUDADispatcher
unumba.core.target_extension
T atarget_registry
dispatcher_registry
jit_registry
target_registry
dispatcher_registry
jit_registry
cuda
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
initialize_all
unumba\cuda\initialize.py
u<module numba.cuda.initialize>
T anumba
jit
aCUDADispatcher
target_registry
dispatcher_registry
jit_registry
cuda_target

.numba.cuda.intrinsic_wrapper
#
numba
cuda
vote_sync_intrinsic
l
l l l ashfl_sync_intrinsic
l a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
decorators
T ajit
jit
T tT adevice
all_sync
any_sync
eq_sync
ballot_sync
shfl_sync
shfl_up_sync
shfl_down_sync
shfl_xor_sync
unumba\cuda\intrinsic_wrapper.py
u<module numba.cuda.intrinsic_wrapper>
T amask
predicate
T amask
value
delta
T amask
value
src_lane
T amask
value
lane_mask

.numba.cuda.intrinsics
m
t
literal_value
l atypes
int64
T l l aUniTuple
aNumbaValueError
T uargument can only be 1, 2, 3
signature
int32
aIntegerLiteral
aRequireLiteralValue
a_type_grid_function
codegen
ugrid.<locals>.codegen
return_type
nvvmutils
get_global_id
D adim
l acount
T adim
cgutils
pack_array
a_nthreads_for_dim
ugridsize.<locals>._nthreads_for_dim
ugridsize.<locals>.codegen
ir
aIntType
T l@acall_sreg
untid.

unctaid.
mul
sext
wxwyl l wzu_warpsize.<locals>.codegen
warpsize
get
ucuda_warpsize.<locals>.get
a_warpsize
none
usyncthreads.<locals>.codegen
module
aFunctionType
aVoidType
get_or_insert_function
ullvm.nvvm.barrier0
call
get_dummy_value
aInteger
i4
u_syncthreads_predicate.<locals>.codegen
T l afname
a_syncthreads_predicate
ullvm.nvvm.barrier0.popc
ullvm.nvvm.barrier0.and
ullvm.nvvm.barrier0.or
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
llvmlite
T air
l
numba
T acuda
types
cuda
unumba.core
T acgutils
unumba.core.errors
T aRequireLiteralValue
aNumbaValueError
unumba.core.typing
T asignature
unumba.core.extending
T aoverload_attribute
overload_attribute
unumba.cuda
T anvvmutils
unumba.cuda.extending
T aintrinsic
intrinsic
grid
gridsize
aModule
D atarget
cuda
cuda_warpsize
syncthreads
syncthreads_count
syncthreads_and
syncthreads_or
unumba\cuda\intrinsics.py
u<module numba.cuda.intrinsics>
T abuilder
dim
i64
ntid
nctaid
T atypingctx
predicate
fname
sig
codegen
T andim
val
restype
T atypingctx
sig
codegen
T acontext
builder
sig
args
fnty
sync
fname
T afname
T acontext
builder
sig
args
T acontext
builder
sig
args
restype
ids
T	acontext
builder
sig
args
restype
nx
any
nz
a_nthreads_for_dim
T a_nthreads_for_dim
T acontext
builder
sig
args
fname
lmod
fnty
sync
T amod
get
T amod
T atypingctx
ndim
sig
codegen
T atypingctx
ndim
sig
a_nthreads_for_dim
codegen
T atypingctx
predicate
fname
.numba.cuda.kernels
h
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_numba
u\not_existing
ucuda\kernels
T aNUITKA_PACKAGE_numba_cuda
u\not_existing
kernels
T aNUITKA_PACKAGE_numba_cuda_kernels
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
unumba\cuda\kernels\__init__.py
u<module numba.cuda.kernels>

.numba.cuda.kernels.reduction
f
numba
T acuda
l
cuda
jit
T tT adevice
a_WARPSIZE
l a_NUMWARPS
inner_warp_reduction
u_gpu_reduce_factory.<locals>.inner_warp_reduction
device_reduce_full_block
u_gpu_reduce_factory.<locals>.device_reduce_full_block
device_reduce_partial_block
u_gpu_reduce_factory.<locals>.device_reduce_partial_block
gpu_reduce_block_strided
u_gpu_reduce_factory.<locals>.gpu_reduce_block_strided
threadIdx
wx:nnnasyncwarp
l awidth
laneid
sm_this
reduce_op
blockIdx
blockDim
gridDim
size
tmp
syncthreads
T l
pT l l
result
shared
array
inner_sm_size
nbtype
T adtype
max_blocksize
partials
a_functor
a_cache
a_gpu_reduce_factory
from_dtype
kernel
ndim
uonly support 1D array
arr
dtype
type
a_compile
min
device_array
T ashape
dtype
:nl nacopy_to_device
T astream
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
unumba.np.numpy_support
T afrom_dtype
l l T Oobject
a__prepare__
aReduce
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
