# Reconstructed from integrated Nuitka blob
# Module: unumba.cuda.cudadrv.driver

a__qualname__
a__orig_bases__
uCudaAPIError.__init__
a__str__
uCudaAPIError.__str__

CUDA driver library cannot be found.
If you are sure that a CUDA driver is installed,
try setting environment variable NUMBA_CUDA_DRIVER
with the file path of the CUDA driver shared library.

Possible CUDA driver libraries are found but error occurred during load:
%s
a_build_reverse_error_map
T Oobject
aDriver
uDriver.__new__
uDriver.__init__
uDriver.ensure_initialized
uDriver._initialize_extras
property
is_available
uDriver.is_available
a__getattr__
uDriver.__getattr__
uDriver._ctypes_wrap_fn
uDriver._cuda_python_wrap_fn
uDriver._find_api
uDriver._detect_fork
uDriver._check_ctypes_error
uDriver._check_cuda_python_error
uDriver.get_device
uDriver.get_device_count
list_devices
uDriver.list_devices
uDriver.reset
uDriver.pop_active_context
uDriver.get_active_context
uDriver.get_version
local
u_ActiveContext.__enter__
u_ActiveContext.__exit__
a__bool__
u_ActiveContext.__bool__
a__nonzero__
a_build_reverse_device_attrs
classmethod
uDevice.from_identity
uDevice.__init__
uDevice.get_device_identity
a__repr__
uDevice.__repr__
uDevice.__getattr__
a__hash__
uDevice.__hash__
uDevice.__eq__
a__ne__
uDevice.__ne__
get_primary_context
uDevice.get_primary_context
uDevice.release_primary_context
uDevice.reset
supports_float16
uDevice.supports_float16
metaclass
aBaseCUDAMemoryManager
uBaseCUDAMemoryManager.__init__
uBaseCUDAMemoryManager.memalloc
uBaseCUDAMemoryManager.memhostalloc
uBaseCUDAMemoryManager.mempin
uBaseCUDAMemoryManager.initialize
uBaseCUDAMemoryManager.get_ipc_handle
uBaseCUDAMemoryManager.get_memory_info
uBaseCUDAMemoryManager.reset
uBaseCUDAMemoryManager.defer_cleanup
uBaseCUDAMemoryManager.interface_version
aHostOnlyCUDAMemoryManager
uHostOnlyCUDAMemoryManager.__init__
uHostOnlyCUDAMemoryManager._attempt_allocation
T FppuHostOnlyCUDAMemoryManager.memhostalloc
T FuHostOnlyCUDAMemoryManager.mempin
uHostOnlyCUDAMemoryManager.memallocmanaged
uHostOnlyCUDAMemoryManager.reset
contextmanager
aGetIpcHandleMixin
uGetIpcHandleMixin.get_ipc_handle
uNumbaCUDAMemoryManager.initialize
uNumbaCUDAMemoryManager.memalloc
uNumbaCUDAMemoryManager.get_memory_info
uNumbaCUDAMemoryManager.interface_version
T Oint
u_SizeNotSet.__new__
w?u_SizeNotSet.__str__
u_PendingDeallocs.__init__
u_PendingDeallocs._max_pending_bytes
u_PendingDeallocs.add_item
u_PendingDeallocs.clear
u_PendingDeallocs.is_disabled
a__len__
u_PendingDeallocs.__len__
T aMemoryInfo
ufree,total
uContext.__init__
uContext.reset
uContext.get_memory_info
get_active_blocks_per_multiprocessor
uContext.get_active_blocks_per_multiprocessor
uContext._cuda_python_active_blocks_per_multiprocessor
uContext._ctypes_active_blocks_per_multiprocessor
get_max_potential_block_size
uContext.get_max_potential_block_size
uContext._ctypes_max_potential_block_size
uContext._cuda_python_max_potential_block_size
uContext.prepare_for_use
push
uContext.push
pop
uContext.pop
uContext.memalloc
T tuContext.memallocmanaged
uContext.memhostalloc
uContext.mempin
uContext.get_ipc_handle
uContext.open_ipc_handle
enable_peer_access
uContext.enable_peer_access
uContext.can_access_peer
create_module_ptx
uContext.create_module_ptx
uContext.create_module_image
uContext.unload_module
get_default_stream
uContext.get_default_stream
get_legacy_default_stream
uContext.get_legacy_default_stream
get_per_thread_default_stream
uContext.get_per_thread_default_stream
create_stream
uContext.create_stream
create_external_stream
uContext.create_external_stream
create_event
uContext.create_event
uContext.synchronize
uContext.__repr__
uContext.__eq__
uContext.__ne__
u_CudaIpcImpl.__init__
u_CudaIpcImpl.open
u_CudaIpcImpl.close
u_StagedIpcImpl.__init__
u_StagedIpcImpl.open
u_StagedIpcImpl.close
T nl
uIpcHandle.__init__
uIpcHandle._sentry_source_info
uIpcHandle.can_access_peer
uIpcHandle.open_staged
uIpcHandle.open_direct
uIpcHandle.open
open_array
uIpcHandle.open_array
uIpcHandle.close
a__reduce__
uIpcHandle.__reduce__
a_rebuild
uIpcHandle._rebuild
T nnuMemoryPointer.__init__
uMemoryPointer.owner
uMemoryPointer.own
uMemoryPointer.free
memset
uMemoryPointer.memset
uMemoryPointer.view
uMemoryPointer.device_ctypes_pointer
uMemoryPointer.device_pointer_value
uAutoFreePointer.__init__
uMappedMemory.__init__
uMappedMemory.own
aMemAlloc
uPinnedMemory.__init__
uPinnedMemory.own
uManagedMemory.__init__
uManagedMemory.own
uOwnedPointer.__init__
uOwnedPointer.__getattr__
uStream.__init__
a__int__
uStream.__int__
uStream.__repr__
uStream.synchronize
uStream.add_callback
staticmethod
uStream._stream_callback
async_done
uStream.async_done
uEvent.__init__
query
uEvent.query
record
uEvent.record
uEvent.synchronize
wait
uEvent.wait
elapsed_time
uEvent.elapsed_time
T aModule
T
aModule
uModule.__init__
unload
uModule.unload
get_function
uModule.get_function
get_global_symbol
uModule.get_global_symbol
uCtypesModule.get_function
uCtypesModule.get_global_symbol
uCudaPythonModule.get_function
uCudaPythonModule.get_global_symbol
L aregs
shared
local
const
maxthreads
T aFunction
T
aFunction
T l ppagriddim
blockdim
stream
sharedmem
uFunction.__init__
uFunction.__repr__
uFunction.device
cache_config
uFunction.cache_config
uFunction.read_func_attr
uFunction.read_func_attr_all
uCtypesFunction.cache_config
uCtypesFunction.read_func_attr
uCtypesFunction.read_func_attr_all
uCudaPythonFunction.cache_config
uCudaPythonFunction.read_func_attr
uCudaPythonFunction.read_func_attr_all
launch_kernel
jitty
woaCU_JIT_INPUT_OBJECT
aCU_JIT_INPUT_LIBRARY
aCU_JIT_INPUT_CUBIN
aCU_JIT_INPUT_FATBINARY
T aLinker
T
aLinker
T l
Fnanew
uLinker.new
uLinker.__init__
uLinker.info_log
uLinker.error_log
uLinker.add_ptx
uLinker.add_cu
uLinker.add_file
uLinker.add_cu_file
add_file_guess_ext
uLinker.add_file_guess_ext
uLinker.complete
uMinor version compatibility requires ptxcompiler and cubinlinker packages to be available
T nFnuMVCLinker.__init__
uMVCLinker.info_log
uMVCLinker.error_log
T u<cudapy-ptx>
uMVCLinker.add_ptx
uMVCLinker.add_file
uMVCLinker.complete
uCtypesLinker.__init__
uCtypesLinker.info_log
uCtypesLinker.error_log
uCtypesLinker.add_ptx
uCtypesLinker.add_file
uCtypesLinker.complete
uCudaPythonLinker.__init__
uCudaPythonLinker.info_log
uCudaPythonLinker.error_log
uCudaPythonLinker.add_ptx
uCudaPythonLinker.add_file
uCudaPythonLinker.complete
get_devptr_for_active_ctx
device_memory_size
memory_size_from_info
host_memory_size
device_memory_depends
host_to_device
device_to_host
device_memset
unumba\cuda\cudadrv\driver.py
T a.0
weu<module numba.cuda.cudadrv.driver>
T a__class__
T aself
T aself
is_top
hctx
devnum
hdevice
T aself
other
T aself
exc_type
exc_val
exc_tb
T aself
attr
code
value
result
T aself
fname
T aself
args
kwargs
a__class__
T aself
args
kwargs
T aself
device
handle
T aself
max_registers
lineinfo
cc
logsz
linkerinfo
linkererrors
options
cc_val
raw_keys
raw_values
option_keys
option_vals
handle
a__class__
T aself
code
msg
a__class__
T aself
max_registers
lineinfo
cc
logsz
linkerinfo
linkererrors
jit_option
options
cc_val
cc_enum
raw_keys
raw_values
a__class__
T aself
devnum
result
got_devnum
msg
bufsz
buf
name
uuid
uuid_vals
wbab2
b4
b6
fmt
T aself
msg
weT aself
context
handle
finalizer
T aself
module
handle
name
T aself
base
handle
size
source_info
offset
T aself
max_registers
lineinfo
cc
T
self
max_registers
lineinfo
cc
aCubinLinker
err
arch
ptx_compile_opts
arg
a__class__
T aself
context
pointer
size
owner
finalizer
devptr
a__class__
T aself
context
pointer
size
owner
finalizer
T aself
context
handle
info_log
finalizer
T aself
memptr
view
mem
deref
T aself
context
handle
finalizer
external
T aself
parent
T aself
capacity
T aself
parent
source_info
T acls
obj
T acls
args
kwargs
a__class__
T aself
preprocessed_handle
args
T aself
default_streams
ptr
T amemory_manager
ptr
alloc_key
size
allocations
deallocations
core
T aself
allocator
weaoom_code
T aprefix
map
name
T aprefix
map
name
code
T aself
fname
retcode
errname
msg
T aself
fname
returned
retcode
retval
msg
T aself
func
blocksize
memsize
flags
retval
args
T
self
func
b2d_func
memsize
blocksizelimit
flags
gridsize
blocksize
b2d_cb
args
T
self
fname
libfn
proto
restype
argtypes
verbose_cuda_api_call
safe_cuda_api_call
wrapper
safe_call
T aself
func
blocksize
memsize
flags
ps
T
self
func
b2d_func
memsize
blocksizelimit
flags
b2d_cb
ptr
driver_b2d_cb
args
T aself
fname
libfn
verbose_cuda_api_call
safe_cuda_api_call
wrapper
safe_call
T aself
msg
T amgr_module
T adeallocs
handle
core
T aself
fname
variants
variant
absent_function
T amemory_manager
ptr
alloc_key
size
mapped
allocations
deallocations
core
T aself
set_proto
set_cuIpcOpenMemHandle
call_proto
call_cuIpcOpenMemHandle
safe_call
T aobj
dtype
T acontext
handle
dealloc
modules
key
core
T amemory_manager
ptr
alloc_key
mapped
allocations
core
T weT acls
handle_ary
size
source_info
offset
handle
T ahandle
status
data
stream
callback
arg
weT aobj
T aargs
kws
fname
T afname
T aself
callback
arg
data
ptr
stream_callback
T	aself
cu
name
ac
dev
cc
ptx
log
ptx_name
T aself
path
wfacu
T aself
path
kind
pathbuf
weamsg
T aself
path
kind
T
self
path
kind
aCubinLinkerError
err
wfadata
name
fn
weT aself
path
ext
kind
T aself
dtor
handle
size
T aself
ptx
name
ptxbuf
namebuf
weT aself
ptx
name
namebuf
input_ptx
weT aself
ptx
name
T aself
ptx
name
compile_ptx
aCubinLinkerError
err
compile_result
weT aflags
attach_global
ptr
size
T aattach_global
ptr
size
T ama_flags
flags
attach_global
size
T aattach_global
size
T apointer
size
flags
T aflags
pointer
size
T asize
flags
T aflags
size
T aptr
size
T asize
T aself
loop
future
resolver
callback
T aself
prefer_equal
prefer_cache
prefer_shared
flag
T aself
prefer_equal
prefer_cache
prefer_shared
attr
flag
T aself
prefer_equal
prefer_cache
prefer_shared
T astream
status
future
loop
resolver
T aloop
resolver
T aself
peer_device
can_access_peer
T aself
context
source_device
T aself
cubin_buf
size
weacubin_ptr
T aself
aCubinLinkerError
err
weT aallocations
alloc_key
deallocations
ptr
size
T aalloc_key
allocations
deallocations
ptr
size
T adeallocs
handle
T amapped
allocations
alloc_key
deallocations
ptr
size
T aalloc_key
allocations
deallocations
mapped
ptr
size
T ashutting_down
module_unload
dealloc
handle
T adealloc
handle
T amapped
allocations
alloc_key
ptr
T aalloc_key
allocations
mapped
ptr
T aself
timing
flags
handle
T aself
ptr
handle
T aself
image
module
key
T aself
ptx
image
T aself
flags
handle
T amem
T adevmem
devptr
wswnT adevmem
objs
depset
T adevmem
sz
wsweT adst
val
size
stream
varargs
fn
T adst
src
size
stream
varargs
fn
T aself
evtend
T aself
peer_context
flags
T aself
weadescription
T aevtstart
evtend
msec
T adlloader
candidates
dll
path
T aself
identity
devid
wdaerrmsg
T aself
func
blocksize
memsize
flags
args
T aself
handle
T aself
devnum
dev
T aself
count
T aptr
ptr_attrs
attr
ptrobj
devptr
T aself
name
handle
T aself
name
T aself
name
ptr
size
T aself
memory
T aself
memory
base
end
ipchandle
offset
source_info
T aself
func
b2d_func
memsize
blocksizelimit
flags
args
T aself
free
total
T aself
hctx
ctx
T aself
version
dv
major
minor
T aobj
wsweT aobj
readonly
forcewritable
T acufunc_handle
gx
gy
gz
bx
by
bz
sharedmem
hstream
args
cooperative
param_ptrs
params
params_for_launch
extra
T adlloader
candidates
path_not_exist
driver_load_error
path
dll
weaerrmsg
T acontext
image
T acontext
image
logsz
jitinfo
jiterrors
options
option_keys
option_vals
handle
weamsg
info_log
T acontext
image
logsz
jitinfo
jiterrors
jit_option
options
option_keys
option_vals
handle
weaerr_string
msg
info_log
T aenvpath
dlloader
dldir
dlnames
candidates
T alogger
lvl
handler
fmt
T aself
size
T aself
bytesize
T aself
size
allocator
ptr
alloc_key
finalizer
ctx
mem
T aself
bytesize
attach_global
T	aself
size
attach_global
allocator
ptr
alloc_key
finalizer
ctx
mem
T aself
size
mapped
portable
wc
T aself
bytesize
mapped
portable
wc
T aself
size
mapped
portable
wc
flags
allocator
pointer
alloc_key
finalizer
ctx
mem
T ashape
strides
itemsize
ndim
wsweT aself
owner
pointer
size
mapped
T aself
owner
pointer
size
mapped
alloc_key
flags
allocator
finalizer
ctx
mem
T aself
byte
count
stream
T adevice
T ahandle
T acls
max_registers
lineinfo
cc
T aself
context
fn
T aself
context
mem
T aself
context
cuda
srcdev
srcdev_id
impl
source_ptr
newmem
T aself
context
shape
dtype
strides
devicearray
dptr
T aself
context
T aself
handle
size
flags
dptr
T aself
popped
T aself
ac
popped
T aself
weT aself
attrid
retval
T aself
attrid
T aself
nregs
cmem
lmem
smem
maxtpb
T aself
attr
nregs
cmem
lmem
smem
maxtpb
T aself
stream
hstream
T aself
dev
T afuture
status
self
T aargs
retcode
libfn
self
fname
T afname
libfn
self
T aargs
libfn
self
fname
T amm_plugin
dummy
iv
err
T aself
module
key
T aargs
argstr
retcode
libfn
self
fname
T aargs
argstr
libfn
self
fname
T aself
start
stop
size
view
base
pointer
ctypes_ptr
T aself
stream
hstream
flags
.numba.cuda.cudadrv.drvapi
B
{
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
c_byte
l
c_char_p
c_float
c_int
c_size_t
c_uint
c_uint8
c_void_p
py_object
aCFUNCTYPE
aPOINTER
unumba.cuda.cudadrv
T a_extras
a_extras
cu_device
cu_device_attribute
cu_context
cu_module
cu_jit_option
cu_jit_input_type
cu_function
cu_device_ptr
cu_stream
cu_event
cu_link_state
cu_function_attribute
aCUDA_IPC_HANDLE_SIZE
cu_ipc_mem_handle
l acu_uuid
cu_stream_callback_pyobj
cu_occupancy_b2d_size
aCU_STREAM_DEFAULT
l aCU_STREAM_LEGACY
l aCU_STREAM_PER_THREAD
cuInit
cuDriverGetVersion
cuDeviceGetCount
cuDeviceGet
cuDeviceGetName
cuDeviceGetAttribute
cuDeviceComputeCapability
cuDevicePrimaryCtxGetState
cuDevicePrimaryCtxRelease
cuDevicePrimaryCtxReset
cuDevicePrimaryCtxRetain
cuDevicePrimaryCtxSetFlags
cuCtxCreate
cuCtxGetDevice
cuCtxGetCurrent
cuCtxPushCurrent
cuCtxPopCurrent
cuCtxDestroy
cuModuleLoadDataEx
cuModuleUnload
cuModuleGetFunction
cuModuleGetGlobal
cuFuncSetCacheConfig
cuMemAlloc
cuMemAllocManaged
cuMemsetD8
cuMemsetD8Async
cuMemcpyHtoD
cuMemcpyHtoDAsync
cuMemcpyDtoD
cuMemcpyDtoDAsync
cuMemcpyDtoH
cuMemcpyDtoHAsync
cuMemFree
cuStreamCreate
cuStreamDestroy
cuStreamSynchronize
cuStreamAddCallback
cuLaunchKernel
cuLaunchCooperativeKernel
cuMemHostAlloc
cuMemFreeHost
cuMemHostRegister
cuMemHostUnregister
cuMemHostGetDevicePointer
cuMemGetInfo
cuEventCreate
cuEventDestroy
cuEventElapsedTime
cuEventQuery
cuEventRecord
cuEventSynchronize
cuStreamWaitEvent
cuPointerGetAttribute
cuMemGetAddressRange
cuMemHostGetFlags
cuCtxSynchronize
cuLinkCreate
cuLinkAddData
cuLinkAddFile
cuLinkComplete
cuLinkDestroy
cuProfilerStart
cuProfilerStop
cuFuncGetAttribute
cuOccupancyMaxActiveBlocksPerMultiprocessor
cuOccupancyMaxActiveBlocksPerMultiprocessorWithFlags
cuOccupancyMaxPotentialBlockSize
cuOccupancyMaxPotentialBlockSizeWithFlags
cuIpcGetMemHandle
cuIpcOpenMemHandle
cuIpcCloseMemHandle
cuCtxEnablePeerAccess
cuDeviceCanAccessPeer
cuDeviceGetUuid
aAPI_PROTOTYPES
unumba\cuda\cudadrv\drvapi.py
u<module numba.cuda.cudadrv.drvapi>

.numba.cuda.cudadrv.dummyarray
start
stop
size
stride
single
indices
utoo many values to unpack (expected 3)
l
l a_compute_size
aDim
T astart
stop
size
stride
single
q :q nnuDim(start=%s, stop=%s, size=%s, stride=%s)
utoo many values to unpack (expected 2)
get_offset
u<genexpr>
ucompute_index.<locals>.<genexpr>
extent
self
iter_contiguous_extent
uElement.iter_contiguous_extent
offset
D asingle
Fadims
ndim
shape
strides
itemsize
reduce
operator
mul
a_compute_extent
a_compute_layout
flags
uArray.__init__.<locals>.<genexpr>
D aC_CONTIGUOUS
aF_CONTIGUOUS
tpD aC_CONTIGUOUS
aF_CONTIGUOUS
Fpasd
aC_CONTIGUOUS
aF_CONTIGUOUS
compute_index
max
aExtent
u<Array dims=%s itemsize=%s>
u%d extra indices given
item
:nnna__getitem__
aArray
reshape
aElement
is_c_contig
is_f_contig
:l nn:nq nais_contiguous
itertools
product
outerdims
innerdim
uArray.iter_contiguous_extent
order
wCuunknown keyword arguments %s
keys
aCFA
uorder not C|F|A
unknownidx
ucan only specify one unknown dimension
knownsize
ucannot infer valid shape for unknown dimension
newdims
wAwFureshape changes the size of the array
iter_strides_c_contig
iter_strides_f_contig
unreachable
np
empty
ctypeslib
c_intp
array
T adtype
attempt_nocopy_reshape
ureshape would require copy
from_desc
begin
newstrides
T ashape
strides
itemsize
T L
panewshape
append
ucannot select an axis to squeeze out which has size not equal to one
aCA
aFA
uravel on non-contiguous array
arr
sum
gen
uiter_strides_c_contig.<locals>.gen
uis_element_indexing.<locals>.<genexpr>
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
collections
T anamedtuple
namedtuple
functools
ctypes
numpy
numba
T a_helperlib
a_helperlib
end
aCFUNCTYPE
c_int
c_long
ndpointer
D andim
l ac_helpers
T Oobject
a__prepare__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
