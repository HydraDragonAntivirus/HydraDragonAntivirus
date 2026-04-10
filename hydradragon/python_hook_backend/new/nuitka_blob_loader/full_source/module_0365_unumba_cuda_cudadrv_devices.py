# Reconstructed from integrated Nuitka blob
# Module: unumba.cuda.cudadrv.devices

a__qualname__
u_DeviceList.__getattr__
u_DeviceList.__getitem__
a__str__
u_DeviceList.__str__
a__iter__
u_DeviceList.__iter__
a__len__
u_DeviceList.__len__
property
current
u_DeviceList.current
a__orig_bases__
a__init__
u_DeviceContextManager.__init__
u_DeviceContextManager.__getattr__
u_DeviceContextManager.__enter__
u_DeviceContextManager.__exit__
u_DeviceContextManager.__str__
a_Runtime
u_Runtime.__init__
u_Runtime.get_or_create_context
u_Runtime._get_or_create_context_uncached
u_Runtime._activate_context_for
u_Runtime._get_attached_context
u_Runtime._set_attached_context
u_Runtime.reset
u_Runtime._destroy_all_contexts
get_context
require_context
unumba\cuda\cudadrv\devices.py
u<module numba.cuda.cudadrv.devices>
T a__class__
T aself
exc_type
exc_val
exc_tb
T aself
item
T aself
attr
numdev
gpus
a__class__
T aself
devnum
T aself
device
T aself
devnum
gpu
newctx
cached_ctx
T aself
gpu
T aself
devnum
ac
ctx
ctx_handle
ac_ctx_handle
msg
T aargs
kws
fn
T afn
T aself
ctx
T aself
ac
devnum
T aself
oldctx
newctx
T adevnum
T aself
devnum
attached_ctx
T afn
a_require_cuda_context

.numba.cuda.cudadrv.driver
e
logging
getLogger
T unumba.cuda.cudadrv.driver
hasHandlers
config
aCUDA_LOG_LEVEL
upper
aCRITICAL
setLevel
aStreamHandler
stderr
setFormatter
aFormatter
T u== CUDA [%(relativeCreated)d] %(levelname)5s -- %(message)s
T afmt
addHandler
aNullHandler
code
msg
aCudaAPIError
a__init__
u[%s] %s
aCUDA_DRIVER
w0a_raise_driver_not_found
aWinDLL
u\windows\system32
unvcuda.dll
uNUMBA_CUDA_DRIVER %s is not a valid path
uNUMBA_CUDA_DRIVER %s is not a valid file path.  Note it must be a filepath of the .so/.dll/.dylib or the driver
product
utoo many values to unpack (expected 2)
join
dlloader
path_not_exist
driver_load_error
dll
w
a_raise_driver_error
u<genexpr>
uload_driver.<locals>.<genexpr>
locate_driver_and_loader
load_driver
aCudaSupportError
aDRIVER_NOT_FOUND_MSG
aDRIVER_LOAD_ERROR_MSG
aCUDA_ERROR
utils
aUniqueDict
enums
startswith
prefix
map
getpid
a_singleton
a__new__
devices
is_initialized
initialization_error
pid
aDISABLE_CUDA
T uCUDA is disabled due to setting NUMBA_DISABLE_CUDA=1 in the environment, or because CUDA is unsupported on 32-bit systems.
find_driver
lib
make_logger
a_logger
info
T ainit
cuInit
T l

u (
w)uError at driver init:
a_getpid
a_initialize_extras
aUSE_NV_BINDING
aCFUNCTYPE
c_void_p
a_extras
set_cuIpcOpenMemHandle
a_find_api
T acuIpcOpenMemHandle
c_int
aPOINTER
drvapi
cu_device_ptr
cu_ipc_mem_handle
c_uint
call_cuIpcOpenMemHandle
a__name__
a_ctypes_wrap_fn
cuIpcOpenMemHandle
ensure_initialized
uError at driver init:
%s:
a_cuda_python_wrap_fn
aAPI_PROTOTYPES
l
:l nnarestype
argtypes
verbose_cuda_api_call
uDriver._ctypes_wrap_fn.<locals>.verbose_cuda_api_call
safe_cuda_api_call
uDriver._ctypes_wrap_fn.<locals>.safe_cuda_api_call
aCUDA_LOG_API_ARGS
wraps
libfn
u,
debug
ucall driver api: %s(%s)
self
a_check_ctypes_error
fname
ucall driver api: %s
binding
uDriver._cuda_python_wrap_fn.<locals>.verbose_cuda_api_call
uDriver._cuda_python_wrap_fn.<locals>.safe_cuda_api_call
a_check_cuda_python_error
aCUDA_PER_THREAD_DEFAULT_STREAM
T a_v2_ptds
a_v2_ptsz
a_ptds
a_ptsz
a_v2

T a_v2

absent_function
uDriver._find_api.<locals>.absent_function
aCudaDriverError
uDriver missing function:
critical
upid %s forked from pid %s after CUDA driver init
T uCUDA initialized before forking
aCUDA_SUCCESS
aERROR_MAP
get
aUNKNOWN_CUDA_ERROR
uCall to %s results in %s
error
aCUDA_ERROR_NOT_INITIALIZED
a_detect_fork
aCUresult
name
retval
aDevice
weakref
proxy
dev
cuDeviceGetCount
byref
value
values
reset
get_active_context
a__enter__
a__exit__
devnum
driver
cuCtxPopCurrent
cu_context
T nnna_ActiveContext
cuDriverGetVersion
l  l
a_tls_cache
ctx_devnum
cuCtxGetCurrent
hctx
cuCtxGetDevice
cu_device
a_is_top
context_handle
delattr
aCU_DEVICE_ATTRIBUTE_
get_device_count
get_device
get_device_identity
uNo device of {} is found. Target device may not be visible in this process.
cuDeviceGet
id
uDriver returned device
got_devnum
u instead of
attributes
aCOMPUTE_CAPABILITY_MAJOR
aCOMPUTE_CAPABILITY_MINOR
compute_capability
cuDeviceGetName
l  adecode
T uutf-8
rstrip
T w
c_char
cuDeviceGetUuid
bytes
cu_uuid
uGPU-%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x
uuid
primary_context
pci_domain_id
aPCI_DOMAIN_ID
pci_bus_id
aPCI_BUS_ID
pci_device_id
aPCI_DEVICE_ID
u<CUDA device %d '%s'>
aCUdevice_attribute
cuDeviceGetAttribute
aDEVICE_ATTRIBUTES
met_requirement_for_device
cuDevicePrimaryCtxRetain
aContext
cuDevicePrimaryCtxRelease
release_primary_context
cuDevicePrimaryCtxReset
T l l aMIN_REQUIRED_CC
u%s has compute capability < %s
context
uMemory manager requires a context
a__class__
allocations
a_PendingDeallocs
deallocations
aCUDA_ERROR_OUT_OF_MEMORY
clear
aCU_MEMHOSTALLOC_DEVICEMAP
aCU_MEMHOSTALLOC_PORTABLE
aCU_MEMHOSTALLOC_WRITECOMBINED
allocator
uHostOnlyCUDAMemoryManager.memhostalloc.<locals>.allocator
a_attempt_allocation
pointer
a_hostalloc_finalizer
aMappedMemory
T afinalizer
own
aPinnedMemory
cuMemHostAlloc
size
flags
aCU_MEMHOSTREGISTER_DEVICEMAP
uHostOnlyCUDAMemoryManager.mempin.<locals>.allocator
a_pin_finalizer
T aowner
finalizer
cuMemHostRegister
uHostOnlyCUDAMemoryManager.memallocmanaged.<locals>.allocator
a_alloc_finalizer
ptr
aManagedMemory
aCUmemAttach_flags
attach_global
aCU_MEM_ATTACH_GLOBAL
aCU_MEM_ATTACH_HOST
cuMemAllocManaged
disable
defer_cleanup
uHostOnlyCUDAMemoryManager.defer_cleanup
device_extents
cuIpcGetMemHandle
handle
device
aIpcHandle
ipchandle
T aoffset
memory_capacity
a_SizeNotSet
get_memory_info
total
uNumbaCUDAMemoryManager.memalloc.<locals>.allocator
aAutoFreePointer
cuMemAlloc
cuMemGetInfo
c_size_t
aMemoryInfo
T afree
total
a_SUPPORTED_EMM_INTERFACE_VERSION
a_memory_manager
aCUDA_MEMORY_MANAGER
default
aNumbaCUDAMemoryManager
import_module
set_memory_manager
a_numba_memory_manager
uFailed to use memory manager from %s
T nT acontext
interface_version
uEMM Plugin interface has version %d - version %d required
deque
a_cons
a_disable_count
a_size
aCUDA_DEALLOCS_RATIO
uadd pending dealloc: %s %s bytes
append
aCUDA_DEALLOCS_COUNT
a_max_pending_bytes
is_disabled
popleft
utoo many values to unpack (expected 3)
udealloc: %s %s bytes
l u_PendingDeallocs.disable
a_ensure_memory_manager
memory_manager
modules
extras
ureset context of device %s
a_cuda_python_active_blocks_per_multiprocessor
a_ctypes_active_blocks_per_multiprocessor
cuOccupancyMaxActiveBlocksPerMultiprocessor
cuOccupancyMaxActiveBlocksPerMultiprocessorWithFlags
a_cuda_python_max_potential_block_size
a_ctypes_max_potential_block_size
cu_occupancy_b2d_size
cuOccupancyMaxPotentialBlockSize
cuOccupancyMaxPotentialBlockSizeWithFlags
from_bytes
D abyteorder
little
aCUoccupancyB2DSize
initialize
cuCtxPushCurrent
prepare_for_use
pop_active_context
memalloc
memallocmanaged
memhostalloc
aCAN_MAP_HOST_MEMORY
u%s cannot map host memory
mempin
aSUPPORTS_IPC
uOS does not support CUDA IPC
get_ipc_handle
aMemoryPointer
dptr
T acontext
pointer
size
cuCtxEnablePeerAccess
aCUdevice
cuDeviceCanAccessPeer
can_access_peer
encode
T autf8
c_char_p
create_module_image
load_module_image
module
aCUstream
aCU_STREAM_DEFAULT
cu_stream
aStream
aCU_STREAM_LEGACY
aCU_STREAM_PER_THREAD
aCUstream_flags
cuStreamCreate
a_stream_finalizer
uptr for external stream must be an int
D aexternal
taCU_EVENT_DISABLE_TIMING
cuEventCreate
cu_event
aEvent
a_event_finalizer
cuCtxSynchronize
uContext.defer_cleanup
u<CUDA context %s of device %d>
a__eq__
load_module_image_cuda_python
load_module_image_ctypes
aCUDA_LOG_SIZE
aCU_JIT_INFO_LOG_BUFFER
addressof
aCU_JIT_INFO_LOG_BUFFER_SIZE_BYTES
aCU_JIT_ERROR_LOG_BUFFER
aCU_JIT_ERROR_LOG_BUFFER_SIZE_BYTES
aCU_JIT_LOG_VERBOSE
aCUDA_VERBOSE_JIT_LOG
cu_jit_option
cu_module
cuModuleLoadDataEx
ucuModuleLoadDataEx error:
%s
aCtypesModule
a_module_finalizer
aCUjit_option
aCudaPythonModule
core
u_alloc_finalizer.<locals>.core
alloc_key
add_item
cuMemFree
u_hostalloc_finalizer.<locals>.core
mapped
cuMemFreeHost
u_pin_finalizer.<locals>.core
cuMemHostUnregister
u_event_finalizer.<locals>.core
deallocs
cuEventDestroy
u_stream_finalizer.<locals>.core
cuStreamDestroy
u_module_finalizer.<locals>.core
shutting_down
module_unload
u_module_finalizer.<locals>.core.<locals>.module_unload
dealloc
cuModuleUnload
base
offset
a_opened_mem
uopening IpcHandle from original process
uIpcHandle is already opened
open_ipc_handle
view
uIpcHandle not opened
cuIpcCloseMemHandle
parent
source_info
numba
T acuda
cuda
from_identity
a_CudaIpcImpl
T aparent
gpus
open
get_context
device_to_device
source_ptr
close
a_impl
uIPC handle doesn't have source info
a_sentry_source_info
a_StagedIpcImpl
open_direct
open_staged
T adevicearray
devicearray
itemsize
aDeviceNDArray
T ashape
strides
dtype
gpu_data
reserved
serialize
a_rebuild_reduction
aCUipcMemHandle
T abase
handle
size
source_info
offset
device_pointer
a_cuda_memsize_
is_managed
refct
a_owner
finalize
a_finalizer
aOwnedPointer
alive
uFreeing dead memory
cuMemsetD8Async
cuMemsetD8
device_pointer_value
unon-empty slice into empty slice
start
usize cannot be negative
aCUdeviceptr
from_address
getPtr
owner
T aowner
owned
host_pointer
cuMemHostGetDevicePointer
a_bufptr_
devptr
a_buflen_
aMappedOwnedPointer
aManagedOwnedPointer
a_mem
a_view
deref
uOwnedPointer.__init__.<locals>.deref
mem
free
external
u<Default CUDA stream on %s>
u<Legacy default CUDA stream on %s>
u<Per-thread default CUDA stream on %s>
u<External CUDA stream %d on %s>
u<CUDA stream %d on %s>
cuStreamSynchronize
synchronize
auto_synchronize
uStream.auto_synchronize
a_py_incref
a_stream_callback
aCUstreamCallback
cuStreamAddCallback
data
warnings
warn
uException in stream callback:
a_py_decref
asyncio
get_running_loop
create_future
resolver
uStream.async_done.<locals>.resolver
callback
uStream.async_done.<locals>.callback
add_callback
done
set_result
set_exception
uStream error
loop
call_soon_threadsafe
cuEventQuery
aCUDA_ERROR_NOT_READY
cuEventRecord
cuEventSynchronize
cuStreamWaitEvent
event_elapsed_time
cuEventElapsedTime
c_float
info_log
unload_module
cu_function
cuModuleGetFunction
aCtypesFunction
cuModuleGetGlobal
aCudaPythonFunction
read_func_attr_all
attrs
u<CUDA function %s>
aCU_FUNC_CACHE_PREFER_EQUAL
aCU_FUNC_CACHE_PREFER_L1
aCU_FUNC_CACHE_PREFER_SHARED
aCU_FUNC_CACHE_PREFER_NONE
cuFuncSetCacheConfig
cuFuncGetAttribute
read_func_attr
aCU_FUNC_ATTRIBUTE_NUM_REGS
aCU_FUNC_ATTRIBUTE_CONST_SIZE_BYTES
aCU_FUNC_ATTRIBUTE_LOCAL_SIZE_BYTES
aCU_FUNC_ATTRIBUTE_SHARED_SIZE_BYTES
aCU_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK
aFuncAttr
T aregs
const
local
shared
maxthreads
aCUfunction_attribute
cuLaunchCooperativeKernel
cuLaunchKernel
aCUDA_ENABLE_MINOR_VERSION_COMPATIBILITY
aMVCLinker
aCudaPythonLinker
aCtypesLinker
lto
nvrtc
compile
cc
aDUMP_ASSEMBLY
print
uASSEMBLY %s
center
T lPw-T u================================================================================
splitext
u.ptx
add_ptx
rb
read
add_cu
cu
uDon't know how to link file with no extension
add_cu_file
aFILE_EXTENSION_MAP
uDon't know how to link file with extension .
add_file
cubinlinker
T aCubinLinker
aCubinLinker
a_MVC_ERROR_MESSAGE
uMVCLinker requires Compute Capability to be specified, but cc is None
sm_
u--gpu-name
u-c
u--maxrregcount=
u--generate-line-info
ptx_compile_options
u--arch=
a_linker
error_log
ptxcompiler
T acompile_ptx
compile_ptx
T aCubinLinkerError
aCubinLinkerError
add_cubin
compiled_program
aLinkerError
u not found
pathlib
aPath
cubin
fatbin
add_fatbin
wauDon't know how to link
ptx
complete
T l aCU_JIT_MAX_REGISTERS
aCU_JIT_GENERATE_LINE_INFO
aCU_JIT_TARGET_FROM_CUCONTEXT
aCU_JIT_TARGET
cu_link_state
cuLinkCreate
cuLinkDestroy
linker_info_buf
linker_errors_buf
a_keep_alive
cuLinkAddData
aCU_JIT_INPUT_PTX
u%s
%s
cuLinkAddFile
aCUDA_ERROR_FILE_NOT_FOUND
cuLinkComplete
:nnnacast
np
ctypeslib
as_array
T ashape
aCUjit_target
aCU_TARGET_COMPUTE_
aCUjitInputType
aCUpointer_attribute
aCU_POINTER_ATTRIBUTE_DEVICE_POINTER
cuPointerGetAttribute
device_ctypes_pointer
cuMemGetAddressRange
sz
dtype
char
aMm
a_is_datetime_dtype
int64
obj
void
a_workaround_for_datetime
mviewbuf
memoryview_get_buffer
memoryview_get_extents
memoryview_get_extents_info
host_memory_extents
require_device_memory
a__cuda_memory__
is_device_memory
uNot a CUDA memory object.
a_depends_
extend
cuMemcpyHtoDAsync
cuMemcpyHtoD
D areadonly
tacuMemcpyDtoHAsync
cuMemcpyDtoH
cuMemcpyDtoDAsync
cuMemcpyDtoD
cuProfilerStart
cuProfilerStop
profile_start
profile_stop
profiling
get_version
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
sys
os
ctypes
functools
threading
itertools
T aproduct
abc
T aABCMeta
abstractmethod
aABCMeta
abstractmethod
contextlib
importlib
numpy
collections
T anamedtuple
deque
namedtuple
T amviewbuf
unumba.core
T autils
serialize
config
T aCudaSupportError
aCudaDriverError
T aAPI_PROTOTYPES
T acu_occupancy_b2d_size
cu_stream_callback_pyobj
cu_uuid
cu_stream_callback_pyobj
unumba.cuda.cudadrv
T aenums
drvapi
nvrtc
a_extras
aCUDA_USE_NVIDIA_BINDING
T l l apythonapi
aPy_DecRef
aPy_IncRef
py_object
T ERuntimeError
a__prepare__
aDeadMemoryError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
