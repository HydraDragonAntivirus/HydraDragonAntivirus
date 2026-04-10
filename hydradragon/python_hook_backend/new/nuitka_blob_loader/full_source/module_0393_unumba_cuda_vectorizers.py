# Reconstructed from integrated Nuitka blob
# Module: unumba.cuda.vectorizers

a__qualname__
uCUDAUFuncDispatcher.__init__
a__call__
uCUDAUFuncDispatcher.__call__
reduce
uCUDAUFuncDispatcher.reduce
a__reduce
uCUDAUFuncDispatcher.__reduce
a__orig_bases__
a__slots__
u_CUDAGUFuncCallSteps.__init__
is_device_array
u_CUDAGUFuncCallSteps.is_device_array
as_device_array
u_CUDAGUFuncCallSteps.as_device_array
u_CUDAGUFuncCallSteps.to_device
to_host
u_CUDAGUFuncCallSteps.to_host
allocate_device_array
u_CUDAGUFuncCallSteps.allocate_device_array
launch_kernel
u_CUDAGUFuncCallSteps.launch_kernel
uCUDAGeneralizedUFunc.__init__
property
a_call_steps
uCUDAGeneralizedUFunc._call_steps
a_broadcast_scalar_input
uCUDAGeneralizedUFunc._broadcast_scalar_input
a_broadcast_add_axis
uCUDAGeneralizedUFunc._broadcast_add_axis
aDEFAULT_STREAM
launch
uCUDAUFuncMechanism.launch
uCUDAUFuncMechanism.is_device_array
uCUDAUFuncMechanism.as_device_array
uCUDAUFuncMechanism.to_device
uCUDAUFuncMechanism.to_host
uCUDAUFuncMechanism.allocate_device_array
broadcast_device
uCUDAUFuncMechanism.broadcast_device

def __vectorized_{name}({args}, __out__):
__tid__ = __cuda__.grid(1)
if __tid__ < __out__.shape[0]:
__out__[__tid__] = __core__({argitems})
aDeviceVectorize
aCUDAVectorize
a_compile_core
uCUDAVectorize._compile_core
a_get_globals
uCUDAVectorize._get_globals
a_compile_kernel
uCUDAVectorize._compile_kernel
build_ufunc
uCUDAVectorize.build_ufunc
a_kernel_template
uCUDAVectorize._kernel_template

def __gufunc_{name}({args}):
__tid__ = __cuda__.grid(1)
if __tid__ < {checkedarg}:
__core__({argitems})
aDeviceGUFuncVectorize
aCUDAGUFuncVectorize
uCUDAGUFuncVectorize.build_ufunc
uCUDAGUFuncVectorize._compile_kernel
uCUDAGUFuncVectorize._kernel_template
uCUDAGUFuncVectorize._get_globals
unumba\cuda\vectorizers.py
u<module numba.cuda.vectorizers>
T a__class__
T aself
args
kws
T aself
kernelmap
engine
pyfunc
a__class__
T aself
types_to_retty_kernels
pyfunc
T aself
nin
nout
args
kwargs
a__class__
T
self
mem
gpu_mems
stream
wnafatcut
thincut
out
left
right
T aself
ary
newshape
newax
newstrides
T aself
ary
shape
T aself
T aself
sig
cudevfn
T aself
fnobj
sig
T aself
sig
corefn
glbls
T aself
corefn
glbl
T aself
shape
dtype
stream
T aself
shape
dtype
T aself
obj
T aself
ary
shape
ax_differs
missingdim
strides
ax
T aself
engine
T aself
func
count
stream
args
T aself
kernel
nelem
args
T aself
arg
stream
wnagpu_mems
mem
out
buf
T aself
hostary
stream
T aself
hostary
T aself
devary
stream
T aself
devary
hostary
out

.numba.experimental
M
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_numba
u\not_existing
experimental
T aNUITKA_PACKAGE_numba_experimental
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
jitclass
T ajitclass
l l
unumba\experimental\__init__.py
u<module numba.experimental>

.numba.experimental.function_type
Q
aCFunc
a_sig
aWrapperAddressProtocol
signature
ufunction type from
a__name__

aFunctionType
ftype
aFunctionPrototype
lookup
rtype
get_value_type
atypes
dmm
ir
aPointerType
aFunctionProtoModel
a__init__
fe_type
c_addr
types
voidptr
py_addr
jit_addr
aFunctionModel
add_dynamic_addr
T ainfo
get_precise
a_wrapper_address
cgutils
create_struct_proxy
a_getvalue
aDispatcher
a__wrapper_address__
ulower_constant_struct_function_type({}, {}, {}, {})
is_precise
q aaddress
get_compile_result
fndesc
llvm_cfunc_wrapper_name
library
get_pointer_to_function
uget wrapper address of
u instance with
uwrapper address must be integer, got
u instance
l
uwrapper address of
func
u instance must be a positive integer but got
u [sig=
w]allvm_func_name
ujit address must be integer, got
get_python_api
insert_const_string
module
unumba.experimental.function_type
import_module
object_getattr_string
decref
unserialize
serialize_object
call_function_objargs
ignore
if_then
is_null
D alikely
Fa__enter__
a__exit__
return_exc
call_conv
return_null
ret
get_null_object
T nnnacontext
builder
lower_get_wrapper_address
D afailure_mode
return_null
pyapi
long_as_voidptr
ptrtoint
lower_get_jit_address
aNativeValue
T avalue
alloca_once
pyobj
inttoptr
ufirst-class function
u parent object not set
err_set_string
aPyExc_MemoryError
store
load
incref
dispatcher
errors
aNumbaError
pointee
get_or_insert_function
bitcast
declare_function
active_code_library
add_linking_library
gil_ensure
D afailure_mode
return_exc
gil_release
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
partial
unumba.extending
T atypeof_impl
typeof_impl
T amodels
register_model
models
register_model
T aunbox
aNativeValue
box
unbox
box
unumba.core.imputils
T alower_constant
lower_cast
lower_constant
lower_cast
unumba.core.ccallback
T aCFunc
unumba.core
T acgutils
llvmlite
T air
T atypes
errors
unumba.core.types
T aFunctionType
aUndefinedFunctionType
aFunctionPrototype
aWrapperAddressProtocol
aUndefinedFunctionType
unumba.core.dispatcher
T aDispatcher
register
typeof_function_type
aPrimitiveModel
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
