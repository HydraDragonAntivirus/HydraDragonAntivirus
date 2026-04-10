# Reconstructed from integrated Nuitka blob
# Module: unumba.cuda.cudadrv.nvrtc

a__qualname__
l aNVRTC_ERROR_OUT_OF_MEMORY
l aNVRTC_ERROR_PROGRAM_CREATION_FAILURE
l aNVRTC_ERROR_INVALID_INPUT
l aNVRTC_ERROR_INVALID_PROGRAM
l aNVRTC_ERROR_INVALID_OPTION
l l aNVRTC_ERROR_BUILTIN_OPERATION_FAILURE
l aNVRTC_ERROR_NO_NAME_EXPRESSIONS_AFTER_COMPILATION
l	aNVRTC_ERROR_NO_LOWERED_NAMES_BEFORE_COMPILATION
l
aNVRTC_ERROR_NAME_EXPRESSION_NOT_VALID
l aNVRTC_ERROR_INTERNAL_ERROR
a__orig_bases__
aLock
a__init__
uNvrtcProgram.__init__
uNvrtcProgram.handle
a__del__
uNvrtcProgram.__del__
nvrtcGetCUBINSize
nvrtcGetCUBIN
uNVRTC.__new__
get_version
uNVRTC.get_version
uNVRTC.create_program
uNVRTC.compile_program
uNVRTC.destroy_program
uNVRTC.get_compile_log
uNVRTC.get_ptx
compile
unumba\cuda\cudadrv\nvrtc.py
u<module numba.cuda.cudadrv.nvrtc>
T a__class__
T aself
T aself
nvrtc
handle
T	acls
open_cudalib
inst
lib
weaname
proto
func
checked_call
T afunc
name
args
error
error_name
msg
T asrc
name
cc
nvrtc
program
major
minor
arch
include
cudadrv_path
numba_cuda_path
numba_include
options
compile_error
log
msg
ptx
T aself
program
options
encoded_options
option_pointers
c_options_type
c_options
T aself
src
name
handle
T aself
program
T aself
program
log_size
log
T aself
program
ptx_size
ptx
T aself
major
minor
.numba.cuda.cudadrv.nvvm
&
K aNVVM
aNvvmSupportError
a_nvvm_lock
a__enter__
a__exit__
a_NVVM__INSTANCE
a__new__
open_cudalib
T anvvm
driver
ulibNVVM cannot be found. Do `conda install cudatoolkit`:
%s
a_PROTOTYPES
items
utoo many values to unpack (expected 2)
inst
l
restype
:l nnaargtypes
T nnnaget_ir_version
a_majorIR
l a_minorIR
l a_majorDbg
l a_minorDbg
get_supported_ccs
a_supported_ccs
T l l a_datalayout_original
a_datalayout_i128
c_int
nvvmVersion
byref
check_error
uFailed to get version.
value
nvvmIRVersion
uFailed to get IR version.
aNvvmError
aRESULT_CODE_NAMES
print
nvvm_program
a_handle
nvvmCreateProgram
uFailed to create CU
nvvmDestroyProgram
uFailed to destroy CU
D aexit
tanvvmAddModuleToProgram
uFailed to add module
nvvmLazyAddModuleToProgram
stringify_option
uCompilationUnit.compile.<locals>.stringify_option
c_char_p
encode
T autf8
nvvmVerifyProgram
a_try_error
uFailed to verify
nvvmCompileProgram
uFailed to compile
c_size_t
nvvmGetCompiledResultSize
uFailed to get size of compiled result.
c_char
nvvmGetCompiledResult
uFailed to get compiled result.
get_log
log
warnings
warn
aNvvmWarning
T acategory
:nnnareplace
T w_w-w-u
w=u%s
%s
nvvmGetProgramLogSize
uFailed to get compilation log size.
nvvmGetProgramLog
uFailed to get compilation log.
decode
aCTK_SUPPORTED
aCOMPUTE_CAPABILITIES
config
aCUDA_DEFAULT_PTX_CC
unumba.cuda.cudadrv.runtime
T aruntime
runtime
get_version
min
w.uCUDA Toolkit
u is unsupported by Numba -
u is the minimum required version.
ccs_supported_by_ctk
supported_ccs
T uNo supported GPU compute capabilities found. Please check your cudatoolkit version matches your CUDA version.
uGPU compute capability %d.%d is not supported(requires >=%d.%d)
q aFORCE_CUDA_CC
find_closest_arch
ucompute_%d%d
a_cache_
get_libdevice
aMISSING_LIBDEVICE_FILE_MSG
open_libdevice
abc
cas_nvvm
format
T aTi
wTaTi
aOP
aFUNC
aCAS
ir_cas
ir_numba_atomic_binary_template
aNAN
aPTR_OR_VAL
ir_numba_atomic_minmax_template
ir_numba_atomic_inc_template
T wTaTu
aCAS
ir_numba_atomic_dec_template
udeclare double @"___numba_atomic_double_add"(double* %".1", double %".2")
ir_numba_atomic_binary
T adouble
i64
fadd
add
T wTaTi
aOP
aFUNC
udeclare float @"___numba_atomic_float_sub"(float* %".1", float %".2")
T afloat
i32
fsub
sub
udeclare double @"___numba_atomic_double_sub"(double* %".1", double %".2")
T adouble
i64
fsub
sub
udeclare i64 @"___numba_atomic_u64_inc"(i64* %".1", i64 %".2")
ir_numba_atomic_inc
T ai64
u64
T wTaTu
udeclare i64 @"___numba_atomic_u64_dec"(i64* %".1", i64 %".2")
ir_numba_atomic_dec
udeclare float @"___numba_atomic_float_max"(float* %".1", float %".2")
ir_numba_atomic_minmax
T afloat
i32

unnan olt
ptr
max
T wTaTi
aNAN
aOP
aPTR_OR_VAL
aFUNC
udeclare double @"___numba_atomic_double_max"(double* %".1", double %".2")
T adouble
i64

unnan olt
ptr
max
udeclare float @"___numba_atomic_float_min"(float* %".1", float %".2")
T afloat
i32

unnan ogt
ptr
min
udeclare double @"___numba_atomic_double_min"(double* %".1", double %".2")
T adouble
i64

unnan ogt
ptr
min
udeclare float @"___numba_atomic_float_nanmax"(float* %".1", float %".2")
T afloat
i32
nan
ult

max
udeclare double @"___numba_atomic_double_nanmax"(double* %".1", double %".2")
T adouble
i64
nan
ult

max
udeclare float @"___numba_atomic_float_nanmin"(float* %".1", float %".2")
T afloat
i32
nan
ugt

min
udeclare double @"___numba_atomic_double_nanmin"(double* %".1", double %".2")
T adouble
i64
nan
ugt

min
T aimmarg

llvmir
llvm140_to_70_ir
fastmath
update
D aftz
fma
prec_div
prec_sqrt
tpFpaCompilationUnit
aLibDevice
llvm_replace
cu
add_module
lazy_add_module
get
compile
splitlines
startswith
T uattributes #
re_attributes_def
match
group
T l asplit
w abuf
line
w
willreturn
u<genexpr>
ullvm140_to_70_ir.<locals>.<genexpr>
module
ir
aMetaDataString
kernel
aConstant
aIntType
T l aadd_metadata
cgutils
get_or_insert_named_metadata
unvvm.annotations
add
T l aas_pointer
aArrayType
bitcast
aGlobalVariable
ullvm.used
appending
linkage
ullvm.metadata
section
initializer
attributes
discard
T anoinline
i32
add_named_metadata
unvvmir.version
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
logging
re
sys
c_void_p
aPOINTER
threading
llvmlite
T air
error
T aNvvmError
aNvvmSupportError
aNvvmWarning
libs
T aget_libdevice
open_libdevice
open_cudalib
unumba.core
T acgutils
config
getLogger
T unumba.cuda.cudadrv.nvvm
logger
aADDRSPACE_GENERIC
aADDRSPACE_GLOBAL
aADDRSPACE_SHARED
l aADDRSPACE_CONSTANT
l aADDRSPACE_LOCAL
nvvm_result
L
aNVVM_SUCCESS
aNVVM_ERROR_OUT_OF_MEMORY
aNVVM_ERROR_PROGRAM_CREATION_FAILURE
aNVVM_ERROR_IR_VERSION_MISMATCH
aNVVM_ERROR_INVALID_INPUT
aNVVM_ERROR_INVALID_PROGRAM
aNVVM_ERROR_INVALID_IR
aNVVM_ERROR_INVALID_OPTION
aNVVM_ERROR_NO_MODULE_IN_PROGRAM
aNVVM_ERROR_COMPILATION
wiwkamodules
unumba.cuda.cudadrv.nvvm
ue-p:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-v16:16:16-v32:32:32-v64:64:64-v128:128:128-n16:32:64
ue-p:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-i128:128:128-f32:32:32-f64:64:64-v16:16:16-v32:32:32-v64:64:64-v128:128:128-n16:32:64
is_available
aLock
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
