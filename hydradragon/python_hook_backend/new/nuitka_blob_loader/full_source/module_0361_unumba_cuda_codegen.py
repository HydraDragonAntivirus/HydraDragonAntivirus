# Reconstructed from integrated Nuitka blob
# Module: unumba.cuda.codegen

a__qualname__
uCUDACodeLibrary.__init__
property
uCUDACodeLibrary.llvm_strs
get_llvm_str
uCUDACodeLibrary.get_llvm_str
uCUDACodeLibrary._ensure_cc
T nuCUDACodeLibrary.get_asm_str
uCUDACodeLibrary.get_ltoir
uCUDACodeLibrary.get_cubin
get_cufunc
uCUDACodeLibrary.get_cufunc
get_linkerinfo
uCUDACodeLibrary.get_linkerinfo
get_sass
uCUDACodeLibrary.get_sass
get_sass_cfg
uCUDACodeLibrary.get_sass_cfg
add_ir_module
uCUDACodeLibrary.add_ir_module
add_linking_library
uCUDACodeLibrary.add_linking_library
add_linking_file
uCUDACodeLibrary.add_linking_file
uCUDACodeLibrary.get_function
uCUDACodeLibrary.modules
uCUDACodeLibrary.linking_libraries
finalize
uCUDACodeLibrary.finalize
a_reduce_states
uCUDACodeLibrary._reduce_states
classmethod
a_rebuild
uCUDACodeLibrary._rebuild
a__orig_bases__
aJITCUDACodegen
a_library_class
uJITCUDACodegen.__init__
a_create_empty_module
uJITCUDACodegen._create_empty_module
a_add_module
uJITCUDACodegen._add_module
magic_tuple
uJITCUDACodegen.magic_tuple
unumba\cuda\codegen.py
u<module numba.cuda.codegen>
T a__class__
T aself
codegen
name
entry_name
max_registers
nvvm_options
a__class__
T aself
module_name
T aself
module
T aself
name
ir_module
T aself
cc
device
T acls
codegen
name
entry_name
llvm_strs
ptx_cache
cubin_cache
linkerinfo_cache
max_registers
nvvm_options
needs_cudadevrt
instance
T aself
msg
T aself
mod
T aself
filepath
T aself
library
T acubin
flags
T aself
library
mod
fn
T aself
cc
ptxes
arch
options
irs
ptx
T aself
cc
cubin
linker
ltoir
ptx
path
T aself
msg
ctx
device
cufunc
cubin
module
T aself
name
fn
T aself
cc
T aself
T aself
cc
ltoir
arch
options
irs
T aself
libs
lib
T aself
ctx
cc
T acubin
flags
fd
fname
wfacp
weamsg
.numba.cuda.compiler
sanitize_compile_result_entries
aCUDACompileResult
aLoweringPass
a__init__
cr
typing
signature
return_type
args
cuda_compile_result
typingctx
targetctx
status
fail_reason
type_annotation
library
call_helper
fndesc
T atyping_context
target_context
typing_error
type_annotation
library
call_helper
signature
fndesc
codegen
func_id
func_qualname
flags
nvvm_options
create_library
T anvvm_options
enable_object_caching
aDefaultPassBuilder
aPassManager
T acuda
define_untyped_pipeline
state
passes
extend
define_typed_pipeline
define_cuda_lowering_pipeline
finalize
T acuda_lowering
add_pass
aIRLegalization
uensure IR is legal prior to lowering
aAnnotateTypes
uannotate types
aCreateLibrary
ucreate library
aNativeLowering
unative lowering
aCUDABackend
ucuda backend
uCompute Capability must be supplied
descriptor
T acuda_target
l acuda_target
l
typing_context
target_context
aCUDAFlags
no_compile
no_cpython_wrapper
no_cfunc_wrapper
debuginfo
dbg_directives_only
python
error_model
numpy
forceinline
fastmath
compute_capability
unumba.core.target_extension
T atarget_override
target_override
a__enter__
a__exit__
compiler
compile_extra
aCUDACompiler
T atypingctx
targetctx
func
args
return_type
flags
locals
pipeline_class
T nnnacres
name

a_function_
T aentry_name
nvvm_options
add_linking_library
argtypes
restype
aCUDACABICallConv
get_function_type
call_conv
create_module
T ucuda.cabi.wrapper
ir
aFunction
llvm_func_name
aIRBuilder
append_basic_block
T u
get_arg_packer
from_arguments
call_function
utoo many values to unpack (expected 2)
ret
add_ir_module
T anumba
wcuUnsupported ABI:
wcuThe C ABI is not supported for kernels
T aptx
ltoir
uUnsupported output type:
warn
aNumbaInvalidConfigWarning
T udebug=True with opt=True (the default) is not supported by CUDA. This may result in a crash - set debug=False or opt=False.
ltoir
opt
l ugen-lto
sigutils
normalize_signature
config
aCUDA_DEFAULT_PTX_CC
compile_cuda
T adebug
lineinfo
fastmath
nvvm_options
cc
types
void
uCUDA kernel must have void return type.
get
abi_name
a__name__
cabi_wrap_function
a__code__
co_filename
co_firstlineno
prepare_cuda_kernel
get_ltoir
T acc
get_asm_str
get_current_device
compile
T	adebug
lineinfo
device
fastmath
cc
opt
abi
abi_info
output
ptx
compile_ptx
T adebug
lineinfo
device
fastmath
cc
opt
abi
abi_info
declare_device_function_template
key
aExternFunction
aConcreteTemplate
a__prepare__
device_function_template
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
