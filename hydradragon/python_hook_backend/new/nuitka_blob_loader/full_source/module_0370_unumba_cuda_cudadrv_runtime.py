# Reconstructed from integrated Nuitka blob
# Module: unumba.cuda.cudadrv.runtime

a__qualname__
uCudaRuntimeAPIError.__init__
a__str__
uCudaRuntimeAPIError.__str__
a__orig_bases__
aRuntime
uRuntime.__init__
uRuntime._initialize
a__getattr__
uRuntime.__getattr__
uRuntime._wrap_api_call
uRuntime._check_error
uRuntime._find_api
uRuntime.get_version
is_supported_version
uRuntime.is_supported_version
uRuntime.supported_versions
unumba\cuda\cudadrv\runtime.py
u<module numba.cuda.cudadrv.runtime>
T a__class__
T aself
fname
proto
restype
argtypes
libfn
safe_call
T aself
code
msg
a__class__
T aself
T aself
fname
retcode
errname
msg
T aself
fname
absent_function
T aself
msg
T aself
fname
libfn
safe_cuda_api_call
T aargs
kws
msg
fname
T afname
T aself
rtver
major
minor
T aargs
retcode
libfn
self
fname
T afname
libfn
self

.numba.cuda.cudaimpl
F#
nvvmutils
call_sreg
u%s.x
u%s.y
u%s.z
cgutils
pack_struct
initialize_dim3
tid
ntid
ctaid
nctaid
laneid
extract_value
l
l l a_unique_smem_id
u{0}_{1}
args
literal_value
parse_dtype
a_generic_array
a_get_unique_smem_id
T a_cudapy_smem
nvvm
aADDRSPACE_SHARED
T ashape
dtype
symbol_name
addrspace
can_dynsized
a_cudapy_lmem
aADDRSPACE_LOCAL
module
ir
aFunctionType
aVoidType
get_or_insert_function
ullvm.nvvm.membar.cta
call
get_dummy_value
ullvm.nvvm.membar.sys
ullvm.nvvm.membar.gl
get_constant
types
int32
g       anone
ptx_syncwarp_mask
aIntType
T l ullvm.nvvm.bar.warp.sync
utoo many values to unpack (expected 5)
real_domain
bitcast
bitwidth
aLiteralStructType
T l ullvm.nvvm.shfl.sync.i32
l afloat32
aFloatType
make_anonymous_struct
trunc
lshr
i8
zext
T l@ashl
or_
float64
aDoubleType
ullvm.nvvm.vote.sync
utoo many values to unpack (expected 2)
ullvm.nvvm.match.any.sync.i{}
ullvm.nvvm.match.all.sync.i{}
aInlineAsm
uactivemask.b32 $0;
u=r
D aside_effect
tumov.u32 $0, %lanemask_lt;
ctpop
fma
D l l@T af32
wfT af64
wduConversion between float16 and float

u unsupported
errors
aCudaLoweringError
float16_float_ty_constraint
get_value_type
T l ucvt.
u.f16 $0, $1;
w=u,h
ucvt.rn.f16.
u $0, $1;
u=h,
D l l l l@wcwhwrwluConversion between float16 and int
float16_int_constraint
signed
wswuucvt.rni.
lower
float16
ptx_fp16_binary
ulower_fp16_binary.<locals>.ptx_fp16_binary
op
u.f16 $0,$1,$2;
u=h,h,h
uneg.f16 $0, $1;
u=h,h
ptx_fp16_hneg
uabs.f16 $0, $1;
ptx_fp16_habs
ufma.rn.f16 $0,$1,$2,$3;
u=h,h,h,h
fp16_div
ufp16_div_impl.<locals>.fp16_div
compile_internal
cuda
fp16
hdiv
ptx_fp16_comparison
u_gen_fp16_cmp.<locals>.ptx_fp16_comparison
a_fp16_cmp
format
T aop
int16
icmp_unsigned
u!=
ptx_fp16_minmax
ulower_fp16_minmax.<locals>.ptx_fp16_minmax
a_gen_fp16_cmp
select
return_type
cbrt_funcs
a__nv_brev
a__nv_brevll
ctlz
boolean
a__nv_ffs
a__nv_ffsll
utoo many values to unpack (expected 3)
a__nv_fmaxf
a__nv_fmax
cast
double
a__nv_fminf
a__nv_fmin
a__nv_llrint
round_ndigits
uround_to_impl.<locals>.round_ndigits
math
isinf
isnan
l f
$@f  M    Df
?around
wyafabs
f
?f
@andigits
wzapow2
pow1
impl
ugen_deg_rad.<locals>.impl
utoo many values to unpack (expected 1)
const
fmul
integer_domain
aUniTuple
T adtype
count
unpack_tuple
T acount
indty
context
builder
intp
dtype
uexpect %s but got %s
ndim
uindexing %d-D array with %d-D index
imp
u_atomic_dispatcher.<locals>.imp
a_normalize_indices
make_array
get_item_pointer
D awraparound
tadispatch_fn
declare_atomic_add_float32
declare_atomic_add_float64
atomic_rmw
add
monotonic
declare_atomic_sub_float32
declare_atomic_sub_float64
sub
cudadecl
unsigned_int_numba_types
declare_atomic_inc_int
uUnimplemented atomic inc with
u array
declare_atomic_dec_int
uUnimplemented atomic dec with
a_atomic_dispatcher
impl_ptx_atomic
uptx_atomic_bitwise.<locals>.impl_ptx_atomic
aTuple
stub
aArray
aAny
integer_numba_types
uUnimplemented atomic
u with
xchg
uUnimplemented atomic exch with
declare_atomic_max_float64
declare_atomic_max_float32
int64
max
D aordering
monotonic
uint32
uint64
umax
uUnimplemented atomic max with %s array
declare_atomic_min_float64
declare_atomic_min_float32
min
umin
uUnimplemented atomic min with %s array
declare_atomic_nanmax_float64
declare_atomic_nanmax_float32
declare_atomic_nanmin_float64
declare_atomic_nanmin_float32
ptx_atomic_cas
utoo many values to unpack (expected 4)
atomic_cmpxchg
uUnimplemented atomic cas with %s array
unanosleep.u32 $0;
wrareduce
operator
mul
uarray length <= 0
data_model_manager
aRecord
aBoolean
models
aStructModel
number_domain
uunsupported type: %s
get_data_type
aArrayType
alloca_once
T aname
add_global_variable
get_abi_sizeof
bit_length
align
external
linkage
aConstant
aUndefined
initializer
addrspacecast
aPointerType
T l ageneric
all
create_target_data
aNVVM
data_layout
get_abi_size
rstrides
laststride
umov.u32 $0, %dynamic_smem_size;
udiv
wCT adtype
ndim
layout
populate_array
data
type
T adata
shape
strides
itemsize
meminfo
a_getvalue
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
llvmlite
T air
ullvmlite.binding
binding
unumba.core.imputils
T aRegistry
lower_cast
aRegistry
lower_cast
unumba.core.typing.npydecl
T aparse_dtype
unumba.core.datamodel
T amodels
unumba.core
T atypes
cgutils
unumba.np
T aufunc_db
ufunc_db
unumba.np.npyimpl
T aregister_ufuncs
register_ufuncs
cudadrv
T anvvm
numba
T acuda
unumba.cuda
T anvvmutils
stubs
errors
stubs
unumba.cuda.types
T adim3
aCUDADispatcher
dim3
aCUDADispatcher
registry
lower_getattr
lower_attr
lower_constant
aModule
threadIdx
cuda_threadIdx
blockDim
cuda_blockDim
blockIdx
cuda_blockIdx
gridDim
cuda_gridDim
cuda_laneid
wxadim3_x
dim3_y
dim3_z
array_like
cuda_const_array_like
shared
array
aIntegerLiteral
cuda_shared_array_integer
cuda_shared_array_tuple
local
cuda_local_array_integer
ptx_lmem_alloc_array
threadfence_block
ptx_threadfence_block
threadfence_system
ptx_threadfence_system
threadfence
ptx_threadfence_device
syncwarp
ptx_syncwarp
i4
shfl_sync_intrinsic
f4
f8
ptx_shfl_sync_i32
vote_sync_intrinsic
ptx_vote_sync
match_any_sync
ptx_match_any_sync
match_all_sync
ptx_match_all_sync
activemask
ptx_activemask
lanemask_lt
ptx_lanemask_lt
popc
ptx_popc
ptx_fma
aFloat
float16_to_float_cast
float_to_float16_cast
aInteger
float16_to_integer_cast
integer_to_float16_cast
lower_fp16_binary
hadd
iadd
hsub
isub
hmul
imul
hneg
neg
operator_hneg
habs
abs
operator_habs
hfma
ptx_hfma
truediv
itruediv
fp16_div_impl
u{{
.reg .pred __$$f16_cmp_tmp;
setp.{op}.f16 __$$f16_cmp_tmp, $1, $2;
selp.u16 $0, 1, 0, __$$f16_cmp_tmp;
}}
heq
T aeq
eq
hne
T ane
ne
hge
T age
ge
hgt
T agt
gt
hle
T ale
le
hlt
T alt
lt
lower_fp16_minmax
hmax
hmin
a__nv_cbrtf
a__nv_cbrt
cbrt
ptx_cbrt
brev
u4
ptx_brev_u4
u8
ptx_brev_u8
clz
ptx_clz
ffs
ptx_ffs_32
ptx_ffs_64
selp
ptx_selp
ptx_max_f4
ptx_max_f8
ptx_min_f4
ptx_min_f8
ptx_round
round_to_impl
gen_deg_rad
pi
f
f@a_deg2rad
a_rad2deg
radians
degrees
atomic
ptx_atomic_add_tuple
ptx_atomic_sub
inc
ptx_atomic_inc
dec
ptx_atomic_dec
ptx_atomic_bitwise
and_
and
or
xor
exch
ptx_atomic_exch
ptx_atomic_max
ptx_atomic_min
nanmax
ptx_atomic_nanmax
nanmin
ptx_atomic_nanmin
compare_and_swap
ptx_atomic_compare_and_swap
cas
nanosleep
ptx_nanosleep
T Facuda_dispatcher_const
get_ufuncs
unumba\cuda\cudaimpl.py
u<module numba.cuda.cudaimpl>
T adispatch_fn
imp
T aop
ptx_fp16_comparison
T acontext
builder
shape
dtype
symbol_name
addrspace
can_dynsized
elemcount
dynamic_smem
data_model
other_supported_type
lldtype
laryty
dataptr
lmod
gvmem
align
targetdata
itemsize
laststride
rstrides
wialastsize
strides
kstrides
get_dynshared_size
dynsmem_size
kitemsize
kshape
ndim
aryty
ary
T acontext
builder
indty
inds
aryty
valty
indices
dtype
T acontext
builder
sig
args
T acontext
builder
ty
pyval
T acontext
builder
sig
args
length
dtype
T acontext
builder
sig
args
shape
dtype
T abitwidth
typemap
msg
T	acontext
builder
fromty
toty
val
ty
constraint
fnty
asm
T
context
builder
fromty
toty
val
bitwidth
constraint
signedness
fnty
asm
T wxwyT acontext
builder
sig
args
fp16_div
T aconst
impl
T acontext
builder
sig
args
aryty
indty
valty
ary
inds
val
dtype
indices
lary
ptr
dispatch_fn
T adispatch_fn
T acontext
builder
sig
args
argty
factor
const
T aconst
T acontext
builder
dtype
ptr
val
op
T abuilder
prefix
wxwywzT afn
op
ptx_fp16_binary
T afn
fname
op
ptx_fp16_minmax
T acontext
builder
sig
args
activemask
T acontext
builder
dtype
ptr
val
lmod
T astub
op
impl_ptx_atomic
ty
T acontext
builder
sig
args
aryty
indty
oldty
valty
ary
inds
old
val
indices
lary
ptr
lmod
bitwidth
T acontext
builder
dtype
ptr
val
bw
lmod
fn
T acontext
builder
dtype
ptr
val
T acontext
builder
sig
args
fn
T
context
builder
sig
args
ty
fname
fty
lmod
fnty
fn
T acontext
builder
sig
args
fnty
asm
op
T
context
builder
sig
args
fnty
asm
result
zero
int_result
op
T acontext
builder
sig
args
fnty
asm
T acontext
builder
sig
args
choice
op
T acontext
builder
sig
args
argtys
fnty
asm
T acontext
builder
sig
args
mask
value
width
fname
lmod
fnty
func
T acontext
builder
sig
args
nanosleep
ns
T acontext
builder
sig
args
test
wawbT acontext
builder
sig
args
mask
mode
value
index
clamp
value_type
fname
lmod
fnty
func
ret
rv
pred
fv
value1
value_lshr
value2
ret1
ret2
rv1
rv2
rv1_64
rv2_64
rv_shl
T acontext
builder
sig
args
mask
mask_sig
T acontext
builder
sig
args
fname
lmod
fnty
sync
T acontext
builder
sig
args
fname
lmod
fnty
func
T wxandigits
pow1
pow2
wywzT acontext
builder
sig
args
round_ndigits
.numba.cuda.cudamath
`
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
math
l
unumba.core
T atypes
types
unumba.core.typing.templates
T aConcreteTemplate
signature
aRegistry
aConcreteTemplate
signature
aRegistry
registry
register_global
infer_global
a__prepare__
aMath_unary
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
acos
acosh
asin
asinh
atan
atanh
cosh
degrees
erf
erfc
expm1
gamma
lgamma
log1p
radians
sinh
tanh
tan
