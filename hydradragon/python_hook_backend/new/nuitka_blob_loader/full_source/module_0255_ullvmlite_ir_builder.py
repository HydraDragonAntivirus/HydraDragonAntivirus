# Reconstructed from integrated Nuitka blob
# Module: ullvmlite.ir.builder

a__qualname__
T na__init__
uIRBuilder.__init__
property
uIRBuilder.block
uIRBuilder.function
uIRBuilder.module
uIRBuilder.position_before
position_after
uIRBuilder.position_after
position_at_start
uIRBuilder.position_at_start
uIRBuilder.position_at_end
uIRBuilder.append_basic_block
remove
uIRBuilder.remove
contextmanager
uIRBuilder._insert
uIRBuilder._set_terminator
T ashl
shl
uIRBuilder.shl
T alshr
lshr
uIRBuilder.lshr
T aashr
ashr
uIRBuilder.ashr
T aadd
add
uIRBuilder.add
T afadd
fadd
uIRBuilder.fadd
T asub
uIRBuilder.sub
T afsub
fsub
uIRBuilder.fsub
T amul
mul
uIRBuilder.mul
T afmul
fmul
uIRBuilder.fmul
T audiv
udiv
uIRBuilder.udiv
T asdiv
sdiv
uIRBuilder.sdiv
T afdiv
fdiv
uIRBuilder.fdiv
T aurem
urem
uIRBuilder.urem
T asrem
srem
uIRBuilder.srem
T afrem
frem
uIRBuilder.frem
T aor
or_
uIRBuilder.or_
T aand
and_
uIRBuilder.and_
T axor
uIRBuilder.xor
T asadd
sadd_with_overflow
uIRBuilder.sadd_with_overflow
T asmul
smul_with_overflow
uIRBuilder.smul_with_overflow
T assub
ssub_with_overflow
uIRBuilder.ssub_with_overflow
T auadd
uadd_with_overflow
uIRBuilder.uadd_with_overflow
T aumul
umul_with_overflow
uIRBuilder.umul_with_overflow
T ausub
usub_with_overflow
uIRBuilder.usub_with_overflow
not_
uIRBuilder.not_
neg
uIRBuilder.neg
T afneg
fneg
uIRBuilder.fneg
uIRBuilder._icmp
icmp_signed
uIRBuilder.icmp_signed
icmp_unsigned
uIRBuilder.icmp_unsigned
fcmp_ordered
uIRBuilder.fcmp_ordered
fcmp_unordered
uIRBuilder.fcmp_unordered
select
uIRBuilder.select
T atrunc
trunc
uIRBuilder.trunc
T azext
zext
uIRBuilder.zext
T asext
sext
uIRBuilder.sext
T afptrunc
fptrunc
uIRBuilder.fptrunc
T afpext
fpext
uIRBuilder.fpext
T abitcast
bitcast
uIRBuilder.bitcast
T aaddrspacecast
addrspacecast
uIRBuilder.addrspacecast
T afptoui
fptoui
uIRBuilder.fptoui
T auitofp
uitofp
uIRBuilder.uitofp
T afptosi
fptosi
uIRBuilder.fptosi
T asitofp
sitofp
uIRBuilder.sitofp
T aptrtoint
ptrtoint
uIRBuilder.ptrtoint
T ainttoptr
inttoptr
uIRBuilder.inttoptr
T nu
alloca
uIRBuilder.alloca
T u
nnaload
uIRBuilder.load
store
uIRBuilder.store
T u
naload_atomic
uIRBuilder.load_atomic
store_atomic
uIRBuilder.store_atomic
uIRBuilder.switch
uIRBuilder.branch
uIRBuilder.cbranch
branch_indirect
uIRBuilder.branch_indirect
ret_void
uIRBuilder.ret_void
uIRBuilder.ret
uIRBuilder.resume
T u
nFT
pnuIRBuilder.call
uIRBuilder.asm
load_reg
uIRBuilder.load_reg
store_reg
uIRBuilder.store_reg
T u
nT
pnainvoke
uIRBuilder.invoke
T Fu
nagep
uIRBuilder.gep
extract_element
uIRBuilder.extract_element
insert_element
uIRBuilder.insert_element
shuffle_vector
uIRBuilder.shuffle_vector
extract_value
uIRBuilder.extract_value
insert_value
uIRBuilder.insert_value
phi
uIRBuilder.phi
unreachable
uIRBuilder.unreachable
atomic_rmw
uIRBuilder.atomic_rmw
cmpxchg
uIRBuilder.cmpxchg
T u
Falandingpad
uIRBuilder.landingpad
assume
uIRBuilder.assume
fence
uIRBuilder.fence
comment
uIRBuilder.comment
T ullvm.bswap
bswap
uIRBuilder.bswap
T ullvm.bitreverse
bitreverse
uIRBuilder.bitreverse
T ullvm.ctpop
ctpop
uIRBuilder.ctpop
T ullvm.ctlz
ctlz
uIRBuilder.ctlz
T ullvm.cttz
cttz
uIRBuilder.cttz
T ullvm.fma
fma
uIRBuilder.fma
convert_from_fp16
uIRBuilder.convert_from_fp16
T ullvm.convert.to.fp16
convert_to_fp16
uIRBuilder.convert_to_fp16
a__orig_bases__
ullvmlite\ir\builder.py
u<module llvmlite.ir.builder>
T a__class__
T aself
block
T aopname
cls
wrap
T aself
bbenter
bbexit
T aself
prefix
cmpop
lhs
rhs
name
op
instr
T aself
instr
T alabel
suffix
nhead
T aself
term
T aopname
wrap
T aself
lhs
rhs
name
T aself
value
typ
name
T aself
typ
size
name
al
T aself
name
T aself
ftype
asm
constraint
args
side_effect
name
T aself
cond
fn
T aself
op
ptr
val
ordering
name
inst
T aself
cond
T aself
T aself
target
br
T aself
addr
br
T
self
fn
args
name
cconv
tail
fastmath
attrs
arg_attrs
inst
T aself
cond
truebr
falsebr
br
T aself
ptr
cmp
val
ordering
failordering
name
inst
T aself
text
inst
T aself
waato
name
opname
fn
T aself
waT aself
cond
flag
T aself
vector
idx
name
instr
T aself
agg
idx
name
instr
T aself
cmpop
lhs
rhs
name
flags
op
instr
T aself
ordering
targetscope
name
inst
T aself
wawbwcT aself
arg
name
flags
T aself
ptr
indices
inbounds
name
source_etype
instr
T aself
block
old_block
term
T aself
cmpop
lhs
rhs
name
T
self
pred
likely
bb
bbif
bbelse
bbend
br
then
otherwise
T aself
pred
likely
bb
bbif
bbend
br
T aself
vector
value
idx
name
instr
T aself
agg
value
idx
name
instr
T aself
fn
args
normal_to
unwind_to
name
cconv
fastmath
attrs
arg_attrs
inst
T aself
typ
name
cleanup
inst
T aself
ptr
name
align
typ
msg
ld
T aself
ptr
ordering
align
name
typ
msg
ld
T aself
reg_type
reg_name
name
ftype
T aself
value
name
T aself
value
name
rhs
T aself
typ
name
flags
inst
T aself
instr
idx
T aself
landingpad
br
T aself
value
T aself
cond
lhs
rhs
name
flags
instr
T aself
vector1
vector2
mask
name
instr
T aself
value
ptr
align
msg
ast
T aself
value
ptr
ordering
align
msg
ast
T aself
value
reg_type
reg_name
name
ftype
T aself
value
default
swt
T aself
inst
T afn
wrapped
T acls
opname
T aopname
T aself
lhs
rhs
name
flags
instr
cls
opname
T aself
lhs
rhs
name
ty
bool_ty
mod
fnty
fn
ret
opname
T aself
val
typ
name
instr
cls
opname
T aself
wawbwcaname
fn
opname
T aself
operand
name
instr
cls
opname
T aself
operand
name
fn
opname
T aself
operand
flag
name
fn
opname
T aself
arg
name
flags
instr
cls
opname
.llvmlite.ir
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_llvmlite
u\not_existing
ir
T aNUITKA_PACKAGE_llvmlite_ir
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
types
T w*l avalues
module
builder
instructions
transforms
context
T aContext
global_context
aContext
l
global_context
ullvmlite\ir\__init__.py
u<module llvmlite.ir>

.llvmlite.ir.context
6
)
a_utils
aNameScope
scope
identified_types
register
types
aIdentifiedStructType
ty
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
ullvmlite.ir
T a_utils
l
T atypes
T Oobject
a__prepare__
aContext
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
