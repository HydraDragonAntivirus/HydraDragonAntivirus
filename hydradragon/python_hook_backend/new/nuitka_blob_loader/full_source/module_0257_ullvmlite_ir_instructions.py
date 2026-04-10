# Reconstructed from integrated Nuitka blob
# Module: ullvmlite.ir.instructions

a__qualname__
T u
T
uInstruction.__init__
property
uInstruction.function
uInstruction.module
uInstruction.descr
replace_usage
uInstruction.replace_usage
a__repr__
uInstruction.__repr__
a__orig_bases__
frozenset
L aconvergent
noreturn
nounwind
readonly
readnone
noinline
alwaysinline
P anounwind
alwaysinline
convergent
readonly
readnone
noinline
noreturn
a_known
P atail
musttail
notail
L afast
nnan
ninf
nsz
arcp
contract
afn
reassoc
P ansz
reassoc
nnan
afn
fast
contract
arcp
ninf
T u
nnT
pnuCallInstr.__init__
uCallInstr.callee
setter
uCallInstr.args
replace_callee
uCallInstr.replace_callee
called_function
uCallInstr.called_function
uCallInstr._descr
uCallInstr.descr
T u
nT
pnuInvokeInstr.__init__
uInvokeInstr.descr
uTerminator.__init__
uTerminator.descr
aPredictableInstr
set_weights
uPredictableInstr.set_weights
T nuRet.__init__
uRet.return_value
uRet.descr
aBranch
aConditionalBranch
uIndirectBranch.__init__
uIndirectBranch.address
add_destination
uIndirectBranch.add_destination
uIndirectBranch.descr
uSwitchInstr.__init__
uSwitchInstr.value
add_case
uSwitchInstr.add_case
uSwitchInstr.descr
aResume
uSelectInstr.__init__
uSelectInstr.cond
uSelectInstr.lhs
uSelectInstr.rhs
uSelectInstr.descr
uinvalid-compare
uCompareInstr.__init__
uCompareInstr.descr
aICMPInstr
icmp
D
eq
ne
ugt
uge
ult
ule
sgt
sge
slt
sle
equal
unot equal
uunsigned greater than
uunsigned greater or equal
uunsigned less than
uunsigned less or equal
usigned greater than
usigned greater or equal
usigned less than
usigned less or equal
set
aFCMPInstr
fcmp
D afalse
oeq
ogt
oge
olt
ole
one
ord
ueq
ugt
uge
ult
ule
une
uno
true
uno comparison, always returns false
uordered and equal
uordered and greater than
uordered and greater than or equal
uordered and less than
uordered and less than or equal
uordered and not equal
uordered (no nans)
uunordered or equal
uunordered or greater than
uunordered or greater than or equal
uunordered or less than
uunordered or less than or equal
uunordered or not equal
uunordered (either nans)
uno comparison, always returns true
S ansz
reassoc
nnan
afn
fast
contract
arcp
ninf
T u
uCastInstr.__init__
uCastInstr.descr
T u
nuLoadInstr.__init__
uLoadInstr.descr
uStoreInstr.__init__
uStoreInstr.descr
uLoadAtomicInstr.__init__
uLoadAtomicInstr.descr
uStoreAtomicInstr.__init__
uStoreAtomicInstr.descr
uAllocaInstr.__init__
uAllocaInstr.descr
uGEPInstr.__init__
uGEPInstr.descr
T T
uPhiInstr.__init__
uPhiInstr.descr
add_incoming
uPhiInstr.add_incoming
uPhiInstr.replace_usage
uExtractElement.__init__
uExtractElement.descr
uInsertElement.__init__
uInsertElement.descr
uShuffleVector.__init__
uShuffleVector.descr
uExtractValue.__init__
uExtractValue.descr
uInsertValue.__init__
uInsertValue.descr
uUnreachable.__init__
uUnreachable.descr
T Oobject
aInlineAsm
T FuInlineAsm.__init__
uInlineAsm.descr
uInlineAsm.get_reference
a__str__
uInlineAsm.__str__
uAtomicRMW.__init__
uAtomicRMW.descr
uCmpXchg.__init__
uCmpXchg.descr
a_LandingPadClause
u_LandingPadClause.__init__
u_LandingPadClause.__str__
aCatchClause
catch
filter
uFilterClause.__init__
T u
FuLandingPadInstr.__init__
add_clause
uLandingPadInstr.add_clause
uLandingPadInstr.descr
S arelease
acquire
acq_rel
seq_cst
T nu
uFence.__init__
uFence.descr
uComment.__init__
uComment.descr
ullvmlite\ir\instructions.py
T a.0
it
T a.0
op
T a.0
wvwbT a.0
ii
index_range
T a__class__
u<module llvmlite.ir.instructions>
T aself
parent
typ
count
name
operands
a__class__
T aself
parent
op
ptr
val
ordering
name
a__class__
T aself
parent
func
args
name
cconv
tail
fastmath
attrs
arg_attrs
idx
wiaarg
expected_type
msg
a__class__
T aself
parent
op
val
typ
name
a__class__
T
self
parent
ptr
cmp
val
ordering
failordering
name
outtype
a__class__
T aself
parent
text
a__class__
T aself
parent
op
lhs
rhs
name
flags
flag
opname
typ
a__class__
T aself
parent
vector
index
name
typ
a__class__
T aself
parent
agg
indices
name
typ
wia__class__
T aself
parent
ordering
targetscope
name
msg
a__class__
T aself
value
a__class__
T aself
parent
ptr
indices
inbounds
name
source_etype
typ
lasttyp
lastaddrspace
wia__class__
T aself
parent
opname
addr
a__class__
T aself
ftype
asm
constraint
side_effect
T aself
parent
vector
value
index
name
typ
a__class__
T	aself
parent
agg
elem
indices
name
typ
wia__class__
T aself
parent
typ
opname
operands
name
flags
a__class__
T aself
parent
func
args
normal_to
unwind_to
name
cconv
fastmath
attrs
arg_attrs
a__class__
T aself
parent
typ
name
cleanup
a__class__
T aself
parent
ptr
ordering
align
name
typ
a__class__
T aself
parent
ptr
name
typ
a__class__
T aself
parent
typ
name
flags
a__class__
T aself
parent
opname
return_value
operands
a__class__
T aself
parent
cond
lhs
rhs
name
flags
a__class__
T	aself
parent
vector1
vector2
mask
name
typ
index_range
a__class__
T aself
parent
val
ptr
ordering
align
a__class__
T aself
parent
val
ptr
a__class__
T aself
parent
opname
val
default
a__class__
T aself
parent
opname
operands
a__class__
T aself
parent
a__class__
T aself
value
T aself
T aself
buf
add_metadata
descr_arg
args
fnty
ty
callee_ref
tail_marker
fn_attrs
fm_attrs
T aself
val
block
T aself
clause
T aself
block
T aself
value
block
T aself
newcallee
T aself
buf
op
T aself
buf
ptr
val
fmt
T aself
buf
T aself
buf
ptr
cmpval
val
fmt
T aself
buf
operands
T aself
buf
indices
T aself
buf
syncscope
fmt
T aself
buf
indices
op
T aself
buf
destinations
T aself
buf
sideeffect
fmt
T aself
buf
opname
operands
typ
metadata
T aself
buf
a__class__
T aself
buf
fmt
T aself
buf
val
T aself
buf
val
align
T aself
buf
incs
T aself
buf
return_value
metadata
T aself
buf
val
ptr
T aself
buf
val
ptr
align
T aself
buf
cases
T aself
buf
opname
operands
metadata
T wiwaaattrs
self
T aself
newfunc
T aself
old
new
ops
op
T aself
old
new
T aself
weights
operands
wwamd
.llvmlite.ir.module
context
name

data_layout
a_utils
aNameScope
scope
uunknown-unknown-unknown
triple
collections
aOrderedDict
globals
metadata
namedmetadata
a_metadatacache
types
aMetaDataType
T navalues
aMetaDataString
self
T Olist
Otuple
add_metadata
fixed_ops
utoo many values to unpack (expected 2)
encoding
aDIToken
value
str_ops
uexpected a list or tuple of metadata values, got %r
a_fix_metadata_operands
aMDValue
T aname
md
sorted
a_fix_di_operands
items
str_ditok_operands
aDIValue
di
aNamedMetaData
aValue
type
uwrong type for metadata element: got %r
add
aFunction
deduplicate
a_error
uModule.declare_intrinsic.<locals>._error
P ullvm.fma
ullvm.cttz
ullvm.ctlz
l
intrinsic_name
w.aintrinsic
tys
ullvm.assume
aFunctionType
aVoidType
aIntType
T l ullvm.powi
T l ullvm.pow
l ullvm.convert.from.fp16
T l ullvm.convert.to.fp16
ullvm.memset
T l l P ullvm.cttz
ullvm.ctlz
T ullvm.memcpy
ullvm.memmove
ullvm.fma
l uunknown intrinsic %r with %d types
identified_types
get_identified_types
get_declaration
mdbuf
u!{name} = !{{ {operands} }}
u,
operands
T aname
operands
get_reference
u<genexpr>
uModule._get_metadata_lines.<locals>.<genexpr>
w
a_get_body_lines
a_get_metadata_lines
u; ModuleID = "%s"
utarget triple = "%s"
utarget datalayout = "%s"
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
ullvmlite.ir
T acontext
values
types
a_utils
T Oobject
a__prepare__
aModule
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
