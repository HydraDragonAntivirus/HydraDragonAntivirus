# Reconstructed from integrated Nuitka blob
# Module: ullvmlite.ir.context

a__qualname__
a__init__
uContext.__init__
T Faget_identified_type
uContext.get_identified_type
a__orig_bases__
global_context
ullvmlite\ir\context.py
u<module llvmlite.ir.context>
T a__class__
T aself
T aself
name
packed
ty

.llvmlite.ir.instructions
*
aInstruction
a__init__
T aname
opname
operands
flags
metadata
parent
function
module
w u,
get_reference
type
a_stringify_metadata
T tT aleading_comma
append
u{0} {1} {2}{3}
ops
a_clear_string_cache
u<ir.%s %r of type '%s', opname %r, operands %r>
a__name__
name
aFunction
calling_convention
cconv
aTailMarkerOptions
tail

aFastMathFlags
fastmath
aCallInstrAttributes
attributes
arg_attributes
items
utoo many values to unpack (expected 2)
l
uInvalid argument index {}
aArgumentAttributes
self
function_type
args
func
types
aMetaDataType
aMetaDataArgument
arg
uType of #{0} arg mismatch: {1} != {2}
l aCallInstr
return_type
call
:l nnacallee
uNew function has incompatible type
descr_arg
uCallInstr._descr.<locals>.descr_arg
var_arg
u{0} {1}
u{0}
a_to_list
u{tail}{op}{fastmath} {callee}({args}){attr}{meta}
T atail
op
callee
fastmath
args
attr
meta
u{0} {1}{2}
a_descr
D aadd_metadata
taInvokeInstr
T atail
fastmath
attrs
arg_attrs
invoke
normal_to
unwind_to
D aadd_metadata
Fu      to label {0} unwind label {1}{metadata}
T ametadata
aTerminator
aVoidType
aMetaDataString
branch_weights
ubranch weight must be a positive integer
aConstant
aIntType
T l aadd_metadata
set_metadata
prof
aRet
return_value
u{0}{1}
aIndirectBranch
destinations
ulabel {0}
uindirectbr {0} {1}, [{2}]  {3}
address
aSwitchInstr
default
cases
aValue
value
u{0} {1}, label {2}
uswitch {0} {1}, label {2} [{3}]  {4}
aSelectInstr
select
T aname
flags
l uselect {0} {1} {2}, {3} {4}, {5} {6} {7}
cond
lhs
rhs
aVALID_OP
uinvalid comparison %r for %s
aOPNAME
aVALID_FLAG
uinvalid flag %r for %s
aVectorType
T l acount
aCompareInstr
T aflags
name
op
u{opname}{flags} {op} {ty} {lhs}, {rhs} {meta}
T aopname
flags
op
ty
lhs
rhs
meta
u<genexpr>
uCompareInstr.descr.<locals>.<genexpr>
aCastInstr
u{0} {1} {2} to {3} {4}
aAllocaInstr
allocated_type
is_opaque
pointee
uLoad lacks type.
aLoadInstr
load
ptr
align
utoo many values to unpack (expected 1)
u, align %d
uload {0}, {1} {2}{3}{4}
aStoreInstr
store
ustore {0} {1}, {2} {3}{4}{5}
uLoad atomic lacks type.
aLoadAtomicInstr
uload atomic
ordering
uload atomic {0}, {1} {2} {3}, align {4}{5}
aStoreAtomicInstr
ustore atomic
ustore atomic {0} {1}, {2} {3} {4}, align {5}{6}
as_pointer
alloca
u, {0} {1}
u, align {0}
source_etype
typ
gep
aPointerType
addrspace
lasttyp
lastaddrspace
uGEP lacks type.
aGEPInstr
getelementptr
pointer
indices
inbounds
ugetelementptr inbounds
u{0} {1}, {2} {3}, {4} {5}
aPhiInstr
phi
incomings
uphi {0} {1} {2} {3}
u[{0}, {1}]
uPhiInstr.descr.<locals>.<genexpr>
uvector needs to be of VectorType.
uindex needs to be of IntType.
element
aExtractElement
extractelement
u{opname} {operands}
T aopname
operands
uExtractElement.descr.<locals>.<genexpr>
uvalue needs to be of type {} not {}.
aInsertElement
insertelement
uInsertElement.descr.<locals>.<genexpr>
uvector1 needs to be of VectorType.
aUndefined
uvector2 needs to be Undefined or of the same type as vector1.
width
l umask needs to be a constant i32 vector.
constant
umask values need to be in {0}
aShuffleVector
shufflevector
index_range
uShuffleVector.__init__.<locals>.<genexpr>
ushufflevector {0} {1}
uShuffleVector.descr.<locals>.<genexpr>
elements
T EAttributeError
EIndexError
uCan't index at %r in %s
aExtractValue
extractvalue
aggregate
uextractvalue {0} {1}, {2} {3}
uCan only insert %s at %r in %s: got %s
aInsertValue
insertvalue
uinsertvalue {0} {1}, {2} {3}, {4} {5}
aUnreachable
unreachable
D aname

w
asm
constraint
side_effect
sideeffect
uasm {sideeffect} "{asm}", "{constraint}"
T asideeffect
asm
constraint
descr
aAtomicRMW
atomicrmw
operation
uatomicrmw {op} {ptrty} {ptr}, {valty} {val} {ordering} {metadata}
T aop
ptrty
ptr
valty
val
ordering
metadata
aLiteralStructType
aCmpXchg
cmpxchg
failordering
utoo many values to unpack (expected 3)
ucmpxchg {ptrty} {ptr}, {ty} {cmp}, {ty} {val} {ordering} {failordering} {metadata}
T aptrty
ptr
ty
cmp
val
ordering
failordering
metadata
u{kind} {type} {value}
kind
T akind
type
value
aFilterClause
aLandingPadInstr
landingpad
cleanup
clauses
ulandingpad {type}{cleanup}{clauses}
u cleanup

{0}
T atype
cleanup
clauses
aFence
fence
aVALID_FENCE_ORDERINGS
uInvalid fence ordering "{0}"! Should be one of {1}.
targetscope
usyncscope("{0}")
ufence {syncscope}{ordering}
T asyncscope
ordering
aComment
w;atext
u;
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
ullvmlite.ir
T atypes
ullvmlite.ir.values
T
aBlock
aFunction
aValue
aNamedValue
aConstant
aMetaDataArgument
aMetaDataString
aAttributeSet
aUndefined
aArgumentAttributes
aBlock
aNamedValue
aAttributeSet
ullvmlite.ir._utils
T a_HasMetadata
a_HasMetadata
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
