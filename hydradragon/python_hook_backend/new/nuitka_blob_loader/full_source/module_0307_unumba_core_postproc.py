# Reconstructed from integrated Nuitka blob
# Module: unumba.core.postproc

a__qualname__
a__init__
uYieldPoint.__init__
a__orig_bases__
uGeneratorInfo.__init__
uGeneratorInfo.get_yield_points
uVariableLifetime.__init__
uVariableLifetime.cfg
uVariableLifetime.usedefs
uVariableLifetime.livemap
uVariableLifetime.deadmaps
aPostProcessor
uPostProcessor.__init__
T Fparun
uPostProcessor.run
uPostProcessor._populate_generator_info
uPostProcessor._compute_generator_info
T FuPostProcessor._insert_var_dels
uPostProcessor._patch_var_dels
uPostProcessor.remove_dels
unumba\core\postproc.py
T a.0
wvu<module numba.core.postproc>
T a__class__
T aself
T aself
func_ir
T aself
blocks
T aself
block
inst
T	aself
gi
yp
live_vars
weak_live_vars
stmts
stmt
name
ast
T aself
extend_lifetimes
vlt
T aself
internal_dead_map
escaping_dead_map
extend_lifetimes
offset
ir_block
internal_dead_set
delete_pts
stmt
live_set
dead_set
wTadef_func
done_dels
body
lastloc
del_store
delete_set
var_name
delnode
escape_dead_set
T aself
dct
block
inst
yieldinst
index
yp
T aself
emit_dels
extend_lifetimes
vlt
bev
offset
ir_block

.numba.core.pylowering
\
a_frozen_strings
a_live_vars
aPyLower
pre_lower
init_pyapi
init_vars
ir
aAssign
lower_assign
storevar
target
name
aSetItem
loadvar
index
value
pyapi
object_setitem
check_int_status
aDelItem
object_delitem
aSetAttr
object_setattr
a_freeze_string
attr
aDelAttr
object_delattr
aStoreMap
dct
key
dict_setitem
aReturn
generator_info
decref
genlower
return_from_generator
call_conv
return_value
builder
aBranch
cond
type
llvmlite
aIntType
T l aobject_istrue
aConstant
icmp_unsigned
u!=
blkmap
truebr
falsebr
cbranch
aJump
branch
aDel
delvar
aPopBlock
aRaise
exception
incref
raise_object
exc
return_exception_raised

u,
aNumbaNotImplementedError
unumba.core.dispatcher
T aOmittedArg
l
aOmittedArg
unserialize
serialize_object
aConst
aFreeVar
lower_const
aVar
aExpr
lower_expr
aGlobal
lower_global
aYield
lower_yield
aArg
func_ir
func_id
pysig
parameters
get
fnargs
cgutils
alloca_once_value
default
inspect
aParameter
empty
store
get_type
u==
a_omitted_typobj
if_else
D alikely
Fa__enter__
a__exit__
utoo many values to unpack (expected 2)
T nnnaobject_getattr_string
load
slot
yield_points
init_generator_state
generators
aLowerYield
live_vars
weak_live_vars
lower_yield_suspend
lower_yield_resume
make_none
lhs
rhs
aPYTHON_BINOPMAP
T ainplace
aPYTHON_COMPAREOPMAP
fn
in
object_richcompare
check_error
op
binop
lower_binop
D ainplace
Fainplace_binop
D ainplace
taunary
operator
neg
number_negative
pos
number_positive
not_
object_not
bool_from_bool
invert
number_invert
call
args
self
func
tuple_pack
vararg
sequence_tuple
sequence_concat
kws
dict_pack
getattr
object_getattr
build_tuple
items
build_list
list_pack
build_map
dict_new
size
res
build_set
set_new
set_add
getiter
object_getiter
iternext
iter_next
is_not_null
tuple_new
T l atuple_setitem
check_occurred
l apair_first
tuple_getitem
pair_second
exhaust_iter
tuple_size
context
get_constant
types
intp
count
if_unlikely
return_exception
T EValueError
getitem
object_getitem
static_getitem
long_from_ssize_t
getslice
start
stop
get_builtin_obj
T aslice
call_function_objargs
cast
phi
aLoweringError
T uPHI not stripped
null
get_null_value
pyobj
undef
a_UNDEFINED
env_manager
add_const
read_const
get_module_dict
dict_getitem
a_unsupported_builtins
aForbiddenConstruct
ubuiltins %s() is not supported
loc
T aloc
is_null
basic_block
if_then
T a__builtins__
builtin_lookup
add_incoming
builtin
bbif
raise_missing_global_error
retval
env_body
globals
frommod
bbifmod
err_occurred
icmp_signed
w<acleanup_vars
return_exc
get_block_entry_vars
varmap
alloca
T altype
raise_missing_name_error
remove
a_getvar
pointee
add
old
get_value_type
pyobject
goto_block
entry_block
T aname
ptr
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
builtins
cached_property
ullvmlite.ir
unumba.core
T atypes
utils
ir
generators
cgutils
utils
unumba.core.errors
T aForbiddenConstruct
aLoweringError
aNumbaNotImplementedError
unumba.core.lowering
T aBaseLower
aBaseLower
S Olocals
