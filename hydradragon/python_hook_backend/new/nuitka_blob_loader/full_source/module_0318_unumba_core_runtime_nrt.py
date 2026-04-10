# Reconstructed from integrated Nuitka blob
# Module: unumba.core.runtime.nrt

a__qualname__
a__init__
u_Runtime.__init__
initialize
u_Runtime.initialize
u_Runtime._init_guard
staticmethod
shutdown
u_Runtime.shutdown
property
library
u_Runtime.library
u_Runtime.meminfo_new
T Fu_Runtime.meminfo_alloc
get_allocation_stats
u_Runtime.get_allocation_stats
a__orig_bases__
a_MemInfo
register
typeof_meminfo
memsys_use_cpython_allocator
rtsys
unumba\core\runtime\nrt.py
u<module numba.core.runtime.nrt>
T a__class__
T aself
T aself
msg
T aself
ctx
py_name
c_name
c_address
T aself
size
safe
msg
mi
T aself
data
pyobj
mi
T aval
wc.numba.core.runtime.nrtdynmod
t
cgutils
get_or_insert_function
meminfo_data_ty
aNRT_MemInfo_data_fast
ir
aIRBuilder
append_basic_block
args
utoo many values to unpack (expected 1)
bitcast
a_meminfo_struct_type
as_pointer
load
gep
l
l aret
incref_decref_ty
aNRT_incref
attributes
add
T anoinline
icmp_unsigned
u==
get_null_value
type
if_unlikely
a__enter__
a__exit__
ret_void
T nnnaconfig
aDEBUG_NRT
printf
u*** NRT_Incref %zu [%p]
call
aNRT_decref
aFunction
aFunctionType
aVoidType
a_pointer_type
D aname
aNRT_MemInfo_call_dtor
fence
T arelease
u*** NRT_Decref %zu [%p]
aConstant
T aacquire
a_word_type
unrt_atomic_{0}
T aname
l a_disable_atomicity
atomic_rmw
T aordering
store
aIntType
T l D aname
nrt_atomic_cas
utoo many values to unpack (expected 4)
cmpxchg
unpack_tuple
l utoo many values to unpack (expected 2)
zext
return_type
call_conv
get_function_type
types
none
D aname
nrt_unresolved_abort
return_user_exc
T unumba jitted function aborted due to unresolved symbol
codegen
create_library
T anrt
create_ir_module
T anrt_module
a_define_atomic_inc_dec
D aordering
monotonic
sub
a_define_atomic_cas
a_define_nrt_meminfo_data
a_define_nrt_incref
a_define_nrt_decref
a_define_nrt_unresolved_abort
create_nrt_module
add_ir_module
finalize
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
unumba.core
T aconfig
T atypes
cgutils
llvmlite
T air
binding
binding
aMACHINE_BITS
aPointerType
T l aLiteralStructType
compile_nrt_functions
unumba\core\runtime\nrtdynmod.py
u<module numba.core.runtime.nrtdynmod>
Tamodule
ordering
ftype
fn_cas
ptr
cmp
repl
oldptr
bb
builder
outtup
old
ok
T amodule
op
ordering
ftype
fn_atomic
ptr
bb
builder
aONE
oldval
res
newval
T
module
atomic_decr
fn_decref
calldtor
builder
ptr
is_null
word_ptr
newrefct
refct_eq_0
T amodule
atomic_incr
fn_incref
builder
ptr
is_null
word_ptr
T amodule
fn
builder
ptr
struct_ptr
data_ptr
T actx
module
fnty
fn
bb
builder
msg
T actx
ir_mod
library
T actx
codegen
library
ir_mod
atomic_inc
atomic_dec

.numba.core.runtime.nrtopt
;
`
a_extract_functions
u_remove_redundant_nrt_refct.<locals>._extract_functions
a_process_function
u_remove_redundant_nrt_refct.<locals>._process_function
a_extract_basic_blocks
u_remove_redundant_nrt_refct.<locals>._extract_basic_blocks
a_process_basic_block
u_remove_redundant_nrt_refct.<locals>._process_basic_block
a_examine_refct_op
u_remove_redundant_nrt_refct.<locals>._examine_refct_op
a_prune_redundant_refct_ops
u_remove_redundant_nrt_refct.<locals>._prune_redundant_refct_ops
a_move_and_group_decref_after_all_increfs
u_remove_redundant_nrt_refct.<locals>._move_and_group_decref_after_all_increfs
utoo many values to unpack (expected 2)
processed
w
module
splitlines
startswith
T adefine
cur
T w}aout
func_lines
l
:l q na_regex_bb
match
q abb_lines
a_regex_incref
group
T l a_regex_decref
defaultdict
deque
utoo many values to unpack (expected 3)
ui8* null
to_remove
add
append
items
min
incops
pop
decops
popleft
l amax
last_incref_pos
last_decref_pos
decrefs
head
get_function
T aNRT_incref
name
a_remove_redundant_nrt_refct
all
parse_assembly
cgutils
normalize_ir_text
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
re
collections
T adefaultdict
deque
llvmlite
T abinding
binding
unumba.core
T acgutils
compile
T u\s*(?:tail)?\s*call void @NRT_incref\((.*)\)
T u\s*(?:tail)?\s*call void @NRT_decref\((.*)\)
T u[0-9]+:|[\'"]?[-a-zA-Z$._0-9][-a-zA-Z$._0-9]*[\'"]?:|^define|^;\s*<label>
remove_redundant_nrt_refct
unumba\core\runtime\nrtopt.py
u<module numba.core.runtime.nrtopt>
T abb_lines
num
ln
wmT afunc_lines
cur
ln
wmT amodule
cur
line
T abb_lines
last_incref_pos
pos
ln
last_decref_pos
last_pos
decrefs
head
T abb_lines
a_move_and_group_decref_after_all_increfs
a_prune_redundant_refct_ops
T a_move_and_group_decref_after_all_increfs
a_prune_redundant_refct_ops
T afunc_lines
out
is_bb
bb_lines
a_extract_basic_blocks
a_process_basic_block
T a_extract_basic_blocks
a_process_basic_block
Tabb_lines
incref_map
decref_map
to_remove
num
incref_var
decref_var
var
decops
incops
ct
w_a_examine_refct_op
T a_examine_refct_op
T allvmir
a_extract_functions
a_process_function
a_extract_basic_blocks
a_process_basic_block
a_examine_refct_op
a_prune_redundant_refct_ops
a_move_and_group_decref_after_all_increfs
processed
is_func
lines
T all_module
name
newll
new_mod

.numba.core.serialize
w
a_rebuild
a_unpickled_memo
cloudpickle
loads
aNumbaPickler
aBytesIO
a__enter__
a__exit__
D aprotocol
l adump
getvalue
T nnnapickled
utoo many values to unpack (expected 3)
ir
aValue
real_args
ctor
states
a_CustomPickled
utoo many values to unpack (expected 2)
dumps
a_unpickle__CustomPickled
custom_rebuild
pickle
aPicklingError
uPickling of

u is unsupported
disabled_types
add
a_no_pickle
a__class__
reducer_override
a_reduce
custom_reduce
a_reduce_class
a_reduce_states
