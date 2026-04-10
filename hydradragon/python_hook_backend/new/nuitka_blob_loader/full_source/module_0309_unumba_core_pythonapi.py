# Reconstructed from integrated Nuitka blob
# Module: unumba.core.pythonapi

a__qualname__
a__init__
u_Registry.__init__
register
u_Registry.register
u_Registry.lookup
a__orig_bases__
box
unbox
reflect
T a_BoxContext
T acontext
builder
pyapi
env_manager
a__slots__
u_BoxContext.box
T a_UnboxContext
T acontext
builder
pyapi
u_UnboxContext.unbox
T a_ReflectContext
T acontext
builder
pyapi
env_manager
is_error
set_error
u_ReflectContext.set_error
u_ReflectContext.box
u_ReflectContext.reflect
T nnuNativeValue.__init__
uEnvironmentManager.__init__
uEnvironmentManager.add_const
uEnvironmentManager.read_const
T a_IteratorLoop
T avalue
do_break
aPythonAPI
uPythonAPI.__init__
get_env_manager
uPythonAPI.get_env_manager
T Fu
emit_environment_sentry
uPythonAPI.emit_environment_sentry
uPythonAPI.incref
uPythonAPI.decref
get_type
uPythonAPI.get_type
parse_tuple_and_keywords
uPythonAPI.parse_tuple_and_keywords
parse_tuple
uPythonAPI.parse_tuple
unpack_tuple
uPythonAPI.unpack_tuple
uPythonAPI.err_occurred
err_clear
uPythonAPI.err_clear
uPythonAPI.err_set_string
err_format
uPythonAPI.err_format
raise_object
uPythonAPI.raise_object
err_set_object
uPythonAPI.err_set_object
err_set_none
uPythonAPI.err_set_none
err_write_unraisable
uPythonAPI.err_write_unraisable
uPythonAPI.err_fetch
uPythonAPI.err_restore
contextmanager
T FuPythonAPI.get_c_object
raise_missing_global_error
uPythonAPI.raise_missing_global_error
raise_missing_name_error
uPythonAPI.raise_missing_name_error
fatal_error
uPythonAPI.fatal_error
dict_getitem_string
uPythonAPI.dict_getitem_string
dict_getitem
uPythonAPI.dict_getitem
uPythonAPI.dict_new
dict_setitem
uPythonAPI.dict_setitem
uPythonAPI.dict_setitem_string
dict_pack
uPythonAPI.dict_pack
float_from_double
uPythonAPI.float_from_double
number_as_ssize_t
uPythonAPI.number_as_ssize_t
number_long
uPythonAPI.number_long
long_as_ulonglong
uPythonAPI.long_as_ulonglong
long_as_longlong
uPythonAPI.long_as_longlong
long_as_voidptr
uPythonAPI.long_as_voidptr
uPythonAPI._long_from_native_int
uPythonAPI.long_from_long
uPythonAPI.long_from_ulong
long_from_ssize_t
uPythonAPI.long_from_ssize_t
uPythonAPI.long_from_longlong
uPythonAPI.long_from_ulonglong
long_from_signed_int
uPythonAPI.long_from_signed_int
long_from_unsigned_int
uPythonAPI.long_from_unsigned_int
uPythonAPI._get_number_operator
uPythonAPI._call_number_operator
number_add
uPythonAPI.number_add
number_subtract
uPythonAPI.number_subtract
number_multiply
uPythonAPI.number_multiply
number_truedivide
uPythonAPI.number_truedivide
number_floordivide
uPythonAPI.number_floordivide
number_remainder
uPythonAPI.number_remainder
number_matrix_multiply
uPythonAPI.number_matrix_multiply
number_lshift
uPythonAPI.number_lshift
number_rshift
uPythonAPI.number_rshift
number_and
uPythonAPI.number_and
number_or
uPythonAPI.number_or
number_xor
uPythonAPI.number_xor
number_power
uPythonAPI.number_power
number_negative
uPythonAPI.number_negative
number_positive
uPythonAPI.number_positive
number_float
uPythonAPI.number_float
number_invert
uPythonAPI.number_invert
float_as_double
uPythonAPI.float_as_double
uPythonAPI.bool_from_bool
uPythonAPI.bool_from_long
complex_from_doubles
uPythonAPI.complex_from_doubles
complex_real_as_double
uPythonAPI.complex_real_as_double
complex_imag_as_double
uPythonAPI.complex_imag_as_double
slice_as_ints
uPythonAPI.slice_as_ints
sequence_getslice
uPythonAPI.sequence_getslice
sequence_tuple
uPythonAPI.sequence_tuple
sequence_concat
uPythonAPI.sequence_concat
uPythonAPI.list_new
list_size
uPythonAPI.list_size
list_append
uPythonAPI.list_append
uPythonAPI.list_setitem
uPythonAPI.list_getitem
list_setslice
uPythonAPI.list_setslice
tuple_getitem
uPythonAPI.tuple_getitem
tuple_pack
uPythonAPI.tuple_pack
tuple_size
uPythonAPI.tuple_size
uPythonAPI.tuple_new
tuple_setitem
uPythonAPI.tuple_setitem
set_new
uPythonAPI.set_new
set_add
uPythonAPI.set_add
set_clear
uPythonAPI.set_clear
set_size
uPythonAPI.set_size
set_update
uPythonAPI.set_update
uPythonAPI.set_next_entry
gil_ensure
uPythonAPI.gil_ensure
gil_release
uPythonAPI.gil_release
save_thread
uPythonAPI.save_thread
restore_thread
uPythonAPI.restore_thread
object_get_private_data
uPythonAPI.object_get_private_data
object_set_private_data
uPythonAPI.object_set_private_data
object_reset_private_data
uPythonAPI.object_reset_private_data
import_module
uPythonAPI.import_module
uPythonAPI.call_function_objargs
T T
call_method
uPythonAPI.call_method
uPythonAPI.call
object_type
uPythonAPI.object_type
object_istrue
uPythonAPI.object_istrue
object_not
uPythonAPI.object_not
object_richcompare
uPythonAPI.object_richcompare
iter_next
uPythonAPI.iter_next
object_getiter
uPythonAPI.object_getiter
object_getattr_string
uPythonAPI.object_getattr_string
object_getattr
uPythonAPI.object_getattr
uPythonAPI.object_setattr_string
uPythonAPI.object_setattr
object_delattr_string
uPythonAPI.object_delattr_string
object_delattr
uPythonAPI.object_delattr
object_getitem
uPythonAPI.object_getitem
object_setitem
uPythonAPI.object_setitem
object_delitem
uPythonAPI.object_delitem
uPythonAPI.string_as_string
string_as_string_and_size
uPythonAPI.string_as_string_and_size
string_as_string_size_and_kind
uPythonAPI.string_as_string_size_and_kind
uPythonAPI.string_from_string_and_size
string_from_string
uPythonAPI.string_from_string
string_from_kind_and_data
uPythonAPI.string_from_kind_and_data
bytes_as_string
uPythonAPI.bytes_as_string
bytes_as_string_and_size
uPythonAPI.bytes_as_string_and_size
bytes_from_string_and_size
uPythonAPI.bytes_from_string_and_size
object_hash
uPythonAPI.object_hash
uPythonAPI.object_str
uPythonAPI.make_none
uPythonAPI.borrow_none
uPythonAPI.sys_write_stdout
object_dump
uPythonAPI.object_dump
nrt_adapt_ndarray_to_python
uPythonAPI.nrt_adapt_ndarray_to_python
nrt_meminfo_new_from_pyobject
uPythonAPI.nrt_meminfo_new_from_pyobject
nrt_meminfo_as_pyobject
uPythonAPI.nrt_meminfo_as_pyobject
nrt_meminfo_from_pyobject
uPythonAPI.nrt_meminfo_from_pyobject
nrt_adapt_ndarray_from_python
uPythonAPI.nrt_adapt_ndarray_from_python
nrt_adapt_buffer_from_python
uPythonAPI.nrt_adapt_buffer_from_python
uPythonAPI._get_function
alloca_obj
uPythonAPI.alloca_obj
alloca_buffer
uPythonAPI.alloca_buffer
print_object
uPythonAPI.print_object
print_string
uPythonAPI.print_string
uPythonAPI.get_null_object
return_none
uPythonAPI.return_none
list_pack
uPythonAPI.list_pack
uPythonAPI.unserialize
build_dynamic_excinfo_struct
uPythonAPI.build_dynamic_excinfo_struct
uPythonAPI.serialize_uncached
uPythonAPI.serialize_object
c_api_error
uPythonAPI.c_api_error
uPythonAPI.to_native_value
from_native_return
uPythonAPI.from_native_return
uPythonAPI.from_native_value
uPythonAPI.reflect_native_value
to_native_generator
uPythonAPI.to_native_generator
from_native_generator
uPythonAPI.from_native_generator
numba_array_adaptor
uPythonAPI.numba_array_adaptor
numba_buffer_adaptor
uPythonAPI.numba_buffer_adaptor
complex_adaptor
uPythonAPI.complex_adaptor
extract_record_data
uPythonAPI.extract_record_data
get_buffer
uPythonAPI.get_buffer
release_buffer
uPythonAPI.release_buffer
extract_np_datetime
uPythonAPI.extract_np_datetime
extract_np_timedelta
uPythonAPI.extract_np_timedelta
create_np_datetime
uPythonAPI.create_np_datetime
create_np_timedelta
uPythonAPI.create_np_timedelta
recreate_record
uPythonAPI.recreate_record
string_from_constant_string
uPythonAPI.string_from_constant_string
call_jit_code
uPythonAPI.call_jit_code
aObjModeUtils
uObjModeUtils.__init__
load_dispatcher
uObjModeUtils.load_dispatcher
uObjModeUtils._call_objmode_dispatcher
unumba\core\pythonapi.py
u<module numba.core.pythonapi>
T a__class__
T aself
pyapi
env
env_body
env_ptr
T aself
value
is_error
cleanup
T aself
pyapi
T aself
context
builder
T aself
T aself
name
lhs
rhs
inplace
fn
T acompile_args
dispatcher
argtypes
entrypt
T aself
fnty
name
T aself
name
fnty
fn
T aself
ival
func_name
native_int_type
signed
fnty
fn
resptr
T aself
const
index
val
T aself
ptr
T aself
bval
longval
T aself
ival
fnty
fn
T aself
typ
val
T aself
struct_gv
exc_args
fnty
fn
T aself
obj
fnty
fname
fn
T	aself
obj
p_buffer
p_length
fnty
fname
fn
result
ok
T aself
string
size
fnty
fname
fn
T aself
callee
args
kws
args_was_none
fnty
fn
result
T aself
callee
objargs
fnty
fn
args
T aself
func
sig
args
builder
cres
got_retty
retty
status
res
is_error_ptr
res_type
res_ptr
has_err
no_err
is_error
T
self
callee
method
objargs
cname
fnty
fn
fmt
cfmt
args
T aself
cobj
cmplx
fnty
fn
T aself
realval
imagval
fnty
fn
T aself
cobj
fnty
fn
T aself
val
unit_code
fnty
fn
T afunc
typeclass
self
T aself
typeclass
T aself
obj
fnty
fn
T aself
dic
name
fnty
fn
T aself
dic
name
fnty
fn
cstr
T aself
presize
fnty
fn
T aself
keyvalues
dictobj
wkwvT aself
dictobj
nameobj
valobj
fnty
fn
T aself
dictobj
name
valobj
fnty
fn
cstr
T abuilder
bb_end
T abb_end
builder
T aself
envptr
return_pyobject
debug_msg
is_null
fnty
T aself
fnty
fn
T aself
pty
pval
ptb
fnty
fn
T aself
exctype
msg
format_args
fnty
fn
T aself
keep_new
pty
pval
ptb
ty
val
tb
new_error
if_error
if_ok
T aself
ty
val
tb
fnty
fn
T aself
exctype
fnty
fn
T aself
exctype
excval
fnty
fn
T aself
exctype
msg
fnty
fn
T aself
obj
pbuf
fnty
fn
T aself
msg
fnty
fn
cstr
T aself
fobj
fnty
fn
T aself
fval
fnty
fn
T aself
val
typ
env
llty
gen_struct_size
gendesc
genfnty
genfn
finalizerty
finalizer
fnty
fn
state_size
initial_state
T aself
typ
val
env_manager
out
T aself
typ
val
env_manager
box_unsupported
impl
wcT aself
name
T aself
env
env_body
env_ptr
T aself
gilptrty
fnty
fn
gilptr
T aself
gil
gilptrty
fnty
fn
T aself
obj
T aself
modname
fnty
fn
T aself
iterobj
fnty
fn
T aself
lst
val
fnty
fn
T aself
lst
idx
fnty
fn
T aself
szval
fnty
fn
T aself
items
wnaseq
wiaidx
T aself
lst
idx
val
fnty
fn
T aself
lst
start
stop
obj
fnty
fn
T aself
lst
fnty
fn
T aself
fnty
argtypes
builder
tyctx
wmagv
bb_end
serialized_dispatcher
compile_args
failed_unser
cached
cls
compiler
callee
entry_pt
T aself
numobj
fnty
fn
T aself
ival
func_name
fnty
fn
T aself
ival
T aself
ival
bits
T aself
typeclass
default
cls
func
T aself
buf
ptr
fnty
fn
T aself
ary
ptr
fnty
fn
T aself
aryty
ary
dtypeptr
intty
serial_aryty_pytype
fnty
fn
ndim
writable
aryptr
T aself
miptr
mod
fnty
fn
T aself
miobj
mod
fnty
fn
T aself
data
pyobj
mod
fnty
fn
T aself
lhs
rhs
inplace
T aself
numobj
fnty
fn
exc_class
T aself
val
fnty
fn
T aself
lhs
rhs
inplace
fnty
fname
fn
T aself
obj
attr
T aself
obj
key
fnty
fn
T aself
obj
attr
fnty
fn
T aself
obj
attr
cstr
fnty
fn
T aself
lhs
rhs
opstr
ops
opid
fnty
fn
lopid
bitflag
status
negone
is_good
outptr
truncated
T aself
obj
ptr
fnty
fn
T aself
obj
attr
val
fnty
fn
T aself
obj
attr
val
cstr
fnty
fn
T aself
obj
key
val
fnty
fn
T aself
args
fmt
objs
charptr
argtypes
fnty
fn
T aself
args
kws
fmt
keywords
objs
charptr
charptrary
argtypes
fnty
fn
T aself
obj
strobj
cstr
fmt
T aself
text
fmt
T aself
name
msg
cstr
T aself
exc
fnty
fn
T aself
index
builder
consts
ret
br_not_null
br_null
getitem
T aself
pdata
size
dtype
env_manager
fnty
fn
dtypeaddr
T aself
typ
val
env_manager
impl
is_error
wcT aself
typeclass
decorator
T aself
pbuf
fnty
fn
T aself
thread_state
fnty
fn
T aself
none
T aself
obj1
obj2
fnty
fn
T aself
obj
start
stop
fnty
fn
T aself
obj
gv
struct
name
T	aself
obj
data
name
bdata
hashed
arr
hasharr
struct
T aself
set
value
fnty
fn
T aself
set
fnty
fn
T aself
set
builder
hashptr
keyptr
posptr
bb_body
bb_end
do_break
wrafinished
T aself
iterable
fnty
fn
T aself
set
posptr
keyptr
hashptr
fnty
fn
T aself
set
iterable
fnty
fn
T aself
obj
pstart
pstop
pstep
fnty
fn
res
start
stop
step
T aself
strobj
fnty
fname
fn
T aself
strobj
p_length
fnty
fname
fn
buffer
ok
T aself
strobj
p_length
p_kind
p_ascii
p_hash
fnty
fname
fn
buffer
ok
T aself
string
cstr
sz
T aself
kind
string
size
fnty
fname
fn
T aself
string
fnty
fname
fn
T aself
fmt
args
fnty
fn
T aself
obj
typ
gen_ptr_ty
value
T aself
typ
obj
unbox_unsupported
impl
wcT aself
tup
idx
fnty
fn
T aself
count
fnty
fn
T aself
items
fnty
fn
wnaargs
T aself
tuple_val
index
item
fnty
setitem_fn
T aself
tup
fnty
fn
T aself
typ
obj
T
self
args
name
n_min
n_max
objs
charptr
argtypes
fnty
fn
T aself
structptr
fnty
fn
ptr
wnahashed
.numba.core.registry
J
cpu
aCPUContext
typing_context
a_target_name
typing
aContext
a_toplevel_target_context
a_toplevel_typing_context
utils
aUniqueDict
ondemand
key_type
pop
T avalue_type
navalue_type
a_type_check
aDelayedRegistry
a__init__
a__getitem__
check
uDelayedRegistry.__setitem__.<locals>.check
a__setitem__
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
contextlib
l
unumba.core.utils
T athreadsafe_cached_property
threadsafe_cached_property
cached_property
unumba.core.descriptors
T aTargetDescriptor
aTargetDescriptor
unumba.core
T autils
typing
dispatcher
cpu
dispatcher
a__prepare__
aCPUTarget
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
