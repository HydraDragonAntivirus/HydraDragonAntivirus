# Reconstructed from integrated Nuitka blob
# Module: unumba.cpython.hashing

a__qualname__
prefix
a_fields_
a__orig_bases__
aSIPHASH
aDJBX33A
padding
aEXPAT
hashsalt
uc
l afnv
expat
a_build_hashsecret
T asiphash13
siphash24
fnv
uFNV hashing is not implemented in Numba. See PEP 456 https://www.python.org/dev/peps/pep-0456/ for rationale over not using FNV. Numba will continue to work, but hashes for built in types will be computed using siphash24. This will permit e.g. dictionaries to continue to behave as expected, however anything relying on the value of the hash opposed to hash as a derived property is likely to not work as expected.
msg
warn
wawcwdwsa_gen_siphash
T asiphash13
a_siphash13
T asiphash24
a_siphash24
uUnsupported hashing algorithm in use %s
a_impl_load_hashsecret
aUnicodeType
unicode_hash
unumba\cpython\hashing.py
u<module numba.cpython.hashing>
T a__class__
T av0
v1
v2
v3
T wawbwcwdwswtT wxT aval
a_len
a_hash
idx
tmp
T wvwxwmweasign
wyT wxwbT apyhashsecret
info
inject
T ahash_func
T atyctx
val
impl
sig
T aalg
a_ROUNDER
a_EXTRA_ROUND
a_siphash
T aname
imp
T atyctx
name
sym
resty
sig
impl
T
val
a_tmp_shift
mask_shift
wiwxap3
idx
p1
p2
p4
T atyctx
impl
sig
T ak0
k1
src
src_sz
wbav0
v1
v2
v3
idx
mi
wtaboffset
ohexefef
jmp
mask
wia_ROUNDER
a_EXTRA_ROUND
T a_EXTRA_ROUND
a_ROUNDER
T atup
tl
acc
wxalane
T aval
impl
T aobj
attempt_generic_msg
impl
T acgctx
builder
signature
args
val
T acgctx
builder
sig
args
mod
gv
wvasym
T asym
T acgctx
builder
signature
args
state_ptr
bits
value
T aval
hashreal
hashimag
combined
T aval
fpextended
hashed
T aval
hashed
T aobj
attempt_generic_msg
T aattempt_generic_msg
T aval
mag
ret
needs_negate
a_BIG
a_SIGNED_MIN
a_HASH_I64_MIN
T a_BIG
a_HASH_I64_MIN
a_SIGNED_MIN
T aobj
hash_func
err_msg
T aerr_msg
T aval
T aval
kindwidth
a_len
current_hash
a_kind_to_byte_width
T aname
val
symbol_name
addr
info
T ainfo
T aval
a_HASH_I64_MIN
a_SIGNED_MIN
a_BIG
impl
T aobj
hash_func
err_msg
impl
T aval
asint
T aval
a_kind_to_byte_width
impl
.numba.cpython.heapq
h
j
pos
l aheap
l achildpos
a_siftdown
a_siftdown_max
q areversed_range
a_siftup_max
wxl
types
aList
aListType
aTypingError
T uheap argument must be a list
dtype
aComplex
T u'<' not supported between instances of 'complex' and 'complex'
T uheap type must be the same as item type
assert_heap_type
hq_heapify_impl
uhq_heapify.<locals>.hq_heapify_impl
a_siftup
hq_heappop_impl
uhq_heappop.<locals>.hq_heappop_impl
pop
assert_item_type_consistent_with_heap_type
hq_heappush_impl
uheappush.<locals>.hq_heappush_impl
append
hq_heapreplace
uheapreplace.<locals>.hq_heapreplace
hq_heappushpop_impl
uheappushpop.<locals>.hq_heappushpop_impl
utoo many values to unpack (expected 2)
aInteger
aBoolean
T uFirst argument 'n' must be an integer
aSequence
aArray
T uSecond argument 'iterable' must be iterable
check_input_types
hq_nsmallest_impl
unsmallest.<locals>.hq_nsmallest_impl
;l
pl amin
sorted
a_heapify_max
top
a_heapreplace_max
result
order
sort
hq_nlargest_impl
unlargest.<locals>.hq_nlargest_impl
max
:nnq ahq
heapify
heapreplace
T tT areverse
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
heapq
unumba.core
T atypes
unumba.core.errors
T aTypingError
unumba.core.extending
T aoverload
register_jitable
overload
register_jitable
hq_heapify
heappop
hq_heappop
heappush
heappushpop
nsmallest
nlargest
unumba\cpython\heapq.py
u<module numba.cpython.heapq>
T wxwnwiT aheap
item
returnitem
T aheap
startpos
pos
newitem
parentpos
parent
T aheap
pos
endpos
startpos
newitem
childpos
rightpos
T aheap
dt
msg
T aheap
item
T wnaiterable
T aheap
item
hq_heappush_impl
T aheap
item
hq_heappushpop_impl
T aheap
item
hq_heapreplace
T wxahq_heapify_impl
T aheap
hq_heappop_impl
T aheap
lastelt
returnitem
T
wnaiterable
out
size
it
result
top
order
elem
a_order
T wnaiterable
hq_nlargest_impl
T wnaiterable
hq_nsmallest_impl
T wxu
.numba.cpython.iterators
e
utoo many values to unpack (expected 1)
impl_ret_borrowed
return_type
args
l
get_constant
types
intp
cast
l acall_getiter
context
src
make_helper
cgutils
alloca_once
start_val
type
store
count
aiter
a_getvalue
impl_ret_new_ref
T avalue
load
add
call_iternext
source_type
is_valid
set_valid
if_then
a__enter__
a__exit__
yielded_value
yield_
make_tuple
yield_type
T nnnutoo many values to unpack (expected 2)
builder
zipobj
set_exhausted
get_value_type
alloca_once_value
true_bit
source_types
p_is_valid
and_
gep_inbounds
p_ret_tup
get_generator_impl
add_linking_libs
libs
if_likely
is_ok
T taif_unlikely
is_stop_iteration
is_error
not_
call_conv
return_status_propagate
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
unumba.core
T atypes
cgutils
unumba.core.imputils
T alower_builtin
iternext_impl
call_iternext
call_getiter
impl_ret_borrowed
impl_ret_new_ref
aRefType
lower_builtin
iternext_impl
aRefType
getiter
aIteratorType
iterator_getiter
aIterableType
aInteger
make_enumerate_object
iternext
aEnumerateType
aNEW
iternext_enumerate
aVarArg
aAny
make_zip_object
aZipType
iternext_zip
aGenerator
aBORROWED
unumba\cpython\iterators.py
u<module numba.cpython.iterators>
T acontext
builder
sig
args
it
T acontext
builder
sig
args
result
enumty
enum
count
ncount
srcres
is_valid
srcval
T
context
builder
sig
args
result
genty
gen
impl
status
retval
T acontext
builder
sig
args
result
zip_type
zipobj
p_ret_tup
p_is_valid
wiaiterobj
srcty
is_valid
srcres
val
ptr
T acontext
builder
sig
args
srcty
src
start_val
iterobj
enum
countptr
res
T
context
builder
sig
args
zip_type
zipobj
wiaarg
srcty
res

.numba.cpython.listobj
,
- atypes
aListPayload
nrt
meminfo_data
meminfo
get_data_type
as_pointer
bitcast
make_data_helper
T aref
dtype
get_abi_sizeof
a_payload
size
dirty
a_get_ptr_by_name
T adata
cgutils
gep
a_builder
data
a_gep
load
a_datamodel
from_data
icmp_signed
w<air
aConstant
type
l
add
select
u>=
or_
alloca_once_value
if_then
D alikely
Fa__enter__
a__exit__
store
T nnnais_out_of_bounds
a_context
call_conv
return_user_exc
slicing
fix_slice
incref
decref
a_ty
data_model_manager
make_helper
a_list
get_itemsize
a_itemsize
get_list_payload
parent
a_getvalue
reflected
true_bit
false_bit
decref_value
getitem
zfill
T l aas_data
set_dirty
T taincref_value
get_value_type
intp
sub
ptrtoint
memset
aIntType
T l T l
muladd_with_overflow
utoo many values to unpack (expected 2)
D alikely
tameminfo_new_varsize_dtor_unchecked
get_dtor
T asize
dtor
if_else
is_null
get_constant_null
pyobject
allocated
module
aFunctionType
aVoidType
voidptr_t
get_or_insert_function
u.dtor.list.{}
is_declaration
linkonce_odr
linkage
aIRBuilder
append_basic_block
args
aListPayloadAccessor
for_range_slice
T astart
stop
step
intp
ret_void
define_dtor
allocate_ex
not_
T ucannot allocate list
value
a_payload_realloc
uListInstance.resize.<locals>._payload_realloc
l l w>aashr
context
self
itemsize
builder
intp_t
T ucannot resize list
meminfo_varsize_realloc_unchecked
T asize
guard_memory_error
ucannot resize list
raw_memmove
T aitemsize
a_iter
yield_type
aListInstance
container
get_constant
index
allocate
inst
setitem
D aincref
taimpl_ret_new_ref
list_impl
ulist_constructor.<locals>.list_impl
compile_internal
return_type
aListIterInstance
from_list
impl_ret_borrowed
set_valid
yield_
l afix_index
guard_index
D amsg
ugetitem out of range
D amsg
usetitem out of range
get_dummy_value
guard_invalid_slice
get_slice_length
for_range_slice_generic
start
stop
step
inititem
u==
resize
move
for_range
u!=
T ucannot resize extended list slice with step != 1
list_delitem_impl
udelitem_list_index.<locals>.list_delitem_impl
pop
T uunsupported del list[start:stop:step] with step != 1
seq_contains_impl
uin_seq.<locals>.seq_contains_impl
sequence_bool_impl
usequence_bool.<locals>.sequence_bool_impl
aSequence
impl
usequence_truth.<locals>.impl
cast
a_list_extend_list
aList
T l
l T l l
is_neg_int
mul
D ainc
tageneric_compare
operator
eq
do_break
all_list
list_ne_impl
uimpl_list_ne.<locals>.list_ne_impl
list_le_impl
uimpl_list_le.<locals>.list_le_impl
min
list_lt_impl
uimpl_list_lt.<locals>.list_lt_impl
list_ge_impl
uimpl_list_ge.<locals>.list_ge_impl
list_gt_impl
uimpl_list_gt.<locals>.list_gt_impl
list_copy_impl
ulist_copy.<locals>.list_copy_impl
list_count_impl
ulist_count.<locals>.list_count_impl
res
list_extend
ulist_extend.<locals>.list_extend
append
meth
aInteger
aOmitted
errors
aTypingError
uarg "start" must be an Integer. Got

uarg "stop" must be an Integer. Got
intp_max
list_index_impl
ulist_index.<locals>.list_index_impl
uvalue not in list
clamp_index
D aincref
decref_old_value
tFaguard_zero
T EIndexError
upop from empty list
clear_value
upop index out of range
list_remove_impl
ulist_remove.<locals>.list_remove_impl
ulist.remove(x): x not in list
list_reverse_impl
ulist_reverse.<locals>.list_reverse_impl
lst
aOptional
aBoolean
uan integer is required for 'reverse' (got type %s)
reverse
T uKey must concretely be None or a Numba JIT compiled function, an Optional (union of None and a value) was found
is_nonelike
aDispatcher
T uKey must be None or a Numba JIT compiled function
a_sort_check_key
a_sort_check_reverse
sort_forwards
sort_backwards
arg_sort_forwards
arg_sort_backwards
T nFuol_list_sort.<locals>.impl
aKEY
key
sort_f
sort_b
:nnnaIterableType
uol_sorted.<locals>.impl
sort
T akey
reverse
a_banned_error
aLiteralList
T ulist.index is unsupported for literal lists
uliteral_list_count.<locals>.impl
literal_unroll
count
T uCannot mutate a literal list
T uCannot __getitem__ on a literal list, return type cannot be statically determined.
u<lambda>
uliteral_list_len.<locals>.<lambda>
wluliteral_list_contains.<locals>.impl
unpack_tuple
utoo many values to unpack (expected 3)
make_tuple
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
math
cached_property
llvmlite
T air
unumba.core
T atypes
typing
errors
cgutils
config
typing
config
unumba.core.imputils
T alower_builtin
lower_cast
iternext_impl
impl_ret_borrowed
impl_ret_new_ref
impl_ret_untracked
aRefType
lower_builtin
lower_cast
iternext_impl
impl_ret_untracked
aRefType
unumba.core.extending
T aoverload_method
overload
overload_method
overload
unumba.misc
T aquicksort
quicksort
unumba.cpython
T aslicing
numba
T aliteral_unroll
T Oobject
a__prepare__
a_ListPayloadMixin
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
