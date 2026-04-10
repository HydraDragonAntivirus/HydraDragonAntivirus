# Reconstructed from integrated Nuitka blob
# Module: unumba.cpython.setobj

a__qualname__
a__init__
u_SetPayload.__init__
property
u_SetPayload.mask
setter
u_SetPayload.used
u_SetPayload.fill
u_SetPayload.finger
u_SetPayload.dirty
u_SetPayload.entries
u_SetPayload.ptr
u_SetPayload.get_entry
T Fu_SetPayload._lookup
contextmanager
T na__orig_bases__
uSetInstance.__init__
uSetInstance.dtype
uSetInstance.payload
uSetInstance.value
uSetInstance.meminfo
uSetInstance.parent
uSetInstance.get_size
uSetInstance.set_dirty
uSetInstance._add_entry
T tpuSetInstance._add_key
uSetInstance._remove_entry
uSetInstance._remove_key
uSetInstance.add
add_pyapi
uSetInstance.add_pyapi
uSetInstance._pyapi_get_hash_value
uSetInstance.contains
uSetInstance.discard
uSetInstance.pop
uSetInstance.clear
uSetInstance.copy
uSetInstance.intersect
uSetInstance.difference
uSetInstance.symmetric_difference
uSetInstance.issubset
uSetInstance.isdisjoint
uSetInstance.equals
classmethod
uSetInstance.allocate_ex
uSetInstance.allocate
from_meminfo
uSetInstance.from_meminfo
uSetInstance.choose_alloc_size
uSetInstance.upsize
uSetInstance.downsize
uSetInstance._resize
uSetInstance._replace_payload
uSetInstance._allocate_payload
uSetInstance._free_payload
uSetInstance._copy_payload
uSetInstance._imp_dtor
uSetInstance.incref_value
uSetInstance.decref_value
uSetIterInstance.__init__
uSetIterInstance.from_set
uSetIterInstance.value
uSetIterInstance.meminfo
uSetIterInstance.index
uSetIterInstance.iternext
build_set
T Oset
set_empty_constructor
aIterableType
set_constructor
len
set_len
aAny
in_set
getiter
getiter_set
aSetIter
aBORROWED
iternext_listiter
uset.add
set_add
ol_set_discard
ol_set_pop
remove
ol_set_remove
ol_set_clear
ol_set_copy
set_difference_update_impl
set_intersection_update_impl
set_symmetric_difference_update_impl
uset.update
set_update
gen_operator_impl
iand
ior
isub
ixor
op_
op_impl
impl_set_difference
intersection
set_intersection
xor
set_symmetric_difference
or_
union
set_union
set_isdisjoint
le
set_issubset
ge
issuperset
set_issuperset
set_eq
ne
set_ne
lt
set_lt
gt
set_gt
is_
set_is
set_to_set
unumba\cpython\setobj.py
T wawba_set_operator_intr
T a_set_operator_intr
T wsT wsaitem
T wawbu<module numba.cpython.setobj>
T a__class__
T aself
context
builder
set_type
set_val
T aself
context
builder
iter_type
iter_val
ptr
T aself
context
builder
set_type
ptr
payload
T aself
payload
entry
item
whado_resize
context
builder
old_hash
used
one
T aself
payload
item
whado_resize
do_incref
context
builder
found
wianot_found
entry
old_hash
used
one
T aself
nentries
realloc
context
builder
ok
intp_t
zero
one
payload_type
payload_size
entry_size
allocsize
ovf
meminfo
ptr
alloc_ok
dtor
if_error
if_ok
payload
new_mask
T aself
src_payload
context
builder
ok
intp_t
zero
one
payload_type
payload_size
entry_size
mask
nentries
allocsize
dtor
meminfo
alloc_ok
if_error
if_ok
payload
loop
T aself
ptr
T atypingctx
value
impl
fnty
sig
T aself
context
module
llvoidptr
llsize_t
fnty
fname
fn
builder
payload
loop
entry
T aself
start
context
builder
intp_t
one
size
range_loop
entry
is_used
loop
T aself
item
whafor_insert
context
builder
intp_t
mask
dtype
tyctx
fnty
sig
eqfn
one
five
perturb
index
free_index_sentinel
free_index
bb_body
bb_found
bb_not_found
bb_end
check_entry
wiwpwjafound
Taself
context
builder
intp_t
zero
one
mask
bb_body
bb_end
index
wiaentry
is_used
T aself
pyapi
context
builder
item
argtypes
resty
wrapper
args
sig
is_error
retval
T aself
payload
entry
do_resize
do_decref
used
one
T
self
payload
item
whado_resize
context
builder
found
wiaentry
T aself
nentries
context
builder
loop
entry
ok
T
self
payload
nentries
errmsg
context
builder
old_payload
ok
loop
entry
T atypingctx
wsasig
set_clear
T atypingctx
wsasig
set_copy
T atypingctx
wawbasig
T atypingctx
wsaitem
sig
set_discard
T atypingctx
wawbasig
codegen
T aimpl
T atypingctx
wsasig
set_pop
T atypingctx
wsaitem
sig
set_remove
T aself
item
do_resize
context
builder
payload
whT aself
pyapi
item
do_resize
context
builder
payload
whT acls
context
builder
set_type
nitems
ok
self
T	acls
context
builder
set_type
nitems
intp_t
nentries
self
ok
T acontext
builder
set_type
items
nitems
inst
array
array_ptr
count
loop
item
T asmaller
larger
loop
entry
found
w_abuilder
res
T abuilder
res
T aargs
T wiaentry
entry_hash
eq
wjaself
builder
whaeqfn
item
bb_found
context
bb_not_found
for_insert
free_index
free_index_sentinel
T abb_found
bb_not_found
builder
context
eqfn
for_insert
free_index
free_index_sentinel
whaitem
self
T acls
context
builder
nitems
intp_t
one
minsize
min_entries
size_p
bb_body
bb_end
size
is_large_enough
next_size
T aself
context
builder
intp_t
minsize
T acontext
builder
sig
args
inst
other
T acontext
builder
sig
args
impl
T aself
item
context
builder
payload
whafound
wiT aself
context
builder
payload
used
fill
other
no_deleted_entries
if_no_deleted
if_deleted
ok
nentries
other_payload
loop
entry
T aself
val
T aself
other
context
builder
payload
other_payload
loop
entry
T wawbwsT aself
T aself
value
T aself
item
context
builder
payload
whafound
T aself
nitems
context
builder
intp_t
one
two
minsize
payload
min_entries
max_size
size
need_resize
new_size_p
bb_body
bb_end
new_size
is_too_small
Taself
other
context
builder
payload
other_payload
res
if_same_size
otherwise
loop
entry
found
w_T acls
context
builder
set_type
meminfo
self
T acls
context
builder
iter_type
set_val
set_inst
self
index
T aop
impl
a_set_operator_intr
a_ol_set_operator
T aself
idx
entry_ptr
entry
T acontext
set_type
llty
T acontext
builder
typ
value
typingctx
fnty
sig
fn
whais_ok
fallback
T acontext
builder
set_type
ptr
payload_type
ptrty
payload
T acontext
builder
sig
args
inst
T acontext
builder
typ
args
value
T avalue
T wawbadifference_impl
T
self
other
context
builder
payload
other_payload
loop
entry
found
w_T acontext
builder
whadeleted
T acontext
builder
whaempty
T
self
other
context
builder
payload
other_payload
res
check
if_larger
otherwise
T aself
other
strict
context
builder
payload
other_payload
cmp_op
res
if_smaller
if_larger
loop
entry
found
w_T aself
result
index
payload
one
loop
entry
T acontext
builder
sig
args
result
inst
T aself
context
builder
ptr
T aself
context
builder
lty
key
payload
entry
T acontext
builder
sig
args
inst
item
T
context
builder
sig
args
set_type
items_type
items
wnainst
loop
T acontext
builder
sig
args
set_type
inst
T wawbagt_impl
T wawbaintersection_impl
T acontext
builder
sig
args
wawbama
mb
T wawbasuperset_impl
T wawbane_impl
T acontext
builder
sig
args
inst
used
T acontext
builder
sig
args
inst
item
found
T wawbasymmetric_difference_impl
T acontext
builder
fromty
toty
val
T wawbaunion_impl
T acontext
builder
sig
args
inst
items_type
items
wnanew_size
loop
casted
T aself
other
context
builder
other_payload
loop
key
whapayload
found
wiaentry
if_common
if_not_common
T aself
nitems
context
builder
intp_t
one
two
payload
min_entries
size
need_resize
new_size_p
bb_body
bb_end
new_size
is_too_small
T aval
.numba.cpython.slicing
icmp_signed
w<air
aConstant
type
l
add
select
q afix_bound
ufix_slice.<locals>.fix_bound
if_else
cgutils
is_neg_int
step
a__enter__
a__exit__
utoo many values to unpack (expected 2)
start
stop
T nnnaslice
fix_index
builder
size
zero
if_then
D alikely
Fu>=
l asub
sdiv
u<=
T l
T l amul
has_step
guard_null
T EValueError
uslice step cannot be zero
address_size
get_defaults
context
get_constant
types
intp
utoo many values to unpack (expected 5)
args
none
slice_args
get_arg_value
uslice_constructor_impl.<locals>.get_arg_value
l areturn_type
make_helper
a_getvalue
impl_ret_untracked
call_conv
return_user_exc
T ulength should not be negative
is_scalar_zero
T uslice step cannot be zero
fix_slice
make_tuple
get_value_type
aLiteral
literal_type
make_slice_from_constant
literal_value
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
itertools
T azip_longest
zip_longest
llvmlite
T air
unumba.core
T acgutils
types
typing
utils
typing
utils
unumba.core.imputils
T aimpl_ret_borrowed
impl_ret_new_ref
impl_ret_untracked
iternext_impl
lower_builtin
lower_cast
lower_constant
lower_getattr
impl_ret_borrowed
impl_ret_new_ref
iternext_impl
lower_builtin
lower_cast
lower_constant
lower_getattr
get_slice_length
get_slice_bounds
fix_stride
guard_invalid_slice
aVarArg
aAny
slice_constructor_impl
aSliceType
slice_start_impl
slice_stop_impl
slice_step_impl
uslice.indices
aInteger
slice_indices
constant_slice
misc
aSliceLiteral
cast_from_literal
unumba\cpython\slicing.py
u<module numba.cpython.slicing>
T acontext
builder
fromty
toty
val
T acontext
builder
ty
pyval
typ
T
bound_name
lower_repl
upper_repl
bound
underflow
overflow
slice
builder
size
zero
T abuilder
size
slice
zero
T abuilder
idx
size
is_negative
wrapped_index
T
builder
slice
size
zero
minus_one
fix_bound
if_neg_step
if_pos_step
lower
upper
T abuilder
slice
stride
T wiadefault
val
slice_args
T aslice_args
T acontext
maxint
T	abuilder
slicestruct
start
stop
zero
one
is_step_negative
lower
upper
T abuilder
slicestruct
start
stop
step
one
zero
is_step_negative
delta
pos_dividend
neg_dividend
dividend
nominal_length
is_zero_length
T acontext
builder
typ
slicestruct
T acontext
builder
ty
pyval
sli
lty
default_start_pos
default_start_neg
default_stop_pos
default_stop_neg
default_step
step
step_is_neg
start
stop
T acontext
builder
sig
args
default_start_pos
default_start_neg
default_stop_pos
default_stop_neg
default_step
slice_args
wiaty
val
get_arg_value
step
is_step_negative
default_stop
default_start
stop
start
sli
res
T acontext
builder
sig
args
length
sli
T acontext
builder
typ
value
sli

.numba.cpython.tupleobj
utoo many values to unpack (expected 2)
context
cast
builder
sig
args
return_type
newargs
make_tuple
impl_ret_borrowed
cgutils
unpack_tuple
alloca_once_value
true_bit
append_basic_block
T acmp_end
types
extract_value
wuwvageneric_compare
operator
ne
if_then
a__enter__
a__exit__
op
store
res
branch
bbend
T nnnaget_constant
boolean
position_at_end
load
impl_ret_untracked
eq
and_
not_
tuple_eq
tuple_cmp_ordered
lt
le
gt
ge
fields
index
get_constant_generic
ty
dtype
pack_array
pack_struct
utoo many values to unpack (expected 1)
make_helper
aUniTupleIter
intp
l
alloca_once
type
tuple
a_getvalue
T avalue
container
count
icmp_signed
w<aset_valid
typing
signature
getitem_unituple
enable_nrt
nrt
decref
yield_
add
l aBaseTuple
aIntegerLiteral
literal_value
getitem_literal_idx_impl
ugetitem_literal_idx.<locals>.getitem_literal_idx_impl
idx_val
call_conv
return_user_exc
T utuple index out of range
get_constant_null
T utyped_switch.else
T utyped_switch.end
switch
goto_block
get_value_type
voidptr
phi
utyped_switch.%d
add_case
tupty
tup
typing_context
unify_types
alloca
lrtty
uTYPED_VALUE_SLOT%s
T aname
phinode
add_incoming
bitcast
value_slot
voidptrty
as_pointer
T uswitch.else
T uswitch.end
uswitch.%d
ucannot index at %d in %s
aLiteralStrKeyDict
uunexpected index %r for %s
aBaseNamedTuple
utoo many values to unpack (expected 3)
tuple_index_impl
utuple_index.<locals>.tuple_index_impl
utuple.index(x): x not in tuple
aTuple
u<lambda>
uin_seq_empty_tuple.<locals>.<lambda>
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
unumba.core.imputils
T alower_builtin
lower_getattr_generic
lower_cast
lower_constant
iternext_impl
impl_ret_borrowed
impl_ret_untracked
aRefType
lower_builtin
lower_getattr_generic
lower_cast
lower_constant
iternext_impl
aRefType
unumba.core
T atyping
types
cgutils
unumba.core.extending
T aoverload_method
overload
intrinsic
overload_method
overload
intrinsic
aNamedTupleClass
aVarArg
aAny
namedtuple_constructor
tuple_add
tuple_ne
tuple_lt
tuple_le
tuple_gt
tuple_ge
namedtuple_getattr
aUniTuple
aNamedUniTuple
unituple_constant
aNamedTuple
getiter
getiter_unituple
iternext
aBORROWED
iternext_unituple
getitem
getitem_literal_idx
typed_getitem
getitem_typed
uintp
static_getitem
aStringLiteral
aLiteralList
aSliceLiteral
static_getitem_tuple
tuple_to_tuple
tuple_index
contains
in_seq_empty_tuple
unumba\cpython\tupleobj.py
T wxwyu<module numba.cpython.tupleobj>
T atup
idx
idx_val
getitem_literal_idx_impl
T atup
idx
idx_val
T aidx_val
T acontext
builder
sig
args
tupty
w_atup
idx
errmsg_oob
res
bbelse
bbend
switch
lrtty
voidptrty
phinode
wiaki
bbi
kin
value
aDOCAST
value_slot
casted
T acontext
builder
sig
args
tupty
w_atup
idx
errmsg_oob
res
bbelse
bbend
switch
lrtty
phinode
wiaki
bbi
kin
value
T
context
builder
sig
args
tupty
tup
iterval
index0
indexptr
res
T acontext
builder
sig
args
result
tupiterty
tupiter
iterval
tup
idxptr
idx
count
is_valid
getitem_sig
getitem_out
nidx
T	acontext
builder
sig
args
newargs
wiaarg
casted
res
T acontext
builder
typ
value
attr
index
res
T acontext
builder
sig
args
tupty
idxty
tup
idx
res
items
idx_val
idx_offset
T acontext
builder
sig
args
left
right
res
T acontext
builder
op
sig
args
tu
tv
wuwvares
bbend
wiata
tb
wawbanot_equal
pred
len_compare
T acontext
builder
sig
args
tu
tv
wuwvares
wiata
tb
wawbapred
T acontext
builder
sig
args
res
T atup
value
tuple_index_impl
T atup
value
wiT acontext
builder
fromty
toty
val
olditems
items
T acontext
builder
ty
pyval
consts

.numba.cpython.unicode
HM
m adata
types
voidptr
length
intp
kind
int32
is_ascii
uint32
hash
a_Py_hash_t
meminfo
aMemInfoPointer
parent
pyobject
models
aStructModel
a__init__
index
aEphemeralPointer
uintp
aUnicodeIteratorModel
aCFUNCTYPE
l
c_void_p
c_int
c_uint
c_ssize_t
c_ubyte
py_object
aPOINTER
byref
c_helpers
extract_unicode
ucannot extract unicode data from the given string
value
l a_kind_to_byte_width
from_address
compile_time_get_string_data
utoo many values to unpack (expected 5)
module
insert_const_bytes
cgutils
create_struct_proxy
type
T q a_getvalue
make_string_from_constant
literal_value
pyapi
string_as_string_size_and_kind
utoo many values to unpack (expected 6)
context
builder
nrt_meminfo_new_from_pyobject
is_not_null
err_occurred
aNativeValue
T ais_error
T avalue
string_from_kind_and_data
object_hash
nrt
decref
codegen
umake_deref_codegen.<locals>.codegen
utoo many values to unpack (expected 2)
bitcast
aIntType
bitsize
as_pointer
load
gep
zext
T l amake_deref_codegen
T l T l adetails
u_malloc_string.<locals>.details
unicode_type
utoo many values to unpack (expected 4)
mul
add
aConstant
meminfo_alloc
get_constant
q ameminfo_data
get_null_value
a_malloc_string
a_set_code_point
np
T l
a_kind
aPY_UNICODE_1BYTE_KIND
deref_uint8
a_data
aPY_UNICODE_2BYTE_KIND
deref_uint16
aPY_UNICODE_4BYTE_KIND
deref_uint32
umake_set_codegen.<locals>.codegen
utoo many values to unpack (expected 3)
l atrunc
store
get_dummy_value
void
int64
make_set_codegen
set_uint8
set_uint16
set_uint32
uUnexpected unicode representation in _set_code_point
uUnexpected unicode representation in _pick_kind
aPY_UNICODE_WCHAR_KIND
uPY_UNICODE_WCHAR_KIND unsupported
T l l l uUnexpected unicode encoding encountered
a_length
a_get_code_point
waaa_offset
wbab_offset
l  l   l  CuInvalid codepoint. Found value greater than Unicode maximum
l  aUnicodeType
len_impl
uunicode_len.<locals>.len_impl
is_internal
aOptional
aStringLiteral
aUnicodeCharSeq
eq_impl
uunicode_eq.<locals>.eq_impl
a_cmp_region
ne_impl
uunicode_ne.<locals>.ne_impl
uunicode_ne.<locals>.eq_impl
lt_impl
uunicode_lt.<locals>.lt_impl
min
gt_impl
uunicode_gt.<locals>.gt_impl
le_impl
uunicode_le.<locals>.le_impl
ge_impl
uunicode_ge.<locals>.ge_impl
contains_impl
uunicode_contains.<locals>.contains_impl
a_find
aOmitted
aInteger
aNoneType
aTypingError
u"{}" must be {}, not {}
a_BLOOM_WIDTH
a_bloom_add
substr
mask
mlast
wiaend
wmwja_bloom_check
gap
skip
T nnaimpl
ugenerate_finder.<locals>.impl
a_adjust_indices
find_func
find_impl
uunicode_find.<locals>.find_impl
unicode_idx_check_type
start
unicode_sub_check_type
find
rfind_impl
uunicode_rfind.<locals>.rfind_impl
a_rfind
rfind
sub
rindex_impl
uunicode_rindex.<locals>.rindex_impl
usubstring not found
index_impl
uunicode_index.<locals>.index_impl
sep
uunicode_partition.<locals>.impl
a_empty_string
a_is_ascii
uempty separator
a_count_args_types_check
count_impl
uunicode_count.<locals>.count_impl
uThe substring must be a UnicodeType, not {}
a_normalize_slice_idx_count
sub_len
count
uunicode_rpartition.<locals>.impl
is_nonelike
T uWhen specified, the arg 'start' must be an Integer or None
T uWhen specified, the arg 'end' must be an Integer or None
aUniTuple
dtype
startswith_tuple_impl
uunicode_startswith.<locals>.startswith_tuple_impl
startswith_char_seq_impl
uunicode_startswith.<locals>.startswith_char_seq_impl
startswith_unicode_impl
uunicode_startswith.<locals>.startswith_unicode_impl
T uThe arg 'prefix' should be a string or a tuple of strings
wsastartswith
T uThe arg must be a Integer or None
aTuple
endswith_impl
uunicode_endswith.<locals>.endswith_impl
endswith
u"tabsize" must be {}, not {}
expandtabs_impl
uunicode_expandtabs.<locals>.expandtabs_impl
a_Py_TAB
tabsize
line_pos
g            unew string is too long
g            a_Py_LINEFEED
a_Py_CARRIAGE_RETURN
found
res
a_Py_SPACE
aIntegerLiteral
T nq asplit_impl
uunicode_split.<locals>.split_impl
split_whitespace_impl
uunicode_split.<locals>.split_whitespace_impl
split
T amaxsplit
parts
last
idx
split_count
sep_len
a_PyUnicode_IsSpace
in_whitespace_block
append
rsplit_whitespace_impl
ugenerate_rsplit_whitespace_impl.<locals>.rsplit_whitespace_impl
maxsplit
isspace_func
result
:nnq a_unicode_rsplit_check_type
uunicode_rsplit.<locals>._unicode_rsplit_check_type
uunicode_rsplit.<locals>.rsplit_whitespace_impl
rsplit_impl
uunicode_rsplit.<locals>.rsplit_impl
ascii_rsplit_whitespace_impl
unicode_rsplit_whitespace_impl
a_rsplit_char
uunicode_rsplit.<locals>.rsplit_impl.<locals>._rsplit_char
T astart
end
sep_length
T uThe width must be an Integer
T w acenter_impl
uunicode_center.<locals>.center_impl
w T uThe fillchar must be a UnicodeType
center
uThe fill character must be exactly one character long
unicode_Xjust
ugen_unicode_Xjust.<locals>.unicode_Xjust
aSTRING_FIRST
ljust_impl
ugen_unicode_Xjust.<locals>.unicode_Xjust.<locals>.ljust_impl
rjust_impl
ugen_unicode_Xjust.<locals>.unicode_Xjust.<locals>.rjust_impl
ugen_unicode_Xjust.<locals>.unicode_Xjust.<locals>.impl
ljust
rjust
ugenerate_splitlines_func.<locals>.impl
is_line_break_func
a_Py_ISCARRIAGERETURN
a_Py_ISLINEFEED
aBoolean
keepends
T Fasplitlines_impl
uunicode_splitlines.<locals>.splitlines_impl
a_ascii_splitlines
a_unicode_splitlines

a_pick_kind
a_pick_ascii
a_strncpy
dst_offset
aList
join_list_impl
uunicode_join.<locals>.join_list_impl
aIterableType
join_iter_impl
uunicode_join.<locals>.join_iter_impl
join_str_impl
uunicode_join.<locals>.join_str_impl
join_list
join
T u<width> must be an Integer
zfill_impl
uunicode_zfill.<locals>.zfill_impl
w0T w+w-:l nnT uThe arg must be a UnicodeType or None
T uThe slice indices must be an Integer or None
T nalstrip_impl
uunicode_lstrip.<locals>.lstrip_impl
unicode_strip_types_check
lstrip
unicode_strip_left_bound
rstrip_impl
uunicode_rstrip.<locals>.rstrip_impl
rstrip
unicode_strip_right_bound
strip_impl
uunicode_strip.<locals>.strip_impl
strip
ustring index out of range
u_normalize_slice.<locals>.codegen
args
make_helper
slicing
guard_invalid_slice
fix_slice
u_slice_span.<locals>.codegen
utoo many values to unpack (expected 1)
get_slice_length
memcpy_region
D aalign
l adst
src
src_offset
u_get_str_slice_view.<locals>.codegen
typing_context
resolve_value_type
get_call_type
get_function
enable_nrt
incref
getitem_char
uunicode_getitem.<locals>.getitem_char
aSliceType
getitem_slice
uunicode_getitem.<locals>.getitem_slice
normalize_str_idx
a_codepoint_to_kind
a_get_str_slice_view
a_codepoint_is_ascii
a_normalize_slice
a_slice_span
step
stop
ret
cur
slice_idx
concat_impl
uunicode_concat.<locals>.concat_impl
copy_size
wrap
uunicode_repeat.<locals>.wrap
a_repeat_impl
uunicode_not.<locals>.impl
uUnsupported parameters. The parameters must be Integer. Given count: {}
uThe object must be a UnicodeType. Given: {}
uunicode_replace.<locals>.impl
split_result
new_str
unicode_isAlX
ugen_isAlX.<locals>.unicode_isAlX
ugen_isAlX.<locals>.unicode_isAlX.<locals>.impl
ascii_func
unicode_func
a_PyUnicode_IsNumeric
a_PyUnicode_IsAlpha
u_is_upper.<locals>.impl
is_upper
is_lower
is_title
cased
uunicode_isupper.<locals>.impl
a_ascii_is_upper
a_unicode_is_upper
uunicode_isascii.<locals>.impl
uunicode_istitle.<locals>.impl
a_PyUnicode_IsUppercase
a_PyUnicode_IsTitlecase
previous_is_cased
a_PyUnicode_IsLowercase
uunicode_islower.<locals>.impl
uunicode_isidentifier.<locals>.impl
a_PyUnicode_IsXidStart
l_a_PyUnicode_IsXidContinue
unicode_isX
ugen_isX.<locals>.unicode_isX
ugen_isX.<locals>.unicode_isX.<locals>.impl
a_PyUnicode_IS_func
empty_is_false
ucase_operation.<locals>.impl
l atmp
a_PyUnicode_IsCaseIgnorable
a_PyUnicode_IsCased
wcl  l  l  a_handle_capital_sigma
a_PyUnicode_ToLowerFull
a_do_upper_or_lower
u_gen_unicode_upper_or_lower.<locals>._do_upper_or_lower
zeros
a_Py_UCS4
T l T adtype
lower
a_lower_ucs4
a_PyUnicode_ToUpperFull
mapped
max
maxchars
wka_ascii_upper_or_lower
u_gen_ascii_upper_or_lower.<locals>._ascii_upper_or_lower
func
case_operation
a_ascii_lower
a_unicode_lower
a_ascii_upper
a_unicode_upper
fill
a_PyUnicode_ToFoldedFull
a_Py_TOLOWER
a_ascii_casefold
a_unicode_casefold
a_PyUnicode_ToTitleFull
maxchar
a_Py_TOUPPER
a_ascii_capitalize
a_unicode_capitalize
empty
previous_cased
code_point
a_Py_ISLOWER
a_Py_ISUPPER
a_ascii_title
a_unicode_title
a_ascii_swapcase
a_unicode_swapcase
uol_ord.<locals>.impl
uord() expected a character
a_MAX_UNICODE
a_out_of_range_msg
a_unicode_char
uol_chr.<locals>.impl
a_PyUnicode_FromOrdinal
u<lambda>
uunicode_str.<locals>.<lambda>
uunicode_repr.<locals>.<lambda>
w'T l
uinteger_str.<locals>.impl
floor
log10
l-wnaten
l0uinteger_repr.<locals>.<lambda>
a__str__
uboolean_str.<locals>.<lambda>
aTrue
aFalse
return_type
alloca_once_value
impl_ret_new_ref
operator
getitem
T Olen
icmp_unsigned
w<aset_valid
if_then
a__enter__
a__exit__
yield_
increment_index
T nnna__doc__
a__file__
a__spec__
origin
has_location
a__cached__
sys
numpy
ullvmlite.ir
T aIntType
aConstant
unumba.core.cgutils
T ais_nonelike
unumba.core.extending
T
models
register_model
make_attribute_wrapper
unbox
box
aNativeValue
overload
overload_method
intrinsic
register_jitable
register_model
make_attribute_wrapper
unbox
box
overload
overload_method
intrinsic
register_jitable
unumba.core.imputils
T alower_constant
lower_cast
lower_builtin
iternext_impl
impl_ret_new_ref
aRefType
lower_constant
lower_cast
lower_builtin
iternext_impl
aRefType
unumba.core.datamodel
T aregister_default
aStructModel
register_default
unumba.core
T atypes
cgutils
config
config
unumba.core.utils
T aPYVERSION
aPYVERSION
unumba.core.pythonapi
T aPY_UNICODE_1BYTE_KIND
aPY_UNICODE_2BYTE_KIND
aPY_UNICODE_4BYTE_KIND
unumba._helperlib
T ac_helpers
unumba.cpython.hashing
T a_Py_hash_t
unumba.core.unsafe.bytes
T amemcpy_region
unumba.core.errors
T aTypingError
unumba.cpython.unicode_support
T!a_Py_TOUPPER
a_Py_TOLOWER
a_Py_UCS4
a_Py_ISALNUM
a_PyUnicode_ToUpperFull
a_PyUnicode_ToLowerFull
a_PyUnicode_ToFoldedFull
a_PyUnicode_ToTitleFull
a_PyUnicode_IsPrintable
a_PyUnicode_IsSpace
a_Py_ISSPACE
a_PyUnicode_IsXidStart
a_PyUnicode_IsXidContinue
a_PyUnicode_IsCased
a_PyUnicode_IsCaseIgnorable
a_PyUnicode_IsUppercase
a_PyUnicode_IsLowercase
a_PyUnicode_IsLineBreak
a_Py_ISLINEBREAK
a_Py_ISLINEFEED
a_Py_ISCARRIAGERETURN
a_PyUnicode_IsTitlecase
a_Py_ISLOWER
a_Py_ISUPPER
a_Py_TAB
a_Py_LINEFEED
a_Py_CARRIAGE_RETURN
a_Py_SPACE
a_PyUnicode_IsAlpha
a_PyUnicode_IsNumeric
a_Py_ISALPHA
a_PyUnicode_IsDigit
a_PyUnicode_IsDecimalDigit
a_Py_ISALNUM
a_PyUnicode_IsPrintable
a_Py_ISSPACE
a_PyUnicode_IsLineBreak
a_Py_ISLINEBREAK
a_Py_ISALPHA
a_PyUnicode_IsDigit
a_PyUnicode_IsDecimalDigit
unumba.cpython
T aslicing
T T l l
T l l T aPY_UNICODE_WCHAR_KIND
aUSE_LEGACY_TYPE_SYSTEM
bitwidth
py_int
a__prepare__
aUnicodeModel
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
